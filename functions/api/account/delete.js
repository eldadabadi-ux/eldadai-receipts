/**
 * Cloudflare Pages Function — POST /api/account/delete  (auth: Bearer JWT)
 *
 * GDPR Art.17 / right-to-erasure. Purges ALL of the signed-in user's data —
 * every tenant table, every stored file, their memberships, and the auth user
 * itself. The anon client cannot do this: it needs the service-role key, which
 * lives only on the server.
 *
 * Order: files → rows (atomic) → auth user. Data first, login last, so a partial
 * failure never orphans data behind a deleted login (the user retries).
 *
 * WHY a Postgres function rather than REST deletes (ASVS V2.3.3): fifteen REST
 * calls are fifteen transactions, so a failure halfway through left the account
 * PARTIALLY erased and said so as a count of errors. Erasure is irreversible and
 * is a legal promise — "we deleted some of it" satisfies nobody, and the user
 * cannot tell which half survived. erase_account() either removes every row or
 * none, and returns per-table counts so the scope stays auditable.
 *
 * The cascade on `user_id … ON DELETE CASCADE` remains the backstop; deleting
 * explicitly is what makes the scope VISIBLE rather than implied.
 *
 * Storage is the one step outside the transaction — object storage has no
 * transaction to join — so files go first, where a retry is harmless.
 *
 * What deliberately SURVIVES (both disclosed in the privacy policy):
 *   - `audit_log` — append-only, hash-chained tamper-evidence (A.8.15). Its
 *     user_id carries no FK precisely so the erasure record outlives the user.
 *   - `client_accounts` — the OPERATOR's billing record about the business, not
 *     the tenant's own data; retained for bookkeeping. If the organization is
 *     otherwise empty we anonymise it rather than cascade that record away.
 */

import { requireUser, wrapAuthErrors } from '../_lib/auth.js'
import { writeAudit } from '../_lib/audit.js'
import { checkRateLimit, rateLimitedResponse } from '../_lib/rateLimit.js'

const RECEIPTS_BUCKET = 'receipts'
const LIST_PAGE = 100          // Storage list page size
const DELETE_CHUNK = 100       // objects removed per request
const MAX_OBJECTS = 20000      // hard stop; a runaway prefix must not hang the worker

/**
 * The table list now lives in the erase_account() SQL function, so the
 * deletion order and the transaction live together. Keeping a second copy here
 * would be a list that drifts from the one that actually runs.
 */

function getSupabaseUrl(env) {
  return env.VITE_SUPABASE_URL || env.SUPABASE_URL || 'https://dsoucojqjrodxozcbicf.supabase.co'
}

/**
 * Every object under `prefix`, following sub-folders.
 *
 * Supabase Storage `list` is NON-recursive and paginated: it returns at most
 * `limit` entries of one level, and a sub-folder arrives as a pseudo-entry with
 * `id: null`. A single flat call therefore missed two whole classes of file —
 * anything past the first page, and every event-quote attachment, which lives
 * at `<uid>/events/<quote_id>/<file>`.
 */
async function listAllObjects(url, svc, bucket, prefix, budget = { left: MAX_OBJECTS }) {
  const paths = []
  for (let offset = 0; budget.left > 0; offset += LIST_PAGE) {
    const res = await fetch(`${url}/storage/v1/object/list/${bucket}`, {
      method: 'POST',
      headers: { ...svc, 'Content-Type': 'application/json' },
      body: JSON.stringify({ prefix, limit: LIST_PAGE, offset, sortBy: { column: 'name', order: 'asc' } }),
    })
    // 404 = bucket not created yet → nothing to remove.
    if (res.status === 404) break
    if (!res.ok) throw new Error(`list:${res.status}`)

    const page = await res.json()
    const entries = Array.isArray(page) ? page : []
    if (!entries.length) break

    for (const e of entries) {
      const name = e?.name
      if (!name) continue
      if (e.id === null || e.id === undefined) {
        // Sub-folder → recurse into it.
        const sub = await listAllObjects(url, svc, bucket, `${prefix}${name}/`, budget)
        paths.push(...sub)
      } else {
        paths.push(`${prefix}${name}`)
        budget.left--
      }
    }
    if (entries.length < LIST_PAGE) break
  }
  return paths
}

export const onRequestPost = wrapAuthErrors(async (context) => {
  const user = await requireUser(context.request, context.env)
  const sk = context.env.SUPABASE_SERVICE_ROLE_KEY
  const url = getSupabaseUrl(context.env)

  if (!sk) {
    return Response.json(
      { error: 'server_config', message: 'מחיקת חשבון אינה זמינה (חסר מפתח שירות בשרת).' },
      { status: 500 },
    )
  }

  // Erasure is irreversible and expensive (full storage walk). A handful an
  // hour is far more than a real person needs and well under what a stolen
  // token could use to grind the service-role key.
  const rl = await checkRateLimit(context.env, `${user.user_id}:acct-del`, { limit: 5, windowSec: 3600 })
  if (!rl.allowed) return rateLimitedResponse(rl.retryAfter)

  const uid = user.user_id
  const qid = encodeURIComponent(uid)
  const svc = { apikey: sk, Authorization: `Bearer ${sk}` }
  const errors = []
  let filesRemoved = 0

  // ── 1. Remove every private storage file, at any depth ─────────────────────
  try {
    const paths = await listAllObjects(url, svc, RECEIPTS_BUCKET, `${uid}/`)
    for (let i = 0; i < paths.length; i += DELETE_CHUNK) {
      const chunk = paths.slice(i, i + DELETE_CHUNK)
      const rm = await fetch(`${url}/storage/v1/object/${RECEIPTS_BUCKET}`, {
        method: 'DELETE',
        headers: { ...svc, 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefixes: chunk }),
      })
      if (rm.ok) filesRemoved += chunk.length
      else errors.push(`storage:${rm.status}`)
    }
  } catch (e) {
    errors.push(`storage:${e?.message || 'err'}`)
  }

  // ── 2. Erase every row, atomically ────────────────────────────────────────
  // ONE call, one transaction. Fifteen sequential REST deletes each committed
  // on their own, so a failure in the middle left the account partly erased and
  // reported it as a count of errors — the wrong shape for an irreversible
  // legal promise (GDPR Art.17, ASVS V2.3.3). Organizations the user solely
  // owns are handled inside the same transaction: deleted, or anonymised when
  // the operator's billing record hangs off them.
  let erased = null
  try {
    const res = await fetch(`${url}/rest/v1/rpc/erase_account`, {
      method: 'POST',
      headers: { ...svc, 'Content-Type': 'application/json' },
      body: JSON.stringify({ p_user_id: uid }),
    })
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 300)
      console.error('[account/delete] erase_account failed:', res.status, detail)
      // Nothing was committed — the transaction rolled back — and the auth user
      // is untouched, so the account is intact and the user can retry. Saying
      // so is more useful than a partial-success count.
      return Response.json(
        { error: 'delete_failed', message: 'מחיקת החשבון נכשלה ולא בוצע שינוי. נסה שוב או פנה לתמיכה.' },
        { status: 502 },
      )
    }
    erased = await res.json()
  } catch (e) {
    console.error('[account/delete] erase_account error:', e?.message)
    return Response.json(
      { error: 'delete_failed', message: 'מחיקת החשבון נכשלה ולא בוצע שינוי. נסה שוב או פנה לתמיכה.' },
      { status: 500 },
    )
  }

  // ── 3. Delete the auth user — LAST, so a failure never orphans data ──────────────────────────────────────
  try {
    const res = await fetch(`${url}/auth/v1/admin/users/${qid}`, { method: 'DELETE', headers: svc })
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 200)
      // Detail logged server-side only (A.8.28) — not returned to the client.
      console.error('[account/delete] admin deleteUser failed:', res.status, detail)
      return Response.json(
        { error: 'delete_failed', message: 'מחיקת החשבון נכשלה. נסה שוב או פנה לתמיכה.' },
        { status: 502 },
      )
    }
  } catch (e) {
    console.error('[account/delete] Fatal:', e?.message)
    return Response.json(
      { error: 'delete_failed', message: 'שגיאת שרת במחיקת החשבון.' },
      { status: 500 },
    )
  }

  // Record the erasure SCOPE (append-only trail; audit.user_id has no FK so it
  // survives the user's deletion). Counts only — no PII.
  await writeAudit(context.env, {
    userId: uid,
    action: 'account_deleted',
    target: uid,
    meta: {
      rows: erased?.tables || {},
      files: filesRemoved,
      orgs_deleted: erased?.orgs_deleted ?? 0,
      orgs_anonymised: erased?.orgs_anonymised ?? 0,
      storage_errors: errors.length,
    },
  })

  return Response.json({
    ok: true,
    rows_deleted: erased?.tables || {},
    files_removed: filesRemoved,
    orgs_deleted: erased?.orgs_deleted ?? 0,
    orgs_anonymised: erased?.orgs_anonymised ?? 0,
    // Storage is the one step that is not transactional (object storage has no
    // transaction to join). Repeatable and harmless to retry, so it is reported
    // rather than fatal.
    storage_errors: errors.length ? errors : undefined,
  })
})
