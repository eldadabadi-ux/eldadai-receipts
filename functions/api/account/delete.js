/**
 * Cloudflare Pages Function — POST /api/account/delete  (auth: Bearer JWT)
 *
 * GDPR Art.17 / right-to-erasure. Purges ALL of the signed-in user's data —
 * every tenant table, every stored file, their memberships, and the auth user
 * itself. The anon client cannot do this: it needs the service-role key, which
 * lives only on the server.
 *
 * Order: files → rows → organizations → auth user. Data first, login last, so a
 * partial failure never orphans data behind a deleted login (the user retries).
 *
 * WHY the explicit row deletion, when every tenant table already carries
 * `user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE`: the cascade is the
 * backstop, not the guarantee. A table shipped without the FK, or a row whose
 * user_id was nulled, would survive silently and nobody would know. Deleting
 * explicitly makes the erasure scope auditable — the response and the audit row
 * say which tables were cleared and how many objects were removed.
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

const RECEIPTS_BUCKET = 'receipts'
const LIST_PAGE = 100          // Storage list page size
const DELETE_CHUNK = 100       // objects removed per request
const MAX_OBJECTS = 20000      // hard stop; a runaway prefix must not hang the worker

/**
 * Every table keyed by user_id, children before parents.
 *
 * Order matters even with ON DELETE CASCADE: deleting a parent first makes the
 * child's delete a no-op that still reports 200, which would hide a missing
 * cascade instead of surfacing it.
 */
const USER_TABLES = [
  'sales_lines',
  'sales_days',
  'event_items',
  'event_quotes',
  'supplier_budgets',
  'supplier_aliases',
  'receipts',
  'receipt_books',
  'categories',
  'suppliers',
  'mail_connections',
  'user_settings',
  'memberships',
]

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

  // ── 2. Organizations the user owns — resolved BEFORE the auth delete, which
  //       would null owner_id out from under us (owner_id … ON DELETE SET NULL).
  let ownedOrgs = []
  try {
    const res = await fetch(`${url}/rest/v1/organizations?owner_id=eq.${qid}&select=id`, { headers: svc })
    if (res.ok) ownedOrgs = (await res.json()).map(o => o?.id).filter(Boolean)
  } catch (e) {
    errors.push(`orgs-list:${e?.message || 'err'}`)
  }

  // ── 3. Delete the user's rows, children first ──────────────────────────────
  const cleared = []
  for (const t of USER_TABLES) {
    try {
      const res = await fetch(`${url}/rest/v1/${t}?user_id=eq.${qid}`, {
        method: 'DELETE',
        headers: { ...svc, Prefer: 'return=minimal' },
      })
      // 404 = table doesn't exist in this project → ignore.
      if (res.ok) cleared.push(t)
      else if (res.status !== 404) errors.push(`${t}:${res.status}`)
    } catch (e) {
      errors.push(`${t}:${e?.message || 'err'}`)
    }
  }

  // ── 4. Organizations left with no members ──────────────────────────────────
  // Deleted outright when nothing of the operator's hangs off them (the delete
  // cascades feature_flags and any org-scoped leftovers). When a client_accounts
  // row exists it is the operator's own bookkeeping, so the org is ANONYMISED
  // instead — the billing record survives without the business's identity.
  let orgsDeleted = 0, orgsAnonymised = 0
  for (const orgId of ownedOrgs) {
    try {
      const mem = await fetch(
        `${url}/rest/v1/memberships?org_id=eq.${encodeURIComponent(orgId)}&select=user_id&limit=1`,
        { headers: svc })
      if (!mem.ok) { errors.push(`org-members:${mem.status}`); continue }
      if ((await mem.json()).length > 0) continue      // someone else still works here

      const ca = await fetch(
        `${url}/rest/v1/client_accounts?org_id=eq.${encodeURIComponent(orgId)}&select=org_id&limit=1`,
        { headers: svc })
      const hasBilling = ca.ok && (await ca.json()).length > 0

      if (hasBilling) {
        const an = await fetch(`${url}/rest/v1/organizations?id=eq.${encodeURIComponent(orgId)}`, {
          method: 'PATCH',
          headers: { ...svc, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
          body: JSON.stringify({ name: 'חשבון שנמחק', business_name: null, logo: null, slug: null }),
        })
        if (an.ok) orgsAnonymised++; else errors.push(`org-anon:${an.status}`)
      } else {
        const del = await fetch(`${url}/rest/v1/organizations?id=eq.${encodeURIComponent(orgId)}`, {
          method: 'DELETE',
          headers: { ...svc, Prefer: 'return=minimal' },
        })
        if (del.ok) orgsDeleted++; else errors.push(`org-del:${del.status}`)
      }
    } catch (e) {
      errors.push(`org:${e?.message || 'err'}`)
    }
  }

  // ── 5. Delete the auth user (must succeed) ─────────────────────────────────
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
      tables: cleared.length,
      files: filesRemoved,
      orgs_deleted: orgsDeleted,
      orgs_anonymised: orgsAnonymised,
      errors: errors.length,
    },
  })

  return Response.json({
    ok: true,
    tables_cleared: cleared.length,
    files_removed: filesRemoved,
    orgs_deleted: orgsDeleted,
    orgs_anonymised: orgsAnonymised,
    errors: errors.length ? errors : undefined,
  })
})
