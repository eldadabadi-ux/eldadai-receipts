/**
 * GET /api/admin/chain-check — is the audit trail still intact? (ISO A.8.16)
 *
 * WHY THIS EXISTS, precisely: the hash chain broke on 12.11.2026 and was found
 * on 22.11. Ten days. Not by monitoring — by someone writing a test that
 * happened to call the verifier. The control had been recorded as working in
 * two compliance reports, and nobody had ever run it.
 *
 * A tamper-evidence mechanism nobody polls is a tamper-evidence mechanism that
 * reports a breach whenever you next happen to look. The admin console shows a
 * badge, which is pull-based and therefore has the same flaw.
 *
 * Two callers:
 *   - the scheduled job (x-cron-secret), which turns a broken chain into a
 *     FAILED CI run, and therefore into a notification;
 *   - the platform owner, interactively, with the same MFA step-up as every
 *     other admin route.
 *
 * Returns 200 {ok:true} when intact and **503** when broken — a non-2xx on
 * purpose, so any uptime check pointed at this URL also reports it without
 * needing to understand the body.
 */
import { constantTimeEqual, wrapAuthErrors } from '../_lib/auth.js'
import { guardOwner, sbUrl } from '../_lib/guards.js'
import { writeAudit } from '../_lib/audit.js'

const json = (b, s = 200) => Response.json(b, { status: s, headers: { 'Content-Type': 'application/json' } })

export const onRequestGet = wrapAuthErrors(async (context) => {
  const { request, env } = context

  // ── Who is asking ─────────────────────────────────────────────────────────
  const presented = request.headers.get('x-cron-secret') || ''
  const isCron = !!env.CRON_SECRET && constantTimeEqual(presented, env.CRON_SECRET)

  let key = env.SUPABASE_SERVICE_ROLE_KEY
  let url = sbUrl(env)

  if (!isCron) {
    // Not the scheduler → must be the owner, MFA and all.
    const g = await guardOwner(context)
    if (g.res) return g.res
    key = g.key
    url = g.url
  }
  if (!key) return json({ error: 'server_config' }, 500)

  // ── Ask the database ──────────────────────────────────────────────────────
  let row
  try {
    const res = await fetch(`${url}/rest/v1/rpc/verify_audit_chain`, {
      method: 'POST',
      headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: '{}',
    })
    if (!res.ok) {
      // Unable to check is NOT the same as intact, and must not read as a pass.
      console.error('[chain-check] verifier unreachable:', res.status)
      return json({ ok: false, status: 'unknown', message: 'could not run the verifier' }, 503)
    }
    const out = await res.json()
    row = Array.isArray(out) ? out[0] : out
  } catch (e) {
    console.error('[chain-check] error:', e?.message)
    return json({ ok: false, status: 'unknown', message: 'could not run the verifier' }, 503)
  }

  const intact = !!row?.ok
  const body = {
    ok: intact,
    status: intact ? 'intact' : 'broken',
    broken_id: row?.broken_id ?? null,
    checked: row?.checked ?? null,
    // Present once supabase_audit_chain_fix.sql has been applied: how many rows
    // sit before the baseline and are therefore NOT covered by this verdict.
    baseline_id: row?.baseline_id ?? null,
    skipped: row?.skipped ?? null,
  }

  if (!intact) {
    // Record the detection itself. The chain is append-only, so noticing a
    // break is a new event and belongs in the log beside it — and it gives the
    // investigation a timestamp for when it was first seen.
    await writeAudit(env, {
      action: 'audit_chain_broken',
      target: 'audit_log',
      meta: { broken_id: body.broken_id, checked: body.checked, by: isCron ? 'scheduled' : 'owner' },
    })
    console.error('[chain-check] AUDIT CHAIN BROKEN at row', body.broken_id)
    return json(body, 503)
  }

  return json(body, 200)
})
