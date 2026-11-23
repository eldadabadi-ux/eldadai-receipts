/**
 * POST /api/account/session-event — record an authentication event (ASVS V16.3.1)
 *
 * The audit trail recorded privileged writes and, since 22.11.26, refused
 * access. It still had no idea when anyone signed IN, so a privileged action
 * could not be tied back to the session that performed it: the log could say
 * "the owner changed a customer's modules at 03:14" and nothing about when or
 * from where that session began.
 *
 * WHAT THIS CAN AND CANNOT COVER, because the difference matters:
 *
 *   - Successful sign-in: yes. The caller presents a token, requireUser
 *     verifies it against Supabase, and only then is anything written — so the
 *     record attests to a session that demonstrably exists. A client cannot
 *     forge an entry for someone else.
 *
 *   - FAILED sign-in: no, and it cannot be done from here. A failed attempt
 *     produces no token, so there is nothing for this endpoint to verify, and
 *     an unauthenticated write endpoint would be a way to flood the audit log
 *     with invented failures. Those live in Supabase's own auth logs. The gap
 *     is recorded in docs/SECURITY-POLICY.md §8 rather than papered over with
 *     a record nobody can trust.
 *
 * Called at the point of an explicit sign-in action, NOT from an auth-state
 * listener: that listener also fires on token refresh and on page load with an
 * existing session, which would turn one login into dozens of entries and make
 * the trail useless exactly where it needs to be readable.
 */

import { requireMember, wrapAuthErrors } from '../_lib/auth.js'
import { writeAudit } from '../_lib/audit.js'
import { checkRateLimit, rateLimitedResponse } from '../_lib/rateLimit.js'

/** Events a client may report. An allowlist, so the action column stays closed. */
const EVENTS = {
  signed_in: 'session_started',
  signed_out_others: 'other_sessions_revoked',
}

export const onRequestPost = wrapAuthErrors(async (context) => {
  const user = await requireMember(context.request, context.env)

  // A session event is one write per sign-in. Anything beyond a handful an
  // hour is a loop or an attempt to bury something in noise.
  const rl = await checkRateLimit(context.env, `${user.user_id}:session-event`, { limit: 20, windowSec: 3600 })
  if (!rl.allowed) return rateLimitedResponse(rl.retryAfter)

  let body
  try { body = await context.request.json() } catch { body = {} }

  const action = EVENTS[String(body?.event || '')]
  if (!action) return Response.json({ error: 'bad_event' }, { status: 400 })

  // `method` is the login route the user took. Allowlisted, never free text —
  // a value written into an append-only log must not be caller-chosen prose.
  const method = ['password', 'passkey', 'unknown'].includes(body?.method) ? body.method : 'unknown'

  let ip = null
  try { ip = context.request.headers.get('cf-connecting-ip') || null } catch { /* none */ }

  await writeAudit(context.env, {
    userId: user.user_id,
    orgId: user.org_id,
    action,
    target: 'session',
    // No user agent: it is long, caller-controlled, and would be the one free
    // text field in the log. The method and the source address answer the
    // questions an investigation actually asks.
    meta: { method, ip, aal: user.aal },
  })

  return Response.json({ ok: true })
})
