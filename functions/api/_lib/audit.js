/**
 * audit.js — append one entry to the hash-chained audit_log (A.8.15/A.8.16).
 *
 * Server-side only: writes via the service-role key (RLS denies all client
 * writes; the BEFORE INSERT trigger computes the hash chain). Best-effort — an
 * audit failure is logged but NEVER breaks the primary operation.
 *
 * meta must stay small and PII-free (ids/counts/labels, not raw emails/subjects).
 */
import { getSupabaseUrl } from './extractReceipt.js'

export async function writeAudit(env, { orgId = null, userId = null, action, target = null, meta = null }) {
  try {
    const key = env.SUPABASE_SERVICE_ROLE_KEY
    if (!key || !action) return
    const url = getSupabaseUrl(env)
    await fetch(`${url}/rest/v1/audit_log`, {
      method: 'POST',
      headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ org_id: orgId, user_id: userId, action, target, meta }),
    })
  } catch (e) {
    // Never let auditing break the request it's recording.
    console.error('[audit] write failed:', action, e?.message || '')
  }
}

/**
 * Record a REFUSED access attempt (regulation 10 item 6 · ASVS V16.3.2).
 *
 * Until now the audit trail held successes only: eight privileged writes, all
 * of them things that worked. Every 403 returned in silence — a non-owner
 * reaching the admin console, a session without MFA step-up, a bad inbound
 * secret. The events most worth seeing were the only ones leaving no trace,
 * which is backwards: a denial is evidence of an attempt, and a success is
 * merely evidence of normal use.
 *
 * `scope` is the route or component, `reason` is a short machine code
 * ('not_owner', 'mfa_required', 'bad_secret'). Neither carries a value the
 * caller supplied, so a denial cannot be used to write attacker text into the
 * log, and meta stays PII-free like every other entry.
 *
 * Best-effort, like writeAudit: refusing the request is the security control,
 * and recording it must never be able to fail the refusal.
 */
export async function writeDenial(env, { userId = null, orgId = null, scope, reason, request = null }) {
  let method = null, path = null
  try {
    if (request) {
      method = request.method
      path = new URL(request.url).pathname      // path only — never the query string
    }
  } catch { /* URL unparseable → leave null */ }

  return writeAudit(env, {
    userId, orgId,
    action: 'access_denied',
    target: scope,
    meta: { reason, method, path },
  })
}
