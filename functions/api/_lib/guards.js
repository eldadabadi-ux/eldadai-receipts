/**
 * guards — the ONE platform-owner check (A.5.15, A.5.17, A.8.2).
 *
 * WHY this file exists: the same guard was copy-pasted into four admin
 * endpoints, and the copies drifted. /api/admin/audit — which reads EVERY
 * tenant's audit trail with the service-role key — kept only the email half and
 * never grew the MFA step-up the other three enforce, so the most sensitive
 * read in the product was the one reachable from a password-only session.
 * A duplicated security control does not stay duplicated; it stays *almost*
 * duplicated. Import this instead.
 *
 * Usage:
 *   const g = await guardOwner(context)
 *   if (g.res) return g.res              // 403 / 500 — short-circuit
 *   const { caller, url, key, headers } = g
 */

import { requireUser } from './auth.js'
import { checkRateLimit, rateLimitedResponse } from './rateLimit.js'

// Platform owner — configurable via the Cloudflare env (SUPERADMIN_EMAIL); the
// fallback keeps the console reachable if the var is ever missing.
const SUPERADMIN_FALLBACK = 'eldadabadi@gmail.com'

const JSON_HEADERS = { 'Content-Type': 'application/json' }

export const sbUrl = (env) =>
  env.VITE_SUPABASE_URL || env.SUPABASE_URL || 'https://dsoucojqjrodxozcbicf.supabase.co'

export const isSuperadmin = (email, env) =>
  (email || '').toLowerCase() === (env.SUPERADMIN_EMAIL || SUPERADMIN_FALLBACK).toLowerCase()

/**
 * Authenticate, require the platform owner, and require MFA step-up (AAL2) once
 * the owner has a verified TOTP factor.
 *
 * The factor lookup is best-effort: if Supabase cannot be reached we do NOT
 * hard-block, because a transient auth-admin outage would otherwise lock the
 * owner out of their own console. The email check above it is unconditional, so
 * the worst case degrades to the pre-MFA control, never to open access.
 *
 * @returns {{res:Response}} on refusal, or {caller,key,url,headers} when cleared.
 */
export async function guardOwner(context) {
  const caller = await requireUser(context.request, context.env)

  if (!isSuperadmin(caller.email, context.env)) {
    return { res: Response.json({ error: 'forbidden' }, { status: 403, headers: JSON_HEADERS }) }
  }

  // Throttle the console as a whole (A.8.12). These routes run service-role
  // writes across every tenant, so the one account that can reach them is also
  // the one worth grinding with a stolen token.
  const rl = await checkRateLimit(context.env, `${caller.user_id}:admin`, { limit: 60, windowSec: 60 })
  if (!rl.allowed) return { res: rateLimitedResponse(rl.retryAfter) }

  const key = context.env.SUPABASE_SERVICE_ROLE_KEY
  if (!key) {
    return { res: Response.json({ error: 'server_config' }, { status: 500, headers: JSON_HEADERS }) }
  }

  const url = sbUrl(context.env)
  const svc = { apikey: key, Authorization: `Bearer ${key}` }

  try {
    const fRes = await fetch(`${url}/auth/v1/admin/users/${encodeURIComponent(caller.user_id)}`, { headers: svc })
    if (fRes.ok) {
      const factors = (await fRes.json())?.factors || []
      const hasTotp = factors.some(
        f => f.status === 'verified' && (f.factor_type === 'totp' || f.type === 'totp'),
      )
      if (hasTotp && caller.aal !== 'aal2') {
        return {
          res: Response.json(
            { error: 'mfa_required', message: 'נדרש אימות דו-שלבי (2FA).' },
            { status: 403, headers: JSON_HEADERS },
          ),
        }
      }
    }
  } catch { /* factor lookup unreachable → keep the email guard, don't lock the owner out */ }

  return { caller, key, url, headers: { ...svc, 'Content-Type': 'application/json' } }
}
