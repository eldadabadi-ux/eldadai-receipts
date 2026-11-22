/**
 * cors — the one CORS policy for /api/* (A.8.21, ASVS V3 / V13).
 *
 * WHY this replaced the per-file version: five endpoints each computed
 *
 *     const allowed = env.ALLOWED_ORIGIN || origin || '*'
 *
 * and ALLOWED_ORIGIN was never set in wrangler.toml, so the live middle term
 * won every time — the API echoed back whatever Origin the caller sent. A
 * reflected origin is not a catastrophe here (these routes authenticate with a
 * Bearer JWT, not cookies, and no Allow-Credentials is ever emitted, so a
 * cross-site page still cannot borrow the victim's session) but it is an
 * allowlist that allows everything, and it quietly invited the mistake that
 * WOULD be a catastrophe: adding Allow-Credentials later.
 *
 * The allowlist is explicit, with ALLOWED_ORIGIN as the escape hatch (comma-
 * separated for preview deployments). An origin that is not on it gets the
 * canonical origin back, so the browser blocks the read — the request itself
 * still runs and is still authorised by the JWT, exactly as before.
 */

const CANONICAL = 'https://app.eldadai.co.il'

// Fixed entries. Pages preview builds and local dev are matched by pattern below.
const STATIC_ALLOWED = [
  CANONICAL,
  'http://localhost:5173',
  'http://localhost:4173',
  'http://127.0.0.1:5173',
]

// *.eldadai-receipts.pages.dev — Cloudflare Pages preview deployments.
const PREVIEW_RE = /^https:\/\/[a-z0-9-]+\.eldadai-receipts\.pages\.dev$/i

function allowList(env) {
  const extra = String(env?.ALLOWED_ORIGIN || '')
    .split(',').map(s => s.trim()).filter(Boolean)
  return [...STATIC_ALLOWED, ...extra]
}

/** The origin to echo: the caller's only when it is on the list. */
export function resolveOrigin(request, env) {
  const origin = (request?.headers?.get('origin') || '').trim()
  if (!origin) return CANONICAL
  const list = allowList(env)
  if (list.includes(origin) || PREVIEW_RE.test(origin)) return origin
  return list[0] || CANONICAL
}

/** Headers for an actual (non-preflight) JSON response. */
export function corsHeaders(request, env) {
  return {
    'Access-Control-Allow-Origin': resolveOrigin(request, env),
    Vary: 'Origin',
    'Content-Type': 'application/json',
  }
}

/** 204 preflight response. `methods` is the route's own verb list. */
export function preflight(request, env, methods = 'POST, OPTIONS') {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': resolveOrigin(request, env),
      Vary: 'Origin',
      'Access-Control-Allow-Methods': methods,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    },
  })
}
