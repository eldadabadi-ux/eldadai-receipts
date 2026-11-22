/**
 * Authorisation wiring — static assertions over functions/api/
 * (ASVS V8 · ISO A.5.15, A.5.17, A.8.2)
 *
 * A live IDOR suite would need two provisioned tenants and the network; the RLS
 * pentest already does that for the data layer. What was missing is cheaper and
 * catches a different mistake: a new endpoint file that simply FORGETS its
 * guard. That is a structural property of the source, so it is checked here,
 * offline, on every push.
 *
 * The rule each test encodes is "no route may be added without a guard", not
 * "these specific routes have guards" — a new file is covered the day it lands.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

// fileURLToPath, not URL.pathname — the repo path contains spaces, and pathname
// hands them back percent-encoded.
const API_DIR = fileURLToPath(new URL('../../functions/api', import.meta.url))

function routeFiles(dir = API_DIR, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name !== '_lib') routeFiles(p, out)
    } else if (name.endsWith('.js')) {
      out.push(p)
    }
  }
  return out
}

const routes = routeFiles().map(p => ({
  path: relative(API_DIR, p).replace(/\\/g, '/'),
  src: readFileSync(p, 'utf8'),
}))

const handlers = (src) => [...src.matchAll(/export\s+(?:const|async\s+function)\s+(onRequest\w*)/g)]
  .map(m => m[1])

test('the route inventory is non-empty (the walker actually found files)', () => {
  assert.ok(routes.length >= 10, `only found ${routes.length} route files`)
})

test('every state-changing or data-returning route authenticates', () => {
  for (const r of routes) {
    const verbs = handlers(r.src).filter(h => h !== 'onRequestOptions')
    if (!verbs.length) continue

    const guarded =
      /requireUser|requireMember/.test(r.src) ||      // user session
      /guardOwner/.test(r.src) ||                     // platform owner
      /INBOUND_SECRET/.test(r.src)                    // server-to-server shared secret

    assert.ok(guarded, `${r.path} exposes ${verbs.join(', ')} with no authentication guard`)
  }
})

test('every admin route uses the SHARED owner guard, never its own copy', () => {
  const admin = routes.filter(r => r.path.startsWith('admin/'))
  assert.ok(admin.length >= 4, 'admin routes not found')
  for (const r of admin) {
    assert.match(r.src, /import\s*\{[^}]*guardOwner[^}]*\}\s*from\s*['"]\.\.\/_lib\/guards\.js['"]/,
      `${r.path} does not import the shared guardOwner`)
    assert.ok(!/async function guardOwner/.test(r.src),
      `${r.path} defines a LOCAL guardOwner — that is how admin/audit lost its MFA step-up`)
    assert.ok(!/SUPERADMIN_FALLBACK/.test(r.src),
      `${r.path} hardcodes the superadmin email instead of using the shared guard`)
  }
})

test('the shared guard still enforces owner AND step-up AND throttling', () => {
  const src = readFileSync(join(API_DIR, '_lib/guards.js'), 'utf8')
  assert.match(src, /isSuperadmin/, 'owner check missing')
  assert.match(src, /aal2/, 'MFA step-up check missing')
  assert.match(src, /mfa_required/, 'mfa_required response missing')
  assert.match(src, /checkRateLimit/, 'admin console throttle missing')
})

test('the inbound webhook compares its secret in constant time', () => {
  const r = routes.find(x => x.path === 'inbound.js')
  assert.ok(r, 'inbound.js missing')
  assert.match(r.src, /constantTimeEqual\(/, 'inbound secret compared with ===')
  assert.ok(!/secret\s*===\s*env\.INBOUND_SECRET/.test(r.src), 'timing-unsafe comparison present')
})

test('no route uses a client-supplied tenant id as its only scope', () => {
  for (const r of routes) {
    // body.org_id / query org_id flowing straight into a PostgREST predicate.
    const fromBody = /org_id=eq\.\$\{[^}]*\bbody\b[^}]*\}/.test(r.src)
      || /org_id=eq\.\$\{[^}]*searchParams[^}]*\}/.test(r.src)
    assert.ok(!fromBody, `${r.path} scopes a query by a CLIENT-supplied org_id (guardrail 3)`)
  }
})

test('every value interpolated into a PostgREST query string is encoded', () => {
  // A raw '#' ends the URL at the fragment, dropping the tenant predicate from a
  // service-role request. Interpolations must be encoded, or come from a known
  // server-side id (user.user_id, a row id already read back from the database).
  // `qid` and `t` are the encoded uid and a table name from a literal array in
  // account/delete.js — named explicitly rather than pattern-matched, so a new
  // bare interpolation cannot inherit the exemption by accident.
  const SAFE = /^(q\(|encodeURIComponent\(|inList\(|scope|scopeOf\(|limit\b|pathQs\b|qs\b|path\b|table\b|qid\b|t\b)/
  const offenders = []
  for (const r of routes) {
    for (const m of r.src.matchAll(/rest\/v1\/[^`"']*?\$\{([^}]+)\}/g)) {
      const expr = m[1].trim()
      if (SAFE.test(expr)) continue
      if (/^(user|caller)\.(user_id|org_id)$/.test(expr)) continue   // server-derived uuid
      if (/^(cur|existing\[0\]|org)\.id$/.test(expr)) continue       // id read back from the DB
      offenders.push(`${r.path}: \${${expr}}`)
    }
  }
  assert.deepEqual(offenders, [], 'unencoded interpolation into a PostgREST query string')
})

test('no route returns UPSTREAM error text to the client', () => {
  // Echoing the caller's own invalid input back (`detail: key`) is fine and
  // useful. What must never cross the boundary is an upstream body — PostgREST
  // constraint and column names, Supabase or Gemini error prose — which maps the
  // schema for whoever receives it. The distinction is the SOURCE of the string,
  // so this matches res.text()/err.message flowing into a response rather than
  // the word "detail". admin/clients.js failed this on 22.11.26.
  const UPSTREAM_BODY = /Response\.json\(\s*\{[^}]*:\s*\(?\s*await\s+\w*[Rr]es\w*\.text\(\)/
  const RAW_ERROR = /Response\.json\(\s*\{[^}]*:\s*err(or)?\??\.(message|stack)/
  for (const r of routes) {
    assert.ok(!UPSTREAM_BODY.test(r.src),
      `${r.path} returns an upstream response body to the caller (A.8.28)`)
    assert.ok(!RAW_ERROR.test(r.src),
      `${r.path} returns a raw error message to the caller (A.8.28)`)
  }
})
