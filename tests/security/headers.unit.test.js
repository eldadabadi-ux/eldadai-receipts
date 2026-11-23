/**
 * Response hardening — public/_headers (ASVS V13 · ISO A.8.9, A.8.24)
 *
 * These headers are a single untyped text file that Cloudflare Pages serves
 * verbatim. Nothing in the build validates it, so a deleted line or a CSP
 * loosened "just to get a library working" ships silently and nobody notices
 * until an audit. That is what this suite is for — it is a diff alarm on the
 * security posture, not a test of application behaviour.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const raw = readFileSync(new URL('../../public/_headers', import.meta.url), 'utf8')

// Only the global /* block — later path blocks are cache rules.
const globalBlock = raw.split(/\n(?=\/)/)[0]
const header = (name) => {
  const m = globalBlock.match(new RegExp(`^\\s*${name}:\\s*(.+)$`, 'im'))
  return m ? m[1].trim() : null
}

const csp = header('Content-Security-Policy') || ''
const directive = (name) => {
  const m = csp.match(new RegExp(`(?:^|;)\\s*${name}\\s+([^;]+)`, 'i'))
  return m ? m[1].trim().split(/\s+/) : []
}

test('HSTS is set, long, and preload-eligible', () => {
  const h = header('Strict-Transport-Security')
  assert.ok(h, 'Strict-Transport-Security missing')
  const maxAge = Number(/max-age=(\d+)/.exec(h)?.[1] || 0)
  assert.ok(maxAge >= 31536000, `max-age too short: ${maxAge}`)
  assert.match(h, /includeSubDomains/i)
  assert.match(h, /preload/i)
})

test('clickjacking is blocked at both layers', () => {
  assert.equal(header('X-Frame-Options'), 'DENY')
  assert.deepEqual(directive('frame-ancestors'), ["'none'"])
})

test('MIME sniffing is off', () => {
  assert.equal(header('X-Content-Type-Options'), 'nosniff')
})

test('the referrer never leaks a path cross-origin', () => {
  assert.match(header('Referrer-Policy') || '', /^(strict-origin-when-cross-origin|no-referrer|same-origin|strict-origin)$/)
})

test('powerful features are denied except the camera the scanner needs', () => {
  const pp = header('Permissions-Policy') || ''
  assert.match(pp, /camera=\(self\)/)
  for (const f of ['microphone', 'geolocation', 'payment']) {
    assert.match(pp, new RegExp(`${f}=\\(\\)`), `${f} not denied`)
  }
})

test('cross-origin isolation headers are present', () => {
  assert.ok(header('Cross-Origin-Opener-Policy'), 'COOP missing')
  assert.ok(header('Cross-Origin-Resource-Policy'), 'CORP missing')
})

test('a CSP exists with a locked-down default', () => {
  assert.ok(csp, 'Content-Security-Policy missing')
  assert.deepEqual(directive('default-src'), ["'self'"])
  assert.deepEqual(directive('base-uri'), ["'self'"])
  assert.deepEqual(directive('object-src'), ["'none'"])
  assert.deepEqual(directive('form-action'), ["'self'"])
})

test('scripts are never inline-executable and never eval-able', () => {
  const s = directive('script-src')
  assert.ok(s.length, 'script-src missing')
  assert.ok(!s.includes("'unsafe-inline'"), "script-src must not allow 'unsafe-inline'")
  assert.ok(!s.includes("'unsafe-eval'"), "script-src must not allow 'unsafe-eval'")
  assert.ok(!s.includes('*'), 'script-src must not be a wildcard')
  assert.ok(!s.includes('data:'), 'script-src must not allow data: URIs')
})

/**
 * script-src carries two documented exceptions (cdn.jsdelivr.net and blob:)
 * because tesseract.js loads its worker from there — that is the ON-DEVICE OCR
 * path, where a receipt image never leaves the phone. This test does not demand
 * their removal; it demands that the list NEVER GROWS without someone changing
 * this file, so a third-party script origin cannot be added quietly.
 */
test('the set of third-party script origins is exactly the documented one', () => {
  const external = directive('script-src').filter(v => v.startsWith('http'))
  assert.deepEqual(external, ['https://cdn.jsdelivr.net'],
    'a script origin was added or removed — update the audit, not just the header')
})

test('connect-src is an allowlist, not a wildcard', () => {
  const c = directive('connect-src')
  assert.ok(c.includes("'self'"))
  assert.ok(!c.includes('*'), 'connect-src must not be a wildcard')
})

test('HTML and the service worker are never cached', () => {
  for (const block of ['/*.html', '/sw.js', '/version.json']) {
    const idx = raw.indexOf(block)
    assert.ok(idx > -1, `${block} block missing`)
    assert.match(raw.slice(idx, idx + 200), /no-store/i, `${block} is cacheable`)
  }
})
