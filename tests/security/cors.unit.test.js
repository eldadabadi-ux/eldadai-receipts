/**
 * CORS policy — functions/api/_lib/cors.js (ASVS V3 · ISO A.8.21)
 *
 * The regression this pins: five endpoints used to compute
 * `env.ALLOWED_ORIGIN || origin || '*'`, and ALLOWED_ORIGIN was never set in
 * production — so the API returned Access-Control-Allow-Origin: <whatever the
 * caller sent>. The assertion that matters is therefore not "a header is
 * present" but "an UNKNOWN origin is never echoed".
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveOrigin, corsHeaders, preflight } from '../../functions/api/_lib/cors.js'

const CANONICAL = 'https://app.eldadai.co.il'
const req = (origin) => new Request('https://app.eldadai.co.il/api/chat', {
  headers: origin ? { origin } : {},
})

test('the canonical origin is allowed', () => {
  assert.equal(resolveOrigin(req(CANONICAL), {}), CANONICAL)
})

test('an attacker origin is NEVER echoed back', () => {
  for (const evil of [
    'https://evil.example',
    'https://app.eldadai.co.il.evil.example',   // suffix trick
    'https://appeldadai.co.il',                 // missing dot
    'http://app.eldadai.co.il',                 // downgraded scheme
    'null',
    'https://eldadai.co.il.attacker.pages.dev',
  ]) {
    const got = resolveOrigin(req(evil), {})
    assert.notEqual(got, evil, `echoed back attacker origin: ${evil}`)
    assert.equal(got, CANONICAL)
  }
})

test('a wildcard is never emitted', () => {
  for (const o of [undefined, CANONICAL, 'https://evil.example']) {
    assert.notEqual(corsHeaders(req(o), {})['Access-Control-Allow-Origin'], '*')
  }
})

test('credentials are never allowed — reflection plus credentials is the dangerous pair', () => {
  const h = corsHeaders(req(CANONICAL), {})
  assert.ok(!('Access-Control-Allow-Credentials' in h))
  const p = preflight(req(CANONICAL), {})
  assert.ok(!p.headers.has('access-control-allow-credentials'))
})

test('Vary: Origin is set so a cache cannot serve one origin the other answer', () => {
  assert.equal(corsHeaders(req(CANONICAL), {}).Vary, 'Origin')
  assert.equal(preflight(req(CANONICAL), {}).headers.get('vary'), 'Origin')
})

test('local dev origins work without configuration', () => {
  assert.equal(resolveOrigin(req('http://localhost:5173'), {}), 'http://localhost:5173')
})

test('Pages preview deployments are allowed, lookalikes are not', () => {
  assert.equal(
    resolveOrigin(req('https://abc123.eldadai-receipts.pages.dev'), {}),
    'https://abc123.eldadai-receipts.pages.dev',
  )
  assert.equal(resolveOrigin(req('https://evil.eldadai-receipts.pages.dev.evil.com'), {}), CANONICAL)
  assert.equal(resolveOrigin(req('http://abc.eldadai-receipts.pages.dev'), {}), CANONICAL) // http
})

test('ALLOWED_ORIGIN extends the list without replacing the guard', () => {
  const env = { ALLOWED_ORIGIN: 'https://staging.example, https://qa.example' }
  assert.equal(resolveOrigin(req('https://staging.example'), env), 'https://staging.example')
  assert.equal(resolveOrigin(req('https://qa.example'), env), 'https://qa.example')
  assert.equal(resolveOrigin(req('https://evil.example'), env), CANONICAL)
})

test('a request with no Origin gets the canonical one, not an empty header', () => {
  assert.equal(resolveOrigin(req(undefined), {}), CANONICAL)
})

test('preflight advertises only the headers the API needs', () => {
  const p = preflight(req(CANONICAL), {}, 'POST, OPTIONS')
  assert.equal(p.status, 204)
  assert.equal(p.headers.get('access-control-allow-methods'), 'POST, OPTIONS')
  assert.equal(p.headers.get('access-control-allow-headers'), 'Content-Type, Authorization')
})
