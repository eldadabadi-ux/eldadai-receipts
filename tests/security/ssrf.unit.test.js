/**
 * SSRF allowlist — functions/api/_lib/safeFetch.js (ASVS V5 · ISO A.8.28)
 *
 * safeFetch downloads a receipt from a URL the USER pasted, from inside a
 * Cloudflare Worker that holds the service-role key. If a crafted URL can point
 * it at an internal address, the attacker borrows the server's network position.
 *
 * These assertions are the matrix of what must stay blocked. They need no
 * network: assertSafeUrl is a pure function, which is exactly why it is worth
 * testing exhaustively rather than by sampling.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertSafeUrl } from '../../functions/api/_lib/safeFetch.js'

const blocked = (url) => {
  assert.throws(() => assertSafeUrl(url), (e) => e.code === 'BLOCKED_URL',
    `expected BLOCKED_URL for ${url}`)
}
const allowed = (url) => {
  assert.doesNotThrow(() => assertSafeUrl(url), `expected ${url} to be allowed`)
}

test('loopback is blocked in every spelling', () => {
  for (const u of [
    'http://127.0.0.1/x',
    'http://127.1.2.3/x',
    'https://localhost/x',
    'http://sub.localhost/x',
    'http://[::1]/x',
    'http://0.0.0.0/x',
  ]) blocked(u)
})

test('RFC1918 private ranges are blocked', () => {
  for (const u of [
    'http://10.0.0.1/x',
    'http://10.255.255.254/x',
    'http://172.16.0.1/x',
    'http://172.31.255.1/x',
    'http://192.168.1.1/x',
  ]) blocked(u)
})

test('172.32 and 172.15 are NOT private and stay reachable', () => {
  allowed('http://172.32.0.1/x')
  allowed('http://172.15.0.1/x')
})

test('cloud metadata endpoints are blocked', () => {
  blocked('http://169.254.169.254/latest/meta-data/')
  blocked('http://metadata.google.internal/computeMetadata/v1/')
  blocked('http://metadata/computeMetadata/v1/')
})

test('link-local, CGNAT, benchmarking and multicast are blocked', () => {
  for (const u of [
    'http://169.254.1.1/x',     // link-local
    'http://100.64.0.1/x',      // CGNAT 100.64/10
    'http://198.18.0.1/x',      // benchmarking
    'http://224.0.0.1/x',       // multicast
    'http://240.0.0.1/x',       // reserved
    'http://192.0.0.1/x',       // IETF protocol assignments
  ]) blocked(u)
})

test('internal TLDs are blocked', () => {
  blocked('http://db.internal/x')
  blocked('http://printer.local/x')
})

test('IPv6 ULA, link-local and IPv4-mapped private are blocked', () => {
  for (const u of [
    'http://[fc00::1]/x',
    'http://[fd12:3456::1]/x',
    'http://[fe80::1]/x',
    'http://[::ffff:127.0.0.1]/x',
    'http://[::ffff:10.0.0.1]/x',
  ]) blocked(u)
})

test('non-http schemes are blocked', () => {
  for (const u of [
    'file:///etc/passwd',
    'gopher://127.0.0.1:25/x',
    'ftp://example.com/x',
    'data:text/html,<script>1</script>',
    'javascript:alert(1)',
  ]) blocked(u)
})

test('embedded credentials are blocked', () => {
  blocked('http://user:pass@example.com/x')
  blocked('https://admin@example.com/x')
})

test('malformed input is blocked, not thrown raw', () => {
  for (const u of ['', 'not a url', '///', null, undefined]) blocked(u)
})

test('ordinary public URLs still pass', () => {
  allowed('https://example.com/receipt.pdf')
  allowed('http://8.8.8.8/x')
  allowed('https://files.supplier.co.il/invoice/123.pdf')
})

/**
 * Regression for the bypass this suite found on 22.11.26.
 *
 * `new URL()` normalises an IPv4-mapped address before the guard ever sees the
 * hostname: `[::ffff:127.0.0.1]` arrives as `::ffff:7f00:1`. The old check
 * matched on the DOTTED-QUAD text, which after parsing can never appear - so
 * the branch meant to stop IPv4-mapped addresses was unreachable, and loopback,
 * RFC1918 and the cloud metadata endpoint were all reachable through it.
 *
 * These assert on the parsed form as well as the written one, because the
 * written one is not what the guard is handed.
 */
test('IPv4-mapped IPv6 cannot smuggle an internal address past the guard', () => {
  for (const u of [
    'http://[::ffff:127.0.0.1]/x',
    'http://[::ffff:7f00:1]/x',              // same address, as the URL parser yields it
    'http://[::ffff:10.0.0.1]/x',
    'http://[::ffff:a00:1]/x',
    'http://[::ffff:192.168.1.1]/x',
    'http://[::ffff:169.254.169.254]/x',     // cloud metadata
    'http://[::ffff:a9fe:a9fe]/x',
    'http://[0:0:0:0:0:ffff:127.0.0.1]/x',   // uncompressed spelling
  ]) blocked(u)
})

test('IPv4-compatible and NAT64 spellings are blocked too', () => {
  blocked('http://[::127.0.0.1]/x')          // ::a.b.c.d
  blocked('http://[::a00:1]/x')              // ::10.0.0.1
  blocked('http://[64:ff9b::127.0.0.1]/x')   // NAT64
  blocked('http://[64:ff9b::a9fe:a9fe]/x')   // NAT64 → metadata
})

test('a mapped PUBLIC address is still allowed', () => {
  allowed('http://[::ffff:8.8.8.8]/x')
  allowed('http://[2606:4700::1111]/x')      // ordinary public IPv6
})

test('unparseable IPv6 is refused rather than waved through', () => {
  blocked('http://[1:2:3::4::5]/x')          // two "::" groups
  blocked('http://[12345::1]/x')             // hextet out of range
})
