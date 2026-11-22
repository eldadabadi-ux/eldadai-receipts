/**
 * safeFetch — SSRF-hardened fetch for user-supplied URLs (link import).
 *
 * Guards against Server-Side Request Forgery when we download a receipt/invoice
 * from a link a user pasted or shared:
 *   - http/https only; no embedded credentials.
 *   - blocks localhost, private/reserved/link-local IPs, and cloud metadata.
 *   - manual redirect following with per-hop re-validation (capped).
 *   - response size cap + timeout.
 *
 * Returns { status, contentType, finalUrl, bytes:Uint8Array }.
 * Throws Error with .code ('BLOCKED_URL' | 'TOO_LARGE' | 'TIMEOUT' | 'TOO_MANY_REDIRECTS').
 */

const DEFAULT_MAX_BYTES   = 15 * 1024 * 1024  // 15 MB
const DEFAULT_MAX_REDIR   = 4
const DEFAULT_TIMEOUT_MS  = 15000

function blockedError(message) { const e = new Error(message); e.code = 'BLOCKED_URL'; return e }

// IPv4 literal → blocked if in a private/reserved range.
function isBlockedIPv4(ip) {
  const p = ip.split('.').map(Number)
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false
  const [a, b] = p
  if (a === 10) return true                          // 10/8
  if (a === 127) return true                         // loopback
  if (a === 0) return true                           // 0/8
  if (a === 169 && b === 254) return true            // link-local + cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true   // 172.16/12
  if (a === 192 && b === 168) return true            // 192.168/16
  if (a === 192 && b === 0) return true              // 192.0.0/24 + 192.0.2/24
  if (a === 198 && (b === 18 || b === 19)) return true // 198.18/15 benchmarking
  if (a === 100 && b >= 64 && b <= 127) return true  // 100.64/10 CGNAT
  if (a >= 224) return true                          // multicast/reserved 224/4, 240/4
  return false
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/

function isBlockedHost(hostname) {
  let h = (hostname || '').toLowerCase().trim()
  if (!h) return true
  // strip IPv6 brackets
  const v6 = h.startsWith('[') && h.endsWith(']')
  if (v6) h = h.slice(1, -1)

  if (h === 'localhost' || h.endsWith('.localhost')) return true
  if (h.endsWith('.local') || h.endsWith('.internal')) return true
  if (h === 'metadata.google.internal' || h === 'metadata') return true

  if (IPV4_RE.test(h)) return isBlockedIPv4(h)

  if (v6 || h.includes(':')) return isBlockedIPv6(h)
  return false
}

/**
 * Expand an IPv6 literal to its 8 hextets, or null if it is not one.
 *
 * Needed because matching on the TEXT of an address does not work: `new URL()`
 * normalises before we ever see the hostname, so `[::ffff:127.0.0.1]` arrives
 * as `::ffff:7f00:1`. A check written against the dotted-quad spelling can
 * therefore never fire — see isBlockedIPv6 below.
 */
function expandIPv6(h) {
  let str = String(h || '').toLowerCase()
  if (!str.includes(':')) return null

  // A trailing dotted quad (::ffff:127.0.0.1) becomes two hextets.
  const tail = str.match(/(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (tail) {
    const o = tail[1].split('.').map(Number)
    if (o.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null
    const hex = [((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16)]
    str = str.slice(0, -tail[1].length) + hex.join(':')
  }

  const halves = str.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':').filter(Boolean) : []
  const back = halves.length === 2 ? (halves[1] ? halves[1].split(':').filter(Boolean) : []) : null

  let parts
  if (back === null) {
    parts = head
  } else {
    const fill = 8 - head.length - back.length
    if (fill < 0) return null
    parts = [...head, ...Array(fill).fill('0'), ...back]
  }
  if (parts.length !== 8) return null

  const out = parts.map(p => parseInt(p || '0', 16))
  return out.some(n => !Number.isInteger(n) || n < 0 || n > 0xffff) ? null : out
}

/** Dotted quad from the last two hextets of an embedded-IPv4 address. */
const embeddedV4 = (g) =>
  `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`

/**
 * Block an IPv6 literal that resolves anywhere internal.
 *
 * Covers loopback and unspecified, ULA (fc00::/7), link-local (fe80::/10), and
 * — the case the previous string match silently missed — every address that
 * CARRIES an IPv4 address inside it: IPv4-mapped (::ffff:a.b.c.d),
 * IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::/96). Each of those is just a
 * second spelling of an IPv4 address, so each gets the IPv4 verdict.
 */
function isBlockedIPv6(h) {
  const g = expandIPv6(h)
  if (!g) return true                                   // unparseable → refuse

  const allZero = g.slice(0, 7).every(x => x === 0)
  if (allZero && (g[7] === 0 || g[7] === 1)) return true // :: and ::1

  if ((g[0] & 0xfe00) === 0xfc00) return true            // fc00::/7  ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true            // fe80::/10 link-local

  // ::ffff:a.b.c.d  — IPv4-mapped
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) return isBlockedIPv4(embeddedV4(g))
  // ::a.b.c.d       — IPv4-compatible (deprecated, still routable text)
  if (g.slice(0, 6).every(x => x === 0)) return isBlockedIPv4(embeddedV4(g))
  // 64:ff9b::/96    — NAT64
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every(x => x === 0)) {
    return isBlockedIPv4(embeddedV4(g))
  }
  return false
}

// Validate a single URL; throws BLOCKED_URL if unsafe. Returns the URL object.
export function assertSafeUrl(raw) {
  let u
  try { u = new URL(raw) } catch { throw blockedError('כתובת לא תקינה') }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw blockedError('פרוטוקול לא נתמך (http/https בלבד)')
  if (u.username || u.password) throw blockedError('כתובת עם פרטי התחברות אינה מותרת')
  if (isBlockedHost(u.hostname)) throw blockedError('כתובת פנימית/חסומה אינה מותרת')
  return u
}

export async function safeFetch(rawUrl, opts = {}) {
  const {
    method = 'GET',
    headers = {},
    maxBytes = DEFAULT_MAX_BYTES,
    maxRedirects = DEFAULT_MAX_REDIR,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = opts

  let current = assertSafeUrl(rawUrl).toString()

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), timeoutMs)
    let res
    try {
      res = await fetch(current, {
        method,
        headers: { 'User-Agent': 'EldadAI-ReceiptBot/1.0', Accept: '*/*', ...headers },
        redirect: 'manual',
        signal: ctrl.signal,
      })
    } catch (err) {
      clearTimeout(timer)
      if (err?.name === 'AbortError') { const e = new Error('timeout'); e.code = 'TIMEOUT'; throw e }
      throw err
    }
    clearTimeout(timer)

    // Manual redirect handling — re-validate each hop.
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      const next = new URL(res.headers.get('location'), current)
      assertSafeUrl(next.toString())
      current = next.toString()
      continue
    }

    // Enforce size via Content-Length hint, then via streamed read.
    const cl = Number(res.headers.get('content-length') || 0)
    if (cl && cl > maxBytes) { const e = new Error('too large'); e.code = 'TOO_LARGE'; throw e }

    const reader = res.body?.getReader()
    if (!reader) {
      const buf = new Uint8Array(await res.arrayBuffer())
      if (buf.byteLength > maxBytes) { const e = new Error('too large'); e.code = 'TOO_LARGE'; throw e }
      return { status: res.status, contentType: res.headers.get('content-type') || '', finalUrl: current, bytes: buf }
    }
    const chunks = []
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maxBytes) { try { await reader.cancel() } catch {} const e = new Error('too large'); e.code = 'TOO_LARGE'; throw e }
      chunks.push(value)
    }
    const bytes = new Uint8Array(total)
    let off = 0
    for (const c of chunks) { bytes.set(c, off); off += c.byteLength }
    return { status: res.status, contentType: res.headers.get('content-type') || '', finalUrl: current, bytes }
  }

  const e = new Error('too many redirects'); e.code = 'TOO_MANY_REDIRECTS'; throw e
}

// Base64-encode a byte array (chunked to avoid call-stack limits).
export function bytesToBase64(bytes) {
  let binary = ''
  const CH = 0x8000
  for (let i = 0; i < bytes.length; i += CH) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CH))
  }
  return btoa(binary)
}
