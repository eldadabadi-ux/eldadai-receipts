/**
 * fileType — what a file ACTUALLY is, read from its first bytes (ASVS V5.2.2).
 *
 * Until now the pipeline believed the caller: `mimeType` came from the request
 * body (or from an email part header) and went straight into Gemini's
 * inline_data and into the Storage object's content type. Nothing ever looked
 * at the bytes. A caller could label anything image/jpeg.
 *
 * The practical exposure was bounded — the bucket is private, never served as
 * HTML, and SVG is already off the allowlist — so this is defence in depth
 * rather than a hole being closed. What it buys concretely:
 *
 *   - a Storage object can no longer be stored under a content type that
 *     disagrees with its bytes, which is what makes a "receipt" render as
 *     something else later if the serving path ever changes;
 *   - a corrupt or truncated upload is refused at the door with a clear reason,
 *     instead of costing an OCR call and coming back as an empty extraction;
 *   - the declared type stops being a free-text field that reaches an upstream
 *     API unvalidated.
 *
 * Signature-based, not extension-based: the filename is not consulted at all.
 */

/** Longest prefix any check below needs. */
export const SNIFF_BYTES = 32

const startsWith = (b, sig, offset = 0) =>
  sig.every((x, i) => b[offset + i] === x)

const ascii = (b, offset, text) =>
  [...text].every((ch, i) => b[offset + i] === ch.charCodeAt(0))

/**
 * Detect the type from a byte prefix.
 * @param {Uint8Array} bytes first bytes of the file (SNIFF_BYTES is enough)
 * @returns {string|null} canonical mime type, or null when unrecognised
 */
export function sniffMime(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || [])
  if (b.length < 4) return null

  // JPEG — FF D8 FF
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'image/jpeg'

  // PNG — 89 50 4E 47 0D 0A 1A 0A
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png'

  // PDF — "%PDF-"
  if (ascii(b, 0, '%PDF-')) return 'application/pdf'

  // GIF — "GIF87a" / "GIF89a"
  if (ascii(b, 0, 'GIF87a') || ascii(b, 0, 'GIF89a')) return 'image/gif'

  // RIFF container: "RIFF" ???? "WEBP"
  if (ascii(b, 0, 'RIFF') && ascii(b, 8, 'WEBP')) return 'image/webp'

  // ISO-BMFF ("....ftyp...."): HEIC/HEIF brands. Used by every modern iPhone,
  // so a receipt photographed on one arrives here rather than as JPEG.
  if (ascii(b, 4, 'ftyp')) {
    const brand = String.fromCharCode(b[8], b[9], b[10], b[11])
    if (['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis'].includes(brand)) return 'image/heic'
    if (['mif1', 'msf1'].includes(brand)) return 'image/heif'
    return null                                   // some other ISO-BMFF (mp4, …)
  }

  return null
}

/** Types the OCR pipeline accepts, by signature. */
const ACCEPTED = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/heic', 'image/heif',
  'application/pdf',
])

/** Spellings a client may legitimately send for the same real type. */
const ALIASES = {
  'image/jpg': 'image/jpeg',
  'image/heif': 'image/heic',
  'image/heic': 'image/heic',
}
const canonical = (m) => {
  const t = String(m || '').split(';')[0].trim().toLowerCase()
  return ALIASES[t] || t
}

/**
 * Verify a file against the type its sender claims.
 *
 * Returns the type to TRUST (the sniffed one) so callers can store and forward
 * the real type rather than the asserted one.
 *
 * @param {Uint8Array} bytes    first bytes (>= SNIFF_BYTES)
 * @param {string} declaredMime what the caller said it was
 * @returns {{ok:true, mime:string} | {ok:false, code:string, detail:string}}
 */
export function verifyFileType(bytes, declaredMime) {
  const sniffed = sniffMime(bytes)
  if (!sniffed) {
    return {
      ok: false,
      code: 'UNRECOGNISED_FILE',
      detail: 'the file does not begin with a supported image or PDF signature',
    }
  }
  if (!ACCEPTED.has(sniffed)) {
    return { ok: false, code: 'BAD_MIME', detail: `unsupported file type: ${sniffed}` }
  }

  // HEIC and HEIF are the same container with different brands; jpg and jpeg
  // are the same thing spelled twice. Anything else must agree.
  const want = canonical(declaredMime)
  const got = canonical(sniffed)
  const heicPair = (a, b) => ['image/heic', 'image/heif'].includes(a) && ['image/heic', 'image/heif'].includes(b)

  if (want && want !== got && !heicPair(want, got)) {
    return {
      ok: false,
      code: 'MIME_MISMATCH',
      detail: `declared ${want} but the bytes are ${got}`,
    }
  }

  return { ok: true, mime: sniffed }
}

/** Decode just enough leading base64 to sniff, without decoding the whole file. */
export function prefixFromBase64(b64, n = SNIFF_BYTES) {
  const clean = String(b64 || '').replace(/\s+/g, '')
  // 4 base64 chars → 3 bytes; take a whole number of quads to avoid padding games.
  const quads = Math.ceil(n / 3)
  const head = clean.slice(0, quads * 4)
  if (!head) return new Uint8Array(0)
  try {
    const bin = atob(head)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return new Uint8Array(0)              // not valid base64 → caller refuses it
  }
}
