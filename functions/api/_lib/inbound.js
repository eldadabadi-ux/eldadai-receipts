/**
 * inbound — pure helpers for the self-service email channel (client request #7).
 *
 * A customer gets one opaque address, alias@INBOUND_DOMAIN, and sets a forwarding
 * rule in their own mailbox. Cloudflare Email Routing hands each message to an
 * Email Worker, which parses the MIME and POSTs the attachments to /api/inbound;
 * this module holds the bits worth testing without a network: how an address maps
 * to an alias, which attachments are worth OCR-ing, and how a fresh alias is minted.
 */

const ALIAS_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

/** Attachment types the OCR pipeline can read. */
const OCR_MIME_RE = /^(image\/(jpe?g|png|webp|gif|heic|heif)|application\/pdf)$/i
const MAX_ATTACH_BYTES = 10 * 1024 * 1024   // 10 MB per file — matches the scan limit

/**
 * Extract the alias (local part) from a recipient address.
 * Lower-cased, sub-addressing tag ("+anything") dropped, so "Inbox+x@d.com" and
 * "inbox@d.com" resolve to the same customer. Returns '' for anything invalid.
 */
export function aliasFromAddress(addr) {
  const at = String(addr || '').trim().toLowerCase()
  const local = at.split('@')[0] || ''
  const base = local.split('+')[0]
  return ALIAS_RE.test(base) ? base : ''
}

/** Is this alias string well-formed (what we would have minted)? */
export const isValidAlias = (a) => ALIAS_RE.test(String(a || ''))

/**
 * Keep only attachments the OCR can use, normalized to { filename, mimeType, b64 }.
 * Oversized or unsupported parts are dropped (inline logos, signatures, calendar
 * invites) rather than sent to OCR.
 */
export function pickAttachments(attachments) {
  const out = []
  for (const a of Array.isArray(attachments) ? attachments : []) {
    const mimeType = String(a?.mimeType || a?.contentType || '').split(';')[0].trim()
    const b64 = String(a?.contentBase64 || a?.content || '').replace(/\s+/g, '')
    if (!OCR_MIME_RE.test(mimeType) || !b64) continue
    // base64 length → byte count (4 chars ≈ 3 bytes); cheap size guard.
    if (Math.floor(b64.length * 3 / 4) > MAX_ATTACH_BYTES) continue
    out.push({ filename: String(a?.filename || a?.name || 'attachment').slice(0, 200), mimeType, b64 })
  }
  return out
}

const slugify = (s) =>
  String(s || '').normalize('NFKD').replace(/[^\p{Letter}\p{Number}]+/gu, '-')
    .replace(/^-+|-+$/g, '').toLowerCase().slice(0, 24)

/**
 * Cryptographically random base36 suffix.
 *
 * WHY NOT Math.random(): the alias IS the credential for this channel. Anyone
 * who knows alias@<domain> can mail it and have the attachments ingested into
 * that tenant's books — there is no second factor, because an email channel
 * cannot carry one. The readable half of the alias is the business name, so the
 * suffix is the ONLY thing standing between a guess and writing into another
 * business's account. V8's Math.random() is xorshift128+: fast, uniform, and
 * state-recoverable from a handful of outputs, which is exactly the wrong
 * property for a value that must stay unguessable.
 *
 * 10 chars of base36 is ~51 bits, up from the previous ~31.
 */
const SUFFIX_CHARS = 10
function randomSuffix() {
  const bytes = new Uint8Array(SUFFIX_CHARS)
  crypto.getRandomValues(bytes)
  // 0-25 -> a-z, 26-35 -> 0-9. The 36-value modulo of 256 is very slightly
  // biased (256 = 7*36 + 4); irrelevant at this size, and noted so the next
  // reader does not have to work it out.
  let out = ''
  for (const b of bytes) {
    const v = b % 36
    out += v < 26 ? String.fromCharCode(97 + v) : String(v - 26)
  }
  return out
}

/**
 * Mint a new alias. A readable slug of the business name (ASCII only — a Hebrew
 * name slugs to nothing, so fall back to "inbox") plus a random suffix for
 * uniqueness AND unguessability. `rand` is injected so the result is testable.
 */
export function genAlias(businessName, rand) {
  const r = (rand || randomSuffix)()
  const asciiSlug = slugify(businessName).replace(/[^a-z0-9-]/g, '')
  const head = asciiSlug && /[a-z0-9]/.test(asciiSlug) ? asciiSlug : 'inbox'
  return `${head}-${r}`.replace(/-+/g, '-')
}

/** Full address for an alias under a given inbound domain. */
export const inboundAddress = (alias, domain) =>
  alias && domain ? `${alias}@${domain}` : ''
