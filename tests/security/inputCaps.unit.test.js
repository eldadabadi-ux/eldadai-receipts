/**
 * Extraction input ceilings — functions/api/_lib/extractReceipt.js
 * (ASVS V2 · ISO A.8.12 — resource exhaustion)
 *
 * The regression this pins: /api/scan-receipt is rate-limited per REQUEST, but
 * accepted an unbounded `imagesBase64` array — so one request carrying 500
 * pages cost 500 OCR pages against a budget that thought it had spent one. The
 * caps live in extractReceipt rather than the route precisely so that the
 * inbound-email and link-import paths cannot drift away from them.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  assertExtractionInput, MAX_PAGES, MAX_IMAGE_BYTES, ALLOWED_MIME_RE,
} from '../../functions/api/_lib/extractReceipt.js'

const codeOf = (fn) => { try { fn(); return null } catch (e) { return e.code } }

// Real signatures. Since 23.11.26 the caps are enforced alongside a magic-byte
// check (ASVS V5.2.2), so a placeholder string is no longer a valid page — and
// a test that fed one would be asserting on a file the product now refuses.
const b64 = (...parts) => Buffer.from(Uint8Array.from(parts.flat())).toString('base64')
const filler = (n) => Array(n).fill(0)
const SIG = {
  'image/jpeg':      [0xFF, 0xD8, 0xFF, 0xE0],
  'image/jpg':       [0xFF, 0xD8, 0xFF, 0xE0],
  'image/png':       [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  'image/webp':      [...'RIFF'].map(c => c.charCodeAt(0)).concat([0, 0, 0, 0], [...'WEBP'].map(c => c.charCodeAt(0))),
  'image/gif':       [...'GIF89a'].map(c => c.charCodeAt(0)),
  'image/heic':      [0, 0, 0, 24, ...[...'ftypheic'].map(c => c.charCodeAt(0))],
  'image/heif':      [0, 0, 0, 24, ...[...'ftypmif1'].map(c => c.charCodeAt(0))],
  'application/pdf': [...'%PDF-1.7'].map(c => c.charCodeAt(0)),
}
const fileOf = (mime) => b64(SIG[mime], filler(32))
const page = fileOf('image/jpeg')

/** A real JPEG padded out to ~n decoded bytes. */
const bytes = (n) => b64(SIG['image/jpeg'], filler(Math.max(0, n - 4)))

test('a normal single-page scan is accepted', () => {
  assert.equal(codeOf(() => assertExtractionInput([page], 'image/jpeg')), null)
})

test('a multi-page receipt up to the cap is accepted', () => {
  assert.equal(codeOf(() => assertExtractionInput(Array(MAX_PAGES).fill(page), 'image/jpeg')), null)
})

test('one page over the cap is refused', () => {
  assert.equal(
    codeOf(() => assertExtractionInput(Array(MAX_PAGES + 1).fill(page), 'image/jpeg')),
    'TOO_MANY_PAGES',
  )
})

test('the cost-amplification case is refused — 500 pages in one request', () => {
  assert.equal(
    codeOf(() => assertExtractionInput(Array(500).fill(page), 'image/jpeg')),
    'TOO_MANY_PAGES',
  )
})

test('an oversized page is refused', () => {
  assert.equal(
    codeOf(() => assertExtractionInput([bytes(MAX_IMAGE_BYTES + 1024)], 'image/png')),
    'TOO_LARGE',
  )
})

test('an oversized page hidden among small ones is still caught', () => {
  const imgs = [page, page, bytes(MAX_IMAGE_BYTES + 1024), page]
  assert.equal(codeOf(() => assertExtractionInput(imgs, 'image/png')), 'TOO_LARGE')
})

test('every supported receipt type is accepted', () => {
  for (const m of [
    'image/jpeg', 'image/jpg', 'image/png', 'image/webp',
    'image/gif', 'image/heic', 'image/heif', 'application/pdf',
  ]) {
    assert.equal(codeOf(() => assertExtractionInput([fileOf(m)], m)), null, `rejected ${m}`)
  }
})

test('a page whose bytes contradict the declared type is refused (V5.2.2)', () => {
  assert.equal(codeOf(() => assertExtractionInput([fileOf('image/png')], 'image/jpeg')), 'MIME_MISMATCH')
})

test('one bad page hidden among good ones is still caught', () => {
  const html = Buffer.from('<html><body>not an image</body></html>').toString('base64')
  assert.equal(
    codeOf(() => assertExtractionInput([page, page, html], 'image/jpeg')),
    'UNRECOGNISED_FILE',
    'every page is checked, not just the first',
  )
})

test('mime types that are not receipts are refused', () => {
  for (const m of [
    'text/html',            // would be sent to the model as if it were an image
    'image/svg+xml',        // scriptable
    'application/xml',
    'application/javascript',
    'text/plain',
    '*/*',
    '',
  ]) {
    assert.equal(codeOf(() => assertExtractionInput([page], m)), m ? 'BAD_MIME' : 'BAD_INPUT',
      `accepted ${m || '(empty)'}`)
  }
})

test('a charset parameter does not smuggle a bad type through', () => {
  assert.equal(codeOf(() => assertExtractionInput([page], 'image/jpeg; charset=utf-8')), null)
  assert.equal(codeOf(() => assertExtractionInput([page], 'text/html; charset=utf-8')), 'BAD_MIME')
})

test('the allowlist is a full-string match, not a substring one', () => {
  assert.ok(!ALLOWED_MIME_RE.test('text/html;image/jpeg'))
  assert.ok(!ALLOWED_MIME_RE.test('evil/image/jpeg'))
  assert.ok(!ALLOWED_MIME_RE.test('image/jpeg.evil'))
})

test('missing input is refused', () => {
  assert.equal(codeOf(() => assertExtractionInput([], 'image/jpeg')), 'BAD_INPUT')
  assert.equal(codeOf(() => assertExtractionInput([page], null)), 'BAD_INPUT')
})
