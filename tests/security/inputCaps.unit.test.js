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
const page = 'QUJDRA=='                                  // tiny valid-ish base64
const bytes = (n) => 'A'.repeat(Math.ceil(n * 4 / 3))    // base64 of ~n bytes

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
    assert.equal(codeOf(() => assertExtractionInput([page], m)), null, `rejected ${m}`)
  }
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
