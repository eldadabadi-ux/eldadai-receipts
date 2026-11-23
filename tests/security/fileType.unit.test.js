/**
 * File type by signature, not by assertion — ASVS V5.2.2.
 *
 * Before this, `mimeType` came from the request body (or an email part header)
 * and went straight into Gemini's inline_data and onto the Storage object's
 * content type. Nothing read the bytes, so a caller could label anything
 * image/jpeg.
 *
 * The exposure was bounded — the bucket is private and never served as HTML —
 * which is why this is defence in depth rather than a hole being closed. The
 * property worth keeping is simply that the declared type stops being a
 * free-text field that reaches an upstream API and an object store unchecked.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sniffMime, verifyFileType, prefixFromBase64, SNIFF_BYTES } from '../../functions/api/_lib/fileType.js'

const bytes = (...b) => Uint8Array.from(b.flat())
const pad = (n = SNIFF_BYTES) => Array(n).fill(0)

const JPEG = bytes([0xFF, 0xD8, 0xFF, 0xE0], pad(20))
const PNG  = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], pad(20))
const PDF  = bytes([...'%PDF-1.7'].map(c => c.charCodeAt(0)), pad(20))
const GIF  = bytes([...'GIF89a'].map(c => c.charCodeAt(0)), pad(20))
const WEBP = bytes([...'RIFF'].map(c => c.charCodeAt(0)), [0, 0, 0, 0], [...'WEBP'].map(c => c.charCodeAt(0)), pad(16))
const HEIC = bytes([0, 0, 0, 24], [...'ftypheic'].map(c => c.charCodeAt(0)), pad(16))
const HTML = bytes([...'<html><body>x'].map(c => c.charCodeAt(0)), pad(20))
const SVG  = bytes([...'<svg xmlns="http'].map(c => c.charCodeAt(0)), pad(16))

// ── detection ───────────────────────────────────────────────────────────────

test('every type the OCR pipeline accepts is detected from its signature', () => {
  assert.equal(sniffMime(JPEG), 'image/jpeg')
  assert.equal(sniffMime(PNG),  'image/png')
  assert.equal(sniffMime(PDF),  'application/pdf')
  assert.equal(sniffMime(GIF),  'image/gif')
  assert.equal(sniffMime(WEBP), 'image/webp')
  assert.equal(sniffMime(HEIC), 'image/heic')
})

test('HEIC matters specifically — it is what a modern iPhone produces', () => {
  assert.equal(sniffMime(HEIC), 'image/heic', 'a photographed receipt must not be refused')
})

test('things that are not receipts are not recognised', () => {
  for (const [name, b] of [['html', HTML], ['svg', SVG]]) {
    assert.equal(sniffMime(b), null, `${name} should not pass as an image`)
  }
})

test('a truncated or empty file is not recognised', () => {
  assert.equal(sniffMime(bytes([0xFF, 0xD8])), null)
  assert.equal(sniffMime(bytes([])), null)
  assert.equal(sniffMime(null), null)
})

test('a RIFF container that is not WEBP is refused', () => {
  const wav = bytes([...'RIFF'].map(c => c.charCodeAt(0)), [0, 0, 0, 0], [...'WAVE'].map(c => c.charCodeAt(0)), pad(16))
  assert.equal(sniffMime(wav), null)
})

test('an ISO-BMFF video is refused even though it shares HEIC\'s container', () => {
  const mp4 = bytes([0, 0, 0, 24], [...'ftypisom'].map(c => c.charCodeAt(0)), pad(16))
  assert.equal(sniffMime(mp4), null, 'same box structure, different brand — not an image')
})

// ── verification against the claim ──────────────────────────────────────────

test('bytes and declared type agreeing is accepted, and the SNIFFED type is returned', () => {
  const v = verifyFileType(JPEG, 'image/jpeg')
  assert.ok(v.ok)
  assert.equal(v.mime, 'image/jpeg', 'callers should store the real type, not the asserted one')
})

test('a disguised file is refused with the mismatch named', () => {
  const v = verifyFileType(PNG, 'image/jpeg')
  assert.equal(v.ok, false)
  assert.equal(v.code, 'MIME_MISMATCH')
  assert.match(v.detail, /image\/png/)
})

test('a non-image declared as an image is refused as unrecognised', () => {
  assert.equal(verifyFileType(HTML, 'image/jpeg').code, 'UNRECOGNISED_FILE')
  assert.equal(verifyFileType(SVG, 'image/png').code, 'UNRECOGNISED_FILE')
})

test('jpg and jpeg are the same thing spelled twice', () => {
  assert.ok(verifyFileType(JPEG, 'image/jpg').ok)
})

test('heic and heif are the same container and must not fight each other', () => {
  assert.ok(verifyFileType(HEIC, 'image/heif').ok)
  assert.ok(verifyFileType(HEIC, 'image/heic').ok)
})

test('a charset parameter on the declared type is ignored', () => {
  assert.ok(verifyFileType(PDF, 'application/pdf; charset=binary').ok)
})

// ── base64 prefix decoding ──────────────────────────────────────────────────

test('only the head of a base64 payload is decoded, and it is enough to decide', () => {
  const big = Buffer.concat([Buffer.from(JPEG), Buffer.alloc(5_000_000)]).toString('base64')
  const head = prefixFromBase64(big)
  assert.ok(head.length >= 4 && head.length <= SNIFF_BYTES + 3,
    `decoded ${head.length} bytes — a 5MB file must not be decoded to read its signature`)
  assert.equal(sniffMime(head), 'image/jpeg')
})

test('whitespace and data-URL-style padding do not confuse the prefix', () => {
  const spaced = Buffer.from(PNG).toString('base64').replace(/(.{8})/g, '$1\n')
  assert.equal(sniffMime(prefixFromBase64(spaced)), 'image/png')
})

test('junk that is not base64 yields no bytes rather than throwing', () => {
  assert.equal(prefixFromBase64('####').length, 0)
  assert.equal(prefixFromBase64(null).length, 0)
  assert.equal(verifyFileType(prefixFromBase64('####'), 'image/jpeg').ok, false)
})
