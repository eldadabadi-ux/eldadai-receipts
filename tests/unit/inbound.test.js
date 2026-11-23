/**
 * inbound.test — pure helpers for the self-service email channel (Phase 7,
 * client issue #7). The endpoint and Worker do I/O; these are the parts worth
 * pinning down: address→alias mapping, attachment filtering, alias minting.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { aliasFromAddress, isValidAlias, pickAttachments, genAlias, inboundAddress } from '../../functions/api/_lib/inbound.js'

test('aliasFromAddress lower-cases, strips the +tag and the domain', () => {
  assert.equal(aliasFromAddress('Moses-ab12@receipts-inbox.com'), 'moses-ab12')
  assert.equal(aliasFromAddress('inbox+anything@d.com'), 'inbox')
  assert.equal(aliasFromAddress('INBOX@D.COM'), 'inbox')
})

test('aliasFromAddress rejects malformed locals', () => {
  for (const bad of ['', null, 'has space@d.com', 'weird!char@d.com', '@d.com']) {
    assert.equal(aliasFromAddress(bad), '', String(bad))
  }
})

// Real leading bytes — an attachment is now judged by its signature, not by the
// MIME header the SENDER wrote (ASVS V5.2.2), so the fixtures must be genuine.
const b64 = (bytes) => Buffer.from(Uint8Array.from(bytes)).toString('base64')
const JPEG = b64([0xFF, 0xD8, 0xFF, 0xE0, 0, 16, 74, 70, 73, 70, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0])
const PNG  = b64([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1])
const PDF  = b64([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37, 0x0A, 0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A, 0x31, 0x20, 0x30, 0x20, 0x6F, 0x62, 0x6A])

test('pickAttachments keeps only OCR-able types, normalized', () => {
  const out = pickAttachments([
    { filename: 'a.pdf', mimeType: 'application/pdf', contentBase64: PDF },
    { filename: 'b.jpg', contentType: 'image/jpeg; name=b', content: JPEG },
    { filename: 'sig.txt', mimeType: 'text/plain', contentBase64: PNG },        // dropped (type)
    { filename: 'cal.ics', mimeType: 'text/calendar', contentBase64: PDF },     // dropped (type)
    { filename: 'empty.png', mimeType: 'image/png', contentBase64: '' },        // dropped (no bytes)
  ])
  assert.equal(out.length, 2)
  assert.deepEqual(out.map(a => a.mimeType), ['application/pdf', 'image/jpeg'])
})

test('an attachment whose bytes contradict its MIME header is dropped', () => {
  // The header on an email part is written by the sender, so it is a claim.
  const html = Buffer.from('<html><body>not an image at all, whatever the header says</body></html>', 'utf8').toString('base64')
  const out = pickAttachments([
    { filename: 'invoice.jpg', mimeType: 'image/jpeg', contentBase64: html },
    { filename: 'real.jpg',    mimeType: 'image/jpeg', contentBase64: JPEG },
  ])
  assert.equal(out.length, 1, 'the mislabelled part must go')
  assert.equal(out[0].filename, 'real.jpg', 'and the genuine receipt beside it must stay')
})

test('a png declared as a jpeg is dropped — the two must agree', () => {
  assert.equal(pickAttachments([{ filename: 'x.jpg', mimeType: 'image/jpeg', contentBase64: PNG }]).length, 0)
})

test('pickAttachments drops oversized files', () => {
  const big = JPEG + 'A'.repeat(15 * 1024 * 1024)   // valid signature, over the 10MB cap
  assert.equal(pickAttachments([{ filename: 'big.jpg', mimeType: 'image/jpeg', contentBase64: big }]).length, 0)
})

test('genAlias yields a valid alias; Hebrew names fall back to inbox', () => {
  let n = 0
  const rand = () => ['abc123', 'def456'][n++]
  assert.equal(genAlias('Moses Cafe', rand), 'moses-cafe-abc123')
  assert.equal(genAlias('בית קפה השכונה', rand), 'inbox-def456')   // Hebrew slugs to nothing → inbox
  assert.ok(isValidAlias(genAlias('x', () => 'q1w2e3')))
})

test('inboundAddress joins alias and domain, empty when either is missing', () => {
  assert.equal(inboundAddress('moses-ab12', 'receipts-inbox.com'), 'moses-ab12@receipts-inbox.com')
  assert.equal(inboundAddress('moses-ab12', null), '')
  assert.equal(inboundAddress('', 'd.com'), '')
})
