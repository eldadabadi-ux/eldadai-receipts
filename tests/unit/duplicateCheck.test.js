/**
 * duplicateCheck — the rules that decide whether a receipt is already in the book.
 *
 * QA plan item 3: "preventing data mixing or duplicate entries". Mixing between
 * customers is proven in tests/security/rls.pentest.test.js; this is the other
 * half — the same document entered twice into ONE book, which inflates expenses
 * and corrupts the profit figure item 4 asks about.
 *
 * The hard cases are the ones that must NOT warn: a second genuine purchase from
 * the same kiosk on the same day, and a summary invoice sitting alongside the
 * delivery note it aggregates.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { findDuplicates, compareOne, normalizeDocNum, duplicateWarning } from '../../src/lib/duplicateCheck.js'

const r = (o) => ({
  id: o.id ?? Math.random().toString(36).slice(2),
  vendor_name: 'מאפיית הבוקר',
  receipt_date: '2026-11-20',
  amount: 240.5,
  doc_number: null,
  supplier_id: null,
  doc_type: 'receipt',
  ...o,
})

// ── document number: the supplier's own identifier ──────────────────────────

test('same supplier and document number is an EXACT duplicate', () => {
  const existing = [r({ id: 'a', doc_number: '1234' })]
  const got = findDuplicates(r({ id: 'new', doc_number: '1234' }), existing)
  assert.equal(got.level, 'exact')
  assert.equal(got.matches.length, 1)
})

test('a document number matches regardless of how it was printed or read', () => {
  const existing = [r({ id: 'a', doc_number: 'ת. 00123' })]
  // Second scan read the prefix differently and the total slightly differently.
  const got = findDuplicates(r({ id: 'new', doc_number: '123', amount: 240.49 }), existing)
  assert.equal(got.level, 'exact', 'the document number alone should settle it')
})

test('the same document number from a DIFFERENT supplier is not a duplicate', () => {
  const existing = [r({ id: 'a', doc_number: '1000', vendor_name: 'מאפיית הבוקר' })]
  const got = findDuplicates(r({ id: 'new', doc_number: '1000', vendor_name: 'ירקות השדה' }), existing)
  assert.equal(got.level, null, 'invoice numbering is per-supplier; collisions are expected')
})

test('supplier ids beat names when both rows carry one', () => {
  const existing = [r({ id: 'a', doc_number: '55', supplier_id: 'sup-1', vendor_name: 'מאפיה' })]
  const same = findDuplicates(r({ id: 'n', doc_number: '55', supplier_id: 'sup-1', vendor_name: 'מאפיית הבוקר בעמ' }), existing)
  assert.equal(same.level, 'exact', 'same supplier id, different spelling → still the same supplier')

  const other = findDuplicates(r({ id: 'n', doc_number: '55', supplier_id: 'sup-2', vendor_name: 'מאפיה' }), existing)
  assert.equal(other.level, null, 'different supplier id → different supplier, whatever the name says')
})

// ── no document number: supplier + date + amount ────────────────────────────

test('same supplier, date and amount is a LIKELY duplicate, not an exact one', () => {
  const existing = [r({ id: 'a' })]
  const got = findDuplicates(r({ id: 'new' }), existing)
  assert.equal(got.level, 'likely', 'this pattern is repeatable in real life — warn, do not assert')
})

test('a different amount on the same day is not a duplicate', () => {
  const existing = [r({ id: 'a', amount: 240.5 })]
  assert.equal(findDuplicates(r({ id: 'n', amount: 118 }), existing).level, null)
})

test('the same amount on a different day is not a duplicate', () => {
  const existing = [r({ id: 'a', receipt_date: '2026-11-20' })]
  assert.equal(findDuplicates(r({ id: 'n', receipt_date: '2026-11-21' }), existing).level, null)
})

test('amounts within one agora are the same amount', () => {
  const existing = [r({ id: 'a', amount: 240.5 })]
  assert.equal(findDuplicates(r({ id: 'n', amount: 240.504 }), existing).level, 'likely')
  assert.equal(findDuplicates(r({ id: 'n', amount: 240.52 }), existing).level, null)
})

// ── the cases that must NOT warn ────────────────────────────────────────────

test('a summary invoice is not a duplicate of the delivery note it aggregates', () => {
  const note = r({ id: 'a', doc_type: 'delivery_note' })
  const invoice = r({ id: 'n', doc_type: 'summary_invoice' })
  assert.equal(findDuplicates(invoice, [note]).level, null,
    'same supplier, date and money - but a different KIND of document')
})

test('a row never matches itself when re-saved', () => {
  const row = r({ id: 'same', doc_number: '77' })
  assert.equal(findDuplicates(row, [row]).level, null, 'editing a receipt must not flag it as its own duplicate')
})

test('a receipt with no vendor name matches nothing', () => {
  const existing = [r({ id: 'a', vendor_name: '' })]
  assert.equal(findDuplicates(r({ id: 'n', vendor_name: '' }), existing).level, null,
    'an empty name must not make every unnamed receipt a duplicate of every other')
})

// ── shape of the result ─────────────────────────────────────────────────────

test('an exact match outranks likely ones found alongside it', () => {
  const existing = [
    r({ id: 'likely' }),
    r({ id: 'exact', doc_number: '900' }),
  ]
  const got = findDuplicates(r({ id: 'n', doc_number: '900' }), existing)
  assert.equal(got.level, 'exact')
  assert.equal(got.matches.length, 2, 'both are reported; the strongest decides the level')
})

test('every match carries why it matched', () => {
  const got = findDuplicates(r({ id: 'n', doc_number: '12' }), [r({ id: 'a', doc_number: '12' })])
  assert.ok(got.matches[0]._reason.length > 0)
  assert.equal(got.matches[0]._match, 'exact')
})

test('no existing rows, empty input and junk are all handled', () => {
  assert.equal(findDuplicates(r({}), []).level, null)
  assert.equal(findDuplicates(r({}), null).level, null)
  assert.equal(findDuplicates(null, [r({})]).level, null)
  assert.equal(compareOne(null, null).level, null)
})

test('normalizeDocNum strips punctuation, prefixes and leading zeros', () => {
  assert.equal(normalizeDocNum('ת. 00123'), '123')
  assert.equal(normalizeDocNum('#0001'), '1')
  assert.equal(normalizeDocNum('INV-2026/0045'), '202600450'.slice(0, 0) + '20260045')
  assert.equal(normalizeDocNum(null), '')
})

test('the warning names the count and the reason, and asks rather than tells', () => {
  const got = findDuplicates(r({ id: 'n', doc_number: '5' }), [r({ id: 'a', doc_number: '5' })])
  const msg = duplicateWarning(got)
  assert.match(msg, /כבר קיימת/)
  assert.match(msg, /לשמור בכל זאת/, 'the user decides — this must never read as a refusal')
  assert.equal(duplicateWarning({ level: null, matches: [] }), '')
})
