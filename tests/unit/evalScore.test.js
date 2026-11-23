/**
 * The eval scorer decides whether a model upgrade ships, so it is tested itself.
 * Run: node --test tests/unit/evalScore.test.js
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { scoreOne, summarize, compareRuns } from '../eval/score.mjs'
import { FIXTURES, totalsOf } from '../eval/fixtures.mjs'

const fx = (id) => FIXTURES.find(f => f.id === id)

/**
 * A perfect extraction for a fixture, built from its own ground truth.
 *
 * `doc.items` describe what is PRINTED on the receipt; `expect` describes the
 * correct EXTRACTION. For a receipt that prints no unit column they differ on
 * purpose: the right answer is an inferred unit, not the blank the paper shows.
 */
function perfect(f) {
  const t = totalsOf(f)
  return {
    vendor_name: f.expect.vendor_name,
    receipt_date: f.expect.receipt_date,
    total_amount: f.expect.total_amount ?? t.total,
    amount_before_vat: t.before_vat,
    vat_amount: t.vat_amount,
    currency: f.expect.currency || 'ILS',
    doc_type: f.expect.doc_type || 'receipt',
    doc_number: f.expect.doc_number,
    doc_refs: f.expect.doc_refs,
    items: f.doc.items.map((it, i) => ({
      item_name: it.item_name, quantity: it.quantity,
      unit: f.expect.units?.[i] ?? f.expect.units_inferred_as ?? it.unit,
      unit_price: it.unit_price, price: it.price,
      base_unit: f.expect.base_units?.[i] ?? null,
    })),
  }
}

test('every fixture can be scored, and a perfect answer scores 100%', () => {
  for (const f of FIXTURES) {
    const r = scoreOne(f, perfect(f))
    assert.equal(r.score, r.max, `${f.id} failed: ${JSON.stringify(r.failures)}`)
  }
})

test('a corpus of perfect answers summarizes to 100%', () => {
  const s = summarize(FIXTURES.map(f => scoreOne(f, perfect(f))))
  assert.equal(s.pct, 100)
  assert.equal(s.perfect, FIXTURES.length)
})

// ── the specific failures the corpus exists to catch ─────────────────────────
test('a month/day swap is caught', () => {
  const f = fx('produce-kg-daydirst')
  const r = scoreOne(f, { ...perfect(f), receipt_date: '2026-03-07' })   // 3 July read as 7 March
  assert.ok(r.failures.some(x => x.name === 'date'))
})

test('a rounded unit price is caught', () => {
  const f = fx('exact-prices')
  const p = perfect(f)
  p.items[0].unit_price = 6.21                                           // 6.2102 rounded
  assert.ok(scoreOne(f, p).failures.some(x => x.name === 'unit_prices_exact'))
})

test('a truncated item list is caught', () => {
  const f = fx('long-item-list')
  const p = perfect(f)
  p.items = p.items.slice(0, 12)
  assert.ok(scoreOne(f, p).failures.some(x => x.name === 'item_count'))
})

test('a unit spelling variant is NOT a failure', () => {
  const f = fx('unit-spelling-kilo')
  const p = perfect(f)
  p.items[0].unit = 'ק"ג'                                                // printed "קילו"
  assert.equal(scoreOne(f, p).failures.length, 0)
})

test('a vendor-name spelling variant is NOT a failure', () => {
  const f = fx('produce-kg-daydirst')
  const p = perfect(f)
  p.vendor_name = 'קטיף ירקות קצוצים בעמ'                                // quote dropped
  assert.equal(scoreOne(f, p).failures.length, 0)
})

test('a genuinely wrong vendor IS a failure', () => {
  const f = fx('produce-kg-daydirst')
  assert.ok(scoreOne(f, { ...perfect(f), vendor_name: 'אהרון שוק' })
    .failures.some(x => x.name === 'vendor'))
})

test('missing units on a receipt that prints none is caught', () => {
  const f = fx('no-units-printed')
  const p = perfect(f)
  p.items = p.items.map(i => ({ ...i, unit: '' }))
  assert.ok(scoreOne(f, p).failures.some(x => x.name === 'unit_inference'))
})

test('a summary invoice classified as a receipt is caught', () => {
  const f = fx('summary-invoice')
  assert.ok(scoreOne(f, { ...perfect(f), doc_type: 'receipt' })
    .failures.some(x => x.name === 'doc_type'))
})

// ── comparing two runs ───────────────────────────────────────────────────────
test('a strictly better run is reported as an upgrade', () => {
  const base = FIXTURES.map(f => {
    const p = perfect(f)
    if (f.id === 'produce-kg-daydirst') p.receipt_date = '2026-03-07'
    return scoreOne(f, p)
  })
  const cand = FIXTURES.map(f => scoreOne(f, perfect(f)))
  const c = compareRuns(base, cand)
  assert.equal(c.verdict, 'upgrade')
  assert.ok(c.delta > 0)
  assert.equal(c.regressions.length, 0)
  assert.ok(c.fixes.some(x => x.field === 'date'))
})

test('a higher score that breaks something is NOT an upgrade', () => {
  // Candidate fixes two dates but starts truncating a long list — a trade, not
  // a win, and a single blended score would have hidden it.
  const base = FIXTURES.map(f => {
    const p = perfect(f)
    if (f.id === 'produce-kg-daydirst') p.receipt_date = '2026-03-07'
    if (f.id === 'unit-spelling-kilo') p.receipt_date = '2026-12-08'
    return scoreOne(f, p)
  })
  const cand = FIXTURES.map(f => {
    const p = perfect(f)
    if (f.id === 'long-item-list') p.items = p.items.slice(0, 10)
    return scoreOne(f, p)
  })
  const c = compareRuns(base, cand)
  assert.equal(c.verdict, 'has regressions')
  assert.ok(c.regressions.some(r => r.field === 'item_count'))
})

test('per-field accuracy is reported, not just a total', () => {
  const s = summarize(FIXTURES.map(f => scoreOne(f, perfect(f))))
  const names = s.byField.map(b => b.name)
  for (const n of ['vendor', 'date', 'total', 'item_count', 'units']) {
    assert.ok(names.includes(n), `missing field report: ${n}`)
  }
})

/**
 * Regression: doc_refs arrive as objects, not strings.
 *
 * The scorer mapped digits() over them directly, so each one stringified to
 * "[object Object]", lost every digit, and the field scored 0/1 while the model
 * was returning all three note numbers. The eval exists to decide whether a
 * model change is an improvement — a blind spot in it is worse than a bug in
 * what it grades, because it silently devalues correct output.
 */
test('doc_refs are read from note_number, not from the object', () => {
  const fx = { doc: { items: [] }, expect: { doc_refs: ['45871', '45902', '46011'] } }
  const got = {
    doc_refs: [
      { note_number: '45871', note_date: '2026-07-03', amount: 1250.4 },
      { note_number: '45902', note_date: '2026-07-14', amount: 980.15 },
      { note_number: '46011', note_date: '2026-07-28', amount: 1442.3 },
    ],
  }
  const r = scoreOne(fx, got)
  const f = r.fields.find(x => x.name === 'doc_refs')
  assert.ok(f.ok, `doc_refs should pass, got detail: ${f.detail}`)
})

test('doc_refs still compare by digits, and order does not matter', () => {
  const fx = { doc: { items: [] }, expect: { doc_refs: ['123', '456'] } }
  const got = { doc_refs: [{ note_number: 'ת. 00456' }, { note_number: '#123' }] }
  assert.ok(scoreOne(fx, got).fields.find(x => x.name === 'doc_refs').ok)
})

test('a genuinely missing doc_ref still fails', () => {
  const fx = { doc: { items: [] }, expect: { doc_refs: ['1', '2'] } }
  const got = { doc_refs: [{ note_number: '1' }] }
  assert.ok(!scoreOne(fx, got).fields.find(x => x.name === 'doc_refs').ok)
})

test('plain-string doc_refs are still supported', () => {
  const fx = { doc: { items: [] }, expect: { doc_refs: ['77'] } }
  assert.ok(scoreOne(fx, { doc_refs: ['77'] }).fields.find(x => x.name === 'doc_refs').ok)
})
