# QA plan → tests that cover it

Maps the four areas of the QA/systems test plan (`security/gemini-code-*.md`) to
what actually runs, and records what each one measured on 23.11.2026.

Run the lot:

```
npm run test:qa          # items 1, 3, 4 — offline, no API cost
npm run eval:scan        # items 1, 2 — calls Gemini, costs money, needs .env.test
```

`test:qa` is in the ship gates. `eval:scan` is NOT: it spends real API budget per
run, so it belongs on a model change or a prompt change, not on every push.

---

## 1. Input validation and classification

*"Verify that the vision model correctly classifies inbound document types and separates them accordingly."*

| | |
|---|---|
| Covered by | `tests/eval/fixtures.mjs` (6 of 13 fixtures assert `doc_type`) · `tests/unit/extract.test.js` · `tests/unit/classify.test.js` |
| Measured | **doc_type 100% (6/6)** |

The classes are `receipt`, `delivery_note` and `summary_invoice` — the three the
product acts on. "Separates them accordingly" is the part that matters
financially and is enforced in code, not prompt: `isExpenseDoc()` keeps a summary
invoice out of every expense total, because it aggregates delivery notes that are
already counted. `loadYearReceipts` applies that filter at the loader, so the
dashboard and supplier comparison inherit it.

**Not covered:** `contract` is not a document class here — that belongs to the
law CRM, which is a separate codebase and has not been reviewed.

## 2. OCR data extraction accuracy

*"Evaluate extraction precision for dates, vendor names, totals and VAT. Must match sources with 100% fidelity."*

| | |
|---|---|
| Covered by | `npm run eval:scan` — 13 synthetic receipts, graded field by field by `tests/eval/score.mjs` (itself unit-tested in `tests/unit/evalScore.test.js`) |
| Measured | **96.5% overall (192/199), 10/13 perfect** |

Against the four fields the plan names:

| field | result |
|---|---|
| date | **100%** (13/13) |
| total | **100%** (13/13) |
| VAT (`before_vat`) | **100%** (12/12) |
| vendor | **92%** (12/13) |

Also measured: `doc_number` 100%, `item_count` 100%, `units` 100%, `currency` 100%.
Below 100%: `vendor` 12/13, `base_units` 0/1, `doc_refs` 0/1.

**On the 100% bar.** It is the right target for the four named fields and three of
them meet it. It is not a meaningful target for the suite as a whole, and a
harness that reported 100% on a probabilistic extractor would mean its fixtures
were too easy, not that the model was perfect. The value here is the per-field
breakdown: a model upgrade that reads dates better but truncates long item lists
shows up as exactly that, instead of averaging into a single reassuring number.

## 3. Database integration and schema matching

*"Ensure every processed document is linked to the correct customer record, preventing data mixing or duplicate entries."*

Two separate properties, both now covered.

**Linked to the correct customer / no mixing** — `tests/security/rls.pentest.test.js`,
44 live assertions across 17 tables plus Storage. Two real tenants are
provisioned and neither can read, write, re-tag, join or reach the other.
Enforced in Postgres (RLS + an `enforce_own_org` trigger), not in the client.
43 pass; the one failure is the audit-chain alarm, unrelated to linkage.

**No duplicate entries** — `tests/unit/duplicateCheck.test.js`, 16 assertions.
This was a real gap found by this plan: the mail channel deduplicated on message
id, the camera and upload paths did not, and `receipts` has no uniqueness
constraint. Fixed in `src/lib/duplicateCheck.js` (commit `473c519`). It warns
rather than blocks, because two identical small purchases on one day are
legitimate and only the user can tell them from a double scan.

## 4. Financial balance calculation

*"Accurately compute total expenses versus revenue per case, with an updated profit and loss statement."*

| | |
|---|---|
| Covered by | `tests/unit/salesMath.test.js` · `tests/unit/quotes.test.js` · `tests/unit/budgets.test.js` · `tests/unit/reconciliation.test.js` · `tests/unit/installments.test.js` |
| Verified | expenses exclude summary invoices at the loader; an event with no recorded costs reports "profit unknown" rather than a profit figure that is really just revenue |

"Per case" maps to **per event** here (the events book: a quote is the revenue
side, receipts in that book are the cost side). Revenue also comes from
`sales_days`/`sales_lines`.

Two correctness properties worth stating, because both are easy to get wrong and
both hold:

- **No double counting.** A summary invoice and the delivery notes it aggregates
  describe the same money. `loadYearReceipts` filters summary invoices out, so
  every total downstream — dashboard, supplier comparison, monthly bars —
  inherits the exclusion from one place.
- **No invented profit.** `profit: t.fully_costed ? (t.profit || 0) : 0`, with the
  event counted as `unknown`. An uncosted event contributes revenue and is shown
  as profit-unknown, instead of displaying its revenue as if it were margin.

**"Real-time" is accurate with one caveat:** figures are computed client-side from
a cached page of rows (`pageCache`), invalidated on write via
`invalidateReceiptData()`. A second device's changes appear on the next load, not
instantly.
