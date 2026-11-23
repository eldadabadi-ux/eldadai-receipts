/**
 * duplicateCheck — is this receipt already in the book?
 *
 * WHY: the mail channel has deduplicated since it shipped (`alreadyImported`
 * matches on the message id), but the manual paths — camera, file upload, link
 * import — insert unconditionally. Photograph a receipt, lose signal, photograph
 * it again, and the expense is counted twice. Nothing warns, and nothing in the
 * schema prevents it: `receipts` has no uniqueness constraint.
 *
 * That lands directly on the P&L. A duplicated delivery note inflates expenses,
 * understates profit for that month, and quietly corrupts supplier comparisons
 * and budget consumption — all of which read the same rows.
 *
 * WARN, NEVER BLOCK. Two coffees from the same kiosk on the same morning are a
 * real pair of receipts, not a mistake, and a hard uniqueness constraint would
 * refuse the second one. The user is the only one who can tell the difference,
 * so this returns what it found and leaves the decision to them.
 *
 * Pure and synchronous: it grades a candidate against rows already loaded. No
 * query, no I/O — so the rules are unit-testable, which is the point.
 */
import { normalizeVendor, vendorSimilarity } from '../../functions/api/_lib/supplierMatch.js'
import { docTypeOf } from './docTypes.js'

/** Document numbers compare by digits only: "ת. 00123" === "123". */
export const normalizeDocNum = (s) => String(s || '').replace(/\D+/g, '').replace(/^0+/, '')

/** Amounts within one agora are the same amount. */
const sameAmount = (a, b) => {
  const x = Number(a), y = Number(b)
  return Number.isFinite(x) && Number.isFinite(y) && Math.abs(x - y) < 0.01
}

const sameDay = (a, b) => !!a && !!b && String(a).slice(0, 10) === String(b).slice(0, 10)

/** Same supplier — by id when both carry one, else by normalized name. */
function sameSupplier(a, b) {
  if (a?.supplier_id && b?.supplier_id) return a.supplier_id === b.supplier_id
  const na = normalizeVendor(a?.vendor_name), nb = normalizeVendor(b?.vendor_name)
  if (!na || !nb) return false
  return na === nb || vendorSimilarity(a?.vendor_name, b?.vendor_name) >= 0.92
}

/**
 * Grade one existing row against the candidate.
 * @returns {{level:'exact'|'likely'|null, reason:string}}
 */
export function compareOne(candidate, existing) {
  if (!candidate || !existing) return { level: null, reason: '' }
  if (existing.id && candidate.id && existing.id === candidate.id) return { level: null, reason: '' }

  // A document number is the supplier's own unique identifier for the document.
  // Same supplier + same number is the strongest signal there is, and it holds
  // even when the date or total was read differently by OCR on the second scan.
  const cNum = normalizeDocNum(candidate.doc_number)
  const eNum = normalizeDocNum(existing.doc_number)
  if (cNum && eNum && cNum === eNum && sameSupplier(candidate, existing)) {
    return { level: 'exact', reason: `אותו ספק ואותו מספר מסמך (${candidate.doc_number})` }
  }

  // No document number to go on: supplier + date + amount together are a strong
  // hint, but legitimately repeatable - hence 'likely', and hence a warning.
  if (sameSupplier(candidate, existing)
      && sameDay(candidate.receipt_date, existing.receipt_date)
      && sameAmount(candidate.amount, existing.amount)) {
    // A delivery note and the summary invoice that aggregates it are a
    // different document type for the same money - not a duplicate.
    if (docTypeOf(candidate) !== docTypeOf(existing)) return { level: null, reason: '' }
    return { level: 'likely', reason: 'אותו ספק, אותו תאריך ואותו סכום' }
  }

  return { level: null, reason: '' }
}

/**
 * Find rows that look like the candidate.
 *
 * @param {object} candidate   the receipt about to be saved
 * @param {object[]} existing  rows already in the book (the loaded page is enough)
 * @returns {{level:'exact'|'likely'|null, reason:string, matches:object[]}}
 */
export function findDuplicates(candidate, existing = []) {
  const matches = []
  let level = null, reason = ''

  for (const row of Array.isArray(existing) ? existing : []) {
    const r = compareOne(candidate, row)
    if (!r.level) continue
    matches.push({ ...row, _match: r.level, _reason: r.reason })
    // An exact match outranks any number of likely ones.
    if (r.level === 'exact' && level !== 'exact') { level = 'exact'; reason = r.reason }
    else if (!level) { level = 'likely'; reason = r.reason }
  }

  return { level, reason, matches }
}

/** Hebrew confirmation text for a found duplicate. Empty when there is none. */
export function duplicateWarning(result) {
  if (!result?.level) return ''
  const n = result.matches.length
  const head = result.level === 'exact'
    ? 'נראה שהקבלה הזו כבר קיימת במערכת.'
    : 'ייתכן שהקבלה הזו כבר קיימת במערכת.'
  const found = n === 1 ? 'נמצאה רשומה תואמת' : `נמצאו ${n} רשומות תואמות`
  return `${head}\n${found} — ${result.reason}.\n\nלשמור בכל זאת?`
}
