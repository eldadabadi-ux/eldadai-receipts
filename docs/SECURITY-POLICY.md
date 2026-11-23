# Security policy — מנהל קבלות (receipts-app)

**Version 1.0 · 23.11.2026 · applies to v2.14.0 onward · classification: internal**

This document exists because ~17 ASVS 5.0 L1/L2 requirements ask for a *written*
policy, not a control. In almost every case the control was already in the code;
what was missing was a statement of it that a reviewer could check the code
against. Where a policy records a decision nobody has actually made, it says so
rather than inventing one.

Each section names the requirements it answers.

---

## 1. Input validation rules — V2.1.1, V2.1.2, V2.1.3

**Principle.** Validation is enforced at a trusted service layer — Postgres RLS,
the Pages Functions, or a pure module called by both. Client-side checks exist
for usability and are never the control (V2.2.2).

**Positive validation** (allowlist) is used wherever the value space is closed:

| Input | Rule | Enforced in |
|---|---|---|
| Receipt file type | JPEG, PNG, WEBP, GIF, HEIC/HEIF, PDF — **verified by signature**, not by the declared type | `_lib/fileType.js`, `_lib/extractReceipt.js` |
| Pages per scan | ≤ 10 | `_lib/extractReceipt.js` (`MAX_PAGES`) |
| Bytes per page | ≤ 10 MB | `_lib/extractReceipt.js` (`MAX_IMAGE_BYTES`) |
| Quote attachment | ≤ 25 MB, any type (private bucket, never served as HTML) | `src/lib/eventFiles.js` |
| Inbound alias | `^[a-z0-9]+(-[a-z0-9]+)*$` | `_lib/inbound.js` (`ALIAS_RE`) |
| Payment method | one of `bank_transfer, standing_order, bit, credit_card, check, other` | `admin/clients.js` |
| Client status | one of `active, trial, paused, churned` | `admin/clients.js` |
| Module flag key | must be in `MODULE_FLAGS` | `admin/flags.js` |
| Dates | `YYYY-MM-DD`, not older than 3 years, not more than 30 days ahead | `_lib/extractReceipt.js` |
| Amounts | finite, `>= 0` (DB constraint), VAT rate `> 0` | `supabase_hardening_27001.sql` |
| Tenant ids | **never** taken from the client — derived from the session | RLS + `enforce_own_org` trigger |

**Encoding.** Every value interpolated into a PostgREST query string is
URL-encoded. This is not a convention but an enforced one: a raw `#` truncates
the URL at the fragment and silently drops the `&org_id=eq.…` predicate from a
service-role request. `tests/security/authz.unit.test.js` fails the build on any
unencoded interpolation.

**Contextual consistency (V2.1.2).** Extraction reconciles line items against the
stated total and rejects an implausible date. A summary invoice is reconciled
against the delivery notes it aggregates, with a ₪1.00 rounding tolerance
(`src/lib/reconciliation.js`).

**Business limits (V2.1.3).** Per-user, fixed-window:

| Operation | Limit |
|---|---|
| Receipt scan | 30 / min |
| Assistant chat | 20 / min |
| Recategorise | 10 / min |
| Supplier resolve | 60 / min |
| Supplier merge | 20 / min |
| Inbound alias | 20 / min |
| Admin console (all routes) | 60 / min |
| Account deletion | 5 / hour |

Backed by Cloudflare KV and **fail-open by design**: if the binding is missing,
requests pass. Abuse and cost protection must never be able to take the product
down.

## 2. File handling policy — V5.1.1

Permitted types and sizes are in §1. In addition:

- Stored paths are **generated internally** (`<user_id>/<receipt_id>.<ext>`,
  `<user_id>/events/<quote_id>/<random>.<ext>`). A user-supplied filename is kept
  for display only and never becomes a path.
- The bucket is **private**. Files are read through short-lived signed URLs and
  are never served from the application origin.
- Archives are never accepted as input. JSZip is used for export only, so there
  is no decompression path and no zip-bomb surface.
- **No antivirus scanning** (V5.4.3). Accepted risk at current scale: files are
  not executed, not served as HTML, and reach only Gemini and a private bucket.
  **Review trigger:** before any feature serves an uploaded file to a user other
  than its owner.

## 3. Authentication policy — V6.1.1, V6.1.2, V6.1.3, V6.3.4

**Pathways.** Exactly three, all through Supabase Auth:

1. **Email + password** — minimum 8 characters, enforced at onboarding
   (`admin/onboard.js`) and by the Supabase project policy for self-service.
2. **Passkey (WebAuthn)** — an account may switch to passkey-only.
3. **TOTP** — a second factor, not a pathway on its own.

There are no others: no social IdP, no magic links, no API tokens for end users.
The retired Gmail/Outlook OAuth channel (17.11.2026) authorised *mailbox access*
and was never a sign-in route.

**Step-up.** Once the platform owner has a verified TOTP factor, **every**
`admin/*` route requires AAL2. Enforced in one place (`_lib/guards.js`), and a
test forbids any admin route from defining its own copy.

**Rate limiting and anti-automation.** Credential-stuffing and brute-force
protection on the sign-in itself is Supabase's. **This has not been independently
verified** (ASVS V6.3.1 is recorded as PROVIDER, not PASS). Application-level
limits cover everything after authentication, per §1.

**Banned-password list (V6.1.2).** None is configured. Supabase's HaveIBeenPwned
check may or may not be enabled on this project — **not inspected**. *Action: one
console check, then record the result here.*

**Lost MFA factor (V6.4.4).** No documented process. In practice the operator
would act through the Supabase console. *Action: write it down, or the first
occurrence will be improvised.*

## 4. Session policy — V7.1.1, V7.1.2

Current behaviour is the Supabase default: ~1 hour access token with refresh
rotation, no application-level inactivity timeout, no absolute lifetime cap, and
no limit on concurrent sessions.

**This is a default, not a decision.** For a system holding a business's
financial records it deserves an explicit one. Recorded here as the current
state so that it is visible rather than assumed. *Action: decide an inactivity
timeout and an absolute lifetime, then configure and record them.*

Sessions terminate on sign-out (which also clears the page cache) and on account
deletion. Users **cannot** currently view or terminate their own other sessions,
and an administrator cannot terminate another user's (V7.4.5, V7.5.2 — open).

## 5. Authorization model — V8.1.1, V8.1.2

Function- and data-level rules are in `CLAUDE.md` ("Tenant separation"), which is
binding on all work in the repo. Summary:

- `org_id` is the canonical tenant scope; `user_id` is the original scoping and
  is retained.
- Every tenant table has RLS **and** an `enforce_own_org` trigger pinning both
  columns on end-user writes. RLS alone is insufficient: permissive policies are
  OR'd, so a foreign `org_id` on a write is not stopped by RLS.
- `memberships` has no INSERT policy — a user cannot join another organization.
- Proven by 44 live cross-tenant assertions before each release.

**Field-level (V8.1.2).** The only field-level restriction in the product is
`client_accounts` — the operator's billing record about each customer — which is
RLS-enabled **with no policy at all**, so no tenant can read any field of it.
Everything else is row-level. Service-role responses select explicit column
lists; the service-role key never reaches the browser.

## 6. Cryptographic key inventory and management — V11.1.1, V11.1.2

| Key | Purpose | Held in | Rotation |
|---|---|---|---|
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side DB access; **bypasses all RLS** | Cloudflare Pages env | On suspicion; on staff change |
| `SUPABASE_ANON_KEY` | Public client key; safe in the bundle | Bundle + env | With the project |
| `GEMINI_API_KEY` | OCR | Cloudflare Pages env | Annually; on suspicion |
| `ANTHROPIC_API_KEY` | Assistant | Cloudflare Pages env | Annually; on suspicion |
| `INBOUND_SECRET` | Email Worker → `/api/inbound` | Pages env **and** the Worker | Annually; both sides together |
| `CRON_SECRET` | Scheduled chain check | Pages env **and** GitHub secrets | Annually; both sides together |
| Supabase JWT secret | Signs session tokens | Supabase, never exported | Supabase-managed |
| TOTP seeds | MFA | Supabase | Per user, on re-enrolment |
| Audit chain | SHA-256 over row content | n/a — keyless | n/a |

**Algorithms in use:** AES-256-GCM (authenticated encryption), SHA-256,
HMAC-SHA256, bcrypt (Supabase, for passwords). No ECB, no PKCS#1 v1.5, no MD5 or
SHA-1. Randomness for anything unguessable uses `crypto.getRandomValues`;
`Math.random()` is permitted only for values that gate nothing (see §9).

**Rotation procedure.** For any key above: create the new value, set it in the
Cloudflare environment, redeploy, verify, then revoke the old one. For the two
shared secrets (`INBOUND_SECRET`, `CRON_SECRET`) both sides must change in the
same window; a mismatch fails loudly, which is the intended behaviour.

**Known weakness — least privilege (V13.3.1, V13.3.2).** One service-role key
does every server-side operation, from reading a category to erasing an account,
and it bypasses every RLS policy. There is no narrower role. This is the largest
single privilege concentration in the system. **Accepted for now; remediation is
a restricted Postgres role for read paths, which is a change that touches every
endpoint and must not be made without a staged rollout.**

**Crypto agility (V11.2.2).** Low. The audit chain hard-codes SHA-256 inside a
trigger, and `mailCrypto` hard-codes AES-GCM with no algorithm identifier stored
beside the ciphertext, so a future migration has nothing to branch on. Noted;
not currently blocking.

## 7. Data classification and protection — V14.1.1, V14.1.2, V14.2.4

| Class | Data | Protection | Retention |
|---|---|---|---|
| **Sensitive** | Receipt images and extracted financials; supplier contacts; event-quote customer names and phone numbers | RLS + trigger; private bucket; TLS; signed URLs only | While the account is active. Tax law may require 7 years — **the business owner's obligation, not the system's** |
| **Sensitive** | OAuth refresh tokens | AES-GCM at rest, server-side only | *Legacy — the channel was retired 17.11.2026* |
| **Operator** | `client_accounts` (contact, pricing, payment) | RLS with no tenant policy; service-role only | Survives tenant erasure, for bookkeeping; the organization is anonymised |
| **Evidence** | `audit_log` | Append-only, hash-chained, no UPDATE/DELETE | **Undecided — see below** |
| **Technical** | Server logs | Cloudflare; no PII (verified) | Cloudflare default |
| **Non-sensitive** | UI preferences in `localStorage` | none needed | Until the browser clears it |

**Retention is the open item.** No numeric policy exists for `audit_log`
(proposed: 24 months, which is also the regulatory floor for access logging) or
for receipts. *Action: operator decision, then state it here and in the privacy
policy.*

**Session token in `localStorage`** (V3.3.4, V14.3.3) is a known, accepted risk:
the supabase-js default, mitigated by a CSP with no `unsafe-inline` for scripts.
Remediation would be an httpOnly cookie via a proxy. Recorded as accepted, and
recorded as an unmet requirement — both are true.

## 8. Logging inventory — V16.1.1, V16.2.3

| Mechanism | Captures | Destination | Protection |
|---|---|---|---|
| `audit_log` | Privileged writes (onboarding, flags, client card, erasure, supplier merge/resolve) **and refused access** (`access_denied`) | Postgres | Append-only; hash-chained; UPDATE/DELETE revoked; readable only by the owning org, or by the platform owner |
| `console.*` | Unexpected errors with a correlation id; upstream failure detail | Cloudflare logs | Platform ACL |
| Supabase platform | Authentication events, Postgres logs | Supabase | Platform ACL |

**Content rule.** Audit `meta` carries ids, counts and short machine codes only —
never raw emails, document contents or mail subjects. Denial records keep the
request **method and path only**, never the query string, so a refused request
cannot be used to write attacker-chosen text into an append-only log.

**Known gaps, stated rather than implied:**
- Authentication events are **not** in the audit trail (V16.3.1). Supabase has
  them; they are not correlatable with privileged actions here.
- **Read access is not logged at all.** 101 of the client's data accesses go
  directly from browser to PostgREST under RLS and never reach our server, so
  an API-layer access log would cover a few percent while *looking* like
  compliance. See `security/regulation-10-22.11.26.md`; `pgaudit` is the only
  complete answer.
- Logs are **not** shipped to a separate system (V16.4.3). The daily
  `audit-chain` workflow is the one push-based detection that exists.

**Periodic review.** The audit chain is verified daily by the `audit-chain`
workflow; a break fails the run and notifies. This requirement was added after a
break went unnoticed for ten days.

## 9. Secure development — V15.1.1, V15.1.2, V15.1.3

**Vulnerability remediation time frames:**

| Severity (production tree) | Action |
|---|---|
| Critical | Same day. Release blocked. |
| High | Within 7 days. `npm audit --omit=dev --audit-level=high` blocks ship and CI, so this is enforced, not aspirational. |
| Moderate | Next planned release. |
| Low / dev-only | Tracked; not release-blocking. Dev-only advisories are not shipped to a customer and must never block a release that fixes something real. |

**SBOM (V15.1.2).** `docs/sbom.cyclonedx.json`, CycloneDX 1.5, production tree.
Regenerate with `npm sbom --sbom-format=cyclonedx --omit=dev`.

**Resource-intensive functionality (V15.1.3).** Gemini OCR (per page, paid), the
tool-calling assistant (multi-round, paid), full-tenant export, and the storage
walk in account erasure. All rate-limited per §1; the OCR paths additionally
capped by pages and bytes, enforced in `extractReceipt` so every ingestion
channel inherits the same ceiling.

**Release gates.** `npm run ship` and the CI workflow both run: unit tests,
offline security suites, QA suites, production dependency audit, migration
ledger check, cross-tenant RLS pentest, build. Both paths run the same gates —
previously only the local one did.

**Randomness.** `crypto.getRandomValues` for anything that must be unguessable.
`Math.random()` is permitted only where the value gates nothing: correlation
ids, an organization slug suffix, a receipt-book key, a storage object name
under a path already protected by RLS.

## 10. Open items

These are unmet and deliberately listed rather than quietly omitted.

| Item | Requirement | Owner |
|---|---|---|
| Session timeout and lifetime are undecided | V7.1.1, V7.3.1, V7.3.2 | Operator |
| Users cannot see or end their own sessions | V7.5.2 | Developer |
| Admin cannot terminate another user's sessions | V7.4.5 | Developer |
| No breached-password check confirmed | V6.2.4, V6.2.12 | Operator (one console check) |
| No lost-MFA recovery procedure | V6.4.4 | Operator |
| Single service-role key for everything | V13.3.1, V13.3.2 | Developer (staged) |
| `audit_log` retention undecided | V14.2.4, A.8.15 | Operator |
| Authentication events not in the audit trail | V16.3.1 | Developer |
| Read access not logged (needs `pgaudit`) | Regulation 10 | Operator + developer |
| Logs not shipped off-platform | V16.4.3 | Operator |
| No antivirus scanning of uploads | V5.4.3 | Accepted; review trigger in §2 |
| No dynamic scan (ZAP) has ever been run | — | Developer |

---

*Review this document on any change to authentication, tenancy, the key
inventory, or the logging mechanisms, and at minimum annually.*
