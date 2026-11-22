-- ════════════════════════════════════════════════════════════════════════════
-- supabase_audit_chain_diagnose.sql — why does verify_audit_chain() fail?
-- (22.11.2026, security review)
--
-- READ-ONLY. This script changes NOTHING. Run it in the Supabase SQL editor and
-- send the output; it tells us which rows fail and in what way, which decides
-- what the fix is.
--
-- WHY IT EXISTS
-- -------------
-- verify_audit_chain() reports the chain broken at row 25 (12.11.2026, action
-- `suppliers_merged`). The LINKAGE is intact there — every prev_hash matches the
-- previous row's row_hash — so the failure is the CONTENT check: that row's
-- stored row_hash is not what the formula produces from the row as it stands
-- today.
--
-- Three things can produce that, and they need very different responses:
--
--   (a) The row was UPDATEd after insert. REVOKE UPDATE covers `authenticated`
--       and `anon`, but service_role is not revoked and the chain trigger is
--       BEFORE INSERT only — so a server-side update rewrites content and
--       leaves the hash behind. Benign cause, real gap: add a BEFORE UPDATE
--       trigger that refuses.
--
--   (b) The hash is not reproducible across sessions. The formula hashes
--       `created_at::text`, and timestamptz renders in the SESSION's TimeZone.
--       A row inserted from a session in one timezone cannot verify from a
--       session in another. If so the control has been unreliable since day one
--       and the formula must be pinned to UTC.
--
--   (c) The row really was altered. Then this is an incident, not a bug.
--
-- Query 3 separates (b) from (a)/(c): it recomputes each row's hash under
-- several timezones. If a row matches under some timezone, the cause is (b).
--
-- DO NOT "repair" the chain by recomputing the stored hashes. That is precisely
-- what tampering would look like, and it destroys the evidence for the window
-- in question. Diagnose first; re-baseline only deliberately, and record the
-- re-baseline in the log itself.
-- ════════════════════════════════════════════════════════════════════════════

-- ── 1. Current verdict and table size ───────────────────────────────────────
SELECT 'verdict' AS section, * FROM verify_audit_chain();

SELECT 'size' AS section, count(*) AS rows, min(id) AS first_id, max(id) AS last_id
FROM audit_log;

-- ── 2. EVERY failing row, not just the first ────────────────────────────────
-- verify_audit_chain() stops at the first problem; this lists them all, and
-- says whether each is a linkage break or a content mismatch.
WITH chained AS (
  SELECT
    a.*,
    lag(a.row_hash) OVER (ORDER BY a.id) AS actual_prev
  FROM audit_log a
),
checked AS (
  SELECT
    id, action, created_at, user_id, org_id,
    (coalesce(prev_hash, '') IS DISTINCT FROM coalesce(actual_prev, '')) AS linkage_broken,
    (row_hash IS DISTINCT FROM encode(digest(
        coalesce(prev_hash, '') || coalesce(action, '') || coalesce(target, '') ||
        coalesce(meta::text, '') || coalesce(user_id::text, '') ||
        coalesce(org_id::text, '') || created_at::text,
      'sha256'), 'hex')) AS content_broken
  FROM chained
)
SELECT 'failures' AS section, id, action, created_at, linkage_broken, content_broken
FROM checked
WHERE linkage_broken OR content_broken
ORDER BY id;

-- ── 3. Is the cause timezone-dependent serialisation? ───────────────────────
-- Recompute row 25's hash under a few session timezones. A match under ANY of
-- them means the stored hash is correct and the FORMULA is the defect — the
-- chain was never reproducible across sessions.
DO $$
DECLARE
  tz      text;
  r       audit_log%ROWTYPE;
  expect  text;
  hit     boolean := false;
BEGIN
  SELECT * INTO r FROM audit_log WHERE id = 25;
  IF NOT FOUND THEN RAISE NOTICE 'row 25 not present'; RETURN; END IF;

  FOREACH tz IN ARRAY ARRAY['UTC', 'Asia/Jerusalem', 'America/New_York', 'Etc/GMT-2', 'Etc/GMT-3']
  LOOP
    EXECUTE format('SET LOCAL TimeZone = %L', tz);
    expect := encode(digest(
      coalesce(r.prev_hash, '') || coalesce(r.action, '') || coalesce(r.target, '') ||
      coalesce(r.meta::text, '') || coalesce(r.user_id::text, '') ||
      coalesce(r.org_id::text, '') || r.created_at::text,
    'sha256'), 'hex');
    IF expect = r.row_hash THEN
      hit := true;
      RAISE NOTICE 'MATCH under TimeZone=%  ->  cause (b): the formula is timezone-dependent, the row is fine', tz;
    END IF;
  END LOOP;

  IF NOT hit THEN
    RAISE NOTICE 'no timezone reproduces the stored hash -> cause (a) a later UPDATE, or (c) alteration. Check query 4.';
  END IF;
END $$;

-- ── 4. Context around the failing row ───────────────────────────────────────
-- What was happening either side of it, and whether neighbours verify. A single
-- bad row among good ones points at that row; a run of bad rows from a point
-- onward points at a change in how they were written.
SELECT 'context' AS section, id, action, target, user_id, org_id, meta, created_at
FROM audit_log
WHERE id BETWEEN 20 AND 32
ORDER BY id;

-- ── 5. Known-good baseline ──────────────────────────────────────────────────
-- Rows 1..24 are expected to verify. If they do NOT, the problem is the formula
-- (or this verifier), not any one row.
WITH chained AS (
  SELECT a.*, lag(a.row_hash) OVER (ORDER BY a.id) AS actual_prev FROM audit_log a
)
SELECT 'baseline_1_24' AS section,
       count(*) FILTER (WHERE row_hash = encode(digest(
         coalesce(prev_hash,'') || coalesce(action,'') || coalesce(target,'') ||
         coalesce(meta::text,'') || coalesce(user_id::text,'') ||
         coalesce(org_id::text,'') || created_at::text, 'sha256'), 'hex')) AS verifying,
       count(*) AS total
FROM chained
WHERE id <= 24;

-- ════════════════════════════════════════════════════════════════════════════
-- SEPARATELY, AND INDEPENDENT OF THE ABOVE: a second break exists at row 95.
--
-- That one is understood and is ours. Row 94 was a synthetic `pentest_fixture`
-- row inserted by the RLS security suite, and the suite's teardown deleted it
-- on 22.11.2026 — which is exactly what the chain is built to notice. The
-- teardown no longer touches audit_log (see tests/security/rls.pentest.test.js);
-- the gap it already made cannot be undone without rewriting hashes, which is
-- the one thing nobody should do to an audit log.
--
-- So expect TWO findings from query 2: a content mismatch at 25 (unexplained,
-- the subject of this script) and a linkage break at 95 (explained, ours,
-- 22.11.2026).
-- ════════════════════════════════════════════════════════════════════════════
