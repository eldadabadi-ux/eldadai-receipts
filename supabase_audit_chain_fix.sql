-- ════════════════════════════════════════════════════════════════════════════
-- supabase_audit_chain_fix.sql — stop the schema from rewriting the audit log
-- (22.11.2026, security review — finding N14)
--
-- Run ONCE in Supabase → SQL Editor. Idempotent. Then:
--   npm run migrations -- --mark=supabase_audit_chain_fix.sql
--
-- ── WHAT WAS WRONG ──────────────────────────────────────────────────────────
--
-- verify_audit_chain() failed. The cause is not tampering and not the hash
-- formula — it is this line from supabase_audit.sql:
--
--     org_id uuid REFERENCES organizations(id) ON DELETE SET NULL
--
-- audit_log is append-only and hash-chained, and that foreign key gives the
-- database standing permission to UPDATE it. Delete an organization and
-- Postgres quietly sets org_id = NULL on every audit row that referenced it —
-- rewriting content whose hash was computed while org_id was still there. The
-- row_hash is left behind, so the row no longer verifies, and every row after
-- it inherits a chain that no longer adds up.
--
-- The correlation is total, across 110 rows:
--
--     org_id set   ->  72 rows,  72 verify,   0 fail
--     org_id NULL  ->  38 rows,   0 verify,  38 fail
--
-- Confirmed by a controlled case: the RLS suite's own `pentest_fixture` rows
-- were written WITH an org_id, verified at the time, and failed after the
-- suite's teardown deleted the throwaway organizations. Nothing touched the
-- rows themselves.
--
-- user_id was always right: it carries NO foreign key, deliberately, so that
-- an erasure record outlives the user it describes. org_id simply never got
-- the same treatment.
--
-- ── WHAT THIS DOES NOT DO ───────────────────────────────────────────────────
--
-- It does not repair the 38 rows. It cannot: the org_id they were hashed with
-- is gone, overwritten by the cascade. Recomputing their hashes would make the
-- verifier green while destroying the only evidence that anything happened —
-- which is exactly what tampering looks like, and is the one operation nobody
-- should ever perform on an audit log.
--
-- Instead the history is split at a baseline. Rows before it are marked
-- unverifiable WITH THE REASON RECORDED IN THE LOG ITSELF; rows after it are
-- verifiable and stay that way.
-- ════════════════════════════════════════════════════════════════════════════

-- ── 1. Remove the foreign key that mutates the log ──────────────────────────
-- Keeping org_id as a plain uuid matches user_id: the audit row records which
-- organization acted at the time, which stays true even after that
-- organization is gone. Referential integrity is the wrong property for an
-- immutable record of the past.
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c
  FROM pg_constraint
  WHERE conrelid = 'audit_log'::regclass
    AND contype = 'f'
    AND 'org_id' = ANY (
      SELECT attname FROM pg_attribute
      WHERE attrelid = conrelid AND attnum = ANY (conkey)
    );
  IF c IS NOT NULL THEN
    EXECUTE format('ALTER TABLE audit_log DROP CONSTRAINT %I', c);
    RAISE NOTICE 'dropped FK % on audit_log.org_id', c;
  ELSE
    RAISE NOTICE 'no FK on audit_log.org_id (already removed)';
  END IF;
END $$;

-- ── 2. Make append-only true for service_role as well ───────────────────────
-- REVOKE UPDATE/DELETE covered `authenticated` and `anon` only, and the chain
-- trigger was BEFORE INSERT only — so a server-side write could still edit a
-- row and leave its hash stale. This refuses at the table, whoever is asking.
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
BEGIN
  RAISE EXCEPTION
    'audit_log is append-only: % on row % is refused (A.8.15)',
    TG_OP, COALESCE(OLD.id::text, '?');
END $$;

DROP TRIGGER IF EXISTS audit_log_no_update_trg ON audit_log;
CREATE TRIGGER audit_log_no_update_trg BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- ── 3. Record the baseline — in the log, as an entry ────────────────────────
-- The gap is itself an auditable event, so it is written as one. Inserted
-- BEFORE the verifier changes below, so it is a normal chained row.
INSERT INTO audit_log (user_id, org_id, action, target, meta)
SELECT NULL, NULL, 'audit_chain_rebaselined', 'audit_log',
       jsonb_build_object(
         'reason',          'org_id FK ON DELETE SET NULL rewrote rows of deleted organizations',
         'finding',         'N14',
         'rows_unverifiable', (
            SELECT count(*) FROM audit_log WHERE org_id IS NULL
         ),
         'total_rows',      (SELECT count(*) FROM audit_log),
         'fix',             'FK dropped; BEFORE UPDATE OR DELETE refused',
         'note',            'earlier rows are NOT rewritten - the gap is recorded, not hidden'
       )
WHERE NOT EXISTS (
  SELECT 1 FROM audit_log WHERE action = 'audit_chain_rebaselined'
);

-- ── 4. Verifier: check from the baseline forward, and say so ────────────────
-- Same formula as before. The change is that it reports the baseline it
-- started from, so "ok" can never quietly mean "we skipped the awkward part".
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE(ok boolean, broken_id bigint, checked bigint, baseline_id bigint, skipped bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  r      audit_log%ROWTYPE;
  prev   text;
  expect text;
  n      bigint := 0;
  base   bigint;
BEGIN
  SELECT id INTO base FROM audit_log
   WHERE action = 'audit_chain_rebaselined' ORDER BY id LIMIT 1;
  base := COALESCE(base, 0);

  SELECT count(*) INTO skipped FROM audit_log WHERE id < base;
  baseline_id := base;

  -- Start from the baseline row's own prev_hash so linkage is checked honestly
  -- from that point rather than assumed.
  SELECT prev_hash INTO prev FROM audit_log WHERE id = base;
  prev := COALESCE(prev, '');

  FOR r IN SELECT * FROM audit_log WHERE id >= base ORDER BY id ASC LOOP
    n := n + 1;
    IF COALESCE(r.prev_hash, '') <> prev THEN
      ok := false; broken_id := r.id; checked := n; RETURN NEXT; RETURN;
    END IF;
    expect := encode(digest(
      COALESCE(r.prev_hash,'') || COALESCE(r.action,'') || COALESCE(r.target,'') ||
      COALESCE(r.meta::text,'') || COALESCE(r.user_id::text,'') ||
      COALESCE(r.org_id::text,'') || r.created_at::text, 'sha256'), 'hex');
    IF r.row_hash IS DISTINCT FROM expect THEN
      ok := false; broken_id := r.id; checked := n; RETURN NEXT; RETURN;
    END IF;
    prev := r.row_hash;
  END LOOP;

  ok := true; broken_id := NULL; checked := n; RETURN NEXT;
END $$;

REVOKE ALL   ON FUNCTION verify_audit_chain() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION verify_audit_chain() TO service_role;

-- ── 5. Check ────────────────────────────────────────────────────────────────
-- Expect ok = true, with skipped = the pre-baseline rows and baseline_id > 0.
SELECT * FROM verify_audit_chain();
