-- ════════════════════════════════════════════════════════════════════════════
-- supabase_erase_account.sql — make account erasure all-or-nothing (23.11.2026)
--
-- Run ONCE in Supabase → SQL Editor. Idempotent. Then:
--   npm run migrations -- --mark=supabase_erase_account.sql
--
-- ── WHY ─────────────────────────────────────────────────────────────────────
--
-- /api/account/delete issued ~15 separate REST deletes in sequence. Each one is
-- its own transaction, so a failure in the middle — a dropped connection, a
-- rate limit, a worker timeout — left the account PARTIALLY erased, and the
-- endpoint reported it as a count of errors in a JSON field.
--
-- That is the wrong shape for this particular operation. Erasure is a legal
-- promise (GDPR Art.17) and it is irreversible: "we deleted some of your data
-- and here is a number" satisfies nobody, and the user cannot tell which half
-- is gone. ASVS V2.3.3 asks for a transaction here for exactly this reason.
--
-- Postgres can give that; a sequence of REST calls cannot. So the row deletion
-- moves into ONE function that either completes or rolls back entirely.
--
-- ── WHAT STAYS OUTSIDE THE TRANSACTION, AND WHY ─────────────────────────────
--
-- Storage objects and the auth user are not Postgres rows in this schema's
-- transactional reach, so they stay in the Worker, ORDERED AFTER this call:
--
--   1. files   (best-effort, repeatable — deleting a file twice is harmless)
--   2. THIS    (atomic: every row, or none)
--   3. auth    (last, so a failure never orphans data behind a dead login)
--
-- A crash between 2 and 3 leaves a login with no data, which the user can
-- simply retry. The reverse — data with no login — is the one that cannot be
-- fixed from the outside, and that ordering prevents it.
-- ════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION erase_account(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_counts    jsonb := '{}'::jsonb;
  v_table     text;
  v_deleted   bigint;
  v_org       record;
  v_orgs_del  int := 0;
  v_orgs_anon int := 0;
  -- Children before parents. Every one of these carries
  -- `user_id … ON DELETE CASCADE`, so the cascade is the backstop; deleting
  -- explicitly is what makes the SCOPE auditable instead of implied.
  v_tables text[] := ARRAY[
    'sales_lines', 'sales_days', 'event_items', 'event_quotes',
    'supplier_budgets', 'supplier_aliases', 'receipts', 'receipt_books',
    'categories', 'suppliers', 'user_settings', 'memberships'
  ];
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'erase_account: p_user_id is required';
  END IF;

  -- ── 1. Organizations this user solely owns ────────────────────────────────
  -- Resolved BEFORE the membership rows go, because "sole member" is decided
  -- from memberships, and before the auth user goes, because owner_id is
  -- ON DELETE SET NULL and would be gone by then.
  FOR v_org IN
    SELECT o.id,
           EXISTS (SELECT 1 FROM client_accounts c WHERE c.org_id = o.id) AS has_billing
    FROM organizations o
    WHERE o.owner_id = p_user_id
      AND NOT EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.org_id = o.id AND m.user_id <> p_user_id
      )
  LOOP
    IF v_org.has_billing THEN
      -- The operator's own bookkeeping hangs off this org, and deleting it
      -- would cascade that away. Strip the business's identity instead.
      UPDATE organizations
         SET name = 'חשבון שנמחק', business_name = NULL, logo = NULL, slug = NULL
       WHERE id = v_org.id;
      v_orgs_anon := v_orgs_anon + 1;
    ELSE
      DELETE FROM organizations WHERE id = v_org.id;
      v_orgs_del := v_orgs_del + 1;
    END IF;
  END LOOP;

  -- ── 2. Every row keyed by this user ───────────────────────────────────────
  FOREACH v_table IN ARRAY v_tables LOOP
    -- to_regclass keeps this working on a project where an optional migration
    -- has not been run, without the "ignore a 404" guesswork the REST version
    -- needed.
    IF to_regclass('public.' || v_table) IS NOT NULL THEN
      EXECUTE format('DELETE FROM public.%I WHERE user_id = $1', v_table)
        USING p_user_id;
      GET DIAGNOSTICS v_deleted = ROW_COUNT;
      v_counts := v_counts || jsonb_build_object(v_table, v_deleted);
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'ok',              true,
    'tables',          v_counts,
    'orgs_deleted',    v_orgs_del,
    'orgs_anonymised', v_orgs_anon
  );
END $$;

-- Service-role only. This bypasses RLS by design, so nobody else may call it:
-- an end user able to invoke it could erase any account by id.
REVOKE ALL   ON FUNCTION erase_account(uuid) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION erase_account(uuid) TO service_role;

-- Check (expects ok=true and all-zero counts for a random, non-existent id):
--   SELECT erase_account('00000000-0000-0000-0000-000000000000'::uuid);
