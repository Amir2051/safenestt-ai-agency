-- 004_rls_tenant_context_privileges.sql
--
-- Corrective migration. Does NOT touch historical migrations.
--
-- WHY THIS EXISTS
--   migrate.py grants the application role blanket table access:
--       GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app
--       ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safenestt_app
--   and then tries to undo it for _tenant_context specifically:
--       IF EXISTS (... AND r.rolname = current_user) THEN
--           REVOKE ALL ON _tenant_context FROM safenestt_app
--
--   That undo never fires on a real deployment. _tenant_context is created by
--   the APPLICATION role (ensure_schema() runs before the owner path), so when
--   migrate.py connects as postgres the ownership test `r.rolname = current_user`
--   is false and the whole REVOKE block is skipped -- while the GRANT directly
--   above it has already run. The result is that safenestt_app retains
--   INSERT/UPDATE/DELETE on _tenant_context.
--
--   That made tenant identity forgeable by anyone who can run SQL as the
--   application role -- no API key, no fingerprint, no establish_tenant_context():
--
--       INSERT INTO public._tenant_context (backend_pid, tenant_id, key_fingerprint, expires_at)
--       VALUES (pg_backend_pid(), '<any tenant>', 'forged', NOW() + INTERVAL '1 hour');
--
--   get_current_tenant() trusts that row, so every RLS policy (which delegates to
--   it) then admits the attacker's chosen tenant. Reproduced against this database:
--   3 victim rows exposed from a single INSERT. The primary key is backend_pid, so
--   an attacker can equally ON CONFLICT DO UPDATE a live victim session's row.
--
--   The application's SECURITY DEFINER design shows _tenant_context is meant to be
--   written ONLY by establish_tenant_context(), which runs as the owner and
--   re-verifies the API-key fingerprint in SQL. The app role needs no direct
--   write access to the table.
--
-- WHAT THIS DOES
--   1. Revokes INSERT, UPDATE, DELETE on public._tenant_context from safenestt_app.
--      SELECT is retained: it is read-only and supports operational inspection.
--   2. Revokes all table privileges on _tenant_context from the leftover rls_test_*
--      roles (test residue). The roles themselves are NOT dropped here.
--   3. Revokes any direct table privileges on _tenant_context from PUBLIC.
--   4. Re-asserts EXECUTE on the tenant-resolution functions for safenestt_app,
--      which the legitimate application flow requires.
--
-- SAFETY
--   Idempotent. Touches no application data: no INSERT, UPDATE, DELETE or TRUNCATE
--   against any application table. RLS policies and function definitions are not
--   modified. 001-003 are left exactly as applied.

BEGIN;

-- 1. The application role must not be able to write tenant identity directly.
--    SECURITY DEFINER establish_tenant_context() remains the only writer.
REVOKE INSERT, UPDATE, DELETE ON public._tenant_context FROM safenestt_app;

-- 2. Obsolete RLS test roles must not be able to write tenant identity either.
--    Roles are retained (not dropped) by instruction.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'rls\_test\_%' LOOP
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE, SELECT ON public._tenant_context FROM %I', r.rolname);
    END LOOP;
END $$;

-- 3. PUBLIC must never hold direct access to the tenant-binding table.
REVOKE INSERT, UPDATE, DELETE, SELECT ON public._tenant_context FROM PUBLIC;

-- 4. Re-assert the privileges the legitimate flow depends on (idempotent safety net).
GRANT EXECUTE ON FUNCTION public.establish_tenant_context(TEXT, TEXT) TO safenestt_app;
GRANT EXECUTE ON FUNCTION public.get_current_tenant() TO safenestt_app;
GRANT EXECUTE ON FUNCTION public.clear_tenant_context() TO safenestt_app;

COMMIT;
