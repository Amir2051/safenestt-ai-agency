-- 003_rls_tenant_identity_hardening.sql
--
-- Corrective migration. Does NOT touch historical migrations.
--
-- WHY THIS EXISTS
--   A deployed public.get_current_tenant() read a caller-controlled GUC as a
--   fallback tenant identity:
--       v_tenant_id := current_setting('app.current_tenant_id', true);
--   Every RLS policy delegates its decision to that function
--   (tenant_id = get_current_tenant()), so any role able to run SQL -- not just
--   superuser or a BYPASSRLS role -- could claim ANY tenant with:
--       SET LOCAL app.current_tenant_id = '<victim>';
--   and then read (and, where policies permit, write) that tenant's
--   investigations, evidence, findings, reports and agent runs.
--
--   The in-function comment claimed this was safe "because RLS policies still
--   enforce tenant_id column matching". That is inverted: the policy *is* the
--   call to this function, so spoofing the function satisfies the policy.
--
--   The repository definition could not repair it either: get_current_tenant()
--   was created only `IF NOT EXISTS`, so a redeploy silently kept whatever
--   definition the database already had.
--
-- WHAT THIS DOES
--   1. Recreates get_current_tenant() with NO caller-controlled fallback. Tenant
--      identity comes only from the PID-bound, fingerprint-verified
--      public._tenant_context written by establish_tenant_context(). With no
--      valid context it returns '', which matches no row, so policies fail closed.
--   2. Hardens both SECURITY DEFINER functions: schema-qualified object
--      references (public._tenant_context, public.api_keys) and
--      `SET search_path = pg_catalog, public`. pg_temp is searched FIRST unless
--      explicitly ordered last, so a bare `SET search_path = public` did not
--      prevent temporary-object shadowing.
--   3. Moves establish_tenant_context()'s tenant-match check BEFORE it writes
--      any context row, so a rejected key leaves no binding behind.
--   4. Revokes EXECUTE on the tenant-resolution functions from leftover
--      rls_test_* roles (test residue). safenestt_app KEEPS its EXECUTE grants --
--      the legitimate application flow requires them.
--
-- SAFETY
--   Idempotent (CREATE OR REPLACE). Touches no application data: no INSERT,
--   UPDATE, DELETE or TRUNCATE. RLS policies themselves are not modified.
--   001 and 002 are left exactly as applied.

BEGIN;

CREATE OR REPLACE FUNCTION public.get_current_tenant() RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $fn$
DECLARE
    v_tenant_id TEXT;
BEGIN
    SELECT tc.tenant_id INTO v_tenant_id
    FROM public._tenant_context tc
    WHERE tc.backend_pid = pg_backend_pid()
      AND tc.expires_at > NOW();

    RETURN COALESCE(v_tenant_id, '');
END;
$fn$;

CREATE OR REPLACE FUNCTION public.establish_tenant_context(
    p_tenant_id TEXT, p_key_fingerprint TEXT) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog, public
AS $fn$
DECLARE
    v_tenant_id TEXT;
    v_key_record RECORD;
BEGIN
    SELECT ak.tenant_id, ak.expires_at, ak.revoked
    INTO v_key_record
    FROM public.api_keys ak
    WHERE ak.key_fingerprint = p_key_fingerprint
      AND ak.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid API key or tenant mismatch';
    END IF;

    IF v_key_record.revoked = TRUE THEN
        RAISE EXCEPTION 'API key has been revoked';
    END IF;

    IF v_key_record.expires_at IS NOT NULL AND v_key_record.expires_at < NOW() THEN
        RAISE EXCEPTION 'API key has expired';
    END IF;

    v_tenant_id := v_key_record.tenant_id;

    -- Validate BEFORE writing: a rejected key must not leave a binding behind.
    IF v_tenant_id <> p_tenant_id THEN
        RAISE EXCEPTION 'Invalid API key or tenant mismatch';
    END IF;

    INSERT INTO public._tenant_context (backend_pid, tenant_id, key_fingerprint, expires_at)
    VALUES (pg_backend_pid(), v_tenant_id, p_key_fingerprint, NOW() + INTERVAL '1 hour')
    ON CONFLICT (backend_pid) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        key_fingerprint = EXCLUDED.key_fingerprint,
        established_at = NOW(),
        expires_at = NOW() + INTERVAL '1 hour';

    RETURN v_tenant_id;
END;
$fn$;

-- Leftover RLS test roles must not be able to resolve or mint tenant context.
-- safenestt_app is deliberately left alone.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'rls\_test\_%' LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION public.establish_tenant_context(text,text) FROM %I', r.rolname);
        EXECUTE format('REVOKE ALL ON FUNCTION public.get_current_tenant() FROM %I', r.rolname);
        EXECUTE format('REVOKE ALL ON FUNCTION public.clear_tenant_context() FROM %I', r.rolname);
        EXECUTE format('REVOKE ALL ON FUNCTION public.cleanup_expired_tenant_context() FROM %I', r.rolname);
    END LOOP;
END $$;

-- Re-assert the application role's required privileges. Idempotent, and a
-- safety net if an earlier REVOKE ran too broadly.
GRANT EXECUTE ON FUNCTION public.establish_tenant_context(TEXT, TEXT) TO safenestt_app;
GRANT EXECUTE ON FUNCTION public.get_current_tenant() TO safenestt_app;
GRANT EXECUTE ON FUNCTION public.clear_tenant_context() TO safenestt_app;
REVOKE ALL ON FUNCTION public.establish_tenant_context(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_current_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.clear_tenant_context() FROM PUBLIC;

COMMIT;
