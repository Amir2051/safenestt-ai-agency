#!/usr/bin/env bash
# ============================================================================
# Provision the application role inside the DEDICATED test instance.
# ============================================================================
#
# WHY
# ---
# RLS tests need a NON-superuser, non-BYPASSRLS application role: that is the
# whole point of the RLS test. Production has `safenestt_app`; the isolated
# test instance ships with only its own superuser (`safenestt_test`), so
# tests that connect as the app role fail with
# "password authentication failed for user safenestt_app".
#
# This creates the SAME role name in the test instance, with the TEST password,
# and grants it DML only — never ownership, never BYPASSRLS, never superuser.
# A role with those properties in the test instance mirrors production's
# security posture closely enough for RLS tests to be meaningful, and is
# completely unable to touch the production server because it does not exist
# there with this password and lives on a different port.
#
# Scope: TEST INSTANCE ONLY. It connects to 127.0.0.1:55432 and refuses to run
# against 54322.
# ============================================================================
set -euo pipefail

PORT="${SAFENESTT_TEST_PORT:-55432}"
DB="${SAFENESTT_TEST_DB_NAME:-safenestt_ai_test}"
OWNER="${SAFENESTT_TEST_OWNER_USER:-safenestt_test}"
PW="${SAFENESTT_TEST_PASSWORD:-safenestt_test_local_only}"
APP_PW="${SAFENESTT_TEST_APP_PASSWORD:-safenestt_test_local_only}"

if [ "$PORT" = "54322" ]; then
  echo "REFUSING: port 54322 is the PRODUCTION Postgres port." >&2
  exit 2
fi

echo "==> Provisioning safenestt_app in the TEST instance (127.0.0.1:${PORT}/${DB})"

PGPASSWORD="${PW}" psql -h 127.0.0.1 -p "${PORT}" -U "${OWNER}" -d "${DB}" -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'safenestt_app') THEN
    CREATE ROLE safenestt_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
      PASSWORD '${APP_PW}';
    RAISE NOTICE 'created role safenestt_app (NOSUPERUSER NOBYPASSRLS)';
  ELSE
    RAISE NOTICE 'role safenestt_app already exists';
  END IF;
END
\$\$;

-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- MIRROR PRODUCTION'S OWNER POSTURE
--
-- remediation_tests/test_graph_rls_security.py::test_force_rls_enabled_and_bypassrls_documented
-- pins down production's owner behaviour: the owner is NOT a superuser but
-- DOES carry BYPASSRLS (verified 2026-10-04: rolsuper=f, rolbypassrls=t), so
-- FORCE ROW LEVEL SECURITY binds the owner without overriding the BYPASSRLS
-- attribute. A stock postgres image creates a SUPERUSER owner, which would make
-- that assertion fail for a reason unrelated to RLS.
--
-- A role CANNOT demote itself ("The bootstrap user must have the SUPERUSER
-- attribute"), so demoting ${OWNER} is impossible from any session that is not
-- already a different superuser. Instead a dedicated role carrying the
-- production posture is created, and the schema bootstrap creates the tables AS
-- that role so it genuinely becomes the owner. The test then asserts against a
-- real NOSUPERUSER+BYPASSRLS owner rather than a superuser.
--
-- This applies ONLY to the dedicated test instance on ${PORT}. It cannot touch
-- production: this script refuses to run against 54322.
-- ---------------------------------------------------------------------------
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'safenestt_owner_test') THEN
    CREATE ROLE safenestt_owner_test LOGIN NOSUPERUSER BYPASSRLS NOCREATEROLE
      PASSWORD '${PW}';
    RAISE NOTICE 'created owner role safenestt_owner_test (NOSUPERUSER BYPASSRLS)';
  ELSE
    RAISE NOTICE 'owner role safenestt_owner_test already exists';
  END IF;
END
\$\$;

-- Adopt any pre-existing tenant-context functions as OWNER role.
--
-- The remediation schema bootstrap runs as safenestt_owner_test, which is
-- deliberately NOSUPERUSER. ensure_tenant_context() repairs a stale definition
-- by issuing "DROP FUNCTION IF EXISTS", which requires ownership. If those
-- functions were created by the bootstrap superuser (the common case, since it
-- creates them on a fresh database), the non-superuser owner cannot drop them
-- and every run after the first fails with:
--     InsufficientPrivilege: must be owner of function establish_tenant_context
--
-- Reassignment must happen HERE, as the superuser, because PostgreSQL does not
-- let a non-superuser take ownership away from another role. Doing it once at
-- provisioning time is what makes the remediation suite idempotent.
DO \$fnadopt\$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig,
           pg_get_userbyid(p.proowner) AS owner
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname IN ('establish_tenant_context',
                        'get_current_tenant',
                        'clear_tenant_context')
      AND pg_get_userbyid(p.proowner) <> 'safenestt_owner_test'
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO safenestt_owner_test', r.sig);
    RAISE NOTICE 'adopted % (was owned by %)', r.sig, r.owner;
  END LOOP;
END
\$fnadopt\$;

GRANT ALL ON SCHEMA public TO safenestt_owner_test;
GRANT ALL ON ALL TABLES IN SCHEMA public TO safenestt_owner_test;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO safenestt_owner_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO safenestt_owner_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO safenestt_owner_test;

-- ---------------------------------------------------------------------------
-- OWNER ROLE: full DDL, so it can create and own the schema.
--
-- Both conftests bootstrap schema AS this role. It needs CREATE on the schema
-- because it owns the tables it creates, and ownership is what lets
-- ensure_tenant_context() repair definitions via DROP FUNCTION.
-- ---------------------------------------------------------------------------
GRANT CONNECT ON DATABASE ${DB} TO safenestt_owner_test;
GRANT USAGE, CREATE ON SCHEMA public TO safenestt_owner_test;
GRANT ALL ON ALL TABLES IN SCHEMA public TO safenestt_owner_test;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO safenestt_owner_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO safenestt_owner_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO safenestt_owner_test;

-- ---------------------------------------------------------------------------
-- APPLICATION ROLE: DML only.
--
-- No CREATE, so it can never own a table and therefore can never drop one.
-- No BYPASSRLS, so RLS actually applies to it — that is the entire point of
-- having it. All grants live here rather than in a conftest because the owner
-- role is NOSUPERUSER and cannot grant to a role it is not a member of.
-- ---------------------------------------------------------------------------
GRANT CONNECT ON DATABASE ${DB} TO safenestt_app;
GRANT USAGE ON SCHEMA public TO safenestt_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO safenestt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO safenestt_app;
SQL

echo "==> Role flags (must show NOSUPERUSER + NOBYPASSRLS):"
PGPASSWORD="${PW}" psql -h 127.0.0.1 -p "${PORT}" -U "${OWNER}" -d "${DB}" -t -A -c \
  "SELECT 'rolsuper='||rolsuper||' rolbypassrls='||rolbypassrls||' rolcreatedb='||rolcreatedb
   FROM pg_roles WHERE rolname='safenestt_app';" | sed 's/^/    /'
echo "Done."