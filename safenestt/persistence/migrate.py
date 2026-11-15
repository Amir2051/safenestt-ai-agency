"""Database migration — creates schema with secure tenant context."""
from __future__ import annotations

import logging
import sys

from safenestt.persistence.engine import get_owner_engine
from safenestt.persistence.models import Base
from safenestt.persistence.rls import apply_rls_policies

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    """Run migrations."""
    logger.info("Starting database migration (owner role)...")
    
    try:
        owner_engine = get_owner_engine()
        
        logger.info("Creating tables if they don't exist...")
        Base.metadata.create_all(owner_engine)
        
        logger.info("Creating secure tenant context infrastructure...")
        # Tenant context infrastructure (_tenant_context, the api_keys
        # .key_fingerprint column, get_current_tenant, clear_tenant_context)
        # is defined ONCE in rls.py::TENANT_CONTEXT_SQL and applied here, so
        # migrate.py and ensure_schema() cannot drift apart. It previously
        # lived only in this file, which meant ensure_schema() — the path the
        # FastAPI app calls at startup — could not bootstrap a fresh database.
        from safenestt.persistence.rls import ensure_tenant_context
        ensure_tenant_context(owner_engine)

        with owner_engine.connect() as conn:
            from sqlalchemy import text

            # Create safenestt_app role if missing
            result = conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = 'safenestt_app'")
            ).fetchone()
            if not result:
                conn.execute(text("CREATE ROLE safenestt_app LOGIN PASSWORD 'safenestt_app_pass';"))
                logger.info("  Created safenestt_app role")

            # The tenant context table must not be directly writable by the
            # application role — only via the SECURITY DEFINER functions.
            # Guarded on ownership: ensure_schema() may have created
            # _tenant_context under the app role if it ran first, and a
            # non-owner REVOKE raises "must be owner of table".
            conn.execute(text("""
                DO $$
                BEGIN
                    IF EXISTS (
                        -- CORRECTED (migration 004): this ownership test was false on
                        -- every real run -- _tenant_context is created by the APPLICATION role
                        -- via ensure_schema(), while the migration connects as the owner, so the
                        -- REVOKE below was silently skipped while GRANT ... ON ALL TABLES above
                        -- had already run. Revoking another role's grant does not require owning
                        -- the table; guard only on existence. Idempotent.
                        SELECT 1 FROM pg_class c
                        WHERE c.relname = '_tenant_context'
                          AND c.relnamespace = 'public'::regnamespace
                    ) THEN
                        EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public._tenant_context FROM safenestt_app';
                        EXECUTE 'REVOKE ALL ON public._tenant_context FROM PUBLIC';
                    END IF;
                END $$;
            """))

            conn.commit()

        with owner_engine.connect() as conn:
            from sqlalchemy import text

            # NOTE: the tenant functions are intentionally NOT redefined here.
            #
            # migrate.py previously carried its own copies of
            # establish_tenant_context, get_current_tenant and
            # clear_tenant_context, which conflicted with the authoritative
            # definitions in rls.py:
            #   * get_current_tenant / clear_tenant_context now come from
            #     rls.py::TENANT_CONTEXT_SQL (applied just above), which
            #     preserves an existing deployment's definitions instead of
            #     overwriting them.
            #   * establish_tenant_context is created by RLS_POLICY_SQL, whose
            #     version additionally inspects the key's `revoked` and
            #     `expires_at` values. The migrate.py copy did not, so running
            #     migrate.main() AFTER a policy application silently replaced
            #     the stricter function with the weaker one.
            #
            # Keeping a single definition removes that downgrade path.
            #
            # EXECUTE grants therefore happen LATER, after apply_rls_policies()
            # has created establish_tenant_context. Granting on a function that
            # does not exist yet fails with UndefinedFunction.

            # Drop old/insecure functions
            conn.execute(text("""
                DROP FUNCTION IF EXISTS set_app_tenant_context(TEXT);
                DROP FUNCTION IF EXISTS clear_app_tenant_context();
                DROP FUNCTION IF EXISTS get_app_tenant_context();
                DROP FUNCTION IF EXISTS check_cross_tenant_access(TEXT, TEXT);
            """))

            conn.commit()

        logger.info("Applying RLS policies...")
        # Creates establish_tenant_context as part of RLS_POLICY_SQL, after
        # ensure_tenant_context() has already created get_current_tenant().
        apply_rls_policies(owner_engine)

        with owner_engine.connect() as conn:
            from sqlalchemy import text

            # Grant EXECUTE on the tenant functions to the app role, and keep
            # them away from PUBLIC.
            conn.execute(text("GRANT EXECUTE ON FUNCTION establish_tenant_context(TEXT, TEXT) TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION get_current_tenant() TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION clear_tenant_context() TO safenestt_app"))
            conn.execute(text("REVOKE ALL ON FUNCTION establish_tenant_context(TEXT, TEXT) FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION get_current_tenant() FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION clear_tenant_context() FROM PUBLIC"))

            conn.commit()

        logger.info("Granting privileges to safenestt_app role...")
        with owner_engine.connect() as conn:
            conn.execute(text("GRANT USAGE ON SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app"))
            # SECURITY: these used to be GRANT ALL, which produced the default ACL
            # "safenestt_app=arwdDxtm" -- every future table would silently inherit
            # INSERT/UPDATE/DELETE/TRUNCATE/TRIGGER. A newly created security-sensitive
            # table would be writable by the application role by default.
            # Restricted to SELECT; writes must be granted per table.
            # REVOKE-then-GRANT so a broader default from a prior run is removed.
            # Idempotent. Sequence behaviour (USAGE, SELECT) is preserved.
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO safenestt_app"))
            
            # --- SECURITY (004): _tenant_context privilege protections ----------
            # This is the ONLY statement in this file that restores the privilege
            # state enforced by migrations/004_rls_tenant_context_privileges.sql,
            # which is NOT executed by any runner (migrate.py reads no .sql files).
            # It must run AFTER the GRANT ... ON ALL TABLES above, which would
            # otherwise re-grant write access to the tenant-binding table.
            # Idempotent; guarded on table existence.
            conn.execute(text("""
            DO $$
            DECLARE _r record;
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_class c
                    WHERE c.relname = '_tenant_context'
                      AND c.relnamespace = 'public'::regnamespace
                ) THEN
                    EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public._tenant_context FROM safenestt_app';
                    EXECUTE 'REVOKE ALL ON public._tenant_context FROM PUBLIC';
                    FOR _r IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'rls\_test\_%' LOOP
                        EXECUTE format('REVOKE ALL ON public._tenant_context FROM %I', _r.rolname);
                    END LOOP;
                END IF;
            END $$;
            """))

            # Re-revoke access to _tenant_context. The GRANT ... ON ALL TABLES above
            # would otherwise hand the app role full access to it. Guarded on
            # ownership for the same reason as the earlier REVOKE.
            conn.execute(text("""
                DO $$
                BEGIN
                    IF EXISTS (
                        -- CORRECTED (migration 004): this ownership test was false on
                        -- every real run -- _tenant_context is created by the APPLICATION role
                        -- via ensure_schema(), while the migration connects as the owner, so the
                        -- REVOKE below was silently skipped while GRANT ... ON ALL TABLES above
                        -- had already run. Revoking another role's grant does not require owning
                        -- the table; guard only on existence. Idempotent.
                        SELECT 1 FROM pg_class c
                        WHERE c.relname = '_tenant_context'
                          AND c.relnamespace = 'public'::regnamespace
                    ) THEN
                        EXECUTE 'REVOKE INSERT, UPDATE, DELETE ON public._tenant_context FROM safenestt_app';
                        EXECUTE 'REVOKE ALL ON public._tenant_context FROM PUBLIC';
                    END IF;
                END $$;
            """))
            
            conn.commit()
        
        logger.info("Writing migration-complete marker...")
        # wait_for_migrate.py polls for this table to decide whether the API may
        # start. It was never created, so the poll ALWAYS timed out (120s) and
        # the compose `api` service — which gates uvicorn on it with `&&` —
        # could never start. The marker is created only after every preceding
        # step succeeded.
        with owner_engine.connect() as conn:
            from sqlalchemy import text as _text
            conn.execute(_text("""
                CREATE TABLE IF NOT EXISTS _migration_complete (
                    completed_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    api_version TEXT
                )
            """))
            conn.execute(_text(
                "UPDATE _migration_complete SET completed_at = NOW()"))
            conn.commit()

        logger.info("Migration complete.")
        return 0
        
    except Exception as exc:
        logger.error("Migration failed: %s", exc)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
