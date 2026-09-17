"""Database migration script — run as a separate one-time job with owner privileges.

This module is executed by the `migrate` service in docker-compose.yml.
It creates tables, applies RLS policies with SECURITY DEFINER functions,
and grants least-privilege access to the safenestt_app role. The always-
running API container never holds owner credentials.
"""
from __future__ import annotations

import logging
import sys

from safenestt.persistence.engine import get_owner_engine
from safenestt.persistence.models import Base
from safenestt.persistence.rls import apply_rls_policies

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    """Run migrations. Returns 0 on success, 1 on failure."""
    logger.info("Starting database migration (owner role)...")
    
    try:
        owner_engine = get_owner_engine()
        
        logger.info("Creating tables if they don't exist...")
        Base.metadata.create_all(owner_engine)
        
        logger.info("Creating SECURITY DEFINER helper functions...")
        with owner_engine.connect() as conn:
            from sqlalchemy import text
            
            # Create the safenestt_app role if it doesn't exist
            result = conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = 'safenestt_app'")
            ).fetchone()
            if not result:
                conn.execute(text("""
                    CREATE ROLE safenestt_app LOGIN PASSWORD 'safenestt_app_pass';
                """))
                logger.info("  Created safenestt_app role")
            
            # SECURITY DEFINER function: set tenant context (validates input)
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION set_app_tenant_context(p_tenant_id TEXT)
                RETURNS VOID AS $$
                BEGIN
                    -- Validate tenant_id format (prevent injection)
                    IF p_tenant_id IS NULL OR p_tenant_id = '' THEN
                        RAISE EXCEPTION 'Invalid tenant_id: cannot be empty';
                    END IF;
                    IF LENGTH(p_tenant_id) > 128 THEN
                        RAISE EXCEPTION 'Invalid tenant_id: too long';
                    END IF;
                    -- Set the GUC
                    PERFORM set_config('app.current_tenant_id', p_tenant_id, FALSE);
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            # SECURITY DEFINER function: clear tenant context
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION clear_app_tenant_context()
                RETURNS VOID AS $$
                BEGIN
                    PERFORM set_config('app.current_tenant_id', '', FALSE);
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            # SECURITY DEFINER function: get current tenant context
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION get_app_tenant_context()
                RETURNS TEXT AS $$
                BEGIN
                    RETURN current_setting('app.current_tenant_id', TRUE);
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            # SECURITY DEFINER function: check cross-tenant access (returns BOOLEAN only)
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION check_cross_tenant_access(p_investigation_id TEXT, p_tenant_id TEXT)
                RETURNS BOOLEAN AS $$
                BEGIN
                    -- Use fixed search_path to prevent injection
                    SET search_path = public;
                    RETURN EXISTS(
                        SELECT 1 FROM investigations i
                        WHERE i.investigation_id = p_investigation_id
                        AND i.tenant_id != p_tenant_id
                    );
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            # Grant EXECUTE to app role (it can call the function but not see underlying data)
            conn.execute(text("GRANT EXECUTE ON FUNCTION set_app_tenant_context(TEXT) TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION clear_app_tenant_context() TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION get_app_tenant_context() TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION check_cross_tenant_access(TEXT, TEXT) TO safenestt_app"))
            
            # Revoke public execute (defense in depth)
            conn.execute(text("REVOKE ALL ON FUNCTION set_app_tenant_context(TEXT) FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION clear_app_tenant_context() FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION get_app_tenant_context() FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION check_cross_tenant_access(TEXT, TEXT) FROM PUBLIC"))
            
            conn.commit()
        
        logger.info("Applying RLS policies...")
        apply_rls_policies(owner_engine)
        
        logger.info("Granting privileges to safenestt_app role...")
        with owner_engine.connect() as conn:
            from sqlalchemy import text
            
            # Grant least-privilege to app role
            conn.execute(text("GRANT USAGE ON SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safenestt_app"))
            
            # Create migration marker table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS _migration_complete (
                    id SERIAL PRIMARY KEY,
                    completed_at TIMESTAMP DEFAULT NOW(),
                    version TEXT DEFAULT '1.0.0'
                );
                INSERT INTO _migration_complete DEFAULT VALUES;
            """))
            
            conn.commit()
        
        logger.info("Migration complete.")
        return 0
        
    except Exception as exc:
        logger.error("Migration failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
