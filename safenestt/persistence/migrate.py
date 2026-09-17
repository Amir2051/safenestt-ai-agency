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
        with owner_engine.connect() as conn:
            from sqlalchemy import text
            
            # Create safenestt_app role if missing
            result = conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = 'safenestt_app'")
            ).fetchone()
            if not result:
                conn.execute(text("CREATE ROLE safenestt_app LOGIN PASSWORD 'safenestt_app_pass';"))
                logger.info("  Created safenestt_app role")
            
            # Session-bound tenant context table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS _tenant_context (
                    backend_pid INTEGER PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    established_at TIMESTAMP DEFAULT NOW(),
                    expires_at TIMESTAMP NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_context_expires 
                ON _tenant_context (expires_at);
            """))
            
            # Revoke ALL from app role
            conn.execute(text("REVOKE ALL ON _tenant_context FROM safenestt_app"))
            conn.execute(text("REVOKE ALL ON _tenant_context FROM PUBLIC"))
            
            # Add key_fingerprint column to api_keys if it doesn't exist
            conn.execute(text("""
                DO $$ 
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'api_keys' AND column_name = 'key_fingerprint'
                    ) THEN
                        ALTER TABLE api_keys ADD COLUMN key_fingerprint TEXT;
                    END IF;
                END $$;
            """))
            
            # SECURITY DEFINER: establish_tenant_context
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION establish_tenant_context(
                    p_tenant_id TEXT, 
                    p_key_fingerprint TEXT
                )
                RETURNS TEXT AS $$
                DECLARE
                    v_count INTEGER;
                BEGIN
                    SET search_path = public;
                    
                    -- Verify that an active key exists with matching tenant_id AND fingerprint
                    SELECT COUNT(*) INTO v_count
                    FROM api_keys ak
                    WHERE ak.key_fingerprint = p_key_fingerprint
                    AND ak.tenant_id = p_tenant_id
                    AND ak.active = TRUE
                    AND ak.revoked = FALSE
                    AND (ak.expires_at IS NULL OR ak.expires_at > NOW());
                    
                    IF v_count = 0 THEN
                        RAISE EXCEPTION 'Invalid API key or tenant mismatch';
                    END IF;
                    
                    -- Record context
                    INSERT INTO _tenant_context (backend_pid, tenant_id, key_fingerprint, expires_at)
                    VALUES (pg_backend_pid(), p_tenant_id, p_key_fingerprint, NOW() + INTERVAL '1 hour')
                    ON CONFLICT (backend_pid) 
                    DO UPDATE SET 
                        tenant_id = EXCLUDED.tenant_id,
                        key_fingerprint = EXCLUDED.key_fingerprint,
                        established_at = NOW(),
                        expires_at = NOW() + INTERVAL '1 hour';
                    
                    RETURN p_tenant_id;
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION get_current_tenant()
                RETURNS TEXT AS $$
                DECLARE
                    v_tenant_id TEXT;
                BEGIN
                    SET search_path = public;
                    SELECT tc.tenant_id INTO v_tenant_id
                    FROM _tenant_context tc
                    WHERE tc.backend_pid = pg_backend_pid()
                    AND tc.expires_at > NOW();
                    RETURN COALESCE(v_tenant_id, '');
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION clear_tenant_context()
                RETURNS VOID AS $$
                BEGIN
                    SET search_path = public;
                    DELETE FROM _tenant_context WHERE backend_pid = pg_backend_pid();
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            # Drop old/insecure functions
            conn.execute(text("""
                DROP FUNCTION IF EXISTS set_app_tenant_context(TEXT);
                DROP FUNCTION IF EXISTS clear_app_tenant_context();
                DROP FUNCTION IF EXISTS get_app_tenant_context();
                DROP FUNCTION IF EXISTS check_cross_tenant_access(TEXT, TEXT);
            """))
            
            # Grant EXECUTE to app role
            conn.execute(text("GRANT EXECUTE ON FUNCTION establish_tenant_context(TEXT, TEXT) TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION get_current_tenant() TO safenestt_app"))
            conn.execute(text("GRANT EXECUTE ON FUNCTION clear_tenant_context() TO safenestt_app"))
            
            conn.execute(text("REVOKE ALL ON FUNCTION establish_tenant_context(TEXT, TEXT) FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION get_current_tenant() FROM PUBLIC"))
            conn.execute(text("REVOKE ALL ON FUNCTION clear_tenant_context() FROM PUBLIC"))
            
            conn.commit()
        
        logger.info("Applying RLS policies...")
        apply_rls_policies(owner_engine)
        
        logger.info("Granting privileges to safenestt_app role...")
        with owner_engine.connect() as conn:
            conn.execute(text("GRANT USAGE ON SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safenestt_app"))
            
            # Re-revoke access to _tenant_context
            conn.execute(text("REVOKE ALL ON _tenant_context FROM safenestt_app"))
            conn.execute(text("REVOKE ALL ON _tenant_context FROM PUBLIC"))
            
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
