"""Database migration script — run as a separate one-time job with owner privileges.

This module is executed by the `migrate` service in docker-compose.yml.
It creates tables, applies RLS policies, and grants least-privilege access
to the safenestt_app role. The always-running API container never holds
owner credentials.
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
        
        logger.info("Applying RLS policies...")
        apply_rls_policies(owner_engine)
        
        logger.info("Creating SECURITY DEFINER function for cross-tenant detection...")
        with owner_engine.connect() as conn:
            from sqlalchemy import text
            
            # SECURITY DEFINER function: checks if a record exists but belongs to another tenant
            # Runs with owner privileges but only returns a boolean (no data exposure)
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION check_cross_tenant_access(p_investigation_id TEXT, p_tenant_id TEXT)
                RETURNS BOOLEAN AS $$
                BEGIN
                    RETURN EXISTS(
                        SELECT 1 FROM investigations i
                        WHERE i.investigation_id = p_investigation_id
                        AND i.tenant_id != p_tenant_id
                    );
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """))
            
            # Grant EXECUTE to app role (it can call the function but not see underlying data)
            conn.execute(text("GRANT EXECUTE ON FUNCTION check_cross_tenant_access(TEXT, TEXT) TO safenestt_app"))
            
            # Revoke public execute (defense in depth)
            conn.execute(text("REVOKE ALL ON FUNCTION check_cross_tenant_access(TEXT, TEXT) FROM PUBLIC"))
            
            # Migrate tenant_id columns to NOT NULL where required
            tables_with_tenant = ["investigations"]
            for table in tables_with_tenant:
                try:
                    conn.execute(text(f"""
                        ALTER TABLE {table} 
                        ALTER COLUMN tenant_id SET NOT NULL
                    """))
                    logger.info(f"  {table}.tenant_id -> NOT NULL")
                except Exception as exc:
                    logger.warning(f"  Could not set {table}.tenant_id NOT NULL: {exc}")
            
            # Grant least-privilege to app role
            logger.info("Granting privileges to safenestt_app role...")
            conn.execute(text("GRANT USAGE ON SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safenestt_app"))
            conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safenestt_app"))
            
            conn.commit()
        
        logger.info("Migration complete.")
        return 0
        
    except Exception as exc:
        logger.error("Migration failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
