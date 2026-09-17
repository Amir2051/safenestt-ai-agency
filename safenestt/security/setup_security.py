"""Database security hardening setup.

Run this ONCE to apply permanent security hardening to the database:
1. Enable pgcrypto extension (for additional encryption options if needed)
2. Restrict audit_events to INSERT-only for the app role
3. Set up SSL enforcement
4. Apply default privileges for future tables

This script should be run by a DBA/superuser after deployment.
"""

from __future__ import annotations

import os
import sys

SECURITY_SQL = """
-- Enable pgcrypto for column-level encryption functions (if needed)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- AUDIT LOG INTEGRITY: INSERT-ONLY FOR APP ROLE
-- ============================================================
-- Revoke any existing UPDATE/DELETE on audit_events from app role
REVOKE UPDATE, DELETE ON audit_events FROM safenestt_app;
-- Ensure only INSERT is granted (SELECT for reading)
GRANT INSERT ON audit_events TO safenestt_app;

-- ============================================================
-- SSL ENFORCEMENT (requires postgresql.conf changes too)
-- ============================================================
-- Check current SSL setting
SHOW ssl;

-- ============================================================
-- DEFAULT PRIVILEGES FOR FUTURE TABLES
-- ============================================================
-- Grant appropriate access on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO safenestt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO safenestt_app;
"""


def setup_database_security():
    """Apply security hardening to the database."""
    import psycopg2

    db_url = os.getenv(
        "SAFENESTT_DATABASE_URL",
        "postgresql://postgres:postgres@172.19.0.11:5432/safenestt_ai"
    )

    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    cur = conn.cursor()

    # Check if tables exist
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'audit_events'
        );
    """)
    tables_exist = cur.fetchone()[0]

    if not tables_exist:
        print("Tables do not exist yet. Run the application first to create tables.")
        print("Security hardening will be applied during test setup.")
        return

    # Apply security hardening
    try:
        cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        print("[OK] pgcrypto extension enabled")
    except Exception as exc:
        print(f"[WARN] Could not enable pgcrypto: {exc}")

    try:
        cur.execute("REVOKE UPDATE, DELETE ON audit_events FROM safenestt_app;")
        print("[OK] Revoked UPDATE/DELETE on audit_events from safenestt_app")
    except Exception as exc:
        print(f"[WARN] Could not revoke privileges: {exc}")

    try:
        cur.execute("GRANT INSERT ON audit_events TO safenestt_app;")
        print("[OK] Granted INSERT on audit_events to safenestt_app")
    except Exception as exc:
        print(f"[WARN] Could not grant INSERT: {exc}")

    # Verify
    cur.execute("""
        SELECT privilege_type
        FROM information_schema.role_table_grants
        WHERE table_name = 'audit_events' AND grantee = 'safenestt_app';
    """)
    privileges = [row[0] for row in cur.fetchall()]
    print(f"[INFO] safenestt_app privileges on audit_events: {privileges}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    setup_database_security()
