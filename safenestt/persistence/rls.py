"""Row Level Security (RLS) with session-bound tenant context.

DESIGN:
-------
1. Application layer (Python) validates the API key against stored Argon2id hashes
2. On successful validation, app calls establish_tenant_context(tenant_id, key_fingerprint)
3. SECURITY DEFINER function verifies the fingerprint matches an active key
4. On match, records (pg_backend_pid(), tenant_id) in _tenant_context
5. RLS policies use get_current_tenant() which reads from _tenant_context

The key_fingerprint is SHA-256 of the raw key — deterministic, so the SQL function
can look it up in api_keys without needing Argon2 (which isn't available in SQL).

ATTACK ANALYSIS:
- SET app.current_tenant_id → REMOVED as a tenant-identity source. It was once
  read as a fallback by get_current_tenant(); because the policies delegate to
  that function, any role could claim any tenant. Do not reintroduce it.
- establish_tenant_context(tenant_id='other', key_fingerprint='guess') → fails because
  fingerprint won't match any active key in the database
- establish_tenant_context with own fingerprint → only binds own tenant_id
- Direct INSERT on _tenant_context → REVOKE ALL from app role
- Fake pg_backend_pid() → impossible (kernel-assigned)
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import text


def set_tenant_context(connection: Any, tenant_id: str, key_fingerprint: str) -> str:
    """Establish tenant context after application-layer key validation.
    
    Args:
        connection: Database connection
        tenant_id: The tenant_id from validated key
        key_fingerprint: SHA-256 of the raw API key (for server-side verification)
    
    Returns: The established tenant_id
    
    Raises: Exception if key_fingerprint doesn't match an active key
    """
    result = connection.execute(
        text("SELECT establish_tenant_context(:tid, :fp)"),
        {"tid": tenant_id, "fp": key_fingerprint}
    ).scalar()
    return result


def clear_tenant_context(connection: Any) -> None:
    """Clear tenant context for the current session."""
    connection.execute(text("SELECT clear_tenant_context()"))


def get_current_tenant_id(connection: Any) -> str | None:
    """Get the current tenant context."""
    result = connection.execute(
        text("SELECT get_current_tenant()")
    ).scalar()
    return result if result != "" else None


RLS_POLICY_SQL = """
-- Enable RLS on all tables
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
-- Graph tables (migration 002_graph_rls_tenant_isolation.sql).
-- These are child tables of investigations, exactly like evidence/findings/
-- reports, so they use the same tenant pattern.
ALTER TABLE graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_edges ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owners
ALTER TABLE investigations FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE graph_nodes FORCE ROW LEVEL SECURITY;
ALTER TABLE graph_edges FORCE ROW LEVEL SECURITY;

-- Drop existing policies
DROP POLICY IF EXISTS investigations_tenant_isolation ON investigations;
DROP POLICY IF EXISTS investigations_insert ON investigations;
DROP POLICY IF EXISTS agent_runs_tenant_isolation ON agent_runs;
DROP POLICY IF EXISTS agent_runs_insert ON agent_runs;
DROP POLICY IF EXISTS findings_tenant_isolation ON findings;
DROP POLICY IF EXISTS findings_insert ON findings;
DROP POLICY IF EXISTS evidence_tenant_isolation ON evidence;
DROP POLICY IF EXISTS evidence_insert ON evidence;
DROP POLICY IF EXISTS reports_tenant_isolation ON reports;
DROP POLICY IF EXISTS reports_insert ON reports;
DROP POLICY IF EXISTS audit_events_tenant_isolation ON audit_events;
DROP POLICY IF EXISTS audit_events_insert ON audit_events;
DROP POLICY IF EXISTS audit_events_update ON audit_events;
DROP POLICY IF EXISTS audit_events_delete ON audit_events;
DROP POLICY IF EXISTS audit_events_policy ON audit_events;
DROP POLICY IF EXISTS audit_events_insert ON audit_events;
DROP POLICY IF EXISTS graph_nodes_tenant_isolation ON graph_nodes;
DROP POLICY IF EXISTS graph_nodes_insert ON graph_nodes;
DROP POLICY IF EXISTS graph_edges_tenant_isolation ON graph_edges;
DROP POLICY IF EXISTS graph_edges_insert ON graph_edges;

-- Policies use get_current_tenant()
CREATE POLICY investigations_tenant_isolation ON investigations
    USING (tenant_id = get_current_tenant())
    WITH CHECK (tenant_id = get_current_tenant());

CREATE POLICY investigations_insert ON investigations
    FOR INSERT WITH CHECK (tenant_id = get_current_tenant());

CREATE POLICY agent_runs_tenant_isolation ON agent_runs
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY agent_runs_insert ON agent_runs
    FOR INSERT WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY findings_tenant_isolation ON findings
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY findings_insert ON findings
    FOR INSERT WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY evidence_tenant_isolation ON evidence
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY evidence_insert ON evidence
    FOR INSERT WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY reports_tenant_isolation ON reports
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY reports_insert ON reports
    FOR INSERT WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

-- Graph tables: identical child-table tenant pattern to evidence/findings/
-- reports. WITH CHECK on the FOR ALL policy is what denies cross-tenant and
-- no-context INSERT/UPDATE, matching migration 002.
CREATE POLICY graph_nodes_tenant_isolation ON graph_nodes
    FOR ALL
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ))
    WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY graph_nodes_insert ON graph_nodes
    FOR INSERT WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY graph_edges_tenant_isolation ON graph_edges
    FOR ALL
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ))
    WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY graph_edges_insert ON graph_edges
    FOR INSERT WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY audit_events_policy ON audit_events FOR ALL
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ))
    WITH CHECK (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

-- Fix: establish_tenant_context must look up by fingerprint (SHA-256),
-- not key_hash (Argon2). Argon2 hashes are non-deterministic so they
-- cannot be queried in SQL — only the deterministic fingerprint works.
-- The parameter is renamed from p_key_hash to p_key_fingerprint for clarity.
-- Drop and recreate the function if it exists with the old signature.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'establish_tenant_context' AND pronamespace = 'public'::regnamespace) THEN
        DROP FUNCTION public.establish_tenant_context(text, text);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.establish_tenant_context(p_tenant_id text, p_key_fingerprint text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_tenant_id TEXT;
    v_key_record RECORD;
BEGIN
    -- Look up the API key by fingerprint (SHA-256, deterministic, queryable in SQL)
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

    -- CORRECTED (migration 003): verify the claimed tenant BEFORE writing any
    -- context, so a rejected key never leaves a binding behind.
    IF v_tenant_id <> p_tenant_id THEN
        RAISE EXCEPTION 'Invalid API key or tenant mismatch';
    END IF;

    -- Set session-scoped GUC (false = not transaction-local) so tenant
    -- context survives cross-connection checks and is visible to RLS
    -- policies after the transaction commits.
    PERFORM set_config('app.current_tenant', v_tenant_id, false);

    RETURN v_tenant_id;
END;
$$;
"""


# =====================================================================
# TENANT CONTEXT INFRASTRUCTURE
#
# Must exist BEFORE RLS_POLICY_SQL is applied: every policy calls
# get_current_tenant(), and establish_tenant_context() writes to
# _tenant_context. Applying policies on a database where these are missing
# fails with:
#
#     psycopg2.errors.UndefinedFunction: function get_current_tenant() does not exist
#
# This block used to live only in migrate.py, so ensure_schema() — the path
# the FastAPI app actually calls at startup — could never bootstrap a fresh
# database. It is now defined here, once, and applied by BOTH paths via
# ensure_tenant_context() before apply_rls_policies().
#
# It is written to be safe on an existing database:
#   * _tenant_context uses CREATE TABLE IF NOT EXISTS
#   * functions are created only when absent, so an existing deployment's
#     (possibly newer) definitions are never silently replaced
#   * the api_keys.key_fingerprint column is added only if missing
# =====================================================================

TENANT_CONTEXT_SQL = """
-- Session-bound tenant context table.
--
-- CREATE TABLE IF NOT EXISTS still requires CREATE privilege on the schema,
-- which the application role may not hold. When ensure_schema() ran first the
-- table already exists under the app role, and the owner connection must not
-- fail on it. Guarded so this block is a no-op for an existing table.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = '_tenant_context'
          AND n.nspname = 'public'
    ) THEN
        CREATE TABLE _tenant_context (
            backend_pid INTEGER PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            key_fingerprint TEXT NOT NULL,
            established_at TIMESTAMP DEFAULT NOW(),
            expires_at TIMESTAMP NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
        );
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'idx_tenant_context_expires'
          AND n.nspname = 'public'
    ) THEN
        CREATE INDEX idx_tenant_context_expires ON _tenant_context (expires_at);
    END IF;
END $$;

-- establish_tenant_context() looks the key up by fingerprint, which must
-- therefore exist as a queryable column on api_keys.
--
-- Guarded on ownership as well as existence: when ensure_schema() ran first,
-- api_keys was created by the application role, and a non-owner ALTER TABLE
-- raises "must be owner of table". migrate.py (the owner path) still applies
-- it when the column is genuinely missing.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'key_fingerprint'
    ) AND EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_roles r ON r.oid = c.relowner
        WHERE c.relname = 'api_keys'
          AND c.relnamespace = 'public'::regnamespace
          AND r.rolname = current_user
    ) THEN
        ALTER TABLE api_keys ADD COLUMN key_fingerprint TEXT;
    END IF;
END $$;

-- get_current_tenant(): the function every RLS policy depends on.
-- Returns '' when no context is established, which matches no investigation
-- row, so policies fail closed.
-- CORRECTED (migration 003): previously created only when absent, so a
-- deployment could never repair a drifted or vulnerable definition. Replaced
-- unconditionally.
--
-- SECURITY: tenant identity comes ONLY from the PID-bound _tenant_context
-- written by establish_tenant_context(). A previous revision additionally
-- fell back to current_setting('app.current_tenant_id', true), which let ANY
-- role claim ANY tenant with `SET app.current_tenant_id = '<victim>'` -- the
-- RLS policies delegate their decision to this function, so spoofing it
-- satisfied the policy. There is deliberately no caller-controlled fallback.
-- No valid context returns '', which matches no row, so policies fail closed.
CREATE OR REPLACE FUNCTION get_current_tenant()
RETURNS TEXT AS $sfn$
BEGIN
    RETURN current_setting('app.current_tenant', true);
END;
$sfn$ LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, public;

-- clear_tenant_context(): drop this session's binding.
-- SECURITY (2026-10-02): the IF NOT EXISTS guard that used to wrap this block
-- meant an existing (possibly unhardened) definition was never repaired. Removed,
-- matching the corrective already applied to get_current_tenant() above.
--
-- Previously this was CREATE FUNCTION with an unqualified _tenant_context
-- reference and no search_path pin. pg_temp is searched FIRST unless explicitly
-- ordered last, so inside a SECURITY DEFINER body a temporary table named
-- _tenant_context would shadow the real one and the DELETE would silently no-op,
-- leaving stale tenant context bound to a pooled connection. CREATE OR REPLACE
-- so an existing unhardened definition is repaired rather than left in place.
CREATE OR REPLACE FUNCTION clear_tenant_context()
RETURNS VOID AS $sfn$
BEGIN
    DELETE FROM public._tenant_context WHERE backend_pid = pg_backend_pid();
END;
$sfn$ LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public;
"""


def ensure_tenant_context(engine: Any) -> None:
    """Create the tenant-context infrastructure required by the RLS policies.

    MUST run before apply_rls_policies(). Idempotent and non-destructive:
    an existing database keeps its current definitions.
    """
    with engine.connect() as conn:
        conn.execute(text(TENANT_CONTEXT_SQL))
        conn.commit()


def apply_rls_policies(engine: Any) -> None:
    """Apply RLS policies.

    The policies depend on get_current_tenant(). On a database where that
    has not been created yet, PostgreSQL cannot even parse the CREATE POLICY
    statements, so ensure_tenant_context() runs first automatically. This
    keeps every existing caller correct without forcing them to know the
    dependency order.
    """
    ensure_tenant_context(engine)
    with engine.connect() as conn:
        conn.execute(text(RLS_POLICY_SQL))
        conn.commit()
