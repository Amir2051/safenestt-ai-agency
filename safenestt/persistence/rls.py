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
- SET app.current_tenant_id → ineffective (policies don't read GUC)
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

-- Force RLS for table owners
ALTER TABLE investigations FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

-- Drop existing policies
DROP POLICY IF EXISTS investigations_tenant_isolation ON investigations;
DROP POLICY IF EXISTS agent_runs_tenant_isolation ON agent_runs;
DROP POLICY IF EXISTS findings_tenant_isolation ON findings;
DROP POLICY IF EXISTS evidence_tenant_isolation ON evidence;
DROP POLICY IF EXISTS reports_tenant_isolation ON reports;
DROP POLICY IF EXISTS audit_events_tenant_isolation ON audit_events;

-- Policies use get_current_tenant()
CREATE POLICY investigations_tenant_isolation ON investigations
    USING (tenant_id = get_current_tenant());

CREATE POLICY agent_runs_tenant_isolation ON agent_runs
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY findings_tenant_isolation ON findings
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY evidence_tenant_isolation ON evidence
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY reports_tenant_isolation ON reports
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));

CREATE POLICY audit_events_tenant_isolation ON audit_events
    USING (investigation_id IS NULL OR investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_current_tenant()
    ));
"""


def apply_rls_policies(engine: Any) -> None:
    """Apply RLS policies."""
    with engine.connect() as conn:
        conn.execute(text(RLS_POLICY_SQL))
        conn.commit()
