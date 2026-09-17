"""Row Level Security (RLS) for PostgreSQL tenant isolation.

RLS policies are enforced at the database level. They apply to all
non-owner roles. The table owner (typically `postgres`) bypasses RLS
by default in PostgreSQL. For production defense-in-depth, the
application connects as a dedicated non-owner role (`safenestt_app`).

The `apply_rls_policies()` function enables RLS and creates policies
on all tables. The `set_tenant_context()` helper sets the `app.current_tenant_id`
GUC that the policies read from.

CRITICAL: RLS policies use SECURITY DEFINER functions to prevent
the app role from spoofing the tenant context.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import text

# Fixed search_path for SECURITY DEFINER functions
_SEARCH_PATH = "SET search_path = public"


def set_tenant_context(connection: Any, tenant_id: str | None) -> None:
    """Set the PostgreSQL GUC for RLS tenant filtering.
    
    Uses a SECURITY DEFINER function to validate and set tenant context.
    The app role cannot bypass this validation.
    """
    connection.execute(text(_SEARCH_PATH))
    if tenant_id:
        connection.execute(
            text("SELECT set_app_tenant_context(:tid)"),
            {"tid": tenant_id}
        )
    else:
        connection.execute(text("SELECT clear_app_tenant_context()"))


def clear_tenant_context(connection: Any) -> None:
    """Clear the RLS tenant context."""
    connection.execute(text(_SEARCH_PATH))
    connection.execute(text("SELECT clear_app_tenant_context()"))


def get_current_tenant_id(connection: Any) -> str | None:
    """Get the current tenant context from the database."""
    connection.execute(text(_SEARCH_PATH))
    result = connection.execute(
        text("SELECT get_app_tenant_context()")
    ).scalar()
    return result if result != "" else None


# SQL to create RLS policies on all tenant-scoped tables
# Policies use get_app_tenant_context() SECURITY DEFINER function
# to prevent the app role from spoofing the tenant context
RLS_POLICY_SQL = """
-- Enable RLS on all tables
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owners too (defense in depth)
ALTER TABLE investigations FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

-- Drop existing policies if any (idempotent)
DROP POLICY IF EXISTS investigations_tenant_isolation ON investigations;
DROP POLICY IF EXISTS agent_runs_tenant_isolation ON agent_runs;
DROP POLICY IF EXISTS findings_tenant_isolation ON findings;
DROP POLICY IF EXISTS evidence_tenant_isolation ON evidence;
DROP POLICY IF EXISTS reports_tenant_isolation ON reports;
DROP POLICY IF EXISTS audit_events_tenant_isolation ON audit_events;

-- Investigations: direct tenant_id match using SECURITY DEFINER function
CREATE POLICY investigations_tenant_isolation ON investigations
    USING (tenant_id = get_app_tenant_context());

-- Child tables: join to investigations for tenant check
CREATE POLICY agent_runs_tenant_isolation ON agent_runs
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_app_tenant_context()
    ));

CREATE POLICY findings_tenant_isolation ON findings
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_app_tenant_context()
    ));

CREATE POLICY evidence_tenant_isolation ON evidence
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_app_tenant_context()
    ));

CREATE POLICY reports_tenant_isolation ON reports
    USING (investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_app_tenant_context()
    ));

-- Audit events: investigation_id IS NULL for system-level events
CREATE POLICY audit_events_tenant_isolation ON audit_events
    USING (investigation_id IS NULL OR investigation_id IN (
        SELECT investigation_id FROM investigations
        WHERE tenant_id = get_app_tenant_context()
    ));
"""


def apply_rls_policies(engine: Any) -> None:
    """Apply RLS policies to all tenant-scoped tables.
    
    Safe to call multiple times — drops and recreates policies.
    Must be called AFTER tables exist AND SECURITY DEFINER functions exist.
    """
    with engine.connect() as conn:
        conn.execute(text(RLS_POLICY_SQL))
        conn.commit()
