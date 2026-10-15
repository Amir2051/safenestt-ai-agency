"""Deployment database gate — readiness verification.

WHY THIS EXISTS
---------------
Enabling RLS requires table OWNERSHIP. The application role
(`safenestt_app`) cannot do `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, so
RLS is installed exclusively by `safenestt.persistence.migrate`, which runs
with owner credentials in a privileged, one-shot step.

Nothing in the repository enforced that sequence, so the API could serve
traffic against a database where tenant isolation was never installed. This
module makes that state observable and blocks readiness until it is correct.

WHAT IT CHECKS
--------------
 1. database connectivity
 2. tenant functions exist (get_current_tenant, establish_tenant_context,
    clear_tenant_context)
 3. required tables exist
 4. RLS enabled on required tables
 5. FORCE RLS enabled on required tables
 6. required tenant policies exist
 7. application role is NOT superuser
 8. application role is NOT BYPASSRLS

DESIGN CONSTRAINTS
------------------
* Runs on the APPLICATION engine (least privilege). It only reads.
* It never raises into the health endpoint. Failures are returned as data so
  the endpoint can answer 503 with a minimal, non-sensitive body while the
  detailed reason goes to structured logs.
* It does NOT apply, repair, or attempt to install anything. Verification
  only — this module must never mutate database state.
* Liveness and readiness are separate concerns: see app.py.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)

# Tables that MUST carry tenant isolation. Keep in sync with RLS_POLICY_SQL in
# rls.py. These are the investigation-owned tables; `audit_events` has its own
# policy shape and is intentionally not listed here.
REQUIRED_RLS_TABLES = (
    "investigations",
    "agent_runs",
    "findings",
    "evidence",
    "reports",
    "graph_nodes",
    "graph_edges",
)

REQUIRED_TENANT_FUNCTIONS = (
    "get_current_tenant",
    "establish_tenant_context",
    "clear_tenant_context",
)

# (table, policy name) pairs that must exist.
REQUIRED_POLICIES = (
    ("investigations", "investigations_tenant_isolation"),
    ("agent_runs", "agent_runs_tenant_isolation"),
    ("findings", "findings_tenant_isolation"),
    ("evidence", "evidence_tenant_isolation"),
    ("reports", "reports_tenant_isolation"),
    ("graph_nodes", "graph_nodes_tenant_isolation"),
    ("graph_nodes", "graph_nodes_insert"),
    ("graph_edges", "graph_edges_tenant_isolation"),
    ("graph_edges", "graph_edges_insert"),
)


@dataclass
class ReadinessResult:
    """Outcome of the readiness gate."""

    ready: bool
    checks: dict[str, bool] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "checks": self.checks,
            "failures": self.failures,
        }

    def public_body(self) -> dict[str, Any]:
        """Minimal, non-sensitive payload for the public readiness endpoint.

        Deliberately excludes database names, role names, hostnames and any
        other infrastructure detail. Only the gate's verdict and the count of
        unmet prerequisites. Detail belongs in the logs.
        """
        return {
            "status": "ready" if self.ready else "not_ready",
            "unmet_prerequisites": len(self.failures),
        }


def check_readiness(engine: Any, app_role: str = "safenestt_app") -> ReadinessResult:
    """Verify the database security state required to serve traffic.

    Read-only. Never raises: every failure becomes a reported failure.
    """
    checks: dict[str, bool] = {}
    failures: list[str] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks[name] = bool(ok)
        if not ok:
            failures.append(detail)
            logger.warning("readiness_check_failed check=%s detail=%s", name, detail)

    # 1. connectivity
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")).scalar()
        record("database_connectivity", True, "")
    except Exception as exc:
        record("database_connectivity", False,
               f"cannot connect to the database: {type(exc).__name__}")
        # Without connectivity nothing else can be determined.
        return ReadinessResult(ready=False, checks=checks, failures=failures)

    with engine.connect() as conn:
        # 2. tenant functions
        try:
            rows = conn.execute(text("""
                SELECT proname FROM pg_proc
                WHERE pronamespace = 'public'::regnamespace
                  AND proname = ANY(:names)
            """), {"names": list(REQUIRED_TENANT_FUNCTIONS)}).scalars().all()
            present = set(rows)
            missing = [n for n in REQUIRED_TENANT_FUNCTIONS if n not in present]
            record("tenant_functions", not missing,
                   f"missing tenant function(s): {', '.join(missing)}"
                   if missing else "")
        except Exception as exc:
            record("tenant_functions", False,
                   f"could not inspect tenant functions: {type(exc).__name__}")

        # 3. tables exist
        try:
            rows = conn.execute(text("""
                SELECT c.relname FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relname = ANY(:names)
            """), {"names": list(REQUIRED_RLS_TABLES)}).scalars().all()
            missing = [t for t in REQUIRED_RLS_TABLES if t not in set(rows)]
            record("required_tables", not missing,
                   f"missing table(s): {', '.join(missing)}" if missing else "")
        except Exception as exc:
            record("required_tables", False,
                   f"could not inspect tables: {type(exc).__name__}")

        # 4 + 5. RLS and FORCE RLS
        try:
            rows = conn.execute(text("""
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relname = ANY(:names)
            """), {"names": list(REQUIRED_RLS_TABLES)}).all()
            state = {r[0]: (r[1], r[2]) for r in rows}
            no_rls = [t for t in REQUIRED_RLS_TABLES if t in state and not state[t][0]]
            no_force = [t for t in REQUIRED_RLS_TABLES
                        if t in state and not state[t][1]]
            record("rls_enabled", not no_rls,
                   f"RLS not enabled on: {', '.join(no_rls)}" if no_rls else "")
            record("force_rls_enabled", not no_force,
                   f"FORCE RLS not enabled on: {', '.join(no_force)}"
                   if no_force else "")
        except Exception as exc:
            record("rls_enabled", False,
                   f"could not inspect RLS state: {type(exc).__name__}")
            record("force_rls_enabled", False,
                   f"could not inspect FORCE RLS state: {type(exc).__name__}")

        # 6. policies
        try:
            rows = conn.execute(text("""
                SELECT c.relname, p.polname
                FROM pg_policy p
                JOIN pg_class c ON c.oid = p.polrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
            """)).all()
            present = {(r[0], r[1]) for r in rows}
            missing = [f"{t}.{p}" for t, p in REQUIRED_POLICIES
                       if (t, p) not in present]
            record("tenant_policies", not missing,
                   f"missing policy(ies): {', '.join(missing)}" if missing else "")
        except Exception as exc:
            record("tenant_policies", False,
                   f"could not inspect policies: {type(exc).__name__}")

        # 7 + 8. application role privileges
        try:
            row = conn.execute(text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :r"),
                {"r": app_role}).fetchone()
            if row is None:
                record("app_role_not_superuser", False,
                       "application role does not exist")
                record("app_role_not_bypassrls", False,
                       "application role does not exist")
            else:
                is_super, is_bypass = bool(row[0]), bool(row[1])
                record("app_role_not_superuser", not is_super,
                       "application role has SUPERUSER (can bypass all RLS)"
                       if is_super else "")
                record("app_role_not_bypassrls", not is_bypass,
                       "application role has BYPASSRLS (can bypass RLS)"
                       if is_bypass else "")
        except Exception as exc:
            record("app_role_not_superuser", False,
                   f"could not inspect application role: {type(exc).__name__}")
            record("app_role_not_bypassrls", False,
                   f"could not inspect application role: {type(exc).__name__}")

    ready = all(checks.values())
    logger.info(
        "readiness_verdict ready=%s checks_passed=%d/%d",
        ready, sum(1 for v in checks.values() if v), len(checks),
    )
    # Security invariants run in their own connection: the surrounding
    # `with engine.connect()` block above has already closed by this point,
    # and using it here raises ResourceClosedError.
    with engine.connect() as conn:
        # --- SECURITY INVARIANTS (2026-10-02) ----------------------------------
        # These encode the fixes proved by the confirmed cross-tenant bypasses:
        #   * a GUC fallback in get_current_tenant() let any role claim any tenant
        #   * INSERT/UPDATE on _tenant_context let any role forge tenant identity
        # A regression in any of these must fail readiness, not just log.
        # All checks below are catalog reads; none mutates anything.

        def _priv(grantee: str, obj: str, p: str) -> bool:
            return bool(conn.execute(
                text("SELECT has_table_privilege(:g, :o, :p)"),
                {"g": grantee, "o": obj, "p": p}).scalar())

        for _p in ("INSERT", "UPDATE", "DELETE"):
            record(f"tenant_context_no_{_p.lower()}",
                   not _priv(app_role, "public._tenant_context", _p),
                   f"{app_role} must not hold {_p} on _tenant_context")

        record("tenant_context_no_public_write",
               not bool(conn.execute(text("""
                   SELECT EXISTS (
                       SELECT 1 FROM information_schema.role_table_grants
                       WHERE table_name = '_tenant_context'
                         AND grantee = 'PUBLIC'
                         AND privilege_type IN ('INSERT','UPDATE','DELETE'))
               """)).scalar()),
               "PUBLIC must not hold write privileges on _tenant_context")

        _gct = conn.execute(text(
            "SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND proname = 'get_current_tenant'")).scalar() or ""
        record("no_guc_tenant_fallback", "app.current_tenant_id" not in _gct,
               "get_current_tenant() must not read a caller-controlled GUC")
        record("tenant_fn_schema_qualified", "public._tenant_context" in _gct,
               "get_current_tenant() must schema-qualify _tenant_context")

        for _fn in ("get_current_tenant", "clear_tenant_context", "establish_tenant_context"):
            _sp = conn.execute(text(
                "SELECT COALESCE(proconfig::text,'') FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'public' AND proname = :fn"), {"fn": _fn}).scalar() or ""
            record(f"{_fn}_search_path_hardened",
                   "pg_catalog" in _sp and "public" in _sp,
                   f"{_fn} has an unsafe search_path: {_sp!r}")
            _secdef = conn.execute(text(
                "SELECT prosecdef FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'public' AND proname = :fn"), {"fn": _fn}).scalar()
            record(f"{_fn}_security_definer", _secdef is True,
                   f"{_fn} must remain SECURITY DEFINER")

        _acl = conn.execute(text(
            "SELECT COALESCE(array_to_string(defaclacl,';'),'') FROM pg_default_acl "
            "WHERE defaclrole = (SELECT oid FROM pg_roles WHERE rolname = 'postgres') "
            "AND defaclobjtype = 'r'")).scalar() or ""
        record("default_privileges_not_all",
               "arwd" not in _acl and "Dxt" not in _acl,
               f"default table privileges grant write access to {app_role}: {_acl!r}")

        _flags = conn.execute(text(
            "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = :r"),
            {"r": app_role}).scalar()
        record("app_role_not_privileged", _flags is False,
               f"{app_role} must not be superuser or BYPASSRLS")

    return ReadinessResult(ready=ready, checks=checks, failures=failures)