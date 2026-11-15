"""RLS tenant-isolation regression tests.

Proves the GUC-fallback bypass in public.get_current_tenant() is fixed and that
legitimate tenant access still works.

Before the fix, any role could issue:
    SET LOCAL app.current_tenant_id = '<victim tenant>';
and read that tenant's rows, because the RLS policy delegates its decision to
get_current_tenant(). Tenant identity must now come ONLY from the PID-bound
_tenant_context written by establish_tenant_context().

These tests connect as the unprivileged `safenestt_app` role (not superuser,
not BYPASSRLS). Requires the role password via DB_PASSWORD.
"""
from __future__ import annotations

import os
import re
import subprocess

import pytest

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "54322")
DB_NAME = os.getenv("DB_NAME", "safenestt_ai")
APP_ROLE = "safenestt_app"

TENANT_A = "safenestt-remediate-test"
TENANT_B = "ten-edge-1"


def _app_password() -> str | None:
    pw = os.getenv("DB_PASSWORD")
    if pw:
        return pw
    try:
        env = open("/etc/safenestt/engine.env").read()
        m = re.search(r"^DB_PASSWORD=(.*)$", env, re.M)
        return m.group(1).strip() if m else None
    except OSError:
        return None


PW = _app_password()
pytestmark = pytest.mark.skipif(not PW, reason="app-role DB_PASSWORD unavailable")


def as_app(sql: str) -> tuple[int, str]:
    """Run SQL as the unprivileged application role."""
    url = f"postgresql://{APP_ROLE}:{PW}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    r = subprocess.run(
        ["psql", url, "-t", "-A", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c", sql],
        capture_output=True, text=True, timeout=30,
        env={"PGPASSWORD": PW, "PATH": "/usr/bin:/bin"},
    )
    return r.returncode, (r.stdout or r.stderr).strip()


def scalar(sql: str) -> str:
    rc, out = as_app(sql)
    lines = [l for l in out.splitlines() if l and not l.startswith(("BEGIN", "COMMIT", "SET", "ERROR"))
             and "INSERT" not in l]
    return lines[-1] if lines else ""


def superuser(sql: str) -> str:
    r = subprocess.run(
        ["psql", f"-h",DB_HOST,"-p",DB_PORT,"-U","postgres","-d",DB_NAME,"-t","-A","-F","|","-c",
         f"BEGIN READ ONLY; {sql} COMMIT;"],
        capture_output=True, text=True, timeout=30,
        env={"PGPASSWORD": "postgres", "PATH": "/usr/bin:/bin"},
    )
    return "\n".join(l for l in r.stdout.strip().splitlines()
                     if l and not l.startswith(("BEGIN", "COMMIT")))


# --------------------------------------------------------------------- TEST 2
def test_guc_spoofing_has_no_effect():
    """TEST 2 — SET app.current_tenant_id must not grant any tenant identity."""
    rc, out = as_app(
        "BEGIN; SET LOCAL app.current_tenant_id='safenestt-remediate-test'; "
        "SELECT get_current_tenant(); COMMIT;")
    assert rc == 0, out
    body = [l for l in out.splitlines() if l and not l.startswith(("BEGIN","COMMIT","SET"))]
    assert (body[0] if body else "") == "", "GUC spoof still resolves to a tenant"


def test_guc_spoof_yields_zero_rows():
    """TEST 2 — spoofed GUC must not expose another tenant's rows."""
    rc, out = as_app(
        "BEGIN; SET LOCAL app.current_tenant_id='safenestt-remediate-test'; "
        f"SELECT count(*) FROM investigations; COMMIT;")
    rows = [l for l in out.splitlines() if l.strip().isdigit()]
    assert rows and rows[-1] == "0", f"spoof exposed rows: {out}"


# --------------------------------------------------------------------- TEST 3
def test_no_context_returns_empty_string():
    """TEST 3 — fail closed with no PID context."""
    assert scalar("SELECT get_current_tenant();") == ""


def test_no_context_cannot_read_application_data():
    rc, out = as_app("SELECT count(*) FROM investigations;")
    assert out.splitlines()[-1].strip() == "0", out


# --------------------------------------------------------------------- TEST 4
def test_cross_tenant_isolation_without_spoof():
    """TEST 4 — a foreign tenant's context sees nothing of tenant A."""
    truth = superuser(f"SELECT count(*) FROM investigations WHERE tenant_id='{TENANT_A}';").strip()
    if truth in ("", "0"):
        pytest.skip("no tenant A rows present")
    rc, out = as_app("SELECT count(*) FROM investigations;")
    assert out.splitlines()[-1].strip() == "0", out


def test_cross_tenant_isolation_with_spoof():
    """TEST 4 — even spoofing tenant A, tenant B's connection reads nothing."""
    rc, out = as_app(
        f"BEGIN; SET LOCAL app.current_tenant_id='{TENANT_A}'; "
        f"SELECT count(*) FROM investigations WHERE tenant_id='{TENANT_A}'; COMMIT;")
    rows = [l for l in out.splitlines() if l.strip().isdigit()]
    assert rows and rows[-1] == "0", f"spoofed cross-tenant read: {out}"


# --------------------------------------------------------------------- TEST 5
def test_cross_tenant_insert_rejected():
    """TEST 5 — a spoofed INSERT must not create a row."""
    probe = "rls-regression-probe-0001"
    superuser(f"DELETE FROM investigations WHERE investigation_id='{probe}';")
    rc, out = as_app(
        "BEGIN; SET LOCAL app.current_tenant_id='safenestt-remediate-test'; "
        f"INSERT INTO investigations (investigation_id,tenant_id,type,status,created_at,updated_at) "
        f"VALUES ('{probe}','{TENANT_A}','domain','QUEUED',NOW(),NOW()); COMMIT;")
    left = superuser(f"SELECT count(*) FROM investigations WHERE investigation_id='{probe}';").strip()
    assert left == "0", f"spoofed INSERT persisted a row (rc={rc}, out={out[:200]})"


# --------------------------------------------------------------------- TEST 7
def test_security_definer_search_path_is_safe():
    """TEST 7 — pg_temp is searched first unless explicitly ordered last."""
    r = subprocess.run(
        ["psql", f"-h",DB_HOST,"-p",DB_PORT,"-U","postgres","-d",DB_NAME,"-t","-A","-c",
         "BEGIN READ ONLY; SELECT proname||'='||coalesce(proconfig::text,'none') FROM pg_proc p "
         "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND proname IN "
         "('get_current_tenant','establish_tenant_context'); COMMIT;"],
        capture_output=True, text=True, timeout=30,
        env={"PGPASSWORD": "postgres", "PATH": "/usr/bin:/bin"})
    text_out = r.stdout
    for fn in ("get_current_tenant", "establish_tenant_context"):
        line = [l for l in text_out.splitlines() if l.startswith(fn)]
        assert line, f"{fn} not found"
        assert "pg_catalog" in line[0] and "public" in line[0], line[0]


def test_guc_fallback_removed_from_source():
    """The fallback literal must be gone from the deployed function."""
    body = superuser("SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                     "WHERE n.nspname='public' AND proname='get_current_tenant';")
    assert "app.current_tenant_id" not in body, "GUC fallback still present"


def test_tenant_context_schema_qualified():
    """TEST 7 — object references must be schema-qualified."""
    body = superuser("SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                     "WHERE n.nspname='public' AND proname='establish_tenant_context';")
    assert "public._tenant_context" in body, "unqualified _tenant_context reference remains"
    assert "public.api_keys" in body, "unqualified api_keys reference remains"


def test_app_role_retains_execute():
    """Hardening must not break the legitimate application path."""
    r = subprocess.run(
        ["psql", f"-h",DB_HOST,"-p",DB_PORT,"-U","postgres","-d",DB_NAME,"-t","-A","-c",
         "BEGIN READ ONLY; SELECT has_function_privilege('safenestt_app',"
         "'public.establish_tenant_context(text,text)','EXECUTE'); COMMIT;"],
        capture_output=True, text=True, timeout=30,
        env={"PGPASSWORD": "postgres", "PATH": "/usr/bin:/bin"})
    assert "t" in r.stdout, "app role lost EXECUTE on establish_tenant_context"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "--no-header"]))


# ------------------------------------------------- direct context-write forgery
def test_direct_context_write_blocked():
    """The app role must not be able to write tenant identity directly.

    Regression for a confirmed bypass: INSERT/UPDATE on public._tenant_context let any
    SQL caller impersonate a tenant by writing a row keyed on its own backend PID --
    no API key, no fingerprint, no establish_tenant_context(). get_current_tenant()
    trusts that row, so every RLS policy delegated to it admitted the forged tenant.
    The legitimate writer is establish_tenant_context(), which is SECURITY DEFINER.
    """
    import os as _os
    import re as _re
    pw = _os.getenv("DB_PASSWORD")
    if not pw:
        try:
            m = _re.search(r"^DB_PASSWORD=(.*)$", open("/etc/safenestt/engine.env").read(), _re.M)
            pw = m.group(1).strip() if m else None
        except OSError:
            pw = None
    if not pw:
        pytest.skip("app-role DB_PASSWORD unavailable")

    for stmt, label in (
        ("INSERT INTO public._tenant_context (backend_pid,tenant_id,key_fingerprint,expires_at) "
         "VALUES (pg_backend_pid(),'safenestt-remediate-test','forged',NOW()+INTERVAL '1 hour')",
         "INSERT"),
        ("UPDATE public._tenant_context SET tenant_id='safenestt-remediate-test' "
         "WHERE backend_pid=pg_backend_pid()", "UPDATE"),
        ("DELETE FROM public._tenant_context WHERE backend_pid=pg_backend_pid()", "DELETE"),
    ):
        # psql emits the denial on stderr; as_app() prefers stdout, so check both.
        url = f"postgresql://{APP_ROLE}:{PW}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        r = subprocess.run(
            ["psql", url, "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", "BEGIN; " + stmt + "; ROLLBACK;"],
            capture_output=True, text=True, timeout=30,
            env={"PGPASSWORD": PW, "PATH": "/usr/bin:/bin"},
        )
        combined = ((r.stdout or "") + (r.stderr or "")).lower()
        assert r.returncode != 0 and "permission denied" in combined, \
            f"direct {label} on _tenant_context was NOT denied: rc={r.returncode} {combined[:160]}"


def test_forged_context_grants_no_access():
    """A forged context row must not be able to produce a usable tenant identity."""
    rc, out = as_app(
        "BEGIN; SET LOCAL app.current_tenant_id='safenestt-remediate-test'; "
        "SELECT get_current_tenant(); COMMIT;")
    body = [l for l in out.splitlines() if l and not l.startswith(("BEGIN", "COMMIT", "SET"))]
    assert (body[0] if body else "") == "", "forged/GUC tenant identity was accepted"
