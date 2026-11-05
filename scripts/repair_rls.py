#!/usr/bin/env python3
"""Repair: enable + FORCE row-level security on the engine's RLS tables.

WHY THIS EXISTS
---------------
On 2026-10-04 an accidental destructive test run against the production
database dropped investigations/evidence/findings/agent_runs/reports. They
were recreated by `ensure_schema()`, which connects with the APPLICATION role
(`safenestt_app`). That makes `safenestt_app` the table OWNER.

The consequence is a security regression: `migrate.py` connects as `postgres`,
and `postgres` on this host is neither superuser (`rolsuper = f`) nor a member
of `safenestt_app` — so `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` fails with
"InsufficientPrivilege: must be owner of table investigations". The recreated
tables were therefore left with RLS DISABLED.

This script connects AS the owner (`safenestt_app`) and applies the RLS flags
plus the authoritative policy set from `rls.py`. It is the same policy source
the application uses; nothing is defined here.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/home/ronzoro/safenestt-ai")

from sqlalchemy import text  # noqa: E402

from safenestt.persistence.engine import create_engine  # noqa: E402
from safenestt.persistence.rls import apply_rls_policies, ensure_tenant_context  # noqa: E402

TABLES = [
    "investigations",
    "evidence",
    "findings",
    "agent_runs",
    "reports",
    "graph_nodes",
    "graph_edges",
]


def main() -> int:
    engine = create_engine()  # application role == table owner

    ensure_tenant_context(engine)
    apply_rls_policies(engine)

    with engine.connect() as conn:
        for table in TABLES:
            conn.execute(text(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY"))
            conn.execute(text(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY"))
        conn.commit()

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT relname, relrowsecurity, relforcerowsecurity "
                "FROM pg_class WHERE relname = ANY(:t) ORDER BY relname"
            ),
            {"t": TABLES},
        ).fetchall()
        bad = [r for r in rows if not (r[1] and r[2])]
        for name, rls, force in rows:
            print(f"  {name:16s} rls={rls} force={force}")
        if bad:
            print(f"FAILED: {len(bad)} table(s) still lack RLS")
            return 1

    print("All RLS tables have ENABLE + FORCE ROW LEVEL SECURITY.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())