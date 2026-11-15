#!/usr/bin/env python3
"""Mint a Hermes API key for the SafeNestT backend and register it.

WHY THIS EXISTS
---------------
On 2026-10-04 the `HERMES_API_KEY` present in BOTH
`/etc/safenestt/engine.env` and `apps/api/.env` hashed to fingerprint
`dea30747...`, which does not exist in the `api_keys` table. Every
authenticated call from the SafeNestT backend to the engine therefore
returned 401 `invalid_key` — the two halves of the pipeline could not talk to
each other at all.

This script mints a fresh key for the tenant that owns the existing
investigations, registers its Argon2id hash + SHA-256 fingerprint, and writes
the raw value into the backend `.env`.

The raw key is NEVER printed. It is written directly to the destination file.

Re-running is safe: it revokes nothing and only adds a new active key row, so
an operator can roll back by revoking the new fingerprint.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

sys.path.insert(0, "/home/ronzoro/safenestt-ai")

from sqlalchemy import text  # noqa: E402

from safenestt.persistence.engine import create_engine, session_scope_bypass_rls  # noqa: E402
from safenestt.security.api_keys import generate_api_key  # noqa: E402

TENANT = os.environ.get("HERMES_BACKEND_TENANT", "safenestt-remediate-test")
NAME = "SafeNestT Backend (pipeline)"
BACKEND_ENV = pathlib.Path("/home/ronzoro/safenestt-platform/apps/api/.env")


def main() -> int:
    create_engine()
    raw_key, key_hash, fingerprint = generate_api_key(prefix="sn_live_")

    with session_scope_bypass_rls() as session:
        existing = session.execute(
            text("SELECT 1 FROM api_keys WHERE key_fingerprint = :fp"),
            {"fp": fingerprint},
        ).first()
        if existing:
            print("ERROR: fingerprint collision — refusing to insert.")
            return 1

        cols = {
            r[0] for r in session.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='api_keys'"
                )
            ).fetchall()
        }
        # NOT NULL columns must all be supplied or the insert fails.
        payload = {
            "key_hash": key_hash,
            "key_fingerprint": fingerprint,
            "tenant_id": TENANT,
            "name": NAME,
            "active": True,
            "revoked": False,
            "use_count": 0,
            "scopes": '["read","write"]',
        }
        if "expires_at" in cols:
            payload["expires_at"] = None
        if "created_at" in cols:
            payload["created_at"] = "NOW()"

        keys = [k for k in payload if k in cols]
        stmt = text(
            f"INSERT INTO api_keys ({', '.join(keys)}) "
            f"VALUES ({', '.join(':' + k for k in keys)})"
        )
        params = {k: payload[k] for k in keys}
        # created_at passed as SQL expression, not bind param.
        if "created_at" in keys:
            stmt = text(
                f"INSERT INTO api_keys ({', '.join(keys)}) VALUES ("
                + ", ".join("NOW()" if k == "created_at" else ":" + k for k in keys)
                + ")"
            )
            params.pop("created_at", None)
        session.execute(stmt, params)

    # Write the raw key into the backend .env without ever printing it.
    text_in = BACKEND_ENV.read_text()
    line = f"HERMES_API_KEY={raw_key}"
    if re.search(r"^HERMES_API_KEY=", text_in, re.M):
        new_text = re.sub(r"^HERMES_API_KEY=.*$", line, text_in, count=1, flags=re.M)
        action = "replaced"
    else:
        new_text = text_in.rstrip("\n") + "\n" + line + "\n"
        action = "added"

    BACKEND_ENV.write_text(new_text)
    BACKEND_ENV.chmod(0o600)

    print(f"Registered API key for tenant={TENANT}")
    print(f"  fingerprint : {fingerprint}")
    print(f"  backend .env: HERMES_API_KEY {action}")
    print("  raw key value: NOT printed (written to file only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())