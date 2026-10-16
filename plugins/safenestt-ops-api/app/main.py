"""SafeNestT Operations API — read-only plugin server.

Serves:
  - /.well-known/ai-plugin.json   (ChatGPT plugin manifest)
  - /openapi.json                 (OpenAPI 3.1)
  - /v1/health                    (readiness probe)
  - /v1/ops/query                 (read-only SQL, SELECT/EXPLAIN only)
  - /v1/ops/schema                (table/column introspect)
"""
from __future__ import annotations

import os
import re
import socket
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import psycopg2
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader

app = FastAPI(title="SafeNestT Operations", version="v1")

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_READ_ONLY_RE = re.compile(r"^\s*(SELECT|EXPLAIN\s+(ONLY\s+)?(ANALYZE\s+)?)?", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Configuration (env-driven; no secrets in source)
# ---------------------------------------------------------------------------
_OWNER_USER = os.getenv("SAFENESTT_OWNER_USER", "safenestt_owner_test")
_OWNER_PASS = os.getenv("SAFENESTT_OWNER_PASSWORD", "safenestt_test_local_only")
_DB_HOST = os.getenv("SAFENESTT_DB_HOST", "127.0.0.1")
_DB_PORT = os.getenv("SAFENESTT_DB_PORT", "55432")
_DB_NAME = os.getenv("SAFENESTT_DB_NAME", "safenestt_ai_test")
DB_DSN = os.getenv(
    "SAFENESTT_OPS_DB_DSN",
    f"postgresql://{_OWNER_USER}:{_OWNER_PASS}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}",
)
API_KEY = os.getenv("SAFENESTT_OPS_API_KEY", "safenestt-ops-local-dev-key")

PLUGIN_MANIFEST = {
    "schema_version": "v1",
    "name_for_model": "safenestt-ops",
    "name_for_human": "SafeNestT Operations",
    "description": "Read-only SafeNestT operations & observability: audit_events, findings, agent_runs, RLS status, service health. Local/private beta.",
    "author": "SafeNestT operations",
    "icon": "https://github.com/Amir2051/safenestt-ai/raw/main/docs/logo.png",
    "contact_email": "ops@safenestt.com",
    "contact_url": "https://safenestt.com/ops",
    "logo_url": "https://github.com/Amir2051/safenestt-ai/raw/main/docs/logo.png",
    "legal_info_url": "https://safenestt.com/legal/privacypolicy",
    "server": {"host": "127.0.0.1", "port": 8321, "protocol": "https"},
    "api_version": "v1",
    "auth": {"type": "api_key", "in": "header", "name": "X-API-Key"},
}


def _get_conn() -> psycopg2.extensions.connection:
    try:
        conn = psycopg2.connect(DB_DSN, connect_timeout=5)
    except Exception as exc:
        raise RuntimeError(f"DB connection failed: {exc}") from exc
    return conn


@app.get("/v1/health")
def health(*, api_key: str | None = Header(default=None, alias="X-API-Key")):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    try:
        with closing(_get_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "degraded", "error": str(exc)})
    return {"status": "ok", "db": True, "ts": time.time()}


@app.get("/openapi.json")
def openapi(*, api_key: str | None = Header(default=None, alias="X-API-Key")):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    return JSONResponse(content={"openapi": "3.1.0", "info": {"title": "SafeNestT Operations", "version": "v1"},
                               "servers": [{"url": "https://127.0.0.1:8321/v1", "description": "local"}],
                               "paths": {"/health": {"get": {"summary": "Health", "responses": {"200": {"description": "OK"}}}},
                                         "/ops/query": {"post": {"summary": "Read-only ops query",
                                                                  "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                                                                                                      "properties": {"sql": {"type": "string", "description": "A read-only SQL statement (SELECT/EXPLAIN ONLY). Must not contain INSERT/UPDATE/DELETE/DROP."}}}}}}},
                                         "/ops/schema": {"get": {"summary": "Schema introspection", "responses": {"200": {"description": "Tables and columns"}}}}}}})


@app.get("/.well-known/ai-plugin.json")
def plugin_manifest(*, api_key: str | None = Header(default=None, alias="X-API-Key")):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    manifest_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".well-known", "ai-plugin.json")
    if os.path.exists(manifest_path):
        return FileResponse(manifest_path)
    return JSONResponse(content=PLUGIN_MANIFEST)


@app.get("/v1/ops/schema")
def schema(*, api_key: str | None = Header(default=None, alias="X-API-Key")):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    rows = []
    try:
        with closing(_get_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name, column_name, data_type, is_nullable "
                    "FROM information_schema.columns "
                    "WHERE table_schema='public' "
                    "ORDER BY table_name, ordinal_position"
                )
                cols = [d[0] for d in cur.description] if cur.description else []
                for r in cur.fetchall():
                    rows.append(dict(zip(cols, r)))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"schema query failed: {exc}")
    return {"tables": len({r["table_name"] for r in rows}), "columns": rows}


@app.post("/v1/ops/query")
def query(req: dict[str, Any], *, api_key: str | None = Header(default=None, alias="X-API-Key")):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")
    sql = (req.get("sql") or "").strip()
    if not sql:
        raise HTTPException(status_code=400, detail="'sql' is required")
    if not _READ_ONLY_RE.match(sql):
        raise HTTPException(status_code=403, detail="read-only policy: only SELECT/EXPLAIN/CHECK allowed")
    if re.search(r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|COPY|REPLACE|SET\s+.*=)\b", sql, re.IGNORECASE):
        raise HTTPException(status_code=403, detail="write/mutation keywords are forbidden (read-only policy)")

    try:
        with closing(_get_conn()) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                cols = [d[0] for d in cur.description] if cur.description else []
                rows = [dict(zip(cols, row)) for row in cur.fetchall()]
                return {"rows": rows, "columns": cols, "row_count": len(rows), "warning": None}
    except psycopg2.errors.SyntaxError as exc:
        raise HTTPException(status_code=400, detail=f"SQL syntax error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"query failed: {exc}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8321)
