import json
import os
import urllib.request

KEY = "safenestt-ops-test-key-20260609"
BASE = "http://127.0.0.1:8321"
# strip any trailing slash for clean path join
BASE = BASE.rstrip("/")

def call(path, data=None):
    req = urllib.request.Request(BASE + path, method="POST" if data else "GET")
    req.add_header("X-API-Key", KEY)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        body = json.dumps(data).encode()
    else:
        body = None
    try:
        with urllib.request.urlopen(req, data=body, timeout=8) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def echo(label, resp):
    print(f"--- {label} ---")
    print(json.dumps(resp, indent=2)[:900])

# 1. health
st, body = call("/v1/health")
echo("health", body)

# 2. schema
st, body = call("/v1/ops/schema")
echo("schema", body)

# 3. audit_events count
st, body = call("/v1/ops/query", {"sql": "SELECT COUNT(*) AS n FROM audit_events;"})
echo("audit_events COUNT", body)

# 4. audit_events latest 3 (real columns)
st, body = call("/v1/ops/query", {"sql": "SELECT action, created_at FROM audit_events ORDER BY created_at DESC LIMIT 3;"})
echo("audit_events latest 3", body)

# 5. INSERT forbidden
st, body = call("/v1/ops/query", {"sql": "INSERT INTO audit_events VALUES (1);"})
echo("INSERT forbidden", {"status": st, "body": body})

# 6. DELETE forbidden
st, body = call("/v1/ops/query", {"sql": "DELETE FROM audit_events;"})
echo("DELETE forbidden", {"status": st, "body": body})

# 7. 8 RLS tables
sql7 = "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('graph_nodes','graph_edges','investigations','evidence','findings','agent_runs','reports','audit_events');"
st, body = call("/v1/ops/query", {"sql": sql7})
echo("8 RLS tables", body)
