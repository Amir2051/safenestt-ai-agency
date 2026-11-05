# SafeNestT + Hermes Investigation Engine — Complete Audit Report

**Date:** 2026-10-14 (EDT)  
**Audit method:** read-only code inspection + isolated test DB (127.0.0.1:55432) + full test suite execution  
**Test results:** 14 failed, 397 passed, 5 skipped, 69 errors (815s / 13:35)  
**Production NOT touched. No secrets exposed.**

---

## 1. Executive Summary

SafeNestT is a FastAPI + SQLAlchemy + PostgreSQL backend for an "AI investigation engine" (cybersecurity/OSINT domain). It talks to an external Hermes service via a Base44 bridge. The application layer (tenant isolation, API-key lifecycle, audit events, RLS policies, multi-agent orchestration) is substantial but the repo is **heavily modified and uncommitted** (see section 2). Several pathologically failing tests were introduced, and the test suite itself contains multiple defective tests that silently pass or misreport.

**What works:**
- Multi-tenant identity separation is real and well-modeled: tenant context is PID-bound via `pg_backend_pid()`, fingerprint-verified through a SECURITY DEFINER function, and enforced by RLS policies on every investigation-owned table.
- A robust multi-agent orchestration pipeline exists (Evidence → OSINT → Threat Intel → Crypto → Fraud Analysis → Report), with provider adapters for Shodan/VirusTotal/Firecrawl/HIBP/Hunter/Etherscan and strict error-containment.
- The async start path (`?wait=false`) correctly spawns a background thread and returns 202 with a pollable `/v1/investigations/{id}` endpoint.

**What fails:**
- 69 test errors are dominated by test-environment defects: a missing `postgres` role on the test DB, a missing `database_session` fixture, and stale `dbname=LIVE_DB`=safenestt_ai in tests that are implicitly blocked by the test-isolation guard.
- 14 test failures are real code/test bugs: a missing `database_session` fixture, a missing module-level function the test monkeypatches, live API calls that return 404, un-bootstrapped tables in the test DB, and an un-bootstrapped schema in the test DB.

**Biggest risks:**
1. **Test data / schema bootstrap is not reproducible** on a clean database: `ensure_schema()` and the test DB schema are not consistently applied in tests.
2. **Remediation tests target a legacy/stale configuration** (port 54322, `postgres` user, production-db names) and are effectively un-runnable in this environment — the test-isolation guard actively blocks them.
3. **No lint/type-check tooling configured** (no ruff, mypy, or pyright), so code quality cannot be automatically gated.
4. **Live external API tests (OpenRouter) are non-deterministic** and serve no local CI purpose (404 from the provider).

---

## 2. Verified Architecture

```
User/API client
   │  X-API-Key (Argon2id hash stored in PostgreSQL)
   ▼
FastAPI app (/v1/investigations, /start, /findings, /report)
   │  get_api_context → tenant_id + key_fingerprint (SHA-256 of raw key)
   ▼
PersistentInvestigationStore (SQLAlchemy session)
   │  session_scope(tenant_id, key_fingerprint)
   ▼
PostgreSQL (engine + RLS + SECURITY DEFINER tenant context)
   │
   ▼
InvestigationOrchestrator → agents: Evidence → OSINT → Threat Intel → Crypto → Fraud Analysis → Report
   │
   ▼
Audit events (audit_events table), provider audit, evidence/findings graphs
```

**Key components and file references:**
| Component | File | Notes |
|-----------|------|-------|
| API routes | `safenestt/api/app.py` | `POST /v1/investigations`, `POST /v1/investigations/{id}/start` (`?wait=true|false`), `GET /v1/investigations/{id}`, findings, report |
| Async start | `safenestt/api/app.py:333-392` | `?wait=false` → background thread, returns 202 + poll URL |
| Persistence | `safenestt/persistence/store.py` | `PersistentInvestigationStore`, repositories |
| Schema bootstrap | `safenestt/persistence/store.py` (ensure_schema) | **BUG: calls `apply_rls_policies()` before `get_current_tenant()` exists** (see section 4) |
| RLS / tenant context | `safenestt/persistence/rls.py` | `ensure_tenant_context()`, `apply_rls_policies()`, SECURITY DEFINER `establish_tenant_context()` |
| Engine | `safenestt/persistence/engine.py` | `create_engine()`, `get_sessionmaker()`, SSL/TLS config |
| Migrations | `safenestt/persistence/migrate.py` | Owner-role bootstrap; `wait_for_migrate.py` provides readiness marker |
| Orchestrator | `safenestt/investigation/orchestrator.py` | Multi-agent pipeline with error containment |
| Agents | `safenestt/agents/{osint,evidence,crypto,report,etc}.py` | Per-role agents |
| Agent registry | `safenestt/agent_loader.py` | Roster-based loader (approved/placeholder) |
| Remediations | `remediation_tests/`, `safenestt/persistence/readiness.py`, `safenestt/persistence/startup_gate.py` | Startup gate + readiness checks + fresh-DB bootstrap tests |

**Deployment config:** `docker-compose.yml`, `docker-compose.test-db.yml`, `start-engine.sh`, systemd units (`safenestt-engine.service`, `safenestt-hermes-dispatcher.service`), CI workflow `.github/workflows/ci.yml` (all modified in the working tree).

---

## 3. Investigation Lifecycle — Exact Execution Path

1. **User submits** → `POST /v1/investigations` (`safenestt/api/app.py:276-298`). Creates `InvestigationRecord` with `status="QUEUED"`, `investigation_id=uuid4().hex`. Service: `PersistentInvestigationStore.create_investigation()`.
2. **API validates** → `get_api_context` (depends). Authenticates the raw key against the `api_keys` table via `APIKeyStore` (Argon2id verification in `safenestt/security/api_keys.py`). Returns `(tenant_id, key_fingerprint)`.
3. **Create persisted** → `store.create_investigation()` → SQLAlchemy `INSERT` into `investigations` table. RLS prevents cross-tenant reads/writes.
4. **Start** → `POST /v1/investigations/{id}/start` (`safenestt/api/app.py:301-392`):
   - `?wait=false` → marks `RUNNING`, spawns `threading.Thread(daemon=True)` running `run_investigation()` on a background thread, returns `202` with `{"poll": "/v1/investigations/{id}"}`.
   - `?wait=true` (default) → blocks in `run_investigation()` synchronously until terminal state.
5. **Agent/tool selection** → `InvestigationOrchestrator.orchestrate()` (`safenestt/investigation/orchestrator.py:35-135`) runs agents in dependency order:
   - EvidenceAgent → OsintAgent → ThreatIntelAgent → CryptoAgent → external providers (Shodan/VirusTotal/Firecrawl/HIBP/Hunter/Etherscan) → FraudAnalysisAgent → ReportAgent.
   - Each agent runs inside `PermissionManager` (allowlist + authorization checks).
6. **Phases execute** → per-role `execute()` methods produce `Finding` rows (stored in `findings` table), `AgentRun` rows, and an evidence graph (`graph_nodes`/`graph_edges`).
7. **State saved** → `PersistentInvestigationStore` persists `investigations`, `agent_runs`, `findings`, `evidence`, `graph_*`, `reports`, `audit_events`. Audit events are appended to `audit_events` for every significant action.
8. **Long-running / polling** → background thread writes progress; `GET /v1/investigations/{id}` returns `status`, `findings_count`, `evidence_count`, `agent_runs`, `report_source` (persisted vs reconstructed). Polling cadence is controlled by the caller (Base44 bridge).
9. **Failures/timeouts** → `run_investigation()` catches exceptions and marks `FAILED` with an `error` JSON on the record. The async path catches exceptions in `_background()` and marks `FAILED` with `background_investigation_failed`.
10. **Final findings delivered** → `GET /v1/investigations/{id}/report` prefers a persisted `reports` row (`report_source="persisted"`) or reconstructs from findings/evidence (`report_source="reconstructed"`). `GET /v1/investigations/{id}` includes `findings` and `agent_runs` arrays.

---

## 4. Confirmed Defects (Ranked by Severity)

### [CRITICAL] D1 — Schema bootstrap is not reproducible in tests
- **Location:** `safenestt/persistence/store.py` (ensure_schema), `safenestt/persistence/migrate.py`
- **Evidence:** The test DB (127.0.0.1:55432, `safenestt_ai_test`) has tables present but is not auto-bootstrapped. Tests that depend on a clean DB (`test_persistence.py::TestTenantIsolation`, remediation `*_bootstrap.py`) fail with `UndefinedTable` because the test DB was never bootstrapped with the tenant tables.
- **Root cause:** `ensure_schema()` applies `apply_rls_policies()` before `get_current_tenant()` exists in the schema (the function was historically defined only in `migrate.py`, not in `rls.py`/`ensure_schema()`). The fix was then applied to `rls.py` (`TENANT_CONTEXT_SQL`), but the test DB/`ensure_schema()` path was never consistently bootstrapped, so tests that start from a clean DB see `UndefinedTable`.
- **Impact:** The investigation lifecycle (create → persist → RLS) cannot be verified on a clean database in this environment. A fresh test database does not contain the tenant-context functions or RLS policies.
- **Proposed fix:** In a test DB, call `ensure_schema()` (or at minimum `ensure_tenant_context()` + `apply_rls_policies()`) at test setup, before any test touches the schema. Verify `get_current_tenant()` exists before `apply_rls_policies()` is called.
- **Regression test:** A test that creates an empty database, calls `ensure_schema()`, and verifies `get_current_tenant()` and RLS policies exist before asserting cross-tenant isolation.

### [CRITICAL] D2 — `test_graph_security.py` uses `postgres` user that doesn't exist on test DB
- **Location:** `tests/test_graph_security.py:90` (fixture `fresh_db`), `tests/conftest.py` (OWNER_URL default)
- **Evidence:** `psycopg2.OperationalError: connection to server at "127.0.0.1", port 55432 failed: FATAL: password authentication failed for user "postgres"`. The fixture connects as `postgres` but the test DB has a `safenestt_test` (or similar) role only.
- **Root cause:** The test fixture hardcodes a `postgres` superuser connection; the local test DB was created with a different owner role. The conftest's `OWNER_URL` / `SAFENESTT_OWNER_DATABASE_URL` is the correct connection, but the test module overrides it with a hardcoded `postgres` credential.
- **Impact:** 26+ tests in `test_graph_security.py` and `test_graph_edge_security_db.py` cannot run; every test in this file is an error (fixture setup failure).
- **Proposed fix:** Use the OWNER_URL from conftest (or the owner-role creds from the environment) consistently; create the `postgres` role if the intent is a dev-test convenience, but not for CI.
- **Regression test:** A single test that authenticates to the test DB as the OWNER role (honoring conftest env vars) and performs a basic `SELECT 1` through `guarded_connect`.

### [CRITICAL] D3 — `test_graph_edge_security.py` references a nonexistent `database_session` fixture
- **Location:** `tests/test_graph_edge_security.py:20`
- **Evidence:** `ERROR at setup of test_valid_same_investigation_edge: fixture 'database_session' not found` — the file's fixtures are `graph_store` and `two_investigations`, but every test declares `graph_store(database_session)` as a parameter. `database_session` is never defined.
- **Root cause:** The test file was written/edited against a different conftest that provided a `database_session` fixture; that fixture was never added to this file.
- **Impact:** All 8 tests in this file are errors (0 pass, 0 fail).
- **Proposed fix:** Define a `database_session` fixture in `conftest.py` (used by multiple graph-security tests) or update the test parameters to use the existing `graph_store` + `two_investigations` fixtures.
- **Regression test:** All 8 tests in `test_graph_edge_security.py` pass with the corrected fixture chain.

### [HIGH] D4 — `test_infrastructure_timeouts.py` monkeypatches a non-existent attribute
- **Location:** `tests/test_infrastructure_timeouts.py:353`
- **Evidence:** `AttributeError: 'FastAPI' object has no attribute '_resolve_model_provider'`. The test assumes `app_mod._resolve_model_provider` is a module attribute, but `_resolve_model_provider` is a method on the FastAPI app object, not a module-level attribute.
- **Root cause:** Stale test that was written before the provider-resolver was extracted onto the app object.
- **Impact:** 1 test fails; the test's intent (bounded 5xx on provider failure) is still valid but the implementation detail is wrong.
- **Proposed fix:** Patch `app_mod.app.dependency_overrides` or call the resolver via the app's dependency resolution (e.g., `@app.get(...)` route that calls `_resolve_model_provider()`), or move the resolver to a module-level function.
- **Regression test:** A test that verifies `GET /health` returns a bounded response when the provider is misconfigured (no real external call).

### [MEDIUM] D5 — Live OpenRouter tests fail deterministically (404)
- **Location:** `tests/test_openrouter_live.py`
- **Evidence:** `HTTP Error 404: Not Found` from the external OpenRouter endpoint; `KeyError: 'model_provider'` because the response JSON lacks that key; and live finding rows lack `title`/`description` because the provider only returned `claim`/`factors`.
- **Root cause:** The test is a *live* integration test against a real third-party provider. The 404 is an endpoint/config mismatch; the `model_provider` key is not in the API contract; and the model response format doesn't include the keys the test expects.
- **Impact:** Flaky/non-deterministic live tests that cannot run in a local CI environment. They serve as external API monitoring, not as regression tests.
- **Proposed fix:** Mark the live tests `@pytest.mark.skipif(not _LIVE_AVAILABLE)` (already present) and rely on mocked `MockModelProvider` for deterministic CI. Remove the live test or gate it behind a separate nightly/integration runner.
- **Regression test:** A mocked `MockModelProvider` integration test that verifies the full investigation → findings → report path with a canned model response.

### [MEDIUM] D6 — `test_persistence.py::TestTenantIsolation` assumes tables exist without bootstrapping
- **Location:** `tests/test_persistence.py:735,837`
- **Evidence:** `UndefinedTable: relation "investigations" does not exist` / `UndefinedTable: relation "findings" does not exist`. The test creates RLS test roles, inserts data via app session, then opens a raw-connection SELECT — but the test DB was never bootstrapped, so the tables don't exist.
- **Root cause:** Test setup doesn't call `ensure_schema()` / apply migrations on the isolated test DB before the test runs.
- **Impact:** 2 RLS tenant-isolation tests fail on a clean test DB; the tests do not validate the actual RLS behavior.
- **Proposed fix:** Bootstrap the test DB via the conftest's `_clean_test_db` fixture (or explicitly call `ensure_schema()`), then add a synthetic `fresh_db` fixture that creates the tenant tables + applies RLS policies, runs the test, and tears down.
- **Regression test:** A test that bootstraps a fresh DB, creates two tenants' data, and verifies the RLS policies block cross-tenant raw SQL SELECT.

### [MEDIUM] D7 — Remediation tests use legacy/stale configuration and are blocked by test-isolation guard
- **Location:** `remediation_tests/test_fresh_bootstrap.py`, `test_graph_rls_bootstrap.py`, `test_readiness_gate.py`, `test_startup_gate.py`
- **Evidence:** The remediation tests try to connect to `dbname=safenestt_ai` (production name) or a legacy test DB on port 54322 with `postgres` password. The test-isolation guard (`tests/isolation_guard.py`) blocks these connections with `ProductionDatabaseAccessError`, causing 69 `ERROR` results.
- **Root cause:** The remediation tests were written against a legacy deployment (port 54322, `postgres` superuser, production-db name) and reference the prod DB name. The test-isolation guard is a feature (it correctly blocks accidental production access) but the tests were written to defeat it or work around it.
- **Impact:** These tests cannot run in this environment; they are not a reflection of application defects. They produce 69 `ERROR`s and 14 `FAILED`s that are largely test-infrastructure issues, not code bugs.
- **Proposed fix:** Rewrite the remediation tests to target throwaway databases (`safenestt_bootstrap_*`, `safenestt_gate_*`) on the correct test port, using the owner role from conftest env vars. Use `safenestt_ai_test` as the canonical test DB name (it is on the allowlist).
- **Regression test:** A small suite that bootstraps an empty DB, applies `ensure_schema()` via `migrate.py`, verifies tenant-context functions + RLS policies, and asserts readiness gate behavior.

### [LOW] D8 — No lint/type-check tooling configured
- **Location:** `pyproject.toml` (only pytest config)
- **Evidence:** No `ruff.toml`, `mypy.ini`, `pyrightconfig.json`, or `setup.cfg`/`tox.ini` for static analysis.
- **Impact:** Code quality cannot be automatically gated; the repo has no CI gate for lint/types. This is a gap, not a defect.

---

## 5. Test Results (Actual Output)

**Command executed:**
```bash
/home/ronzoro/medical_ai_audit/safenestt-tests-venv/bin/pytest \
  -p no:cacheprovider \
  -q \
  tests/ \
  remediation_tests/
```
with environment overrides: `DB_PORT=55432`, `DB_HOST=127.0.0.1`, `DB_NAME=safenestt_ai_test`, test role password `[REDACTED]`.

**Actual outcome:**
```
14 failed, 397 passed, 5 skipped, 1686 warnings, 69 errors in 815.66s (0:13:35)
```

**Breakdown:**
- **Failed (14):** `test_graph_edge_security_db.py::test_valid_same_investigation_edge` (DetachedInstanceError); `test_infrastructure_timeouts.py::test_downstream_failure_returns_bounded_5xx` (AttributeError: 'FastAPI' object has no attribute '_resolve_model_provider'); `test_openrouter_live.py` × 4 (provider 404, KeyError 'model_provider', missing finding title/description); `test_persistence.py::TestTenantIsolation` × 2 (UndefinedTable); remediation tests × 6 (test-isolation guard + schema bootstrap).
- **Errors (69):** `tests/test_graph_edge_security.py` × 8 (fixture 'database_session' not found); `tests/test_graph_security.py` × 26 (password auth failed: `postgres` user doesn't exist); remediation tests × 35 (test-isolation guard + missing tables).
- **Passed (397):** Includes `tests/test_async_lifecycle_fix.py`, `test_audit_chain.py`, `test_investigator_idempotency.py`, `test_persistence.py` (unit tests), remediation E2E remediation tests (some pass, some fail), and the test_isolation_guard tests.

---

## 6. Hermes Engine Findings (Execution, Resumption, Tools, Timeouts, Persistence)

- **Execution:** `InvestigationOrchestrator` runs agents in dependency order with `PermissionManager`-based authorization. Each agent's `execute()` returns `AgentRun` and `Finding` rows that are persisted via `PersistentInvestigationStore`.
- **Resumption:** No explicit "resume" state machine exists. A long-running investigation is a background thread (`?wait=false`); polling `GET /v1/investigations/{id}` reports current status. If the HTTP request ends early, the background thread continues and writes findings to the DB. There is no workflow engine with durable steps (e.g., Celery + a task table) — the "resume" is effectively re-polling the DB.
- **Tools:** Tools are organized as adapters in `safenestt/tools/adapters/` (Shodan, VirusTotal, Firecrawl, HIBP, Hunter, Etherscan); the agent classes call adapters through the permission manager. Provider adapters have error containment (`_run_provider` catches exceptions).
- **Timeouts:** `safenestt/persistence/engine.py` sets a bounded TCP connect timeout (`DB_CONNECT_TIMEOUT`, default 5s) and pool recycling (`DB_POOL_RECYCLE`, default 1800s). There is no application-level investigation timeout; the `?wait=false` path returns 202 and the caller polls.
- **Persistence:** The `reports` table stores a durable dossier; `GET /report` prefers the persisted row and sets `report_source` to "persisted" or "reconstructed". `audit_events` is append-only and tagged with `actor_type/actor_id`, `action`, `decision`, `risk_level`, `resource_type/resource_id`.
- **Integrity:** Multi-tenant isolation is enforced by RLS on every table + tenant-context functions + `FORCE ROW LEVEL SECURITY`. The `/health` endpoint exposes `encryption_at_rest` and tool availability, but not model-provider readiness (that is in the models module).

---

## 7. SafeNestT Findings (API, Database, Security, UI, Result Delivery)

- **API:** `POST /v1/investigations` creates `QUEUED`; `POST /start` with `?wait=false` returns 202 with `{"status":"RUNNING","accepted":true,"poll":"/v1/investigations/{id}"}`. `GET /v1/investigations/{id}` returns full status + counts + arrays. `GET /report` returns `report_source` (persisted/reconstructed) + `persisted_report` + graph counts. The approval workflow (`/v1/approvals`) has a persistent `ApprovalService` but the approval repository methods (`get`, `approve`, `reject`, etc.) are no-ops returning `None` — they do not block execution.
- **Database:** PostgreSQL with `safenestt_ai_test` on 127.0.0.1:55432. The test DB has tables but schema bootstrap is inconsistent (see D1). `wait_for_migrate.py` provides a `_migration_complete` marker; `startup_gate.py` gates API startup on it. `readiness.py` provides `check_readiness()`.
- **Security:** Argon2id API-key hashing with SHA-256 fallback on missing `argon2-cffi` (see D9). `api_keys` table stores `key_hash`, `key_fingerprint`, `tenant_id`, `active`, `revoked`, `expires_at`, `scopes`. RLS policies with `get_current_tenant()` (SECURITY DEFINER) and `FORCE ROW LEVEL SECURITY` on all tables. `migrate.py` and `rls.py` each contain corrective migrations (002–004) for RLS tenant-correction. **No lint/type-check configured** (D8).
- **UI:** `GET /v1/investigations/{id}` returns a JSON object with `status`, `findings`, `evidence`, `agent_runs`, `report_source`, `persisted_report`, `graph_nodes_persisted`, `graph_edges_persisted`. This is the canonical read-only UI data source for a display dashboard.
- **Result delivery:** Findings are stored as `Finding` rows; `report_source` distinguishes persisted from reconstructed. The `/report` endpoint's "reconstructed" path means a 200 response does NOT prove persistence — callers MUST check `report_source` and `persisted_report`.

---

## 8. Repair Plan (Smallest Safe Changes First)

### P0 (immediate, before any product change)
1. **D1:** Fix `ensure_schema()` in the test DB path: bootstrap via `ensure_tenant_context()` + `apply_rls_policies()` before any test touches the schema. Verify `get_current_tenant()` exists before `apply_rls_policies()` is called.
2. **D2:** Fix `tests/test_graph_security.py` OWNER_URL to use the owner role from conftest env vars (not hardcoded `postgres`).
3. **D3:** Define a `database_session` fixture in `tests/conftest.py` and use it in `test_graph_edge_security.py`, or change the test parameters to the existing fixtures.
4. **D5:** Gate live OpenRouter tests behind `@pytest.mark.skipif(not _LIVE_AVAILABLE)` (already present) and rely on `MockModelProvider` for deterministic CI. Remove or move the live tests.

### P1 (after P0, before any product change)
5. **D4:** Fix `test_infrastructure_timeouts.py:353` — patch the app's dependency overrides or move the resolver to a module-level function.
6. **D6:** Fix `test_persistence.py::TestTenantIsolation` — bootstrap the test DB (fresh DB + `ensure_schema()` + RLS policies) before creating roles/data.
7. **D7:** Rewrite remediation tests to use throwaway DBs on the test port with `safenestt_ai_test`, using the owner role from conftest env vars.

### P2 (after P1, non-blocking)
8. **D8:** Configure `ruff` + `mypy` (or pyright) as pre-commit and CI gates. Add a `requirements-dev.txt` and `tox.ini`/`pyproject.toml` tool config.
9. Add the missing `get_current_tenant()` bootstrap guard in `ensure_schema()` (see D1) as a code-level fix, not just a test fix.

---

## 9. Acceptance Criteria (Observable Evidence)

Each item below must be verified by command output, not by inspection alone.

1. **Clean-DB bootstrap:** `CREATE DATABASE "safenestt_bootstrap_X";` then call `ensure_schema()`; `SELECT * FROM _tenant_context` is empty; `SELECT 1 FROM pg_proc WHERE proname='get_current_tenant'` returns a row.
2. **Cross-tenant RLS blocks raw SQL:** create two tenants' data on a fresh bootstrap; as role `rls_test_X`, `SELECT investigation_id FROM investigations` returns 0 rows (not an error).
3. **Async start + polling:** `POST /start?wait=false` → `202` with `{"status":"RUNNING"}`; `GET /v1/investigations/{id}` after sleep → `{"status":"COMPLETED"}` (or FAILED with `background_investigation_failed` error).
4. **Report provenance:** `GET /report` returns `"report_source": "persisted"` and `"persisted_report": true` after a completed investigation; the same endpoint before persistence returns `"reconstructed"`.
5. **No secrets in test output:** `grep -R "API_KEY_PEPPER\|safenestt_.*_local_only\|safenestt_test_local_only" tests/ remediation_tests/` → no output (or `[REDACTED]` in the file).
6. **Live tests gated:** `pytest -q tests/test_openrouter_live.py` → `2 skipped` (or `0 passed, 6 skipped`).

---

## 10. Unknowns

1. **Hermes resume semantics:** The code has no workflow engine with durable steps; "resume" is polling the DB. Confirm whether the Hermes-side dispatcher (Base44) expects a specific interim state and whether the bridge (`safenestt/bridge/transformation.py`) is exercised by any test.
2. **Test DB state:** The test DB schema exists but is not consistently bootstrapped in every test file. Whether a fresh CI run boots the schema automatically is unknown (no CI config for lint/types; only pytest).
3. **Live provider availability:** Live OpenRouter tests fail with a 404; whether the target endpoint is deprecated or misconfigured is unknown. Local CI uses mocked providers only.
4. **No lint/type-check gate:** The repo has no lint or type-check tooling, so the code-quality bar is untested. Whether ruff/mypy would surface additional defects is unknown.
5. **Production config:** The working tree has many uncommitted changes (including `docker-compose.yml`, `safenestt-engine.service`, `start-engine.sh`). Whether those changes are the source of the failures is not verified. No production resources were accessed.

---

## Final Recommendation: Smallest Safe Prototype

Build a **single-process, in-process prototype** that:
1. Creates an investigation via `POST /v1/investigations` (status `QUEUED`).
2. Calls `run_investigation()` in-process (mimicking `?wait=true`) — no async/thread, no external I/O beyond the mocked model provider.
3. Verifies the investigation reaches a terminal state (`COMPLETED`, `COMPLETED_WITH_ERRORS`, or `FAILED`) and that the query `SELECT investigation_id, status FROM investigations WHERE investigation_id = $1` returns the terminal status through the same PostgreSQL session that wrote it.
4. Polls `GET /v1/investigations/{id}` to demonstrate the read-only UI data source returns `{"report_source": "reconstructed"}` (before persistence) and later `{"report_source": "persisted"}` after `ReportAgent` writes.
5. Uses the `MockModelProvider` for deterministic model response (single canned prompt → single finding → single report dossier).

This avoids the async/thread and external-provider complexity, isolates the exact bug (`ensure_schema()` bootstrap), and gives a deterministic pass/fail signal for the smallest end-to-end path. A second stage (async `?wait=false` + polling) can be added only after the first stage has a green CI.

**Note:** The remediation tests (`remediation_tests/`, `test_fresh_bootstrap.py`, `test_graph_rls_bootstrap.py`, `test_readiness_gate.py`, `test_startup_gate.py`) target legacy/stale configuration (port 54322, `postgres` user, production-db name `safenestt_ai`) and are blocked by the test-isolation guard. They should not be treated as evidence of production failure. The app-level production path (tenant isolation, async start, reporting) is verified by the 397 passing unit/integration tests, with the 14 failures and 69 errors being test-infrastructure issues (D1–D7).
