-- SafeNestT AI Investigation Engine - Initial Schema Migration
-- Creates all tables, roles, RLS policies, and functions for the investigation engine.
-- Idempotent: uses CREATE IF NOT EXISTS and DROP POLICY IF EXISTS patterns.

BEGIN;

-- ============================================================
-- 1. Create safenestt_app role (least-privilege app role)
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'safenestt_app') THEN
        CREATE ROLE safenestt_app LOGIN PASSWORD 'CHANGE_IN_PRODUCTION';
        RAISE NOTICE 'Created safenestt_app role';
    END IF;
END $$;

-- ============================================================
-- 2. Core tables
-- ============================================================

CREATE TABLE IF NOT EXISTS public.api_keys (
    id              INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    key_hash        TEXT NOT NULL UNIQUE,
    key_fingerprint TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    name            TEXT,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    scopes          JSON NOT NULL DEFAULT '[]'::json,
    use_count       INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS public.api_key_audit (
    id          INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    api_key_id  INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    action      TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT 'system',
    details     JSON,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.investigations (
    id                INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    investigation_id  TEXT NOT NULL UNIQUE,
    case_id           TEXT,
    tenant_id         TEXT,
    created_by        TEXT,
    target            TEXT,
    type              TEXT,
    status            TEXT NOT NULL DEFAULT 'QUEUED',
    risk_level        TEXT,
    current_stage     TEXT,
    error             JSON,
    meta              JSON,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.agent_runs (
    id              INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    run_id          TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    agent_type      TEXT NOT NULL,
    status          TEXT NOT NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    model_provider  TEXT,
    model_name      TEXT,
    error           JSON,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    inputs          JSON,
    outputs         JSON,
    tool_calls      JSON,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.findings (
    id               INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    finding_id       TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    agent            TEXT,
    finding_type     TEXT,
    claim            TEXT,
    severity         TEXT,
    confidence       NUMERIC NOT NULL DEFAULT 0,
    source           TEXT,
    evidence_ids     JSON,
    reality_status   TEXT NOT NULL DEFAULT 'AI_INFERENCE',
    risk_score       NUMERIC NOT NULL DEFAULT 0,
    factors          JSON,
    meta             JSON,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.evidence (
    id               INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    evidence_id      TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    source           TEXT,
    source_type      TEXT,
    target           TEXT,
    observed_at      TIMESTAMPTZ,
    data             JSON,
    confidence       NUMERIC NOT NULL DEFAULT 1,
    provenance       TEXT,
    integrity_hash   TEXT,
    meta             JSON,
    tool_run_id      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.reports (
    id            INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    report_id     TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    draft         JSON,
    review_state  TEXT NOT NULL DEFAULT 'draft',
    approval_state TEXT NOT NULL DEFAULT 'pending',
    submitted_state TEXT NOT NULL DEFAULT 'draft',
    version       INTEGER NOT NULL DEFAULT 1,
    meta          JSON,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.audit_events (
    id           INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    event_id     TEXT NOT NULL,
    investigation_id TEXT REFERENCES investigations(investigation_id),
    actor_type   TEXT NOT NULL,
    actor_id     TEXT,
    action       TEXT NOT NULL,
    decision     TEXT NOT NULL,
    risk_level   TEXT NOT NULL DEFAULT 'LOW',
    resource_type TEXT,
    resource_id  TEXT,
    detail       TEXT,
    meta         JSON,
    chain_hash   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.approvals (
    id                    INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    approval_id           TEXT NOT NULL UNIQUE,
    agent_id              TEXT NOT NULL,
    tool_id               TEXT NOT NULL,
    action                TEXT NOT NULL,
    requested_capability  TEXT NOT NULL,
    risk_level            TEXT NOT NULL DEFAULT 'LOW',
    requester_context     JSON,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expiration_at         TIMESTAMPTZ,
    decision_at           TIMESTAMPTZ,
    approver_identity     TEXT,
    status                TEXT NOT NULL DEFAULT 'pending',
    redacted_metadata     JSON,
    organization_id       TEXT
);

CREATE TABLE IF NOT EXISTS public.rate_limits (
    id            INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    scope         TEXT NOT NULL,
    key           TEXT NOT NULL,
    limit         INTEGER NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_end    TIMESTAMPTZ NOT NULL,
    count         INTEGER NOT NULL DEFAULT 1,
    UNIQUE (scope, key, window_start)
);

CREATE TABLE IF NOT EXISTS public._tenant_context (
    backend_pid     INTEGER PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    established_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
);

-- ============================================================
-- 3. Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_active ON api_keys(tenant_id, active);
CREATE INDEX IF NOT EXISTS idx_tenant_context_expires ON _tenant_context(expires_at);
CREATE INDEX IF NOT EXISTS ix_investigations_tenant_status ON investigations(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_investigations_target_type ON investigations(target, type);
CREATE INDEX IF NOT EXISTS ix_agent_runs_investigation_agent ON agent_runs(investigation_id, agent_type);
CREATE INDEX IF NOT EXISTS ix_findings_investigation_type ON findings(investigation_id, finding_type);
CREATE INDEX IF NOT EXISTS ix_findings_reality ON findings(investigation_id, reality_status);
CREATE INDEX IF NOT EXISTS ix_evidence_investigation_source ON evidence(investigation_id, source);
CREATE INDEX IF NOT EXISTS ix_reports_investigation_version ON reports(investigation_id, version);
CREATE INDEX IF NOT EXISTS ix_audit_investigation_action ON audit_events(investigation_id, action);
CREATE INDEX IF NOT EXISTS ix_audit_actor_action ON audit_events(actor_type, action);

-- ============================================================
-- 4. Grant privileges to safenestt_app
-- ============================================================
GRANT USAGE ON SCHEMA public TO safenestt_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safenestt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safenestt_app;

-- ============================================================
-- 5. Revoke access to _tenant_context from app role
-- ============================================================
REVOKE ALL ON _tenant_context FROM safenestt_app;
REVOKE ALL ON _tenant_context FROM PUBLIC;

-- ============================================================
-- 6. SECURITY DEFINER functions for tenant context
-- ============================================================

CREATE OR REPLACE FUNCTION establish_tenant_context(p_tenant_id TEXT, p_key_fingerprint TEXT)
RETURNS TEXT AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SET search_path = public;
    SELECT COUNT(*) INTO v_count
    FROM api_keys ak
    WHERE ak.key_fingerprint = p_key_fingerprint
      AND ak.tenant_id = p_tenant_id
      AND ak.active = TRUE
      AND ak.revoked = FALSE
      AND (ak.expires_at IS NULL OR ak.expires_at > NOW());
    IF v_count = 0 THEN
        RAISE EXCEPTION 'Invalid API key or tenant mismatch';
    END IF;
    INSERT INTO _tenant_context (backend_pid, tenant_id, key_fingerprint, expires_at)
    VALUES (pg_backend_pid(), p_tenant_id, p_key_fingerprint, NOW() + INTERVAL '1 hour')
    ON CONFLICT (backend_pid) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        key_fingerprint = EXCLUDED.key_fingerprint,
        established_at = NOW(),
        expires_at = NOW() + INTERVAL '1 hour';
    RETURN p_tenant_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_current_tenant()
RETURNS TEXT AS $$
DECLARE
    v_tenant_id TEXT;
BEGIN
    SET search_path = public;
    SELECT tc.tenant_id INTO v_tenant_id
    FROM _tenant_context tc
    WHERE tc.backend_pid = pg_backend_pid()
      AND tc.expires_at > NOW();
    RETURN COALESCE(v_tenant_id, '');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION clear_tenant_context()
RETURNS VOID AS $$
BEGIN
    SET search_path = public;
    DELETE FROM _tenant_context WHERE backend_pid = pg_backend_pid();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION establish_tenant_context(TEXT, TEXT) TO safenestt_app;
GRANT EXECUTE ON FUNCTION get_current_tenant() TO safenestt_app;
GRANT EXECUTE ON FUNCTION clear_tenant_context() TO safenestt_app;
REVOKE ALL ON FUNCTION establish_tenant_context(TEXT, TEXT), get_current_tenant(), clear_tenant_context() FROM PUBLIC;

-- ============================================================
-- 7. RLS Policies
-- ============================================================

ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
CREATE POLICY investigations_tenant_isolation ON investigations
    FOR ALL USING (tenant_id = get_current_tenant());

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY findings_tenant_isolation ON findings
    FOR ALL USING (
        investigation_id IN (
            SELECT investigation_id FROM investigations
            WHERE tenant_id = get_current_tenant()
        )
    );

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY evidence_tenant_isolation ON evidence
    FOR ALL USING (
        investigation_id IN (
            SELECT investigation_id FROM investigations
            WHERE tenant_id = get_current_tenant()
        )
    );

ALTER TABLE agent_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY agent_runs_tenant_isolation ON agent_runs
    FOR ALL USING (
        investigation_id IN (
            SELECT investigation_id FROM investigations
            WHERE tenant_id = get_current_tenant()
        )
    );

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY reports_tenant_isolation ON reports
    FOR ALL USING (
        investigation_id IN (
            SELECT investigation_id FROM investigations
            WHERE tenant_id = get_current_tenant()
        )
    );

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_events_policy ON audit_events
    FOR ALL USING (
        investigation_id IS NULL OR
        investigation_id IN (
            SELECT investigation_id FROM investigations
            WHERE tenant_id = get_current_tenant()
        )
    );

COMMIT;
