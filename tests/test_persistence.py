from __future__ import annotations

import pytest
import psycopg2
import uuid
import os
from datetime import datetime, UTC
from sqlalchemy import text, create_engine as sa_create_engine
from sqlalchemy.orm import sessionmaker, Session

from safenestt.persistence.models import (
    AgentRunModel,
    AuditEventModel,
    EvidenceModel,
    FindingModel,
    InvestigationModel,
    ReportModel,
    Base,
)
from safenestt.persistence.repositories import (
    AgentRunRepository,
    AuditEventRepository,
    EvidenceRepository,
    FindingRepository,
    InvestigationRepository,
    ReportRepository,
)
from safenestt.persistence.rls import apply_rls_policies, set_tenant_context
from safenestt.investigations.records import InvestigationRecord, FindingRecord, EvidenceRecord

# DB connection URLs - passwords from env for security, with dev fallbacks
_OWNER_PASS = os.getenv("SAFENESTT_OWNER_PASSWORD", os.getenv("POSTGRES_PASSWORD", "postgres"))
_APP_PASS = os.getenv("SAFENESTT_DB_PASSWORD", os.getenv("DB_PASSWORD", "safenestt_app_pass"))
OWNER_URL = f"postgresql://postgres:{_OWNER_PASS}@172.19.0.11:5432/safenestt_ai"
APP_URL = f"postgresql://safenestt_app:{_APP_PASS}@172.19.0.11:5432/safenestt_ai"


def _app_session():
    engine = sa_create_engine(APP_URL)
    return sessionmaker(bind=engine)()


@pytest.fixture(autouse=True)
def fresh_db():
    # DDL via owner
    conn = psycopg2.connect(OWNER_URL)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS audit_events, reports, evidence, findings, agent_runs, investigations CASCADE")
    cur.close()
    conn.close()

    owner_engine = sa_create_engine(OWNER_URL)
    Base.metadata.create_all(owner_engine)
    apply_rls_policies(owner_engine)

    # Grant privileges
    conn = psycopg2.connect(OWNER_URL)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO safenestt_app")
    cur.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO safenestt_app")
    cur.close()
    conn.close()

    yield

    conn = psycopg2.connect(OWNER_URL)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS audit_events, reports, evidence, findings, agent_runs, investigations CASCADE")
    cur.close()
    conn.close()


class TestInvestigationRepository:
    def test_create_and_get(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            repo = InvestigationRepository(s)
            record = InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            )
            repo.create(record)
            s.commit()
            retrieved = repo.get("inv-1")
            assert retrieved is not None
            assert retrieved.investigation_id == "inv-1"
            assert retrieved.tenant_id == "org-1"
            assert retrieved.status == "QUEUED"
        finally:
            s.close()

    def test_update_status(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            repo = InvestigationRepository(s)
            record = InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            )
            repo.create(record)
            s.commit()
            record.status = "RUNNING"
            repo.update(record)
            s.commit()
            retrieved = repo.get("inv-1")
            assert retrieved.status == "RUNNING"
        finally:
            s.close()

    def test_list_by_tenant(self, fresh_db):
        # Create data for two tenants using separate sessions
        s1 = _app_session()
        try:
            set_tenant_context(s1.connection(), "org-1")
            repo1 = InvestigationRepository(s1)
            for i in range(3):
                rec = InvestigationRecord(
                    investigation_id=f"inv-{i}", tenant_id="org-1", created_by="user-1",
                    target=f"target-{i}.com", type="domain", status="QUEUED",
                )
                repo1.create(rec)
            s1.commit()
        finally:
            s1.close()

        s2 = _app_session()
        try:
            set_tenant_context(s2.connection(), "org-2")
            repo2 = InvestigationRepository(s2)
            rec2 = InvestigationRecord(
                investigation_id="inv-other", tenant_id="org-2", created_by="user-1",
                target="other.com", type="domain", status="QUEUED",
            )
            repo2.create(rec2)
            s2.commit()
        finally:
            s2.close()

        # Verify org-1 sees only its data
        s1 = _app_session()
        try:
            set_tenant_context(s1.connection(), "org-1")
            repo1 = InvestigationRepository(s1)
            org1 = repo1.list_by_tenant(tenant_id="org-1")
            assert len(org1) == 3
        finally:
            s1.close()

        # Verify org-2 sees only its data
        s2 = _app_session()
        try:
            set_tenant_context(s2.connection(), "org-2")
            repo2 = InvestigationRepository(s2)
            org2 = repo2.list_by_tenant(tenant_id="org-2")
            assert len(org2) == 1
        finally:
            s2.close()


class TestAgentRunRepository:
    def test_create_and_complete(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = AgentRunRepository(s)
            run = repo.create(inv.investigation_id, "run-1", "osint", model_provider="mock", model_name="mock-model")
            assert run.run_id == "run-1"
            assert run.status == "running"
            s.commit()
            completed = repo.complete("run-1", outputs={"findings": []})
            s.commit()
            assert completed.status == "completed"
            assert completed.completed_at is not None
        finally:
            s.close()

    def test_increment_retry(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = AgentRunRepository(s)
            repo.create(inv.investigation_id, "run-1", "osint")
            s.commit()
            incremented = repo.increment_retry("run-1")
            assert incremented.retry_count == 1
        finally:
            s.close()

    def test_list_by_investigation(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = AgentRunRepository(s)
            repo.create(inv.investigation_id, "run-1", "osint")
            repo.create(inv.investigation_id, "run-2", "threat_intel")
            repo.create(inv.investigation_id, "run-3", "crypto")
            s.commit()
            runs = repo.list_by_investigation("inv-1")
            assert len(runs) == 3
        finally:
            s.close()


class TestFindingRepository:
    def test_add_and_list(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = FindingRepository(s)
            finding = FindingRecord(
                investigation_id=inv.investigation_id, finding_id="find-1", claim="Suspicious domain",
            )
            repo.add(inv.investigation_id, finding)
            s.commit()
            findings = repo.list_by_investigation("inv-1")
            assert len(findings) == 1
            assert findings[0].finding_id == "find-1"
            assert findings[0].reality_status == "AI_INFERENCE"
        finally:
            s.close()


class TestEvidenceRepository:
    def test_add_and_list(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = EvidenceRepository(s)
            evidence = EvidenceRecord(
                investigation_id=inv.investigation_id, evidence_id="ev-1", source="dns",
                source_type="tool", target="example.com",
                observed_at=datetime.now(UTC), data={"records": ["1.1.1.1"]},
                confidence=1.0, provenance="dns.lookup", tool_run_id="run-1",
            )
            repo.add(inv.investigation_id, evidence)
            s.commit()
            items = repo.list_by_investigation("inv-1")
            assert len(items) == 1
            assert items[0].evidence_id == "ev-1"
            assert items[0].integrity_hash is not None
        finally:
            s.close()

    def test_integrity_hash_changes_with_content(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = EvidenceRepository(s)
            ev1 = EvidenceRecord(
                investigation_id=inv.investigation_id, evidence_id="ev-1", source="dns",
                source_type="tool", target="example.com",
                observed_at=datetime.now(UTC), data={"records": ["1.1.1.1"]},
                confidence=1.0, provenance="dns.lookup", tool_run_id="run-1",
            )
            ev2 = EvidenceRecord(
                investigation_id=inv.investigation_id, evidence_id="ev-2", source="dns",
                source_type="tool", target="example.com",
                observed_at=datetime.now(UTC), data={"records": ["2.2.2.2"]},
                confidence=1.0, provenance="dns.lookup", tool_run_id="run-1",
            )
            repo.add(inv.investigation_id, ev1)
            repo.add(inv.investigation_id, ev2)
            s.commit()
            items = repo.list_by_investigation("inv-1")
            assert items[0].integrity_hash != items[1].integrity_hash
        finally:
            s.close()


class TestReportRepository:
    def test_create_and_update(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = ReportRepository(s)
            repo.create(inv.investigation_id, "report-1")
            s.commit()
            report = repo.get_by_investigation("inv-1")
            assert report is not None
            assert report.review_state == "draft"
            assert report.approval_state == "pending"
            assert report.submitted_state == "draft"
            assert report.version == 1

            repo.update_review("report-1", "under_review", approval_state="pending")
            assert report.review_state == "under_review"
            assert report.version == 2

            repo.update_submission("report-1", "submitted")
            assert report.submitted_state == "submitted"
            assert report.version == 3
        finally:
            s.close()


class TestAuditEventRepository:
    def test_record_and_list(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = AuditEventRepository(s)
            from safenestt.security.audit import AuditEvent, RiskLevel
            event = AuditEvent(
                event_id="evt-1", actor_type="agent", actor_id="a1",
                action="tool.execute", decision="ALLOW", risk_level=RiskLevel.LOW,
                metadata={"investigation_id": "inv-1"},
            )
            repo.record(event)
            s.commit()
            events = repo.list_by_investigation("inv-1")
            assert len(events) == 1
            assert events[0].event_id == "evt-1"
        finally:
            s.close()

    def test_sanitizes_secrets(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()
            repo = AuditEventRepository(s)
            from safenestt.security.audit import AuditEvent, RiskLevel
            event = AuditEvent(
                event_id="evt-2", actor_type="agent", actor_id="a1",
                action="tool.execute", decision="ALLOW", risk_level=RiskLevel.LOW,
                metadata={"api_key": "secret123", "password": "pass456", "note": "ok", "investigation_id": "inv-1"},
            )
            repo.record(event)
            s.commit()
            events = repo.list_by_investigation("inv-1")
            assert len(events) == 1

            # Secrets redacted
            assert "api_key" not in (events[0].meta or {})
            assert "password" not in (events[0].meta or {})
            assert events[0].meta.get("note") == "ok"
        finally:
            s.close()

    def test_hash_chain_integrity(self, fresh_db):
        """Verify that hash-chain integrity is maintained across multiple events."""
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()

            repo = AuditEventRepository(s)
            from safenestt.security.audit import AuditEvent, RiskLevel

            # Record 3 events
            for i in range(3):
                event = AuditEvent(
                    event_id=f"evt-{i}",
                    actor_type="agent",
                    actor_id=f"a{i}",
                    action="tool.execute",
                    decision="ALLOW",
                    risk_level=RiskLevel.LOW,
                )
                repo.record(event)
            s.commit()

            # Verify chain integrity
            events = repo.list_all()
            assert len(events) == 3

            is_valid, msg = AuditEventRepository.verify_chain_integrity(events)
            assert is_valid, f"Chain should be valid: {msg}"

            # Verify each event has a chain_hash
            for evt in events:
                assert evt.chain_hash is not None
                assert len(evt.chain_hash) == 64  # SHA-256 hex

        finally:
            s.close()

    def test_hash_chain_detects_tampering(self, fresh_db):
        """Verify that modifying a historical event breaks the chain."""
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()

            repo = AuditEventRepository(s)
            from safenestt.security.audit import AuditEvent, RiskLevel

            # Record 3 events
            for i in range(3):
                event = AuditEvent(
                    event_id=f"evt-{i}",
                    actor_type="agent",
                    actor_id=f"a{i}",
                    action="tool.execute",
                    decision="ALLOW",
                    risk_level=RiskLevel.LOW,
                )
                repo.record(event)
            s.commit()

            # Tamper with the first event's action (simulating DB-level tampering)
            events = repo.list_all()
            assert len(events) == 3
            first_event = events[0]

            # Direct SQL to bypass audit logging — simulate an attacker with DB access
            s.execute(
                text("UPDATE audit_events SET action = 'tampered' WHERE event_id = :evt_id"),
                {"evt_id": first_event.event_id}
            )
            s.commit()

            # Re-fetch and verify — chain should be broken
            events_after = repo.list_all()
            is_valid, msg = AuditEventRepository.verify_chain_integrity(events_after)
            assert not is_valid, f"Chain should be broken after tampering: {msg}"
            assert "evt-0" in msg or "tampered" in msg.lower() or "Chain broken" in msg

        finally:
            s.close()

    def test_chain_hash_stored_in_dedicated_column(self, fresh_db):
        """Verify chain_hash is stored in its own column, not in meta JSON."""
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            inv_repo = InvestigationRepository(s)
            inv = inv_repo.create(InvestigationRecord(
                investigation_id="inv-1", tenant_id="org-1", created_by="user-1",
                target="example.com", type="domain", status="QUEUED",
            ))
            s.commit()

            repo = AuditEventRepository(s)
            from safenestt.security.audit import AuditEvent, RiskLevel
            event = AuditEvent(
                event_id="evt-col", actor_type="agent", actor_id="a1",
                action="tool.execute", decision="ALLOW", risk_level=RiskLevel.LOW,
            )
            repo.record(event)
            s.commit()

            events = repo.list_all()
            assert len(events) == 1

            evt = events[0]
            # chain_hash is a dedicated column
            assert evt.chain_hash is not None
            # NOT stored in mutable meta
            assert "_chain_hash" not in (evt.meta or {})

        finally:
            s.close()


class TestPersistentStore:
    def test_health_check(self, fresh_db):
        # Create data with explicit tenant_id (required by RLS policy)
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            s.add(InvestigationModel(investigation_id="inv-1", tenant_id="org-1", status="QUEUED"))
            s.commit()
        finally:
            s.close()

        # Verify org-1 can see its data
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            result = s.execute(text("SELECT COUNT(*) FROM investigations")).scalar()
            assert result >= 1
        finally:
            s.close()

    def test_table_counts_after_writes(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            s.add(InvestigationModel(investigation_id="inv-1", tenant_id="org-1", status="QUEUED"))
            s.commit()
            s.add(AgentRunModel(run_id="run-1", investigation_id="inv-1", agent_type="osint", status="running"))
            s.commit()
            result = s.execute(text("SELECT COUNT(*) FROM investigations")).scalar()
            assert result >= 1
            result2 = s.execute(text("SELECT COUNT(*) FROM agent_runs")).scalar()
            assert result2 >= 1
        finally:
            s.close()


class TestUpgradePersistence:
    def test_upgrade_returns_schema_info(self, fresh_db):
        s = _app_session()
        try:
            set_tenant_context(s.connection(), "org-1")
            tables = s.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'")).scalars().all()
            assert "investigations" in tables
            assert "agent_runs" in tables
            assert "findings" in tables
            assert "evidence" in tables
            assert "reports" in tables
            assert "audit_events" in tables
        finally:
            s.close()


class TestTenantIsolation:
    def test_cross_tenant_investigations_separate(self, fresh_db):
        # Create data for org-1
        s1 = _app_session()
        try:
            set_tenant_context(s1.connection(), "org-1")
            repo1 = InvestigationRepository(s1)
            for i in range(3):
                rec = InvestigationRecord(
                    investigation_id=f"inv-{i}", tenant_id="org-1", created_by="user-1",
                    target=f"target-{i}.com", type="domain", status="QUEUED",
                )
                repo1.create(rec)
            s1.commit()
        finally:
            s1.close()

        # Create data for org-2
        s2 = _app_session()
        try:
            set_tenant_context(s2.connection(), "org-2")
            repo2 = InvestigationRepository(s2)
            rec2 = InvestigationRecord(
                investigation_id="inv-a", tenant_id="org-2", created_by="user-2",
                target="target-a.com", type="domain", status="QUEUED",
            )
            repo2.create(rec2)
            s2.commit()
        finally:
            s2.close()

        # Verify org-1 sees only its data
        s1 = _app_session()
        try:
            set_tenant_context(s1.connection(), "org-1")
            org1 = InvestigationRepository(s1).list_by_tenant(tenant_id="org-1")
            assert len(org1) == 3
        finally:
            s1.close()

        # Verify org-2 sees only its data
        s2 = _app_session()
        try:
            set_tenant_context(s2.connection(), "org-2")
            org2 = InvestigationRepository(s2).list_by_tenant(tenant_id="org-2")
            assert len(org2) == 1
        finally:
            s2.close()

    def test_rls_blocks_cross_tenant_raw_query(self, fresh_db):
        """Test that RLS blocks cross-tenant access even via raw SQL bypass."""
        role_name = f"rls_test_{uuid.uuid4().hex[:8]}"
        role_pass = "rls_test_pass"

        setup_conn = psycopg2.connect(OWNER_URL)
        setup_conn.autocommit = True
        setup_cur = setup_conn.cursor()
        setup_cur.execute(f"CREATE ROLE {role_name} LOGIN PASSWORD %s", (role_pass,))
        setup_cur.execute(f"GRANT USAGE ON SCHEMA public TO {role_name}")
        setup_cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role_name}")
        setup_cur.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role_name}")
        setup_cur.close()
        setup_conn.close()

        try:
            # Create data via app session (RLS applies)
            s1 = _app_session()
            try:
                set_tenant_context(s1.connection(), "tenant-a")
                s1.add(InvestigationModel(
                    investigation_id="inv-a", tenant_id="tenant-a", status="QUEUED",
                    created_at=datetime.now(UTC), updated_at=datetime.now(UTC)
                ))
                s1.commit()
            finally:
                s1.close()

            s2 = _app_session()
            try:
                set_tenant_context(s2.connection(), "tenant-b")
                s2.add(InvestigationModel(
                    investigation_id="inv-b", tenant_id="tenant-b", status="QUEUED",
                    created_at=datetime.now(UTC), updated_at=datetime.now(UTC)
                ))
                s2.commit()
            finally:
                s2.close()

            # Test via separate role (not app role)
            conn_a = psycopg2.connect(f"postgresql://{role_name}:{role_pass}@172.19.0.11:5432/safenestt_ai")
            conn_a.autocommit = False
            cur_a = conn_a.cursor()
            cur_a.execute("BEGIN")
            cur_a.execute("SET LOCAL app.current_tenant_id = 'tenant-a'")
            cur_a.execute("SELECT investigation_id FROM investigations")
            result_a = [r[0] for r in cur_a.fetchall()]
            assert "inv-a" in result_a
            assert "inv-b" not in result_a, f"RLS failure: tenant-a can see tenant-b: {result_a}"
            conn_a.commit()
            cur_a.close()
            conn_a.close()

            conn_b = psycopg2.connect(f"postgresql://{role_name}:{role_pass}@172.19.0.11:5432/safenestt_ai")
            conn_b.autocommit = False
            cur_b = conn_b.cursor()
            cur_b.execute("BEGIN")
            cur_b.execute("SET LOCAL app.current_tenant_id = 'tenant-b'")
            cur_b.execute("SELECT investigation_id FROM investigations")
            result_b = [r[0] for r in cur_b.fetchall()]
            assert "inv-b" in result_b
            assert "inv-a" not in result_b, f"RLS failure: tenant-b can see tenant-a: {result_b}"
            conn_b.commit()
            cur_b.close()
            conn_b.close()
        finally:
            setup_conn = psycopg2.connect(OWNER_URL)
            setup_conn.autocommit = True
            setup_cur = setup_conn.cursor()
            try:
                setup_cur.execute(f"DROP OWNED BY {role_name} CASCADE")
                setup_cur.execute(f"DROP ROLE {role_name}")
            except psycopg2.Error:
                pass
            setup_cur.close()
            setup_conn.close()

    def test_rls_blocks_child_table_cross_tenant_access(self, fresh_db):
        role_name = f"rls_test_{uuid.uuid4().hex[:8]}"
        role_pass = "rls_test_pass"

        setup_conn = psycopg2.connect(OWNER_URL)
        setup_conn.autocommit = True
        setup_cur = setup_conn.cursor()
        setup_cur.execute(f"CREATE ROLE {role_name} LOGIN PASSWORD %s", (role_pass,))
        setup_cur.execute(f"GRANT USAGE ON SCHEMA public TO {role_name}")
        setup_cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role_name}")
        setup_cur.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role_name}")
        setup_cur.close()
        setup_conn.close()

        try:
            # Create data via app session
            s1 = _app_session()
            try:
                set_tenant_context(s1.connection(), "tenant-a")
                s1.add(InvestigationModel(
                    investigation_id="inv-a", tenant_id="tenant-a", status="QUEUED",
                    created_at=datetime.now(UTC), updated_at=datetime.now(UTC)
                ))
                s1.add(FindingModel(finding_id="find-a", investigation_id="inv-a", claim="Secret", finding_type="AI_INFERENCE"))
                s1.commit()
            finally:
                s1.close()

            s2 = _app_session()
            try:
                set_tenant_context(s2.connection(), "tenant-b")
                s2.add(InvestigationModel(
                    investigation_id="inv-b", tenant_id="tenant-b", status="QUEUED",
                    created_at=datetime.now(UTC), updated_at=datetime.now(UTC)
                ))
                s2.add(FindingModel(finding_id="find-b", investigation_id="inv-b", claim="Other secret", finding_type="AI_INFERENCE"))
                s2.commit()
            finally:
                s2.close()

            conn_a = psycopg2.connect(f"postgresql://{role_name}:{role_pass}@172.19.0.11:5432/safenestt_ai")
            conn_a.autocommit = False
            cur_a = conn_a.cursor()
            cur_a.execute("BEGIN")
            cur_a.execute("SET LOCAL app.current_tenant_id = 'tenant-a'")
            cur_a.execute("SELECT finding_id FROM findings")
            result_a = [r[0] for r in cur_a.fetchall()]
            assert "find-a" in result_a
            assert "find-b" not in result_a, f"RLS failure on findings: {result_a}"
            conn_a.commit()
            cur_a.close()
            conn_a.close()

            conn_b = psycopg2.connect(f"postgresql://{role_name}:{role_pass}@172.19.0.11:5432/safenestt_ai")
            conn_b.autocommit = False
            cur_b = conn_b.cursor()
            cur_b.execute("BEGIN")
            cur_b.execute("SET LOCAL app.current_tenant_id = 'tenant-b'")
            cur_b.execute("SELECT finding_id FROM findings")
            result_b = [r[0] for r in cur_b.fetchall()]
            assert "find-b" in result_b
            assert "find-a" not in result_b, f"RLS failure on findings: {result_b}"
            conn_b.commit()
            cur_b.close()
            conn_b.close()
        finally:
            setup_conn = psycopg2.connect(OWNER_URL)
            setup_conn.autocommit = True
            setup_cur = setup_conn.cursor()
            try:
                setup_cur.execute(f"DROP OWNED BY {role_name} CASCADE")
                setup_cur.execute(f"DROP ROLE {role_name}")
            except psycopg2.Error:
                pass
            setup_cur.close()
            setup_conn.close()

    def test_null_tenant_investigation_hidden(self, fresh_db):
        """Verify that a NULL-tenant investigation is NOT visible to any tenant."""
        # Create NULL-tenant investigation via owner (bypasses RLS)
        setup_conn = psycopg2.connect(OWNER_URL)
        setup_conn.autocommit = True
        setup_cur = setup_conn.cursor()
        setup_cur.execute("INSERT INTO investigations (investigation_id, tenant_id, status, created_at, updated_at) VALUES ('inv-null', NULL, 'QUEUED', NOW(), NOW())")
        setup_cur.close()
        setup_conn.close()

        try:
            # App session should NOT see NULL-tenant investigation
            s = _app_session()
            try:
                set_tenant_context(s.connection(), "some-tenant")
                result = s.execute(text("SELECT investigation_id FROM investigations")).scalars().all()
                assert "inv-null" not in result, f"FAIL: NULL-tenant visible to some-tenant: {result}"
            finally:
                s.close()

            # Another tenant also should NOT see it
            s2 = _app_session()
            try:
                set_tenant_context(s2.connection(), "another-tenant")
                result = s2.execute(text("SELECT investigation_id FROM investigations")).scalars().all()
                assert "inv-null" not in result, f"FAIL: NULL-tenant visible to another-tenant: {result}"
            finally:
                s2.close()
        finally:
            setup_conn = psycopg2.connect(OWNER_URL)
            setup_conn.autocommit = True
            setup_cur = setup_conn.cursor()
            setup_cur.execute("DELETE FROM investigations WHERE investigation_id = 'inv-null'")
            setup_cur.close()
            setup_conn.close()
