from __future__ import annotations

import hashlib
import json
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class InvestigationModel(Base):
    __tablename__ = "investigations"

    id = mapped_column(Integer, primary_key=True)
    investigation_id = mapped_column(Text, unique=True, nullable=False, index=True)
    case_id = mapped_column(Text, nullable=True, index=True)
    tenant_id = mapped_column(Text, nullable=True, index=True)
    created_by = mapped_column(Text, nullable=True)
    target = mapped_column(Text, nullable=True)
    type = mapped_column(Text, nullable=True)
    status = mapped_column(Text, nullable=False, default="QUEUED")
    risk_level = mapped_column(Text, nullable=True)
    current_stage = mapped_column(Text, nullable=True)
    error = mapped_column(JSON, nullable=True)
    meta = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    agent_runs: Mapped[list["AgentRunModel"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    findings: Mapped[list["FindingModel"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    evidence: Mapped[list["EvidenceModel"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    reports: Mapped[list["ReportModel"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    audit_events: Mapped[list["AuditEventModel"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_investigations_tenant_status", "tenant_id", "status"),
        Index("ix_investigations_target_type", "target", "type"),
    )


class AgentRunModel(Base):
    __tablename__ = "agent_runs"

    id = mapped_column(Integer, primary_key=True)
    run_id = mapped_column(Text, unique=True, nullable=False, index=True)
    investigation_id = mapped_column(Text, ForeignKey("investigations.investigation_id"), nullable=False, index=True)
    agent_type = mapped_column(Text, nullable=False, index=True)
    status = mapped_column(Text, nullable=False)
    started_at = mapped_column(DateTime, nullable=True)
    completed_at = mapped_column(DateTime, nullable=True)
    model_provider = mapped_column(Text, nullable=True)
    model_name = mapped_column(Text, nullable=True)
    error = mapped_column(JSON, nullable=True)
    retry_count = mapped_column(Integer, nullable=False, default=0)
    inputs = mapped_column(JSON, nullable=True)
    outputs = mapped_column(JSON, nullable=True)
    tool_calls = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    investigation: Mapped["InvestigationModel"] = relationship(back_populates="agent_runs")

    __table_args__ = (
        Index("ix_agent_runs_investigation_agent", "investigation_id", "agent_type"),
    )


class FindingModel(Base):
    __tablename__ = "findings"

    id = mapped_column(Integer, primary_key=True)
    finding_id = mapped_column(Text, unique=True, nullable=False, index=True)
    investigation_id = mapped_column(Text, ForeignKey("investigations.investigation_id"), nullable=False, index=True)
    agent = mapped_column(Text, nullable=True)
    finding_type = mapped_column(Text, nullable=True)  # Optional - for future use
    claim = mapped_column(Text, nullable=True)
    severity = mapped_column(Text, nullable=True)
    confidence = mapped_column(Float, nullable=False, default=0.0)
    source = mapped_column(Text, nullable=True)
    evidence_ids = mapped_column(JSON, nullable=True)
    reality_status = mapped_column(Text, nullable=False, default="AI_INFERENCE")
    risk_score = mapped_column(Float, nullable=False, default=0.0)
    factors = mapped_column(JSON, nullable=True)
    meta = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    investigation: Mapped["InvestigationModel"] = relationship(back_populates="findings")

    __table_args__ = (
        Index("ix_findings_investigation_type", "investigation_id", "finding_type"),
        Index("ix_findings_reality", "investigation_id", "reality_status"),
    )


class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = mapped_column(Integer, primary_key=True)
    evidence_id = mapped_column(Text, unique=True, nullable=False, index=True)
    investigation_id = mapped_column(Text, ForeignKey("investigations.investigation_id"), nullable=False, index=True)
    source = mapped_column(Text, nullable=True)
    source_type = mapped_column(Text, nullable=True)
    target = mapped_column(Text, nullable=True)
    observed_at = mapped_column(DateTime, nullable=True)
    data = mapped_column(JSON, nullable=True)
    confidence = mapped_column(Float, nullable=False, default=1.0)
    provenance = mapped_column(Text, nullable=True)
    integrity_hash = mapped_column(Text, nullable=True)
    meta = mapped_column(JSON, nullable=True)
    tool_run_id = mapped_column(Text, nullable=True, index=True)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))

    investigation: Mapped["InvestigationModel"] = relationship(back_populates="evidence")

    __table_args__ = (
        Index("ix_evidence_investigation_source", "investigation_id", "source"),
        Index("ix_evidence_tool_run", "tool_run_id"),
    )


class ReportModel(Base):
    __tablename__ = "reports"

    id = mapped_column(Integer, primary_key=True)
    report_id = mapped_column(Text, unique=True, nullable=False, index=True)
    investigation_id = mapped_column(Text, ForeignKey("investigations.investigation_id"), nullable=False, index=True)
    draft = mapped_column(JSON, nullable=True)
    review_state = mapped_column(Text, nullable=False, default="draft")
    approval_state = mapped_column(Text, nullable=False, default="pending")
    submitted_state = mapped_column(Text, nullable=False, default="draft")
    version = mapped_column(Integer, nullable=False, default=1)
    meta = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    investigation: Mapped["InvestigationModel"] = relationship(back_populates="reports")

    __table_args__ = (
        Index("ix_reports_investigation_version", "investigation_id", "version"),
    )


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id = mapped_column(Integer, primary_key=True)
    event_id = mapped_column(Text, unique=True, nullable=False, index=True)
    investigation_id = mapped_column(Text, ForeignKey("investigations.investigation_id"), nullable=True, index=True)
    actor_type = mapped_column(Text, nullable=False)
    actor_id = mapped_column(Text, nullable=True)
    action = mapped_column(Text, nullable=False)
    decision = mapped_column(Text, nullable=False)
    risk_level = mapped_column(Text, nullable=False, default="LOW")
    resource_type = mapped_column(Text, nullable=True)
    resource_id = mapped_column(Text, nullable=True)
    detail = mapped_column(Text, nullable=True)
    meta = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    # Hash-chain integrity: each row stores a hash of (previous_hash + this row's data)
    chain_hash = mapped_column(Text, nullable=False)

    investigation: Mapped["InvestigationModel | None"] = relationship(back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_investigation_action", "investigation_id", "action"),
        Index("ix_audit_actor_action", "actor_type", "action"),
    )


class APIKeyModel(Base):
    """PostgreSQL-backed API key storage.
    
    Keys are NEVER stored in plaintext — only Argon2id hashes.
    Each key belongs to exactly one tenant.
    key_fingerprint is SHA-256 for fast lookup (Argon2 uses random salts).
    """
    __tablename__ = "api_keys"

    id = mapped_column(Integer, primary_key=True)
    key_hash = mapped_column(Text, unique=True, nullable=False, index=True)
    key_fingerprint = mapped_column(Text, unique=True, nullable=False, index=True)
    tenant_id = mapped_column(Text, nullable=False, index=True)
    name = mapped_column(Text, nullable=True)
    active = mapped_column(Boolean, nullable=False, default=True)
    revoked = mapped_column(Boolean, nullable=False, default=False)
    revoked_at = mapped_column(DateTime, nullable=True)
    expires_at = mapped_column(DateTime, nullable=True)
    scopes = mapped_column(JSON, nullable=False, default=list)
    created_at = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    last_used_at = mapped_column(DateTime, nullable=True)
    use_count = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_api_keys_tenant_active", "tenant_id", "active"),
    )