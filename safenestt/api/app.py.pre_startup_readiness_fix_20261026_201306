from fastapi import FastAPI, HTTPException, Request, Depends, Response
from pydantic import BaseModel
import hashlib
import hmac
from typing import Any
import os
import logging
import threading

from safenestt.investigations.investigator import run_investigation
from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.store import (
    PersistentInvestigationStore,
    TenantIsolationError,
    ensure_schema,
)
from safenestt.investigations.intelligence import build_dossier_intelligence
from safenestt.model.registry import GeminiProvider, ModelProvider, OllamaProvider, OpenAICompatibleProvider, OpenRouterProvider
from safenestt.security.encryption import is_encryption_enabled
from safenestt.persistence.engine import get_engine
from safenestt.persistence.readiness import check_readiness
from safenestt.security.rate_limit import RateLimitService, RateLimitScope
from safenestt.security.approval import ApprovalService
from safenestt.security.api_keys import get_key_store
from safenestt.persistence.repositories import PersistentApprovalRepository
from safenestt.local_env import load_local_osint_env

# Local development only: load the user's explicitly designated OSINT env files.
load_local_osint_env()

logger = logging.getLogger(__name__)


def _validate_production_security() -> None:
    """Fail-closed: refuse to start in production without encryption key."""
    if os.getenv("MODE") == "production":
        if not is_encryption_enabled():
            raise RuntimeError(
                "FATAL: SAFENESTT_ENCRYPTION_KEY is not set or invalid. "
                "Refusing to start in production without encryption at rest."
            )


_validate_production_security()

app = FastAPI(title="SafeNestT AI Engine", version="0.1.0")
_rate_limiter = RateLimitService()


def _resolve_model_provider() -> ModelProvider | None:
    provider = os.getenv("MODEL_PROVIDER", "").lower()
    if not provider and os.getenv("OPENROUTER_API_KEY"):
        provider = "openrouter"
    elif not provider:
        provider = "ollama"

    if provider == "gemini":
        return GeminiProvider()
    if provider == "openrouter":
        return OpenRouterProvider()
    if provider in {"openai", "anthropic"}:
        return OpenAICompatibleProvider()
    if provider == "ollama":
        base_url = os.getenv("MODEL_BASE_URL", "http://localhost:11434/v1")
        default_model = os.getenv("MODEL_NAME", "qwen3:1.7b")
        return OllamaProvider(base_url=base_url, default_model=default_model)
    return None


class TargetObject(BaseModel):
    type: str
    value: str


class InvestigationCreateRequest(BaseModel):
    target: TargetObject
    investigation_type: str
    case_id: str | None = None


class InvestigationStartResponse(BaseModel):
    investigation_id: str
    status: str
    target: dict[str, Any]
    evidence: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    risk: dict[str, Any]
    model_provider: str | None
    model: str | None


def _record_to_dict(record: InvestigationRecord | EvidenceRecord | FindingRecord) -> dict[str, Any]:
    data = record.__dict__.copy()
    for key, value in data.items():
        if hasattr(value, "isoformat"):
            data[key] = value.isoformat()
    return data


def _to_api_error(code: str, message: str, status_code: int = 400) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _handle_tenant_isolation(exc: TenantIsolationError) -> HTTPException:
    return _to_api_error("tenant_access_denied", str(exc), 403)


def _enforce_rate_limit(request: Request, api_key_hash: str) -> None:
    """Enforce per-API-key rate limiting."""
    if request.method == "POST" and "/investigations" in request.url.path:
        result = _rate_limiter.enforce(
            scope=RateLimitScope.API_KEY,
            key=api_key_hash,
            limit=int(os.getenv("RATE_LIMIT_INVESTIGATIONS_PER_MINUTE", "10")),
            window_seconds=60,
        )
        if not result.allowed:
            raise _to_api_error("rate_limit_exceeded", f"Rate limit exceeded: {result.detail}", 429)
    
    if request.method == "POST" and "/start" in request.url.path:
        result = _rate_limiter.enforce(
            scope=RateLimitScope.API_KEY,
            key=f"{api_key_hash}:start",
            limit=int(os.getenv("RATE_LIMIT_START_PER_MINUTE", "30")),
            window_seconds=60,
        )
        if not result.allowed:
            raise _to_api_error("rate_limit_exceeded", f"Rate limit exceeded: {result.detail}", 429)


def get_api_context(request: Request) -> tuple[str, str]:
    """Authenticate and authorize API request.

    Returns: (tenant_id, key_fingerprint)

    key_fingerprint is SHA-256 of the raw API key — used for RLS session
    context and per-key rate limiting.
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise _to_api_error("missing_api_key", "X-API-Key header is required", 401)

    store = get_key_store()
    is_valid, tenant_id, key_fingerprint, metadata = store.validate_key(api_key)

    if is_valid:
        asserted_tenant = request.headers.get("X-SafeNestT-Tenant")
        assertion = request.headers.get("X-SafeNestT-Tenant-Signature")
        client_secret = os.getenv("SAFENESTT_CLIENT_SERVICE_SECRET")
        if asserted_tenant and assertion and client_secret:
            expected = hmac.new(client_secret.encode(), asserted_tenant.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, assertion):
                raise _to_api_error("tenant_assertion_invalid", "Invalid tenant assertion", 403)
            tenant_id = asserted_tenant
        return tenant_id, key_fingerprint

    error = metadata.get("error", "invalid_key")
    # ------------------------------------------------------------------
    # SAFE DIAGNOSTIC LOGGING (temporary, added 2026-10-04)
    #
    # Purpose: identify WHICH credential a failing caller is actually sending.
    # A Base44 cloud caller was returning 401 invalid_key while the same key
    # worked from the SafeNestT backend, so the mismatch had to be observed at
    # the point of rejection rather than inferred.
    #
    # SAFETY: this logs ONLY a SHA-256 fingerprint. The raw key is never
    # logged, never included in the error body, and never returned to the
    # caller. A SHA-256 of a high-entropy key is not a credential.
    #
    # Log fields: route, remote host, key length, key fingerprint prefix,
    # and the failure reason. Remove once the caller is identified.
    # ------------------------------------------------------------------
    try:
        import hashlib as _hashlib

        _fp = _hashlib.sha256(api_key.encode()).hexdigest()
        logger.warning(
            "hermes_auth_failed route=%s remote=%s key_present=%s key_len=%d "
            "key_fingerprint=%s reason=%s",
            request.url.path,
            (request.client.host if request.client else "unknown"),
            True,
            len(api_key),
            _fp[:16],
            error,
        )
    except Exception:  # diagnostics must never break auth
        pass

    if error == "key_revoked":
        raise _to_api_error("key_revoked", "This API key has been revoked", 401)
    elif error == "key_expired":
        raise _to_api_error("key_expired", "This API key has expired", 401)
    else:
        raise _to_api_error("invalid_key", "Invalid API key", 401)


@app.on_event("startup")
async def startup_event():
    """Initialize database schema on startup."""
    try:
        ensure_schema()
        logger.info("Database schema initialized")
    except Exception as exc:
        logger.warning("Could not initialize database schema: %s", exc)


@app.middleware("http")
async def enforce_https(request: Request, call_next):
    """Redirect HTTP to HTTPS in production."""
    if os.getenv("MODE") == "production":
        if request.url.scheme == "http":
            from starlette.responses import RedirectResponse
            url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(url), status_code=308)
    return await call_next(request)


# ---------------------------------------------------------------------
# READINESS (traffic gate) vs LIVENESS
#
#   /v1/health — the process is ALIVE. Does not consult the database and
#                does not fail because of database state. A load balancer
#                must keep the process in rotation while this returns 200.
#   /v1/ready  — the process is SAFE TO RECEIVE TRAFFIC. Requires the
#                database security state installed by
#                safenestt.persistence.migrate, because enabling RLS needs
#                table OWNERSHIP which the least-privilege application role
#                does not have. Returns 503 while any prerequisite is unmet.
#
# The readiness body is deliberately minimal: no database names, role names,
# hosts or policy details. Detail goes to structured logs.
# ---------------------------------------------------------------------


@app.get("/v1/ready", response_model=dict)
def ready(response: Response) -> dict[str, Any]:
    """Report whether this instance may accept traffic."""
    engine = get_engine()
    if engine is None:
        # No engine yet: not ready rather than guessing.
        response.status_code = 503
        return {"status": "not_ready", "unmet_prerequisites": 1}

    result = check_readiness(engine)
    if not result.ready:
        response.status_code = 503
    return result.public_body()


@app.get("/v1/health", response_model=dict)
def health() -> dict[str, Any]:
    provider = _resolve_model_provider()
    health_model = {"provider": "unconfigured", "model": "unavailable", "status": "unavailable"}
    if provider:
        health_model["provider"] = getattr(provider, "provider_name", "unconfigured")
        health_model["model"] = getattr(provider, "default_model", "unavailable")
        model_health = provider.health_check()
        health_model["status"] = "available" if model_health.error is None else "unavailable"
    return {
        "status": "ok",
        "model": health_model,
        "tools": {
            "dns.lookup": "available",
            "dns.reverse": "available",
        },
        "environment": {
            "api_version": "0.1.0",
            "mode": os.getenv("MODE", "development"),
            "encryption_at_rest": is_encryption_enabled(),
        },
    }


@app.post("/v1/investigations", response_model=dict)
def create_investigation(
    payload: InvestigationCreateRequest,
    request: Request,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    tenant_id, key_fingerprint = api_context
    _enforce_rate_limit(request, key_fingerprint)
    
    service = PersistentInvestigationStore(tenant_id=tenant_id, key_fingerprint=key_fingerprint)
    record = InvestigationRecord(
        investigation_id=__import__("uuid").uuid4().hex,
        tenant_id=tenant_id,
        created_by=None,
        target=payload.target.value,
        type=payload.investigation_type,
        status="QUEUED",
        case_id=payload.case_id,
    )
    service.create_investigation(record)
    response = _record_to_dict(record)
    response["target"] = {"type": payload.target.type, "value": payload.target.value}
    return response


@app.post("/v1/investigations/{investigation_id}/start", response_model=dict)
def start_investigation(
    investigation_id: str,
    request: Request,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    tenant_id, key_fingerprint = api_context
    _enforce_rate_limit(request, key_fingerprint)

    service = PersistentInvestigationStore(tenant_id=tenant_id, key_fingerprint=key_fingerprint)
    try:
        record = service.get_investigation(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    if record.status != "QUEUED":
        raise _to_api_error("invalid_state", f"investigation_already_{record.status.lower()}", 409)

    # Blocker 4 — long-running investigations.
    # The historical contract is synchronous: POST /start blocks until the
    # investigation reaches a terminal state and returns the full result.
    # Through a Cloudflare tunnel that exceeds the edge's ~100s budget and
    # returns 524 while the work continues server-side, so Base44 has no
    # reliable way to observe completion.
    #
    # Rather than change the default (which would break existing callers that
    # read the full result from the POST response), we add an OPT-IN
    # acknowledgement mode: `?wait=false` returns 202 with the investigation
    # already marked RUNNING and performs the work on a background thread.
    # Callers then poll GET /v1/investigations/{id}, which is already the
    # documented Base44 pattern. `?wait=true` (default) is unchanged.
    wait = request.query_params.get("wait", "true").lower() != "false"

    if not wait:
        record.mark("RUNNING")
        service.update_investigation(record)

        def _background() -> None:
            try:
                run_investigation(
                    investigation_id=investigation_id,
                    target=record.target or "",
                    tenant_id=record.tenant_id,
                    created_by=record.created_by,
                    case_id=record.case_id,
                    model_provider=_resolve_model_provider(),
                    store=service,
                )
            except Exception as exc:  # background work must still be visible
                logger.exception(
                    "background_investigation_failed investigation=%s error=%s",
                    investigation_id, type(exc).__name__,
                )
                try:
                    failed = service.get_investigation(investigation_id)
                    if failed:
                        failed.error = {
                            "code": "background_investigation_failed",
                            "message": str(exc)[:300],
                        }
                        failed.mark("FAILED")
                        service.update_investigation(failed)
                except Exception:
                    logger.exception(
                        "background_investigation_failure_record_failed "
                        "investigation=%s", investigation_id,
                    )

        threading.Thread(
            target=_background, name=f"inv-{investigation_id[:12]}", daemon=True
        ).start()
        return {
            "investigation_id": investigation_id,
            "status": "RUNNING",
            "accepted": True,
            "poll": f"/v1/investigations/{investigation_id}",
        }

    # Run the investigation synchronously (blocks until COMPLETED or FAILED).
    # Errors are recorded on the investigation record by run_investigation itself,
    # so we return the result directly.
    result = run_investigation(
        investigation_id=investigation_id,
        target=record.target or "",
        tenant_id=record.tenant_id,
        created_by=record.created_by,
        case_id=record.case_id,
        model_provider=_resolve_model_provider(),
        store=service,
    )
    return result


@app.get("/v1/investigations/{investigation_id}", response_model=dict)
def get_investigation(
    investigation_id: str,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    tenant_id, key_fingerprint = api_context
    service = PersistentInvestigationStore(tenant_id=tenant_id, key_fingerprint=key_fingerprint)
    try:
        record = service.get_investigation(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    evidence = service.list_evidence(investigation_id)
    findings = service.list_findings(investigation_id)
    agent_runs = service.list_agent_runs(investigation_id)
    return {
        **_record_to_dict(record),
        "evidence_count": len(evidence),
        "findings_count": len(findings),
        "agent_runs_count": len(agent_runs),
        "evidence": [_record_to_dict(item) for item in evidence],
        "findings": [_record_to_dict(item) for item in findings],
        "agent_runs": agent_runs,
    }


@app.get("/v1/investigations/{investigation_id}/evidence", response_model=list[dict[str, Any]])
def get_investigation_evidence(
    investigation_id: str,
    api_context: tuple = Depends(get_api_context),
) -> list[dict[str, Any]]:
    tenant_id, key_fingerprint = api_context
    service = PersistentInvestigationStore(tenant_id=tenant_id, key_fingerprint=key_fingerprint)
    try:
        evidence = service.list_evidence(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    return [_record_to_dict(item) for item in evidence]


@app.get("/v1/investigations/{investigation_id}/findings", response_model=list[dict[str, Any]])
def get_investigation_findings(
    investigation_id: str,
    api_context: tuple = Depends(get_api_context),
) -> list[dict[str, Any]]:
    tenant_id, key_fingerprint = api_context
    service = PersistentInvestigationStore(tenant_id=tenant_id, key_fingerprint=key_fingerprint)
    try:
        findings = service.list_findings(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    return [_record_to_dict(item) for item in findings]


@app.get("/v1/investigations/{investigation_id}/report", response_model=dict)
def get_investigation_report(
    investigation_id: str,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    tenant_id, key_fingerprint = api_context
    service = PersistentInvestigationStore(tenant_id=tenant_id, key_fingerprint=key_fingerprint)
    try:
        record = service.get_investigation(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    evidence = service.list_evidence(investigation_id)
    findings = service.list_findings(investigation_id)

    # Prefer the DURABLE report row when one exists. Previously this endpoint
    # ALWAYS rebuilt the dossier in memory from evidence+findings, so a 200
    # response proved nothing about persistence — a completely absent report
    # still produced a full dossier with a populated graph.
    #
    # Compatibility fallback: if no persisted report exists (investigations
    # run before report persistence existed, or an older record), we rebuild
    # from evidence+findings so the UI keeps working. The response always
    # states which path produced the payload via `report_source`, so a
    # reconstructed dossier can never be read as proof of persistence.
    persisted_report = None
    try:
        persisted_report = service.get_report(investigation_id)
    except Exception as report_err:
        # A failure to READ a report must not fabricate one silently.
        logger.warning(
            "persisted_report_read_failed investigation=%s error=%s",
            investigation_id, type(report_err).__name__,
        )

    graph_nodes = service.list_graph_nodes(investigation_id)
    graph_edges = service.list_graph_edges(investigation_id)

    intelligence_payload: dict[str, Any]
    if persisted_report and persisted_report.get("draft"):
        dossier = persisted_report["draft"]
        report_source = "persisted"
        intelligence_payload = {
            "dossier": dossier,
            "note": "dossier served from persisted reports row",
        }
    else:
        intelligence = build_dossier_intelligence(
            target=record.target or "",
            findings=[_record_to_dict(finding) for finding in findings],
            evidence=[_record_to_dict(item) for item in evidence],
        )
        dossier = intelligence["dossier"]
        report_source = "reconstructed"
        intelligence_payload = intelligence

    return {
        "investigation_id": investigation_id,
        "status": record.status,
        "target": record.target,
        "evidence_count": len(evidence),
        "finding_count": len(findings),
        "findings": [_record_to_dict(finding) for finding in findings],
        "evidence": [_record_to_dict(item) for item in evidence],
        "intelligence": intelligence_payload,
        "dossier": dossier,
        # Provenance of the payload above — callers MUST check this before
        # treating the dossier as proof that the investigation persisted.
        "report_source": report_source,
        "persisted_report": bool(persisted_report and persisted_report.get("draft")),
        "graph_nodes_persisted": len(graph_nodes),
        "graph_edges_persisted": len(graph_edges),
    }


# =============================================================================
# Approval Workflow Endpoints
# =============================================================================

_approval_service = ApprovalService(PersistentApprovalRepository())


@app.get("/v1/approvals", response_model=list[dict])
def list_pending_approvals(
    request: Request,
    api_context: tuple = Depends(get_api_context),
) -> list[dict[str, Any]]:
    """List pending approvals for the authenticated tenant."""
    tenant_id, _ = api_context
    pending = _approval_service.repository.list_pending(tenant_id=tenant_id)
    return [
        {
            "approval_id": p.approval_id,
            "agent_id": p.agent_id,
            "tool_id": p.tool_id,
            "action": p.action,
            "requested_capability": p.requested_capability,
            "risk_level": p.risk_level,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "expiration_at": p.expiration_at.isoformat() if p.expiration_at else None,
            "organization_id": p.organization_id,
        }
        for p in pending
    ]


@app.post("/v1/approvals/{approval_id}/decision", response_model=dict)
def record_approval_decision(
    approval_id: str,
    body: dict,
    request: Request,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    """Record an approve/deny decision for a pending approval.
    
    Body: {"approved": true/false, "approver_identity": "optional"}
    """
    tenant_id, _ = api_context
    approved = body.get("approved", False)
    approver_identity = body.get("approver_identity")
    
    record = _approval_service.record_decision(
        approval_id,
        approved,
        tenant_id=tenant_id,
        approver_identity=approver_identity,
    )
    
    if not record:
        raise _to_api_error("approval_not_found", "Approval not found or already decided", 404)
    
    return {
        "approval_id": record.approval_id,
        "status": record.status,
        "decided": True,
    }
