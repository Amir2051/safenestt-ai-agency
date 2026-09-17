from fastapi import FastAPI, HTTPException, Request, Query
from pydantic import BaseModel, Field, validator
from typing import Any, Annotated
import os
import time
import logging

from safenestt.investigations.investigator import run_investigation
from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.store import InvestigationService, TenantIsolationError
from safenestt.model.registry import GeminiProvider, ModelProvider, OllamaProvider, OpenAICompatibleProvider
from safenestt.security.encryption import is_encryption_enabled
from safenestt.security.rate_limit import RateLimitService, RateLimitScope

logger = logging.getLogger(__name__)

app = FastAPI(title="SafeNestT AI Engine", version="0.1.0")
_service_instance: InvestigationService | None = None
_rate_limiter = RateLimitService()


def _get_service() -> InvestigationService:
    global _service_instance
    if _service_instance is None:
        _service_instance = InvestigationService()
    return _service_instance


def _resolve_model_provider() -> ModelProvider | None:
    provider = os.getenv("MODEL_PROVIDER", "").lower()
    if not provider and os.getenv("OPENROUTER_API_KEY"):
        provider = "openrouter"
    elif not provider:
        provider = "ollama"

    if provider == "gemini":
        return GeminiProvider()
    if provider == "openrouter":
        api_key = os.getenv("OPENROUTER_API_KEY")
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        default_model = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3.5-lightning:free")
        return OpenAICompatibleProvider(api_key=api_key, base_url=base_url, default_model=default_model)
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
    tenant_id: str = Field(..., min_length=1, description="Tenant identifier is required")

    @validator("tenant_id")
    def validate_tenant_id(cls, v):
        if not v or not v.strip():
            raise ValueError("tenant_id is required and cannot be empty")
        return v.strip()


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


def _enforce_rate_limit(request: Request, tenant_id: str) -> None:
    """Enforce per-tenant rate limiting."""
    # Limit: 10 requests per minute per tenant for investigation creation
    if request.method == "POST" and "/investigations" in request.url.path:
        result = _rate_limiter.enforce(
            scope=RateLimitScope.ORGANIZATION,
            key=tenant_id,
            limit=int(os.getenv("RATE_LIMIT_INVESTIGATIONS_PER_MINUTE", "10")),
            window_seconds=60,
        )
        if not result.allowed:
            raise _to_api_error("rate_limit_exceeded", f"Rate limit exceeded: {result.detail}", 429)
    
    # Limit: 30 requests per minute per tenant for OpenRouter-backed endpoints (investigation start)
    if request.method == "POST" and "/start" in request.url.path:
        result = _rate_limiter.enforce(
            scope=RateLimitScope.ORGANIZATION,
            key=f"{tenant_id}:start",
            limit=int(os.getenv("RATE_LIMIT_START_PER_MINUTE", "30")),
            window_seconds=60,
        )
        if not result.allowed:
            raise _to_api_error("rate_limit_exceeded", f"Rate limit exceeded: {result.detail}", 429)


@app.middleware("http")
async def enforce_https(request: Request, call_next):
    """Redirect HTTP to HTTPS in production."""
    if os.getenv("MODE") == "production":
        if request.url.scheme == "http":
            from starlette.responses import RedirectResponse
            url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(url), status_code=308)
    return await call_next(request)


@app.get("/v1/health")
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
def create_investigation(payload: InvestigationCreateRequest, request: Request) -> dict[str, Any]:
    _enforce_rate_limit(request, payload.tenant_id)
    service = _get_service()
    record = service.create(
        investigation_id=__import__("uuid").uuid4().hex,
        target=payload.target.value,
        tenant_id=payload.tenant_id,
        created_by=None,
        type=payload.investigation_type,
    )
    response = _record_to_dict(record)
    response["target"] = {"type": payload.target.type, "value": payload.target.value}
    return response


@app.post("/v1/investigations/{investigation_id}/start", response_model=dict)
def start_investigation(investigation_id: str, request: Request, tenant_id: Annotated[str, Query(..., min_length=1)] = ...) -> dict[str, Any]:
    _enforce_rate_limit(request, tenant_id)
    service = _get_service()
    try:
        record = service.get_investigation(investigation_id, tenant_id=tenant_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    if record.status != "QUEUED":
        raise _to_api_error("invalid_state", f"investigation_already_{record.status.lower()}", 409)
    try:
        result = run_investigation(
            investigation_id=investigation_id,
            target=record.target or "",
            tenant_id=record.tenant_id,
            created_by=record.created_by,
            model_provider=_resolve_model_provider(),
            store=service,
        )
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    except Exception as exc:
        service.fail(investigation_id, tenant_id=tenant_id)
        raise _to_api_error("investigation_failed", str(exc), 500)
    if result.get("status") == "FAILED":
        raise _to_api_error(result.get("error", {}).get("code", "investigation_failed"), result.get("error", {}).get("message", "investigation_failed"), 500)
    return result


@app.get("/v1/investigations/{investigation_id}", response_model=dict)
def get_investigation(investigation_id: str, tenant_id: Annotated[str, Query(..., min_length=1)] = ...) -> dict[str, Any]:
    service = _get_service()
    try:
        record = service.get_investigation(investigation_id, tenant_id=tenant_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    return _record_to_dict(record)


@app.get("/v1/investigations/{investigation_id}/evidence", response_model=list[dict[str, Any]])
def get_investigation_evidence(investigation_id: str, tenant_id: Annotated[str, Query(..., min_length=1)] = ...) -> list[dict[str, Any]]:
    service = _get_service()
    try:
        evidence = service.list_evidence(investigation_id, tenant_id=tenant_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    return [_record_to_dict(item) for item in evidence]


@app.get("/v1/investigations/{investigation_id}/findings", response_model=list[dict[str, Any]])
def get_investigation_findings(investigation_id: str, tenant_id: Annotated[str, Query(..., min_length=1)] = ...) -> list[dict[str, Any]]:
    service = _get_service()
    try:
        findings = service.list_findings(investigation_id, tenant_id=tenant_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    return [_record_to_dict(item) for item in findings]


@app.get("/v1/investigations/{investigation_id}/report", response_model=dict)
def get_investigation_report(investigation_id: str, tenant_id: Annotated[str, Query(..., min_length=1)] = ...) -> dict[str, Any]:
    service = _get_service()
    try:
        record = service.get_investigation(investigation_id, tenant_id=tenant_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    evidence = service.list_evidence(investigation_id, tenant_id=tenant_id)
    findings = service.list_findings(investigation_id, tenant_id=tenant_id)
    return {
        "investigation_id": investigation_id,
        "status": record.status,
        "target": record.target,
        "evidence_count": len(evidence),
        "finding_count": len(findings),
        "findings": [_record_to_dict(finding) for finding in findings],
        "evidence": [_record_to_dict(item) for item in evidence],
    }
