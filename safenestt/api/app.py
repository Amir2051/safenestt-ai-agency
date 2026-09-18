from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
import hashlib
import hmac
from typing import Any
import os
import logging

from safenestt.investigations.investigator import run_investigation
from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.store import (
    PersistentInvestigationStore,
    TenantIsolationError,
    ensure_schema,
)
from safenestt.model.registry import GeminiProvider, ModelProvider, OllamaProvider, OpenAICompatibleProvider
from safenestt.security.encryption import is_encryption_enabled
from safenestt.security.rate_limit import RateLimitService, RateLimitScope
from safenestt.security.api_keys import get_key_store
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
    
    Returns: (api_key_hash, tenant_id)
    
    All keys must be registered in PostgreSQL. No fallback to raw-key-as-tenant.
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
def create_investigation(
    payload: InvestigationCreateRequest,
    request: Request,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    api_key_hash, tenant_id = api_context
    _enforce_rate_limit(request, api_key_hash)
    
    service = PersistentInvestigationStore(api_key_hash=api_key_hash)
    record = InvestigationRecord(
        investigation_id=__import__("uuid").uuid4().hex,
        tenant_id=tenant_id,
        created_by=None,
        target=payload.target.value,
        type=payload.investigation_type,
        status="QUEUED",
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
    api_key_hash, tenant_id = api_context
    _enforce_rate_limit(request, api_key_hash)
    
    service = PersistentInvestigationStore(api_key_hash=api_key_hash)
    try:
        record = service.get_investigation(investigation_id)
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
        service.update_investigation(record)
        raise _to_api_error("investigation_failed", str(exc), 500)
    if result.get("status") == "FAILED":
        return result
    return result


@app.get("/v1/investigations/{investigation_id}", response_model=dict)
def get_investigation(
    investigation_id: str,
    api_context: tuple = Depends(get_api_context),
) -> dict[str, Any]:
    api_key_hash, tenant_id = api_context
    service = PersistentInvestigationStore(api_key_hash=api_key_hash)
    try:
        record = service.get_investigation(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    return _record_to_dict(record)


@app.get("/v1/investigations/{investigation_id}/evidence", response_model=list[dict[str, Any]])
def get_investigation_evidence(
    investigation_id: str,
    api_context: tuple = Depends(get_api_context),
) -> list[dict[str, Any]]:
    api_key_hash, tenant_id = api_context
    service = PersistentInvestigationStore(api_key_hash=api_key_hash)
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
    api_key_hash, tenant_id = api_context
    service = PersistentInvestigationStore(api_key_hash=api_key_hash)
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
    api_key_hash, tenant_id = api_context
    service = PersistentInvestigationStore(api_key_hash=api_key_hash)
    try:
        record = service.get_investigation(investigation_id)
    except TenantIsolationError as exc:
        raise _handle_tenant_isolation(exc)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    evidence = service.list_evidence(investigation_id)
    findings = service.list_findings(investigation_id)
    return {
        "investigation_id": investigation_id,
        "status": record.status,
        "target": record.target,
        "evidence_count": len(evidence),
        "finding_count": len(findings),
        "findings": [_record_to_dict(finding) for finding in findings],
        "evidence": [_record_to_dict(item) for item in evidence],
    }
