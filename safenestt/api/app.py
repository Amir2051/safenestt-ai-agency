from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any
import os

from safenestt.investigations.investigator import run_investigation
from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.store import InvestigationService
from safenestt.model.registry import GeminiProvider, ModelProvider, OllamaProvider, OpenAICompatibleProvider
from safenestt.tools.dns import dns_lookup_manifest, dns_reverse_manifest

app = FastAPI(title="SafeNestT AI Engine", version="0.1.0")
service = InvestigationService()


def _resolve_model_provider() -> ModelProvider | None:
    provider = os.getenv("MODEL_PROVIDER", "ollama").lower()
    if provider == "gemini":
        return GeminiProvider()
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
        },
    }


@app.post("/v1/investigations", response_model=dict)
def create_investigation(payload: InvestigationCreateRequest) -> dict[str, Any]:
    record = service.create(investigation_id=__import__("uuid").uuid4().hex, target=payload.target.value, tenant_id=None, created_by=None, type=payload.investigation_type)
    response = _record_to_dict(record)
    response["target"] = {"type": payload.target.type, "value": payload.target.value}
    return response


@app.post("/v1/investigations/{investigation_id}/start", response_model=dict)
def start_investigation(investigation_id: str) -> dict[str, Any]:
    record = service.get_investigation(investigation_id)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    if record.status != "QUEUED":
        raise _to_api_error("invalid_state", f"investigation_already_{record.status.lower()}", 409)
    try:
        result = run_investigation(investigation_id=investigation_id, target=record.target, tenant_id=record.tenant_id, created_by=record.created_by, model_provider=_resolve_model_provider(), store=service)
    except Exception as exc:  # pragma: no cover - defensive guard
        service.fail(investigation_id)
        raise _to_api_error("investigation_failed", str(exc), 500)
    if result.get("status") == "FAILED":
        raise _to_api_error(result.get("error", {}).get("code", "investigation_failed"), result.get("error", {}).get("message", "investigation_failed"), 500)
    return result


@app.get("/v1/investigations/{investigation_id}", response_model=dict)
def get_investigation(investigation_id: str) -> dict[str, Any]:
    record = service.get_investigation(investigation_id)
    if not record:
        raise _to_api_error("not_found", "investigation_not_found", 404)
    return _record_to_dict(record)


@app.get("/v1/investigations/{investigation_id}/evidence", response_model=list[dict[str, Any]])
def get_investigation_evidence(investigation_id: str) -> list[dict[str, Any]]:
    if not service.get_investigation(investigation_id):
        raise _to_api_error("not_found", "investigation_not_found", 404)
    return [_record_to_dict(item) for item in service.list_evidence(investigation_id)]


@app.get("/v1/investigations/{investigation_id}/findings", response_model=list[dict[str, Any]])
def get_investigation_findings(investigation_id: str) -> list[dict[str, Any]]:
    if not service.get_investigation(investigation_id):
        raise _to_api_error("not_found", "investigation_not_found", 404)
    return [_record_to_dict(item) for item in service.list_findings(investigation_id)]


@app.get("/v1/investigations/{investigation_id}/report", response_model=dict)
def get_investigation_report(investigation_id: str) -> dict[str, Any]:
    record = service.get_investigation(investigation_id)
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
