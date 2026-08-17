from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any
import os

from safenestt.investigations.investigator import run_investigation
from safenestt.investigations.records import EvidenceRecord, FindingRecord, InvestigationRecord
from safenestt.investigations.store import InvestigationService
from safenestt.model.registry import GeminiProvider, ModelProvider, OllamaProvider, OpenAICompatibleProvider

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


class InvestigationCreateRequest(BaseModel):
    target: str
    tenant_id: str | None = None
    created_by: str | None = None
    type: str = "domain"


class InvestigationStartResponse(BaseModel):
    investigation_id: str
    status: str
    target: str
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


@app.post("/investigations", response_model=dict)
def create_investigation(payload: InvestigationCreateRequest) -> dict[str, Any]:
    record = service.create(investigation_id=__import__("uuid").uuid4().hex, target=payload.target, tenant_id=payload.tenant_id, created_by=payload.created_by, type=payload.type)
    return _record_to_dict(record)


@app.post("/investigations/{investigation_id}/start", response_model=dict)
def start_investigation(investigation_id: str) -> dict[str, Any]:
    record = service.get_investigation(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="investigation_not_found")
    result = run_investigation(target=record.target, tenant_id=record.tenant_id, created_by=record.created_by)
    return result


@app.get("/investigations/{investigation_id}", response_model=dict)
def get_investigation(investigation_id: str) -> dict[str, Any]:
    record = service.get_investigation(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="investigation_not_found")
    return _record_to_dict(record)


@app.get("/investigations/{investigation_id}/evidence", response_model=list[dict[str, Any]])
def get_investigation_evidence(investigation_id: str) -> list[dict[str, Any]]:
    if not service.get_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="investigation_not_found")
    return [_record_to_dict(item) for item in service.list_evidence(investigation_id)]


@app.get("/investigations/{investigation_id}/findings", response_model=list[dict[str, Any]])
def get_investigation_findings(investigation_id: str) -> list[dict[str, Any]]:
    if not service.get_investigation(investigation_id):
        raise HTTPException(status_code=404, detail="investigation_not_found")
    return [_record_to_dict(item) for item in service.list_findings(investigation_id)]
