import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safenestt.local_env import load_local_osint_env
from safenestt.model.registry import OpenAICompatibleProvider
from safenestt.model.provider import ModelRequest
import os

load_local_osint_env()
provider = OpenAICompatibleProvider(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
    default_model=os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3.5-lightning:free"),
)
response = provider.generate(ModelRequest(prompt="Return only OK", model=provider.default_model, max_tokens=8))
print({
    "key_loaded": bool(provider.api_key),
    "provider": response.provider,
    "model": response.model,
    "status": "ok" if response.error is None else "error",
    "error_code": response.error.code if response.error else None,
})
