from __future__ import annotations

import re
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|apikey)"),
    re.compile(r"(?i)(password|passwd|pwd)"),
    re.compile(r"(?i)(secret|token|refresh_token|access_token)"),
    re.compile(r"(?i)(authorization|bearer)"),
    re.compile(r"(?i)(private_key|client_secret)"),
]


def _looks_secret(value: str) -> bool:
    for pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return True
    return False


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, val in value.items():
            if _looks_secret(key):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(val)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        if _looks_secret(value):
            return "[REDACTED]"
    return value
