"""Authoritative JSON-safe normalization for investigation persistence.

WHY THIS EXISTS
---------------
Several investigation payloads (notably the report dossier) are assembled from
dataclass `__dict__` values and ORM rows. Those carry Python-native types that
the PostgreSQL `json`/`jsonb` columns reject at bind time:

    TypeError: Object of type datetime is not JSON serializable

That failure previously sat *behind* an earlier defect in the same code path, so
it was never reached. Rather than scattering `str(...)` calls across the
report generator (which would corrupt meaning and lose structure), every value
crossing into a JSON column goes through `json_safe()` here.

SEMANTIC CONTRACTS
------------------
- datetime / date / time -> ISO-8601 string (lossless, round-trippable)
- UUID -> canonical str
- Enum -> its `.value` (preserves the semantic payload, not repr())
- set / frozenset / tuple -> list (order preserved where ordered)
- Decimal -> str (exact, no float rounding)
- bytes -> base64 ASCII (no binary ever reaches a JSON column raw)
- dict -> new dict with string keys, values normalized
- list -> new list, elements normalized
- None / bool / int / float / str -> unchanged

WHAT IT REFUSES TO DO
---------------------
It does NOT stringify arbitrary objects. An unsupported type raises
`JSONSerializationError` naming the offending type and path, so persistence
fails explicitly instead of silently writing `<object at 0x...>` into a report
that later reads as if it were real data.

ENCRYPTION
----------
This module performs NO encryption and NO decryption. Callers apply
`encrypt_value()`/`decrypt_value()` around the normalized value exactly as
before; normalization happens strictly inside the plaintext domain so the
ciphertext boundary is unchanged.
"""
from __future__ import annotations

import base64
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

__all__ = ["JSONSerializationError", "json_safe", "json_safe_text"]


class JSONSerializationError(TypeError):
    """Raised when a value cannot be represented in JSON without losing meaning.

    Subclasses TypeError so existing `except TypeError` handling around JSON
    binding keeps working, while giving callers a precise, greppable type.
    """

    def __init__(self, value: Any, path: str = "$") -> None:
        self.value_type = type(value).__name__
        self.path = path
        super().__init__(
            f"cannot serialize {self.value_type} at {path} to JSON "
            f"without losing meaning"
        )


def json_safe(value: Any, *, path: str = "$", _depth: int = 0) -> Any:
    """Return a JSON-native copy of `value`, or raise JSONSerializationError.

    Recursion is depth-bounded so a self-referential structure fails loudly
    instead of exhausting the stack.
    """
    if _depth > 100:
        raise JSONSerializationError(value, path)

    # Primitives pass through untouched.
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    # Temporal types -> ISO-8601. Checked before the generic `__dict__` path.
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, Enum):
        return json_safe(value.value, path=f"{path}.value", _depth=_depth + 1)

    if isinstance(value, Decimal):
        # str() is exact; float() would lose precision.
        return str(value)

    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            # Non-string keys (e.g. int, tuple, Enum) are normalized too, so a
            # dict keyed by UUID or int does not silently collide.
            norm_key = key if isinstance(key, str) else str(
                json_safe(key, path=f"{path}.<key>", _depth=_depth + 1)
            )
            out[norm_key] = json_safe(item, path=f"{path}.{norm_key}", _depth=_depth + 1)
        return out

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            json_safe(item, path=f"{path}[{i}]", _depth=_depth + 1)
            for i, item in enumerate(value)
        ]

    # Dataclasses and ORM-ish objects: use their declared field dict if they
    # expose one, but ONLY after the explicit types above have been handled.
    as_dict = getattr(value, "__dict__", None)
    if isinstance(as_dict, dict) and as_dict:
        return json_safe(as_dict, path=path, _depth=_depth + 1)

    # Anything else is refused rather than stringified.
    raise JSONSerializationError(value, path)


def json_safe_text(value: Any) -> str:
    """`json_safe` followed by `json.dumps`. Raises on unsupported types.

    Provided so callers that need the serialized text (log lines, audit
    details) go through the same normalization boundary as persistence.
    """
    import json

    return json.dumps(json_safe(value), ensure_ascii=False, sort_keys=False)