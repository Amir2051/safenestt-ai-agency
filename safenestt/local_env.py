from __future__ import annotations

import os
from pathlib import Path

RAW_FILE_MAP = {
    "/home/ronzoro/openrouter.env": "OPENROUTER_API_KEY",
    "/home/ronzoro/abuse.env": "ABUSEIPDB_API_KEY",
    "/home/ronzoro/censys.token.env": "CENSYS_API_TOKEN",
    "/home/ronzoro/deehashed.env": "DEHASHED_API_KEY",
    "/home/ronzoro/fireclaw.env": "FIRECRAWL_API_KEY",
    "/home/ronzoro/hunter-io.env": "HUNTER_API_KEY",
    "/home/ronzoro/emai;osint.env": "EMAIL_OSINT_API_KEY",
    "/home/ronzoro/Downloads/urlscan.env": "URLSCAN_API_KEY",
}

DEFAULT_FILES = [
    "/home/ronzoro/openrouter.env",
    "/home/ronzoro/safenest-ai.env",
    "/home/ronzoro/abuse.env",
    "/home/ronzoro/censys.token.env",
    "/home/ronzoro/deehashed.env",
    "/home/ronzoro/etherscan.env",
    "/home/ronzoro/fireclaw.env",
    "/home/ronzoro/hunter-io.env",
    "/home/ronzoro/emai;osint.env",
    "/home/ronzoro/Downloads/urlscan.env",
]


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[7:].lstrip()
    if "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    if not key or not (key[0].isalpha() or key[0] == "_"):
        return None
    if any(not (c.isalnum() or c == "_") for c in key):
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return key, value


def load_local_osint_env() -> list[str]:
    """Load explicitly configured local OSINT env files without logging values."""
    if os.getenv("MODE", "development").lower() == "production":
        return []
    if os.getenv("SAFENESTT_LOAD_LOCAL_OSINT_ENV", "1").lower() in {"0", "false", "no"}:
        return []
    raw_paths = os.getenv("SAFENESTT_OSINT_ENV_FILES", "")
    paths = [p.strip() for p in raw_paths.split(":") if p.strip()] if raw_paths else DEFAULT_FILES
    loaded: list[str] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            parsed_any = False
            for line in text.splitlines():
                parsed = _parse_line(line)
                if not parsed:
                    continue
                key, value = parsed
                parsed_any = True
                if value and not os.getenv(key):
                    os.environ[key] = value
            if not parsed_any and raw_path in RAW_FILE_MAP:
                value = text.strip()
                if value and not os.getenv(RAW_FILE_MAP[raw_path]):
                    os.environ[RAW_FILE_MAP[raw_path]] = value
            loaded.append(str(path))
        except OSError:
            continue
    return loaded
