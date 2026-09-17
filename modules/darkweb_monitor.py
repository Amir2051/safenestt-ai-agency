"""Darkweb/paste monitoring for SafeNestT investigation engine.

Provides paste-site lookups via public index (Ahmia).
No API key required — uses public HTTP scraping only.

Tenant-agnostic: takes a query, returns results.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

# Optional JSON-file persistence (disabled by default; SafeNestT uses PostgreSQL)
ALERTS_DB = Path(os.getenv("ALERTS_DB", "/tmp/safenestt_alerts.json"))
MONITOR_DB = Path(os.getenv("MONITOR_DB", "/tmp/safenestt_monitors.json"))


def _load_db(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}
    return {}


def _save_db(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, default=str))


async def add_monitor_target(keyword: str, keyword_type: str, client_id: str) -> dict:
    db = _load_db(MONITOR_DB)
    if client_id not in db:
        db[client_id] = []
    target = {
        "keyword": keyword,
        "keyword_type": keyword_type,
        "active": True,
        "last_checked": None,
        "alert_count": 0,
    }
    db[client_id].append(target)
    _save_db(MONITOR_DB, db)
    return {"status": "added", "keyword": keyword, "client_id": client_id}


async def get_alerts(client_id: str) -> dict:
    db = _load_db(ALERTS_DB)
    return {"client_id": client_id, "alerts": db.get(client_id, [])}


async def _scan_keyword(keyword: str, keyword_type: str) -> list:
    """Run all scan types for a keyword."""
    results = []
    results.extend(await _scan_dehashed(keyword, keyword_type))
    results.extend(await _scan_paste_sites(keyword))
    return results


async def _scan_dehashed(keyword: str, keyword_type: str) -> list:
    """Search DeHashed breach database. Requires API key."""
    import os

    api_key = os.getenv("DEHASHED_API_KEY")
    email = os.getenv("DEHASHED_EMAIL")

    if not api_key or not email:
        return []  # Gracefully skip — no key configured

    import httpx

    results = []
    field = "email" if keyword_type == "email" else "username" if keyword_type == "username" else "domain"
    url = f"https://api.dehashed.com/search?query={field}:{keyword}"

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=15, auth=(email, api_key))
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("entries", []):
                    results.append({
                        "source": "DeHashed",
                        "type": "breach_record",
                        "keyword": keyword,
                        "email": entry.get("email"),
                        "username": entry.get("username"),
                        "database": entry.get("database_name"),
                        "found_at": datetime.utcnow().isoformat(),
                        "severity": "HIGH",
                    })
        except Exception:
            pass

    return results


async def _scan_paste_sites(keyword: str) -> list:
    """Search indexed paste sites via Ahmia (public, no key)."""
    try:
        import httpx2 as httpx
    except ImportError:
        import httpx

    results = []
    url = f"https://ahmia.fi/search/?q={keyword}"

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=15, follow_redirects=True)
            if resp.status_code == 200 and keyword.lower() in resp.text.lower():
                results.append({
                    "source": "Ahmia",
                    "type": "indexed_reference",
                    "keyword": keyword,
                    "url": url,
                    "found_at": datetime.utcnow().isoformat(),
                    "severity": "MEDIUM",
                })
        except Exception:
            pass

    return results


async def _store_alerts(client_id: str, keyword: str, findings: list):
    db = _load_db(ALERTS_DB)
    if client_id not in db:
        db[client_id] = []
    for finding in findings:
        alert = {
            "alert_id": f"ALT-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
            "client_id": client_id,
            "keyword": keyword,
            "finding": finding,
            "created_at": datetime.utcnow().isoformat(),
            "read": False,
            "severity": finding.get("severity", "MEDIUM"),
        }
        db[client_id].append(alert)
    _save_db(ALERTS_DB, db)


async def run_scheduled_scan():
    monitor_db = _load_db(MONITOR_DB)
    for client_id, targets in monitor_db.items():
        for target in targets:
            if not target.get("active"):
                continue
            findings = await _scan_keyword(target["keyword"], target["keyword_type"])
            if findings:
                await _store_alerts(client_id, target["keyword"], findings)
                target["alert_count"] += len(findings)
            target["last_checked"] = datetime.utcnow().isoformat()
    _save_db(MONITOR_DB, monitor_db)


# Synchronous wrappers for non-async callers


def scan_paste_sites_sync(keyword: str) -> list:
    """Synchronous wrapper for _scan_paste_sites."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_scan_paste_sites(keyword))
    else:
        # Already in an async context — return empty to avoid event-loop deadlock
        return []


def scan_dehashed_sync(keyword: str, keyword_type: str = "email") -> list:
    """Synchronous wrapper for _scan_dehashed."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_scan_dehashed(keyword, keyword_type))
    else:
        return []
