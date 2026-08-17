from __future__ import annotations

from typing import Any

from safenestt.investigations.records import FindingRecord


def calculate_risk(findings: list[FindingRecord]) -> dict[str, Any]:
    if not findings:
        return {"score": 0.0, "level": "LOW", "factors": {"finding_count": 0}}
    supported = [finding for finding in findings if finding.reality_status == "EVIDENCE_SUPPORTED"]
    unsupported = [finding for finding in findings if finding.reality_status != "EVIDENCE_SUPPORTED"]
    score = min(1.0, (len(supported) * 0.3) + (len(unsupported) * 0.1))
    level = "LOW"
    if score >= 0.75:
        level = "CRITICAL"
    elif score >= 0.5:
        level = "HIGH"
    elif score >= 0.25:
        level = "MEDIUM"
    return {
        "score": round(score, 2),
        "level": level,
        "factors": {
            "finding_count": len(findings),
            "supported": len(supported),
            "unsupported": len(unsupported),
        },
    }
