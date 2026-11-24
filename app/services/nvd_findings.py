"""Normalize and bound NVD evidence for both V2 inventories."""

import json
from datetime import UTC, datetime
from uuid import uuid4

from app.core.errors import APIError
from app.services.applicability import encoded, evidence_for


def _severity(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values and isinstance(values[0], dict):
            data = values[0].get("cvssData", {})
            severity = (data.get("baseSeverity") if isinstance(data, dict) else None) or values[
                0
            ].get("baseSeverity")
            if isinstance(severity, str):
                normalized = severity.casefold()
                if normalized in {"critical", "high", "medium", "low", "none"}:
                    return normalized
    return "unknown"


def _contains_nul(value):
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_contains_nul(key) or _contains_nul(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_nul(item) for item in value)
    return False


def nvd_date(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=parsed.tzinfo or UTC)


def finding_rows(page, cpe, observed_version):
    page_cves = [
        entry.cve.model_dump(mode="json", exclude_unset=True) for entry in page.vulnerabilities
    ]
    warnings = []
    rows = []
    for record in page_cves:
        if _contains_nul(record):
            raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE NVD no válida")
        applicability, evidence = evidence_for(cpe, observed_version, record)
        if evidence.get("truncated"):
            warnings.append("EVIDENCE_BUDGET_REACHED")
        descriptions = record.get("descriptions", [])
        title = next((item.get("value") for item in descriptions if item.get("lang") == "en"), None)
        if isinstance(title, str):
            normalized_title = " ".join(title.split())
            if len(normalized_title) > 500:
                warnings.append("TITLE_TRUNCATED")
            # Display title is bounded; evidence_for retains original descriptions.
            title = normalized_title[:500].rstrip()
        else:
            title = None
        metrics = record.get("metrics") or None
        if metrics and len(encoded(metrics)) > 24000:
            warnings.append("METRICS_OMITTED")
            metrics = None
        rows.append(
            {
                "id": uuid4(),
                "external_id": record["id"],
                "title": title or None,
                "severity": _severity(record.get("metrics") or {}),
                "cvss": json.dumps(metrics) if metrics else None,
                "applicability": applicability,
                "evidence": json.dumps(evidence),
                "published": nvd_date(record["published"]),
                "modified": nvd_date(record["lastModified"]),
            }
        )
    return page_cves, rows, warnings
