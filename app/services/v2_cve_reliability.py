"""V2 query snapshots, bounded lazy recovery and independent freshness dimensions."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import text

from app.core.errors import APIError


def recover(session):
    session.execute(text("SELECT vulntrack.recover_cve_runs()"))


def source_kind(client):
    if getattr(client, "transport", None) is not None:
        return "fixture" if getattr(client, "source_kind", None) == "fixture" else "simulated"
    return "live" if getattr(client, "live", False) is True else "unknown"


def context(request, *, identification_id, cpe_mode, cpe_source, vendor, product, version):
    return {
        "contract": "v2-cve-5a-1",
        "cve_source": source_kind(request.app.state.cve),
        "identification_id": str(identification_id) if identification_id else None,
        "cpe_mode": cpe_mode,
        "cpe_source": cpe_source,
        "observed_vendor": vendor,
        "observed_product": product,
        "observed_version": version,
    }


def require_active(session, kind, workspace, run):
    table = {
        "applications": "vulntrack.application_analysis_runs",
        "devices": "vulntrack_devices.runs",
    }[kind]
    row = (
        session.execute(
            text(f"""SELECT status,lease_expires_at>clock_timestamp() AS alive
        FROM {table} WHERE workspace_id=:workspace AND id=:run FOR UPDATE"""),
            {"workspace": workspace, "run": run},
        )
        .mappings()
        .first()
    )
    if row is None or row["status"] != "running" or not row["alive"]:
        raise APIError(409, "ANALYSIS_INTERRUPTED", "La consulta dejó de estar activa")


def as_date(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.replace(tzinfo=value.tzinfo or UTC) if value else None


def decorate(session, settings, kind, rows):
    """One bounded query for the current identities of a page; no catalogue or network."""
    if not rows:
        return []
    rows = [dict(r) for r in rows]
    key = "technology_id" if kind == "applications" else "device_id"
    ids = list({UUID(str(r[key])) for r in rows if r.get(key)})
    if kind == "applications":
        sql = """SELECT t.id,t.vendor,t.product,t.version,t.selected_cpe,
            c.id AS identification_id FROM vulntrack.technologies t
            LEFT JOIN LATERAL (SELECT id FROM vulntrack_technology_cpe.confirmations
                WHERE workspace_id=t.workspace_id AND technology_id=t.id
                ORDER BY event_number DESC LIMIT 1) c ON true
            WHERE t.id=ANY(CAST(:ids AS uuid[]))"""
    else:
        sql = """SELECT d.id,d.product_vendor AS vendor,d.product,d.version,
            i.cpe_name AS selected_cpe,i.id AS identification_id FROM vulntrack_devices.devices d
            LEFT JOIN LATERAL (SELECT id,cpe_name FROM vulntrack_devices.identifications
                WHERE workspace_id=d.workspace_id AND device_id=d.id
                  AND identity_generation=d.identity_generation
                ORDER BY created_at DESC,id DESC LIMIT 1) i ON true
            WHERE d.id=ANY(CAST(:ids AS uuid[]))"""
    current = {str(r["id"]): r for r in session.execute(text(sql), {"ids": ids}).mappings()}
    now = datetime.now(UTC)
    for r in rows:
        saved = r.pop("run_context", None)
        r.pop("lease_expires_at", None)
        received = as_date(r.get("response_received_at"))
        source = (
            saved["cve_source"]
            if saved
            else ("fixture" if r.get("nvd_mode", r.get("mode")) == "fixture" else "unknown")
        )
        # Legacy source labels are retained, but not promoted to proven live transport.
        provenance = {
            "cve_source": source,
            "contract": saved.get("contract") if saved else None,
            "identification_id": saved.get("identification_id")
            if saved
            else r.get("identification_id"),
            "cpe_mode": saved.get("cpe_mode") if saved else None,
            "cpe_source": saved.get("cpe_source") if saved else None,
            "observed_version": saved.get("observed_version")
            if saved
            else r.get("observed_version"),
            "requested_at": r.get("created_at"),
            "response_received_at": received,
            "source_timestamp": r.get("source_timestamp"),
        }
        actual = current.get(str(r.get(key)))
        correspondence = "unknown"
        if actual:
            if r["selected_cpe"] != actual["selected_cpe"]:
                correspondence = "historical"
            elif saved:
                matching = (
                    saved["identification_id"] is not None
                    and saved["identification_id"] == str(actual["identification_id"])
                    and saved["observed_version"] == actual["version"]
                    and saved["observed_product"] == actual["product"]
                    and saved["observed_vendor"] == actual["vendor"]
                )
                correspondence = "current" if matching else "historical"
                if saved["identification_id"] is None and (
                    saved["observed_version"] == actual["version"]
                    and saved["observed_product"] == actual["product"]
                    and saved["observed_vendor"] == actual["vendor"]
                ):
                    correspondence = "unknown"
            elif kind == "devices":
                correspondence = (
                    "current"
                    if (
                        str(r["identification_id"]) == str(actual["identification_id"])
                        and r.get("observed_version") == actual["version"]
                    )
                    else "historical"
                )
        expires = received + timedelta(seconds=settings.cve_freshness_seconds) if received else None
        freshness = (
            "unknown" if not received or received > now else ("fresh" if now < expires else "stale")
        )
        coverage = r.get("coverage") or "unknown"
        if kind == "devices":
            r["is_current_technology"] = correspondence == "current"
        r["assessment"] = {
            "execution": r["status"],
            "coverage": coverage,
            "freshness": freshness,
            "correspondence": correspondence,
            "requires_new_query": not (
                r["status"] == "completed"
                and coverage == "complete"
                and freshness == "fresh"
                and correspondence == "current"
            ),
            "expires_at": expires,
            "freshness_policy_seconds": settings.cve_freshness_seconds,
        }
        r["provenance"] = provenance
    return rows


def query_state_sql(kind, alias):
    """Trusted aliases only; a compact summary on the inventory page, never N+1 HTTP."""
    if kind == "devices":
        predicate = f"""r.workspace_id={alias}.workspace_id AND r.device_id={alias}.id
            AND r.identification_id=(SELECT i.id FROM vulntrack_devices.identifications i
              WHERE i.workspace_id={alias}.workspace_id AND i.device_id={alias}.id
                AND i.identity_generation={alias}.identity_generation
              ORDER BY i.created_at DESC,i.id DESC LIMIT 1)"""
        table = "vulntrack_devices.runs"
    else:
        predicate = f"""r.workspace_id={alias}.workspace_id AND r.technology_id={alias}.id
            AND r.selected_cpe={alias}.selected_cpe
            AND r.run_context->>'observed_version'={alias}.version
            AND r.run_context->>'identification_id'=(SELECT c.id::text
                FROM vulntrack_technology_cpe.confirmations c
                WHERE c.workspace_id={alias}.workspace_id AND c.technology_id={alias}.id
                ORDER BY c.event_number DESC LIMIT 1)"""
        table = "vulntrack.application_analysis_runs"
    if kind == "devices":
        missing = (
            f"NOT EXISTS(SELECT 1 FROM vulntrack_devices.identifications i WHERE "
            f"i.workspace_id={alias}.workspace_id AND i.device_id={alias}.id "
            f"AND i.identity_generation={alias}.identity_generation)"
        )
        unknown = "'identification_required'"
    else:
        missing = (
            f"NOT EXISTS(SELECT 1 FROM vulntrack_technology_cpe.confirmations c WHERE "
            f"c.workspace_id={alias}.workspace_id AND c.technology_id={alias}.id)"
        )
        unknown = (
            f"CASE WHEN {alias}.selected_cpe IS NULL THEN 'identification_required' "
            "ELSE 'unknown' END"
        )
    return (
        f"CASE WHEN {missing} THEN {unknown} "
        f"WHEN EXISTS(SELECT 1 FROM {table} r WHERE {predicate}) "
        "THEN 'recorded' ELSE 'not_queried' END"
    )


def historical_row(row):
    from app.schemas.cpe import parse_cpe, unbind_component

    try:
        _, vendor, product, version, *_ = map(unbind_component, parse_cpe(row["selected_cpe"]))
        evaluated = {
            "vendor": vendor,
            "product": product,
            "version": version,
            "basis": "historical_cpe",
        }
    except (ValueError, TypeError):
        evaluated = None
    result = dict(row) | {"evaluated_technology": evaluated}
    if evaluated:
        result.update(product=evaluated["product"], version=evaluated["version"])
    return result
