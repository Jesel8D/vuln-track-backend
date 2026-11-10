"""NVD workflows bound to Database V2 applications and workspace RLS."""

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from app.api.router import Identity
from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.schemas.cpe import Candidate, CandidateList, SearchInput, parse_cpe, unbind_component
from app.services.applicability import encoded, evidence_for

logger = logging.getLogger("vulntrack.v2.nvd")
router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/applications/{application_id}")
IdempotencyKey = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    ),
]


class CPESelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpe_name_id: UUID
    expected_selected_cpe: str | None = Field(default=None, max_length=1024)


def _authorize(session, workspace_id, application_id, role="owner", actor_id=None):
    if role == "writer":
        allowed = session.scalar(
            text("SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor'])"),
            {"workspace": workspace_id},
        )
    else:
        allowed = session.scalar(
            text("SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor','viewer'])"),
            {"workspace": workspace_id},
        )
    if not allowed:
        raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
    found = session.scalar(
        text("""SELECT 1 FROM vulntrack.applications
               WHERE workspace_id=:workspace AND id=:application AND status='active'"""),
        {"workspace": workspace_id, "application": application_id},
    )
    if not found:
        raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")


def _severity(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values and isinstance(values[0], dict):
            data = values[0].get("cvssData", {})
            severity = data.get("baseSeverity") or values[0].get("baseSeverity")
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


@router.get("/cpe-candidates", response_model=CandidateList)
def cpe_candidates(
    workspace_id: UUID,
    application_id: UUID,
    user: Identity,
    request: Request,
    search: Annotated[SearchInput, Query()],
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id)
    # Network calls happen after the RLS transaction has closed.
    return request.app.state.nvd.search(user.id, search)


@router.put("/technologies/{technology_id}/cpe", response_model=Candidate)
def confirm_cpe(
    workspace_id: UUID,
    application_id: UUID,
    technology_id: UUID,
    payload: CPESelection,
    user: Identity,
    request: Request,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        current = session.execute(
            text("""SELECT selected_cpe, version FROM vulntrack.technologies
                WHERE workspace_id=:workspace AND application_id=:application
                  AND id=:technology"""),
            {"workspace": workspace_id, "application": application_id, "technology": technology_id},
        ).mappings().first()
        if current is None:
            raise APIError(404, "TECHNOLOGY_NOT_FOUND", "Tecnología no encontrada")
        if current["selected_cpe"] != payload.expected_selected_cpe:
            raise APIError(409, "CPE_SELECTION_CHANGED", "La selección CPE cambió")

    candidate, _ = request.app.state.nvd.resolve(user.id, payload.cpe_name_id)
    candidate_version = unbind_component(parse_cpe(candidate.cpe_name)[3])
    if candidate_version in {"*", "-"} or candidate_version.casefold() != current["version"].casefold():
        raise APIError(409, "CPE_VERSION_MISMATCH", "El CPE NVD debe coincidir con la versión observada")
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        updated = session.execute(
            text("""UPDATE vulntrack.technologies SET selected_cpe=:cpe, confidence='user_confirmed'
                WHERE workspace_id=:workspace AND application_id=:application AND id=:technology
                  AND selected_cpe IS NOT DISTINCT FROM :expected
                RETURNING id"""),
            {
                "cpe": candidate.cpe_name,
                "workspace": workspace_id,
                "application": application_id,
                "technology": technology_id,
                "expected": payload.expected_selected_cpe,
            },
        ).first()
        if updated is None:
            raise APIError(409, "CPE_SELECTION_CHANGED", "La selección CPE cambió")
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'technology.cpe_confirmed','technology',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": technology_id},
        )
    return candidate


@router.post("/technologies/{technology_id}/analyses", status_code=201)
def analyze_technology(
    workspace_id: UUID,
    application_id: UUID,
    technology_id: UUID,
    user: Identity,
    request: Request,
    idempotency_key: IdempotencyKey,
):
    key = UUID(idempotency_key)
    request_body = {
        "version": 1,
        "method": "POST",
        "route": (
            f"/api/v2/workspaces/{workspace_id}/applications/{application_id}/"
            f"technologies/{technology_id}/analyses"
        ),
        "body": {"kind": "nvd_cve"},
    }
    request_hash = hashlib.sha256(encoded(request_body)).hexdigest()
    run_id = None

    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        technology = session.execute(
            text("""SELECT selected_cpe, version, confidence FROM vulntrack.technologies
                WHERE workspace_id=:workspace AND application_id=:application AND id=:technology"""),
            {"workspace": workspace_id, "application": application_id, "technology": technology_id},
        ).mappings().first()
        if technology is None:
            raise APIError(404, "TECHNOLOGY_NOT_FOUND", "Tecnología no encontrada")
        if technology["confidence"] != "user_confirmed" or not technology["selected_cpe"]:
            raise APIError(409, "CPE_CONFIRMATION_REQUIRED", "Confirma un CPE NVD antes de consultar CVE")
        previous = session.execute(
            text("""SELECT id, request_hash, status, coverage, total_results, stored_count
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND initiated_by=:actor AND request_key=:key"""),
            {"workspace": workspace_id, "actor": user.id, "key": key},
        ).mappings().first()
        if previous:
            if previous["request_hash"] != request_hash:
                raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otra solicitud")
            return dict(previous)
        active = session.scalar(
            text("""SELECT id FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND technology_id=:technology
                  AND status IN ('queued','running') LIMIT 1"""),
            {"workspace": workspace_id, "technology": technology_id},
        )
        if active:
            raise APIError(409, "ANALYSIS_IN_PROGRESS", "Ya existe una consulta activa para esta tecnología")
        request.app.state.nvd.quota.check_user(user.id, "cve")
        run_id = uuid4()
        session.execute(
            text("""INSERT INTO vulntrack.application_analysis_runs
                (id, workspace_id, application_id, technology_id, initiated_by, selected_cpe,
                 status, request_key, request_hash, query_parameters)
                VALUES (:id,:workspace,:application,:technology,:actor,:cpe,
                 'queued',:key,:digest,CAST(:params AS jsonb))"""),
            {
                "id": run_id,
                "workspace": workspace_id,
                "application": application_id,
                "technology": technology_id,
                "actor": user.id,
                "cpe": technology["selected_cpe"],
                "key": key,
                "digest": request_hash,
                "params": json.dumps({"cpeName": technology["selected_cpe"], "resultsPerPage": 100}),
            },
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'nvd.analysis_requested','analysis',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": run_id},
        )

    try:
        with workspace_session(
            request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
        ) as session:
            _authorize(session, workspace_id, application_id, "writer")
            session.execute(
                text("UPDATE vulntrack.application_analysis_runs SET status='running', started_at=clock_timestamp() WHERE id=:id"),
                {"id": run_id},
            )

        # No SQL transaction/connection is held during the external request.
        page = request.app.state.cve.page(technology["selected_cpe"], 0, 100)
        page_cves = [entry.cve.model_dump(mode="json", exclude_none=True) for entry in page.vulnerabilities]
        warnings = []
        rows = []
        for record in page_cves:
            if _contains_nul(record):
                raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE NVD no válida")
            applicability, evidence = evidence_for(technology["selected_cpe"], technology["version"], record)
            if evidence.get("truncated"):
                warnings.append("EVIDENCE_BUDGET_REACHED")
            descriptions = record.get("descriptions", [])
            title = next((item.get("value") for item in descriptions if item.get("lang") == "en"), None)
            title = " ".join(title.split())[:500] if isinstance(title, str) else None
            metrics = record.get("metrics") or None
            if metrics and len(encoded(metrics)) > 24000:
                warnings.append("METRICS_OMITTED")
                metrics = None
            rows.append({
                "id": uuid4(), "workspace": workspace_id, "analysis": run_id,
                "external_id": record["id"], "title": title or None,
                "severity": _severity(record.get("metrics") or {}), "cvss": json.dumps(metrics) if metrics else None,
                "applicability": applicability, "evidence": json.dumps(evidence),
                "published": datetime.fromisoformat(record["published"].replace("Z", "+00:00")),
                "modified": datetime.fromisoformat(record["lastModified"].replace("Z", "+00:00")),
            })
        complete = page.totalResults <= len(page_cves)
        if not complete:
            warnings.append("PAGE_BUDGET_REACHED")
        with workspace_session(
            request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
        ) as session:
            _authorize(session, workspace_id, application_id, "writer")
            for row in rows:
                session.execute(
                    text("""INSERT INTO vulntrack.application_findings
                        (id,workspace_id,analysis_id,external_id,title,severity,cvss,applicability,evidence,published_at,last_modified_at)
                        VALUES (:id,:workspace,:analysis,:external_id,:title,:severity,
                        CAST(:cvss AS jsonb),:applicability,CAST(:evidence AS jsonb),:published,:modified)"""), row,
                )
            ids = [record["id"] for record in page_cves]
            manifest = [{"start_index": 0, "count": len(ids), "total": page.totalResults,
                         "ids_sha256": hashlib.sha256(encoded(ids)).hexdigest(),
                         "timestamp": page.timestamp.isoformat()}]
            session.execute(
                text("""UPDATE vulntrack.application_analysis_runs SET
                    status='completed', coverage=:coverage, completed_at=clock_timestamp(),
                    total_results=:total, retrieved_count=:retrieved, stored_count=:stored,
                    page_count=1, next_index=:next, source_timestamp=:timestamp,
                    warning_codes=CAST(:warnings AS jsonb),
                    source_timestamps=CAST(:timestamps AS jsonb), page_manifest=CAST(:manifest AS jsonb)
                    WHERE id=:id"""),
                {"coverage": "complete" if complete else "partial", "total": page.totalResults,
                 "retrieved": len(page_cves), "stored": len(rows), "next": len(page_cves),
                 "timestamp": page.timestamp, "warnings": json.dumps(sorted(set(warnings))),
                 "timestamps": json.dumps([page.timestamp.isoformat()]), "manifest": json.dumps(manifest), "id": run_id},
            )
    except APIError as exc:
        _fail_run(request, user.id, workspace_id, application_id, run_id, exc.code)
        raise
    except Exception as exc:
        _fail_run(request, user.id, workspace_id, application_id, run_id, "PROCESSING_ERROR")
        logger.error("v2_nvd_processing_error run_id=%s type=%s", run_id, type(exc).__name__)
        raise APIError(503, "NVD_PROCESSING_FAILED", "No se pudo completar la consulta NVD") from None

    return {"id": str(run_id), "status": "completed", "coverage": "complete" if complete else "partial",
            "total_results": page.totalResults, "retrieved_count": len(page_cves), "stored_count": len(rows),
            "source_timestamp": page.timestamp.isoformat(), "warning_codes": sorted(set(warnings))}


def _fail_run(request, actor, workspace, application, run_id, code):
    if run_id is None:
        return
    try:
        with workspace_session(
            request.app.state.session_factory, request.app.state.settings, actor, workspace
        ) as session:
            _authorize(session, workspace, application, "writer")
            session.execute(
                text("""UPDATE vulntrack.application_analysis_runs SET status='failed',
                    completed_at=clock_timestamp(), failure_code=:code WHERE id=:id AND status IN ('queued','running')"""),
                {"code": code if code.isupper() and len(code) <= 80 else "PROCESSING_ERROR", "id": run_id},
            )
    except Exception as exc:
        logger.error("v2_nvd_run_failure_persist_failed run_id=%s type=%s", run_id, type(exc).__name__)


@router.get("/analyses/{run_id}")
def get_analysis(workspace_id: UUID, application_id: UUID, run_id: UUID, user: Identity, request: Request):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id)
        row = session.execute(
            text("""SELECT id,status,coverage,total_results,retrieved_count,stored_count,page_count,
                warning_codes,failure_code,source_timestamp,created_at,started_at,completed_at
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND application_id=:application AND id=:id"""),
            {"workspace": workspace_id, "application": application_id, "id": run_id},
        ).mappings().first()
        if row is None:
            raise APIError(404, "ANALYSIS_NOT_FOUND", "Consulta no encontrada")
        return dict(row)


@router.get("/analyses/{run_id}/findings")
def get_findings(
    workspace_id: UUID,
    application_id: UUID,
    run_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id)
        run = session.execute(
            text("""SELECT status,coverage FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND application_id=:application AND id=:id"""),
            {"workspace": workspace_id, "application": application_id, "id": run_id},
        ).mappings().first()
        if run is None:
            raise APIError(404, "ANALYSIS_NOT_FOUND", "Consulta no encontrada")
        rows = session.execute(
            text("""SELECT id,external_id,title,severity,cvss,applicability,status,evidence,
                published_at,last_modified_at,observed_at FROM vulntrack.application_findings
                WHERE workspace_id=:workspace AND analysis_id=:id
                ORDER BY external_id LIMIT :limit OFFSET :offset"""),
            {"workspace": workspace_id, "id": run_id, "limit": limit, "offset": offset},
        ).mappings().all()
        total = session.scalar(
            text("SELECT count(*) FROM vulntrack.application_findings WHERE workspace_id=:workspace AND analysis_id=:id"),
            {"workspace": workspace_id, "id": run_id},
        )
        return {"items": [dict(row) for row in rows], "page": {"limit": limit, "offset": offset, "total": total},
                "run_status": run["status"], "coverage": run["coverage"]}
