"""NVD workflows bound to Database V2 applications and workspace RLS."""

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from app.api.cpe_catalog import Part, admit_catalog, catalog_row, find_candidates, normalized_text
from app.api.router import Identity
from app.core.errors import APIError
from app.db.pagination import page
from app.db.workspace_context import workspace_session
from app.schemas.assets import Page
from app.schemas.cpe import Candidate, CandidateList, SearchInput, parse_cpe, unbind_component
from app.services.applicability import encoded
from app.services.cpe_catalog import Mode
from app.services.nvd_findings import finding_rows
from app.services.v2_cve_cache import fetch_page
from app.services.v2_cve_reliability import context as query_context
from app.services.v2_cve_reliability import decorate, recover, require_active

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


class ApplicationCpeSearch(SearchInput):
    technology_id: UUID | None = None
    part: Part = "a"
    mode: Mode = "live"


class CPESelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpe_name_id: UUID
    expected_selected_cpe: str | None = Field(default=None, max_length=1024)
    expected_cpe_name: str | None = Field(default=None, max_length=1024)
    part: Part = "a"
    mode: Mode = "live"
    expected_confirmation_id: UUID | None = None
    reason: str | None = Field(default=None, min_length=1, max_length=500)
    evidence: str | None = Field(default=None, min_length=1, max_length=2000)

    @field_validator("reason", "evidence")
    @classmethod
    def clean_explanation(cls, value):
        if value is None:
            return None
        value = " ".join(value.split())
        if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Texto inválido")
        return value


class TechnologyCpeConfirmation(BaseModel):
    id: UUID
    event_number: int
    workspace_id: UUID
    application_id: UUID
    technology_id: UUID
    recorded_by: UUID
    confirmed_at: datetime
    cpe_name_id: UUID
    cpe_name: str
    mode: Mode
    source: Literal["nvd-api", "nvd-feed", "nvd-captured-fixture"]
    observed_vendor: str | None
    observed_product: str
    observed_version: str
    reason: str | None
    evidence: str | None
    catalog_evidence: dict
    is_current: bool


class TechnologyCpeHistory(BaseModel):
    items: list[TechnologyCpeConfirmation]
    page: Page
    current_confirmation_id: UUID | None
    legacy_provenance: Literal["not_recorded"] | None


class FindingReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    applicability: str = Field(pattern=r"^(potential|undetermined|not_applicable)$")
    expected_updated_at: datetime

    @field_validator("expected_updated_at")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None:
            raise ValueError("expected_updated_at requiere zona horaria")
        return value


class RecommendationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recommendation: str = Field(min_length=1, max_length=4000)
    source_url: str | None = Field(default=None, max_length=2048)
    assigned_to: UUID | None = None
    due_at: datetime | None = None

    @field_validator("recommendation", mode="before")
    @classmethod
    def clean_recommendation(cls, value):
        if not isinstance(value, str):
            return value
        value = " ".join(value.split())
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("Texto inválido")
        return value

    @field_validator("source_url")
    @classmethod
    def safe_source_url(cls, value):
        if value is None:
            return value
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("source_url debe ser HTTPS y no incluir credenciales")
        return value

    @field_validator("due_at")
    @classmethod
    def due_date_aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("due_at requiere zona horaria")
        return value


class RecommendationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern=r"^(pending|in_progress|fixed|accepted_risk)$")
    expected_updated_at: datetime

    @field_validator("expected_updated_at")
    @classmethod
    def expected_time_aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("expected_updated_at requiere zona horaria")
        return value


def _authorize(
    session, workspace_id, application_id, role="owner", actor_id=None, *, active_only=True
):
    if role == "writer":
        allowed = session.scalar(
            text("SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor'])"),
            {"workspace": workspace_id},
        )
    else:
        allowed = session.scalar(
            text(
                "SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor','viewer'])"
            ),
            {"workspace": workspace_id},
        )
    if not allowed:
        raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
    recover(session)
    found = session.scalar(
        text("""SELECT 1 FROM vulntrack.applications
               WHERE workspace_id=:workspace AND id=:application
                 AND (NOT :active_only OR status='active')"""),
        {"workspace": workspace_id, "application": application_id, "active_only": active_only},
    )
    if not found:
        raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")


def _technology(session, workspace_id, application_id, technology_id):
    row = (
        session.execute(
            text("""SELECT selected_cpe, vendor, product, version FROM vulntrack.technologies
                WHERE workspace_id=:workspace AND application_id=:application
                  AND id=:technology"""),
            {"workspace": workspace_id, "application": application_id, "technology": technology_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise APIError(404, "TECHNOLOGY_NOT_FOUND", "Tecnología no encontrada")
    return row


def _catalog_name(value):
    return "_".join(normalized_text(value or "").casefold().split())


def _confirmation_id(session, workspace_id, application_id, technology_id):
    return session.scalar(
        text("""SELECT id FROM vulntrack_technology_cpe.confirmations
            WHERE workspace_id=:workspace AND application_id=:application
              AND technology_id=:technology ORDER BY event_number DESC LIMIT 1"""),
        {"workspace": workspace_id, "application": application_id, "technology": technology_id},
    )


@router.get("/technologies/{technology_id}/cpe-confirmations", response_model=TechnologyCpeHistory)
def cpe_confirmations(
    workspace_id: UUID,
    application_id: UUID,
    technology_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, active_only=False)
        current = _technology(session, workspace_id, application_id, technology_id)
        latest = _confirmation_id(session, workspace_id, application_id, technology_id)
        params = {
            "workspace": workspace_id,
            "application": application_id,
            "technology": technology_id,
            "limit": limit,
            "offset": offset,
        }
        result = (
            session.execute(
                text("""WITH matches AS MATERIALIZED (
                SELECT * FROM vulntrack_technology_cpe.confirmations
                WHERE workspace_id=:workspace AND application_id=:application
                  AND technology_id=:technology
            ) SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.event_number DESC),'[]') AS items,
                     (SELECT count(*) FROM matches) AS total
                FROM (SELECT * FROM matches ORDER BY event_number DESC
                      LIMIT :limit OFFSET :offset) p"""),
                params,
            )
            .mappings()
            .one()
        )
        items = []
        for row in result["items"]:
            row["is_current"] = (
                row["id"] == str(latest)
                and row["cpe_name"] == current["selected_cpe"]
                and row["observed_vendor"] == current["vendor"]
                and row["observed_product"] == current["product"]
                and row["observed_version"] == current["version"]
            )
            items.append(row)
        return {
            "items": items,
            "page": Page(limit=limit, offset=offset, total=result["total"]),
            "current_confirmation_id": latest,
            "legacy_provenance": "not_recorded" if current["selected_cpe"] and not latest else None,
        }


@router.get("/cpe-candidates", response_model=CandidateList)
def cpe_candidates(
    workspace_id: UUID,
    application_id: UUID,
    user: Identity,
    request: Request,
    search: Annotated[ApplicationCpeSearch, Query()],
):
    vendor, product, version = "", _catalog_name(search.product_query), ""
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id)
        if search.technology_id is not None:
            technology = _technology(session, workspace_id, application_id, search.technology_id)
            vendor = _catalog_name(technology["vendor"])
            product = _catalog_name(technology["product"])
            version = technology["version"]

    admit_catalog(request, user)
    result = find_candidates(
        request,
        mode=search.mode,
        part=search.part,
        q=search.query,
        vendor=vendor,
        product=product,
        version=version,
        deprecated=False,
        limit=search.limit,
        offset=search.offset,
        concrete_version=True,
    )
    return result | {"source_timestamp": datetime.now(UTC)}


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
        current = _technology(session, workspace_id, application_id, technology_id)
        if current["selected_cpe"] != payload.expected_selected_cpe:
            raise APIError(409, "CPE_SELECTION_CHANGED", "La selección CPE cambió")
        if _confirmation_id(session, workspace_id, application_id, technology_id) != (
            payload.expected_confirmation_id
        ):
            raise APIError(409, "CPE_SELECTION_CHANGED", "La confirmación CPE cambió")

    admit_catalog(request, user)
    with request.app.state.catalog_reader.connect(payload.mode) as connection:
        candidate = catalog_row(connection, payload.mode, payload.cpe_name_id)
        feed = None
        if candidate["source"] == "nvd-feed":
            row = (
                connection.execute(
                    text("""SELECT digest,source_modified,status
                FROM vulntrack_catalog.feed_imports ORDER BY updated_at DESC LIMIT 1""")
                )
                .mappings()
                .first()
            )
            feed = dict(row) if row else None
    if candidate["mode"] != payload.mode or (
        (candidate["source"] == "nvd-captured-fixture") != (payload.mode == "fixture")
    ):
        raise APIError(409, "CPE_SOURCE_MISMATCH", "La fuente del CPE no coincide")
    if candidate["deprecated"]:
        raise APIError(409, "CPE_DEPRECATED", "El CPE seleccionado está deprecado")
    if payload.expected_cpe_name is not None and candidate["cpe_name"] != payload.expected_cpe_name:
        raise APIError(409, "CPE_SELECTION_CHANGED", "El registro CPE cambió")
    if (
        candidate["version"] != current["version"]
        or candidate["version"] == "-"
        or any(wildcard in candidate["version"] for wildcard in "*?")
    ):
        raise APIError(
            409, "CPE_VERSION_MISMATCH", "El CPE NVD debe coincidir con la versión observada"
        )
    vendor = _catalog_name(current["vendor"])
    if (
        candidate["part"] != payload.part
        or candidate["product"] != _catalog_name(current["product"])
        or (vendor and candidate["vendor"] != vendor)
    ):
        raise APIError(
            409, "CPE_PRODUCT_MISMATCH", "El tipo, fabricante o producto CPE no coincide"
        )
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        # Serialize re-confirmations even when two sources contain the same CPE
        # string. A CAS on selected_cpe alone cannot detect that race.
        session.execute(
            text("""SELECT id FROM vulntrack.technologies
                WHERE workspace_id=:workspace AND application_id=:application
                  AND id=:technology FOR UPDATE"""),
            {"workspace": workspace_id, "application": application_id, "technology": technology_id},
        )
        if _confirmation_id(session, workspace_id, application_id, technology_id) != (
            payload.expected_confirmation_id
        ):
            raise APIError(409, "CPE_SELECTION_CHANGED", "La confirmación CPE cambió")
        updated = session.execute(
            text("""UPDATE vulntrack.technologies SET selected_cpe=:cpe, confidence='user_confirmed'
                WHERE workspace_id=:workspace AND application_id=:application AND id=:technology
                  AND selected_cpe IS NOT DISTINCT FROM :expected
                  AND vendor IS NOT DISTINCT FROM :vendor AND product=:product AND version=:version
                RETURNING id"""),
            {
                "cpe": candidate["cpe_name"],
                "workspace": workspace_id,
                "application": application_id,
                "technology": technology_id,
                "expected": payload.expected_selected_cpe,
                "vendor": current["vendor"],
                "product": current["product"],
                "version": current["version"],
            },
        ).first()
        if updated is None:
            raise APIError(409, "CPE_SELECTION_CHANGED", "La selección CPE cambió")
        session.execute(
            text("""INSERT INTO vulntrack_technology_cpe.confirmations
                (id,workspace_id,application_id,technology_id,recorded_by,cpe_name_id,cpe_name,
                 mode,source,observed_vendor,observed_product,observed_version,
                 reason,evidence,catalog_evidence)
                VALUES (:id,:workspace,:application,:technology,:actor,:name_id,:name,:mode,
                    :source,:vendor,:product,:version,:reason,:evidence,
                    CAST(:catalog AS jsonb))"""),
            {
                "id": uuid4(),
                "workspace": workspace_id,
                "application": application_id,
                "technology": technology_id,
                "actor": user.id,
                "name_id": candidate["cpe_name_id"],
                "name": candidate["cpe_name"],
                "mode": payload.mode,
                "source": candidate["source"],
                "vendor": current["vendor"],
                "product": current["product"],
                "version": current["version"],
                "reason": payload.reason,
                "evidence": payload.evidence,
                "catalog": json.dumps({"record": candidate, "feed": feed}, default=str),
            },
        )
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
        _authorize(session, workspace_id, application_id, "writer", active_only=False)
        technology = (
            session.execute(
                text("""SELECT selected_cpe, vendor, product, version, confidence
                FROM vulntrack.technologies
                WHERE workspace_id=:workspace AND application_id=:application AND
                id=:technology FOR UPDATE"""),
                {
                    "workspace": workspace_id,
                    "application": application_id,
                    "technology": technology_id,
                },
            )
            .mappings()
            .first()
        )
        if technology is None:
            raise APIError(404, "TECHNOLOGY_NOT_FOUND", "Tecnología no encontrada")
        previous = (
            session.execute(
                text("""SELECT *,COALESCE(query_parameters->>'nvd_mode','unknown') AS nvd_mode
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND initiated_by=:actor AND request_key=:key"""),
                {"workspace": workspace_id, "actor": user.id, "key": key},
            )
            .mappings()
            .first()
        )
        if previous:
            if previous["request_hash"] != request_hash:
                raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otra solicitud")
            public = {
                key: value
                for key, value in previous.items()
                if key
                in {
                    "id",
                    "application_id",
                    "technology_id",
                    "selected_cpe",
                    "status",
                    "coverage",
                    "total_results",
                    "retrieved_count",
                    "stored_count",
                    "page_count",
                    "warning_codes",
                    "failure_code",
                    "source_timestamp",
                    "created_at",
                    "started_at",
                    "completed_at",
                    "run_context",
                    "lease_expires_at",
                    "response_received_at",
                    "cache_response_id",
                    "cache_usage",
                    "nvd_mode",
                }
            }
            return decorate(
                session, request.app.state.settings, "applications", [_historical_run(public)]
            )[0]
        _authorize(session, workspace_id, application_id, "writer")
        if technology["confidence"] != "user_confirmed" or not technology["selected_cpe"]:
            raise APIError(
                409, "CPE_CONFIRMATION_REQUIRED", "Confirma un CPE NVD antes de consultar CVE"
            )
        try:
            parsed = parse_cpe(technology["selected_cpe"])
        except ValueError:
            raise APIError(409, "CPE_INVALID", "Vuelve a confirmar un CPE válido") from None
        if (
            unbind_component(parsed[3]) != technology["version"]
            or any(c in parsed[3] for c in "*?")
            or parsed[3] == "-"
        ):
            raise APIError(
                409, "CPE_VERSION_MISMATCH", "Confirma un CPE para la versión observada actual"
            )
        confirmation = (
            session.execute(
                text("""SELECT id,mode,source,cpe_name,observed_vendor,observed_product,
                observed_version FROM vulntrack_technology_cpe.confirmations
            WHERE workspace_id=:workspace AND technology_id=:technology
            ORDER BY event_number DESC LIMIT 1"""),
                {"workspace": workspace_id, "technology": technology_id},
            )
            .mappings()
            .first()
        )
        if confirmation and any(
            confirmation[saved] != technology[current]
            for saved, current in (
                ("cpe_name", "selected_cpe"),
                ("observed_vendor", "vendor"),
                ("observed_product", "product"),
                ("observed_version", "version"),
            )
        ):
            raise APIError(
                409, "CPE_CONFIRMATION_REQUIRED", "Vuelve a confirmar la identificación actual"
            )
        if request.app.state.nvd_mode == "live" and (
            not confirmation or confirmation["mode"] != "live"
        ):
            raise APIError(
                409, "CPE_PROVENANCE_REQUIRED", "Confirma un CPE oficial antes de usar CVE live"
            )
        saved_context = query_context(
            request,
            identification_id=confirmation["id"] if confirmation else None,
            cpe_mode=confirmation["mode"] if confirmation else None,
            cpe_source=confirmation["source"] if confirmation else None,
            vendor=technology["vendor"],
            product=technology["product"],
            version=technology["version"],
        )
        active = session.scalar(
            text("""SELECT id FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND technology_id=:technology
                  AND status IN ('queued','running') LIMIT 1"""),
            {"workspace": workspace_id, "technology": technology_id},
        )
        if active:
            raise APIError(
                409, "ANALYSIS_IN_PROGRESS", "Ya existe una consulta activa para esta tecnología"
            )
        request.app.state.nvd.quota.check_user(user.id, "cve")
        run_id = uuid4()
        session.execute(
            text("""INSERT INTO vulntrack.application_analysis_runs
                (id, workspace_id, application_id, technology_id, initiated_by, selected_cpe,
                 status, request_key, request_hash, query_parameters,run_context,lease_expires_at)
                VALUES (:id,:workspace,:application,:technology,:actor,:cpe,
                 'queued',:key,:digest,CAST(:params AS jsonb),CAST(:context AS jsonb),
                 clock_timestamp()+make_interval(secs=>:seconds))"""),
            {
                "id": run_id,
                "workspace": workspace_id,
                "application": application_id,
                "technology": technology_id,
                "actor": user.id,
                "cpe": technology["selected_cpe"],
                "key": key,
                "digest": request_hash,
                "context": json.dumps(saved_context),
                "seconds": request.app.state.settings.cve_execution_seconds,
                "params": json.dumps(
                    {
                        "cpeName": technology["selected_cpe"],
                        "resultsPerPage": getattr(request.app.state.cve, "page_limit", 100),
                        "nvd_mode": request.app.state.nvd_mode,
                    }
                ),
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
            _authorize(session, workspace_id, application_id, "writer", active_only=False)
            session.execute(
                text(
                    "UPDATE vulntrack.application_analysis_runs SET status='running', "
                    "started_at=clock_timestamp() WHERE id=:id"
                ),
                {"id": run_id},
            )

        # No SQL transaction/connection is held during the external request.
        result = fetch_page(request, user.id, workspace_id, technology["selected_cpe"])
        page = result.page
        page_cves, rows, warnings = finding_rows(
            page, technology["selected_cpe"], technology["version"]
        )
        complete = page.totalResults <= len(page_cves)
        if not complete:
            warnings.append("PAGE_BUDGET_REACHED")
        with workspace_session(
            request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
        ) as session:
            _authorize(session, workspace_id, application_id, "writer", active_only=False)
            require_active(session, "applications", workspace_id, run_id)
            for row in rows:
                session.execute(
                    text("""INSERT INTO vulntrack.application_findings
                        (id,workspace_id,analysis_id,external_id,title,severity,cvss,applicability,evidence,published_at,last_modified_at)
                        VALUES (:id,:workspace,:analysis,:external_id,:title,:severity,
                        CAST(:cvss AS jsonb),:applicability,CAST(:evidence AS
                        jsonb),:published,:modified)"""),
                    {**row, "workspace": workspace_id, "analysis": run_id},
                )
            ids = [record["id"] for record in page_cves]
            manifest = [
                {
                    "start_index": 0,
                    "count": len(ids),
                    "total": page.totalResults,
                    "ids_sha256": hashlib.sha256(encoded(ids)).hexdigest(),
                    "timestamp": page.timestamp.isoformat(),
                }
            ]
            session.execute(
                text("""UPDATE vulntrack.application_analysis_runs SET
                    status='completed', coverage=:coverage, completed_at=clock_timestamp(),
                    response_received_at=coalesce(:received,clock_timestamp()),
                    cache_response_id=:cache_response,cache_usage=CAST(:cache_usage AS jsonb),
                    total_results=:total, retrieved_count=:retrieved, stored_count=:stored,
                    page_count=1, next_index=:next, source_timestamp=:timestamp,
                    warning_codes=CAST(:warnings AS jsonb),
                    source_timestamps=CAST(:timestamps AS jsonb), page_manifest=CAST(:manifest
                    AS jsonb)
                    WHERE id=:id"""),
                {
                    "coverage": "complete" if complete else "partial",
                    "received": result.received_at,
                    "cache_response": result.response_id,
                    "cache_usage": json.dumps(result.usage) if result.usage else None,
                    "total": page.totalResults,
                    "retrieved": len(page_cves),
                    "stored": len(rows),
                    "next": len(page_cves),
                    "timestamp": page.timestamp,
                    "warnings": json.dumps(sorted(set(warnings))),
                    "timestamps": json.dumps([page.timestamp.isoformat()]),
                    "manifest": json.dumps(manifest),
                    "id": run_id,
                },
            )
    except APIError as exc:
        _fail_run(
            request,
            user.id,
            workspace_id,
            application_id,
            run_id,
            exc.code,
            getattr(exc, "cache_usage", None),
        )
        raise
    except Exception as exc:
        _fail_run(request, user.id, workspace_id, application_id, run_id, "PROCESSING_ERROR")
        logger.error("v2_nvd_processing_error run_id=%s type=%s", run_id, type(exc).__name__)
        raise APIError(
            503, "NVD_PROCESSING_FAILED", "No se pudo completar la consulta NVD"
        ) from None

    return get_analysis(workspace_id, application_id, run_id, user, request)


def _fail_run(request, actor, workspace, application, run_id, code, cache_usage=None):
    if run_id is None:
        return
    try:
        with workspace_session(
            request.app.state.session_factory, request.app.state.settings, actor, workspace
        ) as session:
            _authorize(session, workspace, application, "writer", active_only=False)
            session.execute(
                text("""UPDATE vulntrack.application_analysis_runs SET status='failed',
                    completed_at=clock_timestamp(), failure_code=:code,
                    cache_usage=CAST(:cache_usage AS jsonb) WHERE id=:id AND status
                    IN ('queued','running')"""),
                {
                    "code": code if code.isupper() and len(code) <= 80 else "PROCESSING_ERROR",
                    "id": run_id,
                    "cache_usage": json.dumps(cache_usage) if cache_usage else None,
                },
            )
    except Exception as exc:
        logger.error(
            "v2_nvd_run_failure_persist_failed run_id=%s type=%s", run_id, type(exc).__name__
        )


def _historical_run(row):
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
    if evaluated and "product" in row:
        result.update(product=evaluated["product"], version=evaluated["version"])
    return result


@router.get("/analyses/{run_id}")
def get_analysis(
    workspace_id: UUID, application_id: UUID, run_id: UUID, user: Identity, request: Request
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, active_only=False)
        row = (
            session.execute(
                text("""SELECT
                id,application_id,technology_id,selected_cpe,status,coverage,total_results,retrieved_count,stored_count,page_count,
                warning_codes,failure_code,source_timestamp,created_at,started_at,completed_at,run_context,lease_expires_at,response_received_at,cache_response_id,cache_usage,
                COALESCE(query_parameters->>'nvd_mode','unknown') AS nvd_mode
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND application_id=:application AND id=:id"""),
                {"workspace": workspace_id, "application": application_id, "id": run_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise APIError(404, "ANALYSIS_NOT_FOUND", "Consulta no encontrada")
        return decorate(
            session, request.app.state.settings, "applications", [_historical_run(row)]
        )[0]


@router.get("/analyses")
def list_analyses(
    workspace_id: UUID,
    application_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
):
    """List NVD runs for this application without exposing other workspaces."""
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, active_only=False)
        result = page(
            session,
            select="r.id,r.application_id,r.technology_id,r.selected_cpe,t.product,t.version,"
            "r.status,r.coverage,r.total_results,r.retrieved_count,r.stored_count,r.page_count,"
            "r.warning_codes,r.failure_code,r.source_timestamp,r.created_at,r.started_at,"
            "r.completed_at,r.run_context,r.lease_expires_at,r.response_received_at,r.cache_response_id,r.cache_usage,"
            "COALESCE(r.query_parameters->>'nvd_mode','unknown') AS nvd_mode",
            table="vulntrack.application_analysis_runs r JOIN vulntrack.technologies t "
            "ON t.workspace_id=r.workspace_id AND t.application_id=r.application_id "
            "AND t.id=r.technology_id",
            where="r.workspace_id=:workspace AND r.application_id=:application",
            sort="created_at DESC,id DESC",
            scope={"workspace": workspace_id, "application": application_id},
            limit=limit,
            offset=offset,
        )
        result["items"] = decorate(
            session,
            request.app.state.settings,
            "applications",
            [_historical_run(row) for row in result["items"]],
        )
        return result


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
        _authorize(session, workspace_id, application_id, active_only=False)
        run = (
            session.execute(
                text("""SELECT id,application_id,technology_id,selected_cpe,
                    created_at,status,coverage,run_context,lease_expires_at,response_received_at,cache_response_id,cache_usage,source_timestamp,
                    COALESCE(query_parameters->>'nvd_mode','unknown') AS nvd_mode
                    FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND application_id=:application AND id=:id"""),
                {"workspace": workspace_id, "application": application_id, "id": run_id},
            )
            .mappings()
            .first()
        )
        if run is None:
            raise APIError(404, "ANALYSIS_NOT_FOUND", "Consulta no encontrada")
        result = page(
            session,
            select="id,external_id,title,severity,cvss,applicability,status,evidence,"
            "published_at,last_modified_at,observed_at,updated_at",
            table="vulntrack.application_findings",
            where="workspace_id=:workspace AND analysis_id=:id",
            sort="external_id,id",
            scope={"workspace": workspace_id, "id": run_id},
            limit=limit,
            offset=offset,
        )
        return result | {
            "run_status": run["status"],
            "coverage": run["coverage"],
            "analysis": decorate(
                session, request.app.state.settings, "applications", [_historical_run(run)]
            )[0],
        }


@router.patch("/findings/{finding_id}")
def review_finding(
    workspace_id: UUID,
    application_id: UUID,
    finding_id: UUID,
    payload: FindingReview,
    user: Identity,
    request: Request,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        row = (
            session.execute(
                text("""SELECT f.id,f.analysis_id,f.external_id,f.title,f.severity,f.cvss,
                f.applicability,f.status,f.evidence,f.published_at,f.last_modified_at,
                f.observed_at,f.updated_at,r.status AS run_status
                FROM vulntrack.application_findings f
                JOIN vulntrack.application_analysis_runs r
                  ON r.workspace_id=f.workspace_id AND r.id=f.analysis_id
                WHERE f.workspace_id=:workspace AND r.application_id=:application
                  AND f.id=:finding FOR UPDATE OF f"""),
                {"workspace": workspace_id, "application": application_id, "finding": finding_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise APIError(404, "FINDING_NOT_FOUND", "Hallazgo no disponible")
        if (
            row["status"] != "open"
            or row["run_status"] not in {"completed", "failed"}
            or row["updated_at"] != payload.expected_updated_at
        ):
            raise APIError(
                409, "FINDING_REVIEW_CONFLICT", "El hallazgo ya cambió o no puede revisarse"
            )
        session.execute(
            text("""UPDATE vulntrack.application_findings
                SET status='reviewed',applicability=:applicability
                WHERE workspace_id=:workspace AND id=:finding AND status='open'"""),
            {
                "applicability": payload.applicability,
                "workspace": workspace_id,
                "finding": finding_id,
            },
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,:action,'finding',:finding)"""),
            {
                "workspace": workspace_id,
                "actor": user.id,
                "action": f"finding.reviewed.{payload.applicability}",
                "finding": finding_id,
            },
        )
        updated = (
            session.execute(
                text("""SELECT id,external_id,title,severity,cvss,applicability,status,evidence,
                published_at,last_modified_at,observed_at,updated_at
                FROM vulntrack.application_findings WHERE workspace_id=:workspace AND
                id=:finding"""),
                {"workspace": workspace_id, "finding": finding_id},
            )
            .mappings()
            .one()
        )
        return dict(updated)


@router.get("/findings/{finding_id}/recommendations")
def list_recommendations(
    workspace_id: UUID,
    application_id: UUID,
    finding_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
    status: Literal["pending", "in_progress", "fixed", "accepted_risk"] | None = None,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, active_only=False)
        found = session.scalar(
            text("""SELECT 1 FROM vulntrack.application_findings f
                JOIN vulntrack.application_analysis_runs r
                  ON r.workspace_id=f.workspace_id AND r.id=f.analysis_id
                WHERE f.workspace_id=:workspace AND f.id=:finding
                  AND r.application_id=:application"""),
            {"workspace": workspace_id, "finding": finding_id, "application": application_id},
        )
        if not found:
            raise APIError(404, "FINDING_NOT_FOUND", "Hallazgo no disponible")
        return page(
            session,
            select="id,finding_id,recommendation,source_url,status,assigned_to,"
            "created_by,due_at,completed_at,created_at,updated_at",
            table="vulntrack.recommendations",
            where="workspace_id=:workspace AND finding_id=:finding "
            "AND (CAST(:status AS text) IS NULL OR status=:status)",
            sort="created_at,id",
            scope={"workspace": workspace_id, "finding": finding_id, "status": status},
            limit=limit,
            offset=offset,
        )


@router.post("/findings/{finding_id}/recommendations", status_code=201)
def create_recommendation(
    workspace_id: UUID,
    application_id: UUID,
    finding_id: UUID,
    payload: RecommendationCreate,
    user: Identity,
    request: Request,
):
    recommendation_id = uuid4()
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        found = session.scalar(
            text("""SELECT 1 FROM vulntrack.application_findings f
                JOIN vulntrack.application_analysis_runs r
                  ON r.workspace_id=f.workspace_id AND r.id=f.analysis_id
                WHERE f.workspace_id=:workspace AND f.id=:finding
                  AND r.application_id=:application FOR UPDATE OF f"""),
            {"workspace": workspace_id, "finding": finding_id, "application": application_id},
        )
        if not found:
            raise APIError(404, "FINDING_NOT_FOUND", "Hallazgo no disponible")
        recommendation_count = session.scalar(
            text("""SELECT count(*) FROM vulntrack.recommendations
                WHERE workspace_id=:workspace AND finding_id=:finding"""),
            {"workspace": workspace_id, "finding": finding_id},
        )
        if recommendation_count >= 50:
            raise APIError(
                409, "RECOMMENDATION_LIMIT", "Este hallazgo alcanzó el límite de 50 medidas"
            )
        if payload.assigned_to and not session.scalar(
            text(
                "SELECT 1 FROM vulntrack.workspace_members WHERE "
                "workspace_id=:workspace AND user_id=:assignee"
            ),
            {"workspace": workspace_id, "assignee": payload.assigned_to},
        ):
            raise APIError(404, "ASSIGNEE_NOT_FOUND", "Miembro no disponible en este workspace")
        row = (
            session.execute(
                text("""INSERT INTO vulntrack.recommendations
                (id,workspace_id,finding_id,recommendation,source_url,assigned_to,created_by,due_at)
                VALUES (:id,:workspace,:finding,:recommendation,:source,:assignee,:actor,:due)
                RETURNING id,finding_id,recommendation,source_url,status,assigned_to,
                    created_by,due_at,completed_at,created_at,updated_at"""),
                {
                    "id": recommendation_id,
                    "workspace": workspace_id,
                    "finding": finding_id,
                    "recommendation": payload.recommendation,
                    "source": payload.source_url,
                    "assignee": payload.assigned_to,
                    "actor": user.id,
                    "due": payload.due_at,
                },
            )
            .mappings()
            .one()
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'recommendation.created','recommendation',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": recommendation_id},
        )
        return dict(row)


@router.patch("/recommendations/{recommendation_id}")
def update_recommendation(
    workspace_id: UUID,
    application_id: UUID,
    recommendation_id: UUID,
    payload: RecommendationUpdate,
    user: Identity,
    request: Request,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, "writer")
        current = (
            session.execute(
                text("""SELECT r.updated_at FROM vulntrack.recommendations r
                JOIN vulntrack.application_findings f
                  ON f.workspace_id=r.workspace_id AND f.id=r.finding_id
                JOIN vulntrack.application_analysis_runs a
                  ON a.workspace_id=f.workspace_id AND a.id=f.analysis_id
                WHERE r.workspace_id=:workspace AND r.id=:id
                  AND a.application_id=:application FOR UPDATE OF r"""),
                {"workspace": workspace_id, "id": recommendation_id, "application": application_id},
            )
            .mappings()
            .first()
        )
        if current is None:
            raise APIError(404, "RECOMMENDATION_NOT_FOUND", "Recomendación no disponible")
        if current["updated_at"] != payload.expected_updated_at:
            raise APIError(
                409, "RECOMMENDATION_CONFLICT", "La recomendación cambió; actualiza la lista"
            )
        row = (
            session.execute(
                text("""UPDATE vulntrack.recommendations SET status=:status,
                completed_at=CASE WHEN :status='fixed' THEN clock_timestamp() ELSE NULL END
                WHERE workspace_id=:workspace AND id=:id
                RETURNING id,finding_id,recommendation,source_url,status,assigned_to,
                    created_by,due_at,completed_at,created_at,updated_at"""),
                {"status": payload.status, "workspace": workspace_id, "id": recommendation_id},
            )
            .mappings()
            .one()
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,:action,'recommendation',:object)"""),
            {
                "workspace": workspace_id,
                "actor": user.id,
                "action": f"recommendation.status.{payload.status}",
                "object": recommendation_id,
            },
        )
        return dict(row)
