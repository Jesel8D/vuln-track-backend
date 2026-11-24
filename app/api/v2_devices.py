"""Devices retain workspace authorization, identity snapshots and separate history."""

import hashlib
import json
import logging
from contextlib import contextmanager
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Query, Request
from pydantic import ValidationError
from sqlalchemy import text

from app.api.cpe_catalog import catalog_row
from app.api.router import Identity
from app.api.v2_nvd import IdempotencyKey
from app.core.errors import APIError
from app.db.inventory_labels import label_key
from app.db.pagination import page
from app.db.workspace_context import workspace_session
from app.schemas.cpe import Candidate, CandidateList, SearchInput
from app.schemas.devices import (
    DeviceCreate,
    DeviceEdit,
    DeviceFindingReview,
    DeviceIdentificationCreate,
    DeviceRecommendationCreate,
    DeviceReidentification,
    DeviceStatus,
    DeviceStatusUpdate,
    DeviceType,
)
from app.services.device_identity import validate_device_candidate, validate_device_cpe
from app.services.device_revisions import (
    EDITABLE,
    edit_device,
    edit_reason,
    present_run,
    require_version,
)
from app.services.nvd_findings import finding_rows
from app.services.v2_cve_reliability import context as query_context
from app.services.v2_cve_reliability import decorate, query_state_sql, recover, require_active

router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/devices", tags=["Dispositivos RC2"])
logger = logging.getLogger(__name__)
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=1000000)]
DEVICE_SCOPE = "workspace_id=:workspace AND device_id=:device"
RUN_FIELDS = """id, identification_id, selected_cpe, observed_version, mode, source,
    status,
    coverage, total_results, retrieved_count, stored_count, warning_codes,
    failure_code,
    source_timestamp, created_at, completed_at, evaluated_technology,
    device_id,run_context,lease_expires_at,response_received_at,
    (SELECT i.identity_generation FROM vulntrack_devices.identifications i
      WHERE i.workspace_id=runs.workspace_id AND i.device_id=runs.device_id
        AND i.id=runs.identification_id) AS identity_generation,
    EXISTS(SELECT 1 FROM vulntrack_devices.devices d
      JOIN vulntrack_devices.identifications i ON i.workspace_id=d.workspace_id
        AND i.device_id=d.id AND i.identity_generation=d.identity_generation
      WHERE d.workspace_id=runs.workspace_id AND d.id=runs.device_id
        AND i.id=runs.identification_id) AS is_current_technology"""
FINDING_FIELDS = """id, analysis_id, external_id, title, severity, cvss, evidence, applicability,
    status, published_at, last_modified_at, reviewed_by, review_reason,
    review_evidence, updated_at"""
RECOMMENDATION_FIELDS = "id, finding_id, created_by, recommendation, status, created_at"


@contextmanager
def access(request, actor, workspace, *, write=False):
    settings = request.app.state.settings
    with workspace_session(
        request.app.state.session_factory, settings, actor, workspace
    ) as session:
        roles = ["owner", "editor"] if write else ["owner", "editor", "viewer"]
        if not session.scalar(
            text("SELECT vulntrack.has_workspace_role(:workspace, CAST(:roles AS text[]))"),
            {"workspace": workspace, "roles": roles},
        ):
            raise APIError(404, "DEVICE_SCOPE_UNAVAILABLE", "Inventario no disponible")
        recover(session)
        session.info["cve_settings"] = settings
        yield session


def one(session, sql, params, code="DEVICE_NOT_FOUND"):
    row = session.execute(text(sql), params).mappings().first()
    if row is None:
        raise APIError(404, code, "Recurso de dispositivo no disponible")
    return dict(row)


def device(session, scope, *, write=False):
    row = one(
        session,
        """
        SELECT * FROM vulntrack_devices.devices WHERE workspace_id=:workspace AND id=:device
    """,
        scope,
    )
    if write and row["status"] != "active":
        raise APIError(409, "DEVICE_RETIRED", "El dispositivo está retirado")
    return row


def lock_device(session, scope):
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:device AS text), 24))"),
        scope,
    )


def current_identification(session, scope):
    row = (
        session.execute(
            text(f"""
        SELECT * FROM vulntrack_devices.identifications WHERE {DEVICE_SCOPE}
        AND identity_generation=(SELECT identity_generation FROM vulntrack_devices.devices
                                  WHERE workspace_id=:workspace AND id=:device)
        ORDER BY created_at DESC, id DESC LIMIT 1
    """),
            scope,
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def audit(session, scope, action, resource, identifier):
    session.execute(
        text("""
        INSERT INTO vulntrack.audit_events(workspace_id,actor_id,action,object_type,object_id)
        VALUES (:workspace,:actor,:action,:resource,:identifier)
    """),
        {**scope, "action": action, "resource": resource, "identifier": identifier},
    )


def register_identification(session, scope, candidate, mode, reason, evidence=None):
    result = one(
        session,
        """
        INSERT INTO vulntrack_devices.identifications
            (id,workspace_id,device_id,recorded_by,cpe_name,cpe_name_id,mode,reason,catalog_evidence,
             created_at)
        VALUES (:id,:workspace,:device,:actor,:name,:name_id,:mode,:reason,CAST(:evidence AS jsonb),
                clock_timestamp())
        RETURNING *
    """,
        {
            **scope,
            "id": uuid4(),
            "name": candidate.cpe_name,
            "name_id": candidate.cpe_name_id,
            "mode": mode,
            "reason": reason,
            "evidence": json.dumps(evidence) if evidence else None,
        },
    )
    session.execute(
        text("""
        UPDATE vulntrack_devices.devices SET updated_at=clock_timestamp()
        WHERE workspace_id=:workspace AND id=:device
    """),
        scope,
    )
    audit(session, scope, "device.cpe_confirmed", "device_identification", result["id"])
    return result


def selected_catalog_candidate(session, selection, reader):
    if reader.is_external(selection.mode):
        with reader.connect(selection.mode) as connection:
            row = catalog_row(connection, selection.mode, selection.cpe_name_id)
    else:
        session.execute(text("SELECT pg_advisory_xact_lock_shared(2222, 1)"))
        row = catalog_row(session, selection.mode, selection.cpe_name_id)
    if (
        row["deprecated"]
        or row["cpe_name"] != selection.expected_cpe_name
        or row["nvd_modified"] != selection.expected_nvd_modified
    ):
        raise APIError(409, "CATALOG_CPE_CHANGED", "Vuelve a seleccionar un CPE vigente")
    if row["version"] == "-" or any(mark in row["version"] for mark in "*?"):
        raise APIError(409, "VERSION_REQUIRED", "Selecciona una versión concreta y observada")
    return row


def assisted_identity(session, scope, selection, reader):
    row = selected_catalog_candidate(session, selection, reader)
    if scope["product_vendor"] not in (None, row["vendor"]) or scope["product"] not in (
        None,
        row["product"],
    ):
        raise APIError(409, "CPE_PRODUCT_MISMATCH", "El producto seleccionado cambio")
    scope.update(product_vendor=row["vendor"], product=row["product"])
    if len(scope["product_vendor"]) > 120 or len(scope["product"]) > 160:
        raise APIError(
            422, "CATALOG_VALUE_UNSUPPORTED", "Identificador de producto demasiado largo"
        )
    candidate = Candidate.model_validate(row)
    validate_device_candidate(scope, candidate)
    return candidate, {
        "source": row["source"],
        "nvd_modified": row["nvd_modified"].isoformat(),
        "synchronized_at": row["synchronized_at"].isoformat(),
        "observed_version": scope["version"],
        "observed_vendor": scope["product_vendor"],
        "observed_product": scope["product"],
        "component_kind": scope["component_kind"],
    }


@router.post("", status_code=201)
def create_device(
    workspace_id: UUID,
    payload: DeviceCreate,
    user: Identity,
    request: Request,
    idempotency_key: Annotated[UUID | None, Header(alias="Idempotency-Key")] = None,
):
    selection = payload.catalog_selection
    if selection and idempotency_key is None:
        raise APIError(
            422, "IDEMPOTENCY_REQUIRED", "Idempotency-Key requerido para el alta asistida"
        )
    scope = {
        "workspace": workspace_id,
        "actor": user.id,
        "id": uuid4(),
        **payload.model_dump(exclude={"catalog_selection"}),
    }
    with access(request, user.id, workspace_id, write=True) as session:
        if idempotency_key:
            receipt = {
                **scope,
                "key": idempotency_key,
                "fingerprint": hashlib.sha256(payload.model_dump_json().encode()).hexdigest(),
            }
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:lock, 2222))"),
                {"lock": f"{workspace_id}/{user.id}/{idempotency_key}"},
            )
            previous = (
                session.execute(
                    text("""
                SELECT fingerprint,device_id,identification_id
                FROM vulntrack_catalog_private.device_registrations
                WHERE workspace_id=:workspace AND actor_id=:actor AND request_key=:key
            """),
                    receipt,
                )
                .mappings()
                .one_or_none()
            )
            if previous:
                if previous["fingerprint"] != receipt["fingerprint"]:
                    raise APIError(
                        409, "IDEMPOTENCY_CONFLICT", "La clave ya se uso con otros datos"
                    )
                replay = {
                    **scope,
                    "device": previous["device_id"],
                    "identity": previous["identification_id"],
                }
                result = device(session, replay)
                if previous["identification_id"]:
                    result["current_identification"] = one(
                        session,
                        """
                        SELECT * FROM vulntrack_devices.identifications
                        WHERE workspace_id=:workspace AND device_id=:device AND id=:identity
                    """,
                        replay,
                    )
                return result
        if selection:
            candidate, evidence = assisted_identity(
                session, scope, selection, request.app.state.catalog_reader
            )
        result = one(
            session,
            """
            INSERT INTO vulntrack_devices.devices
                (id,workspace_id,created_by,device_type,manufacturer,model,product_vendor,
                 product,component_kind,version,site_label,inventory_label,notes)
            VALUES (:id,:workspace,:actor,:device_type,:manufacturer,:model,:product_vendor,
                    :product,:component_kind,:version,:site_label,:inventory_label,:notes)
            RETURNING *
        """,
            scope,
        )
        audit(session, scope, "device.created", "device", result["id"])
        identification = None
        if selection:
            created_scope = {**scope, "device": result["id"]}
            identification = register_identification(
                session, created_scope, candidate, selection.mode, selection.reason, evidence
            )
            result = device(session, created_scope)
            result["current_identification"] = identification
        if idempotency_key:
            session.execute(
                text("""
                INSERT INTO vulntrack_catalog_private.device_registrations
                  (workspace_id,actor_id,request_key,fingerprint,device_id,identification_id)
                VALUES (:workspace,:actor,:key,:fingerprint,:device,:identification)
            """),
                {
                    **receipt,
                    "device": result["id"],
                    "identification": identification["id"] if identification else None,
                },
            )
        return result


@router.get("")
def list_devices(
    workspace_id: UUID,
    user: Identity,
    request: Request,
    q: Annotated[str, Query(max_length=120)] = "",
    device_type: DeviceType | None = None,
    status: DeviceStatus | None = None,
    limit: Limit = 20,
    offset: Offset = 0,
    manufacturer_key: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    model_key: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
):
    if any(
        ord(character) < 32 or ord(character) == 127
        for value in (q, manufacturer_key or "", model_key or "")
        for character in value
    ):
        raise APIError(422, "SEARCH_INVALID", "Texto de búsqueda inválido")
    scope = {
        "workspace": workspace_id,
        "q": q.strip(),
        "type": device_type,
        "status": status,
        "manufacturer_key": manufacturer_key,
        "model_key": model_key,
    }
    with access(request, user.id, workspace_id) as session:
        return page(
            session,
            select="""d.*, EXISTS(SELECT 1 FROM vulntrack_devices.identifications i
                WHERE i.workspace_id=d.workspace_id AND i.device_id=d.id
                AND i.identity_generation=d.identity_generation) AS cpe_confirmed""",
            table="vulntrack_devices.devices d",
            where=f"""workspace_id=:workspace AND (CAST(:type AS text) IS NULL OR device_type=:type)
                  AND (CAST(:status AS text) IS NULL OR status=:status)
                  AND (CAST(:manufacturer_key AS text) IS NULL OR
                    {label_key("manufacturer")}={label_key("CAST(:manufacturer_key AS text)")})
                  AND (CAST(:model_key AS text) IS NULL OR
                    {label_key("model")}={label_key("CAST(:model_key AS text)")})
                  AND (strpos(lower(manufacturer),lower(:q))>0
                       OR strpos(lower(model),lower(:q))>0)""",
            sort="created_at DESC,id DESC",
            scope=scope,
            limit=limit,
            offset=offset,
        )


def device_detail(session, scope):
    return one(
        session,
        f"""
        SELECT d.*, {query_state_sql("devices", "d")} AS current_cve_query_state,
            to_jsonb(i) AS current_identification,
            CASE WHEN i.id IS NOT NULL THEN 'confirmed'
                 WHEN d.identity_generation > 1 THEN 'needs_review'
                 ELSE 'pending' END AS cpe_review_state
        FROM vulntrack_devices.devices d
        LEFT JOIN LATERAL (
            SELECT * FROM vulntrack_devices.identifications
            WHERE workspace_id=d.workspace_id AND device_id=d.id
              AND identity_generation=d.identity_generation
            ORDER BY created_at DESC,id DESC LIMIT 1
        ) i ON TRUE
        WHERE d.workspace_id=:workspace AND d.id=:device
    """,
        scope,
    )


@router.get("/{device_id}")
def get_device(workspace_id: UUID, device_id: UUID, user: Identity, request: Request):
    with access(request, user.id, workspace_id) as session:
        return device_detail(session, {"workspace": workspace_id, "device": device_id})


@router.patch(
    "/{device_id}", responses={409: {"description": "Conflicto o confirmación pendiente"}}
)
def revise_device(
    workspace_id: UUID,
    device_id: UUID,
    payload: DeviceEdit,
    user: Identity,
    request: Request,
):
    scope = {"workspace": workspace_id, "device": device_id}
    with access(request, user.id, workspace_id, write=True) as session:
        lock_device(session, scope)
        edit_device(session, device(session, scope), scope, payload)
        return device_detail(session, scope)


@router.get("/{device_id}/revisions")
def list_revisions(
    workspace_id: UUID,
    device_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 20,
    offset: Offset = 0,
):
    scope = {"workspace": workspace_id, "device": device_id}
    with access(request, user.id, workspace_id) as session:
        device(session, scope)
        return page(
            session,
            select="*",
            table="vulntrack_devices.revisions",
            where=DEVICE_SCOPE,
            sort="new_version DESC",
            scope=scope,
            limit=limit,
            offset=offset,
        )


@router.get("/{device_id}/revisions/compare")
def compare_revisions(
    workspace_id: UUID,
    device_id: UUID,
    user: Identity,
    request: Request,
    from_version: Annotated[int, Query(ge=1, le=9007199254740991)],
    to_version: Annotated[int, Query(ge=1, le=9007199254740991)],
):
    scope = {"workspace": workspace_id, "device": device_id, "from": from_version, "to": to_version}
    with access(request, user.id, workspace_id) as session:
        row = device(session, scope)
        if from_version > to_version:
            raise APIError(422, "DEVICE_REVISION_ORDER", "Elige un intervalo ascendente")
        if to_version > row["record_version"]:
            raise APIError(404, "DEVICE_REVISION_NOT_FOUND", "La revisión no está disponible")

        def values(version):
            if version == row["record_version"]:
                return {field: row[field] for field in EDITABLE if field != "notes"}
            return session.scalar(
                text(f"""
                SELECT CASE WHEN :version=1 THEN previous_values ELSE new_values END
                FROM vulntrack_devices.revisions WHERE {DEVICE_SCOPE}
                  AND new_version=greatest(2,:version)
            """),
                {**scope, "version": version},
            )

        previous, latest = values(from_version), values(to_version)
        fields = [name for name in previous if previous[name] != latest[name]]
        if session.scalar(
            text(f"""
            SELECT EXISTS(SELECT 1 FROM vulntrack_devices.revisions WHERE {DEVICE_SCOPE}
               AND new_version > :from AND new_version <= :to AND 'notes'=ANY(changed_fields))
        """),
            scope,
        ):
            fields.append("notes")
        return {
            "from_version": from_version,
            "to_version": to_version,
            "previous_values": previous,
            "new_values": latest,
            "changed_fields": fields,
        }


@router.patch("/{device_id}/status")
def update_status(
    workspace_id: UUID,
    device_id: UUID,
    payload: DeviceStatusUpdate,
    user: Identity,
    request: Request,
):
    scope = {
        "workspace": workspace_id,
        "device": device_id,
        "actor": user.id,
        "status": payload.status,
    }
    with access(request, user.id, workspace_id, write=True) as session:
        lock_device(session, scope)
        edit_reason(session, "Cambio de estado por la ruta de inventario")
        result = one(
            session,
            """
            UPDATE vulntrack_devices.devices SET status=:status,updated_at=clock_timestamp()
            WHERE workspace_id=:workspace AND id=:device RETURNING *
        """,
            scope,
        )
        audit(session, scope, "device.status_changed", "device", device_id)
        return result


@router.get("/{device_id}/cpe-candidates", response_model=CandidateList)
def cpe_candidates(
    workspace_id: UUID,
    device_id: UUID,
    user: Identity,
    request: Request,
    query: Annotated[str, Query(min_length=2, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=20)] = 10,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
):
    scope = {"workspace": workspace_id, "device": device_id}
    with access(request, user.id, workspace_id) as session:
        device(session, scope)
    try:
        search = SearchInput(query=query, limit=limit, offset=offset)
    except ValidationError:
        raise APIError(422, "SEARCH_INVALID", "Texto de búsqueda inválido") from None
    return request.app.state.nvd.search(user.id, search)


@router.post("/{device_id}/identifications", status_code=201)
def confirm_identification(
    workspace_id: UUID,
    device_id: UUID,
    payload: DeviceIdentificationCreate,
    user: Identity,
    request: Request,
):
    scope = {"workspace": workspace_id, "device": device_id, "actor": user.id}
    with access(request, user.id, workspace_id, write=True) as session:
        row = device(session, scope, write=True)
        expected_record = row["record_version"]
        if row["version"] is None:
            raise APIError(
                409, "VERSION_REQUIRED", "Registra una versión conocida antes de confirmar"
            )

    candidate, _ = request.app.state.nvd.resolve(user.id, payload.cpe_name_id)
    with access(request, user.id, workspace_id, write=True) as session:
        device(session, scope, write=True)
        lock_device(session, scope)
        row = device(session, scope, write=True)
        require_version(row, expected_record)
        current = current_identification(session, scope)
        if (current["id"] if current else None) != payload.expected_identification_id:
            raise APIError(409, "CPE_SELECTION_CHANGED", "La identificación vigente cambió")
        validate_device_candidate(row, candidate)
        return register_identification(
            session,
            scope,
            candidate,
            request.app.state.nvd_mode,
            payload.reason,
            {
                "observed_vendor": row["product_vendor"],
                "observed_product": row["product"],
                "observed_version": row["version"],
                "component_kind": row["component_kind"],
            },
        )


@router.post(
    "/{device_id}/reidentification",
    status_code=201,
    responses={409: {"description": "Candidato o revisión en conflicto"}},
)
def reidentify_device(
    workspace_id: UUID,
    device_id: UUID,
    payload: DeviceReidentification,
    user: Identity,
    request: Request,
):
    scope = {"workspace": workspace_id, "device": device_id, "actor": user.id}
    with access(request, user.id, workspace_id, write=True) as session:
        lock_device(session, scope)
        row = device(session, scope, write=True)
        require_version(row, payload.expected_record_version)
        current = current_identification(session, scope)
        if (current["id"] if current else None) != payload.expected_identification_id:
            raise APIError(409, "CPE_SELECTION_CHANGED", "La identificación vigente cambió")
        record = selected_catalog_candidate(session, payload, request.app.state.catalog_reader)
        candidate = Candidate.model_validate(record)
        validate_device_candidate(row, candidate)
        evidence = {
            "source": record["source"],
            "nvd_modified": record["nvd_modified"].isoformat(),
            "cpe_name_id": str(candidate.cpe_name_id),
            "observed_vendor": row["product_vendor"],
            "observed_product": row["product"],
            "observed_version": row["version"],
            "component_kind": row["component_kind"],
        }
        return register_identification(
            session, scope, candidate, payload.mode, payload.reason, evidence
        )


@router.get("/{device_id}/identifications")
def list_identifications(
    workspace_id: UUID,
    device_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 20,
    offset: Offset = 0,
):
    scope = {"workspace": workspace_id, "device": device_id}
    with access(request, user.id, workspace_id) as session:
        device(session, scope)
        return page(
            session,
            select="*",
            table="vulntrack_devices.identifications",
            where=DEVICE_SCOPE,
            sort="created_at DESC,id DESC",
            scope=scope,
            limit=limit,
            offset=offset,
        )


def run(session, scope):
    return decorate(
        session,
        session.info["cve_settings"],
        "devices",
        [
            present_run(
                one(
                    session,
                    f"""
        SELECT {RUN_FIELDS} FROM vulntrack_devices.runs WHERE {DEVICE_SCOPE} AND id=:run
    """,
                    scope,
                    "DEVICE_RUN_NOT_FOUND",
                )
            )
        ],
    )[0]


@router.post("/{device_id}/analyses", status_code=201)
def analyze_device(
    workspace_id: UUID,
    device_id: UUID,
    user: Identity,
    request: Request,
    idempotency_key: IdempotencyKey,
):
    scope = {
        "workspace": workspace_id,
        "device": device_id,
        "actor": user.id,
        "key": UUID(idempotency_key),
        "run": uuid4(),
    }
    mode = request.app.state.nvd_mode
    with access(request, user.id, workspace_id, write=True) as session:
        device(session, scope)
        lock_device(session, scope)
        row = device(session, scope)
        before = session.scalar(
            text(f"""
            SELECT id FROM vulntrack_devices.runs
            WHERE {DEVICE_SCOPE} AND initiated_by=:actor AND request_key=:key
        """),
            scope,
        )
        if before:
            return run(session, {**scope, "run": before})
        if row["status"] != "active":
            raise APIError(409, "DEVICE_RETIRED", "El dispositivo está retirado")
        selected = current_identification(session, scope)
        if not selected or row["version"] is None:
            raise APIError(409, "CPE_CONFIRMATION_REQUIRED", "Confirma un CPE con versión conocida")
        validate_device_cpe(row, selected["cpe_name"])
        if mode == "live" and selected["mode"] != "live":
            raise APIError(
                409, "CPE_MODE_CHANGED", "Vuelve a confirmar el CPE en el modo NVD actual"
            )
        if session.scalar(
            text(f"""
            SELECT id FROM vulntrack_devices.runs WHERE {DEVICE_SCOPE} AND status='running'
        """),
            scope,
        ):
            raise APIError(
                409, "ANALYSIS_IN_PROGRESS", "Ya existe una consulta activa para este dispositivo"
            )
        request.app.state.nvd.quota.check_user(user.id, "cve")
        session.execute(
            text("""
            INSERT INTO vulntrack_devices.runs (id,workspace_id,device_id,identification_id,
                initiated_by,request_key,selected_cpe,observed_version,mode,run_context,lease_expires_at)
            VALUES (:run,:workspace,:device,:identification,:actor,:key,:cpe,:version,:mode,
                    CAST(:context AS jsonb),clock_timestamp()+make_interval(secs=>:seconds))
        """),
            {
                **scope,
                "identification": selected["id"],
                "cpe": selected["cpe_name"],
                "version": row["version"],
                # The legacy column is bound to the CPE identification by the DB guard.
                # CVE transport provenance is independent and lives in run_context.
                "mode": selected["mode"],
                "context": json.dumps(
                    query_context(
                        request,
                        identification_id=selected["id"],
                        cpe_mode=selected["mode"],
                        cpe_source=(selected.get("catalog_evidence") or {}).get("source"),
                        vendor=row["product_vendor"],
                        product=row["product"],
                        version=row["version"],
                    )
                ),
                "seconds": request.app.state.settings.cve_execution_seconds,
            },
        )
        audit(session, scope, "device.analysis_requested", "device_analysis", scope["run"])

    # NVD is called without any database connection or transaction.
    try:
        upstream = request.app.state.cve.page(selected["cpe_name"], 0, 100)
        records, findings, warnings = finding_rows(upstream, selected["cpe_name"], row["version"])
        partial = upstream.totalResults > len(records)
        if partial:
            warnings.append("PAGE_BUDGET_REACHED")
        with access(request, user.id, workspace_id, write=True) as session:
            lock_device(session, scope)
            require_active(session, "devices", workspace_id, scope["run"])
            for entry in findings:
                session.execute(
                    text("""
                    INSERT INTO vulntrack_devices.findings (id,workspace_id,device_id,analysis_id,
                        external_id,title,severity,cvss,applicability,evidence,
                        published_at,last_modified_at)
                    VALUES (:id,:workspace,:device,:run,:external_id,:title,:severity,
                            CAST(:cvss AS jsonb),:applicability,
                            CAST(:evidence AS jsonb),:published,:modified)
                """),
                    {**entry, **scope},
                )
            session.execute(
                text(f"""
                UPDATE vulntrack_devices.runs SET status='completed',coverage=:coverage,
                    completed_at=clock_timestamp(),response_received_at=clock_timestamp(),
                    total_results=:total,
                    retrieved_count=:retrieved,
                    stored_count=:stored, source_timestamp=:timestamp,
                    warning_codes=CAST(:warnings AS jsonb)
                WHERE {DEVICE_SCOPE} AND id=:run AND status='running'
            """),
                {
                    **scope,
                    "coverage": "partial" if partial else "complete",
                    "total": upstream.totalResults,
                    "retrieved": len(records),
                    "stored": len(findings),
                    "timestamp": upstream.timestamp,
                    "warnings": json.dumps(sorted(set(warnings))),
                },
            )
            return run(session, scope)
    except Exception as exc:
        code = exc.code if isinstance(exc, APIError) else "PROCESSING_ERROR"
        try:
            with access(request, user.id, workspace_id, write=True) as session:
                session.execute(
                    text(f"""
                    UPDATE vulntrack_devices.runs SET status='failed',
                        completed_at=clock_timestamp(),
                        failure_code=:code WHERE {DEVICE_SCOPE} AND id=:run AND status='running'
                """),
                    {**scope, "code": code},
                )
        except Exception:
            logger.error("device_analysis_failed_to_finalize run_id=%s", scope["run"])
        if isinstance(exc, APIError):
            raise
        logger.error(
            "device_analysis_processing_error run_id=%s type=%s", scope["run"], type(exc).__name__
        )
        raise APIError(
            503, "NVD_PROCESSING_FAILED", "No se pudo completar la consulta NVD"
        ) from None


@router.get("/{device_id}/analyses")
def list_analyses(
    workspace_id: UUID,
    device_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 20,
    offset: Offset = 0,
):
    scope = {"workspace": workspace_id, "device": device_id}
    with access(request, user.id, workspace_id) as session:
        device(session, scope)
        result = page(
            session,
            select=RUN_FIELDS,
            table="vulntrack_devices.runs",
            where=DEVICE_SCOPE,
            sort="created_at DESC,id DESC",
            scope=scope,
            limit=limit,
            offset=offset,
        )
        result["items"] = decorate(
            session,
            request.app.state.settings,
            "devices",
            [present_run(item) for item in result["items"]],
        )
        return result


@router.get("/{device_id}/analyses/{run_id}")
def get_analysis(
    workspace_id: UUID, device_id: UUID, run_id: UUID, user: Identity, request: Request
):
    with access(request, user.id, workspace_id) as session:
        return run(session, {"workspace": workspace_id, "device": device_id, "run": run_id})


@router.get("/{device_id}/analyses/{run_id}/findings")
def list_findings(
    workspace_id: UUID,
    device_id: UUID,
    run_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 20,
    offset: Offset = 0,
):
    scope = {"workspace": workspace_id, "device": device_id, "run": run_id}
    with access(request, user.id, workspace_id) as session:
        analysis = run(session, scope)
        result = page(
            session,
            select=FINDING_FIELDS,
            table="vulntrack_devices.findings",
            where=DEVICE_SCOPE + " AND analysis_id=:run",
            sort="external_id,id",
            scope=scope,
            limit=limit,
            offset=offset,
        )
        return result | {"analysis": analysis}


def finding(session, scope):
    return one(
        session,
        f"""
        SELECT {FINDING_FIELDS} FROM vulntrack_devices.findings WHERE {DEVICE_SCOPE} AND id=:finding
    """,
        scope,
        "DEVICE_FINDING_NOT_FOUND",
    )


@router.patch("/{device_id}/findings/{finding_id}")
def review_finding(
    workspace_id: UUID,
    device_id: UUID,
    finding_id: UUID,
    payload: DeviceFindingReview,
    user: Identity,
    request: Request,
):
    scope = {
        "workspace": workspace_id,
        "device": device_id,
        "finding": finding_id,
        "actor": user.id,
        **payload.model_dump(),
    }
    with access(request, user.id, workspace_id, write=True) as session:
        finding(session, scope)
        result = (
            session.execute(
                text(f"""
            UPDATE vulntrack_devices.findings SET applicability=:applicability, status='reviewed',
                reviewed_by=:actor, review_reason=:reason, review_evidence=:evidence,
                updated_at=clock_timestamp()
            WHERE {DEVICE_SCOPE} AND id=:finding AND status='open'
              AND updated_at=:expected_updated_at
            RETURNING {FINDING_FIELDS}
        """),
                scope,
            )
            .mappings()
            .first()
        )
        if result is None:
            raise APIError(
                409, "REVIEW_CONFLICT", "El hallazgo ya cambió. Actualiza antes de revisar."
            )
        audit(session, scope, "device.finding_reviewed", "device_finding", finding_id)
        return dict(result)


@router.get("/{device_id}/findings/{finding_id}/recommendations")
def list_recommendations(
    workspace_id: UUID,
    device_id: UUID,
    finding_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 20,
    offset: Offset = 0,
):
    scope = {"workspace": workspace_id, "device": device_id, "finding": finding_id}
    with access(request, user.id, workspace_id) as session:
        finding(session, scope)
        return page(
            session,
            select=RECOMMENDATION_FIELDS,
            table="vulntrack_devices.recommendations",
            where=DEVICE_SCOPE + " AND finding_id=:finding",
            sort="created_at DESC,id DESC",
            scope=scope,
            limit=limit,
            offset=offset,
        )


@router.post("/{device_id}/findings/{finding_id}/recommendations", status_code=201)
def create_recommendation(
    workspace_id: UUID,
    device_id: UUID,
    finding_id: UUID,
    payload: DeviceRecommendationCreate,
    user: Identity,
    request: Request,
    idempotency_key: IdempotencyKey,
):
    scope = {
        "workspace": workspace_id,
        "device": device_id,
        "finding": finding_id,
        "actor": user.id,
        "key": UUID(idempotency_key),
        "id": uuid4(),
        **payload.model_dump(),
    }
    with access(request, user.id, workspace_id, write=True) as session:
        finding(session, scope)
        lock_device(session, scope)
        existing = (
            session.execute(
                text(f"""
            SELECT {RECOMMENDATION_FIELDS} FROM vulntrack_devices.recommendations
            WHERE {DEVICE_SCOPE} AND finding_id=:finding AND created_by=:actor AND request_key=:key
        """),
                scope,
            )
            .mappings()
            .first()
        )
        if existing:
            if existing["recommendation"] != payload.recommendation:
                raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otra solicitud")
            return dict(existing)
        result = one(
            session,
            f"""
            INSERT INTO vulntrack_devices.recommendations
                (id,workspace_id,device_id,finding_id,created_by,request_key,recommendation)
            VALUES (:id,:workspace,:device,:finding,:actor,:key,:recommendation)
            RETURNING {RECOMMENDATION_FIELDS}
        """,
            scope,
        )
        audit(
            session, scope, "device.recommendation_created", "device_recommendation", result["id"]
        )
        return result
