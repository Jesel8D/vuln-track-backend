"""Authorized web targets inventory for Database V2 applications."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from app.api.router import Identity
from app.core.errors import APIError
from app.db.pagination import page
from app.db.workspace_context import workspace_session
from app.services.web_target_authorization import public_target
from app.services.web_target_policy import INVENTORY_POLICY, DestinationDenied

router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets")
workspace_router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/targets")


def _authorize(session, workspace_id, application_id, write=False):
    roles = "ARRAY['owner','editor']" if write else "ARRAY['owner','editor','viewer']"
    if not session.scalar(
        text(f"SELECT vulntrack.has_workspace_role(:workspace, {roles})"),
        {"workspace": workspace_id},
    ):
        raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
    if not session.scalar(
        text("""SELECT 1 FROM vulntrack.applications
            WHERE workspace_id=:workspace AND id=:application
              AND (NOT :write OR status='active')"""),
        {"workspace": workspace_id, "application": application_id, "write": write},
    ):
        raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=8, max_length=2048)
    label: str | None = Field(default=None, max_length=120)

    @field_validator("url")
    @classmethod
    def valid_target_url(cls, value):
        try:
            return INVENTORY_POLICY.parse(value).url
        except DestinationDenied:
            raise ValueError(
                "Destino HTTP(S) público válido, sin credenciales y en puerto estándar"
            ) from None

    @field_validator("label", mode="before")
    @classmethod
    def clean_label(cls, value):
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        result = " ".join(value.split())
        if not result or any(ord(char) < 32 for char in result):
            raise ValueError("Etiqueta inválida")
        return result


class TargetAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authorization_status: Literal["approved", "rejected"]
    authorization_expires_at: datetime | None = None
    authorization_reference: str = Field(min_length=1, max_length=500)
    expected_updated_at: datetime

    @field_validator("authorization_expires_at")
    @classmethod
    def expiry_aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("La vigencia requiere zona horaria")
        return value

    @field_validator("expected_updated_at")
    @classmethod
    def expected_time_aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("expected_updated_at requiere zona horaria")
        return value

    @field_validator("authorization_reference", mode="before")
    @classmethod
    def clean_reference(cls, value):
        if not isinstance(value, str):
            return value
        result = " ".join(value.split())
        if not result or any(ord(char) < 32 for char in result):
            raise ValueError("Referencia inválida")
        return result


def _present_target(row, workspace_id, application_id):
    # JSON pages preserve timestamps as ISO strings; policy evaluation expects
    # aware datetime values, exactly as the original SQL row mapping did.
    for key in ("authorization_expires_at", "created_at", "updated_at"):
        if isinstance(row.get(key), str):
            row[key] = datetime.fromisoformat(row[key])
    return public_target(row, workspace_id, application_id)


TargetState = Literal["pending", "approved", "rejected", "expired"]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=1000000)]
TARGET_FIELDS = """t.id,t.url,t.label,
    CASE WHEN t.authorization_status='approved'
              AND t.authorization_expires_at <= statement_timestamp()
         THEN 'expired' ELSE t.authorization_status END AS authorization_status,
    t.authorization_expires_at,t.authorization_reference,t.created_at,t.updated_at"""
TARGET_FILTER = """t.workspace_id=:workspace
    AND (:q='' OR strpos(lower(t.url||' '||coalesce(t.label,'')),lower(:q))>0)
    AND (CAST(:state AS text) IS NULL OR
        CASE WHEN t.authorization_status='approved'
                  AND t.authorization_expires_at <= statement_timestamp()
             THEN 'expired' ELSE t.authorization_status END = :state)"""


@workspace_router.get("")
def list_workspace_targets(
    workspace_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Offset = 0,
    q: Annotated[str, Query(max_length=160)] = "",
    authorization_status: TargetState | None = None,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text(
                "SELECT vulntrack.has_workspace_role(:workspace,ARRAY['owner','editor','viewer'])"
            ),
            {"workspace": workspace_id},
        ):
            raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no disponible")
        result = page(
            session,
            select=TARGET_FIELDS + ",t.application_id,a.name AS application_name,"
            "a.status AS application_status",
            table="vulntrack.application_targets t JOIN vulntrack.applications a "
            "ON a.workspace_id=t.workspace_id AND a.id=t.application_id",
            where=TARGET_FILTER,
            sort="created_at DESC,id",
            scope={"workspace": workspace_id, "q": q.strip(), "state": authorization_status},
            limit=limit,
            offset=offset,
        )
        result["items"] = [
            _present_target(row, workspace_id, row["application_id"]) for row in result["items"]
        ]
        return result


@router.get("")
def list_targets(
    workspace_id: UUID,
    application_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 100,
    offset: Offset = 0,
    q: Annotated[str, Query(max_length=160)] = "",
    authorization_status: TargetState | None = None,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id)
        result = page(
            session,
            select=TARGET_FIELDS,
            table="vulntrack.application_targets t",
            where=TARGET_FILTER + " AND t.application_id=:application",
            sort="created_at,id",
            scope={
                "workspace": workspace_id,
                "application": application_id,
                "q": q.strip(),
                "state": authorization_status,
            },
            limit=limit,
            offset=offset,
        )
        result["items"] = [
            _present_target(row, workspace_id, application_id) for row in result["items"]
        ]
        return result


@router.post("", status_code=201)
def create_target(
    workspace_id: UUID,
    application_id: UUID,
    payload: TargetCreate,
    user: Identity,
    request: Request,
):
    target_id = uuid4()
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, write=True)
        session.execute(
            text("""SELECT id FROM vulntrack.applications
                WHERE workspace_id=:workspace AND id=:application FOR UPDATE"""),
            {"workspace": workspace_id, "application": application_id},
        ).first()
        count = session.scalar(
            text("""SELECT count(*) FROM vulntrack.application_targets
                WHERE workspace_id=:workspace AND application_id=:application"""),
            {"workspace": workspace_id, "application": application_id},
        )
        if count >= 100:
            raise APIError(409, "TARGET_LIMIT", "La aplicación alcanzó el límite de 100 destinos")
        row = (
            session.execute(
                text("""INSERT INTO vulntrack.application_targets
                (id,workspace_id,application_id,url,label,created_by)
                VALUES (:id,:workspace,:application,:url,:label,:actor)
                RETURNING id,url,label,authorization_status,authorization_expires_at,
                    authorization_reference,created_at,updated_at"""),
                {
                    "id": target_id,
                    "workspace": workspace_id,
                    "application": application_id,
                    "url": payload.url,
                    "label": payload.label,
                    "actor": user.id,
                },
            )
            .mappings()
            .one()
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'target.created','application_target',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": target_id},
        )
        return public_target(row, workspace_id, application_id)


@router.patch("/{target_id}/authorization")
def update_target_authorization(
    workspace_id: UUID,
    application_id: UUID,
    target_id: UUID,
    payload: TargetAuthorization,
    user: Identity,
    request: Request,
):
    now = datetime.now(UTC)
    if payload.authorization_status == "approved":
        if (
            payload.authorization_expires_at is None
            or not now < payload.authorization_expires_at <= now + timedelta(days=365)
        ):
            raise APIError(
                422,
                "AUTHORIZATION_EXPIRY_INVALID",
                "La autorización debe vencer dentro del próximo año",
            )
    elif payload.authorization_expires_at is not None:
        raise APIError(
            422, "AUTHORIZATION_EXPIRY_INVALID", "Un destino rechazado no debe tener vigencia"
        )

    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        _authorize(session, workspace_id, application_id, write=True)
        current = (
            session.execute(
                text("""SELECT updated_at,authorization_status FROM vulntrack.application_targets
                WHERE workspace_id=:workspace AND application_id=:application AND id=:id
                FOR UPDATE"""),
                {"workspace": workspace_id, "application": application_id, "id": target_id},
            )
            .mappings()
            .first()
        )
        if current is None:
            raise APIError(404, "TARGET_NOT_FOUND", "Destino no disponible")
        if current["updated_at"] != payload.expected_updated_at:
            raise APIError(
                409, "TARGET_AUTHORIZATION_CONFLICT", "El destino cambió; actualiza la vista"
            )
        row = (
            session.execute(
                text("""UPDATE vulntrack.application_targets SET
                authorization_status=:status,authorization_expires_at=:expires,
                authorization_reference=:reference
                WHERE workspace_id=:workspace AND application_id=:application AND id=:id
                RETURNING id,url,label,authorization_status,authorization_expires_at,
                    authorization_reference,created_at,updated_at"""),
                {
                    "status": payload.authorization_status,
                    "expires": payload.authorization_expires_at
                    if payload.authorization_status == "approved"
                    else None,
                    "reference": payload.authorization_reference,
                    "workspace": workspace_id,
                    "application": application_id,
                    "id": target_id,
                },
            )
            .mappings()
            .first()
        )
        if row is None:
            raise APIError(404, "TARGET_NOT_FOUND", "Destino no disponible")
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,:action,'application_target',:object)"""),
            {
                "workspace": workspace_id,
                "actor": user.id,
                "action": (
                    "target.authorization.withdrawn"
                    if current["authorization_status"] == "approved"
                    and payload.authorization_status == "rejected"
                    else f"target.authorization.{payload.authorization_status}"
                ),
                "object": target_id,
            },
        )
        return public_target(row, workspace_id, application_id)
