"""Minimal V2 workspace, application and technology resources used by NVD flows."""

import unicodedata
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Query, Request
from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.api.router import Identity
from app.core.errors import APIError
from app.db.workspace_context import list_user_workspaces, workspace_session

router = APIRouter(prefix="/api/v2")
Name = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=160)]
Version = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=120)]


class WorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=120)]

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value):
        return _clean(value)


class ApplicationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name
    description: Annotated[str, StringConstraints(strict=True, max_length=2000)] | None = None

    @field_validator("name", "description", mode="before")
    @classmethod
    def normalize_text(cls, value):
        return _clean(value) if value is not None else None


class TechnologyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product: Name
    vendor: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=160)] | None = (
        None
    )
    version: Version
    detection_method: Literal["manual", "http_fingerprint", "manifest_import"] = "manual"

    @field_validator("product", "vendor", "version", mode="before")
    @classmethod
    def normalize_text(cls, value):
        return _clean(value) if value is not None else None


def _clean(value):
    if value is None:
        return None
    normalized = " ".join(unicodedata.normalize("NFKC", value).strip().split())
    if not normalized:
        raise ValueError("El texto no puede estar vacío")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise ValueError("El texto contiene caracteres de control")
    return normalized


@router.post("/workspaces", status_code=201)
def create_workspace(
    payload: WorkspaceCreate,
    user: Identity,
    request: Request,
    idempotency_key: Annotated[
        str,
        Header(
            alias="Idempotency-Key",
            min_length=36,
            max_length=36,
            pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        ),
    ],
):
    workspace_id = UUID(idempotency_key)
    name = _clean(payload.name)
    with workspace_session(
        request.app.state.session_factory,
        request.app.state.settings,
        user.id,
        workspace_id,
        bootstrap=True,
    ) as session:
        existing = (
            session.execute(
                text("SELECT id,name,created_by FROM vulntrack.workspaces WHERE id=:id"),
                {"id": workspace_id},
            )
            .mappings()
            .first()
        )
        if existing:
            if existing["created_by"] != user.id or existing["name"] != name:
                raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otro workspace")
            return {"id": str(existing["id"]), "name": existing["name"]}
        inserted = True
        try:
            # Neither RETURNING nor ON CONFLICT: both require visibility of the new row
            # before its first membership exists under the published SELECT RLS policy.
            # A savepoint arbitrates duplicate UUIDs without rolling back signed context.
            with session.begin_nested():
                session.execute(
                    text("""INSERT INTO vulntrack.workspaces(id,name,created_by)
                        VALUES (:id,:name,:actor)"""),
                    {"id": workspace_id, "name": name, "actor": user.id},
                )
        except IntegrityError as error:
            if (
                getattr(error.orig, "sqlstate", None) != "23505"
                or getattr(getattr(error.orig, "diag", None), "constraint_name", None)
                != "workspaces_pkey"
            ):
                raise
            inserted = False
        if not inserted:
            existing = (
                session.execute(
                    text("SELECT id,name,created_by FROM vulntrack.workspaces WHERE id=:id"),
                    {"id": workspace_id},
                )
                .mappings()
                .first()
            )
            if existing and existing["created_by"] == user.id and existing["name"] == name:
                return {"id": str(existing["id"]), "name": existing["name"]}
            raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otro workspace")
        session.execute(
            text(
                "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                "VALUES (:id,:actor,'owner')"
            ),
            {"id": workspace_id, "actor": user.id},
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'workspace.created','workspace',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": workspace_id},
        )
    return {"id": str(workspace_id), "name": name}


@router.get("/workspaces")
def get_my_workspaces(user: Identity, request: Request):
    return {
        "items": list_user_workspaces(
            request.app.state.session_factory, request.app.state.settings, user.id
        )
    }


@router.get("/workspaces/{workspace_id}")
def get_workspace(workspace_id: UUID, user: Identity, request: Request):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        row = (
            session.execute(
                text(
                    "SELECT id,name,created_by,created_at,updated_at "
                    "FROM vulntrack.workspaces WHERE id=:id"
                ),
                {"id": workspace_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no encontrado")
        return dict(row)


@router.post("/workspaces/{workspace_id}/applications", status_code=201)
def create_application(
    workspace_id: UUID, payload: ApplicationCreate, user: Identity, request: Request
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text("SELECT vulntrack.has_workspace_role(:id, ARRAY['owner','editor'])"),
            {"id": workspace_id},
        ):
            raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no encontrado")
        application_id = uuid4()
        row = (
            session.execute(
                text(
                    """INSERT INTO
                    vulntrack.applications(id,workspace_id,name,description,created_by)
                VALUES (:id,:workspace,:name,:description,:actor)
                RETURNING id,name,description,status,created_at,updated_at"""
                ),
                {
                    "id": application_id,
                    "workspace": workspace_id,
                    "name": payload.name,
                    "description": payload.description,
                    "actor": user.id,
                },
            )
            .mappings()
            .one()
        )
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'application.created','application',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": application_id},
        )
        return dict(row)


@router.get("/workspaces/{workspace_id}/applications")
def list_applications(
    workspace_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
    q: Annotated[str, Query(max_length=160)] = "",
    application_id: UUID | None = None,
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
        result = (
            session.execute(
                text("""WITH matches AS MATERIALIZED (
                SELECT id,name,description,status,created_at,updated_at
                FROM vulntrack.applications a WHERE workspace_id=:workspace
                  AND (CAST(:application AS uuid) IS NULL OR id=:application)
                  AND (:q='' OR strpos(lower(name||' '||coalesce(description,'')),lower(:q))>0
                    OR EXISTS (SELECT 1 FROM vulntrack.application_targets t
                        WHERE t.workspace_id=a.workspace_id AND t.application_id=a.id
                          AND strpos(lower(t.url),lower(:q))>0))
            ) SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.created_at DESC,p.id),'[]') AS items,
                (SELECT count(*) FROM matches) AS total
            FROM (SELECT * FROM matches ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset) p
            """),
                {
                    "workspace": workspace_id,
                    "application": application_id,
                    "q": q.strip(),
                    "limit": limit,
                    "offset": offset,
                },
            )
            .mappings()
            .one()
        )
        return {
            "items": result["items"],
            "page": {"limit": limit, "offset": offset, "total": result["total"]},
        }


@router.post(
    "/workspaces/{workspace_id}/applications/{application_id}/technologies", status_code=201
)
def create_technology(
    workspace_id: UUID,
    application_id: UUID,
    payload: TechnologyCreate,
    user: Identity,
    request: Request,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text("SELECT vulntrack.has_workspace_role(:id, ARRAY['owner','editor'])"),
            {"id": workspace_id},
        ):
            raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
        if not session.scalar(
            text(
                "SELECT 1 FROM vulntrack.applications "
                "WHERE workspace_id=:workspace AND id=:application"
            ),
            {"workspace": workspace_id, "application": application_id},
        ):
            raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
        technology_id = uuid4()
        row = (
            session.execute(
                text(
                    """INSERT INTO vulntrack.technologies
                (id,workspace_id,application_id,product,vendor,version,detection_method,created_by)
                VALUES (:id,:workspace,:application,:product,:vendor,:version,:method,:actor)
                RETURNING
                id,product,vendor,version,selected_cpe,detection_method,confidence,observed_at"""
                ),
                {
                    "id": technology_id,
                    "workspace": workspace_id,
                    "application": application_id,
                    "product": payload.product,
                    "vendor": payload.vendor,
                    "version": payload.version,
                    "method": payload.detection_method,
                    "actor": user.id,
                },
            )
            .mappings()
            .first()
        )
        if row is None:
            raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
        session.execute(
            text("""INSERT INTO vulntrack.audit_events
                (workspace_id,actor_id,action,object_type,object_id)
                VALUES (:workspace,:actor,'technology.created','technology',:object)"""),
            {"workspace": workspace_id, "actor": user.id, "object": technology_id},
        )
        return dict(row)


@router.get("/workspaces/{workspace_id}/applications/{application_id}/technologies")
def list_technologies(
    workspace_id: UUID,
    application_id: UUID,
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text("""SELECT 1 FROM vulntrack.applications
                WHERE workspace_id=:workspace AND id=:application"""),
            {"workspace": workspace_id, "application": application_id},
        ):
            raise APIError(404, "APPLICATION_NOT_FOUND", "Aplicación no disponible")
        result = (
            session.execute(
                text("""WITH matches AS MATERIALIZED (SELECT
                    t.id,t.product,t.vendor,t.version,t.selected_cpe,t.detection_method,
                    t.confidence,t.observed_at,t.created_at
                    FROM vulntrack.technologies t WHERE t.workspace_id=:workspace
                      AND t.application_id=:application
                ) SELECT coalesce(jsonb_agg((to_jsonb(p)-'created_at') ||
                    jsonb_build_object('cpe_confirmation',c.confirmation)
                    ORDER BY p.created_at DESC,p.id),'[]') AS items,
                    (SELECT count(*) FROM matches) AS total,
                    (SELECT count(*) FROM matches WHERE selected_cpe IS NOT NULL
                        AND confidence='user_confirmed') AS confirmed
                FROM (SELECT * FROM matches ORDER BY created_at DESC,id
                    LIMIT :limit OFFSET :offset) p
                LEFT JOIN LATERAL (
                    SELECT to_jsonb(h)-'catalog_evidence' AS confirmation
                    FROM vulntrack_technology_cpe.confirmations h
                    WHERE h.workspace_id=:workspace AND h.application_id=:application
                      AND h.technology_id=p.id ORDER BY event_number DESC LIMIT 1
                ) c ON TRUE"""),
                {
                    "workspace": workspace_id,
                    "application": application_id,
                    "limit": limit,
                    "offset": offset,
                },
            )
            .mappings()
            .one()
        )
        return {
            "items": result["items"],
            "page": {"limit": limit, "offset": offset, "total": result["total"]},
            "summary": {"confirmed_cpe": result["confirmed"]},
        }
