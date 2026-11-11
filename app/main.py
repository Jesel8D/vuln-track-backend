import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError, TimeoutError
from starlette.exceptions import HTTPException

from app.api.analyses import router as analyses_router
from app.api.cpe import router as cpe_router
from app.api.router import router
from app.api.v2_nvd import router as v2_nvd_router
from app.api.v2_resources import router as v2_resources_router
from app.api.v2_targets import (
    router as v2_targets_router,
    workspace_router as v2_workspace_targets_router,
)
from app.core.config import Settings, get_settings
from app.core.cors import BrowserCORSMiddleware
from app.core.errors import APIError
from app.core.http import RequestBoundary, error_body
from app.core.security import LoginLimiter
from app.db.session import build_engine, build_session_factory
from app.integrations.nvd import NVDClient
from app.integrations.nvd_cve import CVEClient
from app.services.analyses import AnalysisService
from app.services.assets import AssetService
from app.services.authorization import AssetAuthorization
from app.services.cpe import IdentificationService
from app.services.cve_worker import CVEWorker

logger = logging.getLogger("vulntrack")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = build_engine(settings)

    @asynccontextmanager
    async def lifespan(app):
        if settings.cve_worker_enabled:
            app.state.cve_worker.start()
        try:
            yield
        finally:
            app.state.cve_worker.close()
            engine.dispose()

    app = FastAPI(title="VulnTrack API", version="0.2.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.assets = AssetService(app.state.session_factory, AssetAuthorization())
    app.state.nvd = NVDClient(settings.nvd_api_key, settings.nvd_timeout_seconds)
    app.state.identifications = IdentificationService(
        app.state.session_factory,
        AssetAuthorization(),
        app.state.nvd,
    )
    app.state.cve = CVEClient(
        settings.nvd_api_key, settings.nvd_timeout_seconds, quota=app.state.nvd.quota
    )
    app.state.analyses = AnalysisService(app.state.session_factory, AssetAuthorization())
    app.state.cve_worker = CVEWorker(engine, app.state.session_factory, app.state.cve)
    app.state.analyses.worker_ready = lambda: app.state.cve_worker.available
    app.state.login_limiter = LoginLimiter(settings.login_attempts_per_minute)
    app.add_middleware(RequestBoundary, max_body_bytes=settings.max_body_bytes)
    # Outside RequestBoundary: CORS also wraps its 413 and sanitized 500 responses.
    app.add_middleware(
        BrowserCORSMiddleware, allow_origins=settings.cors_origins, max_age=settings.cors_max_age
    )

    def response(request, status, code, message):
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else {}
        if status in {429, 503}:
            headers["Retry-After"] = "60" if status == 429 else "3"
        return JSONResponse(
            error_body(code, message, request.state.request_id), status_code=status, headers=headers
        )

    @app.exception_handler(APIError)
    async def application_error(request: Request, exc: APIError):
        return response(request, exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return response(request, 422, "VALIDATION_ERROR", "Solicitud inválida")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return response(request, exc.status_code, "HTTP_ERROR", "Solicitud no disponible")

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        state = getattr(getattr(exc, "orig", None), "sqlstate", None)
        logger.error(
            "database_error request_id=%s type=%s sqlstate=%s",
            request.state.request_id,
            type(exc).__name__,
            state,
        )
        if state == "23505":
            return response(request, 409, "CONCURRENT_CONFLICT", "La solicitud entra en conflicto con un cambio concurrente")
        if state == "23514":
            return response(request, 409, "INTEGRITY_CONFLICT", "La operación no cumple una transición permitida")
        if state == "42501":
            return response(request, 404, "RESOURCE_NOT_FOUND", "Recurso no disponible")
        if state == "28000":
            return response(request, 503, "DATABASE_CONTEXT_INVALID", "Contexto de workspace no disponible")
        if state in {"42703", "42P01", "42883"}:
            return response(
                request, 503, "DATABASE_SCHEMA_NOT_READY", "Esquema requerido no disponible"
            )
        if isinstance(exc, TimeoutError) or state in {"55P03", "57014"}:
            return response(request, 503, "DATABASE_BUSY", "Servicio temporalmente ocupado")
        if isinstance(exc, DBAPIError) and (
            exc.connection_invalidated or state is None or str(state).startswith("08")
        ):
            return response(request, 503, "DATABASE_UNAVAILABLE", "Dependencia no disponible")
        return response(request, 500, "DATABASE_ERROR", "Error de persistencia")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        if settings.workspace_hmac_key is None:
            raise APIError(503, "WORKSPACE_CONTEXT_UNAVAILABLE", "Contexto de workspace no configurado")
        with engine.connect() as connection:
            safe_role = connection.scalar(
                text(
                    "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls) "
                    "FROM pg_roles WHERE rolname=current_user"
                )
            )
            if not safe_role:
                raise APIError(503, "UNSAFE_DATABASE_ROLE", "Dependencia no disponible")
            connection.execute(text("SELECT id, created_by FROM vulntrack.assets LIMIT 0"))
            connection.execute(text("SELECT id, active FROM vulntrack.users LIMIT 0"))
            connection.execute(
                text("SELECT user_id FROM vulntrack.asset_registration_requests LIMIT 0")
            )
            connection.execute(
                text("SELECT id, valid_to FROM vulntrack.asset_cpe_identifications LIMIT 0")
            )
            connection.execute(
                text("SELECT identification_id, page_count FROM vulntrack.analysis_runs LIMIT 0")
            )
            connection.execute(text("SELECT evidence, reviewed_by FROM vulntrack.findings LIMIT 0"))
            connection.execute(text("SELECT request_key, page_manifest FROM vulntrack.application_analysis_runs LIMIT 0"))
            connection.execute(text("SELECT evidence, published_at FROM vulntrack.application_findings LIMIT 0"))
            if not connection.scalar(
                text(
                    "SELECT to_regprocedure("
                    "'vulntrack.establish_new_workspace_context(uuid,uuid,bigint,uuid,text)'"
                    ") IS NOT NULL AND to_regprocedure("
                    "'vulntrack.establish_context(uuid,uuid,bigint,uuid,text)'"
                    ") IS NOT NULL AND to_regprocedure("
                    "'vulntrack.list_user_workspaces(uuid,bigint,uuid,text)'"
                    ") IS NOT NULL"
                )
            ):
                raise APIError(503, "DATABASE_SCHEMA_NOT_READY", "Esquema requerido no disponible")
            nullable = connection.scalar(
                text(
                    "SELECT NOT attnotnull FROM pg_attribute "
                    "WHERE attrelid='vulntrack.assets'::regclass AND attname='version'"
                )
            )
            if not nullable:
                raise APIError(503, "DATABASE_SCHEMA_NOT_READY", "Esquema requerido no disponible")
        return {"status": "ready"}

    app.include_router(router)
    app.include_router(cpe_router)
    app.include_router(analyses_router)
    app.include_router(v2_resources_router)
    app.include_router(v2_nvd_router)
    app.include_router(v2_targets_router)
    app.include_router(v2_workspace_targets_router)
    return app
