import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError, TimeoutError
from starlette.exceptions import HTTPException

from app.api.router import router
from app.core.config import Settings, get_settings
from app.core.errors import APIError
from app.core.http import RequestBoundary, error_body
from app.core.security import LoginLimiter
from app.db.session import build_engine, build_session_factory
from app.services.assets import AssetService
from app.services.authorization import AssetAuthorization

logger = logging.getLogger("vulntrack")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = build_engine(settings)

    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.dispose()

    app = FastAPI(title="VulnTrack API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.assets = AssetService(app.state.session_factory, AssetAuthorization())
    app.state.login_limiter = LoginLimiter(settings.login_attempts_per_minute)
    app.add_middleware(RequestBoundary, max_body_bytes=settings.max_body_bytes)

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
        with engine.connect() as connection:
            safe_role = connection.scalar(
                text(
                    "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls) "
                    "FROM pg_roles WHERE rolname=current_user"
                )
            )
            if not safe_role:
                raise APIError(503, "UNSAFE_DATABASE_ROLE", "Dependencia no disponible")
            connection.execute(text("SELECT id FROM vulntrack.assets LIMIT 0"))
            connection.execute(text("SELECT id, active FROM vulntrack.users LIMIT 0"))
            connection.execute(
                text("SELECT user_id FROM vulntrack.asset_registration_requests LIMIT 0")
            )
        return {"status": "ready"}

    app.include_router(router)
    return app
