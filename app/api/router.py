from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import undefer

from app.api.dependencies import current_user
from app.core.errors import unauthorized
from app.core.security import issue_token, verify_password
from app.models.database_v1 import User
from app.schemas.assets import AssetCreate, AssetList, AssetRead

router = APIRouter(prefix="/api/v1")
Identity = Annotated[User, Depends(current_user)]


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$", max_length=80)
    password: SecretStr = Field(min_length=1, max_length=256)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserRead(BaseModel):
    id: UUID
    username: str


@router.post("/auth/login", response_model=Token)
def login(payload: Login, request: Request):
    request.app.state.login_limiter.check(
        payload.username, request.client.host if request.client else "unknown"
    )
    with request.app.state.session_factory() as session:
        user = session.scalar(
            select(User)
            .options(undefer(User.password_hash))
            .where(User.username == payload.username)
        )
        valid = verify_password(
            user.password_hash if user else None, payload.password.get_secret_value()
        )
        if not valid or not user or not user.active:
            raise unauthorized()
        settings = request.app.state.settings
        return JSONResponse(
            Token(
                access_token=issue_token(user, settings),
                expires_in=settings.token_ttl_seconds,
            ).model_dump(),
            headers={"Cache-Control": "no-store"},
        )


@router.get("/auth/me", response_model=UserRead)
def me(user: Identity):
    return UserRead(id=user.id, username=user.username)


@router.post("/assets", status_code=201, response_model=AssetRead)
def register(
    payload: AssetCreate,
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
    body = request.app.state.assets.register(user.id, UUID(idempotency_key), payload)
    return JSONResponse(
        body,
        status_code=201,
        headers={
            "Location": f"/api/v1/assets/{body['id']}",
            "Cache-Control": "no-store",
        },
    )


@router.get("/assets", response_model=AssetList)
def list_assets(
    user: Identity,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
):
    return request.app.state.assets.list(user.id, limit, offset)


@router.get("/assets/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: UUID, user: Identity, request: Request):
    return request.app.state.assets.get(user.id, asset_id)
