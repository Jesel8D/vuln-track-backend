from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from app.core.errors import unauthorized
from app.core.security import decode_token
from app.models.database_v1 import User

bearer = HTTPBearer(auto_error=False)


def current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> User:
    if credentials is None:
        raise unauthorized()
    claims = decode_token(credentials.credentials, request.app.state.settings)
    with request.app.state.session_factory() as session:
        user = session.scalar(select(User).where(User.id == UUID(claims["sub"])))
        if not user or not user.active or user.updated_at.isoformat() != claims["ver"]:
            raise unauthorized()
        return user
