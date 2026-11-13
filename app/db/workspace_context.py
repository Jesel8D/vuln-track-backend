"""Install a transaction-local identity for Database V2 row-level security."""

import hashlib
import hmac
import time
from contextlib import contextmanager
from uuid import UUID, uuid4

from sqlalchemy import text

from app.core.errors import APIError


def install_workspace_context(
    session, settings, user_id: UUID, workspace_id: UUID, *, bootstrap=False
):
    """Install only on the caller's transaction; used also for atomic enrollment."""
    configured = settings.workspace_hmac_key
    if configured is None:
        raise APIError(503, "WORKSPACE_CONTEXT_UNAVAILABLE", "Contexto de workspace no configurado")

    expires = int(time.time()) + 30
    nonce = uuid4()
    payload = f"v1|{user_id}|{workspace_id}|{expires}|{nonce}".encode()
    key = bytes.fromhex(configured.get_secret_value())
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()

    # The signed GUCs use SET LOCAL inside this transaction. Never return a
    # connection with identity context installed to SQLAlchemy's pool.
    function = (
        "vulntrack.establish_new_workspace_context" if bootstrap else "vulntrack.establish_context"
    )
    session.execute(
        text(f"SELECT {function}(:user_id, :workspace_id, :expires, :nonce, :signature)"),
        {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "expires": expires,
            "nonce": nonce,
            "signature": signature,
        },
    )


@contextmanager
def workspace_session(
    session_factory, settings, user_id: UUID, workspace_id: UUID, *, bootstrap=False
):
    with session_factory.begin() as session:
        install_workspace_context(session, settings, user_id, workspace_id, bootstrap=bootstrap)
        yield session


def list_user_workspaces(session_factory, settings, user_id: UUID):
    configured = settings.workspace_hmac_key
    if configured is None:
        raise APIError(503, "WORKSPACE_CONTEXT_UNAVAILABLE", "Contexto de workspace no configurado")
    expires = int(time.time()) + 30
    nonce = uuid4()
    payload = f"v1-directory|{user_id}|{expires}|{nonce}".encode()
    signature = hmac.new(
        bytes.fromhex(configured.get_secret_value()), payload, hashlib.sha256
    ).hexdigest()
    with session_factory.begin() as session:
        rows = (
            session.execute(
                text("""SELECT workspace_id,name,role,created_at
                FROM vulntrack.list_user_workspaces(:user_id,:expires,:nonce,:signature)"""),
                {"user_id": user_id, "expires": expires, "nonce": nonce, "signature": signature},
            )
            .mappings()
            .all()
        )
        return [dict(row) for row in rows]
