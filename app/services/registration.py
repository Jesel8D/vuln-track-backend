"""Create a normal account and its personal workspace as one PostgreSQL transaction."""

from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.errors import APIError
from app.core.security import hash_password
from app.db.workspace_context import install_workspace_context
from app.models.database_v1 import User


class RegistrationService:
    def __init__(self, session_factory, settings, gate):
        self.session_factory = session_factory
        self.settings = settings
        self.gate = gate

    def register(self, payload):
        # Expensive hashing happens before opening the DB transaction, with bounded concurrency.
        with self.gate.hashing():
            encoded = hash_password(payload.password.get_secret_value())
        actor, workspace = uuid4(), uuid4()
        try:
            with self.session_factory.begin() as session:
                session.add(
                    User(id=actor, username=payload.username, password_hash=encoded, active=True)
                )
                session.flush()  # Real users_username_key arbitrates simultaneous registrations.
                install_workspace_context(session, self.settings, actor, workspace, bootstrap=True)
                session.execute(
                    text(
                        "INSERT INTO vulntrack.workspaces(id,name,created_by) "
                        "VALUES (:workspace,:name,:actor)"
                    ),
                    {
                        "workspace": workspace,
                        "actor": actor,
                        "name": "Personal de " + payload.username,
                    },
                )
                session.execute(
                    text(
                        "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                        "VALUES (:workspace,:actor,'owner')"
                    ),
                    {"workspace": workspace, "actor": actor},
                )
                session.execute(
                    text(
                        "INSERT INTO vulntrack.audit_events"
                        "(workspace_id,actor_id,action,object_type,object_id) "
                        "VALUES (:workspace,:actor,'account.registered','user',:actor)"
                    ),
                    {"workspace": workspace, "actor": actor},
                )
                # Check deferred owner/FK guards while the signed SET LOCAL context is valid.
                session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            return {"id": actor, "username": payload.username}
        except DBAPIError as error:
            if getattr(error.orig, "sqlstate", None) == "42501":
                raise APIError(503, "REGISTRATION_NOT_READY", "Registro no disponible") from None
            if (
                getattr(error.orig, "sqlstate", None) == "23505"
                and getattr(getattr(error.orig, "diag", None), "constraint_name", None)
                == "users_username_key"
            ):
                raise APIError(
                    409, "REGISTRATION_UNAVAILABLE", "No se pudo crear la cuenta"
                ) from None
            raise
