"""Explicit local maintenance command. Never activates or changes an existing account."""

import getpass
import os
import re
import sys
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.database_v1 import User


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,79}", sys.argv[1]):
        sys.exit("Uso: python scripts/provision_user.py username_ascii_minúsculas")
    username = sys.argv[1]
    url = os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        sys.exit("Definir MIGRATION_DATABASE_URL de mantenimiento fuera de Git")
    if username == "demo_operator":
        sys.exit("El usuario seed se conserva inactivo")
    password = getpass.getpass("Contraseña nueva (12–256 caracteres): ")
    if password != getpass.getpass("Repetir contraseña: "):
        sys.exit("Las contraseñas no coinciden")
    encoded = hash_password(password)
    engine = create_engine(url, hide_parameters=True)
    try:
        with Session(engine) as session, session.begin():
            if session.scalar(select(User.id).where(User.username == username)):
                sys.exit("La cuenta ya existe; no se modificará")
            user_id = uuid4()
            session.add(User(id=user_id, username=username, active=True, password_hash=encoded))
        print(
            f"Cuenta creada: {user_id}. "
            "Acceso propuesto V1.1 limitado a activos propios tras migración revisada."
        )
    except Exception as exc:
        # DBAPI errors may carry statement values. Print type, never str(exc).
        sys.exit(f"Aprovisionamiento fallido ({type(exc).__name__}); transacción revertida")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
