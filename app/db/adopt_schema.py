"""Recognize an already-created proposed schema only after exhaustive validation.

This does not migrate V1 and never changes business data. The mission executes this
only on disposable PostgreSQL. Formal approval remains a separate release prerequisite.
"""

import argparse
import os
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from app.db.base import Base
from app.db.coordination import lock_schema_operation
from app.db.verify_schema import (
    CPE_REVISION,
    CVE_REVISION,
    OWNERSHIP_REVISION,
    installed_revision,
    verify_schema,
)


def adopt_verified_ownership(connection, script_directory):
    return adopt_verified(connection, script_directory, OWNERSHIP_REVISION)


def adopt_verified(connection, script_directory, revision):
    if revision not in {OWNERSHIP_REVISION, CPE_REVISION, CVE_REVISION}:
        raise RuntimeError("Revisión de adopción no permitida")
    if not connection.in_transaction():
        raise RuntimeError("Adopción requiere una transacción explícita")
    lock_schema_operation(connection)
    current = installed_revision(connection)
    if current not in {None, revision}:
        raise RuntimeError("Una revisión existente no se reemplaza mediante adopción")
    if revision in {CPE_REVISION, CVE_REVISION} and not inspect(connection).has_table(
        "asset_cpe_identifications", schema="vulntrack"
    ):
        raise RuntimeError("Baseline bloqueado: falta tabla CPE")
    # No writer/DDL on these tables may race the validation and version write.
    names = ", ".join(
        f'"{table.schema}"."{table.name}"'
        for table in Base.metadata.sorted_tables
        if revision in {CPE_REVISION, CVE_REVISION} or table.name != "asset_cpe_identifications"
    )
    connection.execute(text(f"LOCK TABLE {names} IN SHARE MODE"))
    verify_schema(connection, revision)
    if current is None:
        MigrationContext.configure(connection, opts={"version_table_schema": "public"}).stamp(
            script_directory, revision
        )
    if installed_revision(connection) != revision:
        raise RuntimeError("No se pudo verificar la revisión reconocida")
    verify_schema(connection, revision)
    return revision


def main():
    parser = argparse.ArgumentParser(
        description="Adoptar exclusivamente un esquema V1.1 verificado"
    )
    parser.add_argument(
        "--confirm-proposal",
        action="store_true",
        required=True,
        help="Reconocer ejecución de propuesta; no significa aprobación formal",
    )
    parser.add_argument("--mvp-a", action="store_true", help="Adoptar bootstrap MVP-A verificado")
    parser.add_argument("--mvp-b", action="store_true", help="Adoptar bootstrap MVP-B verificado")
    args = parser.parse_args()
    if args.mvp_a and args.mvp_b:
        parser.error("Elegir una revisión de adopción")
    url = os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        parser.error("Definir MIGRATION_DATABASE_URL de mantenimiento fuera de Git")
    engine = create_engine(
        url,
        hide_parameters=True,
        connect_args={
            "connect_timeout": 5,
            "options": "-c lock_timeout=5000 -c statement_timeout=60000",
        },
    )
    try:
        config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
        scripts = ScriptDirectory.from_config(config)
        with engine.begin() as connection:
            revision = adopt_verified(
                connection,
                scripts,
                CVE_REVISION if args.mvp_b else CPE_REVISION if args.mvp_a else OWNERSHIP_REVISION,
            )
        print(f"Esquema verificado y reconocido: {revision}; sin cambios a datos de negocio.")
    except Exception as exc:
        # DBAPI exceptions can include statements/values. Never print their text or the URL.
        parser.exit(1, f"Adopción bloqueada ({type(exc).__name__}); transacción revertida.\n")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
