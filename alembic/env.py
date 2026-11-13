import os

from sqlalchemy import create_engine

from alembic import context
from app.db.base import Base
from app.db.coordination import lock_schema_operation
from app.db.verify_schema import V1_REVISION, installed_revision, verify_schema

if context.is_offline_mode():
    raise RuntimeError("Baseline requiere verificar PostgreSQL real; modo offline bloqueado")
url = os.environ.get("MIGRATION_DATABASE_URL")
if not url:
    raise RuntimeError("Definir MIGRATION_DATABASE_URL de mantenimiento; nunca usar login API")
engine = create_engine(
    url,
    hide_parameters=True,
    connect_args={
        "connect_timeout": 5,
        "options": "-c lock_timeout=5000 -c statement_timeout=60000",
    },
)
try:
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            include_schemas=True,
            version_table_schema="public",
            compare_type=True,
            include_name=lambda name, type_, parent: (
                name == "vulntrack"
                if type_ == "schema"
                else (
                    name in {table.name for table in Base.metadata.sorted_tables}
                    if type_ == "table"
                    else True
                )
            ),
        )
        with context.begin_transaction():
            lock_schema_operation(connection)
            current = installed_revision(connection)
            verify_schema(connection, current or V1_REVISION)
            context.run_migrations()
            # Validate the destination inside the same DDL transaction, before commit.
            destination = installed_revision(connection)
            verify_schema(connection, destination or V1_REVISION)
finally:
    engine.dispose()
