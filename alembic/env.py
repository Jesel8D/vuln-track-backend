import os

from sqlalchemy import create_engine

from alembic import context
from app.db.base import Base
from app.db.verify_schema import verify_schema

if context.is_offline_mode():
    raise RuntimeError("Baseline requiere verificar PostgreSQL real; modo offline bloqueado")
url = os.environ.get("MIGRATION_DATABASE_URL")
if not url:
    raise RuntimeError("Definir MIGRATION_DATABASE_URL de mantenimiento; nunca usar login API")
engine = create_engine(url, hide_parameters=True)
try:
    with engine.connect() as connection:
        verify_schema(connection)
        connection.rollback()
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            include_schemas=True,
            compare_type=True,
            include_name=lambda name, type_, parent: (
                name == "vulntrack" if type_ == "schema" else True
            ),
        )
        with context.begin_transaction():
            context.run_migrations()
finally:
    engine.dispose()
