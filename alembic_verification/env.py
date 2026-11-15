"""Explicit additive V2 extension; keeps the legacy Alembic head untouched."""

import os

from sqlalchemy import create_engine

from alembic import context
from app.db.coordination import lock_schema_operation
from app.db.verify_schema import CVE_REVISION, verify_schema
from app.db.verify_verification import verify_verification_schema

if context.is_offline_mode():
    raise RuntimeError("Verification migration requires a real compatible PostgreSQL")
url = os.environ.get("MIGRATION_DATABASE_URL")
if not url:
    raise RuntimeError("Maintenance MIGRATION_DATABASE_URL required; never use API login")
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
            version_table="alembic_verification_version",
            version_table_schema="public",
        )
        with context.begin_transaction():
            lock_schema_operation(connection)
            verify_schema(connection, CVE_REVISION)
            context.run_migrations()
            verify_schema(connection, CVE_REVISION)
            verify_verification_schema(connection)
finally:
    engine.dispose()
