"""SQL008-equivalent extension with checked bootstrap adoption, never blind stamp."""

from importlib.resources import files

from sqlalchemy import text

from alembic import op
from app.db.verify_verification import verify_verification_schema

revision = "v2_0001_target_verification"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if connection.scalar(text("SELECT to_regnamespace('vulntrack_verification')")) is None:
        connection.exec_driver_sql(
            files("app.db").joinpath("verification_schema.sql").read_text(),
            execution_options={"no_parameters": True},
        )
    # Existing SQL008 is adopted only if every catalog/security object is exact.
    verify_verification_schema(connection)


def downgrade():
    raise RuntimeError("Durable evidence must be retained; roll back code without dropping SQL008")
