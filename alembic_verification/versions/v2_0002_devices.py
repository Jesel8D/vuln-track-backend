"""Install the additive, workspace-scoped RC2 device schema."""

from importlib.resources import files

from alembic import op
from app.db.verify_devices import verify_devices_schema

revision = "v2_0002_devices"
down_revision = "v2_0001_target_verification"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    connection.exec_driver_sql(
        files("app.db").joinpath("devices_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )
    verify_devices_schema(connection)


def downgrade():
    raise RuntimeError(
        "Device history is durable. Retain the RC2 volume and roll code back separately."
    )
