"""Add the local NVD dictionary and workspace-scoped registration receipts."""

from importlib.resources import files

from alembic import op
from app.db.verify_catalog import verify_catalog_schema

revision = "v2_0003_cpe_catalog"
down_revision = "v2_0002_devices"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    connection.exec_driver_sql(
        files("app.db").joinpath("cpe_catalog_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )
    verify_catalog_schema(connection)


def downgrade():
    raise RuntimeError("Keep the catalog and registration history. Roll back code separately.")
