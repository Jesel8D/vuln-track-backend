"""Retain raw evidence of rejected official dictionary entries."""

from importlib.resources import files

from alembic import op

revision = "v2_0006_cpe_quarantine"
down_revision = "v2_0005_cpe_summary"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("cpe_quarantine_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )


def downgrade():
    raise RuntimeError("Keep the quarantine evidence and roll back only application code")
