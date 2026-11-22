"""Add immutable device revisions and generation-bound security evidence."""

from importlib.resources import files

from alembic import op

revision = "v2_0007_device_revisions"
down_revision = "v2_0006_cpe_quarantine"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("device_revisions_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )


def downgrade():
    raise RuntimeError("Preserve device revisions. Use the isolated RC2.4 deployment for rollback.")
