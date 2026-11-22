"""Add the verified feed checkpoint and indexes to the existing dictionary."""

from importlib.resources import files

from alembic import op

revision = "v2_0004_cpe_feed"
down_revision = "v2_0003_cpe_catalog"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("cpe_feed_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )


def downgrade():
    raise RuntimeError("Retain durable feed receipts and roll the application back separately")
