"""Keep coverage totals out of catalog request-path aggregation."""

from importlib.resources import files

from alembic import op

revision = "v2_0005_cpe_summary"
down_revision = "v2_0004_cpe_feed"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("cpe_summary_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )


def downgrade():
    raise RuntimeError("Roll application code back while retaining catalog snapshots")
