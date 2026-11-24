"""Preserve new technology CPE confirmations without backfilling old selections."""

from importlib.resources import files

from alembic import op
from app.db.verify_technology_cpe import verify_technology_cpe_schema

revision = "v2_0008_technology_cpe"
down_revision = "v2_0007_device_revisions"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("technology_cpe_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )
    verify_technology_cpe_schema(op.get_bind())


def downgrade():
    raise RuntimeError("Preserve confirmation history; roll back application code only.")
