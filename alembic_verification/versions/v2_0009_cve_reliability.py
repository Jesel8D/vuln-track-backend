"""Bounded V2 interruption recovery and immutable query provenance; no backfill."""

from importlib.resources import files

from alembic import op
from app.db.verify_cve_reliability import verify_cve_reliability_schema

revision = "v2_0009_cve_reliability"
down_revision = "v2_0008_technology_cpe"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("cve_reliability_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )
    verify_cve_reliability_schema(op.get_bind())


def downgrade():
    raise RuntimeError("Preserve CVE query evidence; roll back compatible code only.")
