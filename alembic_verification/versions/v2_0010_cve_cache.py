"""Workspace-isolated persistent CVE responses, without rewriting historical evidence."""

from importlib.resources import files

from alembic import op
from app.db.verify_cve_cache import verify_cve_cache_schema

revision = "v2_0010_cve_cache"
down_revision = "v2_0009_cve_reliability"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql(
        files("app.db").joinpath("cve_cache_schema.sql").read_text(),
        execution_options={"no_parameters": True},
    )
    verify_cve_cache_schema(op.get_bind())


def downgrade():
    raise RuntimeError(
        "Preserve CVE cache evidence and private references; no destructive downgrade."
    )
