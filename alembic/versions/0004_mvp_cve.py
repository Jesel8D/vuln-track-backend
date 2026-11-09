"""Extend existing runs/findings without rewriting legacy evidence (mission MVP-B)."""

from importlib.resources import files

from alembic import op
from app.db.verify_schema import CPE_REVISION, CVE_REVISION, verify_schema

revision = CVE_REVISION
down_revision = CPE_REVISION
branch_labels = None
depends_on = None


def upgrade():
    # Explicit maintenance CLI only, never at API startup. Keeping upgrade head
    # compatible also preserves the existing Web V1 disposable launcher.
    verify_schema(op.get_bind(), CPE_REVISION)
    op.get_bind().exec_driver_sql(files("app.db").joinpath("cve_schema.sql").read_text())
    verify_schema(op.get_bind(), CVE_REVISION)


def downgrade():
    raise RuntimeError("Downgrade blocked: would discard CVE evidence and review history")
