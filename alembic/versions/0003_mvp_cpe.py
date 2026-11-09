"""MVP-A: nullable version and CPE events. Bootstrap counterpart lives in Database."""

from importlib.resources import files

from alembic import context, op
from app.db.verify_schema import CPE_REVISION, OWNERSHIP_REVISION, verify_schema

revision = CPE_REVISION
down_revision = OWNERSHIP_REVISION
branch_labels = None
depends_on = None


def upgrade():
    if context.get_x_argument(as_dictionary=True).get("mvp_a") != "1":
        raise RuntimeError("MVP-A requires explicit -x mvp_a=1; never run at API startup")
    verify_schema(op.get_bind(), OWNERSHIP_REVISION)
    op.alter_column("assets", "version", nullable=True, schema="vulntrack")
    op.get_bind().exec_driver_sql(files("app.db").joinpath("cpe_table.sql").read_text())
    op.get_bind().exec_driver_sql(files("app.db").joinpath("cpe_guards.sql").read_text())
    verify_schema(op.get_bind(), CPE_REVISION)


def downgrade():
    raise RuntimeError("Downgrade blocked: would discard CPE history or unknown versions")
