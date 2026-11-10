"""PROPUESTA V1.1: individual ownership, preserving unowned historical assets.

Requires formal approval and Database coordination before integration. This mission
executes it only in disposable PostgreSQL. No data backfill or table recreation.
"""

from sqlalchemy import UUID, Column, ForeignKey

from alembic import context, op
from app.db.verify_schema import OWNERSHIP_REVISION, V1_REVISION, verify_schema

revision = OWNERSHIP_REVISION
down_revision = V1_REVISION
branch_labels = None
depends_on = None


def upgrade():
    if context.get_x_argument(as_dictionary=True).get("ownership_proposal") != "1":
        raise RuntimeError(
            "Cambio PROPUESTA: revisar aprobación/entorno y usar -x ownership_proposal=1"
        )
    verify_schema(op.get_bind(), V1_REVISION)
    op.add_column(
        "assets",
        Column(
            "created_by",
            UUID(),
            ForeignKey("vulntrack.users.id", name="assets_created_by_fkey", ondelete="RESTRICT"),
            nullable=True,
        ),
        schema="vulntrack",
    )
    op.create_index(
        "assets_owner_created_id_idx",
        "assets",
        ["created_by", "created_at", "id"],
        schema="vulntrack",
    )
    verify_schema(op.get_bind(), OWNERSHIP_REVISION)


def downgrade():
    # Dropping created_by would erase authorization information. Restore an approved
    # backup or design a reviewed forward migration; never silently lose ownership.
    raise RuntimeError("Downgrade bloqueado: perdería información de propiedad")
