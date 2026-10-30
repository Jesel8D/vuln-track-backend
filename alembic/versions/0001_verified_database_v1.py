"""Recognize an existing, verified Database V1; never recreate its tables."""

revision = "0001_database_v1"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # env.py verifies the live catalog and ORM before creating alembic_version.
    pass


def downgrade():
    raise RuntimeError("Baseline no reversible: no se elimina el esquema Database V1")
