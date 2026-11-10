"""MVP-A: one append-only event table for identification and history."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.database_v1 import check


class CPEIdentification(Base):
    __tablename__ = "asset_cpe_identifications"
    __table_args__ = (
        UniqueConstraint("asset_id", "id", name="cpe_asset_id_unique"),
        UniqueConstraint(
            "asset_id", "recorded_by", "idempotency_key", name="cpe_idempotency_unique"
        ),
        ForeignKeyConstraint(
            ["asset_id", "replaces_id"],
            [
                "vulntrack.asset_cpe_identifications.asset_id",
                "vulntrack.asset_cpe_identifications.id",
            ],
            name="cpe_replaces_same_asset",
            ondelete="RESTRICT",
        ),
        check("state IN ('confirmed', 'needs_review')", "cpe_state_valid"),
        check(
            "component_kind IN ('hardware', 'firmware', 'os', 'software')", "cpe_component_valid"
        ),
        check("source = 'NVD'", "cpe_source_valid"),
        check(
            "left(cpe_name, 8) = 'cpe:2.3:' AND vulntrack.valid_text(cpe_name, 1024)",
            "cpe_name_valid",
        ),
        check(
            "observed_version IS NULL OR vulntrack.valid_text(observed_version, 120)",
            "cpe_version_valid",
        ),
        check("vulntrack.valid_text(reason, 500)", "cpe_reason_valid"),
        check("request_hash ~ '^[0-9a-f]{64}$'", "cpe_hash_valid"),
        check("valid_to IS NULL OR valid_to >= recorded_at", "cpe_time_order"),
        check("validated_at <= recorded_at", "cpe_validation_order"),
        check("replaces_id IS NULL OR replaces_id <> id", "cpe_no_self_replace"),
        Index(
            "cpe_current_unique", "asset_id", unique=True, postgresql_where=text("valid_to IS NULL")
        ),
        Index(
            "cpe_replaces_unique",
            "replaces_id",
            unique=True,
            postgresql_where=text("replaces_id IS NOT NULL"),
        ),
        Index("cpe_history_idx", "asset_id", "recorded_at", "id"),
        {"schema": "vulntrack"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("vulntrack.assets.id", ondelete="RESTRICT"))
    state: Mapped[str] = mapped_column(Text)
    cpe_name: Mapped[str] = mapped_column(Text)
    cpe_name_id: Mapped[UUID]
    component_kind: Mapped[str] = mapped_column(Text)
    observed_version: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_by: Mapped[UUID] = mapped_column(ForeignKey("vulntrack.users.id", ondelete="RESTRICT"))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)
    replaces_id: Mapped[UUID | None]
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[UUID]
    request_hash: Mapped[str] = mapped_column(Text)
