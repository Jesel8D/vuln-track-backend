"""Database V1 mappings plus proposed V1.1 ownership; migrations are explicit."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SCHEMA = "vulntrack"


def check(expression, name):
    return CheckConstraint(expression, name=name)


class Audit:
    id: Mapped[UUID] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("statement_timestamp()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("statement_timestamp()")
    )


class User(Audit, Base):
    __tablename__ = "users"
    __table_args__ = (
        check("username ~ '^[a-z0-9][a-z0-9_.-]{0,79}$'", "users_username_valid"),
        check(
            r"password_hash IS NULL OR password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,"
            r"t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'",
            "users_hash_not_plaintext",
        ),
        check("updated_at >= created_at", "users_time_order"),
        {"schema": SCHEMA},
    )
    username: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str | None] = mapped_column(Text, deferred=True)
    active: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


class Asset(Audit, Base):
    __tablename__ = "assets"
    __table_args__ = (
        *(
            check(f"vulntrack.valid_text({field}, {limit})", f"assets_{field}_valid")
            for field, limit in [
                ("device_type", 80),
                ("manufacturer", 120),
                ("model", 120),
                ("version", 120),
                ("site_label", 120),
            ]
        ),
        *(
            check(
                f"{field} IS NULL OR vulntrack.valid_text({field}, {limit})",
                f"assets_{field}_valid",
            )
            for field, limit in [("inventory_label", 120), ("notes", 1000)]
        ),
        check("updated_at >= created_at", "assets_time_order"),
        Index("assets_created_id_idx", "created_at", "id"),
        Index("assets_owner_created_id_idx", "created_by", "created_at", "id"),
        {"schema": SCHEMA},
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("vulntrack.users.id", name="assets_created_by_fkey", ondelete="RESTRICT")
    )
    device_type: Mapped[str] = mapped_column(Text)
    manufacturer: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    site_label: Mapped[str] = mapped_column(Text)
    inventory_label: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)


class AnalysisRun(Audit, Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (
        check("kind = 'nvd_cve'", "analysis_runs_kind_v1"),
        check(
            "left(selected_cpe, 8) = 'cpe:2.3:' AND vulntrack.valid_text(selected_cpe, 1024)",
            "analysis_runs_cpe_valid",
        ),
        check(
            "status IN ('queued', 'running', 'completed', 'failed')", "analysis_runs_status_valid"
        ),
        check("coverage IN ('complete', 'partial')", "analysis_runs_coverage_valid"),
        check(
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL "
            "AND coverage IS NULL) OR (status = 'running' AND started_at IS NOT NULL "
            "AND completed_at IS NULL AND coverage IS NULL) OR (status = 'completed' "
            "AND started_at IS NOT NULL AND completed_at IS NOT NULL AND coverage IS NOT NULL) "
            "OR (status = 'failed' AND completed_at IS NOT NULL)",
            "analysis_runs_lifecycle",
        ),
        check("completed_at >= started_at", "analysis_runs_execution_order"),
        check("updated_at >= created_at", "analysis_runs_time_order"),
        Index("analysis_runs_initiated_by_idx", "initiated_by"),
        {"schema": SCHEMA},
    )
    kind: Mapped[str] = mapped_column(Text, server_default=text("'nvd_cve'"))
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("vulntrack.assets.id", ondelete="RESTRICT"))
    initiated_by: Mapped[UUID] = mapped_column(
        ForeignKey("vulntrack.users.id", ondelete="RESTRICT")
    )
    selected_cpe: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'queued'"))
    coverage: Mapped[str | None] = mapped_column(Text)
    source_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index(
    "analysis_runs_asset_started_idx",
    AnalysisRun.asset_id,
    AnalysisRun.started_at.desc(),
    AnalysisRun.id,
)


class Finding(Audit, Base):
    __tablename__ = "findings"
    __table_args__ = (
        check("source = 'NVD'", "findings_source_v1"),
        check("external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", "findings_cve_valid"),
        check("title IS NULL OR vulntrack.valid_text(title, 500)", "findings_title_valid"),
        check("applicability = 'potential'", "findings_applicability_v1"),
        check("status IN ('open', 'reviewed')", "findings_status_valid"),
        check("cvss IS NULL OR jsonb_typeof(cvss) = 'object'", "findings_cvss_object"),
        check("updated_at >= created_at", "findings_time_order"),
        Index("findings_analysis_id_idx", "analysis_id", "id"),
        {"schema": SCHEMA},
    )
    analysis_id: Mapped[UUID] = mapped_column(
        ForeignKey("vulntrack.analysis_runs.id", ondelete="RESTRICT")
    )
    source: Mapped[str] = mapped_column(Text, server_default=text("'NVD'"))
    external_id: Mapped[str] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text)
    applicability: Mapped[str] = mapped_column(Text, server_default=text("'potential'"))
    status: Mapped[str] = mapped_column(Text, server_default=text("'open'"))
    cvss: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("statement_timestamp()")
    )


class RegistrationRequest(Base):
    __tablename__ = "asset_registration_requests"
    __table_args__ = (
        check("method = 'POST' AND route = '/assets'", "registration_scope"),
        check("request_hash ~ '^[0-9a-f]{64}$'", "registration_hash_valid"),
        check("response_status = 201", "registration_response_status"),
        check(
            "jsonb_typeof(response_body) = 'object' AND response_body ? 'id' "
            "AND response_body->>'id' IS NOT NULL "
            "AND response_body->>'id' = asset_id::text",
            "registration_response_valid",
        ),
        check("expires_at > created_at", "registration_expiry"),
        Index("registration_asset_id_idx", "asset_id"),
        {"schema": SCHEMA},
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("vulntrack.users.id", ondelete="RESTRICT"), primary_key=True
    )
    method: Mapped[str] = mapped_column(Text, primary_key=True, server_default=text("'POST'"))
    route: Mapped[str] = mapped_column(Text, primary_key=True, server_default=text("'/assets'"))
    idempotency_key: Mapped[UUID] = mapped_column(primary_key=True)
    request_hash: Mapped[str] = mapped_column(Text)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("vulntrack.assets.id", ondelete="RESTRICT"))
    response_status: Mapped[int] = mapped_column(SmallInteger, server_default=text("201"))
    response_body: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("statement_timestamp()")
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("statement_timestamp() + interval '24 hours'"),
    )


# Preserve upstream comments so autogenerate never proposes removing them.
Asset.__table__.comment = "Inventario; registrar un dispositivo no autoriza escanearlo"
AnalysisRun.__table__.comment = "Solo consultas NVD V1; no ejecuta integraciones"
Finding.__table__.comment = "CVE potencialmente aplicables, nunca confirmados automáticamente"
RegistrationRequest.__table__.comment = "Soporte transaccional; API e idempotencia E2E pendientes"
