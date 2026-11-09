"""Database V1 mappings plus proposed V1.1 ownership; migrations are explicit."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    SmallInteger,
    Text,
    UniqueConstraint,
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
    version: Mapped[str | None] = mapped_column(Text)
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
        ForeignKeyConstraint(
            ["asset_id", "identification_id"],
            [
                "vulntrack.asset_cpe_identifications.asset_id",
                "vulntrack.asset_cpe_identifications.id",
            ],
            name="analysis_identification_fk",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "asset_id", "initiated_by", "idempotency_key", name="analysis_idempotency_unique"
        ),
        Index(
            "analysis_active_unique",
            "asset_id",
            unique=True,
            postgresql_where=text("status IN ('queued','running')"),
        ),
        Index("analysis_created_idx", "asset_id", "created_at", "id"),
        Index("analysis_queue_idx", "created_at", "id", postgresql_where=text("status='queued'")),
        check(
            "(identification_id IS NULL AND observed_version IS NULL AND idempotency_key IS "
            "NULL AND request_hash IS NULL) OR (identification_id IS NOT NULL AND "
            "observed_version IS NOT NULL AND vulntrack.valid_text(observed_version,120) AND "
            "idempotency_key IS NOT NULL AND request_hash IS NOT NULL AND request_hash ~ "
            "'^[0-9a-f]{64}$')",
            "analysis_identity_valid",
        ),
        check(
            "total_results >= 0 AND retrieved_count >= 0 AND stored_count >= 0 AND "
            "stored_count <= retrieved_count AND page_count BETWEEN 0 AND 5 AND next_index >= "
            "0 AND retry_count BETWEEN 0 AND 10",
            "analysis_counts_valid",
        ),
        check(
            "jsonb_typeof(query_parameters)='object' AND "
            "octet_length(query_parameters::text)<=4096 AND "
            "jsonb_typeof(warning_codes)='array' AND jsonb_array_length(warning_codes)<=20 "
            "AND jsonb_typeof(source_timestamps)='array' AND "
            "jsonb_array_length(source_timestamps)<=5 AND jsonb_typeof(page_manifest)='array' "
            "AND jsonb_array_length(page_manifest)<=5 AND "
            "octet_length(page_manifest::text)<=8192",
            "analysis_metadata_valid",
        ),
        check(
            "failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,79}$'",
            "analysis_failure_valid",
        ),
        check(
            "identification_id IS NULL OR ((status IN ('queued','running') AND coverage IS "
            "NULL AND failure_code IS NULL) OR (status='completed' AND page_count>0 AND "
            "coverage IS NOT NULL AND (coverage='partial' OR (failure_code IS NULL AND "
            "jsonb_array_length(warning_codes)=0 AND next_index=total_results AND "
            "stored_count=total_results))) OR (status='failed' AND coverage IS NULL AND "
            "page_count=0 AND failure_code IS NOT NULL))",
            "analysis_outcome_valid",
        ),
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

    identification_id: Mapped[UUID | None] = mapped_column()
    observed_version: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[UUID | None] = mapped_column()
    request_hash: Mapped[str | None] = mapped_column(Text)
    total_results: Mapped[int | None] = mapped_column(Integer)
    retrieved_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    stored_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    page_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    next_index: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    retry_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    query_parameters: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    warning_codes: Mapped[list] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    source_timestamps: Mapped[list] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    page_manifest: Mapped[list] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    failure_code: Mapped[str | None] = mapped_column(Text)
    nvd_cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


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
        check(
            "applicability IN ('potential','undetermined','not_applicable')",
            "findings_applicability_valid",
        ),
        check(
            "evidence IS NULL OR (jsonb_typeof(evidence)='object' AND "
            "octet_length(evidence::text)<=65536 AND evidence->>'initial_applicability' IS "
            "NOT NULL AND evidence->>'initial_applicability' IN ('potential','undetermined'))",
            "findings_evidence_valid",
        ),
        check(
            "(reviewed_by IS NULL AND reviewed_at IS NULL AND review_reason IS NULL AND "
            "review_evidence IS NULL AND (evidence IS NULL OR status='open')) OR (evidence IS "
            "NOT NULL AND status='reviewed' AND reviewed_by IS NOT NULL AND reviewed_at IS "
            "NOT NULL AND reviewed_at>=observed_at AND review_reason IS NOT NULL AND "
            "vulntrack.valid_text(review_reason,500) AND review_evidence IS NOT NULL AND "
            "vulntrack.valid_text(review_evidence,2000))",
            "findings_review_valid",
        ),
        UniqueConstraint("analysis_id", "source", "external_id", name="findings_cve_unique"),
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

    evidence: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    reviewed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("vulntrack.users.id", ondelete="RESTRICT")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_reason: Mapped[str | None] = mapped_column(Text)
    review_evidence: Mapped[str | None] = mapped_column(Text)


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
