"""Read mappings for SQL008; canonical constraints/RLS live in Database SQL.

Separate metadata prevents V2 extension tables from changing the legacy MVP
Alembic line. No create_all or automatic migrations are used by the service.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Integer, SmallInteger, Text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class VerificationBase(DeclarativeBase):
    pass


class Challenge(VerificationBase):
    __tablename__ = "challenges"
    __table_args__ = {"schema": "vulntrack_verification"}
    id: Mapped[UUID] = mapped_column(primary_key=True)
    workspace_id: Mapped[UUID]
    application_id: Mapped[UUID]
    target_id: Mapped[UUID]
    issued_by: Mapped[UUID]
    request_key: Mapped[UUID]
    method: Mapped[str] = mapped_column(Text)
    purpose: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(Text)
    url_sha256: Mapped[str] = mapped_column(Text)
    declaration_version: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    declaration_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    proof_sha256: Mapped[str] = mapped_column(Text, deferred=True)
    state: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(SmallInteger)
    version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_code: Mapped[str] = mapped_column(Text)


class VerificationAttempt(VerificationBase):
    __tablename__ = "attempts"
    __table_args__ = {"schema": "vulntrack_verification"}
    id: Mapped[UUID] = mapped_column(primary_key=True)
    workspace_id: Mapped[UUID]
    application_id: Mapped[UUID]
    target_id: Mapped[UUID]
    challenge_id: Mapped[UUID]
    actor_id: Mapped[UUID]
    provenance: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str] = mapped_column(Text)
    received_sha256: Mapped[str | None] = mapped_column(Text, deferred=True)
    peer_ip: Mapped[str | None] = mapped_column(INET, deferred=True)
    certificate_sha256: Mapped[str | None] = mapped_column(Text, deferred=True)
