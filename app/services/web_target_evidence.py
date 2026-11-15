"""Trusted verifier output contract; never a client request or scan permission."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ControlEvidence:
    workspace_id: UUID
    application_id: UUID
    target_id: UUID
    origin: str
    declaration_updated_at: datetime
    method: Literal["dns_txt", "http_file", "administrative"]
    evidence_sha256: str
    verified_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
