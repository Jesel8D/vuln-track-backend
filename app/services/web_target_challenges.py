"""Local reference implementation of single-purpose HTTPS control challenges.

NOT wired to API/worker, NOT durable, NOT a production authorization repository.
The future adapter must obtain Scope from JWT + membership + locked RLS rows,
and persist challenge/evidence/audit atomically under D-002. Client-provided
roles, origins or versions must never be used to construct a trusted Scope.
"""

import asyncio
import hashlib
import hmac
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.services.web_target_evidence import ControlEvidence
from app.services.web_target_policy import DestinationDenied, DestinationPolicy
from app.services.web_target_tokens import PURPOSE as PURPOSE
from app.services.web_target_tokens import challenge_material


@dataclass(frozen=True, slots=True)
class Scope:
    workspace_id: UUID
    application_id: UUID
    target_id: UUID
    actor_id: UUID
    role: str
    url: str
    declaration_updated_at: datetime
    declaration_expires_at: datetime
    declaration_status: str = "approved"
    application_status: str = "active"

    def eligible(self, now):
        if (
            now.tzinfo is None
            or self.role not in {"owner", "editor"}
            or self.declaration_status != "approved"
            or self.application_status != "active"
            or self.declaration_updated_at.tzinfo is None
            or self.declaration_expires_at.tzinfo is None
            or not self.declaration_updated_at <= now < self.declaration_expires_at
        ):
            raise DestinationDenied("CHALLENGE_SCOPE_DENIED")
        return DestinationPolicy().parse(self.url)


@dataclass(frozen=True, slots=True)
class Challenge:
    id: UUID
    scope: Scope
    origin: str
    proof_sha256: str = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    state: str = "pending"
    version: int = 1
    evidence: ControlEvidence | None = None

    @property
    def url(self):
        # Fixed path under the canonical origin, no user-controlled path/query.
        return f"{self.origin}/.well-known/vulntrack-verification/{self.id}"


@dataclass(frozen=True, slots=True)
class ChallengeInstructions:
    id: UUID
    url: str
    expires_at: datetime
    body: bytes = field(repr=False)


class LaboratoryChallengeStore:
    """Bounded, locked reference store; only for owned local tests/laboratory.

    No disk persistence, no restoration of proofs, no lookup by a client API.
    audit_sink runs before mutation while locked: a failed audit commits nothing.
    """

    def __init__(self, *, audit_sink=None):
        self._records = {}
        self._lock = threading.RLock()
        self.events = []
        self.audit_sink = audit_sink

    def _commit(self, record, action):
        event = {
            "action": action,
            "challenge_id": str(record.id),
            "workspace_id": str(record.scope.workspace_id),
            "target_id": str(record.scope.target_id),
            "actor_id": str(record.scope.actor_id),
            "state": record.state,
            "version": record.version,
            "purpose": PURPOSE,
        }
        if self.audit_sink is not None:
            self.audit_sink(event.copy())
        self._records[record.id] = record
        self.events.append(event)

    def issue(self, scope, now):
        destination = scope.eligible(now)
        with self._lock:
            # No eviction of replay markers. Bounded lab lifecycle only.
            if len(self._records) >= 256:
                raise DestinationDenied("CHALLENGE_LAB_CAPACITY")
            if any(
                record.scope.target_id == scope.target_id
                and record.scope.workspace_id == scope.workspace_id
                and record.state in {"pending", "checking", "verified"}
                for record in self._records.values()
            ):
                raise DestinationDenied("CHALLENGE_ALREADY_ACTIVE")
            identity, body, digest = challenge_material()
            expiry = min(now + timedelta(minutes=10), scope.declaration_expires_at)
            record = Challenge(identity, scope, destination.origin, digest, now, expiry)
            self._commit(record, "control.challenge.issued")
            return ChallengeInstructions(identity, record.url, expiry, body)

    def _lookup(self, identity, scope):
        record = self._records.get(identity)
        if record is None or record.scope != scope:
            raise DestinationDenied("CHALLENGE_NOT_AVAILABLE")
        return record

    def claim(self, identity, scope, now):
        scope.eligible(now)
        with self._lock:
            record = self._lookup(identity, scope)
            if record.state != "pending":
                raise DestinationDenied("CHALLENGE_ALREADY_CONSUMED")
            if not record.issued_at <= now < record.expires_at:
                self._commit(
                    replace(record, state="expired", version=record.version + 1),
                    "control.challenge.expired",
                )
                raise DestinationDenied("CHALLENGE_EXPIRED")
            claimed = replace(record, state="checking", version=record.version + 1)
            self._commit(claimed, "control.challenge.claimed")
            return claimed

    def reject(self, claimed):
        with self._lock:
            current = self._lookup(claimed.id, claimed.scope)
            if current.state == "checking" and current.version == claimed.version:
                self._commit(
                    replace(current, state="rejected", version=current.version + 1),
                    "control.challenge.rejected",
                )

    def finish(self, claimed, body, fresh_scope, now):
        with self._lock:
            current = self._lookup(claimed.id, claimed.scope)
            if current.state != "checking" or current.version != claimed.version:
                raise DestinationDenied("CHALLENGE_CHANGED")
            try:
                if not isinstance(fresh_scope, Scope):
                    raise DestinationDenied("CHALLENGE_SCOPE_DENIED")
                fresh_scope.eligible(now)
                valid = (
                    fresh_scope == claimed.scope
                    and claimed.issued_at <= now < claimed.expires_at
                    and isinstance(body, bytes)
                    and hmac.compare_digest(hashlib.sha256(body).hexdigest(), current.proof_sha256)
                )
            except DestinationDenied:
                valid = False
            if not valid:
                self.reject(claimed)
                raise DestinationDenied("CHALLENGE_PROOF_REJECTED")
            evidence = ControlEvidence(
                workspace_id=fresh_scope.workspace_id,
                application_id=fresh_scope.application_id,
                target_id=fresh_scope.target_id,
                origin=current.origin,
                declaration_updated_at=fresh_scope.declaration_updated_at,
                method="http_file",
                evidence_sha256=current.proof_sha256,
                verified_at=now,
                expires_at=min(now + timedelta(hours=24), fresh_scope.declaration_expires_at),
            )
            self._commit(
                replace(current, state="verified", version=current.version + 1, evidence=evidence),
                "control.challenge.verified",
            )
            return evidence

    def revoke(self, identity, scope, now):
        # Revocation is allowed even after declaration expiry, but the caller
        # must still be the same currently authorized owner/editor in the scope.
        if scope.role not in {"owner", "editor"} or now.tzinfo is None:
            raise DestinationDenied("CHALLENGE_SCOPE_DENIED")
        with self._lock:
            current = self._lookup(identity, scope)
            if current.state == "revoked":
                raise DestinationDenied("CHALLENGE_ALREADY_REVOKED")
            evidence = replace(current.evidence, revoked_at=now) if current.evidence else None
            self._commit(
                replace(current, state="revoked", version=current.version + 1, evidence=evidence),
                "control.challenge.revoked",
            )


class LaboratoryVerifier:
    """HTTPS verifier composition for tests; the live application never creates it."""

    def __init__(self, store, transport, resolver, *, clock=lambda: datetime.now(UTC)):
        self.store, self.transport, self.resolver, self.clock = store, transport, resolver, clock

    async def verify(self, identity, scope, *, reload_scope, cancelled=None):
        claimed = self.store.claim(identity, scope, self.clock())
        try:
            plan = DestinationPolicy().prepare_connection(claimed.url, self.resolver)
            result = await self.transport.fetch(plan, self.resolver, cancelled=cancelled)
            # The future repository must reload AND lock membership/declaration
            # in the same transaction that consumes the proof and writes audit.
            return self.store.finish(claimed, result.body, reload_scope(), self.clock())
        except (Exception, asyncio.CancelledError):
            self.store.reject(claimed)
            raise
