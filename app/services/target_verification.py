"""Durable scoped lifecycle. Remote verification is unconditionally unavailable.

Issuance and revocation call audited, RLS-constrained SQL008 functions. No DNS,
socket, task queue, lab verifier or HTTP client is instantiated by this service.
"""

import hashlib
from datetime import UTC, datetime

from sqlalchemy import select, text

from app.core.errors import APIError
from app.models.verification import Challenge, VerificationAttempt
from app.services.web_target_policy import DestinationDenied, DestinationPolicy
from app.services.web_target_tokens import challenge_material

BLOCKING_REASONS = [
    "PUBLIC_EGRESS_UNPROVEN",
    "OPERATIONAL_DNS_UNAVAILABLE",
    "WEB_EXECUTOR_DISABLED",
]


class VerificationService:
    def __init__(self, session, workspace_id, application_id, target_id, *, write=False):
        self.session = session
        self.workspace, self.application, self.target_id = workspace_id, application_id, target_id
        roles = ["owner", "editor"] if write else ["owner", "editor", "viewer"]
        if not session.scalar(
            text("SELECT vulntrack.has_workspace_role(:w,:roles)"),
            {"w": workspace_id, "roles": roles},
        ):
            raise APIError(404, "TARGET_NOT_FOUND", "Destino no disponible")
        self.target = (
            session.execute(
                text("""SELECT t.*,a.status AS application_status
            FROM vulntrack.application_targets t JOIN vulntrack.applications a
            ON a.workspace_id=t.workspace_id AND a.id=t.application_id
            WHERE t.workspace_id=:w AND t.application_id=:a AND t.id=:t"""),
                {"w": workspace_id, "a": application_id, "t": target_id},
            )
            .mappings()
            .first()
        )
        if self.target is None:
            raise APIError(404, "TARGET_NOT_FOUND", "Destino no disponible")

    def get(self, identity):
        record = self.session.scalar(
            select(Challenge).where(
                Challenge.workspace_id == self.workspace,
                Challenge.application_id == self.application,
                Challenge.target_id == self.target_id,
                Challenge.id == identity,
            )
        )
        if record is None:
            raise APIError(404, "VERIFICATION_NOT_FOUND", "Verificación no disponible")
        return record

    def public(self, record):
        now = datetime.now(UTC)
        target = self.target
        invalidated = (
            record.declaration_version != target["updated_at"]
            or record.url_sha256 != hashlib.sha256(target["url"].encode()).hexdigest()
            or target["application_status"] != "active"
            or target["authorization_status"] != "approved"
            or target["authorization_expires_at"] is None
            or target["authorization_expires_at"] <= now
        )
        effective = record.state
        if record.state == "revoked":
            effective = "revoked"
        elif record.state == "pending" and record.expires_at <= now:
            effective = "expired"
        elif invalidated:
            effective = "revoked"
        elif record.state == "verified" or (record.state == "pending" and record.attempts):
            # No operational verifier/provenance exists in this release.
            effective = "unavailable"
        attempts = self.session.scalars(
            select(VerificationAttempt).where(
                VerificationAttempt.workspace_id == self.workspace,
                VerificationAttempt.challenge_id == record.id,
            )
        ).all()
        return {
            "id": record.id,
            "workspace_id": record.workspace_id,
            "application_id": record.application_id,
            "target_id": record.target_id,
            "method": record.method,
            "origin": record.origin,
            "state": record.state,
            "effective_state": effective,
            "scope_invalidated": invalidated,
            "version": record.version,
            "attempts": record.attempts,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "consumed_at": record.consumed_at,
            "verified_at": record.verified_at,
            "revoked_at": record.revoked_at,
            "result_code": record.result_code,
            "control_verified": False,
            "remote_verification_available": False,
            "execution_enabled": False,
            "blocking_reasons": BLOCKING_REASONS.copy(),
            "evidence": [
                {
                    "id": attempt.id,
                    "provenance": attempt.provenance,
                    "started_at": attempt.started_at,
                    "completed_at": attempt.completed_at,
                    "outcome": attempt.outcome,
                }
                for attempt in attempts
            ],
        }

    def listing(self):
        rows = self.session.scalars(
            select(Challenge)
            .where(
                Challenge.workspace_id == self.workspace,
                Challenge.application_id == self.application,
                Challenge.target_id == self.target_id,
            )
            .order_by(Challenge.created_at.desc(), Challenge.id.desc())
            .limit(20)
        ).all()
        return {
            "items": [self.public(row) for row in rows],
            "remote_verification_available": False,
            "execution_enabled": False,
            "blocking_reasons": BLOCKING_REASONS.copy(),
        }

    def issue(self, expected, request_key):
        target = self.target
        try:
            destination = DestinationPolicy().parse(target["url"])
        except DestinationDenied:
            raise APIError(
                422, "VERIFICATION_DESTINATION_DENIED", "Destino HTTPS no elegible"
            ) from None
        if target["application_status"] != "active" or target["authorization_status"] != "approved":
            raise APIError(409, "DECLARATION_REQUIRED", "Se requiere una declaración vigente")
        identity, body, digest = challenge_material()
        row = (
            self.session.execute(
                text("""SELECT * FROM vulntrack_verification.issue(
            :w,:a,:t,:id,:key,:expected,:origin,:digest)"""),
                {
                    "w": self.workspace,
                    "a": self.application,
                    "t": self.target_id,
                    "id": identity,
                    "key": request_key,
                    "expected": expected,
                    "origin": destination.origin,
                    "digest": digest,
                },
            )
            .mappings()
            .one()
        )
        record = self.get(row["challenge_id"])
        return {
            "challenge": self.public(record),
            "created": row["created"],
            "instructions": {
                "url": f"{record.origin}/.well-known/vulntrack-verification/{record.id}",
                "body": body.decode("ascii"),
            }
            if row["created"]
            else None,
        }

    def revoke(self, identity, expected):
        self.session.execute(
            text("SELECT vulntrack_verification.revoke(:w,:a,:t,:id,:version)"),
            {
                "w": self.workspace,
                "a": self.application,
                "t": self.target_id,
                "id": identity,
                "version": expected,
            },
        )
        self.session.expire_all()
        return self.public(self.get(identity))

    def verify(self, identity, expected):
        record = self.get(identity)
        if record.version != expected:
            raise APIError(
                409, "VERIFICATION_CONFLICT", "La verificación cambió; actualiza la vista"
            )
        if self.public(record)["effective_state"] != "pending":
            raise APIError(409, "VERIFICATION_NOT_PENDING", "El desafío ya no admite comprobación")
        # Not a feature flag. No operation can cross this boundary in Phase 2B.
        raise APIError(
            503,
            "VERIFICATION_EGRESS_UNAVAILABLE",
            "Verificación remota no disponible: egreso y DNS operativos pendientes",
        )
