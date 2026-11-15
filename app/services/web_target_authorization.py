"""Separate a stored declaration from control verification and execution.

No verification producer/store or web executor exists in Phase 1. API callers
cannot submit ControlEvidence; existing approvals are always unverified.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from app.core.errors import APIError
from app.services.web_target_policy import INVENTORY_POLICY, POLICY_VERSION, DestinationDenied

AuthorizationState = Literal[
    "registered",
    "requested",
    "verification_pending",
    "verified",
    "rejected",
    "revoked",
    "expired",
    "incomplete",
]


@dataclass(frozen=True, slots=True)
class ControlEvidence:
    """Future trusted verifier output, NOT a request schema or a permission token.

    Persistence, trusted provenance and DNS/HTTP verification remain pending.
    IDs/origin/version/expiry binding is locally testable without network access.
    """

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


def _aware(value):
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
    )


def assess_target(
    row,
    workspace_id: UUID,
    application_id: UUID,
    *,
    now: datetime | None = None,
    evidence: ControlEvidence | None = None,
):
    """Describe an already RLS-authorized row; never authorizes a connection.

    The resource IDs must come from a checked workspace transaction, not a
    request body. Runtime serializers always leave evidence=None in Phase 1.
    """
    now = now or datetime.now(UTC)
    if not _aware(now):
        raise ValueError("Timezone-aware authorization clock required")
    reasons = []
    state: AuthorizationState = "incomplete"
    url_allowed = False
    destination = None
    try:
        destination = INVENTORY_POLICY.parse(row.get("url"))
        url_allowed = True
    except DestinationDenied:
        reasons.append("URL_POLICY_DENIED")
    status = row.get("authorization_status")
    expiry = row.get("authorization_expires_at")
    updated = row.get("updated_at")
    reference = row.get("authorization_reference")
    if status == "pending":
        state = "registered"
        reasons.append("DECLARATION_REQUIRED")
    elif status == "rejected":
        state = "rejected"
        reasons.append("DECLARATION_REJECTED_OR_WITHDRAWN")
    elif status == "expired" or (status == "approved" and _aware(expiry) and expiry <= now):
        state = "expired"
        reasons.append("DECLARATION_EXPIRED")
    elif (
        status == "approved"
        and _aware(expiry)
        and _aware(updated)
        and (isinstance(reference, str) and reference.strip())
    ):
        state = "verification_pending"
    else:
        reasons.append("AUTHORIZATION_INCOMPLETE")

    verified = False
    if state == "verification_pending" and evidence is not None:
        if evidence.revoked_at is not None:
            state = "revoked"
            reasons.append("CONTROL_REVOKED")
        elif (
            _aware(evidence.verified_at)
            and _aware(evidence.expires_at)
            and evidence.verified_at <= now < evidence.expires_at
            and evidence.expires_at <= expiry
            and evidence.workspace_id == workspace_id
            and evidence.application_id == application_id
            and evidence.target_id == row.get("id")
            and evidence.declaration_updated_at == updated
            and evidence.method in {"dns_txt", "http_file", "administrative"}
            and isinstance(evidence.evidence_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", evidence.evidence_sha256)
            and destination is not None
            and evidence.origin == destination.origin
        ):
            state, verified = "verified", True
        else:
            reasons.append("CONTROL_EVIDENCE_INVALID_OR_STALE")
    if not verified:
        reasons.append("CONTROL_VERIFICATION_REQUIRED")
    if row.get("application_status", "active") != "active":
        reasons.append("APPLICATION_INACTIVE")
    # No switch, env var, user role or supplied evidence can enable an executor.
    reasons.extend(
        [
            "PINNED_TRANSPORT_UNAVAILABLE",
            "NETWORK_ISOLATION_UNAVAILABLE",
            "WEB_EXECUTOR_DISABLED",
        ]
    )
    return {
        "policy_version": POLICY_VERSION,
        "authorization_state": state,
        "control_verified": verified,
        "url_policy_allowed": url_allowed,
        "execution_enabled": False,
        "blocking_reasons": reasons,
    }


def public_target(row, workspace_id: UUID, application_id: UUID):
    result = dict(row)
    # Never reconstruct verification from an approval/reference or accept proof
    # from the client. No verified record is manufactured for historical rows.
    result["analysis_readiness"] = assess_target(result, workspace_id, application_id)
    return result


def require_web_execution():
    """Future integration must retain this denial until Phase 2 is authorized."""
    raise APIError(503, "WEB_EXECUTOR_DISABLED", "La ejecución web no está habilitada")
