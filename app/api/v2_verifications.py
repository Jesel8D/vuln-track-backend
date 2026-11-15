"""Durable challenge metadata only; no remote verification is enabled."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import DBAPIError

from app.api.router import Identity
from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.services.target_verification import VerificationService

router = APIRouter(
    prefix="/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets/{target_id}/verifications"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChallengeIssue(StrictModel):
    expected_updated_at: datetime

    @field_validator("expected_updated_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timezone required")
        return value


class ChallengeVersion(StrictModel):
    expected_version: int = Field(strict=True, ge=1, le=2147483647)


class Evidence(StrictModel):
    id: UUID
    provenance: Literal["laboratory"]
    started_at: datetime
    completed_at: datetime | None
    outcome: Literal[
        "in_progress",
        "laboratory_match",
        "proof_mismatch",
        "transport_failed",
        "expired",
        "revoked",
    ]


class ChallengeRead(StrictModel):
    id: UUID
    workspace_id: UUID
    application_id: UUID
    target_id: UUID
    method: Literal["https_file"]
    origin: str
    state: Literal["pending", "verified", "failed", "expired", "revoked"]
    effective_state: Literal["pending", "failed", "expired", "revoked", "unavailable"]
    scope_invalidated: bool
    version: int
    attempts: int = Field(ge=0, le=1)
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    verified_at: datetime | None
    revoked_at: datetime | None
    result_code: str
    control_verified: Literal[False]
    remote_verification_available: Literal[False]
    execution_enabled: Literal[False]
    blocking_reasons: list[str]
    evidence: list[Evidence]


class Instructions(StrictModel):
    url: str
    body: str = Field(repr=False)


class IssueResult(StrictModel):
    challenge: ChallengeRead
    created: bool
    instructions: Instructions | None


class ChallengeList(StrictModel):
    items: list[ChallengeRead]
    remote_verification_available: Literal[False]
    execution_enabled: Literal[False]
    blocking_reasons: list[str]


def service(session, w, a, t, *, write=False):
    return VerificationService(session, w, a, t, write=write)


@router.get("", response_model=ChallengeList)
def list_verifications(
    workspace_id: UUID, application_id: UUID, target_id: UUID, user: Identity, request: Request
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        return service(session, workspace_id, application_id, target_id).listing()


@router.post(
    "", response_model=IssueResult, status_code=201, responses={200: {"model": IssueResult}}
)
def issue_verification(
    workspace_id: UUID,
    application_id: UUID,
    target_id: UUID,
    payload: ChallengeIssue,
    user: Identity,
    request: Request,
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
):
    try:
        with workspace_session(
            request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
        ) as session:
            result = service(session, workspace_id, application_id, target_id, write=True).issue(
                payload.expected_updated_at, idempotency_key
            )
            validated = IssueResult.model_validate(result)
        return JSONResponse(
            validated.model_dump(mode="json"),
            status_code=201 if result["created"] else 200,
            headers={"Pragma": "no-cache"},
        )
    except DBAPIError as error:
        if getattr(error.orig, "sqlstate", None) == "54000":
            raise APIError(
                429, "VERIFICATION_QUOTA_REACHED", "Cuota de desafíos alcanzada"
            ) from None
        raise


@router.get("/{challenge_id}", response_model=ChallengeRead)
def get_verification(
    workspace_id: UUID,
    application_id: UUID,
    target_id: UUID,
    challenge_id: UUID,
    user: Identity,
    request: Request,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        component = service(session, workspace_id, application_id, target_id)
        return component.public(component.get(challenge_id))


@router.post("/{challenge_id}/revoke", response_model=ChallengeRead)
def revoke_verification(
    workspace_id: UUID,
    application_id: UUID,
    target_id: UUID,
    challenge_id: UUID,
    payload: ChallengeVersion,
    user: Identity,
    request: Request,
):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        return service(session, workspace_id, application_id, target_id, write=True).revoke(
            challenge_id, payload.expected_version
        )


@router.post("/{challenge_id}/verify", status_code=503)
def verify_target_control(
    workspace_id: UUID,
    application_id: UUID,
    target_id: UUID,
    challenge_id: UUID,
    payload: ChallengeVersion,
    user: Identity,
    request: Request,
):
    """Explicitly unavailable: no DNS/network call, queue, attempt or result is created."""
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        service(session, workspace_id, application_id, target_id, write=True).verify(
            challenge_id, payload.expected_version
        )
