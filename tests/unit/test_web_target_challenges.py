import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.main import create_app
from app.services.web_target_authorization import assess_target, public_target
from app.services.web_target_challenges import (
    PURPOSE,
    LaboratoryChallengeStore,
    LaboratoryVerifier,
    Scope,
)
from app.services.web_target_policy import DestinationDenied


@pytest.fixture
def setup():
    now = datetime.now(UTC)
    scope = Scope(
        *(uuid4() for _ in range(4)),
        "owner",
        "https://control.example.net/path?q=private",
        now,
        now + timedelta(hours=1),
    )
    store = LaboratoryChallengeStore()
    return store, scope, now


def test_random_tokens_are_hashed_bound_expiring_and_never_in_audit_or_repr(setup):
    store, scope, now = setup
    issued = store.issue(scope, now)
    assert issued.body.startswith(PURPOSE.encode())
    assert issued.expires_at == now + timedelta(minutes=10)
    nonce = issued.body.rsplit(b":", 1)[1]
    assert len(nonce) == 43  # 32 random bytes / 256 bits
    assert nonce.decode() not in repr(issued)
    assert nonce.decode() not in repr(store._records)
    assert nonce.decode() not in str(store.events)
    assert "private" not in str(store.events)
    assert (
        issued.url == f"https://control.example.net/.well-known/vulntrack-verification/{issued.id}"
    )
    other = store.issue(replace(scope, target_id=uuid4()), now)
    assert other.body != issued.body


@pytest.mark.parametrize(
    "changes",
    [
        {"role": "viewer"},
        {"role": "none"},
        {"declaration_status": "pending"},
        {"declaration_status": "rejected"},
        {"application_status": "archived"},
        {"url": "http://example.com/"},
        {"url": "https://127.0.0.1/"},
        {"declaration_expires_at": datetime(2020, 1, 1, tzinfo=UTC)},
        {"declaration_updated_at": datetime(2100, 1, 1, tzinfo=UTC)},
    ],
)
def test_ineligible_scope_cannot_issue_a_challenge(setup, changes):
    store, scope, now = setup
    with pytest.raises(DestinationDenied):
        store.issue(replace(scope, **changes), now)
    assert not store._records and not store.events


@pytest.mark.parametrize("field", ["workspace_id", "application_id", "target_id", "actor_id"])
def test_foreign_identity_or_resource_cannot_claim_or_revoke(setup, field):
    store, scope, now = setup
    issued = store.issue(scope, now)
    other = replace(scope, **{field: uuid4()})
    for operation in [store.claim, store.revoke]:
        with pytest.raises(DestinationDenied, match="CHALLENGE_NOT_AVAILABLE"):
            operation(issued.id, other, now)
    assert store._records[issued.id].state == "pending"


def test_claim_concurrency_and_replay_are_atomic(setup):
    store, scope, now = setup
    issued = store.issue(scope, now)

    def claim(_):
        try:
            return store.claim(issued.id, scope, now)
        except DestinationDenied:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))
    claimed = [value for value in results if value]
    assert len(claimed) == 1
    evidence = store.finish(claimed[0], issued.body, scope, now)
    assert evidence.origin == "https://control.example.net"
    with pytest.raises(DestinationDenied, match="CHALLENGE_ALREADY_CONSUMED"):
        store.claim(issued.id, scope, now)
    with pytest.raises(DestinationDenied, match="CHALLENGE_CHANGED"):
        store.finish(claimed[0], issued.body, scope, now)
    assert len([e for e in store.events if e["action"] == "control.challenge.verified"]) == 1


def test_duplicate_active_challenges_and_expiry_are_denied(setup):
    store, scope, now = setup
    issued = store.issue(scope, now)
    with pytest.raises(DestinationDenied, match="CHALLENGE_ALREADY_ACTIVE"):
        store.issue(scope, now)
    with pytest.raises(DestinationDenied, match="CHALLENGE_EXPIRED"):
        store.claim(issued.id, scope, now + timedelta(minutes=10))
    assert store._records[issued.id].state == "expired"
    assert store.issue(scope, now + timedelta(minutes=11)).id != issued.id


@pytest.mark.parametrize("body", [b"wrong", b"", None, b"vulntrack-login-token:other-purpose"])
def test_wrong_proof_consumes_challenge_without_evidence(setup, body):
    store, scope, now = setup
    issued = store.issue(scope, now)
    claimed = store.claim(issued.id, scope, now)
    with pytest.raises(DestinationDenied, match="CHALLENGE_PROOF_REJECTED"):
        store.finish(claimed, body, scope, now)
    assert store._records[issued.id].state == "rejected"
    assert store._records[issued.id].evidence is None


@pytest.mark.parametrize(
    "change", ["membership_removed", "declaration_changed", "expired", "missing"]
)
def test_authorization_is_reloaded_before_evidence_is_committed(setup, change):
    store, scope, now = setup
    issued = store.issue(scope, now)
    claimed = store.claim(issued.id, scope, now)
    fresh = (
        replace(scope, role="none")
        if change == "membership_removed"
        else replace(scope, declaration_updated_at=now + timedelta(seconds=1))
        if change == "declaration_changed"
        else None
        if change == "missing"
        else scope
    )
    finish_time = now + timedelta(minutes=11) if change == "expired" else now
    with pytest.raises(DestinationDenied, match="CHALLENGE_PROOF_REJECTED"):
        store.finish(claimed, issued.body, fresh, finish_time)
    assert store._records[issued.id].evidence is None


def test_revocation_invalidates_verified_control_without_enabling_execution(setup):
    store, scope, now = setup
    issued = store.issue(scope, now)
    claimed = store.claim(issued.id, scope, now)
    evidence = store.finish(claimed, issued.body, scope, now)
    row = {
        "id": scope.target_id,
        "url": scope.url,
        "authorization_status": "approved",
        "authorization_expires_at": scope.declaration_expires_at,
        "authorization_reference": "Lab declaration",
        "updated_at": scope.declaration_updated_at,
    }
    readiness = assess_target(
        row, scope.workspace_id, scope.application_id, now=now, evidence=evidence
    )
    assert readiness["control_verified"] and not readiness["execution_enabled"]
    # API serializers STILL have no evidence producer/store and cannot verify.
    assert not public_target(row, scope.workspace_id, scope.application_id)["analysis_readiness"][
        "control_verified"
    ]
    store.revoke(issued.id, scope, now)
    evidence = store._records[issued.id].evidence
    readiness = assess_target(
        row, scope.workspace_id, scope.application_id, now=now, evidence=evidence
    )
    assert readiness["authorization_state"] == "revoked"
    assert not readiness["control_verified"] and not readiness["execution_enabled"]


def test_audit_failure_never_commits_verification(setup):
    store, scope, now = setup
    issued = store.issue(scope, now)
    claimed = store.claim(issued.id, scope, now)

    def reject_audit(event):
        raise RuntimeError("Simulated audit unavailable")

    store.audit_sink = reject_audit
    with pytest.raises(RuntimeError, match="Simulated audit unavailable"):
        store.finish(claimed, issued.body, scope, now)
    assert store._records[issued.id] == claimed
    assert store._records[issued.id].evidence is None
    assert not any(event["state"] == "verified" for event in store.events)


def test_revocation_during_inflight_verification_wins(setup):
    store, scope, now = setup
    issued = store.issue(scope, now)

    async def run():
        started, release = asyncio.Event(), asyncio.Event()

        class Transport:
            async def fetch(self, *args, **kwargs):
                started.set()
                await release.wait()
                return SimpleNamespace(body=issued.body)

        verifier = LaboratoryVerifier(
            store, Transport(), lambda host: ["8.8.8.8"], clock=lambda: now
        )
        task = asyncio.create_task(verifier.verify(issued.id, scope, reload_scope=lambda: scope))
        await started.wait()
        store.revoke(issued.id, scope, now)
        release.set()
        with pytest.raises(DestinationDenied, match="CHALLENGE_CHANGED"):
            await task
        assert store._records[issued.id].state == "revoked"
        assert store._records[issued.id].evidence is None

    asyncio.run(run())


def test_remote_verifier_and_executor_are_not_registered_or_enabled_by_environment(
    monkeypatch, settings
):
    monkeypatch.setenv("DOMAIN_VERIFICATION_ENABLED", "true")
    monkeypatch.setenv("ZAP_ENABLED", "true")
    routes = create_app(settings).openapi()["paths"]
    assert not any("zap" in path for path in routes)
    verification = next(
        value
        for path, value in routes.items()
        if path.endswith("/verifications/{challenge_id}/verify")
    )
    assert "503" in verification["post"]["responses"]
    assert "200" not in verification["post"]["responses"]
