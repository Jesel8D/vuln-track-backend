from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.core.errors import APIError
from app.main import create_app
from app.services.web_target_authorization import (
    ControlEvidence,
    assess_target,
    public_target,
    require_web_execution,
)


@pytest.fixture
def declaration():
    now = datetime.now(UTC)
    workspace, application = uuid4(), uuid4()
    row = {
        "id": uuid4(),
        "url": "https://example.com/",
        "authorization_status": "approved",
        "authorization_expires_at": now + timedelta(days=1),
        "authorization_reference": "Declaracion de laboratorio",
        "updated_at": now,
    }
    evidence = ControlEvidence(
        workspace,
        application,
        row["id"],
        "https://example.com",
        now,
        "dns_txt",
        "a" * 64,
        now,
        now + timedelta(hours=1),
    )
    return workspace, application, row, evidence, now


@pytest.mark.parametrize(
    "status,state",
    [
        ("pending", "registered"),
        ("approved", "verification_pending"),
        ("rejected", "rejected"),
        ("expired", "expired"),
        ("unknown", "incomplete"),
    ],
)
def test_declarations_never_manufacture_verified_control(declaration, status, state):
    workspace, application, row, _, now = declaration
    row["authorization_status"] = status
    result = assess_target(row, workspace, application, now=now)
    assert result["authorization_state"] == state
    assert not result["control_verified"] and not result["execution_enabled"]
    assert "WEB_EXECUTOR_DISABLED" in result["blocking_reasons"]
    assert (
        public_target(row, workspace, application)["analysis_readiness"]["control_verified"]
        is False
    )


def test_valid_local_evidence_still_cannot_enable_execution(declaration, monkeypatch):
    workspace, application, row, evidence, now = declaration
    monkeypatch.setenv("ZAP_ENABLED", "true")
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    result = assess_target(row, workspace, application, now=now, evidence=evidence)
    assert result["authorization_state"] == "verified" and result["control_verified"]
    assert not result["execution_enabled"]
    assert "PINNED_TRANSPORT_UNAVAILABLE" in result["blocking_reasons"]
    with pytest.raises(APIError) as error:
        require_web_execution()
    assert error.value.code == "WEB_EXECUTOR_DISABLED"
    # Runtime responses never take evidence, even if a caller adds forged fields.
    row["control_verified"] = True
    assert (
        public_target(row, workspace, application)["analysis_readiness"]["control_verified"]
        is False
    )


@pytest.mark.parametrize(
    "change",
    [
        {"workspace_id": uuid4()},
        {"application_id": uuid4()},
        {"target_id": uuid4()},
        {"origin": "https://evil.com"},
        {"origin": "http://example.com"},
        {"method": "checkbox"},
        {"evidence_sha256": "not-evidence"},
        {"declaration_updated_at": datetime(2000, 1, 1, tzinfo=UTC)},
        {"verified_at": datetime(2100, 1, 1, tzinfo=UTC)},
        {"verified_at": datetime(2000, 1, 1)},
        {"expires_at": datetime(2000, 1, 1, tzinfo=UTC)},
        {"expires_at": datetime(2100, 1, 1, tzinfo=UTC)},
    ],
)
def test_evidence_bound_to_resource_origin_version_and_expiry(declaration, change):
    workspace, application, row, evidence, now = declaration
    result = assess_target(
        row, workspace, application, now=now, evidence=replace(evidence, **change)
    )
    assert not result["control_verified"] and not result["execution_enabled"]


def test_revocation_expiry_and_incomplete_authorization_fail_closed(declaration):
    workspace, application, row, evidence, now = declaration
    result = assess_target(
        row, workspace, application, now=now, evidence=replace(evidence, revoked_at=now)
    )
    assert result["authorization_state"] == "revoked" and not result["control_verified"]
    row["authorization_expires_at"] = now
    assert assess_target(row, workspace, application, now=now)["authorization_state"] == "expired"
    row["authorization_expires_at"] = None
    assert (
        assess_target(row, workspace, application, now=now)["authorization_state"] == "incomplete"
    )


def test_unsafe_historical_url_is_not_rewritten_or_eligible(declaration):
    workspace, application, row, _, now = declaration
    row["url"] = "http://127.0.0.1/"
    result = public_target(row, workspace, application)
    assert result["url"] == row["url"]
    assert not result["analysis_readiness"]["url_policy_allowed"]
    assert "URL_POLICY_DENIED" in result["analysis_readiness"]["blocking_reasons"]
    row["application_status"] = "archived"
    assert (
        "APPLICATION_INACTIVE"
        in assess_target(row, workspace, application, now=now)["blocking_reasons"]
    )


def test_no_zap_or_target_scan_operation_in_openapi(settings):
    schema = create_app(settings).openapi()
    for path, operations in schema["paths"].items():
        assert "zap" not in path.lower() and "scan" not in path.lower()
        if "/targets" in path:
            assert "/analyses" not in path
        assert "WEB_EXECUTOR_ENABLED" not in str(operations)
