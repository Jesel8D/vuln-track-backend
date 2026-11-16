"""Adversarial control-plane boundaries, independent from live kernel/TLS checks."""

import asyncio
import dataclasses
import json
from uuid import uuid4

import pytest

from app.services.web_target_policy import DestinationDenied
from laboratory.phase2c.authority import Authority
from laboratory.phase2c.gateway import Gateway
from laboratory.phase2c.policy import LabPermit, operation_request, require_lab_snapshot
from laboratory.phase2c.protocol import decode, encode, signed, verified


def permit(**changes):
    values = {
        field: str(uuid4())
        for field in (
            "operation_id",
            "workspace_id",
            "application_id",
            "target_id",
            "challenge_id",
            "actor_id",
            "gateway_epoch",
            "authority_epoch",
        )
    }
    values.update(
        url="https://control.example.net/ok",
        hostname="control.example.net",
        scheme="https",
        port=443,
        addresses=("93.184.216.10",),
        target_version="2026-11-15T12:00:00Z",
        challenge_version=1,
        issued_at=1000.0,
        expires_at=1008.0,
        declaration_expires_at=2000.0,
        challenge_expires_at=1500.0,
    )
    return LabPermit(**(values | changes))


def request(p, action="acquire", session=None):
    return {
        "action": action,
        "nonce": str(uuid4()),
        "operation_id": p.operation_id,
        "session_id": session or str(uuid4()),
        "gateway_epoch": p.gateway_epoch,
    }


def state(p, **changes):
    return {"lease_until": 1001.6, "policies": {p.operation_id: p.to_dict()}} | changes


def test_permit_round_trip_immutable_and_lab_only():
    p = permit()
    assert LabPermit.read(json.loads(json.dumps(p.to_dict()))) == p
    assert LabPermit.read(p.to_dict()).digest == p.digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.port = 80


@pytest.mark.parametrize(
    "changes",
    [
        {"provenance": "operational"},
        {"port": 80},
        {"port": True},
        {"scheme": "http"},
        {"url": "https://127.0.0.1/"},
        {"url": "https://user:pw@control.example.net/"},
        {"url": "https://control.example.net:8443/"},
        {"hostname": "other.example.net"},
        {"addresses": ()},
        {"addresses": ("10.0.0.1",)},
        {"addresses": ("93.184.216.10", "127.0.0.1")},
        {"addresses": ("::1",)},
        {"addresses": ("2606:4700:ffff::10%eth0",)},
        {"addresses": ("93.184.216.10", "93.184.216.10")},
        {"addresses": ["93.184.216.10"]},
        {"expires_at": 1011},
        {"expires_at": 999},
        {"issued_at": float("nan")},
        {"expires_at": float("inf")},
        {"expires_at": True},
        {"declaration_expires_at": 1005},
        {"challenge_expires_at": 1005},
        {"maximum_seconds": 60},
        {"maximum_seconds": True},
        {"maximum_connections": 2},
        {"maximum_connections": True},
        {"challenge_version": 0},
        {"challenge_version": True},
        {"workspace_id": "untrusted-workspace"},
        {"operation_id": "none"},
    ],
)
def test_permit_rejects_scope_protocol_address_time_and_resource_bypasses(changes):
    with pytest.raises((ValueError, TypeError)):
        permit(**changes)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {"operation_id": "bad"},
        {"operation_id": str(uuid4()), "ip": "93.184.216.10"},
        {"operation_id": str(uuid4()), "host": "control.example.net"},
        {"operation_id": str(uuid4()), "port": 443},
        {"operation_id": str(uuid4()), "workspace_id": str(uuid4())},
    ],
)
def test_worker_cannot_choose_a_network_policy(value):
    with pytest.raises((ValueError, TypeError)):
        operation_request(value)


def test_authenticated_frames_reject_tampering_duplicate_fields_and_oversize():
    key = bytes(range(32))
    value = {"nonce": str(uuid4()), "allowed": False}
    frame = signed(value, key)
    assert verified(decode(encode(frame)), key) == value
    assert key.hex().encode() not in encode(frame)
    altered = {"message": value | {"allowed": True}, "mac": frame["mac"]}
    with pytest.raises(ValueError):
        verified(altered, key)
    with pytest.raises(ValueError):
        verified(frame, b"wrong-key")
    with pytest.raises(ValueError):
        decode(b'{"allowed":false,"allowed":true}')
    with pytest.raises(ValueError):
        decode(b"x" * 8193)
    with pytest.raises(ValueError):
        encode({"value": float("nan")})


def test_authority_serializes_consumption_and_checks_current_session():
    p = permit()
    authority = Authority(b"private-lab-key")
    authority.epoch = p.authority_epoch
    initial = request(p)
    assert authority.decide(initial, state(p), 1001)["allowed"]
    assert not authority.decide(request(p), state(p), 1001)["allowed"]
    assert authority.decide(request(p, "check", initial["session_id"]), state(p), 1001)["allowed"]
    assert not authority.decide(request(p, "check"), state(p), 1001)["allowed"]


def test_authority_heartbeat_revocation_and_restart_are_fail_closed():
    p = permit()
    authority = Authority(b"private-lab-key")
    authority.epoch = p.authority_epoch
    assert not authority.decide(request(p), state(p, lease_until=1000), 1001)["allowed"]
    assert not authority.decide(request(p), state(p, lease_until=1010), 1001)["allowed"]
    assert not authority.decide(request(p), state(p, policies={}), 1001)["allowed"]
    restarted = Authority(b"private-lab-key")
    assert not restarted.decide(request(p), state(p), 1001)["allowed"]
    with pytest.raises(DestinationDenied):
        p.require_current(1008, p.gateway_epoch)
    with pytest.raises(DestinationDenied):
        p.require_current(1001, str(uuid4()))


@pytest.mark.parametrize(
    "changes",
    [
        {"workspace_id": str(uuid4())},
        {"application_id": str(uuid4())},
        {"target_id": str(uuid4())},
        {"state": "verified"},
        {"state": "revoked"},
        {"effective_state": "expired"},
        {"scope_invalidated": True},
        {"attempts": 1},
        {"control_verified": True},
        {"remote_verification_available": True},
        {"execution_enabled": True},
    ],
)
def test_fixtures_and_foreign_or_stale_scopes_cannot_become_operational_permission(changes):
    p = permit()
    target = {
        "id": p.target_id,
        "workspace_id": p.workspace_id,
        "application_id": p.application_id,
        "url": p.url,
        "authorization_status": "approved",
    }
    challenge = {
        "workspace_id": p.workspace_id,
        "application_id": p.application_id,
        "target_id": p.target_id,
        "state": "pending",
        "effective_state": "pending",
        "scope_invalidated": False,
        "attempts": 0,
        "control_verified": False,
        "remote_verification_available": False,
        "execution_enabled": False,
    }
    require_lab_snapshot(
        target, challenge, workspace=p.workspace_id, application=p.application_id, actor=p.actor_id
    )
    with pytest.raises(ValueError):
        require_lab_snapshot(
            target,
            challenge | changes,
            workspace=p.workspace_id,
            application=p.application_id,
            actor=p.actor_id,
        )


@pytest.mark.parametrize(
    "attack", ["bad_mac", "wrong_nonce", "wrong_gateway_epoch", "scope_changed"]
)
def test_gateway_rejects_forged_replayed_and_changed_control_response(monkeypatch, attack):
    # Construct only the control client; do not instantiate DNS, TLS or sockets.
    key = bytes(range(32))
    gateway = object.__new__(Gateway)
    gateway.key = key
    p = permit()
    gateway.epoch = p.gateway_epoch
    gateway.config = {"authority": "127.0.0.1"}
    monkeypatch.setattr("laboratory.phase2c.gateway.time.time", lambda: 1001)

    async def fake_rpc(address, port, frame):
        req = verified(frame, key)
        issued = p
        if attack == "wrong_gateway_epoch":
            issued = dataclasses.replace(p, gateway_epoch=str(uuid4()))
        if attack == "scope_changed":
            issued = dataclasses.replace(p, target_id=str(uuid4()))
        response = {
            "nonce": req["nonce"] if attack != "wrong_nonce" else str(uuid4()),
            "authority_epoch": p.authority_epoch,
            "allowed": True,
            "reason": "LABORATORY_ONLY",
            "policy": issued.to_dict(),
        }
        return signed(response, key if attack != "bad_mac" else b"forged")

    monkeypatch.setattr("laboratory.phase2c.gateway.rpc", fake_rpc)
    with pytest.raises(DestinationDenied):
        asyncio.run(
            gateway.decision(
                p.operation_id, str(uuid4()), "check", original=p, authority_epoch=p.authority_epoch
            )
        )
