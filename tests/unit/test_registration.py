from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import APIError
from app.core.registration import RegistrationGate
from app.schemas.registration import Registration

PASSWORD = "A unique test phrase 7319!"


def test_ascii_normalization_and_secret_representation():
    payload = Registration(username="  New_User  ", password=PASSWORD)
    assert payload.username == "new_user"
    assert PASSWORD not in repr(payload)
    assert payload.password.get_secret_value() == PASSWORD


@pytest.mark.parametrize("username", ["ab", "x" * 81, "équipe", "ｕser", "bad@name", 3])
def test_invalid_account_identifiers(username):
    with pytest.raises(ValidationError):
        Registration(username=username, password=PASSWORD)


@pytest.mark.parametrize(
    "password",
    [
        "short",
        "x" * 129,
        "a" * 20,
        "abcd" * 5,
        "Password123456789!",
        "qwertyuiopasdfgh",
    "passwordpassword",
    "Administrator123456789!",
    "12345678901234567890",
        "new_user123456",
        "abc\x00de FG 1234567",
        "abc\ud800de FG 1234567",
    ],
)
def test_invalid_new_passwords(password):
    with pytest.raises(ValidationError):
        Registration(username="new_user", password=password)


@pytest.mark.parametrize(
    "field",
    [
        "is_admin",
        "role",
        "id",
        "created_by",
        "workspace_id",
        "workspace_owner",
        "verified_email",
        "active",
        "email",
    ],
)
def test_internal_or_unsupported_fields_forbidden(field):
    with pytest.raises(ValidationError):
        Registration(username="new_user", password=PASSWORD, **{field: "forged"})


def test_gate_bounds_concurrent_hashing_and_releases_after_error():
    gate = RegistrationGate(3, 20)
    with gate.hashing(), gate.hashing():
        with pytest.raises(APIError, match="ocupado"):
            with gate.hashing():
                pytest.fail("third concurrent hash")
    with pytest.raises(ValueError), gate.hashing():
        raise ValueError("synthetic failure")
    with gate.hashing(), gate.hashing():
        pass


def test_concurrent_global_admission_is_atomic_and_window_expires(monkeypatch):
    ticks = [100.0]
    monkeypatch.setattr("app.core.registration.time.monotonic", lambda: ticks[0])
    gate = RegistrationGate(3, 4)

    def admitted(peer):
        try:
            gate.check(peer)
            return True
        except APIError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(admitted, map(str, range(8)))) == 4
    assert all(isinstance(key, bytes) for key in gate.peers)
    ticks[0] = 160.0
    assert admitted("next") and len(gate.peers) == 1


def test_enrollment_requires_v2_key_and_is_opt_in(settings, client):
    assert not settings.registration_enabled
    assert client.post("/api/v1/auth/register", json={}).status_code == 503
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **(settings.model_dump() | {"registration_enabled": True}))
