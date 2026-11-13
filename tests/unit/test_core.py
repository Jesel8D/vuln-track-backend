from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import APIError
from app.core.security import (
    LoginLimiter,
    decode_token,
    hash_password,
    issue_token,
    verify_password,
)
from app.schemas.assets import AssetCreate
from app.services.assets import request_fingerprint
from app.services.authorization import AssetAuthorization

BODY = dict(
    device_type="router", manufacturer="Ejemplo", model="Modelo", version="1", site_label="LAB"
)


@pytest.mark.parametrize("field", [f for f in BODY if f != "version"])
def test_required(field):
    body = {**BODY}
    del body[field]
    with pytest.raises(ValidationError):
        AssetCreate(**body)


@pytest.mark.parametrize("value", ["", " ", "x" * 121, 10, "a\x00b", "a\ud800b"])
def test_invalid_text(value):
    with pytest.raises(ValidationError):
        AssetCreate(**{**BODY, "model": value})


def test_normalization_and_fingerprint():
    one = AssetCreate(**{**BODY, "manufacturer": "  Cafe\u0301  "})
    two = AssetCreate(**{**BODY, "manufacturer": "Café", "notes": None})
    assert one.manufacturer == "Café"
    assert request_fingerprint(one) == request_fingerprint(two)
    assert request_fingerprint(one) != request_fingerprint(one.model_copy(update={"version": "2"}))
    with pytest.raises(ValidationError):
        AssetCreate(**BODY, owner_id=str(uuid4()))
    with pytest.raises(ValidationError):
        AssetCreate(**BODY, notes=" ")


def test_settings(settings):
    assert settings.db_pool_size == 5
    assert settings.db_pool_pre_ping
    for update in [
        {"token_secret": "short"},
        {"db_pool_size": 0},
        {"database_url": "sqlite:///file"},
        {"database_url": "postgresql+psycopg://postgres@localhost/test"},
        {"environment": "production"},
    ]:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{**settings.model_dump(), **update})
    good = settings.model_dump() | {
        "environment": "production",
        "database_url": "postgresql+psycopg://api@db/test?sslmode=verify-full&sslrootcert=/ca.pem",
    }
    assert Settings(_env_file=None, **good).environment == "production"
    assert "postgresql" not in repr(settings)
    configured = settings.model_dump() | {"workspace_hmac_key": "a" * 64}
    assert Settings(_env_file=None, **configured).workspace_hmac_key.get_secret_value() == "a" * 64
    for invalid_key in ["a" * 63, "A" * 64, "g" * 64]:
        with pytest.raises(ValidationError):
            Settings(
                _env_file=None, **(settings.model_dump() | {"workspace_hmac_key": invalid_key})
            )


def test_passwords():
    password = "synthetic-long-password"
    encoded = hash_password(password)
    assert encoded.startswith("$argon2id$v=19$")
    assert verify_password(encoded, password)
    assert not verify_password(encoded, "wrong")
    assert not verify_password(None, password)
    assert not verify_password("invalid", password)
    assert not verify_password(encoded.replace("m=65536", "m=999999999"), password)
    with pytest.raises(ValueError):
        hash_password("short")


def test_jwt(settings):
    user = SimpleNamespace(id=uuid4(), updated_at=datetime.now(UTC))
    token = issue_token(user, settings)
    assert decode_token(token, settings)["sub"] == str(user.id)
    with pytest.raises(APIError):
        decode_token(token + "tampered", settings)
    claims = jwt.decode(
        token,
        settings.token_secret.get_secret_value(),
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    for update in [
        {"exp": 1},
        {"aud": "other"},
        {"iss": "other"},
        {"sub": "not-a-uuid"},
        {"exp": claims["iat"] + 999999},
    ]:
        forged = jwt.encode(claims | update, settings.token_secret.get_secret_value(), "HS256")
        with pytest.raises(APIError):
            decode_token(forged, settings)
    with pytest.raises(APIError):
        decode_token(
            jwt.encode(
                {"sub": str(user.id)}, "arbitrary-key-with-at-least-thirty-two-bytes", "HS256"
            ),
            settings,
        )


def test_authorization_requires_identity_and_filters_owner():
    policy = AssetAuthorization()
    for operation in [policy.require_create, policy.require_list, policy.visible_assets]:
        with pytest.raises(APIError) as exc:
            operation(None)
        assert exc.value.status == 401
    owner_id = uuid4()
    policy.require_create(owner_id)
    policy.require_list(owner_id)
    expression = policy.visible_assets(owner_id)
    assert "assets.created_by" in str(expression)
    assert expression.compile().params == {"created_by_1": owner_id}
    with pytest.raises(ValidationError):
        AssetCreate(**BODY, created_by=str(owner_id))


def test_limiter():
    limiter = LoginLimiter(1)
    limiter.check("name", "address")
    with pytest.raises(APIError) as exc:
        limiter.check("name", "another-address")
    assert exc.value.status == 429
