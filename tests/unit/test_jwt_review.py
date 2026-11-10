from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest

from app.core.errors import APIError
from app.core.security import decode_token, issue_token


def claims(settings):
    user = SimpleNamespace(id=uuid4(), updated_at=datetime.now(UTC))
    encoded = issue_token(user, settings)
    return jwt.decode(
        encoded,
        settings.token_secret.get_secret_value(),
        algorithms=["HS256"],
        options={"verify_aud": False},
    )


@pytest.mark.parametrize(
    "variant",
    [
        "expired",
        "future",
        "missing_exp",
        "string_exp",
        "float_iat",
        "bool_nbf",
        "long_ttl",
        "list_audience",
        "wrong_issuer",
    ],
)
def test_strict_temporal_and_required_claims(settings, variant):
    body = claims(settings)
    changes = {
        "expired": {"iat": 1, "nbf": 1, "exp": 2},
        "future": {"iat": body["iat"] + 3600, "nbf": body["iat"] + 3600, "exp": body["iat"] + 3700},
        "string_exp": {"exp": str(body["exp"])},
        "float_iat": {"iat": float(body["iat"])},
        "bool_nbf": {"nbf": False},
        "long_ttl": {"exp": body["iat"] + 901},
        "list_audience": {"aud": ["vulntrack-api", "other"]},
        "wrong_issuer": {"iss": "other"},
    }
    if variant == "missing_exp":
        del body["exp"]
    else:
        body.update(changes[variant])
    token = jwt.encode(body, settings.token_secret.get_secret_value(), algorithm="HS256")
    with pytest.raises(APIError) as result:
        decode_token(token, settings)
    assert result.value.status == 401


@pytest.mark.parametrize("algorithm", ["none", "HS384", "HS512"])
def test_algorithm_is_fixed_to_hs256(settings, algorithm):
    key = "" if algorithm == "none" else settings.token_secret.get_secret_value()
    token = jwt.encode(claims(settings), key, algorithm=algorithm)
    with pytest.raises(APIError):
        decode_token(token, settings)


def test_bad_signature_and_oversized_tokens(settings):
    token = jwt.encode(
        claims(settings), "different-key-with-over-thirty-two-bytes", algorithm="HS256"
    )
    for value in [token, "x" * 2049, "not.a.valid.token"]:
        with pytest.raises(APIError):
            decode_token(value, settings)
