import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import Argon2Error

from app.core.errors import APIError, unauthorized

hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, type=Type.ID)
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 256:
        raise ValueError("La contraseña debe tener entre 12 y 256 caracteres")
    return hasher.hash(password)


def verify_password(encoded: str | None, password: str) -> bool:
    try:
        parameters = extract_parameters(encoded or DUMMY_HASH)
        if (
            parameters.type != Type.ID
            or parameters.version != 19
            or not 19456 <= parameters.memory_cost <= 262144
            or not 2 <= parameters.time_cost <= 10
            or not 1 <= parameters.parallelism <= 8
        ):
            hasher.verify(DUMMY_HASH, password)
            return False
        valid = hasher.verify(encoded or DUMMY_HASH, password)
        return valid and encoded is not None
    except (Argon2Error, ValueError, TypeError):
        return False


def issue_token(user, settings) -> str:
    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        {
            "sub": str(user.id),
            "iat": now,
            "nbf": now,
            "exp": now + settings.token_ttl_seconds,
            "iss": "vulntrack",
            "aud": "vulntrack-api",
            "jti": str(uuid4()),
            "ver": user.updated_at.isoformat(),
        },
        settings.token_secret.get_secret_value(),
        algorithm="HS256",
    )


def decode_token(token: str, settings) -> dict:
    try:
        if len(token) > 2048:
            raise ValueError
        claims = jwt.decode(
            token,
            settings.token_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="vulntrack-api",
            issuer="vulntrack",
            options={"require": ["sub", "iat", "nbf", "exp", "iss", "aud", "jti", "ver"]},
        )
        UUID(claims["sub"])
        UUID(claims["jti"])
        if (
            not isinstance(claims["ver"], str)
            or claims["exp"] - claims["iat"] > settings.token_ttl_seconds
        ):
            raise ValueError
        return claims
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise unauthorized() from None


class LoginLimiter:
    """Per-process bounded limiter; production needs an upstream shared limiter."""

    def __init__(self, limit: int):
        self.limit = limit
        self.lock = threading.Lock()
        self.entries = OrderedDict()
        self.salt = secrets.token_bytes(32)

    def check(self, username: str, origin: str):
        now = time.monotonic()
        keys = [
            hmac.digest(self.salt, value.encode(), hashlib.sha256)
            for value in ("user:" + username, "ip:" + origin)
        ]
        with self.lock:
            while self.entries and next(iter(self.entries.values()))[0] <= now - 60:
                self.entries.popitem(last=False)
            if len(self.entries) + 2 > 10000:
                raise APIError(429, "LOGIN_RATE_LIMIT", "Demasiados intentos")
            for key in keys:
                started, count = self.entries.get(key, (now, 0))
                if count >= self.limit:
                    raise APIError(429, "LOGIN_RATE_LIMIT", "Demasiados intentos")
                self.entries[key] = (started, count + 1)
