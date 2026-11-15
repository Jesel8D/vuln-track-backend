"""Shared single-purpose 256-bit challenge material; never persisted in plaintext."""

import hashlib
import secrets
from uuid import uuid4

PURPOSE = "vulntrack-domain-control-https-v1"


def challenge_material():
    identity = uuid4()
    body = f"{PURPOSE}:{identity}:{secrets.token_urlsafe(32)}".encode("ascii")
    return identity, body, hashlib.sha256(body).hexdigest()
