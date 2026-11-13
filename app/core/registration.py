"""Bounded, process-local public enrollment gate. No forwarded IP headers are trusted."""

import hashlib
import hmac
import secrets
import threading
import time
from contextlib import contextmanager

from fastapi import Request

from app.core.errors import APIError


class RegistrationGate:
    def __init__(self, per_peer: int, total: int):
        self.per_peer = per_peer
        self.total = total
        self.lock = threading.Lock()
        self.salt = secrets.token_bytes(32)
        self.started = time.monotonic()
        self.count = 0
        self.peers = {}
        self.hash_slots = threading.BoundedSemaphore(2)

    def check(self, peer: str):
        key = hmac.digest(self.salt, peer.encode(), hashlib.sha256)
        with self.lock:
            now = time.monotonic()
            if now - self.started >= 60:
                self.started, self.count, self.peers = now, 0, {}
            if self.count >= self.total or self.peers.get(key, 0) >= self.per_peer:
                raise APIError(429, "REGISTRATION_RATE_LIMIT", "Demasiados intentos de registro")
            self.count += 1
            self.peers[key] = self.peers.get(key, 0) + 1

    @contextmanager
    def hashing(self):
        if not self.hash_slots.acquire(blocking=False):
            raise APIError(503, "REGISTRATION_BUSY", "Registro temporalmente ocupado")
        try:
            yield
        finally:
            self.hash_slots.release()


def registration_access(request: Request):
    if not request.app.state.settings.registration_enabled:
        raise APIError(503, "REGISTRATION_DISABLED", "El registro no está habilitado")
    request.app.state.registration_gate.check(request.client.host if request.client else "unknown")
