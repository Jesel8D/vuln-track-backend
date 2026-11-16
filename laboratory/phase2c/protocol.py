"""Bounded, nonce-bound authenticated control frames; no secrets in logs."""

import asyncio
import hashlib
import hmac
import json
import socket
from contextlib import suppress

MAX_FRAME = 8192
CONTROL_TIMEOUT = 0.35
CONTROL_LEASE_SECONDS = 1.5


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate field")
        value[key] = item
    return value


def decode(data):
    if not 1 <= len(data) <= MAX_FRAME:
        raise ValueError("Frame limit")
    return json.loads(data, object_pairs_hook=unique_object)


def encode(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > MAX_FRAME:
        raise ValueError("Frame limit")
    return data + b"\n"


def signed(value, key):
    return {"message": value, "mac": hmac.new(key, encode(value), hashlib.sha256).hexdigest()}


def verified(value, key):
    if not isinstance(value, dict) or set(value) != {"message", "mac"}:
        raise ValueError("Invalid authenticated frame")
    expected = signed(value["message"], key)["mac"]
    if not isinstance(value["mac"], str) or not hmac.compare_digest(value["mac"], expected):
        raise ValueError("Control authentication failed")
    return value["message"]


async def close(writer):
    writer.close()
    with suppress(Exception, asyncio.CancelledError):
        await asyncio.wait_for(writer.wait_closed(), 0.2)


async def rpc(address, port, message, *, timeout=CONTROL_TIMEOUT):
    # Numeric endpoints only. Never resolve a hostname through the system.
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.setblocking(False)
    writer = None
    try:
        async with asyncio.timeout(timeout):
            await asyncio.get_running_loop().sock_connect(raw, (address, port))
            reader, writer = await asyncio.open_connection(sock=raw, limit=MAX_FRAME + 1)
            writer.write(encode(message))
            await writer.drain()
            return decode(await reader.readuntil(b"\n"))
    finally:
        if writer is not None:
            await close(writer)
        raw.close()
