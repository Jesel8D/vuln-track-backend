"""Ephemeral LAB control service. No public endpoint, DB credentials or production grants."""

import asyncio
import json
import time
from pathlib import Path
from uuid import uuid4

from laboratory.phase2c.policy import LabPermit, identity, number
from laboratory.phase2c.protocol import (
    CONTROL_LEASE_SECONDS,
    close,
    decode,
    encode,
    signed,
    verified,
)


class Authority:
    def __init__(self, key):
        self.key = key
        self.epoch = str(uuid4())
        self.claims = {}

    def decide(self, request, state, now):
        if set(request) != {"action", "nonce", "operation_id", "session_id", "gateway_epoch"}:
            raise ValueError("Control shape")
        for field in ("nonce", "operation_id", "session_id", "gateway_epoch"):
            identity(request[field])
        response = {
            "nonce": request["nonce"],
            "authority_epoch": self.epoch,
            "allowed": False,
            "reason": "AUTHORIZATION_UNAVAILABLE",
            "policy": None,
        }
        lease = number(state["lease_until"])
        if not now < lease <= now + CONTROL_LEASE_SECONDS + 0.05:
            return response
        value = state["policies"].get(request["operation_id"])
        if value is None:
            response["reason"] = "AUTHORIZATION_REVOKED"
            return response
        permit = LabPermit.read(value)
        permit.require_current(now, request["gateway_epoch"])
        if permit.authority_epoch != self.epoch:
            return response
        operation, session = request["operation_id"], request["session_id"]
        if permit.operation_id != operation:
            raise ValueError("Control identity")
        if request["action"] == "acquire":
            if operation in self.claims:
                response["reason"] = "POLICY_ALREADY_CONSUMED"
                return response
            self.claims[operation] = session
        elif request["action"] != "check" or self.claims.get(operation) != session:
            response["reason"] = "POLICY_SESSION_INVALID"
            return response
        response.update(allowed=True, reason="LABORATORY_ONLY", policy=permit.to_dict())
        return response

    async def handle(self, reader, writer):
        try:
            async with asyncio.timeout(0.5):
                request = verified(decode(await reader.readuntil(b"\n")), self.key)
                # Atomic replacement by the external broker; never cache old permits.
                state = json.loads(Path("/tmp/phase2c-state.json").read_text())
                result = self.decide(request, state, time.time())
                writer.write(encode(signed(result, self.key)))
                await writer.drain()
        except Exception:
            # Malformed/expired/unavailable control produces no permissive response.
            pass
        finally:
            await close(writer)


async def main():
    config = json.loads(Path("/tmp/phase2c-config.json").read_text())
    authority = Authority(bytes.fromhex(config["control_key"]))
    servers = [
        await asyncio.start_server(authority.handle, ip, 9443, limit=8193) for ip in config["bind"]
    ]
    Path("/tmp/phase2c-ready.json").write_text(json.dumps({"epoch": authority.epoch}))
    async with servers[0]:
        await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
