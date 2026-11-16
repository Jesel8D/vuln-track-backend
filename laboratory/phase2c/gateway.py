"""Mandatory bounded HTTPS fetch gateway, ONLY for isolated Phase 2C fixtures.

Not a CONNECT proxy, verifier, ZAP executor or operational service. Worker input
contains one operation UUID; no target, proxy headers, IP, port or policy rules.
"""

import asyncio
import hashlib
import json
import ssl
import time
from contextlib import suppress
from pathlib import Path
from uuid import uuid4

from app.services.controlled_dns import ControlledDNS, DNSEndpoint
from app.services.web_target_policy import DestinationDenied, DestinationPolicy
from app.services.web_target_transport import PinnedHTTPS
from laboratory.phase2c.policy import LabPermit, operation_request
from laboratory.phase2c.protocol import close, decode, encode, rpc, signed, verified


class Gateway:
    def __init__(self, config):
        self.config = config
        self.key = bytes.fromhex(config["control_key"])
        self.epoch = str(uuid4())
        self.active = 0
        context = ssl.create_default_context(cafile="/lab/certs/ca.pem")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.transport = PinnedHTTPS(tls_context=context)
        self.resolver = ControlledDNS(DNSEndpoint(config["dns"]))

    async def decision(self, operation, session, action, *, original=None, authority_epoch=None):
        nonce = str(uuid4())
        request = {
            "action": action,
            "nonce": nonce,
            "operation_id": operation,
            "session_id": session,
            "gateway_epoch": self.epoch,
        }
        try:
            result = verified(
                await rpc(self.config["authority"], 9443, signed(request, self.key)), self.key
            )
            if (
                set(result) != {"nonce", "authority_epoch", "allowed", "reason", "policy"}
                or result["nonce"] != nonce
            ):
                raise DestinationDenied("POLICY_AUTHENTICATION_INVALID")
            if result["allowed"] is not True:
                safe_codes = {
                    "AUTHORIZATION_UNAVAILABLE",
                    "AUTHORIZATION_REVOKED",
                    "POLICY_ALREADY_CONSUMED",
                    "POLICY_SESSION_INVALID",
                }
                raise DestinationDenied(
                    result["reason"] if result["reason"] in safe_codes else "POLICY_DENIED"
                )
            permit = LabPermit.read(result["policy"])
            permit.require_current(time.time(), self.epoch)
            if result["authority_epoch"] != permit.authority_epoch:
                raise DestinationDenied("POLICY_AUTHORITY_RESTARTED")
            if permit.operation_id != operation or (original is not None and permit != original):
                raise DestinationDenied("POLICY_SCOPE_CHANGED")
            if authority_epoch is not None and result["authority_epoch"] != authority_epoch:
                raise DestinationDenied("POLICY_AUTHORITY_RESTARTED")
            return permit, result["authority_epoch"]
        except DestinationDenied:
            raise
        except Exception:
            raise DestinationDenied("POLICY_UNAVAILABLE") from None

    async def perform(self, permit, session, authority_epoch):
        policy = DestinationPolicy()
        first = await self.resolver.resolve(permit.hostname)
        second = await self.resolver.resolve(permit.hostname)
        if first != second or second.addresses != permit.addresses:
            raise DestinationDenied("POLICY_DNS_CHANGED")
        plan = policy.prepare_connection(permit.url, lambda host: second.addresses)
        # Fresh authorization after DNS, immediately before numeric connect.
        await self.decision(
            permit.operation_id, session, "check", original=permit, authority_epoch=authority_epoch
        )
        result = await self.transport.fetch(plan, lambda host: second.addresses)
        # Do not release a buffered result after losing current authorization.
        await self.decision(
            permit.operation_id, session, "check", original=permit, authority_epoch=authority_epoch
        )
        return {
            "result": "ok",
            "lab_only": True,
            "peer_ip": result.peer_ip,
            "body_sha256": hashlib.sha256(result.body).hexdigest(),
        }

    async def watch(self, permit, session, authority_epoch):
        while True:
            await asyncio.sleep(0.1)
            await self.decision(
                permit.operation_id,
                session,
                "check",
                original=permit,
                authority_epoch=authority_epoch,
            )

    async def handle(self, reader, writer):
        task = watcher = None
        admitted = False
        code = "GATEWAY_REJECTED"
        op_digest = None
        try:
            async with asyncio.timeout(8):
                operation = operation_request(
                    decode(await asyncio.wait_for(reader.readuntil(b"\n"), timeout=0.5))
                )
                op_digest = hashlib.sha256(operation.encode()).hexdigest()
                if self.active >= 4:
                    raise DestinationDenied("GATEWAY_CAPACITY")
                self.active += 1
                admitted = True
                session = str(uuid4())
                permit, authority_epoch = await self.decision(operation, session, "acquire")
                # A monotonic local deadline cannot be extended by a later wall-clock change.
                remaining = min(permit.maximum_seconds, permit.expires_at - time.time())
                if remaining <= 0:
                    raise DestinationDenied("POLICY_EXPIRED")
                async with asyncio.timeout(remaining):
                    task = asyncio.create_task(self.perform(permit, session, authority_epoch))
                    watcher = asyncio.create_task(self.watch(permit, session, authority_epoch))
                    done, _ = await asyncio.wait(
                        [task, watcher], return_when=asyncio.FIRST_COMPLETED
                    )
                    if watcher in done:
                        await watcher
                        raise DestinationDenied("POLICY_UNAVAILABLE")
                    result = await task
                    code = "ALLOWED_LAB_ONLY"
                    writer.write(encode(result))
                    await writer.drain()
        except DestinationDenied as error:
            code = error.code
        except TimeoutError:
            code = "POLICY_OR_REQUEST_DEADLINE"
        except Exception:
            code = "GATEWAY_REJECTED"
        finally:
            for owned in (task, watcher):
                if owned is not None:
                    if not owned.done():
                        owned.cancel()
                    with suppress(Exception, asyncio.CancelledError):
                        await owned
            if admitted:
                self.active -= 1
            if code != "ALLOWED_LAB_ONLY":
                with suppress(Exception):
                    writer.write(encode({"result": "denied", "code": code, "lab_only": True}))
                    await writer.drain()
            # Sanitized decision metadata only: no URL, body, identities or control key.
            with suppress(OSError):
                log_path = Path("/tmp/phase2c-decisions.jsonl")
                if log_path.exists() and log_path.stat().st_size >= 1024 * 1024:
                    log_path.write_text("")
                with log_path.open("a") as log:
                    log.write(json.dumps({"operation_sha256": op_digest, "decision": code}) + "\n")
            await close(writer)  # No keep-alive or reusable worker tunnel.


async def main():
    config = json.loads(Path("/tmp/phase2c-config.json").read_text())
    gateway = Gateway(config)
    servers = [
        await asyncio.start_server(gateway.handle, ip, 8443, limit=8193) for ip in config["bind"]
    ]
    Path("/tmp/phase2c-ready.json").write_text(json.dumps({"epoch": gateway.epoch}))
    async with servers[0]:
        await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
