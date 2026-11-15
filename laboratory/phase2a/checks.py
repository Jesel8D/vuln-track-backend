"""Real sockets/TLS inside an egress-denied lab; output never contains tokens."""

import asyncio
import base64
import json
import os
import socket
import ssl
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from app.services.web_target_challenges import (
    LaboratoryChallengeStore,
    LaboratoryVerifier,
    Scope,
)
from app.services.web_target_policy import DestinationDenied, DestinationPolicy
from app.services.web_target_transport import PinnedHTTPS, TransportLimits

V4, V6 = "93.184.216.10", "2606:4700:ffff::10"


async def main():
    now = datetime.now(UTC)
    scope = Scope(
        *(uuid4() for _ in range(4)),
        "owner",
        "https://control.example.net/",
        now,
        now + timedelta(hours=1),
    )
    store = LaboratoryChallengeStore()
    instructions = store.issue(scope, now)
    # Private host-orchestrator protocol. Parent consumes this without printing,
    # provisions the owned fixture, then acknowledges before any request starts.
    print(
        json.dumps({"fixture_body_b64": base64.b64encode(instructions.body).decode()}), flush=True
    )
    assert input() == "READY"
    checks = []
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    for family in ["-4", "-6"]:
        routes = json.loads(subprocess.check_output(["ip", "-j", family, "route", "show"]))
        assert all(route.get("dev") == "lo" and route.get("dst") != "default" for route in routes)
    checks.append("live namespace: loopback only, no IPv4/IPv6 external/default routes")
    initial_fds = len(os.listdir("/proc/self/fd"))
    context = ssl.create_default_context(cafile="/lab/certs/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    class DiagnosticHTTPS(PinnedHTTPS):
        async def _exchange(self, plan):
            try:
                return await super()._exchange(plan)
            except Exception as error:
                # Stable type/errno only, never request/proof/response contents.
                print(type(error).__name__, getattr(error, "errno", None), file=sys.stderr)
                raise

    client = DiagnosticHTTPS(tls_context=context)

    def no_dns(*args, **kwargs):
        raise AssertionError("Unexpected DNS resolution from actual connection")

    socket.getaddrinfo = no_dns
    os.environ.update(
        {"HTTPS_PROXY": "http://127.0.0.1:5432", "ALL_PROXY": "http://10.77.0.10:5432"}
    )
    policy = DestinationPolicy()

    def resolver(host):
        return [V4]

    plan = policy.prepare_connection(scope.url, resolver)
    result = await client.fetch(plan, resolver)
    assert result.body == instructions.body and result.peer_ip == V4
    assert len(result.certificate_sha256) == 64
    checks.extend(
        [
            "real IPv4 pinned TCP/TLS",
            "original Host and certificate hostname",
            "getaddrinfo forbidden during real exchange",
            "environment proxies ignored",
        ]
    )

    def ipv6(host):
        return [V6]

    result = await client.fetch(policy.prepare_connection(scope.url, ipv6), ipv6)
    assert result.peer_ip == V6 and result.body == instructions.body
    checks.append("real IPv6 pinned TCP/TLS")
    verifier = LaboratoryVerifier(store, client, resolver)
    evidence = await verifier.verify(instructions.id, scope, reload_scope=lambda: scope)
    assert evidence.target_id == scope.target_id and evidence.method == "http_file"
    store.revoke(instructions.id, scope, datetime.now(UTC))
    checks.extend(["random single-purpose challenge over real pinned HTTPS", "proof revocation"])

    async def denied(
        path, code, *, transport=client, host="control.example.net", resolve=resolver, scenario=None
    ):
        try:
            await transport.fetch(
                policy.prepare_connection(f"https://{host}/{path}", resolve), resolve
            )
        except DestinationDenied as error:
            assert error.code == code, (error.code, code)
        else:
            raise AssertionError("Expected closed failure: " + code)
        checks.append(scenario or code + (":" + path if path else ""))

    await denied(
        "",
        "TLS_CERTIFICATE_REJECTED",
        host="wrong.example.net",
        scenario="wrong certificate hostname rejected",
    )
    await denied(
        "",
        "TLS_CERTIFICATE_REJECTED",
        transport=PinnedHTTPS(),
        scenario="untrusted certificate chain rejected",
    )
    await denied(
        "",
        "TLS_CERTIFICATE_REJECTED",
        resolve=lambda host: ["93.184.216.11"],
        scenario="expired certificate rejected",
    )
    await denied("redirect", "REDIRECTS_DISABLED")
    await denied("huge", "HTTP_BODY_TOO_LARGE")
    await denied("header-flood", "HTTPS_EXCHANGE_FAILED")
    await denied("chunked", "HTTP_ENCODING_DENIED")
    short = PinnedHTTPS(tls_context=context, limits=TransportLimits(total_seconds=0.15))
    await denied("slow", "REQUEST_DEADLINE_EXCEEDED", transport=short)
    cancel = asyncio.Event()
    request = asyncio.create_task(
        client.fetch(
            policy.prepare_connection("https://control.example.net/slow", resolver),
            resolver,
            cancelled=cancel,
        )
    )
    await asyncio.sleep(0.05)
    cancel.set()
    try:
        await request
    except DestinationDenied as error:
        assert error.code == "REQUEST_CANCELLED"
    else:
        raise AssertionError("Cancellation failed")
    checks.append("in-flight socket cancellation")

    # Deliberately BYPASS Python policy: independent netfilter must block these.
    for host, port in [
        ("127.0.0.1", 5432),
        ("10.77.0.10", 5432),
        ("169.254.169.254", 80),
        (V4, 80),
        ("127.0.0.11", 53),
    ]:
        sock = socket.socket()
        sock.settimeout(0.12)
        try:
            sock.connect((host, port))
        except (TimeoutError, PermissionError):
            pass
        else:
            raise AssertionError("Independent egress filter did not deny lab canary")
        finally:
            sock.close()
    checks.append("raw TCP denied to listening DB/private/metadata/HTTP/DNS lab canaries")
    for family, kind, address in [
        (socket.AF_INET6, socket.SOCK_STREAM, ("::1", 5432, 0, 0)),
        (socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.11", 53)),
    ]:
        sock = socket.socket(family, kind)
        sock.settimeout(0.12)
        try:
            if kind == socket.SOCK_DGRAM:
                sock.sendto(b"lab-dns-canary", address)
                sock.recvfrom(32)
            else:
                sock.connect(address)
        except (TimeoutError, PermissionError):
            pass
        else:
            raise AssertionError("Independent IPv6/UDP egress was not denied")
        finally:
            sock.close()
    checks.append("raw IPv6 TCP and UDP DNS denied independently of Python policy")
    assert os.getuid() == 65532
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status
    assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == str(128 * 1024**2)
    assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "32"
    assert Path("/sys/fs/cgroup/cpu.max").read_text().split()[0] == "50000"
    assert not Path("/var/run/docker.sock").exists()
    assert not Path("/run/secrets").exists()
    assert not any(
        os.environ.get(key)
        for key in [
            "DATABASE_URL",
            "TOKEN_SECRET",
            "WORKSPACE_HMAC_KEY",
            "NVD_API_KEY",
            "POSTGRES_PASSWORD",
        ]
    )
    try:
        raw_probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        pass
    else:
        raw_probe.close()
        raise AssertionError("Worker unexpectedly has raw-socket privileges")
    await asyncio.sleep(0.05)
    assert len(os.listdir("/proc/self/fd")) == initial_fds
    checks.append("no socket FD leaks after success, TLS failures, timeout or cancellation")
    try:
        Path("/lab/forbidden-write").write_text("no")
    except OSError:
        pass
    else:
        raise AssertionError("Root filesystem writable")
    checks.extend(
        [
            "non-root and zero capabilities",
            "no-new-privileges",
            "read-only root; no host files/socket/app secrets",
            "live cgroup memory/pids/CPU limits",
        ]
    )
    print(json.dumps({"result": "passed", "checks": checks, "zap_executed": False}), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
