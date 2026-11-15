"""Real controlled TCP DNS + pinned TLS. No DB credentials enter this worker."""

import asyncio
import hashlib
import json
import os
import socket
import ssl
import sys

from app.services.controlled_dns import ControlledDNS, DNSEndpoint, DNSLimits, DNSPinnedHTTPS
from app.services.web_target_policy import DestinationDenied
from app.services.web_target_transport import PinnedHTTPS


async def main():
    request = json.loads(input())
    assert request["url"].startswith(
        "https://control.example.net/.well-known/vulntrack-verification/"
    )
    assert not any(
        os.environ.get(key)
        for key in ["DATABASE_URL", "TOKEN_SECRET", "WORKSPACE_HMAC_KEY", "POSTGRES_PASSWORD"]
    )
    initial_fds = len(os.listdir("/proc/self/fd"))

    def forbidden_dns(*args, **kwargs):
        raise AssertionError("OS DNS fallback during controlled DNS/TLS")

    socket.getaddrinfo = forbidden_dns

    class DiagnosticDNS(ControlledDNS):
        async def _exchange(self, question):
            try:
                return await super()._exchange(question)
            except Exception as error:
                print(type(error).__name__, getattr(error, "errno", None), file=sys.stderr)
                raise

    resolver = DiagnosticDNS(DNSEndpoint("10.77.0.53"))
    context = ssl.create_default_context(cafile="/lab/certs/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    transport = PinnedHTTPS(tls_context=context)
    result = await DNSPinnedHTTPS(resolver, transport).fetch(request["url"])
    evidence = {
        "received_sha256": hashlib.sha256(result.body).hexdigest(),
        "peer_ip": result.peer_ip,
        "certificate_sha256": result.certificate_sha256,
    }
    checks = [
        "real TCP DNS A/AAAA and pinned HTTPS composed without OS DNS",
        "no database/application credentials in network worker",
    ]
    alias = await resolver.resolve("cname.example.net")
    assert alias.canonical_name == "control.example.net" and len(alias.aliases) == 1
    checks.append("real CNAME resolution with bounded depth")
    ipv6_dns = await ControlledDNS(DNSEndpoint("fd00:77::53")).resolve("control.example.net")
    assert len(ipv6_dns.addresses) == 2
    checks.append("real numeric IPv6 TCP DNS endpoint with A/AAAA answers")
    for name, expected in [
        ("mixed.example.net", "NON_PUBLIC_IP"),
        ("loop.example.net", "DNS_CNAME_LOOP_OR_CONFLICT"),
        ("oversize.example.net", "DNS_WIRE_BUDGET"),
        ("truncated.example.net", "DNS_RESPONSE_INVALID"),
    ]:
        try:
            await resolver.resolve(name)
        except DestinationDenied as error:
            assert error.code == expected, (error.code, expected)
        else:
            raise AssertionError("Unsafe DNS fixture accepted")
        checks.append(expected)
    try:
        await DNSPinnedHTTPS(resolver, transport).fetch("https://rebind.example.net/")
    except DestinationDenied as error:
        assert error.code == "DNS_CHANGED"
    else:
        raise AssertionError("Rebinding reached HTTPS")
    checks.append("changed DNS set denied before a TLS connection")
    short = ControlledDNS(DNSEndpoint("10.77.0.53"), limits=DNSLimits(total_seconds=0.1))
    try:
        await short.resolve("slow.example.net")
    except DestinationDenied as error:
        assert error.code == "DNS_TIMEOUT"
    else:
        raise AssertionError("DNS deadline ignored")
    checks.append("real DNS timeout without retry")
    cancel = asyncio.Event()
    task = asyncio.create_task(
        DNSPinnedHTTPS(resolver, transport).fetch("https://slow.example.net/", cancelled=cancel)
    )
    await asyncio.sleep(0.05)
    cancel.set()
    try:
        await task
    except DestinationDenied as error:
        assert error.code == "REQUEST_CANCELLED"
    else:
        raise AssertionError("DNS cancellation ignored")
    checks.append("cancellation during real TCP DNS closes the socket")
    # Deliberately bypass Python to prove that the DNS-changed public-shaped
    # local alias remains denied by the independent static egress policy.
    probe = socket.socket()
    probe.settimeout(0.15)
    try:
        probe.connect(("93.184.216.12", 443))
    except (TimeoutError, PermissionError):
        pass
    else:
        raise AssertionError("Unapproved changed destination bypassed netfilter")
    finally:
        probe.close()
    checks.append("independent egress denies the changed IP even when Python is bypassed")
    await asyncio.sleep(0.05)
    assert len(os.listdir("/proc/self/fd")) == initial_fds
    checks.append("DNS/TLS success, rejection, timeout and cancellation leak no socket FDs")
    print(json.dumps({"result": "passed", "checks": checks, "evidence": evidence}), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
