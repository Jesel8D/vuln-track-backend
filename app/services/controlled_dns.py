"""Bounded operator-selected TCP DNS, exercised only in an owned network lab.

No OS DNS configuration, cache, retry or user-selected nameserver. This module
does not enable operational egress; the FastAPI verifier never instantiates it.
dnspython parses wire messages; URL/IDNA/IP decisions stay in DestinationPolicy.
"""

import asyncio
import ipaddress
import socket
from contextlib import suppress
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from app.services.web_target_policy import DestinationDenied, DestinationPolicy, public_ip


@dataclass(frozen=True, slots=True)
class DNSEndpoint:
    # Trusted operator constructor only, not an API schema or environment flag.
    # Private DNS infrastructure is distinct from destinations, which stay public-only.
    address: str
    port: int = 53

    def __post_init__(self):
        if "%" in self.address or self.port != 53:
            raise ValueError("Fixed numeric TCP/53 DNS endpoint required")
        ipaddress.ip_address(self.address)


@dataclass(frozen=True, slots=True)
class DNSLimits:
    total_seconds: float = 2
    max_answers: int = 16
    max_cnames: int = 4
    max_wire_bytes: int = 4096
    max_queries: int = 10

    def __post_init__(self):
        if not (
            0 < self.total_seconds <= 2
            and 1 <= self.max_answers <= 16
            and 0 <= self.max_cnames <= 4
            and 512 <= self.max_wire_bytes <= 4096
            and 1 <= self.max_queries <= 10
        ):
            raise ValueError("Invalid bounded DNS limits")


@dataclass(frozen=True, slots=True)
class Resolution:
    hostname: str
    canonical_name: str
    aliases: tuple[tuple[str, str], ...]
    addresses: tuple[str, ...]


def canonical_name(value):
    destination = DestinationPolicy().parse("https://" + value + "/")
    if destination.literal_ip is not None:
        raise DestinationDenied("DNS_ALIAS_NOT_A_HOSTNAME")
    return destination.hostname


class ControlledDNS:
    def __init__(self, endpoint: DNSEndpoint, *, limits=None):
        self.endpoint = endpoint
        self.limits = limits or DNSLimits()

    async def resolve(self, hostname):
        destination = DestinationPolicy().parse("https://" + hostname + "/")
        if destination.literal_ip:
            return Resolution(
                destination.hostname, destination.hostname, (), (destination.literal_ip,)
            )
        name = destination.hostname
        budget = [0]
        try:
            async with asyncio.timeout(self.limits.total_seconds):
                ipv4 = await self._family(name, dns.rdatatype.A, budget)
                ipv6 = await self._family(name, dns.rdatatype.AAAA, budget)
                if ipv4[:2] != ipv6[:2]:
                    raise DestinationDenied("DNS_CNAME_INCONSISTENT")
                addresses = tuple(sorted(set(ipv4[2] + ipv6[2])))
                if not addresses or len(addresses) > self.limits.max_answers:
                    raise DestinationDenied("DNS_ANSWER_SET_INVALID")
                return Resolution(name, ipv4[0], ipv4[1], addresses)
        except TimeoutError:
            raise DestinationDenied("DNS_TIMEOUT") from None
        except (OSError, EOFError, asyncio.IncompleteReadError, dns.exception.DNSException):
            raise DestinationDenied("DNS_UNAVAILABLE") from None

    async def _family(self, initial, kind, budget):
        current = initial
        aliases = {}
        while True:
            budget[0] += 1
            if budget[0] > self.limits.max_queries:
                raise DestinationDenied("DNS_QUERY_BUDGET")
            question = dns.message.make_query(current + ".", kind)
            response = await self._exchange(question)
            if (
                not question.is_response(response)
                or response.flags & dns.flags.TC
                or response.rcode() != dns.rcode.NOERROR
            ):
                raise DestinationDenied("DNS_RESPONSE_INVALID")
            if (
                sum(
                    len(section)
                    for section in (response.answer, response.authority, response.additional)
                )
                > 32
            ):
                raise DestinationDenied("DNS_RECORD_BUDGET")
            edges = {}
            values = {}
            count = 0
            for section in (response.answer, response.authority, response.additional):
                for rrset in section:
                    if rrset.rdclass != dns.rdataclass.IN:
                        raise DestinationDenied("DNS_CLASS_DENIED")
                    if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        for record in rrset:
                            count += 1
                            address = public_ip(record.address)
                            if count > self.limits.max_answers:
                                raise DestinationDenied("DNS_ANSWER_SET_INVALID")
                            if section is response.answer:
                                owner = canonical_name(rrset.name.to_text(omit_final_dot=True))
                                values.setdefault(owner, []).append((rrset.rdtype, address))
                    elif section is response.answer and rrset.rdtype == dns.rdatatype.CNAME:
                        owner = canonical_name(rrset.name.to_text(omit_final_dot=True))
                        if len(rrset) != 1 or owner in edges:
                            raise DestinationDenied("DNS_AMBIGUOUS_CNAME")
                        edges[owner] = canonical_name(
                            next(iter(rrset)).target.to_text(omit_final_dot=True)
                        )
                    elif section is response.answer:
                        raise DestinationDenied("DNS_ANSWER_TYPE_DENIED")
            start = current
            visited = set()
            while current in edges:
                if current in visited or current in aliases or current in values:
                    raise DestinationDenied("DNS_CNAME_LOOP_OR_CONFLICT")
                visited.add(current)
                aliases[current] = edges[current]
                if len(aliases) > self.limits.max_cnames:
                    raise DestinationDenied("DNS_CNAME_DEPTH")
                current = edges[current]
                if current in aliases:
                    raise DestinationDenied("DNS_CNAME_LOOP_OR_CONFLICT")
            if set(edges) - visited or any(owner != current for owner in values):
                raise DestinationDenied("DNS_SCOPE_MISMATCH")
            answers = [
                address for record_kind, address in values.get(current, []) if record_kind == kind
            ]
            if answers or current == start:
                return current, tuple(sorted(aliases.items())), answers
            # A CNAME-only response requires another bounded query to its final hostname.

    async def _exchange(self, question):
        address = str(ipaddress.ip_address(self.endpoint.address))
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        target = (address, 53, 0, 0) if family == socket.AF_INET6 else (address, 53)
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.setblocking(False)
        writer = None
        try:
            await asyncio.get_running_loop().sock_connect(raw, target)
            reader, writer = await asyncio.open_connection(sock=raw)
            wire = question.to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            length = int.from_bytes(await reader.readexactly(2), "big")
            if not 12 <= length <= self.limits.max_wire_bytes:
                raise DestinationDenied("DNS_WIRE_BUDGET")
            response = await reader.readexactly(length)
            return dns.message.from_wire(response, one_rr_per_rrset=True, ignore_trailing=False)
        finally:
            if writer is not None:
                writer.close()
                with suppress(Exception, asyncio.CancelledError):
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            raw.close()


class DNSPinnedHTTPS:
    """Compose fresh bounded DNS with the unchanged pinned HTTPS component.

    Both resolutions must agree in addresses AND CNAME chain. The TLS socket
    receives only a numeric validated IP; it never silently resolves again.
    """

    def __init__(self, resolver: ControlledDNS, transport):
        self.resolver, self.transport = resolver, transport

    async def fetch(self, url, *, cancelled=None):
        if cancelled is not None and cancelled.is_set():
            raise DestinationDenied("REQUEST_CANCELLED")
        operation = asyncio.create_task(self._fetch(url))
        watcher = None
        try:
            async with asyncio.timeout(10):
                if cancelled is not None:
                    watcher = asyncio.create_task(cancelled.wait())
                    done, _ = await asyncio.wait(
                        [operation, watcher], return_when=asyncio.FIRST_COMPLETED
                    )
                    if watcher in done:
                        raise DestinationDenied("REQUEST_CANCELLED")
                return await operation
        except TimeoutError:
            raise DestinationDenied("VERIFICATION_DEADLINE_EXCEEDED") from None
        finally:
            for task in [operation, watcher]:
                if task is not None:
                    if not task.done():
                        task.cancel()
                    with suppress(Exception, asyncio.CancelledError):
                        await task

    async def _fetch(self, url):
        policy = DestinationPolicy()
        destination = policy.parse(url)
        if destination.literal_ip:
            plan = policy.prepare_connection(url, lambda host: ())
            return await self.transport.fetch(plan, lambda host: ())
        original = await self.resolver.resolve(destination.hostname)
        plan = policy.prepare_connection(url, lambda host: original.addresses)
        fresh = await self.resolver.resolve(destination.hostname)
        if original != fresh:
            raise DestinationDenied("DNS_CHANGED")
        plan = policy.revalidate_plan(plan, lambda host: fresh.addresses)
        return await self.transport.fetch(plan, lambda host: fresh.addresses)
