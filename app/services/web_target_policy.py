"""Local URL policy and connection *plans*. This module never opens a connection.

A plan is not an execution permission or a transport. A future adapter must pin
the selected IP, preserve Host/SNI/TLS verification and enforce independent egress.
Until that adapter is implemented and tested, web execution stays unavailable.
"""

import ipaddress
import re
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from itertools import islice
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import idna

Resolver = Callable[[str], Iterable[str]]
POLICY_VERSION = "web-public-v1"
MAX_DNS_ANSWERS = 16
PLAN_LIFETIME_SECONDS = 5
LOCAL_SUFFIXES = (
    "localhost",
    "localdomain",
    "local",
    "internal",
    "lan",
    "home",
    "arpa",
    "test",
    "example",
    "invalid",
    "onion",
    "alt",
)
IPV4_DENIED = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "168.63.129.16/32",
    )
)
IPV6_UNICAST = ipaddress.ip_network("2000::/3")
IPV6_DENIED = tuple(
    ipaddress.ip_network(value)
    for value in ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")
)


class DestinationDenied(ValueError):
    """Stable public code only; never include a submitted URL or DNS exception."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def public_ip(value: str) -> str:
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
    except ValueError:
        raise DestinationDenied("INVALID_IP") from None
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise DestinationDenied("NON_PUBLIC_IP")
    if isinstance(address, ipaddress.IPv4Address):
        if any(address in network for network in IPV4_DENIED):
            raise DestinationDenied("NON_PUBLIC_IP")
    elif (
        address not in IPV6_UNICAST
        or any(address in network for network in IPV6_DENIED)
        or address.ipv4_mapped is not None
        or address.sixtofour is not None
        or address.teredo is not None
    ):
        raise DestinationDenied("IPV6_TRANSITION_OR_NON_PUBLIC")
    return str(address)


@dataclass(frozen=True, slots=True)
class Destination:
    url: str
    scheme: str
    hostname: str
    port: int
    literal_ip: str | None

    @property
    def origin(self):
        authority = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{self.scheme}://{authority}"

    @property
    def http_host(self):
        return self.origin.split("://", 1)[1]


@dataclass(frozen=True, slots=True)
class ConnectionPlan:
    destination: Destination
    addresses: tuple[str, ...]
    resolved_at: float
    verify_tls: bool = field(default=True, init=False)
    trust_environment: bool = field(default=False, init=False)
    follow_redirects: bool = field(default=False, init=False)
    automatic_retries: int = field(default=0, init=False)

    @property
    def server_hostname(self):
        return self.destination.hostname


@dataclass(frozen=True, slots=True)
class DestinationPolicy:
    # HTTP is explicit only for recording existing HTTP(S) inventory contracts.
    # Future execution planning defaults to HTTPS/443, without environment flags.
    allow_http: bool = False

    def parse(self, value: str) -> Destination:
        if (
            not isinstance(value, str)
            or not 8 <= len(value) <= 2048
            or "\\" in value
            or "#" in value
            or any(c.isspace() or unicodedata.category(c).startswith("C") for c in value)
            or re.search(r"%(?![0-9a-fA-F]{2})", value)
        ):
            raise DestinationDenied("INVALID_URL")
        try:
            parsed = urlsplit(value)
            port = parsed.port
            host = parsed.hostname
        except ValueError:
            raise DestinationDenied("INVALID_URL") from None
        schemes = {"https", "http"} if self.allow_http else {"https"}
        if parsed.scheme not in schemes or not value.lower().startswith(parsed.scheme + "://"):
            raise DestinationDenied("SCHEME_NOT_ALLOWED")
        if not host or parsed.username is not None or parsed.password is not None:
            raise DestinationDenied("INVALID_AUTHORITY")
        if "%" in parsed.netloc or parsed.netloc.endswith(":") or host.endswith("."):
            raise DestinationDenied("AMBIGUOUS_HOST")
        approved_port = 443 if parsed.scheme == "https" else 80
        if port is not None and (
            port != approved_port or parsed.netloc.rsplit(":", 1)[1] != str(port)
        ):
            raise DestinationDenied("PORT_NOT_ALLOWED")
        literal = None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if (
                ":" in host
                or any(separator in host for separator in "\u3002\uff0e\uff61")
                or unicodedata.normalize("NFC", host) != host
            ):
                raise DestinationDenied("AMBIGUOUS_HOST") from None
            try:
                host = idna.encode(host.lower(), uts46=False, std3_rules=True).decode("ascii")
            except (idna.IDNAError, UnicodeError):
                raise DestinationDenied("INVALID_HOST") from None
            labels = host.split(".")
            if (
                len(host) > 253
                or len(labels) < 2
                or labels[-1] in LOCAL_SUFFIXES
                or any(not label or len(label) > 63 for label in labels)
                or re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host)
                or not re.search(r"[a-z]", labels[-1])
            ):
                raise DestinationDenied("LOCAL_OR_AMBIGUOUS_HOST") from None
        else:
            literal = public_ip(host)
            host = literal
        # Reject parser/request-target confusion without decoding the actual URL.
        decoded_path = parsed.path
        for _ in range(3):
            try:
                decoded_path = unquote(decoded_path, errors="strict")
            except UnicodeError:
                raise DestinationDenied("INVALID_PATH") from None
            if (
                decoded_path.startswith("//")
                or any(segment in {".", ".."} for segment in decoded_path.split("/"))
                or "\\" in decoded_path
                or any(unicodedata.category(c).startswith("C") for c in decoded_path)
            ):
                raise DestinationDenied("AMBIGUOUS_PATH")
        authority = f"[{host}]" if ":" in host else host
        decoded_query = parsed.query
        for _ in range(3):
            try:
                decoded_query = unquote(decoded_query, errors="strict")
            except UnicodeError:
                raise DestinationDenied("INVALID_QUERY") from None
            if any(unicodedata.category(c).startswith("C") for c in decoded_query):
                raise DestinationDenied("INVALID_QUERY")
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
        canonical = urlunsplit((parsed.scheme, authority, path, query, ""))
        if len(canonical) > 2048:
            raise DestinationDenied("INVALID_URL")
        return Destination(canonical, parsed.scheme, host, approved_port, literal)

    def prepare_connection(self, value: str, resolver: Resolver) -> ConnectionPlan:
        destination = self.parse(value)
        if destination.literal_ip:
            answers = (destination.literal_ip,)
        else:
            try:
                answers = tuple(islice(iter(resolver(destination.hostname)), MAX_DNS_ANSWERS + 1))
            except Exception:
                raise DestinationDenied("DNS_UNAVAILABLE") from None
        if not answers or len(answers) > MAX_DNS_ANSWERS:
            raise DestinationDenied("DNS_ANSWER_SET_INVALID")
        # Deny the ENTIRE set if even one answer is unsafe. No fallback/retry.
        addresses = tuple(sorted({public_ip(address) for address in answers}))
        return ConnectionPlan(destination, addresses, time.monotonic())

    def revalidate_plan(self, plan: ConnectionPlan, resolver: Resolver) -> ConnectionPlan:
        elapsed = time.monotonic() - plan.resolved_at
        if not 0 <= elapsed <= PLAN_LIFETIME_SECONDS:
            raise DestinationDenied("CONNECTION_PLAN_EXPIRED")
        fresh = self.prepare_connection(plan.destination.url, resolver)
        if fresh.destination != plan.destination or fresh.addresses != plan.addresses:
            raise DestinationDenied("DNS_CHANGED")
        return fresh

    def redirect(self, location: str):
        # Including same-origin, relative redirects and protocol upgrades.
        # No second request is permitted, so no attacker-supplied Location is fetched.
        raise DestinationDenied("REDIRECTS_DISABLED")


INVENTORY_POLICY = DestinationPolicy(allow_http=True)
