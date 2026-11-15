"""Bounded HTTPS/1.1 transport component, NOT an enabled verifier or executor.

Only a numeric validated address reaches the socket API. Host, SNI and certificate
verification retain the canonical hostname. No system DNS, proxies, redirects,
cookies, arbitrary headers, retries or credentials. A caller must supply a bounded
controlled resolver and separately authorize the operation and enforce egress.
The application does not instantiate this component in Phase 2A.
"""

import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
from contextlib import suppress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.services.web_target_policy import (
    ConnectionPlan,
    DestinationDenied,
    DestinationPolicy,
    Resolver,
)


@dataclass(frozen=True, slots=True)
class TransportLimits:
    total_seconds: float = 5
    max_body_bytes: int = 4096
    max_header_bytes: int = 8192

    def __post_init__(self):
        if (
            not 0 < self.total_seconds <= 5
            or not 1 <= self.max_body_bytes <= 4096
            or not 256 <= self.max_header_bytes <= 8192
        ):
            raise ValueError("Invalid bounded transport limits")


@dataclass(frozen=True, slots=True)
class HTTPSResult:
    body: bytes = field(repr=False)
    peer_ip: str
    certificate_sha256: str


class PinnedHTTPS:
    def __init__(self, *, tls_context=None, limits=None):
        # Custom trust is constructor-only for an operator-controlled lab CA;
        # there is no HTTP schema, env switch or insecure TLS option.
        self.context = tls_context or ssl.create_default_context()
        if tls_context is None:
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.limits = limits or TransportLimits()
        self._check_tls()

    def _check_tls(self):
        if (
            self.context.verify_mode != ssl.CERT_REQUIRED
            or not self.context.check_hostname
            or self.context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise DestinationDenied("TLS_VERIFICATION_REQUIRED")

    async def fetch(self, plan: ConnectionPlan, resolver: Resolver, *, cancelled=None):
        """One GET, one numeric connection, a hard deadline and no fallback.

        Resolver is synchronous and MUST be bounded/nonblocking (lab fixtures
        are in-memory). No default OS resolver or deployable DNS adapter exists.
        Task cancellation closes every owned socket, including during handshake.
        """
        self._check_tls()
        if cancelled is not None and cancelled.is_set():
            raise DestinationDenied("REQUEST_CANCELLED")
        # Resolve again immediately before connecting; reject any changed set.
        fresh = DestinationPolicy().revalidate_plan(plan, resolver)
        operation = asyncio.create_task(self._exchange(fresh))
        watcher = None
        try:
            async with asyncio.timeout(self.limits.total_seconds):
                if cancelled is not None:
                    watcher = asyncio.create_task(cancelled.wait())
                    done, _ = await asyncio.wait(
                        [operation, watcher], return_when=asyncio.FIRST_COMPLETED
                    )
                    if watcher in done:
                        raise DestinationDenied("REQUEST_CANCELLED")
                return await operation
        except TimeoutError:
            raise DestinationDenied("REQUEST_DEADLINE_EXCEEDED") from None
        except ssl.SSLCertVerificationError:
            raise DestinationDenied("TLS_CERTIFICATE_REJECTED") from None
        except ssl.SSLError:
            raise DestinationDenied("TLS_FAILED") from None
        except (OSError, EOFError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            raise DestinationDenied("HTTPS_EXCHANGE_FAILED") from None
        finally:
            for task in [operation, watcher]:
                if task is not None:
                    if not task.done():
                        task.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await task

    async def _exchange(self, plan):
        destination = plan.destination
        selected = plan.addresses[0]
        family = socket.AF_INET6 if ipaddress.ip_address(selected).version == 6 else socket.AF_INET
        address = (
            (selected, destination.port, 0, 0)
            if family == socket.AF_INET6
            else (selected, destination.port)
        )
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.setblocking(False)
        writer = None
        try:
            # AF_INET/6 + canonical numeric IP: loop.sock_connect uses inet_pton;
            # tests prohibit getaddrinfo throughout the REAL TLS exchange.
            await asyncio.get_running_loop().sock_connect(raw, address)
            if str(ipaddress.ip_address(raw.getpeername()[0])) != selected:
                raise DestinationDenied("CONNECTED_PEER_MISMATCH")
            reader, writer = await asyncio.open_connection(
                sock=raw,
                ssl=self.context,
                server_hostname=destination.hostname,
                ssl_handshake_timeout=self.limits.total_seconds,
                limit=self.limits.max_header_bytes,
            )
            parsed = urlsplit(destination.url)
            request_target = parsed.path + ("?" + parsed.query if parsed.query else "")
            request = (
                f"GET {request_target} HTTP/1.1\r\nHost: {destination.http_host}\r\n"
                "Accept: text/plain\r\nAccept-Encoding: identity\r\n"
                "Cache-Control: no-cache\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            headers = await reader.readuntil(b"\r\n\r\n")
            length = self._response_length(headers)
            body = await reader.readexactly(length)
            if await reader.read(1):
                raise DestinationDenied("HTTP_TRAILING_DATA")
            certificate = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            return HTTPSResult(body, selected, hashlib.sha256(certificate).hexdigest())
        finally:
            if writer is not None:
                writer.close()
                with suppress(Exception, asyncio.CancelledError):
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            raw.close()

    def _response_length(self, data):
        if len(data) > self.limits.max_header_bytes:
            raise DestinationDenied("HTTP_HEADERS_TOO_LARGE")
        lines = data[:-4].split(b"\r\n")
        if not lines or not re.fullmatch(rb"HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e]*)?", lines[0]):
            raise DestinationDenied("HTTP_RESPONSE_INVALID")
        status = int(lines[0].split(b" ")[1])
        if 300 <= status < 400:
            raise DestinationDenied("REDIRECTS_DISABLED")
        if status != 200 or len(lines) > 50:
            raise DestinationDenied("HTTP_STATUS_OR_HEADERS_DENIED")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if (
                not separator
                or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or name.lower() in headers
                or any(char < 32 and char != 9 or char == 127 for char in value)
            ):
                raise DestinationDenied("HTTP_RESPONSE_INVALID")
            headers[name.lower()] = value.strip()
        if b"transfer-encoding" in headers or b"content-encoding" in headers:
            raise DestinationDenied("HTTP_ENCODING_DENIED")
        length = headers.get(b"content-length", b"")
        if not re.fullmatch(rb"(?:0|[1-9][0-9]{0,8})", length):
            raise DestinationDenied("HTTP_LENGTH_REQUIRED")
        if int(length) > self.limits.max_body_bytes:
            raise DestinationDenied("HTTP_BODY_TOO_LARGE")
        if headers.get(b"content-type", b"").split(b";", 1)[0].lower() != b"text/plain":
            raise DestinationDenied("HTTP_CONTENT_TYPE_DENIED")
        return int(length)
