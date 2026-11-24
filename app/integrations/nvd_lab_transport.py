"""One fixed-origin lab adapter; HTTP decoding/limits stay in cve_transport.

HTTPX 0.28.1/httpcore 1.0.9 forward sni_hostname to start_tls. The URL's
numeric host pins the TCP destination; Host/SNI/certificate name remain NVD.
"""

import asyncio
import hashlib
import ipaddress
import ssl
import time
from dataclasses import dataclass

import certifi
import httpx

from app.core.errors import APIError
from app.integrations.nvd_lab_authorization import HOST, PARAMS, Permit, denied


def public_ipv4(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError("Public unicast IPv4 required")
    return str(address)


def validated_answers(answers):
    # Fail if *any* address is special/private; no selecting a good answer from a
    # poisoned set. IPv4 only is deliberate; no host-wide IPv6 modification.
    if not isinstance(answers, list) or not 1 <= len(answers) <= 16:
        raise ValueError("Bounded DNS answers required")
    return sorted({public_ipv4(value) for value in answers})


@dataclass(frozen=True)
class Pin:
    address: str
    resolved_monotonic: float
    started_monotonic: float | None = None

    def check(self):
        public_ipv4(self.address)
        start = (
            self.started_monotonic
            if self.started_monotonic is not None
            else self.resolved_monotonic
        )
        if not start <= self.resolved_monotonic <= time.monotonic() < start + 20:
            raise denied()

    def remaining(self):
        self.check()
        start = (
            self.started_monotonic
            if self.started_monotonic is not None
            else self.resolved_monotonic
        )
        return 20 - (time.monotonic() - start)


class NVDLabTransport(httpx.AsyncBaseTransport):
    """Only the verified lab factory supplies a Permit. No URL/proxy/TLS options."""

    def __init__(self, permit, pin):
        if type(permit) is not Permit:
            raise denied()
        permit.check()
        pin.check()
        self.permit, self.pin = permit, pin
        self.attempts = 0
        self.peer_verified = False
        self.raw_digest = None
        self.evidence = None
        self.closed = False
        self._lock = asyncio.Lock()
        self.context = ssl.create_default_context(cafile=certifi.where())
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._http = httpx.AsyncHTTPTransport(
            verify=self.context,
            trust_env=False,
            retries=0,
            http2=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        )

    async def handle_async_request(self, request):
        async with self._lock:
            self.permit.check()
            self.pin.check()
            expected = {k: str(v) for k, v in PARAMS.items()}
            if (
                request.method != "GET"
                or request.url.scheme != "https"
                or request.url.host != HOST
                or request.url.port not in (None, 443)
                or request.url.path != "/rest/json/cves/2.0"
                or request.url.username
                or request.url.password
                or request.url.fragment
                or len(request.url.params.multi_items()) != 3
                or dict(request.url.params) != expected
                or request.headers.get("host") != HOST
                or "authorization" in request.headers
                or "apiKey" in request.headers
                or set(request.extensions) - {"timeout"}
            ):
                raise APIError(502, "TRIAL_PLAN_MISMATCH", "Consulta fuera del plan")
            if self.closed or self.attempts:
                raise APIError(503, "REQUEST_BUDGET_REACHED", "Ensayo ya consumido")
            self.attempts += 1  # Failed TLS/HTTP attempts are terminal too.
            # Never resolve HOST again; this numeric destination is from validated
            # DNS inside the lab's short-lived network namespace.
            pinned = httpx.Request(
                "GET",
                request.url.copy_with(host=self.pin.address),
                headers=request.headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": HOST},
            )
            response = await self._http.handle_async_request(pinned)
            try:
                stream = response.extensions.get("network_stream")
                tls = stream.get_extra_info("ssl_object") if stream else None
                peer = stream.get_extra_info("server_addr") if stream else None
                if (
                    not isinstance(tls, (ssl.SSLObject, ssl.SSLSocket))
                    or tls.context is not self.context
                    or tls.context.verify_mode != ssl.CERT_REQUIRED
                    or not tls.context.check_hostname
                    or tls.server_hostname != HOST
                    or not tls.getpeercert(binary_form=True)
                    or not peer
                    or peer[0] != self.pin.address
                    or peer[1] != 443
                ):
                    raise APIError(502, "TRIAL_TLS_UNVERIFIED", "Identidad TLS no acreditada")
                self.evidence = {
                    "status": response.status_code,
                    "peer_ip": self.pin.address,
                    "tls_version": tls.version(),
                    "certificate_sha256": hashlib.sha256(
                        tls.getpeercert(binary_form=True)
                    ).hexdigest(),
                    "content_type": response.headers.get("Content-Type", "")[:128],
                    "content_encoding": response.headers.get("Content-Encoding", "identity")[:32],
                    "content_length": response.headers.get("Content-Length", "")[:16],
                }
                self.peer_verified = True
                return response
            except BaseException:
                await response.aclose()
                raise

    def attest(self, raw):
        # Called only after CVEClient schema validation, not on HTTP status alone.
        if not self.peer_verified or self.attempts != 1:
            raise denied()
        self.raw_digest = hashlib.sha256(raw).hexdigest()

    async def aclose(self):
        self.closed = True
        await self._http.aclose()
