"""Per-request, pinned-IP HTTPS transport for the fixed NVD CVE endpoint."""

import asyncio
import ipaddress
import socket

import httpx

from app.integrations.cve_transport import CVE_URL

NVD_HOST = "services.nvd.nist.gov"
NVD_PATH = "/rest/json/cves/2.0"


def _peer_ip(value):
    if isinstance(value, (tuple, list)):
        value = value[0]
    if not isinstance(value, str):
        raise ValueError("NVD peer address unavailable")
    return ipaddress.ip_address(value.split("%", 1)[0])


class NVDPinnedTransport(httpx.AsyncBaseTransport):
    """Resolve the one permitted host, reject non-public answers, pin, then verify TLS."""

    def __init__(self):
        self._transport = httpx.AsyncHTTPTransport(
            verify=True,
            trust_env=False,
            retries=0,
            http2=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        )

    async def handle_async_request(self, request):
        if (
            request.method != "GET"
            or request.url.scheme != "https"
            or request.url.host != NVD_HOST
            or request.url.port not in {None, 443}
            or request.url.path != NVD_PATH
            or set(request.url.params) != {"cpeName", "startIndex", "resultsPerPage"}
        ):
            raise httpx.ConnectError("NVD request outside fixed policy", request=request)

        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(NVD_HOST, 443, type=socket.SOCK_STREAM), timeout=3
            )
            resolved = (
                ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records
            )
            addresses = list(dict.fromkeys(resolved))
        except (OSError, TimeoutError, ValueError):
            raise httpx.ConnectError("NVD DNS resolution failed", request=request) from None
        if not addresses or any(not address.is_global for address in addresses):
            raise httpx.ConnectError("NVD DNS answer rejected by network policy", request=request)

        pinned = addresses[0]
        original_url = request.url
        request.url = original_url.copy_with(host=pinned.compressed)
        request.headers["host"] = NVD_HOST
        request.extensions["sni_hostname"] = NVD_HOST
        try:
            response = await self._transport.handle_async_request(request)
            stream = response.extensions.get("network_stream")
            peer = stream.get_extra_info("server_addr") if stream is not None else None
            if _peer_ip(peer) != pinned:
                await response.aclose()
                raise httpx.ConnectError("NVD peer did not match pinned address", request=request)
            return response
        except (ValueError, TypeError):
            raise httpx.ConnectError("NVD peer verification failed", request=request) from None

    async def aclose(self):
        await self._transport.aclose()


def create_nvd_transport():
    return NVDPinnedTransport()
