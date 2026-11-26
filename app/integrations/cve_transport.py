"""CVE-only bounded transport. Ordinary clients have NO real CVE network capability.

Injected httpx.MockTransport is the ordinary adapter. A separately authorized
laboratory capability reuses this exact exchange and all its limits.
CPE/catalog transport remains independent and unchanged.
"""

import asyncio
import math
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from threading import Lock

import httpx

from app.core.errors import APIError
from app.schemas.cpe import parse_cpe

CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True)
class HTTPPolicy:
    timeout: float = 10
    max_bytes: int = 2097152

    def __post_init__(self):
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 30:
            raise ValueError("Invalid CVE HTTP deadline")
        if type(self.max_bytes) is not int or not 1024 <= self.max_bytes <= 2097152:
            raise ValueError("Invalid CVE body limit")


class RequestBudget:
    """One execution, including failed attempts; never reset on page/retry."""

    def __init__(
        self, *, requests=1, max_bytes=2097152, seconds=10, clock=time.monotonic, cancelled=None
    ):
        if type(requests) is not int or not 1 <= requests <= 15:
            raise ValueError("Invalid CVE request budget")
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 10485760:
            raise ValueError("Invalid CVE execution bytes")
        if not math.isfinite(seconds) or not 0 < seconds <= 300:
            raise ValueError("Invalid CVE execution deadline")
        self.limit, self.max_bytes = requests, max_bytes
        self.clock, self.cancelled = clock, cancelled
        self.deadline = clock() + seconds
        self.requests, self.bytes = 0, 0

    def remaining(self):
        if self.cancelled is not None and self.cancelled.is_set():
            raise APIError(503, "INTERRUPTED", "Consulta CVE interrumpida")
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise APIError(504, "TIME_BUDGET_REACHED", "Presupuesto de ejecución CVE agotado")
        return remaining

    def reserve(self):
        self.remaining()
        if self.requests >= self.limit:
            raise APIError(503, "REQUEST_BUDGET_REACHED", "Presupuesto de solicitudes CVE agotado")
        self.requests += 1

    def consume(self, size):
        self.bytes += size  # Received bytes count even if this page is rejected.
        if self.bytes > self.max_bytes:
            raise APIError(502, "BYTE_BUDGET_REACHED", "Presupuesto de bytes CVE agotado")
        self.remaining()


def validate_request(url, params):
    if url != CVE_URL:
        raise APIError(502, "NVD_INVALID_ORIGIN", "Origen CVE no permitido")
    if set(params) != {"cpeName", "startIndex", "resultsPerPage"}:
        raise ValueError("Only public CVE parameters are supported")
    parse_cpe(params["cpeName"])
    if (
        type(params["startIndex"]) is not int
        or not 0 <= params["startIndex"] <= 10000
        or type(params["resultsPerPage"]) is not int
        or not 1 <= params["resultsPerPage"] <= 100
    ):
        raise ValueError("Invalid bounded CVE pagination")


def retry_delay(value, *, now=None):
    """Never shorten an unbounded provider cooldown to fit a retry budget."""
    if value is None:
        return 60.0
    if len(value) > 128:
        return math.inf  # Administrative review, no automatic retry.
    if re.fullmatch(r"[0-9]+", value.strip()):
        number = int(value)
        return float(number) if number <= 86400 else math.inf
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=UTC)
        seconds = (date - (now or datetime.now(UTC))).total_seconds()
        return max(60.0, seconds) if seconds <= 86400 else math.inf
    except (ValueError, TypeError, OverflowError):
        return 60.0


def flight_lock(quota):
    # All clients sharing the app's quota also share a CVE concurrency gate.
    with quota.lock:
        if not hasattr(quota, "cve_flight_lock"):
            quota.cve_flight_lock = Lock()
        return quota.cve_flight_lock


async def _exchange(client, url, params, budget, policy):
    deadline = min(policy.timeout, budget.remaining())
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    if client.api_key:
        headers["apiKey"] = client.api_key.get_secret_value()

    transport = client.transport
    if transport is None and getattr(client, "live_transport_enabled", False):
        from app.integrations.nvd_pinned_transport import create_nvd_transport

        transport = create_nvd_transport()

    # Do not propagate an injected adapter exception/body/header or key to logs/errors.
    async def request():
        async with (
            httpx.AsyncClient(
                verify=True,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(
                    deadline,
                    connect=min(5, deadline),
                    pool=min(1, deadline),
                    write=min(5, deadline),
                ),
                transport=transport,
            ) as http,
            http.stream("GET", url, params=params, headers=headers) as response,
        ):
            budget.remaining()
            if response.status_code in {403, 429} or response.status_code >= 500:
                delay = retry_delay(response.headers.get("Retry-After"))
                client.quota.backoff(str(max(60, delay)))
                raise APIError(
                    503,
                    "NVD_THROTTLED" if response.status_code in {403, 429} else "NVD_UNAVAILABLE",
                    "NVD temporalmente no disponible",
                )
            if response.status_code != 200:
                raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE NVD no válida")
            # Never decompress an untrusted bomb. identity is requested and required.
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise APIError(502, "NVD_INVALID_RESPONSE", "Codificación CVE no admitida")
            kind = response.headers.get("Content-Type", "application/json").split(";", 1)[0]
            length = response.headers.get("Content-Length")
            if (
                kind.strip().lower() != "application/json"
                or length is not None
                and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > policy.max_bytes)
            ):
                raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE NVD no válida")
            content = bytearray()

            def append(chunk):
                budget.consume(len(chunk))
                if len(content) + len(chunk) > policy.max_bytes:
                    raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE demasiado grande")
                content.extend(chunk)

            if response.is_stream_consumed:  # Eager, trusted MockTransport response only.
                append(response.content)
            else:
                async for chunk in response.aiter_raw(chunk_size=8192):
                    append(chunk)
            if length is not None and len(content) != int(length):
                raise APIError(502, "NVD_INVALID_RESPONSE", "Longitud CVE inconsistente")
            budget.remaining()
            return bytes(content)

    operation = asyncio.create_task(request())

    async def watch():
        while True:
            budget.remaining()
            await asyncio.sleep(0.05)

    observer = asyncio.create_task(watch())
    try:
        async with asyncio.timeout(deadline):
            done, _ = await asyncio.wait([operation, observer], return_when=asyncio.FIRST_COMPLETED)
            if observer in done:
                observer.result()
            return await operation
    except TimeoutError:
        raise APIError(504, "NVD_TIMEOUT", "NVD excedió el tiempo de espera") from None
    finally:
        for task in (operation, observer):
            if not task.done():
                task.cancel()
        await asyncio.gather(operation, observer, return_exceptions=True)


def content(client, url, params, *, budget=None):
    validate_request(url, params)
    # Only a MockTransport, a scoped lab permit, or the configured pinned NVD
    # transport can pass this capability gate; a mode flag alone is insufficient.
    from app.integrations.nvd_lab_client import lab_client

    live_transport = bool(getattr(client, "live_transport_enabled", False))
    if (
        not isinstance(client.transport, httpx.MockTransport)
        and not lab_client(client)
        and not live_transport
    ):
        raise APIError(503, "CVE_LIVE_DISABLED", "CVE live no habilitado en esta versión")
    if lab_client(client):
        client.permit.check()
    policy = client.http_policy
    budget = budget or RequestBudget(max_bytes=policy.max_bytes, seconds=policy.timeout)
    guard = flight_lock(client.quota)
    if not guard.acquire(blocking=False):
        raise APIError(409, "NVD_BUSY", "Consulta CVE en curso")
    try:
        budget.remaining()
        client.quota.reserve()  # Global app quota, independent of workspace/actor.
        budget.reserve()
        return asyncio.run(_exchange(client, url, params, budget, policy))
    except APIError:
        raise
    except httpx.TimeoutException:
        raise APIError(504, "NVD_TIMEOUT", "NVD excedió el tiempo de espera") from None
    except httpx.HTTPError:
        raise APIError(503, "NVD_UNAVAILABLE", "NVD temporalmente no disponible") from None
    except (ValueError, TypeError, RecursionError):
        raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE NVD no válida") from None
    except Exception:
        raise APIError(503, "NVD_UNAVAILABLE", "NVD temporalmente no disponible") from None
    finally:
        guard.release()
