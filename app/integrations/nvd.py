"""Fixed-origin NVD Products API. No redirects, automatic retries or reference fetching."""

import time
from collections import OrderedDict, deque
from datetime import UTC, datetime
from threading import Lock
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.errors import APIError
from app.schemas.assets import Page
from app.schemas.cpe import Candidate, CandidateList, SearchInput, parse_cpe

NVD_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class Quota:
    """One API process/egress budget; fail fast instead of queueing unbounded work.

    MVP runs one process, one instance. Shared deployments must introduce a shared
    quota before scaling. Supplying a key deliberately does not raise the budget.
    """

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = Lock()
        self.next_call = 0.0
        self.cooldown = 0.0
        self.users = OrderedDict()

    def check_user(self, actor, operation):
        with self.lock:
            now = self.clock()
            key = (actor, operation)
            # Evict inactive actors; active actors are never evicted to evade limits.
            for old in list(self.users):
                if not self.users[old] or self.users[old][-1] <= now - 60:
                    del self.users[old]
            if key not in self.users and len(self.users) >= 10000:
                raise APIError(429, "CPE_RATE_LIMIT", "Presupuesto CPE ocupado")
            calls = self.users.setdefault(key, deque())
            while calls and calls[0] <= now - 60:
                calls.popleft()
            if len(calls) >= 6:
                raise APIError(429, "CPE_RATE_LIMIT", "Límite de solicitudes CPE")
            calls.append(now)

    def reserve(self):
        with self.lock:
            now = self.clock()
            if now < self.cooldown:
                raise APIError(503, "NVD_UNAVAILABLE", "NVD temporalmente no disponible")
            if now < self.next_call:
                raise APIError(429, "NVD_RATE_LIMIT", "Esperar antes de consultar NVD")
            # Conservative spacing also without API key, no bursts (max 5/30s).
            self.next_call = now + 7

    def backoff(self):
        with self.lock:
            self.cooldown = self.clock() + 60


class Title(BaseModel):
    title: str = Field(max_length=2048)
    lang: str


class Product(BaseModel):
    model_config = ConfigDict(strict=True)
    deprecated: bool
    cpeName: str = Field(max_length=1024)
    cpeNameId: str
    titles: list[Title] = Field(default_factory=list, max_length=100)

    @field_validator("cpeName")
    @classmethod
    def valid_binding(cls, value):
        parse_cpe(value)
        return value

    @field_validator("cpeNameId")
    @classmethod
    def valid_uuid(cls, value):
        UUID(value)
        return value


class Entry(BaseModel):
    cpe: Product


class NVDPage(BaseModel):
    resultsPerPage: int = Field(strict=True, ge=0, le=20)
    startIndex: int = Field(strict=True, ge=0)
    totalResults: int = Field(strict=True, ge=0)
    format: str
    version: str
    timestamp: datetime
    products: list[Entry] = Field(max_length=20)


class NVDClient:
    def __init__(self, api_key=None, timeout=10, transport=None, quota=None):
        self.api_key = api_key
        self.timeout = timeout
        self.transport = transport
        self.quota = quota or Quota()

    def _page(self, params):
        self.quota.reserve()
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if self.api_key:
            headers["apiKey"] = self.api_key.get_secret_value()
        try:
            started = time.monotonic()
            # New bounded connection per request, no ambient proxy credentials.
            with (
                httpx.Client(
                    timeout=httpx.Timeout(self.timeout, connect=5),
                    follow_redirects=False,
                    trust_env=False,
                    transport=self.transport,
                ) as client,
                client.stream("GET", NVD_URL, params=params, headers=headers) as response,
            ):
                if response.status_code in {403, 429} or response.status_code >= 500:
                    self.quota.backoff()
                    raise APIError(503, "NVD_UNAVAILABLE", "NVD temporalmente no disponible")
                if response.status_code != 200:
                    raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta NVD no válida")
                content = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - started > self.timeout:
                        raise APIError(504, "NVD_TIMEOUT", "NVD excedió el tiempo de espera")
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise APIError(
                            502, "NVD_INVALID_RESPONSE", "Respuesta NVD demasiado grande"
                        )
            page = NVDPage.model_validate_json(content)
            count = len(page.products)
            if (
                page.format != "NVD_CPE"
                or page.version != "2.0"
                or page.startIndex != params["startIndex"]
                or page.resultsPerPage != count
                or count > params["resultsPerPage"]
                or count
                != min(params["resultsPerPage"], max(0, page.totalResults - page.startIndex))
                or len({p.cpe.cpeNameId.lower() for p in page.products}) != count
            ):
                raise ValueError("Inconsistent NVD page")
            return page
        except httpx.TimeoutException:
            raise APIError(504, "NVD_TIMEOUT", "NVD excedió el tiempo de espera") from None
        except httpx.HTTPError:
            raise APIError(503, "NVD_UNAVAILABLE", "NVD temporalmente no disponible") from None
        except (ValidationError, ValueError):
            raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta NVD no válida") from None

    def search(self, actor, search: SearchInput):
        self.quota.check_user(actor, "search")
        query = " ".join(v for v in [search.query, search.product_query] if v)
        page = self._page(
            {
                "keywordSearch": query,
                "resultsPerPage": search.limit,
                "startIndex": search.offset,
            }
        )
        return CandidateList(
            items=[self._candidate(item.cpe) for item in page.products],
            page=Page(limit=search.limit, offset=search.offset, total=page.totalResults),
            source_timestamp=page.timestamp.replace(tzinfo=page.timestamp.tzinfo or UTC),
        )

    def resolve(self, actor, name_id):
        self.quota.check_user(actor, "confirm")
        page = self._page({"cpeNameId": str(name_id), "resultsPerPage": 1, "startIndex": 0})
        if not page.products:
            raise APIError(409, "CPE_UNAVAILABLE", "CPE inexistente o deprecado")
        candidate = self._candidate(page.products[0].cpe)
        if candidate.cpe_name_id != name_id:
            raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta NVD no válida")
        if candidate.deprecated:
            raise APIError(409, "CPE_UNAVAILABLE", "CPE inexistente o deprecado")
        return candidate, datetime.now(UTC)

    @staticmethod
    def _candidate(product):
        title = next((t.title for t in product.titles if t.lang == "en"), None)
        return Candidate(
            cpe_name_id=UUID(product.cpeNameId),
            cpe_name=product.cpeName,
            title=title,
            deprecated=product.deprecated,
        )
