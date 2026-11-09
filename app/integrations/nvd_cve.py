"""NVD CVE 2.0 boundary. Fixed HTTPS origin, bounded body, no redirects/references."""

import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.errors import APIError
from app.integrations.nvd import NVDClient
from app.schemas.cpe import parse_cpe

CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVE(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=80)
    vulnStatus: str = Field(min_length=1, max_length=80)
    published: str = Field(max_length=40)
    lastModified: str = Field(max_length=40)
    descriptions: list[dict] = Field(default_factory=list, max_length=100)
    references: list[dict] = Field(default_factory=list, max_length=1000)
    configurations: list[dict] = Field(default_factory=list, max_length=1000)
    metrics: dict = Field(default_factory=dict)

    @field_validator("published", "lastModified")
    @classmethod
    def iso_timestamp(cls, value):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None and parsed.utcoffset().total_seconds() != 0:
            raise ValueError("NVD date must be UTC")
        return value


class Entry(BaseModel):
    cve: CVE


class CVEPage(BaseModel):
    resultsPerPage: int = Field(strict=True, ge=0, le=100)
    startIndex: int = Field(strict=True, ge=0)
    totalResults: int = Field(strict=True, ge=0)
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: list[Entry] = Field(max_length=100)


class CVEClient(NVDClient):
    throttle_code = "NVD_THROTTLED"

    def page(self, cpe, start=0, limit=100):
        parse_cpe(cpe)
        if (
            type(start) is not int
            or not 0 <= start <= 10000
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise ValueError("Invalid bounded CVE pagination")
        try:
            raw = self._content(
                CVE_URL, {"cpeName": cpe, "startIndex": start, "resultsPerPage": limit}
            )

            # Reject duplicate keys/NaN rather than silently accepting ambiguous evidence.
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("Duplicate JSON key")
                    result[key] = value
                return result

            obj = json.loads(
                raw,
                object_pairs_hook=pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            page = CVEPage.model_validate(obj)
            count = len(page.vulnerabilities)
            if (
                page.format != "NVD_CVE"
                or page.version != "2.0"
                or page.startIndex != start
                or page.resultsPerPage != count
                or count > limit
                or count != min(limit, max(0, page.totalResults - start))
            ):
                raise ValueError("Inconsistent NVD page")
            page.timestamp = page.timestamp.replace(tzinfo=page.timestamp.tzinfo or UTC)
            return page
        except (ValidationError, ValueError, TypeError, RecursionError):
            raise APIError(502, "NVD_INVALID_RESPONSE", "Respuesta CVE NVD no válida") from None
