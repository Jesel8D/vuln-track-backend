import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.assets import AssetCreate, Page


def parse_cpe(value: str) -> list[str]:
    """CPE 2.3 formatted string binding, preserving escaped delimiters and wildcards.

    A conservative ASCII binding; unsupported syntax fails closed. Dictionary UUID
    resolution is additionally required: syntax alone never proves NVD provenance.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        raise ValueError("Invalid CPE length")
    parts, current, escaped = [], "", False
    for char in value:
        if escaped:
            current += "\\" + char
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append(current)
            current = ""
        else:
            current += char
    if escaped:
        raise ValueError("Incomplete CPE escape")
    parts.append(current)
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"] or parts[2] not in {"h", "o", "a"}:
        raise ValueError("Invalid CPE binding")
    # Unescaped punctuation is limited by the formatted-string binding.
    component = (
        r"(?:\*|\?|-)\Z|(?:\*|\?+)?"
        r"""(?:[A-Za-z0-9._-]|\\[\\!"#$%&'()+,/:;<=>?@\[\]^`{|}~*?-])+"""
        r"(?:\*|\?+)?\Z"
    )
    if any(not re.fullmatch(component, part) for part in parts[3:]):
        raise ValueError("Invalid CPE component")
    if not re.fullmatch(r"\*|-|[a-zA-Z]{2,3}(?:-(?:[a-zA-Z]{2}|[0-9]{3}))?", parts[8]):
        raise ValueError("Invalid CPE language")
    return parts[2:]


def unbind_component(value):
    return re.sub(r"\\(.)", r"\1", value)


class SearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: Annotated[str, StringConstraints(strict=True, min_length=2, max_length=200)]
    product_query: (
        Annotated[str, StringConstraints(strict=True, min_length=1, max_length=160)] | None
    ) = None
    limit: int = Field(default=10, ge=1, le=20)
    offset: int = Field(default=0, ge=0, le=10000)
    normalize = field_validator("query", "product_query", mode="before")(
        AssetCreate.normalize.__func__
    )


class Candidate(BaseModel):
    cpe_name_id: UUID
    cpe_name: str
    title: str | None
    deprecated: bool


class CandidateList(BaseModel):
    items: list[Candidate]
    page: Page
    source_timestamp: datetime


class EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_current_id: UUID | None
    reason: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]
    normalize = field_validator("reason", mode="before")(AssetCreate.normalize.__func__)


class Confirm(EventBase):
    state: Literal["confirmed"]
    cpe_name_id: UUID
    component_kind: Literal["hardware", "firmware", "os", "software"]


class NeedsReview(EventBase):
    state: Literal["needs_review"]


EventInput = Annotated[Confirm | NeedsReview, Field(discriminator="state")]


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    asset_id: UUID
    state: Literal["confirmed", "needs_review"]
    cpe_name_id: UUID
    cpe_name: str
    component_kind: str
    observed_version: str | None
    source: Literal["NVD"]
    validated_at: datetime
    recorded_by: UUID
    recorded_at: datetime
    reason: str
    replaces_id: UUID | None


class HistoryEvent(EventRead):
    valid_to: datetime | None
    is_current: bool


class IdentificationList(BaseModel):
    current_state: Literal["pending", "confirmed", "needs_review"]
    items: list[HistoryEvent]
    page: Page
