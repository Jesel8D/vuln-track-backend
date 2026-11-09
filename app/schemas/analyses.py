from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.assets import AssetCreate, Page


class AnalysisInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identification_id: UUID


class Accepted(BaseModel):
    id: UUID
    accepted_at: datetime


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    asset_id: UUID
    identification_id: UUID | None
    initiated_by: UUID
    selected_cpe: str
    observed_version: str | None
    status: Literal["queued", "running", "completed", "failed"]
    coverage: Literal["complete", "partial"] | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    source_timestamp: datetime | None
    total_results: int | None
    retrieved_count: int
    stored_count: int
    page_count: int
    next_index: int
    retry_count: int
    query_parameters: dict
    warning_codes: list[str]
    source_timestamps: list[str]
    page_manifest: list[dict]
    failure_code: str | None
    nvd_cooldown_until: datetime | None


class AnalysisList(BaseModel):
    items: list[AnalysisRead]
    page: Page


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    analysis_id: UUID
    external_id: str
    source: Literal["NVD"]
    title: str | None
    applicability: Literal["potential", "undetermined", "not_applicable"]
    status: Literal["open", "reviewed"]
    cvss: dict | None
    evidence: dict | None
    observed_at: datetime
    created_at: datetime
    updated_at: datetime
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_reason: str | None
    review_evidence: str | None


class FindingList(BaseModel):
    items: list[FindingRead]
    page: Page
    run_status: str
    coverage: str | None


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["reviewed"]
    applicability: Literal["potential", "undetermined", "not_applicable"]
    expected_updated_at: datetime = Field()
    reason: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]
    evidence: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2000)]
    normalize = field_validator("reason", "evidence", mode="before")(AssetCreate.normalize.__func__)

    @field_validator("expected_updated_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timezone required")
        return value
