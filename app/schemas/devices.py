"""RC2 device inputs. The server derives actor, status and workspace."""

import unicodedata
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

Text120 = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=120)]
DeviceType = Literal["router", "switch", "server"]
DeviceStatus = Literal["active", "retired"]
ComponentKind = Literal["firmware", "os", "software", "hardware"]
Mode = Literal["fixture", "live", "unknown"]


class DeviceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def normalize(cls, value):
        if isinstance(value, str):
            value = unicodedata.normalize("NFC", value).strip()
            if any(unicodedata.category(char) in {"Cc", "Cs"} for char in value):
                raise ValueError("No se permiten caracteres de control")
        return value


class DeviceCreate(DeviceInput):
    device_type: DeviceType
    manufacturer: Text120
    model: Text120
    product_vendor: Text120
    product: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=160)]
    component_kind: ComponentKind
    version: Text120 | None = None
    site_label: Text120
    inventory_label: Text120 | None = None
    notes: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=1000)] | None = (
        None
    )

    @field_validator("version")
    @classmethod
    def unknown_is_null(cls, value):
        if value is not None and value.casefold() in {"unknown", "*", "-"}:
            raise ValueError("Usar null si la versión es desconocida")
        return value


class DeviceStatusUpdate(DeviceInput):
    status: DeviceStatus


class DeviceIdentificationCreate(DeviceInput):
    cpe_name_id: UUID
    expected_identification_id: UUID | None = None
    reason: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]


class DeviceFindingReview(DeviceInput):
    applicability: Literal["potential", "undetermined", "not_applicable"]
    expected_updated_at: datetime
    reason: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]
    evidence: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2000)]

    @field_validator("expected_updated_at")
    @classmethod
    def require_timezone(cls, value):
        if value.tzinfo is None:
            raise ValueError("La fecha requiere zona horaria")
        return value


class DeviceRecommendationCreate(DeviceInput):
    recommendation: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=4000)]
