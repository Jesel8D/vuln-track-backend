import unicodedata
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

Text80 = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=80)]
Text120 = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=120)]
Text1000 = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=1000)]


class AssetFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_type: Text80
    manufacturer: Text120
    model: Text120
    version: Text120 | None = None
    site_label: Text120
    inventory_label: Text120 | None = None
    notes: Text1000 | None = None

    @field_validator("*", mode="before")
    @classmethod
    def normalize(cls, value):
        if isinstance(value, str):
            value = unicodedata.normalize("NFC", value).strip()
            if any(unicodedata.category(char) in {"Cc", "Cs"} for char in value):
                raise ValueError("No se permiten caracteres de control")
        return value


class AssetCreate(AssetFields):
    @field_validator("version")
    @classmethod
    def real_version_or_null(cls, value):
        if value is not None and value.casefold() in {"unknown", "*", "-"}:
            raise ValueError("Usar null para versión desconocida")
        return value


class AssetRead(AssetFields):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    created_at: datetime


class Page(BaseModel):
    limit: int
    offset: int
    total: int


class AssetList(BaseModel):
    items: list[AssetRead]
    page: Page
