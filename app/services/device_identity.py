"""Match a deliberately recorded product against a resolved CPE dictionary record."""

import re

from app.core.errors import APIError
from app.schemas.cpe import parse_cpe, unbind_component

PARTS = {"firmware": "o", "os": "o", "software": "a", "hardware": "h"}


def words(value):
    return tuple(re.findall(r"[^\W_]+", value.casefold(), flags=re.UNICODE))


def validate_device_candidate(device, candidate):
    fields = parse_cpe(candidate.cpe_name)
    part, vendor, product, version = (unbind_component(field) for field in fields[:4])
    if not device["version"]:
        raise APIError(409, "VERSION_REQUIRED", "Registra una versión conocida antes de confirmar")
    if version in {"*", "-"} or version.casefold() != device["version"].casefold():
        raise APIError(
            409, "CPE_VERSION_MISMATCH", "La versión NVD no coincide con la versión registrada"
        )
    if (
        part != PARTS[device["component_kind"]]
        or not words(vendor)
        or not words(product)
        or words(vendor) != words(device["product_vendor"] or "")
        or words(product) != words(device["product"] or "")
    ):
        raise APIError(
            409, "CPE_PRODUCT_MISMATCH", "El componente, fabricante o producto NVD no coincide"
        )
