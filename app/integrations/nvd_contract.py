"""Pinned NVD schemas. Validation never retrieves a schema or follows payload URLs."""

import hashlib
import json
import re
from datetime import datetime
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).with_name("nvd_schemas")
PRIVATE_KEYS = frozenset(
    "workspace workspaceid user username userid location sitelabel notes password apikey "
    "authorization credentials memberships reviewedby reviewreason reviewevidence recommendations "
    "inventorylabel internalinventory deviceid applicationid technologyid".split()
)
UNSAFE_KEYS = {"__proto__", "prototype", "constructor", "__class__"}


def bounded_json(value, path=(), depth=0):
    if depth > 24:
        raise ValueError("Nested NVD payload")
    if isinstance(value, dict):
        # Only SSVC option *labels* have schema-defined arbitrary names. Their values
        # remain bounded, inert JSON. Never exempt the entire metrics subtree.
        option = (
            len(path) == 8
            and path[:2] == ("vulnerabilities", "[]")
            and path[2:6] == ("cve", "metrics", "ssvcV203", "[]")
            and path[6:] == ("ssvcData", "options[]")
        )
        for key, child in value.items():
            if not isinstance(key, str) or key in UNSAFE_KEYS:
                raise ValueError("Unsafe JSON key")
            normalized = re.sub(r"[^a-z]", "", key.casefold())
            if not option and normalized in PRIVATE_KEYS:
                raise ValueError("Private field in provider body")
            next_path = path + (key,)
            if key == "options" and path[-1:] == ("ssvcData",) and isinstance(child, list):
                for entry in child:
                    bounded_json(entry, path + ("options[]",), depth + 2)
            else:
                bounded_json(child, next_path, depth + 1)
    elif isinstance(value, list):
        for child in value:
            bounded_json(child, path + ("[]",), depth + 1)
    elif isinstance(value, str):
        if "\x00" in value:
            raise ValueError("NUL in NVD payload")
        if path[-1:] in {("url",), ("repo",), ("collectionURL",), ("decisionTreeUrl",)}:
            if urlsplit(value).scheme.casefold() not in {"https", "http"}:
                raise ValueError("Non-HTTP evidence link")
    elif value is not None and type(value) not in {int, float, bool}:
        raise ValueError("Non-JSON value")


def no_remote(uri):
    raise NoSuchResource(ref=uri)


@lru_cache(maxsize=1)
def validator():
    manifest = json.loads((ROOT / "manifest.json").read_text())
    registry = Registry(retrieve=no_remote)
    main = None
    for record in manifest:
        raw = (ROOT / record["file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError("Pinned schema integrity")
        schema = json.loads(raw, parse_float=Decimal)
        registry = registry.with_resource(record["url"], Resource.from_contents(schema))
        if record["file"] == "cve_api_json_2.0.schema":
            main = schema
    formats = FormatChecker()

    @formats.checks("date-time", raises=(ValueError, TypeError))
    def nvd_datetime(value):
        # NVD's established format also uses timezone-less UTC, as in our original
        # verified capture. Preserve it verbatim instead of adding an invented zone.
        if not isinstance(value, str):
            return True
        return "T" in value and bool(datetime.fromisoformat(value.replace("Z", "+00:00")))

    return Draft7Validator(main, registry=registry, format_checker=formats)


def validate_page(value):
    bounded_json(value)
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(raw.encode()) > 2097152:
        raise ValueError("NVD payload size")
    try:
        if not validator().is_valid(json.loads(raw, parse_float=Decimal)):
            raise ValueError("NVD schema mismatch")
    except Exception:
        # Unknown external refs (including optional decisionTree) fail closed.
        # Never expose provider data or try network retrieval to resolve them.
        raise ValueError("NVD schema mismatch") from None
