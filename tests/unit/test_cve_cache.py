"""Deterministic public query identity; all CVE data is an offline fixture."""

from copy import deepcopy

import pytest

from app.core.errors import APIError
from app.services.v2_cve_cache import query_key, validate_public_page
from tests.cve_support import CPE, RAW, response_page


def test_query_keys_preserve_binding_and_separate_every_result_dimension():
    key, query = query_key("fixture", "capture:abc", CPE)
    assert (key, query) == query_key("fixture", "capture:abc", CPE, filters={})
    variants = [query_key(mode, "capture:abc", CPE)[0] for mode in ["simulated", "live", "unknown"]]
    variants += [
        query_key("fixture", "capture:def", CPE)[0],
        query_key("fixture", "capture:abc", CPE.replace(":1.0.0.33:", ":2.0:"))[0],
        query_key("fixture", "capture:abc", CPE, start=100)[0],
        query_key("fixture", "capture:abc", CPE, limit=50)[0],
        query_key("fixture", "capture:abc", CPE, contract="next")[0],
    ]
    assert key not in variants and len(set(variants)) == len(variants)
    escaped = CPE.replace("small_business_rv340_firmware", r"router\:firmware")
    assert r"router\\:firmware" in query_key("fixture", "capture:abc", escaped)[1]
    assert query_key("fixture", "capture:abc", CPE.replace("cisco", "CISCO"))[0] != key


@pytest.mark.parametrize(
    "kwargs",
    [
        {"start": -1},
        {"limit": 0},
        {"limit": 101},
        {"start": True},
        {"filters": {"unknown": "ignored"}},
        {"namespace": "private space"},
        {"mode": "real"},
    ],
)
def test_invalid_query_identity_is_rejected(kwargs):
    args = dict(mode="fixture", namespace="capture:abc", cpe=CPE) | kwargs
    with pytest.raises(ValueError):
        query_key(**args)


@pytest.mark.parametrize("mutation", ["duplicate", "private", "nul", "count", "format", "unknown"])
def test_invalid_public_evidence_is_rejected_without_silent_field_removal(mutation):
    raw = deepcopy(RAW)
    cve = raw["vulnerabilities"][0]["cve"]
    if mutation == "duplicate":
        raw = response_page(["CVE-2026-5555", "CVE-2026-5555"])
    elif mutation == "private":
        cve["metrics"]["workspaceId"] = "private"
    elif mutation == "nul":
        cve["descriptions"][0]["value"] = "bad\x00text"
    elif mutation == "count":
        raw["totalResults"] = -1
    elif mutation == "format":
        raw["format"] = "wrong"
    elif mutation == "unknown":
        cve["internalInventory"] = "secret"
    with pytest.raises(APIError) as error:
        validate_public_page(raw)
    assert error.value.code == "CVE_CACHE_INVALID_RESPONSE"


def test_valid_body_is_canonical_and_does_not_discard_unsupported_predicates():
    page, body, digest = validate_public_page(RAW)
    assert validate_public_page(page)[1:] == (body, digest)
    assert "affected" in body  # Kept for the evaluator's conservative undetermined result.
