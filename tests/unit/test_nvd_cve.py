import json
from copy import deepcopy

import httpx
import pytest
from pydantic import SecretStr

from app.core.errors import APIError
from app.integrations.nvd import NVDClient
from app.integrations.nvd_cve import CVE_URL
from tests.cve_support import CPE, RAW, Clock, client_for, response_page


def test_real_verified_cve_retains_complex_evidence_and_metrics():
    page = client_for().page(CPE)
    assert page.totalResults == 1 and page.resultsPerPage == 1
    cve = page.vulnerabilities[0].cve
    assert cve.id == "CVE-2017-6784" and cve.vulnStatus == "Modified"
    assert set(cve.metrics) == {"cvssMetricV30", "cvssMetricV2"}
    assert cve.configurations[0]["operator"] == "AND"
    assert page.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    "changes",
    [
        {"metrics": {}},
        {"configurations": []},
        {"references": []},
        {"vulnStatus": "Rejected"},
        {"vulnStatus": "Modified"},
    ],
)
def test_optional_cve_data_is_not_fabricated(changes):
    raw = deepcopy(RAW)
    raw["vulnerabilities"][0]["cve"].update(changes)
    cve = client_for(raw=raw).page(CPE).vulnerabilities[0].cve
    for field, value in changes.items():
        assert getattr(cve, field) == value


def test_empty_is_a_valid_page_not_an_error():
    page = client_for(raw=response_page([])).page(CPE)
    assert page.totalResults == 0 and page.vulnerabilities == []


def test_fixed_origin_encoded_cpe_no_secret_in_url_and_shared_quota():
    seen = []
    clock = Clock()
    client = client_for(
        handler=lambda r: seen.append(r) or httpx.Response(200, json=RAW), clock=clock
    )
    client.api_key = SecretStr("synthetic-only-private-key")
    client.page(CPE)
    req = seen[0]
    assert str(req.url).startswith(CVE_URL + "?")
    assert dict(req.url.params) == {"cpeName": CPE, "startIndex": "0", "resultsPerPage": "100"}
    assert req.headers["apiKey"] == "synthetic-only-private-key"
    assert "synthetic" not in str(req.url)
    cpe_client = NVDClient(quota=client.quota)
    with pytest.raises(APIError) as error:
        cpe_client.quota.reserve()
    assert error.value.code == "NVD_RATE_LIMIT"
    clock.advance(7)
    cpe_client.quota.reserve()


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "NVD_INVALID_RESPONSE"),
        (302, "NVD_INVALID_RESPONSE"),
        (403, "NVD_THROTTLED"),
        (429, "NVD_THROTTLED"),
        (500, "NVD_UNAVAILABLE"),
        (503, "NVD_UNAVAILABLE"),
    ],
)
def test_http_failures_do_not_become_zero(status, code):
    clock = Clock()
    client = client_for(
        handler=lambda r: httpx.Response(status, headers={"Retry-After": "120"}), clock=clock
    )
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code == code
    if status in {403, 429, 500, 503}:
        assert client.quota.wait_seconds() >= 120


@pytest.mark.parametrize(
    "failure,code", [(httpx.ReadTimeout, "NVD_TIMEOUT"), (httpx.ConnectError, "NVD_UNAVAILABLE")]
)
def test_network_failure(failure, code):
    def handler(r):
        raise failure("synthetic secret must not surface")

    with pytest.raises(APIError) as error:
        client_for(handler=handler).page(CPE)
    assert error.value.code == code and "secret" not in error.value.message


@pytest.mark.parametrize(
    "changes",
    [
        {"startIndex": 1},
        {"resultsPerPage": 2},
        {"totalResults": 5},
        {"format": "OTHER"},
        {"version": "1.0"},
        {"totalResults": True},
        {"vulnerabilities": [{}]},
        {"timestamp": "invalid"},
    ],
)
def test_inconsistent_page_rejected(changes):
    with pytest.raises(APIError) as error:
        client_for(raw=deepcopy(RAW) | changes).page(CPE)
    assert error.value.code == "NVD_INVALID_RESPONSE"


@pytest.mark.parametrize(
    "content",
    [b"{bad", b'{"totalResults":0,"totalResults":1}', b"NaN", b"x" * (2 * 1024 * 1024 + 1)],
)
def test_invalid_json_and_size(content):
    with pytest.raises(APIError) as error:
        client_for(handler=lambda r: httpx.Response(200, content=content)).page(CPE)
    assert error.value.code == "NVD_INVALID_RESPONSE"


def test_bounded_pagination_and_second_page_parameters():
    seen = []
    raw = response_page(["CVE-2026-11111"], total=2, start=1)
    page = client_for(handler=lambda r: seen.append(r) or httpx.Response(200, json=raw)).page(
        CPE, 1, 1
    )
    assert page.startIndex == 1 and seen[0].url.params["startIndex"] == "1"
    for args in [(CPE, -1, 100), (CPE, 0, 101), ("https://example.org", 0, 1), (CPE, 0, True)]:
        with pytest.raises(ValueError):
            client_for().page(*args)


def test_missing_required_cve_identity_dates_and_types():
    for field, value in [
        ("id", "CVE-bad"),
        ("published", "yesterday"),
        ("references", {}),
        ("vulnStatus", None),
        ("lastModified", "2026-01-01T00:00:00+01:00"),
    ]:
        raw = deepcopy(RAW)
        raw["vulnerabilities"][0]["cve"][field] = value
        with pytest.raises(APIError):
            client_for(raw=raw).page(CPE)


def test_duplicate_keys_nested_are_rejected():
    raw = json.dumps(RAW).replace(
        '"vulnStatus": "Modified"', '"vulnStatus": "Modified", "vulnStatus": "Rejected"'
    )
    with pytest.raises(APIError):
        client_for(handler=lambda r: httpx.Response(200, content=raw)).page(CPE)
