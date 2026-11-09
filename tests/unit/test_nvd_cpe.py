from copy import deepcopy
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from app.core.errors import APIError
from app.integrations.nvd import NVDClient, Quota
from app.schemas.assets import AssetCreate
from app.schemas.cpe import SearchInput, parse_cpe
from app.services.assets import request_fingerprint
from tests.cpe_support import NAME_ID, RAW, client_for


def test_verified_candidate_and_uuid_resolution():
    result = client_for().search(uuid4(), SearchInput(query="Cisco RV340"))
    assert result.items[0].cpe_name_id == NAME_ID
    assert result.items[0].cpe_name == RAW["products"][0]["cpe"]["cpeName"]
    assert result.page.total == 1 and result.source_timestamp.tzinfo
    candidate, when = client_for().resolve(uuid4(), NAME_ID)
    assert candidate == result.items[0] and when.tzinfo


def test_multiple_candidates_and_second_page():
    raw = deepcopy(RAW)
    raw.update(resultsPerPage=2, totalResults=4, startIndex=2)
    extra = deepcopy(raw["products"][0])
    extra["cpe"]["cpeNameId"] = str(uuid4())
    raw["products"].append(extra)
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, json=raw)

    result = client_for(handler=handler).search(
        uuid4(), SearchInput(query="Cisco", limit=2, offset=2)
    )
    assert len(result.items) == 2 and result.page.total == 4 and result.page.offset == 2
    assert seen == [{"keywordSearch": "Cisco", "resultsPerPage": "2", "startIndex": "2"}]


def test_empty_is_not_external_failure():
    raw = deepcopy(RAW)
    raw.update(products=[], totalResults=0, resultsPerPage=0)
    assert client_for(raw).search(uuid4(), SearchInput(query="no match")).items == []
    with pytest.raises(APIError) as exc:
        client_for(raw).resolve(uuid4(), NAME_ID)
    assert (exc.value.status, exc.value.code) == (409, "CPE_UNAVAILABLE")


@pytest.mark.parametrize(
    "status,expected", [(403, 503), (429, 503), (500, 503), (503, 503), (302, 502), (400, 502)]
)
def test_safe_external_errors(status, expected):
    nvd = client_for(handler=lambda req: httpx.Response(status, text="private external message"))
    with pytest.raises(APIError) as exc:
        nvd.search(uuid4(), SearchInput(query="Cisco"))
    assert exc.value.status == expected
    assert "private" not in exc.value.message


@pytest.mark.parametrize("exception,status", [(httpx.ReadTimeout, 504), (httpx.ConnectError, 503)])
def test_network_errors(exception, status):
    def handler(request):
        raise exception("sensitive response", request=request)

    with pytest.raises(APIError) as exc:
        client_for(handler=handler).search(uuid4(), SearchInput(query="Cisco"))
    assert exc.value.status == status


@pytest.mark.parametrize(
    "change",
    [
        {"products": [{}]},
        {"timestamp": "bad"},
        {"resultsPerPage": True},
        {"products": []},
        {"format": "HTML"},
        {"version": "3"},
        {"startIndex": 2},
        {"totalResults": -1},
        {"resultsPerPage": 21},
    ],
)
def test_invalid_response(change):
    with pytest.raises(APIError) as exc:
        client_for(deepcopy(RAW) | change).search(uuid4(), SearchInput(query="Cisco"))
    assert exc.value.status == 502


@pytest.mark.parametrize(
    "field,value",
    [("cpeName", "cpe:2.3:o:malformed"), ("cpeNameId", "bad"), ("deprecated", "false")],
)
def test_invalid_product(field, value):
    raw = deepcopy(RAW)
    raw["products"][0]["cpe"][field] = value
    with pytest.raises(APIError) as exc:
        client_for(raw).resolve(uuid4(), NAME_ID)
    assert exc.value.status == 502


def test_deprecated_or_wrong_uuid_never_confirmed():
    for field, value, status in [("deprecated", True, 409), ("cpeNameId", str(uuid4()), 502)]:
        raw = deepcopy(RAW)
        raw["products"][0]["cpe"][field] = value
        with pytest.raises(APIError) as exc:
            client_for(raw).resolve(uuid4(), NAME_ID)
        assert exc.value.status == status


@pytest.mark.parametrize("content", [b"{", b"x" * (2 * 1024 * 1024 + 1)])
def test_invalid_json_and_size_bound(content):
    with pytest.raises(APIError) as exc:
        client_for(handler=lambda r: httpx.Response(200, content=content)).search(
            uuid4(), SearchInput(query="Cisco")
        )
    assert exc.value.status == 502


def test_fixed_https_encoding_and_no_redirect_following():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=RAW)

    query = "https://evil.invalid/?apiKey=evil&startIndex=500"
    client_for(handler=handler).search(uuid4(), SearchInput(query=query, product_query="firmware"))
    url = seen[0].url
    assert str(url).startswith("https://services.nvd.nist.gov/rest/json/cpes/2.0?")
    assert dict(url.params) == {
        "keywordSearch": query + " firmware",
        "resultsPerPage": "10",
        "startIndex": "0",
    }
    assert "apiKey" not in seen[0].headers


def test_api_key_only_in_header():
    from pydantic import SecretStr

    def handler(request):
        assert request.headers["apiKey"] == "synthetic-test-key"
        assert "synthetic-test-key" not in str(request.url)
        return httpx.Response(200, json=RAW)

    client = NVDClient(
        api_key=SecretStr("synthetic-test-key"), transport=httpx.MockTransport(handler)
    )
    client.search(uuid4(), SearchInput(query="Cisco"))


def test_global_user_quota_and_cooldown():
    now = [100.0]
    quota = Quota(clock=lambda: now[0])
    quota.reserve()
    with pytest.raises(APIError) as exc:
        quota.reserve()
    assert exc.value.status == 429
    now[0] += 7
    quota.reserve()
    actor = uuid4()
    for _ in range(6):
        quota.check_user(actor, "search")
    with pytest.raises(APIError):
        quota.check_user(actor, "search")
    quota.check_user(uuid4(), "search")
    quota.backoff()
    now[0] += 7
    with pytest.raises(APIError) as exc:
        quota.reserve()
    assert exc.value.status == 503
    now[0] += 60
    quota.reserve()
    quota.check_user(actor, "search")


@pytest.mark.parametrize(
    "data",
    [
        {"query": "x"},
        {"query": "x" * 201},
        {"query": "ab\x00cd"},
        {"query": "ab", "limit": 21},
        {"query": "ab", "offset": 10001},
        {"query": "ab", "url": "https://evil.invalid"},
        {"query": "ab", "product_query": " "},
    ],
)
def test_search_validation(data):
    with pytest.raises(ValidationError):
        SearchInput(**data)


@pytest.mark.parametrize(
    "name",
    [
        "cpe:2.3:o:a:b:1:*:*:*:*:*:*",
        "cpe:2.3:x:a:b:1:*:*:*:*:*:*:*",
        "cpe:2.3:o:a:b:1:*:*:english:*:*:*:*",
        "cpe:2.3:o:a:b:1:*:*:*:*:*:*:a b",
        "cpe:2.3:o:a:b:1:*:*:*:*:*:*:a\\",
    ],
)
def test_malformed_binding(name):
    with pytest.raises(ValueError):
        parse_cpe(name)


def test_escaped_delimiter_and_literal_wildcard():
    assert parse_cpe(r"cpe:2.3:a:vendor:product\:name:1.0\?:*:*:*:*:*:*:*")[2] == r"product\:name"


def test_unknown_version_and_original_registration_hash():
    body = {"device_type": "router", "manufacturer": "Cisco", "model": "RV340", "site_label": "LAB"}
    assert AssetCreate(**body).version is None
    assert request_fingerprint(AssetCreate(**body)) == request_fingerprint(
        AssetCreate(**body, version=None)
    )
    # Frozen pre-MVP fingerprint, computed independently from the original body shape.
    import hashlib
    import json

    old = body | {"version": "1", "inventory_label": None, "notes": None}
    expected = hashlib.sha256(
        json.dumps(
            {"version": 1, "method": "POST", "route": "/assets", "body": old},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    assert request_fingerprint(AssetCreate(**old)) == expected
    for invalid in ["unknown", "*", "-", "", 123]:
        with pytest.raises(ValidationError):
            AssetCreate(**body, version=invalid)


def test_legacy_unknown_strings_remain_readable():
    from datetime import UTC, datetime

    from app.schemas.assets import AssetRead

    legacy = AssetRead(
        id=uuid4(),
        created_at=datetime.now(UTC),
        device_type="router",
        manufacturer="Legacy",
        model="Legacy",
        version="unknown",
        site_label="LAB",
    )
    assert legacy.version == "unknown"
