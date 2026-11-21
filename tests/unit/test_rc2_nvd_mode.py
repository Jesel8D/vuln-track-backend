"""Failure handling is verified with a synthetic transport and clock."""

import json
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from app.core.errors import APIError
from app.integrations.nvd import NVD_URL, NVDClient, Quota
from app.schemas.cpe import SearchInput


def test_disabled_mode_never_constructs_a_real_transport(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("HTTP client must not be opened in disabled mode")

    monkeypatch.setattr(httpx, "Client", forbidden)
    with pytest.raises(APIError) as error:
        NVDClient(live=False).search(uuid4(), SearchInput(query="RV340"))
    assert error.value.code == "NVD_MODE_REQUIRED"


@pytest.mark.parametrize("upstream", [429, 403, 500, "dns", "timeout"])
def test_live_mode_has_a_fixed_budget_and_respects_retry_after(monkeypatch, upstream):
    seen = []
    now = [100.0]
    quota = Quota(clock=lambda: now[0])
    monkeypatch.setattr(
        "app.integrations.nvd.time.sleep", lambda delay: now.__setitem__(0, now[0] + delay)
    )

    def reply(request):
        assert request.url.scheme == "https" and request.url.host == "services.nvd.nist.gov"
        assert "apiKey" not in request.headers
        seen.append(now[0])
        if upstream == "timeout":
            raise httpx.ReadTimeout("synthetic")
        if upstream == "dns":
            raise httpx.ConnectError("synthetic")
        return httpx.Response(
            upstream, headers={"Retry-After": "90"} if upstream in {429, 403} else {}
        )

    client = NVDClient(transport=httpx.MockTransport(reply), quota=quota, live=True)
    with pytest.raises(APIError):
        client._content(NVD_URL, {})
    if upstream in {429, 403}:
        assert seen == [100] and quota.wait_seconds() == 90
    else:
        assert seen == [100, 107]


def test_fixed_origin_key_only_header_and_bounded_empty_result():
    def reply(request):
        assert request.url.host == "services.nvd.nist.gov"
        assert request.url.path == "/rest/json/cpes/2.0"
        assert request.headers["apiKey"] == "synthetic-key"
        assert "synthetic-key" not in str(request.url)
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "format": "NVD_CPE",
                    "version": "2.0",
                    "startIndex": 0,
                    "resultsPerPage": 0,
                    "totalResults": 0,
                    "timestamp": "2026-11-21T00:00:00Z",
                    "products": [],
                }
            ),
        )

    client = NVDClient(
        api_key=SecretStr("synthetic-key"), transport=httpx.MockTransport(reply), live=True
    )
    with pytest.raises(APIError) as error:
        client._content("https://example.com/", {})
    assert error.value.code == "NVD_INVALID_ORIGIN"
    assert client.search(uuid4(), SearchInput(query="RV340")).items == []
