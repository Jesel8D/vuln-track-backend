"""5C.1 transport policy and real asynchronous cancellation, never external I/O."""

import asyncio
import math
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from unittest.mock import Mock

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.core.errors import APIError
from app.integrations.cve_transport import CVE_URL, HTTPPolicy, RequestBudget, retry_delay
from app.integrations.nvd_cve import CVEClient
from tests.cve_support import CPE, RAW, Clock, client_for, response_page


@pytest.mark.parametrize(
    "url",
    [
        "http://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://services.nvd.nist.gov:444/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0/",
        "https://services.nvd.nist.gov.evil.invalid/rest/json/cves/2.0",
        "https://secret@services.nvd.nist.gov/rest/json/cves/2.0",
        "https://127.0.0.1/rest/json/cves/2.0",
        "https://169.254.169.254/",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=private",
        "https://services.nvd.nist.gov/rest/json/cpes/2.0",
    ],
)
def test_fixed_endpoint_rejects_any_alternative_before_adapter(url):
    seen = []
    client = client_for(handler=lambda r: seen.append(r))
    with pytest.raises(APIError) as error:
        client._content(url, {"cpeName": CPE, "startIndex": 0, "resultsPerPage": 100})
    assert error.value.code == "NVD_INVALID_ORIGIN" and not seen


@pytest.mark.parametrize("live", [None, False, True])
def test_release_gate_blocks_before_client_dns_socket_or_quota(monkeypatch, live):
    forbidden = Mock(side_effect=AssertionError("Real network constructor must not run"))
    monkeypatch.setattr(httpx, "AsyncClient", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    client = CVEClient(live=live, api_key=SecretStr("synthetic-only"))
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code == "CVE_LIVE_DISABLED"
    assert not forbidden.called and client.quota.next_call == 0


def test_non_mock_adapter_cannot_bypass_release_gate():
    class Adapter(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise AssertionError("Must never run")

    with pytest.raises(APIError) as error:
        CVEClient(live=True, transport=Adapter()).page(CPE)
    assert error.value.code == "CVE_LIVE_DISABLED"


def test_tls_redirect_and_proxy_options_are_explicit(monkeypatch):
    original = httpx.AsyncClient
    options = []

    def captured(**kwargs):
        options.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", captured)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    assert client_for().page(CPE).totalResults == 1
    assert len(options) == 1 and options[0]["verify"] is True
    assert options[0]["trust_env"] is False and options[0]["follow_redirects"] is False
    assert options[0]["timeout"].connect <= 5 and options[0]["timeout"].read <= 10


def test_only_public_parameters_leave_and_references_are_never_followed():
    seen = []
    raw = response_page()
    raw["vulnerabilities"][0]["cve"]["references"] = [
        {"url": "http://127.0.0.1/private-credentials"},
        {"url": "https://exploit.invalid/"},
    ]
    cpe = CPE.replace("small_business_rv340_firmware", r"firmware\:router")

    def reply(request):
        seen.append(request)
        return httpx.Response(200, json=raw)

    client = client_for(handler=reply)
    client.api_key = SecretStr("synthetic-only-secret")
    client.page(cpe)
    assert len(seen) == 1
    assert dict(seen[0].url.params) == {"cpeName": cpe, "startIndex": "0", "resultsPerPage": "100"}
    assert seen[0].headers["apiKey"] == "synthetic-only-secret"
    assert "synthetic-only-secret" not in str(seen[0].url)
    with pytest.raises(ValueError):
        client._content(
            CVE_URL,
            {"cpeName": cpe, "startIndex": 0, "resultsPerPage": 100, "workspace": "private"},
        )


@pytest.mark.parametrize("status", [301, 302, 307, 308, 403, 429, 500, 503])
def test_status_never_retried_in_transport_and_error_body_is_not_leaked(status, caplog):
    seen = []

    def reply(r):
        seen.append(r)
        return httpx.Response(
            status,
            headers={"Location": "http://127.0.0.1/secret", "Retry-After": "120"},
            text="private-body-token",
        )

    client = client_for(handler=reply)
    client.live = True
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert (
        len(seen) == 1
        and "private" not in error.value.message
        and "private-body-token" not in caplog.text
    )
    assert error.value.code == (
        "NVD_INVALID_RESPONSE"
        if status < 400
        else "NVD_THROTTLED"
        if status < 500
        else "NVD_UNAVAILABLE"
    )
    if status >= 400:
        assert client.quota.wait_seconds() >= 120


@pytest.mark.parametrize(
    "exception",
    [
        httpx.ReadTimeout("private secret"),
        httpx.ConnectError("private secret"),
        httpx.ConnectError("private certificate", request=httpx.Request("GET", CVE_URL)),
        RuntimeError("private unexpected"),
    ],
)
def test_transport_errors_are_sanitized(exception, caplog):
    def reply(request):
        if isinstance(exception, httpx.ConnectError):
            raise exception from ssl.SSLCertVerificationError("private certificate details")
        raise exception

    with pytest.raises(APIError) as error:
        client_for(handler=reply).page(CPE)
    assert "private" not in error.value.message and "private" not in caplog.text
    assert error.value.__suppress_context__


def test_deadline_cancels_blocked_async_transport_and_closes_stream():
    closed = []

    async def reply(request):
        try:
            await asyncio.sleep(1)
        finally:
            closed.append(True)

    client = client_for(handler=reply)
    client.http_policy = HTTPPolicy(timeout=0.02)
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code == "NVD_TIMEOUT" and closed == [True]


def test_worker_cancellation_interrupts_an_active_async_wait():
    stop = Event()
    entered = Event()
    closed = []

    async def reply(request):
        entered.set()
        try:
            await asyncio.sleep(5)
        finally:
            closed.append(True)

    client = client_for(handler=reply)
    budget = RequestBudget(seconds=5, cancelled=stop)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(client.page, CPE, budget=budget)
        assert entered.wait(1)
        stop.set()
        with pytest.raises(APIError) as error:
            future.result(timeout=1)
    assert error.value.code == "INTERRUPTED" and closed == [True]


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "identity,gzip"])
def test_compressed_bomb_is_rejected_before_read_or_decompression(encoding):
    read = []

    class Bomb(httpx.AsyncByteStream):
        async def __aiter__(self):
            read.append(True)
            yield b"not even decoded"

    client = client_for(
        handler=lambda r: httpx.Response(200, headers={"Content-Encoding": encoding}, stream=Bomb())
    )
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code == "NVD_INVALID_RESPONSE" and not read


def test_streamed_bytes_are_bounded_without_content_length():
    class Large(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(4):
                yield b"x" * 1024

    client = client_for(handler=lambda r: httpx.Response(200, stream=Large()))
    client.http_policy = HTTPPolicy(max_bytes=1024)
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code in {"NVD_INVALID_RESPONSE", "BYTE_BUDGET_REACHED"}


@pytest.mark.parametrize("header", ["9999999999", "-1", "NaN", "1e2"])
def test_invalid_or_excessive_declared_size_is_rejected(header):
    with pytest.raises(APIError):
        client_for(
            handler=lambda r: httpx.Response(200, headers={"Content-Length": header}, content=b"{}")
        ).page(CPE)


def test_shared_request_and_byte_budgets_do_not_reset_for_a_second_page():
    clock = Clock()
    seen = []
    client = client_for(
        handler=lambda r: seen.append(r) or httpx.Response(200, json=RAW), clock=clock
    )
    budget = RequestBudget(requests=1, clock=clock)
    client.page(CPE, budget=budget)
    clock.advance(8)
    with pytest.raises(APIError) as error:
        client.page(CPE, budget=budget)
    assert error.value.code == "REQUEST_BUDGET_REACHED" and len(seen) == 1
    assert budget.bytes == len(httpx.Response(200, json=RAW).content)


def test_shared_quota_concurrency_gate_is_not_keyed_by_workspace():
    clock = Clock()
    seen = []
    entered = Event()
    release = Event()

    async def blocked(r):
        seen.append(r)
        entered.set()
        while not release.is_set():
            await asyncio.sleep(0.01)
        return httpx.Response(200, json=RAW)

    a = client_for(handler=blocked, clock=clock)
    b = client_for()
    b.quota = a.quota
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(a.page, CPE)
        assert entered.wait(1)
        clock.advance(8)
        try:
            with pytest.raises(APIError) as error:
                b.page(CPE)
            assert error.value.code == "NVD_BUSY"
        finally:
            release.set()
        assert first.result().totalResults == 1
    assert len(seen) == 1


def test_retry_after_seconds_dates_malformed_and_excessive():
    now = datetime(2026, 11, 24, tzinfo=UTC)
    assert retry_delay("90", now=now) == 90
    future = (now + timedelta(seconds=120)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert retry_delay(future, now=now) == 120
    assert retry_delay("nonsense", now=now) == 60
    assert retry_delay(None) == 60
    assert math.isinf(retry_delay("999999999999999999999"))


def test_settings_key_or_live_mode_cannot_enable_cve_egress(settings):
    values = settings.model_dump() | {"nvd_mode": "live", "nvd_api_key": "synthetic"}
    assert Settings(_env_file=None, **values).cve_live_enabled is False
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **(values | {"cve_live_enabled": True}))
    for patch in [
        {"cve_max_requests": 16},
        {"cve_http_max_bytes": 2097153},
        {"cve_max_seconds": 301},
    ]:
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **(values | patch))


def test_schema_verified_public_fields_are_retained_in_cache_not_silently_dropped():
    import json
    from pathlib import Path

    from app.services.v2_cve_cache import validate_public_page

    schema = json.loads(
        (Path(__file__).parents[1] / "fixtures/nvd_cve_api_2_2_4.schema.json").read_text()
    )
    raw = response_page()
    fields = {
        "evaluatorComment": "public evaluator text",
        "evaluatorSolution": "public solution",
        "evaluatorImpact": "public impact",
        "cisaExploitAdd": "2026-11-24",
        "cisaActionDue": "2026-12-01",
        "cisaRequiredAction": "public recommended action",
        "cisaVulnerabilityName": "public name",
    }
    assert set(fields) <= set(schema["definitions"]["cve_item"]["properties"])
    raw["vulnerabilities"][0]["cve"].update(fields)
    _, body, _ = validate_public_page(raw)
    assert json.loads(body)["vulnerabilities"][0]["cve"].items() >= fields.items()


@pytest.mark.parametrize(
    "version", ["cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"]
)
def test_cvss_versions_keep_all_sources_without_claiming_risk(version):
    from app.services.nvd_findings import finding_rows

    raw = response_page()
    raw["vulnerabilities"][0]["cve"]["metrics"] = {
        version: [
            {
                "source": "one@example.invalid",
                "cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1},
            },
            {
                "source": "two@example.invalid",
                "cvssData": {"baseSeverity": "LOW", "baseScore": 3.1},
            },
        ]
    }
    page = client_for(raw=raw).page(CPE)
    _, rows, _ = finding_rows(page, CPE, "1.0.0.33")
    assert rows[0]["severity"] == "high"
    import json

    assert len(json.loads(rows[0]["cvss"])[version]) == 2
    assert rows[0]["applicability"] == "undetermined"


def test_probe_plan_requires_official_specific_non_deprecated_public_identity():
    from uuid import uuid4

    from scripts.nvd_controlled_probe import build_plan

    record = {
        "mode": "live",
        "source": "nvd-feed",
        "cpe_name_id": uuid4(),
        "cpe_name": CPE,
        "vendor": "cisco",
        "product": "small_business_rv340_firmware",
        "version": "1.0.0.33",
        "deprecated": False,
    }
    result = build_plan(record)
    assert result["authorization_granted"] is False and result["release_live_enabled"] is False
    assert set(result["params"]) == {"cpeName", "startIndex", "resultsPerPage"}
    for patch in [
        {"mode": "fixture"},
        {"source": "unknown"},
        {"deprecated": True},
        {"version": "2.0"},
        {"vendor": "other"},
        {"cpe_name_id": "invalid"},
    ]:
        with pytest.raises(ValueError):
            build_plan(record | patch)


def test_future_probe_command_is_fail_closed_even_with_explicit_execute(monkeypatch):
    from scripts import nvd_controlled_probe as probe

    monkeypatch.setattr("sys.argv", ["probe", "--execute-live"])

    def forbidden(*a, **kw):
        raise AssertionError("Execution must stop before database or network")

    monkeypatch.setattr(probe, "prepare", forbidden)
    assert probe.main() == 2


def test_cpe_base_helper_cannot_be_used_as_a_second_cve_transport(monkeypatch):
    from app.integrations.nvd import NVDClient

    forbidden = Mock(side_effect=AssertionError("CPE base must reject CVE before client/DNS"))
    monkeypatch.setattr(httpx, "Client", forbidden)
    base = NVDClient(live=True)
    for method in (base._content, base._content_once):
        with pytest.raises(APIError) as error:
            method(CVE_URL, {})
        assert error.value.code == "NVD_INVALID_ORIGIN"
    assert not forbidden.called and base.quota.next_call == 0
