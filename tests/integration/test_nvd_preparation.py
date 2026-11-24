"""5C.1 real PostgreSQL/worker/cache integration; every upstream is offline."""

from uuid import uuid4

import httpx
import pytest

from app.integrations.nvd_cve import CVEClient
from tests.cve_support import response_page
from tests.integration.test_cve_cache import counts, provider
from tests.integration.test_cve_reliability import post, setup_case
from tests.integration.test_v2_stabilization import api  # noqa: F401
from tests.integration.test_z_mvp_b import accept, b_api, findings, read  # noqa: F401

pytestmark = pytest.mark.postgres


@pytest.mark.parametrize(
    "kind,reason",
    [
        ("requests", "REQUEST_BUDGET_REACHED"),
        ("records", "RECORD_BUDGET_REACHED"),
        ("bytes", "BYTE_BUDGET_REACHED"),
        ("duration", "TIME_BUDGET_REACHED"),
        ("skipped", "NVD_INVALID_RESPONSE"),
        ("empty_wrong", "NVD_INVALID_RESPONSE"),
    ],
)
def test_worker_execution_budgets_and_missing_page_preserve_earlier_evidence(b_api, kind, reason):  # noqa: F811
    b = b_api
    worker = b["worker"]
    seen = []
    raw = response_page(["CVE-2026-11000"], total=3, start=0, simple=True)
    if kind == "requests":
        worker.max_requests = 1
    if kind == "records":
        worker.max_records = 1
    if kind == "bytes":
        worker.max_bytes = len(httpx.Response(200, json=raw).content) + 100
    if kind == "duration":
        worker.max_seconds = 2
    worker.page_size = 1

    def reply(request):
        index = int(request.url.params["startIndex"])
        seen.append(index)
        if index and kind == "skipped":
            return httpx.Response(
                200, json=response_page(["CVE-2026-11001"], total=3, start=2, simple=True)
            )
        if index and kind == "empty_wrong":
            return httpx.Response(200, json=response_page([], total=3, start=1))
        return httpx.Response(
            200,
            json=response_page([f"CVE-2026-{11000 + index}"], total=3, start=index, simple=True),
        )

    from tests.cve_support import client_for

    worker.client = client_for(handler=reply, clock=b["clock"])
    accepted = accept(b)
    assert accepted.status_code == 202, accepted.json()
    assert worker.process_next()
    run = read(b, accepted)
    assert run["status"] == "completed" and run["coverage"] == "partial"
    assert reason in run["warning_codes"], run
    assert run["page_count"] == 1 and run["stored_count"] == 1
    assert len(findings(b, accepted)["items"]) == 1
    assert len(seen) <= 2


def test_v1_worker_cannot_escape_the_release_live_gate(b_api, monkeypatch):  # noqa: F811
    b = b_api
    worker = b["worker"]
    worker.client = CVEClient(live=True)

    def forbidden(*a, **kw):
        raise AssertionError("No real CVE client may be constructed")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden)
    accepted = accept(b)
    assert accepted.status_code == 202
    assert worker.process_next()
    run = read(b, accepted)
    assert run["status"] == "failed" and run["failure_code"] == "CVE_LIVE_DISABLED"
    assert run["coverage"] is None and findings(b, accepted)["items"] == []


def test_other_workspace_does_not_reset_provider_quota_and_hit_uses_no_slot(api, postgres):  # noqa: F811
    app, client = api
    a, path_a, _ = setup_case(app, client, postgres, "devices")
    b, path_b, _ = setup_case(app, client, postgres, "devices")
    upstream, calls = provider()
    wire = []
    original = upstream.transport.handler

    def tracked(request):
        wire.append(request)
        return original(request)

    upstream.transport.handler = tracked
    app.state.cve = upstream
    first = post(client, a, path_a)
    assert first.status_code == 201, first.json()
    second_key = str(uuid4())
    blocked = post(client, b, path_b, second_key)
    assert blocked.status_code == 429 and blocked.json()["error"]["code"] == "NVD_RATE_LIMIT"
    failed = post(client, b, path_b, second_key).json()
    assert failed["status"] == "failed" and failed["coverage"] is None
    assert len(calls) == 2  # page invocation counter includes the quota-rejected attempt.
    assert len(wire) == 1
    assert counts(postgres, b["workspace"])["responses"] == 0
    # A's valid hit succeeds even while the shared provider budget refuses new I/O.
    hit = post(client, a, path_a)
    assert hit.status_code == 201
    assert hit.json()["storage"]["resolution"] == "reused" and len(calls) == 2
    upstream.quota.clock.advance(8)
    assert post(client, b, path_b).status_code == 201
    assert counts(postgres, b["workspace"])["responses"] == 1
    assert len(wire) == 2
