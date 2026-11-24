"""5A source classification and local contracts; no sockets allowed by conftest."""

from copy import deepcopy

import httpx
import pytest

from app.core.errors import APIError
from app.integrations.nvd import Quota
from app.integrations.nvd_cve import CVEClient
from app.services.nvd_findings import finding_rows
from app.services.v2_cve_reliability import source_kind
from tests.cve_support import CPE, RAW, client_for


@pytest.mark.parametrize(
    "status",
    [
        "Received",
        "Awaiting Analysis",
        "Undergoing Analysis",
        "Analyzed",
        "Modified",
        "Deferred",
        "Rejected",
        "FutureUnknownState",
    ],
)
def test_enrichment_status_is_preserved_not_replaced_with_security(status):
    raw = deepcopy(RAW)
    record = raw["vulnerabilities"][0]["cve"]
    record["vulnStatus"] = status
    record.pop("metrics", None)
    record["references"] = []  # Required by the official schema, may be empty.
    page = client_for(raw=raw).page(CPE)
    _, rows, _ = finding_rows(page, CPE, "1.0.0.33")
    assert rows[0]["severity"] == "unknown" and rows[0]["cvss"] is None
    assert status in rows[0]["evidence"]
    assert rows[0]["applicability"] == "undetermined"


def test_simulated_transport_is_never_promoted_to_live():
    mocked = httpx.MockTransport(lambda r: httpx.Response(503))
    assert source_kind(CVEClient(live=True, transport=mocked)) == "simulated"
    assert source_kind(CVEClient(transport=mocked, source_kind="fixture")) == "fixture"
    assert source_kind(CVEClient(live=False)) == "unknown"
    # Classification only: no live client is called.
    assert source_kind(CVEClient(live=True)) == "live"
    with pytest.raises(ValueError):
        CVEClient(transport=mocked, source_kind="live")
    with pytest.raises(ValueError):
        CVEClient(source_kind="fixture")


def test_conservative_adjustable_quota_and_invalid_upstream_metadata():
    now = [100.0]
    quota = Quota(clock=lambda: now[0], spacing=12)
    quota.reserve()
    assert quota.wait_seconds() == 12
    with pytest.raises(APIError):
        quota.reserve()
    now[0] += 12
    quota.reserve()
    with pytest.raises(ValueError):
        Quota(spacing=0.6)
    for changes in [{"format": "NVD_CVE_OLD"}, {"timestamp": None}, {"resultsPerPage": 2000}]:
        with pytest.raises(APIError):
            client_for(raw=deepcopy(RAW) | changes).page(CPE)
