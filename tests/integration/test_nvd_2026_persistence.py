"""New schema cases through real V2 cache/history/RLS, never NVD I/O."""

import copy
import json

import pytest
from sqlalchemy import text

from tests.cve_support import client_for
from tests.integration.test_cve_reliability import post, setup_case
from tests.integration.test_v2_stabilization import api  # noqa: F401
from tests.unit.test_nvd_2026_contract import sample

pytestmark = pytest.mark.postgres


def test_new_fields_missing_status_persist_reuse_and_remain_historical(api, postgres):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    raw = sample()
    upstream = client_for(raw=raw)
    upstream.source_kind = "simulated"
    upstream.cache_namespace = "compatibility:5c1r"
    upstream.page_limit = 20
    calls = []
    original = upstream.page

    def counted(*args):
        calls.append(args)
        return original(*args)

    upstream.page = counted
    app.state.cve = upstream
    first = post(client, user, path)
    assert first.status_code == 201, first.json()
    first = first.json()
    findings_path = base + "/analyses/" + first["id"] + "/findings"
    before = copy.deepcopy(client.get(findings_path, headers=user["headers"]).json())
    assert first["provenance"]["cve_source"] == "simulated"
    assert first["assessment"]["freshness"] == "fresh"
    hit = post(client, user, path).json()
    assert hit["storage"]["resolution"] == "reused" and len(calls) == 1
    assert calls[0][1:] == (0, 20)
    assert hit["storage"]["obtained_at"] == first["storage"]["obtained_at"]
    assert hit["storage"]["expires_at"] == first["storage"]["expires_at"]
    with postgres.connect() as db:
        body = db.scalar(
            text(
                "SELECT body FROM vulntrack_cve_cache.responses r JOIN "
                "vulntrack_cve_cache.slots s ON s.id=r.slot_id WHERE s.workspace_id=:w"
            ),
            {"w": user["workspace"]},
        )
        stored = json.loads(body)["vulnerabilities"][0]["cve"]
        assert "vulnStatus" not in stored
        assert stored["publicFutureField"] == raw["vulnerabilities"][0]["cve"]["publicFutureField"]
    # Administrative mutation belongs only to the disposable regression DB; the
    # isolated executor correctly does not receive privileges to edit technologies.
    with postgres.begin() as db:
        db.execute(
            text("UPDATE vulntrack.technologies SET version='2.4.50' WHERE id=:id"),
            {"id": path.rsplit("/", 1)[1]},
        )
    historical = client.get(base + "/analyses/" + first["id"], headers=user["headers"]).json()
    assert historical["provenance"] == first["provenance"]
    assert historical["assessment"]["correspondence"] == "historical"
    assert client.get(findings_path, headers=user["headers"]).json()["items"] == before["items"]
