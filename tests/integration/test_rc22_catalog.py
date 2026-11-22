"""Local dictionary search, bounded sync and atomic assisted device creation."""

import json
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.integrations.nvd import NVDClient, Quota
from app.services import cpe_catalog
from tests.integration.test_rc2_devices import api, owner  # noqa: F401

pytestmark = pytest.mark.postgres
CAPTURE = Path(__file__).resolve().parents[1] / "fixtures/nvd_cpe_verified.json"
SCOPE = cpe_catalog.CatalogScope(vendor="cisco", product="small_business_rv340_firmware")
CATALOG = "/api/v2/cpe-catalog"


def dictionary(monkeypatch, postgres):
    source = json.loads(CAPTURE.read_text())
    entry = source["products"][0]
    # Simulated subsequent dates on a previously recorded official CPE.
    next_entry = json.loads(json.dumps(entry))
    next_entry["cpe"]["deprecated"] = True
    next_entry["cpe"]["deprecatedBy"] = [
        {"cpeNameId": entry["cpe"]["cpeNameId"], "cpeName": entry["cpe"]["cpeName"]}
    ]
    next_entry["cpe"]["lastModified"] = "2030-01-01T00:00:00.000"
    p = {"rows": [entry], "error": None}
    monkeypatch.setattr(cpe_catalog, "PAGE_SIZE", 1)
    with postgres.begin() as connection:
        connection.execute(
            text("""
            DELETE FROM vulntrack_catalog.products WHERE mode='fixture'
        """)
        )
    offsets = []

    def reply(request):
        offset = int(request.url.params["startIndex"])
        offsets.append(offset)
        assert request.url.host == "services.nvd.nist.gov"
        assert request.url.params["cpeMatchString"] == (
            "cpe:2.3:*:cisco:small_business_rv340_firmware"
        )
        if p["error"]:
            return httpx.Response(p["error"], headers={"Retry-After": "90"})
        selected = p["rows"][offset : offset + 1]
        return httpx.Response(
            200,
            json=source
            | {
                "startIndex": offset,
                "resultsPerPage": len(selected),
                "totalResults": len(p["rows"]),
                "products": selected,
            },
        )

    def sync(**kwargs):
        ticks = count(0, 120)
        client = NVDClient(
            transport=httpx.MockTransport(reply), quota=Quota(clock=lambda: next(ticks))
        )
        return cpe_catalog.synchronize(postgres, client, "fixture", wait=lambda _: None, **kwargs)

    return p, entry, next_entry, offsets, sync


def test_resume_upsert_deprecation_and_discard(monkeypatch, postgres):
    setting, entry, successor, offsets, sync = dictionary(monkeypatch, postgres)
    wrong_scope = json.loads(json.dumps(entry))
    wrong_scope["cpe"]["cpeName"] = wrong_scope["cpe"]["cpeName"].replace(":cisco:", ":apache:")
    setting["rows"] = [entry, wrong_scope]
    first = sync(scope=SCOPE)
    assert (first["status"], first["stored"], first["next_offset"]) == ("partial", 1, 1)
    setting["error"] = 429
    failed = sync(resume=first["id"])
    assert failed["status"] == "failed" and failed["next_offset"] == 1
    assert failed["error_code"] == "NVD_UNAVAILABLE"
    setting["error"] = None
    completed = sync(resume=first["id"])
    assert (completed["status"], completed["stored"], completed["received"]) == ("complete", 1, 2)
    assert offsets == [0, 1, 1]
    with postgres.connect() as connection:
        assert connection.scalar(
            text("""
            SELECT discarded FROM vulntrack_catalog.sync_pages WHERE run_id=:id AND page_offset=1
        """),
            {"id": first["id"]},
        ) == {"outside_scope": 1}
    setting["rows"] = [successor]
    assert sync(scope=SCOPE)["stored"] == 1
    setting["rows"] = [entry]
    assert sync(scope=SCOPE)["stored"] == 0
    with postgres.connect() as connection:
        record = (
            connection.execute(
                text("""
            SELECT deprecated,deprecated_by FROM vulntrack_catalog.products WHERE mode='fixture'
        """)
            )
            .mappings()
            .one()
        )
        assert (
            record["deprecated"]
            and record["deprecated_by"][0]["cpeName"] == entry["cpe"]["cpeName"]
        )


def test_catalog_api_atomic_receipt_and_mode(monkeypatch, postgres, api):  # noqa: F811
    setting, entry, changed, _, sync = dictionary(monkeypatch, postgres)
    assert sync(scope=SCOPE)["stored"] == 1
    app, client = api
    endpoint, user = owner(app, client)
    headers = user["headers"]
    _, other = owner(app, client)
    path = CATALOG + "/candidates"
    assert client.get(path, params={"mode": "fixture"}).status_code == 401
    req = {"mode": "fixture", "q": "RV340"}
    initial = client.get(path, params=req, headers=headers).json()
    assert initial["page"]["total"] == 1
    output = initial["items"][0]
    assert output["cpe_name"] == entry["cpe"]["cpeName"]
    assert client.get(path, params={"mode": "live"}, headers=headers).json()["items"] == []
    assert (
        client.get(path, params=req | {"offset": 1}, headers=headers).json()["page"]["total"] == 1
    )
    assert client.get(path, params=req | {"limit": 31}, headers=headers).status_code == 422
    assert (
        client.get(
            CATALOG + "/vendors", params={"mode": "fixture", "q": "%"}, headers=headers
        ).json()["items"]
        == []
    )
    assert (
        client.get(
            CATALOG + "/versions",
            params={"mode": "fixture", "vendor": SCOPE.vendor, "product": SCOPE.product},
            headers=headers,
        ).json()["items"][0]["version"]
        == "1.0.0.33"
    )
    select = {
        "cpe_name_id": output["cpe_name_id"],
        "expected_cpe_name": output["cpe_name"],
        "expected_nvd_modified": output["nvd_modified"],
        "mode": "fixture",
        "confirmed": True,
        "reason": "Observada en laboratorio",
    }
    payload = {
        "device_type": "router",
        "manufacturer": "Cisco",
        "model": "RV340",
        "component_kind": "firmware",
        "site_label": "Lab",
        "version": "1.0.0.33",
        "catalog_selection": select,
    }
    assert client.post(endpoint, json=payload, headers=headers).status_code == 422
    keyed = headers | {"Idempotency-Key": str(uuid4())}
    assert (
        client.post(endpoint, json=payload | {"version": "2.4.58"}, headers=keyed).status_code
        == 409
    )
    assert client.get(endpoint, headers=headers).json()["items"] == []
    created = client.post(endpoint, json=payload, headers=keyed)
    assert created.status_code == 201, created.json()
    response = created.json()
    assert response["product"] == SCOPE.product and response["product_vendor"] == SCOPE.vendor
    assert (
        response["current_identification"]["catalog_evidence"]["source"] == "nvd-captured-fixture"
    )
    assert client.post(endpoint, json=payload, headers=keyed).json() == response
    assert (
        client.post(endpoint, json=payload | {"model": "distinto"}, headers=keyed).status_code
        == 409
    )
    dest = endpoint + "/" + response["id"]
    assert client.get(dest, headers=other["headers"]).status_code == 404
    pending = client.post(
        endpoint,
        headers=headers,
        json={
            "device_type": "switch",
            "manufacturer": "Manual",
            "model": "Inventario",
            "component_kind": "hardware",
            "site_label": "Lab",
        },
    )
    assert pending.status_code == 201 and pending.json()["version"] is None
    assert pending.json()["product_vendor"] is None
    assert (
        client.post(endpoint + "/" + pending.json()["id"] + "/analyses", headers=keyed).status_code
        == 409
    )
    setting["rows"] = [changed]
    sync(scope=SCOPE)
    assert (
        client.post(
            endpoint, json=payload, headers=headers | {"Idempotency-Key": str(uuid4())}
        ).status_code
        == 409
    )
    assert (
        client.get(dest, headers=headers).json()["current_identification"]["cpe_name"]
        == output["cpe_name"]
    )
    with postgres.connect() as connection:
        with suppress(DBAPIError):
            with connection.begin():
                connection.execute(text("SET LOCAL ROLE vulntrack_app"))
                connection.execute(text("DELETE FROM vulntrack_catalog.products"))
                pytest.fail("API role unexpectedly writes catalog")


def test_incremental_filters_and_empty_scope():
    now = datetime.now(UTC)
    scope = cpe_catalog.CatalogScope(vendor="cisco", since=now - timedelta(days=1), until=now)
    assert scope.parameters(0)["lastModStartDate"]
    with pytest.raises(ValueError):
        scope.model_copy(update={"since": now - timedelta(days=121)}).parameters(0)
    with pytest.raises(ValueError):
        cpe_catalog.CatalogScope(vendor="https://example.com")
