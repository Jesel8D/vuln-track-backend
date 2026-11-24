"""External CPE test uses a distinct disposable PostgreSQL, never a historical profile."""

import json
import secrets
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from app.services.catalog_reader import CatalogReader
from app.services.cpe_catalog import UPSERT, normalize, refresh_summary
from scripts.disposable_v2 import DisposableV2
from tests.integration.test_rc2_devices import ROUTER, api, owner  # noqa: F401

pytestmark = pytest.mark.postgres
CAT = "/api/v2/cpe-catalog"


def test_external_catalog_readonly_and_local_registration(api, postgres):  # noqa: F811
    app, client = api
    endpoint, user = owner(app, client)
    headers = user["headers"]
    password = secrets.token_urlsafe(24)
    with DisposableV2("new", sql_checks=False) as external:
        assert external.port != make_url(app.state.settings.database_url.get_secret_value()).port
        admin = create_engine(external.url("postgres"), hide_parameters=True)
        external.sql(
            "CREATE ROLE lab_catalog_reader LOGIN NOINHERIT PASSWORD '" + password + "';"
            "GRANT CONNECT ON DATABASE vulntrack_backend_test TO lab_catalog_reader;"
            "GRANT USAGE ON SCHEMA vulntrack_catalog TO lab_catalog_reader;"
            "GRANT SELECT ON vulntrack_catalog.products,vulntrack_catalog.summary,"
            "vulntrack_catalog.sync_runs,vulntrack_catalog.feed_imports TO lab_catalog_reader;"
        )
        source = Path(__file__).resolve().parents[1] / "fixtures/rc3_rv340_alternate_cpe.json"
        entry = json.loads(source.read_text())
        item = normalize(entry, "live", None, source="nvd-feed")
        with admin.begin() as db, postgres.begin() as local:
            db.execute(UPSERT, item)
            refresh_summary(db, "live")
            local.execute(UPSERT, normalize(entry, "fixture", None))
            refresh_summary(local, "fixture")
            fixture_count = local.scalar(
                text("SELECT count(*) FROM vulntrack_catalog.products WHERE mode='fixture'")
            )
        url = make_url(external.url("postgres")).set(
            username="lab_catalog_reader", password=password
        )
        reader = CatalogReader(
            app.state.engine, SecretStr(url.render_as_string(hide_password=False))
        )
        app.state.catalog_reader = reader
        try:
            for mode, backend, count in [
                ("live", "external_readonly", 1),
                ("fixture", "local", fixture_count),
            ]:
                status = client.get(CAT + "/status", headers=headers, params={"mode": mode})
                assert status.status_code == 200
                assert status.json()["records"] == count
                assert status.json()["catalog_backend"] == backend
            lookup = client.get(CAT + "/vendors", headers=headers, params={"q": "cis", "part": "o"})
            assert lookup.json()["items"] == [{"vendor": "cisco"}]
            assert (
                client.get(CAT + "/products", headers=headers, params={"vendor": "other"}).json()[
                    "items"
                ]
                == []
            )
            page = client.get(CAT + "/candidates", headers=headers, params={"limit": 1})
            assert page.json()["items"][0]["source"] == "nvd-feed"
            assert (
                client.get(
                    CAT + "/candidates", headers=headers, params={"offset": 1, "limit": 1}
                ).json()["items"]
                == []
            )
            candidate = page.json()["items"][0]
            selection = {
                "mode": "live",
                "cpe_name_id": candidate["cpe_name_id"],
                "expected_cpe_name": candidate["cpe_name"],
                "expected_nvd_modified": candidate["nvd_modified"],
                "confirmed": True,
                "reason": "Selección humana de prueba",
            }
            body = ROUTER | {"version": candidate["version"], "catalog_selection": selection}
            create_headers = headers | {"Idempotency-Key": str(uuid4())}
            response = client.post(endpoint, headers=create_headers, json=body)
            assert response.status_code == 201, response.json()
            path = endpoint + "/" + response.json()["id"]
            assert (
                response.json()["current_identification"]["catalog_evidence"]["source"]
                == "nvd-feed"
            )
            analysis = client.post(path + "/analyses", headers=create_headers)
            assert analysis.status_code == 201, analysis.json()
            assert analysis.json()["provenance"]["cpe_mode"] == "live"
            assert analysis.json()["provenance"]["cpe_source"] == "nvd-feed"
            assert analysis.json()["provenance"]["cve_source"] == "simulated"
            for revision, version in [(1, None), (2, candidate["version"])]:
                edit = client.patch(
                    path,
                    headers=headers,
                    json={
                        "expected_record_version": revision,
                        "reason": "Nueva observación",
                        "version": version,
                        "confirm_sensitive": True,
                    },
                )
                assert edit.status_code == 200, edit.json()
                assert edit.json()["cpe_review_state"] == "needs_review"
            confirmed = client.post(
                path + "/reidentification",
                headers=headers,
                json=selection
                | {
                    "expected_record_version": 3,
                    "expected_identification_id": None,
                },
            )
            assert confirmed.status_code == 201, confirmed.json()
            assert confirmed.json()["catalog_evidence"]["source"] == "nvd-feed"
            history = client.get(path + "/identifications", headers=headers).json()["items"]
            assert [row["identity_generation"] for row in history] == [3, 1]
            with admin.connect() as db:
                assert db.scalar(text("SELECT count(*) FROM vulntrack_devices.devices")) == 0
                assert db.scalar(text("SELECT count(*) FROM vulntrack_catalog.products")) == 1
            credentials = create_engine(url, hide_parameters=True)
            try:
                with pytest.raises(DBAPIError), credentials.begin() as db:
                    db.execute(
                        text("UPDATE vulntrack_catalog.products SET version='00' WHERE false")
                    )
                with pytest.raises(DBAPIError), credentials.begin() as db:
                    db.execute(text("SELECT count(*) FROM vulntrack.users"))
            finally:
                credentials.dispose()

            with admin.begin() as db:
                db.execute(text("LOCK TABLE vulntrack_catalog.products IN ACCESS EXCLUSIVE MODE"))
                unavailable = client.get(CAT + "/candidates", headers=headers)
                assert unavailable.status_code == 503
                assert unavailable.json()["error"]["code"] == "CATALOG_SOURCE_UNAVAILABLE"
            assert client.get(CAT + "/candidates", headers=headers).status_code == 200
            with admin.begin() as db:
                db.execute(text("UPDATE vulntrack_catalog.products SET version='inconsistent'"))
            bad = client.get(CAT + "/candidates/" + candidate["cpe_name_id"], headers=headers)
            assert bad.status_code == 503
            assert bad.json()["error"]["code"] == "CATALOG_SOURCE_INCONSISTENT"
            rejected = client.post(
                endpoint, headers=headers | {"Idempotency-Key": str(uuid4())}, json=body
            )
            assert rejected.status_code == 503
            assert client.get(endpoint, headers=headers).json()["page"]["total"] == 1
        finally:
            reader.close()
            admin.dispose()

        # Even a reachable valid PostgreSQL URL fails closed for a broad login.
        bad_reader = CatalogReader(app.state.engine, SecretStr(external.url("postgres")))
        app.state.catalog_reader = bad_reader
        try:
            denied = client.get(CAT + "/status", headers=headers)
            assert denied.status_code == 503 and password not in denied.text
        finally:
            bad_reader.close()

    app.state.catalog_reader = CatalogReader(
        app.state.engine, SecretStr(url.render_as_string(hide_password=False))
    )
    try:
        disconnected = client.get(CAT + "/status", headers=headers)
        assert disconnected.status_code == 503 and password not in disconnected.text
        assert client.get(CAT + "/status?mode=fixture", headers=headers).status_code == 200
    finally:
        app.state.catalog_reader.close()
