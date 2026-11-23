"""Application CPE search and confirmation use the same bounded dictionary."""

import secrets
from copy import deepcopy
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from app.services.catalog_reader import CatalogReader
from app.services.cpe_catalog import UPSERT, normalize
from scripts.disposable_v2 import DisposableV2
from tests.cpe_support import NAME_ID, RAW
from tests.integration.test_v2_stabilization import account, api  # noqa: F401

pytestmark = pytest.mark.postgres


def catalog_record(
    *,
    vendor="apache",
    product="http_server",
    version="2.4.49",
    part="a",
    update="*",
    deprecated=False,
):
    entry = deepcopy(RAW["products"][0])
    entry["cpe"].update(
        cpeNameId=str(uuid4()),
        cpeName=f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*",
        deprecated=deprecated,
        titles=[{"lang": "en", "title": f"{vendor} {product} {version}"}],
    )
    return normalize(entry, "live", None, source="nvd-feed")


def test_application_search_and_confirmation_from_external_catalog(api, postgres):  # noqa: F811
    app, client = api
    owner, outsider = account(client), account(client)
    headers = owner["headers"]
    apps = f"/api/v2/workspaces/{owner['workspace']}/applications"
    created = client.post(apps, headers=headers, json={"name": "Regresión oficial Apache"})
    assert created.status_code == 201
    base = apps + "/" + created.json()["id"]
    technology = client.post(
        base + "/technologies",
        headers=headers,
        json={"vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"},
    )
    assert technology.status_code == 201
    technology_id = technology.json()["id"]
    confirmation = f"{base}/technologies/{technology_id}/cpe"
    with postgres.begin() as connection:
        connection.execute(UPSERT, normalize(RAW["products"][0], "fixture", None))

    first = catalog_record()
    second = catalog_record(update="release")
    rejected = [
        (catalog_record(deprecated=True), "CPE_DEPRECATED"),
        (catalog_record(vendor="cisco"), "CPE_PRODUCT_MISMATCH"),
        (catalog_record(product="other"), "CPE_PRODUCT_MISMATCH"),
        (catalog_record(part="o"), "CPE_PRODUCT_MISMATCH"),
        (catalog_record(version="2.4.51"), "CPE_VERSION_MISMATCH"),
    ]

    with DisposableV2("new", sql_checks=False) as source:
        password = secrets.token_urlsafe(24)
        role = "application_catalog_lab"
        source.sql(
            f"CREATE ROLE {role} LOGIN NOINHERIT PASSWORD '{password}';"
            f"GRANT CONNECT ON DATABASE {source.database} TO {role};"
            f"GRANT USAGE ON SCHEMA vulntrack_catalog TO {role};"
            "GRANT SELECT ON vulntrack_catalog.products,vulntrack_catalog.summary,"
            f"vulntrack_catalog.sync_runs,vulntrack_catalog.feed_imports TO {role};"
        )
        admin = create_engine(source.url("postgres"), hide_parameters=True)
        with admin.begin() as connection:
            connection.execute(UPSERT, [first, second, *(row for row, _ in rejected)])
        admin.dispose()
        url = make_url(source.url("postgres")).set(username=role, password=password)
        reader = CatalogReader(
            app.state.engine, SecretStr(url.render_as_string(hide_password=False))
        )
        app.state.catalog_reader = reader
        criteria = {"query": "http_server", "technology_id": technology_id, "part": "a"}

        def search(changes=None):
            response = client.get(
                base + "/cpe-candidates", headers=headers, params=criteria | (changes or {})
            )
            assert response.status_code == 200, response.json()
            return response.json()

        def confirm(identifier, **changes):
            return client.put(
                confirmation,
                headers=headers,
                json={"cpe_name_id": str(identifier), **changes},
            )

        try:
            pages = [search({"limit": 1, "offset": offset}) for offset in (0, 1)]
            assert [page["page"]["total"] for page in pages] == [2, 2]
            assert {page["items"][0]["cpe_name_id"] for page in pages} == {
                str(first["cpe_name_id"]),
                str(second["cpe_name_id"]),
            }
            assert search({"query": "cisco"})["items"] == []
            assert search({"mode": "fixture", "part": "o"})["items"] == []
            assert (
                client.get(
                    base + "/cpe-candidates", headers=outsider["headers"], params=criteria
                ).status_code
                == 404
            )
            assert (
                client.get(
                    base + "/cpe-candidates",
                    headers=headers,
                    params=criteria | {"technology_id": str(uuid4())},
                ).status_code
                == 404
            )
            assert (
                client.put(
                    confirmation,
                    headers=outsider["headers"],
                    json={"cpe_name_id": str(first["cpe_name_id"])},
                ).status_code
                == 404
            )
            assert confirm(uuid4()).status_code == 404
            assert confirm(NAME_ID).status_code == 404
            assert confirm(first["cpe_name_id"], mode="fixture").status_code == 404
            assert (
                confirm(first["cpe_name_id"], expected_cpe_name=second["cpe_name"]).status_code
                == 409
            )
            for record, code in rejected:
                denied = confirm(record["cpe_name_id"])
                assert denied.status_code == 409 and denied.json()["error"]["code"] == code

            confirmed = confirm(first["cpe_name_id"], expected_cpe_name=first["cpe_name"])
            assert confirmed.status_code == 200
            assert confirmed.json()["cpe_name"] == first["cpe_name"]
            assert confirm(second["cpe_name_id"]).status_code == 409
            persisted = client.get(base + "/technologies", headers=headers).json()["items"][0]
            assert persisted["id"] == technology_id and persisted["confidence"] == "user_confirmed"
            assert persisted["selected_cpe"] == first["cpe_name"]
            assert (persisted["vendor"], persisted["product"], persisted["version"]) == (
                "Apache",
                "HTTP Server",
                "2.4.49",
            )
        finally:
            reader.close()

    offline = client.get(base + "/cpe-candidates", headers=headers, params=criteria)
    assert offline.status_code == 503
    assert offline.json()["error"]["code"] == "CATALOG_SOURCE_UNAVAILABLE"
