"""Analytics checked against independent row calculations on disposable PostgreSQL."""

import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, text

from app.db.workspace_context import workspace_session
from tests.integration.test_rc2_devices import api, confirm, create, owner  # noqa: F401
from tests.integration.test_rc3_device_revisions import edit
from tests.integration.test_v2_registration import account

pytestmark = pytest.mark.postgres


def analytics(user, resource):
    return f"/api/v2/workspaces/{user['workspace']}/inventory-analytics/{resource}"


def get(client, user, resource="distribution", **params):
    response = client.get(analytics(user, resource), headers=user["headers"], params=params)
    assert response.status_code == 200, response.json()
    return response.json()


def seed_inventory(postgres, user):
    """Explicit synthetic records, never added to persistent application inventory."""
    app, archived = uuid4(), uuid4()
    with postgres.begin() as db:
        for identifier, status in ((app, "active"), (archived, "archived")):
            db.execute(
                text("""INSERT INTO vulntrack.applications
                (id,workspace_id,name,status,created_by)
                VALUES (:id,:ws,'Synthetic app',:status,:actor)
            """),
                {"id": identifier, "ws": user["workspace"], "status": status, "actor": user["id"]},
            )
        devices = [(f"Vendor {n:02}", "Shared model", "active") for n in range(15)]
        devices += [
            ("Cisco  Systems", "RV  340", "active"),
            ("cisco systems", "rv 340", "active"),
            ("Excluded", "Old", "retired"),
        ]
        for vendor, model, status in devices:
            db.execute(
                text("""INSERT INTO vulntrack_devices.devices
                (id,workspace_id,created_by,device_type,manufacturer,model,product_vendor,product,
                 component_kind,site_label,status)
                VALUES (:id,:ws,:actor,'router',:vendor,:model,'different_firmware_vendor',
                    'firmware','firmware','Disposable lab',:status)"""),
                {
                    "id": uuid4(),
                    "ws": user["workspace"],
                    "actor": user["id"],
                    "vendor": vendor,
                    "model": model,
                    "status": status,
                },
            )
        technologies = [(f"Software {n:02}", "Same product", app) for n in range(15)]
        technologies += [
            ("Acme  Software", "Suite  X", app),
            ("acme software", "suite x", app),
            ("Acme-Software", "suite x", app),
            (None, "Known product", app),
            (None, "Other known product", app),
            ("Archived", "Excluded", archived),
        ]
        for vendor, product, application in technologies:
            db.execute(
                text("""INSERT INTO vulntrack.technologies
                (id,workspace_id,application_id,vendor,product,version,detection_method,created_by)
                VALUES (:id,:ws,:app,:vendor,:product,'1.0','manual',:actor)"""),
                {
                    "id": uuid4(),
                    "ws": user["workspace"],
                    "app": application,
                    "vendor": vendor,
                    "product": product,
                    "actor": user["id"],
                },
            )


def independent_distribution(postgres, user, kind, dimension, limit):
    if kind == "devices":
        query = (
            "SELECT manufacturer AS vendor,model AS product,status FROM vulntrack_devices.devices"
        )
    else:
        query = """SELECT t.vendor,t.product,a.status FROM vulntrack.technologies t
            JOIN vulntrack.applications a ON a.workspace_id=t.workspace_id
            AND a.id=t.application_id"""
    query += " WHERE " + ("t." if kind == "technologies" else "") + "workspace_id=:ws"
    with postgres.connect() as db:
        rows = db.execute(text(query), {"ws": user["workspace"]}).mappings().all()

    def normalize(value):
        return re.sub(r"\s+", " ", value).strip().lower() if value else None

    active = [r for r in rows if r["status"] == "active"]
    groups = Counter()
    unknown = 0
    for row in active:
        vendor, product = normalize(row["vendor"]), normalize(row["product"])
        if vendor is None or (dimension == "product" and product is None):
            unknown += 1
        else:
            groups[(vendor, product if dimension == "product" else None)] += 1
    ranked = sorted(groups.items(), key=lambda row: (-row[1], row[0]))
    return {
        "total": len(active),
        "excluded_inactive": len(rows) - len(active),
        "unknown": unknown,
        "other": sum(n for _, n in ranked[limit:]),
        "categories": ranked[:limit],
    }


def test_empty_single_record_auth_and_bounded_contract(api):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    outsider = account(client)
    for resource in ("distribution", "events"):
        path = analytics(user, resource)
        assert client.get(path).status_code == 401
        assert client.get(path, headers=outsider["headers"]).status_code == 404
        assert (
            client.get(
                path.replace(user["workspace"], str(uuid4())), headers=user["headers"]
            ).status_code
            == 404
        )
    assert get(client, user)["total"] == 0
    for kind in ("devices", "technologies"):
        data = get(client, user, "events", inventory_kind=kind, days=90)
        assert len(data["daily"]) == 90 and not any(data["totals"].values())
    create(client, base, user, {"version": None})
    result = get(client, user)
    assert result["total"] == 1 and result["categories"][0]["count"] == 1
    assert get(client, user, "events")["totals"]["first_confirmations"] == 0
    assert "InventoryDistribution" in str(app.openapi()["paths"][analytics_schema("distribution")])
    days_parameter = next(
        p
        for p in app.openapi()["paths"][analytics_schema("events")]["get"]["parameters"]
        if p["name"] == "days"
    )
    assert days_parameter["schema"]["enum"] == [30, 90]
    for params in (
        {"limit": 0},
        {"limit": 11},
        {"dimension": "' OR true"},
        {"inventory_kind": "all"},
    ):
        assert (
            client.get(
                analytics(user, "distribution"), headers=user["headers"], params=params
            ).status_code
            == 422
        )
    for days in (0, 31, 91, "' OR true"):
        assert (
            client.get(
                analytics(user, "events"), headers=user["headers"], params={"days": days}
            ).status_code
            == 422
        )


def analytics_schema(resource):
    return "/api/v2/workspaces/{workspace_id}/inventory-analytics/" + resource


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_roles_rls_row_oracle_exact_filters_and_page_independence(api, postgres, role):  # noqa: F811
    app, client = api
    _, user = owner(app, client)
    seed_inventory(postgres, user)
    member = account(client)
    with postgres.begin() as db:
        db.execute(
            text("INSERT INTO vulntrack.workspace_members VALUES (:ws,:actor,:role,now())"),
            {"ws": user["workspace"], "actor": member["id"], "role": role},
        )
    actor = member | {"workspace": user["workspace"]}
    observed = []

    def capture(_c, _cur, statement, _p, _context, _many):
        observed.append(statement)

    event.listen(app.state.engine, "before_cursor_execute", capture)
    try:
        for kind in ("devices", "technologies"):
            for dimension in ("vendor", "product"):
                for limit in (1, 10):
                    data = get(client, actor, inventory_kind=kind, dimension=dimension, limit=limit)
                    expected = independent_distribution(postgres, user, kind, dimension, limit)
                    assert {k: data[k] for k in expected if k != "categories"} == {
                        k: v for k, v in expected.items() if k != "categories"
                    }
                    assert [
                        ((r["vendor_key"], r["product_key"]), r["count"])
                        for r in data["categories"]
                    ] == expected["categories"]
        assert not any("vulntrack_catalog." in statement for statement in observed)
    finally:
        event.remove(app.state.engine, "before_cursor_execute", capture)
    before = get(client, actor, dimension="product")
    devices = f"/api/v2/workspaces/{user['workspace']}/devices"
    ids = set()
    for offset in (0, 5, 10, 15):
        response = client.get(
            devices, headers=member["headers"], params={"limit": 5, "offset": offset}
        )
        assert response.status_code == 200
        ids.update(row["id"] for row in response.json()["items"])
    assert len(ids) == 18
    repeated = get(client, actor, dimension="product")
    assert {k: v for k, v in repeated.items() if k != "observed_at"} == {
        k: v for k, v in before.items() if k != "observed_at"
    }

    for row in before["categories"]:
        response = client.get(
            devices,
            headers=member["headers"],
            params={
                "status": "active",
                "manufacturer_key": row["vendor_key"],
                "model_key": row["product_key"],
            },
        )
        assert response.status_code == 200 and response.json()["page"]["total"] == row["count"]
    response = client.get(
        devices, headers=member["headers"], params={"manufacturer_key": "%' OR true --"}
    )
    assert response.status_code == 200 and response.json()["page"]["total"] == 0
    assert (
        client.get(devices, headers=member["headers"], params={"model_key": "x" * 121}).status_code
        == 422
    )
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(member["id"]), UUID(member["workspace"])
    ) as session:
        for table in (
            "vulntrack_devices.devices",
            "vulntrack.technologies",
            "vulntrack_technology_cpe.confirmations",
            "vulntrack_devices.revisions",
        ):
            assert session.scalar(text("SELECT count(*) FROM " + table)) == 0
    assert get(client, member)["total"] == 0
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda u: get(client, u)["total"], (actor, member)))
    assert results == [17, 0]


def test_device_events_use_exclusive_revisions_and_persisted_dates(api, postgres):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    path = create(client, base, user)
    first = confirm(client, path, user)
    assert first.status_code == 201
    assert confirm(client, path, user, first.json()["id"]).status_code == 201
    assert (
        edit(
            client, user, path, 1, version="1.0.1.16", product="New product", confirm_sensitive=True
        ).status_code
        == 200
    )
    assert edit(client, user, path, 2, site_label="Administrative change").status_code == 200
    assert (
        edit(client, user, path, 3, component_kind="os", confirm_sensitive=True).status_code == 200
    )
    data = get(client, user, "events")
    assert data["totals"] == {
        "first_confirmations": 1,
        "subsequent_confirmations": 1,
        "technology_confirmations": 0,
        "version_changes": 1,
        "identity_changes_without_version": 1,
    }
    assert data["confirmation_modes"] == {"fixture": 2, "live": 0, "unknown": 0}
    assert sum(sum(day["counts"].values()) for day in data["daily"]) == 4
    # Retiring preserves the activity; it is not a technological change.
    assert edit(client, user, path, 4, status="retired").status_code == 200
    after = get(client, user, "events")
    assert after["totals"] == data["totals"] and after["daily"] == data["daily"]
    assert get(client, user)["total"] == 0
    with postgres.connect() as db:
        rows = (
            db.execute(
                text(
                    "SELECT changed_fields,recorded_at,change_kind "
                    "FROM vulntrack_devices.revisions "
                    "WHERE workspace_id=:ws"
                ),
                {"ws": user["workspace"]},
            )
            .mappings()
            .all()
        )
    assert sum("version" in row["changed_fields"] for row in rows) == 1
    assert (
        sum(
            row["change_kind"] == "technological" and "version" not in row["changed_fields"]
            for row in rows
        )
        == 1
    )


def test_event_window_utc_edges_and_first_event_outside_window(api, postgres):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    device = create(client, base, user).split("/")[-1]
    with postgres.begin() as db:
        for expression, mode in (
            ("date_trunc('day',now() AT TIME ZONE 'UTC')-interval '80 days'", "fixture"),
            ("date_trunc('day',now() AT TIME ZONE 'UTC')-interval '29 days'", "unknown"),
            ("date_trunc('day',now() AT TIME ZONE 'UTC')+interval '1 day'", "live"),
        ):
            db.execute(
                text(f"""INSERT INTO vulntrack_devices.identifications
                (id,workspace_id,device_id,recorded_by,cpe_name,cpe_name_id,mode,reason,created_at)
                VALUES (:id,:ws,:device,:actor,'cpe:2.3:o:cisco:firmware:1.0:*:*:*:*:*:*:*',:cpe,
                    :mode,'Synthetic UTC boundary',({expression}) AT TIME ZONE 'UTC')"""),
                {
                    "id": uuid4(),
                    "ws": user["workspace"],
                    "device": device,
                    "actor": user["id"],
                    "cpe": uuid4(),
                    "mode": mode,
                },
            )
    thirty, ninety = get(client, user, "events"), get(client, user, "events", days=90)
    assert thirty["totals"]["first_confirmations"] == 0
    assert thirty["totals"]["subsequent_confirmations"] == 1
    assert thirty["daily"][0]["counts"]["subsequent_confirmations"] == 1
    assert thirty["confirmation_modes"] == {"live": 0, "fixture": 0, "unknown": 1}
    assert ninety["totals"]["first_confirmations"] == 1
    assert ninety["totals"]["subsequent_confirmations"] == 1
    assert len(thirty["daily"]) == 30 and len(ninety["daily"]) == 90


def test_technology_legacy_gaps_and_recorded_confirmations_not_cve(api, postgres):  # noqa: F811
    app, client = api
    user = account(client)
    base = f"/api/v2/workspaces/{user['workspace']}/applications"
    response = client.post(base, headers=user["headers"], json={"name": "Synthetic history"})
    assert response.status_code == 201
    base += "/" + response.json()["id"]
    response = client.post(
        base + "/technologies",
        headers=user["headers"],
        json={"vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"},
    )
    assert response.status_code == 201
    tech = base + "/technologies/" + response.json()["id"]
    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    with postgres.begin() as db:
        db.execute(
            text(
                "UPDATE vulntrack.technologies SET selected_cpe=:cpe,"
                "confidence='user_confirmed' WHERE id=:id"
            ),
            {"cpe": cpe, "id": tech.split("/")[-1]},
        )
    legacy = get(client, user, "events", inventory_kind="technologies")
    assert (
        not any(legacy["totals"].values()) and legacy["selections_without_confirmation_events"] == 1
    )
    assert legacy["version_history_available"] is False
    # An explicit synthetic event, checked by the real immutable-history trigger.
    # This analytics test must not seed a global dictionary used by importer tests.
    with postgres.begin() as db:
        db.execute(
            text("""INSERT INTO vulntrack_technology_cpe.confirmations
            (id,workspace_id,application_id,technology_id,recorded_by,cpe_name_id,cpe_name,
             mode,source,observed_vendor,observed_product,observed_version,catalog_evidence)
            VALUES (:id,:ws,:app,:tech,:actor,:name_id,:cpe,'fixture','nvd-captured-fixture',
                'Apache','HTTP Server','2.4.49','{"test":"synthetic"}')"""),
            {
                "id": uuid4(),
                "ws": user["workspace"],
                "app": base.split("/")[-1],
                "tech": tech.split("/")[-1],
                "actor": user["id"],
                "name_id": uuid4(),
                "cpe": cpe,
            },
        )
    saved = get(client, user, "events", inventory_kind="technologies")
    assert saved["totals"]["technology_confirmations"] == 1
    assert saved["confirmation_modes"] == {"live": 0, "fixture": 1, "unknown": 0}
    assert saved["selections_without_confirmation_events"] == 0
    # No retrospective version history from a changed current record; existing event is immutable.
    with postgres.begin() as db:
        db.execute(
            text("UPDATE vulntrack.technologies SET version='2.4.50' WHERE id=:id"),
            {"id": tech.split("/")[-1]},
        )
        db.execute(
            text("UPDATE vulntrack.applications SET status='archived' WHERE id=:id"),
            {"id": base.split("/")[-1]},
        )
    after = get(client, user, "events", inventory_kind="technologies")
    assert after["daily"] == saved["daily"] and after["totals"] == saved["totals"]
    assert get(client, user, inventory_kind="technologies")["total"] == 0


def test_distribution_total_and_categories_share_snapshot(api, postgres):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    create(client, base, user)
    inserted = []

    def after(_c, _cur, statement, _p, _context, _many):
        if "WITH inventory AS MATERIALIZED" in statement and not inserted:
            inserted.append(True)
            seed_inventory(postgres, user)

    event.listen(app.state.engine, "after_cursor_execute", after)
    try:
        data = get(client, user)
        assert inserted and data["total"] == data["categories"][0]["count"] == 1
    finally:
        event.remove(app.state.engine, "after_cursor_execute", after)
    assert get(client, user)["total"] == 18
