"""Workspace coverage on a real restricted PostgreSQL connection, not mock statistics."""

from uuid import uuid4

import pytest
from sqlalchemy import text

from app.db.workspace_context import workspace_session
from tests.integration.test_rc2_devices import api, confirm, create, owner  # noqa: F401
from tests.integration.test_rc3_device_revisions import edit
from tests.integration.test_v2_registration import account

pytestmark = pytest.mark.postgres


def endpoint(user):
    return f"/api/v2/workspaces/{user['workspace']}/inventory-coverage"


def get(client, user):
    response = client.get(endpoint(user), headers=user["headers"])
    assert response.status_code == 200, response.json()
    result = response.json()
    for key in ("devices", "technologies"):
        row = result[key]
        assert row["confirmed"] + row["pending"] + row["needs_review"] == row["total"]
    return result


def test_empty_auth_scope_and_openapi(api):  # noqa: F811
    app, client = api
    user, outsider = account(client), account(client)
    path = endpoint(user)
    assert client.get(path).status_code == 401
    assert client.get(path, headers=outsider["headers"]).status_code == 404
    assert (
        client.get(
            path.replace(user["workspace"], str(uuid4())), headers=user["headers"]
        ).status_code
        == 404
    )
    result = get(client, user)
    assert result["workspace_id"] == user["workspace"] and result["scope"] == "active"
    assert result["devices"]["total"] == result["technologies"]["total"] == 0
    operation = app.openapi()["paths"]["/api/v2/workspaces/{workspace_id}/inventory-coverage"][
        "get"
    ]
    assert operation["security"] and "InventoryCoverage" in str(operation["responses"]["200"])


def test_generations_modes_retired_and_unknown_version(api):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    create(client, base, user, {"version": None})
    fixture = create(client, base, user)
    first = confirm(client, fixture, user)
    assert first.status_code == 201
    second = confirm(client, fixture, user, first.json()["id"])
    assert second.status_code == 201
    # Synthetic resolver in this test, no NVD requests. Persisted acquisition modes differ.
    app.state.nvd_mode = "live"
    official = create(client, base, user)
    assert confirm(client, official, user).status_code == 201
    app.state.nvd_mode = "unknown"
    unknown = create(client, base, user)
    assert confirm(client, unknown, user).status_code == 201
    changed = create(client, base, user)
    assert confirm(client, changed, user).status_code == 201
    assert (
        edit(client, user, changed, 1, version="1.0.1.16", confirm_sensitive=True).status_code
        == 200
    )
    retired = create(client, base, user)
    assert confirm(client, retired, user).status_code == 201
    assert edit(client, user, retired, 1, status="retired").status_code == 200
    data = get(client, user)["devices"]
    assert data == {
        "total": 5,
        "confirmed": 3,
        "pending": 1,
        "needs_review": 1,
        "excluded_inactive": 1,
        "without_version": 1,
        "confirmed_by_mode": {"live": 1, "fixture": 1, "unknown": 1},
    }
    # Reconfirming the current generation moves exactly one device out of review.
    app.state.nvd_mode = "fixture"
    assert (
        edit(client, user, changed, 2, version="1.0.0.33", confirm_sensitive=True).status_code
        == 200
    )
    assert confirm(client, changed, user).status_code == 201
    assert get(client, user)["devices"]["confirmed"] == 4
    assert get(client, user)["devices"]["needs_review"] == 0


def test_technology_units_archived_and_unrecorded_provenance(api, postgres):  # noqa: F811
    _, client = api
    user = account(client)
    base = f"/api/v2/workspaces/{user['workspace']}/applications"
    application = client.post(
        base, headers=user["headers"], json={"name": "Active coverage test"}
    ).json()["id"]
    archived = client.post(
        base, headers=user["headers"], json={"name": "Archived coverage test"}
    ).json()["id"]
    identifiers = []
    for index in range(5):
        response = client.post(
            base + "/" + (archived if index == 4 else application) + "/technologies",
            headers=user["headers"],
            json={"product": "same_product", "vendor": "same_vendor", "version": "1.0"},
        )
        assert response.status_code == 201
        identifiers.append(response.json()["id"])
    with postgres.begin() as db:
        for index, confidence in [(1, "user_confirmed"), (2, "high")]:
            db.execute(
                text(
                    "UPDATE vulntrack.technologies SET selected_cpe="
                    "'cpe:2.3:a:same_vendor:same_product:1.0:*:*:*:*:*:*:*',"
                    "confidence=:confidence WHERE id=:id"
                ),
                {"confidence": confidence, "id": identifiers[index]},
            )
        # A legacy confidence flag alone is not a confirmed identity.
        db.execute(
            text("UPDATE vulntrack.technologies SET confidence='user_confirmed' WHERE id=:id"),
            {"id": identifiers[3]},
        )
        db.execute(
            text("UPDATE vulntrack.applications SET status='archived' WHERE id=:id"),
            {"id": archived},
        )
    assert get(client, user)["technologies"] == {
        "total": 4,
        "confirmed": 1,
        "pending": 2,
        "needs_review": 1,
        "excluded_inactive": 1,
        "confirmation_provenance": "per_confirmation",
    }


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_roles_rls_and_reused_connections_do_not_leak(api, postgres, role):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    create(client, base, user)
    member, outsider = account(client), account(client)
    with postgres.begin() as db:
        db.execute(
            text(
                "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                "VALUES (:workspace,:member,:role)"
            ),
            {"workspace": user["workspace"], "member": member["id"], "role": role},
        )
    assert client.get(endpoint(user), headers=member["headers"]).json()["devices"]["total"] == 1
    assert client.get(endpoint(user), headers=outsider["headers"]).status_code == 404
    for actor, expected in [(user, 1), (outsider, 0), (member, 0), (user, 1)]:
        assert get(client, actor)["devices"]["total"] == expected
        # This SQL intentionally has no WHERE. RLS itself must enforce isolation.
        with workspace_session(
            app.state.session_factory, app.state.settings, actor["id"], actor["workspace"]
        ) as db:
            assert db.scalar(text("SELECT count(*) FROM vulntrack_devices.devices")) == expected
    with app.state.session_factory() as db:
        assert db.scalar(text("SELECT count(*) FROM vulntrack_devices.devices")) == 0
    viewer_copy = {**member, "workspace": user["workspace"]}
    assert get(client, viewer_copy)["devices"]["total"] == 1


def test_endpoint_is_readonly_and_does_not_open_catalog(api, postgres, monkeypatch):  # noqa: F811
    app, client = api
    base, user = owner(app, client)
    create(client, base, user)

    def forbidden(*args, **kwargs):
        pytest.fail("Inventory coverage must not read the dictionary or request CVE")

    monkeypatch.setattr(app.state.catalog_reader, "connect", forbidden)
    monkeypatch.setattr(app.state.nvd, "resolve", forbidden)
    with postgres.connect() as db:
        before = db.scalar(
            text(
                "SELECT md5(string_agg(to_jsonb(d)::text,'' ORDER BY id)) "
                "FROM vulntrack_devices.devices d WHERE workspace_id=:w"
            ),
            {"w": user["workspace"]},
        )
    for _ in range(3):
        assert get(client, user)["devices"]["total"] == 1
    with postgres.connect() as db:
        after = db.scalar(
            text(
                "SELECT md5(string_agg(to_jsonb(d)::text,'' ORDER BY id)) "
                "FROM vulntrack_devices.devices d WHERE workspace_id=:w"
            ),
            {"w": user["workspace"]},
        )
    assert before == after
