"""Real disposable database, JWT and workspace RLS. NVD transport is synthetic."""

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.db.workspace_context import workspace_session
from app.integrations.nvd import Quota
from tests.cpe_support import NAME_ID
from tests.integration import test_v2_stabilization as shared

api = shared.api
pytestmark = pytest.mark.postgres

ROUTER = {
    "device_type": "router",
    "manufacturer": "Cisco",
    "model": "RV340",
    "product_vendor": "cisco",
    "product": "small_business_rv340_firmware",
    "component_kind": "firmware",
    "version": "1.0.0.33",
    "site_label": "Laboratorio",
}


def owner(app, client):
    app.state.nvd_mode = "fixture"
    # Offset each mocked request by one interval. SQL concurrency remains real.
    from itertools import count

    ticks = count(100, 7)
    app.state.nvd.quota = Quota(clock=lambda: next(ticks))
    account = shared.account(client)
    return f"/api/v2/workspaces/{account['workspace']}/devices", account


def create(client, base, user, data=None):
    result = client.post(base, headers=user["headers"], json=ROUTER | (data or {}))
    assert result.status_code == 201, result.json()
    return base + "/" + result.json()["id"]


def confirm(client, path, user, expected=None):
    return client.post(
        path + "/identifications",
        headers=user["headers"],
        json={
            "cpe_name_id": str(NAME_ID),
            "reason": "Identificación humana",
            "expected_identification_id": expected,
        },
    )


def test_devices_separate_history_review_recommendations_and_source(api, postgres):
    app, client = api
    base, a = owner(app, client)
    router = create(client, base, a)
    create(client, base, a, {"device_type": "switch", "model": "Switch"})
    server = create(
        client,
        base,
        a,
        {
            "device_type": "server",
            "manufacturer": "Equipo ficticio",
            "model": "Servidor ficticio",
            "product_vendor": "apache",
            "product": "http_server",
            "component_kind": "software",
            "version": None,
        },
    )
    assert confirm(client, server, a).json()["error"]["code"] == "VERSION_REQUIRED"
    assert (
        client.get(base + "?q=RV340&device_type=router", headers=a["headers"]).json()["page"][
            "total"
        ]
        == 1
    )
    candidates = client.get(router + "/cpe-candidates?query=RV340", headers=a["headers"])
    assert candidates.status_code == 200 and len(candidates.json()["items"]) == 1
    selection = confirm(client, router, a)
    assert selection.status_code == 201, selection.json()
    first = selection.json()
    assert first["mode"] == "fixture"
    assert confirm(client, router, a).status_code == 409

    key = a["headers"] | {"Idempotency-Key": str(uuid4())}
    response = client.post(router + "/analyses", headers=key)
    assert response.status_code == 201, response.json()
    run = response.json()
    assert run["status"] == "completed" and run["mode"] == "fixture"
    assert run["identification_id"] == first["id"]
    assert client.post(router + "/analyses", headers=key).json() == run
    app.state.nvd_mode = "live"  # Simulate changing provenance, transport remains mocked.
    assert (
        client.post(
            router + "/analyses",
            headers=a["headers"]
            | {
                "Idempotency-Key": str(uuid4()),
            },
        ).json()["error"]["code"]
        == "CPE_MODE_CHANGED"
    )
    assert confirm(client, router, a, first["id"]).json()["mode"] == "live"
    historical = client.get(router + "/analyses/" + run["id"], headers=a["headers"]).json()
    assert historical["assessment"]["correspondence"] == "historical"
    assert historical["assessment"]["requires_new_query"]
    assert not historical["is_current_technology"]
    assert {
        **historical,
        "assessment": run["assessment"],
        "is_current_technology": run["is_current_technology"],
    } == run
    identities = client.get(router + "/identifications", headers=a["headers"]).json()["items"]
    assert [value["mode"] for value in identities] == ["live", "fixture"]
    finding = client.get(
        router + "/analyses/" + run["id"] + "/findings?limit=100", headers=a["headers"]
    ).json()["items"][0]
    assert finding["external_id"] == "CVE-2017-6784" and finding["applicability"] == "undetermined"
    finding_path = router + "/findings/" + finding["id"]
    review = {
        "applicability": "undetermined",
        "expected_updated_at": finding["updated_at"],
        "reason": "Evaluación de laboratorio",
        "evidence": "Condiciones adicionales sin datos",
    }
    result = client.patch(finding_path, headers=a["headers"], json=review)
    assert result.status_code == 200, result.json()
    assert result.json()["status"] == "reviewed"
    assert client.patch(finding_path, headers=a["headers"], json=review).status_code == 409
    result = client.post(
        finding_path + "/recommendations",
        headers=key,
        json={"recommendation": "Revisar el aviso del fabricante"},
    )
    assert result.status_code == 201, result.json()
    assert client.get(finding_path + "/recommendations", headers=a["headers"]).json()["items"] == [
        result.json()
    ]
    assert (
        client.get(
            f"/api/v2/workspaces/{a['workspace']}/nvd-dashboard/fixture", headers=a["headers"]
        ).json()["summary"]["analyses_total"]
        == 0
    )
    with postgres.connect() as db:
        assert (
            db.scalar(
                text(
                    "SELECT count(*) FROM vulntrack.audit_events WHERE workspace_id=:id "
                    "AND action LIKE 'device.%'"
                ),
                {"id": a["workspace"]},
            )
            == 8
        )


@pytest.mark.parametrize(
    "changes, code",
    [
        ({"version": "2.4.58"}, "CPE_VERSION_MISMATCH"),
        ({"product_vendor": "apache", "product": "http_server"}, "CPE_PRODUCT_MISMATCH"),
        ({"product": "asr1000"}, "CPE_PRODUCT_MISMATCH"),
        ({"component_kind": "hardware"}, "CPE_PRODUCT_MISMATCH"),
    ],
)
def test_incompatible_cpe_rejected(api, changes, code):
    app, client = api
    base, a = owner(app, client)
    result = confirm(client, create(client, base, a, changes), a)
    assert result.status_code == 409 and result.json()["error"]["code"] == code


def test_real_roles_foreign_ids_and_rls_context_reuse(api, postgres):
    app, client = api
    base, a = owner(app, client)
    _, b = owner(app, client)
    _, c = owner(app, client)
    router = create(client, base, a)
    assert client.get(router, headers=b["headers"]).status_code == 404
    assert client.get(router, headers=c["headers"]).status_code == 404
    assert (
        client.get(router.replace(a["workspace"], b["workspace"]), headers=b["headers"]).status_code
        == 404
    )
    assert (
        client.post(
            base, headers=a["headers"], json=ROUTER | {"workspace_id": b["workspace"]}
        ).status_code
        == 422
    )
    with postgres.begin() as db:
        db.execute(
            text(
                "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                "VALUES (:workspace,:viewer,'viewer'),(:workspace,:editor,'editor')"
            ),
            {"workspace": a["workspace"], "viewer": b["id"], "editor": c["id"]},
        )
    assert client.get(router, headers=b["headers"]).status_code == 200
    assert client.post(base, headers=b["headers"], json=ROUTER).status_code == 404
    assert confirm(client, router, b).status_code == 404
    assert client.post(base, headers=c["headers"], json=ROUTER).status_code == 201
    assert confirm(client, router, c).status_code == 201
    for _ in range(4):
        for account, expected in [(a, 2), (b, 0), (a, 2)]:
            with workspace_session(
                app.state.session_factory, app.state.settings, account["id"], account["workspace"]
            ) as db:
                assert db.scalar(text("SELECT count(*) FROM vulntrack_devices.devices")) == expected


def test_two_confirmations_with_same_prior_id_create_one_event(api):
    app, client = api
    base, a = owner(app, client)
    router = create(client, base, a)
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: confirm(client, router, a).status_code, range(2)))
    assert sorted(statuses) == [201, 409]
    assert (
        client.get(router + "/identifications", headers=a["headers"]).json()["page"]["total"] == 1
    )
