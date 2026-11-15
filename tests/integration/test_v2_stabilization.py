"""Regress workspace bootstrap and original NVD fixtures on restricted V2 + real RLS."""

import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, text

from app.core.config import Settings
from app.main import create_app
from tests.cpe_support import NAME_ID
from tests.cpe_support import client_for as cpe_client
from tests.cve_support import RAW, response_page
from tests.cve_support import client_for as cve_client
from tests.integration.test_v2_registration import account

pytestmark = pytest.mark.postgres


@pytest.fixture
def api(postgres):
    if os.environ.get("TEST_V2_ENABLED") != "1":
        pytest.skip("Use scripts.test_v2_registration")
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=os.environ["TEST_APP_DATABASE_URL"],
        token_secret=secrets.token_urlsafe(48),
        workspace_hmac_key=os.environ["WORKSPACE_HMAC_KEY"],
        registration_enabled=True,
        registration_attempts_per_minute=10,
        registration_total_per_minute=100,
        cve_worker_enabled=False,
    )
    app = create_app(settings)
    app.state.nvd = cpe_client()
    app.state.cve = cve_client()
    with TestClient(app) as client:
        yield app, client


def technology(client, user):
    base = f"/api/v2/workspaces/{user['workspace']}/applications"
    result = client.post(base, json={"name": "Regresión V2"}, headers=user["headers"])
    assert result.status_code == 201
    base += "/" + result.json()["id"]
    result = client.post(
        base + "/technologies",
        json={
            "product": "small_business_rv340_firmware",
            "vendor": "cisco",
            "version": ("1.0.0.33"),
        },
        headers=user["headers"],
    )
    assert result.status_code == 201
    tech = base + "/technologies/" + result.json()["id"]
    result = client.put(
        tech + "/cpe",
        json={"cpe_name_id": str(NAME_ID), "expected_selected_cpe": None},
        headers=user["headers"],
    )
    assert result.status_code == 200
    return base, tech


def test_additional_workspace_idempotency_membership_and_isolation(api, postgres):
    _, client = api
    a, b = account(client), account(client)
    key = str(uuid4())
    headers = a["headers"] | {"Idempotency-Key": key}
    for _ in range(2):
        result = client.post("/api/v2/workspaces", json={"name": "Adicional"}, headers=headers)
        assert result.status_code == 201 and result.json() == {"id": key, "name": ("Adicional")}
    assert (
        client.post(
            "/api/v2/workspaces", json={"name": "Otra intención"}, headers=headers
        ).status_code
        == 409
    )
    directory = client.get("/api/v2/workspaces", headers=a["headers"]).json()["items"]
    assert {x["workspace_id"] for x in directory} == {key, a["workspace"]}
    assert all(x["role"] == "owner" for x in directory)
    assert client.get("/api/v2/workspaces/" + key, headers=b["headers"]).status_code == 404
    with postgres.connect() as db:
        assert (
            db.scalar(
                text("SELECT count(*) FROM vulntrack.workspace_members WHERE workspace_id=:id"),
                {"id": key},
            )
            == 1
        )
        assert (
            db.scalar(
                text(

                        "SELECT count(*) FROM vulntrack.audit_events WHERE "
                        "object_id=:id AND action='workspace.created'"

                ),
                {"id": key},
            )
            == 1
        )


def test_concurrent_workspace_creation_keeps_one_workspace_and_owner(api, postgres):
    app, client = api
    user = account(client)
    key = str(uuid4())
    barrier = Barrier(2)

    def sync(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO vulntrack.workspaces(id,name,created_by)"):
            barrier.wait(timeout=10)

    event.listen(app.state.engine, "before_cursor_execute", sync)

    def create(_):
        return client.post(
            "/api/v2/workspaces",
            json={"name": "Carrera"},
            headers=user["headers"] | {"Idempotency-Key": key},
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, range(2)))
    finally:
        event.remove(app.state.engine, "before_cursor_execute", sync)
    assert [r.status_code for r in results] == [201, 201]
    assert all(r.json()["id"] == key for r in results)
    with postgres.connect() as db:
        assert (
            db.scalar(text("SELECT count(*) FROM vulntrack.workspaces WHERE id=:id"), {"id": key})
            == 1
        )
        assert (
            db.scalar(
                text("SELECT count(*) FROM vulntrack.workspace_members WHERE workspace_id=:id"),
                {"id": key},
            )
            == 1
        )


@pytest.mark.parametrize("original_and", [True, False])
def test_original_cve_description_persists_without_bad_trailing_title(api, original_and):
    app, client = api
    if not original_and:
        app.state.cve = cve_client(raw=response_page(simple=True))
    user = account(client)
    base, tech = technology(client, user)
    result = client.post(
        tech + "/analyses", headers=user["headers"] | {"Idempotency-Key": str(uuid4())}
    )
    assert result.status_code == 201 and result.json()["status"] == "completed"
    assert "TITLE_TRUNCATED" in result.json()["warning_codes"]
    found = client.get(
        base + "/analyses/" + result.json()["id"] + "/findings", headers=user["headers"]
    ).json()
    assert found["page"]["total"] == 1
    finding = found["items"][0]
    assert finding["applicability"] == ("undetermined" if original_and else "potential")
    assert len(finding["title"]) <= 500 and finding["title"] == finding["title"].strip()
    assert finding["evidence"]["descriptions"] == RAW["vulnerabilities"][0]["cve"][("descriptions")]
    assert not finding["evidence"]["truncated"]
    evidence = finding["evidence"]
    reviewed = client.patch(
        base + "/findings/" + finding["id"],
        headers=user["headers"],
        json={"applicability": "undetermined", "expected_updated_at": finding["updated_at"]},
    )
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "reviewed"
    assert reviewed.json()["evidence"] == evidence
    stale = client.patch(
        base + "/findings/" + finding["id"],
        headers=user["headers"],
        json={"applicability": "potential", "expected_updated_at": finding["updated_at"]},
    )
    assert stale.status_code == 409
    other = account(client)
    assert (
        client.get(base + "/analyses/" + result.json()["id"], headers=other["headers"]).status_code
        == 404
    )
