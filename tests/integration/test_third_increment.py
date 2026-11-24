"""Read-only listing closure on disposable PostgreSQL with real roles and RLS."""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, text

from app.db.workspace_context import workspace_session
from tests.cve_support import client_for, response_page
from tests.integration.test_rc2_devices import confirm, create, owner
from tests.integration.test_rc3_device_revisions import edit
from tests.integration.test_v2_stabilization import account, api, technology  # noqa: F401

pytestmark = pytest.mark.postgres


def members(client, postgres, role):
    owner, member, outsider = account(client), account(client), account(client)
    with postgres.begin() as db:
        db.execute(
            text("""INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role)
            VALUES (:ws,:actor,:role)"""),
            {"ws": owner["workspace"], "actor": member["id"], "role": role},
        )
    return owner, member, outsider


def app_id(client, actor, name):
    path = f"/api/v2/workspaces/{actor['workspace']}/applications"
    result = client.post(path, headers=actor["headers"], json={"name": name})
    assert result.status_code == 201
    return result.json()["id"]


def seed_targets(postgres, actor, application, count=45):
    with postgres.begin() as db:
        db.execute(
            text("""INSERT INTO vulntrack.application_targets
            (id,workspace_id,application_id,url,label,authorization_status,
             authorization_expires_at,authorization_reference,created_by,created_at)
            SELECT gen_random_uuid(),:ws,:app,'https://example.com/'||n,
                'Literal %_ destino '||n,
                CASE WHEN n%3=0 THEN 'pending' ELSE 'approved' END,
                CASE WHEN n%3=0 THEN NULL WHEN n%3=1 THEN now()+interval '1 day'
                    ELSE now()-interval '1 day' END,
                'Declaración sintética de prueba',:actor,'2026-01-01T00:00:00Z'
            FROM generate_series(1,:count) n"""),
            {"ws": actor["workspace"], "app": application, "actor": actor["id"], "count": count},
        )


def get(client, path, actor, **params):
    response = client.get(path, headers=actor["headers"], params=params)
    assert response.status_code == 200, response.json()
    return response.json()


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_target_pages_summaries_filters_roles_and_unchanged_declarations(api, postgres, role):  # noqa: F811
    app, client = api
    actor, member, outsider = members(client, postgres, role)
    first, second = app_id(client, actor, "Primera"), app_id(client, actor, "Segunda")
    seed_targets(postgres, actor, first)
    seed_targets(postgres, actor, second, 75)
    base = f"/api/v2/workspaces/{actor['workspace']}"
    path = base + "/applications/" + first + "/targets"
    with postgres.connect() as db:
        before = (
            db.execute(
                text(
                    "SELECT md5(to_jsonb(t)::text) FROM vulntrack.application_targets t "
                    "WHERE workspace_id=:ws ORDER BY id"
                ),
                {"ws": actor["workspace"]},
            )
            .scalars()
            .all()
        )
    pages = [get(client, path, member, limit=20, offset=n) for n in (0, 20, 40, 60)]
    assert all(p["page"]["total"] == 45 for p in pages)
    assert len({t["id"] for p in pages for t in p["items"]}) == 45
    assert pages[-1]["items"] == []
    for state in ("pending", "approved", "expired"):
        data = get(client, path, member, limit=20, q="%_", authorization_status=state)
        assert data["page"]["total"] == 15
        assert all(t["authorization_status"] == state for t in data["items"])
        if state == "approved":
            assert all(
                t["analysis_readiness"]["authorization_state"] == "verification_pending"
                for t in data["items"]
            )
    assert get(client, path, member, q="%' OR true --")["page"]["total"] == 0
    assert get(client, path, member, q="missing")["items"] == []
    for params in (
        {"limit": 101},
        {"offset": -1},
        {"q": "x" * 161},
        {"authorization_status": "forged"},
    ):
        assert client.get(path, headers=member["headers"], params=params).status_code == 422
    all_targets = [
        get(client, base + "/targets", member, limit=20, offset=n) for n in range(0, 140, 20)
    ]
    assert all(p["page"]["total"] == 120 for p in all_targets)
    assert len({t["id"] for p in all_targets for t in p["items"]}) == 120
    apps = get(client, base + "/applications", member, application_id=first)["items"]
    assert apps[0]["target_summary"]["total"] == 45
    assert apps[0]["target_summary"]["approved"] == 15
    assert len(apps[0]["target_summary"]["items"]) == 2
    assert client.get(path, headers=outsider["headers"]).status_code == 404
    assert (
        client.get(
            path.replace(actor["workspace"], member["workspace"]), headers=member["headers"]
        ).status_code
        == 404
    )
    created = client.post(path, headers=member["headers"], json={"url": "https://example.com/new"})
    assert created.status_code == (404 if role == "viewer" else 201)
    with postgres.connect() as db:
        after = (
            db.execute(
                text(
                    "SELECT md5(to_jsonb(t)::text) FROM vulntrack.application_targets t "
                    "WHERE workspace_id=:ws AND url<>'https://example.com/new' ORDER BY id"
                ),
                {"ws": actor["workspace"]},
            )
            .scalars()
            .all()
        )
    assert after == before
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(member["id"]), UUID(member["workspace"])
    ) as session:
        assert session.scalar(text("SELECT count(*) FROM vulntrack.application_targets")) == 0


def dataset(app, client, postgres, actor):
    app.state.nvd_mode = "fixture"
    app.state.cve = client_for(
        raw=response_page([f"CVE-2026-{90000 + n}" for n in range(45)], simple=True)
    )
    base, tech = technology(client, actor, postgres)
    result = client.post(
        tech + "/analyses", headers=actor["headers"] | {"Idempotency-Key": str(uuid4())}
    )
    assert result.status_code == 201, result.json()
    run = result.json()["id"]
    findings = base + "/analyses/" + run + "/findings"
    first = get(client, findings, actor, limit=1)["items"][0]
    with postgres.begin() as db:
        db.execute(
            text("""INSERT INTO vulntrack.recommendations
            (id,workspace_id,finding_id,recommendation,status,created_by,created_at)
            SELECT gen_random_uuid(),:ws,:finding,'Medida sintética explícita '||n,
                CASE WHEN n%2=0 THEN 'pending' ELSE 'in_progress' END,:actor,
                '2026-01-01T00:00:00Z' FROM generate_series(1,24) n"""),
            {"ws": actor["workspace"], "finding": first["id"], "actor": actor["id"]},
        )
    return base, tech, run, findings, base + "/findings/" + first["id"] + "/recommendations"


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_findings_recommendations_historical_source_and_rls(api, postgres, role):  # noqa: F811
    app, client = api
    actor, member, outsider = members(client, postgres, role)
    base, tech, run, findings, recs = dataset(app, client, postgres, actor)
    pages = [get(client, findings, member, limit=20, offset=n) for n in (0, 20, 40, 60)]
    assert all(
        p["page"]["total"] == 45
        and p["analysis"]["id"] == run
        and p["analysis"]["nvd_mode"] == "fixture"
        for p in pages
    )
    assert len({f["id"] for p in pages for f in p["items"]}) == 45
    assert all(
        f["evidence"] and f["published_at"] and f["observed_at"] for p in pages for f in p["items"]
    )
    all_recs = [get(client, recs, member, limit=10, offset=n) for n in (0, 10, 20, 30)]
    assert all(p["page"]["total"] == 24 for p in all_recs)
    assert len({r["id"] for p in all_recs for r in p["items"]}) == 24
    assert get(client, recs, member, status="pending")["page"]["total"] == 12
    assert get(client, recs, member, status="fixed")["items"] == []
    for path in (findings, recs, base + "/analyses"):
        assert client.get(path, headers=outsider["headers"]).status_code == 404
        assert client.get(path, headers=member["headers"], params={"limit": 101}).status_code == 422
        assert client.get(path, headers=member["headers"], params={"offset": -1}).status_code == 422
    assert (
        client.get(recs, headers=member["headers"], params={"status": "' OR true --"}).status_code
        == 422
    )
    original = get(client, recs, member, limit=100)
    with postgres.begin() as db:
        db.execute(
            text(
                "UPDATE vulntrack.technologies SET version='2.0',product='Current label' "
                "WHERE id=:id"
            ),
            {"id": tech.split("/")[-1]},
        )
        db.execute(
            text("UPDATE vulntrack.applications SET status='archived' WHERE id=:id"),
            {"id": base.split("/")[-1]},
        )
    assert get(client, recs, member, limit=100) == original
    restored = get(client, base + "/analyses", member)["items"][0]
    assert (
        restored["version"] == "1.0.0.33"
        and restored["evaluated_technology"]["basis"] == "historical_cpe"
    )
    assert get(client, findings, member, limit=20)["items"] == pages[0]["items"]
    assert (
        client.post(
            recs, headers=member["headers"], json={"recommendation": "Intento sobre archivada"}
        ).status_code
        == 404
    )


def test_target_total_and_page_share_snapshot_under_concurrent_insert(api, postgres):  # noqa: F811
    app, client = api
    actor = account(client)
    application = app_id(client, actor, "Concurrencia")
    seed_targets(postgres, actor, application, 6)
    inserted = []

    def after(connection, cursor, statement, parameters, context, many):
        if (
            "WITH matches AS MATERIALIZED" in statement
            and "application_targets" in statement
            and not inserted
        ):
            inserted.append(True)
            with postgres.begin() as db:
                db.execute(
                    text("""INSERT INTO vulntrack.application_targets
                    (id,workspace_id,application_id,url,created_by)
                    VALUES (:id,:ws,:app,'https://example.com/concurrent',:actor)"""),
                    {
                        "id": uuid4(),
                        "ws": actor["workspace"],
                        "app": application,
                        "actor": actor["id"],
                    },
                )

    path = f"/api/v2/workspaces/{actor['workspace']}/applications/{application}/targets"
    event.listen(app.state.engine, "after_cursor_execute", after)
    try:
        page = get(client, path, actor, limit=5)
        assert inserted and page["page"]["total"] == 6 and len(page["items"]) == 5
    finally:
        event.remove(app.state.engine, "after_cursor_execute", after)
    assert get(client, path, actor)["page"]["total"] == 7
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda offset: get(client, path, actor, limit=4, offset=offset), (0, 4))
        )
    assert len({r["id"] for p in results for r in p["items"]}) == 7


def test_device_pages_and_recommendations_survive_firmware_change(api, postgres):  # noqa: F811
    app, client = api
    base, actor = owner(app, client)
    path = create(client, base, actor)
    app.state.cve = client_for(
        raw=response_page([f"CVE-2026-{95000 + n}" for n in range(45)], simple=True)
    )
    assert confirm(client, path, actor).status_code == 201
    response = client.post(
        path + "/analyses", headers=actor["headers"] | {"Idempotency-Key": str(uuid4())}
    )
    assert response.status_code == 201, response.json()
    run = response.json()
    findings = path + "/analyses/" + run["id"] + "/findings"
    pages = [get(client, findings, actor, limit=20, offset=n) for n in (0, 20, 40)]
    assert len({f["id"] for p in pages for f in p["items"]}) == 45
    recs = path + "/findings/" + pages[0]["items"][0]["id"] + "/recommendations"
    for n in range(3):
        assert (
            client.post(
                recs,
                headers=actor["headers"] | {"Idempotency-Key": str(uuid4())},
                json={"recommendation": f"Medida de laboratorio {n}"},
            ).status_code
            == 201
        )
    before = get(client, recs, actor, limit=1)
    assert before["page"]["total"] == 3
    changed = edit(client, actor, path, 1, version="1.0.1.16", confirm_sensitive=True)
    assert changed.status_code == 200
    assert get(client, recs, actor, limit=1) == before
    assert get(client, findings, actor, limit=20)["items"] == pages[0]["items"]
    saved = get(client, path + "/analyses/" + run["id"], actor)
    assert (
        saved["mode"] == "fixture"
        and saved["evaluated_technology"]["observed_version"] == "1.0.0.33"
    )
