"""Workspace isolation, immutable CPE provenance and bounded operational pages."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.config import Settings
from app.db.workspace_context import workspace_session
from app.main import create_app
from app.services.cpe_catalog import UPSERT, normalize
from scripts.disposable_v2 import DisposableV2
from tests.integration.test_rc31_application_catalog import catalog_record
from tests.integration.test_v2_stabilization import account, api  # noqa: F401

pytestmark = pytest.mark.postgres


def setup_catalog(client, postgres, user):
    base = f"/api/v2/workspaces/{user['workspace']}/applications"
    app = client.post(base, headers=user["headers"], json={"name": "Provenance lab"})
    assert app.status_code == 201
    base += "/" + app.json()["id"]
    technology = client.post(
        base + "/technologies",
        headers=user["headers"],
        json={"vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"},
    )
    assert technology.status_code == 201
    tech = base + "/technologies/" + technology.json()["id"]
    official = catalog_record()
    fixture = normalize(json.loads(official["original"]), "fixture", None)
    cisco = catalog_record(vendor="cisco", product="firmware", part="o")
    with postgres.begin() as connection:
        connection.execute(UPSERT, [official, fixture, cisco])
    body = {
        "cpe_name_id": str(official["cpe_name_id"]),
        "mode": "live",
        "expected_cpe_name": official["cpe_name"],
        "expected_selected_cpe": None,
        "reason": "Comparado con la instalación",
        "evidence": "Versión declarada en laboratorio",
    }
    return base, tech, official, cisco, body


def history(client, tech, user, **params):
    response = client.get(tech + "/cpe-confirmations", headers=user["headers"], params=params)
    assert response.status_code == 200
    return response.json()


def test_provenance_modes_same_uuid_and_immutable_history(api, postgres):  # noqa: F811
    app, client = api
    user = account(client)
    base, tech, official, cisco, body = setup_catalog(client, postgres, user)
    assert history(client, tech, user)["items"] == []
    for changes, code in [
        (
            {
                "cpe_name_id": str(cisco["cpe_name_id"]),
                "part": "o",
                "expected_cpe_name": cisco["cpe_name"],
            },
            "CPE_PRODUCT_MISMATCH",
        ),
        ({"expected_cpe_name": cisco["cpe_name"]}, "CPE_SELECTION_CHANGED"),
        ({"cpe_name_id": str(uuid4()), "mode": "fixture"}, "CATALOG_CPE_NOT_FOUND"),
    ]:
        denied = client.put(tech + "/cpe", headers=user["headers"], json=body | changes)
        assert denied.status_code in (404, 409) and denied.json()["error"]["code"] == code
    assert history(client, tech, user)["items"] == []
    assert client.put(tech + "/cpe", headers=user["headers"], json=body).status_code == 200
    first = history(client, tech, user)["items"][0]
    assert first["mode"] == "live" and first["source"] == "nvd-feed"
    assert first["is_current"] and first["cpe_name_id"] == str(official["cpe_name_id"])
    assert first["observed_version"] == "2.4.49" and first["reason"] == body["reason"]
    assert first["catalog_evidence"]["record"]["source"] == "nvd-feed"
    stale = body | {"mode": "fixture", "expected_selected_cpe": official["cpe_name"]}
    assert client.put(tech + "/cpe", headers=user["headers"], json=stale).status_code == 409
    assert (
        client.put(
            tech + "/cpe",
            headers=user["headers"],
            json=stale | {"expected_confirmation_id": first["id"]},
        ).status_code
        == 200
    )
    latest = history(client, tech, user, limit=1)
    assert latest["page"]["total"] == 2 and latest["items"][0]["mode"] == "fixture"
    assert latest["items"][0]["source"] == "nvd-captured-fixture"
    old = history(client, tech, user, limit=1, offset=1)["items"][0]
    assert old == first | {"is_current": False}
    persisted = client.get(base + "/technologies", headers=user["headers"]).json()["items"][0]
    assert persisted["cpe_confirmation"]["id"] == latest["items"][0]["id"]
    with TestClient(create_app(app.state.settings)) as restarted:
        assert history(restarted, tech, user) == history(client, tech, user)
    for statement in (
        "UPDATE vulntrack_technology_cpe.confirmations SET reason='rewrite'",
        "DELETE FROM vulntrack_technology_cpe.confirmations",
    ):
        with pytest.raises(DBAPIError), postgres.begin() as connection:
            connection.execute(text(statement))
    with app.state.session_factory.begin() as session:
        assert (
            session.scalar(text("SELECT count(*) FROM vulntrack_technology_cpe.confirmations")) == 0
        )


def test_legacy_provenance_is_never_inferred(api, postgres):  # noqa: F811
    _, client = api
    user = account(client)
    base, tech, official, _, _ = setup_catalog(client, postgres, user)
    with postgres.begin() as connection:
        connection.execute(
            text("""UPDATE vulntrack.technologies SET selected_cpe=:cpe,
            confidence='user_confirmed' WHERE id=:id"""),
            {"cpe": official["cpe_name"], "id": UUID(tech.split("/")[-1])},
        )
    current = client.get(base + "/technologies", headers=user["headers"]).json()["items"][0]
    assert current["cpe_confirmation"] is None
    assert history(client, tech, user)["legacy_provenance"] == "not_recorded"


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_provenance_roles_and_cross_workspace_writes(api, postgres, role):  # noqa: F811
    app, client = api
    owner, actor, outsider = account(client), account(client), account(client)
    base, tech, _, _, body = setup_catalog(client, postgres, owner)
    with postgres.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role)
            VALUES (:workspace,:actor,:role)"""),
            {"workspace": owner["workspace"], "actor": actor["id"], "role": role},
        )
    assert history(client, tech, actor)["items"] == []
    result = client.put(tech + "/cpe", headers=actor["headers"], json=body)
    assert result.status_code == (404 if role == "viewer" else 200)
    assert client.get(tech + "/cpe-confirmations", headers=outsider["headers"]).status_code == 404
    foreign = tech.replace(owner["workspace"], actor["workspace"])
    assert client.put(foreign + "/cpe", headers=actor["headers"], json=body).status_code == 404
    assert (
        client.post(
            base + "/technologies",
            headers=outsider["headers"],
            json={"vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"},
        ).status_code
        == 404
    )
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(actor["id"]), UUID(actor["workspace"])
    ) as session:
        assert (
            session.scalar(text("SELECT count(*) FROM vulntrack_technology_cpe.confirmations")) == 0
        )
        with pytest.raises(DBAPIError) as denied, session.begin_nested():
            session.execute(
                text("""INSERT INTO vulntrack_technology_cpe.confirmations
                (id,workspace_id,application_id,technology_id,recorded_by,cpe_name_id,cpe_name,
                 mode,source,observed_product,observed_vendor,observed_version,catalog_evidence)
                VALUES (:id,:workspace,:application,:technology,:actor,:name_id,:cpe,
                    'live','nvd-feed','HTTP Server','Apache','2.4.49','{}')"""),
                {
                    "id": uuid4(),
                    "workspace": owner["workspace"],
                    "application": base.split("/")[-1],
                    "technology": tech.split("/")[-1],
                    "actor": actor["id"],
                    "name_id": body["cpe_name_id"],
                    "cpe": body["expected_cpe_name"],
                },
            )
        # A context that does not own the row cannot bind a technology or insert
        # foreign evidence. Both policy and snapshot guards fail closed.
        assert denied.value.orig.sqlstate in {"42501", "23514"}


def test_concurrent_same_string_confirmations_have_one_winner(api, postgres, monkeypatch):  # noqa: F811
    _, client = api
    user = account(client)
    _, tech, _, _, body = setup_catalog(client, postgres, user)
    import app.api.v2_nvd as module

    original = module.catalog_row
    barrier = Barrier(2)

    def delayed(*args, **kwargs):
        candidate = original(*args, **kwargs)
        barrier.wait(timeout=10)
        return candidate

    monkeypatch.setattr(module, "catalog_row", delayed)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda mode: (
                    client.put(
                        tech + "/cpe", headers=user["headers"], json=body | {"mode": mode}
                    ).status_code
                ),
                ("live", "fixture"),
            )
        )
    assert sorted(results) == [200, 409]
    assert history(client, tech, user)["page"]["total"] == 1


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_operational_pagination_totals_and_rls(api, postgres, role):  # noqa: F811
    _, client = api
    owner, actor, outsider = account(client), account(client), account(client)
    ws = owner["workspace"]
    base = f"/api/v2/workspaces/{ws}/applications"
    with postgres.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role)
            VALUES (:ws,:actor,:role)"""),
            {"ws": ws, "actor": actor["id"], "role": role},
        )
        ids = (
            connection.execute(
                text("""INSERT INTO vulntrack.applications
            (id,workspace_id,name,created_by) SELECT gen_random_uuid(),:ws,
                'Literal %_ '||n,:actor FROM generate_series(1,107) n RETURNING id"""),
                {"ws": ws, "actor": owner["id"]},
            )
            .scalars()
            .all()
        )
        connection.execute(
            text("""INSERT INTO vulntrack.technologies
            (id,workspace_id,application_id,product,version,detection_method,created_by,
             confidence,selected_cpe)
            SELECT gen_random_uuid(),:ws,:app,'Product '||n,'1.0','manual',:actor,
              'user_confirmed','cpe:2.3:a:lab:product:1.0:*:*:*:*:*:*:*'
            FROM generate_series(1,105) n"""),
            {"ws": ws, "app": ids[0], "actor": owner["id"]},
        )
    seen = []
    for offset in range(0, 120, 20):
        response = client.get(
            base, headers=actor["headers"], params={"limit": 20, "offset": offset}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == {"limit": 20, "offset": offset, "total": 107}
        seen.extend(row["id"] for row in data["items"])
    assert len(seen) == len(set(seen)) == 107
    assert (
        client.get(base, headers=actor["headers"], params={"q": "%_"}).json()["page"]["total"]
        == 107
    )
    assert (
        client.get(base, headers=actor["headers"], params={"q": "missing"}).json()["page"]["total"]
        == 0
    )
    assert client.get(base, headers=outsider["headers"]).status_code == 404
    assert client.get(base, headers=actor["headers"], params={"limit": 101}).status_code == 422
    assert client.get(base, headers=actor["headers"], params={"offset": -1}).status_code == 422
    detail = client.get(
        base, headers=actor["headers"], params={"application_id": str(ids[0])}
    ).json()
    assert detail["page"]["total"] == 1 and detail["items"][0]["id"] == str(ids[0])
    technologies = base + "/" + str(ids[0]) + "/technologies"
    pages = [
        client.get(
            technologies, headers=actor["headers"], params={"limit": 20, "offset": offset}
        ).json()
        for offset in (0, 20, 40, 60, 80, 100, 120)
    ]
    assert all(p["page"]["total"] == 105 and p["summary"]["confirmed_cpe"] == 105 for p in pages)
    assert len({t["id"] for p in pages for t in p["items"]}) == 105
    assert pages[-1]["items"] == []
    assert client.get(technologies, headers=outsider["headers"]).status_code == 404


def test_migration_from_rc31_preserves_legacy_rows_and_is_repeatable():
    with DisposableV2(
        "new", sql_checks=False, verification_revision="v2_0007_device_revisions"
    ) as old:
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=old.environment["TEST_APP_DATABASE_URL"],
            workspace_hmac_key=old.environment["WORKSPACE_HMAC_KEY"],
            token_secret=old.environment["TOKEN_SECRET"],
            registration_enabled=True,
            cve_worker_enabled=False,
        )
        with TestClient(create_app(settings)) as client:
            actor = account(client)
            base = f"/api/v2/workspaces/{actor['workspace']}/applications"
            result = client.post(base, headers=actor["headers"], json={"name": "Legacy"})
            base += "/" + result.json()["id"]
            technology = client.post(
                base + "/technologies",
                headers=actor["headers"],
                json={"product": "HTTP Server", "vendor": "Apache", "version": "2.4.49"},
            ).json()
        tables = json.loads(
            old.sql("""SELECT jsonb_agg(schemaname||'.'||tablename)
            FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')
              AND tablename<>'alembic_verification_version';""").stdout
        )

        def snapshot():
            return {
                table: old.sql(f"SELECT md5(to_jsonb(t)::text) FROM {table} t ORDER BY 1;").stdout
                for table in tables
            }

        before = snapshot()
        old.verification_migrate()
        assert snapshot() == before
        assert (
            old.sql("SELECT count(*) FROM vulntrack_technology_cpe.confirmations;").stdout.strip()
            == "0"
        )
        old.verification_migrate()
        assert snapshot() == before
        with TestClient(create_app(settings)) as restarted:
            saved = restarted.get(base + "/technologies", headers=actor["headers"]).json()
            assert saved["items"][0]["id"] == technology["id"]
            assert saved["items"][0]["cpe_confirmation"] is None
