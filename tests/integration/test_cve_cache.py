"""5B: real PostgreSQL/JWT/RLS and counted offline CVE providers only."""

import hashlib
import time
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.main import create_app
from app.services.applicability import encoded
from tests.cve_support import RAW, client_for, response_page
from tests.integration.test_cve_reliability import post, setup_case
from tests.integration.test_v2_stabilization import account, api  # noqa: F401

pytestmark = pytest.mark.postgres


def provider(raw=None, *, source="fixture", namespace=None):
    raw = raw or RAW
    client = client_for(raw=raw)
    client.source_kind = source
    client.cache_namespace = namespace or "test:" + hashlib.sha256(encoded(raw)).hexdigest()
    calls = []
    original = client.page

    def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    client.page = counted
    return client, calls


def counts(postgres, workspace):
    with postgres.connect() as db:
        return (
            db.execute(
                text("""SELECT
            (SELECT count(*) FROM vulntrack_cve_cache.slots WHERE workspace_id=:w) AS slots,
            count(r.id) AS responses FROM vulntrack_cve_cache.responses r
            JOIN vulntrack_cve_cache.slots s ON s.id=r.slot_id WHERE s.workspace_id=:w"""),
                {"w": workspace},
            )
            .mappings()
            .one()
        )


@pytest.mark.parametrize("kind", ["applications", "devices"])
def test_miss_hit_and_new_api_keep_original_dates_without_provider_call(api, postgres, kind):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, kind)
    upstream, calls = provider()
    app.state.cve = upstream
    first = post(client, user, path)
    assert first.status_code == 201, first.json()
    first = first.json()
    assert first["storage"]["resolution"] == "provider"
    second = post(client, user, path)
    assert second.status_code == 201, second.json()
    second = second.json()
    assert second["id"] != first["id"]
    assert second["storage"]["resolution"] == "reused"
    assert second["storage"]["obtained_at"] == first["storage"]["obtained_at"]
    assert second["storage"]["expires_at"] == first["storage"]["expires_at"]
    assert (
        second["provenance"]["response_received_at"] == first["provenance"]["response_received_at"]
    )
    assert second["assessment"]["freshness"] == "fresh"
    assert second["provenance"]["cve_source"] == "fixture"
    assert len(calls) == 1
    assert dict(counts(postgres, user["workspace"])) == {"slots": 1, "responses": 1}
    assert "cache_response_id" not in second and "cache_usage" not in second

    restarted = create_app(app.state.settings)
    replacement, restarted_calls = provider()

    def offline(*args, **kwargs):
        restarted_calls.append(1)
        raise AssertionError("A persisted hit must not execute the provider")

    replacement.page = offline
    restarted.state.cve = replacement
    with TestClient(restarted) as other:
        third = post(other, user, path)
        assert third.status_code == 201, third.json()
        assert third.json()["storage"]["resolution"] == "reused"
        assert third.json()["storage"]["obtained_at"] == first["storage"]["obtained_at"]
        assert not restarted_calls
    history = client.get(base + "/analyses?limit=1", headers=user["headers"])
    assert history.status_code == 200
    assert history.json()["page"]["total"] == 3
    assert len(history.json()["items"]) == 1


@pytest.mark.parametrize("kind", ["applications", "devices"])
def test_expiration_failure_preserves_old_evidence_and_does_not_return_zero(api, postgres, kind):  # noqa: F811
    app, client = api
    app.state.settings.cve_cache_ttl_seconds = 1
    user, path, base = setup_case(app, client, postgres, kind)
    upstream, calls = provider()
    app.state.cve = upstream
    key = str(uuid4())
    first = post(client, user, path, key)
    assert first.status_code == 201, first.json()
    first = first.json()
    before = client.get(
        base + "/analyses/" + first["id"] + "/findings", headers=user["headers"]
    ).json()
    time.sleep(1.15)

    def unavailable(*args, **kwargs):
        calls.append(1)
        raise APIError(503, "NVD_UNAVAILABLE", "Proveedor de prueba sin conexión")

    upstream.page = unavailable
    failed_key = str(uuid4())
    result = post(client, user, path, failed_key)
    assert result.status_code == 503
    failed = post(client, user, path, failed_key).json()
    assert failed["status"] == "failed" and failed["coverage"] is None
    assert failed["storage"]["resolution"] == "failed"
    assert failed["storage"]["refresh_attempted"]
    assert failed["storage"]["obtained_at"] is None
    assert failed["assessment"]["freshness"] == "unknown"
    assert len(calls) == 2
    historical = client.get(base + "/analyses/" + first["id"], headers=user["headers"]).json()
    assert historical["assessment"]["freshness"] == "stale"
    assert historical["storage"] == first["storage"]
    assert historical["provenance"] == first["provenance"]
    after = client.get(
        base + "/analyses/" + first["id"] + "/findings", headers=user["headers"]
    ).json()
    assert after["items"] == before["items"]
    assert dict(counts(postgres, user["workspace"])) == {"slots": 1, "responses": 1}


@pytest.mark.parametrize("total", [0, 2])
def test_empty_complete_reuses_but_partial_never_satisfies_complete(api, postgres, total):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    raw = response_page([]) if total == 0 else response_page(["CVE-2026-5555"], total=2)
    if total:
        # Valid bounded partial page: server page budget100, more than100 source entries.
        raw = response_page([f"CVE-2026-{10000 + i}" for i in range(100)], total=101)
    upstream, calls = provider(raw, source="simulated")
    app.state.cve = upstream
    first = post(client, user, path)
    assert first.status_code == 201, first.json()
    assert first.json()["coverage"] == ("partial" if total else "complete")
    upstream.quota.clock.advance(8)
    second = post(client, user, path)
    assert second.status_code == 201, second.json()
    assert second.json()["storage"]["resolution"] == ("provider" if total else "reused")
    assert len(calls) == (2 if total else 1)
    if total:
        assert "PAGE_BUDGET_REACHED" in second.json()["warning_codes"]
    else:
        assert second.json()["stored_count"] == 0
        assert second.json()["assessment"]["freshness_policy_seconds"] == 3600


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_cache_rls_roles_and_immutable_public_bodies(api, postgres, role):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    upstream, calls = provider()
    app.state.cve = upstream
    result = post(client, user, path)
    assert result.status_code == 201, result.json()
    other = account(client)
    with postgres.connect() as db:
        body = db.scalar(
            text("""SELECT r.body FROM vulntrack_cve_cache.responses r
            JOIN vulntrack_cve_cache.slots s ON s.id=r.slot_id WHERE s.workspace_id=:w"""),
            {"w": user["workspace"]},
        )
    for private in (user["id"], user["workspace"], user["username"], "Prueba 5A"):
        assert private not in body
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(other["id"]), UUID(other["workspace"])
    ) as db:
        assert db.scalar(text("SELECT count(*) FROM vulntrack_cve_cache.responses")) == 0
        assert db.scalar(text("SELECT count(*) FROM vulntrack_cve_cache.slots")) == 0
    if role != "owner":
        with postgres.begin() as db:
            db.execute(
                text(
                    "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                    "VALUES (:w,:u,:role)"
                ),
                {"w": user["workspace"], "u": other["id"], "role": role},
            )
        reader = other
    else:
        reader = user
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(reader["id"]), UUID(user["workspace"])
    ) as db:
        assert db.scalar(text("SELECT count(*) FROM vulntrack_cve_cache.responses")) == 1
        if role == "viewer":
            changed = db.execute(
                text("UPDATE vulntrack_cve_cache.slots SET lease_token=NULL,lease_expires_at=NULL")
            )
            assert changed.rowcount == 0
    with (
        pytest.raises(DBAPIError),
        workspace_session(
            app.state.session_factory, app.state.settings, UUID(user["id"]), UUID(user["workspace"])
        ) as db,
    ):
        db.execute(text("UPDATE vulntrack_cve_cache.responses SET fetched_at=now()"))
    if role == "viewer":
        assert post(client, reader, path).status_code == 404
    assert len(calls) == 1


def second_device(app, client, user):
    from tests.integration.test_rc2_devices import confirm, create

    path = create(client, f"/api/v2/workspaces/{user['workspace']}/devices", user)
    assert confirm(client, path, user).status_code == 201
    return path


def test_identical_query_in_other_workspace_requires_its_own_provider_call(api, postgres):  # noqa: F811
    app, client = api
    a, path_a, _ = setup_case(app, client, postgres, "devices")
    b, path_b, _ = setup_case(app, client, postgres, "devices")
    upstream, calls = provider()
    app.state.cve = upstream
    assert post(client, a, path_a).json()["storage"]["resolution"] == "provider"
    upstream.quota.clock.advance(8)
    assert post(client, b, path_b).json()["storage"]["resolution"] == "provider"
    assert len(calls) == 2
    assert post(client, a, path_a).json()["storage"]["resolution"] == "reused"
    assert post(client, b, path_b).json()["storage"]["resolution"] == "reused"
    assert len(calls) == 2
    assert counts(postgres, a["workspace"])["responses"] == 1
    assert counts(postgres, b["workspace"])["responses"] == 1


def test_mode_namespace_and_live_gate_cannot_consume_fixture_evidence(api, postgres):  # noqa: F811
    from app.integrations.nvd_cve import CVEClient

    app, client = api
    user, path, _ = setup_case(app, client, postgres, "devices")
    upstream, calls = provider(namespace="scenario:mode")
    app.state.cve = upstream
    assert post(client, user, path).json()["provenance"]["cve_source"] == "fixture"
    upstream.source_kind = "simulated"
    upstream.quota.clock.advance(8)
    response = post(client, user, path)
    assert response.status_code == 201, response.json()
    assert response.json()["storage"]["resolution"] == "provider"
    assert response.json()["provenance"]["cve_source"] == "simulated"
    assert len(calls) == 2 and counts(postgres, user["workspace"])["slots"] == 2
    live = CVEClient(live=True, cache_namespace="scenario:mode")

    def forbidden(*a, **kw):
        raise AssertionError("Live provider must never execute")

    live.page = forbidden
    app.state.cve = live
    response = post(client, user, path)
    assert response.status_code == 503 and response.json()["error"]["code"] == "CVE_LIVE_DISABLED"
    assert counts(postgres, user["workspace"])["responses"] == 2


def test_capacity_refuses_growth_but_preserves_valid_hits(api, postgres):  # noqa: F811
    app, client = api
    app.state.settings.cve_cache_max_entries = 1
    user, path, _ = setup_case(app, client, postgres, "devices")
    first, calls = provider()
    app.state.cve = first
    assert post(client, user, path).status_code == 201
    different, other_calls = provider(namespace="scenario:other")
    app.state.cve = different
    failed = post(client, user, path)
    assert (
        failed.status_code == 503 and failed.json()["error"]["code"] == "CVE_CACHE_CAPACITY_REACHED"
    )
    assert not other_calls
    app.state.cve = first
    assert post(client, user, path).json()["storage"]["resolution"] == "reused"
    assert len(calls) == 1 and counts(postgres, user["workspace"])["responses"] == 1


def test_payload_capacity_and_malformed_provider_do_not_create_zero_evidence(api, postgres):  # noqa: F811
    from copy import deepcopy

    app, client = api
    user, path, _ = setup_case(app, client, postgres, "devices")
    app.state.settings.cve_cache_max_bytes = 1024
    upstream, calls = provider()
    app.state.cve = upstream
    result = post(client, user, path)
    assert result.status_code == 503 and len(calls) == 1
    assert counts(postgres, user["workspace"])["responses"] == 0
    raw = deepcopy(RAW)
    raw["vulnerabilities"][0]["cve"]["metrics"]["notes"] = "private"
    upstream, calls = provider(raw)
    app.state.cve = upstream
    result = post(client, user, path)
    assert result.status_code == 502 and result.json()["error"]["code"] == "NVD_INVALID_RESPONSE"
    assert counts(postgres, user["workspace"])["responses"] == 0


def test_partial_refresh_cannot_replace_complete_historical_version(api, postgres):  # noqa: F811
    app, client = api
    app.state.settings.cve_cache_ttl_seconds = 1
    user, path, _ = setup_case(app, client, postgres, "devices")
    upstream, calls = provider(source="simulated", namespace="scenario:complete-then-partial")
    app.state.cve = upstream
    first = post(client, user, path)
    assert first.status_code == 201, first.json()
    with postgres.connect() as db:
        original = db.scalar(
            text("SELECT current_response_id FROM vulntrack_cve_cache.slots WHERE workspace_id=:w"),
            {"w": user["workspace"]},
        )
    time.sleep(1.15)
    partial = client_for(
        raw=response_page([f"CVE-2026-{30000 + i}" for i in range(100)], total=101)
    )

    def replacement(*a, **kw):
        calls.append(1)
        return partial.page(*a, **kw)

    upstream.page = replacement
    second = post(client, user, path)
    assert second.status_code == 201, second.json()
    assert second.json()["coverage"] == "partial" and second.json()["storage"]["refresh_attempted"]
    with postgres.connect() as db:
        assert (
            db.scalar(
                text(
                    "SELECT current_response_id FROM vulntrack_cve_cache.slots "
                    "WHERE workspace_id=:w"
                ),
                {"w": user["workspace"]},
            )
            == original
        )
    assert counts(postgres, user["workspace"])["responses"] == 2 and len(calls) == 2
    historical = client.get(
        path + "/analyses/" + first.json()["id"], headers=user["headers"]
    ).json()
    assert historical["coverage"] == "complete" and historical["storage"] == first.json()["storage"]


def test_concurrent_requests_deduplicate_and_release_sql_connection(api, postgres):  # noqa: F811
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from tests.integration.test_cve_reliability import invoke

    app, client = api
    user, path, _ = setup_case(app, client, postgres, "devices")
    other = second_device(app, client, user)
    upstream, calls = provider()
    original = upstream.page
    entered, release = Event(), Event()

    def blocked(*a, **kw):
        entered.set()
        assert release.wait(8)
        return original(*a, **kw)

    upstream.page = blocked
    app.state.cve = upstream
    with ThreadPoolExecutor(max_workers=2) as pool:
        leader = pool.submit(invoke, app, user, path, path, "devices", str(uuid4()))
        assert entered.wait(4)
        assert app.state.engine.pool.checkedout() == 0
        try:
            with pytest.raises(APIError) as error:
                invoke(app, user, other, other, "devices", str(uuid4()))
            assert error.value.code == "CVE_CACHE_BUSY"
        finally:
            release.set()
        assert leader.result()["storage"]["resolution"] == "provider"
    assert post(client, user, other).json()["storage"]["resolution"] == "reused"
    assert len(calls) == 1 and dict(counts(postgres, user["workspace"])) == {
        "slots": 1,
        "responses": 1,
    }


def test_expired_leader_cannot_publish_over_recovered_response(api, postgres):  # noqa: F811
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from tests.integration.test_cve_reliability import invoke

    app, client = api
    app.state.settings.cve_cache_lease_seconds = 1
    user, path, _ = setup_case(app, client, postgres, "devices")
    other = second_device(app, client, user)
    upstream, calls = provider()
    original = upstream.page
    entered, release = Event(), Event()

    def blocked(*a, **kw):
        entered.set()
        assert release.wait(8)
        return original(*a, **kw)

    upstream.page = blocked
    app.state.cve = upstream
    with ThreadPoolExecutor(max_workers=2) as pool:
        old = pool.submit(invoke, app, user, path, path, "devices", str(uuid4()))
        assert entered.wait(4)
        time.sleep(1.15)
        replacement, new_calls = provider()
        app.state.cve = replacement
        try:
            recovered = post(client, user, other)
            assert recovered.status_code == 201, recovered.json()
        finally:
            release.set()
        with pytest.raises(APIError) as error:
            old.result()
        assert error.value.code == "CVE_CACHE_LEASE_EXPIRED"
    assert len(calls) == 1 and len(new_calls) == 1
    assert counts(postgres, user["workspace"])["responses"] == 1
    assert post(client, user, path).json()["storage"]["resolution"] == "reused"


def test_reconfirmation_reuses_public_data_but_never_copies_human_review(api, postgres):  # noqa: F811
    from tests.integration.test_rc2_devices import confirm

    app, client = api
    user, path, _ = setup_case(app, client, postgres, "devices")
    upstream, calls = provider()
    app.state.cve = upstream
    first = post(client, user, path).json()
    findings = client.get(
        path + "/analyses/" + first["id"] + "/findings", headers=user["headers"]
    ).json()["items"]
    finding = findings[0]
    review = client.patch(
        path + "/findings/" + finding["id"],
        headers=user["headers"],
        json={
            "applicability": "not_applicable",
            "reason": "Decisión humana solo de este contexto",
            "evidence": "Validación humana offline",
            "expected_updated_at": finding["updated_at"],
        },
    )
    assert review.status_code == 200, review.json()
    selection = confirm(client, path, user, first["identification_id"])
    assert selection.status_code == 201, selection.json()
    second = post(client, user, path)
    assert second.status_code == 201, second.json()
    assert second.json()["storage"]["resolution"] == "reused"
    assert second.json()["identification_id"] != first["identification_id"]
    new = client.get(
        path + "/analyses/" + second.json()["id"] + "/findings", headers=user["headers"]
    ).json()["items"][0]
    assert new["id"] != finding["id"] and new["applicability"] == "undetermined"
    historical = client.get(path + "/analyses/" + first["id"], headers=user["headers"]).json()
    assert historical["assessment"]["correspondence"] == "historical"
    old = client.get(
        path + "/analyses/" + first["id"] + "/findings", headers=user["headers"]
    ).json()["items"][0]
    assert old["applicability"] == "not_applicable"
    assert len(calls) == 1


def test_cpe_version_change_uses_distinct_key_and_preserves_old_observation(api, postgres):  # noqa: F811
    from tests.cve_support import CPE

    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    upstream, calls = provider(source="simulated", namespace="scenario:version-change")
    app.state.cve = upstream
    first = post(client, user, path).json()
    new_cpe = CPE.replace(":1.0.0.33:", ":2.0:")
    with postgres.begin() as db:
        db.execute(
            text("UPDATE vulntrack.technologies SET version='2.0',selected_cpe=:cpe WHERE id=:id"),
            {"id": path.rsplit("/", 1)[1], "cpe": new_cpe},
        )
        db.execute(
            text("""INSERT INTO vulntrack_technology_cpe.confirmations
        (id,workspace_id,application_id,technology_id,recorded_by,cpe_name_id,cpe_name,
         mode,source,observed_vendor,observed_product,observed_version,catalog_evidence)
        VALUES (:id,:w,:a,:t,:u,:name,:cpe,'fixture','nvd-captured-fixture',
            'cisco','small_business_rv340_firmware','2.0','{}')"""),
            {
                "id": uuid4(),
                "w": user["workspace"],
                "a": base.rsplit("/", 1)[1],
                "t": path.rsplit("/", 1)[1],
                "u": user["id"],
                "name": uuid4(),
                "cpe": new_cpe,
            },
        )
    upstream.quota.clock.advance(8)
    second = post(client, user, path)
    assert second.status_code == 201, second.json()
    assert second.json()["storage"]["resolution"] == "provider"
    assert second.json()["provenance"]["observed_version"] == "2.0"
    old = client.get(base + "/analyses/" + first["id"], headers=user["headers"]).json()
    assert old["assessment"]["correspondence"] == "historical"
    assert old["provenance"] == first["provenance"] and old["storage"] == first["storage"]
    assert len(calls) == 2 and counts(postgres, user["workspace"])["slots"] == 2


def test_private_transaction_failure_preserves_reusable_response(api, postgres):  # noqa: F811
    from sqlalchemy import event

    app, client = api
    user, path, _ = setup_case(app, client, postgres, "devices")
    upstream, calls = provider()
    app.state.cve = upstream

    def fail(connection, cursor, statement, parameters, context, executemany):
        if "INSERT INTO vulntrack_devices.findings" in statement:
            raise RuntimeError("Controlled private transaction failure after cache publication")

    event.listen(app.state.engine, "before_cursor_execute", fail)
    try:
        failed = post(client, user, path)
        assert failed.status_code == 503, failed.json()
    finally:
        event.remove(app.state.engine, "before_cursor_execute", fail)
    assert counts(postgres, user["workspace"])["responses"] == 1
    result = post(client, user, path)
    assert result.status_code == 201, result.json()
    assert result.json()["storage"]["resolution"] == "reused" and len(calls) == 1


def test_database_rejects_rewriting_linked_cache_identity(api, postgres):  # noqa: F811
    app, client = api
    user, path, _ = setup_case(app, client, postgres, "devices")
    upstream, _ = provider()
    app.state.cve = upstream
    result = post(client, user, path).json()
    for statement in [
        "UPDATE vulntrack_devices.runs SET cache_usage=NULL WHERE id=:id",
        "UPDATE vulntrack_devices.runs SET cache_response_id=NULL WHERE id=:id",
        "DELETE FROM vulntrack_cve_cache.responses WHERE id=(SELECT cache_response_id "
        "FROM vulntrack_devices.runs WHERE id=:id)",
    ]:
        with pytest.raises(DBAPIError), postgres.begin() as db:
            db.execute(text(statement), {"id": result["id"]})
