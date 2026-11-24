"""5A real PostgreSQL/JWT/RLS with injected CVE transports, never live NVD."""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.api.v2_devices import analyze_device
from app.api.v2_nvd import analyze_technology
from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.main import create_app
from tests.cve_support import CPE, client_for, response_page
from tests.integration.test_rc2_devices import confirm, create, owner
from tests.integration.test_v2_stabilization import account, api  # noqa: F401

pytestmark = pytest.mark.postgres


def setup_case(app, client, postgres, kind):
    if kind == "devices":
        base, user = owner(app, client)
        path = create(client, base, user)
        assert confirm(client, path, user).status_code == 201
        return user, path, path
    user = account(client)
    base = f"/api/v2/workspaces/{user['workspace']}/applications"
    app_id = client.post(base, headers=user["headers"], json={"name": "Prueba 5A"}).json()["id"]
    base += "/" + app_id
    result = client.post(
        base + "/technologies",
        headers=user["headers"],
        json={"vendor": "cisco", "product": "small_business_rv340_firmware", "version": "1.0.0.33"},
    )
    assert result.status_code == 201
    tech = result.json()["id"]
    # Synthetic inventory confirmation only: do not seed the shared catalog.
    with postgres.begin() as db:
        db.execute(
            text(
                "UPDATE vulntrack.technologies SET selected_cpe=:cpe,confidence='user_confirmed' "
                "WHERE id=:id"
            ),
            {"id": tech, "cpe": CPE},
        )
        db.execute(
            text("""INSERT INTO vulntrack_technology_cpe.confirmations
            (id,workspace_id,application_id,technology_id,recorded_by,cpe_name_id,cpe_name,
             mode,source,observed_vendor,observed_product,observed_version,catalog_evidence)
            VALUES (:id,:w,:a,:t,:u,:name,:cpe,'fixture','nvd-captured-fixture',
                'cisco','small_business_rv340_firmware','1.0.0.33','{}')"""),
            {
                "id": uuid4(),
                "w": user["workspace"],
                "a": app_id,
                "t": tech,
                "u": user["id"],
                "name": uuid4(),
                "cpe": CPE,
            },
        )
    return user, base + "/technologies/" + tech, base


def post(client, user, path, key=None):
    return client.post(
        path + "/analyses", headers=user["headers"] | {"Idempotency-Key": key or str(uuid4())}
    )


def invoke(app, user, path, base, kind, key):
    request = SimpleNamespace(app=app)
    identity = SimpleNamespace(id=UUID(user["id"]))
    if kind == "devices":
        return analyze_device(
            UUID(user["workspace"]), UUID(path.rsplit("/", 1)[1]), identity, request, key
        )
    return analyze_technology(
        UUID(user["workspace"]),
        UUID(base.rsplit("/", 1)[1]),
        UUID(path.rsplit("/", 1)[1]),
        identity,
        request,
        key,
    )


@pytest.mark.parametrize("kind", ["applications", "devices"])
@pytest.mark.parametrize("source", ["fixture", "simulated"])
def test_snapshot_provenance_freshness_and_idempotence(api, postgres, monkeypatch, kind, source):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, kind)
    app.state.cve = client_for(raw=response_page())
    app.state.cve.source_kind = "fixture" if source == "fixture" else None
    key = str(uuid4())
    response = post(client, user, path, key)
    assert response.status_code == 201, response.json()
    result = response.json()
    assert result["provenance"]["cve_source"] == source
    assert result["provenance"]["cpe_mode"] == "fixture"
    assert result["provenance"]["identification_id"]
    assert result["provenance"]["observed_version"] == "1.0.0.33"
    assert result["assessment"] == {
        "execution": "completed",
        "coverage": "complete",
        "freshness": "fresh",
        "correspondence": "current",
        "requires_new_query": False,
        "expires_at": result["assessment"]["expires_at"],
        "freshness_policy_seconds": 86400,
    }
    assert post(client, user, path, key).json() == result
    assert (
        client.get(base + "/analyses/" + result["id"], headers=user["headers"]).json()["provenance"]
        == result["provenance"]
    )

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(UTC) + timedelta(days=2)

    monkeypatch.setattr("app.services.v2_cve_reliability.datetime", Future)
    stale = client.get(base + "/analyses/" + result["id"], headers=user["headers"]).json()
    assert stale["assessment"]["freshness"] == "stale"
    assert stale["assessment"]["correspondence"] == "current"
    assert stale["assessment"]["requires_new_query"]
    assert stale["provenance"] == result["provenance"]


@pytest.mark.parametrize("kind", ["applications", "devices"])
def test_late_response_and_restart_recover_once_without_findings(api, postgres, kind):  # noqa: F811
    app, client = api
    app.state.settings.cve_execution_seconds = 30
    user, path, base = setup_case(app, client, postgres, kind)
    entered, release = Event(), Event()
    actual = client_for()
    calls = []

    def delayed(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(45)
        return actual.page(*args, **kwargs)

    app.state.cve.page = delayed
    key = str(uuid4())
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(invoke, app, user, path, base, kind, key)
        try:
            assert entered.wait(10)
            duplicate = post(client, user, path, key)
            assert duplicate.status_code == 201
            runid = duplicate.json()["id"]
            assert duplicate.json()["status"] in {"queued", "running"}
            assert post(client, user, path).status_code == 409
            time.sleep(31)
            # Actual new FastAPI application, same database and token: no worker magic.
            restarted = create_app(app.state.settings)
            with TestClient(restarted) as second:
                recovered = second.get(base + "/analyses/" + runid, headers=user["headers"])
                assert recovered.status_code == 200, recovered.json()
                assert recovered.json()["status"] == "failed"
                assert recovered.json()["failure_code"] == "INTERRUPTED"
                assert recovered.json()["coverage"] is None
        finally:
            release.set()
        with pytest.raises(APIError) as error:
            pending.result(timeout=15)
        assert error.value.code == "ANALYSIS_INTERRUPTED"
    assert len(calls) == 1
    replay = post(client, user, path, key)
    assert replay.status_code == 201 and replay.json()["id"] == runid
    assert replay.json()["status"] == "failed"
    findings = client.get(base + "/analyses/" + runid + "/findings", headers=user["headers"])
    assert findings.json()["page"]["total"] == 0
    table = (
        "vulntrack.application_analysis_runs"
        if kind == "applications"
        else "vulntrack_devices.runs"
    )
    with postgres.connect() as db:
        state = db.execute(
            text(f"SELECT status,completed_at FROM {table} WHERE id=:id"), {"id": runid}
        ).one()
        assert state.status == "failed" and state.completed_at


@pytest.mark.parametrize("kind", ["applications", "devices"])
def test_technology_changed_during_response_keeps_evaluated_version(api, postgres, kind):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, kind)
    actual = client_for()

    def changed(*args, **kwargs):
        if kind == "applications":
            with postgres.begin() as db:
                db.execute(
                    text("UPDATE vulntrack.technologies SET version='2.0' WHERE id=:id"),
                    {"id": path.rsplit("/", 1)[1]},
                )
        else:
            response = client.patch(
                path,
                headers=user["headers"],
                json={
                    "expected_record_version": 1,
                    "confirm_sensitive": True,
                    "reason": "Cambio durante consulta simulada",
                    "version": "2.0",
                },
            )
            assert response.status_code == 200, response.json()
        return actual.page(*args, **kwargs)

    app.state.cve.page = changed
    response = post(client, user, path)
    assert response.status_code == 201, response.json()
    run = response.json()
    assert run["assessment"]["correspondence"] == "historical"
    assert run["assessment"]["freshness"] == "fresh"
    assert run["provenance"]["observed_version"] == "1.0.0.33"
    found = client.get(
        base + "/analyses/" + run["id"] + "/findings", headers=user["headers"]
    ).json()
    assert found["items"][0]["evidence"]["observed_version"] == "1.0.0.33"
    if kind == "applications":
        dashboard = client.get(
            f"/api/v2/workspaces/{user['workspace']}/nvd-dashboard/unknown", headers=user["headers"]
        )
        assert dashboard.status_code == 200, dashboard.json()
        recent = dashboard.json()["recent_analyses"][0]
        assert recent["version"] == "1.0.0.33"
        assert recent["assessment"]["correspondence"] == "historical"


@pytest.mark.parametrize("kind", ["applications", "devices"])
def test_no_external_retry_after_transport_error_and_immutable_context(api, postgres, kind):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, kind)
    calls = []

    def error(*args, **kwargs):
        calls.append(1)
        raise APIError(503, "NVD_UNAVAILABLE", "Simulado")

    app.state.cve.page = error
    key = str(uuid4())
    result = post(client, user, path, key)
    assert result.status_code == 503
    replay = post(client, user, path, key)
    assert replay.status_code == 201 and replay.json()["status"] == "failed"
    assert replay.json()["assessment"]["freshness"] == "unknown"
    assert len(calls) == 1
    table = (
        "vulntrack.application_analysis_runs"
        if kind == "applications"
        else "vulntrack_devices.runs"
    )
    for assignment in [
        "status='running'",
        "run_context='{}'::jsonb",
        "lease_expires_at=now()+interval '1 hour'",
    ]:
        with pytest.raises(DBAPIError), postgres.begin() as db:
            db.execute(
                text(f"UPDATE {table} SET {assignment} WHERE id=:id"), {"id": replay.json()["id"]}
            )
    with pytest.raises(DBAPIError), postgres.begin() as db:
        db.execute(text("SELECT vulntrack.recover_cve_runs()"))


@pytest.mark.parametrize("warning_count", [0, 20])
def test_recovery_signed_context_roles_and_legacy_partial_history(api, postgres, warning_count):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    runid = uuid4()
    tech = path.rsplit("/", 1)[1]
    with postgres.begin() as db:
        db.execute(
            text("""INSERT INTO vulntrack.application_analysis_runs
            (id,workspace_id,application_id,technology_id,initiated_by,selected_cpe,created_at,kind)
            VALUES (:id,:w,:a,:t,:u,:cpe,now()-interval '3 minutes','nvd_cve')"""),
            {
                "id": runid,
                "w": user["workspace"],
                "a": base.rsplit("/", 1)[1],
                "t": tech,
                "u": user["id"],
                "cpe": CPE,
            },
        )
        db.execute(
            text("""UPDATE vulntrack.application_analysis_runs SET status='running',
            started_at=now()-interval '3 minutes' WHERE id=:id"""),
            {"id": runid},
        )
        db.execute(
            text("""UPDATE vulntrack.application_analysis_runs SET page_count=1,
            retrieved_count=0,stored_count=0,next_index=0,total_results=10,
            warning_codes=CAST(:warnings AS jsonb) WHERE id=:id"""),
            {"id": runid, "warnings": json.dumps([f"WARNING_{n}" for n in range(warning_count)])},
        )
    other = account(client)
    assert client.get(base + "/analyses/" + str(runid), headers=other["headers"]).status_code == 404
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(other["id"]), UUID(other["workspace"])
    ) as session:
        session.execute(text("SELECT vulntrack.recover_cve_runs()"))
        assert (
            session.scalar(
                text("SELECT count(*) FROM vulntrack.application_analysis_runs WHERE id=:id"),
                {"id": runid},
            )
            == 0
        )
    with postgres.begin() as db:
        assert (
            db.scalar(
                text("SELECT status FROM vulntrack.application_analysis_runs WHERE id=:id"),
                {"id": runid},
            )
            == "running"
        )
        db.execute(
            text(
                "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                "VALUES (:w,:u,'viewer')"
            ),
            {"w": user["workspace"], "u": other["id"]},
        )
    user = {**other, "workspace": user["workspace"]}
    result = client.get(base + "/analyses/" + str(runid), headers=user["headers"])
    assert result.status_code == 200, result.json()
    assert result.json()["status"] == "completed" and result.json()["coverage"] == "partial"
    if warning_count:
        assert result.json()["warning_codes"] == [f"WARNING_{n}" for n in range(warning_count)]
        assert result.json()["failure_code"] == "INTERRUPTED"
    else:
        assert result.json()["warning_codes"] == ["INTERRUPTED"]
    assert result.json()["assessment"]["freshness"] == "unknown"
    assert result.json()["provenance"]["identification_id"] is None
    assert result.json()["provenance"]["cve_source"] == "unknown"
    assert post(client, user, path).status_code == 404
    with workspace_session(
        app.state.session_factory, app.state.settings, UUID(user["id"]), UUID(user["workspace"])
    ) as session:
        changed = session.execute(
            text("UPDATE vulntrack.application_analysis_runs SET status='running' WHERE id=:id"),
            {"id": runid},
        )
        assert changed.rowcount == 0


@pytest.mark.parametrize("kind", ["applications", "devices"])
def test_acceptance_rollback_never_calls_transport(api, postgres, kind):  # noqa: F811
    from sqlalchemy import event

    app, client = api
    user, path, _ = setup_case(app, client, postgres, kind)
    key = str(uuid4())
    calls = []
    app.state.cve.page = lambda *a, **kw: calls.append(1)

    def reject(connection, cursor, statement, parameters, context, many):
        if "INSERT INTO vulntrack.audit_events" in statement:
            raise RuntimeError("Simulated failure before acceptance commit")

    event.listen(app.state.engine, "before_cursor_execute", reject)
    try:
        response = post(client, user, path, key)
        assert response.status_code == 500
        assert "Simulated failure" not in response.text
    finally:
        event.remove(app.state.engine, "before_cursor_execute", reject)
    assert not calls
    table = (
        "vulntrack.application_analysis_runs"
        if kind == "applications"
        else "vulntrack_devices.runs"
    )
    with postgres.connect() as db:
        assert (
            db.scalar(text(f"SELECT count(*) FROM {table} WHERE request_key=:key"), {"key": key})
            == 0
        )


@pytest.mark.parametrize("role", ["owner", "editor", "viewer"])
def test_roles_read_same_provenance_without_cross_workspace_leak(api, postgres, role):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    app.state.cve = client_for()
    created = post(client, user, path)
    assert created.status_code == 201, created.json()
    other = account(client)
    assert (
        client.get(base + "/analyses/" + created.json()["id"], headers=other["headers"]).status_code
        == 404
    )
    if role == "owner":
        reader = user
    else:
        with postgres.begin() as db:
            db.execute(
                text(
                    "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                    "VALUES (:w,:u,:role)"
                ),
                {"w": user["workspace"], "u": other["id"], "role": role},
            )
        reader = other
    result = client.get(base + "/analyses/" + created.json()["id"], headers=reader["headers"])
    assert result.status_code == 200, result.json()
    assert result.json()["provenance"] == created.json()["provenance"]
    assert result.json()["assessment"] == created.json()["assessment"]
    if role == "viewer":
        assert post(client, reader, path).status_code == 404


def test_application_new_query_needs_current_confirmation_but_receipt_survives(api, postgres):  # noqa: F811
    app, client = api
    user, path, base = setup_case(app, client, postgres, "applications")
    key = str(uuid4())
    first = post(client, user, path, key)
    assert first.status_code == 201, first.json()
    tech = path.rsplit("/", 1)[1]
    with postgres.begin() as db:
        db.execute(
            text("UPDATE vulntrack.technologies SET version='2.0' WHERE id=:id"), {"id": tech}
        )
    receipt = post(client, user, path, key).json()
    assert receipt["assessment"]["correspondence"] == "historical"
    assert receipt | {"assessment": first.json()["assessment"]} == first.json()
    blocked = post(client, user, path)
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "CPE_VERSION_MISMATCH"
    with postgres.begin() as db:
        new_cpe = CPE.replace(":1.0.0.33:", ":2.0:")
        db.execute(
            text("UPDATE vulntrack.technologies SET selected_cpe=:cpe,vendor=NULL WHERE id=:id"),
            {"id": tech, "cpe": new_cpe},
        )
    blocked = post(client, user, path)
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "CPE_CONFIRMATION_REQUIRED"
    identification = uuid4()
    with postgres.begin() as db:
        db.execute(
            text("""INSERT INTO vulntrack_technology_cpe.confirmations
            (id,workspace_id,application_id,technology_id,recorded_by,cpe_name_id,cpe_name,
             mode,source,observed_vendor,observed_product,observed_version,catalog_evidence)
            VALUES (:id,:w,:a,:t,:u,:name,:cpe,'fixture','nvd-captured-fixture',
                NULL,'small_business_rv340_firmware','2.0','{}')"""),
            {
                "id": identification,
                "w": user["workspace"],
                "a": base.rsplit("/", 1)[1],
                "t": tech,
                "u": user["id"],
                "name": uuid4(),
                "cpe": new_cpe,
            },
        )
    # A distinct accepted query still obeys the transport's conservative quota.
    app.state.cve.quota.clock.advance(8)
    result = post(client, user, path)
    assert result.status_code == 201, result.json()
    assert result.json()["assessment"]["correspondence"] == "current"
    assert result.json()["provenance"]["identification_id"] == str(identification)
    assert result.json()["provenance"]["observed_version"] == "2.0"
