"""MVP-B real PostgreSQL + real auth/API, upstream calls via explicit fixtures only."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.core.errors import APIError
from app.models.database_v1 import AnalysisRun as Run
from app.models.database_v1 import Finding
from app.schemas.analyses import AnalysisInput
from app.schemas.cpe import Confirm, NeedsReview
from app.services.cve_worker import CVEWorker, Interrupted
from tests.conftest import login
from tests.cpe_support import NAME_ID
from tests.cpe_support import client_for as cpe_client
from tests.cve_support import CPE, Clock, client_for, response_page

pytestmark = pytest.mark.postgres


@pytest.fixture
def b_api(db_app, users, payload):
    app, client = db_app
    headers = login(client, users)
    asset = client.post(
        "/api/v1/assets",
        json=payload.model_dump() | {"version": "1.0.0.33"},
        headers=headers | {"Idempotency-Key": str(uuid4())},
    ).json()
    asset_id = UUID(asset["id"])
    app.state.identifications.nvd = cpe_client()
    ident = app.state.identifications.record(
        users[0][0],
        asset_id,
        uuid4(),
        Confirm(
            state="confirmed",
            cpe_name_id=NAME_ID,
            component_kind="firmware",
            expected_current_id=None,
            reason="Confirmación humana de prueba",
        ),
    )
    clock = Clock()
    worker = CVEWorker(
        app.state.engine, app.state.session_factory, client_for(clock=clock), clock=clock
    )

    def wait(seconds, deadline):
        if worker.stop.is_set():
            raise Interrupted()
        if clock() + seconds >= deadline:
            raise APIError(503, "TIME_BUDGET_REACHED", "Presupuesto")
        clock.advance(seconds)

    worker._wait = wait
    app.state.analyses.worker_ready = lambda: True
    data = dict(
        app=app,
        client=client,
        headers=headers,
        asset_id=asset_id,
        ident_id=UUID(ident["id"]),
        worker=worker,
        clock=clock,
        actor=users[0][0],
    )
    yield data
    # End only this fixture's unprocessed intentions; no DELETE or shared reset.
    with app.state.session_factory.begin() as session:
        rows = session.scalars(
            select(Run).where(Run.asset_id == asset_id, Run.status.in_(["queued", "running"]))
        )
        for run in rows:
            if run.status == "queued":
                run.status = "running"
                run.started_at = session.scalar(select(func.clock_timestamp()))
                session.flush()
            worker._finish_row(session, run, "TEST_CLEANUP")
    app.state.engine.dispose()


def accept(b, key=None, ident=None):
    return b["client"].post(
        f"/api/v1/assets/{b['asset_id']}/analyses",
        json={"identification_id": str(ident or b["ident_id"])},
        headers=b["headers"] | {"Idempotency-Key": str(key or uuid4())},
    )


def read(b, accepted):
    return b["client"].get(accepted.headers["location"], headers=b["headers"]).json()


def work(b, accepted, raw=None, handler=None, page_size=None, max_pages=None):
    b["worker"].client = client_for(raw=raw, handler=handler, clock=b["clock"])
    if page_size:
        b["worker"].page_size = page_size
    if max_pages:
        b["worker"].max_pages = max_pages
    assert b["worker"].process_next()
    return read(b, accepted)


def findings(b, accepted):
    return b["client"].get(accepted.headers["location"] + "/findings", headers=b["headers"]).json()


def test_complete_http_vertical_two_users_review_and_stable_replay(b_api, users):
    b = b_api
    key = uuid4()
    accepted = accept(b, key)
    assert accepted.status_code == 202 and set(accepted.json()) == {"id", "accepted_at"}
    initial = read(b, accepted)
    assert initial["status"] == "queued" and initial["coverage"] is None
    assert initial["selected_cpe"] == CPE and initial["identification_id"] == str(b["ident_id"])
    assert "request_hash" not in initial and "idempotency_key" not in initial
    assert accept(b, key).json() == accepted.json()
    assert accept(b).json()["error"]["code"] == "ANALYSIS_IN_PROGRESS"
    row = work(b, accepted)
    assert row["status"] == "completed" and row["coverage"] == "complete"
    assert (
        row["total_results"],
        row["retrieved_count"],
        row["stored_count"],
        row["page_count"],
    ) == (1, 1, 1, 1)
    assert row["page_manifest"][0]["start_index"] == 0
    found = findings(b, accepted)
    assert found["page"]["total"] == 1 and found["coverage"] == "complete"
    finding = found["items"][0]
    assert finding["applicability"] == "undetermined"  # verified real AND evidence
    assert finding["evidence"]["initial_applicability"] == "undetermined"
    assert (
        len(finding["cvss"]) == 2 and finding["evidence"]["configurations"][0]["operator"] == "AND"
    )
    assert accept(b, key).json() == accepted.json()  # after finalization, before new-rate check
    assert accept(b).status_code == 429
    path = "/api/v1/findings/" + finding["id"]
    review = {
        "status": "reviewed",
        "applicability": "not_applicable",
        "expected_updated_at": finding["updated_at"],
        "reason": "Revisión documental del entorno",
        "evidence": "La plataforma requerida no está presente según inventario verificado",
    }
    bad = login(b["client"], users, 1)
    for p in [
        f"/api/v1/assets/{b['asset_id']}/analyses",
        accepted.headers["location"],
        accepted.headers["location"] + "/findings",
        path,
    ]:
        assert b["client"].get(p, headers=bad).status_code == 404
        assert b["client"].get(p).status_code == 401
    assert (
        b["client"]
        .post(
            f"/api/v1/assets/{b['asset_id']}/analyses",
            json={"identification_id": str(b["ident_id"])},
            headers=bad | {"Idempotency-Key": str(key)},
        )
        .status_code
        == 404
    )
    assert b["client"].patch(path, json=review, headers=bad).status_code == 404
    reviewed = b["client"].patch(path, json=review, headers=b["headers"])
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["reviewed_by"] == str(users[0][0])
    assert (
        reviewed.json()["evidence"] == finding["evidence"]
        and reviewed.json()["cvss"] == finding["cvss"]
    )
    assert (
        b["client"].patch(path, json=review, headers=b["headers"]).json()["error"]["code"]
        == "REVIEW_CONFLICT"
    )
    assert b["client"].get(path, headers=b["headers"]).json() == reviewed.json()
    history = (
        b["client"].get(f"/api/v1/assets/{b['asset_id']}/analyses", headers=b["headers"]).json()
    )
    assert history["page"]["total"] == 1 and history["items"][0]["id"] == accepted.json()["id"]


@pytest.mark.parametrize("raw", [response_page([]), response_page(simple=True)])
def test_valid_zero_or_simple_positive_is_complete(b_api, raw):
    b = b_api
    accepted = accept(b)
    row = work(b, accepted, raw=raw)
    assert row["status"] == "completed" and row["coverage"] == "complete"
    f = findings(b, accepted)["items"]
    if raw["totalResults"] == 0:
        assert f == [] and row["stored_count"] == 0
    else:
        assert f[0]["applicability"] == "potential"


def test_all_pages_are_requested_with_progress(b_api):
    b = b_api
    accepted = accept(b)
    seen = []

    def handler(req):
        index = int(req.url.params["startIndex"])
        seen.append(index)
        return httpx.Response(
            200,
            json=response_page([f"CVE-2026-{10000 + index}"], total=3, start=index, simple=True),
        )

    row = work(b, accepted, handler=handler, page_size=1)
    assert seen == [0, 1, 2] and row["coverage"] == "complete"
    assert row["retrieved_count"] == row["stored_count"] == 3 and row["page_count"] == 3
    result = (
        b["client"]
        .get(accepted.headers["location"] + "/findings?limit=1&offset=1", headers=b["headers"])
        .json()
    )
    assert result["page"] == {"limit": 1, "offset": 1, "total": 3} and len(result["items"]) == 1


@pytest.mark.parametrize(
    "scenario,code",
    [
        ("budget", "PAGE_BUDGET_REACHED"),
        ("duplicate", "DUPLICATE_CVE"),
        ("changed_total", "TOTAL_CHANGED"),
        ("error", "NVD_INVALID_RESPONSE"),
        ("timeout", "NVD_TIMEOUT"),
        ("quota", "NVD_THROTTLED"),
        ("changed_cve", "CVE_CHANGED"),
        ("order", "ORDER_CHANGED"),
    ],
)
def test_partial_never_complete_and_valid_pages_survive(b_api, scenario, code):
    b = b_api
    accepted = accept(b)
    seen = []

    def handler(req):
        index = int(req.url.params["startIndex"])
        seen.append(index)
        if index and scenario == "error":
            return httpx.Response(200, content=b"bad")
        if index and scenario == "timeout":
            raise httpx.ReadTimeout("private synthetic message")
        if index and scenario == "quota":
            return httpx.Response(429, headers={"Retry-After": "90"})
        id_ = (
            "CVE-2026-11000"
            if scenario in {"duplicate", "changed_cve"}
            else f"CVE-2026-{11000 + index}"
        )
        raw = response_page(
            [id_], total=5 if not index or scenario != "changed_total" else 4, start=index
        )
        if index and scenario == "changed_cve":
            raw["vulnerabilities"][0]["cve"]["lastModified"] = "2026-11-01T00:00:00.000"
        if index and scenario == "order":
            raw["vulnerabilities"][0]["cve"]["published"] = "2000-01-01T00:00:00.000"
        return httpx.Response(200, json=raw)

    row = work(
        b, accepted, handler=handler, page_size=1, max_pages=1 if scenario == "budget" else 5
    )
    assert row["status"] == "completed" and row["coverage"] == "partial"
    assert code in row["warning_codes"] and row["page_count"] >= 1
    assert len(findings(b, accepted)["items"]) == row["stored_count"] >= 1
    if scenario in {"duplicate", "changed_cve"}:
        assert row["stored_count"] == 1 and row["retrieved_count"] == 2
    if scenario == "quota":
        assert row["nvd_cooldown_until"] is not None
        assert len(seen) == 2 and b["worker"].client.quota.wait_seconds() >= 90
    if scenario == "timeout":
        assert row["retry_count"] == 2


@pytest.mark.parametrize(
    "scenario,code",
    [
        ("invalid", "NVD_INVALID_RESPONSE"),
        ("quota", "NVD_THROTTLED"),
        ("network", "NVD_UNAVAILABLE"),
        ("timeout", "NVD_TIMEOUT"),
    ],
)
def test_no_valid_page_is_failed_not_empty_complete(b_api, scenario, code):
    b = b_api
    accepted = accept(b)
    seen = []

    def handler(req):
        seen.append(req)
        if scenario == "quota":
            return httpx.Response(403)
        if scenario == "network":
            raise httpx.ConnectError("private")
        if scenario == "timeout":
            raise httpx.ReadTimeout("private")
        return httpx.Response(200, content=b"bad")

    row = work(b, accepted, handler=handler)
    assert row["status"] == "failed" and row["coverage"] is None and row["failure_code"] == code
    assert row["stored_count"] == row["page_count"] == 0 and findings(b, accepted)["items"] == []
    assert len(seen) == (3 if scenario in {"network", "timeout"} else 1)


def test_transient_retry_same_page_then_success(b_api):
    b = b_api
    accepted = accept(b)
    seen = []

    def handler(req):
        seen.append(req.url.params["startIndex"])
        return httpx.Response(503 if len(seen) == 1 else 200, json=response_page(simple=True))

    row = work(b, accepted, handler=handler)
    assert row["coverage"] == "complete" and row["retry_count"] == 1 and seen == ["0", "0"]


@pytest.mark.parametrize(
    "same_key,same_body,expected",
    [(True, True, [202, 202]), (False, True, [202, 409]), (True, False, [202, 409])],
)
def test_concurrent_acceptance_real_connections(b_api, same_key, same_body, expected):
    b = b_api
    barrier = Barrier(2)
    key = uuid4()

    def call(index):
        barrier.wait()
        try:
            result = b["app"].state.analyses.accept(
                b["actor"],
                b["asset_id"],
                key if same_key else uuid4(),
                AnalysisInput(
                    identification_id=b["ident_id"] if same_body or index == 0 else uuid4()
                ),
            )
            return 202, result.id
        except APIError as e:
            return e.status, e.code

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(call, [0, 1]))
    # A different invalid body may lose the race before any run exists; it still never writes.
    assert sorted(r[0] for r in results) == expected
    with b["app"].state.session_factory() as s:
        assert (
            s.scalar(select(func.count()).select_from(Run).where(Run.asset_id == b["asset_id"]))
            == 1
        )
    if same_key and same_body:
        assert results[0][1] == results[1][1]


def test_snapshot_survives_identification_change_and_replay(b_api):
    b = b_api
    key = uuid4()
    accepted = accept(b, key)
    new = b["app"].state.identifications.record(
        b["actor"],
        b["asset_id"],
        uuid4(),
        NeedsReview(
            state="needs_review", expected_current_id=b["ident_id"], reason="Revisión posterior"
        ),
    )
    assert new["id"] != str(b["ident_id"])
    assert accept(b, key).json() == accepted.json()
    assert accept(b).status_code == 409
    row = work(b, accepted)
    assert row["selected_cpe"] == CPE and row["identification_id"] == str(b["ident_id"])
    assert findings(b, accepted)["items"][0]["evidence"]["selected_cpe"] == CPE


@pytest.mark.parametrize("has_page", [False, True])
def test_crash_recovery_preserves_pages_and_does_not_requeue(b_api, has_page):
    b = b_api
    accepted = accept(b)
    id_ = UUID(accepted.json()["id"])
    with b["app"].state.session_factory.begin() as session:
        row = session.get(Run, id_)
        row.status = "running"
        row.started_at = session.scalar(select(func.clock_timestamp()))
    if has_page:
        page = client_for(raw=response_page(["CVE-2026-11000"], total=2)).page(CPE, 0, 1)
        b["worker"]._persist_page(id_, page, CPE, "1.0.0.33")
    recovered = CVEWorker(b["app"].state.engine, b["app"].state.session_factory, client_for())
    recovered.recover()
    row = read(b, accepted)
    assert row["status"] == ("completed" if has_page else "failed")
    assert (
        row["coverage"] == ("partial" if has_page else None)
        and row["failure_code"] == "INTERRUPTED"
    )
    assert row["stored_count"] == (1 if has_page else 0)
    completed_at = row["completed_at"]
    recovered.recover()
    assert read(b, accepted)["completed_at"] == completed_at


def test_page_rollback_never_completes_and_prior_page_remains(b_api):
    b = b_api
    accepted = accept(b)

    def fail(session, flush_context, instances):
        if any(isinstance(o, Finding) and o.external_id == "CVE-2026-11001" for o in session.new):
            raise RuntimeError("injected second page write failure")

    event.listen(b["app"].state.session_factory, "before_flush", fail)
    try:
        row = work(
            b,
            accepted,
            page_size=1,
            handler=lambda req: httpx.Response(
                200,
                json=response_page(
                    [f"CVE-2026-{11000 + int(req.url.params['startIndex'])}"],
                    total=2,
                    start=int(req.url.params["startIndex"]),
                ),
            ),
        )
    finally:
        event.remove(b["app"].state.session_factory, "before_flush", fail)
    assert row["coverage"] == "partial" and row["failure_code"] == "PROCESSING_ERROR"
    assert row["retrieved_count"] == row["stored_count"] == row["page_count"] == 1
    assert findings(b, accepted)["page"]["total"] == 1


def test_accept_rollback_is_atomic(b_api):
    b = b_api

    def fail(session, flush_context, instances):
        if any(isinstance(o, Run) for o in session.new):
            raise RuntimeError("injected accept failure")

    event.listen(b["app"].state.session_factory, "before_flush", fail)
    try:
        with pytest.raises(RuntimeError):
            b["app"].state.analyses.accept(
                b["actor"], b["asset_id"], uuid4(), AnalysisInput(identification_id=b["ident_id"])
            )
    finally:
        event.remove(b["app"].state.session_factory, "before_flush", fail)
    with b["app"].state.session_factory() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(Run).where(Run.asset_id == b["asset_id"])
            )
            == 0
        )


def test_review_stale_and_concurrent_is_single_transition(b_api):
    b = b_api
    accepted = accept(b)
    work(b, accepted)
    finding = findings(b, accepted)["items"][0]
    from app.schemas.analyses import ReviewInput

    body = ReviewInput(
        status="reviewed",
        applicability="potential",
        expected_updated_at=finding["updated_at"],
        reason="Revisado",
        evidence="Documento",
    )
    with pytest.raises(APIError):
        b["app"].state.analyses.review(
            b["actor"],
            UUID(finding["id"]),
            body.model_copy(
                update={"expected_updated_at": body.expected_updated_at - timedelta(seconds=1)}
            ),
        )
    barrier = Barrier(2)

    def review(index):
        barrier.wait()
        try:
            return b["app"].state.analyses.review(b["actor"], UUID(finding["id"]), body).status
        except APIError as e:
            return e.code

    with ThreadPoolExecutor(2) as pool:
        result = list(pool.map(review, [0, 1]))
    assert sorted(result) == ["REVIEW_CONFLICT", "reviewed"]


def test_new_key_after_failure_retains_historical_run(b_api, postgres):
    b = b_api
    first = accept(b)
    work(b, first, handler=lambda req: httpx.Response(400))
    # Simulate elapsed throttle time without sleeping or rewriting immutable run history.
    from app.services import analyses

    original = analyses.timedelta
    analyses.timedelta = lambda **kw: original(seconds=0)
    try:
        second = accept(b)
        assert second.status_code == 202
    finally:
        analyses.timedelta = original
    work(b, second)
    history = (
        b["client"].get(f"/api/v1/assets/{b['asset_id']}/analyses", headers=b["headers"]).json()
    )
    assert history["page"]["total"] == 2 and read(b, first)["status"] == "failed"
    assert read(b, second)["status"] == "completed"


def test_worker_disabled_rejects_new_but_allows_idempotent_replay(b_api):
    b = b_api
    key = uuid4()
    accepted = accept(b, key)
    b["app"].state.analyses.worker_ready = lambda: False
    assert accept(b, key).json() == accepted.json()
    assert accept(b).json()["error"]["code"] == "CVE_WORKER_UNAVAILABLE"


def test_mixed_missing_ids_and_validation_are_safe(b_api):
    b = b_api
    for p in [
        f"/api/v1/assets/{uuid4()}/analyses",
        f"/api/v1/assets/{b['asset_id']}/analyses/{uuid4()}",
        f"/api/v1/findings/{uuid4()}",
    ]:
        assert b["client"].get(p, headers=b["headers"]).status_code == 404
    path = f"/api/v1/assets/{b['asset_id']}/analyses"
    for body in [
        {},
        {"identification_id": str(b["ident_id"]), "url": "https://example.org"},
        {"identification_id": "bad"},
    ]:
        assert (
            b["client"]
            .post(path, json=body, headers=b["headers"] | {"Idempotency-Key": str(uuid4())})
            .status_code
            == 422
        )
    assert accept(b, ident=uuid4()).json()["error"]["code"] == "IDENTIFICATION_REQUIRED"
    assert b["client"].get(path + "?limit=101", headers=b["headers"]).status_code == 422


def test_inactive_owner_token_cannot_read_or_replay(b_api, postgres):
    b = b_api
    key = uuid4()
    accepted = accept(b, key)
    with postgres.begin() as c:
        c.execute(text("UPDATE vulntrack.users SET active=false WHERE id=:id"), {"id": b["actor"]})
    assert accept(b, key).status_code == 401
    assert b["client"].get(accepted.headers["location"], headers=b["headers"]).status_code == 401
    assert work(b, accepted)["error"]["code"] == "INVALID_CREDENTIALS"
    with b["app"].state.session_factory() as s:
        assert s.get(Run, UUID(accepted.json()["id"])).failure_code == "ACTOR_INACTIVE"


def test_runtime_privileges_immutable_history_and_referential_integrity(b_api, postgres):
    b = b_api
    accepted = accept(b)
    work(b, accepted)
    row = findings(b, accepted)["items"][0]
    for statement in [
        "UPDATE vulntrack.analysis_runs SET selected_cpe=selected_cpe WHERE id=:id",
        "UPDATE vulntrack.analysis_runs SET status=status WHERE id=:id",
        "DELETE FROM vulntrack.analysis_runs WHERE id=:id",
    ]:
        with pytest.raises(DBAPIError), b["app"].state.session_factory.begin() as s:
            s.execute(text(statement), {"id": accepted.json()["id"]})
    with pytest.raises(IntegrityError), postgres.begin() as c:
        c.execute(
            text("UPDATE vulntrack.findings SET evidence='{}'::jsonb WHERE id=:id"),
            {"id": row["id"]},
        )
    with pytest.raises(IntegrityError), postgres.begin() as c:
        c.execute(
            text("DELETE FROM vulntrack.asset_cpe_identifications WHERE id=:id"),
            {"id": b["ident_id"]},
        )


def test_stop_and_time_budget_defined(b_api):
    b = b_api
    accepted = accept(b)
    b["worker"].stop.set()
    row = work(b, accepted)
    assert row["status"] == "failed" and row["failure_code"] == "INTERRUPTED"


def test_evidence_budget_marks_undetermined_and_partial(b_api):
    b = b_api
    accepted = accept(b)
    raw = response_page(simple=True)
    raw["vulnerabilities"][0]["cve"]["descriptions"] = [{"lang": "en", "value": "x" * 70000}]
    row = work(b, accepted, raw=raw)
    assert row["coverage"] == "partial" and "EVIDENCE_BUDGET_REACHED" in row["warning_codes"]
    f = findings(b, accepted)["items"][0]
    assert f["applicability"] == "undetermined" and f["evidence"]["truncated"]


@pytest.mark.parametrize(
    "version,component,expected",
    [(None, "firmware", "VERSION_REQUIRED"), ("1.0.0.33", "hardware", "IDENTIFICATION_INCOMPLETE")],
)
def test_unknown_version_and_hardware_cannot_start_specific_evaluation(
    db_app, users, payload, version, component, expected
):
    from datetime import UTC, datetime

    from app.schemas.cpe import Candidate

    app, client = db_app
    headers = login(client, users)
    app.state.analyses.worker_ready = lambda: True
    asset = client.post(
        "/api/v1/assets",
        json=payload.model_dump() | {"version": version},
        headers=headers | {"Idempotency-Key": str(uuid4())},
    ).json()
    app.state.identifications.nvd = cpe_client()
    if component == "hardware":

        def resolve(actor, name):
            return Candidate(
                cpe_name_id=name,
                cpe_name=CPE.replace(":o:", ":h:"),
                title="Synthetic hardware",
                deprecated=False,
            ), datetime.now(UTC)

        app.state.identifications.nvd.resolve = resolve
    ident = app.state.identifications.record(
        users[0][0],
        UUID(asset["id"]),
        uuid4(),
        Confirm(
            state="confirmed",
            cpe_name_id=NAME_ID,
            component_kind=component,
            expected_current_id=None,
            reason="Selección de prueba",
        ),
    )
    response = client.post(
        f"/api/v1/assets/{asset['id']}/analyses",
        json={"identification_id": ident["id"]},
        headers=headers | {"Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 409 and response.json()["error"]["code"] == expected


def test_confirmed_value_forbidden_and_patch_cors(b_api):
    b = b_api
    accepted = accept(b)
    work(b, accepted)
    finding = findings(b, accepted)["items"][0]
    path = "/api/v1/findings/" + finding["id"]
    response = b["client"].patch(
        path,
        json={
            "status": "reviewed",
            "applicability": "confirmed",
            "expected_updated_at": finding["updated_at"],
            "reason": "No permitido",
            "evidence": "No permitido",
        },
        headers=b["headers"],
    )
    assert response.status_code == 422
    assert b["client"].get(path, headers=b["headers"]).json()["status"] == "open"


def test_idempotency_conflict_and_mixed_asset_run_paths(b_api, users, payload):
    b = b_api
    key = uuid4()
    accepted = accept(b, key)
    assert accept(b, key, ident=uuid4()).json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    other = (
        b["client"]
        .post(
            "/api/v1/assets",
            json=payload.model_dump(),
            headers=b["headers"] | {"Idempotency-Key": str(uuid4())},
        )
        .json()
    )
    path = f"/api/v1/assets/{other['id']}/analyses/{accepted.json()['id']}"
    assert b["client"].get(path, headers=b["headers"]).status_code == 404
    assert b["client"].get(path + "/findings", headers=b["headers"]).status_code == 404


def test_deadline_before_fetch_is_failed_and_no_upstream_call(b_api):
    b = b_api
    accepted = accept(b)
    b["worker"].max_seconds = 0.0001
    b["worker"].client.quota.next_call = b["clock"]() + 1
    seen = []
    b["worker"]._wait = lambda seconds, deadline: (_ for _ in ()).throw(
        APIError(503, "TIME_BUDGET_REACHED", "Presupuesto")
    )
    row = work(b, accepted, handler=lambda r: seen.append(r))
    assert row["status"] == "failed" and row["failure_code"] == "TIME_BUDGET_REACHED" and seen == []


def test_error_log_contains_codes_not_external_messages(b_api, caplog):
    b = b_api
    accepted = accept(b)

    def handler(req):
        raise httpx.ConnectError("PRIVATE-SYNTHETIC-SENTINEL")

    work(b, accepted, handler=handler)
    assert "PRIVATE-SYNTHETIC-SENTINEL" not in caplog.text
    assert "NVD_UNAVAILABLE" in caplog.text


def test_queued_is_recovered_by_actual_thread_and_second_worker_cannot_claim(b_api):
    import time

    b = b_api
    accepted = accept(b)
    worker = b["worker"]
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            row = read(b, accepted)
            if row["status"] == "completed":
                break
            time.sleep(0.02)
        assert row["coverage"] == "complete" and worker.available
        second = CVEWorker(b["app"].state.engine, b["app"].state.session_factory, client_for())
        second.start()
        second.thread.join(timeout=3)
        assert not second.available and not second.thread.is_alive()
        second.close()
    finally:
        worker.close()
    assert not worker.available


def test_real_process_crash_releases_lock_and_restart_recovers(b_api):
    """Kill only an allocated child process, whose database is runner-validated tmpfs."""
    import os
    import subprocess
    import sys
    import time

    b = b_api
    accepted = accept(b)
    source = r"""
import os,time
from sqlalchemy import create_engine,text
from app.services.cve_worker import LOCK_ID
engine=create_engine(os.environ['TEST_APP_DATABASE_URL'],hide_parameters=True)
with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as c:
 assert c.scalar(text('SELECT pg_try_advisory_lock(:key)'),{'key':LOCK_ID})
 c.execute(text("UPDATE vulntrack.analysis_runs SET status='running', "
     "started_at=clock_timestamp() WHERE id=:id"), {'id':os.environ['CRASH_TEST_RUN_ID']})
 print('RUNNING_LOCKED',flush=True)
 time.sleep(30)
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", source],
        env={**os.environ, "CRASH_TEST_RUN_ID": accepted.json()["id"]},
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        import select as io_select

        ready, _, _ = io_select.select([child.stdout], [], [], 5)
        assert ready and child.stdout.readline().strip() == "RUNNING_LOCKED"
        assert read(b, accepted)["status"] == "running"
        child.kill()
        child.wait(timeout=5)
        b["worker"].start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            row = read(b, accepted)
            if row["status"] == "failed":
                break
            time.sleep(0.02)
        assert row["status"] == "failed" and row["failure_code"] == "INTERRUPTED"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
        b["worker"].close()


def test_real_http_uvicorn_vertical_with_fixture_upstream(b_api, users):
    import json
    import socket
    import time
    import urllib.request
    from threading import Thread

    import uvicorn

    b = b_api
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            b["app"], host="127.0.0.1", port=port, log_level="critical", access_log=False
        )
    )
    thread = Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        base = f"http://127.0.0.1:{port}"

        def call(path, body=None, headers=None):
            req = urllib.request.Request(
                base + path,
                data=json.dumps(body).encode() if body is not None else None,
                headers={"Content-Type": "application/json", **(headers or {})},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.load(response), response.headers

        status, token, _ = call(
            "/api/v1/auth/login", {"username": "user_" + users[0][0].hex, "password": users[1]}
        )
        headers = {
            "Authorization": "Bearer " + token["access_token"],
            "Idempotency-Key": str(uuid4()),
        }
        status, accepted, response_headers = call(
            f"/api/v1/assets/{b['asset_id']}/analyses",
            {"identification_id": str(b["ident_id"])},
            headers,
        )
        assert status == 202
        assert b["worker"].process_next()
        _, row, _ = call(response_headers["Location"], headers=headers)
        _, found, _ = call(response_headers["Location"] + "/findings", headers=headers)
        assert row["coverage"] == "complete" and found["page"]["total"] == 1
        assert (
            call(
                f"/api/v1/assets/{b['asset_id']}/analyses",
                {"identification_id": str(b["ident_id"])},
                headers,
            )[1]
            == accepted
        )
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


def test_quota_cooldown_survives_worker_restart(b_api):
    b = b_api
    accepted = accept(b)
    row = work(b, accepted, handler=lambda req: httpx.Response(429, headers={"Retry-After": "600"}))
    assert row["failure_code"] == "NVD_THROTTLED" and row["nvd_cooldown_until"]
    new = CVEWorker(
        b["app"].state.engine, b["app"].state.session_factory, client_for(clock=b["clock"])
    )
    new.restore_cooldown()
    assert new.client.quota.wait_seconds() > 590
