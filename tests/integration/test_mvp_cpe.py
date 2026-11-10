import itertools
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError

from app.core.errors import APIError
from app.db.session import build_session_factory
from app.integrations.nvd import Quota
from app.models.cpe import CPEIdentification as Event
from app.schemas.cpe import Confirm
from tests.conftest import login
from tests.cpe_support import NAME_ID, RAW, client_for

pytestmark = pytest.mark.postgres
CONFIRM = {
    "state": "confirmed",
    "cpe_name_id": str(NAME_ID),
    "component_kind": "firmware",
    "expected_current_id": None,
    "reason": "Comparado con la versión del componente",
}


@pytest.fixture
def cpe_api(db_app, users, payload):
    app, client = db_app
    ticks = itertools.count(100, 8)
    app.state.nvd = client_for(quota=Quota(clock=lambda: next(ticks)))
    app.state.identifications.nvd = app.state.nvd
    headers = login(client, users)
    body = payload.model_dump() | {"version": "1.0.0.33"}
    created = client.post(
        "/api/v1/assets", json=body, headers=headers | {"Idempotency-Key": str(uuid4())}
    )
    assert created.status_code == 201, created.text
    path = f"/api/v1/assets/{created.json()['id']}/cpe-identifications"
    return app, client, headers, path


def post(client, path, headers, body=None, key=None):
    return client.post(
        path, json=body or CONFIRM, headers=headers | {"Idempotency-Key": str(key or uuid4())}
    )


def test_complete_http_vertical_and_replay_history(cpe_api, users):
    app, client, headers, path = cpe_api
    pending = client.get(path, headers=headers).json()
    assert pending["current_state"] == "pending" and pending["items"] == []
    candidates = client.get(
        "/api/v1/cpe-candidates", params={"query": "Cisco RV340"}, headers=headers
    )
    assert candidates.status_code == 200, candidates.text
    assert candidates.json()["items"][0]["cpe_name_id"] == str(NAME_ID)
    key = uuid4()
    first = post(client, path, headers, key=key)
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["observed_version"] == "1.0.0.33" and body["recorded_by"] == str(users[0][0])
    assert body["source"] == "NVD" and "request_hash" not in body
    assert "valid_to" not in body and "is_current" not in body
    assert first.headers["location"] == path and "no-store" in first.headers["cache-control"]

    def unavailable(*args):
        raise AssertionError("replay must not reach NVD")

    original = app.state.nvd.resolve
    app.state.nvd.resolve = unavailable
    assert post(client, path, headers, key=key).json() == body
    assert (
        post(client, path, headers, CONFIRM | {"reason": "different"}, key=key).status_code == 409
    )
    review = post(
        client,
        path,
        headers,
        {
            "state": "needs_review",
            "expected_current_id": body["id"],
            "reason": "Revisar identificación",
        },
    )
    assert review.status_code == 201, review.text
    assert review.json()["validated_at"] == body["validated_at"]
    assert (
        post(
            client,
            path,
            headers,
            {
                "state": "needs_review",
                "expected_current_id": review.json()["id"],
                "reason": "otra revisión",
            },
        ).status_code
        == 409
    )
    app.state.nvd.resolve = original
    third = post(client, path, headers, CONFIRM | {"expected_current_id": review.json()["id"]})
    assert third.status_code == 201, third.text
    history = client.get(path + "?scope=history", headers=headers).json()
    assert history["current_state"] == "confirmed"
    assert history["page"]["total"] == 3
    assert [e["state"] for e in history["items"]] == ["confirmed", "needs_review", "confirmed"]
    assert [e["is_current"] for e in history["items"]] == [False, False, True]
    assert history["items"][0]["valid_to"] == history["items"][1]["recorded_at"]
    assert history["items"][1]["valid_to"] == history["items"][2]["recorded_at"]
    assert history["items"][1]["replaces_id"] == body["id"]
    # Even after replacement, replay returns the original immutable event.
    app.state.nvd.resolve = unavailable
    assert post(client, path, headers, key=key).json() == body
    assert len(client.get(path, headers=headers).json()["items"]) == 1
    page = client.get(path + "?scope=history&limit=1&offset=1", headers=headers).json()
    assert len(page["items"]) == 1 and page["page"]["total"] == 3


def test_owner_and_authentication_before_nvd_and_replay(cpe_api, users):
    app, client, headers, path = cpe_api
    key = uuid4()
    assert post(client, path, headers, key=key).status_code == 201

    def forbidden(*args):
        raise AssertionError("unauthorized NVD call")

    app.state.nvd.resolve = forbidden
    foreign = login(client, users, index=1)
    for actor, status in [({}, 401), (foreign, 404)]:
        assert client.get(path, headers=actor).status_code == status
        assert client.get(path + "?scope=history", headers=actor).status_code == status
        assert post(client, path, actor, key=key).status_code == status
    assert post(client, f"/api/v1/assets/{uuid4()}/cpe-identifications", headers).status_code == 404
    legacy = "/api/v1/assets/10000000-0000-4000-8000-000000000001/cpe-identifications"
    assert client.get(legacy, headers=headers).status_code == 404
    assert post(client, legacy, headers).status_code == 404
    assert client.get("/api/v1/cpe-candidates", params={"query": "Cisco"}).status_code == 401


@pytest.mark.parametrize(
    "changes",
    [
        {"cpe_name_id": "malformed"},
        {"cpe_name": "cpe:2.3:o:forged"},
        {"recorded_by": str(uuid4())},
        {"valid_to": "2026-01-01T00:00:00Z"},
        {"component_kind": "router"},
        {"reason": " "},
        {"expected_current_id": "bad"},
    ],
)
def test_confirmation_rejects_client_internal_fields(cpe_api, changes):
    _, client, headers, path = cpe_api
    assert post(client, path, headers, CONFIRM | changes).status_code == 422


def test_missing_expected_and_invalid_transition(cpe_api):
    _, client, headers, path = cpe_api
    no_expected = {k: v for k, v in CONFIRM.items() if k != "expected_current_id"}
    assert post(client, path, headers, no_expected).status_code == 422
    assert (
        post(
            client,
            path,
            headers,
            {"state": "needs_review", "expected_current_id": None, "reason": "review"},
        ).status_code
        == 409
    )
    assert (
        post(
            client,
            path,
            headers,
            {
                "state": "needs_review",
                "expected_current_id": None,
                "reason": "review",
                "cpe_name_id": str(NAME_ID),
            },
        ).status_code
        == 422
    )
    assert (
        post(client, path, headers, CONFIRM | {"expected_current_id": str(uuid4())}).status_code
        == 409
    )
    for key in ["bad", uuid4().hex]:
        assert (
            client.post(path, json=CONFIRM, headers=headers | {"Idempotency-Key": key}).status_code
            == 422
        )


@pytest.mark.parametrize(
    "error,expected",
    [("empty", 409), ("deprecated", 409), ("malformed", 502), ("timeout", 504), ("failure", 503)],
)
def test_failed_external_confirmation_writes_nothing(cpe_api, error, expected, postgres):
    app, client, headers, path = cpe_api
    raw = deepcopy(RAW)
    if error == "empty":
        raw.update(products=[], totalResults=0, resultsPerPage=0)
    if error == "deprecated":
        raw["products"][0]["cpe"]["deprecated"] = True
    if error == "malformed":
        raw["products"][0]["cpe"]["cpeName"] = "cpe:2.3:o:bad"

    def handler(req):
        if error == "timeout":
            raise httpx.ReadTimeout("sensitive", request=req)
        if error == "failure":
            return httpx.Response(503, text="sensitive")
        return httpx.Response(200, json=raw)

    app.state.identifications.nvd = client_for(handler=handler)
    result = post(client, path, headers)
    assert result.status_code == expected, result.text
    assert "sensitive" not in result.text
    assert client.get(path, headers=headers).json()["items"] == []


def test_component_and_version_mismatch(cpe_api):
    app, client, headers, path = cpe_api
    assert (
        post(client, path, headers, CONFIRM | {"component_kind": "hardware"}).json()["error"][
            "code"
        ]
        == "CPE_COMPONENT_MISMATCH"
    )
    raw = deepcopy(RAW)
    raw["products"][0]["cpe"]["cpeName"] = raw["products"][0]["cpe"]["cpeName"].replace(
        "1.0.0.33", "9.9"
    )
    app.state.identifications.nvd = client_for(raw)
    result = post(client, path, headers)
    assert result.status_code == 409 and result.json()["error"]["code"] == "CPE_VERSION_MISMATCH"


@pytest.mark.parametrize("omit", [False, True])
def test_unknown_version_registration_confirmation_and_idempotency(cpe_api, payload, omit):
    _, client, headers, _ = cpe_api
    body = payload.model_dump() | {"version": None}
    if omit:
        body.pop("version")
    key = uuid4()
    asset = client.post(
        "/api/v1/assets", json=body, headers=headers | {"Idempotency-Key": str(key)}
    )
    assert asset.status_code == 201, asset.text
    assert asset.json()["version"] is None
    assert (
        client.post(
            "/api/v1/assets", json=body, headers=headers | {"Idempotency-Key": str(key)}
        ).json()
        == asset.json()
    )
    path = f"/api/v1/assets/{asset.json()['id']}/cpe-identifications"
    identified = post(client, path, headers)
    assert identified.status_code == 201, identified.text
    assert identified.json()["observed_version"] is None


def test_replacing_with_different_verified_cpe(cpe_api, payload):
    app, client, headers, _ = cpe_api
    body = payload.model_dump() | {"version": None}
    asset = client.post(
        "/api/v1/assets", json=body, headers=headers | {"Idempotency-Key": str(uuid4())}
    ).json()
    path = f"/api/v1/assets/{asset['id']}/cpe-identifications"
    first = post(client, path, headers).json()
    search = json.loads(
        (Path(__file__).parents[1] / "fixtures/nvd_cpe_alternative_verified.json").read_text()
    )
    candidate = next(p for p in search["products"] if UUID(p["cpe"]["cpeNameId"]) != NAME_ID)
    search.update(products=[candidate], resultsPerPage=1, startIndex=0, totalResults=1)
    app.state.identifications.nvd = client_for(search)
    second = post(
        client,
        path,
        headers,
        CONFIRM
        | {"expected_current_id": first["id"], "cpe_name_id": candidate["cpe"]["cpeNameId"]},
    )
    assert second.status_code == 201, second.text
    history = client.get(path + "?scope=history", headers=headers).json()["items"]
    assert len(history) == 2 and history[0]["cpe_name"] != history[1]["cpe_name"]
    assert history[0]["valid_to"] == history[1]["recorded_at"]


@pytest.mark.parametrize("same_key", [False, True, "conflict"])
def test_real_concurrent_confirmation(cpe_api, users, postgres, same_key):
    app, _, _, path = cpe_api
    service = app.state.identifications
    original = service.nvd.resolve
    barrier = Barrier(2)

    def resolve(actor, name_id):
        # Controlled clients isolate the transaction race from the quota.
        result = client_for().resolve(actor, name_id)
        barrier.wait(timeout=10)
        return result

    service.nvd.resolve = resolve
    asset_id = UUID(path.split("/")[4])
    key = uuid4()

    def attempt(index):
        try:
            return service.record(
                users[0][0],
                asset_id,
                key if same_key else uuid4(),
                Confirm(**(CONFIRM | {"reason": "race" if same_key is True else f"race {index}"})),
            )
        except APIError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    service.nvd.resolve = original
    if same_key is True:
        assert results[0] == results[1] and isinstance(results[0], dict)
    else:
        assert sum(isinstance(r, dict) for r in results) == 1
        assert (
            "IDEMPOTENCY_CONFLICT" if same_key == "conflict" else "CURRENT_IDENTIFICATION_CHANGED"
        ) in results
    with build_session_factory(postgres)() as session:
        rows = session.scalars(select(Event).where(Event.asset_id == asset_id)).all()
        assert len(rows) == 1 and rows[0].valid_to is None


def test_injected_insert_failure_rolls_back_previous_closure(cpe_api, users, postgres):
    app, client, headers, path = cpe_api
    first = post(client, path, headers).json()

    def fail(*args):
        raise RuntimeError("injected transaction failure")

    event.listen(Event, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            app.state.identifications.record(
                users[0][0],
                UUID(path.split("/")[4]),
                uuid4(),
                Confirm(**(CONFIRM | {"expected_current_id": first["id"]})),
            )
    finally:
        event.remove(Event, "before_insert", fail)
    current = client.get(path, headers=headers).json()["items"]
    assert len(current) == 1 and current[0]["id"] == first["id"] and current[0]["valid_to"] is None


def test_database_uniqueness_and_same_asset_history_fk(cpe_api, users, postgres):
    _, client, headers, path = cpe_api
    first = post(client, path, headers).json()
    with postgres.connect() as c:
        row = dict(
            c.execute(
                text("SELECT * FROM vulntrack.asset_cpe_identifications WHERE id=:id"),
                {"id": first["id"]},
            )
            .mappings()
            .one()
        )
    # Skip guards only inside a rolled back owner transaction to independently exercise constraints.
    for change, expected in [
        ({"id": uuid4(), "idempotency_key": uuid4()}, "23505"),
        (
            {
                "id": uuid4(),
                "replaces_id": uuid4(),
                "valid_to": first["recorded_at"],
                "idempotency_key": uuid4(),
            },
            "23503",
        ),
    ]:
        with pytest.raises(IntegrityError) as exc, postgres.begin() as c:
            c.execute(
                text(
                    "ALTER TABLE vulntrack.asset_cpe_identifications "
                    "DISABLE TRIGGER cpe_event_guard"
                )
            )
            c.execute(Event.__table__.insert().values(row | change))
        assert exc.value.orig.sqlstate == expected


def test_search_http_limits_validation_and_safe_errors(cpe_api):
    app, client, headers, _ = cpe_api
    for params in [
        {"query": "x"},
        {"query": "ab\x00cd"},
        {"query": "Cisco", "url": "https://evil.invalid"},
        {"query": "Cisco", "limit": 21},
        {"query": "Cisco", "offset": -1},
    ]:
        assert (
            client.get("/api/v1/cpe-candidates", params=params, headers=headers).status_code == 422
        )
    app.state.nvd = client_for()
    first = client.get("/api/v1/cpe-candidates", params={"query": "Cisco"}, headers=headers)
    assert first.status_code == 200
    second = client.get("/api/v1/cpe-candidates", params={"query": "Cisco"}, headers=headers)
    assert second.status_code == 429 and "retry-after" in second.headers
