"""Real auth -> production ownership policy -> PostgreSQL. No dependency/policy overrides."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.db.session import build_session_factory
from app.main import create_app
from app.models.database_v1 import Asset, RegistrationRequest, User
from app.services.assets import request_fingerprint
from tests.conftest import login

pytestmark = pytest.mark.postgres


def register(client, headers, payload, key=None, **changes):
    return client.post(
        "/api/v1/assets",
        headers=headers | {"Idempotency-Key": str(key or uuid4())},
        json=payload.model_dump() | changes,
    )


def owned_counts(engine, user_id):
    with engine.connect() as connection:
        return (
            connection.scalar(
                select(func.count()).select_from(Asset).where(Asset.created_by == user_id)
            ),
            connection.scalar(
                select(func.count())
                .select_from(RegistrationRequest)
                .where(RegistrationRequest.user_id == user_id)
            ),
        )


def test_authenticated_registration_sets_owner_and_rejects_manipulation(
    db_app, users, payload, postgres
):
    _, client = db_app
    headers = login(client, users)
    for owner in [str(users[0][0]), str(users[0][1]), None]:
        assert register(client, headers, payload, created_by=owner).status_code == 422
    assert owned_counts(postgres, users[0][0]) == (0, 0)
    response = register(client, headers, payload)
    assert response.status_code == 201
    body = response.json()
    assert "created_by" not in body  # ownership is internal; snapshot contract unchanged
    assert client.get(response.headers["location"], headers=headers).json() == body
    with postgres.connect() as connection:
        assert (
            connection.scalar(select(Asset.created_by).where(Asset.id == UUID(body["id"])))
            == users[0][0]
        )
    assert register(client, {}, payload).status_code == 401


def test_owner_filtered_pagination_and_totals(db_app, users, payload):
    app, client = db_app
    a, b = login(client, users), login(client, users, 1)
    expected_a = [register(client, a, payload).json() for _ in range(3)]
    expected_b = [register(client, b, payload).json() for _ in range(2)]
    statements = []

    def record(connection, cursor, statement, params, context, executemany):
        if "WITH visible AS" in statement:
            statements.append((statement, params))

    event.listen(app.state.engine, "before_cursor_execute", record)
    try:
        for headers, expected in [(a, expected_a), (b, expected_b)]:
            gathered = []
            for offset in range(len(expected) + 1):
                response = client.get(f"/api/v1/assets?limit=1&offset={offset}", headers=headers)
                assert response.status_code == 200
                page = response.json()
                assert page["page"] == {"limit": 1, "offset": offset, "total": len(expected)}
                gathered.extend(page["items"])
            assert gathered == sorted(expected, key=lambda item: (item["created_at"], item["id"]))
    finally:
        event.remove(app.state.engine, "before_cursor_execute", record)
    assert statements
    assert all("WHERE vulntrack.assets.created_by =" in sql for sql, _ in statements)
    assert all("created_by_1" in params for _, params in statements)
    # Identical inventory values did not cause cross-user visibility or counts.
    assert len({body["id"] for body in expected_a + expected_b}) == 5


def test_authenticated_idempotency_isolated_per_user(db_app, users, payload, postgres):
    _, client = db_app
    a, b = login(client, users), login(client, users, 1)
    key = uuid4()
    first = register(client, a, payload, key)
    again = register(client, a, payload, key)
    assert first.status_code == again.status_code == 201
    assert first.json() == again.json()
    assert first.headers["location"] == again.headers["location"]
    assert register(client, a, payload, key, version="different").status_code == 409
    other = register(client, b, payload, key)
    assert other.status_code == 201
    assert other.json()["id"] != first.json()["id"]
    assert client.get(first.headers["location"], headers=b).status_code == 404
    assert client.get(other.headers["location"], headers=a).status_code == 404
    assert register(client, b, payload, key).json() == other.json()
    assert owned_counts(postgres, users[0][0]) == (1, 1)
    assert owned_counts(postgres, users[0][1]) == (1, 1)


@pytest.mark.parametrize("same_key,changed_payload", [(True, False), (False, False), (True, True)])
def test_authenticated_concurrency(db_app, users, payload, postgres, same_key, changed_payload):
    _, client = db_app
    headers = login(client, users)
    keys = [uuid4(), uuid4()]
    if same_key:
        keys[1] = keys[0]
    barrier = Barrier(2)

    def synchronize(mapper, connection, target):
        if target.idempotency_key in keys:
            barrier.wait(timeout=10)

    event.listen(RegistrationRequest, "before_insert", synchronize)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    register,
                    client,
                    headers,
                    payload,
                    keys[index],
                    version="changed" if changed_payload and index else payload.version,
                )
                for index in range(2)
            ]
            results = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(RegistrationRequest, "before_insert", synchronize)
    if changed_payload:
        assert sorted(response.status_code for response in results) == [201, 409]
    else:
        assert [response.status_code for response in results] == [201, 201]
        if same_key:
            assert results[0].json() == results[1].json()
        else:
            assert results[0].json()["id"] != results[1].json()["id"]
    count = 1 if same_key else 2
    assert owned_counts(postgres, users[0][0]) == (count, count)
    with postgres.connect() as connection:
        owners = connection.execute(
            select(Asset.created_by, RegistrationRequest.user_id)
            .join(RegistrationRequest, RegistrationRequest.asset_id == Asset.id)
            .where(RegistrationRequest.user_id == users[0][0])
        ).all()
        assert owners == [(users[0][0], users[0][0])] * count
    winner = next(response for response in results if response.status_code == 201)
    winning_payload = payload.model_copy(update={"version": winner.json()["version"]})
    # Committed response can be discarded and safely recovered with the original key.
    winner_index = results.index(winner)
    assert register(client, headers, winning_payload, keys[winner_index]).json() == winner.json()


def test_api_failure_rolls_back_owner_and_idempotency(db_app, users, payload, postgres):
    _, client = db_app
    headers = login(client, users)
    key = uuid4()

    def fail(mapper, connection, target):
        if target.idempotency_key == key:
            raise RuntimeError("injected failure before commit")

    event.listen(RegistrationRequest, "before_insert", fail)
    try:
        response = register(client, headers, payload, key)
        assert response.status_code == 500
    finally:
        event.remove(RegistrationRequest, "before_insert", fail)
    assert owned_counts(postgres, users[0][0]) == (0, 0)
    assert register(client, headers, payload, key).status_code == 201
    assert owned_counts(postgres, users[0][0]) == (1, 1)


def test_owner_fk_and_restrict_delete(db_app, users, payload, postgres):
    app, _ = db_app
    with pytest.raises(IntegrityError) as invalid, app.state.session_factory.begin() as session:
        session.add(Asset(id=uuid4(), created_by=uuid4(), **payload.model_dump()))
    assert invalid.value.orig.diag.constraint_name == "assets_created_by_fkey"
    with app.state.session_factory.begin() as session:
        session.add(Asset(id=uuid4(), created_by=users[0][0], **payload.model_dump()))
    with pytest.raises(IntegrityError) as restricted, postgres.begin() as connection:
        connection.execute(text("DELETE FROM vulntrack.users WHERE id=:id"), {"id": users[0][0]})
    assert restricted.value.orig.diag.constraint_name == "assets_created_by_fkey"
    with app.state.engine.connect() as connection, pytest.raises(ProgrammingError):
        connection.execute(text("UPDATE vulntrack.assets SET created_by=NULL"))


def test_inactive_user_cannot_replay_or_read(db_app, users, payload, postgres):
    _, client = db_app
    headers = login(client, users)
    key = uuid4()
    result = register(client, headers, payload, key)
    assert result.status_code == 201
    with build_session_factory(postgres).begin() as session:
        session.get(User, users[0][0]).active = False
    assert register(client, headers, payload, key).status_code == 401
    assert client.get(result.headers["location"], headers=headers).status_code == 401
    assert client.get("/api/v1/assets", headers=headers).status_code == 401
    assert owned_counts(postgres, users[0][0]) == (1, 1)


def test_historical_idempotency_record_is_not_ownership(db_app, users, payload, postgres):
    _, client = db_app
    a, b = login(client, users), login(client, users, 1)
    key, asset_id = uuid4(), UUID("10000000-0000-4000-8000-000000000001")
    with build_session_factory(postgres).begin() as session:
        session.add(
            RegistrationRequest(
                user_id=users[0][0],
                idempotency_key=key,
                asset_id=asset_id,
                request_hash=request_fingerprint(payload),
                response_body={"id": str(asset_id)},
            )
        )
    for headers in [a, b]:
        assert client.get(f"/api/v1/assets/{asset_id}", headers=headers).status_code == 404
    assert register(client, a, payload, key).status_code == 404
    with postgres.connect() as connection:
        assert connection.scalar(select(Asset.created_by).where(Asset.id == asset_id)) is None
    assert owned_counts(postgres, users[0][0]) == (0, 1)


def test_expiration_does_not_grant_other_users_access(db_app, users, payload, postgres):
    _, client = db_app
    a, b = login(client, users), login(client, users, 1)
    key = uuid4()
    first = register(client, a, payload, key)
    with postgres.begin() as connection:
        connection.execute(
            text(
                "UPDATE vulntrack.asset_registration_requests SET "
                "created_at=statement_timestamp()-interval '2 days', "
                "expires_at=statement_timestamp()-interval '1 day' WHERE user_id=:id"
            ),
            {"id": users[0][0]},
        )
    expired = register(client, a, payload, key)
    assert expired.status_code == 409
    assert expired.json()["error"]["code"] == "IDEMPOTENCY_EXPIRED"
    assert client.get(first.headers["location"], headers=b).status_code == 404
    second = register(client, b, payload, key)
    assert second.status_code == 201
    assert second.json()["id"] != first.json()["id"]
    assert owned_counts(postgres, users[0][0]) == (1, 1)


def test_v11_readiness_rejects_unmigrated_v1(legacy_postgres, settings):
    settings = settings.model_copy(
        update={
            "database_url": SecretStr(
                legacy_postgres.url.set(username="backend_test_api").render_as_string(
                    hide_password=False
                )
            )
        }
    )
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        result = client.get("/ready")
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "DATABASE_SCHEMA_NOT_READY"
