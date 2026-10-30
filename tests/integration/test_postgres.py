import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.core.errors import APIError
from app.db.session import build_session_factory
from app.db.verify_schema import verify_schema
from app.models.database_v1 import Asset, RegistrationRequest, User
from app.services.assets import AssetService
from app.services.authorization import AssetAuthorization
from tests.conftest import FixtureAuthorization, login

pytestmark = pytest.mark.postgres


def test_schema_and_alembic(postgres):
    with postgres.connect() as connection:
        assert verify_schema(connection)
    env = {**os.environ, "MIGRATION_DATABASE_URL": os.environ["TEST_DATABASE_URL"]}
    for args in [["upgrade", "head"], ["check"]]:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", *args], capture_output=True, text=True, env=env
        )
        assert result.returncode == 0, result.stdout + result.stderr
    with postgres.begin() as connection:
        connection.execute(text("ALTER TABLE vulntrack.assets ADD COLUMN unexpected text"))
        with pytest.raises(RuntimeError, match="Baseline bloqueado"):
            verify_schema(connection)
        connection.execute(text("ALTER TABLE vulntrack.assets DROP COLUMN unexpected"))


def test_readiness_and_auth(db_app, users, postgres):
    app, client = db_app
    assert client.get("/ready").status_code == 200
    headers = login(client, users)
    result = client.get("/api/v1/auth/me", headers=headers)
    assert result.status_code == 200
    assert result.json()["id"] == str(users[0][0])
    assert "password" not in result.text
    for username, password in [
        ("unknown", users[1]),
        ("user_" + users[0][0].hex, "wrong"),
        ("demo_operator", users[1]),
    ]:
        result = client.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert result.status_code == 401
    with build_session_factory(postgres).begin() as session:
        user = session.get(User, users[0][0])
        user.active = False
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    with build_session_factory(postgres).begin() as session:
        session.get(User, users[0][0]).active = True
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_runtime_role_minimum_privileges(db_app):
    app, _ = db_app
    with app.state.engine.connect() as connection:
        with pytest.raises(ProgrammingError):
            connection.execute(text("DELETE FROM vulntrack.assets"))
        connection.rollback()
        with pytest.raises(ProgrammingError):
            connection.execute(text("CREATE TABLE vulntrack.forbidden(id int)"))


def test_production_authorization_denies(db_app, users, payload):
    _, client = db_app
    headers = login(client, users)
    assert client.get("/api/v1/assets", headers=headers).status_code == 403
    assert client.get(f"/api/v1/assets/{uuid4()}", headers=headers).status_code == 404
    result = client.post(
        "/api/v1/assets",
        headers=headers | {"Idempotency-Key": str(uuid4())},
        json=payload.model_dump(),
    )
    assert result.status_code == 403


def test_api_service_with_explicit_fixture_scope(db_app, users, payload):
    # Only tests the independent routes/service under a synthetic scope, not a product policy.
    app, client = db_app
    app.state.assets = AssetService(app.state.session_factory, FixtureAuthorization(users[0][0]))
    headers = login(client, users)
    headers["Idempotency-Key"] = str(uuid4())
    result = client.post("/api/v1/assets", headers=headers, json=payload.model_dump())
    assert result.status_code == 201, result.text
    body = result.json()
    assert result.headers["location"] == "/api/v1/assets/" + body["id"]
    assert client.get(result.headers["location"], headers=headers).json() == body
    assert client.post("/api/v1/assets", headers=headers, json=payload.model_dump()).json() == body
    other_headers = login(client, users, index=1)
    assert client.get(result.headers["location"], headers=other_headers).status_code == 404
    assert client.get(f"/api/v1/assets/{uuid4()}", headers=headers).status_code == 404
    for query in ["limit=0", "limit=101", "offset=-1"]:
        assert client.get("/api/v1/assets?" + query, headers=headers).status_code == 422
    for key in ["invalid", "x" * 100, uuid4().hex]:
        assert (
            client.post(
                "/api/v1/assets",
                headers=headers | {"Idempotency-Key": key},
                json=payload.model_dump(),
            ).status_code
            == 422
        )
    invalid = payload.model_dump() | {"version": 1}
    assert client.post("/api/v1/assets", headers=headers, json=invalid).status_code == 422
    for offset, count in [(0, 1), (1, 0)]:
        page = client.get(f"/api/v1/assets?limit=1&offset={offset}", headers=headers)
        assert page.status_code == 200, page.text
        assert len(page.json()["items"]) == count
        assert page.json()["page"] == {"limit": 1, "offset": offset, "total": 1}


def test_concurrent_same_key(authorized_service, payload, postgres):
    service, user_id = authorized_service
    key = uuid4()
    barrier = Barrier(2)

    def before_insert(mapper, connection, target):
        if target.idempotency_key == key:
            barrier.wait(timeout=10)

    event.listen(RegistrationRequest, "before_insert", before_insert)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(service.register, user_id, key, payload) for _ in range(2)]
            bodies = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(RegistrationRequest, "before_insert", before_insert)
    assert bodies[0] == bodies[1]
    assert (
        service.register(user_id, key, payload) == bodies[0]
    )  # retry after committed response lost
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                select(func.count()).select_from(Asset).where(Asset.manufacturer == str(user_id))
            )
            == 1
        )
        assert (
            connection.scalar(
                select(func.count())
                .select_from(RegistrationRequest)
                .where(RegistrationRequest.user_id == user_id)
            )
            == 1
        )


def test_different_keys_and_conflict(authorized_service, payload):
    service, user_id = authorized_service
    keys = [uuid4(), uuid4()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(service.register, user_id, key, payload) for key in keys]
        bodies = [f.result(timeout=20) for f in futures]
    assert bodies[0]["id"] != bodies[1]["id"]
    with pytest.raises(APIError) as exc:
        service.register(user_id, keys[0], payload.model_copy(update={"version": "2"}))
    assert exc.value.status == 409


def test_rollback_and_recovery(authorized_service, payload, postgres):
    service, user_id = authorized_service
    key = uuid4()

    def fail(mapper, connection, target):
        if target.idempotency_key == key:
            raise RuntimeError("synthetic pre-commit failure")

    event.listen(RegistrationRequest, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="synthetic"):
            service.register(user_id, key, payload)
    finally:
        event.remove(RegistrationRequest, "before_insert", fail)
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                select(func.count()).select_from(Asset).where(Asset.manufacturer == str(user_id))
            )
            == 0
        )
    assert service.register(user_id, key, payload)["id"]


def test_expiry_and_revoked_scope(authorized_service, payload, postgres):
    service, user_id = authorized_service
    key = uuid4()
    body = service.register(user_id, key, payload)
    service.authorization = AssetAuthorization()
    with pytest.raises(APIError) as exc:
        service.register(user_id, key, payload)
    assert exc.value.status == 403
    service.authorization = FixtureAuthorization(user_id)
    with postgres.begin() as connection:
        connection.execute(
            text(
                "UPDATE vulntrack.asset_registration_requests SET "
                "created_at=statement_timestamp()-interval '2 days', "
                "expires_at=statement_timestamp()-interval '1 day' "
                "WHERE user_id=:id"
            ),
            {"id": user_id},
        )
    with pytest.raises(APIError) as exc:
        service.register(user_id, key, payload)
    assert exc.value.code == "IDEMPOTENCY_EXPIRED"
    assert service.get(user_id, __import__("uuid").UUID(body["id"])).id


def test_referential_integrity(db_app, payload):
    app, _ = db_app
    with pytest.raises(IntegrityError), app.state.session_factory.begin() as session:
        session.add(
            RegistrationRequest(
                user_id=uuid4(),
                idempotency_key=uuid4(),
                request_hash="a" * 64,
                asset_id=uuid4(),
                response_body={"id": str(uuid4())},
            )
        )


def test_same_key_is_scoped_per_user(db_app, users, payload):
    app, _ = db_app
    key = uuid4()
    bodies = []
    for user_id in users[0]:
        service = AssetService(app.state.session_factory, FixtureAuthorization(user_id))
        bodies.append(
            service.register(
                user_id, key, payload.model_copy(update={"manufacturer": str(user_id)})
            )
        )
    assert bodies[0]["id"] != bodies[1]["id"]


def test_pool_exhaustion_is_bounded(db_app, settings):
    from sqlalchemy.exc import TimeoutError

    from app.db.session import build_engine

    app, _ = db_app
    small = app.state.settings.model_copy(
        update={
            "db_pool_size": 1,
            "db_max_overflow": 0,
            "db_pool_timeout": 1,
        }
    )
    engine = build_engine(small)
    try:
        with engine.connect(), pytest.raises(TimeoutError):
            with engine.connect():
                pytest.fail("Pool no limitado")
    finally:
        engine.dispose()
