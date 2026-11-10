import os
import secrets
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.core.config import Settings
from app.core.security import hash_password
from app.db.session import build_session_factory
from app.main import create_app
from app.models.database_v1 import User


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        environment="test",
        cve_worker_enabled=False,
        database_url="postgresql+psycopg://test_api@127.0.0.1:1/vulntrack_backend_test",
        token_secret=secrets.token_urlsafe(48),
        db_connect_timeout=1,
    )


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


@pytest.fixture(scope="session")
def postgres():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("PostgreSQL desechable no configurado; usar scripts/test_postgres.py")
    if make_url(url).database != "vulntrack_backend_test" or not os.environ.get(
        "TEST_DISPOSABLE_DATABASE", ""
    ).startswith("vulntrack-backend-test-"):
        pytest.fail("Solo se permiten bases desechables creadas por el runner")
    engine = create_engine(url, hide_parameters=True)
    yield engine
    engine.dispose()


@pytest.fixture
def db_app(postgres, settings):
    settings = settings.model_copy(
        update={
            "database_url": __import__("pydantic").SecretStr(os.environ["TEST_APP_DATABASE_URL"])
        }
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield app, client


@pytest.fixture
def users(postgres):
    factory = build_session_factory(postgres)
    password = secrets.token_urlsafe(24)
    ids = [uuid4(), uuid4()]
    with factory.begin() as session:
        session.add_all(
            [
                User(
                    id=id_,
                    username="user_" + id_.hex,
                    active=True,
                    password_hash=hash_password(password),
                )
                for id_ in ids
            ]
        )
    return ids, password


@pytest.fixture
def authorized_service(db_app, users):
    app, _ = db_app
    user_id = users[0][0]
    return app.state.assets, user_id


@pytest.fixture
def payload(users):
    from app.schemas.assets import AssetCreate

    return AssetCreate(
        device_type="router",
        manufacturer="Example brand",
        model="Example",
        version="1.0",
        site_label="LAB",
    )


def login(client, users, index=0):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "user_" + users[0][index].hex,
            "password": users[1],
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


@pytest.fixture
def legacy_postgres(postgres):
    name = "vulntrack_backend_test_migration_" + uuid4().hex
    # postgres fixture has validated runner identity and DB name before we reach this point.
    with postgres.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.execute(text(f'CREATE DATABASE "{name}" TEMPLATE "vulntrack_backend_test_v1"'))
    engine = create_engine(postgres.url.set(database=name), hide_parameters=True)
    yield engine
    engine.dispose()  # Data lives only in the runner's tmpfs; no persistent DBs are touched.


@pytest.fixture(autouse=True)
def forbid_uncontrolled_http(monkeypatch):
    import httpx

    def blocked(*args, **kwargs):
        raise AssertionError("Pruebas sin red: usar MockTransport con fixture NVD")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", blocked)
