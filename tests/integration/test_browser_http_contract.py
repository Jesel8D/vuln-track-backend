"""Browser/native HTTP contracts with real JWT, ownership and disposable PostgreSQL."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select

from app.api.router import Token, UserRead
from app.core.config import Settings
from app.db.session import build_session_factory
from app.main import create_app
from app.models.database_v1 import Asset, RegistrationRequest, User
from app.schemas.assets import AssetList, AssetRead
from tests.integration.test_client_contract import BODY

pytestmark = pytest.mark.postgres
ORIGIN = "http://localhost:5173"


@pytest.fixture
def browser_db_app(postgres, settings):
    values = settings.model_dump() | {
        "database_url": os.environ["TEST_APP_DATABASE_URL"],
        "cors_origins": [ORIGIN],
    }
    app = create_app(Settings(_env_file=None, **values))
    with TestClient(app) as client:
        yield app, client


def assert_browser_response(response):
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "Origin" in response.headers["vary"]
    assert "access-control-allow-credentials" not in response.headers
    exposed = {
        value.strip().lower()
        for value in response.headers["access-control-expose-headers"].split(",")
    }
    assert {"location", "x-request-id", "retry-after", "www-authenticate"} <= exposed
    assert "no-store" in response.headers["cache-control"]
    assert response.headers["content-type"] == "application/json"
    UUID(response.headers["x-request-id"])


def browser_login(client, users, index=0):
    result = client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN},
        json={
            "username": "user_" + users[0][index].hex,
            "password": users[1],
        },
    )
    assert result.status_code == 200
    assert_browser_response(result)
    token = Token.model_validate(result.json())
    return {"Origin": ORIGIN, "Authorization": "Bearer " + token.access_token}


def test_full_browser_contract_does_not_leak_across_users(browser_db_app, users, postgres):
    _, client = browser_db_app
    for path, method in [("/api/v1/auth/login", "POST"), ("/api/v1/assets", "POST")]:
        preflight = client.options(
            path,
            headers={
                "Origin": ORIGIN,
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "authorization,content-type,idempotency-key",
            },
        )
        assert preflight.status_code == 200 and preflight.json() == {"status": "ok"}
    a, b = browser_login(client, users), browser_login(client, users, 1)
    me = client.get("/api/v1/auth/me", headers=a)
    assert UserRead.model_validate(me.json()).id == users[0][0]
    assert_browser_response(me)
    key = str(uuid4())
    headers = a | {"Idempotency-Key": key}
    created = client.post("/api/v1/assets", headers=headers, json=BODY)
    assert created.status_code == 201
    assert_browser_response(created)
    asset = AssetRead.model_validate(created.json())
    assert set(created.json()) == set(AssetRead.model_fields)
    assert created.headers["location"] == f"/api/v1/assets/{asset.id}"
    replay = client.post("/api/v1/assets", headers=headers, json=BODY)
    assert replay.status_code == 201 and replay.json() == created.json()
    assert replay.headers["location"] == created.headers["location"]
    assert_browser_response(replay)
    own = client.get(created.headers["location"], headers=a)
    assert own.status_code == 200 and own.json() == created.json()
    assert_browser_response(own)
    conflict = client.post("/api/v1/assets", headers=headers, json=BODY | {"version": "2"})
    assert conflict.status_code == 409
    assert_browser_response(conflict)
    denied = client.get(created.headers["location"], headers=b)
    assert denied.status_code == 404
    assert str(asset.id) not in denied.text
    assert_browser_response(denied)
    page = client.get("/api/v1/assets?limit=1&offset=0", headers=a)
    assert AssetList.model_validate(page.json()).items == [asset]
    assert page.json()["page"] == {"limit": 1, "offset": 0, "total": 1}
    assert_browser_response(page)
    empty = client.get("/api/v1/assets?limit=1&offset=1", headers=a)
    assert empty.json()["items"] == [] and empty.json()["page"]["total"] == 1
    b_page = client.get("/api/v1/assets", headers=b)
    assert b_page.json()["items"] == [] and b_page.json()["page"]["total"] == 0
    other = client.post("/api/v1/assets", headers=b | {"Idempotency-Key": key}, json=BODY)
    assert other.status_code == 201 and other.json()["id"] != str(asset.id)
    assert_browser_response(other)
    invalid = client.post(
        "/api/v1/assets", headers=headers, json=BODY | {"created_by": str(users[0][1])}
    )
    assert invalid.status_code == 422
    assert_browser_response(invalid)
    assert (
        client.get(
            "/api/v1/assets", headers={"Origin": ORIGIN, "X-User-ID": str(users[0][0])}
        ).status_code
        == 401
    )
    with postgres.connect() as connection:
        assert (
            connection.scalar(select(Asset.created_by).where(Asset.id == asset.id)) == users[0][0]
        )
    # CORS controls browser readability, not API authorization or nonbrowser clients.
    external = client.get(
        created.headers["location"], headers=a | {"Origin": "https://evil.example"}
    )
    assert external.status_code == 200 and "access-control-allow-origin" not in external.headers
    assert (
        client.get(
            created.headers["location"], headers={"Origin": "https://evil.example"}
        ).status_code
        == 401
    )


def test_web_and_native_concurrent_retry_share_the_same_authorized_result(
    browser_db_app, users, postgres
):
    _, client = browser_db_app
    web = browser_login(client, users) | {"Idempotency-Key": str(uuid4())}
    native = {key: value for key, value in web.items() if key != "Origin"}
    key = UUID(web["Idempotency-Key"])
    barrier = Barrier(2)

    def synchronize(mapper, connection, target):
        if target.idempotency_key == key:
            barrier.wait(timeout=10)

    event.listen(RegistrationRequest, "before_insert", synchronize)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(client.post, "/api/v1/assets", headers=headers, json=BODY)
                for headers in [web, native]
            ]
            browser, mobile = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(RegistrationRequest, "before_insert", synchronize)
    assert browser.status_code == mobile.status_code == 201
    assert browser.json() == mobile.json()
    assert_browser_response(browser)
    assert "access-control-allow-origin" not in mobile.headers
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                select(func.count()).select_from(Asset).where(Asset.created_by == users[0][0])
            )
            == 1
        )
        assert (
            connection.scalar(
                select(RegistrationRequest.user_id).where(
                    RegistrationRequest.idempotency_key == key
                )
            )
            == users[0][0]
        )


def test_invalid_expired_and_revoked_tokens_have_safe_http_errors(
    browser_db_app, users, postgres, caplog
):
    app, client = browser_db_app
    headers = browser_login(client, users)
    valid = headers["Authorization"].split(" ", 1)[1]
    secret = app.state.settings.token_secret.get_secret_value()
    claims = jwt.decode(valid, secret, algorithms=["HS256"], options={"verify_aud": False})
    expired = jwt.encode(claims | {"iat": 1, "nbf": 1, "exp": 2}, secret, algorithm="HS256")
    wrong_signature = jwt.encode(
        claims, "another-signing-key-with-more-than-thirty-two-bytes", algorithm="HS256"
    )
    wrong_algorithm = jwt.encode(claims, secret, algorithm="HS384")
    malformed = "DO_NOT_LOG_MALFORMED_TOKEN"
    statements = []

    def record(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(app.state.engine, "before_cursor_execute", record)
    try:
        for value in [expired, wrong_signature, wrong_algorithm, malformed, "x" * 2049]:
            response = client.get(
                "/api/v1/auth/me", headers={"Origin": ORIGIN, "Authorization": "Bearer " + value}
            )
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"
            assert response.headers["www-authenticate"] == "Bearer"
            assert_browser_response(response)
            assert value not in response.text
    finally:
        event.remove(app.state.engine, "before_cursor_execute", record)
    assert not statements  # invalid JWTs rejected before user/database lookup
    password_marker = "DO_NOT_LOG_WRONG_PASSWORD"
    failed_login = client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN},
        json={
            "username": "user_" + users[0][0].hex,
            "password": password_marker,
        },
    )
    assert failed_login.status_code == 401
    with build_session_factory(postgres).begin() as session:
        session.get(User, users[0][0]).active = False
    revoked = client.get("/api/v1/assets", headers=headers)
    assert revoked.status_code == 401
    assert_browser_response(revoked)
    for sensitive in [
        valid,
        secret,
        expired,
        wrong_signature,
        wrong_algorithm,
        malformed,
        password_marker,
        users[1],
    ]:
        assert sensitive not in caplog.text
