import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app

ORIGIN = "http://localhost:5173"


def configured(settings, **updates):
    return Settings(_env_file=None, **(settings.model_dump() | updates))


@pytest.fixture
def browser_app(settings):
    return create_app(configured(settings, cors_origins=[ORIGIN]))


@pytest.fixture
def browser_client(browser_app):
    with TestClient(browser_app) as client:
        yield client


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "null",
        "https://*.example.edu",
        "https://portal.example.edu/path",
        "https://portal.example.edu/",
        "https://user:password@portal.example.edu",
        "https://portal.example.edu?x=1",
        "https://portal.example.edu#fragment",
        "https://portal.example.edu:99999",
        "https://Portal.example.edu",
        " https://portal.example.edu",
        "https://portal.example.edu\n",
        "https://portal.example.edu:443",
        "https://portal.example.edu@evil.example/",
        "https://127.1",
        "https://0x7f000001",
        "file:///tmp/client",
        "https://",
    ],
)
def test_unsafe_or_noncanonical_origins_rejected(settings, origin):
    with pytest.raises(ValidationError):
        configured(settings, cors_origins=[origin])


def test_cors_environment_json_and_defaults(settings, monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", '["http://localhost:5173","http://127.0.0.1:5173"]')
    values = settings.model_dump()
    del values["cors_origins"]
    assert configured(settings).cors_origins == []  # explicit constructor wins over environment
    assert Settings(_env_file=None, **values).cors_origins == [ORIGIN, "http://127.0.0.1:5173"]
    for updates in [
        {"cors_allow_credentials": True},
        {"cors_origins": [ORIGIN, ORIGIN]},
        {"cors_max_age": 3601},
    ]:
        with pytest.raises(ValidationError):
            configured(settings, **updates)


@pytest.mark.parametrize(
    "origin",
    [
        "http://portal.example.edu",
        "https://localhost:5173",
        "https://127.0.0.1",
        "https://[::1]",
        "https://[::ffff:7f00:1]",
    ],
)
def test_production_rejects_http_and_loopback(settings, origin):
    with pytest.raises(ValidationError):
        configured(
            settings,
            environment="production",
            cors_origins=[origin],
            database_url="postgresql+psycopg://api@db/test?sslmode=verify-full&sslrootcert=/ca.pem",
        )


def test_production_explicit_https_and_empty_list_are_valid(settings):
    for origins in [[], ["https://portal.example.edu"]]:
        result = configured(
            settings,
            environment="production",
            cors_origins=origins,
            database_url="postgresql+psycopg://api@db/test?sslmode=verify-full&sslrootcert=/ca.pem",
        )
        assert result.cors_origins == origins


@pytest.mark.parametrize(
    "path,method",
    [("/api/v1/auth/login", "POST"), ("/api/v1/assets", "POST"), ("/api/v1/auth/me", "GET")],
)
def test_preflight_is_explicit_and_does_not_authenticate_or_query_db(
    browser_app, path, method, monkeypatch
):
    def forbidden_connect():
        pytest.fail("OPTIONS preflight must not access PostgreSQL")

    monkeypatch.setattr(browser_app.state.engine, "connect", forbidden_connect)
    with TestClient(browser_app) as client:
        response = client.options(
            path,
            headers={
                "Origin": ORIGIN,
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "authorization,content-type,idempotency-key",
            },
        )
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert "Origin" in response.headers["vary"]
    assert set(response.headers["access-control-allow-methods"].split(", ")) == {
        "GET",
        "POST",
        "PATCH",
    }
    allowed = {
        header.strip().lower()
        for header in response.headers["access-control-allow-headers"].split(",")
    }
    assert {"authorization", "content-type", "idempotency-key"} <= allowed
    assert "access-control-allow-credentials" not in response.headers
    assert response.headers["access-control-max-age"] == "600"
    assert "x-request-id" in response.headers


@pytest.mark.parametrize(
    "override",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Origin": "http://localhost:5174"},
        {"Access-Control-Request-Method": "DELETE"},
        {"Access-Control-Request-Headers": "X-User-ID"},
    ],
)
def test_preflight_denials_have_safe_json(browser_client, override):
    response = browser_client.options(
        "/api/v1/assets",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Idempotency-Key",
            **override,
        },
    )
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "CORS_PREFLIGHT_DENIED"
    assert error["request_id"] == response.headers["x-request-id"]
    assert "evil.example" not in response.text
    assert "access-control-allow-credentials" not in response.headers
    if override.get("Origin", ORIGIN) != ORIGIN:
        assert "access-control-allow-origin" not in response.headers


def test_cors_headers_cover_errors_and_do_not_replace_auth(browser_client, browser_app, caplog):
    @browser_app.get("/test-cors-error")
    def broken():
        raise RuntimeError("private-test-message")

    responses = [
        browser_client.get("/api/v1/assets", headers={"Origin": ORIGIN}),
        browser_client.post("/api/v1/auth/login", headers={"Origin": ORIGIN}, json={}),
        browser_client.post("/api/v1/auth/login", headers={"Origin": ORIGIN}, content=b"x" * 8193),
        browser_client.get("/test-cors-error", headers={"Origin": ORIGIN}),
        browser_client.get("/ready", headers={"Origin": ORIGIN}),
    ]
    assert [response.status_code for response in responses] == [401, 422, 413, 500, 503]
    for response in responses:
        assert response.headers["access-control-allow-origin"] == ORIGIN
        assert response.headers["content-type"] == "application/json"
        assert response.json()["error"]["request_id"] == response.headers["x-request-id"]
    assert "private-test-message" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_no_origin_default_closed_and_nonpreflight_options(client, browser_client):
    assert "access-control-allow-origin" not in browser_client.get("/health").headers
    denied = client.options(
        "/api/v1/assets",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers
    ordinary = browser_client.options("/api/v1/assets", headers={"Origin": ORIGIN})
    assert ordinary.status_code == 405
    assert ordinary.headers["access-control-allow-origin"] == ORIGIN
