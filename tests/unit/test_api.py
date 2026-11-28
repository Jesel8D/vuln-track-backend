from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


def test_health_and_ready(client):
    assert client.get("/health").json() == {"status": "ok"}
    response = client.get("/ready")
    assert response.status_code == 503
    assert "127.0.0.1" not in response.text


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/v1/auth/me"),
        ("get", "/api/v1/assets"),
        ("get", f"/api/v1/assets/{uuid4()}"),
        ("post", "/api/v1/assets"),
        ("get", f"/api/v2/workspaces/{uuid4()}/applications/{uuid4()}/cpe-candidates?query=django"),
        (
            "post",
            f"/api/v2/workspaces/{uuid4()}/applications/{uuid4()}/technologies/{uuid4()}/analyses",
        ),
        ("post", "/api/v2/workspaces"),
        ("get", f"/api/v2/workspaces/{uuid4()}/applications"),
    ],
)
def test_no_auth(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


def test_body_limit_and_validation(client):
    assert client.post("/api/v1/auth/login", content=b"x" * 8193).status_code == 413
    response = client.post("/api/v1/auth/login", json={"password": "private"})
    assert response.status_code == 422
    assert "private" not in response.text
    assert client.post("/api/v1/auth/login", content="{").status_code == 422
    assert client.get("/absent").json()["error"]["code"] == "HTTP_ERROR"


def test_chunked_body(client):
    def chunks():
        yield b"x" * 5000
        yield b"y" * 5000

    assert client.post("/api/v1/auth/login", content=chunks()).status_code == 413


def test_declared_oversized_body_is_rejected_before_reading_body():
    import asyncio

    from app.core.http import RequestBoundary

    calls = []
    messages = []

    async def app(scope, receive, send):
        calls.append("app")

    async def receive():
        calls.append("receive")
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    asyncio.run(
        RequestBoundary(app, max_body_bytes=8192)(
            {"type": "http", "headers": [(b"content-length", b"9000")]}, receive, send
        )
    )

    assert calls == []
    assert next(message for message in messages if message["type"] == "http.response.start")[
        "status"
    ] == 413


def test_unexpected_error_is_logged_without_message(app, caplog):
    @app.get("/test-error")
    def broken():
        raise RuntimeError("private-secret")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/test-error")
    assert response.status_code == 500
    assert "private-secret" not in response.text + caplog.text
    assert "RuntimeError" in caplog.text
