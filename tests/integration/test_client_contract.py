"""Contract evidence shared by migrated V1 and a genuinely fresh proposed bootstrap."""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from app.api.router import Token, UserRead
from app.db.verify_schema import OWNERSHIP_REVISION, installed_revision, verify_schema
from app.schemas.assets import AssetList, AssetRead
from tests.conftest import login

pytestmark = pytest.mark.postgres
BODY = {
    "device_type": "router",
    "manufacturer": "Marca ejemplo",
    "model": "Modelo A",
    "version": "1.2",
    "site_label": "SITIO-1",
    "inventory_label": None,
    "notes": None,
}


def test_seed_and_schema_compatibility_on_both_installation_paths(postgres):
    with postgres.connect() as connection:
        assert installed_revision(connection) == OWNERSHIP_REVISION
        assert verify_schema(connection)
        assert connection.scalar(text("SELECT count(*) FROM vulntrack.analysis_runs")) == 2
        assert connection.scalar(text("SELECT count(*) FROM vulntrack.findings")) == 1
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM vulntrack.assets WHERE id IN ("
                    "'10000000-0000-4000-8000-000000000001',"
                    "'10000000-0000-4000-8000-000000000002',"
                    "'10000000-0000-4000-8000-000000000003') AND created_by IS NULL"
                )
            )
            == 3
        )
        assert (
            connection.scalar(
                text(
                    "SELECT NOT active AND password_hash IS NULL FROM vulntrack.users "
                    "WHERE username='demo_operator'"
                )
            )
            is True
        )


def test_client_response_shapes_and_security_headers(db_app, users):
    _, client = db_app
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "user_" + users[0][0].hex,
            "password": users[1],
        },
    )
    assert response.status_code == 200
    token = Token.model_validate(response.json())
    assert token.token_type == "bearer" and token.expires_in == 900
    headers = {"Authorization": "Bearer " + token.access_token, "Idempotency-Key": str(uuid4())}
    me = client.get("/api/v1/auth/me", headers=headers)
    assert UserRead.model_validate(me.json()).id == users[0][0]
    created = client.post("/api/v1/assets", json=BODY, headers=headers)
    assert created.status_code == 201
    asset = AssetRead.model_validate(created.json())
    assert created.headers["location"] == f"/api/v1/assets/{asset.id}"
    assert client.get(created.headers["location"], headers=headers).json() == created.json()
    page = client.get("/api/v1/assets?limit=1&offset=0", headers=headers)
    assert AssetList.model_validate(page.json()).items == [asset]
    for result in [response, me, created, page]:
        assert "no-store" in result.headers["cache-control"]
        assert result.headers["x-content-type-options"] == "nosniff"
        UUID(result.headers["x-request-id"])
    assert token.access_token not in created.text + me.text + page.text
    assert "created_by" not in created.json()


def test_client_error_shape_redaction_and_cors_boundary(db_app, users):
    _, client = db_app
    unauthenticated = client.get("/api/v1/assets")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    headers = login(client, users) | {"Idempotency-Key": str(uuid4())}
    rejected_input = "DO_NOT_ECHO_THIS_CLIENT_VALUE"
    invalid = client.post(
        "/api/v1/assets", headers=headers, json=BODY | {"created_by": rejected_input}
    )
    assert invalid.status_code == 422
    missing = client.get(f"/api/v1/assets/{uuid4()}", headers=headers)
    assert missing.status_code == 404
    for response in [unauthenticated, invalid, missing]:
        body = response.json()
        assert set(body) == {"error"}
        assert set(body["error"]) == {"code", "message", "request_id"}
        assert body["error"]["request_id"] == response.headers["x-request-id"]
        assert rejected_input not in response.text
    origin = client.get("/api/v1/auth/me", headers=headers | {"Origin": "https://client.example"})
    assert (
        "access-control-allow-origin" not in origin.headers
    )  # browser integration still needs review
