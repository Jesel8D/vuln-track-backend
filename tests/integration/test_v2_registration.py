"""Real public registration, JWT, PostgreSQL roles, RLS and a single reused connection."""

import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier, Lock
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from app.core.config import Settings
from app.core.security import verify_password
from app.db.verify_schema import CVE_REVISION, installed_revision, verify_schema
from app.db.workspace_context import workspace_session
from app.main import create_app

pytestmark = pytest.mark.postgres


@pytest.fixture
def v2(postgres):
    if os.environ.get("TEST_V2_ENABLED") != "1":
        pytest.skip("Usar python -m scripts.test_v2_registration")
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=os.environ["TEST_APP_DATABASE_URL"],
        token_secret=secrets.token_urlsafe(48),
        workspace_hmac_key=os.environ["WORKSPACE_HMAC_KEY"],
        registration_enabled=True,
        registration_attempts_per_minute=10,
        registration_total_per_minute=100,
        cve_worker_enabled=False,
        db_pool_size=1,
        db_max_overflow=0,
        cors_origins=["http://localhost:5173"],
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield app, client


def account(client):
    username, password = "new_" + uuid4().hex, secrets.token_urlsafe(24)
    result = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert result.status_code == 201, result.text
    login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    workspaces = client.get("/api/v2/workspaces", headers=headers).json()["items"]
    assert len(workspaces) == 1
    return {
        "id": result.json()["id"],
        "username": username,
        "password": password,
        "headers": headers,
        "workspace": workspaces[0]["workspace_id"],
    }


def test_registration_login_me_personal_workspace_and_empty_dashboard(v2, postgres, caplog):
    app, client = v2
    assert client.get("/ready").status_code == 200
    user = account(client)
    assert client.get("/api/v1/auth/me", headers=user["headers"]).json() == {
        "id": user["id"],
        "username": user["username"],
    }
    workspace = client.get(f"/api/v2/workspaces/{user['workspace']}", headers=user["headers"])
    assert workspace.status_code == 200 and workspace.json()["created_by"] == user["id"]
    dashboard = client.get(
        f"/api/v2/workspaces/{user['workspace']}/dashboard", headers=user["headers"]
    )
    assert dashboard.status_code == 200
    summary = dashboard.json()["summary"]
    assert all(value == 0 for value in summary.values())
    assert client.get(
        f"/api/v2/workspaces/{user['workspace']}/applications", headers=user["headers"]
    ).json() == {"items": []}
    assets = client.get("/api/v1/assets", headers=user["headers"])
    assert assets.status_code == 200 and assets.json()["page"]["total"] == 0
    with postgres.connect() as connection:
        row = connection.execute(
            text("SELECT active,password_hash FROM vulntrack.users WHERE id=:id"),
            {"id": UUID(user["id"])},
        ).one()
        assert row.active and verify_password(row.password_hash, user["password"])
        assert (
            connection.scalar(
                text("SELECT role FROM vulntrack.workspace_members WHERE user_id=:id"),
                {"id": UUID(user["id"])},
            )
            == "owner"
        )
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM vulntrack.audit_events WHERE actor_id=:id AND "
                    "action='account.registered'"
                ),
                {"id": UUID(user["id"])},
            )
            == 1
        )
    assert user["password"] not in caplog.text and row.password_hash not in caplog.text
    assert not app.state.session_factory().in_transaction()


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "active",
        "is_admin",
        "role",
        "created_by",
        "workspace_id",
        "workspace_owner",
        "verified_email",
        "email",
    ],
)
def test_registration_rejects_internal_fields(v2, field):
    _, client = v2
    result = client.post(
        "/api/v1/auth/register",
        json={
            "username": "new_" + uuid4().hex,
            "password": secrets.token_urlsafe(24),
            field: "forged",
        },
    )
    assert result.status_code == 422
    assert "forged" not in result.text and "password" not in result.text


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"username": "bad@mail.test", "password": "A unique test phrase 7319!"},
        {"username": "normal", "password": "short"},
        {"username": "normal", "password": "Password123456789!"},
        {"username": "normal", "password": "a" * 20},
    ],
)
def test_invalid_public_registration(v2, body):
    result = v2[1].post("/api/v1/auth/register", json=body)
    assert result.status_code == 422 and set(result.json()) == {"error"}


def test_duplicate_normalization_retry_and_inactive_seed(v2, postgres):
    client = v2[1]
    user = account(client)
    for password in (user["password"], secrets.token_urlsafe(24)):
        result = client.post(
            "/api/v1/auth/register",
            json={"username": " " + user["username"].upper() + " ", "password": password},
        )
        assert result.status_code == 409
        assert result.json()["error"]["code"] == "REGISTRATION_UNAVAILABLE"
        assert user["id"] not in result.text and user["username"] not in result.text
    seed = client.post(
        "/api/v1/auth/register",
        json={"username": "demo_operator", "password": secrets.token_urlsafe(24)},
    )
    assert seed.status_code == 409
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM vulntrack.workspaces WHERE created_by=:id"),
                {"id": UUID(user["id"])},
            )
            == 1
        )
        assert connection.execute(
            text("SELECT active,password_hash FROM vulntrack.users WHERE username='demo_operator'")
        ).one() == (False, None)


@pytest.mark.parametrize("same_username", [True, False])
def test_concurrent_registration_is_atomic(v2, postgres, same_username):
    settings = v2[0].state.settings.model_copy(update={"db_pool_size": 2})
    racing = create_app(settings)
    barrier = Barrier(2)
    inserts = Barrier(2)
    pids, observed_lock = set(), []
    guard = Lock()
    first = "race_" + uuid4().hex
    names = [first, first if same_username else "race_" + uuid4().hex]
    password = secrets.token_urlsafe(24)

    def synchronize(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO vulntrack.users "):
            pid = connection.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
            with guard:
                pids.add(pid)
            barrier.wait(timeout=10)  # Both real PostgreSQL sessions before either INSERT.

    def overlap(connection, cursor, statement, parameters, context, many):
        if not statement.startswith("INSERT INTO vulntrack.users "):
            return
        if not same_username:
            inserts.wait(timeout=10)  # Both inserts remain uncommitted at once.
            return
        # The winner holds its unique index entry until the second backend waits on it.
        deadline = time.monotonic() + 2
        with postgres.connect().execution_options(isolation_level="AUTOCOMMIT") as monitor:
            while time.monotonic() < deadline:
                if monitor.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE pid=ANY(:pids) "
                        "AND wait_event_type='Lock'"
                    ),
                    {"pids": list(pids)},
                ):
                    observed_lock.append(True)
                    return
                time.sleep(0.01)
        raise AssertionError("Expected concurrent PostgreSQL uniqueness lock was not observed")

    event.listen(racing.state.engine, "before_cursor_execute", synchronize)
    event.listen(racing.state.engine, "after_cursor_execute", overlap)
    with TestClient(racing) as client:

        def submit(name):
            return client.post(
                "/api/v1/auth/register", json={"username": name, "password": password}
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, names))
    assert len(pids) == 2
    if same_username:
        assert observed_lock == [True]
    assert sorted(row.status_code for row in results) == (
        [201, 409] if same_username else [201, 201]
    )
    with postgres.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT u.id,count(w.id) FROM vulntrack.users u LEFT JOIN "
                "vulntrack.workspaces w ON w.created_by=u.id WHERE "
                "username=ANY(:names) GROUP BY u.id"
            ),
            {"names": names},
        ).all()
        assert len(rows) == (1 if same_username else 2) and all(row[1] == 1 for row in rows)


def test_rollback_after_user_workspace_and_membership_allows_retry(v2, postgres):
    client = v2[1]
    username, password = "rollback_" + uuid4().hex, secrets.token_urlsafe(24)
    with postgres.begin() as connection:
        connection.execute(
            text(
                "CREATE FUNCTION public.fail_registration_audit() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure' "
                "USING ERRCODE='23514'; END $$"
            )
        )
        connection.execute(
            text(
                "CREATE TRIGGER fail_registration_audit BEFORE INSERT ON "
                "vulntrack.audit_events FOR EACH ROW EXECUTE FUNCTION "
                "public.fail_registration_audit()"
            )
        )
    try:
        result = client.post(
            "/api/v1/auth/register", json={"username": username, "password": password}
        )
        assert result.status_code == 409 and "synthetic" not in result.text
        with postgres.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM vulntrack.users WHERE username=:name"),
                    {"name": username},
                )
                == 0
            )
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM vulntrack.workspaces WHERE name=:name"),
                    {"name": "Personal de " + username},
                )
                == 0
            )
    finally:
        with postgres.begin() as connection:
            connection.execute(
                text("DROP TRIGGER fail_registration_audit ON vulntrack.audit_events")
            )
            connection.execute(text("DROP FUNCTION public.fail_registration_audit()"))
    assert (
        client.post(
            "/api/v1/auth/register", json={"username": username, "password": password}
        ).status_code
        == 201
    )


def test_real_users_cannot_read_each_others_workspaces_apps_or_assets(v2):
    client = v2[1]
    first, second = account(client), account(client)
    for owner, other in ((first, second), (second, first)):
        base = f"/api/v2/workspaces/{owner['workspace']}"
        application = client.post(
            base + "/applications", headers=owner["headers"], json={"name": "Private app"}
        )
        assert application.status_code == 201
        for path in (
            base,
            base + "/applications",
            base + "/dashboard",
            base + f"/applications/{application.json()['id']}/technologies",
        ):
            assert client.get(path, headers=other["headers"]).status_code == 404
        asset = client.post(
            "/api/v1/assets",
            headers=owner["headers"] | {"Idempotency-Key": str(uuid4())},
            json={
                "device_type": "router",
                "manufacturer": "Synthetic",
                "model": "Lab",
                "version": "1",
                "site_label": "TEST",
            },
        )
        assert asset.status_code == 201
        assert (
            client.get("/api/v1/assets/" + asset.json()["id"], headers=other["headers"]).status_code
            == 404
        )
    for user in (first, second):
        directory = client.get("/api/v2/workspaces", headers=user["headers"]).json()["items"]
        assert [row["workspace_id"] for row in directory] == [user["workspace"]]
        assets = client.get("/api/v1/assets", headers=user["headers"])
        assert assets.status_code == 200 and assets.json()["page"]["total"] == 1


def test_single_pooled_connection_clears_context_on_commit_rollback_and_forgery(v2):
    app, client = v2
    first, second = account(client), account(client)
    pids = []
    for owner in (first, second):
        client.post(
            f"/api/v2/workspaces/{owner['workspace']}/applications",
            headers=owner["headers"],
            json={"name": owner["username"]},
        )
        with workspace_session(
            app.state.session_factory,
            app.state.settings,
            UUID(owner["id"]),
            UUID(owner["workspace"]),
        ) as session:
            pids.append(session.scalar(text("SELECT pg_backend_pid()")))
            assert session.execute(
                text("SELECT name FROM vulntrack.applications")
            ).scalars().all() == [owner["username"]]
        with app.state.session_factory.begin() as session:
            assert session.scalar(text("SELECT NOT vulntrack.context_is_valid()"))
            assert session.scalar(text("SELECT count(*) FROM vulntrack.applications")) == 0
    assert pids[0] == pids[1]
    with (
        pytest.raises(ValueError),
        workspace_session(
            app.state.session_factory,
            app.state.settings,
            UUID(first["id"]),
            UUID(first["workspace"]),
        ),
    ):
        raise ValueError("test rollback")
    with app.state.session_factory.begin() as session:
        assert session.scalar(text("SELECT NOT vulntrack.context_is_valid()"))
        session.execute(
            text(
                "SELECT "
                "set_config('vulntrack.context_user',:user,true),set_config('vulntrack.context_workspace',:workspace,true),set_config('vulntrack.context_signature',repeat('0',64),true)"
            ),
            {"user": second["id"], "workspace": second["workspace"]},
        )
        assert session.scalar(text("SELECT count(*) FROM vulntrack.applications")) == 0


def test_invalid_or_expired_context_and_bad_backend_key_fail_closed(v2, postgres):
    app, client = v2
    user = account(client)
    for expires in (
        int(datetime.now(UTC).timestamp()) - 1,
        int(datetime.now(UTC).timestamp()) + 30,
    ):
        with pytest.raises(DBAPIError) as error, app.state.session_factory.begin() as session:
            session.execute(
                text(
                    "SELECT vulntrack.establish_context(:user,:workspace,:expiry,:nonce,:signature)"
                ),
                {
                    "user": UUID(user["id"]),
                    "workspace": UUID(user["workspace"]),
                    "expiry": expires,
                    "nonce": uuid4(),
                    "signature": "0" * 64,
                },
            )
        assert error.value.orig.sqlstate == "28000"
    bad = create_app(
        app.state.settings.model_copy(update={"workspace_hmac_key": SecretStr("00" * 32)})
    )
    username = "badkey_" + uuid4().hex
    with TestClient(bad) as bad_client:
        assert (
            bad_client.post(
                "/api/v1/auth/register",
                json={"username": username, "password": secrets.token_urlsafe(24)},
            ).status_code
            == 503
        )
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM vulntrack.users WHERE username=:name"),
                {"name": username},
            )
            == 0
        )


def test_registration_rate_limit_and_spoofed_forwarded_headers(v2):
    app, _ = v2
    settings = app.state.settings.model_copy(update={"registration_attempts_per_minute": 2})
    with TestClient(create_app(settings)) as client:
        for index in range(2):
            assert (
                client.post(
                    "/api/v1/auth/register",
                    headers={"X-Forwarded-For": f"192.0.2.{index}"},
                    json={},
                ).status_code
                == 422
            )
        result = client.post(
            "/api/v1/auth/register", headers={"X-Forwarded-For": "192.0.2.99"}, json={}
        )
        assert result.status_code == 429 and result.headers["retry-after"] == "60"


def test_tokens_account_deactivation_and_missing_session(v2, postgres):
    app, client = v2
    user = account(client)
    original = user["headers"]["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(
        original,
        app.state.settings.token_secret.get_secret_value(),
        algorithms=["HS256"],
        audience="vulntrack-api",
    )
    claims.update(iat=claims["iat"] - 1000, nbf=claims["nbf"] - 1000, exp=claims["exp"] - 1000)
    expired = jwt.encode(
        claims, app.state.settings.token_secret.get_secret_value(), algorithm="HS256"
    )
    for headers in (
        {},
        {"Authorization": "Bearer invalid"},
        {"Authorization": "Bearer " + expired},
    ):
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
        assert client.get("/api/v2/workspaces", headers=headers).status_code == 401
    wrong = client.post(
        "/api/v1/auth/login", json={"username": user["username"], "password": "wrong"}
    )
    absent = client.post(
        "/api/v1/auth/login", json={"username": "missing_" + uuid4().hex, "password": "wrong"}
    )
    assert wrong.status_code == absent.status_code == 401
    assert wrong.json()["error"]["code"] == absent.json()["error"]["code"]
    with postgres.begin() as connection:
        connection.execute(
            text("UPDATE vulntrack.users SET active=false WHERE id=:id"), {"id": UUID(user["id"])}
        )
    assert client.get("/api/v1/auth/me", headers=user["headers"]).status_code == 401
    assert client.get("/api/v2/workspaces", headers=user["headers"]).status_code == 401


def test_application_role_is_minimal_and_schema_preserves_legacy(v2, postgres):
    app, _ = v2
    with app.state.session_factory.begin() as session:
        assert not session.scalar(
            text(
                "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls FROM"
                " pg_roles WHERE rolname=current_user"
            )
        )
        assert not session.scalar(
            text(
                "SELECT has_table_privilege(current_user,'vulntrack.users','UPDATE') "
                "OR has_table_privilege(current_user,'vulntrack.users','DELETE')"
            )
        )
    for sql in (
        "UPDATE vulntrack.users SET active=true",
        "SELECT * FROM vulntrack_private.context_keys",
        "INSERT INTO vulntrack.users(id,username,active,created_at) VALUES "
        "(gen_random_uuid(),'forged',true,now())",
    ):
        with pytest.raises(DBAPIError) as error, app.state.session_factory.begin() as session:
            session.execute(text(sql))
        assert error.value.orig.sqlstate == "42501"
    with postgres.connect() as connection:
        assert installed_revision(connection) == CVE_REVISION
        assert verify_schema(connection)
        assert (
            connection.scalar(
                text("SELECT count(*) FROM vulntrack.assets WHERE created_by IS NULL")
            )
            == 3
        )


@pytest.mark.parametrize(
    "drift",
    [
        "ALTER TABLE vulntrack.applications DISABLE ROW LEVEL SECURITY",
        "DROP POLICY workspace_read ON vulntrack.workspaces",
        "ALTER TABLE vulntrack.workspaces DISABLE TRIGGER workspaces_require_owner",
        "ALTER TABLE vulntrack.workspace_members DROP CONSTRAINT workspace_members_role",
    ],
)
def test_v2_catalog_drift_is_rejected_without_changing_installed_state(v2, postgres, drift):
    with pytest.raises(RuntimeError), postgres.begin() as connection:
        connection.execute(text(drift))
        verify_schema(connection)
    with postgres.connect() as connection:
        assert verify_schema(connection)


def test_cors_registration_and_actual_v2_put_contract(v2):
    client = v2[1]
    for method, path in (
        ("POST", "/api/v1/auth/register"),
        ("PUT", f"/api/v2/workspaces/{uuid4()}/applications/{uuid4()}/technologies/{uuid4()}/cpe"),
    ):
        response = client.options(
            path,
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "content-type,authorization,idempotency-key",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert client.get("/api/v1/auth/me").status_code == 401


def test_missing_registration_privilege_fails_closed_without_creating_account(v2, postgres):
    client = v2[1]
    username = "no_grant_" + uuid4().hex
    with postgres.begin() as connection:
        connection.execute(text("REVOKE vulntrack_registration FROM backend_test_api"))
    try:
        ready = client.get("/ready")
        assert ready.status_code == 503
        assert ready.json()["error"]["code"] == "REGISTRATION_NOT_READY"
        result = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "password": secrets.token_urlsafe(24),
            },
        )
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "REGISTRATION_NOT_READY"
        with postgres.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM vulntrack.users WHERE username=:name"),
                    {"name": username},
                )
                == 0
            )
    finally:
        with postgres.begin() as connection:
            connection.execute(text("GRANT vulntrack_registration TO backend_test_api"))


def test_new_api_instance_recovers_account_workspace_and_saved_application(v2):
    app, client = v2
    user = account(client)
    path = f"/api/v2/workspaces/{user['workspace']}/applications"
    application = client.post(path, headers=user["headers"], json={"name": "Saved application"})
    assert application.status_code == 201
    # A new engine/API instance shares only persisted PostgreSQL state and configured keys.
    with TestClient(create_app(app.state.settings)) as restarted:
        logged_in = restarted.post(
            "/api/v1/auth/login",
            json={
                "username": user["username"],
                "password": user["password"],
            },
        )
        assert logged_in.status_code == 200
        headers = {"Authorization": "Bearer " + logged_in.json()["access_token"]}
        directory = restarted.get("/api/v2/workspaces", headers=headers).json()["items"]
        assert [row["workspace_id"] for row in directory] == [user["workspace"]]
        saved = restarted.get(path, headers=headers)
        assert saved.status_code == 200
        assert saved.json()["items"][0]["id"] == application.json()["id"]
