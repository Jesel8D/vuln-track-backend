"""Real JWT/transactions/RLS; run only with the owned disposable V2 runner."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from app.db.workspace_context import workspace_session
from tests.integration import test_v2_registration as registration

account = registration.account
v2 = registration.v2

pytestmark = pytest.mark.postgres


@pytest.fixture
def target_data(v2):
    _, client = v2
    owners = [account(client), account(client)]
    for owner in owners:
        base = f"/api/v2/workspaces/{owner['workspace']}/applications"
        response = client.post(base, headers=owner["headers"], json={"name": "Security laboratory"})
        assert response.status_code == 201
        owner["application"] = response.json()["id"]
        owner["base"] = base + "/" + owner["application"] + "/targets"
        response = client.post(
            owner["base"], headers=owner["headers"], json={"url": "https://example.com/"}
        )
        assert response.status_code == 201
        owner["target"] = response.json()
    return owners


def declaration(target, status="approved"):
    return {
        "authorization_status": status,
        "authorization_expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        if status == "approved"
        else None,
        "authorization_reference": "Controlled test declaration, no scan permission",
        "expected_updated_at": target["updated_at"],
    }


def test_creation_approval_withdrawal_and_audit_are_not_verification(v2, target_data, postgres):
    client = v2[1]
    owner = target_data[0]
    target = owner["target"]
    assert target["authorization_status"] == "pending"
    assert target["analysis_readiness"]["authorization_state"] == "registered"
    path = owner["base"] + "/" + target["id"] + "/authorization"
    approved = client.patch(path, headers=owner["headers"], json=declaration(target))
    assert approved.status_code == 200
    target = approved.json()
    assert target["analysis_readiness"]["authorization_state"] == "verification_pending"
    assert not target["analysis_readiness"]["control_verified"]
    assert not target["analysis_readiness"]["execution_enabled"]
    withdrawn = client.patch(path, headers=owner["headers"], json=declaration(target, "rejected"))
    assert withdrawn.status_code == 200
    target = withdrawn.json()
    assert target["authorization_status"] == "rejected"
    assert not target["analysis_readiness"]["execution_enabled"]
    with postgres.connect() as connection:
        events = connection.execute(
            text(
                "SELECT action,actor_id FROM vulntrack.audit_events WHERE object_id=:id ORDER BY id"
            ),
            {"id": UUID(target["id"])},
        ).all()
    assert [row.action for row in events] == [
        "target.created",
        "target.authorization.approved",
        "target.authorization.withdrawn",
    ]
    assert all(str(row.actor_id) == owner["id"] for row in events)


@pytest.mark.parametrize("kind", ["absent", "invalid", "foreign", "ids"])
def test_authentication_and_foreign_resource_ids(v2, target_data, kind):
    client = v2[1]
    a, b = target_data
    headers = (
        {}
        if kind == "absent"
        else {"Authorization": "Bearer invalid"}
        if kind == "invalid"
        else b["headers"]
    )
    expected = 401 if kind in {"absent", "invalid"} else 404
    base = a["base"] if kind != "ids" else b["base"].replace(b["application"], a["application"])
    assert client.get(base, headers=headers).status_code == expected
    assert (
        client.post(base, headers=headers, json={"url": "https://example.com/"}).status_code
        == expected
    )
    assert (
        client.patch(
            base + "/" + a["target"]["id"] + "/authorization",
            headers=headers,
            json=declaration(a["target"]),
        ).status_code
        == expected
    )
    if kind == "foreign":
        assert (
            client.get(f"/api/v2/workspaces/{a['workspace']}/targets", headers=headers).status_code
            == 404
        )


def test_target_id_cannot_be_moved_between_applications(v2, target_data):
    a, b = target_data
    response = v2[1].patch(
        a["base"] + "/" + b["target"]["id"] + "/authorization",
        headers=a["headers"],
        json=declaration(b["target"]),
    )
    assert response.status_code == 404


@pytest.mark.parametrize("role,expected", [("viewer", 404), ("editor", 200)])
def test_workspace_role_is_read_from_database(v2, target_data, postgres, role, expected):
    a, b = target_data
    with postgres.begin() as connection:
        connection.execute(
            text("""INSERT INTO vulntrack.workspace_members
            (workspace_id,user_id,role) VALUES (:workspace,:user,:role)"""),
            {"workspace": UUID(a["workspace"]), "user": UUID(b["id"]), "role": role},
        )
    client = v2[1]
    assert client.get(a["base"], headers=b["headers"]).status_code == 200
    response = client.patch(
        a["base"] + "/" + a["target"]["id"] + "/authorization",
        headers=b["headers"],
        json=declaration(a["target"]),
    )
    assert response.status_code == expected


@pytest.mark.parametrize(
    "extra",
    [
        {"control_verified": True},
        {"analysis_readiness": {"execution_enabled": True}},
        {"workspace_id": str(uuid4())},
    ],
)
def test_client_cannot_supply_internal_verification_or_scope(v2, target_data, extra):
    a = target_data[0]
    response = v2[1].post(
        a["base"], headers=a["headers"], json={"url": "https://example.com/", **extra}
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/",
        "https://169.254.169.254/",
        "https://name:never-log-this@example.com/",
        "https://example.com:8443/",
    ],
)
def test_unsafe_urls_and_credentials_are_rejected_without_echo(v2, target_data, url):
    a = target_data[0]
    response = v2[1].post(a["base"], headers=a["headers"], json={"url": url})
    assert response.status_code == 422
    assert "never-log-this" not in response.text


def test_legacy_unsafe_or_incomplete_rows_are_preserved_but_blocked(v2, target_data, postgres):
    a = target_data[0]
    with postgres.begin() as connection:
        # Mimic a historical metadata row without changing any existing record.
        target = uuid4()
        connection.execute(
            text("""INSERT INTO vulntrack.application_targets
            (id,workspace_id,application_id,url,created_by,authorization_status,authorization_expires_at)
            VALUES (:id,:workspace,:app,'http://127.0.0.1:8080',:user,'approved',
                clock_timestamp()+interval '1 hour')"""),
            {
                "id": target,
                "workspace": UUID(a["workspace"]),
                "app": UUID(a["application"]),
                "user": UUID(a["id"]),
            },
        )
    items = v2[1].get(a["base"], headers=a["headers"]).json()["items"]
    row = next(row for row in items if row["id"] == str(target))
    assert row["url"] == "http://127.0.0.1:8080"
    assert not row["analysis_readiness"]["url_policy_allowed"]
    assert row["analysis_readiness"]["authorization_state"] == "incomplete"
    assert not row["analysis_readiness"]["execution_enabled"]


def test_expiry_is_derived_without_rewriting_stored_approval(v2, target_data, postgres):
    a = target_data[0]
    with postgres.begin() as connection:
        connection.execute(
            text("""UPDATE vulntrack.application_targets SET authorization_status='approved',
            authorization_reference='expired laboratory declaration',
            authorization_expires_at=clock_timestamp()-interval '1 second' WHERE id=:id"""),
            {"id": UUID(a["target"]["id"])},
        )
    row = v2[1].get(a["base"], headers=a["headers"]).json()["items"][0]
    assert (
        row["authorization_status"] == row["analysis_readiness"]["authorization_state"] == "expired"
    )
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT authorization_status FROM vulntrack.application_targets WHERE id=:id"),
                {"id": UUID(row["id"])},
            )
            == "approved"
        )


def test_concurrent_declarations_have_one_winner_and_one_audit(v2, target_data, postgres):
    a = target_data[0]
    path = a["base"] + "/" + a["target"]["id"] + "/authorization"
    body = declaration(a["target"])
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: v2[1].patch(path, headers=a["headers"], json=body), range(2))
        )
    assert sorted(result.status_code for result in results) == [200, 409]
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM vulntrack.audit_events WHERE object_id=:id "
                    "AND action='target.authorization.approved'"
                ),
                {"id": UUID(a["target"]["id"])},
            )
            == 1
        )


def test_audit_failure_rolls_back_declaration(v2, target_data, postgres):
    app, _ = v2
    a = target_data[0]
    engine = app.state.session_factory.kw["bind"]

    def fail_audit(conn, cursor, statement, parameters, context, many):
        if "INSERT INTO vulntrack.audit_events" in statement:
            raise RuntimeError("Controlled audit failure")

    event.listen(engine, "before_cursor_execute", fail_audit)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.patch(
                a["base"] + "/" + a["target"]["id"] + "/authorization",
                headers=a["headers"],
                json=declaration(a["target"]),
            )
            assert response.status_code == 500
            assert "Controlled audit failure" not in response.text
    finally:
        event.remove(engine, "before_cursor_execute", fail_audit)
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT authorization_status FROM vulntrack.application_targets WHERE id=:id"),
                {"id": UUID(a["target"]["id"])},
            )
            == "pending"
        )


def test_rls_and_reused_connection_do_not_leak_targets_or_audit(v2, target_data):
    app, client = v2
    a, b = target_data
    factory, settings = app.state.session_factory, app.state.settings
    for rollback in (False, True):
        try:
            with workspace_session(
                factory, settings, UUID(a["id"]), UUID(a["workspace"])
            ) as session:
                assert (
                    session.scalar(
                        text("SELECT count(*) FROM vulntrack.application_targets WHERE id=:id"),
                        {"id": UUID(b["target"]["id"])},
                    )
                    == 0
                )
                assert (
                    session.execute(
                        text(
                            "UPDATE vulntrack.application_targets "
                            "SET authorization_status='rejected' "
                            "WHERE id=:id"
                        ),
                        {"id": UUID(b["target"]["id"])},
                    ).rowcount
                    == 0
                )
                if rollback:
                    raise ValueError("rollback")
        except ValueError:
            pass
        with factory.begin() as session:
            assert session.scalar(text("SELECT count(*) FROM vulntrack.application_targets")) == 0
    with (
        pytest.raises(DBAPIError),
        workspace_session(factory, settings, UUID(a["id"]), UUID(a["workspace"])) as session,
    ):
        session.execute(text("SELECT * FROM vulntrack.audit_events"))
    assert (
        client.get(
            f"/api/v2/workspaces/{b['workspace']}/audit-events", headers=a["headers"]
        ).status_code
        == 404
    )


def test_no_target_scan_or_zap_route_even_for_owner(v2, target_data):
    a = target_data[0]
    client = v2[1]
    for suffix in ("/analyses", "/scan", "/zap"):
        assert (
            client.post(
                a["base"] + "/" + a["target"]["id"] + suffix, headers=a["headers"], json={}
            ).status_code
            == 404
        )
