"""SQL008 real JWT/RLS/roles/transactions. Never contact a destination."""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db.verify_verification import verify_verification_schema
from app.db.workspace_context import install_workspace_context, workspace_session
from tests.integration import test_v2_registration as registration
from tests.integration import test_web_target_security as security

v2 = registration.v2
target_data = security.target_data
pytestmark = pytest.mark.postgres


@pytest.mark.parametrize(
    "mutation",
    [
        "ALTER TABLE vulntrack_verification.challenges DISABLE ROW LEVEL SECURITY",
        "GRANT SELECT ON vulntrack_verification.challenges TO PUBLIC",
        "GRANT EXECUTE ON FUNCTION vulntrack_verification.lock_target"
        "(uuid,uuid,uuid,boolean) TO vulntrack_app",
        "ALTER ROLE vulntrack_verification_owner BYPASSRLS",
        "ALTER FUNCTION vulntrack_verification.issue"
        "(uuid,uuid,uuid,uuid,uuid,timestamptz,text,text) SET search_path=public",
        "CREATE TABLE vulntrack_verification.unexpected_object(id integer)",
        "GRANT vulntrack_verification_lab TO vulntrack_app",
    ],
)
def test_exact_schema_adoption_rejects_security_drift(postgres, mutation):
    with pytest.raises(RuntimeError, match="SQL008 verification drift"):
        with postgres.begin() as connection:
            connection.execute(text(mutation))
            verify_verification_schema(connection)
    with postgres.connect() as connection:
        assert verify_verification_schema(connection)


def prepare(v2, target_data):
    client = v2[1]
    owner = target_data[0]
    response = client.patch(
        owner["base"] + "/" + owner["target"]["id"] + "/authorization",
        headers=owner["headers"],
        json=security.declaration(owner["target"]),
    )
    assert response.status_code == 200
    owner["target"] = response.json()
    owner["verifications"] = owner["base"] + "/" + owner["target"]["id"] + "/verifications"
    return owner


def issue(client, owner, *, key=None):
    return client.post(
        owner["verifications"],
        headers={**owner["headers"], "Idempotency-Key": str(key or uuid4())},
        json={"expected_updated_at": owner["target"]["updated_at"]},
    )


def lab_transaction(postgres, app, owner, source, params):
    with postgres.begin() as connection:
        connection.execute(text("SET LOCAL ROLE vulntrack_verification_lab"))
        install_workspace_context(
            connection, app.state.settings, UUID(owner["id"]), UUID(owner["workspace"])
        )
        return connection.execute(text(source), params).all()


def lab_params(owner, challenge, attempt):
    return {
        "w": UUID(owner["workspace"]),
        "a": UUID(owner["application"]),
        "t": UUID(owner["target"]["id"]),
        "id": UUID(challenge["id"]),
        "attempt": attempt,
    }


CLAIM = "SELECT vulntrack_verification.claim_laboratory(:w,:a,:t,:id,:attempt)"
FINISH = "SELECT vulntrack_verification.finish_laboratory(:w,:a,:t,:id,:attempt,:digest,NULL,NULL)"


def test_durable_issue_idempotency_no_token_replay_no_network_and_revoke(
    v2, target_data, postgres, caplog, monkeypatch
):
    app, client = v2
    owner = prepare(v2, target_data)
    key = uuid4()
    response = issue(client, owner, key=key)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    challenge = body["challenge"]
    secret = body["instructions"]["body"]
    assert body["created"] and challenge["state"] == "pending"
    assert not challenge["control_verified"] and not challenge["execution_enabled"]
    assert (
        body["instructions"]["url"]
        == f"https://example.com/.well-known/vulntrack-verification/{challenge['id']}"
    )
    repeat = issue(client, owner, key=key)
    assert repeat.status_code == 200 and repeat.json()["instructions"] is None
    assert repeat.json()["challenge"]["id"] == challenge["id"]
    assert repeat.json()["created"] is False
    listing = client.get(owner["verifications"], headers=owner["headers"])
    assert listing.status_code == 200 and len(listing.json()["items"]) == 1
    assert secret not in listing.text and "proof_sha256" not in listing.text
    monkeypatch.setenv("DOMAIN_VERIFICATION_ENABLED", "true")
    monkeypatch.setenv("ZAP_ENABLED", "true")
    blocked = client.post(
        owner["verifications"] + "/" + challenge["id"] + "/verify",
        headers=owner["headers"],
        json={"expected_version": 1},
    )
    assert (
        blocked.status_code == 503
        and blocked.json()["error"]["code"] == "VERIFICATION_EGRESS_UNAVAILABLE"
    )
    with postgres.connect() as connection:
        stored = connection.execute(
            text(
                "SELECT proof_sha256,attempts,state FROM vulntrack_verification.challenges "
                "WHERE id=:id"
            ),
            {"id": UUID(challenge["id"])},
        ).one()
        assert stored.proof_sha256 == hashlib.sha256(secret.encode()).hexdigest()
        assert stored.attempts == 0 and stored.state == "pending"
    for _ in range(2):
        revoked = client.post(
            owner["verifications"] + "/" + challenge["id"] + "/revoke",
            headers=owner["headers"],
            json={"expected_version": 1},
        )
        assert revoked.status_code == 200 and revoked.json()["effective_state"] == "revoked"
    with postgres.connect() as connection:
        actions = connection.scalars(
            text("SELECT action FROM vulntrack.audit_events WHERE object_id=:id ORDER BY id"),
            {"id": UUID(challenge["id"])},
        ).all()
        assert actions == ["verification.issued", "verification.revoked"]
    assert secret not in caplog.text


@pytest.mark.parametrize(
    "kind", ["absent", "invalid", "foreign_workspace", "foreign_target", "foreign_id"]
)
def test_verification_ids_and_authentication_do_not_cross_scopes(v2, target_data, kind):
    client = v2[1]
    owner = prepare(v2, target_data)
    other = target_data[1]
    challenge = issue(client, owner).json()["challenge"]
    root = owner["verifications"]
    headers = (
        {}
        if kind == "absent"
        else {"Authorization": "Bearer invalid"}
        if kind == "invalid"
        else other["headers"]
    )
    if kind == "foreign_target":
        root = root.replace(owner["target"]["id"], other["target"]["id"])
    if kind == "foreign_id":
        root = other["base"] + "/" + other["target"]["id"] + "/verifications"
    expected = 401 if kind in {"absent", "invalid"} else 404
    assert client.get(root + "/" + challenge["id"], headers=headers).status_code == expected
    for action in ["revoke", "verify"]:
        assert (
            client.post(
                root + "/" + challenge["id"] + "/" + action,
                headers=headers,
                json={"expected_version": 1},
            ).status_code
            == expected
        )


def test_viewer_can_read_metadata_but_cannot_issue_revoke_or_verify(v2, target_data, postgres):
    client = v2[1]
    owner = prepare(v2, target_data)
    viewer = target_data[1]
    challenge = issue(client, owner).json()["challenge"]
    with postgres.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                "VALUES(:w,:u,'viewer')"
            ),
            {"w": UUID(owner["workspace"]), "u": UUID(viewer["id"])},
        )
    assert client.get(owner["verifications"], headers=viewer["headers"]).status_code == 200
    assert (
        client.post(
            owner["verifications"],
            headers={**viewer["headers"], "Idempotency-Key": str(uuid4())},
            json={"expected_updated_at": owner["target"]["updated_at"]},
        ).status_code
        == 404
    )
    for action in ["revoke", "verify"]:
        assert (
            client.post(
                owner["verifications"] + "/" + challenge["id"] + "/" + action,
                headers=viewer["headers"],
                json={"expected_version": 1},
            ).status_code
            == 404
        )


@pytest.mark.parametrize(
    "field",
    ["proof_sha256", "origin", "state", "workspace_id", "control_verified", "resolver", "token"],
)
def test_client_cannot_submit_proof_state_scope_or_resolver(v2, target_data, field):
    client = v2[1]
    owner = prepare(v2, target_data)
    response = client.post(
        owner["verifications"],
        headers={**owner["headers"], "Idempotency-Key": str(uuid4())},
        json={
            "expected_updated_at": owner["target"]["updated_at"],
            field: "private-operator-secret",
        },
    )
    assert response.status_code == 422 and "private-operator-secret" not in response.text


def test_issuance_concurrency_is_unique_and_durable(v2, target_data, postgres):
    client = v2[1]
    owner = prepare(v2, target_data)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: issue(client, owner), range(5)))
    assert sorted(response.status_code for response in results) == [201, 409, 409, 409, 409]
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM vulntrack_verification.challenges WHERE workspace_id=:w"
                ),
                {"w": UUID(owner["workspace"])},
            )
            == 1
        )


@pytest.mark.parametrize("matching", [True, False])
def test_lab_evidence_is_durable_single_use_and_never_real_verification(
    v2, target_data, postgres, matching
):
    app, client = v2
    owner = prepare(v2, target_data)
    issued = issue(client, owner).json()
    challenge = issued["challenge"]
    attempt = uuid4()
    params = lab_params(owner, challenge, attempt)
    lab_transaction(postgres, app, owner, CLAIM, params)
    with pytest.raises(DBAPIError):
        lab_transaction(postgres, app, owner, CLAIM, {**params, "attempt": uuid4()})
    digest = hashlib.sha256(issued["instructions"]["body"].encode()).hexdigest()
    if not matching:
        digest = ("0" if digest[0] != "0" else "1") + digest[1:]
    lab_transaction(postgres, app, owner, FINISH, {**params, "digest": digest})
    with pytest.raises(DBAPIError):
        lab_transaction(postgres, app, owner, FINISH, {**params, "digest": digest})
    result = client.get(
        owner["verifications"] + "/" + challenge["id"], headers=owner["headers"]
    ).json()
    assert result["state"] == "failed" and not result["control_verified"]
    assert result["attempts"] == 1 and result["verified_at"] is None
    assert result["evidence"][0]["provenance"] == "laboratory"
    assert result["evidence"][0]["outcome"] == (
        "laboratory_match" if matching else "proof_mismatch"
    )
    assert "received_sha256" not in str(result)


def test_consumption_concurrency_has_one_winner(v2, target_data, postgres):
    app, client = v2
    owner = prepare(v2, target_data)
    challenge = issue(client, owner).json()["challenge"]

    def claim(_):
        try:
            lab_transaction(postgres, app, owner, CLAIM, lab_params(owner, challenge, uuid4()))
            return True
        except DBAPIError:
            return False

    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(claim, range(5)))
    assert outcomes.count(True) == 1


def test_revocation_wins_against_inflight_persisted_claim(v2, target_data, postgres):
    app, client = v2
    owner = prepare(v2, target_data)
    issued = issue(client, owner).json()
    challenge = issued["challenge"]
    params = lab_params(owner, challenge, uuid4())
    lab_transaction(postgres, app, owner, CLAIM, params)
    response = client.post(
        owner["verifications"] + "/" + challenge["id"] + "/revoke",
        headers=owner["headers"],
        json={"expected_version": 2},
    )
    assert response.status_code == 200
    with pytest.raises(DBAPIError):
        lab_transaction(
            postgres,
            app,
            owner,
            FINISH,
            {
                **params,
                "digest": hashlib.sha256(issued["instructions"]["body"].encode()).hexdigest(),
            },
        )
    result = client.get(
        owner["verifications"] + "/" + challenge["id"], headers=owner["headers"]
    ).json()
    assert result["state"] == "revoked" and result["evidence"][0]["outcome"] == "revoked"
    assert result["verified_at"] is None


@pytest.mark.parametrize("change", ["declaration", "url", "membership"])
def test_scope_changes_invalidate_an_inflight_result(v2, target_data, postgres, change):
    app, client = v2
    owner = prepare(v2, target_data)
    issued = issue(client, owner).json()
    challenge = issued["challenge"]
    params = lab_params(owner, challenge, uuid4())
    actor = owner
    if change == "membership":
        other = target_data[1]
        with postgres.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                    "VALUES(:w,:u,'editor')"
                ),
                {"w": UUID(owner["workspace"]), "u": UUID(other["id"])},
            )
        actor = {**owner, "id": other["id"]}
    lab_transaction(postgres, app, actor, CLAIM, params)
    with postgres.begin() as connection:
        if change == "membership":
            other = target_data[1]
            connection.execute(
                text(
                    "UPDATE vulntrack.workspace_members SET role='viewer' "
                    "WHERE workspace_id=:w AND user_id=:u"
                ),
                {"w": UUID(owner["workspace"]), "u": UUID(other["id"])},
            )
        else:
            statement = (
                "UPDATE vulntrack.application_targets SET "
                + (
                    "url='https://other.example.com/'"
                    if change == "url"
                    else "authorization_reference='Changed declaration'"
                )
                + " WHERE id=:id"
            )
            connection.execute(text(statement), {"id": UUID(owner["target"]["id"])})
    if change == "membership":
        with pytest.raises(DBAPIError):
            lab_transaction(postgres, app, actor, FINISH, {**params, "digest": "a" * 64})
    else:
        lab_transaction(postgres, app, owner, FINISH, {**params, "digest": "a" * 64})
        row = client.get(
            owner["verifications"] + "/" + challenge["id"], headers=owner["headers"]
        ).json()
        assert row["effective_state"] == "revoked" and row["scope_invalidated"]
    with postgres.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT verified_at FROM vulntrack_verification.challenges WHERE id=:id"),
                {"id": UUID(challenge["id"])},
            )
            is None
        )


def test_expiry_is_enforced_by_postgresql_without_clock_bypass(v2, target_data, postgres):
    app, client = v2
    owner = prepare(v2, target_data)
    body = security.declaration(owner["target"])
    body["authorization_expires_at"] = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
    updated = client.patch(
        owner["base"] + "/" + owner["target"]["id"] + "/authorization",
        headers=owner["headers"],
        json=body,
    )
    assert updated.status_code == 200
    owner["target"] = updated.json()
    response = issue(client, owner)
    assert response.status_code == 201
    challenge = response.json()["challenge"]
    time.sleep(2.1)
    with pytest.raises(DBAPIError):
        lab_transaction(postgres, app, owner, CLAIM, lab_params(owner, challenge, uuid4()))
    result = client.get(
        owner["verifications"] + "/" + challenge["id"], headers=owner["headers"]
    ).json()
    assert result["effective_state"] == "expired" and result["state"] == "pending"
    assert (
        client.post(
            owner["verifications"] + "/" + challenge["id"] + "/verify",
            headers=owner["headers"],
            json={"expected_version": 1},
        ).status_code
        == 409
    )


@pytest.mark.parametrize(
    "role,query",
    [
        ("vulntrack_app", "SELECT proof_sha256 FROM vulntrack_verification.challenges"),
        ("vulntrack_app", "SELECT received_sha256 FROM vulntrack_verification.attempts"),
        ("vulntrack_app", "UPDATE vulntrack_verification.challenges SET state='verified'"),
        ("vulntrack_registration", "SELECT id FROM vulntrack_verification.challenges"),
        ("vulntrack_verification_lab", "DELETE FROM vulntrack_verification.attempts"),
    ],
)
def test_sql_roles_cannot_bypass_digest_privacy_or_mutation(postgres, role, query):
    with pytest.raises(DBAPIError) as error:
        with postgres.begin() as connection:
            connection.execute(text("SET LOCAL ROLE " + role))
            connection.execute(text(query))
    assert error.value.orig.sqlstate == "42501"


def test_forced_rls_has_no_unsigned_owner_bypass(v2, target_data, postgres):
    client = v2[1]
    owner = prepare(v2, target_data)
    issue(client, owner)
    with postgres.begin() as connection:
        connection.execute(text("SET LOCAL ROLE vulntrack_verification_owner"))
        assert (
            connection.scalar(text("SELECT count(*) FROM vulntrack_verification.challenges")) == 0
        )
    with postgres.connect() as connection:
        assert verify_verification_schema(connection)


def test_failed_audit_rolls_back_issuance_and_digest(v2, target_data, postgres):
    client = v2[1]
    owner = prepare(v2, target_data)
    with postgres.begin() as connection:
        connection.execute(
            text("""CREATE FUNCTION vulntrack_verification.fail_test_audit() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='verification.issued' THEN
            RAISE EXCEPTION 'controlled audit failure'; END IF; RETURN NEW; END $$;
            CREATE TRIGGER fail_test_audit BEFORE INSERT ON vulntrack.audit_events
            FOR EACH ROW EXECUTE FUNCTION vulntrack_verification.fail_test_audit();""")
        )
    try:
        response = issue(client, owner)
        assert response.status_code == 500
        assert set(response.json()) == {"error"}
        with postgres.connect() as connection:
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM vulntrack_verification.challenges "
                        "WHERE workspace_id=:w"
                    ),
                    {"w": UUID(owner["workspace"])},
                )
                == 0
            )
    finally:
        with postgres.begin() as connection:
            connection.execute(text("DROP TRIGGER fail_test_audit ON vulntrack.audit_events"))
            connection.execute(text("DROP FUNCTION vulntrack_verification.fail_test_audit()"))


def test_workspace_quota_is_transactional_and_revoke_does_not_reset_it(v2, target_data, postgres):
    client = v2[1]
    owner = prepare(v2, target_data)
    for _ in range(20):
        response = issue(client, owner)
        assert response.status_code == 201
        challenge = response.json()["challenge"]
        assert (
            client.post(
                owner["verifications"] + "/" + challenge["id"] + "/revoke",
                headers=owner["headers"],
                json={"expected_version": 1},
            ).status_code
            == 200
        )
    response = issue(client, owner)
    assert response.status_code == 429 and response.headers["retry-after"] == "60"


def test_context_is_cleared_on_reused_connection_after_rollback(v2, target_data):
    app, client = v2
    owner = prepare(v2, target_data)
    issue(client, owner)
    with pytest.raises(RuntimeError):
        with workspace_session(
            app.state.session_factory,
            app.state.settings,
            UUID(owner["id"]),
            UUID(owner["workspace"]),
        ) as session:
            assert (
                session.scalar(text("SELECT count(*) FROM vulntrack_verification.challenges")) == 1
            )
            raise RuntimeError("controlled rollback")
    with app.state.session_factory.begin() as session:
        assert session.scalar(text("SELECT vulntrack.current_workspace_id()")) is None
        assert session.scalar(text("SELECT count(*) FROM vulntrack_verification.challenges")) == 0
