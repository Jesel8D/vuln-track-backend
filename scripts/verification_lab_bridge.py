"""Owned test-only DB broker. Network worker receives no SQL/HMAC/JWT secrets."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.core.config import Settings
from app.db.workspace_context import install_workspace_context
from app.main import create_app
from scripts.disposable_v2 import DisposableV2
from tests.integration.test_v2_registration import account


def run_persisted_lab(command, names, artifacts):
    with DisposableV2("new", sql_checks=False) as stack:
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=stack.environment["DATABASE_URL"],
            token_secret=stack.environment["TOKEN_SECRET"],
            workspace_hmac_key=stack.environment["WORKSPACE_HMAC_KEY"],
            registration_enabled=True,
            cve_worker_enabled=False,
        )
        engine = create_engine(stack.url("postgres"), hide_parameters=True)
        try:
            with TestClient(create_app(settings)) as client:
                user = account(client)
                root = f"/api/v2/workspaces/{user['workspace']}/applications"
                response = client.post(
                    root, headers=user["headers"], json={"name": "DEMO Phase 2B owned lab"}
                )
                assert response.status_code == 201
                application = response.json()["id"]
                base = root + "/" + application + "/targets"
                response = client.post(
                    base, headers=user["headers"], json={"url": "https://control.example.net/"}
                )
                assert response.status_code == 201
                target = response.json()
                response = client.patch(
                    base + "/" + target["id"] + "/authorization",
                    headers=user["headers"],
                    json={
                        "authorization_status": "approved",
                        "authorization_expires_at": (
                            datetime.now(UTC) + timedelta(hours=1)
                        ).isoformat(),
                        "authorization_reference": "DEMO laboratory only, not real domain control",
                        "expected_updated_at": target["updated_at"],
                    },
                )
                assert response.status_code == 200
                target = response.json()
                base += "/" + target["id"] + "/verifications"
                response = client.post(
                    base,
                    headers={**user["headers"], "Idempotency-Key": str(uuid4())},
                    json={"expected_updated_at": target["updated_at"]},
                )
                assert response.status_code == 201
                issued = response.json()
                identity = issued["challenge"]["id"]
                blocked = client.post(
                    base + "/" + identity + "/verify",
                    headers=user["headers"],
                    json={"expected_version": 1},
                )
                assert blocked.status_code == 503
                command("docker", "exec", names["fixture"], "test", "!", "-f", "/tmp/dns-count")
                command(
                    "docker",
                    "exec",
                    "-i",
                    names["fixture"],
                    "python",
                    "-c",
                    "import sys; from pathlib import Path; "
                    "Path('/tmp/proof').write_bytes(sys.stdin.buffer.read())",
                    data=issued["instructions"]["body"].encode(),
                )
                params = {
                    "w": UUID(user["workspace"]),
                    "a": UUID(application),
                    "t": UUID(target["id"]),
                    "id": UUID(identity),
                    "attempt": uuid4(),
                }
                with engine.begin() as connection:
                    connection.execute(text("SET LOCAL ROLE vulntrack_verification_lab"))
                    install_workspace_context(
                        connection, settings, UUID(user["id"]), UUID(user["workspace"])
                    )
                    connection.execute(
                        text(
                            "SELECT vulntrack_verification.claim_laboratory(:w,:a,:t,:id,:attempt)"
                        ),
                        params,
                    )
                result = command(
                    "docker",
                    "exec",
                    "-i",
                    names["worker"],
                    "python",
                    "-m",
                    "laboratory.phase2b.checks",
                    data=json.dumps({"url": issued["instructions"]["url"]}).encode(),
                    timeout=30,
                    check=False,
                )
                (artifacts / "dns-worker.log").write_bytes(result.stderr)
                if result.returncode:
                    diagnostic = command(
                        "docker",
                        "exec",
                        names["fixture"],
                        "python",
                        "-c",
                        "from pathlib import Path; p=Path('/tmp/dns-failure'); "
                        "print(p.read_text() if p.exists() else 'no fixture exception')",
                        check=False,
                    )
                    (artifacts / "dns-fixture.log").write_bytes(
                        diagnostic.stdout + diagnostic.stderr
                    )
                    raise RuntimeError("Owned DNS worker failed; see private dns-worker.log")
                report = json.loads(result.stdout)
                assert report["result"] == "passed"
                evidence = report.pop("evidence")
                with engine.begin() as connection:
                    connection.execute(text("SET LOCAL ROLE vulntrack_verification_lab"))
                    install_workspace_context(
                        connection, settings, UUID(user["id"]), UUID(user["workspace"])
                    )
                    connection.execute(
                        text("""SELECT vulntrack_verification.finish_laboratory(
                        :w,:a,:t,:id,:attempt,:received_sha256,
                        CAST(:peer_ip AS inet),:certificate_sha256)"""),
                        {**params, **evidence},
                    )
                stored = client.get(base + "/" + identity, headers=user["headers"]).json()
                assert (
                    stored["state"] == "failed" and stored["result_code"] == "LABORATORY_MATCH_ONLY"
                )
                assert stored["verified_at"] is None and not stored["control_verified"]
                assert not stored["execution_enabled"]
                assert stored["evidence"][0]["provenance"] == "laboratory"
                report["checks"].extend(
                    [
                        "real FastAPI issuance persisted through restricted API role and RLS",
                        "blocked operational verification created zero DNS requests",
                        "real DNS/TLS result consumed once through restricted lab SQL role",
                        "laboratory evidence persisted but NEVER represented as "
                        "verified domain control",
                    ]
                )
                return report
        finally:
            engine.dispose()
