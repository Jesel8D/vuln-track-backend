"""NEW persistent profiles only: SQL008 data, restart, restore and old-code reads."""

import hashlib
import json
import os
import secrets
import subprocess
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.db.workspace_context import install_workspace_context
from app.main import create_app
from scripts.v2_development import ROOT, PersistentV2
from tests.integration.test_v2_registration import account


def main():
    nonce = secrets.token_hex(5)
    stack = PersistentV2("verification-test-" + nonce, pg_port=0, api_port=0, web_port=0)
    restored = PersistentV2("verification-test-restore-" + nonce, pg_port=0, api_port=0, web_port=0)
    data = {}

    def probe(owned, *, restored_copy=False):
        settings = owned.settings(worker=False)
        with TestClient(create_app(settings)) as client:
            if not data:
                user = account(client)
                data.update(
                    credentials={"username": user["username"], "password": user["password"]},
                    workspace=user["workspace"],
                    user=user["id"],
                )
                headers = user["headers"]
                root = f"/api/v2/workspaces/{user['workspace']}/applications"
                response = client.post(
                    root, headers=headers, json={"name": "DEMO SQL008 persistence only"}
                )
                assert response.status_code == 201
                data["application"] = response.json()["id"]
                base = root + "/" + data["application"] + "/targets"
                response = client.post(
                    base, headers=headers, json={"url": "https://control.example.net/"}
                )
                assert response.status_code == 201
                target = response.json()
                data["target"] = target["id"]
                response = client.patch(
                    base + "/" + target["id"] + "/authorization",
                    headers=headers,
                    json={
                        "authorization_status": "approved",
                        "authorization_expires_at": (
                            datetime.now(UTC) + timedelta(hours=1)
                        ).isoformat(),
                        "authorization_reference": (
                            "DEMO local persistence, not real domain control"
                        ),
                        "expected_updated_at": target["updated_at"],
                    },
                )
                assert response.status_code == 200
                target = response.json()
                data["base"] = base + "/" + target["id"] + "/verifications"
                issued = client.post(
                    data["base"],
                    headers={**headers, "Idempotency-Key": str(uuid4())},
                    json={"expected_updated_at": target["updated_at"]},
                )
                assert issued.status_code == 201
                issued = issued.json()
                data["challenge"] = issued["challenge"]["id"]
                data["digest"] = hashlib.sha256(issued["instructions"]["body"].encode()).hexdigest()
                data["old_token"] = headers["Authorization"]
                params = {
                    "w": UUID(data["workspace"]),
                    "a": UUID(data["application"]),
                    "t": UUID(data["target"]),
                    "id": UUID(data["challenge"]),
                    "attempt": uuid4(),
                    "digest": data["digest"],
                }
                engine = create_engine(owned.url("postgres"), hide_parameters=True)
                try:
                    for statement in [
                        "SELECT vulntrack_verification.claim_laboratory(:w,:a,:t,:id,:attempt)",
                        "SELECT vulntrack_verification.finish_laboratory"
                        "(:w,:a,:t,:id,:attempt,:digest,NULL,NULL)",
                    ]:
                        with engine.begin() as connection:
                            connection.execute(text("SET LOCAL ROLE vulntrack_verification_lab"))
                            install_workspace_context(
                                connection, settings, UUID(data["user"]), UUID(data["workspace"])
                            )
                            connection.execute(text(statement), params)
                finally:
                    engine.dispose()
            login = client.post("/api/v1/auth/login", json=data["credentials"])
            assert login.status_code == 200
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            old = client.get("/api/v1/auth/me", headers={"Authorization": data["old_token"]})
            assert old.status_code == (401 if restored_copy else 200)
            response = client.get(data["base"] + "/" + data["challenge"], headers=headers)
            assert response.status_code == 200
            evidence = response.json()
            assert (
                evidence["state"] == "failed" and evidence["result_code"] == "LABORATORY_MATCH_ONLY"
            )
            assert (
                evidence["attempts"] == 1
                and evidence["verified_at"] is None
                and not evidence["control_verified"]
            )
            assert (
                evidence["evidence"][0]["provenance"] == "laboratory"
                and evidence["evidence"][0]["outcome"] == "laboratory_match"
            )
            with client.app.state.session_factory.begin() as session:
                install_workspace_context(
                    session, settings, UUID(data["user"]), UUID(data["workspace"])
                )
                assert (
                    session.scalar(text("SELECT count(*) FROM vulntrack_verification.challenges"))
                    == 1
                )
            return evidence

    def legacy(path, owned):
        settings = owned.settings(worker=False)
        environment = {
            **os.environ,
            "ENVIRONMENT": "test",
            "REGISTRATION_ENABLED": "true",
            "CVE_WORKER_ENABLED": "false",
            "DATABASE_URL": settings.database_url.get_secret_value(),
            "TOKEN_SECRET": settings.token_secret.get_secret_value(),
            "WORKSPACE_HMAC_KEY": settings.workspace_hmac_key.get_secret_value(),
            "VULNTRACK_VERIFICATION_TEST_PROFILE": owned.profile,
            "VULNTRACK_VERIFICATION_TEST_PORT": str(owned.config["pg_port"]),
        }
        program = (
            "import runpy; runpy.run_path("
            + repr(str(ROOT / "scripts/verification_legacy_probe.py"))
            + ",run_name='__main__')"
        )
        result = subprocess.run(
            [str(path / ".venv/bin/python"), "-c", program],
            cwd=path,
            env=environment,
            input=json.dumps(data),
            text=True,
            capture_output=True,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError("Owned read-only legacy probe failed; no secrets printed")

    try:
        stack.start_database()
        stack.bootstrap()
        expected = probe(stack)
        legacy(ROOT.parents[1] / "VulnTrack/vuln-track-backend", stack)
        legacy(ROOT.parents[1] / "VulnTrack-security-phase2a/vuln-track-backend", stack)
        assert probe(stack) == expected
        archive = stack.backup()
        stack.stop_database()
        stack.start_database()
        stack.bootstrap()
        assert probe(stack) == expected
        restored.restore(archive)
        assert probe(restored, restored_copy=True) == expected
        legacy(ROOT.parents[1] / "VulnTrack/vuln-track-backend", restored)
        stack.verify()
        restored.verify()
        report = {
            "result": "passed",
            "checks": [
                "durable challenge digest and laboratory provenance",
                "IDs, state, attempts and evidence dates identical after full database restart",
                "backup and restore into another NEW volume",
                "RLS remains enabled and forced",
                "old stable and Phase 2A code read compatible core without dropping extension data",
                "original JWT stable after restart and invalid after restore",
                "no laboratory evidence counted as real domain control",
            ],
            "source_volume": stack.volume,
            "restore_volume": restored.volume,
            "volumes_retained": True,
            "personal_database_used": False,
            "zap_executed": False,
        }
        output = ROOT / "api-tests/v2/.artifacts/phase2b/verification-persistence.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        for owned in [restored, stack]:
            if owned.check_owner("container", owned.name):
                owned.stop_database()


if __name__ == "__main__":
    main()
