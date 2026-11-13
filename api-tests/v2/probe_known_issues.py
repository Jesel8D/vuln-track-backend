"""Reproduce existing V2 defects without changing contracts, SQL or privileges."""

import importlib.util
import json
import secrets
import sys
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from app.core.config import Settings  # noqa: E402
from scripts.disposable_v2 import DisposableV2  # noqa: E402

module_spec = importlib.util.spec_from_file_location("fixture_runner", HERE / "run.py")
runner = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(runner)


def setup(client):
    credentials = {"username": "probe_" + uuid4().hex, "password": secrets.token_urlsafe(28)}
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 201
    login = client.post("/api/v1/auth/login", json=credentials)
    assert login.status_code == 200
    headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    workspace = client.get("/api/v2/workspaces", headers=headers).json()["items"][0][
        ("workspace_id")
    ]
    base = f"/api/v2/workspaces/{workspace}/applications"
    response = client.post(base, json={"name": "Probe aislado"}, headers=headers)
    assert response.status_code == 201
    application = response.json()["id"]
    base += f"/{application}"
    response = client.post(
        base + "/technologies",
        json={
            "product": "small_business_rv340_firmware",
            "vendor": "cisco",
            "version": ("1.0.0.33"),
        },
        headers=headers,
    )
    assert response.status_code == 201
    technology = response.json()["id"]
    path = base + f"/technologies/{technology}"
    response = client.put(
        path + "/cpe",
        json={"cpe_name_id": "c817e5ba-62c1-41e7-a15c-fb851fea761e", "expected_selected_cpe": None},
        headers=headers,
    )
    assert response.status_code == 200
    return headers, base, path


def main():
    evidence = []
    with DisposableV2("existing", sql_checks=False) as stack:
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=stack.environment["DATABASE_URL"],
            workspace_hmac_key=stack.environment["WORKSPACE_HMAC_KEY"],
            token_secret=stack.environment["TOKEN_SECRET"],
            registration_enabled=True,
            registration_attempts_per_minute=10,
            cve_worker_enabled=False,
        )
        app = runner.fixture_app(settings)
        with TestClient(app) as client:
            headers, base, path = setup(client)
            result = client.post(
                "/api/v2/workspaces",
                headers=headers | {"Idempotency-Key": str(uuid4())},
                json={"name": "Workspace adicional"},
            )
            assert result.status_code == 404 and result.json()["error"]["code"] == (
                "RESOURCE_NOT_FOUND"
            )
            evidence.append(
                {
                    "issue": "workspace-create-rls",
                    "expected_contract": 201,
                    "observed": 404,
                    "code": "RESOURCE_NOT_FOUND",
                    "sqlstate": "42501",
                    "detail": (
                        "INSERT workspaces ON CONFLICT RETURNING antes de membresía inicial"
                    ),
                }
            )
            assert (
                client.post(
                    path + "/analyses", headers=headers | {"Idempotency-Key": str(uuid4())}
                ).status_code
                == 201
            )
            runs = client.get(base + "/analyses", headers=headers).json()["items"]
            finding = client.get(
                base + f"/analyses/{runs[0]['id']}/findings", headers=headers
            ).json()["items"][0]
            result = client.patch(
                base + f"/findings/{finding['id']}",
                json={
                    "applicability": "undetermined",
                    "expected_updated_at": finding["updated_at"],
                },
                headers=headers,
            )
            assert result.status_code == 409 and result.json()["error"]["code"] == (
                "INTEGRITY_CONFLICT"
            )
            unchanged = client.get(
                base + f"/analyses/{runs[0]['id']}/findings", headers=headers
            ).json()["items"][0]
            assert unchanged["status"] == "open" and unchanged["applicability"] == ("potential")
            evidence.append(
                {
                    "issue": "undetermined-review",
                    "expected_schema": "Pydantic acepta undetermined",
                    "observed": 409,
                    "code": "INTEGRITY_CONFLICT",
                    "constraint": "app_findings_applicability_valid",
                    "rollback_verified": True,
                }
            )
        for name, options, constraint in [
            ("original-and", {"original_and": True}, "app_findings_applicability_valid"),
            ("or-original-title", {"original_title": True}, "app_findings_title_valid"),
        ]:
            with TestClient(runner.fixture_app(settings, **options)) as client:
                headers, base, path = setup(client)
                result = client.post(
                    path + "/analyses", headers=headers | {"Idempotency-Key": str(uuid4())}
                )
                assert (
                    result.status_code == 503
                    and result.json()["error"]["code"] == "NVD_PROCESSING_FAILED"
                )
                runs = client.get(base + "/analyses", headers=headers).json()["items"]
                assert (
                    len(runs) == 1
                    and runs[0]["status"] == "failed"
                    and runs[0]["failure_code"] == "PROCESSING_ERROR"
                )
                findings = client.get(
                    base + f"/analyses/{runs[0]['id']}/findings", headers=headers
                ).json()
                assert findings["items"] == []
                evidence.append(
                    {
                        "issue": name,
                        "expected_contract": 201,
                        "observed": 503,
                        "code": "NVD_PROCESSING_FAILED",
                        "constraint": constraint,
                        "history_status": "failed",
                        "failure_code": "PROCESSING_ERROR",
                        "findings": 0,
                    }
                )
    out = HERE / ".artifacts/known-issues.json"
    out.parent.mkdir(mode=0o700, exist_ok=True)
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    print("4 reproducciones confirmadas; esto no equivale a 4 funcionalidades correctas.")


if __name__ == "__main__":
    main()
