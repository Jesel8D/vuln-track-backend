"""Private stdin input. Stdout carries only identifiers and non-secret state."""

import json
import os
import sys
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def main():
    if not os.environ.get("VULNTRACK_OWNED_UPGRADE_PROBE", "").startswith("upgrade-"):
        raise RuntimeError("Use the isolated upgrade runner")
    data = json.load(sys.stdin)
    settings = Settings(_env_file=None)
    app = create_app(settings)
    with TestClient(app) as client:
        credentials = data["credentials"]

        def request(method, path, *, expected=200, body=None):
            response = client.request(method, path, json=body, headers=data.get("headers", {}))
            assert response.status_code == expected, "Unexpected upgrade probe status"
            return response.json()

        if "workspace" not in data:
            request("POST", "/api/v1/auth/register", expected=201, body=credentials)
        login = request("POST", "/api/v1/auth/login", body=credentials)
        data["headers"] = {"Authorization": "Bearer " + login["access_token"]}
        directory = request("GET", "/api/v2/workspaces")["items"]
        assert len(directory) == 1 and directory[0]["role"] == "owner"
        workspace = directory[0]["workspace_id"]
        if "workspace" in data:
            assert data["workspace"] == workspace
        data["workspace"] = workspace
        root = f"/api/v2/workspaces/{workspace}/applications"
        if "application" not in data:
            application = request(
                "POST", root, expected=201, body={"name": "DEMO upgrade rollback"}
            )
            data["application"] = application["id"]
            base = root + "/" + application["id"] + "/targets"
            target = request("POST", base, expected=201, body={"url": "https://app.example.com/"})
            target = request(
                "PATCH",
                base + "/" + target["id"] + "/authorization",
                body={
                    "authorization_status": "approved",
                    "authorization_reference": "DEMO declaration; not technical proof",
                    "authorization_expires_at": (
                        datetime.now(UTC) + timedelta(hours=1)
                    ).isoformat(),
                    "expected_updated_at": target["updated_at"],
                },
            )
            data["target"] = target["id"]
            data["target_version"] = target["updated_at"]
        assert request("GET", root)["items"][0]["id"] == data["application"]
        base = root + "/" + data["application"] + "/targets"
        target = request("GET", base)["items"][0]
        assert target["id"] == data["target"] and target["updated_at"] == data["target_version"]
        assert target["authorization_status"] == "approved"
        readiness = target.get("analysis_readiness")
        if data["expect_phase1"]:
            assert readiness["authorization_state"] == "verification_pending"
            assert not readiness["control_verified"] and not readiness["execution_enabled"]
            assert "WEB_EXECUTOR_DISABLED" in readiness["blocking_reasons"]
        else:
            assert readiness is None
        request("GET", "/ready")
        # The other workspace cannot see the preserved resource at any version.
        if "other" not in data:
            data["other"] = {
                "username": credentials["username"] + "_b",
                "password": credentials["password"],
            }
            request("POST", "/api/v1/auth/register", expected=201, body=data["other"])
        other_login = request("POST", "/api/v1/auth/login", body=data["other"])
        data["headers"] = {"Authorization": "Bearer " + other_login["access_token"]}
        response = client.get(base, headers=data["headers"])
        assert response.status_code == 404
        data.pop("headers")
    # Keep credentials in the parent. A pipe may still be captured by a shell or CI.
    print(
        json.dumps(
            {
                "workspace": data["workspace"],
                "application": data["application"],
                "target": data["target"],
                "target_version": data["target_version"],
                "other_registered": "other" in data,
            }
        )
    )


if __name__ == "__main__":
    main()
