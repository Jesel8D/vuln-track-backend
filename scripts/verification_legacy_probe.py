"""Read-only old-code probe, authorized exclusively by an owned test profile."""

import json
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url

import app
from app.core.config import Settings
from app.db.verify_schema import CVE_REVISION, verify_schema
from app.main import create_app

if __name__ == "__main__":
    profile = os.environ.get("VULNTRACK_VERIFICATION_TEST_PROFILE", "")
    if not profile.startswith("verification-test-"):
        raise RuntimeError("Owned verification test profile required")
    settings = Settings(_env_file=None)
    assert make_url(settings.database_url.get_secret_value()).port == int(
        os.environ["VULNTRACK_VERIFICATION_TEST_PORT"]
    )
    assert Path(app.__file__).resolve().is_relative_to(Path.cwd())
    data = json.load(sys.stdin)
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json=data["credentials"])
        assert login.status_code == 200
        headers = {"Authorization": "Bearer " + login.json()["access_token"]}
        directory = client.get("/api/v2/workspaces", headers=headers).json()["items"]
        assert len(directory) == 1 and directory[0]["workspace_id"] == data["workspace"]
        path = f"/api/v2/workspaces/{data['workspace']}/applications/{data['application']}/targets"
        targets = client.get(path, headers=headers)
        assert targets.status_code == 200 and targets.json()["items"][0]["id"] == data["target"]
        assert client.get("/ready").status_code == 200
        with client.app.state.engine.connect() as connection:
            assert verify_schema(connection,CVE_REVISION)
    print("Read-only legacy code probe passed")
