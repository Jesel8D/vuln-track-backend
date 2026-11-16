"""External LAB broker: disposable DB credentials never enter any network worker.

Periodically re-reads real API/RLS resources and publishes expiring lab snapshots.
This is not an operational permission issuer, migration or production scheduler.
"""

import threading
import time
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import Settings
from app.db.workspace_context import workspace_session
from app.main import create_app
from laboratory.phase2c.policy import LabPermit, require_lab_snapshot
from laboratory.phase2c.protocol import CONTROL_LEASE_SECONDS
from scripts.disposable_v2 import DisposableV2
from tests.integration.test_v2_registration import account


class LaboratoryBroker:
    def __init__(self, publish):
        self.publish = publish
        self.stack = DisposableV2("new", sql_checks=False)
        self.records = {}
        self.lock = threading.RLock()
        self.halt = threading.Event()
        self.thread = None
        self.refresh_count = 0
        self.error_count = 0
        self.scope_denials = 0
        self.maximum_refresh_seconds = 0

    def __enter__(self):
        self.stack.__enter__()
        try:
            self.settings = Settings(
                _env_file=None,
                environment="test",
                database_url=self.stack.environment["DATABASE_URL"],
                token_secret=self.stack.environment["TOKEN_SECRET"],
                workspace_hmac_key=self.stack.environment["WORKSPACE_HMAC_KEY"],
                registration_enabled=True,
                cve_worker_enabled=False,
            )
            self.app = create_app(self.settings)
            self.client = TestClient(self.app)
            self.client.__enter__()
            self.user = account(self.client)
            self.add_count = 0
            self.resume()
            return self
        except BaseException:
            self.stack.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        self.pause()
        try:
            self.client.__exit__(*args)
        finally:
            self.stack.__exit__(*args)

    def add(self, url, addresses, gateway_epoch, authority_epoch, *, ttl=8):
        if self.add_count and self.add_count % 15 == 0:
            self.user = account(self.client)  # Keep each owned workspace under its SQL quota.
        user = self.user
        self.add_count += 1
        root = f"/api/v2/workspaces/{user['workspace']}/applications"
        response = self.client.post(
            root, headers=user["headers"], json={"name": "DEMO Phase 2C isolated egress only"}
        )
        assert response.status_code == 201
        application = response.json()["id"]
        base = root + "/" + application + "/targets"
        response = self.client.post(base, headers=user["headers"], json={"url": url})
        assert response.status_code == 201
        target = response.json()
        target_path = base + "/" + target["id"]
        response = self.client.patch(
            target_path + "/authorization",
            headers=user["headers"],
            json={
                "authorization_status": "approved",
                "authorization_expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "authorization_reference": "DEMO controlled fixture only; not real domain control",
                "expected_updated_at": target["updated_at"],
            },
        )
        assert response.status_code == 200
        target = response.json()
        # The existing target DTO omits path scope; bind it from the checked
        # authenticated nested route, then cross-check the full challenge DTO.
        target = {**target, "workspace_id": user["workspace"], "application_id": application}
        response = self.client.post(
            target_path + "/verifications",
            headers={**user["headers"], "Idempotency-Key": str(uuid4())},
            json={"expected_updated_at": target["updated_at"]},
        )
        assert response.status_code == 201
        challenge = response.json()[
            "challenge"
        ]  # Deliberately discard one-time proof instructions.
        require_lab_snapshot(
            target,
            challenge,
            workspace=user["workspace"],
            application=application,
            actor=user["id"],
        )
        now = time.time()
        permit = LabPermit(
            operation_id=str(uuid4()),
            workspace_id=user["workspace"],
            application_id=application,
            target_id=target["id"],
            challenge_id=challenge["id"],
            actor_id=user["id"],
            gateway_epoch=gateway_epoch,
            authority_epoch=authority_epoch,
            url=target["url"],
            hostname=url.split("/")[2],
            scheme="https",
            port=443,
            addresses=tuple(sorted(addresses)),
            target_version=target["updated_at"],
            challenge_version=challenge["version"],
            issued_at=now,
            expires_at=now + ttl,
            declaration_expires_at=datetime.fromisoformat(
                target["authorization_expires_at"]
            ).timestamp(),
            challenge_expires_at=datetime.fromisoformat(challenge["expires_at"]).timestamp(),
        )
        with self.lock:
            self.records[permit.operation_id] = {
                "permit": permit,
                "user": user,
                "path": target_path,
                "challenge": challenge,
            }
        self.refresh()
        return permit

    def refresh(self):
        with self.lock:
            snapshot_started = time.time()
            policies = {}
            for operation, record in self.records.items():
                permit, user = record["permit"], record["user"]
                if permit.expires_at <= time.time():
                    continue
                try:
                    # Preserve the existing API: target reads use the scoped list.
                    t = self.client.get(record["path"].rsplit("/", 1)[0], headers=user["headers"])
                    c = self.client.get(
                        record["path"] + "/verifications/" + permit.challenge_id,
                        headers=user["headers"],
                    )
                    if t.status_code != 200 or c.status_code != 200:
                        continue
                    row = next(item for item in t.json()["items"] if item["id"] == permit.target_id)
                    target = {
                        **row,
                        "workspace_id": permit.workspace_id,
                        "application_id": permit.application_id,
                    }
                    challenge = c.json()
                    require_lab_snapshot(
                        target,
                        challenge,
                        workspace=permit.workspace_id,
                        application=permit.application_id,
                        actor=permit.actor_id,
                    )
                    with workspace_session(
                        self.app.state.session_factory,
                        self.settings,
                        UUID(permit.actor_id),
                        UUID(permit.workspace_id),
                    ) as session:
                        allowed = session.scalar(
                            text("SELECT vulntrack.has_workspace_role(:w,:r)"),
                            {"w": UUID(permit.workspace_id), "r": ["owner", "editor"]},
                        )
                    if (
                        allowed
                        and target["updated_at"] == permit.target_version
                        and target["url"] == permit.url
                        and challenge["version"] == permit.challenge_version
                    ):
                        policies[operation] = permit.to_dict()
                except (ValueError, StopIteration):
                    self.scope_denials += 1
                except Exception:
                    # No previous good entry is retained on an authorization/RLS/read failure.
                    self.error_count += 1
            # A slow read/publish cannot extend the lifetime of an old snapshot.
            self.publish(
                {"lease_until": snapshot_started + CONTROL_LEASE_SECONDS, "policies": policies}
            )
            self.maximum_refresh_seconds = max(
                self.maximum_refresh_seconds, time.time() - snapshot_started
            )
            self.refresh_count += 1

    def revoke(self, permit):
        record = self.records[permit.operation_id]
        response = self.client.post(
            record["path"] + "/verifications/" + permit.challenge_id + "/revoke",
            headers=record["user"]["headers"],
            json={"expected_version": permit.challenge_version},
        )
        assert response.status_code == 200
        self.refresh()

    def change_target(self, permit):
        record = self.records[permit.operation_id]
        response = self.client.patch(
            record["path"] + "/authorization",
            headers=record["user"]["headers"],
            json={
                "authorization_status": "rejected",
                "expected_updated_at": permit.target_version,
                "authorization_reference": "DEMO fixture declaration withdrawn",
            },
        )
        assert response.status_code == 200
        self.refresh()

    def blocked_operational(self, permit):
        record = self.records[permit.operation_id]
        response = self.client.post(
            record["path"] + "/verifications/" + permit.challenge_id + "/verify",
            headers=record["user"]["headers"],
            json={"expected_version": permit.challenge_version},
        )
        assert response.status_code == 503
        read = self.client.get(
            record["path"] + "/verifications/" + permit.challenge_id,
            headers=record["user"]["headers"],
        ).json()
        assert read["attempts"] == 0 and read["verified_at"] is None
        assert not read["control_verified"] and not read["execution_enabled"]

    def _loop(self):
        while not self.halt.wait(0.15):
            try:
                self.refresh()
            except Exception:
                self.error_count += (
                    1  # Last published lease expires instead of extending on failure.
                )

    def pause(self):
        self.halt.set()
        if self.thread is not None:
            self.thread.join(timeout=3)
            assert not self.thread.is_alive()
            self.thread = None

    def resume(self):
        self.halt.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
