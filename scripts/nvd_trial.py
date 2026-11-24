"""5C.2 isolated worker. Real adapter exists; an independently signed grant is required."""

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import time
from pathlib import Path
from threading import Event
from uuid import UUID, uuid4

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.core.config import Settings
from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.integrations.cve_transport import CVE_URL, HTTPPolicy, RequestBudget
from app.integrations.nvd_cve import CVEClient
from app.integrations.nvd_lab_authorization import authorize, denied
from app.integrations.nvd_lab_client import LabCVEClient, bind_lab
from app.integrations.nvd_lab_transport import NVDLabTransport, Pin
from app.main import create_app

CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
CPE_ID = "10e70f95-eb64-4262-a822-9055aab8fe76"
REAL_TRIAL_RELEASED = False  # Not an environment setting or a CLI bypass.


def public_plan():
    return {
        "provider": "NVD",
        "endpoint": CVE_URL,
        "cpe": CPE,
        "cpe_name_id": CPE_ID,
        "method": "GET",
        "params": {"cpeName": CPE, "startIndex": 0, "resultsPerPage": 20},
        "requests": 1,
        "pages": 1,
        "records": 20,
        "seconds": 20,
        "bytes": 2097152,
        "retries": 0,
        "redirects": 0,
        "concurrency": 1,
        "real_release_enabled": REAL_TRIAL_RELEASED,
        "authorization_required": [
            "provider",
            "endpoint",
            "cpe",
            "requests",
            "laboratory",
            "duration",
            "purpose",
            "plan_sha256",
            "official_access_evidence",
        ],
    }


class TrialClient(CVEClient):
    page_limit = 20

    def __init__(self, transport, cancelled=None):
        if not isinstance(transport, httpx.MockTransport):
            raise APIError(503, "CVE_LIVE_DISABLED", "Ensayo real bloqueado")
        super().__init__(
            transport=transport,
            source_kind="simulated",
            cache_namespace="trial:5c1r:apache",
            http_policy=HTTPPolicy(timeout=20),
        )
        self.budget = RequestBudget(requests=1, seconds=20, cancelled=cancelled)

    def page(self, cpe, start=0, limit=20, **kwargs):
        if cpe != CPE or start != 0 or limit != 20 or kwargs:
            raise APIError(502, "TRIAL_PLAN_MISMATCH", "Consulta fuera del plan")
        return super().page(cpe, start, limit, budget=self.budget)


def account(client):
    username, password = "trial_" + uuid4().hex, secrets.token_urlsafe(32)
    r = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201, "Synthetic registration failed"
    login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    workspace = client.get("/api/v2/workspaces", headers=headers).json()["items"][0]["workspace_id"]
    return {"id": r.json()["id"], "workspace": workspace, "headers": headers}


def rehearse(config, fixture, output, *, real=None, control=None):
    # This worker accepts only its private, newly created lab settings. It never
    # discovers .env, PersistentV2 profiles, catalogue URLs or ordinary credentials.
    if config.stat().st_size > 4096 or fixture is not None and fixture.stat().st_size > 2097152:
        raise ValueError("Bounded lab files required")
    data = json.loads(config.read_text())
    if set(data) != {"database_url", "token_secret", "workspace_hmac_key", "laboratory"}:
        raise ValueError("Unexpected lab settings")
    laboratory = data.pop("laboratory")
    if (real is None and not laboratory.startswith("vulntrack-5c1r-")) or (
        real is not None and laboratory != real.permit.plan["laboratory"]
    ):
        raise ValueError("Owned laboratory required")
    url = make_url(data["database_url"])
    if (url.host, url.port, url.database, url.username) != (
        ("postgres" if real is None else json.loads((control / "pg.json").read_text())["address"]),
        5432,
        "vulntrack_v2_development",
        "vulntrack_v2_api",
    ) or url.query:
        raise ValueError("Only isolated PostgreSQL endpoint allowed")
    settings = Settings(
        _env_file=None,
        **data,
        environment="test",
        cve_worker_enabled=False,
        registration_enabled=True,
        registration_total_per_minute=100,
    )
    cancelled = Event()
    previous = signal.signal(signal.SIGINT, lambda *_: cancelled.set())
    app = create_app(settings)
    original = fixture.read_bytes() if real is None else None
    requests = []

    def provider(request):
        assert str(request.url).split("?", 1)[0] == CVE_URL
        assert dict(request.url.params) == {
            "cpeName": CPE,
            "startIndex": "0",
            "resultsPerPage": "20",
        }
        assert "authorization" not in request.headers and "apiKey" not in request.headers
        requests.append(str(request.url))
        return httpx.Response(200, content=original, headers={"Content-Type": "application/json"})

    upstream = real or TrialClient(httpx.MockTransport(provider), cancelled)
    if real is None:
        app.state.cve = upstream
    else:
        upstream.budget.cancelled = cancelled
        bind_lab(app, upstream, data["database_url"])
    # Deny public/private socket destinations, including during cache reuse. The
    # container's internal bridge is a second independent external-egress barrier.
    attempts = []
    old_connect = socket.socket.connect
    allowed = {x[4][0] for x in socket.getaddrinfo(url.host, 5432, type=socket.SOCK_STREAM)}

    def connect(sock, address):
        if sock.family in {socket.AF_INET, socket.AF_INET6}:
            attempts.append((address[0], address[1]))
            if not (address[0] in allowed and address[1] == 5432) and not (
                real is not None
                and address[0] == real.transport.pin.address
                and address[1] == 443
                and not cancelled.is_set()
            ):
                raise AssertionError("Offline worker denies non-lab socket")
        return old_connect(sock, address)

    socket.socket.connect = connect
    try:
        if real is not None:
            try:
                real.prepare()  # TLS + bounded exchange + schema/privacy, once.
                original = real.last_response_bytes
                (output / "response.nvd.json").write_bytes(original)
            finally:
                (output / "close-egress").touch(mode=0o600)
            deadline = time.monotonic() + 3
            while not (control / "egress-closed").exists():
                if time.monotonic() >= deadline:
                    raise denied()
                time.sleep(0.05)
            cancelled.set()  # Local processing/cache cannot reopen the provider.

        def count():
            return len(requests) if real is None else real.transport.attempts

        expected_source = "simulated" if real is None else "live"
        with TestClient(app) as client:
            owner = account(client)
            other = account(client)
            base = f"/api/v2/workspaces/{owner['workspace']}/applications"
            r = client.post(base, headers=owner["headers"], json={"name": "Synthetic Apache trial"})
            assert r.status_code == 201
            base += "/" + r.json()["id"]
            r = client.post(
                base + "/technologies",
                headers=owner["headers"],
                json={"vendor": "apache", "product": "http_server", "version": "2.4.49"},
            )
            assert r.status_code == 201
            path = base + "/technologies/" + r.json()["id"]
            r = client.put(
                path + "/cpe",
                headers=owner["headers"],
                json={
                    "cpe_name_id": CPE_ID,
                    "mode": "live",
                    "part": "a",
                    "expected_selected_cpe": None,
                    "expected_confirmation_id": None,
                    "expected_cpe_name": CPE,
                    "reason": "Owned synthetic rehearsal",
                    "evidence": "Public record copied readonly from the verified NVD feed snapshot",
                },
            )
            assert r.status_code == 200, r.json()
            headers = owner["headers"] | {"Idempotency-Key": str(uuid4())}
            r = client.post(path + "/analyses", headers=headers)
            assert r.status_code == 201, r.json()
            first = r.json()
            assert first["provenance"]["cve_source"] == expected_source
            assert first["storage"]["resolution"] == "provider" and count() == 1
            findings = client.get(
                base + "/analyses/" + first["id"] + "/findings", headers=owner["headers"]
            ).json()
            assert len(findings["items"]) <= 20
            complete = first["coverage"] == "complete"
            # Close provider capability *before* the second intent, not after hit.
            cancelled.set()
            if complete:
                second = client.post(
                    path + "/analyses", headers=owner["headers"] | {"Idempotency-Key": str(uuid4())}
                )
                assert second.status_code == 201, second.json()
                hit = second.json()
                assert hit["storage"]["resolution"] == "reused" and count() == 1
                assert hit["storage"]["obtained_at"] == first["storage"]["obtained_at"]
                assert hit["storage"]["expires_at"] == first["storage"]["expires_at"]
                assert hit["provenance"] == first["provenance"] or (
                    hit["provenance"]["response_received_at"]
                    == first["provenance"]["response_received_at"]
                )
            assert (
                client.get(base + "/analyses/" + first["id"], headers=other["headers"]).status_code
                == 404
            )
            with workspace_session(
                app.state.session_factory, settings, UUID(other["id"]), UUID(other["workspace"])
            ) as db:
                assert db.scalar(text("SELECT count(*) FROM vulntrack_cve_cache.responses")) == 0
            # Reuse creates a new intention without rewriting the first history.
            saved = client.get(base + "/analyses/" + first["id"], headers=owner["headers"]).json()
            assert saved["provenance"] == first["provenance"]
            assert saved["assessment"]["correspondence"] == "current"
            again = client.get(
                base + "/analyses/" + first["id"] + "/findings", headers=owner["headers"]
            ).json()
            assert again["items"] == findings["items"]
        assert upstream.last_response_bytes == original
        result = {
            "result": "passed",
            "plan": public_plan() if real is None else real.permit.plan,
            "source": expected_source,
            "external_requests": 0 if real is None else count(),
            "mock_requests": count() if real is None else 0,
            "mock_requests_after_hit": count() if real is None else 0,
            "cache_hit_checked": complete,
            "coverage": first["coverage"],
            "raw_sha256": hashlib.sha256(original).hexdigest(),
            "cache_hit_dates_unchanged": True if complete else None,
            "rls_other_workspace_denied": True,
            "history_unchanged_after_cache_hit": True if complete else None,
            "provider_closed_before_hit": cancelled.is_set(),
            "socket_destinations_only_lab_pg": all(a in allowed and p == 5432 for a, p in attempts)
            if real is None
            else None,
            "real_receipt": {
                "grant_sha256": real.permit.grant_sha256,
                "peer_ip": real.transport.pin.address,
                "tls_verified": real.transport.peer_verified,
                "transport": real.transport.evidence,
            }
            if real is not None
            else None,
        }
        output.mkdir(mode=0o700, exist_ok=True)
        (output / ("response.simulated.json" if real is None else "response.nvd.json")).write_bytes(
            original
        )
        (output / "rehearsal.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        socket.socket.connect = old_connect
        signal.signal(signal.SIGINT, previous)
        cancelled.set()
        app.state.engine.dispose()


def execute_real(args):
    from app.integrations import nvd_lab_authorization as policy

    if policy.TRUSTED_AUTHORITY_SHA256 is None:
        raise denied()  # Before all config, auth file, DB, DNS or quota I/O.
    if not all(
        [
            args.config,
            args.plan_file,
            args.authorization_record,
            args.output,
            args.control,
            args.image_id,
        ]
    ):
        raise denied()
    commit = Path("/app/REVIEWED_COMMIT").read_text().strip()
    permit = authorize(
        args.plan_file,
        args.authorization_record,
        commit=commit,
        image=args.image_id.read_text().strip(),
    )
    pin = json.loads((args.control / "pin.json").read_text())
    adapter = NVDLabTransport(permit, Pin(**pin))
    try:
        return rehearse(
            args.config,
            None,
            args.output,
            real=LabCVEClient(adapter, Event()),
            control=args.control,
        )
    except APIError as error:
        (args.output / "failure.json").write_text(
            json.dumps(
                {
                    "result": "failed",
                    "code": error.code,
                    "http_attempts": adapter.attempts,
                    "transport": adapter.evidence,
                    "persistence": "not-certified-on-failure",
                }
            )
            + "\n"
        )
        raise
    finally:
        (args.output / "close-egress").touch(mode=0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline", "real"], required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--authorization-record", type=Path)
    parser.add_argument("--plan-file", type=Path)
    parser.add_argument("--control", type=Path)
    parser.add_argument("--image-id", type=Path)
    args = parser.parse_args()
    if args.mode == "real":
        try:
            execute_real(args)
            return 0
        except APIError:
            print(
                "NO-GO: real trial requires trusted documentary review and a signed one-use grant"
            )
            return 2
    os.umask(0o077)
    if not all([args.config, args.fixture, args.output]):
        parser.error("offline requires explicit owned config, fixture and output")
    rehearse(args.config, args.fixture, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
