"""Own a disposable PostgreSQL + fixture-only real HTTP API, optionally run Newman."""

import argparse
import json
import secrets
import socket
import subprocess
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import uvicorn
from sqlalchemy import event

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.core.config import Settings  # noqa: E402
from app.integrations.nvd import NVDClient, Quota  # noqa: E402
from app.integrations.nvd_cve import CVEClient  # noqa: E402
from app.main import create_app  # noqa: E402
from scripts.disposable_v2 import DisposableV2  # noqa: E402

HERE = Path(__file__).resolve().parent


class FixtureClock:
    """Advance spacing only for MockTransport; real authorization/SQL/quotas remain."""

    def __init__(self):
        self.value = time.monotonic()
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            self.value += 70
            return self.value


@contextmanager
def server(app, port):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))
        sock.listen(128)
        selected = sock.getsockname()[1]
        instance = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        thread = threading.Thread(target=instance.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 20
            while not instance.started:
                if not thread.is_alive() or time.monotonic() > deadline:
                    raise RuntimeError("API did not start")
                time.sleep(0.05)
            yield f"http://127.0.0.1:{selected}"
        finally:
            instance.should_exit = True
            thread.join(15)
            if thread.is_alive():
                raise RuntimeError("API did not stop")


def fixture_app(settings, *, original_and=False, original_title=False):
    # Only upstream HTTP is replaced. No endpoint overrides, no RLS bypass.
    cpe = json.loads((ROOT / "tests/fixtures/nvd_cpe_verified.json").read_text())
    cve = json.loads((ROOT / "tests/fixtures/nvd_cve_verified.json").read_text())
    if not original_and:
        # Explicitly SIMULATED OR derivative; the original verified AND is separately probed.
        cve = deepcopy(cve)
        if not original_title:
            cve["vulnerabilities"][0]["cve"]["descriptions"] = [
                {
                    "lang": "en",
                    "value": (
                        "Fixture SIMULADO OR de documentación; no afirma vulnerabilidad "
                        "de un sistema real."
                    ),
                }
            ]
        binding = cpe["products"][0]["cpe"]["cpeName"]
        cve["vulnerabilities"][0]["cve"]["configurations"] = [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": binding,
                                "matchCriteriaId": "8750a439-1d5f-4d40-9875-d5cd0c116c11",
                            }
                        ],
                    }
                ]
            }
        ]
    quota = Quota(clock=FixtureClock())

    def upstream(request):
        if request.url.host != "services.nvd.nist.gov":
            raise RuntimeError("Unexpected upstream origin")
        if request.url.path == "/rest/json/cpes/2.0":
            data = cpe
        elif request.url.path == "/rest/json/cves/2.0":
            data = cve
        else:
            raise RuntimeError("Unexpected upstream path")
        return httpx.Response(200, json=data)

    app = create_app(settings)

    @event.listens_for(app.state.engine, "handle_error")
    def diagnostic(context):
        error = context.original_exception
        info = getattr(error, "diag", None)
        # Public SQL operation/constraint only; never parameters, URLs or driver repr.
        print(
            "SQL diagnostic:",
            getattr(error, "sqlstate", None),
            getattr(info, "constraint_name", None),
            (context.statement or "").splitlines()[0][:100],
            flush=True,
        )

    app.state.nvd = NVDClient(transport=httpx.MockTransport(upstream), quota=quota)
    app.state.identifications.nvd = app.state.nvd
    app.state.cve = CVEClient(transport=httpx.MockTransport(upstream), quota=quota)
    app.state.cve_worker.client = app.state.cve
    return app


def expired_token(settings):
    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        {
            "sub": str(uuid4()),
            "jti": str(uuid4()),
            "iat": now - 120,
            "nbf": now - 120,
            "exp": now - 60,
            "iss": "vulntrack",
            "aud": "vulntrack-api",
            "ver": datetime.now(UTC).isoformat(),
        },
        settings.token_secret.get_secret_value(),
        algorithm="HS256",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", choices=["existing", "new"], default="existing")
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Keep fixture API for local Postman; Ctrl+C destroys its database",
    )
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    artifacts = HERE / ".artifacts"
    artifacts.mkdir(mode=0o700, exist_ok=True)
    with DisposableV2(args.installation) as stack:
        settings = Settings(
            _env_file=None,
            environment="test",
            database_url=stack.environment["DATABASE_URL"],
            workspace_hmac_key=stack.environment["WORKSPACE_HMAC_KEY"],
            token_secret=stack.environment["TOKEN_SECRET"],
            registration_enabled=True,
            registration_attempts_per_minute=10,
            registration_total_per_minute=100,
            cve_worker_enabled=True,
        )
        app = fixture_app(settings)
        disabled = fixture_app(
            settings.model_copy(update={"registration_enabled": False, "cve_worker_enabled": False})
        )
        with ExitStack() as servers:
            base = servers.enter_context(server(app, args.port if args.serve else 0))
            disabled_base = servers.enter_context(server(disabled, 0))
            # Verify live documentation, not just filesystem copies.
            with httpx.Client(trust_env=False) as client:
                for path in ["/docs", "/openapi.json", "/redoc"]:
                    response = client.get(base + path)
                    assert response.status_code == 200, path
                live = client.get(base + "/openapi.json").json()
                assert live == json.loads((HERE / "openapi.json").read_text()), "Regenerate OpenAPI"
            if args.serve:
                print(f"API de FIXTURES: {base}; Swagger {base}/docs", flush=True)
                print(f"API registro deshabilitado: {disabled_base}", flush=True)
                print(
                    (
                        "Postman: entorno test, disposable_confirmed=true, password "
                        "privado propio. Ctrl+C destruye datos."
                    ),
                    flush=True,
                )
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
                return 0
            data = {
                "base_url": base,
                "disabled_base_url": disabled_base,
                "password": secrets.token_urlsafe(28),
                "nvd_mode": "fixture",
                "disposable_confirmed": "true",
                "allow_live_nvd": "false",
                "expired_token": expired_token(settings),
                "installation": args.installation,
                "output": str(artifacts / f"{args.installation}.json"),
            }
            result = subprocess.run(
                ["node", str(HERE / "run-newman.cjs")], input=json.dumps(data), text=True, cwd=ROOT
            )
            return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
