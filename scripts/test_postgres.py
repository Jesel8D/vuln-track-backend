"""Run only against a new, disposable container; never accepts an existing DB URL."""

import hashlib
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

from sqlalchemy import URL

ROOT = Path(__file__).resolve().parents[1]
reference = Path(os.environ.get("DATABASE_V1_PATH", "../vuln-track-database")).resolve()
required = [
    "sql/001_schema.sql",
    "sql/002_privileges.sql",
    "seed/001_demo.sql",
    "tests/001_integrity.sql",
]
for name in required:
    if not (reference / name).is_file():
        sys.exit(f"Falta referencia Database V1: {name}; definir DATABASE_V1_PATH")
digests = {
    "sql/001_schema.sql": "fd2984a80911cd094283d9c9b1f503a7a0db87b921f9169c2a8362a8941b9297",
    "sql/002_privileges.sql": "46f0b4f0093fa579ee27e4e8e348d97d8fe5db515b6bbbef1aa7a479f67a3f2e",
    "seed/001_demo.sql": "ab2a079cfaf7f1800beb6103f1a34d5f480df2defd9c180f974342f49db097ef",
    "tests/001_integrity.sql": "cc9b373a3895e857ab2c6acb8e7f1e897786d7c1c2a165bb512e1ce079be1193",
}
for path, digest in digests.items():
    if hashlib.sha256((reference / path).read_bytes()).hexdigest() != digest:
        sys.exit(f"Referencia distinta a Database V1 b493fd1: {path}; revisar integración")
fresh_bootstrap = "--bootstrap-v11" in sys.argv
if fresh_bootstrap and "--catalog" in sys.argv:
    sys.exit("No se recaptura el catálogo V1 desde un bootstrap propuesto")
name = "vulntrack-backend-test-" + secrets.token_hex(6)
database = "vulntrack_backend_test"
password = secrets.token_urlsafe(32)
env = {**os.environ, "POSTGRES_PASSWORD": password}
image = (
    "postgres:16.15-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab"
)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def sql(source):
    return run(
        "docker",
        "exec",
        "-i",
        name,
        "psql",
        "-X",
        "-q",
        "-U",
        "postgres",
        "-d",
        database,
        "-v",
        "ON_ERROR_STOP=1",
        input=source,
    ).stdout


print(f"Contenedor desechable nuevo: {name}", flush=True)
try:
    run(
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        "vulntrack.disposable=true",
        "--tmpfs",
        "/var/lib/postgresql/data:rw",
        "-p",
        "127.0.0.1::5432",
        "-e",
        "POSTGRES_PASSWORD",
        "-e",
        f"POSTGRES_DB={database}",
        "-e",
        "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
        image,
        env=env,
    )
    for _ in range(90):
        result = subprocess.run(
            ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        time.sleep(0.5)
    else:
        sys.exit("PostgreSQL temporal no inició")
    print(sql("SELECT version();").strip(), flush=True)
    for source in required:
        if fresh_bootstrap and source.startswith("tests/"):
            print(
                "Integridad original V1 (5 FK): se ejecuta sin cambios en la ruta V1; "
                "la ruta propuesta verifica 6 FK mediante catálogo y pytest.",
                flush=True,
            )
            continue
        if fresh_bootstrap and source == "sql/001_schema.sql":
            from database_proposal import proposed_bootstrap

            content = proposed_bootstrap(reference)
        else:
            content = (reference / source).read_text()
        output = sql(content)
        if source.startswith("seed/") and fresh_bootstrap:
            sql(content)  # unmodified seed remains repeatable with NULL owners
        if source.startswith("tests/"):
            print("Integridad SQL referencia:", output.strip(), flush=True)
    sql(
        "CREATE ROLE backend_test_api LOGIN PASSWORD '" + password + "' "
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; "
        "GRANT vulntrack_app TO backend_test_api; "
        "GRANT SELECT(password_hash) ON vulntrack.users TO backend_test_api;"
    )
    port = run("docker", "port", name, "5432").stdout.strip().rsplit(":", 1)[1]

    def url(username):
        return URL.create(
            "postgresql+psycopg",
            username=username,
            password=password,
            host="127.0.0.1",
            port=int(port),
            database=database,
        ).render_as_string(hide_password=False)

    test_env = {
        **os.environ,
        "TEST_DATABASE_URL": url("postgres"),
        "TEST_APP_DATABASE_URL": url("backend_test_api"),
        "TEST_DISPOSABLE_DATABASE": name,
        "TEST_BOOTSTRAP_KIND": "proposed" if fresh_bootstrap else "migrated",
    }
    if fresh_bootstrap:
        adoption = subprocess.run(
            [sys.executable, "-m", "app.db.adopt_schema", "--confirm-proposal"],
            cwd=ROOT,
            env={**test_env, "MIGRATION_DATABASE_URL": url("postgres")},
        )
        if adoption.returncode:
            sys.exit(adoption.returncode)
    elif "--catalog" not in sys.argv:
        # Freeze a legacy copy for migration tests BEFORE any Alembic change.
        sql("CREATE DATABASE vulntrack_backend_test_v1 TEMPLATE vulntrack_backend_test;")
        migration = subprocess.run(
            [sys.executable, "-m", "alembic", "-x", "ownership_proposal=1", "upgrade", "head"],
            cwd=ROOT,
            env={**test_env, "MIGRATION_DATABASE_URL": url("postgres")},
        )
        if migration.returncode:
            sys.exit(migration.returncode)
    if "--catalog" in sys.argv:
        import json

        from sqlalchemy import create_engine

        from app.db.verify_schema import catalog

        engine = create_engine(url("postgres"))
        with engine.connect() as connection:
            (ROOT / "app/db/database_v1_catalog.json").write_text(
                json.dumps(catalog(connection), indent=2, ensure_ascii=False) + "\n"
            )
        engine.dispose()
        print("Catálogo capturado desde SQL de referencia; revisar diff.", flush=True)
    elif "--docker-smoke" in sys.argv:
        api_name = name + "-api"
        from uuid import uuid4

        from app.core.security import hash_password

        smoke_username = "smoke_" + secrets.token_hex(8)
        smoke_password = secrets.token_urlsafe(24)
        sql(
            "INSERT INTO vulntrack.users(id,username,password_hash,active) VALUES ('"
            + str(uuid4())
            + "','"
            + smoke_username
            + "','"
            + hash_password(smoke_password)
            + "',true);"
        )
        api_env = {
            **os.environ,
            "TOKEN_SECRET": secrets.token_urlsafe(48),
            "CORS_ORIGINS": '["http://localhost:5173"]',
            "SMOKE_USERNAME": smoke_username,
            "SMOKE_PASSWORD": smoke_password,
            "DATABASE_URL": URL.create(
                "postgresql+psycopg",
                username="backend_test_api",
                password=password,
                host="127.0.0.1",
                port=5432,
                database=database,
            ).render_as_string(hide_password=False),
        }
        try:
            run(
                "docker",
                "run",
                "--detach",
                "--name",
                api_name,
                "--network",
                "container:" + name,
                "-e",
                "DATABASE_URL",
                "-e",
                "TOKEN_SECRET",
                "-e",
                "SMOKE_USERNAME",
                "-e",
                "SMOKE_PASSWORD",
                "-e",
                "CORS_ORIGINS",
                os.environ.get("BACKEND_TEST_IMAGE", "vulntrack-backend:v1.3"),
                env=api_env,
            )
            smoke = """
import json, os, urllib.request, urllib.error, uuid
assert os.getuid() == 10001
base = "http://127.0.0.1:8000"
assert urllib.request.urlopen(base + "/health").status == 200
assert urllib.request.urlopen(base + "/ready").status == 200
origin = "http://localhost:5173"
preflight = urllib.request.Request(base + "/api/v1/assets", method="OPTIONS", headers={
    "Origin":origin, "Access-Control-Request-Method":"POST",
    "Access-Control-Request-Headers":"authorization,content-type,idempotency-key"})
with urllib.request.urlopen(preflight) as result:
    assert result.status == 200 and json.load(result) == {"status":"ok"}
    assert result.headers["Access-Control-Allow-Origin"] == origin
    assert result.headers.get("Access-Control-Allow-Credentials") is None
forbidden = urllib.request.Request(base + "/api/v1/assets", method="OPTIONS", headers={
    "Origin":"https://unlisted.example", "Access-Control-Request-Method":"POST"})
try:
    urllib.request.urlopen(forbidden)
    raise AssertionError("Unlisted origin accepted")
except urllib.error.HTTPError as error:
    assert error.code == 400 and error.headers.get("Access-Control-Allow-Origin") is None
    assert json.load(error)["error"]["code"] == "CORS_PREFLIGHT_DENIED"
def call(path, body=None, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {},
        data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    req.add_header("Origin", origin)
    with urllib.request.urlopen(req) as response:
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert response.headers.get("Access-Control-Allow-Credentials") is None
        assert "Location" in response.headers["Access-Control-Expose-Headers"]
        return response.status, json.load(response)
_, token = call("/api/v1/auth/login", {
    "username": os.environ["SMOKE_USERNAME"], "password": os.environ["SMOKE_PASSWORD"]})
headers = {"Authorization": "Bearer " + token["access_token"], "Idempotency-Key": str(uuid.uuid4())}
body = {"device_type":"router","manufacturer":"Smoke",
        "model":"Example","version":"1","site_label":"LAB"}
status, asset = call("/api/v1/assets", body, headers)
assert status == 201
assert call("/api/v1/assets", body, headers) == (201, asset)
assert call("/api/v1/assets/" + asset["id"], headers=headers) == (200, asset)
_, page = call("/api/v1/assets", headers=headers)
assert page["items"] == [asset] and page["page"]["total"] == 1
print("V1.3: UID 10001; preflight allowed 200/denied 400; CORS login/create/replay/get/list OK")
"""
            for _ in range(30):
                result = subprocess.run(
                    ["docker", "exec", api_name, "python", "-c", smoke],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    print(result.stdout.strip(), flush=True)
                    break
                time.sleep(0.5)
            else:
                sys.exit("Smoke del contenedor falló; revisar configuración sin exponer secretos")
        finally:
            subprocess.run(["docker", "stop", "--time", "10", api_name], capture_output=True)
    else:
        arguments = [arg for arg in sys.argv[1:] if arg != "--bootstrap-v11"]
        if fresh_bootstrap:
            # These same real API tests run on BOTH installation paths. The legacy-only
            # readiness test is covered in the full migrated suite, never changed/hidden.
            arguments = [
                "tests/integration/test_postgres.py",
                "tests/integration/test_ownership.py",
                "tests/integration/test_client_contract.py",
                "tests/integration/test_browser_http_contract.py",
                "-k",
                "not v11_readiness_rejects_unmigrated_v1",
                *arguments,
            ]
        result = subprocess.run(
            [sys.executable, "-m", "pytest", *arguments], cwd=ROOT, env=test_env
        )
        sys.exit(result.returncode)
finally:
    # This exact container was allocated above with a cryptographically random name and tmpfs.
    subprocess.run(["docker", "stop", "--time", "10", name], capture_output=True)
    print(
        f"Detenido: {name}; datos tmpfs desechados, sin tocar volúmenes persistentes.", flush=True
    )
