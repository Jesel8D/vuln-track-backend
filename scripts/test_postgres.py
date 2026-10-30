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
        output = sql((reference / source).read_text())
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
    }
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
        api_env = {
            **os.environ,
            "TOKEN_SECRET": secrets.token_urlsafe(48),
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
                "vulntrack-backend:v1",
                env=api_env,
            )
            smoke = (
                "import urllib.request,os; "
                "assert os.getuid()==10001; "
                "assert urllib.request.urlopen('http://127.0.0.1:8000/health').status==200; "
                "assert urllib.request.urlopen('http://127.0.0.1:8000/ready').status==200; "
                "print('Container smoke: UID 10001, health 200, ready PostgreSQL 200')"
            )
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
        result = subprocess.run(
            [sys.executable, "-m", "pytest", *sys.argv[1:]], cwd=ROOT, env=test_env
        )
        sys.exit(result.returncode)
finally:
    # This exact container was allocated above with a cryptographically random name and tmpfs.
    subprocess.run(["docker", "stop", "--time", "10", name], capture_output=True)
    print(
        f"Detenido: {name}; datos tmpfs desechados, sin tocar volúmenes persistentes.", flush=True
    )
