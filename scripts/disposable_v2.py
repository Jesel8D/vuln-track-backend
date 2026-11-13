"""Owned tmpfs PostgreSQL only. Shared by API tests and the real browser launcher."""

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from importlib.resources import files
from pathlib import Path

from sqlalchemy import URL

ROOT = Path(__file__).resolve().parents[1]
IMAGE = (
    "postgres:16.15-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab"
)
SOURCES = json.loads(files("app.db").joinpath("v2_source_manifest.json").read_text())["sources"]


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        # Never propagate CalledProcessError with SQL, database URLs or environment values.
        raise RuntimeError(
            f"Disposable command failed ({Path(args[0]).name}, exit {result.returncode})"
        )
    return result


class DisposableV2:
    def __init__(self, installation="existing", *, sql_checks=True):
        if installation not in {"existing", "new"}:
            raise ValueError("Unknown installation path")
        self.installation, self.sql_checks = installation, sql_checks
        self.reference = Path(
            os.environ.get("DATABASE_V2_PATH", ROOT.parent / "vuln-track-database")
        )
        self.name = "vulntrack-backend-test-v2-" + secrets.token_hex(6)
        self.password = secrets.token_urlsafe(32)
        self.database = "vulntrack_backend_test"
        self.created = False

    def sql(self, source):
        return run(
            "docker",
            "exec",
            "-i",
            self.name,
            "psql",
            "-XqAt",
            "-U",
            "postgres",
            "-d",
            self.database,
            "-v",
            "ON_ERROR_STOP=1",
            input=source,
        )

    def apply(self, relative):
        return self.sql((self.reference / relative).read_text())

    def migrate(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-x",
                "ownership_proposal=1",
                "-x",
                "mvp_a=1",
                "upgrade",
                "head",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "MIGRATION_DATABASE_URL": self.url("postgres")},
        )
        if result.returncode:
            raise RuntimeError("Verified Alembic upgrade failed; no credentials printed")

    def url(self, username):
        return URL.create(
            "postgresql+psycopg",
            username=username,
            password=self.password,
            host="127.0.0.1",
            port=self.port,
            database=self.database,
        ).render_as_string(hide_password=False)

    def __enter__(self):
        for relative, digest in SOURCES.items():
            if hashlib.sha256((self.reference / relative).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Database V2 source drift: " + relative)
        try:
            run(
                "docker",
                "run",
                "--rm",
                "-d",
                "--name",
                self.name,
                "--label",
                "vulntrack.disposable=true",
                "--tmpfs",
                "/var/lib/postgresql/data:rw",
                "-p",
                "127.0.0.1::5432",
                "-e",
                "POSTGRES_PASSWORD",
                "-e",
                f"POSTGRES_DB={self.database}",
                "-e",
                "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
                IMAGE,
                env={**os.environ, "POSTGRES_PASSWORD": self.password},
            )
            self.created = True
            for _ in range(120):
                ready = subprocess.run(
                    [
                        "docker",
                        "exec",
                        self.name,
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-U",
                        "postgres",
                    ],
                    capture_output=True,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Disposable PostgreSQL not ready")
            self.port = int(
                run("docker", "port", self.name, "5432").stdout.strip().rsplit(":", 1)[1]
            )
            self.apply("sql/001_schema.sql")
            self.apply("sql/002_privileges.sql")
            # Keep an untouched V1 template for all existing migration regressions.
            self.apply("seed/001_demo.sql")
            self.apply("seed/001_demo.sql")
            if self.sql_checks:
                integrity = self.apply("tests/001_integrity.sql")
                print(
                    f"tests/001_integrity.sql: {len(re.findall(r'ok - ', integrity.stderr))} "
                    "SQL checks passed before migrations",
                    flush=True,
                )
            self.sql("CREATE DATABASE vulntrack_backend_test_v1 TEMPLATE vulntrack_backend_test;")
            if self.installation == "existing":
                self.migrate()
            self.apply("sql/004_v2_application_model.sql")
            self.apply("sql/005_v2_nvd_evidence.sql")
            self.apply("sql/006_self_service_registration.sql")
            if self.installation == "new":
                # Bootstrap's V2 objects are verified in full before baseline; no blind stamp.
                self.migrate()
            if self.sql_checks:
                for relative in (
                    "tests/002_v2_security.sql",
                    "tests/004_v2_workspace_bootstrap.sql",
                    "tests/005_self_service_privileges.sql",
                ):
                    result = self.apply(relative)
                    print(
                        f"{relative}: {len(re.findall(r'ok - ', result.stderr))} SQL checks passed",
                        flush=True,
                    )
            self.sql(
                "CREATE ROLE backend_test_api LOGIN PASSWORD '" + self.password + "' "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; "
                "GRANT vulntrack_app,vulntrack_registration TO backend_test_api; "
                "GRANT SELECT(password_hash) ON vulntrack.users TO backend_test_api;"
            )
            key = self.sql(
                "SELECT encode(hmac_key,'hex') FROM vulntrack_private.context_keys;"
            ).stdout.strip()
            self.environment = {
                "DATABASE_URL": self.url("backend_test_api"),
                "WORKSPACE_HMAC_KEY": key,
                "TOKEN_SECRET": secrets.token_urlsafe(48),
                "REGISTRATION_ENABLED": "true",
                "CVE_WORKER_ENABLED": "false",
                "ENVIRONMENT": "test",
                "TEST_DATABASE_URL": self.url("postgres"),
                "TEST_APP_DATABASE_URL": self.url("backend_test_api"),
                "TEST_DISPOSABLE_DATABASE": self.name,
                "TEST_V2_ENABLED": "1",
                "TEST_V2_INSTALLATION": self.installation,
            }
            print(f"Disposable V2 ready ({self.installation}): {self.name}", flush=True)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.created:
            subprocess.run(["docker", "stop", "--time", "5", self.name], capture_output=True)
            print("Owned tmpfs PostgreSQL stopped; no persistent volumes used", flush=True)
