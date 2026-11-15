"Owned V2 development only: named-volume PostgreSQL, verified bootstrap and local API/web."

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import URL, create_engine, text

from app.core.config import Settings
from app.db.verify_schema import CVE_REVISION, verify_schema
from app.main import create_app
from scripts.disposable_v2 import SOURCES

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "dev/v2/compose.yaml"
PURPOSE = "v2-development"
DB = "vulntrack_v2_development"
API_ROLE = "vulntrack_v2_api"
PROFILE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")


def command(args, *, data=None, env=None):
    result = subprocess.run(args, input=data, capture_output=True, env=env, cwd=ROOT)
    if result.returncode:
        raise RuntimeError(
            "".join(
                (
                    "Owned development command failed: ",
                    f"{Path(args[0]).name}",
                    " (",
                    f"{result.returncode}",
                    "); no secrets printed",
                )
            )
        )
    return result.stdout


def private_json(path, value):
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    temporary.replace(path)


def free_port(preferred=0):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", preferred))
        return sock.getsockname()[1]


def process_identity(pid):
    try:
        # starttime guards against terminating a reused process ID.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


class PersistentV2:
    def __init__(self, profile="development", *, pg_port=55434, api_port=8000, web_port=5173):
        if not PROFILE.fullmatch(profile):
            raise ValueError("Invalid development profile")
        self.profile = profile
        self.directory = ROOT / ".local" / profile
        self.path = self.directory / "config.json"
        self.reference = Path(
            os.environ.get("DATABASE_V2_PATH", ROOT.parent / "vuln-track-database")
        ).resolve()
        if self.path.exists():
            self.config = json.loads(self.path.read_text())
            if self.config["profile"] != profile:
                raise RuntimeError("Profile mismatch")
        else:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.directory, 0o700)
            self.config = {
                "profile": profile,
                "installation": secrets.token_hex(16),
                "project": "vulntrack-v2-" + profile,
                "container": "vulntrack-v2-" + profile + "-postgres",
                "volume": "vulntrack_v2_" + profile.replace("-", "_") + "_pgdata",
                "pg_port": free_port(pg_port),
                "api_port": free_port(api_port),
                "web_port": free_port(web_port),
                "phase": "new",
                "api_password": secrets.token_urlsafe(36),
                "token_secret": secrets.token_urlsafe(48),
            }
            self.save()
            fd = os.open(
                self.directory / "postgres.password", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(fd, "w") as stream:
                stream.write(secrets.token_urlsafe(48))
        self.name = self.config["container"]
        self.volume = self.config["volume"]
        self.owner_labels = {
            "io.vulntrack.purpose": PURPOSE,
            "io.vulntrack.installation": self.config["installation"],
        }

    def save(self):
        private_json(self.path, self.config)

    @contextmanager
    def lock(self):
        with (self.directory / "control.lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def inspect(self, kind, name):
        result = subprocess.run(["docker", kind, "inspect", name], capture_output=True)
        if result.returncode:
            # Distinguish absent resources from daemon/permission failures.
            command(["docker", "info", "--format", "{{.ServerVersion}}"])
            return None
        return json.loads(result.stdout)[0]

    def check_owner(self, kind, name):
        info = self.inspect(kind, name)
        if info:
            labels = (
                info.get("Config", {}).get("Labels", {})
                if kind == "container"
                else info.get("Labels", {})
            )
            if any(labels.get(k) != v for k, v in self.owner_labels.items()):
                raise RuntimeError(
                    "".join(
                        (
                            "Resource name belongs to another installation: ",
                            f"{kind}",
                            " ",
                            f"{name}",
                        )
                    )
                )
        return info

    def preflight(self, *, create_volume=False):
        for relative, digest in SOURCES.items():
            if hashlib.sha256((self.reference / relative).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Database source drift: " + relative)
        volume = self.check_owner("volume", self.volume)
        self.check_owner("container", self.name)
        self.check_owner("network", self.config["project"] + "_default")
        if volume is None:
            if not create_volume or self.config["phase"] != "new":
                raise RuntimeError(
                    "Owned persistent volume is missing; do not recreate initialized data"
                )
            args = ["docker", "volume", "create"]
            for key, value in self.owner_labels.items():
                args.extend(["--label", key + "=" + value])
            command(args + [self.volume])
        self.check_owner("volume", self.volume)

    def compose(self, *args):
        values = {
            "VT_PROJECT": self.config["project"],
            "VT_CONTAINER": self.name,
            "VT_VOLUME": self.volume,
            "VT_INSTALLATION": self.config["installation"],
            "VT_PG_PORT": str(self.config["pg_port"]),
            "VT_PASSWORD_FILE": str(self.directory / "postgres.password"),
        }
        env_file = self.directory / ".env"
        # Only resource metadata/secret FILE PATH, never password values.
        env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
        os.chmod(env_file, 0o600)
        return command(
            ["docker", "compose", "--env-file", str(env_file), "-f", str(COMPOSE), *args],
            env={**os.environ, **values},
        )

    def start_database(self):
        self.preflight(create_volume=True)
        info = self.check_owner("container", self.name)
        if not info or not info["State"]["Running"]:
            free_port(self.config["pg_port"])
        self.compose("up", "-d", "--wait", "postgres")
        self.check_owner("container", self.name)
        marker = (
            self.sql(
                "SELECT shobj_description(oid,'pg_database') FROM "
                "pg_database WHERE datname=current_database();"
            )
            .decode()
            .strip()
        )
        expected = "VulnTrack V2 development " + self.config["installation"]
        if marker and marker != expected:
            raise RuntimeError("Database installation marker mismatch")
        if not marker:
            if self.config["phase"] != "new":
                raise RuntimeError(
                    "Missing database marker; inspect ownership instead of resetting"
                )
            self.sql(f"COMMENT ON DATABASE {DB} IS '{expected}';")

    def sql(self, source):
        self.check_owner("container", self.name)
        return command(
            [
                "docker",
                "exec",
                "-i",
                self.name,
                "psql",
                "-XqAt",
                "-U",
                "postgres",
                "-d",
                DB,
                "-v",
                "ON_ERROR_STOP=1",
            ],
            data=source.encode(),
        )

    def url(self, user):
        password = (
            self.config["api_password"]
            if user == API_ROLE
            else (self.directory / "postgres.password").read_text()
        )
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=password,
            host="127.0.0.1",
            port=self.config["pg_port"],
            database=DB,
        ).render_as_string(hide_password=False)

    def api_role(self):
        # Random URL-safe password only; never accept SQL identifiers/passwords from HTTP.
        password = self.config["api_password"]
        self.sql(
            "".join(
                (
                    "CREATE ROLE ",
                    f"{API_ROLE}",
                    " LOGIN PASSWORD '",
                    f"{password}",
                    "' NOSUPERUSER NOCREATEDB NOCREATEROLE ",
                    "NOREPLICATION NOBYPASSRLS;",
                )
            )
        )

    def grant_api(self):
        self.sql(
            "".join(
                (
                    "REVOKE ALL ON DATABASE ",
                    f"{DB}",
                    " FROM PUBLIC; GRANT ",
                    "vulntrack_app,vulntrack_registration TO ",
                    f"{API_ROLE}",
                    "; GRANT SELECT(password_hash) ON vulntrack.users",
                    " TO ",
                    f"{API_ROLE}",
                    "; GRANT CONNECT ON DATABASE ",
                    f"{DB}",
                    " TO ",
                    f"{API_ROLE}",
                    ";",
                )
            )
        )

    def bootstrap(self):
        if self.config["phase"] == "ready":
            self.verify()
            return
        if self.config["phase"] != "new":
            raise RuntimeError(
                "Incomplete bootstrap/restore: preserve volume and inspect; no automatic reset"
            )
        if self.sql("SELECT to_regclass('vulntrack.users') IS NOT NULL;").decode().strip() != ("f"):
            raise RuntimeError("Database is not empty; refusing bootstrap")
        self.config["phase"] = "initializing"
        self.save()
        for relative in ["sql/001_schema.sql", "sql/002_privileges.sql"]:
            self.sql((self.reference / relative).read_text())
        # Actual existing route: V1 SQL -> verified Alembic 0001..0004 -> SQL004..007.
        env = {**os.environ, "MIGRATION_DATABASE_URL": self.url("postgres")}
        command(
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
            env=env,
        )
        for relative in [
            "sql/004_v2_application_model.sql",
            "sql/005_v2_nvd_evidence.sql",
            "sql/006_self_service_registration.sql",
            "sql/007_v2_stabilization.sql",
        ]:
            self.sql((self.reference / relative).read_text())
        self.api_role()
        self.grant_api()
        self.config["workspace_hmac_key"] = (
            self.sql("SELECT encode(hmac_key,'hex') FROM vulntrack_private.context_keys;")
            .decode()
            .strip()
        )
        self.config["phase"] = "ready"
        self.save()
        self.verify()

    def verify(self):
        self.preflight()
        engine = create_engine(self.url("postgres"), hide_parameters=True)
        try:
            with engine.connect() as connection:
                verify_schema(connection, CVE_REVISION)
                checks = [
                    connection.scalar(text("SELECT version_num FROM public.alembic_version"))
                    == CVE_REVISION
                ]
                checks.append(
                    connection.scalar(
                        text(

                                "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR"
                                " rolbypassrls OR rolreplication) FROM pg_roles WHERE "
                                "rolname=:role"

                        ),
                        {"role": API_ROLE},
                    )
                )
                checks.append(
                    connection.scalar(
                        text(

                                "SELECT NOT rolcanlogin AND NOT rolsuper AND NOT "
                                "rolbypassrls FROM pg_roles WHERE "
                                "rolname='vulntrack_registration'"

                        )
                    )
                )
                checks.append(
                    not connection.scalar(
                        text(
                            "SELECT pg_has_role('vulntrack_app','vulntrack_registration','MEMBER')"
                        )
                    )
                )
                checks.append(
                    not connection.scalar(
                        text(

                                "SELECT has_table_privilege(:role,'vulntrack_private.con"
                                "text_keys','SELECT')"

                        ),
                        {"role": API_ROLE},
                    )
                )
                checks.append(
                    connection.scalar(
                        text("SELECT count(*) FROM pg_policies WHERE schemaname='vulntrack'")
                    )
                    == 29
                )
                checks.append(
                    connection.scalar(
                        text(

                                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON "
                                "n.oid=c.relnamespace WHERE n.nspname IN "
                                "('vulntrack','vulntrack_private') AND "
                                "pg_get_userbyid(c.relowner)=:role"

                        ),
                        {"role": API_ROLE},
                    )
                    == 0
                )
                database_key = connection.scalar(
                    text("SELECT encode(hmac_key,'hex') FROM vulntrack_private.context_keys")
                )
                checks.append(
                    secrets.compare_digest(
                        database_key or "", self.config.get("workspace_hmac_key", "")
                    )
                )
                if not all(checks):
                    raise RuntimeError("Development schema, role or key verification failed")
        finally:
            engine.dispose()
        api_engine = create_engine(self.url(API_ROLE), hide_parameters=True)
        try:
            with api_engine.connect() as connection:
                if connection.scalar(text("SELECT current_user")) != API_ROLE:
                    raise RuntimeError("Unexpected development API role")
        finally:
            api_engine.dispose()
        return True

    def settings(self, *, worker=True):
        if self.config["phase"] != "ready":
            raise RuntimeError("Initialize owned development database first")
        return Settings(
            _env_file=None,
            environment="development",
            database_url=self.url(API_ROLE),
            token_secret=self.config["token_secret"],
            workspace_hmac_key=self.config["workspace_hmac_key"],
            registration_enabled=True,
            cve_worker_enabled=worker,
            cors_origins=[f"http://127.0.0.1:{self.config['web_port']}"],
        )

    def stop_database(self):
        self.preflight()
        self.compose("stop", "postgres")

    def backup(self):
        self.start_database()
        self.verify()
        destination = (
            self.directory
            / "backups"
            / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2))
        )
        destination.mkdir(mode=0o700, parents=True)
        archive = command(
            ["docker", "exec", self.name, "pg_dump", "-Fc", "-U", "postgres", "-d", DB]
        )
        path = destination / "database.dump"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(archive)
        metadata = {
            "format": 1,
            "sha256": hashlib.sha256(archive).hexdigest(),
            "source_volume": self.volume,
            "source_installation": self.config["installation"],
            "database": DB,
            "api_role": API_ROLE,
            "sources": SOURCES,
            "alembic_revision": CVE_REVISION,
        }
        private_json(destination / "manifest.json", metadata)
        return path

    def restore(self, archive):
        if self.config["phase"] != "new" or self.inspect("volume", self.volume) is not None:
            raise RuntimeError(
                "Restore requires a NEW profile and absent volume; never overwrite a database"
            )
        archive = archive.resolve()
        manifest = json.loads(archive.with_name("manifest.json").read_text())
        if (
            manifest["sources"] != SOURCES
            or manifest["database"] != DB
            or manifest["sha256"] != hashlib.sha256(archive.read_bytes()).hexdigest()
        ):
            raise RuntimeError("Backup manifest, source version or checksum mismatch")
        self.start_database()
        self.config["phase"] = "restoring"
        self.save()
        self.sql(
            "CREATE ROLE vulntrack_app NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE "
            "vulntrack_registration NOLOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS;"
        )
        self.api_role()
        # Full archive into an empty owned database: no --clean, DROP or source mutations.
        command(
            [
                "docker",
                "exec",
                "-i",
                self.name,
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "-U",
                "postgres",
                "-d",
                DB,
            ],
            data=archive.read_bytes(),
        )
        self.grant_api()
        self.config["workspace_hmac_key"] = (
            self.sql("SELECT encode(hmac_key,'hex') FROM vulntrack_private.context_keys;")
            .decode()
            .strip()
        )
        self.config["phase"] = "ready"
        self.save()
        self.verify()

    def stop_processes(self):
        path = self.directory / "runtime.json"
        if path.exists():
            processes = json.loads(path.read_text()).get("processes", [])
            for process in reversed(processes):
                if process_identity(process["pid"]) == process["starttime"]:
                    with suppress(ProcessLookupError):
                        os.killpg(process["pid"], signal.SIGTERM)

    def up(self, *, frontend=None, nvd_mode="fixture"):
        runtime = self.directory / "runtime.json"
        if runtime.exists():
            for process in json.loads(runtime.read_text()).get("processes", []):
                if process_identity(process["pid"]) == process["starttime"]:
                    raise RuntimeError("This development profile is already running")
        frontend = (
            frontend
            or Path(
                os.environ.get("VULNTRACK_FRONTEND_PATH", ROOT.parent / ("vuln-track-frontend"))
            )
        ).resolve()
        if not (frontend / "node_modules").is_dir():
            raise RuntimeError(
                "Frontend checkout with npm ci required; set VULNTRACK_FRONTEND_PATH"
            )
        free_port(self.config["api_port"])
        free_port(self.config["web_port"])
        with self.lock():
            self.start_database()
            self.bootstrap()
        processes = []
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "USER", "LANG", "SHELL", "TERM", "TZ"}
        }
        try:
            with (
                (self.directory / "api.log").open("ab") as api_log,
                (self.directory / "web.log").open("ab") as web_log,
            ):
                api_env = {
                    **env,
                    "VULNTRACK_V2_PROFILE": self.profile,
                    "VULNTRACK_V2_NVD_MODE": nvd_mode,
                }
                processes.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-m",
                            "uvicorn",
                            "scripts.v2_development:create_development_app",
                            "--factory",
                            "--host",
                            "127.0.0.1",
                            "--port",
                            str(self.config["api_port"]),
                            "--no-access-log",
                            "--no-proxy-headers",
                        ],
                        cwd=ROOT,
                        env=api_env,
                        stdout=api_log,
                        stderr=api_log,
                        start_new_session=True,
                    )
                )
                public_env = {
                    **env,
                    "VITE_API_URL": "".join(
                        ("http://127.0.0.1:", "".join(f"{self.config['api_port']}"))
                    ),
                }
                processes.append(
                    subprocess.Popen(
                        ["npm", "run", "dev", "--", "--port", str(self.config["web_port"])],
                        cwd=frontend,
                        env=public_env,
                        stdout=web_log,
                        stderr=web_log,
                        start_new_session=True,
                    )
                )
                private_json(
                    runtime,
                    {
                        "processes": [
                            {"pid": p.pid, "starttime": process_identity(p.pid)} for p in processes
                        ]
                    },
                )
                import httpx

                for url in [
                    f"http://127.0.0.1:{self.config['api_port']}/ready",
                    f"http://127.0.0.1:{self.config['web_port']}",
                ]:
                    deadline = time.monotonic() + 60
                    while True:
                        if any(p.poll() is not None for p in processes):
                            raise RuntimeError(
                                "Local service exited; inspect private api.log/web.log"
                            )
                        try:
                            if httpx.get(url, timeout=1, trust_env=False).status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        if time.monotonic() > deadline:
                            raise RuntimeError("Local readiness timeout")
                        time.sleep(0.25)
                print(
                    "".join(
                        (
                            "V2 PERSISTENTE: ",
                            f"{self.volume}",
                            "\nFrontend http://127.0.0.1:",
                            f"{self.config['web_port']}",
                            "/crear-cuenta\nSwagger http://127.0.0.1:",
                            f"{self.config['api_port']}",
                            "/docs\nNVD mode: ",
                            f"{nvd_mode}",
                            " (fixture = captured offline data). Ctrl+C stops",
                            " services, retains all data.",
                        )
                    ),
                    flush=True,
                )
                while all(p.poll() is None for p in processes):
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        with suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
            self.stop_database()
            private_json(runtime, {"processes": []})


def fixture_application(settings):
    path = ROOT / "api-tests/v2/run.py"
    spec = importlib.util.spec_from_file_location("v2_fixture_runtime", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fixture_app(settings, original_and=True)


def create_development_app():
    stack = PersistentV2(os.environ.get("VULNTRACK_V2_PROFILE", "development"))
    settings = stack.settings()
    return (
        fixture_application(settings)
        if os.environ.get("VULNTRACK_V2_NVD_MODE", "fixture") == "fixture"
        else create_app(settings)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init", "up", "stop", "status", "backup", ("restore")])
    parser.add_argument("--profile", default="development")
    parser.add_argument("--pg-port", type=int, default=55434)
    parser.add_argument("--api-port", type=int, default=8000)
    parser.add_argument("--web-port", type=int, default=5173)
    parser.add_argument("--frontend", type=Path)
    parser.add_argument("--nvd-mode", choices=["fixture", "live"], default="fixture")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    stack = PersistentV2(
        args.profile, pg_port=args.pg_port, api_port=args.api_port, web_port=args.web_port
    )
    if args.command == "up":
        stack.up(frontend=args.frontend, nvd_mode=args.nvd_mode)
    elif args.command == "stop":
        stack.stop_processes()
        stack.stop_database()
        print("Owned services stopped; named volume retained")
    elif args.command == "status":
        stack.preflight()
        print(
            json.dumps(
                {
                    "profile": stack.profile,
                    "volume": stack.volume,
                    "phase": stack.config["phase"],
                    "postgres_running": bool(
                        (stack.inspect("container", stack.name) or {})
                        .get("State", {})
                        .get("Running")
                    ),
                    "api_port": stack.config["api_port"],
                    "web_port": stack.config["web_port"],
                },
                indent=2,
            )
        )
    else:
        with stack.lock():
            if args.command == "restore":
                if not args.archive:
                    parser.error("--archive required")
                stack.restore(args.archive)
                print("Restored into NEW owned volume:", stack.volume)
            else:
                stack.start_database()
                stack.bootstrap()
                print("Backup:", stack.backup()) if args.command == "backup" else print(
                    "Persistent V2 initialized and verified:", stack.volume
                )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(f"V2 development stopped: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
