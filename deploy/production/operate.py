#!/usr/bin/env python3
"""Explicit production operations; new runtime/volumes, no automatic data migration."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1]
DB = "vulntrack"
ROLE = "vulntrack_v2_api"
TABLES = {
    "products": "mode,cpe_name_id",
    "summary": "mode",
    "feed_imports": "digest",
    "feed_quarantine": "digest,cpe_name_id",
    "sync_runs": "id",
}
os.umask(0o077)


def private(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n" if not isinstance(value, str) else value)
    path.chmod(0o600)


class Operations:
    def __init__(self, runtime):
        self.root = runtime.resolve()
        self.meta = json.loads((self.root / "installation.json").read_text())
        if self.meta["runtime"] != str(self.root) or not re.fullmatch(
            r"vulntrack-prod-[a-f0-9]{10}", self.meta["project"]
        ):
            raise RuntimeError("Invalid owned production runtime")

    def run(self, args, data=None):
        r = subprocess.run(args, input=data, capture_output=True)
        if r.returncode:
            with (self.root / "operation-errors.log").open("ab") as log:
                log.write(r.stderr)
            raise RuntimeError(
                "Operation failed; inspect protected operation-errors.log; never reset volumes"
            )
        return r.stdout

    def compose(self, *args):
        return self.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(self.root / "compose.env"),
                "-f",
                str(HERE / "compose.yaml"),
                "-f",
                str(self.root / "network-subnets.yaml"),
                *args,
            ]
        )

    def container(self, service):
        value = self.compose("ps", "-q", service).decode().strip()
        if not value:
            raise RuntimeError("Owned service is not running")
        info = json.loads(self.run(["docker", "inspect", value]))[0]
        if info["Config"]["Labels"].get("com.docker.compose.project") != self.meta["project"]:
            raise RuntimeError("Service belongs to another project")
        return value

    def sql(self, service, query, user="postgres"):
        return (
            self.run(
                [
                    "docker",
                    "exec",
                    "-i",
                    self.container(service),
                    "psql",
                    "-XqAtw",
                    "-U",
                    user,
                    "-d",
                    DB,
                    "-v",
                    "ON_ERROR_STOP=1",
                ],
                query.encode(),
            )
            .decode()
            .strip()
        )

    def empty(self, service):
        if (
            self.sql(
                service,
                "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema');",
            )
            != "0"
        ):
            raise RuntimeError("Destination is not EMPTY; refusing initialization/restore")

    def migrate(self):
        self.compose("run", "--rm", "migrate")
        if (
            self.sql("postgres", "SELECT version_num FROM public.alembic_verification_version;")
            != "v2_0010_cve_cache"
        ):
            raise RuntimeError("Unexpected verification migration head")

    def create_login(self):
        value = json.loads((self.root / "credentials.json").read_text())["api_password"]
        self.sql(
            "postgres",
            f"CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{value}';",
        )

    def settings(self):
        values = json.loads((self.root / "credentials.json").read_text())
        hmac = self.sql(
            "postgres", "SELECT encode(hmac_key,'hex') FROM vulntrack_private.context_keys;"
        )
        if not re.fullmatch("[0-9a-f]{64}", hmac):
            raise RuntimeError("Missing workspace HMAC")
        self.sql(
            "postgres",
            f"REVOKE ALL ON DATABASE {DB} FROM PUBLIC; GRANT vulntrack_app,vulntrack_registration TO {ROLE}; GRANT SELECT(password_hash) ON vulntrack.users TO {ROLE}; GRANT CONNECT ON DATABASE {DB} TO {ROLE};",
        )
        data = {
            "environment": "production",
            "database_url": self.url("postgres", ROLE, values["api_password"]),
            "token_secret": values["token_secret"],
            "token_ttl_seconds": 300,
            "workspace_hmac_key": hmac,
            "cpe_catalog_read_url": self.url(
                "catalog", "vulntrack_catalog_reader", values["reader_password"]
            ),
            "cors_origins": [self.meta["origin"]],
            "cors_allow_credentials": False,
            "registration_enabled": True,
            "nvd_mode": "disabled",
            "cve_live_enabled": False,
            "cve_worker_enabled": False,
            "login_attempts_per_minute": 10,
            "db_pool_size": 5,
            "db_max_overflow": 0,
        }
        private(self.root / "api-settings.json", data)
        self.compose("run", "--rm", "--no-deps", "prepare")

    @staticmethod
    def url(host, user, password):
        return f"postgresql+psycopg://{user}:{quote(password, safe='')}@{host}:5432/{DB}?sslmode=verify-full&sslrootcert=/run/tls/ca.crt"

    def initialize(self, database):
        self.compose("up", "-d", "--wait", "postgres", "catalog")
        self.empty("postgres")
        manifest = json.loads((BACKEND / "app/db/v2_source_manifest.json").read_text())["sources"]
        for relative, digest in manifest.items():
            if hashlib.sha256((database / relative).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Canonical Database source drift")
        for name in [
            "001_schema.sql",
            "002_privileges.sql",
            "004_v2_application_model.sql",
            "005_v2_nvd_evidence.sql",
            "006_self_service_registration.sql",
            "007_v2_stabilization.sql",
        ]:
            self.sql("postgres", (database / "sql" / name).read_text())
        self.migrate()
        self.create_login()
        self.settings()
        if self.sql("postgres", "SELECT count(*) FROM vulntrack.users;") != "0":
            raise RuntimeError("Fresh production installation must not contain accounts")
        print(
            "PASS new private database, v10, non-admin API role; no users or private data imported"
        )

    def restore_cpe(self, directory):
        m = json.loads((directory / "manifest.json").read_text())
        if m["format"] != 2 or set(m["tables"]) != set(TABLES) or m["official"] != 1880952:
            raise RuntimeError("Unsupported official catalogue backup")
        for name, info in m["files"].items():
            path = directory / name
            if Path(name).name != name or path.is_symlink() or path.stat().st_size != info["bytes"]:
                raise RuntimeError("Unsafe catalogue backup entry")
            if hashlib.file_digest(path.open("rb"), "sha256").hexdigest() != info["sha256"]:
                raise RuntimeError("Catalogue checksum mismatch")
        self.empty("catalog")
        self.sql("catalog", (directory / "catalogo-preambulo.sql").read_text())
        self.run(
            [
                "docker",
                "exec",
                "-i",
                self.container("catalog"),
                "pg_restore",
                "-U",
                "postgres",
                "-d",
                DB,
                "--no-owner",
                "--no-acl",
                "--single-transaction",
                "--exit-on-error",
            ],
            (directory / "catalogo-cpe.dump").read_bytes(),
        )
        self.sql("catalog", (directory / "catalogo-consultas-local.sql").read_text())
        self.sql("catalog", "VACUUM (ANALYZE,PARALLEL 0) vulntrack_catalog.products;")
        fingerprints = {}
        for table, order in TABLES.items():
            sql = f"BEGIN READ ONLY; SET LOCAL TIME ZONE 'UTC'; COPY (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') FROM vulntrack_catalog.{table} t ORDER BY {order}) TO STDOUT; ROLLBACK;"
            process = subprocess.Popen(
                [
                    "docker",
                    "exec",
                    self.container("catalog"),
                    "psql",
                    "-Xqw",
                    "-U",
                    "postgres",
                    "-d",
                    DB,
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-c",
                    sql,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            digest = hashlib.sha256()
            while chunk := process.stdout.read(1024 * 1024):
                digest.update(chunk)
            if process.wait() or digest.hexdigest() != m["fingerprints"][table]:
                raise RuntimeError("Catalogue fingerprint mismatch")
            fingerprints[table] = digest.hexdigest()
        password = json.loads((self.root / "credentials.json").read_text())["reader_password"]
        role = "vulntrack_catalog_reader"
        self.sql(
            "catalog",
            f"REVOKE ALL ON DATABASE {DB} FROM PUBLIC; CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}'; GRANT CONNECT ON DATABASE {DB} TO {role}; GRANT USAGE ON SCHEMA vulntrack_catalog TO {role}; GRANT SELECT ON vulntrack_catalog.products,vulntrack_catalog.summary,vulntrack_catalog.sync_runs,vulntrack_catalog.feed_imports TO {role}; ALTER ROLE {role} IN DATABASE {DB} SET default_transaction_read_only=on; ALTER ROLE {role} IN DATABASE {DB} SET statement_timeout='2s';",
        )
        if (
            self.sql(
                "catalog",
                "SELECT count(*) FROM vulntrack_catalog.products WHERE mode='live' AND source='nvd-feed';",
            )
            != "1880952"
        ):
            raise RuntimeError("Catalogue count mismatch")
        private(
            self.root / "catalogue-result.json",
            {
                "result": "passed",
                "project": self.meta["project"],
                "official": 1880952,
                "fingerprints": fingerprints,
                "backup_sha256": m["files"]["catalogo-cpe.dump"]["sha256"],
            },
        )
        print("PASS official catalogue restored, five fingerprints match, new readonly reader")

    def backup(self):
        directory = (
            self.root
            / "backups"
            / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
        )
        directory.mkdir(parents=True, mode=0o700)
        raw = self.run(
            [
                "docker",
                "exec",
                self.container("postgres"),
                "pg_dump",
                "-Fc",
                "-U",
                "postgres",
                "-d",
                DB,
            ]
        )
        (directory / "database.dump").write_bytes(raw)
        private(
            directory / "manifest.json",
            {
                "kind": "vulntrack-production-private-v1",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "head": "v2_0010_cve_cache",
            },
        )
        print("PASS private backup created in a new protected directory:", directory.name)

    def restore_private(self, archive):
        manifest = json.loads(archive.with_name("manifest.json").read_text())
        if (
            manifest.get("kind") != "vulntrack-production-private-v1"
            or manifest.get("head") != "v2_0010_cve_cache"
            or hashlib.file_digest(archive.open("rb"), "sha256").hexdigest() != manifest["sha256"]
        ):
            raise RuntimeError(
                "Not a verified production backup; personal database migration is not authorized"
            )
        self.compose("up", "-d", "--wait", "postgres", "catalog")
        self.empty("postgres")
        for role in [
            "vulntrack_app",
            "vulntrack_registration",
            "vulntrack_verification_owner",
            "vulntrack_verification_lab",
        ]:
            self.sql(
                "postgres",
                f"CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;",
            )
        self.create_login()
        self.run(
            [
                "docker",
                "exec",
                "-i",
                self.container("postgres"),
                "pg_restore",
                "-U",
                "postgres",
                "-d",
                DB,
                "--single-transaction",
                "--exit-on-error",
            ],
            archive.read_bytes(),
        )
        self.settings()
        self.migrate()
        print(
            "PASS production backup restored only into EMPTY new database; new infrastructure credentials"
        )


def generate(args):
    root = args.runtime.resolve()
    if root.exists():
        raise RuntimeError("Runtime must be NEW; existing secrets/volumes are never overwritten")
    if any(
        root.is_relative_to(BACKEND.parent / name)
        for name in [
            "vuln-track-backend",
            "vuln-track-frontend",
            "vuln-track-database",
            "vuln-track-context",
        ]
    ):
        raise RuntimeError("Keep private runtime OUTSIDE code repositories")
    if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", args.email) or any(
        not 1 <= p <= 65535 for p in (args.http_port, args.https_port)
    ):
        raise RuntimeError("Invalid email or port")
    u = urlsplit(args.origin)
    if (
        u.scheme != "https"
        or not u.hostname
        or not re.fullmatch(r"[a-z0-9.-]+", u.hostname)
        or u.path
        or u.query
        or u.fragment
        or u.username
    ):
        raise RuntimeError("Canonical HTTPS origin required")
    root.mkdir(mode=0o700, parents=True)
    project = "vulntrack-prod-" + secrets.token_hex(5)
    private(
        root / "installation.json",
        {"project": project, "runtime": str(root), "origin": args.origin},
    )
    values = {
        name: secrets.token_urlsafe(48)
        for name in ["api_password", "reader_password", "token_secret"]
    }
    private(root / "credentials.json", values)
    for name in ["postgres", "catalog"]:
        private(root / (name + "-password"), secrets.token_urlsafe(48))

    def ssl(*items):
        result = subprocess.run(["openssl", *items], cwd=root, capture_output=True)
        if result.returncode:
            raise RuntimeError("Local TLS material generation failed")

    ssl(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "365",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        "-subj",
        "/CN=VulnTrack private database CA",
    )
    for host in ["postgres", "catalog"]:
        d = root / host
        d.mkdir(mode=0o700)
        ssl(
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            host + "/server.key",
            "-out",
            host + "/server.csr",
            "-subj",
            "/CN=" + host,
        )
        (d / "server.ext").write_text(
            "subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n"
        )
        ssl(
            "x509",
            "-req",
            "-in",
            host + "/server.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "90",
            "-out",
            host + "/server.crt",
            "-extfile",
            host + "/server.ext",
        )
    for p in root.rglob("*"):
        if p.is_file():
            p.chmod(0o600)
    (root / "ca.crt").chmod(0o644)
    private(
        root / "migration-url",
        Operations.url("postgres", "postgres", (root / "postgres-password").read_text()),
    )
    private(
        root / "compose.env",
        f"COMPOSE_PROJECT_NAME={project}\nRUNTIME_DIR={root}\nSITE_HOST={u.hostname}\nPUBLIC_ORIGIN={args.origin}\nACME_EMAIL={args.email}\nPUBLIC_BIND=127.0.0.1\nHTTP_PORT={args.http_port}\nHTTPS_PORT={args.https_port}\nTLS_MODE={'internal' if args.tls_internal else ''}\n",
    )
    ids = subprocess.check_output(["docker", "network", "ls", "-q"], text=True).split()
    used = []
    for network in json.loads(subprocess.check_output(["docker", "network", "inspect", *ids])):
        for config in network.get("IPAM", {}).get("Config") or []:
            if config.get("Subnet") and ":" not in config["Subnet"]:
                used.append(ipaddress.ip_network(config["Subnet"]))
    routes = json.loads(subprocess.check_output(["ip", "-j", "route"], text=True))
    for route in routes:
        if route.get("dst", "default") != "default":
            try:
                used.append(ipaddress.ip_network(route["dst"], strict=False))
            except ValueError:
                pass
    chosen = []
    for i in range(250):
        candidate = ipaddress.ip_network(f"10.246.{i}.0/24")
        if not any(candidate.overlaps(n) for n in used):
            chosen.append(str(candidate))
            used.append(candidate)
        if len(chosen) == 3:
            break
    if len(chosen) != 3:
        raise RuntimeError(
            "No safe private Docker subnets available; choose ranges explicitly, never prune"
        )
    private(
        root / "network-subnets.yaml",
        "networks:\n"
        + "".join(
            f"  {name}:\n    ipam:\n      config:\n        - subnet: {network}\n"
            for name, network in zip(["edge", "private_db", "private_catalog"], chosen, strict=True)
        ),
    )
    print(
        "PASS new private production runtime; credentials not printed; TLS keys are transport-only, not NVD approvals"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "action",
        choices=[
            "generate",
            "build",
            "init-db",
            "restore-cpe",
            "up",
            "stop",
            "status",
            "migrate",
            "backup",
            "restore-private",
            "configure",
        ],
    )
    p.add_argument("--runtime", required=True, type=Path)
    p.add_argument("--origin", default="https://vulntrack.example.org")
    p.add_argument("--email", default="operator@example.org")
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--https-port", type=int, default=443)
    p.add_argument("--tls-internal", action="store_true")
    p.add_argument("--database", type=Path, default=BACKEND.parent / "vuln-track-database")
    p.add_argument("--directory", type=Path)
    p.add_argument("--archive", type=Path)
    p.add_argument("--registration", choices=["on", "off"])
    p.add_argument("--cve-live", choices=["on", "off"])
    p.add_argument("--rotate-token", action="store_true")
    a = p.parse_args()
    if a.action == "generate":
        return generate(a)
    s = Operations(a.runtime)
    if a.action == "build":
        s.compose("build", "prepare", "proxy")
        print("PASS images built")
    elif a.action == "init-db":
        s.initialize(a.database.resolve())
    elif a.action == "restore-cpe":
        if not a.directory:
            p.error("--directory required")
        s.restore_cpe(a.directory.resolve())
    elif a.action == "restore-private":
        if not a.archive:
            p.error("--archive required")
        s.restore_private(a.archive.resolve())
    elif a.action == "up":
        receipt = json.loads((s.root / "catalogue-result.json").read_text())
        if receipt.get("result") != "passed" or receipt.get("project") != s.meta["project"]:
            raise RuntimeError("Restore and verify the catalogue before exposing the proxy")
        s.compose("up", "-d", "--wait", "api", "proxy")
        print("PASS production services healthy")
    elif a.action == "stop":
        s.compose("stop")
        print("PASS services stopped; volumes retained")
    elif a.action == "status":
        print(s.compose("ps").decode())
    elif a.action == "migrate":
        s.migrate()
        print("PASS explicit maintenance migration")
    elif a.action == "backup":
        s.backup()
    elif a.action == "configure":
        if a.registration is None and a.cve_live is None and not a.rotate_token:
            p.error("Select --registration on/off, --cve-live on/off or --rotate-token")
        values = json.loads((s.root / "api-settings.json").read_text())
        if a.registration is not None:
            values["registration_enabled"] = a.registration == "on"
        if a.cve_live is not None:
            enabled = a.cve_live == "on"
            values["nvd_mode"] = "live" if enabled else "disabled"
            values["cve_live_enabled"] = enabled
            values["cve_worker_enabled"] = enabled
        if a.rotate_token:
            values["token_secret"] = secrets.token_urlsafe(48)
            credentials = json.loads((s.root / "credentials.json").read_text())
            credentials["token_secret"] = values["token_secret"]
            private(s.root / "credentials.json", credentials)
        private(s.root / "api-settings.json", values)
        s.compose("run", "--rm", "--no-deps", "prepare")
        s.compose("up", "-d", "--no-deps", "--force-recreate", "--wait", "api")
        print(
            "PASS explicit configuration applied to this installation only; old JWTs expire normally unless token rotation was requested"
        )


if __name__ == "__main__":
    main()
