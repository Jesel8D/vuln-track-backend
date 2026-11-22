"""Restore an authenticated archive into a fresh, networkless, no-swap RAM volume."""

import argparse
import json
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scripts.disposable_v2 import IMAGE
from scripts.rc24_backup import DB, GIB, RecoveryError, check, load_data, postgres

DATA = "/var/lib/postgresql/data"
ROLES = """
CREATE ROLE vulntrack_app NOLOGIN;
CREATE ROLE vulntrack_registration NOLOGIN;
CREATE ROLE vulntrack_verification_owner NOLOGIN;
CREATE ROLE vulntrack_verification_lab NOLOGIN;
CREATE ROLE vulntrack_v2_api LOGIN NOSUPERUSER NOBYPASSRLS;
"""


def run(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        raise RecoveryError(f"RAM drill failed during {args[1]}")
    return result.stdout


def sql(name, query):
    return run(*postgres(name, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-c", query))


def preflight(size):
    ram = next(
        int(row.split()[1]) * 1024
        for row in Path("/proc/meminfo").read_text().splitlines()
        if row.startswith("MemAvailable:")
    )
    if shutil.disk_usage("/mnt/c").free < 2_500_000_000 or not Path("/mnt/c").is_mount():
        raise RecoveryError("C: must retain at least 2.5 GB free during the WSL2 drill")
    volume_bytes = 2 * size + GIB
    container_bytes = volume_bytes + GIB
    if volume_bytes > 7 * GIB:
        raise RecoveryError("Archive exceeds the 7 GiB RAM volume budget")
    if (
        min(ram, int(run("docker", "info", "--format", "{{.MemTotal}}")))
        < container_bytes + 3 * GIB
    ):
        raise RecoveryError("Not enough RAM for the archive and host reserve")
    return volume_bytes, container_bytes


def drill(directory, key):
    manifest = check(directory, key)
    volume_bytes, container_bytes = preflight(manifest["database_bytes"])
    token = secrets.token_hex(6)
    name = "vulntrack-v2-rc24-drill-" + token
    volume = "vulntrack_v2_rc24_drill_" + token
    run(
        "docker",
        "volume",
        "create",
        "--label",
        "vulntrack.rc24=ram-drill",
        "--driver",
        "local",
        "--opt",
        "type=tmpfs",
        "--opt",
        "device=tmpfs",
        "--opt",
        f"o=size={volume_bytes},noswap,uid=70,gid=70,mode=0700",
        volume,
    )
    run(
        "docker",
        "run",
        "-d",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--label",
        "vulntrack.rc24=ram-drill",
        "--network",
        "none",
        "--memory",
        str(container_bytes),
        "--memory-swap",
        str(container_bytes),
        "--log-driver",
        "none",
        "--mount",
        f"type=volume,src={volume},dst={DATA},volume-nocopy",
        "-e",
        f"POSTGRES_DB={DB}",
        "-e",
        "POSTGRES_HOST_AUTH_METHOD=trust",
        IMAGE,
        "postgres",
        "-c",
        "listen_addresses=",
        "-c",
        "max_wal_size=512MB",
        "-c",
        "maintenance_work_mem=128MB",
    )
    try:
        lines = run("docker", "exec", name, "cat", "/proc/self/mountinfo").decode().splitlines()
        if not any(DATA in row and " - tmpfs " in row and "noswap" in row for row in lines):
            raise RecoveryError("RAM volume with noswap was not verified")
        for _ in range(80):
            try:
                if (
                    run("docker", "exec", name, "cat", "/proc/1/comm").strip() == b"postgres"
                    and sql(
                        name, "SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'vulntrack%'"
                    )
                    == b"0\n"
                ):
                    break
            except RecoveryError:
                pass
            time.sleep(0.5)
        else:
            raise RecoveryError("New empty database did not become ready")
        sql(name, ROLES)
        begin = time.monotonic()
        load_data(name, directory, key, manifest)
        summary = sql(
            name,
            """
          SELECT coalesce(json_object_agg(mode,records),'{}'::json)
          FROM (SELECT mode,count(*) records FROM vulntrack_catalog.products GROUP BY mode) totals
        """,
        )
        return {
            "volume": volume,
            "catalog": json.loads(summary),
            "roles_and_rls": int(
                sql(name, "SELECT count(*) FROM pg_policies WHERE schemaname LIKE 'vulntrack%'")
            ),
            "database_bytes": int(sql(name, "SELECT pg_database_size(current_database())")),
            "seconds": round(time.monotonic() - begin, 2),
        }
    finally:
        run("docker", "stop", "--time", "10", name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    args = parser.parse_args()
    result = drill(args.directory.resolve(), args.key_file.absolute())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        message = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print("RC2.4 RAM drill:", message, file=sys.stderr)
        raise SystemExit(1) from None
