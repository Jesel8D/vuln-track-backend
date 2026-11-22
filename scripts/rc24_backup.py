"""Stream an authenticated PostgreSQL archive outside Docker; restore only to new storage."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.v2_development import DB, SOURCES, PersistentV2

GIB = 1024**3
PROFILE = "rc2-catalog24"
ARCHIVE = "database.dump.gpg"
BASE_SOURCES = {path: digest for path, digest in SOURCES.items() if not path.startswith("sql/013_")}


class RecoveryError(RuntimeError):
    """Operator-facing failure without subprocess output or private content."""


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path):
    if not path.is_file() or path.is_symlink():
        raise RecoveryError("Expected a regular file")
    return path.stat()


def gpg(work, key):
    mode = regular(key)
    if mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) & 0o077:
        raise RecoveryError("Keep the recovery key in an owner-only Linux file")
    if not 32 <= mode.st_size <= 128:
        raise RecoveryError("Expected an independent high-entropy recovery key")
    return [
        "gpg",
        "--no-options",
        "--homedir",
        work,
        "--batch",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--no-symkey-cache",
        "--passphrase-file",
        str(key),
    ]


def postgres(name, program, *args, stdin=False):
    return [
        "docker",
        "exec",
        *(["-i"] if stdin else []),
        name,
        program,
        "-U",
        "postgres",
        "-d",
        DB,
        *args,
    ]


def pipe(left, right, output, *, source=None):
    with subprocess.Popen(
        left,
        stdin=source,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as producer:
        try:
            with subprocess.Popen(
                right,
                stdin=producer.stdout,
                stdout=output,
                stderr=subprocess.DEVNULL,
            ) as consumer:
                producer.stdout.close()
                consumer_status = consumer.wait()
                producer_status = producer.wait()
        finally:
            if producer.poll() is None:
                producer.kill()
        if producer_status or consumer_status:
            raise RecoveryError("Archive pipeline failed")


def dump(name, output, key, source, database_bytes, sources):
    """The caller proves target ownership and that F: is the intended destination."""
    if database_bytes <= 0 or shutil.disk_usage(output.parent).free < 2 * database_bytes + GIB:
        raise RecoveryError("Insufficient space for archive and safety reserve")
    if key.resolve().is_relative_to(output.resolve()):
        raise RecoveryError("Recovery key must be stored separately")
    with TemporaryDirectory(prefix="vt-rc24-gpg-") as work:
        crypto = gpg(work, key)
        output.mkdir(mode=0o700, exist_ok=False)
        incomplete = output / (ARCHIVE + ".partial")
        with incomplete.open("xb") as stream:
            pipe(
                postgres(name, "pg_dump", "-Fc", "--no-password", "--serializable-deferrable"),
                crypto + ["--cipher-algo", "AES256", "--compress-algo", "none", "--symmetric"],
                stream,
            )
            stream.flush()
            os.fsync(stream.fileno())
        if not incomplete.stat().st_size:
            raise RecoveryError("Empty encrypted archive")
        manifest = {
            "format": 2,
            "database": DB,
            "postgres_major": 16,
            "source": source,
            "sources": sources,
            "created_at": datetime.now(UTC).isoformat(),
            "database_bytes": database_bytes,
            "ciphertext_bytes": incomplete.stat().st_size,
            "sha256": digest(incomplete),
        }
        incomplete.rename(output / ARCHIVE)
        pending = output / "manifest.json.partial"
        with pending.open("x") as stream:
            json.dump(manifest, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        pending.rename(output / "manifest.json")
        return manifest


def check(directory, key):
    """Authenticate the whole archive before PostgreSQL receives any bytes."""
    archive, receipt = directory / ARCHIVE, directory / "manifest.json"
    if regular(receipt).st_size > 64 * 1024:
        raise RecoveryError("Invalid archive manifest")
    manifest = json.loads(receipt.read_text())
    if (
        manifest["format"] != 2
        or manifest["database"] != DB
        or manifest["postgres_major"] != 16
        or manifest["sources"] not in (SOURCES, BASE_SOURCES)
        or type(manifest["database_bytes"]) is not int
        or manifest["database_bytes"] <= 0
        or manifest["ciphertext_bytes"] != regular(archive).st_size
        or not re.fullmatch(r"[a-f0-9]{64}", manifest["sha256"])
        or digest(archive) != manifest["sha256"]
    ):
        raise RecoveryError("Archive manifest or checksum mismatch")
    with TemporaryDirectory(prefix="vt-rc24-gpg-") as work, archive.open("rb") as stream:
        result = subprocess.run(
            gpg(work, key) + ["--decrypt"],
            stdin=stream,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode:
            raise RecoveryError("Encrypted archive authentication failed")
    return manifest


def load_data(name, directory, key, manifest):
    archive = directory / ARCHIVE
    with TemporaryDirectory(prefix="vt-rc24-gpg-") as work, archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != manifest["sha256"]:
            raise RecoveryError("Archive changed after authentication")
        stream.seek(0)
        pipe(
            gpg(work, key) + ["--decrypt"],
            postgres(name, "pg_restore", "--exit-on-error", "--single-transaction", stdin=True),
            subprocess.DEVNULL,
            source=stream,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "verify", "restore"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.directory.absolute()
    key = args.key_file.absolute()
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise RecoveryError("Redirected archive path")
    if args.action == "verify":
        manifest = check(directory, key)
    else:
        stack = PersistentV2(PROFILE, pg_port=55448, api_port=8014, web_port=5187)
        if (
            stack.volume,
            stack.config["pg_port"],
            stack.config["api_port"],
            stack.config["web_port"],
        ) != (
            "vulntrack_v2_rc2_catalog24_pgdata",
            55448,
            8014,
            5187,
        ):
            raise RecoveryError("Unexpected RC2.4 profile or ports")
        with stack.lock():
            if args.action == "backup":
                stack.verify()
                size = int(stack.sql("SELECT pg_database_size(current_database());"))
                manifest = dump(stack.name, directory, key, PROFILE, size, SOURCES)
            else:
                manifest = check(directory, key)
                if not Path("/mnt/c").is_mount() or shutil.disk_usage("/mnt/c").free < (
                    2 * manifest["database_bytes"] + GIB
                ):
                    raise RecoveryError("Persistent restore exceeds safe available space on C:")
                stack.prepare_restore()
                load_data(stack.name, directory, key, manifest)
                stack.finish_restore(upgrade_catalog=True)
    print(
        json.dumps(
            {field: manifest[field] for field in ("sha256", "ciphertext_bytes", "created_at")}
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        detail = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print("RC2.4 recovery:", detail, file=sys.stderr)
        raise SystemExit(1) from None
