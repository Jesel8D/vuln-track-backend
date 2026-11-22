"""Explicit importer for the official dictionary, guarded to the owned RC2.4 profile."""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from resource import RUSAGE_SELF, getrusage

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from app.services.cpe_feed import FeedError, FeedMeta, download, ingest, read_meta, verify
from app.services.cpe_quarantine import COUNT, EDITION
from scripts.v2_development import ROOT, PersistentV2, catalog_live_lock, command

PROFILE = "rc2-catalog24"
MIB = 1024**2
WINDOWS_VOLUME = Path("/mnt/c")


def local_edition(archive, manifest):
    if (
        not archive.is_file()
        or archive.is_symlink()
        or not manifest.is_file()
        or manifest.is_symlink()
        or manifest.stat().st_size > 16384
    ):
        raise FeedError("OFFLINE_EDITION_FILES")
    data = json.loads(manifest.read_text())
    meta = FeedMeta(
        data["json_sha256"],
        datetime.fromisoformat(data["source_modified"]),
        data["json_bytes"],
        data["compressed_bytes"],
    )
    if meta != EDITION or data["processed"] != COUNT or archive.stat().st_size != meta.gz_bytes:
        raise FeedError("OFFLINE_EDITION_NOT_PINNED")
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != data["compressed_sha256"]:
            raise FeedError("OFFLINE_ARCHIVE_CHECKSUM")
    return meta


def measure(engine, stack, meta, archive=None):
    with engine.connect() as db:
        compatible = db.scalar(
            text("""
            SELECT to_regclass('vulntrack_catalog.feed_imports') IS NOT NULL
               AND to_regclass('vulntrack_catalog.catalog_cpe_exact_idx') IS NOT NULL
        """)
        )
        version = db.scalar(text("SHOW server_version"))
        existing = db.scalar(text("SELECT pg_database_size(current_database())"))
        checkpoint = (
            db.execute(
                text("""
            SELECT next_item,total_items FROM vulntrack_catalog.feed_imports WHERE digest=:digest
        """),
                {"digest": meta.digest},
            )
            .mappings()
            .first()
        )
    docker_df = (
        command(["docker", "exec", stack.name, "df", "-P", "-B1", "/var/lib/postgresql/data"])
        .decode()
        .splitlines()
    )
    pg_free = int(docker_df[-1].split()[3])
    docker_mem = int(command(["docker", "info", "--format", "{{.MemTotal}}"]))
    mem = dict(
        (key.rstrip(":"), int(value) * 1024)
        for key, value, *_ in (
            line.split() for line in Path("/proc/meminfo").read_text().splitlines()
        )
    )
    host = shutil.disk_usage(WINDOWS_VOLUME).free if WINDOWS_VOLUME.is_mount() else None
    wsl = shutil.disk_usage(stack.directory).free
    archive = archive or stack.directory / "cpe-feed" / meta.digest / "dictionary.tar.gz.part"
    downloaded = archive.stat().st_size if archive.is_file() and not archive.is_symlink() else 0
    remaining_json = meta.json_bytes
    if checkpoint and checkpoint["total_items"]:
        total = checkpoint["total_items"]
        rest = total - checkpoint["next_item"]
        remaining_json = (meta.json_bytes * rest + total - 1) // total
    needed = max(0, meta.gz_bytes - downloaded) + 6 * remaining_json + 512 * MIB
    needed_memory = max(512 * MIB, 2 * meta.json_bytes + 256 * MIB)
    return {
        "profile": PROFILE,
        "postgres_version": version,
        "postgres_ready": True,
        "schema_compatible": compatible,
        "volume": stack.volume,
        "current_database_bytes": existing,
        "windows_free_bytes": host,
        "wsl_free_bytes": wsl,
        "docker_volume_free_bytes": pg_free,
        "docker_memory_bytes": docker_mem,
        "available_memory_bytes": mem["MemAvailable"],
        "estimated_required_bytes": needed,
        "staged_bytes": downloaded,
        "processed_items": checkpoint["next_item"] if checkpoint else 0,
        "estimated_required_memory_bytes": needed_memory,
        "feed_digest": meta.digest,
        "source_modified": meta.modified.isoformat(),
        "gz_bytes": meta.gz_bytes,
        "json_bytes": meta.json_bytes,
        "resume": {"download": "HTTP Range", "database": "feed digest and committed item"},
        "full_safe": bool(
            compatible
            and host is not None
            and min(host, wsl, pg_free) >= needed
            and min(mem["MemAvailable"], docker_mem) >= needed_memory
        ),
    }


def stats(engine):
    with engine.connect() as db:
        summary = db.execute(
            text("""
            SELECT mode,count(*) records,count(DISTINCT vendor) vendors,
                   count(DISTINCT (part,vendor,product)) products,
                   count(DISTINCT (part,vendor,product,version))
                    FILTER(WHERE version NOT IN ('*','-','?')) product_versions,
                   count(*) FILTER(WHERE deprecated) deprecated,max(synchronized_at) last_sync
            FROM vulntrack_catalog.products GROUP BY mode ORDER BY mode
        """)
        ).mappings()
        counts = [dict(record) for record in summary]
        by_part = db.execute(
            text("""
            SELECT mode,part,source,count(*) records FROM vulntrack_catalog.products
            GROUP BY mode,part,source ORDER BY mode,part,source
        """)
        ).mappings()
        parts = [dict(record) for record in by_part]
        checkpoint = (
            db.execute(
                text("""
            SELECT * FROM vulntrack_catalog.feed_imports ORDER BY updated_at DESC LIMIT 1
        """)
            )
            .mappings()
            .first()
        )
        storage = db.scalar(
            text("""
            SELECT sum(pg_total_relation_size(oid))::bigint FROM pg_class
            WHERE relnamespace='vulntrack_catalog'::regnamespace AND relkind='r'
        """)
        )
    return {
        "catalog": counts,
        "breakdown": parts,
        "catalog_bytes": storage,
        "feed": dict(checkpoint) if checkpoint else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["preflight", "stage", "import", "stats"])
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--edition", type=Path)
    args = parser.parse_args()
    if bool(args.archive) != bool(args.edition) or (args.archive and args.action == "stats"):
        parser.error("--archive and --edition are used together with preflight, stage or import")
    if not (ROOT / ".local" / PROFILE / "config.json").is_file():
        raise FeedError("RC24_PROFILE_REQUIRED")
    stack = PersistentV2(PROFILE)
    stack.verify()
    engine = create_engine(stack.url("postgres"), hide_parameters=True)
    try:
        if args.action == "stats":
            print(json.dumps(stats(engine), default=str, indent=2))
            return 0
        connection = (
            nullcontext()
            if args.archive
            else httpx.Client(
                timeout=httpx.Timeout(15, connect=5), follow_redirects=False, trust_env=False
            )
        )
        with connection as client, catalog_live_lock(stack):
            meta = local_edition(args.archive, args.edition) if args.archive else read_meta(client)
            resources = measure(engine, stack, meta, args.archive)
            print(json.dumps(resources, indent=2), flush=True)
            if args.action == "preflight":
                return 0
            if not resources["full_safe"] and (not args.archive or args.action == "import"):
                raise FeedError("PREFLIGHT_FULL_IMPORT_BLOCKED")
            begin = time.monotonic()
            archive = args.archive
            if archive:
                size = meta.gz_bytes
            else:
                base = stack.directory / "cpe-feed"
                base.mkdir(mode=0o700, exist_ok=True)
                target = base / meta.digest
                target.mkdir(mode=0o700, exist_ok=True)
                if base.is_symlink() or target.is_symlink():
                    raise FeedError("UNSAFE_FEED_DIRECTORY")
                archive = target / "dictionary.tar.gz.part"
                if archive.is_symlink() or (archive.exists() and not archive.is_file()):
                    raise FeedError("UNSAFE_FEED_FILE")
                size = download(client, archive, meta)
            if args.action == "stage":
                total = verify(archive, meta)
                print(
                    json.dumps(
                        {
                            "bytes": size,
                            "verified_items": total,
                            "seconds": time.monotonic() - begin,
                        }
                    )
                )
                return 0

            def progress(row):
                free = shutil.disk_usage(WINDOWS_VOLUME).free
                position = row["next_item"]
                if position % 50000 == 0 or position == row["total_items"]:
                    print(
                        json.dumps(
                            {
                                "next_item": position,
                                "total_items": row["total_items"],
                                "discarded": row["discarded"],
                                "windows_free_bytes": free,
                                "rss_kib": getrusage(RUSAGE_SELF).ru_maxrss,
                            }
                        ),
                        flush=True,
                    )
                if free < 512 * MIB and row["status"] != "complete":
                    raise FeedError("PREFLIGHT_HEADROOM_PAUSE")

            result = ingest(engine, archive, meta, progress=progress)
            print(
                json.dumps(
                    {
                        "bytes": size,
                        "seconds": time.monotonic() - begin,
                        "rss_kib": getrusage(RUSAGE_SELF).ru_maxrss,
                        "result": result,
                    },
                    default=str,
                    indent=2,
                )
            )
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    try:
        raise SystemExit(main())
    except (httpx.HTTPError, OSError, RuntimeError, SQLAlchemyError, KeyError, ValueError) as error:
        reason = str(error) if isinstance(error, FeedError) else type(error).__name__
        print("CPE feed:", reason, file=sys.stderr)
        raise SystemExit(1) from None
