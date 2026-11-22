"""Verify and stream the official chunked CPE dictionary without extracting paths."""

import gzip
import hashlib
import itertools
import os
import re
import tarfile
import time
from datetime import datetime
from typing import NamedTuple

import ijson
from sqlalchemy import text

from app.services.cpe_catalog import (
    CATALOG_COLUMNS,
    CATALOG_FIELDS,
    UPSERT_POLICY,
    normalize,
    refresh_summary,
)

FEED_ROOT = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0"
META_URL = FEED_ROOT + ".meta"
ARCHIVE_URL = FEED_ROOT + ".tar.gz"
MEMBER = re.compile(r"nvdcpe-2[.]0-chunks/nvdcpe-2[.]0-chunk-([0-9]{5})[.]json")
CHUNK_BYTES = 65536
MAX_MEMBERS = 512
MAX_MEMBER_BYTES = 128 * 1024**2
MAX_JSON_BYTES = 2 * 1024**3
MAX_ARCHIVE_BYTES = 256 * 1024**2
BATCH = 500


class FeedError(RuntimeError):
    """No download content, connection strings or file data enter error logs."""


class FeedMeta(NamedTuple):
    digest: str
    modified: datetime
    json_bytes: int
    gz_bytes: int


def read_meta(client):
    with client.stream("GET", META_URL, headers={"Accept-Encoding": "identity"}) as reply:
        if (
            reply.status_code != 200
            or reply.headers.get("content-encoding", "identity") != "identity"
        ):
            raise FeedError("FEED_META_HTTP")
        data = bytearray()
        for piece in reply.iter_bytes(1024):
            data.extend(piece)
            if len(data) > 4096:
                raise FeedError("FEED_META_LIMIT")
    try:
        pairs = [line.split(":", 1) for line in data.decode("ascii").splitlines() if line]
        fields = dict(pairs)
        result = FeedMeta(
            fields["sha256"].lower(),
            datetime.fromisoformat(fields["lastModifiedDate"]),
            int(fields["size"]),
            int(fields["gzSize"]),
        )
    except (KeyError, UnicodeError, ValueError):
        raise FeedError("FEED_META_INVALID") from None
    if (
        len(fields) != len(pairs)
        or not re.fullmatch(r"[a-f0-9]{64}", result.digest)
        or not result.modified.tzinfo
        or not 0 < result.json_bytes <= MAX_JSON_BYTES
        or not 0 < result.gz_bytes <= MAX_ARCHIVE_BYTES
    ):
        raise FeedError("FEED_META_INVALID")
    return result


def download(client, path, meta, *, clock=time.monotonic):
    offset = path.stat().st_size if path.exists() else 0
    if offset > meta.gz_bytes:
        raise FeedError("FEED_CHECKPOINT_SIZE")
    if offset == meta.gz_bytes:
        return offset
    headers = {"Accept-Encoding": "identity"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    started = clock()
    with client.stream("GET", ARCHIVE_URL, headers=headers) as reply:
        if reply.headers.get("content-encoding", "identity") != "identity":
            raise FeedError("FEED_ENCODING")
        if offset and reply.status_code == 206:
            expected = f"bytes {offset}-{meta.gz_bytes - 1}/{meta.gz_bytes}"
            if reply.headers.get("content-range") != expected:
                raise FeedError("FEED_RANGE")
        elif reply.status_code == 200:
            offset = 0  # Server ignored Range. Restart just this digest's partial file.
        else:
            raise FeedError(f"FEED_HTTP_{reply.status_code}")
        if "content-length" in reply.headers:
            if reply.headers["content-length"] != str(meta.gz_bytes - offset):
                raise FeedError("FEED_SIZE")
        with path.open("ab" if offset else "wb") as target:
            for piece in reply.iter_bytes(CHUNK_BYTES):
                if clock() - started > 600:
                    raise FeedError("FEED_DOWNLOAD_TIMEOUT")
                if offset + len(piece) > meta.gz_bytes:
                    raise FeedError("FEED_SIZE")
                target.write(piece)
                offset += len(piece)
            target.flush()
            os.fsync(target.fileno())
    if offset != meta.gz_bytes:
        raise FeedError("FEED_DOWNLOAD_INCOMPLETE")
    return offset


def exact(source, count):
    data = source.read(count)
    if len(data) != count:
        raise FeedError("FEED_TAR_TRUNCATED")
    return data


class MemberReader:
    def __init__(self, source, size, digest):
        self.source = source
        self.remaining = size
        self.digest = digest

    def read(self, count):
        chunk = exact(self.source, min(count, self.remaining, CHUNK_BYTES))
        self.remaining -= len(chunk)
        self.digest.update(chunk)
        return chunk


def members(path, meta, digest):
    """Accept original regular JSON files only; interpret headers without extraction."""
    with gzip.open(path, "rb") as source:
        total = number = 0
        directory_seen = False
        while True:
            block = exact(source, tarfile.BLOCKSIZE)
            if block == bytes(tarfile.BLOCKSIZE):
                if any(exact(source, tarfile.BLOCKSIZE)) or any(source.read(CHUNK_BYTES)):
                    raise FeedError("FEED_TAR_TRAILER")
                if source.read(1):
                    raise FeedError("FEED_TAR_TRAILER_LIMIT")
                break
            try:
                header = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
            except (tarfile.TarError, UnicodeError):
                raise FeedError("FEED_TAR_HEADER") from None
            if header.isdir() and header.name.rstrip("/") == "nvdcpe-2.0-chunks":
                if directory_seen or number or header.size:
                    raise FeedError("FEED_TAR_DIRECTORY")
                directory_seen = True
                continue
            match = MEMBER.fullmatch(header.name)
            number += 1
            if not (
                header.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
                and match
                and int(match[1]) == number
                and number <= MAX_MEMBERS
                and 0 < header.size <= MAX_MEMBER_BYTES
            ):
                raise FeedError("FEED_TAR_MEMBER")
            total += header.size
            if total > meta.json_bytes:
                raise FeedError("FEED_JSON_SIZE")
            stream = MemberReader(source, header.size, digest)
            yield stream
            if stream.remaining:
                raise FeedError("FEED_CHUNK_INCOMPLETE")
            pad = -header.size % tarfile.BLOCKSIZE
            if any(exact(source, pad)):
                raise FeedError("FEED_TAR_PADDING")
    if number == 0 or total != meta.json_bytes:
        raise FeedError("FEED_JSON_SIZE")


def inspect_chunk(stream):
    keys = set()
    fields = {}
    count = depth = 0
    array = False
    for prefix, event, value in ijson.parse(stream, use_float=True):
        if event in {"start_map", "start_array"}:
            depth += 1
        if event in {"end_map", "end_array"}:
            depth -= 1
        if depth > 24 or (isinstance(value, str) and len(value) > CHUNK_BYTES):
            raise FeedError("FEED_JSON_LIMIT")
        if not prefix and event == "map_key":
            if value in keys or len(keys) >= 20:
                raise FeedError("FEED_CHUNK_SCHEMA")
            keys.add(value)
        if prefix == "products":
            array |= event == "start_array"
        if prefix == "products.item":
            if event == "start_map":
                count += 1
            elif event in {"start_array", "string", "number", "boolean", "null"}:
                raise FeedError("FEED_CHUNK_SCHEMA")
        if prefix in {"format", "version", "resultsPerPage", "totalResults", "startIndex"}:
            fields[prefix] = value
    if not (
        array
        and fields.get("format") == "NVD_CPE"
        and fields.get("version") == "2.0"
        and type(fields.get("resultsPerPage")) is int
        and fields["resultsPerPage"] == count
        and type(fields.get("totalResults")) is int
        and fields["totalResults"] >= count
        and type(fields.get("startIndex")) is int
        and fields["startIndex"] >= 0
    ):
        raise FeedError("FEED_CHUNK_SCHEMA")
    return count, fields["totalResults"]


def verify(path, meta):
    if path.stat().st_size != meta.gz_bytes:
        raise FeedError("FEED_SIZE")
    digest = hashlib.sha256()
    received = 0
    expected = None
    try:
        for stream in members(path, meta, digest):
            count, total = inspect_chunk(stream)
            if expected is not None and total != expected:
                raise FeedError("FEED_TOTAL_CHANGED")
            expected = total
            received += count
    except (OSError, EOFError, ValueError, ijson.JSONError):
        raise FeedError("FEED_ARCHIVE_INVALID") from None
    if received != expected or digest.hexdigest() != meta.digest:
        raise FeedError("FEED_INTEGRITY")
    return received


def rows(path, meta):
    for stream in members(path, meta, hashlib.sha256()):
        yield from ijson.items(stream, "products.item", use_float=True)


def write_batch(connection, batch):
    items = {}
    discarded = skipped = 0
    for product in batch:
        try:
            row = normalize(product, "live", None, source="nvd-feed")
        except ValueError:
            discarded += 1
            continue
        uuid = row["cpe_name_id"]
        if uuid in items:
            skipped += 1
            if items[uuid]["nvd_modified"] > row["nvd_modified"]:
                continue
        items[uuid] = row
    if not items:
        return 0, discarded, skipped
    connection.execute(
        text("""
      CREATE TEMP TABLE cpe_feed_stage
      (LIKE vulntrack_catalog.products INCLUDING DEFAULTS) ON COMMIT DROP
    """)
    )
    with connection.connection.driver_connection.cursor() as cursor:
        with cursor.copy(f"COPY cpe_feed_stage({CATALOG_FIELDS}) FROM STDIN") as transfer:
            for record in items.values():
                transfer.write_row(tuple(record[key] for key in CATALOG_COLUMNS))
    stored = connection.scalar(
        text(f"""
      WITH written AS (
        INSERT INTO vulntrack_catalog.products ({CATALOG_FIELDS})
        SELECT {CATALOG_FIELDS} FROM cpe_feed_stage ORDER BY cpe_name_id
        {UPSERT_POLICY}
        RETURNING 1
      )
      SELECT count(*) FROM written
    """)
    )
    return stored, discarded, skipped + len(items) - stored


def ingest(engine, path, meta, *, max_batches=None, progress=lambda _report: None):
    total = verify(path, meta)  # Complete verified input before mutating the database.
    identity = {
        "digest": meta.digest,
        "source_modified": meta.modified,
        "gz_bytes": meta.gz_bytes,
        "json_bytes": meta.json_bytes,
        "total_items": total,
    }
    receipt = text("SELECT * FROM vulntrack_catalog.feed_imports WHERE digest=:digest")
    with engine.begin() as connection:
        connection.execute(
            text("""
            INSERT INTO vulntrack_catalog.feed_imports
                (digest,source_modified,gz_bytes,json_bytes,total_items)
            VALUES (:digest,:source_modified,:gz_bytes,:json_bytes,:total_items)
            ON CONFLICT (digest) DO NOTHING
        """),
            identity,
        )
        original = connection.execute(receipt, identity).mappings().one()
        if any(original[key] != identity[key] for key in ("json_bytes", "total_items")):
            raise FeedError("FEED_RECEIPT_MISMATCH")
    offset = original["next_item"]
    if original["status"] == "complete":
        return dict(original)
    items = rows(path, meta)
    try:
        iterator = itertools.islice(items, offset, None)
        batch_count = 0
        while batch := list(itertools.islice(iterator, BATCH)):
            with engine.begin() as connection:
                connection.execute(text("SELECT pg_advisory_xact_lock(2222, 1)"))
                position = connection.scalar(
                    text("""
                    SELECT next_item FROM vulntrack_catalog.feed_imports
                    WHERE digest=:digest FOR UPDATE
                """),
                    identity,
                )
                if position != offset:
                    raise FeedError("FEED_CHECKPOINT_CHANGED")
                stored, discarded, skipped = write_batch(connection, batch)
                next_offset = offset + len(batch)
                connection.execute(
                    text("""
                    UPDATE vulntrack_catalog.feed_imports
                    SET next_item=:offset, stored=stored+:stored, discarded=discarded+:discarded,
                        skipped=skipped+:skipped, error_code=NULL,
                        status=CASE WHEN :offset=total_items THEN 'complete' ELSE 'partial' END,
                        updated_at=statement_timestamp()
                    WHERE digest=:digest
                """),
                    identity
                    | {
                        "offset": next_offset,
                        "stored": stored,
                        "discarded": discarded,
                        "skipped": skipped,
                    },
                )
                if next_offset == total:
                    refresh_summary(connection, "live")
                report = dict(connection.execute(receipt, identity).mappings().one())
            offset = next_offset
            progress(report)
            batch_count += 1
            if max_batches is not None and batch_count >= max_batches:
                break
        if total == 0:
            with engine.begin() as connection:
                connection.execute(text("SELECT pg_advisory_xact_lock(2222, 1)"))
                connection.execute(
                    text("""
                    UPDATE vulntrack_catalog.feed_imports SET status='complete'
                    WHERE digest=:digest AND total_items=0
                """),
                    identity,
                )
                refresh_summary(connection, "live")
    except Exception:
        with engine.begin() as connection:
            connection.execute(
                text("""
                UPDATE vulntrack_catalog.feed_imports
                SET status='failed',error_code='FEED_BATCH_FAILED',updated_at=statement_timestamp()
                WHERE digest=:digest AND status<>'complete' AND next_item=:offset
            """),
                identity | {"offset": offset},
            )
        raise
    finally:
        items.close()
    with engine.connect() as connection:
        return dict(connection.execute(receipt, identity).mappings().one())
