"""Account for the known malformed name without making it selectable."""

import itertools
import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import text

from app.schemas.cpe import parse_cpe
from app.services.cpe_feed import FeedError, FeedMeta, rows, verify

EDITION = FeedMeta(
    "770fb8040e62e9e9249265997b6bdc15b516f4f1b0004bdf0236354e1425f6bd",
    datetime.fromisoformat("2026-11-20T23:50:01-05:00"),
    914798391,
    85329096,
)
COUNT = 1880953
ORDINAL = 133537
CPE_ID = UUID("38b903e9-19bb-4c83-bdf4-d90a0e71838d")
CPE_NAME = "cpe:2.3:a:ipswitch:whatsup:2006:-:professional:premium:*:*:*:*"
REASON = "INVALID_CPE_LANGUAGE"


def rejected_record(entry):
    cpe = entry["cpe"]
    if UUID(cpe["cpeNameId"]) != CPE_ID or cpe["cpeName"] != CPE_NAME:
        raise FeedError("QUARANTINE_RECORD_MISMATCH")
    try:
        parse_cpe(cpe["cpeName"])
    except ValueError as error:
        if str(error) == "Invalid CPE language":
            return json.dumps(entry, ensure_ascii=True, allow_nan=False)
    raise FeedError("QUARANTINE_REASON_CHANGED")


def quarantine(engine, archive):
    if verify(archive, EDITION) != COUNT:
        raise FeedError("QUARANTINE_EDITION_MISMATCH")
    records = rows(archive, EDITION)
    try:
        original = rejected_record(next(itertools.islice(records, ORDINAL - 1, ORDINAL)))
    finally:
        records.close()
    params = {
        "digest": EDITION.digest,
        "ordinal": ORDINAL,
        "cpe_id": CPE_ID,
        "original": original,
        "reason": REASON,
        "source_modified": EDITION.modified,
        "count": COUNT,
        "gz_bytes": EDITION.gz_bytes,
        "json_bytes": EDITION.json_bytes,
    }
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(2222, 1)"))
        if not connection.scalar(
            text("""
            SELECT status='complete' AND discarded=1 AND next_item=:count AND total_items=:count
              AND source_modified=:source_modified AND gz_bytes=:gz_bytes AND json_bytes=:json_bytes
            FROM vulntrack_catalog.feed_imports WHERE digest=:digest
        """),
            params,
        ):
            raise FeedError("QUARANTINE_COMPLETE_RECEIPT_REQUIRED")
        stored = connection.scalar(
            text("""
            INSERT INTO vulntrack_catalog.feed_quarantine
                (digest,cpe_name_id,ordinal,reason,original)
            VALUES (:digest,:cpe_id,:ordinal,:reason,CAST(:original AS jsonb))
            ON CONFLICT (digest,cpe_name_id) DO NOTHING
            RETURNING ordinal
        """),
            params,
        )
        if stored is None and not connection.scalar(
            text("""
            SELECT ordinal=:ordinal AND reason=:reason AND original=CAST(:original AS jsonb)
            FROM vulntrack_catalog.feed_quarantine WHERE digest=:digest AND cpe_name_id=:cpe_id
        """),
            params,
        ):
            raise FeedError("QUARANTINE_RECEIPT_MISMATCH")
    return {
        "digest": EDITION.digest,
        "cpe_name_id": str(CPE_ID),
        "ordinal": ORDINAL,
        "reason": REASON,
        "inserted": stored is not None,
    }
