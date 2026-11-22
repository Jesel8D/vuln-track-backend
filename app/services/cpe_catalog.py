"""Bounded NVD acquisition and durable page receipts for the local CPE dictionary."""

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from time import sleep
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from sqlalchemy import text

from app.core.errors import APIError
from app.integrations.nvd import Product
from app.schemas.cpe import parse_cpe, unbind_component

Mode = Literal["fixture", "live"]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]{1,120}$")]
PAGE_SIZE = 20
SOURCE = {"fixture": "nvd-captured-fixture", "live": "nvd-api"}


class CatalogScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vendor: Slug
    product: Slug | None = None
    since: AwareDatetime | None = None
    until: AwareDatetime | None = None

    def parameters(self, offset):
        base = f"cpe:2.3:*:{self.vendor}"
        if self.product is not None:
            base += f":{self.product}"
        args = {"cpeMatchString": base, "startIndex": offset, "resultsPerPage": PAGE_SIZE}
        if self.since is not None or self.until is not None:
            if (
                not self.since
                or not self.until
                or not timedelta(0) < self.until - self.since <= timedelta(days=120)
            ):
                raise ValueError("Use an increasing range of at most 120 days")
            for name, instant in [("lastModStartDate", self.since), ("lastModEndDate", self.until)]:
                args[name] = instant.astimezone(UTC).isoformat(timespec="milliseconds")
        return args


class Replacement(BaseModel):
    cpeName: str = Field(min_length=1, max_length=1024)
    cpeNameId: UUID


class CatalogProduct(Product):
    created: datetime
    lastModified: datetime
    deprecatedBy: list[Replacement] = Field(default_factory=list, max_length=100)


def utc(instant):
    return instant.replace(tzinfo=instant.tzinfo or UTC).astimezone(UTC)


def normalize(entry, mode, scope):
    if not isinstance(entry, dict) or not isinstance(entry.get("cpe"), dict):
        raise ValueError("invalid_record")
    original = json.dumps(entry, ensure_ascii=True, allow_nan=False)
    if len(original) > 60_000 or "\\u0000" in original:
        raise ValueError("invalid_record")
    try:
        parsed = CatalogProduct.model_validate_json(original_for_product(entry))
        part, vendor, product, version = [
            unbind_component(s) for s in parse_cpe(parsed.cpeName)[:4]
        ]
        for successor in parsed.deprecatedBy:
            parse_cpe(successor.cpeName)
    except (ValidationError, ValueError):
        raise ValueError("invalid_record") from None
    vendor, product = vendor.casefold(), product.casefold()
    if vendor != scope.vendor or (scope.product and product != scope.product):
        raise ValueError("outside_scope")
    created, modified = utc(parsed.created), utc(parsed.lastModified)
    if created > modified:
        raise ValueError("invalid_record")
    if scope.since and not scope.since <= modified <= scope.until:
        raise ValueError("outside_window")
    titles = [title.model_dump() for title in parsed.titles]
    title = next(
        (item["title"] for item in titles if item["lang"] == "es"),
        next((item["title"] for item in titles if item["lang"] == "en"), parsed.cpeName),
    )
    return {
        "mode": mode,
        "cpe_name_id": UUID(parsed.cpeNameId),
        "cpe_name": parsed.cpeName,
        "part": part,
        "vendor": vendor,
        "product": product,
        "version": version,
        "title": title,
        "search_text": " ".join(
            [vendor, product, version, *(v["title"] for v in titles)]
        ).casefold(),
        "titles": json.dumps(titles),
        "deprecated": parsed.deprecated,
        "deprecated_by": json.dumps([v.model_dump(mode="json") for v in parsed.deprecatedBy]),
        "nvd_created": created,
        "nvd_modified": modified,
        "source": SOURCE[mode],
        "original": original,
    }


def original_for_product(entry):
    return json.dumps(entry["cpe"], ensure_ascii=True, allow_nan=False)


UPSERT = text("""
    INSERT INTO vulntrack_catalog.products
        (mode,cpe_name_id,cpe_name,part,vendor,product,version,title,search_text,titles,
         deprecated,deprecated_by,nvd_created,nvd_modified,source,original)
    VALUES (:mode,:cpe_name_id,:cpe_name,:part,:vendor,:product,:version,:title,:search_text,
         CAST(:titles AS jsonb),:deprecated,CAST(:deprecated_by AS jsonb),:nvd_created,
         :nvd_modified,:source,CAST(:original AS jsonb))
    ON CONFLICT (mode,cpe_name_id) DO UPDATE SET
      cpe_name=excluded.cpe_name,part=excluded.part,vendor=excluded.vendor,product=excluded.product,
      version=excluded.version,title=excluded.title,search_text=excluded.search_text,titles=excluded.titles,
      deprecated=excluded.deprecated,deprecated_by=excluded.deprecated_by,original=excluded.original,
      nvd_created=excluded.nvd_created,nvd_modified=excluded.nvd_modified,
      synchronized_at=statement_timestamp()
    WHERE vulntrack_catalog.products.nvd_modified<=excluded.nvd_modified
    RETURNING cpe_name_id
""")


def store_page(connection, run, mode, scope, page):
    discarded = Counter()
    items = {}
    for entry in page.products:
        try:
            data = normalize(entry, mode, scope)
        except ValueError as issue:
            reason = str(issue)
            discarded[
                reason if reason in {"outside_scope", "outside_window"} else "invalid_record"
            ] += 1
            continue
        if data["cpe_name_id"] in items:
            discarded["duplicate"] += 1
            continue
        items[data["cpe_name_id"]] = data
    connection.execute(text("SELECT pg_advisory_xact_lock(2222, 1)"))
    stored = 0
    for item in items.values():
        if connection.scalar(UPSERT, item) is None:
            discarded["newer_local_copy"] += 1
        else:
            stored += 1
    offset = page.startIndex
    following = offset + len(page.products)
    finished = following >= page.totalResults
    connection.execute(
        text("""
        INSERT INTO vulntrack_catalog.sync_pages
        (run_id,page_offset,nvd_timestamp,received_count,stored_count,discarded)
        VALUES (:id,:offset,:timestamp,:received,:stored,CAST(:discarded AS jsonb))
    """),
        {
            "id": run,
            "offset": offset,
            "timestamp": utc(page.timestamp),
            "received": len(page.products),
            "stored": stored,
            "discarded": json.dumps(discarded),
        },
    )
    connection.execute(
        text("""
        UPDATE vulntrack_catalog.sync_runs SET next_offset=:next, total_reported=:total,
        status=:status, error_code=NULL, retry_after=NULL, updated_at=statement_timestamp()
        WHERE id=:id
    """),
        {
            "next": following,
            "total": page.totalResults,
            "status": "complete" if finished else "partial",
            "id": run,
        },
    )
    return finished


def synchronize(engine, client, mode, *, scope=None, resume=None, pages=1, wait=sleep):
    if mode not in SOURCE or not 1 <= pages <= 5 or (scope is None) == (resume is None):
        raise ValueError("Choose one scope or run ID and a limit of 1-5 pages")
    if scope:
        scope.parameters(0)
    with engine.begin() as connection:
        if resume:
            row = (
                connection.execute(
                    text("""
              SELECT mode,scope,status FROM vulntrack_catalog.sync_runs WHERE id=:id
            """),
                    {"id": resume},
                )
                .mappings()
                .one_or_none()
            )
            if row is None or row["mode"] != mode or row["status"] == "complete":
                raise ValueError("Sync must be resumable and match the selected mode")
            scope = CatalogScope.model_validate(row["scope"])
            run = resume
        else:
            run = uuid4()
            connection.execute(
                text("""
              INSERT INTO vulntrack_catalog.sync_runs(id,mode,scope)
              VALUES (:id,:mode,CAST(:scope AS jsonb))
            """),
                {"id": run, "mode": mode, "scope": scope.model_dump_json()},
            )

    for _ in range(pages):
        with engine.begin() as connection:
            row = (
                connection.execute(
                    text("""
              SELECT next_offset,total_reported,status FROM vulntrack_catalog.sync_runs
              WHERE id=:id FOR UPDATE
            """),
                    {"id": run},
                )
                .mappings()
                .one()
            )
            if row["status"] == "complete":
                break
            # Bound the transaction to one explicit page and protect this resume cursor.
            wait(client.quota.wait_seconds())
            try:
                page = client.catalog_page(scope.parameters(row["next_offset"]))
                if row["total_reported"] is not None and page.totalResults != row["total_reported"]:
                    raise APIError(409, "CATALOG_RESULT_SET_CHANGED", "Reinicia este alcance")
            except APIError as error:
                retry_at = datetime.now(UTC) + timedelta(seconds=client.quota.wait_seconds())
                connection.execute(
                    text("""
                    UPDATE vulntrack_catalog.sync_runs SET status='failed',error_code=:code,
                    retry_after=:retry,updated_at=statement_timestamp() WHERE id=:id
                """),
                    {"code": error.code, "retry": retry_at, "id": run},
                )
                break
            if store_page(connection, run, mode, scope, page):
                break

    with engine.connect() as connection:
        result = (
            connection.execute(
                text("""
          SELECT r.*,
            COALESCE((SELECT sum(received_count) FROM vulntrack_catalog.sync_pages
                      WHERE run_id=r.id),0) received,
            COALESCE((SELECT sum(stored_count) FROM vulntrack_catalog.sync_pages
                      WHERE run_id=r.id),0) stored,
            (SELECT count(*) FROM vulntrack_catalog.sync_pages WHERE run_id=r.id) pages
          FROM vulntrack_catalog.sync_runs r WHERE r.id=:id
        """),
                {"id": run},
            )
            .mappings()
            .one()
        )
        return dict(result)
