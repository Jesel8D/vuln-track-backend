"""Authenticated, bounded reads of the locally synchronized dictionary."""

import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text

from app.api.router import Identity
from app.core.errors import APIError
from app.services.cpe_catalog import SOURCE, Mode


def admit_catalog(request: Request, user: Identity):
    request.app.state.catalog_reads.check_user(user.id, "catalog_read", limit=90)


router = APIRouter(
    prefix="/api/v2/cpe-catalog", tags=["Catálogo CPE"], dependencies=[Depends(admit_catalog)]
)
Part = Literal["h", "o", "a"]
Search = Annotated[str, Query(max_length=120)]
FullSearch = Annotated[str, Query(max_length=1024)]
SEARCH_WINDOW = 500
Limit = Annotated[int, Query(ge=1, le=30)]
Offset = Annotated[int, Query(ge=0, le=10000)]
RECORD = """
    cpe_name_id,cpe_name,part,vendor,product,version,title,titles,
    deprecated,deprecated_by,nvd_created,nvd_modified,synchronized_at,source,mode
"""
LITERAL_VERSION = "version <> '-' AND strpos(version,'*')=0 AND strpos(version,'?')=0"


def normalized_text(q):
    normalized = unicodedata.normalize("NFC", q.strip())
    if any(unicodedata.category(c) in {"Cc", "Cs"} for c in normalized):
        raise APIError(422, "SEARCH_INVALID", "Texto de búsqueda inválido")
    return normalized


def search_argument(q):
    return (
        "%"
        + normalized_text(q).casefold().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        + "%"
    )


def listing(request, mode, part, q, limit, offset, *, select, where="", order, **scope):
    query = (
        """
        WHERE mode=:mode AND (CAST(:part AS text) IS NULL OR part=:part)
    """
        + where
    )
    values = {
        key: normalized_text(value)
        if key in {"version", "exact"}
        else normalized_text(value).casefold()
        for key, value in scope.items()
    }
    pattern = search_argument(q)
    params = {"mode": mode, "part": part, "q": pattern, "prefix": pattern[1:], **values}
    with request.app.state.engine.connect() as connection:
        connection.execute(text("SET LOCAL statement_timeout=2000"))
        rows = (
            connection.execute(
                text(f"""
            WITH matches AS MATERIALIZED (
                SELECT {select} FROM vulntrack_catalog.products {query}
                ORDER BY {order} LIMIT :window
            )
            SELECT coalesce(jsonb_agg(to_jsonb(page)), '[]'::jsonb) AS items,
                   (SELECT count(*) FROM matches) AS total
            FROM (SELECT * FROM matches ORDER BY {order}
                  LIMIT :limit OFFSET :offset) page
        """),
                params
                | {
                    "limit": min(limit, max(0, SEARCH_WINDOW - offset)),
                    "offset": min(offset, SEARCH_WINDOW),
                    "window": SEARCH_WINDOW + 1,
                },
            )
            .mappings()
            .one()
        )
    return {
        "items": rows["items"],
        "page": {
            "limit": limit,
            "offset": offset,
            "total": min(rows["total"], SEARCH_WINDOW),
            "truncated": rows["total"] > SEARCH_WINDOW,
        },
        "mode": mode,
    }


@router.get("/status")
def status(request: Request, user: Identity, mode: Mode = "live"):
    with request.app.state.engine.connect() as connection:
        connection.execute(text("SET LOCAL statement_timeout=2000"))
        counts = (
            connection.execute(
                text("""
            SELECT records,vendors,products,last_synchronized_at,refreshed_at
            FROM vulntrack_catalog.summary WHERE mode=:mode
        """),
                {"mode": mode},
            )
            .mappings()
            .one()
        )
        latest = (
            connection.execute(
                text("""
            SELECT scope,status,total_reported,next_offset,updated_at,error_code
            FROM vulntrack_catalog.sync_runs WHERE mode=:mode
            ORDER BY updated_at DESC,id DESC LIMIT 1
        """),
                {"mode": mode},
            )
            .mappings()
            .one_or_none()
        )
        feed = None
        if mode == "live":
            feed = (
                connection.execute(
                    text("""
                SELECT digest,source_modified,total_items,next_item,stored,discarded,skipped,
                       status,updated_at,error_code
                FROM vulntrack_catalog.feed_imports
                ORDER BY updated_at DESC LIMIT 1
            """)
                )
                .mappings()
                .first()
            )
    last = counts["last_synchronized_at"]
    complete = feed and feed["status"] == "complete" and not feed["discarded"]
    return {
        **counts,
        "mode": mode,
        "source": SOURCE[mode],
        "coverage": "complete" if complete else ("partial" if counts["records"] else "empty"),
        "feed": dict(feed) if feed else None,
        "stale": bool(last and datetime.now(UTC) - last > timedelta(days=7)),
        "last_run": dict(latest) if latest else None,
    }


@router.get("/vendors")
def vendors(
    request: Request,
    user: Identity,
    mode: Mode = "live",
    part: Part | None = None,
    q: Search = "",
    limit: Limit = 15,
    offset: Offset = 0,
):
    return listing(
        request,
        mode,
        part,
        q,
        limit,
        offset,
        select="DISTINCT vendor",
        where="AND vendor LIKE :prefix ESCAPE '!'",
        order="vendor",
    )


@router.get("/products")
def products(
    request: Request,
    user: Identity,
    vendor: Search,
    mode: Mode = "live",
    part: Part | None = None,
    q: Search = "",
    limit: Limit = 15,
    offset: Offset = 0,
):
    return listing(
        request,
        mode,
        part,
        q,
        limit,
        offset,
        select="vendor,product,part,min(title) AS title",
        where="AND vendor=:vendor AND search_text LIKE :q ESCAPE '!' GROUP BY vendor,product,part",
        order="product,part",
        vendor=vendor,
    )


@router.get("/versions")
def versions(
    request: Request,
    user: Identity,
    vendor: Search,
    product: Search,
    mode: Mode = "live",
    part: Part | None = None,
    q: Search = "",
    limit: Limit = 15,
    offset: Offset = 0,
):
    return listing(
        request,
        mode,
        part,
        q,
        limit,
        offset,
        select="version,bool_and(deprecated) AS deprecated",
        where=f"""AND vendor=:vendor AND product=:product AND {LITERAL_VERSION}
                  AND lower(version) LIKE :q ESCAPE '!' GROUP BY version""",
        order="version",
        vendor=vendor,
        product=product,
    )


@router.get("/candidates")
def candidates(
    request: Request,
    user: Identity,
    mode: Mode = "live",
    part: Part | None = None,
    q: FullSearch = "",
    vendor: Search = "",
    product: Search = "",
    version: Search = "",
    deprecated: bool | None = None,
    limit: Limit = 15,
    offset: Offset = 0,
):
    exact = normalized_text(q)
    cpe_exact = exact.startswith("cpe:2.3:")
    stale = (
        " AND deprecated IS TRUE"
        if deprecated is True
        else " AND deprecated IS FALSE"
        if deprecated is False
        else ""
    )
    match = " AND cpe_name=:exact" if cpe_exact else " AND search_text LIKE :q ESCAPE '!'"
    return listing(
        request,
        mode,
        part,
        q,
        limit,
        offset,
        select=RECORD,
        where="""
        AND (:vendor='' OR vendor=:vendor) AND (:product='' OR product=:product)
        AND (:version='' OR version=:version)
    """
        + match
        + stale,
        exact=exact,
        order="deprecated,vendor,product,version,cpe_name_id",
        vendor=vendor,
        product=product,
        version=version,
    )


def catalog_row(executor, mode, name_id):
    row = (
        executor.execute(
            text(f"""
        SELECT {RECORD} FROM vulntrack_catalog.products
        WHERE mode=:mode AND cpe_name_id=:id
    """),
            {"mode": mode, "id": name_id},
        )
        .mappings()
        .one_or_none()
    )
    if not row:
        raise APIError(404, "CATALOG_CPE_NOT_FOUND", "Identificador ausente del catálogo local")
    return dict(row)


@router.get("/candidates/{cpe_name_id}")
def detail(request: Request, user: Identity, cpe_name_id: UUID, mode: Mode = "live"):
    with request.app.state.engine.connect() as connection:
        connection.execute(text("SET LOCAL statement_timeout=2000"))
        return catalog_row(connection, mode, cpe_name_id)
