"""Bounded offline CVE reuse. Public bodies never contain inventory/review context."""

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import text

from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.integrations.nvd_cve import CVE, CVEPage
from app.schemas.cpe import parse_cpe
from app.services.applicability import encoded
from app.services.nvd_findings import _contains_nul
from app.services.v2_cve_reliability import source_kind

logger = logging.getLogger(__name__)
CONTRACT = "nvd-cve-page-2.0-cache-1"
PARSER = "public-cve-5b-1"
MAX_BODY = 2097152
PRIVATE_KEYS = frozenset(
    "workspace workspaceid user username userid location sitelabel notes "
    "password apikey authorization credentials memberships reviewedby reviewreason "
    "reviewevidence recommendations inventorylabel deviceid applicationid technologyid".split()
)


class CacheFailure(APIError):
    def __init__(self, error, refresh=False):
        super().__init__(error.status, error.code, error.message)
        self.cache_usage = {"resolution": "failed", "refresh_attempted": refresh, "used_at": None}


@dataclass
class Result:
    page: CVEPage
    response_id: UUID | None = None
    usage: dict | None = None
    received_at: datetime | None = None


def query_key(mode, namespace, cpe, start=0, limit=100, *, filters=None, contract=CONTRACT):
    parse_cpe(cpe)  # Keep the validated binding verbatim: no unescape/casefold/aliasing.
    if mode not in {"fixture", "simulated", "live", "unknown"} or not re.fullmatch(
        r"[a-zA-Z0-9:._-]{1,128}", namespace
    ):
        raise ValueError("Invalid cache source namespace")
    if (
        type(start) is not int
        or not 0 <= start <= 10000
        or type(limit) is not int
        or not 1 <= limit <= 100
    ):
        raise ValueError("Invalid cache page")
    if filters not in (None, {}):
        raise ValueError("No additional CVE filters are implemented")
    query = encoded(
        {
            "provider": "NVD",
            "mode": mode,
            "namespace": namespace,
            "contract": contract,
            "parser": PARSER,
            "params": {"cpeName": cpe, "startIndex": start, "resultsPerPage": limit, "filters": {}},
        }
    ).decode()
    return hashlib.sha256(query.encode()).hexdigest(), query


def validate_public_page(value, start=0, limit=100):
    """Revalidate on both insertion and reuse; never remove an unknown predicate."""
    try:
        page = CVEPage.model_validate(
            value.model_dump(mode="json") if isinstance(value, CVEPage) else value
        )
        count = len(page.vulnerabilities)
        if (
            page.format != "NVD_CVE"
            or page.version != "2.0"
            or page.startIndex != start
            or page.resultsPerPage != count
            or count > limit
            or count != min(limit, max(0, page.totalResults - start))
            or len({entry.cve.id for entry in page.vulnerabilities}) != count
        ):
            raise ValueError("Invalid page identity/counts")
        page.timestamp = page.timestamp.replace(tzinfo=page.timestamp.tzinfo or UTC)
        body = page.model_dump(mode="json", exclude_none=True)
        allowed = set(CVE.model_fields) | {
            "sourceIdentifier",
            "weaknesses",
            "cveTags",
            "vendorComments",
            "affected",
        }
        if any(set(entry["cve"]) - allowed for entry in body["vulnerabilities"]):
            raise ValueError("Unrecognized CVE fields")

        def check(item, depth=0):
            if depth > 24:
                raise ValueError("Nested payload")
            if isinstance(item, dict):
                for key, child in item.items():
                    if re.sub(r"[^a-z]", "", key.casefold()) in PRIVATE_KEYS:
                        raise ValueError("Private field in provider body")
                    check(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    check(child, depth + 1)

        check(body)
        if _contains_nul(body):
            raise ValueError("NUL")
        raw = encoded(body)
        if len(raw) > MAX_BODY:
            raise ValueError("Payload size")
        page.timestamp = page.timestamp.replace(tzinfo=page.timestamp.tzinfo or UTC)
        return page, raw.decode(), hashlib.sha256(raw).hexdigest()
    except (ValueError, TypeError, ValidationError, RecursionError):
        raise APIError(
            502, "CVE_CACHE_INVALID_RESPONSE", "Respuesta pública CVE no válida"
        ) from None


def scoped(request, actor, workspace):
    return workspace_session(
        request.app.state.session_factory, request.app.state.settings, actor, workspace
    )


def lock(session, workspace):
    if not session.scalar(
        text("SELECT pg_try_advisory_xact_lock(hashtextextended(CAST(:w AS text),55))"),
        {"w": workspace},
    ):
        raise APIError(409, "CVE_CACHE_BUSY", "La consulta almacenada está siendo actualizada")


def capacity(session, workspace, settings, *, new_slot=False, extra_bytes=0):
    stats = (
        session.execute(
            text("""SELECT
        (SELECT count(*) FROM vulntrack_cve_cache.slots WHERE workspace_id=:w) AS slots,
        count(r.id) AS responses,coalesce(sum(octet_length(r.body)),0) AS bytes
        FROM vulntrack_cve_cache.responses r JOIN vulntrack_cve_cache.slots s ON s.id=r.slot_id
        WHERE s.workspace_id=:w"""),
            {"w": workspace},
        )
        .mappings()
        .one()
    )
    if (
        (new_slot and stats["slots"] >= settings.cve_cache_max_entries)
        or stats["responses"] >= settings.cve_cache_max_entries
        or stats["bytes"] + extra_bytes > settings.cve_cache_max_bytes
    ):
        raise APIError(
            503, "CVE_CACHE_CAPACITY_REACHED", "Capacidad de almacenamiento CVE alcanzada"
        )


def lease_context(session, token):
    session.execute(
        text("SELECT set_config('vulntrack.cache_lease',:token,true)"), {"token": str(token)}
    )


def fetch_page(request, actor, workspace, cpe):
    client = request.app.state.cve
    settings = request.app.state.settings
    mode = source_kind(client)
    # This increment must never turn a cache miss into permission for real network I/O.
    if mode == "live":
        raise APIError(503, "CVE_LIVE_DISABLED", "CVE live no está habilitado en este incremento")
    namespace = getattr(client, "cache_namespace", None)
    if not settings.cve_cache_enabled or namespace is None or mode == "unknown":
        return Result(client.page(cpe, 0, 100))
    key, query = query_key(mode, namespace, cpe)
    token, slot, refresh = uuid4(), None, False
    try:
        with scoped(request, actor, workspace) as session:
            if not session.scalar(
                text("SELECT vulntrack.has_workspace_role(:w,ARRAY['owner','editor'])"),
                {"w": workspace},
            ):
                raise APIError(404, "CVE_SCOPE_UNAVAILABLE", "Consulta no disponible")
            lock(session, workspace)
            row = (
                session.execute(
                    text("""SELECT s.*,r.body,r.digest,r.fetched_at,r.expires_at,
                r.coverage,clock_timestamp() AS observed_at FROM vulntrack_cve_cache.slots s
                LEFT JOIN vulntrack_cve_cache.responses r ON r.id=s.current_response_id
                WHERE s.workspace_id=:w AND s.key=:key FOR UPDATE OF s NOWAIT"""),
                    {"w": workspace, "key": key},
                )
                .mappings()
                .first()
            )
            if row and row["query"] != query:
                raise APIError(503, "CVE_CACHE_INTEGRITY", "Evidencia almacenada no válida")
            if (
                row
                and row["body"]
                and row["coverage"] == "complete"
                and row["expires_at"] > row["observed_at"]
            ):
                if hashlib.sha256(row["body"].encode()).hexdigest() != row["digest"]:
                    raise APIError(503, "CVE_CACHE_INTEGRITY", "Evidencia almacenada no válida")
                page, body, digest = validate_public_page(json.loads(row["body"]))
                if digest != row["digest"]:
                    raise APIError(503, "CVE_CACHE_INTEGRITY", "Evidencia almacenada no válida")
                return Result(
                    page,
                    row["current_response_id"],
                    {
                        "resolution": "reused",
                        "refresh_attempted": False,
                        "used_at": row["observed_at"].isoformat(),
                    },
                    row["fetched_at"],
                )
            if row:
                slot = row["id"]
                refresh = bool(
                    session.scalar(
                        text(
                            "SELECT EXISTS(SELECT 1 FROM vulntrack_cve_cache.responses "
                            "WHERE slot_id=:slot)"
                        ),
                        {"slot": slot},
                    )
                )
                if row["lease_token"] and row["lease_expires_at"] > row["observed_at"]:
                    raise APIError(
                        409, "CVE_CACHE_BUSY", "La consulta almacenada está siendo actualizada"
                    )
            capacity(session, workspace, settings, new_slot=row is None)
            if row is None:
                slot = uuid4()
                session.execute(
                    text("""INSERT INTO vulntrack_cve_cache.slots
                    (id,workspace_id,key,query,source) VALUES (:id,:w,:key,:query,:source)"""),
                    {"id": slot, "w": workspace, "key": key, "query": query, "source": mode},
                )
            lease_context(session, token)
            session.execute(
                text("""UPDATE vulntrack_cve_cache.slots SET lease_token=:token,
                lease_expires_at=clock_timestamp()+make_interval(secs=>:seconds) WHERE id=:id"""),
                {
                    "id": slot,
                    "token": token,
                    "seconds": min(
                        settings.cve_cache_lease_seconds, settings.cve_execution_seconds
                    ),
                },
            )

        # No SQL transaction/connection is held while the controlled provider executes.
        page, body, digest = validate_public_page(client.page(cpe, 0, 100))
        coverage = "complete" if page.totalResults == len(page.vulnerabilities) else "partial"
        warnings = [] if coverage == "complete" else ["PAGE_BUDGET_REACHED"]
        ttl = (
            settings.cve_cache_ttl_seconds
            if page.totalResults
            else settings.cve_cache_empty_ttl_seconds
        )
        with scoped(request, actor, workspace) as session:
            lock(session, workspace)
            active = session.scalar(
                text("""SELECT id FROM vulntrack_cve_cache.slots
                WHERE id=:id AND lease_token=:token AND lease_expires_at>clock_timestamp()
                FOR UPDATE NOWAIT"""),
                {"id": slot, "token": token},
            )
            if not active:
                raise APIError(
                    409, "CVE_CACHE_LEASE_EXPIRED", "La actualización dejó de estar activa"
                )
            capacity(session, workspace, settings, extra_bytes=len(body.encode()))
            lease_context(session, token)
            response = (
                session.execute(
                    text("""INSERT INTO vulntrack_cve_cache.responses
                (id,slot_id,body,digest,coverage,warning_codes,fetched_at,expires_at)
                SELECT :id,:slot,:body,:digest,:coverage,CAST(:warnings AS jsonb),n,
                    n+make_interval(secs=>:ttl) FROM (SELECT clock_timestamp() AS n) clock
                RETURNING id,fetched_at,expires_at"""),
                    {
                        "id": uuid4(),
                        "slot": slot,
                        "body": body,
                        "digest": digest,
                        "coverage": coverage,
                        "warnings": json.dumps(warnings),
                        "ttl": ttl,
                    },
                )
                .mappings()
                .one()
            )
            session.execute(
                text("""UPDATE vulntrack_cve_cache.slots SET lease_token=NULL,
                lease_expires_at=NULL,current_response_id=CASE WHEN :complete
                THEN :response ELSE current_response_id END WHERE id=:id AND lease_token=:token"""),
                {
                    "id": slot,
                    "token": token,
                    "response": response["id"],
                    "complete": coverage == "complete",
                },
            )
            return Result(
                page,
                response["id"],
                {
                    "resolution": "provider",
                    "refresh_attempted": refresh,
                    "used_at": response["fetched_at"].isoformat(),
                },
                response["fetched_at"],
            )
    except Exception as exc:
        if slot:
            try:
                with scoped(request, actor, workspace) as session:
                    lock(session, workspace)
                    lease_context(session, token)
                    session.execute(
                        text("""UPDATE vulntrack_cve_cache.slots SET lease_token=NULL,
                        lease_expires_at=NULL WHERE id=:id AND lease_token=:token"""),
                        {"id": slot, "token": token},
                    )
            except Exception:
                logger.warning("CVE cache lease left for bounded recovery")
        error = (
            exc
            if isinstance(exc, APIError)
            else APIError(503, "CVE_CACHE_UNAVAILABLE", "Almacenamiento CVE no disponible")
        )
        raise CacheFailure(error, refresh) from None


def storage_metadata(session, rows):
    ids = list({r["cache_response_id"] for r in rows if r.get("cache_response_id")})
    if not ids:
        return {}
    return {
        str(r["id"]): r
        for r in session.execute(
            text("""SELECT id,fetched_at,expires_at,coverage
        FROM vulntrack_cve_cache.responses WHERE id=ANY(CAST(:ids AS uuid[]))"""),
            {"ids": ids},
        ).mappings()
    }
