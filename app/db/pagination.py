"""Bounded workspace pages; SQL fragments come only from trusted server constants."""

from datetime import datetime

from sqlalchemy import text


def page(session, *, select, table, where, sort, scope, limit, offset):
    # A single statement gives items and total the same MVCC snapshot. No catalog
    # reads. Values from requests are parameters, never SQL fragments.
    result = (
        session.execute(
            text(f"""WITH matches AS MATERIALIZED (
            SELECT {select} FROM {table} WHERE {where}
        ) SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY {sort}),'[]') AS items,
                 (SELECT count(*) FROM matches) AS total
          FROM (SELECT * FROM matches ORDER BY {sort} LIMIT :limit OFFSET :offset) p"""),
            {**scope, "limit": limit, "offset": offset},
        )
        .mappings()
        .one()
    )
    # Restore top-level timestamp types so FastAPI preserves the same ISO
    # representation as native SQL row mappings (including microsecond padding).
    for item in result["items"]:
        for key, value in item.items():
            if isinstance(value, str) and (key.endswith("_at") or key == "source_timestamp"):
                item[key] = datetime.fromisoformat(value)
    return {
        "items": result["items"],
        "page": {"limit": limit, "offset": offset, "total": result["total"]},
    }
