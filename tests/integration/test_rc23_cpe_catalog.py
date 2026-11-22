"""Bulk checkpoints, multilingual exact lookup and additive receipt semantics."""

import pytest
from sqlalchemy import text

from app.services import cpe_feed
from tests.integration.test_rc2_devices import api, owner  # noqa: F401
from tests.unit.test_rc23_cpe_feed import SAMPLE, archive

pytestmark = pytest.mark.postgres


def test_chunked_import_resumes_from_committed_checkpoint(tmp_path, monkeypatch, postgres):
    path, meta = archive(tmp_path)
    monkeypatch.setattr(cpe_feed, "BATCH", 2)

    def interrupted(_):
        raise RuntimeError("simulated operator interruption")

    with pytest.raises(RuntimeError, match="simulated operator interruption"):
        cpe_feed.ingest(postgres, path, meta, progress=interrupted)
    with postgres.connect() as connection:
        state = connection.execute(
            text("""
            SELECT next_item,status FROM vulntrack_catalog.feed_imports WHERE digest=:digest
        """),
            {"digest": meta.digest},
        ).one()
        assert tuple(state) == (2, "failed")
    result = cpe_feed.ingest(postgres, path, meta)
    assert result["status"] == "complete" and result["stored"] == len(SAMPLE)
    assert cpe_feed.ingest(postgres, path, meta) == result
    with postgres.connect() as connection:
        assert connection.scalar(
            text("""
            SELECT count(*) FROM vulntrack_catalog.products WHERE source='nvd-feed'
        """)
        ) == len(SAMPLE)
        assert connection.scalar(
            text("""
            SELECT summary.records = (SELECT count(*) FROM vulntrack_catalog.products
                                      WHERE mode='live')
            FROM vulntrack_catalog.summary WHERE mode='live'
        """)
        )


def test_exact_and_unicode_queries_after_feed(tmp_path, postgres, api):  # noqa: F811
    path, meta = archive(tmp_path)
    # The previous test may already have installed these exact rows.
    assert cpe_feed.ingest(postgres, path, meta)["status"] == "complete"
    app, client = api
    _, user = owner(app, client)
    item = SAMPLE[-1]["cpe"]
    prefix = "/api/v2/cpe-catalog"
    for query in [item["cpeName"], next(t["title"] for t in item["titles"] if t["lang"] == "ja")]:
        reply = client.get(
            prefix + "/candidates",
            params={"q": query, "mode": "live", "deprecated": False},
            headers=user["headers"],
        )
        assert (
            reply.status_code == 200
            and reply.json()["items"][0]["cpe_name_id"] == item["cpeNameId"].lower()
        )
    reply = client.get(
        prefix + "/candidates",
        params={"q": item["cpeName"], "mode": "fixture"},
        headers=user["headers"],
    )
    assert reply.json()["items"] == []
    stats = client.get(prefix + "/status", headers=user["headers"]).json()
    assert stats["feed"]["status"] == "complete" and stats["coverage"] == "complete"
