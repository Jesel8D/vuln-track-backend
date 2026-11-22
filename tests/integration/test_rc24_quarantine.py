"""Migration and accounting preserve the exact invalid official name."""

import pytest
from sqlalchemy import create_engine, text

from app.services import cpe_quarantine as service
from scripts.disposable_v2 import DisposableV2

pytestmark = pytest.mark.postgres


def test_migration_and_quarantine_are_additive(tmp_path, monkeypatch, postgres):
    # The outer fixture enforces this test only in the verified DB test runner.
    assert postgres is not None
    table = "vulntrack_catalog.feed_quarantine"
    with DisposableV2(
        "existing", sql_checks=False, verification_revision="v2_0005_cpe_summary"
    ) as old:
        assert not old.sql(f"SELECT to_regclass('{table}');").stdout.strip()
        old.verification_migrate()
        engine = create_engine(old.url("postgres"), hide_parameters=True)
        with engine.begin() as db:
            db.execute(
                text("""
                INSERT INTO vulntrack_catalog.feed_imports
                  (digest,source_modified,gz_bytes,json_bytes,total_items,next_item,stored,discarded,status)
                VALUES (:digest,:date,:gz,:js,:count,:count,:stored,1,'complete')
            """),
                {
                    "digest": service.EDITION.digest,
                    "date": service.EDITION.modified,
                    "gz": service.EDITION.gz_bytes,
                    "js": service.EDITION.json_bytes,
                    "count": service.COUNT,
                    "stored": service.COUNT - 1,
                },
            )
        entry = {
            "cpe": {
                "cpeNameId": str(service.CPE_ID),
                "cpeName": service.CPE_NAME,
                "titles": [{"lang": "en", "title": "Ipswitch WhatsUp"}],
            }
        }
        monkeypatch.setattr(service, "ORDINAL", 1)
        monkeypatch.setattr(service, "verify", lambda *_: service.COUNT)
        monkeypatch.setattr(service, "rows", lambda *_: (item for item in [entry]))
        try:
            assert service.quarantine(engine, tmp_path)["inserted"] is True
            assert service.quarantine(engine, tmp_path)["inserted"] is False
            with engine.connect() as db:
                assert db.scalar(text(f"SELECT original FROM {table}")) == entry
                assert db.scalar(text("SELECT count(*) FROM vulntrack_catalog.products")) == 0
                assert db.scalar(text("SELECT discarded FROM vulntrack_catalog.feed_imports")) == 1
        finally:
            engine.dispose()
