"""MVP-A data/history -> MVP-B, fresh equivalence, drift and transactional aborts."""

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from alembic.config import Config
from sqlalchemy import text

from alembic import command
from app.db.session import build_session_factory
from app.db.verify_schema import CPE_REVISION, CVE_REVISION, installed_revision, verify_schema
from app.models.database_v1 import User
from app.schemas.assets import AssetCreate
from app.schemas.cpe import Confirm, NeedsReview
from app.services.assets import AssetService
from app.services.authorization import AssetAuthorization
from app.services.cpe import IdentificationService
from tests.cpe_support import NAME_ID, client_for
from tests.integration.test_migrations import migrate, require_success

pytestmark = pytest.mark.postgres


def test_mvp_a_registered_assets_confirmed_and_history_survive_upgrade(legacy_postgres):
    engine = legacy_postgres
    require_success(migrate(engine, "upgrade", CPE_REVISION, proposal=True))
    factory = build_session_factory(engine)
    actor = uuid4()
    with factory.begin() as s:
        s.add(User(id=actor, username="migration_" + actor.hex, active=True))
    asset = AssetService(factory, AssetAuthorization()).register(
        actor,
        uuid4(),
        AssetCreate(
            device_type="router",
            manufacturer="Cisco",
            model="RV340",
            version="1.0.0.33",
            site_label="LAB",
        ),
    )
    asset_id = UUID(asset["id"])
    service = IdentificationService(factory, AssetAuthorization(), client_for())
    event = service.record(
        actor,
        asset_id,
        uuid4(),
        Confirm(
            state="confirmed",
            cpe_name_id=NAME_ID,
            component_kind="firmware",
            expected_current_id=None,
            reason="Confirmación anterior a MVP-B",
        ),
    )
    service.record(
        actor,
        asset_id,
        uuid4(),
        NeedsReview(
            state="needs_review",
            expected_current_id=event["id"],
            reason="Revisión anterior a migración",
        ),
    )
    with engine.connect() as c:
        before = {
            table: c.execute(text(f"SELECT to_jsonb(t) FROM vulntrack.{table} t ORDER BY id"))
            .scalars()
            .all()
            for table in ["assets", "asset_cpe_identifications", "findings"]
        }
        oid = c.scalar(text("SELECT 'vulntrack.analysis_runs'::regclass::oid"))
    require_success(migrate(engine, "upgrade", "head"))
    require_success(migrate(engine, "check"))
    with engine.connect() as c:
        assert installed_revision(c) == CVE_REVISION and verify_schema(c)
        assert c.scalar(text("SELECT 'vulntrack.analysis_runs'::regclass::oid")) == oid
        for table in ["assets", "asset_cpe_identifications"]:
            assert (
                c.execute(text(f"SELECT to_jsonb(t) FROM vulntrack.{table} t ORDER BY id"))
                .scalars()
                .all()
                == before[table]
            )
        rows = (
            c.execute(text("SELECT to_jsonb(t) FROM vulntrack.findings t ORDER BY id"))
            .scalars()
            .all()
        )
        assert [{k: r[k] for k in before["findings"][0]} for r in rows] == before["findings"]
        assert all(r["evidence"] is None for r in rows)  # no invented provenance
    assert migrate(engine, "downgrade", CPE_REVISION).returncode != 0
    require_success(migrate(engine, "upgrade", "head"))


def test_duplicate_legacy_cve_aborts_without_dropping_or_merging(legacy_postgres):
    require_success(migrate(legacy_postgres, "upgrade", CPE_REVISION, proposal=True))
    with legacy_postgres.begin() as c:
        c.execute(
            text(
                "INSERT INTO vulntrack.findings(id,analysis_id,external_id) "
                "SELECT :id,analysis_id,external_id FROM vulntrack.findings LIMIT 1"
            ),
            {"id": uuid4()},
        )
    result = migrate(legacy_postgres, "upgrade", "head")
    assert result.returncode != 0
    with legacy_postgres.connect() as c:
        assert installed_revision(c) == CPE_REVISION and verify_schema(c, CPE_REVISION)
        assert c.scalar(text("SELECT count(*) FROM vulntrack.findings")) == 2


def test_b_post_ddl_failure_rolls_back_and_preserves_a_marker(legacy_postgres, monkeypatch):
    import app.db.verify_schema as verifier

    require_success(migrate(legacy_postgres, "upgrade", CPE_REVISION, proposal=True))
    real = verifier.verify_schema

    def injected(connection, revision=None):
        result = real(connection, revision)
        if revision == CVE_REVISION:
            raise RuntimeError("injected B verification failure")
        return result

    config = Config("alembic.ini")
    config.cmd_opts = SimpleNamespace(x=[])
    monkeypatch.setenv(
        "MIGRATION_DATABASE_URL", legacy_postgres.url.render_as_string(hide_password=False)
    )
    monkeypatch.setattr(verifier, "verify_schema", injected)
    with pytest.raises(RuntimeError, match="B verification"):
        command.upgrade(config, "head")
    with legacy_postgres.connect() as c:
        assert installed_revision(c) == CPE_REVISION and real(c, CPE_REVISION)


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE vulntrack.analysis_runs DISABLE TRIGGER analysis_guard",
        "ALTER TABLE vulntrack.findings DROP CONSTRAINT findings_cve_unique",
        "DROP INDEX vulntrack.analysis_active_unique",
    ],
)
def test_b_catalog_rejects_missing_integrity(postgres, statement):
    with pytest.raises(RuntimeError, match="Baseline bloqueado"), postgres.begin() as c:
        c.execute(text(statement))
        verify_schema(c)
    with postgres.connect() as c:
        assert verify_schema(c)
