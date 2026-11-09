"""CPE migration/adoption use only the runner's disposable V1 template."""

from types import SimpleNamespace

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from alembic import command
from app.db.adopt_schema import adopt_verified
from app.db.verify_schema import CPE_REVISION, OWNERSHIP_REVISION, installed_revision, verify_schema
from tests.integration.test_migrations import asset_snapshot, migrate, require_success

pytestmark = pytest.mark.postgres


def test_explicit_cpe_upgrade_preserves_v1_and_v11_history(legacy_postgres):
    engine = legacy_postgres
    require_success(migrate(engine, "upgrade", OWNERSHIP_REVISION, proposal=True))
    with engine.connect() as c:
        before = asset_snapshot(c)
        findings = (
            c.execute(text("SELECT to_jsonb(f) FROM vulntrack.findings f ORDER BY id"))
            .scalars()
            .all()
        )
        oid = c.scalar(text("SELECT 'vulntrack.assets'::regclass::oid"))
    rejected = migrate(engine, "upgrade", CPE_REVISION)
    assert rejected.returncode != 0 and "mvp_a=1" in rejected.stderr
    with engine.connect() as c:
        assert installed_revision(c) == OWNERSHIP_REVISION
        assert verify_schema(c, OWNERSHIP_REVISION)
    require_success(migrate(engine, "upgrade", CPE_REVISION, proposal=True))
    with engine.connect() as c:
        assert verify_schema(c, CPE_REVISION)
        assert asset_snapshot(c) == before
        assert (
            c.execute(text("SELECT to_jsonb(f) FROM vulntrack.findings f ORDER BY id"))
            .scalars()
            .all()
            == findings
        )
        assert c.scalar(text("SELECT 'vulntrack.assets'::regclass::oid")) == oid
    require_success(migrate(engine, "check"))
    require_success(migrate(engine, "upgrade", "head", proposal=True))
    assert migrate(engine, "downgrade", OWNERSHIP_REVISION).returncode != 0


def test_cpe_post_ddl_failure_rolls_back_schema_and_marker(legacy_postgres, monkeypatch):
    import app.db.verify_schema as verifier

    require_success(migrate(legacy_postgres, "upgrade", OWNERSHIP_REVISION, proposal=True))
    real = verifier.verify_schema

    def injected(connection, revision=None):
        result = real(connection, revision)
        if revision == CPE_REVISION:
            raise RuntimeError("injected CPE post-DDL failure")
        return result

    config = Config("alembic.ini")
    config.cmd_opts = SimpleNamespace(x=["mvp_a=1"])
    with monkeypatch.context() as patch:
        patch.setenv(
            "MIGRATION_DATABASE_URL", legacy_postgres.url.render_as_string(hide_password=False)
        )
        patch.setattr(verifier, "verify_schema", injected)
        with pytest.raises(RuntimeError, match="post-DDL"):
            command.upgrade(config, "head")
    with legacy_postgres.connect() as c:
        assert installed_revision(c) == OWNERSHIP_REVISION
        assert real(c, OWNERSHIP_REVISION)
        assert not inspect(c).has_table("asset_cpe_identifications", schema="vulntrack")


def test_never_adopt_v1_as_cpe_without_required_schema(legacy_postgres):
    with pytest.raises(RuntimeError, match="Baseline bloqueado"), legacy_postgres.begin() as c:
        adopt_verified(c, ScriptDirectory.from_config(Config("alembic.ini")), CPE_REVISION)
    with legacy_postgres.connect() as c:
        assert installed_revision(c) is None


def test_cpe_catalog_rejects_disabled_guard_and_missing_unique_index(postgres):
    for statement in [
        "ALTER TABLE vulntrack.asset_cpe_identifications DISABLE TRIGGER cpe_event_guard",
        "DROP INDEX vulntrack.cpe_current_unique",
    ]:
        with pytest.raises(RuntimeError, match="Baseline bloqueado"), postgres.begin() as c:
            c.execute(text(statement))
            verify_schema(c, CPE_REVISION)
    with postgres.connect() as c:
        assert verify_schema(c, CPE_REVISION)
