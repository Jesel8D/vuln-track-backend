"""Adoption is a separate, verified path; it must never fake a V1 migration."""

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.db.adopt_schema import adopt_verified_ownership
from app.db.coordination import lock_schema_operation
from app.db.verify_schema import OWNERSHIP_REVISION, installed_revision, verify_schema
from tests.integration.test_migrations import asset_snapshot, migrate, require_success

pytestmark = pytest.mark.postgres


def proposed_schema(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql(Path("docs/proposals/database-v11-ownership.sql").read_text())


def adopt(connection):
    return adopt_verified_ownership(connection, ScriptDirectory.from_config(Config("alembic.ini")))


def test_legacy_v1_is_never_stamped_as_v11(legacy_postgres):
    with (
        pytest.raises(RuntimeError, match="Baseline bloqueado"),
        legacy_postgres.begin() as connection,
    ):
        adopt(connection)
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) is None


def test_verified_adoption_preserves_data_and_is_idempotent(legacy_postgres):
    proposed_schema(legacy_postgres)
    with legacy_postgres.begin() as connection:
        before = asset_snapshot(connection)
        oid = connection.scalar(text("SELECT 'vulntrack.assets'::regclass::oid"))
        assert installed_revision(connection) is None
        assert adopt(connection) == OWNERSHIP_REVISION
    for _ in range(2):
        with legacy_postgres.begin() as connection:
            assert adopt(connection) == OWNERSHIP_REVISION
            assert verify_schema(connection)
            assert asset_snapshot(connection) == before
            assert connection.scalar(text("SELECT 'vulntrack.assets'::regclass::oid")) == oid
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM vulntrack.assets WHERE created_by IS NOT NULL")
                )
                == 0
            )
    require_success(migrate(legacy_postgres, "upgrade", "head", proposal=True))
    require_success(migrate(legacy_postgres, "check"))


def test_adoption_requires_explicit_transaction(legacy_postgres):
    with legacy_postgres.connect() as connection:
        with pytest.raises(RuntimeError, match="transacción explícita"):
            adopt(connection)


def test_adoption_does_not_replace_an_existing_v1_revision(legacy_postgres):
    require_success(migrate(legacy_postgres, "upgrade", "0001_database_v1"))
    proposed_schema(legacy_postgres)
    with (
        pytest.raises(RuntimeError, match="no se reemplaza"),
        legacy_postgres.begin() as connection,
    ):
        adopt(connection)


def test_missing_index_blocks_adoption_without_a_false_marker(legacy_postgres):
    proposed_schema(legacy_postgres)
    with legacy_postgres.begin() as connection:
        connection.execute(text("DROP INDEX vulntrack.assets_owner_created_id_idx"))
    with (
        pytest.raises(RuntimeError, match="Baseline bloqueado"),
        legacy_postgres.begin() as connection,
    ):
        adopt(connection)
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) is None


def test_post_stamp_failure_rolls_back_marker(legacy_postgres, monkeypatch):
    import app.db.adopt_schema as adoption

    proposed_schema(legacy_postgres)
    real_verify = adoption.verify_schema
    calls = 0

    def fail_after_stamp(connection, revision):
        nonlocal calls
        calls += 1
        real_verify(connection, revision)
        if calls == 2:
            assert installed_revision(connection) == OWNERSHIP_REVISION
            raise RuntimeError("injected post-stamp validation failure")

    monkeypatch.setattr(adoption, "verify_schema", fail_after_stamp)
    with pytest.raises(RuntimeError, match="post-stamp"), legacy_postgres.begin() as connection:
        adopt(connection)
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) is None
        assert verify_schema(connection)


def test_schema_operations_are_serialized_and_timeout_safely(legacy_postgres):
    proposed_schema(legacy_postgres)
    with legacy_postgres.begin() as first:
        lock_schema_operation(first)
        with pytest.raises(OperationalError) as blocked, legacy_postgres.begin() as second:
            second.execute(text("SET LOCAL lock_timeout='100ms'"))
            adopt(second)
        assert blocked.value.orig.sqlstate == "55P03"
    with legacy_postgres.begin() as connection:
        assert installed_revision(connection) is None
        assert adopt(connection) == OWNERSHIP_REVISION


def test_disabled_trigger_is_not_accepted_as_compatible(legacy_postgres):
    proposed_schema(legacy_postgres)
    with legacy_postgres.begin() as connection:
        connection.execute(text("ALTER TABLE vulntrack.assets DISABLE TRIGGER assets_touch"))
    with pytest.raises(RuntimeError, match="triggers"), legacy_postgres.begin() as connection:
        adopt(connection)
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) is None
