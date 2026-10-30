"""Migration tests clone only the V1 template inside the runner's disposable server."""

import os
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command
from app.db.verify_schema import (
    OWNERSHIP_REVISION,
    V1_REVISION,
    installed_revision,
    verify_schema,
)

pytestmark = pytest.mark.postgres


@pytest.fixture
def legacy_postgres(postgres):
    name = "vulntrack_backend_test_migration_" + uuid4().hex
    # postgres fixture has validated runner identity and DB name before we reach this point.
    with postgres.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.execute(text(f'CREATE DATABASE "{name}" TEMPLATE "vulntrack_backend_test_v1"'))
    engine = create_engine(postgres.url.set(database=name), hide_parameters=True)
    yield engine
    engine.dispose()  # Data lives only in the runner's tmpfs; no persistent DBs are touched.


def migrate(engine, *args, proposal=False):
    switches = ["-x", "ownership_proposal=1"] if proposal else []
    return subprocess.run(
        [sys.executable, "-m", "alembic", *switches, *args],
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "MIGRATION_DATABASE_URL": engine.url.render_as_string(hide_password=False),
        },
    )


def require_success(result):
    assert result.returncode == 0, result.stdout + result.stderr


def asset_snapshot(connection):
    return (
        connection.execute(
            text("SELECT to_jsonb(a) - 'created_by' FROM vulntrack.assets a ORDER BY id")
        )
        .scalars()
        .all()
    )


def test_migrate_v1_preserves_history_and_requires_explicit_proposal(legacy_postgres):
    engine = legacy_postgres
    with engine.connect() as connection:
        assert installed_revision(connection) is None
        assert verify_schema(connection, V1_REVISION)
        before = asset_snapshot(connection)
        assert len(before) == 3
    require_success(migrate(engine, "upgrade", V1_REVISION))
    rejected = migrate(engine, "upgrade", "head")
    assert rejected.returncode != 0
    assert "ownership_proposal=1" in rejected.stderr
    with engine.connect() as connection:
        assert installed_revision(connection) == V1_REVISION
        assert verify_schema(connection, V1_REVISION)
    require_success(migrate(engine, "upgrade", "head", proposal=True))
    require_success(migrate(engine, "check"))
    with engine.connect() as connection:
        assert installed_revision(connection) == OWNERSHIP_REVISION
        assert verify_schema(connection)
        assert asset_snapshot(connection) == before
        assert (
            connection.scalar(
                text("SELECT count(*) FROM vulntrack.assets WHERE created_by IS NOT NULL")
            )
            == 0
        )
        fk = [
            fk
            for fk in inspect(connection).get_foreign_keys("assets", schema="vulntrack")
            if fk["name"] == "assets_created_by_fkey"
        ]
        assert fk[0]["options"]["ondelete"] == "RESTRICT"
    # Recognition and migration are repeatable; there is no duplicate DDL.
    require_success(migrate(engine, "upgrade", "head", proposal=True))
    assert migrate(engine, "downgrade", V1_REVISION).returncode != 0
    with engine.connect() as connection:
        assert installed_revision(connection) == OWNERSHIP_REVISION
        assert asset_snapshot(connection) == before


def test_unversioned_v1_can_upgrade_without_recreating_tables(legacy_postgres):
    engine = legacy_postgres
    with engine.connect() as connection:
        oid = connection.scalar(text("SELECT 'vulntrack.assets'::regclass::oid"))
    require_success(migrate(engine, "upgrade", "head", proposal=True))
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT 'vulntrack.assets'::regclass::oid")) == oid
        assert verify_schema(connection)


def test_drift_blocks_baseline_without_stamping(legacy_postgres):
    with legacy_postgres.begin() as connection:
        connection.execute(text("ALTER TABLE vulntrack.assets ADD COLUMN unexpected text"))
    result = migrate(legacy_postgres, "upgrade", "head", proposal=True)
    assert result.returncode != 0
    assert "Baseline bloqueado" in result.stderr
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) is None
        assert "unexpected" in {
            c["name"] for c in inspect(connection).get_columns("assets", schema="vulntrack")
        }


def test_unknown_revision_is_rejected(legacy_postgres):
    with legacy_postgres.begin() as connection:
        connection.execute(
            text("CREATE TABLE public.alembic_version(version_num varchar(32) PRIMARY KEY)")
        )
        connection.execute(text("INSERT INTO public.alembic_version VALUES ('unknown_revision')"))
    result = migrate(legacy_postgres, "upgrade", "head", proposal=True)
    assert result.returncode != 0
    assert "Revisión Alembic desconocida" in result.stderr


def test_cannot_blind_stamp_ownership(legacy_postgres):
    result = migrate(legacy_postgres, "stamp", OWNERSHIP_REVISION)
    assert result.returncode != 0
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) is None
        assert verify_schema(connection, V1_REVISION)


def test_failed_migration_rolls_back_ddl_and_revision(legacy_postgres, monkeypatch):
    import app.db.verify_schema as verifier

    require_success(migrate(legacy_postgres, "upgrade", V1_REVISION))
    with legacy_postgres.connect() as connection:
        before = asset_snapshot(connection)
    real_verify = verifier.verify_schema

    def fail_after_ddl(connection, revision=OWNERSHIP_REVISION):
        result = real_verify(connection, revision)
        if revision == OWNERSHIP_REVISION:
            raise RuntimeError("injected post-DDL verification failure")
        return result

    config = Config("alembic.ini")
    config.cmd_opts = SimpleNamespace(x=["ownership_proposal=1"])
    with monkeypatch.context() as patch:
        patch.setenv(
            "MIGRATION_DATABASE_URL", legacy_postgres.url.render_as_string(hide_password=False)
        )
        patch.setattr(verifier, "verify_schema", fail_after_ddl)
        with pytest.raises(RuntimeError, match="post-DDL"):
            command.upgrade(config, "head")
    with legacy_postgres.connect() as connection:
        assert installed_revision(connection) == V1_REVISION
        assert real_verify(connection, V1_REVISION)
        assert asset_snapshot(connection) == before


def test_database_sql_proposal_has_same_schema(legacy_postgres):
    from pathlib import Path

    with legacy_postgres.begin() as connection:
        before = asset_snapshot(connection)
        proposal = Path("docs/proposals/database-v11-ownership.sql").read_text()
        connection.exec_driver_sql(proposal)
        assert verify_schema(connection)
        assert installed_revision(connection) is None  # SQL does not claim an Alembic baseline.
        assert asset_snapshot(connection) == before
