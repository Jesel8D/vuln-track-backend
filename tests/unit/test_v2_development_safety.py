"""Prevent adopting foreign Docker resources or replacing initialized development data."""

from pathlib import Path

import pytest

import scripts.v2_development as development


@pytest.fixture
def owned(tmp_path, monkeypatch):
    source = development.ROOT.parent / "vuln-track-database"
    monkeypatch.setattr(development, "ROOT", tmp_path)
    stack = development.PersistentV2("unit-safety", pg_port=0, api_port=0, web_port=0)
    stack.reference = source
    return stack


@pytest.mark.parametrize("foreign_kind", ["volume", "container", "network"])
def test_foreign_resource_collision_cannot_create_or_mutate_resources(
    owned, monkeypatch, foreign_kind
):
    def inspect(kind, name):
        if kind == foreign_kind:
            return {
                "Labels": {"io.vulntrack.installation": "another-project"},
                "Config": {"Labels": {"io.vulntrack.installation": "another-project"}},
            }
        return None

    monkeypatch.setattr(owned, "inspect", inspect)
    calls = []
    monkeypatch.setattr(development, "command", lambda args, **kwargs: calls.append(args))
    with pytest.raises(RuntimeError, match="another installation"):
        owned.preflight(create_volume=True)
    assert calls == []


def test_missing_initialized_volume_is_not_recreated(owned, monkeypatch):
    owned.config["phase"] = "ready"
    monkeypatch.setattr(owned, "inspect", lambda *args: None)
    calls = []
    monkeypatch.setattr(development, "command", lambda args, **kwargs: calls.append(args))
    with pytest.raises(RuntimeError, match="do not recreate"):
        owned.preflight(create_volume=True)
    assert calls == []


def test_restore_never_overwrites_ready_profile(owned, monkeypatch):
    owned.config["phase"] = "ready"
    calls = []
    monkeypatch.setattr(development, "command", lambda args, **kwargs: calls.append(args))
    with pytest.raises(RuntimeError, match="NEW profile"):
        owned.restore(Path("/does-not-exist/backup.dump"))
    assert calls == []
