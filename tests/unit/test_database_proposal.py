import hashlib
import json
from pathlib import Path

import pytest

from scripts.database_proposal import proposed_bootstrap


def test_proposal_manifest_pins_original_sql_and_reviewed_patch():
    root = Path("docs/proposals")
    manifest = json.loads((root / "database-v1.1-manifest.json").read_text())
    assert (
        manifest["source_sha256"]
        == "fd2984a80911cd094283d9c9b1f503a7a0db87b921f9169c2a8362a8941b9297"
    )
    assert (
        hashlib.sha256((root / manifest["patch"]).read_bytes()).hexdigest()
        == manifest["patch_sha256"]
    )
    assert manifest["status"] == "PROPUESTA"


def test_unknown_source_is_rejected_without_modification(tmp_path):
    (tmp_path / "sql").mkdir()
    source = tmp_path / "sql/001_schema.sql"
    source.write_text("unreviewed schema")
    with pytest.raises(RuntimeError, match="manifiesto"):
        proposed_bootstrap(tmp_path)
    assert source.read_text() == "unreviewed schema"
