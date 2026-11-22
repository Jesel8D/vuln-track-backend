"""Tampering and wrong keys fail before PostgreSQL receives an archive."""

import shutil
import sys

import pytest

from scripts import rc24_backup as backup


@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg required for archive test")
def test_archive_authentication_and_corruption(monkeypatch, tmp_path):
    key = tmp_path / "separate.key"
    key.touch(mode=0o600)
    key.write_text("A" * 48)
    output = tmp_path / "archive"
    monkeypatch.setattr(
        backup, "postgres",
        lambda *_args: [sys.executable, "-c", "import sys; sys.stdout.write('archive test')"],
    )
    saved = backup.dump("isolated", output, key, "synthetic", 1024, backup.SOURCES)
    assert saved == backup.check(output, key)
    assert b"archive test" not in (output / backup.ARCHIVE).read_bytes()
    bad_key = tmp_path / "wrong.key"
    bad_key.touch(mode=0o600)
    bad_key.write_text("B" * 48)
    with pytest.raises(backup.RecoveryError, match="authentication failed"):
        backup.check(output, bad_key)
    with (output / backup.ARCHIVE).open("r+b") as stream:
        stream.seek(5)
        byte = stream.read(1)
        stream.seek(5)
        stream.write(bytes([byte[0] ^ 1]))
    with pytest.raises(backup.RecoveryError, match="checksum mismatch"):
        backup.check(output, key)


def test_backup_refuses_key_in_destination(tmp_path):
    output = tmp_path / "archive"
    with pytest.raises(backup.RecoveryError, match="stored separately"):
        backup.dump("never-opened", output, output / "key", "synthetic", 1, backup.SOURCES)
    assert not output.exists()
