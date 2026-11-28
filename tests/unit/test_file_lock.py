import pytest

from scripts.file_lock import FileLockBusy, exclusive_nonblocking_lock


def test_exclusive_lock_rejects_concurrent_owner_and_releases(tmp_path):
    path = tmp_path / "operator.lock"
    with path.open("a+") as first:
        with exclusive_nonblocking_lock(first):
            with path.open("a+") as second:
                with pytest.raises(FileLockBusy):
                    with exclusive_nonblocking_lock(second):
                        pass

        with path.open("a+") as second:
            with exclusive_nonblocking_lock(second):
                pass
