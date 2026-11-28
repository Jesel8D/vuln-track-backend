"""Non-blocking exclusive file locks for local VulnTrack operators."""

from contextlib import contextmanager
import os


class FileLockBusy(RuntimeError):
    """Raised when another process owns the requested lock."""


@contextmanager
def exclusive_nonblocking_lock(stream):
    """Lock one file for the context; the lock is released even on failure."""
    if os.name == "nt":
        import msvcrt

        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write("\0")
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise FileLockBusy from None
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise FileLockBusy from None
    try:
        yield
    finally:
        fcntl.flock(stream, fcntl.LOCK_UN)
