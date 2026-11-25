"""Explicit maintenance job. Never invoked by the API startup."""

import os
import subprocess
import sys
from pathlib import Path


def main():
    os.environ["MIGRATION_DATABASE_URL"] = Path("/run/bootstrap/migration-url").read_text().strip()
    for args in [
        ["-x", "ownership_proposal=1", "-x", "mvp_a=1", "upgrade", "head"],
        ["-c", "alembic-verification.ini", "upgrade", "head"],
    ]:
        result = subprocess.run([sys.executable, "-m", "alembic", *args], capture_output=True)
        if result.returncode:
            raise RuntimeError(
                "Migration failed; inspect protected maintenance logs, never reset volumes"
            )
    print("PASS explicit migrations: V1 head and verification v10")


if __name__ == "__main__":
    main()
