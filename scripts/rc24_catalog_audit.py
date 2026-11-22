"""Quarantine one official, digest-verified rejection in the dedicated RC2.4 profile."""

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

from app.services.cpe_quarantine import quarantine
from scripts.rc24_backup import PROFILE
from scripts.v2_development import ROOT, PersistentV2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    if not (ROOT / ".local" / PROFILE / "config.json").is_file():
        raise RuntimeError("Initialize RC2.4 first")
    stack = PersistentV2(PROFILE)
    if stack.volume != "vulntrack_v2_rc2_catalog24_pgdata":
        raise RuntimeError("Only the owned RC2.4 volume is allowed")
    with stack.lock():
        stack.verify()
        engine = create_engine(stack.url("postgres"), hide_parameters=True)
        try:
            print(json.dumps(quarantine(engine, args.archive)))
        finally:
            engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, SQLAlchemyError, StopIteration) as error:
        print("Catalog audit failed:", type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
