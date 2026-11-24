"""Offline plan from local readonly CPE catalogue; NEVER execute a live CVE request."""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.integrations.cve_transport import CVE_URL
from app.schemas.cpe import parse_cpe, unbind_component
from scripts.v2_development import PersistentV2


def build_plan(record):
    parts = parse_cpe(record["cpe_name"])
    UUID(str(record["cpe_name_id"]))
    if (
        record["mode"] != "live"
        or record["source"] != "nvd-feed"
        or record["deprecated"] is not False
        or any(p in {"*", "-"} or "*" in p or "?" in p for p in parts[1:4])
        or parts[0] not in {"a", "o"}
        or any(
            unbind_component(parts[i]) != record[k]
            for i, k in ((1, "vendor"), (2, "product"), (3, "version"))
        )
    ):
        raise ValueError("Current official, nondeprecated, exact public CPE required")
    return {
        "kind": "offline-plan-only",
        "prepared_utc": datetime.now(UTC).isoformat(),
        "release_live_enabled": False,
        "authorization_granted": False,
        "official_catalogue_cpe_name_id": str(record["cpe_name_id"]),
        "official_catalogue_source": record["source"],
        "catalogue_mode": record["mode"],
        "endpoint_candidate_not_revalidated": CVE_URL,
        "method": "GET",
        "params": {"cpeName": record["cpe_name"], "startIndex": 0, "resultsPerPage": 20},
        "budget": {
            "requests": 1,
            "pages": 1,
            "records": 20,
            "response_bytes": 2097152,
            "total_seconds": 20,
            "retries": 0,
        },
        "required_before_execution": [
            "official_contract_and_quota_readable",
            "bounded_pinned_public_dns_egress_review",
            "isolated_postgresql_workspace",
            "current_human_confirmed_identification",
            "explicit_later_authorization",
            "reviewed_5c2_release",
        ],
    }


def prepare(cpe_id, cpe):
    parse_cpe(cpe)
    # Existing private profile config only; no HTTP call and no inventory write.
    settings = PersistentV2("rc3-catalog31").settings(worker=False)
    if settings.cpe_catalog_read_url is None:
        raise ValueError("Local readonly catalogue configuration required")
    value = settings.cpe_catalog_read_url.get_secret_value()
    url = make_url(value)
    if (
        url.drivername != "postgresql+psycopg"
        or url.host not in {"127.0.0.1", "::1"}
        or url.username != "vulntrack_catalog_reader"
    ):
        raise ValueError("Dedicated loopback readonly catalogue login required")
    engine = create_engine(value, hide_parameters=True, connect_args={"connect_timeout": 5})
    try:
        with engine.begin() as db:
            db.execute(text("SET TRANSACTION READ ONLY"))
            assert db.scalar(text("SELECT current_user")) == "vulntrack_catalog_reader"
            if db.scalar(
                text(
                    "SELECT has_table_privilege(current_user,'vulntrack_catalog.products', "
                    "'INSERT,UPDATE,DELETE,TRUNCATE')"
                )
            ):
                raise ValueError("Readonly catalogue role required")
            record = (
                db.execute(
                    text("""SELECT mode,cpe_name_id,cpe_name,vendor,product,version,
                deprecated,source FROM vulntrack_catalog.products WHERE mode='live'
                AND cpe_name_id=:id AND cpe_name=:cpe"""),
                    {"id": cpe_id, "cpe": cpe},
                )
                .mappings()
                .one()
            )
            return build_plan(dict(record))
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--authorization-record", type=Path)
    parser.add_argument("--plan-file", type=Path)
    parser.add_argument("--cpe-name-id", type=UUID)
    parser.add_argument("--cpe")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.execute_live:
        print(
            "NO-GO: 5C.1 does not permit live execution; a reviewed 5C.2 release "
            "and later explicit authorization are required.",
            file=sys.stderr,
        )
        return 2
    if not args.plan or not args.cpe or not args.cpe_name_id or not args.output:
        parser.error("--plan --cpe-name-id --cpe --output required")
    try:
        result = prepare(args.cpe_name_id, args.cpe)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except Exception as exc:
        print(
            "Offline plan refused: " + type(exc).__name__ + "; no credentials printed.",
            file=sys.stderr,
        )
        return 1
    print("Offline public-CPE plan prepared; no CVE request or authorization granted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
