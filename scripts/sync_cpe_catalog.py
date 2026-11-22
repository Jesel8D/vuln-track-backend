"""Explicitly synchronize at most five CPE pages into the owned RC2.4 volume."""

import argparse
import json
import sys
from uuid import UUID

import httpx
from sqlalchemy import create_engine

from app.core.errors import APIError
from app.integrations.nvd import NVD_URL, NVDClient
from app.services.cpe_catalog import CatalogScope, synchronize
from scripts.catalog_budget import CatalogQuota
from scripts.v2_development import (
    ROOT,
    PersistentV2,
    catalog_live_lock,
    nvd_live_settings,
    private_json,
)

PROFILE = "rc2-catalog24"


def fixture_client():
    capture = json.loads((ROOT / "tests/fixtures/nvd_cpe_verified.json").read_text())

    def upstream(request):
        if str(request.url.copy_with(query=None)) != NVD_URL:
            raise RuntimeError("Unexpected fixture endpoint")
        return httpx.Response(200, json=capture)

    return NVDClient(transport=httpx.MockTransport(upstream), live=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=["live", "fixture"])
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    parser.add_argument("--modified-from")
    parser.add_argument("--modified-through")
    parser.add_argument("--resume", type=UUID)
    parser.add_argument("--pages", type=int, choices=range(1, 6), default=1)
    args = parser.parse_args()
    if args.resume and any((args.vendor, args.product, args.modified_from, args.modified_through)):
        parser.error("--resume reuses the saved scope")
    if not args.resume and not args.vendor:
        parser.error("--vendor required for a new scope")
    scope = (
        None
        if args.resume
        else CatalogScope(
            vendor=args.vendor.strip().lower(),
            product=args.product.strip().lower() if args.product else None,
            since=args.modified_from,
            until=args.modified_through,
        )
    )
    if not (ROOT / ".local" / PROFILE / "config.json").is_file():
        raise RuntimeError("Initialize the owned RC2.4 profile first")
    stack = PersistentV2(PROFILE)
    stack.verify()
    engine = create_engine(stack.url("postgres"), hide_parameters=True)
    budget = stack.directory / "nvd-catalog-budget.json"
    try:
        with catalog_live_lock(stack):
            if args.mode == "live":
                settings = nvd_live_settings(stack)
                client = NVDClient(
                    settings.nvd_api_key,
                    settings.nvd_timeout_seconds,
                    live=True,
                    quota=CatalogQuota(budget, private_json),
                )
                if not args.resume and client.quota.wait_seconds() > 0:
                    seconds = int(client.quota.wait_seconds()) + 1
                    raise RuntimeError(f"Wait {seconds} seconds before a new NVD request")
            else:
                client = fixture_client()
            result = synchronize(
                engine, client, args.mode, scope=scope, resume=args.resume, pages=args.pages
            )
    finally:
        engine.dispose()
    print(json.dumps(result, default=str, indent=2))
    return int(result["status"] == "failed")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, APIError) as error:
        reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print("Catalog sync stopped:", reason, file=sys.stderr)
        raise SystemExit(1) from None
