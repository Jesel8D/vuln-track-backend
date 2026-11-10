"""Verified NVD fixture; test variants explicitly simulate response scenarios."""

import json
from copy import deepcopy
from pathlib import Path
from uuid import UUID

import httpx

from app.integrations.nvd import NVDClient, Quota

RAW = json.loads((Path(__file__).parent / "fixtures/nvd_cpe_verified.json").read_text())
NAME_ID = UUID(RAW["products"][0]["cpe"]["cpeNameId"])


def client_for(raw=None, handler=None, quota=None):
    data = deepcopy(RAW if raw is None else raw)
    transport = httpx.MockTransport(handler or (lambda request: httpx.Response(200, json=data)))
    return NVDClient(transport=transport, quota=quota or Quota(clock=lambda: 100.0))
