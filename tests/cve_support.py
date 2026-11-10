"""One verified live response; every derivative is explicitly a simulated scenario."""

import json
from copy import deepcopy
from pathlib import Path

import httpx

from app.integrations.nvd import Quota
from app.integrations.nvd_cve import CVEClient
from tests.cpe_support import RAW as CPE_RAW

RAW = json.loads((Path(__file__).parent / "fixtures/nvd_cve_verified.json").read_text())
CPE = CPE_RAW["products"][0]["cpe"]["cpeName"]
RECORD = RAW["vulnerabilities"][0]["cve"]


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += max(0, seconds) + 0.001


def response_page(ids=None, total=None, start=0, *, simple=False):
    data = deepcopy(RAW)
    ids = [RECORD["id"]] if ids is None else ids
    data.update(
        startIndex=start, resultsPerPage=len(ids), totalResults=len(ids) if total is None else total
    )
    data["vulnerabilities"] = []
    for id_ in ids:
        cve = deepcopy(RECORD)
        cve["id"] = id_
        if simple:
            cve["configurations"] = [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": CPE,
                                    "matchCriteriaId": "8750A439-1D5F-4D40-9875-D5CD0C116C11",
                                }
                            ],
                        }
                    ]
                }
            ]
        data["vulnerabilities"].append({"cve": cve})
    return data


def client_for(handler=None, raw=None, clock=None):
    clock = clock or Clock()
    return CVEClient(
        transport=httpx.MockTransport(
            handler or (lambda r: httpx.Response(200, json=deepcopy(raw or RAW)))
        ),
        quota=Quota(clock=clock),
    )
