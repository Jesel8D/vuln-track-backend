"""Targeted schema compatibility and failure boundaries; all data synthetic/offline."""

from copy import deepcopy
from unittest.mock import Mock

import httpx
import pytest

from app.core.errors import APIError
from app.services.nvd_findings import finding_rows
from app.services.v2_cve_cache import validate_public_page
from scripts.nvd_trial import CPE, TrialClient


def sample():
    record = {
        "id": "CVE-2026-99990001",
        "published": "2026-06-17T12:00:00Z",
        "lastModified": "2026-06-17T12:00:00Z",
        "references": [],
        "descriptions": [{"lang": "en", "value": "Synthetic offline record"}],
        "metrics": {
            "ssvcV203": [
                {
                    "source": "synthetic-cisa-adp",
                    "ssvcData": {
                        "options": [{"User": "synthetic"}],
                        "role": "test",
                        "version": "2.0.3",
                    },
                }
            ]
        },
        "publicFutureField": {"value": "kept", "nullable": None},
    }
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-11-24T12:00:00Z",
        "vulnerabilities": [{"cve": record}],
    }


def test_three_demonstrated_rejections_are_corrected_without_inventing_status():
    raw = sample()
    page, body, _ = validate_public_page(raw, limit=20)
    import json

    stored = json.loads(body)["vulnerabilities"][0]["cve"]
    assert validate_public_page(page, limit=20)[1] == body
    assert "vulnStatus" not in stored
    assert stored["metrics"] == raw["vulnerabilities"][0]["cve"]["metrics"]
    assert stored["publicFutureField"] == {"value": "kept", "nullable": None}
    records, findings, _ = finding_rows(page, CPE, "2.4.49")
    assert findings[0]["severity"] == "unknown" and findings[0]["applicability"] == "undetermined"
    assert records[0]["publicFutureField"] == stored["publicFutureField"]
    assert json.loads(findings[0]["evidence"])["vulnStatus"] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "required",
        "type",
        "id",
        "ssvc-required",
        "ssvc-type",
        "ssvc-extra",
        "description-extra",
        "entry-extra",
        "page-extra",
        "private",
        "nested-private",
        "unsafe-key",
        "bad-url",
        "depth",
        "size",
        "duplicate-id",
        "count",
        "affected-status",
    ],
)
def test_invalid_schema_privacy_and_limits_still_reject(mutation):
    raw = deepcopy(sample())
    cve = raw["vulnerabilities"][0]["cve"]
    if mutation == "required":
        del cve["descriptions"]
    elif mutation == "type":
        cve["references"] = "wrong"
    elif mutation == "id":
        cve["id"] = "not-a-CVE"
    elif mutation == "ssvc-required":
        del cve["metrics"]["ssvcV203"][0]["ssvcData"]["role"]
    elif mutation == "ssvc-type":
        cve["metrics"]["ssvcV203"][0]["ssvcData"]["options"] = [{"User": 42}]
    elif mutation == "ssvc-extra":
        cve["metrics"]["ssvcV203"][0]["ssvcData"]["unknown"] = True
    elif mutation == "description-extra":
        cve["descriptions"][0]["unknown"] = True
    elif mutation == "entry-extra":
        raw["vulnerabilities"][0]["unknown"] = True
    elif mutation == "page-extra":
        raw["unknown"] = True
    elif mutation == "private":
        cve["workspaceId"] = "synthetic-secret"
    elif mutation == "nested-private":
        cve["metrics"]["ssvcV203"][0]["password"] = "secret"
    elif mutation == "unsafe-key":
        cve["publicFutureField"]["__proto__"] = {"admin": True}
    elif mutation == "bad-url":
        cve["references"] = [{"url": "javascript:alert(1)"}]
    elif mutation == "depth":
        item = cve
        for _ in range(26):
            item["extension"] = {}
            item = item["extension"]
    elif mutation == "size":
        cve["publicFutureField"] = "x" * 2097152
    elif mutation == "duplicate-id":
        raw["vulnerabilities"] *= 2
        raw["totalResults"] = raw["resultsPerPage"] = 2
    elif mutation == "count":
        raw["startIndex"] = 20
    elif mutation == "affected-status":
        cve["affected"] = [
            {
                "source": "test",
                "affectedData": [
                    {"product": "Apache", "versions": [{"version": "2.4.49", "status": "safe"}]}
                ],
            }
        ]
    with pytest.raises(APIError) as error:
        validate_public_page(raw, limit=20)
    assert error.value.code == "CVE_CACHE_INVALID_RESPONSE"


def test_payload_schema_refs_are_data_and_never_loaded(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("No schema network"))
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    raw = sample()
    raw["vulnerabilities"][0]["cve"]["publicFutureField"] = {
        "$ref": "https://127.0.0.1/private",
        "text": "<script>throw Error('inert')</script>",
    }
    page, body, _ = validate_public_page(raw)
    assert "<script>" in body and not forbidden.called
    # Provider strings are evidence only, never exec/eval/template/HTML instructions.
    assert (
        page.vulnerabilities[0].cve.publicFutureField
        == raw["vulnerabilities"][0]["cve"]["publicFutureField"]
    )


def test_optional_unbundled_decision_tree_fails_closed_without_retrieval(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("No schema network"))
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    raw = sample()
    raw["vulnerabilities"][0]["cve"]["metrics"]["ssvcV203"][0]["ssvcData"]["decisionTree"] = {}
    with pytest.raises(APIError):
        validate_public_page(raw)
    assert not forbidden.called


@pytest.mark.parametrize("body", [b"{bad", b'{"a":1,"a":2}', b'{"x":NaN}'])
def test_malformed_or_ambiguous_json_is_rejected(body):
    provider = TrialClient(httpx.MockTransport(lambda _: httpx.Response(200, content=body)))
    with pytest.raises(APIError):
        provider.page(CPE)


def test_trial_single_attempt_and_cancellation_are_terminal():
    calls = []
    client = TrialClient(
        httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json=sample()))
    )
    assert client.page(CPE).totalResults == 1
    client.quota.next_call = 0
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code == "REQUEST_BUDGET_REACHED" and len(calls) == 1


def test_real_mode_env_and_authorization_file_cannot_enable_network(monkeypatch, capsys):
    from scripts import nvd_trial

    forbidden = Mock(side_effect=AssertionError("No real mode I/O"))
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("pathlib.Path.read_text", forbidden)
    monkeypatch.setenv("CVE_LIVE_ENABLED", "true")
    monkeypatch.setattr(
        "sys.argv",
        [
            "nvd_trial",
            "--mode",
            "real",
            "--config",
            "private.json",
            "--authorization-record",
            "forged.json",
        ],
    )
    assert nvd_trial.main() == 2
    assert not forbidden.called and "NO-GO" in capsys.readouterr().out


def test_cancelled_trial_never_calls_provider():
    from threading import Event

    stop = Event()
    stop.set()
    provider = Mock(side_effect=AssertionError("Must stay cancelled"))
    client = TrialClient(httpx.MockTransport(provider), stop)
    with pytest.raises(APIError) as error:
        client.page(CPE)
    assert error.value.code == "INTERRUPTED" and not provider.called
