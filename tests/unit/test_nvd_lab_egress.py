"""No external sockets: ephemeral test signatures, fake DNS and HTTPX doubles."""

import asyncio
import base64
import hashlib
import json
import socket
import ssl
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from app.core.errors import APIError
from app.integrations import nvd_lab_authorization as auth
from app.integrations.cve_transport import CVE_URL
from app.integrations.nvd_cve import CVEClient
from app.integrations.nvd_lab_client import LabCVEClient, proven
from app.integrations.nvd_lab_transport import NVDLabTransport, Pin, validated_answers
from app.services.v2_cve_reliability import source_kind
from scripts import nvd_trial, nvd_trial_lab, nvd_trial_network


def plan():
    return {
        "version": "5c2-egress-1",
        "laboratory": "vulntrack-5c2-000000000000",
        "commit": "a" * 40,
        "image": "sha256:" + "b" * 64,
        "endpoint": CVE_URL,
        "method": "GET",
        "params": dict(auth.PARAMS),
        "requests": 1,
        "seconds": 20,
        "max_bytes": 2097152,
        "purpose": "first-isolated-nvd-cve-trial",
        "nonce": "c" * 32,
    }


def permit():
    value = plan()
    return auth.Permit(
        value,
        "d" * 64,
        hashlib.sha256(auth.canonical(value)).hexdigest(),
        datetime.now(UTC) + timedelta(seconds=60),
        auth._SEAL,
    )


def adapter():
    return NVDLabTransport(permit(), Pin("8.8.8.8", time.monotonic()))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.1.1",
        "172.20.1.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "::ffff:8.8.8.8",
    ],
)
def test_private_special_or_ipv6_answer_fails_entire_resolution(address):
    with pytest.raises(ValueError):
        validated_answers(["8.8.8.8", address])


def test_dns_answers_are_bounded_and_no_second_resolution_is_used(monkeypatch):
    assert validated_answers(["8.8.8.8", "1.1.1.1", "8.8.8.8"]) == ["1.1.1.1", "8.8.8.8"]
    for values in [[], ["8.8.8.8"] * 17, "8.8.8.8"]:
        with pytest.raises(ValueError):
            validated_answers(values)
    forbidden = Mock(side_effect=AssertionError("No second DNS"))
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    seen = []
    a = adapter()

    async def lower(request):
        seen.append(request)
        return httpx.Response(200, content=b"{}")  # no authenticated TLS evidence

    monkeypatch.setattr(a._http, "handle_async_request", lower)
    request = httpx.Request("GET", CVE_URL, params=auth.PARAMS)
    with pytest.raises(APIError) as error:
        asyncio.run(a.handle_async_request(request))
    assert error.value.code == "TRIAL_TLS_UNVERIFIED"
    assert seen[0].url.host == "8.8.8.8"
    assert seen[0].headers["Host"] == auth.HOST
    assert seen[0].extensions["sni_hostname"] == auth.HOST
    assert not forbidden.called and not a.peer_verified


@pytest.mark.parametrize(
    "url,params,method",
    [
        ("http://services.nvd.nist.gov/rest/json/cves/2.0", auth.PARAMS, "GET"),
        ("https://services.nvd.nist.gov.evil.invalid/rest/json/cves/2.0", auth.PARAMS, "GET"),
        ("https://services.nvd.nist.gov:444/rest/json/cves/2.0", auth.PARAMS, "GET"),
        (CVE_URL + "/", auth.PARAMS, "GET"),
        (CVE_URL, auth.PARAMS, "POST"),
        (CVE_URL, {**auth.PARAMS, "startIndex": 20}, "GET"),
        (CVE_URL, {**auth.PARAMS, "resultsPerPage": 21}, "GET"),
        (CVE_URL, {**auth.PARAMS, "cpeName": "private"}, "GET"),
        (CVE_URL, {**auth.PARAMS, "apiKey": "never"}, "GET"),
    ],
)
def test_endpoint_and_params_are_closed_before_lower_transport(url, params, method, monkeypatch):
    a = adapter()
    forbidden = Mock(side_effect=AssertionError("Forbidden destination"))
    monkeypatch.setattr(a._http, "handle_async_request", forbidden)
    with pytest.raises(APIError) as error:
        asyncio.run(a.handle_async_request(httpx.Request(method, url, params=params)))
    assert error.value.code == "TRIAL_PLAN_MISMATCH"
    assert a.attempts == 0 and not forbidden.called


def test_tls_policy_ignores_environment_and_failed_attempt_is_terminal(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/does/not/exist")
    a = adapter()
    assert a.context.verify_mode == ssl.CERT_REQUIRED and a.context.check_hostname
    assert a.context.minimum_version >= ssl.TLSVersion.TLSv1_2
    calls = []

    async def failed(request):
        calls.append(request)
        raise httpx.ConnectError("synthetic TLS error")

    monkeypatch.setattr(a._http, "handle_async_request", failed)
    client = LabCVEClient(a, Event())
    with pytest.raises(APIError):
        client.prepare()
    assert not proven(client) and source_kind(client) == "unknown"
    with pytest.raises(APIError):
        client.prepare()
    assert a.attempts == 1 and len(calls) == 1 and client.budget.requests == 1


def test_pre_cancelled_budget_cannot_reach_adapter(monkeypatch):
    a = adapter()
    stop = Event()
    stop.set()
    forbidden = Mock(side_effect=AssertionError("Must not enter HTTP"))
    monkeypatch.setattr(a._http, "handle_async_request", forbidden)
    with pytest.raises(APIError) as error:
        LabCVEClient(a, stop).prepare()
    assert error.value.code == "INTERRUPTED" and not forbidden.called and a.attempts == 0


def test_old_or_private_pin_and_mutated_authorization_fail_closed():
    with pytest.raises(APIError):
        NVDLabTransport(permit(), Pin("8.8.8.8", time.monotonic() - 21))
    p = permit()
    p.plan["commit"] = "f" * 40
    with pytest.raises(APIError):
        p.check()
    p = permit()
    p = auth.Permit(p.plan, p.grant_sha256, p.plan_sha256, p.not_after, object())
    with pytest.raises(APIError):
        p.check()


def test_mock_cannot_get_live_provenance_or_be_lab_capability():
    client = CVEClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)), live=True)
    client.source_kind = "live"  # Even an injected source label is not proof.
    assert source_kind(client) == "simulated"
    with pytest.raises(APIError):
        LabCVEClient(client.transport, Event())
    with pytest.raises(APIError):
        NVDLabTransport(None, Pin("8.8.8.8", time.monotonic()))


def test_real_entry_points_block_before_all_io_or_claims(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("No IO when no authority provisioned"))
    monkeypatch.setattr(auth, "TRUSTED_AUTHORITY_SHA256", None)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(nvd_trial_lab, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setenv("CVE_LIVE_ENABLED", "true")
    for fn in [
        lambda: auth.authorize(None, None, commit="a" * 40, image="sha256:" + "b" * 64),
        lambda: nvd_trial.execute_real(SimpleNamespace()),
        lambda: nvd_trial_lab.execute(SimpleNamespace()),
    ]:
        with pytest.raises(APIError) as error:
            fn()
        assert error.value.code == "TRIAL_NOT_AUTHORIZED"
    assert not forbidden.called


def test_synthetic_signature_binds_every_scope_and_time_not_a_real_grant(tmp_path, monkeypatch):
    # Test issuer exists ONLY in pytest's temporary directory, never in a release
    # or a Docker lab. No authorization for an existing environment is produced.
    private = tmp_path / "test.key"
    public = tmp_path / "test.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr(auth, "AUTHORITY", public)
    monkeypatch.setattr(
        auth, "TRUSTED_AUTHORITY_SHA256", hashlib.sha256(public.read_bytes()).hexdigest()
    )
    value = plan()
    pp = tmp_path / "test-plan.json"
    gp = tmp_path / "test-grant.json"
    pp.write_bytes(auth.canonical(value))
    now = datetime.now(UTC)
    grant = {
        "plan_sha256": hashlib.sha256(auth.canonical(value)).hexdigest(),
        "not_before": (now - timedelta(seconds=1)).isoformat(),
        "not_after": (now + timedelta(seconds=60)).isoformat(),
        "official_evidence": dict.fromkeys(auth.DOCUMENTS, "0" * 64),
        "approved_by": "PYTEST SYNTHETIC ONLY",
    }
    raw = tmp_path / "raw"
    sig = tmp_path / "sig"
    raw.write_bytes(auth.canonical(grant))
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private),
            "-rawin",
            "-in",
            str(raw),
            "-out",
            str(sig),
        ],
        check=True,
        capture_output=True,
    )
    envelope = {"grant": grant, "signature": base64.b64encode(sig.read_bytes()).decode()}
    gp.write_text(json.dumps(envelope))
    result = auth.authorize(pp, gp, commit=value["commit"], image=value["image"])
    result.check()
    for patch in [
        {"requests": 2},
        {"commit": "f" * 40},
        {"laboratory": "vulntrack-5c2-111111111111"},
        {"params": {**auth.PARAMS, "startIndex": 1}},
    ]:
        pp.write_bytes(auth.canonical(value | patch))
        with pytest.raises(APIError):
            auth.authorize(pp, gp, commit=value["commit"], image=value["image"])
    pp.write_bytes(auth.canonical(value))
    envelope["grant"]["not_after"] = (now - timedelta(seconds=1)).isoformat()
    gp.write_text(json.dumps(envelope))
    with pytest.raises(APIError):
        auth.authorize(pp, gp, commit=value["commit"], image=value["image"])


def test_namespace_rules_have_only_pg_and_one_public_pin_and_expire():
    rules = nvd_trial_network.rules("10.245.240.2", "8.8.8.8")
    assert ":OUTPUT DROP" in rules and ":FORWARD DROP" in rules
    assert "-d 10.245.240.2/32 -p tcp --dport 5432" in rules
    assert "-d 8.8.8.8/32 -p tcp --dport 443 -m time --datestop " in rules
    assert "127.0.0.11" not in rules and "ACCEPT" in rules
    assert "--dport 80 " not in rules
    assert "-d 8.8.8.8/" not in nvd_trial_network.rules("10.245.240.2")
    assert "127.0.0.11/32" in nvd_trial_network.rules("10.245.240.2", dns=True)


def test_dns_subprocess_failure_closes_rules_without_fallback(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(nvd_trial_network, "install", lambda pg, **kw: calls.append(kw))

    def timeout(*args, **kw):
        assert kw["timeout"] == 4
        raise subprocess.TimeoutExpired(args[0], 4)

    monkeypatch.setattr(nvd_trial_network.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        nvd_trial_network.setup("10.245.240.2", tmp_path)
    assert calls == [{"dns": True}, {}] and not (tmp_path / "pin.json").exists()


def test_spent_grant_cannot_be_reused_with_new_destination(tmp_path, monkeypatch):
    p = permit()
    monkeypatch.setattr(nvd_trial_lab, "ROOT", tmp_path)
    monkeypatch.setattr(auth, "TRUSTED_AUTHORITY_SHA256", "0" * 64)
    monkeypatch.setattr(auth, "authorize", lambda *a, **k: p)

    def run(args, **kwargs):
        if args[-1] == "--porcelain":
            return b""
        if args[-1] == "HEAD":
            return p.plan["commit"].encode()
        return json.dumps(
            [
                {
                    "Id": p.plan["image"],
                    "Config": {"Labels": {"io.vulntrack.reviewed-commit": p.plan["commit"]}},
                }
            ]
        ).encode()

    monkeypatch.setattr(nvd_trial_lab, "run", run)
    calls = []
    monkeypatch.setattr(nvd_trial_lab, "launch", lambda *a, **k: calls.append(a))
    args = SimpleNamespace(
        plan_file=tmp_path / "plan",
        authorization_record=tmp_path / "grant",
        catalogue_record=tmp_path / "public-cpe",
        destination=tmp_path / "fresh",
    )
    nvd_trial_lab.execute(args)
    args.destination = tmp_path / "another-fresh"
    with pytest.raises(FileExistsError):
        nvd_trial_lab.execute(args)
    assert len(calls) == 1


# Keep the original method before the autouse no-HTTP fixture replaces it. This
# single test admits only sockets to its own loopback listener, never Internet.
_LOCAL_HTTPX_METHOD = httpx.AsyncHTTPTransport.handle_async_request


def test_actual_local_tls_keeps_nvd_sni_rejects_untrusted_ca_and_nonpublic_peer(
    tmp_path, monkeypatch
):
    import threading
    import types

    from httpcore._backends.anyio import AnyIOBackend

    key, cert = tmp_path / "key", tmp_path / "cert"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=" + auth.HOST,
            "-addext",
            "subjectAltName=DNS:" + auth.HOST,
        ],
        check=True,
        capture_output=True,
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    names = []
    http_requests = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_servername_callback(lambda sock, name, context: names.append(name))

    def serve():
        for _ in range(2):
            try:
                conn, _ = listener.accept()
                with conn:
                    try:
                        with ctx.wrap_socket(conn, server_side=True) as tls:
                            raw = tls.recv(8192)
                            http_requests.append(raw)
                            tls.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                b"Content-Type: application/json\r\nConnection: close\r\n\r\n{}"
                            )
                    except ssl.SSLError:
                        pass
            except TimeoutError:
                break

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    original_connect = AnyIOBackend.connect_tcp

    async def local_only(self, host, port, **kwargs):
        assert host == "8.8.8.8" and port == 443
        return await original_connect(self, "127.0.0.1", listener.getsockname()[1], **kwargs)

    monkeypatch.setattr(AnyIOBackend, "connect_tcp", local_only)
    original_socket_connect = socket.socket.connect

    def guard(sock, address):
        assert address[0] == "127.0.0.1" and address[1] == port
        return original_socket_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guard)
    try:
        for trust_test_ca in (False, True):
            a = adapter()
            if trust_test_ca:
                a.context.load_verify_locations(cafile=str(cert))
            monkeypatch.setattr(
                a._http, "handle_async_request", types.MethodType(_LOCAL_HTTPX_METHOD, a._http)
            )
            client = LabCVEClient(a, Event())
            with pytest.raises(APIError) as error:
                client.prepare()
            assert error.value.code == (
                "TRIAL_TLS_UNVERIFIED" if trust_test_ca else "NVD_UNAVAILABLE"
            )
            assert not proven(client) and source_kind(client) == "unknown"
        assert names == [auth.HOST, auth.HOST] and len(http_requests) == 1
    finally:
        thread.join(timeout=6)
        listener.close()


def test_active_cancellation_closes_the_lab_exchange_without_retry(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    a = adapter()
    entered = Event()
    stop = Event()
    closed = []

    async def lower(request):
        entered.set()
        try:
            await asyncio.sleep(5)
        finally:
            closed.append(True)

    monkeypatch.setattr(a._http, "handle_async_request", lower)
    c = LabCVEClient(a, stop)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(c.prepare)
        assert entered.wait(1)
        stop.set()
        with pytest.raises(APIError) as error:
            future.result(timeout=1)
    assert error.value.code == "INTERRUPTED" and closed == [True] and a.attempts == 1
    assert source_kind(c) == "unknown" and not proven(c)


def test_redirect_response_has_no_follow_up_and_no_live_proof(monkeypatch):
    a = adapter()
    calls = []

    async def lower(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/private"})

    monkeypatch.setattr(a._http, "handle_async_request", lower)
    c = LabCVEClient(a, Event())
    with pytest.raises(APIError):
        c.prepare()
    assert len(calls) == 1 and not proven(c) and source_kind(c) == "unknown"


def test_dns_and_worker_share_one_twenty_second_deadline(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(nvd_trial_network.time, "monotonic", lambda: clock[0])
    calls = []
    monkeypatch.setattr(nvd_trial_network, "install", lambda pg, **kw: calls.append(kw))

    def lookup(*args, **kwargs):
        clock[0] += 3
        return SimpleNamespace(returncode=0, stdout=b'["8.8.8.8"]')

    monkeypatch.setattr(nvd_trial_network.subprocess, "run", lookup)
    nvd_trial_network.setup("10.245.240.2", tmp_path)
    pin = Pin(**json.loads((tmp_path / "pin.json").read_text()))
    assert pin.remaining() == 17 and calls[-1] == {"public": "8.8.8.8", "seconds": 17}
    clock[0] = 120.0
    with pytest.raises(APIError):
        pin.check()
