import asyncio
import ssl
from dataclasses import replace

import pytest

from app.services.web_target_policy import DestinationDenied, DestinationPolicy
from app.services.web_target_transport import HTTPSResult, PinnedHTTPS, TransportLimits


@pytest.mark.parametrize("change", ["no_tls_verification", "old_tls"])
def test_insecure_tls_is_not_a_configuration_option(change):
    context = ssl.create_default_context()
    if change == "no_tls_verification":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with pytest.raises(DestinationDenied, match="TLS_VERIFICATION_REQUIRED"):
        PinnedHTTPS(tls_context=context)


@pytest.mark.parametrize(
    "options",
    [
        {"total_seconds": 0},
        {"total_seconds": 6},
        {"max_body_bytes": 4097},
        {"max_header_bytes": 8193},
        {"max_header_bytes": 255},
        {"max_body_bytes": 0},
    ],
)
def test_transport_budgets_cannot_be_disabled(options):
    with pytest.raises(ValueError, match="Invalid bounded transport limits"):
        TransportLimits(**options)


@pytest.mark.parametrize(
    "headers,expected",
    [
        (b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\n\r\n", "REDIRECTS_DISABLED"),
        (b"HTTP/1.1 100 Continue\r\n\r\n", "HTTP_STATUS_OR_HEADERS_DENIED"),
        (b"HTTP/1.1 404 Missing\r\n\r\n", "HTTP_STATUS_OR_HEADERS_DENIED"),
        (b"HTTP/2 200\r\n\r\n", "HTTP_RESPONSE_INVALID"),
        (b"HTTP/1.1 200 OK\r\n\r\n", "HTTP_LENGTH_REQUIRED"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n", "HTTP_LENGTH_REQUIRED"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\n", "HTTP_LENGTH_REQUIRED"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n", "HTTP_BODY_TOO_LARGE"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n",
            "HTTP_RESPONSE_INVALID",
        ),
        (b"HTTP/1.1 200 OK\r\n Content-Length: 1\r\n\r\n", "HTTP_RESPONSE_INVALID"),
        (b"HTTP/1.1 200 OK\r\nInvalid\r\n\r\n", "HTTP_RESPONSE_INVALID"),
        (b"HTTP/1.1 200 OK\r\nSecret: x\x00token\r\n\r\n", "HTTP_RESPONSE_INVALID"),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP_ENCODING_DENIED"),
        (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n", "HTTP_ENCODING_DENIED"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/html\r\n\r\n",
            "HTTP_CONTENT_TYPE_DENIED",
        ),
        (b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8200 + b"\r\n\r\n", "HTTP_HEADERS_TOO_LARGE"),
    ],
)
def test_http_ambiguities_and_unbounded_responses_fail_closed(headers, expected):
    with pytest.raises(DestinationDenied) as error:
        PinnedHTTPS()._response_length(headers)
    assert error.value.code == expected
    assert "token" not in str(error.value) and "169.254" not in str(error.value)


def test_static_text_file_response_is_bounded():
    assert "private-token" not in repr(HTTPSResult(b"private-token", "8.8.8.8", "a" * 64))
    assert (
        PinnedHTTPS()._response_length(
            b"HTTP/1.1 200 OK\r\nContent-Length: 120\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        )
        == 120
    )


@pytest.mark.parametrize("answers", [["127.0.0.1"], ["8.8.8.8", "10.0.0.1"], ["1.1.1.1"]])
def test_rebinding_cannot_reach_the_connect_step(monkeypatch, answers):
    client = PinnedHTTPS()
    plan = DestinationPolicy().prepare_connection("https://example.com/", lambda host: ["8.8.8.8"])

    async def forbidden(plan):
        pytest.fail("Connection attempted after DNS changed")

    monkeypatch.setattr(client, "_exchange", forbidden)
    with pytest.raises(DestinationDenied):
        asyncio.run(client.fetch(plan, lambda host: answers))


def test_expired_plan_is_not_reused(monkeypatch):
    client = PinnedHTTPS()
    plan = DestinationPolicy().prepare_connection("https://example.com/", lambda host: ["8.8.8.8"])
    plan = replace(plan, resolved_at=plan.resolved_at - 6)
    with pytest.raises(DestinationDenied, match="CONNECTION_PLAN_EXPIRED"):
        asyncio.run(client.fetch(plan, lambda host: pytest.fail("Expired plan resolved")))


def test_pre_cancelled_request_never_resolves():
    async def run():
        cancelled = asyncio.Event()
        cancelled.set()
        plan = DestinationPolicy().prepare_connection(
            "https://example.com/", lambda host: ["8.8.8.8"]
        )
        with pytest.raises(DestinationDenied, match="REQUEST_CANCELLED"):
            await PinnedHTTPS().fetch(
                plan, lambda host: pytest.fail("Cancelled DNS"), cancelled=cancelled
            )

    asyncio.run(run())


def test_low_level_failures_are_sanitized_and_not_retried(monkeypatch):
    calls = []
    client = PinnedHTTPS()
    plan = DestinationPolicy().prepare_connection("https://example.com/", lambda host: ["8.8.8.8"])

    async def failure(plan):
        calls.append(plan)
        raise OSError("operator-secret-cookie-token")

    monkeypatch.setattr(client, "_exchange", failure)
    with pytest.raises(DestinationDenied) as error:
        asyncio.run(client.fetch(plan, lambda host: ["8.8.8.8"]))
    assert str(error.value) == "HTTPS_EXCHANGE_FAILED" and len(calls) == 1
