import asyncio
from dataclasses import replace

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from app.services.controlled_dns import (
    ControlledDNS,
    DNSEndpoint,
    DNSLimits,
    DNSPinnedHTTPS,
    Resolution,
)
from app.services.web_target_policy import DestinationDenied

HOST = "control.example.net"
V4 = "93.184.216.10"
V6 = "2606:4700:ffff::10"


def answer(question, records=()):
    response = dns.message.make_response(question)
    for owner, kind, values in records:
        response.answer.append(dns.rrset.from_text(owner + '.', 30, "IN", kind, *values))
    return response


def resolver_for(handler, *, limits=None):
    resolver = ControlledDNS(DNSEndpoint("10.77.0.53"), limits=limits)
    calls = []

    async def exchange(question):
        calls.append(question)
        return handler(question)

    resolver._exchange = exchange
    return resolver, calls


def public_response(question):
    kind = dns.rdatatype.to_text(question.question[0].rdtype)
    return answer(question, [(HOST, kind, [V4 if kind == "A" else V6])])


def test_a_and_aaaa_are_both_validated_without_os_dns_cache_or_retry():
    resolver, calls = resolver_for(public_response)
    first = asyncio.run(resolver.resolve(HOST))
    second = asyncio.run(resolver.resolve(HOST))
    assert first == second
    assert first.addresses == tuple(sorted([V4, V6])) and first.aliases == ()
    assert len(calls) == 4


@pytest.mark.parametrize(
    "bad",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "fc00::1",
        "::1",
        "fe80::1",
        "::ffff:8.8.8.8",
        "2001:db8::1",
    ],
)
def test_one_forbidden_address_denies_the_entire_dns_result(bad):
    def handler(question):
        records = [(HOST, "A", [V4])]
        records.append((HOST, "AAAA" if ":" in bad else "A", [bad]))
        return answer(question, records)

    resolver, _ = resolver_for(handler)
    with pytest.raises(DestinationDenied):
        asyncio.run(resolver.resolve(HOST))


def test_forbidden_glue_is_not_silently_ignored():
    def handler(question):
        response = public_response(question)
        response.additional.append(dns.rrset.from_text("ns.example.net", 30, "IN", "A", "10.1.1.1"))
        return response

    resolver, _ = resolver_for(handler)
    with pytest.raises(DestinationDenied):
        asyncio.run(resolver.resolve(HOST))


def test_cname_chain_is_bound_to_both_address_families():
    def handler(question):
        kind = dns.rdatatype.to_text(question.question[0].rdtype)
        return answer(
            question,
            [
                (HOST, "CNAME", ["alias.example.net."]),
                ("alias.example.net", kind, [V4 if kind == "A" else V6]),
            ],
        )

    resolver, _ = resolver_for(handler)
    result = asyncio.run(resolver.resolve(HOST))
    assert result.canonical_name == "alias.example.net"
    assert result.aliases == ((HOST, "alias.example.net"),)


@pytest.mark.parametrize(
    "case",
    ["loop", "deep", "ambiguous", "mixed", "unscoped", "dname", "inconsistent", "private_alias"],
)
def test_adversarial_cname_and_scope_fail_closed(case):
    def handler(question):
        kind = dns.rdatatype.to_text(question.question[0].rdtype)
        records = [(HOST, "CNAME", ["alias.example.net."])]
        if case == "loop":
            records.append(("alias.example.net", "CNAME", [HOST + "."]))
        if case == "deep":
            records = [(HOST, "CNAME", ["n1.example.net."])] + [
                (f"n{i}.example.net", "CNAME", [f"n{i + 1}.example.net."]) for i in range(1, 5)
            ]
        if case == "ambiguous":
            records.append((HOST, "CNAME", ["other.example.net."]))
        if case == "mixed":
            records.append((HOST, "A", [V4]))
        if case == "unscoped":
            records = [("other.example.net", "A", [V4])]
        if case == "dname":
            records = [(HOST, "DNAME", ["other.example.net."])]
        if case == "private_alias":
            records = [(HOST, "CNAME", ["localhost."])]
        if case == "inconsistent":
            alias = "alias.example.net" if kind == "A" else "other.example.net"
            records = [(HOST, "CNAME", [alias + "."]), (alias, kind, [V4 if kind == "A" else V6])]
        return answer(question, records)

    resolver, _ = resolver_for(handler)
    with pytest.raises(DestinationDenied):
        asyncio.run(resolver.resolve(HOST))


@pytest.mark.parametrize(
    "case", ["id", "question", "truncated", "nxdomain", "servfail", "empty", "many"]
)
def test_invalid_or_unbounded_dns_messages_are_rejected(case):
    def handler(question):
        response = public_response(question)
        if case == "id":
            response.id ^= 1
        if case == "question":
            response.question = dns.message.make_query("other.example.net", "A").question
        if case == "truncated":
            response.flags |= dns.flags.TC
        if case == "nxdomain":
            response.set_rcode(dns.rcode.NXDOMAIN)
        if case == "servfail":
            response.set_rcode(dns.rcode.SERVFAIL)
        if case == "empty":
            response.answer = []
        if case == "many":
            response.answer = [
                dns.rrset.from_text(HOST, 30, "IN", "A", *[f"93.184.216.{i}" for i in range(1, 18)])
            ]
        return response

    resolver, _ = resolver_for(handler)
    with pytest.raises(DestinationDenied):
        asyncio.run(resolver.resolve(HOST))


def test_cname_only_response_is_followed_with_a_query_budget():
    def handler(question):
        name = question.question[0].name.to_text(omit_final_dot=True)
        kind = dns.rdatatype.to_text(question.question[0].rdtype)
        if name == HOST:
            return answer(question, [(HOST, "CNAME", ["alias.example.net."])])
        return answer(question, [(name, kind, [V4 if kind == "A" else V6])])

    resolver, calls = resolver_for(handler)
    assert asyncio.run(resolver.resolve(HOST)).canonical_name == "alias.example.net"
    assert len(calls) == 4
    resolver, _ = resolver_for(handler, limits=DNSLimits(max_queries=1))
    with pytest.raises(DestinationDenied, match="DNS_QUERY_BUDGET"):
        asyncio.run(resolver.resolve(HOST))


def test_idna_is_normalized_before_dns_and_malformed_names_are_not_queried():
    seen = []

    def handler(question):
        name = question.question[0].name.to_text(omit_final_dot=True)
        seen.append(name)
        kind = dns.rdatatype.to_text(question.question[0].rdtype)
        return answer(question, [(name, kind, [V4 if kind == "A" else V6])])

    resolver, _ = resolver_for(handler)
    assert asyncio.run(resolver.resolve("BÜCHER.de")).hostname == "xn--bcher-kva.de"
    assert seen == ["xn--bcher-kva.de"] * 2
    with pytest.raises(DestinationDenied):
        asyncio.run(resolver.resolve("evil\u3002com"))
    assert len(seen) == 2


def test_dns_failures_are_sanitized_without_retries():
    resolver = ControlledDNS(DNSEndpoint("10.77.0.53"))
    calls = []

    async def failing(question):
        calls.append(question)
        raise OSError("secret DNS upstream details")

    resolver._exchange = failing
    with pytest.raises(DestinationDenied) as error:
        asyncio.run(resolver.resolve(HOST))
    assert str(error.value) == "DNS_UNAVAILABLE" and len(calls) == 1


def test_dns_deadline_and_task_cancellation():
    async def run():
        resolver = ControlledDNS(DNSEndpoint("10.77.0.53"), limits=DNSLimits(total_seconds=0.01))
        closed = []

        async def hanging(question):
            try:
                await asyncio.Event().wait()
            finally:
                closed.append(True)

        resolver._exchange = hanging
        with pytest.raises(DestinationDenied, match="DNS_TIMEOUT"):
            await resolver.resolve(HOST)
        task = asyncio.create_task(resolver.resolve(HOST))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(closed) == 2

    asyncio.run(run())


@pytest.mark.parametrize("change", ["ip", "chain"])
def test_rebinding_and_changed_cname_never_reach_the_tls_socket(change):
    original = Resolution(HOST, HOST, (), (V4,))
    calls = []

    class Resolver:
        async def resolve(self, host):
            calls.append(host)
            if len(calls) == 1:
                return original
            return (
                replace(original, addresses=("93.184.216.12",))
                if change == "ip"
                else replace(
                    original,
                    canonical_name="alias.example.net",
                    aliases=((HOST, "alias.example.net"),),
                )
            )

    class Transport:
        async def fetch(self, *args, **kwargs):
            pytest.fail("TLS attempted after DNS changed")

    with pytest.raises(DestinationDenied, match="DNS_CHANGED"):
        asyncio.run(DNSPinnedHTTPS(Resolver(), Transport()).fetch("https://" + HOST + "/"))
    assert len(calls) == 2


def test_cancellation_event_covers_dns_before_any_https_operation():
    async def run():
        started = asyncio.Event()
        cancel = asyncio.Event()
        closed = []

        class Resolver:
            async def resolve(self, host):
                try:
                    started.set()
                    await asyncio.Event().wait()
                finally:
                    closed.append(True)

        class Transport:
            async def fetch(self, *args, **kwargs):
                pytest.fail("HTTPS attempted after cancellation")

        task = asyncio.create_task(
            DNSPinnedHTTPS(Resolver(), Transport()).fetch("https://" + HOST + "/", cancelled=cancel)
        )
        await started.wait()
        cancel.set()
        with pytest.raises(DestinationDenied, match="REQUEST_CANCELLED"):
            await task
        assert closed == [True]

    asyncio.run(run())


@pytest.mark.parametrize(
    "options",
    [
        {"total_seconds": 3},
        {"max_answers": 17},
        {"max_cnames": 5},
        {"max_wire_bytes": 65535},
        {"max_queries": 11},
    ],
)
def test_dns_budgets_cannot_be_disabled(options):
    with pytest.raises(ValueError):
        DNSLimits(**options)
