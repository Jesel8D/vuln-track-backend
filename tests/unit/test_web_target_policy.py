from dataclasses import FrozenInstanceError

import pytest

from app.api.v2_targets import TargetCreate
from app.services.web_target_policy import INVENTORY_POLICY, DestinationDenied, DestinationPolicy


@pytest.fixture(autouse=True)
def no_real_dns_or_connection(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("The target policy must not contact a network")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)


@pytest.mark.parametrize(
    "url,canonical",
    [
        ("HTTPS://Example.COM:443", "https://example.com/"),
        ("https://example.com/a?x=1", "https://example.com/a?x=1"),
        ("https://bücher.de/seguridad", "https://xn--bcher-kva.de/seguridad"),
        ("https://faß.de/", "https://xn--fa-hia.de/"),
        ("https://93.184.216.34/", "https://93.184.216.34/"),
        ("https://[2606:4700:4700::1111]/", "https://[2606:4700:4700::1111]/"),
    ],
)
def test_public_urls_are_canonical_without_resolving(url, canonical):
    assert DestinationPolicy().parse(url).url == canonical
    assert TargetCreate(url=url).url == canonical


def test_http_is_an_explicit_inventory_policy_not_the_default_connection_policy():
    assert INVENTORY_POLICY.parse("http://example.com:80").url == "http://example.com/"
    with pytest.raises(DestinationDenied):
        DestinationPolicy().parse("http://example.com/")


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "https:///missing",
        "https://",
        "https://example.com:bad/",
        "https://user:secret@example.com/",
        "https://@example.com/",
        "https://:secret@example.com/",
        "https://example.com@127.0.0.1/",
        "https://example.com/#fragment",
        "https://example.com/#",
        "https://localhost/",
        "https://sub.localhost/",
        "https://LOCALHOST/",
        "https://service.local/",
        "https://localhost.localdomain/",
        "https://router.home.arpa/",
        "https://host.internal/",
        "https://host.lan/",
        "https://host.home/",
        "https://host.test/",
        "https://host.invalid/",
        "https://metadata.google.internal/",
        "https://singlelabel/",
        "https://127.0.0.1/",
        "https://0.0.0.0/",
        "https://10.0.0.1/",
        "https://172.16.0.1/",
        "https://192.168.1.1/",
        "https://100.100.100.200/",
        "https://169.254.169.254/",
        "https://168.63.129.16/",
        "https://192.0.0.9/",
        "https://192.0.2.1/",
        "https://198.18.0.1/",
        "https://198.51.100.1/",
        "https://203.0.113.1/",
        "https://224.0.0.1/",
        "https://255.255.255.255/",
        "https://[::]/",
        "https://[::1]/",
        "https://[fc00::1]/",
        "https://[fe80::1]/",
        "https://[ff02::1]/",
        "https://[2001:db8::1]/",
        "https://[3fff::1]/",
        "https://[2001:20::1]/",
        "https://[::ffff:8.8.8.8]/",
        "https://[::ffff:127.0.0.1]/",
        "https://[2002:0808:0808::1]/",
        "https://[64:ff9b::808:808]/",
        "https://[fe80::1%25eth0]/",
        "https://2130706433/",
        "https://127.1/",
        "https://0177.0.0.1/",
        "https://0x7f000001/",
        "https://0x7f.0.0.1/",
        "https://127.0.0.01/",
        "https://%31%32%37.0.0.1/",
        "https://example.com:22/",
        "https://example.com:8443/",
        "https://example.com:80/",
        "http://example.com:443/",
        "https://example.com:0443/",
        "https://example.com:/",
        "https://example.com./",
        "https://example..com/",
        "https://-example.com/",
        "https://example_.com/",
        "https://example.123/",
        "https://example.com\\@127.0.0.1/",
        "https://example.com/\nnext",
        " https://example.com/",
        "https://example.com/\x00",
        "https://example.com/\x7f",
        "https://example.com//evil",
        "https://example.com/%2f%2fevil",
        "https://example.com/%255csecret",
        "https://example.com/%0d%0aHost:evil",
        "https://example.com/?q=%0d%0aHost:evil",
        "https://example.com/a/../private",
        "https://example.com/%252e%252e/private",
        "https://example.com/%zz",
        "https://example.com/%ff",
        "https://exa\u200bmple.com/",
        "https://ｅxample.com/",
        "https://example。com/",
        "https://bu\u0308cher.de/",
        "https://example.com\uff20evil.com/",
    ],
)
def test_unsafe_and_ambiguous_urls_fail_closed(url):
    with pytest.raises(DestinationDenied):
        INVENTORY_POLICY.parse(url)


def test_nonexistent_dns_and_errors_do_not_echo_input_or_resolver_details():
    def fail(host):
        raise OSError("secret resolver infrastructure")

    with pytest.raises(DestinationDenied) as error:
        DestinationPolicy().prepare_connection("https://example.com/", fail)
    assert str(error.value) == "DNS_UNAVAILABLE"
    assert "secret" not in str(error.value)
    with pytest.raises(DestinationDenied):
        DestinationPolicy().prepare_connection("https://example.com/", lambda host: [])


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["10.1.2.3"],
        ["169.254.169.254"],
        ["::1"],
        ["93.184.216.34", "192.168.1.1"],
        ["2606:4700:4700::1111", "fc00::1"],
        ["8.8.8.8", "168.63.129.16"],
        ["::ffff:8.8.8.8"],
        ["not-an-ip"],
        ["8.8.8.8"] * 17,
    ],
)
def test_every_dns_answer_must_be_allowed(answers):
    with pytest.raises(DestinationDenied):
        DestinationPolicy().prepare_connection("https://example.com/", lambda host: answers)


def test_rebinding_public_rotation_and_retries_require_new_validation():
    policy = DestinationPolicy()
    answers = ["93.184.216.34"]
    calls = []

    def resolver(host):
        calls.append(host)
        return answers

    plan = policy.prepare_connection("https://example.com/private", resolver)
    assert policy.revalidate_plan(plan, resolver).addresses == ("93.184.216.34",)
    answers[:] = ["8.8.8.8"]
    with pytest.raises(DestinationDenied, match="DNS_CHANGED"):
        policy.revalidate_plan(plan, resolver)
    answers[:] = ["127.0.0.1"]
    with pytest.raises(DestinationDenied, match="NON_PUBLIC_IP"):
        policy.revalidate_plan(plan, resolver)
    assert len(calls) == 4  # each operation resolves again, with no automatic retry


def test_expired_plans_cannot_be_reused(monkeypatch):
    policy = DestinationPolicy()
    monkeypatch.setattr("app.services.web_target_policy.time.monotonic", lambda: 1)
    plan = policy.prepare_connection("https://example.com/", lambda host: ["8.8.8.8"])
    monkeypatch.setattr("app.services.web_target_policy.time.monotonic", lambda: 7)
    with pytest.raises(DestinationDenied, match="CONNECTION_PLAN_EXPIRED"):
        policy.revalidate_plan(plan, lambda host: pytest.fail("must not resolve expired plan"))


def test_plan_binds_origin_ip_host_and_sni_ignoring_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    plan = DestinationPolicy().prepare_connection(
        "https://BÜCHER.de:443/path", lambda host: ["8.8.8.8", "1.1.1.1"]
    )
    assert plan.destination.origin == "https://xn--bcher-kva.de"
    assert plan.destination.http_host == plan.server_hostname == "xn--bcher-kva.de"
    assert plan.addresses == ("1.1.1.1", "8.8.8.8")
    assert plan.verify_tls and not plan.trust_environment and not plan.follow_redirects
    assert plan.automatic_retries == 0
    with pytest.raises(FrozenInstanceError):
        plan.destination = DestinationPolicy().parse("https://evil.com/")


@pytest.mark.parametrize(
    "location",
    [
        "https://127.0.0.1/",
        "http://example.com/",
        "https://evil.com/",
        "//169.254.169.254/",
        "/relative",
        "https://example.com/same-origin",
    ],
)
def test_redirects_are_never_followed(location):
    with pytest.raises(DestinationDenied, match="REDIRECTS_DISABLED"):
        DestinationPolicy().redirect(location)
