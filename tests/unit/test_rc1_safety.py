"""Acceptance tooling must refuse personal resources before any browser writes."""

import socket

import pytest

from scripts.rc1_acceptance import guard
from scripts.v2_development import free_port


def config(profile="rc1", **changes):
    return {
        "profile": profile,
        "phase": "ready",
        "volume": "vulntrack_v2_" + profile.replace("-", "_") + "_pgdata",
        "pg_port": 55438,
        "api_port": 8004,
        "web_port": 5177,
    } | changes


@pytest.mark.parametrize("profile", ["rc1", "rc1-restore", "rc1-restore-0123abcd"])
def test_exact_owned_candidate_profiles_use_only_loopback_and_separate_ports(profile):
    result = guard(profile, config(profile))
    assert result["fixture"] is True
    assert result["api_url"] == "http://127.0.0.1:8004"
    assert result["volume"] != "vulntrack_v2_development_pgdata"


@pytest.mark.parametrize(
    "profile",
    [
        "development",
        "../development",
        "rc1-other",
        "rc1-restore-abc",
        "RC1",
        "rc1-restore-0123ABCD",
    ],
)
def test_personal_paths_and_ambiguous_candidate_names_are_refused(profile):
    with pytest.raises(RuntimeError):
        guard(profile, config(profile))


@pytest.mark.parametrize(
    "changes",
    [
        {"profile": "development"},
        {"phase": "new"},
        {"volume": "vulntrack_v2_development_pgdata"},
        {"pg_port": 55434},
        {"api_port": 8000},
        {"web_port": 5173},
        {"web_port": 8004},
        {"api_port": 1},
        {"web_port": True},
        {"pg_port": 65536},
    ],
)
def test_personal_volume_ports_and_uninitialized_or_ambiguous_profiles_are_refused(changes):
    with pytest.raises(RuntimeError):
        guard("rc1", config(**changes))


def test_restart_port_probe_still_refuses_a_live_listener():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen()
        with pytest.raises(OSError):
            free_port(server.getsockname()[1])


def test_restart_port_probe_accepts_a_closed_connection_in_time_wait():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            connection, _ = server.accept()
            with connection:
                connection.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b""
    # The old probe fails here despite there being no listening server.
    with socket.socket() as old_probe, pytest.raises(OSError):
        old_probe.bind(("127.0.0.1", port))
    assert free_port(port) == port
