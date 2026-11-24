"""Namespace-only egress guard. Never changes the host firewall.

Keeper is the only NET_ADMIN/NET_RAW container; worker shares its namespace but
has neither capability. All IPv6 and forwarding are denied. PostgreSQL is the
only private destination. Public egress lasts <=20 seconds, then fails closed.
"""

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.integrations.nvd_lab_authorization import HOST
from app.integrations.nvd_lab_transport import public_ipv4, validated_answers

TOOLS = Path("/opt/nvd-netguard")


def rules(pg, public=None, dns=False, seconds=20):
    if ipaddress.ip_address(pg).version != 4 or not ipaddress.ip_address(pg).is_private:
        raise ValueError("Owned private PG IPv4 required")
    output = [
        "*filter",
        ":INPUT DROP [0:0]",
        ":FORWARD DROP [0:0]",
        ":OUTPUT DROP [0:0]",
        "-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT",
        f"-A OUTPUT -d {pg}/32 -p tcp --dport 5432 -j ACCEPT",
    ]
    if public:
        expiry = (datetime.now(UTC) + timedelta(seconds=max(0, min(20, seconds)))).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        output.append(
            f"-A OUTPUT -d {public_ipv4(public)}/32 -p tcp --dport 443 "
            f"-m time --datestop {expiry} -j ACCEPT"
        )
    if dns:
        # Docker's embedded resolver only, for a single bounded getaddrinfo; its
        # NAT uses ephemeral local ports, so scope to resolver address, not :53.
        expiry = (datetime.now(UTC) + timedelta(seconds=4)).strftime("%Y-%m-%dT%H:%M:%S")
        output.append(f"-A OUTPUT -d 127.0.0.11/32 -m time --datestop {expiry} -j ACCEPT")
    return "\n".join(output + ["COMMIT", ""])


def install(pg, public=None, dns=False, seconds=20):
    env = {
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(TOOLS / "lib"),
        "XTABLES_LIBDIR": str(TOOLS / "xtables"),
    }
    # Docker disables IPv6 in THIS namespace before a public interface is attached.
    # Do not load a missing host ip6tables module or alter host IPv6 settings.
    for name in ("all", "default"):
        if Path(f"/proc/sys/net/ipv6/conf/{name}/disable_ipv6").read_text().strip() != "1":
            raise RuntimeError("Lab namespace IPv6 must be disabled")
    for binary, data in [("iptables-restore", rules(pg, public, dns, seconds))]:
        result = subprocess.run(
            [str(TOOLS / binary), "-w", "2"],
            input=data.encode(),
            capture_output=True,
            timeout=3,
            env=env,
        )
        if result.returncode:
            raise RuntimeError("Namespace egress policy installation failed")


def resolve():
    # This subprocess is given a hard 4s deadline by its parent. No fallbacks,
    # retries, user hostnames, alternate resolver or IPv6 connection attempt.
    answers = socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    print(json.dumps(validated_answers([x[4][0] for x in answers])))


def hold(pg, directory):
    install(pg)
    directory.joinpath("guard-ready").touch(mode=0o600)
    deadline = time.monotonic() + 180
    opened = None
    closed = False
    while time.monotonic() < deadline:
        pin = directory / "pin.json"
        if opened is None and pin.exists():
            data = json.loads(pin.read_text())
            if set(data) != {"address", "resolved_monotonic", "started_monotonic"}:
                raise ValueError("Unexpected pin")
            age = time.monotonic() - data["resolved_monotonic"]
            if not 0 <= age < 20:
                raise ValueError("Expired pin")
            # setup process installs the one pinned public rule before writing pin
            opened = data["started_monotonic"]
        if not closed and (
            Path("/output/close-egress").exists()
            or opened is not None
            and time.monotonic() - opened >= 20
        ):
            install(pg)
            directory.joinpath("egress-closed").touch(mode=0o644)
            closed = True
        time.sleep(0.05)
    install(pg)  # DROP default remains even if the keeper process then exits.


def setup(pg, directory):
    started = time.monotonic()
    install(pg, dns=True)
    try:
        result = subprocess.run(
            ["python", "-m", "scripts.nvd_trial_network", "--resolve"],
            capture_output=True,
            timeout=4,
            env={"PATH": os.environ["PATH"]},
        )
        if result.returncode:
            raise RuntimeError("Controlled DNS failed")
        answers = validated_answers(json.loads(result.stdout))
        pin = {
            "address": answers[0],
            "resolved_monotonic": time.monotonic(),
            "started_monotonic": started,
        }
        remaining = 20 - (time.monotonic() - started)
        if remaining <= 0:
            raise ValueError("DNS consumed the execution deadline")
        install(pg, public=pin["address"], seconds=remaining)
        p = directory / "pin.json"
        pending = directory / "pin.pending.json"
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w") as f:
            json.dump(pin, f)
            f.flush()
            os.fsync(f.fileno())
        os.link(pending, p)  # Atomic, refuses reuse; keeper never sees partial JSON.
    except BaseException:
        install(pg)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--resolve", action="store_true")
    p.add_argument("--action", choices=["hold", "setup", "close"])
    p.add_argument("--pg")
    p.add_argument("--directory", type=Path, default=Path("/control"))
    a = p.parse_args()
    if a.resolve:
        resolve()
    elif a.action == "hold":
        try:
            hold(a.pg, a.directory)
        finally:
            install(a.pg)
    elif a.action == "setup":
        setup(a.pg, a.directory)
    elif a.action == "close":
        install(a.pg)
    else:
        p.error("explicit action required")


if __name__ == "__main__":
    main()
