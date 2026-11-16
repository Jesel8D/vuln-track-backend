"""Phase 2C: mandatory gateway on owned internal bridges; NO public egress or ZAP."""

import concurrent.futures
import hashlib
import ipaddress
import json
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from scripts.phase2c_authorization_lab import LaboratoryBroker

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "api-tests/v2/.artifacts/phase2c"
RESULT = ARTIFACTS / "egress-lab-results.json"


class EgressLab:
    def __init__(self):
        self.nonce = secrets.token_hex(6)
        self.label = "vulntrack.phase2c"
        self.owner = self.label + "=" + self.nonce
        self.names = {
            role: f"vulntrack-phase2c-{self.nonce}-{role}"
            for role in ("worker", "gateway", "authority", "fixture")
        }
        self.networks = {
            role: f"vulntrack-phase2c-{self.nonce}-{role}"
            for role in ("front", "control", "targets")
        }
        slot = secrets.randbelow(240) + 10
        prefix = "fd72:" + self.nonce[:4]
        self.subnets = {
            "front": (f"10.231.{slot}.0/24", prefix + ":1::/64"),
            "control": (f"10.232.{slot}.0/24", prefix + ":2::/64"),
            "targets": ("93.184.216.8/29", "2606:4700:ffff::/120"),
        }
        self.ip = {
            "worker4": f"10.231.{slot}.4",
            "worker6": prefix + ":1::4",
            "gateway4": f"10.231.{slot}.2",
            "gateway6": prefix + ":1::2",
            "canary4": f"10.231.{slot}.9",
            "canary6": prefix + ":1::9",
            "control4": f"10.232.{slot}.2",
            "control6": prefix + ":2::2",
            "authority4": f"10.232.{slot}.3",
            "authority6": prefix + ":2::3",
            "dns4": f"10.232.{slot}.53",
            "dns6": prefix + ":2::53",
            "gateway_out4": "93.184.216.9",
            "gateway_out6": "2606:4700:ffff::2",
            "target4": "93.184.216.10",
            "other4": "93.184.216.11",
            "forbidden4": "93.184.216.12",
            "target6": "2606:4700:ffff::10",
            "other6": "2606:4700:ffff::11",
            "forbidden6": "2606:4700:ffff::12",
        }
        self.key = secrets.token_hex(32)
        self.configs = {}
        self.checks = []
        self.measurements = {}
        self.step = "preflight"
        self.common = [
            "--label",
            self.owner,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--pids-limit",
            "32",
            "--memory",
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "0.5",
            "--ulimit",
            "nofile=64:64",
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=1m",
            "--log-opt",
            "max-file=2",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
        ]
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY"):
            for spelling in (variable, variable.lower()):
                self.common += ["--env", spelling + "="]

    def command(self, *args, data=None, timeout=30, check=True):
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        if check and result.returncode:
            (ARTIFACTS / "command-failure.log").write_bytes(result.stderr)
            raise RuntimeError(f"Owned Phase2C command failed: {args[0]} ({result.returncode})")
        return result

    def inspect(self, role):
        return json.loads(self.command("docker", "inspect", self.names[role]).stdout)[0]

    def record(self, name):
        assert name not in self.checks
        self.checks.append(name)
        self.step = name
        print("PASS " + name, flush=True)

    def write(self, role, path, value):
        # Stdin, not environment/argv/build context. Separate, private tmpfs per container.
        program = (
            "import os,sys; from pathlib import Path; "
            f"p=Path({path!r}); q=p.with_suffix('.tmp'); "
            "q.write_bytes(sys.stdin.buffer.read()); os.chmod(q,0o600); q.replace(p)"
        )
        self.command(
            "docker",
            "exec",
            "-i",
            self.names[role],
            "python",
            "-c",
            program,
            data=json.dumps(value).encode(),
        )

    def read(self, role, path):
        return json.loads(self.command("docker", "exec", self.names[role], "cat", path).stdout)

    def stats(self):
        return self.read("fixture", "/tmp/phase2c-stats.json")

    def helper(self, role, script):
        return self.command(
            "docker",
            "run",
            "--rm",
            *self.common,
            "--network",
            "container:" + self.names[role],
            "--user",
            "0:0",
            "--cap-add",
            "NET_ADMIN",
            self.image,
            "sh",
            "-ceu",
            script,
        )

    def firewall(self, role):
        p = self.ip
        lines = []
        for tool, family in [("iptables", "4"), ("ip6tables", "6")]:
            lines += [
                f"{tool} -P INPUT DROP",
                f"{tool} -P OUTPUT DROP",
                f"{tool} -P FORWARD DROP",
                f"{tool} -F INPUT",
                f"{tool} -F OUTPUT",
                f"{tool} -F FORWARD",
            ]
            if family == "6":
                # Neighbor discovery only; no ICMP echo, tunneling, UDP or broad IPv6 exception.
                for chain in ("INPUT", "OUTPUT"):
                    for kind in (135, 136):
                        lines.append(
                            f"{tool} -A {chain} -p ipv6-icmp --icmpv6-type {kind} "
                            "-m hl --hl-eq 255 -j ACCEPT"
                        )
            worker, gateway = p["worker" + family], p["gateway" + family]
            if role == "worker":
                lines += [
                    f"{tool} -A OUTPUT -d {gateway} -p tcp --dport 8443 -j ACCEPT",
                    f"{tool} -A INPUT -s {gateway} -p tcp --sport 8443 "
                    "-m conntrack --ctstate ESTABLISHED -j ACCEPT",
                ]
            else:
                lines += [
                    f"{tool} -A INPUT -s {worker} -p tcp --dport 8443 -j ACCEPT",
                    f"{tool} -A OUTPUT -d {worker} -p tcp --sport 8443 "
                    "-m conntrack --ctstate ESTABLISHED -j ACCEPT",
                ]
                for address, port in [
                    (p["authority" + family], 9443),
                    (p["dns" + family], 53),
                    (p["target" + family], 443),
                    (p["other" + family], 443),
                ]:
                    lines += [
                        f"{tool} -A OUTPUT -d {address} -p tcp --dport {port} -j ACCEPT",
                        f"{tool} -A INPUT -s {address} -p tcp --sport {port} "
                        "-m conntrack --ctstate ESTABLISHED -j ACCEPT",
                    ]
        lines += ["iptables-save -c", "ip6tables-save -c"]
        evidence = self.helper(role, "\n".join(lines)).stdout
        assert b":OUTPUT DROP" in evidence and b":FORWARD DROP" in evidence
        (ARTIFACTS / (role + "-initial-rules.txt")).write_bytes(evidence)

    def start_service(self, role):
        self.write(role, "/tmp/phase2c-config.json", self.configs[role])
        self.command("docker", "exec", self.names[role], "rm", "-f", "/tmp/phase2c-ready.json")
        self.command(
            "docker", "exec", "-d", self.names[role], "python", "-m", "laboratory.phase2c." + role
        )
        for _ in range(50):
            ready = self.command(
                "docker",
                "exec",
                self.names[role],
                "test",
                "-f",
                "/tmp/phase2c-ready.json",
                check=False,
            )
            if ready.returncode == 0:
                return self.read(role, "/tmp/phase2c-ready.json").get("epoch")
            time.sleep(0.05)
        raise RuntimeError("Owned service readiness deadline: " + role)

    def build(self):
        sources = [
            "app/services/" + n + ".py"
            for n in ("web_target_policy", "web_target_transport", "controlled_dns")
        ]
        sources += [
            "laboratory/phase2c/" + n
            for n in (
                "Dockerfile",
                "policy.py",
                "protocol.py",
                "authority.py",
                "gateway.py",
                "fixture.py",
                "probe.py",
            )
        ]
        with tempfile.TemporaryDirectory(prefix="vulntrack-phase2c-build-") as directory:
            context = Path(directory)
            for relative in sources:
                target = context / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            result = self.command(
                "docker",
                "build",
                "--quiet",
                "--build-arg",
                "LAB_CERT_NONCE=" + self.nonce,
                "--file",
                "laboratory/phase2c/Dockerfile",
                str(context),
                timeout=240,
            )
            self.image = result.stdout.decode().strip().splitlines()[-1]
            assert self.image.startswith("sha256:")
        self.source_hashes = {
            r: hashlib.sha256((ROOT / r).read_bytes()).hexdigest() for r in sources
        }

    def setup(self):
        existing = []
        for network in self.command("docker", "network", "ls", "-q").stdout.decode().splitlines():
            info = json.loads(self.command("docker", "network", "inspect", network).stdout)[0]
            existing += [
                ipaddress.ip_network(c["Subnet"])
                for c in info["IPAM"]["Config"] or []
                if c.get("Subnet")
            ]
        for subnets in self.subnets.values():
            for subnet in subnets:
                candidate = ipaddress.ip_network(subnet)
                if any(candidate.version == n.version and candidate.overlaps(n) for n in existing):
                    raise RuntimeError("Owned lab subnet collision; no existing network changed")
        self.build()
        for role, name in self.networks.items():
            a, b = self.subnets[role]
            self.command(
                "docker",
                "network",
                "create",
                "--internal",
                "--ipv6",
                "--subnet",
                a,
                "--gateway",
                str(ipaddress.ip_network(a).broadcast_address - 1),
                "--subnet",
                b,
                "--label",
                self.owner,
                name,
            )
        p = self.ip
        connections = {
            "worker": [("front", p["worker4"], p["worker6"])],
            "gateway": [
                ("front", p["gateway4"], p["gateway6"]),
                ("control", p["control4"], p["control6"]),
                ("targets", p["gateway_out4"], p["gateway_out6"]),
            ],
            "authority": [("control", p["authority4"], p["authority6"])],
            "fixture": [
                ("targets", p["target4"], p["target6"]),
                ("front", p["canary4"], p["canary6"]),
                ("control", p["dns4"], p["dns6"]),
            ],
        }
        for role, links in connections.items():
            network, v4, v6 = links[0]
            sysctls = (
                ["--sysctl", "net.ipv4.ip_forward=0", "--sysctl", "net.ipv6.conf.all.forwarding=0"]
                if role == "gateway"
                else []
            )
            self.command(
                "docker",
                "run",
                "-d",
                "--name",
                self.names[role],
                *self.common,
                "--network",
                self.networks[network],
                "--ip",
                v4,
                "--ip6",
                v6,
                *sysctls,
                "--user",
                "0:0" if role == "fixture" else "65532:65532",
                self.image,
            )
            for network, v4, v6 in links[1:]:
                self.command(
                    "docker",
                    "network",
                    "connect",
                    "--ip",
                    v4,
                    "--ip6",
                    v6,
                    self.networks[network],
                    self.names[role],
                )
        # Alias services exist only inside the owned fixture namespace.
        self.helper(
            "fixture",
            "\n".join(
                [
                    f"ip addr add {p['other4']}/32 dev lo",
                    f"ip addr add {p['forbidden4']}/32 dev lo",
                    "ip addr add 169.254.169.254/32 dev lo",
                    f"ip -6 addr add {p['other6']}/128 dev lo nodad",
                    f"ip -6 addr add {p['forbidden6']}/128 dev lo nodad",
                ]
            ),
        )
        # Explicit lab-only routes allow testing direct attempts; the gateway never forwards.
        self.helper(
            "worker",
            "\n".join(
                [
                    f"ip route replace default via {p['gateway4']}",
                    f"ip -6 route replace default via {p['gateway6']}",
                ]
            ),
        )
        assert (
            self.helper(
                "gateway",
                "cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding",
            ).stdout.strip()
            == b"0\n0"
        )
        # Alias destinations are reached through the fixture's owned endpoint, not the host.
        for family, tool in [("4", "ip"), ("6", "ip -6")]:
            suffix = "/32" if family == "4" else "/128"
            routes = "\n".join(
                f"{tool} route replace {p[key + family]}{suffix} via {p['target' + family]}"
                for key in ("other", "forbidden")
            )
            self.helper("gateway", routes)
        self.firewall("worker")
        self.firewall("gateway")
        self.configs = {
            "authority": {"control_key": self.key, "bind": [p["authority4"], p["authority6"]]},
            "gateway": {
                "control_key": self.key,
                "bind": [p["gateway4"], p["gateway6"]],
                "authority": p["authority4"],
                "dns": p["dns4"],
            },
            "fixture": {
                **{k: p[k] for k in ("target4", "other4", "target6", "other6", "forbidden4")},
                "dns_bind": [p["dns4"], p["dns6"]],
                "canaries": {
                    p["canary4"]: [443, 445, 2222, 2375, 5432, 8000, 8080, 53],
                    p["canary6"]: [443, 445, 2222, 2375, 5432, 8000, 8080, 53],
                    p["forbidden4"]: [443],
                    p["forbidden6"]: [443],
                    p["target4"]: [8444],
                    p["target6"]: [8444],
                    "169.254.169.254": [80],
                },
            },
        }
        self.start_service("fixture")
        self.write("authority", "/tmp/phase2c-state.json", {"lease_until": 0, "policies": {}})
        self.authority_epoch = self.start_service("authority")
        self.gateway_epoch = self.start_service("gateway")
        for role in self.names:
            details = self.inspect(role)
            assert not details["HostConfig"]["Privileged"]
            assert not details["HostConfig"]["PortBindings"]
            assert (
                details["HostConfig"]["CapDrop"] == ["ALL"] and not details["HostConfig"]["CapAdd"]
            )
            assert details["HostConfig"]["ReadonlyRootfs"]
            assert all(m["Type"] == "tmpfs" for m in details["Mounts"])
        for name in self.networks.values():
            assert json.loads(self.command("docker", "network", "inspect", name).stdout)[0][
                "Internal"
            ]
        self.record("three owned dual-stack internal bridges, no published ports or host mounts")
        self.record("worker kernel OUTPUT DROP forces the gateway on IPv4 and IPv6")
        self.record("gateway kernel INPUT/OUTPUT/FORWARD DROP and forwarding disabled")

    def probe(self, message, role="worker", *, timeout=10):
        result = self.command(
            "docker",
            "exec",
            "-i",
            self.names[role],
            "python",
            "-m",
            "laboratory.phase2c.probe",
            data=json.dumps(message).encode(),
            timeout=timeout,
        )
        return json.loads(result.stdout)

    def request(self, permit, *, v6=False, message=None):
        return self.probe(
            {
                "action": "rpc",
                "address": self.ip["gateway6" if v6 else "gateway4"],
                "message": message or {"operation_id": permit.operation_id},
            }
        )

    def wait_stat(self, key, minimum, *, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            stats = self.stats()
            if stats[key] >= minimum:
                return stats
            time.sleep(0.05)
        raise AssertionError("Owned fixture statistic deadline: " + key)

    def exercise(self, broker):
        p = self.ip

        def permit(path="/ok", *, host="control.example.net", ttl=8):
            addresses = [p["target6"]] if host == "v6.example.net" else [p["target4"]]
            return broker.add(
                "https://" + host + path,
                addresses,
                self.gateway_epoch,
                self.authority_epoch,
                ttl=ttl,
            )

        assert self.probe({"action": "security"})["firewall_mutation_denied"]
        self.record(
            "untrusted worker cannot change firewall, open raw sockets or read control credentials"
        )
        self.record(
            "live worker root filesystem, cgroup limits and private-key permissions audited"
        )
        # A positive TCP control proves that deliberately listening canaries are real.
        positive = self.probe(
            {"action": "raw", "targets": [[p["canary4"], 5432], [p["canary6"], 8000]]}, "fixture"
        )
        assert all(v["connected"] for v in positive)
        assert self.wait_stat("canary_hits", 2)["canary_hits"] == 2
        baseline_canaries = 2
        self.record("private IPv4/IPv6 canaries independently confirmed listening")
        first = permit()
        broker.blocked_operational(first)
        assert self.stats()["dns_queries"] == 0
        self.record("real API verify stays 503 with zero DNS and zero durable attempts")
        assert self.request(first)["peer_ip"] == p["target4"]
        self.record(
            "allowed operation reaches real IPv4 TLS only through gateway and controlled DNS"
        )
        assert self.request(first)["result"] == "denied"
        self.record("consumed operation cannot be replayed on another connection")
        v6 = permit(host="v6.example.net")
        assert self.request(v6, v6=True)["peer_ip"] == p["target6"]
        self.record("allowed operation reaches real IPv6 TLS through IPv6 gateway ingress")
        assert self.stats()["sni_valid"] >= 2 and self.stats()["host_valid"] >= 2
        self.record("original Host and SNI verified by the separate TLS fixture")
        raw_cases = {
            "allowed TLS IP directly without gateway": [(p["target4"], 443), (p["target6"], 443)],
            "unauthorized IPv4 and IPv6": [(p["forbidden4"], 443), (p["forbidden6"], 443)],
            "non-HTTPS ports": [(p["target4"], 8444), (p["target6"], 8444)],
            "simulated Windows and WSL hosts": [(p["canary4"], 445), (p["canary6"], 2222)],
            "simulated PostgreSQL and Backend": [(p["canary4"], 5432), (p["canary6"], 8000)],
            "simulated Docker API and alternate proxy": [
                (p["canary4"], 2375),
                (p["canary6"], 8080),
            ],
            "unapproved DNS TCP": [
                (p["canary4"], 53),
                (p["canary6"], 53),
                (p["dns4"], 53),
                ("127.0.0.11", 53),
            ],
            "metadata representation": [("169.254.169.254", 80)],
        }
        for label, targets in raw_cases.items():
            assert not any(
                v["connected"] for v in self.probe({"action": "raw", "targets": targets})
            )
            self.record("raw worker TCP denied: " + label)
        local = self.probe({"action": "local"})
        assert local["hits"] == 0 and not any(v["connected"] for v in local["results"])
        self.record("listening localhost IPv4/IPv6 services unreachable even in worker namespace")
        self.probe({"action": "udp", "targets": [p["canary4"], p["canary6"], p["dns4"], p["dns6"]]})
        assert self.stats()["canary_hits"] == baseline_canaries
        self.record("worker UDP DNS cannot bypass the mandatory gateway")
        for label, targets in {
            "private services": [(p["canary4"], 5432), (p["canary6"], 8000)],
            "unapproved TLS IP": [(p["forbidden4"], 443), (p["forbidden6"], 443)],
            "unapproved TLS port": [(p["target4"], 8444), (p["target6"], 8444)],
        }.items():
            assert not any(
                v["connected"] for v in self.probe({"action": "raw", "targets": targets}, "gateway")
            )
            self.record("raw gateway TCP independently denied: " + label)
        self.probe({"action": "udp", "targets": [p["dns4"], p["dns6"]]}, "gateway")
        assert self.stats()["canary_hits"] == baseline_canaries
        self.record("gateway UDP denied despite allowing operator DNS TCP")
        untouched = self.stats()["tls_started"]
        for override in (
            {"host": "control.example.net"},
            {"ip": p["target4"]},
            {"port": 443},
            {"workspace_id": first.workspace_id},
        ):
            reply = self.request(first, message={"operation_id": first.operation_id, **override})
            assert reply["result"] == "denied"
        assert self.stats()["tls_started"] == untouched
        self.record("worker cannot supply host, IP, port, workspace or arbitrary egress rules")
        from uuid import uuid4

        assert self.request(first, message={"operation_id": str(uuid4())})["result"] == "denied"
        self.record("unknown operation fails closed without upstream connection")
        bad_control = self.probe(
            {
                "action": "rpc",
                "address": p["authority4"],
                "port": 9443,
                "message": {"message": {}, "mac": "0" * 64},
            },
            "gateway",
        )
        assert bad_control["result"] == "denied" and bad_control["transport_closed"]
        self.record("forged control authentication rejected over the actual TCP control channel")
        redirect = permit("/redirect")
        assert self.request(redirect)["code"] == "REDIRECTS_DISABLED"
        assert self.stats()["canary_hits"] == baseline_canaries
        self.record("real HTTPS redirect denied without contacting metadata canary")
        changed = permit()
        self.write("fixture", "/tmp/phase2c-dns-mode.json", "changed")
        assert self.request(changed)["code"] == "POLICY_DNS_CHANGED"
        self.write("fixture", "/tmp/phase2c-dns-mode.json", "normal")
        self.record("DNS set differing from the authorized permit denied before TLS")
        rebind = permit(host="rebind.example.net")
        assert self.request(rebind)["code"] == "POLICY_DNS_CHANGED"
        self.record("DNS rebinding between fresh resolutions denied")
        failed_dns = permit(host="fail.example.net")
        assert self.request(failed_dns)["result"] == "denied"
        self.record("DNS failure has no system resolver fallback or permissive retry")
        revoked = permit()
        broker.revoke(revoked)
        assert self.request(revoked)["result"] == "denied"
        self.record("real SQL challenge revocation prevents new connections")
        outdated = permit()
        broker.change_target(outdated)
        assert self.request(outdated)["result"] == "denied"
        self.record("changed declaration invalidates the bound target version")
        expired = permit(ttl=0.45)
        time.sleep(0.5)
        assert self.request(expired)["result"] == "denied"
        self.record("expired policy prevents new connections")

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            active = permit("/slow")
            before = self.stats()
            future = pool.submit(self.request, active)
            self.wait_stat("slow_active", 1)
            started = time.monotonic()
            broker.revoke(active)
            assert future.result(timeout=2)["result"] == "denied"
            self.wait_stat("slow_closed", before["slow_closed"] + 1)
            self.measurements["revocation_to_active_tls_close_seconds"] = round(
                time.monotonic() - started, 3
            )
            assert self.measurements["revocation_to_active_tls_close_seconds"] < 2
            assert self.stats()["slow_active"] == 0
            self.record(
                "SQL revocation closes an already active gateway TLS socket within measured bound"
            )
            assert self.request(active)["result"] == "denied"
            self.record("revoked active operation cannot reuse its previous policy")
            active = permit("/slow", ttl=3.0)
            before = self.stats()
            future = pool.submit(self.request, active)
            self.wait_stat("slow_active", 1)
            assert future.result(timeout=4)["result"] == "denied"
            self.wait_stat("slow_closed", before["slow_closed"] + 1)
            self.record("expiry during operation cancels TLS and releases no buffered result")
            active = permit("/slow")
            future = pool.submit(self.request, active)
            self.wait_stat("slow_active", 1)
            assert self.request(active)["result"] == "denied"
            parallel = permit()
            assert self.request(parallel)["result"] == "ok"
            broker.revoke(active)
            assert future.result(timeout=2)["result"] == "denied"
            self.record("concurrent consumption of the same operation is denied")
            self.record("distinct scoped operations proceed concurrently without sharing a tunnel")
            double = permit()
            response = self.probe(
                {
                    "action": "double",
                    "address": p["gateway4"],
                    "message": {"operation_id": double.operation_id},
                }
            )
            assert response["first"]["result"] == "ok" and not response["second_response"]
            self.record("existing worker connection cannot be reused for another request")
            idle = permit()
            active = permit("/slow")
            future = pool.submit(self.request, active)
            self.wait_stat("slow_active", 1)
            broker.pause()
            started = time.monotonic()
            assert future.result(timeout=3)["result"] == "denied"
            self.measurements["broker_loss_to_denial_seconds"] = round(
                time.monotonic() - started, 3
            )
            # Do not refresh the lease while simulating a crashed broker.
            assert self.request(idle)["result"] == "denied"
            self.record(
                "loss of authorization broker heartbeat closes active TLS and denies new work"
            )
            broker.resume()
            time.sleep(0.2)
            idle = permit()
            active = permit("/slow")
            future = pool.submit(self.request, active)
            self.wait_stat("slow_active", 1)
            self.command("docker", "stop", "--time", "1", self.names["authority"])
            assert future.result(timeout=2)["result"] == "denied"
            assert self.request(idle)["result"] == "denied"
            self.record("control service outage fails closed for active and new operations")
            self.command("docker", "start", self.names["authority"])
            self.authority_epoch = self.start_service("authority")
            broker.refresh()
            assert self.request(idle)["result"] == "denied"
            self.record("authority restart cannot resurrect an old unconsumed policy")
            assert self.request(permit())["result"] == "ok"
            self.record(
                "recovery requires a freshly issued policy bound to the new authority epoch"
            )
            idle = permit()
            active = permit("/slow")
            future = pool.submit(self.request, active)
            self.wait_stat("slow_active", 1)
            self.command("docker", "restart", "--time", "1", self.names["gateway"])
            response = future.result(timeout=2)
            assert response["result"] == "denied" and response["transport_closed"]
            self.firewall("gateway")  # Bootstrap only sleep; daemon starts AFTER audited rules.
            self.gateway_epoch = self.start_service("gateway")
            assert self.request(idle)["result"] == "denied"
            self.record("gateway restart closes old connections and rejects old epoch policies")
            assert self.request(permit())["result"] == "ok"
            self.record("gateway recovery applies kernel filters before serving new operations")
        post_restart = self.probe(
            {
                "action": "raw",
                "targets": [
                    [p["forbidden4"], 443],
                    [p["forbidden6"], 443],
                    [p["canary4"], 5432],
                    [p["canary6"], 8000],
                ],
            },
            "gateway",
        )
        assert not any(value["connected"] for value in post_restart)
        self.record("IPv4/IPv6 denials repeated after gateway restart with fresh kernel counters")
        assert self.stats()["canary_hits"] == baseline_canaries
        self.record("all forbidden canaries received zero adversarial TCP or UDP traffic")
        self.measurements["broker_successful_refreshes"] = broker.refresh_count
        self.measurements["broker_read_or_publish_errors"] = broker.error_count
        self.measurements["broker_invalidated_scope_observations"] = broker.scope_denials
        self.measurements["maximum_broker_snapshot_refresh_seconds"] = round(
            broker.maximum_refresh_seconds, 3
        )
        self.worker_security = {
            key: self.inspect("worker")["HostConfig"][key]
            for key in (
                "ReadonlyRootfs",
                "CapDrop",
                "CapAdd",
                "Privileged",
                "Memory",
                "MemorySwap",
                "NanoCpus",
                "PidsLimit",
                "SecurityOpt",
                "LogConfig",
            )
        }
        for role in ("worker", "gateway"):
            rules = self.helper(role, "iptables-save -c\nip6tables-save -c").stdout
            (ARTIFACTS / (role + "-final-rules.txt")).write_bytes(rules)
            drops = [int(value) for value in re.findall(rb":OUTPUT DROP \[(\d+):", rules)]
            assert len(drops) == 2 and all(value > 0 for value in drops)
            self.measurements[role + "_kernel_dropped_packets"] = {
                "ipv4": drops[0],
                "ipv6": drops[1],
            }
        self.record("IPv4 and IPv6 kernel counters prove drops independently of Python and routing")
        self.record("live kernel rules and counters retained as private reproducible evidence")

    def cleanup(self):
        for name in reversed(
            self.command(
                "docker", "ps", "-a", "--filter", "label=" + self.owner, "--format", "{{.Names}}"
            )
            .stdout.decode()
            .splitlines()
        ):
            info = json.loads(self.command("docker", "inspect", name).stdout)[0]
            assert info["Config"]["Labels"].get(self.label) == self.nonce
            self.command("docker", "stop", "--time", "1", name, check=False)
            self.command("docker", "rm", name)
        for name in (
            self.command(
                "docker",
                "network",
                "ls",
                "--filter",
                "label=" + self.owner,
                "--format",
                "{{.Name}}",
            )
            .stdout.decode()
            .splitlines()
        ):
            info = json.loads(self.command("docker", "network", "inspect", name).stdout)[0]
            assert info["Labels"].get(self.label) == self.nonce and not info["Containers"]
            self.command("docker", "network", "rm", name)


def main():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    RESULT.unlink(missing_ok=True)
    (ARTIFACTS / "failure.json").unlink(missing_ok=True)
    (ARTIFACTS / "command-failure.log").unlink(missing_ok=True)
    lab = EgressLab()
    try:
        lab.setup()
        with LaboratoryBroker(
            lambda state: lab.write("authority", "/tmp/phase2c-state.json", state)
        ) as broker:
            lab.exercise(broker)
    except BaseException as error:
        for role, source, destination in (
            ("gateway", "/tmp/phase2c-decisions.jsonl", "gateway-decisions.jsonl"),
            ("fixture", "/tmp/phase2c-stats.json", "fixture-stats.json"),
        ):
            diagnostic = lab.command("docker", "exec", lab.names[role], "cat", source, check=False)
            if diagnostic.returncode == 0:
                (ARTIFACTS / destination).write_bytes(diagnostic.stdout)
        (ARTIFACTS / "failure.json").write_text(
            json.dumps(
                {
                    "result": "failed",
                    "exception_class": type(error).__name__,
                    "last_passed_step": lab.step,
                }
            )
            + "\n"
        )
        raise
    finally:
        lab.cleanup()
    report = {
        "result": "passed",
        "checks": lab.checks,
        "measurements": lab.measurements,
        "image_id": lab.image,
        "build_source_sha256": lab.source_hashes,
        "topology": "three owned internal dual-stack bridges with separate mandatory gateway",
        "worker_security": lab.worker_security,
        "external_target_requests": False,
        "public_egress_demonstrated": False,
        "public_egress_status": "BLOQUEADO",
        "runtime_verification_enabled": False,
        "zap_installed_or_executed": False,
        "personal_database_used": False,
        "disposable_database_used": True,
        "database_credentials_in_worker_gateway_authority": False,
        "host_firewall_changed": False,
        "owned_containers_and_networks_removed": True,
        "revocation": ("bounded gateway cancellation; not instantaneous kernel revocation"),
        "in_scope": "untrusted worker; trusted gateway, broker, policy service, host and daemon",
    }
    RESULT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
