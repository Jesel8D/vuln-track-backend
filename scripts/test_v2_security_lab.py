"""Owned network-none laboratory only. Never starts ZAP or uses an application DB."""

import argparse
import base64
import json
import secrets
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "api-tests/v2/.artifacts/phase2a"


def command(*args, data=None, timeout=30, check=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS / "lab-command-failure.log").write_bytes(result.stderr)
        raise RuntimeError(f"Owned lab command failed: {args[0]} ({result.returncode})")
    return result


def inspect(name):
    return json.loads(command("docker", "inspect", name).stdout)[0]


def main():
    global ARTIFACTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase2b",
        action="store_true",
        help="Add controlled DNS and durable lab-only evidence tests",
    )
    options = parser.parse_args()
    phase = "phase2b" if options.phase2b else "phase2a"
    ARTIFACTS = ROOT / "api-tests/v2/.artifacts" / phase
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "network-lab-results.json").unlink(missing_ok=True)
    (ARTIFACTS / "lab-command-failure.log").unlink(missing_ok=True)
    nonce = secrets.token_hex(6)
    label = "vulntrack." + phase
    owner = label + "=" + nonce
    names = {role: f"vulntrack-{phase}-{nonce}-{role}" for role in ["fixture", "worker", "memory"]}
    created = []
    worker_process = None
    common = [
        "--label",
        owner,
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
    try:
        # Explicit allowlist build context: never send .local, .env, DB files,
        # Git credentials, node_modules or the user's host tree to Docker.
        with tempfile.TemporaryDirectory(prefix="vulntrack-lab-build-") as directory:
            context = Path(directory)
            sources = [
                f"app/services/{name}.py"
                for name in [
                    "web_target_policy",
                    "web_target_transport",
                    "web_target_challenges",
                    "web_target_evidence",
                    "web_target_tokens",
                    "controlled_dns",
                ]
            ] + [f"laboratory/phase2a/{name}" for name in ["Dockerfile", "fixture.py", "checks.py"]]
            sources += ["laboratory/phase2b/dns_fixture.py", "laboratory/phase2b/checks.py"]
            for relative in sources:
                target = context / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            result = command(
                "docker",
                "build",
                "--quiet",
                "--build-arg",
                "LAB_CERT_NONCE=" + nonce,
                "--file",
                "laboratory/phase2a/Dockerfile",
                str(context),
                timeout=240,
            )
            image = result.stdout.decode().strip().splitlines()[-1]
            assert image.startswith("sha256:")
        command(
            "docker",
            "run",
            "-d",
            "--name",
            names["fixture"],
            *common,
            "--network",
            "none",
            "--user",
            "0:0",
            image,
        )
        created.append(names["fixture"])
        # NET_ADMIN exists ONLY in this short-lived trusted setup helper, in the
        # owned network-none namespace. Never in worker; no host-network changes.
        firewall = r"""
set -eu
ip addr add 93.184.216.10/32 dev lo
ip addr add 93.184.216.11/32 dev lo
ip addr add 10.77.0.10/32 dev lo
ip addr add 169.254.169.254/32 dev lo
ip -6 addr add 2606:4700:ffff::10/128 dev lo nodad
iptables -P OUTPUT DROP
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d 93.184.216.10/32 -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -d 93.184.216.11/32 -p tcp --dport 443 -j ACCEPT
ip6tables -P OUTPUT DROP
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -d 2606:4700:ffff::10/128 -p tcp --dport 443 -j ACCEPT
"""
        if options.phase2b:
            firewall += """
ip addr add 10.77.0.53/32 dev lo
ip addr add 93.184.216.12/32 dev lo
ip -6 addr add fd00:77::53/128 dev lo nodad
iptables -A OUTPUT -d 10.77.0.53/32 -p tcp --dport 53 -j ACCEPT
ip6tables -A OUTPUT -d fd00:77::53/128 -p tcp --dport 53 -j ACCEPT
"""
        command(
            "docker",
            "run",
            "--rm",
            *common,
            "--network",
            "container:" + names["fixture"],
            "--user",
            "0:0",
            "--cap-add",
            "NET_ADMIN",
            image,
            "sh",
            "-ceu",
            firewall,
        )
        command(
            "docker",
            "exec",
            "-d",
            *(["-e", "VULNTRACK_LAB_DNS=1"] if options.phase2b else []),
            "--user",
            "0:0",
            names["fixture"],
            "python",
            "-m",
            "laboratory.phase2a.fixture",
        )
        for _ in range(50):
            ready = command(
                "docker", "exec", names["fixture"], "test", "-f", "/tmp/ready", check=False
            )
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Owned TLS fixture did not start")
        command(
            "docker",
            "run",
            "-d",
            "--name",
            names["worker"],
            *common,
            "--network",
            "container:" + names["fixture"],
            "--user",
            "65532:65532",
            image,
        )
        created.append(names["worker"])
        worker = inspect(names["worker"])
        fixture = inspect(names["fixture"])
        assert fixture["HostConfig"]["NetworkMode"] == "none"
        assert worker["HostConfig"]["NetworkMode"] == "container:" + fixture["Id"]
        assert set(fixture["NetworkSettings"]["Networks"]) == {"none"}
        assert not worker["Mounts"] or all(m["Type"] == "tmpfs" for m in worker["Mounts"])
        assert not worker["HostConfig"]["Privileged"]
        assert worker["HostConfig"]["CapDrop"] == ["ALL"]
        assert not worker["HostConfig"]["CapAdd"]
        assert not worker["HostConfig"]["PortBindings"]
        worker_process = subprocess.Popen(
            ["docker", "exec", "-i", names["worker"], "python", "-m", "laboratory.phase2a.checks"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not select.select([worker_process.stdout], [], [], 15)[0]:
            raise RuntimeError("Lab protocol deadline")
        instructions = json.loads(worker_process.stdout.readline())
        body = base64.b64decode(instructions["fixture_body_b64"], validate=True)
        assert 80 < len(body) < 256
        command(
            "docker",
            "exec",
            "-i",
            names["fixture"],
            "python",
            "-c",
            "import sys; from pathlib import Path; "
            "Path('/tmp/proof').write_bytes(sys.stdin.buffer.read())",
            data=body,
        )
        output, errors = worker_process.communicate(input=b"READY\n", timeout=40)
        (ARTIFACTS / "lab-checks.log").write_bytes(errors)
        if worker_process.returncode:
            raise RuntimeError("Owned lab checks failed; see private lab-checks.log")
        report = json.loads(output)
        assert report["result"] == "passed" and not report["zap_executed"]
        probe = command(
            "docker",
            "exec",
            names["fixture"],
            "python",
            "-c",
            "from pathlib import Path; "
            "assert not Path('/tmp/canary-hits').exists(); "
            "assert Path('/tmp/sni').read_text() == 'control.example.net'",
        )
        assert probe.returncode == 0
        report["checks"].extend(
            ["listening lab canaries received zero connections", "original SNI observed"]
        )
        if options.phase2b:
            from scripts.verification_lab_bridge import run_persisted_lab

            dns_report = run_persisted_lab(command, names, ARTIFACTS)
            report["checks"].extend(dns_report["checks"])
            command("docker", "exec", names["fixture"], "test", "!", "-f", "/tmp/canary-hits")
            report["checks"].append("DNS-changed unauthorized TLS canary received zero connections")
            report["durable_lab_result_never_counts_as_domain_control"] = True
        # A real, small, isolated OOM experiment verifies memory enforcement.
        memory = names["memory"]
        command(
            "docker",
            "create",
            "--name",
            memory,
            "--label",
            owner,
            "--network",
            "none",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "32m",
            "--memory-swap",
            "32m",
            "--pids-limit",
            "16",
            "--cpus",
            "0.25",
            image,
            "python",
            "-c",
            "bytearray(80 * 1024 * 1024)",
        )
        created.append(memory)
        command("docker", "start", "-a", memory, check=False, timeout=20)
        memory_state = inspect(memory)["State"]
        assert memory_state["OOMKilled"] and memory_state["ExitCode"] == 137
        report["checks"].append("real cgroup OOM enforced on owned 32MiB probe")
        report.update(
            {
                "image_id": image,
                "topology": "shared lab network-none namespace, loopback fixtures only",
                "python_policy_bypassed_for_network_negative_tests": True,
                "application_database_used": options.phase2b,
                "personal_database_used": False,
                "disposable_application_database_used": options.phase2b,
                "network_worker_received_database_credentials": False,
                "external_target_requests": False,
                "production_egress_guarantee": False,
                "runtime_verification_enabled": False,
                "worker_security": {
                    key: worker["HostConfig"][key]
                    for key in [
                        "NetworkMode",
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
                    ]
                },
            }
        )
        (ARTIFACTS / "network-lab-results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        if worker_process is not None and worker_process.poll() is None:
            worker_process.kill()
            worker_process.communicate(timeout=5)
        owned_names = (
            command("docker", "ps", "-a", "--filter", "label=" + owner, "--format", "{{.Names}}")
            .stdout.decode()
            .splitlines()
        )
        for name in reversed(owned_names):
            details = inspect(name)
            if details["Config"]["Labels"].get(label) != nonce:
                raise RuntimeError("Refusing cleanup of an unowned container")
            command("docker", "stop", "--time", "2", name, check=False)
            command("docker", "rm", name)
        print(
            "Owned lab containers removed; no volumes or application services touched", flush=True
        )


if __name__ == "__main__":
    main()
