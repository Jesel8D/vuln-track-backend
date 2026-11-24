"""Owned lab launcher: separate signed grant for real execution; no public API."""

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]


def run(args, *, env=None, data=None, timeout=180):
    r = subprocess.run(args, input=data, capture_output=True, timeout=timeout, env=env)
    if r.returncode:
        raise RuntimeError(f"Owned lab command failed ({Path(args[0]).name}, exit {r.returncode})")
    return r.stdout


def launch(catalogue, fixture, destination, *, plan=None, grant=None):
    if destination.exists():
        raise ValueError("New lab destination required; never reuse an existing profile")
    os.umask(0o077)
    destination.mkdir(parents=True, mode=0o700)
    source = destination / "source"
    source.mkdir()
    for name in ["app", "scripts", "alembic", "alembic_verification", "dev"]:
        if (ROOT / name).is_dir():
            shutil.copytree(
                ROOT / name,
                source / name,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".local"),
            )
    for name in ["pyproject.toml", "requirements.lock", "alembic.ini", "alembic-verification.ini"]:
        shutil.copyfile(ROOT / name, source / name)
    # Only public schema sources, never copy another installation's profiles.
    database = ROOT.parent / "vuln-track-database"
    reference = destination / "database-reference"
    reference.mkdir()
    files = run(["git", "-C", str(database), "ls-files", "-z"]).decode().split("\0")
    for name in filter(None, files):
        p = reference / name
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(database / name, p)
    shutil.copyfile(catalogue, destination / "catalogue.json")
    if plan is None:
        shutil.copyfile(fixture, destination / "fixture.json")
    else:
        shutil.copyfile(plan, destination / "plan.json")
        shutil.copyfile(grant, destination / "grant.json")
        (source / "REVIEWED_COMMIT").write_text(
            run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
        )
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "PYTHONPATH": str(source),
        "DATABASE_V2_PATH": str(reference),
    }
    # Python environment belongs to the developer; no application secrets inherited.
    command = (
        [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; from scripts.nvd_trial_lab import child; "
            "child(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))",
            str(destination),
            str(destination / "plan.json"),
            str(destination / "grant.json"),
        ]
        if plan
        else [
            sys.executable,
            "-m",
            "scripts.nvd_trial_lab",
            "--child",
            "--destination",
            str(destination),
        ]
    )
    r = subprocess.run(
        command,
        cwd=source,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
    )
    (destination / "lifecycle.log").write_bytes(r.stdout)
    if r.returncode:
        raise RuntimeError("Offline rehearsal failed; private lifecycle.log retained")
    return json.loads((destination / "results/rehearsal.json").read_text())


def free_subnet():
    ids = run(["docker", "network", "ls", "-q"]).decode().split()
    used = []
    for net in json.loads(run(["docker", "network", "inspect", *ids])):
        for item in net.get("IPAM", {}).get("Config") or []:
            if item.get("Subnet"):
                used.append(ipaddress.ip_network(item["Subnet"]))
    for slot in range(250):
        net = ipaddress.ip_network(f"10.245.{slot}.0/24")
        if not any(net.version == other.version and net.overlaps(other) for other in used):
            return str(net)
    raise RuntimeError("No free owned lab subnet")


def child(destination, plan=None, grant=None):
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    from app.services.cpe_catalog import UPSERT, normalize, refresh_summary
    from scripts.v2_development import API_ROLE, PersistentV2, private_json

    permit = None
    if plan is not None:
        from app.integrations.nvd_lab_authorization import authorize, read_json

        info = read_json(plan)
        permit = authorize(
            plan, grant, commit=(ROOT / "REVIEWED_COMMIT").read_text().strip(), image=info["image"]
        )
        actual = json.loads(run(["docker", "image", "inspect", info["image"]]))[0]
        if (
            actual.get("Config", {}).get("Labels", {}).get("io.vulntrack.reviewed-commit")
            != info["commit"]
        ):
            raise ValueError("Reviewed image/commit required")
    nonce = secrets.token_hex(6) if permit is None else permit.plan["laboratory"].rsplit("-", 1)[1]
    name = "vulntrack-5c1r-" + nonce if permit is None else permit.plan["laboratory"]
    stack = PersistentV2("rc3", pg_port=0, api_port=0, web_port=0)
    stack.config.update(project=name, container=name + "-postgres", volume=name + "-pgdata")
    stack.save()
    stack.name, stack.volume = stack.config["container"], stack.config["volume"]
    network, worker = name + "-internal", name + "-worker"
    created_network = False
    guard, egress = name + "-guard", name + "-egress"
    pg_ip = None
    try:
        # Only this fresh source copy's Compose file is adapted. Docker's default
        # address pool is exhausted by existing retained labs; never prune them.
        compose = ROOT / "dev/v2/compose.yaml"
        original = compose.read_text()
        original = original.replace(
            "networks:\n  default:\n",
            "networks:\n  default:\n    ipam:\n      config:\n        - subnet: "
            + free_subnet()
            + "\n",
        )
        compose.write_text(original)
        stack.start_database()
        stack.bootstrap()
        entry = json.loads((destination / "catalogue.json").read_text())
        if UUID(entry["cpe"]["cpeNameId"]) != UUID("10e70f95-eb64-4262-a822-9055aab8fe76"):
            raise ValueError("Exact official snapshot record required")
        engine = create_engine(stack.url("postgres"), hide_parameters=True)
        with engine.begin() as db:
            db.execute(UPSERT, normalize(entry, "live", None, source="nvd-feed"))
            refresh_summary(db, "live")
        engine.dispose()
        run(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--subnet",
                free_subnet(),
                "--label",
                "vulntrack.trial=" + nonce,
                network,
            ]
        )
        created_network = True
        run(["docker", "network", "connect", "--alias", "postgres", network, stack.name])
        current = stack.inspect("container", stack.name)
        for old in current["NetworkSettings"]["Networks"]:
            if old != network:
                run(["docker", "network", "disconnect", old, stack.name])
        pg_ip = stack.inspect("container", stack.name)["NetworkSettings"]["Networks"][network][
            "IPAddress"
        ]
        url = make_url(stack.url(API_ROLE)).set(
            host="postgres" if permit is None else pg_ip, port=5432
        )
        private_json(
            destination / "worker.json",
            {
                "database_url": url.render_as_string(hide_password=False),
                "token_secret": stack.config["token_secret"],
                "workspace_hmac_key": stack.config["workspace_hmac_key"],
                "laboratory": name,
            },
        )
        outputs = destination / "results"
        outputs.mkdir(mode=0o700)
        image = (
            os.environ.get("TRIAL_IMAGE", "vulntrack-backend:5c1r-trial")
            if permit is None
            else permit.plan["image"]
        )
        worker_network = network
        extra_mounts, extra_args = [], []
        if permit is not None:
            control = destination / "control"
            control.mkdir(mode=0o700)
            private_json(control / "pg.json", {"address": pg_ip})
            (destination / "image-id").write_text(image)
            run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    guard,
                    "--network",
                    "none",
                    "--read-only",
                    "--user=0:0",
                    "--cap-drop=ALL",
                    "--cap-add=NET_ADMIN",
                    "--cap-add=NET_RAW",
                    "--security-opt=no-new-privileges",
                    "--pids-limit=32",
                    "--memory=128m",
                    "--mount",
                    f"type=bind,src={control},dst=/control",
                    "--mount",
                    f"type=bind,src={outputs},dst=/output,readonly",
                    "--entrypoint",
                    "python",
                    image,
                    "-m",
                    "scripts.nvd_trial_network",
                    "--action",
                    "hold",
                    "--pg",
                    pg_ip,
                ]
            )
            import time

            end = time.monotonic() + 5
            while not (control / "guard-ready").exists():
                if time.monotonic() >= end:
                    raise RuntimeError("Egress guard not ready; no network attached")
                time.sleep(0.05)
            run(["docker", "network", "connect", network, guard])
            run(
                [
                    "docker",
                    "network",
                    "create",
                    "--subnet",
                    free_subnet(),
                    "--label",
                    "vulntrack.trial=" + nonce,
                    egress,
                ]
            )
            run(["docker", "network", "connect", egress, guard])
            run(
                [
                    "docker",
                    "exec",
                    guard,
                    "python",
                    "-m",
                    "scripts.nvd_trial_network",
                    "--action",
                    "setup",
                    "--pg",
                    pg_ip,
                ],
                timeout=12,
            )
            worker_network = "container:" + guard
            for host, target in [
                (plan, "/input/plan.json"),
                (grant, "/input/grant.json"),
                (control, "/control"),
                (destination / "image-id", "/input/image-id"),
            ]:
                extra_mounts += ["--mount", f"type=bind,src={host},dst={target},readonly"]
            extra_args = [
                "--plan-file",
                "/input/plan.json",
                "--authorization-record",
                "/input/grant.json",
                "--control",
                "/control",
                "--image-id",
                "/input/image-id",
            ]
        run(
            [
                "docker",
                "run",
                "--name",
                worker,
                "--network",
                worker_network,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--pids-limit=64",
                "--memory=384m",
                "--cpus=1",
                "--no-healthcheck",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--mount",
                f"type=bind,src={destination / 'worker.json'},dst=/input/config.json,readonly",
                *(
                    [
                        "--mount",
                        f"type=bind,src={destination / 'fixture.json'},"
                        "dst=/input/fixture.json,readonly",
                    ]
                    if permit is None
                    else extra_mounts
                ),
                "--mount",
                f"type=bind,src={outputs},dst=/output",
                "--entrypoint",
                "python",
                image,
                "-m",
                "scripts.nvd_trial",
                "--mode",
                "offline" if permit is None else "real",
                "--config",
                "/input/config.json",
                *(["--fixture", "/input/fixture.json"] if permit is None else extra_args),
                "--output",
                "/output",
            ],
            timeout=90,
        )
        info = json.loads(run(["docker", "inspect", worker]))[0]
        net = json.loads(run(["docker", "network", "inspect", network]))[0]
        assert net["Internal"] and not info["HostConfig"]["PortBindings"]
        if permit is None:
            assert set(info["NetworkSettings"]["Networks"]) == {network}
        else:
            assert info["HostConfig"]["NetworkMode"].startswith("container:")
            run(
                [
                    "docker",
                    "exec",
                    guard,
                    "python",
                    "-m",
                    "scripts.nvd_trial_network",
                    "--action",
                    "close",
                    "--pg",
                    pg_ip,
                ]
            )
        result = json.loads((outputs / "rehearsal.json").read_text())
        result.update(
            container=worker,
            postgres=stack.name,
            volume=stack.volume,
            internal_network=permit is None,
            namespace_egress_guard=permit is not None,
            public_ports=0,
            private_installation_mounts=False,
            immutable_root=True,
            source_code_sha256=hashlib.sha256(
                (ROOT / "scripts/nvd_trial.py").read_bytes()
            ).hexdigest(),
        )
        (outputs / "rehearsal.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        # Keep all owned resources/evidence/data. No rm/down-v/prune/volume deletion.
        subprocess.run(["docker", "stop", "--time", "5", worker], capture_output=True)
        if permit is not None:
            if pg_ip:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        guard,
                        "python",
                        "-m",
                        "scripts.nvd_trial_network",
                        "--action",
                        "close",
                        "--pg",
                        pg_ip,
                    ],
                    capture_output=True,
                    timeout=5,
                )
            subprocess.run(["docker", "stop", "--time", "5", guard], capture_output=True)
        subprocess.run(["docker", "stop", "--time", "5", stack.name], capture_output=True)
        private_json(
            destination / "resources.json",
            {
                "postgres": stack.name,
                "worker": worker,
                "volume": stack.volume,
                "network": network if created_network else None,
                "stopped": True,
                "data_retained": True,
                "guard": guard if permit else None,
                "egress_network": egress if permit else None,
            },
        )


def create_plan(output):
    from app.integrations.nvd_lab_authorization import CVE_URL, PARAMS, canonical, validate_plan

    if run(["git", "-C", str(ROOT), "status", "--porcelain"]).strip():
        raise ValueError("Commit reviewed code before preparing a plan")
    commit = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
    image = json.loads(run(["docker", "image", "inspect", "vulntrack-backend:5c2-egress"]))[0]
    if image["Config"].get("Labels", {}).get("io.vulntrack.reviewed-commit") != commit:
        raise ValueError("Image must match reviewed commit")
    plan = {
        "version": "5c2-egress-1",
        "laboratory": "vulntrack-5c2-" + secrets.token_hex(6),
        "commit": commit,
        "image": image["Id"],
        "endpoint": CVE_URL,
        "method": "GET",
        "params": PARAMS,
        "requests": 1,
        "seconds": 20,
        "max_bytes": 2097152,
        "purpose": "first-isolated-nvd-cve-trial",
        "nonce": secrets.token_hex(16),
    }
    validate_plan(plan)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(plan))


def execute(args):
    from app.integrations import nvd_lab_authorization as policy

    if policy.TRUSTED_AUTHORITY_SHA256 is None:
        raise policy.denied()  # No file/DB/Docker/DNS I/O without trusted review.
    if not all([args.plan_file, args.authorization_record, args.catalogue_record]):
        raise policy.denied()
    if run(["git", "-C", str(ROOT), "status", "--porcelain"]).strip():
        raise policy.denied()
    commit = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
    image = json.loads(run(["docker", "image", "inspect", "vulntrack-backend:5c2-egress"]))[0]
    permit = policy.authorize(
        args.plan_file, args.authorization_record, commit=commit, image=image["Id"]
    )
    if image["Config"].get("Labels", {}).get("io.vulntrack.reviewed-commit") != commit:
        raise policy.denied()
    import fcntl

    directory = ROOT / ".local/nvd-trial-authorizations"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (directory / "operator.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Burn before setup/DNS; failures never rearm this approval, even when a
        # new destination is selected. Do not remove this ledger to retry.
        fd = os.open(directory / permit.plan["nonce"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        return launch(
            args.catalogue_record.resolve(),
            None,
            args.destination.resolve(),
            plan=args.plan_file.resolve(),
            grant=args.authorization_record.resolve(),
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalogue-record", type=Path)
    p.add_argument("--fixture", type=Path)
    p.add_argument("--destination", type=Path, required=True)
    p.add_argument("--mode", choices=["offline", "real"], default="offline")
    p.add_argument("--plan-real", type=Path, help="Write a review plan only; no permission or DNS")
    p.add_argument("--plan-file", type=Path)
    p.add_argument("--authorization-record", type=Path)
    p.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.child:
        if args.plan_file or args.authorization_record or args.mode == "real":
            from app.integrations.nvd_lab_authorization import denied

            raise denied()  # Internal public CLI cannot bypass the one-use ledger.
        child(args.destination.resolve())
    elif args.plan_real:
        create_plan(args.plan_real)
    elif args.mode == "real":
        execute(args)
    else:
        if not args.catalogue_record or not args.fixture:
            p.error("explicit public catalogue record and simulated fixture required")
        launch(args.catalogue_record.resolve(), args.fixture.resolve(), args.destination.resolve())


if __name__ == "__main__":
    main()
