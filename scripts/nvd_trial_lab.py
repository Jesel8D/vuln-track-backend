"""Owned offline lab launcher: new source copy, PG volume, internal network, no public API."""

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


def launch(catalogue, fixture, destination):
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
    shutil.copyfile(fixture, destination / "fixture.json")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "PYTHONPATH": str(source),
        "DATABASE_V2_PATH": str(reference),
    }
    # Python environment belongs to the developer; no application secrets inherited.
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.nvd_trial_lab",
            "--child",
            "--destination",
            str(destination),
        ],
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


def child(destination):
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    from app.services.cpe_catalog import UPSERT, normalize, refresh_summary
    from scripts.v2_development import API_ROLE, PersistentV2, private_json

    nonce = secrets.token_hex(6)
    name = "vulntrack-5c1r-" + nonce
    stack = PersistentV2("rc3", pg_port=0, api_port=0, web_port=0)
    stack.config.update(project=name, container=name + "-postgres", volume=name + "-pgdata")
    stack.save()
    stack.name, stack.volume = stack.config["container"], stack.config["volume"]
    network, worker = name + "-internal", name + "-worker"
    created_network = False
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
        url = make_url(stack.url(API_ROLE)).set(host="postgres", port=5432)
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
        image = os.environ.get("TRIAL_IMAGE", "vulntrack-backend:5c1r-trial")
        run(
            [
                "docker",
                "run",
                "--name",
                worker,
                "--network",
                network,
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
                "--mount",
                f"type=bind,src={destination / 'fixture.json'},dst=/input/fixture.json,readonly",
                "--mount",
                f"type=bind,src={outputs},dst=/output",
                "--entrypoint",
                "python",
                image,
                "-m",
                "scripts.nvd_trial",
                "--mode",
                "offline",
                "--config",
                "/input/config.json",
                "--fixture",
                "/input/fixture.json",
                "--output",
                "/output",
            ],
            timeout=90,
        )
        info = json.loads(run(["docker", "inspect", worker]))[0]
        net = json.loads(run(["docker", "network", "inspect", network]))[0]
        assert net["Internal"] and not info["HostConfig"]["PortBindings"]
        assert set(info["NetworkSettings"]["Networks"]) == {network}
        result = json.loads((outputs / "rehearsal.json").read_text())
        result.update(
            container=worker,
            postgres=stack.name,
            volume=stack.volume,
            internal_network=True,
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
            },
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalogue-record", type=Path)
    p.add_argument("--fixture", type=Path)
    p.add_argument("--destination", type=Path, required=True)
    p.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.child:
        child(args.destination.resolve())
    else:
        if not args.catalogue_record or not args.fixture:
            p.error("explicit public catalogue record and simulated fixture required")
        launch(args.catalogue_record.resolve(), args.fixture.resolve(), args.destination.resolve())


if __name__ == "__main__":
    main()
