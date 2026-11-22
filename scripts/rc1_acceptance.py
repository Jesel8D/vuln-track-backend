"""Browser acceptance on an explicitly owned RC1 profile, never personal development."""

import argparse
import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from uuid import uuid4

from scripts.v2_development import ROOT, PersistentV2, private_json, process_identity

PROFILE = re.compile(r"rc3|(?:rc[12]|rc2-catalog(?:2[34])?)(?:-restore(?:-[0-9a-f]{8})?)?")


def guard(profile, config):
    if not PROFILE.fullmatch(profile) or config["profile"] != profile or config["phase"] != "ready":
        raise RuntimeError("An initialized RC1 profile is required")
    expected = "vulntrack_v2_" + profile.replace("-", "_") + "_pgdata"
    if config["volume"] != expected:
        raise RuntimeError("Only the exact RC1 volume is allowed")
    ports = [config[k] for k in ("pg_port", "api_port", "web_port")]
    if (
        any(type(p) is not int or not 1024 <= p <= 65535 for p in ports)
        or len(set(ports)) != 3
        or set(ports) & {55434, 8000, 5173}
        or (profile.startswith("rc2") and set(ports) & {55438, 8004, 5177})
    ):
        raise RuntimeError("RC1 ports must be separate from personal development")
    if profile == "rc3":
        if ports != [55450, 8016, 5189]:
            raise RuntimeError("RC3 requires its isolated profile ports")
    elif profile.startswith("rc2-catalog24"):
        expected_ports = [55449, 8015, 5188] if "-restore-" in profile else [55448, 8014, 5187]
        if ports != expected_ports:
            raise RuntimeError("RC2.4 requires its isolated catalog ports")
    elif profile.startswith("rc2-catalog23"):
        expected_ports = [55447, 8013, 5186] if "-restore-" in profile else [55446, 8012, 5185]
        if ports != expected_ports:
            raise RuntimeError("RC2.3 requires its isolated catalog ports")
    elif profile.startswith("rc2-catalog"):
        expected_ports = [55445, 8011, 5184] if "-restore-" in profile else [55444, 8010, 5183]
        if ports != expected_ports:
            raise RuntimeError("RC2.2 requires its isolated catalog ports")
    return {
        "profile": profile,
        "volume": expected,
        "api_url": f"http://127.0.0.1:{config['api_port']}",
        "web_url": f"http://127.0.0.1:{config['web_port']}",
        "fixture": True,
    }


def identity():
    return {"username": "rc1_demo_" + secrets.token_hex(6), "password": secrets.token_urlsafe(30)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="rc1")
    parser.add_argument("--phase", choices=("create", "resume", "restore"), default="create")
    parser.add_argument("--frontend", type=Path, default=ROOT.parent / "vuln-track-frontend")
    args = parser.parse_args()
    if not PROFILE.fullmatch(args.profile):
        parser.error("Expected an owned rc1, rc2 or rc2-catalog profile")
    if not (ROOT / ".local" / args.profile / "config.json").is_file():
        parser.error("Start the separate RC1 fixture profile first")
    stack = PersistentV2(args.profile)
    public = guard(args.profile, stack.config)
    stack.preflight()
    stack.verify()
    runtime = json.loads((stack.directory / "runtime.json").read_text())
    found = False
    for process in runtime["processes"]:
        pid = process["pid"]
        if process_identity(pid) != process["starttime"]:
            continue
        if (Path("/proc") / str(pid) / "cwd").resolve() != ROOT:
            continue
        env = dict(
            part.split(b"=", 1)
            for part in (Path("/proc") / str(pid) / "environ").read_bytes().split(b"\0")
            if b"=" in part
        )
        if (
            env.get(b"VULNTRACK_V2_PROFILE") == args.profile.encode()
            and env.get(b"VULNTRACK_V2_NVD_MODE") == b"fixture"
        ):
            found = True
    if not found:
        raise RuntimeError("Owned RC1 API must be running explicitly in fixture mode")
    primary = ROOT / ".local" / args.profile.split("-restore")[0]
    state_path = primary / "demo-access.json"
    if args.phase == "create":
        if state_path.exists():
            archive = primary / "acceptance-archives"
            archive.mkdir(mode=0o700, exist_ok=True)
            private_json(archive / (str(uuid4()) + ".json"), json.loads(state_path.read_text()))
        private_json(
            state_path,
            {"format": 1, "primary": identity(), "secondary": identity(), "dataset": None},
        )
    elif not state_path.is_file() or not json.loads(state_path.read_text()).get("dataset"):
        raise RuntimeError("A completed RC1 demonstration dataset is required")
    guard_path = stack.directory / "browser-guard.json"
    private_json(guard_path, public)
    frontend = args.frontend.resolve()
    if not (frontend / "node_modules").is_dir():
        raise RuntimeError("RC1 Frontend with npm ci required")
    environment = {
        k: v
        for k, v in os.environ.items()
        if k
        in {"PATH", "HOME", "USER", "LANG", "SHELL", "TERM", "TZ", "PLAYWRIGHT_CHROMIUM_EXECUTABLE"}
    }
    environment.update(
        RC1_GUARD_FILE=str(guard_path), RC1_STATE_FILE=str(state_path), RC1_PHASE=args.phase
    )
    result = subprocess.run(["npm", "run", "test:e2e:rc1"], cwd=frontend, env=environment)
    print("Browser acceptance completed; demo credentials remain in the private profile directory")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
