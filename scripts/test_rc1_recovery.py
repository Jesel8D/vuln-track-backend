"""Actual isolated RC1 restart, private backup, NEW-volume restore and browser checks."""

import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import time

import httpx

from scripts.rc1_acceptance import guard
from scripts.v2_development import ROOT, PersistentV2, private_json

ARTIFACTS = ROOT / "api-tests/v2/.artifacts/rc1"


def wait_ready(stack):
    public = guard(stack.profile, stack.config)
    with httpx.Client(trust_env=False, timeout=1) as client:
        for _ in range(160):
            try:
                if (
                    client.get(public["api_url"] + "/ready").status_code == 200
                    and client.get(public["web_url"]).status_code == 200
                ):
                    return public
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise RuntimeError("Owned RC1 readiness deadline")


def start(stack):
    stack.preflight()
    log = (stack.directory / "rc1-launcher.log").open("ab")
    os.chmod(stack.directory / "rc1-launcher.log", 0o600)
    env = {
        k: v
        for k, v in os.environ.items()
        if k in {"PATH", "HOME", "USER", "LANG", "SHELL", "TERM", "TZ"}
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "scripts.v2_development",
            "up",
            "--profile",
            stack.profile,
            "--frontend",
            str(ROOT.parent / "vuln-track-frontend"),
            "--nvd-mode",
            "fixture",
        ],
        cwd=ROOT,
        env=env,
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    log.close()
    wait_ready(stack)
    return process


def stop(stack):
    guard(stack.profile, stack.config)
    stack.preflight()
    stack.stop_processes()
    stack.stop_database()
    for _ in range(80):
        running = (stack.inspect("container", stack.name) or {}).get("State", {}).get("Running")
        runtime = json.loads((stack.directory / "runtime.json").read_text())
        if not running and not runtime["processes"]:
            return
        time.sleep(0.25)
    raise RuntimeError("Owned RC1 stop deadline")


def login(client, base, user):
    response = client.post(base + "/api/v1/auth/login", json=user)
    if response.status_code != 200:
        raise RuntimeError("Synthetic RC1 login failed")
    return "Bearer " + response.json()["access_token"]


def snapshot(client, base, data):
    token = login(client, base, data["primary"])
    headers = {"Authorization": token}
    expected = data["dataset"]
    root = base + f"/api/v2/workspaces/{data['workspace']}/applications"
    app = root + "/" + expected["application"]["id"]

    def read(path):
        response = client.get(path, headers=headers)
        if response.status_code != 200:
            raise RuntimeError("Owned RC1 snapshot resource unavailable")
        return response.json()

    actual = {
        "application": next(
            v for v in read(root)["items"] if v["id"] == expected["application"]["id"]
        ),
        "technology": next(
            v
            for v in read(app + "/technologies")["items"]
            if v["id"] == expected["technology"]["id"]
        ),
        "run": read(app + "/analyses/" + expected["run"]["id"]),
        "finding": next(
            v
            for v in read(app + "/analyses/" + expected["run"]["id"] + "/findings")["items"]
            if v["id"] == expected["finding"]["id"]
        ),
        "recommendation": next(
            v
            for v in read(app + "/findings/" + expected["finding"]["id"] + "/recommendations")[
                "items"
            ]
            if v["id"] == expected["recommendation"]["id"]
        ),
    }
    if any(actual[k] != expected[k] for k in actual):
        raise RuntimeError("RC1 durable DTO differs from the browser-created dataset")
    if (
        actual["finding"]["applicability"] != "undetermined"
        or actual["finding"]["status"] != "reviewed"
    ):
        raise RuntimeError("Conservative reviewed finding changed")
    second = login(client, base, data["secondary"])
    for _ in range(12):
        if client.get(app + "/technologies", headers={"Authorization": second}).status_code != 404:
            raise RuntimeError("RC1 foreign resource leaked")
        if client.get(app + "/technologies", headers=headers).status_code != 200:
            raise RuntimeError("RC1 own resource unavailable after pooled reuse")
    return token, hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest()


def browser(profile, phase):
    with (ARTIFACTS / ("browser-" + phase + ".log")).open("wb") as log:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.rc1_acceptance",
                "--profile",
                profile,
                "--phase",
                phase,
            ],
            cwd=ROOT,
            stdout=log,
            stderr=log,
        )
    if result.returncode:
        raise RuntimeError("Owned RC1 browser recovery check failed; see private log")


def main():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    result_path = ARTIFACTS / "recovery-results.json"
    result_path.unlink(missing_ok=True)
    data = json.loads((ROOT / ".local/rc1/demo-access.json").read_text())
    if not data.get("dataset") or not data.get("secondaryWorkspace"):
        raise RuntimeError("Complete RC1 browser A/C acceptance before recovery")
    stack = PersistentV2("rc1")
    original = wait_ready(stack)
    checks = []
    restored = None
    with httpx.Client(trust_env=False, timeout=8) as client:
        old_token, digest = snapshot(client, original["api_url"], data)
        checks.append(
            "browser-created application, CPE, run, reviewed finding and recommendation captured"
        )
        volume = stack.volume
        stop(stack)
        checks.append("RC1 API, web and database stopped without deleting their named volume")
        start(stack)
        stack.verify()
        _, after = snapshot(client, original["api_url"], data)
        assert digest == after and stack.volume == volume
        checks.append("exact IDs, states and dates survive full restart on the same RC1 volume")
        assert (
            client.get(
                original["api_url"] + "/api/v1/auth/me", headers={"Authorization": old_token}
            ).status_code
            == 200
        )
        checks.append("existing JWT remains valid after restart with the same private keys")
        browser("rc1", "resume")
        checks.append("existing-user browser journey succeeds after full restart")
        archive = stack.backup()
        manifest = json.loads(archive.with_name("manifest.json").read_text())
        assert manifest["source_volume"] == volume
        assert manifest["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
        assert stat.S_IMODE(archive.stat().st_mode) == 0o600
        assert (
            subprocess.run(["git", "check-ignore", "--quiet", str(archive)], cwd=ROOT).returncode
            == 0
        )
        checks.append(
            "sensitive RC1 backup checksum, private permissions and Git exclusion verified"
        )
        profile = "rc1-restore-" + secrets.token_hex(4)
        restored = PersistentV2(profile, pg_port=55439, api_port=8005, web_port=5178)
        try:
            assert restored.inspect("volume", restored.volume) is None
            restored.restore(archive)
            assert (
                restored.volume != volume and restored.volume != "vulntrack_v2_development_pgdata"
            )
            checks.append("backup restored transactionally into another NEW owned volume")
            restored.verify()
            checks.append(
                "restored core and verification schemas, RLS, roles and keys verified exactly"
            )
            start(restored)
            recovery = wait_ready(restored)
            _, restored_digest = snapshot(client, recovery["api_url"], data)
            assert restored_digest == digest
            checks.append(
                "restored IDs, CPE, analysis, review, recommendations and dates match original DTOs"
            )
            assert (
                client.get(
                    recovery["api_url"] + "/api/v1/auth/me", headers={"Authorization": old_token}
                ).status_code
                == 401
            )
            checks.append(
                "old JWT rejected on restored profile while normal password login succeeds"
            )
            checks.append("multiuser isolation and pooled connection reuse rechecked after restore")
            browser(profile, "restore")
            checks.append("existing-user browser journey succeeds against restored API and web")
        finally:
            if restored.config.get("phase") == "ready":
                stop(restored)
        checks.append(
            "restored services stopped; source RC1 remains ready and both volumes retained"
        )
        wait_ready(stack)
    report = {
        "result": "passed",
        "checks": checks,
        "source_volume": stack.volume,
        "restore_profile": restored.profile,
        "restore_volume": restored.volume,
        "backup_sha256": manifest["sha256"],
        "dataset_dto_sha256": digest,
        "backup_sensitive": True,
        "backup_published": False,
        "backup_relative_private_path": str(archive.relative_to(ROOT)),
        "personal_database_used": False,
        "source_rc1_running": True,
        "restore_stopped": True,
        "volumes_retained": True,
    }
    private_json(result_path, report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
