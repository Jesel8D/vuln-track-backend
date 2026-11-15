"""Version switch and rollback on NEW isolated persistent profiles only."""

import hashlib
import json
import os
import secrets
import subprocess

from scripts.v2_development import ROOT, PersistentV2


def main():
    home = ROOT.parents[1]
    previous = home / "VulnTrack/vuln-track-backend"
    phase1 = home / "VulnTrack-security-phase1/vuln-track-backend"
    expected = {
        previous: "fcabbe986f2a4d3dffb259edda0b7245e533ee91",
        phase1: "56c1274fdb4f48f7c2cb852c4975c8c0ec5bafff",
    }
    for path, commit in expected.items():
        actual = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
        ).strip()
        if (
            actual != commit
            or subprocess.check_output(
                ["git", "-C", str(path), "status", "--porcelain"], text=True
            ).strip()
        ):
            raise RuntimeError("Upgrade reference is not the verified clean version")
    # Exact migration/schema assets, not just a declaration of no SQL changes.
    for path in [previous, phase1]:
        for source in (ROOT / "alembic").rglob("*.py"):
            relative = source.relative_to(ROOT)
            if (
                hashlib.sha256(source.read_bytes()).digest()
                != hashlib.sha256((path / relative).read_bytes()).digest()
            ):
                raise RuntimeError("Migration sources changed; refuse downgrade assumption")
    nonce = secrets.token_hex(5)
    stack = PersistentV2("upgrade-" + nonce, pg_port=0, api_port=0, web_port=0)
    restored = PersistentV2("upgrade-restore-" + nonce, pg_port=0, api_port=0, web_port=0)
    data = {
        "credentials": {"username": "demo_upgrade_" + nonce, "password": secrets.token_urlsafe(28)}
    }

    def probe(path, *, phase1_expected, owned=stack):
        nonlocal data
        settings = owned.settings()
        environment = {
            **os.environ,
            "VULNTRACK_OWNED_UPGRADE_PROBE": stack.profile,
            "DATABASE_URL": settings.database_url.get_secret_value(),
            "TOKEN_SECRET": settings.token_secret.get_secret_value(),
            "WORKSPACE_HMAC_KEY": settings.workspace_hmac_key.get_secret_value(),
            "ENVIRONMENT": "test",
            "REGISTRATION_ENABLED": "true",
            "CVE_WORKER_ENABLED": "false",
        }
        data["expect_phase1"] = phase1_expected
        result = subprocess.run(
            [
                str(path / ".venv/bin/python"),
                "-c",
                "import runpy; runpy.run_path("
                + repr(str(ROOT / "scripts/phase2a_upgrade_probe.py"))
                + ", run_name='__main__')",
            ],
            cwd=path,
            env=environment,
            input=json.dumps(data),
            text=True,
            capture_output=True,
            timeout=60,
        )
        if result.returncode:
            # Diagnostics contain synthetic credentials only; keep private.
            out = ROOT / "api-tests/v2/.artifacts/phase2a/upgrade-probe.log"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(result.stderr)
            raise RuntimeError("Owned upgrade probe failed; no credentials printed")
        data = json.loads(result.stdout)

    try:
        stack.start_database()
        stack.bootstrap()
        probe(previous, phase1_expected=False)
        probe(phase1, phase1_expected=True)
        probe(ROOT, phase1_expected=True)
        probe(previous, phase1_expected=False)  # rollback, same IDs and unchanged target version
        archive = stack.backup()
        stack.stop_database()
        stack.start_database()
        stack.bootstrap()
        probe(ROOT, phase1_expected=True)
        restored.restore(archive)
        probe(previous, phase1_expected=False, owned=restored)
        stack.verify()
        restored.verify()
        report = {
            "result": "passed",
            "versions": [
                "stable fcabbe9",
                "phase1 56c1274",
                "phase2a working tree",
                "rollback fcabbe9",
            ],
            "checks": [
                "registration/login at each version",
                "workspace owner membership retained",
                "application/target IDs and declaration version retained",
                "A/B access denied",
                "runtime verification/scan remain disabled",
                "no new schema or migration sources",
                "owned database restart",
                "backup/restore into NEW volume",
                "rollback after restore",
            ],
            "source_volume": stack.volume,
            "restore_volume": restored.volume,
            "volumes_retained": True,
            "personal_database_used": False,
            "zap_executed": False,
        }
        out = ROOT / "api-tests/v2/.artifacts/phase2a/upgrade-results.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        for owned in [restored, stack]:
            if owned.check_owner("container", owned.name):
                owned.stop_database()


if __name__ == "__main__":
    main()
