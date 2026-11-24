"""Build the reviewed local image without network/package downloads or secrets."""

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build():
    commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    if subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"]).strip():
        raise ValueError("Commit reviewed code before building the release image")
    parent = ROOT / ".local"
    parent.mkdir(exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix="nvd-egress-build-", dir=parent))
    for name in ("app", "scripts"):
        shutil.copytree(
            ROOT / name, dest / name, ignore=shutil.ignore_patterns("__pycache__", ".local")
        )
    policy = dest / "trial-policy"
    policy.mkdir()
    authority = ROOT / "dev/nvd-trial/authority.pem"
    if authority.exists():
        if authority.is_symlink() or authority.stat().st_size > 4096:
            raise ValueError("Invalid public authority file")
        shutil.copyfile(authority, policy / "authority.pem")
    else:
        (policy / "authority.pem").write_text("NO AUTHORITY PROVISIONED\n")
    tools = dest / "netguard"
    (tools / "lib").mkdir(parents=True)
    (tools / "xtables").mkdir()
    manifest = {}

    def copy(src, target):
        shutil.copyfile(src, target)
        target.chmod(0o755 if target.parent == tools else 0o644)
        manifest[str(src)] = hashlib.sha256(target.read_bytes()).hexdigest()

    for name in ("iptables", "ip6tables"):
        copy(Path("/usr/sbin/" + name + "-legacy-restore"), tools / (name + "-restore"))
    for name in ("libxtables.so.12", "libip4tc.so.2", "libip6tc.so.2"):
        copy(Path("/lib/x86_64-linux-gnu") / name, tools / "lib" / name)
    for name in ("libxt_conntrack.so", "libxt_tcp.so", "libxt_standard.so", "libxt_time.so"):
        copy(Path("/usr/lib/x86_64-linux-gnu/xtables") / name, tools / "xtables" / name)
    for package in ("iptables", "libxtables12", "libip4tc2", "libip6tc2"):
        copy(Path("/usr/share/doc") / package / "copyright", tools / (package + "-copyright"))
    (tools / "host-tools.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copyfile(ROOT / "dev/nvd-trial/Dockerfile.egress", dest / "Dockerfile")
    subprocess.run(
        [
            "docker",
            "build",
            "--network",
            "none",
            "--pull=false",
            "--build-arg",
            "REVIEWED_COMMIT=" + commit,
            "-t",
            "vulntrack-backend:5c2-egress",
            str(dest),
        ],
        check=True,
    )


if __name__ == "__main__":
    build()
