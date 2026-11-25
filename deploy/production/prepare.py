"""One-shot root permission setup for fresh named volumes; no network/database access."""

import os
import shutil
from pathlib import Path

for name in ("postgres", "catalog"):
    target = Path("/tls-" + name)
    target.mkdir(exist_ok=True)
    for file in ("server.crt", "server.key"):
        shutil.copyfile(Path("/run/bootstrap") / name / file, target / file)
        os.chown(target / file, 70, 70)
        (target / file).chmod(0o600)
for name in ("socket", "caddy-data", "caddy-config", "runtime"):
    path = Path("/" + name)
    os.chown(path, 10001, 10001)
    path.chmod(0o700)
source = Path("/run/bootstrap/api-settings.json")
if source.exists():
    dest = Path("/runtime/api-settings.json")
    shutil.copyfile(source, dest)
    os.chown(dest, 10001, 10001)
    dest.chmod(0o600)
print("PASS private volume permissions prepared")
