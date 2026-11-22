#!/usr/bin/env bash
# Copy pinned RC2.2 dependencies to an isolated, volatile WSL directory.
set -euo pipefail
umask 077
backend="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
root="$(dirname "$backend")"
previous="$(dirname "$root")/VulnTrack-RC2.2"
frontend="$root/vuln-track-frontend"
for path in "$backend/.venv" "$backend/api-tests/v2/node_modules" "$frontend/node_modules"; do
    if [[ -e "$path" && ! -L "$path" ]]; then
        echo "Existing real dependency directory requires no replacement: $path" >&2
        exit 1
    fi
done
if [[ -x "$backend/.venv/bin/python" && -x "$frontend/node_modules/.bin/vite" && \
    -d "$backend/api-tests/v2/node_modules/newman" ]] &&
    "$backend/.venv/bin/python" -c 'import ijson' 2>/dev/null; then
    exit 0
fi
deps="$(mktemp -d /dev/shm/vulntrack-rc23-deps.XXXXXXXX)"
mkdir -p "$deps/web-root/node_modules" "$deps/newman-root/node_modules"
cp -a "$previous/vuln-track-backend/.venv" "$deps/venv"
cp -a "$previous/vuln-track-frontend/node_modules/." "$deps/web-root/node_modules/"
cp -a "$previous/vuln-track-backend/api-tests/v2/node_modules/." "$deps/newman-root/node_modules/"
cd "$backend"
"$deps/venv/bin/python" -m pip install --no-cache-dir -q --no-deps -e .
"$deps/venv/bin/python" -m pip install --no-cache-dir -q -r requirements-cpe-feed.lock
"$deps/venv/bin/python" -m pip check
ln -sfn "$deps/venv" "$backend/.venv"
ln -sfn "$deps/web-root/node_modules" "$frontend/node_modules"
ln -sfn "$deps/newman-root/node_modules" "$backend/api-tests/v2/node_modules"
