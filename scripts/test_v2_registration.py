"""Reproduce SQL, API, concurrency and RLS tests on an owned disposable cluster."""

import argparse
import os
import subprocess
import sys

from scripts.disposable_v2 import ROOT, DisposableV2

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", choices=["existing", "new"], default="existing")
    parser.add_argument("--full", action="store_true", help="Include existing V1/MVP regressions")
    options = parser.parse_args()
    with DisposableV2(options.installation) as stack:
        selection = [] if options.full else ["tests/integration/test_v2_registration.py"]
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *selection],
            cwd=ROOT,
            env={**os.environ, **stack.environment},
        )
    sys.exit(result.returncode)
