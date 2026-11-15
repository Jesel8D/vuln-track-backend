"""Regress former V2 defects on a NEW tmpfs cluster; historical evidence stays versioned."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.disposable_v2 import DisposableV2  # noqa: E402


def main():
    with DisposableV2(sql_checks=False) as stack:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", ("tests/integration/test_v2_stabilization.py")],
            cwd=ROOT,
            env={**os.environ, **stack.environment},
        )
    summary = {
        "result": "passed" if result.returncode == 0 else "failed",
        "suite": "tests/integration/test_v2_stabilization.py",
        "covers": [
            "additional workspace/replay/concurrency",
            "unchanged RLS isolation",
            "original AND applicability",
            "original full description and bounded title",
            "undetermined review and stale conflict",
        ],
        "historical_report": (
            "examples/known-issues.json is evidence from "
            "commit 6331564, not current expected behavior"
        ),
    }
    out = ROOT / "api-tests/v2/.artifacts/stabilization-regression.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
