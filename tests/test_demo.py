from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_demo_runs_and_all_scenarios_pass() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "demo.py"), "--extended", "--no-audit"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=ROOT,
        env={"COLUMNS": "160", "PATH": ""},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "9/9 scenarios matched" in proc.stdout
