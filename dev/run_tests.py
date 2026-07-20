"""Run one test suite with explicit intentionally-empty semantics."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = ("unit", "integration", "e2e")
PYTEST_NO_TESTS_COLLECTED = 5


def main() -> None:
    """Run the selected suite and report intentional empty boundaries."""
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", choices=SUITES)
    arguments = parser.parse_args()
    result = subprocess.run(
        (sys.executable, "-m", "pytest", str(ROOT / "tests" / arguments.suite)),
        cwd=ROOT,
        check=False,
    )
    if result.returncode == PYTEST_NO_TESTS_COLLECTED and arguments.suite != "unit":
        print(f"{arguments.suite} suite is intentionally empty")
        return
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
