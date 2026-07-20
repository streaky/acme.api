"""Enforce a minimum coverage percentage for every measured source file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TypedDict, cast


class CoverageSummary(TypedDict):
    """Coverage values used by the per-file gate."""

    percent_covered: float


class FileCoverage(TypedDict):
    """Coverage report entry for one source file."""

    summary: CoverageSummary


class CoverageReport(TypedDict):
    """Subset of the Coverage.py JSON schema consumed here."""

    files: dict[str, FileCoverage]


def main() -> None:
    """Fail when any measured file falls below the requested percentage."""
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--minimum", type=float, default=80.0)
    arguments = parser.parse_args()

    with arguments.report.open(encoding="utf-8") as report_file:
        report = cast(CoverageReport, json.load(report_file))

    if not report["files"]:
        raise SystemExit("coverage report contains no measured files")

    failures = [
        (filename, coverage["summary"]["percent_covered"])
        for filename, coverage in sorted(report["files"].items())
        if coverage["summary"]["percent_covered"] < arguments.minimum
    ]
    if failures:
        details = "\n".join(f"  {filename}: {percentage:.2f}%" for filename, percentage in failures)
        raise SystemExit(f"files below the {arguments.minimum:.2f}% coverage minimum:\n{details}")

    print(f"all {len(report['files'])} measured files meet the {arguments.minimum:.2f}% coverage minimum")


if __name__ == "__main__":
    main()
