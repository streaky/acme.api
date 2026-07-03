"""Check per-file statement coverage from coverage.py JSON output."""

import argparse
import json
from pathlib import Path


def main() -> None:
    """Validate that every measured Python file meets the configured coverage floor."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--minimum", type=float, required=True)
    parser.add_argument("--coverage-json", type=Path, required=True)
    args = parser.parse_args()

    data = json.loads(args.coverage_json.read_text(encoding="utf-8"))
    failures: list[str] = []
    for file_name, file_data in data["files"].items():
        summary = file_data["summary"]
        if summary["num_statements"] == 0:
            continue
        percent = float(summary["percent_covered"])
        if percent < args.minimum:
            failures.append(f"{file_name}: {percent:.2f}% < {args.minimum:.2f}%")
    if failures:
        raise SystemExit("Per-file coverage check failed:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
