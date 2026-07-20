"""Check that no Python file exceeds the configured maximum line count."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Enforce per-file line limits.")
    parser.add_argument("--max-lines", type=int, required=True)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()

    offenders: list[str] = []
    for root_path in args.paths:
        p = Path(root_path)
        if p.is_file():
            files = [p]
        else:
            files = sorted(p.rglob("*.py"))
        for fpath in files:
            line_count = sum(1 for _ in fpath.read_text(encoding="utf-8").splitlines())
            if line_count > args.max_lines:
                offenders.append(f"{fpath}: {line_count} lines (max {args.max_lines})")

    if offenders:
        print("Max-lines check failed:")
        for msg in offenders:
            print(f"  {msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
