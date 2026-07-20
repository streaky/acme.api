"""Regenerate or verify lock-derived requirement exports."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = (
    ("requirements.txt", ("--no-dev",)),
    ("requirements-dev.txt", ("--group", "dev")),
)


def run(*arguments: str) -> None:
    """Run a command from the repository root and require success."""
    subprocess.run(arguments, cwd=ROOT, check=True)


def export(output: Path, options: tuple[str, ...]) -> None:
    """Export one hashed requirements file from the committed lock."""
    run(
        "uv",
        "export",
        "--locked",
        *options,
        "--no-emit-project",
        "--format",
        "requirements.txt",
        "--output-file",
        str(output),
    )


def check() -> None:
    """Verify the lock and committed requirement exports agree."""
    run("uv", "lock", "--check")
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        temporary_root = Path(directory)
        stale: list[str] = []
        for filename, options in EXPORTS:
            generated = temporary_root / filename
            export(generated.relative_to(ROOT), options)
            committed = ROOT / filename
            if not committed.is_file():
                stale.append(filename)
                continue
            committed_body = committed.read_text(encoding="utf-8").splitlines(keepends=True)[2:]
            generated_body = generated.read_text(encoding="utf-8").splitlines(keepends=True)[2:]
            if committed_body != generated_body:
                stale.append(filename)
        if stale:
            raise SystemExit(f"lock-derived requirement exports are stale: {', '.join(stale)}")


def regenerate() -> None:
    """Regenerate both committed requirement exports from the lock."""
    run("uv", "lock", "--check")
    for filename, options in EXPORTS:
        export(Path(filename), options)


def main() -> None:
    """Dispatch the requested dependency operation."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "export"))
    arguments = parser.parse_args()
    if arguments.command == "check":
        check()
    else:
        regenerate()


if __name__ == "__main__":
    main()
