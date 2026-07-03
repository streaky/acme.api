"""Fail when source files import modules that are intentionally unsupported."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

FORBIDDEN_IMPORTS = {
    "httpx": "Use httpx2; httpx is not a project dependency.",
}


def main() -> None:
    """Check Python files under the requested paths for forbidden imports."""
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", help="Files or directories to scan.")
    args = parser.parse_args()

    failures: list[str] = []
    for path_arg in args.paths:
        path = Path(path_arg)
        for source_path in _python_files(path):
            failures.extend(_check_file(source_path))

    if failures:
        raise SystemExit("\n".join(failures))


def _python_files(path: Path) -> list[Path]:
    """Return Python source files under a file or directory path."""
    if path.is_file() and path.suffix == ".py":
        return [path]
    if path.is_dir():
        return sorted(path.rglob("*.py"))
    return []


def _check_file(path: Path) -> list[str]:
    """Return formatted forbidden import failures for one source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    failures: list[str] = []

    for node in ast.walk(tree):
        for module_name in _imported_module_names(node):
            root_name = module_name.split(".", maxsplit=1)[0]
            reason = FORBIDDEN_IMPORTS.get(root_name)
            if reason is not None:
                failures.append(
                    f"{path}:{node.lineno}: forbidden import '{root_name}': {reason}"
                )

    return failures


def _imported_module_names(node: ast.AST) -> list[str]:
    """Return imported module names for import AST nodes."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.module is not None:
        return [node.module]
    return []


if __name__ == "__main__":
    main()
