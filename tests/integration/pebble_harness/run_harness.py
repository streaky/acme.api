"""Run the optional Pebble-backed integration harness."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
HARNESS_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.harness.yaml"
ENV_FILE = HARNESS_DIR / ".env.test"
PROJECT_NAME = "acme_api_pebble_harness"
PEBBLE_DIRECTORY_URL = "http://pebble:14000/directory"
PEBBLE_POLL_SERVICE = "acme-api-test"
CONTAINER_PYTHON = "python"
TEST_CONFIG = HARNESS_DIR / "acme.api.test-config.yaml"
TEST_TARGET = "tests/integration/test_e2e_lifecycle.py::test_full_certificate_lifecycle_with_webhooks"
RUNTIME_DIR = Path("/tmp/acme-api-pebble-harness")
RUNTIME_SUBDIRS = ("data", "certificates", "acmesh")

MAX_POLL_ATTEMPTS = 8
POLL_INTERVAL_SEC = 3.0
MAX_TEST_TIMEOUT_SEC = 900
TIMEOUT_EXIT_CODE = 124


def _compose_command(*args: str) -> list[str]:
    """Build a docker compose command for the harness project."""
    command = [
        "docker",
        "compose",
        "--project-name",
        PROJECT_NAME,
        "-f",
        str(COMPOSE_FILE),
    ]
    if ENV_FILE.exists():
        command.extend(["--env-file", str(ENV_FILE)])
    command.extend(args)
    return command


def _run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command from the repository root."""
    return subprocess.run(command, check=check, cwd=REPO_ROOT, text=True)


def _prepare_runtime_dir() -> None:
    """Create writable host directories for the harness bind mount."""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.chmod(0o777)
    for subdir in RUNTIME_SUBDIRS:
        directory = RUNTIME_DIR / subdir
        directory.mkdir(exist_ok=True)
        directory.chmod(0o777)


def _compose_up() -> None:
    """Pull and start the docker compose stack."""
    print("Bringing up Pebble harness compose stack...")
    try:
        _prepare_runtime_dir()
        _run_command(_compose_command("pull", "--quiet", "--ignore-buildable"))
        _run_command(_compose_command("up", "-d", "--build", "--force-recreate"))
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"compose up failed with exit code {exc.returncode}") from exc


def _poll_pebble_from_compose_network() -> bool:
    """Return whether Pebble is reachable from the API container network."""
    script = (
        "from urllib.request import urlopen; "
        f"urlopen({PEBBLE_DIRECTORY_URL!r}, timeout=5).close()"
    )
    command = _compose_command(
        "exec",
        "-T",
        PEBBLE_POLL_SERVICE,
        CONTAINER_PYTHON,
        "-c",
        script,
    )
    result = _run_command(command, check=False)
    return result.returncode == 0


def _health_poll() -> None:
    """Wait until Pebble's directory endpoint responds from the compose network."""
    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        if _poll_pebble_from_compose_network():
            print(f"Pebble ready on attempt {attempt}.")
            return
        print(
            f"Poll #{attempt}: Pebble not ready. "
            f"Retrying after {POLL_INTERVAL_SEC}s..."
        )
        time.sleep(POLL_INTERVAL_SEC)

    raise TimeoutError(
        f"Timed out waiting for {PEBBLE_DIRECTORY_URL} after "
        f"{MAX_POLL_ATTEMPTS} attempts."
    )


def _teardown() -> None:
    """Best-effort compose cleanup."""
    print("Tearing down Pebble harness...")
    try:
        _run_command(_compose_command("down", "-v", "--timeout", "1"), check=False)
    except OSError as exc:
        print(f"Teardown failed: {exc}")


def _run_pytest() -> int:
    """Run the harness pytest target and return its exit code."""
    command = [sys.executable, "-m", "pytest", TEST_TARGET]
    print(f"Running e2e ACME harness test; config={TEST_CONFIG} root={HARNESS_DIR}")
    try:
        result = subprocess.run(
            command,
            check=False,
            cwd=REPO_ROOT,
            text=True,
            timeout=MAX_TEST_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired as exc:
        print(f"Test phase timed out after {exc.timeout}s.")
        return TIMEOUT_EXIT_CODE
    except OSError as exc:
        print(f"Test phase failed: {exc}")
        return 1

    return result.returncode


def main() -> int:
    """Start Pebble, run the selected pytest target, and always clean up."""
    print("--- ACME harness start ---")
    exit_code = 1
    try:
        _compose_up()
        _health_poll()
        exit_code = _run_pytest()
    except (OSError, RuntimeError, TimeoutError) as exc:
        print(f"Fatal harness error: {exc}")
    finally:
        _teardown()

    print(f"--- ACME harness exit (rc={exit_code}) ---")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
