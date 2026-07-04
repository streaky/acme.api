"""End-to-end ACME harness for Pebble bring-up and health-poll checks."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


HARNESS_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = HARNESS_DIR / "docker-compose.test.yml"
TEST_CONFIG = HARNESS_DIR / "acme.api.test-config.yaml"
PEBBLE_DIR_URL = "http://pebble:14000/directory"

MAX_POLL_ATTEMPTS = 8
POLL_INTERVAL_SEC = 3.0
MAX_TEST_TIMEOUT_SEC = 900  # ~15 min wall-clock cap


def _health_poll() -> None:
    """Block until Pebble hits /directory; fail on timeout."""
    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        try:
            resp = urlopen(PEBBLE_DIR_URL)
            if resp.status == 200:
                print(f"Pebble ready on attempt {attempt}.")
                return
        except URLError as exc:
            msg = (
                f"Poll #{attempt}: not yet ready ({exc}). "
                f"Retrying after {POLL_INTERVAL_SEC}s..."
            )
            print(msg)
        time.sleep(POLL_INTERVAL_SEC)
    msg = (
        f"Timed out waiting for {PEBBLE_DIR_URL} "
        f"across {MAX_POLL_ATTEMPTS} attempts."
    )
    raise RuntimeError(msg)


def _compose_up() -> None:
    """Bring up the docker-compose stack detached."""
    print("Bringing up harness compose stack...")
    try:
        subprocess.check_call(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "pull",
                "--quiet",
            ],
        )
        subprocess.check_call(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "--env-file",
                ".env.test",
                "up",
                "-d",
                "--build",
                "--force-recreate",
            ],
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"compose up failed (rc={exc.returncode})") from exc


def _teardown() -> None:
    """Unconditionally clean the harness stack and logs."""
    print("Tearing down harness...")
    try:
        subprocess.run(
            [
                "docker",
                "compose",
                "-p", "pytest_harness",
                "-f", str(COMPOSE_FILE),
                "--env-file", ".env.test",
                "down",
                "-v", "--timeout", "1",
            ],
            check=True, capture_output=False, text=True,
        )
    except subprocess.CalledProcessError:  # noqa: SIM117 / best effort
        pass
    try:
        subprocess.run(
            [
                "docker",
                "compose",
                "-p", "_harness_tmp_local",
                "--env-file", ".env.test",
                "down",
                "-v",
            ],
            shell=False, stdout=None, stderr=subprocess.DEVNULL,
        )  # noqa: SIM117 / best effort
    except Exception as exc:  # noqa: BLE001 / best effort only
        print(f"Teardown (cleanup tmp) error {exc}")


def _run_pytest() -> int:
    """Invoke pytest bounded via subprocess timeout; return its exit code."""
    tests = ".".join([
        "tests", "integration",
        "test_e2e_lifecycle.py::TestE2ELifecycle"
        "::test_full_certificate_lifecycle_with_webhooks",
    ])
    cmd = [sys.executable, "-m", "pytest"] + tests.split(" ")
    print(f"Running e2e ACME harness test set; config={TEST_CONFIG} root={HARNESS_DIR}")  # noqa: E501
    try:
        result = subprocess.run(
            cmd, timeout=MAX_TEST_TIMEOUT_SEC, check=False, text=True,
        )
    except subprocess.TimeoutExpired as exc:  # noqa: FBT003 / bounded run
        print(f"Test phase timed out ({exc.timeout}s); tearing down.")
        return 124

    _teardown()
    return result.returncode


def main() -> int:
    """Entrypoint: compose up, poll, pytest, teardown."""
    print("--- ACME harness start ---")
    test_rc = 0
    try:
        _compose_up()
        try:
            _health_poll()
            test_rc = _run_pytest()
        finally:
            # Best-effort cleanup if any intermediate failure occurred.
            _teardown()
    except Exception as exc:  # noqa: BLE001 / fatal teardown path
        print(f"Fatal harness error {exc}; forced clean-up.")
        try:
            subprocess.run(  # best effort
                [
                    "docker",
                    "-f", str(COMPOSE_FILE),
                    "--env-file", ".env.test",
                    "down", "-v",
                ], check=False, stdout=subprocess.DEVNULL, text=True,
            )
        except Exception:  # noqa: BLE001 / best effort only
            pass

    print(f"--- ACME harness exit (rc={test_rc}) ---")
    return test_rc


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
