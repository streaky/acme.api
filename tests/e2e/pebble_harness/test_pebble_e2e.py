"""Live end-to-end test against the Pebble-backed docker compose harness.

Exercises the real DNS Persist workflow over HTTP: create a certificate via
the API, let the real ``acme.sh`` backend complete a DNS-01 order against
Pebble (TXT records published to challtestsrv), then verify the certificate
reaches ``valid`` and its artifacts are atomically deployed on disk.

This module only runs when ``run_harness.py`` has brought the compose stack
up and set ``PEBBLE_HARNESS=1``; under normal test gates it is skipped.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx2
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("PEBBLE_HARNESS") != "1",
    reason="Requires the Pebble docker compose harness (run via make test-harness).",
)

#: Must match ``api_keys.admin`` in acme.api.test-config.yaml.
API_KEY = "pebble-harness-admin-key"
API_PORT = int(os.environ.get("HARNESS_API_PORT", "11980"))
BASE_URL = f"http://127.0.0.1:{API_PORT}"
RUNTIME_DIR = Path(os.environ.get("HARNESS_RUNTIME_DIR", "/tmp/acme-api-pebble-harness"))

#: Resolved by challtestsrv inside the compose network; never leaves it.
TEST_DOMAIN = "harness-e2e.example.test"

HEALTH_TIMEOUT_SEC = 120.0
ISSUANCE_TIMEOUT_SEC = 300.0
POLL_INTERVAL_SEC = 3.0

_TERMINAL_STATUSES = {"valid", "failed", "revoked"}


def _wait_for_health(client: httpx2.Client) -> None:
    """Block until the API container answers its health endpoint."""
    deadline = time.monotonic() + HEALTH_TIMEOUT_SEC
    last_error = "no attempt made"
    while time.monotonic() < deadline:
        try:
            response = client.get("/health")
            if response.status_code == 200:
                return
            last_error = f"HTTP {response.status_code}"
        except httpx2.HTTPError as exc:
            last_error = str(exc)
        time.sleep(POLL_INTERVAL_SEC)
    pytest.fail(f"API never became healthy at {BASE_URL}: {last_error}")


def _poll_until_terminal(client: httpx2.Client, certificate_id: str) -> dict[str, Any]:
    """Poll the certificate until issuance settles or the timeout elapses."""
    deadline = time.monotonic() + ISSUANCE_TIMEOUT_SEC
    body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/v1/certificates/{certificate_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        if body["status"] in _TERMINAL_STATUSES:
            return body
        time.sleep(POLL_INTERVAL_SEC)
    raise AssertionError(f"Certificate {certificate_id} still {body.get('status')!r} after {ISSUANCE_TIMEOUT_SEC}s")


def test_dns_persist_workflow_issues_and_deploys_certificate() -> None:
    """Create -> issue (real acme.sh vs Pebble) -> poll -> verify artifacts."""
    with httpx2.Client(
        base_url=BASE_URL,
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=10.0,
    ) as client:
        _wait_for_health(client)

        # Unique name per run: the harness runtime dir (and its SQLite DB)
        # survives across runs, and duplicate names are rejected with 409.
        name = f"pebble-harness-{uuid.uuid4().hex[:8]}"
        response = client.post(
            "/v1/certificates",
            json={
                "name": name,
                "domains": [TEST_DOMAIN],
                "acme_account_ref": "pebble-local",
                "dns_provider_ref": "challtestsrv",
            },
        )
        assert response.status_code == 202, response.text
        created = response.json()
        assert created["status"] == "pending"
        assert created["domains"] == [TEST_DOMAIN]

        final = _poll_until_terminal(client, created["id"])

    assert final["status"] == "valid", f"issuance failed: {final}"
    assert final["expiry_date"] is not None

    deploy_dir = RUNTIME_DIR / "certificates" / TEST_DOMAIN
    for file_name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
        artifact = deploy_dir / file_name
        assert artifact.is_file(), f"missing deployed artifact: {artifact}"
    fullchain = (deploy_dir / "fullchain.pem").read_text()
    assert "-----BEGIN CERTIFICATE-----" in fullchain
    assert (deploy_dir / "metadata.json").is_file()
