"""Live end-to-end tests against the Compose-native Pebble test stack.

Exercises provider-managed DNS-01 and manually-published DNS Persist workflows
over HTTP against the real ``acme.sh`` backend and Pebble. Both paths verify
that successful issuance atomically deploys certificate artifacts.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx2
import pytest

#: Must match ``api_keys.admin`` in acme.api.test-config.yaml.
API_KEY = "pebble-harness-admin-key"
BASE_URL = os.environ.get("PEBBLE_API_URL", "http://acme-api-test:8080")
RUNTIME_DIR = Path(os.environ.get("PEBBLE_RUNTIME_DIR", "/tmp/acme-api-pebble-harness"))
CHALLTESTSRV_URL = os.environ.get("PEBBLE_CHALLTESTSRV_URL", "http://pebble-challtestsrv:8055")

#: Resolved by challtestsrv inside the compose network; never leaves it.
TEST_DOMAIN = "harness-e2e.example.test"
PERSIST_TEST_DOMAIN = "*.persist-harness-e2e.example.test"
PERSIST_BASE_DOMAIN = PERSIST_TEST_DOMAIN.removeprefix("*.")

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


def test_provider_dns_workflow_issues_and_deploys_certificate() -> None:
    """Create -> automatic provider DNS-01 issue -> poll -> verify artifacts."""
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
        if final["status"] != "valid":
            events = client.get("/v1/events", params={"certificate_id": created["id"]})
            assert events.status_code == 200, events.text
            raise AssertionError(f"issuance failed: {final}; events: {events.json()}")

    assert final["status"] == "valid", f"issuance failed: {final}"
    assert final["expiry_date"] is not None

    deploy_dir = RUNTIME_DIR / "certificates" / TEST_DOMAIN
    for file_name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
        artifact = deploy_dir / file_name
        assert artifact.is_file(), f"missing deployed artifact: {artifact}"
    fullchain = (deploy_dir / "fullchain.pem").read_text()
    assert "-----BEGIN CERTIFICATE-----" in fullchain
    assert (deploy_dir / "metadata.json").is_file()


def test_dns_persist_workflow_issues_and_deploys_certificate() -> None:
    """Publish the returned persistent TXT value, authorize, then verify issuance."""
    with httpx2.Client(
        base_url=BASE_URL,
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=10.0,
    ) as client:
        _wait_for_health(client)
        response = client.post(
            "/v1/certificates",
            json={
                "name": f"pebble-persist-{uuid.uuid4().hex[:8]}",
                "domains": [PERSIST_TEST_DOMAIN],
                "acme_account_ref": "pebble-local",
                "challenge_method": "dns-persist",
            },
        )
        assert response.status_code == 202, response.text
        created = response.json()
        assert created["status"] == "pending_dns"
        challenge = created["challenge"]
        assert challenge["method"] == "dns-persist"
        assert challenge["record_type"] == "TXT"
        assert challenge["record_name"] == f"_validation-persist.{PERSIST_BASE_DOMAIN}"
        assert challenge["record_value"]

        published = httpx2.post(
            f"{CHALLTESTSRV_URL}/set-txt",
            json={"host": f"{challenge['record_name']}.", "value": challenge["record_value"]},
            timeout=10.0,
        )
        assert published.is_success, published.text

        authorized = client.post(f"/v1/certificates/{created['id']}/authorize")
        assert authorized.status_code == 202, authorized.text
        assert authorized.json()["status"] == "issuing"

        final = _poll_until_terminal(client, created["id"])
        if final["status"] != "valid":
            events = client.get("/v1/events", params={"certificate_id": created["id"]})
            assert events.status_code == 200, events.text
            raise AssertionError(f"DNS Persist issuance failed: {final}; events: {events.json()}")

    deploy_dir = RUNTIME_DIR / "certificates" / f"wildcard.{PERSIST_BASE_DOMAIN}"
    assert final["status"] == "valid"
    assert final["expiry_date"] is not None
    assert final["challenge"] == challenge
    for file_name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "metadata.json"):
        assert (deploy_dir / file_name).is_file()
