"""Certificate-authority revocation API contract tests."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import NoReturn
from unittest.mock import ANY, AsyncMock

import pytest
from fastapi.testclient import TestClient

from acme_api.backend.acmesh_errors import TerminalAcmeShError
from acme_api.deployer import DeploymentError
from acme_api.services import certificate_revocations
from tests.helpers.api import ArtifactBackend, make_api_app


def test_certificate_authority_revocation_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revoke one issued domain through the backend without changing local deployment."""
    headers = {"Authorization": "Bearer operator-key-12345", "Idempotency-Key": "revoke-once"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "revoke-authority-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
                "key_algorithm": "rsa-2048",
            },
        )
        certificate_id = created.json()["id"]
        dispatched = AsyncMock()
        monkeypatch.setattr(app.state.certificate_service, "_dispatch_webhook", dispatched)
        revoked = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers)
        repeated = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers)

    assert revoked.status_code == 200
    assert revoked.json()["status"] == "succeeded"
    assert revoked.json()["reason"] is None
    assert repeated.json()["id"] == revoked.json()["id"]
    assert backend.revocation.requests == [
        ("example.com", None, None, "https://acme-v02.api.letsencrypt.org/directory")
    ]
    assert backend.revocation.key_algorithms == ["rsa-2048"]
    dispatched.assert_awaited_once_with(ANY, "certificate.revoked_at_ca", ANY)


def test_certificate_authority_revocation_persists_terminal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep a terminal acme.sh revocation result durable and idempotent."""
    headers = {"Authorization": "Bearer operator-key-12345", "Idempotency-Key": "terminal-revoke"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    backend.revocation.error = TerminalAcmeShError("private-key-material-must-not-leak")
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "terminal-revoke-cert",
                "domains": ["example.net"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        certificate_id = created.json()["id"]
        dispatched = AsyncMock()
        monkeypatch.setattr(app.state.certificate_service, "_dispatch_webhook", dispatched)
        failed = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers, json={"reason": 4})
        repeated = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers, json={"reason": 4})

    assert failed.status_code == 200
    assert failed.json()["status"] == "failed"
    assert failed.json()["error_category"] == "terminal"
    assert repeated.json()["id"] == failed.json()["id"]
    assert failed.json()["error_details"] == "acme.sh reported a terminal revocation failure."
    assert len(backend.revocation.requests) == 1
    dispatched.assert_awaited_once_with(ANY, "certificate.revocation_failed", ANY)


def test_certificate_authority_revocation_persists_missing_account_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persist a missing configured ACME account as a terminal revocation failure."""
    headers = {"Authorization": "Bearer operator-key-12345", "Idempotency-Key": "missing-account"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "missing-account-revoke-cert",
                "domains": ["missing-account.example"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        certificate_id = created.json()["id"]

        def missing_account(_name: str) -> NoReturn:
            raise DeploymentError("ACME account not configured: letsencrypt-production")

        monkeypatch.setattr(app.state.certificate_service, "_acme_account", missing_account)
        failed = client.post(
            f"/v1/certificates/{certificate_id}/revoke",
            headers=headers,
            json={"reason": 1},
        )

    assert failed.status_code == 200
    assert failed.json()["status"] == "failed"
    assert failed.json()["error_category"] == "terminal"
    assert not backend.revocation.requests


def test_certificate_authority_revocation_resumes_expired_pending_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retry a request after a dead worker's revocation lease expires."""
    headers = {"Authorization": "Bearer operator-key-12345", "Idempotency-Key": "resume-pending"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    backend.revocation.error = RuntimeError("worker stopped after request persistence")
    with TestClient(app, raise_server_exceptions=False) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "resume-pending-revoke-cert",
                "domains": ["example.org"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        certificate_id = created.json()["id"]
        interrupted = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers, json={"reason": 5})
        backend.revocation.error = None
        in_progress = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers, json={"reason": 5})
        assert in_progress.status_code == 200
        assert in_progress.json()["status"] == "pending"
        assert len(backend.revocation.requests) == 1
        monkeypatch.setattr(certificate_revocations, "_REVOCATION_LEASE", timedelta())
        resumed = client.post(f"/v1/certificates/{certificate_id}/revoke", headers=headers, json={"reason": 5})

    assert interrupted.status_code == 500
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "succeeded"
    assert len(backend.revocation.requests) == 2
