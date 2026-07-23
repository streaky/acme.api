"""Held DNS Persist request API contracts."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from acme_api.db import get_db
from acme_api.models.certificate import Certificate, CertificateStatus
from tests.unit.test_api_phase5 import _ArtifactBackend, _make_app


def test_held_dns_persist_requires_current_keyed_release(tmp_path: Path) -> None:
    """Held DNS Persist requests cannot issue until their current revision is released."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    app = _make_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, _ArtifactBackend)
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "held-example-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
                "held": True,
            },
        )
        assert created.status_code == 202
        held = created.json()
        assert held["status"] == "held"
        assert held["challenge"]["record_value"] == "persist-value-for-example.com"
        assert backend.issue_calls == 0

        authorization_ready = client.post(f"/v1/certificates/{held['id']}/authorize", headers=headers)
        assert authorization_ready.status_code == 202
        assert authorization_ready.json()["status"] == "authorization_ready"
        assert backend.issue_calls == 0

        stale = client.post(
            f"/v1/certificates/{held['id']}/release",
            headers={**headers, "Idempotency-Key": "release-1"},
            json={"revision": held["revision"]},
        )
        assert stale.status_code == 409
        assert backend.issue_calls == 0

        released = client.post(
            f"/v1/certificates/{held['id']}/release",
            headers={**headers, "Idempotency-Key": "release-1"},
            json={"revision": authorization_ready.json()["revision"]},
        )
        assert released.status_code == 202
        assert backend.issue_calls == 1

        repeated = client.post(
            f"/v1/certificates/{held['id']}/release",
            headers={**headers, "Idempotency-Key": "release-1"},
            json={"revision": authorization_ready.json()["revision"]},
        )
        assert repeated.status_code == 202
        assert backend.issue_calls == 1


def test_held_dns_persist_survives_restart_and_can_cancel(tmp_path: Path) -> None:
    """A persisted held request remains non-issuing across a service restart."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(_make_app(tmp_path)) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "restart-held-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
                "held": True,
            },
        )
        assert created.status_code == 202
        certificate_id = created.json()["id"]

    restarted = _make_app(tmp_path)
    backend = restarted.state.acme_backend
    assert isinstance(backend, _ArtifactBackend)
    with TestClient(restarted) as client:
        persisted = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert persisted.json()["status"] == "held"
        assert backend.issue_calls == 0
        cancelled = client.delete(f"/v1/certificates/{certificate_id}", headers=headers)
        assert cancelled.status_code == 204
        assert client.get(f"/v1/certificates/{certificate_id}", headers=headers).json()["status"] == "cancelled"


def test_restart_resumes_held_issuance_interrupted_after_claim(tmp_path: Path) -> None:
    """Startup resumes a released request that crashed after becoming issuing."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(_make_app(tmp_path)) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "interrupted-held-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
                "held": True,
            },
        )
        assert created.status_code == 202
        certificate_id = uuid.UUID(created.json()["id"])

        async def simulate_interrupted_issue() -> None:
            async with get_db() as session:
                certificate = await session.get(Certificate, certificate_id)
                assert certificate is not None
                certificate.status = CertificateStatus.ISSUING
                certificate.release_idempotency_key = "interrupted-release"
                await session.commit()

        asyncio.run(simulate_interrupted_issue())

    restarted = _make_app(tmp_path)
    backend = restarted.state.acme_backend
    assert isinstance(backend, _ArtifactBackend)
    with TestClient(restarted) as client:
        recovered = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert recovered.json()["status"] == "valid"
    assert backend.issue_calls == 1
