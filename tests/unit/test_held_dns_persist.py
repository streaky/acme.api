"""Held DNS Persist request API contracts."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from acme_api.db import get_db
from acme_api.models.certificate import Certificate, CertificateStatus
from tests.helpers.api import ArtifactBackend, make_api_app


def test_held_dns_persist_requires_current_keyed_release(tmp_path: Path) -> None:
    """Held DNS Persist requests cannot issue until their current revision is released."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
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
    with TestClient(make_api_app(tmp_path)) as client:
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

    restarted = make_api_app(tmp_path)
    backend = restarted.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(restarted) as client:
        persisted = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert persisted.json()["status"] == "held"
        assert backend.issue_calls == 0
        cancelled = client.delete(f"/v1/certificates/{certificate_id}", headers=headers)
        assert cancelled.status_code == 204
        assert client.get(f"/v1/certificates/{certificate_id}", headers=headers).json()["status"] == "cancelled"
        repeated_cancel = client.delete(f"/v1/certificates/{certificate_id}", headers=headers)
        assert repeated_cancel.status_code == 204
        assert client.get(f"/v1/certificates/{certificate_id}", headers=headers).json()["status"] == "cancelled"
        duplicate = client.post(
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
        assert duplicate.status_code == 409
        assert backend.issue_calls == 0


def test_cancel_claimed_held_issuance_preserves_cancelled_state(tmp_path: Path) -> None:
    """A held release claimed for issuance remains a cancellation, not a revocation."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(make_api_app(tmp_path)) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "claimed-held-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
                "held": True,
            },
        )
        assert created.status_code == 202
        certificate_id = uuid.UUID(created.json()["id"])

        async def mark_claimed() -> None:
            async with get_db() as session:
                certificate = await session.get(Certificate, certificate_id)
                assert certificate is not None
                certificate.status = CertificateStatus.ISSUING
                certificate.release_idempotency_key = "claimed-release"
                await session.commit()

        asyncio.run(mark_claimed())
        cancelled = client.delete(f"/v1/certificates/{certificate_id}", headers=headers)
        assert cancelled.status_code == 204
        status_response = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert status_response.json()["status"] == "cancelled"


def test_cancelled_claimed_issuance_cannot_finalize_as_valid(tmp_path: Path) -> None:
    """A stale issuance worker cannot overwrite a held request cancellation."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "finalization-race-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
                "held": True,
            },
        )
        assert created.status_code == 202
        certificate_id = uuid.UUID(created.json()["id"])

        async def simulate_cancelled_finalization_race() -> None:
            async with get_db() as session:
                certificate = await session.get(Certificate, certificate_id)
                assert certificate is not None
                certificate.status = CertificateStatus.ISSUING
                certificate.release_idempotency_key = "race-release"
                await session.commit()

            started = asyncio.Event()
            continue_issuance = asyncio.Event()
            original_issue = backend.issue_certificate

            async def blocking_issue(
                domains: list[str],
                method: str,
                challenge_params: dict[str, object],
                account_key_path: str | None = None,
                server_url: str | None = None,
            ) -> object:
                started.set()
                await continue_issuance.wait()
                return await original_issue(domains, method, challenge_params, account_key_path, server_url)

            with patch.object(backend, "issue_certificate", new=blocking_issue):
                issuance = asyncio.create_task(
                    app.state.certificate_service.issue_dns_persist_certificate(certificate_id)
                )
                await started.wait()
                await app.state.certificate_service.revoke_certificate(certificate_id)
                continue_issuance.set()
                await issuance

        asyncio.run(simulate_cancelled_finalization_race())
        recovered = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert recovered.json()["status"] == "cancelled"


def test_cancelled_claimed_issuance_cannot_finalize_as_failed(tmp_path: Path) -> None:
    """A stale failed issuance cannot overwrite a held request cancellation."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "failed-finalization-race-cert",
                "domains": ["example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
                "held": True,
            },
        )
        assert created.status_code == 202
        certificate_id = uuid.UUID(created.json()["id"])

        async def simulate_cancelled_failure_race() -> None:
            async with get_db() as session:
                certificate = await session.get(Certificate, certificate_id)
                assert certificate is not None
                certificate.status = CertificateStatus.ISSUING
                certificate.release_idempotency_key = "failed-race-release"
                await session.commit()

            started = asyncio.Event()
            continue_issuance = asyncio.Event()
            original_issue = backend.issue_certificate

            async def blocking_issue(
                domains: list[str],
                method: str,
                challenge_params: dict[str, object],
                account_key_path: str | None = None,
                server_url: str | None = None,
            ) -> object:
                started.set()
                await continue_issuance.wait()
                return await original_issue(domains, method, challenge_params, account_key_path, server_url)

            with patch.object(backend, "issue_certificate", new=blocking_issue):
                issuance = asyncio.create_task(
                    app.state.certificate_service.issue_dns_persist_certificate(certificate_id)
                )
                await started.wait()
                await app.state.certificate_service.revoke_certificate(certificate_id)
                backend.fail_issues = True
                continue_issuance.set()
                await issuance

        asyncio.run(simulate_cancelled_failure_race())
        recovered = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert recovered.json()["status"] == "cancelled"


def test_restart_resumes_held_issuance_interrupted_after_claim(tmp_path: Path) -> None:
    """Startup resumes a released request that crashed after becoming issuing."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(make_api_app(tmp_path)) as client:
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

    restarted = make_api_app(tmp_path)
    backend = restarted.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(restarted) as client:
        recovered = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        for _ in range(19):
            if recovered.json()["status"] == "valid":
                break
            time.sleep(0.05)
            recovered = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert recovered.json()["status"] == "valid"
    assert backend.issue_calls == 1
