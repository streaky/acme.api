"""Tests for Phase 5 REST API endpoints."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from acme_api.backend.acmesh_errors import TerminalAcmeShError, TransientAcmeShError
from tests.helpers.api import ArtifactBackend, make_api_app


def test_certificate_lifecycle_endpoints(tmp_path: Path) -> None:
    """Create, list, read, renew, and revoke a certificate."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(make_api_app(tmp_path)) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "example-cert",
                "domains": ["example.com", "www.example.com"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        assert created.status_code == 202
        body = created.json()
        assert body["status"] == "pending"

        certificate_id = body["id"]
        listed = client.get("/v1/certificates?domain=example.com", headers=headers)
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [certificate_id]

        detail = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["name"] == "example-cert"
        assert detail.json()["status"] == "valid"
        assert (tmp_path / "certs" / "example.com" / "fullchain.pem").is_file()

        renewed = client.post(f"/v1/certificates/{certificate_id}/renew", headers=headers)
        assert renewed.status_code == 202
        assert renewed.json()["status"] == "valid"

        deleted = client.delete(f"/v1/certificates/{certificate_id}", headers=headers)
        assert deleted.status_code == 204

        revoked = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert revoked.json()["status"] == "revoked"


def test_dns_persist_lifecycle_endpoints(tmp_path: Path) -> None:
    """DNS Persist requests wait for explicit authorization and retain instructions."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        payload = {
            "name": "manual-example-cert",
            "domains": ["Example.COM", "WWW.Example.COM", "api.EXAMPLE.com"],
            "acme_account_ref": "letsencrypt-production",
            "challenge_method": "dns-persist",
            "key_algorithm": "ecdsa",
        }
        created = client.post("/v1/certificates", headers=headers, json=payload)
        assert created.status_code == 202
        pending = created.json()
        assert pending["status"] == "pending_dns"
        assert pending["challenge"] == {
            "method": "dns-persist",
            "record_type": "TXT",
            "record_name": "_validation-persist.example.com",
            "record_value": "persist-value-for-example.com",
        }

        resumed_payload = {**payload, "domains": ["example.com", "api.example.com", "www.example.com"]}
        resumed = client.post("/v1/certificates", headers=headers, json=resumed_payload)
        assert resumed.status_code == 202
        assert resumed.json()["id"] == pending["id"]
        assert resumed.json()["challenge"] == pending["challenge"]

        authorized = client.post(f"/v1/certificates/{pending['id']}/authorize", headers=headers)
        assert authorized.json()["status"] == "issuing"
        issued = client.get(f"/v1/certificates/{pending['id']}", headers=headers)
        assert issued.json()["status"] == "valid"
        assert authorized.json()["challenge"] == pending["challenge"]

        renewed = client.post(f"/v1/certificates/{pending['id']}/renew", headers=headers)
        assert renewed.status_code == 202
        assert renewed.json()["status"] == "valid"

    assert backend.persist_value_requests == [("example.com", True)]


def test_dns_persist_recreation_of_revoked_request_conflicts(tmp_path: Path) -> None:
    """Revoked DNS Persist rows cannot be mistakenly resumed as active requests."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    payload = {
        "name": "revoked-manual-cert",
        "domains": ["example.com"],
        "acme_account_ref": "letsencrypt-production",
        "challenge_method": "dns-persist",
    }
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        created = client.post("/v1/certificates", headers=headers, json=payload)
        assert created.status_code == 202

        revoked = client.delete(f"/v1/certificates/{created.json()['id']}", headers=headers)
        assert revoked.status_code == 204

        recreated = client.post("/v1/certificates", headers=headers, json=payload)

    assert recreated.status_code == 409
    assert recreated.json()["detail"] == (
        "Certificate name, ACME account, and challenge method already identify another request."
    )
    assert backend.persist_value_requests == [("example.com", False)]


def test_dns_persist_value_generation_errors_are_controlled(tmp_path: Path) -> None:
    """DNS Persist setup reports backend failures without creating a request."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    payload = {
        "name": "manual-example-cert",
        "domains": ["example.com"],
        "acme_account_ref": "letsencrypt-production",
        "challenge_method": "dns-persist",
    }
    cases = (
        (TerminalAcmeShError("Could not parse DNS Persist value"), 422),
        (TransientAcmeShError("ACME server unavailable"), 503),
    )

    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    for error, expected_status in cases:
        backend.persist_value_error = error
        with TestClient(app) as client:
            response = client.post("/v1/certificates", headers=headers, json=payload)
            requests = client.get("/v1/certificates", headers=headers)

        assert response.status_code == expected_status
        assert response.json()["detail"] == f"Unable to generate DNS Persist instructions: {error}"
        assert requests.json() == []


def test_dns_persist_rejects_sans_outside_primary_scope(tmp_path: Path) -> None:
    """DNS Persist refuses SANs that a single returned TXT record cannot authorize."""
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        response = client.post(
            "/v1/certificates",
            headers={"Authorization": "Bearer operator-key-12345"},
            json={
                "name": "unrelated-manual-cert",
                "domains": ["www.example.com", "example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
            },
        )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "DNS Persist SANs must be the primary domain or its subdomains; create separate requests for unrelated domains."
    )
    assert not backend.persist_value_requests


def test_wildcard_dns_persist_uses_base_domain_policy(tmp_path: Path) -> None:
    """Wildcard requests publish one base-domain TXT record with wildcard policy."""
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    with TestClient(app) as client:
        response = client.post(
            "/v1/certificates",
            headers={"Authorization": "Bearer operator-key-12345"},
            json={
                "name": "wildcard-manual-cert",
                "domains": ["*.example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
            },
        )

    assert response.status_code == 202
    assert backend.persist_value_requests == [("example.com", True)]
    assert response.json()["challenge"]["record_name"] == "_validation-persist.example.com"

    assert response.json()["deployment_directory"] == "@wildcard@.example.com"


def test_dns_persist_dns_failure_can_be_authorized_again(tmp_path: Path) -> None:
    """A DNS error retains the durable instruction and allows an explicit retry."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    app = make_api_app(tmp_path)
    backend = app.state.acme_backend
    assert isinstance(backend, ArtifactBackend)
    backend.fail_issues = True
    with TestClient(app) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "retry-manual-cert",
                "domains": ["retry.example.com"],
                "acme_account_ref": "letsencrypt-production",
                "challenge_method": "dns-persist",
            },
        ).json()
        certificate_id = created["id"]
        challenge = created["challenge"]
        client.post(f"/v1/certificates/{certificate_id}/authorize", headers=headers)
        failed = client.get(f"/v1/certificates/{certificate_id}", headers=headers).json()
        assert failed["status"] == "failed"
        assert failed["challenge"] == challenge

        backend.fail_issues = False
        retried = client.post(f"/v1/certificates/{certificate_id}/authorize", headers=headers)
        assert retried.json()["status"] == "issuing"
        assert client.get(f"/v1/certificates/{certificate_id}", headers=headers).json()["status"] == "valid"


def test_dns_persist_request_survives_app_restart(tmp_path: Path) -> None:
    """Restarting the API resumes stored pending DNS state without a new order."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    payload = {
        "name": "restart-manual-cert",
        "domains": ["restart.example.com"],
        "acme_account_ref": "letsencrypt-production",
        "challenge_method": "dns-persist",
    }
    first_app = make_api_app(tmp_path)
    first_backend = first_app.state.acme_backend
    assert isinstance(first_backend, ArtifactBackend)
    with TestClient(first_app) as client:
        original = client.post("/v1/certificates", headers=headers, json=payload).json()
    assert first_backend.persist_value_calls == 1

    restarted_app = make_api_app(tmp_path)
    restarted_backend = restarted_app.state.acme_backend
    assert isinstance(restarted_backend, ArtifactBackend)
    with TestClient(restarted_app) as client:
        resumed = client.post("/v1/certificates", headers=headers, json=payload).json()
    assert resumed["id"] == original["id"]
    assert resumed["challenge"] == original["challenge"]
    assert restarted_backend.persist_value_calls == 0


def test_dns_persist_authorization_reports_invalid_requests(tmp_path: Path) -> None:
    """Authorization and account validation expose deliberate client errors."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(make_api_app(tmp_path)) as client:
        unknown_account = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "unknown-account-cert",
                "domains": ["unknown.example.com"],
                "acme_account_ref": "not-configured",
                "challenge_method": "dns-persist",
            },
        )
        assert unknown_account.status_code == 422
        assert client.post(f"/v1/certificates/{uuid.uuid4()}/authorize", headers=headers).status_code == 404

        normal = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "normal-cert",
                "domains": ["normal.example.com"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        assert normal.status_code == 202
        assert client.post(f"/v1/certificates/{normal.json()['id']}/authorize", headers=headers).status_code == 409


def test_config_and_events_endpoints(tmp_path: Path) -> None:
    """List config-owned integrations and audit events."""
    headers = {"Authorization": "Bearer readonly-key-12345"}
    operator_headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(make_api_app(tmp_path)) as client:
        assert client.get("/v1/accounts", headers=headers).json()[0]["name"] == ("letsencrypt-production")
        assert client.get("/v1/providers", headers=headers).json()[0]["name"] == ("cloudflare-main")
        client.post(
            "/v1/certificates",
            headers=operator_headers,
            json={
                "name": "event-cert",
                "domains": ["events.example.com"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )

        events = client.get("/v1/events?event_type=certificate.created", headers=headers)
        assert events.status_code == 200
        assert events.json()[0]["event_type"] == "certificate.created"


def test_admin_client_management_requires_admin_and_hides_hashes(tmp_path: Path) -> None:
    """Admins can manage all roles without exposing persisted credential hashes."""
    with TestClient(make_api_app(tmp_path)) as client:
        admin_headers = {"Authorization": "Bearer admin-key-12345"}
        assert client.get("/v1/admin/clients").status_code == 401
        assert (
            client.get("/v1/admin/clients", headers={"Authorization": "Bearer readonly-key-12345"}).status_code == 403
        )

        created = client.post(
            "/v1/admin/clients",
            headers=admin_headers,
            json={"name": "inventory", "role": "readonly"},
        )
        assert created.status_code == 201
        credential = created.json()["credential"]
        assert credential
        assert "hashed_key" not in created.json()
        assert "key_lookup_hash" not in created.json()

        client_id = created.json()["id"]
        listed = client.get("/v1/admin/clients", headers=admin_headers)
        assert listed.status_code == 200
        assert all("credential" not in item for item in listed.json())

        rotated = client.post(f"/v1/admin/clients/{client_id}/rotate", headers=admin_headers)
        assert rotated.status_code == 200
        assert rotated.json()["credential"] != credential

        revoked = client.post(f"/v1/admin/clients/{client_id}/revoke", headers=admin_headers)
        assert revoked.status_code == 200
        assert revoked.json()["is_active"] is False


def test_generation_selection_restores_a_retained_deployment(tmp_path: Path) -> None:
    """Operators can idempotently restore a retained immutable deployment."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(make_api_app(tmp_path, generation_aware=True)) as client:
        created = client.post(
            "/v1/certificates",
            headers=headers,
            json={
                "name": "generation-example",
                "domains": ["generation.example.com"],
                "acme_account_ref": "letsencrypt-production",
                "dns_provider_ref": "cloudflare-main",
            },
        )
        assert created.status_code == 202
        certificate_id = created.json()["id"]
        issued = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert issued.status_code == 200
        first = issued.json()["current_generation_id"]
        renewed = client.post(f"/v1/certificates/{certificate_id}/renew", headers=headers)
        assert renewed.status_code == 202
        renewed_read = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert renewed_read.status_code == 200
        second = renewed_read.json()["current_generation_id"]
        assert first != second

        selected = client.post(
            f"/v1/certificates/{certificate_id}/generations/select",
            headers={**headers, "Idempotency-Key": "select-first"},
            json={"generation_id": first},
        )
        assert selected.status_code == 200, selected.text
        assert selected.json()["current_generation_id"] == first
        assert selected.json()["current_generation_details"]["generation_id"] == first
        repeated = client.post(
            f"/v1/certificates/{certificate_id}/generations/select",
            headers={**headers, "Idempotency-Key": "select-first"},
            json={"generation_id": first},
        )
        assert repeated.status_code == 200
