"""Tests for Phase 5 REST API endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from acme_api.config import (
    AcmeAccountConfig,
    AcmeConfig,
    AppSettings,
    DatabaseConfig,
    DeploymentConfig,
    DnsProviderConfig,
)
from acme_api.main import create_app


def _make_app(tmp_path: Path) -> FastAPI:
    env_file = tmp_path / "cloudflare.env"
    env_file.write_text("CF_Token=test\n", encoding="utf-8")
    settings = AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path / "certs"),
        acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        dns_providers=[
            DnsProviderConfig(
                name="cloudflare-main",
                provider_name="cloudflare",
                env_vars_file_path=env_file,
            )
        ],
        acme_accounts=[AcmeAccountConfig(name="letsencrypt-production")],
        api_keys={
            "admin": "admin-key-12345",
            "operator": "operator-key-12345",
            "readonly": "readonly-key-12345",
        },
    )
    return create_app(settings=settings)


def test_certificate_lifecycle_endpoints(tmp_path: Path) -> None:
    """Create, list, read, renew, and revoke a certificate."""
    headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(_make_app(tmp_path)) as client:
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

        renewed = client.post(
            f"/v1/certificates/{certificate_id}/renew", headers=headers
        )
        assert renewed.status_code == 202
        assert renewed.json()["status"] == "renewing"

        deleted = client.delete(f"/v1/certificates/{certificate_id}", headers=headers)
        assert deleted.status_code == 204

        revoked = client.get(f"/v1/certificates/{certificate_id}", headers=headers)
        assert revoked.json()["status"] == "revoked"


def test_config_and_events_endpoints(tmp_path: Path) -> None:
    """List config-owned integrations and audit events."""
    headers = {"Authorization": "Bearer readonly-key-12345"}
    operator_headers = {"Authorization": "Bearer operator-key-12345"}
    with TestClient(_make_app(tmp_path)) as client:
        assert client.get("/v1/accounts", headers=headers).json()[0]["name"] == (
            "letsencrypt-production"
        )
        assert client.get("/v1/providers", headers=headers).json()[0]["name"] == (
            "cloudflare-main"
        )
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

        events = client.get(
            "/v1/events?event_type=certificate.created", headers=headers
        )
        assert events.status_code == 200
        assert events.json()[0]["event_type"] == "certificate.created"
