"""Round-trip serialization and validation tests for Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from acme_api.schemas.certificate import (
    CertificateCreate,
    CertificateRead,
    CertificateStatus,
)
from acme_api.schemas.config_readonly import AcmeAccountRead, DnsProviderRead
from acme_api.schemas.event import EventCreate

# ── TestCertificateCreate ──────────────────────────────────────────────


class TestCertificateCreate:
    def test_valid_creation(self) -> None:
        cert = CertificateCreate(
            name="my-cert",
            domains=["example.com", "www.example.com"],
            acme_account_ref="letsencrypt-prod",
            dns_provider_ref="cloudflare",
            key_algorithm="ecdsa",
        )
        assert cert.name == "my-cert"
        assert cert.domains == ["example.com", "www.example.com"]
        assert cert.acme_account_ref == "letsencrypt-prod"
        assert cert.dns_provider_ref == "cloudflare"
        assert cert.key_algorithm == "ecdsa"

    def test_domains_are_normalized_and_secondary_order_is_deterministic(self) -> None:
        """Normalize equivalent DNS Persist domain identities without changing the primary."""
        first_request = CertificateCreate(
            name="my-cert",
            domains=[" Example.COM ", "WWW.Example.COM", "api.example.com", "www.example.com"],
            acme_account_ref="letsencrypt-staging",
            challenge_method="dns-persist",
        )
        resumed_request = CertificateCreate(
            name="my-cert",
            domains=["example.com", "api.example.com", "www.example.com"],
            acme_account_ref="letsencrypt-staging",
            challenge_method="dns-persist",
        )

        assert first_request.domains == ["example.com", "api.example.com", "www.example.com"]
        assert resumed_request.domains == first_request.domains

    def test_default_key_algorithm(self) -> None:
        """Default key_algorithm should be 'ecdsa' when omitted."""
        cert = CertificateCreate(
            name="my-cert",
            domains=["example.com"],
            acme_account_ref="acme-acc",
            dns_provider_ref="dns-prov",
        )
        assert cert.key_algorithm == "ecdsa"

    def test_rsa_key_algorithms(self) -> None:
        """Both rsa-2048 and rsa-4096 should be accepted."""
        for algo in ("rsa-2048", "rsa-4096"):
            cert = CertificateCreate(
                name="my-cert",
                domains=["example.com"],
                acme_account_ref="acme-acc",
                dns_provider_ref="dns-prov",
                key_algorithm=algo,
            )
            assert cert.key_algorithm == algo

    def test_domain_validation_rejects_bare_string(self) -> None:
        """A domain without a dot (e.g. 'notadomain') should fail validation."""
        with pytest.raises(ValueError, match=r"does not match a valid DNS label"):
            CertificateCreate(
                name="my-cert",
                domains=["notadomain"],
                acme_account_ref="acme-acc",
                dns_provider_ref="dns-prov",
            )

    def test_domain_validation_accepts_standard(self) -> None:
        """A standard FQDN like 'example.com' should pass validation."""
        cert = CertificateCreate(
            name="my-cert",
            domains=["example.com"],
            acme_account_ref="acme-acc",
            dns_provider_ref="dns-prov",
        )
        assert "example.com" in cert.domains

    def test_domain_validation_accepts_wildcard(self) -> None:
        """A wildcard domain like '*.example.com' should pass validation."""
        cert = CertificateCreate(
            name="my-cert",
            domains=["*.example.com"],
            acme_account_ref="acme-acc",
            dns_provider_ref="dns-prov",
        )
        assert "*.example.com" in cert.domains

    def test_domain_validation_rejects_overlong_fqdn(self) -> None:
        """Domains longer than RFC max length should fail validation."""
        too_long = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62])
        with pytest.raises(ValueError, match="exceeds maximum length"):
            CertificateCreate(
                name="my-cert",
                domains=[too_long],
                acme_account_ref="acme-acc",
                dns_provider_ref="dns-prov",
            )

    def test_empty_domains_raises(self) -> None:
        """An empty domains list should raise (min_length=1)."""
        with pytest.raises(ValueError):
            CertificateCreate(
                name="my-cert",
                domains=[],
                acme_account_ref="acme-acc",
                dns_provider_ref="dns-prov",
            )


# ── TestCertificateRead ────────────────────────────────────────────────


class TestCertificateRead:
    def test_from_attributes_roundtrip(self) -> None:
        """Build a dict of attributes and construct CertificateRead via model_validate."""
        now = datetime.now(UTC)
        data = {
            "id": uuid.uuid4(),
            "name": "round-trip-cert",
            "domains": ["example.com", "www.example.com"],
            "acme_account_ref": "letsencrypt-prod",
            "dns_provider_ref": "cloudflare",
            "key_algorithm": "ecdsa",
            "expiry_date": now.replace(year=now.year + 1),
            "status": CertificateStatus.PENDING,
            "deployment_directory": "example.com",
            "created_at": now,
            "updated_at": now,
        }

        cert = CertificateRead.model_validate(data)

        # All fields round-trip faithfully.
        assert cert.id == data["id"]
        assert cert.name == data["name"]
        assert cert.domains == data["domains"]
        assert cert.acme_account_ref == data["acme_account_ref"]
        assert cert.dns_provider_ref == data["dns_provider_ref"]
        assert cert.key_algorithm == data["key_algorithm"]
        assert cert.expiry_date == data["expiry_date"]
        assert cert.deployment_directory == data["deployment_directory"]
        assert cert.status == CertificateStatus.PENDING
        assert cert.created_at == now
        assert cert.updated_at == now

        # Serialize back to dict and verify no drift.
        serialized = cert.model_dump()
        assert serialized["name"] == "round-trip-cert"
        assert serialized["domains"] == ["example.com", "www.example.com"]
        assert serialized["status"] == CertificateStatus.PENDING


# ── TestEventCreate ────────────────────────────────────────────────────


class TestEventCreate:
    def test_valid_creation(self) -> None:
        evt = EventCreate(
            event_type="certificate.created",
            certificate_id=uuid.uuid4(),
            details={"foo": "bar"},
        )
        assert evt.event_type == "certificate.created"
        assert evt.details == {"foo": "bar"}

    def test_default_details(self) -> None:
        """Details should default to an empty dict when omitted."""
        evt = EventCreate(event_type="test.event")
        assert evt.details == {}


# ── TestAcmeAccountRead ────────────────────────────────────────────────


class TestAcmeAccountRead:
    def test_valid_creation(self) -> None:
        acct = AcmeAccountRead(
            name="letsencrypt-production",
            server_url="https://acme.v02.api.letsencrypt.org/directory",
        )
        assert acct.name == "letsencrypt-production"
        assert acct.server_url == "https://acme.v02.api.letsencrypt.org/directory"

        # Round-trip via model_dump / model_validate.
        data = acct.model_dump()
        round_tripped = AcmeAccountRead(**data)
        assert round_tripped.name == acct.name
        assert round_tripped.server_url == acct.server_url


# ── TestDnsProviderRead ────────────────────────────────────────────────


class TestDnsProviderRead:
    def test_valid_creation(self) -> None:
        prov = DnsProviderRead(
            name="production",
            provider_name="cloudflare",
        )
        assert prov.name == "production"
        assert prov.provider_name == "cloudflare"

        # Round-trip via model_dump / model_validate.
        data = prov.model_dump()
        round_tripped = DnsProviderRead(**data)
        assert round_tripped.name == prov.name
        assert round_tripped.provider_name == prov.provider_name
