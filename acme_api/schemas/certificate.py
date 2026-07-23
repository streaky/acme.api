"""Certificate request and response schemas."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_MAX_FQDN_LENGTH = 253


class CertificateStatus(StrEnum):
    """Lifecycle states a certificate can occupy."""

    PENDING = "pending"
    PENDING_DNS = "pending_dns"
    HELD = "held"
    AUTHORIZATION_READY = "authorization_ready"
    RELEASED = "released"
    ISSUING = "issuing"
    VALID = "valid"
    RENEWING = "renewing"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REVOKED = "revoked"


CertificateKeyAlgorithm = Literal["ecdsa", "rsa-2048", "rsa-4096"]
ChallengeMethod = Literal["dns-01", "dns-persist"]


class CertificateCreate(BaseModel):
    """Payload for creating a certificate request.

    DNS Persist requests omit ``dns_provider_ref`` and return a stable, account-bound
    TXT instruction which must be retained for the certificate lifetime.
    """

    name: str = Field(min_length=1, max_length=255)
    domains: list[str] = Field(min_length=1)
    acme_account_ref: str
    challenge_method: ChallengeMethod = "dns-01"
    dns_provider_ref: str | None = None
    key_algorithm: CertificateKeyAlgorithm = "ecdsa"
    held: bool = False

    @field_validator("domains")
    @classmethod
    def _validate_domains(cls, domains: list[str]) -> list[str]:
        """Normalize and validate certificate domains while preserving the primary domain."""
        normalized_domains = [domain.strip().lower() for domain in domains]
        pattern = re.compile(r"^(?:\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
        for domain in normalized_domains:
            if not pattern.match(domain):
                raise ValueError(f"Domain {domain!r} does not match a valid DNS label pattern.")
            fqdn = domain[2:] if domain.startswith("*.") else domain
            if len(fqdn) > _MAX_FQDN_LENGTH:
                raise ValueError(f"Domain {domain!r} exceeds maximum length of {_MAX_FQDN_LENGTH} characters.")
        primary_domain = normalized_domains[0]
        return [primary_domain, *sorted(set(normalized_domains[1:]) - {primary_domain})]


class CertificateRelease(BaseModel):
    """Optimistic-concurrency input for releasing a held certificate request."""

    revision: int = Field(ge=1)


class DnsPersistChallenge(BaseModel):
    """One-time account-bound TXT record required by DNS Persist mode."""

    method: Literal["dns-persist"]
    record_type: Literal["TXT"]
    record_name: str
    record_value: str


class CertificateRead(BaseModel):
    """Full certificate representation returned by authenticated endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    domains: list[str]
    acme_account_ref: str
    dns_provider_ref: str | None = None
    challenge_method: ChallengeMethod = "dns-01"
    challenge: DnsPersistChallenge | None = None
    deployment_directory: str = Field(description="Artifact directory relative to the configured deployment root.")
    key_algorithm: str
    expiry_date: datetime | None = None
    status: CertificateStatus
    revision: int = 1
    created_at: datetime
    updated_at: datetime


class CertificateList(BaseModel):
    """Short form for list responses.

    Attributes:
        id: Unique identifier.
        name: Human-readable label / alias.
        domains: List of DNS names covered by this certificate.
        status: Current lifecycle state of the certificate.
        expiry_date: UTC datetime when the certificate expires; ``None`` before issuance.
    """

    id: uuid.UUID
    name: str
    domains: list[str]
    status: CertificateStatus
    expiry_date: datetime | None = None
