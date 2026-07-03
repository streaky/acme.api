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
    ISSUING = "issuing"
    VALID = "valid"
    RENEWING = "renewing"
    FAILED = "failed"
    REVOKED = "revoked"


CertificateKeyAlgorithm = Literal["ecdsa", "rsa-2048", "rsa-4096"]


class CertificateCreate(BaseModel):
    """Payload for creating a new certificate.

    Attributes:
        name: Human-readable label / alias for the certificate.
        domains: List of DNS names covered by this certificate.
        acme_account_ref: Alias referencing an ACME account in config.yaml.
        dns_provider_ref: Alias referencing a DNS provider in config.yaml.
        key_algorithm: Key algorithm (default ``ecdsa``).
    """

    name: str = Field(min_length=1, max_length=255)
    domains: list[str] = Field(min_length=1)
    acme_account_ref: str
    dns_provider_ref: str
    key_algorithm: CertificateKeyAlgorithm = "ecdsa"

    @field_validator("domains")
    @classmethod
    def _validate_domains(cls, v: list[str]) -> list[str]:
        """Each domain must be a valid DNS name or wildcard."""
        pattern = re.compile(
            r"^(?:\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        for domain in v:
            if not pattern.match(domain):
                raise ValueError(
                    f"Domain {domain!r} does not match a valid DNS label pattern."
                )
            normalized = domain[2:] if domain.startswith("*.") else domain
            if len(normalized) > _MAX_FQDN_LENGTH:
                raise ValueError(
                    f"Domain {domain!r} exceeds maximum length of {_MAX_FQDN_LENGTH} characters."
                )
        return v


class CertificateRead(BaseModel):
    """Full certificate representation returned by GET endpoints.

    Attributes:
        id: Unique identifier.
        name: Human-readable label / alias.
        domains: List of DNS names covered by this certificate.
        acme_account_ref: Alias referencing an ACME account in config.yaml.
        dns_provider_ref: Alias referencing a DNS provider in config.yaml.
        key_algorithm: Key algorithm used for the certificate key pair.
        expiry_date: UTC datetime when the certificate expires; ``None`` before issuance.
        status: Current lifecycle state of the certificate.
        created_at: Timestamp when the row was first inserted.
        updated_at: Timestamp of the most recent update to this row.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    domains: list[str]
    acme_account_ref: str
    dns_provider_ref: str
    key_algorithm: str
    expiry_date: datetime | None = None
    status: CertificateStatus
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
