"""Domain-model-agnostic return types for AcmeBackend Protocol."""

from __future__ import annotations

import dataclasses as _dc
import datetime as _dt


@_dc.dataclass(frozen=True)
class AccountInfo:
    """Registration info returned from acme.sh account operations.

    Attributes:
        key_path: Path to the ACME account private key on disk.
        email: Registered contact email address.
        server_url: The ACME CA endpoint used for registration.
    """

    key_path: str
    email: str
    server_url: str


@_dc.dataclass(frozen=True)
class CertExpiry:
    """Parsed expiry information from a certificate or acme.sh --renew output.

    Attributes:
        cert_path: Absolute path to the deployed PEM file (e.g., /acmesh/cert.pem).
        privkey_path: Absolute path to the private key PEM.
        chain_path: Absolute path to the CA chain PEM.
        fullchain_path: Absolute path to the concatenated cert+chain PEM.
        expires_at: UTC datetime when the certificate expires.
    """

    cert_path: str
    privkey_path: str
    chain_path: str
    fullchain_path: str
    expires_at: _dt.datetime


@_dc.dataclass(frozen=True)
class IssuanceResult:
    """Result of a successful certificate issuance/renewal operation.

    Attributes:
        account_key_path: Path to the acme.sh account private key used.
        cert: Parsed expiry and file layout information for the new certificate.
        domains: List of SANs that were issued (including primary).
        message: Human-readable summary or debug hint if non-empty.
    """

    account_key_path: str
    cert: CertExpiry
    domains: list[str]
    message: str = ""
