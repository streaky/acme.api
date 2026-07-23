"""Pure certificate lifecycle utility functions."""

from __future__ import annotations

from acme_api.backend.acmesh_errors import AcmeShError, TransientAcmeShError
from acme_api.config import AcmeAccountConfig
from acme_api.services.certificate_contracts import CertificateLifecycleError


def dns_persist_scope(domains: list[str]) -> tuple[str, bool]:
    """Return the primary DNS Persist scope and wildcard policy."""
    scope = domains[0].removeprefix("*.")
    if any(
        domain.removeprefix("*.") != scope and not domain.removeprefix("*.").endswith(f".{scope}") for domain in domains
    ):
        raise CertificateLifecycleError(
            "DNS Persist SANs must be the primary domain or its subdomains; "
            "create separate requests for unrelated domains."
        )
    return scope, len(domains) > 1 or domains[0].startswith("*.")


def account_key_path(account: AcmeAccountConfig) -> str | None:
    """Return an optional configured account-key path."""
    return str(account.account_key_path) if account.account_key_path is not None else None


def error_category(error: Exception) -> str:
    """Classify issuance errors for event metadata."""
    if isinstance(error, TransientAcmeShError):
        return "transient"
    return "terminal" if isinstance(error, AcmeShError) else "deployment"
