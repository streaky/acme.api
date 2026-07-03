"""Read-only schemas for config-owned integrations."""

from __future__ import annotations

from pydantic import BaseModel


class AcmeAccountRead(BaseModel):
    """Read-only schema reflecting config.yaml acme_accounts entries.

    Accounts are admin-defined in configuration and surfaced as a read-only list
    so API consumers can reference them by name when creating certificates.

    Attributes:
        name: Human-readable alias (e.g. ``letsencrypt-production``).
        server_url: ACME directory URL for the account.
    """

    name: str
    server_url: str


class DnsProviderRead(BaseModel):
    """Read-only schema reflecting config.yaml dns_providers entries.

    DNS providers are admin-defined in configuration and surfaced as a read-only list
    so API consumers can reference them by name when creating certificates.

    Attributes:
        name: Human-readable alias (e.g. ``production``, ``staging``).
        provider_name: acme.sh DNS API name (e.g. ``cloudflare``).
    """

    name: str
    provider_name: str
