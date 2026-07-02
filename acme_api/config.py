"""Runtime configuration loader.

Reads ``config.yaml`` and validates it against a Pydantic schema.
Path is taken from the ``ACME_API_CONFIG`` environment variable or falls back to
``./config.yaml`` in the working directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class StrictConfigModel(BaseModel):
    """Base config model that rejects unknown keys."""

    model_config = ConfigDict(extra="forbid")


class LogConfig(StrictConfigModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "text"] = "json"


class DatabaseConfig(StrictConfigModel):
    """SQLite database configuration."""

    url: str = "sqlite+aiosqlite:///./data/acme.db"
    pool_size: int = Field(default=5, ge=1)


class DeploymentConfig(StrictConfigModel):
    """Certificate filesystem deployment configuration."""

    directory: Path = Path("/certificates")
    permissions_cert: int = 0o644
    permissions_key: int = 0o600


class DnsProviderConfig(StrictConfigModel):
    """DNS provider alias configuration.

    Attributes:
        name: Human-readable alias (e.g. ``production``, ``staging``).
        provider_name: acme.sh DNS API name (e.g. ``cloudflare``).
        env_vars_file_path: Path to a file containing the DNS provider's
            environment variables / credentials.
    """

    name: str = Field(min_length=1)
    provider_name: str = Field(min_length=1)
    env_vars_file_path: Path


class AcmeAccountConfig(StrictConfigModel):
    """ACME account configuration.

    Attributes:
        name: Human-readable alias (e.g. ``letsencrypt-production``).
        server_url: ACME directory URL (e.g. Let's Encrypt prod/staging,
            ZeroSSL, Buypass).
        account_key_path: Filesystem path to the account key managed by
            acme.sh.  Defaults to a path inside the configured home_dir.
    """

    name: str = Field(min_length=1)
    server_url: str = Field(
        default="https://acme-v02.api.letsencrypt.org/directory", min_length=1
    )
    account_key_path: Path | None = None


class AcmeConfig(StrictConfigModel):
    """acme.sh binary and state directory configuration."""

    binary_path: str = "/usr/local/bin/acme.sh"
    home_dir: Path = Path("/acmesh")


class RenewalConfig(StrictConfigModel):
    """Automatic renewal scheduling configuration."""

    enabled: bool = True
    check_interval_hours: int = Field(default=24, ge=1)
    window_days: int = Field(default=30, ge=1)
    max_retries: int = Field(default=3, ge=0)


class AppSettings(StrictConfigModel):
    """Top-level application settings loaded from config.yaml.

    Attributes:
        log: Logging level and format.
        database: SQLite connection configuration.
        deployment: Where certificates are written on disk.
        acme: Path to the acme.sh binary and its state directory.
        renewal: Scheduling parameters for automatic renewals.
        dns_providers: Configured DNS provider aliases.
        acme_accounts: Configured ACME account references.
    """
    log: LogConfig = Field(default_factory=LogConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    acme: AcmeConfig = Field(default_factory=AcmeConfig)
    renewal: RenewalConfig = Field(default_factory=RenewalConfig)
    dns_providers: list[DnsProviderConfig] = Field(default_factory=list)
    acme_accounts: list[AcmeAccountConfig] = Field(default_factory=list)
    api_keys: dict[str, str] = Field(
        default_factory=dict,
        description="Bootstrap API keys for initial admin/operator/readonly access.",
    )

    def check(self) -> None:
        """Validate configuration at startup.

        Performs runtime checks that cannot be expressed with Pydantic field
        constraints alone (cross-field references, filesystem existence, etc.).

        Raises:
            ValueError: When required configuration is missing or invalid.
        """
        errors = []

        # v1 is SQLite-backed. Keep validation narrow until another database
        # backend is intentionally supported end to end.
        if not self.database.url.startswith("sqlite"):
            errors.append(
                f"database.url must start with 'sqlite', got: {self.database.url!r}"
            )

        # Deployment directory should exist. Creation is handled separately so
        # validation remains free of runtime side effects.
        if not self.deployment.directory.exists():
            errors.append(
                f"deployment.directory '{self.deployment.directory}' does not exist"
            )

        # ACME home directory should exist. Creation is handled separately so
        # validation remains free of runtime side effects.
        if not self.acme.home_dir.exists():
            errors.append(f"acme.home_dir '{self.acme.home_dir}' does not exist")

        # Check for duplicate DNS provider names
        provider_names = [p.name for p in self.dns_providers]
        if len(provider_names) != len(set(provider_names)):
            errors.append("dns_providers contains duplicate 'name' values")

        # Check for duplicate ACME account names
        account_names = [a.name for a in self.acme_accounts]
        if len(account_names) != len(set(account_names)):
            errors.append("acme_accounts contains duplicate 'name' values")

        # DNS provider env var files should exist (warn-only at startup;
        # hard-fail when first used). This is informational.
        for provider in self.dns_providers:
            if not provider.env_vars_file_path.exists():
                errors.append(
                    f"dns_provider '{provider.name}': env_vars_file_path "
                    f"'{provider.env_vars_file_path}' does not exist"
                )

        if errors:
            raise ValueError("\n".join(errors))


def prepare_runtime_paths(settings: AppSettings) -> None:
    """Create runtime directories required by the application."""
    settings.deployment.directory.mkdir(parents=True, exist_ok=True)
    settings.acme.home_dir.mkdir(parents=True, exist_ok=True)


def load_config(path: Path | None = None) -> AppSettings:
    """Load and validate configuration from a YAML file.

    Args:
        path: Override for the config file path.  Falls back to the
              ``ACME_API_CONFIG`` environment variable or ``./config.yaml``.

    Returns:
        A validated :class:`AppSettings` instance.

    Raises:
        FileNotFoundError: When no config file can be located.
        ValueError: When the YAML content fails schema validation.
    """
    if path is None:
        env_path = os.environ.get("ACME_API_CONFIG")
        if env_path:
            path = Path(env_path)
        else:
            path = Path("./config.yaml")

    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")

    with open(path, encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    return AppSettings(**raw)
