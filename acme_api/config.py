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
from pydantic import BaseModel, Field


class LogConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "text"] = "json"


class DatabaseConfig(BaseModel):
    """SQLite database configuration."""

    url: str = "sqlite+aiosqlite:///./data/acme.db"
    pool_size: int = Field(default=5, ge=1)


class DeploymentConfig(BaseModel):
    """Certificate filesystem deployment configuration."""

    directory: Path = Path("/certificates")
    permissions_cert: int = 0o644
    permissions_key: int = 0o600


class AcmeConfig(BaseModel):
    """acme.sh binary and state directory configuration."""

    binary_path: str = "/usr/local/bin/acme.sh"
    home_dir: Path = Path("/acmesh")


class RenewalConfig(BaseModel):
    """Automatic renewal scheduling configuration."""

    window_days: int = Field(default=30, ge=1)
    max_retries: int = Field(default=3, ge=0)


class AppSettings(BaseModel):
    """Top-level application settings loaded from config.yaml.

    Attributes:
        log: Logging level and format.
        database: SQLite connection configuration.
        deployment: Where certificates are written on disk.
        acme: Path to the acme.sh binary and its state directory.
        renewal: Scheduling parameters for automatic renewals.
    """

    log: LogConfig = Field(default_factory=LogConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    acme: AcmeConfig = Field(default_factory=AcmeConfig)
    renewal: RenewalConfig = Field(default_factory=RenewalConfig)


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

    raw: dict[str, Any] = {}
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

    return AppSettings(**raw)
