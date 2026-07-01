"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from acme_api.config import (
    AcmeConfig,
    AppSettings,
    DatabaseConfig,
    DeploymentConfig,
    LogConfig,
    RenewalConfig,
    load_config,
)


class TestLogConfig:
    def test_defaults(self) -> None:
        cfg = LogConfig()
        assert cfg.level == "INFO"
        assert cfg.format == "json"

    def test_custom_level(self) -> None:
        cfg = LogConfig(level="DEBUG", format="text")
        assert cfg.level == "DEBUG"
        assert cfg.format == "text"


class TestDatabaseConfig:
    def test_defaults(self) -> None:
        cfg = DatabaseConfig()
        assert cfg.url == "sqlite+aiosqlite:///./data/acme.db"
        assert cfg.pool_size == 5


class TestDeploymentConfig:
    def test_defaults(self) -> None:
        cfg = DeploymentConfig()
        assert cfg.directory == Path("/certificates")

    def test_custom_directory(self) -> None:
        cfg = DeploymentConfig(directory=Path("/mnt/certs"))
        assert cfg.directory == Path("/mnt/certs")


class TestAcmeConfig:
    def test_defaults(self) -> None:
        cfg = AcmeConfig()
        assert cfg.binary_path == "/usr/local/bin/acme.sh"
        assert cfg.home_dir == Path("/acmesh")


class TestRenewalConfig:
    def test_defaults(self) -> None:
        cfg = RenewalConfig()
        assert cfg.window_days == 30

    def test_custom_window(self) -> None:
        cfg = RenewalConfig(window_days=60, max_retries=5)
        assert cfg.window_days == 60
        assert cfg.max_retries == 5


class TestAppSettings:
    def test_full_defaults(self) -> None:
        settings = AppSettings()
        assert settings.log.level == "INFO"
        assert settings.database.url == "sqlite+aiosqlite:///./data/acme.db"
        assert settings.deployment.directory == Path("/certificates")

    def test_partial_override(self) -> None:
        settings = AppSettings(log=LogConfig(level="DEBUG"))
        assert settings.log.level == "DEBUG"
        # Other defaults still apply.
        assert settings.database.url == "sqlite+aiosqlite:///./data/acme.db"


class TestLoadConfig:
    def test_missing_file_returns_defaults(self, tmp_path: Path) -> None:
        """When no config file exists at the given path, return schema defaults."""
        cfg = load_config(tmp_path / "nope.yaml")
        assert isinstance(cfg, AppSettings)

    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        data = {
            "log": {"level": "DEBUG"},
            "database": {"url": "sqlite+aiosqlite:///./test.db"},
        }
        with open(config_file, "w") as fh:
            yaml.dump(data, fh)

        cfg = load_config(config_file)
        assert cfg.log.level == "DEBUG"
        assert cfg.database.url == "sqlite+aiosqlite:///./test.db"

    def test_env_var_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_file = tmp_path / "env_config.yaml"
        with open(config_file, "w") as fh:
            yaml.dump({"renewal": {"window_days": 60}}, fh)

        monkeypatch.setenv("ACME_API_CONFIG", str(config_file))
        cfg = load_config()
        assert cfg.renewal.window_days == 60

    def test_empty_yaml(self, tmp_path: Path) -> None:
        """Empty YAML (None after safe_load) falls back to defaults."""
        config_file = tmp_path / "empty.yaml"
        with open(config_file, "w") as fh:
            fh.write("")
        cfg = load_config(config_file)
        assert isinstance(cfg, AppSettings)

    def test_invalid_log_level(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.yaml"
        with open(config_file, "w") as fh:
            yaml.dump({"log": {"level": "TRACE"}}, fh)

        with pytest.raises(ValueError):
            load_config(config_file)

    def test_fallback_to_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as fh:
            yaml.dump({"renewal": {"window_days": 15}}, fh)

        # No env var set; cwd points to the file.
        monkeypatch.delenv("ACME_API_CONFIG", raising=False)
        cfg = load_config(path=config_file)
        assert cfg.renewal.window_days == 15
