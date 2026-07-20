"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from acme_api.config import (
    AcmeAccountConfig,
    AcmeConfig,
    AppSettings,
    DatabaseConfig,
    DeploymentConfig,
    DnsProviderConfig,
    LogConfig,
    RenewalConfig,
    load_config,
    prepare_runtime_paths,
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
        assert cfg.enabled is True
        assert cfg.check_interval_hours == 24
        assert cfg.window_days == 30

    def test_custom_window(self) -> None:
        cfg = RenewalConfig(check_interval_hours=12, window_days=60, max_retries=5)
        assert cfg.check_interval_hours == 12
        assert cfg.window_days == 60
        assert cfg.max_retries == 5


class TestDnsProviderConfig:
    def test_creation(self) -> None:
        cfg = DnsProviderConfig(
            name="production",
            provider_name="cloudflare",
            env_vars_file_path=Path("/data/creds/cloudflare.env"),
        )
        assert cfg.name == "production"
        assert cfg.provider_name == "cloudflare"

    def test_empty_name_fails(self) -> None:
        with pytest.raises(ValueError):
            DnsProviderConfig(
                name="",
                provider_name="cloudflare",
                env_vars_file_path=Path("/data/env"),
            )


class TestAcmeAccountConfig:
    def test_defaults(self) -> None:
        cfg = AcmeAccountConfig(name="le-prod")
        assert cfg.name == "le-prod"
        assert cfg.server_url == "https://acme-v02.api.letsencrypt.org/directory"
        assert cfg.account_key_path is None

    def test_custom_server(self) -> None:
        cfg = AcmeAccountConfig(
            name="le-staging",
            server_url="https://acme-staging-v02.api.letsencrypt.org/directory",
        )
        assert cfg.server_url == "https://acme-staging-v02.api.letsencrypt.org/directory"

    def test_empty_name_fails(self) -> None:
        with pytest.raises(ValueError):
            AcmeAccountConfig(name="")


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
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        """Missing config paths fail fast."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nope.yaml")

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

    def test_unknown_key_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.yaml"
        with open(config_file, "w") as fh:
            yaml.dump({"renewal": {"renewal_window_days": 30}}, fh)

        with pytest.raises(ValueError, match="renewal_window_days"):
            load_config(config_file)

    def test_fallback_to_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as fh:
            yaml.dump({"renewal": {"window_days": 15}}, fh)

        # No env var set; cwd points to the file.
        monkeypatch.delenv("ACME_API_CONFIG", raising=False)
        cfg = load_config(path=config_file)
        assert cfg.renewal.window_days == 15


class TestAppSettingsValidate:
    def test_validate_passes_with_tmp_dirs(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        )
        # Should not raise
        prepare_runtime_paths(settings)
        settings.check()

    def test_prepare_runtime_paths_creates_dirs(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        )

        prepare_runtime_paths(settings)

        assert settings.deployment.directory.is_dir()
        assert settings.acme.home_dir.is_dir()

    def test_prepare_runtime_paths_creates_absolute_database_parent(self, tmp_path: Path) -> None:
        database_file = tmp_path / "database-parent" / "acme.db"
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{database_file}"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        )

        prepare_runtime_paths(settings)

        assert database_file.parent.is_dir()

    def test_validate_missing_runtime_dir(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "missing-certs"),
            acme=AcmeConfig(home_dir=tmp_path / "missing-acmesh"),
        )

        with pytest.raises(ValueError, match="deployment.directory"):
            settings.check()

    def test_validate_duplicate_dns_provider_names(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            dns_providers=[
                DnsProviderConfig(
                    name="dup",
                    provider_name="cf",
                    env_vars_file_path=tmp_path / "a.env",
                ),
                DnsProviderConfig(
                    name="dup",
                    provider_name="route53",
                    env_vars_file_path=tmp_path / "b.env",
                ),
            ],
        )
        prepare_runtime_paths(settings)
        with pytest.raises(ValueError, match="duplicate"):
            settings.check()

    def test_validate_duplicate_acme_account_names(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            acme_accounts=[
                AcmeAccountConfig(name="dup", server_url="https://a.com"),
                AcmeAccountConfig(name="dup", server_url="https://b.com"),
            ],
        )
        prepare_runtime_paths(settings)
        with pytest.raises(ValueError, match="duplicate"):
            settings.check()

    def test_validate_bad_database_url(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url="mysql://localhost/db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
        )
        prepare_runtime_paths(settings)
        with pytest.raises(ValueError, match="database.url"):
            settings.check()

    def test_validate_missing_env_vars_file(self, tmp_path: Path) -> None:
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            dns_providers=[
                DnsProviderConfig(
                    name="prod",
                    provider_name="cf",
                    env_vars_file_path=tmp_path / "missing.env",
                ),
            ],
        )
        prepare_runtime_paths(settings)
        with pytest.raises(ValueError, match="env_vars_file_path"):
            settings.check()
