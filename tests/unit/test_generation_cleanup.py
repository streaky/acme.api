"""Regression coverage for immutable generation cleanup."""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime

import pytest

from acme_api.backend.dataclasses import CertExpiry
from acme_api.deployer import DeploymentOptions, GenerationOptions, deploy_certificate_artifacts


def _source_certificate(tmp_path: pathlib.Path) -> CertExpiry:
    source_dir = tmp_path / "acmesh"
    source_dir.mkdir()
    for name, content in {
        "cert.pem": b"server-cert\n",
        "chain.pem": b"ca-chain\n",
        "fullchain.pem": b"server-cert\nca-chain\n",
        "privkey.pem": b"private-key\n",
    }.items():
        (source_dir / name).write_bytes(content)
    return CertExpiry(
        cert_path=str(source_dir / "cert.pem"),
        chain_path=str(source_dir / "chain.pem"),
        fullchain_path=str(source_dir / "fullchain.pem"),
        privkey_path=str(source_dir / "privkey.pem"),
        expires_at=datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
    )


def test_generation_cleanup_failure_does_not_rollback_publication(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert = _source_certificate(tmp_path)
    root = tmp_path / "certificates"

    def fail_cleanup(*_: object, **_kwargs: object) -> list[str]:
        raise OSError("retention directory is unavailable")

    monkeypatch.setattr("acme_api.deployer.cleanup_generations", fail_cleanup)
    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["cleanup.example.com"],
        deployment_root=root,
        options=DeploymentOptions(generation=GenerationOptions(enabled=True, retention_count=1)),
    )

    target = root / "cleanup.example.com"
    assert (target / "current").resolve() == deployed.directory
    assert (target / "fullchain.pem").read_bytes() == deployed.fullchain_path.read_bytes()
