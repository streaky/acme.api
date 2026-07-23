"""Regression coverage for immutable generation cleanup."""

from __future__ import annotations

import json
import pathlib
from datetime import UTC, datetime
from typing import cast

import pytest

from acme_api.backend.dataclasses import CertExpiry
from acme_api.deployer import (
    DeploymentError,
    DeploymentOptions,
    GenerationOptions,
    deploy_certificate_artifacts,
    select_generation,
)
from acme_api.services.deployment_generations import generation_details


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


@pytest.mark.parametrize("generation_id", [".", ".."])
def test_selection_rejects_dot_segment_generation_ids(tmp_path: pathlib.Path, generation_id: str) -> None:
    """Dot-segment input cannot replace the current compatibility pointer."""
    cert = _source_certificate(tmp_path)
    root = tmp_path / "certificates"
    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["selector.example.com"],
        deployment_root=root,
        options=DeploymentOptions(generation=GenerationOptions(enabled=True)),
    )

    with pytest.raises(DeploymentError, match="retained generation does not exist"):
        select_generation(root / "selector.example.com", generation_id)

    assert (root / "selector.example.com" / "current").resolve() == deployed.directory


def test_generation_deployment_atomically_migrates_legacy_compatibility_files(tmp_path: pathlib.Path) -> None:
    """Legacy artifact paths become current links through an immutable snapshot."""
    cert = _source_certificate(tmp_path)
    root = tmp_path / "certificates"
    legacy = deploy_certificate_artifacts(
        cert=cert,
        domains=["legacy.example.com"],
        deployment_root=root,
    )
    pathlib.Path(cert.fullchain_path).write_bytes(b"renewed-chain\n")
    legacy_metadata = cast(dict[str, object], json.loads(legacy.metadata_path.read_text(encoding="utf-8")))
    legacy_metadata.pop("fingerprint_sha256", None)
    legacy_metadata.pop("subjects", None)
    legacy.metadata_path.write_text(json.dumps(legacy_metadata), encoding="utf-8")
    legacy_bytes = legacy.fullchain_path.read_bytes()

    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["legacy.example.com"],
        deployment_root=root,
        options=DeploymentOptions(generation=GenerationOptions(enabled=True)),
    )

    target = root / "legacy.example.com"
    filenames = ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem")
    assert all((target / filename).is_symlink() for filename in filenames)
    legacy_ids = [path.name for path in (target / "generations").iterdir() if path.name.startswith("legacy-")]
    restored = select_generation(target, legacy_ids[0])
    assert restored.fullchain_path.read_bytes() == legacy_bytes
    details = generation_details(restored)
    assert details is not None
    assert details["subjects"] == ["legacy.example.com"]
    assert isinstance(details["fingerprint_sha256"], str)
    assert deployed.fullchain_path.read_bytes() == b"renewed-chain\n"
