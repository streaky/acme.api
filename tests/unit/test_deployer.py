"""Tests for atomic certificate filesystem deployment."""

from __future__ import annotations

import json
import os
import pathlib
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from acme_api.backend.dataclasses import CertExpiry, IssuanceResult
from acme_api.deployer import (
    DeploymentError,
    DeploymentOptions,
    deploy_certificate_artifacts,
    deploy_issuance_result,
)


def _write_sources(tmp_path: pathlib.Path) -> CertExpiry:
    source_dir = tmp_path / "acmesh"
    source_dir.mkdir()
    files = {
        "cert.pem": b"server-cert\n",
        "chain.pem": b"ca-chain\n",
        "fullchain.pem": b"server-cert\nca-chain\n",
        "privkey.pem": b"private-key\n",
    }
    for file_name, content in files.items():
        (source_dir / file_name).write_bytes(content)

    return CertExpiry(
        cert_path=str(source_dir / "cert.pem"),
        chain_path=str(source_dir / "chain.pem"),
        fullchain_path=str(source_dir / "fullchain.pem"),
        privkey_path=str(source_dir / "privkey.pem"),
        expires_at=datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
    )


def _mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_deploy_issuance_result_writes_expected_layout(tmp_path: pathlib.Path) -> None:
    """Deployment writes all expected files under the primary domain."""
    cert = _write_sources(tmp_path)
    result = IssuanceResult(
        account_key_path="/acmesh/acct.key",
        cert=cert,
        domains=["example.com", "www.example.com"],
    )

    deployed = deploy_issuance_result(
        result,
        tmp_path / "certificates",
        options=DeploymentOptions(issuer="test-ca"),
    )

    assert deployed.directory == tmp_path / "certificates" / "example.com"
    assert deployed.cert_path.read_bytes() == b"server-cert\n"
    assert deployed.chain_path.read_bytes() == b"ca-chain\n"
    assert deployed.fullchain_path.read_bytes() == b"server-cert\nca-chain\n"
    assert deployed.privkey_path.read_bytes() == b"private-key\n"

    metadata = json.loads(deployed.metadata_path.read_text(encoding="utf-8"))
    assert metadata["primary_domain"] == "example.com"
    assert metadata["domains"] == ["example.com", "www.example.com"]
    assert metadata["issuer"] == "test-ca"
    assert metadata["expires_at"] == "2026-12-31T23:59:00+00:00"


def test_deploy_sets_certificate_and_key_permissions(tmp_path: pathlib.Path) -> None:
    """Certificate files are public-readable and private keys are restricted."""
    cert = _write_sources(tmp_path)

    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["secure.example.com"],
        deployment_root=tmp_path / "certificates",
    )

    assert _mode(deployed.cert_path) == 0o644
    assert _mode(deployed.chain_path) == 0o644
    assert _mode(deployed.fullchain_path) == 0o644
    assert _mode(deployed.metadata_path) == 0o644
    assert _mode(deployed.privkey_path) == 0o600


def test_deploy_sets_configured_artifact_group(tmp_path: pathlib.Path) -> None:
    """Deployment applies the configured consumer group before publication."""
    cert = _write_sources(tmp_path)

    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["group.example.com"],
        deployment_root=tmp_path / "certificates",
        permissions_key=0o640,
        artifact_group_id=os.getgid(),
    )

    deployed_artifacts: tuple[pathlib.Path, ...] = (
        deployed.cert_path,
        deployed.chain_path,
        deployed.fullchain_path,
        deployed.privkey_path,
        deployed.metadata_path,
    )
    assert all(path.stat().st_gid == os.getgid() for path in deployed_artifacts)
    assert _mode(deployed.privkey_path) == 0o640


def test_deploy_group_access_normalizes_root_and_target_directories_under_restrictive_umask(
    tmp_path: pathlib.Path,
) -> None:
    """Consumers can traverse shared deployment directories regardless of service umask."""
    cert = _write_sources(tmp_path)
    deployment_root = tmp_path / "certificates"
    original_umask = os.umask(0o077)
    try:
        deployed = deploy_certificate_artifacts(
            cert=cert,
            domains=["traversal.example.com"],
            deployment_root=deployment_root,
            permissions_key=0o640,
            artifact_group_id=os.getgid(),
        )
    finally:
        _ = os.umask(original_umask)

    assert deployment_root.stat().st_gid == os.getgid()
    assert deployed.directory.stat().st_gid == os.getgid()
    assert _mode(deployment_root) == 0o750
    assert _mode(deployed.directory) == 0o750
    assert _mode(deployed.privkey_path) == 0o640


def test_deploy_wraps_consumer_directory_access_failure(tmp_path: pathlib.Path) -> None:
    """Consumer-group ownership failures are recoverable deployment failures."""
    cert = _write_sources(tmp_path)

    with patch(
        "acme_api.deployer._configure_consumer_directories",
        side_effect=PermissionError("configured group is unavailable"),
    ):
        with pytest.raises(DeploymentError, match="configured group is unavailable"):
            _ = deploy_certificate_artifacts(
                cert=cert,
                domains=["unreadable.example.com"],
                deployment_root=tmp_path / "certificates",
                artifact_group_id=10001,
            )


def test_deploy_fsyncs_artifact_access_controls_after_applying_them(tmp_path: pathlib.Path) -> None:
    """Artifact file descriptors receive group and mode changes before their final sync."""
    cert = _write_sources(tmp_path)
    operations: list[str] = []

    def record(operation: str) -> Callable[..., None]:
        """Return an OS-call stand-in that records the operation name."""
        return lambda *_args: operations.append(operation)

    with (
        patch("acme_api.deployer.os.fchown", side_effect=record("fchown")),
        patch("acme_api.deployer.os.fchmod", side_effect=record("fchmod")),
        patch("acme_api.deployer.os.fsync", side_effect=record("fsync")),
    ):
        _ = deploy_certificate_artifacts(
            cert=cert,
            domains=["durable.example.com"],
            deployment_root=tmp_path / "certificates",
            artifact_group_id=os.getgid(),
        )

    assert operations[:15] == ["fchown", "fchmod", "fsync"] * 5


def test_wildcard_primary_domain_uses_safe_directory_name(tmp_path: pathlib.Path) -> None:
    """Wildcard domains are deployed to a portable directory name."""
    cert = _write_sources(tmp_path)

    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["*.example.com"],
        deployment_root=tmp_path / "certificates",
    )

    assert deployed.directory.name == "@wildcard@.example.com"


def test_wildcard_and_matching_literal_use_distinct_directories(tmp_path: pathlib.Path) -> None:
    """A wildcard certificate cannot overwrite its matching literal certificate."""
    cert = _write_sources(tmp_path)
    deployment_root = tmp_path / "certificates"

    literal = deploy_certificate_artifacts(
        cert=cert,
        domains=["wildcard.example.com"],
        deployment_root=deployment_root,
    )
    wildcard = deploy_certificate_artifacts(
        cert=cert,
        domains=["*.example.com"],
        deployment_root=deployment_root,
    )

    assert literal.directory.name == "wildcard.example.com"
    assert wildcard.directory.name == "@wildcard@.example.com"
    assert literal.directory != wildcard.directory
    assert literal.cert_path.is_file()
    assert wildcard.cert_path.is_file()


def test_missing_source_file_raises(tmp_path: pathlib.Path) -> None:
    """Deployment fails before writing when any source artifact is missing."""
    cert = _write_sources(tmp_path)
    pathlib.Path(cert.chain_path).unlink()

    with pytest.raises(DeploymentError, match="missing certificate source"):
        deploy_certificate_artifacts(
            cert=cert,
            domains=["example.com"],
            deployment_root=tmp_path / "certificates",
        )


def test_symlink_source_file_raises(tmp_path: pathlib.Path) -> None:
    """Deployment rejects symlinked source artifacts."""
    cert = _write_sources(tmp_path)
    cert_path = pathlib.Path(cert.cert_path)
    target_bytes = cert_path.read_bytes()
    cert_path.unlink()
    real_cert = cert_path.parent / "real-cert.pem"
    real_cert.write_bytes(target_bytes)
    cert_path.symlink_to(real_cert)

    with pytest.raises(DeploymentError, match="unsafe certificate source"):
        deploy_certificate_artifacts(
            cert=cert,
            domains=["example.com"],
            deployment_root=tmp_path / "certificates",
        )


def test_source_outside_allowed_root_raises(tmp_path: pathlib.Path) -> None:
    """Deployment rejects source artifacts resolved outside allowed roots."""
    cert = _write_sources(tmp_path)

    with pytest.raises(DeploymentError, match="outside allowed source roots"):
        deploy_certificate_artifacts(
            cert=cert,
            domains=["example.com"],
            deployment_root=tmp_path / "certificates",
            allowed_source_roots=[tmp_path / "other-root"],
        )


def test_unsafe_primary_domain_raises(tmp_path: pathlib.Path) -> None:
    """Primary domain must not escape the deployment root."""
    cert = _write_sources(tmp_path)

    with pytest.raises(DeploymentError, match="unsafe primary domain"):
        deploy_certificate_artifacts(
            cert=cert,
            domains=["../example.com"],
            deployment_root=tmp_path / "certificates",
        )


def test_failed_deploy_preserves_existing_files(tmp_path: pathlib.Path) -> None:
    """A write failure leaves previously deployed files untouched."""
    cert = _write_sources(tmp_path)
    deployment_root = tmp_path / "certificates"
    first = deploy_certificate_artifacts(
        cert=cert,
        domains=["example.com"],
        deployment_root=deployment_root,
    )
    first.cert_path.write_bytes(b"existing-cert\n")

    with patch("acme_api.deployer.os.replace", side_effect=OSError("boom")):
        with pytest.raises(DeploymentError, match="failed to deploy"):
            deploy_certificate_artifacts(
                cert=cert,
                domains=["example.com"],
                deployment_root=deployment_root,
            )

    assert first.cert_path.read_bytes() == b"existing-cert\n"
    assert not any(path.name.startswith(".deploy-") for path in first.directory.iterdir())


def test_custom_permissions_are_honored(tmp_path: pathlib.Path) -> None:
    """Deployment accepts configured certificate and key modes."""
    cert = _write_sources(tmp_path)

    deployed = deploy_certificate_artifacts(
        cert=cert,
        domains=["mode.example.com"],
        deployment_root=tmp_path / "certificates",
        permissions_cert=0o640,
        permissions_key=0o400,
    )

    assert _mode(deployed.cert_path) == 0o640
    assert _mode(deployed.privkey_path) == 0o400
