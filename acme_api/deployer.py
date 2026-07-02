"""Atomic certificate artifact deployment."""

from __future__ import annotations

import dataclasses as dc
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from acme_api.backend.dataclasses import CertExpiry, IssuanceResult

CERT_FILE_NAME = "cert.pem"
CHAIN_FILE_NAME = "chain.pem"
FULLCHAIN_FILE_NAME = "fullchain.pem"
PRIVKEY_FILE_NAME = "privkey.pem"
METADATA_FILE_NAME = "metadata.json"


@dc.dataclass(frozen=True)
class DeploymentPaths:
    """Filesystem paths written for a deployed certificate."""

    directory: Path
    cert_path: Path
    chain_path: Path
    fullchain_path: Path
    privkey_path: Path
    metadata_path: Path


@dc.dataclass(frozen=True)
class DeploymentMetadata:
    """Metadata serialized next to deployed certificate files."""

    primary_domain: str
    domains: list[str]
    expires_at: datetime
    issuer: str | None = None
    source_cert_path: str | None = None
    source_chain_path: str | None = None
    source_fullchain_path: str | None = None

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable metadata dictionary."""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return {
            "primary_domain": self.primary_domain,
            "domains": self.domains,
            "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
            "issuer": self.issuer,
            "source_paths": {
                "cert": self.source_cert_path,
                "chain": self.source_chain_path,
                "fullchain": self.source_fullchain_path,
            },
        }


class DeploymentError(Exception):
    """Raised when certificate artifacts cannot be deployed safely."""


def deploy_issuance_result(
    result: IssuanceResult,
    deployment_root: Path,
    *,
    permissions_cert: int = 0o644,
    permissions_key: int = 0o600,
    issuer: str | None = None,
) -> DeploymentPaths:
    """Deploy files from an ACME issuance or renewal result.

    Args:
        result: Backend result containing source artifact paths and issued domains.
        deployment_root: Root directory such as ``/certificates``.
        permissions_cert: POSIX mode for public certificate artifacts.
        permissions_key: POSIX mode for the private key.
        issuer: Optional issuer string to include in metadata.

    Returns:
        Paths to the deployed certificate artifacts.

    Raises:
        DeploymentError: If domains are missing, unsafe, or source files are absent.
    """
    cert = result.cert
    metadata = DeploymentMetadata(
        primary_domain=_primary_domain(result.domains),
        domains=list(result.domains),
        expires_at=cert.expires_at,
        issuer=issuer,
        source_cert_path=cert.cert_path,
        source_chain_path=cert.chain_path,
        source_fullchain_path=cert.fullchain_path,
    )
    return deploy_certificate_artifacts(
        cert=cert,
        domains=result.domains,
        deployment_root=deployment_root,
        metadata=metadata,
        permissions_cert=permissions_cert,
        permissions_key=permissions_key,
    )


def deploy_certificate_artifacts(  # pylint: disable=too-many-arguments
    *,
    cert: CertExpiry,
    domains: list[str],
    deployment_root: Path,
    metadata: DeploymentMetadata | None = None,
    permissions_cert: int = 0o644,
    permissions_key: int = 0o600,
) -> DeploymentPaths:
    """Atomically deploy certificate files under the primary domain directory."""
    primary_domain = _primary_domain(domains)
    target_dir = deployment_root / _safe_domain_dir_name(primary_domain)
    target_dir.mkdir(parents=True, exist_ok=True)

    source_paths = {
        CERT_FILE_NAME: Path(cert.cert_path),
        CHAIN_FILE_NAME: Path(cert.chain_path),
        FULLCHAIN_FILE_NAME: Path(cert.fullchain_path),
        PRIVKEY_FILE_NAME: Path(cert.privkey_path),
    }
    _validate_source_files(source_paths)

    if metadata is None:
        metadata = DeploymentMetadata(
            primary_domain=primary_domain,
            domains=list(domains),
            expires_at=cert.expires_at,
            source_cert_path=cert.cert_path,
            source_chain_path=cert.chain_path,
            source_fullchain_path=cert.fullchain_path,
        )

    temp_dir = Path(tempfile.mkdtemp(prefix=".deploy-", dir=target_dir))
    try:
        for file_name, source_path in source_paths.items():
            mode = permissions_key if file_name == PRIVKEY_FILE_NAME else permissions_cert
            _copy_fsync_chmod(source_path, temp_dir / f"{file_name}.tmp", mode)

        metadata_bytes = json.dumps(
            metadata.to_json_dict(),
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        _write_fsync_chmod(
            temp_dir / f"{METADATA_FILE_NAME}.tmp",
            metadata_bytes,
            permissions_cert,
        )
        _fsync_directory(temp_dir)

        for file_name in (
            CERT_FILE_NAME,
            CHAIN_FILE_NAME,
            FULLCHAIN_FILE_NAME,
            PRIVKEY_FILE_NAME,
            METADATA_FILE_NAME,
        ):
            os.replace(temp_dir / f"{file_name}.tmp", target_dir / file_name)
        _fsync_directory(target_dir)
    except OSError as exc:
        raise DeploymentError(f"failed to deploy certificate artifacts: {exc}") from exc
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return DeploymentPaths(
        directory=target_dir,
        cert_path=target_dir / CERT_FILE_NAME,
        chain_path=target_dir / CHAIN_FILE_NAME,
        fullchain_path=target_dir / FULLCHAIN_FILE_NAME,
        privkey_path=target_dir / PRIVKEY_FILE_NAME,
        metadata_path=target_dir / METADATA_FILE_NAME,
    )


def _primary_domain(domains: list[str]) -> str:
    """Return the SAN primary domain."""
    if not domains:
        raise DeploymentError("at least one domain is required for deployment")
    return domains[0]


def _safe_domain_dir_name(domain: str) -> str:
    """Return a safe single path segment for a domain name."""
    if "/" in domain or "\\" in domain or domain in {"", ".", ".."}:
        raise DeploymentError(f"unsafe primary domain for deployment: {domain!r}")
    if domain.startswith("*."):
        return f"wildcard.{domain[2:]}"
    return domain


def _validate_source_files(source_paths: dict[str, Path]) -> None:
    """Ensure all source artifact paths exist and are regular files."""
    missing = [
        f"{name}: {path}"
        for name, path in source_paths.items()
        if not path.is_file()
    ]
    if missing:
        raise DeploymentError(
            "missing certificate source artifact(s): " + ", ".join(missing)
        )


def _copy_fsync_chmod(source: Path, destination: Path, mode: int) -> None:
    """Copy a source file to destination, flush it, fsync it, and chmod it."""
    with source.open("rb") as src:
        _write_fsync_chmod(destination, src.read(), mode)


def _write_fsync_chmod(destination: Path, data: bytes, mode: int) -> None:
    """Write bytes durably to a destination path with the requested mode."""
    with destination.open("wb") as file_handle:
        file_handle.write(data)
        file_handle.flush()
        os.fsync(file_handle.fileno())
    os.chmod(destination, mode)


def _fsync_directory(directory: Path) -> None:
    """Flush directory metadata for POSIX filesystems."""
    flags = getattr(os, "O_DIRECTORY", 0)
    fd = os.open(directory, os.O_RDONLY | flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
