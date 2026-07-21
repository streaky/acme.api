"""Atomic certificate artifact deployment."""

from __future__ import annotations

import dataclasses as dc
import json
import os
import shutil
import stat
import tempfile
from datetime import UTC, datetime
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
            expires_at = expires_at.replace(tzinfo=UTC)
        return {
            "primary_domain": self.primary_domain,
            "domains": self.domains,
            "expires_at": expires_at.astimezone(UTC).isoformat(),
            "issuer": self.issuer,
            "source_paths": {
                "cert": self.source_cert_path,
                "chain": self.source_chain_path,
                "fullchain": self.source_fullchain_path,
            },
        }


@dc.dataclass(frozen=True)
class DeploymentOptions:
    """Options that control certificate deployment behavior."""

    permissions_cert: int = 0o644
    permissions_key: int = 0o600
    issuer: str | None = None
    allowed_source_roots: list[Path] | None = None


class DeploymentError(Exception):
    """Raised when certificate artifacts cannot be deployed safely."""


def deploy_issuance_result(
    result: IssuanceResult,
    deployment_root: Path,
    *,
    options: DeploymentOptions | None = None,
) -> DeploymentPaths:
    """Deploy files from an ACME issuance or renewal result.

    Args:
        result: Backend result containing source artifact paths and issued domains.
        deployment_root: Root directory such as ``/certificates``.
        options: Optional deployment behavior overrides.

    Returns:
        Paths to the deployed certificate artifacts.

    Raises:
        DeploymentError: If domains are missing, unsafe, or source files are absent.
    """
    options = options or DeploymentOptions()
    cert = result.cert
    metadata = DeploymentMetadata(
        primary_domain=_primary_domain(result.domains),
        domains=list(result.domains),
        expires_at=cert.expires_at,
        issuer=options.issuer,
        source_cert_path=cert.cert_path,
        source_chain_path=cert.chain_path,
        source_fullchain_path=cert.fullchain_path,
    )
    return deploy_certificate_artifacts(
        cert=cert,
        domains=result.domains,
        deployment_root=deployment_root,
        metadata=metadata,
        permissions_cert=options.permissions_cert,
        permissions_key=options.permissions_key,
        allowed_source_roots=options.allowed_source_roots,
    )


def deploy_certificate_artifacts(  # pylint: disable=too-many-arguments
    *,
    cert: CertExpiry,
    domains: list[str],
    deployment_root: Path,
    metadata: DeploymentMetadata | None = None,
    permissions_cert: int = 0o644,
    permissions_key: int = 0o600,
    allowed_source_roots: list[Path] | None = None,
) -> DeploymentPaths:
    """Atomically deploy certificate files under the primary domain directory."""
    primary_domain = _primary_domain(domains)
    target_dir = deployment_root / deployment_directory_name(primary_domain)
    target_dir.mkdir(parents=True, exist_ok=True)

    source_paths = _source_paths(cert)
    _validate_source_files(source_paths, allowed_source_roots)

    metadata = metadata or _metadata_for_cert(cert, domains, primary_domain)

    temp_dir = Path(tempfile.mkdtemp(prefix=".deploy-", dir=target_dir))
    try:
        _write_temp_artifacts(
            temp_dir=temp_dir,
            source_paths=source_paths,
            metadata=metadata,
            permissions_cert=permissions_cert,
            permissions_key=permissions_key,
        )
        _fsync_directory(temp_dir)

        _replace_artifacts(temp_dir, target_dir)
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


def _write_temp_artifacts(
    *,
    temp_dir: Path,
    source_paths: dict[str, Path],
    metadata: DeploymentMetadata,
    permissions_cert: int,
    permissions_key: int,
) -> None:
    """Write all deployment artifacts into the temporary directory."""
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


def _replace_artifacts(temp_dir: Path, target_dir: Path) -> None:
    """Atomically replace target artifacts with staged temporary files."""
    for file_name in (
        CERT_FILE_NAME,
        CHAIN_FILE_NAME,
        FULLCHAIN_FILE_NAME,
        PRIVKEY_FILE_NAME,
        METADATA_FILE_NAME,
    ):
        os.replace(temp_dir / f"{file_name}.tmp", target_dir / file_name)


def _source_paths(cert: CertExpiry) -> dict[str, Path]:
    """Return deployment destination names mapped to source artifact paths."""
    return {
        CERT_FILE_NAME: Path(cert.cert_path),
        CHAIN_FILE_NAME: Path(cert.chain_path),
        FULLCHAIN_FILE_NAME: Path(cert.fullchain_path),
        PRIVKEY_FILE_NAME: Path(cert.privkey_path),
    }


def _metadata_for_cert(
    cert: CertExpiry,
    domains: list[str],
    primary_domain: str,
) -> DeploymentMetadata:
    """Build default deployment metadata from certificate artifacts."""
    return DeploymentMetadata(
        primary_domain=primary_domain,
        domains=list(domains),
        expires_at=cert.expires_at,
        source_cert_path=cert.cert_path,
        source_chain_path=cert.chain_path,
        source_fullchain_path=cert.fullchain_path,
    )


def _primary_domain(domains: list[str]) -> str:
    """Return the SAN primary domain."""
    if not domains:
        raise DeploymentError("at least one domain is required for deployment")
    return domains[0]


def deployment_directory_name(primary_domain: str) -> str:
    """Return the collision-free deployment directory for a primary domain.

    Wildcards use an ``@wildcard@.`` prefix. ``@`` is not valid in a certificate
    DNS name, making the mapping distinct from every non-wildcard identifier.
    The returned value is relative to the configured deployment root.
    """
    if "/" in primary_domain or "\\" in primary_domain or primary_domain in {"", ".", ".."}:
        raise DeploymentError(f"unsafe primary domain for deployment: {primary_domain!r}")
    if primary_domain.startswith("*."):
        return f"@wildcard@.{primary_domain[2:]}"
    return primary_domain


def _validate_source_files(
    source_paths: dict[str, Path],
    allowed_source_roots: list[Path] | None = None,
) -> None:
    """Ensure all source artifact paths are safe regular files."""
    normalized_roots = [root.resolve() for root in (allowed_source_roots or [])]
    missing = [f"{name}: {path}" for name, path in source_paths.items() if not path.is_file()]
    if missing:
        raise DeploymentError("missing certificate source artifact(s): " + ", ".join(missing))

    unsafe: list[str] = []
    for name, path in source_paths.items():
        if path.is_symlink():
            unsafe.append(f"{name}: {path} (symlinks are not allowed)")
            continue

        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            unsafe.append(f"{name}: {path} (not a regular file)")
            continue

        if normalized_roots:
            resolved = path.resolve()
            if not any(resolved.is_relative_to(root) for root in normalized_roots):
                unsafe.append(f"{name}: {path} (outside allowed source roots)")

    if unsafe:
        raise DeploymentError("unsafe certificate source artifact(s): " + ", ".join(unsafe))


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
