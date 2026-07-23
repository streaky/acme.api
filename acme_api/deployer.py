"""Atomic certificate artifact deployment."""

from __future__ import annotations

import dataclasses as dc
import hashlib
import json
import os
import shutil
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

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
    generation_id: str | None = None


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
class GenerationOptions:
    """Immutable-generation publication and retention settings."""

    enabled: bool = False
    retention_count: int | None = None
    retention_days: int | None = None


@dc.dataclass(frozen=True)
class DeploymentOptions:
    """Options that control certificate deployment behavior."""

    permissions_cert: int = 0o644
    permissions_key: int = 0o600
    artifact_group_id: int | None = None
    issuer: str | None = None
    allowed_source_roots: list[Path] | None = None
    generation: GenerationOptions = dc.field(default_factory=GenerationOptions)


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
        options=DeploymentOptions(
            permissions_cert=options.permissions_cert,
            permissions_key=options.permissions_key,
            artifact_group_id=options.artifact_group_id,
            allowed_source_roots=options.allowed_source_roots,
            generation=options.generation,
        ),
    )


def deploy_certificate_artifacts(
    *,
    cert: CertExpiry,
    domains: list[str],
    deployment_root: Path,
    metadata: DeploymentMetadata | None = None,
    options: DeploymentOptions | None = None,
) -> DeploymentPaths:
    """Deploy certificate artifacts, optionally as an immutable generation."""
    options = options or DeploymentOptions()
    generation = options.generation
    if generation.retention_count is not None and generation.retention_count < 1:
        raise DeploymentError("generation retention count must be at least one")
    if generation.retention_days is not None and generation.retention_days < 0:
        raise DeploymentError("generation retention days cannot be negative")
    temp_dir: Path | None = None
    try:
        deployment_root.mkdir(parents=True, exist_ok=True)
        _configure_consumer_directories(deployment_root, options.artifact_group_id)
        primary_domain = _primary_domain(domains)
        target_dir = deployment_root / deployment_directory_name(primary_domain)
        target_dir.mkdir(parents=True, exist_ok=True)
        _configure_consumer_directories(target_dir, options.artifact_group_id)
        source_paths = _source_paths(cert)
        _validate_source_files(source_paths, options.allowed_source_roots)
        metadata = metadata or _metadata_for_cert(cert, domains, primary_domain)
        if generation.enabled:
            return _deploy_generation(
                target_dir=target_dir,
                source_paths=source_paths,
                metadata=metadata,
                permissions_cert=options.permissions_cert,
                permissions_key=options.permissions_key,
                artifact_group_id=options.artifact_group_id,
                retention_count=generation.retention_count,
                retention_days=generation.retention_days,
            )
        temp_dir = Path(tempfile.mkdtemp(prefix=".deploy-", dir=target_dir))
        _write_temp_artifacts(
            temp_dir=temp_dir,
            source_paths=source_paths,
            metadata=metadata,
            permissions_cert=options.permissions_cert,
            permissions_key=options.permissions_key,
            artifact_group_id=options.artifact_group_id,
        )
        _fsync_directory(temp_dir)
        _replace_artifacts(temp_dir, target_dir)
        _fsync_directory(target_dir)
    except (OSError, OverflowError) as exc:
        raise DeploymentError(f"failed to deploy certificate artifacts: {exc}") from exc
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return _deployment_paths(target_dir)


# pylint: disable-next=too-many-arguments  # Atomic staging needs explicit artifact access controls.
def _write_temp_artifacts(
    *,
    temp_dir: Path,
    source_paths: dict[str, Path],
    metadata: DeploymentMetadata,
    permissions_cert: int,
    permissions_key: int,
    artifact_group_id: int | None,
) -> None:
    """Write all deployment artifacts into the temporary directory."""
    for file_name, source_path in source_paths.items():
        mode = permissions_key if file_name == PRIVKEY_FILE_NAME else permissions_cert
        _copy_fsync_chmod(source_path, temp_dir / f"{file_name}.tmp", mode, artifact_group_id)
    metadata_payload = metadata.to_json_dict()
    metadata_payload["fingerprint_sha256"] = hashlib.sha256(source_paths[CERT_FILE_NAME].read_bytes()).hexdigest()
    metadata_payload["subjects"] = metadata.domains
    metadata_bytes = json.dumps(metadata_payload, indent=2, sort_keys=True).encode("utf-8")
    _write_fsync_chmod(
        temp_dir / f"{METADATA_FILE_NAME}.tmp",
        metadata_bytes,
        permissions_cert,
        artifact_group_id,
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


def _deployment_paths(directory: Path, generation_id: str | None = None) -> DeploymentPaths:
    """Build the public artifact-path value for one deployment directory."""
    return DeploymentPaths(
        directory=directory,
        cert_path=directory / CERT_FILE_NAME,
        chain_path=directory / CHAIN_FILE_NAME,
        fullchain_path=directory / FULLCHAIN_FILE_NAME,
        privkey_path=directory / PRIVKEY_FILE_NAME,
        metadata_path=directory / METADATA_FILE_NAME,
        generation_id=generation_id,
    )


def _deploy_generation(  # pylint: disable=too-many-arguments
    *,
    target_dir: Path,
    source_paths: dict[str, Path],
    metadata: DeploymentMetadata,
    permissions_cert: int,
    permissions_key: int,
    artifact_group_id: int | None,
    retention_count: int | None,
    retention_days: int | None,
) -> DeploymentPaths:
    """Publish a complete immutable generation and atomically select it."""
    generations_dir = target_dir / "generations"
    generations_dir.mkdir(exist_ok=True)
    _configure_consumer_directories(generations_dir, artifact_group_id)
    generation_id = uuid4().hex
    staging_dir = Path(tempfile.mkdtemp(prefix=".generation-", dir=generations_dir))
    _configure_consumer_directories(staging_dir, artifact_group_id)
    generation_dir = generations_dir / generation_id
    try:
        _write_temp_artifacts(
            temp_dir=staging_dir,
            source_paths=source_paths,
            metadata=metadata,
            permissions_cert=permissions_cert,
            permissions_key=permissions_key,
            artifact_group_id=artifact_group_id,
        )
        _replace_artifacts(staging_dir, staging_dir)
        _fsync_directory(staging_dir)
        os.replace(staging_dir, generation_dir)
        _fsync_directory(generations_dir)
        _select_generation_directory(target_dir, generation_id)
        cleanup_generations(target_dir, retention_count=retention_count, retention_days=retention_days)
    except (OSError, OverflowError) as exc:
        raise DeploymentError(f"failed to publish certificate generation: {exc}") from exc
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
    return _deployment_paths(generation_dir, generation_id)


def select_generation(target_dir: Path, generation_id: str) -> DeploymentPaths:
    """Atomically make one retained generation current."""
    generation_dir = target_dir / "generations" / generation_id
    if not generation_dir.is_dir() or generation_id != Path(generation_id).name:
        raise DeploymentError(f"retained generation does not exist: {generation_id}")
    _select_generation_directory(target_dir, generation_id)
    return _deployment_paths(generation_dir, generation_id)


def pin_generation(target_dir: Path, generation_id: str) -> None:
    """Protect one retained generation from retention cleanup."""
    generation_dir = target_dir / "generations" / generation_id
    if not generation_dir.is_dir() or generation_id != Path(generation_id).name:
        raise DeploymentError(f"retained generation does not exist: {generation_id}")
    pinned_dir = target_dir / ".pinned-generations"
    pinned_dir.mkdir(exist_ok=True)
    (pinned_dir / generation_id).touch(exist_ok=True)
    _fsync_directory(pinned_dir)


def unpin_generation(target_dir: Path, generation_id: str) -> None:
    """Allow a previously pinned generation to become retention-eligible."""
    pinned_dir = target_dir / ".pinned-generations"
    pinned_path = pinned_dir / generation_id
    if pinned_path.exists():
        pinned_path.unlink()
        _fsync_directory(pinned_dir)


def _select_generation_directory(target_dir: Path, generation_id: str) -> None:
    """Swap the current symlink and compatibility links without partial artifacts."""
    current_link = target_dir / "current"
    pending_link = target_dir / ".current.pending"
    pending_link.unlink(missing_ok=True)
    pending_link.symlink_to(Path("generations") / generation_id)
    os.replace(pending_link, current_link)
    for filename in (CERT_FILE_NAME, CHAIN_FILE_NAME, FULLCHAIN_FILE_NAME, PRIVKEY_FILE_NAME, METADATA_FILE_NAME):
        compatibility_link = target_dir / filename
        if compatibility_link.exists() and not compatibility_link.is_symlink():
            compatibility_link.unlink()
        if not compatibility_link.exists():
            compatibility_link.symlink_to(Path("current") / filename)
    _fsync_directory(target_dir)


def cleanup_generations(
    target_dir: Path,
    *,
    retention_count: int | None,
    retention_days: int | None,
) -> list[str]:
    """Delete old unpinned generations while always retaining the selected one."""
    if retention_count is None and retention_days is None:
        return []
    generations_dir = target_dir / "generations"
    if not generations_dir.is_dir():
        return []
    current_id = os.readlink(target_dir / "current").split("/")[-1] if (target_dir / "current").is_symlink() else None
    pinned_dir = target_dir / ".pinned-generations"
    pinned_ids: set[str] = {path.name for path in pinned_dir.iterdir()} if pinned_dir.is_dir() else set()
    generations = sorted(
        (path for path in generations_dir.iterdir() if path.is_dir() and not path.name.startswith(".")),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
        reverse=True,
    )
    cutoff = datetime.now(UTC) - timedelta(days=retention_days) if retention_days is not None else None
    removed: list[str] = []
    for index, generation in enumerate(generations):
        exceeds_count = retention_count is None or index >= retention_count
        exceeds_age = cutoff is None or datetime.fromtimestamp(generation.stat().st_mtime, UTC) < cutoff
        if generation.name == current_id or generation.name in pinned_ids or not (exceeds_count and exceeds_age):
            continue
        shutil.rmtree(generation)
        removed.append(generation.name)
    if removed:
        _fsync_directory(generations_dir)
    return removed


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


def _copy_fsync_chmod(source: Path, destination: Path, mode: int, artifact_group_id: int | None) -> None:
    """Copy a source file to destination, flush it, fsync it, and apply access controls."""
    with source.open("rb") as src:
        _write_fsync_chmod(destination, src.read(), mode, artifact_group_id)


def _write_fsync_chmod(destination: Path, data: bytes, mode: int, artifact_group_id: int | None) -> None:
    """Write bytes durably to a destination path with the requested access controls."""
    with destination.open("wb") as file_handle:
        file_handle.write(data)
        file_handle.flush()
        file_descriptor = file_handle.fileno()
        if artifact_group_id is not None:
            os.fchown(file_descriptor, -1, artifact_group_id)
        os.fchmod(file_descriptor, mode)
        os.fsync(file_descriptor)


def _fsync_directory(directory: Path) -> None:
    """Flush directory metadata for POSIX filesystems."""
    flags = getattr(os, "O_DIRECTORY", 0)
    file_descriptor = os.open(directory, os.O_RDONLY | flags)
    try:
        os.fsync(file_descriptor)
    finally:
        os.close(file_descriptor)


def _configure_consumer_directories(directory: Path, artifact_group_id: int | None) -> None:
    """Give a configured consumer group traversal access to a deployment directory."""
    if artifact_group_id is None:
        return
    directory_status = directory.stat()
    group_changed = directory_status.st_gid != artifact_group_id
    if group_changed:
        os.chown(directory, -1, artifact_group_id)
    if group_changed or directory_status.st_uid == os.geteuid():
        os.chmod(directory, 0o750)
