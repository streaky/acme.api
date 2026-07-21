"""acme.sh subprocess wrapper — concrete AcmeBackend implementation."""

from __future__ import annotations

import asyncio
import dataclasses as _dc
import logging
import os
import pathlib
import re
import shlex
import typing as t
from functools import cached_property

from acme_api.backend.acmesh_errors import (
    AcmeShError,
    TerminalAcmeShError,
    TransientAcmeShError,
)
from acme_api.backend.acmesh_output import cert_expiry_from_output, parse_cert_expiry
from acme_api.backend.dataclasses import AccountInfo, CertExpiry, IssuanceResult
from acme_api.backend.protocol import AcmeBackend, ChallengeMethod

logger = logging.getLogger(__name__)

_ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BLOCKED_ENV_KEYS = {
    "PATH",
    "HOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "VIRTUAL_ENV",
    "IFS",
    "ENV",
    "BASH_ENV",
    "SHELL",
}


@_dc.dataclass(frozen=True)
class _AcmeShBackendConfig:
    """Internal runtime configuration for AcmeShBackend."""

    binary_path: pathlib.Path
    home_dir: pathlib.Path
    log_file: pathlib.Path | None
    force_renewal: bool
    dnssleep_seconds: int | None


class AcmeShBackend(AcmeBackend):
    """Wraps the ``acme.sh`` CLI as an async backend.

    All subprocess calls run via :mod:`asyncio.subprocess` to avoid blocking the event loop.
    The binary path is resolved from config; the home directory holds account state, DNS
    records (in persist mode), and deployed certificates.
    """

    def __init__(self, config: _AcmeShBackendConfig) -> None:
        self._cfg = config
        # Lazy — resolved on first call to _ensure_binary so import-time does not fail when
        # acme.sh is not yet installed (e.g., in a fresh test container).
        self._binary_resolved: bool = False

    @cached_property
    def binary_path(self) -> pathlib.Path:
        """Resolve the acme.sh binary path; prefer ``acme.sh`` on PATH if set."""
        return self._cfg.binary_path

    async def _run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        expected_exitcode: int = 0,
        capture_stderr: bool = True,
    ) -> tuple[int, str]:
        """Execute an acme.sh command and return (exit_code, combined_output).

        Raises :class:`TerminalAcmeShError` or :class:`TransientAcmeShError` when the
        subprocess exits non-zero — classification happens in :meth:`_classify_exit`.
        """
        cmd = [str(self.binary_path), "--home", str(self._cfg.home_dir)] + args

        env = {**os.environ, **(env or {})}
        if self._cfg.log_file is not None:
            env["LOG_FILE"] = str(self._cfg.log_file)

        logger.info("Running acme.sh command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL,
            env=env,
        )

        stdout_bytes, stderr_bytes = await proc.communicate()
        stdout_text = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
        stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""

        combined = stdout_text + ("\n" + stderr_text if capture_stderr and stderr_text else "")
        exit_code = proc.returncode or 0

        logger.info(
            "acme.sh exited with code %d (stdout=%d chars, stderr=%d chars)",
            exit_code,
            len(stdout_text),
            len(stderr_text),
        )

        if exit_code != expected_exitcode:
            raise self._classify_exit(exit_code, stdout_text, stderr_text)

        return exit_code, combined

    # -- backend interface ------------------------------------------------------------------

    async def register_account(
        self,
        email: str,
        server_url: str,
    ) -> AccountInfo:
        args = [
            "--register",
            "--email",
            email,
            "--server",
            server_url,
            "--nocaptcha",
            "--accountkey-file",
            str(self._cfg.home_dir / "acct.key"),
        ]
        await self._run(args, capture_stderr=False)

        key_path = self._cfg.home_dir / "acct.key"
        if not key_path.is_file():
            raise TerminalAcmeShError(
                f"acme.sh registered account but key file missing at {key_path}",
            )
        return AccountInfo(
            key_path=str(key_path),
            email=email,
            server_url=server_url,
        )

    async def make_dns_persist_value(
        self,
        domain: str,
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> str:
        """Generate the account-bound persistent TXT value for ``domain``."""
        args = ["--make-dns-persist-value", "--domain", domain]
        if server_url is not None:
            args += ["--server", server_url]
        if account_key_path is not None:
            args += ["--accountkey-file", account_key_path]
        _, output = await self._run(args)
        return _dns_persist_value_from_output(output)

    async def issue_certificate(
        self,
        domains: list[str],
        method: ChallengeMethod,
        challenge_params: dict[str, t.Any],
        account_key_path: str | None = None,
        server_url: str | None = None,
    ) -> IssuanceResult:
        if not domains:
            raise TerminalAcmeShError("At least one domain is required for issuance")

        primary_domain = domains[0]
        command_env: dict[str, str] = {}

        args = [
            "--issue",
            "--domain",
            primary_domain,
            *chain_args_for(domains),
        ]

        if server_url is not None:
            # Without an explicit server acme.sh falls back to its default CA,
            # silently ignoring the account's configured directory URL.
            args += ["--server", server_url]

        if method == "dns-01":
            dns_provider = str(challenge_params["dns_provider"])
            env_vars_file = challenge_params.get("env_vars_file")
            args += ["--dns", dns_provider]
            if self._cfg.dnssleep_seconds is not None:
                args += ["--dnssleep", str(self._cfg.dnssleep_seconds)]
            if env_vars_file is not None:
                command_env.update(_load_env_vars(pathlib.Path(str(env_vars_file))))
        elif method == "dns-persist":
            args.append("--dns-persist")
        elif method == "webroot":
            webroot = str(challenge_params["webroot_dir"])
            args += ["--webroot", webroot]

        if account_key_path is not None:
            args += ["--accountkey-file", account_key_path]

        _, stdout = await self._run(args, env=command_env)

        cert_info = await cert_expiry_from_output(stdout)
        return IssuanceResult(
            account_key_path=account_key_path or str(self._cfg.home_dir / "acct.key"),
            cert=cert_info,
            domains=domains,
        )

    async def renew_certificate(
        self,
        domains: list[str],
        force_renewal: bool = False,
    ) -> IssuanceResult:
        if not domains:
            raise TerminalAcmeShError("At least one domain is required for renewal")

        args = ["--renew", "--domain", domains[0], *chain_args_for(domains)]
        if force_renewal or self._cfg.force_renewal:
            args.append("--force")

        _, stdout = await self._run(args)

        cert_info = await cert_expiry_from_output(stdout)
        return IssuanceResult(
            account_key_path=str(self._cfg.home_dir / "acct.key"),
            cert=cert_info,
            domains=domains,
        )

    async def get_certificate_expiry(self, cert_path: str) -> CertExpiry:
        args = [
            "--in",
            cert_path,
            "--info",
        ]
        _, stdout = await self._run(args)
        return parse_cert_expiry(stdout)

    # -- internals ------------------------------------------------------------------------

    def _classify_exit(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> AcmeShError:
        """Map acme.sh output to a typed error.

        Terminal vs transient classification follows the patterns documented at
        https://github.com/acmesh-official/acme.sh/wiki/ErrorCodes. Transient errors include
        DNS propagation waits, rate limits (429), and temporary CA unavailability.
        """
        combined = f"{stdout}\n{stderr}".lower()

        if any(token in combined for token in ("dns validation failed", "txt record not found", "timeout")):
            return TransientAcmeShError(
                "DNS propagation may still be in progress; retry with longer dnssleep",
                stderr=stderr,
            )

        if any(token in combined for token in ("rate limit reached", "429", "too many requests")):
            return TransientAcmeShError("ACME rate limit hit", stderr=stderr)

        if any(token in combined for token in ("account key invalid", "server returned 403", "unauthorized")):
            return TerminalAcmeShError(
                "Account is invalid or unauthorized — re-register required",
                stderr=stderr,
            )

        if any(token in combined for token in ("domain not match", "misconfiguration", "invalid domain")):
            return TerminalAcmeShError("Configuration error: invalid domains or parameters", stderr=stderr)

        if exit_code == 75:
            # acme.sh uses 75 for general transient failures
            return TransientAcmeShError(
                f"acme.sh exited with transient code {exit_code}",
                stderr=stderr,
            )

        diagnostic_output = f"{stdout}\n{stderr}".strip()
        return TerminalAcmeShError(
            f"acme.sh exited non-zero: code={exit_code}\n{diagnostic_output[:500]}",
            stderr=diagnostic_output,
        )


# -- module-level helpers -------------------------------------------------------------------


def chain_args_for(domains: list[str]) -> list[str]:
    """Return the ``--domain`` arguments for a SAN cert (excluding the primary).

    acme.sh takes the first ``--domain`` as primary; additional SANs come after.
    """
    if len(domains) <= 1:
        return []
    out: list[str] = []
    for domain in domains[1:]:
        out += ["--domain", domain]
    return out


def _load_env_vars(env_vars_file: pathlib.Path) -> dict[str, str]:
    """Load a shell-style ``export VAR=value`` file into a plain dict.

    Used to inject DNS provider credentials (e.g., ``CLOUDFLARE_EMAIL``,
    ``CLOUDFLARE_API_KEY``) before invoking acme.sh — it reads them from the env.
    """
    result: dict[str, str] = {}
    if not env_vars_file.is_file():
        return result

    for raw_line in env_vars_file.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip the leading ``export `` if present.
        if line.startswith("export "):
            line = line[len("export ") :]
        key, separator, value = line.partition("=")
        if separator:
            key = key.strip()
            if not _ENV_KEY_PATTERN.fullmatch(key):
                logger.warning("Ignoring invalid env var name from %s: %r", env_vars_file, key)
                continue
            if key.upper() in _BLOCKED_ENV_KEYS:
                logger.warning(
                    "Ignoring blocked env var name from %s: %s",
                    env_vars_file,
                    key,
                )
                continue
            result[key] = shlex.split(value.strip())[0] if value.strip() else ""
    return result


def _dns_persist_value_from_output(output: str) -> str:
    """Extract the persistent TXT value from acme.sh output."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        match = re.search(r"txt\s+persist\s+value\s*:\s*(.+)$", line, re.IGNORECASE)
        if match is not None:
            return match.group(1).strip().strip("\"'")
    if len(lines) == 1 and not any(character.isspace() for character in lines[0]):
        return lines[0]
    raise TerminalAcmeShError("acme.sh did not return a DNS Persist TXT value")
