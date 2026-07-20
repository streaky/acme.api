"""Parsing of acme.sh output into certificate path and expiry records.

acme.sh 2.x and 3.x differ in how they report file locations ("is there:" vs
"is in:") and 3.x ``--issue`` output carries no expiry date at all, so
:func:`cert_expiry_from_output` falls back to reading ``notAfter`` from the
certificate file itself via ``openssl x509``.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import pathlib
import re
import typing as t

from acme_api.backend.acmesh_errors import TerminalAcmeShError
from acme_api.backend.dataclasses import CertExpiry

_PATH_PATTERNS = {
    "cert": (
        re.compile(r"Your cert is in:?\s+(?P<path>[^,\n]+)", re.IGNORECASE),
        re.compile(r"CertPath=(?P<path>[^\n]+)", re.IGNORECASE),
    ),
    "key": (
        re.compile(r"Your cert key is in:?\s+(?P<path>[^,\n]+)", re.IGNORECASE),
        re.compile(r"KeyPath=(?P<path>[^\n]+)", re.IGNORECASE),
    ),
    "chain": (
        re.compile(
            r"(?:CA certificates|intermediate CA cert)\s+(?:are|is)\s+in:?\s+(?P<path>[^,\n]+)",
            re.IGNORECASE,
        ),
        re.compile(r"CAPath=(?P<path>[^\n]+)", re.IGNORECASE),
    ),
    "fullchain": (
        # acme.sh 2.x: "And the full chain certs is there: <path>"
        # acme.sh 3.x: "And the full-chain cert is in: <path>"
        re.compile(r"full[- ]chain certs? is (?:there|in):?\s+(?P<path>[^\n]+)", re.IGNORECASE),
        re.compile(r"FullChainPath=(?P<path>[^\n]+)", re.IGNORECASE),
    ),
}
_DATE_PATTERNS = (
    re.compile(r"\*{3}\s*Expired at:\s*(?P<date>[^\n]+)", re.IGNORECASE),
    re.compile(r"Le_NextRenewTimeStr=['\"]?(?P<date>[^'\"\n]+)", re.IGNORECASE),
    re.compile(r"Not After\s*:\s*(?P<date>[^\n]+)", re.IGNORECASE),
)


class _CertPaths(t.NamedTuple):
    """File layout parsed from acme.sh output (no expiry — that may live elsewhere)."""

    cert_path: str
    privkey_path: str
    chain_path: str
    fullchain_path: str


def parse_cert_paths(output: str) -> _CertPaths:
    """Extract the certificate file paths from acme.sh output.

    Raises :class:`TerminalAcmeShError` when the cert, key, or chain path is missing — this
    means acme.sh failed silently or returned unexpected content; the caller should inspect
    stderr. A missing fullchain path is derived from the cert's directory.
    """
    cert_path = _extract_path(output, "cert")
    privkey_path = _extract_path(output, "key")
    chain_path = _extract_path(output, "chain")
    fullchain_path = _extract_path(output, "fullchain")

    if cert_path is None or privkey_path is None or chain_path is None:
        raise TerminalAcmeShError(
            "Could not parse cert paths from acme.sh output",
            stderr=output,
        )

    if fullchain_path is None:
        fullchain_path = str(pathlib.Path(cert_path).parent / "fullchain.pem")

    return _CertPaths(
        cert_path=cert_path,
        privkey_path=privkey_path,
        chain_path=chain_path,
        fullchain_path=fullchain_path,
    )


def parse_cert_expiry(output: str) -> CertExpiry:
    """Extract the expiry record from acme.sh output that carries a date.

    Suitable for ``--info`` conf dumps (``Le_NextRenewTimeStr=...``) and legacy issue output.
    Real ``--issue``/``--renew`` output contains no date — use
    :func:`read_cert_notafter` on the parsed cert path instead.

    Raises :class:`TerminalAcmeShError` when no paths or no date can be found.
    """
    paths = parse_cert_paths(output)
    expires_str = _extract_expiry_date(output)

    if expires_str is None:
        raise TerminalAcmeShError(
            "Could not parse cert expiry from acme.sh output",
            stderr=output,
        )

    return CertExpiry(
        cert_path=paths.cert_path,
        privkey_path=paths.privkey_path,
        chain_path=paths.chain_path,
        fullchain_path=paths.fullchain_path,
        expires_at=_parse_acmesh_datetime(expires_str),
    )


async def cert_expiry_from_output(output: str) -> CertExpiry:
    """Build a :class:`CertExpiry` from acme.sh issue/renew output.

    Real acme.sh 3.x issue output lists cert paths but no expiry date, so when no date
    line is present the expiry is read from the certificate file itself via openssl.
    """
    paths = parse_cert_paths(output)
    expires_str = _extract_expiry_date(output)
    if expires_str is not None:
        expires_at = _parse_acmesh_datetime(expires_str)
    else:
        expires_at = await read_cert_notafter(paths.cert_path)
    return CertExpiry(
        cert_path=paths.cert_path,
        privkey_path=paths.privkey_path,
        chain_path=paths.chain_path,
        fullchain_path=paths.fullchain_path,
        expires_at=expires_at,
    )


async def read_cert_notafter(cert_path: str) -> _dt.datetime:
    """Read a PEM certificate's ``notAfter`` timestamp via ``openssl x509``.

    acme.sh itself requires openssl, so the binary is guaranteed present wherever the
    backend runs. This is the ground truth for expiry: acme.sh's ``--issue`` output does
    not include one.
    """
    proc = await asyncio.create_subprocess_exec(
        "openssl",
        "x509",
        "-noout",
        "-enddate",
        "-in",
        cert_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await proc.communicate()
    if proc.returncode != 0:
        raise TerminalAcmeShError(
            f"openssl could not read expiry from {cert_path}",
            stderr=stderr_bytes.decode(errors="replace"),
        )

    # Output shape: ``notAfter=Jul  5 02:29:00 2027 GMT``
    text = stdout_bytes.decode(errors="replace").strip()
    _, separator, value = text.partition("=")
    if not separator:
        raise TerminalAcmeShError(f"Unexpected openssl -enddate output: {text!r}")
    return _parse_acmesh_datetime(value.strip())


def _extract_path(output: str, key: str) -> str | None:
    """Extract and normalize a path field from acme.sh output."""
    for pattern in _PATH_PATTERNS[key]:
        match = pattern.search(output)
        if match:
            return match.group("path").strip().strip("'\"")
    return None


def _extract_expiry_date(output: str) -> str | None:
    """Extract an expiry or next-renewal date from acme.sh output."""
    for pattern in _DATE_PATTERNS:
        match = pattern.search(output)
        if match:
            return match.group("date").strip()
    return None


def _parse_acmesh_datetime(s: str) -> _dt.datetime:
    """Parse acme.sh's ``YYYY-MM-DD HH:MM:SS+ZZZZ`` format.

    acme.sh always emits UTC offsets; we normalize to a timezone-aware datetime.
    """
    # Try ISO-like with offset first, then fall back to plain format.
    try:
        return _dt.datetime.fromisoformat(s.replace(" UTC", "+00:00").replace(" ", "T"))
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S%z", "%b %d %H:%M:%S %Y %Z"):
        try:
            parsed = _dt.datetime.strptime(s, fmt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=_dt.UTC)
            return parsed
        except ValueError:
            continue

    raise TerminalAcmeShError(f"Could not parse acme.sh datetime: {s}")
