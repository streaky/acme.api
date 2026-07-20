"""API key material hashing and verification utilities."""

from __future__ import annotations

import uuid as _uuid
from dataclasses import dataclass
from datetime import datetime
from hashlib import pbkdf2_hmac
from typing import cast

from passlib.hash import pbkdf2_sha512 as _pbkdf2_sha512  # type: ignore[import-untyped]

from acme_api.models.api_key import APIKeyRole

_HASH_ROUNDS = 200_000
_LOOKUP_HASH_ROUNDS = 100_000
_LOOKUP_HASH_SALT = b"acme.api/api-key-lookup/v1"


def api_key_lookup_hash(raw_key: str) -> str:
    """Return a deterministic, work-factor-protected database lookup digest.

    The digest is not used as the verifier; successful authentication still
    requires matching the separately salted PBKDF2 hash. Its purpose is to
    avoid checking every active verifier hash on each request.
    """
    if not raw_key:
        raise ValueError("API key must not be empty.")
    return pbkdf2_hmac(
        "sha512",
        raw_key.encode("utf-8"),
        _LOOKUP_HASH_SALT,
        _LOOKUP_HASH_ROUNDS,
    ).hex()


def hash_api_key(raw_key: str) -> str:
    """Return a PBKDF2-SHA512 hash of the raw API key material.

    PBKDF2 is preferred over bcrypt for high-entropy secrets like API keys,
    because bcrypt has a 72-byte input truncation limit and newer versions of
    ``bcrypt`` are incompatible with passlib's legacy wrapper code.

    Args:
        raw_key: The plaintext API key material (minimum 8 characters).

    Returns:
        A hash string suitable for storage in the database.

    Raises:
        ValueError: If ``raw_key`` is empty or shorter than 8 characters.
    """
    if not raw_key or len(raw_key) < 8:
        raise ValueError("API key must be at least 8 characters long.")
    return cast(str, _pbkdf2_sha512.using(rounds=_HASH_ROUNDS).hash(raw_key))


def verify_api_key(candidate: str, stored_hash: str) -> bool:
    """Return ``True`` when ``candidate`` matches the PBKDF2-stored hash.

    Args:
        candidate: The plaintext API key from the request header.
        stored_hash: The PBKDF2-SHA512 hash stored in the database.

    Returns:
        Whether the two values match.
    """
    if not candidate or not stored_hash:
        return False
    try:
        return cast(bool, _pbkdf2_sha512.verify(candidate, stored_hash))
    except ValueError:  # pragma: no cover — defensive guard only
        return False


@dataclass(frozen=True)
class AuthenticatedUser:
    """Represents an authenticated user after token validation.

    Attributes:
        key_id: The unique identifier of the API key.
        role: The access level granted by this key (admin/operator/readonly).
        name: Human-readable label for the key.
        expires_at: Optional expiration datetime string.
    """

    key_id: _uuid.UUID
    role: APIKeyRole
    name: str | None = None
    expires_at: datetime | None = None


class AuthenticationError(Exception):
    """Base class for authentication failures."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


class ForbiddenError(AuthenticationError):
    """Raised when role permissions are insufficient.

    Attributes:
        required_role: The minimum role needed for this operation (may be ``None``).
    """

    def __init__(self, message: str, required_role: APIKeyRole | None = None) -> None:
        super().__init__(message, status_code=403)
        self.required_role = required_role
