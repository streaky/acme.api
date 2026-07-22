"""Persisted API-client provisioning and management helpers."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.functions import count

from acme_api.auth.hash import api_key_lookup_hash, hash_api_key
from acme_api.models.api_key import APIKey, APIKeyRole
from acme_api.models.event import Event

_MAX_KEY_LENGTH = 4096
_MIN_KEY_LENGTH = 16
_INITIAL_ADMIN_NAME = "initial-admin"


class InitialAdminAlreadyExistsError(Exception):
    """Raised when local initialization is attempted after any client exists."""


def validate_raw_key(raw_key: str) -> str:
    """Validate credential material without returning it in an error message."""
    key = raw_key.rstrip("\r\n")
    if not _MIN_KEY_LENGTH <= len(key) <= _MAX_KEY_LENGTH:
        raise ValueError("Credential must be between 16 and 4096 characters.")
    if not key.isascii() or any(character.isspace() or not character.isprintable() for character in key):
        raise ValueError("Credential must contain only visible ASCII characters without whitespace.")
    return key


@dataclass(frozen=True)
class ProvisionedClient:
    """A newly provisioned API client and its one-time raw credential."""

    client: APIKey
    raw_key: str


def _new_raw_key() -> str:
    """Generate a high-entropy HTTP Bearer-safe API credential."""
    return secrets.token_urlsafe(32)


async def initialize_admin(session: AsyncSession, raw_key: str) -> APIKey:
    """Create the initial admin only if the API-client table is empty."""
    credential = validate_raw_key(raw_key)
    async with session.begin():
        client_count = await session.scalar(select(count(APIKey.id)))
        if client_count:
            raise InitialAdminAlreadyExistsError("API-client initialization has already completed.")
        client = APIKey(
            name=_INITIAL_ADMIN_NAME,
            hashed_key=hash_api_key(credential),
            key_lookup_hash=api_key_lookup_hash(credential),
            role=APIKeyRole.ADMIN,
            is_active=True,
        )
        session.add(client)
        session.add(
            Event(
                event_type="api_client.initialized",
                details={"name": _INITIAL_ADMIN_NAME, "role": APIKeyRole.ADMIN.value},
            )
        )
    return client


async def create_client(session: AsyncSession, name: str, role: APIKeyRole) -> ProvisionedClient:
    """Create an active client with a generated credential returned once."""
    raw_key = _new_raw_key()
    client = APIKey(
        name=name,
        hashed_key=hash_api_key(raw_key),
        key_lookup_hash=api_key_lookup_hash(raw_key),
        role=role,
        is_active=True,
    )
    session.add(client)
    session.add(Event(event_type="api_client.created", details={"name": name, "role": role.value}))
    await session.commit()
    await session.refresh(client)
    return ProvisionedClient(client=client, raw_key=raw_key)


async def rotate_client(session: AsyncSession, client: APIKey) -> ProvisionedClient:
    """Replace one client's credential and return the replacement once."""
    raw_key = _new_raw_key()
    client.hashed_key = hash_api_key(raw_key)
    client.key_lookup_hash = api_key_lookup_hash(raw_key)
    session.add(Event(event_type="api_client.rotated", details={"name": client.name, "role": client.role.value}))
    await session.commit()
    await session.refresh(client)
    return ProvisionedClient(client=client, raw_key=raw_key)


async def revoke_client(session: AsyncSession, client: APIKey) -> APIKey:
    """Deactivate an API client without deleting its audit-relevant record."""
    client.is_active = False
    session.add(Event(event_type="api_client.revoked", details={"name": client.name, "role": client.role.value}))
    await session.commit()
    await session.refresh(client)
    return client
