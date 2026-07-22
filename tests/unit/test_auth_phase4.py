"""Tests for persisted API-client provisioning and authorization primitives."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.admin_clients import InitialAdminAlreadyExistsError, initialize_admin
from acme_api.auth.hash import api_key_lookup_hash, verify_api_key
from acme_api.models.api_key import APIKey, APIKeyRole
from acme_api.models.event import Event


class TestInitialAdminProvisioning:
    """Verify the transactional local bootstrap primitive."""

    @pytest.mark.anyio
    async def test_initialization_persists_only_hashes(self, db: AsyncSession) -> None:
        raw_key = "initial-admin-key-12345"

        client = await initialize_admin(db, raw_key)
        row = await db.get(APIKey, client.id)
        event = await db.scalar(select(Event).where(Event.event_type == "api_client.initialized"))

        assert row is not None
        assert row.role == APIKeyRole.ADMIN
        assert row.hashed_key != raw_key
        assert row.key_lookup_hash == api_key_lookup_hash(raw_key)
        assert verify_api_key(raw_key, row.hashed_key)
        assert event is not None
        assert event.details == {"name": "initial-admin", "role": "admin"}

    @pytest.mark.anyio
    async def test_initialization_refuses_any_existing_record(self, db: AsyncSession) -> None:
        db.add(
            APIKey(
                name="inactive-client",
                hashed_key="not-used",
                key_lookup_hash="a" * 128,
                role=APIKeyRole.READONLY,
                is_active=False,
            )
        )
        await db.commit()

        with pytest.raises(InitialAdminAlreadyExistsError):
            await initialize_admin(db, "initial-admin-key-12345")

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "raw_key",
        ["", "short", "has whitespace credential", "x" * 4097],
    )
    async def test_initialization_rejects_invalid_stdin_material(
        self,
        db: AsyncSession,
        raw_key: str,
    ) -> None:
        with pytest.raises(ValueError):
            await initialize_admin(db, raw_key)


class TestHashUtility:
    """Preserve lookup and password-hash behavior after persistence."""

    def test_api_key_lookup_hash_is_deterministic(self) -> None:
        digest = api_key_lookup_hash("admin-key-12345")

        assert digest == api_key_lookup_hash("admin-key-12345")
        assert len(digest) == 128
