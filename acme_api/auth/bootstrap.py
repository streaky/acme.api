"""Bootstrap API keys from configuration."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.auth.hash import hash_api_key
from acme_api.config import AppSettings
from acme_api.models.api_key import APIKey, APIKeyRole


async def seed_initial_keys(db: AsyncSession, settings: AppSettings) -> list[APIKey]:
    """Create initial admin/operator/readonly keys from config.

    Keys come from ``AppSettings.api_keys`` dict (role → raw key string).
    Only non-empty entries are seeded; missing roles mean that role is not bootstrapped.

    Args:
        db: Async SQLAlchemy session.
        settings: Runtime settings containing bootstrap key material.

    Returns:
        List of created :class:`APIKey` instances.
    """
    keys_raw = settings.api_keys

    created: list[APIKey] = []
    for role_str, raw_key in keys_raw.items():
        if not raw_key:
            continue
        try:
            role = APIKeyRole(role_str)
        except ValueError as exc:
            raise ValueError(
                f"Invalid bootstrap key role '{role_str}'. "
                f"Valid roles: {[r.value for r in APIKeyRole]}"
            ) from exc

        existing = await db.scalar(
            select(APIKey).where(
                APIKey.name == f"bootstrap-{role.value}",
            )
        )
        if existing is not None:
            continue

        hashed = hash_api_key(raw_key)
        key_obj = APIKey(
            name=f"bootstrap-{role.value}",
            hashed_key=hashed,
            role=role,
            is_active=True,
        )
        db.add(key_obj)
        created.append(key_obj)

    if created:
        await db.commit()

    return created


__all__ = ["seed_initial_keys"]
