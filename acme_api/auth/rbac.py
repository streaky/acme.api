"""RBAC FastAPI dependencies for API key authorization."""

from __future__ import annotations

import datetime as _dt

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.auth.hash import AuthenticatedUser, api_key_lookup_hash, verify_api_key
from acme_api.db import get_db_session
from acme_api.models.api_key import APIKey, APIKeyRole


async def require_admin(
    request: Request, db_session: AsyncSession = Depends(get_db_session)
) -> AuthenticatedUser:
    """Require the request holder to have admin role."""
    user = await _authenticate(request, db_session)
    if user.role != APIKeyRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required.",
        )
    return user


async def require_operator(
    request: Request, db_session: AsyncSession = Depends(get_db_session)
) -> AuthenticatedUser:
    """Require the request holder to have operator role or higher."""
    user = await _authenticate(request, db_session)
    allowed = {APIKeyRole.ADMIN, APIKeyRole.OPERATOR}
    if user.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator privileges required.",
        )
    return user


async def require_readonly(
    request: Request, db_session: AsyncSession = Depends(get_db_session)
) -> AuthenticatedUser:
    """Require the request holder to have any authenticated role."""
    return await _authenticate(request, db_session)


async def _authenticate(request: Request, db_session: AsyncSession) -> AuthenticatedUser:
    """Validate Bearer token and return the user if authorized.

    Args:
        request: Incoming FastAPI request.
        db_session: Database session from ``get_db`` dependency.

    Returns:
        An :class:`AuthenticatedUser` on success.

    Raises:
        HTTPException 401 if no valid Bearer token is provided or key not found.
        HTTPException 403 if key is inactive, expired, or lacks required privilege.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = auth_header[7:]  # Strip 'Bearer ' prefix
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    lookup_hash = api_key_lookup_hash(raw_token)
    statement = select(APIKey).where(
        APIKey.is_active.is_(True),
        APIKey.key_lookup_hash == lookup_hash,
    )
    result = await db_session.execute(statement)
    candidate = result.scalar_one_or_none()
    api_key = candidate if candidate and verify_api_key(raw_token, candidate.hashed_key) else None

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = _dt.datetime.now(_dt.timezone.utc)
    expires_at = api_key.expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=_dt.timezone.utc)
    if expires_at and now > expires_at:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key has expired.",
        )

    return AuthenticatedUser(
        key_id=api_key.id,
        role=api_key.role,
        name=api_key.name,
        expires_at=expires_at,
    )


__all__ = ["require_admin", "require_operator", "require_readonly"]
