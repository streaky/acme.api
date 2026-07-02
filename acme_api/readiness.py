"""Readiness probe checks for runtime dependencies."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acme_api.config import AppSettings


async def readiness_status(
    *,
    settings: AppSettings,
    session_factory: async_sessionmaker[AsyncSession],
) -> tuple[bool, dict[str, Any]]:
    """Return aggregate readiness and dependency check details."""
    checks = {
        "database": await _database_ready(session_factory),
        "acme_binary": _acme_binary_ready(settings.acme.binary_path),
    }
    return all(check["ok"] for check in checks.values()), checks


async def _database_ready(
    session_factory: async_sessionmaker[AsyncSession],
) -> dict[str, Any]:
    try:
        async with session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


def _acme_binary_ready(binary_path: str) -> dict[str, Any]:
    resolved = shutil.which(binary_path)
    if resolved is None:
        path = Path(binary_path)
        if path.is_file() and os.access(path, os.X_OK):
            resolved = str(path)
    if resolved is None:
        return {"ok": False, "error": f"acme.sh binary not executable: {binary_path}"}
    return {"ok": True, "path": resolved}
