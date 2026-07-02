"""Health endpoint smoke test."""

from __future__ import annotations

import pytest
from httpx2 import AsyncClient


@pytest.mark.anyio
async def test_health_returns_ok(client: AsyncClient) -> None:
    """GET /health should return 200 with status ok."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert isinstance(response.json()["uptime_seconds"], float)
