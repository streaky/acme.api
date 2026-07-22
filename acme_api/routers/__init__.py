"""FastAPI router registry."""

from __future__ import annotations

from acme_api.routers.admin_clients import router as admin_clients_router
from acme_api.routers.certificates import router as certificates_router
from acme_api.routers.config import router as config_router
from acme_api.routers.events import router as events_router

__all__ = ["admin_clients_router", "certificates_router", "config_router", "events_router"]
