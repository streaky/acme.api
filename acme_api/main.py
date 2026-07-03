"""FastAPI application factory and CLI entry point.

Provides ``create_app`` for dependency-injection wiring and a ``main()``
CLI function that launches uvicorn via the ``acme-api`` console script.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.auth.bootstrap import seed_initial_keys
from acme_api.backend.acmesh_backend import AcmeShBackend, _AcmeShBackendConfig
from acme_api.config import AppSettings, load_config, prepare_runtime_paths
from acme_api.db import get_db, get_session_factory, init_engine, run_migrations
from acme_api.logging import setup_logging
from acme_api.middleware import RequestIdMiddleware
from acme_api.readiness import readiness_status
from acme_api.routers import certificates_router, config_router, events_router
from acme_api.scheduler import RenewalDeploymentConfig, RenewalScheduler
from acme_api.services.certificates import CertificateLifecycleService
from acme_api.webhooks import WebhookDeliverySettings, WebhookDispatcher

_COMMON_OPENAPI_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid API key."},
    403: {"description": "Authenticated API key does not have the required role."},
    500: {"description": "Internal server error."},
}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan handler.

    Configures structured logging, initializes the async DB engine, seeds API
    keys from config on first boot, and validates settings before accepting
    requests. On shutdown, closes all session factories cleanly.
    """
    settings = app.state.settings

    prepare_runtime_paths(settings)
    settings.check()
    setup_logging(level=settings.log.level, format_type=settings.log.format)
    root_logger = logging.getLogger(__name__)
    root_logger.info(
        "acme.api starting up | db=%s deploy_dir=%s",
        settings.database.url,
        settings.deployment.directory,
    )

    # Apply schema migrations before opening async application sessions.
    run_migrations(settings)

    # Phase 4: initialize engine (sets up session factory) and seed API keys.
    engine = init_engine(settings)
    async with get_db() as session:
        created_keys = await seed_initial_keys(session, settings)
        for key in created_keys:
            root_logger.info(
                "seeded api key | name=%s role=%s", key.name, key.role.value
            )

    backend = getattr(app.state, "acme_backend", None) or AcmeShBackend(
        _AcmeShBackendConfig(
            binary_path=Path(settings.acme.binary_path),
            home_dir=settings.acme.home_dir,
            log_file=None,
            force_renewal=False,
            dnssleep_seconds=None,
        )
    )
    app.state.acme_backend = backend

    def webhook_dispatcher_factory(session: AsyncSession) -> WebhookDispatcher:
        return WebhookDispatcher(
            session,
            WebhookDeliverySettings(
                timeout_seconds=settings.webhooks.timeout_seconds,
                max_retries=settings.webhooks.max_retries,
                backoff_seconds=settings.webhooks.backoff_seconds,
            ),
        )
    renewal_scheduler = RenewalScheduler(
        session_factory=get_session_factory(),
        backend=backend,
        config=settings.renewal,
        webhook_dispatcher_factory=webhook_dispatcher_factory,
        deployment=RenewalDeploymentConfig(
            root=settings.deployment.directory,
            permissions_cert=settings.deployment.permissions_cert,
            permissions_key=settings.deployment.permissions_key,
            allowed_source_roots=(
                [settings.acme.home_dir]
                if isinstance(backend, AcmeShBackend)
                else None
            ),
        ),
    )
    app.state.renewal_scheduler = renewal_scheduler
    app.state.certificate_service = CertificateLifecycleService(
        session_factory=get_session_factory(),
        backend=backend,
        settings=settings,
        scheduler=renewal_scheduler,
        webhook_dispatcher_factory=webhook_dispatcher_factory,
    )
    await renewal_scheduler.start()

    try:
        yield
    finally:
        await renewal_scheduler.shutdown()
        await engine.dispose()
        root_logger.info("acme.api shutting down")


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional pre-loaded configuration.  If ``None``, config is
                  loaded from disk/environment at startup time via lifespan.

    Returns:
        A fully configured :class:`FastAPI` instance with a health endpoint.
    """
    if settings is None:
        settings = load_config()

    app = FastAPI(
        title="acme.api",
        description=(
            "Lightweight, self-hosted REST service for managing ACME certificates "
            "via DNS-01 validation."
        ),
        version="0.1.0",
        lifespan=lifespan,
        responses=_COMMON_OPENAPI_RESPONSES,
    )

    app.state.settings = settings
    app.state.started_at = time.monotonic()

    # Middleware: request ID injection (outermost)
    app.add_middleware(RequestIdMiddleware)
    app.include_router(certificates_router)
    app.include_router(config_router)
    app.include_router(events_router)

    @app.get(
        "/health",
        tags=["Health"],
        responses={200: {"description": "Process is running."}},
    )
    async def health() -> dict[str, str | float]:
        """Liveness probe — always returns 200 when the process is running."""
        return {
            "status": "ok",
            "uptime_seconds": round(time.monotonic() - app.state.started_at, 3),
        }

    @app.get(
        "/ready",
        tags=["Health"],
        responses={
            200: {"description": "Runtime dependencies are available."},
            503: {"description": "One or more runtime dependencies are unavailable."},
        },
    )
    async def ready() -> JSONResponse:
        """Readiness probe for database and acme.sh executable availability."""
        ready_ok, checks = await readiness_status(
            settings=app.state.settings,
            session_factory=get_session_factory(),
        )
        status_code = 200 if ready_ok else 503
        return JSONResponse(
            status_code=status_code,
            content={"status": "ready" if ready_ok else "not_ready", "checks": checks},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, _exc: Exception
    ) -> Response:
        logging.exception("unhandled exception on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    return app


def main() -> None:
    """CLI entry point — loads config and launches uvicorn."""
    settings = load_config()
    setup_logging(level=settings.log.level, format_type=settings.log.format)
    host = os.environ.get("ACME_API_HOST", "0.0.0.0")
    port = int(os.environ.get("ACME_API_PORT", "8000"))

    logging.getLogger(__name__).info(
        "launching uvicorn | host=%s port=%s level=%s",
        host,
        port,
        settings.log.level.lower(),
    )

    uvicorn.run(
        "acme_api.main:create_app",
        factory=True,
        host=host,
        port=port,
        log_level=settings.log.level.lower(),
    )


if __name__ == "__main__":
    main()
