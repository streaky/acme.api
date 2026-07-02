"""FastAPI application factory and CLI entry point.

Provides ``create_app`` for dependency-injection wiring and a ``main()``
CLI function that launches uvicorn via the ``acme-api`` console script.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from acme_api.auth.bootstrap import seed_initial_keys
from acme_api.config import AppSettings, load_config, prepare_runtime_paths
from acme_api.db import get_db, init_db, init_engine
from acme_api.logging import setup_logging
from acme_api.middleware import RequestIdMiddleware
from acme_api.routers import certificates_router, config_router, events_router


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

    # Phase 4: initialize engine (sets up session factory) and seed API keys.
    engine = init_engine(settings)
    await init_db(engine)
    async with get_db() as session:
        created_keys = await seed_initial_keys(session, settings)
        for key in created_keys:
            root_logger.info(
                "seeded api key | name=%s role=%s", key.name, key.role.value
            )

    yield

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
    )

    app.state.settings = settings

    # Middleware: request ID injection (outermost)
    app.add_middleware(RequestIdMiddleware)
    app.include_router(certificates_router)
    app.include_router(config_router)
    app.include_router(events_router)

    @app.get("/health", tags=["Health"])
    async def health() -> dict[str, str]:
        """Liveness probe — always returns 200 when the process is running."""
        return {"status": "ok"}

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

    logging.getLogger(__name__).info(
        "launching uvicorn | host=0.0.0.0 port=%s level=%s",
        8000,
        settings.log.level.lower(),
    )

    uvicorn.run(
        "acme_api.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=8000,
        log_level=settings.log.level.lower(),
    )


if __name__ == "__main__":
    main()
