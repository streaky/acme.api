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

from acme_api.config import AppSettings, load_config


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan handler.

    Starts structured logging on startup; nothing to tear down yet.
    """
    settings = app.state.settings
    log_level_name: str = getattr(settings.log, "level", "INFO")
    logging.basicConfig(level=getattr(logging, log_level_name), format="%(asctime)s %(levelname)s %(message)s")
    logging.info("acme.api starting up")
    yield
    logging.info("acme.api shutting down")


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
    level: str = getattr(settings.log, "level", "INFO")
    logging.basicConfig(level=getattr(logging, level), format="%(asctime)s %(levelname)s %(message)s")

    uvicorn.run(
        "acme_api.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=8000,
        log_level=level.lower(),
    )


if __name__ == "__main__":
    main()
