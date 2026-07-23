"""FastAPI application factory and CLI entry point.

Provides ``create_app`` for dependency-injection wiring and a ``main()``
CLI function that launches uvicorn via the ``acme-api`` console script.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.backend.acmesh_backend import AcmeShBackend, _AcmeShBackendConfig
from acme_api.config import AppSettings, load_config, prepare_runtime_paths
from acme_api.db import get_db, get_session_factory, init_engine, run_migrations
from acme_api.logging import setup_logging
from acme_api.middleware import RequestIdMiddleware
from acme_api.readiness import readiness_status
from acme_api.routers import admin_clients_router, certificates_router, config_router, events_router
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
    """Configure runtime dependencies and close them cleanly on shutdown."""
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
    engine = init_engine(settings)

    backend = getattr(app.state, "acme_backend", None) or AcmeShBackend(
        _AcmeShBackendConfig(
            binary_path=Path(settings.acme.binary_path),
            home_dir=settings.acme.home_dir,
            log_file=None,
            force_renewal=settings.acme.force_renewal,
            dnssleep_seconds=settings.acme.dnssleep_seconds,
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
            artifact_group_id=settings.deployment.artifact_group_id,
            allowed_source_roots=([settings.acme.home_dir] if isinstance(backend, AcmeShBackend) else None),
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

    def log_recovery_failure(task: asyncio.Task[None]) -> None:
        """Log an unexpected recovery failure after retrieving its exception."""
        if task.cancelled():
            return
        if exception := task.exception():
            root_logger.error("Unable to resume released DNS Persist requests: %s", exception)

    recovery_task = asyncio.create_task(
        app.state.certificate_service.resume_released_dns_persist_certificates(),
        name="resume-released-dns-persist-requests",
    )
    recovery_task.add_done_callback(log_recovery_failure)

    try:
        yield
    finally:
        recovery_task.cancel()
        # The callback retrieves and logs a completed task's failure.
        with suppress(asyncio.CancelledError, Exception):
            await recovery_task
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
        description=("Lightweight, self-hosted REST service for managing ACME certificates via DNS-01 validation."),
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
    app.include_router(admin_clients_router)

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
    async def unhandled_exception_handler(request: Request, _exc: Exception) -> Response:
        logging.exception("unhandled exception on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    return app


def _command_parser() -> argparse.ArgumentParser:
    """Build the local administrative command parser."""
    parser = argparse.ArgumentParser(prog="acme-api")
    commands = parser.add_subparsers(dest="command")
    admin = commands.add_parser("admin", help="Manage local administrative bootstrap.")
    admin_commands = admin.add_subparsers(dest="admin_command")
    initialize = admin_commands.add_parser(
        "initialize",
        help="Create the one permitted initial admin client from standard input.",
    )
    initialize.add_argument(
        "--key-stdin",
        action="store_true",
        required=True,
        help="Read the initial admin credential from standard input.",
    )
    return parser


async def _initialize_admin_from_stdin() -> int:
    """Persist the initial admin client using a credential read from standard input."""
    from alembic.util.exc import CommandError

    from acme_api.admin_clients import InitialAdminAlreadyExistsError, initialize_admin

    raw_key = sys.stdin.read()
    engine = None
    try:
        settings = load_config()
        prepare_runtime_paths(settings)
        settings.check()
        run_migrations(settings)
        engine = init_engine(settings)
        async with get_db() as session:
            await initialize_admin(session, raw_key)
    except (CommandError, InitialAdminAlreadyExistsError, OSError, SQLAlchemyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            await engine.dispose()
    print("Initial admin client created.")
    return 0


def main() -> None:
    """Launch the HTTP service or execute the local admin bootstrap command."""
    args = _command_parser().parse_args()
    if args.command == "admin":
        if args.admin_command == "initialize":
            raise SystemExit(asyncio.run(_initialize_admin_from_stdin()))
        _command_parser().error("an admin command is required")

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
