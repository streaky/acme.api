"""Tests for request ID middleware."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Generator

import pytest
from fastapi import FastAPI, Request
from httpx2 import ASGITransport, AsyncClient

from acme_api.config import AppSettings, DatabaseConfig, DeploymentConfig
from acme_api.logging import request_id as _request_id_ctxvar


@pytest.fixture(autouse=True)
def _reset_ctxvar() -> Generator[None]:
    token = _request_id_ctxvar.set(None)
    yield
    try:
        _request_id_ctxvar.reset(token)
    except ValueError:
        pass


async def _make_app(tmp_path: Path) -> FastAPI:
    from acme_api.main import create_app

    settings = AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path / "certs"),
    )
    return create_app(settings=settings)


@pytest.mark.anyio
async def test_middleware_injects_request_id_header(tmp_path: Path) -> None:
    """Middleware adds X-Request-ID header to responses."""
    app = await _make_app(tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")

    assert "x-request-id" in resp.headers
    rid = resp.headers["x-request-id"]
    assert len(rid) > 0


@pytest.mark.anyio
async def test_middleware_different_id_per_request(tmp_path: Path) -> None:
    """Each request gets a unique X-Request-ID."""
    app = await _make_app(tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/health")
        r2 = await client.get("/health")

    h1 = r1.headers["x-request-id"]
    h2 = r2.headers["x-request-id"]
    assert h1 != h2


@pytest.mark.anyio
async def test_middleware_preserves_incoming_request_id(tmp_path: Path) -> None:
    """Incoming X-Request-ID is used as the correlation ID."""
    app = await _make_app(tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health", headers={"X-Request-ID": "external-123"})

    assert resp.headers["x-request-id"] == "external-123"


def test_get_request_id_rejects_crlf_injection() -> None:
    """CRLF bytes in request ID are rejected and replaced."""
    from acme_api.middleware import RequestIdMiddleware

    scope = {
        "headers": [(b"x-request-id", b"legit-id\r\nX-Injected: evil")],
    }

    rid = RequestIdMiddleware._get_request_id(scope)

    assert rid != "legit-id\r\nX-Injected: evil"
    assert "\r" not in rid
    assert "\n" not in rid


def test_get_request_id_rejects_oversized_value() -> None:
    """Overly long request IDs are rejected and replaced."""
    from acme_api.middleware import RequestIdMiddleware

    oversized = "a" * 129
    scope = {
        "headers": [(b"x-request-id", oversized.encode("ascii"))],
    }

    rid = RequestIdMiddleware._get_request_id(scope)

    assert rid != oversized
    assert len(rid) > 0
    assert len(rid) <= 128


@pytest.mark.anyio
async def test_middleware_sets_request_state(tmp_path: Path) -> None:
    """Request ID is available to handlers through request.state."""
    app = await _make_app(tmp_path)

    @app.get("/request-id")
    async def request_id_route(request: Request) -> dict[str, str]:
        return {"request_id": request.state.request_id}

    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/request-id", headers={"X-Request-ID": "state-123"})

    assert resp.json() == {"request_id": "state-123"}


@pytest.mark.anyio
async def test_middleware_resets_context_variable(tmp_path: Path) -> None:
    """Context variable is reset to None after the request completes."""
    app = await _make_app(tmp_path)
    transport = ASGITransport(app=app)

    assert _request_id_ctxvar.get() is None

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get("/health")

    # After the request finishes, the context should be reset
    assert _request_id_ctxvar.get() is None


@pytest.mark.anyio
async def test_middleware_resets_context_on_exception() -> None:
    """Context variable is reset even when the handler raises."""
    from acme_api.middleware import RequestIdMiddleware

    async def _app(
        scope: dict[str, Any], receive: Callable[..., Any], send: Callable[[dict[str, Any]], Any]
    ) -> None:  # noqa: ANN401
        raise RuntimeError("boom")

    middleware = RequestIdMiddleware(app=_app)

    scope = {"type": "http", "path": "/fail"}

    async def _receive() -> dict[str, Any]:
        return {}

    def _send(_message: dict[str, Any]) -> None:
        pass

    with pytest.raises(RuntimeError, match="boom"):
        await middleware(scope, lambda _: None, lambda x: None)

    assert _request_id_ctxvar.get() is None


@pytest.mark.anyio
async def test_middleware_adds_headers_key_when_missing() -> None:
    """Middleware writes headers back when response.start has no headers key."""
    from acme_api.middleware import RequestIdMiddleware

    messages: list[dict[str, Any]] = []

    async def _app(
        _scope: dict[str, Any],
        _receive: Callable[..., Any],
        send: Callable[[dict[str, Any]], Any],
    ) -> None:  # noqa: ANN401
        await send({"type": "http.response.start", "status": 204})

    async def _send(message: dict[str, Any]) -> None:
        messages.append(message)

    middleware = RequestIdMiddleware(app=_app)
    await middleware({"type": "http", "path": "/ok"}, lambda: None, _send)

    assert messages[0]["headers"][0][0] == b"x-request-id"


@pytest.mark.anyio
async def test_middleware_skips_non_http_scope() -> None:
    """Middleware passes through non-HTTP scopes without setting request ID."""
    from acme_api.middleware import RequestIdMiddleware

    messages = []

    async def _send(message: dict[str, Any]) -> None:
        messages.append(message)

    middleware = RequestIdMiddleware(  # noqa: B035 — intentional lambda for test
        app=lambda s, r, sd: _send(sd),  # noqa: B026
    )

    scope = {"type": "websocket", "path": "/ws"}
    await middleware(scope, lambda _: None, _send)

    assert len(messages) == 1


@pytest.mark.anyio
async def test_middleware_preserves_app() -> None:
    """Middleware stores a reference to the underlying app."""
    from acme_api.middleware import RequestIdMiddleware

    async def _dummy(
        _scope: dict[str, Any], _receive: Callable[..., Any], _send: Callable[[dict[str, Any]], Any]
    ) -> None:  # noqa: ANN401
        pass

    middleware = RequestIdMiddleware(app=_dummy)
    assert callable(middleware.app)
