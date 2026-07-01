"""Request ID middleware for FastAPI.

Injects a unique request ID into each HTTP request's context,
which is then logged by the structured JSON formatter.
"""

from __future__ import annotations

from typing import Any, Callable, cast
from uuid import uuid4

from acme_api.logging import request_id as _request_id_ctxvar

ASGIApp = Callable[[Any, Any, Any], Any]


class RequestIdMiddleware:
    """Middleware to add request IDs to all requests.

    Sets a unique correlation ID per-request in both ``request.state`` and the
    logging context variable so structured logs can be traced back to the
    originating HTTP request.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Any],
        send: Callable[[dict[str, Any]], Any],
    ) -> None:  # noqa: ANN401
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        rid = str(uuid4())
        token = _request_id_ctxvar.set(rid)

        # Wrap send to inject the X-Request-ID response header
        headers_sent = False

        async def wrapped_send(message: dict[str, Any]) -> None:
            nonlocal headers_sent
            if message["type"] == "http.response.start" and not headers_sent:
                hdrs = cast(list[tuple[bytes, bytes]], message.get("headers", []))
                for i, (key, _) in enumerate(hdrs):
                    if key == b"x-request-id":
                        hdrs[i] = (key, rid.encode())
                        break
                else:
                    hdrs.append((b"x-request-id", rid.encode()))
            headers_sent = True
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            _request_id_ctxvar.reset(token)
