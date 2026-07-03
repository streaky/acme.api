"""Request ID middleware for FastAPI.

Injects a unique request ID into each HTTP request's context,
which is then logged by the structured JSON formatter.
"""

from __future__ import annotations

import re
from typing import Any, Callable, cast
from uuid import uuid4

from acme_api.logging import request_id as _request_id_ctxvar

ASGIApp = Callable[[Any, Any, Any], Any]
_MAX_REQUEST_ID_LENGTH = 128
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


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

        rid = self._get_request_id(scope)
        token = _request_id_ctxvar.set(rid)
        state = scope.setdefault("state", {})
        state["request_id"] = rid

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
                message["headers"] = hdrs
            headers_sent = True
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            _request_id_ctxvar.reset(token)

    @staticmethod
    def _get_request_id(scope: dict[str, Any]) -> str:
        """Return a validated request ID header value or generate a new ID.

        Security invariant: client-supplied request IDs must be short and use a
        restricted character set so they are safe for response headers and logs.
        """
        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        for key, value in headers:
            if key.lower() == b"x-request-id":
                decoded = value.decode("latin-1").strip()
                if (
                    decoded
                    and len(decoded) <= _MAX_REQUEST_ID_LENGTH
                    and _REQUEST_ID_PATTERN.fullmatch(decoded)
                ):
                    return decoded
        return str(uuid4())
