"""Pure-ASGI middleware: verify the token from the headers, before the body exists.

The headers of an ASGI request are in `scope`; the body only arrives through
`receive()`. A refusal here therefore happens with `receive` never called and
the application never invoked, which is the whole point: a hostile caller's
body is never parsed, validated or buffered. Works under Starlette, FastAPI and
any other ASGI server, and imports neither.
"""

from __future__ import annotations

import contextvars
import json
import logging
from collections.abc import Awaitable, Callable, Collection, MutableMapping
from typing import Any

from ._token import Claims, Reason, Verifier

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

logger = logging.getLogger("fancy_service_token")

STATE_KEY = "service_token"
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("fancy_service_token_request_id", default=None)


def current_request_id() -> str | None:
    """The VERIFIED request id of the request being handled, or None outside one."""
    return _request_id.get()


class RequestIdLogFilter(logging.Filter):
    """Stamps `record.request_id` (or "-") so a log format can carry it."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get() or "-"
        return True


class ServiceTokenMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: Verifier,
        header: str = "x-fancy-service-token",
        exempt_paths: Collection[str] = (),
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.header = header.lower().encode("latin-1")
        self.exempt_paths = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind not in ("http", "websocket") or scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        values = [v for k, v in scope.get("headers", ()) if k.lower() == self.header]
        if len(values) > 1:
            reason: Reason | None = Reason.MALFORMED
            claims: Claims | None = None
        else:
            try:
                verdict = self.verifier.verify(values[0] if values else None)
                reason, claims = verdict.reason, verdict.claims
                if not verdict.ok and reason is None:
                    reason = Reason.MALFORMED
            except Exception as exc:  # fail closed; log the class, never the text
                logger.error("service token verifier raised %s; refusing", type(exc).__name__)
                reason, claims = Reason.MALFORMED, None

        if reason is not None or claims is None:
            refused = reason or Reason.MALFORMED
            logger.warning("service token refused: %s", refused.value, extra={"service_token_reason": refused.value})
            await self._refuse(kind, refused, send)
            return

        state = dict(scope.get("state") or {})
        state[STATE_KEY] = claims
        scope = dict(scope)
        scope["state"] = state
        token = _request_id.set(claims.request_id)
        try:
            logger.debug(
                "service token accepted for request %s", claims.request_id, extra={"request_id": claims.request_id}
            )
            await self.app(scope, receive, send)
        finally:
            _request_id.reset(token)

    @staticmethod
    async def _refuse(kind: Any, reason: Reason, send: Send) -> None:
        if kind == "websocket":
            # Before accept: a close is a refusal of the handshake (403 on most servers).
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"error": "service_token_refused", "reason": reason.value}).encode("ascii")
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"www-authenticate", f'FancyServiceToken error="{reason.value}"'.encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
