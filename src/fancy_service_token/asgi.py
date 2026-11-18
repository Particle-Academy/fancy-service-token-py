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
import uuid
from collections.abc import Awaitable, Callable, Collection, Iterable, MutableMapping
from types import MappingProxyType
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


REFUSAL_MESSAGES: MappingProxyType[Reason, str] = MappingProxyType(
    {
        # The `message` of a refusal: one fixed sentence per reason. The Node leg
        # carries the same table; both are compared against
        # conformance/refusal-messages.json in their suites.
        Reason.MISSING: "This request carries no service token.",
        Reason.MALFORMED: "The service token could not be read.",
        Reason.BAD_SIGNATURE: "The service token signature does not match a known key.",
        Reason.EXPIRED: "The service token has expired.",
        Reason.NOT_YET_VALID: "The service token is not valid yet.",
        Reason.WRONG_AUDIENCE: "The service token was issued for a different service.",
        Reason.REPLAYED: "The service token has already been used.",
    }
)

_RID_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")


class ServiceTokenRefused(Exception):  # noqa: N818 -- a refusal, not an error in the code
    """Raised by `service_token_claims` when nothing verified this request.

    `ServiceTokenMiddleware` turns it into the same 401 envelope it sends itself.
    Without the middleware, register `depends.service_token_refused_handler`.
    """

    def __init__(self, reason: Reason = Reason.MISSING) -> None:
        super().__init__(reason.value)
        self.reason = reason


def request_id_from(headers: Iterable[tuple[bytes, bytes]], header: str = "x-request-id") -> str:
    """The incoming request id when it matches `^[A-Za-z0-9._:-]{1,128}$`, else a fresh UUID v4.

    A header sent twice is not trusted. Checked per byte, no regular expression.
    """
    name = header.lower().encode("latin-1")
    values = [v for k, v in headers if k.lower() == name]
    if len(values) == 1 and 1 <= len(values[0]) <= 128 and all(b in _RID_CHARS for b in values[0]):
        return values[0].decode("ascii")
    return str(uuid.uuid4())


def refusal_response(
    reason: Reason, request_id: str, request_id_header: str = "x-request-id"
) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    """The 401 body and headers for a refusal: the Fancy error envelope, exactly
    `{error, message, requestId}`, with the reason in WWW-Authenticate."""
    body = json.dumps(
        {"error": "service_token_refused", "message": REFUSAL_MESSAGES[reason], "requestId": request_id},
        separators=(",", ":"),
    ).encode("ascii")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"www-authenticate", f'FancyServiceToken error="{reason.value}"'.encode("ascii")),
        (request_id_header.lower().encode("latin-1"), request_id.encode("ascii")),
    ]
    return body, headers


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
        request_id_header: str = "x-request-id",
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.header = header.lower().encode("latin-1")
        self.exempt_paths = frozenset(exempt_paths)
        self.request_id_header = request_id_header.lower()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if scope.get("path") in self.exempt_paths:
            await self._run(scope, receive, send)
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
            await self._refuse(scope, refused, send)
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
            await self._run(scope, receive, send)
        finally:
            _request_id.reset(token)

    async def _run(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Call the app; a `ServiceTokenRefused` from inside it becomes the same refusal."""
        started = False

        async def tracking(message: Message) -> None:
            nonlocal started
            if message.get("type") in ("http.response.start", "websocket.accept", "websocket.close"):
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking)
        except ServiceTokenRefused as exc:
            if started:
                raise
            logger.warning(
                "service token refused: %s", exc.reason.value, extra={"service_token_reason": exc.reason.value}
            )
            await self._refuse(scope, exc.reason, send)

    async def _refuse(self, scope: Scope, reason: Reason, send: Send) -> None:
        if scope.get("type") == "websocket":
            # Before accept: a close is a refusal of the handshake (403 on most
            # servers). A close frame carries no body, so no envelope here.
            await send({"type": "websocket.close", "code": 1008})
            return
        request_id = request_id_from(scope.get("headers", ()), self.request_id_header)
        body, headers = refusal_response(reason, request_id, self.request_id_header)
        await send({"type": "http.response.start", "status": 401, "headers": headers})
        await send({"type": "http.response.body", "body": body})
