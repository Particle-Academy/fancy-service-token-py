"""Read the verified claims in a Starlette or FastAPI handler.

    from fastapi import Depends
    from fancy_service_token.depends import service_token_claims

    @app.post("/work")
    def work(job: Job, claims: Claims = Depends(service_token_claims)): ...

This does NOT verify anything. Verification is the middleware's job, because
only middleware runs before FastAPI reads and validates a request body. If the
middleware did not verify this request, this refuses with a 401 rather than
handing back nothing, so a forgotten `add_middleware` fails loudly instead of
open. What the 401 looks like:

- **Behind `ServiceTokenMiddleware`** (an exempt path): the exact Fancy error
  envelope, `{error, message, requestId}`. Nothing to register.
- **Without the middleware, with the handler registered**: the exact envelope.

      app.add_exception_handler(ServiceTokenRefused, service_token_refused_handler)

- **With neither**: `ServiceTokenRefused` is an `HTTPException`, so the
  framework's own handler renders it. Still a 401 with `WWW-Authenticate` and
  `x-request-id`; FastAPI's body is `{"detail": <envelope>}`, Starlette's is the
  sentence as plain text. Register the handler for the exact shape.

Imports Starlette, which every Starlette and FastAPI app already has; the rest
of the package never does. It never imports FastAPI: Starlette's
`HTTPException` is the class FastAPI's handler is registered for.
"""

from __future__ import annotations

import logging
from typing import Any

from starlette.exceptions import HTTPException
from starlette.requests import HTTPConnection
from starlette.responses import Response

from ._token import Claims, Reason
from .asgi import MIDDLEWARE_KEY, REFUSAL_MESSAGES, STATE_KEY, ServiceTokenRefusal, refusal_response, request_id_from

logger = logging.getLogger("fancy_service_token")

__all__ = ["ServiceTokenRefused", "service_token_claims", "service_token_refused_handler"]


class ServiceTokenRefused(HTTPException, ServiceTokenRefusal):
    """A 401 refusal from `service_token_claims`, as an `HTTPException`.

    `detail` is the envelope dict when the app is a FastAPI app (FastAPI renders
    `{"detail": <envelope>}`) and the sentence otherwise (Starlette renders
    `detail` as plain text). The headers are always `WWW-Authenticate`,
    `x-request-id` and `Cache-Control: no-store`.
    """

    def __init__(self, reason: Reason = Reason.MISSING, request_id: str = "", *, envelope_detail: bool = True) -> None:
        rid = request_id or request_id_from(())
        _, headers = refusal_response(reason, rid)
        super().__init__(
            status_code=401,
            detail=REFUSAL_MESSAGES[reason],
            headers={
                k.decode("latin-1"): v.decode("latin-1")
                for k, v in headers
                if k not in (b"content-type", b"content-length")
            },
        )
        self.reason = reason
        self.request_id = rid
        self.envelope: dict[str, Any] = {
            "error": "service_token_refused",
            "message": REFUSAL_MESSAGES[reason],
            "requestId": rid,
        }
        if envelope_detail:
            self.detail = self.envelope  # type: ignore[assignment]  # FastAPI's detail is Any


def _is_fastapi(app: object) -> bool:
    return any(cls.__module__.split(".")[0] == "fastapi" for cls in type(app).__mro__)


def service_token_claims(request: HTTPConnection) -> Claims:
    claims = request.scope.get("state", {}).get(STATE_KEY)
    if isinstance(claims, Claims):
        return claims
    logger.error("service_token_claims used on a route ServiceTokenMiddleware did not verify; refusing")
    if request.scope.get(MIDDLEWARE_KEY):
        # The middleware is outside this app and renders the exact envelope. Not
        # an HTTPException, so the framework's own handler cannot take it first.
        raise ServiceTokenRefusal(Reason.MISSING)
    raise ServiceTokenRefused(
        Reason.MISSING,
        request_id_from(request.scope.get("headers", ())),
        envelope_detail=_is_fastapi(request.scope.get("app")),
    )


def service_token_refused_handler(request: HTTPConnection, exc: Exception) -> Response:
    """Render a `ServiceTokenRefused` as the exact 401 Fancy error envelope."""
    if isinstance(exc, ServiceTokenRefused):
        reason, request_id = exc.reason, exc.request_id
    else:
        reason, request_id = Reason.MISSING, request_id_from(request.scope.get("headers", ()))
    body, headers = refusal_response(reason, request_id)
    response = Response(content=body, status_code=401)
    for name, value in headers:
        if name != b"content-length":
            response.headers[name.decode("latin-1")] = value.decode("latin-1")
    return response
