"""Read the verified claims in a Starlette or FastAPI handler.

    from fastapi import Depends
    from fancy_service_token.depends import service_token_claims

    @app.post("/work")
    def work(job: Job, claims: Claims = Depends(service_token_claims)): ...

This does NOT verify anything. Verification is the middleware's job, because
only middleware runs before FastAPI reads and validates a request body. If the
middleware did not verify this request, this refuses rather than handing back
nothing, so a forgotten `add_middleware` fails loudly instead of open.

The refusal is a `ServiceTokenRefused` exception, never an `HTTPException`:
FastAPI renders an `HTTPException` as `{"detail": ...}`, which is not the Fancy
error envelope. `ServiceTokenMiddleware` (on an exempt path) turns it into the
same 401 envelope it sends itself. An app WITHOUT the middleware registers the
handler once:

    app.add_exception_handler(ServiceTokenRefused, service_token_refused_handler)

With neither, the refusal is an unhandled exception: a 500, never a pass.

Imports Starlette, which every Starlette and FastAPI app already has; the rest
of the package never does.
"""

from __future__ import annotations

import logging

from starlette.requests import HTTPConnection
from starlette.responses import Response

from ._token import Claims
from .asgi import STATE_KEY, ServiceTokenRefused, refusal_response, request_id_from

logger = logging.getLogger("fancy_service_token")

__all__ = ["ServiceTokenRefused", "service_token_claims", "service_token_refused_handler"]


def service_token_claims(request: HTTPConnection) -> Claims:
    claims = request.scope.get("state", {}).get(STATE_KEY)
    if not isinstance(claims, Claims):
        logger.error("service_token_claims used on a route ServiceTokenMiddleware did not verify; refusing")
        raise ServiceTokenRefused()
    return claims


def service_token_refused_handler(request: HTTPConnection, exc: Exception) -> Response:
    """Render a `ServiceTokenRefused` as the 401 Fancy error envelope (request id from `x-request-id`)."""
    reason = exc.reason if isinstance(exc, ServiceTokenRefused) else ServiceTokenRefused().reason
    request_id = request_id_from(request.scope.get("headers", ()))
    body, headers = refusal_response(reason, request_id)
    response = Response(content=body, status_code=401)
    for name, value in headers:
        if name != b"content-length":
            response.headers[name.decode("latin-1")] = value.decode("latin-1")
    return response
