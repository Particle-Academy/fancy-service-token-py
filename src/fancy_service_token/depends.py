"""Read the verified claims in a Starlette or FastAPI handler.

    from fastapi import Depends
    from fancy_service_token.depends import service_token_claims

    @app.post("/work")
    def work(job: Job, claims: Claims = Depends(service_token_claims)): ...

This does NOT verify anything. Verification is the middleware's job, because
only middleware runs before FastAPI reads and validates a request body. If the
middleware is not installed, this refuses with 401 rather than handing back
nothing, so a forgotten `add_middleware` fails loudly instead of open.

Imports Starlette, which every Starlette and FastAPI app already has; the rest
of the package never does.
"""

from __future__ import annotations

import logging

from starlette.exceptions import HTTPException
from starlette.requests import HTTPConnection

from ._token import Claims
from .asgi import STATE_KEY

logger = logging.getLogger("fancy_service_token")


def service_token_claims(request: HTTPConnection) -> Claims:
    claims = request.scope.get("state", {}).get(STATE_KEY)
    if not isinstance(claims, Claims):
        logger.error("service_token_claims used on a route ServiceTokenMiddleware did not verify; refusing")
        raise HTTPException(status_code=401, detail="service_token_refused")
    return claims
