"""FastAPI: the body model is never parsed, and the handler never runs, on a refusal.

No `from __future__ import annotations` here, deliberately: FastAPI resolves a
handler's annotations at decoration time, and stringified ones naming a model
would turn the body into a query parameter.
"""

import pytest
from fastapi import Depends, FastAPI
from pydantic import BaseModel, field_validator

from fancy_service_token import Claims, ServiceTokenMiddleware
from fancy_service_token.depends import ServiceTokenRefused, service_token_claims, service_token_refused_handler

from .asgi import call
from .schema import validate
from .test_middleware import (
    HEADER,
    MESSAGES,
    TAMPERED,
    VALID,
    WRONG_AUDIENCE,
    assert_refusal,
    exploding_receive,
    make_verifier,
)

PARSED: list[str] = []


class Job(BaseModel):
    hello: str

    @field_validator("hello")
    @classmethod
    def record(cls, v: str) -> str:
        PARSED.append(v)
        return v


def test_fastapi_body_model_is_never_parsed_on_refusal() -> None:
    PARSED.clear()
    hits: list[str] = []
    app = FastAPI()
    app.add_middleware(ServiceTokenMiddleware, verifier=make_verifier())

    @app.post("/work")
    def work(job: Job, claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        hits.append("handler")
        return {"rid": claims.request_id, "hello": job.hello}

    for tok, reason in [(None, "missing"), (WRONG_AUDIENCE, "wrong_audience"), (TAMPERED, "bad_signature")]:
        headers = [] if tok is None else [(HEADER, tok.encode())]
        refused = call(app, headers=headers, receive=exploding_receive)
        assert_refusal(refused, reason)
        assert refused.receive_calls == 0
    garbage = call(app, headers=[(HEADER, b"fst1.garbage")], receive=exploding_receive)
    assert garbage.status == 401
    assert garbage.receive_calls == 0
    assert hits == []
    assert PARSED == []

    ok = call(app, headers=[(HEADER, VALID.encode())])
    assert ok.status == 200
    assert ok.json() == {"rid": "req-01HZX3K8Q2", "hello": "world"}
    assert PARSED == ["world"]

    replay = call(app, headers=[(HEADER, VALID.encode())], receive=exploding_receive)
    assert_refusal(replay, "replayed")
    assert replay.receive_calls == 0
    assert hits == ["handler"]
    assert PARSED == ["world"]


def test_fastapi_dependency_without_middleware_refuses_with_the_envelope() -> None:
    app = FastAPI()
    app.add_exception_handler(ServiceTokenRefused, service_token_refused_handler)

    @app.get("/work")
    def work(claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        return {"rid": claims.request_id}

    # A token is present, but nothing verified it: the dependency must not
    # treat "no middleware" as "nothing to check".
    result = call(app, method="GET", headers=[(HEADER, VALID.encode()), (b"x-request-id", b"rid-7")])
    assert_refusal(result, "missing")
    assert result.json()["requestId"] == "rid-7"


def test_fastapi_dependency_on_an_exempt_path_refuses_with_the_envelope_through_the_middleware() -> None:
    # The middleware is installed but skipped this path, so nothing verified it.
    # It still turns the dependency's refusal into the envelope: no handler needed.
    app = FastAPI()
    app.add_middleware(ServiceTokenMiddleware, verifier=make_verifier(), exempt_paths=["/work"])

    @app.get("/work")
    def work(claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        return {"rid": claims.request_id}

    result = call(app, method="GET", headers=[(HEADER, VALID.encode())])
    assert_refusal(result, "missing")


def test_fastapi_dependency_with_middleware_and_handler_is_still_the_exact_envelope() -> None:
    app = FastAPI()
    app.add_exception_handler(ServiceTokenRefused, service_token_refused_handler)
    app.add_middleware(ServiceTokenMiddleware, verifier=make_verifier(), exempt_paths=["/work"])

    @app.get("/work")
    def work(claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        return {"rid": claims.request_id}

    assert_refusal(call(app, method="GET"), "missing")


def test_fastapi_dependency_with_neither_middleware_nor_handler_is_a_401_with_the_envelope_as_detail() -> None:
    # Misconfigured twice over. FastAPI's own HTTPException handler renders it:
    # still a 401 with the right headers, never a 500 and never a pass.
    app = FastAPI()

    @app.get("/work")
    def work(claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        return {"rid": claims.request_id}

    result = call(app, method="GET", headers=[(HEADER, VALID.encode()), (b"x-request-id", b"rid-9")])
    assert result.status == 401
    body = result.json()
    assert sorted(body) == ["detail"]
    envelope = body["detail"]
    assert validate(envelope) == []
    assert envelope == {
        "error": "service_token_refused",
        "message": MESSAGES["messages"]["missing"],
        "requestId": "rid-9",
    }
    assert result.headers["www-authenticate"] == 'FancyServiceToken error="missing"'
    assert result.headers["x-request-id"] == "rid-9"
    assert result.headers["cache-control"] == "no-store"


def test_service_token_refused_is_an_http_exception() -> None:
    from starlette.exceptions import HTTPException

    from fancy_service_token import ServiceTokenRefusal

    assert issubclass(ServiceTokenRefused, HTTPException)
    assert issubclass(ServiceTokenRefused, ServiceTokenRefusal)


@pytest.mark.parametrize("handler", [False, True])
def test_starlette_dependency_without_middleware_is_a_401(handler: bool) -> None:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def work(request: Request) -> JSONResponse:
        return JSONResponse({"rid": service_token_claims(request).request_id})

    app = Starlette(routes=[Route("/work", work)])
    if handler:
        app.add_exception_handler(ServiceTokenRefused, service_token_refused_handler)
    result = call(app, method="GET", headers=[(b"x-request-id", b"rid-3")])
    if handler:
        assert_refusal(result, "missing")
    else:
        # Starlette renders an HTTPException's detail as plain text, so it gets
        # the sentence; the headers are the same.
        assert result.status == 401
        assert result.body.decode() == MESSAGES["messages"]["missing"]
        assert result.headers["www-authenticate"] == 'FancyServiceToken error="missing"'
        assert result.headers["x-request-id"] == "rid-3"
