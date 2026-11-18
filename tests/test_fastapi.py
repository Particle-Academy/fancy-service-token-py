"""FastAPI: the body model is never parsed, and the handler never runs, on a refusal.

No `from __future__ import annotations` here, deliberately: FastAPI resolves a
handler's annotations at decoration time, and stringified ones naming a model
would turn the body into a query parameter.
"""

import pytest
from fastapi import Depends, FastAPI
from pydantic import BaseModel, field_validator

from fancy_service_token import Claims, ServiceTokenMiddleware, ServiceTokenRefused
from fancy_service_token.depends import service_token_claims, service_token_refused_handler

from .asgi import call
from .test_middleware import (
    HEADER,
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


def test_fastapi_dependency_with_neither_middleware_nor_handler_fails_closed() -> None:
    # Misconfigured twice over: nothing can render the refusal, so it is a
    # server error rather than a pass. Never a 200.
    app = FastAPI()

    @app.get("/work")
    def work(claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        return {"rid": claims.request_id}

    with pytest.raises(ServiceTokenRefused):
        call(app, method="GET", headers=[(HEADER, VALID.encode())])
