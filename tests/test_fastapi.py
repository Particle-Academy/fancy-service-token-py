"""FastAPI: the body model is never parsed, and the handler never runs, on a refusal.

No `from __future__ import annotations` here, deliberately: FastAPI resolves a
handler's annotations at decoration time, and stringified ones naming a model
would turn the body into a query parameter.
"""

from fastapi import Depends, FastAPI
from pydantic import BaseModel, field_validator

from fancy_service_token import Claims, ServiceTokenMiddleware
from fancy_service_token.depends import service_token_claims

from .asgi import call
from .test_middleware import HEADER, TAMPERED, VALID, WRONG_AUDIENCE, exploding_receive, make_verifier

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

    for tok in [None, WRONG_AUDIENCE, TAMPERED, "fst1.garbage"]:
        headers = [] if tok is None else [(HEADER, tok.encode())]
        refused = call(app, headers=headers, receive=exploding_receive)
        assert refused.status == 401
        assert refused.receive_calls == 0
    assert hits == []
    assert PARSED == []

    ok = call(app, headers=[(HEADER, VALID.encode())])
    assert ok.status == 200
    assert ok.json() == {"rid": "req-01HZX3K8Q2", "hello": "world"}
    assert PARSED == ["world"]

    replay = call(app, headers=[(HEADER, VALID.encode())], receive=exploding_receive)
    assert replay.status == 401
    assert replay.json() == {"error": "service_token_refused", "reason": "replayed"}
    assert replay.receive_calls == 0
    assert hits == ["handler"]
    assert PARSED == ["world"]


def test_fastapi_dependency_without_middleware_refuses_rather_than_passing() -> None:
    app = FastAPI()

    @app.get("/work")
    def work(claims: Claims = Depends(service_token_claims)) -> dict[str, str]:
        return {"rid": claims.request_id}

    # A token is present, but nothing verified it: the dependency must not
    # treat "no middleware" as "nothing to check".
    result = call(app, method="GET", headers=[(HEADER, VALID.encode())])
    assert result.status == 401
    assert result.json() == {"detail": "service_token_refused"}
