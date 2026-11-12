"""Hostile tests for the ASGI middleware, on raw ASGI, Starlette and FastAPI.

The property that matters most: a refused request never reaches the handler and
its body stream is never read. Each test proves both, by counting.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from fancy_service_token import (
    Claims,
    Key,
    MemoryReplayStore,
    RequestIdLogFilter,
    ServiceTokenMiddleware,
    Verifier,
    current_request_id,
)

from .asgi import call
from .conftest import load_fixtures

FX = load_fixtures()
VALID = FX["sign"][0]["token"]
SECRET = bytes.fromhex(FX["sign"][0]["input"]["secret_hex"])
SIG = VALID.split(".")[2]
NOW = 1793000005
HEADER = b"x-fancy-service-token"


def case_token(name: str) -> str:
    return next(c for c in FX["verify"] if c["name"] == name)["steps"][0]["token"]


WRONG_AUDIENCE = case_token("wrong_audience")
TAMPERED = case_token("tampered_signature")


def make_verifier(**kw: Any) -> Verifier:
    args: dict[str, Any] = {
        "keys": [Key("k2026b", SECRET)],
        "audience": "ocr-sidecar",
        "issuer": "laravel-app",
        "clock": lambda: NOW,
        "replay_store": MemoryReplayStore(),
    }
    args.update(kw)
    return Verifier(**args)


class Spy:
    """An ASGI app that records whether it ran, and reads the body when it does."""

    def __init__(self) -> None:
        self.calls = 0
        self.body = b""
        self.scope: dict[str, Any] = {}
        self.request_id_seen: str | None = None

    async def __call__(self, scope: Any, receive: Callable[[], Awaitable[Any]], send: Any) -> None:
        self.calls += 1
        self.scope = scope
        self.request_id_seen = current_request_id()
        message = await receive()
        self.body = message.get("body", b"")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def exploding_receive() -> Any:
    raise AssertionError("the body stream was read")


# ---------------------------------------------------------------- raw ASGI


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ([], "missing"),
        ([(HEADER, b"")], "missing"),
        ([(HEADER, b"not-a-token")], "malformed"),
        ([(HEADER, WRONG_AUDIENCE.encode())], "wrong_audience"),
        ([(HEADER, TAMPERED.encode())], "bad_signature"),
    ],
)
def test_refused_request_never_touches_handler_or_body(headers: list[tuple[bytes, bytes]], reason: str) -> None:
    spy = Spy()
    result = call(ServiceTokenMiddleware(spy, verifier=make_verifier()), headers=headers, receive=exploding_receive)
    assert result.status == 401
    assert result.json() == {"error": "service_token_refused", "reason": reason}
    assert spy.calls == 0
    assert result.receive_calls == 0


def test_replayed_nonce_is_refused_before_the_body() -> None:
    mw = ServiceTokenMiddleware(Spy(), verifier=make_verifier())
    first = call(mw, headers=[(HEADER, VALID.encode())])
    assert first.status == 200
    spy = Spy()
    again = call(
        ServiceTokenMiddleware(spy, verifier=mw.verifier), headers=[(HEADER, VALID.encode())], receive=exploding_receive
    )
    assert again.status == 401
    assert again.json()["reason"] == "replayed"
    assert spy.calls == 0
    assert again.receive_calls == 0


def test_two_token_headers_are_refused_as_malformed() -> None:
    spy = Spy()
    result = call(
        ServiceTokenMiddleware(spy, verifier=make_verifier()),
        headers=[(HEADER, VALID.encode()), (HEADER, VALID.encode())],
        receive=exploding_receive,
    )
    assert result.json()["reason"] == "malformed"
    assert spy.calls == 0


def test_accepted_request_reaches_handler_with_claims_and_request_id() -> None:
    spy = Spy()
    result = call(ServiceTokenMiddleware(spy, verifier=make_verifier()), headers=[(HEADER, VALID.encode())])
    assert result.status == 200
    assert spy.calls == 1
    assert spy.body == b'{"hello": "world"}'
    claims = spy.scope["state"]["service_token"]
    assert isinstance(claims, Claims)
    assert claims.request_id == "req-01HZX3K8Q2"
    assert spy.request_id_seen == "req-01HZX3K8Q2"
    assert current_request_id() is None  # reset once the request is done


def test_header_name_is_configurable_and_case_insensitive() -> None:
    spy = Spy()
    mw = ServiceTokenMiddleware(spy, verifier=make_verifier(), header="X-Sidecar-Auth")
    assert call(mw, headers=[(b"x-sidecar-auth", VALID.encode())]).status == 200
    assert call(mw, headers=[(HEADER, VALID.encode())], receive=exploding_receive).json()["reason"] == "missing"


def test_exempt_paths_are_exact_matches_only() -> None:
    spy = Spy()
    mw = ServiceTokenMiddleware(spy, verifier=make_verifier(), exempt_paths=["/healthz"])
    assert call(mw, path="/healthz", method="GET").status == 200
    assert call(mw, path="/healthz/../work", receive=exploding_receive).status == 401
    assert call(mw, path="/healthzz", receive=exploding_receive).status == 401


def test_lifespan_passes_through() -> None:
    seen: list[str] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    import asyncio

    async def noop() -> Any:
        return {"type": "lifespan.startup"}

    async def nosend(_: Any) -> None:
        return None

    asyncio.run(ServiceTokenMiddleware(app, verifier=make_verifier())({"type": "lifespan"}, noop, nosend))
    assert seen == ["lifespan"]


def test_websocket_refused_with_policy_close_before_accept() -> None:
    spy = Spy()
    result = call(
        ServiceTokenMiddleware(spy, verifier=make_verifier()), scope_type="websocket", receive=exploding_receive
    )
    assert spy.calls == 0
    assert result.sent == [{"type": "websocket.close", "code": 1008}]


def test_a_verifier_that_raises_fails_closed_without_exception_text(caplog: pytest.LogCaptureFixture) -> None:
    class Boom(Verifier):
        def verify(self, token: Any, now: Any = None) -> Any:
            raise RuntimeError("secret detail " + SECRET.hex())

    spy = Spy()
    v = Boom(keys=[Key("k2026b", SECRET)], audience="a", issuer="i")
    with caplog.at_level(logging.DEBUG, logger="fancy_service_token"):
        result = call(
            ServiceTokenMiddleware(spy, verifier=v), headers=[(HEADER, VALID.encode())], receive=exploding_receive
        )
    assert result.status == 401
    assert result.json() == {"error": "service_token_refused", "reason": "malformed"}
    assert b"secret detail" not in result.body
    assert "secret detail" not in caplog.text
    assert SECRET.hex() not in caplog.text
    assert "RuntimeError" in caplog.text
    assert spy.calls == 0


def test_logs_never_carry_token_or_secret(caplog: pytest.LogCaptureFixture) -> None:
    mw = ServiceTokenMiddleware(Spy(), verifier=make_verifier())
    with caplog.at_level(logging.DEBUG, logger="fancy_service_token"):
        for tok in [VALID, VALID, WRONG_AUDIENCE, TAMPERED, "garbage"]:
            call(mw, headers=[(HEADER, tok.encode())])
    text = caplog.text
    assert "replayed" in text
    assert "wrong_audience" in text
    for needle in [VALID, SIG, WRONG_AUDIENCE, TAMPERED, VALID.split(".")[1], SECRET.hex(), "garbage"]:
        assert needle not in text
    # The accepted request is logged with its verified request id.
    assert "req-01HZX3K8Q2" in text


def test_request_id_log_filter_stamps_records() -> None:
    records: list[logging.LogRecord] = []

    class Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    log = logging.getLogger("tests.handler")
    handler = Grab()
    handler.addFilter(RequestIdLogFilter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    async def app(scope: Any, receive: Any, send: Any) -> None:
        log.info("inside")
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    try:
        call(ServiceTokenMiddleware(app, verifier=make_verifier()), headers=[(HEADER, VALID.encode())])
        log.info("outside")
    finally:
        log.removeHandler(handler)
    assert [getattr(r, "request_id", None) for r in records] == ["req-01HZX3K8Q2", "-"]


# ---------------------------------------------------------------- Starlette


def test_starlette_route_with_body_is_never_reached_on_refusal() -> None:
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from fancy_service_token.depends import service_token_claims

    hits: list[str] = []

    async def work(request: Request) -> JSONResponse:
        hits.append("handler")
        body = await request.json()
        claims = service_token_claims(request)
        return JSONResponse({"rid": claims.request_id, "body": body})

    app = Starlette(
        routes=[Route("/work", work, methods=["POST"])],
        middleware=[Middleware(ServiceTokenMiddleware, verifier=make_verifier())],
    )
    refused = call(app, headers=[(HEADER, TAMPERED.encode())], receive=exploding_receive)
    assert refused.status == 401
    assert refused.json()["reason"] == "bad_signature"
    assert hits == []
    assert refused.receive_calls == 0

    ok = call(app, headers=[(HEADER, VALID.encode())])
    assert ok.status == 200
    assert ok.json() == {"rid": "req-01HZX3K8Q2", "body": {"hello": "world"}}
