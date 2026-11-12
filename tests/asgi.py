"""A forty-line ASGI driver, so the suite needs no HTTP client dependency."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

Scope = dict[str, Any]
Message = dict[str, Any]
ASGIApp = Callable[[Scope, Callable[[], Awaitable[Message]], Callable[[Message], Awaitable[None]]], Awaitable[None]]


@dataclass
class Result:
    status: int
    headers: dict[str, str]
    body: bytes
    receive_calls: int = 0
    sent: list[Message] = field(default_factory=list)

    def json(self) -> Any:
        return json.loads(self.body)


def call(
    app: ASGIApp,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b'{"hello": "world"}',
    method: str = "POST",
    path: str = "/work",
    scope_type: str = "http",
    receive: Callable[[], Awaitable[Message]] | None = None,
) -> Result:
    scope: Scope = {
        "type": scope_type,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json"), *(headers or [])],
        "client": ("127.0.0.1", 5000),
        "server": ("127.0.0.1", 8000),
    }
    result = Result(status=0, headers={}, body=b"")

    async def default_receive() -> Message:
        result.receive_calls += 1
        if result.receive_calls == 1:
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def counting(inner: Callable[[], Awaitable[Message]]) -> Message:
        result.receive_calls += 1
        return await inner()

    async def send(message: Message) -> None:
        result.sent.append(message)
        if message["type"] == "http.response.start":
            result.status = message["status"]
            result.headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in message.get("headers", [])}
        elif message["type"] == "http.response.body":
            result.body += message.get("body", b"")

    rcv = default_receive if receive is None else (lambda: counting(receive))
    asyncio.run(app(scope, rcv, send))
    return result
