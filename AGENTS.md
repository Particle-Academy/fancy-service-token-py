# Using fancy-service-token (Python) — guide for agents

How an agent installs and uses this package in a consumer app. What the package
is, is in [README.md](./README.md). Notes for working ON this repo's code are in
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Install

```bash
pip install fancy-service-token
```

- **Python:** `>=3.11`. Zero runtime dependencies; Starlette / FastAPI are only
  needed for the middleware you mount in them.
- The signer is the Laravel package `particle-academy/fancy-service-token`; this
  package only verifies. The Node verifier is
  `@particle-academy/fancy-service-token`.

## Find it on the Fancy MCP server

The catalog server is `https://ui.particle.academy/mcp` (streamable HTTP, no API
key; MCP id `fancy-ui`). This package is not yet listed there; it appears once
published. Find it then with `search-backend-packages` (stack `python`).

## API essentials

```python
from fancy_service_token import Claims, Key, ServiceTokenMiddleware, Verifier
from fancy_service_token.depends import service_token_claims

verifier = Verifier(
    keys=[Key("k2026b", bytes.fromhex(os.environ["SERVICE_TOKEN_KEY"]))],
    audience="ocr-sidecar",
    issuer="laravel-app",
)
app.add_middleware(ServiceTokenMiddleware, verifier=verifier)


@app.post("/ocr")
def ocr(job: Job, claims: Claims = Depends(service_token_claims)): ...
```

- **Starlette:** `Middleware(ServiceTokenMiddleware, verifier=verifier)`; claims
  are on `request.state.service_token`.
- `ServiceTokenMiddleware(app, verifier=..., header="x-fancy-service-token", exempt_paths=())`.
- The verified request id is `claims.request_id`, `current_request_id()` for the
  duration of the request, and on every log record via
  `handler.addFilter(RequestIdLogFilter())` (`%(request_id)s` in the format).
- Refusal reasons (`Reason`): `missing`, `malformed`, `bad_signature`,
  `expired`, `not_yet_valid`, `wrong_audience`, `replayed`. A refusal is `401`
  with `{"error": "service_token_refused", "reason": "..."}`; a WebSocket
  handshake is closed with `1008` before `accept`.
- Constructor limits and defaults (`clock_skew`, `max_lifetime`,
  `max_token_bytes`, `require_nonce`, `min_key_bytes`, `replay_store`, `clock`)
  are in the README's Configuration table.

## Traps

- **Verification must be the middleware, not a dependency.** FastAPI reads the
  body before resolving dependencies. `service_token_claims` only hands over
  claims, and refuses with `401` if the middleware is missing.
- **Secrets must be at least `min_key_bytes` (32) bytes**, passed as `bytes`.
- **`MemoryReplayStore` is per process.** Several workers need a shared store
  (an atomic `add(key, expires_at, now) -> bool`), or a nonce accepted by one
  worker can be replayed against another. A full store refuses;
  `replay_store=None` turns replay checks off.
- **Key rotation:** sign with the new key in Laravel; here hold both and give
  the old one `accept_until` (unix seconds, inclusive).
- **`exempt_paths` are exact matches**, meant for a health check.
- **A duplicated token header is `malformed`.**
- **Pre-1.0:** breaking changes land in MINOR releases.
