# fancy-service-token (Python)

Verify Fancy service tokens in a Python sidecar. A Laravel app signs a
short-lived token on every request it makes to its sidecar
([`particle-academy/fancy-service-token`](https://github.com/Particle-Academy/fancy-service-token));
this package checks it **before the request body is read** and refuses every
other caller with a named reason.

- Framework-free core, plus pure-ASGI middleware for Starlette and FastAPI.
- HMAC-SHA256 with the standard library only (`hmac`, `compare_digest`). No JWT
  library, no cryptography of our own, zero runtime dependencies.
- Refusals carry one reason from a fixed set, never exception text, and no log
  line ever contains a token or a secret.
- The verified request id reaches your handlers and your logs.

The Node mirror is [`@particle-academy/fancy-service-token`](https://github.com/Particle-Academy/fancy-service-token-js).
All three legs run the same fixture file byte for byte.

<!-- fancy-agents-note:start -->
> **For agents.** This package is not listed on the Fancy MCP catalog server
> yet. The server, `https://ui.particle.academy/mcp` (streamable HTTP, no API key; MCP id
> `fancy-ui`), lists the released Fancy packages with install commands and
> docs. How an agent installs and uses this package is in [AGENTS.md](https://github.com/Particle-Academy/fancy-service-token-py/blob/main/AGENTS.md).
<!-- fancy-agents-note:end -->

## Install

```bash
pip install fancy-service-token
```

## FastAPI

```python
from fastapi import Depends, FastAPI
from fancy_service_token import Claims, Key, ServiceTokenMiddleware, Verifier
from fancy_service_token.depends import service_token_claims

verifier = Verifier(
    keys=[Key("k2026b", bytes.fromhex(os.environ["SERVICE_TOKEN_KEY"]))],
    audience="ocr-sidecar",
    issuer="laravel-app",
)

app = FastAPI()
app.add_middleware(ServiceTokenMiddleware, verifier=verifier)


@app.post("/ocr")
def ocr(job: Job, claims: Claims = Depends(service_token_claims)):
    log.info("ocr for %s", claims.request_id)
```

Verification lives in the **middleware**, not in a dependency, on purpose:
FastAPI reads and validates a request body before it resolves dependencies, so a
dependency cannot refuse "before the body is read". `service_token_claims` only
hands the verified claims to a handler. If the middleware is missing it refuses
with `401` rather than returning nothing, so a forgotten `add_middleware` fails
closed.

## Starlette

```python
from starlette.middleware import Middleware

app = Starlette(routes=routes, middleware=[Middleware(ServiceTokenMiddleware, verifier=verifier)])


async def handler(request):
    claims = request.state.service_token  # or service_token_claims(request)
```

## Refusals

Every refusal is `401` with `Cache-Control: no-store`, a
`WWW-Authenticate: FancyServiceToken error="<reason>"` header, and this body:

```json
{"error": "service_token_refused", "reason": "expired"}
```

| reason | means |
|---|---|
| `missing` | no token header, or an empty one |
| `malformed` | not a well-formed `fst1` token (see the format below), longer than `max_token_bytes`, a lifetime above `max_lifetime`, no nonce while `require_nonce` is on, or the token header sent twice |
| `bad_signature` | the HMAC does not match, the key id is unknown, the key is a previous key past its grace window, or the issuer is not the configured one (no key is held for that issuer) |
| `expired` | `now >= exp + clock_skew` |
| `not_yet_valid` | `now + clock_skew < iat` |
| `wrong_audience` | signed correctly, for a different sidecar |
| `replayed` | the nonce was already accepted (or the replay store is full: it fails closed) |

A WebSocket handshake is refused with a close (`1008`) before `accept`.

## Request id

The token carries the caller's request id, signed. After verification it is in
`request.state.service_token.request_id`, in `current_request_id()` for the
duration of the request, and on every log record through a filter:

```python
handler.addFilter(RequestIdLogFilter())
logging.Formatter("%(asctime)s %(request_id)s %(message)s")
```

Use it to join a sidecar log line to the Laravel request that caused it.

## Configuration

Every limit is a constructor argument with a secure default.

| argument | default | |
|---|---|---|
| `keys` | required | `Key(kid, secret_bytes, accept_until=None)`; secrets of at least `min_key_bytes` |
| `audience` | required | this sidecar's name |
| `issuer` | required | the Laravel app's name |
| `clock_skew` | `10` | seconds of tolerance on both ends of the window |
| `max_lifetime` | `300` | the longest `exp - iat` accepted |
| `max_token_bytes` | `1024` | checked before any parsing |
| `require_nonce` | `True` | refuse tokens without a nonce |
| `min_key_bytes` | `32` | |
| `replay_store` | `MemoryReplayStore()` | anything with an atomic `add(key, expires_at, now) -> bool`; `None` turns replay checks off |
| `clock` | `time.time` | |

`ServiceTokenMiddleware(app, verifier=..., header="x-fancy-service-token", exempt_paths=())`.
`exempt_paths` are exact matches, for a health check.

`MemoryReplayStore(max_entries=100_000)` is per process. A sidecar running
several workers needs a shared store, or a nonce accepted by one worker can be
replayed against another.

### Key rotation

Sign with the new key in Laravel; here, hold both, and give the old one an
`accept_until`:

```python
keys = [Key("k2026b", new_secret), Key("k2026a", old_secret, accept_until=1793000030)]
```

After `accept_until` (unix seconds, inclusive) a token signed with the old key is
`bad_signature`.

## The token format (`fst1`)

```
fst1.<payload>.<signature>
```

- `payload` is the **unpadded base64url** (RFC 4648 section 5) of seven ASCII
  fields joined by a single LF (`0x0A`), in this order, with no trailing LF:

  | # | field | grammar |
  |---|---|---|
  | 1 | `kid` key id | 1-64 of `[A-Za-z0-9._-]` |
  | 2 | `iss` issuer | 1-128 of `[A-Za-z0-9._:/-]` |
  | 3 | `aud` audience | 1-128 of `[A-Za-z0-9._:/-]` |
  | 4 | `iat` issued at | unix seconds, decimal, 1-12 digits, no leading zero |
  | 5 | `exp` expires at | as `iat`; must be greater than `iat` |
  | 6 | `rid` request id | 1-128 of `[A-Za-z0-9._:-]` |
  | 7 | `nonce` | empty, or 16-128 of `[A-Za-z0-9_-]` |

- `signature` is the unpadded base64url of
  `HMAC-SHA256(secret, ASCII("fst1." + payload))`: always 32 bytes, so always 43
  characters.
- base64url must be **canonical**: the right alphabet, no padding, no
  whitespace, and the unused low bits of the last character clear. A second
  spelling of the same bytes is `malformed`.
- The token is sent in one header, `X-Fancy-Service-Token` by default.

The verifier checks, in this order, and stops at the first failure (the order
decides the reason when a token is wrong in two ways, and the fixtures pin it):

1. absent or empty: `missing`
2. longer than `max_token_bytes`: `malformed`
3. not exactly three dot-separated parts, prefix not `fst1`, signature not 43
   characters, either part not canonical base64url: `malformed`
4. payload not ASCII, not exactly seven fields, a field outside its grammar,
   `exp <= iat`, `exp - iat > max_lifetime`, or no nonce while one is required:
   `malformed`
5. unknown `kid`, HMAC mismatch (compared in constant time), a previous key past
   `accept_until`, or `iss` not the configured issuer: `bad_signature`
6. `aud` not this sidecar: `wrong_audience`
7. `now + clock_skew < iat`: `not_yet_valid`
8. `now >= exp + clock_skew`: `expired`
9. nonce already recorded: `replayed`. The nonce is recorded only here, so a
   token refused for any earlier reason never spends one.

There is no `alg` field and nothing to negotiate: one format, one algorithm.

## Conformance

`conformance/service-token-v1.json` is generated by `scripts/build_fixtures.py`
from the format definition alone (raw `hmac`, not this package) and copied byte
for byte into the PHP and Node repositories. Each suite pins its SHA-256.

## License

MIT
