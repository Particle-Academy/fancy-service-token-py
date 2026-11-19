# Changelog

All notable changes to `fancy-service-token` (the Python leg) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0: breaking changes land in MINOR releases.** Read this file before
> upgrading a minor.

## [Unreleased]

### Changed

- CI: re-pin org third-party allowlist to 2614224

## [0.2.0] - 2026-11-18

### Changed

- **BREAKING: the 401 refusal body is now the Fancy error envelope**
  (`fancy-http-errors` `envelope.schema.json`), exactly
  `{"error": "service_token_refused", "message": "<sentence>", "requestId": "<id>"}`.
  **The body no longer has `reason`; read it from `WWW-Authenticate`**
  (`FancyServiceToken error="<reason>"`, unchanged since 0.1.0). If you only
  checked the 401 status, do nothing.
- **BREAKING (FastAPI/Starlette dependency, only without the middleware):**
  `service_token_claims` refuses with `ServiceTokenRefused` (from
  `fancy_service_token.depends`), a Starlette `HTTPException` with status 401
  and the `WWW-Authenticate`, `x-request-id` and `Cache-Control: no-store`
  headers, instead of `HTTPException(401, detail="service_token_refused")`.
  Behind `ServiceTokenMiddleware` (an exempt path) the body is the exact
  envelope: do nothing. Without the middleware, FastAPI's body is now
  `{"detail": <envelope>}` (Starlette's, the sentence as plain text); still a
  401. **Register
  `app.add_exception_handler(ServiceTokenRefused, service_token_refused_handler)`
  to get the exact envelope.** If you only checked the 401 status, do nothing.
- A WebSocket refusal is unchanged: close `1008` before `accept`, no body.

### Added

- `message`: one fixed English sentence per reason, `REFUSAL_MESSAGES`.
  Identical to the Node leg; both are pinned to
  `conformance/refusal-messages.json` (shipped in the sdist).
- `requestId`: the incoming `x-request-id` when it matches
  `^[A-Za-z0-9._:-]{1,128}$` (sent once), else a fresh UUID v4; echoed as an
  `x-request-id` response header. `ServiceTokenMiddleware(request_id_header=...)`
  changes the header name.
- `fancy_service_token.depends.ServiceTokenRefused` and
  `service_token_refused_handler`, and the framework-free base
  `fancy_service_token.ServiceTokenRefusal`, which `ServiceTokenMiddleware`
  renders as the envelope when an app raises it.
- The suite validates every refusal body against a byte copy of the envelope
  schema with a small first-party validator (no new dependency).

## [0.1.0] - 2026-11-18

First release (CC-fancy-0030).

### Added

- **`Verifier`**, a framework-free verifier for `fst1` service tokens:
  HMAC-SHA256 with `hmac` and `compare_digest` from the standard library, no JWT
  library and no runtime dependencies. Refuses with one `Reason` from a fixed
  set: `missing`, `malformed`, `bad_signature`, `expired`, `not_yet_valid`,
  `wrong_audience`, `replayed`. Never raises for any input.
- **Key rotation:** hold the current key and a previous key with an
  `accept_until`; the previous key is accepted until then and is
  `bad_signature` after.
- **Every limit is configurable, with secure defaults:** `clock_skew` 10 s,
  `max_lifetime` 300 s, `max_token_bytes` 1024, `require_nonce` on, keys of at
  least 32 bytes, and a per-process `MemoryReplayStore` (100,000 entries, fails
  closed when full). Bring a shared store for several workers.
- **`ServiceTokenMiddleware`**, pure ASGI, for Starlette and FastAPI. It
  verifies from the headers and refuses with `401` before the body is read and
  before the application is called; WebSocket handshakes are closed with `1008`.
  The response carries the reason and nothing else.
- **The verified request id** reaches handlers (`request.state.service_token`,
  `fancy_service_token.depends.service_token_claims`, `current_request_id()`)
  and logs (`RequestIdLogFilter`).
- **Shared conformance fixtures** (`conformance/service-token-v1.json`, 37 verify
  cases and 2 sign cases), generated from the format definition alone by
  `scripts/build_fixtures.py` and run byte for byte by the PHP and Node legs.
- A sabotage sweep in CI that breaks one clause at a time and fails if the suite
  does not notice.

### Changed

- **CI: the lab-certificate gate verifies against the lab's rotated key list.**
  The lab's first signing key is retired: certificates it already issued still
  verify, and nothing new it signs ever can. Consumers do nothing.

- **CI: the third-party gate and the lab-certificate verifier are pinned to
  `Particle-Academy/.github@8c620be`**, the allowlist that records the framework
  test carve-out for this package (Starlette and FastAPI, test-only). Consumers
  do nothing.

- **Lint:** the `AGENTS.md` FastAPI example is in ruff's format. No code
  changed; nothing to do.

- **Docs:** `AGENTS.md` is now the guide to using this package (install, how to find it on the Fancy MCP catalog server once it is listed, API essentials, traps). The contributor notes it held moved to `CONTRIBUTING.md`, and `CLAUDE.md` is now a symlink to it. The README points to the MCP server and to `AGENTS.md`. No code changed; nothing to do.

### Notes

- **Starlette and FastAPI are TEST dependencies only**, under the framework
  carve-out in the envelope's rules: they are the frameworks this package exists
  to integrate with. `dependencies` is empty, and a CI job runs the
  framework-free suites with both absent.
