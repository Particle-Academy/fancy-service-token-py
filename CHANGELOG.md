# Changelog

All notable changes to `fancy-service-token` (the Python leg) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0: breaking changes land in MINOR releases.** Read this file before
> upgrading a minor.

## [Unreleased]

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
