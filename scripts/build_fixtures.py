"""Build conformance/service-token-v1.json, the fixture set every leg runs.

This is the REFERENCE, and it deliberately does not import the package. Every
token here is built from the format's definition with the standard library's
`hmac` and `base64`, so a verifier bug cannot leak into the fixtures it is
judged against. Run it, then copy the output byte for byte into the PHP and
Node repositories; each suite pins the file's SHA-256, so a copy that drifts
fails every leg rather than only the one that was edited.

    python scripts/build_fixtures.py

Writes with an explicit LF newline so the bytes do not depend on the platform.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

PREFIX = "fst1"
OUT = Path(__file__).resolve().parent.parent / "conformance" / "service-token-v1.json"


def secret(label: str) -> bytes:
    # Test keys only: derived, so the file explains where they came from.
    return hashlib.sha256(("fancy-service-token test key " + label).encode()).digest()


KEYS = {
    "k2026a": secret("k2026a"),  # the previous key
    "k2026b": secret("k2026b"),  # the current key
    "k-other": secret("k-other"),  # a key the verifier does not hold
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def payload(f: dict[str, Any]) -> bytes:
    lines = [f["kid"], f["iss"], f["aud"], str(f["iat"]), str(f["exp"]), f["rid"], f["nonce"]]
    return "\n".join(lines).encode("utf-8")


def token_from_bytes(raw: bytes, key: bytes) -> str:
    p = b64(raw)
    signing_input = (PREFIX + "." + p).encode("ascii")
    return PREFIX + "." + p + "." + b64(hmac.new(key, signing_input, hashlib.sha256).digest())


def token(**over: Any) -> str:
    """BASE with fields overridden; `_sign_with` signs under a different key than `kid` names."""
    sign_with = over.pop("_sign_with", None)
    f = {**BASE, **over}
    return token_from_bytes(payload(f), KEYS[sign_with or f["kid"]])


BASE: dict[str, Any] = {
    "kid": "k2026b",
    "iss": "laravel-app",
    "aud": "ocr-sidecar",
    "iat": 1793000000,
    "exp": 1793000060,
    "rid": "req-01HZX3K8Q2",
    "nonce": "n0nce-AAAAAAAAAAAAAAAA",
}
NOW = 1793000005

VERIFIER = {
    "audience": "ocr-sidecar",
    "issuer": "laravel-app",
    "clock_skew": 10,
    "max_lifetime": 300,
    "max_token_bytes": 1024,
    "require_nonce": True,
    "keys": [
        {"kid": "k2026b", "secret_hex": KEYS["k2026b"].hex(), "accept_until": None},
        {"kid": "k2026a", "secret_hex": KEYS["k2026a"].hex(), "accept_until": 1793000030},
    ],
}


def ok(rid: str = BASE["rid"]) -> dict[str, Any]:
    return {"ok": True, "reason": None, "request_id": rid}


def no(reason: str) -> dict[str, Any]:
    return {"ok": False, "reason": reason, "request_id": None}


def case(name: str, why: str, steps: list[dict[str, Any]], verifier: dict[str, Any] | None = None) -> dict[str, Any]:
    v = dict(VERIFIER)
    v.update(verifier or {})
    return {"name": name, "why": why, "verifier": v, "steps": steps}


def step(tok: str | None, expect: dict[str, Any], now: int = NOW) -> dict[str, Any]:
    return {"token": tok, "now": now, "expect": expect}


def flip_char(s: str, index: int) -> str:
    c = s[index]
    return s[:index] + ("B" if c != "B" else "C") + s[index + 1 :]


valid = token()
_, p_valid, s_valid = valid.split(".")

# A payload changed after signing: the audience swapped, the signature kept.
tampered_payload = PREFIX + "." + b64(payload({**BASE, "aud": "billing-sidecar"})) + "." + s_valid

# Non-canonical base64url: the last character of a 43-char signature carries two
# unused bits. Setting them gives a string that DECODES to the same bytes, so a
# lenient decoder would accept a second spelling of one signature.
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
idx = alphabet.index(s_valid[-1])
assert idx & 0b11 == 0, "a canonical 43-char signature has its two spare bits clear"
noncanon_sig = s_valid[:-1] + alphabet[idx | 0b01]
assert base64.urlsafe_b64decode(noncanon_sig + "=") == base64.urlsafe_b64decode(s_valid + "=")

no_nonce = token(nonce="")

VERIFY = [
    case("valid", "A current-key token for this audience, inside its window.", [step(valid, ok())]),
    case("valid_at_skew_before_iat", "now = iat - skew is still accepted.", [step(valid, ok(), now=BASE["iat"] - 10)]),
    case(
        "valid_last_second",
        "now = exp + skew - 1 is the last accepted second.",
        [step(valid, ok(), now=BASE["exp"] + 9)],
    ),
    case(
        "expired",
        "now = exp + skew: exp is exclusive, so this is refused.",
        [step(valid, no("expired"), now=BASE["exp"] + 10)],
    ),
    case("expired_long_ago", "A day after expiry.", [step(valid, no("expired"), now=BASE["exp"] + 86400)]),
    case("not_yet_valid", "now = iat - skew - 1.", [step(valid, no("not_yet_valid"), now=BASE["iat"] - 11)]),
    case(
        "wrong_audience",
        "Signed correctly, for another sidecar.",
        [step(token(aud="billing-sidecar"), no("wrong_audience"))],
    ),
    case(
        "tampered_signature",
        "One signature character changed.",
        [step(PREFIX + "." + p_valid + "." + flip_char(s_valid, 10), no("bad_signature"))],
    ),
    case(
        "tampered_payload",
        "The audience rewritten after signing; the old signature kept.",
        [step(tampered_payload, no("bad_signature"))],
    ),
    case(
        "signed_with_unknown_key_claiming_current_kid",
        "kid says k2026b, signed with a key the verifier does not hold.",
        [step(token(_sign_with="k-other"), no("bad_signature"))],
    ),
    case("unknown_kid", "A kid the verifier has never heard of.", [step(token(kid="k-other"), no("bad_signature"))]),
    case(
        "wrong_issuer",
        "Signed with a held key but naming another issuer: no key is held for that issuer.",
        [step(token(iss="other-app"), no("bad_signature"))],
    ),
    case(
        "rotated_previous_key_inside_grace",
        "Signed with the previous key, now <= its accept_until.",
        [step(token(kid="k2026a"), ok(), now=1793000030)],
    ),
    case(
        "rotated_previous_key_outside_grace",
        "Signed with the previous key, now > its accept_until.",
        [step(token(kid="k2026a"), no("bad_signature"), now=1793000031)],
    ),
    case(
        "rotated_current_key_unaffected_by_grace",
        "The current key keeps working after the previous key's grace ends.",
        [step(valid, ok(), now=1793000031)],
    ),
    case("missing", "No header at all.", [step(None, no("missing"))]),
    case("missing_empty", "A header present but empty.", [step("", no("missing"))]),
    case("malformed_prefix", "Another format's token.", [step("fst2." + p_valid + "." + s_valid, no("malformed"))]),
    case(
        "malformed_jwt_shape",
        "A JWT-looking string is not this format.",
        [step("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", no("malformed"))],
    ),
    case("malformed_two_parts", "Signature missing.", [step(PREFIX + "." + p_valid, no("malformed"))]),
    case("malformed_four_parts", "An extra segment.", [step(valid + ".x", no("malformed"))]),
    case(
        "malformed_padding",
        "base64url must be unpadded.",
        [step(PREFIX + "." + p_valid + "." + s_valid + "=", no("malformed"))],
    ),
    case(
        "malformed_noncanonical_signature",
        "A second spelling of the same signature bytes.",
        [step(PREFIX + "." + p_valid + "." + noncanon_sig, no("malformed"))],
    ),
    case(
        "malformed_bad_alphabet",
        "Standard base64 characters are not base64url.",
        [step(PREFIX + "." + p_valid[:-1] + "+" + "." + s_valid, no("malformed"))],
    ),
    case("malformed_whitespace", "Surrounding whitespace is not trimmed.", [step(" " + valid, no("malformed"))]),
    case(
        "malformed_six_fields",
        "The payload must have exactly seven LF-separated fields.",
        [
            step(
                token_from_bytes(
                    "\n".join(
                        ["k2026b", "laravel-app", "ocr-sidecar", "1793000000", "1793000060", "req-01HZX3K8Q2"]
                    ).encode(),
                    KEYS["k2026b"],
                ),
                no("malformed"),
            )
        ],
    ),
    case(
        "malformed_leading_zero_time",
        "Times are canonical decimal: no leading zero.",
        [step(token(iat="01793000000"), no("malformed"))],
    ),
    case("malformed_crlf", "A CR inside a field.", [step(token(rid="req-1\r"), no("malformed"))]),
    case("malformed_non_ascii", "Fields are ASCII.", [step(token(rid="req-" + chr(0xE9)), no("malformed"))]),
    case(
        "malformed_exp_not_after_iat", "exp must be greater than iat.", [step(token(exp=BASE["iat"]), no("malformed"))]
    ),
    case(
        "malformed_lifetime_too_long",
        "exp - iat above max_lifetime: no correct signer produces it.",
        [step(token(exp=BASE["iat"] + 301), no("malformed"))],
    ),
    case("malformed_nonce_required", "No nonce, and the verifier requires one.", [step(no_nonce, no("malformed"))]),
    case(
        "valid_without_nonce_when_not_required",
        "require_nonce false accepts an empty nonce.",
        [step(no_nonce, ok())],
        {"require_nonce": False},
    ),
    case(
        "malformed_too_long",
        "Longer than max_token_bytes.",
        [step(token(rid="r" * 128, nonce="n" * 128), no("malformed"))],
        {"max_token_bytes": 200},
    ),
    case(
        "replayed",
        "The same nonce twice: accepted once, then refused.",
        [step(valid, ok()), step(valid, no("replayed"), now=NOW + 1)],
    ),
    case(
        "replay_does_not_block_a_fresh_nonce",
        "A new nonce after a replay is accepted.",
        [step(valid, ok()), step(valid, no("replayed")), step(token(nonce="n0nce-BBBBBBBBBBBBBBBB"), ok())],
    ),
    case(
        "refused_token_does_not_spend_its_nonce",
        "A wrong-audience token with nonce N must not block a valid token with nonce N.",
        [step(token(aud="billing-sidecar"), no("wrong_audience")), step(valid, ok())],
    ),
]

SIGN = [
    {
        "name": "sign_current_key",
        "why": "The signer, given these inputs, produces exactly the valid token.",
        "input": {
            "kid": "k2026b",
            "secret_hex": KEYS["k2026b"].hex(),
            "issuer": "laravel-app",
            "audience": "ocr-sidecar",
            "now": BASE["iat"],
            "ttl": 60,
            "request_id": BASE["rid"],
            "nonce": BASE["nonce"],
        },
        "token": valid,
    },
    {
        "name": "sign_without_nonce",
        "why": "Nonce off gives an empty seventh field.",
        "input": {
            "kid": "k2026b",
            "secret_hex": KEYS["k2026b"].hex(),
            "issuer": "laravel-app",
            "audience": "ocr-sidecar",
            "now": BASE["iat"],
            "ttl": 60,
            "request_id": BASE["rid"],
            "nonce": "",
        },
        "token": no_nonce,
    },
]

doc = {
    "suite": "fancy-service-token/v1",
    "format": PREFIX,
    "generated_by": "fancy-service-token-py/scripts/build_fixtures.py",
    "note": "Test keys only. Copy this file byte for byte; every leg pins its SHA-256.",
    "sign": SIGN,
    "verify": VERIFY,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
print(f"wrote {OUT} ({len(VERIFY)} verify cases, {len(SIGN)} sign cases)")
print("sha256", hashlib.sha256(OUT.read_bytes()).hexdigest())
