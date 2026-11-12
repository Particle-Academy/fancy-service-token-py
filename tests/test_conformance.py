"""The shared fixture set, run exactly as the PHP and Node legs run it."""

from __future__ import annotations

from typing import Any

import pytest

from fancy_service_token import Key, MemoryReplayStore, Reason, Verifier

from .conftest import FIXTURES_SHA256, fixture_bytes, load_fixtures, sha256

CASES = load_fixtures()["verify"]


def build(v: dict[str, Any]) -> Verifier:
    return Verifier(
        keys=[Key(k["kid"], bytes.fromhex(k["secret_hex"]), accept_until=k["accept_until"]) for k in v["keys"]],
        audience=v["audience"],
        issuer=v["issuer"],
        clock_skew=v["clock_skew"],
        max_lifetime=v["max_lifetime"],
        max_token_bytes=v["max_token_bytes"],
        require_nonce=v["require_nonce"],
        replay_store=MemoryReplayStore(),
    )


def test_fixture_file_is_the_pinned_bytes() -> None:
    assert sha256(fixture_bytes()) == FIXTURES_SHA256


def test_fixture_covers_every_reason() -> None:
    seen = {s["expect"]["reason"] for c in CASES for s in c["steps"]}
    assert seen == {None, *(r.value for r in Reason)}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_verify_case(case: dict[str, Any]) -> None:
    verifier = build(case["verifier"])
    for i, step in enumerate(case["steps"]):
        verdict = verifier.verify(step["token"], now=step["now"])
        expect = step["expect"]
        assert verdict.ok is expect["ok"], f"step {i}"
        assert (verdict.reason.value if verdict.reason else None) == expect["reason"], f"step {i}"
        assert (verdict.claims.request_id if verdict.claims else None) == expect["request_id"], f"step {i}"


def test_reason_enum_is_exactly_the_contract() -> None:
    assert [r.value for r in Reason] == [
        "missing",
        "malformed",
        "bad_signature",
        "expired",
        "not_yet_valid",
        "wrong_audience",
        "replayed",
    ]
