"""The framework-free core: configuration limits, rotation, and what never leaks."""

from __future__ import annotations

import pytest

from fancy_service_token import Key, MemoryReplayStore, Reason, Verifier

from .conftest import load_fixtures

FX = load_fixtures()
VALID = FX["sign"][0]["token"]
SECRET = bytes.fromhex(FX["sign"][0]["input"]["secret_hex"])
NOW = 1793000005


def verifier(**kw: object) -> Verifier:
    args: dict[str, object] = {"keys": [Key("k2026b", SECRET)], "audience": "ocr-sidecar", "issuer": "laravel-app"}
    args.update(kw)
    return Verifier(**args)  # type: ignore[arg-type]


def test_secure_defaults() -> None:
    v = verifier()
    assert v.clock_skew == 10
    assert v.max_lifetime == 300
    assert v.max_token_bytes == 1024
    assert v.require_nonce is True
    assert isinstance(v.replay_store, MemoryReplayStore)


def test_a_short_key_is_refused_at_construction_without_echoing_it() -> None:
    with pytest.raises(ValueError) as err:
        Verifier(keys=[Key("k1", b"short-secret-value")], audience="a", issuer="i")
    assert "short-secret-value" not in str(err.value)
    assert "k1" in str(err.value)


def test_min_key_bytes_is_configurable() -> None:
    Verifier(keys=[Key("k1", b"x" * 16)], audience="a", issuer="i", min_key_bytes=16)


def test_duplicate_kid_is_refused() -> None:
    with pytest.raises(ValueError):
        verifier(keys=[Key("k2026b", SECRET), Key("k2026b", SECRET)])


def test_no_keys_is_refused() -> None:
    with pytest.raises(ValueError):
        verifier(keys=[])


@pytest.mark.parametrize("field", ["clock_skew", "max_lifetime", "max_token_bytes"])
def test_negative_limits_are_refused(field: str) -> None:
    with pytest.raises(ValueError):
        verifier(**{field: -1})


def test_key_repr_never_shows_the_secret() -> None:
    assert SECRET.hex() not in repr(Key("k2026b", SECRET))
    assert repr(SECRET) not in repr(Key("k2026b", SECRET))


def test_verdict_and_claims_never_carry_the_token() -> None:
    verdict = verifier().verify(VALID, now=NOW)
    assert verdict.ok
    assert VALID not in repr(verdict)
    assert VALID.split(".")[2] not in repr(verdict)


def test_refusal_carries_only_the_reason() -> None:
    verdict = verifier().verify(VALID, now=NOW + 3600)
    assert verdict.reason is Reason.EXPIRED
    assert verdict.claims is None


def test_garbage_of_every_type_is_a_named_refusal_not_an_exception() -> None:
    v = verifier()
    for junk in [b"\xff\xfe", "fst1." + "\x00" * 50 + ".x", "fst1..", "fst1.%%%.%%%", chr(0x2028), 12345, object()]:
        verdict = v.verify(junk, now=NOW)  # type: ignore[arg-type]
        assert verdict.ok is False
        assert verdict.reason in (Reason.MALFORMED, Reason.MISSING)


def test_bytes_header_values_are_accepted() -> None:
    assert verifier().verify(VALID.encode("ascii"), now=NOW).ok


def test_clock_is_used_when_now_is_not_given() -> None:
    assert verifier(clock=lambda: NOW + 0.9).verify(VALID).ok
    assert verifier(clock=lambda: NOW + 3600).verify(VALID).reason is Reason.EXPIRED


def test_claims_expose_the_verified_fields() -> None:
    claims = verifier().verify(VALID, now=NOW).claims
    assert claims is not None
    assert (claims.kid, claims.issuer, claims.audience) == ("k2026b", "laravel-app", "ocr-sidecar")
    assert (claims.issued_at, claims.expires_at) == (1793000000, 1793000060)
    assert claims.request_id == "req-01HZX3K8Q2"


def test_replay_store_full_fails_closed() -> None:
    store = MemoryReplayStore(max_entries=1)
    assert store.add("a", expires_at=NOW + 60, now=NOW) is True
    assert store.add("b", expires_at=NOW + 60, now=NOW) is False


def test_replay_store_forgets_expired_entries() -> None:
    store = MemoryReplayStore(max_entries=1)
    assert store.add("a", expires_at=NOW + 1, now=NOW) is True
    assert store.add("b", expires_at=NOW + 60, now=NOW + 2) is True
    assert store.add("a", expires_at=NOW + 60, now=NOW + 2) is False


def test_replay_entry_outlives_the_skewed_expiry() -> None:
    # A token is accepted until exp + skew, so its nonce must be held that long.
    v = verifier()
    assert v.verify(VALID, now=NOW).ok
    assert v.verify(VALID, now=1793000060 + 9).reason is Reason.REPLAYED


def test_replay_can_be_disabled_explicitly() -> None:
    v = verifier(replay_store=None)
    assert v.verify(VALID, now=NOW).ok
    assert v.verify(VALID, now=NOW).ok
