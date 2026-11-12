"""The framework-free verifier for `fst1` service tokens.

Standard library only: `hmac.new(..., hashlib.sha256)` and `hmac.compare_digest`.
No JWT library and no cryptography of our own. The format is defined in the
README; the order of the checks below is part of the contract, because it
decides which reason a token that is wrong in two ways is refused with, and the
PHP and Node legs are held to the same order by the shared fixtures.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import hmac
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

PREFIX = "fst1"
SIGNATURE_CHARS = 43  # 32 bytes of HMAC-SHA256, unpadded base64url

_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_KID = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
_NAME = _KID | frozenset(":/")
_RID = _KID | frozenset(":")
_NONCE = _B64URL
_DIGITS = frozenset("0123456789")


class Reason(enum.StrEnum):
    """Why a token was refused. A fixed set: nothing else is ever returned."""

    MISSING = "missing"
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    WRONG_AUDIENCE = "wrong_audience"
    REPLAYED = "replayed"


@dataclass(frozen=True)
class Key:
    """One signing key. `accept_until` (unix seconds) marks a PREVIOUS key in its grace window."""

    kid: str
    secret: bytes = field(repr=False)
    accept_until: int | None = None


@dataclass(frozen=True)
class Claims:
    """The verified contents of a token. Never holds the token or the secret."""

    kid: str
    issuer: str
    audience: str
    issued_at: int
    expires_at: int
    request_id: str
    nonce: str = field(repr=False)


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: Reason | None = None
    claims: Claims | None = None


class ReplayStore(Protocol):
    def add(self, key: str, expires_at: int, now: int) -> bool:
        """Record `key` until `expires_at`. True if it was new, False if already present (or refused)."""
        ...


class MemoryReplayStore:
    """Per-process nonce memory. Fails CLOSED when full: a nonce it cannot record is refused.

    Enough for a single-process sidecar. Several workers behind one port need a
    shared store (anything implementing `ReplayStore.add` atomically).
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.max_entries = max_entries
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def add(self, key: str, expires_at: int, now: int) -> bool:
        with self._lock:
            held = self._seen.get(key)
            if held is not None and held > now:
                return False
            if len(self._seen) >= self.max_entries:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
                if len(self._seen) >= self.max_entries:
                    return False
            self._seen[key] = expires_at
            return True


_DEFAULT_STORE = object()


def _b64decode(text: str) -> bytes | None:
    """Strict unpadded base64url: right alphabet, right length, and the ONE canonical spelling."""
    if not text or len(text) % 4 == 1 or not set(text) <= _B64URL:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        return None
    return raw


def _name(value: str, chars: frozenset[str], max_len: int) -> bool:
    return 0 < len(value) <= max_len and set(value) <= chars


def _time(value: str) -> int | None:
    if not 0 < len(value) <= 12 or not set(value) <= _DIGITS or value[0] == "0":
        return None
    return int(value)


class Verifier:
    """Verify `fst1` tokens. Every limit is a constructor argument with a secure default."""

    def __init__(
        self,
        *,
        keys: Sequence[Key],
        audience: str,
        issuer: str,
        clock_skew: int = 10,
        max_lifetime: int = 300,
        max_token_bytes: int = 1024,
        require_nonce: bool = True,
        min_key_bytes: int = 32,
        replay_store: ReplayStore | object | None = _DEFAULT_STORE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        for label, value in (
            ("clock_skew", clock_skew),
            ("max_lifetime", max_lifetime),
            ("max_token_bytes", max_token_bytes),
        ):
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if not keys:
            raise ValueError("at least one key is required")
        if not _name(audience, _NAME, 128) or not _name(issuer, _NAME, 128):
            raise ValueError("audience and issuer must be 1-128 chars of [A-Za-z0-9._:/-]")
        held: dict[str, Key] = {}
        for key in keys:
            if not _name(key.kid, _KID, 64):
                raise ValueError("a key id must be 1-64 chars of [A-Za-z0-9._-]")
            if key.kid in held:
                raise ValueError(f"duplicate key id {key.kid!r}")
            if not isinstance(key.secret, bytes) or len(key.secret) < min_key_bytes:
                # Names the key, never its value.
                raise ValueError(f"key {key.kid!r} is shorter than {min_key_bytes} bytes")
            held[key.kid] = key
        self._keys = held
        self.audience = audience
        self.issuer = issuer
        self.clock_skew = clock_skew
        self.max_lifetime = max_lifetime
        self.max_token_bytes = max_token_bytes
        self.require_nonce = require_nonce
        self.replay_store: ReplayStore | None = (
            MemoryReplayStore() if replay_store is _DEFAULT_STORE else replay_store  # type: ignore[assignment]
        )
        self._clock = clock

    def verify(self, token: str | bytes | None, now: int | None = None) -> Verdict:
        """Never raises for any input: an unexpected failure is a MALFORMED refusal."""
        try:
            return self._verify(token, int(self._clock()) if now is None else now)
        except Exception:
            return Verdict(False, Reason.MALFORMED)

    def _verify(self, token: object, now: int) -> Verdict:
        # 1. Missing.
        if token is None or token in ("", b""):
            return Verdict(False, Reason.MISSING)
        if isinstance(token, bytes):
            try:
                token = token.decode("ascii")
            except UnicodeDecodeError:
                return Verdict(False, Reason.MALFORMED)
        if not isinstance(token, str):
            return Verdict(False, Reason.MALFORMED)

        # 2. Size, before any parsing.
        if len(token) > self.max_token_bytes:
            return Verdict(False, Reason.MALFORMED)

        # 3. Structure: exactly prefix . payload . signature, each canonical.
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX or len(parts[2]) != SIGNATURE_CHARS:
            return Verdict(False, Reason.MALFORMED)
        signature = _b64decode(parts[2])
        raw = _b64decode(parts[1])
        if signature is None or raw is None or len(signature) != 32:
            return Verdict(False, Reason.MALFORMED)

        # 4. Payload grammar: seven LF-separated ASCII fields.
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            return Verdict(False, Reason.MALFORMED)
        fields = text.split("\n")
        if len(fields) != 7:
            return Verdict(False, Reason.MALFORMED)
        kid, iss, aud, iat_s, exp_s, rid, nonce = fields
        iat, exp = _time(iat_s), _time(exp_s)
        if (
            not _name(kid, _KID, 64)
            or not _name(iss, _NAME, 128)
            or not _name(aud, _NAME, 128)
            or not _name(rid, _RID, 128)
            or iat is None
            or exp is None
            or exp <= iat
            or exp - iat > self.max_lifetime
        ):
            return Verdict(False, Reason.MALFORMED)
        if nonce:
            if not 16 <= len(nonce) <= 128 or not set(nonce) <= _NONCE:
                return Verdict(False, Reason.MALFORMED)
        elif self.require_nonce:
            return Verdict(False, Reason.MALFORMED)

        # 5. Signature. An unknown kid, a retired key past its grace window and
        #    another issuer are all "not signed by a key we hold for this issuer".
        key = self._keys.get(kid)
        expected = hmac.new(
            key.secret if key else b"\0" * 32, (PREFIX + "." + parts[1]).encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, signature) or key is None:
            return Verdict(False, Reason.BAD_SIGNATURE)
        if key.accept_until is not None and now > key.accept_until:
            return Verdict(False, Reason.BAD_SIGNATURE)
        if not hmac.compare_digest(iss.encode("ascii"), self.issuer.encode("ascii")):
            return Verdict(False, Reason.BAD_SIGNATURE)

        # 6. Audience, 7. time window, 8. replay -- last, so only a token that
        #    is otherwise acceptable can spend a nonce.
        if aud != self.audience:
            return Verdict(False, Reason.WRONG_AUDIENCE)
        if now + self.clock_skew < iat:
            return Verdict(False, Reason.NOT_YET_VALID)
        if now >= exp + self.clock_skew:
            return Verdict(False, Reason.EXPIRED)
        store = self.replay_store
        if nonce and store is not None and not store.add(iss + "\n" + nonce, exp + self.clock_skew, now):
            return Verdict(False, Reason.REPLAYED)

        return Verdict(True, None, Claims(kid, iss, aud, iat, exp, rid, nonce))
