"""Break one clause of the verifier at a time; the suite must notice every one.

A suite written alongside its implementation passes on its first run, and a
check never seen to fail cannot be told apart from one that cannot. Each
mutation below is applied to the installed source, the suite is run, and the
file is restored in a `finally`. Exits non-zero if any mutation survives.

    python tests/sabotage.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "fancy_service_token"

MUTATIONS: list[tuple[str, str, str, str]] = [
    (
        "signature unchecked",
        "_token.py",
        "if not hmac.compare_digest(expected, signature) or key is None:",
        "if key is None:",
    ),
    ("audience unchecked", "_token.py", "if aud != self.audience:", "if False:"),
    (
        "issuer unchecked",
        "_token.py",
        'if not hmac.compare_digest(iss.encode("ascii"), self.issuer.encode("ascii")):',
        "if False:",
    ),
    ("exp inclusive", "_token.py", "if now >= exp + self.clock_skew:", "if now > exp + self.clock_skew:"),
    ("iat off by one", "_token.py", "if now + self.clock_skew < iat:", "if now + self.clock_skew < iat - 1:"),
    ("grace window off by one", "_token.py", "now > key.accept_until", "now > key.accept_until + 1"),
    ("replay ignored", "_token.py", "return Verdict(False, Reason.REPLAYED)", "pass"),
    ("nonce not required", "_token.py", "elif self.require_nonce:", "elif False:"),
    ("lifetime unbounded", "_token.py", "or exp - iat > self.max_lifetime", ""),
    ("size unbounded", "_token.py", "if len(token) > self.max_token_bytes:", "if False:"),
    ("non-canonical base64 accepted", "_token.py", "!= text:", "!= text and False:"),
    (
        "nonce spent before audience",
        "_token.py",
        "if aud != self.audience:",
        "if (store := self.replay_store) and nonce and not store.add(iss + chr(10) + nonce, exp + self.clock_skew, now):\n            return Verdict(False, Reason.REPLAYED)\n        if aud != self.audience:",
    ),
    ("middleware never refuses", "asgi.py", "if reason is not None or claims is None:", "if False:"),
    ("duplicate header tolerated", "asgi.py", "if len(values) > 1:", "if False:"),
    (
        "exception text leaked",
        "asgi.py",
        'logger.error("service token verifier raised %s; refusing", type(exc).__name__)',
        'logger.error("service token verifier raised %s; refusing", exc)',
    ),
    (
        "dependency fails open",
        "depends.py",
        'raise HTTPException(status_code=401, detail="service_token_refused")',
        "return None  # type: ignore[return-value]",
    ),
]


def main() -> int:
    survivors = []
    for label, name, old, new in MUTATIONS:
        path = PKG / name
        original = path.read_bytes()
        text = original.decode("utf-8")
        if text.count(old) < 1:
            print(f"BROKEN SWEEP  {label}: pattern not found in {name}")
            survivors.append(label)
            continue
        try:
            path.write_bytes(text.replace(old, new, 1).encode("utf-8"))
            run = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
        finally:
            path.write_bytes(original)
        if run.returncode == 0:
            print(f"SURVIVED      {label}")
            survivors.append(label)
        else:
            print(f"killed        {label}")
    print(f"{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} mutations killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
