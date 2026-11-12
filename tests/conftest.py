from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "conformance" / "service-token-v1.json"

# Pinned in EVERY leg (PHP, Python, Node). A copy that drifts in one repository
# fails that repository's suite, so "byte-identical" is a test result.
FIXTURES_SHA256 = "767caf66f1fc2cba980dc493c10c18df21676720e8183565397bdeea80b328bd"


def load_fixtures() -> dict[str, Any]:
    return json.loads(FIXTURES.read_bytes().decode("utf-8"))


@pytest.fixture(scope="session")
def fixtures() -> dict[str, Any]:
    return load_fixtures()


def fixture_bytes() -> bytes:
    return FIXTURES.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
