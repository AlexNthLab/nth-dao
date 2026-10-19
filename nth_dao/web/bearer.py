"""One strict, byte-safe console Bearer check for ASGI and route guards."""

from __future__ import annotations

import hmac
from collections.abc import Iterable


def extract_bearer_token(headers: Iterable[tuple[bytes, bytes]]) -> bytes:
    values = [value for name, value in headers if name.lower() == b"authorization"]
    if len(values) != 1:
        return b""
    value = values[0]
    if not value.isascii() or not value.startswith(b"Bearer "):
        return b""
    return value[len(b"Bearer ") :].strip()


def console_bearer_matches(
    headers: Iterable[tuple[bytes, bytes]], expected: str
) -> bool:
    candidate = extract_bearer_token(headers)
    if not expected or not candidate:
        return False
    try:
        expected_bytes = expected.encode("utf-8")
    except UnicodeError:
        return False
    return hmac.compare_digest(candidate, expected_bytes)
