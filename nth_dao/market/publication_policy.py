"""Fail-closed checks for values that become public market protocol data."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


_PUBLICATION_PATTERNS = (
    (
        "a private-key marker",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "a Windows user path",
        re.compile(r"(?i)\b[A-Z]:[\\/]Users[\\/][^\\/\s]+[\\/]"),
    ),
    ("a macOS user path", re.compile(r"/" r"Users/[^/\s]+/")),
    ("a Linux user path", re.compile(r"/" r"home/[^/\s]+/")),
    ("a local file URI", re.compile(r"(?i)\bfile://")),
    ("a GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("a GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    (
        "an OpenAI or Anthropic API key",
        re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b"),
    ),
    ("an AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("a Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "a Telegram bot token",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ),
    (
        "a credential-bearing URL",
        re.compile(r"(?i)\bhttps?://[^\s/:]+:[^\s/@]+@"),
    ),
    (
        "an access token query parameter",
        re.compile(r"(?i)[?&](?:access_token|api_key|token)=[^&\s]+"),
    ),
)


def reject_private_publication_data(value: Any, *, label: str = "publication") -> None:
    """Reject obvious machine-local or secret material before federation.

    This is a conservative boundary check, not a general DLP engine. Every
    accepted field must still be treated as public by callers and operators.
    """
    pending: list[tuple[str, Any]] = [(label, value)]
    visited = 0
    while pending:
        path, item = pending.pop()
        visited += 1
        if visited > 4_096:
            raise ValueError(f"{label} contains too many nested values")
        if isinstance(item, str):
            if any(
                ord(character) < 32 and character not in "\t\n\r"
                for character in item
            ):
                raise ValueError(f"{path} contains a forbidden control character")
            for reason, pattern in _PUBLICATION_PATTERNS:
                if pattern.search(item):
                    raise ValueError(
                        f"{path} contains {reason}; public market fields are "
                        "signed and may be federated"
                    )
            continue
        if isinstance(item, Mapping):
            for key, child in item.items():
                pending.append((f"{path}.{key}", child))
            continue
        if isinstance(item, Sequence) and not isinstance(
            item, (bytes, bytearray, memoryview)
        ):
            for index, child in enumerate(item):
                pending.append((f"{path}[{index}]", child))


__all__ = ["reject_private_publication_data"]
