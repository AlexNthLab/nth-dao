"""Shared Resource Profile identifier contract."""

from __future__ import annotations

import re
from typing import Any


RESOURCE_PROFILE_ID_MAX_LENGTH = 190

_RESOURCE_PROFILE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?)?$"
)


def validate_resource_profile_id(value: Any, *, label: str = "profile_id") -> str:
    """Return one canonical Profile ID or reject the cross-wire value."""

    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= RESOURCE_PROFILE_ID_MAX_LENGTH
        or _RESOURCE_PROFILE_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


__all__ = ["RESOURCE_PROFILE_ID_MAX_LENGTH", "validate_resource_profile_id"]
