"""Typed authorization decisions for delivery security boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Tuple, Union


MAX_AUTHORIZATION_CODE_LENGTH = 64
MAX_AUTHORIZATION_REASON_LENGTH = 512
_CODE_RE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")


@dataclass(frozen=True)
class AuthorizationDecision:
    """A stable, machine-readable authorization result.

    ``reason`` is diagnostic text only. Control flow must use ``allowed``,
    ``code``, and ``retryable`` so changing or localizing text cannot alter
    delivery behavior.
    """

    allowed: bool
    code: str
    reason: str
    retryable: bool = False

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise TypeError("allowed must be a bool")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be a bool")
        if not isinstance(self.code, str) or _CODE_RE.fullmatch(self.code) is None:
            raise ValueError(
                "code must be a lowercase authorization code of at most "
                f"{MAX_AUTHORIZATION_CODE_LENGTH} characters"
            )
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")
        if (
            not self.reason
            or len(self.reason.encode("utf-8")) > MAX_AUTHORIZATION_REASON_LENGTH
            or not self.reason.isprintable()
        ):
            raise ValueError(
                "reason must contain printable text up to "
                f"{MAX_AUTHORIZATION_REASON_LENGTH} UTF-8 bytes"
            )
        if self.allowed and self.retryable:
            raise ValueError("an allowed decision cannot be retryable")
        if self.allowed and self.code != "authorized":
            raise ValueError("an allowed decision must use the authorized code")
        if not self.allowed and self.code == "authorized":
            raise ValueError("a denied decision cannot use the authorized code")

    @classmethod
    def allow(cls, reason: str = "authorized") -> "AuthorizationDecision":
        return cls(allowed=True, code="authorized", reason=reason)

    @classmethod
    def deny(
        cls,
        *,
        code: str = "unauthorized",
        reason: str = "unauthorized",
        retryable: bool = False,
    ) -> "AuthorizationDecision":
        return cls(
            allowed=False,
            code=code,
            reason=reason,
            retryable=retryable,
        )


LegacyAuthorizationDecision = Tuple[bool, str]
AuthorizationResult = Union[AuthorizationDecision, LegacyAuthorizationDecision]


def coerce_authorization_decision(
    value: AuthorizationResult,
    *,
    deny_code: str = "unauthorized",
) -> AuthorizationDecision:
    """Normalize the typed result or the strictly validated legacy tuple."""

    if type(value) is AuthorizationDecision:
        # Frozen dataclasses can still be modified through object.__setattr__.
        # Reconstruct at the trust boundary so __post_init__ validates every
        # field again and a truthy non-bool cannot become an authorization.
        return AuthorizationDecision(
            allowed=value.allowed,
            code=value.code,
            reason=value.reason,
            retryable=value.retryable,
        )
    if not isinstance(value, tuple) or len(value) != 2:
        raise TypeError(
            "authorization callback must return AuthorizationDecision or (bool, str)"
        )
    allowed, reason = value
    if type(allowed) is not bool:
        raise TypeError("authorization callback allowed value must be a bool")
    if not isinstance(reason, str):
        raise TypeError("authorization callback reason must be a string")
    if allowed:
        return AuthorizationDecision.allow(reason=reason or "authorized")
    return AuthorizationDecision.deny(
        code=deny_code,
        reason=reason or "unauthorized",
    )
