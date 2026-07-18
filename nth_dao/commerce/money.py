"""Exact decimal/minor-unit conversion for commerce amounts."""

from __future__ import annotations

import re
from decimal import Decimal
from types import MappingProxyType
from typing import Mapping, Tuple, Union


ASSET_DECIMALS: Mapping[str, int] = MappingProxyType(
    {"USDC": 6, "NTH-TEST": 6, "credit": 0}
)
MAX_MINOR_AMOUNT = (1 << 63) - 1
MAX_AMOUNT_TEXT_CHARS = 96
_PLAIN_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")


class MoneyRejected(ValueError):
    """Amount or currency is not representable without loss."""


def _decimal_parts(value: Union[str, Decimal]) -> Tuple[str, str]:
    if isinstance(value, bool) or not isinstance(value, (str, Decimal)):
        raise MoneyRejected("amount must be a plain decimal string or Decimal")
    text = str(value)
    if len(text) > MAX_AMOUNT_TEXT_CHARS:
        raise MoneyRejected("amount text is too long")
    if not _PLAIN_DECIMAL.fullmatch(text):
        raise MoneyRejected("amount must use unsigned plain-decimal notation")
    whole, separator, fraction = text.partition(".")
    return whole, fraction if separator else ""


def decimal_to_minor(
    value: Union[str, Decimal],
    currency: str,
    *,
    require_positive: bool = False,
) -> int:
    """Convert exactly; never accepts floats and never rounds."""
    if currency not in ASSET_DECIMALS:
        raise MoneyRejected(f"unsupported currency: {currency!r}")
    whole, fraction = _decimal_parts(value)
    decimals = ASSET_DECIMALS[currency]
    if len(fraction) > decimals:
        raise MoneyRejected(
            f"amount has more than {decimals} fractional digits"
        )
    scale = 10**decimals
    amount_minor = int(whole) * scale
    if fraction:
        amount_minor += int(fraction.ljust(decimals, "0"))
    if amount_minor > MAX_MINOR_AMOUNT:
        raise MoneyRejected("amount exceeds the supported minor-unit range")
    if require_positive and amount_minor == 0:
        raise MoneyRejected("amount must be positive")
    return amount_minor


def minor_to_decimal(amount_minor: int, currency: str) -> str:
    """Return the canonical plain-decimal spelling of minor units."""
    if currency not in ASSET_DECIMALS:
        raise MoneyRejected(f"unsupported currency: {currency!r}")
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
        raise MoneyRejected("minor amount must be an integer")
    if amount_minor < 0:
        raise MoneyRejected("minor amount must be non-negative")
    if amount_minor > MAX_MINOR_AMOUNT:
        raise MoneyRejected("minor amount exceeds the supported range")
    decimals = ASSET_DECIMALS[currency]
    if decimals == 0:
        return str(amount_minor)
    whole, fraction = divmod(amount_minor, 10**decimals)
    if fraction == 0:
        return str(whole)
    return f"{whole}.{fraction:0{decimals}d}".rstrip("0")
