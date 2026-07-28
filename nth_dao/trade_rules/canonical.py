"""Strict cross-language JSON subset for NTH trade protocol objects."""

from __future__ import annotations

import json
from typing import Any

from nth_dao.canonical_json import canonical_json

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_TRADE_JSON_BYTES = 262_144
MAX_TRADE_JSON_DEPTH = 32
MAX_TRADE_JSON_NODES = 10_000
MAX_TRADE_STRING_BYTES = 65_536
MAX_TRADE_KEY_BYTES = 256


class TradeCanonicalJSONError(ValueError):
    """Raised when input is outside NTH Trade Canonical JSON v1."""


def _walk(
    value: Any,
    *,
    path: str,
    depth: int,
    budget: list[int],
    ancestors: set[int],
) -> None:
    budget[0] += 1
    if budget[0] > MAX_TRADE_JSON_NODES:
        raise TradeCanonicalJSONError("trade JSON exceeds node limit")
    if depth > MAX_TRADE_JSON_DEPTH:
        raise TradeCanonicalJSONError("trade JSON exceeds depth limit")

    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                encoded_value = value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise TradeCanonicalJSONError(
                    f"invalid Unicode string at {path}"
                ) from exc
            if len(encoded_value) > MAX_TRADE_STRING_BYTES:
                raise TradeCanonicalJSONError(f"string too large at {path}")
        return
    if isinstance(value, int):
        if isinstance(value, bool):  # bool is handled above, kept explicit for review.
            return
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise TradeCanonicalJSONError(f"unsafe integer at {path}")
        return
    if isinstance(value, float):
        raise TradeCanonicalJSONError(f"float is forbidden at {path}")

    if isinstance(value, (dict, list)):
        object_id = id(value)
        if object_id in ancestors:
            raise TradeCanonicalJSONError(f"cyclic value at {path}")
        ancestors.add(object_id)
        try:
            if isinstance(value, list):
                for index, item in enumerate(value):
                    _walk(
                        item,
                        path=f"{path}[{index}]",
                        depth=depth + 1,
                        budget=budget,
                        ancestors=ancestors,
                    )
                return

            for key, item in value.items():
                if not isinstance(key, str):
                    raise TradeCanonicalJSONError(f"non-string key at {path}")
                if not key.isascii():
                    raise TradeCanonicalJSONError(f"non-ASCII key at {path}")
                if not key or any(not 0x21 <= ord(char) <= 0x7E for char in key):
                    raise TradeCanonicalJSONError(f"invalid ASCII key at {path}")
                if len(key) > MAX_TRADE_KEY_BYTES:
                    raise TradeCanonicalJSONError(f"object key too large at {path}")
                _walk(
                    item,
                    path=f"{path}.{key}",
                    depth=depth + 1,
                    budget=budget,
                    ancestors=ancestors,
                )
        finally:
            ancestors.remove(object_id)
        return

    raise TradeCanonicalJSONError(f"unsupported {type(value).__name__} at {path}")


def trade_canonical_json(value: dict[str, Any]) -> bytes:
    """Return NTH Trade Canonical JSON v1 bytes for a bounded object."""
    if not isinstance(value, dict):
        raise TradeCanonicalJSONError("trade JSON root must be an object")
    _walk(value, path="$", depth=0, budget=[0], ancestors=set())
    try:
        encoded = canonical_json(value)
    except (
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        UnicodeEncodeError,
    ) as exc:
        raise TradeCanonicalJSONError(str(exc)) from exc
    if len(encoded) > MAX_TRADE_JSON_BYTES:
        raise TradeCanonicalJSONError("trade JSON exceeds byte limit")
    return encoded


def _reject_float(value: str) -> None:
    raise TradeCanonicalJSONError(f"float is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise TradeCanonicalJSONError(f"non-finite number is forbidden: {value}")


def _parse_int(value: str) -> int:
    parsed = int(value)
    if not -MAX_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER:
        raise TradeCanonicalJSONError(f"unsafe integer: {value}")
    return parsed


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TradeCanonicalJSONError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def parse_trade_json(raw: bytes | str) -> dict[str, Any]:
    """Parse strict UTF-8 JSON and reject duplicates before canonicalizing."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_TRADE_JSON_BYTES:
            raise TradeCanonicalJSONError("trade JSON exceeds byte limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TradeCanonicalJSONError("trade JSON is not UTF-8") from exc
    elif isinstance(raw, str):
        try:
            raw_bytes = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise TradeCanonicalJSONError(
                "trade JSON contains invalid Unicode"
            ) from exc
        if len(raw_bytes) > MAX_TRADE_JSON_BYTES:
            raise TradeCanonicalJSONError("trade JSON exceeds byte limit")
        text = raw
    else:
        raise TradeCanonicalJSONError("trade JSON input must be bytes or string")

    if text.startswith("\ufeff"):
        raise TradeCanonicalJSONError("UTF-8 BOM is forbidden")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except TradeCanonicalJSONError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        raise TradeCanonicalJSONError(f"invalid trade JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise TradeCanonicalJSONError("trade JSON root must be an object")
    trade_canonical_json(value)
    return value


__all__ = [
    "MAX_SAFE_INTEGER",
    "MAX_TRADE_JSON_BYTES",
    "TradeCanonicalJSONError",
    "parse_trade_json",
    "trade_canonical_json",
]
