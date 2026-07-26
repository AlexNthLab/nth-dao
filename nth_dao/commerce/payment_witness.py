"""External storage boundary for signed payment-attempt head anchors."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Protocol, Union, runtime_checkable

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import InterProcessLock

PathLike = Union[str, Path]

_ATTEMPT_ID = re.compile(r"^nth-settlement:v1:sha256:[0-9a-f]{64}$")
_MAX_RECORD_BYTES = 16 * 1024
_MAX_WITNESS_BYTES = 1024 * 1024


class PaymentWitnessRejected(RuntimeError):
    pass


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_WITNESS_BYTES + 1)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PaymentWitnessRejected(
            "payment witness cannot be read"
        ) from exc
    if len(raw) > _MAX_WITNESS_BYTES:
        raise PaymentWitnessRejected("payment witness exceeds size limit")
    return raw


@runtime_checkable
class PaymentAttemptHeadWitness(Protocol):
    """Append-only boundary used to detect rollback of local payment state."""

    def append(self, attempt_id: str, anchor: Dict[str, Any]) -> None:
        ...

    def read(self, attempt_id: str) -> List[Dict[str, Any]]:
        ...


class FilePaymentAttemptHeadWitness:
    """Strict JSONL witness rooted outside the payment-attempt workspace.

    Put ``root`` on an independently backed-up or remotely mounted location
    for rollback evidence to survive loss or restoration of the main workspace.
    Signed anchor validation remains the responsibility of PaymentAttemptStore.
    """

    def __init__(self, root: PathLike) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, attempt_id: str) -> Path:
        if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(
            attempt_id
        ):
            raise PaymentWitnessRejected("invalid payment attempt id")
        return self.root / f"{attempt_id.rsplit(':', 1)[-1]}.jsonl"

    @staticmethod
    def _decode(raw: bytes) -> List[Dict[str, Any]]:
        if len(raw) > _MAX_WITNESS_BYTES:
            raise PaymentWitnessRejected("payment witness exceeds size limit")
        if not raw:
            return []
        lines = raw.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        records: List[Dict[str, Any]] = []
        for line in lines:
            if not line or len(line) > _MAX_RECORD_BYTES:
                raise PaymentWitnessRejected(
                    "payment witness contains an invalid record"
                )
            try:
                value = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise PaymentWitnessRejected(
                    "payment witness contains a torn or malformed record"
                ) from exc
            if not isinstance(value, dict):
                raise PaymentWitnessRejected(
                    "payment witness record must be an object"
                )
            records.append(value)
        return records

    def read(self, attempt_id: str) -> List[Dict[str, Any]]:
        path = self._path(attempt_id)
        try:
            return self._decode(_read_bounded(path))
        except FileNotFoundError:
            return []

    def append(self, attempt_id: str, anchor: Dict[str, Any]) -> None:
        path = self._path(attempt_id)
        try:
            encoded = canonical_json(anchor)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise PaymentWitnessRejected(
                "payment witness anchor is not canonical JSON"
            ) from exc
        if len(encoded) > _MAX_RECORD_BYTES:
            raise PaymentWitnessRejected(
                "payment witness anchor exceeds size limit"
            )
        with InterProcessLock(path):
            try:
                raw = _read_bounded(path)
            except FileNotFoundError:
                raw = b""
            records = self._decode(raw)
            if records and records[-1] == anchor:
                return
            if len(raw) + len(encoded) + 1 > _MAX_WITNESS_BYTES:
                raise PaymentWitnessRejected(
                    "payment witness exceeds size limit"
                )
            try:
                with path.open("ab") as handle:
                    if raw and not raw.endswith(b"\n"):
                        handle.write(b"\n")
                    handle.write(encoded + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise PaymentWitnessRejected(
                    "payment witness cannot be persisted"
                ) from exc
