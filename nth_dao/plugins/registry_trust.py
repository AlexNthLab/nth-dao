"""Host-owned signature, freshness, and rollback checks for peer registries."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.util.io import InterProcessLock, atomic_write_json


CURATED_REGISTRY_FORMAT = "nth-dao-peer-registry-v2"
_MAX_CLOCK_SKEW_MS = 30_000
_MAX_ENVELOPE_LIFETIME_MS = 24 * 60 * 60 * 1000
_MAX_PUBLISHERS = 64
_STATE_FORMAT_V1 = "nth-dao-curated-registry-state-v1"
_STATE_FORMAT = "nth-dao-curated-registry-state-v2"


@dataclass(frozen=True)
class _PublisherState:
    version: int
    envelope_digest: str


@dataclass(frozen=True)
class VerifiedRegistryEnvelope:
    publisher_did: str
    version: int
    peers: tuple[Dict[str, Any], ...]
    envelope_digest: str
    already_accepted: bool = False


def _timestamp_ms(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 64:
        raise ValueError(f"curated registry {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"curated registry {field} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"curated registry {field} must include timezone")
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


class CuratedRegistryTrust:
    """Verify signed indexes and persist accepted publisher versions."""

    def __init__(self, workspace: Path) -> None:
        self.path = (
            Path(workspace).resolve()
            / ".nth"
            / "plugin-host"
            / "curated-registry-state.json"
        )
        self._lock = InterProcessLock(self.path, timeout=5.0)
        self._state_thread_lock = threading.RLock()
        self._cycle_path = self.path.with_name("curated-registry-refresh")

    @contextmanager
    def refresh_cycle(self) -> Iterator[None]:
        """Hold one workspace-wide lease for a complete registry refresh.

        Version acceptance and learned-peer writes are one ordering domain.
        Serializing only the version file would allow an older process to
        resume and persist stale peer side effects after a newer process.
        """

        lease = InterProcessLock(self._cycle_path, timeout=0.1, poll=0.02)
        try:
            lease.acquire()
        except TimeoutError as exc:
            raise RuntimeError("curated registry refresh is already running") from exc
        try:
            yield
        finally:
            lease.release()

    def _load_unlocked(self) -> Dict[str, _PublisherState]:
        if not self.path.exists():
            return {}

        def no_duplicates(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("curated registry state has duplicate keys")
                value[key] = item
            return value

        try:
            if self.path.stat().st_size > 64 * 1024:
                raise ValueError("curated registry state exceeds its size limit")
            document = json.loads(
                self.path.read_text(encoding="utf-8"),
                object_pairs_hook=no_duplicates,
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("curated registry state is unreadable") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"format", "publishers"}
            or document.get("format") not in {_STATE_FORMAT_V1, _STATE_FORMAT}
            or not isinstance(document.get("publishers"), dict)
            or len(document["publishers"]) > _MAX_PUBLISHERS
        ):
            raise ValueError("curated registry state is invalid")
        result: Dict[str, _PublisherState] = {}
        legacy = document["format"] == _STATE_FORMAT_V1
        for did, raw_state in document["publishers"].items():
            if not isinstance(did, str) or not is_did_key(did):
                raise ValueError("curated registry publisher state is invalid")
            if legacy:
                version = raw_state
                envelope_digest = ""
            elif (
                isinstance(raw_state, dict)
                and set(raw_state) == {"version", "envelope_digest"}
            ):
                version = raw_state.get("version")
                envelope_digest = raw_state.get("envelope_digest")
            else:
                raise ValueError("curated registry publisher state is invalid")
            if (
                type(version) is not int
                or version < 1
                or not isinstance(envelope_digest, str)
                or (
                    envelope_digest
                    and not re.fullmatch(r"sha256:[0-9a-f]{64}", envelope_digest)
                )
                or (not legacy and not envelope_digest)
            ):
                raise ValueError("curated registry publisher state is invalid")
            result[did] = _PublisherState(version, envelope_digest)
        return result

    def verify(
        self,
        document: Any,
        *,
        expected_publisher_did: str,
        now_ms_override: int = 0,
    ) -> VerifiedRegistryEnvelope:
        if not isinstance(expected_publisher_did, str) or not is_did_key(
            expected_publisher_did,
        ):
            raise ValueError("curated registry publisher DID is not configured")
        expected_fields = {
            "format",
            "publisher_did",
            "version",
            "issued_at",
            "expires_at",
            "peers",
            "sig",
        }
        if not isinstance(document, dict) or set(document) != expected_fields:
            raise ValueError("curated registry signed envelope fields are invalid")
        if document.get("format") != CURATED_REGISTRY_FORMAT:
            raise ValueError("curated registry format is unsupported")
        publisher_did = document.get("publisher_did")
        if not isinstance(publisher_did, str) or not hmac.compare_digest(
            publisher_did, expected_publisher_did,
        ):
            raise ValueError("curated registry publisher DID does not match local pin")
        version = document.get("version")
        if type(version) is not int or not 1 <= version <= 2**63 - 1:
            raise ValueError("curated registry version is invalid")
        peers = document.get("peers")
        if not isinstance(peers, list):
            raise ValueError("curated registry peers must be an array")
        signature = document.get("sig")
        if not isinstance(signature, str) or not re.fullmatch(
            r"[0-9a-fA-F]{128}", signature,
        ):
            raise ValueError("curated registry signature is malformed")
        issued_ms = _timestamp_ms(document.get("issued_at"), field="issued_at")
        expires_ms = _timestamp_ms(document.get("expires_at"), field="expires_at")
        now_ms = int(now_ms_override or time.time() * 1000)
        if issued_ms > now_ms + _MAX_CLOCK_SKEW_MS:
            raise ValueError("curated registry is not active yet")
        if expires_ms <= now_ms:
            raise ValueError("curated registry has expired")
        if expires_ms <= issued_ms or (
            expires_ms - issued_ms > _MAX_ENVELOPE_LIFETIME_MS
        ):
            raise ValueError("curated registry validity window is invalid")
        unsigned = dict(document)
        unsigned.pop("sig")
        try:
            from nacl.exceptions import BadSignatureError
            from nacl.signing import VerifyKey

            VerifyKey(bytes.fromhex(decode_ed25519_did_key_hex(publisher_did))).verify(
                canonical_json(unsigned),
                bytes.fromhex(signature),
            )
        except ImportError as exc:
            raise ValueError("curated registry signature verification is unavailable") from exc
        except (BadSignatureError, TypeError, ValueError) as exc:
            raise ValueError("curated registry signature verification failed") from exc
        digest_document = dict(unsigned)
        digest_document["sig"] = signature.lower()
        envelope_digest = (
            f"sha256:{hashlib.sha256(canonical_json(digest_document)).hexdigest()}"
        )
        with self._state_thread_lock:
            with self._lock:
                accepted = self._load_unlocked().get(publisher_did)
        already_accepted = False
        if accepted is not None:
            if version < accepted.version:
                raise ValueError("curated registry version is rolled back")
            if version == accepted.version:
                if not accepted.envelope_digest:
                    raise ValueError(
                        "curated registry legacy state requires a higher version"
                    )
                if not hmac.compare_digest(
                    envelope_digest, accepted.envelope_digest,
                ):
                    raise ValueError("curated registry version conflicts with accepted content")
                already_accepted = True
        peers_copy = json.loads(
            canonical_json({"peers": peers}).decode("utf-8")
        )["peers"]
        return VerifiedRegistryEnvelope(
            publisher_did=publisher_did,
            version=version,
            peers=tuple(peers_copy),
            envelope_digest=envelope_digest,
            already_accepted=already_accepted,
        )

    def commit(self, envelope: VerifiedRegistryEnvelope) -> bool:
        if not isinstance(envelope, VerifiedRegistryEnvelope):
            raise TypeError("verified curated registry envelope is required")
        with self._state_thread_lock:
            with self._lock:
                return self._commit_unlocked(envelope)

    def _commit_unlocked(self, envelope: VerifiedRegistryEnvelope) -> bool:
        publishers = self._load_unlocked()
        current = publishers.get(envelope.publisher_did)
        if current is not None and envelope.version < current.version:
            raise ValueError("curated registry version was concurrently superseded")
        if current is not None and envelope.version == current.version:
            if not current.envelope_digest:
                raise ValueError(
                    "curated registry legacy state requires a higher version"
                )
            if not hmac.compare_digest(
                envelope.envelope_digest, current.envelope_digest,
            ):
                raise ValueError("curated registry version conflicts with accepted content")
            return False
        if envelope.publisher_did not in publishers and len(
            publishers,
        ) >= _MAX_PUBLISHERS:
            raise ValueError("curated registry publisher capacity is full")
        publishers[envelope.publisher_did] = _PublisherState(
            envelope.version,
            envelope.envelope_digest,
        )
        atomic_write_json(
            self.path,
            {
                "format": _STATE_FORMAT,
                "publishers": {
                    did: {
                        "version": state.version,
                        "envelope_digest": state.envelope_digest,
                    }
                    for did, state in sorted(publishers.items())
                },
            },
        )
        return True


__all__ = [
    "CURATED_REGISTRY_FORMAT",
    "CuratedRegistryTrust",
    "VerifiedRegistryEnvelope",
]
