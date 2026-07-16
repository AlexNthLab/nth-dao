"""Rate limiters for local and public FastAPI routes.

Used by /api/mandates/verify and /api/mandates/store to mitigate
Voss V-30:

  1. DoS - unlimited crypto-verify per anonymous client trivially
     burns server CPU.
  2. Timing oracle - an attacker can repeatedly probe verify with
     small variations on the same mandate to leak structural state
     via wall-clock differences (missing proof ~ a few microseconds,
     Ed25519 verify ~ 100us). Rate limiting raises the cost per
     probe; the constant-time floor below adds a fixed lower bound
     on response time so individual probes don't reveal which gate
     fired.

Two storage models are available:

  * ``RateLimiter`` uses process-local monotonic time for authenticated,
    local-first console routes.
  * ``PersistentRateLimiter`` uses a locked workspace file so multiple web
    workers share one budget on low-frequency anonymous routes.

Both implementations use bounded sliding-window counters. The caller owns
the keying policy, including whether proxy headers are trusted.
  * Key is provided by the caller (actor_id, IP, or composite) -
    rate_limit.py is auth-agnostic.
  * Eviction is lazy at check time; no background thread.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import math
import secrets
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Deque, Dict, Optional
from pathlib import Path

from nth_dao.util.io import (
    InterProcessLock,
    atomic_write_json,
    safe_load_json,
)

logger = logging.getLogger("nth_dao.web.rate_limit")


@dataclass
class RateLimitDecision:
    """Outcome of a rate-limit check.

    Attributes
    ----------
    allowed
        True if the caller is within budget. False if they should be
        429'd.
    retry_after_seconds
        On rejection, the suggested wait before the caller's next
        attempt would succeed (the time until the oldest in-window
        timestamp falls out of the window).
    remaining
        Approximate remaining budget within the current window.
    """

    allowed: bool
    retry_after_seconds: float
    remaining: int


class RateLimiter:
    """Sliding-window per-key counter.

    Thread-safe via a single global lock. The lock is held only for
    the duration of the bucket fix-up + append, which is O(N) where
    N is the per-key limit (typically <= 32). For an
    expected-low-contention path this is fine.

    F-4 (4th-round audit): bounded memory. Previously the per-key
    dict grew monotonically - every unique actor_id created a
    permanent dict entry, even after its bucket emptied. A long-
    running server with N distinct actors over time accumulated N
    dict entries, regardless of current traffic.

    Two safeguards now:

      * After eviction inside ``check()`` the key is REMOVED from the
        dict when its bucket is empty (no in-window timestamps and
        no fresh append). This makes the dict track ACTIVELY rate-
        limited keys only.
      * ``max_tracked_keys`` caps the dict size; if exceeded the
        oldest-touched key is evicted (LRU-ish via insertion order).
    """

    DEFAULT_MAX_TRACKED_KEYS = 10_000

    def __init__(
        self, *, max_per_window: int, window_seconds: float,
        max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
    ):
        if max_per_window <= 0:
            raise ValueError("max_per_window must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_tracked_keys <= 0:
            raise ValueError("max_tracked_keys must be positive")
        self._max = max_per_window
        self._window = float(window_seconds)
        self._max_tracked_keys = max_tracked_keys
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = Lock()

    def check(self, key: str) -> RateLimitDecision:
        """Record an attempt by ``key`` and return whether it's allowed.

        The attempt's timestamp is only kept on success, so a burst of
        denied requests does NOT extend the window. This avoids the
        anti-pattern where a client hitting 429 repeatedly delays
        their own next allowed request.
        """
        if not isinstance(key, str) or not key:
            # No key = no rate limit. Callers should provide a
            # sensible default (e.g. "anonymous") if they want to
            # rate limit anonymous traffic.
            return RateLimitDecision(True, 0.0, self._max)

        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                # F-4: cap the dict size BEFORE creating a new entry.
                if len(self._buckets) >= self._max_tracked_keys:
                    # Pop the oldest insertion-order key. Python dicts
                    # preserve insertion order since 3.7, giving us
                    # cheap LRU-ish behaviour. The evicted actor will
                    # restart their window on next call, which is the
                    # same effect as natural window expiry.
                    oldest = next(iter(self._buckets))
                    self._buckets.pop(oldest, None)
                bucket = deque()
                self._buckets[key] = bucket
            # Evict timestamps older than the window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._max:
                # Reject. Suggest retry-after = until oldest expires.
                retry_after = max(0.0, (bucket[0] + self._window) - now)
                return RateLimitDecision(False, retry_after, 0)
            bucket.append(now)
            return RateLimitDecision(True, 0.0, self._max - len(bucket))

    def gc_empty_buckets(self) -> int:
        """Sweep through and remove keys whose buckets are empty.

        Intended to be called occasionally by background maintenance.
        F-4's natural eviction in ``check()`` only fires for keys that
        get re-touched; this method handles abandoned keys (an actor
        who hit the endpoint once a month ago and never came back).

        Returns the number of keys removed.
        """
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window
            removed = 0
            for key in list(self._buckets.keys()):
                bucket = self._buckets[key]
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                if not bucket:
                    self._buckets.pop(key, None)
                    removed += 1
            return removed

    def reset(self, key: Optional[str] = None) -> None:
        """Test-utility - clear one key's bucket, or all of them."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


class PersistentRateLimiter:
    """Cross-process fixed-window storage for low-frequency public routes.

    The state contains HMAC'd keys, never raw IPs. A random salt is created
    inside the same locked file, so independent web workers share both the
    privacy boundary and one request budget without an external service.
    """

    VERSION = 2

    def __init__(
        self,
        path: Path,
        *,
        max_per_window: int,
        window_seconds: float,
        max_tracked_keys: int = 4096,
        clock=time.time,
    ) -> None:
        if max_per_window <= 0:
            raise ValueError("max_per_window must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_tracked_keys <= 0:
            raise ValueError("max_tracked_keys must be positive")
        self._path = Path(path)
        self._max = int(max_per_window)
        self._window_ms = max(1, int(float(window_seconds) * 1000))
        self._max_tracked_keys = int(max_tracked_keys)
        self._clock = clock
        self._monotonic_clock = time.monotonic
        self._local_cache_secret = secrets.token_bytes(32)
        self._denied_until: Dict[str, tuple[float, int]] = {}
        self._denied_lock = Lock()

    def _local_cache_key(self, key: str) -> str:
        return hmac.new(
            self._local_cache_secret,
            key.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _cached_denial(
        self, key: str, observed_ms: int,
    ) -> Optional[RateLimitDecision]:
        now = self._monotonic_clock()
        private_key = self._local_cache_key(key)
        with self._denied_lock:
            cached = self._denied_until.get(private_key)
            if cached is None:
                return None
            denied_until, wall_until_ms = cached
            if denied_until <= now or observed_ms >= wall_until_ms:
                self._denied_until.pop(private_key, None)
                return None
            retry_after = denied_until - now
            return RateLimitDecision(False, retry_after, 0)

    def _remember_denial(
        self, key: str, retry_after: float, wall_until_ms: int,
    ) -> None:
        private_key = self._local_cache_key(key)
        with self._denied_lock:
            if (
                private_key not in self._denied_until
                and len(self._denied_until) >= self._max_tracked_keys
            ):
                oldest = min(
                    self._denied_until,
                    key=lambda item: self._denied_until[item][0],
                )
                self._denied_until.pop(oldest, None)
            self._denied_until[private_key] = (
                self._monotonic_clock() + max(0.0, retry_after),
                wall_until_ms,
            )

    def _forget_denial(self, key: str) -> None:
        with self._denied_lock:
            self._denied_until.pop(self._local_cache_key(key), None)

    def _load_state(self) -> Dict[str, object]:
        existed = self._path.exists()
        raw = safe_load_json(self._path, fallback=None)
        if raw is None and not existed:
            return {}
        if not isinstance(raw, dict) or raw.get("version") not in {1, self.VERSION}:
            raise ValueError("persistent rate-limit state is malformed")
        salt = raw.get("salt")
        buckets = raw.get("buckets")
        last_now_ms = raw.get("last_now_ms", 0)
        if (
            not isinstance(salt, str)
            or len(salt) != 64
            or not isinstance(buckets, dict)
            or type(last_now_ms) is not int
            or last_now_ms < 0
        ):
            raise ValueError("persistent rate-limit state is malformed")
        try:
            bytes.fromhex(salt)
        except ValueError as exc:
            raise ValueError("persistent rate-limit salt is malformed") from exc
        return {
            "version": self.VERSION,
            "salt": salt,
            "buckets": buckets,
            "last_now_ms": last_now_ms,
        }

    @staticmethod
    def _private_key(salt_hex: str, key: str) -> str:
        return hmac.new(
            bytes.fromhex(salt_hex),
            key.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def check(self, key: str) -> RateLimitDecision:
        if not isinstance(key, str) or not key:
            return RateLimitDecision(True, 0.0, self._max)
        observed_seconds = float(self._clock())
        if not math.isfinite(observed_seconds) or observed_seconds < 0:
            raise ValueError("persistent rate-limit clock is invalid")
        observed_ms = int(observed_seconds * 1000)
        cached = self._cached_denial(key, observed_ms)
        if cached is not None:
            return cached
        with InterProcessLock(self._path, timeout=5.0):
            state = self._load_state()
            # Wall time is required for cross-process persistence. Clamp it to
            # the last committed observation so an NTP/manual clock rollback
            # cannot erase a caller's active budget.
            now_ms_value = max(observed_ms, int(state.get("last_now_ms") or 0))
            cutoff = now_ms_value - self._window_ms
            salt = str(state.get("salt") or secrets.token_hex(32))
            raw_buckets = state.get("buckets")
            buckets = raw_buckets if isinstance(raw_buckets, dict) else {}
            cleaned: Dict[str, list[int]] = {}
            for bucket_key, values in list(buckets.items())[
                : self._max_tracked_keys * 2
            ]:
                if not isinstance(bucket_key, str) or not isinstance(values, list):
                    continue
                timestamps = sorted(
                    item for item in values
                    if type(item) is int and cutoff < item <= now_ms_value
                )[-self._max :]
                if timestamps:
                    cleaned[bucket_key] = timestamps
            private_key = self._private_key(salt, key)
            bucket = cleaned.get(private_key, [])
            if len(bucket) >= self._max:
                retry_ms = max(0, bucket[0] + self._window_ms - now_ms_value)
                retry_after = retry_ms / 1000.0
                # The persistent state is unchanged on rejection. Rewriting
                # it would let a blocked caller turn every 429 into fsync and
                # os.replace work. A short process-local negative cache also
                # avoids repeated lock and JSON reads during the same window.
                self._remember_denial(
                    key,
                    retry_after,
                    bucket[0] + self._window_ms,
                )
                return RateLimitDecision(False, retry_after, 0)
            if (
                private_key not in cleaned
                and len(cleaned) >= self._max_tracked_keys
            ):
                oldest = min(cleaned, key=lambda item: cleaned[item][-1])
                cleaned.pop(oldest, None)
            bucket.append(now_ms_value)
            cleaned[private_key] = bucket
            atomic_write_json(
                self._path,
                {
                    "version": self.VERSION,
                    "salt": salt,
                    "buckets": cleaned,
                    "last_now_ms": now_ms_value,
                },
            )
            self._forget_denial(key)
            return RateLimitDecision(True, 0.0, self._max - len(bucket))


async def enforce_min_response_time(start_monotonic: float, floor_seconds: float) -> None:
    """Pad the request handler's response time up to a floor.

    Mitigates the verify-endpoint timing oracle: without a floor,
    "missing proof" (microseconds) and "Ed25519 verify failed"
    (~100us) are distinguishable by wall-clock, leaking which gate
    fired. With a floor of e.g. 50ms, all rejections take roughly
    the same time.

    This is a SOFT mitigation - a determined attacker with N
    repeated probes can still average out the floor. The real
    defence is rate limiting (above). This floor stacks on top.
    """
    if floor_seconds <= 0:
        return
    elapsed = time.monotonic() - start_monotonic
    remaining = floor_seconds - elapsed
    if remaining > 0:
        await asyncio.sleep(remaining)


__all__ = [
    "RateLimitDecision",
    "RateLimiter",
    "PersistentRateLimiter",
    "enforce_min_response_time",
]
