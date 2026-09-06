"""Sync Nostr relay client — background-loop bridge over the borrowed async
``nostr_sdk.Client`` (same bridge pattern as ``WebSocketGossipTransport``).

Publish semantics: ``publish`` sends one event and waits for the relay OK
(bounded), returning an honest accepted/error result. Subscribe semantics:
a filter-backed subscription delivers events into a bounded queue drained
by ``poll``. All wire machinery (JSON relay protocol, reconnection, EOSE)
is the borrowed layer's; this class adds only the sync bridge and NTH
bounds (relay count cap, publish timeout, queue cap).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from typing import Any, Callable, List, Optional

from nth_dao.nostr import NostrAdapterUnavailable

try:  # pragma: no cover - importorskip in tests
    import nostr_sdk as _ns

    from nostr_sdk import Client as _Client
    from nostr_sdk import Filter as _Filter
    from nostr_sdk import Kind as _Kind
    _NOSTR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ns = None
    _Client = None
    _Filter = None
    _Kind = None
    _NOSTR_AVAILABLE = False

logger = logging.getLogger("nth_dao.nostr")

MAX_RELAYS = 16
MAX_EVENT_QUEUE = 4_096
_DEFAULT_PUBLISH_TIMEOUT = 10.0
_MAX_PUBLISH_TIMEOUT = 60.0


class NostrRelayError(RuntimeError):
    """Raised for relay client lifecycle and publish failures."""


def _validate_relay_url(value: str) -> str:
    """Relay URLs must be wss (ws only for loopback test hosts)."""

    from urllib.parse import urlsplit

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("relay url must be non-empty text")
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme == "wss":
        pass
    elif parsed.scheme == "ws" and hostname in {"localhost", "127.0.0.1", "::1"}:
        pass
    else:
        raise ValueError("relay url must be wss (ws only for loopback)")
    if not parsed.netloc or parsed.username or parsed.password or "@" in parsed.netloc:
        raise ValueError("relay url must not carry credentials")
    return value.rstrip("/")


class NostrRelayClient:
    """Sync facade over the borrowed async relay pool client."""

    def __init__(
        self,
        keys: Any,
        *,
        relay_urls: List[str],
        name: str = "nostr-relay",
        publish_timeout: float = _DEFAULT_PUBLISH_TIMEOUT,
    ) -> None:
        if not _NOSTR_AVAILABLE:
            raise NostrAdapterUnavailable(
                "nostr support requires the optional extra: pip install nth-dao[nostr]"
            )
        if not relay_urls or len(relay_urls) > MAX_RELAYS:
            raise ValueError(f"relay_urls must hold 1..{MAX_RELAYS} entries")
        self._relay_urls = [_validate_relay_url(url) for url in relay_urls]
        if len(set(self._relay_urls)) != len(self._relay_urls):
            raise ValueError("relay_urls must not contain duplicates")
        if not 0.1 <= float(publish_timeout) <= _MAX_PUBLISH_TIMEOUT:
            raise ValueError("publish_timeout must be within [0.1, 60]")
        self._keys = keys
        self._publish_timeout = float(publish_timeout)
        self.capabilities_name = name
        self._client = _Client()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()
        self._start_error: Optional[str] = None
        self._running = False
        self._queue: deque = deque(maxlen=MAX_EVENT_QUEUE)
        self._queue_lock = threading.Lock()

    # ─────────────────────── lifecycle ───────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._started.clear()
        self._start_error = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name=f"nth-nostr-{self.capabilities_name}", daemon=True
        )
        self._thread.start()
        if not self._started.wait(timeout=15.0):
            self._shutdown_loop()
            raise NostrRelayError("nostr relay client failed to start within 15s")
        if self._start_error is not None:
            self._shutdown_loop()
            raise NostrRelayError(f"nostr relay client failed to start: {self._start_error}")
        self._running = True

    def _run_loop(self) -> None:
        loop = self._loop
        assert loop is not None
        asyncio.set_event_loop(loop)

        async def _boot() -> None:
            try:
                from nostr_sdk import RelayUrl as _RelayUrl

                for url in self._relay_urls:
                    await self._client.add_relay(_RelayUrl.parse(url))
                await self._client.connect()
                self._start_error = None
            except Exception as exc:  # noqa: BLE001 - surfaced via the event
                self._start_error = str(exc)
            finally:
                self._started.set()

        boot = loop.create_task(_boot())
        try:
            loop.run_forever()
        finally:
            boot.cancel()
            try:
                loop.run_until_complete(boot)
            except (asyncio.CancelledError, Exception):
                pass
            loop.close()

    def _shutdown_loop(self) -> None:
        loop = self._loop
        self._loop = None
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def stop(self) -> None:
        if not self._running or self._loop is None:
            return
        try:
            stopper = asyncio.run_coroutine_threadsafe(
                self._client.disconnect(), self._loop
            )
            stopper.result(timeout=5.0)
        except Exception as exc:  # noqa: BLE001 - stop must never raise
            logger.warning("nostr relay disconnect failed: %s", exc)
        finally:
            self._running = False
            self._shutdown_loop()

    # ─────────────────────── public API ───────────────────────

    def publish(self, event: Any, *, timeout_s: Optional[float] = None) -> bool:
        """Send one signed event; return True when at least one relay OKs it."""

        if not self._running or self._loop is None:
            raise NostrRelayError("relay client is not running")
        timeout = self._publish_timeout if timeout_s is None else float(timeout_s)
        if not 0.1 <= timeout <= _MAX_PUBLISH_TIMEOUT:
            raise ValueError("timeout_s must be within [0.1, 60]")
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._client.send_event(event), self._loop
            )
            output = fut.result(timeout=timeout)
        except asyncio.TimeoutError:
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("nostr publish failed: %s", exc)
            return False
        return self._output_accepted(output)

    def subscribe_events(
        self,
        *,
        kinds: List[int],
        callback: Optional[Callable[[Any], None]] = None,
    ) -> None:
        """Subscribe to a kinds filter; events are queued and callback'd."""

        if not self._running or self._loop is None:
            raise NostrRelayError("relay client is not running")
        filter_obj = _Filter().kinds([_Kind(k) for k in kinds])
        fut = asyncio.run_coroutine_threadsafe(
            self._subscribe_async(filter_obj, callback), self._loop
        )
        fut.result(timeout=15.0)

    async def _subscribe_async(self, filter_obj: Any, callback: Optional[Callable]) -> None:
        from nostr_sdk import ReqTarget as _ReqTarget

        target = _ReqTarget.auto([filter_obj])
        stream = await self._client.stream_events(target)

        async def _pump() -> None:
            try:
                while True:
                    item = await stream.next()
                    if item is None:
                        break
                    event = getattr(item, "event", None) or getattr(item, "value", None)
                    if event is None:
                        continue
                    with self._queue_lock:
                        if len(self._queue) == self._queue.maxlen:
                            self._queue.popleft()
                        self._queue.append(event)
                    if callback is not None:
                        try:
                            callback(event)
                        except Exception:  # noqa: BLE001
                            logger.exception("nostr subscription callback raised")
            except Exception:  # noqa: BLE001 - stream errors end the pump
                logger.exception("nostr event stream ended with error")

        # cancel any previous pump before replacing it: a second
        # subscribe_events would otherwise leak the first coroutine
        # (round-20 bug GG-16)
        previous = getattr(self, "_stream_task", None)
        if previous is not None and not previous.done():
            previous.cancel()
        self._stream_task = asyncio.get_event_loop().create_task(_pump())

    def poll_events(self, *, max_items: int = 64) -> List[Any]:
        items: List[Any] = []
        with self._queue_lock:
            while self._queue and len(items) < max_items:
                items.append(self._queue.popleft())
        return items

    @staticmethod
    def _output_accepted(output: Any) -> bool:
        """A publish is accepted when at least one relay sent a truthy OK.

        nostr-sdk 0.45 SendEventOutput: ``success`` is a list of RelayUrl
        that OKed the event, ``failed`` maps rejected relays to reasons."""

        try:
            succeeded = getattr(output, "success", None)
            if isinstance(succeeded, list) and len(succeeded) > 0:
                return True
            return False
        except Exception:  # noqa: BLE001 - introspection must not crash
            return False

    # ─────────────────────── internals ───────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    def queue_depth(self) -> int:
        with self._queue_lock:
            return len(self._queue)


__all__ = [
    "MAX_RELAYS",
    "NostrRelayClient",
    "NostrRelayError",
]
