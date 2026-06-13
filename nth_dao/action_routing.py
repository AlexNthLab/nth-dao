"""Action Router - signed cross-agent action dispatch.

Each agent registers handlers for the action types it can serve. An
incoming ``ActionRequest`` is signature-verified against the *claimed*
``from_agent``'s pubkey (looked up via ``pubkey_lookup``), then
dispatched to the matching handler; the resulting ``ActionResponse``
is signed by this agent and returned. Outbound requests are signed
before they leave the local process.

Two-way trust contract
----------------------
The router's security model is "signatures, not trust assertions"
(NTH DAO operating principle P4). To enforce it correctly the router
needs *external* knowledge of who each agent's pubkey is - otherwise
``from_agent = "alice"`` is just a string anyone can write. That
mapping comes from ``pubkey_lookup``, a callable ``str -> str | None``
the integrator wires up. Typical implementations:

    # AgentRegistry-backed
    def lookup(agent_id: str) -> Optional[str]:
        record = registry.get_record(agent_id)
        return record.metadata.get("pubkey_hex") if record else None

    # GroupRegistry-backed for cross-DAO routing
    def lookup(agent_id: str) -> Optional[str]:
        for record in group_registry.list_all():
            for pk in record.member_pubkeys + record.admin_pubkeys:
                if AgentID.from_pubkey(pk).value == agent_id:
                    return pk
        return None

If no ``pubkey_lookup`` is configured the router refuses to start unless
``allow_unsigned_dev=True`` is passed explicitly:
- unsigned requests are accepted only in that explicit dev mode
- signed requests are NOT verified in dev mode (we have no way to)
This is visible in the constructor, not a hidden default.

Production mode (``pubkey_lookup`` set, identity set, can_sign=True)
rejects:
- requests without a signature
- requests whose claimed ``from_agent`` has no registered pubkey
- requests whose signature does not verify under the claimed pubkey
- (implicitly) requests where an attacker forges ``from_agent="alice"``
  but signs with their own key - the lookup yields alice's pubkey,
  the attacker's signature fails to verify

This is the fix for the critical security bug in the original
@andy1868 submission, which called ``verify_json(payload, sig)``
without passing ``from_agent``'s pubkey - falling back to the
router's own pubkey and accidentally rejecting every legitimate
cross-agent request.

Design contributed by @andy1868 in the agent-collab submission
(June 2026). This implementation preserves the request/response
dataclasses, handler registry, four routing strategies, idempotency
cache, byte-offset indexed JSONL logs, and channel integration,
while rewiring the verification path to correctly check the claimed
sender's pubkey via the new ``pubkey_lookup`` injection point.
"""

from __future__ import annotations

import inspect
import json
import logging
import threading
import uuid
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

from datetime import datetime, timezone

from .util import InterProcessLock, atomic_write_json, monotonic_ms, now_iso, safe_load_json
from .identity import normalize_for_canonical_json

if TYPE_CHECKING:
    from .channel import TeamChannel
    from .discovery.peer_finder import PeerFinder
    from .identity import AgentIdentity

logger = logging.getLogger("nth_dao.action_routing")

# Cache key is namespaced by sender to fix C-2 (cross-sender collision).
CacheKey = Tuple[str, str]    # (from_agent, request_id)
MAX_LOG_TO_AGENT_LEN = 128    # H-6: bound attacker-controlled echo

# P2 anti-replay defaults. Production deployments should configure
# these based on the actual network latency tolerance + how long they
# want the nonce ledger to absorb retries.
DEFAULT_REQUEST_TTL_SECONDS = 300.0        # 5 minutes is generous for an action
DEFAULT_CLOCK_SKEW_SECONDS = 60.0          # forward-skew tolerance
DEFAULT_NONCE_LEDGER_NAME = "nonces.json"  # in storage_dir


PubkeyLookup = Callable[[str], Optional[str]]
"""Resolve an agent_id to its hex-encoded Ed25519 pubkey, or None when
the agent is not known. Wired by the integrator to AgentRegistry,
GroupRegistry, or any custom directory."""


def _truncate(value: str, max_len: int) -> str:
    """Bound the length of attacker-controlled strings before logging
    or echoing them in responses (H-6 amplification mitigation)."""
    if not value:
        return ""
    return value if len(value) <= max_len else value[:max_len] + "..."


def _dm_scope(a: str, b: str) -> str:
    """Stable, collision-resistant DM scope id.

    M-3 fix: the original ``f"dm:{min(a,b)}--{max(a,b)}"`` collided
    when an agent_id contained the ``--`` separator. SHA-256 over the
    canonical-JSON of the sorted pair is opaque, bounded length, and
    immune to separator-injection."""
    import hashlib
    pair = sorted((a or "", b or ""))
    payload = json.dumps(pair, separators=(",", ":")).encode("utf-8")
    return "dm:" + hashlib.sha256(payload).hexdigest()[:16]


# --------------------------- enums --------------------------


class ActionStatus(str, Enum):
    REQUEST = "request"
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


class RouteStrategy(str, Enum):
    DIRECT = "direct"
    BEST_MATCH = "best_match"
    FANOUT = "fanout"
    ROUND_ROBIN = "round_robin"


# --------------------------- dataclasses --------------------------


@dataclass
class HandlerInfo:
    action_type: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionRequest:
    request_id: str
    action_type: str
    from_agent: str
    to_agent: str
    params: Dict[str, Any] = field(default_factory=dict)
    strategy: str = RouteStrategy.DIRECT.value
    correlation_id: str = ""
    reply_to: str = ""
    timestamp: str = field(default_factory=now_iso)
    sig: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def signable_dict(self) -> dict:
        d = self.to_dict()
        d.pop("sig", None)
        return normalize_for_canonical_json(d)

    @classmethod
    def from_dict(cls, data: dict) -> "ActionRequest":
        return cls(
            request_id=data.get("request_id", ""),
            action_type=data.get("action_type", ""),
            from_agent=data.get("from_agent", ""),
            to_agent=data.get("to_agent", ""),
            params=data.get("params", {}),
            strategy=data.get("strategy", RouteStrategy.DIRECT.value),
            correlation_id=data.get("correlation_id", ""),
            reply_to=data.get("reply_to", ""),
            timestamp=data.get("timestamp", ""),
            sig=data.get("sig", ""),
        )

    @property
    def short_id(self) -> str:
        return self.request_id[:8] if self.request_id else "?"


@dataclass
class ActionResponse:
    request_id: str
    action_type: str
    from_agent: str
    to_agent: str
    status: str = ActionStatus.COMPLETED.value
    result: Any = None
    error: str = ""
    elapsed_ms: float = 0.0
    timestamp: str = field(default_factory=now_iso)
    sig: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def signable_dict(self) -> dict:
        d = self.to_dict()
        d.pop("sig", None)
        return normalize_for_canonical_json(d)

    @classmethod
    def from_dict(cls, data: dict) -> "ActionResponse":
        return cls(
            request_id=data.get("request_id", ""),
            action_type=data.get("action_type", ""),
            from_agent=data.get("from_agent", ""),
            to_agent=data.get("to_agent", ""),
            status=data.get("status", ActionStatus.COMPLETED.value),
            result=data.get("result"),
            error=data.get("error", ""),
            elapsed_ms=data.get("elapsed_ms", 0.0),
            timestamp=data.get("timestamp", ""),
            sig=data.get("sig", ""),
        )

    @property
    def ok(self) -> bool:
        return self.status == ActionStatus.COMPLETED.value


# --------------------------- router --------------------------


class ActionRouter:
    """Per-agent action handler registry + signed dispatch.

    Production-mode constructor::

        router = ActionRouter(
            agent_id="alice",
            identity=alice_identity,
            pubkey_lookup=lambda aid: registry.get_record(aid).pubkey_hex,
            channel=team.channel,
            workspace=team.workspace,
        )

    Explicit dev-mode constructor (no verification, no signing)::

        router = ActionRouter(
            agent_id="alice",
            workspace=tmp_path,
            allow_unsigned_dev=True,
        )
    """

    DEFAULT_STORAGE_DIR = "team_actions"
    DEFAULT_DEDUP_SIZE = 1024

    def __init__(
        self,
        agent_id: str,
        *,
        identity: Optional["AgentIdentity"] = None,
        pubkey_lookup: Optional[PubkeyLookup] = None,
        channel: Optional["TeamChannel"] = None,
        workspace: Optional[Path] = None,
        storage_dir: str = DEFAULT_STORAGE_DIR,
        max_dedup_entries: int = DEFAULT_DEDUP_SIZE,
        allow_unsigned_dev: bool = False,
        request_ttl_seconds: float = DEFAULT_REQUEST_TTL_SECONDS,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
        enable_nonce_ledger: Optional[bool] = None,
    ):
        """Construct an ActionRouter.

        Production mode (default and recommended) requires BOTH
        ``identity`` and ``pubkey_lookup``. Every incoming request must
        carry a verified Ed25519 signature; unsigned / unverified
        requests are rejected.

        Development mode is OPT-IN via ``allow_unsigned_dev=True``. It
        accepts unsigned requests AND signed-without-lookup requests
        without verification - useful for local smoke tests and
        notebook prototyping. It is a SECURITY HOLE if accidentally
        enabled in production; the flag is deliberately verbose so it
        shows up in code review and config files.

        P1 fix: original code silently fell into dev mode whenever
        identity or pubkey_lookup was missing. Integrators who forgot
        to wire up the directory would get a router that accepted
        every request as "unsigned" - the worst kind of default. Now
        the constructor raises unless dev mode is explicit, OR both
        production prerequisites are present.
        """
        if not allow_unsigned_dev:
            missing = []
            if identity is None or not identity.can_sign:
                missing.append("identity (with can_sign=True)")
            if pubkey_lookup is None:
                missing.append("pubkey_lookup")
            if missing:
                raise ValueError(
                    "ActionRouter requires " + " AND ".join(missing)
                    + " for production mode. To run in development mode "
                    "(accepts unsigned requests - NEVER for production!), "
                    "pass allow_unsigned_dev=True explicitly."
                )

        self.agent_id = agent_id
        self._identity = identity
        self._pubkey_lookup = pubkey_lookup
        self._allow_unsigned_dev = allow_unsigned_dev
        self._channel = channel
        self._workspace = workspace or Path.cwd()
        self._handlers: Dict[str, Callable[[ActionRequest], Any]] = {}
        self._handler_info: Dict[str, HandlerInfo] = {}
        self._round_robin_index: Dict[str, int] = {}
        self._max_dedup = max(1, max_dedup_entries)
        # C-3 fix: keyed on (from_agent, request_id) per C-2; LRU eviction
        # via move_to_end on access. C-1 fix: all reads/writes under _lock.
        self._seen: "OrderedDict[CacheKey, ActionResponse]" = OrderedDict()
        self._lock = threading.RLock()
        self._log_dir = self._workspace / storage_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        # H-5 fix: introspect best_match signature once so per-call dispatch
        # never has to swallow a TypeError to discover the calling convention.
        self._best_match_uses_prefer_status: Optional[bool] = None

        # P2 anti-replay state. Two layers of defence:
        #   1. TTL: reject requests whose timestamp is older than now -
        #      ttl, OR more than skew seconds in the future.
        #   2. Persistent nonce ledger: every successfully-verified
        #      (from_agent, request_id) is reserved on disk BEFORE handler
        #      execution; a second delivery of the SAME pair is rejected
        #      even across parallel routers, cache eviction, and restarts.
        # The ledger is opt-in for dev mode (where it would just add
        # disk churn for smoke tests); production mode turns it on by
        # default unless the caller explicitly opts out.
        self._request_ttl_seconds = max(0.0, request_ttl_seconds)
        self._clock_skew_seconds = max(0.0, clock_skew_seconds)
        if enable_nonce_ledger is None:
            self._enable_nonce_ledger = not allow_unsigned_dev
        else:
            self._enable_nonce_ledger = bool(enable_nonce_ledger)
        self._nonce_ledger_path = self._log_dir / DEFAULT_NONCE_LEDGER_NAME
        self._nonce_lock_path = self._nonce_ledger_path.with_suffix(".json.lock")

    # -- verification (the critical path) ------------------

    @property
    def _verify_enabled(self) -> bool:
        """Production mode requires BOTH a local identity (to know who
        we are) AND a pubkey_lookup (to know who the sender is).
        Either alone is insufficient - running with identity-only would
        let an attacker forge from_agent and have us accept it because
        we'd have no way to refute."""
        return (
            self._identity is not None
            and self._identity.can_sign
            and self._pubkey_lookup is not None
        )

    def _verify_request(self, request: ActionRequest) -> bool:
        """Verify *request.sig* using the *claimed* sender's pubkey.

        Explicit dev mode (allow_unsigned_dev=True): accept unconditionally.
        Production mode:
          - unsigned request -> reject
          - from_agent unknown to lookup -> reject
          - signature does not verify under the looked-up pubkey -> reject
          - same lookup but attacker signed with their own key -> reject
            (because the lookup returns the *claimed* agent's pubkey,
            not the attacker's)
        """
        if not self._verify_enabled:
            return True
        if not request.sig:
            return False
        # CRIT-1 fix 2026-06-10: explicit None check survives `python -O`
        # (assert vanishes under optimisation). The next try/except WOULD
        # catch the resulting TypeError so this isn't a bypass, but a
        # ConfigError surfaces the integrator's setup mistake far earlier
        # and with a useful message rather than a logged "verify reject".
        if self._pubkey_lookup is None:
            raise RuntimeError(
                "ActionRouter._pubkey_lookup is None but _verify_enabled "
                "is True -- caller must wire a lookup callable.",
            )
        # C-9 fix: pubkey_lookup is an arbitrary integrator-provided callable.
        # If it raises (network error, malformed registry record, ...) we
        # must NOT let the exception propagate out of the handle() path -
        # the request just gets rejected with no oracle leakage.
        try:
            sender_pubkey = self._pubkey_lookup(request.from_agent)
        except Exception as exc:   # noqa: BLE001
            logger.warning(
                "verify reject %s: pubkey_lookup raised: %s",
                request.short_id, exc,
            )
            return False
        if not sender_pubkey:
            logger.warning(
                "verify reject %s: from_agent %r not in directory",
                request.short_id, request.from_agent,
            )
            return False
        # CRIT-1 fix 2026-06-10: see explanation above.
        if self._identity is None:
            raise RuntimeError(
                "ActionRouter._identity is None but _verify_enabled "
                "is True -- caller must wire an Identity instance.",
            )
        try:
            return self._identity.verify_json(
                request.signable_dict(),
                request.sig,
                pubkey_hex=sender_pubkey,
            )
        except Exception as exc:   # noqa: BLE001
            logger.warning(
                "verify reject %s: signature verification raised: %s",
                request.short_id, exc,
            )
            return False

    # -- handler registry ----------------------------------

    def register(
        self,
        action_type: str,
        handler: Callable[[ActionRequest], Any],
        *,
        description: str = "",
        input_schema: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if action_type in self._handlers:
            logger.warning("action_type %r already registered - overwriting", action_type)
        self._handlers[action_type] = handler
        # M-8 fix: defensive copies so a mutation by the registrant after
        # register() doesn't leak into the registry.
        self._handler_info[action_type] = HandlerInfo(
            action_type=action_type,
            description=description,
            input_schema=dict(input_schema) if input_schema else {},
            metadata=dict(metadata) if metadata else {},
        )

    def unregister(self, action_type: str) -> bool:
        existed = action_type in self._handlers
        self._handlers.pop(action_type, None)
        self._handler_info.pop(action_type, None)
        self._round_robin_index.pop(action_type, None)
        return existed

    def has_handler(self, action_type: str) -> bool:
        return action_type in self._handlers

    @property
    def capabilities(self) -> List[str]:
        return sorted(self._handlers)

    def list_handlers(self) -> List[HandlerInfo]:
        return [self._handler_info[t] for t in sorted(self._handlers)]

    def handler_info(self, action_type: str) -> Optional[HandlerInfo]:
        return self._handler_info.get(action_type)

    # -- execution -----------------------------------------

    def handle(self, request: ActionRequest) -> ActionResponse:
        """verify -> target gate -> dedup -> dispatch -> sign -> log.

        C-1 fix: the entire critical section is under ``self._lock``.
        Concurrent handle() calls with the same request_id will serialise,
        the second one will hit the dedup cache, and the handler will
        execute exactly once. Without the lock, idempotency was a hope.

        P0-#2 fix: requests addressed to OTHER agents are rejected at
        the gate. Without this check, a signed request for Alice that
        leaks (or is routed) to Bob's router would execute on Bob's
        handlers - the signature is valid, just the destination is wrong.
        Treat as a protocol violation, not a silent bug.
        """
        # P0-#2: target gate - cheaper than signature verify, so do it
        # FIRST and reject misdirected traffic before spending CPU on Ed25519.
        if request.to_agent and request.to_agent != self.agent_id:
            return ActionResponse(
                request_id=request.request_id,
                action_type=request.action_type,
                from_agent=self.agent_id,
                to_agent=_truncate(request.from_agent, MAX_LOG_TO_AGENT_LEN),
                status=ActionStatus.REJECTED.value,
                error=f"misdirected: to_agent={_truncate(request.to_agent, 64)!r} "
                      f"!= self.agent_id={self.agent_id!r}",
                sig="",   # do not sign misdirected rejections (H-6 rule)
            )
        # H-6 fix: signature-failure rejections - same rules as above.
        if not self._verify_request(request):
            return ActionResponse(
                request_id=request.request_id,
                action_type=request.action_type,
                from_agent=self.agent_id,
                to_agent=_truncate(request.from_agent, MAX_LOG_TO_AGENT_LEN),
                status=ActionStatus.REJECTED.value,
                error="signature verification failed",
                # NOT signed - see H-6. Caller cannot replay this as an oracle.
                sig="",
            )
            # NB: rejected responses are also NOT logged or cached. They
            # never reached an authenticated state; pretending otherwise
            # would fill the log with attacker-controlled garbage (H-6).

        # P2 anti-replay gate (#1 of 2): TTL window. Only applies in
        # verified mode; dev mode and the no-TTL configuration skip.
        if self._verify_enabled and self._request_ttl_seconds > 0:
            ttl_error = self._check_request_freshness(request)
            if ttl_error is not None:
                return ActionResponse(
                    request_id=request.request_id,
                    action_type=request.action_type,
                    from_agent=self.agent_id,
                    to_agent=_truncate(request.from_agent, MAX_LOG_TO_AGENT_LEN),
                    status=ActionStatus.REJECTED.value,
                    error=ttl_error,
                    sig="",
                )

        # P2 anti-replay gate (#2 of 2): persistent nonce ledger. The
        # reservation is atomic under an inter-process lock and happens
        # BEFORE handler execution. A post-execution "record nonce" leaves
        # a race where two worker processes both pass the check, both run
        # the handler, and only then write the same key.
        if self._enable_nonce_ledger and self._verify_enabled:
            if not self._reserve_nonce(request):
                return ActionResponse(
                    request_id=request.request_id,
                    action_type=request.action_type,
                    from_agent=self.agent_id,
                    to_agent=_truncate(request.from_agent, MAX_LOG_TO_AGENT_LEN),
                    status=ActionStatus.REJECTED.value,
                    error="replay detected: (from_agent, request_id) "
                          "already processed",
                    sig="",
                )

        # C-2 fix: cache key is (sender, request_id). Two different agents
        # using request_id="r1" will not collide.
        key: CacheKey = (request.from_agent, request.request_id)

        with self._lock:
            cached = self._seen.get(key)
            if cached is not None:
                # C-3 fix: LRU touch on hit so the eviction policy actually
                # keeps the *recently used* entries, not the recently
                # inserted ones.
                self._seen.move_to_end(key)
                return cached

            # H-4 fix: monotonic clock - never goes backward under NTP jumps.
            start_ms = monotonic_ms()
            handler = self._handlers.get(request.action_type)
            if handler is None:
                response = ActionResponse(
                    request_id=request.request_id,
                    action_type=request.action_type,
                    from_agent=self.agent_id,
                    to_agent=request.from_agent,
                    status=ActionStatus.FAILED.value,
                    error=f"no handler registered for action_type {request.action_type!r}",
                )
            else:
                try:
                    result = handler(request)
                    response = ActionResponse(
                        request_id=request.request_id,
                        action_type=request.action_type,
                        from_agent=self.agent_id,
                        to_agent=request.from_agent,
                        status=ActionStatus.COMPLETED.value,
                        result=result,
                        elapsed_ms=round(monotonic_ms() - start_ms, 1),
                    )
                except Exception as exc:   # noqa: BLE001
                    response = ActionResponse(
                        request_id=request.request_id,
                        action_type=request.action_type,
                        from_agent=self.agent_id,
                        to_agent=request.from_agent,
                        status=ActionStatus.FAILED.value,
                        error=f"{type(exc).__name__}: {exc}",
                        elapsed_ms=round(monotonic_ms() - start_ms, 1),
                    )
                    logger.exception("handler %r raised", request.action_type)

            self._sign_response(response)
            self._log(request, response)
            self._cache(key, response)
            return response

    # -- outbound routing ----------------------------------

    def route(
        self,
        action_type: str,
        params: Dict[str, Any],
        *,
        target_agent: str,
        strategy: str = RouteStrategy.DIRECT.value,
        correlation_id: str = "",
        reply_to: str = "",
    ) -> Optional[ActionRequest]:
        if self._channel is None:
            logger.warning("route() called but no channel configured")
            return None
        request = ActionRequest(
            request_id=uuid.uuid4().hex,
            action_type=action_type,
            from_agent=self.agent_id,
            to_agent=target_agent,
            params=params,
            strategy=strategy,
            correlation_id=correlation_id,
            reply_to=reply_to,
        )
        self._sign_request(request)
        # M-3 fix: SHA-256 fingerprint of the sorted (a, b) pair, so an
        # agent_id containing the literal `--` separator can't collide
        # with another (a, b) pair. URL-quoting would also work, but
        # hashing keeps the scope key bounded length AND opaque to log
        # scrapers that don't need to know the participants.
        scope = _dm_scope(self.agent_id, target_agent)
        self._channel.send(
            content=json.dumps(request.to_dict(), ensure_ascii=False),
            scope=scope,
            content_type="action/request",
            metadata={
                "action_type": action_type,
                "request_id": request.request_id,
                "strategy": strategy,
            },
        )
        self._append_log("requests_sent", request.to_dict())
        return request

    def dispatch(
        self,
        action_type: str,
        params: Dict[str, Any],
        *,
        finder: Optional["PeerFinder"] = None,
        strategy: str = RouteStrategy.BEST_MATCH.value,
        correlation_id: str = "",
        exclude_agents: Optional[List[str]] = None,
    ) -> Optional[ActionRequest]:
        if finder is None:
            logger.warning("dispatch() called without finder")
            return None
        exclude = list(exclude_agents or [])
        if self.agent_id not in exclude:
            exclude.append(self.agent_id)

        if strategy == RouteStrategy.BEST_MATCH.value:
            return self._dispatch_best_match(action_type, params, finder, exclude, correlation_id)
        if strategy == RouteStrategy.ROUND_ROBIN.value:
            return self._dispatch_round_robin(action_type, params, finder, exclude, correlation_id)
        if strategy == RouteStrategy.FANOUT.value:
            return self._dispatch_fanout(action_type, params, finder, exclude, correlation_id)
        logger.error("dispatch(%r): unknown strategy %r", action_type, strategy)
        return None

    def _capable_peers(self, finder: "PeerFinder", action_type: str, exclude: List[str]) -> List[Any]:
        if hasattr(finder, "find_available"):
            return finder.find_available(capability=action_type, exclude_agent_ids=exclude)
        return finder.find(
            capability=action_type, status="idle",
            exclude_agent_ids=exclude, only_alive=True,
        )

    def _dispatch_best_match(self, action_type, params, finder, exclude, correlation_id):
        # H-5 fix: introspect best_match's signature ONCE and remember which
        # calling convention this PeerFinder uses. The original code caught
        # TypeError per call to discover the shape - which silently swallowed
        # any UNRELATED TypeError raised inside best_match (e.g. a bug in the
        # PeerFinder itself), retrying with different args and producing
        # confused error messages.
        if self._best_match_uses_prefer_status is None:
            try:
                sig = inspect.signature(finder.best_match)
                self._best_match_uses_prefer_status = "prefer_status" in sig.parameters
            except (TypeError, ValueError):
                # C-extension or unintrospectable callable - default to the
                # newer convention and let any failure surface honestly.
                self._best_match_uses_prefer_status = True
        if self._best_match_uses_prefer_status:
            match = finder.best_match(
                needed_capabilities=[action_type],
                prefer_status="idle",
                exclude_agent_ids=exclude,
            )
        else:
            match = finder.best_match(
                needed_capabilities=[action_type],
                prefer_idle=True,
                exclude_agent_ids=exclude,
            )
        if match is None:
            logger.warning("dispatch(%r): no available agent", action_type)
            return None
        return self.route(
            action_type, params,
            target_agent=match.record.agent_id,
            strategy=RouteStrategy.BEST_MATCH.value,
            correlation_id=correlation_id,
        )

    def _dispatch_round_robin(self, action_type, params, finder, exclude, correlation_id):
        peers = self._capable_peers(finder, action_type, exclude)
        if not peers:
            return None
        idx = self._round_robin_index.get(action_type, 0) % len(peers)
        target = peers[idx].agent_id
        self._round_robin_index[action_type] = idx + 1
        return self.route(
            action_type, params,
            target_agent=target,
            strategy=RouteStrategy.ROUND_ROBIN.value,
            correlation_id=correlation_id,
        )

    def _dispatch_fanout(self, action_type, params, finder, exclude, correlation_id):
        peers = self._capable_peers(finder, action_type, exclude)
        if not peers:
            return None
        first = None
        for peer in peers:
            sent = self.route(
                action_type, params,
                target_agent=peer.agent_id,
                strategy=RouteStrategy.FANOUT.value,
                correlation_id=correlation_id,
            )
            if first is None:
                first = sent
        return first

    # -- inbound parsing -----------------------------------

    def parse_incoming(self, message_data: dict) -> Optional[ActionRequest]:
        """Parse a ChannelMessage envelope OR a flat ActionRequest dict.

        P0-#1 fix: the original implementation expected ``message_data``
        to be flat (``request_id``, ``action_type``, ``to_agent`` at top
        level). That worked for unit tests but NOT for messages produced
        by ``route()`` -> ``channel.send()``, which wraps the request
        payload as a JSON string under ``content`` inside a
        ``ChannelMessage``:

            {"msg_id": ..., "from_agent": ..., "content_type":
             "action/request", "content": "<JSON of ActionRequest>", ...}

        Now handles both shapes:
          * if ``content`` is a string and ``content_type`` is
            ``action/request``, JSON-decode the content and build from it
          * if the dict already looks like a flat ActionRequest, build
            directly (kept for unit tests and out-of-band callers).

        Cross-check: when the envelope carries its own ``from_agent``
        (e.g. relayed via a TeamChannel), and it disagrees with the
        inner request's ``from_agent``, log a warning. Authentication
        still rides on the signature, so this is informational, not
        a rejection.
        """
        if message_data.get("content_type", "") != "action/request":
            return None

        # Real ChannelMessage envelope: content is a JSON string
        content = message_data.get("content")
        request_dict: Dict[str, Any]
        if isinstance(content, str):
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as exc:
                logger.warning("action/request content is not valid JSON: %s", exc)
                return None
            if not isinstance(parsed, dict):
                logger.warning(
                    "action/request content is not a JSON object: %s",
                    type(parsed).__name__,
                )
                return None
            request_dict = parsed
            envelope_sender = message_data.get("from_agent", "")
            if envelope_sender and envelope_sender != request_dict.get("from_agent"):
                logger.info(
                    "action/request envelope sender %r != inner from_agent %r "
                    "(probably a relay; signature verification still applies)",
                    envelope_sender, request_dict.get("from_agent"),
                )
        else:
            # Backwards-compat: flat dict (the unit-test calling pattern).
            request_dict = message_data

        try:
            return ActionRequest.from_dict(request_dict)
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("failed to parse action request: %s", exc)
            return None

    def handle_incoming(self, message_data: dict) -> Optional[ActionResponse]:
        request = self.parse_incoming(message_data)
        if request is None:
            return None
        return self.handle(request)

    # -- history -------------------------------------------

    def requests_sent(self, limit: int = 50) -> List[ActionRequest]:
        return list(self._read_log("requests_sent", ActionRequest, limit))

    def responses_sent(self, limit: int = 50) -> List[ActionResponse]:
        return list(self._read_log("responses_sent", ActionResponse, limit))

    def requests_received(self, limit: int = 50) -> List[ActionRequest]:
        return list(self._read_log("requests_received", ActionRequest, limit))

    # -- signing -------------------------------------------

    def _sign_request(self, request: ActionRequest) -> None:
        if self._identity and self._identity.can_sign:
            request.sig = self._identity.sign_json(request.signable_dict())

    def _sign_response(self, response: ActionResponse) -> None:
        if self._identity and self._identity.can_sign:
            response.sig = self._identity.sign_json(response.signable_dict())

    # -- cache / logging -----------------------------------

    def _cache(self, key: CacheKey, response: ActionResponse) -> None:
        """LRU cache write (C-3). Caller MUST hold self._lock."""
        if key in self._seen:
            self._seen.move_to_end(key)
        self._seen[key] = response
        while len(self._seen) > self._max_dedup:
            self._seen.popitem(last=False)   # evict least-recently used
        # The persistent nonce was already reserved before handler
        # execution. Keeping cache writes separate preserves in-process
        # response memoisation without re-opening the cross-process race.

    # ===== P2 anti-replay helpers =====

    def _check_request_freshness(self, request: ActionRequest) -> Optional[str]:
        """Return None if request is within the TTL+skew window, else
        a human-readable rejection reason. Skips when timestamp is
        empty (back-compat, but logs)."""
        if not request.timestamp:
            logger.warning(
                "verified request %s has empty timestamp; skipping TTL check",
                request.short_id,
            )
            return None
        try:
            ts = datetime.fromisoformat(request.timestamp)
        except (ValueError, TypeError):
            return f"malformed timestamp: {request.timestamp!r}"
        # Normalise to aware UTC; reject naive timestamps in production
        # (they could be intentionally ambiguous across timezones to
        # widen the TTL window).
        if ts.tzinfo is None:
            return "naive timestamp rejected; must carry timezone marker"
        now = datetime.now(timezone.utc)
        age = (now - ts).total_seconds()
        if age > self._request_ttl_seconds:
            return (
                f"request expired: age={age:.1f}s "
                f"> ttl={self._request_ttl_seconds:.0f}s"
            )
        if age < -self._clock_skew_seconds:
            return (
                f"request from the future: skew={-age:.1f}s "
                f"> allowed={self._clock_skew_seconds:.0f}s"
            )
        return None

    def _load_nonce_ledger(self) -> Dict[str, float]:
        """Load the persisted nonce ledger ({key: epoch_seconds}).
        Caller MUST hold the inter-process lock."""
        raw = safe_load_json(self._nonce_ledger_path, fallback=None)
        if not isinstance(raw, dict):
            return {}
        # Sweep stale entries while we have the file open: anything older
        # than ttl + skew has its slot recovered for the next emit.
        cutoff = (
            datetime.now(timezone.utc).timestamp()
            - self._request_ttl_seconds
            - self._clock_skew_seconds
        )
        out: Dict[str, float] = {}
        for k, v in raw.items():
            if isinstance(v, (int, float)) and float(v) >= cutoff:
                out[str(k)] = float(v)
        return out

    @staticmethod
    def _nonce_key(from_agent: str, request_id: str) -> str:
        """Flat string key for the JSON ledger. Pipe is forbidden by the
        cache key invariant; using it as separator keeps the file small."""
        return f"{from_agent}|{request_id}"

    def _nonce_already_consumed(self, request: ActionRequest) -> bool:
        try:
            with InterProcessLock(self._nonce_lock_path):
                ledger = self._load_nonce_ledger()
                return self._nonce_key(request.from_agent, request.request_id) in ledger
        except OSError as exc:
            # If the ledger can't be opened, fail CLOSED: better to
            # reject than to silently allow a replay.
            logger.warning("nonce ledger read failed: %s; failing closed", exc)
            return True

    def _reserve_nonce(self, request: ActionRequest) -> bool:
        """Atomically reserve ``(from_agent, request_id)`` before work.

        Returns True only for the first verified delivery inside the TTL
        window. The reservation is deliberately made before handler
        execution: this is the only way to guarantee at-most-once behavior
        when several router instances share the same workspace.
        """
        try:
            with InterProcessLock(self._nonce_lock_path):
                ledger = self._load_nonce_ledger()
                key = self._nonce_key(request.from_agent, request.request_id)
                if key in ledger:
                    return False
                ledger[key] = datetime.now(
                    timezone.utc,
                ).timestamp()
                atomic_write_json(self._nonce_ledger_path, ledger)
                return True
        except OSError as exc:
            logger.warning("nonce ledger reserve failed: %s; failing closed", exc)
            return False

    def _log(self, request: ActionRequest, response: ActionResponse) -> None:
        self._append_log("requests_received", request.to_dict())
        self._append_log("responses_sent", response.to_dict())

    def _log_path(self, name: str) -> Path:
        return self._log_dir / f"{self.agent_id}_{name}.jsonl"

    def _append_log(self, name: str, data: dict) -> None:
        """H-3 fix: serialise append across processes.

        POSIX O_APPEND atomicity only holds for writes <= PIPE_BUF (~4KB);
        JSON lines easily exceed that. Without a lock, two concurrent
        writers can interleave bytes and yield a corrupt JSONL line that
        _read_log silently skips (audit loss). InterProcessLock here
        keeps appends serial across processes on Windows AND POSIX."""
        path = self._log_path(name)
        lock_path = path.with_suffix(path.suffix + ".lock")
        try:
            with InterProcessLock(lock_path):
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(data, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.warning("action log append failed: %s", exc)

    def _read_log(self, name: str, cls, limit: int):
        path = self._log_path(name)
        if not path.exists() or limit <= 0:
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.warning("action log read failed: %s", exc)
            return
        for raw in lines[-limit:]:
            line = raw.strip()
            if not line:
                continue
            try:
                yield cls.from_dict(json.loads(line))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue


__all__ = [
    "ActionStatus",
    "RouteStrategy",
    "ActionRequest",
    "ActionResponse",
    "HandlerInfo",
    "ActionRouter",
    "PubkeyLookup",
]
