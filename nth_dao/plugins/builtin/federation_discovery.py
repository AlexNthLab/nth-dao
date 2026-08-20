"""Built-in adapter for the existing signed market federation protocol.

This module wraps the current implementation; it does not define a second
feed format or weaken peer verification. Network traversal remains on demand
in host API v1 so enabling the plugin does not create a hidden worker thread.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
from itertools import islice
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.discovery.federation_registry import LearnedPeerStore
from nth_dao.plugins.contracts import (
    PLUGIN_HOST_API_VERSION,
    CapabilityContract,
    PluginManifest,
    schema_digest,
)
from nth_dao.plugins.host import (
    CapabilitySchemas,
    PluginContext,
    PluginHost,
    PluginInvocationContext,
)
from nth_dao.plugins.network import VerifiedPeerEndpoint, normalize_peer_url


FEDERATION_DISCOVERY_PLUGIN_ID = "org.nth-dao.discovery.federation"
FEDERATION_DISCOVERY_CAPABILITY_ID = "org.nth-dao.discovery.federation"

FEDERATION_DISCOVERY_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {},
}

FEDERATION_DISCOVERY_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "attempted_sources": {"type": "integer", "minimum": 0},
        "cached_announcements": {"type": "integer", "minimum": 0},
        "cancelled": {"type": "boolean"},
        "completed_sources": {"type": "integer", "minimum": 0},
        "deadline_exhausted": {"type": "boolean"},
        "full_sources": {"type": "integer", "minimum": 0},
        "known_peers": {"type": "integer", "minimum": 0},
    },
    "required": [
        "attempted_sources",
        "cached_announcements",
        "cancelled",
        "completed_sources",
        "deadline_exhausted",
        "full_sources",
        "known_peers"
    ],
}

FEDERATION_DISCOVERY_CONTRACT = CapabilityContract(
    capability_id=FEDERATION_DISCOVERY_CAPABILITY_ID,
    version="1.0.0",
    input_schema_digest=schema_digest(FEDERATION_DISCOVERY_INPUT_SCHEMA),
    output_schema_digest=schema_digest(FEDERATION_DISCOVERY_OUTPUT_SCHEMA),
    effects=("filesystem-read", "filesystem-write", "network-read"),
    consistency="C1",
    privacy="workspace",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="ephemeral",
    failure_semantics="retry-safe",
)

_REQUIRED_GRANTS = frozenset(
    {
        "filesystem.read.workspace",
        "filesystem.write.workspace",
        "network.client",
    }
)
_MAX_CONFIGURED_SEEDS = 64
_MAX_SEED_URL_BYTES = 2048
_ARTIFACT_CLOSURE_PATHS = (
    "nth_dao/discovery/federation_registry.py",
    "nth_dao/plugins/builtin/federation_discovery.py",
    "nth_dao/plugins/network.py",
    "nth_dao/web/market_federation_poll.py",
)


def _artifact_closure_digest() -> str:
    """Bind the manifest to the adapter and its direct execution closure."""

    root = Path(__file__).parents[3]
    files = []
    for relative in _ARTIFACT_CLOSURE_PATHS:
        body = (root / relative).read_bytes()
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    return f"sha256:{hashlib.sha256(canonical_json({'files': files})).hexdigest()}"


def federation_discovery_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=FEDERATION_DISCOVERY_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_HOST_API_VERSION,
        kind="discovery.provider",
        runtime="builtin",
        provides=(FEDERATION_DISCOVERY_CONTRACT,),
        requires=(),
        permissions=tuple(sorted(_REQUIRED_GRANTS)),
        artifact_digest=_artifact_closure_digest(),
    )


@dataclass(frozen=True)
class FederationDiscoveryCycle:
    attempted_sources: int
    completed_sources: int
    full_sources: int
    cached_announcements: int
    known_peers: int
    deadline_exhausted: bool
    cancelled: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted_sources": self.attempted_sources,
            "completed_sources": self.completed_sources,
            "full_sources": self.full_sources,
            "cached_announcements": self.cached_announcements,
            "known_peers": self.known_peers,
            "deadline_exhausted": self.deadline_exhausted,
            "cancelled": self.cancelled,
        }


class FederationDiscoveryProvider:
    """On-demand view over the existing market federation traversal."""

    def __init__(
        self,
        workspace: Path,
        *,
        get_seed_peers: Callable[[], Sequence[str]],
        verify_seed_peer: Callable[[str], Optional[VerifiedPeerEndpoint]],
        verify_gossip_peer: Callable[[str, str], Optional[str]],
        http_get: Optional[Callable[[str, str], Any]] = None,
        max_duration_s: float = 30.0,
    ) -> None:
        if not callable(get_seed_peers):
            raise TypeError("get_seed_peers must be callable")
        if not callable(verify_seed_peer) or not callable(verify_gossip_peer):
            raise TypeError("federation peer verification callbacks are required")
        if isinstance(max_duration_s, bool) or not isinstance(max_duration_s, (int, float)):
            raise TypeError("max_duration_s must be numeric")
        if not 0.1 <= float(max_duration_s) <= 300.0:
            raise ValueError("max_duration_s must be between 0.1 and 300 seconds")
        self.workspace = Path(workspace).resolve()
        self.peer_store = LearnedPeerStore(self.workspace)
        self._get_seed_peers = get_seed_peers
        self._verify_seed_peer = verify_seed_peer
        self._verify_gossip_peer = verify_gossip_peer
        self._http_get = http_get
        self._max_duration_s = float(max_duration_s)
        self._cache = self._new_cache()
        self._active = True
        self._last_known_peer_count = 0
        self._state_lock = threading.Lock()
        self._cycle_lock = threading.Lock()
        self._stop_event = threading.Event()

    @staticmethod
    def _new_cache():
        # The federation runtime historically lives under nth_dao.web. Keep the
        # import lazy so core/plugin imports retain their zero-dependency path.
        from nth_dao.web.market_federation_poll import FederationCache

        return FederationCache()

    def deactivate(self) -> None:
        self._stop_event.set()
        with self._state_lock:
            self._active = False

    def _require_active(self) -> None:
        if not self._active:
            raise RuntimeError("federation discovery provider is disabled")

    def _seed_peers(self) -> tuple[str, ...]:
        try:
            iterator = iter(self._get_seed_peers())
        except TypeError as exc:
            raise TypeError("get_seed_peers must return an iterable") from exc
        raw_values = list(islice(iterator, _MAX_CONFIGURED_SEEDS + 1))
        if len(raw_values) > _MAX_CONFIGURED_SEEDS:
            raise ValueError(
                f"configured federation seeds exceed {_MAX_CONFIGURED_SEEDS}"
            )
        normalized = []
        for value in raw_values:
            if not isinstance(value, str):
                raise TypeError("configured federation seed URLs must be strings")
            candidate = value.strip()
            if not candidate:
                continue
            if len(candidate.encode("utf-8")) > _MAX_SEED_URL_BYTES:
                raise ValueError("configured federation seed URL is too long")
            normalized.append(normalize_peer_url(candidate))
        return tuple(dict.fromkeys(normalized))

    def known_peer_urls(self) -> tuple[str, ...]:
        with self._state_lock:
            self._require_active()
        seeds = self._seed_peers()
        learned = tuple(item.peer_url for item in self.peer_store.active())
        with self._state_lock:
            self._require_active()
            peers = tuple(dict.fromkeys((*seeds, *learned)))
            self._last_known_peer_count = len(peers)
        return peers

    def discover_once(self) -> FederationDiscoveryCycle:
        """Run one bounded cycle using the existing verified wire path."""
        from nth_dao.web.market_federation_poll import (
            FederationCycleReport,
            _urllib_get_json,
            federate_once,
        )

        with self._cycle_lock:
            with self._state_lock:
                self._require_active()
            report = FederationCycleReport()
            peer_count = 0
            try:
                seeds = list(self._seed_peers())
                learned = [
                    item.peer_url
                    for item in self.peer_store.active()
                    if item.peer_url not in seeds
                ]
                peer_count = len(set(seeds) | set(learned))
                with self._state_lock:
                    self._last_known_peer_count = peer_count
                if not seeds and not learned:
                    self._cache.replace_all({}, peer_count=0)
                else:
                    verified_seed_ips: Dict[str, str] = {}

                    def verify_seed(url: str) -> Optional[str]:
                        endpoint = self._verify_seed_peer(url)
                        if endpoint is None:
                            return None
                        if not isinstance(endpoint, VerifiedPeerEndpoint):
                            raise TypeError(
                                "verify_seed_peer must return VerifiedPeerEndpoint or None"
                            )
                        endpoint.require_current(int(time.time() * 1000))
                        if endpoint.url != normalize_peer_url(url):
                            raise ValueError("verified peer binding URL mismatch")
                        verified_seed_ips[url] = endpoint.resolved_ip
                        return endpoint.did

                    entries = federate_once(
                        seeds,
                        _urllib_get_json,
                        untrusted_peers=learned,
                        verify_gossip_peer=self._verify_gossip_peer,
                        verify_seed_peer=verify_seed,
                        verified_seed_ips=verified_seed_ips,
                        pinned_http_get=self._http_get,
                        max_duration_s=self._max_duration_s,
                        cycle_report=report,
                        source_since=self._cache.since_for_source,
                        cancelled=self._stop_event.is_set,
                    )
                    incomplete = len(
                        report.attempted_sources - report.completed_sources
                    )
                    cycle_error = ""
                    if report.cancelled:
                        cycle_error = "federation cycle cancelled"
                    elif report.deadline_exhausted:
                        cycle_error = "federation cycle deadline exhausted"
                    elif incomplete:
                        cycle_error = (
                            f"federation cycle incomplete: {incomplete} of "
                            f"{len(report.attempted_sources)} sources failed verification or pull"
                        )
                    self._cache.apply_cycle(
                        entries,
                        completed_sources=report.completed_sources,
                        full_sources=report.full_sources,
                        source_high_seq=report.source_high_seq,
                        source_dids=report.source_dids,
                        peer_count=peer_count,
                        error=cycle_error,
                    )
            except Exception as exc:
                self._cache.mark_error(
                    f"{type(exc).__name__}: {exc}",
                    peer_count=peer_count,
                )
                raise
            status = self._cache.status()
            return FederationDiscoveryCycle(
                attempted_sources=len(report.attempted_sources),
                completed_sources=len(report.completed_sources),
                full_sources=len(report.full_sources),
                cached_announcements=int(status["cached_announcements"]),
                known_peers=peer_count,
                deadline_exhausted=bool(report.deadline_exhausted),
                cancelled=bool(report.cancelled),
            )

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        if context.capability_id != FEDERATION_DISCOVERY_CAPABILITY_ID:
            raise RuntimeError("federation discovery capability context mismatch")
        if payload:
            raise ValueError("federation discovery input must be empty")
        return self.discover_once().to_dict()

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        with self._state_lock:
            self._require_active()
        return self._cache.snapshot()

    def status(self) -> Dict[str, Any]:
        with self._state_lock:
            self._require_active()
            known_peers = self._last_known_peer_count
        status = dict(self._cache.status())
        status["known_peers"] = known_peers
        status["wire_protocol"] = "nth-feed-digest-v1"
        return status


class FederationDiscoveryPlugin:
    def __init__(
        self,
        workspace: Path,
        *,
        get_seed_peers: Callable[[], Sequence[str]],
        verify_seed_peer: Callable[[str], Optional[VerifiedPeerEndpoint]],
        verify_gossip_peer: Callable[[str, str], Optional[str]],
        http_get: Optional[Callable[[str, str], Any]] = None,
        max_duration_s: float = 30.0,
    ) -> None:
        self._arguments = {
            "workspace": workspace,
            "get_seed_peers": get_seed_peers,
            "verify_seed_peer": verify_seed_peer,
            "verify_gossip_peer": verify_gossip_peer,
            "http_get": http_get,
            "max_duration_s": max_duration_s,
        }
        self._provider: FederationDiscoveryProvider | None = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != FEDERATION_DISCOVERY_PLUGIN_ID:
            raise RuntimeError("federation plugin context id mismatch")
        if not _REQUIRED_GRANTS <= context.granted_permissions:
            raise PermissionError("federation plugin lacks required permission grants")
        configured_workspace = Path(self._arguments["workspace"]).resolve()
        if context.workspace_root is None or configured_workspace != context.workspace_root:
            raise PermissionError(
                "federation plugin workspace is not bound to the host workspace"
            )
        if self._provider is not None:
            raise RuntimeError("federation plugin is already started")
        self._provider = FederationDiscoveryProvider(**self._arguments)
        return {FEDERATION_DISCOVERY_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def register_federation_discovery(
    host: PluginHost,
    workspace: Path,
    *,
    get_seed_peers: Callable[[], Sequence[str]],
    verify_seed_peer: Callable[[str], Optional[VerifiedPeerEndpoint]],
    verify_gossip_peer: Callable[[str, str], Optional[str]],
    http_get: Optional[Callable[[str, str], Any]] = None,
    max_duration_s: float = 30.0,
) -> PluginManifest:
    """Install the reviewed adapter without authorizing or enabling it."""
    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = federation_discovery_manifest()

    def factory() -> FederationDiscoveryPlugin:
        return FederationDiscoveryPlugin(
            workspace,
            get_seed_peers=get_seed_peers,
            verify_seed_peer=verify_seed_peer,
            verify_gossip_peer=verify_gossip_peer,
            http_get=http_get,
            max_duration_s=max_duration_s,
        )

    host.register_builtin(
        item,
        factory,
        allow_manifest_upgrade=True,
        schemas={
            FEDERATION_DISCOVERY_CAPABILITY_ID: CapabilitySchemas(
                FEDERATION_DISCOVERY_INPUT_SCHEMA,
                FEDERATION_DISCOVERY_OUTPUT_SCHEMA,
            )
        },
    )
    return item


__all__ = [
    "FEDERATION_DISCOVERY_CAPABILITY_ID",
    "FEDERATION_DISCOVERY_CONTRACT",
    "FEDERATION_DISCOVERY_INPUT_SCHEMA",
    "FEDERATION_DISCOVERY_OUTPUT_SCHEMA",
    "FEDERATION_DISCOVERY_PLUGIN_ID",
    "FederationDiscoveryCycle",
    "FederationDiscoveryPlugin",
    "FederationDiscoveryProvider",
    "federation_discovery_manifest",
    "register_federation_discovery",
]
