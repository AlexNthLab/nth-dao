"""Optional curated-registry accelerator for federation peer discovery.

The registry is never an authority.  It supplies bounded URL/DID hints; every
candidate is independently DNS checked, IP pinned, identity-card verified, and
admitted through the learned-peer store before it appears in the result.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.discovery.federation_registry import (
    LearnedPeerCapacityError,
)
from nth_dao.federation_transport import (
    get_https_bytes_pinned,
    resolve_safe_public_https_ip,
)
from nth_dao.plugins.contracts import (
    PLUGIN_BASE_HOST_API_VERSION,
    CapabilityContract,
    PluginManifest,
    schema_digest,
)
from nth_dao.plugins.discovery_admission import FederationPeerAdmission
from nth_dao.plugins.registry_trust import (
    CURATED_REGISTRY_FORMAT,
    CuratedRegistryTrust,
)
from nth_dao.plugins.host import (
    CapabilitySchemas,
    PluginContext,
    PluginHost,
    PluginInvocationContext,
)
from nth_dao.plugins.network import normalize_peer_url


CURATED_REGISTRY_PLUGIN_ID = "org.nth-dao.discovery.curated-registry"
CURATED_REGISTRY_CAPABILITY_ID = "org.nth-dao.discovery.curated-registry"
_MAX_RESULTS = 64
_MAX_INDEX_HINTS = 256
_MAX_INDEX_BYTES = 256 * 1024
_MAX_URL_BYTES = 2048
_MAX_DID_BYTES = 512
_MAX_VERIFICATION_ATTEMPTS = 64
_DISCOVERY_DEADLINE_S = 30.0
_PEER_VERIFY_TIMEOUT_S = 2.0

CURATED_REGISTRY_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_RESULTS},
    },
}

_VERIFIED_PEER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "did": {"type": "string", "minLength": 1, "maxLength": _MAX_DID_BYTES},
        "expires_at_ms": {"type": "integer", "minimum": 0},
        "peer_url": {"type": "string", "minLength": 1, "maxLength": _MAX_URL_BYTES},
        "resolved_ip": {"type": "string", "minLength": 1, "maxLength": 64},
        "verified_at_ms": {"type": "integer", "minimum": 0},
    },
    "required": [
        "did",
        "expires_at_ms",
        "peer_url",
        "resolved_ip",
        "verified_at_ms",
    ],
}

CURATED_REGISTRY_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "attempted_hints": {"type": "integer", "minimum": 0},
        "publisher_did": {"type": "string", "minLength": 1, "maxLength": 512},
        "rejected_hints": {"type": "integer", "minimum": 0},
        "registry_version": {"type": "integer", "minimum": 1},
        "truncated": {"type": "boolean"},
        "version_committed": {"type": "boolean"},
        "verified_peers": {
            "type": "array",
            "maxItems": _MAX_RESULTS,
            "items": _VERIFIED_PEER_SCHEMA,
        },
    },
    "required": [
        "attempted_hints",
        "publisher_did",
        "rejected_hints",
        "registry_version",
        "truncated",
        "version_committed",
        "verified_peers",
    ],
}

CURATED_REGISTRY_CONTRACT = CapabilityContract(
    capability_id=CURATED_REGISTRY_CAPABILITY_ID,
    version="2.0.0",
    input_schema_digest=schema_digest(CURATED_REGISTRY_INPUT_SCHEMA),
    output_schema_digest=schema_digest(CURATED_REGISTRY_OUTPUT_SCHEMA),
    effects=("filesystem-read", "filesystem-write", "network-read"),
    consistency="C1",
    privacy="workspace",
    security="verified-input",
    cardinality="many",
    deterministic=False,
    retention="durable",
    failure_semantics="retry-safe",
)

_REQUIRED_GRANTS = frozenset(
    {
        "filesystem.read.workspace",
        "filesystem.write.workspace",
        "network.client",
    }
)
_ARTIFACT_CLOSURE_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/did_key.py",
    "nth_dao/discovery/federation_registry.py",
    "nth_dao/federation_transport.py",
    "nth_dao/plugins/audit.py",
    "nth_dao/plugins/builtin/curated_registry_discovery.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/discovery_admission.py",
    "nth_dao/plugins/federation_trust.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/network.py",
    "nth_dao/plugins/registry_trust.py",
    "nth_dao/plugins/schema.py",
    "nth_dao/util/io.py",
    "requirements/crypto.lock.txt",
)


def _artifact_closure_digest() -> str:
    root = Path(__file__).parents[3]
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in _ARTIFACT_CLOSURE_PATHS
    ]
    return f"sha256:{hashlib.sha256(canonical_json({'files': files})).hexdigest()}"


def curated_registry_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=CURATED_REGISTRY_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="discovery.provider",
        runtime="builtin",
        provides=(CURATED_REGISTRY_CONTRACT,),
        requires=(),
        permissions=tuple(sorted(_REQUIRED_GRANTS)),
        artifact_digest=_artifact_closure_digest(),
    )


def normalize_curated_registry_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("curated registry URL is not configured")
    raw = value.strip()
    if len(raw.encode("utf-8")) > _MAX_URL_BYTES:
        raise ValueError("curated registry URL is too long")
    try:
        parsed = urlsplit(raw)
        parsed.port
    except ValueError as exc:
        raise ValueError("curated registry URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("curated registry URL must be a credential-free HTTPS URL")
    return raw.rstrip("/")


def _fetch_registry_document(registry_url: str) -> Any:
    normalized = normalize_curated_registry_url(registry_url)
    deadline = time.monotonic() + 5.0
    resolved_ip = resolve_safe_public_https_ip(
        normalized,
        timeout_s=1.0,
    )
    if resolved_ip is None:
        raise ValueError("curated registry URL did not resolve to a public HTTPS peer")
    remaining = deadline - time.monotonic()
    if remaining < 0.05:
        raise TimeoutError("curated registry resolution exceeded its deadline")
    body = get_https_bytes_pinned(
        normalized,
        resolved_ip,
        timeout_s=remaining,
        max_bytes=_MAX_INDEX_BYTES,
    )

    def reject_duplicates(pairs):
        document = {}
        for key, value in pairs:
            if key in document:
                raise ValueError(f"curated registry JSON repeats field {key!r}")
            document[key] = value
        return document

    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("curated registry returned invalid JSON") from exc


def _parse_registry_hints(
    document: Any,
    *,
    limit: int,
) -> tuple[list[tuple[str, str]], int, int, bool]:
    if not isinstance(document, Mapping) or set(document) != {"format", "peers"}:
        raise ValueError("curated registry document fields are invalid")
    if document.get("format") != CURATED_REGISTRY_FORMAT:
        raise ValueError("curated registry format is unsupported")
    peers = document.get("peers")
    if not isinstance(peers, list):
        raise ValueError("curated registry peers must be an array")
    if len(peers) > _MAX_INDEX_HINTS:
        raise ValueError("curated registry exceeds the hint limit")

    accepted: list[tuple[str, str]] = []
    seen_urls: set[str] = set()
    rejected = 0
    attempted = 0
    for item in peers:
        if len(accepted) >= limit:
            break
        attempted += 1
        if not isinstance(item, Mapping) or not set(item) <= {"peer_url", "did"}:
            rejected += 1
            continue
        if "peer_url" not in item:
            rejected += 1
            continue
        raw_url = item.get("peer_url")
        expected_did = item.get("did", "")
        if (
            not isinstance(raw_url, str)
            or len(raw_url.encode("utf-8")) > _MAX_URL_BYTES
            or not isinstance(expected_did, str)
            or len(expected_did.encode("utf-8")) > _MAX_DID_BYTES
        ):
            rejected += 1
            continue
        try:
            peer_url = normalize_peer_url(raw_url)
        except (TypeError, ValueError):
            rejected += 1
            continue
        if urlsplit(peer_url).scheme != "https":
            rejected += 1
            continue
        if expected_did and not is_did_key(expected_did):
            rejected += 1
            continue
        if peer_url in seen_urls:
            rejected += 1
            continue
        seen_urls.add(peer_url)
        accepted.append((peer_url, expected_did))
    return accepted, attempted, rejected, attempted < len(peers)


class CuratedRegistryDiscoveryProvider:
    def __init__(
        self,
        workspace: Path,
        *,
        get_registry_url: Callable[[], str],
        get_registry_publisher_did: Callable[[], str],
        admission: Any,
        registry_trust: Any,
        fetch_document: Optional[Callable[[str], Any]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not callable(get_registry_url) or not callable(get_registry_publisher_did):
            raise TypeError("curated registry configuration callbacks are required")
        self.workspace = Path(workspace).resolve()
        self._get_registry_url = get_registry_url
        self._get_registry_publisher_did = get_registry_publisher_did
        self._admission = admission
        if not callable(getattr(admission, "verify_candidate", None)) or not callable(
            getattr(admission, "persist_verified", None)
        ):
            raise TypeError("host-owned federation admission service is required")
        self._registry_trust = registry_trust
        if not callable(getattr(registry_trust, "verify", None)) or not callable(
            getattr(registry_trust, "commit", None)
        ) or not callable(getattr(registry_trust, "refresh_cycle", None)):
            raise TypeError("host-owned curated registry trust service is required")
        self._fetch_document = (
            _fetch_registry_document if fetch_document is None else fetch_document
        )
        if not callable(self._fetch_document):
            raise TypeError("fetch_document must be callable")
        self._clock = time.monotonic if clock is None else clock
        if not callable(self._clock):
            raise TypeError("clock must be callable")
        self._active = True
        self._state_lock = threading.Lock()
        self._cycle_lock = threading.Lock()

    def deactivate(self) -> None:
        with self._state_lock:
            self._active = False

    def _require_active(self) -> None:
        with self._state_lock:
            if not self._active:
                raise RuntimeError("curated registry provider is disabled")

    def _persist_if_active(self, verified: Any) -> None:
        with self._state_lock:
            if not self._active:
                raise RuntimeError("curated registry provider is disabled")
            self._admission.persist_verified(verified)

    def _commit_version_if_active(self, envelope: Any) -> None:
        with self._state_lock:
            if not self._active:
                raise RuntimeError("curated registry provider is disabled")
            self._registry_trust.commit(envelope)

    def discover(self, *, limit: int = 32) -> Dict[str, Any]:
        """Run one process-local and workspace-wide serialized refresh."""

        if type(limit) is not int or not 1 <= limit <= _MAX_RESULTS:
            raise ValueError(f"limit must be between 1 and {_MAX_RESULTS}")
        with self._registry_trust.refresh_cycle():
            return self._discover_under_lease(limit=limit)

    def _discover_under_lease(self, *, limit: int) -> Dict[str, Any]:
        if not self._cycle_lock.acquire(blocking=False):
            raise RuntimeError("curated registry refresh is already running")
        try:
            self._require_active()
            registry_url = normalize_curated_registry_url(self._get_registry_url())
            publisher_did = self._get_registry_publisher_did()
            if not isinstance(publisher_did, str) or not is_did_key(publisher_did):
                raise ValueError("curated registry publisher DID is not configured")
            document = self._fetch_document(registry_url)
            self._require_active()
            envelope = self._registry_trust.verify(
                document,
                expected_publisher_did=publisher_did,
            )
            # Accept the monotonic publisher version before parsing or
            # persisting any peer. If a newer version wins concurrently this
            # call fails before the older registry can create side effects.
            # A byte-identical signed envelope may retry after a partial
            # failure; the same version with different content fails closed.
            self._commit_version_if_active(envelope)
            hints, attempted, rejected, truncated = _parse_registry_hints(
                {
                    "format": CURATED_REGISTRY_FORMAT,
                    "peers": list(envelope.peers),
                },
                limit=_MAX_VERIFICATION_ATTEMPTS,
            )
            verified_peers = []
            seen_dids: set[str] = set()
            deadline = self._clock() + _DISCOVERY_DEADLINE_S
            for index, (peer_url, expected_did) in enumerate(hints):
                if len(verified_peers) >= limit:
                    truncated = truncated or index < len(hints)
                    break
                remaining = deadline - self._clock()
                if remaining < 0.25:
                    truncated = True
                    break
                self._require_active()
                try:
                    verified = self._admission.verify_candidate(
                        peer_url,
                        expected_did=expected_did,
                        timeout_seconds=min(_PEER_VERIFY_TIMEOUT_S, remaining),
                    )
                except (OSError, TimeoutError, ValueError):
                    verified = None
                if verified is None:
                    rejected += 1
                    continue
                self._require_active()
                endpoint = verified.endpoint
                if endpoint.did in seen_dids:
                    rejected += 1
                    continue
                try:
                    self._persist_if_active(verified)
                except (LearnedPeerCapacityError, ValueError):
                    rejected += 1
                    continue
                seen_dids.add(endpoint.did)
                verified_peers.append(
                    {
                        "peer_url": endpoint.url,
                        "did": endpoint.did,
                        "resolved_ip": endpoint.resolved_ip,
                        "verified_at_ms": endpoint.verified_at_ms,
                        "expires_at_ms": endpoint.expires_at_ms,
                    }
                )
            self._require_active()
            return {
                "attempted_hints": attempted,
                "publisher_did": envelope.publisher_did,
                "rejected_hints": rejected,
                "registry_version": envelope.version,
                "truncated": truncated,
                "version_committed": True,
                "verified_peers": verified_peers,
            }
        finally:
            self._cycle_lock.release()

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        if context.capability_id != CURATED_REGISTRY_CAPABILITY_ID:
            raise RuntimeError("curated registry capability context mismatch")
        return self.discover(limit=int(payload.get("limit", 32)))


class CuratedRegistryDiscoveryPlugin:
    def __init__(
        self,
        workspace: Path,
        *,
        get_registry_url: Callable[[], str],
        get_registry_publisher_did: Callable[[], str],
        admission: FederationPeerAdmission,
        registry_trust: CuratedRegistryTrust,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        self.get_registry_url = get_registry_url
        self.get_registry_publisher_did = get_registry_publisher_did
        self.admission = admission
        self.registry_trust = registry_trust
        self._provider: Optional[CuratedRegistryDiscoveryProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != CURATED_REGISTRY_PLUGIN_ID:
            raise RuntimeError("curated registry plugin context id mismatch")
        if not _REQUIRED_GRANTS <= context.granted_permissions:
            raise PermissionError("curated registry plugin lacks required grants")
        if context.workspace_root is None or context.workspace_root != self.workspace:
            raise PermissionError("curated registry workspace is not host-bound")
        if self._provider is not None:
            raise RuntimeError("curated registry plugin is already started")
        self._provider = CuratedRegistryDiscoveryProvider(
            self.workspace,
            get_registry_url=self.get_registry_url,
            get_registry_publisher_did=self.get_registry_publisher_did,
            admission=self.admission,
            registry_trust=self.registry_trust,
        )
        return {CURATED_REGISTRY_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def register_curated_registry_discovery(
    host: PluginHost,
    workspace: Path,
    *,
    get_registry_url: Callable[[], str],
    get_registry_publisher_did: Callable[[], str],
) -> PluginManifest:
    """Install the reviewed registry accelerator without enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = curated_registry_manifest()
    admission = FederationPeerAdmission(workspace)
    registry_trust = CuratedRegistryTrust(workspace)
    host.register_builtin(
        item,
        lambda: CuratedRegistryDiscoveryPlugin(
            workspace,
            get_registry_url=get_registry_url,
            get_registry_publisher_did=get_registry_publisher_did,
            admission=admission,
            registry_trust=registry_trust,
        ),
        allow_manifest_upgrade=True,
        schemas={
            CURATED_REGISTRY_CAPABILITY_ID: CapabilitySchemas(
                CURATED_REGISTRY_INPUT_SCHEMA,
                CURATED_REGISTRY_OUTPUT_SCHEMA,
            )
        },
        audited_capabilities={CURATED_REGISTRY_CAPABILITY_ID},
    )
    return item


__all__ = [
    "CURATED_REGISTRY_CAPABILITY_ID",
    "CURATED_REGISTRY_CONTRACT",
    "CURATED_REGISTRY_FORMAT",
    "CURATED_REGISTRY_INPUT_SCHEMA",
    "CURATED_REGISTRY_OUTPUT_SCHEMA",
    "CURATED_REGISTRY_PLUGIN_ID",
    "CuratedRegistryDiscoveryPlugin",
    "CuratedRegistryDiscoveryProvider",
    "curated_registry_manifest",
    "normalize_curated_registry_url",
    "register_curated_registry_discovery",
]
