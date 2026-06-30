"""A2A Protocol Agent Card emission for NTH DAO nodes (2026-06-08).

Strategic alignment (L0-2 in the roadmap): NTH DAO already publishes a
signed identity card at ``/.well-known/nth-dao/identity.json``. The
shape is NTH-native (``kind: nth-dao-identity-card-v1`` + flat ``sig``
field). The A2A Protocol — adopted by 50+ enterprise partners
including Atlassian, Cohere, PayPal, Salesforce, SAP — has a different
canonical shape published at ``/.well-known/agent.json`` and signed
with JWS-style ``signatures[]`` envelopes per RFC 7515.

This module emits an A2A-compatible AgentCard derived from the SAME
identity material so:

  * NTH peers continue to use the native card (no churn for the
    in-house ecosystem)
  * A2A consumers (LangChain / Cohere / Salesforce / …) can fetch
    ``/.well-known/agent.json`` and treat the NTH node as a regular
    A2A participant
  * Both documents reference the same Ed25519 keypair, so a consumer
    that learned the pubkey from one channel can verify the other

The A2A AgentCard schema is the canonical Protocol Buffer definition
at ``a2aproject/A2A`` ``specification/a2a.proto`` (commit at fetch
time on 2026-06-08). Quoted required fields:

  string name                          [REQUIRED]
  string description                   [REQUIRED]
  repeated AgentInterface supportedInterfaces [REQUIRED]
  string version                       [REQUIRED]
  AgentCapabilities capabilities       [REQUIRED]
  repeated string default_input_modes  [REQUIRED]
  repeated string default_output_modes [REQUIRED]
  repeated AgentSkill skills           [REQUIRED]
  AgentProvider provider               [optional]
  optional string documentation_url
  map<string, SecurityScheme> security_schemes
  repeated SecurityRequirement security_requirements
  repeated AgentCardSignature signatures
  optional string icon_url

Signature envelope (AgentCardSignature):

  string protected   [REQUIRED]  — base64url(JWS protected header JSON)
  string signature   [REQUIRED]  — base64url(Ed25519_sign over input)
  google.protobuf.Struct header   [optional]  — unprotected header

Signing input (RFC 7515 JWS Compact serialization without payload —
"detached payload" mode):

  signing_input = base64url(protected_header_json) + "." +
                  base64url(canonical_json(card_without_signatures))

We choose detached-payload mode rather than embedding the payload
inside the JWS string because the card document IS the payload — the
verifier already has it.

Algorithm: ``EdDSA`` per RFC 8037. ``kid`` carries the did:key of the
signing keypair so a consumer with the DID can derive the pubkey
locally and verify without an external resolver.

Forward compatibility:
  * ``skills`` currently surface the local home channel ID as a
    placeholder skill — future revisions should enumerate group
    capabilities and registered tool surfaces.
  * ``capabilities.streaming = false`` until we wire SSE.
  * ``security_schemes`` only declares the console Bearer scheme for
    privileged calls; the public card itself is unauthenticated by
    contract.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.identity import _NACL_AVAILABLE

# B2 (review fix, 2026-06-08): hoist VerifyKey out of the verify
# function body. ``_VerifyKey is None`` is the single sentinel for
# "we cannot verify in this process" — covers both PyNaCl missing
# entirely and PyNaCl present but broken at runtime. The previous
# pattern (``_NACL_AVAILABLE`` early-return AND a try/except inside
# the function) had dead-code redundancy (B2) and an inline import
# (same family as B1/A3/A4).
try:
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:
    _VerifyKey = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from nth_dao.identity import AgentIdentity

logger = logging.getLogger("nth_dao.a2a_card")


# ─── version pins ──────────────────────────────────────────────────────

# MI-2 (review fix 2026-06-08): resolve at runtime from package
# metadata so a release-engineer who bumps ``nth_dao/pyproject.toml``
# can't accidentally leave this string stale. Falls back to a
# documented placeholder when the package isn't installed (typically
# editable-source dev environments where importlib.metadata may not
# resolve a dist-info), so dev runs still produce a parseable card.
try:
    from importlib.metadata import (
        PackageNotFoundError as _PkgNotFound,
        version as _pkg_version,
    )
    try:
        NTH_A2A_EMISSION_VERSION = _pkg_version("nth-dao")
    except _PkgNotFound:
        NTH_A2A_EMISSION_VERSION = "0.0.0-dev"
except ImportError:  # pragma: no cover — Python ≥3.8 always has it
    NTH_A2A_EMISSION_VERSION = "0.0.0-dev"

# RFC 8037 algorithm identifier for Ed25519 in JWS.
JWS_ALG_EDDSA = "EdDSA"

# A2A v1.0.1 HTTP binding identifiers. The official AgentInterface
# protocol_binding values are open strings; the core set includes
# JSONRPC, GRPC and HTTP+JSON. NTH DAO now advertises HTTP+JSON first
# and keeps the legacy JSONRPC endpoint as a secondary interface.
A2A_SPEC_VERSION = "1.0.1"
A2A_INTERFACE_PROTOCOL_VERSION = "1.0.1"
A2A_HTTP_JSON_BINDING = "HTTP+JSON"
A2A_JSONRPC_BINDING = "JSONRPC"

# Backward-compatible export names used by older tests/importers.
NTH_PROTOCOL_BINDING = A2A_HTTP_JSON_BINDING
NTH_PROTOCOL_VERSION_TAG = A2A_INTERFACE_PROTOCOL_VERSION


# ─── base64url helpers: CR-1 fix (2026-06-08) ─────────────────────────
# Shared codec lives in ``nth_dao.b64u`` to prevent the per-module
# drift that motivated this refactor.

_b64u = b64u_encode


def _b64u_json(obj: Dict[str, Any]) -> str:
    """Canonical-JSON-encode and base64url an object.

    Canonical form (sorted keys, no whitespace, UTF-8) ensures the
    same logical object always produces the same b64 string — required
    for any verifier to reconstruct the signing input without our
    Python implementation in the loop.
    """
    return _b64u(canonical_json(obj))


# ─── skill enumeration (B7, 2026-06-08) ──────────────────────────────


def _build_skill(
    *,
    id: str,
    name: str,
    description: str,
    tags: list,
    examples: list = None,
) -> Dict[str, Any]:
    """Build one A2A AgentSkill dict.

    Schema (a2a.proto AgentSkill):
        REQUIRED: id, name, description, tags
        optional: examples, input_modes, output_modes,
                  security_requirements
    """
    skill: Dict[str, Any] = {
        "id": id,
        "name": name,
        "description": description,
        "tags": list(tags),
    }
    if examples:
        skill["examples"] = list(examples)
    return skill


# Skill IDs are stable across releases — external A2A consumers may
# pin against them. Treat changes here as a wire-format break.
SKILL_ID_CHAT = "nth-dao.chat"
SKILL_ID_DAO_MANAGEMENT = "nth-dao.dao-management"
SKILL_ID_TASKS = "nth-dao.tasks"
SKILL_ID_MANDATE = "nth-dao.mandate"
SKILL_ID_AGENT_DISCOVERY = "nth-dao.agent-discovery"
SKILL_ID_A2A_PROTOCOL = "nth-dao.a2a-protocol"
SKILL_ID_GOVERNANCE = "nth-dao.governance"


def known_skills(state: Any, *, base_url: str = "") -> list:
    """Enumerate the A2A skills this NTH DAO node actually offers.

    B7 (2026-06-08, review fix): replaces the prior placeholder
    ``nth-dao.chat``-only list. An A2A consumer reading the card now
    sees the real surface — DAO management, mandate verification,
    governance voting, agent discovery, and the A2A protocol entry
    itself — instead of treating the node as just a chat bot.

    The enumeration is GUARDED by ``hasattr`` checks against
    ``state``: if a subsystem isn't loaded (e.g. a future refactor
    optionally disables mandates), its skill is silently omitted.
    This keeps the card honest — never advertise a capability the
    HTTP layer can't actually serve.

    Args:
        state: the ``WebState`` (or anything with the same attribute
            shape) used to gate skills.
        base_url: optional root URL prefix. When supplied, each
            skill's ``examples`` entries are made absolute so an A2A
            consumer can build a real test call without joining
            paths themselves.

    Returns:
        A list of AgentSkill dicts, never empty (the chat skill is
        the unconditional fallback so the A2A REQUIRED ``skills``
        array is always populated).
    """

    def _ex(path: str) -> str:
        """Format an example endpoint URL — absolute if base_url is
        supplied, otherwise a bare path."""
        if base_url:
            return f"POST {base_url}{path}"
        return f"POST {path}"

    skills: list = []

    # ── nth-dao.chat ── always available (fallback + core surface)
    skills.append(_build_skill(
        id=SKILL_ID_CHAT,
        name="Chat — post messages to a channel",
        description=(
            "Send a chat message to the node's home channel or to a "
            "DAO channel. Each accepted message is persisted and "
            "(when crypto is available) a signed execution receipt "
            "is emitted to the team_receipts/ store."
        ),
        tags=["nth-dao", "chat", "messaging"],
        examples=[
            _ex("/api/messages"),
            _ex("/api/daos/{slug}/messages"),
        ],
    ))

    # ── nth-dao.dao-management ── DAOs + groups + channels
    if hasattr(state, "group_registry") and hasattr(state, "groups"):
        skills.append(_build_skill(
            id=SKILL_ID_DAO_MANAGEMENT,
            name="DAO management",
            description=(
                "Create DAOs, publish signed group registry records, "
                "list and search the cross-workspace-unique DAO "
                "registry, and provision channels inside a DAO."
            ),
            tags=["nth-dao", "dao", "groups", "registry"],
            examples=[
                _ex("/api/groups/registry"),
                _ex("/api/groups/registry/search"),
                _ex("/api/daos/{slug}/channels"),
            ],
        ))

    # ── nth-dao.tasks ── work item lifecycle
    skills.append(_build_skill(
        id=SKILL_ID_TASKS,
        name="Task tracker",
        description=(
            "Create and patch work-item tasks at the home-DAO level. "
            "Distinct from A2A tasks (which use /api/a2a/rpc); these "
            "are NTH-native task records inside a DAO's blackboard."
        ),
        tags=["nth-dao", "tasks", "tracker"],
        examples=[
            _ex("/api/tasks"),
            f"PATCH {base_url}/api/tasks/{{task_id}}" if base_url
            else "PATCH /api/tasks/{task_id}",
        ],
    ))

    # ── nth-dao.mandate ── mandate triad pipeline
    if hasattr(state, "mandates"):
        skills.append(_build_skill(
            id=SKILL_ID_MANDATE,
            name="Mandate triad (intent / cart / payment)",
            description=(
                "Store and verify signed mandate records — intent, "
                "cart, payment — with cryptographic chain integrity. "
                "An A2A consumer can submit a mandate for verification "
                "and receive a signed verdict."
            ),
            tags=["nth-dao", "mandate", "verification"],
            examples=[
                _ex("/api/mandates/store"),
                _ex("/api/mandates/verify"),
            ],
        ))

    # ── nth-dao.agent-discovery ── search / add / by_code
    if hasattr(state, "peer_finder") and hasattr(state, "contacts"):
        skills.append(_build_skill(
            id=SKILL_ID_AGENT_DISCOVERY,
            name="Agent discovery",
            description=(
                "Fuzzy search across LAN-discovered peers and the "
                "local ContactBook, reverse lookup by visible "
                "8-hex code, and add a remote agent by DID."
            ),
            tags=["nth-dao", "discovery", "peers", "did"],
            examples=[
                f"GET {base_url}/api/agents/search?q={{query}}"
                if base_url
                else "GET /api/agents/search?q={query}",
                f"GET {base_url}/api/agents/by_code/{{code}}"
                if base_url
                else "GET /api/agents/by_code/{code}",
                _ex("/api/agents/add"),
            ],
        ))

    # ── nth-dao.governance ── proposals + voting
    if hasattr(state, "group_registry"):
        skills.append(_build_skill(
            id=SKILL_ID_GOVERNANCE,
            name="Governance — proposals and voting",
            description=(
                "Create policy-change proposals on a DAO and cast "
                "signed votes. Returns proposal resolution status "
                "via the registry."
            ),
            tags=["nth-dao", "governance", "voting", "proposals"],
            examples=[
                _ex(
                    "/api/groups/registry/{group_id}/proposals"
                ),
                _ex(
                    "/api/groups/registry/{group_id}/proposals/"
                    "{proposal_id}/vote"
                ),
            ],
        ))

    # ── nth-dao.a2a-protocol ── the A2A v1.0.1 entry points.
    # Recursive (the A2A card describing the A2A endpoint) but
    # accurate: explicitly listing it lets a consumer pre-flight
    # message:send / tasks.get without having to infer them from
    # supportedInterfaces.
    skills.append(_build_skill(
        id=SKILL_ID_A2A_PROTOCOL,
        name="A2A Protocol — HTTP+JSON and legacy JSON-RPC",
        description=(
            "A2A v1.0.1 HTTP+JSON endpoints accepting /message:send, "
            "GET /tasks/{id}, GET /tasks and /tasks/{id}:cancel. "
            "The legacy /api/a2a/rpc JSON-RPC endpoint remains available "
            "for older clients. Every accepted message emits a signed "
            "motebit-compatible execution receipt for verifiable work proof."
        ),
        tags=["nth-dao", "a2a", "http-json", "json-rpc", "tasks"],
        examples=[
            _ex("/message:send"),
            f"GET {base_url}/tasks/{{id}}" if base_url else "GET /tasks/{id}",
            _ex("/tasks/{id}:cancel"),
            _ex("/api/a2a/rpc"),
        ],
    ))
    return skills


# ─── card construction ───────────────────────────────────────────────


def build_a2a_card(
    *,
    agent_id: str,
    did: str,
    pubkey_hex: str,
    base_url: str,
    description: str = "",
    home_channel_id: str = "",
    skills: Optional[list] = None,
) -> Dict[str, Any]:
    """Build an UNSIGNED A2A AgentCard for this NTH DAO node.

    Args:
        agent_id: the human-readable ``agent_id`` we surface in our
            own UI (``admin`` by default for the bootstrap node).
        did: ``did:key:z…`` form of the Ed25519 pubkey. Carried in
            ``provider.organization`` (so a tool that only reads
            provider info still recovers the DID) and used as ``kid``
            in the JWS signature header.
        pubkey_hex: 64-hex Ed25519 pubkey. Surfaced under
            ``provider.url`` query so a consumer can cross-check.
        base_url: the public-facing root URL of this node — used to
            build the ``supportedInterfaces[].url``. Caller should
            pass the request base (``str(request.base_url)`` minus
            trailing slash).
        description: optional human description.
        home_channel_id: the default channel id the node uses; we
            advertise it as a placeholder skill until the skill
            registry grows real entries.

    Returns:
        A dict whose shape matches the A2A AgentCard schema, EXCLUDING
        the ``signatures`` field. The caller adds signatures after
        signing.
    """
    if not did:
        # An unsigned card without a stable identifier is worse than
        # no card — it would fingerprint the node as "A2A but broken".
        # The endpoint should have 503-ed before getting here; this
        # is a defensive assertion.
        raise ValueError("build_a2a_card requires a non-empty DID")

    base_url = base_url.rstrip("/")
    card: Dict[str, Any] = {
        # A2A v1.0.1 required fields. JSON uses protobuf JSON lowerCamelCase
        # names, not the snake_case identifiers from a2a.proto.
        "name": agent_id,
        "description": (
            description
            or f"NTH DAO node (agent_id={agent_id})"
        ),
        "supportedInterfaces": [
            {
                "url": base_url,
                "protocolBinding": A2A_HTTP_JSON_BINDING,
                "protocolVersion": A2A_INTERFACE_PROTOCOL_VERSION,
            },
            {
                "url": f"{base_url}/api/a2a/rpc",
                "protocolBinding": A2A_JSONRPC_BINDING,
                "protocolVersion": A2A_INTERFACE_PROTOCOL_VERSION,
            },
        ],
        "version": NTH_A2A_EMISSION_VERSION,
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "extensions": [],
            "extendedAgentCard": False,
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        # B7 (2026-06-08): when ``skills`` is supplied (by the
        # endpoint, via ``known_skills(state)``), advertise the real
        # surface. When omitted (pure-function tests or callers that
        # don't have a state handle), fall back to the single chat
        # placeholder so the A2A REQUIRED array is non-empty.
        "skills": list(skills) if skills else [
            _build_skill(
                id=SKILL_ID_CHAT,
                name="Chat — post messages to a channel",
                description=(
                    "Send a message to the node's home channel "
                    "via /api/messages."
                ),
                tags=["nth-dao", "chat"],
            )
        ],
        # A2A optional fields ─────────────────────────────────────
        "provider": {
            "url": base_url,
            # We tunnel DID + pubkey through ``organization`` so a
            # consumer that only reads ``provider`` still recovers
            # the identity. The ``signatures[].header.kid`` carries
            # the authoritative DID for verification.
            "organization": (
                f"nth-dao://{did} (pubkey={pubkey_hex[:16]}…)"
            ),
        },
    }
    # B7 (2026-06-08): when ``skills`` is supplied by the endpoint
    # (via ``known_skills(state)``), each skill already carries its
    # own ``examples``. The legacy ``home_channel_id`` enrichment is
    # now a no-op except in the fallback chat-only branch — and even
    # there it's optional. Kept as a positional knob for callers
    # that haven't moved to the state-based skills enumeration.
    if home_channel_id and skills is None:
        # We're on the placeholder branch — inject the home channel
        # into the single chat skill's examples so a consumer who
        # falls back to this card can still address the right channel.
        card["skills"][0]["examples"] = [
            f'POST /api/messages {{"channel_id":"{home_channel_id}"}}'
        ]

    return card


# ─── JWS-EdDSA detached-payload signature ─────────────────────────────


def sign_a2a_card_jws(
    card_unsigned: Dict[str, Any],
    identity: "AgentIdentity",
    did: str,
) -> Dict[str, Any]:
    """Produce a single ``AgentCardSignature`` envelope for the card.

    Construction (per RFC 7515 with detached payload):

        protected_header = {"alg": "EdDSA", "kid": "<did>"}
        protected_b64 = base64url(canonical_json(protected_header))
        payload_b64 = base64url(canonical_json(card_unsigned))
        signing_input = (protected_b64 + "." + payload_b64).encode()
        signature = Ed25519_sign(signing_input)
        sig_b64 = base64url(signature)

    The returned object is the JSON shape of A2A's
    ``AgentCardSignature``: ``protected``, ``signature``, ``header``.
    ``header`` is the optional unprotected header — we mirror the
    ``kid`` there for consumers that only read unprotected headers
    (per JOSE conventions, ``kid`` is non-confidential so duplicating
    it is fine).

    Verification (any consumer):

        1. Parse base64url(protected) → JSON. Confirm ``alg=EdDSA``.
        2. Resolve kid → Ed25519 pubkey (e.g. decode did:key).
        3. Rebuild payload_b64 from the card excluding ``signatures``.
        4. signing_input = protected + "." + payload_b64.
        5. Ed25519_verify(signing_input, base64url_decode(signature),
                          pubkey).

    Raises:
        RuntimeError if the identity cannot sign (PyNaCl missing,
        keypair never generated, etc.) — propagated so the endpoint
        can fail-closed with 503 rather than emit an unverifiable
        signature.
    """
    protected_header = {"alg": JWS_ALG_EDDSA, "kid": did}
    protected_b64 = _b64u_json(protected_header)
    payload_b64 = _b64u(canonical_json(card_unsigned))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    sig_bytes = identity.sign(signing_input)
    sig_b64 = _b64u(sig_bytes)

    return {
        "protected": protected_b64,
        "signature": sig_b64,
        # Optional unprotected header. Per JWS, fields here are NOT
        # covered by the signature — only fields in ``protected`` are.
        # ``kid`` here is a convenience for consumers; the authoritative
        # ``kid`` is inside ``protected``.
        "header": {"kid": did},
    }


def verify_a2a_card_jws(
    card: Dict[str, Any],
    *,
    expected_pubkey_hex: str = "",
) -> bool:
    """Verify the first signature on an A2A AgentCard.

    Args:
        card: the full card dict (with ``signatures[]`` populated).
        expected_pubkey_hex: optional 64-hex pubkey to bind against.
            If supplied, we ALSO check that the recovered pubkey
            matches — useful when the caller already knows the DID
            and wants belt-and-braces.

    Returns:
        True iff at least one signature in ``signatures[]`` verifies
        against an Ed25519 pubkey derivable from its ``kid``. We
        intentionally only require *one* good signature so an old
        card with multiple historical signatures still verifies as
        long as one current pubkey holds.
    """
    # B2 (review fix 2026-06-08): single sentinel for "cannot verify".
    # _VerifyKey is None iff PyNaCl is not importable. _NACL_AVAILABLE
    # would be redundant — kept as a defence in case identity.py
    # somehow toggles the flag at runtime (it doesn't, but the cost
    # is one boolean check).
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False

    sigs = card.get("signatures") or []
    if not isinstance(sigs, list) or not sigs:
        return False

    card_unsigned = {k: v for k, v in card.items() if k != "signatures"}
    payload_b64 = _b64u(canonical_json(card_unsigned))

    for env in sigs:
        if not isinstance(env, dict):
            continue
        protected_b64 = env.get("protected", "")
        sig_b64 = env.get("signature", "")
        if not protected_b64 or not sig_b64:
            continue

        # Decode protected to recover alg + kid.
        # B1 (review fix): json is imported at module top, not inline.
        # CR-1 (review fix): use shared b64u_decode rather than
        # inline padding-restore + urlsafe_b64decode.
        try:
            protected_raw = b64u_decode(protected_b64)
            protected_header = json.loads(protected_raw)
        except Exception:  # noqa: BLE001
            continue

        if protected_header.get("alg") != JWS_ALG_EDDSA:
            continue
        kid = str(protected_header.get("kid", ""))
        if not kid:
            continue

        # Resolve kid → pubkey. We support did:key today; future
        # revisions can plug in additional resolvers.
        pubkey_hex = ""
        if is_did_key(kid):
            try:
                pubkey_hex = decode_ed25519_did_key_hex(kid) or ""
            except Exception:  # noqa: BLE001
                continue
        if not pubkey_hex:
            continue
        if (
            expected_pubkey_hex
            and pubkey_hex.lower() != expected_pubkey_hex.lower()
        ):
            continue

        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        try:
            # CR-1: shared b64u_decode handles padding restore
            sig_bytes = b64u_decode(sig_b64)
        except Exception:  # noqa: BLE001
            continue

        try:
            # B2: _VerifyKey is the module-top alias bound at import
            # time; the early return above guarantees it's not None.
            _VerifyKey(bytes.fromhex(pubkey_hex)).verify(
                signing_input, sig_bytes,
            )
            return True
        except Exception:  # noqa: BLE001
            continue

    return False
