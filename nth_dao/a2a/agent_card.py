"""A2A Agent Card generator (v0.10 T-7).

Produces the JSON manifest an A2A consumer expects at the well-known
URL ``/.well-known/agent.json``. Other A2A agents fetch this URL to
discover what we can do.

The v0.9.5 ``translate.agent_card_from`` shapes the card from
MissionTemplates (rich, NTH-DAO-aware). This v0.10 module is the
simpler, capabilities-list-shaped builder a generic deployment uses
when it just wants to expose its raw NTH DAO capability strings as
A2A skills. Both coexist - same package, different starting points.

Shape (A2A v1.0)::

    {
      "protocolVersion": "0.3.0",
      "name": "...",
      "description": "...",
      "url": "https://example.com/a2a",
      "version": "0.10.0",
      "preferredTransport": "JSONRPC",
      "capabilities": {
        "streaming": bool,
        "pushNotifications": bool,
        "stateTransitionHistory": bool
      },
      "defaultInputModes":  ["application/json"],
      "defaultOutputModes": ["application/json"],
      "skills": [
        {
          "id":          str,
          "name":        str,
          "description": str,
          "tags":        [str, ...],
          "inputModes":  [str, ...],
          "outputModes": [str, ...]
        }, ...
      ],
      "securitySchemes": {},
      "security": [],
      "provider": {                                # optional
        "organization": "...",
        "url": "..."
      }
    }

The card carries NO NTH DAO-specific identifiers in its main body so
an arbitrary A2A consumer can read it. NTH DAO-specific extras
(e.g. agent_did, registry_url) go under an ``x-nth-dao`` namespace
which A2A consumers will ignore per the standard convention for
unknown ``x-`` prefixed extension fields.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ..attach import TeamSession

logger = logging.getLogger("nth_dao.a2a.agent_card")


# The well-known path A2A consumers fetch. Stable across v0.10+; if the
# A2A spec changes this, bump the protocol version too.
A2A_WELL_KNOWN_PATH = "/.well-known/agent.json"

# A2A protocol version we currently target. Aligned with v0.9.5's
# translate.py so both card builders advertise the same wire format.
A2A_PROTOCOL_VERSION = "1.0.1"

# Skill ids must be URL-safe identifiers - other A2A agents may use them
# in JSON-RPC parameters or URL paths.
_SKILL_ID_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")

# V-35: URL validation cap. Anything past 2 KB is almost certainly a
# misuse (data: URL, CR/LF injection attempt, browser cache poison).
_URL_MAX_LEN = 2048

# V-45: cap on serialized size of a single skill object. A reasonable
# A2A skill (id, name, description, tags, IO modes, a couple of
# small x- extensions) fits comfortably under 4 KB. Larger entries
# are almost certainly an unbounded x- extension being abused.
_SKILL_MAX_SERIALIZED_BYTES = 4096


def _validate_endpoint_url(url: Any, field_label: str = "url") -> None:
    """Voss V-35: tightened URL validation.

    Previously ``url.startswith("http(s)://")`` accepted things like
    bare ``"http://"`` (no host), URLs with embedded CR/LF (header
    injection), and unbounded lengths (DoS). urlparse + length cap
    closes those gaps.
    """
    if not isinstance(url, str) or not url:
        raise ValueError(f"{field_label} must be a non-empty string")
    if len(url) > _URL_MAX_LEN:
        raise ValueError(
            f"{field_label} too long ({len(url)} > {_URL_MAX_LEN} chars)"
        )
    if "\n" in url or "\r" in url:
        raise ValueError(f"{field_label} must not contain CR/LF characters")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"{field_label} scheme must be http(s), got "
            f"{parsed.scheme!r} (input: {url!r})"
        )
    if not parsed.netloc:
        raise ValueError(f"{field_label} must have a host component, got {url!r}")


def build_agent_card(
    *,
    name: str,
    description: str,
    url: str,
    version: str = "0.10.0",
    capabilities: Optional[List[str]] = None,
    skills: Optional[List[Dict[str, Any]]] = None,
    streaming: bool = False,
    push_notifications: bool = False,
    state_transition_history: bool = True,
    default_input_modes: Optional[List[str]] = None,
    default_output_modes: Optional[List[str]] = None,
    provider_org: str = "",
    provider_url: str = "",
    security_schemes: Optional[Dict[str, Any]] = None,
    security: Optional[List[Dict[str, Any]]] = None,
    protocol_version: str = A2A_PROTOCOL_VERSION,
    preferred_transport: str = "HTTP+JSON",
    nth_dao_extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an A2A Agent Card JSON dict.

    Two ways to populate the skills array:

    1. Pass ``capabilities=["code_review", "deploy", ...]`` and let
       each string become a minimal Skill object with that string as
       both id and name. Good for quick advertising; the consumer
       can't tell rich shape from it.
    2. Pass ``skills=[{...full skill dicts...}]`` directly. Use this
       when you have descriptions / tags / IO modes per skill.

    The two are independent - you can pass both and we'll merge,
    skipping capability strings whose id already appears in skills.

    Raises
    ------
    ValueError
        For structural problems: missing required fields, bad URL,
        invalid skill id, etc. Catches the typo at build time, not at
        the consumer's HTTP error.
    """
    if not name or not isinstance(name, str):
        raise ValueError("name must be a non-empty string")
    if not isinstance(description, str):
        raise ValueError("description must be a string (can be empty)")
    _validate_endpoint_url(url, "url")    # V-35
    if provider_url:
        _validate_endpoint_url(provider_url, "provider_url")
    if not version or not isinstance(version, str):
        raise ValueError("version must be a non-empty string")

    merged_skills = _merge_skills(
        capability_list=capabilities or [],
        skill_dicts=skills or [],
    )

    card: Dict[str, Any] = {
        "name": name,
        "description": description,
        "supportedInterfaces": [
            {
                "url": url.rstrip("/"),
                "protocolBinding": preferred_transport,
                "protocolVersion": protocol_version,
            }
        ],
        "version": version,
        "capabilities": {
            "streaming": bool(streaming),
            "pushNotifications": bool(push_notifications),
            "extensions": [],
            "extendedAgentCard": False,
        },
        "defaultInputModes": list(default_input_modes or ["application/json"]),
        "defaultOutputModes": list(default_output_modes or ["application/json"]),
        "skills": merged_skills,
        "securitySchemes": dict(security_schemes or {}),
        "securityRequirements": list(security or []),
    }
    if provider_org or provider_url:
        card["provider"] = {}
        if provider_org:
            card["provider"]["organization"] = provider_org
        if provider_url:
            card["provider"]["url"] = provider_url

    if nth_dao_extras:
        # x- prefix is the standard A2A convention for vendor extensions.
        # Consumers that don't understand them must (per the spec) ignore
        # them rather than reject the whole card.
        # Voss V-37: deep copy so a caller mutating their source dict
        # AFTER build_agent_card returns can't smuggle changes into the
        # served card. The previous ``dict(...)`` was a shallow copy.
        card["x-nth-dao"] = copy.deepcopy(nth_dao_extras)

    return card


def _merge_skills(
    *,
    capability_list: List[str],
    skill_dicts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build the skills array.

    Detailed skill dicts win on id collision (no double advertising).
    Capability strings become minimal skill stubs. Validation happens
    per-skill so the failing entry's id is named in the error.
    """
    out: List[Dict[str, Any]] = []
    seen_ids: set = set()

    for raw in skill_dicts:
        skill = _validate_skill(raw)
        if skill["id"] in seen_ids:
            raise ValueError(f"duplicate skill id: {skill['id']!r}")
        seen_ids.add(skill["id"])
        out.append(skill)

    for cap in capability_list:
        if not isinstance(cap, str) or not cap:
            raise ValueError(f"capability must be a non-empty string, got {cap!r}")
        if not _SKILL_ID_RE.match(cap):
            raise ValueError(
                f"capability {cap!r} contains characters that are not URL-safe; "
                f"allowed: letters / digits / . _ -"
            )
        if cap in seen_ids:
            continue   # already advertised via detailed skill - skip the stub
        seen_ids.add(cap)
        out.append({
            "id": cap,
            "name": cap.replace("_", " ").replace("-", " ").title(),
            "description": "",
            "tags": [],
            "inputModes": ["application/json"],
            "outputModes": ["application/json"],
        })

    return out


def _validate_skill(raw: Any) -> Dict[str, Any]:
    """Per-skill structural check; returns a CLEAN copy.

    Required: id (URL-safe), name. Optional: description (str), tags
    (list of str), inputModes / outputModes (list of str).
    """
    if not isinstance(raw, dict):
        raise ValueError(f"skill must be a dict, got {type(raw).__name__}")
    skill_id = raw.get("id", "")
    if not isinstance(skill_id, str) or not skill_id:
        raise ValueError("skill.id must be a non-empty string")
    if not _SKILL_ID_RE.match(skill_id):
        raise ValueError(
            f"skill id {skill_id!r} contains characters that are not URL-safe; "
            f"allowed: letters / digits / . _ -"
        )
    name = raw.get("name", "")
    if not isinstance(name, str) or not name:
        raise ValueError(f"skill {skill_id!r}.name must be a non-empty string")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise ValueError(f"skill {skill_id!r}.description must be a string")
    tags = raw.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
        raise ValueError(f"skill {skill_id!r}.tags must be a list of strings")
    input_modes = raw.get("inputModes", ["application/json"])
    if not isinstance(input_modes, list) or not input_modes or any(
        not isinstance(m, str) for m in input_modes
    ):
        raise ValueError(
            f"skill {skill_id!r}.inputModes must be a non-empty list of strings"
        )
    output_modes = raw.get("outputModes", ["application/json"])
    if not isinstance(output_modes, list) or not output_modes or any(
        not isinstance(m, str) for m in output_modes
    ):
        raise ValueError(
            f"skill {skill_id!r}.outputModes must be a non-empty list of strings"
        )
    clean: Dict[str, Any] = {
        "id": skill_id,
        "name": name,
        "description": description,
        "tags": list(tags),
        "inputModes": list(input_modes),
        "outputModes": list(output_modes),
    }
    # Carry forward any extra x- prefixed keys (vendor extensions); reject
    # other unknown keys to catch typos.
    for k, v in raw.items():
        if k.startswith("x-"):
            clean[k] = v
        elif k not in ("id", "name", "description", "tags", "inputModes", "outputModes"):
            raise ValueError(
                f"skill {skill_id!r} has unknown field {k!r}; use 'x-{k}' for "
                f"vendor extensions"
            )

    # Voss V-45: cap the serialized size of the cleaned skill. An
    # attacker controlling a skill dict could otherwise smuggle in a
    # 100 MB x- extension value and bloat the well-known card. The
    # cap is enforced AFTER cleaning so we count only fields that
    # actually make it through.
    try:
        serialized_len = len(json.dumps(clean, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"skill {skill_id!r} contains non-JSON-serialisable values: {exc}"
        ) from exc
    if serialized_len > _SKILL_MAX_SERIALIZED_BYTES:
        raise ValueError(
            f"skill {skill_id!r} exceeds max serialized size "
            f"({serialized_len} > {_SKILL_MAX_SERIALIZED_BYTES} bytes); "
            f"trim x- extension values or split into multiple skills"
        )
    return clean


def build_agent_card_from_session(
    session: "TeamSession",
    *,
    url: str,
    name: Optional[str] = None,
    description: str = "",
    version: str = "0.10.0",
    extras: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build a card from an attached TeamSession.

    Pulls ``session.agent_id`` (as default name) and ``session.capabilities``
    automatically. Pass extra kwargs to override anything ``build_agent_card``
    accepts.
    """
    capabilities = list(getattr(session, "capabilities", None) or [])
    nth_dao_extras: Dict[str, Any] = {
        "agent_id": getattr(session, "agent_id", ""),
        "workspace": str(getattr(session, "workspace", "")),
        "groups": list(getattr(session, "groups", None) or []),
    }
    identity = getattr(session, "identity", None)
    if identity is not None and getattr(identity, "pubkey_hex", ""):
        try:
            nth_dao_extras["agent_did"] = identity.as_did()
        except Exception as exc:    # noqa: BLE001
            # Voss V-46: don't silently swallow. Without the agent_did
            # in the card, an A2A consumer can't cross-reference the
            # exposed identity with our DID ledger - that's a
            # diagnosable problem that deserves an audit log entry,
            # not silent degradation.
            logger.warning(
                "agent_did decode failed for session %r; card will be served "
                "without agent_did extra: %s",
                getattr(session, "agent_id", "?"), exc,
            )
    if extras:
        nth_dao_extras.update(extras)

    return build_agent_card(
        name=name or getattr(session, "agent_id", "") or "agent",
        description=description,
        url=url,
        version=version,
        capabilities=capabilities,
        nth_dao_extras=nth_dao_extras,
        **kwargs,
    )


# ===== validation =====


REQUIRED_TOP_LEVEL_FIELDS = (
    "name", "description", "supportedInterfaces", "version",
    "capabilities", "defaultInputModes", "defaultOutputModes", "skills",
)
REQUIRED_CAPABILITIES_FIELDS = (
    "streaming", "pushNotifications",
)
# Voss V-51: ingested card field types. The pre-fix validator only
# checked KEY presence; ``{"name": null, "url": "https://...", ...}``
# passed. Aligning with build_agent_card's type expectations.
_REQUIRED_STRING_FIELDS = ("name", "version")
_REQUIRED_STRING_FIELDS_ALLOW_EMPTY = ("description",)


def validate_agent_card(card: Any) -> Tuple[bool, str]:
    """Structural validation of a generated or externally-supplied card.

    Returns ``(ok, reason)``. Use this when ingesting a card from an
    untrusted source (another A2A agent's well-known URL) - structural
    rejection is cheaper than discovering the missing field at use time.
    """
    if not isinstance(card, dict):
        return False, f"card must be a dict, got {type(card).__name__}"

    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in card:
            return False, f"missing required field: {field!r}"

    # V-51: type-check the string fields, not just presence.
    for field in _REQUIRED_STRING_FIELDS:
        value = card[field]
        if not isinstance(value, str) or not value:
            return False, f"{field} must be a non-empty string, got {value!r}"
    for field in _REQUIRED_STRING_FIELDS_ALLOW_EMPTY:
        value = card[field]
        if not isinstance(value, str):
            return False, f"{field} must be a string, got {value!r}"

    ifaces = card.get("supportedInterfaces")
    if not isinstance(ifaces, list) or not ifaces:
        return False, "supportedInterfaces must be a non-empty list"
    for i, iface in enumerate(ifaces):
        if not isinstance(iface, dict):
            return False, f"supportedInterfaces[{i}] must be an object"
        try:
            _validate_endpoint_url(iface.get("url"), f"supportedInterfaces[{i}].url")
        except ValueError as exc:
            return False, str(exc)
        if not isinstance(iface.get("protocolBinding"), str) or not iface.get("protocolBinding"):
            return False, f"supportedInterfaces[{i}].protocolBinding must be a non-empty string"
        if not isinstance(iface.get("protocolVersion"), str) or not iface.get("protocolVersion"):
            return False, f"supportedInterfaces[{i}].protocolVersion must be a non-empty string"

    caps = card.get("capabilities")
    if not isinstance(caps, dict):
        return False, "capabilities must be a dict"
    for cf in REQUIRED_CAPABILITIES_FIELDS:
        if cf not in caps:
            return False, f"capabilities.{cf} missing"
        if not isinstance(caps[cf], bool):
            return False, f"capabilities.{cf} must be a bool"

    for mode_field in ("defaultInputModes", "defaultOutputModes"):
        v = card.get(mode_field)
        if not isinstance(v, list) or not v or any(not isinstance(m, str) for m in v):
            return False, f"{mode_field} must be a non-empty list of strings"

    skills = card.get("skills")
    if not isinstance(skills, list):
        return False, "skills must be a list"
    for i, skill in enumerate(skills):
        try:
            _validate_skill(skill)
        except ValueError as exc:
            return False, f"skills[{i}]: {exc}"

    return True, "ok"


# ===== file I/O =====


def write_agent_card(path: Path, card: Dict[str, Any]) -> None:
    """Write the card to ``path`` as pretty-printed JSON.

    Validates before writing - we never ship a malformed card to the
    well-known URL.

    Voss V-38: writes atomically via tmp-file + rename so a crashing
    process can't leave a truncated card at the well-known path. An
    A2A consumer fetching during the write window will see the OLD
    card (or 404 on first write) but never garbage.
    """
    ok, reason = validate_agent_card(card)
    if not ok:
        raise ValueError(f"refusing to write invalid card: {reason}")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(card, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(str(tmp), str(path))
