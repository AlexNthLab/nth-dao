"""MissionTemplate —reusable, signed task definitions ("App Store listings").

A MissionTemplate is to a Mission what a recipe is to a meal. The same
template can be instantiated many times, by different agents, on different
days; each instantiation produces a fresh Mission whose `template_lock`
field permanently records which template (and which version) it was made
from.

Design aligned with industry standards (see docs/PROTOCOLS.md 搂9):

    - cargo-crev "Proof" model:  signed by publisher, append-only, P2P
    - F-Droid metadata layout:   one file per template, derived index
    - TUF wire format (future):  monotonic version, delegations placeholder
    - Argo WorkflowTemplate:     template_type enum (5 kinds)
    - GitHub Actions action.yml: inputs/outputs schema field naming
    - Nix flake.lock:            template_lock for reproducible instances

Storage layout:
    missions/
    鈹溾攢鈹€ templates/
    鈹?  鈹溾攢鈹€ <template_id>-v<version>.json   # one file per (template, version)
    鈹?  鈹斺攢鈹€ ...
    鈹溾攢鈹€ _template_index.json                # derived index (F-Droid/TUF style)
    鈹斺攢鈹€ ...

Each template file is signed by its publisher; the index file is signed
by whoever rebuilt it (typically the same publisher, or a team admin).

We do not implement TUF's full 4-role (root/snapshot/targets/timestamp)
hierarchy in v0.9.3 —that's a later step. But we name fields so that a
future TUF adapter is a 50-LOC translation, not a rewrite.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..identity import AgentIdentity, _NACL_AVAILABLE, _VerifyKey, canonical_json
from ..util import InterProcessLock, atomic_write_json, safe_load_json, safe_id

logger = logging.getLogger("nth_dao.orchestration.template")


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ template type taxonomy 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


class TemplateType(str, Enum):
    """5 kinds of mission templates (analogous to Argo's container/script/dag/steps/suspend).

    - AGENT_TASK:     single step, one agent does it end-to-end
    - AGENT_CHAIN:    multiple steps in strict order (no branching)
    - AGENT_DAG:      multiple steps with depends_on graph (parallel-capable)
    - AGENT_REVIEW:   one agent produces output, a second agent reviews it
    - HUMAN_IN_LOOP:  at least one step waits for a human approver
    """

    AGENT_TASK = "agent_task"
    AGENT_CHAIN = "agent_chain"
    AGENT_DAG = "agent_dag"
    AGENT_REVIEW = "agent_review"
    HUMAN_IN_LOOP = "human_in_loop"


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ input/output schema (GitHub Actions style) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@dataclass
class IOField:
    """One input or output field declaration.

    Field naming intentionally aligned with GitHub Actions' action.yml so a
    future adapter is trivial. JSON-Schema is the long-term target but we
    keep a simple subset here.
    """

    description: str = ""
    type: str = "string"     # "string" | "int" | "float" | "bool" | "enum" | "json"
    required: bool = False
    default: Any = ""
    values: List[str] = field(default_factory=list)  # for type="enum"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "IOField":
        return cls(
            description=data.get("description", ""),
            type=data.get("type", "string"),
            required=bool(data.get("required", False)),
            default=data.get("default", ""),
            values=list(data.get("values", [])),
        )

    def validate_value(self, value: Any) -> Optional[str]:
        """Return None if value is acceptable, else an error string."""
        known_types = {"string", "int", "float", "bool", "enum", "json"}
        if self.type not in known_types:
            return f"unknown field type {self.type!r}"
        if value is None or value == "":
            if self.required and not self.default:
                return "required but not provided"
            return None
        if self.type == "string" and not isinstance(value, str):
            return f"expected string, got {type(value).__name__}"
        if self.type == "bool" and not isinstance(value, bool):
            return f"expected bool, got {type(value).__name__}"
        if self.type == "int" and (not isinstance(value, int) or isinstance(value, bool)):
            return f"expected int, got {type(value).__name__}"
        if self.type == "float" and (
            not isinstance(value, (int, float)) or isinstance(value, bool)
        ):
            return f"expected float, got {type(value).__name__}"
        if self.type == "enum" and value not in self.values:
            return f"value {value!r} not in {self.values}"
        return None


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ step skeleton 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@dataclass
class StepSkeleton:
    """A step in the template; instantiated into a real MissionStep when used."""

    id: str
    description: str
    required_capabilities: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    inputs_from: Dict[str, str] = field(default_factory=dict)  # step input -> template input or prior step output

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "StepSkeleton":
        return cls(
            id=data.get("id", ""),
            description=data.get("description", ""),
            required_capabilities=list(data.get("required_capabilities", [])),
            depends_on=list(data.get("depends_on", [])),
            inputs_from=dict(data.get("inputs_from", {})),
        )


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ MissionTemplate 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def _valid_semver(version: str) -> bool:
    return bool(_SEMVER_RE.match(version))


def _semver_key(version: str):
    match = _SEMVER_RE.match(version)
    if not match:
        return (0, 0, 0, -1, (), "")
    major, minor, patch, prerelease, _build = match.groups()
    release = (int(major), int(minor), int(patch))
    if prerelease is None:
        prerelease_rank = (1,)
    else:
        parts = []
        for part in prerelease.split("."):
            if part.isdigit():
                parts.append((0, int(part)))
            else:
                parts.append((1, part))
        prerelease_rank = (0, tuple(parts))
    return (*release, *prerelease_rank)


@dataclass
class MissionTemplate:
    """A signed, reusable task definition.

    Immutable after publication (well —re-publishing same id+version errors).
    Mutable counterparts (rating, install_count) live in separate review files
    so the publisher's signature stays valid.
    """

    # 鈹€鈹€ identity (immutable) 鈹€鈹€
    template_id: str                  # short id, e.g. "code-review"
    version: str                      # semver, e.g. "1.0.0"
    publisher_pubkey: str             # Ed25519 hex; "" when unsigned (legacy)
    publisher_did: str = ""           # did:key:z6Mk... (future-compatible)

    # 鈹€鈹€ content (immutable) 鈹€鈹€
    name: str = ""
    description: str = ""
    template_type: TemplateType = TemplateType.AGENT_TASK
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    inputs: Dict[str, IOField] = field(default_factory=dict)   # name 鈫?IOField
    outputs: Dict[str, IOField] = field(default_factory=dict)
    steps: List[StepSkeleton] = field(default_factory=list)
    suggested_reward: float = 0.0
    suggested_deadline_hours: float = 0.0

    # 鈹€鈹€ lifecycle (immutable) 鈹€鈹€
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    deprecated: bool = False
    deprecated_reason: str = ""
    supersedes: List[str] = field(default_factory=list)   # previous template versions this replaces

    # 鈹€鈹€ future-compatibility (reserved, not used in v0.9.3) 鈹€鈹€
    delegations: List[Dict[str, Any]] = field(default_factory=list)  # TUF-style delegation slots
    credentials_required: List[str] = field(default_factory=list)    # W3C VC types
    legal_jurisdiction: str = ""

    # 鈹€鈹€ signature (over signable_dict) 鈹€鈹€
    publisher_sig: str = ""

    # 鈹€鈹€ runtime helpers 鈹€鈹€

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "version": self.version,
            "publisher_pubkey": self.publisher_pubkey,
            "publisher_did": self.publisher_did,
            "name": self.name,
            "description": self.description,
            "template_type": self.template_type.value if isinstance(self.template_type, TemplateType) else self.template_type,
            "category": self.category,
            "tags": list(self.tags),
            "required_capabilities": list(self.required_capabilities),
            "inputs": {k: v.to_dict() for k, v in self.inputs.items()},
            "outputs": {k: v.to_dict() for k, v in self.outputs.items()},
            "steps": [s.to_dict() for s in self.steps],
            "suggested_reward": float(self.suggested_reward),
            "suggested_deadline_hours": float(self.suggested_deadline_hours),
            "created_at": self.created_at,
            "deprecated": bool(self.deprecated),
            "deprecated_reason": self.deprecated_reason,
            "supersedes": list(self.supersedes),
            "delegations": list(self.delegations),
            "credentials_required": list(self.credentials_required),
            "legal_jurisdiction": self.legal_jurisdiction,
            "publisher_sig": self.publisher_sig,
        }

    def signable_dict(self) -> dict:
        """The dict that gets signed —everything except publisher_sig itself."""
        d = self.to_dict()
        d.pop("publisher_sig", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "MissionTemplate":
        ttype_raw = data.get("template_type", TemplateType.AGENT_TASK.value)
        try:
            ttype = TemplateType(ttype_raw)
        except ValueError:
            ttype = TemplateType.AGENT_TASK
        return cls(
            template_id=data.get("template_id", ""),
            version=data.get("version", "0.0.0"),
            publisher_pubkey=data.get("publisher_pubkey", ""),
            publisher_did=data.get("publisher_did", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            template_type=ttype,
            category=data.get("category", "general"),
            tags=list(data.get("tags", [])),
            required_capabilities=list(data.get("required_capabilities", [])),
            inputs={k: IOField.from_dict(v) for k, v in (data.get("inputs") or {}).items()},
            outputs={k: IOField.from_dict(v) for k, v in (data.get("outputs") or {}).items()},
            steps=[StepSkeleton.from_dict(s) for s in (data.get("steps") or [])],
            suggested_reward=float(data.get("suggested_reward", 0)),
            suggested_deadline_hours=float(data.get("suggested_deadline_hours", 0)),
            created_at=data.get("created_at", datetime.now().isoformat()),
            deprecated=bool(data.get("deprecated", False)),
            deprecated_reason=data.get("deprecated_reason", ""),
            supersedes=list(data.get("supersedes", [])),
            delegations=list(data.get("delegations", [])),
            credentials_required=list(data.get("credentials_required", [])),
            legal_jurisdiction=data.get("legal_jurisdiction", ""),
            publisher_sig=data.get("publisher_sig", ""),
        )

    @property
    def file_stem(self) -> str:
        """File-name stem used on disk: <safe_id>-v<version>."""
        return f"{safe_id(self.template_id)}-v{safe_id(self.version)}"

    def verify_signature(self) -> bool:
        """Verify publisher_sig under publisher_pubkey. False on any failure."""
        if not (_NACL_AVAILABLE and _VerifyKey
                and self.publisher_sig and self.publisher_pubkey):
            return False
        try:
            _VerifyKey(bytes.fromhex(self.publisher_pubkey)).verify(
                canonical_json(self.signable_dict()),
                bytes.fromhex(self.publisher_sig),
            )
            return True
        except Exception:
            return False

    def validate_inputs(self, provided: Dict[str, Any]) -> Optional[str]:
        """Validate a dict of provided inputs against this template's schema.

        Returns None if all checks pass, else a short error string identifying
        the first failing field.
        """
        for name, field_def in self.inputs.items():
            err = field_def.validate_value(provided.get(name))
            if err:
                return f"input {name!r}: {err}"
        # Unknown extra inputs are allowed (forward compatibility)
        return None


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ mint / publish helpers 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def mint_template(
    publisher: AgentIdentity,
    *,
    template_id: str,
    version: str,
    name: str,
    description: str = "",
    template_type: Union[TemplateType, str] = TemplateType.AGENT_TASK,
    category: str = "general",
    tags: Optional[List[str]] = None,
    required_capabilities: Optional[List[str]] = None,
    inputs: Optional[Dict[str, Union[IOField, dict]]] = None,
    outputs: Optional[Dict[str, Union[IOField, dict]]] = None,
    steps: Optional[List[Union[StepSkeleton, dict]]] = None,
    suggested_reward: float = 0.0,
    suggested_deadline_hours: float = 0.0,
    supersedes: Optional[List[str]] = None,
    credentials_required: Optional[List[str]] = None,
) -> MissionTemplate:
    """Create + sign a new MissionTemplate.

    Raises:
        ValueError: invalid semver, empty template_id, or non-crypto identity.
    """
    if not publisher.can_sign:
        raise ValueError("mint_template requires a signing-capable identity")
    if not template_id:
        raise ValueError("template_id must not be empty")
    if not _valid_semver(version):
        raise ValueError(f"version {version!r} is not valid semver")
    if isinstance(template_type, str):
        template_type = TemplateType(template_type)

    def _normalize_io(d: Optional[Dict[str, Union[IOField, dict]]]) -> Dict[str, IOField]:
        if not d:
            return {}
        out: Dict[str, IOField] = {}
        for k, v in d.items():
            if isinstance(v, IOField):
                out[k] = v
            elif isinstance(v, dict):
                out[k] = IOField.from_dict(v)
            else:
                raise TypeError(f"input/output {k!r} must be IOField or dict")
        return out

    def _normalize_steps(s: Optional[List[Union[StepSkeleton, dict]]]) -> List[StepSkeleton]:
        if not s:
            return []
        out: List[StepSkeleton] = []
        for item in s:
            if isinstance(item, StepSkeleton):
                out.append(item)
            elif isinstance(item, dict):
                out.append(StepSkeleton.from_dict(item))
            else:
                raise TypeError("step must be StepSkeleton or dict")
        return out

    # v0.9.5: emit a full W3C did:key (was a simplified placeholder in v0.9.3-0.9.4)
    template = MissionTemplate(
        template_id=template_id,
        version=version,
        publisher_pubkey=publisher.pubkey_hex,
        publisher_did=publisher.as_did(),  # W3C did:key:z<base58btc(0xed01||pubkey)>
        name=name,
        description=description,
        template_type=template_type,
        category=category,
        tags=list(tags or []),
        required_capabilities=list(required_capabilities or []),
        inputs=_normalize_io(inputs),
        outputs=_normalize_io(outputs),
        steps=_normalize_steps(steps),
        suggested_reward=float(suggested_reward),
        suggested_deadline_hours=float(suggested_deadline_hours),
        supersedes=list(supersedes or []),
        credentials_required=list(credentials_required or []),
    )
    template.publisher_sig = publisher.sign_json(template.signable_dict())
    return template


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ persistence 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


class TemplatePublishError(Exception):
    """Raised when a template cannot be published (bad sig, conflict, etc.)."""


class TemplateStore:
    """File-backed store of MissionTemplates under <root>/templates/.

    Independent of MissionStore so it can be plumbed without circular imports.
    MissionStore composes it.
    """

    SUBDIR = "templates"
    INDEX_NAME = "_template_index.json"

    def __init__(self, root: Union[str, Path]):
        self.root = Path(root)
        self.dir = self.root / self.SUBDIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / self.INDEX_NAME

    # 鈹€鈹€ publish / load 鈹€鈹€

    def publish(
        self,
        template: MissionTemplate,
        *,
        allow_overwrite: bool = False,
    ) -> Path:
        """Persist a template file. Verifies signature before writing.

        Raises:
            TemplatePublishError: on signature failure or version conflict.
        """
        if not template.verify_signature():
            raise TemplatePublishError(
                f"template {template.template_id}@{template.version} "
                f"signature does not verify"
            )
        path = self.dir / f"{template.file_stem}.json"
        with InterProcessLock(path):
            if path.exists() and not allow_overwrite:
                raise TemplatePublishError(
                    f"template {template.file_stem} already exists; "
                    f"bump version or pass allow_overwrite=True"
                )
            atomic_write_json(path, template.to_dict())
        with InterProcessLock(self.index_path):
            self._refresh_index_unlocked()
        return path

    def load(self, template_id: str, version: str) -> Optional[MissionTemplate]:
        stem = f"{safe_id(template_id)}-v{safe_id(version)}"
        path = self.dir / f"{stem}.json"
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return MissionTemplate.from_dict(data)
        except Exception as e:
            logger.warning("template at %s failed to parse: %s", path, e)
            return None

    def list_all(self, include_deprecated: bool = False) -> List[MissionTemplate]:
        """All templates currently in <root>/templates/ (no archive scan)."""
        out: List[MissionTemplate] = []
        if not self.dir.exists():
            return out
        for path in sorted(self.dir.glob("*.json")):
            data = safe_load_json(path, fallback=None)
            if data is None:
                continue
            try:
                t = MissionTemplate.from_dict(data)
            except Exception:
                continue
            if t.deprecated and not include_deprecated:
                continue
            out.append(t)
        return out

    def list_versions(self, template_id: str) -> List[str]:
        """All known versions of a given template_id, semver-sorted descending."""
        sid = safe_id(template_id)
        versions = []
        for path in self.dir.glob(f"{sid}-v*.json"):
            # Extract version from filename
            stem = path.stem
            prefix = f"{sid}-v"
            if stem.startswith(prefix):
                versions.append(stem[len(prefix):])
        return sorted(versions, key=_semver_key, reverse=True)

    def latest_version(self, template_id: str) -> Optional[str]:
        versions = self.list_versions(template_id)
        return versions[0] if versions else None

    def deprecate(
        self,
        publisher: AgentIdentity,
        template_id: str,
        version: str,
        reason: str = "",
    ) -> MissionTemplate:
        """Mark a template as deprecated. Only the original publisher may deprecate.

        Re-signs the template (mutation requires re-signature). Returns the
        updated template.
        """
        t = self.load(template_id, version)
        if t is None:
            raise TemplatePublishError(
                f"template {template_id}@{version} not found"
            )
        if t.publisher_pubkey != publisher.pubkey_hex:
            raise TemplatePublishError(
                "only the original publisher can deprecate this template"
            )
        if not publisher.can_sign:
            raise ValueError("publisher must be signing-capable to deprecate")
        t.deprecated = True
        t.deprecated_reason = reason
        t.publisher_sig = publisher.sign_json(t.signable_dict())
        self.publish(t, allow_overwrite=True)
        return t

    # Derived index (F-Droid/TUF-style field names; not a trust anchor)

    def _refresh_index(self) -> None:
        with InterProcessLock(self.index_path):
            self._refresh_index_unlocked()

    def _refresh_index_unlocked(self) -> None:
        """Rebuild the unsigned derived _template_index.json."""

        templates = self.list_all(include_deprecated=True)
        prev = safe_load_json(self.index_path, fallback={}) or {}
        prev_version = int(prev.get("version", 0)) if isinstance(prev, dict) else 0
        by_category: Dict[str, List[str]] = {}
        by_publisher: Dict[str, List[str]] = {}
        by_capability: Dict[str, List[str]] = {}
        meta: Dict[str, Dict[str, Any]] = {}
        for t in templates:
            ref = f"{t.template_id}@{t.version}"
            by_category.setdefault(t.category, []).append(ref)
            by_publisher.setdefault(t.publisher_pubkey[:16] or "anonymous", []).append(ref)
            for cap in t.required_capabilities:
                by_capability.setdefault(cap, []).append(ref)
            stem = t.file_stem
            meta[f"{stem}.json"] = {
                "template_id": t.template_id,
                "version": t.version,
                "publisher_pubkey": t.publisher_pubkey,
                "deprecated": t.deprecated,
                "category": t.category,
            }
        index = {
            "version": prev_version + 1,             # TUF-style monotonic
            "generated_at": datetime.now().isoformat(),
            "meta": meta,                            # TUF snapshot.json field name
            "by_category": by_category,
            "by_publisher": by_publisher,
            "by_capability": by_capability,
        }
        atomic_write_json(self.index_path, index)

    def load_index(self) -> Dict[str, Any]:
        return safe_load_json(self.index_path, fallback={}) or {}

    def rebuild_index(self) -> Dict[str, Any]:
        """Force a full rebuild (useful after manual deletions / restores)."""
        self._refresh_index()
        return self.load_index()
