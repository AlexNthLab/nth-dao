"""Persistent supervised-agent roster for the local web hub.

The roster is private runtime state, not project source. Each row describes
one locally spawned agent and points to that agent's Ed25519 identity file.
On hub restart the supervisor can respawn those agents with the same DID, so
relationships, reputation, and delegated work keep their identity anchor.

Layout:
  <workspace>/agents/roster.json
  <workspace>/agents/identities/<uuid>/identity.json
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from nth_dao.util import InterProcessLock


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRoster:
    """Read and write ``<workspace>/agents/roster.json`` safely."""

    def __init__(self, workspace: Path) -> None:
        self._dir = Path(workspace) / "agents"
        self._path = self._dir / "roster.json"
        self._id_dir = self._dir / "identities"

    def _identity_root(self) -> Path:
        return self._id_dir.resolve(strict=False)

    def _normalize_identity_file(self, identity_file: str) -> Optional[Path]:
        if not isinstance(identity_file, str) or not identity_file.strip():
            return None
        try:
            return Path(identity_file).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            return None

    def is_owned_identity_file(self, identity_file: str) -> bool:
        """Return true only for ``agents/identities/<id>/identity.json``.

        ``roster.json`` is intentionally editable by the operator, so every
        path read from it must be treated as untrusted. Restore and cleanup
        code call this before loading or deleting anything.
        """
        path = self._normalize_identity_file(identity_file)
        if path is None or path.name != "identity.json":
            return False
        parent = path.parent
        return parent.parent == self._identity_root() and bool(parent.name)

    def cleanup_identity_dir(self, identity_file: str) -> bool:
        """Delete the owned per-agent identity directory, if it is safe.

        Returns ``True`` only when a directory was actually removed. Unsafe or
        missing paths are ignored. This keeps callers from deriving
        ``Path(identity_file).parent`` and accidentally deleting outside the
        workspace when a runtime roster is corrupt or hostile.
        """
        if not self.is_owned_identity_file(identity_file):
            return False
        path = self._normalize_identity_file(identity_file)
        if path is None:
            return False
        parent = path.parent
        try:
            if not parent.exists() or parent.is_symlink() or not parent.is_dir():
                return False
            shutil.rmtree(parent)
            return True
        except OSError:
            return False

    def _load(self) -> List[Dict[str, Any]]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, OSError):
            return []
        items = data.get("agents") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        return [x for x in items if isinstance(x, dict)]

    def _load_strict(self) -> List[Dict[str, Any]]:
        """Load a roster for security-sensitive lifecycle decisions.

        A missing roster means there are no persistent agents. Corrupt or
        unreadable data is different: callers must preserve resources rather
        than misclassifying a persistent agent as ephemeral.
        """
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except json.JSONDecodeError as exc:
            raise ValueError("agent roster is not valid JSON") from exc
        except OSError as exc:
            raise OSError("agent roster could not be read") from exc
        if not isinstance(data, dict) or not isinstance(data.get("agents"), list):
            raise ValueError("agent roster must contain an agents list")
        items = data["agents"]
        if any(not isinstance(item, dict) for item in items):
            raise ValueError("agent roster contains a non-object entry")
        return items

    def _save(self, items: List[Dict[str, Any]]) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({"agents": items}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(str(tmp), str(self._path))

    def all(self) -> List[Dict[str, Any]]:
        """Return all persisted agent specs, in file order."""
        return self._load()

    def migrate_legacy_slots(self) -> List[Dict[str, Any]]:
        """Add explicit slot lifecycle and disable hidden legacy duplicates."""

        with InterProcessLock(self._path):
            items = self._load_strict()
            legacy_by_kind: Dict[str, List[int]] = {}
            changed = False
            for index, item in enumerate(items):
                if not item.get("slot_id"):
                    legacy_by_kind.setdefault(str(item.get("kind", "mock")), []).append(index)
                    item["slot_id"] = uuid.uuid4().hex
                    item["enabled"] = item.get("enabled", True) is not False
                    item["updated_at"] = _now()
                    changed = True
            for indices in legacy_by_kind.values():
                for index in indices[:-1]:
                    if items[index].get("enabled", True):
                        items[index]["enabled"] = False
                        items[index]["disabled_at"] = _now()
                        items[index]["disabled_reason"] = "legacy-kind-dedup-migration"
                        changed = True
            if changed:
                self._save(items)
            return items

    def allocate_identity_file(self) -> str:
        """Allocate the private identity path for a new persistent agent."""
        self._id_dir.mkdir(parents=True, exist_ok=True)
        path = self._id_dir / uuid.uuid4().hex / "identity.json"
        return str(path.resolve(strict=False))

    def add(
        self, *, identity_file: str, kind: str, label: str,
        capabilities: Optional[List[str]], did: str,
        project_workdir: str = "", work_access: str = "workspace-write",
        work_revision: str = "",
    ) -> None:
        """Register a persistent agent, deduplicated by identity file."""
        if not self.is_owned_identity_file(identity_file):
            raise ValueError(
                "persistent agent identity_file must live under agents/identities"
            )
        with InterProcessLock(self._path):
            items = self._load_strict()
            existing = next(
                (x for x in items if x.get("identity_file") == identity_file),
                None,
            )
            items = [
                x for x in items if x.get("identity_file") != identity_file
            ]
            items.append({
                "slot_id": str((existing or {}).get("slot_id") or uuid.uuid4().hex),
                "identity_file": identity_file,
                "kind": kind,
                "label": label,
                "capabilities": list(capabilities or []),
                "did": did,
                "project_workdir": str(project_workdir or ""),
                "work_access": str(work_access or "workspace-write"),
                "work_revision": str(work_revision or ""),
                "enabled": True,
                "created_at": str((existing or {}).get("created_at") or _now()),
                "updated_at": _now(),
            })
            self._save(items)

    def disable_by_did(
        self, did: str, *, reason: str = "operator-stop",
    ) -> Optional[Dict[str, Any]]:
        """Disable one persistent slot without deleting identity material."""

        with InterProcessLock(self._path):
            items = self._load_strict()
            disabled: Optional[Dict[str, Any]] = None
            for item in items:
                if item.get("did") != did or item.get("enabled", True) is False:
                    continue
                item["enabled"] = False
                item["disabled_at"] = _now()
                item["disabled_reason"] = str(reason or "operator-stop")[:200]
                item["updated_at"] = item["disabled_at"]
                disabled = dict(item)
                break
            if disabled is not None:
                self._save(items)
            return disabled

    def get_by_did(self, did: str) -> Optional[Dict[str, Any]]:
        """Return one persistent slot using strict lifecycle-safe loading."""

        if not isinstance(did, str) or not did:
            return None
        with InterProcessLock(self._path):
            item = next(
                (row for row in self._load_strict() if row.get("did") == did),
                None,
            )
            return dict(item) if item is not None else None

    def remove_by_did(self, did: str) -> Optional[Dict[str, Any]]:
        """Remove one persistent row by DID and return it for audit/cleanup."""
        with InterProcessLock(self._path):
            items = self._load_strict()
            removed: Optional[Dict[str, Any]] = None
            kept: List[Dict[str, Any]] = []
            for x in items:
                if removed is None and x.get("did") == did:
                    removed = x
                else:
                    kept.append(x)
            if removed is not None:
                self._save(kept)
            return removed
