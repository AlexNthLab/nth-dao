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
from pathlib import Path
from typing import Any, Dict, List, Optional


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

    def allocate_identity_file(self) -> str:
        """Allocate the private identity path for a new persistent agent."""
        self._id_dir.mkdir(parents=True, exist_ok=True)
        path = self._id_dir / uuid.uuid4().hex / "identity.json"
        return str(path.resolve(strict=False))

    def add(
        self, *, identity_file: str, kind: str, label: str,
        capabilities: Optional[List[str]], did: str,
    ) -> None:
        """Register a persistent agent, deduplicated by identity file."""
        if not self.is_owned_identity_file(identity_file):
            raise ValueError(
                "persistent agent identity_file must live under agents/identities"
            )
        items = [x for x in self._load() if x.get("identity_file") != identity_file]
        items.append({
            "identity_file": identity_file,
            "kind": kind,
            "label": label,
            "capabilities": list(capabilities or []),
            "did": did,
        })
        self._save(items)

    def remove_by_did(self, did: str) -> Optional[Dict[str, Any]]:
        """Remove one persistent row by DID and return it for audit/cleanup."""
        items = self._load()
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
