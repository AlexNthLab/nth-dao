"""Hash-chained local lifecycle audit for the plugin Trust Kernel."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import InterProcessLock


class PluginAuditError(RuntimeError):
    """The plugin lifecycle audit is corrupt or cannot be committed."""


_FIELDS = frozenset(
    {"seq", "recorded_at", "event_type", "plugin_id", "details", "previous_hash", "event_hash"}
)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PLUGIN_ID_RE = re.compile(
    r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?){1,7}$"
)
_MAX_AUDIT_BYTES = 16 * 1024 * 1024
_MAX_AUDIT_LINE_BYTES = 64 * 1024
_MAX_AUDIT_RECORDS = 100_000
_EVENT_DETAIL_FIELDS = {
    "plugin.registered": frozenset({"manifest_digest"}),
    "plugin.upgraded": frozenset(
        {"previous_manifest_digest", "manifest_digest"}
    ),
    "plugin.authorized": frozenset({"grants"}),
    "plugin.enable.succeeded": frozenset({"manifest_digest"}),
    "plugin.enable.failed": frozenset({"error_type", "cleanup_failed"}),
    "plugin.disable.succeeded": frozenset(),
    "plugin.disable.failed": frozenset({"error_type"}),
    "plugin.refresh.succeeded": frozenset(),
    "plugin.refresh.failed": frozenset({"error_type"}),
    "plugin.revoked": frozenset(),
    "plugin.uninstalled": frozenset(),
}
_OPERATOR_EVENT_TYPES = frozenset(
    {
        "plugin.authorized",
        "plugin.enable.succeeded",
        "plugin.enable.failed",
        "plugin.disable.succeeded",
        "plugin.disable.failed",
        "plugin.refresh.succeeded",
        "plugin.refresh.failed",
        "plugin.revoked",
        "plugin.uninstalled",
    }
)


def _load_json_object(line: str, *, line_number: int) -> Dict[str, Any]:
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key {key!r}")
            value[key] = item
        return value

    try:
        item = json.loads(line, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        raise PluginAuditError(
            f"plugin audit line {line_number} is invalid JSON"
        ) from exc
    if not isinstance(item, dict):
        raise PluginAuditError(f"plugin audit line {line_number} must be an object")
    return item


def _validate_details(event_type: str, details: Any, *, line_number: int) -> None:
    if not isinstance(details, dict):
        raise PluginAuditError(f"plugin audit details are invalid at line {line_number}")
    expected = _EVENT_DETAIL_FIELDS.get(event_type)
    actual = frozenset(details)
    allowed = {expected}
    if event_type in _OPERATOR_EVENT_TYPES and expected is not None:
        allowed.add(expected | {"operator"})
    if expected is None or actual not in allowed:
        raise PluginAuditError(
            f"plugin audit event details are invalid at line {line_number}"
        )
    if "operator" in details:
        operator = details["operator"]
        if not isinstance(operator, dict) or set(operator) != {
            "actor_id",
            "principal_type",
        }:
            raise PluginAuditError(
                f"plugin audit operator is invalid at line {line_number}"
            )
        for field, limit in (("principal_type", 64), ("actor_id", 256)):
            value = operator[field]
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > limit
                or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
            ):
                raise PluginAuditError(
                    f"plugin audit operator is invalid at line {line_number}"
                )
    for digest_field in ("manifest_digest", "previous_manifest_digest"):
        if digest_field not in details:
            continue
        digest = details[digest_field]
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise PluginAuditError(
                f"plugin audit manifest digest is invalid at line {line_number}"
            )
    if "grants" in details:
        grants = details["grants"]
        if (
            not isinstance(grants, list)
            or len(grants) > 64
            or any(not isinstance(item, str) or not item for item in grants)
            or grants != sorted(set(grants))
        ):
            raise PluginAuditError(
                f"plugin audit grants are invalid at line {line_number}"
            )
    if "error_type" in details:
        error_type = details["error_type"]
        if (
            not isinstance(error_type, str)
            or not error_type
            or len(error_type.encode("utf-8")) > 128
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in error_type)
        ):
            raise PluginAuditError(
                f"plugin audit error_type is invalid at line {line_number}"
            )
    if "cleanup_failed" in details and type(details["cleanup_failed"]) is not bool:
        raise PluginAuditError(
            f"plugin audit cleanup_failed is invalid at line {line_number}"
        )


def _validate_record(item: Dict[str, Any], *, index: int, previous_hash: str) -> None:
    line_number = index + 1
    if set(item) != _FIELDS:
        raise PluginAuditError(f"plugin audit line {line_number} has invalid fields")
    if type(item["seq"]) is not int or item["seq"] != index:
        raise PluginAuditError(f"plugin audit chain breaks at line {line_number}")
    if item["previous_hash"] != previous_hash:
        raise PluginAuditError(f"plugin audit chain breaks at line {line_number}")
    if not isinstance(item["event_hash"], str) or not _DIGEST_RE.fullmatch(
        item["event_hash"]
    ):
        raise PluginAuditError(f"plugin audit hash is invalid at line {line_number}")
    if not isinstance(item["plugin_id"], str) or not _PLUGIN_ID_RE.fullmatch(
        item["plugin_id"]
    ):
        raise PluginAuditError(f"plugin audit plugin_id is invalid at line {line_number}")
    event_type = item["event_type"]
    if not isinstance(event_type, str) or event_type not in _EVENT_DETAIL_FIELDS:
        raise PluginAuditError(f"plugin audit event_type is invalid at line {line_number}")
    recorded_at = item["recorded_at"]
    try:
        parsed_at = datetime.fromisoformat(recorded_at)
    except (TypeError, ValueError) as exc:
        raise PluginAuditError(
            f"plugin audit recorded_at is invalid at line {line_number}"
        ) from exc
    if parsed_at.tzinfo is None or parsed_at.utcoffset() is None:
        raise PluginAuditError(
            f"plugin audit recorded_at is invalid at line {line_number}"
        )
    _validate_details(event_type, item["details"], line_number=line_number)


class PluginAuditLog:
    """Append and verify bounded lifecycle metadata without storing secrets."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock = InterProcessLock(self.path, timeout=5.0)

    def read_verified(self) -> tuple[Dict[str, Any], ...]:
        if not self.path.exists():
            return ()
        try:
            if self.path.stat().st_size > _MAX_AUDIT_BYTES:
                raise PluginAuditError("plugin audit exceeds its size limit")
            body = self.path.read_bytes()
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PluginAuditError("plugin audit is not valid UTF-8") from exc
        except OSError as exc:
            raise PluginAuditError(f"cannot read plugin audit: {exc}") from exc
        lines = text.splitlines()
        if len(lines) > _MAX_AUDIT_RECORDS:
            raise PluginAuditError("plugin audit exceeds its record limit")
        records = []
        previous_hash = ""
        for index, line in enumerate(lines):
            if len(line.encode("utf-8")) > _MAX_AUDIT_LINE_BYTES:
                raise PluginAuditError(
                    f"plugin audit line {index + 1} exceeds its size limit"
                )
            item = _load_json_object(line, line_number=index + 1)
            _validate_record(item, index=index, previous_hash=previous_hash)
            core = {key: item[key] for key in item if key != "event_hash"}
            expected = hashlib.sha256(canonical_json(core)).hexdigest()
            if item["event_hash"] != expected:
                raise PluginAuditError(f"plugin audit hash mismatch at line {index + 1}")
            records.append(item)
            previous_hash = expected
        return tuple(records)

    def append(
        self,
        event_type: str,
        plugin_id: str,
        details: Mapping[str, Any],
    ) -> Dict[str, Any]:
        if not isinstance(event_type, str) or not event_type.startswith("plugin."):
            raise ValueError("plugin audit event_type is invalid")
        if not isinstance(plugin_id, str) or not plugin_id:
            raise ValueError("plugin audit plugin_id is invalid")
        if not isinstance(details, Mapping):
            raise TypeError("plugin audit details must be an object")
        details_copy = json.loads(canonical_json(dict(details)).decode("utf-8"))
        _validate_details(event_type, details_copy, line_number=1)
        with self.lock:
            records = self.read_verified()
            core = {
                "seq": len(records),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "plugin_id": plugin_id,
                "details": details_copy,
                "previous_hash": records[-1]["event_hash"] if records else "",
            }
            item = {
                **core,
                "event_hash": hashlib.sha256(canonical_json(core)).hexdigest(),
            }
            encoded = canonical_json(item) + b"\n"
            if len(encoded) > _MAX_AUDIT_LINE_BYTES:
                raise PluginAuditError("plugin audit record exceeds its size limit")
            existing_size = self.path.stat().st_size if self.path.exists() else 0
            if existing_size + len(encoded) > _MAX_AUDIT_BYTES:
                raise PluginAuditError("plugin audit exceeds its size limit")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.path.open("ab") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise PluginAuditError(f"cannot append plugin audit: {exc}") from exc
            return item

    def projection(self) -> Dict[str, Dict[str, Any]]:
        state: Dict[str, Dict[str, Any]] = {}
        for item in self.read_verified():
            plugin_id = item["plugin_id"]
            details = item["details"]
            event_type = item["event_type"]
            if event_type == "plugin.registered":
                if plugin_id in state:
                    raise PluginAuditError(
                        f"plugin audit registers active plugin {plugin_id!r} twice"
                    )
                state[plugin_id] = {
                    "manifest_digest": details["manifest_digest"],
                    "grants": [],
                    "desired_enabled": False,
                }
                continue
            if plugin_id not in state:
                raise PluginAuditError(
                    f"plugin audit event {event_type!r} precedes registration for "
                    f"{plugin_id!r}"
                )
            if event_type == "plugin.upgraded":
                if (
                    details["previous_manifest_digest"]
                    != state[plugin_id]["manifest_digest"]
                ):
                    raise PluginAuditError(
                        f"plugin audit upgrade does not bind the previous manifest for "
                        f"{plugin_id!r}"
                    )
                state[plugin_id] = {
                    "manifest_digest": details["manifest_digest"],
                    "grants": [],
                    "desired_enabled": False,
                }
            elif event_type == "plugin.authorized":
                state[plugin_id]["grants"] = list(details["grants"])
            elif event_type == "plugin.enable.succeeded":
                if details["manifest_digest"] != state[plugin_id]["manifest_digest"]:
                    raise PluginAuditError(
                        f"plugin audit manifest changes during enable for {plugin_id!r}"
                    )
                state[plugin_id]["desired_enabled"] = True
            elif event_type in {
                "plugin.disable.succeeded",
                "plugin.disable.failed",
                "plugin.revoked",
            }:
                state[plugin_id]["desired_enabled"] = False
                if event_type == "plugin.revoked":
                    state[plugin_id]["grants"] = []
            elif event_type == "plugin.uninstalled":
                state.pop(plugin_id, None)
        return state


__all__ = ["PluginAuditError", "PluginAuditLog"]
