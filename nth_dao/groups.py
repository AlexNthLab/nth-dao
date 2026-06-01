"""Local-first group collaboration primitives.

The group layer stores channels, messages, announcements, tasks, audit events,
and trust hints as JSON/JSONL files. The storage is intentionally plain so it
can be inspected, synced with Git, and merged by higher-level tools later.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .membership import MembershipManager, TeamRole

# Lazy imports to avoid circular deps at module level
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .event_bus import EventBus
    from .identity import AgentIdentity
from .util import atomic_write_json, safe_load_json, safe_id as _safe_id_util

logger = logging.getLogger("nth_dao.groups")


DEFAULT_CHANNELS_DIR = "team_channels"
DEFAULT_TASKS_DIR = "team_tasks"
DEFAULT_ANNOUNCEMENTS_DIR = "team_announcements"
DEFAULT_TRUST_DIR = "team_trust"
DEFAULT_AUDIT_LOG = "team_audit/audit.jsonl"
DEFAULT_CHANNEL_ID = "general"


class MessageKind(str, Enum):
    TEXT = "text"
    COMMAND = "command"
    SYSTEM = "system"


class TaskStatus(str, Enum):
    OPEN = "open"
    ACCEPTED = "accepted"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class Channel:
    """A group chat or topic channel."""

    channel_id: str = DEFAULT_CHANNEL_ID
    name: str = "general"
    topic: str = ""
    created_by: str = ""
    is_private: bool = False
    member_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Channel":
        return cls(
            channel_id=data.get("channel_id", DEFAULT_CHANNEL_ID),
            name=data.get("name", "general"),
            topic=data.get("topic", ""),
            created_by=data.get("created_by", ""),
            is_private=bool(data.get("is_private", False)),
            member_ids=list(data.get("member_ids", [])),
            created_at=data.get("created_at", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Message:
    """A chat message stored append-only per channel."""

    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    channel_id: str = DEFAULT_CHANNEL_ID
    sender_id: str = ""
    body: str = ""
    kind: MessageKind = MessageKind.TEXT
    reply_to: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Message":
        return cls(
            message_id=data.get("message_id", uuid.uuid4().hex[:12]),
            channel_id=data.get("channel_id", DEFAULT_CHANNEL_ID),
            sender_id=data.get("sender_id", ""),
            body=data.get("body", ""),
            kind=_enum_or_default(MessageKind, data.get("kind"), MessageKind.TEXT),
            reply_to=data.get("reply_to", ""),
            created_at=data.get("created_at", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Announcement:
    """Admin-visible announcement for a team or channel."""

    announcement_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    body: str = ""
    author_id: str = ""
    channel_id: str = DEFAULT_CHANNEL_ID
    pinned: bool = True
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Announcement":
        return cls(
            announcement_id=data.get("announcement_id", uuid.uuid4().hex[:12]),
            title=data.get("title", ""),
            body=data.get("body", ""),
            author_id=data.get("author_id", ""),
            channel_id=data.get("channel_id", DEFAULT_CHANNEL_ID),
            pinned=bool(data.get("pinned", True)),
            created_at=data.get("created_at", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Task:
    """A lightweight collaborative task."""

    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    created_by: str = ""
    assignee_id: str = ""
    channel_id: str = DEFAULT_CHANNEL_ID
    status: TaskStatus = TaskStatus.OPEN
    due_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        return cls(
            task_id=data.get("task_id", uuid.uuid4().hex[:12]),
            title=data.get("title", ""),
            description=data.get("description", ""),
            created_by=data.get("created_by", ""),
            assignee_id=data.get("assignee_id", ""),
            channel_id=data.get("channel_id", DEFAULT_CHANNEL_ID),
            status=_enum_or_default(TaskStatus, data.get("status"), TaskStatus.OPEN),
            due_at=data.get("due_at", ""),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AuditEvent:
    """Append-only event describing a group-layer mutation."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    event_type: str = ""
    actor_id: str = ""
    target_type: str = ""
    target_id: str = ""
    summary: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        return cls(
            event_id=data.get("event_id", uuid.uuid4().hex[:12]),
            event_type=data.get("event_type", ""),
            actor_id=data.get("actor_id", ""),
            target_type=data.get("target_type", ""),
            target_id=data.get("target_id", ""),
            summary=data.get("summary", ""),
            created_at=data.get("created_at", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TrustHint:
    """A simple, non-authoritative trust/reputation signal."""

    agent_id: str = ""
    score: float = 0.0
    label: str = ""
    reason: str = ""
    source_id: str = ""
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "TrustHint":
        return cls(
            agent_id=data.get("agent_id", ""),
            score=float(data.get("score", 0.0)),
            label=data.get("label", ""),
            reason=data.get("reason", ""),
            source_id=data.get("source_id", ""),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )


class GroupManager:
    """Local-first channels, messages, announcements, tasks, audit, and trust."""

    def __init__(
        self,
        workspace: Union[str, Path],
        membership: Optional[MembershipManager] = None,
        event_bus: Optional["EventBus"] = None,
        identity: Optional["AgentIdentity"] = None,
    ):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.membership = membership or MembershipManager(self.workspace)
        self._event_bus = event_bus
        self._identity = identity

    @property
    def channels_dir(self) -> Path:
        return self.workspace / DEFAULT_CHANNELS_DIR

    @property
    def tasks_dir(self) -> Path:
        return self.workspace / DEFAULT_TASKS_DIR

    @property
    def announcements_dir(self) -> Path:
        return self.workspace / DEFAULT_ANNOUNCEMENTS_DIR

    @property
    def trust_dir(self) -> Path:
        return self.workspace / DEFAULT_TRUST_DIR

    @property
    def audit_path(self) -> Path:
        return self.workspace / DEFAULT_AUDIT_LOG

    def create_channel(
        self,
        name: str,
        created_by: str,
        topic: str = "",
        channel_id: str = "",
        is_private: bool = False,
        member_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Channel:
        self._require_member(created_by)
        safe_id = self._safe_id(channel_id or name or DEFAULT_CHANNEL_ID)
        members = list(member_ids or [])
        if created_by and created_by not in members:
            members.append(created_by)

        channel = Channel(
            channel_id=safe_id,
            name=name or safe_id,
            topic=topic,
            created_by=created_by,
            is_private=is_private,
            member_ids=members,
            metadata=metadata or {},
        )
        self._write_json(self._channel_path(safe_id), channel.to_dict())
        self._append_audit(
            "channel.created",
            created_by,
            "channel",
            safe_id,
            f"created channel {safe_id}",
        )
        return channel

    def get_channel(self, channel_id: str = DEFAULT_CHANNEL_ID) -> Optional[Channel]:
        path = self._channel_path(channel_id)
        if not path.exists():
            return None
        try:
            data = safe_load_json(path, fallback=None)
            return Channel.from_dict(data) if data is not None else None
        except Exception:
            return None

    def list_channels(self, actor_id: str = "") -> List[Channel]:
        if not self.channels_dir.exists():
            return []
        channels = []
        for path in sorted(self.channels_dir.glob("*.json")):
            channel = self.get_channel(path.stem)
            if channel and self._can_read_channel(channel, actor_id):
                channels.append(channel)
        return channels

    def post_message(
        self,
        channel_id: str,
        sender_id: str,
        body: str,
        kind: Union[MessageKind, str] = MessageKind.TEXT,
        reply_to: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Message:
        self._require_permission(sender_id, "send_messages")
        channel = self._ensure_channel(channel_id, sender_id)
        self._require_channel_access(channel, sender_id)

        message = Message(
            channel_id=channel.channel_id,
            sender_id=sender_id,
            body=body,
            kind=_enum_or_default(MessageKind, kind, MessageKind.TEXT),
            reply_to=reply_to,
            metadata=metadata or {},
        )
        self._append_jsonl(self._messages_path(channel.channel_id), message.to_dict())
        self._append_audit(
            "message.posted",
            sender_id,
            "message",
            message.message_id,
            f"posted message to {channel.channel_id}",
            {"channel_id": channel.channel_id},
        )
        return message

    def list_messages(
        self,
        channel_id: str = DEFAULT_CHANNEL_ID,
        actor_id: str = "",
        limit: Optional[int] = None,
    ) -> List[Message]:
        channel = self.get_channel(channel_id)
        if channel:
            self._require_channel_access(channel, actor_id)
        messages = [
            Message.from_dict(item)
            for item in self._read_jsonl(self._messages_path(channel_id))
        ]
        return messages[-limit:] if limit else messages

    def post_announcement(
        self,
        title: str,
        body: str,
        author_id: str,
        channel_id: str = DEFAULT_CHANNEL_ID,
        pinned: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Announcement:
        self._require_permission(author_id, "post_announcements")
        self._ensure_channel(channel_id, author_id)
        announcement = Announcement(
            title=title,
            body=body,
            author_id=author_id,
            channel_id=channel_id,
            pinned=pinned,
            metadata=metadata or {},
        )
        self._write_json(
            self._announcement_path(announcement.announcement_id),
            announcement.to_dict(),
        )
        self._append_audit(
            "announcement.posted",
            author_id,
            "announcement",
            announcement.announcement_id,
            f"posted announcement {announcement.title}",
            {"channel_id": channel_id},
        )
        return announcement

    def list_announcements(self, channel_id: str = "") -> List[Announcement]:
        if not self.announcements_dir.exists():
            return []
        items = []
        for path in sorted(self.announcements_dir.glob("*.json")):
            data = safe_load_json(path, fallback=None)
            if data is None:
                continue
            try:
                item = Announcement.from_dict(data)
            except Exception:
                continue
            if not channel_id or item.channel_id == channel_id:
                items.append(item)
        return items

    def create_task(
        self,
        title: str,
        created_by: str,
        description: str = "",
        assignee_id: str = "",
        channel_id: str = DEFAULT_CHANNEL_ID,
        due_at: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Task:
        self._require_permission(created_by, "send_messages")
        self._ensure_channel(channel_id, created_by)
        if assignee_id:
            self._require_member(assignee_id)
        task = Task(
            title=title,
            description=description,
            created_by=created_by,
            assignee_id=assignee_id,
            channel_id=channel_id,
            due_at=due_at,
            metadata=metadata or {},
        )
        self._write_json(self._task_path(task.task_id), task.to_dict())
        self._append_audit(
            "task.created",
            created_by,
            "task",
            task.task_id,
            f"created task {task.title}",
            {"channel_id": channel_id, "assignee_id": assignee_id},
        )
        return task

    def update_task_status(
        self,
        task_id: str,
        status: Union[TaskStatus, str],
        actor_id: str,
        note: str = "",
    ) -> Task:
        task = self.get_task(task_id)
        if task is None:
            raise ValueError(f"No task found for '{task_id}'")
        can_update = actor_id in {task.created_by, task.assignee_id}
        can_update = can_update or self.membership.has_permission(actor_id, "manage_members")
        if not can_update:
            raise PermissionError("task status update requires creator, assignee, or admin")

        task.status = _enum_or_default(TaskStatus, status, TaskStatus.OPEN)
        task.updated_at = datetime.now().isoformat()
        if note:
            task.metadata["last_note"] = note
        self._write_json(self._task_path(task.task_id), task.to_dict())
        self._append_audit(
            "task.status_updated",
            actor_id,
            "task",
            task.task_id,
            f"updated task status to {task.status.value}",
            {"note": note} if note else {},
        )
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        path = self._task_path(task_id)
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return Task.from_dict(data)
        except Exception:
            return None

    def list_tasks(self, status: Optional[Union[TaskStatus, str]] = None) -> List[Task]:
        if not self.tasks_dir.exists():
            return []
        wanted = _enum_or_default(TaskStatus, status, None) if status else None
        tasks = []
        for path in sorted(self.tasks_dir.glob("*.json")):
            task = self.get_task(path.stem)
            if task and (wanted is None or task.status == wanted):
                tasks.append(task)
        return tasks

    def set_trust_hint(
        self,
        agent_id: str,
        score: float,
        label: str,
        reason: str,
        source_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TrustHint:
        self._require_permission(source_id, "manage_members")
        self._require_member(agent_id)
        hint = TrustHint(
            agent_id=agent_id,
            score=max(-1.0, min(1.0, float(score))),
            label=label,
            reason=reason,
            source_id=source_id,
            metadata=metadata or {},
        )
        self._write_json(self._trust_path(agent_id), hint.to_dict())
        self._append_audit(
            "trust_hint.set",
            source_id,
            "trust_hint",
            agent_id,
            f"set trust hint for {agent_id}",
            {"score": hint.score, "label": label},
        )
        return hint

    def get_trust_hint(self, agent_id: str) -> Optional[TrustHint]:
        path = self._trust_path(agent_id)
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return TrustHint.from_dict(data)
        except Exception:
            return None

    def list_audit_events(self, limit: Optional[int] = None) -> List[AuditEvent]:
        events = [AuditEvent.from_dict(item) for item in self._read_jsonl(self.audit_path)]
        return events[-limit:] if limit else events

    def _ensure_channel(self, channel_id: str, actor_id: str) -> Channel:
        channel = self.get_channel(channel_id)
        if channel:
            return channel
        if channel_id != DEFAULT_CHANNEL_ID:
            raise ValueError(f"No channel found for '{channel_id}'")
        return self.create_channel(DEFAULT_CHANNEL_ID, actor_id, channel_id=DEFAULT_CHANNEL_ID)

    def _channel_path(self, channel_id: str) -> Path:
        return self.channels_dir / f"{self._safe_id(channel_id)}.json"

    def _messages_path(self, channel_id: str) -> Path:
        return self.channels_dir / f"{self._safe_id(channel_id)}.messages.jsonl"

    def _announcement_path(self, announcement_id: str) -> Path:
        return self.announcements_dir / f"{self._safe_id(announcement_id)}.json"

    def _task_path(self, task_id: str) -> Path:
        return self.tasks_dir / f"{self._safe_id(task_id)}.json"

    def _trust_path(self, agent_id: str) -> Path:
        return self.trust_dir / f"{self._safe_id(agent_id)}.json"

    def _append_audit(
        self,
        event_type: str,
        actor_id: str,
        target_type: str,
        target_id: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            actor_id=actor_id,
            target_type=target_type,
            target_id=target_id,
            summary=summary,
            metadata=metadata or {},
        )

        # Legacy path: append to audit.jsonl (always, for backward compat)
        self._append_jsonl(self.audit_path, event.to_dict())

        # New path: route through EventBus with Ed25519 signing when available
        if self._event_bus is not None:
            try:
                bus_event = self._event_bus.emit(
                    f"group.{event_type}",
                    {
                        "actor_id": actor_id,
                        "target_type": target_type,
                        "target_id": target_id,
                        "summary": summary,
                        "metadata": metadata or {},
                    },
                    identity=self._identity,
                )
                # Cross-reference: store the bus event_id so the legacy
                # audit.jsonl and signed events.jsonl can be correlated
                event.metadata["bus_event_id"] = bus_event.event_id
            except Exception as exc:
                logger.warning("EventBus emit failed for %s: %s", event_type, exc)

        return event

    def _require_permission(self, agent_id: str, permission: str) -> None:
        config = self.membership.load_config()
        if not config.admin_ids and not config.member_ids:
            return
        if not self.membership.has_permission(agent_id, permission):
            raise PermissionError(f"Agent '{agent_id}' lacks permission '{permission}'")

    def _require_member(self, agent_id: str) -> None:
        config = self.membership.load_config()
        if not config.admin_ids and not config.member_ids:
            return
        if config.role_for(agent_id) == TeamRole.GUEST:
            raise PermissionError(f"Agent '{agent_id}' is not a team member")

    def _require_channel_access(self, channel: Channel, actor_id: str) -> None:
        if not channel.is_private:
            self._require_member(actor_id)
            return
        if actor_id not in channel.member_ids:
            raise PermissionError(f"Agent '{actor_id}' cannot access channel '{channel.channel_id}'")

    def _can_read_channel(self, channel: Channel, actor_id: str) -> bool:
        if not channel.is_private:
            return True
        return actor_id in channel.member_ids

    @staticmethod
    def _write_json(path: Path, data: Dict[str, Any]) -> None:
        atomic_write_json(path, data)

    @staticmethod
    def _append_jsonl(path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")

    @staticmethod
    def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        items = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items

    @staticmethod
    def _safe_id(value: str) -> str:
        # 保留 groups 的特殊语义：小写化、空格转 -，然后走 util safe_id
        value = (value or "").strip().lower().replace(" ", "-")
        return _safe_id_util(value, allow_extra="_-.", fallback=DEFAULT_CHANNEL_ID)


def _enum_or_default(enum_cls, value, default):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value))
    except Exception:
        return default
