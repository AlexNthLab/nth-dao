"""
Membership management for NTH DAO.

This module owns join policy, team membership, join requests, and admin-gated
approval actions. It is intentionally filesystem-backed to match the rest of
the local/offline team layer design.

Anti-tamper (anti-git-sync-poisoning) layer:
    If `init_team(..., owner_identity=<AgentIdentity>)` is called with a
    crypto-capable identity, every subsequent save_config() signs the
    canonical (sans-signature) team config with the owner's private key.
    load_config() verifies the signature against the pinned `owner_pubkey`
    in the file. A mutation that doesn't carry a matching signature is
    rejected — meaning a malicious node can't push a tampered team.json
    via git_sync to install themselves as admin.

    This is opt-in: teams initialized without an owner identity behave as
    before (no signing, no verification). To upgrade an existing team, call
    `enable_signed_owner(owner_identity, actor_id=<existing_owner>)`.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .util import atomic_write_json, safe_load_json, safe_id as _safe_id

logger = logging.getLogger("nth_dao.membership")


DEFAULT_TEAM_CONFIG = "team.json"
DEFAULT_REQUESTS_DIR = "team_agents/requests"


class TamperedTeamConfigError(RuntimeError):
    """Raised when a signed team config fails owner-signature verification."""


class JoinPolicy(str, Enum):
    OPEN = "open"
    APPROVAL = "approval"
    INVITE_ONLY = "invite_only"
    TOKEN = "token"


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class TeamRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


ROLE_PERMISSIONS: Dict[TeamRole, set[str]] = {
    TeamRole.OWNER: {
        "manage_team",
        "manage_admins",
        "manage_members",
        "approve_members",
        "post_announcements",
        "read_messages",
        "send_messages",
    },
    TeamRole.ADMIN: {
        "manage_members",
        "approve_members",
        "post_announcements",
        "read_messages",
        "send_messages",
    },
    TeamRole.MEMBER: {
        "read_messages",
        "send_messages",
    },
    TeamRole.GUEST: set(),
}


@dataclass
class TeamConfig:
    """Global team membership configuration.

    When `owner_pubkey` is non-empty, this config is signed:
        owner_sig = sign(canonical_json(self.to_dict() minus owner_sig))

    load_config() will refuse to load a config whose owner_pubkey is set
    but whose owner_sig is missing or invalid — protecting against tampered
    team.json pushed via git_sync.
    """

    team_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    team_name: str = "Unnamed Team"
    join_policy: JoinPolicy = JoinPolicy.OPEN
    join_token: str = ""
    admin_ids: List[str] = field(default_factory=list)
    member_ids: List[str] = field(default_factory=list)
    roles: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Optional owner anchor for anti-tamper signed config.
    owner_pubkey: str = ""  # Ed25519 pubkey hex
    owner_sig: str = ""     # Ed25519 signature hex of canonical_json(this dict - owner_sig)
    sig_updated_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["join_policy"] = self.join_policy.value
        return d

    def signable_dict(self) -> dict:
        """Dict to sign — every field except owner_sig itself."""
        d = self.to_dict()
        d.pop("owner_sig", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "TeamConfig":
        return cls(
            team_id=data.get("team_id", uuid.uuid4().hex[:8]),
            team_name=data.get("team_name", "Unnamed Team"),
            join_policy=MembershipManager.normalize_policy(data.get("join_policy", "open")),
            join_token=data.get("join_token", ""),
            admin_ids=list(data.get("admin_ids", [])),
            member_ids=list(data.get("member_ids", [])),
            roles=dict(data.get("roles", {})),
            created_at=data.get("created_at", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
            owner_pubkey=data.get("owner_pubkey", ""),
            owner_sig=data.get("owner_sig", ""),
            sig_updated_at=data.get("sig_updated_at", ""),
        )

    def is_admin(self, agent_id: str) -> bool:
        return agent_id in self.admin_ids

    def is_member(self, agent_id: str) -> bool:
        return agent_id in self.member_ids

    def role_for(self, agent_id: str) -> TeamRole:
        raw = self.roles.get(agent_id)
        if raw:
            try:
                return TeamRole(raw)
            except ValueError:
                pass
        if agent_id in self.admin_ids:
            return TeamRole.ADMIN
        if agent_id in self.member_ids:
            return TeamRole.MEMBER
        return TeamRole.GUEST

    def has_permission(self, agent_id: str, permission: str) -> bool:
        role = self.role_for(agent_id)
        return permission in ROLE_PERMISSIONS.get(role, set())


@dataclass
class JoinRequest:
    """A pending or historical request for an agent to join a team."""

    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    agent_id: str = ""
    capabilities: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    backend_id: str = "unknown"
    hostname: str = ""
    pid: int = 0
    message: str = ""
    status: RequestStatus = RequestStatus.PENDING
    reviewed_by: str = ""
    review_note: str = ""
    submitted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    reviewed_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "JoinRequest":
        status_raw = data.get("status", "pending")
        try:
            status = RequestStatus(status_raw)
        except ValueError:
            status = RequestStatus.PENDING

        return cls(
            request_id=data.get("request_id", uuid.uuid4().hex[:8]),
            agent_id=data.get("agent_id", ""),
            capabilities=list(data.get("capabilities", [])),
            groups=list(data.get("groups", [])),
            backend_id=data.get("backend_id", "unknown"),
            hostname=data.get("hostname", ""),
            pid=data.get("pid", 0),
            message=data.get("message", ""),
            status=status,
            reviewed_by=data.get("reviewed_by", ""),
            review_note=data.get("review_note", ""),
            submitted_at=data.get("submitted_at", ""),
            reviewed_at=data.get("reviewed_at", ""),
            metadata=data.get("metadata", {}),
        )


MembershipRequest = JoinRequest


class MembershipManager:
    """Team membership, join requests, approval, invite, and removal.

    Optional anti-tamper:
        Pass `owner_identity` to enable signed team.json. When set, every
        save_config() signs the config with owner_identity's private key;
        load_config() verifies against the pinned `owner_pubkey` in the file.
    """

    MAX_REQUEST_AGE_SECONDS = 86400 * 7

    def __init__(self, workspace: Path, owner_identity: Optional[Any] = None):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        # owner_identity: nth_dao.identity.AgentIdentity (lazy import to avoid cycle)
        self._owner_identity = owner_identity

    @staticmethod
    def normalize_policy(policy: Union[JoinPolicy, str]) -> JoinPolicy:
        if isinstance(policy, JoinPolicy):
            return policy
        try:
            return JoinPolicy(str(policy))
        except ValueError as exc:
            valid = ", ".join(p.value for p in JoinPolicy)
            raise ValueError(f"Unknown join_policy '{policy}'. Expected one of: {valid}") from exc

    @property
    def config_path(self) -> Path:
        return self.workspace / DEFAULT_TEAM_CONFIG

    @property
    def requests_dir(self) -> Path:
        return self.workspace / DEFAULT_REQUESTS_DIR

    def load_config(self) -> TeamConfig:
        """Load team config, verifying owner signature if present.

        Returns a fresh default TeamConfig when the file doesn't exist or
        signature verification fails — preventing a tampered team.json from
        granting admin privileges. Failed verification is logged at WARNING.
        """
        data = safe_load_json(self.config_path, fallback=None)
        if data is None:
            return TeamConfig()
        try:
            cfg = TeamConfig.from_dict(data)
        except Exception:
            return TeamConfig()

        # 若文件声明了 owner_pubkey，必须有合法签名
        if cfg.owner_pubkey:
            if not cfg.owner_sig or not _verify_config_signature(cfg):
                logger.warning(
                    "team.json at %s has invalid/missing owner signature — "
                    "rejecting and returning empty config. Possible tamper.",
                    self.config_path,
                )
                raise TamperedTeamConfigError(
                    f"team config at {self.config_path} has invalid owner signature"
                )

        return cfg

    def save_config(self, config: TeamConfig) -> None:
        """Save team config, signing it if owner_identity is set on this manager."""
        # 如果 manager 持有 owner_identity 且能签名 → 写入 owner_pubkey + sig
        if self._owner_identity is not None and getattr(self._owner_identity, "can_sign", False):
            config.owner_pubkey = self._owner_identity.pubkey_hex
            config.sig_updated_at = datetime.now().isoformat()
            # 先清空 owner_sig 再签
            config.owner_sig = ""
            config.owner_sig = self._owner_identity.sign_json(config.signable_dict())
        atomic_write_json(self.config_path, config.to_dict())

    def enable_signed_owner(
        self,
        owner_identity: Any,
        actor_id: str = "",
    ) -> TeamConfig:
        """Upgrade an existing (or fresh) team to signed-config mode.

        Subsequent save_config() calls will sign with this identity.
        Must be called by an existing admin (or on a fresh team before any
        admins are set). The new owner_pubkey is pinned in the file.
        """
        if not getattr(owner_identity, "can_sign", False):
            raise ValueError(
                "enable_signed_owner requires a crypto-capable AgentIdentity "
                "(generate via AgentIdentity.generate() with pynacl)"
            )
        config = self.load_config()
        # Owner enablement is admin-gated unless team has no admins yet
        self._require_admin(config, actor_id)
        self._owner_identity = owner_identity
        # Trigger a signed save
        self.save_config(config)
        return self.load_config()

    def init_team(
        self,
        team_name: str = "My Team",
        policy: Union[JoinPolicy, str] = JoinPolicy.OPEN,
        join_token: str = "",
        admin_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        owner_identity: Any = None,
    ) -> TeamConfig:
        config = self.load_config()
        config.team_name = team_name
        config.join_policy = self.normalize_policy(policy)
        config.join_token = join_token

        had_admin = bool(config.admin_ids)
        for admin_id in admin_ids or []:
            if admin_id not in config.admin_ids:
                config.admin_ids.append(admin_id)
            if admin_id not in config.member_ids:
                config.member_ids.append(admin_id)
            default_role = TeamRole.ADMIN.value if had_admin else TeamRole.OWNER.value
            config.roles.setdefault(admin_id, default_role)
            had_admin = True

        if metadata:
            config.metadata.update(metadata)

        # 如果调用方提供 owner_identity，启用签名（覆盖 manager 默认）
        if owner_identity is not None:
            if not getattr(owner_identity, "can_sign", False):
                raise ValueError(
                    "init_team(owner_identity=) requires crypto-capable identity"
                )
            self._owner_identity = owner_identity

        self.save_config(config)
        return config

    def set_policy(
        self,
        policy: Union[JoinPolicy, str],
        join_token: str = "",
        actor_id: str = "",
    ) -> TeamConfig:
        config = self.load_config()
        self._require_admin(config, actor_id)
        config.join_policy = self.normalize_policy(policy)
        if join_token:
            config.join_token = join_token
        self.save_config(config)
        return config

    def add_admin(self, agent_id: str, actor_id: str = "") -> TeamConfig:
        config = self.load_config()
        self._require_admin(config, actor_id)
        if agent_id not in config.admin_ids:
            config.admin_ids.append(agent_id)
        if agent_id not in config.member_ids:
            config.member_ids.append(agent_id)
        config.roles[agent_id] = TeamRole.ADMIN.value
        self.save_config(config)
        return config

    def remove_admin(self, agent_id: str, actor_id: str = "") -> TeamConfig:
        config = self.load_config()
        self._require_admin(config, actor_id)
        if agent_id in config.admin_ids:
            config.admin_ids.remove(agent_id)
        if config.roles.get(agent_id) == TeamRole.ADMIN.value:
            config.roles[agent_id] = TeamRole.MEMBER.value
        self.save_config(config)
        return config

    def set_role(
        self,
        agent_id: str,
        role: Union[TeamRole, str],
        actor_id: str = "",
    ) -> TeamConfig:
        config = self.load_config()
        self._require_admin(config, actor_id)
        normalized_role = self._normalize_role(role)
        role_value = normalized_role.value

        if agent_id not in config.member_ids:
            raise ValueError(f"Agent '{agent_id}' is not a team member")
        if normalized_role == TeamRole.OWNER and config.role_for(actor_id) != TeamRole.OWNER:
            raise PermissionError("owner role required")
        if role_value in {TeamRole.OWNER.value, TeamRole.ADMIN.value}:
            if agent_id not in config.admin_ids:
                config.admin_ids.append(agent_id)
        elif agent_id in config.admin_ids:
            config.admin_ids.remove(agent_id)

        config.roles[agent_id] = role_value
        self.save_config(config)
        return config

    def role_for(self, agent_id: str) -> TeamRole:
        return self.load_config().role_for(agent_id)

    def has_permission(self, agent_id: str, permission: str) -> bool:
        return self.load_config().has_permission(agent_id, permission)

    def can_join(self, agent_id: str, token: str = "") -> tuple[bool, str]:
        config = self.load_config()

        if agent_id in config.member_ids:
            return True, "already_member"

        policy = config.join_policy

        if policy == JoinPolicy.OPEN:
            return True, "open_policy"

        if policy == JoinPolicy.APPROVAL:
            existing = self.get_request(agent_id)
            if existing and existing.status == RequestStatus.APPROVED:
                return True, "approved_request"
            return False, "approval_required"

        if policy == JoinPolicy.INVITE_ONLY:
            return False, "invite_only"

        if policy == JoinPolicy.TOKEN:
            # 常量时间比较，避免定时侧信道
            if (
                config.join_token
                and token
                and hmac.compare_digest(token, config.join_token)
            ):
                return True, "valid_token"
            return False, "invalid_or_missing_token"

        return False, f"unknown_policy: {policy}"

    def ensure_member(self, agent_id: str, token: str = "") -> tuple[bool, str]:
        allowed, reason = self.can_join(agent_id, token=token)
        if not allowed:
            return False, reason

        config = self.load_config()
        if agent_id not in config.member_ids:
            config.member_ids.append(agent_id)
        config.roles.setdefault(agent_id, TeamRole.MEMBER.value)
        self.save_config(config)
        return True, reason

    def request_join(
        self,
        agent_id: str,
        capabilities: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
        backend_id: str = "unknown",
        hostname: str = "",
        pid: int = 0,
        message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        token: str = "",
    ) -> JoinRequest:
        config = self.load_config()

        if agent_id in config.member_ids:
            return JoinRequest(
                agent_id=agent_id,
                capabilities=capabilities or [],
                groups=groups or [],
                backend_id=backend_id,
                hostname=hostname,
                pid=pid,
                message="already member",
                status=RequestStatus.APPROVED,
                reviewed_by="system",
                reviewed_at=datetime.now().isoformat(),
            )

        existing = self.get_request(agent_id)
        if existing and existing.status == RequestStatus.PENDING:
            raise ValueError(
                f"Agent '{agent_id}' already has a pending join request. "
                "Wait for approval or cancel first."
            )

        if config.join_policy == JoinPolicy.TOKEN:
            if (
                not config.join_token
                or not token
                or not hmac.compare_digest(token, config.join_token)
            ):
                raise PermissionError("join_policy=token requires a valid join_token.")

        if config.join_policy == JoinPolicy.INVITE_ONLY:
            raise PermissionError(
                f"join_policy=invite_only. Agent '{agent_id}' can only be invited by an admin."
            )

        req = JoinRequest(
            agent_id=agent_id,
            capabilities=capabilities or [],
            groups=groups or [],
            backend_id=backend_id,
            hostname=hostname,
            pid=pid,
            message=message,
            status=RequestStatus.PENDING,
            metadata=metadata or {},
        )
        self._write_request(req)

        if config.join_policy == JoinPolicy.OPEN:
            return self.approve(req.agent_id, reviewed_by="system", note="open policy")

        if config.join_policy == JoinPolicy.TOKEN:
            return self.approve(req.agent_id, reviewed_by="system", note="token auto-approve")

        return req

    def get_request(self, agent_id: str) -> Optional[JoinRequest]:
        path = self._request_path_for(agent_id)
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return JoinRequest.from_dict(data)
        except Exception:
            return None

    def list_requests(self, status: Optional[RequestStatus] = None) -> List[JoinRequest]:
        reqs = []
        if not self.requests_dir.exists():
            return reqs
        for f in sorted(self.requests_dir.glob("*.json")):
            data = safe_load_json(f, fallback=None)
            if data is None:
                continue
            try:
                req = JoinRequest.from_dict(data)
            except Exception:
                continue
            if status is None or req.status == status:
                reqs.append(req)
        return reqs

    def list_pending(self) -> List[JoinRequest]:
        return self.list_requests(status=RequestStatus.PENDING)

    def approve(
        self,
        agent_id: str,
        reviewed_by: str = "",
        note: str = "",
    ) -> JoinRequest:
        req = self.get_request(agent_id)
        if req is None:
            raise ValueError(f"No join request found for '{agent_id}'")

        config = self.load_config()
        self._require_admin(config, reviewed_by, allow_system=True)

        if req.status != RequestStatus.PENDING:
            raise ValueError(f"Request for '{agent_id}' is already {req.status.value}")

        req.status = RequestStatus.APPROVED
        req.reviewed_by = reviewed_by
        req.reviewed_at = datetime.now().isoformat()
        req.review_note = note or "approved"
        self._write_request(req)

        if agent_id not in config.member_ids:
            config.member_ids.append(agent_id)
        config.roles.setdefault(agent_id, TeamRole.MEMBER.value)
        self.save_config(config)

        return req

    def reject(
        self,
        agent_id: str,
        reviewed_by: str = "",
        note: str = "",
    ) -> JoinRequest:
        req = self.get_request(agent_id)
        if req is None:
            raise ValueError(f"No join request found for '{agent_id}'")

        config = self.load_config()
        self._require_admin(config, reviewed_by, allow_system=True)

        if req.status != RequestStatus.PENDING:
            raise ValueError(f"Request for '{agent_id}' is already {req.status.value}")

        req.status = RequestStatus.REJECTED
        req.reviewed_by = reviewed_by
        req.reviewed_at = datetime.now().isoformat()
        req.review_note = note or "rejected"
        self._write_request(req)

        return req

    def invite(
        self,
        agent_id: str,
        capabilities: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
        invited_by: str = "",
        note: str = "",
    ) -> JoinRequest:
        config = self.load_config()
        self._require_admin(config, invited_by)

        existing = self.get_request(agent_id)
        if existing and existing.status == RequestStatus.PENDING:
            return self.approve(agent_id, reviewed_by=invited_by, note=note)

        req = JoinRequest(
            agent_id=agent_id,
            capabilities=capabilities or [],
            groups=groups or [],
            backend_id="unknown",
            hostname="",
            pid=0,
            message=f"Invited by {invited_by}" + (f": {note}" if note else ""),
            status=RequestStatus.APPROVED,
            reviewed_by=invited_by,
            reviewed_at=datetime.now().isoformat(),
            review_note=note,
        )
        self._write_request(req)

        if agent_id not in config.member_ids:
            config.member_ids.append(agent_id)
        config.roles.setdefault(agent_id, TeamRole.MEMBER.value)
        self.save_config(config)

        return req

    def remove_member(self, agent_id: str, actor_id: str = "") -> None:
        config = self.load_config()
        self._require_admin(config, actor_id)
        if agent_id in config.member_ids:
            config.member_ids.remove(agent_id)
        if agent_id in config.admin_ids:
            config.admin_ids.remove(agent_id)
        config.roles.pop(agent_id, None)
        self.save_config(config)

    def _request_path_for(self, agent_id: str) -> Path:
        if not agent_id:
            raise ValueError("agent_id cannot be empty")
        return self.requests_dir / f"{_safe_id(agent_id)}.json"

    def _write_request(self, req: JoinRequest) -> None:
        path = self._request_path_for(req.agent_id)
        atomic_write_json(path, req.to_dict())

    def _require_admin(
        self,
        config: TeamConfig,
        actor_id: str,
        allow_system: bool = False,
    ) -> None:
        if allow_system and actor_id == "system":
            return
        if not config.admin_ids:
            return
        if not actor_id:
            raise PermissionError("admin action requires actor_id/reviewed_by")
        if actor_id not in config.admin_ids:
            raise PermissionError(f"Agent '{actor_id}' is not a team admin")

    @staticmethod
    def _normalize_role(role: Union[TeamRole, str]) -> TeamRole:
        if isinstance(role, TeamRole):
            return role
        try:
            return TeamRole(str(role))
        except ValueError as exc:
            valid = ", ".join(r.value for r in TeamRole)
            raise ValueError(f"Unknown team role '{role}'. Expected one of: {valid}") from exc

    def dashboard(self) -> str:
        config = self.load_config()
        pending = self.list_pending()

        lines = [
            "=" * 50,
            f"  Team: {config.team_name} ({config.team_id})",
            f"  Policy: {config.join_policy.value}",
            f"  Admins: {', '.join(config.admin_ids) or '(none)'}",
            f"  Roles: {len(config.roles)} assigned",
            f"  Members ({len(config.member_ids)}): {', '.join(config.member_ids[:10])}"
            + ("..." if len(config.member_ids) > 10 else ""),
            "=" * 50,
        ]

        if pending:
            lines.append(f"\n  Pending Requests ({len(pending)}):")
            for r in pending:
                caps = ",".join(r.capabilities[:3])
                lines.append(
                    f"    [{r.request_id}] {r.agent_id}"
                    f"  caps=[{caps}]  submitted={r.submitted_at[:16]}"
                )
                if r.message:
                    lines.append(f'         "{r.message}"')
        else:
            lines.append("\n  No pending requests.")

        recent = [r for r in self.list_requests() if r.status != RequestStatus.PENDING]
        recent.sort(key=lambda r: r.reviewed_at, reverse=True)
        if recent:
            lines.append("\n  Recent Decisions:")
            for r in recent[:5]:
                marker = "OK" if r.status == RequestStatus.APPROVED else "NO"
                lines.append(
                    f"    {marker} {r.agent_id} -> {r.status.value} "
                    f"by {r.reviewed_by or '?'}  {r.reviewed_at[:16]}"
                )

        return "\n".join(lines)


# ───────────────────── module-level signature helpers ─────────────────────


def _verify_config_signature(cfg: TeamConfig) -> bool:
    """Verify cfg.owner_sig against cfg.owner_pubkey over canonical signable dict.

    Returns False (not raising) on any failure — caller handles it as tamper.
    """
    try:
        # Lazy import avoids cycle nth_dao.identity → nth_dao.membership
        from .identity import _NACL_AVAILABLE, _VerifyKey, canonical_json  # type: ignore
    except Exception:
        return False
    if not _NACL_AVAILABLE or _VerifyKey is None:
        # Without crypto we can't verify; refuse to trust a signed config
        return False
    try:
        pubkey = bytes.fromhex(cfg.owner_pubkey)
        sig = bytes.fromhex(cfg.owner_sig)
    except ValueError:
        return False
    try:
        _VerifyKey(pubkey).verify(canonical_json(cfg.signable_dict()), sig)
        return True
    except Exception:
        return False
