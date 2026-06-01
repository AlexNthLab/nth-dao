"""
Channel  Agent //

QQ/Agents @ Agent



- team_messages/{channel_id}/*.jsonlappend-only ledger
- {hostname}_{agent_id}_{timestamp}.jsonlgit_sync
-  scope
    - "team"
    - "group:<name>"
    - "dm:<a>_<b>"    agent_id
-  Ed25519  identity
- pullfetch(since=...)
- @mentions  @


    team = nth.attach(identity=ident, ...)

    #
    team.channel.send("", scope="team")

    #
    team.channel.send("", scope="group:backend")

    #
    team.channel.dm("bob", " PR LGTM!")

    # @
    team.channel.send(" @alice ", mentions=["alice"])

    #
    msgs = team.channel.fetch(since=last_checkpoint)
    for m in msgs:
        print(f"[{m.from_agent}] {m.content}")

    #
    all_msgs = team.channel.fetch_all(since=last_checkpoint)

    #  @
    mentions = team.channel.mentions_for(my_agent_id)


    team_messages/
     team/
        host1_alice_2026-05-27.jsonl
        host2_bob_2026-05-27.jsonl
     group--backend/
        host1_alice_2026-05-27.jsonl
     dm--alice--bob/
         host1_alice_2026-05-27.jsonl
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .identity import AgentIdentity


#

DEFAULT_MESSAGES_DIR = "team_messages"
TEAM_CHANNEL = "team"
DM_PREFIX = "dm"
GROUP_PREFIX = "group"


#


@dataclass
class ChannelMessage:
    """"""

    msg_id: str
    channel: str           # "team" | "group:xxx" | "dm:alice--bob"
    from_agent: str        # agent_id
    content: str
    content_type: str = "text"  # "text" | "markdown" | "json"
    reply_to: str = ""     #  msg_id =
    mentions: List[str] = field(default_factory=list)  # @ agent_id
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    sig: str = ""          # Ed25519 128  hex
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "msg_id": self.msg_id,
            "channel": self.channel,
            "from_agent": self.from_agent,
            "content": self.content,
            "content_type": self.content_type,
            "reply_to": self.reply_to,
            "mentions": self.mentions,
            "timestamp": self.timestamp,
            "sig": self.sig,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChannelMessage":
        return cls(
            msg_id=data.get("msg_id", ""),
            channel=data.get("channel", TEAM_CHANNEL),
            from_agent=data.get("from_agent", "?"),
            content=data.get("content", ""),
            content_type=data.get("content_type", "text"),
            reply_to=data.get("reply_to", ""),
            mentions=data.get("mentions", []),
            timestamp=data.get("timestamp", ""),
            sig=data.get("sig", ""),
            metadata=data.get("metadata", {}),
        )

    @property
    def is_reply(self) -> bool:
        return bool(self.reply_to)

    @property
    def short_id(self) -> str:
        return self.msg_id[:8] if self.msg_id else "?"

    def __repr__(self) -> str:
        preview = self.content[:40].replace("\n", " ")
        return f"[{self.channel}] {self.from_agent}: {preview}"


#


def _channel_dir(channel: str) -> str:
    """

    "team"       "team"
    "group:backend"  "group--backend"
    "dm:alice--bob"  "dm--alice--bob"
    """
    return channel.replace(":", "--").replace("/", "-")


def _dm_channel(agent_a: str, agent_b: str) -> str:
    """ DM  agent """
    a, b = sorted([agent_a, agent_b])
    return f"{DM_PREFIX}:{a}--{b}"


#  TeamChannel


class TeamChannel:
    """Agent """

    #
    MAX_CONTENT_LENGTH = 10000

    def __init__(
        self,
        workspace: Path,
        agent_id: str,
        identity: Optional[AgentIdentity] = None,
        messages_dir: str = DEFAULT_MESSAGES_DIR,
    ):
        """
        Args:
            workspace:
            agent_id:  Agent  ID
            identity:
            messages_dir:
        """
        self.workspace = workspace
        self.agent_id = agent_id
        self.identity = identity
        self.base_dir = workspace / messages_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    #

    def send(
        self,
        content: str,
        scope: str = TEAM_CHANNEL,
        content_type: str = "text",
        reply_to: str = "",
        mentions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ChannelMessage:
        """

        Args:
            content:
            scope: "team" / "group:<name>" / "dm:<alice>--<bob>"
            content_type: "text" | "markdown" | "json"
            reply_to:  ID
            mentions: @ agent_id
            metadata:

        Returns:
             ChannelMessage
        """
        #
        if len(content) > self.MAX_CONTENT_LENGTH:
            content = content[: self.MAX_CONTENT_LENGTH - 50] + "\n... [truncated]"

        msg = ChannelMessage(
            msg_id=uuid.uuid4().hex,
            channel=scope,
            from_agent=self.agent_id,
            content=content,
            content_type=content_type,
            reply_to=reply_to,
            mentions=mentions or [],
            metadata=metadata or {},
        )

        #
        if self.identity and self.identity.can_sign:
            payload = {
                "msg_id": msg.msg_id,
                "channel": msg.channel,
                "from_agent": msg.from_agent,
                "content": msg.content,
                "content_type": msg.content_type,
                "reply_to": msg.reply_to,
                "mentions": msg.mentions,
                "timestamp": msg.timestamp,
                "metadata": msg.metadata,
            }
            msg.sig = self.identity.sign_json(payload)

        self._append(msg)
        return msg

    def dm(
        self,
        to_agent: str,
        content: str,
        content_type: str = "text",
    ) -> ChannelMessage:
        """"""
        channel = _dm_channel(self.agent_id, to_agent)
        return self.send(content=content, scope=channel, content_type=content_type)

    def reply(
        self,
        to_msg: ChannelMessage,
        content: str,
        mentions: Optional[List[str]] = None,
    ) -> ChannelMessage:
        """"""
        return self.send(
            content=content,
            scope=to_msg.channel,
            reply_to=to_msg.msg_id,
            mentions=mentions,
        )

    #

    def fetch(
        self,
        channel: str = TEAM_CHANNEL,
        since: Optional[str] = None,      # ISO timestamp, 严格大于此值
        since_msg_id: Optional[str] = None,  # 取这个 msg 之后的所有
        limit: int = 50,
    ) -> List[ChannelMessage]:
        """读取 channel 最近 limit 条消息（按 timestamp 全局排序）。

        修复了原版本：
            1) 跨多文件（{host}_{agent}_{date}.jsonl）按文件遍历会乱序
               → 现在先全部加载，按 timestamp 全局排序，再切 limit
            2) since_msg_id 在跨文件时可能漏掉 → 改成"先排序后切"
        """
        dir_path = self.base_dir / _channel_dir(channel)
        if not dir_path.exists():
            return []

        # 1) 全部加载 + 按 timestamp 排序
        all_msgs: List[ChannelMessage] = []
        for file_path in sorted(dir_path.glob("*.jsonl")):
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                try:
                    all_msgs.append(ChannelMessage.from_dict(data))
                except Exception:
                    continue

        all_msgs.sort(key=lambda m: (m.timestamp, m.msg_id))

        # 2) 切 since 边界
        if since_msg_id:
            cut = -1
            for i, m in enumerate(all_msgs):
                if m.msg_id == since_msg_id:
                    cut = i
                    break
            if cut >= 0:
                all_msgs = all_msgs[cut + 1:]
            # since_msg_id 没找到 → 当作没过滤（caller bookmark 已过期/不在本节点）
        elif since:
            all_msgs = [m for m in all_msgs if m.timestamp > since]

        # 3) 切 limit
        if limit > 0 and len(all_msgs) > limit:
            return all_msgs[-limit:]
        return all_msgs

    def fetch_all(
        self,
        since: Optional[str] = None,
        limit_per_channel: int = 20,
        channels: Optional[List[str]] = None,
    ) -> Dict[str, List[ChannelMessage]]:
        """

        Args:
            since:
            limit_per_channel:
            channels: None =

        Returns:
            {channel_name: [messages]}
        """
        result = {}

        if channels:
            dirs = [_channel_dir(c) for c in channels]
        else:
            if not self.base_dir.exists():
                return result
            dirs = sorted(
                d.name for d in self.base_dir.iterdir()
                if d.is_dir() and not d.name.startswith(".")
            )

        for dir_name in dirs:
            #
            channel = dir_name.replace("--", ":", 1)
            msgs = self.fetch(channel=channel, since=since, limit=limit_per_channel)
            if msgs:
                result[channel] = msgs

        return result

    def mentions_for(
        self,
        agent_id: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 30,
    ) -> List[ChannelMessage]:
        """ @ Agent

        Args:
            agent_id:  @  agent = self.agent_id
            since:
            limit:

        Returns:
             @mention
        """
        target = agent_id or self.agent_id
        results = []

        if not self.base_dir.exists():
            return results

        for dir_path in sorted(self.base_dir.iterdir()):
            if not dir_path.is_dir() or dir_path.name.startswith("."):
                continue
            for file_path in sorted(dir_path.glob("*.jsonl")):
                try:
                    for line in file_path.read_text(encoding="utf-8").strip().split("\n"):
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        mentions = data.get("mentions", [])
                        if target not in mentions:
                            continue
                        if since and data.get("timestamp", "") <= since:
                            continue
                        results.append(ChannelMessage.from_dict(data))
                        if len(results) >= limit:
                            break
                except Exception:
                    continue

        return results

    #

    def search(
        self,
        keyword: str,
        channel: Optional[str] = None,
        from_agent: Optional[str] = None,
        limit: int = 20,
    ) -> List[ChannelMessage]:
        """

        Args:
            keyword:
            channel: None =
            from_agent:
            limit:
        """
        results = []
        keyword_lower = keyword.lower()

        dirs_to_search = (
            [self.base_dir / _channel_dir(channel)]
            if channel
            else [d for d in self.base_dir.iterdir() if d.is_dir()]
        )

        for dir_path in dirs_to_search:
            if not dir_path.exists():
                continue
            for file_path in sorted(dir_path.glob("*.jsonl")):
                try:
                    for line in file_path.read_text(encoding="utf-8").strip().split("\n"):
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        if keyword_lower not in data.get("content", "").lower():
                            continue
                        if from_agent and data.get("from_agent") != from_agent:
                            continue
                        results.append(ChannelMessage.from_dict(data))
                        if len(results) >= limit:
                            return results
                except Exception:
                    continue

        return results

    #

    def list_channels(self) -> List[str]:
        """"""
        if not self.base_dir.exists():
            return []
        return sorted(
            d.name.replace("--", ":", 1)
            for d in self.base_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )

    def stats(self) -> Dict[str, Any]:
        """"""
        total_messages = 0
        channels = {}

        if self.base_dir.exists():
            for dir_path in self.base_dir.iterdir():
                if not dir_path.is_dir() or dir_path.name.startswith("."):
                    continue
                count = 0
                for file_path in dir_path.glob("*.jsonl"):
                    try:
                        count += sum(
                            1
                            for line in file_path.read_text(encoding="utf-8").splitlines()
                            if line.strip()
                        )
                    except Exception:
                        pass
                channel_name = dir_path.name.replace("--", ":", 1)
                channels[channel_name] = count
                total_messages += count

        return {
            "total_messages": total_messages,
            "channels": channels,
            "channel_count": len(channels),
        }

    def cleanup(self, before: str) -> int:
        """

        Args:
            before: ISO

        Returns:

        """
        removed = 0
        if not self.base_dir.exists():
            return 0

        for file_path in self.base_dir.rglob("*.jsonl"):
            try:
                # {hostname}_{agent_id}_{timestamp}.jsonl
                #  timestamp
                stem = file_path.stem
                parts = stem.rsplit("_", 1)
                if len(parts) == 2:
                    ts = parts[1]
                    if ts < before:
                        file_path.unlink()
                        removed += 1
            except Exception:
                continue
        return removed

    #

    def _append(self, msg: ChannelMessage) -> None:
        """ JSONL """
        channel_dir = self.base_dir / _channel_dir(msg.channel)
        channel_dir.mkdir(parents=True, exist_ok=True)

        # {hostname}_{agent_id}_{date}.jsonl
        date = msg.timestamp[:10]
        hostname = socket.gethostname().replace(".", "-")
        safe_agent = "".join(
            c if c.isalnum() or c in "_-" else "-" for c in msg.from_agent
        )
        filename = f"{hostname}_{safe_agent}_{date}.jsonl"
        file_path = channel_dir / filename

        line = json.dumps(msg.to_dict(), ensure_ascii=False) + "\n"
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(line)
