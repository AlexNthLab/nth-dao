"""Tests for v0.9.8 agent discovery enhancement - complements, seeking, accepting_tasks.

Includes positive, negative, and failure-path tests per NTH DAO merge standards.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from nth_dao.discovery.agent_registry import (
    AgentRecord,
    AgentRegistry,
    CLOCK_SKEW_TOLERANCE_SECONDS,
    FUTURE_STALE_SECONDS,
)
from nth_dao.discovery.peer_finder import PeerFinder


# -------------------------- Fixtures --------------------------


@pytest.fixture
def tmp_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def registry(tmp_workspace):
    reg = AgentRegistry(agents_dir=str(tmp_workspace / "agents"))
    yield reg


@pytest.fixture
def multi_agent_registry(tmp_workspace):
    """Registry with 5 agents for complement testing."""
    agents_dir = tmp_workspace / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    reg = AgentRegistry(agents_dir=str(agents_dir))

    # Alice: has python/web, seeks solidity
    r1 = AgentRegistry(agents_dir=str(agents_dir))
    r1.register("alice", capabilities=["python", "web"], seeking=["solidity"],
                start_heartbeat=False)
    # Bob: has solidity/audit, seeks python
    r2 = AgentRegistry(agents_dir=str(agents_dir))
    r2.register("bob", capabilities=["solidity", "audit"], seeking=["python"],
                start_heartbeat=False)
    # Carol: has python/web, no seeking, accepting tasks for code_review
    r3 = AgentRegistry(agents_dir=str(agents_dir))
    r3.register("carol", capabilities=["python", "web"], seeking=[],
                accepting_tasks=True, available_for=["code_review"],
                start_heartbeat=False)
    # Dave: has deploy, seeks nothing
    r4 = AgentRegistry(agents_dir=str(agents_dir))
    r4.register("dave", capabilities=["deploy"], seeking=[],
                start_heartbeat=False)
    # Eve: has solidity+audit, accepting tasks for audit only
    r5 = AgentRegistry(agents_dir=str(agents_dir))
    r5.register("eve", capabilities=["solidity", "audit"], seeking=[],
                accepting_tasks=True, available_for=["audit"],
                start_heartbeat=False)

    yield reg
    for r in [r1, r2, r3, r4, r5]:
        r.unregister()


# -------------------------- AgentRecord --------------------------


class TestAgentRecord:
    def test_new_fields_default(self):
        r = AgentRecord(agent_id="test", hostname="h", pid=1)
        assert r.seeking == []
        assert r.accepting_tasks is False
        assert r.available_for == []

    def test_seeking_set(self):
        r = AgentRecord(agent_id="alice", hostname="h", pid=1,
                        seeking=["solidity", "audit"])
        assert r.seeking == ["solidity", "audit"]

    def test_accepting_tasks_true(self):
        r = AgentRecord(agent_id="bob", hostname="h", pid=1,
                        accepting_tasks=True, available_for=["code_review"])
        assert r.accepting_tasks is True
        assert r.available_for == ["code_review"]

    def test_round_trip_new_fields(self):
        r = AgentRecord(agent_id="carol", hostname="h", pid=1,
                        capabilities=["python"], seeking=["rust"],
                        accepting_tasks=True, available_for=["deploy"])
        d = r.to_dict()
        r2 = AgentRecord.from_dict(d)
        assert r2.seeking == ["rust"]
        assert r2.accepting_tasks is True
        assert r2.available_for == ["deploy"]

    def test_short_shows_seeking(self):
        r = AgentRecord(agent_id="alice", hostname="h", pid=1,
                        capabilities=["py"], seeking=["solidity"])
        s = r.short()
        assert "seek=[solidity]" in s

    def test_short_shows_accepting(self):
        r = AgentRecord(agent_id="bob", hostname="h", pid=1,
                        accepting_tasks=True)
        s = r.short()
        assert "accept" in s

    # -- C1: from_dict ignores unknown fields --

    def test_from_dict_ignores_unknown_fields(self):
        data = {
            "agent_id": "test", "hostname": "h", "pid": 1,
            "typo_field": "should_be_dropped",
            "another_junk": 42,
        }
        r = AgentRecord.from_dict(data)
        assert r.agent_id == "test"


# -------------------------- is_alive / clock skew --------------------------


class TestIsAlive:
    def test_alive_when_recent(self):
        r = AgentRecord(agent_id="test", hostname="h", pid=1)
        assert r.is_alive(max_stale_seconds=9999) is True

    def test_not_alive_when_old(self):
        r = AgentRecord(agent_id="test", hostname="h", pid=1,
                        last_seen="2000-01-01T00:00:00")
        assert r.is_alive(max_stale_seconds=1) is False

    def test_clock_skew_tolerance_applied(self):
        """CRIT-2(2026-06-10)后:skew 缓冲只用于宽恕"未来"的小幅时钟漂移
        (远端时钟略快),不再用来加宽"过期"窗口。窗口为 [-SKEW, max_stale)。
        因此一个 20s 未来(在 30s skew 内)的心跳仍算存活。"""
        future = (datetime.now() + timedelta(seconds=20)).isoformat()
        r = AgentRecord(agent_id="test", hostname="h", pid=1, last_seen=future)
        # delta=-20:>= -SKEW(30) 且 < max_stale(90) -> 存活。
        assert r.is_alive(max_stale_seconds=90) is True

    def test_barely_stale_past_is_dead(self):
        """CRIT-2 后:95s 前的心跳 >= max_stale(90) -> 死。skew 不再加宽过期
        窗口(旧实现 max_stale+SKEW 会误判 95s 仍活,已修)。"""
        past = (datetime.now() - timedelta(seconds=95)).isoformat()
        r = AgentRecord(agent_id="test", hostname="h", pid=1, last_seen=past)
        assert r.is_alive(max_stale_seconds=90) is False

    def test_far_future_rejected_even_with_skew(self):
        """Timestamp 10 minutes in the future exceeds FUTURE_STALE_SECONDS,
        so is_alive returns False regardless of skew buffer."""
        future = (datetime.now() + timedelta(seconds=600)).isoformat()
        r = AgentRecord(agent_id="test", hostname="h", pid=1, last_seen=future)
        assert r.is_alive(max_stale_seconds=90) is False

    def test_future_beyond_skew_is_dead(self):
        """CRIT-2 后:未来漂移的容忍只有 CLOCK_SKEW_TOLERANCE_SECONDS(30s),
        一个 120s 未来的时间戳已超出 -> 视为死(时钟被篡改/严重漂移),与更
        宽松的 FUTURE_STALE_SECONDS 无关(后者对未来路径已是死代码)。"""
        future = (datetime.now() + timedelta(seconds=120)).isoformat()
        r = AgentRecord(agent_id="test", hostname="h", pid=1, last_seen=future)
        assert r.is_alive(max_stale_seconds=90) is False


# -------------------------- find_complements --------------------------


class TestFindComplements:
    def test_finds_complement(self, multi_agent_registry):
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("alice")
        assert len(results) >= 1
        bob = [m for m in results if m.record.agent_id == "bob"]
        assert len(bob) == 1
        assert "solidity" in bob[0].matched_capabilities

    def test_bidirectional_complement(self, multi_agent_registry):
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("bob")
        alice = [m for m in results if m.record.agent_id == "alice"]
        assert len(alice) == 1
        assert "python" in alice[0].matched_capabilities

    def test_no_complements_when_no_seeking(self, multi_agent_registry):
        finder = PeerFinder(multi_agent_registry)
        assert finder.find_complements("dave") == []

    def test_accepting_tasks_bonus(self, multi_agent_registry):
        """T1 fix: assert len >= 2 FIRST, then check bonus."""
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("alice")
        assert len(results) >= 2, f"expected >= 2 complements, got {len(results)}"
        bob_score = [m.score for m in results if m.record.agent_id == "bob"][0]
        assert bob_score >= 1.0

    def test_unknown_agent(self, multi_agent_registry):
        finder = PeerFinder(multi_agent_registry)
        assert finder.find_complements("nobody") == []

    # -- available_for is metadata only --

    def test_available_for_is_metadata_only(self, multi_agent_registry):
        """Eve has solidity, Alice seeks solidity -> match regardless of available_for."""
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("alice")
        eve = [m for m in results if m.record.agent_id == "eve"]
        assert len(eve) == 1

    def test_complement_match_ignores_available_for(self, multi_agent_registry):
        """Bob seeks python. Carol has python. available_for=['code_review'] irrelevant."""
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("bob")
        carol = [m for m in results if m.record.agent_id == "carol"]
        assert len(carol) == 1

    # -- M2: match_direction --

    def test_match_direction(self, multi_agent_registry):
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("alice")
        bob = [m for m in results if m.record.agent_id == "bob"][0]
        kind = bob.match_details
        assert "they_have" in kind
        assert "solidity" in kind["they_have"]
        assert "i_have" in kind
        assert "python" in kind["i_have"]

    # -- D4: direction parameter --

    def test_direction_incoming(self, multi_agent_registry):
        """Alice seeks solidity; Bob has solidity. incoming: who can help Alice."""
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("alice", direction="incoming")
        bob = [m for m in results if m.record.agent_id == "bob"]
        assert len(bob) == 1
        assert "solidity" in bob[0].matched_capabilities
        assert "python" not in bob[0].matched_capabilities

    def test_direction_outgoing(self, multi_agent_registry):
        """Alice seeks solidity; Bob has solidity. outgoing from Bob's POV:
        who can Bob help? Alice (she seeks what Bob has)."""
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("bob", direction="outgoing")
        alice = [m for m in results if m.record.agent_id == "alice"]
        assert len(alice) == 1
        assert "solidity" in alice[0].matched_capabilities

    def test_direction_bidirectional_covers_both(self, multi_agent_registry):
        finder = PeerFinder(multi_agent_registry)
        results = finder.find_complements("alice", direction="bidirectional")
        bob = [m for m in results if m.record.agent_id == "bob"][0]
        assert len(bob.matched_capabilities) >= 2

    def test_invalid_direction_raises_valueerror(self, multi_agent_registry):
        """Non-standard direction values must raise ValueError."""
        finder = PeerFinder(multi_agent_registry)
        with pytest.raises(ValueError, match="direction must be"):
            finder.find_complements("alice", direction="sideways")


# -------------------------- Registry --------------------------


class TestRegistryWithSeeking:
    def test_register_with_seeking(self, registry):
        registry.register("alice", capabilities=["python"],
                          seeking=["solidity"],
                          accepting_tasks=True,
                          available_for=["code_review"],
                          start_heartbeat=False)
        record = registry._record
        assert record is not None
        assert record.seeking == ["solidity"]
        assert record.accepting_tasks is True
        assert record.available_for == ["code_review"]

    def test_register_reentrant_safe(self, registry):
        """register() then register() again -- RLock prevents deadlock."""
        registry.register("agent1", start_heartbeat=False)
        registry.register("agent1", capabilities=["updated"],
                          start_heartbeat=False)
        assert registry._record is not None
        assert registry._record.capabilities == ["updated"]

    def test_update_status_under_lock(self, registry):
        """update_status() must not race with heartbeat (lock protects)."""
        registry.register("agent1", start_heartbeat=False)
        registry.update_status(status="busy", metadata_patch={"key": "val"})
        assert registry._record.status == "busy"
        assert registry._record.metadata["key"] == "val"

    def test_unregister_without_register(self, registry):
        """unregister() on a never-registered registry is a no-op."""
        registry.unregister()  # must not raise


# -------------------------- broadcast_order --------------------------


class TestBroadcastOrder:
    def test_broadcast_creates_order(self, tmp_workspace):
        from nth_dao.marketplace import TaskMarketplace
        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="test-agent",
            marketplace_dir="test_orders",
        )
        order = mkt.broadcast_order("review PR", reward=10)
        assert order.title == "review PR"
        assert order.reward == 10
        assert order.status.value == "open"

    def test_broadcast_without_finder_still_creates(self, tmp_workspace):
        from nth_dao.marketplace import TaskMarketplace
        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="test-agent",
            marketplace_dir="test_orders",
        )
        order = mkt.broadcast_order("review PR")
        assert order is not None

    # -- fanout path tests --

    def test_broadcast_dms_accepting_agents(self, tmp_workspace, multi_agent_registry):
        """When finder + channel are provided, DMs go to accepting_tasks agents."""
        from nth_dao.marketplace import TaskMarketplace
        finder = PeerFinder(multi_agent_registry)
        mock_channel = MagicMock()

        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="test-creator",
            channel=mock_channel, marketplace_dir="test_orders",
        )
        mkt.broadcast_order(
            "review PR", reward=10, capability="python",
            finder=finder, channel=mock_channel,
        )
        dm_recipients = {call[0][0] for call in mock_channel.dm.call_args_list}
        assert "carol" in dm_recipients  # python + accepting_tasks

    def test_broadcast_dm_includes_order_info(self, tmp_workspace, multi_agent_registry):
        """DM payload must include order ID, reward, and title."""
        from nth_dao.marketplace import TaskMarketplace
        finder = PeerFinder(multi_agent_registry)
        mock_channel = MagicMock()

        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="test-creator",
            channel=mock_channel, marketplace_dir="test_orders",
        )
        mkt.broadcast_order(
            "review PR", capability="solidity",
            finder=finder, channel=mock_channel,
        )
        if mock_channel.dm.call_args_list:
            body = mock_channel.dm.call_args_list[0][0][1]
            assert "ID:" in body
            assert "Reward:" in body
            assert "[New Task]" in body

    def test_broadcast_empty_targets_no_dm(self, tmp_workspace, multi_agent_registry):
        """When finder returns no agents, no DMs are sent."""
        from nth_dao.marketplace import TaskMarketplace
        finder = PeerFinder(multi_agent_registry)
        mock_channel = MagicMock()

        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="test-creator",
            channel=mock_channel, marketplace_dir="test_orders",
        )
        mkt.broadcast_order(
            "orphan task", capability="nonexistent",
            finder=finder, channel=mock_channel,
        )
        mock_channel.dm.assert_not_called()

    def test_broadcast_handles_dm_failure_gracefully(self, tmp_workspace, multi_agent_registry):
        """DM failures should not crash broadcast_order."""
        from nth_dao.marketplace import TaskMarketplace
        finder = PeerFinder(multi_agent_registry)
        mock_channel = MagicMock()
        mock_channel.dm.side_effect = RuntimeError("channel down")

        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="test-creator",
            channel=mock_channel, marketplace_dir="test_orders",
        )
        order = mkt.broadcast_order(
            "survives DM failure", capability="python",
            finder=finder, channel=mock_channel,
        )
        assert order is not None

    # -- self-DM prevention --

    def test_broadcast_never_dms_self(self, tmp_workspace):
        """broadcast_order must exclude self.agent_id from DM recipients."""
        from nth_dao.marketplace import TaskMarketplace

        # Create a registry where the broadcaster IS one of the agents
        agents_dir = tmp_workspace / "self_agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        reg = AgentRegistry(agents_dir=str(agents_dir))
        reg.register("me", capabilities=["python"], accepting_tasks=True,
                     start_heartbeat=False)
        reg.register("other", capabilities=["python"], accepting_tasks=True,
                     start_heartbeat=False)

        finder = PeerFinder(reg)
        mock_channel = MagicMock()

        mkt = TaskMarketplace(
            workspace=tmp_workspace, agent_id="me",
            channel=mock_channel, marketplace_dir="self_orders",
        )
        mkt.broadcast_order(
            "self test", capability="python",
            finder=finder, channel=mock_channel,
        )
        dm_recipients = {call[0][0] for call in mock_channel.dm.call_args_list}
        assert "me" not in dm_recipients, "must not DM self"
        assert "other" in dm_recipients
