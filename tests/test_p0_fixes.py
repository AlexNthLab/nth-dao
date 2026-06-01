"""P0/P1 修复回归测试。

覆盖：
    - Mission.try_claim 原子 CAS (C-3)
    - Mission FAILED 终态 (P0-6)
    - identity.load 校验 keypair 一致 (C-6)
    - membership token compare_digest (C-4) —— 已通过 test_membership 覆盖
    - reputation 速率限制 / upsert (H-8)
    - marketplace credits 双花防护 (H-11)
    - marketplace reject 通知正确 claimant (H-10)
    - channel.fetch 全局排序 + limit 正确 (H-7)
"""

import json
import time
from pathlib import Path

import pytest

import nth_dao as nth
from nth_dao.membership import TamperedTeamConfigError
from nth_dao.orchestration import Mission
from nth_dao.orchestration.mission_store import ClaimConflict, MissionStore
from nth_dao.identity import AgentIdentity, crypto_available


# ─────────────────── Mission 原子 claim ───────────────────


def _make_store_with_step(tmp_path: Path) -> tuple:
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(
        title="t", goal="g", owner="alice",
        steps=[{
            "id": "s1", "description": "do thing",
            "required_capabilities": ["python"],
        }],
    )
    store.create(m)
    return store, m


def test_try_claim_succeeds_when_step_open(tmp_path):
    store, m = _make_store_with_step(tmp_path)
    step = store.try_claim(m.id, "s1", agent_id="alice", capabilities=["python"])
    assert step is not None
    assert step.assignee == "alice"
    assert step.status == "active"


def test_try_claim_rejects_when_already_claimed(tmp_path):
    store, m = _make_store_with_step(tmp_path)
    store.try_claim(m.id, "s1", agent_id="alice", capabilities=["python"])
    with pytest.raises(ClaimConflict):
        store.try_claim(m.id, "s1", agent_id="bob", capabilities=["python"])


def test_try_claim_rejects_when_capabilities_insufficient(tmp_path):
    store, m = _make_store_with_step(tmp_path)
    with pytest.raises(ClaimConflict, match="requires"):
        store.try_claim(m.id, "s1", agent_id="bob", capabilities=["ruby"])


def test_handoff_only_to_specific_agent(tmp_path):
    store, m = _make_store_with_step(tmp_path)
    store.try_claim(m.id, "s1", agent_id="alice", capabilities=["python"])
    store.update_step(m.id, "s1", status="handed_off", assignee="bob")
    # carol 不应该能 claim 这个 handed_off 给 bob 的 step
    with pytest.raises(ClaimConflict):
        store.try_claim(m.id, "s1", agent_id="carol", capabilities=["python"])
    # bob 可以
    step = store.try_claim(m.id, "s1", agent_id="bob", capabilities=["python"])
    assert step.assignee == "bob"


def test_previous_assignees_pushed_once_per_transition(tmp_path):
    store, m = _make_store_with_step(tmp_path)
    store.try_claim(m.id, "s1", agent_id="alice", capabilities=["python"])
    # alice → bob in one update (status + assignee)
    store.update_step(m.id, "s1", status="handed_off", assignee="bob")
    m2 = store.get(m.id)
    step = m2.get_step("s1")
    # 在 bug 修复前，alice 会被 append 两次
    assert step.previous_assignees.count("alice") == 1


# ─────────────────── Mission FAILED 终态 ───────────────────


def test_mission_transitions_to_failed_when_step_fails_and_no_others(tmp_path):
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(
        title="t", goal="g", owner="alice",
        steps=[{"id": "only", "description": "x"}],
    )
    store.create(m)
    store.update_step(m.id, "only", status="failed", note="boom")
    m2 = store.get(m.id)
    assert m2.status == "failed"
    assert m2.completed_at


def test_mission_stays_active_if_other_steps_actionable(tmp_path):
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(
        title="t", goal="g", owner="alice",
        steps=[
            {"id": "a", "description": "x"},
            {"id": "b", "description": "y"},
        ],
    )
    store.create(m)
    store.update_step(m.id, "a", status="failed")
    m2 = store.get(m.id)
    # b 还能做 → mission 仍 active，不是 failed
    assert m2.status != "failed"


# ─────────────────── Identity keypair tampering ───────────────────


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl not installed")
def test_identity_load_rejects_tampered_pubkey(tmp_path):
    """换 pubkey 但保留 private_key → 必须拒绝。"""
    ident = AgentIdentity.generate(label="alice")
    path = tmp_path / "id.json"
    ident.save(path)

    data = json.loads(path.read_text())
    # 把 pubkey 替换成另一对密钥的 pubkey
    other = AgentIdentity.generate(label="evil")
    data["pubkey"] = other.pubkey_hex
    path.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="keypair mismatch"):
        AgentIdentity.load(path)


# ─────────────────── Reputation 去重 + 速率限制 ───────────────────


def test_reputation_rate_self_rejected(tmp_path):
    rep = nth.ReputationManager(tmp_path, agent_id="alice")
    with pytest.raises(ValueError, match="cannot rate yourself"):
        rep.rate("alice", context="chat", score=5.0)


def test_reputation_rate_score_range_validated(tmp_path):
    rep = nth.ReputationManager(tmp_path, agent_id="alice")
    with pytest.raises(ValueError, match="score must be in"):
        rep.rate("bob", context="chat", score=6.0)


def test_reputation_upsert_replaces_not_appends(tmp_path):
    rep = nth.ReputationManager(tmp_path, agent_id="alice")
    rep.rate("bob", context="chat", score=3.0, upsert=True)
    rep.rate("bob", context="chat", score=4.5, upsert=True)
    # 自己文件里同一 triple 只剩一条
    triples = rep._my_entries_for_triple("bob", "chat")
    assert len(triples) == 1
    assert triples[0].score == 4.5


def test_reputation_anti_sybil_credits_run_out(tmp_path):
    """P2 anti-Sybil: rater 用光 credit 后必须 raise，无法继续刷新评分。"""
    from nth_dao.reputation import INITIAL_RATING_CREDITS
    rep = nth.ReputationManager(tmp_path, agent_id="alice")
    assert rep.credits() == INITIAL_RATING_CREDITS
    # 用 upsert=False 强制新增；每次扣 1
    for i in range(INITIAL_RATING_CREDITS):
        # 同一 triple 在 rate-limit 内不能 non-upsert，所以每次换 subject
        rep.rate(f"bob{i}", context="chat", score=3.0, upsert=False)
    assert rep.credits() == 0
    with pytest.raises(PermissionError, match="out of rating credits"):
        rep.rate("carol", context="chat", score=3.0, upsert=False)


def test_reputation_upsert_does_not_consume_credit(tmp_path):
    """Upsert 替换不消耗 credit（避免双重惩罚）。"""
    rep = nth.ReputationManager(tmp_path, agent_id="alice")
    rep.rate("bob", context="chat", score=3.0, upsert=True)
    before = rep.credits()
    rep.rate("bob", context="chat", score=4.0, upsert=True)
    assert rep.credits() == before


def test_reputation_non_upsert_rate_limited(tmp_path):
    rep = nth.ReputationManager(tmp_path, agent_id="alice")
    rep.rate("bob", context="chat", score=3.0, upsert=False)
    with pytest.raises(PermissionError, match="rate limited"):
        rep.rate("bob", context="chat", score=2.0, upsert=False)


# ─────────────────── Marketplace 双花防护 + reject 通知 ───────────────────


def test_marketplace_credits_no_double_spend(tmp_path):
    mk = nth.TaskMarketplace(tmp_path, agent_id="alice")
    initial = mk.balance
    # 创建 reward=80 的订单 → 余额 = initial - 80
    o1 = mk.create_order("t1", reward=80)
    assert mk.balance == initial - 80
    # 再创建 reward=30 → 应该失败（initial=100, 已扣 80, 剩 20 < 30）
    with pytest.raises(ValueError, match="Insufficient credits"):
        mk.create_order("t2", reward=30)
    # 余额不变
    assert mk.balance == initial - 80


def test_marketplace_cancel_refunds_credits(tmp_path):
    mk = nth.TaskMarketplace(tmp_path, agent_id="alice")
    initial = mk.balance
    o = mk.create_order("t", reward=20)
    assert mk.balance == initial - 20
    mk.cancel(o.order_id)
    assert mk.balance == initial


def test_marketplace_credit_ledger_records_transactions(tmp_path):
    mk = nth.TaskMarketplace(tmp_path, agent_id="alice")
    o = mk.create_order("t", reward=15)
    mk.cancel(o.order_id)
    ledger = tmp_path / "team_marketplace" / "alice_credits.ledger.jsonl"
    assert ledger.exists()
    lines = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    kinds = [e.get("kind") for e in lines]
    assert "escrow_lock" in kinds
    assert "escrow_refund_cancel" in kinds


def test_marketplace_reject_records_original_claimant(tmp_path):
    """reject 之前的 hasattr bug 会把通知发到 'unknown'；现在 timeline 必须含 rejected_claimant。"""
    creator = nth.TaskMarketplace(tmp_path, agent_id="creator")
    o = creator.create_order("t", reward=0)
    # 用第二个 marketplace 实例模拟 claimant
    claimer = nth.TaskMarketplace(tmp_path, agent_id="claimer")
    claimer.claim(o.order_id)
    claimer.submit(o.order_id, proof="done")
    rejected = creator.reject(o.order_id, reason="bad work")
    last = rejected.timeline[-1]
    assert last["action"] == "rejected"
    assert last["rejected_claimant"] == "claimer"


# ─────────────────── Channel.fetch 全局排序 ───────────────────


def test_peer_finder_min_match_excludes_zero_cap_matches(tmp_path):
    """H-6: 需要 ["python","web","db"]，没有任何 cap 匹中的 agent 不应入选。"""
    reg = nth.AgentRegistry(agents_dir=str(tmp_path / "agents"))
    # 模拟两条 record：alice 匹中 1 个、bob 完全不匹但 idle
    reg.register(
        agent_id="alice", backend_id="mock",
        capabilities=["python"], start_heartbeat=False,
    )
    reg._record = None  # 重置以注册第二个
    reg._atexit_registered = True  # 避免重复 atexit
    reg.register(
        agent_id="bob", backend_id="mock",
        capabilities=["ruby"], start_heartbeat=False,
    )
    finder = nth.PeerFinder(reg)
    # 默认 min_match=1 → bob (0 个匹中) 不应出现
    results = finder.rank(needed_capabilities=["python", "web", "db"])
    ids = [r.record.agent_id for r in results]
    assert "alice" in ids
    assert "bob" not in ids


def test_mission_runner_handoff_refuses_dead_target(tmp_path):
    """M-10: handoff 到一个 registry 里不存在的 agent → 拒绝。"""
    from nth_dao.orchestration import Mission
    from nth_dao.orchestration.mission_store import MissionStore
    from nth_dao.orchestration.mission_runner import MissionRunner

    store = MissionStore(str(tmp_path / "missions"))
    reg = nth.AgentRegistry(agents_dir=str(tmp_path / "agents"))
    # 不注册任何 agent
    m = Mission.new(
        title="t", goal="g", owner="alice",
        steps=[{"id": "s", "description": "x"}],
    )
    store.create(m)
    store.try_claim(m.id, "s", agent_id="alice", capabilities=[])

    runner = MissionRunner(
        store=store, agent_id="alice", capabilities=[], registry=reg,
    )
    outcome = runner.handoff(m.id, "s", to_agent_id="ghost")
    assert not outcome.success
    assert "not registered" in outcome.note


def test_membership_signed_config_round_trip(tmp_path):
    """P3: 用 owner_identity 签名的 team.json 可正常加载。"""
    if not crypto_available():
        pytest.skip("PyNaCl not installed")
    owner = AgentIdentity.generate(label="owner")
    mm = nth.MembershipManager(tmp_path, owner_identity=owner)
    cfg = mm.init_team(team_name="signed-team", admin_ids=["alice"])
    # 文件里应该有 owner_pubkey + owner_sig
    on_disk = json.loads((tmp_path / "team.json").read_text(encoding="utf-8"))
    assert on_disk["owner_pubkey"] == owner.pubkey_hex
    assert on_disk["owner_sig"]
    # 再 load 一次必须通过验签
    reloaded = mm.load_config()
    assert reloaded.team_name == "signed-team"
    assert reloaded.owner_pubkey == owner.pubkey_hex


def test_membership_tampered_signed_config_rejected(tmp_path):
    """P3: 篡改 team.json 字段（如 admin_ids）必须导致 load_config 返回空配置。"""
    if not crypto_available():
        pytest.skip("PyNaCl not installed")
    owner = AgentIdentity.generate(label="owner")
    mm = nth.MembershipManager(tmp_path, owner_identity=owner)
    mm.init_team(team_name="signed-team", admin_ids=["alice"])

    # 攻击者篡改：把自己加入 admin_ids（模拟 git_sync 投毒）
    path = tmp_path / "team.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["admin_ids"].append("evil")
    path.write_text(json.dumps(data), encoding="utf-8")

    # 任何 reader（甚至不持私钥的）load_config 应该看到空 cfg —— 拒绝 tamper
    reader = nth.MembershipManager(tmp_path)
    with pytest.raises(TamperedTeamConfigError):
        reader.load_config()


def test_membership_tampered_signed_config_cannot_rebootstrap_admin(tmp_path):
    """Invalid owner signature must not become a fresh unsigned team."""
    if not crypto_available():
        pytest.skip("PyNaCl not installed")
    owner = AgentIdentity.generate(label="owner")
    mm = nth.MembershipManager(tmp_path, owner_identity=owner)
    mm.init_team(team_name="signed-team", admin_ids=["owner"])

    path = tmp_path / "team.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["admin_ids"].append("evil")
    path.write_text(json.dumps(data), encoding="utf-8")

    attacker = nth.MembershipManager(tmp_path)
    with pytest.raises(TamperedTeamConfigError):
        attacker.add_admin("evil", actor_id="evil")

    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["owner_pubkey"] == owner.pubkey_hex
    assert after["admin_ids"].count("evil") == 1


def test_membership_unsigned_config_still_loads(tmp_path):
    """P3: 已有未签名 team.json（升级前）继续工作（向后兼容）。"""
    mm = nth.MembershipManager(tmp_path)  # 无 owner_identity
    mm.init_team(team_name="legacy", admin_ids=["alice"])
    reloaded = mm.load_config()
    assert reloaded.team_name == "legacy"
    assert reloaded.admin_ids == ["alice"]
    assert reloaded.owner_pubkey == ""  # 未签名


def test_reputation_credits_scoped_by_pubkey(tmp_path):
    """P3: 同 pubkey 的不同 agent_id 共享 credit 池，无法 5×agent_id sybil。"""
    if not crypto_available():
        pytest.skip("PyNaCl not installed")
    shared_id = AgentIdentity.generate(label="shared")
    # 两个 agent_id 但用 *同一* identity 实例 → credit 文件名按 pubkey fingerprint
    rep_a = nth.ReputationManager(tmp_path, agent_id="alice", identity=shared_id)
    rep_b = nth.ReputationManager(tmp_path, agent_id="bob", identity=shared_id)
    # 同一 pubkey 应该指向同一个 credit 文件
    assert rep_a._credit_file == rep_b._credit_file
    # alice rate 一次 (subject 必须不是自己也不是 bob 同 identity？其实只看 agent_id)
    rep_a.rate("carol", context="chat", score=3.0, upsert=False)
    assert rep_a.credits() == 4
    assert rep_b.credits() == 4  # 同步扣减


def test_reputation_credits_isolated_by_pubkey(tmp_path):
    """P3: 不同 pubkey 的 identity → 不同 credit 池（合法多 agent 不被互相影响）。"""
    if not crypto_available():
        pytest.skip("PyNaCl not installed")
    id1 = AgentIdentity.generate(label="alice")
    id2 = AgentIdentity.generate(label="bob")
    rep1 = nth.ReputationManager(tmp_path, agent_id="alice", identity=id1)
    rep2 = nth.ReputationManager(tmp_path, agent_id="bob", identity=id2)
    rep1.rate("zzz", context="chat", score=3.0, upsert=False)
    assert rep1.credits() == 4
    assert rep2.credits() == 5  # 独立


def test_channel_fetch_global_sort_and_limit(tmp_path):
    a = nth.TeamChannel(tmp_path, agent_id="alice")
    b = nth.TeamChannel(tmp_path, agent_id="bob")
    # 交替发，每条相隔一点点
    for i in range(5):
        a.send(f"alice {i}", scope="team")
        time.sleep(0.01)
        b.send(f"bob {i}", scope="team")
        time.sleep(0.01)
    msgs = a.fetch(channel="team", limit=4)
    assert len(msgs) == 4
    # 全局 timestamp 单调递增
    ts = [m.timestamp for m in msgs]
    assert ts == sorted(ts)
    # 最后一条应是最新发的 bob 4
    assert msgs[-1].content == "bob 4"
