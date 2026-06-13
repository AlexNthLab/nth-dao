"""CS2 测试 —— commerce↔market 绑定校验 + DeterministicTestVerifier。

CS2a 退出门槛：verify_trade_binding 证明 trade 锚定真实市场证据；
  自导自演的假交易（自绑全角色）被识破。
CS2b 退出门槛：DeterministicTestVerifier 对 nth.test-execution.v1 确定性
  验收 —— commit/command/exit 全对 → pass；任一不对 → fail。
端到端：市场 claim → open_trade → worker 交付带 execution receipt →
  DeterministicTestVerifier 算 verdict → record_verification → settle。
"""

from __future__ import annotations

import pytest

from nth_dao.cap_token import sign_cap_token, CAP_NTH_RECEIPT_SIGN
from nth_dao.identity import AgentIdentity
from nth_dao.market import (
    MarketFeed, ClaimStore, claim_announcement, sign_announcement,
)
from nth_dao.commerce import (
    TradeStore, open_trade, submit_delivery, record_verification,
    record_settlement, trade_state, verify_trade, verify_trade_binding,
    DeterministicTestVerifier, sign_test_execution_receipt,
    VERDICT_PASS, VERDICT_FAIL, STATE_SETTLED, STATE_FAILED,
)
from nth_dao.commerce.binding import (
    REJECT_CLAIMANT_MISMATCH, REJECT_PUBLISHER_MISMATCH, REJECT_ANN_ID_MISMATCH,
)

pytest.importorskip("nacl")


def _token(issuer, claimant, caps=("test_execution", CAP_NTH_RECEIPT_SIGN)):
    return sign_cap_token(issuer=issuer, subject_did=claimant.as_did(),
                          capabilities=list(caps))


def _setup_claim(tmp_path, *, commit="a" * 40, command="pytest -q"):
    """造一条真实市场链：公告（带 SKU input_schema）→ 认领。返回各方 + 记录。"""
    feed = MarketFeed(tmp_path)
    store = ClaimStore(tmp_path)
    issuer = AgentIdentity.generate(label="issuer")
    publisher = AgentIdentity.generate(label="publisher")
    worker = AgentIdentity.generate(label="worker")
    ann = sign_announcement(
        publisher=publisher, title="run tests on commit",
        capability_set=["test_execution"], reward_minor=10,
        input_schema={"repository_url": "https://x/r", "commit": commit,
                      "commands": [command]},
        acceptance={"accept_exit_codes": [0]},
    )
    feed.publish(ann)
    out = claim_announcement(feed, store, ann.announcement_id, claimant=worker,
                             cap_token=_token(issuer, worker))
    return {
        "feed": feed, "store": store, "publisher": publisher, "worker": worker,
        "ann": ann, "claim_record": out.claim_record, "commit": commit,
        "command": command,
    }


# ─── CS2a：绑定校验 ─────────────────────────────────────────────


def test_binding_passes_for_real_trade(tmp_path) -> None:
    s = _setup_claim(tmp_path)
    tstore = TradeStore(tmp_path)
    authority = AgentIdentity.generate(label="dao")
    open_trade(tstore, authority=authority, claim_record=s["claim_record"])
    events = tstore.get_events(s["ann"].announcement_id)
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert ok, reason


def test_binding_catches_self_dealt_fake_trade(tmp_path) -> None:
    """攻击者自绑全角色造一条 verify_trade 通过的假交易 → 绑定校验识破
    （claim_record 的 ClaimReceipt 不是 attacker 签的 / 公告不是真 publisher）。"""
    # 真实链
    s = _setup_claim(tmp_path)
    tstore = TradeStore(tmp_path)
    # 攻击者把自己当 authority 开 trade，但 claimant 绑成自己（≠ 真 ClaimReceipt 签名者）
    attacker = AgentIdentity.generate(label="attacker")
    fake_claim = {
        "announcement_id": s["ann"].announcement_id,
        "claimant_did": attacker.as_did(),       # 谎称自己认领
        "publisher_did": s["publisher"].as_did(),
        "receipt_id": s["claim_record"]["receipt_id"],
    }
    open_trade(tstore, authority=attacker, claim_record=fake_claim)
    events = tstore.get_events(s["ann"].announcement_id)
    # verify_trade（链自洽）会过，但 binding 用真 claim_record（worker 签的 receipt）核对
    ok, reason = verify_trade_binding(events, announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert not ok
    assert reason == REJECT_CLAIMANT_MISMATCH   # opened.claimant ≠ ClaimReceipt 签名者


def test_binding_catches_wrong_announcement(tmp_path) -> None:
    s = _setup_claim(tmp_path)
    tstore = TradeStore(tmp_path)
    authority = AgentIdentity.generate(label="dao")
    open_trade(tstore, authority=authority, claim_record=s["claim_record"])
    events = tstore.get_events(s["ann"].announcement_id)
    # 拿另一条公告来核对 → id 不匹配
    other = sign_announcement(publisher=s["publisher"], title="other",
                              capability_set=["test_execution"], reward_minor=1)
    ok, reason = verify_trade_binding(events, announcement=other,
                                      claim_record=s["claim_record"])
    assert not ok
    assert reason == REJECT_ANN_ID_MISMATCH


# ─── CS2b：DeterministicTestVerifier ────────────────────────────


def test_verifier_pass_when_all_match(tmp_path) -> None:
    s = _setup_claim(tmp_path)
    receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit=s["commit"],
        command=s["command"], exit_code=0,
        announcement_id=s["ann"].announcement_id,
    )
    v = DeterministicTestVerifier()
    out = v.verify(announcement=s["ann"], execution_receipt=receipt,
                   expected_signer_did=s["worker"].as_did())
    assert out.passed, out.reason
    assert all(out.checks.values())


def test_verifier_fail_on_wrong_commit(tmp_path) -> None:
    s = _setup_claim(tmp_path, commit="a" * 40)
    receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit="b" * 40,  # 错 commit
        command=s["command"], exit_code=0,
        announcement_id=s["ann"].announcement_id)
    out = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=receipt,
        expected_signer_did=s["worker"].as_did())
    assert out.verdict == VERDICT_FAIL
    assert out.reason == "commit-mismatch"


def test_verifier_fail_on_nonzero_exit(tmp_path) -> None:
    s = _setup_claim(tmp_path)
    receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit=s["commit"],
        command=s["command"], exit_code=1,
        announcement_id=s["ann"].announcement_id)   # 测试失败
    out = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=receipt,
        expected_signer_did=s["worker"].as_did())
    assert out.verdict == VERDICT_FAIL
    assert out.reason == "exit-code-not-accepted"


def test_verifier_fail_on_disallowed_command(tmp_path) -> None:
    s = _setup_claim(tmp_path, command="pytest -q")
    receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit=s["commit"],
        command="rm -rf /", exit_code=0,
        announcement_id=s["ann"].announcement_id)   # 不在允许命令列表
    out = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=receipt,
        expected_signer_did=s["worker"].as_did())
    assert out.verdict == VERDICT_FAIL
    assert out.reason == "command-mismatch"


def test_verifier_rejects_receipt_reuse_across_announcements(tmp_path) -> None:
    """独立审查回归 (CS2 R1)：work-once-claim-many。worker 跑一次活、签
    一张绑 ann1 的 receipt，复用到同 commit+command 的 ann2 → 必须被拒。
    否则一次活收 N 份钱。"""
    s = _setup_claim(tmp_path)
    ann1 = s["ann"]
    # 同 commit+command 的另一条公告
    ann2 = sign_announcement(
        publisher=s["publisher"], title="job2", capability_set=["test_execution"],
        reward_minor=10, input_schema={"repository_url": "https://x/r",
        "commit": s["commit"], "commands": [s["command"]]},
        acceptance={"accept_exit_codes": [0]})
    # receipt 绑 ann1
    receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit=s["commit"],
        command=s["command"], exit_code=0, announcement_id=ann1.announcement_id)
    v = DeterministicTestVerifier()
    assert v.verify(announcement=ann1, execution_receipt=receipt,
                    expected_signer_did=s["worker"].as_did()).passed   # 本主 ok
    out2 = v.verify(announcement=ann2, execution_receipt=receipt,
                    expected_signer_did=s["worker"].as_did())          # 复用拒
    assert out2.verdict == VERDICT_FAIL
    assert out2.reason == "announcement-id-mismatch"


def test_verifier_fail_on_wrong_signer(tmp_path) -> None:
    s = _setup_claim(tmp_path)
    impostor = AgentIdentity.generate(label="impostor")
    receipt = sign_test_execution_receipt(
        impostor, repository_url="https://x/r", commit=s["commit"],
        command=s["command"], exit_code=0)   # 别人签的 receipt
    out = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=receipt,
        expected_signer_did=s["worker"].as_did())
    assert out.verdict == VERDICT_FAIL
    assert out.reason == "signer-mismatch"


# ─── 端到端：市场 → trade → 确定性验收 → 结算 ──────────────────


def test_end_to_end_market_to_settled(tmp_path) -> None:
    """完整闭环：claim → open_trade → 交付(带 execution receipt) →
    DeterministicTestVerifier 算 verdict → record_verification → settle。
    并且 verify_trade（链）+ verify_trade_binding（锚定）双双通过。"""
    s = _setup_claim(tmp_path)
    ann_id = s["ann"].announcement_id
    tstore = TradeStore(tmp_path)
    authority = AgentIdentity.generate(label="dao")
    verifier_ident = AgentIdentity.generate(label="verifier")

    # 开 trade（verifier = 一个独立验收方；settler = publisher）
    open_trade(tstore, authority=authority, claim_record=s["claim_record"],
               verifier_did=verifier_ident.as_did(),
               settler_did=s["publisher"].as_did())

    # worker 跑测试、签 execution receipt、提交交付
    exec_receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit=s["commit"],
        command=s["command"], exit_code=0, announcement_id=ann_id)
    submit_delivery(tstore, ann_id, claimant=s["worker"],
                    delivery={"execution_receipt": exec_receipt})

    # 验收方跑确定性验收器
    outcome = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=exec_receipt,
        expected_signer_did=s["worker"].as_did())
    assert outcome.passed
    # 把 verdict 喂状态机
    record_verification(tstore, ann_id, verifier=verifier_ident,
                        verdict=outcome.verdict, result=outcome.checks)
    # 结算
    record_settlement(tstore, ann_id, settler=s["publisher"],
                      settlement={"adapter_id": "manual", "amount_minor": 10})

    assert trade_state(tstore, ann_id) == STATE_SETTLED
    # 链自洽
    assert verify_trade(tstore, ann_id)[0]
    # 锚定真实市场证据
    ok, reason = verify_trade_binding(tstore.get_events(ann_id),
                                      announcement=s["ann"],
                                      claim_record=s["claim_record"])
    assert ok, reason


def test_end_to_end_failing_tests_no_settlement(tmp_path) -> None:
    """测试不过（exit_code=1）→ verdict=fail → 状态 FAILED → 不能结算。"""
    s = _setup_claim(tmp_path)
    ann_id = s["ann"].announcement_id
    tstore = TradeStore(tmp_path)
    authority = AgentIdentity.generate(label="dao")
    open_trade(tstore, authority=authority, claim_record=s["claim_record"])
    exec_receipt = sign_test_execution_receipt(
        s["worker"], repository_url="https://x/r", commit=s["commit"],
        command=s["command"], exit_code=1, announcement_id=ann_id)
    submit_delivery(tstore, ann_id, claimant=s["worker"],
                    delivery={"execution_receipt": exec_receipt})
    outcome = DeterministicTestVerifier().verify(
        announcement=s["ann"], execution_receipt=exec_receipt,
        expected_signer_did=s["worker"].as_did())
    assert outcome.verdict == VERDICT_FAIL
    # 默认 verifier = publisher（_setup 公告的 publisher）
    record_verification(tstore, ann_id, verifier=s["publisher"],
                        verdict=outcome.verdict, result=outcome.checks)
    assert trade_state(tstore, ann_id) == STATE_FAILED
