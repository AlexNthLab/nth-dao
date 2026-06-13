"""commerce↔market 绑定校验（CS2a）—— 把 trade 锚定到真实市场证据。

CS1 的 ``verify_trade`` 证明"事件链内部自洽 + 签名真实 + 不可跳步"，但
**不**证明绑定的各方是真实市场参与者：攻击者把自己同时绑成
publisher/claimant/verifier/settler，也能造出一条 verify_trade 通过的
"已结算"假交易。

``verify_trade_binding`` 补上这一刀：交叉核对 trade 的 opened 事件 ↔
真实 ``announcement``（publisher 签）+ 真实 ``claim_record``（claimant
签的 ClaimReceipt）。全过 → 这个 trade 确实是"**真 publisher 发的活、
真 claimant 认领的**"，而不是某人自导自演。

完整可信 = verify_trade（链自洽）∧ verify_trade_binding（锚定真证据）。
两者各自独立，组合起来才是"这笔交易真实且合法"。

边界：binding 证明"绑定的 publisher 真签了这条公告、绑定的 claimant 真签
了这次认领"。它**不**证明 publisher ≠ claimant，也不证明任一方可信 ——
一个把自己同时当 publisher 和 claimant 的自导自演交易（自签公告 + 自认领）
能通过 binding。防自导自演 / Sybil 靠 M5 可解释信誉（counterparty
diversity 等）+ 消费方自定信任策略（publisher_trust_floor /
claimant_policy），而非 binding。信誉本就不是 Sybil-proof（设计如此，见
reputation.py），由消费方据可解释维度自行定夺。
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from nth_dao.execution_receipt import verify_receipt
from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.commerce.trade import EVENT_TRADE_OPENED

REJECT_NO_OPENED = "binding-no-opened-event"
REJECT_ANN_ID_MISMATCH = "binding-announcement-id-mismatch"
REJECT_ANN_SIG_INVALID = "binding-announcement-sig-invalid"
REJECT_PUBLISHER_MISMATCH = "binding-publisher-mismatch"
REJECT_CLAIM_RECEIPT_INVALID = "binding-claim-receipt-invalid"
REJECT_CLAIM_SIGNER_MISMATCH = "binding-claim-signer-mismatch"
REJECT_CLAIMANT_MISMATCH = "binding-claimant-mismatch"
REJECT_CLAIM_ANN_MISMATCH = "binding-claim-announcement-mismatch"
REJECT_CLAIM_RECEIPT_ID_MISMATCH = "binding-claim-receipt-id-mismatch"
REJECT_TERMS_REWARD_MISMATCH = "binding-terms-reward-mismatch"
REJECT_TERMS_ASSET_MISMATCH = "binding-terms-asset-mismatch"


def _claimed_payload(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """从 ClaimReceipt 取 nth.task_claimed 的 payload（取不到返回 {}）。"""
    timeline = receipt.get("timeline") if isinstance(receipt, dict) else None
    if not isinstance(timeline, list):
        return {}
    for entry in timeline:
        if isinstance(entry, dict) and entry.get("type") == "nth.task_claimed":
            p = entry.get("payload")
            if isinstance(p, dict):
                return p
    return {}


def verify_trade_binding(
    trade_events: List[Dict[str, Any]],
    *,
    announcement: TaskAnnouncement,
    claim_record: Dict[str, Any],
) -> Tuple[bool, str]:
    """证明一个 trade 锚定在真实、双方签名的市场证据上。

    Args:
        trade_events: TradeStore.get_events(trade_id) 的事件列表。
        announcement: 该交易对应的市场公告（将被 verify_announcement 验签）。
        claim_record: 市场 ClaimStore 里的认领记录（内含 claimant 签的
            ClaimReceipt，将被 verify_receipt 验签）。

    Returns:
        ``(ok, reason)``。全部交叉核对通过才 True：
          1. opened 事件存在。
          2. opened.announcement_id == announcement.announcement_id。
          3. announcement 自验签（真 publisher 发的）。
          4. opened.publisher_did == announcement.publisher_did。
          5. claim_record 的嵌入 ClaimReceipt 自验签。
          6. opened.claimant_did == ClaimReceipt.signer_did（真 claimant 签的）。
          7. ClaimReceipt 的 nth.task_claimed payload.announcement_id ==
             announcement.announcement_id（这次认领确实是认领这条公告）。
          8. opened.claim_receipt_id == claim_record.receipt_id。
    """
    if not trade_events:
        return False, REJECT_NO_OPENED
    opened = trade_events[0]
    if not isinstance(opened, dict) or opened.get("type") != EVENT_TRADE_OPENED:
        return False, REJECT_NO_OPENED
    op = opened.get("payload", {}) if isinstance(opened.get("payload"), dict) else {}

    ann_id = announcement.announcement_id

    # 2. opened ↔ announcement id 一致
    if str(op.get("announcement_id", "")) != ann_id:
        return False, REJECT_ANN_ID_MISMATCH

    # 3. announcement 自验签（真 publisher 发的）
    ok, _ = verify_announcement(announcement)
    if not ok:
        return False, REJECT_ANN_SIG_INVALID

    # 4. publisher 绑定一致
    if str(op.get("publisher_did", "")) != announcement.publisher_did:
        return False, REJECT_PUBLISHER_MISMATCH

    # 5. ClaimReceipt 自验签
    receipt = claim_record.get("receipt") if isinstance(claim_record, dict) else None
    if not isinstance(receipt, dict) or not verify_receipt(receipt):
        return False, REJECT_CLAIM_RECEIPT_INVALID

    # 6. claimant 是 ClaimReceipt 的真实签名者（受签名保护，不是可伪造的顶层字段）
    claim_signer = str(receipt.get("signer_did", ""))
    if str(op.get("claimant_did", "")) != claim_signer:
        return False, REJECT_CLAIMANT_MISMATCH

    # 7. 这次认领确实是认领这条公告（用签名 payload，不是顶层）
    claimed = _claimed_payload(receipt)
    if str(claimed.get("announcement_id", "")) != ann_id:
        return False, REJECT_CLAIM_ANN_MISMATCH
    if str(claimed.get("claimant_did", "")) != claim_signer:
        return False, REJECT_CLAIM_SIGNER_MISMATCH

    # 8. opened 指向的 claim_receipt_id 对得上
    if str(op.get("claim_receipt_id", "")) != str(claim_record.get("receipt_id", "")):
        return False, REJECT_CLAIM_RECEIPT_ID_MISMATCH

    # 9. CS4：若 trade 签了 terms（约定结算条款），必须等于公告承诺的
    #    reward。verify_trade 只能用 terms 核对 settlement，但 terms 是
    #    **开局方**（authority/publisher）签的 —— 若不回锚到 claimant 真正
    #    认领的那条公告 reward，恶意 publisher 可把 terms 压成 1（公告
    #    reward=1000），verify_trade 照样判合格、claimant 被白嫖。这一刀
    #    把 terms 钉死在签名公告的 reward 上，真正端到端闭合白嫖。
    terms = op.get("terms")
    if isinstance(terms, dict):
        t_amt = terms.get("amount_minor")
        if (isinstance(t_amt, bool) or not isinstance(t_amt, int)
                or t_amt != announcement.reward_minor):
            return False, REJECT_TERMS_REWARD_MISMATCH
        if str(terms.get("currency", "")) != str(announcement.reward_asset):
            return False, REJECT_TERMS_ASSET_MISMATCH

    return True, ""
