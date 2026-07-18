"""Commerce 状态机（CS1）—— 从市场认领闭合到结算的"后半环"。

主动市场止于 ``claimed``（谁来干）。commerce 接手 ``执行 → 交付 →
验收 → 结算``（干得怎样、钱怎么付）。CS1 是这个状态机的内核：一条
**append-only、逐事件签名**的 Trade 事件日志，状态由事件折叠得出，
转移由固定转移表（前置状态 + 执行者角色）守卫。

为什么这样建（中out）：
  - 中：``Trade`` = 签名事件链 + 转移表。和 receipt/feed 同构（追加、
    签名、可独立验证）。
  - 上：闭合 claim→settle，并补全 M5 信誉里留空的 completion/dispute
    维度（那些维度需要交付/验收数据）。
  - 下：TradeStore（一交易一文件，CAS）+ 4 个转移函数 + verify_trade。

状态（CS1）：
    EXECUTING ──deliver──► DELIVERED ──verify(pass)──► VERIFIED ──settle──► SETTLED
                                     └──verify(fail)──► FAILED（终态）
  DISPUTED / REFUNDED / 部分结算留给 CS3；x402 真钱结算留给 CS4。CS1
  无真钱（settlement 是签名的 manual 记录）。

转移守卫（每条都强制）：
  - 前置状态正确（只能从合法的上一态转）。
  - 执行者角色正确（交付必须 claimant 签、验收必须 verifier 签、
    结算必须 settler 签 —— 角色在 open 时绑定）。
  - 单调 seq（并发转移经文件锁，只有一个能推进同一 seq）。
  - 每个事件 actor 签名，可独立验签。

与市场的接缝：``open_trade`` 吃一条市场 claim_record（M3），把
claimant/publisher 从中取出并绑定。一笔认领 → 一个 trade
（trade_id = announcement_id）。
"""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.util.io import (
    InterProcessLock, atomic_write_json, safe_id, safe_load_json,
)

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

logger = logging.getLogger("nth_dao.commerce.trade")

PathLike = Union[str, Path]

NTH_TRADE_EVENT_KIND = "nth-trade-event-v1"
_MAX_TRADE_PAYLOAD_BYTES = 256 * 1024
_MAX_TRADE_CHAIN_BYTES = 320 * 1024
_TRADE_EVENT_FIELDS = frozenset({
    "trade_id", "seq", "type", "actor_did", "prev_state", "new_state",
    "payload", "created_at_ms", "kind", "event_sig",
})

# ── 状态 ──
STATE_EXECUTING = "executing"
STATE_DELIVERED = "delivered"
STATE_VERIFIED = "verified"
STATE_FAILED = "failed"
STATE_SETTLED = "settled"
# CS3 争议处理
STATE_DISPUTED = "disputed"
STATE_REFUNDED = "refunded"
STATE_SPLIT_SETTLED = "split_settled"
# 终态：已结清的三种结局。FAILED 不算终态 —— claimant 可对错误的 fail
# 提争议（见 _LEGAL_PRIOR）；未提争议时 FAILED 自然停在那（半终态）。
TERMINAL_STATES = frozenset({STATE_SETTLED, STATE_REFUNDED, STATE_SPLIT_SETTLED})

# ── 事件类型 ──
EVENT_TRADE_OPENED = "trade_opened"
EVENT_DELIVERY_SUBMITTED = "delivery_submitted"
EVENT_VERIFICATION_RECORDED = "verification_recorded"
EVENT_SETTLEMENT_RECORDED = "settlement_recorded"
# CS3
EVENT_DISPUTE_OPENED = "dispute_opened"
EVENT_DISPUTE_RESOLVED = "dispute_resolved"

# ── 验收结论 ──
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"

# ── 争议裁决（CS3）──
RESOLUTION_SETTLE = "settle"    # claimant 胜，全额结算 → SETTLED
RESOLUTION_REFUND = "refund"    # publisher 胜，退款 → REFUNDED
RESOLUTION_SPLIT = "split"      # 各打五十大板，部分结算 → SPLIT_SETTLED

# ── reject reasons ──
REJECT_TRADE_NOT_FOUND = "trade-not-found"
REJECT_TRADE_EXISTS = "trade-already-exists"
REJECT_ILLEGAL_TRANSITION = "illegal-transition"
REJECT_WRONG_ACTOR = "wrong-actor"
REJECT_BAD_VERDICT = "bad-verdict"
REJECT_BAD_RESOLUTION = "bad-resolution"
REJECT_EVENT_SIG_INVALID = "event-sig-invalid"
REJECT_EVENT_BAD_ACTOR_DID = "event-bad-actor-did"
REJECT_CHAIN_BROKEN = "chain-broken"
REJECT_CRYPTO_UNAVAILABLE = "crypto-unavailable"
REJECT_PAYLOAD_INVALID = "payload-invalid"


class TradeRejected(Exception):
    """转移因前置/角色/输入问题被拒（带 machine-readable reason）。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class TradeConflict(Exception):
    """并发转移的败者（seq 已被别人推进）。"""


# ─── 事件 ───────────────────────────────────────────────────────


@dataclass
class TradeEvent:
    trade_id: str
    seq: int
    type: str
    actor_did: str
    prev_state: str         # 转移前状态（"" 表示开局事件）
    new_state: str          # 转移后状态
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at_ms: int = 0
    kind: str = NTH_TRADE_EVENT_KIND
    event_sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TradeEvent":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def signing_body(self) -> Dict[str, Any]:
        return {k: v for k, v in self.to_dict().items() if k != "event_sig"}


def sign_trade_event(actor: "Any", event: TradeEvent) -> TradeEvent:
    """用 actor 身份签一个事件（in place 填 event_sig 并返回）。"""
    sig = actor.sign(canonical_json(event.signing_body()))
    event.event_sig = b64u_encode(sig)
    return event


def verify_trade_event(event: TradeEvent) -> Tuple[bool, str]:
    """验单个事件的 actor 签名。fail-closed。"""
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, REJECT_CRYPTO_UNAVAILABLE
    did = event.actor_did
    if not isinstance(did, str) or not is_did_key(did):
        return False, REJECT_EVENT_BAD_ACTOR_DID
    hexk = decode_ed25519_did_key_hex(did) or ""
    if not hexk:
        return False, REJECT_EVENT_BAD_ACTOR_DID
    if not isinstance(event.event_sig, str) or not (
        1 <= len(event.event_sig) <= 128
    ):
        return False, REJECT_EVENT_SIG_INVALID
    try:
        sig = b64u_decode(str(event.event_sig))
        if len(sig) != 64 or b64u_encode(sig) != event.event_sig:
            return False, REJECT_EVENT_SIG_INVALID
        _VerifyKey(bytes.fromhex(hexk)).verify(
            canonical_json(event.signing_body()), sig,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, REJECT_EVENT_SIG_INVALID
    return True, ""


# ─── 存储 ───────────────────────────────────────────────────────

_LOCKS: Dict[str, threading.RLock] = {}
_LOCK_GUARD = threading.Lock()


def _thread_lock_for(path: str) -> threading.RLock:
    with _LOCK_GUARD:
        if path not in _LOCKS:
            _LOCKS[path] = threading.RLock()
        return _LOCKS[path]


class TradeStore:
    """一交易一文件，存事件列表。布局 ``<root>/trades/<trade_id>.json``。"""

    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "trades"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, trade_id: str) -> Path:
        return self.root / f"{safe_id(trade_id)}.json"

    def get_events(self, trade_id: str) -> Optional[List[Dict[str, Any]]]:
        data = safe_load_json(self._path(trade_id), fallback=None)
        if data is None:
            return None
        events = data.get("events") if isinstance(data, dict) else None
        return events if isinstance(events, list) else []

    def import_verified_events(
        self,
        trade_id: str,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merge a remote signed chain only when it extends our exact prefix.

        This is the replication rule for buyer/seller projections: duplicate
        delivery is harmless, a longer valid chain advances local state, and
        forks or out-of-order suffixes fail closed instead of being patched
        together into a chain nobody signed.
        """
        if not isinstance(events, list) or not events:
            raise TradeRejected(REJECT_CHAIN_BROKEN, "empty remote trade chain")
        if len(events) > 1000:
            raise TradeRejected(REJECT_CHAIN_BROKEN, "remote trade chain too long")
        candidate = [dict(item) if isinstance(item, dict) else item for item in events]
        path = self._path(trade_id)
        lock = _thread_lock_for(str(path))
        with lock, InterProcessLock(path):
            existing = self.get_events(trade_id)
            if path.exists() and existing is None:
                raise TradeConflict("stored trade is unreadable; refuse to overwrite")
            if existing and candidate[:len(existing)] != existing:
                raise TradeConflict("remote trade does not extend the local signed prefix")
            if existing is not None and len(candidate) < len(existing):
                raise TradeConflict("remote trade is older than the local signed chain")
            class _CandidateStore:
                def get_events(self, requested_trade_id: str):
                    return candidate if requested_trade_id == trade_id else None

            # Verify before replacing durable state. The previous
            # write-then-rollback sequence left a corrupt chain behind if the
            # process died between those two writes.
            ok, reason = verify_trade(_CandidateStore(), trade_id)  # type: ignore[arg-type]
            if not ok:
                raise TradeRejected(reason, "remote trade chain failed verification")
            atomic_write_json(
                path,
                {"trade_id": trade_id, "events": candidate},
            )
            return candidate


# ─── 转移表 ─────────────────────────────────────────────────────
#
# 每个事件类型 → (合法前置状态集合, 默认新状态)。verification 的新状态
# 由 verdict 决定，故这里标 None 由转移函数填。
_LEGAL_PRIOR: Dict[str, frozenset] = {
    EVENT_TRADE_OPENED: frozenset({""}),                    # 开局
    EVENT_DELIVERY_SUBMITTED: frozenset({STATE_EXECUTING}),
    EVENT_VERIFICATION_RECORDED: frozenset({STATE_DELIVERED}),
    EVENT_SETTLEMENT_RECORDED: frozenset({STATE_VERIFIED}),
    # CS3：交付后任一非终态都可提争议（交付/已验/失败）。
    EVENT_DISPUTE_OPENED: frozenset({
        STATE_DELIVERED, STATE_VERIFIED, STATE_FAILED,
    }),
    EVENT_DISPUTE_RESOLVED: frozenset({STATE_DISPUTED}),
}


def _current_state(events: List[Dict[str, Any]]) -> str:
    """折叠事件得当前状态（空 = 尚未开局）。"""
    if not events:
        return ""
    return str(events[-1].get("new_state", ""))


def _expected_new_state(event_type: str, payload: Dict[str, Any]) -> Optional[str]:
    """给定事件类型 + payload，算出**该事件唯一合法的** new_state。

    独立审查修复 (CS1 R1)：状态机绝不能信任事件里存的 new_state ——
    那是签名者可控字段。一个 claimant 完全可以自签一个 delivery 事件却
    把 new_state 直接写成 ``settled``，跳过验收/结算。verify_trade 必须
    用本函数算出期望 new_state 并比对，不符即判链断。

    verification 的 new_state 由 verdict 决定（pass→verified, fail→failed）；
    其余事件类型有唯一确定的 new_state。未知事件类型返回 None（拒）。
    """
    if event_type == EVENT_TRADE_OPENED:
        return STATE_EXECUTING
    if event_type == EVENT_DELIVERY_SUBMITTED:
        return STATE_DELIVERED
    if event_type == EVENT_VERIFICATION_RECORDED:
        verdict = payload.get("verdict")
        if verdict == VERDICT_PASS:
            return STATE_VERIFIED
        if verdict == VERDICT_FAIL:
            return STATE_FAILED
        return None  # 缺/坏 verdict → 非法
    if event_type == EVENT_SETTLEMENT_RECORDED:
        return STATE_SETTLED
    if event_type == EVENT_DISPUTE_OPENED:
        return STATE_DISPUTED
    if event_type == EVENT_DISPUTE_RESOLVED:
        # 新状态由裁决决定，同 verdict 思路（不信任存值）
        resolution = payload.get("resolution")
        if resolution == RESOLUTION_SETTLE:
            return STATE_SETTLED
        if resolution == RESOLUTION_REFUND:
            return STATE_REFUNDED
        if resolution == RESOLUTION_SPLIT:
            return STATE_SPLIT_SETTLED
        return None  # 缺/坏 resolution → 非法
    return None  # 未知事件类型


def _parties(events: List[Dict[str, Any]]) -> Dict[str, str]:
    """从开局事件 payload 取绑定的各方 DID。"""
    if not events:
        return {}
    opened = events[0]
    p = opened.get("payload", {}) if isinstance(opened, dict) else {}
    return {
        "claimant_did": str(p.get("claimant_did", "")),
        "publisher_did": str(p.get("publisher_did", "")),
        "verifier_did": str(p.get("verifier_did", "")),
        "settler_did": str(p.get("settler_did", "")),
        "resolver_did": str(p.get("resolver_did", "")),
    }


def _trade_terms(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """从开局事件取约定结算条款（CS4）；未签 terms 返回 None。"""
    if not events:
        return None
    opened = events[0]
    p = opened.get("payload", {}) if isinstance(opened, dict) else {}
    t = p.get("terms")
    return t if isinstance(t, dict) else None


def _append_event(
    store: TradeStore,
    trade_id: str,
    *,
    actor: "Any",
    event_type: str,
    new_state: str,
    payload: Dict[str, Any],
    expect_open: bool,
    allowed_actor_dids: Optional[set],
    now_ms_override: int,
) -> TradeEvent:
    """通用转移：锁内 load → 校验前置/角色 → 签名 append。

    expect_open=True 用于 open_trade（要求 trade 尚不存在）。其余转移
    要求 trade 已存在且前置状态合法。

    allowed_actor_dids：None = 不校验角色；非空集 = actor 必须在集内
    （单角色传单元素集；dispute_opened 可由 publisher 或 claimant 提，
    传双元素集）。集里的 "" 会被剔除（未绑定的角色不算合法签名者）。
    """
    if not isinstance(payload, dict):
        raise TradeRejected(REJECT_PAYLOAD_INVALID, "event payload must be an object")
    try:
        if len(canonical_json(payload)) > _MAX_TRADE_PAYLOAD_BYTES:
            raise TradeRejected(REJECT_PAYLOAD_INVALID, "event payload exceeds 256 KiB")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise TradeRejected(REJECT_PAYLOAD_INVALID, "event payload is not canonical JSON") from exc
    path = store._path(trade_id)
    with _thread_lock_for(str(path)), InterProcessLock(path):
        data = safe_load_json(path, fallback=None)
        if path.exists() and not isinstance(data, dict):
            raise TradeRejected(REJECT_CHAIN_BROKEN, "stored trade is unreadable")
        if isinstance(data, dict) and not isinstance(data.get("events", []), list):
            raise TradeRejected(REJECT_CHAIN_BROKEN, "stored trade events are malformed")
        events: List[Dict[str, Any]] = (
            data.get("events", []) if isinstance(data, dict) else []
        )
        if events:
            ok, reason = verify_trade(store, trade_id)
            if not ok:
                raise TradeRejected(reason, "stored trade failed verification")

        if expect_open:
            if events:
                raise TradeRejected(REJECT_TRADE_EXISTS, trade_id)
            prev_state = ""
        else:
            if not events:
                raise TradeRejected(REJECT_TRADE_NOT_FOUND, trade_id)
            prev_state = _current_state(events)
            # 前置状态守卫
            legal = _LEGAL_PRIOR.get(event_type, frozenset())
            if prev_state not in legal:
                raise TradeRejected(
                    REJECT_ILLEGAL_TRANSITION,
                    f"{event_type} 不能从 {prev_state!r}（合法前置 {sorted(legal)}）",
                )
            # 角色守卫
            if allowed_actor_dids is not None:
                allowed = {d for d in allowed_actor_dids if d}
                if actor.as_did() not in allowed:
                    raise TradeRejected(
                        REJECT_WRONG_ACTOR,
                        f"{event_type} 必须由 {sorted(allowed)!r} 之一签，"
                        f"实际 {actor.as_did()!r}",
                    )

        seq = len(events)
        ev = TradeEvent(
            trade_id=trade_id,
            seq=seq,
            type=event_type,
            actor_did=actor.as_did(),
            prev_state=prev_state,
            new_state=new_state,
            payload=payload,
            created_at_ms=now_ms_override or now_ms(),
        )
        sign_trade_event(actor, ev)
        candidate_events = [*events, ev.to_dict()]
        try:
            if len(canonical_json({"events": candidate_events})) > _MAX_TRADE_CHAIN_BYTES:
                raise TradeRejected(
                    REJECT_PAYLOAD_INVALID,
                    "signed trade chain exceeds the 320 KiB federation budget",
                )
        except TradeRejected:
            raise
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise TradeRejected(
                REJECT_PAYLOAD_INVALID, "signed trade chain is not canonical JSON",
            ) from exc
        events.append(ev.to_dict())
        atomic_write_json(path, {"trade_id": trade_id, "events": events})
        return ev


# ─── 转移函数（4 个）────────────────────────────────────────────


def open_trade(
    store: TradeStore,
    *,
    authority: "Any",       # 开局方（主 DAO），签 trade_opened
    claim_record: Dict[str, Any],
    verifier_did: str = "",
    settler_did: str = "",
    resolver_did: str = "",
    terms: Optional[Dict[str, Any]] = None,
    now_ms_override: int = 0,
) -> TradeEvent:
    """从一条市场 claim 开一个 trade（状态 → EXECUTING）。

    claimant/publisher 从 claim_record 取并绑定。verifier/settler/resolver
    由开局方指定（默认 verifier/settler = publisher_did；resolver（争议
    裁决方，CS3）默认 = verifier_did —— 生产中应换成中立仲裁方）。

    terms（CS4）：约定结算条款 ``{"amount_minor":int,"currency":str,
    "payee_did":str}``（金额来自公告 reward；payee 默认 claimant）。由
    authority 在开局事件里签下后，``verify_trade`` 会用它**自动**核对
    settlement 金额/币种/收款方 —— 闭合"settler 改小金额白嫖"缺口，无需
    审计方另带条款。不传 terms → 老行为（verify_trade 不校验金额）。

    一笔认领一个 trade（trade_id = announcement_id）。重复 open → 拒。
    """
    announcement_id = str(claim_record.get("announcement_id", ""))
    claimant_did = str(claim_record.get("claimant_did", ""))
    publisher_did = str(claim_record.get("publisher_did", ""))
    if not announcement_id or not claimant_did or not publisher_did:
        raise TradeRejected(
            "bad-claim-record",
            "claim_record 缺 announcement_id/claimant_did/publisher_did",
        )
    vd = verifier_did or publisher_did
    sd = settler_did or publisher_did
    rd = resolver_did or vd
    payload = {
        "announcement_id": announcement_id,
        "claimant_did": claimant_did,
        "publisher_did": publisher_did,
        "verifier_did": vd,
        "settler_did": sd,
        "resolver_did": rd,
        "claim_receipt_id": str(claim_record.get("receipt_id", "")),
    }
    if terms is not None:
        # 快失败：terms 一旦给出就必须是良构的（正整数金额 + 非空币种），
        # 否则别签进链。早先用 -1 哨兵兜底坏 terms，会让一笔诚实结算永远
        # 过不了 verify_trade（amount != -1）—— 等于静默 brick 这笔 trade。
        # 宁可在开局当场拒。payee 默认 claimant（干活的人收钱）。
        amt = terms.get("amount_minor")
        if isinstance(amt, bool) or not isinstance(amt, int) or amt <= 0:
            raise TradeRejected(
                "bad-terms", f"terms.amount_minor 必须正整数，实际 {amt!r}"
            )
        cur = str(terms.get("currency", ""))
        if not cur:
            raise TradeRejected("bad-terms", "terms.currency 不能为空")
        payload["terms"] = {
            "amount_minor": amt,
            "currency": cur,
            "payee_did": str(terms.get("payee_did", "")) or claimant_did,
        }
    return _append_event(
        store, announcement_id, actor=authority,
        event_type=EVENT_TRADE_OPENED, new_state=STATE_EXECUTING,
        payload=payload, expect_open=True, allowed_actor_dids=None,
        now_ms_override=now_ms_override,
    )


def submit_delivery(
    store: TradeStore,
    trade_id: str,
    *,
    claimant: "Any",
    delivery: Dict[str, Any],
    now_ms_override: int = 0,
) -> TradeEvent:
    """claimant 提交交付（EXECUTING → DELIVERED）。必须由绑定的 claimant 签。"""
    parties = _parties(store.get_events(trade_id) or [])
    return _append_event(
        store, trade_id, actor=claimant,
        event_type=EVENT_DELIVERY_SUBMITTED, new_state=STATE_DELIVERED,
        payload={"delivery": delivery},
        expect_open=False,
        allowed_actor_dids={parties.get("claimant_did")},
        now_ms_override=now_ms_override,
    )


def record_verification(
    store: TradeStore,
    trade_id: str,
    *,
    verifier: "Any",
    verdict: str,
    result: Dict[str, Any],
    now_ms_override: int = 0,
) -> TradeEvent:
    """verifier 记录验收（DELIVERED → VERIFIED|FAILED）。必须由绑定的 verifier 签。

    verdict 必须是 ``pass`` / ``fail``。验收结果（result）写进 payload。
    """
    if verdict not in (VERDICT_PASS, VERDICT_FAIL):
        raise TradeRejected(REJECT_BAD_VERDICT, f"verdict={verdict!r}")
    new_state = STATE_VERIFIED if verdict == VERDICT_PASS else STATE_FAILED
    parties = _parties(store.get_events(trade_id) or [])
    return _append_event(
        store, trade_id, actor=verifier,
        event_type=EVENT_VERIFICATION_RECORDED, new_state=new_state,
        payload={"verdict": verdict, "result": result},
        expect_open=False,
        allowed_actor_dids={parties.get("verifier_did")},
        now_ms_override=now_ms_override,
    )


def record_settlement(
    store: TradeStore,
    trade_id: str,
    *,
    settler: "Any",
    settlement: Dict[str, Any],
    now_ms_override: int = 0,
) -> TradeEvent:
    """settler 记录结算（VERIFIED → SETTLED）。必须由绑定的 settler 签。

    CS1 无真钱：settlement 是签名的 manual 记录（adapter_id="manual"）。
    x402 testnet 结算留给 CS4。
    """
    parties = _parties(store.get_events(trade_id) or [])
    return _append_event(
        store, trade_id, actor=settler,
        event_type=EVENT_SETTLEMENT_RECORDED, new_state=STATE_SETTLED,
        payload={"settlement": settlement},
        expect_open=False,
        allowed_actor_dids={parties.get("settler_did")},
        now_ms_override=now_ms_override,
    )


# ─── CS3：争议处理 ─────────────────────────────────────────────


def open_dispute(
    store: TradeStore,
    trade_id: str,
    *,
    disputant: "Any",       # publisher 或 claimant（任一方都可提）
    reason: str,
    evidence: Optional[Dict[str, Any]] = None,
    now_ms_override: int = 0,
) -> TradeEvent:
    """提起争议（DELIVERED|VERIFIED|FAILED → DISPUTED）。

    任一方（publisher 或 claimant）都能提。整条 trade 事件日志本身就是
    争议材料包（claim→交付→验收→争议都在内、各自签名），无需另造对象。
    """
    parties = _parties(store.get_events(trade_id) or [])
    disputant_did = disputant.as_did()
    role = ("publisher" if disputant_did == parties.get("publisher_did")
            else "claimant" if disputant_did == parties.get("claimant_did")
            else "")
    return _append_event(
        store, trade_id, actor=disputant,
        event_type=EVENT_DISPUTE_OPENED, new_state=STATE_DISPUTED,
        payload={
            "reason": reason,
            "disputant_role": role,
            "evidence": evidence or {},
        },
        expect_open=False,
        allowed_actor_dids={
            parties.get("publisher_did"), parties.get("claimant_did"),
        },
        now_ms_override=now_ms_override,
    )


def resolve_dispute(
    store: TradeStore,
    trade_id: str,
    *,
    resolver: "Any",        # 绑定的 resolver（仲裁方）
    resolution: str,        # settle / refund / split
    settlement: Optional[Dict[str, Any]] = None,
    rationale: str = "",
    now_ms_override: int = 0,
) -> TradeEvent:
    """裁决争议（DISPUTED → SETTLED|REFUNDED|SPLIT_SETTLED）。必须由绑定的
    resolver 签。

    resolution：
      settle → claimant 胜，全额结算
      refund → publisher 胜，退款
      split  → 部分结算（settlement 里带各方金额）

    CS1/CS3 无真钱：settlement 是签名 manual 记录；x402 真钱留给 CS4。
    """
    if resolution not in (RESOLUTION_SETTLE, RESOLUTION_REFUND, RESOLUTION_SPLIT):
        raise TradeRejected(REJECT_BAD_RESOLUTION, f"resolution={resolution!r}")
    new_state = {
        RESOLUTION_SETTLE: STATE_SETTLED,
        RESOLUTION_REFUND: STATE_REFUNDED,
        RESOLUTION_SPLIT: STATE_SPLIT_SETTLED,
    }[resolution]
    parties = _parties(store.get_events(trade_id) or [])
    return _append_event(
        store, trade_id, actor=resolver,
        event_type=EVENT_DISPUTE_RESOLVED, new_state=new_state,
        payload={
            "resolution": resolution,
            "settlement": settlement or {},
            "rationale": rationale,
        },
        expect_open=False,
        allowed_actor_dids={parties.get("resolver_did")},
        now_ms_override=now_ms_override,
    )


# ─── 查询 + 验证 ───────────────────────────────────────────────


def trade_state(store: TradeStore, trade_id: str) -> Optional[str]:
    """当前状态（trade 不存在返回 None）。"""
    events = store.get_events(trade_id)
    if events is None:
        return None
    return _current_state(events)


def verify_trade(store: TradeStore, trade_id: str) -> Tuple[bool, str]:
    """完整复核一个 trade 的事件链：每事件验签 + seq 单调 + 转移合法 +
    角色正确。任一不过 → (False, reason)。

    这是"离线审计"入口：拿到一个 trade 的事件日志，不依赖任何中心，
    就能独立确认整条交易是否每一步都合法且签名真实。

    边界（CS1）：verify_trade 证明的是"这条事件链**内部自洽** + 每步
    签名真实 + 转移合法 + new_state 不可被伪造跳步"。它**不**证明绑定
    的各方就是真实市场参与者 —— 一个攻击者把自己同时绑成
    publisher/claimant/verifier/settler 也能造出一条 verify_trade 通过
    的"已结算"假交易。要证明交易锚定真实市场证据，需另行交叉核对
    opened 事件里的 ``claim_receipt_id`` 对得上真实的市场 ClaimReceipt
    （claimant 签）+ 公告（publisher 签）。那是 commerce↔market 的绑定
    校验，属 CS2/集成范围，不在本函数。
    """
    events = store.get_events(trade_id)
    if not events:
        return False, REJECT_TRADE_NOT_FOUND
    try:
        if len(canonical_json({"events": events})) > _MAX_TRADE_CHAIN_BYTES:
            return False, REJECT_PAYLOAD_INVALID
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False, REJECT_PAYLOAD_INVALID

    parties: Dict[str, str] = {}
    state = ""
    for i, raw in enumerate(events):
        if not isinstance(raw, dict) or set(raw) != _TRADE_EVENT_FIELDS:
            return False, REJECT_CHAIN_BROKEN
        try:
            ev = TradeEvent.from_dict(raw)
        except (TypeError, ValueError):
            return False, REJECT_CHAIN_BROKEN
        if not isinstance(ev.payload, dict):
            return False, REJECT_PAYLOAD_INVALID
        try:
            if len(canonical_json(ev.payload)) > _MAX_TRADE_PAYLOAD_BYTES:
                return False, REJECT_PAYLOAD_INVALID
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False, REJECT_PAYLOAD_INVALID
        # seq 单调
        if ev.seq != i:
            return False, REJECT_CHAIN_BROKEN
        # 签名
        ok, reason = verify_trade_event(ev)
        if not ok:
            return False, reason
        # prev_state 与折叠一致
        if ev.prev_state != state:
            return False, REJECT_CHAIN_BROKEN
        # 转移合法（前置状态）
        legal = _LEGAL_PRIOR.get(ev.type, frozenset())
        if state not in legal:
            return False, REJECT_ILLEGAL_TRANSITION
        # new_state 必须等于"该事件类型唯一合法的 new_state"——
        # 不信任事件里存的 new_state（CS1 R1：签名者可控，会被伪造跳步）
        expected = _expected_new_state(ev.type, ev.payload or {})
        if expected is None or ev.new_state != expected:
            return False, REJECT_ILLEGAL_TRANSITION
        # 角色（开局事件绑定各方；之后校验 actor 在该事件允许的角色集内）
        if ev.type == EVENT_TRADE_OPENED:
            parties = _parties([raw])
        else:
            allowed: Dict[str, set] = {
                EVENT_DELIVERY_SUBMITTED: {parties.get("claimant_did")},
                EVENT_VERIFICATION_RECORDED: {parties.get("verifier_did")},
                EVENT_SETTLEMENT_RECORDED: {parties.get("settler_did")},
                EVENT_DISPUTE_OPENED: {
                    parties.get("publisher_did"), parties.get("claimant_did"),
                },
                EVENT_DISPUTE_RESOLVED: {parties.get("resolver_did")},
            }
            role_set = allowed.get(ev.type)
            if role_set is not None:
                role_set = {d for d in role_set if d}
                if ev.actor_did not in role_set:
                    return False, REJECT_WRONG_ACTOR
            # CS4：直接结算（VERIFIED→SETTLED）若开局签了 terms，自动核对
            # settlement 金额/币种/收款方 —— 闭合"settler 改小金额白嫖"。
            # 争议裁决（dispute_resolved）的金额由 resolver 判，不受 terms 约束，
            # 故只在 SETTLEMENT_RECORDED 这一支强制。
            if ev.type == EVENT_SETTLEMENT_RECORDED:
                terms = _trade_terms(events)
                if terms:
                    from nth_dao.commerce.settlement import verify_settlement
                    settlement = (ev.payload or {}).get("settlement", {})
                    exp_amt = terms.get("amount_minor")
                    if isinstance(exp_amt, bool) or not isinstance(exp_amt, int):
                        exp_amt = -1
                    ok, reason = verify_settlement(
                        settlement if isinstance(settlement, dict) else {},
                        expected_amount_minor=exp_amt,
                        expected_currency=str(terms.get("currency", "")),
                        expected_payee_did=str(terms.get("payee_did", "")),
                    )
                    if not ok:
                        return False, reason
            elif ev.type == EVENT_DISPUTE_RESOLVED:
                terms = _trade_terms(events)
                if terms:
                    settlement = (ev.payload or {}).get("settlement", {})
                    if not isinstance(settlement, dict):
                        return False, "settlement-malformed"
                    resolution = (ev.payload or {}).get("resolution")
                    amount = terms.get("amount_minor")
                    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
                        return False, "settlement-amount-invalid"
                    currency = str(terms.get("currency", ""))
                    if resolution == RESOLUTION_SETTLE:
                        from nth_dao.commerce.settlement import verify_settlement
                        ok, reason = verify_settlement(
                            settlement,
                            expected_amount_minor=amount,
                            expected_currency=currency,
                            expected_payee_did=str(terms.get("payee_did", "")),
                            expected_payer_did=parties.get("publisher_did", ""),
                        )
                        if not ok:
                            return False, reason
                    elif resolution == RESOLUTION_REFUND:
                        if not (
                            settlement.get("adapter_id") == "manual"
                            and settlement.get("amount_minor") == 0
                            and settlement.get("refunded_amount_minor") == amount
                            and settlement.get("currency") == currency
                            and settlement.get("payee_did") == parties.get("publisher_did")
                            and settlement.get("payer_did") == parties.get("publisher_did")
                        ):
                            return False, "settlement-refund-mismatch"
                    elif resolution == RESOLUTION_SPLIT:
                        paid = settlement.get("amount_minor")
                        refunded = settlement.get("refunded_amount_minor")
                        if (
                            isinstance(paid, bool)
                            or not isinstance(paid, int)
                            or isinstance(refunded, bool)
                            or not isinstance(refunded, int)
                            or paid <= 0
                            or refunded <= 0
                            or paid + refunded != amount
                            or settlement.get("adapter_id") != "manual"
                            or settlement.get("currency") != currency
                            or settlement.get("payee_did") != parties.get("claimant_did")
                            or settlement.get("payer_did") != parties.get("publisher_did")
                        ):
                            return False, "settlement-split-mismatch"
        state = ev.new_state

    return True, ""
