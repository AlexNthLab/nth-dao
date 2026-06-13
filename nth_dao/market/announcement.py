"""TaskAnnouncement —— 主动任务市场的结构化任务公告。

与 ``nth_dao.marketplace.TaskOrder`` 的关系：
  - TaskOrder 是单 DAO 内的"订单 + 状态机 + credits"，偏执行态。
  - TaskAnnouncement 是"对外发布的、可被陌生 Agent 发现的、可联邦
    传播的公告"，偏发现态。它带 ``publisher_did`` + ``publisher_sig``,
    所以任何收到它的人都能独立验证真伪（约束 E：全程签名）。

签名模型完全沿用 ``cap_token`` / ``execution_receipt``：
  body = {除 publisher_sig 外的所有字段}
  publisher_sig = b64u(ed25519_sign(canonical_json(body)))
canonical_json 用 sort_keys，所以字段插入顺序不影响签名。

M1 只负责"造公告 + 验公告"。匹配（M2）、认领（M3）、联邦（M4）在
各自模块。这里刻意不放任何 I/O —— 纯数据 + 纯密码学，方便单测。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import uuid

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE

try:
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover - exercised only without pynacl
    _VerifyKey = None  # type: ignore[assignment]


# ─── reject reasons（machine-readable，与 cap_token 风格一致）───

REJECT_ANN_MISSING_FIELD = "ann-missing-field"
REJECT_ANN_BAD_PUBLISHER_DID = "ann-bad-publisher-did"
REJECT_ANN_SIG_INVALID = "ann-sig-invalid"
REJECT_ANN_SIG_DECODE_FAILED = "ann-sig-decode-failed"
REJECT_ANN_CRYPTO_UNAVAILABLE = "ann-crypto-unavailable"

# 公告版本钉死，跨实现解析时用来识别 schema。
NTH_ANNOUNCEMENT_KIND = "nth-task-announcement-v1"


@dataclass
class TaskAnnouncement:
    """一条可发现、可验证、可联邦的任务公告。

    字段分组（见开发指导 §3.2）：
      身份/版本 —— kind / announcement_id / publisher_did
      标题 ——      title / description
      客观匹配 ——  capability_set / context / input_schema / acceptance
      经济 ——      reward_minor（整数最小单位，禁 float）/ reward_asset
      关联 ——      mission_id（约束 B：关联上层 Mission）
      时效 ——      published_at_ms / not_after
      签名 ——      publisher_sig（约束 E）
    """

    announcement_id: str
    publisher_did: str
    title: str
    # —— 客观匹配维度（Match 的"能力"侧，M2 用）——
    capability_set: List[str] = field(default_factory=list)
    context: str = "general"
    input_schema: Dict[str, Any] = field(default_factory=dict)
    acceptance: Dict[str, Any] = field(default_factory=dict)
    # —— 经济维度（整数最小单位，继承交易铁律：禁 float 金额）——
    reward_minor: int = 0
    reward_asset: str = "credit"
    # —— 关联维度（约束 B）——
    mission_id: str = ""
    # —— 发布方侧准入策略（M5，约束 D 的对称面）——
    # 对称于订阅的 ``publisher_trust_floor``：订阅方按信誉过滤发布方,
    # 发布方按信誉门槛过滤认领方。空 dict = 不设门槛 = 无许可认领
    # （保持 M4 permissionless 默认）。门槛字段对 ReputationProfile 的
    # 可解释维度，如 ``{"min_claims_count": 3, "min_distinct_publishers": 2}``。
    # 由认领权威（主 DAO）在 claim 时按自己计算的 claimant 信誉判定。
    claimant_policy: Dict[str, Any] = field(default_factory=dict)
    # —— 描述（自由文本，不参与匹配，仅供人/Agent 阅读）——
    description: str = ""
    # —— 时效 ——
    published_at_ms: int = 0
    not_after: int = 0  # 0 = 不过期
    # —— 版本 + 签名 ——
    kind: str = NTH_ANNOUNCEMENT_KIND
    publisher_sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskAnnouncement":
        # 只取已知字段，忽略未来版本的额外字段（向前兼容）。
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def signing_body(self) -> Dict[str, Any]:
        """签名覆盖的 body —— 除 publisher_sig 外的全部字段。

        canonical_json 内部 sort_keys，所以这里不需要手动排序。
        """
        return {k: v for k, v in self.to_dict().items() if k != "publisher_sig"}

    def is_expired(self, now_ms_override: int = 0) -> bool:
        if not self.not_after:
            return False
        now = now_ms_override or now_ms()
        return now > self.not_after


def sign_announcement(
    *,
    publisher: "Any",  # AgentIdentity —— 必须 can_sign
    title: str,
    capability_set: Optional[List[str]] = None,
    context: str = "",
    input_schema: Optional[Dict[str, Any]] = None,
    acceptance: Optional[Dict[str, Any]] = None,
    reward_minor: int = 0,
    reward_asset: str = "credit",
    mission_id: str = "",
    claimant_policy: Optional[Dict[str, Any]] = None,
    description: str = "",
    not_after: int = 0,
    announcement_id: str = "",
    published_at_ms: int = 0,
) -> TaskAnnouncement:
    """构造并签名一条公告。

    Raises:
        ValueError —— title 为空、reward_minor 非 int 或为负、
            capability_set 含非字符串/空串。
        RuntimeError —— publisher 无法签名。
    """
    if not isinstance(title, str) or not title.strip():
        raise ValueError("announcement title must be a non-empty string")
    if not isinstance(reward_minor, int) or isinstance(reward_minor, bool):
        # bool 是 int 子类，显式排除 —— reward_minor=True 不该当 1。
        raise ValueError(
            f"reward_minor must be a non-bool int (minor units); "
            f"got {type(reward_minor).__name__}"
        )
    if reward_minor < 0:
        raise ValueError(f"reward_minor must be >= 0; got {reward_minor}")

    caps: List[str] = []
    for c in (capability_set or []):
        if not isinstance(c, str) or not c.strip():
            raise ValueError(
                f"capability_set entries must be non-empty strings; got {c!r}"
            )
        caps.append(c.strip())
    # 去重 + 排序，让 canonical body 不依赖输入顺序。
    caps = sorted(set(caps))

    # 独立审查修复 (M2 R1)：context 默认从主能力派生，而不是恒为
    # "general"。footgun 根因 —— 一条 capability_set=["code_review"]
    # 但忘了设 context 的公告会拿到 context="general"，于是把
    # contexts=["code_review"] 的订阅者挡在外面（能干却看不见）。
    # 现在：未显式给 context 时，取首个（排序后）能力作为类别；
    # 无能力则回落 "general"。显式传入的 context 永远优先。
    resolved_context = context.strip() if isinstance(context, str) else ""
    if not resolved_context:
        resolved_context = caps[0] if caps else "general"

    ann = TaskAnnouncement(
        announcement_id=announcement_id or uuid.uuid4().hex,
        publisher_did=publisher.as_did(),
        title=title,
        capability_set=caps,
        context=resolved_context,
        input_schema=dict(input_schema or {}),
        acceptance=dict(acceptance or {}),
        reward_minor=reward_minor,
        reward_asset=reward_asset,
        mission_id=mission_id,
        claimant_policy=dict(claimant_policy or {}),
        description=description,
        published_at_ms=published_at_ms or now_ms(),
        not_after=not_after,
    )
    sig_bytes = publisher.sign(canonical_json(ann.signing_body()))
    ann.publisher_sig = b64u_encode(sig_bytes)
    return ann


def verify_announcement(ann: TaskAnnouncement) -> Tuple[bool, str]:
    """验证公告的 publisher_sig 是否由 publisher_did 签出。

    Returns ``(ok, reason)``；ok=True 时 reason 为 ""。

    注意：这里只验"签名真伪 + 必填字段 + DID 合法"，**不验**业务
    规则（报酬是否合理、能力是否存在于词表）—— 那些是 M2 match 和
    上层 policy 的事。fail-closed：任何检查不过即拒。
    """
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, REJECT_ANN_CRYPTO_UNAVAILABLE

    # 必填字段（缺一即拒，对应 cap_token 的 shape 检查）
    for required in ("kind", "announcement_id", "publisher_did", "title",
                     "publisher_sig"):
        val = getattr(ann, required, None)
        if not val:
            return False, REJECT_ANN_MISSING_FIELD

    pub_did = ann.publisher_did
    if not isinstance(pub_did, str) or not is_did_key(pub_did):
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    pub_hex = decode_ed25519_did_key_hex(pub_did) or ""
    if not pub_hex:
        return False, REJECT_ANN_BAD_PUBLISHER_DID

    try:
        sig_bytes = b64u_decode(str(ann.publisher_sig))
    except Exception:  # noqa: BLE001 - 解码失败即拒
        return False, REJECT_ANN_SIG_DECODE_FAILED

    try:
        _VerifyKey(bytes.fromhex(pub_hex)).verify(
            canonical_json(ann.signing_body()), sig_bytes,
        )
    except Exception:  # noqa: BLE001 - 验签失败即拒
        return False, REJECT_ANN_SIG_INVALID

    return True, ""
