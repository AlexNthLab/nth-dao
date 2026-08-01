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
import hashlib
import re
import uuid

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover - exercised only without pynacl
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]


# ─── reject reasons（machine-readable，与 cap_token 风格一致）───

REJECT_ANN_MISSING_FIELD = "ann-missing-field"
REJECT_ANN_BAD_PUBLISHER_DID = "ann-bad-publisher-did"
REJECT_ANN_SIG_INVALID = "ann-sig-invalid"
REJECT_ANN_SIG_DECODE_FAILED = "ann-sig-decode-failed"
REJECT_ANN_CRYPTO_UNAVAILABLE = "ann-crypto-unavailable"
REJECT_ANN_SCHEMA_INVALID = "ann-schema-invalid"

# 公告版本钉死，跨实现解析时用来识别 schema。
NTH_ANNOUNCEMENT_KIND_V1 = "nth-task-announcement-v1"
NTH_ANNOUNCEMENT_KIND_V2 = "nth-task-announcement-v2"
NTH_ANNOUNCEMENT_KIND_V3 = "nth-task-announcement-v3"
NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1 = "nth-trade-offer-announcement-v1"
# Preserve the historical default so existing callers do not silently change
# their signed wire body. Commerce publishers opt in to v3 explicitly.
NTH_ANNOUNCEMENT_KIND = NTH_ANNOUNCEMENT_KIND_V2

_MAX_ANNOUNCEMENT_ID_CHARS = 256
_MAX_DID_CHARS = 128
_MAX_TITLE_CHARS = 512
_MAX_DESCRIPTION_CHARS = 64 * 1024
_MAX_CAPABILITIES = 64
_MAX_CAPABILITY_CHARS = 128
_MAX_CONTEXT_CHARS = 128
_MAX_ASSET_CHARS = 64
_MAX_MISSION_ID_CHARS = 256
_MAX_POLICY_BYTES = 64 * 1024
_MAX_AVAILABILITY_BYTES = 4 * 1024
_MAX_OFFER_URI_CHARS = 2048
_MAX_SIGNED_INT = (1 << 63) - 1
_ANNOUNCEMENT_ID_PATTERN = re.compile(r"[A-Za-z0-9_:-][A-Za-z0-9._:-]{0,255}\Z")
_OFFER_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _bounded_text(value: Any, *, minimum: int = 0, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and minimum <= len(value.encode("utf-8")) <= maximum
    )


def _bounded_json_object(value: Any, *, maximum: int) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        return len(canonical_json(value)) <= maximum
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False


def _valid_non_negative_int(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_SIGNED_INT


def _valid_announcement_id(ann: "TaskAnnouncement") -> bool:
    """Validate IDs according to the signed announcement version.

    Version 1 did not define a transport-safe alphabet. Existing signed v1
    records therefore remain readable when their IDs are bounded printable
    text. Version 2 IDs are also used in URLs and keep the strict alphabet.
    """
    value = ann.announcement_id
    if not _bounded_text(
        value, minimum=1, maximum=_MAX_ANNOUNCEMENT_ID_CHARS,
    ) or value in {".", ".."}:
        return False
    if ann.kind == NTH_ANNOUNCEMENT_KIND_V1:
        return value.isprintable()
    return _ANNOUNCEMENT_ID_PATTERN.fullmatch(value) is not None


def announcement_federation_key(ann: "TaskAnnouncement") -> str:
    """Return the content-bound identifier used outside one DAO namespace.

    ``announcement_id`` is only locally unique. The signed body hash also
    binds publisher, claim authority, payload, and timestamps, so unrelated
    DAOs can safely use the same local id without shadowing each other.
    """
    digest = hashlib.sha256(canonical_json(ann.signing_body())).hexdigest()
    return f"nth-ann-sha256:{digest}"


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
    # The publisher signs which DAO is the claim/CAS authority. Legacy v1
    # records omit this field and therefore authorize only publisher_did.
    authority_did: str = ""
    # v3 commerce discovery summary. These fields are absent from the signed
    # v1/v2 body and must stay at their neutral defaults for legacy records.
    listing_type: str = ""
    offer_digest: str = ""
    offer_uri: str = ""
    price_minor: int = 0
    price_asset: str = ""
    availability_summary: Dict[str, Any] = field(default_factory=dict)
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
        # Unknown fields are unsigned parser input, not forward-compatible
        # extensions. Protocol evolution must introduce a new signed kind.
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        if not isinstance(data, dict) or not set(data).issubset(known):
            raise ValueError("announcement has unknown fields")
        # Missing fields retain dataclass defaults so historical v1/v2 wire
        # records remain readable. New fields require a new signed `kind`.
        return cls(**data)

    def signing_body(self) -> Dict[str, Any]:
        """签名覆盖的 body —— 除 publisher_sig 外的全部字段。

        canonical_json 内部 sort_keys，所以这里不需要手动排序。
        """
        body = {k: v for k, v in self.to_dict().items() if k != "publisher_sig"}
        if self.kind in {NTH_ANNOUNCEMENT_KIND_V1, NTH_ANNOUNCEMENT_KIND_V2}:
            for key in (
                "listing_type", "offer_digest", "offer_uri", "price_minor",
                "price_asset", "availability_summary",
            ):
                body.pop(key, None)
        if self.kind == NTH_ANNOUNCEMENT_KIND_V1:
            body.pop("authority_did", None)
        return body

    def effective_authority_did(self) -> str:
        """Return the signed claim authority, with a safe v1 fallback."""
        if self.kind == NTH_ANNOUNCEMENT_KIND_V1:
            return self.publisher_did
        return self.authority_did

    def is_expired(self, now_ms_override: int = 0) -> bool:
        if not self.not_after:
            return False
        now = now_ms_override or now_ms()
        return now > self.not_after


def _validate_announcement_schema(
    ann: TaskAnnouncement, *, require_signature: bool = True,
) -> Tuple[bool, str]:
    """Validate the complete signed wire shape before cryptographic work.

    A valid signature authenticates bytes, not their runtime types. This
    guard prevents a legitimately signed but malformed object from reaching
    matching, expiry, persistence, or claim code.
    """
    if ann.kind not in {
        NTH_ANNOUNCEMENT_KIND_V1,
        NTH_ANNOUNCEMENT_KIND_V2,
        NTH_ANNOUNCEMENT_KIND_V3,
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    }:
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _valid_announcement_id(ann):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_text(ann.publisher_did, minimum=1, maximum=_MAX_DID_CHARS):
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    if not is_did_key(ann.publisher_did):
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    authority_did = ann.effective_authority_did()
    if not _bounded_text(authority_did, minimum=1, maximum=_MAX_DID_CHARS):
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    if not is_did_key(authority_did):
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    if ann.kind == NTH_ANNOUNCEMENT_KIND_V3:
        if ann.listing_type not in {"product", "service"}:
            return False, REJECT_ANN_SCHEMA_INVALID
        if not isinstance(ann.offer_digest, str) or not _OFFER_DIGEST_PATTERN.fullmatch(ann.offer_digest):
            return False, REJECT_ANN_SCHEMA_INVALID
        if not _bounded_text(
            ann.offer_uri, minimum=1, maximum=_MAX_OFFER_URI_CHARS,
        ):
            return False, REJECT_ANN_SCHEMA_INVALID
        if not _valid_non_negative_int(ann.price_minor):
            return False, REJECT_ANN_SCHEMA_INVALID
        if not _bounded_text(ann.price_asset, minimum=1, maximum=_MAX_ASSET_CHARS):
            return False, REJECT_ANN_SCHEMA_INVALID
        if not _bounded_json_object(
            ann.availability_summary,
            maximum=_MAX_AVAILABILITY_BYTES,
        ):
            return False, REJECT_ANN_SCHEMA_INVALID
        if ann.price_minor != ann.reward_minor or ann.price_asset != ann.reward_asset:
            return False, REJECT_ANN_SCHEMA_INVALID
    elif ann.kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
        if ann.listing_type != "exchange":
            return False, REJECT_ANN_SCHEMA_INVALID
        if not isinstance(ann.offer_digest, str) or not _OFFER_DIGEST_PATTERN.fullmatch(
            ann.offer_digest
        ):
            return False, REJECT_ANN_SCHEMA_INVALID
        if not _bounded_text(
            ann.offer_uri, minimum=1, maximum=_MAX_OFFER_URI_CHARS,
        ):
            return False, REJECT_ANN_SCHEMA_INVALID
        if ann.offer_uri != f"/api/v2/trade/federation/offers/{ann.offer_digest}":
            return False, REJECT_ANN_SCHEMA_INVALID
        if ann.price_minor != 0 or ann.price_asset != "":
            return False, REJECT_ANN_SCHEMA_INVALID
        if ann.reward_minor != 0 or ann.reward_asset != "exchange":
            return False, REJECT_ANN_SCHEMA_INVALID
        if not _bounded_json_object(
            ann.availability_summary,
            maximum=_MAX_AVAILABILITY_BYTES,
        ):
            return False, REJECT_ANN_SCHEMA_INVALID
        offer_id = ann.availability_summary.get("offer_id")
        revision = ann.availability_summary.get("revision")
        if not _bounded_text(offer_id, minimum=3, maximum=256):
            return False, REJECT_ANN_SCHEMA_INVALID
        if type(revision) is not int or not 1 <= revision <= 2_147_483_647:
            return False, REJECT_ANN_SCHEMA_INVALID
        if ann.availability_summary.get("state") != "active":
            return False, REJECT_ANN_SCHEMA_INVALID
    elif (
        ann.listing_type != ""
        or ann.offer_digest != ""
        or ann.offer_uri != ""
        or ann.price_minor != 0
        or ann.price_asset != ""
        or ann.availability_summary != {}
    ):
        # Never let a legacy signature authenticate v3-looking unsigned data.
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_text(ann.title, minimum=1, maximum=_MAX_TITLE_CHARS):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_text(ann.description, maximum=_MAX_DESCRIPTION_CHARS):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not isinstance(ann.capability_set, list):
        return False, REJECT_ANN_SCHEMA_INVALID
    if len(ann.capability_set) > _MAX_CAPABILITIES:
        return False, REJECT_ANN_SCHEMA_INVALID
    if any(
        not _bounded_text(cap, minimum=1, maximum=_MAX_CAPABILITY_CHARS)
        for cap in ann.capability_set
    ):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_text(ann.context, minimum=1, maximum=_MAX_CONTEXT_CHARS):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_json_object(ann.input_schema, maximum=_MAX_POLICY_BYTES):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_json_object(ann.acceptance, maximum=_MAX_POLICY_BYTES):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_json_object(ann.claimant_policy, maximum=_MAX_POLICY_BYTES):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _valid_non_negative_int(ann.reward_minor):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_text(ann.reward_asset, minimum=1, maximum=_MAX_ASSET_CHARS):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _bounded_text(ann.mission_id, maximum=_MAX_MISSION_ID_CHARS):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _valid_non_negative_int(ann.published_at_ms):
        return False, REJECT_ANN_SCHEMA_INVALID
    if not _valid_non_negative_int(ann.not_after):
        return False, REJECT_ANN_SCHEMA_INVALID
    if require_signature:
        if not _bounded_text(ann.publisher_sig, minimum=1, maximum=128):
            return False, REJECT_ANN_MISSING_FIELD
        try:
            decoded = b64u_decode(ann.publisher_sig)
            if len(decoded) != 64 or b64u_encode(decoded) != ann.publisher_sig:
                return False, REJECT_ANN_SIG_DECODE_FAILED
        except (TypeError, ValueError, UnicodeError):
            return False, REJECT_ANN_SIG_DECODE_FAILED
    return True, ""


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
    authority_did: str = "",
    mission_id: str = "",
    claimant_policy: Optional[Dict[str, Any]] = None,
    description: str = "",
    not_after: int = 0,
    announcement_id: str = "",
    published_at_ms: int = 0,
    kind: str = NTH_ANNOUNCEMENT_KIND,
    listing_type: str = "",
    offer_digest: str = "",
    offer_uri: str = "",
    price_minor: int = 0,
    price_asset: str = "",
    availability_summary: Optional[Dict[str, Any]] = None,
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

    resolved_authority_did = authority_did or publisher.as_did()
    if not isinstance(resolved_authority_did, str) or not is_did_key(
        resolved_authority_did
    ):
        raise ValueError("authority_did must be an Ed25519 did:key identifier")

    ann = TaskAnnouncement(
        announcement_id=announcement_id or uuid.uuid4().hex,
        publisher_did=publisher.as_did(),
        authority_did=resolved_authority_did,
        listing_type=listing_type,
        offer_digest=offer_digest,
        offer_uri=offer_uri,
        price_minor=price_minor,
        price_asset=price_asset,
        availability_summary=dict(availability_summary or {}),
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
        kind=kind,
    )
    schema_ok, schema_reason = _validate_announcement_schema(
        ann, require_signature=False,
    )
    if not schema_ok:
        raise ValueError(f"invalid announcement schema: {schema_reason}")
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
    # 独立审查修复 (M4 R2)：用精确的"None 或空/纯空白字符串"判定，不用
    # ``not val``。``not val`` 语义过载——not "   " 为 False（漏判纯空格）,
    # 且若未来必填列表混入数值字段，not 0 为 True 会误拒合法的 0。这里
    # 必填字段全是字符串，按字符串语义判空才正确且面向未来稳健。
    for required in ("kind", "announcement_id", "publisher_did", "title",
                     "publisher_sig"):
        val = getattr(ann, required, None)
        if val is None or (isinstance(val, str) and not val.strip()):
            return False, REJECT_ANN_MISSING_FIELD

    schema_ok, schema_reason = _validate_announcement_schema(ann)
    if not schema_ok:
        return False, schema_reason

    pub_did = ann.publisher_did
    if not isinstance(pub_did, str) or not is_did_key(pub_did):
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    pub_hex = decode_ed25519_did_key_hex(pub_did) or ""
    if not pub_hex:
        return False, REJECT_ANN_BAD_PUBLISHER_DID
    try:
        sig_bytes = b64u_decode(str(ann.publisher_sig))
    except (TypeError, ValueError, UnicodeError):
        return False, REJECT_ANN_SIG_DECODE_FAILED

    try:
        _VerifyKey(bytes.fromhex(pub_hex)).verify(
            canonical_json(ann.signing_body()), sig_bytes,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, REJECT_ANN_SIG_INVALID

    return True, ""


def announcement_listing_type(ann: TaskAnnouncement) -> str:
    """Return the trusted listing type across supported wire formats."""
    if ann.kind in {
        NTH_ANNOUNCEMENT_KIND_V3,
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    }:
        return ann.listing_type
    schema = ann.input_schema if isinstance(ann.input_schema, dict) else {}
    value = schema.get("__nth_listing_type", schema.get("listing_type", "task"))
    return value if value in {"task", "service", "product"} else "task"
