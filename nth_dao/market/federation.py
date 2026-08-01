"""跨 DAO 联邦（约束 C：无中心索引）—— 流浪地球级协作的发现层。

愿景第 4 点：DAO-A 发的公告，DAO-B 的 Agent 能发现并认领，没有
github.com 那样的中心。这里给出**无中心索引**的联邦数据模型。

两层设计（开发指导 §2.3「digest 走 gossip，全文按需拉」）：

  1. **FeedDigest（廉价提示，可 gossip）**
     每个 DAO 把自己 feed 的"可匹配摘要"签名后广播：每条公告只带
     匹配需要的字段（capability_set / context / reward / 时效），不带
     重的 input_schema / acceptance。digest 由 source DAO 的 DID 签名 ——
     **provenance**：你知道是"谁"在广播这批摘要。

  2. **全文按需拉（验证真相）**
     Agent 对感兴趣的 ref 才去源 DAO 拉完整公告。完整公告自带
     ``publisher_sig`` 自验证 —— 这才是权威。

信任模型（关键）：
  - digest 的 source 签名 = "谁在转发这批摘要"（provenance，可被中继）。
  - ref 本身**不单独签名** —— 它只是 source DAO 关于"我有这些活"的
    *声明*，不可全信。
  - 拉回的完整公告的 ``publisher_sig`` = 真权威。恶意 source 可以在
    digest 里塞假 ref，但你一拉全文，要么不存在、要么 publisher_sig
    验不过 → 丢弃。**digest 是不可信提示，全文是验证真相。**
  - 中继能**审查**（丢公告）但不能**伪造/篡改**（签名挡住）。

认领的归属（解决跨机 CAS 难题）：
  公告的**主 DAO 是认领权威**。DAO-B 的 Agent 通过联邦*发现* DAO-A 的
  公告，但*认领*必须回到 DAO-A 的 ClaimStore（DAO-A 的单点 CAS 仲裁）。
  这样 C4 的文件锁 CAS 不需要跨机器 —— 每条公告的认领永远由它的主
  DAO 仲裁。本模块只管发现；认领仍调 ``claim_announcement(主DAO的
  feed, 主DAO的store, ...)``。

传输无关：FeedDigest 是一个签名 blob，怎么传（gossip / mDNS / HTTP /
文件）是上层传输的事。本模块只定义数据模型 + 验证，``pull_announcements``
是主 DAO 的 serve 侧（测试直接调，生产由传输层包成网络请求）。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.market.announcement import (
    NTH_ANNOUNCEMENT_KIND_V1,
    NTH_ANNOUNCEMENT_KIND_V2,
    NTH_ANNOUNCEMENT_KIND_V3,
    NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    TaskAnnouncement,
    announcement_federation_key,
    verify_announcement,
)
from nth_dao.market.match import match
from nth_dao.market.subscription import MarketSubscription

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]


NTH_FEED_DIGEST_KIND = "nth-feed-digest-v1"

REJECT_DIGEST_MISSING_FIELD = "digest-missing-field"
REJECT_DIGEST_BAD_SOURCE_DID = "digest-bad-source-did"
REJECT_DIGEST_SIG_INVALID = "digest-sig-invalid"
REJECT_DIGEST_SIG_DECODE_FAILED = "digest-sig-decode-failed"
REJECT_DIGEST_CRYPTO_UNAVAILABLE = "digest-crypto-unavailable"
REJECT_DIGEST_SCHEMA_INVALID = "digest-schema-invalid"

_MAX_DIGEST_REFS = 1_000
_MAX_DIGEST_SIGNED_INT = (1 << 63) - 1
_MAX_DIGEST_DID_CHARS = 128
_MAX_DIGEST_ID_CHARS = 256
_MAX_DIGEST_CAPABILITIES = 64
_MAX_DIGEST_CAPABILITY_CHARS = 128
_MAX_DIGEST_CONTEXT_CHARS = 128
_MAX_DIGEST_ASSET_CHARS = 64
_MAX_DIGEST_AVAILABILITY_BYTES = 4 * 1024
_FEDERATION_KEY_PREFIX = "nth-ann-sha256:"
_FEDERATION_KEY_CHARS = len(_FEDERATION_KEY_PREFIX) + 64

# ref 里只放匹配需要的字段（刻意不含 input_schema / acceptance）。
_REF_FIELDS = (
    "kind", "announcement_id", "publisher_did", "authority_did",
    "capability_set", "context", "reward_minor", "reward_asset",
    "published_at_ms", "not_after", "listing_type", "offer_digest",
    "price_minor", "price_asset", "availability_summary",
)
_REF_ALLOWED_FIELDS = frozenset((*_REF_FIELDS, "federation_key"))


@dataclass
class FeedDigest:
    """一个 DAO feed 的签名可匹配摘要（联邦发现单位）。"""

    source_did: str
    generated_at_ms: int
    high_seq: int
    refs: List[Dict[str, Any]] = field(default_factory=list)
    kind: str = NTH_FEED_DIGEST_KIND
    digest_sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeedDigest":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        if not isinstance(data, dict) or not set(data).issubset(known):
            raise ValueError("feed digest has unknown fields")
        return cls(**data)

    def signing_body(self) -> Dict[str, Any]:
        return {k: v for k, v in self.to_dict().items() if k != "digest_sig"}


def _digest_text(value: Any, *, minimum: int = 0, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and minimum <= len(value.encode("utf-8")) <= maximum
    )


def _digest_uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_DIGEST_SIGNED_INT


def _validate_digest_ref(ref: Any) -> bool:
    if not isinstance(ref, dict):
        return False
    if not set(ref).issubset(_REF_ALLOWED_FIELDS):
        return False
    if not _digest_text(
        ref.get("announcement_id"), minimum=1, maximum=_MAX_DIGEST_ID_CHARS,
    ):
        return False
    federation_key = ref.get("federation_key")
    if federation_key is not None and not (
        isinstance(federation_key, str)
        and len(federation_key) == _FEDERATION_KEY_CHARS
        and federation_key.startswith(_FEDERATION_KEY_PREFIX)
        and all(ch in "0123456789abcdef" for ch in federation_key[-64:])
    ):
        return False
    publisher_did = ref.get("publisher_did")
    if not _digest_text(
        publisher_did, minimum=1, maximum=_MAX_DIGEST_DID_CHARS,
    ) or not is_did_key(publisher_did):
        return False
    authority_did = ref.get("authority_did", "")
    if authority_did and (
        not _digest_text(
            authority_did, minimum=1, maximum=_MAX_DIGEST_DID_CHARS,
        )
        or not is_did_key(authority_did)
    ):
        return False
    caps = ref.get("capability_set")
    if not isinstance(caps, list) or len(caps) > _MAX_DIGEST_CAPABILITIES:
        return False
    if any(
        not _digest_text(
            cap, minimum=1, maximum=_MAX_DIGEST_CAPABILITY_CHARS,
        )
        for cap in caps
    ):
        return False
    if not _digest_text(
        ref.get("context"), minimum=1, maximum=_MAX_DIGEST_CONTEXT_CHARS,
    ):
        return False
    if not _digest_uint(ref.get("reward_minor")):
        return False
    if not _digest_text(
        ref.get("reward_asset"), minimum=1, maximum=_MAX_DIGEST_ASSET_CHARS,
    ):
        return False
    if not _digest_uint(ref.get("published_at_ms")):
        return False
    if not _digest_uint(ref.get("not_after")):
        return False
    # Historical nth-feed-digest-v1 refs did not carry announcement kind.
    # Absence therefore means a legacy v2 summary, not an invalid digest.
    kind = ref.get("kind", NTH_ANNOUNCEMENT_KIND_V2)
    if kind not in {
        NTH_ANNOUNCEMENT_KIND_V1,
        NTH_ANNOUNCEMENT_KIND_V2,
        NTH_ANNOUNCEMENT_KIND_V3,
        NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1,
    }:
        return False
    listing_type = ref.get("listing_type", "")
    offer_digest = ref.get("offer_digest", "")
    price_asset = ref.get("price_asset", "")
    availability = ref.get("availability_summary", {})
    if kind == NTH_ANNOUNCEMENT_KIND_V3:
        if not set((*_REF_FIELDS, "federation_key")).issubset(ref):
            return False
        if listing_type not in {"product", "service"}:
            return False
        if not (
            isinstance(offer_digest, str)
            and len(offer_digest) == 71
            and offer_digest.startswith("sha256:")
            and all(ch in "0123456789abcdef" for ch in offer_digest[7:])
        ):
            return False
        if not _digest_uint(ref.get("price_minor")):
            return False
        if not _digest_text(price_asset, minimum=1, maximum=_MAX_DIGEST_ASSET_CHARS):
            return False
        if not isinstance(availability, dict):
            return False
        try:
            if len(canonical_json(availability)) > _MAX_DIGEST_AVAILABILITY_BYTES:
                return False
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False
        if (
            ref.get("price_minor") != ref.get("reward_minor")
            or price_asset != ref.get("reward_asset")
        ):
            return False
    elif kind == NTH_TRADE_OFFER_ANNOUNCEMENT_KIND_V1:
        if not set((*_REF_FIELDS, "federation_key")).issubset(ref):
            return False
        if listing_type != "exchange":
            return False
        if not (
            isinstance(offer_digest, str)
            and len(offer_digest) == 71
            and offer_digest.startswith("sha256:")
            and all(ch in "0123456789abcdef" for ch in offer_digest[7:])
        ):
            return False
        if (
            ref.get("price_minor") != 0
            or price_asset != ""
            or ref.get("reward_minor") != 0
            or ref.get("reward_asset") != "exchange"
        ):
            return False
        if not isinstance(availability, dict):
            return False
        try:
            if len(canonical_json(availability)) > _MAX_DIGEST_AVAILABILITY_BYTES:
                return False
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False
        if not _digest_text(
            availability.get("offer_id"), minimum=3, maximum=256,
        ):
            return False
        revision = availability.get("revision")
        if type(revision) is not int or not 1 <= revision <= 2_147_483_647:
            return False
        if availability.get("state") != "active":
            return False
        if ref.get("not_after") <= ref.get("published_at_ms"):
            return False
    elif (
        listing_type != "" or offer_digest != "" or ref.get("price_minor", 0) != 0
        or price_asset != "" or availability != {}
    ):
        return False
    return True


def _validate_digest_schema(
    digest: FeedDigest, *, require_signature: bool = True,
) -> Tuple[bool, str]:
    """Reject signed-but-malformed wire data before consumers touch it."""
    if digest.kind != NTH_FEED_DIGEST_KIND:
        return False, REJECT_DIGEST_SCHEMA_INVALID
    if not _digest_text(
        digest.source_did, minimum=1, maximum=_MAX_DIGEST_DID_CHARS,
    ) or not is_did_key(digest.source_did):
        return False, REJECT_DIGEST_BAD_SOURCE_DID
    if not _digest_uint(digest.generated_at_ms):
        return False, REJECT_DIGEST_SCHEMA_INVALID
    if type(digest.high_seq) is not int or not (
        -1 <= digest.high_seq <= _MAX_DIGEST_SIGNED_INT
    ):
        return False, REJECT_DIGEST_SCHEMA_INVALID
    if not isinstance(digest.refs, list) or len(digest.refs) > _MAX_DIGEST_REFS:
        return False, REJECT_DIGEST_SCHEMA_INVALID
    if any(not _validate_digest_ref(ref) for ref in digest.refs):
        return False, REJECT_DIGEST_SCHEMA_INVALID
    if require_signature:
        if not _digest_text(digest.digest_sig, minimum=1, maximum=128):
            return False, REJECT_DIGEST_MISSING_FIELD
        try:
            decoded = b64u_decode(digest.digest_sig)
            if len(decoded) != 64 or b64u_encode(decoded) != digest.digest_sig:
                return False, REJECT_DIGEST_SIG_DECODE_FAILED
        except (TypeError, ValueError, UnicodeError):
            return False, REJECT_DIGEST_SIG_DECODE_FAILED
    return True, ""


def build_digest(
    feed: "Any",  # MarketFeed
    source_identity: "Any",  # AgentIdentity，必须 can_sign
    *,
    since_seq: int = -1,
    include_expired: bool = False,
    now_ms_override: int = 0,
    limit: "Any" = None,  # Optional[int]：每个 digest 最多多少 ref，None=不限
    is_open: Optional[Callable[[TaskAnnouncement], bool]] = None,
) -> FeedDigest:
    """从本地 feed 生成签名摘要，供广播。

    只收 since_seq 之后、未过期的公告，每条压成 ref（匹配字段）。
    digest 由 source DAO 的 DID 签名（provenance）。

    ``limit`` 封顶单个 digest 的 ref 数（serve 侧防无界响应）；截断时
    ``high_seq`` 停在已收末尾，拉方据此带 ``since`` 翻下一页。
    """
    if type(since_seq) is not int or since_seq < -1:
        raise ValueError("since_seq must be an integer >= -1")
    if limit is None:
        page_limit = _MAX_DIGEST_REFS
    elif type(limit) is int and limit >= 0:
        page_limit = min(limit, _MAX_DIGEST_REFS)
    else:
        raise ValueError("limit must be a non-negative integer or None")
    if type(now_ms_override) is not int or now_ms_override < 0:
        raise ValueError("now_ms_override must be a non-negative integer")

    poll = feed.poll(
        since_seq, limit=page_limit, include_expired=include_expired,
        now_ms_override=now_ms_override,
    )
    refs: List[Dict[str, Any]] = []
    source_did = source_identity.as_did()
    for ann in poll.announcements:
        # v1 has no signed publisher-to-DAO delegation statement. Until that
        # protocol exists, a node may advertise only announcements signed by
        # its own endpoint identity; otherwise a mirror could impersonate the
        # claim authority for another publisher's valid announcement.
        if ann.effective_authority_did() != source_did:
            continue
        if is_open is not None and not is_open(ann):
            continue
        d = ann.to_dict()
        ref = {k: d.get(k) for k in _REF_FIELDS}
        ref["federation_key"] = announcement_federation_key(ann)
        refs.append(ref)

    digest = FeedDigest(
        source_did=source_did,
        generated_at_ms=now_ms_override or now_ms(),
        high_seq=poll.cursor,
        refs=refs,
    )
    schema_ok, schema_reason = _validate_digest_schema(
        digest, require_signature=False,
    )
    if not schema_ok:
        raise ValueError(f"invalid digest schema: {schema_reason}")
    sig_bytes = source_identity.sign(canonical_json(digest.signing_body()))
    digest.digest_sig = b64u_encode(sig_bytes)
    return digest


def verify_digest(digest: FeedDigest) -> Tuple[bool, str]:
    """验证 digest 的 source 签名（provenance）。

    注意：这只证明"是 source_did 广播了这批 refs"，**不**证明 refs 真实
    —— 单个 ref 的真伪要靠拉回全文后的 publisher_sig（见模块 docstring
    的信任模型）。fail-closed。
    """
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, REJECT_DIGEST_CRYPTO_UNAVAILABLE
    for required in ("kind", "source_did", "digest_sig"):
        if not getattr(digest, required, None):
            return False, REJECT_DIGEST_MISSING_FIELD
    schema_ok, schema_reason = _validate_digest_schema(digest)
    if not schema_ok:
        return False, schema_reason
    src = digest.source_did
    if not isinstance(src, str) or not is_did_key(src):
        return False, REJECT_DIGEST_BAD_SOURCE_DID
    src_hex = decode_ed25519_did_key_hex(src) or ""
    if not src_hex:
        return False, REJECT_DIGEST_BAD_SOURCE_DID
    try:
        sig_bytes = b64u_decode(str(digest.digest_sig))
    except (TypeError, ValueError, UnicodeError):
        return False, REJECT_DIGEST_SIG_DECODE_FAILED
    try:
        _VerifyKey(bytes.fromhex(src_hex)).verify(
            canonical_json(digest.signing_body()), sig_bytes,
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, REJECT_DIGEST_SIG_INVALID
    return True, ""


def _ref_to_partial_ann(ref: Dict[str, Any]) -> TaskAnnouncement:
    """把一个 ref 还原成只含匹配字段的 TaskAnnouncement（供 match() 复用）。

    缺 input_schema / acceptance / publisher_sig（ref 不带）—— 但 match()
    只看四维 + 时效，不验签，所以够用。绝不能拿这个 partial 去认领。

    独立审查修复 (M4 R2)：ref 来自**不可信** digest（联邦信任模型明确
    说 digest 是提示，任何 source 含恶意都能签名推送）。因此对每个字段
    都做**类型安全强转**，绝不裸 ``int()``/``list()`` —— 否则
    ``"reward_minor":"abc"`` 或 ``"capability_set":12345`` 这种恶意 ref
    会让消费方 ``int("abc")``/``list(int)`` 崩溃（DoS）。坏类型一律静默
    回退默认值，让匹配照常进行（反正全文层还要再验签）。
    """
    return TaskAnnouncement(
        announcement_id=_safe_str(ref.get("announcement_id")),
        publisher_did=_safe_str(ref.get("publisher_did")),
        title="",
        kind=_safe_str(ref.get("kind")) or NTH_ANNOUNCEMENT_KIND_V2,
        capability_set=_safe_str_list(ref.get("capability_set")),
        context=_safe_str(ref.get("context")) or "general",
        reward_minor=_safe_int(ref.get("reward_minor")),
        reward_asset=_safe_str(ref.get("reward_asset")) or "credit",
        published_at_ms=_safe_int(ref.get("published_at_ms")),
        not_after=_safe_int(ref.get("not_after")),
        listing_type=_safe_str(ref.get("listing_type")),
        offer_digest=_safe_str(ref.get("offer_digest")),
        price_minor=_safe_int(ref.get("price_minor")),
        price_asset=_safe_str(ref.get("price_asset")),
        availability_summary=(
            dict(ref.get("availability_summary"))
            if isinstance(ref.get("availability_summary"), dict)
            else {}
        ),
    )


def _safe_str(v: Any) -> str:
    """不可信 ref 字段 → str；非字符串一律 ""（不强转，避免 str(dict) 噪音）。"""
    return v if isinstance(v, str) else ""


def _safe_int(v: Any) -> int:
    """不可信 ref 字段 → int；bool/字符串/任何非 int 一律 0（绝不裸 int()）。"""
    if isinstance(v, bool):
        return 0
    return v if isinstance(v, int) else 0


def _safe_str_list(v: Any) -> List[str]:
    """不可信 ref 字段 → list[str]；非 list 回退 []，非字符串元素剔除。"""
    if not isinstance(v, list):
        return []
    return [x for x in v if isinstance(x, str)]


def match_digest_refs(
    digest: FeedDigest,
    sub: MarketSubscription,
    *,
    publisher_rep: float = 0.0,
    now_ms_override: int = 0,
) -> List[Dict[str, Any]]:
    """对一个（已 verify 的）digest 的 refs 跑订阅匹配，返回命中的 refs。

    复用 M2 的 ``match()``（四维归一），所以联邦发现与本地发现**同一套
    匹配语义**。返回的 ref 带 announcement_id，供下一步 ``pull``。

    调用方契约：先 ``verify_digest`` 通过再调本函数。
    """
    out: List[Dict[str, Any]] = []
    for ref in digest.refs:
        partial = _ref_to_partial_ann(ref)
        if match(partial, sub, publisher_rep=publisher_rep,
                 now_ms_override=now_ms_override).ok:
            out.append(ref)
    return out


def merge_digest_refs(digests: List[FeedDigest]) -> List[Dict[str, Any]]:
    """多源 digest 合并 + 按 announcement_id 去重（同一公告经多个中继到达）。

    去重保留第一次出现的 ref。返回扁平 ref 列表。

    注意：本函数 trust-agnostic —— 不验证各 digest 的 provenance。调用方
    应先对每个 digest ``verify_digest`` 以确认来源，再合并。即便不验，
    安全性也由后续"拉全文验签"兜底（refs 本就不可信）。
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for d in digests:
        for ref in d.refs:
            key = ref.get("federation_key") or ref.get("announcement_id")
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(ref)
    return out


def pull_announcements(
    source_feed: "Any",  # 主 DAO 的 MarketFeed（serve 侧）
    announcement_ids: List[str],
    *,
    include_expired: bool = False,
    now_ms_override: int = 0,
) -> List[TaskAnnouncement]:
    """主 DAO 的"按需拉全文"serve 侧：按 id 返回**完整且已验签**的公告。

    只返回 feed 里存在且 ``verify_announcement`` 通过的（feed.get 内部已
    验签 + 跳过篡改）。请求了但不存在/验不过的 id 静默略过 —— 拉方据此
    丢弃对应 ref（信任模型：全文验签才是真相）。

    生产中这是主 DAO 的网络 serve 端点；测试直接调。
    """
    out: List[TaskAnnouncement] = []
    for aid in announcement_ids:
        ann = source_feed.get(
            aid, include_expired=include_expired,
            now_ms_override=now_ms_override,
        )
        if ann is None:
            continue
        ok, _ = verify_announcement(ann)
        if ok:
            out.append(ann)
    return out


def pull_announcements_by_keys(
    source_feed: "Any",
    federation_keys: List[str],
    *,
    include_expired: bool = False,
    now_ms_override: int = 0,
) -> List[TaskAnnouncement]:
    """Return verified announcements selected by signed-body content hash."""
    out: List[TaskAnnouncement] = []
    for key in federation_keys:
        ann = source_feed.get_by_federation_key(
            key,
            include_expired=include_expired,
            now_ms_override=now_ms_override,
        )
        if ann is None:
            continue
        ok, _ = verify_announcement(ann)
        if ok and announcement_federation_key(ann) == key:
            out.append(ann)
    return out
