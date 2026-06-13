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
from typing import Any, Dict, List, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.market.match import match
from nth_dao.market.subscription import MarketSubscription

try:
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _VerifyKey = None  # type: ignore[assignment]


NTH_FEED_DIGEST_KIND = "nth-feed-digest-v1"

REJECT_DIGEST_MISSING_FIELD = "digest-missing-field"
REJECT_DIGEST_BAD_SOURCE_DID = "digest-bad-source-did"
REJECT_DIGEST_SIG_INVALID = "digest-sig-invalid"
REJECT_DIGEST_SIG_DECODE_FAILED = "digest-sig-decode-failed"
REJECT_DIGEST_CRYPTO_UNAVAILABLE = "digest-crypto-unavailable"

# ref 里只放匹配需要的字段（刻意不含 input_schema / acceptance）。
_REF_FIELDS = (
    "announcement_id", "publisher_did", "capability_set", "context",
    "reward_minor", "reward_asset", "published_at_ms", "not_after",
)


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
        return cls(**{k: v for k, v in data.items() if k in known})

    def signing_body(self) -> Dict[str, Any]:
        return {k: v for k, v in self.to_dict().items() if k != "digest_sig"}


def build_digest(
    feed: "Any",  # MarketFeed
    source_identity: "Any",  # AgentIdentity，必须 can_sign
    *,
    since_seq: int = -1,
    include_expired: bool = False,
    now_ms_override: int = 0,
) -> FeedDigest:
    """从本地 feed 生成签名摘要，供广播。

    只收 since_seq 之后、未过期的公告，每条压成 ref（匹配字段）。
    digest 由 source DAO 的 DID 签名（provenance）。
    """
    poll = feed.poll(
        since_seq, include_expired=include_expired,
        now_ms_override=now_ms_override,
    )
    refs: List[Dict[str, Any]] = []
    for ann in poll.announcements:
        d = ann.to_dict()
        refs.append({k: d.get(k) for k in _REF_FIELDS})

    digest = FeedDigest(
        source_did=source_identity.as_did(),
        generated_at_ms=now_ms_override or now_ms(),
        high_seq=poll.cursor,
        refs=refs,
    )
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
    src = digest.source_did
    if not isinstance(src, str) or not is_did_key(src):
        return False, REJECT_DIGEST_BAD_SOURCE_DID
    src_hex = decode_ed25519_did_key_hex(src) or ""
    if not src_hex:
        return False, REJECT_DIGEST_BAD_SOURCE_DID
    try:
        sig_bytes = b64u_decode(str(digest.digest_sig))
    except Exception:  # noqa: BLE001
        return False, REJECT_DIGEST_SIG_DECODE_FAILED
    try:
        _VerifyKey(bytes.fromhex(src_hex)).verify(
            canonical_json(digest.signing_body()), sig_bytes,
        )
    except Exception:  # noqa: BLE001
        return False, REJECT_DIGEST_SIG_INVALID
    return True, ""


def _ref_to_partial_ann(ref: Dict[str, Any]) -> TaskAnnouncement:
    """把一个 ref 还原成只含匹配字段的 TaskAnnouncement（供 match() 复用）。

    缺 input_schema / acceptance / publisher_sig（ref 不带）—— 但 match()
    只看四维 + 时效，不验签，所以够用。绝不能拿这个 partial 去认领。
    """
    return TaskAnnouncement(
        announcement_id=str(ref.get("announcement_id", "")),
        publisher_did=str(ref.get("publisher_did", "")),
        title="",
        capability_set=list(ref.get("capability_set") or []),
        context=str(ref.get("context") or "general"),
        reward_minor=int(ref.get("reward_minor") or 0),
        reward_asset=str(ref.get("reward_asset") or "credit"),
        published_at_ms=int(ref.get("published_at_ms") or 0),
        not_after=int(ref.get("not_after") or 0),
    )


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
            aid = ref.get("announcement_id")
            if not aid or aid in seen:
                continue
            seen.add(aid)
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
