"""Capability delegation tokens — L1-3 (2026-06-08).

Strategic role: this is the "注意力集中 / 任务专注" engine the user
asked for. Without it the only auth NTH DAO exposes is the operator-
level ``console_token`` — full power, all or nothing. A helper Agent
delegated by the admin to do ONE thing on ONE task would need the
operator's full token, which is a serious over-grant.

A capability token narrows that: the issuer (admin, with the workspace
keypair) signs a short-lived envelope saying "this subject DID may
invoke these capabilities, optionally scoped to a specific A2A task
or a specific DAO, between not_before and not_after". The subject
presents the token in ``Authorization: CapToken <b64u>`` header.

Wire format (``nth-cap-token-v1``):

  kind:            "nth-cap-token-v1"
  spec:            "nth-dao/cap-token@1.0"
  token_id:        uuid hex (audit + revocation key)
  issuer_did:      did:key:z… (the admin/operator)
  subject_did:     did:key:z… (the helper Agent that may act)
  capabilities:    sorted list of cap strings
  scope_task_id:   string ("" → not bound to a specific task)
  scope_dao:       string ("" → not bound to a specific DAO)
  not_before:      int epoch ms
  not_after:       int epoch ms (TTL ≤ 1 week)
  nonce:           random hex (defeats replay against tokens with
                   identical content)
  sig:             base64url(Ed25519 over canonical_json(
                     token-excluding-sig))

Capability vocabulary (namespaced like motebit's event types):

  a2a:message_send   — POST /api/a2a/rpc method message/send
  a2a:task_get       — POST /api/a2a/rpc method tasks/get
  a2a:task_cancel    — POST /api/a2a/rpc method tasks/cancel
  nth:post_message   — POST /api/messages (NTH-native chat)
  nth:add_member     — POST /api/agents/add (admin-grade)

The verifier MUST check ALL of:
  1. Time bounds: not_before ≤ now ≤ not_after
  2. Revocation: token_id is not in the revoked set
  3. Signature: Ed25519 verify against the issuer_did's pubkey
  4. Capability sufficiency: required ⊆ token.capabilities
  5. Scope match: when ``required_task_id`` is set, it must equal
     ``token.scope_task_id`` (or token has empty scope = unrestricted)

The fail-closed contract: any check failure → reject and return a
specific machine-readable reason so audit logs can distinguish
expiry from revocation from sig forgery.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import (
    TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple,
)

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import _NACL_AVAILABLE

try:
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:
    _VerifyKey = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from nth_dao.identity import AgentIdentity

logger = logging.getLogger("nth_dao.cap_token")


# ─── capability vocabulary ───────────────────────────────────────────

CAP_A2A_MESSAGE_SEND = "a2a:message_send"
CAP_A2A_TASK_GET = "a2a:task_get"
CAP_A2A_TASK_CANCEL = "a2a:task_cancel"
# L1-4 (2026-06-08): splitting a Task into a structured Mission is
# a structural change with much wider blast radius than appending a
# message. A helper Agent delegated to send messages on task X should
# NOT automatically be able to restructure task X into a 50-step
# orchestration. Modelled as a separate capability so issuer must
# grant it explicitly.
CAP_A2A_TASK_SPLIT = "a2a:task_split"
CAP_NTH_POST_MESSAGE = "nth:post_message"
CAP_NTH_ADD_MEMBER = "nth:add_member"
# C2 (DESIGN_TRADE_OFFS §2 + Appendix B, 2026-06-08): the
# capability an ephemeral subject DID must hold in order to sign
# execution receipts that chain back to the issuer's root authority.
# Naming follows the nth: verb_noun convention (see Appendix B).
CAP_NTH_RECEIPT_SIGN = "nth:receipt_sign"

KNOWN_CAPABILITIES = frozenset({
    CAP_A2A_MESSAGE_SEND,
    CAP_A2A_TASK_GET,
    CAP_A2A_TASK_CANCEL,
    CAP_A2A_TASK_SPLIT,
    CAP_NTH_POST_MESSAGE,
    CAP_NTH_ADD_MEMBER,
    CAP_NTH_RECEIPT_SIGN,
})


# ─── version pins ────────────────────────────────────────────────────

NTH_CAP_TOKEN_KIND = "nth-cap-token-v1"
NTH_CAP_TOKEN_SPEC = "nth-dao/cap-token@1.0"

# Validity windows
DEFAULT_TTL_MS = 60 * 60 * 1000          # 1 hour
MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000     # 1 week

# Authorization header scheme — distinguishes cap tokens from the
# operator's console Bearer token at the HTTP layer.
AUTH_SCHEME_CAP_TOKEN = "CapToken"


# ─── reject reasons (machine-readable, audit-friendly) ──────────────

REJECT_MISSING_FIELD = "missing-field"
REJECT_BAD_KIND = "bad-kind"
REJECT_NOT_YET_VALID = "not-yet-valid"
REJECT_EXPIRED = "expired"
REJECT_REVOKED = "revoked"
REJECT_BAD_ISSUER_DID = "bad-issuer-did"
REJECT_SIG_INVALID = "sig-invalid"
REJECT_CAP_INSUFFICIENT = "cap-insufficient"
REJECT_SCOPE_MISMATCH = "scope-mismatch"
REJECT_CRYPTO_UNAVAILABLE = "crypto-unavailable"
REJECT_SIG_DECODE_FAILED = "sig-decode-failed"


# ─── sign ────────────────────────────────────────────────────────────


def sign_cap_token(
    *,
    issuer: "AgentIdentity",
    subject_did: str,
    capabilities: Iterable[str],
    scope_task_id: str = "",
    scope_dao: str = "",
    scope_model_allowlist: Optional[List[str]] = None,
    ttl_ms: int = DEFAULT_TTL_MS,
    token_id: str = "",
) -> Dict[str, Any]:
    """Issue a signed capability token.

    Args:
        issuer: the workspace ``AgentIdentity`` — must hold a signing key.
        subject_did: did:key of the bearer who will present this token.
        capabilities: iterable of capability strings. Deduplicated +
            sorted for byte-stable canonical form. Empty input rejected.
        scope_task_id: optional A2A task id binding. Empty = no
            task scope (token holder can act on any task in
            capabilities).
        scope_dao: optional DAO slug binding. Empty = no DAO scope.
        scope_model_allowlist: Phase 6b — optional per-token model
            scope for the A2A ``ask``/``ask-stream`` ``params['model']``
            override. Semantics by value:

              • ``None``        — field is omitted from the token body.
                                  Means "no per-token scope; the A2A
                                  handler defers to the backend's
                                  ``MODEL_ALLOWLIST``." Backward-compat
                                  for tokens issued before 6b.
              • ``[]``  (empty) — field is present and empty. Means
                                  "this token forbids all model
                                  OVERRIDES via ``params['model']``."
                                  Important asymmetry (I-2 R2):
                                  ``[]`` does NOT prevent the backend
                                  from running on its DEFAULT_MODEL —
                                  the empty scope only blocks the
                                  override path. To pin peers to the
                                  cheapest model, set
                                  ``_AskBackend.DEFAULT_MODEL`` AND
                                  use ``[]`` so peers can neither
                                  pick a model nor escape the default.
              • non-empty list  — field is present. Means "this token
                                  allows ONLY these models." The A2A
                                  handler intersects this with the
                                  backend's ``MODEL_ALLOWLIST`` so the
                                  scope can only narrow, never widen.

            Per-token scope lets one hub issue tokens with different
            cost allowances to different peers — a "trusted peer" gets
            sonnet+haiku, a "lower-trust peer" gets only haiku.
        ttl_ms: token lifetime in milliseconds. Capped at MAX_TTL_MS.
            Default 1 hour.
        token_id: optional caller-supplied uuid; minted if absent.

    Raises:
        ValueError on bad input (empty caps, bad subject DID, ttl
        out of range, bad model_allowlist shape).
        RuntimeError if the issuer cannot sign.
    """
    caps_list = sorted({c for c in capabilities})
    if not caps_list:
        raise ValueError("at least one capability required")
    for c in caps_list:
        if not isinstance(c, str) or not c:
            raise ValueError(
                f"capability entries must be non-empty strings; got {c!r}"
            )
    if not isinstance(ttl_ms, int) or ttl_ms <= 0:
        raise ValueError(f"ttl_ms must be a positive int; got {ttl_ms!r}")
    if ttl_ms > MAX_TTL_MS:
        raise ValueError(
            f"ttl_ms {ttl_ms} exceeds maximum {MAX_TTL_MS} ms "
            f"(1 week). Long-lived delegations should be re-issued "
            f"on a schedule, not granted in one token."
        )
    if not isinstance(subject_did, str) or not is_did_key(subject_did):
        raise ValueError(
            f"subject_did must be a did:key; got {subject_did!r}"
        )

    rid = token_id or uuid.uuid4().hex
    # Token IDs become file paths in the audit store; reject anything
    # that wouldn't survive a flat-filename round trip.
    if not all(c.isalnum() or c == "-" for c in rid):
        raise ValueError(
            f"token_id must be alphanumeric (or dash); got {rid!r}"
        )

    # Phase 6b: 校验 model 名单的形状 —— 必须是 list[str]，每个
    # 元素都是非空字符串。None 表示 "字段不上 wire"，跟空 list
    # 是两个不同语义（见 docstring），不要 normalize 成同一个。
    # 6B-9 自审 (Phase 6b R1): 同时 strip 每个 entry —— operator
    # 写 ``"claude-sonnet-4-6 "`` (尾巴一个空格) 会跟 peer 后面
    # 不带空格的 ``params['model']="claude-sonnet-4-6"`` 因为
    # 严格相等比对而不命中，构成静默 mismatch。strip 之后再判空。
    if scope_model_allowlist is not None:
        if not isinstance(scope_model_allowlist, list):
            raise ValueError(
                "scope_model_allowlist must be a list[str] or None; "
                f"got {type(scope_model_allowlist).__name__}"
            )
        normalized_scope: List[str] = []
        for m in scope_model_allowlist:
            if not isinstance(m, str):
                raise ValueError(
                    "scope_model_allowlist entries must be strings; "
                    f"got {m!r}"
                )
            stripped = m.strip()
            if not stripped:
                raise ValueError(
                    "scope_model_allowlist entries must be non-empty "
                    f"after strip; got {m!r}"
                )
            normalized_scope.append(stripped)
        # 用 normalize 后的 list 替换 caller 传进来的版本，
        # 后面写 body 时直接用它。
        scope_model_allowlist = normalized_scope

    now = now_ms()
    body = {
        "kind": NTH_CAP_TOKEN_KIND,
        "spec": NTH_CAP_TOKEN_SPEC,
        "token_id": rid,
        "issuer_did": issuer.as_did(),
        "subject_did": subject_did,
        "capabilities": caps_list,
        "scope_task_id": scope_task_id,
        "scope_dao": scope_dao,
        "not_before": now,
        "not_after": now + ttl_ms,
        "nonce": uuid.uuid4().hex,
    }
    # Phase 6b: 只在 caller 显式给了 scope_model_allowlist 才上 wire,
    # 以保留 6a 前签发的旧 token 的字节级 stable signature。
    # 排序：跟 capabilities 一样去重 + 排序，让 canonical bytes
    # 不依赖输入顺序。
    if scope_model_allowlist is not None:
        body["scope_model_allowlist"] = sorted(set(scope_model_allowlist))
    sig_bytes = issuer.sign(canonical_json(body))
    body["sig"] = b64u_encode(sig_bytes)
    return body


# ─── verify ──────────────────────────────────────────────────────────


def verify_cap_token(
    token: Dict[str, Any],
    *,
    now_ms_override: int = 0,
    revoked_ids: Optional[Set[str]] = None,
    required_capabilities: Optional[Iterable[str]] = None,
    required_task_id: str = "",
    required_dao: str = "",
) -> Tuple[bool, str]:
    """Verify a capability token presented at request time.

    All five checks (shape, time, revocation, capability, scope, sig)
    are run; the first failure short-circuits with a machine-readable
    reason so audit logs can distinguish expiry from revocation from
    sig forgery.

    Args:
        token: the parsed token dict.
        now_ms_override: for tests — pin the clock.
        revoked_ids: caller passes the current revocation set
            (typically loaded from CapTokenStore). None = no
            revocation check.
        required_capabilities: iterable of caps the request needs.
            ALL must be in token.capabilities.
        required_task_id: if set, must equal token.scope_task_id
            (or token has empty scope, meaning unrestricted).
        required_dao: same as task_id, for DAO scope.

    Returns:
        (ok, reason). ``ok=True`` → reason is "". ``ok=False`` →
        reason is one of the REJECT_* constants.
    """
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, REJECT_CRYPTO_UNAVAILABLE

    # Shape: required fields all present
    for required in (
        "kind", "issuer_did", "subject_did", "capabilities",
        "not_before", "not_after", "sig", "token_id",
    ):
        if required not in token:
            return False, REJECT_MISSING_FIELD
    if token["kind"] != NTH_CAP_TOKEN_KIND:
        return False, REJECT_BAD_KIND

    # Time bounds (before crypto — cheap to reject, no side channel)
    now = now_ms_override or now_ms()
    try:
        nbf = int(token["not_before"])
        exp = int(token["not_after"])
    except (TypeError, ValueError):
        return False, REJECT_MISSING_FIELD
    if now < nbf:
        return False, REJECT_NOT_YET_VALID
    if now > exp:
        return False, REJECT_EXPIRED

    # Revocation
    if revoked_ids and token["token_id"] in revoked_ids:
        return False, REJECT_REVOKED

    # Capability sufficiency: every required cap must be in the token
    token_caps = set(token["capabilities"])
    if required_capabilities is not None:
        needed = set(required_capabilities)
        if not needed <= token_caps:
            return False, REJECT_CAP_INSUFFICIENT

    # Scope match: required task/DAO must match if token has scope
    if required_task_id:
        scope = token.get("scope_task_id", "")
        if scope and scope != required_task_id:
            return False, REJECT_SCOPE_MISMATCH
    if required_dao:
        scope = token.get("scope_dao", "")
        if scope and scope != required_dao:
            return False, REJECT_SCOPE_MISMATCH

    # Signature verification (most expensive — last)
    issuer_did = token["issuer_did"]
    if not isinstance(issuer_did, str) or not is_did_key(issuer_did):
        return False, REJECT_BAD_ISSUER_DID
    issuer_pubkey_hex = decode_ed25519_did_key_hex(issuer_did) or ""
    if not issuer_pubkey_hex:
        return False, REJECT_BAD_ISSUER_DID

    body = {k: v for k, v in token.items() if k != "sig"}
    try:
        sig_bytes = b64u_decode(str(token["sig"]))
    except Exception:  # noqa: BLE001
        return False, REJECT_SIG_DECODE_FAILED

    try:
        _VerifyKey(bytes.fromhex(issuer_pubkey_hex)).verify(
            canonical_json(body), sig_bytes,
        )
    except Exception:  # noqa: BLE001
        return False, REJECT_SIG_INVALID

    return True, ""


# ─── Phase 6b: per-token model-allowlist helper ──────────────────────


REJECT_MODEL_NOT_IN_TOKEN_SCOPE = "model-not-in-token-scope"


def token_allows_model(
    token: Dict[str, Any], requested_model: str,
) -> Tuple[bool, str]:
    """Phase 6b: check a verified cap_token's per-token model scope.

    Caller contract: ``token`` MUST have already been verified by
    ``verify_cap_token`` first. This function does not re-verify —
    it only inspects the ``scope_model_allowlist`` field.

    Args:
        token: a verified cap_token dict.
        requested_model: the (stripped) model name from
            ``params['model']``. Empty string is treated as "no
            override" and returns OK regardless of scope.

    Returns:
        (ok, reason):
            • ``(True, "")`` if the token has no scope_model_allowlist
              (legacy / "defer to backend"), OR the requested model is
              in the scope.
            • ``(False, REJECT_MODEL_NOT_IN_TOKEN_SCOPE)`` if the scope
              is present and the requested model isn't in it.

    Semantics on missing / empty field:
        • Field absent       → no per-token scope → defer to backend.
        • Field present, []  → token forbids ALL ``params['model']``
                               OVERRIDES. NOTE (I-2 R2 doc fix): this
                               only restricts the override path. A
                               peer who omits ``params['model']``
                               still gets the BACKEND'S
                               ``DEFAULT_MODEL`` — the empty scope
                               does NOT prevent operator-pinned
                               defaults from being used. Operators
                               wanting a true cost floor must set
                               ``_AskBackend.DEFAULT_MODEL`` to the
                               cheapest model, then use ``[]`` to
                               freeze peers there.
        • Field present list → token allows ONLY these.

    This sits BESIDE the backend's ``MODEL_ALLOWLIST`` — both must
    pass. The A2A handler should call this first (cheap inline
    check) and let the backend's ``_check_model_allowed`` enforce
    its own policy second. Final permission = intersection.
    """
    if not requested_model:
        return True, ""
    if "scope_model_allowlist" not in token:
        return True, ""
    scope = token["scope_model_allowlist"]
    if not isinstance(scope, list):
        # Malformed scope field — fail closed.
        return False, REJECT_MODEL_NOT_IN_TOKEN_SCOPE
    if requested_model in scope:
        return True, ""
    return False, REJECT_MODEL_NOT_IN_TOKEN_SCOPE


# ─── envelope codec for the Authorization header ─────────────────────


def encode_authorization_header(token: Dict[str, Any]) -> str:
    """Return a value suitable for ``Authorization: CapToken <value>``.

    The encoding is ``base64url(canonical_json(token))``. canonical
    JSON guarantees the bytes-on-wire are stable across producers
    (so we can re-verify the signature without seeing the original
    JSON formatting).
    """
    return b64u_encode(canonical_json(token))


def decode_authorization_value(value: str) -> Optional[Dict[str, Any]]:
    """Reverse of ``encode_authorization_header``.

    Returns None on malformed input rather than raising — middleware
    needs to fail-closed gracefully without exception leaks.
    """
    try:
        raw = b64u_decode(value)
        return json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


# ─── persistent store ────────────────────────────────────────────────


class CapTokenStore:
    """File-backed audit + revocation store.

    Layout:
        <workspace>/team_cap_tokens/
            <token_id>.json         — issued-token audit records
            revoked.json            — {"revoked": [<token_id>, …]}

    All writes are atomic via temp + replace, like ``ReceiptStore``.
    Revocation is monotonic: a token_id once revoked stays revoked;
    the store doesn't support un-revoking (revocation is a one-way
    operation per the L1-3 contract).
    """

    SUFFIX = ".json"
    REVOKED_FILE = "revoked.json"

    def __init__(self, workspace: Path) -> None:
        self.root = Path(workspace) / "team_cap_tokens"
        self.root.mkdir(parents=True, exist_ok=True)
        self.revoked_path = self.root / self.REVOKED_FILE

    # ── audit ────────────────────────────────────────────────────

    def record(self, token: Dict[str, Any]) -> Path:
        """Persist an issued token. Atomic write."""
        tid = str(token.get("token_id", "") or "")
        if not tid or not all(c.isalnum() or c == "-" for c in tid):
            raise ValueError(f"invalid token_id {tid!r}")
        path = self.root / (tid + self.SUFFIX)
        tmp = path.with_suffix(self.SUFFIX + ".tmp")
        tmp.write_text(
            json.dumps(token, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(str(tmp), str(path))
        return path

    def get(self, token_id: str) -> Optional[Dict[str, Any]]:
        if not token_id or not all(
            c.isalnum() or c == "-" for c in token_id
        ):
            return None
        path = self.root / (token_id + self.SUFFIX)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # ── revocation ───────────────────────────────────────────────

    def revoked_set(self) -> Set[str]:
        """Current revocation list, fresh from disk every call.

        v1 doesn't cache — revocation should take effect within one
        request cycle, and the file is small enough that re-reading
        per request is cheap.
        """
        if not self.revoked_path.exists():
            return set()
        try:
            data = json.loads(self.revoked_path.read_text(encoding="utf-8"))
            return set(str(t) for t in data.get("revoked", []))
        except (OSError, json.JSONDecodeError):
            return set()

    def revoke(self, token_id: str) -> bool:
        """Add ``token_id`` to the revoked set. Returns True iff this
        call mutated the set (False if already revoked).
        """
        if not token_id or not all(
            c.isalnum() or c == "-" for c in token_id
        ):
            raise ValueError(f"invalid token_id {token_id!r}")
        current = self.revoked_set()
        if token_id in current:
            return False
        current.add(token_id)
        tmp = self.revoked_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(
                {"revoked": sorted(current)},
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
        os.replace(str(tmp), str(self.revoked_path))
        return True
