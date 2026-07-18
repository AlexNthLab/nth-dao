"""Seller-signed, content-addressed product/service listings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key
from nth_dao.identity import _NACL_AVAILABLE
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json
from nth_dao.commerce.money import decimal_to_minor

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]

PathLike = Union[str, Path]
NTH_COMMERCE_LISTING_KIND = "nth-commerce-listing-v1"
LISTING_PRODUCT = "product"
LISTING_SERVICE = "service"
LISTING_TYPES = frozenset({LISTING_PRODUCT, LISTING_SERVICE})
_METHOD = re.compile(r"^[a-z][a-z0-9_]{0,15}:[a-z0-9][a-z0-9_]{0,31}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ListingRejected(ValueError):
    pass


@dataclass
class SignedListing:
    listing_id: str
    listing_type: str
    seller_did: str
    title: str
    description: str
    price_value: str
    price_currency: str
    settlement_methods: List[str]
    details: Dict[str, Any] = field(default_factory=dict)
    published_at_ms: int = 0
    not_after_ms: int = 0
    kind: str = NTH_COMMERCE_LISTING_KIND
    seller_sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_body(self) -> Dict[str, Any]:
        return {k: v for k, v in self.to_dict().items() if k != "seller_sig"}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedListing":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        if not isinstance(data, dict) or set(data) != known:
            raise ListingRejected("listing has missing or unknown fields")
        return cls(**data)


def _validate_shape(listing: SignedListing) -> Tuple[bool, str]:
    if listing.kind != NTH_COMMERCE_LISTING_KIND:
        return False, "wrong listing kind"
    if not isinstance(listing.listing_id, str) or not (1 <= len(listing.listing_id) <= 128):
        return False, "invalid listing_id"
    if listing.listing_type not in LISTING_TYPES:
        return False, "invalid listing_type"
    if not isinstance(listing.title, str) or not (1 <= len(listing.title) <= 200):
        return False, "invalid title"
    if not isinstance(listing.description, str) or len(listing.description) > 4000:
        return False, "invalid description"
    if not is_did_key(listing.seller_did):
        return False, "invalid seller_did"
    if isinstance(listing.published_at_ms, bool) or not isinstance(listing.published_at_ms, int) or listing.published_at_ms <= 0:
        return False, "invalid published_at_ms"
    if isinstance(listing.not_after_ms, bool) or not isinstance(listing.not_after_ms, int) or listing.not_after_ms <= listing.published_at_ms:
        return False, "invalid not_after_ms"
    try:
        decimal_to_minor(listing.price_value, listing.price_currency, require_positive=True)
    except ValueError as exc:
        return False, f"invalid price: {exc}"
    methods = listing.settlement_methods
    if not isinstance(methods, list) or not methods or len(methods) > 16:
        return False, "invalid settlement_methods"
    if any(not isinstance(m, str) or not _METHOD.fullmatch(m) for m in methods):
        return False, "invalid settlement method"
    if len(set(methods)) != len(methods):
        return False, "duplicate settlement method"
    if not isinstance(listing.details, dict):
        return False, "details must be an object"
    try:
        if len(canonical_json(listing.details)) > 32_768:
            return False, "details too large"
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return False, f"details are not canonical JSON: {exc}"
    return True, "ok"


def sign_listing(identity: Any, listing: SignedListing) -> SignedListing:
    if identity.as_did() != listing.seller_did:
        raise ListingRejected("signer does not match seller_did")
    ok, reason = _validate_shape(listing)
    if not ok:
        raise ListingRejected(reason)
    listing.seller_sig = b64u_encode(identity.sign(canonical_json(listing.signing_body())))
    return listing


def verify_listing(listing: SignedListing) -> Tuple[bool, str]:
    ok, reason = _validate_shape(listing)
    if not ok:
        return False, reason
    if not _NACL_AVAILABLE or _VerifyKey is None:
        return False, "crypto unavailable"
    key_hex = decode_ed25519_did_key_hex(listing.seller_did) or ""
    if not isinstance(listing.seller_sig, str) or not (
        1 <= len(listing.seller_sig) <= 128
    ):
        return False, "seller signature invalid"
    try:
        signature = b64u_decode(listing.seller_sig)
        if len(signature) != 64 or b64u_encode(signature) != listing.seller_sig:
            return False, "seller signature invalid"
        _VerifyKey(bytes.fromhex(key_hex)).verify(
            canonical_json(listing.signing_body()), signature
        )
    except (_BadSignatureError, TypeError, ValueError, UnicodeError):
        return False, "seller signature invalid"
    return True, "ok"


def listing_digest(listing: SignedListing) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(listing.to_dict())).hexdigest()


class ListingStore:
    def __init__(self, root: PathLike) -> None:
        self.root = Path(root) / "commerce" / "listings"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ListingRejected("invalid listing digest")
        return self.root / f"{digest[7:]}.json"

    def save(self, listing: SignedListing) -> str:
        ok, reason = verify_listing(listing)
        if not ok:
            raise ListingRejected(reason)
        digest = listing_digest(listing)
        path = self._path(digest)
        with InterProcessLock(path):
            existing = safe_load_json(path, fallback=None)
            document = listing.to_dict()
            if path.exists() and existing is None:
                raise ListingRejected("stored listing is unreadable; refuse to overwrite")
            if existing is not None and existing != document:
                raise ListingRejected("content-address collision")
            if existing is None:
                atomic_write_json(path, document)
        return digest

    def get(self, digest: str) -> SignedListing | None:
        data = safe_load_json(self._path(digest), fallback=None)
        if not isinstance(data, dict):
            return None
        try:
            listing = SignedListing.from_dict(data)
        except (TypeError, ValueError):
            return None
        ok, _ = verify_listing(listing)
        if not ok or listing_digest(listing) != digest:
            return None
        return listing
