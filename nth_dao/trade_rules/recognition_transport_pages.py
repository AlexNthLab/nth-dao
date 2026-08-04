"""Signed, bounded pages for complete Rule Recognition graph federation."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from nth_dao.did_key import is_did_key
from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.package_binding import (
    OfferPackageBindingRejected,
    SignedOfferPackageBinding,
    require_offer_package_binding,
)
from nth_dao.trade_rules.package_store import RulePackage
from nth_dao.trade_rules.recognition import (
    MAX_RULE_RECOGNITION_STATEMENTS,
    TradeRuleRecognition,
)
from nth_dao.trade_rules.recognition_transport import (
    DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_CLOCK_SKEW_SECONDS,
    DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS,
    MAX_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS,
    RuleRecognitionProofBundleRejected,
    _clock_skew,
    _format_timestamp,
    _heads_digest,
    _timestamp,
    _utc_now,
    _validate_chain,
    _verified_package,
    _verified_statement,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

RULE_RECOGNITION_PROOF_PAGE_KIND = (
    "nth.dao.trade.rule-recognition-proof-page"
)
RULE_RECOGNITION_PROOF_PAGE_PROTOCOL_VERSION = "2"
RULE_RECOGNITION_PROOF_PAGE_PROOF_TYPE = "NthEd25519SignatureV1"
RULE_RECOGNITION_PROOF_PAGE_PROOF_PURPOSE = (
    "tradeRuleRecognitionObservationPage"
)
RULE_RECOGNITION_PROOF_PAGE_SIGNING_DOMAIN = (
    b"nth-dao/trade-rule-recognition-proof-page/v2"
)
MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS = 128
MAX_RULE_RECOGNITION_PROOF_PAGES = 1_024
MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES = 256 * 1024
MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES = 64 * 1024 * 1024
_PAGE_TARGET_STATEMENT_BYTES = 160 * 1024

_PAGE_FIELDS = frozenset({
    "kind",
    "protocol_version",
    "offer_digest",
    "offer_package_binding",
    "package_digest",
    "observer_did",
    "observed_at",
    "not_after",
    "observation_digest",
    "graph_heads_digest",
    "statement_set_digest",
    "statement_count",
    "page_index",
    "page_count",
    "issuer_segments",
    "proof",
})
_SEGMENT_FIELDS = frozenset({
    "issuer_did",
    "previous_statement_digest",
    "statements",
})
_PROOF_FIELDS = frozenset({
    "type",
    "created",
    "verification_method",
    "proof_purpose",
    "proof_value",
})


def _digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(trade_canonical_json(value)).hexdigest()


def _statement_set_digest(
    statements: Iterable[TradeRuleRecognition],
) -> str:
    return _digest({
        "statement_digests": sorted(statement.digest for statement in statements)
    })


def _observation_projection(
    *,
    offer_digest: str,
    package_digest: str,
    observer_did: str,
    observed_at: str,
    not_after: str,
    graph_heads_digest: str,
    statement_set_digest: str,
    statement_count: int,
    page_count: int,
) -> dict[str, Any]:
    return {
        "offer_digest": offer_digest,
        "package_digest": package_digest,
        "observer_did": observer_did,
        "observed_at": observed_at,
        "not_after": not_after,
        "graph_heads_digest": graph_heads_digest,
        "statement_set_digest": statement_set_digest,
        "statement_count": statement_count,
        "page_count": page_count,
    }


def _page_observation_digest(document: dict[str, Any]) -> str:
    return _digest(_observation_projection(
        offer_digest=document["offer_digest"],
        package_digest=document["package_digest"],
        observer_did=document["observer_did"],
        observed_at=document["observed_at"],
        not_after=document["not_after"],
        graph_heads_digest=document["graph_heads_digest"],
        statement_set_digest=document["statement_set_digest"],
        statement_count=document["statement_count"],
        page_count=document["page_count"],
    ))


def _verify_page_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(
            RULE_RECOGNITION_PROOF_PAGE_SIGNING_DOMAIN,
            document,
        )
    except TradeProofError as exc:
        raise RuleRecognitionProofBundleRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["observer_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        raise RuleRecognitionProofBundleRejected(
            f"Recognition proof page observer {reason}"
        )


def _validate_segments(
    value: Any,
    *,
    package: RulePackage,
) -> tuple[TradeRuleRecognition, ...]:
    if not isinstance(value, list):
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page issuer_segments must be an array"
        )
    output: list[TradeRuleRecognition] = []
    previous_issuer = ""
    for segment in value:
        if not isinstance(segment, dict) or set(segment) != _SEGMENT_FIELDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page segment fields are invalid"
            )
        issuer = segment["issuer_did"]
        raw_statements = segment["statements"]
        if (
            not isinstance(issuer, str)
            or not is_did_key(issuer)
            or issuer <= previous_issuer
            or not isinstance(raw_statements, list)
            or not raw_statements
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page segments must be unique and DID-sorted"
            )
        previous_issuer = issuer
        statements = tuple(
            _verified_statement(item, package=package)
            for item in raw_statements
        )
        if any(
            statement.to_dict()["issuer_did"] != issuer
            for statement in statements
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page segment contains another issuer"
            )
        ordered = tuple(sorted(
            statements,
            key=lambda statement: (
                statement.to_dict()["sequence"],
                statement.digest,
            ),
        ))
        if ordered != statements:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page segment is not sequence-sorted"
            )
        first_previous = statements[0].to_dict()["previous_statement_digest"]
        if segment["previous_statement_digest"] != first_previous:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page predecessor commitment is invalid"
            )
        for previous, current in zip(statements, statements[1:]):
            previous_document = previous.to_dict()
            current_document = current.to_dict()
            if (
                current_document["sequence"] != previous_document["sequence"] + 1
                or current_document["previous_statement_digest"]
                != previous.digest
            ):
                raise RuleRecognitionProofBundleRejected(
                    "Recognition proof page segment is not contiguous"
                )
        output.extend(statements)
    if len(output) > MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page statement count exceeds its limit"
        )
    return tuple(output)


@dataclass(frozen=True, init=False)
class VerifiedRuleRecognitionProofPage:
    _canonical_bytes: bytes
    _statements: tuple[TradeRuleRecognition, ...]

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        package: RulePackage,
        expected_offer_digest: str | None = None,
        expected_offer_publisher_did: str | None = None,
        now: datetime | None = None,
        clock_skew_seconds: float = (
            DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_CLOCK_SKEW_SECONDS
        ),
    ) -> "VerifiedRuleRecognitionProofPage":
        verified_package = _verified_package(package)
        if not isinstance(value, dict) or set(value) != _PAGE_FIELDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page fields are invalid"
            )
        if (
            value["kind"] != RULE_RECOGNITION_PROOF_PAGE_KIND
            or value["protocol_version"]
            != RULE_RECOGNITION_PROOF_PAGE_PROTOCOL_VERSION
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page kind or version is unsupported"
            )
        try:
            binding = require_offer_package_binding(
                value["offer_package_binding"],
                expected_offer_digest=(
                    expected_offer_digest or value["offer_digest"]
                ),
                expected_package_digest=verified_package.digest,
                expected_publisher_did=expected_offer_publisher_did,
            )
        except OfferPackageBindingRejected as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        if (
            value["offer_digest"] != binding.offer_digest
            or value["package_digest"] != verified_package.digest
            or value["observer_did"] != binding.publisher_did
            or not is_did_key(value["observer_did"])
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page binding is inconsistent"
            )
        observed_at = _timestamp(value["observed_at"], label="observed_at")
        not_after = _timestamp(value["not_after"], label="not_after")
        if not_after <= observed_at:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page not_after must follow observed_at"
            )
        if (
            not_after - observed_at
        ).total_seconds() > MAX_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page TTL exceeds its limit"
            )
        moment = _utc_now(now)
        skew = _clock_skew(clock_skew_seconds)
        if observed_at > moment + timedelta(seconds=skew):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page observation is in the future"
            )
        if moment >= not_after:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page has expired"
            )
        for field in (
            "statement_count",
            "page_index",
            "page_count",
        ):
            if isinstance(value[field], bool) or not isinstance(value[field], int):
                raise RuleRecognitionProofBundleRejected(
                    f"Recognition proof page {field} is invalid"
                )
        if (
            not 0 <= value["statement_count"] <= MAX_RULE_RECOGNITION_STATEMENTS
            or not 1 <= value["page_count"] <= MAX_RULE_RECOGNITION_PROOF_PAGES
            or not 0 <= value["page_index"] < value["page_count"]
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page bounds are invalid"
            )
        for field in (
            "observation_digest",
            "graph_heads_digest",
            "statement_set_digest",
        ):
            field_value = value[field]
            if (
                not isinstance(field_value, str)
                or len(field_value) != 71
                or not field_value.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in field_value[7:]
                )
            ):
                raise RuleRecognitionProofBundleRejected(
                    f"Recognition proof page {field} is invalid"
                )
        if value["observation_digest"] != _page_observation_digest(value):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page observation commitment is invalid"
            )
        statements = _validate_segments(
            value["issuer_segments"],
            package=verified_package,
        )
        if value["statement_count"] == 0:
            if value["page_count"] != 1 or statements:
                raise RuleRecognitionProofBundleRejected(
                    "empty Recognition graph must use one empty page"
                )
        elif not statements:
            raise RuleRecognitionProofBundleRejected(
                "non-empty Recognition graph page cannot be empty"
            )
        proof = value["proof"]
        if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page signature fields are invalid"
            )
        if (
            proof["type"] != RULE_RECOGNITION_PROOF_PAGE_PROOF_TYPE
            or proof["created"] != value["observed_at"]
            or proof["verification_method"]
            != verification_method_for_did(value["observer_did"])
            or proof["proof_purpose"]
            != RULE_RECOGNITION_PROOF_PAGE_PROOF_PURPOSE
        ):
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page signature metadata is invalid"
            )
        _verify_page_signature(value)
        try:
            canonical = trade_canonical_json(value)
        except TradeCanonicalJSONError as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        if len(canonical) > MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page exceeds its byte limit"
            )
        instance = object.__new__(cls)
        object.__setattr__(instance, "_canonical_bytes", canonical)
        object.__setattr__(instance, "_statements", statements)
        return instance

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        **kwargs: Any,
    ) -> "VerifiedRuleRecognitionProofPage":
        try:
            value = parse_trade_json(raw)
        except TradeCanonicalJSONError as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        return cls.from_dict(value, **kwargs)

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def statements(self) -> tuple[TradeRuleRecognition, ...]:
        return self._statements

    @property
    def statement_count(self) -> int:
        return len(self._statements)

    @property
    def package_digest(self) -> str:
        return self.to_dict()["package_digest"]

    @property
    def offer_digest(self) -> str:
        return self.to_dict()["offer_digest"]

    @property
    def observer_did(self) -> str:
        return self.to_dict()["observer_did"]

    @property
    def observed_heads_digest(self) -> str:
        return self.to_dict()["graph_heads_digest"]

    @property
    def observation_digest(self) -> str:
        return self.to_dict()["observation_digest"]

    @property
    def page_index(self) -> int:
        return self.to_dict()["page_index"]

    @property
    def page_count(self) -> int:
        return self.to_dict()["page_count"]

    @property
    def total_statement_count(self) -> int:
        return self.to_dict()["statement_count"]

    @property
    def statement_set_digest(self) -> str:
        return self.to_dict()["statement_set_digest"]

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


@dataclass(frozen=True)
class VerifiedRuleRecognitionProofSet:
    pages: tuple[VerifiedRuleRecognitionProofPage, ...]
    statements: tuple[TradeRuleRecognition, ...]
    observation_digest: str
    graph_heads_digest: str
    statement_set_digest: str

    @property
    def proof_digests(self) -> tuple[str, ...]:
        return tuple(
            "sha256:" + hashlib.sha256(page.canonical_bytes).hexdigest()
            for page in self.pages
        )


def parse_rule_recognition_proof_pages(
    values: Iterable[VerifiedRuleRecognitionProofPage | dict[str, Any] | bytes | str],
    *,
    package: RulePackage,
    expected_offer_digest: str | None = None,
    expected_offer_publisher_did: str | None = None,
    now: datetime | None = None,
) -> VerifiedRuleRecognitionProofSet:
    pages = []
    total_bytes = 0
    for value in values:
        if isinstance(value, VerifiedRuleRecognitionProofPage):
            page = VerifiedRuleRecognitionProofPage.from_json(
                value.canonical_bytes,
                package=package,
                expected_offer_digest=expected_offer_digest,
                expected_offer_publisher_did=expected_offer_publisher_did,
                now=now,
            )
        elif isinstance(value, (bytes, str)):
            page = VerifiedRuleRecognitionProofPage.from_json(
                value,
                package=package,
                expected_offer_digest=expected_offer_digest,
                expected_offer_publisher_did=expected_offer_publisher_did,
                now=now,
            )
        elif isinstance(value, dict):
            page = VerifiedRuleRecognitionProofPage.from_dict(
                value,
                package=package,
                expected_offer_digest=expected_offer_digest,
                expected_offer_publisher_did=expected_offer_publisher_did,
                now=now,
            )
        else:
            raise TypeError("Recognition proof page must be an object or JSON bytes")
        total_bytes += len(page.canonical_bytes)
        if total_bytes > MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page set exceeds its byte limit"
            )
        pages.append(page)
        if len(pages) > MAX_RULE_RECOGNITION_PROOF_PAGES:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof page count exceeds its limit"
            )
    if not pages:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page set cannot be empty"
        )
    pages.sort(key=lambda page: page.page_index)
    documents = [page.to_dict() for page in pages]
    first = documents[0]
    expected_indexes = list(range(first["page_count"]))
    if [document["page_index"] for document in documents] != expected_indexes:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page set is incomplete or duplicated"
        )
    shared_fields = (
        "offer_digest",
        "package_digest",
        "observer_did",
        "observed_at",
        "not_after",
        "observation_digest",
        "graph_heads_digest",
        "statement_set_digest",
        "statement_count",
        "page_count",
    )
    if any(
        any(document[field] != first[field] for field in shared_fields)
        for document in documents[1:]
    ):
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof pages belong to different observations"
        )
    statements = tuple(
        statement for page in pages for statement in page.statements
    )
    if len(statements) != first["statement_count"]:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page set statement count is incomplete"
        )
    if len({statement.digest for statement in statements}) != len(statements):
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page set repeats a statement"
        )
    if _statement_set_digest(statements) != first["statement_set_digest"]:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page statement-set commitment is invalid"
        )
    grouped: dict[str, list[TradeRuleRecognition]] = {}
    for statement in statements:
        issuer = statement.to_dict()["issuer_did"]
        grouped.setdefault(issuer, []).append(statement)
    chains = []
    verified_statements: list[TradeRuleRecognition] = []
    for issuer, issuer_statements in sorted(grouped.items()):
        ordered = sorted(
            issuer_statements,
            key=lambda statement: (
                statement.to_dict()["sequence"],
                statement.digest,
            ),
        )
        digests = {statement.digest for statement in ordered}
        referenced = {
            statement.to_dict()["previous_statement_digest"]
            for statement in ordered
            if statement.to_dict()["previous_statement_digest"] is not None
        }
        chain = {
            "issuer_did": issuer,
            "head_digests": sorted(digests - referenced),
            "statements": [statement.to_dict() for statement in ordered],
        }
        verified_statements.extend(_validate_chain(
            chain,
            package=package,
            max_statements=MAX_RULE_RECOGNITION_STATEMENTS,
        ))
        chains.append(chain)
    if _heads_digest(chains) != first["graph_heads_digest"]:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof page graph-head commitment is invalid"
        )
    return VerifiedRuleRecognitionProofSet(
        pages=tuple(pages),
        statements=tuple(verified_statements),
        observation_digest=first["observation_digest"],
        graph_heads_digest=first["graph_heads_digest"],
        statement_set_digest=first["statement_set_digest"],
    )


def _pack_segments(
    grouped: dict[str, list[TradeRuleRecognition]],
) -> list[list[dict[str, Any]]]:
    pages: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_count = 0
    current_bytes = 0

    def finish() -> None:
        nonlocal current, current_count, current_bytes
        if current:
            pages.append(current)
            current = []
            current_count = 0
            current_bytes = 0

    for issuer, issuer_statements in sorted(grouped.items()):
        ordered = sorted(
            issuer_statements,
            key=lambda statement: (
                statement.to_dict()["sequence"],
                statement.digest,
            ),
        )
        offset = 0
        while offset < len(ordered):
            if current_count >= MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS:
                finish()
            remaining_count = (
                MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS - current_count
            )
            segment_statements: list[TradeRuleRecognition] = []
            while offset < len(ordered) and len(segment_statements) < remaining_count:
                statement = ordered[offset]
                size = len(statement.canonical_bytes)
                if size > _PAGE_TARGET_STATEMENT_BYTES:
                    raise RuleRecognitionProofBundleRejected(
                        "Recognition statement is too large for paged transport"
                    )
                if (
                    current_count > 0
                    and current_bytes + size > _PAGE_TARGET_STATEMENT_BYTES
                ):
                    break
                segment_statements.append(statement)
                current_count += 1
                current_bytes += size
                offset += 1
            if not segment_statements:
                finish()
                continue
            current.append({
                "issuer_did": issuer,
                "previous_statement_digest": segment_statements[0].to_dict()[
                    "previous_statement_digest"
                ],
                "statements": [
                    statement.to_dict() for statement in segment_statements
                ],
            })
            if (
                current_count >= MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS
                or current_bytes >= _PAGE_TARGET_STATEMENT_BYTES
            ):
                finish()
    finish()
    return pages or [[]]


def build_rule_recognition_proof_pages(
    package: RulePackage,
    statements: Iterable[TradeRuleRecognition | dict[str, Any]],
    *,
    offer_package_binding: SignedOfferPackageBinding | dict[str, Any],
    observer_identity: AgentIdentity,
    observed_at: str | None = None,
    not_after: str | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any], ...]:
    verified_package = _verified_package(package)
    if not isinstance(observer_identity, AgentIdentity):
        raise TypeError("observer_identity must be an AgentIdentity")
    if not observer_identity.can_sign:
        raise RuleRecognitionProofBundleRejected(
            "observer_identity has no signing key"
        )
    try:
        binding = require_offer_package_binding(
            offer_package_binding,
            expected_package_digest=verified_package.digest,
            expected_publisher_did=observer_identity.as_did(),
        )
    except OfferPackageBindingRejected as exc:
        raise RuleRecognitionProofBundleRejected(str(exc)) from exc
    verified = []
    for value in statements:
        if len(verified) >= MAX_RULE_RECOGNITION_STATEMENTS:
            raise RuleRecognitionProofBundleRejected(
                "Recognition proof graph statement count exceeds its limit"
            )
        verified.append(_verified_statement(value, package=verified_package))
    if len({statement.digest for statement in verified}) != len(verified):
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof graph repeats a statement"
        )
    grouped: dict[str, list[TradeRuleRecognition]] = {}
    for statement in verified:
        grouped.setdefault(statement.to_dict()["issuer_did"], []).append(statement)
    chains = []
    for issuer, issuer_statements in sorted(grouped.items()):
        ordered = sorted(
            issuer_statements,
            key=lambda statement: (
                statement.to_dict()["sequence"],
                statement.digest,
            ),
        )
        digests = {statement.digest for statement in ordered}
        referenced = {
            statement.to_dict()["previous_statement_digest"]
            for statement in ordered
            if statement.to_dict()["previous_statement_digest"] is not None
        }
        chain = {
            "issuer_did": issuer,
            "head_digests": sorted(digests - referenced),
            "statements": [statement.to_dict() for statement in ordered],
        }
        _validate_chain(
            chain,
            package=verified_package,
            max_statements=MAX_RULE_RECOGNITION_STATEMENTS,
        )
        chains.append(chain)
    segments = _pack_segments(grouped)
    if len(segments) > MAX_RULE_RECOGNITION_PROOF_PAGES:
        raise RuleRecognitionProofBundleRejected(
            "Recognition proof graph requires too many pages"
        )
    moment = _utc_now(now)
    observed = observed_at or _format_timestamp(moment)
    observed_value = _timestamp(observed, label="observed_at")
    expires = not_after or _format_timestamp(
        observed_value
        + timedelta(seconds=DEFAULT_RULE_RECOGNITION_PROOF_BUNDLE_TTL_SECONDS)
    )
    shared = {
        "offer_digest": binding.offer_digest,
        "package_digest": verified_package.digest,
        "observer_did": observer_identity.as_did(),
        "observed_at": observed,
        "not_after": expires,
        "graph_heads_digest": _heads_digest(chains),
        "statement_set_digest": _statement_set_digest(verified),
        "statement_count": len(verified),
        "page_count": len(segments),
    }
    observation_digest = _digest(shared)
    pages = []
    for page_index, page_segments in enumerate(segments):
        wire = {
            "kind": RULE_RECOGNITION_PROOF_PAGE_KIND,
            "protocol_version": RULE_RECOGNITION_PROOF_PAGE_PROTOCOL_VERSION,
            "offer_digest": binding.offer_digest,
            "offer_package_binding": binding.to_dict(),
            "package_digest": verified_package.digest,
            "observer_did": observer_identity.as_did(),
            "observed_at": observed,
            "not_after": expires,
            "observation_digest": observation_digest,
            "graph_heads_digest": shared["graph_heads_digest"],
            "statement_set_digest": shared["statement_set_digest"],
            "statement_count": len(verified),
            "page_index": page_index,
            "page_count": len(segments),
            "issuer_segments": page_segments,
            "proof": {
                "type": RULE_RECOGNITION_PROOF_PAGE_PROOF_TYPE,
                "created": observed,
                "verification_method": verification_method_for_did(
                    observer_identity.as_did()
                ),
                "proof_purpose": RULE_RECOGNITION_PROOF_PAGE_PROOF_PURPOSE,
                "proof_value": "A" * 86,
            },
        }
        try:
            wire["proof"]["proof_value"] = encode_ed25519_signature(
                observer_identity.sign(
                    signed_document_input(
                        RULE_RECOGNITION_PROOF_PAGE_SIGNING_DOMAIN,
                        copy.deepcopy(wire),
                    )
                )
            )
        except TradeProofError as exc:
            raise RuleRecognitionProofBundleRejected(str(exc)) from exc
        pages.append(wire)
    return tuple(
        page.to_dict()
        for page in parse_rule_recognition_proof_pages(
            pages,
            package=verified_package,
            expected_offer_digest=binding.offer_digest,
            expected_offer_publisher_did=observer_identity.as_did(),
            now=moment,
        ).pages
    )


__all__ = [
    "MAX_RULE_RECOGNITION_PROOF_PAGE_BYTES",
    "MAX_RULE_RECOGNITION_PROOF_PAGE_SET_BYTES",
    "MAX_RULE_RECOGNITION_PROOF_PAGES",
    "MAX_RULE_RECOGNITION_PROOF_PAGE_STATEMENTS",
    "RULE_RECOGNITION_PROOF_PAGE_KIND",
    "RULE_RECOGNITION_PROOF_PAGE_PROTOCOL_VERSION",
    "RuleRecognitionProofBundleRejected",
    "VerifiedRuleRecognitionProofPage",
    "VerifiedRuleRecognitionProofSet",
    "build_rule_recognition_proof_pages",
    "parse_rule_recognition_proof_pages",
]
