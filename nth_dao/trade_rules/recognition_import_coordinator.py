"""Protocol-layer transaction coordinator for Recognition proof imports."""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from nth_dao.trade_rules.canonical import parse_trade_json
from nth_dao.trade_rules.package_store import RulePackage
from nth_dao.trade_rules.recognition_audit import RuleRecognitionAuditCoordinator
from nth_dao.trade_rules.recognition_import import (
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
    EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
    RuleRecognitionProofImportError,
    RuleRecognitionProofImportState,
    RuleRecognitionProofStore,
    append_recognition_proof_import_event,
    recognition_proof_digest,
    recognition_proof_import_payload,
    recognition_proof_import_states,
    recognition_proof_observation_id,
)
from nth_dao.trade_rules.recognition_store import (
    MAX_RULE_RECOGNITION_IMPORT_BATCH,
)
from nth_dao.trade_rules.recognition_transport import (
    VerifiedRuleRecognitionProofBundle,
    parse_rule_recognition_proof_bundle,
)
from nth_dao.trade_rules.recognition_transport_pages import (
    RULE_RECOGNITION_PROOF_PAGE_KIND,
    VerifiedRuleRecognitionProofPage,
    VerifiedRuleRecognitionProofSet,
    parse_rule_recognition_proof_pages,
)
from nth_dao.util.io import InterProcessLock

DEFAULT_RULE_RECOGNITION_IMPORT_MAX_CONCURRENCY = 2
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuleRecognitionProofImportBusy(RuntimeError):
    """Another process owns the Package transaction or all import slots."""


@contextmanager
def rule_recognition_import_slot(
    workspace_root: str | Path,
    *,
    max_concurrency: int = DEFAULT_RULE_RECOGNITION_IMPORT_MAX_CONCURRENCY,
) -> Iterator[None]:
    """Reserve one bounded process-independent import slot."""

    if (
        isinstance(max_concurrency, bool)
        or not isinstance(max_concurrency, int)
        or max_concurrency <= 0
        or max_concurrency > 32
    ):
        raise ValueError("max_concurrency must be an integer in 1..32")
    slot_root = (
        Path(workspace_root).resolve()
        / "trade"
        / "rule_recognition_import_slots"
    )
    for index in range(max_concurrency):
        lock = InterProcessLock(slot_root / str(index), timeout=0.0)
        try:
            lock.acquire()
        except TimeoutError:
            continue
        try:
            yield
        finally:
            lock.release()
        return
    raise RuleRecognitionProofImportBusy(
        "Rule Recognition import concurrency is full"
    )


@dataclass(frozen=True)
class RuleRecognitionProofImportCommit:
    proof: VerifiedRuleRecognitionProofBundle
    imported: tuple[Any, ...]
    reconciled_anchor_count: int
    import_id: str
    source_origin: str
    proposal_event_id: str
    completion_event_id: str
    observed_heads_digest: str

    @property
    def audit(self) -> dict[str, str]:
        return {
            "import_id": self.import_id,
            "source_origin": self.source_origin,
            "proposal_event_id": self.proposal_event_id,
            "completion_event_id": self.completion_event_id,
            "observed_heads_digest": self.observed_heads_digest,
        }


@dataclass(frozen=True)
class RuleRecognitionProofSetImportCommit:
    proof_set: VerifiedRuleRecognitionProofSet
    imported: tuple[Any, ...]
    reconciled_anchor_count: int
    page_audits: tuple[dict[str, str], ...]


class RuleRecognitionProofImportCoordinator:
    """Recover or commit one observed graph as a durable local transaction."""

    def __init__(
        self,
        workspace_root: str | Path,
        recognition_audit: RuleRecognitionAuditCoordinator,
        *,
        max_concurrency: int = DEFAULT_RULE_RECOGNITION_IMPORT_MAX_CONCURRENCY,
    ) -> None:
        if not isinstance(recognition_audit, RuleRecognitionAuditCoordinator):
            raise TypeError(
                "recognition_audit must be a RuleRecognitionAuditCoordinator"
            )
        if (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or max_concurrency <= 0
            or max_concurrency > 32
        ):
            raise ValueError("max_concurrency must be an integer in 1..32")
        self.workspace_root = Path(workspace_root).resolve()
        self.recognition_audit = recognition_audit
        self.max_concurrency = max_concurrency

    def _lock_target(self, package_digest: str) -> Path:
        if not isinstance(package_digest, str) or _DIGEST.fullmatch(
            package_digest
        ) is None:
            raise RuleRecognitionProofImportError(
                "Rule Recognition Package digest is invalid"
            )
        return (
            self.workspace_root
            / "trade"
            / "rule_recognition_imports"
            / package_digest.removeprefix("sha256:")
        )

    @contextmanager
    def _slot(self) -> Iterator[None]:
        with rule_recognition_import_slot(
            self.workspace_root,
            max_concurrency=self.max_concurrency,
        ):
            yield

    def _verified_state_proof(
        self,
        state: Any,
        *,
        proof_store: RuleRecognitionProofStore,
        package: RulePackage,
        order_digest: str,
        offer_digest: str,
        offer_publisher_did: str,
    ) -> VerifiedRuleRecognitionProofBundle | VerifiedRuleRecognitionProofPage:
        raw = proof_store.get(state.payload["proof_digest"])
        proposed_at = datetime.fromtimestamp(
            state.proposed_event.ts_ms / 1000,
            tz=timezone.utc,
        )
        inspected = parse_trade_json(raw)
        if inspected.get("kind") == RULE_RECOGNITION_PROOF_PAGE_KIND:
            proof = VerifiedRuleRecognitionProofPage.from_dict(
                inspected,
                package=package,
                expected_offer_digest=offer_digest,
                expected_offer_publisher_did=offer_publisher_did,
                now=proposed_at,
            )
        else:
            proof = parse_rule_recognition_proof_bundle(
                inspected,
                package=package,
                expected_offer_digest=offer_digest,
                expected_offer_publisher_did=offer_publisher_did,
                now=proposed_at,
            )
        expected = recognition_proof_import_payload(
            proof,
            event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
            order_digest=order_digest,
            offer_digest=offer_digest,
            source_origin=state.payload["source_origin"],
        )
        if expected != state.payload:
            raise RuleRecognitionProofImportError(
                "stored proof does not match its import audit"
            )
        return proof

    def _complete(
        self,
        proof: VerifiedRuleRecognitionProofBundle,
        proposed_payload: dict[str, Any],
        proposed_event: Any,
        *,
        package: RulePackage,
    ) -> RuleRecognitionProofImportCommit:
        results = self.recognition_audit.record_batch(
            list(proof.statements),
            package=package,
        )
        completed_payload = dict(proposed_payload)
        completed_payload["action"] = "recognition-proof-imported"
        completed_event, _created = append_recognition_proof_import_event(
            self.recognition_audit.spine,
            event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
            payload=completed_payload,
        )
        verified_digests = {
            statement.digest
            for statement in self.recognition_audit.verified_statements(
                package=package
            )
        }
        expected_digests = {
            statement.digest for statement in proof.statements
        }
        if not expected_digests.issubset(verified_digests):
            raise RuleRecognitionProofImportError(
                "Rule Recognition import did not reach a verified local state"
            )
        imported = tuple(result for result in results if result.store_created)
        reconciled = sum(
            result.anchor_created and not result.store_created
            for result in results
        )
        return RuleRecognitionProofImportCommit(
            proof=proof,
            imported=imported,
            reconciled_anchor_count=reconciled,
            import_id=proposed_payload["import_id"],
            source_origin=proposed_payload["source_origin"],
            proposal_event_id=proposed_event.event_id,
            completion_event_id=completed_event.event_id,
            observed_heads_digest=proposed_payload["observed_heads_digest"],
        )

    def _complete_page_set(
        self,
        proof_set: VerifiedRuleRecognitionProofSet,
        pending: tuple[tuple[Any, dict[str, Any], Any], ...],
        *,
        package: RulePackage,
        all_states: tuple[tuple[Any, dict[str, Any], Any], ...],
    ) -> RuleRecognitionProofSetImportCommit:
        self.recognition_audit.store.require_import_capacity(
            proof_set.statements,
            package=package,
        )
        results = []
        statements = list(proof_set.statements)
        for offset in range(
            0,
            len(statements),
            MAX_RULE_RECOGNITION_IMPORT_BATCH,
        ):
            results.extend(self.recognition_audit.record_batch(
                statements[offset:offset + MAX_RULE_RECOGNITION_IMPORT_BATCH],
                package=package,
            ))
        completed_by_import_id: dict[str, Any] = {
            payload["import_id"]: state.completed_event
            for state, payload, _page in all_states
            if state.completed_event is not None
        }
        for state, payload, _page in pending:
            completed_payload = dict(payload)
            completed_payload["action"] = "recognition-proof-imported"
            completed_event, _created = append_recognition_proof_import_event(
                self.recognition_audit.spine,
                event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORTED,
                payload=completed_payload,
            )
            completed_by_import_id[payload["import_id"]] = completed_event
        verified_digests = {
            statement.digest
            for statement in self.recognition_audit.verified_statements(
                package=package
            )
        }
        expected_digests = {
            statement.digest for statement in proof_set.statements
        }
        if not expected_digests.issubset(verified_digests):
            raise RuleRecognitionProofImportError(
                "Recognition proof pages did not reach a verified local state"
            )
        audits = []
        for state, payload, _page in sorted(
            all_states,
            key=lambda item: item[2].page_index,
        ):
            completion = completed_by_import_id.get(payload["import_id"])
            if completion is None:
                raise RuleRecognitionProofImportError(
                    "Recognition proof page completion is missing"
                )
            audits.append({
                "import_id": payload["import_id"],
                "source_origin": payload["source_origin"],
                "proposal_event_id": state.proposed_event.event_id,
                "completion_event_id": completion.event_id,
                "observed_heads_digest": payload["observed_heads_digest"],
            })
        return RuleRecognitionProofSetImportCommit(
            proof_set=proof_set,
            imported=tuple(
                result for result in results if result.store_created
            ),
            reconciled_anchor_count=sum(
                result.anchor_created and not result.store_created
                for result in results
            ),
            page_audits=tuple(audits),
        )

    def _recover_page_set(
        self,
        *,
        states: tuple[RuleRecognitionProofImportState, ...],
        pending_states: tuple[RuleRecognitionProofImportState, ...],
        proof_store: RuleRecognitionProofStore,
        order_digest: str,
        package: RulePackage,
        offer_digest: str,
        offer_publisher_did: str,
    ) -> RuleRecognitionProofSetImportCommit:
        pending_pages = []
        for state in pending_states:
            proof = self._verified_state_proof(
                state,
                proof_store=proof_store,
                package=package,
                order_digest=order_digest,
                offer_digest=offer_digest,
                offer_publisher_did=offer_publisher_did,
            )
            if not isinstance(proof, VerifiedRuleRecognitionProofPage):
                raise RuleRecognitionProofImportError(
                    "pending import mixes legacy and paged proof documents"
                )
            pending_pages.append((state, state.payload, proof))
        pending_observations = {
            item[2].observation_digest for item in pending_pages
        }
        if len(pending_observations) != 1:
            raise RuleRecognitionProofImportError(
                "pending proof pages belong to multiple observations"
            )
        observation = next(iter(pending_observations))
        recovery_time = datetime.fromtimestamp(
            min(
                item[0].proposed_event.ts_ms
                for item in pending_pages
            ) / 1000,
            tz=timezone.utc,
        )
        proof_set = parse_rule_recognition_proof_pages(
            proof_store.find_observation_pages(observation),
            package=package,
            expected_offer_digest=offer_digest,
            expected_offer_publisher_did=offer_publisher_did,
            now=recovery_time,
        )
        state_by_proof_digest = {
            state.payload["proof_digest"]: state for state in states
        }
        transaction = []
        for page in proof_set.pages:
            page_digest = recognition_proof_digest(page)
            state = state_by_proof_digest.get(page_digest)
            payload = recognition_proof_import_payload(
                page,
                event_type=EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED,
                order_digest=order_digest,
                offer_digest=offer_digest,
                source_origin=pending_pages[0][1]["source_origin"],
            )
            if state is None:
                proposed_event, _created = append_recognition_proof_import_event(
                    self.recognition_audit.spine,
                    event_type=(
                        EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
                    ),
                    payload=payload,
                )
                state = RuleRecognitionProofImportState(
                    payload=payload,
                    proposed_event=proposed_event,
                    completed_event=None,
                )
            elif state.payload != payload:
                raise RuleRecognitionProofImportError(
                    "stored proof page has a conflicting audit binding"
                )
            transaction.append((state, payload, page))
        transaction_tuple = tuple(transaction)
        pending = tuple(
            item
            for item in transaction_tuple
            if item[0].completed_event is None
        )
        return self._complete_page_set(
            proof_set,
            pending,
            package=package,
            all_states=transaction_tuple,
        )

    def import_pages_or_recover(
        self,
        *,
        order_digest: str,
        package: RulePackage,
        offer_digest: str,
        offer_publisher_did: str,
        source_origin: str,
        fetch_proof_set: Callable[[], VerifiedRuleRecognitionProofSet],
    ) -> RuleRecognitionProofSetImportCommit:
        """Atomically expose a complete, independently signed page set."""

        if not isinstance(package, RulePackage):
            raise TypeError("package must be a RulePackage")
        if not callable(fetch_proof_set):
            raise TypeError("fetch_proof_set must be callable")
        lock = InterProcessLock(
            self._lock_target(package.digest),
            timeout=35.0,
        )
        try:
            lock.acquire()
        except TimeoutError as exc:
            raise RuleRecognitionProofImportBusy(
                "another process is importing Rule Recognition evidence"
            ) from exc
        try:
            with self._slot():
                proof_store = RuleRecognitionProofStore(self.workspace_root)
                try:
                    states = recognition_proof_import_states(
                        self.recognition_audit.spine.verified_snapshot(),
                        package_digest=package.digest,
                        order_digest=order_digest,
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    raise RuleRecognitionProofImportError(
                        "Recognition proof import audit is unavailable"
                    ) from exc
                pending_states = tuple(
                    state for state in states if state.completed_event is None
                )
                if pending_states:
                    return self._recover_page_set(
                        states=states,
                        pending_states=pending_states,
                        proof_store=proof_store,
                        order_digest=order_digest,
                        package=package,
                        offer_digest=offer_digest,
                        offer_publisher_did=offer_publisher_did,
                    )

                fetched = fetch_proof_set()
                if not isinstance(fetched, VerifiedRuleRecognitionProofSet):
                    raise TypeError(
                        "fetch_proof_set must return a verified proof set"
                    )
                proof_set = parse_rule_recognition_proof_pages(
                    fetched.pages,
                    package=package,
                    expected_offer_digest=offer_digest,
                    expected_offer_publisher_did=offer_publisher_did,
                )
                self.recognition_audit.store.require_import_capacity(
                    proof_set.statements,
                    package=package,
                )
                payloads = tuple(
                    recognition_proof_import_payload(
                        page,
                        event_type=(
                            EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
                        ),
                        order_digest=order_digest,
                        offer_digest=offer_digest,
                        source_origin=source_origin,
                    )
                    for page in proof_set.pages
                )
                existing_by_observation: dict[str, list[Any]] = {}
                for state in states:
                    if state.completed_event is not None:
                        existing_by_observation.setdefault(
                            recognition_proof_observation_id(state.payload),
                            [],
                        ).append(state)
                matched = []
                for page, payload in zip(proof_set.pages, payloads):
                    candidates = existing_by_observation.get(
                        recognition_proof_observation_id(payload),
                        [],
                    )
                    if len(candidates) > 1:
                        raise RuleRecognitionProofImportError(
                            "Recognition proof audit repeats an observed page"
                        )
                    if candidates:
                        matched.append((candidates[0], payload, page))
                if len(matched) == len(proof_set.pages):
                    existing_pages = []
                    transaction = []
                    for state, _payload, _page in matched:
                        existing_page = self._verified_state_proof(
                            state,
                            proof_store=proof_store,
                            package=package,
                            order_digest=order_digest,
                            offer_digest=offer_digest,
                            offer_publisher_did=offer_publisher_did,
                        )
                        if not isinstance(
                            existing_page,
                            VerifiedRuleRecognitionProofPage,
                        ):
                            raise RuleRecognitionProofImportError(
                                "observed page key resolves to a legacy proof"
                            )
                        existing_pages.append(existing_page)
                        transaction.append((state, state.payload, existing_page))
                    existing_set = parse_rule_recognition_proof_pages(
                        existing_pages,
                        package=package,
                        expected_offer_digest=offer_digest,
                        expected_offer_publisher_did=offer_publisher_did,
                        now=datetime.fromtimestamp(
                            min(
                                item[0].proposed_event.ts_ms
                                for item in transaction
                            ) / 1000,
                            tz=timezone.utc,
                        ),
                    )
                    return self._complete_page_set(
                        existing_set,
                        (),
                        package=package,
                        all_states=tuple(transaction),
                    )
                transaction = []
                for page in proof_set.pages:
                    proof_store.put(page)
                for page, payload in zip(proof_set.pages, payloads):
                    proposed_event, _created = (
                        append_recognition_proof_import_event(
                            self.recognition_audit.spine,
                            event_type=(
                                EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
                            ),
                            payload=payload,
                        )
                    )
                    state = RuleRecognitionProofImportState(
                        payload=payload,
                        proposed_event=proposed_event,
                        completed_event=None,
                    )
                    transaction.append((state, payload, page))
                return self._complete_page_set(
                    proof_set,
                    tuple(transaction),
                    package=package,
                    all_states=tuple(transaction),
                )
        finally:
            lock.release()

    def import_or_recover(
        self,
        *,
        order_digest: str,
        package: RulePackage,
        offer_digest: str,
        offer_publisher_did: str,
        source_origin: str,
        fetch_proof: Callable[[], VerifiedRuleRecognitionProofBundle],
    ) -> RuleRecognitionProofImportCommit | RuleRecognitionProofSetImportCommit:
        if not isinstance(package, RulePackage):
            raise TypeError("package must be a RulePackage")
        if not callable(fetch_proof):
            raise TypeError("fetch_proof must be callable")
        lock = InterProcessLock(
            self._lock_target(package.digest),
            timeout=35.0,
        )
        try:
            lock.acquire()
        except TimeoutError as exc:
            raise RuleRecognitionProofImportBusy(
                "another process is importing Rule Recognition evidence"
            ) from exc
        try:
            with self._slot():
                proof_store = RuleRecognitionProofStore(self.workspace_root)
                try:
                    states = recognition_proof_import_states(
                        self.recognition_audit.spine.verified_snapshot(),
                        package_digest=package.digest,
                        order_digest=order_digest,
                    )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    raise RuleRecognitionProofImportError(
                        "Recognition proof import audit is unavailable"
                    ) from exc
                incomplete = [
                    state for state in states if state.completed_event is None
                ]
                if incomplete:
                    pending = incomplete[0]
                    proof = self._verified_state_proof(
                        pending,
                        proof_store=proof_store,
                        package=package,
                        order_digest=order_digest,
                        offer_digest=offer_digest,
                        offer_publisher_did=offer_publisher_did,
                    )
                    if isinstance(proof, VerifiedRuleRecognitionProofPage):
                        return self._recover_page_set(
                            states=states,
                            pending_states=tuple(incomplete),
                            proof_store=proof_store,
                            order_digest=order_digest,
                            package=package,
                            offer_digest=offer_digest,
                            offer_publisher_did=offer_publisher_did,
                        )
                    if len(incomplete) > 1:
                        raise RuleRecognitionProofImportError(
                            "multiple incomplete legacy proof imports exist"
                        )
                    return self._complete(
                        proof,
                        pending.payload,
                        pending.proposed_event,
                        package=package,
                    )

                fetched = fetch_proof()
                if not isinstance(fetched, VerifiedRuleRecognitionProofBundle):
                    raise TypeError(
                        "fetch_proof must return a verified Recognition proof"
                    )
                proof = parse_rule_recognition_proof_bundle(
                    fetched.canonical_bytes,
                    package=package,
                    expected_offer_digest=offer_digest,
                    expected_offer_publisher_did=offer_publisher_did,
                )
                proposed_payload = recognition_proof_import_payload(
                    proof,
                    event_type=(
                        EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
                    ),
                    order_digest=order_digest,
                    offer_digest=offer_digest,
                    source_origin=source_origin,
                )
                observation_id = recognition_proof_observation_id(
                    proposed_payload
                )
                matching = [
                    state
                    for state in states
                    if state.completed_event is not None
                    and recognition_proof_observation_id(state.payload)
                    == observation_id
                ]
                if len(matching) > 1:
                    raise RuleRecognitionProofImportError(
                        "Recognition proof import audit repeats an observed graph"
                    )
                if matching:
                    existing = matching[0]
                    existing_proof = self._verified_state_proof(
                        existing,
                        proof_store=proof_store,
                        package=package,
                        order_digest=order_digest,
                        offer_digest=offer_digest,
                        offer_publisher_did=offer_publisher_did,
                    )
                    verified_digests = {
                        statement.digest
                        for statement in self.recognition_audit.verified_statements(
                            package=package
                        )
                    }
                    if not set(existing.payload["statement_digests"]).issubset(
                        verified_digests
                    ):
                        raise RuleRecognitionProofImportError(
                            "completed import is missing Recognition statements"
                        )
                    return RuleRecognitionProofImportCommit(
                        proof=existing_proof,
                        imported=(),
                        reconciled_anchor_count=0,
                        import_id=existing.payload["import_id"],
                        source_origin=existing.payload["source_origin"],
                        proposal_event_id=existing.proposed_event.event_id,
                        completion_event_id=existing.completed_event.event_id,
                        observed_heads_digest=existing.payload[
                            "observed_heads_digest"
                        ],
                    )
                proof_store.put(proof)
                proposed_event, _created = append_recognition_proof_import_event(
                    self.recognition_audit.spine,
                    event_type=(
                        EVENT_TRADE_RULE_RECOGNITION_PROOF_IMPORT_PROPOSED
                    ),
                    payload=proposed_payload,
                )
                return self._complete(
                    proof,
                    proposed_payload,
                    proposed_event,
                    package=package,
                )
        finally:
            lock.release()


__all__ = [
    "DEFAULT_RULE_RECOGNITION_IMPORT_MAX_CONCURRENCY",
    "RuleRecognitionProofImportBusy",
    "RuleRecognitionProofImportCommit",
    "RuleRecognitionProofImportCoordinator",
    "RuleRecognitionProofSetImportCommit",
    "rule_recognition_import_slot",
]
