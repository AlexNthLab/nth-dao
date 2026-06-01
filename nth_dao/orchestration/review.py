"""MissionReview — signed ratings on completed missions.

Reviews are append-only, signed by the reviewer, and stored per template:

    missions/reviews/<template_id>-v<version>.jsonl

The publisher's signature on the template stays valid because reviews are
in their own file, not patched into the template. This mirrors cargo-crev's
"Proof" model and lets the on-disk template act as an immutable contract.

Aggregations (average_rating, install_count, …) are derived state, computed
on demand or by `_review_index.json`. We never edit them into the template.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..identity import AgentIdentity, _NACL_AVAILABLE, _VerifyKey, canonical_json
from ..util import InterProcessLock, atomic_write_json, safe_load_json, safe_id

logger = logging.getLogger("nth_dao.orchestration.review")


SCORE_MIN = 0.0
SCORE_MAX = 5.0


@dataclass
class MissionReview:
    """One signed review of one (template_id, version) by one reviewer.

    Aligned with cargo-crev Review Proof:
        - reviewer signs entire payload (sans-sig)
        - persisted as one line in a per-template JSONL ledger
        - duplicate (reviewer, template, version, mission_id) is the same review;
          a fresh write supersedes — the latest sig wins on aggregation
    """

    review_id: str
    reviewer_pubkey: str
    reviewer_agent_id: str
    template_id: str
    template_version: str
    mission_id: str               # which mission instance is being reviewed
    score: float                  # 0.0–5.0
    feedback: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    reviewer_sig: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def signable_dict(self) -> dict:
        d = self.to_dict()
        d.pop("reviewer_sig", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "MissionReview":
        return cls(
            review_id=data.get("review_id", ""),
            reviewer_pubkey=data.get("reviewer_pubkey", ""),
            reviewer_agent_id=data.get("reviewer_agent_id", ""),
            template_id=data.get("template_id", ""),
            template_version=data.get("template_version", ""),
            mission_id=data.get("mission_id", ""),
            score=float(data.get("score", 0)),
            feedback=data.get("feedback", ""),
            metadata=dict(data.get("metadata", {})),
            created_at=data.get("created_at", ""),
            reviewer_sig=data.get("reviewer_sig", ""),
        )

    def verify_signature(self) -> bool:
        if not (_NACL_AVAILABLE and _VerifyKey
                and self.reviewer_sig and self.reviewer_pubkey):
            return False
        try:
            _VerifyKey(bytes.fromhex(self.reviewer_pubkey)).verify(
                canonical_json(self.signable_dict()),
                bytes.fromhex(self.reviewer_sig),
            )
            return True
        except Exception:
            return False


def mint_review(
    reviewer: AgentIdentity,
    *,
    template_id: str,
    template_version: str,
    mission_id: str,
    score: float,
    feedback: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> MissionReview:
    """Create + sign a MissionReview.

    Raises:
        ValueError: non-crypto identity, score out of range, missing ids.
    """
    if not reviewer.can_sign:
        raise ValueError("mint_review requires a signing-capable identity")
    if not (SCORE_MIN <= score <= SCORE_MAX):
        raise ValueError(f"score must be in [{SCORE_MIN}, {SCORE_MAX}]")
    if not template_id or not template_version or not mission_id:
        raise ValueError("template_id, template_version, mission_id required")
    review = MissionReview(
        review_id=uuid.uuid4().hex[:12],
        reviewer_pubkey=reviewer.pubkey_hex,
        reviewer_agent_id=str(reviewer.agent_id),
        template_id=template_id,
        template_version=template_version,
        mission_id=mission_id,
        score=float(score),
        feedback=feedback,
        metadata=dict(metadata or {}),
    )
    review.reviewer_sig = reviewer.sign_json(review.signable_dict())
    return review


@dataclass
class TemplateStats:
    """Aggregated stats for one (template_id, version) — derived, not persisted in template file."""

    template_id: str
    version: str
    install_count: int = 0           # number of distinct missions instantiated from this template
    review_count: int = 0
    average_rating: float = 0.0
    weighted_average: float = 0.0    # EWMA, recent reviews weighted higher
    unique_reviewers: int = 0
    min_rating: float = 0.0
    max_rating: float = 0.0
    last_review_at: str = ""


class ReviewStore:
    """File-backed store of signed MissionReviews.

    Layout:
        missions/reviews/
        ├── <template_id>-v<version>.jsonl    # one file per template version
        └── _review_index.json                # aggregated stats
    """

    SUBDIR = "reviews"
    INDEX_NAME = "_review_index.json"

    def __init__(self, root: Union[str, Path]):
        self.root = Path(root)
        self.dir = self.root / self.SUBDIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / self.INDEX_NAME

    def _path_for(self, template_id: str, version: str) -> Path:
        return self.dir / f"{safe_id(template_id)}-v{safe_id(version)}.jsonl"

    def append(self, review: MissionReview) -> Path:
        """Append a verified review to its template's jsonl ledger.

        Raises:
            ValueError: signature verification fails.
        """
        if not review.verify_signature():
            raise ValueError("review signature does not verify")
        path = self._path_for(review.template_id, review.template_version)
        path.parent.mkdir(parents=True, exist_ok=True)
        with InterProcessLock(path):
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(review.to_dict(), ensure_ascii=False) + "\n")
        with InterProcessLock(self.index_path):
            self._refresh_index_for_unlocked(review.template_id, review.template_version)
        return path

    def list_for(
        self,
        template_id: str,
        version: str,
        *,
        only_latest_per_reviewer: bool = True,
    ) -> List[MissionReview]:
        """Read all reviews for one template version.

        only_latest_per_reviewer=True: when one reviewer has multiple entries
        (e.g. they re-rated after a bug fix), keep only the most recent —
        but the underlying JSONL keeps every entry for audit.
        """
        path = self._path_for(template_id, version)
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        reviews: List[MissionReview] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                r = MissionReview.from_dict(json.loads(line))
            except (json.JSONDecodeError, KeyError):
                continue
            if not r.verify_signature():
                logger.warning(
                    "skipping review %s with bad signature", r.review_id[:8],
                )
                continue
            reviews.append(r)
        if not only_latest_per_reviewer:
            return reviews
        # Keep the most recent per (reviewer, mission_id) tuple
        deduped: Dict[tuple, MissionReview] = {}
        for r in reviews:
            key = (r.reviewer_pubkey, r.mission_id)
            existing = deduped.get(key)
            if existing is None or r.created_at > existing.created_at:
                deduped[key] = r
        return sorted(deduped.values(), key=lambda r: r.created_at)

    # ── aggregation ──

    def stats(self, template_id: str, version: str) -> TemplateStats:
        reviews = self.list_for(template_id, version, only_latest_per_reviewer=True)
        if not reviews:
            return TemplateStats(template_id=template_id, version=version)
        scores = [r.score for r in reviews]
        # EWMA: recent reviews weighted more (alpha=0.3)
        alpha = 0.3
        sorted_by_time = sorted(reviews, key=lambda r: r.created_at)
        ewma = sorted_by_time[0].score
        for r in sorted_by_time[1:]:
            ewma = alpha * r.score + (1 - alpha) * ewma
        return TemplateStats(
            template_id=template_id,
            version=version,
            install_count=len({r.mission_id for r in reviews}),
            review_count=len(reviews),
            average_rating=round(sum(scores) / len(scores), 2),
            weighted_average=round(ewma, 2),
            unique_reviewers=len({r.reviewer_pubkey for r in reviews}),
            min_rating=min(scores),
            max_rating=max(scores),
            last_review_at=max(r.created_at for r in reviews),
        )

    def _refresh_index_for(self, template_id: str, version: str) -> None:
        with InterProcessLock(self.index_path):
            self._refresh_index_for_unlocked(template_id, version)

    def _refresh_index_for_unlocked(self, template_id: str, version: str) -> None:
        """Recompute and persist aggregated stats for one template version."""
        index = safe_load_json(self.index_path, fallback={}) or {}
        if not isinstance(index, dict):
            index = {}
        key = f"{template_id}@{version}"
        index[key] = asdict(self.stats(template_id, version))
        atomic_write_json(self.index_path, index)

    def load_index(self) -> Dict[str, Any]:
        return safe_load_json(self.index_path, fallback={}) or {}

    def rebuild_index(self) -> Dict[str, Any]:
        """Force a full rebuild from all jsonl files in <root>/reviews/."""
        index: Dict[str, Any] = {}
        for path in sorted(self.dir.glob("*.jsonl")):
            stem = path.stem
            # Parse "<template_id>-v<version>"
            if "-v" not in stem:
                continue
            template_id, version = stem.rsplit("-v", 1)
            index[f"{template_id}@{version}"] = asdict(
                self.stats(template_id, version)
            )
        with InterProcessLock(self.index_path):
            atomic_write_json(self.index_path, index)
        return index
