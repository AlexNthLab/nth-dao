"""
MissionStore — file-backed persistence for Mission objects.

Design:
    - Each mission lives in missions/<mission_id>.json
    - Writes use a tmp + rename atomic dance (see util.atomic_write_json)
    - Multi-process safety: try_claim() and update_step() acquire an
      InterProcessLock + thread-local RLock before reading + writing
    - Mission state is what gets Git-synced (via PR 5 git_sync) — that's how
      missions follow you across terminals
"""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .mission import Mission, MissionStatus, MissionStep, StepStatus
from .template import (
    MissionTemplate,
    TemplateStore,
    TemplatePublishError,
    TemplateType,
)
from .review import (
    MissionReview,
    ReviewStore,
    TemplateStats,
    mint_review,
)
from ..util import (
    atomic_write_json,
    safe_load_json,
    safe_id as _safe_id,
    InterProcessLock,
)


# 进程内 RLock 加 fast path（避免对同一 mission 多个 thread 都去抢文件锁）
_LOCKS: Dict[str, threading.RLock] = {}
_LOCK_GUARD = threading.Lock()


def _thread_lock_for(path: str) -> threading.RLock:
    with _LOCK_GUARD:
        if path not in _LOCKS:
            _LOCKS[path] = threading.RLock()
        return _LOCKS[path]


class ClaimConflict(Exception):
    """Step 已被别的 agent claim 或已超出可 claim 状态。"""


class MissionNotFound(Exception):
    pass


class StepNotFound(Exception):
    pass


class MissionStore:
    """Mission """

    DEFAULT_DIR = "missions"

    def __init__(self, root: Optional[str] = None):
        """
        Args:
            root: Mission root dir, defaults to ./missions/. Git-syncable.
        """
        self.root = Path(root) if root else Path(self.DEFAULT_DIR)
        self.root.mkdir(parents=True, exist_ok=True)
        # v0.9.3: template + review sub-stores live under the same root
        self.templates = TemplateStore(self.root)
        self.reviews = ReviewStore(self.root)

    #

    def save(self, mission: Mission) -> Path:
        """Atomically save a mission under thread and process locks."""
        path = self._path_for(mission.id)
        with _thread_lock_for(str(path)), InterProcessLock(path):
            return self._save_unlocked(mission)

    def create(self, mission: Mission) -> Path:
        """Create a new mission, failing if the id already exists."""
        path = self._path_for(mission.id)
        with _thread_lock_for(str(path)), InterProcessLock(path):
            if path.exists():
                raise FileExistsError(f"mission {mission.id} already exists")
            return self._save_unlocked(mission)

    def delete(self, mission_id: str) -> bool:
        path = self._path_for(mission_id)
        if not path.exists():
            return False
        with _thread_lock_for(str(path)), InterProcessLock(path):
            if path.exists():
                path.unlink()
        return True

    #

    def get(self, mission_id: str) -> Optional[Mission]:
        path = self._path_for(mission_id)
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return Mission.from_dict(data)
        except Exception:
            return None

    def list_all(self) -> List[Mission]:
        results = []
        for f in sorted(self.root.glob("*.json")):
            data = safe_load_json(f, fallback=None)
            if data is None:
                continue
            try:
                results.append(Mission.from_dict(data))
            except Exception:
                continue
        return results

    def list_active(self) -> List[Mission]:
        return [
            m for m in self.list_all()
            if m.status in (MissionStatus.ACTIVE.value, MissionStatus.PLANNING.value)
        ]

    # ─── v0.9.3: archive + history ───

    ARCHIVE_SUBDIR = "archive"

    def _archive_dir_for(self, when: Optional[str]) -> Path:
        """Archive dir bucketed by year-month: archive/YYYY-MM/."""
        if not when:
            when = datetime.now().isoformat()
        ym = when[:7] if len(when) >= 7 else datetime.now().strftime("%Y-%m")
        return self.root / self.ARCHIVE_SUBDIR / ym

    def archive_completed(self, older_than_days: int = 30) -> int:
        """Move done/failed/cancelled missions older than N days into archive/.

        Archive layout:
            missions/archive/YYYY-MM/<id>.json

        Active scans (list_all, list_active) only look at the top level; the
        archive grows separately and survives git_sync. `my_history()` walks
        both. Returns the number of missions moved.
        """
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=max(0, older_than_days))
        moved = 0
        terminal = {
            MissionStatus.COMPLETED.value,
            MissionStatus.FAILED.value,
            MissionStatus.CANCELLED.value,
        }
        for mission in self.list_all():
            if mission.status not in terminal:
                continue
            ref_ts = mission.completed_at or mission.updated_at or mission.created_at
            try:
                ref_dt = datetime.fromisoformat(ref_ts)
            except (TypeError, ValueError):
                continue
            if ref_dt > cutoff:
                continue
            src = self._path_for(mission.id)
            dst_dir = self._archive_dir_for(ref_ts)
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / src.name
            with _thread_lock_for(str(src)), InterProcessLock(src):
                if not src.exists():
                    continue
                # Use atomic write to dst, then unlink src — safer than rename
                # which can fail across filesystems
                atomic_write_json(dst, mission.to_dict())
                try:
                    src.unlink()
                except OSError:
                    # Roll back the dst if we couldn't remove the src
                    try:
                        dst.unlink()
                    except OSError:
                        pass
                    continue
                moved += 1
        return moved

    def list_archive(self, year_month: Optional[str] = None) -> List[Mission]:
        """All archived missions; optionally restrict to a YYYY-MM bucket."""
        archive_root = self.root / self.ARCHIVE_SUBDIR
        if not archive_root.exists():
            return []
        if year_month:
            buckets = [archive_root / year_month]
        else:
            buckets = [d for d in archive_root.iterdir() if d.is_dir()]
        out: List[Mission] = []
        for bucket in sorted(buckets):
            if not bucket.exists():
                continue
            for f in sorted(bucket.glob("*.json")):
                data = safe_load_json(f, fallback=None)
                if data is None:
                    continue
                try:
                    out.append(Mission.from_dict(data))
                except Exception:
                    continue
        return out

    def my_history(
        self,
        agent_id: str,
        *,
        since: Optional[str] = None,
        include_archive: bool = True,
        limit: Optional[int] = None,
    ) -> List[Mission]:
        """All missions this agent participated in (owned, assigned, or prior assignee).

        Used by the future AgentLedger reducer; for now exposed as a
        first-class query so users can build personal kanban / contribution
        views without writing a custom walker.

        Args:
            agent_id: target agent_id (matched against owner, current assignees,
                      and previous_assignees on each step)
            since: ISO timestamp lower bound (uses completed_at, falling back to created_at)
            include_archive: walk archive/ too (default True)
            limit: cap on returned mission count, newest first

        Returns missions ordered by completed_at desc (None first / still active).
        """
        out: List[Mission] = []
        sources: List[Mission] = list(self.list_all())
        if include_archive:
            sources.extend(self.list_archive())

        def _touched(m: Mission) -> bool:
            if m.owner == agent_id:
                return True
            for s in m.steps:
                if s.assignee == agent_id:
                    return True
                if agent_id in s.previous_assignees:
                    return True
            return False

        for m in sources:
            if not _touched(m):
                continue
            if since:
                ref = m.completed_at or m.updated_at or m.created_at
                if ref and ref < since:
                    continue
            out.append(m)

        # Sort: still-active first (no completed_at), then newest completed first
        def _sortkey(m: Mission):
            ts = m.completed_at or "9999-12-31"  # active items bubble to front
            return ts
        out.sort(key=_sortkey, reverse=True)
        if limit:
            return out[:limit]
        return out

    def list_for_agent(
        self,
        agent_id: str,
        agent_capabilities: Optional[List[str]] = None,
        include_team: bool = True,
    ) -> List[Mission]:
        """
         Agent  Mission
        -  owner
        -  step.assignee=
        - shared scope  include_team
        -  claim  step  capability
        """
        all_missions = self.list_active()
        relevant = []
        for m in all_missions:
            if m.owner == agent_id:
                relevant.append(m)
                continue
            if any(s.assignee == agent_id for s in m.steps):
                relevant.append(m)
                continue
            if include_team and m.scope == "shared":
                actionable = m.next_actionable(agent_capabilities)
                if actionable:
                    relevant.append(m)
        return relevant

    #

    def update_step(
        self,
        mission_id: str,
        step_id: str,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        output: Optional[dict] = None,
        note: Optional[str] = None,
        note_author: str = "system",
        expect_status: Optional[str] = None,
        expect_assignee_in: Optional[List[str]] = None,
    ) -> Optional[MissionStep]:
        """更新 step + 检查 mission 终态。

        新增 compare-and-swap 前置条件参数：
            expect_status: 调用方期待 step 当前状态在此列表里（单值或 None=不检查）
            expect_assignee_in: 期待 step.assignee 在此列表里（"" 字符串代表"未占用"）
        前置不满足 → 抛 ClaimConflict（NOT silent overwrite）。

        Mission 状态机：
            - 所有 step DONE                  → COMPLETED
            - 至少一个 step FAILED 且无 actionable → FAILED
            - PLANNING 中有任意 step 离开 TODO → ACTIVE
        """
        path = self._path_for(mission_id)
        with _thread_lock_for(str(path)), InterProcessLock(path):
            mission = self.get(mission_id)
            if mission is None:
                return None
            step = mission.get_step(step_id)
            if step is None:
                return None

            # ── compare-and-swap 前置 ──
            if expect_status is not None and step.status != expect_status:
                raise ClaimConflict(
                    f"step {step_id} expected status={expect_status} "
                    f"but is {step.status}"
                )
            if expect_assignee_in is not None:
                # "" 在列表里 = 允许未分配；其它字符串 = 允许这个 agent
                if (step.assignee or "") not in expect_assignee_in:
                    raise ClaimConflict(
                        f"step {step_id} expected assignee in {expect_assignee_in} "
                        f"but is '{step.assignee}'"
                    )

            # ── apply 状态变更 ──
            # 关键修复：previous_assignees 在同一次调用里只 push 一次
            old_assignee = step.assignee
            new_assignee = assignee if assignee is not None else old_assignee
            if old_assignee and new_assignee and old_assignee != new_assignee:
                step.previous_assignees.append(old_assignee)

            if status is not None:
                step.status = status
                if status == StepStatus.DONE.value:
                    step.completed_at = datetime.now().isoformat()
            if assignee is not None:
                step.assignee = assignee
            if output is not None:
                step.output = output
            if note:
                step.add_note(note, note_author)

            # ── Mission 终态机 ──
            now_iso = datetime.now().isoformat()
            if mission.is_finished():
                mission.status = MissionStatus.COMPLETED.value
                mission.completed_at = now_iso
            elif _mission_is_dead(mission):
                # 有 FAILED step 且没有 actionable step → mission FAILED
                mission.status = MissionStatus.FAILED.value
                if not mission.completed_at:
                    mission.completed_at = now_iso
            elif mission.status == MissionStatus.PLANNING.value and any(
                s.status != StepStatus.TODO.value for s in mission.steps
            ):
                mission.status = MissionStatus.ACTIVE.value

            self._save_unlocked(mission)
            return step

    def try_claim(
        self,
        mission_id: str,
        step_id: str,
        agent_id: str,
        capabilities: Optional[List[str]] = None,
    ) -> Optional[MissionStep]:
        """专门的原子 claim 入口 —— 失败抛 ClaimConflict.

        要求 step 当前在 TODO/HANDED_OFF/BLOCKED 之一，且 assignee 为空 或 == agent_id
        （后者支持 retry 同一 agent 重新 claim）。
        """
        allowed_status_when_unassigned = StepStatus.TODO.value
        # 用 update_step 的 CAS：但 update_step 一次只能 expect 一个 status；
        # 这里手动加锁后再做更细的检查。
        path = self._path_for(mission_id)
        with _thread_lock_for(str(path)), InterProcessLock(path):
            mission = self.get(mission_id)
            if mission is None:
                raise MissionNotFound(mission_id)
            step = mission.get_step(step_id)
            if step is None:
                raise StepNotFound(step_id)

            if step.status not in (
                StepStatus.TODO.value,
                StepStatus.HANDED_OFF.value,
                StepStatus.BLOCKED.value,
            ):
                raise ClaimConflict(
                    f"step {step_id} not claimable (status={step.status})"
                )

            if step.assignee and step.assignee != agent_id:
                # HANDED_OFF 给特定 agent 的情况：只允许那个 agent claim
                if step.status == StepStatus.HANDED_OFF.value:
                    raise ClaimConflict(
                        f"step {step_id} handed off to {step.assignee}, not {agent_id}"
                    )
                # 其它情况 assignee != "" 意味着已被 claim
                raise ClaimConflict(
                    f"step {step_id} already claimed by {step.assignee}"
                )

            # capability check
            if step.required_capabilities and capabilities is not None:
                if not set(step.required_capabilities).issubset(set(capabilities)):
                    raise ClaimConflict(
                        f"step {step_id} requires {step.required_capabilities}, "
                        f"agent only has {capabilities}"
                    )

            # 提交 claim
            old_assignee = step.assignee
            if old_assignee and old_assignee != agent_id:
                step.previous_assignees.append(old_assignee)
            step.status = StepStatus.ACTIVE.value
            step.assignee = agent_id
            step.add_note(
                f"claimed by {agent_id} (caps={capabilities or []})",
                author=agent_id,
            )

            if mission.status == MissionStatus.PLANNING.value:
                mission.status = MissionStatus.ACTIVE.value

            self._save_unlocked(mission)
            return step

    # ─── v0.9.3: template + review API ───

    def publish_template(
        self,
        template: MissionTemplate,
        *,
        allow_overwrite: bool = False,
    ) -> Path:
        """Persist a signed MissionTemplate. Verifies sig before writing."""
        return self.templates.publish(template, allow_overwrite=allow_overwrite)

    def list_templates(
        self,
        *,
        category: Optional[str] = None,
        publisher_pubkey: Optional[str] = None,
        required_capabilities: Optional[List[str]] = None,
        include_deprecated: bool = False,
    ) -> List[MissionTemplate]:
        """Flat listing of all known templates; optional simple filters."""
        out = self.templates.list_all(include_deprecated=include_deprecated)
        if category is not None:
            out = [t for t in out if t.category == category]
        if publisher_pubkey is not None:
            out = [t for t in out if t.publisher_pubkey == publisher_pubkey]
        if required_capabilities is not None:
            required = set(required_capabilities)
            out = [t for t in out if required.issubset(set(t.required_capabilities))]
        return out

    def browse_templates(
        self,
        *,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_average_rating: float = 0.0,
        sort_by: str = "rating",        # "rating" | "recent" | "popularity"
        limit: int = 20,
        include_deprecated: bool = False,
    ) -> List[dict]:
        """Browse templates joined with their aggregated stats.

        Returns a list of dicts, each {"template": MissionTemplate,
        "stats": TemplateStats}, ordered by sort_by.
        """
        templates = self.list_templates(
            category=category,
            include_deprecated=include_deprecated,
        )
        if tags:
            tag_set = set(tags)
            templates = [t for t in templates if tag_set.intersection(t.tags)]
        joined = []
        for t in templates:
            stats = self.reviews.stats(t.template_id, t.version)
            if stats.weighted_average < min_average_rating and stats.review_count > 0:
                continue
            # No reviews yet → don't gate by min_average_rating; surface them
            joined.append({"template": t, "stats": stats})

        def _rating_key(item):
            s = item["stats"]
            # Reviewed templates first, then by EWMA score, then by review count
            return (s.review_count > 0, s.weighted_average, s.review_count)

        if sort_by == "rating":
            joined.sort(key=_rating_key, reverse=True)
        elif sort_by == "recent":
            joined.sort(
                key=lambda i: i["template"].created_at, reverse=True,
            )
        elif sort_by == "popularity":
            joined.sort(
                key=lambda i: (i["stats"].install_count, i["stats"].review_count),
                reverse=True,
            )
        else:
            raise ValueError(f"unknown sort_by: {sort_by!r}")
        return joined[:limit] if limit else joined

    def instantiate(
        self,
        template_id: str,
        version: Optional[str] = None,
        *,
        owner: str,
        inputs: Optional[Dict[str, Any]] = None,
        scope: str = "shared",
        priority: str = "normal",
        title: Optional[str] = None,
        goal: Optional[str] = None,
    ) -> Mission:
        """Create a Mission instance from a template (Nix-flake-lock style).

        The resulting Mission carries template_id, template_version, AND a
        snapshot of the publisher_sig so that even if the template is later
        modified or deprecated, this instance stays reproducible.

        Raises:
            ValueError:  template missing, deprecated, or inputs invalid.
            TemplatePublishError: signature on the loaded template fails.
        """
        if version is None:
            version = self.templates.latest_version(template_id)
            if version is None:
                raise ValueError(f"no template found for {template_id!r}")
        tpl = self.templates.load(template_id, version)
        if tpl is None:
            raise ValueError(
                f"template {template_id}@{version} not found in store"
            )
        if not tpl.verify_signature():
            raise TemplatePublishError(
                f"loaded template {template_id}@{version} "
                f"has invalid signature; refusing to instantiate"
            )
        if tpl.deprecated:
            raise ValueError(
                f"template {template_id}@{version} is deprecated: "
                f"{tpl.deprecated_reason or '(no reason given)'}"
            )
        inputs = dict(inputs or {})
        err = tpl.validate_inputs(inputs)
        if err:
            raise ValueError(f"inputs for {template_id}@{version}: {err}")

        # Build the mission from the template's step skeletons
        step_dicts = []
        for skel in tpl.steps:
            step_inputs: Dict[str, Any] = {}
            for skel_input_key, source in skel.inputs_from.items():
                # Simple sourcing: "input:NAME" pulls from the provided inputs
                if source.startswith("input:"):
                    src_name = source[len("input:"):]
                    if src_name in inputs:
                        step_inputs[skel_input_key] = inputs[src_name]
            step_dicts.append({
                "id": skel.id,
                "description": skel.description,
                "required_capabilities": list(skel.required_capabilities),
                "depends_on": list(skel.depends_on),
                "inputs": step_inputs,
            })

        mission = Mission.new(
            title=title or tpl.name or f"{template_id} instance",
            goal=goal or tpl.description or "",
            owner=owner,
            scope=scope,
            steps=step_dicts,
            deadline=None,
            priority=priority,
            tags=list(tpl.tags),
        )
        mission.template_id = template_id
        mission.template_version = version
        # Nix-flake-lock style snapshot of the template at instantiation time
        mission.template_lock = {
            "publisher_pubkey": tpl.publisher_pubkey,
            "publisher_sig": tpl.publisher_sig,
            "template_type": tpl.template_type.value if isinstance(tpl.template_type, TemplateType) else tpl.template_type,
            "category": tpl.category,
            "instantiated_at": datetime.now().isoformat(),
        }
        self.create(mission)
        return mission

    def review_mission(
        self,
        mission_id: str,
        reviewer,                # AgentIdentity
        score: float,
        feedback: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MissionReview:
        """Sign + append a review of a completed mission.

        Raises:
            ValueError: mission missing, self-review, or no template linkage.
        """
        mission = self.get(mission_id)
        if mission is None:
            raise ValueError(f"mission {mission_id} not found")
        if not mission.template_id or not mission.template_version:
            raise ValueError(
                f"mission {mission_id} was not instantiated from a template; "
                "free-form missions cannot accept reviews in v0.9.3"
            )
        if mission.status != MissionStatus.COMPLETED.value:
            raise ValueError(
                f"mission {mission_id} is not completed; "
                f"current status={mission.status!r}"
            )
        # Self-review guard: the mission's owner cannot review their own work
        if mission.owner == str(getattr(reviewer, "agent_id", "")):
            raise ValueError("cannot review your own mission")
        review = mint_review(
            reviewer=reviewer,
            template_id=mission.template_id,
            template_version=mission.template_version,
            mission_id=mission_id,
            score=score,
            feedback=feedback,
            metadata=metadata,
        )
        self.reviews.append(review)
        return review

    def template_stats(
        self,
        template_id: str,
        version: Optional[str] = None,
    ) -> TemplateStats:
        if version is None:
            version = self.templates.latest_version(template_id) or ""
        return self.reviews.stats(template_id, version)

    #

    def _path_for(self, mission_id: str) -> Path:
        return self.root / f"{_safe_id(mission_id)}.json"

    def _save_unlocked(self, mission: Mission) -> Path:
        path = self._path_for(mission.id)
        mission.updated_at = datetime.now().isoformat()
        atomic_write_json(path, mission.to_dict())
        return path


def _mission_is_dead(mission: Mission) -> bool:
    """有 FAILED step 且不再有 actionable 的 step → 整个 mission 死了。"""
    if not any(s.status == StepStatus.FAILED.value for s in mission.steps):
        return False
    # 不传 capability，宽容意义上看是否还有 step 能被推进
    return not mission.next_actionable(agent_capabilities=None)
