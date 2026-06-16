"""执行检查点:签验、最新恢复点、归属锁防劫持、record fail-closed。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.identity import AgentIdentity
from nth_dao.runtime import (
    CheckpointProjection,
    record_checkpoint,
    sign_checkpoint,
    verify_checkpoint,
)
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _proj(spine: SignedEventLog) -> CheckpointProjection:
    p = CheckpointProjection()
    replay(spine.read_all(), p)
    return p


def test_sign_verify_tamper() -> None:
    ex = _id()
    cp = sign_checkpoint(executor=ex, execution_id="run1", step=2, state={"done": ["a", "b"]})
    ok, why = verify_checkpoint(cp)
    assert ok, why
    cp["step"] = 99
    bad, _ = verify_checkpoint(cp)
    assert not bad


def test_resume_from_latest(tmp_path: Path) -> None:
    node, ex = _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    record_checkpoint(spine, sign_checkpoint(executor=ex, execution_id="run1", step=1, state={"i": 1}))
    record_checkpoint(spine, sign_checkpoint(executor=ex, execution_id="run1", step=2, state={"i": 2}))
    record_checkpoint(spine, sign_checkpoint(executor=ex, execution_id="run2", step=1, state={"j": 1}))

    ok, why = spine.verify_chain()
    assert ok, why
    proj = _proj(spine)
    r = proj.resume_point("run1")
    assert r is not None
    assert r.step == 2 and r.state == {"i": 2} and r.checkpoints == 2
    assert proj.resume_point("run2").step == 1
    assert proj.resume_point("nope") is None


def test_ownership_lock_rejects_hijack(tmp_path: Path) -> None:
    node, ex, evil = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    record_checkpoint(spine, sign_checkpoint(executor=ex, execution_id="run1", step=5, state={"i": 5}))
    # evil 想把 run1 回退到 step 0(伪造检查点劫持)。
    record_checkpoint(spine, sign_checkpoint(executor=evil, execution_id="run1", step=0, state={"i": 0}))
    r = _proj(spine).resume_point("run1")
    assert r.executor_did == ex.as_did() and r.step == 5     # evil 被拒,仍是 ex 的 step 5


def test_record_rejects_invalid(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    cp = sign_checkpoint(executor=_id(), execution_id="r", step=1)
    cp["sig"] = "forged"
    with pytest.raises(ValueError, match="invalid checkpoint"):
        record_checkpoint(spine, cp)
