"""v0.9.3 — MissionTemplate + MissionReview + browse_templates.

Aligned with the schemas of cargo-crev / F-Droid / TUF / GitHub Actions
(see docs/PROTOCOLS.md §9). These tests pin the on-disk format so future
adapters to those ecosystems stay cheap.
"""

import json
from pathlib import Path

import pytest

import nth_dao as nth
from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.orchestration import (
    IOField,
    MissionStore,
    MissionTemplate,
    MissionReview,
    StepSkeleton,
    TemplateType,
    TemplatePublishError,
    mint_review,
    mint_template,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl required for signed template tests"
)


# ─────────────────── Template — mint / load / persistence ───────────────────


def _basic_template(publisher: AgentIdentity, **overrides) -> MissionTemplate:
    kwargs = dict(
        template_id="code-review",
        version="1.0.0",
        name="Code Review",
        description="Review a diff and flag issues.",
        template_type=TemplateType.AGENT_TASK,
        category="code_review",
        tags=["python"],
        required_capabilities=["code_review"],
        inputs={
            "diff_url": IOField(description="diff URL", type="string", required=True),
        },
        outputs={
            "severity": IOField(description="severity", type="enum",
                                values=["low", "med", "high"]),
        },
        steps=[StepSkeleton(
            id="review",
            description="Read diff and write review",
            required_capabilities=["code_review"],
            inputs_from={"diff_url": "input:diff_url"},
        )],
        suggested_reward=5.0,
    )
    kwargs.update(overrides)
    return mint_template(publisher, **kwargs)


def _mark_completed(store: MissionStore, mission) -> None:
    mission.status = "completed"
    mission.completed_at = "2026-01-01T00:00:00"
    store.save(mission)


def test_mint_template_signs_payload(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    t = _basic_template(pub)
    assert t.publisher_pubkey == pub.pubkey_hex
    assert t.publisher_sig
    assert t.verify_signature()


def test_mint_template_invalid_semver_rejected(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    with pytest.raises(ValueError, match="semver"):
        _basic_template(pub, version="not-a-version")


def test_mint_template_unsigned_identity_rejected(tmp_path):
    # Plain (non-crypto) identity has no signing key
    plain = AgentIdentity.from_string("alice")
    with pytest.raises(ValueError, match="signing-capable"):
        _basic_template(plain)


def test_template_tamper_fails_signature(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    t = _basic_template(pub)
    assert t.verify_signature()
    t.suggested_reward = 99.0  # tamper after signing
    assert not t.verify_signature()


def test_template_publish_round_trip(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    t = _basic_template(pub)
    path = store.publish_template(t)
    assert path.exists()
    # On-disk filename matches file_stem
    assert path.name == "code-review-v1.0.0.json"
    # Reload via store
    loaded = store.templates.load("code-review", "1.0.0")
    assert loaded is not None
    assert loaded.publisher_sig == t.publisher_sig
    assert loaded.verify_signature()


def test_template_publish_duplicate_version_rejected(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    t = _basic_template(pub)
    store.publish_template(t)
    with pytest.raises(TemplatePublishError, match="already exists"):
        store.publish_template(t)
    # Bump version → ok
    t2 = _basic_template(pub, version="1.0.1")
    store.publish_template(t2)


def test_template_publish_rejects_invalid_signature(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    t = _basic_template(pub)
    t.publisher_sig = "00" * 64  # tamper
    with pytest.raises(TemplatePublishError, match="signature does not verify"):
        store.publish_template(t)


def test_signed_index_built_on_publish(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    idx = store.templates.load_index()
    assert idx["version"] >= 1
    assert "code-review-v1.0.0.json" in idx["meta"]
    assert "code_review" in idx["by_category"]
    assert any("code-review" in ref for ref in idx["by_category"]["code_review"])


def test_list_versions_descending(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    for v in ("0.9.0", "1.0.0", "1.0.1", "2.0.0"):
        store.publish_template(_basic_template(pub, version=v))
    versions = store.templates.list_versions("code-review")
    assert versions == ["2.0.0", "1.0.1", "1.0.0", "0.9.0"]
    assert store.templates.latest_version("code-review") == "2.0.0"


def test_list_versions_uses_semver_prerelease_precedence(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    for v in ("1.0.0-rc.1", "1.0.0", "1.0.1"):
        store.publish_template(_basic_template(pub, version=v))
    assert store.templates.list_versions("code-review") == [
        "1.0.1", "1.0.0", "1.0.0-rc.1",
    ]


def test_iofield_rejects_bool_as_int_and_unknown_type():
    assert IOField(type="int").validate_value(True) == "expected int, got bool"
    assert IOField(type="mystery").validate_value("x") == "unknown field type 'mystery'"


# ─────────────────── Instantiation ───────────────────


def test_instantiate_produces_mission_with_template_lock(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    t = _basic_template(pub)
    store.publish_template(t)
    m = store.instantiate(
        "code-review", "1.0.0",
        owner="bob",
        inputs={"diff_url": "https://example.com/pr/42"},
    )
    assert m.template_id == "code-review"
    assert m.template_version == "1.0.0"
    # Lock snapshots publisher signature
    assert m.template_lock["publisher_sig"] == t.publisher_sig
    assert m.template_lock["publisher_pubkey"] == t.publisher_pubkey
    assert m.template_lock["template_type"] == "agent_task"
    # Steps were materialized from the skeleton
    assert len(m.steps) == 1
    assert m.steps[0].description == "Read diff and write review"
    assert m.steps[0].inputs["diff_url"] == "https://example.com/pr/42"


def test_instantiate_validates_required_inputs(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    with pytest.raises(ValueError, match="diff_url"):
        store.instantiate(
            "code-review", "1.0.0", owner="bob",
            inputs={},  # missing required diff_url
        )


def test_instantiate_validates_enum_outputs_indirectly_at_input_layer(tmp_path):
    """Enum validation runs only on inputs; outputs are produced by agents."""
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    # Add an enum *input* and confirm bad value is rejected
    t = mint_template(
        pub,
        template_id="enum-test",
        version="1.0.0",
        name="Enum",
        inputs={
            "severity": IOField(type="enum", values=["low", "high"], required=True),
        },
    )
    store.publish_template(t)
    with pytest.raises(ValueError, match="enum"):
        store.instantiate("enum-test", "1.0.0", owner="bob",
                          inputs={"severity": "BOGUS"})


def test_instantiate_latest_when_version_omitted(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub, version="1.0.0"))
    store.publish_template(_basic_template(pub, version="2.5.0"))
    m = store.instantiate("code-review", owner="bob",
                          inputs={"diff_url": "x"})
    assert m.template_version == "2.5.0"


def test_instantiate_deprecated_template_rejected(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    store.templates.deprecate(pub, "code-review", "1.0.0",
                              reason="known to misjudge security issues")
    with pytest.raises(ValueError, match="deprecated"):
        store.instantiate("code-review", "1.0.0", owner="bob",
                          inputs={"diff_url": "x"})


def test_deprecate_by_non_publisher_rejected(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    other = AgentIdentity.generate(label="mallory")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    with pytest.raises(TemplatePublishError, match="original publisher"):
        store.templates.deprecate(other, "code-review", "1.0.0")


def test_legacy_mission_without_template_unaffected(tmp_path):
    """v0.9.2-style free-form mission still works (no template fields set)."""
    from nth_dao.orchestration import Mission
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(
        title="adhoc", goal="g", owner="alice",
        steps=[{"id": "s1", "description": "x"}],
    )
    store.create(m)
    assert store.get(m.id).template_id is None
    assert store.get(m.id).template_lock == {}


# ─────────────────── Review ───────────────────


def test_review_signs_and_persists(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    m = store.instantiate("code-review", "1.0.0", owner="alice",
                          inputs={"diff_url": "x"})
    _mark_completed(store, m)
    r = store.review_mission(m.id, reviewer=bob, score=4.5,
                             feedback="caught 3 edge cases")
    assert r.verify_signature()
    # On-disk JSONL line written
    review_file = tmp_path / "missions" / "reviews" / "code-review-v1.0.0.jsonl"
    assert review_file.exists()
    lines = review_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


def test_review_score_range_validated(tmp_path):
    bob = AgentIdentity.generate(label="bob")
    with pytest.raises(ValueError, match="score must be in"):
        mint_review(bob, template_id="x", template_version="1.0.0",
                    mission_id="m", score=7.0)


def test_review_self_review_rejected(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    m = store.instantiate("code-review", "1.0.0",
                          owner=str(pub.agent_id),
                          inputs={"diff_url": "x"})
    _mark_completed(store, m)
    with pytest.raises(ValueError, match="own mission"):
        store.review_mission(m.id, reviewer=pub, score=5.0)


def test_review_non_template_mission_rejected(tmp_path):
    from nth_dao.orchestration import Mission
    bob = AgentIdentity.generate(label="bob")
    store = MissionStore(str(tmp_path / "missions"))
    m = Mission.new(title="adhoc", goal="g", owner="alice",
                    steps=[{"id": "s1", "description": "x"}])
    store.create(m)
    with pytest.raises(ValueError, match="not instantiated from a template"):
        store.review_mission(m.id, reviewer=bob, score=5.0)


def test_review_unfinished_template_mission_rejected(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    m = store.instantiate("code-review", "1.0.0", owner="alice",
                          inputs={"diff_url": "x"})
    with pytest.raises(ValueError, match="not completed"):
        store.review_mission(m.id, reviewer=bob, score=4.0)


def test_review_tamper_rejected_at_append(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    m = store.instantiate("code-review", "1.0.0", owner="alice",
                          inputs={"diff_url": "x"})
    r = mint_review(bob, template_id="code-review", template_version="1.0.0",
                    mission_id=m.id, score=3.0)
    r.feedback = "tampered"  # post-signing tamper
    with pytest.raises(ValueError, match="signature does not verify"):
        store.reviews.append(r)


def test_template_stats_aggregate_ratings(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    # Three different reviewers + different missions
    for i, score in enumerate([3.0, 4.0, 5.0]):
        bob = AgentIdentity.generate(label=f"bob-{i}")
        m = store.instantiate("code-review", "1.0.0", owner="alice",
                              inputs={"diff_url": f"diff-{i}"})
        _mark_completed(store, m)
        store.review_mission(m.id, reviewer=bob, score=score)
    stats = store.template_stats("code-review", "1.0.0")
    assert stats.review_count == 3
    assert stats.install_count == 3
    assert stats.unique_reviewers == 3
    assert stats.average_rating == pytest.approx(4.0)
    assert stats.min_rating == 3.0
    assert stats.max_rating == 5.0


def test_review_dedup_per_reviewer_per_mission(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    m = store.instantiate("code-review", "1.0.0", owner="alice",
                          inputs={"diff_url": "x"})
    _mark_completed(store, m)
    store.review_mission(m.id, reviewer=bob, score=3.0)
    store.review_mission(m.id, reviewer=bob, score=4.5)  # bob updates rating
    reviews = store.reviews.list_for("code-review", "1.0.0",
                                     only_latest_per_reviewer=True)
    assert len(reviews) == 1
    assert reviews[0].score == 4.5
    # The audit log still has both
    raw = store.reviews.list_for("code-review", "1.0.0",
                                 only_latest_per_reviewer=False)
    assert len(raw) == 2


# ─────────────────── Browse ───────────────────


def test_browse_orders_by_rating(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    # Two templates; second gets higher ratings
    store.publish_template(_basic_template(pub, template_id="a", version="1.0.0"))
    store.publish_template(_basic_template(pub, template_id="b", version="1.0.0"))
    bob = AgentIdentity.generate(label="bob")
    m1 = store.instantiate("a", "1.0.0", owner="alice", inputs={"diff_url": "x"})
    _mark_completed(store, m1)
    store.review_mission(m1.id, reviewer=bob, score=2.0)
    m2 = store.instantiate("b", "1.0.0", owner="alice", inputs={"diff_url": "x"})
    _mark_completed(store, m2)
    store.review_mission(m2.id, reviewer=bob, score=4.8)

    results = store.browse_templates(sort_by="rating")
    assert [r["template"].template_id for r in results[:2]] == ["b", "a"]


def test_browse_filters_by_category(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub, template_id="cr",
                                           category="code_review"))
    store.publish_template(_basic_template(pub, template_id="dc",
                                           category="data_cleanup"))
    results = store.browse_templates(category="data_cleanup")
    assert len(results) == 1
    assert results[0]["template"].template_id == "dc"


def test_browse_excludes_deprecated_by_default(tmp_path):
    pub = AgentIdentity.generate(label="alice")
    store = MissionStore(str(tmp_path / "missions"))
    store.publish_template(_basic_template(pub))
    store.templates.deprecate(pub, "code-review", "1.0.0", reason="obsolete")
    assert store.browse_templates() == []
    assert len(store.browse_templates(include_deprecated=True)) == 1


# ─────────────────── facade ───────────────────


# ─────────────────── Archive + history ───────────────────


def test_archive_completed_moves_old_terminal_missions(tmp_path):
    from datetime import datetime, timedelta
    from nth_dao.orchestration import Mission, MissionStatus
    store = MissionStore(str(tmp_path / "missions"))
    # Fresh terminal mission — should NOT move
    fresh = Mission.new(title="fresh", goal="g", owner="alice",
                        steps=[{"id": "s", "description": "x"}])
    fresh.status = MissionStatus.COMPLETED.value
    fresh.completed_at = datetime.now().isoformat()
    store.create(fresh)
    # Old terminal mission — should move
    old = Mission.new(title="old", goal="g", owner="alice",
                      steps=[{"id": "s", "description": "x"}])
    old.status = MissionStatus.COMPLETED.value
    old.completed_at = (datetime.now() - timedelta(days=60)).isoformat()
    store.create(old)
    # Still-active mission — should NOT move
    live = Mission.new(title="live", goal="g", owner="alice",
                       steps=[{"id": "s", "description": "x"}])
    store.create(live)

    moved = store.archive_completed(older_than_days=30)
    assert moved == 1
    # Old gone from top-level
    assert store.get(old.id) is None
    # But discoverable via archive
    archived_ids = [m.id for m in store.list_archive()]
    assert old.id in archived_ids
    # Fresh and live still at top-level
    assert store.get(fresh.id) is not None
    assert store.get(live.id) is not None


def test_my_history_owner_and_assignee(tmp_path):
    from nth_dao.orchestration import Mission
    store = MissionStore(str(tmp_path / "missions"))
    # Mission alice owns
    m1 = Mission.new(title="owned", goal="g", owner="alice",
                     steps=[{"id": "s", "description": "x"}])
    store.create(m1)
    # Mission bob owns, alice is current assignee
    m2 = Mission.new(title="assigned", goal="g", owner="bob",
                     steps=[{"id": "s", "description": "x"}])
    store.create(m2)
    store.try_claim(m2.id, "s", agent_id="alice", capabilities=[])
    # Mission carol owns, alice was prior assignee but handed off
    m3 = Mission.new(title="handed", goal="g", owner="carol",
                     steps=[{"id": "s", "description": "x"}])
    store.create(m3)
    store.try_claim(m3.id, "s", agent_id="alice", capabilities=[])
    store.update_step(m3.id, "s", status="handed_off", assignee="dave")

    hist = store.my_history("alice")
    ids = {m.id for m in hist}
    assert m1.id in ids and m2.id in ids and m3.id in ids
    # carol-owned mission with no alice touch not in alice history
    m4 = Mission.new(title="other", goal="g", owner="carol",
                     steps=[{"id": "s", "description": "x"}])
    store.create(m4)
    hist2 = store.my_history("alice")
    assert m4.id not in {m.id for m in hist2}


def test_my_history_walks_archive(tmp_path):
    from datetime import datetime, timedelta
    from nth_dao.orchestration import Mission, MissionStatus
    store = MissionStore(str(tmp_path / "missions"))
    old = Mission.new(title="ancient", goal="g", owner="alice",
                      steps=[{"id": "s", "description": "x"}])
    old.status = MissionStatus.COMPLETED.value
    old.completed_at = (datetime.now() - timedelta(days=100)).isoformat()
    store.create(old)
    store.archive_completed(older_than_days=30)
    # Archive-only mission still surfaces in history by default
    assert store.get(old.id) is None
    assert any(m.id == old.id for m in store.my_history("alice"))
    # Disable archive walk → archived items no longer in history
    assert not any(m.id == old.id for m in store.my_history("alice", include_archive=False))


def test_facade_exports_v093_symbols():
    assert nth.MissionTemplate is MissionTemplate
    assert nth.TemplateType is TemplateType
    assert nth.IOField is IOField
    assert nth.StepSkeleton is StepSkeleton
    assert nth.mint_template is mint_template
    assert nth.MissionReview is MissionReview
    assert nth.mint_review is mint_review
    assert nth.TemplatePublishError is TemplatePublishError
