import hashlib
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import (
    manifest_body,
    offer_body,
    offer_digest,
    sign_manifest,
    sign_offer,
)
from nth_dao.trade_rules.negotiation import (
    RuleNegotiationError,
    RuleResolutionPolicy,
    resolve_canonical_offer_rules,
    resolve_offer_rules,
)
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageStore,
    build_rule_package,
)
from nth_dao.trade_rules.store import OfferStore

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)

_AT = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _manifest(
    identity,
    *,
    rule_id,
    version="1.0.0",
    dependencies=(),
    conflicts=(),
    capabilities=(),
    execution_mode="declarative",
    permissions=(),
    published_at="2026-07-29T00:00:00Z",
    not_after="2027-07-29T00:00:00Z",
):
    payload = f"terms:{rule_id}:{version}".encode()
    digest = _digest(payload)
    body = manifest_body(
        rule_id=rule_id,
        version=version,
        publisher_did=identity.as_did(),
        summary=f"Rule {rule_id}",
        applies_to=["service"],
        families=["fulfillment"],
        resources=[
            {
                "purpose": "terms",
                "media_type": "application/json",
                "digest": digest,
                "size": len(payload),
            }
        ],
        dependencies=dependencies,
        conflicts=conflicts,
        required_capabilities=capabilities,
        execution_mode=execution_mode,
        permissions=permissions,
        published_at=published_at,
        not_after=not_after,
    )
    manifest = sign_manifest(
        identity, body, created=published_at
    )
    return manifest, {digest: payload}


def _offer(identity, refs, *, state="active", not_after="2027-07-29T00:00:00Z"):
    descriptor = _digest(b"service")
    body = offer_body(
        offer_id="org.nthdao.test/negotiation",
        publisher_did=identity.as_did(),
        title="Negotiated service",
        summary="Offer whose rules must resolve exactly.",
        provides=[
            {
                "leg_id": "service",
                "resource_type": "service",
                "resource_id": "urn:nthdao:test:service",
                "quantity": "1",
                "unit": "job",
                "descriptor_digest": descriptor,
            }
        ],
        requests=[],
        rule_refs=refs,
        state=state,
        published_at="2026-07-29T00:00:00Z",
        not_after=not_after,
    )
    return sign_offer(
        identity, body, created="2026-07-29T00:00:01Z"
    )


def _successor(identity, previous, refs):
    body = offer_body(
        offer_id=previous.offer_id,
        revision=2,
        previous_offer_digest=offer_digest(previous),
        publisher_did=identity.as_did(),
        title="Negotiated service revision 2",
        summary="Canonical successor.",
        provides=previous.to_dict()["provides"],
        requests=[],
        rule_refs=refs,
        published_at="2026-07-30T00:00:00Z",
        not_after="2027-07-30T00:00:00Z",
    )
    return sign_offer(
        identity, body, created="2026-07-30T00:00:01Z"
    )


def _install(store, manifest, resources):
    return store.install(manifest, resources).digest


def test_empty_rule_set_needs_no_trust_grant(tmp_path):
    identity = AgentIdentity.generate()
    resolution = resolve_offer_rules(
        _offer(identity, []),
        RulePackageStore(tmp_path),
        RuleResolutionPolicy(),
        at=_AT,
    )
    assert resolution.ordered_digests == ()
    assert resolution.bindings() == ()


def test_resolves_exact_rule_accepted_by_publisher(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.delivery",
        capabilities=["org.nthdao.test/evidence"],
    )
    digest = _install(store, manifest, resources)
    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": manifest.rule_id, "digest": digest}],
    )
    policy = RuleResolutionPolicy(
        accepted_publishers={publisher.as_did()},
        available_capabilities={"org.nthdao.test/evidence"},
    )

    resolution = resolve_offer_rules(offer, store, policy, at=_AT)

    assert resolution.root_digests == (digest,)
    assert resolution.ordered_digests == (digest,)
    assert resolution.required_capabilities == (
        "org.nthdao.test/evidence",
    )
    assert resolution.execution_modes == ("declarative",)
    assert resolution.bindings() == (
        {"rule_id": manifest.rule_id, "digest": digest},
    )


def test_exact_digest_acceptance_does_not_trust_other_publisher_packages(
    tmp_path,
):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    accepted, accepted_resources = _manifest(
        publisher, rule_id="org.nthdao.test.accepted"
    )
    other, other_resources = _manifest(
        publisher, rule_id="org.nthdao.test.other"
    )
    accepted_digest = _install(store, accepted, accepted_resources)
    other_digest = _install(store, other, other_resources)
    policy = RuleResolutionPolicy(
        accepted_package_digests={accepted_digest}
    )

    resolved = resolve_offer_rules(
        _offer(
            AgentIdentity.generate(),
            [{"rule_id": accepted.rule_id, "digest": accepted_digest}],
        ),
        store,
        policy,
        at=_AT,
    )
    assert resolved.ordered_digests == (accepted_digest,)

    with pytest.raises(RuleNegotiationError, match="not accepted"):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [{"rule_id": other.rule_id, "digest": other_digest}],
            ),
            store,
            policy,
            at=_AT,
        )


def test_default_policy_rejects_valid_but_untrusted_rule(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher, rule_id="org.nthdao.test.untrusted"
    )
    digest = _install(store, manifest, resources)

    with pytest.raises(RuleNegotiationError, match="not accepted"):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [{"rule_id": manifest.rule_id, "digest": digest}],
            ),
            store,
            RuleResolutionPolicy(),
            at=_AT,
        )


def test_missing_or_wrong_rule_binding_fails_closed(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher, rule_id="org.nthdao.test.actual"
    )
    digest = _install(store, manifest, resources)
    policy = RuleResolutionPolicy(
        accepted_publishers={publisher.as_did()}
    )

    with pytest.raises(RuleNegotiationError, match="unavailable"):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [{
                    "rule_id": manifest.rule_id,
                    "digest": "sha256:" + ("0" * 64),
                }],
            ),
            store,
            policy,
            at=_AT,
        )
    with pytest.raises(RuleNegotiationError, match="does not declare"):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [{"rule_id": "org.nthdao.test.wrong", "digest": digest}],
            ),
            store,
            policy,
            at=_AT,
        )


def test_dependency_resolution_is_postorder_and_each_publisher_is_trusted(
    tmp_path,
):
    store = RulePackageStore(tmp_path)
    dependency_publisher = AgentIdentity.generate()
    root_publisher = AgentIdentity.generate()
    dependency, dependency_resources = _manifest(
        dependency_publisher,
        rule_id="org.nthdao.test.base",
    )
    dependency_digest = _install(
        store, dependency, dependency_resources
    )
    root, root_resources = _manifest(
        root_publisher,
        rule_id="org.nthdao.test.root",
        dependencies=[{
            "rule_id": dependency.rule_id,
            "digest": dependency_digest,
        }],
    )
    root_digest = _install(store, root, root_resources)
    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": root.rule_id, "digest": root_digest}],
    )

    with pytest.raises(RuleNegotiationError, match="not accepted"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                accepted_publishers={root_publisher.as_did()}
            ),
            at=_AT,
        )

    resolved = resolve_offer_rules(
        offer,
        store,
        RuleResolutionPolicy(
            accepted_publishers={
                root_publisher.as_did(),
                dependency_publisher.as_did(),
            }
        ),
        at=_AT,
    )
    assert resolved.ordered_digests == (
        dependency_digest,
        root_digest,
    )


def test_missing_capability_is_rejected(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.capability",
        capabilities=["org.nthdao.test/escrow"],
    )
    digest = _install(store, manifest, resources)
    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": manifest.rule_id, "digest": digest}],
    )

    with pytest.raises(RuleNegotiationError, match="unavailable capabilities"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                accepted_publishers={publisher.as_did()}
            ),
            at=_AT,
        )


def test_non_declarative_rule_needs_mode_and_exact_approval(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.adapter",
        execution_mode="adapter",
        permissions=["payment:authorize:test"],
    )
    digest = _install(store, manifest, resources)
    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": manifest.rule_id, "digest": digest}],
    )

    with pytest.raises(RuleNegotiationError, match="mode is not allowed"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                accepted_publishers={publisher.as_did()}
            ),
            at=_AT,
        )
    with pytest.raises(RuleNegotiationError, match="exact executable"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                accepted_publishers={publisher.as_did()},
                allowed_execution_modes={"declarative", "adapter"},
            ),
            at=_AT,
        )
    with pytest.raises(RuleNegotiationError, match="disallowed permissions"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                allowed_execution_modes={"declarative", "adapter"},
                approved_executable_digests={digest},
            ),
            at=_AT,
        )

    resolved = resolve_offer_rules(
        offer,
        store,
        RuleResolutionPolicy(
            allowed_execution_modes={"declarative", "adapter"},
            approved_executable_digests={digest},
            allowed_permissions={"payment:authorize:test"},
        ),
        at=_AT,
    )
    assert resolved.execution_modes == ("adapter",)


def test_structural_resolver_keeps_federation_boundary_open(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher, rule_id="org.nthdao.test.remote"
    )
    digest = _install(store, manifest, resources)

    class Resolver:
        def load(self, requested_digest):
            return store.load(requested_digest)

    resolution = resolve_offer_rules(
        _offer(
            AgentIdentity.generate(),
            [{"rule_id": manifest.rule_id, "digest": digest}],
        ),
        Resolver(),
        RuleResolutionPolicy(
            accepted_publishers={publisher.as_did()}
        ),
        at=_AT,
    )
    assert resolution.ordered_digests == (digest,)


def test_high_level_resolution_selects_only_canonical_offer_head(tmp_path):
    package_store = RulePackageStore(tmp_path)
    offer_store = OfferStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher, rule_id="org.nthdao.test.canonical"
    )
    digest = _install(package_store, manifest, resources)
    offer_publisher = AgentIdentity.generate()
    first = _offer(offer_publisher, [])
    second = _successor(
        offer_publisher,
        first,
        [{"rule_id": manifest.rule_id, "digest": digest}],
    )
    offer_store.publish(first)
    offer_store.publish(second)

    resolution = resolve_canonical_offer_rules(
        offer_publisher.as_did(),
        first.offer_id,
        offer_store,
        package_store,
        RuleResolutionPolicy(
            accepted_publishers={publisher.as_did()}
        ),
        at=_AT,
    )

    assert resolution.root_digests == (digest,)
    assert resolution.offer_publisher_did == offer_publisher.as_did()
    assert resolution.offer_id == first.offer_id
    assert resolution.offer_revision == 2
    assert resolution.offer_digest == offer_digest(second)
    assert resolution.canonical_chain_digests == (
        offer_digest(first),
        offer_digest(second),
    )
    assert resolution.evaluated_at == "2026-08-01T00:00:00Z"
    assert resolution.policy_digest.startswith("sha256:")
    assert resolution.policy_digest == (
        "sha256:"
        + hashlib.sha256(resolution.policy_canonical_bytes).hexdigest()
    )


def test_high_level_resolution_rejects_forked_offer(tmp_path):
    package_store = RulePackageStore(tmp_path)
    offer_store = OfferStore(tmp_path)
    offer_publisher = AgentIdentity.generate()
    first = _offer(offer_publisher, [])
    competing = _offer(offer_publisher, [])
    competing_document = competing.to_dict()
    competing_document["title"] = "Competing root"
    competing = sign_offer(
        offer_publisher,
        {
            key: value
            for key, value in competing_document.items()
            if key != "proof"
        },
        created="2026-07-29T00:00:02Z",
    )
    offer_store.publish(first)
    offer_store.publish(competing)

    with pytest.raises(RuleNegotiationError, match="forked"):
        resolve_canonical_offer_rules(
            offer_publisher.as_did(),
            first.offer_id,
            offer_store,
            package_store,
            RuleResolutionPolicy(),
            at=_AT,
        )


def test_high_level_resolution_rejects_orphan_revision(tmp_path):
    package_store = RulePackageStore(tmp_path)
    offer_store = OfferStore(tmp_path)
    offer_publisher = AgentIdentity.generate()
    missing_root = _offer(offer_publisher, [])
    orphan = _successor(offer_publisher, missing_root, [])
    offer_store.publish(orphan)

    with pytest.raises(RuleNegotiationError, match="incomplete"):
        resolve_canonical_offer_rules(
            offer_publisher.as_did(),
            orphan.offer_id,
            offer_store,
            package_store,
            RuleResolutionPolicy(),
            at=_AT,
        )


def test_high_level_resolution_rechecks_snapshot_head_digest(tmp_path):
    package_store = RulePackageStore(tmp_path)
    offer_publisher = AgentIdentity.generate()
    selected = _offer(offer_publisher, [])
    different = _offer(offer_publisher, [])
    different_document = different.to_dict()
    different_document["summary"] = "Different signed bytes"
    different = sign_offer(
        offer_publisher,
        {
            key: value
            for key, value in different_document.items()
            if key != "proof"
        },
        created="2026-07-29T00:00:02Z",
    )

    class InconsistentResolver:
        def canonical_snapshot(self, publisher_did, offer_id):
            view = type(
                "View",
                (),
                {
                    "status": "canonical",
                    "canonical_head_digest": offer_digest(selected),
                    "canonical_digests": (offer_digest(selected),),
                },
            )()
            return view, different

    with pytest.raises(RuleNegotiationError, match="digest does not match"):
        resolve_canonical_offer_rules(
            offer_publisher.as_did(),
            selected.offer_id,
            InconsistentResolver(),
            package_store,
            RuleResolutionPolicy(),
            at=_AT,
        )


def test_high_level_resolution_rejects_unbound_lifecycle_evidence(tmp_path):
    package_store = RulePackageStore(tmp_path)
    offer_publisher = AgentIdentity.generate()
    selected = _offer(offer_publisher, [])

    class IncompleteResolver:
        def canonical_snapshot(self, publisher_did, offer_id):
            view = type(
                "View",
                (),
                {
                    "status": "canonical",
                    "canonical_head_digest": offer_digest(selected),
                    "canonical_digests": (),
                },
            )()
            return view, selected

    with pytest.raises(RuleNegotiationError, match="evidence is invalid"):
        resolve_canonical_offer_rules(
            offer_publisher.as_did(),
            selected.offer_id,
            IncompleteResolver(),
            package_store,
            RuleResolutionPolicy(),
            at=_AT,
        )


def test_policy_digest_is_deterministic_and_sensitive_to_policy():
    publisher = AgentIdentity.generate().as_did()
    first = RuleResolutionPolicy(
        accepted_publishers={publisher},
        available_capabilities={"org.nthdao.test/a", "org.nthdao.test/b"},
    )
    reordered = RuleResolutionPolicy(
        accepted_publishers=frozenset(reversed(tuple({publisher}))),
        available_capabilities={"org.nthdao.test/b", "org.nthdao.test/a"},
    )
    different = RuleResolutionPolicy(
        accepted_publishers={publisher},
        available_capabilities={"org.nthdao.test/a"},
    )

    assert first.canonical_bytes == reordered.canonical_bytes
    assert first.digest == reordered.digest
    assert first.digest != different.digest


def test_dependency_depth_and_package_count_are_bounded(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    leaf, leaf_resources = _manifest(
        publisher, rule_id="org.nthdao.test.depth-leaf"
    )
    leaf_digest = _install(store, leaf, leaf_resources)
    middle, middle_resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.depth-middle",
        dependencies=[{
            "rule_id": leaf.rule_id,
            "digest": leaf_digest,
        }],
    )
    middle_digest = _install(store, middle, middle_resources)
    root, root_resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.depth-root",
        dependencies=[{
            "rule_id": middle.rule_id,
            "digest": middle_digest,
        }],
    )
    root_digest = _install(store, root, root_resources)
    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": root.rule_id, "digest": root_digest}],
    )
    trust = {"accepted_publishers": {publisher.as_did()}}

    with pytest.raises(RuleNegotiationError, match="depth exceeds 2"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(**trust, max_depth=2),
            at=_AT,
        )
    with pytest.raises(RuleNegotiationError, match="exceeds 2 packages"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(**trust, max_packages=2),
            at=_AT,
        )


def test_exact_conflict_is_rejected(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    second, second_resources = _manifest(
        publisher, rule_id="org.nthdao.test.second"
    )
    second_digest = _install(store, second, second_resources)
    first, first_resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.first",
        conflicts=[{
            "rule_id": second.rule_id,
            "digest": second_digest,
        }],
    )
    first_digest = _install(store, first, first_resources)
    offer = _offer(
        AgentIdentity.generate(),
        [
            {"rule_id": first.rule_id, "digest": first_digest},
            {"rule_id": second.rule_id, "digest": second_digest},
        ],
    )

    with pytest.raises(RuleNegotiationError, match="rule conflict"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                accepted_publishers={publisher.as_did()}
            ),
            at=_AT,
        )


def test_same_rule_id_cannot_resolve_to_two_digests(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    first, first_resources = _manifest(
        publisher, rule_id="org.nthdao.test.versioned", version="1.0.0"
    )
    second, second_resources = _manifest(
        publisher, rule_id="org.nthdao.test.versioned", version="2.0.0"
    )
    first_digest = _install(store, first, first_resources)
    second_digest = _install(store, second, second_resources)

    with pytest.raises(RuleNegotiationError, match="multiple exact digests"):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [
                    {"rule_id": first.rule_id, "digest": first_digest},
                    {"rule_id": second.rule_id, "digest": second_digest},
                ],
            ),
            store,
            RuleResolutionPolicy(
                accepted_publishers={publisher.as_did()}
            ),
            at=_AT,
        )


@pytest.mark.parametrize(
    "published_at, not_after, reason",
    [
        (
            "2026-09-01T00:00:00Z",
            "2027-09-01T00:00:00Z",
            "not_yet_active",
        ),
        (
            "2025-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "expired",
        ),
    ],
)
def test_inactive_rule_package_is_rejected(
    tmp_path, published_at, not_after, reason
):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.timed",
        published_at=published_at,
        not_after=not_after,
    )
    digest = _install(store, manifest, resources)

    with pytest.raises(RuleNegotiationError, match=reason):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [{"rule_id": manifest.rule_id, "digest": digest}],
            ),
            store,
            RuleResolutionPolicy(
                accepted_publishers={publisher.as_did()}
            ),
            at=_AT,
        )


def test_inactive_offer_is_rejected_before_rule_loading(tmp_path):
    with pytest.raises(RuleNegotiationError, match="expired"):
        resolve_offer_rules(
            _offer(
                AgentIdentity.generate(),
                [],
                not_after="2026-07-30T00:00:00Z",
            ),
            RulePackageStore(tmp_path),
            RuleResolutionPolicy(),
            at=_AT,
        )


def test_policy_rejects_invalid_trust_and_mode_values():
    with pytest.raises(ValueError, match="accepted_publishers"):
        RuleResolutionPolicy(accepted_publishers={"not-a-did"})
    with pytest.raises(ValueError, match="allowed_execution_modes"):
        RuleResolutionPolicy(
            allowed_execution_modes={"declarative", "python-eval"}
        )


def test_resolution_recomputes_manifest_digest_from_resolver_package():
    trusted_publisher = AgentIdentity.generate()
    attacker = AgentIdentity.generate()
    rule_id = "org.nthdao.test.digest-substitution"
    trusted_manifest, trusted_resources = _manifest(
        trusted_publisher,
        rule_id=rule_id,
    )
    attacker_manifest, attacker_resources = _manifest(
        attacker,
        rule_id=rule_id,
    )
    trusted_package = build_rule_package(
        trusted_manifest,
        trusted_resources,
    )
    attacker_package = build_rule_package(
        attacker_manifest,
        attacker_resources,
    )
    forged = RulePackage._create(
        digest=trusted_package.digest,
        manifest=attacker_package.manifest,
        resources=attacker_package.resources,
    )

    class Resolver:
        def load(self, _digest):
            return forged

    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": rule_id, "digest": trusted_package.digest}],
    )
    with pytest.raises(RuleNegotiationError, match="content digest"):
        resolve_offer_rules(
            offer,
            Resolver(),
            RuleResolutionPolicy(
                accepted_package_digests={trusted_package.digest}
            ),
            at=_AT,
        )


def test_resolution_revalidates_resources_from_resolver_package():
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.resource-substitution",
    )
    package = build_rule_package(manifest, resources)
    resource_digest = next(iter(resources))
    forged = RulePackage._create(
        digest=package.digest,
        manifest=package.manifest,
        resources={resource_digest: b"forged"},
    )

    class Resolver:
        def load(self, _digest):
            return forged

    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": manifest.rule_id, "digest": package.digest}],
    )
    with pytest.raises(RuleNegotiationError, match="unverified package"):
        resolve_offer_rules(
            offer,
            Resolver(),
            RuleResolutionPolicy(
                accepted_package_digests={package.digest}
            ),
            at=_AT,
        )


def test_resolution_bounds_total_resource_bytes(tmp_path):
    store = RulePackageStore(tmp_path)
    publisher = AgentIdentity.generate()
    manifest, resources = _manifest(
        publisher,
        rule_id="org.nthdao.test.resource-budget",
    )
    digest = _install(store, manifest, resources)
    offer = _offer(
        AgentIdentity.generate(),
        [{"rule_id": manifest.rule_id, "digest": digest}],
    )

    with pytest.raises(RuleNegotiationError, match="resources exceed"):
        resolve_offer_rules(
            offer,
            store,
            RuleResolutionPolicy(
                accepted_package_digests={digest},
                max_resource_bytes=1,
            ),
            at=_AT,
        )

    resolution = resolve_offer_rules(
        offer,
        store,
        RuleResolutionPolicy(
            accepted_package_digests={digest},
            max_resource_bytes=sum(map(len, resources.values())),
        ),
        at=_AT,
    )
    assert resolution.resolved_resource_bytes == sum(
        map(len, resources.values())
    )
    with pytest.raises(ValueError, match="include declarative"):
        RuleResolutionPolicy(allowed_execution_modes={"adapter"})
    with pytest.raises(ValueError, match="4096-entry"):
        RuleResolutionPolicy(
            accepted_package_digests=[
                "sha256:" + (f"{index:064x}"[-64:])
                for index in range(4_097)
            ]
        )


def test_structural_resolvers_fail_with_protocol_errors_on_bad_results():
    identity = AgentIdentity.generate()
    digest = "sha256:" + ("0" * 64)
    offer = _offer(
        identity,
        [{"rule_id": "org.nthdao.test.bad-resolver", "digest": digest}],
    )

    class BadRuleResolver:
        def load(self, requested_digest):
            return {"digest": requested_digest}

    with pytest.raises(RuleNegotiationError, match="invalid package"):
        resolve_offer_rules(
            offer,
            BadRuleResolver(),
            RuleResolutionPolicy(accepted_package_digests={digest}),
            at=_AT,
        )

    class BadOfferResolver:
        def canonical_snapshot(self, publisher_did, offer_id):
            return ["not", "a tuple"]

    with pytest.raises(RuleNegotiationError, match="invalid canonical"):
        resolve_canonical_offer_rules(
            identity.as_did(),
            offer.offer_id,
            BadOfferResolver(),
            BadRuleResolver(),
            RuleResolutionPolicy(),
            at=_AT,
        )
