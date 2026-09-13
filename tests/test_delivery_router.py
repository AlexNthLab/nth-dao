"""Tests for the policy-scored router and the loopback hub/mesh transports.

These encode the design doc §8.2 rules: no fixed fallback order, policy
scoring, privacy floors exclude leakage-prone transports, health cooldowns,
and first-ACK-cancels-the-rest being an outbox concern (not the router's).
"""

from __future__ import annotations

import pytest

from nth_dao.delivery.envelope import (
    TransportEnvelopeRejected,
    sign_envelope,
    validate_envelope,
)
from nth_dao.delivery.policy import (
    CENTRALIZED_POLICY,
    DECENTRALIZED_POLICY,
    OFFLINE_POLICY,
    RoutePolicy,
    RoutePolicyError,
)
from nth_dao.delivery.router import DeliveryRouter
from nth_dao.delivery.transports.base import (
    PRIVACY_LOCAL,
    PRIVACY_PEER,
    PRIVACY_PUBLIC_RELAY,
    SendResult,
    Transport,
    TRANSPORT_ACK_NONE,
    TransportCapabilities,
    TransportHealth,
)
from nth_dao.delivery.transports.loopback import (
    MODE_HUB,
    MODE_MESH,
    LoopbackEndpoint,
    LoopbackWire,
    LoopbackWireError,
)

pytest.importorskip("nacl")

NOW_MS = 1_750_000_000_000


@pytest.fixture()
def alice_identity():
    from nth_dao.identity import AgentIdentity

    return AgentIdentity.generate(label="alice")


def _envelope(alice_identity, recipient="dao:core", hop_limit=0):
    return sign_envelope(
        alice_identity,
        kind="channel.message",
        recipient=recipient,
        payload={"body": "hi"},
        created_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 60_000,
        hop_limit=hop_limit,
    )


class _StaticTransport(Transport):
    """Scripted transport for router behavior tests."""

    def __init__(self, name, *, privacy=PRIVACY_PEER, realtime=True, infra=False,
                 accept=True, error_code="unreachable", max_bytes=524_288,
                 ack_mode="host", reachable=True):
        self.capabilities = TransportCapabilities(
            name=name,
            realtime=realtime,
            privacy_level=privacy,
            external_infrastructure=infra,
            max_envelope_bytes=max_bytes,
            ack_mode=ack_mode,
        )
        self._accept = accept
        self._error_code = error_code
        self._reachable = reachable
        self.sent = []

    def send(self, envelope):
        self.sent.append(envelope)
        if self._accept:
            return SendResult(accepted=True)
        return SendResult(accepted=False, error_code=self._error_code)

    def health(self):
        return TransportHealth(reachable=self._reachable)


class _MutatingTransport(_StaticTransport):
    def send(self, envelope):
        self.sent.append(envelope)
        envelope.payload["body"] = "forged"
        envelope.recipient = "attacker:queue"
        envelope.signature = ""
        return SendResult(accepted=False, error_code="transport-mutated-input")


class TestRoutePolicy:
    def test_defaults_valid(self):
        policy = RoutePolicy()
        assert policy.copy_count == 1

    def test_bad_copy_count_rejected(self):
        with pytest.raises(RoutePolicyError):
            RoutePolicy(copy_count=0)

    def test_bad_privacy_floor_rejected(self):
        with pytest.raises(RoutePolicyError):
            RoutePolicy(privacy_floor=7)

    def test_duplicate_names_rejected(self):
        with pytest.raises(RoutePolicyError, match="duplicates"):
            RoutePolicy(allowed_transports=("a", "a"))

    def test_bad_names_rejected(self):
        with pytest.raises(RoutePolicyError):
            RoutePolicy(allowed_transports=("",))

    def test_mode_presets_differ_on_privacy(self):
        assert CENTRALIZED_POLICY.privacy_floor == PRIVACY_PUBLIC_RELAY
        assert DECENTRALIZED_POLICY.privacy_floor >= PRIVACY_PEER
        assert OFFLINE_POLICY.require_ack is False

    @pytest.mark.parametrize(
        "field,value",
        [
            ("copy_count", True),
            ("require_ack", 1),
            ("prefer_realtime", 1),
            ("allow_fallback", 1),
            ("max_hop_limit", True),
            ("require_external_infrastructure", 1),
        ],
    )
    def test_boolean_and_integer_types_are_not_interchangeable(self, field, value):
        with pytest.raises(RoutePolicyError):
            RoutePolicy(**{field: value})


class TestRouter:
    @pytest.mark.parametrize(
        "kwargs,error",
        [
            ({"name": "bad\nname"}, ValueError),
            ({"name": "界" * 22}, ValueError),
            ({"unicast": 1}, TypeError),
            ({"broadcast": 1}, TypeError),
            ({"realtime": 1}, TypeError),
            ({"external_infrastructure": 1}, TypeError),
            ({"privacy_level": True}, ValueError),
            ({"privacy_level": 1.0}, ValueError),
            ({"max_envelope_bytes": True}, ValueError),
            ({"max_envelope_bytes": 1.5}, ValueError),
            ({"ack_mode": 1}, ValueError),
        ],
    )
    def test_transport_capabilities_reject_type_confusion(self, kwargs, error):
        values = {"name": "valid"}
        values.update(kwargs)
        with pytest.raises(error):
            TransportCapabilities(**values)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"failure_threshold": True},
            {"failure_threshold": 1.5},
            {"cooldown_ms": True},
            {"cooldown_ms": 1.5},
        ],
    )
    def test_constructor_rejects_non_integer_limits(self, kwargs):
        with pytest.raises(ValueError, match="integer"):
            DeliveryRouter(**kwargs)

    def test_constructor_rejects_non_callable_clock(self):
        with pytest.raises(TypeError, match="clock"):
            DeliveryRouter(clock=1)

    @pytest.mark.parametrize("value", [True, -1, 1.5, "100"])
    def test_runtime_rejects_invalid_clock_values(self, value):
        router = DeliveryRouter(clock=lambda: value)
        with pytest.raises(ValueError, match="router clock"):
            router.stats()

    @pytest.mark.parametrize(
        "error_code", ["failed\u0085forged", "failed\u2028forged", "界" * 86]
    )
    def test_send_result_rejects_nonportable_error_text(self, error_code):
        with pytest.raises(ValueError, match="printable text"):
            SendResult(accepted=False, error_code=error_code)

    def test_register_and_list(self):
        router = DeliveryRouter()
        router.register(_StaticTransport("a"))
        router.register(_StaticTransport("b"))
        assert router.transport_names() == ["a", "b"]

    def test_duplicate_registration_rejected(self):
        router = DeliveryRouter()
        router.register(_StaticTransport("a"))
        with pytest.raises(ValueError, match="already registered"):
            router.register(_StaticTransport("a"))

    def test_duplicate_registration_does_not_probe_rejected_provider(self):
        router = DeliveryRouter()
        router.register(_StaticTransport("a"))
        duplicate = _StaticTransport("a")
        probed = []
        duplicate.health = lambda: probed.append(True) or TransportHealth()

        with pytest.raises(ValueError, match="already registered"):
            router.register(duplicate)

        assert probed == []

    def test_unreachable_transport_is_excluded_at_registration(self, alice_identity):
        router = DeliveryRouter()
        down = _StaticTransport("down", reachable=False)
        router.register(down)

        result = router.send(_envelope(alice_identity))

        assert result.accepted is False
        assert down.sent == []
        assert router.health_of("down").reachable is False

    def test_dynamic_health_refresh_allows_recovered_transport(self, alice_identity):
        router = DeliveryRouter()
        recovering = _StaticTransport("recovering", reachable=False)
        router.register(recovering)
        assert router.send(_envelope(alice_identity)).accepted is False

        recovering._reachable = True
        result = router.send(_envelope(alice_identity))

        assert result.sent_via == ["recovering"]

    def test_health_probe_failure_is_fail_closed(self, alice_identity, caplog):
        router = DeliveryRouter()
        broken = _StaticTransport("broken")

        def broken_health():
            raise RuntimeError("sensitive health provider detail")

        broken.health = broken_health
        router.register(broken)

        assert router.send(_envelope(alice_identity)).accepted is False
        assert broken.sent == []
        assert "sensitive health provider detail" not in caplog.text

    def test_recovered_health_probe_clears_probe_failure(self, alice_identity):
        router = DeliveryRouter(failure_threshold=1, cooldown_ms=60_000)
        recovering = _StaticTransport("recovering")

        def broken_health():
            raise RuntimeError("probe failed")

        recovering.health = broken_health
        router.register(recovering)
        assert router.health_of("recovering").consecutive_failures == 1

        recovering.health = lambda: TransportHealth(reachable=True)
        result = router.send(_envelope(alice_identity))

        assert result.sent_via == ["recovering"]
        assert router.health_of("recovering").consecutive_failures == 0

    def test_health_probe_does_not_erase_router_observed_failure(
        self, alice_identity
    ):
        router = DeliveryRouter()
        flaky = _StaticTransport("flaky", accept=False)
        router.register(flaky)

        assert router.send(_envelope(alice_identity)).accepted is False
        assert router.health_of("flaky").consecutive_failures == 1
        router.refresh_health()
        assert router.health_of("flaky").consecutive_failures == 1

        flaky._accept = True
        assert router.send(_envelope(alice_identity)).accepted is True
        assert router.health_of("flaky").consecutive_failures == 0

    def test_invalid_send_result_is_failure(self, alice_identity):
        router = DeliveryRouter()
        invalid = _StaticTransport("invalid")
        invalid.send = lambda envelope: {"accepted": True}
        router.register(invalid)

        result = router.send(_envelope(alice_identity))

        assert result.accepted is False
        assert result.attempts[0].error_code == "invalid-send-result"

    def test_mutated_send_result_cannot_become_truthy_success(self, alice_identity):
        router = DeliveryRouter()
        invalid = _StaticTransport("invalid")
        forged = SendResult(accepted=False, error_code="rejected")
        object.__setattr__(forged, "accepted", "false")
        invalid.send = lambda envelope: forged
        router.register(invalid)

        result = router.send(_envelope(alice_identity))

        assert result.accepted is False
        assert result.attempts[0].error_code == "invalid-send-result"

    def test_policy_scoring_prefers_realtime(self, alice_identity):
        router = DeliveryRouter()
        slow_private = _StaticTransport("slow-private", realtime=False, privacy=PRIVACY_LOCAL, infra=False)
        fast_relay = _StaticTransport("fast-relay", realtime=True, privacy=PRIVACY_PUBLIC_RELAY, infra=True)
        router.register(fast_relay)
        router.register(slow_private)
        policy = RoutePolicy(copy_count=1, prefer_realtime=True, privacy_floor=PRIVACY_PUBLIC_RELAY)
        result = router.send(_envelope(alice_identity), policy)
        # fast-relay scores higher on realtime; both are allowed by floor
        assert result.sent_via == ["fast-relay"]

    def test_privacy_floor_excludes_relay(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("relay", privacy=PRIVACY_PUBLIC_RELAY, realtime=True, infra=True))
        router.register(_StaticTransport("mesh", privacy=PRIVACY_PEER, realtime=True))
        policy = RoutePolicy(privacy_floor=PRIVACY_PEER, prefer_realtime=True)
        result = router.send(_envelope(alice_identity), policy)
        assert result.sent_via == ["mesh"]

    def test_allowlist_restricts_candidates(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("a"))
        router.register(_StaticTransport("b"))
        policy = RoutePolicy(allowed_transports=("b",))
        result = router.send(_envelope(alice_identity), policy)
        assert result.sent_via == ["b"]
        assert [a.transport for a in result.attempts] == ["b"]

    def test_mode_policies_enforce_infrastructure_boundary(self, alice_identity):
        router = DeliveryRouter()
        router.register(
            _StaticTransport(
                "relay", privacy=PRIVACY_PUBLIC_RELAY, infra=True
            )
        )
        router.register(_StaticTransport("peer", privacy=PRIVACY_PEER, infra=False))

        assert router.send(_envelope(alice_identity), CENTRALIZED_POLICY).sent_via == [
            "relay"
        ]
        assert router.send(
            _envelope(alice_identity), DECENTRALIZED_POLICY
        ).sent_via == ["peer"]

    def test_offline_policy_accepts_local_transport_without_host_ack(
        self, alice_identity
    ):
        router = DeliveryRouter()
        router.register(
            _StaticTransport(
                "offline",
                privacy=PRIVACY_LOCAL,
                realtime=False,
                infra=False,
                ack_mode=TRANSPORT_ACK_NONE,
            )
        )
        assert router.send(_envelope(alice_identity), OFFLINE_POLICY).sent_via == [
            "offline"
        ]

    def test_hop_limit_cannot_exceed_active_policy(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("peer"))
        envelope = _envelope(alice_identity, hop_limit=2)
        with pytest.raises(TransportEnvelopeRejected, match="hop_limit"):
            router.send(envelope, RoutePolicy(max_hop_limit=1))

    def test_direct_recipient_never_uses_broadcast_only_transport(self, alice_identity):
        from nth_dao.identity import AgentIdentity

        router = DeliveryRouter()
        broadcast = _StaticTransport("broadcast")
        broadcast.capabilities = TransportCapabilities(
            name="broadcast",
            unicast=False,
            broadcast=True,
        )
        router.register(broadcast)
        recipient = AgentIdentity.generate(label="recipient").as_did()

        result = router.send(_envelope(alice_identity, recipient=recipient))

        assert not result.accepted
        assert broadcast.sent == []

    def test_oversized_envelope_skips_transport(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("tiny", max_bytes=10))
        router.register(_StaticTransport("big", max_bytes=524_288))
        result = router.send(_envelope(alice_identity), RoutePolicy(allow_fallback=False))
        assert result.sent_via == ["big"]

    def test_fallback_tries_next_candidate(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("primary", accept=False, error_code="unreachable"))
        router.register(_StaticTransport("backup", accept=True))
        result = router.send(_envelope(alice_identity), RoutePolicy())
        assert result.sent_via == ["backup"]
        assert [a.transport for a in result.attempts] == ["primary", "backup"]

    def test_transport_mutation_cannot_poison_caller_or_fallback(
        self, alice_identity
    ):
        router = DeliveryRouter()
        mutator = _MutatingTransport("a-mutator")
        backup = _StaticTransport("b-backup")
        router.register(mutator)
        router.register(backup)
        envelope = _envelope(alice_identity)
        original = envelope.to_dict()

        result = router.send(envelope, RoutePolicy(copy_count=1))

        assert result.sent_via == ["b-backup"]
        assert envelope.to_dict() == original
        assert mutator.sent[0] is not backup.sent[0]
        assert backup.sent[0].to_dict() == original

    def test_no_fallback_exhausts(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("primary", accept=False, error_code="unreachable"))
        result = router.send(_envelope(alice_identity), RoutePolicy(allow_fallback=False))
        assert not result.accepted
        assert result.exhausted

    def test_copy_count_sends_simultaneous_copies(self, alice_identity):
        router = DeliveryRouter()
        router.register(_StaticTransport("a"))
        router.register(_StaticTransport("b"))
        result = router.send(_envelope(alice_identity), RoutePolicy(copy_count=2))
        assert sorted(result.sent_via) == ["a", "b"]

    def test_health_cooldown_skips_failing_transport(self, alice_identity):
        """After `failure_threshold` consecutive failures a transport cools
        down (is excluded from scoring) until the cooldown elapses.

        The health score bonus would rotate attempts to a healthy peer, so
        the allowlist pins attempts onto "flaky" to exercise the threshold.
        """

        clock = {"now": NOW_MS}
        router = DeliveryRouter(clock=lambda: clock["now"], failure_threshold=2, cooldown_ms=30_000)
        flaky = _StaticTransport("flaky", accept=False, error_code="unreachable")
        solid = _StaticTransport("solid", accept=False, error_code="unreachable")
        router.register(flaky)
        router.register(solid)
        policy = RoutePolicy(allowed_transports=("flaky",), copy_count=1, allow_fallback=False)
        for _ in range(2):
            router.send(_envelope(alice_identity), policy)
            clock["now"] += 1_000
        stats = router.stats()
        assert stats["flaky"]["in_cooldown"] is True
        assert stats["solid"]["in_cooldown"] is False
        # after cooldown expiry flaky is scored again
        clock["now"] += 31_000
        stats = router.stats()
        assert stats["flaky"]["in_cooldown"] is False

    def test_health_score_rotates_away_from_failing_transport(self, alice_identity):
        """A failing transport scores lower, so the next send prefers the
        healthy peer even at equal capability — load shifts away from the
        failure without any fixed fallback table."""

        router = DeliveryRouter()
        flaky = _StaticTransport("flaky", accept=False, error_code="unreachable")
        solid = _StaticTransport("solid", accept=False, error_code="unreachable")
        router.register(flaky)
        router.register(solid)
        policy = RoutePolicy(copy_count=1, allow_fallback=False)
        first = router.send(_envelope(alice_identity), policy)
        assert [a.transport for a in first.attempts] == ["flaky"]
        second = router.send(_envelope(alice_identity), policy)
        assert [a.transport for a in second.attempts] == ["solid"]

    def test_send_exception_counts_as_failure(self, alice_identity, caplog):
        router = DeliveryRouter()
        bomb = _StaticTransport("bomb")

        def _boom(envelope):
            raise RuntimeError("sensitive send provider detail")

        bomb.send = _boom
        router.register(bomb)
        router.register(_StaticTransport("safe", realtime=False))
        result = router.send(_envelope(alice_identity), RoutePolicy(prefer_realtime=True))
        assert result.sent_via == ["safe"]
        assert router.health_of("bomb").consecutive_failures == 1
        assert "sensitive send provider detail" not in caplog.text

    def test_receive_polls_all_transports(self, alice_identity):
        router = DeliveryRouter()
        wire = LoopbackWire()
        receiver = LoopbackEndpoint(wire, "n1", mode=MODE_MESH)
        router.register(receiver)
        sender = LoopbackEndpoint(wire, "n2", mode=MODE_MESH)
        sender.send(_envelope(alice_identity))
        received = router.receive()
        assert len(received) == 1
        assert received[0].transport == "loopback-n1"

    def test_receive_skips_send_only_degraded_transport(self):
        router = DeliveryRouter()
        send_only = _StaticTransport("send-only")
        send_only.health = lambda: TransportHealth(
            reachable=True,
            receive_reachable=False,
        )
        polled = []
        send_only.poll = lambda *, max_items=64: polled.append(max_items) or []
        router.register(send_only)

        assert router.receive() == []
        assert polled == []
        assert router.stats()["send-only"]["reachable"] is True
        assert router.stats()["send-only"]["receive_reachable"] is False

    def test_receive_failure_does_not_put_send_path_in_cooldown(
        self, alice_identity, caplog
    ):
        router = DeliveryRouter(failure_threshold=1, cooldown_ms=60_000)
        transport = _StaticTransport("duplex", accept=True)

        def broken_poll(*, max_items=64):
            raise RuntimeError("sensitive receive provider detail")

        transport.poll = broken_poll
        router.register(transport)

        assert router.receive() == []
        assert "sensitive receive provider detail" not in caplog.text
        failed_health = router.health_of("duplex")
        assert failed_health.receive_reachable is False
        assert failed_health.consecutive_failures == 0

        result = router.send(_envelope(alice_identity))
        assert result.sent_via == ["duplex"]


class TestLoopbackModes:
    def test_mesh_fanout_reaches_all_peers(self, alice_identity):
        wire = LoopbackWire()
        alice = LoopbackEndpoint(wire, "alice", mode=MODE_MESH)
        bob = LoopbackEndpoint(wire, "bob", mode=MODE_MESH)
        carol = LoopbackEndpoint(wire, "carol", mode=MODE_MESH)
        result = alice.send(_envelope(alice_identity))
        assert result.accepted
        assert bob.pending_inbox_depth() == 1
        assert carol.pending_inbox_depth() == 1
        assert alice.pending_inbox_depth() == 0  # sender does not self-deliver

    def test_sender_mutation_after_send_cannot_change_queued_envelope(
        self, alice_identity
    ):
        wire = LoopbackWire()
        sender = LoopbackEndpoint(wire, "sender", mode=MODE_MESH)
        receiver = LoopbackEndpoint(wire, "receiver", mode=MODE_MESH)
        envelope = _envelope(alice_identity)

        assert sender.send(envelope).accepted is True
        envelope.payload["body"] = "forged-after-send"
        received = receiver.poll()[0]

        assert received is not envelope
        assert received.payload == {"body": "hi"}
        assert validate_envelope(
            received, now_ms=NOW_MS, require_signature=True
        ) == (True, "ok")

    def test_mesh_receivers_do_not_share_mutable_envelope_objects(
        self, alice_identity
    ):
        wire = LoopbackWire()
        sender = LoopbackEndpoint(wire, "sender", mode=MODE_MESH)
        first = LoopbackEndpoint(wire, "first", mode=MODE_MESH)
        second = LoopbackEndpoint(wire, "second", mode=MODE_MESH)

        assert sender.send(_envelope(alice_identity)).accepted is True
        first_copy = first.poll()[0]
        first_copy.payload["body"] = "receiver-local-change"
        second_copy = second.poll()[0]

        assert first_copy is not second_copy
        assert second_copy.payload == {"body": "hi"}
        assert validate_envelope(
            second_copy, now_ms=NOW_MS, require_signature=True
        ) == (True, "ok")

    def test_loopback_rejects_envelope_when_snapshot_fails(self, alice_identity):
        class HostilePayload:
            def __deepcopy__(self, memo):
                raise RuntimeError("sensitive hostile object detail")

        wire = LoopbackWire()
        sender = LoopbackEndpoint(wire, "sender", mode=MODE_MESH)
        LoopbackEndpoint(wire, "receiver", mode=MODE_MESH)
        envelope = _envelope(alice_identity)
        envelope.payload["body"] = HostilePayload()

        result = sender.send(envelope)

        assert result.accepted is False
        assert result.error_code == "invalid-envelope"

    def test_mesh_isolated_endpoint_cannot_send(self, alice_identity):
        wire = LoopbackWire()
        lonely = LoopbackEndpoint(wire, "lonely", mode=MODE_MESH)
        result = lonely.send(_envelope(alice_identity))
        assert not result.accepted and result.error_code == "no-reachable-peer"

    def test_hub_claims_by_recipient(self, alice_identity):
        wire = LoopbackWire()
        hub_bob = LoopbackEndpoint(wire, "bob", mode=MODE_HUB, serve={"dao:bob-inbox"})
        hub_other = LoopbackEndpoint(wire, "other", mode=MODE_HUB, serve={"dao:other"})
        result = hub_other.send(_envelope(alice_identity, recipient="dao:bob-inbox"))
        assert result.accepted
        got_bob = hub_bob.poll()
        assert len(got_bob) == 1
        assert got_bob[0].recipient == "dao:bob-inbox"
        assert hub_other.poll() == []
        assert wire.hub_depth() == 0

    def test_hub_unclaimed_items_stay_parked(self, alice_identity):
        wire = LoopbackWire()
        hub = LoopbackEndpoint(wire, "bob", mode=MODE_HUB, serve={"did:key:zzz"})
        hub.send(_envelope(alice_identity, recipient="dao:nobody-serves"))
        assert wire.hub_depth() == 1
        assert hub.poll() == []
        assert wire.hub_depth() == 1

    def test_modes_are_distinct_fabrics(self, alice_identity):
        """Mesh fanout skips hub endpoints; the hub queue skips mesh pollers.

        The two modes are distinct fabrics — a policy picks one, never both.
        """

        wire = LoopbackWire()
        mesh = LoopbackEndpoint(wire, "m", mode=MODE_MESH)
        hub = LoopbackEndpoint(wire, "h", mode=MODE_HUB, serve={"dao:core"})
        mesh.send(_envelope(alice_identity))
        assert hub.poll() == []
        assert mesh.pending_inbox_depth() == 0  # no OTHER mesh endpoint exists

    def test_bad_mode_rejected(self):
        with pytest.raises(ValueError, match="mode"):
            LoopbackEndpoint(LoopbackWire(), "x", mode="carrier-pigeon")

    def test_double_attach_rejected(self):
        wire = LoopbackWire()
        LoopbackEndpoint(wire, "dup")
        with pytest.raises(LoopbackWireError, match="attached twice"):
            LoopbackEndpoint(wire, "dup")
        assert wire.endpoint_ids() == ["dup"]
