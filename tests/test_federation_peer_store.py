from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path

import pytest

from nth_dao.discovery.federation_registry import (
    LearnedPeerCapacityError,
    LearnedPeerStore,
)
from nth_dao.did_key import encode_ed25519_did_key


def _metadata(url: str, suffix: str) -> dict:
    pubkey = hashlib.sha256(suffix.encode("utf-8")).digest()
    return {
        "peer_url": url,
        "identity_url": f"{url}/.well-known/nth-dao/identity.json",
        "did": encode_ed25519_did_key(pubkey),
        "pubkey_hex": pubkey.hex(),
    }


def test_verified_peer_survives_restart_and_expires(tmp_path: Path) -> None:
    url = "https://dao-a.example"
    store = LearnedPeerStore(tmp_path, ttl_ms=60_000, clock=lambda: 1_000_000)
    store.upsert_verified(url, _metadata(url, "A"))

    restarted = LearnedPeerStore(tmp_path, ttl_ms=60_000, clock=lambda: 1_000_001)
    assert [record.peer_url for record in restarted.active()] == [url]
    assert restarted.active(now_ms_override=1_060_001) == []
    assert restarted.prune(now_ms_override=1_060_001) == 1


def test_same_did_moves_to_newly_verified_endpoint(tmp_path: Path) -> None:
    old = "https://old.example"
    new = "https://new.example"
    store = LearnedPeerStore(tmp_path, clock=lambda: 2_000_000)
    store.upsert_verified(old, _metadata(old, "A"), now_ms_override=2_000_000)
    store.upsert_verified(new, _metadata(new, "A"), now_ms_override=2_000_001)

    records = store.active(now_ms_override=2_000_002)
    assert [record.peer_url for record in records] == [new]


def test_full_capacity_admits_new_network_by_evicting_oldest(
    tmp_path: Path,
) -> None:
    store = LearnedPeerStore(tmp_path, max_peers=2)
    for index, suffix in enumerate(("A", "B"), start=1):
        url = f"https://dao-{suffix.lower()}.example"
        store.upsert_verified(
            url,
            _metadata(url, suffix),
            now_ms_override=3_000_000 + index,
        )
    store.upsert_verified(
        "https://dao-c.example",
        _metadata("https://dao-c.example", "C"),
        now_ms_override=3_000_003,
    )

    assert {
        record.peer_url
        for record in store.active(now_ms_override=3_000_010)
    } == {"https://dao-b.example", "https://dao-c.example"}


def test_expired_peer_releases_capacity_for_new_identity(tmp_path: Path) -> None:
    store = LearnedPeerStore(tmp_path, max_peers=1, ttl_ms=60_000)
    old = "https://old.example"
    new = "https://new.example"
    store.upsert_verified(old, _metadata(old, "A"), now_ms_override=1_000_000)

    store.upsert_verified(new, _metadata(new, "B"), now_ms_override=1_060_001)

    assert [
        record.peer_url for record in store.active(now_ms_override=1_060_002)
    ] == [new]


def test_full_registry_evicts_from_most_represented_network(
    tmp_path: Path,
) -> None:
    store = LearnedPeerStore(
        tmp_path, max_peers=3, max_peers_per_network=2,
    )
    incumbents = [
        ("https://dense-old.example", "93.184.216.34"),
        ("https://dense-new.example", "93.184.216.99"),
        ("https://singleton.example", "203.0.113.10"),
    ]
    for index, (url, resolved_ip) in enumerate(incumbents):
        store.upsert_verified(
            url, _metadata(url, chr(ord("A") + index)),
            resolved_ip=resolved_ip,
            now_ms_override=8_000_000 + index,
        )

    newcomer = "https://new-network.example"
    store.upsert_verified(
        newcomer,
        _metadata(newcomer, "N"),
        resolved_ip="198.51.100.10",
        now_ms_override=8_001_000,
    )

    assert {
        record.peer_url for record in store.active(now_ms_override=8_002_000)
    } == {
        "https://dense-new.example",
        "https://singleton.example",
        newcomer,
    }


def test_full_registry_replaces_within_existing_network(
    tmp_path: Path,
) -> None:
    store = LearnedPeerStore(
        tmp_path, max_peers=2, max_peers_per_network=2,
    )
    same_network_old = "https://old.example"
    other_network = "https://other.example"
    store.upsert_verified(
        same_network_old,
        _metadata(same_network_old, "A"),
        resolved_ip="93.184.216.34",
        now_ms_override=8_100_000,
    )
    store.upsert_verified(
        other_network,
        _metadata(other_network, "B"),
        resolved_ip="203.0.113.10",
        now_ms_override=8_100_001,
    )

    same_network_new = "https://new.example"
    store.upsert_verified(
        same_network_new,
        _metadata(same_network_new, "C"),
        resolved_ip="93.184.216.99",
        now_ms_override=8_100_002,
    )

    assert {
        record.peer_url for record in store.active(now_ms_override=8_100_003)
    } == {same_network_new, other_network}


def test_one_network_cannot_fill_learned_peer_registry(tmp_path: Path) -> None:
    store = LearnedPeerStore(
        tmp_path, max_peers=16, max_peers_per_network=2,
    )
    for index in range(2):
        url = f"https://sybil-{index}.example"
        store.upsert_verified(
            url,
            _metadata(url, f"S{index}"),
            resolved_ip="93.184.216.34",
            now_ms_override=9_000_000 + index,
        )

    third = "https://sybil-2.example"
    with pytest.raises(LearnedPeerCapacityError, match="per-network"):
        store.upsert_verified(
            third,
            _metadata(third, "S2"),
            resolved_ip="93.184.216.99",
            now_ms_override=9_000_003,
        )

    assert len(store.active(now_ms_override=9_000_004)) == 2


def test_rejects_unverified_or_non_public_shapes(tmp_path: Path) -> None:
    store = LearnedPeerStore(tmp_path)

    with pytest.raises(ValueError, match="HTTPS"):
        store.upsert_verified(
            "http://192.168.1.20:8080",
            _metadata("http://192.168.1.20:8080", "A"),
        )
    with pytest.raises(ValueError, match="another peer"):
        store.upsert_verified(
            "https://dao-a.example",
            _metadata("https://dao-b.example", "A"),
        )

    mismatched = _metadata("https://dao-a.example", "A")
    mismatched["pubkey_hex"] = _metadata(
        "https://dao-a.example", "B",
    )["pubkey_hex"]
    with pytest.raises(ValueError, match="does not match public key"):
        store.upsert_verified("https://dao-a.example", mismatched)


def test_concurrent_upserts_do_not_lose_records(tmp_path: Path) -> None:
    store = LearnedPeerStore(tmp_path, max_peers=32)

    def add(index: int) -> None:
        url = f"https://dao-{index}.example"
        store.upsert_verified(
            url,
            {
                **_metadata(url, "A"),
                **_metadata(url, f"peer-{index}"),
            },
            now_ms_override=4_000_000 + index,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add, range(16)))

    assert len(store.active(now_ms_override=4_000_100)) == 16


def test_identity_url_must_be_exactly_bound_to_peer(tmp_path: Path) -> None:
    store = LearnedPeerStore(tmp_path)
    url = "https://dao-a.example"
    metadata = _metadata(url, "A")
    metadata["identity_url"] = f"{url}/unrelated"

    with pytest.raises(ValueError, match="identity URL"):
        store.upsert_verified(url, metadata)


def test_key_rotation_at_same_url_resets_first_seen(tmp_path: Path) -> None:
    store = LearnedPeerStore(tmp_path)
    url = "https://rotating.example"
    store.upsert_verified(url, _metadata(url, "A"), now_ms_override=5_000_000)
    store.upsert_verified(url, _metadata(url, "B"), now_ms_override=5_000_100)

    record = store.active(now_ms_override=5_000_101)[0]
    assert record.did == _metadata(url, "B")["did"]
    assert record.first_seen_ms == 5_000_100


def test_malformed_non_ascii_identity_url_is_ignored(tmp_path: Path) -> None:
    store = LearnedPeerStore(tmp_path)
    store.path.parent.mkdir(parents=True)
    store.path.write_text(
        json.dumps({
            "version": 1,
            "peers": [{
                **_metadata("https://dao-a.example", "A"),
                "identity_url": "https://dao-a.example/\N{SNOWMAN}",
                "first_seen_ms": 1,
                "last_verified_ms": 1,
                "expires_at_ms": 2,
            }],
        }),
        encoding="utf-8",
    )

    assert store.active(now_ms_override=1) == []


def test_same_identity_survives_wall_clock_rollback(tmp_path: Path) -> None:
    url = "https://rollback.example"
    store = LearnedPeerStore(tmp_path, ttl_ms=60_000)
    store.upsert_verified(url, _metadata(url, "A"), now_ms_override=20_000)

    store.upsert_verified(url, _metadata(url, "A"), now_ms_override=10_000)

    record = store.active(now_ms_override=20_001)[0]
    assert record.first_seen_ms == 20_000
    assert record.last_verified_ms == 20_000
    assert record.expires_at_ms == 80_000
    restarted = LearnedPeerStore(tmp_path, ttl_ms=60_000)
    assert restarted.active(now_ms_override=20_001)[0] == record


def test_same_identity_refresh_is_write_debounced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.discovery.federation_registry as registry

    writes = 0
    original_write = registry.atomic_write_json

    def counted_write(*args, **kwargs):
        nonlocal writes
        writes += 1
        return original_write(*args, **kwargs)

    monkeypatch.setattr(registry, "atomic_write_json", counted_write)
    url = "https://stable.example"
    store = LearnedPeerStore(
        tmp_path,
        ttl_ms=120_000,
        min_refresh_write_ms=60_000,
    )
    first = store.upsert_verified(
        url, _metadata(url, "A"), now_ms_override=10_000,
    )
    cached = store.upsert_verified(
        url, _metadata(url, "A"), now_ms_override=20_000,
    )
    refreshed = store.upsert_verified(
        url, _metadata(url, "A"), now_ms_override=70_001,
    )

    assert writes == 2
    assert cached == first
    assert refreshed.last_verified_ms == 70_001
