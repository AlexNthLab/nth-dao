import hashlib
import multiprocessing
import os
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.trade_rules import manifest_body, sign_manifest
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageBusyError,
    RulePackageCapacityError,
    RulePackageCorruptionError,
    RulePackageCryptoUnavailableError,
    RulePackageError,
    RulePackageStore,
    RulePackageValidationError,
    build_rule_package,
)

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="Trade Rule signatures require PyNaCl"
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _process_install(root, manifest, resources, output):
    try:
        result = RulePackageStore(root, lock_timeout=10).install(
            manifest,
            resources,
        )
        output.put(("ok", result.installed, result.digest))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def test_rule_package_cannot_be_constructed_without_verification():
    with pytest.raises(TypeError):
        RulePackage("sha256:" + ("0" * 64), object(), {})


def test_linklike_detection_supports_legacy_windows_reparse_points(
    monkeypatch,
):
    class LegacyPath:
        def is_symlink(self):
            return False

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(
        os,
        "lstat",
        lambda _path: SimpleNamespace(
            st_file_attributes=getattr(
                stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                0x400,
            )
        ),
    )

    assert RulePackageStore._is_linklike(LegacyPath()) is True


def _package(identity=None, *, rule_id="org.nthdao.test.delivery", payload=b"terms"):
    identity = identity or AgentIdentity.generate()
    digest = _digest(payload)
    body = manifest_body(
        rule_id=rule_id,
        version="1.0.0",
        publisher_did=identity.as_did(),
        summary="Content-addressed test rule",
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
        published_at="2026-07-29T00:00:00Z",
        not_after="2027-07-29T00:00:00Z",
    )
    manifest = sign_manifest(
        identity, body, created="2026-07-29T00:00:01Z"
    )
    return manifest, {digest: payload}


def test_build_rule_package_verifies_and_freezes_resources():
    manifest, resources = _package()
    package = build_rule_package(manifest, resources)
    digest = next(iter(resources))

    resources[digest] = b"changed outside"

    assert package.digest.startswith("sha256:")
    assert package.resource(digest) == b"terms"
    with pytest.raises(TypeError):
        package.resources[digest] = b"mutate"  # type: ignore[index]


@pytest.mark.parametrize(
    "mutator, reason",
    [
        (lambda manifest, resources: {}, "missing"),
        (
            lambda manifest, resources: {
                **resources,
                _digest(b"extra"): b"extra",
            },
            "extra",
        ),
            (
                lambda manifest, resources: {
                    next(iter(resources)): b"x",
                },
                "size",
            ),
    ],
)
def test_build_rule_package_rejects_incomplete_or_wrong_resources(
    mutator, reason
):
    manifest, resources = _package()
    with pytest.raises(RulePackageValidationError, match=reason):
        build_rule_package(manifest, mutator(manifest, resources))


def test_build_rule_package_rejects_same_size_digest_mismatch():
    manifest, resources = _package()
    digest = next(iter(resources))
    with pytest.raises(RulePackageValidationError, match="digest mismatch"):
        build_rule_package(manifest, {digest: b"other"})


def test_build_rule_package_rejects_mutable_resource_buffers():
    manifest, resources = _package()
    digest = next(iter(resources))
    with pytest.raises(RulePackageValidationError, match="immutable bytes"):
        build_rule_package(manifest, {digest: bytearray(b"terms")})


def test_build_rule_package_bounds_supplied_entries_and_bytes():
    manifest, resources = _package()
    too_many = {
        _digest(f"extra-{index}".encode()): b"x"
        for index in range(129)
    }
    with pytest.raises(RulePackageValidationError, match="128-entry"):
        build_rule_package(manifest, too_many)

    digest = next(iter(resources))
    with pytest.raises(RulePackageValidationError, match="byte limit"):
        build_rule_package(manifest, {digest: b"x" * (1_048_576 + 1)})


def test_build_rule_package_reverifies_manifest_signature():
    manifest, resources = _package()
    document = manifest.to_dict()
    document["summary"] = "tampered"
    with pytest.raises(RulePackageValidationError, match="manifest rejected"):
        build_rule_package(document, resources)


def test_store_install_load_list_and_idempotent_retry(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()

    first = store.install(manifest, resources)
    duplicate = store.install(manifest, resources)
    loaded = store.load(first.digest)

    assert first.installed is True
    assert duplicate.installed is False
    assert duplicate.digest == first.digest
    assert loaded is not None
    assert loaded.manifest.canonical_bytes == manifest.canonical_bytes
    assert dict(loaded.resources) == resources
    assert store.list_digests() == (first.digest,)


def test_store_deduplicates_shared_resource_blobs(tmp_path):
    store = RulePackageStore(tmp_path)
    identity = AgentIdentity.generate()
    first_manifest, resources = _package(
        identity, rule_id="org.nthdao.test.first"
    )
    second_manifest, _ = _package(
        identity, rule_id="org.nthdao.test.second"
    )

    store.install(first_manifest, resources)
    store.install(second_manifest, resources)

    assert len(list(store.resource_root.glob("*.blob"))) == 1
    assert len(store.list_digests()) == 2


def test_store_fails_closed_on_resource_tampering(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    installed = store.install(manifest, resources)
    resource_path = store._resource_path(next(iter(resources)))
    resource_path.write_bytes(b"other")

    with pytest.raises(RulePackageCorruptionError):
        store.load(installed.digest)
    with pytest.raises(RulePackageCorruptionError):
        store.install(manifest, resources)


def test_store_fails_closed_on_manifest_tampering(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    installed = store.install(manifest, resources)
    store._manifest_path(installed.digest).write_bytes(b"{}")

    with pytest.raises(RulePackageCorruptionError):
        store.load(installed.digest)


def test_manifest_is_commit_marker_after_resource_write_failure(
    tmp_path, monkeypatch
):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    real_write = store._atomic_write

    def fail_manifest(path, payload):
        if path.parent == store.manifest_root:
            raise RulePackageError("injected manifest failure")
        return real_write(path, payload)

    monkeypatch.setattr(store, "_atomic_write", fail_manifest)
    with pytest.raises(RulePackageError, match="injected"):
        store.install(manifest, resources)

    assert store.list_digests() == ()
    assert list(store.resource_root.glob("*.blob"))

    report = store.reconcile()
    assert report.orphan_resource_digests == tuple(resources)
    assert report.pruned_paths == ()
    assert list(store.resource_root.glob("*.blob"))

    pruned = store.reconcile(prune=True)
    assert pruned.orphan_resource_digests == tuple(resources)
    assert pruned.pruned_paths
    assert pruned.reclaimed_bytes == sum(map(len, resources.values()))
    assert not list(store.resource_root.glob("*.blob"))
    assert store.reconcile().orphan_resource_digests == ()


def test_store_package_count_is_bounded(tmp_path):
    store = RulePackageStore(tmp_path, max_packages=1)
    identity = AgentIdentity.generate()
    first, resources = _package(identity, rule_id="org.nthdao.test.first")
    second, _ = _package(identity, rule_id="org.nthdao.test.second")
    store.install(first, resources)

    with pytest.raises(RulePackageCapacityError, match="max_packages"):
        store.install(second, resources)


def test_store_concurrent_install_has_one_commit(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda _index: store.install(manifest, resources),
                range(16),
            )
        )

    assert sum(result.installed for result in results) == 1
    assert len({result.digest for result in results}) == 1
    assert store.list_digests() == (results[0].digest,)


def test_store_cross_process_install_has_one_commit(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_process_install,
            args=(tmp_path, manifest.to_dict(), resources, output),
        )
        for _ in range(4)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            pytest.fail("cross-process package install did not terminate")
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert sum(result[1] for result in results) == 1
    assert len({result[2] for result in results}) == 1
    assert store.list_digests() == (results[0][2],)


def test_load_waits_for_concurrent_manifest_commit(tmp_path, monkeypatch):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    digest = build_rule_package(manifest, resources).digest
    real_write = store._atomic_write
    manifest_pending = threading.Event()
    release = threading.Event()

    def delayed_manifest(path, payload):
        if path.parent == store.manifest_root:
            manifest_pending.set()
            assert release.wait(timeout=2)
        return real_write(path, payload)

    monkeypatch.setattr(store, "_atomic_write", delayed_manifest)
    with ThreadPoolExecutor(max_workers=2) as executor:
        installing = executor.submit(store.install, manifest, resources)
        assert manifest_pending.wait(timeout=2)
        loading = executor.submit(store.load, digest)
        time.sleep(0.05)
        assert not loading.done()
        release.set()
        assert installing.result(timeout=2).installed is True
        assert loading.result(timeout=2) is not None


def test_store_ignores_bounded_atomic_temp_residue(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    result = store.install(manifest, resources)
    (store.manifest_root / "interrupted.json.random.tmp").write_bytes(b"x")
    (store.resource_root / "interrupted.blob.random.tmp").write_bytes(b"x")

    assert store.list_digests() == (result.digest,)


def test_store_rejects_unrecognized_files_and_directories(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    store.install(manifest, resources)
    (store.resource_root / "not-content-addressed.txt").write_bytes(b"x")

    with pytest.raises(RulePackageCorruptionError, match="unexpected"):
        store.list_digests()


def test_store_lock_contention_is_retryable(tmp_path):
    from nth_dao.util.io import InterProcessLock

    store = RulePackageStore(tmp_path, lock_timeout=0.05)
    manifest, resources = _package()
    store.install(manifest, resources)

    with InterProcessLock(store.lock_path, timeout=1):
        with pytest.raises(RulePackageBusyError, match="busy"):
            store.list_digests()


def test_store_empty_reads_do_not_create_directories(tmp_path):
    store = RulePackageStore(tmp_path)
    missing = "sha256:" + ("0" * 64)

    assert store.load(missing) is None
    assert store.list_digests() == ()
    assert not (tmp_path / "trade").exists()


def test_store_rejects_invalid_digest_without_path_access(tmp_path):
    store = RulePackageStore(tmp_path)
    with pytest.raises(ValueError, match="sha256"):
        store.load("../../identity.json")


def test_store_rejects_broken_manifest_symlink_as_corruption(tmp_path):
    store = RulePackageStore(tmp_path)
    digest = "sha256:" + ("0" * 64)
    path = store._manifest_path(digest)
    path.parent.mkdir(parents=True)
    try:
        os.symlink(path.parent / "missing-target", path)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RulePackageCorruptionError, match="symlink"):
        store.load(digest)


def test_load_rejects_linklike_resource_parent(tmp_path, monkeypatch):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    installed = store.install(manifest, resources)
    real_is_linklike = store._is_linklike

    monkeypatch.setattr(
        store,
        "_is_linklike",
        lambda path: path == store.resource_root or real_is_linklike(path),
    )

    with pytest.raises(RulePackageCorruptionError, match="junction"):
        store.load(installed.digest)


def test_operations_reject_linklike_lock_directory(tmp_path, monkeypatch):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    store.install(manifest, resources)
    real_is_linklike = store._is_linklike

    monkeypatch.setattr(
        store,
        "_is_linklike",
        lambda path: (
            path == store.lock_path.parent or real_is_linklike(path)
        ),
    )

    with pytest.raises(RulePackageCorruptionError, match="junction"):
        store.list_digests()


def test_reconcile_reports_missing_resources_without_deleting_manifest(tmp_path):
    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    installed = store.install(manifest, resources)
    resource_digest = next(iter(resources))
    store._resource_path(resource_digest).unlink()

    report = store.reconcile(prune=True)

    assert report.missing_resource_digests == (resource_digest,)
    assert report.pruned_paths == ()
    assert store._manifest_path(installed.digest).exists()


def test_reconcile_can_recover_store_that_is_already_over_file_limit(tmp_path):
    store = RulePackageStore(tmp_path, max_packages=2, max_files=2)
    manifest, resources = _package()
    store.install(manifest, resources)
    residue = store.resource_root / "interrupted.blob.random.tmp"
    residue.write_bytes(b"x")

    with pytest.raises(RulePackageCapacityError, match="max_files"):
        store.list_digests()

    report = store.reconcile(prune=True)

    assert report.temporary_paths == ("resources/interrupted.blob.random.tmp",)
    assert report.pruned_paths == report.temporary_paths
    assert report.reclaimed_bytes == 1
    assert store.list_digests()


def test_crypto_unavailable_is_not_reported_as_corruption(
    tmp_path, monkeypatch
):
    import nth_dao.trade_rules.signing as signing

    store = RulePackageStore(tmp_path)
    manifest, resources = _package()
    installed = store.install(manifest, resources)
    monkeypatch.setattr(signing, "_VerifyKey", None)

    with pytest.raises(RulePackageCryptoUnavailableError, match="PyNaCl"):
        RulePackageStore(tmp_path).load(installed.digest)
