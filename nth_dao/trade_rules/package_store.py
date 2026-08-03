"""Content-addressed, non-executing storage for Trade Rule Packages."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from nth_dao.canonical_json import canonical_json
from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.trade_rules.manifest import (
    MAX_PACKAGE_RESOURCE_BYTES,
    MAX_RESOURCE_BYTES,
    ManifestRejected,
    TradeRuleManifest,
    manifest_digest,
)
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT

DEFAULT_MAX_PACKAGES = 4_096
DEFAULT_MAX_PACKAGE_STORE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_PACKAGE_STORE_FILES = 16_384
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_MANIFEST_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_RESOURCE_FILE = re.compile(r"^([0-9a-f]{64})\.blob$")
_PROVENANCE_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_PROVENANCE_SOURCES = frozenset({"federated", "local"})
_MAX_PROVENANCE_BYTES = 512


class RulePackageError(RuntimeError):
    """Base error for package validation or durable local storage."""


class RulePackageValidationError(RulePackageError):
    """A submitted package is not a complete verified package."""


class RulePackageCorruptionError(RulePackageError):
    """Stored package bytes do not match their signed declarations."""


class RulePackageCapacityError(RulePackageError):
    """The configured package-store bounds would be exceeded."""


class RulePackageBusyError(RulePackageError):
    """Another process currently owns the package-store write lock."""


class RulePackageCryptoUnavailableError(RulePackageError):
    """Manifest signatures cannot be verified in this runtime."""


@dataclass(frozen=True, init=False)
class RulePackage:
    """Verified manifest plus exact immutable resource bytes."""

    digest: str
    manifest: TradeRuleManifest
    resources: Mapping[str, bytes]

    @classmethod
    def _create(
        cls,
        *,
        digest: str,
        manifest: TradeRuleManifest,
        resources: Mapping[str, bytes],
    ) -> "RulePackage":
        package = object.__new__(cls)
        object.__setattr__(package, "digest", digest)
        object.__setattr__(package, "manifest", manifest)
        object.__setattr__(
            package,
            "resources",
            MappingProxyType(dict(resources)),
        )
        return package

    def resource(self, digest: str) -> bytes:
        try:
            return self.resources[digest]
        except KeyError as exc:
            raise KeyError(f"package has no resource {digest}") from exc


@dataclass(frozen=True)
class RulePackageInstallResult:
    digest: str
    installed: bool
    package: RulePackage


@dataclass(frozen=True)
class RulePackageReconciliationReport:
    orphan_resource_digests: tuple[str, ...]
    missing_resource_digests: tuple[str, ...]
    temporary_paths: tuple[str, ...]
    pruned_paths: tuple[str, ...]
    reclaimed_bytes: int


def _verified_manifest(
    value: TradeRuleManifest | dict[str, Any],
) -> TradeRuleManifest:
    try:
        if isinstance(value, TradeRuleManifest):
            return TradeRuleManifest.from_json(value.canonical_bytes)
        if isinstance(value, dict):
            return TradeRuleManifest.from_dict(value)
    except ManifestRejected as exc:
        if str(exc) == "crypto unavailable":
            raise RulePackageCryptoUnavailableError(
                "Trade Rule signature verification requires PyNaCl"
            ) from exc
        raise RulePackageValidationError(f"manifest rejected: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise RulePackageValidationError(f"manifest rejected: {exc}") from exc
    raise TypeError("manifest must be a TradeRuleManifest or object")


def build_rule_package(
    manifest: TradeRuleManifest | dict[str, Any],
    resources: Mapping[str, bytes],
) -> RulePackage:
    """Verify a complete package without granting trust or execution rights."""

    verified = _verified_manifest(manifest)
    if not isinstance(resources, Mapping):
        raise TypeError("resources must be a digest-to-bytes mapping")
    supplied: dict[str, bytes] = {}
    for index, (digest, payload) in enumerate(resources.items()):
        if index >= 128:
            raise RulePackageValidationError(
                "package resources exceed the 128-entry limit"
            )
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise RulePackageValidationError(
                "resource keys must be lowercase sha256 digests"
            )
        if type(payload) is not bytes:
            raise RulePackageValidationError(
                f"resource {digest} must contain immutable bytes"
            )
        if len(payload) > MAX_RESOURCE_BYTES:
            raise RulePackageValidationError(
                f"resource {digest} exceeds the per-resource byte limit"
            )
        supplied[digest] = bytes(payload)

    declared: dict[str, int] = {}
    for resource in verified.to_dict()["resources"]:
        digest = resource["digest"]
        size = resource["size"]
        existing_size = declared.setdefault(digest, size)
        if existing_size != size:
            raise RulePackageValidationError(
                f"manifest declares conflicting sizes for resource {digest}"
            )
    missing = sorted(set(declared) - set(supplied))
    extra = sorted(set(supplied) - set(declared))
    if missing or extra:
        raise RulePackageValidationError(
            f"package resources mismatch; missing={missing}, extra={extra}"
        )
    for digest, expected_size in declared.items():
        payload = supplied[digest]
        if len(payload) != expected_size:
            raise RulePackageValidationError(
                f"resource {digest} size does not match its manifest"
            )
        actual = "sha256:" + hashlib.sha256(payload).hexdigest()
        if actual != digest:
            raise RulePackageValidationError(
                f"resource {digest} content digest mismatch"
            )
    return RulePackage._create(
        digest=manifest_digest(verified),
        manifest=verified,
        resources=supplied,
    )


class RulePackageStore:
    """Durable local cache for verified packages; never executes resources."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_packages: int = DEFAULT_MAX_PACKAGES,
        max_bytes: int = DEFAULT_MAX_PACKAGE_STORE_BYTES,
        max_files: int = DEFAULT_MAX_PACKAGE_STORE_FILES,
        lock_timeout: float = LOCK_TIMEOUT_PATIENT,
    ) -> None:
        if isinstance(max_packages, bool) or not isinstance(max_packages, int):
            raise TypeError("max_packages must be an integer")
        if max_packages < 1:
            raise ValueError("max_packages must be positive")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise TypeError("max_bytes must be an integer")
        minimum_bytes = MAX_PACKAGE_RESOURCE_BYTES + MAX_TRADE_JSON_BYTES
        if max_bytes < minimum_bytes:
            raise ValueError(f"max_bytes must be at least {minimum_bytes}")
        if isinstance(max_files, bool) or not isinstance(max_files, int):
            raise TypeError("max_files must be an integer")
        if max_files < max_packages:
            raise ValueError("max_files must be at least max_packages")
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.root = Path(root) / "trade" / "rule_packages"
        self.manifest_root = self.root / "manifests"
        self.resource_root = self.root / "resources"
        self.provenance_root = self.root / "provenance"
        self.lock_path = self.root / ".locks" / "packages"
        self.max_packages = max_packages
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.lock_timeout = float(lock_timeout)

    @staticmethod
    def _digest_suffix(digest: str) -> str:
        if not isinstance(digest, str):
            raise ValueError("package digest must be a lowercase sha256 digest")
        match = _DIGEST.fullmatch(digest)
        if match is None:
            raise ValueError("package digest must be a lowercase sha256 digest")
        return match.group(1)

    def _manifest_path(self, digest: str) -> Path:
        return self.manifest_root / f"{self._digest_suffix(digest)}.json"

    def _resource_path(self, digest: str) -> Path:
        return self.resource_root / f"{self._digest_suffix(digest)}.blob"

    def _provenance_path(self, digest: str) -> Path:
        return self.provenance_root / f"{self._digest_suffix(digest)}.json"

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        if os.name == "nt":
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                return False
            attributes = getattr(
                metadata,
                "st_file_attributes",
                0,
            )
            return bool(
                attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        return False

    def _assert_store_path(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise RulePackageCorruptionError(
                "package-store path escapes its configured root"
            ) from exc
        current = self.root
        candidates = [current]
        for part in relative.parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise RulePackageCorruptionError(
                    "package store must not contain symlinks or junctions"
                )

    @contextmanager
    def _package_lock(self):
        lock_directory = self.lock_path.parent
        actual_lock_path = Path(str(self.lock_path) + ".lock")
        lock_directory.mkdir(parents=True, exist_ok=True)
        self._assert_store_path(lock_directory)
        self._assert_store_path(actual_lock_path)
        with InterProcessLock(self.lock_path, timeout=self.lock_timeout):
            self._assert_store_path(lock_directory)
            self._assert_store_path(actual_lock_path)
            yield

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_store_path(path.parent)
            self._assert_store_path(path)
            descriptor, temporary = tempfile.mkstemp(
                prefix=path.name + ".",
                suffix=".tmp",
                dir=str(path.parent),
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            temporary = None
            self._fsync_directory(path.parent)
        except OSError as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise RulePackageError(
                f"package write durability could not be confirmed: {exc}"
            ) from exc

    def _read_exact(self, path: Path, *, maximum: int, label: str) -> bytes:
        try:
            self._assert_store_path(path)
            size = path.stat().st_size
            if size > maximum:
                raise RulePackageCorruptionError(f"{label} exceeds its size limit")
            payload = path.read_bytes()
        except FileNotFoundError as exc:
            raise RulePackageCorruptionError(f"{label} is missing") from exc
        except OSError as exc:
            raise RulePackageError(f"unable to read {label}: {exc}") from exc
        if len(payload) != size:
            raise RulePackageCorruptionError(f"{label} changed while being read")
        return payload

    def _usage_locked(
        self,
        *,
        enforce_limits: bool = True,
    ) -> tuple[int, int, int]:
        total_bytes = 0
        total_files = 0
        package_count = 0
        if not self.root.exists():
            return 0, 0, 0
        try:
            self._assert_store_path(self.root)
            for path in self.root.rglob("*"):
                relative = path.relative_to(self.root)
                if self._is_linklike(path):
                    raise RulePackageCorruptionError(
                        "package store must not contain symlinks or junctions"
                    )
                if relative.parts and relative.parts[0] == ".locks":
                    continue
                if path.is_dir():
                    if path not in {
                        self.manifest_root,
                        self.resource_root,
                        self.provenance_root,
                    }:
                        raise RulePackageCorruptionError(
                            f"unexpected package-store directory {path.name!r}"
                        )
                    continue
                total_files += 1
                if enforce_limits and total_files > self.max_files:
                    raise RulePackageCapacityError(
                        "package store exceeds configured max_files"
                    )
                total_bytes += path.stat().st_size
                if enforce_limits and total_bytes > self.max_bytes:
                    raise RulePackageCapacityError(
                        "package store exceeds configured max_bytes"
                    )
                if path.parent == self.manifest_root:
                    if path.name.endswith(".tmp"):
                        continue
                    if _MANIFEST_FILE.fullmatch(path.name) is None:
                        raise RulePackageCorruptionError(
                            f"unexpected manifest-store file {path.name!r}"
                        )
                    package_count += 1
                elif path.parent == self.resource_root:
                    if (
                        not path.name.endswith(".tmp")
                        and _RESOURCE_FILE.fullmatch(path.name) is None
                    ):
                        raise RulePackageCorruptionError(
                            f"unexpected resource-store file {path.name!r}"
                        )
                elif path.parent == self.provenance_root:
                    if (
                        not path.name.endswith(".tmp")
                        and _PROVENANCE_FILE.fullmatch(path.name) is None
                    ):
                        raise RulePackageCorruptionError(
                            f"unexpected provenance-store file {path.name!r}"
                        )
                    if not path.name.endswith(".tmp"):
                        match = _PROVENANCE_FILE.fullmatch(path.name)
                        assert match is not None
                        digest = "sha256:" + match.group(1)
                        if not self._manifest_path(digest).exists():
                            raise RulePackageCorruptionError(
                                f"provenance {digest} has no stored manifest"
                            )
                        self._provenance_sources_locked(digest)
                else:
                    raise RulePackageCorruptionError(
                        f"unexpected package-store file {path.name!r}"
                    )
        except OSError as exc:
            raise RulePackageError(f"unable to inspect package store: {exc}") from exc
        if enforce_limits and package_count > self.max_packages:
            raise RulePackageCapacityError(
                "package store exceeds configured max_packages"
            )
        return package_count, total_files, total_bytes

    def _verify_existing_file(
        self,
        path: Path,
        expected: bytes,
        *,
        label: str,
    ) -> bool:
        if not path.exists():
            return False
        actual = self._read_exact(path, maximum=len(expected), label=label)
        if actual != expected:
            raise RulePackageCorruptionError(
                f"{label} conflicts with its content-addressed path"
            )
        return True

    @staticmethod
    def _validate_source(source: str | None) -> str | None:
        if source is not None and source not in _PROVENANCE_SOURCES:
            raise ValueError("source must be 'local', 'federated', or None")
        return source

    @staticmethod
    def _provenance_bytes(digest: str, sources: tuple[str, ...]) -> bytes:
        return canonical_json(
            {
                "package_digest": digest,
                "sources": list(sources),
                "version": 1,
            }
        )

    def _provenance_sources_locked(self, digest: str) -> tuple[str, ...]:
        path = self._provenance_path(digest)
        if not path.exists():
            return ()
        raw = self._read_exact(
            path,
            maximum=_MAX_PROVENANCE_BYTES,
            label=f"provenance {digest}",
        )
        try:
            document = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RulePackageCorruptionError(
                f"stored provenance {digest} is invalid"
            ) from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"package_digest", "sources", "version"}
            or document.get("package_digest") != digest
            or document.get("version") != 1
            or not isinstance(document.get("sources"), list)
            or not document["sources"]
            or any(source not in _PROVENANCE_SOURCES for source in document["sources"])
            or document["sources"] != sorted(set(document["sources"]))
            or raw != self._provenance_bytes(digest, tuple(document["sources"]))
        ):
            raise RulePackageCorruptionError(
                f"stored provenance {digest} is invalid"
            )
        return tuple(document["sources"])

    def install(
        self,
        manifest: TradeRuleManifest | dict[str, Any],
        resources: Mapping[str, bytes],
        *,
        source: str | None = None,
    ) -> RulePackageInstallResult:
        source = self._validate_source(source)
        package = build_rule_package(manifest, resources)
        manifest_path = self._manifest_path(package.digest)
        try:
            with self._package_lock():
                package_count, total_files, total_bytes = self._usage_locked()
                manifest_exists = manifest_path.exists()
                existing_sources = self._provenance_sources_locked(package.digest)
                desired_sources = tuple(
                    sorted(set(existing_sources) | ({source} if source else set()))
                )
                provenance_path = self._provenance_path(package.digest)
                existing_provenance_bytes = (
                    self._provenance_bytes(package.digest, existing_sources)
                    if existing_sources
                    else b""
                )
                desired_provenance_bytes = (
                    self._provenance_bytes(package.digest, desired_sources)
                    if desired_sources
                    else b""
                )
                additional_bytes = 0
                additional_files = 0
                for digest, payload in package.resources.items():
                    path = self._resource_path(digest)
                    if not path.exists():
                        additional_bytes += len(payload)
                        additional_files += 1
                if not manifest_exists:
                    additional_bytes += len(package.manifest.canonical_bytes)
                    additional_files += 1
                    if package_count + 1 > self.max_packages:
                        raise RulePackageCapacityError(
                            "package store has reached configured max_packages"
                        )
                if desired_provenance_bytes != existing_provenance_bytes:
                    additional_bytes += (
                        len(desired_provenance_bytes)
                        - len(existing_provenance_bytes)
                    )
                    if not provenance_path.exists():
                        additional_files += 1
                if total_files + additional_files > self.max_files:
                    raise RulePackageCapacityError(
                        "package store has reached configured max_files"
                    )
                if total_bytes + additional_bytes > self.max_bytes:
                    raise RulePackageCapacityError(
                        "package store has reached configured max_bytes"
                    )

                for digest, payload in package.resources.items():
                    path = self._resource_path(digest)
                    if not self._verify_existing_file(
                        path, payload, label=f"resource {digest}"
                    ):
                        self._atomic_write(path, payload)
                if self._verify_existing_file(
                    manifest_path,
                    package.manifest.canonical_bytes,
                    label=f"manifest {package.digest}",
                ):
                    loaded = self._load_locked(package.digest)
                    if desired_provenance_bytes != existing_provenance_bytes:
                        self._atomic_write(
                            provenance_path,
                            desired_provenance_bytes,
                        )
                    return RulePackageInstallResult(
                        digest=package.digest,
                        installed=False,
                        package=loaded,
                    )
                self._atomic_write(
                    manifest_path, package.manifest.canonical_bytes
                )
                if desired_provenance_bytes:
                    self._atomic_write(
                        provenance_path,
                        desired_provenance_bytes,
                    )
                return RulePackageInstallResult(
                    digest=package.digest,
                    installed=True,
                    package=package,
                )
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc

    def _load_manifest_locked(self, digest: str) -> TradeRuleManifest:
        manifest_path = self._manifest_path(digest)
        raw_manifest = self._read_exact(
            manifest_path,
            maximum=MAX_TRADE_JSON_BYTES,
            label=f"manifest {digest}",
        )
        try:
            manifest = TradeRuleManifest.from_json(raw_manifest)
        except ManifestRejected as exc:
            if str(exc) == "crypto unavailable":
                raise RulePackageCryptoUnavailableError(
                    "Trade Rule signature verification requires PyNaCl"
                ) from exc
            raise RulePackageCorruptionError(
                f"stored manifest {digest} is invalid: {exc}"
            ) from exc
        actual_digest = manifest_digest(manifest)
        if actual_digest != digest:
            raise RulePackageCorruptionError(
                f"stored manifest digest mismatch for {digest}"
            )
        return manifest

    def _load_locked(self, digest: str) -> RulePackage:
        manifest = self._load_manifest_locked(digest)
        resources: dict[str, bytes] = {}
        for item in manifest.to_dict()["resources"]:
            resource_digest = item["digest"]
            if resource_digest in resources:
                continue
            payload = self._read_exact(
                self._resource_path(resource_digest),
                maximum=item["size"],
                label=f"resource {resource_digest}",
            )
            resources[resource_digest] = payload
        try:
            return build_rule_package(manifest, resources)
        except RulePackageCryptoUnavailableError:
            raise
        except RulePackageValidationError as exc:
            raise RulePackageCorruptionError(
                f"stored package {digest} is invalid: {exc}"
            ) from exc

    def load(self, digest: str) -> RulePackage | None:
        path = self._manifest_path(digest)
        self._assert_store_path(path)
        if not self.root.exists():
            return None
        try:
            with self._package_lock():
                self._assert_store_path(path)
                if not path.exists():
                    return None
                return self._load_locked(digest)
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc

    def provenance_sources(self, digest: str) -> tuple[str, ...]:
        """Return explicit acquisition sources; empty means unclassified."""

        manifest_path = self._manifest_path(digest)
        self._assert_store_path(manifest_path)
        if not self.root.exists():
            return ()
        try:
            with self._package_lock():
                self._usage_locked()
                sources = self._provenance_sources_locked(digest)
                if sources and not manifest_path.exists():
                    raise RulePackageCorruptionError(
                        f"provenance {digest} has no stored manifest"
                    )
                return sources
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc

    def provenance_sources_many(
        self,
        digests: tuple[str, ...],
    ) -> dict[str, tuple[str, ...]]:
        """Read bounded provenance for a verified catalog page under one lock."""

        if len(digests) > 500:
            raise ValueError("at most 500 package digests may be inspected")
        for digest in digests:
            self._digest_suffix(digest)
        if len(set(digests)) != len(digests):
            raise ValueError("package digests must be unique")
        if not self.root.exists():
            return {digest: () for digest in digests}
        try:
            with self._package_lock():
                self._usage_locked()
                result: dict[str, tuple[str, ...]] = {}
                for digest in digests:
                    sources = self._provenance_sources_locked(digest)
                    if sources and not self._manifest_path(digest).exists():
                        raise RulePackageCorruptionError(
                            f"provenance {digest} has no stored manifest"
                        )
                    result[digest] = sources
                return result
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc

    def list_digests(self) -> tuple[str, ...]:
        self._assert_store_path(self.manifest_root)
        if not self.manifest_root.exists():
            return ()
        try:
            with self._package_lock():
                self._usage_locked()
                digests: list[str] = []
                for path in self.manifest_root.iterdir():
                    if path.name.endswith(".tmp"):
                        continue
                    match = _MANIFEST_FILE.fullmatch(path.name)
                    if match is None:
                        raise RulePackageCorruptionError(
                            f"unexpected manifest-store file {path.name!r}"
                        )
                    digest = "sha256:" + match.group(1)
                    self._load_manifest_locked(digest)
                    digests.append(digest)
                return tuple(sorted(digests))
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc

    def list_page(
        self,
        *,
        after: str | None = None,
        limit: int = 100,
    ) -> tuple[tuple[RulePackage, ...], str | None]:
        """Return one verified digest-ordered page without replaying all packages.

        Directory shape and configured capacity bounds are checked for the
        whole store. Publisher signatures and resource bytes are then replayed
        only for the selected page while the same cross-process lock is held.
        The cursor is intentionally not a snapshot token: concurrent installs
        whose digests sort before ``after`` appear on a later fresh traversal.
        """

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 500:
            raise ValueError("limit must be in 1..500")
        after_suffix = self._digest_suffix(after) if after is not None else None
        self._assert_store_path(self.manifest_root)
        if not self.manifest_root.exists():
            return (), None
        try:
            with self._package_lock():
                self._usage_locked()
                suffixes: list[str] = []
                for path in self.manifest_root.iterdir():
                    if path.name.endswith(".tmp"):
                        continue
                    match = _MANIFEST_FILE.fullmatch(path.name)
                    if match is None:
                        raise RulePackageCorruptionError(
                            f"unexpected manifest-store file {path.name!r}"
                        )
                    suffix = match.group(1)
                    if after_suffix is None or suffix > after_suffix:
                        suffixes.append(suffix)
                selected = sorted(suffixes)[: limit + 1]
                page_suffixes = selected[:limit]
                packages = tuple(
                    self._load_locked("sha256:" + suffix)
                    for suffix in page_suffixes
                )
                next_cursor = (
                    packages[-1].digest
                    if len(selected) > limit and packages
                    else None
                )
                return packages, next_cursor
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc

    def reconcile(
        self,
        *,
        prune: bool = False,
    ) -> RulePackageReconciliationReport:
        """Inspect crash residue; delete it only after explicit opt-in."""

        if not isinstance(prune, bool):
            raise TypeError("prune must be a boolean")
        try:
            with self._package_lock():
                self._usage_locked(enforce_limits=False)
                referenced: set[str] = set()
                if self.manifest_root.exists():
                    for path in self.manifest_root.iterdir():
                        if path.name.endswith(".tmp"):
                            continue
                        match = _MANIFEST_FILE.fullmatch(path.name)
                        if match is None:
                            raise RulePackageCorruptionError(
                                f"unexpected manifest-store file {path.name!r}"
                            )
                        digest = "sha256:" + match.group(1)
                        manifest = self._load_manifest_locked(digest)
                        referenced.update(
                            item["digest"]
                            for item in manifest.to_dict()["resources"]
                        )

                available: set[str] = set()
                if self.resource_root.exists():
                    for path in self.resource_root.iterdir():
                        match = _RESOURCE_FILE.fullmatch(path.name)
                        if match is not None:
                            available.add("sha256:" + match.group(1))

                temporary = tuple(
                    sorted(
                        path.relative_to(self.root).as_posix()
                        for path in self.root.rglob("*.tmp")
                        if not (
                            path.relative_to(self.root).parts
                            and path.relative_to(self.root).parts[0] == ".locks"
                        )
                    )
                )
                orphaned = tuple(sorted(available - referenced))
                missing = tuple(sorted(referenced - available))
                pruned_paths: list[str] = []
                reclaimed_bytes = 0
                if prune:
                    candidates = [
                        self._resource_path(digest) for digest in orphaned
                    ]
                    candidates.extend(self.root / value for value in temporary)
                    for path in candidates:
                        self._assert_store_path(path)
                        reclaimed_bytes += path.stat().st_size
                        path.unlink()
                        pruned_paths.append(
                            path.relative_to(self.root).as_posix()
                        )
                    for directory in (self.resource_root, self.manifest_root):
                        if directory.exists():
                            self._fsync_directory(directory)
                return RulePackageReconciliationReport(
                    orphan_resource_digests=orphaned,
                    missing_resource_digests=missing,
                    temporary_paths=temporary,
                    pruned_paths=tuple(sorted(pruned_paths)),
                    reclaimed_bytes=reclaimed_bytes,
                )
        except TimeoutError as exc:
            raise RulePackageBusyError("Trade Rule package store is busy") from exc
        except OSError as exc:
            raise RulePackageError(f"package store I/O failed: {exc}") from exc


__all__ = [
    "DEFAULT_MAX_PACKAGES",
    "DEFAULT_MAX_PACKAGE_STORE_BYTES",
    "DEFAULT_MAX_PACKAGE_STORE_FILES",
    "RulePackage",
    "RulePackageBusyError",
    "RulePackageCapacityError",
    "RulePackageCorruptionError",
    "RulePackageCryptoUnavailableError",
    "RulePackageError",
    "RulePackageInstallResult",
    "RulePackageReconciliationReport",
    "RulePackageStore",
    "RulePackageValidationError",
    "build_rule_package",
]
