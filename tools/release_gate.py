"""Fail-closed release checks for source trees and built distributions.

The gate intentionally scans Git-tracked content instead of trusting
``.gitignore``. Ignored files are useful during development, but only the
tracked tree and the final archives define what a release exposes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_JSON_DOCUMENTS = 10_000
# Exact, previously reviewed public assets; extensions alone grant no bypass.
REVIEWED_BINARY_ASSETS = {
    "frontend/public/nth-dao-logo.jpg": "7f081d7dcae3e43e773ddf78fe09f45e1c453d70e430fbd5edf9fbac6a2acacb",
    "nth_dao/web/static/nth-dao-logo.jpg": "7f081d7dcae3e43e773ddf78fe09f45e1c453d70e430fbd5edf9fbac6a2acacb",
}
RUNTIME_ROOTS = frozenset(
    {
        ".nth",
        "agent_links",
        "blackboard",
        "market_claims",
        "market_feed",
        "missions",
        "sidechain",
        "team_agents",
        "team_announcements",
        "team_audit",
        "team_channels",
        "team_logs",
        "team_marketplace",
        "team_messages",
        "team_tasks",
        "team_trust",
    }
)
RUNTIME_PLACEHOLDERS = frozenset({".gitignore", ".gitkeep"})
SENSITIVE_BASENAMES = frozenset(
    {
        ".env",
        "console.token",
        "credentials.json",
        "identity.json",
        "roster.json",
        "team.json",
    }
)
SENSITIVE_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx"})
CACHE_PARTS = frozenset(
    {"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
)

CONTENT_PATTERNS = (
    (
        "private-key marker",
        re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "Windows user path",
        re.compile(
            r"(?i)\b[A-Z]:(?:\\{1,2})Users(?:\\{1,2})"
            r"[^\\\r\n\t ]+(?:\\{1,2})"
        ),
    ),
    (
        "macOS user path",
        re.compile("/" + r"Users/[^/\s]+/"),
    ),
    (
        "Linux user path",
        re.compile("/" + r"home/[^/\s]+/"),
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "OpenAI/Anthropic-style API key",
        re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b"),
    ),
    (
        "AWS access key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "Telegram bot token",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ),
)


@dataclass(frozen=True)
class Finding:
    location: str
    reason: str


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def git_root(start: Path) -> Path:
    raw = _git(start, "rev-parse", "--show-toplevel")
    return Path(raw.decode("utf-8").strip()).resolve()


def dirty_entries(root: Path) -> list[str]:
    raw = _git(root, "status", "--porcelain", "--untracked-files=all")
    return [line for line in raw.decode("utf-8", errors="replace").splitlines()]


def tracked_paths(root: Path) -> list[Path]:
    raw = _git(root, "ls-files", "-z")
    return [root / item.decode("utf-8") for item in raw.split(b"\0") if item]


def untracked_paths(root: Path) -> list[Path]:
    raw = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    return [root / item.decode("utf-8") for item in raw.split(b"\0") if item]


def _logical_parts(name: str) -> tuple[str, ...]:
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return PurePosixPath(normalized).parts


def scan_name(
    name: str,
    *,
    archive: bool = False,
    allow_sdist_metadata: bool = False,
) -> list[Finding]:
    parts = _logical_parts(name)
    if not parts:
        return []
    findings: list[Finding] = []
    lowered = tuple(part.lower() for part in parts)
    basename = lowered[-1]

    if archive and (name.startswith(("/", "\\")) or ".." in parts):
        findings.append(Finding(name, "unsafe archive member path"))
    if any(part in CACHE_PARTS for part in lowered):
        findings.append(Finding(name, "cache directory in release input"))
    if basename in SENSITIVE_BASENAMES or Path(basename).suffix in SENSITIVE_SUFFIXES:
        findings.append(Finding(name, "sensitive credential/runtime filename"))
    if lowered[0] in RUNTIME_ROOTS and basename not in RUNTIME_PLACEHOLDERS:
        findings.append(Finding(name, "runtime data under repository root"))
    if (
        archive
        and len(lowered) >= 2
        and lowered[-2:] == ("nth_dao", "pyproject.toml")
    ):
        findings.append(Finding(name, "stale nested packaging metadata"))
    generated_sdist_metadata = (
        allow_sdist_metadata
        and bool(lowered)
        and lowered[0] == "nth_dao.egg-info"
    )
    if (
        any(part.endswith(".egg-info") for part in lowered)
        and not generated_sdist_metadata
    ):
        findings.append(Finding(name, "egg-info build residue"))
    return findings


def scan_text(location: str, text: str) -> list[Finding]:
    try:
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            return [Finding(location, "content scan incomplete: text exceeds byte limit")]
    except UnicodeError:
        return [Finding(location, "content scan incomplete: invalid Unicode")]
    findings: list[Finding] = []
    for reason, pattern in CONTENT_PATTERNS:
        if pattern.search(text):
            findings.append(Finding(location, reason))
    contains_key, incomplete = _scan_json(text)
    if contains_key:
        findings.append(Finding(location, "JSON private signing key"))
    if incomplete and (_looks_like_json(text) or Path(location).suffix.lower() in {".json", ".jsonl", ".ndjson"}):
        findings.append(Finding(location, "content scan incomplete: invalid or over-budget JSON/JSONL"))
    return findings


def _looks_like_json(text: str) -> bool:
    prefix = text.lstrip("\ufeff \t\r\n")
    if prefix.startswith("{"):
        return True
    if not prefix.startswith("["):
        return False
    value = prefix[1:].lstrip()
    return not value or value[0] in '{["-0123456789]' or value.startswith(("true", "false", "null"))


def _scan_json(text: str) -> tuple[bool, bool]:
    """Scan whitespace-separated JSON documents without logging private values.

    Inspect each object pair before folding duplicate fields so a later empty
    value cannot hide private material. Parsing failures are not clean scans;
    the caller distinguishes JSON-shaped input from ordinary source text.
    """
    found = False

    def private_value(value: object) -> bool:
        # Only an explicit null or empty string denotes absent private material.
        # Arrays/objects may contain raw key bytes; invalid scalar types also
        # require review rather than becoming a type-based scanner bypass.
        return value is not None and (not isinstance(value, str) or bool(value.strip()))

    def inspect(pairs: list[tuple[str, object]]) -> dict:
        nonlocal found
        for key, value in pairs:
            if key.lower().replace("_", "").replace("-", "") in {"privatekey", "signingkey"}:
                found |= private_value(value)
        if any(key == "kty" and value in ("OKP", "EC", "RSA") for key, value in pairs):
            found |= any(key == "d" and private_value(value) for key, value in pairs)
        return dict(pairs)

    text = text.lstrip("\ufeff")
    decoder = json.JSONDecoder(object_pairs_hook=inspect)
    position = 0
    documents = 0
    while position < len(text):
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        if position == len(text):
            break
        if documents >= MAX_JSON_DOCUMENTS:
            return found, True
        try:
            _, position = decoder.raw_decode(text, position)
        except (ValueError, RecursionError):
            return found, True
        documents += 1
        if position < len(text) and text[position] not in " \t\r\n":
            return found, True
    return found, False


def _decode_text(data: bytes) -> str | None:
    if len(data) > MAX_TEXT_BYTES:
        return None
    try:
        if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            text = data.decode("utf-32")
        elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        else:
            text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    return None if "\0" in text else text


def scan_bytes(location: str, data: bytes, *, logical_name: str) -> list[Finding]:
    """Every input is scanned, explicitly pinned binary, or visibly blocked."""
    if len(data) > MAX_TEXT_BYTES:
        return [Finding(location, "content scan incomplete: input exceeds byte limit")]
    text = _decode_text(data)
    if text is not None:
        return scan_text(location, text)
    expected = REVIEWED_BINARY_ASSETS.get(logical_name)
    if expected is not None and hashlib.sha256(data).hexdigest() == expected:
        return []
    return [Finding(location, "content scan incomplete: unreviewed binary or unsupported encoding")]


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(MAX_TEXT_BYTES + 1)


def _read_index(root: Path, relative: str) -> bytes:
    # Pin the immutable blob before checking its size; an index edit cannot
    # swap in a larger object between the check and the bounded blob read.
    oid = _git(root, "rev-parse", "--verify", f":{relative}").strip()
    if len(oid) not in {40, 64} or any(char not in b"0123456789abcdef" for char in oid):
        raise RuntimeError("index input has no unambiguous blob identity")
    size = int(_git(root, "cat-file", "-s", oid.decode("ascii")))
    if size > MAX_TEXT_BYTES:
        raise RuntimeError("content scan incomplete: index blob exceeds byte limit")
    return _git(root, "cat-file", "blob", oid.decode("ascii"))


def scan_tracked_tree(root: Path) -> list[Finding]:
    """Scan both staged/index bytes and current worktree bytes."""
    findings: list[Finding] = []
    for path in tracked_paths(root):
        relative = path.relative_to(root).as_posix()
        findings.extend(scan_name(relative))
        try:
            index_data = _read_index(root, relative)
        except (RuntimeError, ValueError) as exc:
            findings.append(Finding(f"index:{relative}", str(exc)))
        else:
            findings.extend(scan_bytes(f"index:{relative}", index_data, logical_name=relative))
        if not path.is_file():
            continue
        try:
            data = _read_file(path)
        except OSError as exc:
            findings.append(Finding(relative, f"could not read tracked file: {exc}"))
            continue
        findings.extend(scan_bytes(relative, data, logical_name=relative))
    return findings


def scan_untracked_tree(root: Path) -> list[Finding]:
    """Scan files that Git could add, even when dirty status is allowed."""
    findings: list[Finding] = []
    for path in untracked_paths(root):
        relative = path.relative_to(root).as_posix()
        findings.extend(scan_name(relative))
        if not path.is_file():
            continue
        try:
            data = _read_file(path)
        except OSError as exc:
            findings.append(Finding(relative, f"could not read untracked file: {exc}"))
            continue
        findings.extend(scan_bytes(relative, data, logical_name=relative))
    return findings


def _archive_members(path: Path) -> Iterator[tuple[str, bytes]]:
    if path.suffix == ".whl" or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                with archive.open(info) as handle:
                    yield info.filename, handle.read(MAX_TEXT_BYTES + 1)
        return
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            for info in archive.getmembers():
                if not info.isfile():
                    continue
                handle = archive.extractfile(info)
                if handle is not None:
                    with handle:
                        yield info.name, handle.read(MAX_TEXT_BYTES + 1)
        return
    raise ValueError(f"unsupported distribution archive: {path}")


def _strip_sdist_root(name: str) -> str:
    parts = _logical_parts(name)
    if len(parts) > 1 and parts[0].startswith("nth_dao-"):
        return PurePosixPath(*parts[1:]).as_posix()
    return PurePosixPath(*parts).as_posix()


def scan_distribution(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    wheel_names: set[str] = set()
    is_wheel = path.suffix == ".whl"
    for raw_name, data in _archive_members(path):
        logical = _strip_sdist_root(raw_name)
        location = f"{path.name}:{logical}"
        findings.extend(
            Finding(location, finding.reason)
            for finding in scan_name(
                logical,
                archive=True,
                allow_sdist_metadata=not is_wheel,
            )
        )
        if is_wheel:
            wheel_names.add(logical)
            if logical.startswith(("tests/", "examples/")):
                findings.append(Finding(location, "non-runtime tree included in wheel"))
        findings.extend(scan_bytes(location, data, logical_name=logical))

    if is_wheel:
        expected = {
            path.relative_to(root).as_posix()
            for path in root.glob("nth_dao/**/__init__.py")
        } | {
            path.relative_to(root).as_posix()
            for path in root.glob("team_layer/**/__init__.py")
        }
        for missing in sorted(expected - wheel_names):
            findings.append(Finding(path.name, f"wheel missing package marker {missing}"))
        for required in (
            "nth_dao/web/static/index.html",
            "nth_dao/web/static/v2.html",
        ):
            if required not in wheel_names:
                findings.append(Finding(path.name, f"wheel missing static asset {required}"))
    return findings


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(set(findings), key=lambda item: (item.location, item.reason))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="scan a development tree without treating its dirty state as a failure",
    )
    parser.add_argument(
        "--skip-tree",
        action="store_true",
        help="inspect only archives supplied with --dist",
    )
    parser.add_argument(
        "--dist",
        nargs="*",
        default=[],
        metavar="ARCHIVE",
        help="wheel or sdist archives to inspect",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = git_root(Path.cwd())
    findings: list[Finding] = []

    if not args.skip_tree:
        if not args.allow_dirty:
            for entry in dirty_entries(root):
                findings.append(Finding(entry, "release requires a clean worktree"))
        findings.extend(scan_tracked_tree(root))
        findings.extend(scan_untracked_tree(root))

    for archive_name in args.dist:
        archive = Path(archive_name).resolve()
        if not archive.is_file():
            findings.append(Finding(str(archive), "distribution archive not found"))
            continue
        try:
            findings.extend(scan_distribution(archive, root))
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
            findings.append(Finding(str(archive), f"could not inspect archive: {exc}"))

    findings = _dedupe(findings)
    if findings:
        print("Release gate failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding.location}: {finding.reason}", file=sys.stderr)
        return 1

    scope = "distribution archives" if args.skip_tree else "tracked tree"
    if args.dist and not args.skip_tree:
        scope += " and archives"
    print(f"Release gate passed for {scope}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
