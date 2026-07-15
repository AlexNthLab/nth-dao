"""Fail-closed release checks for source trees and built distributions.

The gate intentionally scans Git-tracked content instead of trusting
``.gitignore``. Ignored files are useful during development, but only the
tracked tree and the final archives define what a release exposes.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator


MAX_TEXT_BYTES = 2 * 1024 * 1024
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
        re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\r\n\t ]+\\"),
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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
    findings: list[Finding] = []
    for reason, pattern in CONTENT_PATTERNS:
        if pattern.search(text):
            findings.append(Finding(location, reason))
    return findings


def _decode_text(data: bytes) -> str | None:
    if len(data) > MAX_TEXT_BYTES or b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_tracked_tree(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in tracked_paths(root):
        relative = path.relative_to(root).as_posix()
        findings.extend(scan_name(relative))
        if not path.is_file():
            continue
        try:
            text = _decode_text(path.read_bytes())
        except OSError as exc:
            findings.append(Finding(relative, f"could not read tracked file: {exc}"))
            continue
        if text is not None:
            findings.extend(scan_text(relative, text))
    return findings


def _archive_members(path: Path) -> Iterator[tuple[str, bytes]]:
    if path.suffix == ".whl" or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                yield info.filename, archive.read(info)
        return
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            for info in archive.getmembers():
                if not info.isfile():
                    continue
                handle = archive.extractfile(info)
                if handle is not None:
                    yield info.name, handle.read()
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
        text = _decode_text(data)
        if text is not None:
            findings.extend(scan_text(location, text))

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
