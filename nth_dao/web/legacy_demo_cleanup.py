"""Quarantine legacy demo records that older web-console builds persisted.

The migration is deliberately narrow. It moves only records whose path and
payload match the old built-in seed data. ``mock`` agents and the historical
``echo-agent`` member are not selected because those values were also valid
operator choices and the old records did not preserve creation provenance.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from nth_dao.util import atomic_write_json

logger = logging.getLogger(__name__)

_MIGRATION_KIND = "nth-dao-legacy-demo-cleanup-v2"
_MIGRATION_DIR = "legacy-demo-cleanup-v2"

_SEED_AGENTS = {
    "1f9c-44de": (
        "did:key:z6MkpQ8eF1xRzL3tJyN5sWvD9XbA2C7uYkP4hM8kT6f3B",
        "code-helper",
    ),
    "62b1-08e4": (
        "did:key:z6Mk5p1H3kT9YqXqMpL7Wm2N6bV8jK4cD5fE3hQ9rZxAtPq",
        "mumolawos-coordinator",
    ),
    "7e3a-91b2": (
        "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A",
        "billing-helper",
    ),
    "a3d8-c5fa": (
        "did:key:z6MkrTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "Alice (Acme Cloud rep)",
    ),
    "ff04-7c3b": (
        "did:key:z6MkjyN3aP2qLkR8wEsTvB4nMc6dF9gXuYhAvKkH7tQ4rPsM",
        "fulfillment-bot",
    ),
}

_SEED_CAPS = {
    "cap-bnHs82Lq.json": "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A",
    "cap-3xQ1pTaM.json": "did:key:z6MkpQ8eF1xRzL3tJyN5sWvD9XbA2C7uYkP4hM8kT6f3B",
}

_SEED_RECEIPTS = {
    "rcpt-aaa1.json": "0a9c0bf3e89b6901cdab12345678cafe...",
    "rcpt-aaa2.json": "a7f8ab3c5b93c83a...",
}


def _load_object(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _quarantine(
    workspace: Path,
    path: Path,
    *,
    quarantined: list[str],
    failures: list[str],
) -> None:
    if path.is_symlink() or not path.is_file():
        return
    try:
        relative = path.relative_to(workspace)
    except ValueError:
        return
    target = workspace / "migrations" / _MIGRATION_DIR / "quarantine" / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        if target.exists():
            if target.is_symlink() or target.read_bytes() != path.read_bytes():
                logger.warning(
                    "legacy demo quarantine collision; preserved source: %s",
                    relative,
                )
                failures.append(relative.as_posix())
                return
            path.unlink()
        else:
            path.replace(target)
    except (FileNotFoundError, OSError):
        logger.warning("legacy demo record could not be quarantined: %s", relative)
        failures.append(relative.as_posix())
        return
    quarantined.append(relative.as_posix())


def _quarantine_matching(
    workspace: Path,
    path: Path,
    *,
    field: str,
    expected: str,
    quarantined: list[str],
    failures: list[str],
) -> None:
    if path.is_symlink():
        return
    payload = _load_object(path)
    if payload is None or str(payload.get(field) or "") != expected:
        return
    _quarantine(
        workspace,
        path,
        quarantined=quarantined,
        failures=failures,
    )


def _quarantine_seed_agents(
    workspace: Path,
    quarantined: list[str],
    failures: list[str],
) -> None:
    root = workspace / "team_agents"
    for code, (did, label) in _SEED_AGENTS.items():
        identity_path = root / code / "identity.json"
        if identity_path.is_symlink():
            continue
        payload = _load_object(identity_path)
        if payload is None:
            continue
        if (
            str(payload.get("did") or "") != did
            or str(payload.get("label") or "") != label
        ):
            continue
        _quarantine(
            workspace,
            identity_path,
            quarantined=quarantined,
            failures=failures,
        )
        try:
            identity_path.parent.rmdir()
        except OSError:
            pass


def purge_legacy_demo_state(state: Any) -> dict[str, Any]:
    """Apply the one-time legacy-demo migration for a :class:`WebState`.

    A completion marker is written only after the bounded cleanup succeeds.
    Re-running after interruption is safe because every operation is
    idempotent and payload-verified.
    """

    workspace = Path(state.workspace)
    marker = workspace / "migrations" / f"{_MIGRATION_DIR}.json"
    prior = _load_object(marker)
    if prior and prior.get("kind") == _MIGRATION_KIND:
        return prior

    quarantined: list[str] = []
    failures: list[str] = []
    _quarantine_seed_agents(workspace, quarantined, failures)
    for filename, subject_did in _SEED_CAPS.items():
        _quarantine_matching(
            workspace,
            workspace / "team_cap_tokens" / filename,
            field="subject_did",
            expected=subject_did,
            quarantined=quarantined,
            failures=failures,
        )
    for filename, content_hash in _SEED_RECEIPTS.items():
        _quarantine_matching(
            workspace,
            workspace / "team_receipts" / filename,
            field="content_hash",
            expected=content_hash,
            quarantined=quarantined,
            failures=failures,
        )

    result = {
        "kind": _MIGRATION_KIND,
        "quarantined": quarantined,
        "quarantined_count": len(quarantined),
        "failures": failures,
        "completed": not failures,
    }
    if not failures:
        atomic_write_json(marker, result)
    else:
        logger.warning(
            "legacy demo cleanup incomplete; %d record(s) will be retried",
            len(failures),
        )
    if quarantined:
        logger.info("quarantined %d legacy demo record(s)", len(quarantined))
    return result


__all__ = ["purge_legacy_demo_state"]
