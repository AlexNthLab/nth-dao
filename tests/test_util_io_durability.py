from __future__ import annotations

import json

import pytest

from nth_dao.util import io


def test_durable_json_fsync_failure_preserves_existing_target(
    tmp_path, monkeypatch,
):
    path = tmp_path / "state.json"
    original = b'{"state":"old"}'
    path.write_bytes(original)

    def fail_fsync(_descriptor):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(io.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="simulated fsync failure"):
        io.atomic_write_json(path, {"state": "new"}, durable=True)

    assert path.read_bytes() == original
    assert list(tmp_path.glob("state.json.*.tmp")) == []


def test_non_durable_json_keeps_historical_best_effort_fsync(
    tmp_path, monkeypatch,
):
    path = tmp_path / "state.json"

    def fail_fsync(_descriptor):
        raise OSError("simulated unsupported fsync")

    monkeypatch.setattr(io.os, "fsync", fail_fsync)

    io.atomic_write_json(path, {"state": "written"})

    assert json.loads(path.read_text(encoding="utf-8")) == {"state": "written"}


def test_durable_and_legacy_json_have_equal_data(tmp_path):
    data = {"message": "中文", "nested": {"count": 2}}
    legacy = tmp_path / "legacy.json"
    durable = tmp_path / "durable.json"

    io.atomic_write_json(legacy, data, indent=2, ensure_ascii=False)
    io.atomic_write_json(
        durable,
        data,
        indent=2,
        ensure_ascii=False,
        durable=True,
    )

    assert json.loads(legacy.read_text(encoding="utf-8")) == data
    assert json.loads(durable.read_text(encoding="utf-8")) == data
