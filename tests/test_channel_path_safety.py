"""Regression tests for cross-platform channel storage paths."""

import json
from pathlib import Path

import pytest

from nth_dao.channel import (
    CHANNEL_DIR_PREFIX,
    ChannelMessage,
    TeamChannel,
    _channel_dir,
    _legacy_channel_dir,
)


@pytest.mark.parametrize(
    "channel",
    [
        "team",
        "group:backend",
        "dm:alice--bob",
        "topic/2026",
        "agent..v2",
    ],
)
def test_channel_dir_is_one_fixed_length_portable_component(channel: str) -> None:
    directory = _channel_dir(channel)

    assert directory.startswith(CHANNEL_DIR_PREFIX)
    assert len(directory) == len(CHANNEL_DIR_PREFIX) + 64
    assert "/" not in directory
    assert "\\" not in directory
    assert ":" not in directory
    assert _channel_dir(channel) == directory


@pytest.mark.parametrize("channel", ["", ".", ".."])
def test_channel_dir_rejects_empty_or_relative_components(channel: str) -> None:
    with pytest.raises(ValueError):
        _channel_dir(channel)


@pytest.mark.parametrize(
    "channel",
    [
        r"..\..\outside",
        r"C:\temp\messages",
        r"\\server\share",
    ],
)
def test_channel_dir_rejects_windows_path_syntax(channel: str) -> None:
    with pytest.raises(ValueError, match="backslashes"):
        _channel_dir(channel)


def test_send_rejects_windows_traversal_before_writing(
    tmp_path: Path,
) -> None:
    channel = TeamChannel(tmp_path, agent_id="alice")
    scope = r"..\..\outside"

    with pytest.raises(ValueError, match="backslashes"):
        channel.send("safe", scope=scope)

    assert not (tmp_path / "outside").exists()
    assert not any((tmp_path / "team_messages").iterdir())


def test_colliding_legacy_names_remain_isolated_in_v2_storage(
    tmp_path: Path,
) -> None:
    channel = TeamChannel(tmp_path, agent_id="alice")
    first = "group:backend"
    second = "group--backend"
    assert _legacy_channel_dir(first) == _legacy_channel_dir(second)
    assert _channel_dir(first) != _channel_dir(second)

    channel.send("first-only", scope=first)
    channel.send("second-only", scope=second)

    assert [message.content for message in channel.fetch(first)] == ["first-only"]
    assert [message.content for message in channel.fetch(second)] == ["second-only"]
    assert channel.list_channels() == sorted([first, second])
    assert set(channel.fetch_all()) == {first, second}
    assert [message.content for message in channel.search("only", channel=first)] == [
        "first-only"
    ]
    assert channel.stats()["channels"] == {first: 1, second: 1}


def test_legacy_directory_is_read_but_filtered_by_original_channel(
    tmp_path: Path,
) -> None:
    channel = TeamChannel(tmp_path, agent_id="alice")
    first = "group:backend"
    second = "group--backend"
    legacy_dir = channel.base_dir / _legacy_channel_dir(first)
    legacy_dir.mkdir()
    messages = [
        ChannelMessage("one", first, "alice", "first"),
        ChannelMessage("two", second, "mallory", "second"),
    ]
    (legacy_dir / "legacy.jsonl").write_text(
        "".join(json.dumps(message.to_dict()) + "\n" for message in messages),
        encoding="utf-8",
    )

    assert [message.content for message in channel.fetch(first)] == ["first"]
    assert [message.content for message in channel.fetch(second)] == ["second"]
    assert channel.list_channels() == sorted([first, second])


def test_fetch_all_empty_filter_preserves_all_channels_contract(
    tmp_path: Path,
) -> None:
    channel = TeamChannel(tmp_path, agent_id="alice")
    channel.send("one", scope="group:one")
    channel.send("two", scope="group:two")

    assert set(channel.fetch_all(channels=[])) == {"group:one", "group:two"}


def test_long_channel_name_does_not_break_legacy_compatibility_probe(
    tmp_path: Path,
) -> None:
    channel = TeamChannel(tmp_path, agent_id="alice")
    long_name = "group:" + ("x" * 500)
    channel.send("portable", scope=long_name)

    assert [message.content for message in channel.fetch(long_name)] == ["portable"]
