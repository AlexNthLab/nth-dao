from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1] / "tools" / "start_nth_dao.ps1"
)


def test_desktop_launcher_keeps_hermes_in_channel_team() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert '$JoinKinds = "codex,hermes,mock"' in text
    assert '$ChannelAgentKinds = "codex,hermes,mock"' in text
    assert '$CodexModel = "gpt-5.4"' in text
    assert '$HermesModel = "deepseek-v4-flash"' in text
    assert '$HermesToolsets = "safe"' in text
    assert 'NTH_CODEX_MODEL' in text
    assert 'NTH_HERMES_MODEL' in text
    assert 'NTH_HERMES_TOOLSETS' in text
    assert '$env:NTH_AGENT_WORKDIR = $RepoRoot' in text
    assert 'NTH_AGENT_WORKDIR' in text
