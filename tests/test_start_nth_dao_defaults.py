from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1] / "tools" / "start_nth_dao.ps1"
)


def test_desktop_launcher_detects_agents_without_auto_joining() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert '$AutoAgents = ""' in text
    assert '$JoinKinds = ""' in text
    assert '$ChannelAgentKinds = "codex,claude-code,hermes"' in text
    assert '$LanFederation = $true' in text
    assert '$env:NTH_LAN_DISCOVERY = "1"' in text
    assert '"`$env:NTH_LAN_DISCOVERY = ' in text
    assert '$env:NTH_AUTO_AGENT_PERSIST = "0"' in text
    assert '"mock"' not in text
    assert '$CodexModel = "gpt-5.4"' in text
    assert '$HermesModel = "deepseek-v4-flash"' in text
    assert '$HermesToolsets = "safe"' in text
    assert 'NTH_CODEX_MODEL' in text
    assert 'NTH_HERMES_MODEL' in text
    assert 'NTH_HERMES_TOOLSETS' in text
    assert '$env:NTH_AGENT_WORKDIR = $RepoRoot' in text
    assert '[string] $AgentWorkdir = ""' in text
    assert 'Resolve-Path -LiteralPath $AgentWorkdir' in text
    assert 'NTH_AGENT_WORKDIR' in text
