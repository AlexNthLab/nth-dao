import os
from pathlib import Path
import subprocess


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
    assert "-ArgumentList $pythonArgs" in text
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
    assert "function Get-NthDaoHealth" in text
    assert "$ExistingHealth.federation.lan_ready" in text
    assert "process is local-only and cannot exchange tasks" in text
    assert "-PassThru" in text
    assert "Stop-Process -Id $ServerProcess.Id" in text
    assert "-FilePath $fileName" in text
    assert "$childCommands" not in text


def test_desktop_launcher_rejects_loopback_lan_configuration() -> None:
    env = os.environ.copy()
    env.update({
        "NTH_HOST": "127.0.0.1",
        "NTH_ALLOW_REMOTE_BIND": "1",
        "NTH_LAN_PUBLISH": "1",
        "NTH_LAN_DISCOVERY": "1",
    })

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
        ],
        cwd=SCRIPT.parents[1],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )

    assert result.returncode != 0
    assert "requires a non-loopback NTH_HOST" in (
        result.stdout + result.stderr
    )
