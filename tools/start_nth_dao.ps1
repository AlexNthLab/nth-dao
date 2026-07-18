param(
    [int] $Port = 8080,
    [string] $AutoAgents = "codex,hermes,mock",
    [string] $JoinChannels = "general",
    # Hermes is part of the default local team. It must be both a channel
    # member and an allowed channel responder; otherwise the process can be
    # healthy while every Channel dispatch silently excludes it.
    [string] $JoinKinds = "codex,hermes,mock",
    [string] $ChannelAgentKinds = "codex,hermes,mock",
    [string] $CodexModel = "gpt-5.4",
    [int] $CodexTimeoutSeconds = 240,
    [string] $HermesModel = "deepseek-v4-flash",
    [string] $HermesToolsets = "safe",
    [string] $AgentWorkdir = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not $env:NTH_PORT) {
    $env:NTH_PORT = [string] $Port
}
if (-not $env:NTH_AUTO_AGENTS) {
    $env:NTH_AUTO_AGENTS = $AutoAgents
}
if (-not $env:NTH_AUTO_AGENT_JOIN_CHANNELS) {
    $env:NTH_AUTO_AGENT_JOIN_CHANNELS = $JoinChannels
}
if (-not $env:NTH_AUTO_AGENT_JOIN_KINDS) {
    $env:NTH_AUTO_AGENT_JOIN_KINDS = $JoinKinds
}
if (-not $env:NTH_CHANNEL_AGENT_KINDS) {
    $env:NTH_CHANNEL_AGENT_KINDS = $ChannelAgentKinds
}
if (-not $env:NTH_AUTO_AGENT_PERSIST) {
    $env:NTH_AUTO_AGENT_PERSIST = "1"
}
if (-not $env:NTH_HERMES_ASK_TIMEOUT_S) {
    $env:NTH_HERMES_ASK_TIMEOUT_S = "300"
}
if (-not $env:NTH_CODEX_MODEL) {
    $env:NTH_CODEX_MODEL = $CodexModel
}
if (-not $env:NTH_CODEX_ASK_TIMEOUT_S) {
    $env:NTH_CODEX_ASK_TIMEOUT_S = [string] $CodexTimeoutSeconds
}
if (-not $env:NTH_HERMES_MODEL) {
    $env:NTH_HERMES_MODEL = $HermesModel
}
if (-not $env:NTH_HERMES_TOOLSETS) {
    $env:NTH_HERMES_TOOLSETS = $HermesToolsets
}
if ($AgentWorkdir) {
    $resolvedAgentWorkdir = Resolve-Path -LiteralPath $AgentWorkdir -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolvedAgentWorkdir -PathType Container)) {
        throw "AgentWorkdir must name an existing directory: $AgentWorkdir"
    }
    $env:NTH_AGENT_WORKDIR = [string] $resolvedAgentWorkdir
} elseif (-not $env:NTH_AGENT_WORKDIR) {
    $env:NTH_AGENT_WORKDIR = $RepoRoot
}

$RuntimeDeps = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies"
$BundledNodeBin = Join-Path $RuntimeDeps "node\bin"
$BundledToolBin = Join-Path $RuntimeDeps "bin"
$PathPrefix = @()
if (Test-Path (Join-Path $BundledNodeBin "node.exe")) {
    $PathPrefix += $BundledNodeBin
    if (-not $env:NTH_DAO_NODE) {
        $env:NTH_DAO_NODE = Join-Path $BundledNodeBin "node.exe"
    }
}
if (Test-Path $BundledToolBin) {
    $PathPrefix += $BundledToolBin
}
$ReversedPathPrefix = @($PathPrefix)
[array]::Reverse($ReversedPathPrefix)
foreach ($prefix in $ReversedPathPrefix) {
    $parts = ($env:PATH -split [IO.Path]::PathSeparator) | Where-Object { $_ }
    if ($parts -notcontains $prefix) {
        $env:PATH = $prefix + [IO.Path]::PathSeparator + $env:PATH
    }
}

$BaseUrl = "http://127.0.0.1:$($env:NTH_PORT)"
$HealthUrl = "$BaseUrl/api/v2/health"
$ConsoleUrl = "$BaseUrl/v2.html"

function Test-NthDaoHealth {
    try {
        $response = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2
        return [bool] $response
    } catch {
        return $false
    }
}

if (Test-NthDaoHealth) {
    Start-Process $ConsoleUrl
    return
}

$LogDir = Join-Path $env:LOCALAPPDATA "NthDAO\logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$OutLog = Join-Path $LogDir "nth-dao-web.out.log"
$ErrLog = Join-Path $LogDir "nth-dao-web.err.log"

$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $python) {
    $python = Get-Command py -ErrorAction SilentlyContinue
}
if ($null -eq $python) {
    throw "Python was not found on PATH. Install Python or add it to PATH, then rerun this shortcut."
}

$fileName = $python.Source

function Quote-PowerShellLiteral([string] $Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

$childCommands = @(
    "`$env:NTH_PORT = $(Quote-PowerShellLiteral $env:NTH_PORT)",
    "`$env:NTH_AUTO_AGENTS = $(Quote-PowerShellLiteral $env:NTH_AUTO_AGENTS)",
    "`$env:NTH_AUTO_AGENT_JOIN_CHANNELS = $(Quote-PowerShellLiteral $env:NTH_AUTO_AGENT_JOIN_CHANNELS)",
    "`$env:NTH_AUTO_AGENT_JOIN_KINDS = $(Quote-PowerShellLiteral $env:NTH_AUTO_AGENT_JOIN_KINDS)",
    "`$env:NTH_CHANNEL_AGENT_KINDS = $(Quote-PowerShellLiteral $env:NTH_CHANNEL_AGENT_KINDS)",
    "`$env:NTH_AUTO_AGENT_PERSIST = $(Quote-PowerShellLiteral $env:NTH_AUTO_AGENT_PERSIST)",
    "`$env:NTH_HERMES_ASK_TIMEOUT_S = $(Quote-PowerShellLiteral $env:NTH_HERMES_ASK_TIMEOUT_S)",
    "`$env:NTH_CODEX_MODEL = $(Quote-PowerShellLiteral $env:NTH_CODEX_MODEL)",
    "`$env:NTH_CODEX_ASK_TIMEOUT_S = $(Quote-PowerShellLiteral $env:NTH_CODEX_ASK_TIMEOUT_S)",
    "`$env:NTH_HERMES_MODEL = $(Quote-PowerShellLiteral $env:NTH_HERMES_MODEL)",
    "`$env:NTH_HERMES_TOOLSETS = $(Quote-PowerShellLiteral $env:NTH_HERMES_TOOLSETS)",
    "`$env:NTH_AGENT_WORKDIR = $(Quote-PowerShellLiteral $env:NTH_AGENT_WORKDIR)",
    "`$env:NTH_DAO_NODE = $(Quote-PowerShellLiteral $env:NTH_DAO_NODE)",
    "`$env:PATH = $(Quote-PowerShellLiteral $env:PATH)",
    "Set-Location -LiteralPath $(Quote-PowerShellLiteral $RepoRoot)"
)

$pythonCommand = "& $(Quote-PowerShellLiteral $fileName)"
if ((Split-Path -Leaf $fileName).ToLowerInvariant() -eq "py.exe") {
    $pythonCommand += " -3"
}
$pythonCommand += " -m nth_dao.web"
$childCommands += $pythonCommand
$childCommand = $childCommands -join "; "

Start-Process `
    -FilePath powershell.exe `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $childCommand) `
    -WorkingDirectory $RepoRoot `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -WindowStyle Hidden

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if (Test-NthDaoHealth) {
        Start-Process $ConsoleUrl
        return
    }
}

Write-Warning "NTH DAO did not become healthy within 30 seconds. Logs: $OutLog ; $ErrLog"
Start-Process $LogDir
