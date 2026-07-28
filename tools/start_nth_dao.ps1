param(
    [int] $Port = 8080,
    [string] $AutoAgents = "",
    [string] $JoinChannels = "general",
    [string] $JoinKinds = "",
    [string] $ChannelAgentKinds = "codex,claude-code,hermes",
    [bool] $LanFederation = $true,
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
if ($LanFederation) {
    if (-not $env:NTH_HOST) {
        $env:NTH_HOST = "0.0.0.0"
    }
    if (-not $env:NTH_ALLOW_REMOTE_BIND) {
        $env:NTH_ALLOW_REMOTE_BIND = "1"
    }
    if (-not $env:NTH_LAN_PUBLISH) {
        $env:NTH_LAN_PUBLISH = "1"
    }
    if (-not $env:NTH_LAN_DISCOVERY) {
        $env:NTH_LAN_DISCOVERY = "1"
    }
    $normalizedHost = $env:NTH_HOST.Trim().ToLowerInvariant()
    if ($normalizedHost -in @("127.0.0.1", "::1", "localhost")) {
        throw (
            "LanFederation requires a non-loopback NTH_HOST. Clear NTH_HOST " +
            "or set it to 0.0.0.0 before running this launcher."
        )
    }
    if ($env:NTH_ALLOW_REMOTE_BIND -ne "1") {
        throw "LanFederation requires NTH_ALLOW_REMOTE_BIND=1."
    }
    if ($env:NTH_LAN_PUBLISH -ne "1") {
        throw "LanFederation requires NTH_LAN_PUBLISH=1."
    }
    if ($env:NTH_LAN_DISCOVERY -ne "1") {
        throw "LanFederation requires NTH_LAN_DISCOVERY=1."
    }
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
    $env:NTH_AUTO_AGENT_PERSIST = "0"
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

function Get-NthDaoHealth {
    try {
        return Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2
    } catch {
        return $null
    }
}

function Test-NthDaoHealth {
    $response = Get-NthDaoHealth
    if ($null -eq $response -or -not [bool] $response.ok) {
        return $false
    }
    if ($LanFederation -and -not [bool] $response.federation.lan_ready) {
        return $false
    }
    return $true
}

$ExistingHealth = Get-NthDaoHealth
if ($null -ne $ExistingHealth) {
    if ($LanFederation -and -not [bool] $ExistingHealth.federation.lan_ready) {
        throw (
            "NTH DAO is already running on port $($env:NTH_PORT), but that " +
            "process is local-only and cannot exchange tasks with another PC. " +
            "Stop that process, then rerun this launcher (or start with " +
            "'python -m nth_dao.web --lan')."
        )
    }
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

$pythonArgs = @()
if ((Split-Path -Leaf $fileName).ToLowerInvariant() -eq "py.exe") {
    $pythonArgs += "-3"
}
$pythonArgs += @("-m", "nth_dao.web")

$ServerProcess = Start-Process `
    -FilePath $fileName `
    -ArgumentList $pythonArgs `
    -WorkingDirectory $RepoRoot `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -WindowStyle Hidden `
    -PassThru

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if (Test-NthDaoHealth) {
        Start-Process $ConsoleUrl
        return
    }
}

if (-not $ServerProcess.HasExited) {
    Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue
}
throw (
    "NTH DAO did not become LAN-ready within 30 seconds; the process started " +
    "by this launcher was stopped. Logs: $OutLog ; $ErrLog"
)
