param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $VitestArgs
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$vitest = Join-Path $root "node_modules\vitest\vitest.mjs"

if (-not (Test-Path $vitest)) {
    throw "Vitest entrypoint not found at $vitest. Run npm install first."
}

$candidates = @()
if ($env:NTH_DAO_NODE) {
    $candidates += $env:NTH_DAO_NODE
}
$candidates += @(
    "C:\Program Files\nodejs\node.exe",
    "$env:LOCALAPPDATA\Programs\nodejs\node.exe"
)

$pathNode = Get-Command node.exe -All -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -and ($_.Source -notlike "*\WindowsApps\*") } |
    Select-Object -First 1 -ExpandProperty Source
if ($pathNode) {
    $candidates += $pathNode
}

$node = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $node) {
    throw "Could not find a usable node.exe. Set NTH_DAO_NODE to an absolute node.exe path."
}

if (-not $VitestArgs) {
    $VitestArgs = @()
}

$resolvedArgs = [System.Collections.Generic.List[string]]::new()
foreach ($arg in $VitestArgs) {
    $resolvedArgs.Add($arg)
}

$lowerArgs = @($resolvedArgs | ForEach-Object { $_.ToLowerInvariant() })
$hasMode = $lowerArgs | Where-Object {
    $_ -in @("run", "--run", "watch", "dev", "related")
}
if (-not $hasMode) {
    $resolvedArgs.Insert(0, "run")
}

$hasEnvironment = $lowerArgs | Where-Object {
    $_ -eq "--environment" -or $_.StartsWith("--environment=")
}
if (-not $hasEnvironment) {
    $resolvedArgs.Add("--environment")
    $resolvedArgs.Add("jsdom")
}

# Several jsdom tests intentionally stub globals such as fetch, window,
# timers, and module mocks. Keep file execution deterministic unless the
# caller explicitly chooses a fileParallelism setting.
$hasFileParallelism = $lowerArgs | Where-Object {
    $_ -eq "--fileparallelism" `
        -or $_.StartsWith("--fileparallelism=") `
        -or $_ -eq "--no-file-parallelism"
}
if (-not $hasFileParallelism) {
    $resolvedArgs.Add("--fileParallelism=false")
}

& $node $vitest @resolvedArgs
exit $LASTEXITCODE
