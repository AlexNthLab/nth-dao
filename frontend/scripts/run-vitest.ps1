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

if (-not $VitestArgs -or $VitestArgs.Count -eq 0) {
    # Several jsdom tests intentionally stub globals such as fetch, window,
    # timers, and module mocks. Running test files in parallel lets those
    # globals bleed across files in Vitest's shared worker context, producing
    # order-dependent false negatives. Keep frontend verification deterministic
    # by default; callers can still pass their own VitestArgs for local speed.
    $VitestArgs = @("run", "--environment", "jsdom", "--fileParallelism=false")
}

& $node $vitest @VitestArgs
exit $LASTEXITCODE
