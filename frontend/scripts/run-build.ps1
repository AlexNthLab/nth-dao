$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$tsc = Join-Path $root "node_modules\typescript\bin\tsc"
$vite = Join-Path $root "node_modules\vite\bin\vite.js"

foreach ($entry in @($tsc, $vite)) {
    if (-not (Test-Path $entry)) {
        throw "Build entrypoint not found at $entry. Run npm install first."
    }
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

& $node $tsc
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $node $vite build
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

# Vite preserves template newlines around injected asset tags. On Windows this
# can produce mixed CRLF/LF output and even a stray CR before </div>, making
# generated release artifacts fail git diff --check. Normalize HTML only after
# a successful build; JavaScript and CSS bundles remain byte-for-byte intact.
$staticRoot = Join-Path (Split-Path -Parent $root) "nth_dao\web\static"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
Get-ChildItem -LiteralPath $staticRoot -Filter "*.html" -File | ForEach-Object {
    $content = [System.IO.File]::ReadAllText($_.FullName)
    $normalized = $content.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText($_.FullName, $normalized, $utf8NoBom)
}

exit 0
