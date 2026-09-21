# Extract AR_SERVER_INFO_* constants from Constants.java and emit JSON for hitt.sh.
# Regenerate and embed:
#   pwsh -File scripts/gen-ar-server-info-json.ps1 | bash scripts/embed-hitt-ar-server-info.sh
param(
    [string]$JavaPath = "w:\ars-serverj\domain\src\main\java\com\bmc\arsys\domain\constants\Constants.java",
    [string]$OutPath = ""
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $JavaPath)) {
    throw "Not found: $JavaPath"
}

$pattern = 'public\s+(?:static\s+final|final\s+static)\s+int\s+(AR_SERVER_INFO_\w+)\s*=\s*(-?\d+)\s*;'
$byName = [ordered]@{}
Get-Content -LiteralPath $JavaPath -Encoding UTF8 | ForEach-Object {
    if ($_ -match $pattern) {
        $byName[$Matches[1]] = [int]$Matches[2]
    }
}
if ($byName.Count -eq 0) {
    throw "No AR_SERVER_INFO_* constants found in $JavaPath"
}

$items = [System.Collections.Generic.List[object]]::new()
foreach ($entry in ($byName.GetEnumerator() | Sort-Object { $_.Value }, { $_.Name })) {
    $items.Add([ordered]@{ name = $entry.Name; id = $entry.Value })
}

$json = $items | ConvertTo-Json -Depth 3 -Compress
if ($OutPath) {
    [System.IO.File]::WriteAllText($OutPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Wrote $OutPath ($($byName.Count) name:id pairs)"
} else {
    Write-Output $json
}
