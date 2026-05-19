# Regenerates use-cases-data.js from use-cases.json so file:// and offline opens work.
# Run from repo root or from this directory after editing use-cases.json:
#   pwsh -File docs/hitt/update-bundled-data.ps1

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$jsonPath = Join-Path $here "use-cases.json"
$jsPath = Join-Path $here "use-cases-data.js"
if (-not (Test-Path $jsonPath)) {
  throw "Not found: $jsonPath"
}
$j = Get-Content -Raw -Encoding UTF8 $jsonPath
$out = "/* Generated from use-cases.json - run update-bundled-data.ps1 after editing the JSON. */`r`nwindow.HITT_USE_CASES = " + $j.Trim() + ";`r`n"
[System.IO.File]::WriteAllText($jsPath, $out, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $jsPath"
