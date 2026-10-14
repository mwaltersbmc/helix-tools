# Extract AR_SERVER_INFO_* constants from Constants.java and emit JSON for hitt.sh.
#
# Default source: GitHub API (private repo — set GITHUB_TOKEN or GH_TOKEN).
# Local file override: -JavaPath path\to\Constants.java (relative paths are under helix-tools repo root).
#
# Run from any directory using this script's path:
#   pwsh -File path\to\helix-tools\scripts\gen-ar-server-info-json.ps1 -OutPath ar-server-info.json
#   bash path/to/helix-tools/scripts/embed-hitt-ar-server-info.sh ar-server-info.json
param(
    [string]$JavaPath = "",
    [string]$OutPath = "",
    [string]$GitHubOwner = "RemedyPlatform",
    [string]$GitHubRepo = "ars-serverj",
    [string]$GitHubRef = "10R",
    [string]$GitHubConstantsPath = "domain/src/main/java/com/bmc/arsys/domain/constants/Constants.java",
    [string]$GitHubToken = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Resolve-RepoPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $RepoRoot $Path)
}

$pattern = 'public\s+(?:static\s+final|final\s+static)\s+int\s+(AR_SERVER_INFO_\w+)\s*=\s*(-?\d+)\s*;'

function Get-ConstantsJavaTextFromGitHub {
    param(
        [string]$Owner,
        [string]$Repo,
        [string]$Ref,
        [string]$FilePath,
        [string]$Token
    )
    if (-not $Token) {
        $Token = $env:GITHUB_TOKEN
    }
    if (-not $Token) {
        $Token = $env:GH_TOKEN
    }
    if (-not $Token) {
        throw "GitHub authentication required. Set GITHUB_TOKEN or GH_TOKEN (repo scope for RemedyPlatform/ars-serverj), or pass -JavaPath to a local Constants.java."
    }

    $uri = "https://api.github.com/repos/$Owner/$Repo/contents/$FilePath?ref=$([Uri]::EscapeDataString($Ref))"
    $headers = @{
        Authorization       = "Bearer $Token"
        Accept              = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    } catch {
        throw "GitHub API request failed for $Owner/$Repo@${Ref}: $($_.Exception.Message)"
    }

    if (-not $response.content) {
        throw "GitHub API returned no file content (check path, ref, and token access to $Owner/$Repo)."
    }

    $b64 = ($response.content -replace "`n", "").Trim()
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
}

function Get-ArServerInfoConstantsFromJavaText {
    param([string]$JavaText)
    $byName = [ordered]@{}
    $JavaText -split "`n" | ForEach-Object {
        if ($_ -match $pattern) {
            $byName[$Matches[1]] = [int]$Matches[2]
        }
    }
    if ($byName.Count -eq 0) {
        throw "No AR_SERVER_INFO_* constants found in Constants.java"
    }
    return $byName
}

if ($JavaPath) {
    $JavaPath = Resolve-RepoPath $JavaPath
}
if ($OutPath) {
    $OutPath = Resolve-RepoPath $OutPath
}

if ($JavaPath -and (Test-Path -LiteralPath $JavaPath)) {
    $javaText = Get-Content -LiteralPath $JavaPath -Raw -Encoding UTF8
    $sourceLabel = $JavaPath
} else {
    if ($JavaPath) {
        Write-Warning "Local file not found: $JavaPath — fetching from GitHub instead."
    }
    $javaText = Get-ConstantsJavaTextFromGitHub -Owner $GitHubOwner -Repo $GitHubRepo -Ref $GitHubRef `
        -FilePath $GitHubConstantsPath -Token $GitHubToken
    $sourceLabel = "github.com/$GitHubOwner/$GitHubRepo@$GitHubRef/$GitHubConstantsPath"
}

$byName = Get-ArServerInfoConstantsFromJavaText -JavaText $javaText

$items = [System.Collections.Generic.List[object]]::new()
foreach ($entry in ($byName.GetEnumerator() | Sort-Object { $_.Value }, { $_.Name })) {
    $items.Add([ordered]@{ name = $entry.Name; id = $entry.Value })
}

$json = $items | ConvertTo-Json -Depth 3 -Compress
if ($OutPath) {
    [System.IO.File]::WriteAllText($OutPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Wrote $OutPath ($($byName.Count) name:id pairs from $sourceLabel)"
} else {
    Write-Output $json
}
