# Convert an xWiki HTML export to Markdown for docs/checklists/.
param(
    [Parameter(Mandatory = $true)]
    [string]$InputHtml,

    [Parameter(Mandatory = $true)]
    [string]$OutputMd,

    [string]$SourceUrl = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$inputPath = if ([System.IO.Path]::IsPathRooted($InputHtml)) { $InputHtml } else { Join-Path $repoRoot $InputHtml }
$outputPath = if ([System.IO.Path]::IsPathRooted($OutputMd)) { $OutputMd } else { Join-Path $repoRoot $OutputMd }

if (-not (Test-Path -LiteralPath $inputPath)) {
    Write-Error "Input HTML not found: $inputPath"
}

$content = Get-Content -LiteralPath $inputPath -Raw -Encoding UTF8
if ($content -match 'BMCHelix - Sign In|Sign in with your account to access xWiki') {
    Write-Error "Input looks like an Okta login page, not wiki content. Export the page while logged in and try again."
}

Push-Location $repoRoot
try {
    npx --yes -p node-html-markdown -c "import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'; import { dirname, resolve } from 'node:path'; import { NodeHtmlMarkdown } from 'node-html-markdown'; const [inputPath, outputPath, sourceUrl] = process.argv.slice(2); let html = readFileSync(inputPath, 'utf8'); const bodyMatch = html.match(/<div[^>]+id=\"xwikicontent\"[^>]*>([\s\S]*?)<\/div>\s*<\/div>\s*<\/main>/i); if (bodyMatch) html = bodyMatch[1]; const md = NodeHtmlMarkdown.translate(html).replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim(); const header = sourceUrl ? '> Source: [Helix xWiki](' + sourceUrl + ')\n\n' : ''; mkdirSync(dirname(resolve(outputPath)), { recursive: true }); writeFileSync(outputPath, header + md + '\n', 'utf8');" -- $inputPath $outputPath $SourceUrl | Out-Null
}
finally {
    Pop-Location
}

Write-Host "Wrote $outputPath"
