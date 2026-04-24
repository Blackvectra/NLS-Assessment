#Requires -Version 7.0
<#
.SYNOPSIS
    NextLayerSec Portfolio Summary
    Aggregates all tenant assessment reports into a single cross-tenant view.

.DESCRIPTION
    Reads all assessment reports in the output directory and produces a
    ranked summary showing all managed tenants by gap count, with a
    breakdown of controls passing and failing across the portfolio.

    Run this after completing assessments across multiple tenants to get
    a portfolio-level view of which clients need the most attention.

.PARAMETER OutputDir
    Path to the output directory containing tenant reports.
    Defaults to .\output relative to script location.

.PARAMETER OutputPath
    Path for the summary report. Defaults to .\output\NLS-Portfolio-<date>.md

.EXAMPLE
    .\Invoke-NLSSummary.ps1

.EXAMPLE
    .\Invoke-NLSSummary.ps1 -OutputDir "C:\Assessments\output"

.NOTES
    Author:  NextLayerSec
    Version: 2.1.0
    License: CC BY-ND 4.0
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if (-not $OutputDir) { $OutputDir = Join-Path $scriptDir 'output' }
if (-not (Test-Path $OutputDir)) {
    Write-Host "[!] Output directory not found: $OutputDir" -ForegroundColor Red
    Write-Host "    Run assessments first to generate reports." -ForegroundColor Gray
    exit 1
}

$dateStamp  = (Get-Date).ToString('yyyyMMdd')
if (-not $OutputPath) { $OutputPath = Join-Path $OutputDir "NLS-Portfolio-$dateStamp.md" }

Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host '  NextLayerSec Portfolio Summary' -ForegroundColor White
Write-Host '  nextlayersec.io' -ForegroundColor DarkGray
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host ''

# ── Discover reports ─────────────────────────────────────────
$reportFiles = Get-ChildItem -Path $OutputDir -Filter '*.md' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -notmatch '-exceptions' -and
        $_.Name -notmatch 'NLS-Portfolio'
    } |
    Sort-Object LastWriteTime -Descending

# For each tenant keep only the most recent report
$latestByTenant = [ordered]@{}
foreach ($file in $reportFiles) {
    # Extract tenant name -- everything before the last date segment
    if ($file.BaseName -match '^(.+)-\d{8}$') {
        $tenant = $Matches[1]
        if (-not $latestByTenant.Contains($tenant)) {
            $latestByTenant[$tenant] = $file
        }
    }
}

if ($latestByTenant.Count -eq 0) {
    Write-Host "[!] No tenant reports found in: $OutputDir" -ForegroundColor Yellow
    Write-Host "    Run .\Invoke-NLSAssessment.ps1 against one or more tenants first." -ForegroundColor Gray
    exit 0
}

Write-Host "[-] Found $($latestByTenant.Count) tenant report(s)" -ForegroundColor DarkGray
Write-Host ''

# ── Parse each report ────────────────────────────────────────
$tenantResults = @()

foreach ($tenant in $latestByTenant.Keys) {
    $file    = $latestByTenant[$tenant]
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    # Extract summary counts from markdown table
    $gap       = if ($content -match '\| Gap\s*\|\s*(\d+)') { [int]$Matches[1] } else { 0 }
    $partial   = if ($content -match '\| Partial\s*\|\s*(\d+)') { [int]$Matches[1] } else { 0 }
    $satisfied = if ($content -match '\| Satisfied\s*\|\s*(\d+)') { [int]$Matches[1] } else { 0 }
    $total     = if ($content -match '\|\s*\*\*Total Checks\*\*\s*\|\s*\*\*(\d+)\*\*') { [int]$Matches[1] } else { 0 }

    # Extract date from filename
    $reportDate = if ($file.BaseName -match '(\d{8})$') { $Matches[1] } else { 'Unknown' }
    $reportDate = if ($reportDate -ne 'Unknown') {
        [datetime]::ParseExact($reportDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd')
    } else { 'Unknown' }

    # Extract frameworks active
    $frameworks = if ($content -match '\| Frameworks Active\s*\|\s*(.+?)\s*\|') { $Matches[1].Trim() } else { 'Unknown' }

    # Risk score -- weight gaps higher than partials
    $riskScore = ($gap * 2) + $partial

    $tenantResults += [ordered]@{
        Tenant     = $tenant.ToUpper()
        Gap        = $gap
        Partial    = $partial
        Satisfied  = $satisfied
        Total      = $total
        RiskScore  = $riskScore
        ReportDate = $reportDate
        Frameworks = $frameworks
        ReportFile = $file.Name
    }

    Write-Host "  [+] $($tenant.ToUpper()) -- Gap: $gap  Partial: $partial  Satisfied: $satisfied" -ForegroundColor DarkGray
}

# Sort by risk score descending
$tenantResults = $tenantResults | Sort-Object { $_.RiskScore } -Descending

# ── Generate report ──────────────────────────────────────────
$sb = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine('# NextLayerSec Portfolio Summary')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('> Cross-tenant assessment summary. Tenants ranked by risk score.')
[void]$sb.AppendLine('> Risk Score = (Gap x 2) + Partial. Higher score = more exposure.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("**Generated:** $((Get-Date).ToString('yyyy-MM-dd HH:mm')) UTC")
[void]$sb.AppendLine("**Tenants Assessed:** $($tenantResults.Count)")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# ── Portfolio overview table ──────────────────────────────────
[void]$sb.AppendLine('## Tenant Rankings')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Rank | Tenant | Risk Score | Gap | Partial | Satisfied | Total | Last Assessment |')
[void]$sb.AppendLine('|:---:|---|:---:|:---:|:---:|:---:|:---:|---|')

$rank = 1
foreach ($t in $tenantResults) {
    $riskColor = if ($t.RiskScore -gt 10) { '🔴' } elseif ($t.RiskScore -gt 5) { '🟡' } else { '🟢' }
    [void]$sb.AppendLine("| $rank | $($t.Tenant) | $riskColor $($t.RiskScore) | $($t.Gap) | $($t.Partial) | $($t.Satisfied) | $($t.Total) | $($t.ReportDate) |")
    $rank++
}

[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# ── Portfolio totals ──────────────────────────────────────────
$totalGap       = ($tenantResults | Measure-Object -Property Gap -Sum).Sum
$totalPartial   = ($tenantResults | Measure-Object -Property Partial -Sum).Sum
$totalSatisfied = ($tenantResults | Measure-Object -Property Satisfied -Sum).Sum
$totalChecks    = ($tenantResults | Measure-Object -Property Total -Sum).Sum

[void]$sb.AppendLine('## Portfolio Totals')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| State | Count | Percentage |')
[void]$sb.AppendLine('|---|:---:|:---:|')
$gapPct  = if ($totalChecks -gt 0) { [math]::Round(($totalGap / $totalChecks) * 100, 1) } else { 0 }
$partPct = if ($totalChecks -gt 0) { [math]::Round(($totalPartial / $totalChecks) * 100, 1) } else { 0 }
$satPct  = if ($totalChecks -gt 0) { [math]::Round(($totalSatisfied / $totalChecks) * 100, 1) } else { 0 }
[void]$sb.AppendLine("| Gap | $totalGap | $gapPct% |")
[void]$sb.AppendLine("| Partial | $totalPartial | $partPct% |")
[void]$sb.AppendLine("| Satisfied | $totalSatisfied | $satPct% |")
[void]$sb.AppendLine("| **Total Checks** | **$totalChecks** | |")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')

# ── Per-tenant detail ─────────────────────────────────────────
[void]$sb.AppendLine('## Tenant Detail')
[void]$sb.AppendLine('')

$rank = 1
foreach ($t in $tenantResults) {
    [void]$sb.AppendLine("### $rank. $($t.Tenant)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Field | Value |")
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| Risk Score | $($t.RiskScore) |")
    [void]$sb.AppendLine("| Gap | $($t.Gap) |")
    [void]$sb.AppendLine("| Partial | $($t.Partial) |")
    [void]$sb.AppendLine("| Satisfied | $($t.Satisfied) |")
    [void]$sb.AppendLine("| Total Checks | $($t.Total) |")
    [void]$sb.AppendLine("| Frameworks | $($t.Frameworks) |")
    [void]$sb.AppendLine("| Last Assessment | $($t.ReportDate) |")
    [void]$sb.AppendLine("| Report File | $($t.ReportFile) |")
    [void]$sb.AppendLine('')
    $rank++
}

[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('*Generated by NextLayerSec M365 Assessment Framework -- nextlayersec.io*')

# Write report
$sb.ToString() | Out-File -FilePath $OutputPath -Encoding utf8 -Force

Write-Host ''
Write-Host "  Portfolio summary written to: $OutputPath" -ForegroundColor Cyan
Write-Host ''

# Auto-open in VS Code if available
$vsCode = Get-Command code -ErrorAction SilentlyContinue
if ($vsCode) {
    Write-Host '[-] Opening portfolio summary in VS Code...' -ForegroundColor DarkGray
    & code $OutputPath
}
