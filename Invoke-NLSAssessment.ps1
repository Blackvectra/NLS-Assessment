#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    NextLayerSec Control-Plane Assessor v2
    Read-only M365 security assessment instrument.

.DESCRIPTION
    Connects to Exchange Online and Microsoft Graph, collects security policy
    configuration and sign-in telemetry, scores findings against the NextLayerSec
    baseline, and produces structured markdown artifacts mapped to authoritative
    compliance frameworks.

    No tenant configuration changes are made at any point.

.PARAMETER UserPrincipalName
    Admin UPN used to authenticate to Exchange Online and Microsoft Graph.

.PARAMETER SkipConnect
    Skip connection step if already connected to Exchange Online and Graph.

.PARAMETER Quick
    Skip sign-in log telemetry collection. Faster run.

.PARAMETER NoTelemetry
    Explicitly skip telemetry collection. Same as -Quick.

.PARAMETER NoGraph
    Skip Microsoft Graph entirely. Exchange Online checks only.
    No Graph modules required. No browser consent prompt.

.PARAMETER NIST
    Include NIST SP 800-53 Rev 5 citations. Default when no framework flag passed.

.PARAMETER CIS
    Include CIS Controls v8.1 citations.

.PARAMETER HIPAA
    Include HIPAA Security Rule current enforceable rule citations.

.PARAMETER HIPAAProposed
    Include HIPAA NPRM December 2024 proposed rule citations.
    Use with -HIPAA for dual-state gap analysis. Expected final rule May 2026.

.PARAMETER ZeroTrust
    Include CISA Zero Trust Maturity Model mapping in findings.
    Adds ZT-specific checks for Identity and Devices pillars.

.PARAMETER SecureScore
    Pull Microsoft Secure Score and per-control recommendations from Graph.
    Adds Secure Score section to the report with top improvement opportunities.

.PARAMETER MFAReport
    Pull per-user MFA registration status from Graph.
    Surfaces exactly which users have no MFA registered.
    Requires Reports.Read.All scope.

.PARAMETER RedactSensitiveData
    Scrub UPNs, GUIDs, and IP addresses from all output files.

.PARAMETER OpenReport
    Auto-open AssessmentSummary.md on completion.

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -NIST

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -SecureScore -MFAReport -RedactSensitiveData

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed -ZeroTrust -SecureScore -MFAReport

.NOTES
    Author:   NextLayerSec
    Version:  2.0.0
    Requires: PowerShell 7+
              ExchangeOnlineManagement
              Microsoft.Graph (full SDK)
    License:  CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/

    Graph scopes:
      Policy.Read.ConditionalAccess     -- CA policy collection
      Directory.Read.All                -- Graph directory access
      AuditLog.Read.All                 -- Sign-in log telemetry (Full mode)
      Reports.Read.All                  -- User MFA registration (-MFAReport)
      SecurityEvents.Read.All           -- Secure Score (-SecureScore)
#>

[CmdletBinding(DefaultParameterSetName = 'Full')]
param (
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnect,

    [Parameter(ParameterSetName = 'Quick')]
    [switch]$Quick,

    [Parameter(ParameterSetName = 'Full')]
    [switch]$Full,

    [Parameter(Mandatory = $false)]
    [switch]$NoTelemetry,

    [Parameter(Mandatory = $false)]
    [switch]$NoGraph,

    # ── Framework routing flags ───────────────────────────────
    [Parameter(Mandatory = $false)]
    [switch]$NIST,

    [Parameter(Mandatory = $false)]
    [switch]$CIS,

    [Parameter(Mandatory = $false)]
    [switch]$HIPAA,

    [Parameter(Mandatory = $false)]
    [switch]$HIPAAProposed,

    [Parameter(Mandatory = $false)]
    [switch]$ZeroTrust,
    # ─────────────────────────────────────────────────────────

    # ── v2 feature flags ─────────────────────────────────────
    [Parameter(Mandatory = $false)]
    [switch]$SecureScore,

    [Parameter(Mandatory = $false)]
    [switch]$MFAReport,

    [Parameter(Mandatory = $false)]
    [switch]$OpenReport,
    # ─────────────────────────────────────────────────────────

    [Parameter(Mandatory = $false)]
    [switch]$RedactSensitiveData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────
# Hard Runtime Safeguard Banner
# ─────────────────────────────────────────────

Write-Host ''
Write-Host '================================================================' -ForegroundColor DarkRed
Write-Host ' READ-ONLY ASSESSMENT INSTRUMENT' -ForegroundColor Red
Write-Host ' - No tenant configuration changes will be made.' -ForegroundColor Gray
Write-Host ' - Results depend on RBAC, licensing, and API visibility.' -ForegroundColor Gray
Write-Host ' - Missing telemetry is NOT equivalent to missing policy.' -ForegroundColor Gray
Write-Host ' - Do not run against production tenants without authorization.' -ForegroundColor Gray
Write-Host '================================================================' -ForegroundColor DarkRed
Write-Host ''

# ─────────────────────────────────────────────
# Operator Mode Resolution
# ─────────────────────────────────────────────

$runTelemetry  = -not ($Quick -or $NoTelemetry -or $NoGraph)
$runGraph      = -not $NoGraph
$runRedaction  = [bool]$RedactSensitiveData
$runSecScore   = [bool]$SecureScore -and $runGraph
$runMFAReport  = [bool]$MFAReport -and $runGraph

Write-Host '[*] Execution Mode: ' -NoNewline -ForegroundColor Cyan
if ($NoGraph) {
    Write-Host 'EXCHANGE ONLY (No Graph) ' -NoNewline -ForegroundColor Yellow
} elseif ($Quick -or $NoTelemetry) {
    Write-Host 'QUICK (No Telemetry) ' -NoNewline -ForegroundColor Yellow
} else {
    Write-Host 'FULL ' -NoNewline -ForegroundColor Green
}
if ($runRedaction) { Write-Host '| REDACTED OUTPUT ' -NoNewline -ForegroundColor Magenta }
Write-Host ''

Write-Host '[*] Frameworks: ' -NoNewline -ForegroundColor Cyan
$activeFrameworks = @()
if (-not ($NIST -or $CIS -or $HIPAA -or $HIPAAProposed -or $ZeroTrust)) {
    $activeFrameworks += 'NIST (default)'
} else {
    if ($NIST)          { $activeFrameworks += 'NIST' }
    if ($CIS)           { $activeFrameworks += 'CIS' }
    if ($HIPAA)         { $activeFrameworks += 'HIPAA Current' }
    if ($HIPAAProposed) { $activeFrameworks += 'HIPAA Proposed' }
    if ($ZeroTrust)     { $activeFrameworks += 'Zero Trust' }
}
Write-Host ($activeFrameworks -join ', ') -ForegroundColor White

Write-Host '[*] Features: ' -NoNewline -ForegroundColor Cyan
$activeFeatures = @()
if ($runSecScore)  { $activeFeatures += 'Secure Score' }
if ($runMFAReport) { $activeFeatures += 'MFA Report' }
if ($activeFeatures.Count -gt 0) {
    Write-Host ($activeFeatures -join ', ') -ForegroundColor White
} else {
    Write-Host 'Standard' -ForegroundColor White
}
Write-Host ''

# ─────────────────────────────────────────────
# Prerequisite Validation
# ─────────────────────────────────────────────

Write-Host '[-] Validating prerequisites...' -ForegroundColor DarkGray

$requiredModules = @('ExchangeOnlineManagement')
if ($runGraph) {
    $requiredModules += 'Microsoft.Graph.Authentication'
    if ($runTelemetry) { $requiredModules += 'Microsoft.Graph.Identity.SignIns' }
}

$missingModules = foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) { $mod }
}

if ($missingModules) {
    Write-Host "[!] Missing required modules: $($missingModules -join ', ')" -ForegroundColor Red
    Write-Host ''
    Write-Host '    Install with:' -ForegroundColor Gray
    foreach ($mod in $missingModules) {
        Write-Host "    Install-Module -Name $mod -Scope CurrentUser -Force" -ForegroundColor Gray
    }
    Write-Host ''
    exit 1
}

Write-Host '  [+] All required modules present' -ForegroundColor Green

# ─────────────────────────────────────────────
# Module Loading
# ─────────────────────────────────────────────

$scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$modulesDir = Join-Path $scriptDir 'Modules'

if (-not (Test-Path $modulesDir)) {
    Write-Host "[!] Modules directory not found at: $modulesDir" -ForegroundColor Red
    exit 1
}

$moduleFiles = Get-ChildItem -Path $modulesDir -Filter '*.psm1' -ErrorAction Stop
if ($moduleFiles.Count -eq 0) {
    Write-Host '[!] No .psm1 files found in Modules directory' -ForegroundColor Red
    exit 1
}

foreach ($mod in $moduleFiles) {
    try {
        Import-Module $mod.FullName -Force -ErrorAction Stop
        Write-Host "  [+] Loaded: $($mod.Name)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [!] Failed to load module $($mod.Name): $_" -ForegroundColor Red
        exit 1
    }
}

# ─────────────────────────────────────────────
# Output Directory Setup
# ─────────────────────────────────────────────

$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$outDir    = Join-Path $scriptDir "output\$timestamp"

try {
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    Write-Host "  [+] Output directory: $outDir" -ForegroundColor DarkGray
} catch {
    Write-Host "[!] Failed to create output directory: $_" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────
# Connection Bootstrap
# ─────────────────────────────────────────────

if (-not $SkipConnect) {
    $upn = if ($UserPrincipalName) { $UserPrincipalName } else { Read-Host 'Enter Admin UPN' }

    Write-Host ''
    Write-Host '[-] Establishing read-only connections...' -ForegroundColor DarkGray

    try {
        Connect-ExchangeOnline -UserPrincipalName $upn -ShowBanner:$false -ErrorAction Stop
        Write-Host '  [+] Exchange Online connected' -ForegroundColor Green
    } catch {
        Write-Host "  [!] Exchange Online connection failed: $_" -ForegroundColor Red
        exit 1
    }

    if ($runGraph) {
        $graphScopes = @(
            'Policy.Read.ConditionalAccess',
            'Directory.Read.All'
        )
        if ($runTelemetry)  { $graphScopes += 'AuditLog.Read.All' }
        if ($runMFAReport)  { $graphScopes += 'Reports.Read.All' }
        if ($runSecScore)   { $graphScopes += 'SecurityEvents.Read.All' }

        try {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
            Write-Host '  [+] Microsoft Graph connected' -ForegroundColor Green
        } catch {
            Write-Host "  [!] Microsoft Graph connection failed: $_" -ForegroundColor Red
            Write-Host '      Conditional Access checks will be unavailable.' -ForegroundColor Yellow
        }
    } else {
        Write-Host '  [!] Graph skipped (-NoGraph). Exchange Online only.' -ForegroundColor Yellow
    }
}

Write-Host ''

# ─────────────────────────────────────────────
# Data Collection
# ─────────────────────────────────────────────

Write-Host '[-] Collecting Exchange Online policies...' -ForegroundColor DarkGray
$exchangeResults = Get-NLSExchangePolicies -Redact $runRedaction

$caResults          = @{}
$caTelemetryResults = @{}
$mfaStatusResults   = @{}
$secureScoreResults = @{}

if ($runGraph) {
    Write-Host '[-] Collecting Conditional Access policies...' -ForegroundColor DarkGray
    $caResults = Get-NLSConditionalAccessPolicies -Redact $runRedaction

    if ($runTelemetry) {
        Write-Host '[-] Collecting sign-in log telemetry...' -ForegroundColor DarkGray
        $caTelemetryResults = Get-NLSConditionalAccessTelemetry -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' `
            -Status 'NotCollected' -Reason 'Operator specified -Quick or -NoTelemetry'
        Write-Host '  [!] Telemetry skipped (Quick/NoTelemetry mode)' -ForegroundColor Yellow
    }

    if ($runMFAReport) {
        Write-Host '[-] Collecting user MFA registration status...' -ForegroundColor DarkGray
        $mfaStatusResults = Get-NLSUserMFAStatus -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'UserMFAStatus' `
            -Status 'NotCollected' -Reason 'Operator did not pass -MFAReport flag'
    }

    if ($runSecScore) {
        Write-Host '[-] Collecting Microsoft Secure Score...' -ForegroundColor DarkGray
        $secureScoreResults = Get-NLSSecureScore -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'SecureScore' `
            -Status 'NotCollected' -Reason 'Operator did not pass -SecureScore flag'
    }
} else {
    Register-NLSCoverage -ControlFamily 'ConditionalAccess' `
        -Status 'NotCollected' -Reason 'Operator specified -NoGraph'
    Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' `
        -Status 'NotCollected' -Reason 'Operator specified -NoGraph'
    Register-NLSCoverage -ControlFamily 'UserMFAStatus' `
        -Status 'NotCollected' -Reason 'Operator specified -NoGraph'
    Register-NLSCoverage -ControlFamily 'SecureScore' `
        -Status 'NotCollected' -Reason 'Operator specified -NoGraph'
    Write-Host '  [!] CA and Graph checks skipped (-NoGraph mode)' -ForegroundColor Yellow
}

Write-Host '[-] Collecting metadata...' -ForegroundColor DarkGray
$metadata = Get-NLSMetadata -Redact $runRedaction

Write-Host ''

# ─────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────

Write-Host '[-] Applying scoring model...' -ForegroundColor DarkGray

$allResults = @{
    ExchangePolicies           = $exchangeResults
    ConditionalAccess          = $caResults
    ConditionalAccessTelemetry = $caTelemetryResults
}

$scoringParams = @{
    Results      = $allResults
    Redact       = $runRedaction
    ZeroTrust    = [bool]$ZeroTrust
}

if ($PSBoundParameters.ContainsKey('NIST'))          { $scoringParams.NIST          = $NIST.IsPresent }
if ($PSBoundParameters.ContainsKey('CIS'))           { $scoringParams.CIS           = $CIS.IsPresent }
if ($PSBoundParameters.ContainsKey('HIPAA'))         { $scoringParams.HIPAA         = $HIPAA.IsPresent }
if ($PSBoundParameters.ContainsKey('HIPAAProposed')) { $scoringParams.HIPAAProposed = $HIPAAProposed.IsPresent }

$scoredResults = Invoke-NLSScoringModel @scoringParams

Write-Host ''

# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────

Write-Host '[-] Generating assessment artifacts...' -ForegroundColor DarkGray

$summaryPath    = Join-Path $outDir 'AssessmentSummary.md'
$exceptionsPath = Join-Path $outDir 'Exceptions.md'

# Build extended data for reporting
$extendedData = @{}
if ($caResults -and $caResults['ConditionalAccess']) {
    $extendedData['ConditionalAccess'] = $caResults['ConditionalAccess']
}
if ($mfaStatusResults -and $mfaStatusResults['UserMFAStatus']) {
    $extendedData['UserMFAStatus'] = $mfaStatusResults['UserMFAStatus']
}
if ($secureScoreResults -and $secureScoreResults['SecureScore']) {
    $extendedData['SecureScore'] = $secureScoreResults['SecureScore']
}

Publish-NLSAssessmentSummary `
    -ScoredResults $scoredResults `
    -Metadata $metadata `
    -Coverage (Get-NLSCoverageMap) `
    -OutputPath $summaryPath `
    -ExtendedData $extendedData `
    -Redact $runRedaction

$exceptions = Get-NLSExceptions
if ($null -eq $exceptions) { $exceptions = @() }

Publish-NLSExceptionsList `
    -Exceptions $exceptions `
    -OutputPath $exceptionsPath `
    -Redact $runRedaction

# ─────────────────────────────────────────────
# Summary Output
# ─────────────────────────────────────────────

$s = $scoredResults.Summary

Write-Host ''
Write-Host '================================================================' -ForegroundColor DarkGray
Write-Host '  Assessment Complete' -ForegroundColor White
Write-Host '================================================================' -ForegroundColor DarkGray
Write-Host "  Satisfied  $($s.Satisfied)" -ForegroundColor Green
Write-Host "  Partial    $($s.Partial)"   -ForegroundColor $(if ($s.Partial -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Gap        $($s.Gap)"       -ForegroundColor $(if ($s.Gap -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Total      $($s.Total)"     -ForegroundColor White
Write-Host ''
Write-Host "  Artifacts: $outDir" -ForegroundColor Cyan
Write-Host ''

# Auto-open report if -OpenReport flag passed
if ($OpenReport) {
    $reportFile = Join-Path $outDir 'AssessmentSummary.md'
    if (Test-Path $reportFile) {
        Write-Host '[-] Opening assessment report...' -ForegroundColor DarkGray
        Start-Process $reportFile
    }
}

# ─────────────────────────────────────────────
# Disconnect
# ─────────────────────────────────────────────

if (-not $SkipConnect) {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        if ($runGraph) { Disconnect-MgGraph -ErrorAction SilentlyContinue }
        Write-Host '[-] Sessions disconnected.' -ForegroundColor DarkGray
    } catch { }
}

Write-Host ''
