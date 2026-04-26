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

    # ── Profile flag ─────────────────────────────────────────
    # Predefined bundles of framework and feature flags.
    # Individual flags can be added on top of a profile.
    # Profile is applied first, then any explicit flags override.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Quick', 'Standard', 'HIPAA', 'MSP', 'ZeroTrust', 'Full')]
    [string]$P,
    # ─────────────────────────────────────────────────────────

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

    [Parameter(Mandatory = $false)]
    [string]$Compare,       # Manual path to previous report for delta comparison

    [Parameter(Mandatory = $false)]
    [switch]$AdminRoles,        # Admin role inventory and over-privilege detection

    [Parameter(Mandatory = $false)]
    [switch]$StaleAccounts,     # Accounts inactive 90+ days

    [Parameter(Mandatory = $false)]
    [switch]$GuestInventory,    # External guest account inventory

    [Parameter(Mandatory = $false)]
    [switch]$NamedLocations,    # Named location definition check

    [Parameter(Mandatory = $false)]
    [switch]$ServicePrincipals, # High-privilege service principal inventory

    [Parameter(Mandatory = $false)]
    [switch]$DMARC,             # DMARC policy state per domain

    [Parameter(Mandatory = $false)]
    [switch]$DNSRecords,        # Live DNS lookup -- SPF, DMARC, DKIM records per domain

    [Parameter(Mandatory = $false)]
    [switch]$MailFlowHardening, # MTA-STS, inbound spam, malware filter checks

    [Parameter(Mandatory = $false)]
    [switch]$IdentityHardening, # Security defaults, SSPR, auth methods, consent, PIM

    [Parameter(Mandatory = $false)]
    [switch]$BreakGlass,        # Break-glass account configuration check

    [Parameter(Mandatory = $false)]
    [switch]$SharedMailboxes,   # Shared mailbox hardening check
    # ─────────────────────────────────────────────────────────

    [Parameter(Mandatory = $false)]
    [switch]$ClearToken,       # Force clear cached Graph token before connecting

    [Parameter(Mandatory = $false)]
    [switch]$GenerateManifest, # Generate SHA-256 hash manifest for module integrity baseline

    [Parameter(Mandatory = $false)]
    [switch]$DebugScoring,      # Surface verbose scoring errors to console during assessment

    [Parameter(Mandatory = $false)]
    [switch]$DebugDNS,          # Trace DNS collection and rendering pipeline

    [Parameter(Mandatory = $false)]
    [switch]$DebugAll,          # Full debug -- all sections, all data, all rendering

    [Parameter(Mandatory = $false)]
    [switch]$RedactSensitiveData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────
# Debug flag expansion
if ($DebugAll) {
    $DebugScoring = $true
    $DebugDNS     = $true
}

# ─────────────────────────────────────────────
# Profile Resolution
# ─────────────────────────────────────────────
# Profiles are applied before individual flags.
# Explicit flags passed alongside a profile are additive.
# Profile sets the baseline -- individual flags expand on top.

if ($P) {
    switch ($P) {

        'Quick' {
            # Exchange only, NIST, no Graph -- fastest run for initial triage
            if (-not $PSBoundParameters.ContainsKey('NoGraph')) { $NoGraph = $true }
            if (-not $PSBoundParameters.ContainsKey('NIST'))    { $NIST    = $true }
        }

        'Standard' {
            # NIST + CIS with full Graph -- general purpose assessment
            if (-not $PSBoundParameters.ContainsKey('NIST')) { $NIST = $true }
            if (-not $PSBoundParameters.ContainsKey('CIS'))  { $CIS  = $true }
        }

        'HIPAA' {
            # Healthcare client -- dual-state HIPAA gap analysis with email auth and MFA
            if (-not $PSBoundParameters.ContainsKey('HIPAA'))         { $HIPAA         = $true }
            if (-not $PSBoundParameters.ContainsKey('HIPAAProposed'))  { $HIPAAProposed = $true }
            if (-not $PSBoundParameters.ContainsKey('DMARC'))          { $DMARC         = $true }
            if (-not $PSBoundParameters.ContainsKey('SharedMailboxes')){ $SharedMailboxes = $true }
            if (-not $PSBoundParameters.ContainsKey('MFAReport'))      { $MFAReport     = $true }
            if (-not $PSBoundParameters.ContainsKey('AdminRoles'))     { $AdminRoles    = $true }
        }

        'MSP' {
            # MSP tenant assessment -- NIST + CIS with tenant hygiene inventory
            if (-not $PSBoundParameters.ContainsKey('NIST'))           { $NIST           = $true }
            if (-not $PSBoundParameters.ContainsKey('CIS'))            { $CIS            = $true }
            if (-not $PSBoundParameters.ContainsKey('AdminRoles'))     { $AdminRoles     = $true }
            if (-not $PSBoundParameters.ContainsKey('StaleAccounts'))  { $StaleAccounts  = $true }
            if (-not $PSBoundParameters.ContainsKey('GuestInventory')) { $GuestInventory = $true }
            if (-not $PSBoundParameters.ContainsKey('DMARC'))          { $DMARC          = $true }
            if (-not $PSBoundParameters.ContainsKey('SharedMailboxes')){ $SharedMailboxes = $true }
            if (-not $PSBoundParameters.ContainsKey('DNSRecords'))     { $DNSRecords      = $true }
            if (-not $PSBoundParameters.ContainsKey('MailFlowHardening')) { $MailFlowHardening = $true }
        }

        'ZeroTrust' {
            # Zero Trust posture assessment -- identity and devices pillars
            if (-not $PSBoundParameters.ContainsKey('NIST'))               { $NIST               = $true }
            if (-not $PSBoundParameters.ContainsKey('ZeroTrust'))          { $ZeroTrust          = $true }
            if (-not $PSBoundParameters.ContainsKey('NamedLocations'))     { $NamedLocations     = $true }
            if (-not $PSBoundParameters.ContainsKey('AdminRoles'))         { $AdminRoles         = $true }
            if (-not $PSBoundParameters.ContainsKey('MFAReport'))          { $MFAReport          = $true }
            if (-not $PSBoundParameters.ContainsKey('ServicePrincipals'))  { $ServicePrincipals  = $true }
            if (-not $PSBoundParameters.ContainsKey('StaleAccounts'))      { $StaleAccounts      = $true }
            if (-not $PSBoundParameters.ContainsKey('IdentityHardening'))  { $IdentityHardening  = $true }
            if (-not $PSBoundParameters.ContainsKey('BreakGlass'))         { $BreakGlass         = $true }
        }

        'Full' {
            # Everything -- all frameworks, all features, all inventory
            if (-not $PSBoundParameters.ContainsKey('NIST'))               { $NIST               = $true }
            if (-not $PSBoundParameters.ContainsKey('CIS'))                { $CIS                = $true }
            if (-not $PSBoundParameters.ContainsKey('HIPAA'))              { $HIPAA              = $true }
            if (-not $PSBoundParameters.ContainsKey('HIPAAProposed'))      { $HIPAAProposed      = $true }
            if (-not $PSBoundParameters.ContainsKey('ZeroTrust'))          { $ZeroTrust          = $true }
            if (-not $PSBoundParameters.ContainsKey('SecureScore'))        { $SecureScore        = $true }
            if (-not $PSBoundParameters.ContainsKey('MFAReport'))          { $MFAReport          = $true }
            if (-not $PSBoundParameters.ContainsKey('AdminRoles'))         { $AdminRoles         = $true }
            if (-not $PSBoundParameters.ContainsKey('StaleAccounts'))      { $StaleAccounts      = $true }
            if (-not $PSBoundParameters.ContainsKey('GuestInventory'))     { $GuestInventory     = $true }
            if (-not $PSBoundParameters.ContainsKey('NamedLocations'))     { $NamedLocations     = $true }
            if (-not $PSBoundParameters.ContainsKey('ServicePrincipals'))  { $ServicePrincipals  = $true }
            if (-not $PSBoundParameters.ContainsKey('DMARC'))              { $DMARC              = $true }
            if (-not $PSBoundParameters.ContainsKey('SharedMailboxes'))    { $SharedMailboxes    = $true }
            if (-not $PSBoundParameters.ContainsKey('DNSRecords'))         { $DNSRecords         = $true }
            if (-not $PSBoundParameters.ContainsKey('MailFlowHardening'))  { $MailFlowHardening  = $true }
            if (-not $PSBoundParameters.ContainsKey('IdentityHardening'))  { $IdentityHardening  = $true }
            if (-not $PSBoundParameters.ContainsKey('BreakGlass'))         { $BreakGlass         = $true }
        }
    }
    Write-Host "[*] Profile: $P applied" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────
# Custom Help Output
# ─────────────────────────────────────────────

if ($args -contains '--help' -or $args -contains '-h') {
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host '  NextLayerSec M365 Assessment Framework v2' -ForegroundColor White
    Write-Host '  nextlayersec.io' -ForegroundColor DarkGray
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'USAGE' -ForegroundColor Yellow
    Write-Host '  .\Invoke-NLSAssessment.ps1 [flags]'
    Write-Host ''
    Write-Host 'CONNECTION' -ForegroundColor Yellow
    Write-Host '  -UserPrincipalName     Admin UPN for Exchange Online and Graph'
    Write-Host '  -SkipConnect           Skip connection if already authenticated'
    Write-Host '  -ClearToken            Clear cached Graph token before connecting (fixes AccessDenied)'
    Write-Host '  -NoGraph               Exchange Online only -- no Graph required'
    Write-Host '  -Quick                 Skip sign-in log telemetry'
    Write-Host '  -NoTelemetry           Same as -Quick'
    Write-Host ''
    Write-Host 'SETUP' -ForegroundColor Yellow
    Write-Host '  -GenerateManifest      Generate SHA-256 hash manifest for module integrity baseline'
    Write-Host '                         Run once after clean install or after updating modules'
    Write-Host '  -DebugScoring          Surface verbose scoring errors -- use when investigating null/exception errors'
    Write-Host ''
    Write-Host 'FRAMEWORKS' -ForegroundColor Yellow
    Write-Host '  -NIST                  NIST SP 800-53 Rev 5 Release 5.2.0'
    Write-Host '  -CIS                   CIS Controls v8.1 June 2024'
    Write-Host '  -HIPAA                 HIPAA Security Rule 45 CFR 164.312 (current)'
    Write-Host '  -HIPAAProposed         HIPAA NPRM December 2024 (proposed -- final May 2026)'
    Write-Host '  -ZeroTrust             CISA Zero Trust Maturity Model 2023'
    Write-Host ''
    Write-Host '  Pass one or more framework flags. Default is -NIST when none specified.' -ForegroundColor DarkGray
    Write-Host '  Use -HIPAA -HIPAAProposed together for dual-state gap analysis.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'FEATURES' -ForegroundColor Yellow
    Write-Host '  -SecureScore           Microsoft Secure Score integration'
    Write-Host '                         Requires SecurityEvents.Read.All scope'
    Write-Host '  -MFAReport             Per-user MFA registration status'
    Write-Host '                         Requires Reports.Read.All scope'
    Write-Host '  -OpenReport            Auto-open AssessmentSummary.md on completion'
    Write-Host ''
    Write-Host 'OUTPUT' -ForegroundColor Yellow
    Write-Host '  -RedactSensitiveData   Scrub UPNs, GUIDs, and IPs from all output'
    Write-Host ''
    Write-Host 'PROFILES  (-P <name>)' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Quick' -ForegroundColor White -NoNewline
    Write-Host '       Exchange only, no Graph, NIST citations -- fastest initial triage'
    Write-Host '  Standard' -ForegroundColor White -NoNewline
    Write-Host '     NIST + CIS, full Graph -- general purpose assessment'
    Write-Host '  HIPAA' -ForegroundColor White -NoNewline
    Write-Host '        HIPAA current + proposed, MFAReport, AdminRoles, DMARC, SharedMailboxes'
    Write-Host '  MSP' -ForegroundColor White -NoNewline
    Write-Host '          NIST + CIS, AdminRoles, StaleAccounts, GuestInventory, DMARC, SharedMailboxes'
    Write-Host '  ZeroTrust' -ForegroundColor White -NoNewline
    Write-Host '    NIST + ZeroTrust, NamedLocations, AdminRoles, MFAReport, ServicePrincipals, StaleAccounts'
    Write-Host '  Full' -ForegroundColor White -NoNewline
    Write-Host '         All frameworks + all features'
    Write-Host ''
    Write-Host '  Profiles are additive. Extra flags passed alongside -P expand the profile.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'EXAMPLES' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Quick triage -- Exchange only, no Graph:'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Quick' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  MSP tenant assessment:'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Healthcare client -- dual-state HIPAA, redacted:'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P HIPAA -RedactSensitiveData' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Zero Trust posture assessment:'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P ZeroTrust' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Full assessment -- everything, redacted:'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -RedactSensitiveData' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Profile + extra flag (MSP with Secure Score added):'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -SecureScore' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Manual flags -- no profile:'
    Write-Host '    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'PERMISSIONS' -ForegroundColor Yellow
    Write-Host '  Exchange Admin or Global Admin   Exchange Online collection'
    Write-Host '  Policy.Read.ConditionalAccess    CA policy collection'
    Write-Host '  Directory.Read.All               Graph directory access'
    Write-Host '  AuditLog.Read.All                Sign-in telemetry (Full mode)'
    Write-Host '  Reports.Read.All                 User MFA registration (-MFAReport)'
    Write-Host '  SecurityEvents.Read.All          Secure Score (-SecureScore)'
    Write-Host ''
    Write-Host 'TROUBLESHOOTING' -ForegroundColor Yellow
    Write-Host '  CA Partial on Global Admin -- stale token:'
    Write-Host '    Disconnect-MgGraph; Remove-Item "$env:USERPROFILE\.mg" -Recurse -Force' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Defender cmdlets not found -- licensing gap:'
    Write-Host '    Tenant requires M365 Business Premium or Defender for O365 Plan 1+' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Script blocked on first run:'
    Write-Host '    Unblock-File -Path .\Invoke-NLSAssessment.ps1; Unblock-File -Path .\Modules\*.psm1' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host '  See README.md for full documentation' -ForegroundColor DarkGray
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ''
    exit 0
}

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
$runSecScore          = [bool]$SecureScore -and $runGraph
$runMFAReport         = [bool]$MFAReport -and $runGraph
$runAdminRoles        = [bool]$AdminRoles -and $runGraph
$runStaleAccounts     = [bool]$StaleAccounts -and $runGraph
$runGuestInventory    = [bool]$GuestInventory -and $runGraph
$runNamedLocations    = [bool]$NamedLocations -and $runGraph
$runServicePrincipals = [bool]$ServicePrincipals -and $runGraph
$runDMARC             = [bool]$DMARC
$runSharedMailboxes   = [bool]$SharedMailboxes
$runDNSRecords        = [bool]$DNSRecords
$runMailFlowHardening = [bool]$MailFlowHardening
$runIdentityHardening = [bool]$IdentityHardening -and $runGraph
$runBreakGlass        = [bool]$BreakGlass -and $runGraph

if ($P) {
    Write-Host "[*] Profile: $P" -ForegroundColor Cyan
}
Write-Host '[*] Execution Mode: ' -NoNewline -ForegroundColor Cyan
if ($NoGraph) {
    Write-Host 'EXCHANGE ONLY (No Graph) ' -NoNewline -ForegroundColor Yellow
} elseif ($Quick -or $NoTelemetry) {
    Write-Host 'QUICK (No Telemetry) ' -NoNewline -ForegroundColor Yellow
} elseif ($P) {
    Write-Host "$P " -NoNewline -ForegroundColor Green
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
if ($runSecScore)          { $activeFeatures += 'Secure Score' }
if ($runMFAReport)         { $activeFeatures += 'MFA Report' }
if ($runAdminRoles)        { $activeFeatures += 'Admin Roles' }
if ($runStaleAccounts)     { $activeFeatures += 'Stale Accounts' }
if ($runGuestInventory)    { $activeFeatures += 'Guest Inventory' }
if ($runNamedLocations)    { $activeFeatures += 'Named Locations' }
if ($runServicePrincipals) { $activeFeatures += 'Service Principals' }
if ($runDMARC)             { $activeFeatures += 'DMARC' }
if ($runSharedMailboxes)   { $activeFeatures += 'Shared Mailboxes' }
if ($runDNSRecords)        { $activeFeatures += 'DNS Records' }
if ($runMailFlowHardening) { $activeFeatures += 'Mail Flow Hardening' }
if ($runIdentityHardening) { $activeFeatures += 'Identity Hardening' }
if ($runBreakGlass)        { $activeFeatures += 'Break Glass' }
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

# Generate hash manifest if requested -- run this after clean install or update
if ($GenerateManifest) {
    Write-Host '[-] Generating module hash manifest...' -ForegroundColor DarkGray
    $null = New-NLSModuleHashManifest -ModulesPath $modulesDir
    Write-Host '  [+] Manifest generated. Re-run without -GenerateManifest to run assessment.' -ForegroundColor Green
    exit 0
}

# Module integrity check -- verify all NLS modules loaded from expected path
$integrityCheck = Test-NLSModuleIntegrity -ExpectedModulesPath $modulesDir
if (-not $integrityCheck.Passed) {
    Write-Host '[!] MODULE INTEGRITY VIOLATION DETECTED' -ForegroundColor Red
    foreach ($v in $integrityCheck.Violations) {
        Write-Host "    $($v.Module) loaded from unexpected path: $($v.LoadedFrom)" -ForegroundColor Red
    }
    Write-Host '    Aborting. Verify Modules directory has not been tampered with.' -ForegroundColor Red
    exit 1
}
Write-Host '  [+] Module integrity verified' -ForegroundColor DarkGray
if ($integrityCheck.Warnings) {
    foreach ($w in $integrityCheck.Warnings) {
        Write-Host "  [!] $w" -ForegroundColor Yellow
    }
}

# ─────────────────────────────────────────────
# Output Directory Setup
# ─────────────────────────────────────────────

# Build tenant name from UPN for filename
$tenantName = if ($UserPrincipalName -and $UserPrincipalName -match '@(.+)') {
    # Extract domain, strip TLD, use first segment
    $domain = $Matches[1] -split '\.' | Select-Object -First 1
    $domain.ToLower() -replace '[^a-z0-9]', ''
} elseif ($SkipConnect) {
    'tenant'
} else {
    'unknown'
}

$dateStamp  = (Get-Date).ToString('yyyyMMdd')
$reportName = "$tenantName-$dateStamp"
$outDir     = Join-Path $scriptDir "output"

try {
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    $pathProtected = Protect-NLSOutputPath -OutputPath $outDir
    if ($pathProtected) {
        Write-Host "  [+] Output directory: $outDir (permissions locked)" -ForegroundColor DarkGray
    } else {
        Write-Host "  [+] Output directory: $outDir" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "[!] Failed to create output directory: $_" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────
# Connection Bootstrap
# ─────────────────────────────────────────────

if (-not $SkipConnect) {
    $upn = if ($UserPrincipalName) { $UserPrincipalName } else { Read-Host 'Enter Admin UPN' }

    # Validate UPN format before connecting
    $upnValidation = Test-NLSInputUPN -UPN $upn
    if (-not $upnValidation.Valid) {
        Write-Host "[!] Invalid UPN: $($upnValidation.Reason)" -ForegroundColor Red
        exit 1
    }

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
        # Always disconnect stale session; if -ClearToken passed also wipe WAM cache
        try { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue 2>$null } catch { }
        if ($ClearToken) {
            Write-Host '  [*] Clearing cached Graph token...' -ForegroundColor DarkGray
            Remove-Item -Path "$env:USERPROFILE\.mg" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\TokenCache" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host '  [+] Token cache cleared' -ForegroundColor Green
        }

        $graphScopes = @(
            'Policy.Read.ConditionalAccess',
            'Policy.Read.All',
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

# Initialize all result variables
$caResults                = @{}
$caTelemetryResults       = @{}
$mfaStatusResults         = @{}
$secureScoreResults       = @{}
$adminRoleResults         = @{}
$staleAccountResults      = @{}
$guestResults             = @{}
$namedLocationResults     = @{}
$servicePrincipalResults  = @{}
$dmarcResults             = @{}
$sharedMailboxResults     = @{}
$dnsRecordResults         = @{}
$mailFlowResults          = @{}
$identityHardeningResults = @{}
$breakGlassResults        = @{}

if ($runDMARC) {
    Write-Host '[-] Collecting DMARC policy status...' -ForegroundColor DarkGray
    $dmarcResults = Get-NLSDMARCStatus -Redact $runRedaction
} else {
    Register-NLSCoverage -ControlFamily 'DMARC' `
        -Status 'NotCollected' -Reason 'Operator did not pass -DMARC flag'
    $dmarcResults = @{}
}

if ($runSharedMailboxes) {
    Write-Host '[-] Collecting shared mailbox hardening status...' -ForegroundColor DarkGray
    $sharedMailboxResults = Get-NLSSharedMailboxHardening -Redact $runRedaction
} else {
    Register-NLSCoverage -ControlFamily 'SharedMailboxHardening' `
        -Status 'NotCollected' -Reason 'Operator did not pass -SharedMailboxes flag'
    $sharedMailboxResults = @{}
}

if ($runDNSRecords) {
    Write-Host '[-] Looking up DNS email records (SPF, DMARC, DKIM)...' -ForegroundColor DarkGray
    $dnsRecordResults = Get-NLSDNSEmailRecords -Redact $runRedaction -DebugMode ([bool]$DebugDNS)
} else {
    Register-NLSCoverage -ControlFamily 'DNSEmailRecords' `
        -Status 'NotCollected' -Reason 'Operator did not pass -DNSRecords flag'
    $dnsRecordResults = @{}
}

if ($runMailFlowHardening) {
    Write-Host '[-] Collecting mail flow hardening status...' -ForegroundColor DarkGray
    $mailFlowResults = Get-NLSMailFlowHardening -Redact $runRedaction
} else {
    Register-NLSCoverage -ControlFamily 'MTASTS' -Status 'NotCollected' -Reason 'Operator did not pass -MailFlowHardening flag'
    Register-NLSCoverage -ControlFamily 'InboundSpam' -Status 'NotCollected' -Reason 'Operator did not pass -MailFlowHardening flag'
    Register-NLSCoverage -ControlFamily 'MalwareFilter' -Status 'NotCollected' -Reason 'Operator did not pass -MailFlowHardening flag'
}

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

    if ($runAdminRoles) {
        Write-Host '[-] Collecting admin role inventory...' -ForegroundColor DarkGray
        $adminRoleResults = Get-NLSAdminRoleInventory -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'AdminRoleInventory' `
            -Status 'NotCollected' -Reason 'Operator did not pass -AdminRoles flag'
    }

    if ($runStaleAccounts) {
        Write-Host '[-] Collecting stale account data...' -ForegroundColor DarkGray
        $staleAccountResults = Get-NLSStaleAccounts -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'StaleAccounts' `
            -Status 'NotCollected' -Reason 'Operator did not pass -StaleAccounts flag'
    }

    if ($runGuestInventory) {
        Write-Host '[-] Collecting guest account inventory...' -ForegroundColor DarkGray
        $guestResults = Get-NLSGuestAccountInventory -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'GuestAccountInventory' `
            -Status 'NotCollected' -Reason 'Operator did not pass -GuestInventory flag'
    }

    if ($runNamedLocations) {
        Write-Host '[-] Collecting named locations...' -ForegroundColor DarkGray
        $namedLocationResults = Get-NLSNamedLocations -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'NamedLocations' `
            -Status 'NotCollected' -Reason 'Operator did not pass -NamedLocations flag'
    }

    if ($runServicePrincipals) {
        Write-Host '[-] Collecting service principal inventory...' -ForegroundColor DarkGray
        $servicePrincipalResults = Get-NLSServicePrincipalInventory -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'ServicePrincipalInventory' `
            -Status 'NotCollected' -Reason 'Operator did not pass -ServicePrincipals flag'
    }

    if ($runIdentityHardening) {
        Write-Host '[-] Collecting identity hardening status...' -ForegroundColor DarkGray
        $identityHardeningResults = Get-NLSIdentityHardening -Redact $runRedaction
    } else {
        foreach ($family in @('SecurityDefaults','PasswordProtection','SSPR','AuthenticationMethods','ConsentFramework','ExternalCollaboration','PIM')) {
            Register-NLSCoverage -ControlFamily $family -Status 'NotCollected' -Reason 'Operator did not pass -IdentityHardening flag'
        }
    }

    if ($runBreakGlass) {
        Write-Host '[-] Checking break-glass account configuration...' -ForegroundColor DarkGray
        $breakGlassResults = Get-NLSBreakGlassAccount -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'BreakGlassAccounts' -Status 'NotCollected' -Reason 'Operator did not pass -BreakGlass flag'
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
$profileLabel = if ($P) { $P } else { 'Custom' }
$metadata = Get-NLSMetadata `
    -Redact $runRedaction `
    -ActiveFrameworks $activeFrameworks `
    -ActiveFeatures $activeFeatures `
    -ExecutionMode $profileLabel

Write-Host ''

# ─────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────

Write-Host '[-] Applying scoring model...' -ForegroundColor DarkGray

$allResults = @{
    ExchangePolicies           = $exchangeResults
    ConditionalAccess          = $caResults
    ConditionalAccessTelemetry = $caTelemetryResults
    DMARC                      = $dmarcResults
    SharedMailboxes            = $sharedMailboxResults
    MailFlow                   = $mailFlowResults
    IdentityHardening          = $identityHardeningResults
    BreakGlass                 = $breakGlassResults
    StaleAccounts              = $staleAccountResults
    AdminRoles                 = $adminRoleResults
    NamedLocations             = $namedLocationResults
    MFAStatus                  = $mfaStatusResults
}

# Pass framework flags directly from current variable values
# PSBoundParameters check is NOT used here -- profiles set variables directly
# so we read the variables, not the parameter binding state
$anyFramework = [bool]$NIST -or [bool]$CIS -or [bool]$HIPAA -or [bool]$HIPAAProposed -or [bool]$ZeroTrust

$scoringParams = @{
    Results      = $allResults
    Redact       = $runRedaction
    NIST         = if ($anyFramework) { [bool]$NIST } else { $true } # Default to NIST if none passed
    CIS          = [bool]$CIS
    HIPAA        = [bool]$HIPAA
    HIPAAProposed = [bool]$HIPAAProposed
    ZeroTrust    = [bool]$ZeroTrust
    DebugMode    = [bool]$DebugScoring
}

$scoredResults = Invoke-NLSScoringModel @scoringParams

Write-Host ''

# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────

Write-Host '[-] Generating assessment artifacts...' -ForegroundColor DarkGray

# Initialize delta data -- will be populated after report path is known
$deltaData = [ordered]@{ Available = $false }

$summaryPath    = Join-Path $outDir "$reportName.md"
$exceptionsPath = Join-Path $outDir "$reportName-exceptions.md" 

# Build extended data for reporting
$extendedData = @{}
if ($caResults -and $caResults['ConditionalAccess'])                               { $extendedData['ConditionalAccess']        = $caResults['ConditionalAccess'] }
if ($mfaStatusResults -and $mfaStatusResults['UserMFAStatus'])                     { $extendedData['UserMFAStatus']            = $mfaStatusResults['UserMFAStatus'] }
if ($secureScoreResults -and $secureScoreResults['SecureScore'])                   { $extendedData['SecureScore']              = $secureScoreResults['SecureScore'] }
if ($adminRoleResults -and $adminRoleResults['AdminRoleInventory'])                 { $extendedData['AdminRoleInventory']       = $adminRoleResults['AdminRoleInventory'] }
if ($staleAccountResults -and $staleAccountResults['StaleAccounts'])               { $extendedData['StaleAccounts']            = $staleAccountResults['StaleAccounts'] }
if ($guestResults -and $guestResults['GuestAccountInventory'])                     { $extendedData['GuestAccountInventory']    = $guestResults['GuestAccountInventory'] }
if ($namedLocationResults -and $namedLocationResults['NamedLocations'])            { $extendedData['NamedLocations']           = $namedLocationResults['NamedLocations'] }
if ($servicePrincipalResults -and $servicePrincipalResults['ServicePrincipalInventory']) { $extendedData['ServicePrincipalInventory'] = $servicePrincipalResults['ServicePrincipalInventory'] }
if ($dmarcResults -and $dmarcResults['DMARC'])                                     { $extendedData['DMARC']                    = $dmarcResults['DMARC'] }
if ($sharedMailboxResults -and $sharedMailboxResults['SharedMailboxHardening'])    { $extendedData['SharedMailboxHardening']   = $sharedMailboxResults['SharedMailboxHardening'] }
if ($dnsRecordResults)                                                              { $extendedData['DNSEmailRecords']          = $dnsRecordResults['DNSEmailRecords'] }
if ($mailFlowResults -and $mailFlowResults['MTASTS'])                               { $extendedData['MTASTS']                   = $mailFlowResults['MTASTS'] }
if ($mailFlowResults -and $mailFlowResults['InboundSpam'])                          { $extendedData['InboundSpam']              = $mailFlowResults['InboundSpam'] }
if ($mailFlowResults -and $mailFlowResults['MalwareFilter'])                        { $extendedData['MalwareFilter']            = $mailFlowResults['MalwareFilter'] }
if ($identityHardeningResults -and $identityHardeningResults['SecurityDefaults'])   { $extendedData['SecurityDefaults']         = $identityHardeningResults['SecurityDefaults'] }
if ($identityHardeningResults -and $identityHardeningResults['AuthenticationMethods']) { $extendedData['AuthenticationMethods'] = $identityHardeningResults['AuthenticationMethods'] }
if ($identityHardeningResults -and $identityHardeningResults['ConsentFramework'])   { $extendedData['ConsentFramework']         = $identityHardeningResults['ConsentFramework'] }
if ($identityHardeningResults -and $identityHardeningResults['PIM'])               { $extendedData['PIM']                      = $identityHardeningResults['PIM'] }
if ($breakGlassResults -and $breakGlassResults['BreakGlassAccounts'])              { $extendedData['BreakGlassAccounts']        = $breakGlassResults['BreakGlassAccounts'] }

if ($DebugAll) {
    Write-Host '  [DEBUG] === allResults keys ===' -ForegroundColor DarkGray
    foreach ($k in ($allResults.Keys | Sort-Object)) {
        $v = $allResults[$k]
        $d = if ($null -eq $v) { 'NULL' } elseif ($v -is [System.Collections.Specialized.OrderedDictionary]) { "[ordered]($($v.Keys.Count))" } elseif ($v -is [hashtable]) { "[hashtable]($($v.Keys.Count))" } else { $v.GetType().Name }
        Write-Host "    $($k.PadRight(30)) $d" -ForegroundColor DarkGray
    }
    Write-Host '  [DEBUG] === extendedData keys ===' -ForegroundColor DarkGray
    foreach ($k in ($extendedData.Keys | Sort-Object)) {
        $v = $extendedData[$k]
        $d = if ($null -eq $v) { 'NULL' } elseif ($v -is [System.Collections.Specialized.OrderedDictionary]) { "[ordered]($($v.Keys.Count)) keys: $($v.Keys -join ', ')" } elseif ($v -is [hashtable]) { "[hashtable]($($v.Keys.Count))" } else { $v.GetType().Name }
        Write-Host "    $($k.PadRight(30)) $d" -ForegroundColor DarkGray
    }
    Write-Host '' -ForegroundColor DarkGray
}

Publish-NLSAssessmentSummary `
    -ScoredResults $scoredResults `
    -DebugDNS ([bool]$DebugDNS) `
    -Metadata $metadata `
    -Coverage (Get-NLSCoverageMap) `
    -OutputPath $summaryPath `
    -ExtendedData $extendedData `
    -DeltaData $deltaData `
    -Redact $runRedaction

$exceptions = Get-NLSExceptions
if ($null -eq $exceptions) { $exceptions = @() }

Publish-NLSExceptionsList `
    -Exceptions $exceptions `
    -OutputPath $exceptionsPath `
    -Redact $runRedaction

# ── Remediation Script ────────────────────────────────────────
$remediationPath = Join-Path $outDir "$reportName-remediation.ps1"
[void](Publish-NLSRemediationScript `
    -ScoredResults $scoredResults `
    -OutputPath $remediationPath `
    -TenantName $tenantName `
    -Redact $runRedaction)

# ── Delta Reporting ───────────────────────────────────────────

# Try manual path first, then auto-find
$previousReport = $null
if ($Compare -and (Test-Path $Compare)) {
    $previousReport = $Compare
    Write-Host "[-] Using specified previous report for delta..." -ForegroundColor DarkGray
} else {
    $previousReport = Find-NLSPreviousReport `
        -OutputDir $outDir `
        -TenantName $tenantName `
        -CurrentReportPath $summaryPath
    if ($previousReport) {
        Write-Host "[-] Previous report found for delta: $(Split-Path $previousReport -Leaf)" -ForegroundColor DarkGray
    }
}

if ($previousReport) {
    $deltaData = Get-NLSDeltaReport `
        -CurrentResults $scoredResults `
        -PreviousReportPath $previousReport
}

# ─────────────────────────────────────────────
# Summary Output
# ─────────────────────────────────────────────

$s = $scoredResults['Summary']

Write-Host ''
Write-Host '================================================================' -ForegroundColor DarkGray
Write-Host '  Assessment Complete' -ForegroundColor White
Write-Host '================================================================' -ForegroundColor DarkGray
Write-Host "  Satisfied  $($s['Satisfied'])" -ForegroundColor Green
Write-Host "  Partial    $($s['Partial'])"   -ForegroundColor $(if ($s['Partial'] -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Gap        $($s['Gap'])"       -ForegroundColor $(if ($s['Gap'] -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Total      $($s['Total'])"     -ForegroundColor White
Write-Host ''
Write-Host "  Report:      $outDir\$reportName.md" -ForegroundColor Cyan
Write-Host "  Remediation: $outDir\$reportName-remediation.ps1" -ForegroundColor Cyan
Write-Host "  Exceptions:  $outDir\$reportName-exceptions.md" -ForegroundColor DarkGray
if ($deltaData['Available']) {
    Write-Host "  Delta:       Improved $($deltaData['ImprovedCount'])  Regressed $($deltaData['RegressedCount'])  New $($deltaData['NewCount'])" -ForegroundColor Cyan
}
Write-Host ''

# Auto-open report in VS Code if installed
$reportFile = Join-Path $outDir "$reportName.md"
try {
    $vsCode = Get-Command code -ErrorAction SilentlyContinue
    if ($vsCode -and (Test-Path $reportFile)) {
        Write-Host '[-] Opening report in VS Code...' -ForegroundColor DarkGray
        $null = Start-Process -FilePath 'code' -ArgumentList $reportFile -ErrorAction SilentlyContinue
    } elseif ($OpenReport -and (Test-Path $reportFile)) {
        Write-Host '[-] Opening report...' -ForegroundColor DarkGray
        Start-Process $reportFile
    }
} catch { }

# ─────────────────────────────────────────────
# Disconnect
# ─────────────────────────────────────────────

if (-not $SkipConnect) {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        if ($runGraph) { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue 2>$null }
        Write-Host '[-] Sessions disconnected.' -ForegroundColor DarkGray
    } catch { }
}

Write-Host ''
