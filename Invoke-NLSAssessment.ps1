#Requires -Version 7.0
#
# Invoke-NLSAssessment.ps1
# Entry point for NLS-Assessment (version read from module manifest at runtime)
#
# NextLayerSec | NextLayerSec LLC
# Author: NextLayerSec
#
# Flow:
#   1. Import module (loads Lib, Collectors, Evaluators, Publishers)
#   2. Connect to M365 services
#   3. Run collectors -> raw data stored in module state
#   4. Run evaluators -> findings registered via Add-NLSFinding
#   5. Run publishers -> HTML, Markdown, JSON, XLSX, Playbook, Remediation script
#
# Usage:
#   .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@client.com
#   .\Invoke-NLSAssessment.ps1 -AppId <guid> -TenantId <guid> -CertificateThumbprint <40hex> -OrganizationDomain contoso.onmicrosoft.com
#

[CmdletBinding()]
param(
    # OWASP ASVS V5.1.3 — UPN must match standard email format before reaching auth
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$|^$')]
    [string] $UserPrincipalName,
    [string] $OutputPath,

    # App-only / certificate authentication for unattended runs
    [string] $AppId,
    [string] $TenantId,
    [string] $CertificateThumbprint,
    [string] $OrganizationDomain,

    # One-time tenant onboarding: register a read-only enterprise app + cert in
    # the customer tenant so future scans run app-only (no device codes, no
    # Conditional-Access flow blocks). Requires an operator who can create app
    # registrations; you'll be connected interactively with write scopes first.
    [switch] $RegisterApp,

    # Auto-grant admin consent during -RegisterApp (operator must be Global
    # Administrator). Omit to instead receive a consent URL for a Global Admin.
    [switch] $GrantConsent,

    # Convenience: look up a previously-onboarded tenant's ClientId + cert
    # thumbprint from Config/clients.json by domain, so unattended scans don't
    # need the GUIDs pasted every time. Also the target for -RegisterApp.
    [ValidatePattern('^$|^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
    [string] $TenantDomain,

    # Cloud environment
    [ValidateSet('commercial','gcc','gcchigh','dod')]
    [string] $Environment = 'commercial',

    # Skip switches
    [switch] $SkipPurview,
    [switch] $IncludePurview,   # Include Purview/IPPSSession (skipped by default — EOM v3.4 WAM crash)
    [switch] $SkipTeams,
    [switch] $SkipSharePoint,
    [switch] $SkipIntune,
    [switch] $SkipPowerPlatform,
    [switch] $SkipDNS,

    # Run modes
    [switch] $NonInteractive,
    # Audit fix (v4.6.x MED #6): validate that FromResults / BaselineResults
    # point at an existing file via -LiteralPath. This refuses wildcard input
    # ('*'), path-traversal sequences, and silently-missing files before any
    # downstream Get-Content / republish step touches the path.
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in FromResults." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "FromResults file not found: $_" }
        return $true
    })]
    [string] $FromResults,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in BaselineResults." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "BaselineResults file not found: $_" }
        return $true
    })]
    [string] $BaselineResults,
    # OWASP ASVS V5.1.3 — every DnsDomains entry must be an FQDN before DNS resolver sees it
    [ValidateScript({
        foreach ($d in $_) {
            if ($d -notmatch '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
                throw "Invalid DNS domain name: '$d'"
            }
        }
        return $true
    })]
    [string[]] $DnsDomains,
    [switch] $JsonOnly,
    [switch] $WhatIfConnections,

    # Launch the local web GUI instead of running a scan in the terminal.
    # The GUI is a local Pode-backed server (loopback only, never exposed
    # to the network) that lets the operator pick a tenant, trigger scans,
    # watch progress, and view reports in a browser. See Lib/Start-NLSWebServer.ps1
    # and Web/. No tenant data leaves the workstation.
    [switch] $Web,

    # Port for the -Web GUI loopback server. Default avoids common collisions.
    [ValidateRange(1024, 65535)]
    [int] $WebPort = 8765,

    # ── Quick scan mode ──────────────────────────────────────────────────────
    # Only evaluate Critical + High controls. Skips Medium / Low / Informational
    # evaluators entirely. Designed for live demos and sanity checks; finishes
    # in under a minute on most tenants instead of ~10 min for the full sweep.
    [switch] $Quick,

    # ── Automation-friendly threshold exit codes ────────────────────────────
    # Non-zero exit on failure threshold. Default 0 = disabled (preserves the
    # existing exit-code spec). When any of these fires, the run still produces
    # all artifacts; the non-zero exit is purely a signal for cron / Task
    # Scheduler / CI integrations to take action (email IT, file a ticket).
    #   10 = critical-gap threshold breached
    #   11 = high-gap threshold breached
    #   12 = score below threshold
    [ValidateRange(0, 999)]
    [int] $FailOnCritical = 0,

    [ValidateRange(0, 999)]
    [int] $FailOnHigh     = 0,

    [ValidateRange(0, 100)]
    [int] $FailOnScoreBelow = 0
)

# OWASP ASVS V16.4.1 — strict mode at the entry point so the orchestrator
# uses the same semantics as the module body (uninitialized variable access,
# property access on $null, indexing past array end all throw).
Set-StrictMode -Version Latest

# v4.6.4 CRITICAL FIX: pre-initialize exit-code vars so StrictMode reads at end
# (lines 570 + 586) never throw VariableIsUndefined on the success path. Without
# this every successful run crashes with a stack trace AFTER the report is
# written but BEFORE `exit 0` lands → callers see exit code 1.
$script:NLSFatalExitCode     = $null
$script:NLSSuccessExitCode   = $null
$script:NLSThresholdExitCode = $null

# OWASP ASVS V11.2.2 / OSSTMM DN5 — enforce TLS 1.2 minimum (Microsoft endpoints
# already require this, but defense-in-depth catches dev/test environments where
# .NET defaults might drift back to older protocols)
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13

# Disable WAM broker before any module loads — prevents RuntimeBroker NullReferenceException
$env:MSAL_ALLOW_BROKER        = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'
$env:MSAL_DISABLE_WAM         = '1'

# Purview skipped by default — EOM v3.4 WAM broker crashes on background thread
# Pass -IncludePurview to attempt it (works when running standalone PS7 window)
if (-not $IncludePurview -and -not $SkipPurview) { $SkipPurview = $true }

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── Pre-banner version probe ─────────────────────────────────────────────────
# Read ModuleVersion from the manifest BEFORE the module is imported so the
# banner version stays in lockstep with the .psd1 / .psm1 single source of
# truth. Falls back to 'unknown' if the manifest can't be parsed — the import
# step below will then fail loudly and exit anyway.
$script:NLSAssessmentVersion = 'unknown'
try {
    $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptDir 'NLS-Assessment.psd1') -ErrorAction Stop
    if ($manifestData.ModuleVersion) { $script:NLSAssessmentVersion = [string]$manifestData.ModuleVersion }
} catch { }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NLS-Assessment v$($script:NLSAssessmentVersion) — Read-Only M365 Security Assessment" -ForegroundColor Cyan
Write-Host " NextLayerSec | NextLayerSec LLC"                     -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── Output path ───────────────────────────────────────────────────────────────
# OWASP A01 / ASVS V12.3.1 — reject ..[/\\] path-traversal sequences before any
# file operation. Also ensure the resolved path stays under the script directory
# unless an absolute path was explicitly provided by the operator.
if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
if ($OutputPath -match '\.\.[\\/]') {
    throw "OutputPath rejected: contains '..[/\\]' traversal sequence."
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    [void][System.IO.Directory]::CreateDirectory($OutputPath)
}
# Resolve to absolute path so downstream auto-open / publish steps can verify
# generated files via $resolvedOutput.StartsWith($resolvedOutput) bounds checks.
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)

# ── Import module ─────────────────────────────────────────────────────────────
Write-Host "[-] Loading NLS-Assessment module..." -ForegroundColor Cyan
$manifestPath = Join-Path $scriptDir 'NLS-Assessment.psd1'
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    Write-Host "  [+] Module loaded (v$($NLSAssessmentVersion))" -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# -Web short-circuits the terminal flow: hand control to the local Pode-backed
# web GUI, which handles tenant selection, scan triggering, progress display,
# and report viewing in a browser. The server binds to 127.0.0.1 only —
# never exposed to the network — and exits cleanly on Ctrl+C.
if ($Web) {
    Start-NLSWebServer -Port $WebPort -ScriptDir $scriptDir
    exit 0
}

# -RegisterApp short-circuits into one-time tenant onboarding: connect
# interactively with WRITE scopes, then create the read-only enterprise app +
# cert in the customer tenant and record it in clients.json. After this, scans
# of that tenant run app-only. This is a privileged, deliberate operation — it
# never happens during a normal scan.
if ($RegisterApp) {
    if (-not $TenantDomain) {
        Write-Host "  [!] -RegisterApp requires -TenantDomain (the customer's domain)." -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    Write-Host "[-] Connecting to Microsoft Graph with onboarding (write) scopes..." -ForegroundColor Cyan
    Write-Host "    A browser sign-in will open. Authorize as an admin of $TenantDomain." -ForegroundColor DarkGray
    try {
        Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All' `
                        -ContextScope Process -NoWelcome -ErrorAction Stop
    } catch {
        Write-Host "  [!] Graph connect failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    $regParams = @{ TenantDomain = $TenantDomain }
    if ($GrantConsent) { $regParams['GrantConsent'] = $true }
    Register-NLSTenantApp @regParams
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 0
}

# -TenantDomain convenience: if the operator gave a domain but no explicit
# app-only credentials, look up a previously-onboarded record in clients.json
# and populate AppId / TenantId / CertificateThumbprint so the scan runs
# app-only with zero typed GUIDs.
if ($TenantDomain -and -not ($AppId -and $TenantId -and $CertificateThumbprint)) {
    $clientsPath = Join-Path $scriptDir 'Config\clients.json'
    if (Test-Path -LiteralPath $clientsPath) {
        try {
            $rec = @(Get-Content -LiteralPath $clientsPath -Raw -Encoding utf8 | ConvertFrom-Json) |
                   Where-Object { $_.TenantDomain -eq $TenantDomain -and $_.PSObject.Properties['ClientId'] -and $_.ClientId } |
                   Select-Object -First 1
        } catch { $rec = $null }
        if ($rec) {
            $AppId                 = [string]$rec.ClientId
            $TenantId              = [string]$rec.TenantId
            $CertificateThumbprint = [string]$rec.CertThumbprint
            if (-not $OrganizationDomain -and $rec.PSObject.Properties['TenantDomain']) {
                $OrganizationDomain = [string]$rec.TenantDomain
            }
            Write-Host "  [+] Using app-only auth for $TenantDomain (ClientId $AppId)" -ForegroundColor Green
        } else {
            Write-Host "  [i] $TenantDomain is not onboarded for app-only auth. Falling back to interactive." -ForegroundColor DarkGray
            Write-Host "      Onboard it once with:  .\Invoke-NLSAssessment.ps1 -RegisterApp -TenantDomain $TenantDomain" -ForegroundColor DarkGray
        }
    }
}

Clear-NLSFindings

# OWASP ASVS V7.3.2 — wrap the entire run in try/finally so service sessions
# always disconnect, even if a collector / evaluator / publisher throws.
try {

# ── Module prerequisite check ─────────────────────────────────────────────────
# EOM is pinned to 3.2.0 — 3.4.0+ has a WAM broker crash that kills the process
# from a background .NET thread (uncatchable from PowerShell).
$moduleSpecs = @(
    @{ Name='Microsoft.Graph.Authentication'; MinVersion='2.0.0'; PinVersion=$null   }
    @{ Name='ExchangeOnlineManagement';       MinVersion='3.0.0'; PinVersion='3.2.0' }
    @{ Name='MicrosoftTeams';                 MinVersion='5.0.0'; PinVersion=$null   }
)
$needsAction = @()
foreach ($spec in $moduleSpecs) {
    $installed = Get-Module -ListAvailable -Name $spec.Name -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed) {
        $needsAction += @{ Spec=$spec; Action='install'; Current=$null }
    } elseif ($spec.PinVersion -and $installed.Version -ne [version]$spec.PinVersion) {
        $needsAction += @{ Spec=$spec; Action='repin'; Current=$installed.Version }
    } elseif ($installed.Version -lt [version]$spec.MinVersion) {
        $needsAction += @{ Spec=$spec; Action='upgrade'; Current=$installed.Version }
    }
}

if ($needsAction.Count -gt 0) {
    Write-Host ""
    foreach ($n in $needsAction) {
        $name = $n.Spec.Name
        if ($n.Action -eq 'install') {
            Write-Host "  [!] Missing: $name" -ForegroundColor Yellow
        } elseif ($n.Action -eq 'repin') {
            Write-Host "  [!] $name $($n.Current) installed — recommended: $($n.Spec.PinVersion)" -ForegroundColor Yellow
            if ([version]$n.Current -gt [version]$n.Spec.PinVersion) {
                Write-Host "      Version $($n.Current) has known crash bugs in this tool's auth flow." -ForegroundColor DarkYellow
            }
        }
    }
    if ($NonInteractive) {
        Write-Host "  [!] NonInteractive — run .\Install-NLSPrerequisites.ps1 manually then retry." -ForegroundColor Red
        exit 1
    }
    $install = Read-Host "  Install/fix modules now? [Y/N]"
    if ($install -match '^[Yy]') {
        foreach ($n in $needsAction) {
            $name = $n.Spec.Name
            $targetVer = $n.Spec.PinVersion
            try {
                if ($n.Action -eq 'repin' -and [version]$n.Current -gt [version]$n.Spec.PinVersion) {
                    # OneDrive-synced PowerShell module paths can't be removed (OneDrive holds
                    # file locks on every file in the synced tree). Detect that case up front
                    # and refuse with an actionable message rather than letting Uninstall-PSResource
                    # fail mid-sweep with a confusing 'Cannot remove package path' error.
                    $existing = Get-Module -Name $name -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
                    if ($existing -and $existing.ModuleBase -match '(?i)\bOneDrive\b') {
                        Write-Host "  [!] $name is installed in a OneDrive-synced path:" -ForegroundColor Red
                        Write-Host "      $($existing.ModuleBase)" -ForegroundColor DarkYellow
                        Write-Host "      OneDrive prevents PowerShell from removing this module." -ForegroundColor Yellow
                        Write-Host "      Fix: pause OneDrive sync on your Documents folder, OR move your" -ForegroundColor Yellow
                        Write-Host "      PowerShell modules out of OneDrive (Settings -> OneDrive -> Backup)." -ForegroundColor Yellow
                        Write-Host "      Then re-run this script." -ForegroundColor Yellow
                        continue
                    }
                    Write-Host "  [*] Downgrading $name $($n.Current) -> $targetVer..." -ForegroundColor Cyan
                    Uninstall-PSResource -Name $name -ErrorAction SilentlyContinue
                }
                if ($targetVer) {
                    Write-Host "  [*] Installing $name $targetVer..." -ForegroundColor Cyan
                    Install-PSResource -Name $name -Version $targetVer -TrustRepository -Scope CurrentUser -Reinstall -ErrorAction Stop
                } else {
                    Write-Host "  [*] Installing $name (latest)..." -ForegroundColor Cyan
                    Install-PSResource -Name $name -TrustRepository -Scope CurrentUser -ErrorAction Stop
                }
                Write-Host "  [+] $name ready" -ForegroundColor Green
            } catch {
                Write-Host "  [!] $name failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [!] Skipping. Run .\Install-NLSPrerequisites.ps1 to set up manually." -ForegroundColor Yellow
    }
}

# ── FromResults mode — skip collection, just republish ───────────────────────
if ($FromResults -and (Test-Path -LiteralPath $FromResults)) {
    Write-Host "[-] FromResults mode — regenerating reports from $FromResults" -ForegroundColor Cyan
    # PS7 -AsHashtable gives us hashtables all the way down so downstream
    # `.Contains(key)` (Maturity badge, threshold exit codes) works. The prior
    # `@{} + $priorData.Metadata` form threw `A hash table can only be added
    # to another hash table` because ConvertFrom-Json returns PSCustomObject.
    $priorData = Get-Content -LiteralPath $FromResults -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    $findings = [object[]]@($priorData.Findings)
    $conn = if ($priorData.Connections) { [hashtable]$priorData.Connections } else { @{} }
    $reportMetadata = if ($priorData.Metadata) { [hashtable]$priorData.Metadata } else {
        @{ TenantDomain='Unknown'; AssessmentDate=(Get-Date -Format 'MMMM dd, yyyy'); ToolVersion=$script:NLSAssessmentVersion }
    }
    if ($Quick) {
        Write-Warning "-Quick has no effect with -FromResults: findings are loaded from the baseline JSON, not re-evaluated. To produce a Quick scan, re-run against the live tenant."
    }
    $tenantTag = if ($reportMetadata.TenantDomain) { ($reportMetadata.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "  [+] Loaded $($findings.Count) findings" -ForegroundColor Green
    $skipCollection = $true
} else {
    $skipCollection = $false
}

if (-not $skipCollection) {
    # ── Connect to services ──────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Connecting to M365 services..." -ForegroundColor Cyan

    $connectParams = @{}
    if ($AppId -and $TenantId -and $CertificateThumbprint) {
        $connectParams['AppId']                  = $AppId
        $connectParams['TenantId']               = $TenantId
        $connectParams['CertificateThumbprint']  = $CertificateThumbprint
        if ($OrganizationDomain) { $connectParams['OrganizationDomain'] = $OrganizationDomain }
    } elseif ($UserPrincipalName) {
        $connectParams['UserPrincipalName'] = $UserPrincipalName
    }
    if ($SkipPurview) { $connectParams['SkipPurview'] = $true }
    if ($SkipTeams)   { $connectParams['SkipTeams']   = $true }
    $connectParams['SkipSharePoint'] = $true  # SharePoint via Graph

    $rawConn = @(Connect-NLSServices @connectParams)
    $conn = $rawConn | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
    if (-not $conn) {
        $conn = @{ Graph=$false; EXO=$false; IPPSSession=$false; Teams=$false; SharePoint=$false }
    }
    # Exit-code spec (v4.6.3 P2): exit 1 on auth failure means no Graph/EXO
    # at all. The downstream collectors will skip silently but the result
    # would be useless — fail loudly here so batch runners can flag the
    # client as auth-broken in their summary.
    if (-not $conn.Graph -and -not $conn.EXO) {
        Write-Host "  [!] Connect-NLSServices returned no usable session (Graph and EXO both unavailable)." -ForegroundColor Red
        $script:NLSFatalExitCode = 1
        throw [System.InvalidOperationException]::new('Authentication failure: no Graph or EXO session available.')
    }
    if (-not $conn.ContainsKey('SharePoint')) { $conn['SharePoint'] = $false }

    if ($WhatIfConnections) {
        Write-Host ""
        Write-Host "Connections (WhatIf mode):" -ForegroundColor Yellow
        $conn | Format-Table -AutoSize
        return
    }

    # ── Run collectors ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running collectors..." -ForegroundColor Cyan

    function Invoke-NLSCollector { param([string]$fn)
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try { & $fn | Out-Null }
            catch { Write-Warning "Collector $fn failed: $($_.Exception.Message.Split([char]10)[0])" }
        }
    }

    if ($conn.Graph) {
        Write-Host "  [*] AAD: Auth + authorization policies..."
        Invoke-NLSCollector 'Invoke-NLSCollectAADAuthPolicies'
        Write-Host "  [*] AAD: Conditional Access policies..."
        Invoke-NLSCollector 'Invoke-NLSCollectAADCAPolicies'
        Write-Host "  [*] AAD: Users and MFA registration state..."
        Invoke-NLSCollector 'Invoke-NLSCollectAADUsers'
        Write-Host "  [*] AAD: Directory role assignments..."
        Invoke-NLSCollector 'Invoke-NLSCollectAADRoles'
        Write-Host "  [*] AAD: PIM eligible and active schedules..."
        Invoke-NLSCollector 'Invoke-NLSCollectAADPIM'
        Invoke-NLSCollector 'Invoke-NLSCollectAADIdentityGovernance'
        Write-Host "  [*] AAD: Inventory (guests, stale, OAuth, Secure Score)..."
        Invoke-NLSCollector 'Invoke-NLSCollectAADInventory'

        if (-not $SkipSharePoint) {
            Write-Host "  [*] SharePoint: Tenant settings via Graph..."
            Invoke-NLSCollector 'Invoke-NLSCollectSharePoint'
        }
        if (-not $SkipIntune) {
            Write-Host "  [*] Intune: Endpoint Security (LAPS / ASR / Firewall / EDR / AV)..."
            Invoke-NLSCollector 'Invoke-NLSCollectIntuneEndpointSecurity'
            Write-Host "  [*] Intune: Device Compliance, WHfB, Update Rings, Enrollment..."
            Invoke-NLSCollector 'Invoke-NLSCollectIntuneDeviceCompliance'
            Write-Host "  [*] Intune: App Protection (MAM) and App Configuration..."
            Invoke-NLSCollector 'Invoke-NLSCollectIntuneAppProtection'
        }
        if (-not $SkipPowerPlatform) {
            Write-Host "  [*] Power Platform: Environments, tenant isolation, DLP..."
            Invoke-NLSCollector 'Invoke-NLSCollectPowerPlatform'
        }
    }

    if ($conn.EXO) {
        Write-Host "  [*] EXO: Mailbox configuration..."
        Invoke-NLSCollector 'Invoke-NLSCollectEXOMailboxConfig'
        Write-Host "  [*] EXO: Inventory (forwarding, shared, audit, SMTP AUTH)..."
        Invoke-NLSCollector 'Invoke-NLSCollectEXOInventory'
        Write-Host "  [*] Defender: Safe Attachments, Safe Links, Anti-phishing..."
        Invoke-NLSCollector 'Invoke-NLSCollectDefender'
        if (-not $SkipDNS) {
            Write-Host "  [*] DNS: SPF/DKIM/DMARC/MTA-STS for accepted domains..."
            if ($DnsDomains) {
                if (Get-Command Invoke-NLSCollectDNSEmailRecords -ErrorAction SilentlyContinue) {
                    Invoke-NLSCollectDNSEmailRecords -Domains $DnsDomains | Out-Null
                }
            } else {
                Invoke-NLSCollector 'Invoke-NLSCollectDNSEmailRecords'
            }
        }
    }

    if ($conn.Teams -and -not $SkipTeams) {
        Write-Host "  [*] Teams: Meeting, external access, client policies..."
        Invoke-NLSCollector 'Invoke-NLSCollectTeams'
    }

    if ($conn.IPPSSession -and -not $SkipPurview) {
        Write-Host "  [*] Purview: Audit, DLP, retention, sensitivity labels..."
        Invoke-NLSCollector 'Invoke-NLSCollectPurview'
    }

    # Copilot collector runs after Purview so it can reuse label/DLP/audit raw data
    if ($conn.Graph) {
        Write-Host "  [*] M365 Copilot: Licensing, label alignment, DLP coverage, Studio bots..."
        Invoke-NLSCollector 'Invoke-NLSCollectM365Copilot'
    }

    # ── Run evaluators ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

    function Invoke-NLSEvaluator { param([string]$fn)
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try { & $fn }
            catch {
                # Strict-mode tightening (v4.6.x audit fix): a property-access
                # crash on partial collector data now surfaces both as a warning
                # for the operator console AND as a Register-NLSException so the
                # incident is captured in the JSON output for follow-up.
                $errMsg = $_.Exception.Message.Split([char]10)[0]
                Write-Warning "Evaluator $($fn) — $errMsg"
                if (Get-Command Register-NLSException -ErrorAction SilentlyContinue) {
                    try { Register-NLSException -Source $fn -Message $errMsg } catch { }
                }
            }
        }
    }

    # All evaluators discovered by name from the loaded module
    $evaluators = @(Get-Command -Module NLS-Assessment -Name 'Test-NLSControl*' -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name)

    # ── -Quick: filter evaluators to those that handle Critical / High controls
    # NOTE: filter is by evaluator FUNCTION name, so any workload-level function
    # that handles BOTH Critical/High and Medium/Low controls (DEF-1.x, PVW-*,
    # SPO-*, etc) will still emit its Low/Medium findings. The maturity badge
    # and HTML score ring reflect the actual set, not the requested severity
    # range. Treat -Quick as "skip the workloads that ONLY have low-severity
    # checks" rather than "skip every Low/Medium finding."
    if ($Quick) {
        $highSevEvaluators = @{}
        # Fail-closed: a corrupt controls.json must not silently produce a
        # filter that excludes every evaluator and exits 2 ("no findings").
        # The outer try/catch already turns this into fatal=4 with a message.
        foreach ($ctrl in (Get-NLSControlDefinitions)) {
            if ($ctrl.Severity -in @('Critical','High') -and $ctrl.EvaluatorFunction) {
                $highSevEvaluators[$ctrl.EvaluatorFunction] = $true
            }
        }
        $beforeCount = $evaluators.Count
        $evaluators  = @($evaluators | Where-Object { $highSevEvaluators.ContainsKey($_) })
        Write-Host "  [i] Quick mode: $($evaluators.Count) of $beforeCount evaluators (workloads with Critical+High only; lower-severity findings inside those workloads still surface)" -ForegroundColor Yellow
    }

    foreach ($ev in $evaluators) {
        Invoke-NLSEvaluator $ev
    }

    $findings = Get-NLSFindings
    Write-Host "  [+] $($findings.Count) findings evaluated" -ForegroundColor Green

    # ── Build report metadata ────────────────────────────────────────────────
    $tenantTag = if ($conn.TenantDomain) { ($conn.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    $reportMetadata = @{
        TenantDomain   = $conn.TenantDomain
        TenantId       = $conn.TenantId
        Operator       = $UserPrincipalName
        AssessmentDate = (Get-Date).ToString('MMMM dd, yyyy')
        AssessmentTime = (Get-Date).ToString('o')
        ToolVersion    = $NLSAssessmentVersion
        Brand          = $NLSBrand
        QuickScan      = [bool]$Quick
    }
}

# ── Maturity tier (roadmap F1) ──────────────────────────────────────────────
# Derived from the final findings stream — recomputed every run including
# -FromResults so the badge always reflects the current findings, not whatever
# Maturity value (if any) the baseline JSON happened to carry. Result is
# embedded in the metadata so publishers (HTML, JSON, Markdown, Playbook,
# Delta) can render the same classification. Failure is logged + surfaced
# via the summary banner so a missing badge doesn't slip past the operator.
try {
    $reportMetadata['Maturity'] = Get-NLSMaturityTier -Findings $findings
} catch {
    Write-Warning "Maturity-tier classification failed: $($_.Exception.Message)"
    $reportMetadata['MaturityError'] = $_.Exception.Message
}

# ── Publish reports ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Generating reports..." -ForegroundColor Cyan

$jsonPath = Join-Path $OutputPath "$baseName-results.json"
# Capture the raw-data snapshot for drift detection on the NEXT run. The
# delta publisher compares this snapshot against a future run's snapshot to
# surface raw configuration changes (new CA policies, new admin assignments,
# new OAuth apps, DMARC policy regression) — not just finding state changes.
$rawDataSnapshot = if (Get-Command Get-NLSRawData -ErrorAction SilentlyContinue) {
    Get-NLSRawData
} else { @{} }
# TOCTOU fix (v4.6.3 P2): Set-NLSSensitiveFileContent pre-creates the file
# and applies the ACL BEFORE any tenant data is written. Previously the
# file inherited the parent directory's permissions during Out-File and was
# only restricted afterwards via Set-Acl — on a shared MSP workstation a
# co-resident process polling the output dir could read tenant data in
# that small window.
$jsonPayload = @{
    Metadata    = $reportMetadata
    Findings    = $findings
    RawData     = $rawDataSnapshot
    Exceptions  = (Get-NLSExceptions)
    Coverage    = (Get-NLSCoverage)
    Connections = $conn
} | ConvertTo-Json -Depth 10
Set-NLSSensitiveFileContent -Path $jsonPath -Content $jsonPayload
Write-Host "  [+] JSON: $jsonPath" -ForegroundColor Green
Write-Host "      Baseline contains sensitive tenant inventory (CA policies, admin assignments, OAuth apps) — file ACL restricted to current user + admins. Path: $jsonPath" -ForegroundColor Yellow

if (-not $JsonOnly) {
    # ── Audit-finding fix (HIGH #2): every secondary report file gets the same
    #    ACL hardening as the JSON baseline. They all contain the same tenant
    #    inventory data (CA policies, admin UPNs, OAuth grants, DMARC records)
    #    rendered into a different format. Inherited permissions on a shared
    #    MSP workstation or synced OneDrive would otherwise make these world-
    #    readable. Set-NLSSensitiveFileAcl is a no-op on non-Windows.
    # Markdown summary
    if (Get-Command Publish-NLSAssessmentSummary -ErrorAction SilentlyContinue) {
        $mdPath = Join-Path $OutputPath "$baseName-assessment.md"
        try {
            Publish-NLSAssessmentSummary -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $mdPath
            Write-Host "  [+] Markdown: $mdPath" -ForegroundColor Green
            Set-NLSSensitiveFileAcl -Path $mdPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Markdown publish failed: $($_.Exception.Message)" }
    }

    # HTML report
    if (Get-Command Publish-NLSAssessmentHTML -ErrorAction SilentlyContinue) {
        $htmlPath = Join-Path $OutputPath "$baseName-assessment.html"
        try {
            Publish-NLSAssessmentHTML -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $htmlPath
            Write-Host "  [+] HTML: $htmlPath" -ForegroundColor Green
            Set-NLSSensitiveFileAcl -Path $htmlPath -ErrorAction SilentlyContinue
        } catch {
        $stack = $_.ScriptStackTrace
        Write-Warning "HTML failed: $($_.Exception.Message)"
        Write-Warning "Stack: $stack"
    }
    }

    # Remediation playbook + executive summary
    # The publisher writes two deliverables: an engineer playbook (-OutputPath)
    # and a client-facing executive summary (-ExecutivePath). Both -Connections
    # and -ExecutivePath are mandatory on the function — omitting them in v4.6.1
    # caused PowerShell to interactively prompt and then fail.
    if (Get-Command Publish-NLSRemediationPlaybook -ErrorAction SilentlyContinue) {
        $pbPath     = Join-Path $OutputPath "$baseName-playbook.md"
        $execPath   = Join-Path $OutputPath "$baseName-executive.md"
        $pbHtmlPath = Join-Path $OutputPath "$baseName-playbook.html"
        try {
            Publish-NLSRemediationPlaybook `
                -Metadata $reportMetadata `
                -Findings $findings `
                -Connections $conn `
                -OutputPath $pbPath `
                -ExecutivePath $execPath `
                -HtmlOutputPath $pbHtmlPath
            Write-Host "  [+] Playbook (md):   $pbPath" -ForegroundColor Green
            Write-Host "  [+] Playbook (html): $pbHtmlPath" -ForegroundColor Green
            Write-Host "  [+] Executive:       $execPath" -ForegroundColor Green
            Set-NLSSensitiveFileAcl -Path $pbPath     -ErrorAction SilentlyContinue
            Set-NLSSensitiveFileAcl -Path $execPath   -ErrorAction SilentlyContinue
            Set-NLSSensitiveFileAcl -Path $pbHtmlPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Playbook publish failed: $($_.Exception.Message)" }
    }

    # Remediation script
    if (Get-Command Publish-NLSRemediationScript -ErrorAction SilentlyContinue) {
        $rsPath = Join-Path $OutputPath "$baseName-remediation.ps1"
        try {
            Publish-NLSRemediationScript -Metadata $reportMetadata -Findings $findings -OutputPath $rsPath
            Write-Host "  [+] Remediation: $rsPath" -ForegroundColor Green
            Set-NLSSensitiveFileAcl -Path $rsPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Remediation publish failed: $($_.Exception.Message)" }
    }

    # XLSX compliance matrix
    if (Get-Command Publish-NLSComplianceMatrix -ErrorAction SilentlyContinue) {
        $xlsxPath = Join-Path $OutputPath "$baseName-compliance-matrix.xlsx"
        try {
            Publish-NLSComplianceMatrix -Metadata $reportMetadata -Findings $findings -OutputPath $xlsxPath
            Write-Host "  [+] XLSX matrix: $xlsxPath" -ForegroundColor Green
            Set-NLSSensitiveFileAcl -Path $xlsxPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "XLSX publish failed: $($_.Exception.Message)" }
    }

    # Delta report (if baseline provided)
    if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults) -and (Get-Command Publish-NLSDeltaReport -ErrorAction SilentlyContinue)) {
        $deltaPath = Join-Path $OutputPath "$baseName-delta.md"
        try {
            Publish-NLSDeltaReport -CurrentFindings $findings -CurrentRawData $rawDataSnapshot -BaselineResultsPath $BaselineResults `
                -Metadata $reportMetadata -OutputPath $deltaPath
            Write-Host "  [+] Delta: $deltaPath" -ForegroundColor Green
            Set-NLSSensitiveFileAcl -Path $deltaPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Delta publish failed: $($_.Exception.Message)" }
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
$s = @{
    Satisfied = @($findings | Where-Object State -eq 'Satisfied').Count
    Partial   = @($findings | Where-Object State -eq 'Partial').Count
    Gap       = @($findings | Where-Object State -eq 'Gap').Count
    NA        = @($findings | Where-Object State -eq 'NotApplicable').Count
}

# Footer version + control count read at runtime so a stale hardcoded value
# never ships in the operator output. Falls back to the count of findings the
# evaluators actually emitted this run rather than guessing at "total controls
# defined in controls.json" which can drift from baseline coverage.
$footerVer    = if ($NLSAssessmentVersion)   { $NLSAssessmentVersion }   else { $script:NLSAssessmentVersion }
$footerCount  = $findings.Count

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Assessment Complete (v$footerVer / $footerCount controls)"      -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Satisfied      $($s.Satisfied)"                                  -ForegroundColor Green
Write-Host "  Partial        $($s.Partial)"                                    -ForegroundColor Yellow
Write-Host "  Gap            $($s.Gap)"                                        -ForegroundColor Red
Write-Host "  Not Applicable $($s.NA)"                                         -ForegroundColor DarkGray
Write-Host "  Total          $($findings.Count)"                               -ForegroundColor White
Write-Host "  Output         $OutputPath"                                      -ForegroundColor White
if ($reportMetadata.Contains('Maturity') -and $reportMetadata['Maturity']) {
    $m = $reportMetadata['Maturity']
    Write-Host "  Maturity       $($m.Label) (tier $($m.Tier)/5, score $($m.Score)/100)" -ForegroundColor Cyan
} elseif ($reportMetadata.Contains('MaturityError')) {
    Write-Host "  Maturity       unavailable ($($reportMetadata['MaturityError']))" -ForegroundColor Yellow
}
Write-Host ""

# ── Threshold exit codes (CI / automation) ────────────────────────────────────
# Opt-in policy gate (default 0 = disabled). Reads pre-computed counts from
# $reportMetadata['Maturity'] so the badge in the report and the threshold the
# CI fires on can never disagree — the older inline `Where-Object` re-derivation
# meant a future change to the maturity counter rule (e.g., excluding Error
# from Gap counts) would silently split into two answers.
#
# Threshold codes (10/11/12) land on $script:NLSThresholdExitCode — a separate
# channel from $script:NLSFatalExitCode (1=auth, 4=fatal). This preserves the
# disambiguation between "graceful policy breach, all reports on disk" and
# "orchestrator crashed mid-publish": the final exit-resolution block at the
# bottom of this script gives fatal precedence over threshold, threshold
# precedence over success.
#
# If the Maturity helper failed (-FailOnScoreBelow uses it), the threshold is
# explicitly skipped with a warning rather than silently no-op'd. Operators
# wiring a CI gate get a loud signal when the gate becomes inoperative.
if ($FailOnCritical -gt 0 -or $FailOnHigh -gt 0 -or $FailOnScoreBelow -gt 0) {
    $mat = if ($reportMetadata.Contains('Maturity')) { $reportMetadata['Maturity'] } else { $null }
    $critGaps = if ($mat) { [int]$mat.CriticalGaps } else { 0 }
    $highGaps = if ($mat) { [int]$mat.HighGaps }     else { 0 }

    if ($FailOnCritical -gt 0 -and $critGaps -ge $FailOnCritical) {
        Write-Host "[!] Threshold breached: $critGaps Critical gaps (limit $FailOnCritical) — exiting 10" -ForegroundColor Red
        $script:NLSThresholdExitCode = 10
    }
    elseif ($FailOnHigh -gt 0 -and $highGaps -ge $FailOnHigh) {
        Write-Host "[!] Threshold breached: $highGaps High gaps (limit $FailOnHigh) — exiting 11" -ForegroundColor Red
        $script:NLSThresholdExitCode = 11
    }
    elseif ($FailOnScoreBelow -gt 0) {
        if ($mat -and $mat.Contains('Score') -and $null -ne $mat.Score) {
            $maturityScore = [int]$mat.Score
            if ($maturityScore -lt $FailOnScoreBelow) {
                Write-Host "[!] Threshold breached: score $maturityScore < $FailOnScoreBelow — exiting 12" -ForegroundColor Red
                $script:NLSThresholdExitCode = 12
            }
        } else {
            Write-Warning "-FailOnScoreBelow $FailOnScoreBelow is set but Maturity score is unavailable — skipping threshold check. Investigate the maturity warning above; the CI gate is INOPERATIVE for this run."
        }
    }
}

# ── Exit-code spec (v4.6.3 P2) ────────────────────────────────────────────────
# CLAUDE.md declares: 0 success, 1 auth failure, 2 no findings, 3 partial
# collection, 4 fatal. Previously only exit 1 (module-load failure) was
# wired. This block computes the right code based on counters set above.
$collectorExceptions = @(Get-NLSExceptions)
if ($findings.Count -eq 0) {
    $script:NLSSuccessExitCode = 2
} elseif ($collectorExceptions.Count -gt 0) {
    # Partial collection: at least one collector raised, but some findings made it.
    $script:NLSSuccessExitCode = 3
} else {
    $script:NLSSuccessExitCode = 0
}

}
catch {
    # Outer fatal-error catch (v4.6.3 P2).
    # $script:NLSFatalExitCode may have been pre-set by an earlier explicit
    # condition (auth failure = 1); otherwise fall through to 4 (fatal).
    if (-not $script:NLSFatalExitCode) { $script:NLSFatalExitCode = 4 }
    Write-Host ""
    Write-Host "[!] Assessment failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    }
}
finally {
    # ── Disconnect on success or error ────────────────────────────────────────
    if (-not $skipCollection) {
        try { Disconnect-NLSServices } catch { }
    }
}

# Resolve and emit the exit code (must be done OUTSIDE the try/catch/finally
# so the exit happens after the disconnect runs).
# Precedence: fatal (auth/crash) > threshold (policy gate) > success.
# Threshold only applies when no fatal error occurred — a crash that happens
# to leave a threshold value set must not masquerade as a graceful breach.
if ($script:NLSFatalExitCode) {
    exit $script:NLSFatalExitCode
}
if ($script:NLSThresholdExitCode) {
    exit $script:NLSThresholdExitCode
}
if ($null -ne $script:NLSSuccessExitCode) {
    exit $script:NLSSuccessExitCode
}
exit 0