#
# NLS.Core.psm1
# NextLayerSec Assessment Framework -- Core Module
# Output safety, coverage tracking, exception handling
#
# Author:  NextLayerSec
# Version: 2.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

$script:Exceptions = @()
$script:CoverageMap = [ordered]@{}

# ─────────────────────────────────────────────
# Security Controls
# ─────────────────────────────────────────────

function Test-NLSModuleIntegrity {
    <#
    .SYNOPSIS
        Verifies all loaded NLS modules are from the expected path.
        Prevents malicious psm1 injection into the Modules directory.
    #>
    param([string]$ExpectedModulesPath)

    $nlsModules = Get-Module | Where-Object { $_.Name -like 'NLS.*' }
    $violations  = @()

    foreach ($mod in $nlsModules) {
        $modPath = Split-Path $mod.Path -Parent
        if ($modPath -ne $ExpectedModulesPath) {
            $violations += [ordered]@{
                Module       = $mod.Name
                LoadedFrom   = $mod.Path
                ExpectedPath = $ExpectedModulesPath
            }
        }
    }

    return [ordered]@{
        Passed     = $violations.Count -eq 0
        Violations = $violations
    }
}

function Test-NLSInputUPN {
    <#
    .SYNOPSIS
        Validates UPN format before passing to Exchange/Graph connections.
        Prevents malformed input from reaching connection cmdlets.
    #>
    param([string]$UPN)

    if ([string]::IsNullOrWhiteSpace($UPN)) {
        return [ordered]@{ Valid = $false; Reason = 'UPN cannot be empty' }
    }

    # RFC 5321 basic format check
    if ($UPN -notmatch '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$') {
        return [ordered]@{ Valid = $false; Reason = "UPN format invalid: $UPN" }
    }

    return [ordered]@{ Valid = $true; Reason = '' }
}

function Protect-NLSOutputPath {
    <#
    .SYNOPSIS
        Validates and locks down the output directory permissions.
        Reduces risk of output tampering on shared systems.
    #>
    param([string]$OutputPath)

    try {
        $acl = Get-Acl -Path $OutputPath -ErrorAction Stop
        # Restrict to current user only
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule($rule)
        Set-Acl -Path $OutputPath -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        # Non-fatal -- log but continue
        return $false
    }
}

function Protect-NLSExceptionsRedaction {
    <#
    .SYNOPSIS
        Applies redaction to exceptions log content.
        v2 fix -- exceptions were not redacted even when -RedactSensitiveData was passed.
    #>
    param([string]$Content)

    $Content = $Content -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED_UPN]'
    $Content = $Content -replace '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '[REDACTED_ID]'
    $Content = $Content -replace '(?:[0-9]{1,3}\.){3}[0-9]{1,3}', '[REDACTED_IP]'
    # Scrub tenant-specific URLs
    $Content = $Content -replace 'https://[a-zA-Z0-9\-\.]+\.microsoft\.com[^\s]*', '[REDACTED_URL]'
    $Content = $Content -replace 'https://[a-zA-Z0-9\-\.]+\.office\.com[^\s]*', '[REDACTED_URL]'
    return $Content
}

function Export-NLSSafeMarkdown {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$OutPath,
        [bool]$Redact = $false
    )
    if ($Redact) {
        $Content = $Content -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED_UPN]'
        $Content = $Content -replace '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '[REDACTED_ID]'
        $Content = $Content -replace '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[REDACTED_IP]'
    }
    $Content | Out-File -FilePath $OutPath -Encoding utf8 -Force
}

function Register-NLSCoverage {
    param(
        [Parameter(Mandatory = $true)][string]$ControlFamily,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Collected', 'Partial', 'NotCollected', 'Unsupported')]
        [string]$Status,
        [string]$Reason = ''
    )
    $script:CoverageMap[$ControlFamily] = [ordered]@{
        Status = $Status
        Reason = $Reason
    }
}

function Get-NLSCoverageMap { return $script:CoverageMap }

function Register-NLSException {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$ErrorDetails = ''
    )
    $script:Exceptions += [ordered]@{
        Timestamp    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Source       = $Source
        Message      = $Message
        ErrorDetails = $ErrorDetails
    }
}

function Get-NLSExceptions { return $script:Exceptions }

function Get-NLSMetadata {
    param(
        [bool]$Redact = $false,
        [string[]]$ActiveFrameworks = @(),
        [string[]]$ActiveFeatures = @(),
        [string]$ExecutionMode = 'Full'
    )
    $mgContext   = Get-MgContext -ErrorAction SilentlyContinue
    $exoModule   = Get-Module ExchangeOnlineManagement -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $graphModule = Get-Module Microsoft.Graph.Authentication -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $upn = if ($mgContext) { $mgContext.Account } else { 'Unknown' }
    if ($Redact -and $upn -ne 'Unknown') { $upn = '[REDACTED_ADMIN_UPN]' }
    [ordered]@{
        ExecutionTimeUTC  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        AuthContext       = $upn
        ExecutionMode     = $ExecutionMode
        ActiveFrameworks  = if ($ActiveFrameworks.Count -gt 0) { $ActiveFrameworks -join ', ' } else { 'NIST (default)' }
        ActiveFeatures    = if ($ActiveFeatures.Count -gt 0) { $ActiveFeatures -join ', ' } else { 'Standard' }
        GraphScopes       = if ($mgContext) { ($mgContext.Scopes -join ', ') } else { $null }
        ModuleVersions    = [ordered]@{
            ExchangeOnlineManagement     = if ($exoModule) { $exoModule.Version.ToString() } else { 'Not found' }
            MicrosoftGraphAuthentication = if ($graphModule) { $graphModule.Version.ToString() } else { 'Not found' }
        }
    }
}

Export-ModuleMember -Function `
    Export-NLSSafeMarkdown, `
    Register-NLSCoverage, `
    Get-NLSCoverageMap, `
    Register-NLSException, `
    Get-NLSExceptions, `
    Get-NLSMetadata, `
    Test-NLSModuleIntegrity, `
    Test-NLSInputUPN, `
    Protect-NLSOutputPath, `
    Protect-NLSExceptionsRedaction
