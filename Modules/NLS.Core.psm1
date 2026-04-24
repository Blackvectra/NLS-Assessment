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

function New-NLSModuleHashManifest {
    <#
    .SYNOPSIS
        Generates SHA-256 hash manifest for all NLS modules.
        Run once after a clean install or update to establish baseline.
        Output saved as modules.sha256 in the Modules directory.
    #>
    param([string]$ModulesPath)

    $manifest = [ordered]@{}
    $psm1Files = Get-ChildItem -Path $ModulesPath -Filter '*.psm1' -ErrorAction Stop

    foreach ($file in $psm1Files) {
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $manifest[$file.Name] = $hash
    }

    $manifestPath = Join-Path $ModulesPath 'modules.sha256'
    $manifest | ConvertTo-Json -Depth 2 | Out-File -FilePath $manifestPath -Encoding utf8 -Force
    Write-Host "  [+] Hash manifest written to: $manifestPath" -ForegroundColor Green
    return $manifest
}

function Test-NLSModuleIntegrity {
    <#
    .SYNOPSIS
        Verifies NLS modules against SHA-256 hash manifest and expected path.
        If no manifest exists, performs path-only check and warns.
        Prevents both path-based injection and in-place file tampering.
    #>
    param([string]$ExpectedModulesPath)

    $violations = @()
    $warnings   = @()

    # Step 1 -- path verification
    $nlsModules = Get-Module | Where-Object { $_.Name -like 'NLS.*' }
    foreach ($mod in $nlsModules) {
        $modPath = Split-Path $mod.Path -Parent
        if ($modPath -ne $ExpectedModulesPath) {
            $violations += [ordered]@{
                Module       = $mod.Name
                LoadedFrom   = $mod.Path
                ExpectedPath = $ExpectedModulesPath
                Type         = 'PathViolation'
            }
        }
    }

    # Step 2 -- hash verification against manifest
    $manifestPath = Join-Path $ExpectedModulesPath 'modules.sha256'
    if (Test-Path $manifestPath) {
        try {
            $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
            $psm1Files = Get-ChildItem -Path $ExpectedModulesPath -Filter '*.psm1' -ErrorAction Stop

            foreach ($file in $psm1Files) {
                $expectedHash = $manifest.($file.Name)
                if (-not $expectedHash) {
                    $warnings += "No hash in manifest for: $($file.Name)"
                    continue
                }
                $actualHash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                if ($actualHash -ne $expectedHash) {
                    $violations += [ordered]@{
                        Module       = $file.Name
                        LoadedFrom   = $file.FullName
                        ExpectedPath = $ExpectedModulesPath
                        Type         = 'HashMismatch'
                        Expected     = $expectedHash
                        Actual       = $actualHash
                    }
                }
            }
        } catch {
            $warnings += "Hash manifest could not be read: $($_.Exception.Message)"
        }
    } else {
        $warnings += 'No hash manifest found. Run New-NLSModuleHashManifest to establish baseline. Path-only check applied.'
    }

    return [ordered]@{
        Passed     = $violations.Count -eq 0
        Violations = $violations
        Warnings   = $warnings
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

function Invoke-NLSRedaction {
    <#
    .SYNOPSIS
        Central redaction function. Applies to both report content and exceptions log.
        Covers UPNs, GUIDs, IPv4, IPv6, and tenant-specific URLs.
    #>
    param([string]$Content)

    # UPNs and email addresses
    $Content = $Content -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED_UPN]'
    # GUIDs
    $Content = $Content -replace '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '[REDACTED_ID]'
    # IPv4
    $Content = $Content -replace '(?:[0-9]{1,3}\.){3}[0-9]{1,3}', '[REDACTED_IP]'
    # IPv6 -- full and compressed forms
    $Content = $Content -replace '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', '[REDACTED_IP]'
    $Content = $Content -replace '(?:[a-fA-F0-9]{1,4}:){1,7}:', '[REDACTED_IP]'
    $Content = $Content -replace '::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}', '[REDACTED_IP]'
    # Tenant-specific URLs
    $Content = $Content -replace 'https://[a-zA-Z0-9\-\.]+\.microsoft\.com[^\s]*', '[REDACTED_URL]'
    $Content = $Content -replace 'https://[a-zA-Z0-9\-\.]+\.office\.com[^\s]*', '[REDACTED_URL]'
    $Content = $Content -replace 'https://[a-zA-Z0-9\-\.]+\.sharepoint\.com[^\s]*', '[REDACTED_URL]'
    return $Content
}

function Protect-NLSExceptionsRedaction {
    param([string]$Content)
    return Invoke-NLSRedaction -Content $Content
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
    New-NLSModuleHashManifest, `
    Test-NLSInputUPN, `
    Protect-NLSOutputPath, `
    Protect-NLSExceptionsRedaction, `
    Invoke-NLSRedaction
