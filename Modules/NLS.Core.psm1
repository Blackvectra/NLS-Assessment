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
    Get-NLSMetadata
