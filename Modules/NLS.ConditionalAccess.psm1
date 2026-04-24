#
# NLS.ConditionalAccess.psm1
# NextLayerSec Assessment Framework -- Conditional Access Collector
# v2.0.0 -- CA inventory, recommended policies, user MFA gap, Secure Score
#
# Author:  NextLayerSec
# Version: 2.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Get-NLSConditionalAccessPolicies {
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        $policyResults = foreach ($policy in $policies) {
            $hasMfaGrant = $false
            if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls) {
                $hasMfaGrant = $policy.GrantControls.BuiltInControls -contains 'mfa'
            }
            $targetsLegacyAuth = $false
            if ($policy.Conditions.ClientAppTypes) {
                $legacyTypes = @('exchangeActiveSync', 'other')
                $targetsLegacyAuth = ($policy.Conditions.ClientAppTypes | Where-Object { $legacyTypes -contains $_ }).Count -gt 0
            }
            $targetsAllUsers = $false
            if ($policy.Conditions.Users.IncludeUsers) {
                $targetsAllUsers = $policy.Conditions.Users.IncludeUsers -contains 'All'
            }
            $requiresCompliantDevice = $false
            if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls) {
                $requiresCompliantDevice = $policy.GrantControls.BuiltInControls -contains 'compliantDevice'
            }
            $excludedUsers = @()
            if ($policy.Conditions.Users.ExcludeUsers -and -not $Redact) {
                $excludedUsers = $policy.Conditions.Users.ExcludeUsers
            }

            [ordered]@{
                DisplayName             = $policy.DisplayName
                State                   = $policy.State
                IsEnabled               = ($policy.State -eq 'enabled')
                IsReportOnly            = ($policy.State -eq 'enabledForReportingButNotEnforced')
                HasMfaGrant             = $hasMfaGrant
                TargetsAllUsers         = $targetsAllUsers
                TargetsLegacyAuth       = $targetsLegacyAuth
                RequiresCompliantDevice = $requiresCompliantDevice
                GrantControls           = if ($policy.GrantControls) { $policy.GrantControls.BuiltInControls -join ', ' } else { 'None' }
                ExcludedUsers           = $excludedUsers
            }
        }

        $enabledCount    = ($policyResults | Where-Object { $_.IsEnabled }).Count
        $reportOnlyCount = ($policyResults | Where-Object { $_.IsReportOnly }).Count
        $disabledCount   = ($policyResults | Where-Object { -not $_.IsEnabled -and -not $_.IsReportOnly }).Count
        $mfaPolicies     = ($policyResults | Where-Object { $_.HasMfaGrant -and $_.IsEnabled }).Count
        $legacyBlocking  = ($policyResults | Where-Object { $_.TargetsLegacyAuth -and $_.IsEnabled }).Count
        $deviceCompliant = ($policyResults | Where-Object { $_.RequiresCompliantDevice -and $_.IsEnabled }).Count

        # v2 -- detect missing recommended policies
        $hasLegacyBlock      = $legacyBlocking -gt 0
        $hasMfaAllUsers      = ($policyResults | Where-Object { $_.HasMfaGrant -and $_.TargetsAllUsers -and $_.IsEnabled }).Count -gt 0
        $hasDeviceCompliance = $deviceCompliant -gt 0
        $hasHighRiskBlock    = ($policyResults | Where-Object {
            $_.IsEnabled -and $_.DisplayName -match 'risk|Risk'
        }).Count -gt 0
        $hasAdminMfa         = ($policyResults | Where-Object {
            $_.IsEnabled -and $_.DisplayName -match 'admin|Admin|privileged|Privileged'
        }).Count -gt 0

        $missingPolicies = @()
        if (-not $hasLegacyBlock)      { $missingPolicies += 'Block legacy authentication for all users and all apps' }
        if (-not $hasMfaAllUsers)      { $missingPolicies += 'Require MFA for all users -- all cloud apps' }
        if (-not $hasDeviceCompliance) { $missingPolicies += 'Require compliant device for corporate resources' }
        if (-not $hasHighRiskBlock)    { $missingPolicies += 'Block access for high sign-in risk (Entra ID Protection)' }
        if (-not $hasAdminMfa)         { $missingPolicies += 'Require phishing-resistant MFA for privileged admin roles' }

        $results['ConditionalAccess'] = [ordered]@{
            TotalPolicies       = $policies.Count
            EnabledCount        = $enabledCount
            ReportOnlyCount     = $reportOnlyCount
            DisabledCount       = $disabledCount
            MfaEnforcingCount   = $mfaPolicies
            LegacyAuthBlocking  = $legacyBlocking
            DeviceCompliance    = $deviceCompliant
            Policies            = @($policyResults)
            MissingPolicies     = $missingPolicies
        }

        Register-NLSCoverage -ControlFamily 'ConditionalAccess' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSConditionalAccessPolicies' -Message 'Failed to retrieve CA policies from Graph' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ConditionalAccess' -Status 'Partial' -Reason $_.Exception.Message
        $results['ConditionalAccess'] = $null
    }

    return $results
}

function Get-NLSConditionalAccessTelemetry {
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $cutoff  = (Get-Date).ToUniversalTime().AddHours(-48).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter  = "createdDateTime ge $cutoff"
        $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop

        $legacyAttempts = $signIns | Where-Object {
            $_.ClientAppUsed -in @('Exchange ActiveSync', 'IMAP4', 'MAPI', 'POP3', 'SMTP', 'Other clients')
        }
        $mfaChallenged  = $signIns | Where-Object { $_.AuthenticationRequirement -eq 'multiFactorAuthentication' }
        $failures       = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 }

        # v2 -- surface accounts with legacy auth attempts
        $legacyByAccount = $legacyAttempts | Group-Object -Property UserPrincipalName | ForEach-Object {
            $upn = if ($Redact) { '[REDACTED_UPN]' } else { $_.Name }
            $protocol = ($_.Group | Group-Object ClientAppUsed | Sort-Object Count -Descending | Select-Object -First 1).Name
            [ordered]@{ UPN = $upn; Attempts = $_.Count; TopProtocol = $protocol }
        }

        $results['ConditionalAccessTelemetry'] = [ordered]@{
            WindowHours          = 48
            TotalSignIns         = $signIns.Count
            LegacyAuthAttempts   = $legacyAttempts.Count
            LegacyAuthByAccount  = @($legacyByAccount)
            MfaChallenged        = $mfaChallenged.Count
            FailedSignIns        = $failures.Count
            Note                 = 'Sign-in log data is sampled. Results reflect visible telemetry only.'
        }

        Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSConditionalAccessTelemetry' -Message 'Failed to retrieve sign-in logs from Graph' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' -Status 'Partial' -Reason $_.Exception.Message
        $results['ConditionalAccessTelemetry'] = $null
    }

    return $results
}

function Get-NLSUserMFAStatus {
    <#
    .SYNOPSIS
        Collects per-user MFA registration and enforcement status.
    .DESCRIPTION
        v2.0.0 -- New function. Requires Reports.Read.All scope.
        Returns per-user MFA registration state and method, allowing the
        report to surface exactly who has no MFA registered vs who has
        MFA registered but not enforced via CA policy.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $userRegs = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop

        $noMFA      = @($userRegs | Where-Object { -not $_.IsMfaRegistered })
        $mfaReg     = @($userRegs | Where-Object { $_.IsMfaRegistered })
        $mfaCapable = @($userRegs | Where-Object { $_.IsMfaCapable })

        $noMFAList = @($noMFA | ForEach-Object {
            $upn = if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
            [ordered]@{ UPN = $upn; IsAdmin = $_.IsAdmin }
        })

        $results['UserMFAStatus'] = [ordered]@{
            TotalUsers          = $userRegs.Count
            NoMFARegistered     = $noMFA.Count
            MFARegistered       = $mfaReg.Count
            MFACapable          = $mfaCapable.Count
            NoMFAList           = $noMFAList
            AdminsWithoutMFA    = ($noMFA | Where-Object { $_.IsAdmin }).Count
            Note                = 'Registration does not equal enforcement. CA policy enforcement is checked separately.'
        }

        Register-NLSCoverage -ControlFamily 'UserMFAStatus' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSUserMFAStatus' -Message 'Failed to retrieve user MFA registration details. Requires Reports.Read.All scope.' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'UserMFAStatus' -Status 'Partial' -Reason $_.Exception.Message
        $results['UserMFAStatus'] = $null
    }

    return $results
}

function Get-NLSSecureScore {
    <#
    .SYNOPSIS
        Retrieves Microsoft Secure Score and per-control recommendations.
    .DESCRIPTION
        v2.0.0 -- New function.
        Pulls current Secure Score and control profiles from Graph.
        Maps controls to existing assessment findings for unified reporting.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $scores  = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop
        $current = $scores | Select-Object -First 1

        $profiles = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop

        $controlSummary = @($profiles | ForEach-Object {
            [ordered]@{
                ControlName       = $_.ControlName
                Title             = $_.Title
                CurrentScore      = $_.CurrentScore
                MaxScore          = $_.MaxScore
                ImplementationStatus = $_.ImplementationStatus
                Threats           = $_.Threats -join ', '
                Remediation       = $_.Remediation
            }
        })

        $notImplemented = @($controlSummary | Where-Object { $_.ImplementationStatus -eq 'notImplemented' } |
            Sort-Object { [double]$_.MaxScore } -Descending |
            Select-Object -First 10)

        $results['SecureScore'] = [ordered]@{
            CurrentScore        = $current.CurrentScore
            MaxScore            = $current.MaxScore
            ScorePercentage     = if ($current.MaxScore -gt 0) { [math]::Round(($current.CurrentScore / $current.MaxScore) * 100, 1) } else { 0 }
            CreatedDate         = $current.CreatedDateTime
            TopGaps             = $notImplemented
            TotalControls       = $profiles.Count
            NotImplemented      = ($controlSummary | Where-Object { $_.ImplementationStatus -eq 'notImplemented' }).Count
            PartiallyImpl       = ($controlSummary | Where-Object { $_.ImplementationStatus -eq 'thirdParty' -or $_.ImplementationStatus -eq 'planned' }).Count
            FullyImplemented    = ($controlSummary | Where-Object { $_.ImplementationStatus -eq 'implemented' }).Count
        }

        Register-NLSCoverage -ControlFamily 'SecureScore' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSSecureScore' -Message 'Failed to retrieve Secure Score from Graph' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'SecureScore' -Status 'Partial' -Reason $_.Exception.Message
        $results['SecureScore'] = $null
    }

    return $results
}

Export-ModuleMember -Function `
    Get-NLSConditionalAccessPolicies, `
    Get-NLSConditionalAccessTelemetry, `
    Get-NLSUserMFAStatus, `
    Get-NLSSecureScore
