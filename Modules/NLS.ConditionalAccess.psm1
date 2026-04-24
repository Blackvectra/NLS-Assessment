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

function Get-NLSAdminRoleInventory {
    <#
    .SYNOPSIS
        Pulls all users with admin roles assigned via Graph.
        Surfaces over-privileged accounts and Global Admin sprawl.
        Requires Directory.Read.All scope.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $directoryRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $highPrivRoles  = @(
            'Global Administrator',
            'Privileged Role Administrator',
            'Security Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'Conditional Access Administrator',
            'Authentication Administrator',
            'Hybrid Identity Administrator'
        )

        $roleInventory = foreach ($role in $directoryRoles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            if ($members.Count -gt 0) {
                [ordered]@{
                    RoleName    = $role.DisplayName
                    IsHighPriv  = $highPrivRoles -contains $role.DisplayName
                    MemberCount = $members.Count
                    Members     = @($members | ForEach-Object {
                        $upn = if ($Redact) { '[REDACTED_UPN]' } else {
                            (Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue).UserPrincipalName
                        }
                        $upn
                    } | Where-Object { $_ })
                }
            }
        }

        $globalAdmins     = ($roleInventory | Where-Object { $_.RoleName -eq 'Global Administrator' })
        $globalAdminCount = if ($globalAdmins) { $globalAdmins.MemberCount } else { 0 }
        $highPrivCount    = ($roleInventory | Where-Object { $_.IsHighPriv } | Measure-Object -Property MemberCount -Sum).Sum

        $results['AdminRoleInventory'] = [ordered]@{
            TotalRolesAssigned  = ($roleInventory | Measure-Object).Count
            GlobalAdminCount    = $globalAdminCount
            HighPrivRoleCount   = $highPrivCount
            GlobalAdminExcessive = $globalAdminCount -gt 2
            Roles               = @($roleInventory)
        }

        Register-NLSCoverage -ControlFamily 'AdminRoleInventory' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSAdminRoleInventory' -Message 'Failed to retrieve admin role inventory' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'AdminRoleInventory' -Status 'Partial' -Reason $_.Exception.Message
        $results['AdminRoleInventory'] = $null
    }

    return $results
}

function Get-NLSStaleAccounts {
    <#
    .SYNOPSIS
        Surfaces user accounts inactive for 90+ days.
        Stale accounts are a common lateral movement and persistence vector.
        Requires AuditLog.Read.All scope.
    #>
    param(
        [bool]$Redact       = $false,
        [int]$ThresholdDays = 90
    )

    $results = [ordered]@{}

    try {
        $cutoff   = (Get-Date).AddDays(-$ThresholdDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter   = "signInActivity/lastSignInDateTime le $cutoff"
        $allUsers = Get-MgUser -All -Filter "accountEnabled eq true" `
            -Property 'displayName,userPrincipalName,signInActivity,assignedLicenses' `
            -ErrorAction Stop

        $staleUsers = @($allUsers | Where-Object {
            $_.SignInActivity -and
            $_.SignInActivity.LastSignInDateTime -and
            $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-$ThresholdDays)
        })

        $neverSignedIn = @($allUsers | Where-Object {
            -not $_.SignInActivity -or -not $_.SignInActivity.LastSignInDateTime
        })

        $results['StaleAccounts'] = [ordered]@{
            ThresholdDays       = $ThresholdDays
            TotalActiveUsers    = $allUsers.Count
            StaleCount          = $staleUsers.Count
            NeverSignedInCount  = $neverSignedIn.Count
            StaleList           = @($staleUsers | ForEach-Object {
                $upn      = if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
                $lastSign = $_.SignInActivity.LastSignInDateTime
                [ordered]@{ UPN = $upn; LastSignIn = $lastSign }
            })
            NeverSignedInList   = @($neverSignedIn | ForEach-Object {
                if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
            })
        }

        Register-NLSCoverage -ControlFamily 'StaleAccounts' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSStaleAccounts' -Message 'Failed to retrieve stale account data. Requires AuditLog.Read.All.' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'StaleAccounts' -Status 'Partial' -Reason $_.Exception.Message
        $results['StaleAccounts'] = $null
    }

    return $results
}

function Get-NLSGuestAccountInventory {
    <#
    .SYNOPSIS
        Surfaces external guest accounts with access to tenant resources.
        Guest accounts are a common BEC and supply chain attack vector.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $guests = Get-MgUser -All -Filter "userType eq 'Guest'" `
            -Property 'displayName,userPrincipalName,signInActivity,createdDateTime,externalUserState' `
            -ErrorAction Stop

        $activeGuests = @($guests | Where-Object { $_.SignInActivity -and $_.SignInActivity.LastSignInDateTime })
        $staleGuests  = @($guests | Where-Object {
            -not $_.SignInActivity -or
            -not $_.SignInActivity.LastSignInDateTime -or
            $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90)
        })

        $results['GuestAccountInventory'] = [ordered]@{
            TotalGuests         = $guests.Count
            ActiveGuests        = $activeGuests.Count
            StaleGuests         = $staleGuests.Count
            GuestList           = @($guests | ForEach-Object {
                $upn      = if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
                $lastSign = if ($_.SignInActivity) { $_.SignInActivity.LastSignInDateTime } else { 'Never' }
                [ordered]@{ UPN = $upn; LastSignIn = $lastSign; State = $_.ExternalUserState }
            })
        }

        Register-NLSCoverage -ControlFamily 'GuestAccountInventory' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSGuestAccountInventory' -Message 'Failed to retrieve guest account inventory' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'GuestAccountInventory' -Status 'Partial' -Reason $_.Exception.Message
        $results['GuestAccountInventory'] = $null
    }

    return $results
}

function Get-NLSNamedLocations {
    <#
    .SYNOPSIS
        Checks whether named locations are defined in Entra ID.
        Named locations are required for Zero Trust network trust segmentation.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $locations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop

        $results['NamedLocations'] = [ordered]@{
            TotalDefined    = $locations.Count
            HasNamedLocations = $locations.Count -gt 0
            Locations       = @($locations | ForEach-Object {
                [ordered]@{
                    DisplayName = $_.DisplayName
                    Type        = $_.OdataType
                    IsTrusted   = if ($_.AdditionalProperties.isTrusted) { $true } else { $false }
                }
            })
        }

        Register-NLSCoverage -ControlFamily 'NamedLocations' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSNamedLocations' -Message 'Failed to retrieve named locations' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'NamedLocations' -Status 'Partial' -Reason $_.Exception.Message
        $results['NamedLocations'] = $null
    }

    return $results
}

function Get-NLSServicePrincipalInventory {
    <#
    .SYNOPSIS
        Surfaces service principals with high-privilege Graph permissions.
        Over-permissioned service principals are a common persistence vector.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $highPrivPermissions = @(
            'Directory.ReadWrite.All',
            'User.ReadWrite.All',
            'Group.ReadWrite.All',
            'Mail.ReadWrite',
            'MailboxSettings.ReadWrite',
            'Files.ReadWrite.All',
            'Sites.FullControl.All',
            'RoleManagement.ReadWrite.Directory'
        )

        $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop |
            Where-Object { $_.AppRoles.Count -gt 0 -or $_.Oauth2PermissionScopes.Count -gt 0 }

        $highPrivSPs = @($servicePrincipals | Where-Object {
            $_.AppRoles | Where-Object { $highPrivPermissions -contains $_.Value }
        })

        $results['ServicePrincipalInventory'] = [ordered]@{
            TotalServicePrincipals = $servicePrincipals.Count
            HighPrivilegeCount     = $highPrivSPs.Count
            HighPrivilegeList      = @($highPrivSPs | ForEach-Object {
                [ordered]@{
                    DisplayName = $_.DisplayName
                    AppId       = if ($Redact) { '[REDACTED_ID]' } else { $_.AppId }
                    Publisher   = $_.PublisherName
                }
            })
        }

        Register-NLSCoverage -ControlFamily 'ServicePrincipalInventory' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSServicePrincipalInventory' -Message 'Failed to retrieve service principal inventory' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ServicePrincipalInventory' -Status 'Partial' -Reason $_.Exception.Message
        $results['ServicePrincipalInventory'] = $null
    }

    return $results
}

Export-ModuleMember -Function `
    Get-NLSConditionalAccessPolicies, `
    Get-NLSConditionalAccessTelemetry, `
    Get-NLSUserMFAStatus, `
    Get-NLSSecureScore, `
    Get-NLSAdminRoleInventory, `
    Get-NLSStaleAccounts, `
    Get-NLSGuestAccountInventory, `
    Get-NLSNamedLocations, `
    Get-NLSServicePrincipalInventory
