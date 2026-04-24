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
            if ($policy.GrantControls) {
                # Check BuiltInControls for legacy MFA grant
                if ($policy.GrantControls.BuiltInControls) {
                    $hasMfaGrant = $policy.GrantControls.BuiltInControls -contains 'mfa'
                }
                # Also check AuthenticationStrength -- newer policies use this instead of mfa grant
                if (-not $hasMfaGrant -and $policy.GrantControls.AuthenticationStrength) {
                    $hasMfaGrant = $true
                }
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
        # MFA check -- any enabled policy with MFA grant OR AuthenticationStrength targeting all users
        # Also accept any enabled policy with 'mfa' or 'multifactor' in the name as a signal
        $hasMfaAllUsers      = ($policyResults | Where-Object {
            $_.IsEnabled -and ($_.HasMfaGrant -or $_.DisplayName -match 'mfa|multifactor|multi-factor')
        }).Count -gt 0
        $hasDeviceCompliance = $deviceCompliant -gt 0
        $hasHighRiskBlock    = ($policyResults | Where-Object {
            $_.IsEnabled -and $_.DisplayName -match 'risk|Risk'
        }).Count -gt 0
        $hasAdminMfa         = ($policyResults | Where-Object {
            $_.IsEnabled -and $_.DisplayName -match 'admin|Admin|privileged|Privileged|phishing'
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
                        if ($Redact) {
                            '[REDACTED_UPN]'
                        } else {
                            $user = Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue
                            if ($user) { $user.UserPrincipalName } else { $null }
                        }
                    } | Where-Object { $_ })
                }
            }
        }

        $globalAdmins     = ($roleInventory | Where-Object { $_.RoleName -eq 'Global Administrator' })
        $globalAdminCount = if ($globalAdmins) { $globalAdmins.MemberCount } else { 0 }
        $highPrivCountRaw = ($roleInventory | Where-Object { $_.IsHighPriv } | Measure-Object -Property MemberCount -Sum).Sum
        $highPrivCount    = if ($null -eq $highPrivCountRaw) { 0 } else { $highPrivCountRaw }

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
                $upn         = if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
                $displayName = if ($Redact) { '[REDACTED]' } else { $_.DisplayName }
                $lastSign    = if ($_.SignInActivity) { $_.SignInActivity.LastSignInDateTime } else { 'Never' }
                [ordered]@{ UPN = $upn; DisplayName = $displayName; LastSignIn = $lastSign; State = $_.ExternalUserState }
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
                    # DisplayName is admin-defined network name, not user PII -- not redacted
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

        # Exclude Microsoft first-party service principals -- these are expected and not a risk
        $msFirstPartyAppIds = @(
            '00000003-0000-0000-c000-000000000000', # Microsoft Graph
            '00000003-0000-0ff1-ce00-000000000000', # Office 365 SharePoint Online
            '00000002-0000-0ff1-ce00-000000000000', # Office 365 Exchange Online
            '00000002-0000-0000-c000-000000000000', # Windows Azure Active Directory
            '00000004-0000-0ff1-ce00-000000000000', # Skype for Business Online
            '00000006-0000-0ff1-ce00-000000000000', # Microsoft Office
            '00000007-0000-0ff1-ce00-000000000000', # Common Data Service
            'c5393580-f805-4401-95e8-94b7a6ef2fc2', # Office 365 Management APIs
            'fc780465-2017-40d4-a0c5-307022471b92', # Microsoft Teams
            '00000005-0000-0000-c000-000000000000'  # Microsoft Azure PowerShell
        )

        $highPrivSPs = @($servicePrincipals | Where-Object {
            $sp = $_
            -not ($msFirstPartyAppIds -contains $sp.AppId) -and
            ($sp.AppRoles | Where-Object { $highPrivPermissions -contains $_.Value })
        })

        $results['ServicePrincipalInventory'] = [ordered]@{
            TotalServicePrincipals = $servicePrincipals.Count
            HighPrivilegeCount     = $highPrivSPs.Count
            HighPrivilegeList      = @($highPrivSPs | ForEach-Object {
                [ordered]@{
                    DisplayName = $_.DisplayName  # App display names are not PII
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

function Get-NLSIdentityHardening {
    <#
    .SYNOPSIS
        Extended identity hardening checks.
        Covers password protection, SSPR, security defaults, legacy per-user MFA,
        PIM, consent framework, external collaboration, and authentication methods.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    # ── Security Defaults ────────────────────────────────────
    try {
        $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $results['SecurityDefaults'] = [ordered]@{
            IsEnabled = $secDefaults.IsEnabled
        }
        Register-NLSCoverage -ControlFamily 'SecurityDefaults' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:SecurityDefaults' -Message 'Failed to check security defaults' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'SecurityDefaults' -Status 'Partial' -Reason $_.Exception.Message
        $results['SecurityDefaults'] = $null
    }

    # ── Password Protection ──────────────────────────────────
    try {
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        $results['PasswordProtection'] = [ordered]@{
            PolicyDescription = $authMethodPolicy.Description
            PolicyVersion     = $authMethodPolicy.PolicyVersion
        }
        Register-NLSCoverage -ControlFamily 'PasswordProtection' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:PasswordProtection' -Message 'Failed to check password protection policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'PasswordProtection' -Status 'Partial' -Reason $_.Exception.Message
        $results['PasswordProtection'] = $null
    }

    # ── SSPR ─────────────────────────────────────────────────
    try {
        $sspr = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $results['SSPR'] = [ordered]@{
            AllowedToResetPassword         = $sspr.AllowedToResetPassword
            DefaultUserRolePermissions     = $sspr.DefaultUserRolePermissions
        }
        Register-NLSCoverage -ControlFamily 'SSPR' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:SSPR' -Message 'Failed to check SSPR/authorization policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'SSPR' -Status 'Partial' -Reason $_.Exception.Message
        $results['SSPR'] = $null
    }

    # ── Authentication Methods ───────────────────────────────
    try {
        $authMethods = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        $fido2 = $authMethods.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq 'Fido2' }
        $msAuth = $authMethods.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq 'MicrosoftAuthenticator' }
        $sms    = $authMethods.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq 'Sms' }
        $results['AuthenticationMethods'] = [ordered]@{
            FIDO2Enabled                 = ($fido2 -and $fido2.State -eq 'enabled')
            MicrosoftAuthenticatorEnabled = ($msAuth -and $msAuth.State -eq 'enabled')
            SMSEnabled                   = ($sms -and $sms.State -eq 'enabled')
        }
        Register-NLSCoverage -ControlFamily 'AuthenticationMethods' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:AuthMethods' -Message 'Failed to check authentication methods policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'AuthenticationMethods' -Status 'Partial' -Reason $_.Exception.Message
        $results['AuthenticationMethods'] = $null
    }

    # ── App Consent Framework ────────────────────────────────
    try {
        $authzPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $userConsentEnabled = $authzPolicy.DefaultUserRolePermissions.AllowedToCreateApps
        $results['ConsentFramework'] = [ordered]@{
            UsersCanConsentToApps        = $userConsentEnabled
            DefaultUserCanCreateApps     = $authzPolicy.DefaultUserRolePermissions.AllowedToCreateApps
            DefaultUserCanCreateTenants  = $authzPolicy.DefaultUserRolePermissions.AllowedToCreateTenants
        }
        Register-NLSCoverage -ControlFamily 'ConsentFramework' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:ConsentFramework' -Message 'Failed to check consent framework policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ConsentFramework' -Status 'Partial' -Reason $_.Exception.Message
        $results['ConsentFramework'] = $null
    }

    # ── External Collaboration ───────────────────────────────
    try {
        $extCollab = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $results['ExternalCollaboration'] = [ordered]@{
            GuestInvitePolicy            = $extCollab.AllowInvitesFrom
            AllowExternalIdpSignup       = $extCollab.AllowExternalIdpSignup
        }
        Register-NLSCoverage -ControlFamily 'ExternalCollaboration' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:ExternalCollab' -Message 'Failed to check external collaboration policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ExternalCollaboration' -Status 'Partial' -Reason $_.Exception.Message
        $results['ExternalCollaboration'] = $null
    }

    # ── Privileged Identity Management ───────────────────────
    try {
        $permanentAdmins = Get-MgDirectoryRole -All -ErrorAction Stop | ForEach-Object {
            $role = $_
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            if ($members.Count -gt 0 -and $role.DisplayName -eq 'Global Administrator') {
                $members | ForEach-Object {
                    $upn = if ($Redact) { '[REDACTED_UPN]' } else {
                        (Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue).UserPrincipalName
                    }
                    $upn
                }
            }
        }
        $results['PIM'] = [ordered]@{
            PermanentGlobalAdmins    = @($permanentAdmins | Where-Object { $_ })
            PermanentGlobalAdminCount = ($permanentAdmins | Where-Object { $_ }).Count
            Note                     = 'PIM eligibility requires Azure AD P2. Permanent assignments shown above should be reviewed.'
        }
        Register-NLSCoverage -ControlFamily 'PIM' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSIdentityHardening:PIM' -Message 'Failed to check PIM/permanent admin assignments' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'PIM' -Status 'Partial' -Reason $_.Exception.Message
        $results['PIM'] = $null
    }

    return $results
}

function Get-NLSBreakGlassAccount {
    <#
    .SYNOPSIS
        Checks break-glass account configuration best practices.
        Break-glass accounts should be excluded from CA, monitored, and not licensed.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        # Look for accounts commonly named as break-glass
        $bgKeywords = @('breakglass', 'break-glass', 'break_glass', 'emergency', 'bg-', 'bg_')
        $allUsers   = Get-MgUser -All -Filter "accountEnabled eq true" `
            -Property 'displayName,userPrincipalName,assignedLicenses,signInActivity' `
            -ErrorAction Stop

        $bgAccounts = @($allUsers | Where-Object {
            $upn = $_.UserPrincipalName.ToLower()
            $bgKeywords | Where-Object { $upn -like "*$_*" }
        })

        # Check if break-glass accounts are excluded from CA policies
        $caPolicies     = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
        $bgExcludedFromCA = @()
        $bgNotExcluded    = @()

        foreach ($bg in $bgAccounts) {
            $excluded = $false
            foreach ($policy in ($caPolicies | Where-Object { $_.State -eq 'enabled' })) {
                if ($policy.Conditions.Users.ExcludeUsers -contains $bg.Id) {
                    $excluded = $true
                    break
                }
            }
            $upn = if ($Redact) { '[REDACTED_UPN]' } else { $bg.UserPrincipalName }
            if ($excluded) { $bgExcludedFromCA += $upn } else { $bgNotExcluded += $upn }
        }

        $results['BreakGlassAccounts'] = [ordered]@{
            Count             = $bgAccounts.Count
            ExcludedFromCA    = $bgExcludedFromCA
            NotExcludedFromCA = $bgNotExcluded
            Configured        = ($bgAccounts.Count -gt 0 -and $bgNotExcluded.Count -eq 0)
            Note              = 'Break-glass accounts should be excluded from all CA policies and monitored via alerts.'
        }
        Register-NLSCoverage -ControlFamily 'BreakGlassAccounts' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSBreakGlassAccount' -Message 'Failed to check break-glass accounts' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'BreakGlassAccounts' -Status 'Partial' -Reason $_.Exception.Message
        $results['BreakGlassAccounts'] = $null
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
    Get-NLSServicePrincipalInventory, `
    Get-NLSIdentityHardening, `
    Get-NLSBreakGlassAccount
