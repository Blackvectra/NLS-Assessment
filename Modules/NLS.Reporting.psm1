#
# NLS.Reporting.psm1
# NextLayerSec Assessment Framework -- Reporting Module
# v2.0.0 -- Granular object lists, current state vs recommended,
#           CA policy inventory, user MFA gap, Secure Score section
#
# Author:  NextLayerSec
# Version: 2.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Publish-NLSAssessmentSummary {
    param(
        [Parameter(Mandatory = $true)][hashtable]$ScoredResults,
        [Parameter(Mandatory = $true)][hashtable]$Metadata,
        [Parameter(Mandatory = $true)][hashtable]$Coverage,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [hashtable]$ExtendedData = @{},
        [hashtable]$DeltaData = @{},
        [bool]$Redact = $false
    )

    $findings = $ScoredResults.Findings
    $summary  = $ScoredResults.Summary
    $sb       = [System.Text.StringBuilder]::new()

    # ── Header ───────────────────────────────────────────────
    [void]$sb.AppendLine('# NextLayerSec M365 Security Assessment')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> Read-only assessment. No tenant configuration changes were made.')
    [void]$sb.AppendLine('> Missing telemetry is NOT equivalent to missing policy.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Metadata ─────────────────────────────────────────────
    [void]$sb.AppendLine('## Assessment Metadata')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Field | Value |')
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| Execution Time (UTC) | $($Metadata.ExecutionTimeUTC) |")
    [void]$sb.AppendLine("| Operator | $($Metadata.AuthContext) |")
    [void]$sb.AppendLine("| Execution Mode | $($Metadata.ExecutionMode) |")
    [void]$sb.AppendLine("| Frameworks Active | $($Metadata.ActiveFrameworks) |")
    [void]$sb.AppendLine("| Features Active | $($Metadata.ActiveFeatures) |")
    [void]$sb.AppendLine("| EXO Module Version | $($Metadata.ModuleVersions.ExchangeOnlineManagement) |")
    [void]$sb.AppendLine("| Graph Module Version | $($Metadata.ModuleVersions.MicrosoftGraphAuthentication) |")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Delta Report ─────────────────────────────────────────
    if ($DeltaData -and $DeltaData.Available) {
        Publish-NLSDeltaSection -Delta $DeltaData -StringBuilder $sb
    }

    # ── Secure Score ─────────────────────────────────────────
    $secureScore = $ExtendedData['SecureScore']
    if ($secureScore) {
        [void]$sb.AppendLine('## Microsoft Secure Score')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("| Metric | Value |")
        [void]$sb.AppendLine('|---|---|')
        [void]$sb.AppendLine("| Current Score | $($secureScore.CurrentScore) / $($secureScore.MaxScore) |")
        [void]$sb.AppendLine("| Score Percentage | $($secureScore.ScorePercentage)% |")
        [void]$sb.AppendLine("| Controls Not Implemented | $($secureScore.NotImplemented) |")
        [void]$sb.AppendLine("| Controls Partially Implemented | $($secureScore.PartiallyImpl) |")
        [void]$sb.AppendLine("| Controls Fully Implemented | $($secureScore.FullyImplemented) |")
        [void]$sb.AppendLine('')

        if ($secureScore.TopGaps -and $secureScore.TopGaps.Count -gt 0) {
            [void]$sb.AppendLine('### Top Score Improvement Opportunities')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('| Control | Max Points | Status |')
            [void]$sb.AppendLine('|---|:---:|---|')
            foreach ($gap in $secureScore.TopGaps) {
                [void]$sb.AppendLine("| $($gap.Title) | $($gap.MaxScore) | $($gap.ImplementationStatus) |")
            }
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── User MFA Status ──────────────────────────────────────
    $mfaStatus = $ExtendedData['UserMFAStatus']
    if ($mfaStatus) {
        [void]$sb.AppendLine('## User MFA Status')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Metric | Count |')
        [void]$sb.AppendLine('|---|:---:|')
        [void]$sb.AppendLine("| Total Users | $($mfaStatus.TotalUsers) |")
        [void]$sb.AppendLine("| MFA Not Registered | $($mfaStatus.NoMFARegistered) |")
        [void]$sb.AppendLine("| MFA Registered | $($mfaStatus.MFARegistered) |")
        [void]$sb.AppendLine("| Admins Without MFA | $($mfaStatus.AdminsWithoutMFA) |")
        [void]$sb.AppendLine('')

        if ($mfaStatus.NoMFAList -and $mfaStatus.NoMFAList.Count -gt 0) {
            [void]$sb.AppendLine('### Users Without MFA Registered')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('| User | Admin |')
            [void]$sb.AppendLine('|---|:---:|')
            foreach ($user in $mfaStatus.NoMFAList) {
                $adminFlag = if ($user.IsAdmin) { 'Yes' } else { 'No' }
                [void]$sb.AppendLine("| $($user.UPN) | $adminFlag |")
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('> *MFA registration does not equal enforcement. CA policy enforcement is checked in findings below.*')
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Executive Summary ────────────────────────────────────
    [void]$sb.AppendLine('## Executive Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| State | Count |')
    [void]$sb.AppendLine('|---|:---:|')
    [void]$sb.AppendLine("| Gap | $($summary.Gap) |")
    [void]$sb.AppendLine("| Partial | $($summary.Partial) |")
    [void]$sb.AppendLine("| Satisfied | $($summary.Satisfied) |")
    [void]$sb.AppendLine("| **Total Checks** | **$($summary.Total)** |")
    [void]$sb.AppendLine('')
    if ($summary.Gap -gt 0) {
        [void]$sb.AppendLine("> **$($summary.Gap) gap(s) identified. Review findings below for remediation steps.**")
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Coverage Map ─────────────────────────────────────────
    [void]$sb.AppendLine('## Collection Coverage')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Control Family | Status | Notes |')
    [void]$sb.AppendLine('|---|:---:|---|')
    foreach ($key in $Coverage.Keys) {
        $entry      = $Coverage[$key]
        $statusIcon = switch ($entry.Status) {
            'Collected'    { 'Collected' }
            'Partial'      { 'Partial' }
            'NotCollected' { 'Not Collected' }
            'Unsupported'  { 'Unsupported' }
            default        { $entry.Status }
        }
        $reason = if ($entry.Reason) { $entry.Reason } else { '' }
        [void]$sb.AppendLine("| $key | $statusIcon | $reason |")
    }
    [void]$sb.AppendLine('')

    # ── Licensing Gaps ───────────────────────────────────────
    $licensingGaps = $Coverage.GetEnumerator() | Where-Object {
        $_.Value.Status -eq 'Partial' -and $_.Value.Reason -match 'not recognized|cmdlet|licensing'
    }
    if ($licensingGaps) {
        [void]$sb.AppendLine('> **Licensing Note:** One or more control families could not be assessed due to tenant licensing.')
        [void]$sb.AppendLine('> Controls marked Partial in the coverage map above require additional licensing to assess.')
        [void]$sb.AppendLine('> This is a licensing gap, not a security finding. See exceptions log for detail.')
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Admin Role Inventory ─────────────────────────────────
    $adminRoles = $ExtendedData['AdminRoleInventory']
    if ($adminRoles) {
        [void]$sb.AppendLine('## Admin Role Inventory')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Metric | Value |')
        [void]$sb.AppendLine('|---|---|')
        [void]$sb.AppendLine("| Global Admins | $($adminRoles.GlobalAdminCount) |")
        [void]$sb.AppendLine("| High Privilege Role Assignments | $($adminRoles.HighPrivRoleCount) |")
        $excessiveFlag = if ($adminRoles.GlobalAdminExcessive) { 'Yes -- review and reduce' } else { 'No' }
        [void]$sb.AppendLine("| Global Admin Count Excessive (>2) | $excessiveFlag |")
        [void]$sb.AppendLine('')
        if ($adminRoles.Roles) {
            [void]$sb.AppendLine('| Role | Members | High Privilege |')
            [void]$sb.AppendLine('|---|:---:|:---:|')
            foreach ($role in ($adminRoles.Roles | Where-Object { $_.MemberCount -gt 0 })) {
                $highPrivFlag = if ($role.IsHighPriv) { 'Yes' } else { 'No' }
                [void]$sb.AppendLine("| $($role.RoleName) | $($role.MemberCount) | $highPrivFlag |")
            }
            [void]$sb.AppendLine('')
        }
        if ($adminRoles.GlobalAdminExcessive) {
            [void]$sb.AppendLine('> **More than 2 Global Admins detected. Review and reduce to minimum required. Apply least privilege.**')
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Stale Accounts ───────────────────────────────────────
    $staleData = $ExtendedData['StaleAccounts']
    if ($staleData) {
        [void]$sb.AppendLine('## Stale Account Analysis')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("| Metric | Value |")
        [void]$sb.AppendLine('|---|---|')
        [void]$sb.AppendLine("| Threshold | $($staleData.ThresholdDays) days |")
        [void]$sb.AppendLine("| Total Active Users | $($staleData.TotalActiveUsers) |")
        [void]$sb.AppendLine("| Inactive $($staleData.ThresholdDays)+ Days | $($staleData.StaleCount) |")
        [void]$sb.AppendLine("| Never Signed In | $($staleData.NeverSignedInCount) |")
        [void]$sb.AppendLine('')
        if ($staleData.StaleList -and $staleData.StaleList.Count -gt 0) {
            [void]$sb.AppendLine('### Inactive Accounts')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('| User | Last Sign-In |')
            [void]$sb.AppendLine('|---|---|')
            foreach ($acct in $staleData.StaleList) {
                [void]$sb.AppendLine("| $($acct.UPN) | $($acct.LastSignIn) |")
            }
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Guest Account Inventory ──────────────────────────────
    $guestData = $ExtendedData['GuestAccountInventory']
    if ($guestData) {
        [void]$sb.AppendLine('## Guest Account Inventory')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Metric | Count |')
        [void]$sb.AppendLine('|---|:---:|')
        [void]$sb.AppendLine("| Total Guest Accounts | $($guestData.TotalGuests) |")
        [void]$sb.AppendLine("| Active Guests (signed in) | $($guestData.ActiveGuests) |")
        [void]$sb.AppendLine("| Stale Guests (90+ days) | $($guestData.StaleGuests) |")
        [void]$sb.AppendLine('')
        if ($guestData.GuestList -and $guestData.GuestList.Count -gt 0) {
            [void]$sb.AppendLine('| Guest UPN | Last Sign-In | State |')
            [void]$sb.AppendLine('|---|---|---|')
            foreach ($guest in $guestData.GuestList) {
                [void]$sb.AppendLine("| $($guest.UPN) | $($guest.LastSignIn) | $($guest.State) |")
            }
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Named Locations ──────────────────────────────────────
    $namedLocData = $ExtendedData['NamedLocations']
    if ($namedLocData) {
        [void]$sb.AppendLine('## Named Locations')
        [void]$sb.AppendLine('')
        if ($namedLocData.TotalDefined -eq 0) {
            [void]$sb.AppendLine('> **No named locations defined.** Named locations are required for Zero Trust network trust segmentation.')
            [void]$sb.AppendLine('> Without named locations, Conditional Access policies cannot differentiate corporate network from external access.')
            [void]$sb.AppendLine('')
        } else {
            [void]$sb.AppendLine("| Location | Type | Trusted |")
            [void]$sb.AppendLine('|---|---|:---:|')
            foreach ($loc in $namedLocData.Locations) {
                $trusted = if ($loc.IsTrusted) { 'Yes' } else { 'No' }
                [void]$sb.AppendLine("| $($loc.DisplayName) | $($loc.Type) | $trusted |")
            }
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Service Principal Inventory ──────────────────────────
    $spData = $ExtendedData['ServicePrincipalInventory']
    if ($spData) {
        [void]$sb.AppendLine('## Service Principal Inventory')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Metric | Count |')
        [void]$sb.AppendLine('|---|:---:|')
        [void]$sb.AppendLine("| Total Service Principals | $($spData.TotalServicePrincipals) |")
        [void]$sb.AppendLine("| High Privilege Detected | $($spData.HighPrivilegeCount) |")
        [void]$sb.AppendLine('')
        if ($spData.HighPrivilegeList -and $spData.HighPrivilegeList.Count -gt 0) {
            [void]$sb.AppendLine('### High Privilege Service Principals')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('| Display Name | Publisher | App ID |')
            [void]$sb.AppendLine('|---|---|---|')
            foreach ($sp in $spData.HighPrivilegeList) {
                [void]$sb.AppendLine("| $($sp.DisplayName) | $($sp.Publisher) | $($sp.AppId) |")
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('> **Review high-privilege service principals. Reduce permissions to minimum required.**')
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── DMARC Status ─────────────────────────────────────────
    $dmarcData = $ExtendedData['DMARC']
    if ($dmarcData) {
        [void]$sb.AppendLine('## DMARC Policy Status')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Domain | Policy | Pct | Enforced |')
        [void]$sb.AppendLine('|---|:---:|:---:|:---:|')
        foreach ($domain in $dmarcData.Domains) {
            $enforced = if ($domain.Enforced) { 'Yes' } elseif ($domain.Partial) { 'Quarantine' } else { 'No' }
            [void]$sb.AppendLine("| $($domain.Domain) | $($domain.Policy) | $($domain.Pct)% | $enforced |")
        }
        [void]$sb.AppendLine('')
        if ($dmarcData.MissingCount -gt 0) {
            [void]$sb.AppendLine("> **$($dmarcData.MissingCount) domain(s) have no DMARC record. Deploy DMARC at p=quarantine then advance to p=reject.**")
            [void]$sb.AppendLine('')
        }
        if ($dmarcData.NoneCount -gt 0) {
            [void]$sb.AppendLine("> **$($dmarcData.NoneCount) domain(s) have DMARC at p=none (monitoring only). Advance to p=quarantine or p=reject.**")
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Shared Mailbox Hardening ─────────────────────────────
    $sharedData = $ExtendedData['SharedMailboxHardening']
    if ($sharedData) {
        [void]$sb.AppendLine('## Shared Mailbox Hardening')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Metric | Count |')
        [void]$sb.AppendLine('|---|:---:|')
        [void]$sb.AppendLine("| Total Shared Mailboxes | $($sharedData.TotalSharedMailboxes) |")
        [void]$sb.AppendLine("| Interactive Sign-In Enabled | $($sharedData.SignInEnabledCount) |")
        [void]$sb.AppendLine("| POP3 Enabled | $($sharedData.PopEnabledCount) |")
        [void]$sb.AppendLine("| IMAP Enabled | $($sharedData.ImapEnabledCount) |")
        [void]$sb.AppendLine('')
        if ($sharedData.SignInEnabledList -and $sharedData.SignInEnabledList.Count -gt 0) {
            [void]$sb.AppendLine('### Shared Mailboxes with Interactive Sign-In Enabled')
            [void]$sb.AppendLine('')
            foreach ($mbx in $sharedData.SignInEnabledList) {
                [void]$sb.AppendLine("  - $mbx")
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('> **Shared mailboxes should have interactive sign-in disabled. Run Set-MsolUser -UserPrincipalName <mbx> -BlockCredential $true**')
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── CA Policy Inventory ──────────────────────────────────
    $caData = $ExtendedData['ConditionalAccess']
    if ($caData -and $caData.Policies -and $caData.Policies.Count -gt 0) {
        [void]$sb.AppendLine('## Conditional Access Policy Inventory')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Policy Name | State | MFA Grant | Legacy Auth Block | Device Compliance |')
        [void]$sb.AppendLine('|---|:---:|:---:|:---:|:---:|')
        foreach ($policy in $caData.Policies) {
            $state   = $policy.State
            $mfa     = if ($policy.HasMfaGrant) { 'Yes' } else { 'No' }
            $legacy  = if ($policy.TargetsLegacyAuth) { 'Yes' } else { 'No' }
            $device  = if ($policy.RequiresCompliantDevice) { 'Yes' } else { 'No' }
            [void]$sb.AppendLine("| $($policy.DisplayName) | $state | $mfa | $legacy | $device |")
        }
        [void]$sb.AppendLine('')

        if ($caData.MissingPolicies -and $caData.MissingPolicies.Count -gt 0) {
            [void]$sb.AppendLine('### Recommended Policies Not Found')
            [void]$sb.AppendLine('')
            foreach ($missing in $caData.MissingPolicies) {
                [void]$sb.AppendLine("- [ ] $missing")
            }
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('---')
        [void]$sb.AppendLine('')
    }

    # ── Findings by Severity ─────────────────────────────────
    [void]$sb.AppendLine('## Findings')
    [void]$sb.AppendLine('')

    $severityOrder = @('Gap', 'Partial', 'Satisfied')

    foreach ($sev in $severityOrder) {
        $sevFindings = $findings | Where-Object { $_.State -eq $sev }
        if (-not $sevFindings) { continue }

        $label = switch ($sev) { 'Gap' { 'High' } 'Partial' { 'Medium' } 'Satisfied' { 'Pass' } }
        [void]$sb.AppendLine("### $label")
        [void]$sb.AppendLine('')

        $categories = $sevFindings | Group-Object -Property Category
        foreach ($category in $categories) {
            [void]$sb.AppendLine("#### $($category.Name)")
            [void]$sb.AppendLine('')

            foreach ($finding in $category.Group) {
                [void]$sb.AppendLine("**$($finding.Title)**")
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine($finding.Detail)

                # v2 -- affected object list
                if ($finding.AffectedObjects -and $finding.AffectedObjects.Count -gt 0) {
                    [void]$sb.AppendLine('')
                    foreach ($obj in $finding.AffectedObjects) {
                        [void]$sb.AppendLine("  - $obj")
                    }
                }

                # v2 -- current state vs recommended
                if ($finding.CurrentState -and $finding.Recommended -and $sev -ne 'Satisfied') {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('| | Value |')
                    [void]$sb.AppendLine('|---|---|')
                    [void]$sb.AppendLine("| **Current State** | $($finding.CurrentState) |")
                    [void]$sb.AppendLine("| **Recommended** | $($finding.Recommended) |")
                }

                # Per-framework recommendation blocks
                if ($finding.NIST_SP800_53_r5) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('**NIST SP 800-53 Rev 5**')
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("- Controls: $($finding.NIST_SP800_53_r5)")
                    if ($finding.NIST_Detail) {
                        [void]$sb.AppendLine("- $($finding.NIST_Detail)")
                    }
                    if ($finding.NIST_Requirement) {
                        [void]$sb.AppendLine("- Requirement level: $($finding.NIST_Requirement)")
                    }
                }

                if ($finding.CIS_v8_1) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('**CIS Controls v8.1**')
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("- Safeguards: $($finding.CIS_v8_1)")
                    if ($finding.CIS_Detail) {
                        [void]$sb.AppendLine("- $($finding.CIS_Detail)")
                    }
                    if ($finding.CIS_Requirement) {
                        [void]$sb.AppendLine("- Implementation Group: $($finding.CIS_Requirement)")
                    }
                }

                if ($finding.HIPAA_Current) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('**HIPAA Security Rule (Current Enforceable)**')
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("- Citations: $($finding.HIPAA_Current)")
                    if ($finding.HIPAA_Detail) {
                        [void]$sb.AppendLine("- $($finding.HIPAA_Detail)")
                    }
                    if ($finding.HIPAA_Req) {
                        [void]$sb.AppendLine("- Requirement: $($finding.HIPAA_Req)")
                    }
                }

                if ($finding.HIPAA_Proposed) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('**HIPAA Security Rule (NPRM Proposed — Expected Final May 2026)**')
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("- Citations: $($finding.HIPAA_Proposed)")
                    if ($finding.HIPAA_Proposed_Detail) {
                        [void]$sb.AppendLine("- $($finding.HIPAA_Proposed_Detail)")
                    }
                    if ($finding.HIPAA_Proposed_Req) {
                        [void]$sb.AppendLine("- Requirement: $($finding.HIPAA_Proposed_Req)")
                    }
                }

                if ($finding.Remediation -and $sev -ne 'Satisfied') {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("*Remediation:* $($finding.Remediation)")
                }
                [void]$sb.AppendLine('')
            }
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('*Assessment performed by NextLayerSec -- nextlayersec.io*')
    [void]$sb.AppendLine('*Read-only instrument. Results reflect visible telemetry at time of assessment.*')

    Export-NLSSafeMarkdown -Content $sb.ToString() -OutPath $OutputPath -Redact $Redact
    Write-Host "  [+] Assessment summary written to: $OutputPath" -ForegroundColor Green
}

function Publish-NLSExceptionsList {
    param(
        [Parameter(Mandatory = $false)][array]$Exceptions = @(),
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [bool]$Redact = $false
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# NextLayerSec Assessment -- Collection Exceptions')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> Exceptions are non-fatal errors encountered during data collection.')
    [void]$sb.AppendLine('> An exception does not mean a control failed -- it means the control could not be assessed.')
    [void]$sb.AppendLine('> Review each exception to determine whether a permissions or licensing gap exists.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    if ($Exceptions.Count -eq 0) {
        [void]$sb.AppendLine('No exceptions encountered during collection.')
    } else {
        [void]$sb.AppendLine("**Total exceptions: $($Exceptions.Count)**")
        [void]$sb.AppendLine('')
        foreach ($ex in $Exceptions) {
            [void]$sb.AppendLine("### $($ex.Source)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Time (UTC):** $($ex.Timestamp)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Message:** $($ex.Message)")
            [void]$sb.AppendLine('')
            if ($ex.ErrorDetails) {
                [void]$sb.AppendLine('**Error Details:**')
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('```')
                [void]$sb.AppendLine($ex.ErrorDetails)
                [void]$sb.AppendLine('```')
                [void]$sb.AppendLine('')
            }
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('*NextLayerSec -- nextlayersec.io*')

    $exceptionsContent = $sb.ToString()
    # v2 security fix -- apply redaction to exceptions log when requested
    # Exceptions were previously written without redaction even with -RedactSensitiveData
    if ($Redact) {
        $exceptionsContent = Protect-NLSExceptionsRedaction -Content $exceptionsContent
    }
    Export-NLSSafeMarkdown -Content $exceptionsContent -OutPath $OutputPath -Redact $false
    Write-Host "  [+] Exceptions list written to: $OutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function Publish-NLSAssessmentSummary, Publish-NLSExceptionsList
