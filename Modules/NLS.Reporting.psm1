#
# NLS.Reporting.psm1
# NextLayerSec Assessment Framework -- Reporting Module
# v2.2.0 -- BLUF report structure: Summary > Gaps > Telemetry > Appendix
#
# Author:  NextLayerSec
# Version: 2.2.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Publish-NLSAssessmentSummary {
    param(
        [Parameter(Mandatory = $true)][hashtable]$ScoredResults,
        [Parameter(Mandatory = $true)][hashtable]$Metadata,
        [Parameter(Mandatory = $true)][hashtable]$Coverage,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [hashtable]$ExtendedData = @{},
        [hashtable]$DeltaData    = @{},
        [bool]$DebugDNS  = $false,
        [bool]$Redact            = $false
    )

    $findings = $ScoredResults.Findings
    $summary  = $ScoredResults.Summary
    $sb       = [System.Text.StringBuilder]::new()

    $gaps     = @($findings | Where-Object { $_['State'] -eq 'Gap' } | Sort-Object { $_['Category'] })
    $partials = @($findings | Where-Object { $_['State'] -eq 'Partial' } | Sort-Object { $_['Category'] })
    $passes   = @($findings | Where-Object { $_['State'] -eq 'Satisfied' } | Sort-Object { $_['Category'] })

    # ── HEADER ───────────────────────────────────────────────
    [void]$sb.AppendLine('# NextLayerSec M365 Security Assessment')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("> Read-only assessment. No tenant configuration changes were made.")
    [void]$sb.AppendLine('')

    # Compact metadata line
    [void]$sb.AppendLine("**Execution Time:** $($Metadata.ExecutionTimeUTC) | **Operator:** $($Metadata.AuthContext) | **Profile:** $($Metadata.ExecutionMode)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("**Frameworks:** $($Metadata.ActiveFrameworks) | **Features:** $($Metadata.ActiveFeatures)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── SECTION 1: EXECUTIVE SUMMARY ─────────────────────────
    [void]$sb.AppendLine('## 1. Executive Summary')
    [void]$sb.AppendLine('')

    $secureScore = $ExtendedData['SecureScore']
    [void]$sb.AppendLine('| Metric | Value |')
    [void]$sb.AppendLine('|---|---|')
    if ($secureScore) {
        [void]$sb.AppendLine("| Microsoft Secure Score | $($secureScore['ScorePercentage'])% ($($secureScore['CurrentScore']) / $($secureScore['MaxScore'])) |")
    }
    [void]$sb.AppendLine("| Checks Passed | $($summary.Satisfied) |")
    [void]$sb.AppendLine("| Active Gaps | $($summary.Gap) |")
    if ($summary.Partial -gt 0) {
        [void]$sb.AppendLine("| Partial Controls | $($summary.Partial) |")
    }
    [void]$sb.AppendLine("| Total Checks | $($summary.Total) |")
    [void]$sb.AppendLine('')

    # BLUF statement
    if ($summary.Gap -eq 0 -and $summary.Partial -eq 0) {
        [void]$sb.AppendLine('> **Bottom Line:** All controls satisfied. No immediate action required. Review telemetry section for hygiene observations.')
    } elseif ($summary.Gap -eq 0) {
        [void]$sb.AppendLine("> **Bottom Line:** No critical gaps. $($summary.Partial) partial control(s) require attention.")
    } else {
        $topGap = if ($gaps.Count -gt 0) { $gaps[0].Title } else { '' }
        [void]$sb.AppendLine("> **Bottom Line:** $($summary.Gap) gap(s) identified requiring immediate remediation. Priority: $topGap.")
    }
    [void]$sb.AppendLine('')

    # Delta summary if available
    if ($DeltaData -and $DeltaData['Available']) {
        [void]$sb.AppendLine("**Delta vs previous run:** Improved $($DeltaData['ImprovedCount']) | Regressed $($DeltaData['RegressedCount']) | New $($DeltaData['NewCount'])")
        [void]$sb.AppendLine('')
        if ($DeltaData['RegressedCount'] -gt 0) {
            [void]$sb.AppendLine('> **Regression detected.** Controls that previously passed have failed. See delta detail in Appendix.')
            [void]$sb.AppendLine('')
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── SECTION 2: ACTION PLAN (GAPS ONLY) ───────────────────
    [void]$sb.AppendLine('## 2. Action Plan')
    [void]$sb.AppendLine('')

    if ($gaps.Count -eq 0 -and $partials.Count -eq 0) {
        [void]$sb.AppendLine('No gaps or partial controls identified. All checks satisfied.')
        [void]$sb.AppendLine('')
    } else {
        if ($gaps.Count -gt 0) {
            [void]$sb.AppendLine('### High Priority Gaps')
            [void]$sb.AppendLine('')
            $gapNum = 1
            foreach ($finding in $gaps) {
                [void]$sb.AppendLine("#### $gapNum. $($finding['Title'])")
                $gapNum++
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine($finding['Detail'])
                [void]$sb.AppendLine('')

                if ($finding['AffectedObjects'] -and $finding['AffectedObjects'].Count -gt 0) {
                    foreach ($obj in $finding['AffectedObjects']) {
                        [void]$sb.AppendLine("  - $obj")
                    }
                    [void]$sb.AppendLine('')
                }

                if ($finding['CurrentState'] -or $finding['Recommended']) {
                    [void]$sb.AppendLine("| | Value |")
                    [void]$sb.AppendLine('|---|---|')
                    if ($finding['CurrentState']) { [void]$sb.AppendLine("| **Current State** | $($finding['CurrentState']) |") }
                    if ($finding['Recommended'])  { [void]$sb.AppendLine("| **Recommended** | $($finding['Recommended']) |") }
                    [void]$sb.AppendLine('')
                }

                # Framework citations compact
                $fwCitations = @()
                if ($finding['NIST_SP800_53_r5']) { $fwCitations += "NIST: $($finding['NIST_SP800_53_r5'])" }
                if ($finding['CIS_v8_1'])         { $fwCitations += "CIS: $($finding['CIS_v8_1'])" }
                if ($finding['HIPAA_Current'])    { $fwCitations += "HIPAA: $($finding['HIPAA_Current'])" }
                if ($fwCitations.Count -gt 0) {
                    [void]$sb.AppendLine("> *$($fwCitations -join ' | ')*")
                    [void]$sb.AppendLine('')
                }

                if ($finding['Remediation']) {
                    # Check if remediation is a PowerShell command or portal action
                    $rem = $finding['Remediation']
                    if ($rem -match '^(Get-|Set-|New-|Enable-|Disable-|Connect-|Remove-|Add-)') {
                        [void]$sb.AppendLine('**Remediation Command:**')
                        [void]$sb.AppendLine('')
                        [void]$sb.AppendLine('```powershell')
                        [void]$sb.AppendLine($rem)
                        [void]$sb.AppendLine('```')
                    } else {
                        [void]$sb.AppendLine("**Remediation:** $rem")
                    }
                    [void]$sb.AppendLine('')
                }
            }
        }

        if ($partials.Count -gt 0) {
            [void]$sb.AppendLine('### Medium Priority — Partial Controls')
            [void]$sb.AppendLine('')
            foreach ($finding in $partials) {
                [void]$sb.AppendLine("#### $($finding['Title'])")
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine($finding['Detail'])
                [void]$sb.AppendLine('')
                if ($finding['Remediation']) {
                    $rem = $finding['Remediation']
                    if ($rem -match '^(Get-|Set-|New-|Enable-|Disable-|Connect-|Remove-|Add-)') {
                        [void]$sb.AppendLine('**Remediation Command:**')
                        [void]$sb.AppendLine('')
                        [void]$sb.AppendLine('```powershell')
                        [void]$sb.AppendLine($rem)
                        [void]$sb.AppendLine('```')
                    } else {
                        [void]$sb.AppendLine("**Remediation:** $rem")
                    }
                    [void]$sb.AppendLine('')
                }
            }
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── SECTION 3: POSTURE & TELEMETRY ───────────────────────
    if ($DebugDNS) {
        Write-Host '  [DEBUG] Section 3 ExtendedData:' -ForegroundColor DarkGray
        foreach ($k in ($ExtendedData.Keys | Sort-Object)) {
            $v = $ExtendedData[$k]
            $desc = if ($null -eq $v) { 'NULL' } elseif ($v -is [System.Collections.Specialized.OrderedDictionary]) { "[ordered] $($v.Keys.Count) keys" } else { $v.GetType().Name }
            Write-Host "    $($k.PadRight(30)) $desc" -ForegroundColor DarkGray
        }
    }
    [void]$sb.AppendLine('## 3. Posture & Telemetry')
    [void]$sb.AppendLine('')

    # Identity & Privilege summary
    [void]$sb.AppendLine('### Identity & Privilege')
    [void]$sb.AppendLine('')

    $adminData = $ExtendedData['AdminRoleInventory']
    $mfaData   = $ExtendedData['UserMFAStatus']
    $staleData = $ExtendedData['StaleAccounts']
    $guestData = $ExtendedData['GuestAccountInventory']
    $bgData    = $ExtendedData['BreakGlassAccounts']
    $pimData   = $ExtendedData['PIM']

    if ($adminData) {
        $gaFlag = if ($adminData['GlobalAdminExcessive']) { ' ⚠ Exceeds recommended maximum of 2' } else { '' }
        [void]$sb.AppendLine("- **Global Admins:** $($adminData['GlobalAdminCount'])$gaFlag")
    }
    if ($mfaData) {
        [void]$sb.AppendLine("- **MFA Registration:** $($mfaData['MFARegistered']) of $($mfaData['TotalUsers']) users registered")
        if ($mfaData['NoMFAList'] -and $mfaData['NoMFAList'].Count -gt 0) {
            foreach ($u in $mfaData['NoMFAList']) {
                $adminFlag = if ($u['IsAdmin']) { ' *(Admin)*' } else { '' }
                [void]$sb.AppendLine("  - $($u['UPN'])$adminFlag — no MFA registered")
            }
        }
    }
    if ($staleData -and $staleData['StaleCount'] -gt 0) {
        [void]$sb.AppendLine("- **Stale Accounts ($($staleData['ThresholdDays'])+ days inactive):** $($staleData['StaleCount'])")
        foreach ($acct in $staleData['StaleList']) {
            [void]$sb.AppendLine("  - $($acct['UPN']) — last sign-in $($acct['LastSignIn'])")
        }
    }
    if ($guestData) {
        [void]$sb.AppendLine("- **Guest Accounts:** $($guestData['TotalGuests']) total ($($guestData['StaleGuests']) stale)")
    }
    if ($bgData) {
        $bgStatus = if ($bgData['Configured']) { 'Configured and excluded from CA' } elseif ($bgData['Count'] -gt 0) { 'Exists but not properly excluded from CA' } else { 'Not detected' }
        [void]$sb.AppendLine("- **Break-Glass Account:** $bgStatus")
    }
    if ($pimData -and $pimData['PermanentGlobalAdminCount'] -gt 0) {
        [void]$sb.AppendLine("- **Permanent Global Admins (no PIM):** $($pimData['PermanentGlobalAdminCount']) — review for PIM eligibility")
    }
    [void]$sb.AppendLine('')

    # Admin Role Table
    if ($adminData -and $adminData['Roles']) {
        [void]$sb.AppendLine('### Admin Role Inventory')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Role | Members | High Privilege |')
        [void]$sb.AppendLine('|---|:---:|:---:|')
        foreach ($role in ($adminData['Roles'] | Where-Object { $_.MemberCount -gt 0 })) {
            $hp = if ($role['IsHighPriv']) { 'Yes' } else { 'No' }
            [void]$sb.AppendLine("| $($role['RoleName']) | $($role['MemberCount']) | $hp |")
        }
        [void]$sb.AppendLine('')
    }

    # Named Locations
    $namedLocData = $ExtendedData['NamedLocations']
    if ($namedLocData -and $namedLocData['TotalDefined'] -gt 0) {
        [void]$sb.AppendLine('### Named Locations')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Location | Type | Trusted |')
        [void]$sb.AppendLine('|---|---|:---:|')
        foreach ($loc in $namedLocData['Locations']) {
            $trusted = if ($loc['IsTrusted']) { 'Yes' } else { 'No' }
            [void]$sb.AppendLine("| $($loc['DisplayName']) | $($loc['Type']) | $trusted |")
        }
        [void]$sb.AppendLine('')
    } elseif ($namedLocData -and $namedLocData['TotalDefined'] -eq 0) {
        [void]$sb.AppendLine('### Named Locations')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('> No named locations defined. Required for Zero Trust network trust segmentation.')
        [void]$sb.AppendLine('')
    }

    # Service Principals
    $spData = $ExtendedData['ServicePrincipalInventory']
    if ($spData -and $spData['HighPrivilegeCount'] -gt 0) {
        [void]$sb.AppendLine('### High Privilege Service Principals')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Display Name | Publisher | App ID |')
        [void]$sb.AppendLine('|---|---|---|')
        foreach ($sp in $spData['HighPrivilegeList']) {
            [void]$sb.AppendLine("| $($sp['DisplayName']) | $($sp['Publisher']) | $($sp['AppId']) |")
        }
        [void]$sb.AppendLine('')
    }

    # Secure Score top gaps
    if ($secureScore -and $secureScore['TopGaps'] -and $secureScore['TopGaps'].Count -gt 0) {
        [void]$sb.AppendLine('### Secure Score — Top Improvement Opportunities')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Control | Max Points | Status |')
        [void]$sb.AppendLine('|---|:---:|---|')
        foreach ($gap in $secureScore['TopGaps']) {
            [void]$sb.AppendLine("| $($gap['Title']) | $($gap['MaxScore']) | $($gap['ImplementationStatus']) |")
        }
        [void]$sb.AppendLine('')
    }

    # CA Policy Inventory
    $caData = $ExtendedData['ConditionalAccess']
    if ($caData -and $caData['Policies'] -and $caData['Policies'].Count -gt 0) {
        [void]$sb.AppendLine('### Conditional Access Policy Inventory')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Policy Name | State | MFA | Legacy Block | Device |')
        [void]$sb.AppendLine('|---|:---:|:---:|:---:|:---:|')
        foreach ($policy in $caData['Policies']) {
            $mfa    = if ($policy['HasMfaGrant']) { 'Yes' } else { 'No' }
            $legacy = if ($policy['TargetsLegacyAuth']) { 'Yes' } else { 'No' }
            $device = if ($policy['RequiresCompliantDevice']) { 'Yes' } else { 'No' }
            [void]$sb.AppendLine("| $($policy['DisplayName']) | $($policy['State']) | $mfa | $legacy | $device |")
        }
        [void]$sb.AppendLine('')

        if ($caData['MissingPolicies'] -and $caData['MissingPolicies'].Count -gt 0) {
            [void]$sb.AppendLine('**Recommended policies not detected:**')
            [void]$sb.AppendLine('')
            foreach ($missing in $caData['MissingPolicies']) {
                [void]$sb.AppendLine("- [ ] $missing")
            }
            [void]$sb.AppendLine('')
        }
    }

    # DNS Email Records
    $dnsExt        = $ExtendedData['DNSEmailRecords']
    $dnsDomainList = if ($dnsExt -and $dnsExt['Domains']) { @($dnsExt['Domains']) } else { @() }
    if ($DebugDNS) {
        Write-Host "  [DNS-DEBUG] dnsExt null=$($null -eq $dnsExt) | domains=$($dnsDomainList.Count) | ExtendedData keys: $($ExtendedData.Keys -join ', ')" -ForegroundColor Cyan
    }
    if ($dnsExt) {
        [void]$sb.AppendLine('### DNS Email Record Verification')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('> Live DNS lookup via 8.8.8.8. Records shown are publicly visible.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Domain | SPF | DMARC | DKIM | DNSSEC | MTA-STS |')
        [void]$sb.AppendLine('|---|:---:|:---:|:---:|:---:|:---:|')
        foreach ($dr in $dnsDomainList) {
            try {
                $c_spf    = if ($dr['SPF']['Found'])      { 'Pass' } else { 'Missing' }
                $c_dmarc  = if ($dr['DMARC']['Found'])    { $dr['DMARC']['Policy'] } else { 'Missing' }
                $c_dkim   = if ($dr['DKIM']['Found'])     { 'Pass' } else { 'Missing' }
                $c_dnssec = if ($dr['DNSSEC']['Enabled']) { 'Pass' } else { 'Missing' }
                $c_mta    = if ($dr['MTASTS']['Enabled']) { 'Pass' } else { 'Missing' }
                [void]$sb.AppendLine("| $($dr['Domain']) | $c_spf | $c_dmarc | $c_dkim | $c_dnssec | $c_mta |")
            } catch { [void]$sb.AppendLine("| $($dr['Domain']) | Error | Error | Error | Error | Error |") }
        }
        [void]$sb.AppendLine('')
        foreach ($dr in $dnsDomainList) {
            try {
                [void]$sb.AppendLine("**$($dr['Domain'])**")
                [void]$sb.AppendLine('')
                $spfVal = if ($dr['SPF']['Found']) { "``$($dr['SPF']['Record'])``" } else { 'Not found' }
                [void]$sb.AppendLine("- **SPF:** $spfVal")
                if ($dr['DMARC']['Found']) {
                    $rua = if ($dr['DMARC']['RUA']) { " | rua=$($dr['DMARC']['RUA'])" } else { '' }
                    [void]$sb.AppendLine("- **DMARC:** p=$($dr['DMARC']['Policy']) | pct=$($dr['DMARC']['Pct'])%$rua")
                } else { [void]$sb.AppendLine('- **DMARC:** Not found') }
                $sel = $dr['DKIM']['Selectors']
                $s1  = if ($sel['selector1']['Found']) { "selector1 ($($sel['selector1']['Type']))" } else { 'selector1 missing' }
                $s2  = if ($sel['selector2']['Found']) { "selector2 ($($sel['selector2']['Type']))" } else { 'selector2 missing' }
                [void]$sb.AppendLine("- **DKIM:** $s1, $s2 | EXO signing: $($dr['DKIM']['EnabledInEXO'])")
                [void]$sb.AppendLine("- **DNSSEC:** $($dr['DNSSEC']['Status'])")
                $mtaVal = if ($dr['MTASTS']['Enabled']) { $dr['MTASTS']['Mode'] } else { 'Not published' }
                [void]$sb.AppendLine("- **MTA-STS:** $mtaVal")
                [void]$sb.AppendLine('')
            } catch { [void]$sb.AppendLine("  *(Error rendering domain detail)*"); [void]$sb.AppendLine('') }
        }
    } else {
        Write-Host "  [DNS] No DNS data in ExtendedData -- skipping section" -ForegroundColor Yellow
    }


        # ── SECTION 4: APPENDIX ──────────────────────────────────
    [void]$sb.AppendLine('## 4. Appendix')
    [void]$sb.AppendLine('')

    # Delta detail
    if ($DeltaData -and $DeltaData['Available']) {
        [void]$sb.AppendLine('### Delta Report')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("> Comparison against: $(Split-Path $DeltaData['PreviousReport'] -Leaf)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Category | Count |')
        [void]$sb.AppendLine('|---|:---:|')
        [void]$sb.AppendLine("| Improved | $($DeltaData['ImprovedCount']) |")
        [void]$sb.AppendLine("| Regressed | $($DeltaData['RegressedCount']) |")
        [void]$sb.AppendLine("| Unchanged | $($DeltaData['UnchangedCount']) |")
        [void]$sb.AppendLine("| New Findings | $($DeltaData['NewCount']) |")
        [void]$sb.AppendLine('')

        if ($DeltaData['ImprovedCount'] -gt 0) {
            [void]$sb.AppendLine('**Improved**')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('| Control | Previous | Current |')
            [void]$sb.AppendLine('|---|:---:|:---:|')
            foreach ($item in $DeltaData['Improved']) {
                [void]$sb.AppendLine("| $($item['Title']) | $($item['PreviousState']) | $($item['CurrentState']) |")
            }
            [void]$sb.AppendLine('')
        }
        if ($DeltaData['RegressedCount'] -gt 0) {
            [void]$sb.AppendLine('**Regressed**')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('| Control | Previous | Current |')
            [void]$sb.AppendLine('|---|:---:|:---:|')
            foreach ($item in $DeltaData['Regressed']) {
                [void]$sb.AppendLine("| $($item['Title']) | $($item['PreviousState']) | $($item['CurrentState']) |")
            }
            [void]$sb.AppendLine('')
        }
    }

    # Satisfied controls
    if ($passes.Count -gt 0) {
        [void]$sb.AppendLine('### Satisfied Controls')
        [void]$sb.AppendLine('')
        $passByCategory = $passes | Group-Object -Property { $_['Category'] }
        foreach ($category in $passByCategory) {
            [void]$sb.AppendLine("**$($category.Name)**")
            [void]$sb.AppendLine('')
            foreach ($finding in $category.Group) {
                [void]$sb.AppendLine("- ✓ $($finding['Title'])")
                if ($finding['Detail']) { [void]$sb.AppendLine("  $($finding['Detail'])") }
                # Framework citations
                $fwCitations = @()
                if ($finding['NIST_SP800_53_r5']) { $fwCitations += "NIST: $($finding['NIST_SP800_53_r5'])" }
                if ($finding['CIS_v8_1'])         { $fwCitations += "CIS: $($finding['CIS_v8_1'])" }
                if ($finding['HIPAA_Current'])    { $fwCitations += "HIPAA: $($finding['HIPAA_Current'])" }
                if ($fwCitations.Count -gt 0) {
                    [void]$sb.AppendLine("  *$($fwCitations -join ' | ')*")
                }
                [void]$sb.AppendLine('')
            }
        }
    }

    # Collection coverage
    [void]$sb.AppendLine('### Collection Coverage')
    [void]$sb.AppendLine('')

    # Check for licensing gaps
    $licensingGaps = $Coverage.GetEnumerator() | Where-Object {
        $_.Value.Status -eq 'Partial' -and $_.Value.Reason -match 'not recognized|cmdlet|licensing'
    }
    if ($licensingGaps) {
        [void]$sb.AppendLine('> **Licensing Note:** One or more control families could not be assessed due to tenant licensing. See exceptions log for detail.')
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('| Control Family | Status | Notes |')
    [void]$sb.AppendLine('|---|:---:|---|')
    foreach ($key in ($Coverage.Keys | Sort-Object)) {
        $entry  = $Coverage[$key]
        $reason = if ($entry.Reason) { $entry.Reason } else { '' }
        [void]$sb.AppendLine("| $key | $($entry.Status) | $reason |")
    }
    [void]$sb.AppendLine('')

    # Assessment metadata detail
    [void]$sb.AppendLine('### Assessment Metadata')
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
    [void]$sb.AppendLine('*Assessment performed by NextLayerSec -- nextlayersec.io*')
    [void]$sb.AppendLine('*Read-only instrument. Results reflect visible telemetry at time of assessment.*')

    # Write output
    $reportContent = $sb.ToString()
    if ($Redact) { $reportContent = Invoke-NLSRedaction -Content $reportContent }
    $reportContent | Out-File -FilePath $OutputPath -Encoding utf8 -Force
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
    [void]$sb.AppendLine('> Non-fatal errors encountered during data collection.')
    [void]$sb.AppendLine('> An exception means the control could not be assessed, not that it failed.')
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
                [void]$sb.AppendLine('```')
                [void]$sb.AppendLine($ex.ErrorDetails)
                [void]$sb.AppendLine('```')
                [void]$sb.AppendLine('')
            }
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('*NextLayerSec -- nextlayersec.io*')

    $exceptionsContent = $sb.ToString()
    if ($Redact) { $exceptionsContent = Protect-NLSExceptionsRedaction -Content $exceptionsContent }
    $exceptionsContent | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Host "  [+] Exceptions list written to: $OutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function Publish-NLSAssessmentSummary, Publish-NLSExceptionsList
