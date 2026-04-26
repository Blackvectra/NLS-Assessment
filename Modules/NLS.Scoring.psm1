#
# NLS.Scoring.psm1
# NextLayerSec Assessment Framework -- Scoring Engine
# v2.0.0 -- Granular detail, current state vs recommended, ZeroTrust flag,
#           CA inventory scoring, user MFA gap, Secure Score integration
#
# Author:  NextLayerSec
# Version: 2.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

# Module-level dedup tracking -- outside Invoke-NLSScoringModel so Add-NLSFinding can access it
$script:findings      = [System.Collections.Generic.List[hashtable]]::new()
$script:addedControls = [System.Collections.Generic.HashSet[string]]::new()
$script:nlsDict       = $null
$script:nlsFrameworks = @{}

function Add-NLSFinding {
    param(
        [string]$ControlId,
        [ValidateSet('Satisfied', 'Partial', 'Gap')]
        [string]$State,
        [string]$Detail,
        [string]$Remediation      = '',
        [string]$CurrentState     = '',
        [string]$Recommended      = '',
        [string[]]$AffectedObjects = @()
    )

    # Dedup -- skip if already scored
    if ($script:addedControls.Contains($ControlId)) { return }

    $dict = $script:nlsDict
    $entry = if ($dict) { $dict[$ControlId] } else { $null }

    $finding = [ordered]@{
        ControlId       = $ControlId
        Title           = if ($entry) { $entry['Title'] } else { $ControlId }
        Category        = if ($entry) { $entry['Category'] } else { 'General' }
        State           = $State
        Severity        = switch ($State) { 'Satisfied' { 'Pass' } 'Partial' { 'Medium' } 'Gap' { 'High' } }
        Detail          = $Detail
        Remediation     = $Remediation
        CurrentState    = $CurrentState
        Recommended     = $Recommended
        AffectedObjects = $AffectedObjects
    }

    $fw = $script:nlsFrameworks
    if ($entry) {
        try {
            if ($fw.NIST -and $entry['NIST']) {
                $nistEntry = $entry['NIST'][$State]
                if ($null -ne $nistEntry -and $nistEntry -is [hashtable]) {
                    $finding['NIST_SP800_53_r5'] = $nistEntry['Citation']
                    $finding['NIST_Requirement'] = $nistEntry['Requirement']
                    $finding['NIST_Detail']      = $nistEntry['Detail']
                }
            }
            if ($fw.CIS -and $entry['CIS']) {
                $cisEntry = $entry['CIS'][$State]
                if ($null -ne $cisEntry -and $cisEntry -is [hashtable]) {
                    $finding['CIS_v8_1']        = $cisEntry['Citation']
                    $finding['CIS_Requirement'] = $cisEntry['Requirement']
                    $finding['CIS_Detail']      = $cisEntry['Detail']
                }
            }
            if ($fw.HIPAA -and $entry['HIPAA']) {
                $hipaaEntry = $entry['HIPAA'][$State]
                if ($null -ne $hipaaEntry -and $hipaaEntry -is [hashtable]) {
                    $finding['HIPAA_Current'] = $hipaaEntry['Citation']
                    $finding['HIPAA_Req']     = $hipaaEntry['Requirement']
                    $finding['HIPAA_Detail']  = $hipaaEntry['Detail']
                }
            }
            if ($fw.HIPAAProposed -and $entry['HIPAAProposed']) {
                $hipaaProposedEntry = $entry['HIPAAProposed'][$State]
                if ($null -ne $hipaaProposedEntry -and $hipaaProposedEntry -is [hashtable]) {
                    $finding['HIPAA_Proposed']        = $hipaaProposedEntry['Citation']
                    $finding['HIPAA_Proposed_Req']    = $hipaaProposedEntry['Requirement']
                    $finding['HIPAA_Proposed_Detail'] = $hipaaProposedEntry['Detail']
                }
            }
        } catch {
            # Non-fatal -- log to exceptions, surface to console only in debug mode
            if ($script:nlsDebug) {
                Write-Host "  [DEBUG] Citation error: ControlId=$ControlId State=$State" -ForegroundColor Yellow
                Write-Host "          Error: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
            Register-NLSException -Source "Add-NLSFinding:Citations" `
                -Message "Framework citation lookup failed for ControlId=$ControlId State=$State" `
                -ErrorDetails $_.Exception.Message
        }
    }

    $script:findings.Add($finding)
    [void]$script:addedControls.Add($ControlId)
}

function Invoke-NLSScoringModel {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Results,
        [bool]$Redact        = $false,
        [bool]$NIST          = $false,
        [bool]$CIS           = $false,
        [bool]$HIPAA         = $false,
        [bool]$HIPAAProposed = $false,
        [bool]$ZeroTrust     = $false,
        [bool]$DebugMode     = $false
    )

    # Reset per-run state -- explicit clear prevents state leakage between
    # multiple calls in the same PS session
    if ($script:findings)      { [void]$script:findings.Clear() }
    if ($script:addedControls) { [void]$script:addedControls.Clear() }
    $script:findings      = [System.Collections.Generic.List[hashtable]]::new()
    $script:addedControls = [System.Collections.Generic.HashSet[string]]::new()
    $script:nlsFrameworks = @{ NIST = $NIST; CIS = $CIS; HIPAA = $HIPAA; HIPAAProposed = $HIPAAProposed; ZeroTrust = $ZeroTrust }
    $script:nlsDebug      = $DebugMode

    # Load dictionary AFTER reset so it is not wiped
    $script:nlsDict = Get-NLSFrameworkDictionary
    if (-not $script:nlsDict) { throw 'NLS.FrameworkDictionary module not loaded.' }

    # Add-NLSFinding is defined at module level for correct scoping

    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Authentication Policies" -ForegroundColor DarkGray }
    # ── Authentication Policies ──────────────────────────────
    $authData = $Results['ExchangePolicies']['AuthenticationPolicies']
    if ($authData) {
        if (-not $authData['OrgDefaultSet']) {
            Add-NLSFinding -ControlId 'AdminMFA' -State 'Partial' `
                -Detail 'No organization default authentication policy set. New users may not inherit MFA or legacy auth restrictions.' `
                -CurrentState 'No default policy assigned' `
                -Recommended 'Organization default authentication policy set' `
                -Remediation 'Set-OrganizationConfig -DefaultAuthenticationPolicy <PolicyName>'
        }
        foreach ($policy in $authData['Policies']) {
            if ($policy['FullyHardened']) {
                Add-NLSFinding -ControlId 'LegacyAuth' -State 'Satisfied' `
                    -Detail "Policy [$($policy['PolicyName'])]: All basic authentication protocols blocked." `
                    -CurrentState 'All basic auth disabled' -Recommended 'All basic auth disabled'
            } else {
                Add-NLSFinding -ControlId 'LegacyAuth' -State 'Gap' `
                    -Detail "Policy [$($policy['PolicyName'])]: Basic auth still enabled on: $($policy['AllFailures'])" `
                    -CurrentState "Basic auth enabled: $($policy['AllFailures'])" `
                    -Recommended 'All AllowBasicAuth* parameters set to False' `
                    -Remediation 'Set all AllowBasicAuth* parameters to $false via Set-AuthenticationPolicy'
            }
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: SMTP Client Auth" -ForegroundColor DarkGray }
    # ── SMTP Client Auth ─────────────────────────────────────
    $smtpData = $Results['ExchangePolicies']['SmtpClientAuth']
    if ($smtpData) {
        if ($smtpData['Disabled']) {
            Add-NLSFinding -ControlId 'SmtpClientAuth' -State 'Satisfied' `
                -Detail 'SMTP client authentication disabled tenant-wide.' `
                -CurrentState 'Disabled' -Recommended 'Disabled'
        } else {
            Add-NLSFinding -ControlId 'SmtpClientAuth' -State 'Gap' `
                -Detail 'SMTP client authentication is enabled. Legacy relay and credential exposure risk.' `
                -CurrentState 'Enabled' -Recommended 'Disabled' `
                -Remediation 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: External Forwarding" -ForegroundColor DarkGray }
    # ── External Forwarding ──────────────────────────────────
    $fwdData = $Results['ExchangePolicies']['ExternalForwarding']
    if ($fwdData) {
        if ($fwdData['AutoForwardDisabled'] -and $fwdData['MailboxesWithForwarding'] -eq 0) {
            Add-NLSFinding -ControlId 'ExternalForwarding' -State 'Satisfied' `
                -Detail 'External auto-forwarding disabled. No mailboxes with active forwarding addresses.' `
                -CurrentState 'Disabled, no mailbox forwarding' -Recommended 'Disabled, no mailbox forwarding'
        } elseif ($fwdData['AutoForwardDisabled'] -and $fwdData['MailboxesWithForwarding'] -gt 0) {
            Add-NLSFinding -ControlId 'ExternalForwarding' -State 'Partial' `
                -Detail "Auto-forward policy disabled but $($fwdData['MailboxesWithForwarding']) mailbox(es) have active forwarding addresses." `
                -CurrentState "Policy disabled, $($fwdData['MailboxesWithForwarding']) mailbox(es) forwarding" `
                -Recommended 'Policy disabled, no mailbox forwarding' `
                -AffectedObjects $fwdData['ForwardingMailboxList'] `
                -Remediation 'Audit and remove unauthorized forwarding addresses on affected mailboxes'
        } else {
            Add-NLSFinding -ControlId 'ExternalForwarding' -State 'Gap' `
                -Detail 'External auto-forwarding is enabled. High exfiltration risk.' `
                -CurrentState 'Enabled' -Recommended 'Disabled' `
                -Remediation 'Set-RemoteDomain Default -AutoForwardEnabled $false'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Mailbox Protocols" -ForegroundColor DarkGray }
    # ── Mailbox Protocols -- v2: granular lists ──────────────
    $protoData = $Results['ExchangePolicies']['MailboxProtocols']
    if ($protoData) {
        if ($protoData['PopEnabledCount'] -eq 0) {
            Add-NLSFinding -ControlId 'PopEnabled' -State 'Satisfied' `
                -Detail "POP3 disabled on all $($protoData['TotalMailboxes']) mailboxes." `
                -CurrentState 'Disabled on all mailboxes' -Recommended 'Disabled on all mailboxes'
        } else {
            Add-NLSFinding -ControlId 'PopEnabled' -State 'Gap' `
                -Detail "$($protoData['PopEnabledCount']) of $($protoData['TotalMailboxes']) mailboxes have POP3 enabled." `
                -CurrentState "Enabled on $($protoData['PopEnabledCount']) mailbox(es)" `
                -Recommended 'Disabled on all mailboxes' `
                -AffectedObjects $protoData['PopEnabledList'] `
                -Remediation 'Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false'
        }

        if ($protoData['ImapEnabledCount'] -eq 0) {
            Add-NLSFinding -ControlId 'ImapEnabled' -State 'Satisfied' `
                -Detail "IMAP disabled on all $($protoData['TotalMailboxes']) mailboxes." `
                -CurrentState 'Disabled on all mailboxes' -Recommended 'Disabled on all mailboxes'
        } else {
            Add-NLSFinding -ControlId 'ImapEnabled' -State 'Gap' `
                -Detail "$($protoData['ImapEnabledCount']) of $($protoData['TotalMailboxes']) mailboxes have IMAP enabled." `
                -CurrentState "Enabled on $($protoData['ImapEnabledCount']) mailbox(es)" `
                -Recommended 'Disabled on all mailboxes' `
                -AffectedObjects $protoData['ImapEnabledList'] `
                -Remediation 'Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -ImapEnabled $false'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Mailbox Auditing" -ForegroundColor DarkGray }
    # ── Mailbox Auditing -- v2: granular lists ───────────────
    $auditData = $Results['ExchangePolicies']['MailboxAuditing']
    if ($auditData) {
        if ($auditData['UnifiedAuditLogEnabled']) {
            Add-NLSFinding -ControlId 'UnifiedAuditLog' -State 'Satisfied' `
                -Detail 'Unified audit logging enabled.' `
                -CurrentState 'Enabled' -Recommended 'Enabled'
        } else {
            Add-NLSFinding -ControlId 'UnifiedAuditLog' -State 'Gap' `
                -Detail 'Unified audit logging is disabled.' `
                -CurrentState 'Disabled' -Recommended 'Enabled' `
                -Remediation 'Enable via Microsoft Purview compliance portal'
        }

        if ($auditData['MailboxesAuditDisabled'] -eq 0) {
            Add-NLSFinding -ControlId 'MailboxAudit' -State 'Satisfied' `
                -Detail 'Mailbox auditing enabled on all mailboxes.' `
                -CurrentState 'Enabled on all mailboxes' -Recommended 'Enabled on all mailboxes'
        } elseif ($auditData['MailboxesAuditDisabled'] -gt 0 -and $auditData['MailboxesAuditDisabled'] -lt 5) {
            Add-NLSFinding -ControlId 'MailboxAudit' -State 'Partial' `
                -Detail "$($auditData['MailboxesAuditDisabled']) mailbox(es) have auditing disabled." `
                -CurrentState "Disabled on $($auditData['MailboxesAuditDisabled']) mailbox(es)" `
                -Recommended 'Enabled on all mailboxes' `
                -AffectedObjects $auditData['AuditDisabledList'] `
                -Remediation 'Set-Mailbox -Identity <mbx> -AuditEnabled $true for affected mailboxes'
        } else {
            Add-NLSFinding -ControlId 'MailboxAudit' -State 'Gap' `
                -Detail "$($auditData['MailboxesAuditDisabled']) mailbox(es) have auditing disabled." `
                -CurrentState "Disabled on $($auditData['MailboxesAuditDisabled']) mailbox(es)" `
                -Recommended 'Enabled on all mailboxes' `
                -AffectedObjects $auditData['AuditDisabledList'] `
                -Remediation 'Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Outbound Spam" -ForegroundColor DarkGray }
    # ── Outbound Spam ────────────────────────────────────────
    $spamData = $Results['ExchangePolicies']['OutboundSpam']
    if ($spamData) {
        if ($spamData['NotifyEnabled'] -and $spamData['NotifyRecipients']) {
            Add-NLSFinding -ControlId 'OutboundSpam' -State 'Satisfied' `
                -Detail 'Outbound spam notification enabled with recipient configured.' `
                -CurrentState 'Enabled' -Recommended 'Enabled with recipient'
        } elseif ($spamData['NotifyEnabled'] -and -not $spamData['NotifyRecipients']) {
            Add-NLSFinding -ControlId 'OutboundSpam' -State 'Partial' `
                -Detail 'Outbound spam notification enabled but no recipient configured. Alerts will not be delivered.' `
                -CurrentState 'Enabled, no recipient' -Recommended 'Enabled with admin recipient' `
                -Remediation 'Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpamRecipients admin@yourdomain.com'
        } else {
            Add-NLSFinding -ControlId 'OutboundSpam' -State 'Gap' `
                -Detail 'Outbound spam notification disabled. Compromised account detection gap.' `
                -CurrentState 'Disabled' -Recommended 'Enabled with admin recipient' `
                -Remediation 'Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Defender for Office 365" -ForegroundColor DarkGray }
    # ── Defender for Office 365 ──────────────────────────────
    $defData = $Results['ExchangePolicies']['DefenderO365']
    if ($defData) {
        $defChecks = @(
            @{ Id = 'SafeAttachments';     Val = $defData['SafeAttachmentBlockEnabled'];  Cur = 'Not enabled'; Rem = 'Enable Safe Attachments policy with Block action in Microsoft Defender portal' }
            @{ Id = 'SafeLinks';           Val = $defData['SafeLinksEnabled'];            Cur = 'Not enabled'; Rem = 'Run Set-SafeLinksPolicy to enable, or configure via https://security.microsoft.com > Policies & rules > Safe Links' }
            @{ Id = 'AntiPhish';           Val = $defData['AntiPhishEnabled'];            Cur = 'Not enabled'; Rem = 'Enable anti-phishing policy in Microsoft Defender portal' }
            @{ Id = 'MailboxIntelligence'; Val = $defData['MailboxIntelligenceEnabled'];  Cur = 'Not enabled'; Rem = 'Enable mailbox intelligence in anti-phishing policy settings' }
            @{ Id = 'ZAPSpam';             Val = $defData['ZapSpamEnabled'];              Cur = 'Not enabled'; Rem = 'Enable ZAP for spam in hosted content filter policy' }
            @{ Id = 'ZAPPhish';            Val = $defData['ZapPhishEnabled'];             Cur = 'Not enabled'; Rem = 'Enable ZAP for phishing in hosted content filter policy' }
            @{ Id = 'ATPSPOTeams';         Val = $defData['ATPForSPOTeamsODB'];           Cur = 'Not enabled'; Rem = 'Enable ATP for SharePoint, Teams, and OneDrive in Microsoft Defender portal' }
        )
        foreach ($check in $defChecks) {
            if ($check['Val']) {
                Add-NLSFinding -ControlId $check['Id'] -State 'Satisfied' `
                    -Detail "$($script:nlsDict[$check['Id']]['Title']) is enabled." `
                    -CurrentState 'Enabled' -Recommended 'Enabled'
            } else {
                Add-NLSFinding -ControlId $check['Id'] -State 'Gap' `
                    -Detail "$($script:nlsDict[$check['Id']]['Title']) is not enabled." `
                    -CurrentState $check['Cur'] -Recommended 'Enabled' `
                    -Remediation $check['Rem']
            }
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: DKIM" -ForegroundColor DarkGray }
    # ── DKIM -- v2: granular domain lists ────────────────────
    $dkimData = $Results['ExchangePolicies']['DKIM']
    if ($dkimData) {
        $dkimDisabled = @($dkimData['Domains'] | Where-Object { -not $_['Enabled'] })
        if ($dkimDisabled.Count -eq 0) {
            Add-NLSFinding -ControlId 'DKIM' -State 'Satisfied' `
                -Detail "DKIM signing enabled on all $(@($dkimData['Domains']).Count) domain(s)." `
                -CurrentState 'Enabled on all domains' -Recommended 'Enabled on all domains'
        } elseif ($dkimDisabled.Count -lt $dkimData['Domains'].Count) {
            Add-NLSFinding -ControlId 'DKIM' -State 'Partial' `
                -Detail "$($dkimDisabled.Count) domain(s) have DKIM signing disabled." `
                -CurrentState "Disabled on $($dkimDisabled.Count) domain(s)" `
                -Recommended 'Enabled on all domains' `
                -AffectedObjects @($dkimDisabled | ForEach-Object { $_['Domain'] }) `
                -Remediation 'Enable-DkimSigningConfig -Identity <domain> for each affected domain'
        } else {
            Add-NLSFinding -ControlId 'DKIM' -State 'Gap' `
                -Detail 'DKIM signing disabled on all domains.' `
                -CurrentState 'Disabled on all domains' -Recommended 'Enabled on all domains' `
                -Remediation 'Enable-DkimSigningConfig -Identity <domain> for each accepted domain'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: DNSSEC" -ForegroundColor DarkGray }
    # ── DNSSEC -- v2: granular domain lists ──────────────────
    $dnssecData = $Results['ExchangePolicies']['DNSSEC']
    if ($dnssecData) {
        $dnssecDisabled = @($dnssecData['Domains'] | Where-Object { -not $_['Enabled'] })
        if ($dnssecDisabled.Count -eq 0) {
            Add-NLSFinding -ControlId 'DNSSEC' -State 'Satisfied' `
                -Detail "DNSSEC enabled on all $(@($dnssecData['Domains']).Count) domain(s)." `
                -CurrentState 'Enabled on all domains' -Recommended 'Enabled on all domains'
        } elseif ($dnssecDisabled.Count -lt $dnssecData['Domains'].Count) {
            Add-NLSFinding -ControlId 'DNSSEC' -State 'Partial' `
                -Detail "$($dnssecDisabled.Count) domain(s) without DNSSEC." `
                -CurrentState "Disabled on $($dnssecDisabled.Count) domain(s)" `
                -Recommended 'Enabled on all domains' `
                -AffectedObjects @($dnssecDisabled | ForEach-Object { $_['Domain'] }) `
                -Remediation 'Enable-DnssecForVerifiedDomain -DomainName <domain> then update MX to p-v1.mx.microsoft endpoint'
        } else {
            Add-NLSFinding -ControlId 'DNSSEC' -State 'Gap' `
                -Detail 'DNSSEC not enabled on any domains.' `
                -CurrentState 'Disabled on all domains' -Recommended 'Enabled on all domains' `
                -Remediation 'Enable-DnssecForVerifiedDomain -DomainName <domain> for each accepted domain'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Conditional Access" -ForegroundColor DarkGray }
    # ── Conditional Access ───────────────────────────────────
    $caData = $Results['ConditionalAccess']['ConditionalAccess']
    if ($caData) {
        # Remove any AdminMFA/LegacyAuth findings from auth policy section
        # CA data is more authoritative for these controls
        $toRemove = @($script:findings | Where-Object { $_['ControlId'] -in @('AdminMFA', 'LegacyAuth') })
        foreach ($r in $toRemove) { [void]$script:findings.Remove($r) }
        [void]$script:addedControls.Remove('AdminMFA')
        [void]$script:addedControls.Remove('LegacyAuth')

        # Also count policies with MFA-related display names as satisfying MFA requirement
        $mfaSatisfied = $caData['MfaEnforcingCount'] -gt 0 -or
            ($caData['Policies'] | Where-Object { $_['IsEnabled'] -and $_['DisplayName'] -match 'mfa|multifactor|multi-factor' }).Count -gt 0

        if ($mfaSatisfied -and $caData['EnabledCount'] -gt 0) {
            Add-NLSFinding -ControlId 'AdminMFA' -State 'Satisfied' `
                -Detail "$($caData['MfaEnforcingCount']) Conditional Access policy/policies enforcing MFA as a grant control." `
                -CurrentState 'MFA enforced via CA policy' -Recommended 'MFA enforced via CA policy'
            Add-NLSFinding -ControlId 'CAPolicy' -State 'Satisfied' `
                -Detail "$($caData['EnabledCount']) CA policy/policies in enforcement mode. $($caData['MfaEnforcingCount']) enforce MFA." `
                -CurrentState "$($caData['EnabledCount']) policies enabled" -Recommended 'Policies in enabled enforcement mode'
        } elseif ($caData['ReportOnlyCount'] -gt 0 -and $caData['MfaEnforcingCount'] -gt 0) {
            Add-NLSFinding -ControlId 'CAPolicy' -State 'Partial' `
                -Detail "$($caData['ReportOnlyCount']) CA policy/policies in report-only mode. Not enforcing access control decisions." `
                -CurrentState "$($caData['ReportOnlyCount']) policies report-only" `
                -Recommended 'All policies in enabled enforcement mode' `
                -Remediation 'Review report-only policies and enable those that are production-ready'
        } else {
            Add-NLSFinding -ControlId 'AdminMFA' -State 'Gap' `
                -Detail 'No enabled Conditional Access policy enforces MFA as a grant control.' `
                -CurrentState 'No MFA enforcement via CA' -Recommended 'CA policy enforcing MFA for all users' `
                -Remediation 'Create or enable a CA policy requiring MFA for all users and all cloud apps'
            Add-NLSFinding -ControlId 'CAPolicy' -State 'Gap' `
                -Detail 'No Conditional Access policies in enabled enforcement mode.' `
                -CurrentState 'No enabled CA policies' -Recommended 'Policies in enabled enforcement mode' `
                -Remediation 'Review and enable CA policies. At minimum enforce MFA and block legacy authentication.'
        }
        if ($caData['LegacyAuthBlocking'] -gt 0) {
            Add-NLSFinding -ControlId 'LegacyAuth' -State 'Satisfied' `
                -Detail "$($caData['LegacyAuthBlocking']) CA policy/policies actively blocking legacy authentication clients." `
                -CurrentState 'Legacy auth blocked via CA' -Recommended 'Legacy auth blocked via CA'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: DMARC" -ForegroundColor DarkGray }
    # ── DMARC Scoring ─────────────────────────────────────────
    # Excludes onmicrosoft.com -- Microsoft-managed, cannot configure DMARC
    $dmarcData = $Results['DMARC']
    if ($dmarcData -and $dmarcData['DMARC']) {
        $dmarc       = $dmarcData['DMARC']
        $allDomains  = @($dmarc['Domains'])
        # Exclude Microsoft-managed domains from scoring
        $userDomains = @($allDomains | Where-Object { $_['Domain'] -notmatch 'onmicrosoft\.com$' })
        $total       = $userDomains.Count
        $missing     = ($userDomains | Where-Object { -not $_['HasDMARC'] }).Count
        $enforced    = ($userDomains | Where-Object { $_['Enforced'] }).Count
        $quarantine  = ($userDomains | Where-Object { $_['Partial'] }).Count
        $nonePolicy  = ($userDomains | Where-Object { $_['Policy'] -eq 'none' }).Count

        if ($missing -eq 0 -and $enforced -eq $total) {
            Add-NLSFinding -ControlId 'DMARC' -State 'Satisfied' `
                -Detail "DMARC at p=reject on all $total domain(s). onmicrosoft.com excluded." `
                -CurrentState 'p=reject on all domains' -Recommended 'p=reject on all domains'
        } elseif ($missing -eq 0) {
            Add-NLSFinding -ControlId 'DMARC' -State 'Partial' `
                -Detail "$quarantine domain(s) at p=quarantine, $nonePolicy at p=none. Advance to p=reject." `
                -CurrentState "Not all at p=reject" -Recommended 'p=reject on all domains' `
                -Remediation 'Advance DMARC policy to p=reject after reviewing aggregate reports'
        } else {
            Add-NLSFinding -ControlId 'DMARC' -State 'Gap' `
                -Detail "$missing of $total domain(s) missing DMARC. onmicrosoft.com excluded." `
                -CurrentState "Missing on $missing domain(s)" -Recommended 'p=reject on all domains' `
                -Remediation 'Add TXT record at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain> then advance to p=reject'
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Mail Flow Hardening" -ForegroundColor DarkGray }
    # ── Mail Flow Hardening ───────────────────────────────────
    $mfData = $Results['MailFlow']
    if ($mfData) {
        # MTA-STS -- exclude onmicrosoft.com (Microsoft-managed, MTA-STS not applicable)
        if ($mfData['MTASTS']) {
            $mtas        = $mfData['MTASTS']
            $mtasDomains = @($mtas['Domains'] | Where-Object { $_['Domain'] -notmatch 'onmicrosoft.com' })
            $mtasTotal   = $mtasDomains.Count
            $mtasEnabled = ($mtasDomains | Where-Object { $_['MTAStsEnabled'] }).Count
            if ($mtasTotal -eq 0) { $mtasTotal = $mtas['TotalDomains']; $mtasEnabled = $mtas['EnabledCount'] }
            if ($mtasEnabled -eq $mtasTotal -and $mtasTotal -gt 0) {
                Add-NLSFinding -ControlId 'MTASTS' -State 'Satisfied' `
                    -Detail "MTA-STS published on all $mtasTotal domain(s). onmicrosoft.com excluded." `
                    -CurrentState 'Enabled on all domains' -Recommended 'Enabled on all domains'
            } else {
                Add-NLSFinding -ControlId 'MTASTS' -State 'Gap' `
                    -Detail "MTA-STS not published on $($mtasTotal - $mtasEnabled) of $mtasTotal domain(s). SMTP downgrade attacks possible." `
                    -CurrentState "Enabled on $($mtas['EnabledCount']) of $($mtas['TotalDomains']) domain(s)" `
                    -Recommended 'MTA-STS policy published on all domains' `
                    -Remediation 'Publish MTA-STS policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt and add _mta-sts TXT record'
            }
        }

        # Inbound spam
        if ($mfData['InboundSpam']) {
            $spam = $mfData['InboundSpam']
            if ($spam['Hardened']) {
                Add-NLSFinding -ControlId 'InboundSpamPolicy' -State 'Satisfied' `
                    -Detail "Inbound spam policy hardened. High confidence spam and phish quarantined. Bulk threshold $($spam['BulkThreshold'])." `
                    -CurrentState 'Hardened' -Recommended 'Hardened'
            } else {
                Add-NLSFinding -ControlId 'InboundSpamPolicy' -State 'Partial' `
                    -Detail "Inbound spam policy not fully hardened. High confidence spam action: $($spam['HighConfidenceSpamAction']). Phish action: $($spam['PhishSpamAction']). Bulk threshold: $($spam['BulkThreshold'])." `
                    -CurrentState "HighConfidenceSpam: $($spam['HighConfidenceSpamAction']), Phish: $($spam['PhishSpamAction']), BCL: $($spam['BulkThreshold'])" `
                    -Recommended 'HighConfidenceSpam: Quarantine, Phish: Quarantine, BCL: 6 or lower' `
                    -Remediation 'Set-HostedContentFilterPolicy -HighConfidenceSpamAction Quarantine -PhishSpamAction Quarantine -BulkThreshold 6'
            }
        }

        # Malware filter -- score on actual values not just Hardened flag
        if ($mfData['MalwareFilter']) {
            $malware    = $mfData['MalwareFilter']
            $mAction    = $malware['Action']
            $mZap       = $malware['ZapEnabled']
            $mHardened  = ($mAction -in @('DeleteMessage','Quarantine','')) -and $mZap
            # Empty action means EXO is using default (DeleteMessage) -- treat as hardened
            $mSatisfied = ($mAction -eq '' -or $mAction -eq 'DeleteMessage') -and $mZap
            if ($mSatisfied -or $malware['Hardened']) {
                Add-NLSFinding -ControlId 'MalwareFilterPolicy' -State 'Satisfied' `
                    -Detail "Malware filter configured. ZAP enabled. Infected messages deleted." `
                    -CurrentState 'DeleteMessage, ZAP enabled' -Recommended 'DeleteMessage, ZAP enabled'
            } else {
                Add-NLSFinding -ControlId 'MalwareFilterPolicy' -State 'Gap' `
                    -Detail "Malware filter action: $mAction. ZAP enabled: $mZap." `
                    -CurrentState "Action: $mAction, ZAP: $mZap" `
                    -Recommended 'Action: DeleteMessage, ZAP: True' `
                    -Remediation 'Set-MalwareFilterPolicy -Action DeleteMessage -ZapEnabled $true'
            }
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Identity Hardening" -ForegroundColor DarkGray }
    # ── Identity Hardening ────────────────────────────────────
    $idData = $Results['IdentityHardening']
    if ($idData) {
        # Security Defaults -- should be disabled when CA is in use
        if ($idData['SecurityDefaults']) {
            $secDef = $idData['SecurityDefaults']
            if (-not $secDef['IsEnabled']) {
                Add-NLSFinding -ControlId 'SecurityDefaults' -State 'Satisfied' `
                    -Detail 'Security Defaults disabled. Conditional Access policies are in control.' `
                    -CurrentState 'Disabled' -Recommended 'Disabled when CA is active'
            } else {
                Add-NLSFinding -ControlId 'SecurityDefaults' -State 'Gap' `
                    -Detail 'Security Defaults enabled. This conflicts with Conditional Access policies and must be disabled.' `
                    -CurrentState 'Enabled' -Recommended 'Disabled' `
                    -Remediation 'Disable Security Defaults in Entra ID > Properties > Manage Security Defaults before creating CA policies'
            }
        }

        # Authentication Methods
        if ($idData['AuthenticationMethods']) {
            $authMeth = $idData['AuthenticationMethods']
            if ($authMeth['MicrosoftAuthenticatorEnabled']) {
                Add-NLSFinding -ControlId 'AuthMethodsPolicy' -State 'Satisfied' `
                    -Detail "Microsoft Authenticator enabled. FIDO2: $($authMeth['FIDO2Enabled']). SMS: $($authMeth['SMSEnabled'])." `
                    -CurrentState 'Authenticator enabled' -Recommended 'Authenticator and/or FIDO2 enabled'
            } else {
                Add-NLSFinding -ControlId 'AuthMethodsPolicy' -State 'Gap' `
                    -Detail 'Microsoft Authenticator not enabled in authentication methods policy.' `
                    -CurrentState 'Authenticator disabled' -Recommended 'Authenticator and/or FIDO2 enabled' `
                    -Remediation 'Enable Microsoft Authenticator in Entra ID > Security > Authentication Methods'
            }
        }

        # Consent Framework
        if ($idData['ConsentFramework']) {
            $consent = $idData['ConsentFramework']
            if (-not $consent['UsersCanConsentToApps']) {
                Add-NLSFinding -ControlId 'ConsentFramework' -State 'Satisfied' `
                    -Detail 'User consent to apps disabled. Admin consent required for all app registrations.' `
                    -CurrentState 'User consent disabled' -Recommended 'User consent disabled'
            } else {
                Add-NLSFinding -ControlId 'ConsentFramework' -State 'Gap' `
                    -Detail 'Users can consent to apps without admin approval. OAuth phishing risk.' `
                    -CurrentState 'User consent enabled' -Recommended 'User consent disabled' `
                    -Remediation 'Disable user consent in Entra ID > Enterprise Applications > Consent and Permissions > User Consent Settings'
            }
        }
    }

        if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Break-Glass Account" -ForegroundColor DarkGray }
    # ── Break-Glass Account ───────────────────────────────────
    $bgData = $Results['BreakGlass']
    if ($bgData -and $bgData['BreakGlassAccounts']) {
        $bg = $bgData['BreakGlassAccounts']
        if ($bg['Count'] -eq 0) {
            Add-NLSFinding -ControlId 'BreakGlass' -State 'Gap' `
                -Detail 'No break-glass account detected. Every tenant should have at least one emergency access account excluded from CA policies.' `
                -CurrentState 'No break-glass account found' `
                -Recommended 'Break-glass account exists and excluded from all CA policies' `
                -Remediation 'Create a cloud-only emergency access account excluded from all CA policies. Name it breakglass@ or emergency@. Monitor sign-ins via alerts.'
        } elseif ($bg['Configured']) {
            Add-NLSFinding -ControlId 'BreakGlass' -State 'Satisfied' `
                -Detail "$($bg['Count']) break-glass account(s) detected and excluded from CA policies." `
                -CurrentState 'Break-glass configured and excluded from CA' -Recommended 'Break-glass configured and excluded from CA'
        } else {
            Add-NLSFinding -ControlId 'BreakGlass' -State 'Partial' `
                -Detail "$($bg['Count']) break-glass account(s) found but not excluded from all enabled CA policies." `
                -CurrentState 'Break-glass exists but not excluded from CA' `
                -Recommended 'Break-glass excluded from all CA policies' `
                -AffectedObjects $bg['NotExcludedFromCA'] `
                -Remediation 'Add break-glass accounts to exclusion list on all enabled CA policies in Entra ID'
        }
    }

    # ── Stale Accounts ───────────────────────────────────────
    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Stale Accounts" -ForegroundColor DarkGray }
    $staleData = $Results['StaleAccounts']
    if ($staleData -and $staleData['StaleAccounts']) {
        $stale = $staleData['StaleAccounts']
        if ($stale['StaleCount'] -eq 0) {
            Add-NLSFinding -ControlId 'StaleAccounts' -State 'Satisfied' `
                -Detail "No accounts inactive beyond $($stale['ThresholdDays']) days." `
                -CurrentState 'No stale accounts' -Recommended 'No stale accounts'
        } elseif ($stale['StaleCount'] -le 2) {
            Add-NLSFinding -ControlId 'StaleAccounts' -State 'Partial' `
                -Detail "$($stale['StaleCount']) account(s) inactive $($stale['ThresholdDays'])+ days. Review and disable or remove." `
                -CurrentState "$($stale['StaleCount']) stale account(s)" -Recommended '0 stale accounts' `
                -AffectedObjects @($stale['StaleList'] | ForEach-Object { $_['UPN'] }) `
                -Remediation 'Get-MgUser -UserId <UPN> | Update-MgUser -AccountEnabled $false'
        } else {
            Add-NLSFinding -ControlId 'StaleAccounts' -State 'Gap' `
                -Detail "$($stale['StaleCount']) account(s) inactive $($stale['ThresholdDays'])+ days. Unreviewed inactive accounts expand the attack surface." `
                -CurrentState "$($stale['StaleCount']) stale account(s)" -Recommended '0 stale accounts' `
                -AffectedObjects @($stale['StaleList'] | ForEach-Object { $_['UPN'] }) `
                -Remediation 'Get-MgUser -UserId <UPN> | Update-MgUser -AccountEnabled $false'
        }
    }

    # ── Global Admin Count ────────────────────────────────────
    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Global Admin Count" -ForegroundColor DarkGray }
    $adminData = $Results['AdminRoles']
    if ($adminData -and $adminData['AdminRoleInventory']) {
        $inv = $adminData['AdminRoleInventory']
        if ($inv['GlobalAdminCount'] -le 2) {
            Add-NLSFinding -ControlId 'GlobalAdminCount' -State 'Satisfied' `
                -Detail "$($inv['GlobalAdminCount']) Global Admin(s). Within recommended maximum of 2." `
                -CurrentState "$($inv['GlobalAdminCount']) Global Admins" -Recommended '2 or fewer Global Admins'
        } else {
            Add-NLSFinding -ControlId 'GlobalAdminCount' -State 'Gap' `
                -Detail "$($inv['GlobalAdminCount']) Global Admins detected. Exceeds recommended maximum of 2. Each additional GA is a full-tenant compromise path." `
                -CurrentState "$($inv['GlobalAdminCount']) Global Admins" -Recommended '2 or fewer Global Admins' `
                -Remediation 'Review Global Administrator assignments in Entra ID > Roles. Demote non-essential admins to scoped roles (Security Admin, Exchange Admin, etc)'
        }
    }

    # ── Shared Mailbox Hardening ──────────────────────────────
    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Shared Mailbox Hardening" -ForegroundColor DarkGray }
    $sharedData = $Results['SharedMailboxes']
    if ($sharedData -and $sharedData['SharedMailboxHardening']) {
        $shared = $sharedData['SharedMailboxHardening']
        if ($shared['SignInEnabledCount'] -eq 0 -and $shared['TotalSharedMailboxes'] -gt 0) {
            Add-NLSFinding -ControlId 'SharedMailboxSignIn' -State 'Satisfied' `
                -Detail "All $($shared['TotalSharedMailboxes']) shared mailbox(es) have interactive sign-in disabled." `
                -CurrentState 'Sign-in disabled on all' -Recommended 'Sign-in disabled on all'
        } elseif ($shared['TotalSharedMailboxes'] -eq 0) {
            # No shared mailboxes -- nothing to check, skip scoring
        } else {
            Add-NLSFinding -ControlId 'SharedMailboxSignIn' -State 'Gap' `
                -Detail "$($shared['SignInEnabledCount']) shared mailbox(es) have interactive sign-in enabled. Shared mailboxes should never have interactive sign-in." `
                -CurrentState "$($shared['SignInEnabledCount']) with sign-in enabled" -Recommended 'Sign-in disabled on all' `
                -AffectedObjects $shared['SignInEnabledList'] `
                -Remediation 'Get-Mailbox -RecipientTypeDetails SharedMailbox | ForEach-Object { Update-MgUser -UserId $_.UserPrincipalName -AccountEnabled $false }'
        }
    }

    # ── Named Locations (Zero Trust) ─────────────────────────
    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: Named Locations" -ForegroundColor DarkGray }
    if ($ZeroTrust) {
        $namedLocData = $Results['NamedLocations']
        if ($namedLocData -and $namedLocData['NamedLocations']) {
            $nlocs = $namedLocData['NamedLocations']
            if ($nlocs['TotalDefined'] -gt 0) {
                Add-NLSFinding -ControlId 'NamedLocations' -State 'Satisfied' `
                    -Detail "$($nlocs['TotalDefined']) named location(s) defined. Network trust boundaries support Zero Trust CA policy conditions." `
                    -CurrentState "$($nlocs['TotalDefined']) locations defined" -Recommended '1 or more named locations defined'
            } else {
                Add-NLSFinding -ControlId 'NamedLocations' -State 'Gap' `
                    -Detail "No named locations defined. Without network trust boundaries CA policies cannot enforce location-based access controls." `
                    -CurrentState '0 named locations' -Recommended '1 or more named locations defined' `
                    -Remediation 'Define named locations in Entra ID > Security > Named Locations. At minimum define corporate network ranges as trusted.'
            }
        }
    }

    # ── User MFA Gap ─────────────────────────────────────────
    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: User MFA Gap" -ForegroundColor DarkGray }
    $mfaData = $Results['MFAStatus']
    if ($mfaData -and $mfaData['UserMFAStatus']) {
        $mfa = $mfaData['UserMFAStatus']
        # Exclude break-glass accounts from MFA requirement
        $nonBGNoMFA = @($mfa['NoMFAList'] | Where-Object { -not ($_['UPN'] -match 'breakglass|break-glass|break_glass|emergency') })
        if ($nonBGNoMFA.Count -eq 0) {
            Add-NLSFinding -ControlId 'UserMFAGap' -State 'Satisfied' `
                -Detail "All non-break-glass users have MFA registered. $($mfa['TotalUsers']) total users." `
                -CurrentState 'All users MFA registered' -Recommended 'All users MFA registered'
        } else {
            Add-NLSFinding -ControlId 'UserMFAGap' -State 'Gap' `
                -Detail "$($nonBGNoMFA.Count) user(s) have no MFA method registered. Unregistered accounts cannot satisfy MFA CA policy grant controls." `
                -CurrentState "$($nonBGNoMFA.Count) users without MFA" -Recommended 'All users MFA registered' `
                -AffectedObjects @($nonBGNoMFA | ForEach-Object { $_['UPN'] }) `
                -Remediation 'Require MFA registration via Entra ID > Security > Authentication Methods > Registration Campaign'
        }
    }

    # ── External Collaboration ────────────────────────────────
    if ($script:nlsDebug) { Write-Host "  [DEBUG] Scoring: External Collaboration" -ForegroundColor DarkGray }
    $extCollabData = $Results['IdentityHardening']
    if ($extCollabData -and $extCollabData['ExternalCollaboration']) {
        $extCollab = $extCollabData['ExternalCollaboration']
        $guestPolicy = $extCollab['GuestInvitePolicy']
        if ($guestPolicy -in @('adminsAndGuestInviters','adminsGuestInvitersAndMemberList','none')) {
            Add-NLSFinding -ControlId 'ExternalCollaboration' -State 'Satisfied' `
                -Detail "Guest invitations restricted. Policy: $guestPolicy." `
                -CurrentState $guestPolicy -Recommended 'adminsAndGuestInviters or none'
        } elseif ($guestPolicy -eq 'everyone') {
            Add-NLSFinding -ControlId 'ExternalCollaboration' -State 'Gap' `
                -Detail "All users can invite external guests. Guest invite policy set to: everyone. Any user can create external collaboration without admin approval." `
                -CurrentState 'everyone (all users can invite)' -Recommended 'adminsAndGuestInviters or none' `
                -Remediation 'Set guest invite policy in Entra ID > External Identities > External collaboration settings'
        } else {
            Add-NLSFinding -ControlId 'ExternalCollaboration' -State 'Partial' `
                -Detail "Guest invite policy: $guestPolicy. Review whether this meets your external collaboration requirements." `
                -CurrentState $guestPolicy -Recommended 'adminsAndGuestInviters or none'
        }
    }

    # ── Summary ──────────────────────────────────────────────
    if ($script:nlsDebug) {
        Write-Host "  [DEBUG] Findings list ($($script:findings.Count) items):" -ForegroundColor DarkGray
        foreach ($f in $script:findings) {
            Write-Host "    $($f.State.PadRight(10)) $($f.ControlId)" -ForegroundColor DarkGray
        }
        Write-Host "  [DEBUG] addedControls set ($($script:addedControls.Count) items): $($script:addedControls -join ', ')" -ForegroundColor DarkGray
    }
    $satisfied = @($script:findings | Where-Object { $_['State'] -eq 'Satisfied' }).Count
    $partial   = @($script:findings | Where-Object { $_['State'] -eq 'Partial' }).Count
    $gap       = @($script:findings | Where-Object { $_['State'] -eq 'Gap' }).Count
    if ($script:nlsDebug) {
        Write-Host "  [DEBUG] Summary calc: Satisfied=$satisfied Partial=$partial Gap=$gap Total=$($script:findings.Count)" -ForegroundColor Cyan
        Write-Host "  [DEBUG] Gap items:" -ForegroundColor Cyan
        $script:findings | Where-Object { $_['State'] -eq 'Gap' } | ForEach-Object {
            Write-Host "    $($_['ControlId']) -- $($_['State'])" -ForegroundColor Cyan
        }
    }

    return [ordered]@{
        Findings  = $script:findings
        Summary   = [ordered]@{
            Satisfied = $satisfied
            Partial   = $partial
            Gap       = $gap
            Total     = $script:findings.Count
        }
        Frameworks = [ordered]@{
            NIST          = $NIST
            CIS           = $CIS
            HIPAA         = $HIPAA
            HIPAAProposed = $HIPAAProposed
            ZeroTrust     = $ZeroTrust
        }
        DictionaryVersion = Get-NLSDictionaryVersion
    }
}

Export-ModuleMember -Function Invoke-NLSScoringModel, Add-NLSFinding
