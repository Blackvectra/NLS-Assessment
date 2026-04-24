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

function Invoke-NLSScoringModel {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Results,
        [bool]$Redact        = $false,
        [bool]$NIST          = $true,
        [bool]$CIS           = $false,
        [bool]$HIPAA         = $false,
        [bool]$HIPAAProposed = $false,
        [bool]$ZeroTrust     = $false
    )

    $dict = Get-NLSFrameworkDictionary
    if (-not $dict) { throw 'NLS.FrameworkDictionary module not loaded.' }

    $findings = [System.Collections.Generic.List[hashtable]]::new()

    # ── Helper ───────────────────────────────────────────────
    function Add-Finding {
        param(
            [string]$ControlId,
            [ValidateSet('Satisfied', 'Partial', 'Gap')]
            [string]$State,
            [string]$Detail,
            [string]$Remediation  = '',
            [string]$CurrentState = '',
            [string]$Recommended  = '',
            [string[]]$AffectedObjects = @()
        )

        $entry = $dict[$ControlId]
        if (-not $entry) {
            Register-NLSException -Source 'Invoke-NLSScoringModel' -Message "ControlId '$ControlId' not found in framework dictionary"
            return
        }

        $finding = [ordered]@{
            ControlId      = $ControlId
            Title          = $entry.Title
            Category       = $entry.Category
            State          = $State
            Severity       = switch ($State) { 'Satisfied' { 'Pass' } 'Partial' { 'Medium' } 'Gap' { 'High' } }
            Detail         = $Detail
            Remediation    = $Remediation
            CurrentState   = $CurrentState
            Recommended    = $Recommended
            AffectedObjects = $AffectedObjects
        }

        if ($NIST -and $entry.NIST -and $entry.NIST[$State]) {
            $finding['NIST_SP800_53_r5'] = $entry.NIST[$State].Citation
            $finding['NIST_Requirement'] = $entry.NIST[$State].Requirement
            $finding['NIST_Detail']      = $entry.NIST[$State].Detail
        }
        if ($CIS -and $entry.CIS -and $entry.CIS[$State]) {
            $finding['CIS_v8_1']         = $entry.CIS[$State].Citation
            $finding['CIS_Requirement']  = $entry.CIS[$State].Requirement
            $finding['CIS_Detail']       = $entry.CIS[$State].Detail
        }
        if ($HIPAA -and $entry.HIPAA -and $entry.HIPAA[$State]) {
            $finding['HIPAA_Current']    = $entry.HIPAA[$State].Citation
            $finding['HIPAA_Req']        = $entry.HIPAA[$State].Requirement
            $finding['HIPAA_Detail']     = $entry.HIPAA[$State].Detail
        }
        if ($HIPAAProposed -and $entry.HIPAAProposed -and $entry.HIPAAProposed[$State]) {
            $finding['HIPAA_Proposed']        = $entry.HIPAAProposed[$State].Citation
            $finding['HIPAA_Proposed_Req']    = $entry.HIPAAProposed[$State].Requirement
            $finding['HIPAA_Proposed_Detail'] = $entry.HIPAAProposed[$State].Detail
        }

        $findings.Add($finding)
    }

    # ── Authentication Policies ──────────────────────────────
    $authData = $Results['ExchangePolicies']['AuthenticationPolicies']
    if ($authData) {
        if (-not $authData.OrgDefaultSet) {
            Add-Finding -ControlId 'AdminMFA' -State 'Partial' `
                -Detail 'No organization default authentication policy set. New users may not inherit MFA or legacy auth restrictions.' `
                -CurrentState 'No default policy assigned' `
                -Recommended 'Organization default authentication policy set' `
                -Remediation 'Run Set-OrganizationConfig -DefaultAuthenticationPolicy <PolicyName>'
        }
        foreach ($policy in $authData.Policies) {
            if ($policy.FullyHardened) {
                Add-Finding -ControlId 'LegacyAuth' -State 'Satisfied' `
                    -Detail "Policy [$($policy.PolicyName)]: All basic authentication protocols blocked." `
                    -CurrentState 'All basic auth disabled' -Recommended 'All basic auth disabled'
            } else {
                Add-Finding -ControlId 'LegacyAuth' -State 'Gap' `
                    -Detail "Policy [$($policy.PolicyName)]: Basic auth still enabled on: $($policy.AllFailures)" `
                    -CurrentState "Basic auth enabled: $($policy.AllFailures)" `
                    -Recommended 'All AllowBasicAuth* parameters set to False' `
                    -Remediation 'Set all AllowBasicAuth* parameters to $false via Set-AuthenticationPolicy'
            }
        }
    }

    # ── SMTP Client Auth ─────────────────────────────────────
    $smtpData = $Results['ExchangePolicies']['SmtpClientAuth']
    if ($smtpData) {
        if ($smtpData.Disabled) {
            Add-Finding -ControlId 'SmtpClientAuth' -State 'Satisfied' `
                -Detail 'SMTP client authentication disabled tenant-wide.' `
                -CurrentState 'Disabled' -Recommended 'Disabled'
        } else {
            Add-Finding -ControlId 'SmtpClientAuth' -State 'Gap' `
                -Detail 'SMTP client authentication is enabled. Legacy relay and credential exposure risk.' `
                -CurrentState 'Enabled' -Recommended 'Disabled' `
                -Remediation 'Run Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
        }
    }

    # ── External Forwarding ──────────────────────────────────
    $fwdData = $Results['ExchangePolicies']['ExternalForwarding']
    if ($fwdData) {
        if ($fwdData.AutoForwardDisabled -and $fwdData.MailboxesWithForwarding -eq 0) {
            Add-Finding -ControlId 'ExternalForwarding' -State 'Satisfied' `
                -Detail 'External auto-forwarding disabled. No mailboxes with active forwarding addresses.' `
                -CurrentState 'Disabled, no mailbox forwarding' -Recommended 'Disabled, no mailbox forwarding'
        } elseif ($fwdData.AutoForwardDisabled -and $fwdData.MailboxesWithForwarding -gt 0) {
            Add-Finding -ControlId 'ExternalForwarding' -State 'Partial' `
                -Detail "Auto-forward policy disabled but $($fwdData.MailboxesWithForwarding) mailbox(es) have active forwarding addresses." `
                -CurrentState "Policy disabled, $($fwdData.MailboxesWithForwarding) mailbox(es) forwarding" `
                -Recommended 'Policy disabled, no mailbox forwarding' `
                -AffectedObjects $fwdData.ForwardingMailboxList `
                -Remediation 'Audit and remove unauthorized forwarding addresses on affected mailboxes'
        } else {
            Add-Finding -ControlId 'ExternalForwarding' -State 'Gap' `
                -Detail 'External auto-forwarding is enabled. High exfiltration risk.' `
                -CurrentState 'Enabled' -Recommended 'Disabled' `
                -Remediation 'Run Set-RemoteDomain Default -AutoForwardEnabled $false'
        }
    }

    # ── Mailbox Protocols -- v2: granular lists ──────────────
    $protoData = $Results['ExchangePolicies']['MailboxProtocols']
    if ($protoData) {
        if ($protoData.PopEnabledCount -eq 0) {
            Add-Finding -ControlId 'PopEnabled' -State 'Satisfied' `
                -Detail "POP3 disabled on all $($protoData.TotalMailboxes) mailboxes." `
                -CurrentState 'Disabled on all mailboxes' -Recommended 'Disabled on all mailboxes'
        } else {
            Add-Finding -ControlId 'PopEnabled' -State 'Gap' `
                -Detail "$($protoData.PopEnabledCount) of $($protoData.TotalMailboxes) mailboxes have POP3 enabled." `
                -CurrentState "Enabled on $($protoData.PopEnabledCount) mailbox(es)" `
                -Recommended 'Disabled on all mailboxes' `
                -AffectedObjects $protoData.PopEnabledList `
                -Remediation 'Run Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false'
        }

        if ($protoData.ImapEnabledCount -eq 0) {
            Add-Finding -ControlId 'ImapEnabled' -State 'Satisfied' `
                -Detail "IMAP disabled on all $($protoData.TotalMailboxes) mailboxes." `
                -CurrentState 'Disabled on all mailboxes' -Recommended 'Disabled on all mailboxes'
        } else {
            Add-Finding -ControlId 'ImapEnabled' -State 'Gap' `
                -Detail "$($protoData.ImapEnabledCount) of $($protoData.TotalMailboxes) mailboxes have IMAP enabled." `
                -CurrentState "Enabled on $($protoData.ImapEnabledCount) mailbox(es)" `
                -Recommended 'Disabled on all mailboxes' `
                -AffectedObjects $protoData.ImapEnabledList `
                -Remediation 'Run Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -ImapEnabled $false'
        }
    }

    # ── Mailbox Auditing -- v2: granular lists ───────────────
    $auditData = $Results['ExchangePolicies']['MailboxAuditing']
    if ($auditData) {
        if ($auditData.UnifiedAuditLogEnabled) {
            Add-Finding -ControlId 'UnifiedAuditLog' -State 'Satisfied' `
                -Detail 'Unified audit logging enabled.' `
                -CurrentState 'Enabled' -Recommended 'Enabled'
        } else {
            Add-Finding -ControlId 'UnifiedAuditLog' -State 'Gap' `
                -Detail 'Unified audit logging is disabled.' `
                -CurrentState 'Disabled' -Recommended 'Enabled' `
                -Remediation 'Enable via Microsoft Purview compliance portal'
        }

        if ($auditData.MailboxesAuditDisabled -eq 0) {
            Add-Finding -ControlId 'MailboxAudit' -State 'Satisfied' `
                -Detail 'Mailbox auditing enabled on all mailboxes.' `
                -CurrentState 'Enabled on all mailboxes' -Recommended 'Enabled on all mailboxes'
        } elseif ($auditData.MailboxesAuditDisabled -gt 0 -and $auditData.MailboxesAuditDisabled -lt 5) {
            Add-Finding -ControlId 'MailboxAudit' -State 'Partial' `
                -Detail "$($auditData.MailboxesAuditDisabled) mailbox(es) have auditing disabled." `
                -CurrentState "Disabled on $($auditData.MailboxesAuditDisabled) mailbox(es)" `
                -Recommended 'Enabled on all mailboxes' `
                -AffectedObjects $auditData.AuditDisabledList `
                -Remediation 'Run Set-Mailbox -Identity <mbx> -AuditEnabled $true for affected mailboxes'
        } else {
            Add-Finding -ControlId 'MailboxAudit' -State 'Gap' `
                -Detail "$($auditData.MailboxesAuditDisabled) mailbox(es) have auditing disabled." `
                -CurrentState "Disabled on $($auditData.MailboxesAuditDisabled) mailbox(es)" `
                -Recommended 'Enabled on all mailboxes' `
                -AffectedObjects $auditData.AuditDisabledList `
                -Remediation 'Run Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true'
        }
    }

    # ── Outbound Spam ────────────────────────────────────────
    $spamData = $Results['ExchangePolicies']['OutboundSpam']
    if ($spamData) {
        if ($spamData.NotifyEnabled -and $spamData.NotifyRecipients) {
            Add-Finding -ControlId 'OutboundSpam' -State 'Satisfied' `
                -Detail 'Outbound spam notification enabled with recipient configured.' `
                -CurrentState 'Enabled' -Recommended 'Enabled with recipient'
        } elseif ($spamData.NotifyEnabled -and -not $spamData.NotifyRecipients) {
            Add-Finding -ControlId 'OutboundSpam' -State 'Partial' `
                -Detail 'Outbound spam notification enabled but no recipient configured. Alerts will not be delivered.' `
                -CurrentState 'Enabled, no recipient' -Recommended 'Enabled with admin recipient' `
                -Remediation 'Run Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpamRecipients admin@yourdomain.com'
        } else {
            Add-Finding -ControlId 'OutboundSpam' -State 'Gap' `
                -Detail 'Outbound spam notification disabled. Compromised account detection gap.' `
                -CurrentState 'Disabled' -Recommended 'Enabled with admin recipient' `
                -Remediation 'Run Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true'
        }
    }

    # ── Defender for Office 365 ──────────────────────────────
    $defData = $Results['ExchangePolicies']['DefenderO365']
    if ($defData) {
        $defChecks = @(
            @{ Id = 'SafeAttachments';     Val = $defData.SafeAttachmentBlockEnabled;  Cur = 'Not enabled'; Rem = 'Enable Safe Attachments policy with Block action in Microsoft Defender portal' }
            @{ Id = 'SafeLinks';           Val = $defData.SafeLinksEnabled;            Cur = 'Not enabled'; Rem = 'Enable Safe Links policy in Microsoft Defender portal' }
            @{ Id = 'AntiPhish';           Val = $defData.AntiPhishEnabled;            Cur = 'Not enabled'; Rem = 'Enable anti-phishing policy in Microsoft Defender portal' }
            @{ Id = 'MailboxIntelligence'; Val = $defData.MailboxIntelligenceEnabled;  Cur = 'Not enabled'; Rem = 'Enable mailbox intelligence in anti-phishing policy settings' }
            @{ Id = 'ZAPSpam';             Val = $defData.ZapSpamEnabled;              Cur = 'Not enabled'; Rem = 'Enable ZAP for spam in hosted content filter policy' }
            @{ Id = 'ZAPPhish';            Val = $defData.ZapPhishEnabled;             Cur = 'Not enabled'; Rem = 'Enable ZAP for phishing in hosted content filter policy' }
            @{ Id = 'ATPSPOTeams';         Val = $defData.ATPForSPOTeamsODB;           Cur = 'Not enabled'; Rem = 'Enable ATP for SharePoint, Teams, and OneDrive in Microsoft Defender portal' }
        )
        foreach ($check in $defChecks) {
            if ($check.Val) {
                Add-Finding -ControlId $check.Id -State 'Satisfied' `
                    -Detail "$($dict[$check.Id].Title) is enabled." `
                    -CurrentState 'Enabled' -Recommended 'Enabled'
            } else {
                Add-Finding -ControlId $check.Id -State 'Gap' `
                    -Detail "$($dict[$check.Id].Title) is not enabled." `
                    -CurrentState $check.Cur -Recommended 'Enabled' `
                    -Remediation $check.Rem
            }
        }
    }

    # ── DKIM -- v2: granular domain lists ────────────────────
    $dkimData = $Results['ExchangePolicies']['DKIM']
    if ($dkimData) {
        $dkimDisabled = @($dkimData.Domains | Where-Object { -not $_.Enabled })
        if ($dkimDisabled.Count -eq 0) {
            Add-Finding -ControlId 'DKIM' -State 'Satisfied' `
                -Detail "DKIM signing enabled on all $($dkimData.Domains.Count) domain(s)." `
                -CurrentState 'Enabled on all domains' -Recommended 'Enabled on all domains'
        } elseif ($dkimDisabled.Count -lt $dkimData.Domains.Count) {
            Add-Finding -ControlId 'DKIM' -State 'Partial' `
                -Detail "$($dkimDisabled.Count) domain(s) have DKIM signing disabled." `
                -CurrentState "Disabled on $($dkimDisabled.Count) domain(s)" `
                -Recommended 'Enabled on all domains' `
                -AffectedObjects @($dkimDisabled | ForEach-Object { $_.Domain }) `
                -Remediation 'Run Enable-DkimSigningConfig -Identity <domain> for each affected domain'
        } else {
            Add-Finding -ControlId 'DKIM' -State 'Gap' `
                -Detail 'DKIM signing disabled on all domains.' `
                -CurrentState 'Disabled on all domains' -Recommended 'Enabled on all domains' `
                -Remediation 'Run Enable-DkimSigningConfig -Identity <domain> for each accepted domain'
        }
    }

    # ── DNSSEC -- v2: granular domain lists ──────────────────
    $dnssecData = $Results['ExchangePolicies']['DNSSEC']
    if ($dnssecData) {
        $dnssecDisabled = @($dnssecData.Domains | Where-Object { -not $_.Enabled })
        if ($dnssecDisabled.Count -eq 0) {
            Add-Finding -ControlId 'DNSSEC' -State 'Satisfied' `
                -Detail "DNSSEC enabled on all $($dnssecData.Domains.Count) domain(s)." `
                -CurrentState 'Enabled on all domains' -Recommended 'Enabled on all domains'
        } elseif ($dnssecDisabled.Count -lt $dnssecData.Domains.Count) {
            Add-Finding -ControlId 'DNSSEC' -State 'Partial' `
                -Detail "$($dnssecDisabled.Count) domain(s) without DNSSEC." `
                -CurrentState "Disabled on $($dnssecDisabled.Count) domain(s)" `
                -Recommended 'Enabled on all domains' `
                -AffectedObjects @($dnssecDisabled | ForEach-Object { $_.Domain }) `
                -Remediation 'Run Enable-DnssecForVerifiedDomain -DomainName <domain> then update MX to p-v1.mx.microsoft endpoint'
        } else {
            Add-Finding -ControlId 'DNSSEC' -State 'Gap' `
                -Detail 'DNSSEC not enabled on any domains.' `
                -CurrentState 'Disabled on all domains' -Recommended 'Enabled on all domains' `
                -Remediation 'Run Enable-DnssecForVerifiedDomain -DomainName <domain> for each accepted domain'
        }
    }

    # ── Conditional Access ───────────────────────────────────
    $caData = $Results['ConditionalAccess']['ConditionalAccess']
    if ($caData) {
        if ($caData.MfaEnforcingCount -gt 0 -and $caData.ReportOnlyCount -eq 0) {
            Add-Finding -ControlId 'AdminMFA' -State 'Satisfied' `
                -Detail "$($caData.MfaEnforcingCount) Conditional Access policy/policies enforcing MFA as a grant control." `
                -CurrentState 'MFA enforced via CA policy' -Recommended 'MFA enforced via CA policy'
            Add-Finding -ControlId 'CAPolicy' -State 'Satisfied' `
                -Detail "$($caData.EnabledCount) CA policy/policies in enforcement mode. $($caData.MfaEnforcingCount) enforce MFA." `
                -CurrentState "$($caData.EnabledCount) policies enabled" -Recommended 'Policies in enabled enforcement mode'
        } elseif ($caData.ReportOnlyCount -gt 0 -and $caData.MfaEnforcingCount -gt 0) {
            Add-Finding -ControlId 'CAPolicy' -State 'Partial' `
                -Detail "$($caData.ReportOnlyCount) CA policy/policies in report-only mode. Not enforcing access control decisions." `
                -CurrentState "$($caData.ReportOnlyCount) policies report-only" `
                -Recommended 'All policies in enabled enforcement mode' `
                -Remediation 'Review report-only policies and enable those that are production-ready'
        } else {
            Add-Finding -ControlId 'AdminMFA' -State 'Gap' `
                -Detail 'No enabled Conditional Access policy enforces MFA as a grant control.' `
                -CurrentState 'No MFA enforcement via CA' -Recommended 'CA policy enforcing MFA for all users' `
                -Remediation 'Create or enable a CA policy requiring MFA for all users and all cloud apps'
            Add-Finding -ControlId 'CAPolicy' -State 'Gap' `
                -Detail 'No Conditional Access policies in enabled enforcement mode.' `
                -CurrentState 'No enabled CA policies' -Recommended 'Policies in enabled enforcement mode' `
                -Remediation 'Review and enable CA policies. At minimum enforce MFA and block legacy authentication.'
        }
        if ($caData.LegacyAuthBlocking -gt 0) {
            Add-Finding -ControlId 'LegacyAuth' -State 'Satisfied' `
                -Detail "$($caData.LegacyAuthBlocking) CA policy/policies actively blocking legacy authentication clients." `
                -CurrentState 'Legacy auth blocked via CA' -Recommended 'Legacy auth blocked via CA'
        }
    }

    # ── Summary ──────────────────────────────────────────────
    $satisfied = ($findings | Where-Object { $_.State -eq 'Satisfied' }).Count
    $partial   = ($findings | Where-Object { $_.State -eq 'Partial' }).Count
    $gap       = ($findings | Where-Object { $_.State -eq 'Gap' }).Count

    return [ordered]@{
        Findings  = $findings
        Summary   = [ordered]@{
            Satisfied = $satisfied
            Partial   = $partial
            Gap       = $gap
            Total     = $findings.Count
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

Export-ModuleMember -Function Invoke-NLSScoringModel
