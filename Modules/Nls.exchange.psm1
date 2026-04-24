#
# NLS.Exchange.psm1
# NextLayerSec Assessment Framework -- Exchange Online Collector
# v2.0.0 -- Granular object lists added to all count-based findings
#
# Author:  NextLayerSec
# Version: 2.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Get-NLSExchangePolicies {
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    # ── Authentication Policies ──────────────────────────────
    try {
        $authPolicies = Get-AuthenticationPolicy -ErrorAction Stop
        $orgConfig    = Get-OrganizationConfig -ErrorAction Stop
        $policyResults = foreach ($policy in $authPolicies) {
            $basicAuthProps = $policy | Select-Object -Property AllowBasicAuth* |
                Select-Object -ExpandProperty PSObject | Select-Object -ExpandProperty Properties
            $failures = $basicAuthProps | Where-Object { $_.Value -eq $true }
            [ordered]@{
                PolicyName    = $policy.Name
                AllFailures   = if ($failures) { $failures.Name -join ', ' } else { $null }
                FullyHardened = ($null -eq $failures -or $failures.Count -eq 0)
            }
        }
        $results['AuthenticationPolicies'] = [ordered]@{
            Policies         = @($policyResults)
            OrgDefaultPolicy = $orgConfig.DefaultAuthenticationPolicy
            OrgDefaultSet    = ($null -ne $orgConfig.DefaultAuthenticationPolicy -and $orgConfig.DefaultAuthenticationPolicy -ne '')
        }
        Register-NLSCoverage -ControlFamily 'AuthenticationPolicies' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:AuthPolicy' -Message 'Failed to retrieve authentication policies' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'AuthenticationPolicies' -Status 'Partial' -Reason $_.Exception.Message
        $results['AuthenticationPolicies'] = $null
    }

    # ── SMTP Client Auth ─────────────────────────────────────
    try {
        $transportConfig = Get-TransportConfig -ErrorAction Stop
        $results['SmtpClientAuth'] = [ordered]@{ Disabled = $transportConfig.SmtpClientAuthenticationDisabled }
        Register-NLSCoverage -ControlFamily 'SmtpClientAuth' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:TransportConfig' -Message 'Failed to retrieve transport config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'SmtpClientAuth' -Status 'Partial' -Reason $_.Exception.Message
        $results['SmtpClientAuth'] = $null
    }

    # ── External Forwarding ──────────────────────────────────
    try {
        $remoteDomain        = Get-RemoteDomain Default -ErrorAction Stop
        $forwardingMailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null }
        $results['ExternalForwarding'] = [ordered]@{
            AutoForwardDisabled     = ($remoteDomain.AutoForwardEnabled -eq $false)
            MailboxesWithForwarding = $forwardingMailboxes.Count
            ForwardingMailboxList   = if ($forwardingMailboxes.Count -gt 0) {
                @($forwardingMailboxes | ForEach-Object {
                    $addr = if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
                    $fwd  = if ($Redact) { '[REDACTED]' } else { "$($_.ForwardingSmtpAddress)$($_.ForwardingAddress)" }
                    "$addr -> $fwd"
                })
            } else { @() }
        }
        Register-NLSCoverage -ControlFamily 'ExternalForwarding' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:Forwarding' -Message 'Failed to retrieve forwarding config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ExternalForwarding' -Status 'Partial' -Reason $_.Exception.Message
        $results['ExternalForwarding'] = $null
    }

    # ── Mailbox Protocol Hardening -- v2: granular lists ─────
    try {
        $casMailboxes    = Get-CasMailbox -ResultSize Unlimited -ErrorAction Stop
        $popEnabled      = @($casMailboxes | Where-Object { $_.PopEnabled })
        $imapEnabled     = @($casMailboxes | Where-Object { $_.ImapEnabled })

        $results['MailboxProtocols'] = [ordered]@{
            TotalMailboxes   = $casMailboxes.Count
            PopEnabledCount  = $popEnabled.Count
            ImapEnabledCount = $imapEnabled.Count
            PopEnabledList   = if ($popEnabled.Count -gt 0) {
                @($popEnabled | ForEach-Object { if ($Redact) { '[REDACTED_UPN]' } else { $_.PrimarySmtpAddress } })
            } else { @() }
            ImapEnabledList  = if ($imapEnabled.Count -gt 0) {
                @($imapEnabled | ForEach-Object { if ($Redact) { '[REDACTED_UPN]' } else { $_.PrimarySmtpAddress } })
            } else { @() }
        }
        Register-NLSCoverage -ControlFamily 'MailboxProtocols' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:CasMailbox' -Message 'Failed to retrieve CAS mailbox config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'MailboxProtocols' -Status 'Partial' -Reason $_.Exception.Message
        $results['MailboxProtocols'] = $null
    }

    # ── Mailbox Auditing -- v2: granular lists ───────────────
    try {
        $adminAuditConfig  = Get-AdminAuditLogConfig -ErrorAction Stop
        $mailboxes         = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        $auditDisabledList = @($mailboxes | Where-Object { $_.AuditEnabled -eq $false })
        $shortRetentionList = @($mailboxes | Where-Object { $_.AuditLogAgeLimit -lt [TimeSpan]::FromDays(90) })

        $results['MailboxAuditing'] = [ordered]@{
            UnifiedAuditLogEnabled  = $adminAuditConfig.UnifiedAuditLogIngestionEnabled
            MailboxesAuditDisabled  = $auditDisabledList.Count
            MailboxesShortRetention = $shortRetentionList.Count
            AuditDisabledList       = if ($auditDisabledList.Count -gt 0) {
                @($auditDisabledList | ForEach-Object { if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName } })
            } else { @() }
            ShortRetentionList      = if ($shortRetentionList.Count -gt 0) {
                @($shortRetentionList | ForEach-Object { if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName } })
            } else { @() }
        }
        Register-NLSCoverage -ControlFamily 'MailboxAuditing' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:Auditing' -Message 'Failed to retrieve audit config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'MailboxAuditing' -Status 'Partial' -Reason $_.Exception.Message
        $results['MailboxAuditing'] = $null
    }

    # ── Outbound Spam ────────────────────────────────────────
    try {
        $spamPolicy = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Where-Object { $_.IsDefault -eq $true }
        if (-not $spamPolicy) { $spamPolicy = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop | Select-Object -First 1 }
        $results['OutboundSpam'] = [ordered]@{
            NotifyEnabled    = $spamPolicy.NotifyOutboundSpam
            NotifyRecipients = if ($Redact) {
                if ($spamPolicy.NotifyOutboundSpamRecipients) { '[REDACTED]' } else { $null }
            } else { $spamPolicy.NotifyOutboundSpamRecipients -join ', ' }
        }
        Register-NLSCoverage -ControlFamily 'OutboundSpam' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:OutboundSpam' -Message 'Failed to retrieve outbound spam policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'OutboundSpam' -Status 'Partial' -Reason $_.Exception.Message
        $results['OutboundSpam'] = $null
    }

    # ── Defender for Office 365 ──────────────────────────────
    try {
        $safeAttach  = Get-SafeAttachmentPolicy -ErrorAction Stop
        $safeLinks   = Get-SafeLinksPolicy -ErrorAction Stop
        $antiPhish   = Get-AntiPhishPolicy -ErrorAction Stop
        $contentFilt = Get-HostedContentFilterPolicy -ErrorAction Stop
        $atpPolicy   = Get-AtpPolicyForO365 -ErrorAction Stop
        $results['DefenderO365'] = [ordered]@{
            SafeAttachmentBlockEnabled = ($safeAttach | Where-Object { $_.Action -eq 'Block' -and $_.Enable -eq $true }).Count -gt 0
            SafeLinksEnabled           = ($safeLinks | Where-Object { $_.IsEnabled -eq $true -or $_.Enabled -eq $true }).Count -gt 0
            AntiPhishEnabled           = ($antiPhish | Where-Object { $_.Enabled -eq $true }).Count -gt 0
            MailboxIntelligenceEnabled = ($antiPhish | Where-Object { $_.EnableMailboxIntelligence -eq $true }).Count -gt 0
            ZapSpamEnabled             = ($contentFilt | Where-Object { $_.SpamZapEnabled -eq $true }).Count -gt 0
            ZapPhishEnabled            = ($contentFilt | Where-Object { $_.PhishZapEnabled -eq $true }).Count -gt 0
            ATPForSPOTeamsODB          = $atpPolicy.EnableATPForSPOTeamsODB
        }
        Register-NLSCoverage -ControlFamily 'DefenderO365' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:Defender' -Message 'Failed to retrieve Defender for O365 policies' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DefenderO365' -Status 'Partial' -Reason $_.Exception.Message
        $results['DefenderO365'] = $null
    }

    # ── DKIM -- v2: granular domain lists ────────────────────
    try {
        $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop
        $results['DKIM'] = [ordered]@{
            Domains = @($dkimConfigs | ForEach-Object {
                [ordered]@{ Domain = $_.Domain; Enabled = $_.Enabled; Status = $_.Status }
            })
            DisabledDomains = @($dkimConfigs | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Domain })
        }
        Register-NLSCoverage -ControlFamily 'DKIM' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:DKIM' -Message 'Failed to retrieve DKIM config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DKIM' -Status 'Partial' -Reason $_.Exception.Message
        $results['DKIM'] = $null
    }

    # ── DNSSEC -- v2: granular domain lists ──────────────────
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $dnssecResults = foreach ($domain in $acceptedDomains) {
            try {
                $dnssec = Get-DnssecStatusForVerifiedDomain -DomainName $domain.DomainName -ErrorAction Stop
                [ordered]@{ Domain = $domain.DomainName; Enabled = ($dnssec.DnssecFeatureStatus -eq 'Enabled'); Status = $dnssec.DnssecFeatureStatus }
            } catch {
                Register-NLSException -Source 'Get-NLSExchangePolicies:DNSSEC' -Message "DNSSEC check failed for $($domain.DomainName)" -ErrorDetails $_.Exception.Message
                [ordered]@{ Domain = $domain.DomainName; Enabled = $false; Status = 'CheckFailed' }
            }
        }
        $results['DNSSEC'] = [ordered]@{
            Domains        = @($dnssecResults)
            DisabledDomains = @($dnssecResults | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Domain })
        }
        Register-NLSCoverage -ControlFamily 'DNSSEC' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:DNSSEC' -Message 'Failed to retrieve accepted domains for DNSSEC check' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DNSSEC' -Status 'Partial' -Reason $_.Exception.Message
        $results['DNSSEC'] = $null
    }

    return $results
}

Export-ModuleMember -Function Get-NLSExchangePolicies

function Get-NLSDMARCStatus {
    <#
    .SYNOPSIS
        Checks DMARC policy state for all accepted domains via DNS lookup.
        Completes the email authentication picture alongside DKIM and DNSSEC.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $dmarcResults    = foreach ($domain in $acceptedDomains) {
            try {
                $dnsResult = Resolve-DnsName -Name "_dmarc.$($domain.DomainName)" -Type TXT -ErrorAction Stop
                $dmarcRecord = $dnsResult | Where-Object { $_.Strings -match 'v=DMARC1' } |
                    Select-Object -ExpandProperty Strings -First 1

                if ($dmarcRecord) {
                    $policy = if ($dmarcRecord -match 'p=([a-z]+)') { $Matches[1] } else { 'unknown' }
                    $pct    = if ($dmarcRecord -match 'pct=([0-9]+)') { [int]$Matches[1] } else { 100 }
                    [ordered]@{
                        Domain   = $domain.DomainName
                        HasDMARC = $true
                        Policy   = $policy
                        Pct      = $pct
                        Enforced = ($policy -eq 'reject')
                        Partial  = ($policy -eq 'quarantine')
                        Record   = $dmarcRecord
                    }
                } else {
                    [ordered]@{
                        Domain   = $domain.DomainName
                        HasDMARC = $false
                        Policy   = 'none'
                        Pct      = 0
                        Enforced = $false
                        Partial  = $false
                        Record   = $null
                    }
                }
            } catch {
                [ordered]@{
                    Domain   = $domain.DomainName
                    HasDMARC = $false
                    Policy   = 'missing'
                    Pct      = 0
                    Enforced = $false
                    Partial  = $false
                    Record   = $null
                }
            }
        }

        $results['DMARC'] = [ordered]@{
            Domains          = @($dmarcResults)
            EnforcedCount    = ($dmarcResults | Where-Object { $_.Enforced }).Count
            QuarantineCount  = ($dmarcResults | Where-Object { $_.Partial }).Count
            MissingCount     = ($dmarcResults | Where-Object { -not $_.HasDMARC }).Count
            NoneCount        = ($dmarcResults | Where-Object { $_.Policy -eq 'none' }).Count
        }

        Register-NLSCoverage -ControlFamily 'DMARC' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSDMARCStatus' -Message 'Failed to check DMARC status' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DMARC' -Status 'Partial' -Reason $_.Exception.Message
        $results['DMARC'] = $null
    }

    return $results
}

function Get-NLSSharedMailboxHardening {
    <#
    .SYNOPSIS
        Checks shared mailboxes for interactive sign-in enabled and unnecessary licenses.
        Shared mailboxes with interactive sign-in are an unmonitored access vector.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    try {
        $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop
        $casShared       = Get-CasMailbox -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $sharedMailboxes.PrimarySmtpAddress -contains $_.PrimarySmtpAddress }

        $signInEnabled = @($sharedMailboxes | Where-Object { $_.AccountDisabled -eq $false })
        $popEnabled    = @($casShared | Where-Object { $_.PopEnabled })
        $imapEnabled   = @($casShared | Where-Object { $_.ImapEnabled })

        $results['SharedMailboxHardening'] = [ordered]@{
            TotalSharedMailboxes    = $sharedMailboxes.Count
            SignInEnabledCount      = $signInEnabled.Count
            PopEnabledCount         = $popEnabled.Count
            ImapEnabledCount        = $imapEnabled.Count
            SignInEnabledList       = if ($signInEnabled.Count -gt 0) {
                @($signInEnabled | ForEach-Object { if ($Redact) { '[REDACTED]' } else { $_.PrimarySmtpAddress } })
            } else { @() }
        }

        Register-NLSCoverage -ControlFamily 'SharedMailboxHardening' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSSharedMailboxHardening' -Message 'Failed to retrieve shared mailbox config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'SharedMailboxHardening' -Status 'Partial' -Reason $_.Exception.Message
        $results['SharedMailboxHardening'] = $null
    }

    return $results
}

Export-ModuleMember -Function Get-NLSExchangePolicies, Get-NLSDMARCStatus, Get-NLSSharedMailboxHardening
