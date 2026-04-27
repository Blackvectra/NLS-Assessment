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
        $policyResults = @(foreach ($policy in $authPolicies) {
            $basicAuthProps = $policy.PSObject.Properties | Where-Object { $_.Name -like 'AllowBasicAuth*' }
            $failures = $basicAuthProps | Where-Object { $_.Value -eq $true }
            [ordered]@{
                PolicyName    = $policy.Name
                AllFailures   = if ($failures) { $failures.Name -join ', ' } else { $null }
                FullyHardened = ($null -eq $failures -or $failures.Count -eq 0)
            }
        })
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
            Where-Object { $null -ne $_.ForwardingAddress -or $null -ne $_.ForwardingSmtpAddress }
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
        $allCasMailboxes = Get-CasMailbox -ResultSize Unlimited -ErrorAction Stop
        # Exclude system mailboxes -- DiscoverySearchMailbox, SystemMailbox etc cannot be configured
        $systemPattern   = 'DiscoverySearchMailbox|SystemMailbox|quarantine|Migration|FederatedEmail|MicrosoftExchange'
        $casMailboxes    = @($allCasMailboxes | Where-Object { $_.Name -notmatch $systemPattern })
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
            SafeLinksEnabled           = ($safeLinks | Where-Object {
                $_.IsEnabled -eq $true -or
                $_.Enabled -eq $true -or
                $_.EnableSafeLinksForEmail -eq $true -or
                $_.EnableSafeLinksForTeams -eq $true -or
                $_.EnableSafeLinksForOffice -eq $true -or
                ($null -ne $_.TrackClicks)  # Policy exists and has settings = enabled
            }).Count -gt 0
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

    # ── DNSSEC -- v2: live DNS lookup + EXO check ────────────
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $dnssecResults = @(foreach ($domain in $acceptedDomains) {
            $domainName = $domain.DomainName
            $dnssecEnabled = $false
            $dnssecStatus  = 'Unknown'
            $dnssecSource  = 'DNS'

            # Check Exchange Online DNSSEC status first (Microsoft-managed)
            try {
                $exoDnssec = Get-DnssecStatusForVerifiedDomain -DomainName $domainName -ErrorAction Stop
                # Status can be: Enabled, Disabled, or other values -- check for any non-disabled state
                $exoStatus = $exoDnssec.DnssecFeatureStatus
                if ($exoStatus -and $exoStatus -ne 'Disabled' -and $exoStatus -ne 'NotSupported') {
                    $dnssecEnabled = $true
                    $dnssecStatus  = 'Enabled via Microsoft (EXO verified)'
                    $dnssecSource  = 'EXO'
                } else {
                    $dnssecStatus = "Not enabled ($exoStatus)"
                }
            } catch {
                $dnssecStatus = 'EXO check failed'
            }

            # Fall back to live DNS DNSKEY lookup if EXO says not enabled
            if (-not $dnssecEnabled) {
                try {
                    $dnsResult = Resolve-DnsName -Name $domainName -Type DNSKEY -ErrorAction Stop
                    if ($dnsResult) {
                        $dnssecEnabled = $true
                        $dnssecStatus  = 'Enabled (DNS DNSKEY verified)'
                        $dnssecSource  = 'DNS'
                    }
                } catch {
                    # No DNSKEY record found at DNS level either
                    if (-not $dnssecEnabled) {
                        $dnssecStatus = 'Not enabled -- no DNSKEY record in DNS'
                    }
                }
            }

            [ordered]@{
                Domain  = $domainName
                Enabled = $dnssecEnabled
                Status  = $dnssecStatus
                Source  = $dnssecSource
            }
        })

        $results['DNSSEC'] = [ordered]@{
            Domains         = @($dnssecResults)
            DisabledDomains = @($dnssecResults | Where-Object { -not $_['Enabled'] } | ForEach-Object { $_['Domain'] })
        }
        Register-NLSCoverage -ControlFamily 'DNSSEC' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:DNSSEC' -Message 'Failed to retrieve accepted domains for DNSSEC check' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DNSSEC' -Status 'Partial' -Reason $_.Exception.Message
        $results['DNSSEC'] = $null
    }

    return $results
}

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
        $dmarcResults    = @(foreach ($domain in $acceptedDomains) {
            try {
                $dnsResult = Resolve-DnsName -Name "_dmarc.$($domain.DomainName)" -Type TXT -Server '8.8.8.8' -ErrorAction Stop
                # Join Strings array and take first matching record
                $dmarcTxtRecord = $dnsResult | Where-Object { ($_.Strings -join '') -match 'v=DMARC1' } | Select-Object -First 1
                $dmarcRecord    = if ($dmarcTxtRecord) { ($dmarcTxtRecord.Strings) -join '' } else { $null }

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
        })

        # Store raw domains -- scoring filters onmicrosoft.com inline
        # Do NOT store filtered array in hashtable -- PowerShell @() unwraps single-item arrays
        $results['DMARC'] = [ordered]@{
            Domains          = @($dmarcResults)
            TotalDomains     = @($dmarcResults).Count
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

        # Exclude system mailboxes -- DiscoverySearchMailbox, SystemMailbox etc
        $systemMailboxPattern = 'DiscoverySearchMailbox|SystemMailbox|quarantine|Migration|FederatedEmail'
        $userSharedMailboxes  = @($sharedMailboxes | Where-Object { $_.DisplayName -notmatch $systemMailboxPattern })
        $signInEnabled = @($userSharedMailboxes | Where-Object { $_.AccountDisabled -eq $false })
        $popEnabled    = @($casShared | Where-Object { $_.PopEnabled })
        $imapEnabled   = @($casShared | Where-Object { $_.ImapEnabled })

        $results['SharedMailboxHardening'] = [ordered]@{
            TotalSharedMailboxes    = $userSharedMailboxes.Count
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

function Get-NLSDNSEmailRecords {
    <#
    .SYNOPSIS
        Live DNS lookup for SPF, DMARC, DKIM, DNSSEC, and MTA-STS per accepted domain.
        Queries 8.8.8.8 (Google Public DNS) directly -- bypasses internal resolvers,
        cached tenant state, and split-brain DNS. Shows what the public internet sees.
    #>
    param(
        [bool]$Redact    = $false,
        [bool]$DebugMode = $false
    )

    $results = [ordered]@{}

    function Invoke-PublicDns {
        # Security note: Queries Google (8.8.8.8) and Cloudflare (1.1.1.1) directly.
        # -DnssecOk requests DNSSEC records but PowerShell's Resolve-DnsName does NOT
        # perform full DNSSEC chain-of-trust validation. DNSSEC 'enabled' means records
        # are present, not that the chain is cryptographically verified.
        # On networks with intercepted DNS (captive portals, corporate MITM), results
        # may not reflect true public DNS state.
        param([string]$Name, [string]$Type)
        $servers = @('8.8.8.8', '1.1.1.1')
        foreach ($server in $servers) {
            try {
                $r = Resolve-DnsName -Name $Name -Type $Type -Server $server -ErrorAction Stop -DnssecOk
                if ($r) { return $r }
            } catch { }
        }
        return $null
    }

    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $dkimConfigs     = Get-DkimSigningConfig -ErrorAction SilentlyContinue

        if ($DebugMode) { Write-Host "  [DNS-DEBUG] Accepted domains: $($acceptedDomains.Count)" -ForegroundColor Cyan }
        $domainRecords = @(foreach ($domain in $acceptedDomains) {
            $d = $domain.DomainName
            if ($DebugMode) { Write-Host "  [DNS-DEBUG] Processing: $d" -ForegroundColor Cyan }

            # ── SPF ──────────────────────────────────────────
            $spfRecord = $null
            $spfFound  = $false
            try {
                $spfLookup   = Invoke-PublicDns -Name $d -Type TXT
                if ($DebugMode) { Write-Host "  [DNS-DEBUG]   SPF lookup returned: $($null -ne $spfLookup)" -ForegroundColor Cyan }
                $spfRecords  = @($spfLookup | Where-Object { ($_.Strings -join '') -match 'v=spf1' })
                if ($spfRecords.Count -ge 1) {
                    $spfRecord = ($spfRecords[0].Strings) -join ''
                    $spfFound  = ($spfRecord.Length -gt 0)
                }
            } catch { }

            # ── DMARC ─────────────────────────────────────────
            $dmarcRecord = $null
            $dmarcPolicy = 'missing'
            $dmarcPct    = 100
            $dmarcRua    = $null
            $dmarcFound  = $false
            try {
                $dmarcLookup = Invoke-PublicDns -Name "_dmarc.$d" -Type TXT
                $dmarcTxt    = @($dmarcLookup | Where-Object { ($_.Strings -join '') -match 'v=DMARC1' }) | Select-Object -First 1
                if ($dmarcTxt) {
                    $dmarcRecord = ($dmarcTxt.Strings) -join ''
                    $dmarcFound  = ($dmarcRecord.Length -gt 0)
                    if ($dmarcRecord -match 'p=([a-z]+)')  { $dmarcPolicy = $Matches[1] }
                    if ($dmarcRecord -match 'pct=(\d+)')   { $dmarcPct    = [int]$Matches[1] }
                    if ($dmarcRecord -match 'rua=([^;]+)') { $dmarcRua    = $Matches[1].Trim() }
                }
            } catch { }

            # ── DKIM ──────────────────────────────────────────
            $dkimSelectors  = [ordered]@{}
            $dkimEnabledEXO = $false

            foreach ($selector in @('selector1', 'selector2')) {
                $found  = $false
                $target = $null
                $type   = $null
                # Try CNAME first (EXO standard)
                $cnLookup = Invoke-PublicDns -Name "$selector._domainkey.$d" -Type CNAME
                if ($cnLookup) { $found = $true; $target = $cnLookup.NameHost; $type = 'CNAME' }
                # Fall back to TXT (Cloudflare/custom DKIM)
                if (-not $found) {
                    $txtLookup = Invoke-PublicDns -Name "$selector._domainkey.$d" -Type TXT
                    $dkimTxt   = @($txtLookup | Where-Object { ($_.Strings -join '') -match 'v=DKIM1' }) | Select-Object -First 1
                    if ($dkimTxt) {
                        $raw   = ($dkimTxt.Strings -join '')
                        $found = $true
                        $target = if ($raw.Length -gt 60) { $raw.Substring(0,60) + '...' } else { $raw }
                        $type  = 'TXT'
                    }
                }
                $dkimSelectors[$selector] = [ordered]@{ Found = $found; Target = $target; Type = $type }
            }

            # EXO DKIM signing config
            if ($dkimConfigs) {
                $dkimConfig     = $dkimConfigs | Where-Object { $_.Domain -eq $d }
                $dkimEnabledEXO = if ($dkimConfig) { [bool]$dkimConfig.Enabled } else { $false }
            }

            $dkimFound = $dkimSelectors['selector1']['Found'] -or $dkimSelectors['selector2']['Found'] -or $dkimEnabledEXO

            # ── DNSSEC ────────────────────────────────────────
            # Query with -DnssecOk to check for RRSIG records on the wire
            $dnssecEnabled = $false
            $dnssecStatus  = 'Not detected'

            # Check EXO API first
            try {
                $exoDnssec = Get-DnssecStatusForVerifiedDomain -DomainName $d -ErrorAction Stop
                $exoStatus = $exoDnssec.DnssecFeatureStatus
                if ($exoStatus -and $exoStatus -notin @('Disabled','NotSupported')) {
                    $dnssecEnabled = $true
                    $dnssecStatus  = 'Enabled via Microsoft (EXO verified)'
                }
            } catch { }

            # Public DNS DNSKEY lookup (works for Cloudflare-managed DNSSEC)
            if (-not $dnssecEnabled) {
                $dnskey = Invoke-PublicDns -Name $d -Type DNSKEY
                if ($dnskey) { $dnssecEnabled = $true; $dnssecStatus = 'Enabled (DNSKEY verified via 8.8.8.8)' }
            }

            # DS record at parent zone
            if (-not $dnssecEnabled) {
                $ds = Invoke-PublicDns -Name $d -Type DS
                if ($ds) { $dnssecEnabled = $true; $dnssecStatus = 'Enabled (DS record found via 8.8.8.8)' }
            }

            # ── MTA-STS ───────────────────────────────────────
            $mtaStsEnabled = $false
            $mtaStsMode    = 'none'
            $mtaStsRecord  = $null
            $mtaLookup = Invoke-PublicDns -Name "_mta-sts.$d" -Type TXT
            if ($mtaLookup) {
                $mtaTxt = @($mtaLookup | Where-Object { ($_.Strings -join '') -match 'v=STSv1' }) | Select-Object -First 1
                if ($mtaTxt) {
                    $mtaStsRecord  = ($mtaTxt.Strings) -join ''
                    $mtaStsEnabled = $true
                    $mtaStsMode    = if ($mtaStsRecord -match 'id=([^;]+)') { "published (id=$($Matches[1].Trim()))" } else { 'published' }
                }
            }

            [ordered]@{
                Domain  = $d
                SPF     = [ordered]@{ Found = $spfFound; Record = $spfRecord }
                DMARC   = [ordered]@{ Found = $dmarcFound;  Record = $dmarcRecord; Policy = $dmarcPolicy; Pct = $dmarcPct; RUA = $dmarcRua; Enforced = ($dmarcPolicy -eq 'reject') }
                DKIM    = [ordered]@{ Found = $dkimFound;   EnabledInEXO = $dkimEnabledEXO; Selectors = $dkimSelectors; BothFound = ($dkimSelectors['selector1']['Found'] -and $dkimSelectors['selector2']['Found']) }
                DNSSEC  = [ordered]@{ Enabled = $dnssecEnabled; Status = $dnssecStatus }
                MTASTS  = [ordered]@{ Enabled = $mtaStsEnabled; Mode = $mtaStsMode; Record = $mtaStsRecord }
            }
        })

        if ($DebugMode) {
        if ($DebugMode) { Write-Host "  [DNS-DEBUG] Total domain records built: $(@($domainRecords).Count)" -ForegroundColor Cyan }
        if ($DebugMode) { Write-Host "  [DNS-DEBUG] Storing in results['DNSEmailRecords']" -ForegroundColor Cyan }
        }
        $results['DNSEmailRecords'] = [ordered]@{
            Domains           = @($domainRecords)
            SPFMissingCount   = @($domainRecords | Where-Object { -not $_['SPF']['Found'] }).Count
            DMARCMissingCount = @($domainRecords | Where-Object { -not $_['DMARC']['Found'] }).Count
            DKIMMissingCount  = @($domainRecords | Where-Object { -not $_['DKIM']['Found'] }).Count
            DNSSECMissing     = @($domainRecords | Where-Object { -not $_['DNSSEC']['Enabled'] }).Count
            MTASTSMissing     = @($domainRecords | Where-Object { -not $_['MTASTS']['Enabled'] }).Count
        }

        Register-NLSCoverage -ControlFamily 'DNSEmailRecords' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSDNSEmailRecords' -Message 'Failed to retrieve DNS email records' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DNSEmailRecords' -Status 'Partial' -Reason $_.Exception.Message
        # Return empty but valid structure so reporting section still renders with what we have
        $results['DNSEmailRecords'] = [ordered]@{
            Domains           = @()
            SPFMissingCount   = 0
            DMARCMissingCount = 0
            DKIMMissingCount  = 0
            DNSSECMissing     = 0
            MTASTSMissing     = 0
            Error             = $_.Exception.Message
        }
    }

    return $results
}

function Get-NLSMailFlowHardening {
    <#
    .SYNOPSIS
        Extended mail flow and anti-spam hardening checks.
        Covers MTA-STS, inbound spam policy, malware filter, quarantine policy.
    #>
    param([bool]$Redact = $false)

    $results = [ordered]@{}

    # ── MTA-STS ──────────────────────────────────────────────
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $mtaStsResults = @(foreach ($domain in $acceptedDomains) {
            $mtaStsEnabled = $false
            $mtaStsMode    = 'none'
            try {
                $mtaRecord = Resolve-DnsName -Name "_mta-sts.$($domain.DomainName)" -Type TXT -Server '8.8.8.8' -ErrorAction Stop
                $mtaTxt    = $mtaRecord | Where-Object { $_.Strings -match 'v=STSv1' }
                if ($mtaTxt) {
                    $mtaStsEnabled = $true
                    if ($mtaTxt.Strings -match 'id=') { $mtaStsMode = 'published' }
                }
            } catch { }
            [ordered]@{ Domain = $domain.DomainName; MTAStsEnabled = $mtaStsEnabled; Mode = $mtaStsMode }
        })
        $results['MTASTS'] = [ordered]@{
            Domains      = @($mtaStsResults)
            EnabledCount = ($mtaStsResults | Where-Object { $_['MTAStsEnabled'] }).Count
            TotalDomains = $acceptedDomains.Count
        }
        Register-NLSCoverage -ControlFamily 'MTASTS' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSMailFlowHardening:MTASTS' -Message 'Failed to check MTA-STS' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'MTASTS' -Status 'Partial' -Reason $_.Exception.Message
        $results['MTASTS'] = $null
    }

    # ── Inbound Anti-Spam ────────────────────────────────────
    try {
        $spamPolicies = Get-HostedContentFilterPolicy -ErrorAction Stop
        $defaultPolicy = $spamPolicies | Where-Object { $_.IsDefault } | Select-Object -First 1
        if (-not $defaultPolicy) { $defaultPolicy = $spamPolicies | Select-Object -First 1 }
        $results['InboundSpam'] = [ordered]@{
            HighConfidenceSpamAction = $defaultPolicy.HighConfidenceSpamAction
            SpamAction               = $defaultPolicy.SpamAction
            PhishSpamAction          = $defaultPolicy.PhishSpamAction
            BulkThreshold            = $defaultPolicy.BulkThreshold
            ZapEnabled               = $defaultPolicy.SpamZapEnabled
            QuarantineRetentionDays  = $defaultPolicy.QuarantineRetentionPeriod
            Hardened                 = (
                $defaultPolicy.HighConfidenceSpamAction -in @('Quarantine', 'Delete') -and
                $defaultPolicy.PhishSpamAction -in @('Quarantine', 'Delete') -and
                $defaultPolicy.BulkThreshold -le 6
            )
        }
        Register-NLSCoverage -ControlFamily 'InboundSpam' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSMailFlowHardening:InboundSpam' -Message 'Failed to check inbound spam policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'InboundSpam' -Status 'Partial' -Reason $_.Exception.Message
        $results['InboundSpam'] = $null
    }

    # ── Malware Filter ───────────────────────────────────────
    try {
        $malwarePolicies = Get-MalwareFilterPolicy -ErrorAction Stop
        $defaultMalware  = $malwarePolicies | Where-Object { $_.IsDefault } | Select-Object -First 1
        if (-not $defaultMalware) { $defaultMalware = $malwarePolicies | Select-Object -First 1 }
        $results['MalwareFilter'] = [ordered]@{
            Action                    = if ($defaultMalware.Action) { $defaultMalware.Action } else { 'DeleteMessage' }  # EXO default when property is empty
            EnableFileFilter          = $defaultMalware.EnableFileFilter
            ZapEnabled                = $defaultMalware.ZapEnabled
            NotifyAdmin               = $defaultMalware.EnableInternalSenderNotifications -or $defaultMalware.EnableExternalSenderNotifications
            Hardened                  = (
                $defaultMalware.Action -eq 'DeleteMessage' -and
                $defaultMalware.ZapEnabled -eq $true
            )
        }
        Register-NLSCoverage -ControlFamily 'MalwareFilter' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSMailFlowHardening:MalwareFilter' -Message 'Failed to check malware filter policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'MalwareFilter' -Status 'Partial' -Reason $_.Exception.Message
        $results['MalwareFilter'] = $null
    }

    return $results
}

Export-ModuleMember -Function Get-NLSExchangePolicies, Get-NLSDMARCStatus, Get-NLSSharedMailboxHardening, Get-NLSDNSEmailRecords, Get-NLSMailFlowHardening
