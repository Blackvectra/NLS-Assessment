#
# NLS.Remediation.psm1
# NextLayerSec Assessment Framework -- Remediation Script Generator
#
# Author:  NextLayerSec
# Version: 2.1.1
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Publish-NLSRemediationScript {
    param(
        [Parameter(Mandatory = $true)][hashtable]$ScoredResults,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$TenantName,
        [bool]$Redact = $false
    )

    $findings = @($ScoredResults.Findings | Where-Object { $_.State -in @('Gap', 'Partial') })
    $lines    = [System.Collections.Generic.List[string]]::new()

    # ── Header ───────────────────────────────────────────────
    $lines.Add('#')
    $lines.Add("# NextLayerSec M365 Remediation Script")
    $lines.Add("# Tenant:    $TenantName")
    $lines.Add("# Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
    $lines.Add("# Findings:  $($findings.Count) Gap/Partial controls")
    $lines.Add('#')
    $lines.Add('# REVIEW BEFORE RUNNING. This script makes configuration changes.')
    $lines.Add('# Each section can be run independently.')
    $lines.Add('#')
    $lines.Add('')
    $lines.Add('#Requires -Version 7.0')
    $lines.Add('#Requires -Modules ExchangeOnlineManagement')
    $lines.Add('')
    $lines.Add('[CmdletBinding(SupportsShouldProcess)]')
    $lines.Add('param(')
    $lines.Add('    [Parameter(Mandatory = $true)]')
    $lines.Add('    [string]$UserPrincipalName,')
    $lines.Add('    [switch]$WhatIf,')
    $lines.Add('    [switch]$Force')
    $lines.Add(')')
    $lines.Add('')
    $lines.Add('Set-StrictMode -Version Latest')
    $lines.Add('$ErrorActionPreference = "Continue"')
    $lines.Add('')
    $lines.Add('# ── Connect ──────────────────────────────────────────────')
    $lines.Add('Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan')
    $lines.Add('Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false')
    $lines.Add('Write-Host "[+] Connected" -ForegroundColor Green')
    $lines.Add('')

    # ── Per finding remediation blocks ───────────────────────
    foreach ($finding in $findings) {
        $nist  = if ($finding.NIST_SP800_53_r5) { "# NIST: $($finding.NIST_SP800_53_r5)" } else { '' }
        $hipaa = if ($finding.HIPAA_Current)    { "# HIPAA: $($finding.HIPAA_Current)" }    else { '' }

        switch ($finding.ControlId) {

            'SmtpClientAuth' {
                $lines.Add('# ── SMTP Client Authentication ───────────────────────────')
                $lines.Add('# Disables legacy SMTP AUTH tenant-wide.')
                if ($nist)  { $lines.Add($nist) }
                if ($hipaa) { $lines.Add($hipaa) }
                $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("Tenant", "Disable SMTP Client Authentication")) {')
                $lines.Add('    Set-TransportConfig -SmtpClientAuthenticationDisabled $true')
                $lines.Add('    Write-Host "[+] SMTP client authentication disabled" -ForegroundColor Green')
                $lines.Add('}')
                $lines.Add('')
            }

            'ExternalForwarding' {
                $lines.Add('# ── External Auto-Forwarding ─────────────────────────────')
                $lines.Add('# Disables external auto-forwarding at the remote domain level.')
                if ($nist)  { $lines.Add($nist) }
                if ($hipaa) { $lines.Add($hipaa) }
                $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("Default Remote Domain", "Disable Auto-Forwarding")) {')
                $lines.Add('    Set-RemoteDomain Default -AutoForwardEnabled $false')
                $lines.Add('    Write-Host "[+] External auto-forwarding disabled" -ForegroundColor Green')
                $lines.Add('}')
                $lines.Add('')
            }

            'PopEnabled' {
                $lines.Add('# ── POP3 Protocol ────────────────────────────────────────')
                $lines.Add('# Disables POP3 on all mailboxes.')
                if ($nist)  { $lines.Add($nist) }
                if ($hipaa) { $lines.Add($hipaa) }
                $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("All Mailboxes", "Disable POP3")) {')
                $lines.Add('    Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false')
                $lines.Add('    Write-Host "[+] POP3 disabled on all mailboxes" -ForegroundColor Green')
                $lines.Add('}')
                $lines.Add('')
            }

            'ImapEnabled' {
                $lines.Add('# ── IMAP Protocol ────────────────────────────────────────')
                $lines.Add('# Disables IMAP on all mailboxes.')
                if ($nist)  { $lines.Add($nist) }
                if ($hipaa) { $lines.Add($hipaa) }
                $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("All Mailboxes", "Disable IMAP")) {')
                $lines.Add('    Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -ImapEnabled $false')
                $lines.Add('    Write-Host "[+] IMAP disabled on all mailboxes" -ForegroundColor Green')
                $lines.Add('}')
                $lines.Add('')
            }

            'MailboxAudit' {
                $lines.Add('# ── Mailbox Auditing ─────────────────────────────────────')
                if ($nist)  { $lines.Add($nist) }
                if ($hipaa) { $lines.Add($hipaa) }
                if ($finding.AffectedObjects -and $finding.AffectedObjects.Count -gt 0) {
                    $affectedList = $finding.AffectedObjects -join ', '
                    $lines.Add("# Affected mailboxes: $affectedList")
                    $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("Affected Mailboxes", "Enable Auditing")) {')
                    foreach ($mbx in $finding.AffectedObjects) {
                        $lines.Add("    Set-Mailbox -Identity '$mbx' -AuditEnabled `$true")
                    }
                } else {
                    $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("All Mailboxes", "Enable Auditing")) {')
                    $lines.Add('    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true')
                }
                $lines.Add('    Write-Host "[+] Mailbox auditing enabled" -ForegroundColor Green')
                $lines.Add('}')
                $lines.Add('')
            }

            'OutboundSpam' {
                $lines.Add('# ── Outbound Spam Notification ───────────────────────────')
                $lines.Add('# Update the recipient address below before running.')
                if ($nist) { $lines.Add($nist) }
                $lines.Add('$notifyRecipient = "admin@yourdomain.com"  # UPDATE THIS')
                $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("Outbound Spam Policy", "Enable Notification")) {')
                $lines.Add('    Set-HostedOutboundSpamFilterPolicy -Identity Default -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $notifyRecipient')
                $lines.Add('    Write-Host "[+] Outbound spam notification enabled" -ForegroundColor Green')
                $lines.Add('}')
                $lines.Add('')
            }

            'DKIM' {
                $lines.Add('# ── DKIM Signing ─────────────────────────────────────────')
                $lines.Add('# DNS CNAME records must exist before enabling.')
                if ($nist) { $lines.Add($nist) }
                if ($finding.AffectedObjects -and $finding.AffectedObjects.Count -gt 0) {
                    $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("Affected Domains", "Enable DKIM")) {')
                    foreach ($domain in $finding.AffectedObjects) {
                        $lines.Add("    Enable-DkimSigningConfig -Identity '$domain'")
                        $lines.Add("    Write-Host '[+] DKIM enabled for $domain' -ForegroundColor Green")
                    }
                    $lines.Add('}')
                } else {
                    $lines.Add('# Run Get-DkimSigningConfig to identify domains and enable:')
                    $lines.Add('# Enable-DkimSigningConfig -Identity <domain>')
                }
                $lines.Add('')
            }

            'DNSSEC' {
                $lines.Add('# ── DNSSEC ───────────────────────────────────────────────')
                $lines.Add('# After enabling, update MX record to p-v1.mx.microsoft endpoint.')
                if ($nist) { $lines.Add($nist) }
                if ($finding.AffectedObjects -and $finding.AffectedObjects.Count -gt 0) {
                    $lines.Add('if ($Force -or $PSCmdlet.ShouldProcess("Affected Domains", "Enable DNSSEC")) {')
                    foreach ($domain in $finding.AffectedObjects) {
                        $lines.Add("    Enable-DnssecForVerifiedDomain -DomainName '$domain'")
                        $lines.Add("    Write-Host '[+] DNSSEC enabled for $domain -- update MX record' -ForegroundColor Green")
                    }
                    $lines.Add('}')
                }
                $lines.Add('')
            }

            'SafeLinks' {
                $lines.Add('# ── Safe Links ───────────────────────────────────────────')
                $lines.Add('# Manual action required -- enable via Microsoft Defender portal.')
                $lines.Add('# https://security.microsoft.com > Email & collaboration > Policies & rules > Safe Links')
                if ($nist) { $lines.Add($nist) }
                $lines.Add('Write-Host "[!] Safe Links -- manual action required in Defender portal" -ForegroundColor Yellow')
                $lines.Add('Write-Host "    https://security.microsoft.com" -ForegroundColor DarkGray')
                $lines.Add('')
            }

            'AdminMFA' {
                $lines.Add('# ── MFA Enforcement ──────────────────────────────────────')
                $lines.Add('# Requires a Conditional Access policy in Entra ID.')
                $lines.Add('# https://entra.microsoft.com > Protection > Conditional Access')
                $lines.Add('# Create policy: All users > All cloud apps > Grant: Require MFA')
                if ($nist) { $lines.Add($nist) }
                $lines.Add('Write-Host "[!] MFA enforcement -- Conditional Access policy required" -ForegroundColor Yellow')
                $lines.Add('Write-Host "    https://entra.microsoft.com" -ForegroundColor DarkGray')
                $lines.Add('')
            }

            'CAPolicy' {
                $lines.Add('# ── Conditional Access Policies ──────────────────────────')
                $lines.Add('# Review and enable policies in Entra ID.')
                $lines.Add('# https://entra.microsoft.com > Protection > Conditional Access')
                $lines.Add('Write-Host "[!] Conditional Access -- review and enable policies in Entra ID" -ForegroundColor Yellow')
                $lines.Add('Write-Host "    https://entra.microsoft.com" -ForegroundColor DarkGray')
                $lines.Add('')
            }

            default {
                $lines.Add("# ── $($finding.Title) ─────────────────────────────────────")
                $lines.Add("# State: $($finding.State)")
                $lines.Add("# $($finding.Detail)")
                if ($finding.Remediation) {
                    $lines.Add("# Remediation: $($finding.Remediation)")
                }
                $lines.Add('# Manual action required.')
                $lines.Add('')
            }
        }
    }

    # ── Footer ───────────────────────────────────────────────
    $lines.Add('# ── Disconnect ───────────────────────────────────────────')
    $lines.Add('Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue')
    $lines.Add('Write-Host ""')
    $lines.Add('Write-Host "Remediation complete. Re-run assessment to verify." -ForegroundColor Cyan')
    $lines.Add('Write-Host "NextLayerSec -- nextlayersec.io"')

    $lines | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Host "  [+] Remediation script written to: $OutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function Publish-NLSRemediationScript
