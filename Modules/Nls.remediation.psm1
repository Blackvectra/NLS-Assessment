#
# NLS.Remediation.psm1
# NextLayerSec Assessment Framework -- Remediation Script Generator
# Produces a tenant-scoped PowerShell remediation script from findings
#
# Author:  NextLayerSec
# Version: 2.1.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Publish-NLSRemediationScript {
    <#
    .SYNOPSIS
        Generates a PowerShell remediation script scoped to assessment findings.
    .DESCRIPTION
        Reads Gap and Partial findings from scored results and produces a
        ready-to-review PowerShell script with all remediation commands
        pre-populated for the specific tenant. Script includes safety checks,
        confirmation prompts, and inline comments tied to framework citations.
        Always generated alongside the assessment report.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$ScoredResults,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$TenantName,
        [bool]$Redact = $false
    )

    $findings = $ScoredResults.Findings | Where-Object { $_.State -in @('Gap', 'Partial') }
    $sb       = [System.Text.StringBuilder]::new()

    # ── Header ───────────────────────────────────────────────
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine("# NextLayerSec M365 Remediation Script")
    [void]$sb.AppendLine("# Tenant: $TenantName")
    [void]$sb.AppendLine("# Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# REVIEW BEFORE RUNNING. This script makes configuration changes.')
    [void]$sb.AppendLine('# Test in a non-production tenant first where possible.')
    [void]$sb.AppendLine('# Each section can be run independently.')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine("# Findings addressed: $($findings.Count) Gap/Partial controls")
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('#Requires -Version 7.0')
    [void]$sb.AppendLine('#Requires -Modules ExchangeOnlineManagement')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('[CmdletBinding(SupportsShouldProcess)]')
    [void]$sb.AppendLine('param(')
    [void]$sb.AppendLine('    [Parameter(Mandatory = $true)]')
    [void]$sb.AppendLine('    [string]$UserPrincipalName,')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    [switch]$WhatIf,    # Preview changes without applying')
    [void]$sb.AppendLine('    [switch]$Force      # Skip confirmation prompts')
    [void]$sb.AppendLine(')')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Set-StrictMode -Version Latest')
    [void]$sb.AppendLine('$ErrorActionPreference = "Continue"')
    [void]$sb.AppendLine('')

    # ── Connection ───────────────────────────────────────────
    [void]$sb.AppendLine('# ── Connect ──────────────────────────────────────────────')
    [void]$sb.AppendLine('Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan')
    [void]$sb.AppendLine('Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false')
    [void]$sb.AppendLine('Write-Host "[+] Connected" -ForegroundColor Green')
    [void]$sb.AppendLine('')

    # ── Remediation blocks per finding ───────────────────────
    $remediationMap = @{
        'SmtpClientAuth'    = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── SMTP Client Authentication ───────────────────────────')
            [void]$sb.AppendLine('# Disables legacy SMTP AUTH tenant-wide.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.HIPAA_Current)    { [void]$sb.AppendLine("# HIPAA: $($f.HIPAA_Current)") }
            [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("Tenant", "Disable SMTP Client Authentication")) {')
            [void]$sb.AppendLine('    Set-TransportConfig -SmtpClientAuthenticationDisabled $true')
            [void]$sb.AppendLine('    Write-Host "[+] SMTP client authentication disabled" -ForegroundColor Green')
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
        'ExternalForwarding' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── External Auto-Forwarding ─────────────────────────────')
            [void]$sb.AppendLine('# Disables external auto-forwarding at the remote domain level.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.HIPAA_Current)    { [void]$sb.AppendLine("# HIPAA: $($f.HIPAA_Current)") }
            [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("Default Remote Domain", "Disable Auto-Forwarding")) {')
            [void]$sb.AppendLine('    Set-RemoteDomain Default -AutoForwardEnabled $false')
            [void]$sb.AppendLine('    Write-Host "[+] External auto-forwarding disabled" -ForegroundColor Green')
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
        'PopEnabled' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── POP3 Protocol ────────────────────────────────────────')
            [void]$sb.AppendLine('# Disables POP3 on all mailboxes.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.HIPAA_Current)    { [void]$sb.AppendLine("# HIPAA: $($f.HIPAA_Current)") }
            [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("All Mailboxes", "Disable POP3")) {')
            [void]$sb.AppendLine('    Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false')
            [void]$sb.AppendLine('    Write-Host "[+] POP3 disabled on all mailboxes" -ForegroundColor Green')
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
        'ImapEnabled' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── IMAP Protocol ────────────────────────────────────────')
            [void]$sb.AppendLine('# Disables IMAP on all mailboxes.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.HIPAA_Current)    { [void]$sb.AppendLine("# HIPAA: $($f.HIPAA_Current)") }
            [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("All Mailboxes", "Disable IMAP")) {')
            [void]$sb.AppendLine('    Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -ImapEnabled $false')
            [void]$sb.AppendLine('    Write-Host "[+] IMAP disabled on all mailboxes" -ForegroundColor Green')
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
        'MailboxAudit' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── Mailbox Auditing ─────────────────────────────────────')
            [void]$sb.AppendLine('# Enables auditing on all mailboxes.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.HIPAA_Current)    { [void]$sb.AppendLine("# HIPAA: $($f.HIPAA_Current)") }
            if ($f.AffectedObjects -and $f.AffectedObjects.Count -gt 0) {
                [void]$sb.AppendLine("# Affected mailboxes: $($f.AffectedObjects -join ', ')")
                [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("Affected Mailboxes", "Enable Auditing")) {')
                foreach ($mbx in $f.AffectedObjects) {
                    [void]$sb.AppendLine("    Set-Mailbox -Identity '$mbx' -AuditEnabled `$true")
                }
            } else {
                [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("All Mailboxes", "Enable Auditing")) {')
                [void]$sb.AppendLine('    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true')
            }
            [void]$sb.AppendLine('    Write-Host "[+] Mailbox auditing enabled" -ForegroundColor Green')
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
        'OutboundSpam' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── Outbound Spam Notification ───────────────────────────')
            [void]$sb.AppendLine('# Enables outbound spam alerting. Update the recipient address below.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            [void]$sb.AppendLine('$notifyRecipient = "admin@yourdomain.com"  # UPDATE THIS')
            [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("Outbound Spam Policy", "Enable Notification")) {')
            [void]$sb.AppendLine('    Set-HostedOutboundSpamFilterPolicy -Identity Default `')
            [void]$sb.AppendLine('        -NotifyOutboundSpam $true `')
            [void]$sb.AppendLine('        -NotifyOutboundSpamRecipients $notifyRecipient')
            [void]$sb.AppendLine('    Write-Host "[+] Outbound spam notification enabled" -ForegroundColor Green')
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
        'DKIM' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── DKIM Signing ─────────────────────────────────────────')
            [void]$sb.AppendLine('# Enables DKIM signing for affected domains.')
            [void]$sb.AppendLine('# Note: DNS CNAME records must exist before enabling.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.AffectedObjects -and $f.AffectedObjects.Count -gt 0) {
                [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("Affected Domains", "Enable DKIM")) {')
                foreach ($domain in $f.AffectedObjects) {
                    [void]$sb.AppendLine("    Enable-DkimSigningConfig -Identity '$domain'")
                    [void]$sb.AppendLine("    Write-Host \"[+] DKIM enabled for $domain\" -ForegroundColor Green")
                }
                [void]$sb.AppendLine('}')
            } else {
                [void]$sb.AppendLine('# Run Get-DkimSigningConfig to identify domains needing DKIM enabled')
                [void]$sb.AppendLine('# Enable-DkimSigningConfig -Identity <domain>')
            }
            [void]$sb.AppendLine('')
        }
        'SafeLinks' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── Safe Links ───────────────────────────────────────────')
            [void]$sb.AppendLine('# Safe Links must be enabled via the Microsoft Defender portal.')
            [void]$sb.AppendLine('# Portal: https://security.microsoft.com > Email & collaboration > Policies & rules > Safe Links')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            [void]$sb.AppendLine('Write-Host "[!] Safe Links -- manual action required in Defender portal" -ForegroundColor Yellow')
            [void]$sb.AppendLine('Write-Host "    https://security.microsoft.com" -ForegroundColor DarkGray')
            [void]$sb.AppendLine('')
        }
        'DNSSEC' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── DNSSEC ───────────────────────────────────────────────')
            [void]$sb.AppendLine('# Enables DNSSEC for affected domains.')
            [void]$sb.AppendLine('# After enabling, update MX record to p-v1.mx.microsoft endpoint.')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            if ($f.AffectedObjects -and $f.AffectedObjects.Count -gt 0) {
                [void]$sb.AppendLine('if ($Force -or $PSCmdlet.ShouldProcess("Affected Domains", "Enable DNSSEC")) {')
                foreach ($domain in $f.AffectedObjects) {
                    [void]$sb.AppendLine("    Enable-DnssecForVerifiedDomain -DomainName '$domain'")
                    [void]$sb.AppendLine("    Write-Host \"[+] DNSSEC enabled for $domain -- update MX record\" -ForegroundColor Green")
                }
                [void]$sb.AppendLine('}')
            }
            [void]$sb.AppendLine('')
        }
        'AdminMFA' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── MFA / Authentication Policy ──────────────────────────')
            [void]$sb.AppendLine('# MFA enforcement requires a Conditional Access policy.')
            [void]$sb.AppendLine('# Portal: https://entra.microsoft.com > Protection > Conditional Access')
            [void]$sb.AppendLine('# Create a policy: All users > All cloud apps > Grant: Require MFA')
            if ($f.NIST_SP800_53_r5) { [void]$sb.AppendLine("# NIST: $($f.NIST_SP800_53_r5)") }
            [void]$sb.AppendLine('Write-Host "[!] MFA enforcement -- Conditional Access policy required" -ForegroundColor Yellow')
            [void]$sb.AppendLine('Write-Host "    https://entra.microsoft.com" -ForegroundColor DarkGray')
            [void]$sb.AppendLine('')
        }
        'CAPolicy' = {
            param($f, $sb)
            [void]$sb.AppendLine('# ── Conditional Access Policies ──────────────────────────')
            [void]$sb.AppendLine('# CA policies must be reviewed and enabled in Entra ID.')
            [void]$sb.AppendLine('# Portal: https://entra.microsoft.com > Protection > Conditional Access')
            [void]$sb.AppendLine('Write-Host "[!] Conditional Access -- review and enable policies in Entra ID" -ForegroundColor Yellow')
            [void]$sb.AppendLine('Write-Host "    https://entra.microsoft.com" -ForegroundColor DarkGray')
            [void]$sb.AppendLine('')
        }
    }

    # Write remediation block for each gap/partial finding
    foreach ($finding in $findings) {
        $block = $remediationMap[$finding.ControlId]
        if ($block) {
            & $block $finding $sb
        } else {
            # Generic block for findings without a specific template
            [void]$sb.AppendLine("# ── $($finding.Title) ─────────────────────────────────")
            [void]$sb.AppendLine("# State: $($finding.State)")
            [void]$sb.AppendLine("# $($finding.Detail)")
            if ($finding.Remediation) {
                [void]$sb.AppendLine("# Remediation: $($finding.Remediation)")
            }
            [void]$sb.AppendLine('# Manual action required -- no automated remediation available for this control.')
            [void]$sb.AppendLine('')
        }
    }

    # ── Footer ───────────────────────────────────────────────
    [void]$sb.AppendLine('# ── Disconnect ───────────────────────────────────────────')
    [void]$sb.AppendLine('Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue')
    [void]$sb.AppendLine('Write-Host ""')
    [void]$sb.AppendLine('Write-Host "Remediation script complete. Re-run assessment to verify." -ForegroundColor Cyan')
    [void]$sb.AppendLine('Write-Host "NextLayerSec -- nextlayersec.io"')

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Host "  [+] Remediation script written to: $OutputPath" -ForegroundColor Green
}

}

Export-ModuleMember -Function Publish-NLSRemediationScript
