#
# NLS.Correlation.psm1
# NextLayerSec Assessment Framework -- Attack Path Correlation Engine
# v2.0.0
#
# Identifies composite attack paths from combined control gaps.
# Each rule maps to real-world attack techniques observed in incident response.
# Rules evaluate findings + extended telemetry to surface exploitation chains.
#
# Rule naming convention:
#   CORR-NNN: Sequential identifier
#   Severity: Critical / High / Medium
#   MITRE ATT&CK techniques mapped per rule
#
# Author:  NextLayerSec
# Version: 2.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Invoke-NLSCorrelationEngine {
    <#
    .SYNOPSIS
        Evaluates combined control gaps to identify attack path correlations.
    .DESCRIPTION
        Runs after scoring. Takes scored findings and extended telemetry as input.
        Returns correlation findings that map combined gaps to attack techniques.
        Correlation findings appear in Section 2 Action Plan at Critical/High priority.
    #>
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Findings,
        [Parameter(Mandatory)]
        [hashtable]$ExtendedData,
        [bool]$DebugMode = $false
    )

    $correlations = [System.Collections.Generic.List[object]]::new()

    # Build state lookup from scored findings
    $state = @{}
    foreach ($f in $Findings) {
        $state[$f['ControlId']] = $f['State']
    }

    # Helper
    function IsGap   { param($id) $state[$id] -eq 'Gap' }
    function IsPartial { param($id) $state[$id] -eq 'Partial' -or $state[$id] -eq 'Gap' }

    # Pull extended data for richer correlation context
    $mfaData    = $ExtendedData['UserMFAStatus']
    $pimData    = $ExtendedData['PIM']
    $adminData  = $ExtendedData['AdminRoleInventory']
    $guestData  = $ExtendedData['GuestAccountInventory']
    $staleData  = $ExtendedData['StaleAccounts']

    $noMFACount  = if ($mfaData)   { [int]$mfaData['NoMFARegistered'] }         else { 0 }
    $gaCount     = if ($adminData) { [int]$adminData['GlobalAdminCount'] }       else { 0 }
    $permGAs     = if ($pimData)   { [int]$pimData['PermanentGlobalAdminCount'] } else { 0 }
    $staleCount  = if ($staleData) { [int]$staleData['StaleCount'] }             else { 0 }
    $staleGuests = if ($guestData) { [int]$guestData['StaleGuests'] }            else { 0 }
    $legacyAttempts = if ($ExtendedData['ConditionalAccessTelemetry']) {
        [int]$ExtendedData['ConditionalAccessTelemetry']['LegacyAuthAttempts']
    } else { 0 }

    # ─────────────────────────────────────────────────────────────────────────
    # CORR-001: Business Email Compromise (BEC) Attack Path
    # Trigger: MFA gap + legacy auth enabled + external forwarding enabled
    # Technique: T1078 Valid Accounts, T1114 Email Collection, T1566 Phishing
    # ─────────────────────────────────────────────────────────────────────────
    $legacyEnabled   = IsGap 'LegacyAuth'
    $mfaGap          = (IsGap 'UserMFAGap') -or ($noMFACount -gt 0)
    $forwardingGap   = IsGap 'ExternalForwarding'

    if ($legacyEnabled -and $mfaGap -and $forwardingGap) {
        $severity = 'Critical'
        $detail   = "Legacy authentication enabled ($($legacyAttempts) recent attempt(s)), $noMFACount user(s) without MFA, and external auto-forwarding active. This is the complete BEC kill chain: legacy auth bypasses MFA CA policies, credential compromise redirects mail externally. Observed in 68% of M365 BEC incidents (CISA AA23-193A)."
        $impact   = "Account takeover via legacy auth → inbox rule creation → financial fraud. Average loss: \$137,000 per incident (FBI IC3 2023)."
    } elseif ($legacyEnabled -and $mfaGap) {
        $severity = 'High'
        $detail   = "Legacy authentication enabled with $noMFACount user(s) lacking MFA. Credential spray via legacy protocols bypasses MFA CA policies for unregistered accounts."
        $impact   = "Account takeover via legacy auth + unprotected accounts. External forwarding not active but inbox rules may be created post-compromise."
    } elseif ($mfaGap -and $forwardingGap) {
        $severity = 'High'
        $detail   = "$noMFACount user(s) without MFA and external forwarding enabled. Compromised accounts can immediately exfiltrate mail without additional configuration."
        $impact   = "Account takeover → immediate mail exfiltration via pre-existing forwarding."
    } else {
        $severity = $null
    }

    if ($severity) {
        [void]$correlations.Add([ordered]@{
            ControlId   = 'CORR-001'
            Title       = 'Business Email Compromise Attack Path'
            State       = 'Gap'
            Severity    = $severity
            Category    = 'Attack Path'
            Detail      = $detail
            Impact      = $impact
            Mitre       = 'T1078 (Valid Accounts), T1114 (Email Collection), T1566 (Phishing), T1534 (Internal Spearphishing)'
            Components  = @('LegacyAuth', 'UserMFAGap', 'ExternalForwarding')
            Remediation = 'Disable legacy authentication via CA policy, enforce MFA registration campaign for all users, disable external auto-forwarding on Default remote domain.'
        })
    }

    # ─────────────────────────────────────────────────────────────────────────
    # CORR-002: Tenant Takeover / Privilege Escalation Path
    # Trigger: GA sprawl + permanent GA assignments + no break-glass
    # Technique: T1078.004 Cloud Accounts, T1098 Account Manipulation
    # ─────────────────────────────────────────────────────────────────────────
    $gaExcessive  = IsGap 'GlobalAdminCount'
    $noBreakGlass = IsGap 'BreakGlass'
    $hasPermanentGAs = $permGAs -gt 2

    if ($gaExcessive -and $hasPermanentGAs -and $noBreakGlass) {
        $severity = 'Critical'
        $detail   = "$gaCount Global Administrators detected, $permGAs permanent (no PIM time-limiting), no break-glass account properly configured. All permanent GAs represent standing full-tenant compromise paths. No emergency recovery account means a compromised GA lockout has no recovery path."
        $impact   = "Single compromised GA credential yields full tenant control. All data, all mailboxes, all applications. No time-limiting means persistence is indefinite."
    } elseif ($gaExcessive -and $hasPermanentGAs) {
        $severity = 'High'
        $detail   = "$gaCount Global Administrators, $permGAs permanent. Standing privilege with no time-limiting via PIM. Each GA is an independent full-tenant compromise path."
        $impact   = "Compromised GA credential yields full tenant control. PIM not deployed means no activation logging or approval workflow to detect abuse."
    } elseif ($gaExcessive) {
        $severity = 'Medium'
        $detail   = "$gaCount Global Administrators exceeds recommended maximum of 2. Each additional GA expands the blast radius of a credential compromise."
        $impact   = "Excess privileged accounts increase likelihood of credential exposure through phishing or credential spray."
    } else {
        $severity = $null
    }

    if ($severity) {
        [void]$correlations.Add([ordered]@{
            ControlId   = 'CORR-002'
            Title       = 'Privileged Access Takeover Path'
            State       = 'Gap'
            Severity    = $severity
            Category    = 'Attack Path'
            Detail      = $detail
            Impact      = $impact
            Mitre       = 'T1078.004 (Valid Accounts: Cloud Accounts), T1098 (Account Manipulation), T1098.003 (Additional Cloud Roles)'
            Components  = @('GlobalAdminCount', 'BreakGlass')
            Remediation = 'Reduce GA count to 2, deploy PIM for time-limited activation on remaining GAs, configure break-glass account excluded from all CA policies.'
        })
    }

    # ─────────────────────────────────────────────────────────────────────────
    # CORR-003: OAuth Persistence / Illicit Consent Grant
    # Trigger: User consent enabled + MFA gap
    # Technique: T1528 Steal Application Access Token, T1550.001 Application Access Token
    # ─────────────────────────────────────────────────────────────────────────
    $consentOpen = IsGap 'ConsentFramework'

    if ($consentOpen -and $mfaGap) {
        $severity = 'High'
        $detail   = "User consent to applications enabled with $noMFACount user(s) without MFA. Phishing campaigns deliver OAuth consent links -- victim clicks grants attacker persistent application access token that survives password resets."
        $impact   = "Persistent application access bypassing all MFA and CA policies. Access token grants mailbox read, file access, or broader permissions depending on scopes requested. Not revoked by password change."
    } elseif ($consentOpen) {
        $severity = 'Medium'
        $detail   = "User consent to applications enabled. Even with MFA enforced, phishing-delivered OAuth consent links can obtain persistent access tokens."
        $impact   = "Application access tokens may persist after incident remediation. Require admin consent to prevent unauthorized app registrations."
    } else {
        $severity = $null
    }

    if ($severity) {
        [void]$correlations.Add([ordered]@{
            ControlId   = 'CORR-003'
            Title       = 'OAuth Persistence / Illicit Consent Grant'
            State       = 'Gap'
            Severity    = $severity
            Category    = 'Attack Path'
            Detail      = $detail
            Impact      = $impact
            Mitre       = 'T1528 (Steal Application Access Token), T1550.001 (Application Access Token), T1566 (Phishing)'
            Components  = @('ConsentFramework', 'UserMFAGap')
            Remediation = 'Disable user consent to applications (require admin approval), enforce MFA registration to reduce phishing exposure.'
        })
    }

    # ─────────────────────────────────────────────────────────────────────────
    # CORR-004: Email Domain Spoofing / Supply Chain Phishing
    # Trigger: DMARC not at reject + DKIM gaps
    # Technique: T1566.002 Spearphishing Link, T1598 Phishing for Information
    # ─────────────────────────────────────────────────────────────────────────
    $dmarcGap  = IsPartial 'DMARC'
    $dkimGap   = IsPartial 'DKIM'

    if ($dmarcGap -and $dkimGap) {
        $severity = 'High'
        $detail   = "DMARC not at p=reject and DKIM signing not fully configured. Attackers can send email appearing to originate from your domains to targets who trust your organization."
        $impact   = "Domain spoofing enables supply chain attacks against clients, partners, and staff. Financial fraud, credential phishing, and malware delivery using your trusted domain identity."
    } elseif ($dmarcGap) {
        $severity = 'Medium'
        $detail   = "DMARC policy not at p=reject. DKIM is configured but DMARC enforcement gap allows spoofed messages through receivers that don't fully enforce DMARC."
        $impact   = "Partial domain spoofing protection. Advance to p=reject after reviewing DMARC aggregate reports to prevent spoofed delivery."
    } else {
        $severity = $null
    }

    if ($severity) {
        [void]$correlations.Add([ordered]@{
            ControlId   = 'CORR-004'
            Title       = 'Email Domain Spoofing Risk'
            State       = if ($severity -eq 'High') { 'Gap' } else { 'Partial' }
            Severity    = $severity
            Category    = 'Attack Path'
            Detail      = $detail
            Impact      = $impact
            Mitre       = 'T1566.002 (Spearphishing Link), T1598 (Phishing for Information), T1534 (Internal Spearphishing)'
            Components  = @('DMARC', 'DKIM')
            Remediation = 'Advance DMARC to p=reject after reviewing aggregate reports. Ensure DKIM signing is enabled on all custom domains.'
        })
    }

    # ─────────────────────────────────────────────────────────────────────────
    # CORR-005: Stale Identity Attack Surface
    # Trigger: Stale accounts + stale guests + no MFA on stale
    # Technique: T1078 Valid Accounts, T1133 External Remote Services
    # ─────────────────────────────────────────────────────────────────────────
    $hasStale  = IsPartial 'StaleAccounts'
    $hasGuests = ($staleGuests -gt 5)

    if ($hasStale -and $hasGuests -and $mfaGap) {
        $severity = 'High'
        $detail   = "$staleCount stale internal accounts and $staleGuests stale guest accounts. Stale accounts are low-detection-risk targets -- compromised credentials for inactive users generate fewer alerts. Combined with MFA gaps, these accounts are valid authentication paths with minimal monitoring."
        $impact   = "Stale accounts provide low-noise initial access. Inactive accounts rarely trigger behavioral anomaly detection. Guest accounts from former vendors may retain SharePoint/Teams access."
    } elseif ($hasStale -and $hasGuests) {
        $severity = 'Medium'
        $detail   = "$staleCount stale internal accounts and $staleGuests stale guest accounts detected. Inactive accounts with valid credentials represent persistent attack surface even with MFA enforced."
        $impact   = "Stale credentials retained by former employees or contractors may be reused. Guest accounts from former vendors retain access to shared resources."
    } else {
        $severity = $null
    }

    if ($severity) {
        [void]$correlations.Add([ordered]@{
            ControlId   = 'CORR-005'
            Title       = 'Stale Identity Attack Surface'
            State       = 'Gap'
            Severity    = $severity
            Category    = 'Attack Path'
            Detail      = $detail
            Impact      = $impact
            Mitre       = 'T1078 (Valid Accounts), T1133 (External Remote Services), T1078.004 (Cloud Accounts)'
            Components  = @('StaleAccounts')
            Remediation = 'Disable stale user accounts and remove stale guest accounts. Implement automated lifecycle management with 90-day inactivity review.'
        })
    }

    if ($DebugMode) {
        Write-Host "  [CORR] Rules evaluated: 5 | Findings generated: $($correlations.Count)" -ForegroundColor Cyan
        foreach ($c in $correlations) {
            Write-Host "  [CORR] $($c['ControlId']) $($c['Severity']): $($c['Title'])" -ForegroundColor Yellow
        }
    }

    return @($correlations)
}

Export-ModuleMember -Function Invoke-NLSCorrelationEngine
