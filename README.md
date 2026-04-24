# NLS-Assessment v2

> NextLayerSec M365 Security Assessment Framework — Version 2
> Read-only assessment instrument for Exchange Online and Entra ID.
> Maps findings to NIST SP 800-53 Rev 5, CIS Controls v8.1, HIPAA current rule,
> HIPAA NPRM proposed rule, and CISA Zero Trust Maturity Model.
> Produces structured markdown artifacts with granular finding detail,
> affected object lists, current state vs recommended comparisons,
> per-framework recommendation blocks, delta reporting, remediation scripts,
> and cross-tenant portfolio summaries.

[![License](https://img.shields.io/badge/License-CC%20BY--ND%204.0-blue?style=flat-square)](https://creativecommons.org/licenses/by-nd/4.0/)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue?style=flat-square)](https://github.com/PowerShell/PowerShell)
[![Read Only](https://img.shields.io/badge/Mode-Read--Only-00c853?style=flat-square)]()
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20HIPAA%20%7C%20ZeroTrust-orange?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-2.3.0-white?style=flat-square)]()

---

## What's New in v2

| Feature | Description |
|---|---|
| Assessment profiles | `-P Quick/Standard/HIPAA/MSP/ZeroTrust/Full` — predefined flag bundles |
| Remediation script | Auto-generated per-tenant PowerShell remediation script every run |
| Delta reporting | Compares current run against previous — surfaces improved, regressed, new |
| Portfolio summary | `Invoke-NLSSummary.ps1` — cross-tenant view ranked by risk score |
| BLUF report structure | Executive Summary → Action Plan → Posture & Telemetry → Appendix |
| Inline PS remediation | PowerShell commands render as copy-paste code blocks in Action Plan |
| Live DNS lookup | SPF, DMARC, DKIM record verification per domain (`-DNSRecords`) |
| SHA-256 module integrity | Hash manifest prevents in-place file tampering (`-GenerateManifest`) |
| Token cache clear | `-ClearToken` fixes stale Graph token scope issues |
| Debug scoring mode | `-DebugScoring` surfaces scoring errors and per-section traces |
| Command injection hardening | Identity variables sanitized in generated remediation scripts |
| Redaction hardening | IPv6, tenant URLs, and display names redacted when `-RedactSensitiveData` |
| Extended checks | DMARC, MTA-STS, Inbound Spam, Malware Filter, Security Defaults, Auth Methods, Consent Framework, PIM, Break-Glass |
| CA policy inventory | Full policy table with state, MFA grant, legacy auth block, device compliance |
| User MFA gap analysis | Per-user MFA registration status with admin flagging (`-MFAReport`) |
| Secure Score integration | Current score, top improvement opportunities (`-SecureScore`) |
| Admin role inventory | Global Admin count, over-privilege detection (`-AdminRoles`) |
| Stale account detection | Accounts inactive 90+ days with last sign-in (`-StaleAccounts`) |
| Guest account inventory | External guest accounts with stale detection (`-GuestInventory`) |
| Named location check | Zero Trust gap warning if no named locations defined (`-NamedLocations`) |
| Service principal inventory | High-privilege app detection, Microsoft first-party excluded (`-ServicePrincipals`) |
| Shared mailbox hardening | Interactive sign-in and legacy protocol check (`-SharedMailboxes`) |
| Break-glass account check | Detects and validates emergency access account CA exclusion (`-BreakGlass`) |
| Auto-open report | Reports open in VS Code automatically if installed |
| Custom help output | `.\Invoke-NLSAssessment.ps1 --help` |

---

## Overview

`Invoke-NLSAssessment` is a precision read-only assessment instrument built for MSP and consulting operations. It connects to Exchange Online and Microsoft Graph, collects security policy configuration and sign-in telemetry, scores findings against the NextLayerSec baseline, and produces structured markdown artifacts mapped to authoritative compliance frameworks.

**No tenant configuration changes are made at any point.**

Every run produces three artifacts — the assessment report, a remediation script, and an exceptions log. If a previous report exists for the same tenant, the report automatically includes a delta section showing what changed since the last run.

---

## Report Structure

Reports follow a BLUF (Bottom Line Up Front) structure designed for both executive and technical readers.

**Section 1 — Executive Summary:** Secure Score, gap/pass counts, and a one-line bottom line. Readers know the tenant's posture in 10 seconds.

**Section 2 — Action Plan:** Gaps and partials only. Each finding shows current state, risk, framework citations, and remediation. PowerShell-executable remediations render as copy-paste code blocks. Portal-only actions are clearly labeled.

**Section 3 — Posture & Telemetry:** Supporting evidence. Identity and privilege summary, admin role table, named locations, service principals, CA policy inventory, DMARC status, DNS records.

**Section 4 — Appendix:** Satisfied controls grouped by category, collection coverage table, and full assessment metadata. Audit trail without cluttering the primary workflow.

---

## What It Checks

### Exchange Online (Standard)
- Legacy authentication policy configuration and org default assignment
- SMTP client authentication status
- External auto-forwarding controls
- Mailbox protocol hardening (POP, IMAP) — with affected mailbox lists
- Mailbox auditing — with list of mailboxes with auditing disabled
- Unified audit log status
- Outbound spam notification
- Defender for Office 365 (Safe Attachments, Safe Links, Anti-Phishing, ZAP, ATP)
- DKIM signing configuration per domain
- DNSSEC status per domain — EXO check with live DNS fallback

### Exchange Online (Optional Flags)
- DMARC policy state per domain via DNS (`-DMARC`)
- Live DNS record lookup — SPF, DMARC, DKIM published values (`-DNSRecords`)
- Shared mailbox hardening — interactive sign-in and legacy protocols (`-SharedMailboxes`)
- MTA-STS, inbound spam policy, malware filter policy (`-MailFlowHardening`)

### Identity (Microsoft Graph — Standard)
- Full CA policy inventory — state, MFA grant, legacy auth block, device compliance
- Missing recommended policy detection
- MFA enforcement via BuiltInControls and AuthenticationStrength
- Legacy authentication blocking
- Sign-in log telemetry

### Graph Extended Data (Optional Flags)
- Per-user MFA registration status with admin flagging (`-MFAReport`)
- Microsoft Secure Score (`-SecureScore`)
- Admin role inventory and over-privilege detection (`-AdminRoles`)
- Stale accounts inactive 90+ days (`-StaleAccounts`)
- External guest account inventory (`-GuestInventory`)
- Named location definition check (`-NamedLocations`)
- High-privilege service principal inventory, Microsoft first-party excluded (`-ServicePrincipals`)
- Security Defaults, authentication methods, consent framework, PIM (`-IdentityHardening`)
- Break-glass account configuration and CA exclusion (`-BreakGlass`)

---

## Framework Mapping

| Framework | Version | Switch |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | `-NIST` |
| CIS Controls | v8.1 June 2024 | `-CIS` |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable rule | `-HIPAA` |
| HIPAA Security Rule NPRM | December 27 2024 proposed rule | `-HIPAAProposed` |
| CISA Zero Trust Maturity Model | 2023 | `-ZeroTrust` |

**Default behavior:** When no framework flag is passed, `-NIST` is applied automatically.

### HIPAA NPRM Note

The December 2024 NPRM proposes eliminating the required/addressable distinction across all implementation specifications. Expected final rule: May 2026 with a 240-day compliance window. Running `-HIPAA -HIPAAProposed` together produces a dual-state gap analysis. Recommended for all healthcare client engagements.

### Finding States

| State | Severity | Meaning |
|---|---|---|
| Gap | High | Control is missing or disabled |
| Partial | Medium | Control exists but not fully enforced |
| Satisfied | Pass | Control is enabled and enforced |

---

## Profiles

| Profile | Syntax | Frameworks | Features Included |
|---|---|---|---|
| Quick | `-P Quick` | NIST | Exchange only, no Graph — fastest triage |
| Standard | `-P Standard` | NIST, CIS | Full Graph — general purpose assessment |
| HIPAA | `-P HIPAA` | HIPAA, HIPAAProposed | MFAReport, AdminRoles, DMARC, SharedMailboxes |
| MSP | `-P MSP` | NIST, CIS | AdminRoles, StaleAccounts, GuestInventory, DMARC, SharedMailboxes, DNSRecords, MailFlowHardening |
| ZeroTrust | `-P ZeroTrust` | NIST, ZeroTrust | NamedLocations, AdminRoles, MFAReport, ServicePrincipals, StaleAccounts, IdentityHardening, BreakGlass |
| Full | `-P Full` | All frameworks | All features |

Profiles are additive — extra flags alongside `-P` expand the profile.

---

## Usage

### Get Help

```powershell
.\Invoke-NLSAssessment.ps1 --help
```

### Profile Examples

```powershell
# Quick triage -- Exchange only, no Graph
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Quick

# MSP tenant assessment
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP

# Healthcare client -- dual-state HIPAA, redacted
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P HIPAA -RedactSensitiveData

# Full assessment -- everything, redacted
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -RedactSensitiveData

# Profile expanded with extra flag
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -SecureScore
```

### Troubleshooting Runs

```powershell
# Fix stale Graph token (AccessDenied on CA or Named Locations)
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -ClearToken

# Debug scoring errors -- surfaces section traces and citation failures
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -DebugScoring

# Filter debug output only
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -DebugScoring 2>&1 | Select-String "DEBUG"
```

### Delta Comparison

Delta runs automatically when a previous report exists for the same tenant. Manual override:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -Compare ".\output\ndaco-20260301.md"
```

### Portfolio Summary

```powershell
.\Invoke-NLSSummary.ps1
```

---

## Security

### Module Integrity

Every run verifies all NLS modules against a SHA-256 hash manifest. If any module has been modified since the manifest was generated, the tool aborts with `MODULE INTEGRITY VIOLATION DETECTED`.

This covers two attack vectors: path injection (malicious `.psm1` from a different directory) and in-place tampering (legitimate module file modified on disk).

### First Run — Generate Hash Manifest

After downloading or updating the tool, generate the baseline hash manifest before running any assessments:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest
```

### Update Procedure

Any time you replace a module file you must regenerate the manifest:

```powershell
# Step 1 -- replace module files
# Step 2 -- regenerate manifest
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest
# Step 3 -- run assessment
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full
```

### Output Security

- Output directory permissions locked to current user on creation
- `-RedactSensitiveData` scrubs UPNs, GUIDs, IPv4, IPv6, and tenant URLs from all output including exceptions log
- Remediation scripts sanitize identity variables to prevent command injection

---

## Output

Every run produces three files in `output\` named using the tenant domain and date.

| File | Example | Contents |
|---|---|---|
| `<tenant>-<date>.md` | `ndaco-20260424.md` | Full assessment report |
| `<tenant>-<date>-remediation.ps1` | `ndaco-20260424-remediation.ps1` | Ready-to-review remediation script |
| `<tenant>-<date>-exceptions.md` | `ndaco-20260424-exceptions.md` | Non-fatal collection errors |

### Remediation Script

```powershell
# Preview changes without applying
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org -WhatIf

# Apply with confirmation prompts
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org

# Apply without prompts
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org -Force
```

Always review the remediation script before running. Outbound spam notification requires updating the recipient address before executing — the script throws a terminating error if the placeholder is not updated.

---

## Architecture

```
NLS-Assessment/
|
|-- Invoke-NLSAssessment.ps1           # Orchestrator -- run this
|-- Invoke-NLSSummary.ps1              # Portfolio summary across all tenants
|
|-- Modules/
|   |-- NLS.Core.psm1                  # Output safety, redaction, integrity, security controls
|   |-- NLS.Exchange.psm1              # Exchange Online + DMARC + DNS + mail flow hardening
|   |-- NLS.ConditionalAccess.psm1     # Graph CA, telemetry, MFA, Secure Score, identity hardening
|   |-- NLS.FrameworkDictionary.psm1   # 27 state-aware compliance citations (data only)
|   |-- NLS.Scoring.psm1               # Scoring engine with module-level dedup
|   |-- NLS.Reporting.psm1             # BLUF markdown report generator
|   |-- NLS.Remediation.psm1           # Remediation script generator
|   |-- NLS.Delta.psm1                 # Delta comparison and reporting
|   `-- modules.sha256                 # SHA-256 hash manifest (generated, not committed)
|
|-- output/                            # Assessment artifacts (gitignored)
|
|-- README.md
`-- .gitignore
```

### Security Controls in NLS.Core

| Function | Purpose |
|---|---|
| `Test-NLSInputUPN` | Validates UPN format before passing to connection cmdlets |
| `Test-NLSModuleIntegrity` | Path check + SHA-256 hash check against manifest |
| `New-NLSModuleHashManifest` | Generates baseline hash manifest |
| `Protect-NLSOutputPath` | Locks output directory permissions to current user |
| `Invoke-NLSRedaction` | Central redaction — UPNs, GUIDs, IPv4, IPv6, tenant URLs |
| `Protect-NLSExceptionsRedaction` | Applies central redaction to exceptions log |

### Scoring Architecture

`Add-NLSFinding` is a module-level function in `NLS.Scoring.psm1`. It maintains a `HashSet[string]` of scored ControlIds to prevent duplicates regardless of how many code paths evaluate the same control. Framework citations are looked up at call time from `NLS.FrameworkDictionary.psm1` and attached to each finding.

### Data and Logic Separation

`NLS.FrameworkDictionary.psm1` contains only compliance mapping data — no execution logic. When a framework releases a new version, only this file changes. All 27 ControlIds have Satisfied, Partial, and Gap states defined for each active framework.

---

## Requirements

### PowerShell Version

PowerShell 7+ required. Windows PowerShell 5.1 not supported.

```powershell
winget install Microsoft.PowerShell
```

### Modules

```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
```

### Permissions

| Scope | Required For |
|---|---|
| Exchange Admin or Global Admin | Exchange Online collection |
| `Policy.Read.ConditionalAccess` | CA policy collection |
| `Policy.Read.All` | Named Locations |
| `Directory.Read.All` | Admin roles, guest inventory, service principals |
| `AuditLog.Read.All` | Sign-in log telemetry, stale accounts |
| `Reports.Read.All` | User MFA registration status (`-MFAReport`) |
| `SecurityEvents.Read.All` | Secure Score (`-SecureScore`) |

---

## First Run Setup

Run these steps in order from PowerShell 7.

```powershell
# 1. Install PowerShell 7 if needed
winget install Microsoft.PowerShell

# 2. Install required modules
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force

# 3. Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 4. Navigate to tool folder
cd ~\Downloads\NLS-Assessment

# 5. Unblock downloaded files
Unblock-File -Path .\Invoke-NLSAssessment.ps1
Unblock-File -Path .\Invoke-NLSSummary.ps1
Unblock-File -Path .\Modules\*.psm1

# 6. Generate hash manifest (required before first run)
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest

# 7. Run first assessment
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Quick
```

---

## Coverage Map

| Status | Meaning |
|---|---|
| Collected | Data retrieved and scored successfully |
| Partial | Data retrieved but incomplete — permissions or licensing gap |
| NotCollected | Operator did not pass the required flag |
| Unsupported | Tenant licensing does not support this control |

---

## Operational Notes

- Always run from a dedicated admin account
- Use `-RedactSensitiveData` for any artifacts leaving your workstation
- The `output\` directory is gitignored — do not commit assessment artifacts
- `modules.sha256` is gitignored — each operator generates their own baseline
- Run from PowerShell 7 — Windows PowerShell 5.1 not supported
- First Graph run against a new tenant prompts for browser consent
- After replacing any module file, run `-GenerateManifest` before next assessment
- Use `-DebugScoring` when investigating scoring errors — outputs section traces and citation failures

---

## Framework Dictionary Versions

| Framework | Version Mapped | Last Updated |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | 2026-04-24 |
| CIS Controls | v8.1 June 2024 | 2026-04-24 |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable | 2026-04-24 |
| HIPAA NPRM | December 27 2024 proposed rule | 2026-04-24 |

---

## Troubleshooting

### Script blocked on first run

```powershell
Unblock-File -Path .\Invoke-NLSAssessment.ps1
Unblock-File -Path .\Invoke-NLSSummary.ps1
Unblock-File -Path .\Modules\*.psm1
```

### Execution policy error

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Module integrity violation

Symptom: `MODULE INTEGRITY VIOLATION DETECTED`

Expected after any module update. Fix:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest
```

If not caused by a legitimate update, re-download the repo and inspect what changed.

### Conditional Access or Named Locations returns Partial (AccessDenied)

Symptom: `[AccessDenied] : required scopes are missing in the token`

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -ClearToken
```

Accept all permissions when the browser opens.

### Scoring errors during assessment

Symptom: `InvalidOperation: Cannot index into a null array` during scoring

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -DebugScoring 2>&1 | Select-String "DEBUG"
```

The yellow citation error lines show exactly which ControlId and State caused the failure.

### Graph module assembly conflict

Symptom: `Could not load file or assembly 'Microsoft.Graph.Authentication'`

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

Close and reopen PowerShell 7.

### Defender for Office 365 Cmdlets Not Found

Symptom: `DefenderO365 | Partial | The term 'Get-SafeAttachmentPolicy' is not recognized`

Cause: Tenant does not have Defender for Office 365 Plan 1 or Plan 2. This is a licensing gap, not a security finding. All other controls still assess correctly.

### Device compliance blocking Graph consent

Symptom: `AADSTS53000: Device is not in required device state`

Options: run from a compliant enrolled device, use `-NoGraph` for Exchange-only checks, or exclude the admin account from the device compliance CA policy in Entra ID.

### Portfolio summary shows no reports

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP
.\Invoke-NLSSummary.ps1
```

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 2.3.0 | 2026-04-24 | BLUF report structure, inline PS remediation, -DebugScoring, 9 new checks (DMARC, MTA-STS, InboundSpam, MalwareFilter, SecurityDefaults, AuthMethods, ConsentFramework, PIM, BreakGlass), extended identity hardening |
| 2.2.0 | 2026-04-24 | SHA-256 integrity, -ClearToken, -GenerateManifest, DNS records, injection hardening, redaction hardening, first-party SP exclusion |
| 2.1.0 | 2026-04-24 | Delta reporting, remediation script generator, portfolio summary |
| 2.0.0 | 2026-04-24 | Full v2 build — profiles, all features, security hardening, extended inventory |
| 1.0.0 | 2026-04-24 | Initial release — public repo nextlayersec-assessment |

---

## Related

- [nextlayersec-assessment](https://github.com/Blackvectra/nextlayersec-assessment) -- v1.0.0 public release
- [nextlayersec-email-security](https://github.com/Blackvectra/nextlayersec-email-security) -- Full email security stack documentation

---

## License

CC BY-ND 4.0 -- See [LICENSE](LICENSE) for details.

---

<div align="center">

**[NextLayerSec](https://nextlayersec.io)** &nbsp;|&nbsp;
**[LinkedIn](https://linkedin.com/company/nextlayersec)** &nbsp;|&nbsp;
**[GitHub](https://github.com/Blackvectra)**

*Cybersecurity consulting for organizations that take security seriously.*

</div>
