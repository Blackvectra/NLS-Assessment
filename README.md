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
[![Version](https://img.shields.io/badge/Version-2.2.0-white?style=flat-square)]()

---

## What's New in v2

| Feature | Description |
|---|---|
| Assessment profiles | `-P Quick/Standard/HIPAA/MSP/ZeroTrust/Full` — predefined flag bundles |
| Remediation script | Auto-generated per-tenant PowerShell remediation script every run |
| Delta reporting | Compares current run against previous — surfaces improved, regressed, new |
| Portfolio summary | `Invoke-NLSSummary.ps1` — cross-tenant view ranked by risk score |
| Live DNS lookup | SPF, DMARC, DKIM record verification per domain (`-DNSRecords`) |
| SHA-256 module integrity | Hash manifest prevents in-place file tampering (`-GenerateManifest`) |
| Token cache clear | `-ClearToken` fixes stale Graph token scope issues |
| Command injection hardening | Identity variables sanitized in generated remediation scripts |
| Redaction hardening | IPv6, tenant URLs, and display names redacted when `-RedactSensitiveData` |
| Granular finding detail | Affected object lists on every count-based finding |
| Current state vs recommended | Structured comparison table per finding |
| Per-framework recommendation blocks | Each framework gets its own section with control name, detail, and requirement level |
| CA policy inventory | Full policy table with state, MFA, legacy auth, device compliance |
| User MFA gap analysis | Per-user MFA registration status with admin flagging (`-MFAReport`) |
| Secure Score integration | Current score, top gaps, per-control improvement opportunities (`-SecureScore`) |
| Admin role inventory | Global Admin count, over-privilege detection (`-AdminRoles`) |
| Stale account detection | Accounts inactive 90+ days with last sign-in (`-StaleAccounts`) |
| Guest account inventory | External guest accounts with stale detection (`-GuestInventory`) |
| Named location check | Zero Trust gap warning if no named locations defined (`-NamedLocations`) |
| Service principal inventory | High-privilege app detection, Microsoft first-party excluded (`-ServicePrincipals`) |
| Shared mailbox hardening | Interactive sign-in and legacy protocol check (`-SharedMailboxes`) |
| Auto-open report | Reports open in VS Code automatically if installed |
| Custom help output | `.\Invoke-NLSAssessment.ps1 --help` |

---

## Overview

`Invoke-NLSAssessment` is a precision read-only assessment instrument built for MSP and consulting operations. It connects to Exchange Online and Microsoft Graph, collects security policy configuration and sign-in telemetry, scores findings against the NextLayerSec baseline, and produces structured markdown artifacts mapped to authoritative compliance frameworks.

**No tenant configuration changes are made at any point.**

Every run produces three artifacts — the assessment report, a remediation script, and an exceptions log. If a previous report exists for the same tenant, the report automatically includes a delta section showing what changed since the last run.

Run `Invoke-NLSSummary.ps1` after assessing multiple tenants to get a portfolio-level view ranked by risk score.

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
- DKIM signing configuration per domain — with disabled domain list
- DNSSEC status per domain — EXO check with live DNS fallback

### Exchange Online (Optional Flags)
- DMARC policy state per domain via DNS (`-DMARC`)
- Live DNS record lookup — SPF, DMARC, DKIM published values (`-DNSRecords`)
- Shared mailbox hardening — interactive sign-in and legacy protocols (`-SharedMailboxes`)

### Conditional Access (Microsoft Graph — Standard)
- Full CA policy inventory — state, MFA grant, legacy auth block, device compliance
- Missing recommended policy detection
- MFA enforcement via BuiltInControls and AuthenticationStrength
- Legacy authentication blocking
- Report-only policy detection
- Sign-in log telemetry — legacy auth attempts by account, MFA challenge rate, failures

### Graph Extended Data (Optional Flags)
- Per-user MFA registration status with admin flagging (`-MFAReport`)
- Microsoft Secure Score with top improvement opportunities (`-SecureScore`)
- Admin role inventory and over-privilege detection (`-AdminRoles`)
- Stale accounts inactive 90+ days (`-StaleAccounts`)
- External guest account inventory (`-GuestInventory`)
- Named location definition check (`-NamedLocations`)
- High-privilege service principal inventory, Microsoft first-party excluded (`-ServicePrincipals`)

---

## Framework Mapping

| Framework | Version | Switch |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | `-NIST` |
| CIS Controls | v8.1 June 2024 | `-CIS` |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable rule | `-HIPAA` |
| HIPAA Security Rule NPRM | December 27 2024 proposed rule | `-HIPAAProposed` |
| CISA Zero Trust Maturity Model | 2023 | `-ZeroTrust` |

**Default behavior:** When no framework flag is passed, `-NIST` is applied automatically. If you pass `-HIPAA` without `-NIST`, you get HIPAA only.

### HIPAA NPRM Note

The December 2024 NPRM proposes eliminating the required/addressable distinction across all implementation specifications. Expected final rule: May 2026 with a 240-day compliance window.

Running `-HIPAA -HIPAAProposed` together produces a dual-state gap analysis. Recommended for all healthcare client engagements.

### Finding States

| State | Severity | Meaning |
|---|---|---|
| Gap | High | Control is missing or disabled |
| Partial | Medium | Control exists but not fully enforced |
| Satisfied | Pass | Control is enabled and enforced |

---

## Profiles

Profiles are predefined bundles of framework and feature flags. Use `-P` instead of typing long flag lists. Profiles are additive — pass additional flags alongside `-P` to expand.

| Profile | Syntax | Frameworks | Features Included |
|---|---|---|---|
| Quick | `-P Quick` | NIST | Exchange only, no Graph — fastest triage |
| Standard | `-P Standard` | NIST, CIS | Full Graph — general purpose assessment |
| HIPAA | `-P HIPAA` | HIPAA, HIPAAProposed | MFAReport, AdminRoles, DMARC, SharedMailboxes |
| MSP | `-P MSP` | NIST, CIS | AdminRoles, StaleAccounts, GuestInventory, DMARC, SharedMailboxes, DNSRecords |
| ZeroTrust | `-P ZeroTrust` | NIST, ZeroTrust | NamedLocations, AdminRoles, MFAReport, ServicePrincipals, StaleAccounts |
| Full | `-P Full` | All frameworks | All features |

### Why Profiles

Before:
```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed -ZeroTrust -SecureScore -MFAReport -AdminRoles -StaleAccounts -GuestInventory -NamedLocations -ServicePrincipals -DMARC -SharedMailboxes -DNSRecords
```

After:
```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full
```

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

### Token Issues

If CA or Named Locations shows `[AccessDenied]` use `-ClearToken` to force fresh consent:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -ClearToken
```

Only needed when scopes are stale or after a tool update that adds new Graph scopes.

### Delta Comparison

Delta runs automatically when a previous report exists for the same tenant. Manual override:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -Compare ".\output\ndaco-20260301.md"
```

### Portfolio Summary

```powershell
.\Invoke-NLSSummary.ps1
```

### Navigate to Tool Directory

```powershell
cd ~\Downloads\NLS-Assessment
# or right-click folder > Open in Terminal
```

---

## Security

### Module Integrity

Every run verifies all NLS modules against a SHA-256 hash manifest. If any module has been modified since the manifest was generated, the tool aborts with `MODULE INTEGRITY VIOLATION DETECTED`.

This prevents two attack vectors:
- **Path injection** — a malicious `.psm1` planted in a different directory
- **In-place tampering** — a legitimate module file modified on disk

### First Run — Generate Hash Manifest

After downloading or updating the tool, generate the baseline hash manifest before running any assessments:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest
```

This writes `Modules\modules.sha256` and exits. The manifest must match all module files before any assessment will run.

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
- `-RedactSensitiveData` scrubs UPNs, GUIDs, IPv4, IPv6, and tenant URLs from all output including the exceptions log
- Remediation scripts sanitize identity variables to prevent command injection

---

## Output

Every assessment run produces three files in `output\` named using the tenant domain and date.

| File | Example | Contents |
|---|---|---|
| `<tenant>-<date>.md` | `ndaco-20260424.md` | Full assessment report |
| `<tenant>-<date>-remediation.ps1` | `ndaco-20260424-remediation.ps1` | Ready-to-review remediation script |
| `<tenant>-<date>-exceptions.md` | `ndaco-20260424-exceptions.md` | Non-fatal collection errors |

The tenant name is extracted from the admin UPN — `admin@ndaco.org` produces `ndaco`.

Reports open automatically in VS Code after each run if VS Code is installed.

### Remediation Script

The remediation script is scoped to exactly what was found. Includes safety controls, WhatIf support, and framework citations.

```powershell
# Preview changes without applying
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org -WhatIf

# Apply with confirmation prompts
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org

# Apply without prompts
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org -Force
```

Always review the remediation script before running. Outbound spam notification requires updating the recipient address before executing.

### Report Sections (in order)

1. **Assessment Metadata** — execution time, operator, profile used, frameworks active, features active
2. **Delta Report** — comparison against previous run if available
3. **Microsoft Secure Score** — current score, top improvement opportunities (if `-SecureScore`)
4. **User MFA Status** — per-user MFA registration with admin flagging (if `-MFAReport`)
5. **Executive Summary** — Gap/Partial/Satisfied counts
6. **Collection Coverage** — status per control family with licensing gap notice
7. **Admin Role Inventory** — role table with over-privilege detection (if `-AdminRoles`)
8. **Stale Account Analysis** — inactive accounts with last sign-in (if `-StaleAccounts`)
9. **Guest Account Inventory** — external guests with stale detection (if `-GuestInventory`)
10. **Named Locations** — Zero Trust gap warning if none defined (if `-NamedLocations`)
11. **Service Principal Inventory** — high-privilege app detection (if `-ServicePrincipals`)
12. **DNS Email Record Verification** — live SPF, DMARC, DKIM values per domain (if `-DNSRecords`)
13. **DMARC Policy Status** — policy state per domain (if `-DMARC`)
14. **Shared Mailbox Hardening** — interactive sign-in and legacy protocol exposure (if `-SharedMailboxes`)
15. **Conditional Access Policy Inventory** — full policy table and missing policy checklist
16. **Findings** — grouped by severity and category with full v2 detail

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
|   |-- NLS.Exchange.psm1              # Exchange Online + DMARC + DNS + shared mailbox
|   |-- NLS.ConditionalAccess.psm1     # Graph CA, telemetry, MFA, Secure Score, inventory
|   |-- NLS.FrameworkDictionary.psm1   # 228 state-aware compliance citations (data only)
|   |-- NLS.Scoring.psm1               # Scoring engine with dedup and state comparison
|   |-- NLS.Reporting.psm1             # Markdown report with all v2 sections
|   |-- NLS.Remediation.psm1           # Remediation script generator
|   |-- NLS.Delta.psm1                 # Delta comparison and reporting
|   `-- modules.sha256                 # SHA-256 hash manifest (generated, not committed)
|
|-- output/
|   |-- ndaco-20260424.md
|   |-- ndaco-20260424-remediation.ps1
|   |-- ndaco-20260424-exceptions.md
|   `-- NLS-Portfolio-20260424.md
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

---

## Requirements

### PowerShell Version

PowerShell 7+ is required. Windows PowerShell 5.1 is not supported.

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

### Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## First Run Setup

Complete these steps in order. Run from PowerShell 7 — not Windows PowerShell.

### 1. Install PowerShell 7

```powershell
winget install Microsoft.PowerShell
```

Close and reopen. Confirm the title bar shows `pwsh`.

### 2. Install modules

```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
```

### 3. Set execution policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 4. Navigate to tool folder

```powershell
cd ~\Downloads\NLS-Assessment
```

Or right-click the folder in File Explorer and select **Open in Terminal**.

### 5. Unblock downloaded files

```powershell
Unblock-File -Path .\Invoke-NLSAssessment.ps1
Unblock-File -Path .\Invoke-NLSSummary.ps1
Unblock-File -Path .\Modules\*.psm1
```

### 6. Generate hash manifest

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest
```

This establishes the security baseline. Required before any assessment will run.

### 7. Run first assessment

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Quick
```

Quick profile — Exchange only, no Graph. Verify the tool loads and connects before running Full.

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
- Run from PowerShell 7 — Windows PowerShell 5.1 is not supported
- First Graph run against a new tenant prompts for browser consent
- Extended inventory flags add significant collection time on large tenants
- Reports open automatically in VS Code after each run if VS Code is installed
- Remediation scripts are generated every run — always review before executing
- After replacing any module file, run `-GenerateManifest` before next assessment

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

Cause: A module file has changed since the manifest was last generated. This fires after every module update — it is expected and correct behavior.

Fix:
```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -GenerateManifest
```

If the violation was not caused by a legitimate update, re-download the repo and inspect what changed.

### Conditional Access or Named Locations returns Partial (AccessDenied)

Symptom: `ConditionalAccess | Partial | [AccessDenied] : required scopes are missing in the token`

Cause: Stale cached Graph token missing one or more required scopes. Global Admin does not override a cached token.

Fix:
```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -ClearToken
```

`-ClearToken` wipes the WAM token cache and forces a fresh consent flow. Accept all permissions when the browser opens.

### Graph module assembly conflict

Symptom: `Could not load file or assembly 'Microsoft.Graph.Authentication'`

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

Close and reopen PowerShell 7.

### Defender for Office 365 Cmdlets Not Found

Symptom: `DefenderO365 | Partial | The term 'Get-SafeAttachmentPolicy' is not recognized`

Cause: Tenant does not have Defender for Office 365 Plan 1 or Plan 2. Required licenses:
- Microsoft 365 Business Premium
- Microsoft Defender for Office 365 Plan 1 or Plan 2
- Microsoft 365 E3/E5

This is a licensing gap, not a security finding. All other controls still assess correctly.

### MFA Report returns Partial

Requires `Reports.Read.All`. Use `-ClearToken` to force scope re-consent:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -ClearToken
```

### Device compliance blocking Graph consent

Symptom: `AADSTS53000: Device is not in required device state`

Options:
- Run from a compliant enrolled device
- Use `-NoGraph` for Exchange-only checks
- Exclude the admin account from the device compliance CA policy in Entra ID

### Portfolio summary shows no reports

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP
.\Invoke-NLSSummary.ps1
```

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 2.2.0 | 2026-04-24 | SHA-256 integrity, -ClearToken, -GenerateManifest, DNS records, injection hardening, redaction hardening |
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
