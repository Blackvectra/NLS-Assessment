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
[![Version](https://img.shields.io/badge/Version-2.1.0-white?style=flat-square)]()

---

## What's New in v2

| Feature | Description |
|---|---|
| Assessment profiles | `-P Quick/Standard/HIPAA/MSP/ZeroTrust/Full` — predefined flag bundles |
| Remediation script | Auto-generated per-tenant PowerShell remediation script every run |
| Delta reporting | Compares current run against previous — surfaces improved, regressed, new |
| Portfolio summary | `Invoke-NLSSummary.ps1` — cross-tenant view ranked by risk score |
| Granular finding detail | Affected object lists on every count-based finding |
| Current state vs recommended | Structured comparison table per finding |
| Per-framework recommendation blocks | Each framework gets its own section with control name, detail, and requirement level |
| Flags used in report | Metadata shows exactly which frameworks and features were active |
| CA policy inventory | Full policy table with state, MFA, legacy auth, device compliance |
| Recommended CA policies | Missing policy detection against CIS M365 Benchmark |
| User MFA gap analysis | Per-user MFA registration status with admin flagging (`-MFAReport`) |
| Secure Score integration | Current score, top gaps, per-control improvement opportunities (`-SecureScore`) |
| Zero Trust flag | CISA Zero Trust Maturity Model mapping (`-ZeroTrust`) |
| Auto-open report | Reports open in VS Code automatically if installed |
| Legacy auth telemetry | Accounts with active legacy auth attempts surfaced by name |
| DMARC policy check | DMARC policy state per domain via DNS (`-DMARC`) |
| Admin role inventory | Global Admin count, over-privilege detection (`-AdminRoles`) |
| Stale account detection | Accounts inactive 90+ days with last sign-in (`-StaleAccounts`) |
| Guest account inventory | External guest accounts with stale detection (`-GuestInventory`) |
| Named location check | Zero Trust gap warning if no named locations defined (`-NamedLocations`) |
| Service principal inventory | High-privilege app detection (`-ServicePrincipals`) |
| Shared mailbox hardening | Interactive sign-in and legacy protocol check (`-SharedMailboxes`) |
| Custom help output | `.\Invoke-NLSAssessment.ps1 --help` |
| Security hardening | UPN input validation, module integrity check, output path locking, exceptions redaction fix |

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
- DNSSEC status per domain — with disabled domain list

### Exchange Online (Optional Flags)
- DMARC policy state per domain via DNS (`-DMARC`)
- Shared mailbox hardening — interactive sign-in and legacy protocols (`-SharedMailboxes`)

### Conditional Access (Microsoft Graph — Standard)
- Full CA policy inventory — state, MFA grant, legacy auth block, device compliance
- Missing recommended policy detection
- MFA enforcement as a grant control
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
- High-privilege service principal inventory (`-ServicePrincipals`)

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
| MSP | `-P MSP` | NIST, CIS | AdminRoles, StaleAccounts, GuestInventory, DMARC, SharedMailboxes |
| ZeroTrust | `-P ZeroTrust` | NIST, ZeroTrust | NamedLocations, AdminRoles, MFAReport, ServicePrincipals, StaleAccounts |
| Full | `-P Full` | All frameworks | All features |

Profiles are additive — extra flags passed alongside `-P` expand the profile.

### Why Profiles

Before:
```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed -ZeroTrust -SecureScore -MFAReport -AdminRoles -StaleAccounts -GuestInventory -NamedLocations -ServicePrincipals -DMARC -SharedMailboxes
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

Displays branded help with the full profile table, all flags, examples, permissions, and troubleshooting.

### Profile Examples

```powershell
# Quick triage -- Exchange only, no Graph
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Quick

# General purpose assessment
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Standard

# MSP tenant assessment
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP

# Healthcare client -- dual-state HIPAA, redacted output
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P HIPAA -RedactSensitiveData

# Zero Trust posture assessment
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P ZeroTrust

# Full assessment -- everything, redacted
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P Full -RedactSensitiveData

# Profile expanded with extra flag
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -SecureScore -OpenReport
```

### Manual Flags (No Profile)

```powershell
# NIST + CIS with DMARC only
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -DMARC

# Exchange only, HIPAA dual-state, redacted
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -HIPAA -HIPAAProposed -RedactSensitiveData
```

### Delta Comparison

Delta runs automatically when a previous report exists for the same tenant in the output folder. To manually specify a previous report:

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -Compare ".\output\ndaco-20260301.md"
```

### Portfolio Summary

Run after completing assessments across multiple tenants:

```powershell
.\Invoke-NLSSummary.ps1
```

Reads all reports in `output\`, ranks tenants by risk score, produces `NLS-Portfolio-<date>.md` and opens it in VS Code.

### Navigate to Tool Directory

```powershell
# Option 1 -- PowerShell shorthand
cd ~\Downloads\NLS-Assessment

# Option 2 -- Right-click folder in File Explorer
# Select "Open in Terminal" -- opens PowerShell 7 in the correct directory
```

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

The remediation script is scoped to exactly what was found in the assessment. It includes safety controls, confirmation prompts, and inline framework citations.

```powershell
# Preview changes without applying
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org -WhatIf

# Apply with confirmation prompts
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org

# Apply without prompts
.\ndaco-20260424-remediation.ps1 -UserPrincipalName admin@ndaco.org -Force
```

**Always review the remediation script before running.** Controls that require portal action (CA policies, Safe Links) are flagged with portal links rather than commands.

### Delta Report

When a previous report exists for the same tenant, the report includes a delta section:

```markdown
## Delta Report

Comparison against previous report: ndaco-20260301.md

| Category    | Count |
|-------------|:-----:|
| Improved    | 4     |
| Regressed   | 1     |
| Unchanged   | 12    |
| New Findings| 0     |

### Improved
| Control                              | Previous | Current   |
|--------------------------------------|:--------:|:---------:|
| Disable SMTP client authentication   | Gap      | Satisfied |
| Disable POP3 on all mailboxes        | Gap      | Satisfied |

### Regressed
> **Action required. Controls that previously passed have regressed.**

| Control                | Previous  | Current |
|------------------------|:---------:|:-------:|
| Enable outbound spam   | Satisfied | Gap     |
```

### Portfolio Summary

```markdown
## Tenant Rankings

| Rank | Tenant     | Risk Score | Gap | Partial | Satisfied | Total | Last Assessment |
|:----:|------------|:----------:|:---:|:-------:|:---------:|:-----:|-----------------|
| 1    | NDACO      | 🔴 20      | 10  | 2       | 8         | 20    | 2026-04-24      |
| 2    | DUNNCOUNTY | 🟡 8       | 4   | 3       | 3         | 10    | 2026-04-24      |
| 3    | CORNERPOST | 🟢 4       | 2   | 2       | 9         | 13    | 2026-04-24      |
```

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
12. **DMARC Policy Status** — policy state per domain (if `-DMARC`)
13. **Shared Mailbox Hardening** — interactive sign-in and legacy protocol exposure (if `-SharedMailboxes`)
14. **Conditional Access Policy Inventory** — full policy table and missing policy checklist
15. **Findings** — grouped by severity and category with full v2 detail

---

## Architecture

```
NLS-Assessment/
|
|-- Invoke-NLSAssessment.ps1           # Orchestrator -- run this
|-- Invoke-NLSSummary.ps1              # Portfolio summary across all tenants
|
|-- Modules/
|   |-- NLS.Core.psm1                  # Output safety, coverage, exceptions, security controls
|   |-- NLS.Exchange.psm1              # Exchange Online + DMARC + shared mailbox collectors
|   |-- NLS.ConditionalAccess.psm1     # Graph CA, telemetry, MFA, Secure Score, inventory
|   |-- NLS.FrameworkDictionary.psm1   # 228 state-aware compliance citations (data only)
|   |-- NLS.Scoring.psm1               # Scoring engine with affected objects and state comparison
|   |-- NLS.Reporting.psm1             # Markdown report with all v2 sections
|   |-- NLS.Remediation.psm1           # Remediation script generator
|   `-- NLS.Delta.psm1                 # Delta comparison and reporting
|
|-- output/
|   |-- ndaco-20260424.md
|   |-- ndaco-20260424-remediation.ps1
|   |-- ndaco-20260424-exceptions.md
|   |-- dunncounty-20260424.md
|   |-- dunncounty-20260424-remediation.ps1
|   `-- NLS-Portfolio-20260424.md
|
|-- README.md
`-- .gitignore
```

### Data and Logic Separation

`NLS.FrameworkDictionary.psm1` contains only compliance mapping data. When a framework releases a new version, only this file changes.

Update procedure:
1. Open `NLS.FrameworkDictionary.psm1`
2. Find affected ControlId entries
3. Update Citation, Detail, and Requirement fields
4. Update `DictionaryVersion` at bottom of file
5. Commit and tag release

### Security Controls in NLS.Core

- `Test-NLSInputUPN` — validates UPN format before passing to connection cmdlets
- `Test-NLSModuleIntegrity` — verifies all NLS modules loaded from expected path, aborts on violation
- `Protect-NLSOutputPath` — locks output directory permissions to current user
- `Protect-NLSExceptionsRedaction` — applies full redaction to exceptions log when `-RedactSensitiveData` is passed

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
| `Directory.Read.All` | Graph directory access, admin roles, guest inventory, service principals |
| `AuditLog.Read.All` | Sign-in log telemetry, stale accounts |
| `Reports.Read.All` | User MFA registration status (`-MFAReport`) |
| `SecurityEvents.Read.All` | Secure Score (`-SecureScore`) |

### Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## First Run Setup

Files downloaded from GitHub are marked untrusted by Windows. Run once after downloading:

```powershell
Unblock-File -Path .\Invoke-NLSAssessment.ps1
Unblock-File -Path .\Invoke-NLSSummary.ps1
Unblock-File -Path .\Modules\*.psm1
```

---

## Coverage Map

| Status | Meaning |
|---|---|
| Collected | Data retrieved and scored successfully |
| Partial | Data retrieved but incomplete — permissions or licensing gap |
| NotCollected | Operator did not pass the required flag |
| Unsupported | Tenant licensing does not support this control |

**Licensing gap notice:** When controls return Partial due to missing licenses (e.g. Defender for Office 365 cmdlets not found), the report includes a licensing note. This is a licensing issue, not a security finding.

---

## Operational Notes

- Always run from a dedicated admin account
- Use `-RedactSensitiveData` for any artifacts leaving your workstation
- The `output\` directory is gitignored — do not commit assessment artifacts
- Run from PowerShell 7 — Windows PowerShell 5.1 is not supported
- First Graph run against a new tenant prompts for browser consent
- Extended inventory flags add significant collection time on large tenants
- Reports open automatically in VS Code after each run if VS Code is installed
- Remediation scripts are generated every run — review before executing
- Run `Invoke-NLSSummary.ps1` after assessing multiple tenants for the portfolio view

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
Get-ExecutionPolicy -Scope CurrentUser
# Should return: RemoteSigned
```

### Graph module assembly conflict

Symptom: `Could not load file or assembly 'Microsoft.Graph.Authentication'`

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

Close PowerShell and reopen in a fresh PowerShell 7 session.

### Conditional Access returns Partial

Symptom: `ConditionalAccess | Partial | One or more errors occurred`

```powershell
Get-Command Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

### Conditional Access Partial on Global Admin Account

Symptom: `ConditionalAccess | Partial | [AccessDenied] : required scopes are missing in the token`

Cause: Stale cached Graph token missing `Policy.Read.ConditionalAccess`. Global Admin does not override a cached token.

```powershell
Disconnect-MgGraph -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\.mg" -Recurse -Force -ErrorAction SilentlyContinue
```

Rerun — browser will prompt for fresh consent. Accept all permissions.

### Defender for Office 365 Cmdlets Not Found

Symptom: `DefenderO365 | Partial | The term 'Get-SafeAttachmentPolicy' is not recognized`

Cause: Tenant does not have Defender for Office 365 Plan 1 or Plan 2. Required licenses:
- Microsoft 365 Business Premium
- Microsoft Defender for Office 365 Plan 1 or Plan 2
- Microsoft 365 E3/E5

This is a licensing gap, not a security finding.

### MFA Report returns Partial

Requires `Reports.Read.All`. Disconnect and reconnect:

```powershell
Disconnect-MgGraph
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP -MFAReport
```

### Secure Score returns Partial

Requires `SecurityEvents.Read.All`. Disconnect and reconnect to force re-consent.

### Device compliance blocking Graph consent

Symptom: `AADSTS53000: Device is not in required device state`

Options:
- Run from a compliant enrolled device
- Use `-NoGraph` to skip Graph and run Exchange checks only
- Exclude the admin account from the device compliance CA policy in Entra ID

### Portfolio summary shows no reports

Symptom: `No tenant reports found in: .\output`

Run at least one assessment first:
```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P MSP
.\Invoke-NLSSummary.ps1
```

### Module integrity violation

Symptom: `MODULE INTEGRITY VIOLATION DETECTED`

A module loaded from an unexpected path. Verify the `Modules\` directory and re-download from the repo.

---

## Version History

| Version | Date | Notes |
|---|---|---|
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
