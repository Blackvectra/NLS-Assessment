# NLS-Assessment v2

> NextLayerSec M365 Security Assessment Framework — Version 2
> Read-only assessment instrument for Exchange Online and Entra ID.
> Maps findings to NIST SP 800-53 Rev 5, CIS Controls v8.1, HIPAA current rule,
> HIPAA NPRM proposed rule, and CISA Zero Trust Maturity Model.
> Produces structured markdown artifacts with granular finding detail,
> affected object lists, current state vs recommended comparisons,
> per-framework recommendation blocks, Secure Score integration,
> per-user MFA gap analysis, and extended tenant security inventory.

[![License](https://img.shields.io/badge/License-CC%20BY--ND%204.0-blue?style=flat-square)](https://creativecommons.org/licenses/by-nd/4.0/)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue?style=flat-square)](https://github.com/PowerShell/PowerShell)
[![Read Only](https://img.shields.io/badge/Mode-Read--Only-00c853?style=flat-square)]()
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20HIPAA%20%7C%20ZeroTrust-orange?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-2.0.0-white?style=flat-square)]()

---

## What's New in v2

| Feature | Description |
|---|---|
| Assessment profiles | `-P Quick/Standard/HIPAA/MSP/ZeroTrust/Full` — predefined flag bundles |
| Granular finding detail | Affected object lists on every count-based finding |
| Current state vs recommended | Structured comparison table per finding |
| Per-framework recommendation blocks | Each framework gets its own section with control name, detail, and requirement level |
| Flags used in report | Metadata shows exactly which frameworks and features were active |
| CA policy inventory | Full policy table with state, MFA, legacy auth, device compliance |
| Recommended CA policies | Missing policy detection against CIS M365 Benchmark |
| User MFA gap analysis | Per-user MFA registration status with admin flagging (`-MFAReport`) |
| Secure Score integration | Current score, top gaps, per-control improvement opportunities (`-SecureScore`) |
| Zero Trust flag | CISA Zero Trust Maturity Model mapping (`-ZeroTrust`) |
| Auto-open report | `-OpenReport` opens `AssessmentSummary.md` on completion |
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

`Invoke-NLSAssessment` is a precision read-only assessment instrument. It connects to Exchange Online and Microsoft Graph, collects security policy configuration and sign-in telemetry, scores findings against the NextLayerSec baseline, and produces structured markdown artifacts mapped to authoritative compliance frameworks.

**No tenant configuration changes are made at any point.**

Each finding is state-aware — returning Satisfied, Partial, or Gap — with citations mapped to the specific control that requires or recommends the configuration.

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

# Profile expanded with multiple extra flags
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -P HIPAA -ZeroTrust -SecureScore -RedactSensitiveData
```

### Manual Flags (No Profile)

Use individual flags for custom combinations:

```powershell
# NIST + CIS with DMARC only
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -DMARC

# Exchange only, HIPAA dual-state, redacted
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -HIPAA -HIPAAProposed -RedactSensitiveData
```

### Redacted Output

Pass `-RedactSensitiveData` with any profile or flag combination. Scrubs UPNs, GUIDs, IP addresses, and tenant-specific URLs from all output including the exceptions log.

### Navigate to Tool Directory

```powershell
# Option 1 -- PowerShell shorthand
cd ~\Downloads\NLS-Assessment

# Option 2 -- Right-click folder in File Explorer
# Select "Open in Terminal" -- opens PowerShell 7 in the correct directory
```

---

## Architecture

```
NLS-Assessment/
|
|-- Invoke-NLSAssessment.ps1           # Orchestrator -- run this
|
|-- Modules/
|   |-- NLS.Core.psm1                  # Output safety, coverage, exceptions, security controls
|   |-- NLS.Exchange.psm1              # Exchange Online + DMARC + shared mailbox collectors
|   |-- NLS.ConditionalAccess.psm1     # Graph CA, telemetry, MFA, Secure Score, inventory
|   |-- NLS.FrameworkDictionary.psm1   # 228 state-aware compliance citations (data only)
|   |-- NLS.Scoring.psm1               # Scoring engine with affected objects and state comparison
|   `-- NLS.Reporting.psm1             # Markdown report with all v2 sections
|
|-- output/
|   `-- <timestamp>/
|       |-- AssessmentSummary.md       # Full findings report
|       `-- Exceptions.md             # Collection exceptions log
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

v2 adds four security functions:

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
Unblock-File -Path .\Modules\*.psm1
```

---

## Output

All artifacts written to `output\` relative to the script directory.

Files are named using the tenant domain and date:

| File | Example | Contents |
|---|---|---|
| `<tenant>-<date>.md` | `ndaco-20260424.md` | Full findings report with all v2 sections |
| `<tenant>-<date>-exceptions.md` | `ndaco-20260424-exceptions.md` | Non-fatal collection errors — fully redacted when `-RedactSensitiveData` is passed |

The tenant name is extracted from the admin UPN — `admin@ndaco.org` produces `ndaco`.

### Report Sections (in order)

1. **Assessment Metadata** — execution time, operator, profile used, frameworks active, features active
2. **Microsoft Secure Score** — current score, top improvement opportunities (if `-SecureScore`)
3. **User MFA Status** — per-user MFA registration with admin flagging (if `-MFAReport`)
4. **Executive Summary** — Gap/Partial/Satisfied counts
5. **Collection Coverage** — status per control family with licensing gap notice
6. **Admin Role Inventory** — role table with over-privilege detection (if `-AdminRoles`)
7. **Stale Account Analysis** — inactive accounts with last sign-in (if `-StaleAccounts`)
8. **Guest Account Inventory** — external guests with stale detection (if `-GuestInventory`)
9. **Named Locations** — Zero Trust gap warning if none defined (if `-NamedLocations`)
10. **Service Principal Inventory** — high-privilege app detection (if `-ServicePrincipals`)
11. **DMARC Policy Status** — policy state per domain (if `-DMARC`)
12. **Shared Mailbox Hardening** — interactive sign-in and legacy protocol exposure (if `-SharedMailboxes`)
13. **Conditional Access Policy Inventory** — full policy table and missing policy checklist
14. **Findings** — grouped by severity and category with full v2 detail

### Sample v2 Finding

```markdown
### High

#### Protocols

**Disable POP3 on all mailboxes**

69 of 69 mailboxes have POP3 enabled.

  - user1@contoso.com
  - user2@contoso.com
  - user3@contoso.com

| | Value |
|---|---|
| **Current State** | Enabled on 69 mailbox(es) |
| **Recommended** | Disabled on all mailboxes |

**NIST SP 800-53 Rev 5**
- Controls: CM-7, IA-2(6)
- CM-7 requires disabling protocols not required for operation. POP3 is unnecessary in modern M365 tenants.
- Requirement level: Required

**HIPAA Security Rule (Current Enforceable)**
- Citations: §164.312(a)(2)(i), §164.312(d), §164.312(e)(1)
- POP3 authenticates with basic credentials, bypassing person authentication and transmission security.
- Requirement: Addressable

**HIPAA Security Rule (NPRM Proposed — Expected Final May 2026)**
- Citations: §164.312(a)(2)(i), §164.312(e)(1)
- Under proposed rule transmission security is mandatory. No addressable alternative pathway.
- Requirement: Required -- NPRM eliminates addressable distinction

*Remediation:* Run Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false
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
- If VS Code is not installed and `-OpenReport` is passed, the system default `.md` handler is used instead

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

Fix:
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

This is a licensing gap, not a security finding. All other controls still assess correctly.

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

### Operator shows as Unknown

Graph was not connected when metadata was collected. Run with Graph enabled or use a profile that includes Graph.

### Module integrity violation

Symptom: `MODULE INTEGRITY VIOLATION DETECTED`

A module loaded from an unexpected path. Verify the `Modules/` directory and re-download from the repo.

---

## Version History

| Version | Date | Notes |
|---|---|---|
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
