# NLS-Assessment v2

> NextLayerSec M365 Security Assessment Framework — Version 2
> Read-only assessment instrument for Exchange Online and Entra ID.
> Maps findings to NIST SP 800-53 Rev 5, CIS Controls v8.1, HIPAA current rule,
> HIPAA NPRM proposed rule, and CISA Zero Trust Maturity Model.
> Produces structured markdown artifacts with granular finding detail,
> affected object lists, current state vs recommended comparisons,
> Secure Score integration, and per-user MFA gap analysis.

[![License](https://img.shields.io/badge/License-CC%20BY--ND%204.0-blue?style=flat-square)](https://creativecommons.org/licenses/by-nd/4.0/)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue?style=flat-square)](https://github.com/PowerShell/PowerShell)
[![Read Only](https://img.shields.io/badge/Mode-Read--Only-00c853?style=flat-square)]()
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20HIPAA%20%7C%20ZeroTrust-orange?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-2.0.0-white?style=flat-square)]()

---

## What's New in v2

| Feature | Description |
|---|---|
| Granular finding detail | Affected object lists on every count-based finding |
| Current state vs recommended | Structured comparison table per finding |
| CA policy inventory | Full policy table with state, MFA, legacy auth, device compliance |
| Recommended CA policies | Missing policy detection against CIS M365 Benchmark |
| User MFA gap analysis | Per-user MFA registration status with admin flagging |
| Secure Score integration | Current score, top gaps, per-control improvement opportunities |
| Zero Trust flag | CISA Zero Trust Maturity Model mapping via `-ZeroTrust` |
| Auto-open report | `-OpenReport` opens `AssessmentSummary.md` on completion |
| Legacy auth telemetry | Accounts with active legacy auth attempts surfaced by name |

---

## Overview

`Invoke-NLSAssessment` is a precision read-only assessment instrument. It connects to Exchange Online and Microsoft Graph, collects security policy configuration and sign-in telemetry, scores findings against the NextLayerSec baseline, and produces structured markdown artifacts mapped to authoritative compliance frameworks.

**No tenant configuration changes are made at any point.**

Each finding is state-aware — returning Satisfied, Partial, or Gap — with citations mapped to the specific control that requires or recommends the configuration. v2 adds affected object lists, current state vs recommended comparisons, and extended data sections for Secure Score and user MFA status.

---

## What It Checks

### Exchange Online
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

### Conditional Access (Microsoft Graph)
- Full CA policy inventory — state, MFA grant, legacy auth block, device compliance
- Missing recommended policy detection
- MFA enforcement as a grant control
- Legacy authentication blocking
- Report-only policy detection
- Sign-in log telemetry — legacy auth attempts by account, MFA challenge rate, failures

### Extended Data (Graph — optional flags)
- Per-user MFA registration status (`-MFAReport`)
- Admin accounts without MFA registered
- Microsoft Secure Score current and max (`-SecureScore`)
- Top 10 improvement opportunities by score impact
- Per-control implementation status

---

## Framework Mapping

| Framework | Version | Switch |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | `-NIST` |
| CIS Controls | v8.1 June 2024 | `-CIS` |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable rule | `-HIPAA` |
| HIPAA Security Rule NPRM | December 27 2024 proposed rule | `-HIPAAProposed` |
| CISA Zero Trust Maturity Model | 2023 | `-ZeroTrust` |

### HIPAA NPRM Note

The December 2024 NPRM proposes eliminating the required/addressable distinction across all implementation specifications. Expected final rule: May 2026 with a 240-day compliance window.

Running `-HIPAA -HIPAAProposed` together produces a dual-state gap analysis showing current compliance posture alongside exposure against the incoming mandatory standard.

### Finding States

| State | Severity | Meaning |
|---|---|---|
| Gap | High | Control is missing or disabled |
| Partial | Medium | Control exists but not fully enforced |
| Satisfied | Pass | Control is enabled and enforced |

---

## Architecture

```
NLS-Assessment/
|
|-- Invoke-NLSAssessment.ps1           # Orchestrator -- run this
|
|-- Modules/
|   |-- NLS.Core.psm1                  # Output safety, coverage tracking, exceptions
|   |-- NLS.Exchange.psm1              # Exchange Online collector (v2 granular lists)
|   |-- NLS.ConditionalAccess.psm1     # Graph CA, telemetry, MFA status, Secure Score
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

---

## Requirements

### PowerShell Version

PowerShell 7+ is required. v2 uses `#Requires -Version 7.0`. Windows PowerShell 5.1 is not supported.

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
| `Directory.Read.All` | Graph directory access |
| `AuditLog.Read.All` | Sign-in log telemetry (Full mode) |
| `Reports.Read.All` | User MFA registration status (`-MFAReport`) |
| `SecurityEvents.Read.All` | Secure Score (`-SecureScore`) |

### Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## First Run Setup

```powershell
Unblock-File -Path .\Invoke-NLSAssessment.ps1
Unblock-File -Path .\Modules\*.psm1
```

Run once after downloading. Repeat if new module files are added.

---

## Usage

### Exchange Only — Quick Triage

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -NIST
```

### Full Assessment — All Frameworks

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed
```

### HIPAA Engagement — Dual State Gap Analysis

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -HIPAA -HIPAAProposed -RedactSensitiveData
```

### Full v2 Stack — All Features

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed -ZeroTrust -SecureScore -MFAReport
```

### Healthcare Client — Full Engagement

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -HIPAA -HIPAAProposed -SecureScore -MFAReport -RedactSensitiveData
```

### Auto-Open Report on Completion

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -OpenReport
```

### Quick Mode — Skip Telemetry

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -Quick -NIST
```

### Redacted Output

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -RedactSensitiveData
```

---

## Output

All artifacts written to `output\<timestamp>\` relative to the script directory.

| File | Contents |
|---|---|
| `AssessmentSummary.md` | Full findings report with all v2 sections |
| `Exceptions.md` | Non-fatal collection errors |

### Report Sections

The v2 report includes the following sections in order:

1. **Assessment Metadata** — execution time, operator, module versions
2. **Microsoft Secure Score** — current score, top improvement opportunities (if `-SecureScore`)
3. **User MFA Status** — per-user MFA registration table (if `-MFAReport`)
4. **Executive Summary** — Gap/Partial/Satisfied counts
5. **Collection Coverage** — status per control family
6. **Conditional Access Policy Inventory** — full policy table and missing policy checklist
7. **Findings** — grouped by severity and category with full v2 detail

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

> *Frameworks: **NIST:** CM-7, IA-2(6) | **CIS:** 4.8 | **HIPAA (Current):** §164.312(a)(2)(i), §164.312(d), §164.312(e)(1)*

*Remediation:* Run Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false
```

### Sample CA Policy Inventory

```markdown
## Conditional Access Policy Inventory

| Policy Name           | State       | MFA Grant | Legacy Auth Block | Device Compliance |
|-----------------------|-------------|-----------|-------------------|-------------------|
| Block Legacy Auth     | enabled     | No        | Yes               | No                |
| Require MFA All Users | reportOnly  | Yes       | No                | No                |

### Recommended Policies Not Found

- [ ] Require MFA for all users -- all cloud apps
- [ ] Require compliant device for corporate resources
- [ ] Block access for high sign-in risk (Entra ID Protection)
- [ ] Require phishing-resistant MFA for privileged admin roles
```

---

## Coverage Map

| Status | Meaning |
|---|---|
| Collected | Data retrieved and scored successfully |
| Partial | Data retrieved but incomplete |
| NotCollected | Operator skipped via flag |
| Unsupported | Tenant licensing does not support this control |

---

## Operational Notes

- Always run from a dedicated admin account
- Use `-RedactSensitiveData` for any artifacts leaving your workstation
- The `output\` directory is gitignored — do not commit assessment artifacts
- Run from PowerShell 7 — Windows PowerShell 5.1 is not supported in v2
- First Graph run against a new tenant prompts for browser consent
- `-MFAReport` and `-SecureScore` require additional Graph scopes and will prompt for consent

---

## Framework Dictionary Versions

| Framework | Version Mapped | Last Updated |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | 2026-04-23 |
| CIS Controls | v8.1 June 2024 | 2026-04-23 |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable | 2026-04-23 |
| HIPAA NPRM | December 27 2024 proposed rule | 2026-04-23 |

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
```

### Graph module assembly conflict

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

Close PowerShell and reopen in a fresh PowerShell 7 session.

### Conditional Access returns Partial

```powershell
Get-Command Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
```

If missing:
```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

### MFA Report returns Partial

Symptom: `UserMFAStatus | Partial | Requires Reports.Read.All scope`

The `-MFAReport` flag requires `Reports.Read.All`. Ensure the admin account consents to this scope when the browser opens. If the scope was not included in a previous consent, disconnect Graph and reconnect:

```powershell
Disconnect-MgGraph
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -MFAReport
```

### Secure Score returns Partial

Symptom: `SecureScore | Partial`

The `-SecureScore` flag requires `SecurityEvents.Read.All`. Ensure the admin account consents to this scope when the browser opens.

### Device compliance blocking Graph consent

Symptom: `AADSTS53000: Device is not in required device state`

Options:
- Run from a compliant enrolled device
- Use `-NoGraph` to skip Graph and run Exchange checks only
- Exclude the admin account from the device compliance CA policy in Entra ID

### Operator shows as Unknown

Graph was not connected when metadata was collected. Run with Graph enabled.

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 2.0.0 | 2026-04-24 | Full v2 build — granular detail, CA inventory, MFA report, Secure Score, Zero Trust |
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
