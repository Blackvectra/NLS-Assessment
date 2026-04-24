# NextLayerSec M365 Assessment Framework

> Read-only M365 security assessment instrument for Exchange Online and Entra ID.
> Maps findings to NIST SP 800-53 Rev 5, CIS Controls v8.1, HIPAA current rule,
> and HIPAA NPRM proposed rule with state-aware citations.
> Designed for MSP and consulting engagements against M365 Business Premium tenants.

[![License](https://img.shields.io/badge/License-CC%20BY--ND%204.0-blue?style=flat-square)](https://creativecommons.org/licenses/by-nd/4.0/)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue?style=flat-square)](https://github.com/PowerShell/PowerShell)
[![Read Only](https://img.shields.io/badge/Mode-Read--Only-00c853?style=flat-square)]()
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20HIPAA-orange?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-white?style=flat-square)]()

---

## Overview

`Invoke-NLSAssessment` is a precision read-only assessment instrument. It connects to Exchange Online and Microsoft Graph, collects security policy configuration and sign-in telemetry, scores findings against the NextLayerSec baseline, and produces structured markdown artifacts mapped to authoritative compliance frameworks.

**No tenant configuration changes are made at any point.**

Each finding is state-aware — returning Satisfied, Partial, or Gap — with citations mapped to the specific control that requires or recommends the configuration. This produces a deliverable suitable for client reporting, audit evidence, and compliance gap analysis.

---

## What It Checks

### Exchange Online
- Legacy authentication policy configuration and org default assignment
- SMTP client authentication status
- External auto-forwarding controls
- Mailbox protocol hardening (POP, IMAP)
- Mailbox auditing and unified audit log status
- Outbound spam notification
- Defender for Office 365 (Safe Attachments, Safe Links, Anti-Phishing, ZAP, ATP)
- DKIM signing configuration per domain
- DNSSEC status per domain

### Conditional Access (Microsoft Graph)
- All CA policy states — enabled, report-only, disabled
- MFA enforcement as a grant control
- Legacy authentication blocking
- Report-only policy detection
- Sign-in log telemetry — legacy auth attempts, MFA challenge rate, failures (Full mode)

---

## Framework Mapping

Each finding is mapped across up to four compliance frameworks depending on operator switches passed at runtime.

| Framework | Version | Switch |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | `-NIST` |
| CIS Controls | v8.1 June 2024 | `-CIS` |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable rule | `-HIPAA` |
| HIPAA Security Rule NPRM | December 27 2024 proposed rule | `-HIPAAProposed` |

### HIPAA NPRM Note

The December 2024 NPRM proposes eliminating the required/addressable distinction across all implementation specifications. Expected final rule: May 2026 with a 240-day compliance window.

Running `-HIPAA -HIPAAProposed` together produces a dual-state gap analysis showing current compliance posture alongside exposure against the incoming mandatory standard. This is the recommended configuration for healthcare client engagements.

### Finding States

Each control returns one of three states:

| State | Meaning |
|---|---|
| Satisfied | Control is enabled and enforced. Citation shows what is satisfied. |
| Partial | Control exists but is not fully enforced. Citation shows what is not yet met. |
| Gap | Control is missing or disabled. Citation shows what is required. |

---

## Architecture

```
nextlayersec-assessment/
|
|-- Invoke-NLSAssessment.ps1           # Orchestrator -- run this
|
|-- Modules/
|   |-- NLS.Core.psm1                  # Output safety, coverage tracking, exceptions
|   |-- NLS.Exchange.psm1              # Exchange Online collector
|   |-- NLS.ConditionalAccess.psm1     # Graph CA policy + telemetry collector
|   |-- NLS.FrameworkDictionary.psm1   # 228 state-aware compliance citations (data only)
|   |-- NLS.Scoring.psm1               # Scoring engine (logic only, imports dictionary)
|   `-- NLS.Reporting.psm1             # Markdown report generation
|
|-- output/
|   `-- <timestamp>/
|       |-- AssessmentSummary.md       # Full findings report with framework citations
|       `-- Exceptions.md             # Collection exceptions log
|
|-- README.md
`-- .gitignore
```

### Data and Logic Separation

`NLS.FrameworkDictionary.psm1` contains only compliance mapping data — no execution logic. When a framework releases a new version, only this file changes. The scoring engine, orchestrator, and reporting module are untouched.

Update procedure when framework versions change:
1. Open `NLS.FrameworkDictionary.psm1`
2. Find affected ControlId entries
3. Update Citation, Detail, and Requirement fields
4. Update `DictionaryVersion` at bottom of file
5. Commit and tag release

---

## Requirements

### Recommended PowerShell Version

PowerShell 7+ is strongly recommended. Windows PowerShell 5.1 may experience Graph SDK module assembly conflicts that cause collection failures.

Install PowerShell 7:
```powershell
winget install Microsoft.PowerShell
```

Always run the script from a PowerShell 7 session.

### Modules

```powershell
# Required for all modes
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force

# The full Graph SDK installs all required submodules including:
# Microsoft.Graph.Authentication
# Microsoft.Graph.Identity.SignIns
```

### Permissions

| Scope | Required For |
|---|---|
| Exchange Admin or Global Admin | Exchange Online collection |
| `Policy.Read.ConditionalAccess` | CA policy collection |
| `Directory.Read.All` | Graph directory access |
| `AuditLog.Read.All` | Sign-in log telemetry (Full mode only) |

### Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Verify:
```powershell
Get-ExecutionPolicy -Scope CurrentUser
# Should return: RemoteSigned
```

---

## First Run Setup

Files downloaded from GitHub are marked untrusted by Windows and will be blocked from running even with the correct execution policy set. Run these commands once after downloading:

```powershell
Unblock-File -Path .\Invoke-NLSAssessment.ps1
Unblock-File -Path .\Modules\*.psm1
```

You only need to do this once after the initial download. If you pull updates from GitHub and new module files are added, run the Unblock-File commands again.

---

## Usage

### Exchange Only — No Graph Setup Required

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph
```

Runs all Exchange Online checks. No Graph modules required. No browser consent prompt. Recommended for initial triage and quick tenant assessments.

### Full Assessment

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com
```

Runs all checks including Conditional Access policies and sign-in log telemetry. Browser will open for Microsoft Graph consent on first run against each tenant.

### NIST Assessment

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -NIST
```

NIST SP 800-53 Rev 5 citations included in all findings. Default framework when no flag is passed.

### HIPAA Engagement — Dual State Gap Analysis

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -HIPAA -HIPAAProposed -RedactSensitiveData
```

Produces findings mapped to both the current enforceable HIPAA Security Rule and the incoming NPRM proposed rule. Recommended for all healthcare client engagements.

### Full Framework Stack

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed
```

All four frameworks included in every finding.

### Quick Mode

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -Quick
```

Skips sign-in log telemetry. Faster run. No `AuditLog.Read.All` required.

### Redacted Output

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -RedactSensitiveData
```

Scrubs UPNs, GUIDs, and IP addresses from all output files before writing to disk. Use for any artifacts leaving your workstation or shared with clients.

### Skip Connection

```powershell
.\Invoke-NLSAssessment.ps1 -SkipConnect
```

Skips connection step if already connected to Exchange Online and Graph.

---

## Output

All artifacts written to `output\<timestamp>\` relative to the script directory.

| File | Contents |
|---|---|
| `AssessmentSummary.md` | Full findings report with state, severity, framework citations, and remediation |
| `Exceptions.md` | Non-fatal collection errors — permissions gaps, licensing limits, API failures |

### Sample Finding Output

```markdown
### High

#### Transport

**Disable SMTP client authentication tenant-wide**

SMTP client authentication is enabled. Legacy relay and credential exposure risk.

> *Frameworks: **NIST:** CM-7, SC-8, IA-3 | **CIS:** 4.8, 9.2 | **HIPAA (Current):** §164.312(e)(1), §164.312(e)(2)(ii) | **HIPAA (Proposed):** §164.312(e)(1), §164.312(e)(2)(ii)*

*Remediation:* Run Set-TransportConfig -SmtpClientAuthenticationDisabled $true
```

---

## Coverage Map

The assessment summary includes a coverage map distinguishing between:

| Status | Meaning |
|---|---|
| Collected | Data retrieved and scored successfully |
| Partial | Data retrieved but incomplete — permissions or licensing gap |
| NotCollected | Operator skipped via `-Quick`, `-NoTelemetry`, or `-NoGraph` |
| Unsupported | Tenant licensing does not support this control |

**Missing telemetry is not equivalent to a missing policy.** The exceptions log documents all collection failures with source, message, and error detail.

---

## Operational Notes

- Always run from a dedicated admin account — not your primary user account
- Use `-RedactSensitiveData` for any artifacts leaving your workstation
- The `output\` directory is gitignored — do not commit assessment artifacts
- Run `-NoGraph -Quick` for initial triage. Run full mode for formal engagement documentation
- First run against a new tenant will prompt for Graph consent in a browser window
- Run from PowerShell 7 to avoid Graph SDK module version conflicts

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
Get-ExecutionPolicy -Scope CurrentUser
# Should return: RemoteSigned
```

### Graph module assembly conflict

Symptom: `Could not load file or assembly 'Microsoft.Graph.Authentication'`

Cause: Multiple versions of Graph modules installed. PowerShell loaded an older cached version.

Fix:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

Close PowerShell completely and reopen in a fresh PowerShell 7 session before running again.

### Conditional Access returns Partial

Symptom: `ConditionalAccess | Partial | One or more errors occurred`

Check the cmdlet is available:
```powershell
Get-Command Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
```

If it returns nothing or an old version:
```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
```

Close PowerShell and reopen in a fresh session.

### Device compliance blocking Graph consent

Symptom: Browser opens with `AADSTS53000: Device is not in required device state`

Cause: Conditional Access policy requires a compliant device. The machine running the script is not Intune enrolled.

Options:
- Run from a compliant enrolled device
- Use `-NoGraph` flag to skip Graph entirely and run Exchange checks only
- Exclude the admin account from the device compliance CA policy in Entra ID

### Operator shows as Unknown in report

Cause: Graph was not connected when metadata was collected. Use Graph mode or the operator field will not populate from the Graph context.

### Module version conflict on Windows PowerShell 5.1

Switch to PowerShell 7. The Graph SDK officially recommends PowerShell 7 for best compatibility.

```powershell
winget install Microsoft.PowerShell
```

Install all modules fresh in the PowerShell 7 session after installing.

---

## Version 2 Roadmap

The following features are planned for v2.0.0 and are not yet implemented.

### Zero Trust Assessment Flag

Add `-ZeroTrust` flag that maps findings to the CISA Zero Trust Maturity Model pillars and maturity levels.

New checks added in ZT mode:
- Break-glass account detection and sign-in monitoring validation
- Privileged Identity Management — permanent vs JIT eligible admin role assignments
- Named locations defined — is network trust explicitly defined or implicit
- Device compliance CA policy — is compliant device required as a grant control
- CA report-only policy count — how many policies are monitoring but not enforcing
- Session controls — sign-in frequency and persistent browser session configuration
- Mailbox audit retention — is 180-day retention enforced across all mailboxes

ZT maturity levels per finding:
- **Traditional** — control absent, no Zero Trust posture
- **Initial** — control partially implemented
- **Advanced** — control enforced with monitoring
- **Optimal** — control enforced, automated, and continuously validated

Report format:
```
> *Frameworks: **NIST:** AC-3 | **ZT Pillar:** Identity | **ZT Maturity:** Initial → Advanced*
```

### Auto-Open Report

Add `-OpenReport` flag to automatically open `AssessmentSummary.md` on completion. Default handler will be VS Code if installed, otherwise system default for `.md` files.

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -OpenReport
```

### Granular Finding Detail

Currently findings report counts only:
```
5 mailbox(es) have auditing disabled.
```

v2 will include the specific affected objects inline:
```
5 mailbox(es) have auditing disabled:
  - user1@contoso.com
  - user2@contoso.com
  - user3@contoso.com
  - user4@contoso.com
  - user5@contoso.com
```

Applies to all controls that return counts:
- Mailbox auditing disabled
- POP3 enabled mailboxes
- IMAP enabled mailboxes
- Mailboxes with active forwarding
- DKIM disabled domains
- DNSSEC disabled domains

### Current State vs Recommended View

Every finding will include a structured comparison table:

```
Control:        SMTP Client Authentication
Current State:  Enabled
Recommended:    Disabled
Standard:       CIS M365 Benchmark 1.1.1
Risk:           Legacy relay vector, credential exposure, MFA bypass
Action:         Set-TransportConfig -SmtpClientAuthenticationDisabled $true
```

This turns the report into a remediation workplan where every row is an actionable ticket.

### Additional Framework Support

- `-ZeroTrust` — CISA Zero Trust Maturity Model (Identity and Devices pillars)
- `-CISBenchmark` — CIS Microsoft 365 Foundations Benchmark (M365-specific controls)
- `-SOC2` — SOC 2 Type II control mapping (CC6 Logical Access, CC7 System Operations)
- `-CMMC` — CMMC Level 2 mapping for defense contractors handling CUI
- `-FTCSafeguards` — FTC Safeguards Rule for financial institutions and covered businesses

### Conditional Access Deep Dive

Currently CA collection returns policy state and MFA enforcement status. v2 will add:
- Named location inventory and review
- Excluded user and group enumeration
- Break-glass account detection and validation
- PIM role assignment status per admin role

### Scheduled Assessment Mode

Run assessments on a defined cadence and compare results against previous runs. Delta reporting to surface new gaps or regressions since the last assessment.

---

## Related

- [nextlayersec-email-security](https://github.com/Blackvectra/nextlayersec-email-security) -- Full email security stack documentation, deployment guides, and DNS record templates

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
