# NLS-Assessment Tool — Claude Code Project Context

**Author:** NextLayerSec — nextlayersec.io
**GitHub:** https://github.com/Blackvectra/NLS-Assessment
**Version:** 4.6.5
**Language:** PowerShell 7.0+
**Purpose:** Read-only Microsoft 365 security assessment framework for MSP multi-tenant environments.

## What This Tool Does

NLS-Assessment runs agentlessly against any Microsoft 365 tenant, collects security configuration data via Microsoft Graph and Exchange Online PowerShell, evaluates 195 controls against a license-aware baseline, and produces an interactive HTML report with executive summary, compliance matrix, attack scenario analysis, and NLS services pitch. It is a read-only assessment — it never modifies tenant configuration.

There are two entry points. `Invoke-NLSAssessment.ps1` runs against a single tenant interactively. `Invoke-NLSBatchAssessment.ps1` runs against all clients defined in `Config/clients.json` sequentially using GDAP delegated access, producing per-client reports and a batch summary.

## Project Structure

`NLS-Assessment-Tool/` contains `Invoke-NLSAssessment.ps1` (single-tenant entry point), `Invoke-NLSBatchAssessment.ps1` (multi-tenant batch entry point), `NLS-Assessment.psm1` (module loader that dot-sources all subdirectories recursively), and `NLS-Assessment.psd1` (module manifest).

`Lib/` contains `Add-NLSFinding.ps1` (state management: findings, raw data, coverage, Clear-NLSState), `Connect-NLSServices.ps1` (Graph + EXO + Teams + IPPSSession connection logic), and `Get-NLSBaselineTier.ps1` (license detection and baseline compliance functions).

`Collectors/` contains one file per workload and is recursively loaded by the psm1. `AAD/` contains `Invoke-NLSCollectAADInventory.ps1` (sets `AAD-Inventory`), `Invoke-NLSCollectAADUsers.ps1` (sets `AAD-Users`), `Invoke-NLSCollectAADAuthPolicies.ps1` (sets `AAD-AuthPolicies` and `AAD-CAPolicies`), `Invoke-NLSCollectAADCAPolicies.ps1` (wrapper to AuthPolicies), `Invoke-NLSCollectAADRoles.ps1` (sets `AAD-DirectoryRoles`, `AAD-PIMSchedules`, `AAD-IdentityGovernance`), `Invoke-NLSCollectAADPIM.ps1` (wrapper to Roles), and `Invoke-NLSCollectAADIdentityGovernance.ps1` (wrapper to Roles). `EXO/` contains `Invoke-NLSCollectEXOMailboxConfig.ps1` (sets `EXO-MailboxConfig`) and `Invoke-NLSCollectEXOConnectionFilter.ps1` (sets `EXO-ConnectionFilter`). `Defender/` contains `Invoke-NLSCollectDefender.ps1` (sets `Defender-Policies`). `DNS/` contains `Invoke-NLSCollectDNSEmailRecords.ps1` (sets `DNS-domain` and `DNS-Summary`). `Teams/` contains `Invoke-NLSCollectTeams.ps1` (sets `Teams`). `SharePoint/` contains `Invoke-NLSCollectSharePoint.ps1` (sets `SharePoint`). `Intune/` contains `Invoke-NLSCollectIntune.ps1` (sets `Intune`). `Purview/` contains `Invoke-NLSCollectPurview.ps1` (sets `Purview`). `PowerPlatform/` contains `Invoke-NLSCollectPowerPlatform.ps1` (sets `PowerPlatform`).

`Evaluators/` contains one file per workload, each function evaluating one control: `Test-NLSControl-AAD.ps1` (41 functions), `Test-NLSControlDefender.ps1` (18 functions), `Test-NLSControlTeams.ps1` (17 functions), `Test-NLSControlPurview.ps1` (15 functions), `Test-NLSControlSharePoint.ps1` (13 functions), `Test-NLSControlIntune.ps1` (13 functions), `Test-NLSControlCopilot.ps1` (5 functions), `Test-NLSControlPowerPlatform.ps1` (4 functions).

`Publishers/` contains `Publish-NLSAssessmentHTML.ps1` (1682-line interactive HTML report generator).

`Config/` contains `clients.json` (batch client list with TenantId, DelegatedOrg, and skip flags), `controls.json` (control definitions including `ControlId`, `Title`, `Severity`, `Workload`, `Category`, `CollectorDependency`, `EvaluatorFunction`, `Remediation`, `References`, and `LicenseRequirement` per control), `frameworks.json` (framework definitions for CIS / SCuBA / NIST / CMMC / ISO 27001 / SOC 2 / HIPAA / PCI DSS / DISA STIG / MITRE ATT&CK), `branding.psd1` (company name, contact, colors, hourly rate, fees), and `schema/controls.schema.json` (JSON Schema validating controls.json shape).

## Control Architecture

195 total controls across 9 workloads: Azure AD / Entra ID (AAD, 46), Exchange Online (EXO, 31), Defender for Office 365 (DEF, 23), Microsoft Teams (TMS, 22), Purview / Compliance (PVW, 18), SharePoint Online (SPO, 17), Microsoft Intune (INT, 17), Power Platform (PPL, 11), Email Auth DNS (DNS, 10). Severity breakdown: 11 Critical, 92 High, 65 Medium, 27 Low.

License-aware scoring is encoded per control via the `LicenseRequirement` string field in `controls.json` (e.g. "M365 Business Premium or Entra ID P1", "Defender for Office 365 P1", "E5 Compliance"). There are no separate per-tier baseline JSON files — the requirement lives on each control row.

License detection runs via `SubscribedSkus` in `Lib/Get-NLSTenantLicenseProfile.ps1`, which returns a `HashSet` of LicenseRequirement strings the tenant satisfies. `Test-NLSLicenseRequirementMet` answers per-control whether the tenant has the licenses needed. Controls whose requirement isn't met are routed to the Upgrade Unlocks section of the HTML report and do not count against the compliance score.

## Data Flow

`Connect-NLSServices` establishes Graph (21 scopes) plus EXO, Teams (optional), and IPPSSession (optional). Collectors run first and populate module-scope raw data using `Set-NLSRawData` with a key per workload. Each result object has `CollectorId`, `CollectedAt`, `Success`, and `Data`. Evaluators read raw data using `Get-NLSRawData` and write findings using `Add-NLSFinding` with states of `Satisfied`, `Gap`, `Partial`, `NotApplicable`, or `Error`. Publishers consume findings via `Get-NLSFindings`, calculate the license-aware score via `Get-NLSBaselineTier`, and produce the HTML report and JSON export.

Raw data keys and their collectors: `AAD-Inventory` set by `Invoke-NLSCollectAADInventory`; `AAD-Users` set by `Invoke-NLSCollectAADUsers`; `AAD-AuthPolicies` set by `Invoke-NLSCollectAADAuthPolicies`; `AAD-CAPolicies` set by `Invoke-NLSCollectAADAuthPolicies` via wrapper; `AAD-DirectoryRoles`, `AAD-PIMSchedules`, `AAD-IdentityGovernance` all set by `Invoke-NLSCollectAADRoles` via wrappers; `EXO-MailboxConfig` set by `Invoke-NLSCollectEXOMailboxConfig`; `EXO-ConnectionFilter` set by `Invoke-NLSCollectEXOConnectionFilter`; `Defender-Policies` set by `Invoke-NLSCollectDefender`; `DNS-domain` and `DNS-Summary` set by `Invoke-NLSCollectDNSEmailRecords`; `Teams` set by `Invoke-NLSCollectTeams`; `SharePoint` set by `Invoke-NLSCollectSharePoint`; `Intune` set by `Invoke-NLSCollectIntune`; `Purview` set by `Invoke-NLSCollectPurview`; `PowerPlatform` set by `Invoke-NLSCollectPowerPlatform`.

## Module State

All state is module-scope and cleared between batch clients by `Clear-NLSState`, which resets four variables: `NLSFindings` (List of hashtable), `NLSRawData` (Dictionary), `NLSCoverage` (Dictionary), and `NLSExceptions` (List of hashtable). `Clear-NLSState` must be called between batch clients or raw data from one client bleeds into the next client's evaluation.

## Coding Standards

Every script file requires a header block with `#Requires -Version 7.0`, the filename, NextLayerSec, Author: NextLayerSec, a one-line purpose statement, the data keys set or consumed, and the Graph scopes or cmdlets required.

All functions use `[CmdletBinding()]`. All data structures that get serialized use `[ordered]` hashtables. All external API calls use `ErrorAction Stop` and are wrapped in `try/catch` with `Register-NLSException`. `Write-Host` is never used in collectors or evaluators — use `Write-Verbose` only. No hardcoded credentials, tenant IDs, or domain names in code. Exit codes are 0 for success, 1 for auth failure, 2 for no findings, 3 for partial collection, 4 for fatal error.

Every collector must initialize a result object with `CollectorId`, `CollectedAt`, `Success` set to `false`, and a `Data` block; execute API calls inside `try/catch`; set `Success` to `true` on completion; call `Set-NLSRawData`; and call `Register-NLSCoverage`.

Every evaluator must guard against missing data as its first action. If `Get-NLSRawData` returns null or `Success` is false, register `NotApplicable` and return immediately. Never allow a null reference to propagate into evaluation logic. `Add-NLSFinding` accepts `ControlId`, `State`, `Category`, `Title`, `Severity`, `Detail`, `FrameworkIds`, `CurrentValue`, `RequiredValue`, and `RemediationSteps`.

## Control Schema

Each entry in `Config/controls.json` is validated by `Config/schema/controls.schema.json`. Required fields: `ControlId` (workload-prefixed, e.g. `AAD-1.1`), `Title`, `Description`, `BusinessRisk`, `Severity` (`Critical|High|Medium|Low|Informational`), `Workload` (one of AAD, EXO, DEF, TMS, PVW, SPO, INT, PPL, DNS), `Category`, `Automated` (boolean), `CollectorDependency` (raw-data key name the evaluator depends on), `EvaluatorFunction` (function name in `Evaluators/`), `Remediation`, `References` (array of framework citations), `LicenseRequirement` (string matched against `Get-NLSTenantLicenseProfile` output).

## Graph Scopes (21 total)

`Application.Read.All`, `AuditLog.Read.All`, `DeviceManagementApps.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementServiceConfig.Read.All`, `Directory.Read.All`, `Group.Read.All`, `IdentityRiskyUser.Read.All`, `Organization.Read.All`, `Policy.Read.All`, `Policy.Read.PermissionGrant`, `Reports.Read.All`, `RoleManagement.Read.All`, `SecurityEvents.Read.All`, `SharePointTenantSettings.Read.All`, `Sites.Read.All`, `TeamSettings.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `PrivilegedAccess.Read.AzureAD`.

Do not add scopes without updating `Connect-NLSServices.ps1`. The scope list must remain in sync with the enterprise app registration in each client tenant.

## Batch Mode

`Config/clients.json` requires the following fields for every client: `ClientName`, `TenantDomain`, `TenantId` (GUID), `DelegatedOrg` (the `.onmicrosoft.com` routing domain — not the primary domain), `UserPrincipalName`, `ClientType` (`Contract`, `NonContract`, or `Prospect`), `NLSHourlyRate`, `DnsDomains` (array), `SkipPurview`, `SkipTeams`, `SkipSharePoint`, `SkipIntune`, `SkipPowerPlatform`, `SkipDNS` (all boolean), `Notes`, and `Active`.

`DelegatedOrg` must be the `.onmicrosoft.com` routing domain. Get it from Microsoft 365 Admin Center under Settings then Domains for each client. Get `TenantId` from `https://login.microsoftonline.com/domain/.well-known/openid-configuration` — the GUID in the issuer field is the TenantId.

Test sequence before first full run: run with `-WhatIf` first, then `-OnlyClient nextlayersec.io -JsonOnly`, then full batch.

## HTML Report Structure

The report produces 13 sections: Executive Overview with score ring and license tier badge; Framework Compliance Matrix covering CIS M365 v6, CISA SCuBA, NIST 800-53r5, and CMMC 2.0; NLS Baseline Compliance with tier-detected score and deviation table; License Gap Analysis; Priority Actions with current state and business risk per finding; Additional Gaps for Medium findings; Attack Scenario Analysis for BEC, Ransomware, Domain Spoofing, and Privilege Escalation; What's Working; NLS Services and Quote; Security Roadmap; Named Findings; Upgrade Unlocks; and All Findings. Report modes are `-ClientType` (`Contract`, `NonContract`, or `Prospect`), and `-NLSHourlyRate` to override the default rate of 150.

## Known Gaps and Roadmap

**Phase 2 priorities** are: extending `Invoke-NLSCollectDNSEmailRecords` with DKIM key rotation age via `Get-DkimSigningConfig`, CAA record validation, TLS certificate expiry on mail hostnames, and CT log checks via `crt.sh`; creating `Invoke-NLSCollectEXOInventory` for external forwarding rules, shared mailbox sign-in state, per-user audit exceptions, and SMTP AUTH per-user overrides; populating real CISA ScubaGear rule identifiers into `controls.json` `FrameworkIds` fields from https://github.com/cisagov/ScubaGear; and creating dedicated evaluator files `Test-NLSControlEXO.ps1` and `Test-NLSControlDNS.ps1` which currently do not exist.

**Phase 3** covers delta and drift detection comparing current run JSON against a prior snapshot for CA policy changes, new admin role assignments, new OAuth app registrations, and DMARC policy regression; a Markdown summary publisher for ConnectWise ticket output; and a remediation playbook publisher consuming baseline `RemediationCmdlet` fields.

**Phase 4** covers `Apply-NLSBaseline.ps1` as a write-mode deployment script with mandatory `WhatIf` support and `-Confirm` required for auth policy or admin role changes; Windows LAPS (INT-4.1) and Windows Hello for Business (INT-4.2) evaluators; and implementation of the five Copilot governance controls which currently return `NotApplicable`.

## Environment

MSP context is NextLayerSec. Government clients have CISA BOD 18-01 compliance obligations. Key clients are `nextlayersec.io`, `example.com`, and `example2.com`. Tooling includes ConnectWise RMM, Cortex XDR, Microsoft Defender for Endpoint, SonicWall, DMARCian, and Microsoft 365/Entra ID. Frameworks referenced are NIST SP 800-53r5, NIST CSF 2.0, MITRE ATT&CK Enterprise, CIS M365 Foundations v3, CISA SCuBA, and CISA BOD 18-01. Logs go to `C:\ProgramData\NLS\Logs`. Assessment output goes to `.\output\tenantdomain\timestamp-results.json`. Batch summary goes to `.\output\batch-summary-timestamp.md`.

## Common Tasks

**To add a new control:** add the entry to `Config/controls.json` with all required fields including `LicenseRequirement`, add the evaluator function to the appropriate file in `Evaluators/`, verify the function name matches `EvaluatorFunction`, verify the collector sets the data key referenced by `CollectorDependency`, and add the new function name to both `FunctionsToExport` in `NLS-Assessment.psd1` and `$script:ExportedFunctions` in `NLS-Assessment.psm1`.

**To add a new client:** get the `TenantId` from the OpenID configuration endpoint, confirm the `.onmicrosoft.com` routing domain from M365 Admin Center, add the entry to `clients.json`, and set Skip flags based on the client's license tier — set `SkipPurview` and `SkipPowerPlatform` for Business Standard clients.

**To debug a collector:** run `-JsonOnly`, open the output JSON, find the collector key under `RawData`, check the `Success` field and `CollectedAt` timestamp, and check the `Exceptions` array for registered errors.

**To debug a wrong evaluator result:** confirm what raw data key it reads, verify the collector set `Success` to `true`, and inspect the specific fields the evaluator accesses against the actual collected data. Evaluators must never crash on missing fields — use null-conditional operators or explicit null checks throughout.

## Security Requirements

The tool is **read-only without exception**. No evaluator, collector, or publisher may write to tenant configuration. All Graph calls use GET only. All EXO calls use read-only cmdlets only. Any future write capability belongs exclusively in `Apply-NLSBaseline.ps1` with mandatory `WhatIf` support. Raw data is stored in module-scope memory only and never written to disk unencrypted. JSON output must not include credentials, tokens, or user PII beyond UPN and display name.
