# Changelog

## v4.6.6.1 (2026-05-27) — HTML report CSP hotfix

### Fixed

- **Interactive buttons silently broken in HTML assessment report.** The CSP emitted by `Publishers/Publish-NLSAssessmentHTML.ps1` was `script-src 'sha256-...'` — correctly authorizing the inline `<script>` block, but with no `'unsafe-inline'` or `'unsafe-hashes'`. Every `onclick="goto(...)"` on the header nav and every `onclick='toggle(this)'` on the expandable finding rows was therefore blocked by the browser, with no visible error to the operator. Nav links and row expanders rendered as cursor-pointer but did nothing on click.

  Fix: removed all inline `onclick=` attributes. Nav spans now use `data-goto="<id>"`; expandable rows are identified by their existing `class="exp"`. Handlers are attached via `addEventListener` inside the existing CSP-hashed `<script>` block, so the SHA-256 hash covers them automatically — no CSP relaxation needed.

  Affected: every HTML assessment report produced by v4.6.3 (when the CSP hash was introduced) through v4.6.6. The playbook HTML was unaffected (no interactive elements).

## v4.6.6 (2026-05-27) — fresh-install hotfix

Two latent bugs surfaced when an operator unboxed v4.6.5 from a fresh GitHub zip on a Windows workstation without MicrosoftTeams installed.

### Fixed

- **`New-Item -LiteralPath ... -ItemType Directory` doesn't work** — `-LiteralPath` is not in `New-Item`'s parameter set even on PS 7. Five sites switched to `[void][System.IO.Directory]::CreateDirectory($path)`:
  - `Invoke-NLSAssessment.ps1`, `Invoke-NLSBatchAssessment.ps1`, `Apply-NLSBaseline.ps1`, `Build/New-NLSCodeSigningCert.ps1`, `tools/Generate-SBOM.ps1`
- **`MicrosoftTeams` demoted from `RequiredModules` to soft dependency.** Module no longer fails to load on workstations without Teams. `Connect-NLSServices` already handles on-demand load.

## v4.6.5 (2026-05-27)

Patch release closing the correctness sweep defined in `docs/CORRECTNESS-SWEEP-v4.6.5.md`. No new features. Every defect surfaced by three real-tenant runs and a follow-on code-review audit is either Resolved here or explicitly tracked Open.

### Fixed

- **Per-tenant remediation script dispatch (Critical).** Generated `<tenant>-remediation.ps1` files called `Apply-NLS* -ErrorAction Stop` with no `-Finding` argument. Every `Apply-NLS*` function declares `[Parameter(Mandatory)] [object] $Finding`, so every dispatched call would have failed at runtime. The generated script now loads its sibling `<baseName>-results.json`, builds `$findingsByCtrl`, and passes `-Finding $fnd` per dispatch. The JSON-load runs BEFORE `Connect-NLSServices` so a missing or corrupt JSON fails fast without paying the Graph/EXO authentication cost. `ConvertFrom-Json` is wrapped in try/catch with a diagnostic message. `$assessment.Findings` is null-checked so an unexpected JSON shape produces an actionable error rather than silent zero-iteration.
- **14 StrictMode property-access NREs** across AAD, Defender, EXO, Intune evaluators (PR #2, #4). Each was silently dropping one or more findings from real-tenant reports.
- **`Get-Mailbox -ResultSize 1000` undercount.** Five EXO collector calls capped at 1000 mailboxes. Switched to `-ResultSize Unlimited` for population-counting calls.
- **HTML playbook alias collision.** `function H` collided with the built-in `h` alias (= `Get-History -Id [long]`). Renamed to `EscHtml`.
- **XLSX compliance matrix `'PCIDSS'` NRE.** All 10 framework-reference accesses now use `Get-NLSNestedProperty`. Also fixed the `PCIDASSS` column header typo.
- **HTML entity leakage in markdown publishers.** `ConvertTo-NLSHtmlSafe` was being applied to markdown source. Markdown `EscMd` now escapes only characters that break markdown table/code-span structure.
- **Findings-table sort under malformed enum values.** Defensive `?? 99` coerces unknown values to a sortable tail.

### Security / privacy

- **`.gitignore` now excludes `output/`.** NLS had the same gap as NRG (only `Reports/` was excluded); NLS never had real client data committed because the port excluded `output/` at copy time, but future `Invoke-NLSAssessment` runs would have started tracking output files.
- **Sample HTML sanitization.** `sample-report/example-assessment.html` had 7 occurrences of real personal domain `mattlevorson.com` (secondary domain on the source tenant) and 2 admin display names rendered as `NextLayerSec` (collision from `Matthew Levorson → NextLayerSec` sanitization). Replaced with `example2.com` / `Admin 2` / `Admin 3`.
- **Branding/PII leaks** in initial NLS port surfaced and fixed: NRG phone number in `branding.psd1`, "North Dakota" geographic identifier in CLAUDE.md, real client names NDACo / Dunn County in sample configs.

### Release engineering

- **In-house signing scaffolding (soft mode, $0 cost).** New `Build/New-NLSCodeSigningCert.ps1` generates a self-signed Authenticode cert on the operator workstation, installs it into `TrustedPublisher` + `Root`, and stashes the thumbprint at `~/.nls-assessment/signing-thumbprint.txt`. `Build/Sign-Release.ps1` treats self-signed as first-class for in-house use. Upgrade path to a paid cert is one parameter.
- **`Apply-NLSBaseline.ps1 -RequireSignedCode`** (new switch, default `$false`). Soft warning by default; hard refusal when set. Future v5.0 may flip the default.
- **`Lib/Test-NLSSignatureStatus.ps1`** (new exported function). Wraps `Get-AuthenticodeSignature` with friendlier status mapping and self-signed chain resolution.
- **`RELEASE-CHECKLIST.md`** (new). Codifies the per-release contract: pre-release OWASP delta walk, code-review pass, adversarial fixtures, real-tenant run; release-time signing + integrity-manifest generation; post-release SBOM + smoke test.

### Documentation

- New `docs/CORRECTNESS-SWEEP-v4.6.5.md` — prioritization rule, 24 Resolved entries with root cause and PR refs, 7 Open entries for follow-up, 3 misclassification entries deferred to v4.7, Definition of Done.
- `CLAUDE.md` rewritten to describe the actual `LicenseRequirement`-per-control architecture.
- New `docs/ROADMAP-v4.7.md` and `docs/ROADMAP-v4.8.md` — design only, no code.

### Readability

- `<tenant>-playbook.md` slimmed (TOC + checklist, no per-item framework wall or time-estimate).
- New `<tenant>-playbook.html` artifact (strict CSP, Trusted Types, print stylesheet).
- `<tenant>-executive.md` got a Bottom-line one-liner and Current state lines under top-5 priorities.
- `<tenant>-assessment.md` findings table sorted Gap → Partial → Satisfied first; NotApplicable folded.
- `<tenant>-remediation.ps1` is now actually runnable.
- New `sample-report/example-assessment.html` so prospective users can see what the tool produces without running an assessment first.

## v4.5.5 (2025-05-18)

Major architectural change: rebuilt on the v4.5.0 baseline pattern to eliminate runtime crashes caused by aggressive `Set-StrictMode -Version Latest` propagation into evaluator scope.

### Fixed
- **StrictMode property access crashes** — removed `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'` from script scope in all evaluators and collectors. Was causing runtime failures on `$obj.MissingProperty` access patterns common in `ConvertFrom-Json` data from Microsoft Graph.
- **Injection scanner false positives** — removed overly aggressive regex (`on\w+\s*=`) from the controls.json validator. Was flagging legitimate strings like `Condition =`, `applications =`, `ActionWhenThresholdReached =`.
- **`?.` null-conditional operator crashes** — all null-conditional access replaced with explicit `if ($obj) { $obj.Prop } else { $null }` patterns. Was hitting tokenizer issues under StrictMode in PS 7.6.1.
- **EOM v3.4 WAM broker crash** — `$env:MSAL_ALLOW_BROKER = '0'`, `$env:MSAL_DISABLE_TOKENBROKER = '1'`, `$env:MSAL_DISABLE_WAM = '1'` set before module import. Recommend EOM 3.2.0 for best results.
- **AI- and INV- ControlId prefixes** — renamed to PPL-3.x (AI), AAD-12.x/AAD-13.1 (INV identity), EXO-6.x (INV email) to match standard workload prefixes.
- **`New-Item -LiteralPath -ItemType Directory`** — replaced with `-Path` (more universally supported).
- **`"```"` parse errors** — backtick before closing quote in double-quoted strings was breaking PS string termination. Switched to single-quoted strings for Markdown code fences.

### Added
- **188 controls** across 9 workloads (AAD=46, DEF=23, DNS=6, EXO=28, INT=17, PPL=11, PVW=18, SPO=17, TMS=22).
- **Premium HTML report** — animated score ring, workload scorecard grid, framework matrix, license gap analysis, priority actions, Named Findings section, 90-Day Roadmap, Best Practices section, Secure Score widget.
- **Named findings** — per-user/per-mailbox lists for MFA gaps, stale guests, stale accounts, OAuth grants, external forwarding, shared mailbox sign-in, mailbox audit, SMTP AUTH overrides.
- **XLSX compliance matrix** — 11 sheets, 7 framework-specific exports (CIS, SCuBA, NIST 800-53, CMMC, ISO 27001, SOC 2, HIPAA), license gaps.
- **Delta report** — comparison vs prior assessment run with new/resolved/regressed/unchanged categorization.
- **10 frameworks** — CIS M365 v6.0.1, CISA SCuBA, NIST 800-53r5, CMMC 2.0 L2, ISO 27001:2022, SOC 2 TSC, HIPAA §164, PCI DSS v4.0.1, DISA STIG, MITRE ATT&CK.
- **5 AI/Copilot controls** (PPL-3.1 through PPL-3.5).
- **App-only certificate authentication** for unattended runs.
- **GCC environment support** (`-Environment commercial|gcc|gcchigh|dod`).
- **NonInteractive mode** for CI/CD.
- **FromResults regeneration** — rebuild reports from prior JSON without re-collecting.
- **BaselineResults delta comparison**.
- **Module prerequisite check with auto-install prompt**.
- **GDAP batch runner** (Invoke-NLSBatchAssessment.ps1) for MSP multi-tenant runs.

### Changed
- **`-SkipPurview` defaults to `$true`** — EOM v3.4 IPPSSession WAM crash. Use `-IncludePurview` to opt in.
- **Evaluator discovery dynamic** — orchestrator enumerates `Test-NLSControl*` from loaded module rather than hardcoded list.
- **Disconnect at end of run** — no try/finally chain that fires on every error.

## v4.5.0 (Baseline)

Initial clean architectural rebuild. 75 controls across Collectors → Evaluators → Publishers pipeline.
