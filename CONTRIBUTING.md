# Contributing

This is internal NextLayerSec tooling. Contributions are managed by the NLS security engineering team.

---

## Adding a Control

1. Add the control definition to `PowerShell/NLSAssessment/Config/controls.json`
2. Add the evaluator function to the appropriate `Evaluators/Test-NLSControl-<SERVICE>.ps1`
3. Update the matching baseline document in `baselines/<service>.md`
4. Update `docs/misc/mappings.md` with the new control row
5. Test against a real tenant before committing

**Control ID format:** `<PRODUCT>-<SECTION>.<SEQUENCE>` (e.g., `AAD-2.5`, `EXO-3.2`)

---

## Adding a Framework

1. Add the framework metadata to `PowerShell/NLSAssessment/Config/frameworks.json`
2. Add the new framework key to relevant controls in `controls.json`
3. Update the crosswalk table in `docs/misc/mappings.md`
4. Update `baselines/README.md` framework list

No code changes required — the publishers read framework data from JSON.

---

## Collector Standards

- One file per data domain under `Collectors/<SERVICE>/`
- Functions return a structured hashtable — no scoring, no output
- All exceptions must be caught and registered via `Add-NLSCollectionError`
- No write operations to the tenant

---

## Evaluator Standards

- One file per service area under `Evaluators/`
- Functions read from module state via `Get-NLSRawData`
- All findings registered via `Add-NLSFinding`
- No API calls — evaluators are pure logic

---

## Code Style

- PowerShell 7.x
- NLS script header on all files (version, author, NIST/MITRE annotations)
- Approved verbs only (`Get-`, `Test-`, `Add-`, `Invoke-`, `Publish-`)
- `$ErrorActionPreference = 'Stop'` inside try blocks

---

## Commit Messages

Follow conventional commits:

```
feat: add AAD-2.5 phishing-resistant MFA evaluator
fix: EXO-2.1 forwarding check fails on non-default policies
docs: update mappings.md with CMMC 2.0 crosswalk
refactor: move DNS collectors to Collectors/DNS/
```
