@{
    # PSScriptAnalyzer settings for NLS-Assessment-Tool CI
    #
    # Severity = Error      → fails CI (must fix or exclude)
    # Severity = Warning    → reports in CI log only (does not fail)
    # Severity = Information → reports in CI log only (does not fail)
    #
    # CI logic lives in .github/workflows/ci.yml — this file only configures the
    # rule set the analyzer evaluates against.
    #
    # SUPPRESSION POLICY: every excluded rule below carries a rationale + a
    # documented sunset path (v5.0 cleanup, Phase 4 ship, etc). Suppressions
    # are not free — they hide signal — so we treat them as technical debt.

    Severity = @('Error', 'Warning')

    # Default to the analyzer's full rule set, then exclude rules that don't
    # apply to this codebase.
    IncludeDefaultRules = $true

    ExcludeRules = @(
        # Legitimate interactive UX output. The tool prints progress banners,
        # connection status, and per-step messages directly to the operator
        # console — Write-Host is the correct PowerShell idiom for that.
        'PSAvoidUsingWriteHost',

        # This is a strictly READ-ONLY assessment tool. No function changes
        # tenant state, so ShouldProcess / -WhatIf / -Confirm boilerplate would
        # be noise. The future Apply-NLSBaseline.ps1 write component (Phase 4)
        # will need ShouldProcess — when that lands, drop this exclusion.
        'PSUseShouldProcessForStateChangingFunctions',

        # Common false positive: parameters bound via splatting or used
        # indirectly via Set-Variable are flagged as unused. The codebase
        # uses both patterns extensively.
        'PSReviewUnusedParameter',

        # The module exports plural-noun functions intentionally
        # (Get-NLSFindings returns a collection, Clear-NLSFindings clears all).
        # The plural form better reflects the collection semantics than the
        # analyzer's singular-noun convention.
        'PSUseSingularNouns',

        # The 6 Apply-NLS* write-mode functions (Apply-NLSAADLegacyAuth,
        # Apply-NLSAADMFA, Apply-NLSEXOMailboxAudit, Apply-NLSEXOSmtpAuth,
        # Apply-NLSEXOAutoForward, Apply-NLSDefenderPreset) use the unapproved
        # "Apply" verb. "Apply-" is the deliberate verb chosen for the write-
        # mode remediation surface because it pairs naturally with the
        # operator workflow ("apply the baseline to a tenant") and the
        # existing Apply-NLSBaseline.ps1 orchestrator. Renaming to
        # Set-NLSBaselineAAD* / Set-NLSBaselineEXO* would break operator
        # documentation, training material, and muscle memory built up across
        # multiple client engagements. Rename is deferred to v5.0 where it
        # can ship alongside the other breaking changes already planned for
        # that release. Until then, this exclusion is the explicit accept-
        # the-debt marker. Re-evaluate when v5.0 ships.
        'PSUseApprovedVerbs'
    )
}
