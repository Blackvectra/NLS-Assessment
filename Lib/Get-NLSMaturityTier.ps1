#Requires -Version 7.0
#
# Get-NLSMaturityTier.ps1  (v4.9.0)
#
# Author: NextLayerSec — nextlayersec.io
# Purpose: Derived classification of tenant security posture into a 5-tier
#          maturity model. Reads the finished findings stream from a run and
#          returns a single tier label, numeric level, and the score / gap
#          counts that fed the decision. Implements roadmap F1.
#
# Inputs:  Findings array (post-evaluation) — same shape Get-NLSFindings emits.
#          Accepts an empty array (silent zero-score result, not a binding error).
# Outputs: [ordered] hashtable with Tier (1-5), Label, Score, CriticalGaps,
#          HighGaps, ScoredControls, Description. Safe to serialize as JSON.
#
# Tier rules (combination of coverage % across license-applicable controls
# and absolute critical/high gap count — captures both "wide" and "deep"):
#
#   5 Optimizing   Score >= 90 AND 0 Critical AND 0 High
#   4 Managed      Score >= 75 AND 0 Critical AND High <= 3
#   3 Defined      Score >= 60 AND 0 Critical
#   2 Developing   Score >= 40 AND Critical <= 5
#   1 Initial      Everything else (<40% coverage OR any critical gap with low score)
#
# Score derivation matches the Publish-NLSAssessmentHTML formula so the
# maturity badge and the score ring never disagree:
#   score = round(100 * (Satisfied + 0.5*Partial) / ScoredControls)
#   ScoredControls = total findings - NotApplicable - Error
#
# Why Error is excluded from the denominator: an `Error` finding means the
# evaluator threw (transient Graph throttling, missing scope, partial collection).
# Counting it as a gap punishes the operator for tool problems and turns
# `-FailOnScoreBelow` in CI into a false alarm on flaky tenants.

function Get-NLSMaturityTier {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Findings
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Single pass over Findings — earlier version did five Where-Object scans
    # AND used simple-syntax that throws under StrictMode when an element is
    # missing State / Severity. Field reads use a shape-agnostic helper so
    # hashtables AND PSCustomObjects (incl. ConvertFrom-Json output from the
    # -FromResults path) both work, and missing keys yield $null instead of
    # throwing.
    function Read-FindingField {
        param($Item, [string]$Key)
        if ($null -eq $Item) { return $null }
        if ($Item -is [System.Collections.IDictionary]) {
            if ($Item.Contains($Key)) { return $Item[$Key] }
            return $null
        }
        $p = $Item.PSObject.Properties[$Key]
        if ($null -ne $p) { return $p.Value }
        return $null
    }

    $sat = 0; $part = 0; $na = 0; $err = 0
    $crit = 0; $high = 0
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $state    = Read-FindingField -Item $f -Key 'State'
        $severity = Read-FindingField -Item $f -Key 'Severity'
        switch ($state) {
            'Satisfied'     { $sat++ }
            'Partial'       { $part++ }
            'NotApplicable' { $na++ }
            'Error'         { $err++ }
            'Gap' {
                if ($severity -eq 'Critical') { $crit++ }
                elseif ($severity -eq 'High') { $high++ }
            }
        }
    }

    $scored = $Findings.Count - $na - $err
    $score  = if ($scored -gt 0) { [Math]::Round(100 * ($sat + 0.5 * $part) / $scored) } else { 0 }

    $tier  = 1
    $label = 'Initial'
    $desc  = 'Foundational gaps remain — establish identity hardening, MFA, and audit logging before deepening other workloads.'

    if ($score -ge 90 -and $crit -eq 0 -and $high -eq 0) {
        $tier = 5; $label = 'Optimizing'
        $desc = 'Posture is continuously measured and tuned. Focus on threat-hunting depth, regression alerting, and supply-chain governance.'
    }
    elseif ($score -ge 75 -and $crit -eq 0 -and $high -le 3) {
        $tier = 4; $label = 'Managed'
        $desc = 'Controls are tracked and enforced. Drive remaining High-severity gaps to closure and add proactive drift detection.'
    }
    elseif ($score -ge 60 -and $crit -eq 0) {
        $tier = 3; $label = 'Defined'
        $desc = 'Security baseline is in place across most workloads. Move toward measured operations — runbooks, change controls, evidence retention.'
    }
    elseif ($score -ge 40 -and $crit -le 5) {
        $tier = 2; $label = 'Developing'
        $desc = 'Core controls exist but coverage is uneven. Close remaining Critical gaps and standardize identity + email hardening first.'
    }

    [ordered]@{
        Tier            = $tier
        Label           = $label
        Score           = [int]$score
        CriticalGaps    = $crit
        HighGaps        = $high
        ScoredControls  = $scored
        ErrorFindings   = $err
        Description     = $desc
    }
}
