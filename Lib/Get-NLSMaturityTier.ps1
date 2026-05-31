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
#   ScoredControls = total findings - NotApplicable

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NLSMaturityTier {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Findings
    )

    $sat  = @($Findings | Where-Object State -eq 'Satisfied').Count
    $part = @($Findings | Where-Object State -eq 'Partial').Count
    $na   = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $scored = $Findings.Count - $na

    $crit = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Critical' }).Count
    $high = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'High' }).Count

    $score = if ($scored -gt 0) { [Math]::Round(100 * ($sat + 0.5 * $part) / $scored) } else { 0 }

    $tier  = 1
    $label = 'Initial'
    $desc  = 'Foundational gaps remain — establish identity hardening, MFA, and audit logging before deepening other workloads.'

    if ($score -ge 90 -and $crit -eq 0 -and $high -eq 0) {
        $tier  = 5
        $label = 'Optimizing'
        $desc  = 'Posture is continuously measured and tuned. Focus on threat-hunting depth, regression alerting, and supply-chain governance.'
    }
    elseif ($score -ge 75 -and $crit -eq 0 -and $high -le 3) {
        $tier  = 4
        $label = 'Managed'
        $desc  = 'Controls are tracked and enforced. Drive remaining High-severity gaps to closure and add proactive drift detection.'
    }
    elseif ($score -ge 60 -and $crit -eq 0) {
        $tier  = 3
        $label = 'Defined'
        $desc  = 'Security baseline is in place across most workloads. Move toward measured operations — runbooks, change controls, evidence retention.'
    }
    elseif ($score -ge 40 -and $crit -le 5) {
        $tier  = 2
        $label = 'Developing'
        $desc  = 'Core controls exist but coverage is uneven. Close remaining Critical gaps and standardize identity + email hardening first.'
    }

    [ordered]@{
        Tier            = $tier
        Label           = $label
        Score           = [int]$score
        CriticalGaps    = $crit
        HighGaps        = $high
        ScoredControls  = $scored
        Description     = $desc
    }
}
