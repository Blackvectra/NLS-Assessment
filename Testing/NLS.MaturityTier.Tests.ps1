#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester tests for Get-NLSMaturityTier. Pins the 5-tier classification
    (Initial / Developing / Defined / Managed / Optimizing) and the score
    formula so the maturity badge can never disagree with the score ring
    in the HTML report.
#>

Describe 'NLS-Assessment Maturity Tier Classification' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        $helperPath = Join-Path $script:RepoRoot 'Lib' 'Get-NLSMaturityTier.ps1'
        . $helperPath
    }

    Context 'Tier 5 — Optimizing' {

        It 'Returns Optimizing when score >= 90, no Critical, no High gaps' {
            $f = 1..10 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier  | Should -Be 5
            $m.Label | Should -Be 'Optimizing'
            $m.Score | Should -BeGreaterOrEqual 90
        }

        It 'Falls out of Optimizing if even one High gap is present' {
            $f = @()
            $f += 1..9 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += @{ State = 'Gap'; Severity = 'High' }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier | Should -BeLessThan 5
        }
    }

    Context 'Tier 4 — Managed' {

        It 'Returns Managed when score >= 75, no Critical, <= 3 High gaps' {
            $f = @()
            $f += 1..8 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..2 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier  | Should -Be 4
            $m.Label | Should -Be 'Managed'
        }
    }

    Context 'Tier 3 — Defined' {

        It 'Returns Defined when score >= 60 and no Critical gaps' {
            $f = @()
            $f += 1..7 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..3 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier         | Should -Be 3
            $m.Label        | Should -Be 'Defined'
            $m.CriticalGaps | Should -Be 0
        }

        It 'Drops to Developing when a Critical gap appears at the same score' {
            $f = @()
            $f += 1..6 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += @{ State = 'Gap'; Severity = 'Critical' }
            $f += 1..3 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier  | Should -BeLessOrEqual 2
        }
    }

    Context 'Tier 2 — Developing' {

        It 'Returns Developing when score >= 40 and <= 5 Critical' {
            $f = @()
            $f += 1..4 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += @{ State = 'Gap'; Severity = 'Critical' }
            $f += 1..5 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier  | Should -Be 2
            $m.Label | Should -Be 'Developing'
        }
    }

    Context 'Tier 1 — Initial' {

        It 'Returns Initial for low coverage' {
            $f = @()
            $f += @{ State = 'Satisfied'; Severity = 'Medium' }
            $f += 1..9 | ForEach-Object { @{ State = 'Gap'; Severity = 'High' } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier  | Should -Be 1
            $m.Label | Should -Be 'Initial'
        }

        It 'Returns Initial when many Critical gaps are present' {
            $f = @()
            $f += 1..3 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..6 | ForEach-Object { @{ State = 'Gap';       Severity = 'Critical' } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier  | Should -Be 1
        }
    }

    Context 'Score formula' {

        It 'Excludes NotApplicable from scored controls' {
            $f = @()
            $f += @{ State = 'Satisfied';     Severity = 'Medium' }
            $f += @{ State = 'NotApplicable'; Severity = 'Medium' }
            $f += @{ State = 'NotApplicable'; Severity = 'Medium' }
            $m = Get-NLSMaturityTier -Findings $f
            $m.ScoredControls | Should -Be 1
            $m.Score          | Should -Be 100
        }

        It 'Counts Partial as half-credit (matches HTML publisher)' {
            $f = @()
            $f += @{ State = 'Satisfied'; Severity = 'Medium' }
            $f += @{ State = 'Partial';   Severity = 'Medium' }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Score | Should -Be 75
        }

        It 'Returns score 0 when every finding is NotApplicable' {
            $f = 1..3 | ForEach-Object { @{ State = 'NotApplicable'; Severity = 'Medium' } }
            $m = Get-NLSMaturityTier -Findings $f
            $m.Score          | Should -Be 0
            $m.ScoredControls | Should -Be 0
        }
    }

    Context 'Output shape' {

        It 'Emits an ordered hashtable with all required keys' {
            $f = @(@{ State = 'Satisfied'; Severity = 'Medium' })
            $m = Get-NLSMaturityTier -Findings $f
            $required = @('Tier','Label','Score','CriticalGaps','HighGaps','ScoredControls','Description')
            foreach ($k in $required) {
                $m.Contains($k) | Should -BeTrue -Because "key '$k' must exist"
            }
        }

        It 'Tier is always between 1 and 5' {
            $f = @(@{ State = 'Satisfied'; Severity = 'Medium' })
            $m = Get-NLSMaturityTier -Findings $f
            $m.Tier | Should -BeGreaterOrEqual 1
            $m.Tier | Should -BeLessOrEqual 5
        }
    }
}
