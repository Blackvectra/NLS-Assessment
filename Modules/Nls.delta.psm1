#
# NLS.Delta.psm1
# NextLayerSec Assessment Framework -- Delta Reporting Module
# Compares current assessment against a previous run for the same tenant
#
# Author:  NextLayerSec
# Version: 2.1.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Find-NLSPreviousReport {
    <#
    .SYNOPSIS
        Auto-finds the most recent previous report for a given tenant.
        Looks in the output directory for files matching <tenant>-*.md
        excluding the current report and exceptions files.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$OutputDir,
        [Parameter(Mandatory = $true)][string]$TenantName,
        [Parameter(Mandatory = $true)][string]$CurrentReportPath
    )

    $pattern = "$TenantName-*.md"
    $reports  = Get-ChildItem -Path $OutputDir -Filter $pattern -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -ne $CurrentReportPath -and
            $_.Name -notmatch '-exceptions'
        } |
        Sort-Object LastWriteTime -Descending

    if ($reports.Count -gt 0) { return $reports[0].FullName }
    return $null
}

function Get-NLSDeltaReport {
    <#
    .SYNOPSIS
        Compares current findings against a previous report.
        Surfaces what improved, what regressed, and what is unchanged.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$CurrentResults,
        [Parameter(Mandatory = $true)][string]$PreviousReportPath
    )

    if (-not (Test-Path $PreviousReportPath)) {
        return [ordered]@{
            Available = $false
            Reason    = "Previous report not found: $PreviousReportPath"
        }
    }

    # Parse previous report findings from markdown
    $previousContent = Get-Content -Path $PreviousReportPath -Raw -ErrorAction Stop
    $previousFindings = [ordered]@{}

    # Extract finding states from markdown -- look for bold titles under state headers
    $currentSection = $null
    foreach ($line in ($previousContent -split "`n")) {
        if ($line -match '^### (Gap|Partial|Satisfied|High|Medium|Pass)') {
            $currentSection = $Matches[1]
            # Normalize old severity names to states
            $currentSection = switch ($currentSection) {
                'High'   { 'Gap' }
                'Medium' { 'Partial' }
                'Pass'   { 'Satisfied' }
                default  { $currentSection }
            }
        }
        if ($line -match '^\*\*(.+)\*\*$' -and $currentSection) {
            $title = $Matches[1]
            $previousFindings[$title] = $currentSection
        }
    }

    # Compare current findings against previous
    $improved   = @()
    $regressed  = @()
    $unchanged  = @()
    $newFindings = @()

    foreach ($finding in $CurrentResults.Findings) {
        $prevState = $previousFindings[$finding.Title]

        if (-not $prevState) {
            $newFindings += [ordered]@{
                Title    = $finding.Title
                Category = $finding.Category
                State    = $finding.State
            }
            continue
        }

        $stateOrder = @{ 'Gap' = 0; 'Partial' = 1; 'Satisfied' = 2 }
        $prevOrder  = $stateOrder[$prevState]
        $currOrder  = $stateOrder[$finding.State]

        if ($currOrder -gt $prevOrder) {
            $improved += [ordered]@{
                Title        = $finding.Title
                Category     = $finding.Category
                PreviousState = $prevState
                CurrentState  = $finding.State
            }
        } elseif ($currOrder -lt $prevOrder) {
            $regressed += [ordered]@{
                Title        = $finding.Title
                Category     = $finding.Category
                PreviousState = $prevState
                CurrentState  = $finding.State
            }
        } else {
            $unchanged += [ordered]@{
                Title  = $finding.Title
                State  = $finding.State
            }
        }
    }

    return [ordered]@{
        Available        = $true
        PreviousReport   = $PreviousReportPath
        Improved         = $improved
        Regressed        = $regressed
        Unchanged        = $unchanged
        NewFindings      = $newFindings
        ImprovedCount    = $improved.Count
        RegressedCount   = $regressed.Count
        UnchangedCount   = $unchanged.Count
        NewCount         = $newFindings.Count
    }
}

function Publish-NLSDeltaSection {
    <#
    .SYNOPSIS
        Renders the delta comparison as a markdown section.
        Injected into the assessment report when a previous report exists.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Delta,
        [Parameter(Mandatory = $true)][System.Text.StringBuilder]$StringBuilder
    )

    $sb = $StringBuilder

    if (-not $Delta.Available) {
        return
    }

    [void]$sb.AppendLine('## Delta Report')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("> Comparison against previous report: $($Delta.PreviousReport | Split-Path -Leaf)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Category | Count |')
    [void]$sb.AppendLine('|---|:---:|')
    [void]$sb.AppendLine("| Improved | $($Delta.ImprovedCount) |")
    [void]$sb.AppendLine("| Regressed | $($Delta.RegressedCount) |")
    [void]$sb.AppendLine("| Unchanged | $($Delta.UnchangedCount) |")
    [void]$sb.AppendLine("| New Findings | $($Delta.NewCount) |")
    [void]$sb.AppendLine('')

    if ($Delta.ImprovedCount -gt 0) {
        [void]$sb.AppendLine('### Improved')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Control | Previous | Current |')
        [void]$sb.AppendLine('|---|:---:|:---:|')
        foreach ($item in $Delta.Improved) {
            [void]$sb.AppendLine("| $($item.Title) | $($item.PreviousState) | $($item.CurrentState) |")
        }
        [void]$sb.AppendLine('')
    }

    if ($Delta.RegressedCount -gt 0) {
        [void]$sb.AppendLine('### Regressed')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('> **Action required. Controls that previously passed have regressed.**')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Control | Previous | Current |')
        [void]$sb.AppendLine('|---|:---:|:---:|')
        foreach ($item in $Delta.Regressed) {
            [void]$sb.AppendLine("| $($item.Title) | $($item.PreviousState) | $($item.CurrentState) |")
        }
        [void]$sb.AppendLine('')
    }

    if ($Delta.NewCount -gt 0) {
        [void]$sb.AppendLine('### New Findings')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Control | Category | State |')
        [void]$sb.AppendLine('|---|---|:---:|')
        foreach ($item in $Delta.NewFindings) {
            [void]$sb.AppendLine("| $($item.Title) | $($item.Category) | $($item.State) |")
        }
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
}

Export-ModuleMember -Function Find-NLSPreviousReport, Get-NLSDeltaReport, Publish-NLSDeltaSection
