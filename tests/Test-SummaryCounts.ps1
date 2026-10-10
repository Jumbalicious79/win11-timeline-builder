# =============================================================
# Summary counts test
# The summary at the end of a run lists "Events by artifact source". These
# counts must be the rows of the finished timeline: the rows left after
# deduplication, which are the rows written to the CSV, so they add up to
# "Total events". Checks Get-ArtifactRowCounts on synthetic rows (rows per
# Artifact, the largest count first, equal counts in name order, only the
# rows it is given) and, in the builder's syntax tree, that the summary
# counts the same rows that are exported to the CSV.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-SummaryCounts.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param(
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$script:failures = 0
$script:checks = 0

function Write-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    $script:checks++
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Name" -ForegroundColor Red
    if ($Message) { Write-Host "  $($Message -replace "`n", "`n  ")" }
    if ($env:GITHUB_ACTIONS) {
        $oneLine = ($Message -replace "`r?`n", " / ")
        Write-Host "::error file=tests/Test-SummaryCounts.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# --- Load the builder's functions ------------------------------------------
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-TestResult -Name "builder parses" -Passed $false -Message "$($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
    exit 1
}
$functionAsts = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
        $parent = $_.Parent
        while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
        $null -eq $parent
    })
foreach ($functionAst in $functionAsts) { . ([scriptblock]::Create($functionAst.Extent.Text)) }
# The XML-invalid character filter used by Add-TimelineEntry
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        @('$script:xmlInvalidPattern', '$script:xmlInvalidRegex') -contains $node.Left.Extent.Text }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

# The counts as "Name=Count|Name=Count|...", in the order returned
function Format-ArtifactRowCounts {
    param([object[]]$Rows)
    return (@(Get-ArtifactRowCounts -Rows $Rows | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join "|")
}

# The builder's commands named -Name that are outside every function (the
# script's main flow)
function Find-MainFlowCommand {
    param([string]$Name)
    # Read here: PSReviewUnusedParameter does not see uses inside the predicate
    $commandName = $Name
    return @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq $commandName }, $true) | Where-Object {
            $parent = $_.Parent
            while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
            $null -eq $parent
        })
}

try {
    Write-Host "Testing Get-ArtifactRowCounts ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."

    # Rows made by Add-TimelineEntry, as in a run (made-up descriptions).
    # Artifacts with equal counts are added in reverse name order.
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $rowTime = [datetime]::new(2025, 6, 30, 12, 0, 0, [System.DateTimeKind]::Utc)
    $artifactNames = @("UsnJournal", "Registry", "FileSystem", "Registry", "Browser", "UsnJournal", "AntiVirus", "FileSystem", "Registry")
    for ($i = 0; $i -lt $artifactNames.Count; $i++) {
        Add-TimelineEntry -Timestamp $rowTime.AddSeconds($i) -Source "Test" -EventType "FileAccess" -Description "Row $i" -Artifact $artifactNames[$i]
    }
    [object[]]$rows = $script:timelineEntries.ToArray()
    $expectedCounts = "Registry=3|FileSystem=2|UsnJournal=2|AntiVirus=1|Browser=1"
    Assert-Equal -Name "rows per Artifact: the largest count first, equal counts in name order" -Expected $expectedCounts -Actual (Format-ArtifactRowCounts $rows)
    $countSum = (@(Get-ArtifactRowCounts -Rows $rows) | Measure-Object -Property Count -Sum).Sum
    Assert-Equal -Name "rows per Artifact: the counts add up to the number of rows" -Expected $rows.Count -Actual $countSum

    # A run collects duplicates too; the summary is given the rows left
    # after deduplication, and only those may be counted
    for ($i = 0; $i -lt 3; $i++) {
        Add-TimelineEntry -Timestamp $rowTime -Source "Test" -EventType "FileAccess" -Description "Row 0" -Artifact "UsnJournal"
    }
    Assert-Equal -Name "rows per Artifact: only the rows given are counted, not every row collected" -Expected $expectedCounts -Actual (Format-ArtifactRowCounts $rows)

    Assert-Equal -Name "rows per Artifact: one row" -Expected "Registry=1" -Actual (Format-ArtifactRowCounts @($rows[1]))
    Assert-Equal -Name "rows per Artifact: no rows give no counts" -Expected "0|0" -Actual "$(@(Get-ArtifactRowCounts -Rows @()).Count)|$(@(Get-ArtifactRowCounts -Rows $null).Count)"

    # --- What the summary counts ---------------------------------------------
    Write-Host "Testing which rows the summary counts ..."
    $countCalls = @(Find-MainFlowCommand -Name "Get-ArtifactRowCounts")
    Assert-Equal -Name "summary: Get-ArtifactRowCounts is called once" -Expected 1 -Actual $countCalls.Count
    $csvExports = @(Find-MainFlowCommand -Name "Export-Csv" | Where-Object { $_.Extent.Text -match '-(?:Literal)?Path \$OutputFile\b' })
    Assert-Equal -Name "CSV export: one Export-Csv -LiteralPath `$OutputFile" -Expected 1 -Actual $csvExports.Count
    if ($countCalls.Count -eq 1 -and $csvExports.Count -eq 1) {
        # The variable passed to the count, and the one piped to Export-Csv
        $countedVariable = @($countCalls[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] } |
                ForEach-Object { $_.VariablePath.UserPath })
        $exportedVariable = @()
        $csvPipeline = $csvExports[0].Parent
        if ($csvPipeline -is [System.Management.Automation.Language.PipelineAst] -and $csvPipeline.PipelineElements.Count -eq 2 -and
            $csvPipeline.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst] -and
            $csvPipeline.PipelineElements[0].Expression -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $exportedVariable = @($csvPipeline.PipelineElements[0].Expression.VariablePath.UserPath)
        }
        Write-TestResult -Name "summary: counts the rows written to the CSV (after deduplication), so the counts add up to the total" `
            -Passed ($exportedVariable.Count -eq 1 -and $countedVariable.Count -eq 1 -and $countedVariable[0] -ceq $exportedVariable[0]) `
            -Message "CSV export: $($csvPipeline.Extent.Text)`nsummary   : $($countCalls[0].Extent.Text)"
    }
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
