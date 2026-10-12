# =============================================================
# Viewer menu test
# Checks what the builder opens at the end of a run (Invoke-TimelineViewer):
# the menu and its numbering for every mix of files (the workbook and the
# findings report both made, no report, no workbook, neither), the first
# choice "Excel + findings report" (shown only when both files were made,
# in green, with PDF or HTML named), Excel in green only when it is [1],
# "Excel + Timeline Explorer" (-Viewer Both), each answer and what it
# starts, a number that is not listed asked again, the end of redirected
# input (nothing opened), every -Viewer value with and without the files
# (ExcelAndReport opens what was made and logs which file is missing),
# Excel started before the report, and one that cannot be started not
# stopping the other. In the builder's syntax tree: -Viewer's ValidateSet
# values, each handled by the function, and each named in README.txt.
# Only Invoke-TimelineViewer is loaded from the builder's AST, so the
# script itself (and its Administrator check) does not run: no admin
# rights needed. Nothing is started: Start-Process, Read-Host, the log
# functions and Get-TimelineExplorer are stand-ins.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ViewerMenu.ps1
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
        Write-Host "::error file=tests/Test-ViewerMenu.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# --- Stand-ins for what Invoke-TimelineViewer calls ---------------------------
# The log lines (warnings with "WARNING: ", as the builder writes them)
$script:log = New-Object System.Collections.Generic.List[string]
function Log { param([string]$Message) $script:log.Add($Message) }
function Log-Warning { param([string]$Message) $script:log.Add("WARNING: $Message") }
function Log-Success { param([string]$Message) $script:log.Add($Message) }
function Log-Error { param([string]$Message) $script:log.Add("ERROR: $Message") }

# Timeline Explorer's path, as if it were downloaded (none with $script:noTe)
$script:noTe = $false
function Get-TimelineExplorer {
    $script:teLookups++
    if ($script:noTe) { return $null }
    return "C:\stub\tools\TimelineExplorer\TimelineExplorer.exe"
}

# Start-Process (an alias for this): records what would be started, in
# order; a path with "fail" in it cannot be started (throws, as the real
# cmdlet does for a file that cannot be opened)
function Start-TestProcess {
    param([string]$FilePath, [string]$ArgumentList)
    if ($FilePath -like "*fail*") { throw "This command cannot be run due to the error: test failure." }
    $entry = $FilePath
    if ($ArgumentList) { $entry += " $ArgumentList" }
    $script:started.Add($entry)
}
Set-Alias -Name Start-Process -Value Start-TestProcess

# Read-Host (an alias for this): the next answer, then $null, as Read-Host
# gives at the end of redirected input; the prompts are recorded
function Get-TestAnswer {
    $script:prompts.Add("$($args[0])")
    if ($script:answers.Count -gt 0) { return $script:answers.Dequeue() }
    return $null
}
Set-Alias -Name Read-Host -Value Get-TestAnswer

# --- Load Invoke-TimelineViewer from the builder ----------------------------
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-TestResult -Name "builder parses" -Passed $false -Message "$($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
    exit 1
}
$viewerAsts = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Invoke-TimelineViewer" }, $true))
if ($viewerAsts.Count -ne 1) {
    Write-TestResult -Name "the builder has one Invoke-TimelineViewer" -Passed $false -Message "found $($viewerAsts.Count)"
    exit 1
}
. ([scriptblock]::Create($viewerAsts[0].Extent.Text))

$csv = "C:\r\timeline_2026-01-01_00-00-00\timeline.csv"
$xlsx = "C:\r\timeline_2026-01-01_00-00-00\timeline.xlsx"
$pdf = "C:\r\timeline_2026-01-01_00-00-00\report.pdf"
$html = "C:\r\timeline_2026-01-01_00-00-00\report.html"
$te = "C:\stub\tools\TimelineExplorer\TimelineExplorer.exe"

# Runs Invoke-TimelineViewer: -Choice is -Viewer ("" for the menu), -Workbook
# whether the workbook was made, -Report the report's path ("" for none),
# -Answers what Read-Host returns. Returns the menu ("n=Label(Color)|..."),
# what was started, the warnings, the log, the prompts and the number of
# "Invalid selection" lines.
function Invoke-TestViewer {
    param([string]$Choice = "", [bool]$Workbook, [string]$Report = "", [string[]]$Answers = @(), [string]$XlsxPath = $xlsx)
    $script:log.Clear()
    $script:started = New-Object System.Collections.Generic.List[string]
    $script:prompts = New-Object System.Collections.Generic.List[string]
    $script:answers = New-Object System.Collections.Queue
    foreach ($answer in $Answers) { $script:answers.Enqueue($answer) }
    $script:teLookups = 0
    $records = @(Invoke-TimelineViewer -Choice $Choice -CsvPath $csv -XlsxPath $XlsxPath -XlsxAvailable $Workbook -ReportPath $Report 6>&1)
    $menu = New-Object System.Collections.Generic.List[string]
    $screen = New-Object System.Collections.Generic.List[string]
    foreach ($record in $records) {
        $text = "$record"
        $screen.Add($text)
        $match = [regex]::Match($text, '^  \[(\d+)\] (.+?) -- ')
        if ($match.Success) {
            $color = ""
            if ($record -is [System.Management.Automation.InformationRecord] -and $record.MessageData -is [System.Management.Automation.HostInformationMessage]) {
                $color = "$($record.MessageData.ForegroundColor)"
            }
            $menu.Add("$($match.Groups[1].Value)=$($match.Groups[2].Value)($color)")
        }
    }
    return [PSCustomObject]@{
        Menu     = ($menu -join "|")
        Started  = ($script:started -join " ; ")
        Warnings = (@($script:log | Where-Object { $_ -like "WARNING:*" }) -join " / ")
        Log      = @($script:log)
        Screen   = $screen.ToArray()
        Prompts  = $script:prompts.ToArray()
        Invalid  = @($screen | Where-Object { $_ -like "Invalid selection*" }).Count
        TeLookup = $script:teLookups
    }
}

# The log's "Viewer selection" line
function Get-Selection {
    param($Result)
    return (@($Result.Log | Where-Object { $_ -like "  Viewer selection: *" }) -join " / ")
}

try {
    Write-Host "Testing Invoke-TimelineViewer ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."
    $menuBoth = "1=Excel + findings report(Green)|2=Excel(White)|3=Timeline Explorer(White)|4=Excel + Timeline Explorer(White)|5=Open report(White)|6=None(DarkGray)"

    # --- The menu ------------------------------------------------------------
    $r = Invoke-TestViewer -Workbook $true -Report $pdf -Answers @("1")
    Assert-Equal -Name "menu, both files: Excel + findings report first, then Excel, Timeline Explorer, Excel + Timeline Explorer, Open report, None" -Expected $menuBoth -Actual $r.Menu
    Write-TestResult -Name "menu, both files: [1] says the report is a PDF and that both are opened together (recommended)" -Passed (@($r.Screen | Where-Object { $_ -ceq "       findings report (PDF), opened together (recommended)" }).Count -eq 1) -Message ($r.Screen -join "`n")
    Assert-Equal -Name "menu, both files: the prompt names 1-6" -Expected "Select a viewer (1-6)" -Actual ($r.Prompts -join " / ")
    Assert-Equal -Name "menu, answer 1: Excel is started, then the report" -Expected "$xlsx ; $pdf" -Actual $r.Started
    Assert-Equal -Name "menu, answer 1: logged as 'Excel + findings report'" -Expected "  Viewer selection: Excel + findings report" -Actual (Get-Selection $r)
    Assert-Equal -Name "menu, answer 1: no warning" -Expected "" -Actual $r.Warnings
    $excelAt = [Array]::IndexOf($r.Log, "--- Opening Color-Coded Timeline in Excel ---")
    $reportAt = [Array]::IndexOf($r.Log, "--- Opening the Findings Report ---")
    Write-TestResult -Name "menu, answer 1: Excel launched and the report opened, in that order in the log" -Passed ($excelAt -ge 0 -and $reportAt -gt $excelAt -and
        $r.Log -contains "  Excel launched with color-coded timeline." -and $r.Log -contains "  Report opened: $pdf" -and $r.TeLookup -eq 0) -Message ($r.Log -join "`n")

    $r = Invoke-TestViewer -Workbook $true -Report $html -Answers @("1")
    Write-TestResult -Name "menu, HTML report: [1] and Open report say HTML" -Passed (@($r.Screen | Where-Object { $_ -ceq "       findings report (HTML), opened together (recommended)" }).Count -eq 1 -and
        @($r.Screen | Where-Object { $_.StartsWith("  [5] Open report -- the findings report (HTML): ") }).Count -eq 1) -Message ($r.Screen -join "`n")
    Assert-Equal -Name "menu, HTML report, answer 1: Excel, then report.html" -Expected "$xlsx ; $html" -Actual $r.Started

    $r = Invoke-TestViewer -Workbook $true -Report "" -Answers @("1")
    Assert-Equal -Name "menu, no report: Excel (green) first, no report choices" -Expected "1=Excel(Green)|2=Timeline Explorer(White)|3=Excel + Timeline Explorer(White)|4=None(DarkGray)" -Actual $r.Menu
    Assert-Equal -Name "menu, no report, answer 1: Excel only" -Expected $xlsx -Actual $r.Started
    Assert-Equal -Name "menu, no report, answer 1: logged as Excel" -Expected "  Viewer selection: Excel (color-coded .xlsx)" -Actual (Get-Selection $r)

    $r = Invoke-TestViewer -Workbook $false -Report $pdf -Answers @("2")
    Assert-Equal -Name "menu, no workbook: Timeline Explorer, Open report, None" -Expected "1=Timeline Explorer(White)|2=Open report(White)|3=None(DarkGray)" -Actual $r.Menu
    Assert-Equal -Name "menu, no workbook, answer 2: the report only" -Expected $pdf -Actual $r.Started

    $r = Invoke-TestViewer -Workbook $false -Report "" -Answers @("2")
    Assert-Equal -Name "menu, neither file: Timeline Explorer and None" -Expected "1=Timeline Explorer(White)|2=None(DarkGray)" -Actual $r.Menu
    Write-TestResult -Name "menu, neither file, answer 2: nothing started, the CSV named" -Passed ($r.Started -eq "" -and $r.Log -contains "  No viewer launched. Files saved to:" -and
        $r.Log -contains "    CSV: $csv" -and -not ($r.Log -match '^    (Excel|Report): ')) -Message ($r.Log -join "`n")

    # Each answer of the full menu
    $answerCases = @(
        @{ Answer = "2"; Started = $xlsx; Label = "Excel (color-coded .xlsx)"; Te = 0 }
        @{ Answer = "3"; Started = "$te `"$csv`""; Label = "Timeline Explorer (Eric Zimmerman)"; Te = 1 }
        @{ Answer = "4"; Started = "$xlsx ; $te `"$csv`""; Label = "Excel + Timeline Explorer"; Te = 1 }
        @{ Answer = "5"; Started = $pdf; Label = "Open report"; Te = 0 }
        @{ Answer = "6"; Started = ""; Label = "None"; Te = 0 }
    )
    foreach ($case in $answerCases) {
        $r = Invoke-TestViewer -Workbook $true -Report $pdf -Answers @($case.Answer)
        Write-TestResult -Name "menu, both files, answer $($case.Answer): starts '$($case.Started)', logged as '$($case.Label)'" -Passed ($r.Started -ceq $case.Started -and
            (Get-Selection $r) -ceq "  Viewer selection: $($case.Label)" -and $r.TeLookup -eq $case.Te -and $r.Warnings -eq "") -Message "started: $($r.Started)`nselection: $(Get-Selection $r)`nTimeline Explorer lookups: $($r.TeLookup)`nwarnings: $($r.Warnings)"
    }
    $r = Invoke-TestViewer -Workbook $true -Report $pdf -Answers @("6")
    Write-TestResult -Name "menu, answer None: the CSV, workbook and report are named" -Passed ($r.Log -contains "    CSV: $csv" -and $r.Log -contains "    Excel: $xlsx" -and $r.Log -contains "    Report: $pdf") -Message ($r.Log -join "`n")

    # A number that is not listed, and the end of input
    $r = Invoke-TestViewer -Workbook $true -Report $pdf -Answers @("9", "0", "x", "1")
    Write-TestResult -Name "menu: 9, 0 and x are asked again (three 'Invalid selection. Enter 1-6.' lines), then 1 opens both" -Passed ($r.Invalid -eq 3 -and
        @($r.Screen | Where-Object { $_ -ceq "Invalid selection. Enter 1-6." }).Count -eq 3 -and $r.Prompts.Count -eq 4 -and $r.Started -ceq "$xlsx ; $pdf") -Message "invalid: $($r.Invalid), prompts: $($r.Prompts.Count), started: $($r.Started)"
    $r = Invoke-TestViewer -Workbook $false -Report "" -Answers @("3", "1")
    Write-TestResult -Name "menu, neither file: 3 is not listed (1-2), asked again" -Passed ($r.Invalid -eq 1 -and @($r.Screen | Where-Object { $_ -ceq "Invalid selection. Enter 1-2." }).Count -eq 1 -and $r.Started -ceq "$te `"$csv`"") -Message "invalid: $($r.Invalid), started: $($r.Started)"
    $r = Invoke-TestViewer -Workbook $true -Report $pdf -Answers @()
    Write-TestResult -Name "menu, end of input: None, nothing started, asked once" -Passed ($r.Started -eq "" -and (Get-Selection $r) -ceq "  Viewer selection: None" -and $r.Prompts.Count -eq 1 -and $r.Invalid -eq 0) -Message "started: $($r.Started)`nselection: $(Get-Selection $r)`nprompts: $($r.Prompts.Count)"
    $script:noTe = $true
    $r = Invoke-TestViewer -Workbook $true -Report $pdf -Answers @("4")
    $script:noTe = $false
    Assert-Equal -Name "menu, Excel + Timeline Explorer when Timeline Explorer is not available: Excel only" -Expected $xlsx -Actual $r.Started

    # --- -Viewer (no menu) ------------------------------------------------------
    $viewerCases = @(
        @{ Viewer = "ExcelAndReport"; Xlsx = $true; Report = $pdf; Started = "$xlsx ; $pdf"; Warning = "" }
        @{ Viewer = "ExcelAndReport"; Xlsx = $true; Report = $html; Started = "$xlsx ; $html"; Warning = "" }
        @{ Viewer = "ExcelAndReport"; Xlsx = $true; Report = ""; Started = $xlsx; Warning = "WARNING:   -Viewer ExcelAndReport: no findings report was written, so only Excel is opened." }
        @{ Viewer = "ExcelAndReport"; Xlsx = $false; Report = $pdf; Started = $pdf; Warning = "WARNING:   -Viewer ExcelAndReport: no Excel file was generated, so only the findings report is opened." }
        @{ Viewer = "ExcelAndReport"; Xlsx = $false; Report = ""; Started = ""; Warning = "WARNING:   -Viewer ExcelAndReport: no Excel file was generated and no findings report was written, so nothing is opened." }
        @{ Viewer = "Excel"; Xlsx = $true; Report = $pdf; Started = $xlsx; Warning = "" }
        @{ Viewer = "Excel"; Xlsx = $false; Report = $pdf; Started = ""; Warning = "WARNING:   -Viewer Excel: no Excel file was generated, so Excel is not opened." }
        @{ Viewer = "TimelineExplorer"; Xlsx = $true; Report = $pdf; Started = "$te `"$csv`""; Warning = "" }
        @{ Viewer = "TimelineExplorer"; Xlsx = $false; Report = ""; Started = "$te `"$csv`""; Warning = "" }
        @{ Viewer = "Both"; Xlsx = $true; Report = $pdf; Started = "$xlsx ; $te `"$csv`""; Warning = "" }
        @{ Viewer = "Both"; Xlsx = $false; Report = $pdf; Started = "$te `"$csv`""; Warning = "WARNING:   -Viewer Both: no Excel file was generated, so Excel is not opened." }
        @{ Viewer = "Report"; Xlsx = $true; Report = $pdf; Started = $pdf; Warning = "" }
        @{ Viewer = "Report"; Xlsx = $true; Report = ""; Started = ""; Warning = "WARNING:   -Viewer Report: no findings report was written, so nothing is opened." }
        @{ Viewer = "None"; Xlsx = $true; Report = $pdf; Started = ""; Warning = "" }
    )
    foreach ($case in $viewerCases) {
        $r = Invoke-TestViewer -Choice $case.Viewer -Workbook $case.Xlsx -Report $case.Report
        $what = "workbook $(if ($case.Xlsx) { 'made' } else { 'not made' }), report $(if ($case.Report) { Split-Path $case.Report -Leaf } else { 'not written' })"
        Write-TestResult -Name "-Viewer $($case.Viewer), ${what}: starts '$($case.Started)'$(if ($case.Warning) { ' and warns' })" -Passed ($r.Started -ceq $case.Started -and $r.Warnings -ceq $case.Warning -and
            $r.Menu -eq "" -and $r.Prompts.Count -eq 0 -and (Get-Selection $r) -ceq "  Viewer selection: $($case.Viewer) (-Viewer)") -Message "started : $($r.Started)`nwarnings: $($r.Warnings)`nmenu    : $($r.Menu)`nprompts : $($r.Prompts.Count)`nselection: $(Get-Selection $r)"
    }
    $r = Invoke-TestViewer -Choice "ExcelAndReport" -Workbook $false -Report ""
    Write-TestResult -Name "-Viewer ExcelAndReport, neither file: the CSV is named" -Passed ($r.Log -contains "  No viewer launched. Files saved to:" -and $r.Log -contains "    CSV: $csv") -Message ($r.Log -join "`n")

    # --- One that cannot be started does not stop the other ----------------------
    $failXlsx = "C:\r\fail\timeline.xlsx"
    $r = Invoke-TestViewer -Choice "ExcelAndReport" -Workbook $true -Report $pdf -XlsxPath $failXlsx
    Write-TestResult -Name "-Viewer ExcelAndReport, Excel cannot be started: logged, and the report is still opened" -Passed ($r.Started -ceq $pdf -and
        $r.Warnings -like "WARNING:   Could not open Excel: *" -and $r.Log -contains "  Report opened: $pdf" -and -not ($r.Log -contains "  Excel launched with color-coded timeline.")) -Message "started: $($r.Started)`n$($r.Log -join "`n")"
    $failPdf = "C:\r\fail\report.pdf"
    $r = Invoke-TestViewer -Workbook $true -Report $failPdf -Answers @("1")
    Write-TestResult -Name "menu, answer 1, the report cannot be opened: logged, and Excel is still started" -Passed ($r.Started -ceq $xlsx -and
        $r.Warnings -like "WARNING:   Could not open the report: *" -and $r.Log -contains "  Excel launched with color-coded timeline.") -Message "started: $($r.Started)`n$($r.Log -join "`n")"

    # --- -Viewer in the builder's syntax tree and README.txt -------------------------
    Write-Host "Testing the -Viewer parameter ..."
    $viewerParameter = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "Viewer" })
    $validateSet = @($viewerParameter | ForEach-Object { $_.Attributes } | Where-Object {
            $_ -is [System.Management.Automation.Language.AttributeAst] -and $_.TypeName.Name -eq "ValidateSet" })
    $values = @()
    if ($validateSet.Count -eq 1) { $values = @($validateSet[0].PositionalArguments | ForEach-Object { $_.Value }) }
    Assert-Equal -Name "-Viewer's ValidateSet: ExcelAndReport, Excel, TimelineExplorer, Both, Report, None" -Expected "ExcelAndReport,Excel,TimelineExplorer,Both,Report,None" -Actual ($values -join ",")
    # Each value except None (the switch's default) has its own switch clause
    $switchAst = @($viewerAsts[0].FindAll({ param($node) $node -is [System.Management.Automation.Language.SwitchStatementAst] }, $true))
    $clauses = @()
    if ($switchAst.Count -ge 1) { $clauses = @($switchAst[0].Clauses | ForEach-Object { $_.Item1.Value }) }
    $unhandled = @($values | Where-Object { $_ -ne "None" -and $clauses -notcontains $_ })
    Write-TestResult -Name "every -Viewer value is handled by Invoke-TimelineViewer" -Passed ($values.Count -gt 0 -and $unhandled.Count -eq 0) -Message "not handled: $($unhandled -join ', ')"
    # README.txt's -Viewer entry names every value
    $readme = [System.IO.File]::ReadAllText((Join-Path $repoRoot "README.txt"))
    $entry = [regex]::Match($readme, '(?ms)^  -Viewer +(.+?)(?=^  -\w)')
    $missing = @($values | Where-Object { -not $entry.Success -or $entry.Groups[1].Value -notmatch "\b$_\b" })
    Write-TestResult -Name "README.txt's -Viewer entry names every value" -Passed ($entry.Success -and $missing.Count -eq 0) -Message "missing: $($missing -join ', ')"
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
