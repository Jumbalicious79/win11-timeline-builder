# =============================================================
# Findings report end-to-end test
# Runs timeline-builder.ps1 on the synthetic collection in
# tests\fixtures\report\builder\collection\ (Defender detections, Run keys
# and BAM rows) and checks what the report adds next to the timeline:
# findings.csv, report-model.json, report.html, report.pdf (skipped only
# when Microsoft Edge is missing), the copied collection_info.json and
# collection_log.txt and, when the workbook was made, its sheets (it opens
# on the full Timeline sheet; the second sheet "Findings" has hyperlinks to
# the Timeline rows) and the Timeline sheet's "Finding" column. Then:
#   -ReportOnly rebuilds the report in the same folder (one Findings sheet
#      and one Finding column, the same findings, no administrator rights
#      needed, no error output -- Windows PowerShell printed a Test-Path
#      binding error for the empty -InputPath);
#   a copy of the builder (in this test's folder) whose Find-VolatilityExe
#      gives a stub with canned Volatility 3 output, run with -MemoryDumpPath
#      on a synthetic dump header: the lead seen only in the memory dump says
#      "Captured in the memory dump" (report-model.json MemoryOnly,
#      findings.csv, the card, the Findings sheet) and the card's row
#      numbers, findings.csv's RowNumber, the Findings sheet's links and the
#      Finding column all point at its Memory-CommandLine row, also after a
#      -ReportOnly that updates the workbook; a lead that also has a BAM row
#      is not memory-only;
#   -ReportOnly -ReportRules <file> -NoExcel uses another rules file and
#      leaves the workbook alone (and says its findings are from an earlier
#      report); -WorkDir and -MemoryDumpPath are ignored with one warning;
#   -ReportOnly on a mounted-image timeline whose run ended with exit code
#      2: the examined computer from the run's log (SYSTEM hive), not the
#      collector host, and the incomplete timeline in the report;
#   a missing -ReportRules file and -NoReport leave the timeline intact
#      and write no report;
#   -ReportOnly works in a folder named "case [1]" (wildcard characters),
#      and a report.pdf held open elsewhere is reported as out of date while
#      the new PDF gets its own name;
#   -ReportOnly on a folder without a timeline fails cleanly;
#   an unexpected error injected into a copy of the builder (in this test's
#      folder): in the rebuild it is logged and the report is still made
#      (exit code 0); a rebuild that stops before it gives its exit code,
#      or an error thrown out of it, gives exit code 1, not 0.
# Before the runs: the builder's Get-TimelineReportCollectionInfo (from its
# syntax tree) takes a mounted image's computer name in collection_info.json
# as the collector host, and the SYSTEM hive's name as the examined one.
#
# Needs Administrator rights, like the builder (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -BuilderPath
# with a copy of the builder that has no admin check, with the lib\ folder
# beside it (e.g. under the git-ignored reports\ folder). Like a user
# run, the builder installs ImportExcel from the PowerShell Gallery when it
# is missing; if that is not possible, the workbook checks are SKIPPED.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ReportBuilder.ps1
# =============================================================
param(
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$builder = (Resolve-Path -LiteralPath $builder).Path
$builderDir = Split-Path $builder -Parent
$fixtureDir = Join-Path $PSScriptRoot "fixtures\report\builder"
$collection = Join-Path $fixtureDir "collection"
$script:failures = 0

# The findings the fixture must produce: rule id -> severity
$expected = [ordered]@{
    "PERSIST-RUNKEY-SUSPICIOUS" = "High"
    "AV-DETECTION-EICAR"        = "Medium"
    "EXEC-STAGING"              = "Medium"
    "PERSIST-RUNKEY-STAGING"    = "Medium"
    "AV-PUA"                    = "Info"
}

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-ReportBuilder.ps1::$Message" }
}

# The builder refuses to run without Administrator rights (a -BuilderPath
# copy may not)
if (-not $BuilderPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-TestResult -Succeeded $false -Message "Administrator rights are required (the builder needs them). Run elevated, or pass -BuilderPath with a builder copy without the admin check."
        exit 1
    }
}

# Run the builder with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path

# Runs the builder with the given arguments; returns its exit code, its
# output, and the lines it wrote to stderr (errors: a red PowerShell error
# such as Windows PowerShell's Test-Path binding error for an empty path)
function Invoke-TimelineBuilder {
    param([string[]]$Arguments)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $errorLines = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" } | Where-Object { $_.Trim() })
    return [PSCustomObject]@{ ExitCode = $exitCode; Output = @($output | ForEach-Object { "$_" }); Errors = $errorLines }
}

# The workbook's sheets and cells (ImportExcel / EPPlus), or $null when the
# module cannot be loaded in this PowerShell
function Read-TestWorkbook {
    param([string]$Path)
    try { Import-Module ImportExcel -ErrorAction Stop }
    catch { return $null }
    $package = Open-ExcelPackage -Path $Path
    try {
        $sheets = @($package.Workbook.Worksheets | ForEach-Object { $_.Name })
        $findingsRows = New-Object System.Collections.Generic.List[object]
        $findingsSheet = $package.Workbook.Worksheets["Findings"]
        $findingsSelected = $false
        if ($findingsSheet) {
            $findingsSelected = [bool]$findingsSheet.View.TabSelected
            for ($r = 2; $r -le $findingsSheet.Dimension.End.Row; $r++) {
                $values = @(for ($c = 1; $c -le 12; $c++) { [string]$findingsSheet.Cells[$r, $c].Value })
                $link = $findingsSheet.Cells[$r, 4].Hyperlink
                $linkText = ""
                if ($link) { $linkText = [string]$link.ReferenceAddress }
                $findingsRows.Add([PSCustomObject]@{
                    Finding     = $values[0]
                    Severity    = $values[1]
                    RowType     = $values[2]
                    Row         = $values[3]
                    Link        = $linkText
                    Time        = $values[4]
                    Description = $values[6]
                    Rule        = $values[11]
                })
            }
        }
        $timeline = $package.Workbook.Worksheets["Timeline"]
        $timelineSelected = [bool]$timeline.View.TabSelected
        $activeTab = [int]$package.Workbook.View.ActiveTab
        $headers = @(for ($c = 1; $c -le $timeline.Dimension.End.Column; $c++) { [string]$timeline.Cells[1, $c].Value })
        $findingColumn = [Array]::IndexOf($headers, "Finding") + 1
        $timelineRows = @(for ($r = 2; $r -le $timeline.Dimension.End.Row; $r++) {
            $timestamp = [string]$timeline.Cells[$r, 1].Value
            $tag = ""
            if ($findingColumn -gt 0) { $tag = [string]$timeline.Cells[$r, $findingColumn].Value }
            [PSCustomObject]@{ Row = $r; Timestamp = $timestamp; Source = [string]$timeline.Cells[$r, 2].Value; Finding = $tag }
        })
        return [PSCustomObject]@{
            Sheets           = $sheets
            FindingsSelected = $findingsSelected
            TimelineSelected = $timelineSelected
            ActiveTab        = $activeTab
            FindingsRows     = $findingsRows.ToArray()
            Headers          = $headers
            TimelineRows     = $timelineRows
        }
    }
    finally { Close-ExcelPackage $package -NoSave }
}

# The Timeline sheet's column widths ("Header=width", widths rounded), or
# $null when ImportExcel cannot be loaded; with -SetColumn/-SetWidth, sets
# that column's width first and saves (an older builder's autosized width)
function Get-TestTimelineWidths {
    param([string]$Path, [int]$SetColumn = 0, [double]$SetWidth = 0)
    try { Import-Module ImportExcel -ErrorAction Stop }
    catch { return $null }
    $package = Open-ExcelPackage -Path $Path
    $save = $false
    try {
        $sheet = $package.Workbook.Worksheets["Timeline"]
        if ($SetColumn -gt 0) { $sheet.Column($SetColumn).Width = $SetWidth; $save = $true }
        return @(for ($c = 1; $c -le $sheet.Dimension.End.Column; $c++) { "$([string]$sheet.Cells[1, $c].Value)=$([Math]::Round($sheet.Column($c).Width))" })
    }
    finally {
        if ($save) { Close-ExcelPackage $package } else { Close-ExcelPackage $package -NoSave }
    }
}

# Checks the lead seen only in the memory dump of the memory run (section
# 2b) in a run folder: "Captured in the memory dump" in report-model.json
# (MemoryOnly), findings.csv, the card and the Findings sheet, and every
# pointer to its rows -- RowNumbers, findings.csv's RowNumber, the card's
# row numbers, the Findings sheet's links and the Finding column -- on its
# Memory-CommandLine row of the timeline. The lead that also has a BAM row
# is not memory-only.
function Test-MemoryOnlyLead {
    param([string]$Folder, [string]$Label)
    $note = "Captured in the memory dump"
    $rows = @(Import-Csv -LiteralPath (Join-Path $Folder "timeline.csv"))
    $memoryModel = Get-Content -LiteralPath (Join-Path $Folder "report-model.json") -Raw | ConvertFrom-Json
    $memoryLeads = @($memoryModel.Findings | Where-Object { $_.MemoryOnly })
    $lead = @($memoryLeads | Where-Object { $_.RuleId -eq "EXEC-STAGING" -and $_.GroupKey -eq "fixture-stage.exe" })
    $mixed = @($memoryModel.Findings | Where-Object { $_.RuleId -eq "EXEC-STAGING" -and $_.GroupKey -eq "fixture-invoice.exe" })
    Write-TestResult -Succeeded ($memoryLeads.Count -eq 1 -and $lead.Count -eq 1 -and $lead[0].MemoryOnlyNote -ceq $note -and -not $lead[0].CapturedDuringCollection -and $lead[0].Severity -eq "Medium" -and
        $mixed.Count -eq 1 -and $mixed[0].PSObject.Properties["MemoryOnly"] -and -not $mixed[0].MemoryOnly -and -not $mixed[0].MemoryOnlyNote) -Message "${Label}: report-model.json marks the lead seen only in the memory dump MemoryOnly ('$note', still a Medium lead, not CapturedDuringCollection), and not the lead that also has a BAM row"
    $id = "(no memory-only lead)"
    if ($lead.Count -eq 1) { $id = [string]$lead[0].Id }
    $memoryRows = (@(for ($i = 0; $i -lt $rows.Count; $i++) { if ($rows[$i].Source -eq "Memory-CommandLine" -and $rows[$i].Description -like "Process command line: fixture-stage.exe *") { $i + 2 } }) -join ",")
    Write-TestResult -Succeeded ($memoryRows -match '^\d+$' -and (@($lead | ForEach-Object { $_.RowNumbers }) -join ",") -eq $memoryRows) -Message "${Label}: ${id}'s RowNumbers are its Memory-CommandLine row of the timeline ($memoryRows)"

    # findings.csv: the note on the summary line, the row on the evidence line
    $lines = @(Import-Csv -LiteralPath (Join-Path $Folder "findings.csv") | Where-Object { $_.FindingId -eq $id })
    $summaryLine = @($lines | Where-Object { -not $_.RowNumber })
    $evidenceLines = @($lines | Where-Object { $_.RowNumber })
    Write-TestResult -Succeeded ($summaryLine.Count -eq 1 -and $summaryLine[0].Description.EndsWith("; $note") -and (@($evidenceLines | ForEach-Object { $_.RowNumber }) -join ",") -eq $memoryRows -and
        @($evidenceLines | Where-Object { $_.Source -ne "Memory-CommandLine" }).Count -eq 0) -Message "${Label}: findings.csv ends ${id}'s summary line with '$note' and gives its evidence line RowNumber $memoryRows"

    # report.html (printed to report.pdf): the card's note and row numbers
    $html = [System.IO.File]::ReadAllText((Join-Path $Folder "report.html"))
    $cardStart = $html.IndexOf('id="finding-' + $id + '"')
    $card = ""
    if ($cardStart -ge 0) { $card = $html.Substring($cardStart, $html.IndexOf('</article>', $cardStart) - $cardStart) }
    $cardRows = @([regex]::Matches($card, '<td class="num mono">(\d+)</td>') | ForEach-Object { $_.Groups[1].Value }) -join ","
    $cardFlags = @([regex]::Matches($card, '<span class="flag[^"]*">(.*?)</span>') | ForEach-Object { $_.Groups[1].Value })
    Write-TestResult -Succeeded (($cardFlags -join "|") -ceq $note -and $cardRows -eq $memoryRows) -Message "${Label}: ${id}'s card says exactly '$note' and lists row $memoryRows ($($cardFlags -join ' | '); rows $cardRows)"

    # The workbook: the card's Excel pointer, the Findings sheet's rows and
    # links, the Finding column
    $xlsx = Join-Path $Folder "timeline.xlsx"
    if (-not (Test-Path -LiteralPath $xlsx)) {
        Write-Host "SKIP: ${Label}: timeline.xlsx was not created (ImportExcel missing and not installable here); workbook checks skipped" -ForegroundColor Yellow
        return
    }
    $book = Read-TestWorkbook -Path $xlsx
    if (-not $book) {
        Write-Host "SKIP: ${Label}: ImportExcel cannot be loaded in this PowerShell; workbook checks skipped" -ForegroundColor Yellow
        return
    }
    Write-TestResult -Succeeded ($memoryModel.Workbook.Available -and $card.Contains('href="./timeline.xlsx"') -and $card.Contains("filter the &quot;Finding&quot; column of the &quot;Timeline&quot; sheet for $id.")) -Message "${Label}: ${id}'s card points at the workbook and at its id in the Finding column"
    $sheetRows = @($book.FindingsRows | Where-Object { $_.Finding -eq $id })
    $sheetSummary = @($sheetRows | Where-Object { $_.RowType -eq "Summary" })
    $sheetEvidence = @($sheetRows | Where-Object { $_.RowType -ne "Summary" })
    $badLinks = @($sheetRows | Where-Object {
        $target = $book.TimelineRows | Where-Object Row -eq ([int]$_.Row)
        $_.Link -ne "'Timeline'!A$($_.Row)" -or -not $target -or $target.Timestamp -ne $_.Time -or $target.Source -ne "Memory-CommandLine"
    })
    Write-TestResult -Succeeded ($sheetSummary.Count -eq 1 -and $sheetSummary[0].Description.EndsWith("; $note") -and (@($sheetEvidence | ForEach-Object { $_.Row }) -join ",") -eq $memoryRows -and
        $badLinks.Count -eq 0) -Message "${Label}: the Findings sheet ends ${id}'s summary row with '$note', and its rows link to Timeline row $memoryRows ($($sheetRows.Count) rows, $($badLinks.Count) wrong links)"
    $tagged = @($book.TimelineRows | Where-Object { @($_.Finding -split ', ') -contains $id } | ForEach-Object { $_.Row }) -join ","
    Write-TestResult -Succeeded ($tagged -eq $memoryRows) -Message "${Label}: the Timeline sheet's Finding column tags $id on row $memoryRows only ($tagged)"
}

# Checks the collector-fixture run (section 2c): the collector's 6 processes
# are not flagged and are listed (model, report.html, findings.csv, workbook),
# while the attacker script (invoice.vbs) and the same-name impostor
# (triage-collector.ps1, another PID) are flagged, the impostor on its own row.
function Test-CollectorFixture {
    param([string]$Folder, [string]$Label)
    $rows = @(Import-Csv -LiteralPath (Join-Path $Folder "timeline.csv"))
    $model = Get-Content -LiteralPath (Join-Path $Folder "report-model.json") -Raw | ConvertFrom-Json
    $cp = $model.Coverage.CollectorProcesses
    # The fixture's collection_info.json has every field the current
    # collector writes, in its order (the provenance fields right after
    # SchemaVersion, CollectorGitCommit null as for a copy outside a git
    # checkout, CollectorProcesses last): the fields the report uses are read
    $c = $model.Collection
    Write-TestResult -Succeeded ($c -and $c.ComputerName -eq "COLLECTOR-FIX" -and $c.Mode -eq "Live" -and $c.TargetTimeZoneId -eq "UTC" -and $c.CollectorUser -eq "FIXTURE\analyst" -and
        $c.SecretsIncluded -eq $false -and $c.ThunderbirdIndexIncluded -eq $false) -Message "${Label}: the current collector's full collection_info.json is read (computer '$($c.ComputerName)', mode '$($c.Mode)', user '$($c.CollectorUser)')"
    Write-TestResult -Succeeded ($cp -and [bool]$cp.Recorded -and [int]$cp.Count -eq 6 -and $cp.Summary -eq "Collector's own processes in the memory dump: 6 (not flagged)") -Message "${Label}: model marks 6 collector processes not flagged ($($cp.Summary))"
    $colRowNums = @($cp.Processes | ForEach-Object { $_.RowNumbers } | ForEach-Object { [int]$_ } | Sort-Object -Unique)
    $allFind = @($model.Findings) + @($model.InfoFindings)
    $flaggedRows = @($allFind | ForEach-Object { $_.RowNumbers } | ForEach-Object { [int]$_ })
    $overlap = @($colRowNums | Where-Object { $flaggedRows -contains $_ })
    Write-TestResult -Succeeded ($overlap.Count -eq 0) -Message "${Label}: no finding holds a collector row ($($overlap.Count) overlap(s))"
    $exec = @($model.Findings | Where-Object { $_.RuleId -eq "EXEC-STAGING" })
    $keys = @($exec | ForEach-Object { $_.GroupKey } | Sort-Object)
    Write-TestResult -Succeeded (($keys -contains "invoice.vbs") -and ($keys -contains "triage-collector.ps1")) -Message "${Label}: the attacker script (invoice.vbs) and the same-name impostor (triage-collector.ps1) are flagged ($($keys -join ', '))"
    $launcherRow = (@(for ($i = 0; $i -lt $rows.Count; $i++) { if ($rows[$i].Source -eq "Memory-CommandLine" -and $rows[$i].Description -eq "Process command line: cmd.exe (PID: 8840)") { $i + 2 } }))[0]
    Write-TestResult -Succeeded ($launcherRow -and -not ($keys -contains "Run-TriageCollector.bat") -and ($colRowNums -contains [int]$launcherRow) -and [int]$cp.OutsideTree -eq 0 -and
        @($model.Coverage.Notes | Where-Object { $_ -match "was altered" }).Count -eq 0) -Message "${Label}: the launcher's Run-TriageCollector.bat command line (row $launcherRow) is left out with the collector, not an EXEC-STAGING lead; no altered note"
    $impRow = (@(for ($i = 0; $i -lt $rows.Count; $i++) { if ($rows[$i].Source -eq "Memory-CommandLine" -and $rows[$i].Description -eq "Process command line: powershell.exe (PID: 7000)") { $i + 2 } }))[0]
    $colCmdRow = (@(for ($i = 0; $i -lt $rows.Count; $i++) { if ($rows[$i].Source -eq "Memory-CommandLine" -and $rows[$i].Description -eq "Process command line: powershell.exe (PID: 9120)") { $i + 2 } }))[0]
    $triage = @($exec | Where-Object { $_.GroupKey -eq "triage-collector.ps1" })
    Write-TestResult -Succeeded ($triage.Count -eq 1 -and (@($triage[0].RowNumbers) -contains $impRow) -and -not (@($triage[0].RowNumbers) -contains $colCmdRow)) -Message "${Label}: triage-collector.ps1 is flagged on the impostor's row ($impRow), not the collector's ($colCmdRow)"
    $csv = @(Import-Csv -LiteralPath (Join-Path $Folder "findings.csv"))
    $block = @($csv | Where-Object { $_.FindingId -eq "Collector" })
    $blockSummary = @($block | Where-Object { -not $_.RowNumber })
    Write-TestResult -Succeeded ($blockSummary.Count -eq 1 -and $blockSummary[0].Severity -eq "Not flagged" -and @($block | Where-Object { $_.RowNumber }).Count -eq [int]$cp.RowCount) -Message "${Label}: findings.csv has the Collector block (summary + $([int]$cp.RowCount) row line(s))"
    $html = [System.IO.File]::ReadAllText((Join-Path $Folder "report.html"))
    Write-TestResult -Succeeded ($html.Contains("Collector&#39;s own processes in the memory dump: 6 (not flagged)") -and $html.Contains("The collector&#39;s own processes (not flagged)")) -Message "${Label}: report.html shows the collector summary and the Evidence-coverage subsection"
    $tableWrong = @($cp.Processes | Where-Object { -not $html.Contains('<tr><td class="mono">' + (@($_.RowNumbers) -join ", ") + '</td><td class="num">' + $_.Pid + '</td><td class="num">' + $_.ParentPid + '</td>') })
    Write-TestResult -Succeeded (@($cp.Processes).Count -eq 6 -and $tableWrong.Count -eq 0) -Message "${Label}: report.html's collector table gives each process's timeline rows and its plain PID and parent PID ($($tableWrong.Count) wrong)"
    $xlsx = Join-Path $Folder "timeline.xlsx"
    if (-not (Test-Path -LiteralPath $xlsx)) {
        Write-Host "SKIP: ${Label}: timeline.xlsx not created; workbook checks skipped" -ForegroundColor Yellow
        return
    }
    $book = Read-TestWorkbook -Path $xlsx
    if (-not $book) {
        Write-Host "SKIP: ${Label}: ImportExcel cannot be loaded; workbook checks skipped" -ForegroundColor Yellow
        return
    }
    $sheetBlock = @($book.FindingsRows | Where-Object { $_.Finding -eq "Collector" })
    Write-TestResult -Succeeded (@($sheetBlock | Where-Object { $_.RowType -eq "Summary" }).Count -eq 1 -and @($sheetBlock | Where-Object { $_.RowType -ne "Summary" }).Count -eq [int]$cp.RowCount -and
        @($sheetBlock | Where-Object { $_.Severity -ne "Not flagged" }).Count -eq 0) -Message "${Label}: the Findings sheet has the Collector summary row and its left-out rows, all 'Not flagged' (as in findings.csv)"
    $tagged = @($book.TimelineRows | Where-Object { $_.Finding -eq "Collector (not flagged)" } | ForEach-Object { [int]$_.Row } | Sort-Object -Unique)
    $tagWrong = @($tagged | Where-Object { $colRowNums -notcontains $_ }) + @($colRowNums | Where-Object { $tagged -notcontains $_ })
    Write-TestResult -Succeeded ($tagWrong.Count -eq 0) -Message "${Label}: the Timeline sheet's Finding column tags the collector rows 'Collector (not flagged)' ($($tagged.Count) of $($colRowNums.Count))"
}

# Report folders the builder writes under its own reports\ (for its log)
$reportsDir = Join-Path $builderDir "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-report-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    . (Join-Path $repoRoot "lib\report\TimelineReport.Render.ps1")
    $edge = Find-ReportPdfEdge

    # --- 0. What the report says about the collection (the builder's
    # Get-TimelineReportCollectionInfo, loaded from its syntax tree) ---
    $builderAst = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$null)
    $infoFunction = @($builderAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Get-TimelineReportCollectionInfo" }, $true))[0]
    . ([scriptblock]::Create($infoFunction.Extent.Text))
    function Log-Warning { param([string]$Message) Write-Host "WARNING: $Message" }
    $infoDir = Join-Path $workDir "info"
    New-Item -ItemType Directory -Path $infoDir | Out-Null
    $imageJson = Join-Path $infoDir "collection_info.json"
    [System.IO.File]::WriteAllText($imageJson, '{ "SchemaVersion": 1, "ComputerName": "ANALYST-WS", "CollectorUser": "ANALYST-WS\\examiner", "Mode": "MountedImage", "CollectionStartUtc": "2026-03-02T12:00:00Z", "TargetTimeZoneId": "UTC" }')
    $imageInfo = Get-TimelineReportCollectionInfo -InfoJsonPath $imageJson
    Write-TestResult -Succeeded ($imageInfo.ComputerName -eq "" -and $imageInfo.CollectorHost -eq "ANALYST-WS" -and $imageInfo.ComputerNameSource -eq "") -Message "mounted image: collection_info.json's computer is the collector host, not the examined computer ('$($imageInfo.ComputerName)', host '$($imageInfo.CollectorHost)')"
    $hiveInfo = Get-TimelineReportCollectionInfo -InfoJsonPath $imageJson -BuilderInfo ([PSCustomObject]@{ Mode = "MountedImage"; ComputerName = "ANALYST-WS" }) -ExaminedComputerName "IMAGED-PC"
    Write-TestResult -Succeeded ($hiveInfo.ComputerName -eq "IMAGED-PC" -and $hiveInfo.ComputerNameSource -eq "SYSTEM hive" -and $hiveInfo.CollectorHost -eq "ANALYST-WS") -Message "mounted image: the examined computer's name from the SYSTEM hive ('$($hiveInfo.ComputerName)')"
    # The workbook validates (no repair needed): opening it in Excel must not
    # tell the user to accept a repair, which could hide real damage
    $viewerFunction = @($builderAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Invoke-TimelineViewer" }, $true))
    Write-TestResult -Succeeded ($viewerFunction.Count -eq 1 -and $viewerFunction[0].Extent.Text -notmatch 'repair') -Message "opening Excel logs no 'Excel may prompt to repair the file' note"
    $liveInfo = Get-TimelineReportCollectionInfo -InfoJsonPath (Join-Path $collection "collection_info.json") -ExaminedComputerName "HIVE-NAME"
    Write-TestResult -Succeeded ($liveInfo.ComputerName -eq "REPORT-FIXTURE" -and $liveInfo.ComputerNameSource -eq "collection_info.json" -and $liveInfo.CollectorHost -eq "" -and $liveInfo.ExaminedComputerName -eq "HIVE-NAME") -Message "live collection: the computer from collection_info.json ('$($liveInfo.ComputerName)')"
    # Whether collection_info.json was read, is missing or could not be read
    # (the report then says why the collector's own process IDs are unknown)
    $badJson = Join-Path $infoDir "truncated.json"
    [System.IO.File]::WriteAllText($badJson, '{ "SchemaVersion": 1, "Mode": "Live", "CollectorProcesses": [ { "Role": "Collec')
    $emptyJson = Join-Path $infoDir "empty-processes.json"
    [System.IO.File]::WriteAllText($emptyJson, '{ "SchemaVersion": 1, "Mode": "Live", "CollectionStartUtc": "2026-03-02T12:00:00Z", "CollectorProcesses": [] }')
    $badInfo = Get-TimelineReportCollectionInfo -InfoJsonPath $badJson
    $missingInfo = Get-TimelineReportCollectionInfo -InfoJsonPath (Join-Path $infoDir "no-such-file.json")
    $emptyInfo = Get-TimelineReportCollectionInfo -InfoJsonPath $emptyJson
    Write-TestResult -Succeeded ($liveInfo.CollectionInfoState -eq "Read" -and $badInfo.CollectionInfoState -eq "Unreadable" -and $missingInfo.CollectionInfoState -eq "Missing" -and
        $emptyInfo.CollectionInfoState -eq "Read" -and $null -ne $emptyInfo.CollectorProcesses -and @($emptyInfo.CollectorProcesses).Count -eq 0) -Message "collection_info.json read ($($liveInfo.CollectionInfoState)), truncated ($($badInfo.CollectionInfoState)), missing ($($missingInfo.CollectionInfoState)); an empty CollectorProcesses stays an empty field, not an absent one"

    # --- 1. A full builder run writes the report next to the timeline ---
    $runDir = Join-Path $workDir "run"
    New-Item -ItemType Directory -Path $runDir | Out-Null
    $timelineCsv = Join-Path $runDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $run = Invoke-TimelineBuilder -Arguments @("-InputPath", $collection, "-Sources", "EventLogs,Persistence,PowerShellHistory", "-OutputFile", $timelineCsv, "-Viewer", "None")
    Write-TestResult -Succeeded ($run.ExitCode -eq 0 -and (Test-Path -LiteralPath $timelineCsv)) -Message "the builder exits with 0 and writes timeline.csv (exit code $($run.ExitCode))"
    if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $run.Output | Select-Object -Last 40 | ForEach-Object { Write-Host "  | $_" }
        throw "the builder did not produce a timeline"
    }
    $timelineRows = @(Import-Csv -LiteralPath $timelineCsv)
    Write-TestResult -Succeeded ($timelineRows.Count -ge 9 -and -not ($timelineRows[0].PSObject.Properties.Name -contains "Finding")) -Message "timeline.csv has the fixture rows ($($timelineRows.Count)) and no Finding column (its schema is unchanged)"
    $reportLogLines = @($run.Output | Where-Object { $_ -match 'Running Report Rules' -or $_ -match '\d+ finding\(s\) in [\d.]+ s: High \d+, Medium \d+, Info \d+' })
    Write-TestResult -Succeeded ($reportLogLines.Count -ge 2) -Message "the builder logs the report rules step with its time and counts per severity"
    $afterRules = $false
    $reportWarnings = @(foreach ($line in $run.Output) {
        if ($line -match '--- Running Report Rules ---') { $afterRules = $true }
        elseif ($afterRules -and $line -match 'WARNING:' -and $line -match 'report|finding|rule|PDF|workbook') {
            # Without Edge the PDF warning is expected
            if (-not ($line -match 'PDF not created' -and -not $edge)) { $line }
        }
    })
    Write-TestResult -Succeeded ($reportWarnings.Count -eq 0) -Message "the report steps log no warnings ($($reportWarnings -join ' / '))"

    # findings.csv: UTF-8 with BOM, a summary line per finding and its evidence lines
    $findingsCsv = Join-Path $runDir "findings.csv"
    $findingsBytes = [System.IO.File]::ReadAllBytes($findingsCsv)
    Write-TestResult -Succeeded ($findingsBytes.Length -gt 3 -and $findingsBytes[0] -eq 0xEF -and $findingsBytes[1] -eq 0xBB -and $findingsBytes[2] -eq 0xBF) -Message "findings.csv is UTF-8 with a BOM (for Excel)"
    $findingLines = @(Import-Csv -LiteralPath $findingsCsv)
    $columns = @($findingLines[0].PSObject.Properties.Name)
    Write-TestResult -Succeeded (($columns -join ",") -eq "FindingId,Severity,RuleId,Title,Category,RowNumber,Timestamp,Source,Description") -Message "findings.csv has the agreed columns ($($columns -join ','))"
    $summaries = @($findingLines | Where-Object { -not $_.RowNumber })
    $found = [ordered]@{}
    foreach ($line in $summaries) { $found[$line.RuleId] = $line.Severity }
    $expectedText = @($expected.Keys | Sort-Object | ForEach-Object { "$_=$($expected[$_])" }) -join ", "
    $foundText = @($found.Keys | Sort-Object | ForEach-Object { "$_=$($found[$_])" }) -join ", "
    Write-TestResult -Succeeded ($summaries.Count -eq $expected.Count -and $foundText -eq $expectedText) -Message "the fixture gives exactly the expected findings and severities ($foundText)"
    $ids = @($summaries | ForEach-Object { $_.FindingId })
    Write-TestResult -Succeeded (($ids -join ",") -eq "F001,F002,F003,F004,F005" -and $summaries[0].Severity -eq "High" -and $summaries[-1].Severity -eq "Info") -Message "findings are numbered F001... High first, Info last ($($ids -join ','))"
    $evidence = @($findingLines | Where-Object { $_.RowNumber })
    $badEvidence = @($evidence | Where-Object {
        $row = $timelineRows[[int]$_.RowNumber - 2]
        -not $row -or $row.Timestamp -ne $_.Timestamp -or $row.Source -ne $_.Source -or $row.Description -ne $_.Description
    })
    Write-TestResult -Succeeded ($evidence.Count -ge $expected.Count -and $badEvidence.Count -eq 0) -Message "every evidence line's RowNumber is that row of the timeline (header = row 1): $($evidence.Count) lines, $($badEvidence.Count) wrong"

    # report-model.json
    $model = Get-Content -LiteralPath (Join-Path $runDir "report-model.json") -Raw | ConvertFrom-Json
    Write-TestResult -Succeeded ($model.Counts.High -eq 1 -and $model.Counts.Medium -eq 3 -and $model.Counts.Info -eq 1 -and @($model.Findings).Count -eq 4 -and @($model.InfoFindings).Count -eq 1) -Message "report-model.json counts 1 High, 3 Medium and 1 Info"
    Write-TestResult -Succeeded ($model.Collection.ComputerName -eq "REPORT-FIXTURE" -and $model.Collection.TargetTimeZoneId -eq "Pacific Standard Time" -and $model.Collection.CollectorUser -eq "FIXTURE\analyst") -Message "the model takes the computer, time zone and collector user from collection_info.json"
    Write-TestResult -Succeeded (@($model.Rules).Count -gt 40 -and $model.Files.TimelineCsv -eq "timeline.csv") -Message "the model lists the rules used and the timeline file"

    # Copied inputs for -ReportOnly
    $copiesMatch = $true
    foreach ($name in @("collection_info.json", "collection_log.txt")) {
        $copy = Join-Path $runDir $name
        if (-not (Test-Path -LiteralPath $copy) -or (Get-FileHash -LiteralPath $copy).Hash -ne (Get-FileHash -LiteralPath (Join-Path $collection $name)).Hash) { $copiesMatch = $false }
    }
    Write-TestResult -Succeeded $copiesMatch -Message "collection_info.json and collection_log.txt are copied next to the timeline"

    # report.html
    $htmlPath = Join-Path $runDir "report.html"
    $htmlBytes = [System.IO.File]::ReadAllBytes($htmlPath)
    Write-TestResult -Succeeded (@($htmlBytes | Where-Object { $_ -gt 127 }).Count -eq 0) -Message "report.html is ASCII only"
    $html = [System.IO.File]::ReadAllText($htmlPath)
    $missingIds = @($ids | Select-Object -First 4 | Where-Object { -not $html.Contains('id="finding-' + $_ + '"') })
    Write-TestResult -Succeeded ($html.Contains("REPORT-FIXTURE") -and $missingIds.Count -eq 0 -and $html.Contains("What this report can&#39;t tell you") -and -not $html.Contains("<script")) -Message "report.html has the summary, a card for every lead and no script"
    $csvHash = (Get-FileHash -LiteralPath $timelineCsv -Algorithm SHA256).Hash
    Write-TestResult -Succeeded ($html.Contains($csvHash) -and -not $html.Contains(">Hashes<")) -Message "report.html's file list gives timeline.csv's SHA-256"

    # report.pdf
    $pdfPath = Join-Path $runDir "report.pdf"
    $xlsxPath = Join-Path $runDir "timeline.xlsx"
    if (-not $edge) {
        Write-Host "SKIP: Microsoft Edge (msedge.exe) was not found; report.pdf checks skipped" -ForegroundColor Yellow
        Write-TestResult -Succeeded (-not (Test-Path -LiteralPath $pdfPath)) -Message "without Edge no report.pdf is written (report.html stays complete)"
    }
    else {
        Write-TestResult -Succeeded (Test-Path -LiteralPath $pdfPath) -Message "report.pdf is written (Edge: $edge)"
        if (Test-Path -LiteralPath $pdfPath) {
            $pdfText = [System.Text.Encoding]::GetEncoding(28591).GetString([System.IO.File]::ReadAllBytes($pdfPath))
            Write-TestResult -Succeeded ($pdfText.StartsWith("%PDF-") -and -not $pdfText.Contains("file:///")) -Message "report.pdf is a PDF and holds no local file:/// path"
            if (Test-Path -LiteralPath $xlsxPath) {
                Write-TestResult -Succeeded ([regex]::IsMatch($pdfText, '/URI\s*\(\./timeline\.xlsx\)')) -Message "report.pdf links to the workbook with the relative link ./timeline.xlsx"
            }
        }
    }

    # The workbook: Timeline first and selected, Findings second, hyperlinks, Finding column
    $workbook = $null
    $firstFindingColumn = @()
    if (-not (Test-Path -LiteralPath $xlsxPath)) {
        Write-Host "SKIP: timeline.xlsx was not created (ImportExcel missing and not installable here); workbook checks skipped" -ForegroundColor Yellow
        Write-TestResult -Succeeded (-not $model.Workbook.Available -and $html.Contains(">CSV row</th>")) -Message "without the workbook the report gives timeline.csv row numbers"
    }
    else {
        $workbook = Read-TestWorkbook -Path $xlsxPath
        if (-not $workbook) {
            Write-Host "SKIP: ImportExcel cannot be loaded in this PowerShell; workbook checks skipped" -ForegroundColor Yellow
        }
        else {
            Write-TestResult -Succeeded ($model.Workbook.Available -and $html.Contains('href="./timeline.xlsx"')) -Message "the report links to the workbook"
            Write-TestResult -Succeeded (($workbook.Sheets -join ",") -eq "Timeline,Findings" -and $workbook.TimelineSelected -and -not $workbook.FindingsSelected -and $workbook.ActiveTab -eq 0) -Message "the workbook opens on the full Timeline sheet (first and only selected); Findings is the second sheet ($($workbook.Sheets -join ', '); active tab $($workbook.ActiveTab))"
            $summaryRows = @($workbook.FindingsRows | Where-Object { $_.RowType -eq "Summary" })
            $evidenceRows = @($workbook.FindingsRows | Where-Object { $_.RowType -ne "Summary" })
            Write-TestResult -Succeeded ($summaryRows.Count -eq $expected.Count -and (@($summaryRows | ForEach-Object { $_.Finding }) -join ",") -eq ($ids -join ",")) -Message "the Findings sheet has a summary row per finding"
            $badLinks = @($workbook.FindingsRows | Where-Object {
                $target = $workbook.TimelineRows | Where-Object Row -eq ([int]$_.Row)
                $_.Link -ne "'Timeline'!A$($_.Row)" -or -not $target -or $target.Timestamp -ne $_.Time
            })
            Write-TestResult -Succeeded ($evidenceRows.Count -eq $evidence.Count -and $badLinks.Count -eq 0) -Message "every Findings row links to its Timeline row ('Timeline'!A<row>, same time): $($workbook.FindingsRows.Count) rows, $($badLinks.Count) wrong"
            Write-TestResult -Succeeded ($workbook.Headers[-1] -eq "Finding" -and @($workbook.Headers | Where-Object { $_ -eq "Finding" }).Count -eq 1) -Message "the Timeline sheet has one Finding column, after the timeline's columns"
            $wrongTags = @($workbook.TimelineRows | Where-Object {
                $tagRow = $_.Row
                $want = @($evidence | Where-Object { [int]$_.RowNumber -eq $tagRow } | ForEach-Object { $_.FindingId } | Sort-Object -Unique) -join ", "
                $_.Finding -ne $want
            })
            Write-TestResult -Succeeded ($wrongTags.Count -eq 0) -Message "the Finding column tags exactly the rows of each finding ($($wrongTags.Count) wrong)"
            $firstFindingColumn = @($workbook.TimelineRows | ForEach-Object { $_.Finding })
            # Export-Excel -AutoSize fits each column to its longest text;
            # the builder caps the Timeline sheet's widths at 80 so that
            # Description and Details stay on the screen (the fixture's
            # Details are longer than that)
            $widths = @(Get-TestTimelineWidths -Path $xlsxPath)
            $wide = @($widths | Where-Object { [double]($_ -replace '^.*=', '') -gt 80 })
            Write-TestResult -Succeeded ($widths.Count -ge 8 -and $wide.Count -eq 0 -and @($widths | Where-Object { $_ -eq "Details=80" }).Count -eq 1) -Message "the Timeline sheet's columns are at most 80 wide, Details capped at 80 ($($widths -join ', '))"
        }
    }
    $excelLines = @($run.Output | Where-Object { $_ -match 'rows to Excel with' })
    Write-TestResult -Succeeded ($excelLines.Count -eq 0 -or ($excelLines[0] -match 'with row colors' -and $excelLines[0] -notmatch 'conditional formatting')) -Message "the Excel step says 'with row colors', not 'conditional formatting' (the workbook has none): $($excelLines -join ' / ')"

    # --- 2. -ReportOnly rebuilds the report in the same folder ---
    $firstFindings = [System.IO.File]::ReadAllText($findingsCsv)
    $firstHtmlTime = (Get-Item -LiteralPath $htmlPath).LastWriteTimeUtc
    # A workbook from an older builder has autosized columns: Details as
    # wide as its longest text in the first 1,000 rows
    if ($workbook) { $null = Get-TestTimelineWidths -Path $xlsxPath -SetColumn 6 -SetWidth 300 }
    Start-Sleep -Milliseconds 1100
    $rebuild = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $runDir, "-Viewer", "None")
    Write-TestResult -Succeeded ($rebuild.ExitCode -eq 0 -and (Test-Path -LiteralPath (Join-Path $runDir "report_log.txt"))) -Message "-ReportOnly <folder> exits with 0 and logs to report_log.txt (exit code $($rebuild.ExitCode))"
    if ($rebuild.ExitCode -ne 0) { $rebuild.Output | Select-Object -Last 30 | ForEach-Object { Write-Host "  | $_" } }
    Write-TestResult -Succeeded ($rebuild.Errors.Count -eq 0 -and @($rebuild.Output | Where-Object { $_ -match 'Cannot bind argument|ParameterBindingValidationException' }).Count -eq 0) -Message "-ReportOnly writes no error (no binding error for the empty -InputPath in Windows PowerShell): $($rebuild.Errors -join ' / ')"
    Write-TestResult -Succeeded ([System.IO.File]::ReadAllText($findingsCsv) -eq $firstFindings -and (Get-Item -LiteralPath $htmlPath).LastWriteTimeUtc -gt $firstHtmlTime) -Message "-ReportOnly rewrites the report with the same findings"
    $rebuiltModel = Get-Content -LiteralPath (Join-Path $runDir "report-model.json") -Raw | ConvertFrom-Json
    Write-TestResult -Succeeded ($rebuiltModel.Collection.ComputerName -eq "REPORT-FIXTURE" -and $rebuiltModel.Collection.CollectorUser -eq "FIXTURE\analyst") -Message "-ReportOnly reads the copied collection_info.json"
    if ($workbook) {
        $rebuiltWorkbook = Read-TestWorkbook -Path $xlsxPath
        Write-TestResult -Succeeded ($rebuiltModel.Workbook.Available -and ($rebuiltWorkbook.Sheets -join ",") -eq "Timeline,Findings" -and $rebuiltWorkbook.TimelineSelected -and
            -not $rebuiltWorkbook.FindingsSelected -and $rebuiltWorkbook.ActiveTab -eq 0 -and
            @($rebuiltWorkbook.Headers | Where-Object { $_ -eq "Finding" }).Count -eq 1) -Message "-ReportOnly replaces the Findings sheet and the Finding column (no duplicates); the workbook still opens on the full Timeline sheet"
        Write-TestResult -Succeeded ((@($rebuiltWorkbook.TimelineRows | ForEach-Object { $_.Finding }) -join "|") -eq ($firstFindingColumn -join "|")) -Message "-ReportOnly writes the same Finding column"
        $rebuiltWidths = @(Get-TestTimelineWidths -Path $xlsxPath)
        Write-TestResult -Succeeded (@($rebuiltWidths | Where-Object { $_ -eq "Details=80" }).Count -eq 1 -and @($rebuiltWidths | Where-Object { [double]($_ -replace '^.*=', '') -gt 80 }).Count -eq 0) -Message "-ReportOnly caps the Timeline sheet's column widths of an older workbook at 80 ($($rebuiltWidths -join ', '))"
    }

    # --- 2b. A lead seen only in the memory dump: a copy of the builder (with
    # lib\ beside it, in this test's folder) whose Find-VolatilityExe gives
    # a stub that prints canned Volatility 3 output, run with -MemoryDumpPath
    # on a synthetic x64 crash dump header captured during the collection.
    # fixture-stage.exe runs from C:\Users\Public only in the dump (a
    # memory-only EXEC-STAGING lead); fixture-invoice.exe is also in the
    # BAM rows (a mixed lead). Then -ReportOnly updates the workbook ---
    $memBuilderDir = Join-Path $workDir "memory-builder"
    $volDir = Join-Path $memBuilderDir "vol"
    New-Item -ItemType Directory -Path $volDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $builderDir "lib") -Destination (Join-Path $memBuilderDir "lib") -Recurse
    $volStub = Join-Path $volDir "vol-canned.cmd"
    [System.IO.File]::WriteAllText($volStub, "@echo off`r`nif not exist `"%~dp0%5.json`" (`r`n  echo No output for %5 1>&2`r`n  exit /b 1`r`n)`r`ntype `"%~dp0%5.json`"`r`n")
    $cannedOutput = @{
        "windows.pslist"  = '[ { "PID": 4321, "PPID": 3000, "ImageFileName": "fixture-stage.", "CreateTime": "2026-03-02T11:30:00+00:00", "Threads": 3, "SessionId": 1, "__children": [] } ]'
        "windows.netscan" = '[ { "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49700, "ForeignAddr": "203.0.113.7", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 4321, "Owner": "fixture-stage.", "Created": "2026-03-02T11:31:00+00:00", "__children": [] } ]'
        "windows.cmdline" = '[ { "PID": 4321, "Process": "fixture-stage.exe", "Args": "\"C:\\Users\\Public\\fixture-stage.exe\" -connect 203.0.113.7", "__children": [] }, { "PID": 4400, "Process": "fixture-invoice.exe", "Args": "C:\\Users\\alice\\Downloads\\fixture-invoice.exe /quiet", "__children": [] } ]'
        "windows.svcscan" = '[ { "PID": 900, "Start": "SERVICE_AUTO_START", "State": "SERVICE_RUNNING", "Name": "Dhcp", "Display": "DHCP Client", "Binary": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p", "__children": [] } ]'
    }
    foreach ($plugin in $cannedOutput.Keys) { [System.IO.File]::WriteAllText((Join-Path $volDir "$plugin.json"), $cannedOutput[$plugin]) }
    # The collection started at 12:00 UTC; the dump was captured at 12:03
    $dumpPath = Join-Path $workDir "memory.dmp"
    $dumpBytes = New-Object byte[] 0x2000
    [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("PAGEDU64"), 0, $dumpBytes, 0, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x8664), 0, $dumpBytes, 0x30, 4)
    $captureUtc = [datetime]::new(2026, 3, 2, 12, 3, 0, [System.DateTimeKind]::Utc)
    [Array]::Copy([BitConverter]::GetBytes([long]$captureUtc.ToFileTimeUtc()), 0, $dumpBytes, 0xFA8, 8)
    [System.IO.File]::WriteAllBytes($dumpPath, $dumpBytes)
    [System.IO.File]::SetLastWriteTimeUtc($dumpPath, $captureUtc.AddMinutes(2))
    $volAnchor = "function Find-VolatilityExe {"
    $memBuilderText = [System.IO.File]::ReadAllText($builder)
    $volAnchorFound = $memBuilderText.IndexOf($volAnchor) -ge 0 -and $memBuilderText.IndexOf($volAnchor) -eq $memBuilderText.LastIndexOf($volAnchor)
    # Preconditions of the memory checks print only when they fail
    if (-not $volAnchorFound) { Write-TestResult -Succeeded $false -Message "the builder has no single Find-VolatilityExe to stub for the memory run" }
    else {
        $memBuilder = Join-Path $memBuilderDir "timeline-builder.ps1"
        [System.IO.File]::WriteAllText($memBuilder, $memBuilderText.Replace($volAnchor, "$volAnchor`r`n    return '" + $volStub.Replace("'", "''") + "'"))
        $memRunDir = Join-Path $workDir "memory-run"
        New-Item -ItemType Directory -Path $memRunDir | Out-Null
        $savedBuilder = $builder
        try {
            $builder = $memBuilder
            Write-Host "Running the builder copy with the memory dump ..."
            $memRun = Invoke-TimelineBuilder -Arguments @("-InputPath", $collection, "-Sources", "Persistence,PowerShellHistory,Memory", "-MemoryDumpPath", $dumpPath,
                "-OutputFile", (Join-Path $memRunDir "timeline.csv"), "-Viewer", "None")
        }
        finally { $builder = $savedBuilder }
        $memRows = @()
        if (Test-Path -LiteralPath (Join-Path $memRunDir "timeline.csv")) { $memRows = @(Import-Csv -LiteralPath (Join-Path $memRunDir "timeline.csv")) }
        $memWarnings = @($memRun.Output | Where-Object { $_ -match 'WARNING:' -and $_ -match 'produced no output|failed|Volatility|memory|report|finding|rule|workbook|PDF' -and -not ($_ -match 'PDF not created' -and -not $edge) })
        if ($memRun.ExitCode -ne 0 -or @($memRows | Where-Object { $_.Source -eq "Memory-CommandLine" }).Count -ne 2 -or $memWarnings.Count -gt 0) {
            Write-TestResult -Succeeded $false -Message "the memory run did not exit with 0 and add the dump's rows without a memory or report warning (exit code $($memRun.ExitCode)) $($memWarnings -join ' / ')"
            $memRun.Output | Select-Object -Last 30 | ForEach-Object { Write-Host "  | $_" }
        }
        Test-MemoryOnlyLead -Folder $memRunDir -Label "memory run"
        # -ReportOnly (the builder under test) updates the workbook: the same note and pointers
        $memRebuild = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $memRunDir, "-Viewer", "None")
        $workbookUpdated = (-not (Test-Path -LiteralPath (Join-Path $memRunDir "timeline.xlsx"))) -or @($memRebuild.Output | Where-Object { $_ -match 'Workbook updated: Findings sheet and Finding column' }).Count -eq 1
        if ($memRebuild.ExitCode -ne 0 -or $memRebuild.Errors.Count -gt 0 -or -not $workbookUpdated) {
            Write-TestResult -Succeeded $false -Message "-ReportOnly on the memory run did not exit with 0 and update its workbook (exit code $($memRebuild.ExitCode)) $($memRebuild.Errors -join ' / ')"
            $memRebuild.Output | Select-Object -Last 30 | ForEach-Object { Write-Host "  | $_" }
        }
        Test-MemoryOnlyLead -Folder $memRunDir -Label "memory run, -ReportOnly"

        # --- 2c. The collector's own processes in the memory dump, recognized
        # by the PIDs in collection_info.json (CollectorProcesses): left
        # unflagged and listed, while an attacker script (invoice.vbs) and a
        # same-name process with another PID (triage-collector.ps1) are still
        # flagged. Uses the stub Volatility with the collector fixture's canned
        # output; its collection_info.json is in the current collector's
        # format, provenance fields included. Then -ReportOnly, and a copy
        # with CollectorProcesses removed (an older collection) where the
        # collector's own run is flagged again ---
        $collectorFix = Join-Path $PSScriptRoot "fixtures\report\collector"
        Get-ChildItem -LiteralPath (Join-Path $collectorFix "vol") -Filter "*.json" | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $volDir $_.Name) -Force }
        $colRunDir = Join-Path $workDir "collector-run"
        New-Item -ItemType Directory -Path $colRunDir | Out-Null
        $savedBuilder2 = $builder
        try {
            $builder = $memBuilder
            $colRun = Invoke-TimelineBuilder -Arguments @("-InputPath", (Join-Path $collectorFix "collection"), "-Sources", "Memory", "-MemoryDumpPath", $dumpPath,
                "-OutputFile", (Join-Path $colRunDir "timeline.csv"), "-Viewer", "None")
        }
        finally { $builder = $savedBuilder2 }
        $colMemRows = @()
        if (Test-Path -LiteralPath (Join-Path $colRunDir "timeline.csv")) { $colMemRows = @(Import-Csv -LiteralPath (Join-Path $colRunDir "timeline.csv") | Where-Object { $_.Source -eq "Memory-Processes" }) }
        if ($colRun.ExitCode -ne 0 -or $colMemRows.Count -ne 8) {
            Write-TestResult -Succeeded $false -Message "the collector memory run did not exit with 0 and add the 8 pslist rows (exit code $($colRun.ExitCode), rows $($colMemRows.Count))"
            $colRun.Output | Select-Object -Last 30 | ForEach-Object { Write-Host "  | $_" }
        }
        Test-CollectorFixture -Folder $colRunDir -Label "collector run"
        $colRebuild = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $colRunDir, "-Viewer", "None")
        Write-TestResult -Succeeded ($colRebuild.ExitCode -eq 0 -and $colRebuild.Errors.Count -eq 0) -Message "-ReportOnly on the collector run exits with 0 and writes no error (exit code $($colRebuild.ExitCode)) $($colRebuild.Errors -join ' / ')"
        Test-CollectorFixture -Folder $colRunDir -Label "collector run, -ReportOnly"

        # A copy whose collection_info.json has no CollectorProcesses (an older
        # collector): the collector's own run comes back as a lead, and the
        # report carries the older-collector note
        $oldDir = Join-Path $workDir "collector-old"
        New-Item -ItemType Directory -Path $oldDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $colRunDir "timeline.csv") -Destination (Join-Path $oldDir "timeline.csv")
        Copy-Item -LiteralPath (Join-Path $collectorFix "collection\collection_log.txt") -Destination (Join-Path $oldDir "collection_log.txt")
        $oldJson = Get-Content -LiteralPath (Join-Path $collectorFix "collection\collection_info.json") -Raw | ConvertFrom-Json
        $oldJson.PSObject.Properties.Remove("CollectorProcesses")
        [System.IO.File]::WriteAllText((Join-Path $oldDir "collection_info.json"), ($oldJson | ConvertTo-Json -Depth 6))
        $oldRun = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $oldDir, "-NoExcel", "-Viewer", "None")
        $oldModel = $null
        if (Test-Path -LiteralPath (Join-Path $oldDir "report-model.json")) { $oldModel = Get-Content -LiteralPath (Join-Path $oldDir "report-model.json") -Raw | ConvertFrom-Json }
        $oldRows = @(Import-Csv -LiteralPath (Join-Path $oldDir "timeline.csv"))
        $colCmdRow = (@(for ($i = 0; $i -lt $oldRows.Count; $i++) { if ($oldRows[$i].Source -eq "Memory-CommandLine" -and $oldRows[$i].Description -eq "Process command line: powershell.exe (PID: 9120)") { $i + 2 } }))[0]
        $oldExec = @($oldModel.Findings | Where-Object { $_.RuleId -eq "EXEC-STAGING" -and $_.GroupKey -eq "triage-collector.ps1" })
        $comesBack = ($oldExec.Count -eq 1 -and (@($oldExec[0].RowNumbers) -contains $colCmdRow))
        $olderNote = $oldModel -and @($oldModel.Coverage.Notes | Where-Object { $_ -match "does not record the collector's own process IDs" }).Count -eq 1
        $batBack = @($oldModel.Findings | Where-Object { $_.RuleId -eq "EXEC-STAGING" -and $_.GroupKey -eq "Run-TriageCollector.bat" }).Count -eq 1
        Write-TestResult -Succeeded ($oldRun.ExitCode -eq 0 -and $oldModel -and -not $oldModel.Coverage.CollectorProcesses.Recorded -and $comesBack -and $batBack -and $olderNote) -Message "collector: with CollectorProcesses removed, the collector's own run (PID 9120) and its launcher .bat are flagged again and the older-collector note appears (exit $($oldRun.ExitCode))"

        # A copy whose collection_info.json also lists the attacker's script
        # host (the pslist row of PID 6000, whose parent is not the
        # collector's) as a Child: the entry is rejected, the attacker's lead
        # stays, and the builder log and the report say to check whether the
        # file was altered
        $editDir = Join-Path $workDir "collector-edited"
        New-Item -ItemType Directory -Path $editDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $colRunDir "timeline.csv") -Destination (Join-Path $editDir "timeline.csv")
        Copy-Item -LiteralPath (Join-Path $collectorFix "collection\collection_log.txt") -Destination (Join-Path $editDir "collection_log.txt")
        # (Windows PowerShell's ConvertFrom-Json sends the array as one object:
        # keep it in a variable, then enumerate it)
        $pslistEntries = @(Get-Content -LiteralPath (Join-Path $collectorFix "vol\windows.pslist.json") -Raw | ConvertFrom-Json)
        $attacker = @($pslistEntries | ForEach-Object { $_ } | Where-Object { [int]$_.PID -eq 6000 })[0]
        $editJson = Get-Content -LiteralPath (Join-Path $collectorFix "collection\collection_info.json") -Raw | ConvertFrom-Json
        $editJson.CollectorProcesses = @($editJson.CollectorProcesses) + @([PSCustomObject]@{ Role = "Child"; Pid = 6000; Name = [string]$attacker.ImageFileName; StartUtc = "2026-03-02T12:01:00.1000000Z"; ParentPid = 9120 })
        [System.IO.File]::WriteAllText((Join-Path $editDir "collection_info.json"), ($editJson | ConvertTo-Json -Depth 6))
        $editRun = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $editDir, "-NoExcel", "-Viewer", "None")
        $editModel = $null
        if (Test-Path -LiteralPath (Join-Path $editDir "report-model.json")) { $editModel = Get-Content -LiteralPath (Join-Path $editDir "report-model.json") -Raw | ConvertFrom-Json }
        $editHtml = ""
        if (Test-Path -LiteralPath (Join-Path $editDir "report.html")) { $editHtml = [System.IO.File]::ReadAllText((Join-Path $editDir "report.html")) }
        $editLead = $editModel -and @($editModel.Findings | Where-Object { $_.RuleId -eq "EXEC-STAGING" -and $_.GroupKey -eq "invoice.vbs" }).Count -eq 1
        $editNote = $editModel -and [int]$editModel.Coverage.CollectorProcesses.OutsideTree -eq 1 -and [int]$editModel.Coverage.CollectorProcesses.Count -eq 6 -and
            @($editModel.Coverage.Notes | Where-Object { $_ -match "lists 1 process\(es\) the collector would not have recorded that way" -and $_ -match "Check whether collection_info.json was altered" }).Count -eq 1
        $editLog = @($editRun.Output | Where-Object { $_ -match "collection_info.json lists 1 process\(es\) the collector would not have recorded that way" }).Count -eq 1
        Write-TestResult -Succeeded ($editRun.ExitCode -eq 0 -and $editLead -and $editNote -and $editLog -and $editHtml.Contains("Check whether collection_info.json was altered after the collection.")) -Message "collector: an entry added to collection_info.json for the attacker's process is rejected (its lead stays, the 6 collector processes are still left out) and the log, the model and report.html say to check whether the file was altered (exit $($editRun.ExitCode))"
    }

    # --- 2d. A Windows ARM64 dump, read with Microsoft's debugger engine: a
    # copy of the builder (with lib\ beside it) whose debugger engine
    # helper (lib\memory\TimelineDbgEng.ps1) returns canned entries instead of
    # reading the dump, run with -MemoryDumpPath on a synthetic ARM64 crash
    # dump header. The builder's own path is real: the engine lookup, the
    # helper in a PowerShell process of its own, its output read back, the
    # rows (the same entries as the memory run of 2b, and the areas' canned
    # entries of tests\fixtures\memory\canned-*.txt with their AREA lines), the
    # log lines the report reads. The report gets the "analyzed with the Windows debugger
    # engine" note and caveat (not the "not analyzed" ones), the memory-only
    # lead still says "Captured in the memory dump", and -ReportOnly keeps
    # them ---
    $armBuilderDir = Join-Path $workDir "arm64-builder"
    New-Item -ItemType Directory -Path $armBuilderDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $builderDir "lib") -Destination (Join-Path $armBuilderDir "lib") -Recurse
    Copy-Item -LiteralPath $builder -Destination (Join-Path $armBuilderDir "timeline-builder.ps1")
    $helperText = [System.IO.File]::ReadAllText((Join-Path $builderDir "lib\memory\TimelineDbgEng.ps1"))
    $helperAnchor = "function Read-DbgEngDump {"
    # The areas' canned entries (tests\fixtures\memory\canned-*.txt, read by
    # the test kit's Read-TestCannedEntries in the helper's process): an area
    # that no file names is not built yet, as the helper's stubs say
    $cannedHelper = @'
function Read-DbgEngDump {
    param([string]$DumpPath, [string]$EngineFolder, [string[]]$EngineDlls, [string]$SymbolCache, [string]$JobFolder)
    Write-DbgEngLog "  Kernel symbols: (canned for the test)"
    $result = New-DbgEngResult
    $result.Processes = @([PSCustomObject]@{ PID = [long]4321; PPID = [long]3000; ImageFileName = "fixture-stage."; Offset = "0xffffa00000001000"; Threads = [long]3; SessionId = [long]1; CreateTime = "2026-03-02T11:30:00.1234567+00:00"; ExitTime = $null })
    $result.CommandLines = @(
        [PSCustomObject]@{ PID = [long]4321; Process = "fixture-stage.exe"; Args = '"C:\Users\Public\fixture-stage.exe" -connect 203.0.113.7' },
        [PSCustomObject]@{ PID = [long]4400; Process = "fixture-invoice.exe"; Args = "C:\Users\alice\Downloads\fixture-invoice.exe /quiet" }
    )
    $result.SessionIds = 1
    . '<KIT>'
    $canned = Read-TestCannedEntries -Path '<FIXTURES>'
    $result.Entries = $canned.Entries
    $result.Areas = @(foreach ($area in @(Get-DbgEngAreas)) {
            $named = @($canned.Areas | Where-Object { $_.Name -eq $area.Name })
            if ($named.Count -gt 0) { $named[0] } else { New-DbgEngAreaSummary -Name $area.Name -State "NotRead" -Note "not built yet" }
        })
    return $result
}

function Read-DbgEngDumpReal {
'@
    $memoryKit = Join-Path $PSScriptRoot "MemoryTestKit.ps1"
    $memoryFixtures = Join-Path $PSScriptRoot "fixtures\memory"
    $cannedHelper = $cannedHelper.Replace("<KIT>", $memoryKit.Replace("'", "''")).Replace("<FIXTURES>", $memoryFixtures.Replace("'", "''"))
    # What the builder and the report must then say: from the same canned
    # areas, with the helper's and the builder's own functions
    . $memoryKit
    [void](Import-MemoryTestFunctions -Path (Join-Path $builderDir "lib\memory\TimelineDbgEng.ps1"))
    [void](Import-MemoryTestFunctions -Path (Join-Path $builderDir "lib\memory\TimelineMemoryRows.ps1"))
    $cannedData = Read-TestCannedEntries -Path $memoryFixtures
    $cannedAreas = @(foreach ($area in @(Get-DbgEngAreas)) {
            $named = @($cannedData.Areas | Where-Object { $_.Name -eq $area.Name })
            if ($named.Count -gt 0) { $named[0] } else { New-DbgEngAreaSummary -Name $area.Name -State "NotRead" -Note "not built yet" }
        })
    $cannedReadText = Get-DbgEngReadText -Areas $cannedAreas
    $cannedCoverage = @(Get-DbgEngCoverageTexts -Areas $cannedAreas)
    $helperAnchorFound = ([regex]::Matches($helperText, [regex]::Escape($helperAnchor))).Count -eq 1
    if (-not $helperAnchorFound) { Write-TestResult -Succeeded $false -Message "the debugger engine helper has no single Read-DbgEngDump to replace for the ARM64 run" }
    else {
        [System.IO.File]::WriteAllText((Join-Path $armBuilderDir "lib\memory\TimelineDbgEng.ps1"), $helperText.Replace($helperAnchor, $cannedHelper))
        $armDump = Join-Path $workDir "arm64 memory.dmp"
        $armBytes = New-Object byte[] 0x2000
        [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("PAGEDU64"), 0, $armBytes, 0, 8)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0xAA64), 0, $armBytes, 0x30, 4)
        $armCapture = [datetime]::new(2026, 3, 2, 12, 3, 0, [System.DateTimeKind]::Utc)
        [Array]::Copy([BitConverter]::GetBytes([long]$armCapture.ToFileTimeUtc()), 0, $armBytes, 0xFA8, 8)
        [System.IO.File]::WriteAllBytes($armDump, $armBytes)
        [System.IO.File]::SetLastWriteTimeUtc($armDump, $armCapture.AddMinutes(2))
        $armRunDir = Join-Path $workDir "arm64-run"
        New-Item -ItemType Directory -Path $armRunDir | Out-Null
        $savedBuilder3 = $builder
        try {
            $builder = Join-Path $armBuilderDir "timeline-builder.ps1"
            Write-Host "Running the builder copy with a Windows ARM64 memory dump ..."
            $armRun = Invoke-TimelineBuilder -Arguments @("-InputPath", $collection, "-Sources", "Persistence,PowerShellHistory,Memory", "-MemoryDumpPath", $armDump,
                "-OutputFile", (Join-Path $armRunDir "timeline.csv"), "-Viewer", "None")
        }
        finally { $builder = $savedBuilder3 }
        $armRows = @()
        if (Test-Path -LiteralPath (Join-Path $armRunDir "timeline.csv")) { $armRows = @(Import-Csv -LiteralPath (Join-Path $armRunDir "timeline.csv")) }
        $analyzedLine = "Memory dump analyzed with the Windows debugger engine: arm64 memory.dmp (8192 bytes) -- $cannedReadText"
        $armWarnings = @($armRun.Output | Where-Object { $_ -match 'WARNING:' -and $_ -match 'memory|debugger|engine|symbol|report|finding|rule|workbook|PDF' -and -not ($_ -match 'PDF not created' -and -not $edge) })
        $armLogged = @($armRun.Output | Where-Object { $_.EndsWith("  $analyzedLine") }).Count -eq 1 -and @($armRun.Output | Where-Object { $_ -match '  Debugger engine: dbgeng\.dll \S+ from .+ \(part of Windows\)$' }).Count -eq 1 -and
            @($armRun.Output | Where-Object { $_ -match 'Kernel symbols: \(canned for the test\)$' }).Count -eq 1
        if ($armRun.ExitCode -ne 0 -or @($armRows | Where-Object { $_.Source -eq "Memory-Processes" }).Count -ne 1 -or @($armRows | Where-Object { $_.Source -eq "Memory-CommandLine" }).Count -ne 2 -or $armWarnings.Count -gt 0 -or -not $armLogged) {
            Write-TestResult -Succeeded $false -Message "the ARM64 run did not exit with 0, log the engine and the helper's line and add the dump's rows without a memory or report warning (exit code $($armRun.ExitCode)) $($armWarnings -join ' / ')"
            $armRun.Output | Select-Object -Last 30 | ForEach-Object { Write-Host "  | $_" }
        }
        else { Write-TestResult -Succeeded $true -Message "the ARM64 run: the engine and the helper's log line, the 'analyzed with the Windows debugger engine' line, one pslist and two cmdline rows" }
        # The ARM64 caveat says what was not read; a scan of network objects and
        # the registry in memory have a caveat of their own when read
        $cannedNotRead = if ($cannedReadText.Contains("; not read ")) { $cannedReadText.Substring($cannedReadText.IndexOf("; not read ") + 11) } else { "" }
        $armCaveats = @(if ($cannedNotRead) { "The memory dump is a Windows ARM64 dump, read with the Windows debugger engine: these were not read from it, so they are not in this report -- $cannedNotRead." } else { "The memory dump is a Windows ARM64 dump, read with the Windows debugger engine, not with Volatility 3." })
        $cannedReadPart = ($cannedReadText -split '; not read ')[0]
        if ($cannedReadPart -match '(?:^read |, )network connections(?:,|$)') { $armCaveats += "Network connections in the memory dump come from a scan of memory for connection objects and can include closed ones (Stale=Yes, never flagged)." }
        if ($cannedReadPart -match '(?:^read |, )registry hives(?:,|$)') { $armCaveats += "The registry in the memory dump is partial: a key or value missing there is not proof that it was absent." }
        $armCaveat = $armCaveats -join " / "
        $armNotesExpected = (@("$analyzedLine.") + @($cannedCoverage | ForEach-Object { "Memory dump coverage: $_." })) -join " / "
        foreach ($pass in @("ARM64 run", "ARM64 run, -ReportOnly")) {
            if ($pass -like "*-ReportOnly") {
                # -ReportOnly reads the run's log next to the timeline (with
                # -OutputFile it stayed in the copy's reports\timeline_<time>\)
                $armLog = @(Get-ChildItem -LiteralPath (Join-Path $armBuilderDir "reports") -Filter "timeline_builder_log.txt" -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1)
                if ($armLog.Count -eq 1) { Copy-Item -LiteralPath $armLog[0].FullName -Destination (Join-Path $armRunDir "timeline_builder_log.txt") }
                else { Write-TestResult -Succeeded $false -Message "the ARM64 run's timeline_builder_log.txt was not found under the copy's reports\" }
                $armRebuild = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $armRunDir, "-Viewer", "None")
                if ($armRebuild.ExitCode -ne 0 -or $armRebuild.Errors.Count -gt 0) { Write-TestResult -Succeeded $false -Message "-ReportOnly on the ARM64 run did not exit with 0 (exit code $($armRebuild.ExitCode)) $($armRebuild.Errors -join ' / ')" }
            }
            $armModel = $null
            if (Test-Path -LiteralPath (Join-Path $armRunDir "report-model.json")) { $armModel = Get-Content -LiteralPath (Join-Path $armRunDir "report-model.json") -Raw | ConvertFrom-Json }
            $armNotes = @($armModel.Coverage.Notes | Where-Object { $_ -match '^Memory dump' })
            $armModelCaveats = @($armModel.Caveats | Where-Object { $_ -match 'memory dump' })
            Write-TestResult -Succeeded ($armModel -and ($armNotes -join " / ") -ceq $armNotesExpected -and ($armModelCaveats -join " / ") -ceq $armCaveat) -Message "${pass}: report-model.json has the 'analyzed with the Windows debugger engine' note (what was read and not), the coverage notes and the ARM64 caveats, no 'not analyzed' note or caveat ($($armNotes -join ' / ') | $($armModelCaveats -join ' / '))"
            Test-MemoryOnlyLead -Folder $armRunDir -Label $pass
        }
    }

    # --- 3. -ReportOnly with another rules file, workbook left alone ---
    $xlsxHashBefore = $null
    if (Test-Path -LiteralPath $xlsxPath) { $xlsxHashBefore = (Get-FileHash -LiteralPath $xlsxPath).Hash }
    # -WorkDir and -MemoryDumpPath bind with -ReportOnly too: ignored, with a warning
    $ignoredWorkDir = Join-Path $workDir "ignored-workdir"
    $custom = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $timelineCsv, "-ReportRules", (Join-Path $fixtureDir "rules-one.json"), "-NoExcel", "-Viewer", "None",
        "-WorkDir", $ignoredWorkDir, "-MemoryDumpPath", (Join-Path $workDir "no-dump.dmp"))
    Write-TestResult -Succeeded (@($custom.Output | Where-Object { $_ -match 'WARNING: -ReportOnly parses nothing, so these are ignored: -WorkDir, -MemoryDumpPath$' }).Count -eq 1 -and -not (Test-Path -LiteralPath $ignoredWorkDir)) -Message "-ReportOnly warns once that -WorkDir and -MemoryDumpPath are ignored, and makes no work folder"
    Write-TestResult -Succeeded ($custom.Errors.Count -eq 0) -Message "-ReportOnly -ReportRules writes no error: $($custom.Errors -join ' / ')"
    $customLines = @(Import-Csv -LiteralPath $findingsCsv)
    $customRules = @($customLines | ForEach-Object { $_.RuleId } | Sort-Object -Unique)
    $customModel = Get-Content -LiteralPath (Join-Path $runDir "report-model.json") -Raw | ConvertFrom-Json
    Write-TestResult -Succeeded ($custom.ExitCode -eq 0 -and ($customRules -join ",") -eq "FIXTURE-RUNKEY" -and @($customLines | Where-Object { $_.RowNumber }).Count -eq 3) -Message "-ReportRules uses the given rules file (findings: $($customRules -join ','))"
    $xlsxUnchanged = (-not $xlsxHashBefore) -or ((Get-FileHash -LiteralPath $xlsxPath).Hash -eq $xlsxHashBefore)
    Write-TestResult -Succeeded ($xlsxUnchanged -and -not $customModel.Workbook.Available) -Message "-ReportOnly -NoExcel leaves the workbook as it is, and the report does not link to it"
    if ($xlsxHashBefore) {
        Write-TestResult -Succeeded (@($custom.Output | Where-Object { $_ -match 'WARNING:.*from an earlier report' }).Count -eq 1 -and
            @($customModel.Caveats | Where-Object { $_ -match 'from an earlier report' }).Count -eq 1) -Message "a workbook left as it is is called out as holding an earlier report's findings (log warning and caveat)"
    }

    # --- 4. A missing rules file and -NoReport: timeline only ---
    $missingDir = Join-Path $workDir "missing-rules"
    New-Item -ItemType Directory -Path $missingDir | Out-Null
    $missing = Invoke-TimelineBuilder -Arguments @("-InputPath", $collection, "-Sources", "Persistence", "-OutputFile", (Join-Path $missingDir "timeline.csv"), "-NoExcel", "-Viewer", "None", "-ReportRules", (Join-Path $workDir "no-such-rules.json"))
    Write-TestResult -Succeeded ($missing.ExitCode -eq 0 -and (Test-Path -LiteralPath (Join-Path $missingDir "timeline.csv")) -and -not (Test-Path -LiteralPath (Join-Path $missingDir "report.html")) -and
        @($missing.Output | Where-Object { $_ -match 'WARNING:.*Rules file not found' }).Count -eq 1) -Message "a missing rules file is a warning: the timeline is still written, without a report"
    $noReportDir = Join-Path $workDir "no-report"
    New-Item -ItemType Directory -Path $noReportDir | Out-Null
    $noReport = Invoke-TimelineBuilder -Arguments @("-InputPath", $collection, "-Sources", "Persistence", "-OutputFile", (Join-Path $noReportDir "timeline.csv"), "-NoExcel", "-NoReport", "-Viewer", "None")
    $leftovers = @("findings.csv", "report.html", "report.pdf", "report-model.json") | Where-Object { Test-Path -LiteralPath (Join-Path $noReportDir $_) }
    Write-TestResult -Succeeded ($noReport.ExitCode -eq 0 -and (Test-Path -LiteralPath (Join-Path $noReportDir "timeline.csv")) -and @($leftovers).Count -eq 0) -Message "-NoReport writes the timeline and no report files"

    # --- 5. -ReportOnly in a folder whose name has [ ] (wildcard characters),
    # and with report.pdf held open by another program ---
    $bracketDir = Join-Path $workDir "case [1]"
    New-Item -ItemType Directory -Path $bracketDir | Out-Null
    foreach ($name in @("timeline.csv", "timeline.xlsx", "collection_info.json", "collection_log.txt")) {
        $from = Join-Path $runDir $name
        if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination (Join-Path $bracketDir $name) }
    }
    $bracket = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $bracketDir, "-Viewer", "None")
    $bracketLog = Join-Path $bracketDir "report_log.txt"
    Write-TestResult -Succeeded ($bracket.ExitCode -eq 0 -and (Test-Path -LiteralPath $bracketLog) -and (Test-Path -LiteralPath (Join-Path $bracketDir "report.html")) -and
        @($bracket.Output | Where-Object { $_ -match 'Add-Content|Cannot find path|Could not find' }).Count -eq 0 -and $bracket.Errors.Count -eq 0) -Message "-ReportOnly works in a folder named 'case [1]' and logs to its report_log.txt, with no error (exit code $($bracket.ExitCode)) $($bracket.Errors -join ' / ')"
    if ($workbook) {
        $bracketModel = Get-Content -LiteralPath (Join-Path $bracketDir "report-model.json") -Raw | ConvertFrom-Json
        Write-TestResult -Succeeded ($bracketModel.Workbook.Available) -Message "-ReportOnly updates the workbook in a folder whose name has [ ]"
    }
    $bracketPdf = Join-Path $bracketDir "report.pdf"
    if ($edge -and (Test-Path -LiteralPath $bracketPdf)) {
        $holder = [System.IO.File]::Open($bracketPdf, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try { $locked = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $bracketDir, "-Viewer", "None") }
        finally { $holder.Dispose() }
        $newPdfs = @(Get-ChildItem -LiteralPath $bracketDir -Filter "report_*.pdf" -File)
        Write-TestResult -Succeeded ($locked.ExitCode -eq 0 -and @($locked.Output | Where-Object { $_ -match 'WARNING:.*report\.pdf is open in another program.*OUT OF DATE' }).Count -eq 1 -and $newPdfs.Count -eq 1) -Message "a report.pdf held open elsewhere is reported as out of date and the new PDF gets its own name ($($newPdfs.Name -join ', '))"
    }

    # --- 5b. -ReportOnly on a mounted-image timeline whose original run
    # ended incomplete (exit code 2): the report names the examined
    # computer from the run's log (SYSTEM hive), not the collector host, and
    # says that the timeline is incomplete ---
    $imageDir = Join-Path $workDir "image"
    New-Item -ItemType Directory -Path $imageDir | Out-Null
    Copy-Item -LiteralPath $timelineCsv -Destination (Join-Path $imageDir "timeline.csv")
    $imageCollectionInfo = Get-Content -LiteralPath (Join-Path $collection "collection_info.json") -Raw | ConvertFrom-Json
    $imageCollectionInfo.Mode = "MountedImage"
    $imageCollectionInfo.ComputerName = "ANALYST-WS"
    [System.IO.File]::WriteAllText((Join-Path $imageDir "collection_info.json"), ($imageCollectionInfo | ConvertTo-Json))
    [System.IO.File]::WriteAllText((Join-Path $imageDir "timeline_builder_log.txt"), (@(
            "[2026-03-02 05:00:00] === Windows 11 Forensic Timeline Builder Started ===",
            "[2026-03-02 05:00:01] Collection metadata from collection_info.json: Mode=MountedImage Start=2026-03-02 12:00:00 UTC CollectorTZ=Pacific Standard Time TargetTZ=Pacific Standard Time",
            "[2026-03-02 05:00:05]   Examined computer name (SYSTEM hive): IMAGED-PC",
            "[2026-03-02 05:01:00] ERROR: 1 of 12 input file(s) disappeared during the run -- rows from them may be missing from the timeline (not if a file was deleted after its parser read it):",
            "[2026-03-02 05:02:00] ERROR: === Timeline Builder Completed WITH 1 MISSING INPUT FILE(S) -- timeline incomplete ===") -join "`r`n") + "`r`n")
    $image = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $imageDir, "-NoExcel", "-Viewer", "None")
    $imageModel = $null
    if (Test-Path -LiteralPath (Join-Path $imageDir "report-model.json")) { $imageModel = Get-Content -LiteralPath (Join-Path $imageDir "report-model.json") -Raw | ConvertFrom-Json }
    Write-TestResult -Succeeded ($image.ExitCode -eq 0 -and $imageModel -and $imageModel.Collection.ComputerName -eq "IMAGED-PC" -and $imageModel.Collection.ComputerNameSource -eq "SYSTEM hive" -and
        $imageModel.Collection.CollectorHost -eq "ANALYST-WS") -Message "-ReportOnly, mounted image: the examined computer from the run's SYSTEM hive line, the collector host kept apart (exit code $($image.ExitCode))"
    $imageHtml = ""
    if (Test-Path -LiteralPath (Join-Path $imageDir "report.html")) { $imageHtml = [System.IO.File]::ReadAllText((Join-Path $imageDir "report.html")) }
    Write-TestResult -Succeeded ($imageHtml.Contains("<h1>IMAGED-PC</h1>") -and -not $imageHtml.Contains("<h1>ANALYST-WS")) -Message "-ReportOnly, mounted image: the report's title is the examined computer"
    Write-TestResult -Succeeded ($imageModel -and $imageModel.Coverage.TimelineCompleteness.Incomplete -and $imageModel.Coverage.TimelineCompleteness.MissingInputFiles -eq 1 -and
        @($imageModel.Caveats | Where-Object { $_ -match '^The timeline is incomplete: 1 input file\(s\) disappeared' }).Count -eq 1 -and $imageHtml.Contains("<h3>Timeline incomplete</h3>")) -Message "-ReportOnly on a timeline that ended with exit code 2: the caveats and Evidence coverage say it is incomplete"

    # --- 6. -ReportOnly without a timeline fails cleanly ---
    $emptyDir = Join-Path $workDir "empty"
    New-Item -ItemType Directory -Path $emptyDir | Out-Null
    $noTimeline = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $emptyDir, "-Viewer", "None")
    Write-TestResult -Succeeded ($noTimeline.ExitCode -eq 1 -and @($noTimeline.Output | Where-Object { $_ -match '-ReportOnly needs a timeline\.csv' }).Count -eq 1) -Message "-ReportOnly on a folder without timeline.csv exits with 1 and says why"

    # --- 7. An unexpected error during -ReportOnly: a copy of the builder
    # (with lib\ beside it, in this test's folder) with one injected
    # change. A statement-terminating error in the rebuild's body is logged
    # and only its statement is skipped (the report is still made, exit code
    # 0); a rebuild that stops before it gives its exit code, or an error
    # thrown out of it, gives exit code 1, never 0 ---
    $injectDir = Join-Path $workDir "inject"
    New-Item -ItemType Directory -Path $injectDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $builderDir "lib") -Destination (Join-Path $injectDir "lib") -Recurse
    $builderText = [System.IO.File]::ReadAllText($builder)
    # A .NET exception whose message names the file in both PowerShell
    # editions (Windows PowerShell's [int]::Parse message has no value)
    $injection = '[void][System.IO.File]::ReadAllText("' + (Join-Path $injectDir "injected-report-error.txt") + '")'
    $bodyAnchor = "`r`n        `$reportInfo = Get-TimelineReportCollectionInfo -InfoJsonPath (Join-Path `$reportDir"
    $finallyAnchor = "`r`n        Restore-ConsoleMode `$consoleMode`r`n"
    $anchorsFound = ($builderText.IndexOf($bodyAnchor) -ge 0 -and $builderText.IndexOf($bodyAnchor) -eq $builderText.LastIndexOf($bodyAnchor) -and
        $builderText.IndexOf($finallyAnchor) -ge 0 -and $builderText.IndexOf($finallyAnchor) -eq $builderText.LastIndexOf($finallyAnchor))
    Write-TestResult -Succeeded $anchorsFound -Message "the places to inject an error are in Invoke-TimelineReportOnly (once each)"
    if ($anchorsFound) {
        $injectedBuilder = Join-Path $injectDir "timeline-builder.ps1"
        $injectRun = Join-Path $workDir "inject-run"
        New-Item -ItemType Directory -Path $injectRun | Out-Null
        foreach ($name in @("timeline.csv", "collection_info.json", "collection_log.txt")) { Copy-Item -LiteralPath (Join-Path $runDir $name) -Destination (Join-Path $injectRun $name) }
        $savedBuilder = $builder
        try {
            $builder = $injectedBuilder
            [System.IO.File]::WriteAllText($injectedBuilder, $builderText.Replace($bodyAnchor, "`r`n        $injection$bodyAnchor"))
            $bodyError = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $injectRun, "-NoExcel", "-Viewer", "None")
            Write-TestResult -Succeeded ($bodyError.ExitCode -eq 0 -and (Test-Path -LiteralPath (Join-Path $injectRun "report.html")) -and
                @($bodyError.Output | Where-Object { $_ -match 'ERROR: Unexpected error at line \d+ \(rest of this step skipped\): .*injected-report-error' }).Count -eq 1) -Message "-ReportOnly: an unexpected error in the rebuild is logged, its statement skipped, and the report still made (exit code $($bodyError.ExitCode))"
            # A rebuild that ends without giving its exit code (as when an
            # error stops it) exits with 1: before the fix it exited with 0
            [System.IO.File]::WriteAllText($injectedBuilder, $builderText.Replace($bodyAnchor, "`r`n        return$bodyAnchor"))
            $noCode = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $injectRun, "-NoExcel", "-Viewer", "None")
            Write-TestResult -Succeeded ($noCode.ExitCode -eq 1) -Message "-ReportOnly: a rebuild stopped before it gives an exit code exits with 1, not 0 (exit code $($noCode.ExitCode))"
            # An error thrown out of the rebuild (here from its finally block)
            [System.IO.File]::WriteAllText($injectedBuilder, $builderText.Replace($finallyAnchor, "`r`n        throw `"injected-report-error`"$finallyAnchor"))
            $stopError = Invoke-TimelineBuilder -Arguments @("-ReportOnly", $injectRun, "-NoExcel", "-Viewer", "None")
            Write-TestResult -Succeeded ($stopError.ExitCode -eq 1 -and @($stopError.Output | Where-Object { $_ -match 'injected-report-error' }).Count -ge 1) -Message "-ReportOnly: an error thrown out of the rebuild gives exit code 1, not 0 (exit code $($stopError.ExitCode))"
        }
        finally { $builder = $savedBuilder }
    }

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all findings report builder checks passed" -ForegroundColor Green
    exit 0
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    exit 1
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a folder (its log) under its reports\; remove the ones from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
