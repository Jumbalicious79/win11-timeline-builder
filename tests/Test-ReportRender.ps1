# =============================================================
# Report renderer test
# Renders the synthetic report models in tests\fixtures\report\render\ with
# report\TimelineReport.Render.ps1 and checks:
#   - report.html is one self-contained offline file: ASCII only, CRLF line
#     endings, no BOM, a Content-Security-Policy, no scripts, images, frames
#     or external links (every href is "#..." or the relative "./" workbook
#     link), balanced markup;
#   - the sections come in the agreed order; every High/Medium finding has a
#     card with its severity label, plain-English why, technical fields,
#     evidence rows with their Excel row numbers and the workbook link; Info
#     items are in the appendix; the summary lists the top five leads;
#   - every value is escaped (the fixture carries markup, quotes and
#     non-ASCII text), and dates in all the forms the model may hold
#     (ISO 8601, "/Date(ms)/", the timeline's text, [datetime]) are shown;
#   - the minimal model (no findings, no workbook) renders the "no leads"
#     wording and no workbook link;
#   - a mounted image: an unknown examined computer is "Not known" (the
#     collector host named only as such, never the title or footer), a
#     SYSTEM-hive name is the title with its source; an incomplete builder
#     run shows "Timeline incomplete" first in Evidence coverage;
#   - with Microsoft Edge installed (skipped with a message otherwise): the
#     PDFs exist, start with %PDF, have a sensible page count and paper size,
#     a valid xref table after the link rewrite, the workbook link in the
#     relative form "./timeline.xlsx", internal links, no local file path,
#     and no leftover Edge profile folder; ConvertTo-ReportPdf returns $false
#     (never throws) for a missing Edge or a missing HTML file.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ReportRender.ps1
#   pwsh -File tests\Test-ReportRender.ps1
# =============================================================

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$fixtureDir = Join-Path $PSScriptRoot "fixtures\report\render"
$script:failures = 0

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-ReportRender.ps1::$Message" }
}

# Reads a fixture model the way report-model.json is read back
function Read-TestModel {
    param([string]$Name)
    return (Get-Content -LiteralPath (Join-Path $fixtureDir $Name) -Raw | ConvertFrom-Json)
}

# Byte checks every written text file must pass: ASCII only, CRLF, no BOM
function Test-TextFileBytes {
    param([string]$Path, [string]$Label)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $nonAscii = 0
    $bareLf = 0
    $bareCr = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $b = $bytes[$i]
        if ($b -gt 127) { $nonAscii++ }
        elseif ($b -eq 10 -and ($i -eq 0 -or $bytes[$i - 1] -ne 13)) { $bareLf++ }
        elseif ($b -eq 13 -and ($i + 1 -ge $bytes.Length -or $bytes[$i + 1] -ne 10)) { $bareCr++ }
    }
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    Write-TestResult -Succeeded ($nonAscii -eq 0 -and -not $bom) -Message "$Label is ASCII without a BOM ($nonAscii non-ASCII byte(s))"
    Write-TestResult -Succeeded ($bareLf -eq 0 -and $bareCr -eq 0) -Message "$Label uses CRLF line endings only ($bareLf bare LF, $bareCr bare CR)"
}

# Checks shared by every rendered page: offline, no active content, balanced
function Test-HtmlSafety {
    param([string]$Html, [string]$Label)
    Write-TestResult -Succeeded ($Html.StartsWith("<!DOCTYPE html>")) -Message "$Label starts with <!DOCTYPE html>"
    Write-TestResult -Succeeded ($Html.Contains("Content-Security-Policy") -and $Html.Contains("default-src 'none'")) -Message "$Label carries a Content-Security-Policy that blocks scripts and external loads"
    $active = [regex]::Matches($Html, '<\s*(script|link|img|iframe|object|embed|base|form|input|meta\s+http-equiv="refresh")\b', "IgnoreCase")
    Write-TestResult -Succeeded ($active.Count -eq 0) -Message "$Label has no script, link, image, frame or form elements ($($active.Count) found)"
    Write-TestResult -Succeeded (-not ($Html -match '@import|url\s*\(|\son[a-z]+\s*=\s*"')) -Message "$Label has no CSS imports, url() loads or event handler attributes"
    $hrefs = @([regex]::Matches($Html, '\shref="([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
    $badHrefs = @($hrefs | Where-Object { -not ($_.StartsWith("#") -or $_.StartsWith("./")) })
    Write-TestResult -Succeeded ($hrefs.Count -gt 0 -and $badHrefs.Count -eq 0) -Message "$Label links only to its own sections or the relative workbook ($($hrefs.Count) link(s); bad: $($badHrefs -join ', '))"
    $anchors = @{}
    foreach ($match in [regex]::Matches($Html, '\sid="([^"]+)"')) { $anchors[$match.Groups[1].Value] = $true }
    $dangling = @($hrefs | Where-Object { $_.StartsWith("#") -and -not $anchors.ContainsKey($_.Substring(1)) })
    Write-TestResult -Succeeded ($dangling.Count -eq 0) -Message "$Label has no internal link without a target ($($dangling -join ', '))"
    foreach ($tag in @("section", "article", "table", "thead", "tbody", "ol", "ul", "svg", "aside", "header")) {
        $open = [regex]::Matches($Html, "<$tag[\s>]").Count
        $close = [regex]::Matches($Html, "</$tag>").Count
        if ($open -ne $close) { Write-TestResult -Succeeded $false -Message "$Label has balanced <$tag> elements ($open open, $close closed)" }
    }
    $rowsOpen = [regex]::Matches($Html, '<tr[\s>]').Count
    $rowsClosed = [regex]::Matches($Html, '</tr>').Count
    Write-TestResult -Succeeded ($rowsOpen -eq $rowsClosed -and $rowsOpen -gt 0) -Message "$Label has balanced markup (sections, tables, lists; $rowsOpen table rows)"
}

# Page count and the first page's size from a PDF's text
function Get-TestPdfInfo {
    param([string]$Path)
    $text = [System.Text.Encoding]::GetEncoding(28591).GetString([System.IO.File]::ReadAllBytes($Path))
    $pages = [regex]::Matches($text, '/Type\s*/Page(?![s\w])').Count
    $box = [regex]::Match($text, '/MediaBox\s*\[\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\]')
    $width = 0.0
    $height = 0.0
    if ($box.Success) {
        $width = [double]::Parse($box.Groups[3].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        $height = [double]::Parse($box.Groups[4].Value, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return @{ Text = $text; Pages = $pages; Width = $width; Height = $height }
}

# Every in-use xref entry points at "N G obj" (the link rewrite kept offsets)
function Test-PdfXref {
    param([string]$Text)
    $start = [regex]::Match($Text, 'startxref\s+(\d+)\s+%%EOF\s*$')
    if (-not $start.Success) { return "no startxref" }
    $offset = [int]$start.Groups[1].Value
    if ($offset -ge $Text.Length -or $Text.Substring($offset, 4) -ne "xref") { return "startxref does not point at an xref table (cross-reference streams are not checked)" }
    $section = [regex]::Match($Text.Substring($offset), '^xref\s+(\d+)\s+(\d+)\s+')
    if (-not $section.Success) { return "unreadable xref header" }
    $first = [int]$section.Groups[1].Value
    $count = [int]$section.Groups[2].Value
    $position = $offset + $section.Length
    $checked = 0
    for ($i = 0; $i -lt $count; $i++) {
        $entry = $Text.Substring($position + $i * 20, 18)
        if ($entry[17] -ne 'n') { continue }
        $objectOffset = [int]$entry.Substring(0, 10)
        $expected = [string]($first + $i) + " " + [int]$entry.Substring(11, 5) + " obj"
        if ($Text.Substring($objectOffset, $expected.Length) -ne $expected) { return "object $($first + $i) is not at offset $objectOffset" }
        $checked++
    }
    return "ok ($checked objects)"
}

. (Join-Path $repoRoot "report\TimelineReport.Render.ps1")

# A folder name with spaces exercises quoting and file:/// URL escaping
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("report render test " + [guid]::NewGuid().ToString("N"))
$profilesBefore = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter "timeline-report-edge-*" -ErrorAction SilentlyContinue).Count
try {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null

    # --- Full model: findings, Info items, coverage, activity, workbook ---
    $fullDir = Join-Path $workDir "full"
    New-Item -ItemType Directory -Path $fullDir -Force | Out-Null
    # A timeline.csv next to the report is hashed into the appendix
    $timelineCsv = Join-Path $fullDir "timeline.csv"
    [System.IO.File]::WriteAllText($timelineCsv, "Timestamp,Source`r`n2026-10-08 14:20:05.000,Test`r`n", (New-Object System.Text.UTF8Encoding($false)))
    $timelineHash = (Get-FileHash -LiteralPath $timelineCsv -Algorithm SHA256).Hash
    $fullHtmlPath = Join-Path $fullDir "report.html"
    $model = Read-TestModel "model-full.json"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $output = @(Export-ReportHtml -Model $model -Path $fullHtmlPath -PaperSize Letter)
    Write-TestResult -Succeeded (Test-Path -LiteralPath $fullHtmlPath) -Message "Export-ReportHtml wrote report.html for the full model ($($stopwatch.ElapsedMilliseconds) ms)"
    Write-TestResult -Succeeded ($output.Count -eq 0) -Message "Export-ReportHtml writes nothing to the pipeline ($($output.Count) object(s))"
    Test-TextFileBytes -Path $fullHtmlPath -Label "the full report.html"
    $html = [System.IO.File]::ReadAllText($fullHtmlPath)
    Test-HtmlSafety -Html $html -Label "the full report"

    # Sections in the agreed order
    $order = @("summary", "leads", "coverage", "antivirus", "access", "persistence", "execution", "initial-access", "file-system", "other", "activity", "appendix-info", "appendix-rules", "appendix-method", "appendix-files")
    $sectionPositions = @($order | ForEach-Object { $html.IndexOf('" id="' + $_ + '">') })
    $inOrder = ($sectionPositions -notcontains -1)
    for ($i = 1; $i -lt $sectionPositions.Count; $i++) { if ($sectionPositions[$i] -le $sectionPositions[$i - 1]) { $inOrder = $false } }
    Write-TestResult -Succeeded $inOrder -Message "sections in the agreed order: summary, leads index, coverage, antivirus, access, persistence, execution, initial access, file system, other, activity, appendix"

    # Summary page: bottom line, key facts, top five leads, caveats box
    $summary = $html.Substring($html.IndexOf('id="summary"'), $html.IndexOf('" id="leads">') - $html.IndexOf('id="summary"'))
    Write-TestResult -Succeeded ($summary.Contains('<span class="n">3</span><span class="l">High leads') -and $summary.Contains('<span class="n">6</span><span class="l">Medium leads') -and $summary.Contains('<span class="n">5</span><span class="l">Informational')) -Message "the bottom line shows 3 High, 6 Medium and 5 Info"
    Write-TestResult -Succeeded ($summary.Contains("<b>2026-09-30 13:40 UTC") -and $summary.Contains("<b>2026-10-01 10:00 UTC")) -Message "the bottom line shows the earliest and latest flagged time"
    Write-TestResult -Succeeded ($summary.Contains("2026-10-08 14:20 UTC") -and $summary.Contains("2026-10-08 07:20 machine time, UTC-07:00")) -Message "the collection time is shown in UTC and in the machine's time zone"
    Write-TestResult -Succeeded ($summary.Contains("WIN11-LAB01") -and $summary.Contains("Windows 11 Pro 24H2") -and $summary.Contains("alice, bob, Administrator, svc_backup") -and $summary.Contains("245,243 timeline rows")) -Message "the key facts show host, OS, users and the rows covered"
    $topLinks = @([regex]::Matches($summary, 'href="#finding-(F\d+)"') | ForEach-Object { $_.Groups[1].Value })
    Write-TestResult -Succeeded (($topLinks -join ",") -eq "F001,F002,F003,F004,F005") -Message "the summary lists the top five leads in order ($($topLinks -join ','))"
    Write-TestResult -Succeeded ($summary.Contains("What this report can&#39;t tell you") -and $summary.Contains("A missing event proves nothing")) -Message "the summary has the 'What this report can't tell you' box with the caveats"
    Write-TestResult -Succeeded ($summary.Contains('href="./timeline.xlsx"')) -Message "the summary links to the workbook with a relative link"

    # Finding cards
    $cards = @([regex]::Matches($html, '<article class="finding f-(high|medium)" id="finding-(F\d+)">') | ForEach-Object { $_.Groups[2].Value })
    Write-TestResult -Succeeded (($cards -join ",") -eq "F003,F001,F002,F004,F005,F006,F007,F008,F009") -Message "every High and Medium finding has a card, in its category section ($($cards -join ','))"
    Write-TestResult -Succeeded ([regex]::Matches($html, '<span class="sev sev-high">High</span>').Count -ge 6 -and [regex]::Matches($html, '<span class="sev sev-medium">Medium</span>').Count -ge 12) -Message "severity is shown as a text label (High / Medium) with its color class"
    $f001Start = $html.IndexOf('id="finding-F001"')
    $f001 = $html.Substring($f001Start, $html.IndexOf('</article>', $f001Start) - $f001Start)
    $fieldChecks = @("Microsoft Defender found a malicious file", "<th>Technical detail</th>", "<th>What to check next</th>", "<th>Common benign causes</th>", "MITRE ATT&amp;CK T1204", "Trojan:Win32/Synthetic.A!test",
        '<td class="num mono">74550</td>', '<td class="num mono">74553</td>', "2026-10-01 09:12:03.412", "Escalated:", 'href="./timeline.xlsx"', "Finding&quot; column")
    $missing = @($fieldChecks | Where-Object { -not $f001.Contains($_) })
    Write-TestResult -Succeeded ($missing.Count -eq 0) -Message "a finding card shows why, technical detail, next steps, false positives, references, evidence rows with Excel row numbers and the workbook link (missing: $($missing -join ' | '))"
    Write-TestResult -Succeeded ($html.Contains("Showing 12 of the 40 rows of this lead (the earliest")) -Message "a truncated evidence list says how many rows the lead has in all"
    Write-TestResult -Succeeded ($html.Contains("1 more matching row was set aside by the allowlist")) -Message "allowlisted rows are counted on the finding"
    $fileSystemStart = $html.IndexOf('id="file-system"')
    $fileSystem = $html.Substring($fileSystemStart, $html.IndexOf('</section>', $fileSystemStart) - $fileSystemStart)
    Write-TestResult -Succeeded ($fileSystem.Contains("No High or Medium leads in this category. 2 rules in this category were checked.") -and $html.Contains('<section class="page flow" id="file-system">')) -Message "a category without leads says so, says how many rules were checked, and does not take a page of its own"

    # Escaping: markup, quotes and non-ASCII text from the evidence
    Write-TestResult -Succeeded (-not $html.Contains("<script>alert") -and $html.Contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")) -Message "markup in a value is escaped, not executed"
    Write-TestResult -Succeeded ($html.Contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt; &amp; more")) -Message "quotes, angle brackets and ampersands in a value are escaped"
    Write-TestResult -Succeeded ($html.Contains("Caf&#xE9; na&#xEF;ve &#x2013;") -and $html.Contains("&#x1F600;")) -Message "non-ASCII text becomes numeric entities (including a surrogate pair as one code point)"

    # Activity charts and appendix
    $charts = [regex]::Matches($html, '<svg class="chart"').Count
    Write-TestResult -Succeeded ($charts -eq 3 -and $html.Contains(">Hour of day (UTC)") -and $html.Contains(">Sep 30</text>") -and $html.Contains('class="mark-high"')) -Message "the activity section has three labelled inline SVG charts (per day, per month, per hour) with lead markers ($charts)"
    Write-TestResult -Succeeded ($html.Contains("Busiest day in this window: <b>2026-10-08</b> with 151,230 rows")) -Message "the busiest day is stated in text"
    $infoRows = @([regex]::Matches($html, '<tr id="finding-(F\d+)">') | ForEach-Object { $_.Groups[1].Value })
    Write-TestResult -Succeeded (($infoRows -join ",") -eq "F010,F011,F012,F013,F014") -Message "Info items are listed in Appendix A ($($infoRows -join ','))"
    Write-TestResult -Succeeded ($html.Contains(">P17-MASS-RENAME</td>") -and $html.Contains("Rules used")) -Message "Appendix B lists the rules"
    Write-TestResult -Succeeded ($html.Contains($timelineHash) -and $html.Contains("findings.csv</td><td><span class=""muted"">not available")) -Message "Appendix D hashes the files next to the report (timeline.csv) and marks missing ones"
    Write-TestResult -Succeeded ($html.Contains("size: letter;") -and $html.Contains('content: "Timeline\000020 report\000020 -\000020 WIN11-LAB01"')) -Message "the page size and the escaped footer text are in the print CSS"
    Write-TestResult -Succeeded ($html.Contains("Microsoft-Windows-PowerShell%4Operational.evtx") -and $html.Contains("5 *")) -Message "the coverage table flags an event log that starts less than 7 days before collection"

    # --- Minimal model: no findings, no workbook, /Date(ms)/ dates ---
    $minimalDir = Join-Path $workDir "minimal"
    $minimalHtmlPath = Join-Path $minimalDir "report.html"
    Export-ReportHtml -Model (Read-TestModel "model-minimal.json") -Path $minimalHtmlPath -PaperSize A4
    Test-TextFileBytes -Path $minimalHtmlPath -Label "the minimal report.html"
    $minimal = [System.IO.File]::ReadAllText($minimalHtmlPath)
    Test-HtmlSafety -Html $minimal -Label "the minimal report"
    Write-TestResult -Succeeded ($minimal.Contains("The rules found <b>no High or Medium leads</b>") -and $minimal.Contains("That is not proof that the computer is clean")) -Message "the minimal report says no leads were found, without a verdict"
    Write-TestResult -Succeeded (-not $minimal.Contains("<article") -and -not $minimal.Contains('id="leads"') -and -not $minimal.Contains('href="./')) -Message "the minimal report has no finding cards, no leads index and no workbook link"
    Write-TestResult -Succeeded ($minimal.Contains("Not created for this timeline (CSV only), or not updated for this report. Row numbers in this report are rows of timeline.csv, counting the header as row 1, as Excel would.</td>")) -Message "the minimal report says the workbook was not created, in a whole sentence that names timeline.csv"
    Write-TestResult -Succeeded ($minimal.Contains("2026-10-08 14:20 UTC") -and $minimal.Contains("Report made 2026-10-08 15:22 UTC")) -Message "/Date(ms)/ dates are read"
    Write-TestResult -Succeeded ($minimal.Contains("credential material") -and $minimal.Contains("size: a4;")) -Message "the minimal report flags credential material and uses A4 when asked"

    # --- In-memory model: dictionaries, [datetime] values, a JSON round trip ---
    $collectionStart = [datetime]::SpecifyKind([datetime]"2026-10-08 14:20:05", [System.DateTimeKind]::Utc)
    $evidenceRow = [pscustomobject]@{ RowNumber = 1234; Timestamp = "2026-10-07 09:13:44.123"; Source = "Security.evtx"; EventType = "Logon"; Description = "Synthetic row"; User = "carol"; Details = "LogonType=3 Source=-:-"; Artifact = "EventLog"; RawPath = "" }
    $finding = [ordered]@{ Id = "F001"; RuleId = "T-1"; Title = "In-memory lead"; Category = "Access"; Severity = "High"; Why = "Plain words."; Technical = "Detail."; NextSteps = "Check."; FalsePositives = "Benign."
        References = @("MITRE ATT&CK T1078"); GroupKey = "carol"; Count = 1; FirstSeenUtc = $collectionStart.AddDays(-1); LastSeenUtc = $collectionStart.AddDays(-1).ToLocalTime(); Evidence = @($evidenceRow)
        EvidenceTruncated = $false; Escalated = $false; AllowlistedCount = 0 }
    $memoryModel = [ordered]@{
        SchemaVersion = 1; GeneratedUtc = (Get-Date -Date $collectionStart)
        Collection = [ordered]@{ ComputerName = "MEMORY-PC"; OS = "Windows 11"; Users = @("carol"); Mode = "Live"; TargetTimeZoneId = "UTC"; CollectionStartUtc = $collectionStart; CollectorUser = "carol"; SecretsIncluded = $false; ThunderbirdIndexIncluded = $false }
        TimeSpan = [ordered]@{ FirstUtc = $collectionStart.AddDays(-2); LastUtc = $collectionStart; Rows = 10 }
        Counts = [ordered]@{ High = 1; Medium = 0; Info = 0 }; TopFindings = @("F001"); Findings = @($finding); InfoFindings = @()
        Coverage = [ordered]@{ Sources = @([ordered]@{ Source = "Security.evtx"; Rows = 10; FirstUtc = $collectionStart.AddDays(-2); LastUtc = $collectionStart }); LogClears = @(); Boots = @(); AuditNotes = @(); CollectorErrors = [ordered]@{ Count = 0; Lines = @() }; Notes = @() }
        Activity = [ordered]@{ PerDay = @([ordered]@{ Day = "2026-10-07"; Rows = 10 }); PerHourUtc = @(0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); TopSources = @([ordered]@{ Source = "Security.evtx"; Rows = 10 }); PerUser = @([ordered]@{ User = "carol"; Rows = 10 }) }
        Caveats = @("Synthetic caveat."); Rules = @([ordered]@{ Id = "T-1"; Title = "In-memory rule"; Severity = "High"; Category = "Access" })
        Workbook = [ordered]@{ FileName = "my timeline #1.xlsx"; Available = $true; TimelineSheet = "Timeline"; FindingsSheet = "Findings" }
        Files = [ordered]@{ TimelineCsv = "timeline.csv"; FindingsCsv = "findings.csv" }
    }
    $memoryHtmlPath = Join-Path $workDir "memory\report.html"
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $memory = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($memory.Contains("Report made 2026-10-08 14:20 UTC") -and $memory.Contains("2026-10-07 14:20:05 UTC") -and $memory.Contains("In-memory lead")) -Message "an in-memory model (dictionaries, [datetime] values in UTC and local time) renders"
    Write-TestResult -Succeeded ($memory.Contains('href="./my%20timeline%20%231.xlsx"')) -Message "the workbook file name is percent-encoded in its relative link"
    $roundTrip = $memoryModel | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    Export-ReportHtml -Model $roundTrip -Path $memoryHtmlPath -NoFileHashes
    $memoryJson = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($memoryJson.Contains("Report made 2026-10-08 14:20 UTC") -and $memoryJson.Contains("2026-10-07 14:20:05 UTC")) -Message "the same model after ConvertTo-Json / ConvertFrom-Json renders the same times ($($PSVersionTable.PSEdition))"

    # Fields the engine's model adds: Files.Hashes (used, not listed as a
    # file), a finding seen only during the collection, and no workbook
    $finding.DuringCollection = $true
    $memoryModel.Workbook = [ordered]@{ FileName = "timeline.xlsx"; Available = $false; TimelineSheet = "Timeline"; FindingsSheet = "Findings" }
    $csvHash = "0123456789ABCDEF" * 4
    $zipHash = "FEDCBA9876543210" * 4
    $memoryModel.Files = [ordered]@{ TimelineCsv = "timeline.csv"; FindingsCsv = "findings.csv"; Hashes = @(
            [ordered]@{ Name = "timeline.csv"; Bytes = 10; Sha256 = $csvHash },
            [ordered]@{ Name = "collection.zip"; Bytes = 20; Sha256 = $zipHash }) }
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath
    $engineShape = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($engineShape.Contains($csvHash) -and $engineShape.Contains("Collection (zip)</td><td>collection.zip</td>") -and $engineShape.Contains($zipHash) -and -not $engineShape.Contains(">Hashes<")) -Message "Appendix D uses the model's Files.Hashes (timeline.csv, the collection zip) and does not list Hashes as a file"
    Write-TestResult -Succeeded ($engineShape.Contains("Every row is from during the collection")) -Message "a lead whose rows are all from during the collection says it may be the collector's own activity"
    Write-TestResult -Succeeded ($engineShape.Contains(">CSV row</th>") -and -not $engineShape.Contains(">Excel row</th>") -and $engineShape.Contains("Rows are numbered as in timeline.csv")) -Message "without the workbook, row numbers are labelled as timeline.csv rows"
    # A lead seen only in Snapshot rows from during the collection (a process
    # in the memory dump): when it was seen, not "the collector's own activity"
    $finding.DuringCollection = $false
    $finding.CapturedDuringCollection = $true
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath
    $captured = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($captured.Contains("Seen only in Snapshot rows from during the collection (the state when it was collected or the memory dump captured): it may have started earlier. Check that it is not the collector or its memory tool") -and
        -not $captured.Contains("Every row is from during the collection")) -Message "a lead seen only in Snapshot rows from during the collection (the memory dump) says so and to check it is not the collector, instead of 'may be the collector's own activity'"
    $finding.CapturedDuringCollection = $false

    # --- Hostile and edge values: bidi controls, a long unbroken title, more
    # evidence than a card prints, a lead dated by file times, a folded lead,
    # an assumed time zone, a missing collector log, a {{group}} rule title ---
    $rtlo = [string][char]0x202E
    $finding.Title = "Lead " + ("x" * 300)
    $finding.Why = "Short why." + $rtlo + " reversed sentence follows. Second sentence."
    $finding.Escalated = $true
    $finding.Count = 29
    $finding.RowNumbers = @(2001..2030)
    $finding.EvidenceTruncated = $true
    $finding.Evidence = @(1..20 | ForEach-Object {
        [pscustomobject]@{ RowNumber = 2000 + $_; Timestamp = ("2026-10-07 09:13:{0:00}.000" -f $_); Source = "Security.evtx"; EventType = "Logon"; Description = ("invoice" + $rtlo + "fdp.exe row " + $_); User = "carol"; Details = ""; Escalation = ($_ -eq 20) }
    })
    $fileTimed = [ordered]@{ Id = "F002"; RuleId = "T-2"; Title = "File-time lead"; Category = "FileSystem"; Severity = "Medium"; Why = "Old file times."; Count = 1; ActivityTime = $false
        FirstSeenUtc = [datetime]::new(2020, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc); LastSeenUtc = [datetime]::new(2020, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc); Evidence = @($evidenceRow) }
    $foldedLead = [ordered]@{ Id = "F003"; RuleId = "T-1"; Title = "In-memory lead (7 more, folded into one lead)"; Category = "Access"; Severity = "Medium"; Why = "Plain words."; Count = 7; FoldedGroups = 7
        GroupKey = "7 more: a, b, c, d, e, f, g"; FirstSeenUtc = $collectionStart.AddHours(-3); LastSeenUtc = $collectionStart.AddHours(-2); Evidence = @($evidenceRow) }
    $memoryModel.Findings = @($finding, $fileTimed, $foldedLead)
    $memoryModel.Counts = [ordered]@{ High = 1; Medium = 2; Info = 0 }
    $memoryModel.TopFindings = @("F001", "F002")
    $memoryModel.Collection.TargetTimeZoneId = "Pacific Standard Time"
    $memoryModel.Collection.TargetTimeZoneAssumed = $true
    $memoryModel.Coverage.CollectorErrors = [ordered]@{ Available = $false; Count = $null; Lines = @() }
    $memoryModel.Rules = @([ordered]@{ Id = "T-1"; Title = "Lead about {{group}}"; Severity = "High"; Category = "Access" })
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $hostile = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($hostile.Contains("invoice[U+202E]fdp.exe row 1") -and $hostile.Contains("Short why.[U+202E] reversed") -and -not $hostile.Contains("&#x202E;")) -Message "a right-to-left override in a value becomes a visible [U+202E] marker, so it cannot reverse the report's text"
    Write-TestResult -Succeeded ($hostile.Contains("Lead " + ("x" * 155) + " [...]") -and -not $hostile.Contains("x" * 200)) -Message "a long title is cut on the card and in the index (the full value stays under 'Grouped by')"
    Write-TestResult -Succeeded ($hostile.Contains("h1, h2, h3, h4, p, li, td, th, div, span, a { overflow-wrap: anywhere; }")) -Message "long unbroken values wrap anywhere, so a page is never wider than the paper (Chromium would shrink the whole PDF)"
    $hostileCardStart = $hostile.IndexOf('id="finding-F001"')
    $hostileCard = $hostile.Substring($hostileCardStart, $hostile.IndexOf('</article>', $hostileCardStart) - $hostileCardStart)
    $printedRows = @([regex]::Matches($hostileCard, '<td class="num mono">(\d+)</td>') | ForEach-Object { $_.Groups[1].Value })
    Write-TestResult -Succeeded ($printedRows.Count -eq 15 -and $printedRows -contains "2020" -and $printedRows -contains "2001" -and $printedRows -notcontains "2015") -Message "a card prints 15 evidence rows: the row that raised the severity and the earliest ($($printedRows -join ','))"
    Write-TestResult -Succeeded ($hostileCard.Contains("Showing 15 of the 30 rows of this lead (the earliest, and the rows that raised its severity). findings.csv lists 20.")) -Message "the card says how many rows it shows, of how many, and where the rest are"
    $hostileSummary = $hostile.Substring($hostile.IndexOf('id="summary"'), $hostile.IndexOf('" id="leads">') - $hostile.IndexOf('id="summary"'))
    Write-TestResult -Succeeded ($hostileSummary.Contains("<b>2026-10-07 14:20 UTC") -and -not $hostileSummary.Contains("<b>2020-01-01") -and $hostileSummary.Contains("(plus 1 lead dated by file times")) -Message "the flagged-activity window leaves out a lead dated by file times and says so"
    Write-TestResult -Succeeded ($hostileSummary.Contains("(and 1 similar lead)")) -Message "a top lead says how many more leads its rule has"
    Write-TestResult -Succeeded ($hostileSummary.Contains("<b>assumed</b>: the collection does not record the computer&#39;s time zone")) -Message "an assumed time zone is marked as assumed"
    Write-TestResult -Succeeded ($hostile.Contains("Folds 7 similar groups of this rule into one lead") -and $hostile.Contains("Dated by file times")) -Message "a folded lead and a lead dated by file times are flagged on their cards"
    Write-TestResult -Succeeded ($hostile.Contains("collection_log.txt) was not available, so problems during the collection are unknown") -and -not $hostile.Contains("logged no errors")) -Message "a missing collector log is not reported as a collection without errors"
    Write-TestResult -Succeeded ($hostile.Contains(">Lead about</td>") -and -not $hostile.Contains("{{group}}")) -Message "Appendix B shows rule titles without the {{group}} placeholder"
    Write-TestResult -Succeeded ($hostile.Contains("2001, 2002, 2003 +27 more")) -Message "the leads index counts every row of a lead after the first ones, not only evidence rows"
    # A lead dated only by a scheduled task's author-supplied date: left out
    # of the window like file times, with its own wording
    $fileTimed.TimesAuthorSupplied = $true
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $authorDated = [System.IO.File]::ReadAllText($memoryHtmlPath)
    $authorSummary = $authorDated.Substring($authorDated.IndexOf('id="summary"'), $authorDated.IndexOf('" id="leads">') - $authorDated.IndexOf('id="summary"'))
    Write-TestResult -Succeeded ($authorSummary.Contains("(plus 1 lead dated by author-supplied task dates, which can be older than the activity or altered)") -and -not $authorSummary.Contains("<b>2020-01-01") -and
        $authorDated.Contains("Dated only by a scheduled task&#39;s author-supplied registration date") -and -not $authorDated.Contains("Dated by file times")) -Message "a lead dated only by a task's author-supplied date is left out of the activity window, and its card and the summary say so"
    $fileTimed.TimesAuthorSupplied = $false
    $memoryModel.Coverage.CollectorErrors = [ordered]@{ Available = $true; Count = 0; WarningCount = 1; Lines = @("[2026-10-08 14:20:00] WARNING: Could not copy BBI") }
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $warned = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($warned.Contains("The collector logged 0 errors and 1 warning.") -and $warned.Contains("WARNING: Could not copy BBI")) -Message "collector warnings are counted as warnings, not errors"
    Write-TestResult -Succeeded (-not $warned.Contains("Timeline incomplete") -and -not $warned.Contains('class="incomplete"')) -Message "a model without TimelineCompleteness (or a complete run) shows no incomplete-timeline block"

    # --- A mounted image: the examined computer, not the collector host ---
    $memoryModel.Collection.Mode = "MountedImage"
    $memoryModel.Collection.ComputerName = ""
    $memoryModel.Collection.ComputerNameSource = ""
    $memoryModel.Collection.CollectorHost = "ANALYST-WS"
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $image = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($image.Contains("<h1>Unknown computer</h1>") -and $image.Contains("<th>Computer</th><td>Not known: the collection was made from a mounted disk image, and the image&#39;s computer name was not found (its SYSTEM hive was not read). The collection was made on ANALYST-WS, which is not the examined computer.</td>")) -Message "a mounted image whose computer name is not known says so, and names the collector host only as such"
    Write-TestResult -Succeeded (-not $image.Contains("Timeline report - ANALYST-WS") -and -not $image.Contains("<h1>ANALYST-WS")) -Message "the collector host is not the report's title or page footer"
    $memoryModel.Collection.ComputerName = "IMAGED-PC"
    $memoryModel.Collection.ComputerNameSource = "SYSTEM hive"
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $imageNamed = [System.IO.File]::ReadAllText($memoryHtmlPath)
    Write-TestResult -Succeeded ($imageNamed.Contains("<h1>IMAGED-PC</h1>") -and $imageNamed.Contains("<th>Computer</th><td>IMAGED-PC <span class=""muted small"">(from the image&#39;s SYSTEM hive)</span></td>") -and $imageNamed.Contains("Timeline report - IMAGED-PC")) -Message "a mounted image's computer name from its SYSTEM hive is the title, the key fact (with its source) and the page footer"

    # --- A timeline that ended incomplete (builder exit code 2) ---
    $memoryModel.Coverage.TimelineCompleteness = [ordered]@{ Incomplete = $true; MissingInputFiles = 2; UnexpectedErrors = 1
        Lines = @("The timeline is incomplete: 2 input file(s) disappeared while it was built (the builder ended with exit code 2), so rows from them may be missing and a missing event proves even less.",
            "The builder hit 1 unexpected error(s) and skipped the rest of those steps (exit code 2): the timeline may be incomplete.") }
    Export-ReportHtml -Model $memoryModel -Path $memoryHtmlPath -NoFileHashes
    $incomplete = [System.IO.File]::ReadAllText($memoryHtmlPath)
    $coverageStart = $incomplete.IndexOf('id="coverage"')
    $incompleteAt = $incomplete.IndexOf("<h3>Timeline incomplete</h3>")
    Write-TestResult -Succeeded ($coverageStart -gt 0 -and $incompleteAt -gt $coverageStart -and $incompleteAt -lt $incomplete.IndexOf("<h3>Integrity leads</h3>") -and
        $incomplete.Contains("<p><b>The timeline is incomplete: 2 input file(s) disappeared while it was built") -and $incomplete.Contains("<p><b>The builder hit 1 unexpected error(s)")) -Message "an incomplete timeline is the first thing in Evidence coverage and integrity, one paragraph per problem"

    # --- PDF with Microsoft Edge ---
    $result = @(ConvertTo-ReportPdf -HtmlPath $fullHtmlPath -PdfPath (Join-Path $fullDir "nope.pdf") -EdgePath (Join-Path $workDir "no-such-folder\msedge.exe"))
    Write-TestResult -Succeeded ($result.Count -eq 1 -and $result[0] -is [bool] -and -not $result[0] -and
        -not (Test-Path -LiteralPath (Join-Path $fullDir "nope.pdf")) -and $script:ReportPdfLastError) -Message "ConvertTo-ReportPdf returns a single `$false without throwing when Edge is missing ($script:ReportPdfLastError)"
    Write-TestResult -Succeeded (-not (ConvertTo-ReportPdf -HtmlPath (Join-Path $workDir "missing.html") -PdfPath (Join-Path $fullDir "nope.pdf"))) -Message "ConvertTo-ReportPdf returns `$false for a missing HTML file"
    $edge = Find-ReportPdfEdge
    if (-not $edge) {
        Write-Host "SKIP: Microsoft Edge (msedge.exe) was not found; PDF checks skipped" -ForegroundColor Yellow
    }
    else {
        Write-Host "Using Edge: $edge"
        $fullPdf = Join-Path $fullDir "report.pdf"
        $stopwatch.Restart()
        $result = @(ConvertTo-ReportPdf -HtmlPath $fullHtmlPath -PdfPath $fullPdf)
        $ok = ($result.Count -eq 1 -and $result[0] -is [bool] -and $result[0])
        Write-TestResult -Succeeded ($ok -and (Test-Path -LiteralPath $fullPdf)) -Message "ConvertTo-ReportPdf printed the full report and returned a single `$true ($($stopwatch.ElapsedMilliseconds) ms) $script:ReportPdfLastError"
        if (Test-Path -LiteralPath $fullPdf) {
            $info = Get-TestPdfInfo -Path $fullPdf
            Write-TestResult -Succeeded ($info.Text.StartsWith("%PDF-")) -Message "the full PDF starts with %PDF"
            Write-TestResult -Succeeded ($info.Pages -ge 8 -and $info.Pages -le 40) -Message "the full PDF has a sensible page count ($($info.Pages))"
            Write-TestResult -Succeeded ([Math]::Abs($info.Width - 612) -lt 2 -and [Math]::Abs($info.Height - 792) -lt 2) -Message "the full PDF is Letter size ($($info.Width) x $($info.Height) pt)"
            $xref = Test-PdfXref -Text $info.Text
            Write-TestResult -Succeeded ($xref.StartsWith("ok")) -Message "the full PDF's xref table is valid after the link rewrite ($xref)"
            Write-TestResult -Succeeded ([regex]::Matches($info.Text, '/URI\s*\(\./timeline\.xlsx\)').Count -ge 10) -Message "the PDF links to the workbook with the relative URI ./timeline.xlsx"
            Write-TestResult -Succeeded (-not $info.Text.Contains("file:///") -and $info.Text.IndexOf($workDir.Replace('\', '/'), [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "the PDF holds no local file path"
            Write-TestResult -Succeeded ([regex]::Matches($info.Text, '/Dest\b').Count -ge 9) -Message "the PDF keeps the internal links (summary and index to the finding cards)"
        }
        $minimalPdf = Join-Path $minimalDir "report.pdf"
        $ok = ConvertTo-ReportPdf -HtmlPath $minimalHtmlPath -PdfPath $minimalPdf
        Write-TestResult -Succeeded ($ok -and (Test-Path -LiteralPath $minimalPdf)) -Message "ConvertTo-ReportPdf printed the minimal report $script:ReportPdfLastError"
        if (Test-Path -LiteralPath $minimalPdf) {
            $info = Get-TestPdfInfo -Path $minimalPdf
            Write-TestResult -Succeeded ($info.Text.StartsWith("%PDF-") -and $info.Pages -ge 3 -and $info.Pages -le 12) -Message "the minimal PDF starts with %PDF and has a sensible page count ($($info.Pages))"
            Write-TestResult -Succeeded ([Math]::Abs($info.Width - 595.3) -lt 2 -and [Math]::Abs($info.Height - 841.9) -lt 2) -Message "the minimal PDF is A4 size ($($info.Width) x $($info.Height) pt)"
            Write-TestResult -Succeeded (-not $info.Text.Contains("/URI")) -Message "the minimal PDF has no workbook link"
        }
        $profilesAfter = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter "timeline-report-edge-*" -ErrorAction SilentlyContinue).Count
        Write-TestResult -Succeeded ($profilesAfter -le $profilesBefore) -Message "no temporary Edge profile folder is left behind ($profilesBefore before, $profilesAfter after)"
    }

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all report renderer checks passed" -ForegroundColor Green
    exit 0
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    exit 1
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
