# =============================================================
# Memory parser test
# Checks where the Memory parser finds a collection's memory dump
# (Find-MemoryDump) on synthetic folders: -MemoryDumpPath first (also a
# relative path and one with [ ] in it; a path that is not a file is
# reported once, then the other places are tried), the dump next to the
# collection zip (.dmp or .raw), Memory\ inside the collection (never the
# Secrets\ folder of -IncludeSecrets or the email attachment copies), and the
# dump next to the collection folder or next to -InputPath (an outer
# folder of another name, also given as a relative path), which must be
# named after the collection folder: another collection's dump in the same
# folder (e.g. the collector's reports\) is never used. The collection
# folder is the folder of collection_manifest.csv (also below -InputPath
# and in the <name>\<name>\ layout of Windows "Extract All"), else
# -InputPath. Parse-Memory without a dump must point to -MemoryDumpPath.
# Then the dump header (Get-MemoryDumpInfo) on synthetic headers: the
# architecture and the capture time (DUMP_HEADER64.SystemTime; zero,
# implausible, 32-bit and raw fall back to the file's last-write time),
# also through Parse-Memory's "Dump time" line; and the rows made from
# canned Volatility JSON (Add-MemoryPluginRows): pslist and netscan entries
# with a valid time of their own are events, every other row is a Snapshot
# row at the capture time, a rejected time stays in Details, a 0 in a PID,
# PPID, Threads, SessionId or port is kept (null and N/A give ""), and the
# counts. The rows must be the same under the de-DE culture. A stub stands
# in for vol.exe to check where its output goes (Invoke-VolatilityPlugin),
# and in a whole Parse-Memory run (rows at the header's capture time, the
# counts per plugin in the log, the warning for a plugin without output).
# Volatility 3 is not run.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryParser.ps1
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
        Write-Host "::error file=tests/Test-MemoryParser.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
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

# A small file (the content does not matter to Find-MemoryDump), with its folders
function New-TestFile {
    param([string]$Path)
    [void][System.IO.Directory]::CreateDirectory((Split-Path $Path -Parent))
    [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] 16))
}

# A collection folder with an (empty) collection_manifest.csv
function New-TestCollection {
    param([string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    [System.IO.File]::WriteAllText((Join-Path $Path "collection_manifest.csv"), "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath`r`n")
}

# The script-scope state the builder sets up for a run: -InputPath (the
# extracted folder for a zip), the zip, -MemoryDumpPath, the collection
# root and a new log file
function Set-TestRunState {
    param([string]$Collection, [string]$Zip = "", [string]$DumpPath = "")
    $script:InputPath = $Collection
    $script:selectedZipPath = $Zip
    $script:MemoryDumpPath = $DumpPath
    $script:collectionManifest = $null
    $script:memoryDumpPathWarned = $false
    # Find-ArtifactFiles skips the email attachment copies (relative to the
    # collection root) and the Secrets\ folder, which the builder looks up
    # once per run
    $script:collectionRoot = Get-CollectionRootFolder
    $script:secretsRoot = $null
    $script:logFile = Join-Path $workDir ("builder-" + [guid]::NewGuid().ToString("N") + ".log")
}

# Find-MemoryDump for one run: the dump found ("" for none) and what was logged
function Invoke-FindMemoryDump {
    param([string]$Collection, [string]$Zip = "", [string]$DumpPath = "")
    Set-TestRunState -Collection $Collection -Zip $Zip -DumpPath $DumpPath
    $found = Find-MemoryDump
    return [PSCustomObject]@{ Path = "$found"; Log = (Get-TestLog) }
}

function Get-TestLog {
    if (-not (Test-Path -LiteralPath $script:logFile)) { return "" }
    return [System.IO.File]::ReadAllText($script:logFile)
}

# A synthetic memory dump header: the signature, the machine type at 0x30
# and SystemTime (a FILETIME) at 0xFA8 in -Length zero bytes, with the
# file's last-write time set to -LastWriteUtc
function New-TestDump {
    param([string]$Path, [string]$Signature = "PAGEDU64", [uint32]$Machine = 0x8664, [long]$SystemTime = 0,
        [int]$Length = 0x2000, [datetime]$LastWriteUtc)
    $bytes = New-Object byte[] $Length
    $signatureBytes = [System.Text.Encoding]::ASCII.GetBytes($Signature)
    [Array]::Copy($signatureBytes, 0, $bytes, 0, [Math]::Min($signatureBytes.Length, $Length))
    if ($Length -ge 0x34) { [Array]::Copy([BitConverter]::GetBytes($Machine), 0, $bytes, 0x30, 4) }
    if ($Length -ge 0xFB0) { [Array]::Copy([BitConverter]::GetBytes($SystemTime), 0, $bytes, 0xFA8, 8) }
    [void][System.IO.Directory]::CreateDirectory((Split-Path $Path -Parent))
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    [System.IO.File]::SetLastWriteTimeUtc($Path, $LastWriteUtc)
}

# Get-MemoryDumpInfo's result as "Architecture|capture time Kind|TimeSource|last write"
function Format-DumpInfo {
    param($Info)
    $capture = ""
    $lastWrite = ""
    if ($null -ne $Info.CaptureTimeUtc) { $capture = "$(Format-TestTime $Info.CaptureTimeUtc) $($Info.CaptureTimeUtc.Kind)" }
    if ($null -ne $Info.LastWriteUtc) { $lastWrite = Format-TestTime $Info.LastWriteUtc }
    return "$($Info.Architecture)|$capture|$($Info.TimeSource)|$lastWrite"
}

function Format-TestTime {
    param([datetime]$Time)
    return $Time.ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Add-MemoryPluginRows on canned Volatility JSON (through ConvertFrom-Json,
# as Parse-Memory does), with the capture time and end of acquisition of
# the test dump: the counts as "Entries|Timed|Snapshot" and each row as
# "Timestamp|EventType|Description|User|Details"
function Invoke-MemoryPluginRows {
    param([string]$Plugin, [string]$Source, [string]$Json)
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:artifactStats = @{}
    $entries = $Json | ConvertFrom-Json
    $counts = Add-MemoryPluginRows -Plugin $Plugin -Source $Source -Entries $entries `
        -CaptureTimeUtc $captureUtc -AcquisitionEndUtc $endUtc -DumpPath $rowDump
    $other = @($script:timelineEntries | Where-Object { $_.Source -ne $Source -or $_.Artifact -ne "MemoryDump" -or $_.RawPath -ne $rowDump })
    return [PSCustomObject]@{
        Counts = "$($counts.Entries)|$($counts.Timed)|$($counts.Snapshot)"
        Rows   = @($script:timelineEntries | ForEach-Object { "$($_.Timestamp)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)" })
        Other  = $other.Count
    }
}

# Synthetic collection names, as the collector makes them (TriageCollection_<time>)
$nameA = "TriageCollection_2025-06-30_12-00"   # zip and dump in reports\, also a folder
$nameB = "TriageCollection_2025-06-29_08-15"   # another collection: only its dump
$nameC = "TriageCollection_2025-06-28_17-40"   # no dump of its own next to it
$nameD = "TriageCollection_2025-06-27_09-05"   # -NoCompress: Memory\memory_dump.raw inside
$nameE = "TriageCollection_2025-06-26_14-30"   # Windows "Extract All" layout
$nameF = "TriageCollection_2025-06-25_10-10"   # manifest below -InputPath
$nameG = "TriageCollection_2025-06-24_16-45"   # a folder named like its dump
$nameH = "TriageCollection_2025-06-23_11-20"   # no collection_manifest.csv
$nameR = "TriageCollection_2025-06-22_13-55"   # a raw image next to the zip
$nameI = "TriageCollection_2025-06-21_15-35"   # extracted into a folder of another name
$nameJ = "TriageCollection_2025-06-20_18-25"   # -IncludeSecrets: dump names in excluded folders
$missingWarning = "-MemoryDumpPath is not an existing file:"

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("memory-parser-test-" + [guid]::NewGuid().ToString("N"))
$pushed = $false
try {
    Write-Host "Testing Find-MemoryDump ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."
    $reports = Join-Path $workDir "reports"
    $extracted = Join-Path $workDir "work\in"
    $dumps = Join-Path $workDir "dumps"
    $cases = Join-Path $workDir "cases"
    $caseDir = Join-Path $workDir "Case001"   # <zip>, its dump, Extracted\<collection>\

    foreach ($name in @($nameA, $nameC, $nameR)) {
        New-TestFile (Join-Path $reports "$name.zip")
        New-TestCollection (Join-Path $extracted $name)
    }
    $dumpA = Join-Path $reports "${nameA}_memory_dump.dmp"
    $dumpB = Join-Path $reports "${nameB}_memory_dump.dmp"
    $dumpR = Join-Path $reports "${nameR}_memory_dump.raw"
    $dumpE = Join-Path $reports "${nameE}_memory_dump.raw"
    $dumpF = Join-Path $cases "${nameF}_memory_dump.dmp"
    $dumpH = Join-Path $reports "${nameH}_memory_dump.dmp"
    $dumpD = Join-Path $reports "$nameD\Memory\memory_dump.raw"
    $elsewhereA = Join-Path $dumps "${nameA}_memory_dump.dmp"
    $elsewhereC = Join-Path $dumps "${nameC}_memory_dump.dmp"
    $bracketedC = Join-Path $workDir "dumps [7]\${nameC}_memory_dump.dmp"
    $dumpI = Join-Path $caseDir "${nameI}_memory_dump.dmp"
    $otherI = Join-Path $caseDir "${nameB}_memory_dump.dmp"
    $dumpJ = Join-Path $reports "${nameJ}_memory_dump.dmp"
    foreach ($file in @($dumpA, $dumpB, $dumpR, $dumpE, $dumpF, $dumpH, $dumpD, $elsewhereA, $elsewhereC, $bracketedC, $dumpI, $otherI, $dumpJ)) { New-TestFile $file }
    foreach ($name in @($nameA, $nameC, $nameD, $nameG)) { New-TestCollection (Join-Path $reports $name) }
    New-TestCollection (Join-Path $reports "$nameE\$nameE")
    New-TestCollection (Join-Path $reports "Extracted\$nameC")
    New-TestCollection (Join-Path $cases $nameF)
    New-TestCollection (Join-Path $caseDir "Extracted\$nameI")
    New-TestFile (Join-Path $reports "$nameH\USB\setupapi.dev.log")
    [void][System.IO.Directory]::CreateDirectory((Join-Path $reports "${nameG}_memory_dump.dmp"))
    # A collection made with the collector's -IncludeSecrets: files named like
    # a dump in its Secrets\ folder and in both email attachment folders,
    # which no parser reads
    $collectionJ = Join-Path $reports $nameJ
    New-TestCollection $collectionJ
    [System.IO.File]::WriteAllText((Join-Path $collectionJ "collection_info.json"), '{"SchemaVersion":1,"SecretsIncluded":true}')
    foreach ($rel in @("Secrets\memory_dump.raw", "Email\alice\Outlook\SecureTemp\memory_dump.dmp", "Email\alice\NewOutlook\Attachments\memory.raw")) {
        New-TestFile (Join-Path $collectionJ $rel)
    }

    # --- Next to the collection zip (browse mode, or a zip as -InputPath) -----
    $zipA = Join-Path $reports "$nameA.zip"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA
    Assert-Equal -Name "zip: the dump next to it" -Expected $dumpA -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameR) -Zip (Join-Path $reports "$nameR.zip")
    Assert-Equal -Name "zip: a raw image next to it" -Expected $dumpR -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameC) -Zip (Join-Path $reports "$nameC.zip")
    Assert-Equal -Name "zip without a dump of its own: other collections' dumps next to it are not used" -Expected "" -Actual $run.Path

    # --- -MemoryDumpPath ------------------------------------------------------
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA -DumpPath $elsewhereA
    Assert-Equal -Name "-MemoryDumpPath: used before the dump next to the zip, nothing logged" -Expected "$elsewhereA|" -Actual "$($run.Path)|$($run.Log)"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath $elsewhereC
    Assert-Equal -Name "-MemoryDumpPath: a collection folder with no dump next to it" -Expected $elsewhereC -Actual $run.Path
    Push-Location -LiteralPath $dumps
    $pushed = $true
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath ".\${nameC}_memory_dump.dmp"
    Pop-Location
    $pushed = $false
    Assert-Equal -Name "-MemoryDumpPath: a relative path becomes a full path" -Expected $elsewhereC -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath $bracketedC
    Assert-Equal -Name "-MemoryDumpPath: [ ] in the path are not wildcards" -Expected "$bracketedC|" -Actual "$($run.Path)|$($run.Log)"

    $missing = Join-Path $dumps "missing_memory_dump.dmp"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA -DumpPath $missing
    Assert-Equal -Name "-MemoryDumpPath missing: warning, then the dump next to the zip" -Expected "$dumpA|True" -Actual "$($run.Path)|$($run.Log.Contains("WARNING: $missingWarning $missing -- looking for the memory dump in and next to the collection instead."))"
    $again = Find-MemoryDump
    $warnings = ([regex]::Matches((Get-TestLog), [regex]::Escape($missingWarning))).Count
    Assert-Equal -Name "-MemoryDumpPath missing: reported once when the dump is looked for twice" -Expected "$dumpA|1" -Actual "$again|$warnings"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath $dumps
    Assert-Equal -Name "-MemoryDumpPath is a folder: warning, no dump" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$missingWarning $dumps "))"

    # A drive letter that does not exist: Get-Item fails, which must not escape
    $usedDrives = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() }) + @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpperInvariant() })
    $freeDrive = @([char[]]"ZYXWVUTSRQPONMLKJIHGFED" | Where-Object { $usedDrives -notcontains [string]$_ }) | Select-Object -First 1
    if ($freeDrive) {
        $noDrive = "${freeDrive}:\dumps\${nameA}_memory_dump.dmp"
        $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA -DumpPath $noDrive
        Assert-Equal -Name "-MemoryDumpPath on a drive that does not exist: warning, then the dump next to the zip" -Expected "$dumpA|True" -Actual "$($run.Path)|$($run.Log.Contains("$missingWarning $noDrive "))"
    }

    # --- Inside the collection folder (-NoCompress) ---------------------------
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameD)
    Assert-Equal -Name "collection folder: Memory\memory_dump.raw inside it" -Expected $dumpD -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection $collectionJ
    Assert-Equal -Name "collection folder: nothing taken from Secrets\ or the email attachment copies, the dump next to it instead" -Expected $dumpJ -Actual $run.Path

    # --- Next to the collection folder ----------------------------------------
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameA)
    Assert-Equal -Name "collection folder: the dump named after it, next to it" -Expected $dumpA -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC)
    Assert-Equal -Name "collection folder: other collections' dumps next to it are not used" -Expected "" -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameG)
    Assert-Equal -Name "collection folder: a folder named like its dump is not used" -Expected "" -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameH)
    Assert-Equal -Name "collection folder without collection_manifest.csv: named after -InputPath" -Expected $dumpH -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameE)
    Assert-Equal -Name "Extract All: the outer folder as -InputPath, the dump next to it" -Expected $dumpE -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports "$nameE\$nameE")
    Assert-Equal -Name "Extract All: the inner folder as -InputPath, the dump next to the outer one" -Expected $dumpE -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection $cases
    Assert-Equal -Name "manifest below -InputPath: the dump named after the manifest's folder" -Expected $dumpF -Actual $run.Path

    # An outer folder of another name as -InputPath (e.g. 7-Zip "Extract
    # files..." into Case001\Extracted\): the dump next to the zip is next to
    # -InputPath, not next to the collection folder
    $run = Invoke-FindMemoryDump -Collection (Join-Path $caseDir "Extracted")
    Assert-Equal -Name "outer folder of another name as -InputPath: the dump named after the collection, next to -InputPath" -Expected $dumpI -Actual $run.Path
    Push-Location -LiteralPath $caseDir
    $pushed = $true
    $run = Invoke-FindMemoryDump -Collection ".\Extracted"
    Pop-Location
    $pushed = $false
    Assert-Equal -Name "outer folder as a relative -InputPath: the dump next to it" -Expected $dumpI -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports "Extracted")
    Assert-Equal -Name "outer folder as -InputPath: other collections' dumps next to it are not used" -Expected "" -Actual $run.Path

    # --- Parse-Memory without a dump ------------------------------------------
    $noDumpWarning = "WARNING: No memory dump found in the collection or next to it (pass -MemoryDumpPath with the dump file if it was saved elsewhere)."
    Set-TestRunState -Collection (Join-Path $reports $nameC)
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory without a dump: the warning names -MemoryDumpPath, then it stops" -Expected "True|False|True" -Actual "$($log.Contains($noDumpWarning))|$($log.Contains('Found memory dump'))|$($log.Contains('Memory parsing complete.'))"
    Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $missing
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory with a missing -MemoryDumpPath and no other dump: both warnings" -Expected "True|True|False" -Actual "$($log.Contains("$missingWarning $missing "))|$($log.Contains($noDumpWarning))|$($log.Contains('Found memory dump'))"

    # --- Dump header: architecture and capture time ---------------------------
    Write-Host "Testing Get-MemoryDumpInfo, Add-MemoryPluginRows and Invoke-VolatilityPlugin ..."
    $headerDir = Join-Path $workDir "headers"
    # DumpIt took about two minutes: the header has the start, the file's
    # last-write time is the end
    $captureUtc = [datetime]::new(2025, 6, 30, 12, 0, 12, 345, [System.DateTimeKind]::Utc)
    $endUtc = [datetime]::new(2025, 6, 30, 12, 2, 14, 500, [System.DateTimeKind]::Utc)
    $captureText = "2025-06-30 12:00:12.345"
    $endText = "2025-06-30 12:02:14.500"
    $fromHeader = "$captureText Utc|crash dump header|$endText"
    $fromFile = "$endText Utc|dump file last-write time|$endText"
    $captureFileTime = $captureUtc.ToFileTimeUtc()
    $headerCases = @(
        @{ Name = "x64 crash dump: the capture time from the header"; Expected = "x64|$fromHeader"; Header = @{ SystemTime = $captureFileTime } },
        @{ Name = "ARM64 crash dump: the capture time from the header"; Expected = "ARM64|$fromHeader"; Header = @{ Machine = 0xAA64; SystemTime = $captureFileTime } },
        @{ Name = "header time a day after the last write (clock skew): used"; Expected = "x64|2025-07-01 12:02:14.500 Utc|crash dump header|$endText"; Header = @{ SystemTime = $endUtc.AddDays(1).ToFileTimeUtc() } },
        @{ Name = "header time more than a day after the last write: the last-write time"; Expected = "x64|$fromFile"; Header = @{ SystemTime = $endUtc.AddDays(1).AddMilliseconds(1).ToFileTimeUtc() } },
        @{ Name = "header time zero: the last-write time"; Expected = "x64|$fromFile"; Header = @{ SystemTime = 0 } },
        @{ Name = "header time before 1980: the last-write time"; Expected = "x64|$fromFile"; Header = @{ SystemTime = [datetime]::new(1979, 12, 31, 23, 59, 59, [System.DateTimeKind]::Utc).ToFileTimeUtc() } },
        @{ Name = "header time 1980-01-01: used"; Expected = "x64|1980-01-01 00:00:00.000 Utc|crash dump header|$endText"; Header = @{ SystemTime = [datetime]::new(1980, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).ToFileTimeUtc() } },
        @{ Name = "header time negative: the last-write time"; Expected = "x64|$fromFile"; Header = @{ SystemTime = -1 } },
        @{ Name = "header time past the year 9999: the last-write time"; Expected = "x64|$fromFile"; Header = @{ SystemTime = [long]::MaxValue } },
        @{ Name = "64-bit header cut off before SystemTime: the last-write time"; Expected = "x64|$fromFile"; Header = @{ Length = 0xFAC } },
        @{ Name = "32-bit crash dump: x86, the last-write time (only 64-bit headers are read)"; Expected = "x86|$fromFile"; Header = @{ Signature = "PAGEDUMP"; Machine = 0; SystemTime = $captureFileTime } },
        @{ Name = "raw image: Raw, the last-write time"; Expected = "Raw|$fromFile"; Header = @{ Signature = ""; Machine = 0; SystemTime = $captureFileTime } },
        @{ Name = "file shorter than the header start: Unknown, the last-write time"; Expected = "Unknown|$fromFile"; Header = @{ Length = 0x3F } }
    )
    $headerNumber = 0
    foreach ($case in $headerCases) {
        $headerNumber++
        $headerPath = Join-Path $headerDir "dump$headerNumber.dmp"
        $header = $case.Header
        New-TestDump -Path $headerPath -LastWriteUtc $endUtc @header
        Assert-Equal -Name "dump header: $($case.Name)" -Expected $case.Expected -Actual (Format-DumpInfo (Get-MemoryDumpInfo -Path $headerPath))
    }

    $bracketedDump = Join-Path $workDir "dumps [7]\${nameA}_memory_dump.dmp"
    New-TestDump -Path $bracketedDump -SystemTime $captureFileTime -LastWriteUtc $endUtc
    Assert-Equal -Name "dump header: [ ] in the path are not wildcards" -Expected "x64|$fromHeader" -Actual (Format-DumpInfo (Get-MemoryDumpInfo -Path $bracketedDump))
    $writer = [System.IO.File]::Open($bracketedDump, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try { $openInfo = Get-MemoryDumpInfo -Path $bracketedDump }
    finally { $writer.Dispose() }
    Assert-Equal -Name "dump header: read while another program has the dump open for writing" -Expected "x64|$fromHeader" -Actual (Format-DumpInfo $openInfo)
    Assert-Equal -Name "dump header: a missing file gives Unknown and no time" -Expected "Unknown|||" -Actual (Format-DumpInfo (Get-MemoryDumpInfo -Path (Join-Path $headerDir "missing.dmp")))

    # Parse-Memory logs the dump time (an ARM64 dump: it stops before
    # looking for Volatility 3)
    $armDump = Join-Path $workDir "dumps [7]\${nameC}_memory_dump.dmp"
    New-TestDump -Path $armDump -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $armDump
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory: the dump time from the header is logged" -Expected "True|True" -Actual "$($log.Contains("Found memory dump: $armDump (0 GB, ARM64)"))|$($log.Contains("Dump time: $captureText UTC (crash dump header)"))"

    # --- Rows from Volatility output ------------------------------------------
    # Volatility 3's JSON renderer writes times as ISO 8601 in UTC and absent
    # values as null. 2025-06-07 is a day of 12 or less (day and month swap
    # under de-DE if parsed with the current culture). The end of the
    # acquisition plus a day is 2025-07-01 12:02:14.500. A 0 is a value and
    # must stay in the row: System's PPID, SessionId 0 (services), Threads 0
    # (a process that has exited), PID 0 and port 0 (a closed socket).
    $rowDump = $bracketedDump
    $pslistJson = @'
[
  {"PID": 404, "PPID": 4, "ImageFileName": "smss.exe", "Threads": 2, "SessionId": null, "CreateTime": "2025-06-07T09:01:02+00:00", "ExitTime": null, "__children": []},
  {"PID": 7340, "PPID": 5120, "ImageFileName": "notepad.exe", "Threads": 3, "SessionId": 1, "CreateTime": "2025-06-30T08:15:42.123456+00:00", "ExitTime": null, "__children": []},
  {"PID": 7612, "PPID": 5120, "ImageFileName": "late.exe", "Threads": 1, "SessionId": 1, "CreateTime": "2025-07-01T12:02:14.500000+00:00", "ExitTime": null, "__children": []},
  {"PID": 7700, "PPID": 5120, "ImageFileName": "future.exe", "Threads": 1, "SessionId": 1, "CreateTime": "2025-07-01T12:02:14.501000+00:00", "ExitTime": null, "__children": []},
  {"PID": 7800, "PPID": 5120, "ImageFileName": "old.exe", "Threads": 1, "SessionId": 1, "CreateTime": "1601-01-01T00:00:00+00:00", "ExitTime": null, "__children": []},
  {"PID": 7850, "PPID": 5120, "ImageFileName": "edge.exe", "Threads": 1, "SessionId": 1, "CreateTime": "1980-01-01T00:00:00+00:00", "ExitTime": null, "__children": []},
  {"PID": 7900, "PPID": 5120, "ImageFileName": "garbled.exe", "Threads": 1, "SessionId": 1, "CreateTime": "0x1f2e3d", "ExitTime": null, "__children": []},
  {"PID": 8, "PPID": null, "ImageFileName": null, "Threads": 3, "SessionId": null, "CreateTime": null, "ExitTime": null, "__children": []},
  {"PID": 9, "PPID": 4, "ImageFileName": "na.exe", "Threads": 1, "SessionId": 1, "CreateTime": "N/A", "ExitTime": null, "__children": []},
  {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 150, "SessionId": null, "CreateTime": "2025-06-30T07:00:00+00:00", "ExitTime": null, "__children": []},
  {"PID": 640, "PPID": 512, "ImageFileName": "services.exe", "Threads": 8, "SessionId": 0, "CreateTime": "2025-06-30T07:00:05+00:00", "ExitTime": null, "__children": []},
  {"PID": 7950, "PPID": 5120, "ImageFileName": "exited.exe", "Threads": 0, "SessionId": 1, "CreateTime": "2025-06-30T09:00:00+00:00", "ExitTime": "2025-06-30T09:05:00+00:00", "__children": []},
  {"PID": 0, "PPID": 0, "ImageFileName": "Idle", "Threads": 0, "SessionId": "N/A", "CreateTime": null, "ExitTime": null, "__children": []}
]
'@
    $pslistRows = @(
        "2025-06-07 09:01:02.000|ProcessCreation|Process in memory: smss.exe (PID: 404, PPID: 4)||Threads=2 SessionId=",
        "2025-06-30 08:15:42.123|ProcessCreation|Process in memory: notepad.exe (PID: 7340, PPID: 5120)||Threads=3 SessionId=1",
        "2025-07-01 12:02:14.500|ProcessCreation|Process in memory: late.exe (PID: 7612, PPID: 5120)||Threads=1 SessionId=1",
        "$captureText|Snapshot|Process in memory: future.exe (PID: 7700, PPID: 5120)||Threads=1 SessionId=1 CreateTime=2025-07-01 12:02:14.501",
        "$captureText|Snapshot|Process in memory: old.exe (PID: 7800, PPID: 5120)||Threads=1 SessionId=1 CreateTime=1601-01-01 00:00:00.000",
        "1980-01-01 00:00:00.000|ProcessCreation|Process in memory: edge.exe (PID: 7850, PPID: 5120)||Threads=1 SessionId=1",
        "$captureText|Snapshot|Process in memory: garbled.exe (PID: 7900, PPID: 5120)||Threads=1 SessionId=1 CreateTime=0x1f2e3d",
        "$captureText|Snapshot|Process in memory: Unknown (PID: 8, PPID: )||Threads=3 SessionId=",
        "$captureText|Snapshot|Process in memory: na.exe (PID: 9, PPID: 4)||Threads=1 SessionId=1",
        "2025-06-30 07:00:00.000|ProcessCreation|Process in memory: System (PID: 4, PPID: 0)||Threads=150 SessionId=",
        "2025-06-30 07:00:05.000|ProcessCreation|Process in memory: services.exe (PID: 640, PPID: 512)||Threads=8 SessionId=0",
        "2025-06-30 09:00:00.000|ProcessCreation|Process in memory: exited.exe (PID: 7950, PPID: 5120)||Threads=0 SessionId=1",
        "$captureText|Snapshot|Process in memory: Idle (PID: 0, PPID: 0)||Threads=0 SessionId="
    )
    $netscanJson = @'
[
  {"Offset": 1, "Proto": "TCPv4", "LocalAddr": "192.0.2.10", "LocalPort": 49731, "ForeignAddr": "198.51.100.20", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 7340, "Owner": "notepad.exe", "Created": "2025-06-30T11:59:01.250000+00:00", "__children": []},
  {"Offset": 2, "Proto": "UDPv4", "LocalAddr": "192.0.2.10", "LocalPort": 5353, "ForeignAddr": "*", "ForeignPort": "*", "State": "", "PID": 2044, "Owner": "svchost.exe", "Created": null, "__children": []},
  {"Offset": 3, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 8080, "ForeignAddr": "::", "ForeignPort": 0, "State": "LISTENING", "PID": 1234, "Owner": "web.exe", "Created": "1601-01-01T00:00:00+00:00", "__children": []},
  {"Offset": 4, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 0, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "CLOSED", "PID": 0, "Owner": null, "Created": null, "__children": []}
]
'@
    $netscanRows = @(
        "2025-06-30 11:59:01.250|NetworkConnection|Memory network: TCPv4 192.0.2.10:49731 -> 198.51.100.20:443 (ESTABLISHED)|notepad.exe|PID=7340",
        "$captureText|Snapshot|Memory network: UDPv4 192.0.2.10:5353 -> *:* ()|svchost.exe|PID=2044",
        "$captureText|Snapshot|Memory network: TCPv6 ::1:8080 -> :::0 (LISTENING)|web.exe|PID=1234 Created=1601-01-01 00:00:00.000",
        "$captureText|Snapshot|Memory network: TCPv4 0.0.0.0:0 -> 0.0.0.0:0 (CLOSED)||PID=0"
    )
    $cmdlineJson = @'
[
  {"PID": 7340, "Process": "notepad.exe", "Args": "\"C:\\Windows\\system32\\notepad.exe\" C:\\Users\\Public\\notes.txt", "__children": []},
  {"PID": 4, "Process": "System", "Args": "N/A", "__children": []},
  {"PID": 88, "Process": "Registry", "Args": null, "__children": []},
  {"PID": 404, "Process": "smss.exe", "Args": "\\SystemRoot\\System32\\smss.exe", "__children": []},
  {"PID": 0, "Process": "zero.exe", "Args": "C:\\Tools\\zero.exe /pid 0", "__children": []}
]
'@
    $cmdlineRows = @(
        "$captureText|Snapshot|Process command line: notepad.exe (PID: 7340)||Args=`"C:\Windows\system32\notepad.exe`" C:\Users\Public\notes.txt",
        "$captureText|Snapshot|Process command line: smss.exe (PID: 404)||Args=\SystemRoot\System32\smss.exe",
        "$captureText|Snapshot|Process command line: zero.exe (PID: 0)||Args=C:\Tools\zero.exe /pid 0"
    )
    $svcscanJson = @'
[
  {"Offset": 1, "Order": 12, "PID": 2044, "Start": "SERVICE_AUTO_START", "State": "SERVICE_RUNNING", "Type": "SERVICE_WIN32_SHARE_PROCESS", "Name": "Dnscache", "Display": "DNS Client", "Binary": "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", "__children": []},
  {"Offset": 2, "Order": 13, "PID": null, "Start": "SERVICE_DEMAND_START", "State": "SERVICE_STOPPED", "Type": "SERVICE_KERNEL_DRIVER", "Name": "TestDrv", "Display": null, "Binary": null, "__children": []},
  {"Offset": 3, "Order": 14, "PID": 0, "Start": "SERVICE_AUTO_START", "State": "SERVICE_RUNNING", "Type": "SERVICE_WIN32_OWN_PROCESS", "Name": "ZeroSvc", "Display": "Zero PID Service", "Binary": "C:\\Tools\\zerosvc.exe", "__children": []}
]
'@
    $svcscanRows = @(
        "$captureText|Snapshot|Service in memory: DNS Client (Dnscache)||State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary=C:\Windows\system32\svchost.exe -k NetworkService -p PID=2044",
        "$captureText|Snapshot|Service in memory: TestDrv (TestDrv)||State=SERVICE_STOPPED StartType=SERVICE_DEMAND_START Binary= PID=",
        "$captureText|Snapshot|Service in memory: Zero PID Service (ZeroSvc)||State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary=C:\Tools\zerosvc.exe PID=0"
    )
    $pluginCases = @(
        @{ Plugin = "windows.pslist"; Source = "Memory-Processes"; Json = $pslistJson; Counts = "13|7|6"; Rows = $pslistRows },
        @{ Plugin = "windows.netscan"; Source = "Memory-Network"; Json = $netscanJson; Counts = "4|1|3"; Rows = $netscanRows },
        @{ Plugin = "windows.cmdline"; Source = "Memory-CommandLine"; Json = $cmdlineJson; Counts = "3|0|3"; Rows = $cmdlineRows },
        @{ Plugin = "windows.svcscan"; Source = "Memory-Services"; Json = $svcscanJson; Counts = "3|0|3"; Rows = $svcscanRows }
    )
    foreach ($case in $pluginCases) {
        $result = Invoke-MemoryPluginRows -Plugin $case.Plugin -Source $case.Source -Json $case.Json
        Assert-Equal -Name "$($case.Plugin): rows (time, EventType, Description, User, Details)" -Expected ($case.Rows -join "`n") -Actual ($result.Rows -join "`n")
        Assert-Equal -Name "$($case.Plugin): counts (entries|timed|snapshot)" -Expected $case.Counts -Actual $result.Counts
        Assert-Equal -Name "$($case.Plugin): Source $($case.Source), Artifact MemoryDump and the dump as RawPath on every row" -Expected 0 -Actual $result.Other
    }
    $result = Invoke-MemoryPluginRows -Plugin "windows.info" -Source "Memory-Info" -Json '[{"Variable": "Kernel Base", "Value": "0xf80000000000"}]'
    Assert-Equal -Name "another plugin: no rows" -Expected "0|0|0|0" -Actual "$($result.Counts)|$($result.Rows.Count)"
    # The numbers of an entry: 0 (as ConvertFrom-Json gives it in either
    # PowerShell version, or as text) is kept; null, empty and N/A are absent
    $fieldTexts = foreach ($fieldValue in @(0, [long]0, "0", 4, " 7 ", "*", $null, "", " ", "N/A", "n/a")) { Get-MemoryFieldText $fieldValue }
    Assert-Equal -Name "numbers of an entry: 0 kept, null, empty and N/A give an empty field" -Expected "0|0|0|4|7|*|||||" -Actual ($fieldTexts -join "|")

    # The same under the de-DE culture (day.month.year, comma decimal
    # separator); set inside one script block, which Windows PowerShell
    # needs for the culture to stay set
    $germanRun = & {
        $savedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo("de-DE")
            $culture = [System.Globalization.CultureInfo]::CurrentCulture.Name
            $rows = @()
            foreach ($case in $pluginCases) {
                $result = Invoke-MemoryPluginRows -Plugin $case.Plugin -Source $case.Source -Json $case.Json
                $rows += $result.Rows
                $rows += $result.Counts
            }
            [PSCustomObject]@{ Culture = $culture; Rows = $rows }
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $savedCulture }
    }
    $expectedRows = @()
    foreach ($case in $pluginCases) { $expectedRows += $case.Rows; $expectedRows += $case.Counts }
    Assert-Equal -Name "de-DE culture: the same rows and counts" -Expected ("de-DE`n" + ($expectedRows -join "`n")) -Actual ("$($germanRun.Culture)`n" + ($germanRun.Rows -join "`n"))

    # --- Volatility output in the work folder's scratch folder ----------------
    # A stub stands in for vol.exe: JSON with two of its arguments on stdout,
    # a line on stderr. -WorkDir may have [ ] in it; a 2> redirection cannot
    # write there, so the output must not go through one.
    $stubDir = Join-Path $workDir "vol"
    [void][System.IO.Directory]::CreateDirectory($stubDir)
    $volStub = Join-Path $stubDir "vol-stub.cmd"
    [System.IO.File]::WriteAllText($volStub, "@echo off`r`necho Volatility 3 Framework (test stub) 1>&2`r`necho [{`"Format`": `"%4`", `"Plugin`": `"%5`"}]`r`n")
    $emptyStub = Join-Path $stubDir "vol-empty.cmd"
    [System.IO.File]::WriteAllText($emptyStub, "@echo off`r`necho Unsatisfied requirement plugins.Test.kernel 1>&2`r`nexit /b 1`r`n")
    $script:runScratchDir = Join-Path $workDir "work [1]\w1234_120000\scratch"
    [void][System.IO.Directory]::CreateDirectory($script:runScratchDir)
    try {
        $volResult = Invoke-VolatilityPlugin -VolExe $volStub -DumpPath $rowDump -Plugin "windows.cmdline"
        $volJson = $volResult.Json | ConvertFrom-Json
        $left = @(Get-ChildItem -LiteralPath $script:runScratchDir -Force).Count
        Assert-Equal -Name "Volatility output: JSON read back from a scratch folder with [ ] in its path, stderr kept apart, the file deleted" -Expected "json|windows.cmdline|Volatility 3 Framework (test stub)|0" -Actual "$($volJson.Format)|$($volJson.Plugin)|$($volResult.Errors.Trim())|$left"
        $volResult = Invoke-VolatilityPlugin -VolExe $emptyStub -DumpPath $rowDump -Plugin "windows.netscan"
        $left = @(Get-ChildItem -LiteralPath $script:runScratchDir -Force).Count
        Assert-Equal -Name "Volatility output: none, stderr returned for the warning" -Expected "|Unsatisfied requirement plugins.Test.kernel|0" -Actual "$($volResult.Json.Trim())|$($volResult.Errors.Trim())|$left"
    }
    finally { $script:runScratchDir = $null }

    # --- Parse-Memory: from Volatility output to rows -------------------------
    # A whole Parse-Memory run on an x64 dump whose header time (the capture
    # time) is two minutes before its last write (the end of the
    # acquisition): Snapshot rows must be at the header time, and late.exe
    # (created at the end plus a day) must still be an event. A stub found
    # in place of vol.exe prints the canned JSON of each plugin; netscan has
    # none, which must give the warning and no rows.
    Write-Host "Testing Parse-Memory with a stub for Volatility 3 ..."
    $parseStub = Join-Path $stubDir "vol-canned.cmd"
    [System.IO.File]::WriteAllText($parseStub, "@echo off`r`nif not exist `"%~dp0%5.json`" (`r`n  echo No output for %5 1>&2`r`n  exit /b 1`r`n)`r`ntype `"%~dp0%5.json`"`r`n")
    $parseCases = @($pluginCases | Where-Object { $_.Plugin -ne "windows.netscan" })
    foreach ($case in $parseCases) { [System.IO.File]::WriteAllText((Join-Path $stubDir "$($case.Plugin).json"), $case.Json) }
    New-TestDump -Path $rowDump -SystemTime $captureFileTime -LastWriteUtc $endUtc
    $realFindVolatility = ${function:Find-VolatilityExe}
    ${function:Find-VolatilityExe} = { return $parseStub }
    $script:runScratchDir = Join-Path $workDir "work [1]\w1234_120001\scratch"
    [void][System.IO.Directory]::CreateDirectory($script:runScratchDir)
    try {
        Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $rowDump
        $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
        $script:artifactStats = @{}
        Parse-Memory | Out-Null
        $log = Get-TestLog
        $left = @(Get-ChildItem -LiteralPath $script:runScratchDir -Force).Count
    }
    finally {
        ${function:Find-VolatilityExe} = $realFindVolatility
        $script:runScratchDir = $null
    }
    $expectedRows = @()
    foreach ($case in $parseCases) { $expectedRows += @($case.Rows | ForEach-Object { "$($case.Source)|$_" }) }
    $parsedRows = @($script:timelineEntries | ForEach-Object { "$($_.Source)|$($_.Timestamp)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)" })
    Assert-Equal -Name "Parse-Memory: rows at the header's capture time, events at their own time (Source, time, EventType, Description, User, Details)" -Expected ($expectedRows -join "`n") -Actual ($parsedRows -join "`n")
    $expectedLog = @(
        "Dump time: $captureText UTC (crash dump header)",
        "Using Volatility 3: $parseStub",
        "windows.pslist: 13 entries (7 timed, 6 snapshot) in ",
        "WARNING:     windows.netscan produced no output. Error: No output for windows.netscan",
        "windows.cmdline: 3 entries (0 timed, 3 snapshot) in ",
        "windows.svcscan: 3 entries (0 timed, 3 snapshot) in ",
        "Memory analysis complete: 19 entries from 0 GB dump"
    )
    $missingLog = @($expectedLog | Where-Object { -not $log.Contains($_) })
    Assert-Equal -Name "Parse-Memory: the dump time, the counts per plugin and the netscan warning are logged, the scratch folder is left empty" -Expected "|0" -Actual "$($missingLog -join ' / ')|$left"
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    if ($pushed) { Pop-Location }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
