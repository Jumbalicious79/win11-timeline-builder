# =============================================================
# Memory parser test
# Checks where the Memory parser finds a collection's memory dump
# (Find-MemoryDump) on synthetic folders: -MemoryDumpPath first (also a
# relative path and one with [ ] in it; a path that is not a file is
# reported once, then the other places are tried), then where the
# collector saved it by collection_manifest.csv (its "(memory dump via
# <tool>)" row: a dump on another drive, also from a zip extracted with
# Expand-CollectionZip and before the dump next to the zip, a renamed
# collection folder, Memory\ with -NoCompress; logged once with the
# manifest's SHA-256; a dump on a drive with another letter now, found at
# the same path under another drive's root (folders stand in for the
# drives), passing over a copy of another size; a dump that is gone is
# logged once and the other places are tried; one of another size gets
# one warning and is used by no check; a name the collector does not
# write, a \\?\ or network path, and a RelativePath outside Memory\ are
# refused with one warning over two lookups, but a dump next to the zip on
# a network share (\\localhost\<drive>$, when reachable) is used; | in the
# manifest's paths does not stop the lookup in Windows PowerShell 5.1; a
# zipped collection and the first collector's manifest find the dump next
# to the zip, its size checked and the manifest's SHA-256 logged once, a
# manifest without a dump row as before, logging nothing; a copy of
# another size next to the zip, also of a zip moved with its dump to
# another folder, or in Memory\, gets one warning and is not used), the
# dump next to the collection zip (.dmp or .raw), Memory\ inside the collection
# (never the Secrets\ folder of -IncludeSecrets or the email attachment
# copies), and the dump next to the collection folder or next to
# -InputPath (an outer folder of another name, also given as a relative
# path), which must be named after the collection folder: another
# collection's dump in the same folder (e.g. the collector's reports\) is
# never used. The collection folder is the folder of
# collection_manifest.csv (also below -InputPath and in the <name>\<name>\
# layout of Windows "Extract All"), else -InputPath. How the offer shows
# the dump (its path in the collection, else its full path). Parse-Memory
# with the manifest's dump. Without a dump, the offer step (all a user of
# Run-TimelineBuilder.bat sees) and Parse-Memory say what the manifest
# lists and how to have the dump analyzed: copy it next to the zip or the
# collection folder under its name, or connect the drive it was saved to;
# only Parse-Memory (-Sources ...,Memory) also names -MemoryDumpPath. The
# offer step also logs the "Memory dump not analyzed" line the findings
# report reads, also for a collection from a Windows ARM64 computer (the
# same copy advice: its dump is analyzed too); the dump of a renamed
# collection folder is named after the folder's original name.
# The size in that line (bytes, or GB with two decimals). The offer itself
# (the builder's block for a run without Memory in -Sources, as from the
# .bat) on a zip with its dump next to it: an ARM64 dump is offered with
# Microsoft's debugger engine (also without vol.exe; the engine in
# tools\dbgeng named), not offered without the engine, no vol.exe for an
# x64 dump, answer 2, the end of redirected input (as 2), an invalid answer
# then 1 (asked again); each dump not analyzed gets the "Memory dump not
# analyzed" line, read back by the findings report's log reader
# (TimelineReport.Engine.ps1), with the size the prompt shows. Parse-Memory
# gives that line too (no vol.exe; an ARM64 dump the engine could not
# read), and for an ARM64 dump that was read the "analyzed with the Windows
# debugger engine" line (what was read and what not; also processes only)
# with its "Memory dump coverage" lines, the WinDbg command, and no
# Volatility 3.
# The debugger engine path for Windows ARM64 dumps, with the helper's
# functions (lib\memory\TimelineDbgEng.ps1) loaded from its syntax tree: the
# architecture folder, Find-DbgEngine (System32; copies of System32's DLLs
# in tools\dbgeng\<arch>\ accepted, an unsigned DLL in a subfolder or a
# missing DLL refused with a warning, no engine), the C# host on the
# runner's own engine (it compiles, loads by full path, runs a command,
# throws for a fake and a missing dump and lets the file go, refuses a
# second engine folder), the dx text parser (echo, quotes, engine errors,
# a query that fails as a whole, the engine's warnings), paging (100-item
# pages, the item cap), the queries (paged, -1 without a session, no "!"
# command, no attacker-tool name of report-rules.json in the helper), the
# kernel's symbol file ID from a fake kernel image (and every refusal), the
# symbol cache and download (a stub: nothing is downloaded), reading names
# and command lines from a fake memory map, and a whole analysis on a fake
# kernel (EPROCESS blocks at the offsets of canned "dt -v" output, the
# process list, the process ID table, tokens and session spaces) through
# the builder's protocol reader and Add-MemoryPluginRows (rows, counts, log
# lines, de-DE, cache reuse, offline, a damaged cached file; FoundBy= on
# every process row): the list copied while Windows ran (a process that
# ended during the copy, a link into reused memory, a loop, a process only
# in the process ID table created after the capture started; the "Memory
# dump process list" warning and the report's reading of it), what copying
# does not explain (a process unlinked from the list: Anomaly=
# NotInProcessList, named first in the warning; not marked without a
# capture start or when both walks stopped early; process IDs changed to 0,
# to one not a multiple of 4 and to another process's: Anomaly=
# ProcessIdChanged and TableId=), capture churn (processes created during
# the copy, 0.78 s and 90 s before it, only in the table under another
# ID: TableId=, not marked, counted in the warning; one created 125 s
# before it is marked), no capture start (nothing marked, the warning says
# it cannot be judged), create times churn cannot have (none, or after the
# capture ended: marked ProcessIdChanged in the list and NotInProcessList
# unlinked), IDs a stale table entry cannot give (not a multiple of 4, 0
# without a table entry: marked even when created during the copy), no
# capture end (a process created after the start not judged), the
# create-time and verdict tables, the process ID table changed during the
# copy (a stale entry) and an object that only starts like a process, the
# scan finding nothing (one warning, the engine's own list's), session ids
# per process (_MM_SESSION_SPACE or the token), the layout's refusals, and
# the debugger engine's own list (canned dx output) when the symbols do not
# describe the process structure (a failing process query, its "corrupted
# linked list" warning, session ids decided per process).
# Real helper processes: the real
# helper on a fake dump, canned entries with every kind of character (an
# area's E and AREA lines and END with three counts too), a crash, an
# error, a hang (ended), output without its end, no helper.
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
# The rows of the debugger engine helper's entries (lib\memory\TimelineMemoryRows.ps1,
# which the builder dot-sources at script level)
$rowsAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $builder -Parent) "lib\memory\TimelineMemoryRows.ps1"), [ref]$null, [ref]$null)
$rowsAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
# The fixed and removable drives where Find-MemoryDump looks for a dump
# whose drive has another letter now: folders of the test stand in for
# them ($script:testDriveRoots, none unless a case sets them), so the
# machine's own drives are never searched
$realDriveRoots = ${function:Get-MemoryDumpDriveRoots}
$script:testDriveRoots = @()
${function:Get-MemoryDumpDriveRoots} = { return $script:testDriveRoots }
# The XML-invalid character filter used by Add-TimelineEntry
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        @('$script:xmlInvalidPattern', '$script:xmlInvalidRegex') -contains $node.Left.Extent.Text }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
# The builder's tools\ folder (its $PSScriptRoot, which a function made
# from text has not): a folder of the test ($script:testToolsFolder)
$script:testToolsFolder = Join-Path ([System.IO.Path]::GetTempPath()) "memory-parser-test-tools"
${function:Get-BuilderToolsFolder} = { return $script:testToolsFolder }
$script:dbgEngTimeoutSeconds = 900
# The findings report's own log reader (TimelineReport.Engine.ps1): the
# lines the Memory parser writes for the report must read back
$engineAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $builder -Parent) "lib\report\TimelineReport.Engine.ps1"), [ref]$null, [ref]$null)
$engineAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        @('Read-ReportEngineLogText', 'Read-ReportEngineBuilderLog') -contains $node.Name }, $false) |
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

# A collection folder whose collection_manifest.csv has the rows the
# collector writes for a memory capture, every field quoted: the
# collection's metadata and the acquisition log (DestPath = -CollectedAt,
# the collection folder on the collecting machine, + RelativePath) and,
# unless -NoDumpRow, the dump: "(memory dump via -Tool)" with -DumpDest,
# -DumpSize and -DumpRel (RelativePath; empty for a dump outside the
# collection). -OldColumns: the first collector's columns (no
# RelativePath, no source times).
function New-TestManifestCollection {
    param([string]$Path, [string]$CollectedAt, [string]$DumpDest = "", [string]$DumpSize = "16", [string]$DumpRel = "",
        [string]$Tool = "DumpIt", [switch]$NoDumpRow, [switch]$OldColumns)
    $rows = @(
        @("(collection metadata)", "$CollectedAt\collection_info.json", "120", "collection_info.json"),
        @("(memory capture tool output: $Tool)", "$CollectedAt\Memory\memory_acquisition_log.txt", "730", "Memory\memory_acquisition_log.txt")
    )
    if (-not $NoDumpRow) { $rows += , @("(memory dump via $Tool)", $DumpDest, $DumpSize, $DumpRel) }
    $header = "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc"
    if ($OldColumns) { $header = "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt" }
    $lines = @($header)
    foreach ($row in $rows) {
        $fields = @($testHash, $row[0], $row[1], $row[2], "2025-06-30 12:05:00")
        if (-not $OldColumns) { $fields += @($row[3], "", "", "") }
        $lines += (($fields | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ",")
    }
    [void][System.IO.Directory]::CreateDirectory($Path)
    [System.IO.File]::WriteAllText((Join-Path $Path "collection_manifest.csv"), (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
}

# A collection zip as the collector writes it ("<folder>/" before every
# entry name) of the files in -Folder
function New-TestCollectionZip {
    param([string]$Folder, [string]$ZipPath)
    $folderName = Split-Path $Folder -Leaf
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $Folder -Recurse -File)) {
            $entryName = $folderName + "/" + $file.FullName.Substring($Folder.Length + 1).Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName)
        }
    }
    finally { $zip.Dispose() }
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
    $script:memoryDumpNotices = $null
    $script:memoryDumpFromManifest = $false
    $script:memoryDumpListedPath = ""
    $script:collectionFolderOriginalName = $null
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

# The log file's text, read with the encoding the builder's Log functions
# (Add-Content) wrote it in: the ANSI code page in Windows PowerShell, UTF-8
# in PowerShell 7 (paths with non-ASCII characters)
function Get-TestLog {
    if (-not (Test-Path -LiteralPath $script:logFile)) { return "" }
    $text = Get-Content -LiteralPath $script:logFile -Raw
    if ($null -eq $text) { return "" }
    return $text
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

# The answer the memory prompt gets (Read-Host is an alias for this in
# Invoke-TestMemoryOffer): the next of $script:offerAnswers, then $null, as
# Read-Host gives at the end of redirected input (the prompt text is ignored)
function Get-TestOfferAnswer {
    $script:offerPrompts++
    if ($script:offerAnswers.Count -gt 0) { return $script:offerAnswers.Dequeue() }
    return $null
}

# The builder's memory dump offer ($offerFile, its top-level block for a run
# without Memory in -Sources) for one collection, run with -Sources USB in
# this function's scope: Volatility 3 found unless -NoVol, the prompt
# answered with -Answers. Returns the console text (Write-Host and the log
# lines), the log file's text, -Sources afterwards and the prompts shown.
function Invoke-TestMemoryOffer {
    param([string]$Collection, [string]$Zip, [switch]$NoVol, [switch]$NoEngine, [string]$EngineSource = "Windows", [string[]]$Answers = @())
    Set-TestRunState -Collection $Collection -Zip $Zip
    $script:offerAnswers = New-Object System.Collections.Queue
    foreach ($answer in $Answers) { $script:offerAnswers.Enqueue($answer) }
    $script:offerPrompts = 0
    $script:offerNoVol = [bool]$NoVol
    $script:offerNoEngine = [bool]$NoEngine
    $script:offerEngineSource = $EngineSource
    $script:offerVolCalls = 0
    Set-Alias -Name Read-Host -Value Get-TestOfferAnswer
    function Find-VolatilityExe { $script:offerVolCalls++; if ($script:offerNoVol) { return $null }; return "C:\stub\tools\volatility3\vol.exe" }
    # Microsoft's debugger engine for an ARM64 dump: the one of Windows, one
    # in tools\dbgeng\<arch>\ (-EngineSource), or none (-NoEngine)
    function Find-DbgEngine {
        if ($script:offerNoEngine) { return [PSCustomObject]@{ Path = ""; Folder = ""; Source = ""; Version = ""; Dlls = @(); Warning = ""; Reason = "the Windows debugger engine (dbgeng.dll) is not in C:\stub\System32" } }
        $folder = "C:\stub\System32"
        if ($script:offerEngineSource -ne "Windows") { $folder = "C:\stub\$($script:offerEngineSource)" }
        return [PSCustomObject]@{ Path = "$folder\dbgeng.dll"; Folder = $folder; Source = $script:offerEngineSource; Version = "10.0.26100.1"; Dlls = @("dbgeng.dll"); Warning = ""; Reason = "" }
    }
    $Sources = @("USB")
    $console = @(. $offerFile 6>&1 | ForEach-Object { "$_" })
    return [PSCustomObject]@{ Console = ($console -join "`n"); Log = (Get-TestLog); Sources = ($Sources -join ","); Prompts = $script:offerPrompts; VolCalls = $script:offerVolCalls }
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
# Collections whose collection_manifest.csv lists the dump (the collector's
# "(memory dump via <tool>)" row)
$nameK = "TriageCollection_2025-06-19_09-55"   # dump on another drive, as picked at the collector's prompt
$nameM = "TriageCollection_2025-06-18_10-20"   # the same as a zip (WinPmem .raw), a dump next to the zip too
$nameL = "TriageCollection_2025-06-17_11-45"   # the listed dump is gone, one next to the folder
$nameS = "TriageCollection_2025-06-16_12-05"   # the listed dump has another size
$nameT = "TriageCollection_2025-06-15_13-25"   # ... and is next to the zip (-MemoryOutputPath = the zip's folder)
$nameU = "TriageCollection_2025-06-14_14-50"   # -NoCompress: in Memory\, another size
$nameV = "TriageCollection_2025-06-13_15-10"   # -NoCompress: in Memory\, the listed size
$nameN = "TriageCollection_2025-06-12_16-30"   # collection folder renamed after the collection
$nameW = "TriageCollection_2025-06-11_17-15"   # rows naming a file the collector does not write
$nameO = "TriageCollection_2025-06-10_18-40"   # zipped: the dump row in the collection, the dump next to the zip
$nameX = "TriageCollection_2025-06-09_19-05"   # the listed dump is gone, nothing else
$nameY = "TriageCollection_2025-06-08_20-30"   # zipped, extracted, the dump not copied along
$nameP = "TriageCollection_2025-06-07_21-55"   # no collection_manifest.csv, no dump
$nameQ = "TriageCollection_2025-06-06_08-10"   # a zip and its dump in another folder: the size checked there
$nameZ = "TriageCollection_2025-06-05_09-20"   # the dump's drive has another letter now
$nameShare = "TriageCollection_2025-06-04_10-30"   # a collection on a network share
$namePipe = "TriageCollection_2025-06-03_11-40"   # | in the manifest's paths
$testHash = "0123456789ABCDEF" * 4             # synthetic SHA-256
$missingWarning = "-MemoryDumpPath is not an existing file:"

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("memory-parser-test-" + [guid]::NewGuid().ToString("N"))
$script:testToolsFolder = Join-Path $workDir "builder tools $([char]0x00E9)\tools"
$pushed = $false
try {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
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
    Assert-Equal -Name "-MemoryDumpPath missing: warning, then the dump next to the zip" -Expected "$dumpA|True" -Actual "$($run.Path)|$($run.Log.Contains("WARNING: $missingWarning $missing -- looking for the memory dump where the collector saved it and in and next to the collection instead."))"
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

    # --- Where the collector saved it (collection_manifest.csv) ---------------
    # The collector records a complete dump as "(memory dump via <tool>)":
    # outside the collection by DestPath (its -MemoryOutputPath, or
    # <drive>\TriageMemory\ picked at its memory prompt when the system
    # drive is low on space), in the collection by RelativePath. $memDrive
    # stands in for D:\TriageMemory, $origReports for the collector's
    # reports\ on the collecting machine. Every test dump is 16 bytes.
    $memDrive = Join-Path $workDir "TriageMemory"
    $origReports = "C:\Triage\reports"
    $foundNotice = "Memory dump where the collector saved it (collection_manifest.csv):"
    $goneNotice = "The collector saved the memory dump to"
    $siblingNotice = "Memory dump:"
    $sizeWarning = "WARNING: Memory dump not used:"
    $refusedWarning = "WARNING: Memory dump in collection_manifest.csv not used:"

    # Found on the other drive: its size and the manifest's SHA-256 logged once
    $driveK = Join-Path $memDrive "${nameK}_memory_dump.dmp"
    New-TestFile $driveK
    New-TestManifestCollection -Path (Join-Path $reports $nameK) -CollectedAt "$origReports\$nameK" -DumpDest $driveK
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameK)
    $foundLine = "$foundNotice $driveK (16 bytes, as listed). SHA-256 in the manifest: $testHash -- the dump is not hashed again here (it is as large as RAM); Get-FileHash -Algorithm SHA256 checks it."
    Assert-Equal -Name "manifest: the dump where the collector saved it (another drive), its size and SHA-256 logged" -Expected "$driveK|True|True" -Actual "$($run.Path)|$($run.Log.Contains($foundLine))|$($script:memoryDumpFromManifest)"
    $again = Find-MemoryDump
    $notices = ([regex]::Matches((Get-TestLog), [regex]::Escape($foundNotice))).Count
    Assert-Equal -Name "manifest: logged once when the dump is looked for twice" -Expected "$driveK|1" -Actual "$again|$notices"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameK) -DumpPath $elsewhereA
    Assert-Equal -Name "manifest: -MemoryDumpPath is still used first, nothing logged" -Expected "$elsewhereA||False" -Actual "$($run.Path)|$($run.Log)|$($script:memoryDumpFromManifest)"

    # A collection zip, extracted into a work folder as the builder does
    # (Expand-CollectionZip): the manifest's dump (WinPmem, .raw) is used
    # before the one next to the zip
    $driveM = Join-Path $memDrive "${nameM}_memory_dump.raw"
    $siblingM = Join-Path $reports "${nameM}_memory_dump.raw"
    foreach ($file in @($driveM, $siblingM)) { New-TestFile $file }
    $sourceM = Join-Path $workDir "zip-source\$nameM"
    New-TestManifestCollection -Path $sourceM -CollectedAt "$origReports\$nameM" -DumpDest $driveM -Tool "WinPmem"
    New-TestFile (Join-Path $sourceM "USB\setupapi.dev.log")
    $zipM = Join-Path $reports "$nameM.zip"
    New-TestCollectionZip -Folder $sourceM -ZipPath $zipM
    $script:inputFiles = New-Object System.Collections.Generic.List[string]
    $script:shortenedNames = @{}
    $script:logFile = $null
    $extractM = Join-Path $workDir "w1234_120000\in"
    Expand-CollectionZip -ZipPath $zipM -Destination $extractM | Out-Null
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extractM $nameM) -Zip $zipM
    Assert-Equal -Name "manifest from a zip extracted into the work folder: its dump on another drive, not the one next to the zip" -Expected "$driveM|True" -Actual "$($run.Path)|$($run.Log.Contains("$foundNotice $driveM (16 bytes, as listed)."))"

    # Gone (moved, deleted, or another machine): logged once, then the
    # other places, here the dump next to the collection folder
    $goneL = Join-Path $memDrive "${nameL}_memory_dump.dmp"
    $nextToL = Join-Path $reports "${nameL}_memory_dump.dmp"
    New-TestFile $nextToL
    New-TestManifestCollection -Path (Join-Path $reports $nameL) -CollectedAt "$origReports\$nameL" -DumpDest $goneL
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameL)
    $again = Find-MemoryDump
    $log = Get-TestLog
    $notices = ([regex]::Matches($log, [regex]::Escape($goneNotice))).Count
    $goneLine = "$goneNotice $goneL (collection_manifest.csv); it is not there now, nor at that path on another drive (moved, deleted, its drive not connected, or this is another machine). Looking in and next to the collection instead."
    Assert-Equal -Name "manifest: the listed dump is gone: logged once (no warning), then the dump next to the collection folder, of the listed size" -Expected "$nextToL|$nextToL|1|True|False|True" -Actual "$($run.Path)|$again|$notices|$($log.Contains($goneLine))|$($log.Contains('WARNING'))|$($log.Contains("$siblingNotice $nextToL (16 bytes, as collection_manifest.csv lists for this collection's dump)."))"
    if ($freeDrive) {
        $noDriveL = "${freeDrive}:\TriageMemory\${nameL}_memory_dump.dmp"
        New-TestManifestCollection -Path (Join-Path $reports $nameL) -CollectedAt "$origReports\$nameL" -DumpDest $noDriveL
        $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameL)
        Assert-Equal -Name "manifest: the listed dump on a drive that does not exist here: logged, then the dump next to the collection folder" -Expected "$nextToL|True" -Actual "$($run.Path)|$($run.Log.Contains("$goneNotice $noDriveL "))"
    }

    # Another size: not the dump the collector saved (a copy cut short).
    # One warning; the file is not used, also not by the checks after the
    # manifest's: next to the zip (-MemoryOutputPath set to the zip's
    # folder) or in Memory\ (-NoCompress)
    $driveS = Join-Path $memDrive "${nameS}_memory_dump.dmp"
    New-TestFile $driveS
    New-TestManifestCollection -Path (Join-Path $reports $nameS) -CollectedAt "$origReports\$nameS" -DumpDest $driveS -DumpSize "34359738368"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameS)
    $again = Find-MemoryDump
    $log = Get-TestLog
    $warnings = ([regex]::Matches($log, [regex]::Escape($sizeWarning))).Count
    $sizeLine = "$sizeWarning $driveS is 16 bytes, but collection_manifest.csv lists 34359738368 bytes for the dump the collector saved there (a copy cut short?)."
    Assert-Equal -Name "manifest: the listed dump has another size: one warning, not used" -Expected "||1|True" -Actual "$($run.Path)|$again|$warnings|$($log.Contains($sizeLine))"
    $siblingT = Join-Path $reports "${nameT}_memory_dump.dmp"
    $zipT = Join-Path $reports "$nameT.zip"
    foreach ($file in @($siblingT, $zipT)) { New-TestFile $file }
    New-TestManifestCollection -Path (Join-Path $extracted $nameT) -CollectedAt "$origReports\$nameT" -DumpDest $siblingT -DumpSize "4096"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameT) -Zip $zipT
    Assert-Equal -Name "manifest: a listed dump of another size next to the zip is not taken by the next-to-the-zip check" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$sizeWarning $siblingT is 16 bytes, but collection_manifest.csv lists 4096 bytes"))"
    New-TestManifestCollection -Path (Join-Path $reports $nameT) -CollectedAt "$origReports\$nameT" -DumpDest $siblingT -DumpSize "4096"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameT)
    Assert-Equal -Name "manifest: ... nor, for the collection folder next to it, by the next-to-the-folder check" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$sizeWarning $siblingT is 16 bytes"))"
    $inU = Join-Path $reports "$nameU\Memory\memory_dump.raw"
    New-TestFile $inU
    New-TestManifestCollection -Path (Join-Path $reports $nameU) -CollectedAt "$origReports\$nameU" -DumpDest "$origReports\$nameU\Memory\memory_dump.raw" -DumpRel "Memory\memory_dump.raw" -DumpSize "20" -Tool "MagnetRAM"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameU)
    Assert-Equal -Name "manifest: a dump in Memory\ of another size is not taken by the in-collection check" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$sizeWarning $inU is 16 bytes, but collection_manifest.csv lists 20 bytes"))"

    # In Memory\ with the listed size (-NoCompress): found by its RelativePath
    $inV = Join-Path $reports "$nameV\Memory\memory_dump.dmp"
    New-TestFile $inV
    New-TestManifestCollection -Path (Join-Path $reports $nameV) -CollectedAt "$origReports\$nameV" -DumpDest "$origReports\$nameV\Memory\memory_dump.dmp" -DumpRel "Memory\memory_dump.dmp"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameV)
    Assert-Equal -Name "manifest: a dump in Memory\ (-NoCompress) with the listed size, by its RelativePath" -Expected "$inV|True" -Actual "$($run.Path)|$($run.Log.Contains("$foundNotice $inV (16 bytes, as listed)."))"

    # A collection folder renamed after the collection: the dump keeps the
    # name the collector gave it (the folder's name then, from the other
    # rows' DestPath and RelativePath)
    $driveN = Join-Path $memDrive "${nameN}_memory_dump.dmp"
    New-TestFile $driveN
    $renamedN = Join-Path $workDir "Case042 laptop"
    New-TestManifestCollection -Path $renamedN -CollectedAt "$origReports\$nameN" -DumpDest $driveN
    $run = Invoke-FindMemoryDump -Collection $renamedN
    Assert-Equal -Name "manifest: a renamed collection folder: the dump named after the folder's name at collection time" -Expected $driveN -Actual $run.Path

    # Names the collector does not write, and paths not on a drive letter:
    # a warning, and nothing is used, also when the file is there with the
    # listed size. 192.0.2.10 is a documentation address (never reached:
    # the path is refused before it is opened).
    $collectionW = Join-Path $reports $nameW
    $notesW = Join-Path $memDrive "notes.txt"
    $otherW = Join-Path $memDrive "${nameB}_memory_dump.dmp"
    $ownW = Join-Path $memDrive "${nameW}_memory_dump.dmp"
    foreach ($file in @($notesW, $otherW, $ownW, (Join-Path $collectionW "Registry\SAM"))) { New-TestFile $file }
    $wrongName = "not a name the collector gives this collection's memory dump (${nameW}_memory_dump.dmp or .raw)"
    $notDrive = "not a path on a drive letter (a network or device path named in a collection is opened only when it is next to the collection zip or folder)"
    $refusedCases = @(
        @{ Name = "a file of another name"; Dest = $notesW; Rel = ""; Shown = $notesW; Reason = $wrongName },
        @{ Name = "another collection's dump"; Dest = $otherW; Rel = ""; Shown = $otherW; Reason = $wrongName },
        @{ Name = "a \\?\ path"; Dest = "\\?\$ownW"; Rel = ""; Shown = "\\?\$ownW"; Reason = $notDrive },
        @{ Name = "a network path"; Dest = "\\192.0.2.10\evidence\${nameW}_memory_dump.dmp"; Rel = ""; Shown = "\\192.0.2.10\evidence\${nameW}_memory_dump.dmp"; Reason = $notDrive },
        @{ Name = "a RelativePath outside Memory\"; Dest = "$origReports\$nameW\Registry\SAM"; Rel = "Registry\SAM"; Shown = "Registry\SAM"; Reason = "not a name the collector gives a memory dump in the collection (Memory\memory_dump.dmp or .raw)" }
    )
    foreach ($case in $refusedCases) {
        New-TestManifestCollection -Path $collectionW -CollectedAt "$origReports\$nameW" -DumpDest $case.Dest -DumpRel $case.Rel
        $run = Invoke-FindMemoryDump -Collection $collectionW
        $again = Find-MemoryDump
        $warnings = ([regex]::Matches((Get-TestLog), [regex]::Escape($refusedWarning))).Count
        Assert-Equal -Name "manifest names $($case.Name): one warning when the dump is looked for twice, nothing used" -Expected "||1|True" -Actual "$($run.Path)|$again|$warnings|$($run.Log.Contains("$refusedWarning $($case.Shown) is $($case.Reason)."))"
    }

    # Zipped: a dump the collector saved in the collection is moved next to
    # the zip, so it is missing from the collection: the dump next to the
    # zip, with its size checked against the manifest's and the manifest's
    # SHA-256 logged once. The same with the first collector's manifest (no
    # RelativePath column). Without a dump row (no memory captured, or a
    # failed capture: only the acquisition log is listed) nothing is
    # checked or logged
    $siblingO = Join-Path $reports "${nameO}_memory_dump.dmp"
    $zipO = Join-Path $reports "$nameO.zip"
    foreach ($file in @($siblingO, $zipO)) { New-TestFile $file }
    $collectionO = Join-Path $extracted $nameO
    $siblingLineO = "[*] $siblingNotice $siblingO (16 bytes, as collection_manifest.csv lists for this collection's dump). SHA-256 in the manifest: $testHash -- the dump is not hashed again here (it is as large as RAM); Get-FileHash -Algorithm SHA256 checks it."
    $zippedCases = @(
        @{ Name = "the dump row in the collection"; Row = @{ DumpDest = "$origReports\$nameO\Memory\memory_dump.dmp"; DumpRel = "Memory\memory_dump.dmp" }; Log = $siblingLineO },
        @{ Name = "the first collector's manifest"; Row = @{ DumpDest = "$origReports\$nameO\Memory\memory_dump.dmp"; OldColumns = $true }; Log = $siblingLineO },
        @{ Name = "no dump row"; Row = @{ NoDumpRow = $true }; Log = "" }
    )
    foreach ($case in $zippedCases) {
        $row = $case.Row
        New-TestManifestCollection -Path $collectionO -CollectedAt "$origReports\$nameO" @row
        $run = Invoke-FindMemoryDump -Collection $collectionO -Zip $zipO
        $again = Find-MemoryDump
        $log = (Get-TestLog) -replace '(?m)^\[[0-9: -]+\]', '[*]'
        Assert-Equal -Name "zipped, $($case.Name): the dump next to the zip, looked for twice: $(if ($case.Log) { 'the manifest''s size and SHA-256 logged once' } else { 'nothing logged' })" -Expected "$siblingO|$siblingO|$($case.Log)" -Actual "$($run.Path)|$again|$($log.Trim())"
    }

    # A copy of another size than the manifest lists is not analyzed, wherever
    # it is found (a copy cut short): next to the zip, with the dump row in
    # the collection (zipped by the collector, which moved the dump), and
    # next to the zip moved to another folder with its dump, its row naming
    # the path next to the zip on the collecting machine (a collector that
    # changes the row when it moves the dump). One warning; with the
    # listed size the dump is used and the manifest's SHA-256 logged
    $collectionQ = Join-Path $extracted $nameQ
    $movedReports = Join-Path $workDir "analysis\cases"
    $siblingQ = Join-Path $movedReports "${nameQ}_memory_dump.dmp"
    $zipQ = Join-Path $movedReports "$nameQ.zip"
    foreach ($file in @($siblingQ, $zipQ)) { New-TestFile $file }
    $cutCases = @(
        @{ Name = "the dump row in the collection"; Row = @{ DumpDest = "$origReports\$nameQ\Memory\memory_dump.dmp"; DumpRel = "Memory\memory_dump.dmp" } },
        @{ Name = "the row naming the path next to the zip on the collecting machine"; Row = @{ DumpDest = "$origReports\${nameQ}_memory_dump.dmp" } }
    )
    foreach ($case in $cutCases) {
        $row = $case.Row
        New-TestManifestCollection -Path $collectionQ -CollectedAt "$origReports\$nameQ" -DumpSize "4096" @row
        $run = Invoke-FindMemoryDump -Collection $collectionQ -Zip $zipQ
        $again = Find-MemoryDump
        $warnings = ([regex]::Matches((Get-TestLog), [regex]::Escape($sizeWarning))).Count
        $cutLine = "$sizeWarning $siblingQ is 16 bytes, but collection_manifest.csv lists 4096 bytes for this collection's dump (a copy cut short?)."
        Assert-Equal -Name "manifest, $($case.Name): a dump of another size next to the zip gets one warning and is not used" -Expected "||1|True" -Actual "$($run.Path)|$again|$warnings|$($run.Log.Contains($cutLine))"
        New-TestManifestCollection -Path $collectionQ -CollectedAt "$origReports\$nameQ" -DumpSize "16" @row
        $run = Invoke-FindMemoryDump -Collection $collectionQ -Zip $zipQ
        Assert-Equal -Name "manifest, $($case.Name): with the listed size the dump next to the zip is used, the manifest's SHA-256 logged" -Expected "$siblingQ|True|False" -Actual "$($run.Path)|$($run.Log.Contains("$siblingNotice $siblingQ (16 bytes, as collection_manifest.csv lists for this collection's dump). SHA-256 in the manifest: $testHash"))|$($run.Log.Contains('WARNING'))"
    }
    # ... and a copy put into the collection's Memory\ folder
    $copiedQ = Join-Path $workDir "copied\$nameQ"
    $inQ = Join-Path $copiedQ "Memory\memory_dump.dmp"
    New-TestFile $inQ
    New-TestManifestCollection -Path $copiedQ -CollectedAt "$origReports\$nameQ" -DumpDest "$origReports\${nameQ}_memory_dump.dmp" -DumpSize "4096"
    $run = Invoke-FindMemoryDump -Collection $copiedQ
    Assert-Equal -Name "manifest: a dump of another size copied into the collection's Memory\ folder gets one warning and is not used" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$sizeWarning $inQ is 16 bytes, but collection_manifest.csv lists 4096 bytes for this collection's dump"))"

    # The dump's drive has another letter now (a USB drive on the analysis
    # machine, or plugged in again): the manifest's path on a drive letter
    # that is not there, the dump at the same path under another drive's
    # root. Folders stand in for the drives; one holds a copy of another
    # size, which is passed over for the dump of the listed size
    if ($freeDrive) {
        $listedZ = "${freeDrive}:\TriageMemory\${nameZ}_memory_dump.dmp"
        $driveWrong = Join-Path $workDir "drive-e"
        $driveRight = Join-Path $workDir "drive-f"
        $wrongZ = Join-Path $driveWrong "TriageMemory\${nameZ}_memory_dump.dmp"
        $rightZ = Join-Path $driveRight "TriageMemory\${nameZ}_memory_dump.dmp"
        foreach ($file in @($wrongZ, $rightZ)) { New-TestFile $file }
        [System.IO.File]::WriteAllBytes($wrongZ, (New-Object byte[] 10))
        $collectionZ = Join-Path $reports $nameZ
        New-TestManifestCollection -Path $collectionZ -CollectedAt "$origReports\$nameZ" -DumpDest $listedZ
        $script:testDriveRoots = @("$driveWrong\", "$driveRight\")
        $run = Invoke-FindMemoryDump -Collection $collectionZ
        $again = Find-MemoryDump
        $log = Get-TestLog
        $notices = ([regex]::Matches($log, [regex]::Escape($foundNotice.Replace(" (collection_manifest.csv):", "")))).Count
        $movedLine = "Memory dump where the collector saved it, on a drive with another letter now (collection_manifest.csv lists $listedZ): $rightZ (16 bytes, as listed). SHA-256 in the manifest: $testHash"
        Assert-Equal -Name "manifest: the dump's drive has another letter now: found at the same path on another drive, a copy of another size passed over, logged once, no warning" -Expected "$rightZ|$rightZ|1|True|$listedZ|False" -Actual "$($run.Path)|$again|$notices|$($log.Contains($movedLine))|$($script:memoryDumpListedPath)|$($log.Contains('WARNING'))"
        $script:testDriveRoots = @("$driveRight\")
        $run = Invoke-FindMemoryDump -Collection $collectionZ
        Assert-Equal -Name "manifest: ... found on the first other drive tried: the path the manifest lists is kept for the offer" -Expected "$rightZ|True|$listedZ" -Actual "$($run.Path)|$($run.Log.Contains($movedLine))|$($script:memoryDumpListedPath)"
        $script:testDriveRoots = @("$driveWrong\")
        $run = Invoke-FindMemoryDump -Collection $collectionZ
        Assert-Equal -Name "manifest: ... only a copy of another size on another drive: one warning, not used" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$sizeWarning $wrongZ is 10 bytes, but collection_manifest.csv lists 16 bytes for the dump the collector saved to $listedZ (a copy cut short?)."))"
        $script:testDriveRoots = @()
        $run = Invoke-FindMemoryDump -Collection $collectionZ
        Write-NoMemoryDumpToOffer
        $log = (Get-TestLog) -replace '(?m)^\[[0-9: -]+\] ', ''
        $offerLines = "No memory dump to offer: the collector saved it to $listedZ (collection_manifest.csv), and it is not there now, nor at that path on another drive.`r`n  To have it analyzed, connect the drive the collector saved it to, or copy the dump to $(Join-Path $reports "${nameZ}_memory_dump.dmp") (collection_manifest.csv lists 16 bytes), then run the builder again."
        Assert-Equal -Name "manifest: ... on no drive: logged, and the offer step says how to have it analyzed (no -MemoryDumpPath)" -Expected "|True|True|False" -Actual "$($run.Path)|$($log.Contains("$goneNotice $listedZ (collection_manifest.csv); it is not there now, nor at that path on another drive"))|$($log.Contains($offerLines))|$($log.Contains('-MemoryDumpPath'))"
    }

    # The real drives: the system drive is one of them
    $systemRoot = "$($env:SystemDrive)\"
    Assert-Equal -Name "drives searched for a dump whose drive has another letter now: the system drive is one" -Expected "True" -Actual "$(@(& $realDriveRoots) -contains $systemRoot)"

    # A collection on a network share (reached here as \\localhost\<drive>$):
    # the manifest names the dump next to the zip on the share, the path the
    # builder looks at anyway, so it is used, with no warning about a
    # network path (the collector's -MemoryOutputPath set to the zip's
    # folder, or a collector that changes the row when it moves the dump)
    $shareWorkDir = "\\localhost\" + $workDir.Substring(0, 1) + "$" + $workDir.Substring(2)
    if (Test-Path -LiteralPath $shareWorkDir) {
        $shareReports = Join-Path $shareWorkDir "share\reports"
        $shareDump = Join-Path $shareReports "${nameShare}_memory_dump.dmp"
        $shareZip = Join-Path $shareReports "$nameShare.zip"
        foreach ($file in @($shareDump, $shareZip)) { New-TestFile $file }
        $collectionShare = Join-Path $extracted $nameShare
        New-TestManifestCollection -Path $collectionShare -CollectedAt "$origReports\$nameShare" -DumpDest $shareDump
        $run = Invoke-FindMemoryDump -Collection $collectionShare -Zip $shareZip
        Assert-Equal -Name "manifest on a network share: the dump next to the zip on the share is used, no warning" -Expected "$shareDump|True|False" -Actual "$($run.Path)|$($run.Log.Contains("$foundNotice $shareDump (16 bytes, as listed)."))|$($run.Log.Contains('WARNING'))"
        $elsewhereShare = Join-Path $shareWorkDir "share\dumps\${nameShare}_memory_dump.dmp"
        New-TestFile $elsewhereShare
        New-TestManifestCollection -Path $collectionShare -CollectedAt "$origReports\$nameShare" -DumpDest $elsewhereShare
        $run = Invoke-FindMemoryDump -Collection $collectionShare -Zip $shareZip
        Assert-Equal -Name "manifest on a network share: a dump elsewhere on the share is refused, the one next to the zip used" -Expected "$shareDump|True" -Actual "$($run.Path)|$($run.Log.Contains("$refusedWarning $elsewhereShare is $notDrive."))"
    }

    # A manifest with characters a path cannot have (here | in the
    # collection's other rows): Windows PowerShell 5.1's Path methods throw
    # on them, which must not stop the lookup
    $drivePipe = Join-Path $memDrive "${namePipe}_memory_dump.dmp"
    New-TestFile $drivePipe
    New-TestManifestCollection -Path (Join-Path $reports $namePipe) -CollectedAt "C:\T\rep|orts\$namePipe" -DumpDest $drivePipe
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $namePipe)
    Assert-Equal -Name "manifest with | in a path: the dump is still found" -Expected $drivePipe -Actual $run.Path

    # How the dump is shown (the "Memory Dump Detected" offer): its path in
    # the collection, else its full path
    Set-TestRunState -Collection (Join-Path $reports $nameD)
    Assert-Equal -Name "dump shown as its path in the collection, or as its full path outside it" -Expected "Memory\memory_dump.raw in the collection|$driveK" -Actual "$(Get-MemoryDumpDisplayName $dumpD)|$(Get-MemoryDumpDisplayName $driveK)"

    # --- No dump found: what the manifest lists, and how to have it analyzed --
    # The offer step (Run-TimelineBuilder.bat: Memory is not in -Sources)
    # and the Memory parser say what collection_manifest.csv lists, and how
    # to have the dump analyzed: copy it next to the collection zip or
    # folder under its name (the .bat cannot pass -MemoryDumpPath), or
    # connect the drive the collector saved it to. The parser, run with
    # -Sources ...,Memory from PowerShell, also names -MemoryDumpPath.
    $noDumpStart = "WARNING: No memory dump found in or next to the collection; "
    $goneX = Join-Path $memDrive "${nameX}_memory_dump.dmp"
    New-TestFile (Join-Path $reports "$nameP\USB\setupapi.dev.log")
    New-TestManifestCollection -Path (Join-Path $reports $nameX) -CollectedAt "$origReports\$nameX" -DumpDest $goneX
    New-TestManifestCollection -Path (Join-Path $reports $nameY) -CollectedAt "$origReports\$nameY" -DumpDest "$origReports\$nameY\Memory\memory_dump.dmp" -DumpRel "Memory\memory_dump.dmp"
    $anyType = " (_memory_dump.raw for a raw image)"
    $noDumpCases = @(
        @{ Name = "no dump row"; Collection = (Join-Path $reports $nameC); Note = "collection_manifest.csv lists none (the collector saved no complete dump)"; Remedy = "copy the dump to $(Join-Path $reports "${nameC}_memory_dump.dmp")$anyType" },
        @{ Name = "no collection_manifest.csv"; Collection = (Join-Path $reports $nameP); Note = "there is no collection_manifest.csv that says where the collector saved one"; Remedy = "copy the dump to $(Join-Path $reports "${nameP}_memory_dump.dmp")$anyType" },
        @{ Name = "the listed dump is gone"; Collection = (Join-Path $reports $nameX); Note = "the collector saved it to $goneX (collection_manifest.csv), and it is not there now, nor at that path on another drive"; Remedy = "connect the drive the collector saved it to, or copy the dump to $(Join-Path $reports "${nameX}_memory_dump.dmp") (collection_manifest.csv lists 16 bytes)"; Size = " (16 bytes)" },
        @{ Name = "the dump row in the collection, no dump next to it"; Collection = (Join-Path $reports $nameY); Note = "collection_manifest.csv lists one in the collection (Memory\memory_dump.dmp), which the collector moves next to the zip as ${nameY}_memory_dump.dmp when it zips the collection"; Remedy = "copy the dump to $(Join-Path $reports "${nameY}_memory_dump.dmp") (collection_manifest.csv lists 16 bytes)"; Size = " (16 bytes)" },
        @{ Name = "the listed dump has another size"; Collection = (Join-Path $reports $nameS); Note = "collection_manifest.csv lists one at $driveS, which was not used (see the warning above)"; Remedy = "copy the dump to $(Join-Path $reports "${nameS}_memory_dump.dmp") (collection_manifest.csv lists 34359738368 bytes)"; Size = " (32 GB)" }
    )
    foreach ($case in $noDumpCases) {
        Set-TestRunState -Collection $case.Collection
        Parse-Memory | Out-Null
        $log = Get-TestLog
        Assert-Equal -Name "Parse-Memory without a dump, $($case.Name): the warning says what the manifest lists and how to have the dump analyzed, then it stops" -Expected "True|False|True" -Actual "$($log.Contains("$noDumpStart$($case.Note). To have it analyzed, $($case.Remedy), or pass the file as -MemoryDumpPath."))|$($log.Contains('Found memory dump'))|$($log.Contains('Memory parsing complete.'))"
        Set-TestRunState -Collection $case.Collection
        Write-NoMemoryDumpToOffer
        $log = (Get-TestLog) -replace '(?m)^\[[0-9: -]+\] ', ''
        # The last line is the one the findings report reads (Coverage.Notes)
        $expected = "No memory dump to offer: $($case.Note).`r`n  To have it analyzed, $($case.Remedy), then run the builder again.`r`n  Memory dump not analyzed: the dump listed in collection_manifest.csv$($case.Size) -- it was not found (or not usable) next to the collection or where the collector saved it."
        if ($case.Name -like "no *") { $expected = "" }
        Assert-Equal -Name "offer step without a dump, $($case.Name): $(if ($expected) { 'what the manifest lists, how to have the dump analyzed, and the line for the report' } else { 'nothing logged' })" -Expected "$expected|False" -Actual "$($log.Trim())|$($log.Contains('-MemoryDumpPath'))"
    }
    # A collection from a Windows ARM64 computer (systeminfo.txt): its dump
    # is analyzed too (Microsoft's debugger engine), so the same copy advice
    $nameArm = "TriageCollection_2025-06-19_07-45"
    $collectionArm = Join-Path $reports $nameArm
    New-TestManifestCollection -Path $collectionArm -CollectedAt "$origReports\$nameArm" -DumpDest "$origReports\$nameArm\Memory\memory_dump.dmp" -DumpRel "Memory\memory_dump.dmp" -DumpSize "8583323648"
    [void][System.IO.Directory]::CreateDirectory((Join-Path $collectionArm "SystemInfo"))
    [System.IO.File]::WriteAllText((Join-Path $collectionArm "SystemInfo\systeminfo.txt"), "`r`nHost Name:                 WS01`r`nOS Name:                   Microsoft Windows 11 Pro`r`nSystem Type:               ARM64-based PC`r`n")
    Set-TestRunState -Collection $collectionArm
    Write-NoMemoryDumpToOffer
    $log = ((Get-TestLog) -replace '(?m)^\[[0-9: -]+\] ', '').Trim()
    $expected = "No memory dump to offer: collection_manifest.csv lists one in the collection (Memory\memory_dump.dmp), which the collector moves next to the zip as ${nameArm}_memory_dump.dmp when it zips the collection.`r`n" +
        "  To have it analyzed, copy the dump to $(Join-Path $reports "${nameArm}_memory_dump.dmp") (collection_manifest.csv lists 8583323648 bytes), then run the builder again.`r`n" +
        "  Memory dump not analyzed: the dump listed in collection_manifest.csv (7.99 GB) -- it was not found (or not usable) next to the collection or where the collector saved it."
    Assert-Equal -Name "offer step without a dump, an ARM64 collection: the copy advice like any other, and the line for the report (the size as the collector gives it)" -Expected $expected -Actual $log
    # The size in that line: bytes under 100 MB, else GB with two decimals
    # (as the memory prompt and the collector's summary give it)
    Assert-Equal -Name "dump size text: bytes, GB with two decimals, nothing for no size" -Expected " (8192 bytes)| (7.99 GB)| (32 GB)| (0.1 GB)||" -Actual "$(Get-MemoryDumpSizeText -Bytes 8192)|$(Get-MemoryDumpSizeText -Bytes 8583323648)|$(Get-MemoryDumpSizeText -Bytes 34359738368)|$(Get-MemoryDumpSizeText -Bytes 104857600)|$(Get-MemoryDumpSizeText -Bytes '')|$(Get-MemoryDumpSizeText -Bytes 'n/a')"
    # The extracted copy of a zip whose top folder had [ ] in its name was
    # renamed (Get-WildcardSafeFolder): the dump is named as the collector
    # named it, after the folder's original name
    Set-TestRunState -Collection (Join-Path $reports $nameY)
    $script:collectionFolderOriginalName = "Case [1]"
    Assert-Equal -Name "no dump next to a renamed collection folder: the note names the dump after the folder's original name" -Expected "True" -Actual "$((Get-MemoryDumpNotFoundText -Listed (Get-ManifestMemoryDump)).Note.Contains('next to the zip as Case [1]_memory_dump.dmp when'))"
    $script:collectionFolderOriginalName = $null
    # A zip: the dump goes next to it
    New-TestManifestCollection -Path $collectionQ -CollectedAt "$origReports\$nameQ" -DumpDest "$origReports\$nameQ\Memory\memory_dump.dmp" -DumpRel "Memory\memory_dump.dmp" -DumpSize "4096"
    Set-TestRunState -Collection $collectionQ -Zip $zipQ
    Write-NoMemoryDumpToOffer
    Assert-Equal -Name "offer step without a dump, a zip: copy the dump next to the zip" -Expected "True" -Actual "$((Get-TestLog).Contains("To have it analyzed, copy the dump to $siblingQ (collection_manifest.csv lists 4096 bytes), then run the builder again."))"
    Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $missing
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory with a missing -MemoryDumpPath and no other dump: both warnings" -Expected "True|True|False" -Actual "$($log.Contains("$missingWarning $missing "))|$($log.Contains($noDumpStart))|$($log.Contains('Found memory dump'))"

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

    # Parse-Memory logs the dump time. An ARM64 dump goes to Microsoft's
    # debugger engine (Invoke-DbgEngMemoryAnalysis, a stub here; the engine
    # itself is tested below), never to Volatility 3: the line the findings
    # report reads ("analyzed with the Windows debugger engine", or "not
    # analyzed" with the engine's reason), and the WinDbg command
    $armDump = Join-Path $workDir "dumps [7]\${nameC}_memory_dump.dmp"
    New-TestDump -Path $armDump -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    $realEngineAnalysis = ${function:Invoke-DbgEngMemoryAnalysis}
    $realFindVolatility = ${function:Find-VolatilityExe}
    ${function:Invoke-DbgEngMemoryAnalysis} = { param([string]$DumpPath) $script:engineCalls++; $script:engineDump = $DumpPath; return $script:engineStub }
    ${function:Find-VolatilityExe} = { $script:volCalls++; return $null }
    $armCases = @(
        @{ Name = "read"; Stub = [PSCustomObject]@{ Entries = 9; Processes = 3; CommandLines = 2; AreaRows = 4; Reason = ""; PartialReason = ""; ReadText = "read processes, command lines, DLLs; not read handles (stopped at its time limit of 60 s)"
                CoverageTexts = @("DLLs -- the loader lists of 2 processes could not be read; 36 processes' memory-region trees were inconsistent") }
            Line = "  Memory dump analyzed with the Windows debugger engine: ${nameC}_memory_dump.dmp (8192 bytes) -- read processes, command lines, DLLs; not read handles (stopped at its time limit of 60 s)"
            Coverage = "  Memory dump coverage: DLLs -- the loader lists of 2 processes could not be read; 36 processes' memory-region trees were inconsistent"
            Complete = "  Memory analysis complete: 9 entries from 0 GB dump"; NotAnalyzed = "" },
        @{ Name = "processes only"; Stub = [PSCustomObject]@{ Entries = 3; Processes = 3; CommandLines = 0; AreaRows = 0; Reason = ""; PartialReason = "its command lines could not be read [boom]"; ReadText = "read processes; not read command lines (could not be read [boom])"; CoverageTexts = @() }
            Line = "  Memory dump analyzed with the Windows debugger engine: ${nameC}_memory_dump.dmp (8192 bytes) -- read processes; not read command lines (could not be read [boom])"
            Coverage = ""; Complete = "  Memory analysis complete: 3 entries from 0 GB dump"; NotAnalyzed = "" },
        @{ Name = "not read"; Stub = [PSCustomObject]@{ Entries = 0; Processes = 0; CommandLines = 0; AreaRows = 0; Reason = "the Windows debugger engine listed no processes in it (Error - Unable to find type '_EPROCESS *' for cast)"; PartialReason = ""; ReadText = ""; CoverageTexts = @() }
            Line = "WARNING:   Memory analysis skipped: the Windows debugger engine listed no processes in it (Error - Unable to find type '_EPROCESS *' for cast)."
            Coverage = ""; Complete = ""; NotAnalyzed = "${nameC}_memory_dump.dmp (8192 bytes) -- the Windows debugger engine listed no processes in it (Error - Unable to find type '_EPROCESS *' for cast)." }
    )
    try {
        foreach ($case in $armCases) {
            $script:engineStub = $case.Stub
            $script:engineCalls = 0
            $script:volCalls = 0
            Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $armDump
            Parse-Memory | Out-Null
            $log = Get-TestLog
            $readBack = Read-ReportEngineBuilderLog -Path $script:logFile
            $expectedEngineLine = ""
            if ($case.Complete) { $expectedEngineLine = $case.Line.Substring("  Memory dump analyzed with the Windows debugger engine: ".Length) }
            $winDbgLine = "  To look further than the builder reads, open the dump in WinDbg; its command-line debugger, with the builder's symbol cache: $(Get-DbgEngWinDbgCommand -DumpPath $armDump)"
            Assert-Equal -Name "Parse-Memory, an ARM64 dump ($($case.Name)): the dump time, the debugger engine (not Volatility 3) on the dump, the line for the report, read back, and the WinDbg command" -Expected "True|True|True|1|$armDump|0|True|True|True|$expectedEngineLine|$($case.NotAnalyzed)|True" `
                -Actual "$($log.Contains("Found memory dump: $armDump (0 GB, ARM64)"))|$($log.Contains("Dump time: $captureText UTC (crash dump header)"))|$($log.Contains("  Windows ARM64 dump: analyzing it with Microsoft's debugger engine (Volatility 3 cannot read ARM64 memory)"))|$($script:engineCalls)|$($script:engineDump)|$($script:volCalls)|$($log.Contains($case.Line))|$(-not $case.Complete -or $log.Contains($case.Complete))|$($log.Contains($winDbgLine))|$($readBack.MemoryDumpEngine)|$($readBack.MemoryDumpNotAnalyzed)|$($log.Contains('Memory parsing complete.'))"
            # The coverage line of an area read in part: an information line
            # (not a warning), read back by the report
            $expectedCoverage = if ($case.Coverage) { $case.Coverage.Substring("  Memory dump coverage: ".Length) } else { "" }
            Assert-Equal -Name "Parse-Memory, an ARM64 dump ($($case.Name)): the coverage line of each area read in part, no warning for it, read back" -Expected "True|False|$expectedCoverage" `
                -Actual "$(if ($case.Coverage) { $log.Contains($case.Coverage) } else { -not $log.Contains('Memory dump coverage') })|$($log -match 'WARNING:\s+Memory dump coverage')|$(@($readBack.MemoryDumpCoverage) -join ' / ')"
        }
        Assert-Equal -Name "the WinDbg command: kdARM64.exe on ARM64 (kd.exe on another architecture), the dump and the builder's symbol cache with Microsoft's symbol server" -Expected "kdARM64.exe -z `"$armDump`" -y `"srv*$($script:testToolsFolder)\symbols*https://msdl.microsoft.com/download/symbols`"|kd.exe -z" `
            -Actual "$(Get-DbgEngWinDbgCommand -DumpPath $armDump -ProcessArchitecture ARM64)|$((Get-DbgEngWinDbgCommand -DumpPath $armDump -ProcessArchitecture AMD64).Substring(0, 9))"
    }
    finally {
        ${function:Invoke-DbgEngMemoryAnalysis} = $realEngineAnalysis
        ${function:Find-VolatilityExe} = $realFindVolatility
    }
    # An x64 dump without Volatility 3 in tools\: the download hint and the
    # line for the report. The hint names the builder's folder
    # ($PSScriptRoot), which a function made from text has not: this
    # Parse-Memory is loaded from a file in the test's folder.
    $noVolDump = Join-Path $workDir "dumps [7]\${nameK}_memory_dump.dmp"
    New-TestDump -Path $noVolDump -SystemTime $captureFileTime -LastWriteUtc $endUtc
    $parseMemoryFile = Join-Path $workDir "Parse-Memory.ps1"
    [System.IO.File]::WriteAllText($parseMemoryFile, @($functionAsts | Where-Object { $_.Name -eq "Parse-Memory" })[0].Extent.Text)
    $realFindVolatility = ${function:Find-VolatilityExe}
    ${function:Find-VolatilityExe} = { return $null }
    try {
        Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $noVolDump
        & { . $parseMemoryFile; Parse-Memory | Out-Null }
        $log = Get-TestLog
    }
    finally { ${function:Find-VolatilityExe} = $realFindVolatility }
    Assert-Equal -Name "Parse-Memory, no vol.exe: the download hint and the 'Memory dump not analyzed' line for the report" -Expected "True|True" -Actual "$($log.Contains('Volatility 3 not found in tools\ directory.'))|$($log.Contains("  Memory dump not analyzed: ${nameK}_memory_dump.dmp (8192 bytes) -- Volatility 3 (vol.exe) is not in the builder's tools\volatility3\ folder."))"
    # Without -MemoryDumpPath: the dump where the collector saved it, on
    # another drive (collection_manifest.csv)
    New-TestDump -Path $driveK -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    New-TestManifestCollection -Path (Join-Path $reports $nameK) -CollectedAt "$origReports\$nameK" -DumpDest $driveK -DumpSize "8192"
    $script:engineStub = $armCases[0].Stub
    ${function:Invoke-DbgEngMemoryAnalysis} = { param([string]$DumpPath) $script:engineCalls++; $script:engineDump = $DumpPath; return $script:engineStub }
    try {
        Set-TestRunState -Collection (Join-Path $reports $nameK)
        Parse-Memory | Out-Null
        $log = Get-TestLog
    }
    finally { ${function:Invoke-DbgEngMemoryAnalysis} = $realEngineAnalysis }
    Assert-Equal -Name "Parse-Memory: the dump where the collector saved it, by collection_manifest.csv" -Expected "True|True|True" -Actual "$($log.Contains("$foundNotice $driveK (8192 bytes, as listed)."))|$($log.Contains("Found memory dump: $driveK (0 GB, ARM64)"))|$($log.Contains("Dump time: $captureText UTC (crash dump header)"))"

    # --- The memory dump offer (Run-TimelineBuilder.bat's path) ---------------
    # The builder's top-level block that runs when Memory is not in -Sources
    # (as with the .bat), on a zipped collection with its dump next to the
    # zip: an ARM64 dump is offered with Microsoft's debugger engine (also
    # without vol.exe, which is not looked for; the engine in tools\dbgeng
    # named), and not offered without it; for an x64 dump no vol.exe, answer
    # 2, the end of redirected input (as 2), and an invalid answer then 1.
    # Each dump that is not analyzed gets the "Memory dump not analyzed"
    # line, which the findings report's own log reader
    # (TimelineReport.Engine.ps1) must read back for Coverage.Notes; the
    # prompt shows the size that line gives.
    Write-Host "Testing the memory dump offer ..."
    $offerAsts = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and
                $node.Clauses[0].Item1.Extent.Text -eq '$Sources -notcontains "Memory"' }, $false))
    Assert-Equal -Name "memory dump offer: the builder's block found" -Expected 1 -Actual $offerAsts.Count
    # From a file, so that $PSScriptRoot (the builder's folder in its
    # vol.exe hint) is set
    $offerFile = Join-Path $workDir "memory-offer.ps1"
    [System.IO.File]::WriteAllText($offerFile, $offerAsts[0].Extent.Text)
    $offerReports = Join-Path $workDir "offer"
    $nameOfferArm = "TriageCollection_2025-06-02_12-50"
    $nameOfferX64 = "TriageCollection_2025-06-01_13-10"
    foreach ($name in @($nameOfferArm, $nameOfferX64)) {
        New-TestFile (Join-Path $offerReports "$name.zip")
        New-TestCollection (Join-Path $extracted $name)
    }
    $offerArmDump = Join-Path $offerReports "${nameOfferArm}_memory_dump.dmp"
    $offerX64Dump = Join-Path $offerReports "${nameOfferX64}_memory_dump.dmp"
    New-TestDump -Path $offerArmDump -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    New-TestDump -Path $offerX64Dump -SystemTime $captureFileTime -LastWriteUtc $endUtc
    # What the prompt says for an ARM64 dump: what reads it, what it adds and
    # what not, the time and the one-time symbol download
    $engineLines = @(
        "  A Windows ARM64 dump: Volatility 3 cannot read it, so the builder uses",
        "  Memory analysis adds the processes (user, program path, parent, start",
        "  time), their command lines and DLLs, kernel drivers, handles,",
        "  executable private memory, the registry in memory, console history,",
        "  network connections and services from the RAM dump.",
        "  Takes under a minute. The first time for each Windows kernel version",
        "  (most Windows updates bring a new one) it downloads the kernel's",
        "  symbol file (about 10 MB) from Microsoft's symbol server into",
        "  tools\symbols\; the request names only that file (see README.txt).",
        "  [1] Yes -- analyze memory dump (recommended for IR)"
    )
    $armSkipped = "${nameOfferArm}_memory_dump.dmp (8192 bytes) -- skipped at the memory prompt; run the builder again and answer 1 to analyze it."
    $offerCases = @(
        @{ Name = "an ARM64 dump: offered with the debugger engine of Windows, answer 2"; Collection = $nameOfferArm; Answers = @("2"); Prompts = 1; Sources = "USB"; VolCalls = 0
            Lines = @("  Found: $offerArmDump (8192 bytes)", "  Microsoft's debugger engine (dbgeng.dll, part of Windows).") + $engineLines + @("Memory analysis skipped (answer 2 at the memory prompt).")
            NotAnalyzed = $armSkipped },
        @{ Name = "an ARM64 dump without vol.exe: offered (Volatility 3 not looked for), answer 1"; Collection = $nameOfferArm; NoVol = $true; Answers = @("1"); Prompts = 1; Sources = "USB,Memory"; VolCalls = 0
            Lines = @("  Found: $offerArmDump (8192 bytes)", "Memory analysis enabled.") + $engineLines; NotAnalyzed = "" },
        @{ Name = "an ARM64 dump, the engine in tools\dbgeng: offered, the folder named"; Collection = $nameOfferArm; EngineSource = "tools\dbgeng\arm64"; Answers = @("2"); Prompts = 1; Sources = "USB"; VolCalls = 0
            Lines = @("  Microsoft's debugger engine (dbgeng.dll in tools\dbgeng\arm64\)."); NotAnalyzed = $armSkipped },
        @{ Name = "an ARM64 dump without the debugger engine: not offered"; Collection = $nameOfferArm; NoEngine = $true; Answers = @(); Prompts = 0; Sources = "USB"; VolCalls = 0
            Lines = @("Memory dump detected ($offerArmDump, Windows ARM64) but Microsoft's debugger engine is not available: the Windows debugger engine (dbgeng.dll) is not in C:\stub\System32.")
            NotAnalyzed = "${nameOfferArm}_memory_dump.dmp (8192 bytes) -- the Windows debugger engine (dbgeng.dll) is not in C:\stub\System32; see ""ARM64 memory dumps"" in README.txt." },
        @{ Name = "no vol.exe: not offered"; Collection = $nameOfferX64; NoVol = $true; Answers = @(); Prompts = 0; Sources = "USB"; VolCalls = 1
            Lines = @("Memory dump detected ($offerX64Dump) but Volatility 3 not found in tools\ directory.")
            NotAnalyzed = "${nameOfferX64}_memory_dump.dmp (8192 bytes) -- Volatility 3 (vol.exe) is not in the builder's tools\volatility3\ folder." },
        @{ Name = "answer 2"; Collection = $nameOfferX64; Answers = @("2"); Prompts = 1; Sources = "USB"; VolCalls = 1
            Lines = @("  Found: $offerX64Dump (8192 bytes)", "  Volatility 3 is available in tools\", "Memory analysis skipped (answer 2 at the memory prompt).")
            NotAnalyzed = "${nameOfferX64}_memory_dump.dmp (8192 bytes) -- skipped at the memory prompt; run the builder again and answer 1 to analyze it." },
        @{ Name = "the end of redirected input: as 2"; Collection = $nameOfferX64; Answers = @(); Prompts = 1; Sources = "USB"; VolCalls = 1
            Lines = @("Memory analysis skipped (answer 2 at the memory prompt).")
            NotAnalyzed = "${nameOfferX64}_memory_dump.dmp (8192 bytes) -- skipped at the memory prompt; run the builder again and answer 1 to analyze it." },
        @{ Name = "an invalid answer, then 1: asked again, then analyzed"; Collection = $nameOfferX64; Answers = @("x", "1"); Prompts = 2; Sources = "USB,Memory"; VolCalls = 1
            Lines = @("  Found: $offerX64Dump (8192 bytes)", "Memory analysis enabled."); NotAnalyzed = "" }
    )
    foreach ($case in $offerCases) {
        $engineSource = "Windows"
        if ($case.EngineSource) { $engineSource = $case.EngineSource }
        $offer = Invoke-TestMemoryOffer -Collection (Join-Path $extracted $case.Collection) -Zip (Join-Path $offerReports "$($case.Collection).zip") -NoVol:([bool]$case.NoVol) -NoEngine:([bool]$case.NoEngine) -EngineSource $engineSource -Answers $case.Answers
        $missingLines = @($case.Lines | Where-Object { -not $offer.Console.Contains($_) })
        $readBack = (Read-ReportEngineBuilderLog -Path $script:logFile).MemoryDumpNotAnalyzed
        $logged = @(([regex]::Matches($offer.Log, '(?m)^\[[^\]]+\]   Memory dump not analyzed: (.+?)\r?$')) | ForEach-Object { $_.Groups[1].Value })
        Assert-Equal -Name "memory dump offer, $($case.Name): prompts, -Sources, the console lines, the 'Memory dump not analyzed' line read back by the report, Volatility 3 looked for" -Expected "$($case.Prompts)|$($case.Sources)||$($case.NotAnalyzed)|$($case.NotAnalyzed)|$(if ($case.NotAnalyzed) { 1 } else { 0 })|$($case.VolCalls)" -Actual "$($offer.Prompts)|$($offer.Sources)|$($missingLines -join ' / ')|$($logged -join ' / ')|$readBack|$(([regex]::Matches($offer.Console, 'Memory dump not analyzed')).Count)|$($offer.VolCalls)"
    }

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
    # Owner is the process that owns the socket: Details Process=, never User
    $netscanRows = @(
        "2025-06-30 11:59:01.250|NetworkConnection|Memory network: TCPv4 192.0.2.10:49731 -> 198.51.100.20:443 (ESTABLISHED)||PID=7340 Process=notepad.exe",
        "$captureText|Snapshot|Memory network: UDPv4 192.0.2.10:5353 -> *:* ()||PID=2044 Process=svchost.exe",
        "$captureText|Snapshot|Memory network: TCPv6 ::1:8080 -> :::0 (LISTENING)||PID=1234 Process=web.exe Created=1601-01-01 00:00:00.000",
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

    # --- Windows ARM64 dumps: Microsoft's debugger engine ---------------------
    Write-Host "Testing the debugger engine path for Windows ARM64 dumps ..."
    $workerPath = Join-Path (Split-Path $builder -Parent) "lib\memory\TimelineDbgEng.ps1"
    $workerErrors = $null
    $workerAst = [System.Management.Automation.Language.Parser]::ParseFile($workerPath, [ref]$null, [ref]$workerErrors)
    Assert-Equal -Name "debugger engine helper: lib\memory\TimelineDbgEng.ps1 parses" -Expected 0 -Actual @($workerErrors).Count
    $workerFunctions = @($workerAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false))
    foreach ($shared in @("Get-DbgEngShortError", "Get-DbgEngErrorText")) {
        $sharedBodies = @(@($functionAsts) + $workerFunctions | Where-Object { $_.Name -eq $shared } | ForEach-Object { $_.Body.Extent.Text })
        Assert-Equal -Name "${shared}: the same in timeline-builder.ps1 and the helper" -Expected "2|True" -Actual "$($sharedBodies.Count)|$($sharedBodies.Count -eq 2 -and $sharedBodies[0] -ceq $sharedBodies[1])"
    }
    foreach ($functionAst in $workerFunctions) { . ([scriptblock]::Create($functionAst.Extent.Text)) }
    # The real functions, put back after the stubs below
    $realFunctions = @{}
    foreach ($name in @("Open-DbgEngSession", "Close-DbgEngSession", "Invoke-DbgEngCommand", "Read-DbgEngVirtual", "Save-KernelSymbolDownload", "Write-DbgEngWorkerLine",
            "Find-DbgEngine", "Start-DbgEngWorker", "Get-DbgEngWorkerPath", "Read-DbgEngCommandLine")) {
        $realFunctions[$name] = (Get-Item -LiteralPath "function:$name").ScriptBlock
    }
    # (dot-sourced, so the functions are put back in this script's scope)
    $restoreTestFunctions = { foreach ($name in @($realFunctions.Keys)) { Set-Item -LiteralPath "function:$name" -Value $realFunctions[$name] } }
    $engineDir = Join-Path $workDir "engine"
    [void][System.IO.Directory]::CreateDirectory($engineDir)
    $script:runScratchDir = Join-Path $workDir "engine-run [1]\scratch"
    [void][System.IO.Directory]::CreateDirectory($script:runScratchDir)

    # The NuGet folder name of the PowerShell process's architecture
    Assert-Equal -Name "Get-DbgEngArchitecture: arm64, amd64 or x86 for this PowerShell's processor architecture, nothing for another" -Expected "arm64|amd64|x86|||arm64" -Actual ((@("ARM64", "AMD64", "x86", "IA64", "", "arm64") | ForEach-Object { Get-DbgEngArchitecture $_ }) -join "|")

    # Find-DbgEngine: System32; copies of System32's (catalog-signed) DLLs in
    # tools\dbgeng\<arch>\ are used, with the load order; an unsigned DLL in
    # a subfolder or a missing DLL: a warning and System32; no dbgeng.dll in
    # the system folder: a reason; another architecture: System32 only
    $system32 = Join-Path $env:SystemRoot "System32"
    $processArch = Get-DbgEngArchitecture
    $engineTools = Join-Path $engineDir "tools"
    $engine = Find-DbgEngine -ToolsFolder $engineTools
    Assert-Equal -Name "Find-DbgEngine without tools\dbgeng: the engine of Windows (System32), by full path, with its version" -Expected "Windows|$system32|dbgeng.dll|$system32\dbgeng.dll|||True" -Actual "$($engine.Source)|$($engine.Folder)|$($engine.Dlls -join ',')|$($engine.Path)|$($engine.Warning)|$($engine.Reason)|$($engine.Version -match '^\d+\.\d+\.\d+')"
    $copyDir = Join-Path $engineTools "dbgeng\$processArch"
    [void][System.IO.Directory]::CreateDirectory($copyDir)
    foreach ($dll in @("dbgeng.dll", "dbghelp.dll", "dbgmodel.dll", "dbgcore.dll")) {
        if (Test-Path -LiteralPath (Join-Path $system32 $dll)) { Copy-Item -LiteralPath (Join-Path $system32 $dll) -Destination (Join-Path $copyDir $dll) }
    }
    $engine = Find-DbgEngine -ToolsFolder $engineTools
    Assert-Equal -Name "Find-DbgEngine: copies of Windows' own (signed) DLLs in tools\dbgeng\$processArch\ are used, loaded in their order" -Expected "tools\dbgeng\$processArch|$copyDir|dbghelp.dll,dbgcore.dll,msdia140.dll,dbgmodel.dll,dbgeng.dll|$copyDir\dbgeng.dll|" -Actual "$($engine.Source)|$($engine.Folder)|$($engine.Dlls -join ',')|$($engine.Path)|$($engine.Warning)"
    $planted = Join-Path $copyDir "winext\planted.dll"
    [void][System.IO.Directory]::CreateDirectory((Split-Path $planted -Parent))
    [System.IO.File]::WriteAllBytes($planted, ([byte[]](0x4D, 0x5A) + (New-Object byte[] 510)))
    $engine = Find-DbgEngine -ToolsFolder $engineTools
    Assert-Equal -Name "Find-DbgEngine: an unsigned DLL in a subfolder of tools\dbgeng\$processArch\: a warning that names it, and the engine of Windows" -Expected "Windows|$system32|True" -Actual "$($engine.Source)|$($engine.Folder)|$($engine.Warning -like "tools\dbgeng\$processArch\ is not used: winext\planted.dll is not signed by Microsoft (signature: *). The debugger engine that is part of Windows is used instead.")"
    Remove-Item -LiteralPath (Split-Path $planted -Parent) -Recurse -Force
    Remove-Item -LiteralPath (Join-Path $copyDir "dbghelp.dll") -Force
    $engine = Find-DbgEngine -ToolsFolder $engineTools
    Assert-Equal -Name "Find-DbgEngine: dbghelp.dll missing in tools\dbgeng\$processArch\: a warning, and the engine of Windows" -Expected "Windows|tools\dbgeng\$processArch\ is not used: dbghelp.dll is missing there (copy every DLL of the package's content folder). The debugger engine that is part of Windows is used instead." -Actual "$($engine.Source)|$($engine.Warning)"
    $noSystem = Join-Path $engineDir "no-system"
    [void][System.IO.Directory]::CreateDirectory($noSystem)
    $engine = Find-DbgEngine -ToolsFolder (Join-Path $engineDir "no-tools") -SystemFolder $noSystem
    Assert-Equal -Name "Find-DbgEngine: no dbgeng.dll in the system folder: no engine, and why" -Expected "||the Windows debugger engine (dbgeng.dll) is not in $noSystem" -Actual "$($engine.Path)|$($engine.Source)|$($engine.Reason)"
    $engine = Find-DbgEngine -ToolsFolder $engineTools -ProcessArchitecture "IA64"
    Assert-Equal -Name "Find-DbgEngine: an architecture without a NuGet folder: the engine of Windows, no warning" -Expected "Windows|" -Actual "$($engine.Source)|$($engine.Warning)"

    # The C# host on this computer's own engine (no dump): it compiles, loads
    # dbgeng.dll by full path (twice is fine), runs a command (output also
    # for a failing one), throws for a fake and a missing dump and lets the
    # file go, and refuses a second engine folder in the same process
    Initialize-DbgEngHost
    $hostCompiled = [bool]([System.Management.Automation.PSTypeName]'TimelineDbgEng.Session').Type
    [TimelineDbgEng.Session]::LoadEngine($system32, [string[]]@("dbgeng.dll"))
    [TimelineDbgEng.Session]::LoadEngine($system32, [string[]]@("dbgeng.dll"))
    $smoke = New-Object TimelineDbgEng.Session
    try {
        $echo = Invoke-DbgEngCommand -Session $smoke -Command ".echo TBX" -TimeoutSeconds 60
        $unresolved = Invoke-DbgEngCommand -Session $smoke -Command "? nosuchsymbol_tb" -TimeoutSeconds 60
    }
    finally {
        $smoke.Dispose()
        $smoke.Dispose()
    }
    Assert-Equal -Name "C# host: compiles, loads dbgeng.dll from System32 by full path, runs a command; a failing one still gives its output" -Expected "True|$system32\dbgeng.dll|True|True" -Actual "$hostCompiled|$([TimelineDbgEng.Session]::LoadedPath('dbgeng.dll'))|$($echo -match 'TBX')|$("$unresolved".Trim().Length -gt 0)"
    $fakeDump = Join-Path $engineDir "fake-arm64.dmp"
    New-TestDump -Path $fakeDump -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    $openResults = foreach ($target in @($fakeDump, (Join-Path $engineDir "missing.dmp"))) {
        $session = New-Object TimelineDbgEng.Session
        try {
            $session.OpenDump($target, 60000)
            "opened"
        }
        catch {
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            $inner.GetType().Name
        }
        finally { $session.Dispose() }
    }
    $released = $false
    try {
        [System.IO.File]::Open($fakeDump, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None).Dispose()
        $released = $true
    }
    catch { Write-Host "  (the fake dump is still open: $($_.Exception.Message))" }
    Assert-Equal -Name "C# host: a fake ARM64 dump and a missing file throw DbgEngException, and the fake dump is released afterwards" -Expected "DbgEngException|DbgEngException|True" -Actual "$($openResults -join '|')|$released"
    $secondEngine = "loaded"
    try { [TimelineDbgEng.Session]::LoadEngine($copyDir, [string[]]@("dbghelp.dll", "dbgcore.dll", "msdia140.dll", "dbgmodel.dll", "dbgeng.dll")) }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        $secondEngine = $inner.Message
    }
    Assert-Equal -Name "C# host: an engine folder whose DLLs are already loaded from another folder is refused (no mixed versions)" -Expected "True" -Actual "$($secondEngine -match ' is already loaded in this PowerShell from ')"

    # The dx text: "[0x..] : value" items; the echoed expression ignored;
    # quotes stripped; engine errors and damaged rows counted as bad items;
    # a query that fails as a whole keeps its "Error:" line (the engine's
    # own text for a type it does not know)
    Assert-Equal -Name "ConvertFrom-DbgEngNumber: decimal (negative too), hex with or without 0x and with a backtick, else nothing" -Expected "4|-1|0|255|$([Convert]::ToUInt64('fffff8035c600000', 16))|||" -Actual ((@(@("4", $false), @("-1", $false), @("0", $false), @("0xff", $true), @("0xfffff803``5c600000", $true), @("zz", $true), @("0x", $true), @("1.5", $false)) | ForEach-Object { if ($_[1]) { ConvertFrom-DbgEngNumber $_[0] -Hex } else { ConvertFrom-DbgEngNumber $_[0] } }) -join "|")
    $corruptWarning = "WARNING: corrupted linked list found. Previous (_LIST_ENTRY*) 0xffffa000000012c8, current (_LIST_ENTRY*) 0xffffa000000022c8."
    $dxText = "$corruptWarning`r`n@`$cursession.Processes.Skip(0).Take(100).Select(p => ...)`r`n" +
        "    [0x0]            : `"TBP|0xffffa00000001000|4|0|133|0|150|0x0|0xffffa000000015a8`"`r`n" +
        "    [0x1]            : Unable to read memory at Address 0x10`r`n" +
        "$corruptWarning`r`n" +
        "    [0x2]            : TBP|zz|1`r`n" +
        "    [0x3``0]         : TBP|0xffffa00000002000|92|4|134|0|4|0x0|0xffffa000000025a8`r`n"
    $parsed = ConvertFrom-DbgEngDxRows -Text $dxText -Tag "TBP" -FieldCount 8
    Assert-Equal -Name "ConvertFrom-DbgEngDxRows: the echo ignored, a quoted value, an engine error and a damaged row as bad items, a backtick in the index, the engine's warning kept once" -Expected "4|2|2|Unable to read memory at Address 0x10||4|92|$corruptWarning" -Actual "$($parsed.Items)|$(@($parsed.Rows).Count)|$($parsed.Bad)|$($parsed.FirstBad)|$($parsed.QueryError)|$($parsed.Rows[0][1])|$($parsed.Rows[1][1])|$(@($parsed.Warnings) -join ' / ')"
    $warningOnly = ConvertFrom-DbgEngDxRows -Text "$corruptWarning`r`n" -Tag "TBP" -FieldCount 8
    Assert-Equal -Name "ConvertFrom-DbgEngDxRows: a warning and nothing else is the query's error" -Expected "0|$corruptWarning" -Actual "$($warningOnly.Items)|$($warningOnly.QueryError)"
    $failedQuery = ConvertFrom-DbgEngDxRows -Text "Error: Unable to find type '_EPROCESS *' for cast.`r`n" -Tag "TBP" -FieldCount 8
    $emptyList = ConvertFrom-DbgEngDxRows -Text "@`$cursession.Processes.Skip(200).Take(100).Select(p => ...)`r`n" -Tag "TBP" -FieldCount 8
    $nothing = ConvertFrom-DbgEngDxRows -Text "" -Tag "TBP" -FieldCount 8
    Assert-Equal -Name "ConvertFrom-DbgEngDxRows: a query that fails as a whole keeps the engine's error; an empty list (the echo only) is no error; no output at all is one" -Expected "0|Error: Unable to find type '_EPROCESS *' for cast.|0||Error: no output" -Actual "$($failedQuery.Items)|$($failedQuery.QueryError)|$($emptyList.Items)|$($emptyList.QueryError)|$($nothing.QueryError)"

    # Paging: 100 items a page, good and bad alike; a short page ends it; a
    # list that does not end stops at -MaxItems; a failing query stops it
    $script:pages = @()
    $script:pageCalls = 0
    ${function:Invoke-DbgEngCommand} = {
        $page = $script:pages[[Math]::Min($script:pageCalls, $script:pages.Count - 1)]
        $script:pageCalls++
        if ($page -is [string]) { return $page }
        $lines = for ($i = 0; $i -lt $page[0]; $i++) { "    [0x$($i.ToString('x'))] : TBS|0x$((4096 + $script:pageCalls * 1000 + $i).ToString('x'))|1" }
        $bad = for ($i = 0; $i -lt $page[1]; $i++) { "    [0x$(($page[0] + $i).ToString('x'))] : Unable to read memory at Address 0x10" }
        return "@`$cursession...`n" + (@($lines) + @($bad) -join "`n")
    }
    $pagingCases = @(
        @{ Name = "100 + 50"; Pages = @(, @(100, 0)) + @(, @(50, 0)); Max = 20000; Expected = "2|150|150|0|False|" },
        @{ Name = "100 + 100 + 0"; Pages = @(, @(100, 0)) + @(, @(100, 0)) + @(, @(0, 0)); Max = 20000; Expected = "3|200|200|0|False|" },
        @{ Name = "90 good + 10 bad, then 5"; Pages = @(, @(90, 10)) + @(, @(5, 0)); Max = 20000; Expected = "2|105|95|10|False|" },
        @{ Name = "always full, -MaxItems 300"; Pages = @(, @(100, 0)); Max = 300; Expected = "3|300|300|0|True|" },
        @{ Name = "100, then a query error"; Pages = @(@(100, 0), "Error: Unable to read memory at Address 0x0"); Max = 20000; Expected = "2|100|100|0|False|Error: Unable to read memory at Address 0x0" }
    )
    foreach ($case in $pagingCases) {
        $script:pages = $case.Pages
        $script:pageCalls = 0
        $paged = Get-DbgEngDxPages -Session $null -Template (Get-DbgEngQuery Session) -Tag "TBS" -FieldCount 2 -MaxItems $case.Max
        Assert-Equal -Name "Get-DbgEngDxPages, $($case.Name): calls|items|rows|bad|capped|query error" -Expected $case.Expected -Actual "$($script:pageCalls)|$($paged.Items)|$(@($paged.Rows).Count)|$($paged.Bad)|$($paged.Capped)|$($paged.QueryError)"
    }
    . $restoreTestFunctions

    # The queries: paged, tagged, formattable with -f (no other braces); no
    # command the helper sends is an extension ("!") command; no
    # attacker-tool name of report-rules.json (Defender's AMSI scans the
    # helper) in the helper's text, its C# host or its queries
    $queryChecks = foreach ($name in @("Process", "Session", "TokenSession")) {
        $query = Get-DbgEngQuery $name
        $tag = if ($name -eq "Process") { "TBP" } else { "TBS" }
        $tagText = '"' + $tag + '|"'
        "$name=$($query.Contains('.Skip({0}).Take(100)'))/$($query.Contains($tagText))/$(($query -f 300).Contains('.Skip(300).Take(100)'))/$($query.StartsWith('dx -r1 '))"
    }
    Assert-Equal -Name "Get-DbgEngQuery: each query paged with Skip({0}).Take(100), tagged, formattable with -f" -Expected "Process=True/True/True/True|Session=True/True/True/True|TokenSession=True/True/True/True" -Actual ($queryChecks -join "|")
    $noSession = '((unsigned __int64)p.KernelObject.Session) == 0 ? (__int64)-1 : '
    $spaceChecked = (Get-DbgEngQuery Session).Contains($noSession)
    $tokenChecked = (Get-DbgEngQuery TokenSession).Contains($noSession + '(__int64)((nt!_TOKEN*)')
    Assert-Equal -Name "Get-DbgEngQuery: both session queries give -1 for a process without a session (EPROCESS.Session 0), the token's only otherwise" -Expected "True|True" -Actual "$spaceChecked|$tokenChecked"
    $workerText = [System.IO.File]::ReadAllText($workerPath)
    $sentCommands = @([regex]::Matches($workerText, '-Command "([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) + @([regex]::Matches($workerText, '\$session\.Execute\("([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) + @("Process", "Session", "TokenSession" | ForEach-Object { Get-DbgEngQuery $_ })
    Assert-Equal -Name "the helper sends no extension (!) command (fixed commands and queries)" -Expected "0|True" -Actual "$(@($sentCommands | Where-Object { $_.TrimStart().StartsWith('!') }).Count)|$($sentCommands.Count -ge 9)"
    $rulesJson = Get-Content -LiteralPath (Join-Path (Split-Path $builder -Parent) "lib\report\report-rules.json") -Raw | ConvertFrom-Json
    $toolPatterns = @($rulesJson.lists.attackerTools)
    $queryText = (@("Process", "Session", "TokenSession") | ForEach-Object { Get-DbgEngQuery $_ }) -join "`n"
    $named = @($toolPatterns | Where-Object { $_ -and ([regex]::IsMatch($workerText, '\b(?:' + $_ + ')', 'IgnoreCase') -or [regex]::IsMatch($queryText, '\b(?:' + $_ + ')', 'IgnoreCase')) })
    Assert-Equal -Name "no attacker-tool name of report-rules.json in the helper, its C# host or its queries ($($toolPatterns.Count) names checked)" -Expected "0|True" -Actual "$($named.Count)|$($toolPatterns.Count -gt 10)"

    # --- A fake memory map: the kernel image and the processes ----------------
    # Regions of bytes in an address space (0: the kernel's), indexed by
    # their 4 KB pages; a read gets the bytes of the first region added that
    # holds its address (never across regions). The arrays stay the
    # regions' own, so a case can change bytes in place.
    $script:memIndex = @{}
    function Clear-TestRegions { $script:memIndex = @{} }
    function Add-TestRegion {
        param([uint64]$Process, [uint64]$Start, [byte[]]$Bytes)
        $region = [PSCustomObject]@{ S = $Start; B = $Bytes }
        $lastPage = ($Start + [uint64][Math]::Max(0, $Bytes.Length - 1)) -shr 12
        for ($page = $Start -shr 12; $page -le $lastPage; $page++) {
            $key = "$Process/$page"
            if (-not $script:memIndex.ContainsKey($key)) { $script:memIndex[$key] = New-Object System.Collections.Generic.List[object] }
            $script:memIndex[$key].Add($region)
        }
    }
    $stubReadVirtual = {
        param([uint64]$Process, [uint64]$Address, [int]$Count)
        $candidates = $script:memIndex["$Process/$($Address -shr 12)"]
        if ($candidates) {
            foreach ($region in $candidates) {
                if ($Address -ge $region.S -and $Address -lt $region.S + [uint64]$region.B.Length) {
                    $offset = [int]($Address - $region.S)
                    $n = [Math]::Min($Count, $region.B.Length - $offset)
                    $out = New-Object byte[] $n
                    [Array]::Copy($region.B, $offset, $out, 0, $n)
                    return , $out
                }
            }
        }
        return , (New-Object byte[] 0)
    }
    # A kernel image header (MZ, PE, PE32+, the debug directory, a CodeView
    # RSDS record) with one thing changed for each refusal
    $kernelBase = [Convert]::ToUInt64("fffff8035c600000", 16)
    $kernelGuid = [Guid]"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
    $kernelKey = "0A1B2C3D4E5F60718293A4B5C6D7E8F91A"
    function New-TestKernelImage {
        param([switch]$NoMz, [int]$PeOffset = 0x100, [uint16]$Magic = 0x20B, [uint32]$DebugSize = 28, [string]$Signature = "RSDS", [string]$PdbName = "ntkrnlmp.pdb", [uint32]$Age = 0x1A)
        $image = New-Object byte[] 0x4000
        if (-not $NoMz) { $image[0] = 0x4D; $image[1] = 0x5A }
        [Array]::Copy([BitConverter]::GetBytes([int]$PeOffset), 0, $image, 0x3C, 4)
        if ($PeOffset -gt 0 -and $PeOffset -lt 0x1000) {
            [Array]::Copy([BitConverter]::GetBytes([uint32]0x4550), 0, $image, $PeOffset, 4)
            [Array]::Copy([BitConverter]::GetBytes([uint16]0xAA64), 0, $image, $PeOffset + 4, 2)
            [Array]::Copy([BitConverter]::GetBytes($Magic), 0, $image, $PeOffset + 0x18, 2)
            [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $image, $PeOffset + 0x18 + 0x6C, 4)
            [Array]::Copy([BitConverter]::GetBytes([uint32]0x2000), 0, $image, $PeOffset + 0x18 + 0x70 + 48, 4)
            [Array]::Copy([BitConverter]::GetBytes($DebugSize), 0, $image, $PeOffset + 0x18 + 0x70 + 52, 4)
        }
        [Array]::Copy([BitConverter]::GetBytes([uint32]2), 0, $image, 0x2000 + 12, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32](24 + $PdbName.Length + 1)), 0, $image, 0x2000 + 16, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x3000), 0, $image, 0x2000 + 20, 4)
        [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes($Signature), 0, $image, 0x3000, 4)
        [Array]::Copy($kernelGuid.ToByteArray(), 0, $image, 0x3004, 16)
        [Array]::Copy([BitConverter]::GetBytes($Age), 0, $image, 0x3014, 4)
        [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes($PdbName), 0, $image, 0x3018, $PdbName.Length)
        return , $image
    }
    $script:evaluateNt = "Evaluate expression: -8779370332160 = fffff803``5c600000`n"
    ${function:Read-DbgEngVirtual} = $stubReadVirtual
    ${function:Invoke-DbgEngCommand} = { param([string]$Command) if ($Command -eq "? nt") { return $script:evaluateNt }; return "" }
    $kernelCases = @(
        @{ Name = "a kernel image with its RSDS record: the name and the key (GUID, then the age 0x1A in hex)"; Image = @{}; Expected = "ntkrnlmp.pdb|$kernelKey|" },
        @{ Name = "no MZ"; Image = @{ NoMz = $true }; Expected = "||the kernel image header is not in the dump" },
        @{ Name = "e_lfanew out of range"; Image = @{ PeOffset = 0xF00 }; Expected = "||the kernel image header is not a 64-bit Windows image" },
        @{ Name = "a 32-bit (PE32) image"; Image = @{ Magic = 0x10B }; Expected = "||the kernel image header is not a 64-bit Windows image" },
        @{ Name = "no debug directory"; Image = @{ DebugSize = 0 }; Expected = "||the kernel image has no usable debug directory" },
        @{ Name = "a debug directory of an odd size"; Image = @{ DebugSize = 30 }; Expected = "||the kernel image has no usable debug directory" },
        @{ Name = "no RSDS record"; Image = @{ Signature = "NB10" }; Expected = "||the kernel image has no symbol file record (RSDS)" },
        @{ Name = "a path in the record's file name"; Image = @{ PdbName = "..\x.pdb" }; Expected = "||the kernel's symbol file record is not one of a Windows kernel" },
        @{ Name = "another file name"; Image = @{ PdbName = "evil.pdb" }; Expected = "||the kernel's symbol file record is not one of a Windows kernel" },
        @{ Name = "age 0"; Image = @{ Age = 0 }; Expected = "||the kernel's symbol file record is not one of a Windows kernel" }
    )
    foreach ($case in $kernelCases) {
        Clear-TestRegions
        $imageArgs = $case.Image
        Add-TestRegion -Process 0 -Start $kernelBase -Bytes (New-TestKernelImage @imageArgs)
        $kernel = Get-KernelSymbolInfo -Session $null
        Assert-Equal -Name "Get-KernelSymbolInfo, $($case.Name)" -Expected $case.Expected -Actual "$($kernel.Name)|$($kernel.Key)|$($kernel.Error)"
    }
    $script:evaluateNt = "Couldn't resolve error at 'nt'`n"
    $kernel = Get-KernelSymbolInfo -Session $null
    Assert-Equal -Name "Get-KernelSymbolInfo: '? nt' not resolved (the engine's own text)" -Expected "||the kernel was not found in the dump" -Actual "$($kernel.Name)|$($kernel.Key)|$($kernel.Error)"
    $script:evaluateNt = "Evaluate expression: -8779370332160 = fffff803``5c600000`n"

    # The symbol cache and the download (a stub: nothing is downloaded)
    $script:logFile = Join-Path $workDir "engine-functions.log"
    ${function:Write-DbgEngWorkerLine} = { param([string]$Line) Receive-DbgEngWorkerLine -Line $Line -State $script:testWorkerState }
    $script:testWorkerState = New-DbgEngWorkerState
    $script:downloads = New-Object System.Collections.Generic.List[string]
    $script:downloadBody = "pdb"
    ${function:Save-KernelSymbolDownload} = {
        param([string]$Url, [string]$Path)
        $script:downloads.Add($Url)
        switch ($script:downloadBody) {
            "pdb" {
                $bytes = New-Object byte[] (100KB)
                [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("Microsoft C/C++ MSF 7.00`r`nGOODPDB"), $bytes, 33)
                [System.IO.File]::WriteAllBytes($Path, $bytes)
            }
            "html" { [System.IO.File]::WriteAllText($Path, "<html><body>" + ("x" * 70000) + "</body></html>") }
            "short" { [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] 10)) }
            "offline" { throw "No such host is known. (msdl.microsoft.com:443)`r`nAt line 2" }
            "raced" {
                # Another run puts the final file there first
                $bytes = New-Object byte[] (100KB)
                [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("Microsoft C/C++ MSF 7.00`r`n"), $bytes, 26)
                [System.IO.File]::WriteAllBytes($Path, $bytes)
                [System.IO.File]::WriteAllBytes(($Path -replace '\.\d+\.download$', ''), $bytes)
            }
        }
    }
    $cacheRoot = Join-Path $engineDir "symbol cache [1]"
    $cachedPdb = Join-Path $cacheRoot "ntkrnlmp.pdb\$kernelKey\ntkrnlmp.pdb"
    $expectedUrl = "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/$kernelKey/ntkrnlmp.pdb"
    $staleDownload = Join-Path $cacheRoot "ntkrnlmp.pdb\$kernelKey\ntkrnlmp.pdb.999.download"
    [void][System.IO.Directory]::CreateDirectory((Split-Path $staleDownload -Parent))
    [System.IO.File]::WriteAllText($staleDownload, "half")
    [System.IO.File]::SetLastWriteTimeUtc($staleDownload, [datetime]::UtcNow.AddDays(-2))
    $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $cacheRoot -Fallback (Join-Path $engineDir "fallback")
    $left = @(Get-ChildItem -LiteralPath (Split-Path $cachedPdb -Parent) -Filter "*.download" -Force).Count
    Assert-Equal -Name "Get-KernelSymbolFile: downloaded from the exact URL into <cache>\ntkrnlmp.pdb\<key>\ntkrnlmp.pdb, no .download left (a stale one of an earlier run deleted)" -Expected "$expectedUrl|$cachedPdb|$(Split-Path $cachedPdb -Parent)|True||0|$expectedUrl" -Actual "$($script:downloads -join ',')|$($file.Path)|$($file.Folder)|$($file.Downloaded)|$($file.Error)|$left|$($file.Url)"
    $script:downloads.Clear()
    $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $cacheRoot -Fallback (Join-Path $engineDir "fallback")
    Assert-Equal -Name "Get-KernelSymbolFile: a file in the cache is used, nothing downloaded" -Expected "0|$cachedPdb|False|" -Actual "$($script:downloads.Count)|$($file.Path)|$($file.Downloaded)|$($file.Error)"
    $badBodies = @(
        @{ Body = "html"; Error = "the server did not send a symbol [PDB] file" },
        @{ Body = "short"; Error = "the server sent 10 bytes, not a kernel symbol file" },
        @{ Body = "offline"; Error = "No such host is known. [msdl.microsoft.com:443]" }
    )
    foreach ($case in $badBodies) {
        Remove-Item -LiteralPath $cacheRoot -Recurse -Force
        $script:downloadBody = $case.Body
        $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $cacheRoot -Fallback (Join-Path $engineDir "fallback")
        $leftFiles = @(Get-ChildItem -LiteralPath $cacheRoot -Recurse -File -Force -ErrorAction SilentlyContinue).Count
        Assert-Equal -Name "Get-KernelSymbolFile, a download that fails ($($case.Body)): the short error, the kind Download, no file left" -Expected "|$($case.Error)|Download|0" -Actual "$($file.Path)|$($file.Error)|$($file.ErrorKind)|$leftFiles"
    }
    Remove-Item -LiteralPath $cacheRoot -Recurse -Force
    $script:downloadBody = "raced"
    $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $cacheRoot -Fallback (Join-Path $engineDir "fallback")
    Assert-Equal -Name "Get-KernelSymbolFile: another run's file under the final name first: kept, this run's download deleted" -Expected "$cachedPdb||1" -Actual "$($file.Path)|$($file.Error)|$(@(Get-ChildItem -LiteralPath (Split-Path $cachedPdb -Parent) -File -Force).Count)"
    $script:downloadBody = "pdb"
    $fileAsRoot = Join-Path $engineDir "cache-is-a-file"
    [System.IO.File]::WriteAllText($fileAsRoot, "x")
    $script:logFile = Join-Path $workDir "engine-fallback.log"
    $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $fileAsRoot -Fallback (Join-Path $engineDir "fallback")
    $fallbackLogged = (Get-TestLog).Contains('  tools\symbols\ cannot be written (')
    Assert-Equal -Name "Get-KernelSymbolFile: a cache that cannot be written: the work folder's fallback, and the log line" -Expected "$(Join-Path $engineDir "fallback\ntkrnlmp.pdb\$kernelKey\ntkrnlmp.pdb")|True|True|" -Actual "$($file.Path)|$($file.Downloaded)|$fallbackLogged|$($file.ErrorKind)"
    # A cache folder that can be made but not written (the download's own
    # file name taken by a folder): the work folder, not a failed download
    $lockedRoot = Join-Path $engineDir "locked cache"
    $lockedFolder = Join-Path $lockedRoot "ntkrnlmp.pdb\$kernelKey"
    [void][System.IO.Directory]::CreateDirectory((Join-Path $lockedFolder "ntkrnlmp.pdb.$PID.download"))
    $script:logFile = Join-Path $workDir "engine-locked.log"
    $script:downloads.Clear()
    $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $lockedRoot -Fallback (Join-Path $engineDir "fallback 2")
    $lockedLogged = (Get-TestLog).Contains('  tools\symbols\ cannot be written (')
    Assert-Equal -Name "Get-KernelSymbolFile: a cache folder whose files cannot be written: the work folder's fallback, the log line, one download" -Expected "$(Join-Path $engineDir "fallback 2\ntkrnlmp.pdb\$kernelKey\ntkrnlmp.pdb")|True||True|1" -Actual "$($file.Path)|$($file.Downloaded)|$($file.ErrorKind)|$lockedLogged|$($script:downloads.Count)"
    # Neither the cache nor the work folder can be written: the kind Folder,
    # nothing downloaded
    $fileAsFallback = Join-Path $engineDir "fallback-is-a-file"
    [System.IO.File]::WriteAllText($fileAsFallback, "x")
    $script:downloads.Clear()
    $file = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot $fileAsRoot -Fallback $fileAsFallback
    Assert-Equal -Name "Get-KernelSymbolFile: no folder can be written: the kind Folder, an error, nothing downloaded" -Expected "|Folder|True|0" -Actual "$($file.Path)|$($file.ErrorKind)|$([bool]$file.Error)|$($script:downloads.Count)"
    $semicolonFile = Get-KernelSymbolFile -Name "ntkrnlmp.pdb" -Key $kernelKey -CacheRoot (Join-Path $engineDir "a;b") -Fallback (Join-Path $engineDir "c;d")
    Assert-Equal -Name "Get-KernelSymbolFile: a ; in both paths: the kind Folder, said in words (the short error turns a ; into a ,)" -Expected "Folder|the work folder's path has a semicolon in it" -Actual "$($semicolonFile.ErrorKind)|$($semicolonFile.Error)"

    # The real download function, with a stand-in for Invoke-WebRequest: the
    # URL, the file, and a fixed user agent (symsrv's), so the request names
    # nothing of the analysis computer (PowerShell's own user agent has its
    # Windows and PowerShell versions and its language)
    $script:webRequest = ""
    Set-Item -LiteralPath function:Invoke-WebRequest -Value {
        [CmdletBinding()]
        param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [string]$UserAgent, [int]$TimeoutSec, [int]$MaximumRedirection)
        $script:webRequest = "$Uri|$OutFile|$UserAgent|$UseBasicParsing|$TimeoutSec|$MaximumRedirection"
    }
    try { & $realFunctions["Save-KernelSymbolDownload"] -Url $expectedUrl -Path "C:\x\ntkrnlmp.pdb.1.download" }
    finally { Remove-Item -LiteralPath function:Invoke-WebRequest }
    Assert-Equal -Name "Save-KernelSymbolDownload: the URL, the file and a fixed user agent (Microsoft-Symbol-Server/10.0.0.0)" -Expected "$expectedUrl|C:\x\ntkrnlmp.pdb.1.download|Microsoft-Symbol-Server/10.0.0.0|True|120|5" -Actual $script:webRequest

    ${function:Invoke-DbgEngCommand} = { param([string]$Command) if ($Command -eq "lm m nt") { return $script:lmOutput }; return "" }
    $script:lmOutput = "start             end                 module name`nfffff803``5c600000 fffff803``5da4f000   nt         (pdb symbols)          c:\x\ntkrnlmp.pdb`n"
    $matched = Use-KernelSymbols -Session $null -Folder "C:\x"
    $script:lmOutput = "start             end                 module name`nfffff803``5c600000 fffff803``5da4f000   nt         (export symbols)       ntkrnlmp.exe`n"
    Assert-Equal -Name "Use-KernelSymbols: '(pdb symbols)' matched, '(export symbols)' not" -Expected "True|False" -Actual "$matched|$(Use-KernelSymbols -Session $null -Folder 'C:\x')"

    # Names and command lines from the fake memory map
    Clear-TestRegions
    $userBase = [Convert]::ToUInt64("7ff600000000", 16)
    $eprocessBase = [Convert]::ToUInt64("ffffa00000000000", 16)
    # One process's PEB, ProcessParameters and command line (-Text as UTF-16,
    # -Length its UNICODE_STRING length, -Cut: only half of the text in memory)
    function Add-TestCommandLine {
        param([uint64]$EProcess, [uint64]$Peb, [string]$Text, [byte[]]$RawBytes, [int]$Length = -1, [switch]$NoParameters, [switch]$NullParameters, [switch]$NullBuffer, [switch]$Cut)
        $parameters = $Peb + [uint64]0x8000
        if ($NullParameters) { $parameters = [uint64]0 }
        Add-TestRegion -Process $EProcess -Start ($Peb + [uint64]0x20) -Bytes ([BitConverter]::GetBytes([uint64]$parameters))
        if ($NoParameters -or $NullParameters) { return }
        $buffer = $Peb + [uint64]0x9000
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
        if ($RawBytes) { $bytes = $RawBytes }
        if ($Length -lt 0) { $Length = $bytes.Length }
        $unicode = New-Object byte[] 16
        [Array]::Copy([BitConverter]::GetBytes([uint16]$Length), 0, $unicode, 0, 2)
        [Array]::Copy([BitConverter]::GetBytes([uint16][Math]::Min(65535, $Length + 2)), 0, $unicode, 2, 2)
        if (-not $NullBuffer) { [Array]::Copy([BitConverter]::GetBytes([uint64]$buffer), 0, $unicode, 8, 8) }
        Add-TestRegion -Process $EProcess -Start ($parameters + [uint64]0x70) -Bytes $unicode
        if ($Cut) { $bytes = $bytes[0..([int]($bytes.Length / 2))] }
        Add-TestRegion -Process $EProcess -Start $buffer -Bytes ([byte[]]$bytes)
    }
    $special = "cmd.exe /c ""echo a|b""`tc`r`nline2 " + [char]0x00FC + [char]0x4E2D + [char]0x20AC + " " + [char]0xD83D + [char]0xDE00
    $longText = "long.exe " + ("y" * 32758)
    $commandCases = @(
        @{ Name = "CR, LF, tab, quotes, | and non-ASCII exactly"; Text = $special; Expected = "Read|$special" },
        @{ Name = "32,767 characters"; Text = $longText; Expected = "Read|$longText" },
        @{ Name = "cut at the first NUL"; Text = ("nul.exe before" + [char]0 + "after"); Expected = "Read|nul.exe before" },
        @{ Name = "an odd length rounded down"; Text = "odd.exe 12345"; Len = 11; Expected = "Read|odd.e" },
        @{ Name = "an unpaired surrogate as U+FFFD"; Text = "-"; Raw = [byte[]](0x78, 0, 0, 0xD8, 0x79, 0); Expected = "Read|x$([char]0xFFFD)y" },
        @{ Name = "length 0"; Text = ""; Len = 0; Expected = "Empty|" },
        @{ Name = "only NULs"; Text = ([string][char]0 * 3); Expected = "Empty|" },
        @{ Name = "no ProcessParameters in memory"; Text = "x"; NoParameters = $true; Expected = "Unreadable|" },
        @{ Name = "a null ProcessParameters"; Text = "x"; NullParameters = $true; Expected = "Unreadable|" },
        @{ Name = "a null buffer"; Text = "abc"; NullBuffer = $true; Expected = "Unreadable|" },
        @{ Name = "half of the buffer in memory"; Text = "partial.exe abcdefghijklmnop"; Cut = $true; Expected = "Unreadable|" }
    )
    $caseNumber = 0
    foreach ($case in $commandCases) {
        $caseNumber++
        $eprocess = $eprocessBase + [uint64]($caseNumber * 0x1000)
        $peb = $userBase + [uint64]($caseNumber * 0x100000)
        $length = -1
        if ($null -ne $case.Len) { $length = $case.Len }
        Add-TestCommandLine -EProcess $eprocess -Peb $peb -Text $case.Text -RawBytes $case.Raw -Length $length -NoParameters:([bool]$case.NoParameters) -NullParameters:([bool]$case.NullParameters) -NullBuffer:([bool]$case.NullBuffer) -Cut:([bool]$case.Cut)
        $commandLine = Read-DbgEngCommandLine -Session $null -Process $eprocess -Peb $peb
        Assert-Equal -Name "Read-DbgEngCommandLine: $($case.Name)" -Expected $case.Expected -Actual "$($commandLine.State)|$($commandLine.Text)"
    }
    $commandLine = Read-DbgEngCommandLine -Session $null -Process ($eprocessBase + [uint64]0x99000) -Peb 0
    $otherSpace = Read-DbgEngCommandLine -Session $null -Process ($eprocessBase + [uint64]0x98000) -Peb ($userBase + [uint64]0x100000)
    Assert-Equal -Name "Read-DbgEngCommandLine: no PEB (a kernel process); the PEB of another process's address space is not read" -Expected "NoPeb|Unreadable" -Actual "$($commandLine.State)|$($otherSpace.State)"
    $nameCases = @(
        @{ Name = "up to the first NUL"; Bytes = ([System.Text.Encoding]::ASCII.GetBytes("smss.exe") + (New-Object byte[] 7)); Expected = "smss.exe" },
        @{ Name = "all 15 bytes, no NUL"; Bytes = [System.Text.Encoding]::ASCII.GetBytes("SearchProtocolHost.exe"); Expected = "SearchProtocolH" },
        @{ Name = "an invalid UTF-8 byte as U+FFFD"; Bytes = [byte[]](0x63, 0x61, 0x66, 0xE9, 0x2E, 0x65, 0x78, 0x65, 0); Expected = "caf$([char]0xFFFD).exe" },
        @{ Name = "a name with spaces"; Bytes = ([System.Text.Encoding]::ASCII.GetBytes("My App.exe") + (New-Object byte[] 5)); Expected = "My App.exe" }
    )
    $caseNumber = 0
    foreach ($case in $nameCases) {
        $caseNumber++
        $address = $eprocessBase + [uint64](0x500000 + $caseNumber * 0x1000)
        Add-TestRegion -Process 0 -Start $address -Bytes ([byte[]]$case.Bytes)
        Assert-Equal -Name "Read-DbgEngImageFileName: $($case.Name)" -Expected $case.Expected -Actual (Read-DbgEngImageFileName -Session $null -Address $address)
    }
    Assert-Equal -Name "Read-DbgEngImageFileName: not in memory, or a null address: empty" -Expected "|" -Actual "$(Read-DbgEngImageFileName -Session $null -Address ($eprocessBase + [uint64]0x900000))|$(Read-DbgEngImageFileName -Session $null -Address 0)"
    $fileTimeCases = @(0, -1, ([datetime]::MaxValue.ToFileTimeUtc() + 1), ([datetime]::new(2026, 10, 10, 6, 0, 1, [DateTimeKind]::Utc).AddTicks(2345678).ToFileTimeUtc()))
    Assert-Equal -Name "ConvertFrom-DbgEngFileTime: 0 and negative give no time, past 9999 the number, else ISO 8601 UTC with 7 decimals" -Expected "<null>|<null>|$([datetime]::MaxValue.ToFileTimeUtc() + 1)|2026-10-10T06:00:01.2345678+00:00" -Actual ((@($fileTimeCases | ForEach-Object { $value = ConvertFrom-DbgEngFileTime $_; if ($null -eq $value) { "<null>" } else { $value } })) -join "|")
    $shortCases = @(
        @("a; b", "a, b"), @("a: b -- c", "a - b - c"), @("x (y)", "x [y]"), @("first line.`r`nsecond line", "first line"), @("`r`n  `r`nafter blank lines", "after blank lines"), @(("z" * 130), (("z" * 117) + "..."))
    )
    Assert-Equal -Name "Get-DbgEngShortError: no ';', ': ', ' -- ' or parentheses, the first line, at most 120 characters" -Expected (($shortCases | ForEach-Object { $_[1] }) -join "|") -Actual (($shortCases | ForEach-Object { Get-DbgEngShortError $_[0] }) -join "|")
    . $restoreTestFunctions

    # --- A whole analysis on a fake kernel -------------------------------------
    # 146 processes and the idle process, twice over: in a fake kernel for the
    # helper's own scan (an EPROCESS each at the offsets of a canned
    # "dt -v nt!_EPROCESS", the process list through ActiveProcessLinks, a
    # level-1 process ID table with threads among the processes, tokens and
    # session spaces), and as canned dx output for the debugger engine's own
    # list (two pages with two bad items, a duplicate and the idle process;
    # one session id unreadable), used when the symbols do not describe the
    # process structure. The helper's result goes through the builder's
    # protocol reader (Receive-DbgEngWorkerLine) into Add-MemoryPluginRows,
    # in this process.
    $boot = [datetime]::new(2026, 10, 10, 6, 0, 0, [DateTimeKind]::Utc)
    $capture = [datetime]::new(2026, 10, 11, 0, 9, 0, [DateTimeKind]::Utc)
    $acquisitionEnd = $capture.AddMinutes(2)
    Clear-TestRegions
    Add-TestRegion -Process 0 -Start $kernelBase -Bytes (New-TestKernelImage)
    # The fake kernel: the layout of Windows 11 24H2 on ARM64 (no
    # _MM_SESSION_SPACE in its symbols), and where its structures are
    $fakeOffsets = @{ UniqueProcessId = 0x1c0; ActiveProcessLinks = 0x1c8; CreateTime = 0x1e8; Token = 0x238; InheritedFromUniqueProcessId = 0x2c0; Peb = 0x2d0; Session = 0x2d8; ImageFileName = 0x328; ActiveThreads = 0x370; ExitTime = 0x680 }
    $dtProcess = @(
        "struct _EPROCESS, 261 elements, 0x900 bytes",
        "   +0x000 Pcb              : struct _KPROCESS, 63 elements, 0x1b8 bytes",
        "   +0x1b8 ProcessLock      : struct _EX_PUSH_LOCK, 7 elements, 0x8 bytes",
        "   +0x1c0 UniqueProcessId  : Ptr64 to Void",
        "   +0x1c8 ActiveProcessLinks : struct _LIST_ENTRY, 2 elements, 0x10 bytes",
        "   +0x1e8 CreateTime       : union _LARGE_INTEGER, 4 elements, 0x8 bytes",
        "   +0x238 Token            : struct _EX_FAST_REF, 3 elements, 0x8 bytes",
        "   +0x2c0 InheritedFromUniqueProcessId : Ptr64 to Void",
        "   +0x2d0 Peb              : Ptr64 to struct _PEB, 124 elements, 0x7d8 bytes",
        "   +0x2d8 Session          : Ptr64 to struct _PSP_SESSION_SPACE, 0 elements, 0x0 bytes",
        "   +0x328 ImageFileName    : [15] UChar",
        "   +0x370 ActiveThreads    : Uint4B",
        "   +0x680 ExitTime         : union _LARGE_INTEGER, 4 elements, 0x8 bytes",
        "   +0x698 ActiveThreadsHighWatermark : Uint4B"
    ) -join "`n"
    $script:dtDefault = @{
        "_EPROCESS" = $dtProcess
        "_TOKEN" = "struct _TOKEN, 55 elements, 0x5c8 bytes`n   +0x000 TokenSource      : struct _TOKEN_SOURCE, 2 elements, 0x10 bytes`n   +0x078 SessionId        : Uint4B`n"
        "_EX_FAST_REF" = "struct _EX_FAST_REF, 3 elements, 0x8 bytes`n   +0x000 Object           : Ptr64 to Void`n   +0x000 RefCnt           : Bitfield Pos 0, 4 Bits`n   +0x000 Value            : Uint8B`n"
        "_HANDLE_TABLE" = "struct _HANDLE_TABLE, 17 elements, 0x80 bytes`n   +0x000 NextHandleNeedingPool : Uint4B`n   +0x008 TableCode        : Uint8B`n"
        "_HANDLE_TABLE_ENTRY" = "union _HANDLE_TABLE_ENTRY, 15 elements, 0x10 bytes`n   +0x000 VolatileLowValue : Int8B`n   +0x000 LowValue         : Int8B`n   +0x000 Unlocked         : Bitfield Pos 0, 1 Bit`n   +0x000 RefCnt           : Bitfield Pos 1, 16 Bits`n   +0x000 Attributes       : Bitfield Pos 17, 3 Bits`n   +0x000 ObjectPointerBits : Bitfield Pos 20, 44 Bits`n   +0x008 GrantedAccessBits : Bitfield Pos 0, 25 Bits`n"
    }
    $script:dtText = $script:dtDefault
    $listHead = $kernelBase + [uint64]0x200000
    $cidVariable = $kernelBase + [uint64]0x200100
    $handleTable = [Convert]::ToUInt64("ffffa10000000000", 16)
    $cidTop = [Convert]::ToUInt64("ffffa10000010000", 16)
    $cidLeafBase = [Convert]::ToUInt64("ffffa10000100000", 16)
    $tokenBase = [Convert]::ToUInt64("ffffa20000000000", 16)
    $spaceBase = [Convert]::ToUInt64("ffffa30000000000", 16)
    $threadBase = [Convert]::ToUInt64("ffffa40000000000", 16)
    function Set-TestUInt64 {
        param([byte[]]$Bytes, [int]$Offset, [uint64]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 8)
    }
    function Get-TestLinkAddress { param([int]$Index) return ($eprocessBase + [uint64]($Index * 0x1000) + [uint64]$fakeOffsets.ActiveProcessLinks) }
    # "? <symbol>" as the engine answers it
    function Format-TestEvaluate {
        param([uint64]$Address)
        $hex = $Address.ToString("x16")
        return "Evaluate expression: -1 = " + $hex.Substring(0, 8) + [char]0x60 + $hex.Substring(8) + "`n"
    }
    $script:listHeadBytes = New-Object byte[] 16
    Add-TestRegion -Process 0 -Start $listHead -Bytes $script:listHeadBytes
    $cidPointer = New-Object byte[] 8
    Set-TestUInt64 -Bytes $cidPointer -Offset 0 -Value $handleTable
    Add-TestRegion -Process 0 -Start $cidVariable -Bytes $cidPointer
    $tableBytes = New-Object byte[] 0x80
    Set-TestUInt64 -Bytes $tableBytes -Offset 8 -Value ($cidTop -bor [uint64]1)
    Add-TestRegion -Process 0 -Start $handleTable -Bytes $tableBytes
    $script:cidTopBytes = New-Object byte[] 4096
    Add-TestRegion -Process 0 -Start $cidTop -Bytes $script:cidTopBytes
    $script:cidLeaves = @{}
    $script:blocks = @{}
    $procs = New-Object System.Collections.Generic.List[object]
    # One process: its EPROCESS (dispatcher type 3, its fields), its token
    # (the session id; -NoToken: not in the dump) and session space (id + 2,
    # read only when the symbols have _MM_SESSION_SPACE; -NoSpace: not in the
    # dump; -Session -1: none, EPROCESS.Session 0), its command line, and its
    # dx line for the engine's own list
    function New-TestProcess {
        param([int]$Index, [long]$ProcId, [long]$ParentId, $Create, $Exit, [int]$Threads, $Name, [string]$CommandLine, [switch]$NoPeb, [switch]$NoParameters, [switch]$Cut, [int]$Length = -1, [long]$Session = 1, [switch]$NoToken, [switch]$NoSpace)
        $eprocess = $eprocessBase + [uint64]($Index * 0x1000)
        $nameAddress = $eprocess + [uint64]$fakeOffsets.ImageFileName
        $nameBytes = if ($Name -is [byte[]]) { $Name } else { [System.Text.Encoding]::ASCII.GetBytes($Name) }
        $block = New-Object byte[] 0x900
        $block[0] = 3
        [Array]::Copy($nameBytes, 0, $block, $fakeOffsets.ImageFileName, [Math]::Min(15, $nameBytes.Length))
        $peb = [uint64]0
        if (-not $NoPeb) {
            $peb = $userBase + [uint64]($Index * 0x100000)
            Add-TestCommandLine -EProcess $eprocess -Peb $peb -Text $CommandLine -Length $Length -NoParameters:$NoParameters -Cut:$Cut
        }
        $createTime = if ($Create -is [datetime]) { $Create.ToFileTimeUtc() } else { [long]$Create }
        $exitTime = if ($Exit -is [datetime]) { $Exit.ToFileTimeUtc() } else { [long]$Exit }
        Set-TestUInt64 -Bytes $block -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]$ProcId)
        Set-TestUInt64 -Bytes $block -Offset $fakeOffsets.InheritedFromUniqueProcessId -Value ([uint64]$ParentId)
        [Array]::Copy([BitConverter]::GetBytes([long]$createTime), 0, $block, $fakeOffsets.CreateTime, 8)
        [Array]::Copy([BitConverter]::GetBytes([long]$exitTime), 0, $block, $fakeOffsets.ExitTime, 8)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$Threads), 0, $block, $fakeOffsets.ActiveThreads, 4)
        Set-TestUInt64 -Bytes $block -Offset $fakeOffsets.Peb -Value $peb
        if ($Session -ge 0) {
            $space = $spaceBase + [uint64]($Index * 0x100)
            Set-TestUInt64 -Bytes $block -Offset $fakeOffsets.Session -Value $space
            if (-not $NoSpace) {
                $spaceBytes = New-Object byte[] 16
                [Array]::Copy([BitConverter]::GetBytes([uint32]($Session + 2)), 0, $spaceBytes, 8, 4)
                Add-TestRegion -Process 0 -Start $space -Bytes $spaceBytes
            }
        }
        # The token pointer with a reference count in its low bits
        $token = $tokenBase + [uint64]($Index * 0x100)
        Set-TestUInt64 -Bytes $block -Offset $fakeOffsets.Token -Value ($token -bor [uint64]7)
        if (-not $NoToken) {
            $tokenBytes = New-Object byte[] 0x80
            [Array]::Copy([BitConverter]::GetBytes([uint32][Math]::Max(0, $Session)), 0, $tokenBytes, 0x78, 4)
            Add-TestRegion -Process 0 -Start $token -Bytes $tokenBytes
        }
        Add-TestRegion -Process 0 -Start $eprocess -Bytes $block
        $script:blocks[$Index] = $block
        $procs.Add([PSCustomObject]@{ Index = $Index; E = $eprocess; ProcId = $ProcId; Line = "TBP|0x$($eprocess.ToString('x'))|$ProcId|$ParentId|$createTime|$exitTime|$Threads|0x$($peb.ToString('x'))|0x$($nameAddress.ToString('x'))"; Session = $Session })
    }
    # The links of one entry of the process list
    function Set-TestLinks {
        param([int]$Index, [uint64]$Flink, [uint64]$Blink)
        Set-TestUInt64 -Bytes $script:blocks[$Index] -Offset $fakeOffsets.ActiveProcessLinks -Value $Flink
        Set-TestUInt64 -Bytes $script:blocks[$Index] -Offset ($fakeOffsets.ActiveProcessLinks + 8) -Value $Blink
    }
    # The process list in this order (indexes of the processes), every link consistent
    function Set-TestProcessList {
        param([int[]]$Order)
        for ($n = 0; $n -lt $Order.Count; $n++) {
            $previous = if ($n -eq 0) { $listHead } else { Get-TestLinkAddress $Order[$n - 1] }
            $next = if ($n -eq $Order.Count - 1) { $listHead } else { Get-TestLinkAddress $Order[$n + 1] }
            Set-TestLinks -Index $Order[$n] -Flink $next -Blink $previous
        }
        Set-TestUInt64 -Bytes $script:listHeadBytes -Offset 0 -Value (Get-TestLinkAddress $Order[0])
        Set-TestUInt64 -Bytes $script:listHeadBytes -Offset 8 -Value (Get-TestLinkAddress $Order[-1])
    }
    # The process ID table: @(id, object address) for each entry; the pages
    # of entries are made as they are needed and emptied first
    function Set-TestCidTable {
        param([object[]]$Entries)
        foreach ($leaf in @($script:cidLeaves.Values)) { [Array]::Clear($leaf, 0, $leaf.Length) }
        $pointerMask = [uint64](([uint64]1 -shl 44) - [uint64]1)
        foreach ($entry in $Entries) {
            $slot = [int][Math]::Floor([long]$entry[0] / 4)
            $page = [int][Math]::Floor($slot / 256)
            if (-not $script:cidLeaves.ContainsKey($page)) {
                $leafBytes = New-Object byte[] 4096
                $leafAddress = $cidLeafBase + [uint64]($page * 0x1000)
                Add-TestRegion -Process 0 -Start $leafAddress -Bytes $leafBytes
                Set-TestUInt64 -Bytes $script:cidTopBytes -Offset ($page * 8) -Value $leafAddress
                $script:cidLeaves[$page] = $leafBytes
            }
            # ObjectPointerBits at bit 20, the Unlocked bit set
            $low = (((([uint64]$entry[1]) -shr 4) -band $pointerMask) -shl 20) -bor [uint64]1
            Set-TestUInt64 -Bytes $script:cidLeaves[$page] -Offset (($slot % 256) * 16) -Value $low
        }
    }
    New-TestProcess -Index 0 -ProcId 4 -ParentId 0 -Create $boot -Exit 0 -Threads 150 -Name "System" -CommandLine "" -NoPeb -Session -1
    New-TestProcess -Index 1 -ProcId 92 -ParentId 4 -Create $boot -Exit 0 -Threads 4 -Name "Registry" -CommandLine "" -NoPeb -Session -1
    New-TestProcess -Index 2 -ProcId 404 -ParentId 4 -Create $boot.AddTicks(12345678) -Exit 0 -Threads 2 -Name "smss.exe" -CommandLine "\SystemRoot\System32\smss.exe" -Session -1
    New-TestProcess -Index 3 -ProcId 5000 -ParentId 4000 -Create $capture.AddMinutes(-30) -Exit 0 -Threads 7 -Name "My App.exe" -CommandLine '"C:\Program Files\My App\My App.exe" --flag'
    New-TestProcess -Index 4 -ProcId 5004 -ParentId 4000 -Create $capture.AddMinutes(-29) -Exit 0 -Threads 7 -Name "SearchProtocolHost.exe" -CommandLine "SearchProtocolHost.exe x"
    New-TestProcess -Index 5 -ProcId 5008 -ParentId 4000 -Create $capture.AddMinutes(-28) -Exit 0 -Threads 1 -Name ([byte[]](0x63, 0x61, 0x66, 0xE9, 0x2E, 0x65, 0x78, 0x65)) -CommandLine "cafe.exe"
    New-TestProcess -Index 6 -ProcId 5012 -ParentId 4000 -Create $capture.AddMinutes(-27) -Exit $capture.AddMinutes(-26) -Threads 0 -Name "exited.exe" -CommandLine "x" -NoParameters
    New-TestProcess -Index 7 -ProcId 5016 -ParentId 4000 -Create 0 -Exit 0 -Threads 1 -Name "notime.exe" -CommandLine "notime.exe"
    New-TestProcess -Index 8 -ProcId 5020 -ParentId 4000 -Create $acquisitionEnd.AddDays(1).AddSeconds(1) -Exit 0 -Threads 1 -Name "future.exe" -CommandLine "future.exe"
    New-TestProcess -Index 9 -ProcId 5024 -ParentId 4000 -Create $capture.AddMinutes(-20) -Exit 0 -Threads 3 -Name "cmd.exe" -CommandLine $special
    New-TestProcess -Index 10 -ProcId 5028 -ParentId 4000 -Create $capture.AddMinutes(-19) -Exit 0 -Threads 3 -Name "long.exe" -CommandLine $longText
    New-TestProcess -Index 11 -ProcId 5032 -ParentId 4000 -Create $capture.AddMinutes(-18) -Exit 0 -Threads 3 -Name "nul.exe" -CommandLine ("nul.exe before" + [char]0 + "after")
    New-TestProcess -Index 12 -ProcId 5036 -ParentId 4000 -Create $capture.AddMinutes(-17) -Exit 0 -Threads 3 -Name "odd.exe" -CommandLine "odd.exe 12345" -Length 11
    New-TestProcess -Index 13 -ProcId 5040 -ParentId 4000 -Create $capture.AddMinutes(-16) -Exit 0 -Threads 3 -Name "empty.exe" -CommandLine "" -Length 0
    New-TestProcess -Index 14 -ProcId 5044 -ParentId 4000 -Create $capture.AddMinutes(-15) -Exit 0 -Threads 3 -Name "partial.exe" -CommandLine "partial.exe abcdefghijklmnop" -Cut
    New-TestProcess -Index 15 -ProcId 5048 -ParentId 4000 -Create $capture.AddMinutes(-14) -Exit 0 -Threads 3 -Name "services.exe" -CommandLine "C:\Windows\system32\services.exe" -Session 0
    for ($i = 16; $i -lt 146; $i++) {
        # proc20: its token is not in the dump (its session id unreadable);
        # proc21: its session space is not in the dump
        New-TestProcess -Index $i -ProcId (6000 + 4 * $i) -ParentId 4000 -Create $capture.AddMinutes(-10) -Exit 0 -Threads 2 -Name "proc$i.exe" -CommandLine "C:\Windows\proc$i.exe /x" -NoToken:($i -eq 20) -NoSpace:($i -eq 21)
    }
    # The idle process: as in a real kernel, in neither the process list
    # nor the process ID table (only the engine's own dx list has it)
    New-TestProcess -Index 146 -ProcId 0 -ParentId 0 -Create 0 -Exit 0 -Threads 4 -Name "Idle" -CommandLine "" -NoPeb
    # Not in the process list by default: a process that ended during the
    # copy (gone.exe), one that was being created after the capture started
    # (new.exe), one that is hidden (hidden.exe: created hours before the
    # capture, no exit time, its links point to itself), memory of a process
    # that was reused (dispatcher type 28, a link to 0x10001), and memory
    # that only starts like a process (type 3, links that are no kernel
    # addresses)
    New-TestProcess -Index 150 -ProcId 7000 -ParentId 4000 -Create $capture.AddMinutes(-5) -Exit $capture.AddMinutes(-4) -Threads 0 -Name "gone.exe" -CommandLine "x" -NoParameters
    New-TestProcess -Index 152 -ProcId 7100 -ParentId 4000 -Create $capture.AddSeconds(30) -Exit 0 -Threads 1 -Name "new.exe" -CommandLine "new.exe /n"
    New-TestProcess -Index 153 -ProcId 7300 -ParentId 4000 -Create $capture.AddHours(-3) -Exit 0 -Threads 5 -Name "hidden.exe" -CommandLine "hidden.exe -q"
    # Capture churn (the shape of a real dump of a computer busy with
    # short-lived processes): processes that only the process ID table has,
    # under the ID of a process that is not in the dump, created 20 s after
    # the capture started (churn1.exe), 0.78 s and 90 s before it
    # (churn2.exe, loop.exe: within the 120-second churn margin) and 125 s
    # before it (early.exe, outside it: judged); their links point to
    # themselves
    New-TestProcess -Index 155 -ProcId 7400 -ParentId 4000 -Create $capture.AddSeconds(20) -Exit 0 -Threads 4 -Name "churn1.exe" -CommandLine "churn1.exe 1"
    New-TestProcess -Index 156 -ProcId 7404 -ParentId 4000 -Create $capture.AddMilliseconds(-780) -Exit 0 -Threads 4 -Name "churn2.exe" -CommandLine "churn2.exe 2"
    New-TestProcess -Index 157 -ProcId 7408 -ParentId 4000 -Create $capture.AddSeconds(-125) -Exit 0 -Threads 4 -Name "early.exe" -CommandLine "early.exe 3"
    New-TestProcess -Index 158 -ProcId 7412 -ParentId 4000 -Create $capture.AddSeconds(-90) -Exit 0 -Threads 4 -Name "loop.exe" -CommandLine "loop.exe 4"
    $reused = New-Object byte[] 0x900
    $reused[0] = 28
    Set-TestUInt64 -Bytes $reused -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]0x123456789)
    Set-TestUInt64 -Bytes $reused -Offset $fakeOffsets.ActiveProcessLinks -Value ([uint64]0x10001)
    $reusedAddress = $eprocessBase + [uint64](151 * 0x1000)
    Add-TestRegion -Process 0 -Start $reusedAddress -Bytes $reused
    $partlyProcess = New-Object byte[] 0x900
    $partlyProcess[0] = 3
    Set-TestUInt64 -Bytes $partlyProcess -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]0x10001)
    Set-TestUInt64 -Bytes $partlyProcess -Offset $fakeOffsets.ActiveProcessLinks -Value ([uint64]0x10001)
    $partlyAddress = $eprocessBase + [uint64](154 * 0x1000)
    Add-TestRegion -Process 0 -Start $partlyAddress -Bytes $partlyProcess
    # Threads (dispatcher type 6) at IDs between the processes'
    $threadEntries = foreach ($threadId in @(8, 12, 16, 20, 4100, 4104)) {
        $thread = New-Object byte[] 16
        $thread[0] = 6
        $threadAddress = $threadBase + [uint64]($threadId * 0x10)
        Add-TestRegion -Process 0 -Start $threadAddress -Bytes $thread
        , @($threadId, $threadAddress)
    }
    foreach ($selfLinked in @(153, 155, 156, 157, 158)) { Set-TestLinks -Index $selfLinked -Flink (Get-TestLinkAddress $selfLinked) -Blink (Get-TestLinkAddress $selfLinked) }
    $defaultOrder = [int[]](0..145)
    # Every process at its ID, and the threads
    $defaultCid = @($procs | Where-Object { $_.Index -le 145 -and $_.ProcId -gt 0 } | ForEach-Object { , @($_.ProcId, $_.E) }) + @($threadEntries)
    function Reset-TestKernel {
        Set-TestProcessList -Order $defaultOrder
        Set-TestCidTable -Entries $defaultCid
        $script:dtText = $script:dtDefault
        $script:engineCountText = "@`$cursession.Processes.Where(p => p.Id != 0).Count() : 0x92`n"
        $script:dxWarning = ""
        $script:headSymbol = $listHead
        $script:cidSymbol = $cidVariable
        # The process IDs of the default processes, as New-TestProcess wrote them
        foreach ($p in $procs) { Set-TestUInt64 -Bytes $script:blocks[$p.Index] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]$p.ProcId) }
    }
    Reset-TestKernel
    function Format-TestItems { param([string[]]$Lines) return (@(for ($i = 0; $i -lt $Lines.Count; $i++) { "    [0x$($i.ToString('x'))]          : $($Lines[$i])" }) -join "`n") }
    $script:processPage1 = @($procs[0..97] | ForEach-Object { $_.Line }) + @("Unable to read memory at Address 0xffffa00000099000", "TBP|zz|1")
    $script:processPage2 = @($procs[98..146] | ForEach-Object { $_.Line }) + @($procs[2].Line)
    $script:sessionLines = @($procs[0..145] | ForEach-Object { "TBS|0x$($_.E.ToString('x'))|$($_.Session)" })
    $script:sessionLines[20] = "Unable to read memory at Address 0x10"
    $defaultSessionLines = $script:sessionLines
    $script:tokenLines = @($procs[0..145] | ForEach-Object { "TBS|0x$($_.E.ToString('x'))|$($_.Session)" })
    $script:tokenLines[20] = "Unable to read memory at Address 0x78"
    $script:processQueryText = ""
    $script:sessionQueryText = ""
    $script:engineCommands = New-Object System.Collections.Generic.List[string]
    ${function:Open-DbgEngSession} = {
        param([string]$EngineFolder, [string[]]$EngineDlls, [string]$DumpPath, [string]$SymbolFolder, [string]$ExtensionFolder)
        $script:opened++
        $script:openedWith = "$EngineFolder|$($EngineDlls -join ',')|$DumpPath|$(Test-Path -LiteralPath $SymbolFolder)|$(Test-Path -LiteralPath $ExtensionFolder)"
        return [PSCustomObject]@{ Fake = $true }
    }
    ${function:Close-DbgEngSession} = { param($Session) if ($Session) { $script:closed++ } }
    ${function:Read-DbgEngVirtual} = $stubReadVirtual
    ${function:Invoke-DbgEngCommand} = {
        param([string]$Command)
        $script:engineCommands.Add($Command)
        if ($Command -eq "? nt") { return $script:evaluateNt }
        if ($Command -like ".sympath *") { $script:symbolFolder = $Command.Substring(9).Trim('"'); $script:symbolsLoaded = $false; return "Symbol search path is: x`n" }
        if ($Command -eq ".reload /f nt") { $script:symbolsLoaded = $true; return "" }
        if ($Command -eq "lm m nt") {
            # (pdb symbols) only for a symbol file the stub download wrote
            $pdb = Join-Path $script:symbolFolder "ntkrnlmp.pdb"
            $good = $script:symbolsLoaded -and (Test-Path -LiteralPath $pdb) -and [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($pdb)).Contains("GOODPDB")
            $kind = if ($good) { "(pdb symbols)          $pdb" } else { "(export symbols)       ntkrnlmp.exe" }
            return "start             end                 module name`nfffff803``5c600000 fffff803``5da4f000   nt         $kind`n"
        }
        if ($Command -match '^dt -v nt!(\w+)$') {
            if ($script:dtText.ContainsKey($Matches[1])) { return $script:dtText[$Matches[1]] }
            return "Symbol nt!$($Matches[1]) not found.`n"
        }
        if ($Command -eq "? nt!PsActiveProcessHead") { return (Format-TestEvaluate $script:headSymbol) }
        if ($Command -eq "? nt!PspCidTable") { return (Format-TestEvaluate $script:cidSymbol) }
        if ($Command -eq 'dx @$cursession.Processes.Where(p => p.Id != 0).Count()') { return $script:engineCountText }
        if ($Command -match '^dx -r1 @\$cursession\.Processes\.Skip\((\d+)\)\.Take\(100\)\.Select\(p => "(TB[PS])\|') {
            $skip = [int]$Matches[1]
            $tag = $Matches[2]
            $echo = $Command.Substring(7)
            if ($tag -eq "TBP") {
                if ($script:processQueryText) { return $script:processQueryText }
                $lines = if ($skip -eq 0) { $script:processPage1 } elseif ($skip -eq 100) { $script:processPage2 } else { @() }
            }
            elseif ($Command.Contains("_TOKEN")) { $lines = @($script:tokenLines | Select-Object -Skip $skip -First 100) }
            else {
                if ($script:sessionQueryText) { return $script:sessionQueryText }
                $lines = @($script:sessionLines | Select-Object -Skip $skip -First 100)
            }
            return "$($script:dxWarning)$echo`n" + (Format-TestItems $lines) + "`n"
        }
        throw "unexpected command $Command"
    }
    ${function:Find-DbgEngine} = { return [PSCustomObject]@{ Path = "C:\stub\dbgeng.dll"; Folder = "C:\stub"; Source = "Windows"; Version = "10.0.26100.1"; Dlls = @("dbgeng.dll"); Warning = ""; Reason = "" } }
    ${function:Get-DbgEngWorkerPath} = { return $workerPath }
    # The helper's work in this process: its result as protocol lines, read
    # back by the builder's reader
    ${function:Start-DbgEngWorker} = {
        param([System.Collections.IDictionary]$Arguments)
        $script:testWorkerState = New-DbgEngWorkerState
        $script:workerArguments = $Arguments
        $workerResult = Read-DbgEngDump -DumpPath $Arguments["DumpPath"] -EngineFolder $Arguments["EngineFolder"] -EngineDlls @("$($Arguments['EngineDlls'])" -split ',') -SymbolCache $Arguments["SymbolCache"] -JobFolder $Arguments["JobFolder"] -CaptureStart $Arguments["CaptureStart"] -CaptureEnd $Arguments["CaptureEnd"]
        Write-DbgEngWorkerResult $workerResult
        $script:testWorkerState.ExitCode = 0
        return $script:testWorkerState
    }
    ${function:Write-DbgEngWorkerLine} = { param([string]$Line) Receive-DbgEngWorkerLine -Line $Line -State $script:testWorkerState }
    ${function:Save-KernelSymbolDownload} = {
        param([string]$Url, [string]$Path)
        $script:downloads.Add($Url)
        if ($script:offline) { throw "No such host is known. (msdl.microsoft.com:443)" }
        $bytes = New-Object byte[] (100KB)
        # -not GOODPDB: a symbol file the engine does not accept
        $text = if ($script:notAccepted) { "Microsoft C/C++ MSF 7.00`r`nOTHERPDB" } else { "Microsoft C/C++ MSF 7.00`r`nGOODPDB" }
        [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes($text), $bytes, $text.Length)
        [System.IO.File]::WriteAllBytes($Path, $bytes)
    }
    $engineDump = "D:\Cases\Fall $([char]0x00E9) [2]\TriageCollection_2026-10-11_00-08_memory_dump.dmp"
    $engineDumpInfo = [PSCustomObject]@{ CaptureTimeUtc = $capture; LastWriteUtc = $acquisitionEnd; Architecture = "ARM64"; TimeSource = "crash dump header" }
    # One analysis: the rows ("Source|Timestamp|EventType|Description|User|
    # Details"), the result, the log (its file too) and what was opened,
    # closed, downloaded
    function Invoke-TestEngineRun {
        $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
        $script:logFile = Join-Path $workDir ("engine-" + [guid]::NewGuid().ToString("N") + ".log")
        $script:opened = 0
        $script:closed = 0
        $script:downloads.Clear()
        $script:engineCommands.Clear()
        $analysis = Invoke-DbgEngMemoryAnalysis -DumpPath $engineDump -DumpInfo $engineDumpInfo
        return [PSCustomObject]@{
            Result = $analysis; Log = ((Get-TestLog) -replace '(?m)^\[[0-9: -]+\] ', ''); LogFile = $script:logFile; Opened = $script:opened; Closed = $script:closed; Downloads = $script:downloads.Count
            Rows = @($script:timelineEntries | ForEach-Object { "$($_.Source)|$($_.Timestamp)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)" })
            Entries = @($script:timelineEntries)
            JobLeft = (Test-Path -LiteralPath (Join-Path $script:runScratchDir "dbgeng"))
        }
    }
    # The rows of a run, sorted (the scan and the engine's list give them in
    # different orders); -Plain: without the scan's FoundBy= (which ways
    # found each process; the engine's own list does not say)
    function Get-TestSortedRows {
        param($Run, [switch]$Plain)
        $rows = @($Run.Rows)
        if ($Plain) { $rows = @($rows | ForEach-Object { $_ -replace ' FoundBy=\S+', '' }) }
        return (($rows | Sort-Object) -join "`n")
    }
    $symbolRoot = Join-Path $script:testToolsFolder "symbols"
    Remove-Item -LiteralPath $symbolRoot -Recurse -Force -ErrorAction SilentlyContinue
    $script:offline = $false
    $run = Invoke-TestEngineRun
    $captureRowTime = "2026-10-11 00:09:00.000"
    $allWays = "ListForward,ListBackward,ProcessIdTable"
    $expectedRows = @(
        "Memory-Processes|2026-10-10 06:00:00.000|ProcessCreation|Process in memory: System (PID: 4, PPID: 0)||Threads=150 SessionId= FoundBy=$allWays",
        "Memory-Processes|2026-10-10 06:00:00.000|ProcessCreation|Process in memory: Registry (PID: 92, PPID: 4)||Threads=4 SessionId= FoundBy=$allWays",
        "Memory-Processes|2026-10-10 06:00:01.234|ProcessCreation|Process in memory: smss.exe (PID: 404, PPID: 4)||Threads=2 SessionId= FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:39:00.000|ProcessCreation|Process in memory: My App.exe (PID: 5000, PPID: 4000)||Threads=7 SessionId=1 FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:40:00.000|ProcessCreation|Process in memory: SearchProtocolH (PID: 5004, PPID: 4000)||Threads=7 SessionId=1 FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:41:00.000|ProcessCreation|Process in memory: caf$([char]0xFFFD).exe (PID: 5008, PPID: 4000)||Threads=1 SessionId=1 FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:42:00.000|ProcessCreation|Process in memory: exited.exe (PID: 5012, PPID: 4000)||Threads=0 SessionId=1 FoundBy=$allWays",
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: notime.exe (PID: 5016, PPID: 4000)||Threads=1 SessionId=1 FoundBy=$allWays",
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: future.exe (PID: 5020, PPID: 4000)||Threads=1 SessionId=1 CreateTime=2026-10-12 00:11:01.000 FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:55:00.000|ProcessCreation|Process in memory: services.exe (PID: 5048, PPID: 4000)||Threads=3 SessionId=0 FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:59:00.000|ProcessCreation|Process in memory: proc20.exe (PID: 6080, PPID: 4000)||Threads=2 SessionId= FoundBy=$allWays",
        "Memory-Processes|2026-10-10 23:59:00.000|ProcessCreation|Process in memory: proc145.exe (PID: 6580, PPID: 4000)||Threads=2 SessionId=1 FoundBy=$allWays",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: smss.exe (PID: 404)||Args=\SystemRoot\System32\smss.exe",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: My App.exe (PID: 5000)||Args=`"C:\Program Files\My App\My App.exe`" --flag",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: cmd.exe (PID: 5024)||Args=$special",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: nul.exe (PID: 5032)||Args=nul.exe before",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: odd.exe (PID: 5036)||Args=odd.e"
    )
    $missingRows = @($expectedRows | Where-Object { $run.Rows -cnotcontains $_ })
    Assert-Equal -Name "debugger engine, a whole analysis (the scan of the fake kernel): the rows of the edge processes (System, Registry and smss.exe without a session, a name with spaces, 15 bytes, invalid UTF-8, exited, no time, a time past the end, session 0 and 1 from the token, an unreadable token; each found all three ways, FoundBy=; exact command lines)" -Expected "" -Actual ($missingRows -join " / ")
    Assert-Equal -Name "debugger engine, a whole analysis: no row has TableId= or Anomaly= (a consistent dump)" -Expected "0" -Actual "$(@($run.Rows | Where-Object { $_ -match 'TableId=|Anomaly=' }).Count)"
    $longRow = @($run.Entries | Where-Object { $_.Description -eq "Process command line: long.exe (PID: 5028)" })
    $noRows = @($run.Entries | Where-Object { $_.Source -eq "Memory-CommandLine" -and $_.Description -match 'exited\.exe|empty\.exe|partial\.exe|: System \(|: Registry \(|\(PID: 0\)' })
    $idle = @($run.Rows | Where-Object { $_ -match 'Idle' })
    Assert-Equal -Name "debugger engine, a whole analysis: 146 pslist and 141 cmdline rows, a 32,767-character command line whole, no command line row for kernel, exited, empty and partly paged-out processes, no idle process" -Expected "146|141|1|32772|0|0" -Actual "$(@($run.Rows | Where-Object { $_.StartsWith('Memory-Processes|') }).Count)|$(@($run.Rows | Where-Object { $_.StartsWith('Memory-CommandLine|') }).Count)|$($longRow.Count)|$(if ($longRow.Count) { $longRow[0].Details.Length })|$($noRows.Count)|$($idle.Count)"
    Assert-Equal -Name "debugger engine, a whole analysis: the result, one session opened and closed, one download, the work folder removed, the dump as RawPath on every row" -Expected "287|146|141|||1|1|1|False|0" -Actual "$($run.Result.Entries)|$($run.Result.Processes)|$($run.Result.CommandLines)|$($run.Result.Reason)|$($run.Result.PartialReason)|$($run.Opened)|$($run.Closed)|$($run.Downloads)|$($run.JobLeft)|$(@($run.Entries | Where-Object { $_.RawPath -ne $engineDump -or $_.Artifact -ne 'MemoryDump' }).Count)"
    Assert-Equal -Name "debugger engine: the helper's arguments (the engine, the symbol cache in tools\, the work folder, the capture start from the dump header and its end from the file's last write, in UTC) and the empty symbol and extension folders" -Expected "C:\stub|dbgeng.dll|$engineDump|True|True|$symbolRoot|$(Join-Path $script:runScratchDir 'dbgeng')|2026-10-11T00:09:00.0000000Z|2026-10-11T00:11:00.0000000Z" -Actual "$($script:openedWith)|$($script:workerArguments['SymbolCache'])|$($script:workerArguments['JobFolder'])|$($script:workerArguments['CaptureStart'])|$($script:workerArguments['CaptureEnd'])"
    $expectedLog = @(
        "  Debugger engine: dbgeng.dll 10.0.26100.1 from C:\stub (part of Windows)",
        "  Downloading the Windows kernel symbol file (about 10 MB) from Microsoft's symbol server: https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/$kernelKey/ntkrnlmp.pdb",
        "  Downloaded 0.1 MB in ",
        "    Processes found: 146; the kernel's process list walked forwards 146, backwards 146, in its process ID table 146, in the debugger engine's own list 146`r`n",
        "    Processes (windows.pslist rows): 146 entries (144 timed, 2 snapshot); session ids for 142`r`n",
        "    Command lines (windows.cmdline rows): 141 entries; none for 2 kernel process(es) without a PEB, 2 not readable (paged out or exited), 1 empty; ",
        "    Debugger engine analysis took "
    )
    $missingLog = @($expectedLog | Where-Object { -not $run.Log.Contains($_) })
    Assert-Equal -Name "debugger engine, a whole analysis: the log lines (the engine, the download, what each way found, the counts), no warning" -Expected "|0" -Actual "$($missingLog -join ' / ')|$(@([regex]::Matches($run.Log, 'WARNING')).Count)"
    $typesRead = @($script:engineCommands | Where-Object { $_ -like 'dt -v nt!*' } | ForEach-Object { $_.Substring(9) }) -join ","
    $headLookups = @($script:engineCommands | Where-Object { $_ -eq '? nt!PsActiveProcessHead' }).Count
    $tableLookups = @($script:engineCommands | Where-Object { $_ -eq '? nt!PspCidTable' }).Count
    $engineCounts = @($script:engineCommands | Where-Object { $_.StartsWith('dx @$cursession.Processes.Where') }).Count
    $enginePages = @($script:engineCommands | Where-Object { $_.StartsWith('dx -r1 ') }).Count
    Assert-Equal -Name "debugger engine, a whole analysis: the structures from the symbols (dt -v), the list head and the process ID table (?), the engine's own list counted once, its dx pages not read" -Expected "_EPROCESS,_TOKEN,_EX_FAST_REF,_MM_SESSION_SPACE,_HANDLE_TABLE,_HANDLE_TABLE_ENTRY|1|1|1|0" -Actual "$typesRead|$headLookups|$tableLookups|$engineCounts|$enginePages"
    $cachedFile = Join-Path $symbolRoot "ntkrnlmp.pdb\$kernelKey\ntkrnlmp.pdb"
    Assert-Equal -Name "debugger engine: the kernel symbol file is kept in tools\symbols\<name>\<key>\<name>" -Expected "True" -Actual "$(Test-Path -LiteralPath $cachedFile)"
    $scanRows = Get-TestSortedRows $run -Plain

    # The same under de-DE (set inside one script block for Windows PowerShell)
    $germanRun = & {
        $savedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo("de-DE")
            Invoke-TestEngineRun
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $savedCulture }
    }
    Assert-Equal -Name "debugger engine, de-DE: the same rows, and the symbol file of the first run used (no download)" -Expected "True|0|True" -Actual "$(($germanRun.Rows -join "`n") -ceq ($run.Rows -join "`n"))|$($germanRun.Downloads)|$($germanRun.Log.Contains("  Kernel symbols: $cachedFile (downloaded earlier)"))"

    # --- Memory copied while Windows ran: the list changed during the copy -----
    # A process that ended during the copy (the shape of a real DumpIt dump):
    # its predecessor's link forwards still points to it, its successor's
    # link back already skips it, and it is still in the process ID table.
    # The engine's own list ends there; the scan has every process, the
    # newest after the break too, and says how each way disagreed.
    Set-TestLinks -Index 100 -Flink (Get-TestLinkAddress 150) -Blink (Get-TestLinkAddress 99)
    Set-TestLinks -Index 150 -Flink (Get-TestLinkAddress 101) -Blink (Get-TestLinkAddress 100)
    Set-TestCidTable -Entries ($defaultCid + @(, @(7000, ($eprocessBase + [uint64](150 * 0x1000)))))
    $script:engineCountText = "WARNING: corrupted linked list found. Previous (_LIST_ENTRY*) 0xffffa000000962c8, current (_LIST_ENTRY*) 0xffffa000000651c8.`n@`$cursession.Processes.Where(p => p.Id != 0).Count() : 0x80`n"
    $endedRun = Invoke-TestEngineRun
    Reset-TestKernel
    $endedNote = "the kernel's list of processes was inconsistent in 1 place, as when memory is copied while Windows runs and processes start or end during the copy. 147 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 1 missed by walking backwards. The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 128 entries and stops at the first inconsistent link."
    $goneRow = "Memory-Processes|2026-10-11 00:04:00.000|ProcessCreation|Process in memory: gone.exe (PID: 7000, PPID: 4000)||Threads=0 SessionId=1 FoundBy=ListForward,ProcessIdTable"
    Assert-Equal -Name "memory copied while Windows ran, a process that ended during the copy: every row of the consistent dump (the newest after the break too) and the ended process's, once, with the ways that found it" -Expected ((@($run.Rows) + @($goneRow) | Sort-Object) -join "`n") -Actual (Get-TestSortedRows $endedRun)
    Assert-Equal -Name "memory copied while Windows ran, a process that ended during the copy: what each way found, and the warning that says how they disagree" -Expected "True|True|147" -Actual "$($endedRun.Log.Contains("    Processes found: 147; the kernel's process list walked forwards 147 (1 inconsistent link), backwards 146 (1 inconsistent link), in its process ID table 147, in the debugger engine's own list 128`r`n"))|$($endedRun.Log.Contains("WARNING:   Memory dump process list: $endedNote`r`n"))|$($endedRun.Result.Processes)"
    # The findings report reads the warning back as its coverage note
    $endedReportLog = Read-ReportEngineBuilderLog -Path $endedRun.LogFile
    Assert-Equal -Name "memory copied while Windows ran: the findings report's log reader gets the note, one colon in it" -Expected "$endedNote|1" -Actual "$($endedReportLog.MemoryDumpProcessList)|$(([regex]::Matches("Memory dump process list: $($endedReportLog.MemoryDumpProcessList)", ':\s')).Count)"

    # A link forwards into memory that was reused (another real dump's
    # shape): the forward walk stops there; the backward walk and the
    # process ID table find the rest, and no row is made of the reused memory
    Set-TestLinks -Index 100 -Flink ($reusedAddress + [uint64]$fakeOffsets.ActiveProcessLinks) -Blink (Get-TestLinkAddress 99)
    $script:engineCountText = "WARNING: corrupted linked list found. Previous (_LIST_ENTRY*) 0x10001, current (_LIST_ENTRY*) 0xffffa000000971c8.`n@`$cursession.Processes.Where(p => p.Id != 0).Count() : 0x66`n"
    $reusedRun = Invoke-TestEngineRun
    Reset-TestKernel
    $reusedNote = "the kernel's list of processes was inconsistent in 1 place, as when memory is copied while Windows runs and processes start or end during the copy. 146 processes were found, 101 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 45 missed by walking forwards. The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 102 entries and stops at the first inconsistent link."
    Assert-Equal -Name "a forward walk that stops at reused memory: the same rows as the consistent dump (none of the reused memory; 45 found backwards and in the table), what each way found, the warning" -Expected "True|True|True|0|45" -Actual "$((Get-TestSortedRows $reusedRun -Plain) -ceq $scanRows)|$($reusedRun.Log.Contains("    Processes found: 146; the kernel's process list walked forwards 101 (stopped at an entry that is not a process), backwards 146 (1 inconsistent link), in its process ID table 146, in the debugger engine's own list 102`r`n"))|$($reusedRun.Log.Contains("WARNING:   Memory dump process list: $reusedNote`r`n"))|$(@($reusedRun.Rows | Where-Object { $_ -match 'PID: -|PID: 4886718345' }).Count)|$(@($reusedRun.Rows | Where-Object { $_.EndsWith(' FoundBy=ListBackward,ProcessIdTable') }).Count)"

    # A list that loops back (its last link forwards points to an earlier
    # entry) and a process only in the process ID table that was created
    # after the capture started (being created during the copy): every
    # process once, the new one named, not marked
    Set-TestLinks -Index 145 -Flink (Get-TestLinkAddress 10) -Blink (Get-TestLinkAddress 144)
    Set-TestCidTable -Entries ($defaultCid + @(, @(7100, ($eprocessBase + [uint64](152 * 0x1000)))))
    $loopRun = Invoke-TestEngineRun
    Reset-TestKernel
    $loopNote = "the kernel's list of processes was inconsistent in 1 place, as when memory is copied while Windows runs and processes start or end during the copy. 147 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 1 only in the process ID table (PID 7100, created after the capture started). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    $loopProcessRows = @($loopRun.Entries | Where-Object { $_.Source -eq "Memory-Processes" })
    $distinctPids = @($loopProcessRows | ForEach-Object { if ($_.Description -match '\(PID: (\d+),') { $Matches[1] } } | Sort-Object -Unique).Count
    Assert-Equal -Name "a list that loops and a process only in the process ID table, created after the capture started: 147 process rows, each process once (new.exe too, found by the table, not marked), what each way found, the warning naming it" -Expected "147|147|1|True|True" -Actual "$($loopProcessRows.Count)|$distinctPids|$(@($loopRun.Rows | Where-Object { $_.EndsWith('Process in memory: new.exe (PID: 7100, PPID: 4000)||Threads=1 SessionId=1 FoundBy=ProcessIdTable') }).Count)|$($loopRun.Log.Contains("    Processes found: 147; the kernel's process list walked forwards 146 (stopped at a link to an entry already walked), backwards 146 (1 inconsistent link), in its process ID table 147, in the debugger engine's own list 146`r`n"))|$($loopRun.Log.Contains("WARNING:   Memory dump process list: $loopNote`r`n"))"

    # A process hidden from the list (unlinked cleanly: its neighbours'
    # links consistent, its own pointing to itself), only in the process ID
    # table, created hours before the capture and without an exit time:
    # listed, marked (Anomaly=NotInProcessList), named first in the warning
    # as something copying does not explain; the report reads the warning
    $hiddenCid = $defaultCid + @(, @(7300, ($eprocessBase + [uint64](153 * 0x1000))))
    Set-TestCidTable -Entries $hiddenCid
    $hiddenRun = Invoke-TestEngineRun
    Reset-TestKernel
    $hiddenNote = "PID 7300 is in neither walk of the kernel's process list, only in its process ID table, yet it was created before the capture started and has no exit time. Copying memory does not explain that, as a process leaves the list only when it ends, and a process hidden from the list (unlinked from it) looks exactly like this. 147 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 1 only in the process ID table (PID 7300). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    $hiddenRows = @(
        "Memory-Processes|2026-10-10 21:09:00.000|ProcessCreation|Process in memory: hidden.exe (PID: 7300, PPID: 4000)||Threads=5 SessionId=1 FoundBy=ProcessIdTable Anomaly=NotInProcessList",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: hidden.exe (PID: 7300)||Args=hidden.exe -q"
    )
    Assert-Equal -Name "a process hidden from the list (unlinked, only in the process ID table, created before the capture, no exit time): every row of the consistent dump and its own two, its process row marked" -Expected ((@($run.Rows) + $hiddenRows | Sort-Object) -join "`n") -Actual (Get-TestSortedRows $hiddenRun)
    Assert-Equal -Name "a process hidden from the list: what each way found (no inconsistent link), the warning names it first and says copying does not explain it, read back by the findings report" -Expected "True|True|$hiddenNote" -Actual "$($hiddenRun.Log.Contains("    Processes found: 147; the kernel's process list walked forwards 146, backwards 146, in its process ID table 147, in the debugger engine's own list 146`r`n"))|$($hiddenRun.Log.Contains("WARNING:   Memory dump process list: $hiddenNote`r`n"))|$((Read-ReportEngineBuilderLog -Path $hiddenRun.LogFile).MemoryDumpProcessList)"
    # The same without a capture start (the dump's time is its file's): the
    # process is named and found by the table, but not marked
    $savedSource = $engineDumpInfo.TimeSource
    $engineDumpInfo.TimeSource = "dump file last-write time"
    Set-TestCidTable -Entries $hiddenCid
    try { $noStartRun = Invoke-TestEngineRun }
    finally { $engineDumpInfo.TimeSource = $savedSource; Reset-TestKernel }
    Assert-Equal -Name "a process only in the process ID table, the capture start not known: no capture start passed, named in the warning, found by the table, not marked" -Expected "|True|1|0" -Actual "$($script:workerArguments['CaptureStart'])|$($noStartRun.Log.Contains("WARNING:   Memory dump process list: 147 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 1 only in the process ID table (PID 7300). The debugger engine's"))|$(@($noStartRun.Rows | Where-Object { $_.EndsWith('hidden.exe (PID: 7300, PPID: 4000)||Threads=5 SessionId=1 FoundBy=ProcessIdTable') }).Count)|$(@($noStartRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)"
    # Both walks stop early (links into reused memory, forwards after entry
    # 100 and backwards before entry 120): the processes between are only in
    # the table, so missing from the list says nothing there; none is marked
    Set-TestLinks -Index 100 -Flink ($reusedAddress + [uint64]$fakeOffsets.ActiveProcessLinks) -Blink (Get-TestLinkAddress 99)
    Set-TestLinks -Index 120 -Flink (Get-TestLinkAddress 121) -Blink ($reusedAddress + [uint64]$fakeOffsets.ActiveProcessLinks)
    Set-TestCidTable -Entries $hiddenCid
    $unwalkedRun = Invoke-TestEngineRun
    Reset-TestKernel
    Assert-Equal -Name "both walks stopped early: the processes between them and the unlinked one only in the table, all listed, none marked, the warning says the walks did not reach them" -Expected "147|20|0|True" -Actual "$(@($unwalkedRun.Rows | Where-Object { $_.StartsWith('Memory-Processes|') }).Count)|$(@($unwalkedRun.Rows | Where-Object { $_.Contains(' FoundBy=ProcessIdTable') }).Count)|$(@($unwalkedRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($unwalkedRun.Log.Contains('Both walks stopped before the end of the list, so a process only in the process ID table can be in the part of the list that neither walk reached.'))"

    # Process IDs changed in memory (the process stays in the list and the
    # table): 0, one that is not a multiple of 4, and System's 4 (the table
    # holds System under 4): each listed as the list holds it, marked
    # (Anomaly=ProcessIdChanged, TableId= the table's ID), named first in
    # the warning; no process is lost
    Set-TestUInt64 -Bytes $script:blocks[140] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]0)
    Set-TestUInt64 -Bytes $script:blocks[141] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]6566)
    Set-TestUInt64 -Bytes $script:blocks[142] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]4)
    $changedRun = Invoke-TestEngineRun
    Reset-TestKernel
    $changedNote = "3 processes have a process ID that Windows did not give them (PID 0 at 0xffffa0000008c000, an ID only the idle process has, held in the process ID table under ID 6560; PID 6566 at 0xffffa0000008d000, not a multiple of 4 as Windows gives them, held in the process ID table under ID 6564; PID 4 at 0xffffa0000008e000, held in the process ID table under ID 6568). Copying memory does not explain that, as they were created before the capture started, and a process whose ID was changed in memory, to hide or disguise it, looks like this. 146 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table)."
    $changedRows = @(
        "Memory-Processes|2026-10-10 23:59:00.000|ProcessCreation|Process in memory: proc140.exe (PID: 0, PPID: 4000)||Threads=2 SessionId=1 FoundBy=$allWays TableId=6560 Anomaly=ProcessIdChanged",
        "Memory-Processes|2026-10-10 23:59:00.000|ProcessCreation|Process in memory: proc141.exe (PID: 6566, PPID: 4000)||Threads=2 SessionId=1 FoundBy=$allWays TableId=6564 Anomaly=ProcessIdChanged",
        "Memory-Processes|2026-10-10 23:59:00.000|ProcessCreation|Process in memory: proc142.exe (PID: 4, PPID: 4000)||Threads=2 SessionId=1 FoundBy=$allWays TableId=6568 Anomaly=ProcessIdChanged"
    )
    $changedMissing = @($changedRows | Where-Object { $changedRun.Rows -cnotcontains $_ })
    Assert-Equal -Name "process IDs changed in memory (0, 6566, System's 4): 146 rows, each marked with the table's ID, what each way found, the warning names them first, read back by the findings report" -Expected "|146|3|True|$changedNote" -Actual "$($changedMissing -join ' / ')|$(@($changedRun.Rows | Where-Object { $_.StartsWith('Memory-Processes|') }).Count)|$(@($changedRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($changedRun.Log.Contains("    Processes found: 146; the kernel's process list walked forwards 146, backwards 146, in its process ID table 146, in the debugger engine's own list 146`r`n"))|$((Read-ReportEngineBuilderLog -Path $changedRun.LogFile).MemoryDumpProcessList)"

    # Capture churn (a real dump's shape, of a computer busy with short-lived
    # processes): three processes only in the process ID table, each under
    # the ID of a process that is not in the dump, one created 20 s after
    # the capture started and two 0.78 s and 90 s before it (within the
    # 120-second churn margin): listed with FoundBy= and TableId=, not
    # marked, and counted as capture churn in the warning (never "copying
    # memory does not explain"), which the findings report reads back
    $churnAddress = @{}
    foreach ($i in 155..158) { $churnAddress[$i] = $eprocessBase + [uint64]($i * 0x1000) }
    $churnCid = $defaultCid + @(@(7500, $churnAddress[155]), @(7600, $churnAddress[156]), @(7800, $churnAddress[158]))
    Set-TestCidTable -Entries $churnCid
    $churnRun = Invoke-TestEngineRun
    Reset-TestKernel
    $churnNote = "3 processes are capture churn, started while memory was being copied (or at most 120 seconds before it), with stale process ID table entries (PID 7400 at 0xffffa0000009b000, held in the process ID table under ID 7500; PID 7404 at 0xffffa0000009c000, held in the process ID table under ID 7600; PID 7412 at 0xffffa0000009e000, held in the process ID table under ID 7800). The process ID table and a process's memory are copied at different moments, and a short-lived process that ends in between leaves its ID or its memory to a new process, so copying memory explains this; they are not marked. 149 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 3 only in the process ID table (PID 7400, created after the capture started; PID 7404, created at most 120 seconds before the capture started; PID 7412, created at most 120 seconds before the capture started). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    $churnRows = @(
        "Memory-Processes|2026-10-11 00:09:20.000|ProcessCreation|Process in memory: churn1.exe (PID: 7400, PPID: 4000)||Threads=4 SessionId=1 FoundBy=ProcessIdTable TableId=7500",
        "Memory-Processes|2026-10-11 00:08:59.220|ProcessCreation|Process in memory: churn2.exe (PID: 7404, PPID: 4000)||Threads=4 SessionId=1 FoundBy=ProcessIdTable TableId=7600",
        "Memory-Processes|2026-10-11 00:07:30.000|ProcessCreation|Process in memory: loop.exe (PID: 7412, PPID: 4000)||Threads=4 SessionId=1 FoundBy=ProcessIdTable TableId=7800",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: churn1.exe (PID: 7400)||Args=churn1.exe 1",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: churn2.exe (PID: 7404)||Args=churn2.exe 2",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: loop.exe (PID: 7412)||Args=loop.exe 4"
    )
    Assert-Equal -Name "capture churn (created 20 s after the capture started, 0.78 s and 90 s before it, only in the process ID table under another ID): every row of the consistent dump and their own, FoundBy= and TableId=, no Anomaly=" -Expected ((@($run.Rows) + $churnRows | Sort-Object) -join "`n") -Actual (Get-TestSortedRows $churnRun)
    Assert-Equal -Name "capture churn: what each way found, the warning counts them as capture churn and says copying explains it (not 'does not explain'), read back by the findings report" -Expected "True|True|False|$churnNote" -Actual "$($churnRun.Log.Contains("    Processes found: 149; the kernel's process list walked forwards 146, backwards 146, in its process ID table 149, in the debugger engine's own list 146`r`n"))|$($churnRun.Log.Contains("WARNING:   Memory dump process list: $churnNote`r`n"))|$($churnRun.Log.Contains('does not explain'))|$((Read-ReportEngineBuilderLog -Path $churnRun.LogFile).MemoryDumpProcessList)"
    # Just outside the churn margin (created 125 s before the capture
    # started, only in the table under another ID, no exit time, the walks
    # complete): judged as before, both marks, named first
    Set-TestCidTable -Entries ($defaultCid + @(, @(7700, $churnAddress[157])))
    $earlyRun = Invoke-TestEngineRun
    Reset-TestKernel
    $earlyNote = "PID 7408 is in neither walk of the kernel's process list, only in its process ID table, yet it was created before the capture started and has no exit time. Copying memory does not explain that, as a process leaves the list only when it ends, and a process hidden from the list (unlinked from it) looks exactly like this. 1 process has a process ID that Windows did not give it (PID 7408 at 0xffffa0000009d000, held in the process ID table under ID 7700). Copying memory does not explain that, as it was created before the capture started, and a process whose ID was changed in memory, to hide or disguise it, looks like this. 147 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 1 only in the process ID table (PID 7408). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    Assert-Equal -Name "a process created 125 s before the capture started (outside the churn margin), only in the table under another ID: marked NotInProcessList and ProcessIdChanged, named first, read back by the findings report" -Expected "1|1|$earlyNote" -Actual "$(@($earlyRun.Rows | Where-Object { $_.EndsWith('Process in memory: early.exe (PID: 7408, PPID: 4000)||Threads=4 SessionId=1 FoundBy=ProcessIdTable TableId=7700 Anomaly=NotInProcessList,ProcessIdChanged') }).Count)|$(@($earlyRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$((Read-ReportEngineBuilderLog -Path $earlyRun.LogFile).MemoryDumpProcessList)"
    # No capture start (the dump's time is its file's): process IDs changed
    # in long-lived processes and the churn alike are listed with TableId=,
    # named, and not marked; the warning says they cannot be judged
    $engineDumpInfo.TimeSource = "dump file last-write time"
    Set-TestUInt64 -Bytes $script:blocks[140] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]0)
    Set-TestUInt64 -Bytes $script:blocks[141] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]6566)
    Set-TestUInt64 -Bytes $script:blocks[142] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]4)
    Set-TestCidTable -Entries $churnCid
    try { $noStartChangedRun = Invoke-TestEngineRun }
    finally { $engineDumpInfo.TimeSource = $savedSource; Reset-TestKernel }
    $noStartChangedNote = "6 processes have a process ID that does not fit (PID 0 at 0xffffa0000008c000, an ID only the idle process has, held in the process ID table under ID 6560; PID 6566 at 0xffffa0000008d000, not a multiple of 4 as Windows gives them, held in the process ID table under ID 6564; PID 4 at 0xffffa0000008e000, held in the process ID table under ID 6568; PID 7400 at 0xffffa0000009b000, held in the process ID table under ID 7500; PID 7404 at 0xffffa0000009c000, held in the process ID table under ID 7600; PID 7412 at 0xffffa0000009e000, held in the process ID table under ID 7800). Whether copying memory explains that cannot be judged without the capture's start time (the time in the dump's header), so they are not marked. 149 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 3 only in the process ID table (PID 7400; PID 7404; PID 7412). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    Assert-Equal -Name "no capture start: changed process IDs and capture churn listed with TableId=, none marked, the warning says they cannot be judged (no 'does not explain'), read back by the findings report" -Expected "||6|0|False|$noStartChangedNote" -Actual "$($script:workerArguments['CaptureStart'])|$($script:workerArguments['CaptureEnd'])|$(@($noStartChangedRun.Rows | Where-Object { $_.Contains(' TableId=') }).Count)|$(@($noStartChangedRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($noStartChangedRun.Log.Contains('does not explain'))|$((Read-ReportEngineBuilderLog -Path $noStartChangedRun.LogFile).MemoryDumpProcessList)"
    # A create time capture churn cannot have (none, or after the capture
    # ended: the dump file's last write) on processes in the list that the
    # table holds under another ID: marked, as before the churn margin
    # existed; the warning says the time, never that copying explains it
    $oddCid = @($defaultCid | Where-Object { $_[0] -ne 5016 -and $_[0] -ne 5020 }) + @(@(7776, ($eprocessBase + [uint64](7 * 0x1000))), @(7780, ($eprocessBase + [uint64](8 * 0x1000))))
    Set-TestCidTable -Entries $oddCid
    $oddRun = Invoke-TestEngineRun
    Reset-TestKernel
    $oddTimeSentence = "Capture churn is a process created between the capture's start and end (the time in the dump's header and the dump file's last-write time) or shortly before: one without a create time, or created after the capture ended, is not."
    $oddNote = "2 processes have a process ID that Windows did not give them (PID 5016 at 0xffffa00000007000, held in the process ID table under ID 7776, without a create time; PID 5020 at 0xffffa00000008000, held in the process ID table under ID 7780, created after the capture ended). Copying memory does not explain that, and a process whose ID was changed in memory, to hide or disguise it, looks like this. $oddTimeSentence 146 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table)."
    $oddRows = @(
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: notime.exe (PID: 5016, PPID: 4000)||Threads=1 SessionId=1 FoundBy=$allWays TableId=7776 Anomaly=ProcessIdChanged",
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: future.exe (PID: 5020, PPID: 4000)||Threads=1 SessionId=1 CreateTime=2026-10-12 00:11:01.000 FoundBy=$allWays TableId=7780 Anomaly=ProcessIdChanged"
    )
    Assert-Equal -Name "process IDs changed on processes without a create time and created a day after the capture ended (in the list, held in the table under another ID): both marked ProcessIdChanged, the warning says their times and that they are not capture churn, read back by the findings report" -Expected "|2|False|$oddNote" -Actual "$(@($oddRows | Where-Object { $oddRun.Rows -cnotcontains $_ }) -join ' / ')|$(@($oddRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($oddRun.Log.Contains('copying memory explains'))|$((Read-ReportEngineBuilderLog -Path $oddRun.LogFile).MemoryDumpProcessList)"
    # The same two unlinked from the list (only in the table, under their
    # own IDs): marked NotInProcessList
    Set-TestProcessList -Order ([int[]]@($defaultOrder | Where-Object { $_ -ne 7 -and $_ -ne 8 }))
    $oddHiddenRun = Invoke-TestEngineRun
    Reset-TestKernel
    $oddHiddenNote = "PIDs 5016 (no create time) and 5020 (created after the capture ended) are in neither walk of the kernel's process list, only in its process ID table, yet they have no exit time and were not created while memory was being copied. Copying memory does not explain that, as a process leaves the list only when it ends, and a process hidden from the list (unlinked from it) looks exactly like this. $oddTimeSentence 146 processes were found, 144 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 2 only in the process ID table (PID 5016; PID 5020)."
    $oddHiddenRows = @(
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: notime.exe (PID: 5016, PPID: 4000)||Threads=1 SessionId=1 FoundBy=ProcessIdTable Anomaly=NotInProcessList",
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: future.exe (PID: 5020, PPID: 4000)||Threads=1 SessionId=1 CreateTime=2026-10-12 00:11:01.000 FoundBy=ProcessIdTable Anomaly=NotInProcessList"
    )
    Assert-Equal -Name "processes without a create time and created after the capture ended, unlinked from the list (only in the table): both marked NotInProcessList, named first with their times, read back by the findings report" -Expected "|2|True|$oddHiddenNote" -Actual "$(@($oddHiddenRows | Where-Object { $oddHiddenRun.Rows -cnotcontains $_ }) -join ' / ')|$(@($oddHiddenRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($oddHiddenRun.Log.Contains("    Processes found: 146; the kernel's process list walked forwards 144, backwards 144, in its process ID table 146, in the debugger engine's own list 146`r`n"))|$((Read-ReportEngineBuilderLog -Path $oddHiddenRun.LogFile).MemoryDumpProcessList)"
    # IDs a stale entry of the process ID table cannot give, on processes
    # created during the copy that the list walks find and the table does
    # not hold: one that is not a multiple of 4 (new.exe) and 0 (churn1.exe)
    # are marked; 0 on a process the table holds under another ID
    # (churn2.exe) is capture churn
    Set-TestProcessList -Order ([int[]]($defaultOrder + @(152, 155)))
    Set-TestUInt64 -Bytes $script:blocks[152] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]7101)
    Set-TestUInt64 -Bytes $script:blocks[155] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]0)
    Set-TestUInt64 -Bytes $script:blocks[156] -Offset $fakeOffsets.UniqueProcessId -Value ([uint64]0)
    Set-TestCidTable -Entries ($defaultCid + @(, @(7600, $churnAddress[156])))
    try { $idRun = Invoke-TestEngineRun }
    finally {
        Reset-TestKernel
        Set-TestLinks -Index 152 -Flink 0 -Blink 0
        Set-TestLinks -Index 155 -Flink (Get-TestLinkAddress 155) -Blink (Get-TestLinkAddress 155)
    }
    $idNote = "2 processes have a process ID that Windows did not give them (PID 7101 at 0xffffa00000098000, not a multiple of 4 as Windows gives them, created during the copy or shortly before it; PID 0 at 0xffffa0000009b000, an ID only the idle process has, created during the copy or shortly before it). Copying memory does not explain that, and a process whose ID was changed in memory, to hide or disguise it, looks like this. 1 process is capture churn, started while memory was being copied (or at most 120 seconds before it), with a stale process ID table entry (PID 0 at 0xffffa0000009c000, an ID only the idle process has, held in the process ID table under ID 7600). The process ID table and a process's memory are copied at different moments, and a short-lived process that ends in between leaves its ID or its memory to a new process, so copying memory explains this; it is not marked. 149 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 2 not in the process ID table, 1 only in the process ID table (PID 0, created at most 120 seconds before the capture started). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    $idRows = @(
        "Memory-Processes|2026-10-11 00:09:30.000|ProcessCreation|Process in memory: new.exe (PID: 7101, PPID: 4000)||Threads=1 SessionId=1 FoundBy=ListForward,ListBackward Anomaly=ProcessIdChanged",
        "Memory-Processes|2026-10-11 00:09:20.000|ProcessCreation|Process in memory: churn1.exe (PID: 0, PPID: 4000)||Threads=4 SessionId=1 FoundBy=ListForward,ListBackward Anomaly=ProcessIdChanged",
        "Memory-Processes|2026-10-11 00:08:59.220|ProcessCreation|Process in memory: churn2.exe (PID: 0, PPID: 4000)||Threads=4 SessionId=1 FoundBy=ProcessIdTable TableId=7600"
    )
    Assert-Equal -Name "created during the copy, an ID not a multiple of 4 and 0 without a table entry: marked ProcessIdChanged; 0 held in the table under another ID: capture churn, not marked; the warning, read back by the findings report" -Expected "|2|$idNote" -Actual "$(@($idRows | Where-Object { $idRun.Rows -cnotcontains $_ }) -join ' / ')|$(@($idRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$((Read-ReportEngineBuilderLog -Path $idRun.LogFile).MemoryDumpProcessList)"
    # The dump file's last write before the header's time (no capture end):
    # a process created after the capture started cannot be judged (named,
    # not marked); those created within the margin before it are churn
    $savedEnd = $engineDumpInfo.LastWriteUtc
    $engineDumpInfo.LastWriteUtc = $capture.AddMinutes(-1)
    Set-TestCidTable -Entries $churnCid
    try { $noEndRun = Invoke-TestEngineRun }
    finally { $engineDumpInfo.LastWriteUtc = $savedEnd; Reset-TestKernel }
    $noEndNote = "1 process has a process ID that does not fit (PID 7400 at 0xffffa0000009b000, held in the process ID table under ID 7500). Whether copying memory explains that cannot be judged without the capture's end time (the dump file's last-write time), as it was created after the capture started, so it is not marked. 2 processes are capture churn, started while memory was being copied (or at most 120 seconds before it), with stale process ID table entries (PID 7404 at 0xffffa0000009c000, held in the process ID table under ID 7600; PID 7412 at 0xffffa0000009e000, held in the process ID table under ID 7800). The process ID table and a process's memory are copied at different moments, and a short-lived process that ends in between leaves its ID or its memory to a new process, so copying memory explains this; they are not marked. 149 processes were found, 146 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 3 only in the process ID table (PID 7400; PID 7404, created at most 120 seconds before the capture started; PID 7412, created at most 120 seconds before the capture started). The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has 146 entries."
    Assert-Equal -Name "no capture end (the dump file's last write before the header's time): no end passed, the process created after the start cannot be judged, the two before it are churn, none marked, read back by the findings report" -Expected "2026-10-11T00:09:00.0000000Z||3|0|False|$noEndNote" -Actual "$($script:workerArguments['CaptureStart'])|$($script:workerArguments['CaptureEnd'])|$(@($noEndRun.Rows | Where-Object { $_.Contains(' TableId=') }).Count)|$(@($noEndRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($noEndRun.Log.Contains('does not explain'))|$((Read-ReportEngineBuilderLog -Path $noEndRun.LogFile).MemoryDumpProcessList)"
    # When a process was created, against the capture (the margin, the
    # end's slack, no end, an end before the start, no start), and what a
    # process ID that does not fit gets for each
    $startTime = $capture.ToFileTimeUtc()
    $endTime = $acquisitionEnd.ToFileTimeUtc()
    $second = [long]10000000
    $whenCases = @(@(0, $startTime, $endTime), @(-5, $startTime, $endTime), @(($startTime - 120 * $second - 1), $startTime, $endTime), @(($startTime - 120 * $second), $startTime, $endTime), @($startTime, $startTime, $endTime),
        @(($endTime + 2 * $second), $startTime, $endTime), @(($endTime + 2 * $second + 1), $startTime, $endTime), @(($startTime + $second), $startTime, 0), @(($startTime - $second), $startTime, 0), @(($startTime + $second), $startTime, ($startTime - 1)), @($startTime, 0, $endTime))
    Assert-Equal -Name "Get-DbgEngCreateWhen: no create time, before the 120-second margin, at it, at the start, up to 2 s after the end, past it, no end (after and before the start), an end before the start, no start" -Expected "NoTime|NoTime|Before|Churn|Churn|Churn|Late|NoEnd|Churn|NoEnd|" -Actual ((@($whenCases | ForEach-Object { Get-DbgEngCreateWhen -CreateTime $_[0] -CaptureFileTime $_[1] -CaptureEndFileTime $_[2] })) -join "|")
    $verdictCases = @(@("Table", 1, ""), @("Table", 1, "Before"), @("Table", 1, "Churn"), @("Table", 1, "NoTime"), @("Table", 1, "Late"), @("Table", 1, "NoEnd"), @("Zero", 1, "Churn"), @("Zero", 0, "Churn"), @("Zero", 0, "NoEnd"), @("Invalid", 1, "Churn"), @("Invalid", 0, ""), @("Invalid", 0, "NoEnd"))
    Assert-Equal -Name "Get-DbgEngIdChangeVerdict: a stale-entry shape (Table, Zero held under an ID) is churn only when created during the copy, not judged without a start or end; 0 without a table entry and an ID not a multiple of 4 are marked whenever the start is known" -Expected "Unjudged|Marked|Churn|Marked|Marked|Unjudged|Churn|Marked|Marked|Marked|Unjudged|Marked" -Actual ((@($verdictCases | ForEach-Object { Get-DbgEngIdChangeVerdict -Kind $_[0] -TableIdCount $_[1] -When $_[2] })) -join "|")

    # The process ID table changed during the copy: an entry that holds a
    # process also held under its own ID (said, TableId=, not marked), and
    # an entry whose object only starts like a process (its links are no
    # kernel addresses: counted, left out, no warning)
    Set-TestCidTable -Entries ($defaultCid + @(, @(7200, $procs[3].E)))
    $staleRun = Invoke-TestEngineRun
    Set-TestCidTable -Entries ($defaultCid + @(, @(7204, $partlyAddress)))
    $partlyRun = Invoke-TestEngineRun
    Reset-TestKernel
    Assert-Equal -Name "a stale entry of the process ID table: the process once, TableId=, not marked, the warning says the table changed during the copy" -Expected "146|1|0|True" -Actual "$(@($staleRun.Rows | Where-Object { $_.StartsWith('Memory-Processes|') }).Count)|$(@($staleRun.Rows | Where-Object { $_.EndsWith('My App.exe (PID: 5000, PPID: 4000)||Threads=7 SessionId=1 FoundBy=ListForward,ListBackward,ProcessIdTable TableId=7200') }).Count)|$(@($staleRun.Rows | Where-Object { $_.Contains('Anomaly=') }).Count)|$($staleRun.Log.Contains('WARNING:   Memory dump process list: 1 entry of the process ID table holds a process that is there under its own ID too, as when the table changes during the copy. 146 processes were found, 146 of them by all three ways'))"
    Assert-Equal -Name "an entry of the process ID table whose object only starts like a process: counted in what the table found, no row, no warning" -Expected "True|True|0" -Actual "$($partlyRun.Log.Contains("    Processes found: 146; the kernel's process list walked forwards 146, backwards 146, in its process ID table 146 (1 entry left out whose object only starts like a process), in the debugger engine's own list 146`r`n"))|$((Get-TestSortedRows $partlyRun) -ceq (Get-TestSortedRows $run))|$(@([regex]::Matches($partlyRun.Log, 'WARNING')).Count)"

    # The symbols describe the structures, but the list head and the
    # process ID table are not in the dump: the scan finds nothing and says
    # so in a plain line; the engine's own list is used, and its warning is
    # the only "Memory dump process list" line, matching the rows
    $script:headSymbol = $kernelBase + [uint64]0x300000
    $script:cidSymbol = $kernelBase + [uint64]0x300100
    $script:dxWarning = "WARNING: corrupted linked list found. Previous (_LIST_ENTRY*) 0xffffa000000962c8, current (_LIST_ENTRY*) 0xffffa000000651c8.`n"
    $emptyScanRun = Invoke-TestEngineRun
    Reset-TestKernel
    $emptyScanNote = "the debugger engine found the kernel's list of processes inconsistent (corrupted linked list), as when memory is copied while Windows runs and processes start or end during the copy, and lists only the 146 processes before that place, so the newest processes can be missing. The kernel's own process structures could not be read to find them."
    Assert-Equal -Name "the scan finds no process (list head and process ID table not in the dump): a plain line says so, then the engine's own list, one 'Memory dump process list' warning that the findings report reads, the same rows" -Expected "True|True|1|$emptyScanNote|True|False" -Actual "$($emptyScanRun.Log.Contains("    No process was found in the kernel's own process structures: the kernel's process list walked forwards 0 (stopped at the list head, which is not in the dump), backwards 0 (stopped at the list head, which is not in the dump), its process ID table not read [it is not in the dump], in the debugger engine's own list 146`r`n"))|$($emptyScanRun.Log.Contains("WARNING:   The kernel's own process structures could not be read (no process was found in them): the debugger engine's own process list is used"))|$(@([regex]::Matches($emptyScanRun.Log, 'Memory dump process list')).Count)|$((Read-ReportEngineBuilderLog -Path $emptyScanRun.LogFile).MemoryDumpProcessList)|$((Get-TestSortedRows $emptyScanRun -Plain) -ceq $scanRows)|$($emptyScanRun.Log.Contains('Processes found:'))"

    # Symbols with _MM_SESSION_SPACE: the session space's id (the fake one
    # is the token's + 2), the token's for a process whose session space is
    # not in the dump, none without a session
    $script:dtText = $script:dtDefault.Clone()
    $script:dtText["_MM_SESSION_SPACE"] = "struct _MM_SESSION_SPACE, 90 elements, 0x1e00 bytes`n   +0x000 ReferenceCount   : Int4B`n   +0x008 SessionId        : Uint4B`n"
    $spaceRun = Invoke-TestEngineRun
    Reset-TestKernel
    $spaceChecks = @("System (PID: 4, PPID: 0)||Threads=150 SessionId=", "My App.exe (PID: 5000, PPID: 4000)||Threads=7 SessionId=3", "services.exe (PID: 5048, PPID: 4000)||Threads=3 SessionId=2",
        "proc20.exe (PID: 6080, PPID: 4000)||Threads=2 SessionId=3", "proc21.exe (PID: 6084, PPID: 4000)||Threads=2 SessionId=1")
    $spaceMissing = @($spaceChecks | Where-Object { $text = $_; @($spaceRun.Rows | ForEach-Object { $_ -replace ' FoundBy=\S+', '' } | Where-Object { $_.EndsWith($text) }).Count -ne 1 })
    Assert-Equal -Name "symbols with _MM_SESSION_SPACE: its session ids, the token's where the session space is not in the dump, none without a session" -Expected "|session ids for 143" -Actual "$($spaceMissing -join ' / ')|$(if ($spaceRun.Log -match 'session ids for \d+') { $Matches[0] })"

    # The kernel's symbols without the process structure: the engine's own
    # list (dx pages), the same rows, a warning that says why; the engine's
    # "corrupted linked list" warning becomes the report's warning
    $script:dtText = @{}
    $fallbackRun = Invoke-TestEngineRun
    $fallbackWarning = "WARNING:   The kernel's own process structures could not be read (the kernel's symbols do not describe its process structure _EPROCESS): the debugger engine's own process list is used, which misses the newest processes when the list changed while the memory was copied."
    Assert-Equal -Name "no process structure in the symbols: the engine's own list (bad items, a duplicate and the idle process left out), the same rows as the scan, the warning, no process list note" -Expected "True|True|True|False" -Actual "$((Get-TestSortedRows $fallbackRun -Plain) -ceq $scanRows)|$($fallbackRun.Log.Contains($fallbackWarning))|$($fallbackRun.Log.Contains('    Processes (windows.pslist rows): 146 entries (144 timed, 2 snapshot); 2 list item(s) could not be read; session ids for 142'))|$($fallbackRun.Log.Contains('Memory dump process list'))"
    $script:dxWarning = "WARNING: corrupted linked list found. Previous (_LIST_ENTRY*) 0xffffa000000962c8, current (_LIST_ENTRY*) 0xffffa000000651c8.`n"
    $corruptRun = Invoke-TestEngineRun
    $corruptNote = "the debugger engine found the kernel's list of processes inconsistent (corrupted linked list), as when memory is copied while Windows runs and processes start or end during the copy, and lists only the 146 processes before that place, so the newest processes can be missing. The kernel's own process structures could not be read to find them."
    Assert-Equal -Name "the engine's own list reports a corrupted list: the warning once, read back by the findings report" -Expected "1|$corruptNote" -Actual "$(@([regex]::Matches($corruptRun.Log, [regex]::Escape("WARNING:   Memory dump process list: $corruptNote"))).Count)|$((Read-ReportEngineBuilderLog -Path $corruptRun.LogFile).MemoryDumpProcessList)"
    $script:dxWarning = ""

    # The engine's own list fails as a whole (the engine's own text): the
    # reason names it
    $script:processQueryText = "Error: Unable to find type '_EPROCESS *' for cast.`n"
    $noProcesses = Invoke-TestEngineRun
    $script:processQueryText = ""
    Assert-Equal -Name "debugger engine: the process query fails as a whole: the reason with the engine's error, no rows" -Expected "the Windows debugger engine listed no processes in it (Error - Unable to find type '_EPROCESS *' for cast)|0|1" -Actual "$($noProcesses.Result.Reason)|$($noProcesses.Rows.Count)|$($noProcesses.Closed)"
    # Session ids of the engine's own list, decided for each process: the
    # session space query fails as a whole, or (as with the symbols of
    # Windows 11 24H2 on ARM64, which have no _MM_SESSION_SPACE) gives only
    # the processes without a session: the token's for the others
    $script:sessionQueryText = "Error: Unable to find type '_MM_SESSION_SPACE *' for cast.`n"
    $tokenRun = Invoke-TestEngineRun
    $script:sessionQueryText = ""
    $script:sessionLines = @($procs[0..145] | ForEach-Object { if ($_.Session -lt 0) { "TBS|0x$($_.E.ToString('x'))|-1" } else { "Unable to find type '_MM_SESSION_SPACE *' for cast." } })
    $mixedRun = Invoke-TestEngineRun
    $script:sessionLines = $defaultSessionLines
    $script:dtText = $script:dtDefault
    $tokenSystem = @($tokenRun.Rows | Where-Object { $_.Contains("Process in memory: System (PID: 4, PPID: 0)") })
    Assert-Equal -Name "the engine's own list, the session query fails as a whole: logged, the token's session ids (none for System), the same rows" -Expected "True|True|1|True" -Actual "$($tokenRun.Log.Contains("    Session ids: Error - Unable to find type '_MM_SESSION_SPACE *' for cast; the token's session id is used for 146 process(es)"))|$($tokenRun.Log.Contains('session ids for 142'))|$(@($tokenSystem | Where-Object { $_.EndsWith('Threads=150 SessionId=') }).Count)|$((Get-TestSortedRows $tokenRun -Plain) -ceq $scanRows)"
    Assert-Equal -Name "the engine's own list, session ids only for the processes without a session: the token's for the others, the same rows" -Expected "True|True|True" -Actual "$($mixedRun.Log.Contains("    Session ids: Unable to find type '_MM_SESSION_SPACE *' for cast; the token's session id is used for 143 process(es)"))|$($mixedRun.Log.Contains('session ids for 142'))|$((Get-TestSortedRows $mixedRun -Plain) -ceq $scanRows)"

    # The kernel's layout from its symbols: what the scan needs, and what
    # it does without
    $layout = Get-DbgEngKernelLayout -Session $null
    Assert-Equal -Name "Get-DbgEngKernelLayout: the EPROCESS offsets and size, the list head, the token's session id and reference count bits, no session space, the process ID table" -Expected "||0x900|0x1c8|0x328|$listHead|120|15|-1|$cidVariable|8|16|20|44" -Actual "$($layout.Error)|$($layout.CidError)|0x$($layout.ProcessSize.ToString('x'))|0x$($layout.Offsets['ActiveProcessLinks'].ToString('x'))|0x$($layout.Offsets['ImageFileName'].ToString('x'))|$($layout.ListHead)|$($layout.TokenSessionId)|$($layout.TokenRefMask)|$($layout.MmSessionId)|$($layout.CidTable)|$($layout.TableCode)|$($layout.EntrySize)|$($layout.PointerPosition)|$($layout.PointerWidth)"
    $script:dtText = $script:dtDefault.Clone()
    $script:dtText["_EPROCESS"] = $dtProcess.Replace("[15] UChar", "[16] UChar").Replace("ActiveThreads    : Uint4B", "ActiveThreads    : Uint8B")
    $wrongTypes = Get-DbgEngKernelLayout -Session $null
    $script:dtText = $script:dtDefault.Clone()
    $script:dtText.Remove("_HANDLE_TABLE_ENTRY")
    $noEntry = Get-DbgEngKernelLayout -Session $null
    $script:dtText = $script:dtDefault
    Assert-Equal -Name "Get-DbgEngKernelLayout: fields of another type than expected are named (the scan is not made); no _HANDLE_TABLE_ENTRY: only the process ID table is not read" -Expected "the kernel's symbols do not give _EPROCESS.ImageFileName, _EPROCESS.ActiveThreads as expected||the kernel's symbols do not give _HANDLE_TABLE_ENTRY.ObjectPointerBits as expected" -Actual "$($wrongTypes.Error)|$($noEntry.Error)|$($noEntry.CidError)"
    $cache = New-Object 'System.Collections.Generic.Dictionary[uint64,object]'
    $capped = Invoke-DbgEngProcessWalk -Session $null -Layout $layout -Cache $cache -MaxEntries 5
    Assert-Equal -Name "Invoke-DbgEngProcessWalk: a walk that does not end within -MaxEntries is capped, not broken" -Expected "5|True|False|False" -Actual "$($capped.Entries.Count)|$($capped.Capped)|$($capped.Broken)|$($capped.Complete)"
    $noCidRun = & {
        $script:dtText = $script:dtDefault.Clone()
        $script:dtText.Remove("_HANDLE_TABLE_ENTRY")
        try { Invoke-TestEngineRun } finally { $script:dtText = $script:dtDefault }
    }
    Assert-Equal -Name "no process ID table in the symbols: both walks, the same rows, said in the counts, no warning" -Expected "True|True|0" -Actual "$((Get-TestSortedRows $noCidRun -Plain) -ceq $scanRows)|$($noCidRun.Log.Contains("    Processes found: 146; the kernel's process list walked forwards 146, backwards 146, its process ID table not read [the kernel's symbols do not give _HANDLE_TABLE_ENTRY.ObjectPointerBits as expected], in the debugger engine's own list 146`r`n"))|$(@([regex]::Matches($noCidRun.Log, 'WARNING')).Count)"
    # The note's wording when the process ID table is not read and the walks disagree
    $fakeWalk = { param([int]$Count, [int]$Mismatches) [PSCustomObject]@{ Entries = @(1..$Count); Mismatches = $Mismatches; Complete = $true; Broken = $false; Capped = $false; Stop = "" } }
    $scanText = Get-DbgEngScanText -Forward (& $fakeWalk 10 0) -Backward (& $fakeWalk 12 1) -Cid ([PSCustomObject]@{ Entries = @(); Error = "it is not in the dump"; UnreadablePages = 0 }) -Methods ([int[]](@(3) * 10 + @(2) * 2))
    Assert-Equal -Name "Get-DbgEngScanText: without the process ID table, both walks named, a process only one walk found, why the table is not read" -Expected "the kernel's list of processes was inconsistent in 1 place, as when memory is copied while Windows runs and processes start or end during the copy. 12 processes were found, 10 of them by both walks of the kernel's process list, 2 only by walking backwards. The process ID table could not be read [it is not in the dump]." -Actual $scanText.Note
    # Many processes only in the table: 10 named, then how many more
    $manyMissed = @(1..12 | ForEach-Object { [PSCustomObject]@{ Pid = 8000 + 4 * $_; Why = $(if ($_ -eq 1) { "Exited" } else { "" }) } })
    $manyText = Get-DbgEngScanText -Forward (& $fakeWalk 10 0) -Backward (& $fakeWalk 10 0) -Cid ([PSCustomObject]@{ Entries = @(1..22); Error = ""; UnreadablePages = 0 }) -Methods ([int[]](@(7) * 10 + @(4) * 12)) -Missed $manyMissed
    Assert-Equal -Name "Get-DbgEngScanText: 12 processes only in the process ID table, 10 of them named (one that had exited said so), then how many more" -Expected "22 processes were found, 10 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 12 only in the process ID table (PID 8004, which had exited; PID 8008; PID 8012; PID 8016; PID 8020; PID 8024; PID 8028; PID 8032; PID 8036; PID 8040; and 2 more)." -Actual $manyText.Note
    # One process ID that cannot be judged and one process of capture churn:
    # the wording for one, the one that cannot be judged first
    $oneChanges = @(
        [PSCustomObject]@{ Address = [Convert]::ToUInt64("ffffa00000002000", 16); Pid = 8010; Kind = "Invalid"; TableIds = @(); When = "" },
        [PSCustomObject]@{ Address = [Convert]::ToUInt64("ffffa00000001000", 16); Pid = 8004; Kind = "Table"; TableIds = @(8100); When = "Churn" }
    )
    $oneText = Get-DbgEngScanText -Forward (& $fakeWalk 10 0) -Backward (& $fakeWalk 10 0) -Cid ([PSCustomObject]@{ Entries = @(1..11); Error = ""; UnreadablePages = 0 }) -Methods ([int[]](@(7) * 10 + @(4))) -Missed @([PSCustomObject]@{ Pid = 8004; Why = "JustBefore" }) -IdChanges $oneChanges
    Assert-Equal -Name "Get-DbgEngScanText: one process ID that cannot be judged, then one process of capture churn (created within the margin before the capture started), in the singular; the churn margin is 120 seconds" -Expected "1 process has a process ID that does not fit (PID 8010 at 0xffffa00000002000, not a multiple of 4 as Windows gives them). Whether copying memory explains that cannot be judged without the capture's start time (the time in the dump's header), so it is not marked. 1 process is capture churn, started while memory was being copied (or at most 120 seconds before it), with a stale process ID table entry (PID 8004 at 0xffffa00000001000, held in the process ID table under ID 8100). The process ID table and a process's memory are copied at different moments, and a short-lived process that ends in between leaves its ID or its memory to a new process, so copying memory explains this; it is not marked. 11 processes were found, 10 of them by all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table), 1 only in the process ID table (PID 8004, created at most 120 seconds before the capture started).|120" -Actual "$($oneText.Note)|$(Get-DbgEngChurnSeconds)"
    $wordCases = @(@(, "a"), @("a", "b"), @("a", "b", "c"), @(1..12 | ForEach-Object { "$_" }))
    Assert-Equal -Name "Join-DbgEngWords: one, two, three, and more than 10 items; with semicolons" -Expected "a|a and b|a, b and c|1, 2, 3, 4, 5, 6, 7, 8, 9, 10 and 2 more|a, x; b|1; 2; 3; 4; 5; 6; 7; 8; 9; 10; and 2 more" -Actual ((@($wordCases | ForEach-Object { Join-DbgEngWords -Items $_ }) + @((Join-DbgEngWords -Items @("a, x", "b") -Semicolons), (Join-DbgEngWords -Items @(1..12 | ForEach-Object { "$_" }) -Semicolons))) -join "|")
    $startCases = @("2026-10-11T05:08:35.9341509Z", "", "not a time", "2026-10-11T05:08:35.9341509+02:00", "1601-01-01T00:00:00.0000000Z")
    Assert-Equal -Name "ConvertFrom-DbgEngCaptureStart: a UTC time as a FILETIME; empty, not a time, not UTC, before 1980: 0" -Expected "$([datetime]::new(2026, 10, 11, 5, 8, 35, [DateTimeKind]::Utc).AddTicks(9341509).ToFileTimeUtc())|0|0|0|0" -Actual ((@($startCases | ForEach-Object { ConvertFrom-DbgEngCaptureStart $_ })) -join "|")

    # A cached symbol file that does not match the dump: deleted, downloaded
    # once more
    [System.IO.File]::WriteAllBytes($cachedFile, ([System.Text.Encoding]::ASCII.GetBytes("Microsoft C/C++ MSF 7.00`r`n") + (New-Object byte[] 70000)))
    $mismatch = Invoke-TestEngineRun
    Assert-Equal -Name "debugger engine: a cached symbol file that does not match: the warning, one download, the rows" -Expected "True|1|287" -Actual "$($mismatch.Log.Contains('WARNING:   The cached kernel symbol file does not match the dump and was deleted; downloading it again.'))|$($mismatch.Downloads)|$($mismatch.Result.Entries)"

    # No internet: the reason, the offline advice, no rows, nothing left
    Remove-Item -LiteralPath $symbolRoot -Recurse -Force
    $script:offline = $true
    $offlineRun = Invoke-TestEngineRun
    $script:offline = $false
    $offlineReason = "the Windows kernel symbol file could not be downloaded from Microsoft's symbol server (No such host is known. [msdl.microsoft.com:443]); connect to the internet and run the builder again, or see ""Windows kernel symbols"" in README.txt"
    Assert-Equal -Name "debugger engine, no internet: the reason, the offline advice, no rows, no partial file, the session closed" -Expected "$offlineReason|True|0|0|1|1" -Actual "$($offlineRun.Result.Reason)|$($offlineRun.Log.Contains("  To analyze it without internet access here, download $expectedUrl on another computer and copy it to $cachedFile, then run the builder again."))|$($offlineRun.Rows.Count)|$(@(Get-ChildItem -LiteralPath $symbolRoot -Recurse -File -Force -ErrorAction SilentlyContinue).Count)|$($offlineRun.Opened)|$($offlineRun.Closed)"

    # The download works but the engine does not accept the file: a newer
    # engine is the advice, not internet access or a copy of the same file
    Remove-Item -LiteralPath $symbolRoot -Recurse -Force -ErrorAction SilentlyContinue
    $script:notAccepted = $true
    $notAcceptedRun = Invoke-TestEngineRun
    $script:notAccepted = $false
    $notAcceptedReason = "the Windows debugger engine did not accept the kernel symbol file from Microsoft's symbol server (this engine may be too old for the dump); put a newer engine in tools\dbgeng\ and run the builder again, see ""Microsoft debugger engine"" in README.txt"
    $notAcceptedWarning = "WARNING:   The Windows debugger engine did not accept the kernel symbol file that Microsoft's symbol server sent for this dump, and it was deleted. This engine may be too old for the dump, or the file was damaged on the way: put a newer engine in tools\dbgeng\ (see ""Microsoft debugger engine"" in README.txt) and run the builder again."
    Assert-Equal -Name "debugger engine, a symbol file the engine does not accept: the reason and the warning name a newer engine, no offline or internet advice, one download, the file deleted, no rows" -Expected "$notAcceptedReason|True|False|1|0|0|1" -Actual "$($notAcceptedRun.Result.Reason)|$($notAcceptedRun.Log.Contains($notAcceptedWarning))|$($notAcceptedRun.Log.Contains('without internet access') -or $notAcceptedRun.Log.Contains('connect to the internet'))|$($notAcceptedRun.Downloads)|$($notAcceptedRun.Rows.Count)|$(@(Get-ChildItem -LiteralPath $symbolRoot -Recurse -File -Force -ErrorAction SilentlyContinue).Count)|$($notAcceptedRun.Closed)"

    # No folder for the symbol file can be written: that is the reason, not
    # internet access
    # (the function: drive changes the function itself, also from a child
    # scope: put back right after)
    $realSymbolFile = ${function:Get-KernelSymbolFile}
    ${function:Get-KernelSymbolFile} = { [PSCustomObject]@{ Path = ""; Folder = ""; Downloaded = $false; Url = $expectedUrl; Error = "Access to the path 'X' is denied"; ErrorKind = "Folder" } }
    try { $folderRun = Invoke-TestEngineRun }
    finally { ${function:Get-KernelSymbolFile} = $realSymbolFile }
    $folderReason = "no folder for the Windows kernel symbol file could be written (Access to the path 'X' is denied); make tools\symbols\ next to the builder writable, or use a -WorkDir that can be written, and run the builder again"
    Assert-Equal -Name "debugger engine, no folder for the symbol file can be written: the reason and the log line name the folders, no offline or internet advice, no rows" -Expected "$folderReason|True|False|0|1" -Actual "$($folderRun.Result.Reason)|$($folderRun.Log.Contains("  Neither tools\symbols\ nor the work folder can be written (Access to the path 'X' is denied), so the kernel symbol file has nowhere to go."))|$($folderRun.Log.Contains('without internet access') -or $folderRun.Log.Contains('connect to the internet'))|$($folderRun.Rows.Count)|$($folderRun.Closed)"

    # The command lines cannot be read: the processes only, and why
    ${function:Read-DbgEngCommandLine} = { throw "boom (in the engine)" }
    $partialRun = Invoke-TestEngineRun
    ${function:Read-DbgEngCommandLine} = $realFunctions["Read-DbgEngCommandLine"]
    Assert-Equal -Name "debugger engine: the command lines cannot be read: the processes, PartialReason, the warning" -Expected "146|146|0|its command lines could not be read [boom [in the engine]]|True" -Actual "$($partialRun.Result.Entries)|$($partialRun.Result.Processes)|$($partialRun.Result.CommandLines)|$($partialRun.Result.PartialReason)|$($partialRun.Log.Contains('WARNING:   Command lines (windows.cmdline rows): none; its command lines could not be read [boom [in the engine]]'))"

    # The engine cannot open the dump; an error while reading: the reasons,
    # and the session closed
    ${function:Open-DbgEngSession} = { throw "OpenDumpFileWide failed (HRESULT 0x80004005)" }
    $notOpened = Invoke-TestEngineRun
    ${function:Open-DbgEngSession} = { $script:opened++; return [PSCustomObject]@{ Fake = $true } }
    $realLayout = ${function:Get-DbgEngKernelLayout}
    ${function:Get-DbgEngKernelLayout} = { throw "the command did not finish within 300 s" }
    try { $stoppedRun = Invoke-TestEngineRun }
    finally { ${function:Get-DbgEngKernelLayout} = $realLayout }
    Assert-Equal -Name "debugger engine: the dump cannot be opened; the engine stops while reading: the reasons, the session closed" -Expected "the Windows debugger engine could not open it (OpenDumpFileWide failed [HRESULT 0x80004005])|0|the Windows debugger engine stopped (the command did not finish within 300 s)|1|1" -Actual "$($notOpened.Result.Reason)|$($notOpened.Closed)|$($stoppedRun.Result.Reason)|$($stoppedRun.Opened)|$($stoppedRun.Closed)"
    . $restoreTestFunctions

    # --- The helper in a process of its own (Start-DbgEngWorker) ----------------
    # The real helper on a fake ARM64 dump, with this computer's engine: the
    # engine cannot open it, and says so. Then stand-in helpers: canned
    # entries with every kind of character through the pipe, a crash, an
    # error, a hang (ended after the time limit), output without its end,
    # and no helper at all.
    Write-Host "Testing the debugger engine helper as a process of its own ..."
    $script:logFile = Join-Path $workDir "engine-process.log"
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    ${function:Get-DbgEngWorkerPath} = { return $workerPath }
    $realHelper = Invoke-DbgEngMemoryAnalysis -DumpPath $fakeDump -DumpInfo $engineDumpInfo
    Assert-Equal -Name "the real helper on a fake ARM64 dump: the engine of Windows logged, it could not open the dump, the work folder removed" -Expected "True|True|0|False" -Actual "$($realHelper.Reason -like 'the Windows debugger engine could not open it (*)')|$((Get-TestLog) -match [regex]::Escape("  Debugger engine: dbgeng.dll ") + '\S+' + [regex]::Escape(" from $system32 (part of Windows)"))|$($realHelper.Entries)|$(Test-Path -LiteralPath (Join-Path $script:runScratchDir 'dbgeng'))"

    ${function:Find-DbgEngine} = { return [PSCustomObject]@{ Path = "C:\stub dir\dbgeng.dll"; Folder = "C:\stub dir"; Source = "Windows"; Version = "10.0.26100.1"; Dlls = @("dbgeng.dll"); Warning = ""; Reason = "" } }
    $helperText = [System.IO.File]::ReadAllText($workerPath)
    $mainAnchor = "# --- Run by the builder ---"
    Assert-Equal -Name "the helper's main block found once (for the stand-in helpers)" -Expected 1 -Actual ([regex]::Matches($helperText, [regex]::Escape($mainAnchor))).Count
    # Canned entries: built from character codes, so this file stays ASCII
    $cannedHelper = Join-Path $engineDir "canned helper.ps1"
    $cannedFunction = @'
function Read-DbgEngDump {
    param([string]$DumpPath, [string]$EngineFolder, [string[]]$EngineDlls, [string]$SymbolCache, [string]$JobFolder, [string]$CaptureStart, [string]$CaptureEnd)
    Write-DbgEngLog "  canned: $DumpPath|$EngineFolder|$($EngineDlls -join '+')|$SymbolCache|$JobFolder|$CaptureStart|$CaptureEnd"
    Write-DbgEngLog -Warning "  canned warning"
    $result = New-DbgEngResult
    $text = "say ""hi""|there`ttab`r`nnext " + [string][char]0x00FC + [char]0x4E2D + [char]0x20AC + [char]0xD83D + [char]0xDE00 + [char]0xFFFE + " end"
    $result.Processes = @(
        [PSCustomObject]@{ PID = [long]4321; PPID = [long]3000; ImageFileName = ("fixture " + [char]0x00E9 + "|x"); Offset = "0xffffa00000001000"; Threads = [long]3; SessionId = $null; CreateTime = "2026-10-10T23:59:01.1234567+00:00"; ExitTime = $null; FoundBy = "ListForward,ProcessIdTable"; TableId = "15804"; Anomaly = "NotInProcessList,ProcessIdChanged" },
        [PSCustomObject]@{ PID = [long]4400; PPID = $null; ImageFileName = ""; Offset = "0xffffa00000002000"; Threads = $null; SessionId = [long]0; CreateTime = $null; ExitTime = "2026-10-10T23:59:02.0000000+00:00" }
    )
    $result.CommandLines = @([PSCustomObject]@{ PID = [long]4321; Process = "fixture-stage.exe"; Args = $text }, [PSCustomObject]@{ PID = [long]4400; Process = "long.exe"; Args = ("y" * 32767) })
    $result.BadItems = 1
    $result.SessionIds = 1
    $result.NoPeb = 2
    $result.Unreadable = 3
    $result.Empty = 4
    $result.Seconds = 1.5
    $result.Entries = @([PSCustomObject]@{ Kind = "Module"; Fields = [ordered]@{ PID = "4321"; Path = $text } })
    $result.Areas = @([PSCustomObject]@{ Name = "Modules"; State = "Partial"; Rows = 1; Seconds = 0.5; Note = "1 process's loader list could not be read" })
    return $result
}

'@
    [System.IO.File]::WriteAllText($cannedHelper, $helperText.Replace($mainAnchor, $cannedFunction + $mainAnchor))
    ${function:Get-DbgEngWorkerPath} = { return $script:testHelperPath }
    $script:testHelperPath = $cannedHelper
    $script:logFile = Join-Path $workDir "engine-canned.log"
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cannedResult = Invoke-DbgEngMemoryAnalysis -DumpPath $engineDump -DumpInfo $engineDumpInfo
    $cannedLog = Get-TestLog
    $cannedText = "say ""hi""|there`ttab`r`nnext " + [string][char]0x00FC + [char]0x4E2D + [char]0x20AC + [char]0xD83D + [char]0xDE00 + [char]0xFFFE + " end"
    $cannedRows = @($script:timelineEntries | ForEach-Object { "$($_.Source)|$($_.Timestamp)|$($_.EventType)|$($_.Description)|$($_.Details)" })
    $expectedCanned = @(
        "Memory-Processes|2026-10-10 23:59:01.123|ProcessCreation|Process in memory: fixture $([char]0x00E9)|x (PID: 4321, PPID: 3000)|Threads=3 SessionId= FoundBy=ListForward,ProcessIdTable TableId=15804 Anomaly=NotInProcessList,ProcessIdChanged",
        "Memory-Processes|$captureRowTime|Snapshot|Process in memory: Unknown (PID: 4400, PPID: )|Threads= SessionId=0",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: fixture-stage.exe (PID: 4321)|Args=$($script:xmlInvalidRegex.Replace($cannedText, ''))",
        "Memory-CommandLine|$captureRowTime|Snapshot|Process command line: long.exe (PID: 4400)|Args=$("y" * 32767)"
    )
    Assert-Equal -Name "the helper as a process: canned entries (non-ASCII, |, quotes, CR/LF, tab, a surrogate pair, U+FFFE, 32,767 characters) come through the pipe whole, as rows" -Expected ($expectedCanned -join "`n") -Actual ($cannedRows -join "`n")
    $argumentLine = "  canned: $engineDump|C:\stub dir|dbgeng.dll|$symbolRoot|$(Join-Path $script:runScratchDir 'dbgeng')|2026-10-11T00:09:00.0000000Z|2026-10-11T00:11:00.0000000Z"
    Assert-Equal -Name "the helper as a process: its arguments (spaces, [ ], non-ASCII), its log lines relayed (a warning too), the counts logged" -Expected "True|True|True|True|4" -Actual "$($cannedLog.Contains($argumentLine))|$($cannedLog.Contains('WARNING:   canned warning'))|$($cannedLog.Contains('    Processes (windows.pslist rows): 2 entries (1 timed, 1 snapshot); 1 list item(s) could not be read; session ids for 1'))|$($cannedLog.Contains('    Command lines (windows.cmdline rows): 2 entries; none for 2 kernel process(es) without a PEB, 3 not readable (paged out or exited), 4 empty; 1.5 s'))|$($cannedResult.Entries)"
    $script:logFile = Join-Path $workDir "engine-direct.log"
    $state = Start-DbgEngWorker -WorkerPath $cannedHelper -WorkingDirectory $engineDir -TimeoutSeconds 120 -Arguments ([ordered]@{ DumpPath = $engineDump; EngineFolder = "C:\x\"; EngineDlls = "a.dll,b.dll"; SymbolCache = "C:\y"; JobFolder = $engineDir })
    Assert-Equal -Name "Start-DbgEngWorker: the entries exactly as sent (U+FFFE too), the END line, exit code 0, a trailing backslash in an argument" -Expected "True|True|0|0|True|True" -Actual "$($state.CommandLines[0].Args -ceq $cannedText)|$($state.Ended)|$($state.ExitCode)|$($state.BadLines)|$((Get-TestLog).Contains("  canned: $engineDump|C:\x\|a.dll+b.dll|C:\y|$engineDir"))|$($state.Processes[1].ExitTime -eq '2026-10-10T23:59:02.0000000+00:00' -and $null -eq $state.Processes[1].CreateTime -and $null -eq $state.Processes[1].PPID)"
    Assert-Equal -Name "Start-DbgEngWorker: an area's entry exactly as sent (E line), its AREA line, the END line with the three counts" -Expected "1|4321|True|Modules|Partial|1|0.5|1 process's loader list could not be read" `
        -Actual "$($state.EntryCount)|$($state.Entries['Module'][0].PID)|$($state.Entries['Module'][0].Path -ceq $cannedText)|$($state.Areas[0].Name)|$($state.Areas[0].State)|$($state.Areas[0].Rows)|$($state.Areas[0].Seconds)|$($state.Areas[0].Note)"
    $readStart = $cannedResult.ReadText.StartsWith('read processes, command lines, DLLs; not read process users and paths (not reported by the debugger engine helper), kernel drivers (not reported')
    $moduleRowsLogged = $cannedLog.Contains('    Memory-Modules rows (Module entries): 0 of 1 entries (0 timed, 0 snapshot)')
    Assert-Equal -Name "the helper as a process: the areas' entries counted, the read text and the coverage text (an area not reported says so)" -Expected "True|DLLs -- 1 process's loader list could not be read|True" `
        -Actual "$readStart|$(@($cannedResult.CoverageTexts) -join ' / ')|$moduleRowsLogged"

    $standIns = @(
        @{ Name = "a crash"; Script = '[Environment]::Exit(-1073741819)'; Reason = "the Windows debugger engine stopped (exit code 0xC0000005)" },
        @{ Name = "an error"; Script = 'throw "boom in the helper"'; Reason = "the Windows debugger engine stopped (exit code 1 - boom in the helper)" },
        @{ Name = "output without its end"; Script = '[Console]::Out.WriteLine("TBDBG|LOG|I|" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("  half-way"))); [Console]::Out.WriteLine("TBDBG|P|1|2"); exit 0'; Reason = "the Windows debugger engine stopped (exit code 0)"; Log = "  half-way" }
    )
    foreach ($case in $standIns) {
        $script:testHelperPath = Join-Path $engineDir "stand-in $($standIns.IndexOf($case)).ps1"
        [System.IO.File]::WriteAllText($script:testHelperPath, "param([string]`$DumpPath, [string]`$EngineFolder, [string]`$EngineDlls, [string]`$SymbolCache, [string]`$JobFolder, [string]`$CaptureStart, [string]`$CaptureEnd)`r`n$($case.Script)`r`n")
        $script:logFile = Join-Path $workDir ("engine-stand-in-" + [guid]::NewGuid().ToString("N") + ".log")
        $standIn = Invoke-DbgEngMemoryAnalysis -DumpPath $engineDump -DumpInfo $engineDumpInfo
        Assert-Equal -Name "the helper as a process, $($case.Name): the reason$(if ($case.Log) { ', its log line relayed' })" -Expected "$($case.Reason)|0|True" -Actual "$($standIn.Reason)|$($standIn.Entries)|$(-not $case.Log -or (Get-TestLog).Contains($case.Log))"
    }
    $script:testHelperPath = Join-Path $engineDir "stand-in hang.ps1"
    $pidFile = Join-Path $engineDir "hang.pid"
    [System.IO.File]::WriteAllText($script:testHelperPath, "param([string]`$DumpPath, [string]`$EngineFolder, [string]`$EngineDlls, [string]`$SymbolCache, [string]`$JobFolder, [string]`$CaptureStart, [string]`$CaptureEnd)`r`n[System.IO.File]::WriteAllText('$($pidFile.Replace("'", "''"))', `"`$PID`")`r`nStart-Sleep -Seconds 120`r`n")
    $script:dbgEngTimeoutSeconds = 4
    $hangTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $hang = Invoke-DbgEngMemoryAnalysis -DumpPath $engineDump -DumpInfo $engineDumpInfo
    $hangSeconds = $hangTimer.Elapsed.TotalSeconds
    $script:dbgEngTimeoutSeconds = 900
    $hangPid = 0
    if (Test-Path -LiteralPath $pidFile) { $hangPid = [int]([System.IO.File]::ReadAllText($pidFile).Trim()) }
    $hangGone = $hangPid -gt 0 -and -not (Get-Process -Id $hangPid -ErrorAction SilentlyContinue)
    Assert-Equal -Name "the helper as a process, a hang: ended after the time limit, the reason" -Expected "the Windows debugger engine did not finish within 4 seconds|True|True" -Actual "$($hang.Reason)|$hangGone|$($hangSeconds -lt 60)"
    $script:testHelperPath = Join-Path $engineDir "no such helper.ps1"
    $noHelper = Invoke-DbgEngMemoryAnalysis -DumpPath $engineDump -DumpInfo $engineDumpInfo
    Assert-Equal -Name "no helper script: the reason" -Expected "the debugger engine helper lib\memory\TimelineDbgEng.ps1 is missing, an antivirus may have removed it; copy the whole win11-timeline-builder folder again" -Actual $noHelper.Reason
    ${function:Find-DbgEngine} = { return [PSCustomObject]@{ Path = ""; Folder = ""; Source = ""; Version = ""; Dlls = @(); Warning = "tools\dbgeng\arm64\ is not used: x"; Reason = "the Windows debugger engine (dbgeng.dll) is not in C:\none" } }
    $script:logFile = Join-Path $workDir "engine-none.log"
    $noEngine = Invoke-DbgEngMemoryAnalysis -DumpPath $engineDump -DumpInfo $engineDumpInfo
    Assert-Equal -Name "no debugger engine: the reason with the README section, the warning logged" -Expected "the Windows debugger engine (dbgeng.dll) is not in C:\none; see ""ARM64 memory dumps"" in README.txt|True" -Actual "$($noEngine.Reason)|$((Get-TestLog).Contains('WARNING:   tools\dbgeng\arm64\ is not used: x'))"
    $errorLines = @(
        @("C:\x\TimelineDbgEng.ps1 : This script contains malicious content and has been blocked by your antivirus software.`r`n    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException", "This script contains malicious content and has been blocked by your antivirus software"),
        @("Exception: C:\x\stand-in.ps1:2`r`nLine |`r`n   2 |  throw ""boom""`r`n     |  ~~~~~~~~~~~~`r`n     | boom: it failed", "boom - it failed"),
        @("", "")
    )
    Assert-Equal -Name "Get-DbgEngWorkerErrorLine: the message of Windows PowerShell's and PowerShell 7's error output" -Expected (($errorLines | ForEach-Object { $_[1] }) -join "|") -Actual (($errorLines | ForEach-Object { Get-DbgEngWorkerErrorLine $_[0] }) -join "|")
    Assert-Equal -Name "Format-DbgEngExitCode: decimal, hex for a Windows error" -Expected "0|1|0xC0000005|0xC000013A|unknown" -Actual ((@(0, 1, -1073741819, 3221225786, $null) | ForEach-Object { Format-DbgEngExitCode $_ }) -join "|")
    . $restoreTestFunctions
    $script:runScratchDir = $null
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
