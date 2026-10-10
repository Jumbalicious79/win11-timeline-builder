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
# report reads; for a collection from a Windows ARM64 computer
# (systeminfo.txt) it gives no copy advice and names WinDbg; the dump of a
# renamed collection folder is named after the folder's original name.
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
        $expected = "No memory dump to offer: $($case.Note).`r`n  To have it analyzed, $($case.Remedy), then run the builder again.`r`n  Memory dump not analyzed: collection_manifest.csv lists one$($case.Size), but it was not found (or not usable) next to the collection or where the collector saved it."
        if ($case.Name -like "no *") { $expected = "" }
        Assert-Equal -Name "offer step without a dump, $($case.Name): $(if ($expected) { 'what the manifest lists, how to have the dump analyzed, and the line for the report' } else { 'nothing logged' })" -Expected "$expected|False" -Actual "$($log.Trim())|$($log.Contains('-MemoryDumpPath'))"
    }
    # A collection from a Windows ARM64 computer (systeminfo.txt): copying
    # the dump would not help (Volatility 3 cannot analyze ARM64 memory), so
    # there is no copy advice, and WinDbg is named
    $nameArm = "TriageCollection_2025-06-19_07-45"
    $collectionArm = Join-Path $reports $nameArm
    New-TestManifestCollection -Path $collectionArm -CollectedAt "$origReports\$nameArm" -DumpDest "$origReports\$nameArm\Memory\memory_dump.dmp" -DumpRel "Memory\memory_dump.dmp" -DumpSize "8583323648"
    [void][System.IO.Directory]::CreateDirectory((Join-Path $collectionArm "SystemInfo"))
    [System.IO.File]::WriteAllText((Join-Path $collectionArm "SystemInfo\systeminfo.txt"), "`r`nHost Name:                 WS01`r`nOS Name:                   Microsoft Windows 11 Pro`r`nSystem Type:               ARM64-based PC`r`n")
    Set-TestRunState -Collection $collectionArm
    Write-NoMemoryDumpToOffer
    $log = ((Get-TestLog) -replace '(?m)^\[[0-9: -]+\] ', '').Trim()
    $expected = "No memory dump to offer: collection_manifest.csv lists one in the collection (Memory\memory_dump.dmp), which the collector moves next to the zip as ${nameArm}_memory_dump.dmp when it zips the collection.`r`n" +
        "  The collection is from a Windows ARM64 computer, and Volatility 3 cannot analyze Windows ARM64 memory, so the dump is not needed here: open it in WinDbg to examine it.`r`n" +
        "  Memory dump not analyzed: collection_manifest.csv lists one (8 GB): a Windows ARM64 dump (the collection's systeminfo.txt says ARM64), which Volatility 3 cannot analyze; examine it in WinDbg."
    Assert-Equal -Name "offer step without a dump, an ARM64 collection: no copy advice, WinDbg named, and the line for the report" -Expected $expected -Actual $log
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

    # Parse-Memory logs the dump time (an ARM64 dump: it stops before
    # looking for Volatility 3)
    $armDump = Join-Path $workDir "dumps [7]\${nameC}_memory_dump.dmp"
    New-TestDump -Path $armDump -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $armDump
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory: the dump time from the header is logged" -Expected "True|True" -Actual "$($log.Contains("Found memory dump: $armDump (0 GB, ARM64)"))|$($log.Contains("Dump time: $captureText UTC (crash dump header)"))"
    # Without -MemoryDumpPath: the dump where the collector saved it, on
    # another drive (collection_manifest.csv)
    New-TestDump -Path $driveK -Machine 0xAA64 -SystemTime $captureFileTime -LastWriteUtc $endUtc
    New-TestManifestCollection -Path (Join-Path $reports $nameK) -CollectedAt "$origReports\$nameK" -DumpDest $driveK -DumpSize "8192"
    Set-TestRunState -Collection (Join-Path $reports $nameK)
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory: the dump where the collector saved it, by collection_manifest.csv" -Expected "True|True|True" -Actual "$($log.Contains("$foundNotice $driveK (8192 bytes, as listed)."))|$($log.Contains("Found memory dump: $driveK (0 GB, ARM64)"))|$($log.Contains("Dump time: $captureText UTC (crash dump header)"))"

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
