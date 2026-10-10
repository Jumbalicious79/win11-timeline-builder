# =============================================================
# Zip input and work folder test
# Windows Storage Sense once deleted extracted collection files from
# %TEMP% while a timeline was being built, and the run still reported
# success. This test checks the fix.
#
# Part 1 -- unit checks (no admin, always run): loads the builder's
#   functions without running it and checks Expand-CollectionZip (entry
#   names with "/" and "\", folder entries, original entry dates, an
#   over-long name shortened with its original name kept for the manifest
#   lookup, a ".." entry not written outside the folder, copied email
#   attachments left in the zip, nothing extracted when the zip does not
#   fit), the rename of an extracted top folder whose name has [ ] (the
#   input-file list and shortened-name map follow it), the manifest
#   lookups from an outer folder (also the email
#   parser's), the input-file list of a collection folder (no memory dump
#   or attachment copy) and the list of missing files, the setupapi logs
#   found (also under names shortened on extraction; email attachment
#   copies and Secrets\ skipped) and those the manifest lists but that are
#   gone, the free-space verdict, the temp-folder check (8.3 short paths
#   and relative paths too), the end-of-run hive list, the clean-up of
#   work folders left by earlier runs, the SRUM database copy (made in the
#   work folder's scratch folder, a missing transaction log reported), the
#   refusal of a network work folder, the end-of-run banners (missing
#   input files, unexpected errors) and the files of a collection folder
#   whose paths have 260 or more characters (named in Windows PowerShell
#   5.1, which cannot open them; none in PowerShell 7; memory dumps and
#   email attachment copies never).
# Part 2 -- builder runs: a synthetic collection zip whose entries are dated
#   2025, with two setupapi logs (USBSTOR devices) under "/" and "\" entry
#   names and a manifest, passed as -InputPath (-Sources USB):
#   - both logs are parsed (USBDevice rows; the USB parser logs "Found 2
#     SetupAPI log(s)"), exit code 0, the extraction and the free-space
#     check are in the log;
#   - the work folder is in %LOCALAPPDATA%\TimelineBuilder, outside every
#     temp folder, and removed at the end; no TriageExtract_* or
#     TimelineHive_* is left in %TEMP%; the zip is not changed;
#   - with the builder's test hook deleting one extracted file mid-run
#     (TIMELINE_BUILDER_TEST_DELETE_INPUT; it only deletes inside the work
#     folder) and -WorkDir: exit code 2, the "MISSING INPUT FILE(S)"
#     banner, the USB parser's warning naming the setupapi log that the
#     manifest lists but that is gone, the work folder made in -WorkDir
#     and removed, -WorkDir kept; this run keeps its findings report (in a
#     folder of its own), which must say the timeline is incomplete, hash
#     the zip and have collection_info.json copied next to it (the other
#     runs use -NoReport, so no run overwrites another's report);
#   - a zip with a copied email attachment (-Sources Email), the test hook
#     pointed at it: it is not extracted, so there is nothing to delete;
#     exit code 0 and its two rows, from the manifest;
#   - -WorkDir with [ ] in its path: the run stops at the start with exit
#     code 1 and an error (the parsers would find nothing there);
#   - a zip "Case [1].zip" whose top folder is "Case [1]": its extracted
#     copy is renamed "Case _1_", exit code 0, both logs parsed, every
#     input file found; run B's report says "incomplete" only twice (the
#     caveat and Evidence coverage);
#   - a collection folder holding a file whose path has 260 or more
#     characters: in Windows PowerShell 5.1 the run stops at the start
#     (exit code 1) and names it; PowerShell 7 builds the timeline;
#   - a collection folder whose own path has 250 characters (even the files
#     right in it have 260+): in Windows PowerShell 5.1 the run stops at
#     the start (exit code 1) and says the folder's path is too long, with
#     its length, instead of counting a few names; PowerShell 7 builds the
#     timeline;
#     (both long-path cases expect the PowerShell 7 result in 5.1 too when
#     Windows long paths are enabled, as on the GitHub runners);
#   - a .7z and a memory dump with [ ] in their names: "Input path is a
#     file" (exit code 1; for the dump, a hint to give its collection), not
#     the folder-wildcard error;
#   - the builder copied into a folder named "inst [1]": it stops at the
#     start (exit code 1) with an error about its folder, writing nothing;
#   - a folder that holds collection zips: no entries, exit code 0, and a
#     hint to drop one .zip on Run-TimelineBuilder.bat.
#   Needs Administrator rights, like the builder itself (GitHub Actions
#   Windows runners are elevated). For a local run without them, pass
#   -BuilderPath with a copy of the builder that has no admin check, kept
#   inside the repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ZipInput.ps1
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
$builder = (Resolve-Path -LiteralPath $builder).Path
$builderDir = Split-Path $builder -Parent
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
        Write-Host "::error file=tests/Test-ZipInput.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Write a zip with the given entries (name -> text; $null = folder entry),
# every entry dated $EntryDate (local time, as zip tools store it). Names
# are used as given, so both "/" and "\" separators can be tested.
function New-TestZip {
    param([string]$Path, [System.Collections.Specialized.OrderedDictionary]$Entries, [datetime]$EntryDate)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive -ArgumentList $stream, ([System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($name in $Entries.Keys) {
                $entry = $zip.CreateEntry($name)
                $entry.LastWriteTime = New-Object DateTimeOffset -ArgumentList $EntryDate
                if ($null -eq $Entries[$name]) { continue }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Entries[$name])
                $entryStream = $entry.Open()
                try { $entryStream.Write($bytes, 0, $bytes.Length) }
                finally { $entryStream.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $stream.Dispose() }
}

# collection_manifest.csv text (the collector's columns) for the given
# relative paths; every file gets the same original times
function New-TestManifest {
    param([string[]]$RelativePaths)
    $lines = @("SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath,SourceCreatedUtc,SourceModifiedUtc,SourceAccessedUtc")
    foreach ($rel in $RelativePaths) {
        $lines += ('"0000","C:\Source\{0}","D:\Collection\{0}","1","2025-01-01 00:00:00","{0}","2024-03-01 10:00:00","2024-03-02 11:00:00","2024-03-03 12:00:00"' -f $rel)
    }
    return ($lines -join "`r`n") + "`r`n"
}

# A setupapi.dev.log section installing one USB storage device
function New-SetupApiText {
    param([string]$Instance, [string]$LocalTime)
    return ">>>  [Device Install (Hardware initiated) - $Instance]`r`n" +
        ">>>  Section start $LocalTime`r`n" +
        "     ump: Creating Install Process: DrvInst.exe`r`n" +
        "<<<  Section end $LocalTime`r`n" +
        "<<<  [Exit status: SUCCESS]`r`n"
}

$entryDate = New-Object DateTime -ArgumentList 2025, 1, 1, 0, 0, 0
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("zip-input-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot | Out-Null

try {
    # =============================================================
    # Part 1: unit checks
    # =============================================================
    Write-Host "Part 1: work folder and zip functions ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion), $builder)"
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        Write-TestResult -Name "builder parses" -Passed $false -Message "$($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
        exit 1
    }
    # Every function that is not inside another function (most sit inside
    # the builder's main try block), and the GetLongPathName declaration
    $nodes = $ast.FindAll({
            param($node)
            ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -or
            ($node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Extent.Text -match "TimelineNative\.LongPath'\)\.Type")
        }, $true) | Where-Object {
        $parent = $_.Parent
        while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
        $null -eq $parent
    }
    foreach ($node in $nodes) { . ([scriptblock]::Create($node.Extent.Text)) }

    # Builder state the functions use
    $logFile = Join-Path $testRoot "unit.log"
    $script:inputFiles = New-Object System.Collections.Generic.List[string]
    $script:shortenedNames = @{}
    $script:collectionManifest = $null
    $script:manifestTimes = $null
    $script:runWorkDir = $null
    $script:runWorkLock = $null
    $script:runScratchDir = $null

    # --- Expand-CollectionZip --------------------------------------------
    $longName = ("LongName_" * 24) + ".lnk"
    $longRel = "UserActivity\alice\Recent\$longName"
    # Copied email attachments (both folders, both separators) stay in the
    # zip; the email listing next to them is extracted
    $classicCopy = "Email\alice\Outlook\SecureTemp\INetCache\ABCD1234\invoice.docm"
    $newOutlookCopy = "Email\alice\NewOutlook\Attachments\0f1e2d3c\report.pdf"
    $emailListing = "Email\alice\Outlook\outlook_temp_files.csv"
    $unitEntries = [ordered]@{
        "Coll/"                          = $null
        "Coll/USB/setupapi.dev.log"      = "forward slashes"
        "Coll\Registry\alice\NTUSER.DAT" = "backslashes"
        "Coll/$($longRel.Replace('\', '/'))" = "long name"
        "Coll/$($classicCopy.Replace('\', '/'))" = "attachment"
        "Coll\$newOutlookCopy"           = "attachment"
        "Coll/$($emailListing.Replace('\', '/'))" = "listing"
        "Coll/collection_manifest.csv"   = (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", "Registry\alice\NTUSER.DAT", $longRel, $classicCopy, $newOutlookCopy, $emailListing))
        "../escape.txt"                  = "must not be written"
    }
    $unitZip = Join-Path $testRoot "unit.zip"
    New-TestZip -Path $unitZip -Entries $unitEntries -EntryDate $entryDate
    $zipNames = @()
    $readZip = [System.IO.Compression.ZipFile]::OpenRead($unitZip)
    try { $zipNames = @($readZip.Entries | ForEach-Object { $_.FullName }) } finally { $readZip.Dispose() }
    Assert-Equal -Name "test zip keeps a backslash entry name" -Expected $true -Actual ($zipNames -ccontains "Coll\Registry\alice\NTUSER.DAT")

    $dest = Join-Path $testRoot "x\in"
    Expand-CollectionZip -ZipPath $unitZip -Destination $dest
    $coll = Join-Path $dest "Coll"
    $unitLog = Get-Content -LiteralPath $logFile -Raw
    Assert-Equal -Name "entry with / separators extracted into its folder" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $coll "USB\setupapi.dev.log") -PathType Leaf)
    Assert-Equal -Name "entry with \ separators extracted into its folder" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $coll "Registry\alice\NTUSER.DAT") -PathType Leaf)
    Assert-Equal -Name "'..' entry not written outside the extraction folder" -Expected $false -Actual (Test-Path -LiteralPath (Join-Path $testRoot "x\escape.txt"))
    Assert-Equal -Name "'..' entry logged as skipped" -Expected $true -Actual ($unitLog -match [regex]::Escape("Zip entry skipped (it would be written outside the extraction folder): ../escape.txt"))
    $recent = Join-Path $coll "UserActivity\alice\Recent"
    $shortFile = @(Get-ChildItem -LiteralPath $recent -File)
    Assert-Equal -Name "over-long name extracted once" -Expected 1 -Actual $shortFile.Count
    if ($shortFile.Count -eq 1) {
        $shortPath = $shortFile[0].FullName
        Write-TestResult -Name "over-long name shortened to 240 characters or less, with a hash" -Passed ($shortPath.Length -le 240 -and $shortFile[0].Name -match '^LongName_.*~[0-9A-F]{8}\.lnk$') -Message "$($shortPath.Length) characters: $($shortFile[0].Name)"
        Assert-Equal -Name "shortened file mapped to its full-length path" -Expected (Join-Path $recent $longName) -Actual $script:shortenedNames[$shortPath]
    }
    Assert-Equal -Name "copied email attachments not extracted (/ and \ entry names)" -Expected "False False" -Actual "$(Test-Path -LiteralPath (Join-Path $coll $classicCopy)) $(Test-Path -LiteralPath (Join-Path $coll $newOutlookCopy))"
    Assert-Equal -Name "the email listing next to them is extracted" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $coll $emailListing) -PathType Leaf)
    Assert-Equal -Name "zip size logged with every file, attachments left in the zip logged" -Expected $true -Actual (
        $unitLog -match "Zip: .+ -- 9 entries, 8 file\(s\)" -and $unitLog -match "Not extracted: 2 copied email attachment\(s\)")
    $extracted = @(Get-ChildItem -LiteralPath $dest -Recurse -File)
    Assert-Equal -Name "files extracted (folder entry, '..' entry and attachment copies skipped)" -Expected 5 -Actual $extracted.Count
    Assert-Equal -Name "extracted files recorded as input files" -Expected 5 -Actual $script:inputFiles.Count
    $wrongDates = @($extracted | Where-Object { $_.LastWriteTime -ne $entryDate } | ForEach-Object { "$($_.Name)=$($_.LastWriteTime.ToString('s'))" })
    Assert-Equal -Name "extracted files keep the zip entry date (2025-01-01)" -Expected "" -Actual ($wrongDates -join ", ")

    # A zip that does not fit on the drive: nothing is extracted. The stub
    # replaces the free-space check only inside this script block (functions
    # are looked up through the caller's scopes).
    $noSpaceDest = Join-Path $testRoot "nospace\in"
    $noSpaceError = & {
        function Test-ExtractionSpace { return $false }
        try { Expand-CollectionZip -ZipPath $unitZip -Destination $noSpaceDest; "" }
        catch { $_.Exception.Message }
    }
    Assert-Equal -Name "zip that does not fit: extraction stops" -Expected "not enough free space to extract the zip" -Actual $noSpaceError
    Assert-Equal -Name "zip that does not fit: nothing extracted or recorded" -Expected "0 5" -Actual "$(@(Get-ChildItem -LiteralPath $noSpaceDest -Recurse -File -ErrorAction SilentlyContinue).Count) $($script:inputFiles.Count)"

    # --- A zip's top folder with [ ] in its name: the extracted copy is
    # renamed, and the input-file list and the shortened-name map follow ---
    $savedInputFiles = $script:inputFiles
    $savedShortenedNames = $script:shortenedNames
    $wildIn = Join-Path $testRoot "wild\in"
    $wildFolder = Join-Path $wildIn "Case [1]"
    [void][System.IO.Directory]::CreateDirectory((Join-Path $wildFolder "USB"))
    $wildFile = Join-Path $wildFolder "USB\setupapi.dev.log"
    [System.IO.File]::WriteAllText($wildFile, "x")
    $otherFile = Join-Path $testRoot "wild\other.txt"
    $script:inputFiles = New-Object System.Collections.Generic.List[string]
    $script:inputFiles.Add($wildFile)
    $script:inputFiles.Add($otherFile)
    $script:shortenedNames = @{ $wildFile = (Join-Path $wildFolder "USB\setupapi.dev.full-length-name.log") }
    $logBefore = @(Get-Content -LiteralPath $logFile).Count
    $safeFolder = Get-WildcardSafeFolder -Folder $wildFolder
    $renameLog = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $logBefore) -join "`n"
    $expectedSafe = Join-Path $wildIn "Case _1_"
    Assert-Equal -Name "zip top folder with [ ]: renamed to Case _1_" -Expected $expectedSafe -Actual $safeFolder
    Assert-Equal -Name "zip top folder with [ ]: the folder and its files moved" -Expected "True False" -Actual "$(Test-Path -LiteralPath (Join-Path $expectedSafe 'USB\setupapi.dev.log') -PathType Leaf) $([System.IO.Directory]::Exists($wildFolder))"
    Assert-Equal -Name "zip top folder with [ ]: the input-file list follows (a file elsewhere is kept)" -Expected "$(Join-Path $expectedSafe 'USB\setupapi.dev.log')|$otherFile" -Actual ($script:inputFiles -join "|")
    Assert-Equal -Name "zip top folder with [ ]: the shortened-name map follows" -Expected "$(Join-Path $expectedSafe 'USB\setupapi.dev.full-length-name.log')" -Actual $script:shortenedNames[(Join-Path $expectedSafe 'USB\setupapi.dev.log')]
    Assert-Equal -Name "zip top folder with [ ]: the rename is logged" -Expected $true -Actual ($renameLog -match [regex]::Escape("its extracted copy was renamed to 'Case _1_'"))
    Assert-Equal -Name "a folder name without wildcard characters is used as it is" -Expected $expectedSafe -Actual (Get-WildcardSafeFolder -Folder $expectedSafe)
    $script:inputFiles = $savedInputFiles
    $script:shortenedNames = $savedShortenedNames

    # --- Manifest lookups (shortened name, outer folder) -----------------
    # -InputPath as the builder's functions read it
    Set-Variable -Name InputPath -Value $coll -Scope Script
    $script:collectionRoot = Get-CollectionRootFolder
    if ($shortFile.Count -eq 1) {
        $times = Get-SourceFileTimes $shortFile[0].FullName
        $modified = ""
        if ($times -and $times.Modified) { $modified = $times.Modified.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) }
        Assert-Equal -Name "original file times found for a shortened file" -Expected "2024-03-02 11:00:00" -Actual $modified
    }
    # The zip extracted with Windows "Extract All" gives an outer folder: the
    # manifest's own folder is still the collection root
    Set-Variable -Name InputPath -Value $dest -Scope Script
    $script:collectionManifest = $null
    $script:manifestTimes = $null
    $script:collectionRoot = Get-CollectionRootFolder
    Assert-Equal -Name "collection root is the manifest's folder for an outer -InputPath" -Expected $coll -Actual $script:collectionRoot
    Assert-Equal -Name "user from the collection layout below an outer folder" -Expected "alice" -Actual (Get-CollectionUser (Join-Path $coll "Registry\alice\NTUSER.DAT"))
    $times = Get-SourceFileTimes (Join-Path $coll "USB\setupapi.dev.log")
    $modified = ""
    if ($times -and $times.Modified) { $modified = $times.Modified.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) }
    Assert-Equal -Name "original file times found below an outer folder" -Expected "2024-03-02 11:00:00" -Actual $modified
    Assert-Equal -Name "manifest lists a collected file" -Expected $true -Actual (Test-ManifestListsFile (Join-Path $coll "Registry\alice\NTUSER.DAT"))
    Assert-Equal -Name "manifest does not list a file it lacks" -Expected $false -Actual (Test-ManifestListsFile (Join-Path $coll "Registry\alice\NTUSER.DAT.LOG1"))
    # The email parser reads the same manifest: the collection's own (the
    # nearest), not the first one a recursive search finds (a deeper one
    # in a folder that sorts first)
    $emailOuter = Join-Path $testRoot "email-outer"
    $emailColl = Join-Path $emailOuter "Coll"
    $decoyDir = Join-Path $emailOuter "Aaa\deeper"
    New-Item -ItemType Directory -Path $emailColl, $decoyDir -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $decoyDir "collection_manifest.csv"), (New-TestManifest -RelativePaths @("Email\decoy\NewOutlook\UserSettings.json")))
    [System.IO.File]::WriteAllText((Join-Path $emailColl "collection_manifest.csv"), (New-TestManifest -RelativePaths @("Email\alice\NewOutlook\UserSettings.json", "USB\setupapi.dev.log")))
    Set-Variable -Name InputPath -Value $emailOuter -Scope Script
    $script:collectionManifest = $null
    $script:collectionInfo = $null
    $script:collectionRoot = Get-CollectionRootFolder
    Assert-Equal -Name "email manifest rows from the collection's own manifest below an outer folder" -Expected "Email\alice\NewOutlook\UserSettings.json" -Actual (@((Get-EmailManifestRows).Keys | Sort-Object) -join ", ")

    # --- Input files of a collection folder ------------------------------
    $folderColl = Join-Path $testRoot "folder\Coll"
    foreach ($rel in @("USB\setupapi.dev.log", "Registry\SYSTEM", "Memory\Coll_memory_dump.dmp", $classicCopy)) {
        $file = Join-Path $folderColl $rel
        New-Item -ItemType Directory -Path (Split-Path $file -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($file, "x")
    }
    [System.IO.File]::WriteAllText((Join-Path $folderColl "collection_manifest.csv"),
        (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", "Registry\SYSTEM", "Memory\Coll_memory_dump.dmp", $classicCopy, "USB\gone_before_the_run.log")))
    Set-Variable -Name InputPath -Value (Split-Path $folderColl -Parent) -Scope Script
    $script:collectionManifest = $null
    $script:inputFiles = New-Object System.Collections.Generic.List[string]
    Add-ManifestInputFiles
    $tracked = @($script:inputFiles | ForEach-Object { $_.Substring($folderColl.Length + 1) } | Sort-Object) -join ", "
    Assert-Equal -Name "folder input: manifest files present at the start are tracked (no memory dump or attachment copy)" -Expected "Registry\SYSTEM, USB\setupapi.dev.log" -Actual $tracked
    Remove-Item -LiteralPath (Join-Path $folderColl "USB\setupapi.dev.log")
    $missing = @(Get-MissingInputFiles)
    Assert-Equal -Name "a deleted input file is reported missing" -Expected (Join-Path $folderColl "USB\setupapi.dev.log") -Actual ($missing -join ", ")
    $logBefore = @(Get-Content -LiteralPath $logFile).Count
    Write-MissingInputFiles -Files $missing -BaseFolder $folderColl
    $groupLines = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $logBefore)
    Assert-Equal -Name "missing files grouped by collection folder" -Expected "WARNING:   Missing in USB\: 1 file(s) |     USB\setupapi.dev.log" -Actual (($groupLines | ForEach-Object { $_ -replace '^\[[^\]]+\] ', '' }) -join " | ")
    # Many missing files (a mass deletion): the console shows 20 names, the
    # log file every one
    $manyMissing = @(1..25 | ForEach-Object { Join-Path $folderColl ("Browser\file{0:D2}.db" -f $_) })
    $logBefore = @(Get-Content -LiteralPath $logFile).Count
    $console = @(Write-MissingInputFiles -Files $manyMissing -BaseFolder $folderColl 6>&1 | ForEach-Object { "$_" })
    $logNames = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $logBefore | Where-Object { $_ -match 'Browser\\file\d\d\.db$' })
    Assert-Equal -Name "25 missing files: all 25 names in the log file" -Expected 25 -Actual $logNames.Count
    Assert-Equal -Name "25 missing files: 20 names and a count on the console" -Expected "20 1" -Actual "$(@($console -match 'Browser\\file\d\d\.db$').Count) $(@($console -match '\.\.\. and 5 more \(all listed in the log file\)$').Count)"

    # --- Paths of 260 or more characters in a collection folder -----------
    # A collection folder is read where it is. Windows PowerShell 5.1 (long
    # paths off, the Windows default) cannot open such a file and does not go
    # into such a folder, so the parsers would leave them out without an
    # error: Get-UnreadableLongPaths names them and the run is refused.
    # PowerShell 7 opens them, so nothing is named there. Memory dumps and
    # copied email attachments do not count (no parser reads them).
    $longColl = Join-Path (Get-LongPath $testRoot) "long\Coll"
    $pad = 275 - $longColl.Length
    $longEvtx = "EventLogs\" + ("e" * ($pad - 15)) + ".evtx"
    $longLnk = "UserActivity\alice\" + ("u" * [Math]::Max(10, 232 - $longColl.Length - 19)) + "\" + ("v" * 40) + "\a.lnk"
    $longDump = "Memory\" + ("m" * ($pad - 11)) + ".dmp"
    $longAttachment = "Email\alice\NewOutlook\Attachments\" + ("a" * ($pad - 40)) + ".pdf"
    foreach ($rel in @($longEvtx, $longLnk, $longDump, $longAttachment, "USB\setupapi.dev.log")) {
        $file = Get-ExtendedLengthPath ($longColl + '\' + $rel)
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($file))
        [System.IO.File]::WriteAllText($file, "x")
    }
    [System.IO.File]::WriteAllText((Join-Path $longColl "collection_manifest.csv"),
        (New-TestManifest -RelativePaths @($longEvtx, $longLnk, $longDump, $longAttachment, "USB\setupapi.dev.log")))
    Set-Variable -Name InputPath -Value $longColl -Scope Script
    $script:collectionManifest = $null
    # Long paths work in PowerShell 7, and in Windows PowerShell 5.1 too when
    # Windows long paths are enabled (LongPathsEnabled = 1, as on the GitHub
    # runners): then nothing is unreadable and nothing is refused
    $script:longPathsWork = [System.IO.File]::Exists($longColl + '\' + $longEvtx)
    $unreadable = @(Get-UnreadableLongPaths -Folder $longColl)
    if ($script:longPathsWork) {
        Assert-Equal -Name "paths of 260+ characters: long paths work here (PowerShell 7 or LongPathsEnabled), nothing named" -Expected "" -Actual ($unreadable -join ", ")
    }
    else {
        $named = "$($unreadable -contains $longEvtx) $($unreadable -contains $longLnk) $(@($unreadable | Where-Object { $_ -like 'Memory\*' -or $_ -like 'Email\*' -or $_ -like 'USB\*' }).Count)"
        Assert-Equal -Name "paths of 260+ characters: the event log and the file in a deep folder named (no dump, attachment or short path)" -Expected "True True 0" -Actual $named
    }
    $script:collectionManifest = $null
    # Windows PowerShell's Remove-Item cannot delete such paths: .NET with \\?\
    [System.IO.Directory]::Delete((Get-ExtendedLengthPath (Split-Path $longColl -Parent)), $true)

    # --- SetupAPI logs the manifest lists (USB parser) --------------------
    # Logs shortened on extraction, named the way Expand-CollectionZip does
    # (the name's start, 8 characters or more, and a hash), are found and
    # count by their full-length names; only a listed log that is gone is
    # reported. Email attachment copies and the Secrets\ folder are skipped
    # like Find-ArtifactFiles skips them, also under a shortened name, and
    # are not counted as listed.
    $usbColl = Join-Path $testRoot "usb\Coll"
    $shortSetupApi = Join-Path $usbColl "USB\setupapi~0123ABCD.log"
    $shortRotated = Join-Path $usbColl "USB\setupapi.dev.2023~4567CDEF.log"
    $attachedLog = Join-Path $usbColl "Email\alice\NewOutlook\Attachments\setupapi.dev.log"
    $shortAttached = Join-Path $usbColl "Email\alice\NewOutlook\Attachments\setupapi~89ABCDEF.log"
    $shortSecrets = Join-Path $usbColl "Secrets\setupapi~CDEF0123.log"
    foreach ($file in @((Join-Path $usbColl "USB\setupapi.dev.log"), $shortSetupApi, $shortRotated, $attachedLog, $shortAttached, $shortSecrets)) {
        New-Item -ItemType Directory -Path (Split-Path $file -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($file, "x")
    }
    [System.IO.File]::WriteAllText((Join-Path $usbColl "collection_manifest.csv"),
        (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", "USB\setupapi.dev.20241201_000000.log", "USB\setupapi.dev.20230601_000000.log", "USB\setupapi.dev.20240101_000000.log", "Registry\SYSTEM",
            "Email\alice\NewOutlook\Attachments\setupapi.dev.log", "Email\alice\NewOutlook\Attachments\setupapi.dev.20220101_000000.log", "Secrets\setupapi.dev.20220202_000000.log")))
    Set-Variable -Name InputPath -Value (Split-Path $usbColl -Parent) -Scope Script
    $script:collectionManifest = $null
    $script:collectionRoot = Get-CollectionRootFolder
    $script:secretsRoot = $null
    $script:shortenedNames = @{
        $shortSetupApi = (Join-Path $usbColl "USB\setupapi.dev.20241201_000000.log")
        $shortRotated  = (Join-Path $usbColl "USB\setupapi.dev.20230601_000000.log")
        $shortAttached = (Join-Path $usbColl "Email\alice\NewOutlook\Attachments\setupapi.dev.20220101_000000.log")
        $shortSecrets  = (Join-Path $usbColl "Secrets\setupapi.dev.20220202_000000.log")
    }
    $foundLogs = @(Find-SetupApiLogFiles)
    $foundNames = [string[]]@($foundLogs | ForEach-Object { $_.Name })
    [Array]::Sort($foundNames, [System.StringComparer]::Ordinal)
    Assert-Equal -Name "SetupAPI logs: found, also under a shortened name, each once" -Expected "setupapi.dev.2023~4567CDEF.log, setupapi.dev.log, setupapi~0123ABCD.log" -Actual ($foundNames -join ", ")
    Assert-Equal -Name "SetupAPI logs: email attachment copies and Secrets\ skipped, also under a shortened name" -Expected "" -Actual (@($foundLogs | Where-Object { $_.FullName -notlike "$usbColl\USB\*" } | ForEach-Object { $_.FullName }) -join ", ")
    $setupApiCheck = Compare-ManifestSetupApiLogs -Found $foundLogs
    Assert-Equal -Name "SetupAPI logs: listed in the manifest (not email attachment copies or Secrets\)" -Expected "USB\setupapi.dev.20230601_000000.log, USB\setupapi.dev.20240101_000000.log, USB\setupapi.dev.20241201_000000.log, USB\setupapi.dev.log" -Actual ($setupApiCheck.Listed -join ", ")
    Assert-Equal -Name "SetupAPI logs: only the one that is gone is missing (shortened ones found)" -Expected "USB\setupapi.dev.20240101_000000.log" -Actual ($setupApiCheck.Missing -join ", ")
    $setupApiCheck = Compare-ManifestSetupApiLogs -Found @()
    Assert-Equal -Name "SetupAPI logs: none found, all listed are missing" -Expected 4 -Actual $setupApiCheck.Missing.Count
    $script:shortenedNames = @{}
    $script:secretsRoot = $null

    # --- Free space verdict ----------------------------------------------
    $need = 2GB
    Assert-Equal -Name "free space: below size + 256 MB is an error" -Expected "Error" -Actual (Get-ExtractionSpaceVerdict -FreeBytes ($need + 255MB) -TotalBytes 1000GB -NeededBytes $need -IsSystemDrive $false)
    Assert-Equal -Name "free space: below size + 1 GB is a warning" -Expected "Warning" -Actual (Get-ExtractionSpaceVerdict -FreeBytes ($need + 512MB) -TotalBytes 1000GB -NeededBytes $need -IsSystemDrive $false)
    Assert-Equal -Name "free space: system drive left under 10% free is a warning" -Expected "Warning" -Actual (Get-ExtractionSpaceVerdict -FreeBytes 100GB -TotalBytes 1000GB -NeededBytes $need -IsSystemDrive $true)
    Assert-Equal -Name "free space: another drive under 10% free is fine" -Expected "Ok" -Actual (Get-ExtractionSpaceVerdict -FreeBytes 100GB -TotalBytes 1000GB -NeededBytes $need -IsSystemDrive $false)
    Assert-Equal -Name "free space: enough" -Expected "Ok" -Actual (Get-ExtractionSpaceVerdict -FreeBytes 500GB -TotalBytes 1000GB -NeededBytes $need -IsSystemDrive $true)

    # --- Temp folder check (8.3 short names expanded) --------------------
    Write-TestResult -Name "a folder in %TEMP% is inside a temp folder" -Passed ([bool](Get-ContainingTempFolder $testRoot)) -Message "no temp folder found for $testRoot"
    $shortTemp = ""
    try { $shortTemp = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($testRoot).ShortPath }
    catch { Write-Host "  (no 8.3 short path available: $($_.Exception.Message))" }
    if ($shortTemp) {
        Write-TestResult -Name "an 8.3 short path of it is too ($shortTemp)" -Passed ([bool](Get-ContainingTempFolder $shortTemp)) -Message "no temp folder found for $shortTemp"
    }
    # A relative -InputPath is resolved against the PowerShell location (as
    # the parsers do), not the process working directory
    Push-Location -LiteralPath $testRoot
    try { $relativeTemp = Get-ContainingTempFolder "." }
    finally { Pop-Location }
    Write-TestResult -Name "a relative path is resolved against the PowerShell location" -Passed ([bool]$relativeTemp) -Message "no temp folder found for '.' in $testRoot (process directory: $([Environment]::CurrentDirectory))"
    $defaultBase = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) "TimelineBuilder"
    Assert-Equal -Name "the default work folder base is not inside a temp folder" -Expected "" -Actual (Get-ContainingTempFolder $defaultBase)

    # --- Hives left loaded: only this run's, only if still loaded ----------
    $script:runHives = New-Object System.Collections.Generic.List[string]
    Register-RunHive "TEMP_TL_ZIPTEST_NOT_LOADED"
    Dismount-RunHives
    Assert-Equal -Name "a registered hive that is not loaded is dropped without reg unload" -Expected 0 -Actual $script:runHives.Count

    # --- Work folders: stale clean-up and lock ----------------------------
    $base = Join-Path $testRoot "base"
    $folders = @{}
    foreach ($name in @("w11_000001", "w12_000002", "w13_000003", "wother")) {
        $folders[$name] = Join-Path $base $name
        New-Item -ItemType Directory -Path (Join-Path $folders[$name] "in\USB") -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $folders[$name] "in\USB\setupapi.dev.log"), "x")
        if ($name -ne "w13_000003") { [System.IO.File]::WriteAllText((Join-Path $folders[$name] ".lock"), "") }
    }
    $held = [System.IO.File]::Open((Join-Path $folders["w12_000002"] ".lock"), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $script:runWorkDir = New-RunWorkFolder -BaseFolder $base
        Assert-Equal -Name "stale work folder (lock not held) removed" -Expected $false -Actual (Test-Path -LiteralPath $folders["w11_000001"])
        Assert-Equal -Name "work folder of a running builder (lock held) kept" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $folders["w12_000002"] "in\USB\setupapi.dev.log"))
        Assert-Equal -Name "w* folder without a lock kept" -Expected $true -Actual (Test-Path -LiteralPath $folders["w13_000003"])
        Assert-Equal -Name "folder with another name kept" -Expected $true -Actual (Test-Path -LiteralPath $folders["wother"])
        Write-TestResult -Name "new work folder w<PID>_<HHmmss> with scratch\ and .lock" -Passed ($script:runWorkDir -and
            (Split-Path $script:runWorkDir -Leaf) -match "^w$($PID)_\d{6}$" -and (Test-Path -LiteralPath (Join-Path $script:runWorkDir "scratch")) -and
            (Test-Path -LiteralPath (Join-Path $script:runWorkDir ".lock"))) -Message "work folder: $($script:runWorkDir)"
        Assert-Equal -Name "scratch copies go to the work folder" -Expected (Join-Path $script:runWorkDir "scratch") -Actual (Get-ScratchFolder)
        # A second builder starting now must leave this run's folder alone
        Remove-StaleWorkFolders -BaseFolder $base
        Assert-Equal -Name "this run's work folder survives another run's clean-up" -Expected $true -Actual (Test-Path -LiteralPath $script:runWorkDir)
        $runFolder = $script:runWorkDir
        Remove-RunWorkFolder
        Assert-Equal -Name "work folder removed at the end of the run" -Expected $false -Actual (Test-Path -LiteralPath $runFolder)
        Assert-Equal -Name "the -WorkDir folder itself is kept" -Expected $true -Actual (Test-Path -LiteralPath $base)
    }
    finally {
        $held.Close()
        if ($script:runWorkLock) { $script:runWorkLock.Close() }
    }

    # --- SRUM: scratch copy in the work folder, missing transaction log ----
    # A SRUDB.dat that is not an ESE database is copied and then skipped:
    # the copy must be made in the work folder's scratch folder (not
    # %TEMP%) and removed. Its manifest lists a log that is gone.
    $srumColl = Join-Path $testRoot "srum\Coll"
    $srumDir = Join-Path $srumColl "Execution\SRUM"
    New-Item -ItemType Directory -Path $srumDir -Force | Out-Null
    foreach ($name in @("SRUDB.dat", "SRU.log", "SRUtmp.jrs")) { [System.IO.File]::WriteAllText((Join-Path $srumDir $name), "not an ESE file") }
    [System.IO.File]::WriteAllText((Join-Path $srumColl "collection_manifest.csv"),
        (New-TestManifest -RelativePaths @("Execution\SRUM\SRUDB.dat", "Execution\SRUM\SRU.log", "Execution\SRUM\SRU00001.log", "Execution\SRUM\SRUtmp.jrs", "Execution\SRUM\SRUres00001.jrs")))
    Set-Variable -Name InputPath -Value $srumColl -Scope Script
    $script:collectionManifest = $null
    $script:manifestTimes = $null
    $script:collectionRoot = Get-CollectionRootFolder
    $script:runScratchDir = Join-Path $testRoot "srum-work\scratch"
    New-Item -ItemType Directory -Path $script:runScratchDir -Force | Out-Null
    if (Initialize-SrumReader) {
        $script:srumCopyDir = ""
        $script:srumCopyMade = $false
        $logBefore = @(Get-Content -LiteralPath $logFile).Count
        # The real Get-SrumWorkingCopy, wrapped to see where it copies to
        & {
            $realGetCopy = ${function:Get-SrumWorkingCopy}
            function Get-SrumWorkingCopy {
                param([System.IO.FileInfo]$File, [string]$TempDir)
                $copy = & $realGetCopy -File $File -TempDir $TempDir
                $script:srumCopyDir = $TempDir
                $script:srumCopyMade = Test-Path -LiteralPath (Join-Path $TempDir "SRUDB.dat") -PathType Leaf
                return $copy
            }
            Add-SrumTimelineEntries -File (Get-Item -LiteralPath (Join-Path $srumDir "SRUDB.dat"))
        }
        $srumLog = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $logBefore)
        Write-TestResult -Name "SRUM copy made in the work folder's scratch folder" -Passed ($script:srumCopyMade -and
            $script:srumCopyDir.StartsWith($script:runScratchDir + "\", [System.StringComparison]::OrdinalIgnoreCase)) -Message "copy folder: $($script:srumCopyDir)"
        Assert-Equal -Name "SRUM copy removed after reading" -Expected $false -Actual (Test-Path -LiteralPath $script:srumCopyDir)
        $missingLogLines = @($srumLog | Where-Object { $_ -match 'Transaction log missing: ' } | ForEach-Object { $_ -replace '^\[[^\]]+\] ', '' })
        Assert-Equal -Name "SRUM: only the transaction log listed in the manifest but gone is reported" -Expected (
            "WARNING:   Transaction log missing: $(Join-Path $srumDir 'SRU00001.log') is in the collection manifest but not here -- the database is read without it (records not yet written to the database are lost)") -Actual ($missingLogLines -join " | ")
    }
    else { Write-TestResult -Name "SRUM reader compiles" -Passed $false -Message "Initialize-SrumReader failed" }
    $script:runScratchDir = $null

    # --- A network work folder is refused (reg load needs local hives) -----
    # Only the path is looked at: no network access
    $uncBase = "\\server.invalid\share\TimelineBuilder"
    Assert-Equal -Name "a UNC path is a network path" -Expected $true -Actual (Test-NetworkPath $uncBase)
    Assert-Equal -Name "a local folder is not a network path" -Expected $false -Actual (Test-NetworkPath $testRoot)
    $logBefore = @(Get-Content -LiteralPath $logFile).Count
    $uncWorkDir = New-RunWorkFolder -BaseFolder $uncBase 6>$null
    $uncLog = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $logBefore) -join "`n"
    Assert-Equal -Name "no work folder made on a network share" -Expected "" -Actual $uncWorkDir
    Assert-Equal -Name "network work folder refusal logged" -Expected $true -Actual ($uncLog -match [regex]::Escape("Not using $uncBase for the work folder: it is on a network drive or share"))

    # --- End-of-run banner and exit code ----------------------------------
    function Get-RunEndResult {
        param([int]$Missing, [int]$Errors, [switch]$NoOutput)
        $script:missingInputCount = $Missing
        $script:unexpectedErrorCount = $Errors
        $before = @(Get-Content -LiteralPath $logFile).Count
        $incomplete = Write-RunEndBanner -NoOutput:$NoOutput 6>$null
        $lines = @(Get-Content -LiteralPath $logFile | Select-Object -Skip $before | ForEach-Object { $_ -replace '^\[[^\]]+\] ', '' })
        return "$incomplete | $($lines -join ' | ')"
    }
    Assert-Equal -Name "banner: complete run" -Expected "False | === Timeline Builder Completed Successfully ===" -Actual (Get-RunEndResult -Missing 0 -Errors 0)
    Assert-Equal -Name "banner: missing input files (exit code 2)" -Expected "True | ERROR: === Timeline Builder Completed WITH 1 MISSING INPUT FILE(S) -- timeline incomplete ===" -Actual (Get-RunEndResult -Missing 1 -Errors 0)
    Assert-Equal -Name "banner: unexpected errors (exit code 2)" -Expected "True | ERROR: === Timeline Builder Completed WITH 2 UNEXPECTED ERROR(S) -- timeline may be incomplete ===" -Actual (Get-RunEndResult -Missing 0 -Errors 2)
    Assert-Equal -Name "banner: both" -Expected "True | ERROR: === Timeline Builder Completed WITH 3 MISSING INPUT FILE(S) -- timeline incomplete === | ERROR: === Timeline Builder Completed WITH 1 UNEXPECTED ERROR(S) -- timeline may be incomplete ===" -Actual (Get-RunEndResult -Missing 3 -Errors 1)
    Assert-Equal -Name "banner: no entries" -Expected "False | === Timeline Builder Finished (no output generated) ===" -Actual (Get-RunEndResult -Missing 0 -Errors 0 -NoOutput)
    Assert-Equal -Name "banner: no entries after an unexpected error (exit code 2)" -Expected "True | ERROR: === Timeline Builder Finished WITH 1 UNEXPECTED ERROR(S) (no output generated) ===" -Actual (Get-RunEndResult -Missing 0 -Errors 1 -NoOutput)
    $script:missingInputCount = 0
    $script:unexpectedErrorCount = 0

    # =============================================================
    # Part 2: builder runs on a collection zip
    # =============================================================
    Write-Host ""
    Write-Host "Part 2: builder runs on a collection zip"
    if (-not $BuilderPath) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-TestResult -Name "Part 2: Administrator rights" -Passed $false -Message "the builder needs them. Run elevated, or pass -BuilderPath with a builder copy without the admin check."
            throw "Part 2 cannot run"
        }
    }
    # Run the builder with the same PowerShell edition as this script
    $powershellExe = (Get-Process -Id $PID).Path
    $reportsDir = Join-Path $builderDir "reports"
    $reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $tempPatterns = @("TriageExtract_*", "TimelineHive_*", "AmcacheRepair_*", "timeline_browser_*")
    $tempBefore = @(foreach ($pattern in $tempPatterns) { Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } })

    $collName = "TriageCollection_2025-01-01_00-00"
    $deviceA = "USBSTOR\Disk&Ven_TestVen&Prod_DiskA&Rev_1.00\TESTSERIAL0001&0"
    $deviceB = "USBSTOR\Disk&Ven_TestVen&Prod_DiskB&Rev_1.00\TESTSERIAL0002&0"
    $collectionInfo = '{ "SchemaVersion": 1, "Mode": "Live", "CollectionStartUtc": "2025-01-01T12:00:00Z", "CollectorTimeZoneId": "UTC", "TargetTimeZoneId": "UTC" }'
    $zipEntries = [ordered]@{
        "$collName/"                                       = $null
        "$collName/collection_info.json"                   = $collectionInfo
        "$collName/collection_manifest.csv"                = (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", "USB\setupapi.dev.20241201_000000.log"))
        "$collName/USB/setupapi.dev.log"                   = (New-SetupApiText -Instance $deviceA -LocalTime "2025/01/02 10:00:00.000")
        "$collName\USB\setupapi.dev.20241201_000000.log"   = (New-SetupApiText -Instance $deviceB -LocalTime "2024/11/30 09:00:00.000")
    }
    $zipPath = Join-Path $testRoot "$collName.zip"
    New-TestZip -Path $zipPath -Entries $zipEntries -EntryDate $entryDate
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash

    # Runs the builder on a zip (default: $zipPath with the USB source; CSV
    # only, and no findings report unless -WithReport: each run writes its
    # own timeline, and only run B checks the report); returns its exit
    # code, console output and log file
    function Invoke-ZipRun {
        param([string]$OutputFile, [string[]]$ExtraArguments = @(), [string]$Zip = $zipPath, [string]$RunSources = "USB", [switch]$WithReport)
        $ErrorActionPreference = "Continue"
        $before = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $runArguments = @($ExtraArguments)
        if (-not $WithReport) { $runArguments += "-NoReport" }
        $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder -InputPath $Zip -Sources $RunSources `
            -OutputFile $OutputFile -NoExcel -Viewer None @runArguments 2>&1
        $exitCode = $LASTEXITCODE
        $newReport = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $before -notcontains $_.FullName }) | Select-Object -First 1
        $logText = ""
        if ($newReport) { $logText = Get-Content -LiteralPath (Join-Path $newReport.FullName "timeline_builder_log.txt") -Raw -ErrorAction SilentlyContinue }
        $lines = @($output | ForEach-Object { "$_" })
        $workFolder = ""
        foreach ($line in $lines) { if ($line -match 'Work folder: (.+?)\s*$') { $workFolder = $Matches[1]; break } }
        return [PSCustomObject]@{ ExitCode = $exitCode; Lines = $lines; Log = "$logText"; WorkFolder = $workFolder }
    }

    function Get-SetupApiRow {
        param([object[]]$Rows, [string]$Serial)
        return @($Rows | Where-Object { $_.Source -eq "USB-SetupAPI" -and $_.Details -like "*$Serial*" })
    }

    # --- Run A: default work folder, both logs parsed ---------------------
    $csvA = Join-Path $testRoot "timeline-a.csv"
    Write-Host "Running the builder ($powershellExe) on $zipPath ..."
    $runA = Invoke-ZipRun -OutputFile $csvA
    if ($runA.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $csvA)) { $runA.Lines | ForEach-Object { Write-Host "  | $_" } }
    Assert-Equal -Name "run A: exit code" -Expected 0 -Actual $runA.ExitCode
    $rowsA = @()
    if (Test-Path -LiteralPath $csvA) { $rowsA = @(Import-Csv -LiteralPath $csvA) }
    $rowA = @(Get-SetupApiRow -Rows $rowsA -Serial "TESTSERIAL0001")
    $rowB = @(Get-SetupApiRow -Rows $rowsA -Serial "TESTSERIAL0002")
    Assert-Equal -Name "run A: device from setupapi.dev.log (/ entry name)" -Expected "1 2025-01-02 10:00:00.000 USBDevice Device install: TestVen DiskA (serial TESTSERIAL0001)" -Actual "$($rowA.Count) $($rowA[0].Timestamp) $($rowA[0].EventType) $($rowA[0].Description)"
    Assert-Equal -Name "run A: device from the rotated setupapi log (\ entry name)" -Expected "1 2024-11-30 09:00:00.000 USBDevice Device install: TestVen DiskB (serial TESTSERIAL0002)" -Actual "$($rowB.Count) $($rowB[0].Timestamp) $($rowB[0].EventType) $($rowB[0].Description)"
    Assert-Equal -Name "run A: both SetupAPI logs found, none reported missing" -Expected "True False" -Actual "$($runA.Log -match 'Found 2 SetupAPI log\(s\)\.') $($runA.Log -match 'SetupAPI log\(s\) missing')"
    Assert-Equal -Name "run A: completed successfully" -Expected 1 -Actual @($runA.Lines -match "=== Timeline Builder Completed Successfully ===").Count
    Assert-Equal -Name "run A: extraction written to the log file" -Expected $true -Actual ($runA.Log -match "Extracting the collection zip" -and $runA.Log -match "Zip: .+ 4 file\(s\)" -and $runA.Log -match "Work folder: ")
    Assert-Equal -Name "run A: free space checked before the extraction" -Expected $true -Actual ($runA.Log -match "Free space on |Low free space on |Free space check skipped")
    Assert-Equal -Name "run A: all input files still present" -Expected $true -Actual ($runA.Log -match "All 4 input file\(s\) were still present")
    $defaultBase = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) "TimelineBuilder"
    Write-TestResult -Name "run A: work folder in %LOCALAPPDATA%\TimelineBuilder" -Passed ($runA.WorkFolder -and $runA.WorkFolder.StartsWith($defaultBase + "\", [System.StringComparison]::OrdinalIgnoreCase)) -Message "work folder: $($runA.WorkFolder)"
    Write-TestResult -Name "run A: work folder not inside a temp folder" -Passed ($runA.WorkFolder -and -not (Get-ContainingTempFolder $runA.WorkFolder) -and
        -not $runA.WorkFolder.StartsWith([System.IO.Path]::GetTempPath(), [System.StringComparison]::OrdinalIgnoreCase)) -Message "work folder: $($runA.WorkFolder)"
    Write-TestResult -Name "run A: work folder removed at the end" -Passed ($runA.WorkFolder -and -not (Test-Path -LiteralPath $runA.WorkFolder)) -Message "still there: $($runA.WorkFolder)"
    $tempAfter = @(foreach ($pattern in $tempPatterns) { Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } })
    Assert-Equal -Name "run A: nothing left in %TEMP% (TriageExtract_*, TimelineHive_*, ...)" -Expected "" -Actual (@($tempAfter | Where-Object { $tempBefore -notcontains $_ }) -join ", ")
    Assert-Equal -Name "run A: the zip is not changed" -Expected $zipHash -Actual (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash

    # --- Run B: a file deleted mid-run, -WorkDir --------------------------
    # (with the findings report, in a folder of its own: it must say that the
    # timeline is incomplete)
    $dirB = Join-Path $testRoot "run-b"
    New-Item -ItemType Directory -Path $dirB | Out-Null
    $csvB = Join-Path $dirB "timeline-b.csv"
    $workDirB = Join-Path $testRoot "wd"
    New-Item -ItemType Directory -Path $workDirB | Out-Null
    Write-Host "Running the builder again, with the test hook deleting an extracted setupapi log and -WorkDir $workDirB ..."
    $env:TIMELINE_BUILDER_TEST_DELETE_INPUT = "USB\setupapi.dev.20241201_000000.log"
    try { $runB = Invoke-ZipRun -OutputFile $csvB -ExtraArguments @("-WorkDir", $workDirB) -WithReport }
    finally { Remove-Item -LiteralPath Env:\TIMELINE_BUILDER_TEST_DELETE_INPUT -ErrorAction SilentlyContinue }
    if ($runB.ExitCode -ne 2) { $runB.Lines | ForEach-Object { Write-Host "  | $_" } }
    Assert-Equal -Name "run B: exit code 2 (timeline incomplete)" -Expected 2 -Actual $runB.ExitCode
    Assert-Equal -Name "run B: banner" -Expected 1 -Actual @($runB.Lines -match [regex]::Escape("=== Timeline Builder Completed WITH 1 MISSING INPUT FILE(S) -- timeline incomplete ===")).Count
    Assert-Equal -Name "run B: no success banner" -Expected 0 -Actual @($runB.Lines -match "Completed Successfully").Count
    Assert-Equal -Name "run B: missing file listed under USB\" -Expected $true -Actual ($runB.Log -match "Missing in USB\\: 1 file\(s\)" -and $runB.Log -match "setupapi\.dev\.20241201_000000\.log")
    $rowsB = @()
    if (Test-Path -LiteralPath $csvB) { $rowsB = @(Import-Csv -LiteralPath $csvB) }
    Assert-Equal -Name "run B: the remaining log is parsed, the deleted one is not" -Expected "1 0" -Actual "$(@(Get-SetupApiRow -Rows $rowsB -Serial 'TESTSERIAL0001').Count) $(@(Get-SetupApiRow -Rows $rowsB -Serial 'TESTSERIAL0002').Count)"
    Assert-Equal -Name "run B: the USB parser names the SetupAPI log the manifest lists but that is gone" -Expected "True True" -Actual "$($runB.Log -match 'Found 1 SetupAPI log\(s\)\.') $($runB.Log -match 'SetupAPI log\(s\) missing: the collection manifest lists 2, 1 of them are not here -- their device installs are not in the timeline: USB\\setupapi\.dev\.20241201_000000\.log')"
    Write-TestResult -Name "run B: work folder made in -WorkDir" -Passed ($runB.WorkFolder -and (Split-Path $runB.WorkFolder -Parent) -eq $workDirB) -Message "work folder: $($runB.WorkFolder)"
    Write-TestResult -Name "run B: work folder removed, -WorkDir kept" -Passed ($runB.WorkFolder -and -not (Test-Path -LiteralPath $runB.WorkFolder) -and (Test-Path -LiteralPath $workDirB)) -Message "work folder: $($runB.WorkFolder)"
    Assert-Equal -Name "run B: the zip is not changed" -Expected $zipHash -Actual (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    # The findings report of an incomplete run says so (the end banner is
    # written after the report, so the report cannot read it from the log)
    $modelB = $null
    $modelPathB = Join-Path $dirB "report-model.json"
    if (Test-Path -LiteralPath $modelPathB) { $modelB = Get-Content -LiteralPath $modelPathB -Raw | ConvertFrom-Json }
    Write-TestResult -Name "run B: the report says the timeline is incomplete (caveat and coverage)" -Passed ($modelB -and $modelB.Coverage.TimelineCompleteness.Incomplete -and
        $modelB.Coverage.TimelineCompleteness.MissingInputFiles -eq 1 -and @($modelB.Caveats | Where-Object { $_ -match '^The timeline is incomplete: 1 input file\(s\) disappeared' }).Count -eq 1) -Message "report-model.json: $(if ($modelB) { ($modelB.Caveats | Select-Object -First 3) -join ' / ' } else { 'missing' })"
    $htmlB = ""
    if (Test-Path -LiteralPath (Join-Path $dirB "report.html")) { $htmlB = [System.IO.File]::ReadAllText((Join-Path $dirB "report.html")) }
    Assert-Equal -Name "run B: report.html shows the incomplete timeline in Evidence coverage" -Expected $true -Actual ($htmlB.Contains("<h3>Timeline incomplete</h3>"))
    Assert-Equal -Name "run B: report.html says it twice (summary caveat, Evidence coverage), not again in the notes" -Expected 2 -Actual ([regex]::Matches($htmlB, [regex]::Escape("The timeline is incomplete: 1 input file(s) disappeared")).Count)
    Assert-Equal -Name "run B: the zip's collection_info.json is copied next to the timeline before the work folder goes" -Expected $true -Actual (Test-Path -LiteralPath (Join-Path $dirB "collection_info.json") -PathType Leaf)
    Assert-Equal -Name "run B: the zip is hashed for the report (input was a .zip)" -Expected $true -Actual ($modelB -and @($modelB.Files.Hashes | Where-Object { $_.Name -eq "$collName.zip" -and $_.Sha256 -eq $zipHash }).Count -eq 1)
    $reportLeftovers = @(@("findings.csv", "report.html", "report-model.json") | Where-Object { Test-Path -LiteralPath (Join-Path $testRoot $_) })
    Assert-Equal -Name "run A (-NoReport): no report next to its timeline" -Expected "" -Actual ($reportLeftovers -join ", ")

    # --- Run D: a -WorkDir whose path has [ ] (wildcard characters) --------
    # The parsers read the extracted collection with -Path, which would find
    # nothing there: the run stops with a clear error instead of ending
    # "successfully" without a timeline
    $csvD = Join-Path $testRoot "timeline-d.csv"
    $workDirD = Join-Path $testRoot "wd [1]"
    New-Item -ItemType Directory -Path $workDirD | Out-Null
    Write-Host "Running the builder with -WorkDir $workDirD ..."
    $runD = Invoke-ZipRun -OutputFile $csvD -ExtraArguments @("-WorkDir", $workDirD)
    if ($runD.ExitCode -ne 1) { $runD.Lines | ForEach-Object { Write-Host "  | $_" } }
    Assert-Equal -Name "run D: exit code 1 (stopped at the start)" -Expected 1 -Actual $runD.ExitCode
    Assert-Equal -Name "run D: the error names the work folder's wildcard characters" -Expected 1 -Actual @($runD.Lines -match "ERROR: The work folder's path has \[ \], \* or \? in it").Count
    Write-TestResult -Name "run D: no timeline, work folder removed, -WorkDir kept" -Passed (-not (Test-Path -LiteralPath $csvD) -and $runD.WorkFolder -and -not (Test-Path -LiteralPath $runD.WorkFolder) -and (Test-Path -LiteralPath $workDirD)) -Message "work folder: $($runD.WorkFolder)"

    # --- Run E: a zip whose top folder has [ ] in its name (a folder named
    # "Case [1]" zipped with Explorer): its extracted copy is renamed, so the
    # parsers find the collection's files ----------------------------------
    $bracketZipPath = Join-Path $testRoot "bracket\Case [1].zip"
    [void][System.IO.Directory]::CreateDirectory((Split-Path $bracketZipPath -Parent))
    $bracketEntries = [ordered]@{}
    foreach ($key in $zipEntries.Keys) { $bracketEntries[$key.Replace($collName, "Case [1]")] = $zipEntries[$key] }
    New-TestZip -Path $bracketZipPath -Entries $bracketEntries -EntryDate $entryDate
    $csvE = Join-Path $testRoot "timeline-e.csv"
    Write-Host "Running the builder on $bracketZipPath (top folder 'Case [1]') ..."
    $runE = Invoke-ZipRun -OutputFile $csvE -Zip $bracketZipPath
    if ($runE.ExitCode -ne 0) { $runE.Lines | ForEach-Object { Write-Host "  | $_" } }
    Assert-Equal -Name "run E: exit code" -Expected 0 -Actual $runE.ExitCode
    $rowsE = @()
    if (Test-Path -LiteralPath $csvE) { $rowsE = @(Import-Csv -LiteralPath $csvE) }
    Assert-Equal -Name "run E: both devices read from the renamed folder" -Expected "1 1" -Actual "$(@(Get-SetupApiRow -Rows $rowsE -Serial 'TESTSERIAL0001').Count) $(@(Get-SetupApiRow -Rows $rowsE -Serial 'TESTSERIAL0002').Count)"
    Assert-Equal -Name "run E: the rename and the collection folder are logged, metadata from collection_info.json" -Expected $true -Actual (
        $runE.Log -match [regex]::Escape("its extracted copy was renamed to 'Case _1_'") -and $runE.Log -match "Collection folder: .+\\in\\Case _1_" -and $runE.Log -match "Collection metadata from collection_info\.json")
    Assert-Equal -Name "run E: every input file found under the new name (none reported missing)" -Expected $true -Actual ($runE.Log -match "All 4 input file\(s\) were still present")
    Write-TestResult -Name "run E: work folder removed at the end" -Passed ($runE.WorkFolder -and -not (Test-Path -LiteralPath $runE.WorkFolder)) -Message "still there: $($runE.WorkFolder)"

    # --- Run C: a copied email attachment (antivirus may quarantine it) ----
    # It stays in the zip and is no input file, so its removal cannot stop
    # the run or mark the timeline incomplete. The test hook is pointed at
    # it and must find nothing to delete; the rows come from the manifest.
    $mailZipPath = Join-Path $testRoot "mail\$collName.zip"
    New-Item -ItemType Directory -Path (Split-Path $mailZipPath -Parent) | Out-Null
    $mailEntries = [ordered]@{
        "$collName/collection_info.json"               = $collectionInfo
        "$collName/collection_manifest.csv"            = (New-TestManifest -RelativePaths @($classicCopy))
        "$collName/$($classicCopy.Replace('\', '/'))"  = "attachment"
    }
    New-TestZip -Path $mailZipPath -Entries $mailEntries -EntryDate $entryDate
    $csvC = Join-Path $testRoot "timeline-c.csv"
    Write-Host "Running the builder on a zip with a copied email attachment, the test hook pointed at it ..."
    $env:TIMELINE_BUILDER_TEST_DELETE_INPUT = $classicCopy
    try { $runC = Invoke-ZipRun -OutputFile $csvC -Zip $mailZipPath -RunSources "Email" }
    finally { Remove-Item -LiteralPath Env:\TIMELINE_BUILDER_TEST_DELETE_INPUT -ErrorAction SilentlyContinue }
    if ($runC.ExitCode -ne 0) { $runC.Lines | ForEach-Object { Write-Host "  | $_" } }
    Assert-Equal -Name "run C: exit code" -Expected 0 -Actual $runC.ExitCode
    Assert-Equal -Name "run C: completed successfully" -Expected 1 -Actual @($runC.Lines -match "=== Timeline Builder Completed Successfully ===").Count
    Assert-Equal -Name "run C: attachment left in the zip (logged; the test hook found no file)" -Expected $true -Actual (
        $runC.Log -match "Not extracted: 1 copied email attachment\(s\)" -and $runC.Log -match "Test hook ignored \(not a file in the work folder\)")
    Assert-Equal -Name "run C: the attachment is no input file" -Expected $true -Actual ($runC.Log -match "All 2 input file\(s\) were still present")
    $rowsC = @()
    if (Test-Path -LiteralPath $csvC) { $rowsC = @(Import-Csv -LiteralPath $csvC) }
    $mailRows = @($rowsC | Where-Object { $_.Source -eq "Email-Attachments" } | ForEach-Object { "$($_.Timestamp) $($_.Description) ($($_.User))" })
    Assert-Equal -Name "run C: attachment rows from the manifest" -Expected (
        "2024-03-01 10:00:00.000 Outlook attachment in temp folder: invoice.docm (alice) | 2024-03-02 11:00:00.000 Outlook attachment in temp folder modified: invoice.docm (alice)") -Actual ($mailRows -join " | ")
    $reportLeftovers = @(@("findings.csv", "report.html", "report-model.json") | Where-Object { Test-Path -LiteralPath (Join-Path $testRoot $_) })
    Assert-Equal -Name "runs A and C (-NoReport): no report next to their timelines" -Expected "" -Actual ($reportLeftovers -join ", ")

    # --- Run F: a collection folder with a file whose path has 260 or more
    # characters. Windows PowerShell 5.1 cannot open it: the run stops at the
    # start with exit code 1 and names it (it would otherwise be left out of
    # a timeline that ends "Completed Successfully"). PowerShell 7 opens it
    # and builds the timeline --------------------------------------------
    $longRunColl = Join-Path (Get-LongPath $testRoot) "longrun\$collName"
    $longRunEvtx = "EventLogs\" + ("e" * (270 - $longRunColl.Length - 15)) + ".evtx"
    $longRunFiles = [ordered]@{
        "collection_info.json"    = $collectionInfo
        "collection_manifest.csv" = (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", $longRunEvtx))
        "USB\setupapi.dev.log"    = (New-SetupApiText -Instance $deviceA -LocalTime "2025/01/02 10:00:00.000")
        $longRunEvtx              = "not read here (-Sources USB)"
    }
    foreach ($rel in $longRunFiles.Keys) {
        $file = Get-ExtendedLengthPath ($longRunColl + '\' + $rel)
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($file))
        [System.IO.File]::WriteAllText($file, [string]$longRunFiles[$rel])
    }
    $csvF = Join-Path $testRoot "timeline-f.csv"
    Write-Host "Running the builder on a collection folder with a $($longRunColl.Length + 1 + $longRunEvtx.Length)-character path in it ..."
    $runF = Invoke-ZipRun -OutputFile $csvF -Zip $longRunColl
    if ($script:longPathsWork) {
        if ($runF.ExitCode -ne 0) { $runF.Lines | ForEach-Object { Write-Host "  | $_" } }
        Assert-Equal -Name "run F (long paths work here): a path of 260+ characters is read, exit code 0, the timeline written" -Expected "0 True" -Actual "$($runF.ExitCode) $(Test-Path -LiteralPath $csvF)"
    }
    else {
        if ($runF.ExitCode -ne 1) { $runF.Lines | ForEach-Object { Write-Host "  | $_" } }
        Assert-Equal -Name "run F: a path of 260+ characters stops the run at the start (exit code 1, no timeline)" -Expected "1 False" -Actual "$($runF.ExitCode) $(Test-Path -LiteralPath $csvF)"
        Assert-Equal -Name "run F: the error says so and names the file" -Expected "1 1" -Actual "$(@($runF.Lines -match 'ERROR: 1 file\(s\) or folder\(s\) of the collection have paths of 260 or more characters').Count) $(@($runF.Lines | Where-Object { $_.EndsWith($longRunEvtx) }).Count)"
    }

    # --- Run F2: a collection folder whose own path has 250 characters: even
    # the files right in it (collection_manifest.csv, ...) have paths of 260+
    # characters. Windows PowerShell 5.1 stops at the start (exit code 1)
    # and says that the folder's path is too long, not a count of a few
    # top-level names (the manifest cannot be read, and Get-ChildItem does
    # not go into the folders, so the rest cannot be counted) ------------
    $longRootBase = Join-Path (Get-LongPath $testRoot) "longroot"
    $longRootColl = $longRootBase + "\" + ("c" * (250 - $longRootBase.Length - 1))
    $longRootFiles = [ordered]@{
        "collection_info.json"    = $collectionInfo
        "collection_manifest.csv" = (New-TestManifest -RelativePaths @("USB\setupapi.dev.log"))
        "USB\setupapi.dev.log"    = (New-SetupApiText -Instance $deviceA -LocalTime "2025/01/02 10:00:00.000")
    }
    foreach ($rel in $longRootFiles.Keys) {
        $file = Get-ExtendedLengthPath ($longRootColl + '\' + $rel)
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($file))
        [System.IO.File]::WriteAllText($file, [string]$longRootFiles[$rel])
    }
    $csvF2 = Join-Path $testRoot "timeline-f2.csv"
    Write-Host "Running the builder on a collection folder whose own path has $($longRootColl.Length) characters ..."
    $runF2 = Invoke-ZipRun -OutputFile $csvF2 -Zip $longRootColl
    if ($script:longPathsWork) {
        if ($runF2.ExitCode -ne 0) { $runF2.Lines | ForEach-Object { Write-Host "  | $_" } }
        Assert-Equal -Name "run F2 (long paths work here): a collection folder of 250 characters is read, exit code 0, the timeline written" -Expected "0 True" -Actual "$($runF2.ExitCode) $(Test-Path -LiteralPath $csvF2)"
    }
    else {
        if ($runF2.ExitCode -ne 1) { $runF2.Lines | ForEach-Object { Write-Host "  | $_" } }
        Assert-Equal -Name "run F2: a collection folder of 250 characters stops the run at the start (exit code 1, no timeline)" -Expected "1 False" -Actual "$($runF2.ExitCode) $(Test-Path -LiteralPath $csvF2)"
        Assert-Equal -Name "run F2: the error says the folder's path is too long (with its length), no count of a few names" -Expected "1 0" -Actual "$(@($runF2.Lines -match "ERROR: The collection folder's path has 250 characters, too long for Windows PowerShell: even files or folders right in it cannot be opened").Count) $(@($runF2.Lines -match 'file\(s\) or folder\(s\) of the collection have paths of 260').Count)"
    }

    # --- Run G: a file that is not a collection zip, with [ ] in its name:
    # "Input path is a file" (not the folder-wildcard error) -------------
    $otherDir = Join-Path $testRoot "other"
    [void][System.IO.Directory]::CreateDirectory($otherDir)
    $sevenZip = Join-Path $otherDir "Case [2].7z"
    [System.IO.File]::WriteAllText($sevenZip, "not a zip")
    $runG = Invoke-ZipRun -OutputFile (Join-Path $testRoot "timeline-g.csv") -Zip $sevenZip
    Assert-Equal -Name "run G: a .7z named 'Case [2].7z': exit code 1, 'Input path is a file', no wildcard error" -Expected "1 1 0" -Actual "$($runG.ExitCode) $(@($runG.Lines -match 'ERROR: Input path is a file, not a collection folder or \.zip: ').Count) $(@($runG.Lines -match 'wildcards').Count)"
    $dumpFile = Join-Path $otherDir "Case [2]_memory_dump.dmp"
    [System.IO.File]::WriteAllText($dumpFile, "not a dump")
    $runG2 = Invoke-ZipRun -OutputFile (Join-Path $testRoot "timeline-g2.csv") -Zip $dumpFile
    Assert-Equal -Name "run G: a memory dump given on its own: exit code 1, 'Input path is a file' and a hint to give its collection" -Expected "1 1 1" -Actual "$($runG2.ExitCode) $(@($runG2.Lines -match 'ERROR: Input path is a file').Count) $(@($runG2.Lines -match 'A memory dump is not read on its own: give its collection').Count)"

    # --- Run H: the builder in a folder whose path has [ ]: it stops at the
    # start (exit code 1) with an error that says so, before anything is
    # written (Export-Csv and ImportExcel would read the brackets as
    # wildcards and write no timeline.csv) --------------------------------
    $bracketBuilderDir = Join-Path $testRoot "inst [1]"
    [void][System.IO.Directory]::CreateDirectory($bracketBuilderDir)
    $bracketBuilder = Join-Path $bracketBuilderDir "timeline-builder.ps1"
    Copy-Item -LiteralPath $builder -Destination $bracketBuilder
    $outputH = @(& $powershellExe -NoProfile -ExecutionPolicy Bypass -File $bracketBuilder -InputPath $zipPath -Sources USB -NoExcel -NoReport -Viewer None 2>&1 | ForEach-Object { "$_" })
    $exitH = $LASTEXITCODE
    Assert-Equal -Name "run H: builder in a folder with [ ]: exit code 1, the error, no reports\ folder" -Expected "1 1 False" -Actual "$exitH $(@($outputH -match "ERROR: The path of the builder's folder has \[ \], \* or \? in it").Count) $([System.IO.Directory]::Exists((Join-Path $bracketBuilderDir 'reports')))"

    # --- Run I: a folder that holds collection zips, not a collection: no
    # entries, and a hint to give one of the zips ---------------------------
    $zipsOnly = Join-Path $testRoot "zips-only"
    [void][System.IO.Directory]::CreateDirectory($zipsOnly)
    Copy-Item -LiteralPath $zipPath -Destination $zipsOnly
    $runI = Invoke-ZipRun -OutputFile (Join-Path $testRoot "timeline-i.csv") -Zip $zipsOnly
    Assert-Equal -Name "run I: a folder of zips: exit code 0, no entries, the hint to drop one .zip" -Expected "0 1 1" -Actual "$($runI.ExitCode) $(@($runI.Lines -match 'No timeline entries were collected\. Check the input path \(and -Sources, if given\)\.').Count) $(@($runI.Lines -match 'This folder holds \.zip file\(s\), not a collection: drop one collection \.zip on Run-TimelineBuilder\.bat').Count)"
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    # Paths of 260+ characters first (Windows PowerShell's Remove-Item
    # cannot delete them)
    foreach ($longFolder in @((Join-Path $testRoot "long"), (Join-Path $testRoot "longrun"), (Join-Path $testRoot "longroot"))) {
        $extendedFolder = '\\?\' + [System.IO.Path]::GetFullPath($longFolder)
        try { if ([System.IO.Directory]::Exists($extendedFolder)) { [System.IO.Directory]::Delete($extendedFolder, $true) } }
        catch { Write-Host "Could not remove ${longFolder}: $($_.Exception.Message)" }
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the ones from this run
    if ($reportsDir) {
        Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $reportsBefore -notcontains $_.FullName } |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
