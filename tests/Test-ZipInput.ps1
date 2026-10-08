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
#   lookup, a ".." entry not written outside the folder, nothing extracted
#   when the zip does not fit), the manifest lookups from an outer folder,
#   the input-file list of a collection folder and the list of missing
#   files, the free-space verdict, the temp-folder check (8.3 short paths
#   too), the end-of-run hive list, the clean-up of work folders left by
#   earlier runs, the refusal of a network work folder and the end-of-run
#   banners (missing input files, unexpected errors).
# Part 2 -- builder runs: a synthetic collection zip whose entries are dated
#   2025, with two setupapi logs (USBSTOR devices) under "/" and "\" entry
#   names and a manifest, passed as -InputPath (-Sources USB):
#   - both logs are parsed, exit code 0, the extraction and the free-space
#     check are in the log;
#   - the work folder is in %LOCALAPPDATA%\TimelineBuilder, outside every
#     temp folder, and removed at the end; no TriageExtract_* or
#     TimelineHive_* is left in %TEMP%; the zip is not changed;
#   - with the builder's test hook deleting one extracted file mid-run
#     (TIMELINE_BUILDER_TEST_DELETE_INPUT; it only deletes inside the work
#     folder) and -WorkDir: exit code 2, the "MISSING INPUT FILE(S)"
#     banner, the work folder made in -WorkDir and removed, -WorkDir kept.
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
    $unitEntries = [ordered]@{
        "Coll/"                          = $null
        "Coll/USB/setupapi.dev.log"      = "forward slashes"
        "Coll\Registry\alice\NTUSER.DAT" = "backslashes"
        "Coll/$($longRel.Replace('\', '/'))" = "long name"
        "Coll/collection_manifest.csv"   = (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", "Registry\alice\NTUSER.DAT", $longRel))
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
    $extracted = @(Get-ChildItem -LiteralPath $dest -Recurse -File)
    Assert-Equal -Name "files extracted (folder entry and '..' entry skipped)" -Expected 4 -Actual $extracted.Count
    Assert-Equal -Name "extracted files recorded as input files" -Expected 4 -Actual $script:inputFiles.Count
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
    Assert-Equal -Name "zip that does not fit: nothing extracted or recorded" -Expected "0 4" -Actual "$(@(Get-ChildItem -LiteralPath $noSpaceDest -Recurse -File -ErrorAction SilentlyContinue).Count) $($script:inputFiles.Count)"

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

    # --- Input files of a collection folder ------------------------------
    $folderColl = Join-Path $testRoot "folder\Coll"
    foreach ($rel in @("USB\setupapi.dev.log", "Registry\SYSTEM", "Memory\Coll_memory_dump.dmp")) {
        $file = Join-Path $folderColl $rel
        New-Item -ItemType Directory -Path (Split-Path $file -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllText($file, "x")
    }
    [System.IO.File]::WriteAllText((Join-Path $folderColl "collection_manifest.csv"),
        (New-TestManifest -RelativePaths @("USB\setupapi.dev.log", "Registry\SYSTEM", "Memory\Coll_memory_dump.dmp", "USB\gone_before_the_run.log")))
    Set-Variable -Name InputPath -Value (Split-Path $folderColl -Parent) -Scope Script
    $script:collectionManifest = $null
    $script:inputFiles = New-Object System.Collections.Generic.List[string]
    Add-ManifestInputFiles
    $tracked = @($script:inputFiles | ForEach-Object { $_.Substring($folderColl.Length + 1) } | Sort-Object) -join ", "
    Assert-Equal -Name "folder input: manifest files present at the start are tracked (no memory dump)" -Expected "Registry\SYSTEM, USB\setupapi.dev.log" -Actual $tracked
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

    # Runs the builder on the zip (USB source, CSV only); returns its exit
    # code, console output and log file
    function Invoke-ZipRun {
        param([string]$OutputFile, [string[]]$ExtraArguments = @())
        $ErrorActionPreference = "Continue"
        $before = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder -InputPath $zipPath -Sources "USB" `
            -OutputFile $OutputFile -NoExcel -Viewer None @ExtraArguments 2>&1
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
    Assert-Equal -Name "run A: device from setupapi.dev.log (/ entry name)" -Expected "1 2025-01-02 10:00:00.000 Device install: TestVen DiskA (serial TESTSERIAL0001)" -Actual "$($rowA.Count) $($rowA[0].Timestamp) $($rowA[0].Description)"
    Assert-Equal -Name "run A: device from the rotated setupapi log (\ entry name)" -Expected "1 2024-11-30 09:00:00.000 Device install: TestVen DiskB (serial TESTSERIAL0002)" -Actual "$($rowB.Count) $($rowB[0].Timestamp) $($rowB[0].Description)"
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
    $csvB = Join-Path $testRoot "timeline-b.csv"
    $workDirB = Join-Path $testRoot "wd"
    New-Item -ItemType Directory -Path $workDirB | Out-Null
    Write-Host "Running the builder again, with the test hook deleting an extracted setupapi log and -WorkDir $workDirB ..."
    $env:TIMELINE_BUILDER_TEST_DELETE_INPUT = "USB\setupapi.dev.20241201_000000.log"
    try { $runB = Invoke-ZipRun -OutputFile $csvB -ExtraArguments @("-WorkDir", $workDirB) }
    finally { Remove-Item -LiteralPath Env:\TIMELINE_BUILDER_TEST_DELETE_INPUT -ErrorAction SilentlyContinue }
    if ($runB.ExitCode -ne 2) { $runB.Lines | ForEach-Object { Write-Host "  | $_" } }
    Assert-Equal -Name "run B: exit code 2 (timeline incomplete)" -Expected 2 -Actual $runB.ExitCode
    Assert-Equal -Name "run B: banner" -Expected 1 -Actual @($runB.Lines -match [regex]::Escape("=== Timeline Builder Completed WITH 1 MISSING INPUT FILE(S) -- timeline incomplete ===")).Count
    Assert-Equal -Name "run B: no success banner" -Expected 0 -Actual @($runB.Lines -match "Completed Successfully").Count
    Assert-Equal -Name "run B: missing file listed under USB\" -Expected $true -Actual ($runB.Log -match "Missing in USB\\: 1 file\(s\)" -and $runB.Log -match "setupapi\.dev\.20241201_000000\.log")
    $rowsB = @()
    if (Test-Path -LiteralPath $csvB) { $rowsB = @(Import-Csv -LiteralPath $csvB) }
    Assert-Equal -Name "run B: the remaining log is parsed, the deleted one is not" -Expected "1 0" -Actual "$(@(Get-SetupApiRow -Rows $rowsB -Serial 'TESTSERIAL0001').Count) $(@(Get-SetupApiRow -Rows $rowsB -Serial 'TESTSERIAL0002').Count)"
    Write-TestResult -Name "run B: work folder made in -WorkDir" -Passed ($runB.WorkFolder -and (Split-Path $runB.WorkFolder -Parent) -eq $workDirB) -Message "work folder: $($runB.WorkFolder)"
    Write-TestResult -Name "run B: work folder removed, -WorkDir kept" -Passed ($runB.WorkFolder -and -not (Test-Path -LiteralPath $runB.WorkFolder) -and (Test-Path -LiteralPath $workDirB)) -Message "work folder: $($runB.WorkFolder)"
    Assert-Equal -Name "run B: the zip is not changed" -Expected $zipHash -Actual (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
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
