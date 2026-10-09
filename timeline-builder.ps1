# =============================================================
# Windows 11 Forensic Timeline Builder
# Builds a unified chronological CSV timeline from forensic
# artifacts collected by triage-collector.ps1 or manually.
# Pure PowerShell alternative to log2timeline/plaso.
# Use Run-TimelineBuilder.bat to launch (handles elevation + policy)
# =============================================================

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "MaxUsnEntries", Justification = "Read by Parse-UsnJournal through script scope")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "MftDays", Justification = "Read by Parse-FileSystem through script scope")]
[CmdletBinding(DefaultParameterSetName = "Direct")]
param(
    # A collection folder, or a collection .zip (extracted into the work folder)
    [Parameter(ParameterSetName = "Direct", Mandatory = $true)]
    [string]$InputPath,

    [Parameter(ParameterSetName = "Browse", Mandatory = $true)]
    [switch]$Browse,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [datetime]$StartDate,

    [Parameter(Mandatory = $false)]
    [datetime]$EndDate,

    # Each value may also be a comma-separated list ("EventLogs,Prefetch"), which
    # is how powershell.exe -File passes -Sources A,B; it is split after binding.
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        $validSources = @("EventLogs", "Prefetch", "RecentFiles", "Registry", "FileSystem", "Browser", "ScheduledTasks", "Services", "Network", "USB", "Persistence", "UsnJournal", "Amcache", "PowerShellHistory", "SystemInfo", "AntiVirus", "Email", "SRUM", "Memory")
        foreach ($name in ("$_" -split ',')) {
            if ($name.Trim() -and $validSources -notcontains $name.Trim()) {
                throw "Unknown source '$($name.Trim())'. Valid sources: $($validSources -join ', ')"
            }
        }
        $true
    })]
    [string[]]$Sources = @("EventLogs", "Prefetch", "RecentFiles", "Registry", "FileSystem", "Browser", "ScheduledTasks", "Services", "Network", "USB", "Persistence", "UsnJournal", "Amcache", "PowerShellHistory", "SystemInfo", "AntiVirus", "Email", "SRUM"),

    [Parameter(Mandatory = $false)]
    [string[]]$Keywords,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 2147483647)]
    [int]$MaxUsnEntries = 0,

    # $MFT file-system events: only times within this many days before the
    # collection are added (0 = all). A full $MFT can hold millions of times.
    # Mark-of-the-Web (downloaded or extracted file) rows are always added.
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 36500)]
    [int]$MftDays = 7,

    # Viewer to open at the end without asking (for scripts and automation)
    [Parameter(Mandatory = $false)]
    [ValidateSet("Excel", "TimelineExplorer", "Both", "None")]
    [string]$Viewer,

    # CSV only: don't generate timeline.xlsx (ImportExcel isn't needed)
    [Parameter(Mandatory = $false)]
    [switch]$NoExcel,

    # Folder in which this run's work folder (extracted zip, scratch copies)
    # is created. Default: %LOCALAPPDATA%\TimelineBuilder. Not a temp folder:
    # Windows cleans those up during the run.
    [Parameter(Mandatory = $false)]
    [string]$WorkDir,

    # Memory dump file (.dmp or .raw) of this collection, used before every
    # other place. Needed only for a dump Find-MemoryDump does not find or
    # does not use: one moved to another folder after the collection, one
    # on a network share that is not next to the collection zip or folder,
    # or one whose size is not the one collection_manifest.csv lists.
    # Without it, Find-MemoryDump finds the dump where the collector saved
    # it (the path in collection_manifest.csv, also on another drive:
    # -MemoryOutputPath or the drive picked at the collector's memory
    # prompt, also when that drive has another letter now), next to the
    # collection zip or folder, and in the collection. A dump copied next
    # to the zip as <zip name>_memory_dump.dmp (.raw) is found from
    # Run-TimelineBuilder.bat too, which cannot pass this parameter.
    [Parameter(Mandatory = $false)]
    [string]$MemoryDumpPath
)

# --- Require Administrator ---
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "  Option 1: Double-click Run-TimelineBuilder.bat (recommended)" -ForegroundColor Yellow
    Write-Host "  Option 2: powershell -ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`"" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

$ErrorActionPreference = "Continue"

# =============================================================
# Logging
# Set up before a collection is opened, so a zip extraction is logged
# too. $logFile is set once a collection is picked and the report folder
# exists; until then messages only go to the console.
# =============================================================
$logFile = $null

function Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    if ($logFile) { Add-Content -Path $logFile -Value $entry }
}

function Log-Warning {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WARNING: $Message"
    Write-Host $entry -ForegroundColor Yellow
    if ($logFile) { Add-Content -Path $logFile -Value $entry }
}

function Log-Error {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $Message"
    Write-Host $entry -ForegroundColor Red
    if ($logFile) { Add-Content -Path $logFile -Value $entry }
}

function Log-Success {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry -ForegroundColor Green
    if ($logFile) { Add-Content -Path $logFile -Value $entry }
}

# =============================================================
# Work folder and input files
# A collection zip is extracted into a per-run work folder,
# <base>\w<PID>_<HHmmss>, outside every temp folder: Windows Storage
# Sense deletes files older than 7 days from %TEMP% when disk space is
# low, and extracted files keep the date stored in the zip (often months
# old), so it deleted collection files while a timeline was being built.
# Scratch copies (hives for reg load, browser databases for sqlite3) go
# to <work folder>\scratch. The main body runs in try/finally, so the
# folder is removed on every exit (errors, exit, Ctrl+C). Every input
# file is recorded; one that disappears before the end makes the run end
# with exit code 2 ("timeline incomplete").
# =============================================================
$script:selectedZipPath = $null
$script:runWorkDir = $null       # this run's work folder
$script:runWorkLock = $null      # its .lock file, held open for the whole run
$script:runScratchDir = $null    # <work folder>\scratch
$script:runHives = New-Object System.Collections.Generic.List[string]    # HKLM hives loaded and not yet unloaded
$script:inputFiles = New-Object System.Collections.Generic.List[string]  # input files that must exist until the end
$script:shortenedNames = @{}     # extracted file shortened to fit -> its full-length path
$script:collectionManifest = $null
$script:missingInputCount = 0
$script:unexpectedErrorCount = 0  # errors caught by the main body's trap (rest of a step skipped)

# Long form of a path: full, with 8.3 short names expanded (GitHub runners
# have a %TEMP% like C:\Users\RUNNER~1\...) and no trailing backslash. A
# path that does not exist is only made full. A relative path (e.g. a
# relative -InputPath) is resolved against the PowerShell location, as the
# parsers' Get-ChildItem calls do, not the process working directory.
if (-not ([System.Management.Automation.PSTypeName]'TimelineNative.LongPath').Type) {
    Add-Type -Namespace TimelineNative -Name LongPath -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetLongPathName(string lpszShortPath, System.Text.StringBuilder lpszLongPath, uint cchBuffer);
'@
}

function Get-LongPath {
    param([string]$Path)
    if (-not $Path) { return "" }
    $full = $Path
    try { $full = [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)) }
    catch {
        try { $full = [System.IO.Path]::GetFullPath($Path) }
        catch { Write-Verbose "Could not make $Path a full path: $($_.Exception.Message)" }
    }
    $buffer = New-Object System.Text.StringBuilder 1024
    $length = [TimelineNative.LongPath]::GetLongPathName($full, $buffer, [uint32]$buffer.Capacity)
    if ($length -gt 0 -and $length -lt $buffer.Capacity) { $full = $buffer.ToString() }
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    return $full
}

# The temp folder (long form) that contains $Path, or "". Windows cleans
# these up on its own (Storage Sense, Disk Cleanup).
function Get-ContainingTempFolder {
    param([string]$Path)
    $long = Get-LongPath $Path
    if (-not $long) { return "" }
    $candidates = @($env:TEMP, $env:TMP, [System.IO.Path]::GetTempPath())
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    if ($localAppData) { $candidates += (Join-Path $localAppData "Temp") }
    if ($env:SystemRoot) { $candidates += (Join-Path $env:SystemRoot "Temp") }
    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        $temp = Get-LongPath $candidate
        if ($long -eq $temp -or $long.StartsWith($temp.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $temp }
    }
    return ""
}

# Remove the work folders of earlier runs in $BaseFolder that ended
# without cleaning up (crash, closed window): only w<PID>_<HHmmss> folders
# whose .lock exists and is not held open by a running builder. Files in
# use (e.g. a hive copy that is still loaded) are skipped; the .lock goes
# last, so such a folder is tried again by the next run.
function Remove-StaleWorkFolders {
    param([string]$BaseFolder)
    foreach ($dir in @(Get-ChildItem -LiteralPath $BaseFolder -Directory -ErrorAction SilentlyContinue)) {
        if ($dir.Name -notmatch '^w\d+_\d{6}(_\d+)?$') { continue }
        $lockPath = Join-Path $dir.FullName ".lock"
        if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { continue }
        try { [System.IO.File]::Open($lockPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None).Close() }
        catch { continue }   # held open: that run is still going
        Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".lock" } |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        if (@(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".lock" }).Count -gt 0) {
            Log-Warning "Could not fully remove the work folder of an earlier run (files in use): $($dir.FullName)"
            continue
        }
        Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        Log "Removed the work folder of an earlier run: $($dir.FullName)"
    }
}

# $true when $Path is a network path: a UNC path (\\server\share\...) or a
# folder on a mapped network drive. reg load (RegLoadKey) only loads a hive
# from a local file, and the hive copies are made in the work folder, so
# the work folder must be on a local drive. A path that is not valid is
# not reported here; creating the folder reports it.
function Test-NetworkPath {
    param([string]$Path)
    $root = ""
    try { $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path)) }
    catch { return $false }
    if (-not $root) { return $false }
    if ($root.StartsWith('\\')) { return $true }
    try { return ((New-Object System.IO.DriveInfo($root)).DriveType -eq [System.IO.DriveType]::Network) }
    catch { return $false }
}

# Create this run's work folder, <base>\w<PID>_<HHmmss> (kept short: deep
# collection paths come close to the 260-character limit), with a
# <work folder>\scratch subfolder, and hold its .lock open until the end
# of the run. Base: -WorkDir if given, else %LOCALAPPDATA%\TimelineBuilder
# (no Windows cleanup covers it), else the script's work\ folder. A base
# on a network drive is not used (see Test-NetworkPath). Returns the
# folder, or "" after logging why not.
function New-RunWorkFolder {
    param([string]$BaseFolder)
    $bases = @()
    if ($BaseFolder) { $bases += $BaseFolder }
    else {
        $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
        if ($localAppData) { $bases += (Join-Path $localAppData "TimelineBuilder") }
        $bases += (Join-Path $PSScriptRoot "work")
    }
    foreach ($base in $bases) {
        if (Test-NetworkPath $base) {
            Log-Warning "Not using $base for the work folder: it is on a network drive or share, and reg load cannot load hives from there."
            continue
        }
        $folder = ""
        try {
            [void][System.IO.Directory]::CreateDirectory($base)
            Remove-StaleWorkFolders -BaseFolder $base
            $name = "w$($PID)_$(Get-Date -Format 'HHmmss')"
            $folder = Join-Path $base $name
            for ($n = 2; Test-Path -LiteralPath $folder; $n++) { $folder = Join-Path $base "$($name)_$n" }
            [void][System.IO.Directory]::CreateDirectory($folder)
            $script:runWorkLock = [System.IO.File]::Open((Join-Path $folder ".lock"), [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $note = [System.Text.Encoding]::ASCII.GetBytes("timeline-builder.ps1 work folder, PID $PID, started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n")
            $script:runWorkLock.Write($note, 0, $note.Length)
            $script:runWorkLock.Flush()
            $script:runScratchDir = Join-Path $folder "scratch"
            [void][System.IO.Directory]::CreateDirectory($script:runScratchDir)
            return $folder
        }
        catch {
            Log-Warning "Could not create a work folder in ${base}: $($_.Exception.Message)"
            if ($script:runWorkLock) { $script:runWorkLock.Close(); $script:runWorkLock = $null }
            $script:runScratchDir = $null
            if ($folder -and (Test-Path -LiteralPath $folder)) { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    return ""
}

# Delete this run's work folder (extracted collection and scratch copies);
# call Dismount-RunHives first. Hive copies stay locked briefly after reg
# unload, so this retries. The .lock goes last: a folder that cannot be
# emptied is removed by the next run.
function Remove-RunWorkFolder {
    if (-not $script:runWorkDir) { return }
    Log "Removing the work folder: $($script:runWorkDir)"
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    $left = @()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Get-ChildItem -LiteralPath $script:runWorkDir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".lock" } |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        $left = @(Get-ChildItem -LiteralPath $script:runWorkDir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne ".lock" })
        if ($left.Count -eq 0) { break }
        if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
    }
    if ($script:runWorkLock) { $script:runWorkLock.Close(); $script:runWorkLock = $null }
    if ($left.Count -eq 0) { Remove-Item -LiteralPath $script:runWorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $script:runWorkDir) {
        Log-Warning "  Could not remove the work folder (file in use). The next run removes it, or delete it manually: $($script:runWorkDir)"
    }
    else { Log "  Work folder removed." }
}

# Folder for scratch copies (hives for reg load, browser databases for
# sqlite3): <work folder>\scratch. Outside a builder run (functions loaded
# by a test) the system temp folder.
function Get-ScratchFolder {
    if ($script:runScratchDir) { return $script:runScratchDir }
    return [System.IO.Path]::GetTempPath()
}

# Hives this run loaded under HKLM (Mount-TimelineHive, Parse-Amcache) and
# has not unloaded yet. Registered before reg load, so an interrupted load
# is covered too.
function Register-RunHive {
    param([string]$Name)
    if ($null -eq $script:runHives) { $script:runHives = New-Object System.Collections.Generic.List[string] }
    if (-not $script:runHives.Contains($Name)) { $script:runHives.Add($Name) }
}

function Unregister-RunHive {
    param([string]$Name)
    if ($script:runHives) { [void]$script:runHives.Remove($Name) }
}

# Unload the hives this run left loaded (a parser stopped by an error or
# Ctrl+C, or an unload that failed), so their copies in the work folder
# can be deleted. Only this run's own TEMP_TL* / TEMP_AMCACHE_* hives.
function Dismount-RunHives {
    if (-not $script:runHives -or $script:runHives.Count -eq 0) { return }
    $loadedNow = @()
    try { $loadedNow = @([Microsoft.Win32.Registry]::LocalMachine.GetSubKeyNames()) }
    catch { Write-Verbose "Could not list the loaded hives: $($_.Exception.Message)" }
    foreach ($name in @($script:runHives)) {
        # Not loaded (any more): nothing to unload
        if ($loadedNow.Count -gt 0 -and $loadedNow -notcontains $name) { Unregister-RunHive $name; continue }
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        $unloaded = $false
        for ($attempt = 1; $attempt -le 3 -and -not $unloaded; $attempt++) {
            $null = & reg unload "HKLM\$name" 2>&1
            $unloaded = ($LASTEXITCODE -eq 0)
            if (-not $unloaded) { Start-Sleep -Milliseconds 1000 }
        }
        if ($unloaded) {
            Log "Unloaded hive HKLM\$name (left loaded by a parser)"
            Unregister-RunHive $name
        }
        else { Log-Warning "Failed to unload hive HKLM\$name -- run: reg unload HKLM\$name" }
    }
}

# Free space verdict for extracting $NeededBytes onto a volume: "Error"
# below the size plus 256 MB, "Warning" below the size plus 1 GB or when
# the system drive would be left with under 10% free, else "Ok"
function Get-ExtractionSpaceVerdict {
    param([long]$FreeBytes, [long]$TotalBytes, [long]$NeededBytes, [bool]$IsSystemDrive)
    if ($FreeBytes -lt $NeededBytes + 256MB) { return "Error" }
    if ($FreeBytes -lt $NeededBytes + 1GB) { return "Warning" }
    if ($IsSystemDrive -and $TotalBytes -gt 0 -and ($FreeBytes - $NeededBytes) -lt ($TotalBytes / 10)) { return "Warning" }
    return "Ok"
}

# Check the free space on the drive of $Folder before extracting
# $NeededBytes into it. Logs the result; $false when the zip cannot fit.
# Skipped (with a log line) for UNC paths and drives that report no size.
function Test-ExtractionSpace {
    param([string]$Folder, [long]$NeededBytes)
    $root = ""
    try { $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Folder)) }
    catch { Write-Verbose "Could not get the drive of ${Folder}: $($_.Exception.Message)" }
    if (-not $root -or $root.StartsWith('\\')) {
        Log "  Free space check skipped: $Folder is not on a drive letter."
        return $true
    }
    try {
        $drive = New-Object System.IO.DriveInfo($root)
        $free = $drive.AvailableFreeSpace
        $total = $drive.TotalSize
    }
    catch {
        Log "  Free space check skipped for ${root}: $($_.Exception.Message)"
        return $true
    }
    $isSystemDrive = $root.TrimEnd('\') -eq "$env:SystemDrive".TrimEnd('\')
    $verdict = Get-ExtractionSpaceVerdict -FreeBytes $free -TotalBytes $total -NeededBytes $NeededBytes -IsSystemDrive $isSystemDrive
    $numbers = "$([math]::Round($free / 1GB, 2)) GB free of $([math]::Round($total / 1GB, 1)) GB, $([math]::Round($NeededBytes / 1MB, 1)) MB to extract"
    if ($verdict -eq "Error") {
        Log-Error "Not enough free space on $root for the extraction ($numbers, plus 256 MB to spare). Free up space or pass -WorkDir with a folder on another drive."
        return $false
    }
    if ($verdict -eq "Warning") {
        Log-Warning "Low free space on $root ($numbers). Windows may start cleaning up when a drive runs low; consider -WorkDir with a folder on another drive."
    }
    else { Log "  Free space on ${root}: $numbers" }
    return $true
}

# $true for a path (relative to the collection, or a zip entry name with
# "\") inside the email attachment copies the collector makes
# (Email\<user>\Outlook\SecureTemp\, Email\<user>\NewOutlook\Attachments\).
# No parser reads them: Parse-Email takes their rows from the manifest and
# the email listings. They can have any name -- an attached .lnk or .evtx
# is not this system's shortcut or event log -- so Find-ArtifactFiles never
# returns them to a parser. They can be malware, which antivirus on this
# machine may quarantine, so they are not extracted from a collection zip
# and are not input files (their removal does not make a timeline
# incomplete).
function Test-EmailAttachmentCopy {
    param([string]$RelativePath)
    return $RelativePath -match '(?:^|\\)Email\\[^\\]+\\(?:Outlook\\SecureTemp|NewOutlook\\Attachments)\\'
}

# Extract a collection zip into $Destination entry by entry (not
# Expand-Archive), so that:
#  - entry names with "/" (the zip standard) and "\" (older collectors)
#    both extract into folders;
#  - a path over 240 characters is shortened (start of the name plus a
#    hash) instead of failing the extraction; the full-length path is kept
#    in $script:shortenedNames, so manifest lookups still find the file;
#  - no entry is written outside $Destination ("..", rooted names);
#  - files keep the date stored in the zip. Several parsers fall back to a
#    file's date, so it is never changed to "now";
#  - copied email attachments stay in the zip (see Test-EmailAttachmentCopy).
# Every extracted file is recorded as an input file. Throws when the zip
# cannot be read, does not fit on the drive, or an entry fails to extract.
function Expand-CollectionZip {
    param([string]$ZipPath, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Destination = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\')
    [void][System.IO.Directory]::CreateDirectory($Destination)
    $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    $sha1 = $null
    try {
        # Folder entries end with a separator
        $fileEntries = New-Object System.Collections.Generic.List[object]
        $attachmentCount = 0
        $attachmentBytes = 0L
        $totalBytes = 0L
        foreach ($entry in $zipArchive.Entries) {
            if (-not $entry.FullName -or $entry.FullName -match '[/\\]$') { continue }
            if (Test-EmailAttachmentCopy $entry.FullName.Replace('/', '\')) {
                $attachmentCount++
                $attachmentBytes += $entry.Length
                continue
            }
            $fileEntries.Add($entry)
            $totalBytes += $entry.Length
        }
        Log "  Zip: $ZipPath -- $($zipArchive.Entries.Count) entries, $($fileEntries.Count + $attachmentCount) file(s), $([math]::Round(($totalBytes + $attachmentBytes) / 1MB, 1)) MB uncompressed"
        if ($attachmentCount -gt 0) {
            Log "  Not extracted: $attachmentCount copied email attachment(s), $([math]::Round($attachmentBytes / 1MB, 1)) MB. No parser reads them (their rows come from the manifest and the email listings), and antivirus may quarantine them."
        }
        if (-not (Test-ExtractionSpace -Folder $Destination -NeededBytes $totalBytes)) {
            throw "not enough free space to extract the zip"
        }

        $shortenedCount = 0
        $skippedCount = 0
        foreach ($entry in $fileEntries) {
            $relName = $entry.FullName.Replace('/', '\')
            $leaf = $relName.Substring($relName.LastIndexOf('\') + 1)
            $entryDest = Join-Path $Destination $relName
            $fullLengthDest = $entryDest
            $shortened = $false
            if ($entryDest.Length -gt 240) {
                # Keep the name's start and add a hash so it stays unique
                $entryDir = Split-Path $entryDest -Parent
                $ext = [System.IO.Path]::GetExtension($leaf)
                if (-not $sha1) { $sha1 = [System.Security.Cryptography.SHA1]::Create() }
                $nameHash =[System.BitConverter]::ToString($sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($leaf))).Replace("-", "").Substring(0, 8)
                $keep = [Math]::Max(8, 240 - $entryDir.Length - 1 - $ext.Length - 9)
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
                if ($baseName.Length -gt $keep) { $baseName = $baseName.Substring(0, $keep) }
                $entryDest = Join-Path $entryDir "$baseName~$nameHash$ext"
                $shortened = $true
            }
            # Never write outside the extraction folder (".." or rooted entry names)
            $fullDest = ""
            try { $fullDest = [System.IO.Path]::GetFullPath($entryDest) }
            catch { Write-Verbose "Zip entry $($entry.FullName) has no valid path: $($_.Exception.Message)" }
            if (-not $fullDest.StartsWith($Destination + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                Log-Warning "  Zip entry skipped (it would be written outside the extraction folder): $($entry.FullName)"
                $skippedCount++
                continue
            }
            [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($fullDest))
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $fullDest, $true)
            $script:inputFiles.Add($fullDest)
            if ($shortened) {
                $script:shortenedNames[$fullDest] = $fullLengthDest
                Log "  Shortened to fit the 260-character path limit: $relName -> $(Split-Path $fullDest -Leaf)"
                $shortenedCount++
            }
        }
        $summary = "  Extracted $($fileEntries.Count - $skippedCount) file(s) to $Destination"
        if ($shortenedCount -gt 0) { $summary += " ($shortenedCount over-long file name(s) shortened)" }
        Log $summary
    }
    finally {
        if ($sha1) { $sha1.Dispose() }
        $zipArchive.Dispose()
    }
}

# collection_manifest.csv of the collection (written by the triage
# collector): the one nearest to -InputPath, so an outer folder (e.g. the
# zip extracted with Windows "Extract All") works too. Its RelativePath
# column is relative to the manifest's own folder. Read once. Path and
# Folder are "" and Rows is empty when there is no manifest.
function Get-CollectionManifest {
    if ($script:collectionManifest) { return $script:collectionManifest }
    $manifest = [PSCustomObject]@{
        Path          = ""
        Folder        = ""
        Rows          = @()
        RelativePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }
    $mf = Get-ChildItem -Path $InputPath -Filter "collection_manifest.csv" -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } | Select-Object -First 1
    if ($mf) {
        $manifest.Path = $mf.FullName
        $manifest.Folder = $mf.DirectoryName
        try {
            $manifest.Rows = @(Import-Csv -LiteralPath $mf.FullName -ErrorAction Stop)
            foreach ($row in $manifest.Rows) {
                if ($row.PSObject.Properties["RelativePath"] -and $row.RelativePath) { [void]$manifest.RelativePaths.Add($row.RelativePath) }
            }
        }
        catch { Log-Warning "Could not read collection manifest: $($_.Exception.Message)" }
    }
    $script:collectionManifest = $manifest
    return $manifest
}

# Folder the collection's relative paths start from: the folder of
# collection_manifest.csv, else -InputPath. A relative -InputPath is
# resolved against the PowerShell location (as the parsers' Get-ChildItem
# calls do), not the process working directory.
function Get-CollectionRootFolder {
    $folder = (Get-CollectionManifest).Folder
    if (-not $folder) { $folder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath) }
    return [System.IO.Path]::GetFullPath($folder).TrimEnd('\')
}

# Input files of a collection folder: the files collection_manifest.csv
# lists that exist now (files gone before the run are not tracked).
# Memory dumps are left out: they are large and found separately. So are
# copied email attachments: no parser reads them, and antivirus may
# quarantine them (see Test-EmailAttachmentCopy). Without a manifest
# nothing is tracked.
function Add-ManifestInputFiles {
    $manifest = Get-CollectionManifest
    if (-not $manifest.Path) {
        Log "No collection_manifest.csv found: input files are not checked for deletion during the run."
        return
    }
    $root = [System.IO.Path]::GetFullPath($manifest.Folder).TrimEnd('\')
    $listed = 0
    foreach ($rel in $manifest.RelativePaths) {
        if ($rel -match '^Memory\\.+\.dmp$' -or (Test-EmailAttachmentCopy $rel)) { continue }
        $listed++
        $full = Join-Path $root $rel
        if ([System.IO.File]::Exists($full)) { $script:inputFiles.Add($full) }
    }
    Log "Input files: $($script:inputFiles.Count) of the $listed file(s) listed in $($manifest.Path) are present."
}

# Input files of this run that no longer exist
function Get-MissingInputFiles {
    return @($script:inputFiles | Where-Object { -not [System.IO.File]::Exists($_) })
}

# Log missing input files grouped by their top folder in the collection
# (USB\, Browser\, Registry\, ...), which shows the parsers affected. The
# log file gets every name; the console shows at most 20 per folder.
function Write-MissingInputFiles {
    param([string[]]$Files, [string]$BaseFolder)
    $base = $BaseFolder.TrimEnd('\') + '\'
    $groups = [ordered]@{}
    foreach ($file in $Files) {
        $name = $file
        if ($file.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) { $name = $file.Substring($base.Length) }
        $folder = "(collection folder)"
        if ($name.Contains('\')) { $folder = $name.Substring(0, $name.IndexOf('\') + 1) }
        if (-not $groups.Contains($folder)) { $groups[$folder] = New-Object System.Collections.Generic.List[string] }
        $groups[$folder].Add($name)
    }
    foreach ($folder in $groups.Keys) {
        $names = $groups[$folder]
        Log-Warning "  Missing in ${folder}: $($names.Count) file(s)"
        $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $lines = @($names | ForEach-Object { "[$time]     $_" })
        $lines | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
        if ($names.Count -gt 20) { Write-Host "[$time]     ... and $($names.Count - 20) more (all listed in the log file)" }
        if ($logFile) { Add-Content -Path $logFile -Value $lines }
    }
}

# The end-of-run banner. The timeline is incomplete when input files
# disappeared during the run, and may be incomplete when the main body's
# trap caught an unexpected error (the rest of that step, e.g. a whole
# parser, was skipped). Returns $true in both cases; the run then ends
# with exit code 2. -NoOutput: no timeline was written (no entries).
function Write-RunEndBanner {
    param([switch]$NoOutput)
    $verb = "Completed"
    $incompleteText = "-- timeline incomplete"
    $maybeText = "-- timeline may be incomplete"
    if ($NoOutput) {
        $verb = "Finished"
        $incompleteText = "(no output generated)"
        $maybeText = "(no output generated)"
    }
    $incomplete = $false
    if ($script:missingInputCount -gt 0) {
        Log-Error "=== Timeline Builder $verb WITH $($script:missingInputCount) MISSING INPUT FILE(S) $incompleteText ==="
        $incomplete = $true
    }
    if ($script:unexpectedErrorCount -gt 0) {
        Log-Error "=== Timeline Builder $verb WITH $($script:unexpectedErrorCount) UNEXPECTED ERROR(S) $maybeText ==="
        $incomplete = $true
    }
    if (-not $incomplete) {
        if ($NoOutput) { Log "=== Timeline Builder Finished (no output generated) ===" }
        else { Log "=== Timeline Builder Completed Successfully ===" }
    }
    return $incomplete
}

# =============================================================
# Browse mode: auto-find triage collections from sibling project
# =============================================================
if ($Browse) {
    # Look for sibling triage-collector/reports directory
    $toolsRoot = Split-Path $PSScriptRoot -Parent
    $triageReportsDir = Join-Path $toolsRoot "win11-triage-collector\reports"

    if (-not (Test-Path $triageReportsDir)) {
        Write-Host ""
        Write-Host "ERROR: Triage collector reports directory not found:" -ForegroundColor Red
        Write-Host "  $triageReportsDir" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Run the triage collector first, or provide a path manually:" -ForegroundColor Cyan
        Write-Host "  Run-TimelineBuilder.bat ""C:\path\to\collection""" -ForegroundColor Cyan
        Write-Host ""
        pause
        exit 1
    }

    # Find all .zip files in the reports directory
    $zipFiles = Get-ChildItem -Path $triageReportsDir -Filter "*.zip" -File | Sort-Object LastWriteTime -Descending

    if ($zipFiles.Count -eq 0) {
        Write-Host ""
        Write-Host "ERROR: No triage collection .zip files found in:" -ForegroundColor Red
        Write-Host "  $triageReportsDir" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Run the triage collector first to generate a collection." -ForegroundColor Cyan
        Write-Host ""
        pause
        exit 1
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Triage Collections Found" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    for ($i = 0; $i -lt $zipFiles.Count; $i++) {
        $z = $zipFiles[$i]
        $sizeMB = [math]::Round($z.Length / 1MB, 1)
        $dateStr = $z.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "  [$($i + 1)] $($z.Name)  ($sizeMB MB, $dateStr)" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  [0] Cancel" -ForegroundColor DarkGray
    Write-Host ""

    do {
        $selection = Read-Host "Select a collection (1-$($zipFiles.Count))"
        if ($selection -eq "0") {
            Write-Host "Cancelled." -ForegroundColor Yellow
            exit 0
        }
        $selIndex = 0
        $valid = [int]::TryParse($selection, [ref]$selIndex) -and $selIndex -ge 1 -and $selIndex -le $zipFiles.Count
        if (-not $valid) {
            Write-Host "Invalid selection. Enter 1-$($zipFiles.Count) or 0 to cancel." -ForegroundColor Red
        }
    } while (-not $valid)

    $selectedZip = $zipFiles[$selIndex - 1]
    $script:selectedZipPath = $selectedZip.FullName
    Write-Host ""
    Write-Host "Selected: $($selectedZip.Name)" -ForegroundColor Green

    # Extracted into this run's work folder once the log is set up (below)
    $InputPath = $selectedZip.FullName
    Write-Host ""
} elseif ((Test-Path -LiteralPath $InputPath -PathType Leaf) -and [System.IO.Path]::GetExtension($InputPath) -eq ".zip") {
    # A collection zip passed as -InputPath is extracted like a browse-mode
    # pick; Find-MemoryDump also looks for the memory dump next to it
    $script:selectedZipPath = (Resolve-Path -LiteralPath $InputPath).ProviderPath
}

# Report folder: created only once a collection is picked, so "[0] Cancel"
# leaves none behind
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportDir = Join-Path $PSScriptRoot "reports\timeline_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$logFile = Join-Path $reportDir "timeline_builder_log.txt"

# Set default output file if not specified
if (-not $OutputFile) {
    $OutputFile = Join-Path $reportDir "timeline.csv"
}

# =============================================================
# Validation
# =============================================================
# Normalize -Keywords: accept -Keywords a,b as well as a single "a,b" string
# (powershell.exe -File and Run-TimelineBuilder.bat pass a list as one string).
# Empty items are dropped -- an empty keyword would flag every row.
if ($Keywords) {
    $Keywords = @($Keywords | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
# Same for -Sources (names were already checked by its ValidateScript)
$Sources = @($Sources | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Log "=== Windows 11 Forensic Timeline Builder Started ==="
Log "Input Path : $InputPath"
Log "Output File: $OutputFile"
Log "Sources    : $($Sources -join ', ')"
if ($StartDate) { Log "Start Date : $StartDate" }
if ($EndDate)   { Log "End Date   : $EndDate" }
if ($Keywords)  { Log "Keywords   : $($Keywords -join ', ')" }
if ($MemoryDumpPath) { Log "Memory Dump: $MemoryDumpPath" }
Log ""

# =============================================================
# Main body. Everything from here to the end of the script runs inside
# this try block, which starts as soon as the work folder exists. Its
# finally block (at the end) unloads any hive this run left loaded and
# deletes the work folder on every exit path: normal end, exit, Ctrl+C
# and terminating errors. The body is intentionally NOT re-indented so
# the diff stays small. (Closing the console window kills the process
# outright; that cannot be caught.)
# =============================================================
if ($WorkDir) { $WorkDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir) }
$script:runWorkDir = New-RunWorkFolder -BaseFolder $WorkDir
try {

# Inside a try block, a statement-terminating error (a .NET exception or a
# method call on $null outside an inner try/catch) would skip the whole
# rest of the run. Log it and go on with the next step instead. Without
# the try block such an error skipped only its own statement; here it
# skips the rest of the step (e.g. the rest of a parser), so it is counted
# and the run ends with "UNEXPECTED ERROR(S)" and exit code 2 instead of
# "Completed Successfully" (Write-RunEndBanner). Ctrl+C
# (PipelineStoppedException) is passed on, so the run stops and the
# finally block cleans up.
trap {
    if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { break }
    $script:unexpectedErrorCount++
    Log-Error "Unexpected error at line $($_.InvocationInfo.ScriptLineNumber) (rest of this step skipped): $($_.Exception.Message)"
    continue
}

if (-not $script:runWorkDir) {
    Log-Error "Could not create a work folder. Pass -WorkDir with a writable folder on a local drive that is not a temp folder."
    exit 1
}
Log "Work folder: $($script:runWorkDir)"
$tempFolder = Get-ContainingTempFolder $script:runWorkDir
if ($tempFolder) {
    Log-Warning "The work folder is inside a temp folder ($tempFolder). Windows Storage Sense deletes files older than 7 days there when disk space is low, also during a run; pass -WorkDir with another folder."
}

if (-not (Test-Path -LiteralPath $InputPath)) {
    Log-Error "Input path does not exist: $InputPath"
    exit 1
}

if ($script:selectedZipPath) {
    Log "Extracting the collection zip into the work folder..."
    $extractDir = Join-Path $script:runWorkDir "in"
    try { Expand-CollectionZip -ZipPath $script:selectedZipPath -Destination $extractDir }
    catch {
        Log-Error "Failed to extract the zip: $($_.Exception.Message)"
        exit 1
    }
    # The zip normally holds one folder, the collection: use it as the input path
    $children = @(Get-ChildItem -LiteralPath $extractDir -Directory)
    if ($children.Count -eq 1 -and -not (Get-ChildItem -LiteralPath $extractDir -File)) {
        $InputPath = $children[0].FullName
    } else {
        $InputPath = $extractDir
    }
    Log "Collection folder: $InputPath"

    # Every extracted file must still be there (antivirus or a cleanup tool
    # can remove files as soon as they are written)
    $missingInputs = @(Get-MissingInputFiles)
    if ($missingInputs.Count -gt 0) {
        Log-Error "$($missingInputs.Count) extracted file(s) disappeared right after the extraction -- stopping:"
        Write-MissingInputFiles -Files $missingInputs -BaseFolder $InputPath
        exit 1
    }

    # Test hook for tests\Test-ZipInput.ps1: delete one extracted file now,
    # as a cleanup tool would during the run. Only a file inside this run's
    # work folder is ever deleted.
    if ($env:TIMELINE_BUILDER_TEST_DELETE_INPUT) {
        $hookFile = [System.IO.Path]::GetFullPath((Join-Path $InputPath $env:TIMELINE_BUILDER_TEST_DELETE_INPUT))
        if ($hookFile.StartsWith($script:runWorkDir + '\', [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $hookFile -PathType Leaf)) {
            Remove-Item -LiteralPath $hookFile -Force
            Log-Warning "Test hook: deleted $hookFile"
        }
        else { Log-Warning "Test hook ignored (not a file in the work folder): $hookFile" }
    }
}
elseif (Test-Path -LiteralPath $InputPath -PathType Leaf) {
    Log-Error "Input path is a file, not a collection folder or .zip: $InputPath"
    exit 1
}
else {
    $tempFolder = Get-ContainingTempFolder $InputPath
    if ($tempFolder) {
        Log-Warning "The input folder is inside a temp folder ($tempFolder). Windows Storage Sense deletes files older than 7 days there when disk space is low, also during a run. Copy the collection elsewhere, or pass the collection .zip as -InputPath."
    }
    Add-ManifestInputFiles
}
Log ""

# =============================================================
# Timeline Entry Collection
# =============================================================
$script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

# Characters that are not allowed in XML 1.0 (and so break the .xlsx):
# control characters other than tab/LF/CR, U+FFFE/U+FFFF, and unpaired
# surrogate halves. Everything else is kept, including non-Latin text and
# emoji (properly paired surrogates). Used here and by the Excel export.
$script:xmlInvalidPattern = '[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]'
$script:xmlInvalidRegex = New-Object System.Text.RegularExpressions.Regex($script:xmlInvalidPattern, [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Add-TimelineEntry {
    param(
        [datetime]$Timestamp,
        [string]$Source,
        [string]$EventType,
        [string]$Description,
        [string]$User = "",
        [string]$Details = "",
        [string]$Artifact,
        [string]$RawPath = ""
    )

    # Normalize to UTC
    $utcTime = $Timestamp.ToUniversalTime()

    # Discard bogus timestamps (Windows FILETIME epoch = 1601, or year 0/1)
    if ($utcTime.Year -lt 1980) { return }

    # Apply date filters
    if ($StartDate -and $utcTime -lt $StartDate.ToUniversalTime()) { return }
    if ($EndDate -and $utcTime -gt $EndDate.ToUniversalTime()) { return }

    # Sanitize strings: remove XML-invalid characters (see $script:xmlInvalidPattern)
    # These cause "Repaired Records" errors when Excel opens the .xlsx
    $Description = $script:xmlInvalidRegex.Replace($Description, '')
    $Details     = $script:xmlInvalidRegex.Replace($Details, '')
    $User        = $script:xmlInvalidRegex.Replace($User, '')
    $Source      = $script:xmlInvalidRegex.Replace($Source, '')
    $RawPath     = $script:xmlInvalidRegex.Replace($RawPath, '')

    $entry = [PSCustomObject]@{
        Timestamp   = $utcTime.ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
        Source      = $Source
        EventType   = $EventType
        Description = $Description
        User        = $User
        Details     = $Details
        Artifact    = $Artifact
        RawPath     = $RawPath
    }

    $script:timelineEntries.Add($entry)
}

# =============================================================
# Helper: Find files recursively with extensions
# =============================================================
function Find-ArtifactFiles {
    param(
        [string]$BasePath,
        [string[]]$Extensions,
        [string[]]$FileNames
    )
    $results = @()
    try {
        if ($Extensions) {
            foreach ($ext in $Extensions) {
                $results += Get-ChildItem -Path $BasePath -Filter "*$ext" -Recurse -ErrorAction SilentlyContinue
            }
        }
        if ($FileNames) {
            foreach ($name in $FileNames) {
                $results += Get-ChildItem -Path $BasePath -Filter $name -Recurse -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Log-Warning "Error searching for files in $BasePath : $_"
    }
    # Email attachment copies ($MFT and other stray names inside them) and the
    # Secrets\ folder (credential material) are never returned to a parser.
    return @($results | Where-Object {
        -not (Test-EmailAttachmentCopy (Get-RelativeCollectionPath $_.FullName)) -and -not (Test-SecretsPath $_.FullName)
    })
}

# =============================================================
# Shared helpers: collection metadata, time conversion, users
# Used by several parsers. collection_info.json and the extra
# collection_manifest.csv columns are written by the triage
# collector (see its README); older collections fall back to
# collection_log.txt and file times.
# =============================================================
# The folder of collection_manifest.csv (its paths are relative to it),
# so an outer folder passed as -InputPath works too; without a manifest,
# -InputPath (a relative one resolved against the PowerShell location)
$script:collectionRoot = Get-CollectionRootFolder
$script:collectionInfo = $null
$script:manifestTimes = $null
$script:secretsRoot = $null

# Path of a file relative to the collection root, or $null if it is outside it
function Get-RelativeCollectionPath {
    param([string]$FullPath)
    if (-not $FullPath) { return $null }
    try { $full = [System.IO.Path]::GetFullPath($FullPath) } catch { $full = $FullPath }
    if ($full.StartsWith($script:collectionRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($script:collectionRoot.Length + 1)
    }
    return $null
}

# Full path of the collection's top-level Secrets\ folder -- the one next to
# collection_info.json (the sibling the collector's -IncludeSecrets writes),
# computed once. Anchoring to it means a user profile folder that happens to be
# named "Secrets" (Browser\Secrets\, UserActivity\secrets\, ...) is NOT treated
# as the credential folder. Falls back to <collection root>\Secrets when there
# is no collection_info.json (older collections, which have no Secrets folder).
function Get-SecretsRoot {
    if ($null -ne $script:secretsRoot) { return $script:secretsRoot }
    $base = $script:collectionRoot
    $jsonFile = Get-ChildItem -Path $InputPath -Filter "collection_info.json" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($jsonFile) {
        try { $base = [System.IO.Path]::GetFullPath($jsonFile.DirectoryName).TrimEnd('\') } catch { Write-Verbose "Resolving the collection base: $($_.Exception.Message)" }
    }
    $script:secretsRoot = (Join-Path $base "Secrets")
    return $script:secretsRoot
}

# $true when the path is inside the collection's top-level Secrets\ folder
# (DPAPI credential material collected with the collector's -IncludeSecrets).
# No parser reads anything there: it holds only secrets, nothing the timeline
# needs. Used by Find-ArtifactFiles (so every caller skips it), the recursive
# searches that bypass it (ScheduledTasks_XML, SRUDB.dat, AntiVirus vendors)
# and the raw $MFT search.
function Test-SecretsPath {
    param([string]$FullPath)
    if (-not $FullPath) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($FullPath) } catch { $full = $FullPath }
    $secretsRoot = Get-SecretsRoot
    if (-not $secretsRoot) { return $false }
    return ($full.StartsWith($secretsRoot + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
        ($full.TrimEnd('\') -ieq $secretsRoot))
}

# Account an artifact belongs to, from the collection's own folder layout
# (Registry\<user>\, UserActivity\<user>\, Browser\<user>\, Email\<user>\) or
# a Users\<user>\ segment inside the collection -- never from the analyst
# machine's path.
function Get-CollectionUser {
    param([string]$FullPath)
    $rel = Get-RelativeCollectionPath $FullPath
    if (-not $rel) { return "" }
    if ($rel -match '^(?:Registry|UserActivity|Browser|Email)\\([^\\]+)\\') { return $Matches[1] }
    if ($rel -match '(?:^|\\)Users\\([^\\]+)\\') { return $Matches[1] }
    return ""
}

# What the User column pass (Update-TimelineUserColumn) needs to know about
# the examined system, gathered while the parsers read the collection (no
# hive is loaded for it): the machine's names (MachineNames: the SYSTEM
# hive's computer and host names; the main body adds the computer name of
# a live collection) and account names by SID (ProfileSids from SOFTWARE
# ProfileList, BamSids from bam_entries.csv)
$script:timelineUserContext = $null
function Get-TimelineUserContext {
    if ($null -eq $script:timelineUserContext) {
        $script:timelineUserContext = [PSCustomObject]@{
            MachineNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            ProfileSids  = @{}
            BamSids      = @{}
        }
    }
    return $script:timelineUserContext
}

# Keep names of the examined machine: "<name>\account" is a local account
# of this machine (see ConvertTo-TimelineUserName)
function Add-TimelineMachineName {
    param([string[]]$Name)
    $context = Get-TimelineUserContext
    foreach ($n in $Name) {
        $text = "$n".Trim()
        if ($text) { [void]$context.MachineNames.Add($text) }
    }
}

# Keep the account name of a SID for the User column. Only SIDs that say
# what they are: local and domain accounts (S-1-5-21-...), Entra ID accounts
# (S-1-12-1-...) and service SIDs (S-1-5-80-..., as NT SERVICE\<name>).
# Never SYSTEM, LOCAL SERVICE or NETWORK SERVICE: their ProfileList folders
# (systemprofile, LocalService, NetworkService) are not account names, and
# ConvertTo-TimelineUserName names them itself. A ProfileList name wins over
# one from bam_entries.csv (see Get-TimelineSidNames).
function Add-TimelineSidName {
    param([string]$Sid, [string]$Name, [switch]$ProfileList)
    $sidText = "$Sid".Trim()
    $account = "$Name".Trim()
    if (-not $account) { return }
    if ($sidText -match '^S-1-5-80(-\d+)+$') {
        if ($account -notmatch '\\') { $account = "NT SERVICE\$account" }
    }
    elseif ($sidText -notmatch '^S-1-(5-21|12-1)(-\d+)+$') { return }
    $context = Get-TimelineUserContext
    if ($ProfileList) { $context.ProfileSids[$sidText] = $account }
    elseif (-not $context.BamSids.ContainsKey($sidText)) { $context.BamSids[$sidText] = $account }
}

# SID -> account name for the User column: ProfileList, else bam_entries.csv
function Get-TimelineSidNames {
    $context = Get-TimelineUserContext
    $names = @{}
    foreach ($sid in $context.BamSids.Keys) { $names[$sid] = $context.BamSids[$sid] }
    foreach ($sid in $context.ProfileSids.Keys) { $names[$sid] = $context.ProfileSids[$sid] }
    return $names
}

# The names Windows writes for its built-in service accounts, in any case
# (hashtable keys are case-insensitive) -> one form each
$script:TimelineUserAliases = @{
    "SYSTEM"                       = "NT AUTHORITY\SYSTEM"
    "LocalSystem"                  = "NT AUTHORITY\SYSTEM"
    "NT AUTHORITY\SYSTEM"          = "NT AUTHORITY\SYSTEM"
    "NT AUTHORITY\LocalSystem"     = "NT AUTHORITY\SYSTEM"
    "LOCAL SERVICE"                = "NT AUTHORITY\LOCAL SERVICE"
    "LocalService"                 = "NT AUTHORITY\LOCAL SERVICE"
    "NT AUTHORITY\LOCAL SERVICE"   = "NT AUTHORITY\LOCAL SERVICE"
    "NT AUTHORITY\LocalService"    = "NT AUTHORITY\LOCAL SERVICE"
    "NETWORK SERVICE"              = "NT AUTHORITY\NETWORK SERVICE"
    "NetworkService"               = "NT AUTHORITY\NETWORK SERVICE"
    "NT AUTHORITY\NETWORK SERVICE" = "NT AUTHORITY\NETWORK SERVICE"
    "NT AUTHORITY\NetworkService"  = "NT AUTHORITY\NETWORK SERVICE"
}

# One form per account for the User column (parsers write what their
# source gives: "HOST\name", a SID, "LocalSystem", ...). In this order:
#   1. trim the value and split it at the first "\"; empty and "-" parts
#      are dropped ("-\-" gives "", "\x" and "-\x" give "x", "X\-" "X")
#   2. S-1-5-18/19/20 -> NT AUTHORITY\SYSTEM, LOCAL SERVICE, NETWORK SERVICE;
#      S-1-5-90-0-n -> Window Manager\DWM-n; S-1-5-96-0-n -> Font Driver
#      Host\UMFD-n
#   3. any other SID -> its name in $SidNames, else the SID as it is
#   4. "X\name" -> "name" when X is "." or a name of the examined machine
#      ($MachineNames, any case): a local account, named the way the
#      profile folders and the collector name it
#   5. the built-in service account names ($script:TimelineUserAliases:
#      SYSTEM, LocalSystem, LocalService, ...) and DWM-n / UMFD-n without a
#      domain -> the forms of step 2
#   6. anything else as it is: other domains, MicrosoftAccount\...,
#      AzureAD\..., the computer account (WORKGROUP\HOST$), NT VIRTUAL
#      MACHINE\..., NT SERVICE\..., group names
function ConvertTo-TimelineUserName {
    param([string]$Value, [hashtable]$SidNames, [string[]]$MachineNames)
    $text = "$Value".Trim()
    $domain = ""
    $name = $text
    $slash = $text.IndexOf('\')
    if ($slash -ge 0) {
        $domain = $text.Substring(0, $slash).Trim()
        $name = $text.Substring($slash + 1).Trim()
    }
    if ($domain -eq "-") { $domain = "" }
    if ($name -eq "-") { $name = "" }
    if (-not $name) {
        $name = $domain
        $domain = ""
    }
    if (-not $name) { return "" }

    if (-not $domain -and $name -match '^S-1-\d+(-\d+)+$') {
        switch -Regex ($name) {
            '^S-1-5-18$'         { return "NT AUTHORITY\SYSTEM" }
            '^S-1-5-19$'         { return "NT AUTHORITY\LOCAL SERVICE" }
            '^S-1-5-20$'         { return "NT AUTHORITY\NETWORK SERVICE" }
            '^S-1-5-90-0-(\d+)$' { return "Window Manager\DWM-$($Matches[1])" }
            '^S-1-5-96-0-(\d+)$' { return "Font Driver Host\UMFD-$($Matches[1])" }
        }
        if ($SidNames -and $SidNames.ContainsKey($name) -and $SidNames[$name]) { return [string]$SidNames[$name] }
        return $name
    }

    if ($domain -and ($domain -eq "." -or ($MachineNames -and $MachineNames -contains $domain))) { $domain = "" }
    $text = if ($domain) { "$domain\$name" } else { $name }
    if ($script:TimelineUserAliases -and $script:TimelineUserAliases.ContainsKey($text)) { return $script:TimelineUserAliases[$text] }
    if (-not $domain -and $name -match '^DWM-\d+$') { return "Window Manager\$name" }
    if (-not $domain -and $name -match '^UMFD-\d+$') { return "Font Driver Host\$name" }
    return $text
}

# The User column pass, after all parsers and before deduplication: each
# row's User through ConvertTo-TimelineUserName (once per distinct value,
# compared exactly). A row whose User was a SID that now has a name keeps
# the SID in Details as UserSID=<sid>, unless Details already has a field
# whose value is that SID (UserSID=, SID=, ModifyingUser=, UserId=, ...;
# not a path such as Location=HKU\<sid>\...). Returns Rows (rows changed),
# SidRows (rows given UserSID=), Transitions (From, To and Rows per changed
# value, most rows first) and Unresolved (Sid and Rows per SID left as it
# is).
function Update-TimelineUserColumn {
    param($Entries, [hashtable]$SidNames, [string[]]$MachineNames)
    # Value -> its new form and the SID it is (if it is one)
    $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    $changedRows = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal)
    $unresolvedRows = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal)
    $rows = 0
    $sidRows = 0
    foreach ($entry in $Entries) {
        $value = [string]$entry.User
        if (-not $value) { continue }
        $known = $null
        if (-not $cache.TryGetValue($value, [ref]$known)) {
            $sid = ""
            if ($value.Trim() -match '^S-1-\d+(-\d+)+$') { $sid = $value.Trim() }
            $known = [PSCustomObject]@{ New = (ConvertTo-TimelineUserName -Value $value -SidNames $SidNames -MachineNames $MachineNames); Sid = $sid }
            $cache[$value] = $known
        }
        $new = $known.New
        $sid = $known.Sid
        $count = 0
        if ($sid -and $new -ceq $sid) {
            [void]$unresolvedRows.TryGetValue($sid, [ref]$count)
            $unresolvedRows[$sid] = $count + 1
        }
        if ($new -ceq $value) { continue }

        $entry.User = $new
        $rows++
        $count = 0
        [void]$changedRows.TryGetValue($value, [ref]$count)
        $changedRows[$value] = $count + 1
        if ($sid -and $new -cne $sid) {
            $details = [string]$entry.Details
            if ($details -notmatch ('=' + [regex]::Escape($sid) + '(?=$|[\s|;,])')) {
                $entry.Details = if ($details) { "$details | UserSID=$sid" } else { "UserSID=$sid" }
                $sidRows++
            }
        }
    }
    $transitions = @($changedRows.Keys | ForEach-Object { [PSCustomObject]@{ From = $_; To = $cache[$_].New; Rows = $changedRows[$_] } } |
        Sort-Object -CaseSensitive -Property @{ Expression = "Rows"; Descending = $true }, @{ Expression = "From"; Descending = $false })
    $unresolved = @($unresolvedRows.Keys | ForEach-Object { [PSCustomObject]@{ Sid = $_; Rows = $unresolvedRows[$_] } } |
        Sort-Object -CaseSensitive -Property @{ Expression = "Rows"; Descending = $true }, @{ Expression = "Sid"; Descending = $false })
    return [PSCustomObject]@{ Rows = $rows; SidRows = $sidRows; Transitions = $transitions; Unresolved = $unresolved }
}

function Get-TimeZoneById {
    param([string]$Id)
    if (-not $Id) { return $null }
    try { return [System.TimeZoneInfo]::FindSystemTimeZoneById($Id) } catch { return $null }
}

# Parse a value that is already UTC (ISO 8601, "yyyy-MM-dd HH:mm:ss", or a
# [datetime] from ConvertFrom-Json). Returns a Kind=Utc [datetime] or $null.
function ConvertFrom-UtcText {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq "") { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt }
    return $null
}

# Convert a wall-clock time in the given time zone to UTC (Kind=Utc)
function Convert-LocalToUtc {
    param([datetime]$Local, [System.TimeZoneInfo]$TimeZone)
    $unspecified = [datetime]::SpecifyKind($Local, [System.DateTimeKind]::Unspecified)
    try { return [System.TimeZoneInfo]::ConvertTimeToUtc($unspecified, $TimeZone) }
    catch {
        # Invalid local time (inside a DST gap) -- apply the zone's offset directly
        return [datetime]::SpecifyKind($unspecified - $TimeZone.GetUtcOffset($unspecified), [System.DateTimeKind]::Utc)
    }
}

# Parse local-time text with no offset. Tries the given culture, then en-US,
# invariant and the analyst's culture. Returns Kind=Unspecified or $null.
function ConvertFrom-LocalText {
    param([string]$Text, [System.Globalization.CultureInfo]$Culture)
    if (-not $Text) { return $null }
    $cultures = @()
    if ($Culture) { $cultures += $Culture }
    $cultures += [System.Globalization.CultureInfo]::GetCultureInfo("en-US")
    $cultures += [System.Globalization.CultureInfo]::InvariantCulture
    $cultures += [System.Globalization.CultureInfo]::CurrentCulture
    $dt = [datetime]::MinValue
    foreach ($c in $cultures) {
        if ([datetime]::TryParse($Text.Trim(), $c, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
            return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Unspecified)
        }
    }
    return $null
}

# Metadata about the collection: mode, when it was taken, and which time zones
# apply. CollectorTimeZone = machine that ran the collector (text written by
# tools such as fsutil is in this zone). TargetTimeZone = the examined Windows
# install (its own logs, e.g. setupapi.dev.log, are in this zone). TargetRoot =
# the examined install's root folder on the collector ("C:\"; "" if unknown).
function Get-CollectionInfo {
    if ($script:collectionInfo) { return $script:collectionInfo }

    $info = [PSCustomObject]@{
        Source             = "defaults (analysis machine)"
        Mode               = ""
        CollectionStartUtc = $null
        CollectorTimeZone  = [System.TimeZoneInfo]::Local
        TargetTimeZone     = $null
        CollectorCulture   = $null
        TargetRoot         = ""
        # The collector host's name: the examined system only in a live collection
        ComputerName       = ""
        # Additive collection_info.json fields (older collections lack them):
        # whether the collection holds unredacted browser files + DPAPI
        # credential material (the Secrets\ folder) and Thunderbird's index
        SecretsIncluded          = $false
        ThunderbirdIndexIncluded = $false
    }

    $jsonFile = Get-ChildItem -Path $InputPath -Filter "collection_info.json" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $collLog = Get-ChildItem -Path $InputPath -Filter "collection_log.txt" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($jsonFile) {
        try {
            $j = Get-Content -Path $jsonFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
            $info.Source = "collection_info.json"
            if ($j.Mode) { $info.Mode = [string]$j.Mode }
            if ($j.TargetRoot) { $info.TargetRoot = [string]$j.TargetRoot }
            if ($j.ComputerName) { $info.ComputerName = [string]$j.ComputerName }
            $info.CollectionStartUtc = ConvertFrom-UtcText $j.CollectionStartUtc
            $tz = Get-TimeZoneById ([string]$j.CollectorTimeZoneId)
            if ($tz) { $info.CollectorTimeZone = $tz }
            $info.TargetTimeZone = Get-TimeZoneById ([string]$j.TargetTimeZoneId)
            if ($j.PSObject.Properties["SecretsIncluded"]) { $info.SecretsIncluded = [bool]$j.SecretsIncluded }
            if ($j.PSObject.Properties["ThunderbirdIndexIncluded"]) { $info.ThunderbirdIndexIncluded = [bool]$j.ThunderbirdIndexIncluded }
            if ($j.CollectorCulture) {
                try { $info.CollectorCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$j.CollectorCulture) }
                catch { Write-Verbose "Could not load collector culture '$($j.CollectorCulture)': $($_.Exception.Message)" }
            }
        }
        catch { Log-Warning "Could not read collection_info.json: $($_.Exception.Message)" }
    }
    elseif ($collLog) {
        # Older collectors: recover mode, time zone and start time from the log
        try {
            $lines = Get-Content -Path $collLog.FullName -TotalCount 40 -ErrorAction Stop
            $info.Source = "collection_log.txt"
            foreach ($line in $lines) {
                if ($line -match 'Mode: LIVE SYSTEM') { $info.Mode = "Live" }
                elseif ($line -match 'Mode: MOUNTED IMAGE') { $info.Mode = "MountedImage" }
                elseif ($line -match 'Time zone: (\(UTC(?:([+-]\d{2}):(\d{2}))?\).*)$') {
                    $display = $Matches[1].Trim()
                    $tz = [System.TimeZoneInfo]::GetSystemTimeZones() | Where-Object { $_.DisplayName -eq $display } | Select-Object -First 1
                    if (-not $tz -and -not $Matches[2]) {
                        $tz = [System.TimeZoneInfo]::Utc
                    }
                    elseif (-not $tz) {
                        # Display names vary by OS language -- fall back to a fixed offset
                        $offset = New-Object TimeSpan ([int]$Matches[2]), ([int]$Matches[3] * [Math]::Sign([int]"$($Matches[2])1")), 0
                        $tz = [System.TimeZoneInfo]::CreateCustomTimeZone("UTC$($Matches[2]):$($Matches[3])", $offset, $display, $display)
                    }
                    $info.CollectorTimeZone = $tz
                }
            }
            if ($lines.Count -gt 0 -and $lines[0] -match '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]') {
                $startLocal = [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
                $info.CollectionStartUtc = Convert-LocalToUtc -Local $startLocal -TimeZone $info.CollectorTimeZone
            }
        }
        catch { Log-Warning "Could not read collection_log.txt: $($_.Exception.Message)" }
    }

    if (-not $info.TargetTimeZone) {
        if ($info.Mode -ne "Live") {
            Log-Warning "Target time zone unknown -- assuming the collector's time zone ($($info.CollectorTimeZone.Id)) for target-local timestamps."
        }
        $info.TargetTimeZone = $info.CollectorTimeZone
    }

    $startText = if ($info.CollectionStartUtc) { $info.CollectionStartUtc.ToString("yyyy-MM-dd HH:mm:ss") + " UTC" } else { "unknown" }
    Log "Collection metadata from $($info.Source): Mode=$($info.Mode) Start=$startText CollectorTZ=$($info.CollectorTimeZone.Id) TargetTZ=$($info.TargetTimeZone.Id)"
    $script:collectionInfo = $info
    return $info
}

# Local-time text written on the collector host (e.g. fsutil usn output) -> UTC.
# In hot loops, call Get-CollectionInfo once and use ConvertFrom-LocalText +
# Convert-LocalToUtc directly to avoid repeated lookups.
function ConvertFrom-CollectorLocalText {
    param([string]$Text)
    $info = Get-CollectionInfo
    $local = ConvertFrom-LocalText -Text $Text -Culture $info.CollectorCulture
    if ($null -eq $local) { return $null }
    return Convert-LocalToUtc -Local $local -TimeZone $info.CollectorTimeZone
}

# Local time recorded by the examined Windows install (e.g. setupapi.dev.log) -> UTC
function ConvertFrom-TargetLocalTime {
    param([datetime]$Local)
    return Convert-LocalToUtc -Local $Local -TimeZone (Get-CollectionInfo).TargetTimeZone
}

# Timestamp for point-in-time state rows (service list, DNS cache, ...):
# when the collection was taken, not when the timeline is built.
# Returns $null if unknown -- callers must check before Add-TimelineEntry.
function Get-SnapshotTimeUtc {
    param([System.IO.FileInfo]$File)
    $info = Get-CollectionInfo
    if ($info.CollectionStartUtc) { return $info.CollectionStartUtc }
    if ($File) { return $File.LastWriteTimeUtc }
    return $null
}

# Original filesystem times of a collected file (Created/Modified/Accessed,
# Kind=Utc), from collection_manifest.csv. $null when the collector did not
# record them (older collectors, command output, reg save exports). A file
# whose name was shortened on extraction is looked up by its original name.
function Get-SourceFileTimes {
    param([string]$FullPath)
    if ($null -eq $script:manifestTimes) {
        $script:manifestTimes = @{}
        foreach ($row in (Get-CollectionManifest).Rows) {
            if ($row.PSObject.Properties["RelativePath"] -and $row.RelativePath -and $row.PSObject.Properties["SourceModifiedUtc"]) {
                $script:manifestTimes[$row.RelativePath] = [PSCustomObject]@{
                    Created  = ConvertFrom-UtcText $row.SourceCreatedUtc
                    Modified = ConvertFrom-UtcText $row.SourceModifiedUtc
                    Accessed = ConvertFrom-UtcText $row.SourceAccessedUtc
                }
            }
        }
        if ($script:manifestTimes.Count -eq 0) {
            Log-Warning "Collection manifest has no original file times (older collector) -- file-time events will be limited."
        }
    }
    if ($FullPath -and $script:shortenedNames -and $script:shortenedNames.ContainsKey($FullPath)) { $FullPath = $script:shortenedNames[$FullPath] }
    $rel = Get-RelativeCollectionPath $FullPath
    if (-not $rel) { return $null }
    return $script:manifestTimes[$rel]
}

# $true when collection_manifest.csv lists the file (the collector saved
# it), so its absence means it was lost after collection
function Test-ManifestListsFile {
    param([string]$FullPath)
    $rel = Get-RelativeCollectionPath $FullPath
    if (-not $rel) { return $false }
    return (Get-CollectionManifest).RelativePaths.Contains($rel)
}

# Last-write time (UTC) of an open registry key, or $null
if (-not ([System.Management.Automation.PSTypeName]'TimelineNative.RegKeyInfo').Type) {
    Add-Type -Namespace TimelineNative -Name RegKeyInfo -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
public static extern int RegQueryInfoKey(
    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
    System.Text.StringBuilder lpClass, IntPtr lpcchClass, IntPtr lpReserved,
    IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen,
    IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
    IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
}

function Get-RegistryKeyLastWriteUtc {
    param([Microsoft.Win32.RegistryKey]$Key)
    if (-not $Key) { return $null }
    $fileTime = 0L
    $z = [IntPtr]::Zero
    $rc = [TimelineNative.RegKeyInfo]::RegQueryInfoKey($Key.Handle, $null, $z, $z, $z, $z, $z, $z, $z, $z, $z, [ref]$fileTime)
    if ($rc -ne 0 -or $fileTime -le 0) { return $null }
    return [datetime]::FromFileTimeUtc($fileTime)
}

# Load and log collection metadata up front
$null = Get-CollectionInfo
if ((Get-CollectionInfo).SecretsIncluded) {
    Log "Collection made with -IncludeSecrets: browser files are unredacted and a Secrets\ folder holds DPAPI credential material. No parser reads Secrets\, and secret values are blanked before the browser files are parsed."
}
Log ""

# ----------------------------------------------------------
# 1. Event Log Parser
# ----------------------------------------------------------

# Value of the first listed column that exists and is not empty in a row
# (Import-Csv or table object), trimmed; "" if none. Lets parsers accept both
# old and new collector column names.
function Get-ArtifactRowValue {
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        $p = $Row.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and "$($p.Value)".Trim() -ne "") { return "$($p.Value)".Trim() }
    }
    return ""
}

# "Name=value | Name=value" text for the Details column; empty values are left out
function Format-ArtifactDetails {
    param([System.Collections.IDictionary]$Pairs)
    $parts = @()
    foreach ($k in $Pairs.Keys) {
        $v = "$($Pairs[$k])".Trim()
        if ($v) { $parts += "$k=$v" }
    }
    return ($parts -join " | ")
}

# Events with the given IDs from an .evtx file (nothing if there are none),
# optionally only those of the given providers (with no -Ids: any ID of
# them). The event log's XPath takes at most about 22 terms per query, so
# longer ID and provider lists are read in groups. A file that cannot be read
# is reported once: the remaining groups are skipped, and so are later calls
# that pass the same -State hashtable (its Failed key is set).
function Get-EvtxEventsById {
    param([string]$Path, [int[]]$Ids, [string]$Label, [string[]]$Providers, [hashtable]$State)
    if ($State -and $State["Failed"]) { return @() }
    $idSize = if ($Providers) { 15 } else { 20 }
    $providerSize = if ($Ids) { 5 } else { 20 }
    $idTerms = @()
    for ($i = 0; $i -lt $Ids.Count; $i += $idSize) {
        $group = $Ids[$i..([Math]::Min($i + $idSize, $Ids.Count) - 1)]
        $idTerms += "(" + (($group | ForEach-Object { "EventID=$_" }) -join " or ") + ")"
    }
    if ($idTerms.Count -eq 0) { $idTerms = @("") }
    $providerTerms = @()
    for ($i = 0; $i -lt $Providers.Count; $i += $providerSize) {
        $group = $Providers[$i..([Math]::Min($i + $providerSize, $Providers.Count) - 1)]
        $providerTerms += "Provider[" + (($group | ForEach-Object { "@Name='$_'" }) -join " or ") + "]"
    }
    if ($providerTerms.Count -eq 0) { $providerTerms = @("") }

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($idTerm in $idTerms) {
        foreach ($providerTerm in $providerTerms) {
            $xpath = "*[System[" + ((@($providerTerm, $idTerm) | Where-Object { $_ }) -join " and ") + "]]"
            try {
                foreach ($record in (Get-WinEvent -Path $Path -FilterXPath $xpath -ErrorAction Stop)) { $events.Add($record) }
            }
            catch {
                if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound*" -and $_.Exception.Message -notmatch "No events were found") {
                    Log-Warning "    Error reading $Label events from $(Split-Path $Path -Leaf) : $($_.Exception.Message)"
                    if ($State) { $State["Failed"] = $true }
                    return $events.ToArray()
                }
            }
        }
    }
    return $events.ToArray()
}

# Fields of an event record as a hashtable: EventData <Data Name="..."> values
# (unnamed ones as param1, param2, ...) and UserData elements, which the
# TerminalServices logs use instead of EventData
function Get-EvtxEventFields {
    param($Record)
    $fields = @{}
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($Record.ToXml())
    foreach ($section in $doc.DocumentElement.ChildNodes) {
        if ($section.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($section.LocalName -eq "EventData") {
            $n = 0
            foreach ($d in $section.ChildNodes) {
                if ($d.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                $n++
                $name = $d.GetAttribute("Name")
                if (-not $name) { $name = "param$n" }
                $fields[$name] = $d.InnerText
            }
        }
        elseif ($section.LocalName -eq "UserData") {
            foreach ($wrapper in $section.ChildNodes) {
                if ($wrapper.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                foreach ($d in $wrapper.ChildNodes) {
                    if ($d.NodeType -eq [System.Xml.XmlNodeType]::Element) { $fields[$d.LocalName] = $d.InnerText }
                }
            }
        }
    }
    return $fields
}

# Time text from a collector CSV: ISO with Z/offset is parsed as such, anything
# else is local time on the collector host (Export-Csv of a local [datetime])
function ConvertFrom-CollectorTimeText {
    param([string]$Text)
    if (-not $Text -or -not $Text.Trim()) { return $null }
    if ($Text.Trim() -match '(Z|[+-]\d{2}:\d{2})$') { return ConvertFrom-UtcText $Text.Trim() }
    return ConvertFrom-CollectorLocalText $Text
}

# Get-MpThreat SeverityID values
$script:DefenderSeverityNames = @{ "0" = "Unknown"; "1" = "Low"; "2" = "Moderate"; "4" = "High"; "5" = "Severe" }
# Get-MpThreatDetection ThreatStatusID values (also in DetectionHistory files)
$script:DefenderThreatStatusNames = @{ "0" = "Unknown"; "1" = "Detected"; "2" = "Cleaned"; "3" = "Quarantined"; "4" = "Removed";
    "5" = "Allowed"; "6" = "Blocked"; "102" = "QuarantineFailed"; "103" = "RemoveFailed"; "104" = "AllowFailed";
    "105" = "Abandoned"; "107" = "BlockedFailed" }

# Defender threat catalog written by the collector (Get-MpThreat: ThreatID,
# ThreatName, SeverityID, CategoryID). Get-MpThreatDetection has no threat
# name, so detections are named from here. Keys are "id:<ThreatID>" and
# "name:<ThreatName>" (the support logs only give the name).
function Get-DefenderThreatCatalog {
    $catalog = @{}
    foreach ($csv in (Find-ArtifactFiles -BasePath $InputPath -FileNames @("defender_threats.csv"))) {
        try {
            # A collection without threats holds only a text placeholder line
            foreach ($row in (Import-Csv -Path $csv.FullName -ErrorAction Stop)) {
                $id = Get-ArtifactRowValue $row @("ThreatID")
                $name = Get-ArtifactRowValue $row @("ThreatName")
                if (-not $id -and -not $name) { continue }
                $severityId = Get-ArtifactRowValue $row @("SeverityID")
                $severity = $severityId
                if ($script:DefenderSeverityNames.ContainsKey($severityId)) { $severity = "$($script:DefenderSeverityNames[$severityId]) ($severityId)" }
                $entry = [PSCustomObject]@{ Name = $name; Severity = $severity; CategoryID = Get-ArtifactRowValue $row @("CategoryID") }
                if ($id) { $catalog["id:$id"] = $entry }
                if ($name) { $catalog["name:$name"] = $entry }
            }
        }
        catch { Log-Warning "  Could not read Defender threat catalog $($csv.Name): $($_.Exception.Message)" }
    }
    return $catalog
}

# "MP_THREAT_ACTION_QUARANTINE" -> "Quarantine", "MPSOURCE_REALTIME" -> "Realtime"
function ConvertTo-DefenderLogName {
    param([string]$Token)
    $words = ($Token -replace '^(MP_THREAT_ACTION_|MPSOURCE_)', '' -replace '_', ' ').ToLowerInvariant()
    return [System.Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($words)
}

# Path of a support-log resource or SDN query, without volume or drive, in
# lower case ("file:C:\x" and "\Device\HarddiskVolume4\x" both give "\x")
function Get-DefenderLogPathKey {
    param([string]$Path)
    return (($Path -replace '^file:', '') -replace '^\\Device\\HarddiskVolume\d+|^[A-Za-z]:', '').ToLowerInvariant()
}

# Exclusion lists of one "RTP Perf Log" block (Process / Path / Ext / Temp
# Exclusions) compared with the block before; differences become rows at
# the block's time. The first block in the logs only lists what was already
# in effect. Returns the number of rows added.
function Compare-DefenderExclusionListing {
    param([hashtable]$State, [System.Collections.Specialized.OrderedDictionary]$Items, $Time, [System.IO.FileInfo]$File, [string]$User, [int]$Line)
    if ($null -eq $Time) { return 0 }
    $added = 0
    $previous = $State.Exclusions
    $previousText = if ($State.ExclusionListTime) { $State.ExclusionListTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC" } else { "" }
    $changes = @()
    foreach ($key in $Items.Keys) {
        if ($null -ne $previous -and $previous.Contains($key)) { continue }
        $what = if ($null -eq $previous) { "in effect" } else { "added" }
        $changes += , @($what, $key)
    }
    if ($null -ne $previous) {
        foreach ($key in $previous.Keys) {
            if (-not $Items.Contains($key)) { $changes += , @("removed", $key) }
        }
    }
    foreach ($change in $changes) {
        $parts = $change[1] -split "`t", 2
        $when = switch ($change[0]) {
            "in effect" { "Listed at the first RTP perf log in the support logs (added earlier)" }
            "added"     { "Not listed at $previousText, listed at this time" }
            "removed"   { "Listed at $previousText, not listed at this time" }
        }
        Add-TimelineEntry -Timestamp $Time -Source $File.Name -EventType "SecurityAlert" `
            -Description "Defender exclusion $($change[0]) ($($parts[0])): $($parts[1])" `
            -User $User `
            -Details (Format-ArtifactDetails ([ordered]@{ Type = $parts[0]; Exclusion = $parts[1]; When = $when; Line = $Line })) `
            -Artifact "AntiVirus" -RawPath $File.FullName
        $added++
    }
    $State.Exclusions = $Items
    $State.ExclusionListTime = $Time
    return $added
}

# Defender support log (MPLog-*.log / MPDetection-*.log, UTF-16). Line times
# are UTC with or without a trailing "Z": in the real logs every session
# header "Current time: ... UTC" equals the time of the next line, also after
# the platform update that dropped the "Z". As a safeguard, a header that
# differs from the next line by 10+ minutes sets an offset for lines without
# "Z". Rows (SecurityAlert) come only from:
#   DETECTIONEVENT / DETECTION           threat detected (SHA-256 from the SDN query)
#   DETECTION_CLEANEVENT                 remediation (quarantine, remove, ...)
#   Path exclusion changed, new size     exclusion list changed (size differs)
#   RTP Perf Log exclusion lists         exclusion added / removed
#   RTPPlugin state ... RTPStatus:x->0   real-time protection off (and back on)
#   [TP] State change (not at startup)   Tamper Protection state changed
# $State carries exclusion state and seen detections from file to file.
# Returns the number of rows added.
function Read-DefenderSupportLog {
    param([System.IO.FileInfo]$File, [hashtable]$State, [hashtable]$Catalog)
    $added = 0
    $user = Get-CollectionUser $File.FullName
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $utcStyles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $formats = [string[]]@("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF", "yyyy-MM-dd'T'HH:mm:ss")
    $offset = [TimeSpan]::Zero
    $headerUtc = $null
    $lastUtc = $null
    $perf = $null
    $lineNo = 0
    foreach ($line in [System.IO.File]::ReadLines($File.FullName)) {
        $lineNo++
        if ($line -notmatch '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z?) (.*)$') {
            # Untimed lines: session headers and RTP perf log blocks
            if ($line -match '^Current time: (\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})[.\d]* UTC') {
                $headerUtc = [datetime]::ParseExact($Matches[1], "MM/dd/yyyy HH:mm:ss", $invariant, $utcStyles)
            }
            elseif ($line -match '^\*+RTP Perf Log\*+\s*$') {
                $perf = @{ Time = $lastUtc; Line = $lineNo; Items = [ordered]@{}; Current = $null }
            }
            elseif ($perf -and $line.Contains("END RTP Perf Log")) {
                $added += Compare-DefenderExclusionListing -State $State -Items $perf.Items -Time $perf.Time -File $File -User $user -Line $perf.Line
                $perf = $null
            }
            elseif ($perf) {
                if ($line -match '^(Process|Path|Ext|Temp) Exclusions:\s*$') { $perf.Current = $Matches[1] }
                elseif ($perf.Current -and $line -match '^\s+(\S.*?)\s*$') { $perf.Items["$($perf.Current)`t$($Matches[1])"] = $true }
                else { $perf.Current = $null }
            }
            continue
        }
        $stamp = $Matches[1]
        $hasZ = $Matches[2] -eq "Z"
        $msg = $Matches[3]
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($stamp, $formats, $invariant, $utcStyles, [ref]$t)) { continue }
        if ($null -ne $headerUtc) {
            $offset = [TimeSpan]::Zero
            $diff = $headerUtc - $t
            if (-not $hasZ -and [Math]::Abs($diff.TotalMinutes) -ge 10) {
                $offset = [TimeSpan]::FromMinutes([Math]::Round($diff.TotalMinutes / 15) * 15)
                Log-Warning "    $($File.Name) line $($lineNo): times without 'Z' differ from the UTC header -- applying an offset of $($offset.TotalMinutes) minute(s)"
            }
            $headerUtc = $null
        }
        if (-not $hasZ) { $t = $t + $offset }
        $lastUtc = $t
        if ($perf) {
            $added += Compare-DefenderExclusionListing -State $State -Items $perf.Items -Time $perf.Time -File $File -User $user -Line $perf.Line
            $perf = $null
        }

        $desc = $null
        $details = $null
        if ($msg.StartsWith("DETECTION")) {
            $source = ""; $action = ""; $result = ""
            if ($msg -match '^DETECTIONEVENT\s+(\S+)\s+(\S+)\s+(.*?);?\s*$') {
                $source = $Matches[1]; $threat = $Matches[2]; $resource = $Matches[3]
                $desc = "Defender detection (support log): $threat"
            }
            elseif ($msg -match '^DETECTION_CLEANEVENT\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*?);?\s*$') {
                $source = $Matches[1]; $action = ConvertTo-DefenderLogName $Matches[2]; $result = $Matches[3]; $threat = $Matches[4]; $resource = $Matches[5]
                $desc = "Defender remediation (support log): $threat ($action)"
            }
            elseif ($msg -match '^DETECTION\s+(\S+)\s+(.*?);?\s*$') {
                $threat = $Matches[1]; $resource = $Matches[2]
                $desc = "Defender detection (support log): $threat"
            }
            else { continue }
            # MPLog and MPDetection can record the same detection
            $seenKey = "$desc`t$($t.Ticks)`t$resource"
            if ($State.Seen.ContainsKey($seenKey)) { continue }
            $State.Seen[$seenKey] = $true
            $known = $Catalog["name:$threat"]
            $pathKey = Get-DefenderLogPathKey (($resource -split ';')[0])
            $details = [ordered]@{
                Resource        = $resource
                DetectionSource = $(if ($source) { ConvertTo-DefenderLogName $source } else { "" })
                Action          = $action
                Result          = $result
                Severity        = $(if ($known) { $known.Severity } else { "" })
                SHA256          = $State.Sha[$pathKey]
            }
        }
        elseif ($msg.StartsWith("SDN:Issuing SDN query for ")) {
            # File hashes sent to the cloud just before a detection
            if ($msg -match '^SDN:Issuing SDN query for (.+?) \(.*sha2=([0-9A-Fa-f]{64})') {
                $State.Sha[(Get-DefenderLogPathKey $Matches[1])] = $Matches[2]
            }
            continue
        }
        elseif ($msg.Contains("Path exclusion changed, new size in bytes:")) {
            if ($msg -notmatch 'new size in bytes: (\d+)') { continue }
            $size = [long]$Matches[1]
            $before = $State.ExclusionSize
            $State.ExclusionSize = $size
            if ($null -eq $before -or $before -eq $size) { continue }
            $change = if ($size -gt $before) { "grew" } else { "shrank" }
            $desc = "Defender path exclusion list changed (support log): $before -> $size bytes"
            $details = [ordered]@{ Change = "list $change (exclusion $(if ($size -gt $before) { 'added' } else { 'removed' }) or changed)" }
        }
        elseif ($msg.Contains("RTPStatus:")) {
            if ($msg -notmatch 'RTPStatus:(\d+)->(\d+)') { continue }
            $from = [int]$Matches[1]
            $to = [int]$Matches[2]
            if ($to -eq 0 -and $from -ne 0) {
                $desc = "Defender real-time protection turned off (support log)"
                $State.RtpOff = $true
            }
            elseif ($to -ne 0 -and $State.RtpOff) {
                $desc = "Defender real-time protection turned back on (support log)"
                $State.RtpOff = $false
            }
            else { continue }
            $details = [ordered]@{ State = ($msg -replace '^.*?follow:\s*', '') }
        }
        elseif ($msg.StartsWith("[TP] State change.")) {
            # Every service start logs OldState 0 -> current state; only a
            # change from a known state is an event
            if ($msg -notmatch 'NewState: (0x[0-9A-Fa-f]+|\d+), OldState: (0x[0-9A-Fa-f]+|\d+)') { continue }
            $newState = $Matches[1]
            $oldState = $Matches[2]
            $newValue = if ($newState -like "0x*") { [Convert]::ToInt32($newState.Substring(2), 16) } else { [int]$newState }
            $oldValue = if ($oldState -like "0x*") { [Convert]::ToInt32($oldState.Substring(2), 16) } else { [int]$oldState }
            if ($oldValue -eq 0 -or $newValue -eq $oldValue) { continue }
            $desc = "Defender Tamper Protection state changed (support log): $oldState -> $newState"
            $details = [ordered]@{ Source = $(if ($msg -match 'Source: ([^,]+)') { $Matches[1] } else { "" }) }
        }
        else { continue }

        $details["Line"] = $lineNo
        Add-TimelineEntry -Timestamp $t -Source $File.Name -EventType "SecurityAlert" `
            -Description $desc -User $user -Details (Format-ArtifactDetails $details) `
            -Artifact "AntiVirus" -RawPath $File.FullName
        $added++
    }
    if ($perf) {
        $added += Compare-DefenderExclusionListing -State $State -Items $perf.Items -Time $perf.Time -File $File -User $user -Line $perf.Line
    }
    return $added
}

# Names for the %%NNNN references in event 4719 (system audit policy changed),
# as msobjs.dll gives them in English. Categories are %%8272-%%8280; the
# subcategories of category n (0-8) are %%(12288 + 256 * n) and up.
$script:AuditCategoryNames = @("System", "Logon/Logoff", "Object Access", "Privilege Use", "Detailed Tracking", "Policy Change", "Account Management", "DS Access", "Account Logon")
$script:AuditSubcategoryNames = @(
    @("Security State Change", "Security System Extension", "System Integrity", "IPsec Driver", "Other System Events"),
    @("Logon", "Logoff", "Account Lockout", "IPsec Main Mode", "Special Logon", "IPsec Quick Mode", "IPsec Extended Mode", "Other Logon/Logoff Events", "Network Policy Server", "User / Device Claims", "Group Membership", "Access Rights"),
    @("File System", "Registry", "Kernel Object", "SAM", "Other Object Access Events", "Certification Services", "Application Generated", "Handle Manipulation", "File Share", "Filtering Platform Packet Drop", "Filtering Platform Connection", "Detailed File Share", "Removable Storage", "Central Policy Staging"),
    @("Sensitive Privilege Use", "Non Sensitive Privilege Use", "Other Privilege Use Events"),
    @("Process Creation", "Process Termination", "DPAPI Activity", "RPC Events", "Plug and Play Events", "Token Right Adjusted Events"),
    @("Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change", "MPSSVC Rule-Level Policy Change", "Filtering Platform Policy Change", "Other Policy Change Events"),
    @("User Account Management", "Computer Account Management", "Security Group Management", "Distribution Group Management", "Application Group Management", "Other Account Management Events"),
    @("Directory Service Access", "Directory Service Changes", "Directory Service Replication", "Detailed Directory Service Replication"),
    @("Credential Validation", "Kerberos Service Ticket Operations", "Other Account Logon Events", "Kerberos Authentication Service")
)
$script:AuditChangeNames = @{ 8448 = "Success removed"; 8449 = "Success added"; 8450 = "Failure removed"; 8451 = "Failure added" }

# Service type and start type codes of event 4697 (as in the 7040 text)
$script:ServiceTypeNames = @{ 1 = "kernel driver"; 2 = "file system driver"; 8 = "recognizer driver"; 16 = "own process"; 32 = "share process"; 272 = "interactive own process"; 288 = "interactive share process" }
$script:ServiceStartTypeNames = @{ 0 = "boot start"; 1 = "system start"; 2 = "auto start"; 3 = "demand start"; 4 = "disabled" }

# Attack surface reduction rule GUIDs (Defender 1121/1122 "ID") -> rule names,
# from Microsoft's ASR rules reference
$script:AsrRuleNames = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
}

# Event sources that third-party antivirus products write to the Application
# log (exact names: the event log's XPath has no wildcards). Symantec
# AntiVirus, McLogEvent and Sophos Anti-Virus are documented sources; the
# others are the products' names as they register them. A name that is not
# in the log costs nothing.
$script:ThirdPartyAvProviders = @(
    "Symantec AntiVirus", "Symantec Endpoint Protection", "Symantec Endpoint Protection Client", "Norton AntiVirus", "Norton Security",
    "McLogEvent", "McAfee Endpoint Security", "Trellix Endpoint Security",
    "Sophos Anti-Virus", "Sophos Endpoint Defense",
    "ESET", "ESET Security",
    "Trend Micro OfficeScan", "OfficeScan NT", "Trend Micro Apex One", "Deep Security Agent",
    "Bitdefender", "Bitdefender Endpoint Security Tools",
    "Kaspersky Endpoint Security", "Kaspersky Security",
    "Malwarebytes", "MBAMService",
    "Webroot", "WRSVC",
    "CrowdStrike", "CSFalconService"
)

# "DOMAIN\name" from an event's domain and account fields; empty and "-"
# parts are left out
function Join-EvtxAccountName {
    param([string]$Domain, [string]$Name)
    return ((@($Domain, $Name) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $_ -ne "-" }) -join "\")
}

# First non-empty value among the named event fields, trimmed ("-" counts as
# empty). Lets a parser list a field's name and its param<n> position, for
# records that store the same fields unnamed (older Windows, ReportEvent).
function Get-EvtxFieldValue {
    param([hashtable]$Fields, [string[]]$Names)
    foreach ($n in $Names) {
        $v = "$($Fields[$n])".Trim()
        if ($v -and $v -ne "-") { return $v }
    }
    return ""
}

# "0x10" -> "0x10 (own process)" from a code -> name table; other text as is
function Format-EvtxCodeText {
    param([string]$Text, [hashtable]$Names)
    $t = "$Text".Trim()
    $value = 0
    if ($t -match '^0x([0-9A-Fa-f]{1,8})$') {
        if (-not [int]::TryParse($Matches[1], [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value)) { return $t }
    }
    elseif (-not [int]::TryParse($t, [ref]$value)) { return $t }
    if ($Names.ContainsKey($value)) { return "$t ($($Names[$value]))" }
    return $t
}

# "%%8274" or "%%8448, %%8450" from event 4719 -> "Object Access" or
# "Success removed, Failure removed"; unknown references are kept as they are
function ConvertFrom-AuditPolicyText {
    param([string]$Text)
    $names = @()
    foreach ($part in ($Text -split ',')) {
        $name = $part.Trim()
        if (-not $name) { continue }
        # At most 9 digits, so that a malformed reference cannot overflow [int]
        if ($name -match '^%%(\d{1,9})$') {
            $n = [int]$Matches[1]
            if ($n -ge 8272 -and $n -le 8280) { $name = $script:AuditCategoryNames[$n - 8272] }
            elseif ($script:AuditChangeNames.ContainsKey($n)) { $name = $script:AuditChangeNames[$n] }
            elseif ($n -ge 12288) {
                $category = [int][Math]::Floor(($n - 12288) / 256)
                $index = ($n - 12288) % 256
                if ($category -lt $script:AuditSubcategoryNames.Count -and $index -lt $script:AuditSubcategoryNames[$category].Count) {
                    $name = $script:AuditSubcategoryNames[$category][$index]
                }
            }
        }
        $names += $name
    }
    return ($names -join ", ")
}

# Action and run-as account of the task XML in events 4698-4702 (TaskContent /
# TaskContentNew). A single Exec action gives Command and Arguments; anything
# else gives Actions, one "<command> <arguments>" or "ComHandler <ClassId>"
# per action joined with "; " (as in the task XML rows), so that arguments
# always stay with their command. Empty if there is no readable XML.
function Get-TaskContentSummary {
    param([string]$TaskXml)
    $summary = [ordered]@{}
    if (-not $TaskXml -or -not $TaskXml.Trim()) { return $summary }
    $doc = New-Object System.Xml.XmlDocument
    try { $doc.LoadXml($TaskXml.Trim()) }
    catch {
        Write-Verbose "Task XML in a scheduled task event is not readable: $($_.Exception.Message)"
        return $summary
    }
    $taskNode = $doc.DocumentElement
    $actions = @()
    $exec = $null
    foreach ($node in $taskNode.SelectNodes("*[local-name()='Actions']/*")) {
        if ($node.LocalName -eq "Exec") {
            $exec = $node
            $actions += ((Get-TaskXmlText $node "Command") + " " + (Get-TaskXmlText $node "Arguments")).Trim()
        }
        elseif ($node.LocalName -eq "ComHandler") {
            $actions += "ComHandler " + (Get-TaskXmlText $node "ClassId")
        }
    }
    if ($actions.Count -eq 1 -and $null -ne $exec) {
        $summary["Command"] = Get-TaskXmlText $exec "Command"
        $summary["Arguments"] = Get-TaskXmlText $exec "Arguments"
    }
    else {
        $summary["Actions"] = (@($actions | Where-Object { $_ }) -join "; ")
    }
    $runAs = Get-TaskXmlText $taskNode "Principals/Principal/UserId"
    if (-not $runAs) { $runAs = Get-TaskXmlText $taskNode "Principals/Principal/GroupId" }
    $summary["RunAs"] = $runAs
    return $summary
}

# SID -> @{ Name = "DOMAIN\name"; EventId = <id> } from the Security events
# that carry both: the target of 4720 / 4724 / 4726 (account created, reset,
# deleted), the account of 4624 logons and the subject of these and 4648.
# Names the member of a group add (4728 / 4732 / 4756), which gives only the
# SID of a local account. Account management events win over logons.
function Get-SecuritySidNames {
    param([object[]]$Records)
    $names = @{}
    foreach ($record in @($Records | Where-Object { $_.Id -in @(4720, 4724, 4726, 4624, 4648) })) {
        $f = Get-EvtxEventFields $record
        $id = [int]$record.Id
        # @(SID, name, rank): lower rank wins
        $accounts = @(, @($f["SubjectUserSid"], (Join-EvtxAccountName $f["SubjectDomainName"] $f["SubjectUserName"]), 2))
        if ($id -in @(4720, 4724, 4726)) { $accounts += , @($f["TargetSid"], (Join-EvtxAccountName $f["TargetDomainName"] $f["TargetUserName"]), 1) }
        elseif ($id -eq 4624) { $accounts += , @($f["TargetUserSid"], (Join-EvtxAccountName $f["TargetDomainName"] $f["TargetUserName"]), 2) }
        foreach ($account in $accounts) {
            $sid = "$($account[0])".Trim()
            if ($sid -notmatch '^S-1-' -or $sid -eq "S-1-0-0" -or -not $account[1]) { continue }
            $known = $names[$sid]
            if ($null -eq $known -or $account[2] -lt $known.Rank) {
                $names[$sid] = @{ Name = $account[1]; EventId = $id; Rank = $account[2] }
            }
        }
    }
    return $names
}

# "4624 x805, 4672 x786": events per ID (and provider, with -ByProvider) for the log
function Format-EvtxEventCounts {
    param([object[]]$Records, [switch]$ByProvider)
    # Read the switch here: PSReviewUnusedParameter does not look inside the script block
    $perProvider = $ByProvider.IsPresent
    $groups = @($Records | Group-Object { if ($perProvider) { "$($_.ProviderName) $($_.Id)" } else { "$($_.Id)" } } | Sort-Object Name)
    return (($groups | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ", ")
}

# Security.evtx events other than logons and process creation (field names
# from the Microsoft-Windows-Security-Auditing templates; 1102 is written by
# Microsoft-Windows-Eventlog as UserData):
#   1102                 audit log cleared                        SecurityAlert
#   4719                 system audit policy changed              SecurityAlert
#   4697                 service installed                        PersistenceChange
#   4698-4702            scheduled task registered/deleted/enabled/
#                        disabled/updated (+ action from the XML) ScheduledTaskChange
#   4728/4732/4756       member added to a global/local/universal
#                        security group                           AccountChange
#   4724 / 4740          password reset attempt / account locked  AccountChange
#   4778 / 4779          session reconnected / disconnected       Logon
# $SidNames (Get-SecuritySidNames) names a group member given only by SID.
function Add-SecurityEventEntry {
    param($Record, [string]$FileName, [string]$FilePath, [hashtable]$SidNames)
    $f = Get-EvtxEventFields $Record
    $id = [int]$Record.Id
    $subject = Join-EvtxAccountName $f["SubjectDomainName"] $f["SubjectUserName"]
    $user = $subject
    $type = "AccountChange"
    $desc = $null
    $details = [ordered]@{ EventID = $id }
    switch ($id) {
        1102 {
            $type = "SecurityAlert"
            $desc = "Security audit log cleared"
            $details["ClearedBy"] = $subject
            $details["SubjectSID"] = $f["SubjectUserSid"]
            $details["LogonID"] = $f["SubjectLogonId"]
            $details["ClientProcessId"] = $f["ClientProcessId"]
        }
        4719 {
            $type = "SecurityAlert"
            $category = ConvertFrom-AuditPolicyText $f["CategoryId"]
            $subcategory = ConvertFrom-AuditPolicyText $f["SubcategoryId"]
            $changes = ConvertFrom-AuditPolicyText $f["AuditPolicyChanges"]
            $desc = "System audit policy changed: $category\$subcategory ($changes)"
            $details["Category"] = $category
            $details["Subcategory"] = $subcategory
            $details["SubcategoryGuid"] = $f["SubcategoryGuid"]
            $details["Changes"] = $changes
        }
        4697 {
            $type = "PersistenceChange"
            $desc = "New service installed: $($f['ServiceName'])"
            $details["ServiceName"] = $f["ServiceName"]
            # ServiceFileName, under the key System 7045 rows use
            $details["ImagePath"] = $f["ServiceFileName"]
            $details["ServiceType"] = Format-EvtxCodeText $f["ServiceType"] $script:ServiceTypeNames
            $details["StartType"] = Format-EvtxCodeText $f["ServiceStartType"] $script:ServiceStartTypeNames
            $details["Account"] = $f["ServiceAccount"]
            $details["ClientProcessId"] = $f["ClientProcessId"]
        }
        { $_ -in @(4698, 4699, 4700, 4701, 4702) } {
            $type = "ScheduledTaskChange"
            # Same verbs as the TaskScheduler 106 / 140 / 141 rows
            $what = @{ 4698 = "registered"; 4699 = "deleted"; 4700 = "enabled"; 4701 = "disabled"; 4702 = "updated" }[$id]
            $desc = "Scheduled task ${what}: $($f['TaskName'])"
            $details["TaskName"] = $f["TaskName"]
            $taskXml = Get-EvtxFieldValue $f @("TaskContentNew", "TaskContent")
            $task = Get-TaskContentSummary $taskXml
            foreach ($key in $task.Keys) { $details[$key] = $task[$key] }
            $details["ClientProcessId"] = $f["ClientProcessId"]
        }
        { $_ -in @(4728, 4732, 4756) } {
            $scope = @{ 4728 = "global"; 4732 = "local"; 4756 = "universal" }[$id]
            # MemberName is a domain account's DN, and "-" for a local account:
            # then the name comes from another event with the same SID
            $member = Get-EvtxFieldValue $f @("MemberName")
            $memberSid = Get-EvtxFieldValue $f @("MemberSid")
            $memberFrom = ""
            if (-not $member -and $memberSid -and $SidNames -and $SidNames.ContainsKey($memberSid)) {
                $member = $SidNames[$memberSid].Name
                $memberFrom = "event $($SidNames[$memberSid].EventId)"
            }
            $desc = "Member added to security-enabled $scope group: $($f['TargetUserName'])"
            $shown = if ($member) { $member } else { $memberSid }
            if ($shown) { $desc += " (member $shown)" }
            $details["Group"] = Join-EvtxAccountName $f["TargetDomainName"] $f["TargetUserName"]
            $details["GroupSID"] = $f["TargetSid"]
            $details["Member"] = $member
            $details["MemberSID"] = $memberSid
            $details["MemberNameFrom"] = $memberFrom
        }
        4724 {
            $target = Join-EvtxAccountName $f["TargetDomainName"] $f["TargetUserName"]
            $desc = "Password reset attempted for account: $target"
            $details["Account"] = $target
            $details["AccountSID"] = $f["TargetSid"]
        }
        4740 {
            # TargetDomainName holds the caller computer name in this event; the
            # subject is the machine (or DC) that reports it, so User is the
            # locked-out account
            $desc = "User account locked out: $($f['TargetUserName'])"
            $user = Get-EvtxFieldValue $f @("TargetUserName", "TargetSid")
            $details["Account"] = $f["TargetUserName"]
            $details["AccountSID"] = $f["TargetSid"]
            $details["CallerComputer"] = $f["TargetDomainName"]
            $details["ReportedBy"] = $subject
        }
        { $_ -in @(4778, 4779) } {
            $type = "Logon"
            $user = Join-EvtxAccountName $f["AccountDomain"] $f["AccountName"]
            $clientName = Get-EvtxFieldValue $f @("ClientName")
            $clientAddress = Get-EvtxFieldValue $f @("ClientAddress")
            $client = (@($clientName, $clientAddress) | Where-Object { $_ }) -join ", "
            $desc = if ($id -eq 4778) { "Session reconnected to window station" } else { "Session disconnected from window station" }
            if ($client) { $desc += " (client $client)" }
            $details["Account"] = $user
            $details["ClientName"] = $clientName
            $details["ClientAddress"] = $clientAddress
            $details["SessionName"] = $f["SessionName"]
            $details["LogonID"] = $f["LogonID"]
        }
    }
    if (-not $desc) { return }
    Add-TimelineEntry -Timestamp $Record.TimeCreated -Source $FileName -EventType $type `
        -Description $desc -User $user -Details (Format-ArtifactDetails $details) `
        -Artifact "EventLogs" -RawPath $FilePath
}

# System.evtx: event log cleared (104, Microsoft-Windows-Eventlog; SecurityAlert)
# and the event log service started / stopped (6005 / 6006, EventLog), the
# markers of a boot and of a clean shutdown (ServiceChange)
function Add-SystemEventEntry {
    param($Record, [string]$FileName, [string]$FilePath)
    $id = [int]$Record.Id
    if ($id -eq 104 -and $Record.ProviderName -eq "Microsoft-Windows-Eventlog") {
        $f = Get-EvtxEventFields $Record
        $by = Join-EvtxAccountName $f["SubjectDomainName"] $f["SubjectUserName"]
        Add-TimelineEntry -Timestamp $Record.TimeCreated -Source $FileName -EventType "SecurityAlert" `
            -Description "Event log cleared: $($f['Channel'])" -User $by `
            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $id; Channel = $f["Channel"]; ClearedBy = $by; BackupPath = $f["BackupPath"]; ClientProcessId = $f["ClientProcessId"] })) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
    elseif ($id -in @(6005, 6006) -and $Record.ProviderName -eq "EventLog") {
        $desc = if ($id -eq 6005) { "Event log service started (system startup)" } else { "Event log service stopped (clean shutdown)" }
        Add-TimelineEntry -Timestamp $Record.TimeCreated -Source $FileName -EventType "ServiceChange" `
            -Description $desc -Details (Format-ArtifactDetails ([ordered]@{ EventID = $id })) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
}

# Defender Operational: malware history deleted (1013) and attack surface
# reduction rule blocked / audited (1121 / 1122), all SecurityAlert. $Fields
# are the record's Get-EvtxEventFields (read here if not given). $Count and
# $LastSeen describe a row that stands for several 1122 events (see
# Add-DefenderAsrAuditEntries).
function Add-DefenderEventEntry {
    param($Record, [hashtable]$Fields, [string]$FileName, [string]$FilePath, [int]$Count = 1, $LastSeen = $null)
    $f = $Fields
    if ($null -eq $f) { $f = Get-EvtxEventFields $Record }
    $id = [int]$Record.Id
    if ($id -eq 1013) {
        # Timestamp: history older than this was removed (UTC). The service
        # itself purges old items every day as SYSTEM (ScanPurgeItemsAfterDelay,
        # 15 days by default), so its cutoff lies whole days before the event;
        # a deletion by a user removes the history up to about now.
        $by = Join-EvtxAccountName $f["Domain"] $f["User"]
        $cutoff = ConvertFrom-UtcText $f["Timestamp"]
        $retention = $f["SID"] -eq "S-1-5-18" -and $null -ne $cutoff -and ($Record.TimeCreated.ToUniversalTime() - $cutoff).TotalHours -ge 23
        if ($retention) {
            $desc = "Defender malware detection history purged by retention (items before $($f['Timestamp']))"
        }
        else {
            $desc = "Defender malware detection history deleted"
            if ($by) { $desc += " by $by" }
        }
        Add-TimelineEntry -Timestamp $Record.TimeCreated -Source $FileName -EventType "SecurityAlert" `
            -Description $desc -User $by `
            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $id; Trigger = $(if ($retention) { "Retention" } else { "User" }); DeletedBefore = $f["Timestamp"]; DeletedBy = $by; SID = $f["SID"] })) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
    elseif ($id -in @(1121, 1122)) {
        $ruleId = "$($f['ID'])".Trim().Trim('{', '}')
        $rule = $script:AsrRuleNames[$ruleId.ToLowerInvariant()]
        if (-not $rule) { $rule = $ruleId }
        $what = if ($id -eq 1121) { "blocked" } else { "audited" }
        $details = [ordered]@{
            EventID           = $id
            RuleID            = $ruleId
            Path              = $f["Path"]
            Process           = $f["Process Name"]
            TargetCommandline = $f["Target Commandline"]
            ParentCommandline = $f["Parent Commandline"]
            InvolvedFile      = $f["Involved File"]
        }
        if ($Count -gt 1) {
            $details["Count"] = $Count
            $details["LastSeen"] = ([datetime]$LastSeen).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        }
        Add-TimelineEntry -Timestamp $Record.TimeCreated -Source $FileName -EventType "SecurityAlert" `
            -Description "Defender attack surface reduction rule ${what}: $rule" -User $f["User"] `
            -Details (Format-ArtifactDetails $details) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
}

# Defender 1122 (attack surface reduction rule audited), folded per rule, path,
# process and UTC day: audit mode can log large numbers of benign events
# (Microsoft says so of the LSASS rule). One row at the first event of each
# group, with Count and LastSeen when it stands for more than one. $Items are
# @{ Record; Fields } pairs. Blocks (1121) are not folded.
function Add-DefenderAsrAuditEntries {
    param([object[]]$Items, [string]$FileName, [string]$FilePath)
    $groups = [ordered]@{}
    foreach ($item in @($Items | Sort-Object { $_.Record.TimeCreated.ToUniversalTime() }, { $_.Record.RecordId })) {
        $f = $item.Fields
        $key = (@("$($f['ID'])".Trim().Trim('{', '}'), "$($f['Path'])", "$($f['Process Name'])",
            $item.Record.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture)) -join "`t").ToLowerInvariant()
        if (-not $groups.Contains($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
        $groups[$key].Add($item)
    }
    foreach ($key in $groups.Keys) {
        $group = $groups[$key]
        Add-DefenderEventEntry -Record $group[0].Record -Fields $group[0].Fields -FileName $FileName -FilePath $FilePath `
            -Count $group.Count -LastSeen $group[$group.Count - 1].Record.TimeCreated
    }
    $folded = @($Items).Count - $groups.Count
    if ($folded -gt 0) {
        Log "    Folded $folded attack surface reduction audit event(s) (1122) into $($groups.Count) row(s)"
    }
}

# A third-party antivirus event: from the Application log (the sources in
# $script:ThirdPartyAvProviders) or from a product's own event log collected
# under AntiVirus\. The text is the vendor's message when its message file
# is on this machine, else the event's values, with whitespace collapsed.
# Critical, Error and Warning events are kept, and Information events whose
# text names a threat and what happened to it ("Virus Found", "Security Risk
# Found", "... Trojan ... deleted"); the other Information events are
# routine (definitions loaded, scan started or finished, update done), and
# for them this returns $null. Otherwise: Description and the Details
# fields that follow EventID.
function Get-AntiVirusEventRow {
    param($Record)
    $detectionPattern = '\b(virus|threat|malware|trojan|worm|ransomware|spyware|infected|infection|security risk)\b.*\b(found|detected|quarantined|blocked|cleaned|removed|deleted)\b'
    $levelNames = @{ 1 = "Critical"; 2 = "Error"; 3 = "Warning"; 4 = "Information" }
    $text = "$($Record.Message)"
    if (-not $text.Trim()) {
        $text = (@($Record.Properties | ForEach-Object { "$($_.Value)".Trim() } | Where-Object { $_ -and $_ -ne "(NULL)" }) -join " | ")
    }
    $text = ($text -replace '\s+', ' ').Trim()
    $level = [int]$Record.Level
    if ($level -notin @(1, 2, 3) -and $text -notmatch $detectionPattern) { return $null }
    $short = if ($text.Length -gt 200) { $text.Substring(0, 200) + "..." } else { $text }
    return [PSCustomObject]@{
        Description = "Antivirus event ($($Record.ProviderName) $($Record.Id)): $short"
        Details     = [ordered]@{
            Provider = $Record.ProviderName
            Level    = $(if ($levelNames.ContainsKey($level)) { $levelNames[$level] } else { "$($Record.Level)" })
            Message  = $(if ($text.Length -gt 1000) { $text.Substring(0, 1000) + "..." } else { $text })
            UserSID  = "$($Record.UserId)"
        }
    }
}

# Application.evtx. Message layouts were checked against the providers'
# message files (msimsg.dll, wer.dll, wersvc.dll, wscsvc.dll, esent.dll):
#   MsiInstaller 1033/1034    installed / removed: product, version,
#                             manufacturer, status              Installation
#   MsiInstaller 11707/11724  only when there is no 1033/1034 for the
#                             same product within a minute      Installation
#   Application Error 1000    crash: app, version, faulting
#                             module, exception code, path      Execution
#   Application Hang 1002     hang: app, version, path          Execution
#   SecurityCenter 15         security product state (ON, OFF, SNOOZED,
#                             EXPIRED): the first per product
#                             and each change                   SecurityAlert
#   SecurityCenter 16         a state update that failed        SecurityAlert
#   ESENT 216, 325-327        database location changed /
#                             created / attached / detached
#                             (shows copies of ntds.dit)        FileAccess
#   $script:ThirdPartyAvProviders, any ID: the message text,
#                             trimmed; Critical, Error and Warning
#                             events, and Information events
#                             whose text reports a detection
#                             (Get-AntiVirusEventRow)           SecurityAlert
# Windows Error Reporting 1001 is not read: its application crashes and hangs
# repeat 1000 / 1002, and the rest (LiveKernelEvent, Store and update
# failures) is routine and can number in the hundreds.
function Add-ApplicationEventEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $items = @($Records | Sort-Object TimeCreated, RecordId | ForEach-Object { [PSCustomObject]@{ Record = $_; Fields = Get-EvtxEventFields $_ } })
    $msiStatusNames = @{ "0" = "success"; "3010" = "success, restart required"; "1641" = "success, restart started"; "1602" = "cancelled by the user"; "1603" = "fatal error" }
    $eseActions = @{ 325 = "created"; 326 = "attached"; 327 = "detached" }

    # Product name -> times of its 1033 (installed) / 1034 (removed) events
    $msiTimes = @{}
    foreach ($item in $items) {
        if ($item.Record.ProviderName -eq "MsiInstaller" -and $item.Record.Id -in @(1033, 1034)) {
            $key = "$($item.Record.Id)`t" + (Get-EvtxFieldValue $item.Fields @("param1"))
            if (-not $msiTimes.ContainsKey($key)) { $msiTimes[$key] = @() }
            $msiTimes[$key] += $item.Record.TimeCreated
        }
    }

    $productStates = @{}
    $rowCounts = [ordered]@{}
    $skipped = [ordered]@{}
    foreach ($item in $items) {
        $r = $item.Record
        $f = $item.Fields
        $provider = $r.ProviderName
        $id = [int]$r.Id
        $type = $null
        $desc = $null
        $user = ""
        $details = [ordered]@{ EventID = $id }

        if ($provider -eq "MsiInstaller") {
            $type = "Installation"
            if ($id -in @(1033, 1034)) {
                # %1 product, %2 version, %3 language, %4 status, %5 manufacturer
                $product = Get-EvtxFieldValue $f @("param1")
                $version = Get-EvtxFieldValue $f @("param2")
                $status = Get-EvtxFieldValue $f @("param4")
                $ok = @("0", "3010", "1641") -contains $status
                $what = if ($id -eq 1033) { $(if ($ok) { "Software installed" } else { "Software installation failed" }) } else { $(if ($ok) { "Software removed" } else { "Software removal failed" }) }
                $desc = "${what}: $product $version".TrimEnd()
                if (-not $ok -and $status) { $desc += " (status $status)" }
                $details["Product"] = $product
                $details["Version"] = $version
                $details["Manufacturer"] = Get-EvtxFieldValue $f @("param5")
                $details["Status"] = $(if ($msiStatusNames.ContainsKey($status)) { "$status ($($msiStatusNames[$status]))" } else { $status })
            }
            else {
                # "Product: <name> -- Installation completed successfully."
                $message = Get-EvtxFieldValue $f @("param1")
                $product = if ($message -match '^\S+:\s*(.+?)\s+--\s') { $Matches[1] } else { "" }
                $pair = if ($id -eq 11707) { 1033 } else { 1034 }
                $twin = @($msiTimes["$pair`t$product"] | Where-Object { $null -ne $_ -and [Math]::Abs(($_ - $r.TimeCreated).TotalSeconds) -le 60 })
                if ($product -and $twin.Count -gt 0) {
                    $skipped["MsiInstaller $id (same install as $pair)"] = 1 + [int]$skipped["MsiInstaller $id (same install as $pair)"]
                    continue
                }
                $what = if ($id -eq 11707) { "Software installed" } else { "Software removed" }
                $desc = if ($product) { "${what}: $product" } else { "${what}: $message" }
                $details["Product"] = $product
                $details["Message"] = $message
            }
            # The product code is the start of the binary data, as ASCII text
            if ($r.ToXml() -match '<Binary>((?:[0-9A-Fa-f]{2}){38})') {
                $hex = $Matches[1]
                $code = -join (0..37 | ForEach-Object { [char][Convert]::ToByte($hex.Substring($_ * 2, 2), 16) })
                if ($code -match '^\{[0-9A-Fa-f-]{36}\}$') { $details["ProductCode"] = $code }
            }
            # The account that ran the install (SYSTEM for most updates)
            $user = Resolve-BamUser -Sid "$($r.UserId)" -SidNames @{}
            $details["UserSID"] = "$($r.UserId)"
        }
        elseif ($provider -eq "Application Error") {
            # Named fields; %1-%15 in the same order in older unnamed records
            $type = "Execution"
            $app = Get-EvtxFieldValue $f @("AppName", "param1")
            $module = Get-EvtxFieldValue $f @("ModuleName", "param4")
            $code = Get-EvtxFieldValue $f @("ExceptionCode", "param7")
            if ($code -and $code -notmatch '^0x') { $code = "0x$code" }
            $offset = Get-EvtxFieldValue $f @("FaultingOffset", "param8")
            if ($offset -and $offset -notmatch '^0x') { $offset = "0x$offset" }
            $desc = "Application crashed: $app (exception $code in $module)"
            $details["Application"] = $app
            $details["Version"] = Get-EvtxFieldValue $f @("AppVersion", "param2")
            $details["Module"] = $module
            $details["ModuleVersion"] = Get-EvtxFieldValue $f @("ModuleVersion", "param5")
            $details["ExceptionCode"] = $code
            $details["FaultOffset"] = $offset
            $details["Path"] = Get-EvtxFieldValue $f @("AppPath", "param11")
            $details["ModulePath"] = Get-EvtxFieldValue $f @("ModulePath", "param12")
        }
        elseif ($provider -eq "Application Hang") {
            # %1 app, %2 version, %3 process ID, %6 path, %10 hang type
            $type = "Execution"
            $app = Get-EvtxFieldValue $f @("AppName", "param1")
            $desc = "Application hung and was closed: $app"
            $details["Application"] = $app
            $details["Version"] = Get-EvtxFieldValue $f @("AppVersion", "param2")
            $details["Path"] = Get-EvtxFieldValue $f @("ExeFileName", "param6")
            $details["HangType"] = Get-EvtxFieldValue $f @("HangType", "param10")
        }
        elseif ($provider -eq "SecurityCenter") {
            # %1 product, %2 state (SECURITY_PRODUCT_STATE_ON / OFF / SNOOZED / EXPIRED).
            # A product that is ON is context, not an alert.
            $product = Get-EvtxFieldValue $f @("param1")
            $state = (Get-EvtxFieldValue $f @("param2")) -replace '^SECURITY_PRODUCT_STATE_', ''
            $type = if ($state -eq "ON") { "Snapshot" } else { "SecurityAlert" }
            if (-not $product) { continue }
            $details["Product"] = $product
            $details["State"] = $state
            if ($id -eq 15) {
                # Each start of the service reports every product again
                $previous = $productStates[$product]
                if ($previous -eq $state) {
                    $skipped["SecurityCenter 15 (state unchanged)"] = 1 + [int]$skipped["SecurityCenter 15 (state unchanged)"]
                    continue
                }
                $productStates[$product] = $state
                $desc = "Security product state: $product $state"
                $details["PreviousState"] = $previous
            }
            else {
                $desc = "Security Center could not update product state: $product $state"
            }
        }
        elseif ($provider -eq "ESENT") {
            # %1 process, %2 "PID,...", %3 instance; 216: %4 old and %5 new
            # location; 325-327: %4 database ID, %5 database path
            $type = "FileAccess"
            if ($id -eq 216) {
                $desc = "ESE database location changed: $(Get-EvtxFieldValue $f @('param4')) -> $(Get-EvtxFieldValue $f @('param5'))"
                $details["OldPath"] = Get-EvtxFieldValue $f @("param4")
                $details["NewPath"] = Get-EvtxFieldValue $f @("param5")
            }
            else {
                $desc = "ESE database $($eseActions[$id]): $(Get-EvtxFieldValue $f @('param5'))"
                $details["Database"] = Get-EvtxFieldValue $f @("param5")
            }
            $details["Process"] = Get-EvtxFieldValue $f @("param1")
            $details["ProcessId"] = ((Get-EvtxFieldValue $f @("param2")) -split ',')[0]
            $details["Instance"] = (Get-EvtxFieldValue $f @("param3")) -replace '\s*:\s*$', ''
        }
        elseif ($script:ThirdPartyAvProviders -contains $provider) {
            $type = "SecurityAlert"
            $avRow = Get-AntiVirusEventRow -Record $r
            if ($null -eq $avRow) {
                $skipped["antivirus Information events that report no detection"] = 1 + [int]$skipped["antivirus Information events that report no detection"]
                continue
            }
            $desc = $avRow.Description
            foreach ($key in $avRow.Details.Keys) { $details[$key] = $avRow.Details[$key] }
        }
        if (-not $desc) { continue }

        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType $type `
            -Description $desc -User $user -Details (Format-ArtifactDetails $details) `
            -Artifact "EventLogs" -RawPath $FilePath
        $rowCounts["$provider $id"] = 1 + [int]$rowCounts["$provider $id"]
    }
    if ($rowCounts.Count -gt 0) {
        Log "    Rows by event: $((@($rowCounts.Keys | ForEach-Object { "$_ x$($rowCounts[$_])" })) -join ', ')"
    }
    foreach ($reason in $skipped.Keys) {
        Log "    Skipped $($skipped[$reason]) event(s): $reason"
    }
}

# Text cut to at most $Max characters, with "..." when it was longer
function Get-EvtxShortText {
    param([string]$Text, [int]$Max)
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max) + "..."
}

# ActivityID (System\Correlation, which ties the events of one operation
# together; lower case, no braces) and ProcessId (System\Execution, the
# process that wrote the event) of an event record; "" when missing
function Get-EvtxSystemIds {
    param($Record)
    $xml = $Record.ToXml()
    $ids = @{ ActivityId = ""; ProcessId = "" }
    if ($xml -match '<Correlation\s[^>]*ActivityID=[''"]\{?([0-9A-Fa-f-]{36})\}?[''"]') { $ids.ActivityId = $Matches[1].ToLowerInvariant() }
    if ($xml -match '<Execution\s[^>]*ProcessID=[''"](\d+)[''"]') { $ids.ProcessId = $Matches[1] }
    return $ids
}

# A third-party antivirus product's own event log, which the collector puts
# in AntiVirus\ (Symantec_SEP_EventLog.evtx, CrowdStrike_EventLog.evtx).
# Every event in it is the product's, so all of them go through the filter
# and wording of the antivirus events in the Application log
# (Get-AntiVirusEventRow). SecurityAlert rows, Artifact AntiVirus.
function Add-AntiVirusLogEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $skipped = 0
    foreach ($r in @($Records | Sort-Object TimeCreated, RecordId)) {
        $avRow = Get-AntiVirusEventRow -Record $r
        if ($null -eq $avRow) { $skipped++; continue }
        $details = [ordered]@{ EventID = [int]$r.Id }
        foreach ($key in $avRow.Details.Keys) { $details[$key] = $avRow.Details[$key] }
        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType "SecurityAlert" `
            -Description $avRow.Description -Details (Format-ArtifactDetails $details) `
            -Artifact "AntiVirus" -RawPath $FilePath
    }
    if ($skipped -gt 0) { Log "    Skipped $skipped event(s): antivirus Information events that report no detection" }
}

# Fields of the context text of a classic Windows PowerShell event, as a
# hashtable. Windows writes "<TAB>Name=value" lines in a fixed order: ...,
# (800: UserId,) HostName, HostVersion, HostId, HostApplication,
# EngineVersion, RunspaceId, PipelineId, then CommandName, CommandType,
# ScriptName, CommandPath, CommandLine (400 / 403) or ScriptName,
# CommandLine (800). HostApplication (the command line that started
# PowerShell) and the CommandLine of an 800 are written as they are, line
# breaks included, so they can hold lines that look like other fields
# ("EngineVersion=2.0"). So the 800's CommandLine, which ends the text and
# is the event's first value (-CommandLine), is taken off first, and
# HostApplication runs up to the LAST EngineVersion line that is followed by
# a RunspaceId line; the other fields are read before and after it.
function Get-PowerShellContextFields {
    param([string]$Text, [string]$CommandLine = "")
    $fields = @{}
    $rest = "$Text"
    $tail = "`tCommandLine=" + $CommandLine
    if ($CommandLine -and $rest.EndsWith($tail, [System.StringComparison]::Ordinal)) {
        $fields["CommandLine"] = $CommandLine.Trim()
        $rest = $rest.Substring(0, $rest.Length - $tail.Length)
    }
    $lines = $rest
    $start = $rest.IndexOf("`tHostApplication=", [System.StringComparison]::Ordinal)
    if ($start -ge 0) {
        $value = $rest.Substring($start + "`tHostApplication=".Length)
        # Greedy: the last EngineVersion / RunspaceId pair is the one Windows wrote
        $m = [regex]::Match($value, '(?s)^(.*)\r?\n(\tEngineVersion=[^\r\n]*\r?\n\tRunspaceId=.*)$')
        # Not the usual layout: HostApplication is its own line only
        if (-not $m.Success) { $m = [regex]::Match($value, '(?s)^([^\r\n]*)(.*)$') }
        $fields["HostApplication"] = $m.Groups[1].Value.Trim()
        $lines = $rest.Substring(0, $start) + "`n" + $m.Groups[2].Value
    }
    foreach ($line in ($lines -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z]+)=(.*)$' -and -not $fields.ContainsKey($Matches[1])) { $fields[$Matches[1]] = $Matches[2].Trim() }
    }
    return $fields
}

# Script text of the -EncodedCommand argument (base64 of UTF-16LE text) in a
# PowerShell command line; "" if there is none or it does not decode to
# text. powershell.exe takes -e, -ec and every abbreviation of
# -EncodedCommand, after "-", "/" or a Unicode dash (en dash, em dash,
# horizontal bar: U+2013-U+2015).
function ConvertFrom-PowerShellEncodedCommand {
    param([string]$CommandLine)
    foreach ($m in [regex]::Matches("$CommandLine", '(?i)(?:^|\s)[-/\u2013\u2014\u2015](e[a-z]*)\s+[''"]?([A-Za-z0-9+/]{8,}={0,2})')) {
        $name = $m.Groups[1].Value.ToLowerInvariant()
        if ($name -ne "ec" -and -not "encodedcommand".StartsWith($name, [System.StringComparison]::Ordinal)) { continue }
        try { $bytes = [Convert]::FromBase64String($m.Groups[2].Value) }
        catch {
            Write-Verbose "PowerShell -EncodedCommand argument is not base64: $($_.Exception.Message)"
            continue
        }
        # UTF-16 text has an even byte count. A script is mostly printable
        # ASCII (commands, operators, variable names), even with strings in
        # another script; random bytes read as UTF-16 almost never are (95 in
        # 65536 code units)
        if ($bytes.Length -eq 0 -or $bytes.Length % 2 -ne 0) { continue }
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
        $printable = [regex]::Matches($text, '[\x09\x0A\x0D\x20-\x7E]').Count
        if ($text.Trim() -and $printable -ge 0.5 * $text.Length) { return $text }
    }
    return ""
}

# Windows PowerShell.evtx, the classic log of Windows PowerShell 2.0-5.1
# (provider "PowerShell", unnamed values; the last one holds "Name=value"
# context lines, see Get-PowerShellContextFields; checked on real records):
#   400  engine started: HostApplication is the command line that started
#        PowerShell (the decoded -EncodedCommand script is added);
#        EngineVersion 2.0 on a current Windows means a downgrade to the
#        old engine, which has no script block or module logging   Execution
#   403  engine stopped: folded into the row of its 400 (same HostId and
#        RunspaceId) as Stopped; a row of its own only when that 400 is not
#        in the log                                                Execution
#   800  pipeline execution details (CommandLine, the commands run, UserId;
#        a long one is split over several 800s with the same PipelineId).
#        PowerShell 2.0 engines: one row per pipeline, as nothing else
#        records what such a session ran. Later engines: one row per
#        session (HostId and RunspaceId) at its first pipeline, with all its
#        command lines and commands, Count and LastSeen. Without module
#        logging Windows writes these only for Add-Type (compiled code); the
#        PowerShell/Operational log, which also has them (4103), usually
#        wraps much sooner, so these are often the only record left.
#                                                                  Execution
# Command lines are cut to 1000 characters in Details (all of a session's:
# 2000), 200 in Description, with their whitespace collapsed there.
function Add-WindowsPowerShellEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $rows = New-Object System.Collections.Generic.List[object]
    $openEngines = @{}
    $groups = @{}
    $folded403 = 0
    $folded800 = 0
    foreach ($r in @($Records | Sort-Object TimeCreated, RecordId)) {
        $f = Get-EvtxEventFields $r
        $id = [int]$r.Id
        # 400 / 403: %1 new state, %2 old state, %3 context; 800: %1 command
        # line, %2 context, %3 details ("CommandInvocation(...)" lines)
        $commandLine = if ($id -eq 800) { "$($f['param1'])" } else { "" }
        $context = Get-PowerShellContextFields -Text $(if ($id -eq 800) { $f["param2"] } else { $f["param3"] }) -CommandLine $commandLine
        $isV2 = "$($context['EngineVersion'])" -match '^2\.'
        $session = "$($context['HostId'])|$($context['RunspaceId'])"
        $time = $r.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        if ($id -eq 403 -and $context["HostId"] -and $openEngines.ContainsKey($session)) {
            $openEngines[$session].Stopped = $time
            $openEngines.Remove($session)
            $folded403++
            continue
        }
        $row = $null
        if ($id -eq 800) {
            $pipelineKey = if ($context["PipelineId"]) { "$session|$($context['PipelineId'])" } else { "$session|record $($r.RecordId)" }
            $groupKey = if ($isV2) { "2.0|$pipelineKey" } elseif ($context["HostId"]) { $session } else { "record $($r.RecordId)" }
            $row = $groups[$groupKey]
            if ($row) { $folded800++ }
        }
        if (-not $row) {
            $row = [PSCustomObject]@{ Record = $r; EventId = $id; Context = $context; IsV2 = $isV2; Stopped = ""; User = ""
                CommandLines = New-Object System.Collections.Generic.List[string]; Commands = New-Object System.Collections.Generic.List[string]
                Pipelines = 0; Pipeline = ""; LastSeen = "" }
            $rows.Add($row)
            if ($id -eq 400 -and $context["HostId"]) { $openEngines[$session] = $row }
            if ($id -eq 800) {
                $groups[$groupKey] = $row
                $row.User = "$($context['UserId'])"
            }
        }
        if ($id -eq 800) {
            # A continuation part (DetailSequence 2 and up) adds commands only
            if ("$($context['DetailSequence'])" -notmatch '^([2-9]|\d{2,})$' -or $row.Pipeline -ne $pipelineKey) {
                $row.Pipelines++
                if ($commandLine.Trim() -and -not $row.CommandLines.Contains($commandLine.Trim())) { $row.CommandLines.Add($commandLine.Trim()) }
            }
            $row.Pipeline = $pipelineKey
            $row.LastSeen = $time
            foreach ($m in [regex]::Matches("$($f['param3'])", 'CommandInvocation\(([^)]+)\)')) {
                if (-not $row.Commands.Contains($m.Groups[1].Value)) { $row.Commands.Add($m.Groups[1].Value) }
            }
        }
    }
    foreach ($row in $rows) {
        $context = $row.Context
        $hostApp = "$($context['HostApplication'])"
        $shown = if ($hostApp) { Get-EvtxShortText (($hostApp -replace '\s+', ' ').Trim()) 200 } else { "host $($context['HostName'])" }
        $details = [ordered]@{ EventID = $row.EventId }
        if ($row.EventId -eq 400) {
            $desc = if ($row.IsV2) { "PowerShell 2.0 engine started (possible downgrade): $shown" } else { "PowerShell engine started: $shown" }
        }
        elseif ($row.EventId -eq 403) {
            $desc = "PowerShell engine stopped: $shown"
        }
        else {
            $first = if ($row.CommandLines.Count -gt 0) { $row.CommandLines[0] } else { "" }
            $shownCommand = Get-EvtxShortText (($first -replace '\s+', ' ').Trim()) 200
            $desc = if ($row.IsV2) { "PowerShell 2.0 pipeline executed: $shownCommand" } else { "PowerShell pipeline executed: $shownCommand" }
            $details["CommandLine"] = Get-EvtxShortText $first 1000
            $details["Commands"] = Get-EvtxShortText ($row.Commands -join ", ") 1000
            if ($row.CommandLines.Count -gt 1) {
                $details["CommandLines"] = Get-EvtxShortText ((@($row.CommandLines) | ForEach-Object { Get-EvtxShortText (($_ -replace '\s+', ' ').Trim()) 200 }) -join " || ") 2000
            }
            if ($row.Pipelines -gt 1) {
                $details["Count"] = $row.Pipelines
                $details["LastSeen"] = $row.LastSeen
            }
        }
        $details["EngineVersion"] = $context["EngineVersion"]
        $details["HostName"] = $context["HostName"]
        $details["HostVersion"] = $context["HostVersion"]
        $details["HostApplication"] = Get-EvtxShortText $hostApp 1000
        if ($row.EventId -eq 400) { $details["EncodedCommand"] = Get-EvtxShortText (ConvertFrom-PowerShellEncodedCommand $hostApp) 1000 }
        $details["ScriptName"] = $context["ScriptName"]
        $details["HostId"] = $context["HostId"]
        $details["RunspaceId"] = $context["RunspaceId"]
        $details["Stopped"] = $row.Stopped
        Add-TimelineEntry -Timestamp $row.Record.TimeCreated -Source $FileName -EventType "Execution" `
            -Description $desc -User $row.User -Details (Format-ArtifactDetails $details) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
    if ($folded403 -gt 0) { Log "    Folded $folded403 engine stopped event(s) (403) into the row of their 400 (Stopped)" }
    if ($folded800 -gt 0) {
        Log "    Folded $folded800 pipeline event(s) (800) into the row of their session (PowerShell 3.0 and later) or pipeline (2.0)"
    }
}

# Value of a property in the MOF text of a WMI instance (Name = "value";
# with \" \\ \n escapes), or ""
function Get-WmiMofProperty {
    param([string]$Text, [string]$Name)
    $m = [regex]::Match("$Text", '(?im)^\s*' + [regex]::Escape($Name) + '\s*=\s*"((?:[^"\\]|\\.)*)"\s*;')
    if (-not $m.Success) { return "" }
    return [regex]::Replace($m.Groups[1].Value, '\\(.)', {
            param($escape)
            switch -CaseSensitive ($escape.Groups[1].Value) {
                "n" { "`n" }
                "r" { "`r" }
                "t" { "`t" }
                default { $escape.Groups[1].Value }
            }
        })
}

# SID in the "CreatorSID = {1, 2, 0, ...};" line (the account that created
# the instance, as the bytes of a binary SID) of the MOF text of a WMI
# instance, or "" when there is none or it is not a valid SID
function Get-WmiMofCreatorSid {
    param([string]$Text)
    $m = [regex]::Match("$Text", '(?im)^\s*CreatorSID\s*=\s*\{([\d,\s]+)\}\s*;')
    if (-not $m.Success) { return "" }
    try {
        $bytes = [byte[]]@($m.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { [byte]$_ })
        return (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $bytes, 0).Value
    }
    catch {
        Write-Verbose "WMI CreatorSID is not a SID: $($_.Exception.Message)"
        return ""
    }
}

# Microsoft-Windows-WMI-Activity/Operational (fields from the UserData of real
# records; the provider manifest has the same names):
#   5861  permanent event subscription: an event filter bound to a consumer
#         (Namespace; ESS = the filter name; CONSUMER = Class="name";
#         PossibleCause = the filter and consumer instances as MOF text,
#         with the query, what the consumer runs and the CreatorSID of
#         each: User is the consumer's creator, else the filter's)
#                                                          PersistenceChange
#   5860  temporary event subscription: a running process waiting for WMI
#         events (NamespaceName, Query, User, Processid, ClientMachine)
#                                                          Execution
# 5861 is written when a binding is created and again each time the WMI
# service starts and activates the bindings that exist, so identical
# bindings are folded into one row at the first event, with Count and
# LastSeen; 5860 likewise per query, user, client machine and UTC day
# (services register the same queries at every start). Windows' own "SCM
# Event Log" binding (an NTEventLogEventConsumer) is labelled as the
# Windows default. 5857 (provider started), 5858 (operation failed) and
# 5859 (filter activated for a permanent consumer) are routine, hundreds a
# day, and only counted.
function Add-WmiActivityEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $skipNames = @{ 5857 = "WMI provider started"; 5858 = "WMI operation failed"; 5859 = "event filter activated for a permanent consumer" }
    $groups = [ordered]@{}
    $skipped = [ordered]@{}
    foreach ($r in @($Records | Sort-Object TimeCreated, RecordId)) {
        $id = [int]$r.Id
        if ($id -notin @(5860, 5861)) {
            $label = "$id $($skipNames[$id])".Trim()
            $skipped[$label] = 1 + [int]$skipped[$label]
            continue
        }
        $f = Get-EvtxEventFields $r
        if ($id -eq 5861) { $parts = @($f["Namespace"], $f["ESS"], $f["CONSUMER"], $f["PossibleCause"]) }
        else { $parts = @($f["NamespaceName"], $f["Query"], $f["User"], $f["ClientMachine"], $r.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture)) }
        $key = ("$id`t" + ((@($parts | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })) -join "`t")).ToLowerInvariant()
        if (-not $groups.Contains($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
        $groups[$key].Add([PSCustomObject]@{ Record = $r; Fields = $f })
    }
    $folded = 0
    foreach ($key in $groups.Keys) {
        $group = $groups[$key]
        $r = $group[0].Record
        $f = $group[0].Fields
        $id = [int]$r.Id
        $user = ""
        $details = [ordered]@{ EventID = $id }
        if ($id -eq 5861) {
            $type = "PersistenceChange"
            # "Binding EventFilter: instance of __EventFilter {...}; Perm. Consumer: instance of <class> {...};"
            $cause = @("$($f['PossibleCause'])" -split 'Perm\. Consumer:', 2)
            $filterText = $cause[0]
            $consumerText = if ($cause.Count -gt 1) { $cause[1] } else { "" }
            $filter = Get-EvtxFieldValue $f @("ESS")
            $consumer = Get-EvtxFieldValue $f @("CONSUMER")
            $consumerType = ""
            $consumerName = $consumer
            if ($consumer -match '^([^=]+)="?(.*?)"?$') {
                $consumerType = $Matches[1].Trim()
                $consumerName = $Matches[2]
            }
            elseif ($consumerText -match 'instance of (\w+)') { $consumerType = $Matches[1] }
            $query = Get-WmiMofProperty $filterText "Query"
            $desc = "WMI permanent event subscription: filter ""$filter"" -> $consumer"
            if ($filter -eq "SCM Event Log Filter" -and $consumerType -eq "NTEventLogEventConsumer" -and $consumerName -eq "SCM Event Log Consumer") {
                $desc += " (Windows default)"
            }
            $details["Namespace"] = $f["Namespace"]
            $details["Filter"] = $filter
            $details["Query"] = Get-EvtxShortText $query 1000
            $details["EventNamespace"] = Get-WmiMofProperty $filterText "EventNamespace"
            $details["ConsumerType"] = $consumerType
            $details["Consumer"] = $consumerName
            # What the consumer runs or writes
            foreach ($name in @("CommandLineTemplate", "ExecutablePath", "WorkingDirectory", "ScriptingEngine", "ScriptFileName", "ScriptText", "Filename", "SourceName")) {
                $details[$name] = Get-EvtxShortText (Get-WmiMofProperty $consumerText $name) 1000
            }
            # Who created the filter and the consumer (S-1-5-32-544: an
            # elevated member of Administrators)
            $filterCreator = Get-WmiMofCreatorSid $filterText
            $consumerCreator = Get-WmiMofCreatorSid $consumerText
            $details["FilterCreatorSID"] = $filterCreator
            $details["ConsumerCreatorSID"] = $consumerCreator
            $creator = if ($consumerCreator) { $consumerCreator } else { $filterCreator }
            $user = if ($creator -eq "S-1-5-32-544") { "BUILTIN\Administrators" } elseif ($creator) { Resolve-BamUser -Sid $creator -SidNames @{} } else { "" }
        }
        else {
            $type = "Execution"
            $query = Get-EvtxFieldValue $f @("Query")
            $user = Get-EvtxFieldValue $f @("User")
            $desc = "WMI temporary event subscription: $(Get-EvtxShortText $query 200)"
            $details["Namespace"] = $f["NamespaceName"]
            $details["Query"] = Get-EvtxShortText $query 1000
            $details["User"] = $user
            $details["ClientProcessId"] = Get-EvtxFieldValue $f @("Processid")
            $details["ClientMachine"] = $f["ClientMachine"]
        }
        if ($group.Count -gt 1) {
            $details["Count"] = $group.Count
            $details["LastSeen"] = $group[$group.Count - 1].Record.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            $folded += $group.Count - 1
        }
        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType $type `
            -Description $desc -User $user -Details (Format-ArtifactDetails $details) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
    if ($folded -gt 0) { Log "    Folded $folded repeated WMI subscription event(s) (5860 / 5861) into their first row (Count, LastSeen)" }
    foreach ($label in $skipped.Keys) { Log "    Skipped $($skipped[$label]) event(s): $label (routine)" }
}

# Microsoft-Windows-TerminalServices-RDPClient/Operational: outbound RDP
# connections made from this machine with the Remote Desktop client
# (provider Microsoft-Windows-TerminalServices-ClientActiveXCore; field names
# from its manifest and real records). The events of one connection share
# an ActivityID, which names the server in the rows of the events that
# do not carry it. All NetworkConnection; User is the account that ran the
# client (the record's SID).
#   1024  connecting to the server (Value = the server name as typed)
#   1025  connected to the server (no data; the connection reached it)
#   1102  multi-transport (UDP) connection initiated (Value = server address)
#   1027  connected to the server's domain (DomainName, SessionId)
#   1029  Base64(SHA-256(user name)) of the account used (TraceMessage)
#   1009  the server did not accept the credentials
#   1026  disconnected (Value = disconnect reason code)
function Add-RdpClientEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    # Disconnect reasons (IMsTscAxEvents::OnDisconnected), the ones that show
    # whether a connection or logon failed
    $reasons = @{ "0" = "no information"; "1" = "local disconnection"; "2" = "remote disconnection by user"; "3" = "remote disconnection by server"
        "260" = "DNS name lookup failure"; "264" = "connection timed out"; "516" = "socket connect failed"; "520" = "host not found"; "1288" = "DNS lookup failed"
        "2055" = "login failed"; "2308" = "socket closed"; "2567" = "no such user"; "2823" = "account disabled"; "3335" = "account locked out"
        "3591" = "account expired"; "3847" = "password expired" }
    $items = @($Records | Sort-Object TimeCreated, RecordId | ForEach-Object {
            [PSCustomObject]@{ Record = $_; Fields = Get-EvtxEventFields $_; ActivityId = (Get-EvtxSystemIds $_).ActivityId }
        })
    # Server of each connection: the name from its 1024, else the address
    # from its 1102
    $servers = @{}
    foreach ($id in @(1024, 1102)) {
        foreach ($item in $items) {
            $name = Get-EvtxFieldValue $item.Fields @("Value")
            if ([int]$item.Record.Id -eq $id -and $item.ActivityId -and $name -and -not $servers.ContainsKey($item.ActivityId)) { $servers[$item.ActivityId] = $name }
        }
    }
    foreach ($item in $items) {
        $r = $item.Record
        $f = $item.Fields
        $id = [int]$r.Id
        $server = if ($item.ActivityId -and $servers.ContainsKey($item.ActivityId)) { $servers[$item.ActivityId] } else { "" }
        $what = ""
        $details = [ordered]@{ EventID = $id }
        switch ($id) {
            1024 { $server = Get-EvtxFieldValue $f @("Value") }
            1102 {
                $address = Get-EvtxFieldValue $f @("Value")
                if (-not $server) { $server = $address }
                $what = "multi-transport connection to $address"
                $details["ServerAddress"] = $address
            }
            1027 {
                $domain = Get-EvtxFieldValue $f @("DomainName")
                $session = Get-EvtxFieldValue $f @("SessionId")
                $what = "connected (domain $domain, session $session)"
                $details["Domain"] = $domain
                $details["SessionID"] = $session
            }
            1029 {
                $hash = Get-EvtxFieldValue $f @("TraceMessage")
                $what = "user name hash $hash"
                $details["UserNameHash"] = $hash
            }
            1025 { $what = "connected to the server" }
            1009 { $what = "credentials not accepted by the server" }
            1026 {
                $code = Get-EvtxFieldValue $f @("Value")
                $what = "disconnected (reason $code"
                if ($reasons.ContainsKey($code)) { $what += ", $($reasons[$code])" }
                $what += ")"
                $details["DisconnectReason"] = $code
            }
        }
        $desc = if ($server) { "Outbound RDP connection to $server" } else { "Outbound RDP connection" }
        if ($what) { $desc += ": $what" }
        $details["Server"] = $server
        $details["ActivityID"] = $item.ActivityId
        $details["UserSID"] = "$($r.UserId)"
        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType "NetworkConnection" `
            -Description $desc -User (Resolve-BamUser -Sid "$($r.UserId)" -SidNames @{}) -Details (Format-ArtifactDetails $details) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
}

# Microsoft-Windows-NTLM/Operational. Written only where NTLM auditing is on
# (the "Network security: Restrict NTLM: Audit ..." policies; 4013, 4020-4024
# and 4030-4033 come from the NTLM logging of Windows 11 24H2 and Windows
# Server 2025). Field names from the manifests of the Microsoft-Windows-NTLM
# and Microsoft-Windows-Security-Netlogon providers on Windows 11 26100:
#   8001       outgoing NTLM authentication: TargetName, the supplied
#              account, the client process                 NetworkConnection
#   4013       outgoing NTLMv1 authentication that failed (this device does
#              not support NTLMv1); same fields as 8001    NetworkConnection
#   4024       outgoing authentication with NTLMv1-derived credentials
#              (single sign-on); same fields as 8001       NetworkConnection
#   8002       incoming NTLM authentication: the process and its caller
#              identity                                    Logon
#   8003       NTLM authentication in this domain (on a server): account,
#              Workstation, LogonType                      Logon
#   8004-8006  NTLM authentication passed to this domain controller:
#              account, WorkstationName, secure channel (the three share
#              one template and message)                   Logon
#   4020/4021  outgoing NTLM authentication, with NtlmVersion
#                                                          NetworkConnection
#   4022/4023  incoming NTLM authentication from a remote client, with
#              NtlmVersion                                 Logon
#   4030/4031  NTLM authentication of an account of this domain processed by
#              this domain controller: client, server, the server or trust
#              it was forwarded from, NtlmVersion          Logon
#   4032/4033  forwarded NTLM authentication from this domain processed by
#              this domain controller: client, server, NtlmVersion   Logon
# NTLMv1 is a finding: the rows of 4013, 4024 and of 4020-4033 with
# NtlmVersion NTLMv1 say "(NTLMv1" in Description. Unset values are written
# as "(NULL)" and read as empty.
function Add-NtlmEventEntry {
    param($Record, [string]$FileName, [string]$FilePath)
    $f = Get-EvtxEventFields $Record
    foreach ($key in @($f.Keys)) { if ("$($f[$key])".Trim() -eq "(NULL)") { $f[$key] = "" } }
    $id = [int]$Record.Id
    $type = "Logon"
    $details = [ordered]@{ EventID = $id }
    switch ($id) {
        { $_ -in @(8001, 4013, 4024) } {
            $type = "NetworkConnection"
            $target = Get-EvtxFieldValue $f @("TargetName")
            $account = Join-EvtxAccountName $f["DomainName"] $f["UserName"]
            $caller = Join-EvtxAccountName $f["ClientDomainName"] $f["ClientUserName"]
            $user = if ($account) { $account } else { $caller }
            $desc = "Outgoing NTLM authentication to $target"
            if ($id -eq 4013) { $desc += " (NTLMv1, failed: not supported on this device)" }
            if ($id -eq 4024) { $desc += " (NTLMv1-derived credentials, single sign-on)" }
            $details["Target"] = $target
            if ($id -ne 8001) { $details["NtlmVersion"] = "NTLMv1" }
            $details["Account"] = $account
            $details["Process"] = $f["ProcessName"]
            $details["PID"] = $f["CallerPID"]
            $details["ProcessAccount"] = $caller
            $details["MechanismOID"] = $f["MechanismOID"]
        }
        8002 {
            $caller = Join-EvtxAccountName $f["ClientDomainName"] $f["ClientUserName"]
            $process = Get-EvtxFieldValue $f @("ProcessName")
            $user = $caller
            $desc = "Incoming NTLM authentication (process $process, account $caller)"
            $details["Process"] = $process
            $details["PID"] = $f["CallerPID"]
            $details["ProcessAccount"] = $caller
            $details["MechanismOID"] = $f["MechanismOID"]
        }
        8003 {
            $user = Join-EvtxAccountName $f["DomainName"] $f["UserName"]
            $workstation = Get-EvtxFieldValue $f @("Workstation")
            $desc = "NTLM authentication in this domain: $user from $workstation"
            $details["Account"] = $user
            $details["Workstation"] = $workstation
            $details["LogonType"] = $f["LogonType"]
            $details["Process"] = $f["ProcessName"]
            $details["PID"] = $f["CallerPID"]
            $details["MechanismOID"] = $f["MechanismOID"]
        }
        { $_ -in @(8004, 8005, 8006) } {
            $user = Join-EvtxAccountName $f["DomainName"] $f["UserName"]
            $workstation = Get-EvtxFieldValue $f @("WorkstationName")
            $channel = Get-EvtxFieldValue $f @("SChannelName")
            $desc = "NTLM authentication passed to this domain controller: $user from $workstation (secure channel $channel)"
            $details["Account"] = $user
            $details["Workstation"] = $workstation
            $details["SecureChannel"] = $channel
            $details["SecureChannelType"] = $f["SChannelType"]
        }
        { $_ -in @(4020, 4021) } {
            $type = "NetworkConnection"
            $user = Join-EvtxAccountName $f["DomainName"] $f["Username"]
            $target = Get-EvtxFieldValue $f @("TargetMachine", "TargetIP", "TargetService")
            $version = Get-EvtxFieldValue $f @("NtlmVersion")
            $desc = "Outgoing NTLM authentication to $target"
            if ($version) { $desc += " ($version)" }
            $details["Target"] = $target
            $details["TargetIP"] = $f["TargetIP"]
            $details["TargetService"] = $f["TargetService"]
            $details["NtlmVersion"] = $version
            $details["Account"] = $user
            $details["Process"] = $f["ProcessName"]
            $details["PID"] = $f["ProcessPID"]
            $details["Reason"] = $f["NtlmUsageReason"]
            $details["ServiceBinding"] = $f["ServiceBinding"]
            $details["MicStatus"] = $f["Mic Status"]
        }
        { $_ -in @(4022, 4023) } {
            $user = Join-EvtxAccountName $f["DomainName"] $f["Username"]
            $client = Get-EvtxFieldValue $f @("RemoteClientMachine", "ClientIP")
            $version = Get-EvtxFieldValue $f @("NtlmVersion")
            $desc = "Incoming NTLM authentication from $client"
            if ($version) { $desc += " ($version)" }
            $details["Account"] = $user
            $details["ClientMachine"] = $f["RemoteClientMachine"]
            $details["ClientIP"] = $f["ClientIP"]
            $details["NtlmVersion"] = $version
            $details["Process"] = $f["ProcessName"]
            $details["PID"] = $f["ProcessPID"]
            $details["Status"] = $f["Status"]
            $details["ServiceBinding"] = $f["ServiceBinding"]
            $details["MicStatus"] = $f["Mic Status"]
        }
        { $_ -in @(4030, 4031, 4032, 4033) } {
            $user = Join-EvtxAccountName $f["AccountDomain"] $f["AccountName"]
            $client = Get-EvtxFieldValue $f @("AccountMachine")
            $server = Join-EvtxAccountName $f["ServerDomain"] $f["ServerName"]
            $version = Get-EvtxFieldValue $f @("NtlmVersion")
            $desc = if ($id -le 4031) { "NTLM authentication processed by this domain controller: $user" } else { "Forwarded NTLM authentication processed by this domain controller: $user" }
            if ($client) { $desc += " from $client" }
            if ($server) { $desc += " to $server" }
            if ($version) { $desc += " ($version)" }
            $details["Account"] = $user
            $details["ClientMachine"] = $client
            $details["Server"] = $server
            $details["ServerIP"] = $f["ServerIP"]
            $details["ServerOS"] = $f["ServerOS"]
            $details["ForwardedFrom"] = Join-EvtxAccountName $f["ForwarderDomain"] $f["ForwarderName"]
            $details["ForwarderIP"] = $f["ForwarderIP"]
            $details["ForwarderType"] = $f["ForwarderType"]
            $details["NtlmVersion"] = $version
            $details["DomainController"] = $f["DCName"]
            $details["TargetMachine"] = $f["TargetMachine"]
            $details["Status"] = $f["Status"]
            $details["ServiceBinding"] = $f["ServiceBinding"]
            $details["MicStatus"] = $f["Mic Status"]
        }
        default { return }
    }
    Add-TimelineEntry -Timestamp $Record.TimeCreated -Source $FileName -EventType $type `
        -Description $desc -User $user -Details (Format-ArtifactDetails $details) `
        -Artifact "EventLogs" -RawPath $FilePath
}

# Firewall profile bit mask ([MS-FASP] FW_PROFILE_TYPE: 1 Domain, 2 Private,
# 4 Public, 0x7FFFFFFF all) as names; other text as it is
function ConvertFrom-FirewallProfileMask {
    param([string]$Value)
    $mask = 0L
    if (-not [long]::TryParse($Value, [ref]$mask) -or $mask -le 0) { return $Value }
    if ($mask -eq 0x7FFFFFFF) { return "All" }
    return ((@(@(1, "Domain"), @(2, "Private"), @(4, "Public")) | Where-Object { $mask -band $_[0] } | ForEach-Object { $_[1] }) -join ", ")
}

# Microsoft-Windows-Windows Firewall With Advanced Security/Firewall. Earlier
# Windows 10 builds write 2002-2006, 2032 and 2033; later builds and Windows 11
# write the same changes under newer IDs that add an ErrorCode (all are in
# the provider manifest; field names from it and from real records):
#   rule added               2004 / 2071 / 2097   PersistenceChange
#   rule modified            2005 / 2073 / 2099   PersistenceChange
#   rule deleted             2006 / 2052          PersistenceChange
#   all rules deleted        2033 / 2059          SecurityAlert
#   reset to the defaults    2032 / 2060          SecurityAlert
#   profile setting changed  2003 / 2082          SecurityAlert
#   global setting changed   2002 / 2083          SecurityAlert
# A firewall rule is a persistent configuration item, like a service or a Run
# key (an inbound allow rule keeps a port open for remote access, an
# outbound block rule can cut off a security product), so rule changes are
# PersistenceChange. Changes to the firewall as a whole (rules wiped, reset,
# the firewall or its logging turned off, default actions changed) are
# tampering, SecurityAlert, like Defender's protection settings.
# A non-zero ErrorCode means the change was attempted and failed: such rows
# read "Firewall rule add failed (error N): ...", "Firewall reset failed
# (error N)" and so on, and a modify or delete of a rule that does not exist
# (ErrorCode 2: installers try a modify before they add the rule) is only
# counted. Also only counted, as the routine churn of packaged apps at every
# install, update and sign-in (hundreds a week): rule events whose
# ModifyingUser is the firewall service itself (NT SERVICE\mpssvc, the rules
# of Store apps), and the rules declared in app packages (MSIX), which
# svchost.exe adds as SYSTEM with EmbeddedContext
# {78E1CD88-49E3-476E-B926-580E596AD309} or a program under \WindowsApps\ or
# \SystemApps\, and deletes again by the same RuleId or RuleName (or a name
# that is an unresolved package resource, "ms-resource:..." or "@{...}").
function Add-FirewallEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $firewallServiceSid = "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052"
    $packageContext = "{78E1CD88-49E3-476E-B926-580E596AD309}"
    $kinds = @{ 2004 = "added"; 2071 = "added"; 2097 = "added"; 2005 = "modified"; 2073 = "modified"; 2099 = "modified"; 2006 = "deleted"; 2052 = "deleted"
        2033 = "all deleted"; 2059 = "all deleted"; 2032 = "reset"; 2060 = "reset"; 2003 = "profile setting"; 2082 = "profile setting"; 2002 = "global setting"; 2083 = "global setting" }
    $verbs = @{ "added" = "add"; "modified" = "modify"; "deleted" = "delete" }
    # [MS-FASP] FW_DIRECTION, FW_RULE_ACTION, IP protocol numbers, FW_PROFILE_CONFIG, FW_RULE_ORIGIN_TYPE
    $directions = @{ "1" = "Inbound"; "2" = "Outbound" }
    $actions = @{ "1" = "Allow bypass"; "2" = "Block"; "3" = "Allow" }
    $protocols = @{ "1" = "ICMPv4"; "6" = "TCP"; "17" = "UDP"; "58" = "ICMPv6"; "256" = "Any" }
    $settingNames = @{ "1" = "Enable firewall"; "2" = "Disable stealth mode"; "3" = "Shielded (block all inbound)"; "4" = "Disable unicast responses to multicast/broadcast"
        "5" = "Log dropped packets"; "6" = "Log successful connections"; "7" = "Log ignored rules"; "8" = "Log max file size"; "9" = "Log file path"
        "10" = "Disable inbound notifications"; "11" = "Authorized apps allow user preference merge"; "12" = "Global ports allow user preference merge"
        "13" = "Allow local policy merge"; "14" = "Allow local IPsec policy merge"; "15" = "Disabled interfaces"; "16" = "Default outbound action"
        "17" = "Default inbound action"; "18" = "Disable stealth mode IPsec secured packet exemption" }
    $origins = @{ "1" = "Local"; "2" = "Group Policy"; "3" = "Dynamic"; "6" = "MDM"; "8" = "Local (Hyper-V host)"; "9" = "Group Policy (Hyper-V host)"
        "10" = "Dynamic (Hyper-V host)"; "11" = "MDM (Hyper-V host)" }
    $serviceRules = 0
    $packageRules = 0
    $missingRules = 0
    $packageRuleIds = @{}
    $packageRuleNames = @{}
    foreach ($r in @($Records | Sort-Object TimeCreated, RecordId)) {
        $f = Get-EvtxEventFields $r
        $id = [int]$r.Id
        $kind = $kinds[$id]
        if (-not $kind) { continue }
        $modifyingUser = Get-EvtxFieldValue $f @("ModifyingUser")
        $modifyingApp = Get-EvtxFieldValue $f @("ModifyingApplication")
        $ruleId = Get-EvtxFieldValue $f @("RuleId")
        $ruleName = Get-EvtxFieldValue $f @("RuleName")
        $errorCode = Get-EvtxFieldValue $f @("ErrorCode")
        $failed = $errorCode -and $errorCode -ne "0"
        $isRuleEvent = $kind -in @("added", "modified", "deleted", "all deleted")
        if ($isRuleEvent -and $modifyingUser -eq $firewallServiceSid) { $serviceRules++; continue }
        if ($kind -in @("modified", "deleted") -and $errorCode -eq "2") { $missingRules++; continue }
        if ($modifyingUser -eq "S-1-5-18" -and $modifyingApp -match '\\svchost\.exe$') {
            $appPath = Get-EvtxFieldValue $f @("ApplicationPath")
            if ($kind -in @("added", "modified") -and ((Get-EvtxFieldValue $f @("EmbeddedContext")) -eq $packageContext -or $appPath -match '\\(WindowsApps|SystemApps)\\')) {
                if ($ruleId) { $packageRuleIds[$ruleId] = $true }
                if ($ruleName) { $packageRuleNames[$ruleName] = $true }
                $packageRules++
                continue
            }
            if ($kind -eq "deleted" -and (($ruleId -and $packageRuleIds.ContainsKey($ruleId)) -or ($ruleName -and $packageRuleNames.ContainsKey($ruleName)) -or $ruleName -match '^(ms-resource:|@\{)')) {
                $packageRules++
                continue
            }
        }
        $type = "SecurityAlert"
        $details = [ordered]@{ EventID = $id }
        if ($kind -in @("added", "modified", "deleted")) {
            $type = "PersistenceChange"
            $direction = Get-EvtxFieldValue $f @("Direction")
            if ($directions.ContainsKey($direction)) { $direction = $directions[$direction] }
            $action = Get-EvtxFieldValue $f @("Action")
            if ($actions.ContainsKey($action)) { $action = $actions[$action] }
            $protocol = Get-EvtxFieldValue $f @("Protocol")
            if ($protocols.ContainsKey($protocol)) { $protocol = $protocols[$protocol] }
            $profiles = ConvertFrom-FirewallProfileMask (Get-EvtxFieldValue $f @("Profiles"))
            $origin = Get-EvtxFieldValue $f @("Origin")
            if ($origins.ContainsKey($origin)) { $origin = $origins[$origin] }
            $desc = if ($failed) { "Firewall rule $($verbs[$kind]) failed (error $errorCode): $ruleName" } else { "Firewall rule ${kind}: $ruleName" }
            # Deleted-rule events name the rule only
            $shape = (@($direction, $action) | Where-Object { $_ }) -join ", "
            if ($shape -and $kind -ne "deleted") { $desc += " ($shape)" }
            $details["RuleName"] = $ruleName
            $details["RuleId"] = $ruleId
            $details["ApplicationPath"] = $f["ApplicationPath"]
            $details["ServiceName"] = $f["ServiceName"]
            $details["Direction"] = $direction
            $details["Action"] = $action
            $details["Protocol"] = $protocol
            $details["LocalPorts"] = $f["LocalPorts"]
            $details["RemotePorts"] = $f["RemotePorts"]
            $details["RemoteAddresses"] = $f["RemoteAddresses"]
            $details["Profiles"] = $profiles
            $details["Active"] = $(switch ("$($f['Active'])".Trim()) { "1" { "Yes" } "0" { "No" } default { $_ } })
            $details["Origin"] = $origin
            $details["EmbeddedContext"] = $f["EmbeddedContext"]
        }
        elseif ($kind -eq "all deleted") {
            $desc = if ($failed) { "Deleting all firewall rules failed (error $errorCode)" } else { "All firewall rules deleted" }
            $details["StoreType"] = $f["Store Type"]
        }
        elseif ($kind -eq "reset") {
            $desc = if ($failed) { "Firewall reset failed (error $errorCode)" } else { "Firewall reset to its default configuration" }
        }
        else {
            $settingType = Get-EvtxFieldValue $f @("SettingType")
            $value = Get-EvtxFieldValue $f @("SettingValueString", "SettingValueDisplay")
            $change = if ($failed) { "change failed (error $errorCode)" } else { "changed" }
            if ($kind -eq "profile setting") {
                $setting = if ($settingNames.ContainsKey($settingType)) { $settingNames[$settingType] } else { "setting type $settingType" }
                $profiles = ConvertFrom-FirewallProfileMask (Get-EvtxFieldValue $f @("Profiles"))
                $desc = "Firewall setting $change ($profiles profile): $setting = $value"
                $details["Profiles"] = $profiles
            }
            else {
                $setting = "global setting type $settingType"
                $desc = "Firewall global setting ${change}: $setting = $value"
            }
            $details["Setting"] = $setting
            $details["SettingType"] = $settingType
            $details["Value"] = $value
        }
        $details["ModifyingApplication"] = $modifyingApp
        $details["ModifyingUser"] = $modifyingUser
        if ($failed) { $details["ErrorCode"] = $errorCode }
        $user = if ($modifyingUser) { Resolve-BamUser -Sid $modifyingUser -SidNames @{} } else { "" }
        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType $type `
            -Description $desc -User $user -Details (Format-ArtifactDetails $details) `
            -Artifact "EventLogs" -RawPath $FilePath
    }
    if ($serviceRules -gt 0) {
        Log "    Skipped $serviceRules event(s): rules the firewall service adds and removes for packaged (Store) apps (ModifyingUser NT SERVICE\mpssvc)"
    }
    if ($packageRules -gt 0) {
        Log "    Skipped $packageRules event(s): rules declared in app packages (MSIX), added and removed by svchost.exe as SYSTEM"
    }
    if ($missingRules -gt 0) {
        Log "    Skipped $missingRules event(s): attempts to modify or delete a rule that does not exist (ErrorCode 2)"
    }
}

# Microsoft-Windows-Shell-Core/Operational: the commands Explorer starts at
# logon from the Run and RunOnce keys and from Active Setup (fields from the
# manifest and real records). 9705 / 9706 open and close the enumeration of
# a Run or RunOnce key (KeyName, without the hive: HKLM and HKCU both log
# "Software\Microsoft\Windows\CurrentVersion\Run"), 62170 / 62171 start and
# finish a logon task (TaskName; "ActiveSetup" runs the StubPath commands of
# HKLM\Software\Microsoft\Active Setup\Installed Components), 9707 says a
# command was started (Command) and 9708 that Explorer finished with it
# (PID, Command; up to about 30 s after the process started). Each 9707 and
# its 9708, from the same Explorer process, make one row at the 9707 time
# (Execution), named after the key being enumerated, else the Active Setup
# task, else "key unknown". Windows logs only the part of the command line
# after its last backslash (the program file name and its arguments, not
# the folder).
function Add-ShellCoreEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $currentKey = @{}
    $openTasks = @{}
    $pending = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Records | Sort-Object TimeCreated, RecordId)) {
        $f = Get-EvtxEventFields $r
        $explorer = (Get-EvtxSystemIds $r).ProcessId
        $id = [int]$r.Id
        if ($id -eq 9705) { $currentKey[$explorer] = Get-EvtxFieldValue $f @("KeyName"); continue }
        if ($id -eq 9706) { $currentKey.Remove($explorer); continue }
        if ($id -in @(62170, 62171)) {
            $task = Get-EvtxFieldValue $f @("TaskName", "param2")
            if (-not $openTasks.ContainsKey($explorer)) { $openTasks[$explorer] = @{} }
            if ($id -eq 62170) { $openTasks[$explorer][$task] = $true } else { $openTasks[$explorer].Remove($task) }
            continue
        }
        $command = Get-EvtxFieldValue $f @("Command")
        $pendingKey = "$explorer`t$command"
        if ($id -eq 9708 -and $pending.ContainsKey($pendingKey)) {
            $row = $pending[$pendingKey]
            $pending.Remove($pendingKey)
        }
        else {
            $inActiveSetup = $openTasks.ContainsKey($explorer) -and $openTasks[$explorer].ContainsKey("ActiveSetup")
            $row = [PSCustomObject]@{ Record = $r; Command = $command; Key = "$($currentKey[$explorer])"; ActiveSetup = $inActiveSetup; ProcessId = ""; Finished = $null }
            $rows.Add($row)
            if ($id -eq 9707) { $pending[$pendingKey] = $row }
        }
        if ($id -eq 9708) {
            $row.ProcessId = Get-EvtxFieldValue $f @("PID")
            $row.Finished = $r.TimeCreated
        }
    }
    foreach ($row in $rows) {
        $r = $row.Record
        $registryKey = $row.Key
        $hive = ""
        $task = ""
        if ($row.Key -match '\\RunOnce$') { $desc = "RunOnce key command started at logon"; $hive = "HKLM or HKCU" }
        elseif ($row.Key -match '\\Run$') { $desc = "Run key command started at logon"; $hive = "HKLM or HKCU" }
        elseif ($row.ActiveSetup) {
            $desc = "Active Setup command started at logon"
            $registryKey = "Software\Microsoft\Active Setup\Installed Components"
            $hive = "HKLM"
            $task = "ActiveSetup"
        }
        else { $desc = "Command started at logon (key unknown)" }
        $details = [ordered]@{
            EventID     = [int]$r.Id
            Command     = $row.Command
            ProcessId   = $row.ProcessId
            RegistryKey = $registryKey
            Hive        = $hive
            LogonTask   = $task
            Finished    = $(if ($null -ne $row.Finished -and [int]$r.Id -eq 9707) { ([datetime]$row.Finished).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) } else { "" })
            UserSID     = "$($r.UserId)"
        }
        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType "Execution" `
            -Description "${desc}: $($row.Command)" -User (Resolve-BamUser -Sid "$($r.UserId)" -SidNames @{}) `
            -Details (Format-ArtifactDetails $details) -Artifact "EventLogs" -RawPath $FilePath
    }
}

# OAlerts.evtx: event 300 of "Microsoft Office <version> Alerts" (classic
# log, unnamed values; message "%1 | %2 | P1: %3 | P2: %4 | P3: %5 | P4: %6").
# Two kinds, told apart by their values (checked on real records):
#   alerts (dialog boxes) shown by Office applications: %1 the application,
#   %2 the alert text (for example a macro, Protected View or "save
#   changes" prompt), P1 an alert ID, P2 the Office version, P3 an error
#   code and P4 the document: "Office alert (<application>): <text>"
#   events of Office add-ins ("Apps for Office" in P1, or %2 the add-in as
#   "Id=..., DisplayName=..., ..."): %1 what happened ("Activated App",
#   "Failed to parse element: ..."), P3 an error code, P4 the open document:
#   "Office add-in event (<what>): <add-in name>"
# Both Execution: the user had the application or document open. User is
# the account the Office application ran as (the record's own UserID, also
# kept as UserSID). Events with fewer than three values (Office diagnostics
# such as "Compositor Type: 1") are neither and are only counted.
function Add-OfficeAlertEntries {
    param([object[]]$Records, [string]$FileName, [string]$FilePath)
    $skipped = 0
    foreach ($r in @($Records | Sort-Object TimeCreated, RecordId)) {
        $f = Get-EvtxEventFields $r
        $values = @(1..6 | ForEach-Object { Get-EvtxFieldValue $f @("param$_") })
        $count = @($f.Keys | Where-Object { $_ -like "param*" }).Count
        $message = ($values[1] -replace '\s+', ' ').Trim()
        if ($count -lt 3 -or -not $message) { $skipped++; continue }
        if ($values[2] -eq "Apps for Office" -or $message -match '^Id=[^,]*, DisplayName=') {
            $addIn = if ($message -match 'DisplayName=([^,]*)') { $Matches[1].Trim() } else { "" }
            if (-not $addIn) { $addIn = Get-EvtxShortText $message 200 }
            $details = [ordered]@{
                EventID   = [int]$r.Id
                Event     = $values[0]
                AddIn     = Get-EvtxShortText $message 1000
                Component = $values[2]
                Version   = $values[3]
                ErrorCode = $values[4]
                Document  = $values[5]
                UserSID   = "$($r.UserId)"
            }
            $desc = "Office add-in event ($($values[0])): $addIn"
        }
        else {
            $details = [ordered]@{
                EventID     = [int]$r.Id
                Application = $values[0]
                Message     = Get-EvtxShortText $message 1000
                P1          = $values[2]
                Version     = $values[3]
                P3          = $values[4]
                Document    = $values[5]
                UserSID     = "$($r.UserId)"
            }
            $desc = "Office alert ($($values[0])): $(Get-EvtxShortText $message 200)"
        }
        Add-TimelineEntry -Timestamp $r.TimeCreated -Source $FileName -EventType "Execution" `
            -Description $desc -User (Resolve-BamUser -Sid "$($r.UserId)" -SidNames @{}) `
            -Details (Format-ArtifactDetails $details) -Artifact "EventLogs" -RawPath $FilePath
    }
    if ($skipped -gt 0) { Log "    Skipped $skipped event(s): Office diagnostics that are not alerts (fewer than three values)" }
}

function Parse-EventLogs {
    Log "--- Parsing Event Logs ---"
    $evtxFiles = Find-ArtifactFiles -BasePath $InputPath -Extensions @(".evtx")

    if ($evtxFiles.Count -eq 0) {
        Log-Warning "No event log files found. Skipping event log parsing."
    }
    else {
        Log "Found $($evtxFiles.Count) event log file(s)"
    }

    # Defender 5007 "configuration changed": only exclusions and protection
    # settings are security-relevant; the rest is routine engine housekeeping
    $defenderTamperPattern = '\\Exclusions\\|\\Real-Time Protection\\|TamperProtection|PUAProtection|Exploit Guard\\|\\Threats\\|\\Policies\\Microsoft\\Windows Defender|\\SpyNet\\(SpyNetReporting|SubmitSamplesConsent)\b|\\Disable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|OnAccessProtection|ScanOnRealtimeEnable|IntrusionPreventionSystem|BlockAtFirstSeen|ScriptScanning|ArchiveScanning|RemovableDriveScanning|EmailScanning|RoutinelyTakingAction)\b'

    foreach ($evtxFile in $evtxFiles) {
        $fileName = $evtxFile.Name
        $filePath = $evtxFile.FullName
        # Channel name from the exported file name, matched exactly below
        # (e.g. "Microsoft-Windows-PowerShell%4Operational.evtx")
        $logName = ($fileName -replace '\.evtx$', '') -replace '%4', '/'
        $entriesBefore = $script:timelineEntries.Count
        Log "  Parsing: $fileName"

        try {
            # Determine which events to look for based on the log name
            $events = @()

            # Security log events (the IDs after 4726 are handled by Add-SecurityEventEntry)
            if ($logName -eq "Security") {
                $targetIds = @(4624, 4625, 4648, 4672, 4688, 4720, 4726,
                    1102, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4724, 4728, 4732, 4740, 4756, 4778, 4779)
                $events = @(Get-EvtxEventsById -Path $filePath -Ids $targetIds -Label "Security")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                # Group adds give a local member's SID only: name it from the other events
                $sidNames = @{}
                if (@($events | Where-Object { $_.Id -in @(4728, 4732, 4756) }).Count -gt 0) { $sidNames = Get-SecuritySidNames -Records $events }

                foreach ($evt in $events) {
                    $xmlData = [xml]$evt.ToXml()
                    $eventData = @{}
                    if ($xmlData.Event.EventData.Data) {
                        foreach ($d in $xmlData.Event.EventData.Data) {
                            if ($d.Name) { $eventData[$d.Name] = $d.'#text' }
                        }
                    }

                    switch ($evt.Id) {
                        4624 {
                            $logonType = $eventData["LogonType"]
                            $logonTypeDesc = switch ($logonType) {
                                "2"  { "Interactive" }
                                "3"  { "Network" }
                                "4"  { "Batch" }
                                "5"  { "Service" }
                                "7"  { "Unlock" }
                                "8"  { "NetworkCleartext" }
                                "9"  { "NewCredentials" }
                                "10" { "RemoteInteractive (RDP)" }
                                "11" { "CachedInteractive" }
                                default { "Type $logonType" }
                            }
                            # The authentication package fields: LmPackageName "NTLM V1" is
                            # an NTLMv1 logon; KeyLength is the session key length
                            $logonDetails = [ordered]@{
                                LogonType                 = $logonType
                                Source                    = "$($eventData['IpAddress']):$($eventData['IpPort'])"
                                LogonID                   = $eventData['TargetLogonId']
                                IpAddress                 = Get-EvtxFieldValue $eventData @("IpAddress")
                                WorkstationName           = Get-EvtxFieldValue $eventData @("WorkstationName")
                                AuthenticationPackageName = Get-EvtxFieldValue $eventData @("AuthenticationPackageName")
                                LmPackageName             = Get-EvtxFieldValue $eventData @("LmPackageName")
                                KeyLength                 = Get-EvtxFieldValue $eventData @("KeyLength")
                            }
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Successful logon ($logonTypeDesc)" `
                                -User (Join-EvtxAccountName $eventData['TargetDomainName'] $eventData['TargetUserName']) `
                                -Details (Format-ArtifactDetails $logonDetails) `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4625 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Failed logon attempt (Status=$($eventData['Status']))" `
                                -User (Join-EvtxAccountName $eventData['TargetDomainName'] $eventData['TargetUserName']) `
                                -Details "FailureReason=$($eventData['SubStatus']) Source=$($eventData['IpAddress'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4648 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Logon using explicit credentials" `
                                -User (Join-EvtxAccountName $eventData['SubjectDomainName'] $eventData['SubjectUserName']) `
                                -Details "TargetUser=$($eventData['TargetDomainName'])\$($eventData['TargetUserName']) TargetServer=$($eventData['TargetServerName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4672 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Special privileges assigned to new logon" `
                                -User (Join-EvtxAccountName $eventData['SubjectDomainName'] $eventData['SubjectUserName']) `
                                -Details "Privileges=$($eventData['PrivilegeList'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4688 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ProcessCreation" `
                                -Description "New process created: $($eventData['NewProcessName'])" `
                                -User (Join-EvtxAccountName $eventData['SubjectDomainName'] $eventData['SubjectUserName']) `
                                -Details "CommandLine=$($eventData['CommandLine']) ParentProcess=$($eventData['ParentProcessName']) PID=$($eventData['NewProcessId'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4720 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "AccountChange" `
                                -Description "User account created: $($eventData['TargetUserName'])" `
                                -User (Join-EvtxAccountName $eventData['SubjectDomainName'] $eventData['SubjectUserName']) `
                                -Details (Format-ArtifactDetails ([ordered]@{ NewAccount = "$($eventData['TargetDomainName'])\$($eventData['TargetUserName'])"; AccountSID = $eventData['TargetSid'] })) `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4726 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "AccountChange" `
                                -Description "User account deleted: $($eventData['TargetUserName'])" `
                                -User (Join-EvtxAccountName $eventData['SubjectDomainName'] $eventData['SubjectUserName']) `
                                -Details (Format-ArtifactDetails ([ordered]@{ DeletedAccount = "$($eventData['TargetDomainName'])\$($eventData['TargetUserName'])"; AccountSID = $eventData['TargetSid'] })) `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        default {
                            Add-SecurityEventEntry -Record $evt -FileName $fileName -FilePath $filePath -SidNames $sidNames
                        }
                    }
                }
            }

            # System log events (104, 6005 and 6006 are handled by Add-SystemEventEntry)
            if ($logName -eq "System") {
                $targetIds = @(7034, 7036, 7040, 7045, 1074, 6008, 104, 6005, 6006)
                $events = @(Get-EvtxEventsById -Path $filePath -Ids $targetIds -Label "System")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }

                foreach ($evt in $events) {
                    $xmlData = [xml]$evt.ToXml()
                    $eventData = @{}
                    if ($xmlData.Event.EventData.Data) {
                        foreach ($d in $xmlData.Event.EventData.Data) {
                            if ($d.Name) { $eventData[$d.Name] = $d.'#text' }
                            else { $eventData["param$($eventData.Count + 1)"] = $d.'#text' }
                        }
                    }

                    switch ($evt.Id) {
                        7034 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ServiceChange" `
                                -Description "Service crashed unexpectedly: $($eventData['param1'])" `
                                -Details "CrashCount=$($eventData['param2'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        7036 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ServiceChange" `
                                -Description "Service state changed: $($eventData['param1']) -> $($eventData['param2'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        7040 {
                            # param1 display name, param2/param3 old/new start type, param4 service (key) name
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ServiceChange" `
                                -Description "Service start type changed: $($eventData['param1'])" `
                                -Details (Format-ArtifactDetails ([ordered]@{ Service = $eventData['param4']; OldType = $eventData['param2']; NewType = $eventData['param3'] })) `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        7045 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "PersistenceChange" `
                                -Description "New service installed: $($eventData['ServiceName'])" `
                                -User $eventData['AccountName'] `
                                -Details (Format-ArtifactDetails ([ordered]@{ ImagePath = $eventData['ImagePath']; StartType = $eventData['StartType'] })) `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        1074 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ServiceChange" `
                                -Description "System shutdown/restart initiated" `
                                -User $eventData['param7'] `
                                -Details "Process=$($eventData['param1']) Reason=$($eventData['param3'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        6008 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ServiceChange" `
                                -Description "Unexpected shutdown detected" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        default {
                            Add-SystemEventEntry -Record $evt -FileName $fileName -FilePath $filePath
                        }
                    }
                }
            }

            # PowerShell Operational log
            if ($logName -eq "Microsoft-Windows-PowerShell/Operational") {
                $targetIds = @(4103, 4104)
                try {
                    $events = Get-WinEvent -Path $filePath -FilterXPath (
                        "*[System[(" + (($targetIds | ForEach-Object { "EventID=$_" }) -join " or ") + ")]]"
                    ) -ErrorAction Stop
                }
                catch [Exception] {
                    if ($_.Exception.Message -notmatch "No events were found") {
                        Log-Warning "    Error reading PowerShell events from $fileName : $($_.Exception.Message)"
                    }
                }

                foreach ($evt in $events) {
                    $xmlData = [xml]$evt.ToXml()
                    $eventData = @{}
                    if ($xmlData.Event.EventData.Data) {
                        foreach ($d in $xmlData.Event.EventData.Data) {
                            if ($d.Name) { $eventData[$d.Name] = $d.'#text' }
                        }
                    }

                    # The account is the event's own UserID (a SID; the User
                    # column pass names it): 4104 has no user field, and 4103
                    # has the user only inside its ContextInfo text
                    switch ($evt.Id) {
                        4104 {
                            $scriptBlock = $eventData['ScriptBlockText']
                            if ($scriptBlock.Length -gt 500) { $scriptBlock = $scriptBlock.Substring(0, 500) + "..." }
                            # Path: the script file; empty for a command typed or passed with -Command
                            $details = "ScriptBlock=$scriptBlock ScriptBlockId=$($eventData['ScriptBlockId'])"
                            if ($eventData['Path']) { $details += " Path=$($eventData['Path'])" }
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Execution" `
                                -Description "PowerShell script block executed" `
                                -User "$($evt.UserId)" `
                                -Details $details `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4103 {
                            $payload = $eventData['Payload']
                            if ($payload -and $payload.Length -gt 500) { $payload = $payload.Substring(0, 500) + "..." }
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Execution" `
                                -Description "PowerShell module logging event" `
                                -User "$($evt.UserId)" `
                                -Details "Payload=$payload" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                    }
                }
            }

            # Sysmon log
            if ($logName -eq "Microsoft-Windows-Sysmon/Operational") {
                $targetIds = @(1, 3, 7, 11, 13)
                try {
                    $events = Get-WinEvent -Path $filePath -FilterXPath (
                        "*[System[(" + (($targetIds | ForEach-Object { "EventID=$_" }) -join " or ") + ")]]"
                    ) -ErrorAction Stop
                }
                catch [Exception] {
                    if ($_.Exception.Message -notmatch "No events were found") {
                        Log-Warning "    Error reading Sysmon events from $fileName : $($_.Exception.Message)"
                    }
                }

                foreach ($evt in $events) {
                    $xmlData = [xml]$evt.ToXml()
                    $eventData = @{}
                    if ($xmlData.Event.EventData.Data) {
                        foreach ($d in $xmlData.Event.EventData.Data) {
                            if ($d.Name) { $eventData[$d.Name] = $d.'#text' }
                        }
                    }

                    switch ($evt.Id) {
                        1 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ProcessCreation" `
                                -Description "Sysmon: Process created: $($eventData['Image'])" `
                                -User $eventData['User'] `
                                -Details "CommandLine=$($eventData['CommandLine']) ParentImage=$($eventData['ParentImage']) Hashes=$($eventData['Hashes'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        3 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "NetworkConnection" `
                                -Description "Sysmon: Network connection by $($eventData['Image'])" `
                                -User $eventData['User'] `
                                -Details "Dest=$($eventData['DestinationIp']):$($eventData['DestinationPort']) Protocol=$($eventData['Protocol']) DestHostname=$($eventData['DestinationHostname'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        7 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Execution" `
                                -Description "Sysmon: Image loaded by $($eventData['Image'])" `
                                -User $eventData['User'] `
                                -Details "ImageLoaded=$($eventData['ImageLoaded']) Hashes=$($eventData['Hashes']) Signed=$($eventData['Signed'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        11 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "FileAccess" `
                                -Description "Sysmon: File created: $($eventData['TargetFilename'])" `
                                -User $eventData['User'] `
                                -Details "Process=$($eventData['Image'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        13 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "PersistenceChange" `
                                -Description "Sysmon: Registry value set: $($eventData['TargetObject'])" `
                                -User $eventData['User'] `
                                -Details "Process=$($eventData['Image']) Details=$($eventData['Details'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                    }
                }
            }

            # Task Scheduler Operational log
            if ($logName -eq "Microsoft-Windows-TaskScheduler/Operational") {
                $targetIds = @(106, 140, 141)
                try {
                    $events = Get-WinEvent -Path $filePath -FilterXPath (
                        "*[System[(" + (($targetIds | ForEach-Object { "EventID=$_" }) -join " or ") + ")]]"
                    ) -ErrorAction Stop
                }
                catch [Exception] {
                    if ($_.Exception.Message -notmatch "No events were found") {
                        Log-Warning "    Error reading TaskScheduler events from $fileName : $($_.Exception.Message)"
                    }
                }

                foreach ($evt in $events) {
                    $xmlData = [xml]$evt.ToXml()
                    $eventData = @{}
                    if ($xmlData.Event.EventData.Data) {
                        foreach ($d in $xmlData.Event.EventData.Data) {
                            if ($d.Name) { $eventData[$d.Name] = $d.'#text' }
                            else { $eventData["param$($eventData.Count + 1)"] = $d.'#text' }
                        }
                    }

                    switch ($evt.Id) {
                        106 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ScheduledTaskChange" `
                                -Description "Scheduled task registered: $($eventData['TaskName'])" `
                                -User $eventData['UserContext'] `
                                -Details "TaskName=$($eventData['TaskName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        140 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ScheduledTaskChange" `
                                -Description "Scheduled task updated: $($eventData['TaskName'])" `
                                -User $eventData['UserContext'] `
                                -Details "TaskName=$($eventData['TaskName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        141 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ScheduledTaskChange" `
                                -Description "Scheduled task deleted: $($eventData['TaskName'])" `
                                -User $eventData['UserContext'] `
                                -Details "TaskName=$($eventData['TaskName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                    }
                }
            }

            # Console / RDP sessions (TerminalServices LocalSessionManager)
            if ($logName -eq "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(21, 22, 23, 24, 25) -Label "TerminalServices")
                foreach ($evt in $events) {
                    $f = Get-EvtxEventFields $evt
                    $what = switch ($evt.Id) {
                        21 { "session logon succeeded" }
                        22 { "shell start notification" }
                        23 { "session logoff succeeded" }
                        24 { "session disconnected" }
                        25 { "session reconnection succeeded" }
                    }
                    # Address is "LOCAL" for console sessions, else the RDP client IP
                    $address = $f["Address"]
                    $origin = if ($address -eq "LOCAL") { ", console" } elseif ($address) { ", from $address" } else { "" }
                    Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                        -Description "Remote Desktop Services: $what (session $($f['SessionID'])$origin)" `
                        -User $f["User"] `
                        -Details (Format-ArtifactDetails ([ordered]@{ EventID = $evt.Id; SessionID = $f["SessionID"]; Address = $address })) `
                        -Artifact "EventLogs" -RawPath $filePath
                }
            }

            # RDP network authentication (TerminalServices RemoteConnectionManager)
            if ($logName -eq "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(1149) -Label "TerminalServices")
                foreach ($evt in $events) {
                    # UserData Param1 = user, Param2 = domain, Param3 = source address
                    $f = Get-EvtxEventFields $evt
                    $rdpUser = (@($f["Param2"], $f["Param1"]) | Where-Object { $_ }) -join "\"
                    Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                        -Description "RDP user authentication succeeded from $($f['Param3'])" `
                        -User $rdpUser `
                        -Details (Format-ArtifactDetails ([ordered]@{ EventID = $evt.Id; SourceIP = $f["Param3"] })) `
                        -Artifact "EventLogs" -RawPath $filePath
                }
            }

            # Windows Defender Operational log: detections and protection tampering
            if ($logName -eq "Microsoft-Windows-Windows Defender/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(1006, 1007, 1008, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012, 5013, 1013, 1121, 1122) -Label "Defender")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                $routineConfig = 0
                $asrAudits = New-Object System.Collections.Generic.List[object]
                foreach ($evt in $events) {
                    $f = Get-EvtxEventFields $evt
                    $id = $evt.Id
                    if ($id -eq 1122) {
                        # Attack surface reduction audits are folded after the loop
                        $asrAudits.Add([PSCustomObject]@{ Record = $evt; Fields = $f })
                    }
                    elseif ($id -eq 5007) {
                        $old = ("$($f['Old Value'])".Trim()) -replace '\s+', ' '
                        $new = ("$($f['New Value'])".Trim()) -replace '\s+', ' '
                        if ("$old $new" -notmatch $defenderTamperPattern) { $routineConfig++; continue }
                        # Values read "<registry path> = <data>"; the path names the setting
                        $setting = if ($new) { $new } else { $old }
                        $eq = $setting.IndexOf(" = ")
                        if ($eq -gt 0) { $setting = $setting.Substring(0, $eq) }
                        if ($setting -match '\\Exclusions\\([^\\]+)\\(.+)$') {
                            $change = if ($new -and -not $old) { "added" } elseif ($old -and -not $new) { "removed" } else { "changed" }
                            $desc = "Defender exclusion $change ($($Matches[1])): $($Matches[2])"
                        }
                        else {
                            $desc = "Defender protection setting changed: $($setting -replace '^.*?\\Windows Defender\\', '')"
                        }
                        Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "SecurityAlert" `
                            -Description $desc `
                            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $id; Old = $old; New = $new })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                    elseif ($id -in @(5001, 5010, 5012)) {
                        $desc = switch ($id) {
                            5001 { "Defender real-time protection disabled" }
                            5010 { "Defender scanning for spyware and unwanted software disabled" }
                            5012 { "Defender scanning for viruses disabled" }
                        }
                        Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "SecurityAlert" `
                            -Description $desc `
                            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $id; ProductVersion = $f["Product Version"] })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                    elseif ($id -eq 5013) {
                        Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "SecurityAlert" `
                            -Description "Defender Tamper Protection $($f['Changed Type']) a change: $($f['Value'])" `
                            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $id; Setting = $f["Value"] })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                    elseif ($id -in @(1013, 1121)) {
                        # Malware history deleted, attack surface reduction rule blocked
                        Add-DefenderEventEntry -Record $evt -Fields $f -FileName $fileName -FilePath $filePath
                    }
                    else {
                        # Detections (1006/1116), actions taken (1007/1117) and failures (1008/1118/1119)
                        $threat = $f["Threat Name"]
                        $action = (@($f["Action Name"], $f["Cleaning Action"]) | Where-Object { $_ } | Select-Object -First 1)
                        $desc = switch ($id) {
                            { $_ -in @(1006, 1116) } { "Defender detected threat: $threat" }
                            { $_ -in @(1007, 1117) } { "Defender action taken on threat: $threat ($action)" }
                            { $_ -in @(1008, 1118) } { "Defender action failed on threat: $threat" }
                            1119 { "Defender critical error acting on threat: $threat" }
                        }
                        $threatUser = $f["Detection User"]
                        if (-not $threatUser) { $threatUser = (@($f["Domain"], $f["User"]) | Where-Object { $_ }) -join "\" }
                        Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "SecurityAlert" `
                            -Description $desc `
                            -User $threatUser `
                            -Details (Format-ArtifactDetails ([ordered]@{
                                EventID     = $id
                                Path        = (@($f["Path"], $f["Path Found"]) | Where-Object { $_ } | Select-Object -First 1)
                                Action      = $action
                                Severity    = $f["Severity Name"]
                                Category    = $f["Category Name"]
                                Process     = $f["Process Name"]
                                Status      = $f["Status Description"]
                                Error       = $f["Error Description"]
                                DetectionID = $f["Detection ID"]
                            })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                }
                if ($asrAudits.Count -gt 0) {
                    Add-DefenderAsrAuditEntries -Items $asrAudits.ToArray() -FileName $fileName -FilePath $filePath
                }
                if ($routineConfig -gt 0) {
                    Log "    Skipped $routineConfig routine Defender configuration change(s) (event 5007)"
                }
            }

            # BITS Client Operational log: background downloads / uploads
            if ($logName -eq "Microsoft-Windows-Bits-Client/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(3, 59, 60) -Label "BITS")
                foreach ($evt in $events) {
                    $f = Get-EvtxEventFields $evt
                    if ($evt.Id -eq 3) {
                        Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "NetworkConnection" `
                            -Description "BITS job created: $($f['jobTitle'])" `
                            -User $f["jobOwner"] `
                            -Details (Format-ArtifactDetails ([ordered]@{ EventID = 3; JobId = $f["jobId"]; Process = $f["processPath"]; PID = $f["processId"] })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                    else {
                        # hr is the transfer result as a signed decimal HRESULT
                        $hr = $f["hr"]
                        $hrValue = 0
                        if ($hr -and [int]::TryParse($hr, [ref]$hrValue)) { $hr = "0x{0:X8}" -f $hrValue }
                        $what = if ($evt.Id -eq 59) { "started" } else { "stopped" }
                        Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "NetworkConnection" `
                            -Description "BITS transfer ${what}: $($f['name']) -> $($f['url'])" `
                            -User "$($evt.UserId)" `
                            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $evt.Id; JobId = $f["Id"]; Url = $f["url"]; Result = $hr; BytesTransferred = $f["bytesTransferred"]; BytesTotal = $f["bytesTotal"]; UserSID = $evt.UserId })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                }
            }

            # Application log: installs, crashes, Security Center, ESE databases
            # and third-party antivirus (see Add-ApplicationEventEntries). The
            # log is large, so only these providers and IDs are read.
            if ($logName -eq "Application") {
                $queries = @(
                    @{ Label = "MsiInstaller"; Providers = @("MsiInstaller"); Ids = @(1033, 1034, 11707, 11724) },
                    @{ Label = "Application Error"; Providers = @("Application Error"); Ids = @(1000) },
                    @{ Label = "Application Hang"; Providers = @("Application Hang"); Ids = @(1002) },
                    @{ Label = "SecurityCenter"; Providers = @("SecurityCenter"); Ids = @(15, 16) },
                    @{ Label = "ESENT"; Providers = @("ESENT"); Ids = @(216, 325, 326, 327) },
                    @{ Label = "antivirus"; Providers = $script:ThirdPartyAvProviders; Ids = @() }
                )
                $events = @()
                # A damaged file is reported once, not once per query
                $readState = @{ Failed = $false }
                foreach ($query in $queries) {
                    $events += @(Get-EvtxEventsById -Path $filePath -Ids $query.Ids -Providers $query.Providers -Label $query.Label -State $readState)
                }
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events -ByProvider)" }
                Add-ApplicationEventEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # Windows PowerShell (classic log): engine start and stop, and the
            # pipeline details (see Add-WindowsPowerShellEntries)
            if ($logName -eq "Windows PowerShell") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(400, 403, 800) -Label "Windows PowerShell")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                Add-WindowsPowerShellEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # WMI activity: permanent and temporary event subscriptions; the
            # routine 5857-5859 are read only to be counted
            if ($logName -eq "Microsoft-Windows-WMI-Activity/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(5857, 5858, 5859, 5860, 5861) -Label "WMI-Activity")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                Add-WmiActivityEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # Outbound RDP connections (Remote Desktop client)
            if ($logName -eq "Microsoft-Windows-TerminalServices-RDPClient/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(1024, 1025, 1102, 1027, 1029, 1009, 1026) -Label "RDPClient")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                Add-RdpClientEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # NTLM authentication auditing
            if ($logName -eq "Microsoft-Windows-NTLM/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(8001, 8002, 8003, 8004, 8005, 8006, 4013, 4020, 4021, 4022, 4023, 4024, 4030, 4031, 4032, 4033) -Label "NTLM")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                foreach ($evt in $events) { Add-NtlmEventEntry -Record $evt -FileName $fileName -FilePath $filePath }
            }

            # Windows Firewall rule and setting changes
            if ($logName -eq "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(2004, 2071, 2097, 2005, 2073, 2099, 2006, 2052, 2033, 2059, 2032, 2060, 2003, 2082, 2002, 2083) -Label "Firewall")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                Add-FirewallEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # Run / RunOnce and Active Setup commands started by Explorer at logon
            if ($logName -eq "Microsoft-Windows-Shell-Core/Operational") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(9705, 9706, 9707, 9708, 62170, 62171) -Label "Shell-Core")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                Add-ShellCoreEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # Office alerts (dialog boxes shown by Office applications) and add-in events
            if ($logName -eq "OAlerts") {
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(300) -Label "OAlerts")
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events)" }
                Add-OfficeAlertEntries -Records $events -FileName $fileName -FilePath $filePath
            }

            # A third-party antivirus product's own event log, collected under
            # AntiVirus\ (Symantec_SEP_EventLog.evtx, CrowdStrike_EventLog.evtx):
            # every event, through the antivirus filter (Add-AntiVirusLogEntries)
            if ($evtxFile.Directory -and $evtxFile.Directory.Name -eq "AntiVirus") {
                $events = @()
                try { $events = @(Get-WinEvent -Path $filePath -FilterXPath "*" -ErrorAction Stop) }
                catch {
                    if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound*" -and $_.Exception.Message -notmatch "No events were found") {
                        Log-Warning "    Error reading antivirus events from $fileName : $($_.Exception.Message)"
                    }
                }
                if ($events.Count -gt 0) { Log "    Events read: $(Format-EvtxEventCounts $events -ByProvider)" }
                Add-AntiVirusLogEntries -Records $events -FileName $fileName -FilePath $filePath
            }

        }
        catch {
            Log-Warning "  Failed to parse $fileName : $($_.Exception.Message)"
        }

        $added = $script:timelineEntries.Count - $entriesBefore
        if ($added -gt 0) { Log "    Added $added timeline entries" }
    }

    # Defender detection history written by the collector (Get-MpThreatDetection).
    # Its times are local [datetime] values that Export-Csv wrote as text on
    # the collector host.
    $threatStatusNames = $script:DefenderThreatStatusNames
    # Get-MpThreatDetection has no threat name: it comes from the Get-MpThreat catalog
    $threatCatalog = Get-DefenderThreatCatalog
    $detectionCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("defender_detections.csv")
    foreach ($csv in $detectionCsvs) {
        Log "  Parsing: $($csv.Name)"
        try {
            # A collection without detections holds only a text placeholder line
            $detections = @(Import-Csv -Path $csv.FullName -ErrorAction Stop | Where-Object { $_.PSObject.Properties["ThreatName"] -or $_.PSObject.Properties["ThreatID"] })
            if ($detections.Count -eq 0) {
                Log "    No Defender detections recorded."
                continue
            }
            $entriesBefore = $script:timelineEntries.Count
            foreach ($det in $detections) {
                $threatId = Get-ArtifactRowValue $det @("ThreatID")
                $known = $threatCatalog["id:$threatId"]
                $threat = Get-ArtifactRowValue $det @("ThreatName")
                if (-not $threat -and $known) { $threat = $known.Name }
                if (-not $threat) { $threat = "ThreatID $threatId" }
                $statusId = Get-ArtifactRowValue $det @("ThreatStatusID")
                $status = if ($threatStatusNames.ContainsKey($statusId)) { $threatStatusNames[$statusId] } else { $statusId }
                $details = Format-ArtifactDetails ([ordered]@{
                    Resources   = Get-ArtifactRowValue $det @("Resources")
                    Process     = Get-ArtifactRowValue $det @("ProcessName")
                    Status      = $status
                    Severity    = $(if ($known) { $known.Severity } else { "" })
                    CategoryID  = $(if ($known) { $known.CategoryID } else { "" })
                    DetectionID = Get-ArtifactRowValue $det @("DetectionID")
                    ThreatID    = $threatId
                })
                $detUser = Get-ArtifactRowValue $det @("DomainUser")
                $times = [ordered]@{
                    "Defender detection: $threat"                       = Get-ArtifactRowValue $det @("InitialDetectionTime")
                    "Defender threat status changed: $threat ($status)" = Get-ArtifactRowValue $det @("LastThreatStatusChangeTime")
                    "Defender remediation: $threat ($status)"           = Get-ArtifactRowValue $det @("RemediationTime")
                }
                $used = @{}
                foreach ($desc in $times.Keys) {
                    $utc = ConvertFrom-CollectorTimeText $times[$desc]
                    if (-not $utc -or $used.ContainsKey($utc)) { continue }
                    $used[$utc] = $true
                    Add-TimelineEntry -Timestamp $utc -Source $csv.Name -EventType "SecurityAlert" `
                        -Description $desc -User $detUser -Details $details `
                        -Artifact "AntiVirus" -RawPath $csv.FullName
                }
                if ($used.Count -eq 0) {
                    $snapshotTs = Get-SnapshotTimeUtc -File $csv
                    if ($snapshotTs) {
                        Add-TimelineEntry -Timestamp $snapshotTs -Source $csv.Name -EventType "Snapshot" `
                            -Description "Defender detection on record (time unknown): $threat" -User $detUser -Details $details `
                            -Artifact "AntiVirus" -RawPath $csv.FullName
                    }
                }
            }
            Log "    Added $($script:timelineEntries.Count - $entriesBefore) timeline entries"
        }
        catch {
            Log-Warning "  Failed to parse Defender detections: $($_.Exception.Message)"
        }
    }

    # Defender support logs (ProgramData\Microsoft\Windows Defender\Support),
    # MPLog files first (in time order) so detections they share with
    # MPDetection keep the file hash. MPDeviceControl / MPScanSkip logs hold no
    # detection or configuration lines and are not read.
    $supportLogs = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("MPLog-*.log") | Sort-Object Name) +
        @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("MPDetection-*.log") | Sort-Object Name)
    $supportState = @{ Seen = @{}; Sha = @{}; ExclusionSize = $null; Exclusions = $null; ExclusionListTime = $null; RtpOff = $false }
    foreach ($supportLog in $supportLogs) {
        Log "  Parsing: $($supportLog.Name)"
        try {
            $added = Read-DefenderSupportLog -File $supportLog -State $supportState -Catalog $threatCatalog
            Log "    Added $added timeline entries"
        }
        catch {
            Log-Warning "  Failed to parse Defender support log $($supportLog.Name): $($_.Exception.Message)"
        }
    }

    Log "  Event log parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 2. Prefetch Parser
# ----------------------------------------------------------
# Windows 10/11 prefetch files are compressed: "MAM" + format byte (low
# nibble 4 = XPRESS Huffman, 0x80 = CRC32 present), uint32 uncompressed
# size, then the data. ntdll's RtlDecompressBufferEx unpacks them.
function Initialize-PrefetchDecompressor {
    if ($null -ne $script:prefetchXpressReady) { return $script:prefetchXpressReady }
    $script:prefetchXpressReady = $false
    try {
        if (-not ([System.Management.Automation.PSTypeName]'TimelineNative.Xpress').Type) {
            Add-Type -Namespace TimelineNative -Name Xpress -ErrorAction Stop -MemberDefinition @'
[DllImport("ntdll.dll")]
public static extern uint RtlGetCompressionWorkSpaceSize(ushort CompressionFormatAndEngine, out uint CompressBufferWorkSpaceSize, out uint CompressFragmentWorkSpaceSize);
[DllImport("ntdll.dll")]
public static extern uint RtlDecompressBufferEx(ushort CompressionFormat, byte[] UncompressedBuffer, int UncompressedBufferSize, byte[] CompressedBuffer, int CompressedBufferSize, out int FinalUncompressedSize, byte[] WorkSpace);
'@
        }
        $bufferSize = [uint32]0
        $fragmentSize = [uint32]0
        $status = [TimelineNative.Xpress]::RtlGetCompressionWorkSpaceSize(4, [ref]$bufferSize, [ref]$fragmentSize)
        if ($status -ne 0) {
            Log-Warning ("  RtlGetCompressionWorkSpaceSize failed (NTSTATUS 0x{0:X8}) -- prefetch run times unavailable." -f $status)
            return $false
        }
        $script:prefetchWorkspace = New-Object byte[] ([Math]::Max(1, [Math]::Max([int]$bufferSize, [int]$fragmentSize)))
        $script:prefetchXpressReady = $true
    }
    catch {
        Log-Warning "  Prefetch decompression unavailable ($($_.Exception.Message)) -- using file times only."
    }
    return $script:prefetchXpressReady
}

# Parse a prefetch file (SCCA versions 17/23/26/30/31). Returns an object with
# Version, ExeName, ExePath, Hash, RunCount and RunTimes (UTC, newest first),
# or a string giving the reason it could not be parsed.
# Layout: uint32 version at 0, "SCCA" at 4, exe name (UTF-16, 60 bytes) at
# 0x10, hash at 0x4C, file-name strings offset/size at 0x64/0x68. Last run
# times: v17 one at 0x78, v23 one at 0x80, v26+ eight at 0x80. Run count:
# v17 0x90, v23 0x98, v26 0xD0; v30/31 0xC8 when the file metrics array
# starts at 0x128 (all Win11 files tested), else 0xD0. The count must agree
# with the number of non-zero run times and the times must be plausible.
function Read-PrefetchFile {
    param([string]$Path, [datetime]$MaxTimeUtc)

    $raw = [System.IO.File]::ReadAllBytes($Path)
    if ($raw.Length -lt 8) { return "file too small" }

    $data = $raw
    if ($raw[0] -eq 0x4D -and $raw[1] -eq 0x41 -and $raw[2] -eq 0x4D) {
        if (($raw[3] -band 0x0F) -ne 4) { return ("unsupported compression format 0x{0:X2}" -f $raw[3]) }
        if (-not (Initialize-PrefetchDecompressor)) { return "decompressor unavailable" }
        $size = [BitConverter]::ToUInt32($raw, 4)
        $dataOffset = 8
        if ($raw[3] -band 0x80) { $dataOffset = 12 }
        if ($size -lt 0x100 -or $size -gt 64MB -or $raw.Length -le $dataOffset) { return "bad uncompressed size $size" }
        $compressed = New-Object byte[] ($raw.Length - $dataOffset)
        [Array]::Copy($raw, $dataOffset, $compressed, 0, $compressed.Length)
        $data = New-Object byte[] $size
        $finalSize = 0
        $status = [TimelineNative.Xpress]::RtlDecompressBufferEx(4, $data, [int]$size, $compressed, $compressed.Length, [ref]$finalSize, $script:prefetchWorkspace)
        if ($status -ne 0) { return ("decompression failed (NTSTATUS 0x{0:X8})" -f $status) }
    }

    if ($data.Length -lt 0xD8 -or [System.Text.Encoding]::ASCII.GetString($data, 4, 4) -ne "SCCA") { return "no SCCA signature" }

    $version = [BitConverter]::ToUInt32($data, 0)
    if ($version -eq 17) { $timeOffset = 0x78; $slots = 1; $countOffsets = @(0x90) }
    elseif ($version -eq 23) { $timeOffset = 0x80; $slots = 1; $countOffsets = @(0x98) }
    elseif ($version -eq 26) { $timeOffset = 0x80; $slots = 8; $countOffsets = @(0xD0) }
    elseif ($version -eq 30 -or $version -eq 31) {
        $timeOffset = 0x80; $slots = 8
        if ([BitConverter]::ToUInt32($data, 0x54) -eq 0x128) { $countOffsets = @(0xC8, 0xD0) } else { $countOffsets = @(0xD0, 0xC8) }
    }
    else { return "unsupported SCCA version $version" }

    # Last run times (slot 0 = most recent)
    $minFileTime = (New-Object DateTime 2000, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)).ToFileTimeUtc()
    $maxFileTime = $MaxTimeUtc.ToFileTimeUtc()
    $runTimes = New-Object System.Collections.Generic.List[datetime]
    for ($i = 0; $i -lt $slots; $i++) {
        $ft = [BitConverter]::ToInt64($data, $timeOffset + 8 * $i)
        if ($ft -eq 0) { continue }
        if ($ft -lt $minFileTime -or $ft -gt $maxFileTime) { return "run time out of range" }
        $runTimes.Add([datetime]::FromFileTimeUtc($ft))
    }
    if ($runTimes.Count -eq 0) { return "no run times" }

    $runCount = $null
    foreach ($off in $countOffsets) {
        $c = [BitConverter]::ToUInt32($data, $off)
        if ($c -ge 1 -and $c -le 1000000 -and $runTimes.Count -eq [Math]::Min([int]$c, $slots)) { $runCount = [int]$c; break }
    }
    if ($null -eq $runCount) { return "run count does not match the run times" }
    # Slots are in update order; runs a moment apart can be swapped, so sort newest first
    $runTimes.Sort()
    $runTimes.Reverse()

    $exeName = [System.Text.Encoding]::Unicode.GetString($data, 0x10, 60).Split([char]0)[0]

    # Full path of the executable from the file-name strings (the header name is cut at 29 chars)
    $exePath = ""
    $strOffset = [int][BitConverter]::ToUInt32($data, 0x64)
    $strSize = [int][BitConverter]::ToUInt32($data, 0x68)
    if ($exeName -and $strOffset -gt 0 -and $strSize -gt 0 -and $strOffset + $strSize -le $data.Length) {
        foreach ($s in [System.Text.Encoding]::Unicode.GetString($data, $strOffset, $strSize).Split([char]0)) {
            $leaf = $s.Substring($s.LastIndexOf('\') + 1)
            if ($leaf -eq $exeName -or ($exeName.Length -ge 29 -and $leaf.StartsWith($exeName, [System.StringComparison]::OrdinalIgnoreCase))) {
                $exePath = $s
                $exeName = $leaf
                break
            }
        }
    }

    return [PSCustomObject]@{
        Version  = $version
        ExeName  = $exeName
        ExePath  = $exePath
        Hash     = "{0:X8}" -f [BitConverter]::ToUInt32($data, 0x4C)
        RunCount = $runCount
        RunTimes = $runTimes
    }
}

function Parse-Prefetch {
    Log "--- Parsing Prefetch Files ---"

    # Look for prefetch files in input path or standard Windows location
    $pfFiles = Find-ArtifactFiles -BasePath $InputPath -Extensions @(".pf")

    if ($pfFiles.Count -eq 0) {
        Log-Warning "No prefetch files found. Skipping prefetch parsing."
        return
    }

    Log "Found $($pfFiles.Count) prefetch file(s)"

    # Run times after the collection (plus slack for programs it ran itself) mean a misread file
    $collectionStart = (Get-CollectionInfo).CollectionStartUtc
    if (-not $collectionStart) { $collectionStart = [datetime]::UtcNow }
    $maxRunTime = $collectionStart.AddDays(1)

    $parsedFiles = 0
    $runRows = 0
    $fallbackFiles = 0
    $failReasons = @{}

    foreach ($pf in $pfFiles) {
        try {
            # Extract executable name from prefetch filename
            # Format: EXECUTABLENAME-HASH.pf
            $pfName = $pf.BaseName
            $exeName = $pfName
            if ($pfName -match '^(.+)-[A-F0-9]{8}$') {
                $exeName = $Matches[1]
            }

            $parsed = $null
            try { $parsed = Read-PrefetchFile -Path $pf.FullName -MaxTimeUtc $maxRunTime }
            catch { $parsed = "parse error: $($_.Exception.Message)" }

            if ($parsed -and $parsed -isnot [string]) {
                # One Execution row per recorded run time (newest = run N of N)
                if ($parsed.ExeName) { $exeName = $parsed.ExeName }
                $details = "RunCount=$($parsed.RunCount)"
                if ($parsed.ExePath) { $details += " Path=$($parsed.ExePath)" }
                $details += " PrefetchFile=$($pf.Name) Version=$($parsed.Version) Hash=$($parsed.Hash)"
                $runNumber = $parsed.RunCount
                foreach ($runTime in $parsed.RunTimes) {
                    Add-TimelineEntry -Timestamp $runTime -Source "Prefetch" -EventType "Execution" `
                        -Description "Prefetch execution: $exeName (run $runNumber of $($parsed.RunCount))" `
                        -Details $details `
                        -Artifact "Prefetch" -RawPath $pf.FullName
                    $runNumber--
                    $runRows++
                }
                $parsedFiles++
                continue
            }

            # Fallback: original file times (Created ~ first run, Modified ~ last run).
            # The copy's own creation time is the collection/extract time, never used.
            $fallbackFiles++
            $reason = "$parsed"
            if (-not $failReasons.ContainsKey($reason)) { $failReasons[$reason] = 0 }
            $failReasons[$reason]++
            $baseDetails = "PrefetchFile=$($pf.Name) Size=$($pf.Length) NotParsed=$reason"
            $src = Get-SourceFileTimes $pf.FullName
            if ($src -and ($src.Created -or $src.Modified)) {
                if ($src.Created) {
                    Add-TimelineEntry -Timestamp $src.Created -Source "Prefetch" -EventType "Execution" `
                        -Description "Prefetch file created (approx. first run): $exeName" `
                        -Details "$baseDetails TimeSource=original file times" `
                        -Artifact "Prefetch" -RawPath $pf.FullName
                }
                if ($src.Modified) {
                    Add-TimelineEntry -Timestamp $src.Modified -Source "Prefetch" -EventType "Execution" `
                        -Description "Prefetch file modified (approx. last run): $exeName" `
                        -Details "$baseDetails TimeSource=original file times" `
                        -Artifact "Prefetch" -RawPath $pf.FullName
                }
            }
            else {
                Add-TimelineEntry -Timestamp $pf.LastWriteTimeUtc -Source "Prefetch" -EventType "Execution" `
                    -Description "Prefetch file last modified: $exeName" `
                    -Details "$baseDetails TimeSource=collected copy LastWriteTime" `
                    -Artifact "Prefetch" -RawPath $pf.FullName
            }
        }
        catch {
            Log-Warning "  Failed to parse prefetch file $($pf.Name) : $($_.Exception.Message)"
        }
    }

    Log "  Parsed $parsedFiles of $($pfFiles.Count) prefetch file(s): $runRows run time(s)."
    if ($fallbackFiles -gt 0) {
        $reasonText = ($failReasons.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join "; "
        Log-Warning "  $fallbackFiles prefetch file(s) not parsed -- file times used instead: $reasonText"
    }
    Log "  Prefetch parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 3. Recent Files (LNK) Parser
# ----------------------------------------------------------
# ShellLinkHeader (MS-SHLLINK 2.1): HeaderSize 0x4C at 0, target file
# Created/Accessed/Written FILETIMEs at 0x1C/0x24/0x2C, target size at 0x34.
# Returns $null if the file has no valid header.
function Read-LnkHeader {
    param([string]$Path)
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 0x4C -or [BitConverter]::ToUInt32($b, 0) -ne 0x4C) { return $null }
    $times = @{}
    foreach ($field in @(@("Created", 0x1C), @("Accessed", 0x24), @("Modified", 0x2C))) {
        $ft = [BitConverter]::ToInt64($b, $field[1])
        $times[$field[0]] = $null
        if ($ft -gt 0 -and $ft -le [datetime]::MaxValue.ToFileTimeUtc()) {
            $times[$field[0]] = [datetime]::FromFileTimeUtc($ft)
        }
    }
    return [PSCustomObject]@{
        TargetCreated  = $times["Created"]
        TargetAccessed = $times["Accessed"]
        TargetModified = $times["Modified"]
        TargetSize     = [BitConverter]::ToUInt32($b, 0x34)
    }
}

# Jump lists are read by a small C# helper (compiled once per session):
#   TimelineJumpList.Reader.ReadAutomatic(path): an AutomaticDestinations
#     file is an OLE compound file (MS-CFB). Its DestList stream lists the
#     entries; each entry's shell link is the stream named by its entry
#     number in hex, parsed as well.
#   TimelineJumpList.Reader.ReadCustom(path): a CustomDestinations file holds
#     shell links back to back; each is found by its header and CLSID.
# DestList: 32-byte header (version, entry count, pinned count, ...). Entry:
# hostname 0x48, entry number 0x58, then
#   version 1 (Win7/8):  FILETIME 0x60, pin 0x68, path length 0x6C, path 0x6E
#   versions 2-4 (Win10): FILETIME 0x60, pin 0x68, access count 0x70,
#                         path length 0x7C, path 0x7E
#   version 6 (Win11 24H2, the test collection): the same fields 4 bytes
#                         later (FILETIME 0x64 ... path length 0x80, path 0x82)
# From version 2 on the path is followed by the size of a property store
# that comes before the next entry. Pin status -1 = not pinned, else the
# pin position (0-based). Path lengths are in UTF-16 characters.
function Initialize-JumpListReader {
    if ($null -ne $script:jumpListReaderReady) { return $script:jumpListReaderReady }
    $script:jumpListReaderReady = $false
    try {
        if (-not ([System.Management.Automation.PSTypeName]'TimelineJumpList.Reader').Type) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TimelineJumpList
{
    // One shell link (MS-SHLLINK): header times, target and string data
    public class LnkData
    {
        public int Offset;
        public int Length;
        public uint Flags;
        public long CreatedFileTime;
        public long AccessedFileTime;
        public long ModifiedFileTime;
        public uint TargetSize;
        public string LocalPath;
        public string NetworkPath;
        public string EnvTarget;
        public string Name;
        public string RelativePath;
        public string WorkingDir;
        public string Arguments;
        public string MachineId;
        public string Error;
        public List<byte[]> IdListItems = new List<byte[]>();
    }

    // One DestList entry of an AutomaticDestinations jump list
    public class DestListEntry
    {
        public int EntryNumber;
        public string Path;
        public long LastAccessFileTime;
        public int AccessCount;
        public int PinStatus;
        public string Hostname;
        public LnkData Lnk;
    }

    public class AutomaticDestinations
    {
        public int Version;
        public int DeclaredEntries;
        public int PinnedEntries;
        public List<DestListEntry> Entries = new List<DestListEntry>();
    }

    public static class Reader
    {
        static readonly byte[] LinkClsid = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
        static readonly long MinFileTime = new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
        static readonly long MaxFileTime = new DateTime(2200, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

        public static AutomaticDestinations ReadAutomatic(string path)
        {
            CompoundFile cf = new CompoundFile(File.ReadAllBytes(path));
            AutomaticDestinations result = new AutomaticDestinations();
            byte[] d = cf.GetStream("DestList");
            if (d == null || d.Length < 32) { return result; }
            result.Version = BitConverter.ToInt32(d, 0);
            result.DeclaredEntries = BitConverter.ToInt32(d, 4);
            result.PinnedEntries = BitConverter.ToInt32(d, 8);
            // Layout 0 = version 1, 1 = versions 2-4, 2 = version 6; for an
            // unknown version the first layout the first entry fits
            int[] order = result.Version <= 1 ? new int[] { 0, 1, 2 } : (result.Version <= 4 ? new int[] { 1, 2, 0 } : new int[] { 2, 1, 0 });
            int layout = order[0];
            foreach (int candidate in order)
            {
                if (EntryFits(d, 32, candidate)) { layout = candidate; break; }
            }
            int shift = layout == 2 ? 4 : 0;
            int lenOff = layout == 0 ? 0x6C : 0x7C + shift;
            int off = 32;
            while (off + lenOff + 2 <= d.Length && result.Entries.Count < result.DeclaredEntries && result.Entries.Count < 100000)
            {
                DestListEntry e = new DestListEntry();
                e.Hostname = AnsiZ(d, off + 0x48, off + 0x58);
                e.EntryNumber = BitConverter.ToInt32(d, off + 0x58);
                e.LastAccessFileTime = BitConverter.ToInt64(d, off + 0x60 + shift);
                e.PinStatus = BitConverter.ToInt32(d, off + 0x68 + shift);
                e.AccessCount = layout == 0 ? -1 : BitConverter.ToInt32(d, off + 0x70 + shift);
                int chars = BitConverter.ToUInt16(d, off + lenOff);
                int pathOff = off + lenOff + 2;
                if (pathOff + chars * 2 > d.Length) { break; }
                e.Path = Encoding.Unicode.GetString(d, pathOff, chars * 2);
                off = pathOff + chars * 2;
                if (layout != 0 && off + 4 <= d.Length)
                {
                    // Size of the property store that follows (0 if none)
                    int extra = BitConverter.ToInt32(d, off);
                    off += 4;
                    if (extra > d.Length - off) { off = d.Length; }
                    else if (extra > 0) { off += extra; }
                }
                byte[] lnk = cf.GetStream(e.EntryNumber.ToString("x"));
                if (lnk != null) { e.Lnk = ParseLnk(lnk, 0, lnk.Length); }
                result.Entries.Add(e);
            }
            return result;
        }

        // True if an entry at off fits the layout: last-access time zero or
        // 1980-2200 and a printable path that ends inside the stream
        static bool EntryFits(byte[] d, int off, int layout)
        {
            int shift = layout == 2 ? 4 : 0;
            int lenOff = layout == 0 ? 0x6C : 0x7C + shift;
            if (off + lenOff + 4 > d.Length) { return false; }
            long ft = BitConverter.ToInt64(d, off + 0x60 + shift);
            if (ft != 0 && (ft < MinFileTime || ft > MaxFileTime)) { return false; }
            int chars = BitConverter.ToUInt16(d, off + lenOff);
            int pathOff = off + lenOff + 2;
            if (chars == 0 || pathOff + chars * 2 > d.Length) { return false; }
            return BitConverter.ToUInt16(d, pathOff) >= 0x20;
        }

        public static List<LnkData> ReadCustom(string path)
        {
            byte[] b = File.ReadAllBytes(path);
            List<LnkData> list = new List<LnkData>();
            int i = 0;
            while (i + 0x4C <= b.Length)
            {
                int hit = FindLinkHeader(b, i);
                if (hit < 0) { break; }
                LnkData l = ParseLnk(b, hit, b.Length);
                if (l == null) { i = hit + 4; continue; }
                list.Add(l);
                i = hit + Math.Max(l.Length, 0x4C);
            }
            return list;
        }

        static int FindLinkHeader(byte[] b, int start)
        {
            for (int i = start; i + 20 <= b.Length; i++)
            {
                if (b[i] != 0x4C || b[i + 1] != 0 || b[i + 2] != 0 || b[i + 3] != 0) { continue; }
                bool match = true;
                for (int k = 0; k < 16; k++) { if (b[i + 4 + k] != LinkClsid[k]) { match = false; break; } }
                if (match) { return i; }
            }
            return -1;
        }

        // Shell link at b[off..end): null if there is no valid header. A
        // damaged link keeps what was read before the damage (Error is set).
        public static LnkData ParseLnk(byte[] b, int off, int end)
        {
            if (b == null || off < 0 || end > b.Length || off + 0x4C > end) { return null; }
            if (BitConverter.ToUInt32(b, off) != 0x4C) { return null; }
            for (int k = 0; k < 16; k++) { if (b[off + 4 + k] != LinkClsid[k]) { return null; } }
            LnkData l = new LnkData();
            l.Offset = off;
            l.Flags = BitConverter.ToUInt32(b, off + 0x14);
            l.CreatedFileTime = BitConverter.ToInt64(b, off + 0x1C);
            l.AccessedFileTime = BitConverter.ToInt64(b, off + 0x24);
            l.ModifiedFileTime = BitConverter.ToInt64(b, off + 0x2C);
            l.TargetSize = BitConverter.ToUInt32(b, off + 0x34);
            int p = off + 0x4C;
            try
            {
                // LinkTargetIDList: shell items, resolved by the caller if needed
                if ((l.Flags & 0x1) != 0)
                {
                    int idEnd = p + 2 + BitConverter.ToUInt16(b, p);
                    int q = p + 2;
                    while (q + 2 <= idEnd)
                    {
                        int itemSize = BitConverter.ToUInt16(b, q);
                        if (itemSize < 3 || q + itemSize > idEnd) { break; }
                        byte[] item = new byte[itemSize];
                        Array.Copy(b, q, item, 0, itemSize);
                        l.IdListItems.Add(item);
                        q += itemSize;
                    }
                    p = idEnd;
                }
                // LinkInfo: local base path + common path suffix, or network share
                if ((l.Flags & 0x2) != 0)
                {
                    int li = p;
                    int liSize = BitConverter.ToInt32(b, li);
                    int liEnd = Math.Min(li + liSize, end);
                    int liHeader = BitConverter.ToInt32(b, li + 4);
                    uint liFlags = BitConverter.ToUInt32(b, li + 8);
                    int localOff = BitConverter.ToInt32(b, li + 16);
                    int netOff = BitConverter.ToInt32(b, li + 20);
                    int suffixOff = BitConverter.ToInt32(b, li + 24);
                    string suffix = null;
                    if (liHeader >= 0x24)
                    {
                        int localUni = BitConverter.ToInt32(b, li + 28);
                        int suffixUni = BitConverter.ToInt32(b, li + 32);
                        if ((liFlags & 1) != 0 && localUni > 0) { l.LocalPath = Utf16Z(b, li + localUni, liEnd); }
                        if (suffixUni > 0) { suffix = Utf16Z(b, li + suffixUni, liEnd); }
                    }
                    if ((liFlags & 1) != 0 && string.IsNullOrEmpty(l.LocalPath) && localOff > 0) { l.LocalPath = AnsiZ(b, li + localOff, liEnd); }
                    if (string.IsNullOrEmpty(suffix) && suffixOff > 0) { suffix = AnsiZ(b, li + suffixOff, liEnd); }
                    if ((liFlags & 2) != 0 && netOff > 0)
                    {
                        int cn = li + netOff;
                        int netNameOff = BitConverter.ToInt32(b, cn + 8);
                        string net = null;
                        if (netNameOff > 0x14)
                        {
                            int netUni = BitConverter.ToInt32(b, cn + 0x14);
                            if (netUni > 0) { net = Utf16Z(b, cn + netUni, liEnd); }
                        }
                        if (string.IsNullOrEmpty(net) && netNameOff > 0) { net = AnsiZ(b, cn + netNameOff, liEnd); }
                        if (!string.IsNullOrEmpty(net))
                        {
                            l.NetworkPath = string.IsNullOrEmpty(suffix) ? net : net.TrimEnd('\\') + "\\" + suffix;
                        }
                    }
                    if (!string.IsNullOrEmpty(l.LocalPath) && !string.IsNullOrEmpty(suffix)) { l.LocalPath = l.LocalPath + suffix; }
                    p = li + liSize;
                }
                // StringData: name, relative path, working dir, arguments, icon
                bool unicode = (l.Flags & 0x80) != 0;
                uint[] stringFlags = { 0x4, 0x8, 0x10, 0x20, 0x40 };
                string[] values = new string[5];
                for (int k = 0; k < 5; k++)
                {
                    if ((l.Flags & stringFlags[k]) == 0) { continue; }
                    int count = BitConverter.ToUInt16(b, p);
                    p += 2;
                    int bytes = unicode ? count * 2 : count;
                    if (p + bytes > end) { throw new InvalidDataException("string data past the end"); }
                    values[k] = unicode ? Encoding.Unicode.GetString(b, p, bytes) : Encoding.Default.GetString(b, p, bytes);
                    p += bytes;
                }
                l.Name = values[0];
                l.RelativePath = values[1];
                l.WorkingDir = values[2];
                l.Arguments = values[3];
                // ExtraData blocks up to the terminal block (size < 4)
                while (p + 4 <= end)
                {
                    int size = BitConverter.ToInt32(b, p);
                    if (size < 4) { p += 4; break; }
                    if (size < 8 || size > end - p) { throw new InvalidDataException("extra data block past the end"); }
                    uint sig = BitConverter.ToUInt32(b, p + 4);
                    if (sig == 0xA0000003 && size >= 0x60) { l.MachineId = AnsiZ(b, p + 16, p + 32); }
                    else if (sig == 0xA0000001 && size >= 0x314)
                    {
                        l.EnvTarget = Utf16Z(b, p + 268, p + 788);
                        if (string.IsNullOrEmpty(l.EnvTarget)) { l.EnvTarget = AnsiZ(b, p + 8, p + 268); }
                    }
                    p += size;
                }
            }
            catch (Exception ex)
            {
                l.Error = ex.Message;
            }
            l.Length = Math.Min(Math.Max(p, off + 0x4C), end) - off;
            return l;
        }

        static string Utf16Z(byte[] b, int start, int limit)
        {
            limit = Math.Min(limit, b.Length);
            if (start < 0 || start >= limit) { return null; }
            int e = start;
            while (e + 1 < limit && (b[e] != 0 || b[e + 1] != 0)) { e += 2; }
            return Encoding.Unicode.GetString(b, start, Math.Min(e, limit) - start);
        }

        static string AnsiZ(byte[] b, int start, int limit)
        {
            limit = Math.Min(limit, b.Length);
            if (start < 0 || start >= limit) { return null; }
            int e = start;
            while (e < limit && b[e] != 0) { e++; }
            return Encoding.Default.GetString(b, start, e - start);
        }
    }

    // Minimal OLE compound file (MS-CFB) reader: FAT and DIFAT, directory,
    // mini stream; enough to read the streams of a jump list
    internal class CompoundFile
    {
        class DirEntry
        {
            public string Name;
            public int Type;
            public uint Start;
            public long Size;
        }

        readonly byte[] data;
        readonly int sectorSize;
        readonly int miniSectorSize;
        readonly uint miniCutoff;
        readonly uint[] fat;
        readonly uint[] miniFat;
        readonly byte[] miniStream;
        readonly List<DirEntry> entries = new List<DirEntry>();

        public CompoundFile(byte[] bytes)
        {
            data = bytes;
            if (bytes.Length < 512 || BitConverter.ToUInt64(bytes, 0) != 0xE11AB1A1E011CFD0UL) { throw new InvalidDataException("not an OLE compound file"); }
            int sectorShift = BitConverter.ToUInt16(bytes, 0x1E);
            if (sectorShift != 9 && sectorShift != 12) { throw new InvalidDataException("unsupported sector size"); }
            sectorSize = 1 << sectorShift;
            miniSectorSize = 1 << BitConverter.ToUInt16(bytes, 0x20);
            int fatCount = BitConverter.ToInt32(bytes, 0x2C);
            uint firstDir = BitConverter.ToUInt32(bytes, 0x30);
            miniCutoff = BitConverter.ToUInt32(bytes, 0x38);
            uint firstMiniFat = BitConverter.ToUInt32(bytes, 0x3C);
            uint difat = BitConverter.ToUInt32(bytes, 0x44);
            int perSector = sectorSize / 4;

            // FAT sector numbers: 109 in the header, the rest in DIFAT sectors
            List<uint> fatSectors = new List<uint>();
            for (int i = 0; i < 109 && fatSectors.Count < fatCount; i++)
            {
                uint s = BitConverter.ToUInt32(bytes, 0x4C + i * 4);
                if (s < 0xFFFFFFFA) { fatSectors.Add(s); }
            }
            int guard = 0;
            while (difat < 0xFFFFFFFA && fatSectors.Count < fatCount && guard++ < 65536)
            {
                long doff = SectorOffset(difat);
                if (doff + sectorSize > data.Length) { break; }
                for (int i = 0; i < perSector - 1 && fatSectors.Count < fatCount; i++)
                {
                    uint s = BitConverter.ToUInt32(data, (int)doff + i * 4);
                    if (s < 0xFFFFFFFA) { fatSectors.Add(s); }
                }
                difat = BitConverter.ToUInt32(data, (int)doff + (perSector - 1) * 4);
            }
            fat = new uint[fatSectors.Count * perSector];
            for (int f = 0; f < fatSectors.Count; f++)
            {
                long foff = SectorOffset(fatSectors[f]);
                for (int i = 0; i < perSector; i++)
                {
                    long pos = foff + i * 4;
                    fat[f * perSector + i] = pos + 4 <= data.Length ? BitConverter.ToUInt32(data, (int)pos) : 0xFFFFFFFF;
                }
            }

            byte[] dir = ReadChain(firstDir, long.MaxValue);
            for (int p = 0; p + 128 <= dir.Length; p += 128)
            {
                DirEntry e = new DirEntry();
                int nameBytes = Math.Min((int)BitConverter.ToUInt16(dir, p + 0x40), 64);
                e.Name = nameBytes >= 2 ? Encoding.Unicode.GetString(dir, p, nameBytes - 2) : "";
                e.Type = dir[p + 0x42];
                e.Start = BitConverter.ToUInt32(dir, p + 0x74);
                // Version 3 files (512-byte sectors) only use the low 32 bits
                e.Size = sectorSize == 512 ? (long)BitConverter.ToUInt32(dir, p + 0x78) : (long)BitConverter.ToUInt64(dir, p + 0x78);
                entries.Add(e);
            }
            miniStream = (entries.Count > 0 && entries[0].Type == 5) ? ReadChain(entries[0].Start, entries[0].Size) : new byte[0];
            byte[] mf = ReadChain(firstMiniFat, long.MaxValue);
            miniFat = new uint[mf.Length / 4];
            for (int i = 0; i < miniFat.Length; i++) { miniFat[i] = BitConverter.ToUInt32(mf, i * 4); }
        }

        long SectorOffset(uint sector)
        {
            return ((long)sector + 1) * sectorSize;
        }

        // Sectors of a FAT chain (stops at the end of the chain or the file,
        // and after as many sectors as the FAT has, so a loop cannot hang)
        byte[] ReadChain(uint start, long size)
        {
            MemoryStream ms = new MemoryStream();
            uint s = start;
            int guard = 0;
            while (s < 0xFFFFFFFA && s < fat.Length && guard++ <= fat.Length && ms.Length < size)
            {
                long off = SectorOffset(s);
                if (off >= data.Length) { break; }
                ms.Write(data, (int)off, (int)Math.Min(sectorSize, data.Length - off));
                s = fat[s];
            }
            return Truncate(ms.ToArray(), size);
        }

        byte[] ReadMiniChain(uint start, long size)
        {
            MemoryStream ms = new MemoryStream();
            uint s = start;
            int guard = 0;
            while (s < 0xFFFFFFFA && s < miniFat.Length && guard++ <= miniFat.Length && ms.Length < size)
            {
                long off = (long)s * miniSectorSize;
                if (off >= miniStream.Length) { break; }
                ms.Write(miniStream, (int)off, (int)Math.Min(miniSectorSize, miniStream.Length - off));
                s = miniFat[s];
            }
            return Truncate(ms.ToArray(), size);
        }

        static byte[] Truncate(byte[] b, long size)
        {
            if (size >= 0 && size < b.Length) { Array.Resize(ref b, (int)size); }
            return b;
        }

        // Contents of the named stream, or null if there is none
        public byte[] GetStream(string name)
        {
            foreach (DirEntry e in entries)
            {
                if (e.Type != 2 || !string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)) { continue; }
                return e.Size < miniCutoff ? ReadMiniChain(e.Start, e.Size) : ReadChain(e.Start, e.Size);
            }
            return null;
        }
    }
}
'@
        }
        $script:jumpListReaderReady = $true
    }
    catch {
        Log-Warning "  Jump list reader unavailable ($($_.Exception.Message)) -- jump lists skipped."
    }
    return $script:jumpListReaderReady
}

# Well-known jump list AppIDs (the file name: a CRC-64 of the program's path
# or AppUserModelID). Other AppIDs are named after the one program their
# CustomDestinations links start, else shown as the AppID.
$script:JumpListAppIds = @{
    "1b4dd67f29cb1962" = "Windows Explorer"
    "f01b4d95cf55d32a" = "Windows Explorer"
    "5f7b5f1e01b83767" = "Quick Access"
    "7e4dca80246863e3" = "Control Panel"
    "9b9cdc69c1c24e2b" = "Notepad (64-bit)"
    "918e0ecb43d17e23" = "Notepad (32-bit)"
    "12dc1ea8e34b5a6"  = "Paint"
    "469e4a7982cea4d4" = "WordPad"
    "1bc392b8e104a00e" = "Remote Desktop Connection"
    "590aee7bdd69b59b" = "Windows PowerShell"
    "16f2f0042ddbe0e8" = "Windows Terminal"
    "28c8b86deab549a1" = "Internet Explorer"
    "ccba5a5986c77e43" = "Microsoft Edge"
    "5d696d521de238c3" = "Google Chrome"
    "6824f4a902c78fbd" = "Mozilla Firefox"
    "b8ab77100df80ab2" = "Microsoft Excel"
    "a52b0784bd667468" = "Photos"
}

# FILETIME -> UTC [datetime], or $null when zero or out of range
function ConvertFrom-JumpListFileTime {
    param([long]$FileTime)
    if ($FileTime -le 0 -or $FileTime -gt [datetime]::MaxValue.ToFileTimeUtc()) { return $null }
    return [datetime]::FromFileTimeUtc($FileTime)
}

# Target of a jump list shell link: LinkInfo path, environment-variable
# target, else (unless -PathOnly) the path built from its shell items, else
# its name
function Get-JumpListLinkTarget {
    param($Link, [switch]$PathOnly)
    if (-not $Link) { return "" }
    foreach ($candidate in @($Link.LocalPath, $Link.NetworkPath, $Link.EnvTarget)) {
        if ($candidate) { return [string]$candidate }
    }
    if ($PathOnly) { return "" }
    $path = ""
    foreach ($item in $Link.IdListItems) {
        $shellItem = Get-ShellItemName ([byte[]]$item)
        if ($shellItem.IsVolume -or -not $path) { $path = $shellItem.Name }
        else { $path = $path.TrimEnd('\') + '\' + $shellItem.Name }
    }
    if ($path) { return $path }
    return [string]$Link.Name
}

# Adds a shell link's arguments, target times and size (from the link
# header) and the machine it was made on to a Details dictionary
function Add-JumpListLinkDetails {
    param([System.Collections.Specialized.OrderedDictionary]$Details, $Link)
    if (-not $Link) { return }
    $Details["Arguments"] = $Link.Arguments
    foreach ($pair in @(@("TargetCreatedUtc", $Link.CreatedFileTime), @("TargetModifiedUtc", $Link.ModifiedFileTime), @("TargetAccessedUtc", $Link.AccessedFileTime))) {
        $time = ConvertFrom-JumpListFileTime $pair[1]
        if ($time) { $Details[$pair[0]] = $time.ToString("yyyy-MM-dd HH:mm:ss") }
    }
    if ($Link.TargetSize -gt 0) { $Details["TargetSize"] = $Link.TargetSize }
    $Details["MachineID"] = $Link.MachineId
    $Details["LinkError"] = $Link.Error
}

# Jump list rows for every user in the collection: one per DestList entry
# (at its last-access time) and one per CustomDestinations link (at the
# list file's last-write time: custom links carry no use time). Returns the
# number of rows added.
function Read-JumpLists {
    $autoFiles = @(Find-ArtifactFiles -BasePath $InputPath -Extensions @(".automaticDestinations-ms"))
    $customFiles = @(Find-ArtifactFiles -BasePath $InputPath -Extensions @(".customDestinations-ms"))
    if ($autoFiles.Count + $customFiles.Count -eq 0) {
        Log "  No jump lists found in the collection."
        return 0
    }
    Log "  Found $($autoFiles.Count) AutomaticDestinations and $($customFiles.Count) CustomDestinations jump list(s)"
    if (-not (Initialize-JumpListReader)) { return 0 }

    $added = 0
    $noTime = 0
    $failed = 0
    # CustomDestinations first: the program their links start names the AppID
    $customLists = @()
    $appHints = @{}
    foreach ($file in $customFiles) {
        try {
            $links = @([TimelineJumpList.Reader]::ReadCustom($file.FullName))
            $customLists += , @($file, $links)
            $programs = @($links | ForEach-Object { [string]$_.LocalPath } | Where-Object { $_ -match '\.exe$' } |
                ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique)
            if ($programs.Count -eq 1) { $appHints[$file.BaseName] = $programs[0] }
        }
        catch {
            $failed++
            Log-Warning "  Could not read jump list $($file.FullName): $($_.Exception.Message)"
        }
    }
    $appNameOf = {
        param([string]$AppId)
        if ($script:JumpListAppIds.ContainsKey($AppId)) { return $script:JumpListAppIds[$AppId] }
        if ($appHints.ContainsKey($AppId)) { return $appHints[$AppId] }
        return $AppId
    }

    # Time for rows without their own: the list file's original last-write
    # time from the manifest, else the collected copy's
    $listFileTime = {
        param([System.IO.FileInfo]$File)
        $src = Get-SourceFileTimes $File.FullName
        if ($src -and $src.Modified) { return @($src.Modified, "jump list file last modified (original)") }
        return @($File.LastWriteTimeUtc, "jump list file last modified (collected copy)")
    }

    foreach ($pair in $customLists) {
        $file = $pair[0]
        try {
            $appId = $file.BaseName.ToLowerInvariant()
            $app = & $appNameOf $appId
            $user = Get-CollectionUser $file.FullName
            $fileTime = & $listFileTime $file
            $n = 0
            foreach ($link in $pair[1]) {
                $n++
                $target = Get-JumpListLinkTarget $link
                if (-not $target) { continue }
                $label = $target
                if ($link.Arguments) { $label = "$target $($link.Arguments)" }
                $details = [ordered]@{ AppID = $appId; EntryNumber = $n; List = "CustomDestinations"; Name = $link.Name }
                Add-JumpListLinkDetails $details $link
                $details["TimeSource"] = $fileTime[1]
                Add-TimelineEntry -Timestamp $fileTime[0] -Source "JumpLists" -EventType "FileAccess" `
                    -Description "Jump list ($app): $label" `
                    -User $user -Details (Format-ArtifactDetails $details) `
                    -Artifact "RecentFiles" -RawPath $file.FullName
                $added++
            }
        }
        catch {
            $failed++
            Log-Warning "  Could not read jump list $($file.FullName): $($_.Exception.Message)"
        }
    }

    foreach ($file in $autoFiles) {
        try {
            $list = [TimelineJumpList.Reader]::ReadAutomatic($file.FullName)
            $appId = $file.BaseName.ToLowerInvariant()
            $app = & $appNameOf $appId
            $user = Get-CollectionUser $file.FullName
            $fileTime = $null
            foreach ($entry in $list.Entries) {
                # Known folders are listed as "knownfolder:{GUID}"; the link has the path
                $path = [string]$entry.Path
                $target = Get-JumpListLinkTarget $entry.Lnk -PathOnly
                if (-not $path -or $path -like "knownfolder:*") {
                    if (-not $target) { $target = Get-JumpListLinkTarget $entry.Lnk }
                    if ($target) { $path = $target }
                }
                if (-not $path) { continue }
                $ts = ConvertFrom-JumpListFileTime $entry.LastAccessFileTime
                $timeSource = "DestList last access"
                if (-not $ts) {
                    if (-not $fileTime) { $fileTime = & $listFileTime $file }
                    $ts = $fileTime[0]
                    $timeSource = "entry has no access time; $($fileTime[1])"
                    $noTime++
                }
                $details = [ordered]@{
                    AccessCount  = $(if ($entry.AccessCount -ge 0) { $entry.AccessCount } else { "" })
                    Pinned       = $(if ($entry.PinStatus -ge 0) { "Yes (position $($entry.PinStatus + 1))" } else { "No" })
                    AppID        = $appId
                    EntryNumber  = $entry.EntryNumber
                    List         = "AutomaticDestinations (DestList version $($list.Version))"
                    DestListPath = $(if ($path -ne $entry.Path) { $entry.Path } else { "" })
                    LinkTarget   = $(if ($target -and $target -ne $path) { $target } else { "" })
                    Hostname     = $entry.Hostname
                }
                Add-JumpListLinkDetails $details $entry.Lnk
                $details["TimeSource"] = $timeSource
                Add-TimelineEntry -Timestamp $ts -Source "JumpLists" -EventType "FileAccess" `
                    -Description "Jump list ($app): $path" `
                    -User $user -Details (Format-ArtifactDetails $details) `
                    -Artifact "RecentFiles" -RawPath $file.FullName
                $added++
            }
        }
        catch {
            $failed++
            Log-Warning "  Could not read jump list $($file.FullName): $($_.Exception.Message)"
        }
    }

    Log "  Jump lists: $added row(s)$(if ($noTime -gt 0) { " ($noTime DestList entr(ies) without an access time use the list file's time)" })$(if ($failed -gt 0) { "; $failed file(s) could not be read" })."
    return $added
}

function Parse-RecentFiles {
    Log "--- Parsing Recent Files (LNK Shortcuts, Jump Lists) ---"

    # Only the collection's own .lnk files -- never the analysis machine's Recent folders
    $lnkFiles = @(Find-ArtifactFiles -BasePath $InputPath -Extensions @(".lnk"))

    if ($lnkFiles.Count -eq 0) {
        Log-Warning "No .lnk files found in the collection."
    }
    else {
        Log "Found $($lnkFiles.Count) LNK file(s)"
    }

    # WScript.Shell resolves the target path; the rows are still written without it
    $shell = $null
    if ($lnkFiles.Count -gt 0) {
        try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop }
        catch { Log-Warning "  WScript.Shell unavailable ($($_.Exception.Message)) -- LNK target paths will be blank." }
    }

    $fromSource = 0
    $fromCopy = 0
    foreach ($lnk in $lnkFiles) {
        try {
            $targetPath = ""
            $arguments = ""
            $workDir = ""
            if ($shell) {
                $shortcut = $null
                try {
                    $shortcut = $shell.CreateShortcut($lnk.FullName)
                    $targetPath = $shortcut.TargetPath
                    $arguments = $shortcut.Arguments
                    $workDir = $shortcut.WorkingDirectory
                }
                catch { Log-Warning "  Could not resolve LNK target for $($lnk.Name) : $($_.Exception.Message)" }
                finally {
                    # Release COM object reference for this shortcut
                    if ($shortcut) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null }
                }
            }

            # Account from the collection's folder layout (e.g. UserActivity\<user>\RecentFiles)
            $user = Get-CollectionUser $lnk.FullName

            $details = "Target=$targetPath Args=$arguments WorkDir=$workDir"
            $header = $null
            try { $header = Read-LnkHeader $lnk.FullName }
            catch { Write-Verbose "Could not read LNK header of $($lnk.Name): $($_.Exception.Message)" }
            if ($header) {
                foreach ($pair in @(@("TargetCreatedUtc", $header.TargetCreated), @("TargetAccessedUtc", $header.TargetAccessed), @("TargetModifiedUtc", $header.TargetModified))) {
                    if ($pair[1]) { $details += " $($pair[0])=$($pair[1].ToString('yyyy-MM-dd HH:mm:ss'))" }
                }
                $details += " TargetSize=$($header.TargetSize)"
            }

            $label = $lnk.BaseName
            if ($targetPath) { $label = "$label -> $targetPath" }
            # A Recent-folder LNK is created when an item is first opened and updated when it is opened again
            $isRecent = $lnk.FullName -match '\\Recent(Files)?\\'
            $createdText = "LNK created"
            $modifiedText = "LNK modified"
            if ($isRecent) {
                $createdText = "LNK created (item first opened)"
                $modifiedText = "LNK modified (item last opened)"
            }

            # Original LNK file times from the manifest; the copy's creation time is the copy/extract time
            $src = Get-SourceFileTimes $lnk.FullName
            if ($src -and ($src.Created -or $src.Modified)) {
                if ($src.Created) {
                    Add-TimelineEntry -Timestamp $src.Created -Source "RecentFiles" -EventType "FileAccess" `
                        -Description "${createdText}: $label" `
                        -User $user `
                        -Details "$details TimeSource=original LNK file times" `
                        -Artifact "RecentFiles" -RawPath $lnk.FullName
                }
                if ($src.Modified) {
                    Add-TimelineEntry -Timestamp $src.Modified -Source "RecentFiles" -EventType "FileAccess" `
                        -Description "${modifiedText}: $label" `
                        -User $user `
                        -Details "$details TimeSource=original LNK file times" `
                        -Artifact "RecentFiles" -RawPath $lnk.FullName
                }
                $fromSource++
            }
            else {
                Add-TimelineEntry -Timestamp $lnk.LastWriteTimeUtc -Source "RecentFiles" -EventType "FileAccess" `
                    -Description "${modifiedText}: $label" `
                    -User $user `
                    -Details "$details TimeSource=collected copy LastWriteTime" `
                    -Artifact "RecentFiles" -RawPath $lnk.FullName
                $fromCopy++
            }
        }
        catch {
            Log-Warning "  Failed to parse LNK file $($lnk.Name) : $($_.Exception.Message)"
        }
    }

    if ($shell) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null }
    if ($lnkFiles.Count -gt 0) {
        Log "  LNK times: $fromSource file(s) with original file times, $fromCopy with the collected copy's last-write time only."
    }

    $null = Read-JumpLists
    Log "  Recent files parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 4. Registry Parser
# ----------------------------------------------------------
# True if the file starts with the given ASCII signature ("regf" for
# registry hives, "SQLite format 3" for SQLite databases)
function Test-FileSignature {
    param([string]$Path, [string]$Signature)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] $Signature.Length
            $read = $fs.Read($buf, 0, $buf.Length)
            return ($read -eq $buf.Length -and [System.Text.Encoding]::ASCII.GetString($buf) -eq $Signature)
        }
        finally { $fs.Close() }
    }
    catch { return $false }
}

# Offline hive file (SYSTEM, SOFTWARE, ...) in the collection: real hive
# files only; the shortest path wins (Registry\SYSTEM before any backup copy)
function Find-OfflineHiveFile {
    param([string]$Name)
    $candidates = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @($Name)) |
        Where-Object { -not $_.PSIsContainer -and $_.Name -eq $Name -and (Test-FileSignature -Path $_.FullName -Signature "regf") } |
        Sort-Object { $_.FullName.Length }
    return ($candidates | Select-Object -First 1)
}

# Load an offline hive under HKLM\<name> from a scratch copy in the work
# folder (plus any .LOG1/.LOG2 transaction logs, so reg load can replay a
# dirty hive). The collected file is never modified. Returns Name/TempDir/
# Root (open .NET RegistryKey) or $null. Always pair with Dismount-TimelineHive.
function Mount-TimelineHive {
    param([System.IO.FileInfo]$HiveFile, [string]$Prefix = "TEMP_TL")
    $hiveName = "$($Prefix)_$(Get-Random)"
    $tempDir = Join-Path (Get-ScratchFolder) "TimelineHive_$(Get-Random)"
    $loaded = $false
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        $tempHive = Join-Path $tempDir $HiveFile.Name
        Copy-Item -LiteralPath $HiveFile.FullName -Destination $tempHive -Force -ErrorAction Stop
        foreach ($logExt in @(".LOG1", ".LOG2")) {
            $logSrc = $HiveFile.FullName + $logExt
            if (Test-Path -LiteralPath $logSrc) {
                Copy-Item -LiteralPath $logSrc -Destination ($tempHive + $logExt) -Force -ErrorAction SilentlyContinue
            }
            elseif (Test-ManifestListsFile $logSrc) {
                Log-Warning "  Transaction log missing: $logSrc is in the collection manifest but not here -- the hive is loaded without it (changes not yet written to the hive are lost)"
            }
        }
        Log "  Loading hive: $($HiveFile.FullName)"
        Register-RunHive $hiveName
        $regLoadResult = & reg load "HKLM\$hiveName" $tempHive 2>&1
        if ($LASTEXITCODE -ne 0) {
            Unregister-RunHive $hiveName
            Log-Warning "  Could not load hive $($HiveFile.FullName) : $regLoadResult"
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            return $null
        }
        $loaded = $true
        # Use .NET RegistryKey directly (not the PowerShell provider) so every
        # handle can be closed explicitly -- open handles block the unload
        $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($hiveName)
        return [PSCustomObject]@{ Name = $hiveName; TempDir = $tempDir; Root = $root }
    }
    catch {
        Log-Warning "  Could not load hive $($HiveFile.FullName) : $($_.Exception.Message)"
        if ($loaded) { return [PSCustomObject]@{ Name = $hiveName; TempDir = $tempDir; Root = $null } }
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        return $null
    }
}

# Close the root key, unload a hive loaded by Mount-TimelineHive and delete
# its temp copy
function Dismount-TimelineHive {
    param($Mount)
    if (-not $Mount) { return }
    if ($Mount.Root) {
        try { $Mount.Root.Close() }
        catch { Write-Verbose "Could not close root key of hive $($Mount.Name): $($_.Exception.Message)" }
    }
    # Force release of any lingering references to the hive before unloading
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    [gc]::Collect()
    $unloaded = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $null = & reg unload "HKLM\$($Mount.Name)" 2>&1
        if ($LASTEXITCODE -eq 0) { $unloaded = $true; break }
        Start-Sleep -Milliseconds 1000
    }
    if ($unloaded) {
        Log "  Unloaded hive: $($Mount.Name)"
        Unregister-RunHive $Mount.Name
        Remove-Item -LiteralPath $Mount.TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        # Tried again at the end of the run, before the work folder is deleted
        Log-Warning "  Failed to unload hive $($Mount.Name) -- may need manual cleanup via: reg unload HKLM\$($Mount.Name) (temp copy: $($Mount.TempDir))"
    }
}

# Value names of an MRU key, most recent first. MRUList (RunMRU) is a string
# of value-name letters; MRUListEx (RecentDocs, BagMRU) is a list of DWORD
# value numbers ending in 0xFFFFFFFF. Empty if the key has no MRU list.
function Get-RegistryMruOrder {
    param([Microsoft.Win32.RegistryKey]$Key)
    $order = @()
    $mruEx = $Key.GetValue("MRUListEx")
    if ($mruEx -is [byte[]]) {
        for ($i = 0; $i + 3 -lt $mruEx.Length; $i += 4) {
            $n = [BitConverter]::ToUInt32($mruEx, $i)
            if ($n -eq [uint32]::MaxValue) { break }
            $order += [string]$n
        }
        return $order
    }
    $mru = $Key.GetValue("MRUList")
    if ($mru -is [string]) {
        foreach ($ch in $mru.ToCharArray()) { $order += [string]$ch }
    }
    return $order
}

# Timestamp + Details note for an entry of an MRU-ordered key. The key's
# last-write time only belongs to the most recent entry (position 1); older
# entries were used before it. Position 0 = not in the MRU list.
function Get-MruEntryTime {
    param($KeyTime, [datetime]$FallbackTime, [int]$Position, [string]$KeyLabel = "key")
    $posText = if ($Position -gt 0) { "MRU position $Position" } else { "MRU position unknown" }
    if ($null -eq $KeyTime) {
        return [PSCustomObject]@{ Time = $FallbackTime; Note = "Time=hive file time ($KeyLabel last-write time unavailable); $posText" }
    }
    if ($Position -eq 1) { $note = "Time=$KeyLabel last write; $posText (most recent entry)" }
    elseif ($Position -gt 1) { $note = "Time=$KeyLabel last write; $posText (older entry: used before this time)" }
    else { $note = "Time=$KeyLabel last write; $posText (used at or before this time)" }
    return [PSCustomObject]@{ Time = $KeyTime; Note = $note }
}

# Null-terminated UTF-16 string at an offset of binary registry data (e.g.
# the file/folder name at the start of a RecentDocs value); "" if none
function Get-Utf16ZString {
    param([byte[]]$Data, [int]$Offset = 0)
    if ($null -eq $Data -or $Offset -lt 0) { return "" }
    for ($i = $Offset; $i -lt $Data.Length - 1; $i += 2) {
        if ($Data[$i] -eq 0 -and $Data[$i + 1] -eq 0) {
            return [System.Text.Encoding]::Unicode.GetString($Data, $Offset, $i - $Offset)
        }
    }
    return ""
}

# Parse the user artifacts in one loaded NTUSER.DAT (root key of the hive):
# TypedPaths, TypedURLs, RunMRU, UserAssist, RecentDocs, the per-user Run
# keys, WordWheelQuery, Office (Read-OfficeUserKeys), the Remote Desktop
# client (Read-RdpClientHistory) and Open/Save dialogs (Read-ComDlg32Mru).
# MRU-style keys record only one time -- the key's last write, which
# belongs to the most recent entry. Returns $true if any of the keys exist.
function Read-NtUserHive {
    param(
        [Microsoft.Win32.RegistryKey]$HiveRoot,
        [string]$User,
        [string]$RawPath,
        [datetime]$FallbackTime
    )
    $found = $false
    # Never expand %variables% with the analyst machine's environment
    $noExpand = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames

    # --- TypedPaths (Explorer address bar; url1 = most recent) ---
    try {
        $key = $HiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
        if ($key) {
            try {
                $found = $true
                $keyTime = Get-RegistryKeyLastWriteUtc $key
                foreach ($val in $key.GetValueNames()) {
                    if ($val -eq "") { continue }
                    $pos = 0
                    if ($val -match '^url(\d+)$') { $pos = [int]$Matches[1] }
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos
                    $typedPath = $key.GetValue($val, $null, $noExpand)
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-TypedPaths" -EventType "FileAccess" `
                        -Description "Explorer typed path: $typedPath" `
                        -User $User -Details "ValueName=$val; $($t.Note)" `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse TypedPaths: $($_.Exception.Message)" }

    # --- TypedURLs (url1 = most recent; TypedURLsTime holds a FILETIME per
    #     entry on Windows 8+, which is used when present) ---
    try {
        $key = $HiveRoot.OpenSubKey("Software\Microsoft\Internet Explorer\TypedURLs")
        if ($key) {
            $timeKey = $null
            try {
                $found = $true
                $keyTime = Get-RegistryKeyLastWriteUtc $key
                $timeKey = $HiveRoot.OpenSubKey("Software\Microsoft\Internet Explorer\TypedURLsTime")
                foreach ($val in $key.GetValueNames()) {
                    if ($val -eq "") { continue }
                    $pos = 0
                    if ($val -match '^url(\d+)$') { $pos = [int]$Matches[1] }
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos
                    if ($timeKey) {
                        $ftData = $timeKey.GetValue($val)
                        if ($ftData -is [byte[]] -and $ftData.Length -ge 8) {
                            $ft = [BitConverter]::ToInt64($ftData, 0)
                            if ($ft -gt 0) {
                                try { $t = [PSCustomObject]@{ Time = [datetime]::FromFileTimeUtc($ft); Note = "Time=TypedURLsTime (when typed); MRU position $pos" } }
                                catch { Write-Verbose "Invalid TypedURLsTime for $val, using key time: $($_.Exception.Message)" }
                            }
                        }
                    }
                    $url = $key.GetValue($val, $null, $noExpand)
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-TypedURLs" -EventType "NetworkConnection" `
                        -Description "IE typed URL: $url" `
                        -User $User -Details "ValueName=$val; $($t.Note)" `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally {
                $key.Close()
                if ($timeKey) { $timeKey.Close() }
            }
        }
    }
    catch { Log-Warning "    Failed to parse TypedURLs: $($_.Exception.Message)" }

    # --- RunMRU (Win+R dialog; MRUList letters, first = most recent) ---
    try {
        $key = $HiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
        if ($key) {
            try {
                $found = $true
                $keyTime = Get-RegistryKeyLastWriteUtc $key
                $order = @(Get-RegistryMruOrder $key)
                foreach ($val in $key.GetValueNames()) {
                    if ($val -eq "" -or $val -eq "MRUList") { continue }
                    $cmd = [string]$key.GetValue($val, $null, $noExpand)
                    # Commands are stored with a trailing "\1"
                    if ($cmd.EndsWith("\1")) { $cmd = $cmd.Substring(0, $cmd.Length - 2) }
                    $pos = [array]::IndexOf($order, $val) + 1
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-RunMRU" -EventType "Execution" `
                        -Description "Run dialog command: $cmd" `
                        -User $User -Details "MRUEntry=$val; $($t.Note)" `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse RunMRU: $($_.Exception.Message)" }

    # --- UserAssist (ROT13 decoded; each value has its own last-run FILETIME) ---
    try {
        $userAssistKey = $HiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
        if ($userAssistKey) {
            $found = $true
            # MatchEvaluator (a scriptblock as -replace replacement needs PowerShell 6+)
            $rot13 = [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $c = [int][char]$m.Value
                $base = if ($c -ge 97) { 97 } else { 65 }
                [string][char]((($c - $base + 13) % 26) + $base)
            }
            $badTimeCount = 0
            foreach ($guidName in $userAssistKey.GetSubKeyNames()) {
                $guidKey = $userAssistKey.OpenSubKey($guidName)
                if (-not $guidKey) { continue }
                $countKey = $guidKey.OpenSubKey("Count")
                if ($countKey) {
                    foreach ($val in $countKey.GetValueNames()) {
                        if ($val -ne "") {
                            # ROT13 decode the value name
                            $decoded = [regex]::Replace($val, '[a-zA-Z]', $rot13)

                            # Parse the binary data for run count and last run time
                            $data = $countKey.GetValue($val)
                            $runCount = 0
                            $lastRun = [datetime]::MinValue
                            if ($data -is [byte[]] -and $data.Length -ge 72) {
                                $runCount = [BitConverter]::ToInt32($data, 4)
                                $fileTime = [BitConverter]::ToInt64($data, 60)
                                if ($fileTime -gt 0) {
                                    try { $lastRun = [datetime]::FromFileTimeUtc($fileTime) }
                                    catch { $badTimeCount++; $badTimeError = $_.Exception.Message }
                                }
                            }

                            if ($lastRun -gt [datetime]::MinValue) {
                                Add-TimelineEntry -Timestamp $lastRun -Source "Registry-UserAssist" -EventType "Execution" `
                                    -Description "UserAssist execution: $decoded" `
                                    -User $User -Details "RunCount=$runCount GUID=$guidName" `
                                    -Artifact "Registry" -RawPath $RawPath
                            }
                        }
                    }
                    $countKey.Close()
                }
                $guidKey.Close()
            }
            if ($badTimeCount -gt 0) { Log-Warning "    $badTimeCount UserAssist entr(ies) skipped: invalid last-run time (last error: $badTimeError)" }
            $userAssistKey.Close()
        }
    }
    catch { Log-Warning "    Failed to parse UserAssist: $($_.Exception.Message)" }

    # --- RecentDocs (MRUListEx; extension subkeys such as .docx and Folder
    #     keep their own MRU order and last-write time) ---
    try {
        $key = $HiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
        if ($key) {
            try {
                $found = $true
                $keyTime = Get-RegistryKeyLastWriteUtc $key

                # Entries of the extension subkeys: name -> subkey, position, subkey time
                $extEntries = @{}
                foreach ($subName in $key.GetSubKeyNames()) {
                    $sub = $key.OpenSubKey($subName)
                    if (-not $sub) { continue }
                    try {
                        $subTime = Get-RegistryKeyLastWriteUtc $sub
                        $subOrder = @(Get-RegistryMruOrder $sub)
                        foreach ($val in $sub.GetValueNames()) {
                            if ($val -notmatch '^\d+$') { continue }
                            $data = $sub.GetValue($val)
                            if (-not ($data -is [byte[]])) { continue }
                            $docName = Get-Utf16ZString $data
                            if (-not $docName -or $extEntries.ContainsKey($docName)) { continue }
                            $extEntries[$docName] = [PSCustomObject]@{
                                SubKey    = $subName
                                ValueName = $val
                                Position  = [array]::IndexOf($subOrder, $val) + 1
                                Time      = $subTime
                                Used      = $false
                            }
                        }
                    }
                    finally { $sub.Close() }
                }

                $order = @(Get-RegistryMruOrder $key)
                foreach ($val in $key.GetValueNames()) {
                    if ($val -notmatch '^\d+$') { continue }
                    $data = $key.GetValue($val)
                    if (-not ($data -is [byte[]])) { continue }
                    $docName = Get-Utf16ZString $data
                    if (-not $docName) { continue }
                    $pos = [array]::IndexOf($order, $val) + 1
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos
                    $note = $t.Note
                    $ext = $extEntries[$docName]
                    if ($ext) {
                        $ext.Used = $true
                        # The extension subkey's time is exact for its newest entry and
                        # a tighter upper bound than the root key's time for the others
                        if ($pos -ne 1 -and $null -ne $ext.Time) {
                            $t = Get-MruEntryTime -KeyTime $ext.Time -FallbackTime $FallbackTime -Position $ext.Position -KeyLabel "RecentDocs\$($ext.SubKey) key"
                            $note = "$($t.Note); overall MRU position $pos"
                        }
                    }
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-RecentDocs" -EventType "FileAccess" `
                        -Description "Recent document: $docName" `
                        -User $User -Details "MRUIndex=$val; $note" `
                        -Artifact "Registry" -RawPath $RawPath
                }

                # Entries that only remain in an extension subkey
                foreach ($docName in @($extEntries.Keys)) {
                    $ext = $extEntries[$docName]
                    if ($ext.Used) { continue }
                    $t = Get-MruEntryTime -KeyTime $ext.Time -FallbackTime $FallbackTime -Position $ext.Position -KeyLabel "RecentDocs\$($ext.SubKey) key"
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-RecentDocs" -EventType "FileAccess" `
                        -Description "Recent document: $docName" `
                        -User $User -Details "MRUIndex=$($ext.SubKey)\$($ext.ValueName); $($t.Note)" `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse RecentDocs: $($_.Exception.Message)" }

    # --- Per-user Run keys (persistence). The key's last-write time is when
    #     the key last changed; an individual value may be older. ---
    $runKeyPaths = @(
        "Software\Microsoft\Windows\CurrentVersion\Run",
        "Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($runPath in $runKeyPaths) {
        try {
            $key = $HiveRoot.OpenSubKey($runPath)
            if (-not $key) { continue }
            try {
                $found = $true
                $ts = Get-RegistryKeyLastWriteUtc $key
                $timeNote = "Time=key last write (key last changed; this value may be older)"
                if ($null -eq $ts) {
                    $ts = $FallbackTime
                    $timeNote = "Time=hive file time (key last-write time unavailable)"
                }
                foreach ($val in $key.GetValueNames()) {
                    $runCmd = $key.GetValue($val, $null, $noExpand)
                    if ($runCmd -is [byte[]]) { $runCmd = [System.Text.Encoding]::Unicode.GetString($runCmd).TrimEnd([char]0) }
                    $runName = if ($val -eq "") { "(Default)" } else { $val }
                    Add-TimelineEntry -Timestamp $ts -Source "Registry-UserRunKey" -EventType "PersistenceChange" `
                        -Description "User Run key: $runName = $runCmd" `
                        -User $User -Details "Key=HKCU\$runPath; $timeNote" `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
        catch { Log-Warning "    Failed to parse $runPath : $($_.Exception.Message)" }
    }

    # --- WordWheelQuery (Explorer search box terms; MRUListEx, values are
    #     UTF-16 text) ---
    try {
        $wordWheelPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        $key = $HiveRoot.OpenSubKey($wordWheelPath)
        if ($key) {
            try {
                $found = $true
                $keyTime = Get-RegistryKeyLastWriteUtc $key
                $order = @(Get-RegistryMruOrder $key)
                foreach ($val in $key.GetValueNames()) {
                    if ($val -notmatch '^\d+$') { continue }
                    $data = $key.GetValue($val)
                    if (-not ($data -is [byte[]])) { continue }
                    $term = Get-Utf16ZString $data
                    if (-not $term) { $term = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }
                    if (-not $term) { continue }
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position ([array]::IndexOf($order, $val) + 1)
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-WordWheelQuery" -EventType "FileAccess" `
                        -Description "Explorer search: $term" `
                        -User $User `
                        -Details (Format-ArtifactDetails ([ordered]@{ MRUIndex = $val; Key = "HKCU\$wordWheelPath"; Time = ($t.Note -replace '^Time=', '') })) `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse WordWheelQuery: $($_.Exception.Message)" }

    # --- Office (trusted documents, File/Place MRU, Outlook attachment
    #     folder), Remote Desktop client and Open/Save dialog history ---
    try { if (Read-OfficeUserKeys -HiveRoot $HiveRoot -User $User -RawPath $RawPath -FallbackTime $FallbackTime) { $found = $true } }
    catch { Log-Warning "    Failed to parse Office keys: $($_.Exception.Message)" }
    try { if (Read-RdpClientHistory -HiveRoot $HiveRoot -User $User -RawPath $RawPath -FallbackTime $FallbackTime) { $found = $true } }
    catch { Log-Warning "    Failed to parse Terminal Server Client: $($_.Exception.Message)" }
    if (Read-ComDlg32Mru -HiveRoot $HiveRoot -User $User -RawPath $RawPath -FallbackTime $FallbackTime) { $found = $true }

    return $found
}

# Root folder GUIDs commonly seen as ShellBags root items
$script:ShellBagGuidNames = @{
    "20D04FE0-3AEA-1069-A2D8-08002B30309D" = "My Computer"
    "59031A47-3F72-44A7-89C5-5595FE6B30EE" = "User Profile"
    "F02C1A0D-BE21-4350-88B0-7367FC96EF3C" = "Network"
    "645FF040-5081-101B-9F08-00AA002F954E" = "Recycle Bin"
    "031E4825-7B94-4DC3-B131-E946B44C8DD5" = "Libraries"
    "26EE0668-A00A-44D7-9371-BEB064C98683" = "Control Panel"
    "21EC2020-3AEA-1069-A2DD-08002B30309D" = "All Control Panel Items"
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641" = "Desktop"
    "F874310E-B6B7-47DC-BC84-B9E6B38F5903" = "Home"
    "679F85CB-0220-4080-B29B-5540CC05AAB6" = "Quick access"
    "088E3905-0323-4B02-9826-5D99428E115F" = "Downloads"
    "374DE290-123F-4565-9164-39C4925E467B" = "Downloads"
    "D3162B92-9365-467A-956B-92703ACA08AF" = "Documents"
    "A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0" = "Documents"
    "24AD3AD4-A569-4530-98E1-AB02F9417AA8" = "Pictures"
    "3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA" = "Pictures"
    "3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE" = "Music"
    "1CF1260C-4DD0-4EBB-811F-33C572699FDE" = "Music"
    "F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A" = "Videos"
    "A0953C92-50DC-43BF-BE83-3742FED03C9C" = "Videos"
    "018D5C66-4533-4307-9B53-224DE2ED1FE6" = "OneDrive"
}

# Display name of one ShellBags shell item (a binary BagMRU value): root
# folder GUIDs, drive letters, items with a 0xBEEF0004 extension block (long
# Unicode name: file entries, user-folder delegates), ZIP folder contents,
# file entries without a long name (short name) and network locations.
# Others are shown by type number.
function Get-ShellItemName {
    param([byte[]]$Data)
    if ($null -eq $Data -or $Data.Length -lt 3) { return [PSCustomObject]@{ Name = "[empty shell item]"; IsVolume = $false } }
    $type = [int]$Data[2]

    # ZIP folder content item: the class byte is meaningless; 0x0010 at offset
    # 32, a UTF-16 date string at 36, name length (chars) at 84, name at 92
    $zipLike = ($Data.Length -ge 96 -and [BitConverter]::ToUInt16($Data, 32) -eq 0x10 -and
                $Data[37] -eq 0 -and $Data[36] -ge 0x20 -and $Data[36] -lt 0x7F)

    # Root folder: GUID at offset 4
    if ($type -eq 0x1F -and $Data.Length -ge 20 -and -not $zipLike) {
        $guid = (New-Object System.Guid (,[byte[]]$Data[4..19])).ToString().ToUpper()
        $name = $script:ShellBagGuidNames[$guid]
        if (-not $name) { $name = "{$guid}" }
        return [PSCustomObject]@{ Name = $name; IsVolume = $false }
    }

    # Volume: drive string ("C:\") at offset 3
    if (($type -band 0x70) -eq 0x20 -and $Data.Length -gt 5) {
        $end = [Array]::IndexOf($Data, [byte]0, 3)
        if ($end -gt 3) {
            $drive = [System.Text.Encoding]::ASCII.GetString($Data, 3, $end - 3)
            if ($drive -match '^[A-Za-z]:\\?$') { return [PSCustomObject]@{ Name = $drive.TrimEnd('\') + '\'; IsVolume = $true } }
        }
    }

    # 0xBEEF0004 extension block (bytes 04 00 EF BE, 4 bytes into the block):
    # long name after a version-dependent header
    $i = if ($Data.Length -gt 6) { [Array]::IndexOf($Data, [byte]0xEF, 6) } else { -1 }
    while ($i -ge 6 -and $i + 1 -lt $Data.Length) {
        if ($Data[$i + 1] -eq 0xBE -and $Data[$i - 1] -eq 0x00 -and $Data[$i - 2] -eq 0x04) {
            $ext = $i - 6
            $version = [BitConverter]::ToUInt16($Data, $ext + 2)
            $off = $ext + 18
            if ($version -ge 7) { $off += 18 }
            if ($version -ge 3) { $off += 2 }
            if ($version -ge 9) { $off += 4 }
            if ($version -ge 8) { $off += 4 }
            $longName = Get-Utf16ZString -Data $Data -Offset $off
            if ($longName) { return [PSCustomObject]@{ Name = $longName; IsVolume = $false } }
            break
        }
        $i = [Array]::IndexOf($Data, [byte]0xEF, $i + 1)
    }

    if ($zipLike) {
        $nameChars = [BitConverter]::ToInt32($Data, 84)
        if ($nameChars -gt 0 -and 92 + $nameChars * 2 -le $Data.Length) {
            $zipName = [System.Text.Encoding]::Unicode.GetString($Data, 92, $nameChars * 2).TrimEnd([char]0)
            if ($zipName) { return [PSCustomObject]@{ Name = $zipName; IsVolume = $false } }
        }
    }

    # Property-store items (e.g. shared folders, devices): "1SPS" storage for
    # FMTID {B725F130-47EF-101A-A5F1-02608C9EEBAC}, property 10 (ItemNameDisplay)
    $fmtid = [byte[]](0x31, 0x53, 0x50, 0x53, 0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC)
    for ($i = 0; $i + $fmtid.Length -le $Data.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $fmtid.Length; $j++) { if ($Data[$i + $j] -ne $fmtid[$j]) { $match = $false; break } }
        if (-not $match) { continue }
        # Values: [size 4][property id 4][reserved 1][VT 2][pad 2][VT_LPWSTR: chars 4][UTF-16]
        $p = $i + $fmtid.Length
        while ($p + 17 -le $Data.Length) {
            $valSize = [BitConverter]::ToInt32($Data, $p)
            if ($valSize -le 0) { break }
            $propId = [BitConverter]::ToInt32($Data, $p + 4)
            $vt = [BitConverter]::ToUInt16($Data, $p + 9)
            if ($propId -eq 10 -and $vt -eq 0x1F) {
                $chars = [BitConverter]::ToInt32($Data, $p + 13)
                if ($chars -gt 0 -and $p + 17 + $chars * 2 -le $Data.Length) {
                    $displayName = [System.Text.Encoding]::Unicode.GetString($Data, $p + 17, $chars * 2).TrimEnd([char]0)
                    if ($displayName) { return [PSCustomObject]@{ Name = $displayName; IsVolume = $false } }
                }
            }
            $p += $valSize
        }
        break
    }

    # File entry without a long name: primary (short) name at offset 14
    if (($type -band 0x70) -eq 0x30 -and $Data.Length -gt 15) {
        if ($type -band 0x04) { $short = Get-Utf16ZString -Data $Data -Offset 14 }
        else {
            $end = [Array]::IndexOf($Data, [byte]0, 14)
            $short = if ($end -gt 14) { [System.Text.Encoding]::ASCII.GetString($Data, 14, $end - 14) } else { "" }
        }
        if ($short) { return [PSCustomObject]@{ Name = $short; IsVolume = $false } }
    }

    # Network location (\\server\share): ASCII string at offset 5
    if (($type -band 0x70) -eq 0x40 -and $Data.Length -gt 6) {
        $end = [Array]::IndexOf($Data, [byte]0, 5)
        if ($end -gt 5) { return [PSCustomObject]@{ Name = [System.Text.Encoding]::ASCII.GetString($Data, 5, $end - 5); IsVolume = $false } }
    }

    return [PSCustomObject]@{ Name = ("[shell item type 0x{0:X2}]" -f $type); IsVolume = $false }
}

# Walk one BagMRU key and its children. A BagMRU key's last-write time
# belongs to its most recently opened child (MRU position 1). Returns the
# number of rows added.
function Read-ShellBagNode {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$KeyPath,
        [string]$ParentPath,
        [int]$Depth,
        [string]$User,
        [string]$RawPath,
        [datetime]$FallbackTime
    )
    if ($Depth -gt 64) { return 0 }
    $count = 0
    $keyTime = Get-RegistryKeyLastWriteUtc $Key
    $order = @(Get-RegistryMruOrder $Key)
    foreach ($val in $Key.GetValueNames()) {
        if ($val -notmatch '^\d+$') { continue }
        $data = $Key.GetValue($val)
        if (-not ($data -is [byte[]])) { continue }
        $item = Get-ShellItemName $data
        if ($item.IsVolume -or -not $ParentPath) { $folderPath = $item.Name }
        else { $folderPath = $ParentPath.TrimEnd('\') + '\' + $item.Name }
        $pos = [array]::IndexOf($order, $val) + 1
        $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos -KeyLabel "parent BagMRU key"
        Add-TimelineEntry -Timestamp $t.Time -Source "Registry-ShellBags" -EventType "FileAccess" `
            -Description "ShellBag folder: $folderPath" `
            -User $User -Details "Key=$KeyPath\$val; $($t.Note)" `
            -Artifact "Registry" -RawPath $RawPath
        $count++
        $child = $Key.OpenSubKey($val)
        if ($child) {
            try {
                $count += Read-ShellBagNode -Key $child -KeyPath "$KeyPath\$val" -ParentPath $folderPath -Depth ($Depth + 1) `
                    -User $User -RawPath $RawPath -FallbackTime $FallbackTime
            }
            finally { $child.Close() }
        }
    }
    return $count
}

# ShellBags (folders opened in Explorer) from one loaded UsrClass.dat.
# Returns the number of rows added.
function Read-ShellBags {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$User, [string]$RawPath, [datetime]$FallbackTime)
    $bagMru = $HiveRoot.OpenSubKey("Local Settings\Software\Microsoft\Windows\Shell\BagMRU")
    if (-not $bagMru) { return 0 }
    try {
        return (Read-ShellBagNode -Key $bagMru -KeyPath "BagMRU" -ParentPath "" -Depth 0 -User $User -RawPath $RawPath -FallbackTime $FallbackTime)
    }
    finally { $bagMru.Close() }
}

# Text of a registry value for Description/Details: REG_MULTI_SZ entries
# joined with "; ", binary data as hex, %variables% not expanded, anything
# after an embedded NUL dropped. "" if the value does not exist.
function Get-RegistryValueText {
    param([Microsoft.Win32.RegistryKey]$Key, [string]$Name)
    $value = $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -eq $value) { return "" }
    if ($value -is [byte[]]) { return [BitConverter]::ToString($value).Replace("-", "") }
    if ($value -is [string[]]) { return ((@($value) | ForEach-Object { $_.Split([char]0)[0].Trim() } | Where-Object { $_ }) -join "; ") }
    return "$value".Split([char]0)[0].Trim()
}

# Number from DWORD/QWORD data or from text such as "0x200" or "512" (some
# tools write GlobalFlag as a string); $null otherwise
function ConvertTo-RegistryNumber {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [long]$Value }
    $text = "$Value".Split([char]0)[0].Trim()
    if ($text -match '^0x([0-9A-Fa-f]{1,16})$') { return [Convert]::ToInt64($Matches[1], 16) }
    $number = 0L
    if ([long]::TryParse($text, [ref]$number)) { return $number }
    return $null
}

# FILETIME stored in value data -> UTC [datetime]; $null when 0, invalid or
# later than $Latest (when given)
function ConvertFrom-RegistryFileTime {
    param([long]$FileTime, $Latest)
    if ($FileTime -le 0) { return $null }
    try { $t = [datetime]::FromFileTimeUtc($FileTime) }
    catch {
        Write-Verbose "Invalid FILETIME $FileTime : $($_.Exception.Message)"
        return $null
    }
    if ($null -ne $Latest -and $t -gt $Latest) { return $null }
    return $t
}

# Timestamp + Details note for a value that has no time of its own: the
# key's last-write time (when the key last changed; the value may be older),
# else the hive file time
function Get-RegistryKeyTime {
    param([Microsoft.Win32.RegistryKey]$Key, [datetime]$FallbackTime, [string]$KeyLabel = "key")
    $keyTime = Get-RegistryKeyLastWriteUtc $Key
    if ($null -eq $keyTime) {
        return [PSCustomObject]@{ Time = $FallbackTime; Note = "hive file time ($KeyLabel last-write time unavailable)" }
    }
    return [PSCustomObject]@{ Time = $keyTime; Note = "$KeyLabel last write (key last changed; this value may be older)" }
}

# Path of an absolute shell item ID list (PIDL) in binary registry data,
# from the given offset: items are [uint16 size][data] up to a size of 0.
# Names come from Get-ShellItemName and are joined like ShellBags paths (a
# drive item starts the path again). "" if no item could be read.
function ConvertFrom-ShellItemIdList {
    param([byte[]]$Data, [int]$Offset = 0)
    $path = ""
    if ($null -eq $Data) { return $path }
    $pos = $Offset
    $items = 0
    while ($pos + 2 -le $Data.Length -and $items -lt 64) {
        $size = [int][BitConverter]::ToUInt16($Data, $pos)
        if ($size -lt 3 -or $pos + $size -gt $Data.Length) { break }
        try { $item = Get-ShellItemName ([byte[]]$Data[$pos..($pos + $size - 1)]) }
        catch {
            Write-Verbose "Unreadable shell item at offset $pos, path cut there: $($_.Exception.Message)"
            break
        }
        if ($item.IsVolume -or -not $path) { $path = $item.Name }
        else { $path = $path.TrimEnd('\') + '\' + $item.Name }
        $pos += $size
        $items++
    }
    return $path
}

# Rows for one Office TrustRecords key (see Read-OfficeUserKeys). Returns
# the number of rows added.
function Add-OfficeTrustRecordRows {
    param([Microsoft.Win32.RegistryKey]$Key, [string]$KeyPath, [string]$App, [string]$Version, [string]$User, [string]$RawPath, [datetime]$FallbackTime)
    $added = 0
    $keyTime = Get-RegistryKeyTime -Key $Key -FallbackTime $FallbackTime -KeyLabel "TrustRecords key"
    foreach ($doc in $Key.GetValueNames()) {
        $data = $Key.GetValue($doc)
        if ($doc -eq "" -or -not ($data -is [byte[]]) -or $data.Length -lt 8) { continue }
        $n = $data.Length
        $macros = ($n -ge 12 -and $data[$n - 4] -eq 0xFF -and $data[$n - 3] -eq 0xFF -and $data[$n - 2] -eq 0xFF -and $data[$n - 1] -eq 0x7F)
        $t = $keyTime
        $trusted = ConvertFrom-RegistryFileTime -FileTime ([BitConverter]::ToInt64($data, 0))
        if ($trusted) { $t = [PSCustomObject]@{ Time = $trusted; Note = "TrustRecords FILETIME (when the user trusted the document)" } }
        # Office records local documents with "/" (e.g. %USERPROFILE%/Downloads/x.docm):
        # Path uses "\" like other rows; URLs (https://...) are kept as they are
        $path = if ($doc -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $doc } else { $doc.Replace('/', '\') }
        $details = Format-ArtifactDetails ([ordered]@{
            App      = $App
            Version  = $Version
            Path     = $path
            Document = $doc
            Trust    = $(if ($macros) { "macros (active content) enabled" } else { "editing enabled" })
            Data     = [BitConverter]::ToString($data).Replace("-", "")
            Key      = $KeyPath
            Time     = $t.Note
        })
        if ($macros) {
            Add-TimelineEntry -Timestamp $t.Time -Source "Registry-TrustRecords" -EventType "Execution" `
                -Description "Office macros enabled on document ($App): $path" `
                -User $User -Details $details -Artifact "Registry" -RawPath $RawPath
        }
        else {
            Add-TimelineEntry -Timestamp $t.Time -Source "Registry-TrustRecords" -EventType "FileAccess" `
                -Description "Office editing enabled on document ($App): $path" `
                -User $User -Details $details -Artifact "Registry" -RawPath $RawPath
        }
        $added++
    }
    return $added
}

# Rows for one Office File MRU / Place MRU key (see Read-OfficeUserKeys).
# $Seen holds the items already added for this app, so an item listed in
# both the per-account and the older list is added once. Returns the number
# of rows added.
function Add-OfficeMruRows {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$KeyPath,
        [string]$App,
        [string]$Version,
        [string]$Account,
        [string]$Kind,
        [hashtable]$Seen,
        [string]$User,
        [string]$RawPath,
        [datetime]$FallbackTime
    )
    $added = 0
    $keyTime = Get-RegistryKeyLastWriteUtc $Key
    foreach ($val in $Key.GetValueNames()) {
        if ($val -notmatch '^Item (\d+)$') { continue }
        $pos = [int]$Matches[1]
        $text = Get-RegistryValueText $Key $val
        if (-not $text) { continue }
        $fields = ""
        $itemPath = $text
        if ($text -match '^((?:\[[^\]]*\])+)\*(.+)$') {
            $fields = $Matches[1]
            $itemPath = $Matches[2]
        }
        $flags = if ($fields -match '\[F([0-9A-Fa-f]+)\]') { $Matches[1] } else { "" }
        $t = $null
        if ($fields -match '\[T([0-9A-Fa-f]{16})\]') {
            $opened = ConvertFrom-RegistryFileTime -FileTime ([Convert]::ToInt64($Matches[1], 16))
            if ($opened) { $t = [PSCustomObject]@{ Time = $opened; Note = "MRU item time (when the item was last opened)" } }
        }
        if (-not $t) {
            $mru = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos
            $t = [PSCustomObject]@{ Time = $mru.Time; Note = $mru.Note -replace '^Time=', '' }
        }
        $seenKey = "$Kind`t$itemPath`t$($t.Time.Ticks)"
        if ($Seen.ContainsKey($seenKey)) { continue }
        $Seen[$seenKey] = $true
        Add-TimelineEntry -Timestamp $t.Time -Source "Registry-OfficeMRU" -EventType "FileAccess" `
            -Description "Office recent $Kind ($App): $itemPath" `
            -User $User `
            -Details (Format-ArtifactDetails ([ordered]@{ App = $App; Version = $Version; Item = $val; Flags = $flags; Account = $Account; Key = $KeyPath; Time = $t.Note })) `
            -Artifact "Registry" -RawPath $RawPath
        $added++
    }
    return $added
}

# Office keys of one loaded NTUSER.DAT (Software\Microsoft\Office\<version>
# \<app>, e.g. 16.0\Word):
#   Security\Trusted Documents\TrustRecords  documents the user trusted.
#       Value name = the document as Office recorded it (often
#       "%USERPROFILE%/Downloads/x.docm"). The data starts with a FILETIME
#       (UTC: when it was trusted) and ends with FF FF FF 7F when macros
#       (active content) were enabled; otherwise only editing was enabled
#       (the document left Protected View).
#   User MRU\<account>\File MRU and Place MRU, and the older File MRU and
#       Place MRU: "Item N" = "[F<flags>][T<FILETIME hex>][O<...>]*<path>",
#       T = when the item was last opened (UTC). Place MRU lists folders.
#   Outlook\Security OutlookSecureTempFolder: the folder Outlook copies
#       opened attachments to (Content.Outlook); one Snapshot row.
# Returns $true if the Office key exists.
function Read-OfficeUserKeys {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$User, [string]$RawPath, [datetime]$FallbackTime)
    $officeKey = $HiveRoot.OpenSubKey("Software\Microsoft\Office")
    if (-not $officeKey) { return $false }
    try {
        foreach ($version in $officeKey.GetSubKeyNames()) {
            if ($version -notmatch '^\d+\.\d+$') { continue }
            $versionKey = $officeKey.OpenSubKey($version)
            if (-not $versionKey) { continue }
            try {
                foreach ($app in $versionKey.GetSubKeyNames()) {
                    $appPath = "HKCU\Software\Microsoft\Office\$version\$app"
                    try {
                        $key = $versionKey.OpenSubKey("$app\Security\Trusted Documents\TrustRecords")
                        if ($key) {
                            try {
                                $null = Add-OfficeTrustRecordRows -Key $key -KeyPath "$appPath\Security\Trusted Documents\TrustRecords" `
                                    -App $app -Version $version -User $User -RawPath $RawPath -FallbackTime $FallbackTime
                            }
                            finally { $key.Close() }
                        }
                    }
                    catch { Log-Warning "    Failed to parse Office TrustRecords ($version\$app): $($_.Exception.Message)" }

                    try {
                        # Per-account lists (Office 2013+) first, then the older lists
                        $mruKeys = @()
                        $userMru = $versionKey.OpenSubKey("$app\User MRU")
                        if ($userMru) {
                            try {
                                foreach ($account in $userMru.GetSubKeyNames()) {
                                    $mruKeys += , @("$app\User MRU\$account\File MRU", $account, "file")
                                    $mruKeys += , @("$app\User MRU\$account\Place MRU", $account, "folder")
                                }
                            }
                            finally { $userMru.Close() }
                        }
                        $mruKeys += , @("$app\File MRU", "", "file")
                        $mruKeys += , @("$app\Place MRU", "", "folder")
                        $seen = @{}
                        foreach ($mru in $mruKeys) {
                            $key = $versionKey.OpenSubKey($mru[0])
                            if (-not $key) { continue }
                            try {
                                $null = Add-OfficeMruRows -Key $key -KeyPath "HKCU\Software\Microsoft\Office\$version\$($mru[0])" `
                                    -App $app -Version $version -Account $mru[1] -Kind $mru[2] -Seen $seen `
                                    -User $User -RawPath $RawPath -FallbackTime $FallbackTime
                            }
                            finally { $key.Close() }
                        }
                    }
                    catch { Log-Warning "    Failed to parse Office File/Place MRU ($version\$app): $($_.Exception.Message)" }

                    if ($app -ne "Outlook") { continue }
                    try {
                        $key = $versionKey.OpenSubKey("Outlook\Security")
                        if ($key) {
                            try {
                                $folder = Get-RegistryValueText $key "OutlookSecureTempFolder"
                                if ($folder) {
                                    $t = Get-RegistryKeyTime -Key $key -FallbackTime $FallbackTime -KeyLabel "Outlook\Security key"
                                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-OutlookSecureTemp" -EventType "Snapshot" `
                                        -Description "Outlook attachment temp folder (OutlookSecureTempFolder): $folder" `
                                        -User $User `
                                        -Details (Format-ArtifactDetails ([ordered]@{ Version = $version; Folder = $folder; Key = "$appPath\Security"; Time = $t.Note })) `
                                        -Artifact "Registry" -RawPath $RawPath
                                }
                            }
                            finally { $key.Close() }
                        }
                    }
                    catch { Log-Warning "    Failed to parse OutlookSecureTempFolder ($version): $($_.Exception.Message)" }
                }
            }
            finally { $versionKey.Close() }
        }
    }
    finally { $officeKey.Close() }
    return $true
}

# Remote Desktop client (mstsc) history of one loaded NTUSER.DAT: Terminal
# Server Client\Default MRU0..MRU9 (MRU0 = most recent; the key's last-write
# time belongs to MRU0) and Servers\<host> (UsernameHint = the account saved
# for that host; the key's last-write time is the last connection that
# updated it). Returns $true if the key exists.
function Read-RdpClientHistory {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$User, [string]$RawPath, [datetime]$FallbackTime)
    $tscPath = "Software\Microsoft\Terminal Server Client"
    $tsc = $HiveRoot.OpenSubKey($tscPath)
    if (-not $tsc) { return $false }
    try {
        $key = $tsc.OpenSubKey("Default")
        if ($key) {
            try {
                $keyTime = Get-RegistryKeyLastWriteUtc $key
                foreach ($val in $key.GetValueNames()) {
                    if ($val -notmatch '^MRU(\d+)$') { continue }
                    $pos = [int]$Matches[1] + 1
                    $target = Get-RegistryValueText $key $val
                    if (-not $target) { continue }
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position $pos -KeyLabel "Terminal Server Client\Default key"
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-RDPClient" -EventType "NetworkConnection" `
                        -Description "Outbound RDP target (Remote Desktop MRU): $target" `
                        -User $User `
                        -Details (Format-ArtifactDetails ([ordered]@{ Target = $target; MRU = $val; Key = "HKCU\$tscPath\Default"; Time = ($t.Note -replace '^Time=', '') })) `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }

        $servers = $tsc.OpenSubKey("Servers")
        if ($servers) {
            try {
                foreach ($server in $servers.GetSubKeyNames()) {
                    $serverKey = $servers.OpenSubKey($server)
                    if (-not $serverKey) { continue }
                    try {
                        $hint = Get-RegistryValueText $serverKey "UsernameHint"
                        $ts = Get-RegistryKeyLastWriteUtc $serverKey
                        $timeNote = "Servers\<host> key last write (last connection that saved the user hint or certificate)"
                        if ($null -eq $ts) {
                            $ts = $FallbackTime
                            $timeNote = "hive file time (key last-write time unavailable)"
                        }
                        $desc = if ($hint) { "Outbound RDP target (saved server, user $hint): $server" } else { "Outbound RDP target (saved server): $server" }
                        Add-TimelineEntry -Timestamp $ts -Source "Registry-RDPClient" -EventType "NetworkConnection" `
                            -Description $desc `
                            -User $User `
                            -Details (Format-ArtifactDetails ([ordered]@{ Target = $server; UsernameHint = $hint; Key = "HKCU\$tscPath\Servers\$server"; Time = $timeNote })) `
                            -Artifact "Registry" -RawPath $RawPath
                    }
                    finally { $serverKey.Close() }
                }
            }
            finally { $servers.Close() }
        }
    }
    finally { $tsc.Close() }
    return $true
}

# Files and folders picked in Open/Save dialogs, from ComDlg32 in one loaded
# NTUSER.DAT:
#   OpenSavePidlMRU\<extension>  values are PIDLs of the items; "*" lists
#       every extension. As for RecentDocs, an extension subkey's last-write
#       time is exact for its newest item and a tighter bound for the others.
#   LastVisitedPidlMRU  values are a UTF-16 program name followed by the
#       PIDL of the folder that program's dialog last used.
# Both keep their order in MRUListEx. Returns $true if either key exists.
function Read-ComDlg32Mru {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$User, [string]$RawPath, [datetime]$FallbackTime)
    $found = $false
    $comDlgPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"

    try {
        $key = $HiveRoot.OpenSubKey("$comDlgPath\OpenSavePidlMRU")
        if ($key) {
            $found = $true
            try {
                # Items of every subkey: path -> subkey, value, position, subkey time
                $entries = @()
                foreach ($ext in $key.GetSubKeyNames()) {
                    $sub = $key.OpenSubKey($ext)
                    if (-not $sub) { continue }
                    try {
                        $subTime = Get-RegistryKeyLastWriteUtc $sub
                        $order = @(Get-RegistryMruOrder $sub)
                        foreach ($val in $sub.GetValueNames()) {
                            if ($val -notmatch '^\d+$') { continue }
                            $data = $sub.GetValue($val)
                            if (-not ($data -is [byte[]])) { continue }
                            $itemPath = ConvertFrom-ShellItemIdList $data
                            if (-not $itemPath) { continue }
                            $entries += [PSCustomObject]@{
                                SubKey    = $ext
                                ValueName = $val
                                Position  = [array]::IndexOf($order, $val) + 1
                                Time      = $subTime
                                Path      = $itemPath
                            }
                        }
                    }
                    finally { $sub.Close() }
                }

                $byExtension = @{}
                foreach ($e in $entries) {
                    if ($e.SubKey -ne "*" -and -not $byExtension.ContainsKey($e.Path)) { $byExtension[$e.Path] = $e }
                }
                $listedInStar = @{}
                foreach ($e in $entries) {
                    if ($e.SubKey -ne "*") { continue }
                    $listedInStar[$e.Path] = $true
                    $t = Get-MruEntryTime -KeyTime $e.Time -FallbackTime $FallbackTime -Position $e.Position -KeyLabel "OpenSavePidlMRU\* key"
                    $note = $t.Note
                    $ext = $byExtension[$e.Path]
                    if ($e.Position -ne 1 -and $ext -and $null -ne $ext.Time) {
                        $t = Get-MruEntryTime -KeyTime $ext.Time -FallbackTime $FallbackTime -Position $ext.Position -KeyLabel "OpenSavePidlMRU\$($ext.SubKey) key"
                        $note = "$($t.Note); overall MRU position $($e.Position)"
                    }
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-OpenSaveMRU" -EventType "FileAccess" `
                        -Description "Open/Save dialog item: $($e.Path)" `
                        -User $User `
                        -Details (Format-ArtifactDetails ([ordered]@{ Extension = $(if ($ext) { $ext.SubKey } else { "" }); MRUIndex = "*\$($e.ValueName)"; Key = "HKCU\$comDlgPath\OpenSavePidlMRU"; Time = ($note -replace '^Time=', '') })) `
                        -Artifact "Registry" -RawPath $RawPath
                }
                # Items only left in an extension subkey
                foreach ($e in $entries) {
                    if ($e.SubKey -eq "*" -or $listedInStar.ContainsKey($e.Path)) { continue }
                    $listedInStar[$e.Path] = $true
                    $t = Get-MruEntryTime -KeyTime $e.Time -FallbackTime $FallbackTime -Position $e.Position -KeyLabel "OpenSavePidlMRU\$($e.SubKey) key"
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-OpenSaveMRU" -EventType "FileAccess" `
                        -Description "Open/Save dialog item: $($e.Path)" `
                        -User $User `
                        -Details (Format-ArtifactDetails ([ordered]@{ Extension = $e.SubKey; MRUIndex = "$($e.SubKey)\$($e.ValueName)"; Key = "HKCU\$comDlgPath\OpenSavePidlMRU"; Time = ($t.Note -replace '^Time=', '') })) `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse OpenSavePidlMRU: $($_.Exception.Message)" }

    try {
        $key = $HiveRoot.OpenSubKey("$comDlgPath\LastVisitedPidlMRU")
        if ($key) {
            $found = $true
            try {
                $keyTime = Get-RegistryKeyLastWriteUtc $key
                $order = @(Get-RegistryMruOrder $key)
                foreach ($val in $key.GetValueNames()) {
                    if ($val -notmatch '^\d+$') { continue }
                    $data = $key.GetValue($val)
                    if (-not ($data -is [byte[]])) { continue }
                    $program = Get-Utf16ZString $data
                    if (-not $program) { continue }
                    $folder = ConvertFrom-ShellItemIdList -Data $data -Offset (($program.Length + 1) * 2)
                    if (-not $folder) { continue }
                    $t = Get-MruEntryTime -KeyTime $keyTime -FallbackTime $FallbackTime -Position ([array]::IndexOf($order, $val) + 1) -KeyLabel "LastVisitedPidlMRU key"
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-LastVisitedMRU" -EventType "FileAccess" `
                        -Description "Open/Save dialog folder last used by ${program}: $folder" `
                        -User $User `
                        -Details (Format-ArtifactDetails ([ordered]@{ Program = $program; MRUIndex = $val; Key = "HKCU\$comDlgPath\LastVisitedPidlMRU"; Time = ($t.Note -replace '^Time=', '') })) `
                        -Artifact "Registry" -RawPath $RawPath
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse LastVisitedPidlMRU: $($_.Exception.Message)" }

    return $found
}

# Accessibility programs that can be started from the logon screen: a
# Debugger set for one of them starts that program (e.g. cmd.exe) as SYSTEM
# before anyone logs on
$script:AccessibilityPrograms = @("sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe")

# One IFEO Debugger row for an Image File Execution Options key (the exe's
# own key or one of its UseFilter subkeys, which also name FilterFullPath).
# Returns the number of rows added (0 or 1).
function Add-IfeoDebuggerRow {
    param([Microsoft.Win32.RegistryKey]$Key, [string]$Program, [string]$KeyPath, [string]$RawPath, [datetime]$FallbackTime)
    $debugger = Get-RegistryValueText $Key "Debugger"
    if (-not $debugger) { return 0 }
    $accessibility = $script:AccessibilityPrograms -contains $Program
    $label = if ($accessibility) { "$Program (accessibility program)" } else { $Program }
    $t = Get-RegistryKeyTime -Key $Key -FallbackTime $FallbackTime
    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-IFEO" -EventType "PersistenceChange" `
        -Description "IFEO Debugger set for ${label}: $debugger" `
        -Details (Format-ArtifactDetails ([ordered]@{
            Program              = $Program
            Debugger             = $debugger
            FilterFullPath       = Get-RegistryValueText $Key "FilterFullPath"
            AccessibilityProgram = $(if ($accessibility) { "yes" } else { "" })
            Key                  = $KeyPath
            Time                 = $t.Note
        })) `
        -Artifact "Registry" -RawPath $RawPath
    return 1
}

# Image File Execution Options hijacks in one loaded SOFTWARE hive:
#   IFEO\<exe> Debugger  starts another program instead of the exe (also in
#       UseFilter subkeys, for one FilterFullPath)
#   SilentProcessExit\<exe>  when the exe exits, ReportingMode bit 0x1
#       launches MonitorProcess and bit 0x2 writes a dump (to
#       LocalDumpFolder; 0x4 = notification). Only active when the exe's
#       IFEO GlobalFlag has 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT); a
#       MonitorProcess without bit 0x1 is configured but never launched.
# Returns the number of rows added.
function Read-IfeoHijacks {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime)
    $added = 0
    $denied = @()
    $globalFlags = @{}
    $ifeoPath = "Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $ifeo = $HiveRoot.OpenSubKey($ifeoPath)
    if ($ifeo) {
        try {
            foreach ($exe in $ifeo.GetSubKeyNames()) {
                # Keys whose ACL denies administrators are skipped (counted below)
                $exeKey = $null
                try { $exeKey = $ifeo.OpenSubKey($exe) }
                catch { $denied += "IFEO\$exe" }
                if (-not $exeKey) { continue }
                try {
                    $flag = ConvertTo-RegistryNumber ($exeKey.GetValue("GlobalFlag"))
                    if ($null -ne $flag) { $globalFlags[$exe.ToLowerInvariant()] = $flag }
                    $added += Add-IfeoDebuggerRow -Key $exeKey -Program $exe -KeyPath "HKLM\SOFTWARE\$ifeoPath\$exe" -RawPath $RawPath -FallbackTime $FallbackTime
                    foreach ($filterName in $exeKey.GetSubKeyNames()) {
                        $filterKey = $null
                        try { $filterKey = $exeKey.OpenSubKey($filterName) }
                        catch { $denied += "IFEO\$exe\$filterName" }
                        if (-not $filterKey) { continue }
                        try {
                            $added += Add-IfeoDebuggerRow -Key $filterKey -Program $exe -KeyPath "HKLM\SOFTWARE\$ifeoPath\$exe\$filterName" -RawPath $RawPath -FallbackTime $FallbackTime
                        }
                        finally { $filterKey.Close() }
                    }
                }
                finally { $exeKey.Close() }
            }
        }
        finally { $ifeo.Close() }
    }

    $spePath = "Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    $spe = $HiveRoot.OpenSubKey($spePath)
    if ($spe) {
        try {
            foreach ($exe in $spe.GetSubKeyNames()) {
                $exeKey = $null
                try { $exeKey = $spe.OpenSubKey($exe) }
                catch { $denied += "SilentProcessExit\$exe" }
                if (-not $exeKey) { continue }
                try {
                    $monitor = Get-RegistryValueText $exeKey "MonitorProcess"
                    $mode = ConvertTo-RegistryNumber ($exeKey.GetValue("ReportingMode"))
                    $dumpFolder = Get-RegistryValueText $exeKey "LocalDumpFolder"
                    if (-not $monitor -and -not $mode -and -not $dumpFolder) { continue }
                    $modeText = "not set"
                    if ($null -ne $mode) {
                        $modeNames = @()
                        if ($mode -band 1) { $modeNames += "launch monitor process" }
                        if ($mode -band 2) { $modeNames += "local dump" }
                        if ($mode -band 4) { $modeNames += "notification" }
                        $modeText = "$mode"
                        if ($modeNames.Count -gt 0) { $modeText += " ($($modeNames -join ', '))" }
                    }
                    # The description follows what ReportingMode makes Windows
                    # do: launch MonitorProcess (0x1) or write a dump (0x2)
                    $launches = ($null -ne $mode -and ($mode -band 1) -ne 0 -and $monitor)
                    $dumps = ($null -ne $mode -and ($mode -band 2) -ne 0)
                    $flag = $globalFlags[$exe.ToLowerInvariant()]
                    $flagSet = ($null -ne $flag -and ($flag -band 0x200) -ne 0)
                    if ($launches) { $desc = "SilentProcessExit monitor process for ${exe}: $monitor" }
                    elseif ($dumps) { $desc = "SilentProcessExit dump on exit for ${exe}: $(if ($dumpFolder) { $dumpFolder } else { '%TEMP%\Silent Process Exit (default folder)' })" }
                    elseif ($monitor) { $desc = "SilentProcessExit monitor process configured for ${exe}, not launched (ReportingMode lacks 0x1): $monitor" }
                    elseif ($dumpFolder) { $desc = "SilentProcessExit dump folder configured for ${exe}, no dump (ReportingMode lacks 0x2): $dumpFolder" }
                    else { $desc = "SilentProcessExit reporting set for ${exe}: ReportingMode=$modeText" }
                    if (-not $flagSet) { $activeText = "no (IFEO GlobalFlag lacks 0x200)" }
                    elseif ($launches -or $dumps) { $activeText = "yes (IFEO GlobalFlag has 0x200, ReportingMode has 0x1 or 0x2)" }
                    else { $activeText = "no (ReportingMode has neither 0x1 nor 0x2)" }
                    $t = Get-RegistryKeyTime -Key $exeKey -FallbackTime $FallbackTime
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-SilentProcessExit" -EventType "PersistenceChange" `
                        -Description $desc `
                        -Details (Format-ArtifactDetails ([ordered]@{
                            Program         = $exe
                            MonitorProcess  = $monitor
                            ReportingMode   = $modeText
                            LocalDumpFolder = $dumpFolder
                            DumpType        = Get-RegistryValueText $exeKey "DumpType"
                            GlobalFlag      = $(if ($null -ne $flag) { "0x{0:X8}" -f $flag } else { "not set" })
                            Active          = $activeText
                            Key             = "HKLM\SOFTWARE\$spePath\$exe"
                            Time            = $t.Note
                        })) `
                        -Artifact "Registry" -RawPath $RawPath
                    $added++
                }
                finally { $exeKey.Close() }
            }
        }
        finally { $spe.Close() }
    }
    if ($denied.Count -gt 0) { Log-Warning "    $($denied.Count) IFEO/SilentProcessExit key(s) could not be opened (access denied): $($denied -join ', ')" }
    return $added
}

# Winlogon values that start the user's session, compared with the Windows
# defaults (case-insensitive):
#   Shell     explorer.exe
#   Userinit  C:\Windows\system32\userinit.exe,  (the trailing comma is normal)
#   Taskman   not set
# Rows only for values that differ. Returns the number of rows added.
function Read-WinlogonHijacks {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime)
    $added = 0
    $winlogonPath = "Microsoft\Windows NT\CurrentVersion\Winlogon"
    $key = $HiveRoot.OpenSubKey($winlogonPath)
    if (-not $key) { return 0 }
    try {
        $defaults = [ordered]@{
            Shell    = @('^explorer\.exe,?$', "explorer.exe")
            Userinit = @('^(?:(?:[A-Za-z]:\\Windows|%SystemDrive%\\Windows|%SystemRoot%|%windir%)\\System32\\)?userinit\.exe,?$', "C:\Windows\system32\userinit.exe,")
            Taskman  = @('^$', "(not set)")
        }
        foreach ($name in $defaults.Keys) {
            $data = Get-RegistryValueText $key $name
            if ($data -match $defaults[$name][0]) { continue }
            if ($name -ne "Taskman" -and -not $data) { continue }
            $t = Get-RegistryKeyTime -Key $key -FallbackTime $FallbackTime -KeyLabel "Winlogon key"
            Add-TimelineEntry -Timestamp $t.Time -Source "Registry-Winlogon" -EventType "PersistenceChange" `
                -Description "Non-default Winlogon ${name}: $data" `
                -Details (Format-ArtifactDetails ([ordered]@{ Value = $name; Data = $data; Default = $defaults[$name][1]; Key = "HKLM\SOFTWARE\$winlogonPath"; Time = $t.Note })) `
                -Artifact "Registry" -RawPath $RawPath
            $added++
        }
    }
    finally { $key.Close() }
    return $added
}

# AppInit_DLLs (DLLs loaded into every process that loads user32.dll) in the
# native and the 32-bit (Wow6432Node) view of one loaded SOFTWARE hive: a row
# when the list is not empty. Windows 8 and later ignore it when Secure Boot
# is on. Returns the number of rows added.
function Read-AppInitDlls {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime)
    $added = 0
    foreach ($windowsPath in @("Microsoft\Windows NT\CurrentVersion\Windows", "Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")) {
        $key = $HiveRoot.OpenSubKey($windowsPath)
        if (-not $key) { continue }
        try {
            $dlls = Get-RegistryValueText $key "AppInit_DLLs"
            if (-not ($dlls -replace '[\s,;]', '')) { continue }
            $load = ConvertTo-RegistryNumber ($key.GetValue("LoadAppInit_DLLs"))
            if ($load) { $state = "loading enabled" }
            elseif ($null -eq $load) { $state = "loading disabled, LoadAppInit_DLLs not set" }
            else { $state = "loading disabled, LoadAppInit_DLLs=0" }
            $t = Get-RegistryKeyTime -Key $key -FallbackTime $FallbackTime -KeyLabel "Windows key"
            Add-TimelineEntry -Timestamp $t.Time -Source "Registry-AppInitDLLs" -EventType "PersistenceChange" `
                -Description "AppInit_DLLs set ($state): $dlls" `
                -Details (Format-ArtifactDetails ([ordered]@{
                    AppInit_DLLs              = $dlls
                    LoadAppInit_DLLs          = $(if ($null -ne $load) { "$load" } else { "not set" })
                    RequireSignedAppInit_DLLs = Get-RegistryValueText $key "RequireSignedAppInit_DLLs"
                    Key                       = "HKLM\SOFTWARE\$windowsPath"
                    Note                      = "ignored when Secure Boot is on (Windows 8 and later)"
                    Time                      = $t.Note
                })) `
                -Artifact "Registry" -RawPath $RawPath
            $added++
        }
        finally { $key.Close() }
    }
    return $added
}

# UTF-16 string stored as [uint32 byte count][bytes] at an offset of binary
# data: Text and Next (the offset after it), or $null if it does not fit
function Get-SizedUtf16String {
    param([byte[]]$Data, [int]$Offset)
    if ($Offset -lt 0 -or $Offset + 4 -gt $Data.Length) { return $null }
    $size = [long][BitConverter]::ToUInt32($Data, $Offset)
    if (($size % 2) -ne 0 -or $Offset + 4 + $size -gt $Data.Length) { return $null }
    return [PSCustomObject]@{
        Text = [System.Text.Encoding]::Unicode.GetString($Data, $Offset + 4, [int]$size).TrimEnd([char]0)
        Next = $Offset + 4 + [int]$size
    }
}

# Command lines of a TaskCache Actions value (layout in Read-TaskCache),
# joined with "; "; "" when the data is not in the expected format
function ConvertFrom-TaskCacheActions {
    param($Data)
    if (-not ($Data -is [byte[]]) -or $Data.Length -lt 6 -or [BitConverter]::ToUInt16($Data, 0) -ne 3) { return "" }
    $context = Get-SizedUtf16String -Data $Data -Offset 2
    if (-not $context) { return "" }
    $actions = @()
    $pos = $context.Next
    while ($pos + 2 -le $Data.Length -and $actions.Count -lt 32) {
        $type = [BitConverter]::ToUInt16($Data, $pos)
        $id = Get-SizedUtf16String -Data $Data -Offset ($pos + 2)
        if (-not $id) { break }
        if ($type -eq 0x6666) {
            $command = Get-SizedUtf16String -Data $Data -Offset $id.Next
            if (-not $command) { break }
            $arguments = Get-SizedUtf16String -Data $Data -Offset $command.Next
            if (-not $arguments) { break }
            $workDir = Get-SizedUtf16String -Data $Data -Offset $arguments.Next
            if (-not $workDir) { break }
            $actions += ("$($command.Text) $($arguments.Text)").Trim()
            $pos = $workDir.Next + 2
        }
        elseif ($type -eq 0x7777) {
            if ($id.Next + 20 -gt $Data.Length) { break }
            $clsid = New-Object System.Guid (,[byte[]]$Data[$id.Next..($id.Next + 15)])
            $actions += "COM handler {$($clsid.ToString().ToUpper())}"
            # The data size is a uint32: check it before using it as an offset
            $size = [long][BitConverter]::ToUInt32($Data, $id.Next + 16)
            if ($id.Next + 20 + $size -gt $Data.Length) { break }
            $pos = $id.Next + 20 + [int]$size
        }
        else { break }
    }
    return ($actions -join "; ")
}

# Walk TaskCache\Tree: every key with an Id value is a task, every other key
# below Tree a task folder (which has only an SD value). Fills $Tasks (task
# GUID in upper case -> Path, HasSD, Index, KeyTime, KeyPath) and $Folders
# (folder path -> HasSD, KeyTime, KeyPath).
function Read-TaskCacheTreeNode {
    param([Microsoft.Win32.RegistryKey]$Key, [string]$TaskPath, [string]$KeyPath, [hashtable]$Tasks, [hashtable]$Folders, [int]$Depth)
    if ($Depth -gt 32) { return }
    foreach ($name in $Key.GetSubKeyNames()) {
        $child = $null
        try { $child = $Key.OpenSubKey($name) }
        catch { Log-Warning "    Cannot open $KeyPath\$name : $($_.Exception.Message)" }
        if (-not $child) { continue }
        try {
            $sd = $child.GetValue("SD")
            $node = [PSCustomObject]@{
                Path    = "$TaskPath\$name"
                HasSD   = ($sd -is [byte[]] -and $sd.Length -gt 0)
                Index   = Get-RegistryValueText $child "Index"
                KeyTime = Get-RegistryKeyLastWriteUtc $child
                KeyPath = "$KeyPath\$name"
            }
            $id = Get-RegistryValueText $child "Id"
            if ($id) { $Tasks[$id.Trim('{', '}').ToUpperInvariant()] = $node }
            else { $Folders[$node.Path] = $node }
            Read-TaskCacheTreeNode -Key $child -TaskPath "$TaskPath\$name" -KeyPath "$KeyPath\$name" -Tasks $Tasks -Folders $Folders -Depth ($Depth + 1)
        }
        finally { $child.Close() }
    }
}

# Scheduled tasks that the collection's task list also puts on the
# timeline (Parse-ScheduledTasks): scheduled_tasks.csv (live collections;
# HasLastRun = the CSV gives a last run time, read like Get-ScheduledTaskInfo
# from the same scheduler state as TaskCache DynamicInfo, so Read-TaskCache
# leaves that task's last run to the list) and ScheduledTasks_XML (mounted
# images; no run times). Task path in lower case -> HasLastRun. Empty when
# the ScheduledTasks source is not selected.
function Get-CollectedTaskNames {
    $listed = @{}
    if ($Sources -notcontains "ScheduledTasks") { return $listed }
    foreach ($csv in @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("scheduled_tasks.csv") | Where-Object { -not $_.PSIsContainer })) {
        try {
            foreach ($task in (Import-Csv -Path $csv.FullName -ErrorAction Stop)) {
                $taskName = Get-ArtifactRowValue $task @("TaskName", "Name")
                if (-not $taskName) { continue }
                $taskPath = Get-ArtifactRowValue $task @("TaskPath")
                $fullName = if ($taskPath) { $taskPath.TrimEnd('\') + "\" + $taskName } else { "\" + $taskName }
                $lastRun = ConvertFrom-UtcText (Get-ArtifactRowValue $task @("LastRunTimeUtc"))
                $listed[$fullName.ToLowerInvariant()] = ($null -ne $lastRun -and $lastRun.Year -ge 2000)
            }
        }
        catch { Log-Warning "    Could not read $($csv.FullName) for the TaskCache comparison: $($_.Exception.Message)" }
    }
    foreach ($dir in @(Get-ChildItem -Path $InputPath -Directory -Recurse -Filter "ScheduledTasks_XML" -ErrorAction SilentlyContinue | Where-Object { -not (Test-SecretsPath $_.FullName) })) {
        foreach ($tf in @(Get-ChildItem -Path $dir.FullName -File -Recurse -ErrorAction SilentlyContinue)) {
            try {
                $doc = New-Object System.Xml.XmlDocument
                $doc.Load($tf.FullName)
                if (-not $doc.DocumentElement -or $doc.DocumentElement.LocalName -ne "Task") { continue }
                $uri = Get-TaskXmlText $doc.DocumentElement "RegistrationInfo/URI"
                $fullName = if ($uri) { $uri } else { "\" + $tf.Name }
                if (-not $listed.ContainsKey($fullName.ToLowerInvariant())) { $listed[$fullName.ToLowerInvariant()] = $false }
            }
            catch { Write-Verbose "Not a readable task XML file: $($tf.FullName): $($_.Exception.Message)" }
        }
    }
    return $listed
}

# The first of $Folders (task folder paths) that contains the task or
# folder $Path, or ""
function Get-TaskCacheParentFolder {
    param([string]$Path, [string[]]$Folders)
    foreach ($folder in $Folders) {
        if ($Path.StartsWith("$folder\", [System.StringComparison]::OrdinalIgnoreCase)) { return $folder }
    }
    return ""
}

# TaskCache registered times (UTC) by task path in lower case, filled by
# Read-TaskCache (Registry source, which runs first) and read by
# Test-TaskCacheRegistered (ScheduledTasks source)
$script:taskCacheRegistered = @{}

# Scheduled tasks in the TaskCache of one loaded SOFTWARE hive
# (Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache):
#   Tree\<folder>\<task>  Id (task GUID), Index and SD (security
#       descriptor); a folder key has only SD. A task or folder whose SD
#       value is missing is hidden from schtasks and the Task Scheduler UI,
#       but its tasks still run (G DATA, "Windows Registry Analysis -
#       Today's Episode: Tasks", cyber.wtf, 2022).
#   Tasks\{GUID}  Path, Author, Actions, DynamicInfo.
# DynamicInfo, 28 bytes (Windows 7) or 36 bytes (Windows 8 and later), as
# documented by plaso's task cache parser and G DATA's winreg-tasks; other
# sizes are skipped:
#   0  uint32    magic (3)           20 uint32    task state (no longer used)
#   4  FILETIME  created/registered  24 uint32    last error code
#   12 FILETIME  last run (launch)   28 FILETIME  last successful run (36 bytes)
# Times later than the hive file time + 1 day are treated as invalid.
# "Scheduled task registered" is added for every task, also one that
# scheduled_tasks.csv or ScheduledTasks_XML lists: Windows records the
# created time, while the date those lists give is the task XML's
# RegistrationInfo/Date, which whoever wrote the task sets (Microsoft's own
# tasks: often years before the install). The registered times are kept in
# $script:taskCacheRegistered, so Parse-ScheduledTasks leaves out an XML
# date that is the same time. "Last run" is only added where it is new to
# the timeline: not for a task that scheduled_tasks.csv lists with a run
# time (Get-CollectedTaskNames). Hidden tasks are never in
# scheduled_tasks.csv.
# Actions (format version 3; older versions are not parsed): uint16 version,
# uint32 size + UTF-16 context, then per action uint16 type, uint32 size +
# UTF-16 id and for type 0x6666 (exec) command, arguments and working
# directory (uint32 size + UTF-16 each) plus uint16 flags; for type 0x7777
# (COM handler) a 16-byte CLSID and uint32 size + data. Parsing stops at
# any other type.
# Returns the number of rows added.
function Read-TaskCache {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime, [hashtable]$ListedTasks = @{})
    $cachePath = "Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
    $added = 0
    $tree = @{}
    $folders = @{}
    $treeKey = $HiveRoot.OpenSubKey("$cachePath\Tree")
    if ($treeKey) {
        try { Read-TaskCacheTreeNode -Key $treeKey -TaskPath "" -KeyPath "HKLM\SOFTWARE\$cachePath\Tree" -Tasks $tree -Folders $folders -Depth 0 }
        finally { $treeKey.Close() }
    }

    # Hidden folders (no SD value). Only reported when other folders of this
    # hive have one, so a Windows version that keeps no SD on folder keys
    # does not turn every folder into a finding.
    $hiddenFolders = @()
    $noSdFolders = @($folders.Keys | Where-Object { -not $folders[$_].HasSD } | Sort-Object)
    if ($noSdFolders.Count -gt 0 -and $noSdFolders.Count -lt $folders.Count) { $hiddenFolders = $noSdFolders }
    elseif ($noSdFolders.Count -gt 0) { Log-Warning "    $($noSdFolders.Count) TaskCache\Tree folder(s) without an SD value not reported: no folder in this hive has one" }

    $latest = $FallbackTime.AddDays(1)
    $actionsById = @{}
    $taskCount = 0
    $badDynamicInfo = 0
    $leftToList = 0
    $tasksKey = $HiveRoot.OpenSubKey("$cachePath\Tasks")
    if ($tasksKey) {
        try {
            foreach ($guidName in $tasksKey.GetSubKeyNames()) {
                $taskKey = $null
                try { $taskKey = $tasksKey.OpenSubKey($guidName) }
                catch { Log-Warning "    Cannot open TaskCache\Tasks\$guidName : $($_.Exception.Message)" }
                if (-not $taskKey) { continue }
                # One bad task is skipped; the others and the hidden-task
                # check below still run
                try {
                    $taskCount++
                    $id = $guidName.Trim('{', '}').ToUpperInvariant()
                    $treeEntry = $tree[$id]
                    $taskPath = Get-RegistryValueText $taskKey "Path"
                    if (-not $taskPath -and $treeEntry) { $taskPath = $treeEntry.Path }
                    if (-not $taskPath) { $taskPath = $guidName }
                    $actions = ConvertFrom-TaskCacheActions ($taskKey.GetValue("Actions"))
                    $actionsById[$id] = $actions
                    $dynamicInfo = $taskKey.GetValue("DynamicInfo")
                    if (-not ($dynamicInfo -is [byte[]]) -or ($dynamicInfo.Length -ne 28 -and $dynamicInfo.Length -ne 36)) {
                        if ($null -ne $dynamicInfo) { $badDynamicInfo++ }
                        continue
                    }

                    # Listed by the collection (by its Path value or its Tree location)?
                    $names = @($taskPath.ToLowerInvariant())
                    if ($treeEntry) { $names += $treeEntry.Path.ToLowerInvariant() }
                    $isListed = $false
                    $listedRun = $false
                    foreach ($name in $names) {
                        if (-not $ListedTasks.ContainsKey($name)) { continue }
                        $isListed = $true
                        if ($ListedTasks[$name]) { $listedRun = $true }
                    }

                    $hidden = ""
                    if ($treeEntry -and -not $treeEntry.HasSD) { $hidden = "yes (no SD value in TaskCache\Tree)" }
                    else {
                        $hiddenFolder = Get-TaskCacheParentFolder -Path $(if ($treeEntry) { $treeEntry.Path } else { $taskPath }) -Folders $hiddenFolders
                        if ($hiddenFolder) { $hidden = "yes (folder $hiddenFolder has no SD value in TaskCache\Tree)" }
                    }
                    $lastSuccess = $null
                    if ($dynamicInfo.Length -eq 36) { $lastSuccess = ConvertFrom-RegistryFileTime -FileTime ([BitConverter]::ToInt64($dynamicInfo, 28)) -Latest $latest }
                    $times = [ordered]@{
                        "registered" = ConvertFrom-RegistryFileTime -FileTime ([BitConverter]::ToInt64($dynamicInfo, 4)) -Latest $latest
                        "last run"   = ConvertFrom-RegistryFileTime -FileTime ([BitConverter]::ToInt64($dynamicInfo, 12)) -Latest $latest
                    }
                    foreach ($what in $times.Keys) {
                        if (-not $times[$what]) { continue }
                        $isRun = ($what -eq "last run")
                        if ($isRun -and $listedRun) {
                            $leftToList++
                            continue
                        }
                        if (-not $isRun) {
                            foreach ($name in $names) {
                                if (-not $script:taskCacheRegistered.ContainsKey($name)) { $script:taskCacheRegistered[$name] = @() }
                                $script:taskCacheRegistered[$name] += $times[$what]
                            }
                        }
                        $details = Format-ArtifactDetails ([ordered]@{
                            Id                   = $guidName
                            Actions              = $actions
                            Author               = Get-RegistryValueText $taskKey "Author"
                            Hidden               = $hidden
                            LastErrorCode        = $(if ($isRun) { "0x{0:X8}" -f [BitConverter]::ToUInt32($dynamicInfo, 24) } else { "" })
                            LastSuccessfulRunUtc = $(if ($isRun -and $lastSuccess) { $lastSuccess.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) } else { "" })
                            Listed               = $(if (-not $isListed) { "" } elseif ($isRun) { "yes (scheduled task list of the collection, without a run time)" } else { "yes (scheduled task list of the collection)" })
                            Key                  = "HKLM\SOFTWARE\$cachePath\Tasks\$guidName"
                            Time                 = $(if ($isRun) { "TaskCache DynamicInfo last run time" } else { "TaskCache DynamicInfo created (registered) time" })
                        })
                        $eventType = if ($isRun) { "Execution" } else { "ScheduledTaskChange" }
                        Add-TimelineEntry -Timestamp $times[$what] -Source "Registry-TaskCache" -EventType $eventType `
                            -Description "Scheduled task ${what}: $taskPath" `
                            -Details $details -Artifact "Registry" -RawPath $RawPath
                        $added++
                    }
                }
                catch { Log-Warning "    Failed to parse TaskCache\Tasks\$guidName : $($_.Exception.Message)" }
                finally { $taskKey.Close() }
            }
        }
        finally { $tasksKey.Close() }
    }

    # Hidden tasks and folders: Tree key without SD. The key's last-write
    # time is when the SD value was removed (or the key last changed).
    $hiddenCount = 0
    $hiddenEntries = @()
    foreach ($id in @($tree.Keys)) {
        if (-not $tree[$id].HasSD) { $hiddenEntries += , @($id, $tree[$id]) }
    }
    foreach ($folder in $hiddenFolders) { $hiddenEntries += , @("", $folders[$folder]) }
    foreach ($hiddenEntry in $hiddenEntries) {
        $id = $hiddenEntry[0]
        $entry = $hiddenEntry[1]
        $ts = $entry.KeyTime
        $timeNote = "TaskCache\Tree key last write (when the SD value was removed, or the key last changed)"
        if ($null -eq $ts) {
            $ts = $FallbackTime
            $timeNote = "hive file time (key last-write time unavailable)"
        }
        if ($id) {
            $description = "Hidden scheduled task (no SD value in TaskCache\Tree): $($entry.Path)"
            $details = [ordered]@{ Id = "{$id}"; Index = $entry.Index; Actions = $actionsById[$id]; Key = $entry.KeyPath; Time = $timeNote }
        }
        else {
            $description = "Hidden scheduled task folder (no SD value in TaskCache\Tree): $($entry.Path)"
            $inside = @($tree.Values | Where-Object { $_.Path.StartsWith("$($entry.Path)\", [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { $_.Path } | Sort-Object)
            $details = [ordered]@{ Tasks = ($inside -join "; "); Key = $entry.KeyPath; Time = $timeNote }
        }
        Add-TimelineEntry -Timestamp $ts -Source "Registry-TaskCache" -EventType "ScheduledTaskChange" `
            -Description $description -Details (Format-ArtifactDetails $details) -Artifact "Registry" -RawPath $RawPath
        $added++
        $hiddenCount++
    }
    Log "    TaskCache: $taskCount task(s), $hiddenCount hidden task(s)/folder(s) (no SD value), $leftToList last run time(s) already on the timeline from the ScheduledTasks source"
    if ($badDynamicInfo -gt 0) { Log-Warning "    $badDynamicInfo TaskCache DynamicInfo value(s) skipped: size is not 28 or 36 bytes" }
    return $added
}

# Lines of a text file written by the triage collector with Add-Content
# (collection_log.txt): ANSI in Windows PowerShell 5.1, UTF-8 without BOM in
# PowerShell 7, whichever edition reads it. Strict UTF-8 first, else the
# system ANSI code page.
function Read-CollectorTextLines {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    try { $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) }
    catch {
        Write-Verbose "$Path is not UTF-8, reading it as ANSI: $($_.Exception.Message)"
        $text = [System.Text.Encoding]::GetEncoding(0).GetString($bytes)
    }
    return ($text.TrimStart([char]0xFEFF) -split "`r?`n")
}

# Output folder the triage collector excluded from Defender while it ran,
# from collection_log.txt: the "Output directory:" line (Path), the name of
# the collection folder (Name; the zip's top folder is the output folder)
# and whether the cleanup at the end of the run logged that the exclusion
# was removed (Removed = "yes", "no" or "" when not logged). "" when unknown.
function Get-CollectorOutputFolder {
    $result = [PSCustomObject]@{ Path = ""; Name = ""; Removed = "" }
    $collLog = Get-ChildItem -Path $InputPath -Filter "collection_log.txt" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $collLog) { return $result }
    $result.Name = Split-Path $collLog.DirectoryName -Leaf
    try {
        foreach ($line in (Read-CollectorTextLines $collLog.FullName)) {
            if (-not $result.Path -and $line -match '^\[[^\]]+\] Output directory: (.+?)\s*$') { $result.Path = $Matches[1].TrimEnd('\') }
            elseif ($line -match '^\[[^\]]+\] OK: Defender exclusion removed\.') { $result.Removed = "yes" }
            elseif ($line -match '^\[[^\]]+\] WARNING: Could not remove the temporary Defender exclusion') { $result.Removed = "no" }
        }
    }
    catch { Log-Warning "  Could not read collection_log.txt: $($_.Exception.Message)" }
    return $result
}

# How a Defender path exclusion relates to the triage collector: "this" (the
# output folder of this collection), "other" (a collector output folder of
# another collection, so that run did not remove its exclusion) or "".
# Non-ASCII characters are compared loosely: a log written on a machine
# with another ANSI code page decodes them differently. The folder name
# alone identifies this collection when the log has no path, or when it is
# the collector's default name (TriageCollection_<date>_<minute>).
function Get-CollectorExclusionKind {
    param([string]$Exclusion, $CollectorFolder)
    $path = $Exclusion.Trim().TrimEnd('\')
    $leaf = $path -replace '^.*\\', ''
    $defaultName = '^TriageCollection_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}$'
    if ($CollectorFolder) {
        if ($CollectorFolder.Path) {
            if ($path -eq $CollectorFolder.Path) { return "this" }
            if (($path -replace '[^\x20-\x7E]+', '?') -eq ($CollectorFolder.Path -replace '[^\x20-\x7E]+', '?')) { return "this" }
        }
        if ($CollectorFolder.Name -and $leaf -eq $CollectorFolder.Name -and (-not $CollectorFolder.Path -or $leaf -match $defaultName)) { return "this" }
    }
    if ($leaf -match $defaultName) { return "other" }
    return ""
}

# Defender exclusions in one loaded SOFTWARE hive: Microsoft\Windows
# Defender\Exclusions\<type> (local settings, e.g. Add-MpPreference) and
# Policies\Microsoft\Windows Defender\Exclusions\<type> (Group Policy). Each
# value name is one exclusion; types are Paths, Extensions, Processes,
# IpAddresses (and TemporaryPaths). One SecurityAlert row per exclusion,
# timed with its type key's last-write time. When Group Policy sets
# DisableLocalAdminMerge, only the Group Policy lists are used: local
# exclusions are then "ignored by policy" instead of "in effect". The
# triage collector excludes its own output folder while it runs and the
# hive is saved during the run, so that exclusion is a Snapshot row
# labelled as the collector's own (a SecurityAlert if collection_log.txt
# says the collector could not remove it).
# Returns the number of rows added.
function Read-DefenderExclusionKeys {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime, $CollectorFolder)
    $added = 0
    $merge = $null
    try {
        $policyKey = $HiveRoot.OpenSubKey("Policies\Microsoft\Windows Defender")
        if ($policyKey) {
            try { $merge = ConvertTo-RegistryNumber ($policyKey.GetValue("DisableLocalAdminMerge")) }
            finally { $policyKey.Close() }
        }
    }
    catch { Log-Warning "    Could not read Defender DisableLocalAdminMerge (local exclusions are reported as in effect): $($_.Exception.Message)" }
    $localIgnored = ($null -ne $merge -and $merge -ne 0)
    $removed = if ($CollectorFolder) { $CollectorFolder.Removed } else { "" }
    foreach ($basePath in @("Microsoft\Windows Defender\Exclusions", "Policies\Microsoft\Windows Defender\Exclusions")) {
        $isPolicy = $basePath -like "Policies\*"
        $state = if ($localIgnored -and -not $isPolicy) { "ignored by policy" } else { "in effect" }
        $baseKey = $HiveRoot.OpenSubKey($basePath)
        if (-not $baseKey) { continue }
        try {
            foreach ($type in $baseKey.GetSubKeyNames()) {
                $typeKey = $baseKey.OpenSubKey($type)
                if (-not $typeKey) { continue }
                try {
                    $keyTime = Get-RegistryKeyLastWriteUtc $typeKey
                    $exclusions = @($typeKey.GetValueNames() | Where-Object { $_ -ne "" })
                    $kinds = @{}
                    foreach ($exclusion in $exclusions) {
                        $kinds[$exclusion] = if ($type -like "*Paths") { Get-CollectorExclusionKind -Exclusion $exclusion -CollectorFolder $CollectorFolder } else { "" }
                    }
                    $collectorAdded = @($kinds.Values) -contains "this"
                    foreach ($exclusion in $exclusions) {
                        $kind = $kinds[$exclusion]
                        $ts = $keyTime
                        if ($null -eq $ts) {
                            $ts = $FallbackTime
                            $timeNote = "hive file time (key last-write time unavailable)"
                        }
                        elseif ($kind -eq "this") { $timeNote = "Exclusions\$type key last write (when the triage collector added this exclusion)" }
                        elseif ($collectorAdded) { $timeNote = "Exclusions\$type key last write, when the triage collector added its own exclusion during the collection; this exclusion is older" }
                        else { $timeNote = "Exclusions\$type key last write (key last changed; this exclusion may be older)" }
                        $details = [ordered]@{
                            Type        = $type
                            Exclusion   = $exclusion
                            Policy      = $(if ($isPolicy) { "yes (Group Policy)" } else { "" })
                            NotInEffect = $(if ($state -ne "in effect") { "local exclusion lists are ignored (Group Policy DisableLocalAdminMerge=$merge)" } else { "" })
                            Origin      = ""
                            Key         = "HKLM\SOFTWARE\$basePath\$type"
                            Time        = $timeNote
                        }
                        $eventType = "SecurityAlert"
                        $description = "Defender exclusion $state ($type): $exclusion"
                        if ($kind -eq "this" -and $removed -eq "no") {
                            $details["Origin"] = "triage collector: output folder of this collection; collection_log.txt records that the collector could not remove it at the end of the collection, so it was left in place"
                            $description += " (triage collector's own exclusion, not removed after the collection)"
                        }
                        elseif ($kind -eq "this") {
                            $details["Origin"] = "triage collector: output folder of this collection, excluded while the collector ran; " +
                                $(if ($removed -eq "yes") { "collection_log.txt records that it was removed at the end of the collection" } else { "its removal is not recorded in collection_log.txt" })
                            $eventType = "Snapshot"
                            $description += " (triage collector's own temporary exclusion)"
                        }
                        elseif ($kind -eq "other") { $details["Origin"] = "triage collector output folder of another collection; the collector removes its exclusion when it finishes, so this one was left behind" }
                        Add-TimelineEntry -Timestamp $ts -Source "Registry-DefenderExclusions" -EventType $eventType `
                            -Description $description `
                            -Details (Format-ArtifactDetails $details) -Artifact "Registry" -RawPath $RawPath
                        $added++
                    }
                }
                finally { $typeKey.Close() }
            }
        }
        finally { $baseKey.Close() }
    }
    return $added
}

# Machine-wide autostart hijacks, scheduled tasks (TaskCache) and Defender
# exclusions from one loaded SOFTWARE hive (root = HKLM\SOFTWARE). Returns
# the number of rows added.
function Read-SoftwareHive {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime, $CollectorFolder, [hashtable]$ListedTasks = @{})
    $added = 0
    try { $added += Read-IfeoHijacks -HiveRoot $HiveRoot -RawPath $RawPath -FallbackTime $FallbackTime }
    catch { Log-Warning "    Failed to parse Image File Execution Options / SilentProcessExit: $($_.Exception.Message)" }
    try { $added += Read-WinlogonHijacks -HiveRoot $HiveRoot -RawPath $RawPath -FallbackTime $FallbackTime }
    catch { Log-Warning "    Failed to parse Winlogon: $($_.Exception.Message)" }
    try { $added += Read-AppInitDlls -HiveRoot $HiveRoot -RawPath $RawPath -FallbackTime $FallbackTime }
    catch { Log-Warning "    Failed to parse AppInit_DLLs: $($_.Exception.Message)" }
    try { $added += Read-TaskCache -HiveRoot $HiveRoot -RawPath $RawPath -FallbackTime $FallbackTime -ListedTasks $ListedTasks }
    catch { Log-Warning "    Failed to parse TaskCache: $($_.Exception.Message)" }
    try { $added += Read-DefenderExclusionKeys -HiveRoot $HiveRoot -RawPath $RawPath -FallbackTime $FallbackTime -CollectorFolder $CollectorFolder }
    catch { Log-Warning "    Failed to parse Defender exclusions: $($_.Exception.Message)" }
    return $added
}

# LSA packages that ship with Windows (lower case, without ".dll"); rows are
# added only for other entries. Windows 10/11 defaults:
#   Lsa\Authentication Packages     msv1_0
#   Lsa\Notification Packages       scecli (servers with RRAS: also rassfm)
#   Lsa\Security Packages           "" (Windows 7: kerberos msv1_0 schannel
#                                   wdigest tspkg pku2u)
#   Lsa\OSConfig\Security Packages  kerberos msv1_0 schannel wdigest tspkg
#                                   pku2u cloudap (when present)
# negoexts and livessp are also Windows security packages.
$script:LsaDefaultPackages = @{
    "Authentication Packages" = @("msv1_0")
    "Notification Packages"   = @("scecli", "rassfm")
    "Security Packages"       = @("kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp")
}

# LSA packages (non-default entries, PersistenceChange) and WDigest
# UseLogonCredential (clear-text credential caching, SecurityAlert) from one
# loaded SYSTEM hive (root = HKLM\SYSTEM). Returns the number of rows added.
function Read-SystemHive {
    param([Microsoft.Win32.RegistryKey]$HiveRoot, [string]$RawPath, [datetime]$FallbackTime)
    $controlSet = Get-OfflineControlSetName $HiveRoot
    if (-not $controlSet) {
        Log-Warning "    No control set found in the SYSTEM hive"
        return 0
    }
    $added = 0
    $noExpand = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
    $checks = @(
        @("Control\Lsa", "Authentication Packages", "LSA Authentication Package"),
        @("Control\Lsa", "Notification Packages", "LSA Notification Package (password filter)"),
        @("Control\Lsa", "Security Packages", "LSA Security Package"),
        @("Control\Lsa\OSConfig", "Security Packages", "LSA Security Package (OSConfig)")
    )
    foreach ($check in $checks) {
        try {
            $key = $HiveRoot.OpenSubKey("$controlSet\$($check[0])")
            if (-not $key) { continue }
            try {
                $raw = $key.GetValue($check[1], $null, $noExpand)
                if ($null -eq $raw) { continue }
                $entries = @(@($raw) | ForEach-Object { "$_".Split([char]0) } | ForEach-Object { $_.Trim().Trim('"').Trim() } | Where-Object { $_ })
                $defaults = $script:LsaDefaultPackages[$check[1]]
                $t = Get-RegistryKeyTime -Key $key -FallbackTime $FallbackTime -KeyLabel "$($check[0] -replace '^Control\\', '') key"
                foreach ($entry in $entries) {
                    if ($defaults -contains ($entry -replace '\.dll$', '').ToLowerInvariant()) { continue }
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-LSA" -EventType "PersistenceChange" `
                        -Description "Non-default $($check[2]): $entry" `
                        -Details (Format-ArtifactDetails ([ordered]@{ Value = $check[1]; Entry = $entry; AllEntries = ($entries -join "; "); Key = "HKLM\SYSTEM\$controlSet\$($check[0])"; Time = $t.Note })) `
                        -Artifact "Registry" -RawPath $RawPath
                    $added++
                }
            }
            finally { $key.Close() }
        }
        catch { Log-Warning "    Failed to parse $($check[0])\$($check[1]): $($_.Exception.Message)" }
    }

    try {
        $wdigestPath = "$controlSet\Control\SecurityProviders\WDigest"
        $key = $HiveRoot.OpenSubKey($wdigestPath)
        if ($key) {
            try {
                $useLogonCredential = ConvertTo-RegistryNumber ($key.GetValue("UseLogonCredential"))
                if ($null -ne $useLogonCredential -and $useLogonCredential -ne 0) {
                    $t = Get-RegistryKeyTime -Key $key -FallbackTime $FallbackTime -KeyLabel "WDigest key"
                    Add-TimelineEntry -Timestamp $t.Time -Source "Registry-WDigest" -EventType "SecurityAlert" `
                        -Description "WDigest UseLogonCredential=${useLogonCredential}: Windows keeps clear-text passwords in LSASS memory" `
                        -Details (Format-ArtifactDetails ([ordered]@{ UseLogonCredential = $useLogonCredential; Key = "HKLM\SYSTEM\$wdigestPath"; Time = $t.Note })) `
                        -Artifact "Registry" -RawPath $RawPath
                    $added++
                }
            }
            finally { $key.Close() }
        }
    }
    catch { Log-Warning "    Failed to parse WDigest: $($_.Exception.Message)" }
    return $added
}

function Parse-Registry {
    Log "--- Parsing Registry Artifacts ---"

    $registryParsed = $false

    # Try to find offline registry hives in the input path
    $ntUserFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("NTUSER.DAT") | Where-Object { -not $_.PSIsContainer })

    # Parse NTUSER.DAT hives (see Read-NtUserHive for the keys)
    foreach ($ntuser in $ntUserFiles) {
        $mount = $null
        try {
            # Account from the collection layout (Registry\<user>\NTUSER.DAT),
            # never from the analyst machine's path
            $user = Get-CollectionUser $ntuser.FullName

            # Fallback time for keys whose last-write time cannot be read
            $hiveTime = $ntuser.LastWriteTimeUtc
            $srcTimes = Get-SourceFileTimes $ntuser.FullName
            if ($srcTimes -and $srcTimes.Modified) { $hiveTime = $srcTimes.Modified }

            $mount = Mount-TimelineHive -HiveFile $ntuser -Prefix "TEMP_TL"
            if ($mount -and $mount.Root) {
                $hiveFound = Read-NtUserHive -HiveRoot $mount.Root -User $user -RawPath $ntuser.FullName -FallbackTime $hiveTime
                if ($hiveFound -eq $true) { $registryParsed = $true }
            }
        }
        catch {
            Log-Warning "  Failed to process NTUSER.DAT at $($ntuser.FullName) : $($_.Exception.Message)"
        }
        finally {
            Dismount-TimelineHive $mount
        }
    }

    # ShellBags from UsrClass.dat (Registry\<user>\UsrClass.dat)
    $usrClassFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("UsrClass.dat") | Where-Object { -not $_.PSIsContainer })
    foreach ($usrClass in $usrClassFiles) {
        $mount = $null
        try {
            $user = Get-CollectionUser $usrClass.FullName
            $hiveTime = $usrClass.LastWriteTimeUtc
            $srcTimes = Get-SourceFileTimes $usrClass.FullName
            if ($srcTimes -and $srcTimes.Modified) { $hiveTime = $srcTimes.Modified }

            $mount = Mount-TimelineHive -HiveFile $usrClass -Prefix "TEMP_TLUC"
            if ($mount -and $mount.Root) {
                $bagCount = Read-ShellBags -HiveRoot $mount.Root -User $user -RawPath $usrClass.FullName -FallbackTime $hiveTime
                Log "  Parsed $bagCount ShellBag folder entries for user $user."
                if ($bagCount -gt 0) { $registryParsed = $true }
            }
        }
        catch {
            Log-Warning "  Failed to process UsrClass.dat at $($usrClass.FullName) : $($_.Exception.Message)"
        }
        finally {
            Dismount-TimelineHive $mount
        }
    }

    # Machine-wide keys from Registry\SOFTWARE (IFEO / SilentProcessExit,
    # Winlogon, AppInit_DLLs, TaskCache, Defender exclusions) and
    # Registry\SYSTEM (LSA packages, WDigest). reg save output has no
    # original file times, so the fallback time is the collected file's.
    foreach ($hiveName in @("SOFTWARE", "SYSTEM")) {
        $hiveFile = Find-OfflineHiveFile $hiveName
        if (-not $hiveFile) {
            Log "  No $hiveName hive in the collection."
            continue
        }
        $mount = $null
        try {
            $hiveTime = $hiveFile.LastWriteTimeUtc
            $srcTimes = Get-SourceFileTimes $hiveFile.FullName
            if ($srcTimes -and $srcTimes.Modified) { $hiveTime = $srcTimes.Modified }

            $mount = Mount-TimelineHive -HiveFile $hiveFile -Prefix $(if ($hiveName -eq "SOFTWARE") { "TEMP_TLSW" } else { "TEMP_TLSYS" })
            if ($mount -and $mount.Root) {
                # Account and machine names for the User column too
                if ($hiveName -eq "SOFTWARE") {
                    $rowCount = Read-SoftwareHive -HiveRoot $mount.Root -RawPath $hiveFile.FullName -FallbackTime $hiveTime `
                        -CollectorFolder (Get-CollectorOutputFolder) -ListedTasks (Get-CollectedTaskNames)
                    Add-OfflineProfileNames $mount.Root
                }
                else {
                    $rowCount = Read-SystemHive -HiveRoot $mount.Root -RawPath $hiveFile.FullName -FallbackTime $hiveTime
                    Add-TimelineMachineName (Get-OfflineComputerNames $mount.Root)
                }
                Log "  Added $rowCount row(s) from the $hiveName hive."
                $registryParsed = $true
            }
        }
        catch {
            Log-Warning "  Failed to process $hiveName hive at $($hiveFile.FullName) : $($_.Exception.Message)"
        }
        finally {
            Dismount-TimelineHive $mount
        }
    }

    # BAM/DAM and AppCompatCache (SYSTEM hive, bam_entries.csv,
    # appcompat_cache.reg) are parsed in the PowerShell History section

    if (-not $registryParsed) {
        Log-Warning "No registry artifacts found or parseable."
    }
    Log "  Registry parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 5. Browser History Parser
# ----------------------------------------------------------
# Locate sqlite3.exe: PATH first, then the tool folders next to this script.
# As a last resort download the official sqlite-tools build (x64; sqlite.org
# publishes no ARM64 tools build, and x64 runs under emulation on ARM64).
function Find-Sqlite3Exe {
    # sqlite-tools release used for the download; the year folder on
    # sqlite.org must match the release
    $sqliteVersion = "3490100"
    $sqliteYear = "2025"

    $onPath = Get-Command "sqlite3" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { return $onPath.Path }

    $toolsDir = Join-Path $PSScriptRoot "tools\sqlite3"
    $locations = @(
        (Join-Path $toolsDir "sqlite3.exe"),
        (Join-Path $PSScriptRoot "tools\sqlite3.exe"),
        (Join-Path $PSScriptRoot "sqlite3.exe"),
        (Join-Path $PSScriptRoot "reports\sqlite3\sqlite3.exe"),
        (Join-Path $env:TEMP "sqlite3_timeline\sqlite3.exe")
    )
    foreach ($loc in $locations) {
        if (Test-Path -LiteralPath $loc) { return $loc }
    }
    # An earlier download may have unpacked into a subfolder
    if (Test-Path -LiteralPath $toolsDir) {
        $found = Get-ChildItem -LiteralPath $toolsDir -Filter "sqlite3.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    $urls = @("https://www.sqlite.org/$sqliteYear/sqlite-tools-win-x64-$sqliteVersion.zip")

    Log "  sqlite3.exe not found locally. Downloading sqlite-tools $sqliteVersion from sqlite.org..."
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 }
    catch { Write-Verbose "Could not enable TLS 1.2: $($_.Exception.Message)" }
    foreach ($url in $urls) {
        $zipPath = Join-Path $env:TEMP "sqlite3_download_$(Get-Random).zip"
        try {
            Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
            New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
            Expand-Archive -Path $zipPath -DestinationPath $toolsDir -Force -ErrorAction Stop
            # The zip may contain a subfolder -- find sqlite3.exe
            $found = Get-ChildItem -LiteralPath $toolsDir -Filter "sqlite3.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                Log-Success "  Downloaded sqlite3.exe ($url) to: $($found.FullName)"
                return $found.FullName
            }
        }
        catch { Log-Warning "  Failed to download $url : $($_.Exception.Message)" }
        finally { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
    }
    Log-Warning "  Browser history parsing will be skipped."
    Log-Warning "  To fix: put sqlite3.exe on PATH or in $toolsDir (https://www.sqlite.org/download.html)."
    return $null
}

# Run a query with sqlite3 against a scratch copy of the database in the work
# folder (plus its -wal file, so recent history not yet checkpointed is
# included, and its rollback -journal, so a copy taken mid-transaction is
# rolled back to its last committed state instead of being read
# half-written). Returns the CSV output lines, decoded as UTF-8. -Attach:
# other databases the query reads, as alias -> path; each is attached from
# its own scratch copy (with its -wal and -journal) under that alias.
function Invoke-Sqlite3Query {
    param([string]$Sqlite3Exe, [string]$DbPath, [string]$Query, [System.Collections.IDictionary]$Attach)
    # Found by the parser, so gone since then (not a sqlite3 problem)
    $dbFiles = @($DbPath)
    if ($Attach) { $dbFiles += @($Attach.Values) }
    foreach ($dbFile in $dbFiles) {
        if (-not (Test-Path -LiteralPath $dbFile -PathType Leaf)) {
            Log-Warning "    sqlite3 query skipped, input file missing: $dbFile"
            return @()
        }
    }
    $tempDb = Join-Path (Get-ScratchFolder) "timeline_browser_$(Get-Random).db"
    $tempFiles = New-Object System.Collections.Generic.List[string]
    $tempFiles.Add($tempDb)
    $prevEncoding = $null
    try {
        $copies = @(, @($DbPath, $tempDb))
        $attachSql = ""
        if ($Attach) {
            foreach ($alias in $Attach.Keys) {
                $tempAttach = Join-Path (Get-ScratchFolder) "timeline_browser_$(Get-Random).db"
                $tempFiles.Add($tempAttach)
                $copies += , @($Attach[$alias], $tempAttach)
                $attachSql += "ATTACH '" + $tempAttach.Replace("'", "''") + "' AS $alias; "
            }
        }
        foreach ($copy in $copies) {
            Copy-Item -LiteralPath $copy[0] -Destination $copy[1] -Force -ErrorAction Stop
            foreach ($companion in @("-wal", "-journal")) {
                if (Test-Path -LiteralPath "$($copy[0])$companion") {
                    Copy-Item -LiteralPath "$($copy[0])$companion" -Destination "$($copy[1])$companion" -Force -ErrorAction SilentlyContinue
                }
            }
        }
        # sqlite3 writes UTF-8; without this, titles are decoded with the OEM code page
        try { $prevEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
        catch { Write-Verbose "Could not set console output encoding to UTF-8: $($_.Exception.Message)" }
        $output = & $Sqlite3Exe -csv $tempDb ($attachSql + $Query) 2>&1
        if ($LASTEXITCODE -eq 0) { return @($output | Where-Object { $_ -is [string] }) }
        Log-Warning "    sqlite3 error: $output"
        return @()
    }
    catch {
        Log-Warning "    sqlite3 query failed for $DbPath : $($_.Exception.Message)"
        return @()
    }
    finally {
        if ($prevEncoding) {
            try { [Console]::OutputEncoding = $prevEncoding }
            catch { Write-Verbose "Could not restore console output encoding: $($_.Exception.Message)" }
        }
        foreach ($tempFile in $tempFiles) {
            foreach ($tmp in @($tempFile, "$tempFile-wal", "$tempFile-shm", "$tempFile-journal")) {
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

# Browser of a Chromium "History" file: from the collection layout
# Browser\<user>\<browser>\[<profile>\]History, else from the install path.
# Opera GX must be checked before Opera.
function Get-ChromiumBrowserName {
    param([string]$FullPath)
    $rel = Get-RelativeCollectionPath $FullPath
    if ($rel -and $rel -match '^Browser\\[^\\]+\\([^\\]+)\\') {
        switch -Regex ($Matches[1]) {
            '^Opera ?GX'  { return "OperaGX" }
            '^Opera'      { return "Opera" }
            '^Edge$'      { return "Edge" }
            '^Brave'      { return "Brave" }
            '^Vivaldi$'   { return "Vivaldi" }
            '^Chrome$'    { return "Chrome" }
        }
    }
    $p = if ($rel) { $rel } else { $FullPath }
    if ($p -match '\\Opera ?GX[^\\]*\\|\\Opera_GX[^\\]*\\') { return "OperaGX" }
    if ($p -match '\\Opera[^\\]*\\') { return "Opera" }
    if ($p -match '\\Microsoft\\Edge\\|\\Edge\\') { return "Edge" }
    if ($p -match '\\BraveSoftware\\|\\Brave\\') { return "Brave" }
    if ($p -match '\\Vivaldi\\') { return "Vivaldi" }
    return "Chrome"
}

# Browser profile folder (e.g. "Default") from the collection layout, or "".
# <profile>\Network\Cookies (current Chromium versions), <profile>\Sessions\*
# and Firefox's <profile>\sessionstore-backups\* belong to <profile>.
function Get-BrowserProfileName {
    param([string]$FullPath)
    $rel = Get-RelativeCollectionPath $FullPath
    if ($rel -and $rel -match '^Browser\\[^\\]+\\[^\\]+\\(.+)\\[^\\]+$') { return ($Matches[1] -replace '(?:^|\\)(?:Network|Sessions|sessionstore-backups)$', '') }
    return ""
}

# Chromium visits.transition core types (transition & 0xFF)
$script:ChromiumTransitions = @{
    0 = "LINK"; 1 = "TYPED"; 2 = "AUTO_BOOKMARK"; 3 = "AUTO_SUBFRAME"; 4 = "MANUAL_SUBFRAME"
    5 = "GENERATED"; 6 = "AUTO_TOPLEVEL"; 7 = "FORM_SUBMIT"; 8 = "RELOAD"; 9 = "KEYWORD"; 10 = "KEYWORD_GENERATED"
}
# Firefox moz_historyvisits.visit_type
$script:FirefoxVisitTypes = @{
    1 = "LINK"; 2 = "TYPED"; 3 = "BOOKMARK"; 4 = "EMBED"; 5 = "REDIRECT_PERMANENT"
    6 = "REDIRECT_TEMPORARY"; 7 = "DOWNLOAD"; 8 = "FRAMED_LINK"; 9 = "RELOAD"
}

# Turn sqlite3 -csv visit rows (Total,Url,Title,VisitCount,VisitTime,Type) into
# timeline entries. VisitTime is UTC text from SQLite. Returns the row count.
function Add-BrowserVisitRows {
    param(
        [string[]]$Lines,
        [string]$Source,
        [string]$User,
        [string]$ProfileName,
        [hashtable]$TypeNames,
        [string]$RawPath,
        [int]$MaxVisits
    )
    $count = 0
    $total = 0
    if (-not $Lines -or $Lines.Count -eq 0) { return 0 }
    $rows = $Lines | ConvertFrom-Csv -Header "Total", "Url", "Title", "VisitCount", "VisitTime", "Type"
    foreach ($r in $rows) {
        if ($total -eq 0) { [void][int]::TryParse([string]$r.Total, [ref]$total) }
        # SQLite datetime text is UTC -- do not treat it as local time
        $ts = ConvertFrom-UtcText $r.VisitTime
        if ($null -eq $ts) { continue }
        $typeName = ""
        $typeNum = 0
        if ([int]::TryParse([string]$r.Type, [ref]$typeNum)) {
            $typeName = $TypeNames[$typeNum]
            if (-not $typeName) { $typeName = "$typeNum" }
        }
        $label = if ($r.Title) { $r.Title } else { $r.Url }
        $details = "URL=$($r.Url) VisitCount=$($r.VisitCount) Transition=$typeName"
        if ($ProfileName) { $details += " Profile=$ProfileName" }
        Add-TimelineEntry -Timestamp $ts -Source $Source -EventType "NetworkConnection" `
            -Description "Browser visit: $label" `
            -User $User -Details $details `
            -Artifact "Browser" -RawPath $RawPath
        $count++
    }
    if ($total -gt $MaxVisits) {
        Log-Warning "    $total visits in database; only the newest $MaxVisits were added (cap)."
    }
    return $count
}

# Chromium time (microseconds since 1601-01-01 UTC, as text or a number)
# -> UTC [datetime], or $null when zero or out of range
function ConvertFrom-ChromiumTime {
    param($Value)
    $us = 0L
    if (-not [long]::TryParse([string]$Value, [ref]$us) -or $us -le 0 -or $us -gt [datetime]::MaxValue.ToFileTimeUtc() / 10) { return $null }
    return [datetime]::FromFileTimeUtc($us * 10)
}

# Chromium "Bookmarks" file (JSON) of one profile: a row per bookmark at its
# date_added. Returns the number of rows added.
function Add-ChromiumBookmarkRows {
    param([System.IO.FileInfo]$File)
    $json = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    if (-not $json -or -not $json.PSObject.Properties["roots"]) { return 0 }
    $browserName = Get-ChromiumBrowserName $File.FullName
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    # Depth-first walk; each stack item is @(node, folder path)
    $stack = New-Object System.Collections.Stack
    foreach ($root in $json.roots.PSObject.Properties) {
        if ($root.Value -and $root.Value.PSObject.Properties["type"]) { $stack.Push(@($root.Value, [string]$root.Value.name)) }
    }
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $node = $item[0]
        if ($node.type -eq "url") {
            $addedTime = ConvertFrom-ChromiumTime $node.date_added
            if (-not $addedTime) { continue }
            $lastUsed = ConvertFrom-ChromiumTime $node.date_last_used
            $desc = if ($node.name) { "Bookmark added: $($node.name) ($($node.url))" } else { "Bookmark added: $($node.url)" }
            Add-TimelineEntry -Timestamp $addedTime -Source "$browserName Bookmarks" -EventType "NetworkConnection" `
                -Description $desc `
                -User $user `
                -Details (Format-ArtifactDetails ([ordered]@{
                    URL         = $node.url
                    Folder      = $item[1]
                    LastUsedUtc = $(if ($lastUsed) { $lastUsed.ToString("yyyy-MM-dd HH:mm:ss") } else { "" })
                    Profile     = $profileName
                })) `
                -Artifact "Browser" -RawPath $File.FullName
            $count++
            continue
        }
        if (-not $node.PSObject.Properties["children"]) { continue }
        foreach ($child in @($node.children)) {
            if ($null -eq $child) { continue }
            $folder = if ($child.type -eq "folder") { "$($item[1])/$($child.name)" } else { $item[1] }
            $stack.Push(@($child, $folder))
        }
    }
    return $count
}

# ----- Downloads and the credential, cookie and form stores -----
# Metadata only: sites, user names, form field names and times. Saved
# passwords, cookie values, autofill and form values, payment cards and
# addresses are never selected, so they never reach the timeline.

# Column names of the given tables in a SQLite database: hashtable of table
# name -> string[] (tables that do not exist are left out). The queries are
# built from the columns present, as they differ between browser versions.
# Plain PRAGMA table_info works with any sqlite3 version (pragma_table_info()
# needs 3.16, and an older sqlite3 on PATH is used first); a row with cid -1
# names the table whose columns follow.
function Get-Sqlite3TableColumns {
    param([string]$Sqlite3Exe, [string]$DbPath, [string[]]$Tables)
    $query = ($Tables | ForEach-Object {
        "SELECT -1, '" + $_.Replace("'", "''") + "'; PRAGMA table_info(""" + $_.Replace('"', '""') + """);"
    }) -join " "
    $columns = @{}
    $table = ""
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $DbPath -Query $query)
    # table_info rows: cid, name, type, notnull, dflt_value, pk
    foreach ($r in ($rows | ConvertFrom-Csv -Header "Cid", "Name")) {
        if ($r.Cid -eq "-1") { $table = $r.Name; continue }
        if (-not $table) { continue }
        if (-not $columns.ContainsKey($table)) { $columns[$table] = @() }
        $columns[$table] += $r.Name
    }
    return $columns
}

# SQL select expressions for columns that older versions may not have: the
# column (text with line breaks replaced by spaces, so each row stays on one
# CSV line; numbers as 0 when NULL), or '' / 0 when the column is missing
function Get-SqliteColumnSql {
    param([string[]]$Columns, [string[]]$Names, [string]$Alias = "", [switch]$Number)
    foreach ($name in $Names) {
        $ref = if ($Alias) { "$Alias.$name" } else { $name }
        if ($Columns -notcontains $name) { if ($Number) { "0" } else { "''" } }
        elseif ($Number) { "coalesce($ref, 0)" }
        else { "replace(replace(coalesce($ref, ''), char(13), ' '), char(10), ' ')" }
    }
}

# Unix time (since 1970-01-01 UTC, as text or a number) in the given unit ->
# UTC [datetime], or $null when zero or out of range. Firefox stores PRTime
# (microseconds) or milliseconds; Chromium autofill stores seconds.
function ConvertFrom-UnixTime {
    param($Value, [ValidateSet("Seconds", "Milliseconds", "Microseconds")][string]$Unit = "Seconds")
    $n = 0L
    if (-not [long]::TryParse([string]$Value, [ref]$n) -or $n -le 0) { return $null }
    $ticksPerUnit = switch ($Unit) { "Seconds" { 10000000L } "Milliseconds" { 10000L } default { 10L } }
    $epochTicks = 621355968000000000L
    if ($n -gt ([datetime]::MaxValue.Ticks - $epochTicks) / $ticksPerUnit) { return $null }
    return [datetime]::new($epochTicks + $n * $ticksPerUnit, [System.DateTimeKind]::Utc)
}

# UTC time as Details text ("yyyy-MM-dd HH:mm:ss"), or "" for $null
function Format-UtcDetailTime {
    param($Time)
    if ($null -eq $Time) { return "" }
    return ([datetime]$Time).ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Chromium downloads.state, danger_type and interrupt_reason
# (components/history download_constants.h, download_interrupt_reason_values.h)
$script:ChromiumDownloadStates = @{ "0" = "IN_PROGRESS"; "1" = "COMPLETE"; "2" = "CANCELLED"; "3" = "INTERRUPTED"; "4" = "INTERRUPTED" }
$script:ChromiumDangerTypes = @{
    "0" = "NOT_DANGEROUS"; "1" = "DANGEROUS_FILE"; "2" = "DANGEROUS_URL"; "3" = "DANGEROUS_CONTENT"
    "4" = "MAYBE_DANGEROUS_CONTENT"; "5" = "UNCOMMON_CONTENT"; "6" = "USER_VALIDATED"; "7" = "DANGEROUS_HOST"
    "8" = "POTENTIALLY_UNWANTED"; "9" = "ALLOWLISTED_BY_POLICY"; "10" = "ASYNC_SCANNING"; "11" = "BLOCKED_PASSWORD_PROTECTED"
    "12" = "BLOCKED_TOO_LARGE"; "13" = "SENSITIVE_CONTENT_WARNING"; "14" = "SENSITIVE_CONTENT_BLOCK"; "15" = "DEEP_SCANNED_SAFE"
    "16" = "DEEP_SCANNED_OPENED_DANGEROUS"; "17" = "PROMPT_FOR_SCANNING"; "18" = "BLOCKED_UNSUPPORTED_FILETYPE"
    "19" = "DANGEROUS_ACCOUNT_COMPROMISE"; "20" = "DEEP_SCANNED_FAILED"; "21" = "PROMPT_FOR_LOCAL_PASSWORD_SCANNING"
    "22" = "ASYNC_LOCAL_PASSWORD_SCANNING"; "23" = "BLOCKED_SCAN_FAILED"; "24" = "FORCED_SAVE_TO_GDRIVE"; "25" = "FORCED_SAVE_TO_ONEDRIVE"
}
$script:ChromiumInterruptReasons = @{
    "1" = "FILE_FAILED"; "2" = "FILE_ACCESS_DENIED"; "3" = "FILE_NO_SPACE"; "5" = "FILE_NAME_TOO_LONG"; "6" = "FILE_TOO_LARGE"
    "7" = "FILE_VIRUS_INFECTED"; "10" = "FILE_TRANSIENT_ERROR"; "11" = "FILE_BLOCKED"; "12" = "FILE_SECURITY_CHECK_FAILED"
    "13" = "FILE_TOO_SHORT"; "14" = "FILE_HASH_MISMATCH"; "15" = "FILE_SAME_AS_SOURCE"; "20" = "NETWORK_FAILED"
    "21" = "NETWORK_TIMEOUT"; "22" = "NETWORK_DISCONNECTED"; "23" = "NETWORK_SERVER_DOWN"; "24" = "NETWORK_INVALID_REQUEST"
    "30" = "SERVER_FAILED"; "31" = "SERVER_NO_RANGE"; "33" = "SERVER_BAD_CONTENT"; "34" = "SERVER_UNAUTHORIZED"
    "35" = "SERVER_CERT_PROBLEM"; "36" = "SERVER_FORBIDDEN"; "37" = "SERVER_UNREACHABLE"; "38" = "SERVER_CONTENT_LENGTH_MISMATCH"
    "39" = "SERVER_CROSS_ORIGIN_REDIRECT"; "40" = "USER_CANCELED"; "41" = "USER_SHUTDOWN"; "50" = "CRASH"; "51" = "LOCAL_DOWNLOAD_BLOCKED"
}
# Firefox downloads/metaData state (DownloadHistory.sys.mjs), and the
# Chromium state name used for it in Details (State=; the Firefox name is
# kept in FirefoxState=). Paused = stopped with partial data, which Chromium
# stores as interrupted. BLOCKED: blocked by parental controls, the
# reputation check (DIRTY) or content analysis.
$script:FirefoxDownloadStates = @{ "1" = "FINISHED"; "2" = "FAILED"; "3" = "CANCELED"; "4" = "PAUSED"; "6" = "BLOCKED_PARENTAL"; "8" = "DIRTY"; "9" = "BLOCKED_CONTENT_ANALYSIS" }
$script:FirefoxDownloadStateNames = @{
    FINISHED = "COMPLETE"; FAILED = "INTERRUPTED"; CANCELED = "CANCELLED"; PAUSED = "INTERRUPTED"
    BLOCKED_PARENTAL = "BLOCKED"; DIRTY = "BLOCKED"; BLOCKED_CONTENT_ANALYSIS = "BLOCKED"
}
# Verb of the row at a download's end time, by state (no row for other states)
$script:DownloadEndVerbs = @{ COMPLETE = "completed"; CANCELLED = "cancelled"; INTERRUPTED = "interrupted"; BLOCKED = "blocked" }
# Firefox moz_perms.permission and expireType (nsIPermissionManager)
$script:FirefoxPermissionValues = @{ "0" = "UNKNOWN"; "1" = "ALLOW"; "2" = "DENY"; "3" = "PROMPT"; "8" = "ALLOW_SESSION" }
$script:FirefoxPermissionExpiry = @{ "0" = "NEVER"; "1" = "SESSION"; "2" = "TIME"; "3" = "POLICY" }

# Rows for one download: started; ended (completed, cancelled, ...) when that
# is at least a minute after the start -- a quicker end is only in Details;
# and opened from the browser. FileAccess: a download writes a file to disk.
# Returns the number of rows added.
function Add-BrowserDownloadRows {
    param(
        [string]$Source,
        [string]$User,
        [string]$RawPath,
        [string]$Path,
        [string]$Url,
        $StartTime,
        $EndTime,
        $OpenedTime,
        [string]$State,
        [System.Collections.IDictionary]$Details
    )
    $label = if ($Path -and $Url) { "$Path ($Url)" } elseif ($Path) { $Path } else { $Url }
    $verb = $script:DownloadEndVerbs[$State]
    $rows = @(, @($StartTime, "Download started: $label"))
    if ($verb -and $EndTime -and (-not $StartTime -or ($EndTime - $StartTime).TotalSeconds -ge 60)) {
        $rows += , @($EndTime, "Download $($verb): $label")
    }
    $rows += , @($OpenedTime, "Download opened: $label")
    $detailText = Format-ArtifactDetails $Details
    $count = 0
    foreach ($row in $rows) {
        if ($null -eq $row[0]) { continue }
        Add-TimelineEntry -Timestamp $row[0] -Source $Source -EventType "FileAccess" `
            -Description $row[1] `
            -User $User -Details $detailText `
            -Artifact "Browser" -RawPath $RawPath
        $count++
    }
    return $count
}

# Chromium downloads (History): the downloads table with the first and last
# URL of each download's redirect chain (the link followed, the file's URL).
# Times are Chromium times. Returns the number of rows added.
function Add-ChromiumDownloadRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $schema = Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Tables @("downloads", "downloads_url_chains")
    $c = $schema["downloads"]
    if (-not $c -or $c -notcontains "target_path" -or $c -notcontains "start_time") { return 0 }
    $urls = @("''", "''")
    if ($schema["downloads_url_chains"]) {
        $chainUrl = "(SELECT replace(replace(u.url, char(13), ' '), char(10), ' ') FROM downloads_url_chains u " +
                    "WHERE u.id = d.id ORDER BY u.chain_index {0} LIMIT 1)"
        $urls = @(($chainUrl -f "ASC"), ($chainUrl -f "DESC"))
    }
    $sha256 = if ($c -contains "hash") { "CASE WHEN length(d.hash) = 32 THEN lower(hex(d.hash)) ELSE '' END" } else { "''" }
    $text = @(Get-SqliteColumnSql -Columns $c -Alias "d" -Names @("target_path", "current_path", "referrer", "site_url", "tab_url", "tab_referrer_url", "mime_type", "by_ext_name"))
    $numbers = @(Get-SqliteColumnSql -Columns $c -Alias "d" -Number -Names @("start_time", "end_time", "last_access_time", "received_bytes", "total_bytes", "state", "danger_type", "interrupt_reason", "opened"))
    $query = "SELECT " + (($text + $urls + $sha256 + $numbers) -join ", ") + " FROM downloads d ORDER BY d.start_time;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)

    $source = "$(Get-ChromiumBrowserName $File.FullName) Downloads"
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $header = @("Path", "CurrentPath", "Referrer", "SiteUrl", "TabUrl", "TabReferrer", "MimeType", "Extension", "FirstUrl", "Url", "Sha256",
                "Start", "End", "LastAccess", "Received", "Total", "State", "Danger", "Interrupt", "Opened")
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header $header)) {
        $start = ConvertFrom-ChromiumTime $r.Start
        $end = ConvertFrom-ChromiumTime $r.End
        $opened = ConvertFrom-ChromiumTime $r.LastAccess
        $state = Get-AntiVirusCodeName -Names $script:ChromiumDownloadStates -Code $r.State
        $details = [ordered]@{
            Path            = $r.Path
            URL             = $r.Url
            OriginalURL     = $(if ($r.FirstUrl -ne $r.Url) { $r.FirstUrl } else { "" })
            Referrer        = $r.Referrer
            TabURL          = $r.TabUrl
            TabReferrer     = $r.TabReferrer
            SiteURL         = $r.SiteUrl
            MimeType        = $r.MimeType
            State           = $state
            DangerType      = Get-AntiVirusCodeName -Names $script:ChromiumDangerTypes -Code $r.Danger
            InterruptReason = $(if ($r.Interrupt -ne "0") { Get-AntiVirusCodeName -Names $script:ChromiumInterruptReasons -Code $r.Interrupt } else { "" })
            Bytes           = $r.Received
            TotalBytes      = $(if ($r.Total -ne $r.Received -and $r.Total -ne "0") { $r.Total } else { "" })
            Opened          = $(if ($r.Opened -eq "1") { "Yes" } else { "No" })
            StartUtc        = Format-UtcDetailTime $start
            EndUtc          = Format-UtcDetailTime $end
            LastOpenedUtc   = Format-UtcDetailTime $opened
            CurrentPath     = $(if ($r.CurrentPath -ne $r.Path) { $r.CurrentPath } else { "" })
            Extension       = $r.Extension
            SHA256          = $r.Sha256
            Profile         = $profileName
        }
        $count += Add-BrowserDownloadRows -Source $source -User $user -RawPath $File.FullName -Path $r.Path -Url $r.Url `
            -StartTime $start -EndTime $end -OpenedTime $opened -State $state -Details $details
    }
    return $count
}

# Firefox downloads (places.sqlite): the downloads/destinationFileURI
# annotation on the download's URL (added when the download starts; PRTime)
# and the downloads/metaData JSON (state, endTime in milliseconds, fileSize,
# reputationCheckVerdict). Firefox keeps the URL the download started from
# (before any redirect); the referrer is the page of the download visit's
# from_visit (visit_type 7 = DOWNLOAD). Returns the number of rows added.
function Add-FirefoxDownloadRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $query = "SELECT replace(replace(p.url, char(13), ' '), char(10), ' '), replace(replace(d.content, char(13), ' '), char(10), ' '), d.dateAdded, " +
             "coalesce((SELECT replace(replace(m.content, char(13), ' '), char(10), ' ') FROM moz_annos m " +
             "JOIN moz_anno_attributes ma ON ma.id = m.anno_attribute_id WHERE m.place_id = d.place_id AND ma.name = 'downloads/metaData' LIMIT 1), ''), " +
             "coalesce((SELECT replace(replace(rp.url, char(13), ' '), char(10), ' ') FROM moz_historyvisits v " +
             "JOIN moz_historyvisits rv ON rv.id = v.from_visit JOIN moz_places rp ON rp.id = rv.place_id " +
             "WHERE v.place_id = d.place_id AND v.visit_type = 7 ORDER BY v.visit_date DESC LIMIT 1), '') " +
             "FROM moz_annos d JOIN moz_anno_attributes a ON a.id = d.anno_attribute_id JOIN moz_places p ON p.id = d.place_id " +
             "WHERE a.name = 'downloads/destinationFileURI' ORDER BY d.dateAdded;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header "Url", "FileUri", "Added", "MetaData", "Referrer")) {
        $path = $r.FileUri
        try {
            $uri = New-Object System.Uri($r.FileUri)
            if ($uri.IsFile) { $path = $uri.LocalPath }
        }
        catch { Write-Verbose "Download destination is not a file URI: $($r.FileUri)" }
        $meta = $null
        if ($r.MetaData) {
            try { $meta = $r.MetaData | ConvertFrom-Json -ErrorAction Stop }
            catch { Write-Verbose "Could not read download metadata for $($r.Url): $($_.Exception.Message)" }
        }
        $start = ConvertFrom-UnixTime $r.Added -Unit Microseconds
        $end = $null
        $firefoxState = ""
        if ($meta) {
            $end = ConvertFrom-UnixTime $meta.endTime -Unit Milliseconds
            if ($null -ne $meta.state) { $firefoxState = Get-AntiVirusCodeName -Names $script:FirefoxDownloadStates -Code $meta.state }
        }
        $state = $script:FirefoxDownloadStateNames[$firefoxState]
        if (-not $state) { $state = $firefoxState }
        $details = [ordered]@{
            Path         = $path
            URL          = $r.Url
            Referrer     = $r.Referrer
            State        = $state
            FirefoxState = $firefoxState
            DangerType   = $(if ($meta) { $meta.reputationCheckVerdict } else { "" })
            Bytes        = $(if ($meta) { $meta.fileSize } else { "" })
            StartUtc     = Format-UtcDetailTime $start
            EndUtc       = Format-UtcDetailTime $end
            Deleted      = $(if ($meta -and $meta.deleted -eq $true) { "Yes" } else { "" })
            Profile      = $profileName
        }
        $count += Add-BrowserDownloadRows -Source "Firefox Downloads" -User $user -RawPath $File.FullName -Path $path -Url $r.Url `
            -StartTime $start -EndTime $end -OpenedTime $null -State $state -Details $details
    }
    return $count
}

# Rows for one saved login: created; last used, when at least a minute after
# created (both browsers set the last-used time when a login is saved --
# Chromium at the form submit, seconds before the user clicks Save -- so an
# earlier or equal time is not a use and is only in Details); and password
# changed (-Changed, when later than created). A "never save" entry gets one
# row when it was added. -AccountName is the site user name, if known.
# Returns the number of rows added.
function Add-BrowserLoginRows {
    param(
        [string]$Source,
        [string]$User,
        [string]$RawPath,
        [string]$Url,
        [string]$AccountName,
        $Created,
        $LastUsed,
        $Changed,
        [bool]$NeverSave,
        [string]$Details
    )
    $label = if ($AccountName) { "$Url (user: $AccountName)" } else { $Url }
    if ($NeverSave) {
        $rows = @(, @($Created, "Saved login declined: $Url (never save for this site)"))
    }
    else {
        $rows = @(, @($Created, "Saved login created: $label"))
        if ($LastUsed -and (-not $Created -or ($LastUsed - $Created).TotalSeconds -ge 60)) {
            $rows += , @($LastUsed, "Saved login last used: $label")
        }
        if ($Changed -and (-not $Created -or ($Changed - $Created).TotalSeconds -ge 1)) {
            $rows += , @($Changed, "Saved password changed: $label")
        }
    }
    $count = 0
    foreach ($row in $rows) {
        if ($null -eq $row[0]) { continue }
        Add-TimelineEntry -Timestamp $row[0] -Source $Source -EventType "NetworkConnection" `
            -Description $row[1] `
            -User $User -Details $Details `
            -Artifact "Browser" -RawPath $RawPath
        $count++
    }
    return $count
}

# Chromium "Login Data" (logins table): saved logins per site with the user
# name. Times are Chromium times. Returns the number of rows added.
function Add-ChromiumLoginRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $c = (Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Tables @("logins"))["logins"]
    if (-not $c -or $c -notcontains "origin_url" -or $c -notcontains "date_created") { return 0 }
    # Never add password_value (or any other secret column) to these lists
    $text = @(Get-SqliteColumnSql -Columns $c -Names @("origin_url", "action_url", "signon_realm", "username_value"))
    $numbers = @(Get-SqliteColumnSql -Columns $c -Number -Names @("date_created", "date_last_used", "date_password_modified", "times_used", "blacklisted_by_user"))
    $query = "SELECT " + (($text + $numbers) -join ", ") + " FROM logins ORDER BY date_created;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)

    $source = "$(Get-ChromiumBrowserName $File.FullName) Logins"
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header "Url", "Action", "Realm", "Username", "Created", "LastUsed", "PasswordChanged", "TimesUsed", "NeverSave")) {
        $created = ConvertFrom-ChromiumTime $r.Created
        $lastUsed = ConvertFrom-ChromiumTime $r.LastUsed
        $changed = ConvertFrom-ChromiumTime $r.PasswordChanged
        $neverSave = $r.NeverSave -eq "1"
        $details = Format-ArtifactDetails ([ordered]@{
            URL                = $r.Url
            Action             = $r.Action
            Realm              = $r.Realm
            Username           = $r.Username
            TimesUsed          = $r.TimesUsed
            NeverSave          = $(if ($neverSave) { "Yes" } else { "" })
            CreatedUtc         = Format-UtcDetailTime $created
            LastUsedUtc        = Format-UtcDetailTime $lastUsed
            PasswordChangedUtc = Format-UtcDetailTime $changed
            Profile            = $profileName
        })
        $count += Add-BrowserLoginRows -Source $source -User $user -RawPath $File.FullName -Url $r.Url -AccountName $r.Username `
            -Created $created -LastUsed $lastUsed -Changed $changed -NeverSave $neverSave -Details $details
    }
    return $count
}

# Firefox logins.json: saved logins per site. Times are milliseconds since
# 1970 UTC. User names and passwords are stored encrypted; they are blanked
# in the text before it is parsed, so they are never read -- also when the
# file ends inside one (a partial copy). The JSON parser's error is not
# passed on: in Windows PowerShell it quotes the text it could not parse.
function Add-FirefoxLoginRows {
    param([System.IO.FileInfo]$File)
    $text = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8 -ErrorAction Stop
    $text = $text -replace '"(encryptedUsername|encryptedPassword)"\s*:\s*"(?:[^"\\]|\\.?)*(?:"|$)', '"$1":""'
    if ([string]::IsNullOrWhiteSpace($text)) { return 0 }
    try { $json = $text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "not valid JSON (damaged or incomplete file)" }
    if (-not $json -or -not $json.PSObject.Properties["logins"]) { return 0 }
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    foreach ($login in @($json.logins)) {
        if ($null -eq $login) { continue }
        $created = ConvertFrom-UnixTime $login.timeCreated -Unit Milliseconds
        $lastUsed = ConvertFrom-UnixTime $login.timeLastUsed -Unit Milliseconds
        $changed = ConvertFrom-UnixTime $login.timePasswordChanged -Unit Milliseconds
        $details = Format-ArtifactDetails ([ordered]@{
            URL                = $login.hostname
            Action             = $login.formSubmitURL
            Realm              = $login.httpRealm
            UsernameField      = $login.usernameField
            TimesUsed          = $login.timesUsed
            CreatedUtc         = Format-UtcDetailTime $created
            LastUsedUtc        = Format-UtcDetailTime $lastUsed
            PasswordChangedUtc = Format-UtcDetailTime $changed
            Profile            = $profileName
        })
        $count += Add-BrowserLoginRows -Source "Firefox Logins" -User $user -RawPath $File.FullName -Url $login.hostname -AccountName "" `
            -Created $created -LastUsed $lastUsed -Changed $changed -NeverSave $false -Details $details
    }
    return $count
}

# Cookie rows aggregated per host (a profile holds thousands of cookies):
# one at the host's oldest cookie creation and one at its latest access
# (when later), with the cookie count and names. Each host object has Host,
# Cookies, Names (tab-separated), FirstSet, LastAccess, LatestExpiry,
# Persistent, Secure and HttpOnly. Returns the number of rows added.
function Add-BrowserCookieHostRows {
    param([string]$Source, [string]$User, [string]$ProfileName, [string]$RawPath, [object[]]$Hosts)
    $count = 0
    foreach ($cookieHost in $Hosts) {
        # Names sorted and de-duplicated (case-sensitive), cut at 200 characters
        $nameSet = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($n in ("$($cookieHost.Names)" -split "`t")) { if ($n) { [void]$nameSet.Add($n) } }
        $names = @($nameSet) -join ", "
        if ($names.Length -gt 200) { $names = $names.Substring(0, 200) + "... ($($nameSet.Count) names)" }
        $label = "$($cookieHost.Host) ($($cookieHost.Cookies) cookie$(if ($cookieHost.Cookies -ne '1') { 's' }))"
        $details = Format-ArtifactDetails ([ordered]@{
            Host            = $cookieHost.Host
            Cookies         = $cookieHost.Cookies
            Names           = $names
            Persistent      = $cookieHost.Persistent
            Secure          = $cookieHost.Secure
            HttpOnly        = $cookieHost.HttpOnly
            FirstSetUtc     = Format-UtcDetailTime $cookieHost.FirstSet
            LastAccessUtc   = Format-UtcDetailTime $cookieHost.LastAccess
            LatestExpiryUtc = Format-UtcDetailTime $cookieHost.LatestExpiry
            Profile         = $ProfileName
        })
        $rows = @(, @($cookieHost.FirstSet, "Cookies first set: $label"))
        if ($cookieHost.LastAccess -and (-not $cookieHost.FirstSet -or ($cookieHost.LastAccess - $cookieHost.FirstSet).TotalSeconds -ge 1)) {
            $rows += , @($cookieHost.LastAccess, "Cookies last accessed: $label")
        }
        foreach ($row in $rows) {
            if ($null -eq $row[0]) { continue }
            Add-TimelineEntry -Timestamp $row[0] -Source $Source -EventType "NetworkConnection" `
                -Description $row[1] `
                -User $User -Details $details `
                -Artifact "Browser" -RawPath $RawPath
            $count++
        }
    }
    return $count
}

# Chromium cookies (<profile>\Network\Cookies, or the older <profile>\Cookies):
# aggregated per host_key. Times are Chromium times. Returns the row count.
function Add-ChromiumCookieRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $c = (Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Tables @("cookies"))["cookies"]
    if (-not $c -or $c -notcontains "host_key" -or $c -notcontains "name" -or $c -notcontains "creation_utc") { return 0 }
    # Flag counts; older versions name the flags persistent/secure/httponly
    $flagSums = foreach ($names in @(@("is_persistent", "persistent"), @("is_secure", "secure"), @("is_httponly", "httponly"))) {
        $flag = $names | Where-Object { $c -contains $_ } | Select-Object -First 1
        if ($flag) { "SUM(coalesce($flag, 0))" } else { "''" }
    }
    # Never add value or encrypted_value to this query
    $query = "SELECT replace(replace(host_key, char(13), ' '), char(10), ' '), COUNT(*), MIN(CASE WHEN creation_utc > 0 THEN creation_utc END), " +
             "MAX($(Get-SqliteColumnSql -Columns $c -Names 'last_access_utc' -Number)), MAX($(Get-SqliteColumnSql -Columns $c -Names 'expires_utc' -Number)), " +
             ($flagSums -join ", ") + ", group_concat(replace(replace(name, char(13), ' '), char(10), ' '), char(9)) " +
             "FROM cookies GROUP BY host_key ORDER BY host_key;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)
    $hosts = foreach ($r in ($rows | ConvertFrom-Csv -Header "Host", "Cookies", "FirstSet", "LastAccess", "Expiry", "Persistent", "Secure", "HttpOnly", "Names")) {
        [PSCustomObject]@{
            Host         = $r.Host
            Cookies      = $r.Cookies
            Names        = $r.Names
            FirstSet     = ConvertFrom-ChromiumTime $r.FirstSet
            LastAccess   = ConvertFrom-ChromiumTime $r.LastAccess
            LatestExpiry = ConvertFrom-ChromiumTime $r.Expiry
            Persistent   = $r.Persistent
            Secure       = $r.Secure
            HttpOnly     = $r.HttpOnly
        }
    }
    return Add-BrowserCookieHostRows -Source "$(Get-ChromiumBrowserName $File.FullName) Cookies" -User (Get-CollectionUser $File.FullName) `
        -ProfileName (Get-BrowserProfileName $File.FullName) -RawPath $File.FullName -Hosts @($hosts)
}

# Firefox cookies.sqlite (moz_cookies): aggregated per host. creationTime and
# lastAccessed are PRTime. Returns the number of rows added.
function Add-FirefoxCookieRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    # Never add value to this query
    $query = "SELECT replace(replace(host, char(13), ' '), char(10), ' '), COUNT(*), MIN(CASE WHEN creationTime > 0 THEN creationTime END), MAX(lastAccessed), " +
             "SUM(coalesce(isSecure, 0)), SUM(coalesce(isHttpOnly, 0)), group_concat(replace(replace(name, char(13), ' '), char(10), ' '), char(9)) " +
             "FROM moz_cookies GROUP BY host ORDER BY host;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)
    $hosts = foreach ($r in ($rows | ConvertFrom-Csv -Header "Host", "Cookies", "FirstSet", "LastAccess", "Secure", "HttpOnly", "Names")) {
        [PSCustomObject]@{
            Host         = $r.Host
            Cookies      = $r.Cookies
            Names        = $r.Names
            FirstSet     = ConvertFrom-UnixTime $r.FirstSet -Unit Microseconds
            LastAccess   = ConvertFrom-UnixTime $r.LastAccess -Unit Microseconds
            LatestExpiry = $null
            Persistent   = ""
            Secure       = $r.Secure
            HttpOnly     = $r.HttpOnly
        }
    }
    return Add-BrowserCookieHostRows -Source "Firefox Cookies" -User (Get-CollectionUser $File.FullName) `
        -ProfileName (Get-BrowserProfileName $File.FullName) -RawPath $File.FullName -Hosts @($hosts)
}

# Form entry rows (Chromium autofill, Firefox form history): when an entry
# was saved and when it was last used (when later). Only the field name is
# kept; the value typed is never read. Each entry has Total (entries in the
# database), Field, TimesUsed, FirstUsed and LastUsed; the caller passes the
# newest MaxRows. Returns the number of rows added.
function Add-BrowserFormEntryRows {
    param([string]$Source, [string]$User, [string]$ProfileName, [string]$RawPath, [object[]]$Entries, [int]$MaxRows)
    $count = 0
    $total = 0
    foreach ($entry in $Entries) {
        if ($total -eq 0) { [void][int]::TryParse([string]$entry.Total, [ref]$total) }
        $details = Format-ArtifactDetails ([ordered]@{
            Field        = $entry.Field
            TimesUsed    = $entry.TimesUsed
            FirstUsedUtc = Format-UtcDetailTime $entry.FirstUsed
            LastUsedUtc  = Format-UtcDetailTime $entry.LastUsed
            Profile      = $ProfileName
        })
        $rows = @(, @($entry.FirstUsed, "Form entry saved: field $($entry.Field)"))
        if ($entry.LastUsed -and (-not $entry.FirstUsed -or ($entry.LastUsed - $entry.FirstUsed).TotalSeconds -ge 1)) {
            $rows += , @($entry.LastUsed, "Form entry last used: field $($entry.Field)")
        }
        foreach ($row in $rows) {
            if ($null -eq $row[0]) { continue }
            Add-TimelineEntry -Timestamp $row[0] -Source $Source -EventType "NetworkConnection" `
                -Description $row[1] `
                -User $User -Details $details `
                -Artifact "Browser" -RawPath $RawPath
            $count++
        }
    }
    if ($total -gt $MaxRows) {
        Log-Warning "    $total form entries in database; only the newest $MaxRows were added (cap)."
    }
    return $count
}

# Chromium "Web Data" autofill table: form field names with the times they
# were first and last used (seconds since 1970 UTC). Returns the row count.
function Add-ChromiumAutofillRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File, [int]$MaxRows = 20000)
    $c = (Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Tables @("autofill"))["autofill"]
    if (-not $c -or $c -notcontains "name" -or $c -notcontains "date_created") { return 0 }
    # Field names only: never add value or value_lower to this query
    $numbers = @(Get-SqliteColumnSql -Columns $c -Number -Names @("date_created", "date_last_used", "count"))
    $orderBy = if ($c -contains "date_last_used") { "date_last_used DESC, date_created DESC" } else { "date_created DESC" }
    $query = "SELECT (SELECT COUNT(*) FROM autofill), replace(replace(name, char(13), ' '), char(10), ' '), " + ($numbers -join ", ") +
             " FROM autofill ORDER BY $orderBy LIMIT $MaxRows;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)
    $entries = foreach ($r in ($rows | ConvertFrom-Csv -Header "Total", "Field", "Created", "LastUsed", "TimesUsed")) {
        [PSCustomObject]@{
            Total     = $r.Total
            Field     = $r.Field
            TimesUsed = $r.TimesUsed
            FirstUsed = ConvertFrom-UnixTime $r.Created -Unit Seconds
            LastUsed  = ConvertFrom-UnixTime $r.LastUsed -Unit Seconds
        }
    }
    return Add-BrowserFormEntryRows -Source "$(Get-ChromiumBrowserName $File.FullName) Autofill" -User (Get-CollectionUser $File.FullName) `
        -ProfileName (Get-BrowserProfileName $File.FullName) -RawPath $File.FullName -Entries @($entries) -MaxRows $MaxRows
}

# Firefox formhistory.sqlite (moz_formhistory): form field names with first
# and last use (PRTime). Returns the number of rows added.
function Add-FirefoxFormHistoryRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File, [int]$MaxRows = 20000)
    # Field names only: never add value to this query
    $query = "SELECT (SELECT COUNT(*) FROM moz_formhistory), replace(replace(fieldname, char(13), ' '), char(10), ' '), " +
             "firstUsed, lastUsed, timesUsed FROM moz_formhistory ORDER BY lastUsed DESC, firstUsed DESC LIMIT $MaxRows;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)
    $entries = foreach ($r in ($rows | ConvertFrom-Csv -Header "Total", "Field", "FirstUsed", "LastUsed", "TimesUsed")) {
        [PSCustomObject]@{
            Total     = $r.Total
            Field     = $r.Field
            TimesUsed = $r.TimesUsed
            FirstUsed = ConvertFrom-UnixTime $r.FirstUsed -Unit Microseconds
            LastUsed  = ConvertFrom-UnixTime $r.LastUsed -Unit Microseconds
        }
    }
    return Add-BrowserFormEntryRows -Source "Firefox Form History" -User (Get-CollectionUser $File.FullName) `
        -ProfileName (Get-BrowserProfileName $File.FullName) -RawPath $File.FullName -Entries @($entries) -MaxRows $MaxRows
}

# Chromium "Web Data" keywords table: the search engines the browser knows,
# with when each was added, modified and last used (the last two when later
# than added; Chromium times). An engine added or changed outside the
# browser's own sources is a known hijack. Kind: Prepopulated (built in),
# Policy, StarterPack (@bookmarks, ...), AutoGenerated (from a site's search
# form) or Custom (added or edited by the user -- or by software writing to
# Web Data). Returns the row count.
function Add-ChromiumSearchEngineRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $c = (Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Tables @("keywords"))["keywords"]
    if (-not $c -or $c -notcontains "url" -or $c -notcontains "date_created") { return 0 }
    $text = @(Get-SqliteColumnSql -Columns $c -Names @("short_name", "keyword", "url", "originating_url"))
    $numbers = @(Get-SqliteColumnSql -Columns $c -Number -Names @("date_created", "last_modified", "last_visited", "prepopulate_id", "safe_for_autoreplace", "created_by_policy", "starter_pack_id", "usage_count"))
    # Numbers first: a site picks the name of an engine made from its search
    # form, and ConvertFrom-Csv drops a line that starts with '#' (a comment)
    $query = "SELECT " + (($numbers + $text) -join ", ") + " FROM keywords ORDER BY date_created;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)

    $source = "$(Get-ChromiumBrowserName $File.FullName) Search Engines"
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $header = @("Created", "Modified", "LastUsed", "Prepopulated", "AutoReplace", "Policy", "StarterPack", "UsageCount", "Name", "Keyword", "Url", "OriginatingUrl")
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header $header)) {
        $created = ConvertFrom-ChromiumTime $r.Created
        $modified = ConvertFrom-ChromiumTime $r.Modified
        $lastUsed = ConvertFrom-ChromiumTime $r.LastUsed
        $kind = "Custom"
        if ($r.Policy -ne "0") { $kind = "Policy" }
        elseif ($r.Prepopulated -ne "0") { $kind = "Prepopulated" }
        elseif ($r.StarterPack -ne "0") { $kind = "StarterPack" }
        elseif ($r.AutoReplace -eq "1") { $kind = "AutoGenerated" }
        $label = if ($r.Name) { "$($r.Name) ($($r.Url))" } else { $r.Url }
        $details = Format-ArtifactDetails ([ordered]@{
            Name           = $r.Name
            Keyword        = $r.Keyword
            URL            = $r.Url
            Kind           = $kind
            OriginatingURL = $r.OriginatingUrl
            UsageCount     = $r.UsageCount
            CreatedUtc     = Format-UtcDetailTime $created
            ModifiedUtc    = Format-UtcDetailTime $modified
            LastUsedUtc    = Format-UtcDetailTime $lastUsed
            Profile        = $profileName
        })
        $rowList = @(, @($created, "Search engine added: $label"))
        if ($modified -and (-not $created -or ($modified - $created).TotalSeconds -ge 1)) {
            $rowList += , @($modified, "Search engine modified: $label")
        }
        if ($lastUsed -and (-not $created -or ($lastUsed - $created).TotalSeconds -ge 1)) {
            $rowList += , @($lastUsed, "Search engine last used: $label")
        }
        foreach ($row in $rowList) {
            if ($null -eq $row[0]) { continue }
            Add-TimelineEntry -Timestamp $row[0] -Source $source -EventType "NetworkConnection" `
                -Description $row[1] `
                -User $user -Details $details `
                -Artifact "Browser" -RawPath $File.FullName
            $count++
        }
    }
    return $count
}

# Firefox permissions.sqlite (moz_perms): site permissions (notifications,
# camera, microphone, location, pop-ups, add-on installs, ...) at the time
# they were last set (milliseconds since 1970 UTC). Returns the row count.
function Add-FirefoxPermissionRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $query = "SELECT replace(replace(origin, char(13), ' '), char(10), ' '), replace(replace(type, char(13), ' '), char(10), ' '), " +
             "permission, expireType, expireTime, modificationTime FROM moz_perms WHERE modificationTime > 0 ORDER BY modificationTime;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header "Origin", "Type", "Permission", "ExpireType", "ExpireTime", "Modified")) {
        $ts = ConvertFrom-UnixTime $r.Modified -Unit Milliseconds
        if ($null -eq $ts) { continue }
        $value = Get-AntiVirusCodeName -Names $script:FirefoxPermissionValues -Code $r.Permission
        $expires = if ($r.ExpireType -eq "2") { ConvertFrom-UnixTime $r.ExpireTime -Unit Milliseconds } else { $null }
        Add-TimelineEntry -Timestamp $ts -Source "Firefox Permissions" -EventType "NetworkConnection" `
            -Description "Site permission set: $($r.Origin) $($r.Type)=$value" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                Origin     = $r.Origin
                Type       = $r.Type
                Permission = $value
                Expiry     = Get-AntiVirusCodeName -Names $script:FirefoxPermissionExpiry -Code $r.ExpireType
                ExpiresUtc = Format-UtcDetailTime $expires
                Profile    = $profileName
            })) `
            -Artifact "Browser" -RawPath $File.FullName
        $count++
    }
    return $count
}

# ----- Extensions, sessions, settings, history snapshots and favicons -----
# Readers for the binary and compressed browser files, compiled on first
# use (C# 5: Windows PowerShell 5.1 compiles Add-Type code with the old
# compiler -- no interpolation, "=>" members, out var, tuples or nameof):
#   DecompressMozLz4  Firefox session files: "mozLz40\0", uint32 size of
#                     the data, then one LZ4 block
#   BlankJsonMembers  sets the values of the named members of a JSON text
#                     to null before it is parsed, so form data, cookies,
#                     keys and page state are never read
#   StripJsonComments removes // and /* */ comments and trailing commas
#                     outside strings (Chromium accepts them in extension
#                     manifests; ConvertFrom-Json in Windows PowerShell 5.1
#                     does not)
#   ReadSnss          Chromium Session_* / Tabs_* files (an SNSS command
#                     log: "SNSS", int32 version, then uint16 size + uint8
#                     id + payload per command): the navigation entries
#                     (UpdateTabNavigation, a base::Pickle: tab id, index,
#                     URL, title, page state -- skipped, never decoded --,
#                     transition, type mask, referrer, referrer policy,
#                     original URL, user agent flag, time), the selected
#                     entry of each tab, and the close times. Session
#                     files (components/sessions session_service_commands):
#                     SetTabWindow 0 {window id, tab id}, SetSelectedNavigation
#                     Index 7 {tab id, index}, TabClosed 16 and WindowClosed
#                     17 {id, int64 time}. Tabs files (tab_restore_service_
#                     impl): SelectedNavigationInTab 4 {id, index -- among the
#                     entries kept in the file --, int64 time; the time is 0
#                     for the tabs of a closed window}, and Window 9 (a
#                     pickle: window id, selected tab, tab count, int64 close
#                     time), followed by the commands of its tabs
function Initialize-BrowserReader {
    if ($null -ne $script:browserReaderReady) { return $script:browserReaderReady }
    $script:browserReaderReady = $false
    try {
        if (-not ([System.Management.Automation.PSTypeName]'TimelineBrowser.Reader').Type) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TimelineBrowser
{
    // One navigation entry of a Chromium session or tab-restore file
    public sealed class SnssNavigation
    {
        public int TabId;
        public int Index;
        public string Url = "";
        public string Title = "";
        public string Referrer = "";
        public int Transition = -1;
        public long Timestamp;
    }

    public sealed class SnssFile
    {
        public int Version;
        public int Commands;
        // In file order (an entry rewritten later comes later)
        public List<SnssNavigation> Navigations = new List<SnssNavigation>();
        // Tab (or tab-restore entry) id -> close time (Chromium time)
        public Dictionary<int, long> ClosedTimes = new Dictionary<int, long>();
        // Tab id -> window id, and window id -> close time
        public Dictionary<int, int> TabWindows = new Dictionary<int, int>();
        public Dictionary<int, long> WindowClosedTimes = new Dictionary<int, long>();
        // Tab id -> selected entry (Session: navigation index; Tabs: position
        // among the tab's entries in the file, by index)
        public Dictionary<int, int> SelectedIndexes = new Dictionary<int, int>();
        // Tab-restore entries (tabs or windows) the user reopened
        public HashSet<int> Restored = new HashSet<int>();
    }

    public static class Reader
    {
        const int MaxDecompressedSize = 512 * 1024 * 1024;

        public static byte[] DecompressMozLz4(byte[] data)
        {
            byte[] magic = Encoding.ASCII.GetBytes("mozLz40\0");
            if (data == null || data.Length < 12) { throw new InvalidDataException("file too small"); }
            for (int i = 0; i < magic.Length; i++)
            {
                if (data[i] != magic[i]) { throw new InvalidDataException("no mozLz40 header"); }
            }
            int size = BitConverter.ToInt32(data, 8);
            // LZ4 cannot expand data more than about 255 times
            if (size < 0 || size > MaxDecompressedSize || (long)size > (long)(data.Length - 12) * 255 + 64)
            {
                throw new InvalidDataException("implausible data size " + size);
            }
            byte[] output = new byte[size];
            int ip = 12;
            int op = 0;
            while (ip < data.Length)
            {
                int token = data[ip++];
                int literals = token >> 4;
                if (literals == 15) { literals += ReadLength(data, ref ip); }
                if (literals > data.Length - ip || literals > size - op) { throw new InvalidDataException("LZ4 literals out of range at offset " + ip); }
                Buffer.BlockCopy(data, ip, output, op, literals);
                ip += literals;
                op += literals;
                // The last sequence has literals only
                if (ip >= data.Length) { break; }
                if (data.Length - ip < 2) { throw new InvalidDataException("LZ4 data ends inside a match offset"); }
                int offset = data[ip] | (data[ip + 1] << 8);
                ip += 2;
                if (offset == 0 || offset > op) { throw new InvalidDataException("LZ4 match offset out of range at offset " + ip); }
                int matchLength = token & 15;
                if (matchLength == 15) { matchLength += ReadLength(data, ref ip); }
                matchLength += 4;
                if (matchLength > size - op) { throw new InvalidDataException("LZ4 match runs past the data size"); }
                // Byte by byte: the match may overlap the bytes it produces
                int from = op - offset;
                for (int k = 0; k < matchLength; k++) { output[op++] = output[from++]; }
            }
            if (op != size) { Array.Resize(ref output, op); }
            return output;
        }

        static int ReadLength(byte[] data, ref int ip)
        {
            int total = 0;
            int b;
            do
            {
                if (ip >= data.Length) { throw new InvalidDataException("LZ4 data ends inside a length"); }
                b = data[ip++];
                total += b;
                if (total > MaxDecompressedSize) { throw new InvalidDataException("implausible LZ4 length"); }
            } while (b == 255);
            return total;
        }

        // The JSON text with the value of every member called one of the
        // names (at any depth) replaced by null
        public static string BlankJsonMembers(string json, string[] names)
        {
            HashSet<string> blank = new HashSet<string>(names, StringComparer.Ordinal);
            StringBuilder sb = new StringBuilder(json.Length);
            int n = json.Length;
            int i = 0;
            while (i < n)
            {
                char c = json[i];
                if (c != '"') { sb.Append(c); i++; continue; }
                int end = SkipString(json, i);
                sb.Append(json, i, end - i);
                int j = end;
                while (j < n && char.IsWhiteSpace(json[j])) { j++; }
                if (j < n && json[j] == ':' && end - i >= 2 && blank.Contains(json.Substring(i + 1, end - i - 2)))
                {
                    sb.Append(json, end, j + 1 - end);
                    int v = j + 1;
                    while (v < n && char.IsWhiteSpace(json[v])) { v++; }
                    sb.Append("null");
                    i = SkipValue(json, v);
                    continue;
                }
                i = end;
            }
            return sb.ToString();
        }

        // Like BlankJsonMembers, but a member is also blanked when its name
        // (lowercased) contains one of nameParts. This mirrors the collector's
        // secret-name pattern (names containing encrypted_key, _encrypted_data,
        // token or _salt) so an UNREDACTED browser file collected with
        // -IncludeSecrets still has those values removed before it is parsed.
        // nameParts must be lowercase.
        public static string BlankJsonMembersMatching(string json, string[] names, string[] nameParts)
        {
            HashSet<string> blank = new HashSet<string>(names ?? new string[0], StringComparer.Ordinal);
            string[] parts = nameParts ?? new string[0];
            StringBuilder sb = new StringBuilder(json.Length);
            int n = json.Length;
            int i = 0;
            while (i < n)
            {
                char c = json[i];
                if (c != '"') { sb.Append(c); i++; continue; }
                int end = SkipString(json, i);
                sb.Append(json, i, end - i);
                int j = end;
                while (j < n && char.IsWhiteSpace(json[j])) { j++; }
                bool isMember = j < n && json[j] == ':' && end - i >= 2;
                bool match = false;
                if (isMember)
                {
                    string key = json.Substring(i + 1, end - i - 2);
                    match = blank.Contains(key);
                    if (!match && parts.Length > 0)
                    {
                        string lower = key.ToLowerInvariant();
                        for (int p = 0; p < parts.Length; p++)
                        {
                            if (lower.IndexOf(parts[p], StringComparison.Ordinal) >= 0) { match = true; break; }
                        }
                    }
                }
                if (match)
                {
                    sb.Append(json, end, j + 1 - end);
                    int v = j + 1;
                    while (v < n && char.IsWhiteSpace(json[v])) { v++; }
                    sb.Append("null");
                    i = SkipValue(json, v);
                    continue;
                }
                i = end;
            }
            return sb.ToString();
        }

        // The JSON text without // and /* */ comments and without commas
        // that close a list or object (outside strings)
        public static string StripJsonComments(string json)
        {
            StringBuilder sb = new StringBuilder(json.Length);
            int n = json.Length;
            int i = 0;
            while (i < n)
            {
                char c = json[i];
                if (c == '"')
                {
                    int end = SkipString(json, i);
                    sb.Append(json, i, end - i);
                    i = end;
                    continue;
                }
                if (c == '/' && i + 1 < n && json[i + 1] == '/')
                {
                    while (i < n && json[i] != '\n' && json[i] != '\r') { i++; }
                    continue;
                }
                if (c == '/' && i + 1 < n && json[i + 1] == '*')
                {
                    int close = json.IndexOf("*/", i + 2, StringComparison.Ordinal);
                    i = close < 0 ? n : close + 2;
                    sb.Append(' ');
                    continue;
                }
                if (c == ',')
                {
                    // A comma followed (after blanks and comments) by } or ]
                    int k = i + 1;
                    while (k < n)
                    {
                        if (char.IsWhiteSpace(json[k])) { k++; continue; }
                        if (json[k] == '/' && k + 1 < n && json[k + 1] == '/')
                        {
                            while (k < n && json[k] != '\n' && json[k] != '\r') { k++; }
                            continue;
                        }
                        if (json[k] == '/' && k + 1 < n && json[k + 1] == '*')
                        {
                            int close = json.IndexOf("*/", k + 2, StringComparison.Ordinal);
                            k = close < 0 ? n : close + 2;
                            continue;
                        }
                        break;
                    }
                    if (k < n && (json[k] == '}' || json[k] == ']')) { i++; continue; }
                }
                sb.Append(c);
                i++;
            }
            return sb.ToString();
        }

        // Index after the string that starts at s[i] (a quote)
        static int SkipString(string s, int i)
        {
            i++;
            while (i < s.Length)
            {
                char c = s[i];
                if (c == '\\') { i += 2; continue; }
                if (c == '"') { return i + 1; }
                i++;
            }
            return s.Length;
        }

        // Index after the JSON value that starts at s[i]
        static int SkipValue(string s, int i)
        {
            if (i >= s.Length) { return i; }
            char c = s[i];
            if (c == '"') { return SkipString(s, i); }
            if (c == '{' || c == '[')
            {
                int depth = 0;
                while (i < s.Length)
                {
                    char d = s[i];
                    if (d == '"') { i = SkipString(s, i); continue; }
                    if (d == '{' || d == '[') { depth++; }
                    else if (d == '}' || d == ']')
                    {
                        depth--;
                        if (depth == 0) { return i + 1; }
                    }
                    i++;
                }
                return s.Length;
            }
            while (i < s.Length && s[i] != ',' && s[i] != '}' && s[i] != ']' && !char.IsWhiteSpace(s[i])) { i++; }
            return i;
        }

        public static SnssFile ReadSnss(byte[] data, bool tabRestore)
        {
            if (data == null || data.Length < 8 || data[0] != 0x53 || data[1] != 0x4E || data[2] != 0x53 || data[3] != 0x53)
            {
                throw new InvalidDataException("no SNSS header");
            }
            SnssFile file = new SnssFile();
            file.Version = BitConverter.ToInt32(data, 4);
            if (file.Version == 2 || file.Version == 4) { throw new InvalidDataException("encrypted session file (SNSS version " + file.Version + ")"); }
            int navigationCommand = tabRestore ? 1 : 6;
            // Tabs files: the window whose tabs follow, and how many are left
            int windowId = 0;
            int windowTabsLeft = 0;
            int pos = 8;
            while (data.Length - pos >= 2)
            {
                int size = BitConverter.ToUInt16(data, pos);
                pos += 2;
                // A file cut off inside a command ends here
                if (size == 0 || size > data.Length - pos) { break; }
                int id = data[pos];
                int start = pos + 1;
                int length = size - 1;
                pos += size;
                file.Commands++;
                if (id == navigationCommand)
                {
                    SnssNavigation navigation = ReadNavigation(data, start, length);
                    if (navigation != null) { file.Navigations.Add(navigation); }
                }
                else if (tabRestore)
                {
                    if (id == 4 && length >= 8)
                    {
                        int tabId = BitConverter.ToInt32(data, start);
                        file.SelectedIndexes[tabId] = BitConverter.ToInt32(data, start + 4);
                        if (length >= 16)
                        {
                            long closed = BitConverter.ToInt64(data, start + 8);
                            if (closed > 0) { file.ClosedTimes[tabId] = closed; }
                        }
                        if (windowTabsLeft > 0)
                        {
                            file.TabWindows[tabId] = windowId;
                            windowTabsLeft--;
                        }
                    }
                    else if (id == 9 && length >= 24)
                    {
                        // Pickle: uint32 payload size, window id, selected tab,
                        // tab count, int64 close time, bounds, ...
                        windowId = BitConverter.ToInt32(data, start + 4);
                        windowTabsLeft = Math.Max(0, BitConverter.ToInt32(data, start + 12));
                        long closed = BitConverter.ToInt64(data, start + 16);
                        if (closed > 0) { file.WindowClosedTimes[windowId] = closed; }
                    }
                    else if (id == 2 && length >= 4)
                    {
                        file.Restored.Add(BitConverter.ToInt32(data, start));
                    }
                }
                else if (id == 0 && length >= 8)
                {
                    file.TabWindows[BitConverter.ToInt32(data, start + 4)] = BitConverter.ToInt32(data, start);
                }
                else if (id == 7 && length >= 8)
                {
                    file.SelectedIndexes[BitConverter.ToInt32(data, start)] = BitConverter.ToInt32(data, start + 4);
                }
                else if ((id == 16 || id == 17) && length >= 16)
                {
                    long closed = BitConverter.ToInt64(data, start + 8);
                    if (closed <= 0) { continue; }
                    if (id == 16) { file.ClosedTimes[BitConverter.ToInt32(data, start)] = closed; }
                    else { file.WindowClosedTimes[BitConverter.ToInt32(data, start)] = closed; }
                }
            }
            return file;
        }

        static SnssNavigation ReadNavigation(byte[] data, int start, int length)
        {
            if (length < 12) { return null; }
            int payloadSize = BitConverter.ToInt32(data, start);
            int pos = start + 4;
            int end = start + length;
            if (payloadSize >= 0 && payloadSize < end - pos) { end = pos + payloadSize; }
            SnssNavigation navigation = new SnssNavigation();
            int value;
            long time;
            string text;
            if (!ReadInt(data, ref pos, end, out navigation.TabId) || !ReadInt(data, ref pos, end, out navigation.Index)) { return null; }
            if (!ReadString(data, ref pos, end, false, out text)) { return null; }
            navigation.Url = text;
            // Older versions stop after any of these fields
            if (!ReadString(data, ref pos, end, true, out text)) { return navigation; }
            navigation.Title = text;
            if (!SkipString(data, ref pos, end)) { return navigation; }
            if (!ReadInt(data, ref pos, end, out value)) { return navigation; }
            navigation.Transition = value;
            if (!ReadInt(data, ref pos, end, out value)) { return navigation; }
            if (!ReadString(data, ref pos, end, false, out text)) { return navigation; }
            navigation.Referrer = text;
            if (!ReadInt(data, ref pos, end, out value)) { return navigation; }
            if (!SkipString(data, ref pos, end)) { return navigation; }
            if (!ReadInt(data, ref pos, end, out value)) { return navigation; }
            if (!ReadInt64(data, ref pos, end, out time)) { return navigation; }
            navigation.Timestamp = time;
            return navigation;
        }

        // base::Pickle fields: 4-byte aligned; strings are an int32 length
        // (UTF-16 strings: in characters) followed by the data
        static bool ReadInt(byte[] data, ref int pos, int end, out int value)
        {
            value = 0;
            if (end - pos < 4) { return false; }
            value = BitConverter.ToInt32(data, pos);
            pos += 4;
            return true;
        }

        static bool ReadInt64(byte[] data, ref int pos, int end, out long value)
        {
            value = 0;
            if (end - pos < 8) { return false; }
            value = BitConverter.ToInt64(data, pos);
            pos += 8;
            return true;
        }

        static bool ReadString(byte[] data, ref int pos, int end, bool utf16, out string value)
        {
            value = "";
            int length;
            if (!ReadInt(data, ref pos, end, out length) || length < 0) { return false; }
            int bytes = utf16 ? length * 2 : length;
            if (length > end - pos || bytes > end - pos) { return false; }
            value = utf16 ? Encoding.Unicode.GetString(data, pos, bytes) : Encoding.UTF8.GetString(data, pos, bytes);
            pos += (bytes + 3) & ~3;
            return true;
        }

        static bool SkipString(byte[] data, ref int pos, int end)
        {
            int length;
            if (!ReadInt(data, ref pos, end, out length) || length < 0 || length > end - pos) { return false; }
            pos += (length + 3) & ~3;
            return true;
        }
    }
}
'@
        }
        $script:browserReaderReady = $true
    }
    catch {
        Log-Warning "  Browser file reader could not be compiled ($($_.Exception.Message)) -- sessions, settings and extensions skipped."
    }
    return $script:browserReaderReady
}

# ConvertFrom-Json for browser files. PowerShell 7 turns strings that look
# like ISO dates into [datetime] (Windows PowerShell 5.1 does not); from 7.5
# -DateKind String keeps them as text, so titles and names read the same in
# both editions (7.0 to 7.4 still convert them).
$script:jsonDateKindSupported = (Get-Command ConvertFrom-Json).Parameters.ContainsKey("DateKind")
function ConvertFrom-BrowserJsonText {
    param([string]$Text)
    if ($script:jsonDateKindSupported) { return ($Text | ConvertFrom-Json -DateKind String -ErrorAction Stop) }
    return ($Text | ConvertFrom-Json -ErrorAction Stop)
}

# Parse a browser JSON file (Preferences, Local State, extensions.json, ...).
# -Blank: members whose values are set to null first (never read); without
# the reader that does this, the file is not read at all. -AllowComments:
# comments and trailing commas are removed first (extension manifest.json
# and messages.json, which Chromium reads with comments allowed).
function Read-BrowserJsonFile {
    param([string]$Path, [string[]]$Blank, [string[]]$BlankNameParts, [switch]$AllowComments)
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($Blank -or $BlankNameParts -or $AllowComments) {
        if (-not (Initialize-BrowserReader)) { throw "not read (the browser file reader is not available)" }
        if ($AllowComments) { $text = [TimelineBrowser.Reader]::StripJsonComments($text) }
        # -BlankNameParts also blanks members whose name contains a secret
        # substring (Chromium Preferences / Local State), so an unredacted copy
        # is cleaned before parsing; otherwise exact names only.
        if ($BlankNameParts) { $text = [TimelineBrowser.Reader]::BlankJsonMembersMatching($text, [string[]]$Blank, [string[]]$BlankNameParts) }
        elseif ($Blank) { $text = [TimelineBrowser.Reader]::BlankJsonMembers($text, $Blank) }
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { return (ConvertFrom-BrowserJsonText $text) }
    catch { throw "not valid JSON (damaged or incomplete file)" }
}

# Value at a dotted path ("download.default_directory") in the first of the
# parsed JSON documents that has it, or $null. Lists are returned as lists.
function Get-BrowserJsonValue {
    param([object[]]$Documents, [string]$Path)
    foreach ($doc in $Documents) {
        $node = $doc
        foreach ($name in $Path.Split('.')) {
            if ($null -eq $node -or $node -isnot [System.Management.Automation.PSCustomObject]) { $node = $null; break }
            $property = $node.PSObject.Properties[$name]
            $node = if ($property) { $property.Value } else { $null }
        }
        if ($null -ne $node) { return , $node }
    }
    return $null
}

# "a, b, c" from a JSON list (objects by their first member name), cut at
# -MaxLength characters with the total count
function Format-BrowserList {
    param($Items, [int]$MaxLength = 300)
    $names = @(foreach ($item in @($Items)) {
        if ($null -eq $item) { continue }
        if ($item -is [System.Management.Automation.PSCustomObject]) { @($item.PSObject.Properties)[0].Name } else { "$item" }
    })
    $text = $names -join ", "
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + "... ($($names.Count) in all)" }
    return $text
}

# One Snapshot row for a browser setting: "Browser setting: <Setting> = <Value>"
function Add-BrowserSettingRow {
    param($Time, [string]$Source, [string]$User, [string]$RawPath, [string]$Setting, [string]$Value, [string]$Pref,
          [System.Collections.IDictionary]$Extra, [string]$ProfileName)
    $pairs = [ordered]@{ Setting = $Setting; Value = $Value; Pref = $Pref }
    if ($Extra) { foreach ($k in $Extra.Keys) { $pairs[$k] = $Extra[$k] } }
    $pairs["Profile"] = $ProfileName
    Add-TimelineEntry -Timestamp $Time -Source $Source -EventType "Snapshot" `
        -Description "Browser setting: $Setting = $Value" `
        -User $User -Details (Format-ArtifactDetails $pairs) `
        -Artifact "Browser" -RawPath $RawPath
}

# Chromium extension install locations (extensions::mojom::ManifestLocation)
$script:ChromiumExtensionLocations = @{
    "1" = "Internal"; "2" = "ExternalPref"; "3" = "ExternalRegistry"; "4" = "Unpacked"; "5" = "Component"
    "6" = "ExternalPrefDownload"; "7" = "ExternalPolicyDownload"; "8" = "CommandLine"; "9" = "ExternalPolicy"; "10" = "ExternalComponent"
}
# Chromium extension disable reasons (extensions/browser/disable_reason.h):
# bit, name (deprecated bits too, for older profiles). Bits not listed are
# shown as numbers (a browser built on Chromium may add its own).
$script:ChromiumDisableReasons = @(
    @(1, "USER_ACTION"), @(2, "PERMISSIONS_INCREASE"), @(4, "RELOAD"), @(8, "UNSUPPORTED_REQUIREMENT"), @(16, "SIDELOAD_WIPEOUT"),
    @(32, "UNKNOWN_FROM_SYNC"), @(64, "PERMISSIONS_CONSENT"), @(128, "KNOWN_DISABLED"),
    @(256, "NOT_VERIFIED"), @(512, "GREYLIST"), @(1024, "CORRUPTED"), @(2048, "REMOTE_INSTALL"), @(4096, "INACTIVE_EPHEMERAL_APP"),
    @(8192, "EXTERNAL_EXTENSION"), @(16384, "UPDATE_REQUIRED_BY_POLICY"), @(32768, "CUSTODIAN_APPROVAL_REQUIRED"), @(65536, "BLOCKED_BY_POLICY"),
    @(131072, "BLOCKED_MATURE"), @(262144, "REMOTELY_FOR_MALWARE"), @(524288, "REINSTALL"), @(1048576, "NOT_ALLOWLISTED"),
    @(2097152, "NOT_ASH_KEEPLISTED"), @(4194304, "PUBLISHED_IN_STORE_REQUIRED_BY_POLICY"), @(8388608, "UNSUPPORTED_MANIFEST_VERSION"),
    @(16777216, "UNSUPPORTED_DEVELOPER_EXTENSION"), @(33554432, "UNKNOWN"), @(67108864, "BLOCKED_BY_CLOUD_POLICY_CHECK"),
    @(134217728, "BY_ANOTHER_EXTENSION")
)
# Members never read from Chromium Preferences, Secure Preferences and Local
# State: keys, password hashes, MACs, account data and per-site settings.
# keystore_encryption_key_state is the Chromium sync keystore key the
# collector also blanks.
$script:ChromiumPrefsBlankMembers = @("os_crypt", "password_hash_data_list", "protection", "account_info", "gaia_cookie", "content_settings", "incognito_content_settings", "keystore_encryption_key_state")
# Secret-name substrings (lowercase) blanked in those files too, so an
# UNREDACTED copy (collector -IncludeSecrets) still has its encrypted keys,
# tokens and salts removed before parsing. Mirrors the collector's secret
# pattern (names containing encrypted_key, _encrypted_data, token or _salt).
$script:ChromiumSecretNameParts = @("encrypted_key", "_encrypted_data", "token", "_salt")

# Disable reasons of a Chromium extension (a bit mask, or a list in newer
# versions) as names; unknown bits as numbers
function Format-ChromiumDisableReasons {
    param($Value)
    $mask = 0L
    foreach ($v in @($Value)) {
        $n = 0L
        if ([long]::TryParse("$v", [ref]$n)) { $mask = $mask -bor $n }
    }
    if ($mask -eq 0) { return "" }
    $names = @()
    foreach ($reason in $script:ChromiumDisableReasons) {
        $bit = [long]$reason[0]
        if (($mask -band $bit) -ne 0) { $names += $reason[1]; $mask = $mask -band (-bnot $bit) }
    }
    if ($mask -ne 0) { $names += "$mask" }
    return ($names -join ", ")
}

# Extension name from its manifest: "__MSG_key__" names are looked up in
# _locales\<default_locale>\messages.json next to the collected manifest
# (keys are case-insensitive). Returns the name as found when that fails.
function Resolve-ChromiumExtensionName {
    param([string]$Name, [string]$ManifestDir, [string]$Locale)
    if ($Name -notmatch '^__MSG_(.+)__$' -or -not $ManifestDir -or -not $Locale) { return $Name }
    $key = $Matches[1]
    $messagesPath = Join-Path $ManifestDir "_locales\$Locale\messages.json"
    if (-not (Test-Path -LiteralPath $messagesPath)) { return $Name }
    try {
        $messages = Read-BrowserJsonFile -Path $messagesPath -AllowComments
        foreach ($property in $messages.PSObject.Properties) {
            if ($property.Name -eq $key -and $property.Value.message) { return [string]$property.Value.message }
        }
    }
    catch { Write-Verbose "Could not read $messagesPath : $($_.Exception.Message)" }
    return $Name
}

# Installed extensions of one Chromium profile, from extensions.settings in
# Secure Preferences and Preferences (Secure Preferences first; an entry in
# both is merged). Rows: installed (first_install_time, or install_time in
# older versions) and updated (last_update_time, at least a minute later),
# EventType Installation; an extension with no install time gets a Snapshot
# row. Name and version come from the manifest stored in the settings, else
# from the collected Extensions\<id>\<version>\manifest.json. Component
# extensions (location Component / ExternalComponent) are part of the browser
# -- installed and updated with it -- and are only counted in the log; so are
# entries without a location (permission records of extensions that are not
# installed). Returns the number of rows added.
function Add-ChromiumExtensionRows {
    param([object[]]$Documents, [string]$ProfileDir, [string]$Source, [string]$User, [string]$ProfileName, [string]$RawPath, $SnapshotTime)
    # id -> settings objects for that id, Secure Preferences first
    $settings = [ordered]@{}
    foreach ($doc in $Documents) {
        $all = Get-BrowserJsonValue -Documents @($doc) -Path "extensions.settings"
        if ($null -eq $all) { continue }
        foreach ($property in $all.PSObject.Properties) {
            if (-not $settings.Contains($property.Name)) { $settings[$property.Name] = @() }
            $settings[$property.Name] += $property.Value
        }
    }
    $count = 0
    $builtIn = 0
    foreach ($id in $settings.Keys) {
        $entries = $settings[$id]
        $field = @{}
        foreach ($name in @("location", "manifest", "path", "first_install_time", "install_time", "last_update_time", "from_webstore",
                            "was_installed_by_default", "was_installed_by_oem", "state", "disable_reasons", "granted_permissions", "active_permissions")) {
            $field[$name] = Get-BrowserJsonValue -Documents $entries -Path $name
        }
        $locationCode = "$($field['location'])"
        if (-not $locationCode) { continue }
        if ($locationCode -eq "5" -or $locationCode -eq "10") { $builtIn++; continue }

        # Manifest: from the settings, else the collected copy
        $relPath = "$($field['path'])"
        $manifestDir = $null
        if ($relPath -and -not [System.IO.Path]::IsPathRooted($relPath)) {
            $manifestDir = Join-Path $ProfileDir "Extensions\$relPath"
        }
        elseif (Test-Path -LiteralPath (Join-Path $ProfileDir "Extensions\$id")) {
            $found = Get-ChildItem -LiteralPath (Join-Path $ProfileDir "Extensions\$id") -Filter "manifest.json" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { $manifestDir = $found.DirectoryName }
        }
        $manifest = $field["manifest"]
        if ($null -eq $manifest -and $manifestDir -and (Test-Path -LiteralPath (Join-Path $manifestDir "manifest.json"))) {
            try { $manifest = Read-BrowserJsonFile -Path (Join-Path $manifestDir "manifest.json") -AllowComments }
            catch { Log-Warning "    Could not read the manifest of extension $id : $($_.Exception.Message)" }
        }
        $name = ""
        $version = ""
        $updateUrl = ""
        $overrides = @()
        if ($manifest) {
            $name = Resolve-ChromiumExtensionName -Name "$($manifest.name)" -ManifestDir $manifestDir -Locale "$($manifest.default_locale)"
            $version = "$($manifest.version)"
            $updateUrl = "$($manifest.update_url)"
            foreach ($overrideKey in @("chrome_settings_overrides", "chrome_url_overrides")) {
                if ($manifest.PSObject.Properties[$overrideKey] -and $manifest.$overrideKey) {
                    $overrides += @($manifest.$overrideKey.PSObject.Properties | ForEach-Object { $_.Name })
                }
            }
        }

        $permissions = $field["granted_permissions"]
        if ($null -eq $permissions) { $permissions = $field["active_permissions"] }
        $apiList = @()
        $hostList = @()
        if ($permissions) {
            $apiList = @($permissions.api) + @($permissions.manifest_permissions)
            $hostList = @($permissions.explicit_host) + @($permissions.scriptable_host) | Select-Object -Unique
        }
        $disabled = Format-ChromiumDisableReasons $field["disable_reasons"]
        $state = if ($disabled -or "$($field['state'])" -eq "0") { "Disabled" } else { "Enabled" }
        $location = $script:ChromiumExtensionLocations[$locationCode]
        if (-not $location) { $location = $locationCode }
        $installed = ConvertFrom-ChromiumTime $field["first_install_time"]
        if (-not $installed) { $installed = ConvertFrom-ChromiumTime $field["install_time"] }
        $updated = ConvertFrom-ChromiumTime $field["last_update_time"]
        $details = Format-ArtifactDetails ([ordered]@{
            ID                 = $id
            Name               = $name
            Version            = $version
            Location           = $location
            LocationCode       = $locationCode
            State              = $state
            DisableReasons     = $disabled
            FromWebstore       = $(if ($field["from_webstore"] -eq $true) { "Yes" } else { "No" })
            InstalledByDefault = $(if ($field["was_installed_by_default"] -eq $true) { "Yes" } else { "" })
            InstalledByOEM     = $(if ($field["was_installed_by_oem"] -eq $true) { "Yes" } else { "" })
            Path               = $(if ([System.IO.Path]::IsPathRooted($relPath)) { $relPath } else { "" })
            UpdateURL          = $updateUrl
            Overrides          = ($overrides -join ", ")
            Permissions        = Format-BrowserList $apiList
            HostPermissions    = Format-BrowserList $hostList
            InstallTimeUtc     = Format-UtcDetailTime $installed
            UpdateTimeUtc      = Format-UtcDetailTime $updated
            Profile            = $ProfileName
        })
        $label = if ($name) { "$name ($id)" } else { $id }
        $rows = @()
        if ($installed) {
            $rows += , @($installed, "Installation", "Browser extension installed: $label")
            if ($updated -and ($updated - $installed).TotalSeconds -ge 60) { $rows += , @($updated, "Installation", "Browser extension updated: $label") }
        }
        elseif ($SnapshotTime) {
            $rows += , @($SnapshotTime, "Snapshot", "Browser extension present: $label")
        }
        foreach ($row in $rows) {
            Add-TimelineEntry -Timestamp $row[0] -Source $Source -EventType $row[1] `
                -Description $row[2] `
                -User $User -Details $details `
                -Artifact "Browser" -RawPath $RawPath
            $count++
        }
    }
    if ($builtIn -gt 0) { Log "    $builtIn built-in component extension(s) not listed (installed and updated with the browser)." }
    return $count
}

# Chromium session.restore_on_startup (session_startup_pref.h)
$script:ChromiumStartupModes = @{ "1" = "Restore last session"; "4" = "Open specific pages"; "5" = "New tab page"; "6" = "Restore last session and open specific pages" }

# Leaves (dotted path and value) of a parsed JSON object; lists are leaves
function Get-BrowserJsonLeaves {
    param($Node, [string]$Prefix)
    if ($Node -isnot [System.Management.Automation.PSCustomObject]) {
        [PSCustomObject]@{ Path = $Prefix; Value = $Node }
        return
    }
    foreach ($property in $Node.PSObject.Properties) {
        $path = if ($Prefix) { "$Prefix.$($property.Name)" } else { $property.Name }
        Get-BrowserJsonLeaves -Node $property.Value -Prefix $path
    }
}

# Settings of forensic interest from a Chromium profile's Preferences and
# Secure Preferences, as Snapshot rows at the collection time: proxy (also
# one an extension set), download directory, startup pages, homepage,
# default search engine, clearing data on exit (any "clear ... on exit"
# setting, and cookies kept for the session only), history saving disabled
# and private browsing forced. Only what the profile stores: settings
# enforced by policy (the registry) are not here. Chromium on Windows keeps
# no time of the last "Clear browsing data" (browser.last_clear_browsing_
# data_time is registered on iOS only), so there is no row for it. Returns
# the row count.
function Add-ChromiumSettingRows {
    param([object[]]$Documents, [string]$Source, [string]$User, [string]$ProfileName, [string]$RawPath, $SnapshotTime)
    $count = 0
    $settingRows = New-Object System.Collections.Generic.List[object]

    $proxy = Get-BrowserJsonValue -Documents $Documents -Path "proxy"
    if ($proxy -and $proxy.mode -and $proxy.mode -ne "system") {
        $target = @($proxy.server, $proxy.pac_url) | Where-Object { $_ } | Select-Object -First 1
        $settingRows.Add(@("Proxy", ("$($proxy.mode) $target").Trim(), "proxy", [ordered]@{ Bypass = $proxy.bypass_list }))
    }
    # A proxy set by an extension is kept with that extension's settings
    # (in either file)
    $extensionProxyPrefs = @()
    foreach ($doc in $Documents) {
        $extensionSettings = Get-BrowserJsonValue -Documents @($doc) -Path "extensions.settings"
        if (-not $extensionSettings) { continue }
        foreach ($extension in $extensionSettings.PSObject.Properties) {
            foreach ($scope in @("preferences", "regular_only_preferences", "incognito_preferences")) {
                $extensionProxy = Get-BrowserJsonValue -Documents @($extension.Value) -Path "$scope.proxy"
                $pref = "extensions.settings.$($extension.Name).$scope.proxy"
                if (-not $extensionProxy -or $extensionProxyPrefs -contains $pref) { continue }
                $extensionProxyPrefs += $pref
                $mode = Get-BrowserJsonValue -Documents @($extensionProxy) -Path "mode"
                $target = @((Get-BrowserJsonValue -Documents @($extensionProxy) -Path "server"), (Get-BrowserJsonValue -Documents @($extensionProxy) -Path "pac_url")) |
                    Where-Object { $_ } | Select-Object -First 1
                $settingRows.Add(@("Proxy", ("$mode $target").Trim(), $pref, [ordered]@{ SetByExtension = $extension.Name }))
            }
        }
    }

    $downloadDir = Get-BrowserJsonValue -Documents $Documents -Path "download.default_directory"
    if ($downloadDir) {
        $prompt = Get-BrowserJsonValue -Documents $Documents -Path "download.prompt_for_download"
        $settingRows.Add(@("Download directory", "$downloadDir", "download.default_directory", [ordered]@{ PromptForDownload = $(if ($null -ne $prompt) { if ($prompt) { "Yes" } else { "No" } } else { "" }) }))
    }

    $startupMode = "$(Get-BrowserJsonValue -Documents $Documents -Path 'session.restore_on_startup')"
    # (Assigned first: @() around the call would wrap the returned list once more)
    $startupUrls = Get-BrowserJsonValue -Documents $Documents -Path "session.startup_urls"
    $startupUrls = @($startupUrls | Where-Object { $_ })
    if ($startupMode -or $startupUrls.Count -gt 0) {
        $modeName = $script:ChromiumStartupModes[$startupMode]
        if (-not $modeName) { $modeName = $(if ($startupMode) { "Mode $startupMode" } else { "Open specific pages" }) }
        $value = if ($startupUrls.Count -gt 0) { "$($modeName): $(Format-BrowserList $startupUrls)" } else { $modeName }
        $settingRows.Add(@("Startup", $value, "session.restore_on_startup, session.startup_urls", $null))
    }

    $homepage = Get-BrowserJsonValue -Documents $Documents -Path "homepage"
    if ($homepage) {
        $isNewTab = Get-BrowserJsonValue -Documents $Documents -Path "homepage_is_newtabpage"
        $settingRows.Add(@("Homepage", "$homepage", "homepage", [ordered]@{ HomepageIsNewTabPage = $(if ($isNewTab -eq $true) { "Yes" } elseif ($isNewTab -eq $false) { "No" } else { "" }) }))
    }

    $engine = Get-BrowserJsonValue -Documents $Documents -Path "default_search_provider_data.template_url_data"
    if ($engine -and $engine.url) {
        $engineName = if ($engine.short_name) { "$($engine.short_name) ($($engine.url))" } else { "$($engine.url)" }
        $settingRows.Add(@("Default search engine", $engineName, "default_search_provider_data.template_url_data", [ordered]@{ Keyword = $engine.keyword }))
    }
    else {
        $legacyUrl = Get-BrowserJsonValue -Documents $Documents -Path "default_search_provider.search_url"
        if ($legacyUrl) {
            $legacyName = Get-BrowserJsonValue -Documents $Documents -Path "default_search_provider.name"
            $settingRows.Add(@("Default search engine", ("$legacyName ($legacyUrl)" -replace '^ \(|\)$', '').Trim(), "default_search_provider.search_url", $null))
        }
    }

    # Clearing data on exit: any "clear ... on exit / close / shutdown"
    # setting that is on -- true, or a list that is not empty (names differ
    # between Chromium browsers, e.g. Brave's browser.clear_data.
    # cookies_on_exit; notices, prompts and counters about such a setting
    # are not the setting) -- and cookies kept for the session only (default
    # cookie setting 4)
    $onExit = @()
    foreach ($doc in $Documents) {
        foreach ($leaf in @(Get-BrowserJsonLeaves -Node $doc -Prefix "")) {
            if ($leaf.Path -like "extensions.*" -or $leaf.Path -notmatch '(?i)clear[a-z_.]*on_?(exit|close|shutdown)|(exit|close|shutdown)[a-z_.]*clear') { continue }
            if (($leaf.Path -split '\.')[-1] -match '(?i)notice|migrat|shown|seen|dismiss|prompt|promo|count|time|version') { continue }
            $on = ($leaf.Value -is [bool] -and $leaf.Value) -or ($leaf.Value -is [array] -and $leaf.Value.Count -gt 0)
            if ($on -and $onExit -notcontains $leaf.Path) { $onExit += $leaf.Path }
        }
    }
    if ($onExit.Count -gt 0) {
        $settingRows.Add(@("Clear data on exit", "On ($(($onExit | ForEach-Object { ($_ -split '\.')[-1] }) -join ', '))", ($onExit -join ", "), $null))
    }
    if ("$(Get-BrowserJsonValue -Documents $Documents -Path 'profile.default_content_setting_values.cookies')" -eq "4") {
        $settingRows.Add(@("Clear data on exit", "On (cookies and site data: kept for the session only)", "profile.default_content_setting_values.cookies", $null))
    }
    if ((Get-BrowserJsonValue -Documents $Documents -Path "history.saving_disabled") -eq $true) {
        $settingRows.Add(@("History disabled", "Yes", "history.saving_disabled", $null))
    }
    if ("$(Get-BrowserJsonValue -Documents $Documents -Path 'incognito.mode_availability')" -eq "2") {
        $settingRows.Add(@("Private browsing always on", "Yes", "incognito.mode_availability", $null))
    }

    if ($SnapshotTime) {
        foreach ($s in $settingRows) {
            Add-BrowserSettingRow -Time $SnapshotTime -Source $Source -User $User -RawPath $RawPath -Setting $s[0] -Value $s[1] -Pref $s[2] -Extra $s[3] -ProfileName $ProfileName
            $count++
        }
    }
    return $count
}

# Firefox prefs.js: user_pref("name", value) lines as a hashtable of name ->
# value (text, bool or number). Prefs named like a secret (token, secret,
# password, push user agent ID) are not read.
function Read-FirefoxPrefs {
    param([string]$Path)
    $prefs = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        if ($line -notmatch '^\s*user_pref\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*(.+?)\s*\)\s*;\s*$') { continue }
        $name = $Matches[1]
        if ($name -match '(?i)token|secret|password|useragentid') { continue }
        $raw = $Matches[2]
        $value = $raw
        if ($raw -match '^"(.*)"$') {
            $value = $Matches[1]
            try { $value = [regex]::Unescape($value) } catch { Write-Verbose "Could not unescape pref $name" }
        }
        elseif ($raw -eq "true") { $value = $true }
        elseif ($raw -eq "false") { $value = $false }
        else {
            $number = 0L
            if ([long]::TryParse($raw, [ref]$number)) { $value = $number }
        }
        $prefs[$name] = $value
    }
    return $prefs
}

# Firefox network.proxy.type and browser.startup.page values
$script:FirefoxProxyTypes = @{ "0" = "None (direct)"; "1" = "Manual"; "2" = "PAC"; "4" = "Auto-detect (WPAD)"; "5" = "System" }
$script:FirefoxStartupPages = @{ "0" = "Blank page"; "1" = "Homepage"; "3" = "Restore previous session" }
# What Firefox clears on shutdown when privacy.sanitize.sanitizeOnShutdown is
# on: the items of one pref branch and their defaults (browser/app/profile/
# firefox.js). prefs.js holds only values that differ from the default, so
# the defaults are overlaid with it. The branch in use: privacy.
# clearOnShutdown_v2 once Firefox migrated the old prefs (privacy.sanitize.
# clearOnShutdown.hasMigratedToNewPrefs2 / 3), else privacy.clearOnShutdown.
$script:FirefoxClearOnShutdownItems = @{
    "v1"  = [ordered]@{ history = $true; formdata = $true; downloads = $true; cookies = $true; cache = $true; sessions = $true; offlineApps = $false; siteSettings = $false; openWindows = $false }
    "v2"  = [ordered]@{ historyFormDataAndDownloads = $true; cookiesAndStorage = $true; cache = $true; siteSettings = $false }
    "v2b" = [ordered]@{ browsingHistoryAndDownloads = $true; formdata = $false; cookiesAndStorage = $true; cache = $true; siteSettings = $false }
}

# Settings of forensic interest from a Firefox prefs.js (only settings the
# user changed are in the file), as Snapshot rows at the collection time:
# proxy (network.proxy.*), homepage and startup (browser.startup.*),
# download directory (browser.download.dir), clearing data on shutdown
# (privacy.sanitize.sanitizeOnShutdown with the items cleared and kept, see
# above; cookies kept for the session only: network.cookie.lifetimePolicy
# 2), history disabled (places.history.enabled = false) and private
# browsing always on (browser.privatebrowsing.autostart). Returns the row
# count.
function Add-FirefoxSettingRows {
    param([System.IO.FileInfo]$File)
    $snapshotTime = Get-SnapshotTimeUtc -File $File
    if (-not $snapshotTime) { return 0 }
    $prefs = Read-FirefoxPrefs -Path $File.FullName
    $settingRows = New-Object System.Collections.Generic.List[object]

    if ($prefs.ContainsKey("network.proxy.type")) {
        $type = "$($prefs['network.proxy.type'])"
        $value = $script:FirefoxProxyTypes[$type]
        if (-not $value) { $value = "Type $type" }
        if ($type -eq "1") {
            $servers = foreach ($kind in @("http", "ssl", "socks")) {
                if ($prefs["network.proxy.$kind"]) { "$kind=$($prefs["network.proxy.$kind"]):$($prefs["network.proxy.$($kind)_port"])" }
            }
            if ($servers) { $value += " " + (@($servers) -join " ") }
        }
        elseif ($type -eq "2" -and $prefs["network.proxy.autoconfig_url"]) { $value += " $($prefs['network.proxy.autoconfig_url'])" }
        $settingRows.Add(@("Proxy", $value, "network.proxy.type", [ordered]@{ Bypass = $prefs["network.proxy.no_proxies_on"] }))
    }
    if ($prefs["browser.startup.homepage"]) {
        # Several pages are separated by |
        $settingRows.Add(@("Homepage", ("$($prefs['browser.startup.homepage'])" -replace '\|', ', '), "browser.startup.homepage", $null))
    }
    if ($prefs.ContainsKey("browser.startup.page")) {
        $page = "$($prefs['browser.startup.page'])"
        $value = $script:FirefoxStartupPages[$page]
        if (-not $value) { $value = "Page $page" }
        $settingRows.Add(@("Startup", $value, "browser.startup.page", $null))
    }
    if ($prefs["browser.download.dir"]) {
        $settingRows.Add(@("Download directory", "$($prefs['browser.download.dir'])", "browser.download.dir", [ordered]@{ FolderList = $prefs["browser.download.folderList"] }))
    }
    if ($prefs["privacy.sanitize.sanitizeOnShutdown"] -eq $true) {
        $set = "v1"
        $branch = "privacy.clearOnShutdown"
        if ($prefs["privacy.sanitize.useOldClearHistoryDialog"] -ne $true) {
            if ($prefs["privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3"] -eq $true) { $set = "v2b" }
            elseif ($prefs["privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs2"] -eq $true) { $set = "v2" }
            if ($set -ne "v1") { $branch = "privacy.clearOnShutdown_v2" }
        }
        $cleared = @()
        $kept = @()
        foreach ($item in $script:FirefoxClearOnShutdownItems[$set].Keys) {
            $on = $script:FirefoxClearOnShutdownItems[$set][$item]
            if ($prefs.ContainsKey("$branch.$item") -and $prefs["$branch.$item"] -is [bool]) { $on = $prefs["$branch.$item"] }
            if ($on) { $cleared += $item } else { $kept += $item }
        }
        $value = "On (cleared: $(if ($cleared) { $cleared -join ', ' } else { 'nothing' }))"
        $settingRows.Add(@("Clear data on exit", $value, "privacy.sanitize.sanitizeOnShutdown",
            [ordered]@{ Cleared = ($cleared -join ", "); Kept = ($kept -join ", "); PrefBranch = $branch }))
    }
    if ("$($prefs['network.cookie.lifetimePolicy'])" -eq "2") {
        $settingRows.Add(@("Clear data on exit", "On (cookies and site data: kept for the session only)", "network.cookie.lifetimePolicy", $null))
    }
    if ($prefs["places.history.enabled"] -eq $false) {
        $settingRows.Add(@("History disabled", "Yes", "places.history.enabled", $null))
    }
    if ($prefs["browser.privatebrowsing.autostart"] -eq $true) {
        $settingRows.Add(@("Private browsing always on", "Yes", "browser.privatebrowsing.autostart", $null))
    }

    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    foreach ($s in $settingRows) {
        Add-BrowserSettingRow -Time $snapshotTime -Source "Firefox Preferences" -User $user -RawPath $File.FullName -Setting $s[0] -Value $s[1] -Pref $s[2] -Extra $s[3] -ProfileName $profileName
    }
    return $settingRows.Count
}

# Firefox add-on install locations of add-ons built into Firefox (system
# add-ons and built-in themes and extensions): only counted in the log
$script:FirefoxBuiltInAddonLocations = @("app-builtin", "app-builtin-addons", "app-system-defaults", "app-system-addons")
# AddonManager.SIGNEDSTATE_*
$script:FirefoxSignedStates = @{ "-2" = "Broken"; "-1" = "Unknown"; "0" = "Missing"; "1" = "Preliminary"; "2" = "Signed"; "3" = "System"; "4" = "Privileged" }

# Firefox extensions.json: the add-ons of a profile (extensions, themes,
# language packs, dictionaries), with installed and updated rows like the
# Chromium extensions. Names: defaultLocale.name, else addons.json (the
# add-ons site data next to it). Returns the number of rows added.
function Add-FirefoxExtensionRows {
    param([System.IO.FileInfo]$File)
    $json = Read-BrowserJsonFile -Path $File.FullName -Blank @("startupData", "locales", "targetApplications", "icons")
    if (-not $json -or -not $json.PSObject.Properties["addons"]) { return 0 }
    $siteNames = @{}
    $addonsJson = Join-Path $File.DirectoryName "addons.json"
    if (Test-Path -LiteralPath $addonsJson) {
        try {
            foreach ($a in @((Read-BrowserJsonFile -Path $addonsJson).addons)) { if ($a -and $a.id -and $a.name) { $siteNames["$($a.id)"] = "$($a.name)" } }
        }
        catch { Log-Warning "    Could not read $addonsJson : $($_.Exception.Message)" }
    }
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    $builtIn = 0
    foreach ($addon in @($json.addons)) {
        if ($null -eq $addon -or -not $addon.id) { continue }
        if ($script:FirefoxBuiltInAddonLocations -contains "$($addon.location)") { $builtIn++; continue }
        $id = "$($addon.id)"
        $name = ""
        if ($addon.defaultLocale -and $addon.defaultLocale.name) { $name = "$($addon.defaultLocale.name)" }
        elseif ($siteNames.ContainsKey($id)) { $name = $siteNames[$id] }
        $installed = ConvertFrom-UnixTime $addon.installDate -Unit Milliseconds
        $updated = ConvertFrom-UnixTime $addon.updateDate -Unit Milliseconds
        $signed = ""
        if ($null -ne $addon.signedState) { $signed = Get-AntiVirusCodeName -Names $script:FirefoxSignedStates -Code "$($addon.signedState)" }
        $details = Format-ArtifactDetails ([ordered]@{
            ID              = $id
            Name            = $name
            Version         = $addon.version
            Type            = $addon.type
            Location        = $addon.location
            Active          = $(if ($addon.active -eq $true) { "Yes" } else { "No" })
            UserDisabled    = $(if ($addon.userDisabled -eq $true) { "Yes" } else { "" })
            SignedState     = $signed
            SourceURI       = $addon.sourceURI
            ForeignInstall  = $(if ($addon.foreignInstall -eq $true) { "Yes" } else { "" })
            InstallSource   = $(if ($addon.installTelemetryInfo) { $addon.installTelemetryInfo.source } else { "" })
            Hidden          = $(if ($addon.hidden -eq $true) { "Yes" } else { "" })
            Permissions     = $(if ($addon.userPermissions) { Format-BrowserList $addon.userPermissions.permissions } else { "" })
            HostPermissions = $(if ($addon.userPermissions) { Format-BrowserList $addon.userPermissions.origins } else { "" })
            InstallTimeUtc  = Format-UtcDetailTime $installed
            UpdateTimeUtc   = Format-UtcDetailTime $updated
            Profile         = $profileName
        })
        $label = if ($name) { "$name ($id)" } else { $id }
        $rows = @()
        if ($installed) {
            $rows += , @($installed, "Browser extension installed: $label")
            if ($updated -and ($updated - $installed).TotalSeconds -ge 60) { $rows += , @($updated, "Browser extension updated: $label") }
        }
        foreach ($row in $rows) {
            Add-TimelineEntry -Timestamp $row[0] -Source "Firefox Extensions" -EventType "Installation" `
                -Description $row[1] `
                -User $user -Details $details `
                -Artifact "Browser" -RawPath $File.FullName
            $count++
        }
    }
    if ($builtIn -gt 0) { Log "    $builtIn built-in Firefox add-on(s) not listed (system add-ons, built-in themes)." }
    return $count
}

# Pages that are only a new tab or a blank page: no session rows
$script:BrowserBlankPagePattern = '^(about:(blank|newtab|home|privatebrowsing|sessionrestore|welcome)|(chrome|edge|brave|vivaldi|opera)://(newtab|new-tab-page|startpage|vivaldi-webui/startpage)/?)$'

# Chromium session files: Session_* (the tabs of the current and last
# session; older versions: Current/Last Session) and Tabs_* (recently closed
# tabs and windows; Current/Last Tabs).
function Test-ChromiumTabRestoreFile {
    param([System.IO.FileInfo]$File)
    return ($File.Name -match '^(Tabs_|Current Tabs$|Last Tabs$)')
}

# Profile folder of a Chromium session file: the parent of Sessions\, else
# the file's own folder (older versions, Opera)
function Get-ChromiumSessionProfileDir {
    param([System.IO.FileInfo]$File)
    if ($File.Directory.Name -eq "Sessions") { return $File.Directory.Parent.FullName }
    return $File.DirectoryName
}

# Visits of a Chromium History between two Chromium times, as URL -> list of
# visit times (Chromium time), to tell whether a session entry is also in
# the History. The newest 200,000. $null when the History could not be read
# (a first row "-1" tells a query that worked from one that failed).
function Get-ChromiumHistoryVisitTimes {
    param([string]$Sqlite3Exe, [string]$HistoryPath, [long]$FromTime, [long]$ToTime)
    $query = "SELECT -1, '' UNION ALL SELECT * FROM (SELECT v.visit_time, u.url FROM visits v JOIN urls u ON u.id = v.url " +
             "WHERE v.visit_time BETWEEN $FromTime AND $ToTime ORDER BY v.visit_time DESC LIMIT 200000);"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $HistoryPath -Query $query)
    if (@($rows | Where-Object { $_ -match '^-1,' }).Count -eq 0) { return $null }
    $visits = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[long]]'
    foreach ($r in ($rows | ConvertFrom-Csv -Header "VisitTime", "Url")) {
        $time = 0L
        if (-not $r.Url -or -not [long]::TryParse([string]$r.VisitTime, [ref]$time) -or $time -lt 0) { continue }
        if (-not $visits.ContainsKey($r.Url)) { $visits[$r.Url] = New-Object 'System.Collections.Generic.List[long]' }
        $visits[$r.Url].Add($time)
    }
    return $visits
}

# Two kinds of rows from one session file (read with ReadSnss):
#   - each navigation entry (a page in a tab's back/forward list) at the
#     time the page was visited: "Browser visit in session tab: <title>",
#     or "Browser visit in closed tab: <title>" in a Tabs file and for a tab
#     the Session file records as closed. Current=Yes marks the page the tab
#     showed. InHistory: Yes when the profile's live History (-HistoryVisits)
#     has a visit to the URL within a minute of that time, No when it has
#     none (only the session file still holds that visit), blank when there
#     was no History to compare with.
#   - each closed tab with a known close time: "Browser closed tab: <title>"
#     at that time (as for Firefox), with the page the tab showed, its time
#     (VisitedUtc) and the number of pages in the tab (Entries). A tab closed
#     with its window has the window's close time (ClosedWindow=Yes).
# An entry written more than once (the log rewrites it when the title
# changes) gives one row, with its last title. New tab pages give no rows.
# The newest -MaxRows entries. Returns the row count.
function Add-ChromiumSessionRows {
    param([System.IO.FileInfo]$File, $Snss, $HistoryVisits, [int]$MaxRows = 20000)
    $tabRestore = Test-ChromiumTabRestoreFile $File
    # One object per entry (last write wins), and the last entry written at
    # each tab position
    $latest = New-Object 'System.Collections.Generic.Dictionary[string, object]'
    $atIndex = New-Object 'System.Collections.Generic.Dictionary[string, object]'
    $tabIndexes = @{}
    foreach ($navigation in $Snss.Navigations) {
        $latest["$($navigation.TabId)|$($navigation.Index)|$($navigation.Timestamp)|$($navigation.Url)"] = $navigation
        $atIndex["$($navigation.TabId)|$($navigation.Index)"] = $navigation
        if (-not $tabIndexes.ContainsKey($navigation.TabId)) { $tabIndexes[$navigation.TabId] = New-Object 'System.Collections.Generic.SortedSet[int]' }
        [void]$tabIndexes[$navigation.TabId].Add($navigation.Index)
    }

    # Per tab: the page it showed, when it was closed, reopened or not
    $tabs = @{}
    foreach ($tabId in $tabIndexes.Keys) {
        $current = $null
        if ($Snss.SelectedIndexes.ContainsKey($tabId)) {
            $selected = $Snss.SelectedIndexes[$tabId]
            if ($tabRestore) {
                # Tabs files: the position among the tab's entries in the file
                $indexes = @($tabIndexes[$tabId])
                if ($selected -ge 0 -and $selected -lt $indexes.Count) { $current = $atIndex["$tabId|$($indexes[$selected])"] }
            }
            elseif ($atIndex.ContainsKey("$tabId|$selected")) { $current = $atIndex["$tabId|$selected"] }
        }
        if ($null -eq $current) {
            foreach ($index in $tabIndexes[$tabId]) {
                $candidate = $atIndex["$tabId|$index"]
                if ($null -eq $current -or $candidate.Timestamp -gt $current.Timestamp) { $current = $candidate }
            }
        }
        $window = $null
        if ($Snss.TabWindows.ContainsKey($tabId)) { $window = $Snss.TabWindows[$tabId] }
        $closed = $null
        $closedWindow = $false
        if ($Snss.ClosedTimes.ContainsKey($tabId)) { $closed = ConvertFrom-ChromiumTime $Snss.ClosedTimes[$tabId] }
        elseif ($null -ne $window -and $Snss.WindowClosedTimes.ContainsKey($window)) {
            $closed = ConvertFrom-ChromiumTime $Snss.WindowClosedTimes[$window]
            $closedWindow = $true
        }
        $tabs[$tabId] = @{
            Current      = $current
            Entries      = $tabIndexes[$tabId].Count
            Closed       = $closed
            IsClosed     = ($tabRestore -or $null -ne $closed)
            ClosedWindow = $(if ($closedWindow -or ($tabRestore -and $null -ne $window)) { "Yes" } else { "" })
            Reopened     = $(if ($Snss.Restored.Contains($tabId) -or ($null -ne $window -and $Snss.Restored.Contains($window))) { "Yes" } else { "" })
        }
    }

    $source = "$(Get-ChromiumBrowserName $File.FullName) Sessions"
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    $count = 0
    $noTime = 0
    foreach ($navigation in @($latest.Values | Sort-Object Timestamp -Descending)) {
        if (-not $navigation.Url -or $navigation.Url -match $script:BrowserBlankPagePattern) { continue }
        $ts = ConvertFrom-ChromiumTime $navigation.Timestamp
        if (-not $ts) { $noTime++; continue }
        if ($count -ge $MaxRows) { Log-Warning "    More than $MaxRows navigation entries; only the newest $MaxRows were added (cap)."; break }
        $tab = $tabs[$navigation.TabId]
        $transition = ""
        if ($navigation.Transition -ge 0) {
            $transition = $script:ChromiumTransitions[$navigation.Transition -band 255]
            if (-not $transition) { $transition = "$($navigation.Transition -band 255)" }
        }
        $inHistory = ""
        if ($null -ne $HistoryVisits) {
            $inHistory = "No"
            if ($HistoryVisits.ContainsKey($navigation.Url)) {
                foreach ($visitTime in $HistoryVisits[$navigation.Url]) {
                    if ([Math]::Abs($visitTime - $navigation.Timestamp) -le 60000000) { $inHistory = "Yes"; break }
                }
            }
        }
        $label = if ($navigation.Title) { $navigation.Title } else { $navigation.Url }
        $where = if ($tab.IsClosed) { "closed tab" } else { "session tab" }
        Add-TimelineEntry -Timestamp $ts -Source $source -EventType "NetworkConnection" `
            -Description "Browser visit in $($where): $label" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                URL          = $navigation.Url
                Title        = $navigation.Title
                Transition   = $transition
                Referrer     = $navigation.Referrer
                Current      = $(if ([object]::ReferenceEquals($navigation, $tab.Current)) { "Yes" } else { "" })
                InHistory    = $inHistory
                ClosedUtc    = Format-UtcDetailTime $tab.Closed
                ClosedWindow = $tab.ClosedWindow
                Reopened     = $tab.Reopened
                Profile      = $profileName
            })) `
            -Artifact "Browser" -RawPath $File.FullName
        $count++
    }

    # Closed tabs, at their close time
    foreach ($tabId in $tabs.Keys) {
        $tab = $tabs[$tabId]
        $page = $tab.Current
        if ($null -eq $tab.Closed -or $null -eq $page -or -not $page.Url -or $page.Url -match $script:BrowserBlankPagePattern) { continue }
        $label = if ($page.Title) { $page.Title } else { $page.Url }
        Add-TimelineEntry -Timestamp $tab.Closed -Source $source -EventType "NetworkConnection" `
            -Description "Browser closed tab: $label" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                URL          = $page.Url
                Title        = $page.Title
                Entries      = $tab.Entries
                VisitedUtc   = Format-UtcDetailTime (ConvertFrom-ChromiumTime $page.Timestamp)
                ClosedUtc    = Format-UtcDetailTime $tab.Closed
                ClosedWindow = $tab.ClosedWindow
                Reopened     = $tab.Reopened
                Profile      = $profileName
            })) `
            -Artifact "Browser" -RawPath $File.FullName
        $count++
    }
    if ($noTime -gt 0) { Log "    $noTime navigation entr(ies) without a time skipped." }
    return $count
}

# Members of a Firefox session file that are never read (set to null before
# the JSON is parsed): form data, cookies, session storage, POST data, page
# state, typed text, and bulky members the rows do not use
$script:FirefoxSessionBlankMembers = @("formdata", "cookies", "storage", "postdata_b64", "structuredCloneState", "scroll", "presState", "children",
    "userTypedValue", "csp", "referrerInfo", "triggeringPrincipal_base64", "principalToInherit_base64",
    "partitionedPrincipalToInherit_base64", "image", "iconLoadingPrincipal", "extData", "attributes")

# Firefox session files (sessionstore.jsonlz4, sessionstore-backups\
# recovery.jsonlz4 / recovery.baklz4 / previous.jsonlz4 / upgrade.jsonlz4-*):
# open tabs at their lastAccessed time ("Browser session tab"), recently
# closed tabs and the tabs of recently closed windows at their closedAt time
# ("Browser closed tab"), each with the page the tab showed (Firefox keeps no
# time per page of a tab). The members above are blanked before the JSON is
# parsed. Returns the number of rows added.
function Add-FirefoxSessionRows {
    param([System.IO.FileInfo]$File)
    if (-not (Initialize-BrowserReader)) { return 0 }
    $bytes = [TimelineBrowser.Reader]::DecompressMozLz4([System.IO.File]::ReadAllBytes($File.FullName))
    $text = [TimelineBrowser.Reader]::BlankJsonMembers([System.Text.Encoding]::UTF8.GetString($bytes), [string[]]$script:FirefoxSessionBlankMembers)
    try { $json = ConvertFrom-BrowserJsonText $text }
    catch { throw "not valid JSON after decompression" }
    $user = Get-CollectionUser $File.FullName
    $profileName = Get-BrowserProfileName $File.FullName
    # Each item: @(tab state, closed time or $null, closed with its window)
    $tabs = New-Object System.Collections.Generic.List[object]
    $windows = @(@($json.windows) | ForEach-Object { @{ Window = $_; Closed = $null } }) +
               @(@($json._closedWindows) | ForEach-Object { @{ Window = $_; Closed = ConvertFrom-UnixTime $_.closedAt -Unit Milliseconds } })
    foreach ($w in $windows) {
        if ($null -eq $w.Window) { continue }
        foreach ($tab in @($w.Window.tabs)) {
            if ($null -eq $tab) { continue }
            $tabs.Add(@($tab, $w.Closed, ($null -ne $w.Closed)))
        }
        foreach ($closedTab in @($w.Window._closedTabs)) {
            if ($null -eq $closedTab -or $null -eq $closedTab.state) { continue }
            $tabs.Add(@($closedTab.state, (ConvertFrom-UnixTime $closedTab.closedAt -Unit Milliseconds), $false))
        }
    }
    $count = 0
    foreach ($item in $tabs) {
        $state = $item[0]
        $closed = $item[1]
        $entries = @($state.entries | Where-Object { $null -ne $_ })
        if ($entries.Count -eq 0) { continue }
        $index = 0
        if (-not [int]::TryParse("$($state.index)", [ref]$index) -or $index -lt 1 -or $index -gt $entries.Count) { $index = $entries.Count }
        $entry = $entries[$index - 1]
        $url = "$($entry.url)"
        if (-not $url -or $url -match $script:BrowserBlankPagePattern) { continue }
        $lastAccessed = ConvertFrom-UnixTime $state.lastAccessed -Unit Milliseconds
        $ts = if ($closed) { $closed } else { $lastAccessed }
        if (-not $ts) { continue }
        $title = "$($entry.title)"
        $label = if ($title) { $title } else { $url }
        $verb = if ($closed) { "Browser closed tab" } else { "Browser session tab" }
        Add-TimelineEntry -Timestamp $ts -Source "Firefox Sessions" -EventType "NetworkConnection" `
            -Description "$($verb): $label" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                URL             = $url
                Title           = $title
                Entries         = $entries.Count
                LastAccessedUtc = Format-UtcDetailTime $lastAccessed
                ClosedUtc       = Format-UtcDetailTime $closed
                ClosedWindow    = $(if ($item[2]) { "Yes" } else { "" })
                Profile         = $profileName
            })) `
            -Artifact "Browser" -RawPath $File.FullName
        $count++
    }
    return $count
}

# Snapshot folder of a Chromium history snapshot file:
# <browser>\Snapshots\<version>\<profile>\<file>, with <browser> = Browser\
# <user>\<browser> in a collection (or a User Data folder), <version> a
# version number and <profile> a profile folder name. Returns the version,
# the profile and the live profile folder the snapshot was taken from
# (<browser>\<profile>; Opera, whose folder is its profile: <browser>), or
# $null for any other file.
function Get-ChromiumSnapshotInfo {
    param([string]$FullPath)
    $snapshotPattern = '\\Snapshots\\(?<version>\d+(?:\.\d+){1,3})\\(?<profile>Default|Profile \d+|Guest Profile)\\[^\\]+$'
    $rel = Get-RelativeCollectionPath $FullPath
    if ($rel -and $rel -match ('^(?<root>Browser\\[^\\]+\\[^\\]+)' + $snapshotPattern)) {
        $root = Join-Path $script:collectionRoot $Matches["root"]
    }
    elseif ($FullPath -match ('^(?<root>.+\\User Data)' + $snapshotPattern)) {
        $root = $Matches["root"]
    }
    else { return $null }
    $version = $Matches["version"]
    $profileName = $Matches["profile"]
    $liveDir = Join-Path $root $profileName
    if (-not (Test-Path -LiteralPath $liveDir) -and (Test-Path -LiteralPath (Join-Path $root "History"))) { $liveDir = $root }
    return [PSCustomObject]@{
        Version = $version
        Profile = $profileName
        LiveDir = $liveDir
    }
}

# Whether a file is anywhere inside a Chromium snapshot profile folder
# (Snapshots\<version>\<profile>\, also its Sessions\ folder): such copies
# are not parsed as the profile's own files
function Test-ChromiumSnapshotPath {
    param([string]$FullPath)
    return ($FullPath -match '\\Snapshots\\\d+(?:\.\d+){1,3}\\(?:Default|Profile \d+|Guest Profile)\\')
}

# Days of history Chromium keeps (older visits expire)
$script:ChromiumHistoryRetentionDays = 90

# Visits in a Chromium history snapshot (Snapshots\<version>\<profile>\History,
# a copy the browser makes before an update) that are not in the profile's
# live History -- same URL and visit time: removed from the History after
# the snapshot was taken (SnapshotTakenUtc: the snapshot file's creation time
# from the collection manifest), or expired. Chromium's own "Clear browsing
# data" also deletes the snapshots taken in the time range it clears, so a
# visit kept only in a snapshot was removed some other way (deleted from the
# history page, by an extension or sync, or the database edited outside the
# browser) or expired. Reason: Deleted (the visit is within the 90 days
# Chromium keeps, counted back from the last write of the live History --
# LiveHistoryModifiedUtc, else the collection time -- so it did not expire),
# Expired or deleted (older), or No live History (the profile's History was
# not collected). Snapshots are processed newest version first and a visit
# is reported once per profile (-Reported). The newest 20,000 per snapshot.
# Returns the row count.
function Add-ChromiumSnapshotHistoryRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File, [System.Collections.Generic.HashSet[string]]$Reported, [int]$MaxRows = 20000)
    $info = Get-ChromiumSnapshotInfo $File.FullName
    if (-not $info) { return 0 }
    $liveHistory = Join-Path $info.LiveDir "History"
    $attach = $null
    $notInLive = ""
    if ((Test-Path -LiteralPath $liveHistory) -and (Test-FileSignature -Path $liveHistory -Signature "SQLite format 3")) {
        $attach = @{ live = $liveHistory }
        $notInLive = " WHERE NOT EXISTS (SELECT 1 FROM live.visits lv JOIN live.urls lu ON lu.id = lv.url WHERE lv.visit_time = v.visit_time AND lu.url = u.url)"
    }
    $query = "SELECT v.visit_time, u.url, replace(replace(u.title, char(13), ' '), char(10), ' '), u.visit_count, v.transition & 255 " +
             "FROM visits v JOIN urls u ON u.id = v.url$notInLive ORDER BY v.visit_time DESC LIMIT $($MaxRows + 1);"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query -Attach $attach)
    if ($rows.Count -gt $MaxRows) {
        Log-Warning "    More than $MaxRows visits only in this snapshot; only the newest $MaxRows were added (cap)."
        $rows = $rows[0..($MaxRows - 1)]
    }
    $snapshotTimes = Get-SourceFileTimes $File.FullName
    $taken = if ($snapshotTimes) { $snapshotTimes.Created } else { $null }
    $liveModified = $null
    if ($attach) {
        $liveTimes = Get-SourceFileTimes $liveHistory
        if ($liveTimes) { $liveModified = $liveTimes.Modified }
    }
    $reference = $liveModified
    if (-not $reference) { $reference = (Get-CollectionInfo).CollectionStartUtc }
    if (-not $reference) { $reference = $File.LastWriteTimeUtc }
    $retentionStart = $reference.AddDays(-$script:ChromiumHistoryRetentionDays)
    $source = "$(Get-ChromiumBrowserName $File.FullName) History Snapshot"
    $user = Get-CollectionUser $File.FullName
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header "VisitTime", "Url", "Title", "VisitCount", "Type")) {
        $ts = ConvertFrom-ChromiumTime $r.VisitTime
        if (-not $ts -or -not $Reported.Add("$($info.LiveDir)|$($r.VisitTime)|$($r.Url)")) { continue }
        $reason = if (-not $attach) { "No live History" } elseif ($ts -ge $retentionStart) { "Deleted" } else { "Expired or deleted" }
        $typeName = $script:ChromiumTransitions[[int]$r.Type]
        $label = if ($r.Title) { $r.Title } else { $r.Url }
        Add-TimelineEntry -Timestamp $ts -Source $source -EventType "NetworkConnection" `
            -Description "Browser visit only in history snapshot: $label" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                URL                    = $r.Url
                Title                  = $r.Title
                VisitCount             = $r.VisitCount
                Transition             = $(if ($typeName) { $typeName } else { $r.Type })
                Reason                 = $reason
                Snapshot               = $info.Version
                SnapshotTakenUtc       = Format-UtcDetailTime $taken
                LiveHistoryModifiedUtc = Format-UtcDetailTime $liveModified
                Profile                = $info.Profile
            })) `
            -Artifact "Browser" -RawPath $File.FullName
        $count++
    }
    return $count
}

# Chromium Favicons: pages with an icon mapping whose URL is in neither the
# live History nor the profile's bookmarks. Chromium itself removes a page's
# icon mappings when it deletes or expires the page's history (unless the
# page is bookmarked), so such a page was removed from the History some
# other way (a cleaning tool, the database edited outside the browser), came
# in another way (e.g. sync), or the two files were copied at different
# times: a lead, not proof of a deletion, and no reason is given. The row
# time is when the icon was last stored (favicon_bitmaps.last_updated,
# IconUpdatedUtc), not a visit to the page: one icon often serves many pages
# of a site (PagesSharingIcon), and a visit to any of them updates it. To
# keep out noise: only http(s) pages; never a bookmarked page; only icons
# stored on a visit ("on-demand" icons, last_updated 0, are fetched without
# a visit -- for new-tab-page tiles and suggestions, e.g. Edge's default top
# sites); nothing when the profile's live History was not collected (there
# is nothing to compare with). For a Favicons file in a history snapshot,
# pages in that snapshot's History are left out too (reported as snapshot
# visits). Live Favicons first, then snapshots newest first: a page is
# reported once per profile (-Reported). The newest 5,000 per file. Returns
# the number of rows added.
function Add-ChromiumFaviconRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File, [System.Collections.Generic.HashSet[string]]$Reported, [int]$MaxRows = 5000)
    $snapshot = Get-ChromiumSnapshotInfo $File.FullName
    $liveDir = if ($snapshot) { $snapshot.LiveDir } else { $File.DirectoryName }
    $liveHistory = Join-Path $liveDir "History"
    if (-not (Test-Path -LiteralPath $liveHistory) -or -not (Test-FileSignature -Path $liveHistory -Signature "SQLite format 3")) {
        Log "    No History of this profile to compare with -- skipped."
        return 0
    }
    $schema = Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Tables @("icon_mapping", "favicons", "favicon_bitmaps")
    if (-not $schema["icon_mapping"] -or -not $schema["favicons"] -or -not $schema["favicon_bitmaps"]) { return 0 }
    $profileName = if ($snapshot) { $snapshot.Profile } else { Get-BrowserProfileName $File.FullName }
    $attach = @{ live = $liveHistory }
    $conditions = @("(m.page_url LIKE 'http://%' OR m.page_url LIKE 'https://%')", "NOT EXISTS (SELECT 1 FROM live.urls hu WHERE hu.url = m.page_url)")
    $snapshotHistory = Join-Path $File.DirectoryName "History"
    if ($snapshot -and (Test-Path -LiteralPath $snapshotHistory) -and (Test-FileSignature -Path $snapshotHistory -Signature "SQLite format 3")) {
        $attach["snap"] = $snapshotHistory
        $conditions += "NOT EXISTS (SELECT 1 FROM snap.urls hu WHERE hu.url = m.page_url)"
    }
    # Per page, the icon stored last: with MAX() as the only aggregate,
    # SQLite takes the other columns (icon URL and id) from that same row
    $query = "SELECT t.updated, replace(replace(t.page_url, char(13), ' '), char(10), ' '), replace(replace(t.icon_url, char(13), ' '), char(10), ' '), " +
             "(SELECT COUNT(DISTINCT m2.page_url) FROM icon_mapping m2 WHERE m2.icon_id = t.icon_id) FROM " +
             "(SELECT MAX(b.last_updated) AS updated, m.page_url AS page_url, f.url AS icon_url, f.id AS icon_id FROM icon_mapping m " +
             "JOIN favicons f ON f.id = m.icon_id JOIN favicon_bitmaps b ON b.icon_id = f.id AND b.last_updated > 0 WHERE " + ($conditions -join " AND ") +
             " GROUP BY m.page_url) t ORDER BY t.updated DESC;"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query -Attach $attach)

    # Bookmarked pages of the profile
    $bookmarked = New-Object 'System.Collections.Generic.HashSet[string]'
    $bookmarksFile = Join-Path $liveDir "Bookmarks"
    if (Test-Path -LiteralPath $bookmarksFile) {
        try {
            $bookmarks = Get-Content -LiteralPath $bookmarksFile -Raw -Encoding UTF8 -ErrorAction Stop
            foreach ($m in [regex]::Matches($bookmarks, '"url"\s*:\s*"((?:[^"\\]|\\.)*)"')) { [void]$bookmarked.Add([regex]::Unescape($m.Groups[1].Value)) }
        }
        catch { Log-Warning "    Could not read bookmarks $bookmarksFile : $($_.Exception.Message)" }
    }
    $source = "$(Get-ChromiumBrowserName $File.FullName) Favicons"
    $user = Get-CollectionUser $File.FullName
    $count = 0
    foreach ($r in ($rows | ConvertFrom-Csv -Header "Updated", "PageUrl", "IconUrl", "Pages")) {
        if ($bookmarked.Contains($r.PageUrl)) { continue }
        $ts = ConvertFrom-ChromiumTime $r.Updated
        if (-not $ts -or -not $Reported.Add("$liveDir|$($r.PageUrl)")) { continue }
        if ($count -ge $MaxRows) { Log-Warning "    More than $MaxRows favicon pages not in history; only the newest $MaxRows were added (cap)."; break }
        Add-TimelineEntry -Timestamp $ts -Source $source -EventType "NetworkConnection" `
            -Description "Browser favicon for page not in history: $($r.PageUrl)" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                URL              = $r.PageUrl
                IconURL          = $r.IconUrl
                IconUpdatedUtc   = Format-UtcDetailTime $ts
                PagesSharingIcon = $r.Pages
                Snapshot         = $(if ($snapshot) { $snapshot.Version } else { "" })
                Profile          = $profileName
            })) `
            -Artifact "Browser" -RawPath $File.FullName
        $count++
    }
    return $count
}

function Parse-BrowserHistory {
    Log "--- Parsing Browser History ---"

    $browserParsed = $false
    # Newest visits kept per database
    $maxVisits = 20000

    # Find browser history databases (SQLite files only). A Chromium History
    # under Snapshots\<version>\<profile>\ is a pre-update copy: only its
    # visits that are no longer in the live History are added (see
    # Add-ChromiumSnapshotHistoryRows).
    $chromeHistoryPaths = @()
    $chromeSnapshotHistoryPaths = @()
    $firefoxHistoryPaths = @()

    $historyFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("History", "places.sqlite")
    foreach ($f in $historyFiles) {
        if ($f.PSIsContainer) { continue }
        if (-not (Test-FileSignature -Path $f.FullName -Signature "SQLite format 3")) { continue }
        if ($f.Name -eq "History") {
            if (Get-ChromiumSnapshotInfo $f.FullName) { $chromeSnapshotHistoryPaths += $f } else { $chromeHistoryPaths += $f }
        }
        if ($f.Name -eq "places.sqlite") { $firefoxHistoryPaths += $f }
    }
    $chromeFaviconPaths = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("Favicons") |
        Where-Object { -not $_.PSIsContainer -and (Test-FileSignature -Path $_.FullName -Signature "SQLite format 3") })

    # Settings, extensions and sessions (JSON and binary files, no sqlite3
    # needed). Chromium: Preferences and Secure Preferences per profile
    # folder, Local State per browser, Session_* / Tabs_* (SNSS). Firefox:
    # extensions.json, prefs.js and the session files (mozLz4) -- in a
    # Firefox folder only (Thunderbird profiles have files of the same names).
    # Copies inside a history snapshot folder are not read.
    $chromePrefsDirs = [ordered]@{}
    $localStateFiles = @()
    $firefoxExtensionFiles = @()
    $firefoxPrefsFiles = @()
    foreach ($f in (Find-ArtifactFiles -BasePath $InputPath -FileNames @("Preferences", "Secure Preferences", "Local State", "extensions.json", "prefs.js"))) {
        if ($f.PSIsContainer -or (Test-ChromiumSnapshotPath $f.FullName)) { continue }
        $inBrowserFolder = "$(Get-RelativeCollectionPath $f.FullName)" -match '^Browser\\'
        switch ($f.Name) {
            "extensions.json" { if ($f.FullName -match '\\Firefox\\') { $firefoxExtensionFiles += $f } }
            "prefs.js"        { if ($f.FullName -match '\\Firefox\\') { $firefoxPrefsFiles += $f } }
            "Local State"     { if ($inBrowserFolder -or $f.FullName -match '\\User Data\\Local State$|\\Opera[^\\]*\\Local State$') { $localStateFiles += $f } }
            default {
                # A browser profile (Electron apps keep a Preferences file too)
                if (-not $inBrowserFolder -and -not (Test-Path -LiteralPath (Join-Path $f.DirectoryName "History"))) { continue }
                if (-not $chromePrefsDirs.Contains($f.DirectoryName)) { $chromePrefsDirs[$f.DirectoryName] = @() }
                $chromePrefsDirs[$f.DirectoryName] += $f
            }
        }
    }
    $chromeSessionFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("Session_*", "Tabs_*", "Current Session", "Current Tabs", "Last Session", "Last Tabs") |
        Where-Object { -not $_.PSIsContainer -and $_.Name -match '^((Session|Tabs)_\d+|(Current|Last) (Session|Tabs))$' -and -not (Test-ChromiumSnapshotPath $_.FullName) -and
                       (Test-FileSignature -Path $_.FullName -Signature "SNSS") })
    $firefoxSessionFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("*lz4*") |
        Where-Object { -not $_.PSIsContainer -and $_.Name -match '^(sessionstore|recovery|previous|upgrade)\.(jsonlz4|baklz4)' -and $_.FullName -match '\\Firefox\\' -and
                       (Test-FileSignature -Path $_.FullName -Signature ("mozLz40" + [char]0)) })

    # Other Chromium profile files: Shortcuts and Top Sites (SQLite), Bookmarks (JSON)
    $chromeShortcutPaths = @()
    $chromeTopSitesPaths = @()
    foreach ($f in (Find-ArtifactFiles -BasePath $InputPath -FileNames @("Shortcuts", "Top Sites"))) {
        if ($f.PSIsContainer) { continue }
        if (-not (Test-FileSignature -Path $f.FullName -Signature "SQLite format 3")) { continue }
        if ($f.Name -eq "Shortcuts") { $chromeShortcutPaths += $f } else { $chromeTopSitesPaths += $f }
    }
    $bookmarkFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("Bookmarks") | Where-Object { -not $_.PSIsContainer })

    # Credential, cookie, form and permission stores (metadata only, see above)
    $chromeLoginPaths = @()
    $chromeCookiePaths = @()
    $chromeWebDataPaths = @()
    $firefoxCookiePaths = @()
    $firefoxFormHistoryPaths = @()
    $firefoxPermissionPaths = @()
    foreach ($f in (Find-ArtifactFiles -BasePath $InputPath -FileNames @("Login Data", "Cookies", "Web Data", "cookies.sqlite", "formhistory.sqlite", "permissions.sqlite"))) {
        if ($f.PSIsContainer) { continue }
        if (-not (Test-FileSignature -Path $f.FullName -Signature "SQLite format 3")) { continue }
        switch ($f.Name) {
            "Login Data"         { $chromeLoginPaths += $f }
            "Cookies"            { $chromeCookiePaths += $f }
            "Web Data"           { $chromeWebDataPaths += $f }
            "cookies.sqlite"     { $firefoxCookiePaths += $f }
            "formhistory.sqlite" { $firefoxFormHistoryPaths += $f }
            "permissions.sqlite" { $firefoxPermissionPaths += $f }
        }
    }
    $firefoxLoginFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("logins.json") | Where-Object { -not $_.PSIsContainer })

    $totalBrowserFiles = $chromeHistoryPaths.Count + $firefoxHistoryPaths.Count + $chromeShortcutPaths.Count + $chromeTopSitesPaths.Count +
        $chromeLoginPaths.Count + $chromeCookiePaths.Count + $chromeWebDataPaths.Count +
        $firefoxCookiePaths.Count + $firefoxFormHistoryPaths.Count + $firefoxPermissionPaths.Count +
        $chromeSnapshotHistoryPaths.Count + $chromeFaviconPaths.Count
    $otherBrowserFiles = $bookmarkFiles.Count + $firefoxLoginFiles.Count + $chromePrefsDirs.Count + $localStateFiles.Count +
        $firefoxExtensionFiles.Count + $firefoxPrefsFiles.Count + $chromeSessionFiles.Count + $firefoxSessionFiles.Count
    if ($totalBrowserFiles + $otherBrowserFiles -eq 0) {
        Log-Warning "No browser history databases found. Skipping."
        Log ""
        return
    }

    # Chromium bookmarks (JSON, no sqlite3 needed): date_added = microseconds since 1601 UTC
    foreach ($bm in $bookmarkFiles) {
        Log "  Parsing: $(Get-ChromiumBrowserName $bm.FullName) Bookmarks ($(Get-CollectionUser $bm.FullName))"
        try {
            $added = Add-ChromiumBookmarkRows -File $bm
            Log "    $added bookmark(s) added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not read bookmarks $($bm.FullName): $($_.Exception.Message)" }
    }
    # Firefox saved logins (JSON, no sqlite3 needed)
    foreach ($lj in $firefoxLoginFiles) {
        Log "  Parsing: Firefox Logins ($(Get-CollectionUser $lj.FullName))"
        try {
            $added = Add-FirefoxLoginRows -File $lj
            Log "    $added saved login row(s) added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not read saved logins $($lj.FullName): $($_.Exception.Message)" }
    }

    # Chromium extensions and settings, per profile folder (Secure
    # Preferences first: Windows keeps extensions.settings and the protected
    # settings there)
    foreach ($profileDir in $chromePrefsDirs.Keys) {
        $prefsFiles = @($chromePrefsDirs[$profileDir] | Sort-Object { if ($_.Name -eq "Secure Preferences") { 0 } else { 1 } })
        $browserName = Get-ChromiumBrowserName $prefsFiles[0].FullName
        $user = Get-CollectionUser $prefsFiles[0].FullName
        $profileName = Get-BrowserProfileName $prefsFiles[0].FullName
        Log "  Parsing: $browserName Preferences ($user$(if ($profileName) { ", $profileName" }))"
        $documents = @()
        foreach ($pf in $prefsFiles) {
            try {
                $doc = Read-BrowserJsonFile -Path $pf.FullName -Blank $script:ChromiumPrefsBlankMembers -BlankNameParts $script:ChromiumSecretNameParts
                if ($doc) { $documents += $doc }
            }
            catch { Log-Warning "    Could not read $($pf.FullName): $($_.Exception.Message)" }
        }
        if ($documents.Count -eq 0) { continue }
        $snapshotTime = Get-SnapshotTimeUtc -File $prefsFiles[0]
        $settingsPath = ($prefsFiles | Where-Object { $_.Name -eq "Preferences" } | Select-Object -First 1)
        $settingsPath = if ($settingsPath) { $settingsPath.FullName } else { $prefsFiles[0].FullName }
        try {
            $added = Add-ChromiumExtensionRows -Documents $documents -ProfileDir $profileDir -Source "$browserName Extensions" -User $user `
                -ProfileName $profileName -RawPath $prefsFiles[0].FullName -SnapshotTime $snapshotTime
            $settingCount = Add-ChromiumSettingRows -Documents $documents -Source "$browserName Preferences" -User $user `
                -ProfileName $profileName -RawPath $settingsPath -SnapshotTime $snapshotTime
            Log "    $added extension row(s) and $settingCount setting row(s) added."
            if ($added + $settingCount -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not parse the preferences in $profileDir : $($_.Exception.Message)" }
    }
    # Chromium Local State: experimental features turned on (chrome://flags)
    foreach ($ls in $localStateFiles) {
        $browserName = Get-ChromiumBrowserName $ls.FullName
        Log "  Parsing: $browserName Local State ($(Get-CollectionUser $ls.FullName))"
        try {
            $doc = Read-BrowserJsonFile -Path $ls.FullName -Blank $script:ChromiumPrefsBlankMembers -BlankNameParts $script:ChromiumSecretNameParts
            $flags = Get-BrowserJsonValue -Documents @($doc) -Path "browser.enabled_labs_experiments"
            $flags = @($flags | Where-Object { $_ })
            $snapshotTime = Get-SnapshotTimeUtc -File $ls
            if ($flags.Count -gt 0 -and $snapshotTime) {
                Add-BrowserSettingRow -Time $snapshotTime -Source "$browserName Local State" -User (Get-CollectionUser $ls.FullName) -RawPath $ls.FullName `
                    -Setting "Experimental flags" -Value (Format-BrowserList $flags) -Pref "browser.enabled_labs_experiments" -ProfileName ""
                Log "    1 setting row added."
                $browserParsed = $true
            }
        }
        catch { Log-Warning "    Could not read $($ls.FullName): $($_.Exception.Message)" }
    }
    # Firefox add-ons and settings
    foreach ($ej in $firefoxExtensionFiles) {
        Log "  Parsing: Firefox Extensions ($(Get-CollectionUser $ej.FullName))"
        try {
            $added = Add-FirefoxExtensionRows -File $ej
            Log "    $added extension row(s) added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not read $($ej.FullName): $($_.Exception.Message)" }
    }
    foreach ($pj in $firefoxPrefsFiles) {
        Log "  Parsing: Firefox Preferences ($(Get-CollectionUser $pj.FullName))"
        try {
            $added = Add-FirefoxSettingRows -File $pj
            Log "    $added setting row(s) added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not read $($pj.FullName): $($_.Exception.Message)" }
    }
    # --- Ensure sqlite3.exe is available (auto-download if needed): for the
    # databases, and to compare Chromium session entries with the History ---
    $sqlite3Exe = $null
    if ($totalBrowserFiles -gt 0) {
        Log "  Found $totalBrowserFiles browser database(s)"
        $sqlite3Exe = Find-Sqlite3Exe
        if ($sqlite3Exe) { Log "  Using sqlite3: $sqlite3Exe" }
    }

    # Open and recently closed tabs. Chromium session files are read per
    # profile, then the profile's History once for their time span (to tell
    # which session entries it also has, see Add-ChromiumSessionRows).
    $sessionGroups = [ordered]@{}
    foreach ($sf in $chromeSessionFiles) {
        $sessionDir = Get-ChromiumSessionProfileDir $sf
        if (-not $sessionGroups.Contains($sessionDir)) { $sessionGroups[$sessionDir] = @() }
        $sessionGroups[$sessionDir] += $sf
    }
    foreach ($sessionDir in $sessionGroups.Keys) {
        if (-not (Initialize-BrowserReader)) { break }
        # Each item: @(file, parsed file or $null, read error)
        $parsedFiles = @()
        $firstTime = 0L
        $lastTime = 0L
        foreach ($sf in $sessionGroups[$sessionDir]) {
            try {
                $snss = [TimelineBrowser.Reader]::ReadSnss([System.IO.File]::ReadAllBytes($sf.FullName), (Test-ChromiumTabRestoreFile $sf))
                foreach ($navigation in $snss.Navigations) {
                    if ($navigation.Timestamp -le 0) { continue }
                    if ($firstTime -eq 0 -or $navigation.Timestamp -lt $firstTime) { $firstTime = $navigation.Timestamp }
                    if ($navigation.Timestamp -gt $lastTime) { $lastTime = $navigation.Timestamp }
                }
                $parsedFiles += , @($sf, $snss, "")
            }
            catch { $parsedFiles += , @($sf, $null, $_.Exception.Message) }
        }
        $historyVisits = $null
        $sessionHistory = Join-Path $sessionDir "History"
        if ($sqlite3Exe -and $lastTime -gt 0 -and (Test-Path -LiteralPath $sessionHistory) -and (Test-FileSignature -Path $sessionHistory -Signature "SQLite format 3")) {
            $historyVisits = Get-ChromiumHistoryVisitTimes -Sqlite3Exe $sqlite3Exe -HistoryPath $sessionHistory -FromTime ($firstTime - 60000000) -ToTime ($lastTime + 60000000)
        }
        foreach ($item in $parsedFiles) {
            $sf = $item[0]
            Log "  Parsing: $(Get-ChromiumBrowserName $sf.FullName) Sessions $($sf.Name) ($(Get-CollectionUser $sf.FullName))"
            if ($item[2]) { Log-Warning "    Could not read session file $($sf.FullName): $($item[2])"; continue }
            try {
                $added = Add-ChromiumSessionRows -File $sf -Snss $item[1] -HistoryVisits $historyVisits
                Log "    $added tab row(s) added."
                if ($added -gt 0) { $browserParsed = $true }
            }
            catch { Log-Warning "    Could not read session file $($sf.FullName): $($_.Exception.Message)" }
        }
    }
    foreach ($sf in $firefoxSessionFiles) {
        Log "  Parsing: Firefox Sessions $($sf.Name) ($(Get-CollectionUser $sf.FullName))"
        try {
            $added = Add-FirefoxSessionRows -File $sf
            Log "    $added tab row(s) added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not read session file $($sf.FullName): $($_.Exception.Message)" }
    }

    if ($totalBrowserFiles -eq 0) {
        Log "  Browser history parsing complete."
        Log ""
        return
    }
    if (-not $sqlite3Exe) {
        Log-Warning "  sqlite3.exe not available. Skipping browser parsing."
        Log "  Browser history parsing complete."
        Log ""
        return
    }

    # Parse Chrome/Edge/Brave/Opera/Vivaldi history (Chromium format): one row
    # per visit (visits joined to urls); visit_time = microseconds since 1601 UTC
    foreach ($histDb in $chromeHistoryPaths) {
        $browserName = "$(Get-ChromiumBrowserName $histDb.FullName) History"
        $user = Get-CollectionUser $histDb.FullName
        $profileName = Get-BrowserProfileName $histDb.FullName

        Log "  Parsing: $browserName ($user)"

        $query = "SELECT (SELECT COUNT(*) FROM visits), u.url, replace(replace(u.title, char(13), ' '), char(10), ' '), u.visit_count, " +
                 "strftime('%Y-%m-%d %H:%M:%f', v.visit_time / 1000000.0 - 11644473600, 'unixepoch'), v.transition & 255 " +
                 "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC LIMIT $maxVisits;"
        $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $sqlite3Exe -DbPath $histDb.FullName -Query $query)
        $added = Add-BrowserVisitRows -Lines $rows -Source $browserName -User $user -ProfileName $profileName `
            -TypeNames $script:ChromiumTransitions -RawPath $histDb.FullName -MaxVisits $maxVisits
        Log "    $added visit(s) added."
        if ($added -gt 0) { $browserParsed = $true }
    }

    # Chromium history snapshots: visits no longer in the live History.
    # Newest version first, so a visit in several snapshots is reported from
    # the newest one.
    $reportedSnapshotVisits = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($histDb in @($chromeSnapshotHistoryPaths | Sort-Object { (Get-ChromiumSnapshotInfo $_.FullName).Version -as [version] } -Descending)) {
        $snapshot = Get-ChromiumSnapshotInfo $histDb.FullName
        Log "  Parsing: $(Get-ChromiumBrowserName $histDb.FullName) History Snapshot $($snapshot.Version) ($(Get-CollectionUser $histDb.FullName), $($snapshot.Profile))"
        try {
            $added = Add-ChromiumSnapshotHistoryRows -Sqlite3Exe $sqlite3Exe -File $histDb -Reported $reportedSnapshotVisits
            Log "    $added visit(s) only in this snapshot added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not parse history snapshot $($histDb.FullName): $($_.Exception.Message)" }
    }
    # Chromium Favicons: pages not in history. Live files first, then
    # snapshots newest first; a page is reported once per profile.
    $reportedFaviconPages = New-Object 'System.Collections.Generic.HashSet[string]'
    $orderedFavicons = @($chromeFaviconPaths | Sort-Object @{ Expression = { $null -ne (Get-ChromiumSnapshotInfo $_.FullName) } },
        @{ Expression = { (Get-ChromiumSnapshotInfo $_.FullName).Version -as [version] }; Descending = $true })
    foreach ($db in $orderedFavicons) {
        Log "  Parsing: $(Get-ChromiumBrowserName $db.FullName) Favicons ($(Get-CollectionUser $db.FullName))"
        try {
            $added = Add-ChromiumFaviconRows -Sqlite3Exe $sqlite3Exe -File $db -Reported $reportedFaviconPages
            Log "    $added page(s) not in history added."
            if ($added -gt 0) { $browserParsed = $true }
        }
        catch { Log-Warning "    Could not parse favicons $($db.FullName): $($_.Exception.Message)" }
    }

    # Parse Firefox places.sqlite: visit_date = microseconds since 1970 UTC
    foreach ($placesDb in $firefoxHistoryPaths) {
        $user = Get-CollectionUser $placesDb.FullName
        $profileName = Get-BrowserProfileName $placesDb.FullName

        Log "  Parsing: Firefox History ($user)"

        $query = "SELECT (SELECT COUNT(*) FROM moz_historyvisits), p.url, replace(replace(p.title, char(13), ' '), char(10), ' '), p.visit_count, " +
                 "strftime('%Y-%m-%d %H:%M:%f', h.visit_date / 1000000.0, 'unixepoch'), h.visit_type " +
                 "FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date DESC LIMIT $maxVisits;"
        $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $sqlite3Exe -DbPath $placesDb.FullName -Query $query)
        $added = Add-BrowserVisitRows -Lines $rows -Source "Firefox History" -User $user -ProfileName $profileName `
            -TypeNames $script:FirefoxVisitTypes -RawPath $placesDb.FullName -MaxVisits $maxVisits
        Log "    $added visit(s) added."
        if ($added -gt 0) { $browserParsed = $true }

        # Bookmarks (moz_bookmarks type 1) joined to moz_places; dateAdded and
        # lastModified = microseconds since 1970 UTC; "place:" URLs are saved queries
        $query = "SELECT replace(replace(coalesce(b.title, p.title, ''), char(13), ' '), char(10), ' '), p.url, " +
                 "strftime('%Y-%m-%d %H:%M:%f', b.dateAdded / 1000000.0, 'unixepoch'), " +
                 "strftime('%Y-%m-%d %H:%M:%f', b.lastModified / 1000000.0, 'unixepoch'), " +
                 "replace(replace(coalesce(f.title, ''), char(13), ' '), char(10), ' ') " +
                 "FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk LEFT JOIN moz_bookmarks f ON f.id = b.parent " +
                 "WHERE b.type = 1 AND b.dateAdded > 0 AND p.url NOT LIKE 'place:%' ORDER BY b.dateAdded;"
        $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $sqlite3Exe -DbPath $placesDb.FullName -Query $query)
        $bookmarks = 0
        foreach ($r in ($rows | ConvertFrom-Csv -Header "Title", "Url", "Added", "Modified", "Folder")) {
            $ts = ConvertFrom-UtcText $r.Added
            if ($null -eq $ts) { continue }
            $desc = if ($r.Title) { "Bookmark added: $($r.Title) ($($r.Url))" } else { "Bookmark added: $($r.Url)" }
            Add-TimelineEntry -Timestamp $ts -Source "Firefox Bookmarks" -EventType "NetworkConnection" `
                -Description $desc `
                -User $user `
                -Details (Format-ArtifactDetails ([ordered]@{ URL = $r.Url; Folder = $r.Folder; LastModifiedUtc = ($r.Modified -replace '\.\d+$', ''); Profile = $profileName })) `
                -Artifact "Browser" -RawPath $placesDb.FullName
            $bookmarks++
        }
        Log "    $bookmarks bookmark(s) added."
        if ($bookmarks -gt 0) { $browserParsed = $true }
    }

    # Chromium Shortcuts (omni_box_shortcuts): text typed in the address bar
    # and the suggestion it was completed to; last_access_time = microseconds
    # since 1601 UTC
    foreach ($db in $chromeShortcutPaths) {
        $browserName = Get-ChromiumBrowserName $db.FullName
        $user = Get-CollectionUser $db.FullName
        $profileName = Get-BrowserProfileName $db.FullName
        Log "  Parsing: $browserName Shortcuts ($user)"
        $query = "SELECT replace(replace(text, char(13), ' '), char(10), ' '), url, " +
                 "strftime('%Y-%m-%d %H:%M:%f', last_access_time / 1000000.0 - 11644473600, 'unixepoch'), number_of_hits, " +
                 "replace(replace(contents, char(13), ' '), char(10), ' '), replace(replace(description, char(13), ' '), char(10), ' ') " +
                 "FROM omni_box_shortcuts WHERE last_access_time > 0 ORDER BY last_access_time;"
        $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $sqlite3Exe -DbPath $db.FullName -Query $query)
        $shortcuts = 0
        foreach ($r in ($rows | ConvertFrom-Csv -Header "Text", "Url", "LastAccess", "Hits", "Contents", "Title")) {
            $ts = ConvertFrom-UtcText $r.LastAccess
            if ($null -eq $ts) { continue }
            Add-TimelineEntry -Timestamp $ts -Source "$browserName Shortcuts" -EventType "NetworkConnection" `
                -Description "Address bar shortcut used: $($r.Text) -> $($r.Url)" `
                -User $user `
                -Details (Format-ArtifactDetails ([ordered]@{ Hits = $r.Hits; Suggestion = $r.Contents; Title = $r.Title; URL = $r.Url; Profile = $profileName })) `
                -Artifact "Browser" -RawPath $db.FullName
            $shortcuts++
        }
        Log "    $shortcuts shortcut(s) added."
        if ($shortcuts -gt 0) { $browserParsed = $true }
    }

    # Chromium Top Sites: the most visited sites shown on the new tab page.
    # No times -- Snapshot rows at collection time.
    foreach ($db in $chromeTopSitesPaths) {
        $browserName = Get-ChromiumBrowserName $db.FullName
        $user = Get-CollectionUser $db.FullName
        $profileName = Get-BrowserProfileName $db.FullName
        Log "  Parsing: $browserName Top Sites ($user)"
        $snapshotTs = Get-SnapshotTimeUtc -File $db
        if (-not $snapshotTs) { Log-Warning "    Collection time unknown -- top sites skipped."; continue }
        $query = "SELECT url, url_rank, replace(replace(title, char(13), ' '), char(10), ' ') FROM top_sites ORDER BY url_rank;"
        $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $sqlite3Exe -DbPath $db.FullName -Query $query)
        $sites = 0
        foreach ($r in ($rows | ConvertFrom-Csv -Header "Url", "Rank", "Title")) {
            if (-not $r.Url) { continue }
            $rank = 0
            $rankText = if ([int]::TryParse([string]$r.Rank, [ref]$rank)) { $rank + 1 } else { $r.Rank }
            $desc = if ($r.Title) { "Browser top site: $($r.Title) ($($r.Url))" } else { "Browser top site: $($r.Url)" }
            Add-TimelineEntry -Timestamp $snapshotTs -Source "$browserName Top Sites" -EventType "Snapshot" `
                -Description $desc `
                -User $user `
                -Details (Format-ArtifactDetails ([ordered]@{ Rank = $rankText; URL = $r.Url; Profile = $profileName })) `
                -Artifact "Browser" -RawPath $db.FullName
            $sites++
        }
        Log "    $sites top site(s) added (snapshot)."
        if ($sites -gt 0) { $browserParsed = $true }
    }

    # Downloads and the credential, cookie, form and permission stores: files,
    # the Add-* function that parses one, the Source suffix, and whether the
    # browser name comes from the Chromium layout (else Firefox). Web Data
    # holds both autofill and the search engines.
    $storeParsers = @(
        @{ Files = $chromeHistoryPaths;      Parser = "Add-ChromiumDownloadRows";     Label = "Downloads";      Chromium = $true }
        @{ Files = $firefoxHistoryPaths;     Parser = "Add-FirefoxDownloadRows";      Label = "Downloads";      Chromium = $false }
        @{ Files = $chromeLoginPaths;        Parser = "Add-ChromiumLoginRows";        Label = "Logins";         Chromium = $true }
        @{ Files = $chromeCookiePaths;       Parser = "Add-ChromiumCookieRows";       Label = "Cookies";        Chromium = $true }
        @{ Files = $chromeWebDataPaths;      Parser = "Add-ChromiumAutofillRows";     Label = "Autofill";       Chromium = $true }
        @{ Files = $chromeWebDataPaths;      Parser = "Add-ChromiumSearchEngineRows"; Label = "Search Engines"; Chromium = $true }
        @{ Files = $firefoxCookiePaths;      Parser = "Add-FirefoxCookieRows";        Label = "Cookies";        Chromium = $false }
        @{ Files = $firefoxFormHistoryPaths; Parser = "Add-FirefoxFormHistoryRows";   Label = "Form History";   Chromium = $false }
        @{ Files = $firefoxPermissionPaths;  Parser = "Add-FirefoxPermissionRows";    Label = "Permissions";    Chromium = $false }
    )
    foreach ($store in $storeParsers) {
        foreach ($db in $store.Files) {
            $storeName = if ($store.Chromium) { "$(Get-ChromiumBrowserName $db.FullName) $($store.Label)" } else { "Firefox $($store.Label)" }
            Log "  Parsing: $storeName ($(Get-CollectionUser $db.FullName))"
            try {
                $added = & $store.Parser -Sqlite3Exe $sqlite3Exe -File $db
                Log "    $added row(s) added."
                if ($added -gt 0) { $browserParsed = $true }
            }
            catch { Log-Warning "    Could not parse $storeName from $($db.FullName): $($_.Exception.Message)" }
        }
    }

    if (-not $browserParsed) {
        Log-Warning "No browser history entries parsed (SQLite unavailable or no data)."
    }
    Log "  Browser history parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 6. Scheduled Tasks Parser
# ----------------------------------------------------------

# Task registration date as written in task XML (RegistrationInfo/Date) or by
# Get-ScheduledTask ("Date"): UTC if it carries Z or an offset, otherwise the
# examined system's local time. Returns a Kind=Utc [datetime] or $null.
function ConvertFrom-TaskDateText {
    param([string]$Text)
    if (-not $Text -or -not $Text.Trim()) { return $null }
    $Text = $Text.Trim()
    if ($Text -match '(Z|[+-]\d{2}:\d{2})$') { return ConvertFrom-UtcText $Text }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($Text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
        return ConvertFrom-TargetLocalTime $dt
    }
    return $null
}

# Trimmed text of the first node at a path such as "RegistrationInfo/Date"
# below a task XML element (namespace-agnostic), or ""
function Get-TaskXmlText {
    param([System.Xml.XmlNode]$Node, [string]$Path)
    $xpath = (($Path -split '/') | ForEach-Object { "*[local-name()='$_']" }) -join '/'
    $match = $Node.SelectSingleNode($xpath)
    if ($match) { return $match.InnerText.Trim() }
    return ""
}

# $true when Read-TaskCache recorded a TaskCache registered time for the
# task (path such as "\Folder\Task") less than 2 seconds from $Time, a date
# from the task XML: that date is then the time Windows recorded (it often
# has whole seconds only) and its row would repeat the TaskCache row
function Test-TaskCacheRegistered {
    param([string]$TaskName, [datetime]$Time)
    if (-not $script:taskCacheRegistered -or -not $TaskName) { return $false }
    $key = $TaskName.ToLowerInvariant()
    if (-not $script:taskCacheRegistered.ContainsKey($key)) { return $false }
    foreach ($cacheTime in $script:taskCacheRegistered[$key]) {
        if ([Math]::Abs(($cacheTime - $Time).TotalSeconds) -lt 2) { return $true }
    }
    return $false
}

function Parse-ScheduledTasks {
    Log "--- Parsing Scheduled Tasks ---"

    $tasksParsed = $false

    # The registration date of the task XML (RegistrationInfo/Date) is set by
    # whoever wrote the task, not recorded by Windows: its rows say so. The
    # time Windows recorded is the TaskCache "Scheduled task registered" row
    # (Registry source); a date that is that time is not added again.
    $authorDateNote = "task XML RegistrationInfo/Date (author-supplied, not recorded by Windows)"

    # scheduled_tasks.csv from the triage collector (live systems). Newer
    # collectors add RegistrationDateUtc (the XML date, as Get-ScheduledTask
    # reports it) and LastRunTimeUtc; a task with no row from either (and
    # every task from older collectors) becomes one Snapshot row.
    $tasksCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("scheduled_tasks.csv")

    foreach ($csv in $tasksCsv) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $tasks = Import-Csv -Path $csv.FullName -ErrorAction Stop
            $snapshotTs = Get-SnapshotTimeUtc -File $csv
            $eventRows = 0
            $snapshotRows = 0
            $sameAsCache = 0
            foreach ($task in $tasks) {
                $taskName = Get-ArtifactRowValue $task @("TaskName", "Name")
                if (-not $taskName) { $taskName = "Unknown" }
                $taskPath = Get-ArtifactRowValue $task @("TaskPath")
                $fullName = if ($taskPath) { $taskPath.TrimEnd('\') + "\" + $taskName } else { $taskName }
                # Task path as Get-CollectedTaskNames and the TaskCache name it
                $cacheName = if ($taskPath) { $fullName } else { "\" + $taskName }
                $userId = Get-ArtifactRowValue $task @("UserId")
                $author = Get-ArtifactRowValue $task @("Author")
                $taskUser = if ($userId) { $userId } else { $author }
                $pairs = [ordered]@{
                    Actions  = Get-ArtifactRowValue $task @("Actions")
                    UserId   = $userId
                    Author   = $author
                    State    = Get-ArtifactRowValue $task @("State")
                    Triggers = Get-ArtifactRowValue $task @("Triggers")
                }

                $registered = ConvertFrom-UtcText (Get-ArtifactRowValue $task @("RegistrationDateUtc"))
                if (-not $registered) { $registered = ConvertFrom-TaskDateText (Get-ArtifactRowValue $task @("Date")) }
                if ($registered -and (Test-TaskCacheRegistered -TaskName $cacheName -Time $registered)) {
                    $registered = $null
                    $sameAsCache++
                }
                $lastRun = ConvertFrom-UtcText (Get-ArtifactRowValue $task @("LastRunTimeUtc"))
                # Task Scheduler reports 11/30/1999 for tasks that never ran
                if ($lastRun -and $lastRun.Year -lt 2000) { $lastRun = $null }

                if ($registered) {
                    $pairs["Time"] = $authorDateNote
                    Add-TimelineEntry -Timestamp $registered -Source "ScheduledTasks" -EventType "ScheduledTaskChange" `
                        -Description "Scheduled task registration date (author-supplied): $fullName" `
                        -User $taskUser -Details (Format-ArtifactDetails $pairs) `
                        -Artifact "ScheduledTasks" -RawPath $csv.FullName
                    $pairs.Remove("Time")
                    $eventRows++
                }
                if ($lastRun) {
                    $pairs["LastTaskResult"] = Get-ArtifactRowValue $task @("LastTaskResult")
                    Add-TimelineEntry -Timestamp $lastRun -Source "ScheduledTasks" -EventType "Execution" `
                        -Description "Scheduled task last run: $fullName" `
                        -User $taskUser -Details (Format-ArtifactDetails $pairs) `
                        -Artifact "ScheduledTasks" -RawPath $csv.FullName
                    $eventRows++
                }
                if (-not $registered -and -not $lastRun -and $snapshotTs) {
                    Add-TimelineEntry -Timestamp $snapshotTs -Source "ScheduledTasks" -EventType "Snapshot" `
                        -Description "Scheduled task: $fullName" `
                        -User $taskUser -Details (Format-ArtifactDetails $pairs) `
                        -Artifact "ScheduledTasks" -RawPath $csv.FullName
                    $snapshotRows++
                }
                $tasksParsed = $true
            }
            Log "    $eventRows dated row(s), $snapshotRows snapshot row(s)"
            if ($sameAsCache -gt 0) { Log "    $sameAsCache registration date(s) not added: the same time as the task's TaskCache registered row" }
        }
        catch {
            Log-Warning "  Failed to parse scheduled tasks CSV: $($_.Exception.Message)"
        }
    }

    # Task XML definitions copied from a mounted image (Windows\System32\Tasks).
    # RegistrationInfo/Date gives the (author-supplied) registration date;
    # tasks without it, or whose date is the TaskCache registered time,
    # become Snapshot rows.
    $xmlDirs = @(Get-ChildItem -Path $InputPath -Directory -Recurse -Filter "ScheduledTasks_XML" -ErrorAction SilentlyContinue | Where-Object { -not (Test-SecretsPath $_.FullName) })
    foreach ($dir in $xmlDirs) {
        $taskFiles = @(Get-ChildItem -Path $dir.FullName -File -Recurse -ErrorAction SilentlyContinue)
        Log "  Parsing: $($dir.FullName) ($($taskFiles.Count) file(s))"
        $eventRows = 0
        $snapshotRows = 0
        $sameAsCache = 0
        $skipped = 0
        foreach ($tf in $taskFiles) {
            try {
                # XmlDocument.Load honours the UTF-16 byte order mark / declaration
                $doc = New-Object System.Xml.XmlDocument
                $doc.Load($tf.FullName)
                $taskNode = $doc.DocumentElement
                if (-not $taskNode -or $taskNode.LocalName -ne "Task") { $skipped++; continue }

                $uri = Get-TaskXmlText $taskNode "RegistrationInfo/URI"
                $fullName = if ($uri) { $uri } else { "\" + $tf.Name }
                $author = Get-TaskXmlText $taskNode "RegistrationInfo/Author"
                $userId = Get-TaskXmlText $taskNode "Principals/Principal/UserId"
                if (-not $userId) { $userId = Get-TaskXmlText $taskNode "Principals/Principal/GroupId" }
                $taskUser = if ($userId) { $userId } else { $author }
                $actions = @()
                foreach ($exec in $taskNode.SelectNodes("*[local-name()='Actions']/*[local-name()='Exec']")) {
                    $actions += ((Get-TaskXmlText $exec "Command") + " " + (Get-TaskXmlText $exec "Arguments")).Trim()
                }
                foreach ($com in $taskNode.SelectNodes("*[local-name()='Actions']/*[local-name()='ComHandler']")) {
                    $actions += "ComHandler " + (Get-TaskXmlText $com "ClassId")
                }
                $triggers = @()
                foreach ($trig in $taskNode.SelectNodes("*[local-name()='Triggers']/*")) { $triggers += $trig.LocalName }
                $pairs = [ordered]@{
                    Actions  = ($actions -join "; ")
                    UserId   = $userId
                    Author   = $author
                    Enabled  = Get-TaskXmlText $taskNode "Settings/Enabled"
                    Triggers = ($triggers -join ", ")
                }

                $registered = ConvertFrom-TaskDateText (Get-TaskXmlText $taskNode "RegistrationInfo/Date")
                if ($registered -and (Test-TaskCacheRegistered -TaskName $fullName -Time $registered)) {
                    $registered = $null
                    $sameAsCache++
                }
                if ($registered) {
                    $pairs["Time"] = $authorDateNote
                    Add-TimelineEntry -Timestamp $registered -Source "ScheduledTasks-XML" -EventType "ScheduledTaskChange" `
                        -Description "Scheduled task registration date (author-supplied): $fullName" `
                        -User $taskUser -Details (Format-ArtifactDetails $pairs) `
                        -Artifact "ScheduledTasks" -RawPath $tf.FullName
                    $eventRows++
                }
                else {
                    $snapshotTs = Get-SnapshotTimeUtc -File $tf
                    if ($snapshotTs) {
                        Add-TimelineEntry -Timestamp $snapshotTs -Source "ScheduledTasks-XML" -EventType "Snapshot" `
                            -Description "Scheduled task: $fullName" `
                            -User $taskUser -Details (Format-ArtifactDetails $pairs) `
                            -Artifact "ScheduledTasks" -RawPath $tf.FullName
                        $snapshotRows++
                    }
                }
                $tasksParsed = $true
            }
            catch {
                $skipped++
            }
        }
        Log "    $eventRows dated row(s), $snapshotRows snapshot row(s)"
        if ($sameAsCache -gt 0) { Log "    $sameAsCache registration date(s) not added: the same time as the task's TaskCache registered row" }
        if ($skipped -gt 0) { Log-Warning "    Skipped $skipped file(s) that are not readable task XML." }
    }

    if (-not $tasksParsed) {
        Log-Warning "No scheduled task data found."
    }
    Log "  Scheduled tasks parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 7. Services Parser
# ----------------------------------------------------------

# Rows for services.csv / drivers.csv: one ServiceChange row at the service
# registry key's last-write time (KeyLastWriteUtc, newer collectors), else one
# Snapshot row at collection time. Returns the number of rows added.
function Add-ServiceListEntries {
    param([System.IO.FileInfo]$Csv, [string]$Kind, [string]$Source, [string]$Artifact)
    $snapshotTs = Get-SnapshotTimeUtc -File $Csv
    $eventRows = 0
    $snapshotRows = 0
    foreach ($svc in (Import-Csv -Path $Csv.FullName -ErrorAction Stop)) {
        $name = Get-ArtifactRowValue $svc @("Name", "ServiceName")
        if (-not $name) { $name = "Unknown" }
        $displayName = Get-ArtifactRowValue $svc @("DisplayName")
        $label = if ($displayName -and $displayName -ne $name) { "$name ($displayName)" } else { $name }
        $details = Format-ArtifactDetails ([ordered]@{
            PathName    = Get-ArtifactRowValue $svc @("PathName", "BinaryPathName")
            StartMode   = Get-ArtifactRowValue $svc @("StartMode", "StartType")
            StartName   = Get-ArtifactRowValue $svc @("StartName")
            State       = Get-ArtifactRowValue $svc @("State", "Status")
            ServiceType = Get-ArtifactRowValue $svc @("ServiceType")
        })
        $keyWrite = ConvertFrom-UtcText (Get-ArtifactRowValue $svc @("KeyLastWriteUtc"))
        if ($keyWrite) {
            Add-TimelineEntry -Timestamp $keyWrite -Source $Source -EventType "ServiceChange" `
                -Description "$Kind registry key last modified: $label" `
                -Details $details -Artifact $Artifact -RawPath $Csv.FullName
            $eventRows++
        }
        elseif ($snapshotTs) {
            Add-TimelineEntry -Timestamp $snapshotTs -Source $Source -EventType "Snapshot" `
                -Description "${Kind}: $label" `
                -Details $details -Artifact $Artifact -RawPath $Csv.FullName
            $snapshotRows++
        }
    }
    Log "    $eventRows key last-write row(s), $snapshotRows snapshot row(s)"
    return ($eventRows + $snapshotRows)
}

function Parse-Services {
    Log "--- Parsing Services ---"

    $servicesParsed = $false

    # services.csv from triage collection (Win32_Service). The list itself is
    # collection-time state; only the registry key last-write time is an event.
    $servicesCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("services.csv")

    foreach ($csv in $servicesCsv) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $count = Add-ServiceListEntries -Csv $csv -Kind "Service" -Source "Services" -Artifact "Services"
            if ($count -gt 0) { $servicesParsed = $true }
        }
        catch {
            Log-Warning "  Failed to parse services CSV: $($_.Exception.Message)"
        }
    }

    if (-not $servicesParsed) {
        Log-Warning "No service data found."
    }
    Log "  Services parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 8. File System Parser
# ----------------------------------------------------------
# Raw $MFT copied by newer collectors (FileSystem\$MFT), parsed in C# for
# speed (TimelineNtfs.MftParser). FILE record header: update sequence array
# offset 0x04 and count 0x06 (the last 2 bytes of every stride of record size /
# (count - 1) must equal the array's first value and are restored from it),
# sequence number 0x10, first attribute 0x14, flags 0x16 (0x01 in use, 0x02
# directory), bytes allocated 0x1C (record size, from the first record), base
# record reference 0x20 (non-zero = extension record; its attributes belong to
# the base record). Attributes: 0x10 $STANDARD_INFORMATION (Created, Modified,
# MFT changed, Accessed FILETIMEs), 0x30 $FILE_NAME (parent reference = 6-byte
# record + 2-byte sequence at 0, the same 4 times at 0x08, name length 0x40,
# namespace 0x41: 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS, UTF-16 name 0x42; the
# DOS 8.3 name is used only if there is no other) and the unnamed 0x80 $DATA
# (file size). Paths are volume-relative (\Users\...), built from the parent
# references; record 5 is the root. A missing parent, or one whose sequence
# number does not match (record reused), gives an "<orphan>\" prefix. NTFS
# increments the sequence number when a record is freed, so a deleted parent
# also matches a reference one lower.
# Mark of the Web: a downloaded file has a named 0x80 $DATA stream
# "Zone.Identifier" (attribute name length 0x09, name offset 0x0A, UTF-16)
# holding INI text ([ZoneTransfer] ZoneId=3, ReferrerUrl=, HostUrl=). It is
# small, so it is almost always resident (non-resident flag 0x08 = 0) and the
# text is in the record itself. Attributes in an extension record (one an
# $ATTRIBUTE_LIST points to) count for its base record, names and this stream
# alike (the stream only from an in-use extension record when the file is in
# use). A non-resident stream's text is in clusters outside the $MFT: such a
# file still gets a row, with the zone unknown.
function Initialize-MftParser {
    if ($null -ne $script:mftParserReady) { return $script:mftParserReady }
    $script:mftParserReady = $false
    try {
        if (-not ([System.Management.Automation.PSTypeName]'TimelineNtfs.MftParser').Type) {
            # C# 5 (Windows PowerShell 5.1 compiler): no interpolation, no "=>" members
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace TimelineNtfs
{
    public sealed class MftRow
    {
        public DateTime Time { get; set; }
        public string Description { get; set; }
        public string User { get; set; }
        public string Details { get; set; }
        public bool MarkOfTheWeb { get; set; }
    }

    public sealed class MftResult
    {
        public MftResult()
        {
            Rows = new List<MftRow>();
            ZoneCounts = new SortedDictionary<string, long>(StringComparer.Ordinal);
        }
        public List<MftRow> Rows { get; private set; }
        public int RecordSize { get; set; }
        public long RecordsRead { get; set; }
        public long InUse { get; set; }
        public long Deleted { get; set; }
        public long Unused { get; set; }
        public long Extension { get; set; }
        public long BadSignature { get; set; }
        public long FixupMismatch { get; set; }
        public long BadAttributes { get; set; }
        public long ParseFailures { get { return BadSignature + FixupMismatch + BadAttributes; } }
        public long OutsideWindow { get; set; }
        public long KeptForTimestomp { get; set; }
        public long OrphanPaths { get; set; }
        public long TimestompRecords { get; set; }
        public long TimestompRows { get; set; }
        public bool HasReference { get; set; }
        public bool ReferenceFromMft { get; set; }
        public DateTime ReferenceUtc { get; set; }
        public bool HasWindow { get; set; }
        public DateTime WindowStartUtc { get; set; }
        // Zone.Identifier (Mark of the Web) streams, after extension records are applied
        public long ZoneStreams { get; set; }
        public long ZoneResident { get; set; }
        public long ZoneNonResident { get; set; }
        public long ZoneFolders { get; set; }
        public long ZoneRows { get; set; }
        public long ZoneExtracted { get; set; }
        public long ZoneDeleted { get; set; }
        public long ZoneFnTime { get; set; }
        public long ZoneOutsideWindow { get; set; }
        public long ZoneNoTime { get; set; }
        public SortedDictionary<string, long> ZoneCounts { get; private set; }
    }

    public sealed class MftParser
    {
        const uint FileSignature = 0x454C4946;   // "FILE"
        const int RootRecord = 5;
        const long TicksPerSecond = 10000000L;
        const long TicksPerDay = 864000000000L;
        const string OrphanPrefix = "<orphan>";
        const string TimeFormat = "yyyy-MM-dd HH:mm:ss.fffffff";
        const byte StValid = 1;
        const byte StInUse = 2;
        const byte StDir = 4;
        const byte StHasSI = 8;
        const byte StVisiting = 16;
        const byte StZone = 32;              // resident Zone.Identifier (text in zoneTexts)
        const byte StZoneNonResident = 64;   // non-resident Zone.Identifier (text not in the $MFT)
        const string ZoneStreamName = "zone.identifier";
        static readonly long MaxFileTime = DateTime.MaxValue.ToFileTimeUtc();
        // Add-TimelineEntry drops times before 1980
        static readonly long MinRowTime = new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
        static readonly Encoding Ansi = GetAnsiEncoding();
        static readonly char[] LineBreaks = { '\r', '\n' };

        // $FILE_NAME / $DATA found in an extension record, applied to its base record
        sealed class ExtensionPart
        {
            public int BaseRecord;
            public ushort BaseSeq;
            public string Name;
            public int Priority;
            public int Parent;
            public ushort ParentSeq;
            public long FnCreated;
            public long Size;
            public string Zone;
            public bool ZoneNonResident;
            public bool InUse;
        }

        readonly MftResult result = new MftResult();
        readonly List<ExtensionPart> extensions = new List<ExtensionPart>();
        readonly List<int> chain = new List<int>();
        int count;
        int recordSize;

        // Per base record (index = record number)
        byte[] state;
        ushort[] seq;
        long[] siCreated;
        long[] siModified;
        long[] siChanged;
        long[] siAccessed;
        long[] fnCreated;
        long[] dataSize;
        string[] names;
        byte[] namePriority;
        int[] parents;
        ushort[] parentSeqs;
        string[] dirPaths;
        // Zone.Identifier text by record (few records have one)
        readonly Dictionary<int, string> zoneTexts = new Dictionary<int, string>();

        // Attributes of the record being read
        bool curHasSI;
        long curSiCreated;
        long curSiModified;
        long curSiChanged;
        long curSiAccessed;
        string curName;
        int curPriority;
        int curParent;
        ushort curParentSeq;
        long curFnCreated;
        long curSize;
        string curZone;
        bool curZoneNonResident;

        MftParser() { }

        // referenceFileTime: collection start as a UTC FILETIME (0 = unknown, use
        // the newest plausible $MFT time); days: window before it (0 = all times)
        public static MftResult Parse(string path, long referenceFileTime, int days)
        {
            MftParser parser = new MftParser();
            parser.ReadFile(path);
            parser.ApplyExtensions();
            parser.BuildRows(referenceFileTime, days);
            return parser.result;
        }

        static int ReadFull(Stream s, byte[] buffer, int length)
        {
            int total = 0;
            while (total < length)
            {
                int n = s.Read(buffer, total, length - total);
                if (n <= 0) break;
                total += n;
            }
            return total;
        }

        static bool IsValidTime(long fileTime)
        {
            return fileTime > 0 && fileTime <= MaxFileTime;
        }

        static bool IsRowTime(long fileTime)
        {
            return fileTime >= MinRowTime && fileTime <= MaxFileTime;
        }

        void ReadFile(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan))
            {
                byte[] head = new byte[0x30];
                if (ReadFull(fs, head, head.Length) < head.Length || BitConverter.ToUInt32(head, 0) != FileSignature)
                    throw new IOException("not an $MFT copy: the first record has no FILE signature");
                recordSize = (int)BitConverter.ToUInt32(head, 0x1C);
                if (recordSize < 256 || recordSize > 65536 || (recordSize & (recordSize - 1)) != 0)
                    throw new IOException("unexpected MFT record size " + recordSize.ToString(Inv) + " in the first record");
                long total = fs.Length / recordSize;
                if (total > int.MaxValue / 2) throw new IOException("$MFT too large (" + total.ToString(Inv) + " records)");
                count = (int)total;
                result.RecordSize = recordSize;

                state = new byte[count];
                seq = new ushort[count];
                siCreated = new long[count];
                siModified = new long[count];
                siChanged = new long[count];
                siAccessed = new long[count];
                fnCreated = new long[count];
                dataSize = new long[count];
                names = new string[count];
                namePriority = new byte[count];
                parents = new int[count];
                parentSeqs = new ushort[count];
                dirPaths = new string[count];

                fs.Position = 0;
                int perChunk = Math.Max(1, (4 * 1024 * 1024) / recordSize);
                byte[] buffer = new byte[perChunk * recordSize];
                int rec = 0;
                while (rec < count)
                {
                    int want = Math.Min(perChunk, count - rec);
                    int got = ReadFull(fs, buffer, want * recordSize) / recordSize;
                    for (int i = 0; i < got; i++) ReadRecord(buffer, i * recordSize, rec + i);
                    rec += got;
                    if (got < want) { count = rec; break; }
                }
            }
        }

        // Check and undo the update sequence fixups (in place)
        bool ApplyFixups(byte[] b, int o)
        {
            int usaOffset = BitConverter.ToUInt16(b, o + 0x04);
            int usaCount = BitConverter.ToUInt16(b, o + 0x06);
            if (usaCount < 2 || usaOffset < 0x28 || usaOffset + usaCount * 2 > recordSize) return false;
            int stride = recordSize / (usaCount - 1);
            if (stride < 256 || stride * (usaCount - 1) != recordSize) return false;
            int u = o + usaOffset;
            for (int k = 1; k < usaCount; k++)
            {
                int p = o + k * stride - 2;
                if (b[p] != b[u] || b[p + 1] != b[u + 1]) return false;
            }
            for (int k = 1; k < usaCount; k++)
            {
                int p = o + k * stride - 2;
                b[p] = b[u + 2 * k];
                b[p + 1] = b[u + 2 * k + 1];
            }
            return true;
        }

        void ReadRecord(byte[] b, int o, int rec)
        {
            result.RecordsRead++;
            uint signature = BitConverter.ToUInt32(b, o);
            if (signature != FileSignature)
            {
                if (signature == 0) result.Unused++;
                else result.BadSignature++;
                return;
            }
            if (!ApplyFixups(b, o)) { result.FixupMismatch++; return; }

            ushort sequence = BitConverter.ToUInt16(b, o + 0x10);
            int firstAttribute = BitConverter.ToUInt16(b, o + 0x14);
            int flags = BitConverter.ToUInt16(b, o + 0x16);
            uint bytesInUse = BitConverter.ToUInt32(b, o + 0x18);
            int used = bytesInUse > (uint)recordSize ? recordSize : (int)bytesInUse;
            ulong baseReference = BitConverter.ToUInt64(b, o + 0x20);
            long baseRecord = (long)(baseReference & 0xFFFFFFFFFFFFUL);

            if (!ReadAttributes(b, o, firstAttribute, used)) result.BadAttributes++;

            if (baseRecord != 0)
            {
                result.Extension++;
                if (baseRecord < count && baseRecord != rec && (curName != null || curSize >= 0 || curZone != null || curZoneNonResident))
                {
                    ExtensionPart part = new ExtensionPart();
                    part.BaseRecord = (int)baseRecord;
                    part.BaseSeq = (ushort)(baseReference >> 48);
                    part.Name = curName;
                    part.Priority = curPriority;
                    part.Parent = curParent;
                    part.ParentSeq = curParentSeq;
                    part.FnCreated = curFnCreated;
                    part.Size = curSize;
                    part.Zone = curZone;
                    part.ZoneNonResident = curZoneNonResident;
                    part.InUse = (flags & 0x01) != 0;
                    extensions.Add(part);
                }
                return;
            }

            byte st = StValid;
            if ((flags & 0x01) != 0) st |= StInUse;
            if ((flags & 0x02) != 0) st |= StDir;
            if (curHasSI) st |= StHasSI;
            if (curZone != null) { st |= StZone; zoneTexts[rec] = curZone; }
            if (curZoneNonResident) st |= StZoneNonResident;
            state[rec] = st;
            seq[rec] = sequence;
            siCreated[rec] = curSiCreated;
            siModified[rec] = curSiModified;
            siChanged[rec] = curSiChanged;
            siAccessed[rec] = curSiAccessed;
            names[rec] = curName;
            namePriority[rec] = (byte)curPriority;
            parents[rec] = curParent;
            parentSeqs[rec] = curParentSeq;
            fnCreated[rec] = curFnCreated;
            dataSize[rec] = curSize;
        }

        // Fills the cur* fields; false if the attribute list is damaged (what was
        // read before the damage is kept)
        bool ReadAttributes(byte[] b, int o, int first, int used)
        {
            curHasSI = false;
            curSiCreated = 0; curSiModified = 0; curSiChanged = 0; curSiAccessed = 0;
            curName = null; curPriority = 0; curParent = -1; curParentSeq = 0;
            curFnCreated = 0; curSize = -1;
            curZone = null; curZoneNonResident = false;

            int a = first;
            while (a + 4 <= used)
            {
                uint type = BitConverter.ToUInt32(b, o + a);
                if (type == 0xFFFFFFFF) return true;
                if (a + 0x18 > used) return false;
                uint length = BitConverter.ToUInt32(b, o + a + 4);
                if (length < 0x18 || length > (uint)(used - a)) return false;
                int len = (int)length;
                int nameLength = b[o + a + 9];
                if (b[o + a + 8] == 0)
                {
                    // Resident: content length 0x10, content offset 0x14
                    long contentLength = BitConverter.ToUInt32(b, o + a + 0x10);
                    int contentOffset = BitConverter.ToUInt16(b, o + a + 0x14);
                    if (contentOffset + contentLength > len) return false;
                    int c = o + a + contentOffset;
                    if (type == 0x10 && contentLength >= 0x20)
                    {
                        curHasSI = true;
                        curSiCreated = BitConverter.ToInt64(b, c);
                        curSiModified = BitConverter.ToInt64(b, c + 0x08);
                        curSiChanged = BitConverter.ToInt64(b, c + 0x10);
                        curSiAccessed = BitConverter.ToInt64(b, c + 0x18);
                    }
                    else if (type == 0x30)
                    {
                        if (contentLength < 0x42) return false;
                        int chars = b[c + 0x40];
                        if (0x42 + chars * 2 > contentLength) return false;
                        int priority = b[c + 0x41] == 2 ? 1 : 2;
                        if (chars > 0 && priority > curPriority)
                        {
                            ulong parentReference = BitConverter.ToUInt64(b, c);
                            long parentRecord = (long)(parentReference & 0xFFFFFFFFFFFFUL);
                            curPriority = priority;
                            curName = Encoding.Unicode.GetString(b, c + 0x42, chars * 2);
                            curParent = parentRecord > int.MaxValue ? -1 : (int)parentRecord;
                            curParentSeq = (ushort)(parentReference >> 48);
                            curFnCreated = BitConverter.ToInt64(b, c + 0x08);
                        }
                    }
                    else if (type == 0x80 && nameLength == 0)
                    {
                        curSize = contentLength;
                    }
                    else if (type == 0x80 && IsZoneIdentifier(b, o + a, len, nameLength))
                    {
                        curZone = DecodeZoneText(b, c, (int)contentLength);
                    }
                }
                else if (type == 0x80 && nameLength == 0)
                {
                    // Non-resident: the first extent (start VCN 0x10 = 0) holds the real size (0x30)
                    if (len < 0x40) return false;
                    if (BitConverter.ToInt64(b, o + a + 0x10) == 0) curSize = BitConverter.ToInt64(b, o + a + 0x30);
                }
                else if (type == 0x80 && IsZoneIdentifier(b, o + a, len, nameLength))
                {
                    curZoneNonResident = true;
                }
                a += len;
            }
            return true;
        }

        // Attribute name (UTF-16 at the name offset 0x0A) is "Zone.Identifier",
        // ignoring ASCII case, compared in place: this runs for every named $DATA
        static bool IsZoneIdentifier(byte[] b, int attribute, int len, int nameLength)
        {
            if (nameLength != ZoneStreamName.Length) return false;
            int nameOffset = BitConverter.ToUInt16(b, attribute + 0x0A);
            if (nameOffset + nameLength * 2 > len) return false;
            int p = attribute + nameOffset;
            for (int i = 0; i < nameLength; i++)
            {
                int ch = b[p + 2 * i] | (b[p + 2 * i + 1] << 8);
                if (ch >= 'A' && ch <= 'Z') ch += 32;
                if (ch != ZoneStreamName[i]) return false;
            }
            return true;
        }

        // Windows-1252, or Latin-1 (the same but for 0x80-0x9F) where the .NET
        // runtime has no code-page encodings registered
        static Encoding GetAnsiEncoding()
        {
            try { return Encoding.GetEncoding(1252); }
            catch (NotSupportedException) { return Encoding.GetEncoding(28591); }
            catch (ArgumentException) { return Encoding.GetEncoding(28591); }
        }

        // Zone.Identifier text: UTF-16 with a BOM (or little-endian without one,
        // seen as a 0 second byte), UTF-8 with or without a BOM, else ANSI
        static string DecodeZoneText(byte[] b, int start, int length)
        {
            string text;
            if (length >= 2 && b[start] == 0xFF && b[start + 1] == 0xFE)
            {
                text = Encoding.Unicode.GetString(b, start + 2, (length - 2) & ~1);
            }
            else if (length >= 2 && b[start] == 0xFE && b[start + 1] == 0xFF)
            {
                text = Encoding.BigEndianUnicode.GetString(b, start + 2, (length - 2) & ~1);
            }
            else if (length >= 4 && b[start] != 0 && b[start + 1] == 0 && b[start + 3] == 0)
            {
                text = Encoding.Unicode.GetString(b, start, length & ~1);
            }
            else
            {
                if (length >= 3 && b[start] == 0xEF && b[start + 1] == 0xBB && b[start + 2] == 0xBF) { start += 3; length -= 3; }
                try { text = StrictUtf8.GetString(b, start, length); }
                catch (DecoderFallbackException) { text = Ansi.GetString(b, start, length); }
            }
            return text.Trim('\0', ' ', '\t', '\r', '\n');
        }

        // Sequence check; a freed record's number was incremented when it was freed
        bool SequenceMatches(int r, ushort referenceSeq)
        {
            if (seq[r] == referenceSeq) return true;
            if ((state[r] & StInUse) != 0) return false;
            ushort next = (ushort)(referenceSeq + 1);
            if (next == 0) next = 1;
            return seq[r] == next;
        }

        void ApplyExtensions()
        {
            foreach (ExtensionPart part in extensions)
            {
                int r = part.BaseRecord;
                if ((state[r] & StValid) == 0 || !SequenceMatches(r, part.BaseSeq)) continue;
                if (part.Name != null && part.Priority > namePriority[r])
                {
                    names[r] = part.Name;
                    namePriority[r] = (byte)part.Priority;
                    parents[r] = part.Parent;
                    parentSeqs[r] = part.ParentSeq;
                    fnCreated[r] = part.FnCreated;
                }
                if (part.Size >= 0 && dataSize[r] < 0) dataSize[r] = part.Size;
                // A freed extension record keeps the stream an in-use file has
                // since lost (Unblock-File): only a deleted file takes it
                if (!part.InUse && (state[r] & StInUse) != 0) continue;
                if (part.Zone != null && (state[r] & StZone) == 0)
                {
                    zoneTexts[r] = part.Zone;
                    state[r] |= StZone;
                }
                if (part.ZoneNonResident) state[r] |= StZoneNonResident;
            }
            extensions.Clear();
        }

        bool ParentOk(int r)
        {
            int p = parents[r];
            if (p == RootRecord) return true;
            if (p < 0 || p >= count || p == r) return false;
            if ((state[p] & StValid) == 0 || names[p] == null) return false;
            return SequenceMatches(p, parentSeqs[r]);
        }

        // Path of a folder used as a parent ("" for the root), memoised. Walks up
        // until a known path, the root, a bad parent or a cycle, then builds down.
        string DirPath(int d)
        {
            if (d == RootRecord) return "";
            if (dirPaths[d] != null) return dirPaths[d];
            chain.Clear();
            string basePath;
            int cur = d;
            while (true)
            {
                if (cur == RootRecord) { basePath = ""; break; }
                if (dirPaths[cur] != null) { basePath = dirPaths[cur]; break; }
                if ((state[cur] & StVisiting) != 0) { basePath = OrphanPrefix; break; }
                state[cur] |= StVisiting;
                chain.Add(cur);
                if (!ParentOk(cur)) { basePath = OrphanPrefix; break; }
                cur = parents[cur];
            }
            for (int i = chain.Count - 1; i >= 0; i--)
            {
                int c = chain[i];
                basePath = basePath + "\\" + names[c];
                dirPaths[c] = basePath;
                state[c] = (byte)(state[c] & ~StVisiting);
            }
            return basePath;
        }

        string FullPath(int r)
        {
            if (r == RootRecord) return "\\";
            if (names[r] == null) return OrphanPrefix + "\\<record " + r.ToString(Inv) + ">";
            string prefix = ParentOk(r) ? DirPath(parents[r]) : OrphanPrefix;
            return prefix + "\\" + names[r];
        }

        static string UserFromPath(string path)
        {
            const string usersPrefix = "\\Users\\";
            if (!path.StartsWith(usersPrefix, StringComparison.OrdinalIgnoreCase)) return "";
            int end = path.IndexOf('\\', usersPrefix.Length);
            return end > usersPrefix.Length ? path.Substring(usersPrefix.Length, end - usersPrefix.Length) : "";
        }

        // Possible timestomping: on an executable or script, SI Created is on a
        // whole second and more than 1 s earlier than FN Created (backdating
        // tools set whole-second times). Windows servicing and installers lay
        // files down the same way in WinSxS, servicing, Installer, dotnet and
        // WindowsApps; those locations are not flagged (on a real system they
        // were 98% of all hits without this rule).
        const string TimestompReason = "possible timestomping: executable/script whose SI Created is on a whole second and more than 1 s earlier than FN Created";
        static readonly string[] StompExtensions = { ".exe", ".dll", ".sys", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".com", ".cpl", ".msi", ".lnk" };
        static readonly string[] StompExcludedPrefixes = {
            "\\Windows\\WinSxS\\", "\\Windows\\servicing\\", "\\Windows\\SoftwareDistribution\\",
            "\\Windows\\Installer\\", "\\Windows\\assembly\\", "\\Program Files\\dotnet\\",
            "\\Program Files (x86)\\dotnet\\", "\\Program Files\\WindowsApps\\" };

        static bool StompTimes(long created, long fnCreatedTime)
        {
            if (!IsValidTime(created) || !IsValidTime(fnCreatedTime)) return false;
            return created < fnCreatedTime - TicksPerSecond && created % TicksPerSecond == 0;
        }

        static bool StompPath(string path)
        {
            // Extension by hand: paths can hold characters Path.GetExtension rejects
            int dot = path.LastIndexOf('.');
            if (dot <= path.LastIndexOf('\\')) return false;
            string ext = path.Substring(dot);
            bool executable = false;
            foreach (string e in StompExtensions)
            {
                if (string.Equals(ext, e, StringComparison.OrdinalIgnoreCase)) { executable = true; break; }
            }
            if (!executable) return false;
            foreach (string prefix in StompExcludedPrefixes)
            {
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            }
            return true;
        }

        static void AppendTime(StringBuilder sb, string label, long fileTime)
        {
            if (!IsValidTime(fileTime)) return;
            sb.Append(" | ").Append(label).Append('=').Append(DateTime.FromFileTimeUtc(fileTime).ToString(TimeFormat, Inv));
        }

        void AppendRecord(StringBuilder sb, int r)
        {
            sb.Append("MftRecord=").Append(r.ToString(Inv)).Append(" | Seq=").Append(seq[r].ToString(Inv));
            if ((state[r] & StDir) == 0 && dataSize[r] >= 0) sb.Append(" | Size=").Append(dataSize[r].ToString(Inv));
        }

        string Details(int r, bool createdRow, string stomp)
        {
            StringBuilder sb = new StringBuilder(256);
            AppendRecord(sb, r);
            if (createdRow) AppendTime(sb, "SI.Modified", siModified[r]);
            else AppendTime(sb, "SI.Created", siCreated[r]);
            AppendTime(sb, "SI.MftChanged", siChanged[r]);
            AppendTime(sb, "SI.Accessed", siAccessed[r]);
            AppendTime(sb, "FN.Created", fnCreated[r]);
            if (stomp != null) sb.Append(" | Timestomp=").Append(stomp);
            return sb.ToString();
        }

        // key=value lines of a Zone.Identifier ([ZoneTransfer] ZoneId=3,
        // ReferrerUrl=, HostUrl=, sometimes LastWriterPackageFamilyName,
        // AppZoneId). Section and comment lines and empty values are skipped,
        // the first of a repeated key is kept, the three usual keys come first
        // with their usual spelling, then the others in file order. The text is
        // written by whatever saved the file, so keys not known here get a
        // "Zone." prefix (a stream line cannot pose as MftRecord, SI.Created and
        // so on) and "|" becomes %7C (Details stay splittable on " | ").
        static readonly string[] ZoneKeys = { "ZoneId", "HostUrl", "ReferrerUrl" };
        static readonly string[] OtherZoneKeys = { "LastWriterPackageFamilyName", "AppZoneId", "AppDefinedZoneId", "HostIpAddress" };

        static string ZoneField(string text)
        {
            return text.IndexOf('|') < 0 ? text : text.Replace("|", "%7C");
        }

        static string ZoneKey(string key)
        {
            foreach (string known in ZoneKeys)
            {
                if (string.Equals(key, known, StringComparison.OrdinalIgnoreCase)) return known;
            }
            foreach (string known in OtherZoneKeys)
            {
                if (string.Equals(key, known, StringComparison.OrdinalIgnoreCase)) return known;
            }
            return "Zone." + ZoneField(key);
        }

        static List<KeyValuePair<string, string>> ParseZoneText(string text)
        {
            List<KeyValuePair<string, string>> found = new List<KeyValuePair<string, string>>();
            foreach (string rawLine in text.Split(LineBreaks, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line[0] == '[' || line[0] == ';') continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line.Substring(0, eq).Trim();
                string value = line.Substring(eq + 1).Trim();
                if (key.Length == 0 || value.Length == 0) continue;
                key = ZoneKey(key);
                if (ZoneValue(found, key) != null) continue;
                found.Add(new KeyValuePair<string, string>(key, ZoneField(value)));
            }
            List<KeyValuePair<string, string>> pairs = new List<KeyValuePair<string, string>>(found.Count);
            foreach (string known in ZoneKeys)
            {
                string value = ZoneValue(found, known);
                if (value != null) pairs.Add(new KeyValuePair<string, string>(known, value));
            }
            foreach (KeyValuePair<string, string> pair in found)
            {
                if (Array.IndexOf(ZoneKeys, pair.Key) < 0) pairs.Add(pair);
            }
            return pairs;
        }

        static string ZoneValue(List<KeyValuePair<string, string>> pairs, string key)
        {
            if (pairs == null) return null;
            foreach (KeyValuePair<string, string> pair in pairs)
            {
                if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase)) return pair.Value;
            }
            return null;
        }

        // URLZONE names as Internet Options shows them; null pairs = non-resident stream
        static string ZoneLabel(List<KeyValuePair<string, string>> pairs)
        {
            int zone;
            if (!int.TryParse(ZoneValue(pairs, "ZoneId"), NumberStyles.Integer, Inv, out zone)) return "zone unknown";
            switch (zone)
            {
                case 0: return "Local machine zone";
                case 1: return "Local intranet zone";
                case 2: return "Trusted sites zone";
                case 3: return "Internet zone";
                case 4: return "Restricted sites zone";
                default: return "zone " + zone.ToString(Inv);
            }
        }

        // Appended to the Details of the file's "File created" row: ZoneId and
        // HostUrl, or ReferrerUrl when there is no HostUrl (an extracted file)
        static string ZoneSuffix(List<KeyValuePair<string, string>> pairs)
        {
            if (pairs == null) return "";
            StringBuilder sb = new StringBuilder(128);
            string zoneId = ZoneValue(pairs, "ZoneId");
            string hostUrl = ZoneValue(pairs, "HostUrl");
            string referrerUrl = ZoneValue(pairs, "ReferrerUrl");
            if (zoneId != null) sb.Append(" | ZoneId=").Append(zoneId);
            if (hostUrl != null) sb.Append(" | HostUrl=").Append(hostUrl);
            else if (referrerUrl != null) sb.Append(" | ReferrerUrl=").Append(referrerUrl);
            return sb.ToString();
        }

        // Explorer (and other unzip tools) give each file extracted from an
        // archive with Mark of the Web the archive's ZoneId and its local or
        // network path as ReferrerUrl, with no HostUrl
        static bool IsExtracted(List<KeyValuePair<string, string>> pairs)
        {
            if (ZoneValue(pairs, "HostUrl") != null) return false;
            string referrer = ZoneValue(pairs, "ReferrerUrl");
            if (referrer == null) return false;
            if (referrer.Length >= 3 && referrer[1] == ':' && (referrer[2] == '\\' || referrer[2] == '/'))
            {
                char drive = char.ToUpperInvariant(referrer[0]);
                if (drive >= 'A' && drive <= 'Z') return true;
            }
            return referrer.StartsWith("\\\\", StringComparison.Ordinal) || referrer.StartsWith("file:", StringComparison.OrdinalIgnoreCase);
        }

        string ZoneDetails(int r, List<KeyValuePair<string, string>> pairs, bool fnTime, string stomp)
        {
            StringBuilder sb = new StringBuilder(512);
            if (pairs == null) sb.Append("ZoneIdentifier=non-resident (its text is not in the $MFT)");
            else if (pairs.Count == 0) sb.Append("ZoneIdentifier=no key=value lines");
            else
            {
                foreach (KeyValuePair<string, string> pair in pairs)
                {
                    if (sb.Length > 0) sb.Append(" | ");
                    sb.Append(pair.Key).Append('=').Append(pair.Value);
                }
            }
            sb.Append(" | ");
            AppendRecord(sb, r);
            AppendTime(sb, "SI.Created", siCreated[r]);
            AppendTime(sb, "SI.Modified", siModified[r]);
            AppendTime(sb, "SI.MftChanged", siChanged[r]);
            AppendTime(sb, "SI.Accessed", siAccessed[r]);
            AppendTime(sb, "FN.Created", fnCreated[r]);
            if (fnTime) sb.Append(" | RowTime=FN.Created");
            if (stomp != null) sb.Append(" | Timestomp=").Append(stomp);
            return sb.ToString();
        }

        // "Downloaded file (Mark of the Web, <zone>): <path>", or "Extracted
        // file (...)" (see IsExtracted), "; record deleted" in the brackets for
        // a record no longer in use. The row is at SI Created, or at FN Created
        // (RowTime=FN.Created in Details) when SI Created is missing, before 1980
        // or more than 1 s earlier: backdating tools, and extraction (which sets
        // the archive entry's time), change SI Created, while FN Created is when
        // the file arrived on the volume. [SI<FN] as on the file's other rows,
        // but not for an extracted file, whose earlier SI Created the stream
        // explains. Added whatever the -MftDays window. False if the file has no
        // time from 1980 on.
        bool AddZoneRow(int r, string path, string user, List<KeyValuePair<string, string>> pairs, string stomp, long windowStart)
        {
            long time = siCreated[r];
            bool fnTime = IsRowTime(fnCreated[r]) && (!IsRowTime(time) || time < fnCreated[r] - TicksPerSecond);
            if (fnTime) time = fnCreated[r];
            if (!IsRowTime(time)) { result.ZoneNoTime++; return false; }
            string zone = ZoneLabel(pairs);
            long seen;
            result.ZoneCounts.TryGetValue(zone, out seen);
            result.ZoneCounts[zone] = seen + 1;
            if (fnTime) result.ZoneFnTime++;
            if (time < windowStart) result.ZoneOutsideWindow++;
            string noun = "Downloaded file";
            if (IsExtracted(pairs)) { noun = "Extracted file"; stomp = null; result.ZoneExtracted++; }
            string qualifier = zone;
            if ((state[r] & StInUse) == 0) { qualifier += "; record deleted"; result.ZoneDeleted++; }
            string marker = stomp != null ? " [SI<FN]" : "";
            AddRow(time, noun + " (Mark of the Web, " + qualifier + "): " + path + marker, user, ZoneDetails(r, pairs, fnTime, stomp)).MarkOfTheWeb = true;
            result.ZoneRows++;
            return true;
        }

        MftRow AddRow(long fileTime, string description, string user, string details)
        {
            MftRow row = new MftRow();
            row.Time = DateTime.FromFileTimeUtc(fileTime);
            row.Description = description;
            row.User = user;
            row.Details = details;
            result.Rows.Add(row);
            return row;
        }

        static long Newer(long newest, long fileTime, long limit)
        {
            return (IsValidTime(fileTime) && fileTime <= limit && fileTime > newest) ? fileTime : newest;
        }

        void BuildRows(long referenceFileTime, int days)
        {
            // Counts, and the newest plausible SI time (not after tomorrow)
            long limit = DateTime.UtcNow.AddDays(1).ToFileTimeUtc();
            long newest = 0;
            for (int r = 0; r < count; r++)
            {
                byte st = state[r];
                if ((st & StValid) == 0) continue;
                if ((st & StInUse) != 0) result.InUse++;
                else if ((st & StHasSI) != 0 || names[r] != null) result.Deleted++;
                else result.Unused++;
                if ((st & (StZone | StZoneNonResident)) != 0)
                {
                    result.ZoneStreams++;
                    if ((st & StZone) != 0) result.ZoneResident++;
                    else result.ZoneNonResident++;
                    if ((st & StDir) != 0) result.ZoneFolders++;
                }
                if ((st & StHasSI) == 0) continue;
                newest = Newer(newest, siCreated[r], limit);
                newest = Newer(newest, siModified[r], limit);
                newest = Newer(newest, siChanged[r], limit);
            }

            long reference = referenceFileTime;
            if (!IsValidTime(reference))
            {
                reference = newest;
                result.ReferenceFromMft = newest > 0;
            }
            long windowStart = long.MinValue;
            if (reference > 0)
            {
                result.HasReference = true;
                result.ReferenceUtc = DateTime.FromFileTimeUtc(reference);
                if (days > 0)
                {
                    windowStart = reference - days * TicksPerDay;
                    result.HasWindow = true;
                    result.WindowStartUtc = DateTime.FromFileTimeUtc(Math.Max(0L, windowStart));
                }
            }

            for (int r = 0; r < count; r++)
            {
                byte st = state[r];
                if ((st & StValid) == 0) continue;
                // Mark of the Web rows are for files; a record without
                // $STANDARD_INFORMATION (SI times all 0) gets only that row
                bool hasZone = (st & StDir) == 0 && (st & (StZone | StZoneNonResident)) != 0;
                if ((st & StHasSI) == 0 && !hasZone) continue;
                long created = siCreated[r];
                long modified = siModified[r];
                string stomp = null;
                if ((st & StDir) == 0 && StompTimes(created, fnCreated[r]) && StompPath(FullPath(r)))
                {
                    stomp = TimestompReason;
                }
                if (stomp != null) result.TimestompRecords++;
                // Backdating moves SI times out of the window: keep flagged records
                // whose FN Created time is in it
                bool keepFlagged = stomp != null && fnCreated[r] >= windowStart;

                bool createdRow = false;
                bool modifiedRow = false;
                if (IsValidTime(created))
                {
                    if (created >= windowStart) createdRow = true;
                    else if (keepFlagged) { createdRow = true; result.KeptForTimestomp++; }
                    else result.OutsideWindow++;
                }
                if (IsValidTime(modified))
                {
                    if (modified >= windowStart) modifiedRow = true;
                    else if (keepFlagged) { modifiedRow = true; result.KeptForTimestomp++; }
                    else result.OutsideWindow++;
                }
                if (!createdRow && !modifiedRow && !hasZone) continue;

                string path = FullPath(r);
                bool isDir = (st & StDir) != 0;
                string noun;
                if ((st & StInUse) == 0) noun = isDir ? "Deleted folder" : "Deleted file";
                else noun = isDir ? "Folder" : "File";
                string marker = stomp != null ? " [SI<FN]" : "";
                string user = UserFromPath(path);
                List<KeyValuePair<string, string>> zonePairs = null;
                if (hasZone && (st & StZone) != 0) zonePairs = ParseZoneText(zoneTexts[r]);
                // The origin URL also goes on the file's created row (Details only)
                if (createdRow) AddRow(created, noun + " created: " + path + marker, user, Details(r, true, stomp) + ZoneSuffix(zonePairs));
                if (modifiedRow) AddRow(modified, noun + " modified: " + path + marker, user, Details(r, false, stomp));
                if (stomp != null) result.TimestompRows += (createdRow ? 1 : 0) + (modifiedRow ? 1 : 0);
                bool zoneRow = hasZone && AddZoneRow(r, path, user, zonePairs, stomp, windowStart);
                if ((createdRow || modifiedRow || zoneRow) && path.StartsWith(OrphanPrefix, StringComparison.Ordinal)) result.OrphanPaths++;
            }
        }
    }
}
'@
        }
        $script:mftParserReady = $true
    }
    catch {
        Log-Warning "  `$MFT parser could not be compiled: $($_.Exception.Message)"
    }
    return $script:mftParserReady
}

# Timeline rows (Source MFT) from one $MFT copy: SI Created and SI Modified of
# every file and folder record, for times at most -MftDays days before the
# collection start (the newest $MFT time if that is unknown); later times are
# kept. Records flagged [SI<FN] (possible timestomping) are also kept when
# their FN Created time is in the window, as backdating moves SI times out of it.
# A file with a Zone.Identifier stream (Mark of the Web) also gets a
# "Downloaded file (Mark of the Web, <zone>): <path>" row ("Extracted file"
# when the stream names the archive it came from instead of a URL) with ZoneId,
# HostUrl, ReferrerUrl and any other key=value of the stream in Details, at SI
# Created, or at FN Created when SI Created is earlier (backdated, or the
# archive entry time). These rows are added whatever -MftDays: there are few of
# them and they tie a file to the URL it came from. The file's "File created"
# row, when in the window, gets ZoneId and HostUrl (or ReferrerUrl) appended to
# its Details.
function Add-MftTimelineEntries {
    param([System.IO.FileInfo]$File)
    if (-not (Initialize-MftParser)) { return }

    Log "  Parsing: $($File.FullName) ($([Math]::Round($File.Length / 1MB, 1)) MB)"
    $collectionStart = (Get-CollectionInfo).CollectionStartUtc
    $referenceFileTime = 0L
    if ($collectionStart) { $referenceFileTime = $collectionStart.ToFileTimeUtc() }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $mftResult = [TimelineNtfs.MftParser]::Parse($File.FullName, $referenceFileTime, $MftDays)
    }
    catch {
        $failure = $_.Exception
        if ($failure.InnerException) { $failure = $failure.InnerException }
        Log-Warning "  Failed to parse `$MFT $($File.FullName): $($failure.Message)"
        return
    }
    $parseSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
    Log ("  Read $($mftResult.RecordsRead) record(s) of $($mftResult.RecordSize) bytes in $parseSeconds s: " +
        "$($mftResult.InUse) in use, $($mftResult.Deleted) deleted, $($mftResult.Extension) extension, $($mftResult.Unused) unused; " +
        "$($mftResult.ParseFailures) parse failure(s) ($($mftResult.BadSignature) bad signature, $($mftResult.FixupMismatch) fixup mismatch, " +
        "$($mftResult.BadAttributes) damaged attribute list).")

    if ($mftResult.HasWindow) {
        $referenceText = $mftResult.ReferenceUtc.ToString("yyyy-MM-dd HH:mm:ss")
        $anchor = "the collection start ($referenceText UTC)"
        if ($mftResult.ReferenceFromMft) { $anchor = "the newest `$MFT time ($referenceText UTC; collection start unknown)" }
        Log "  Window: times from $($mftResult.WindowStartUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC, $MftDays day(s) before $anchor (-MftDays 0 = all)."
    }
    elseif ($MftDays -gt 0) {
        Log "  No usable `$MFT time to anchor the -MftDays window -- all times added."
    }
    else {
        Log "  -MftDays 0: all `$MFT times added."
    }

    $before = $script:timelineEntries.Count
    $rawPath = $File.FullName
    $zoneAdded = 0
    foreach ($row in $mftResult.Rows) {
        $entryCount = $script:timelineEntries.Count
        Add-TimelineEntry -Timestamp $row.Time -Source "MFT" -EventType "FileAccess" `
            -Description $row.Description -User $row.User -Details $row.Details `
            -Artifact "FileSystem" -RawPath $rawPath
        if ($row.MarkOfTheWeb -and $script:timelineEntries.Count -gt $entryCount) { $zoneAdded++ }
    }
    $added = $script:timelineEntries.Count - $before
    $summary = "  Added $added row(s); $($mftResult.OutsideWindow) time(s) outside the window skipped"
    if ($mftResult.Rows.Count -gt $added) { $summary += "; $($mftResult.Rows.Count - $added) row(s) dropped by -StartDate/-EndDate or dated before 1980" }
    Log "$summary."
    if ($mftResult.TimestompRecords -gt 0) {
        Log "  $($mftResult.TimestompRecords) record(s) flagged [SI<FN] (possible timestomping; see Details): $($mftResult.TimestompRows) row(s), $($mftResult.KeptForTimestomp) of them outside the window."
    }
    if ($mftResult.ZoneStreams -gt 0) {
        $zoneSummary = @($mftResult.ZoneCounts.GetEnumerator() | ForEach-Object { "$($_.Value) $($_.Key)" }) -join ", "
        Log ("  Mark of the Web: $($mftResult.ZoneStreams) Zone.Identifier stream(s), $($mftResult.ZoneResident) resident (text read from the `$MFT), " +
            "$($mftResult.ZoneNonResident) non-resident (text not in the `$MFT; their rows say 'zone unknown').")
        if ($mftResult.ZoneRows -gt 0) {
            Log ("  Mark of the Web: $($mftResult.ZoneRows) row(s) ($zoneSummary): $($mftResult.ZoneExtracted) 'Extracted file', " +
                "$($mftResult.ZoneDeleted) with the record deleted, $($mftResult.ZoneFnTime) at FN Created (RowTime=FN.Created); " +
                "added regardless of -MftDays, $($mftResult.ZoneOutsideWindow) of them dated before its window.")
        }
        if ($mftResult.ZoneRows -gt $zoneAdded) {
            Log "  Mark of the Web: $($mftResult.ZoneRows - $zoneAdded) of these row(s) dropped by -StartDate/-EndDate."
        }
        if ($mftResult.ZoneFolders -gt 0) {
            Log "  Mark of the Web: $($mftResult.ZoneFolders) folder(s) with a Zone.Identifier stream skipped (rows are for files)."
        }
        if ($mftResult.ZoneNoTime -gt 0) {
            Log-Warning "  Mark of the Web: $($mftResult.ZoneNoTime) file(s) with a Zone.Identifier stream skipped: no SI or FN Created time from 1980 on."
        }
    }
    else {
        Log "  Mark of the Web: no Zone.Identifier streams in this `$MFT."
    }
    if ($mftResult.OrphanPaths -gt 0) {
        Log "  $($mftResult.OrphanPaths) record(s) with rows have a missing or reused parent folder (path starts with <orphan>)."
    }
    Log "  `$MFT done in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) s."
}

function Parse-FileSystem {
    Log "--- Parsing File System Metadata ---"

    # Raw $MFT from newer collectors (FileSystem\$MFT). -Force: a copy may keep
    # the Hidden/System attributes of the original. A mail attachment named
    # $MFT (in the Email\ attachment copies), or anything under Secrets\, is
    # not this system's MFT and is skipped.
    $mftFiles = @(Get-ChildItem -Path $InputPath -Filter '$MFT' -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq '$MFT' -and -not (Test-EmailAttachmentCopy (Get-RelativeCollectionPath $_.FullName)) -and -not (Test-SecretsPath $_.FullName) })
    if ($mftFiles.Count -gt 0) {
        foreach ($mftFile in $mftFiles) {
            Add-MftTimelineEntries -File $mftFile
        }
        Log "  File system parsing complete."
        Log ""
        return
    }

    $fsParsed = $false

    # Look for file_listing.csv or similar from triage collection
    $fileCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("file_listing.csv", "file_list.csv", "filesystem.csv", "files.csv")

    if ($fileCsvs.Count -gt 0) {
        foreach ($csv in $fileCsvs) {
            Log "  Parsing: $($csv.FullName)"
            try {
                $files = Import-Csv -Path $csv.FullName -ErrorAction Stop
                $count = 0
                $timeErrorCount = 0
                foreach ($f in $files) {
                    $path = if ($f.PSObject.Properties["FullName"]) { $f.FullName }
                            elseif ($f.PSObject.Properties["Path"]) { $f.Path }
                            elseif ($f.PSObject.Properties["FilePath"]) { $f.FilePath }
                            else { continue }

                    # Creation time
                    $creationFields = @("CreationTimeUtc", "CreationTime", "Created")
                    foreach ($field in $creationFields) {
                        if ($f.PSObject.Properties[$field] -and $f.$field) {
                            try {
                                $ts = [datetime]::Parse($f.$field)
                                Add-TimelineEntry -Timestamp $ts -Source "FileSystem" -EventType "FileAccess" `
                                    -Description "File created: $(Split-Path $path -Leaf)" `
                                    -Details "FullPath=$path" `
                                    -Artifact "FileSystem" -RawPath $csv.FullName
                                $fsParsed = $true
                                $count++
                                break
                            }
                            catch { $timeErrorCount++; $lastTimeError = $_.Exception.Message }
                        }
                    }

                    # Modification time
                    $modFields = @("LastWriteTimeUtc", "LastWriteTime", "Modified")
                    foreach ($field in $modFields) {
                        if ($f.PSObject.Properties[$field] -and $f.$field) {
                            try {
                                $ts = [datetime]::Parse($f.$field)
                                Add-TimelineEntry -Timestamp $ts -Source "FileSystem" -EventType "FileAccess" `
                                    -Description "File modified: $(Split-Path $path -Leaf)" `
                                    -Details "FullPath=$path" `
                                    -Artifact "FileSystem" -RawPath $csv.FullName
                                $fsParsed = $true
                                $count++
                                break
                            }
                            catch { $timeErrorCount++; $lastTimeError = $_.Exception.Message }
                        }
                    }

                    # Throttle to avoid massive timelines from full file listings
                    if ($count -ge 50000) {
                        Log-Warning "  File system entries capped at 50,000 to prevent excessive output."
                        break
                    }
                }
                if ($timeErrorCount -gt 0) {
                    Log-Warning "  $timeErrorCount time value(s) in $($csv.Name) could not be parsed and were skipped (last error: $lastTimeError)"
                }
            }
            catch {
                Log-Warning "  Failed to parse file listing CSV: $($_.Exception.Message)"
            }
        }
        if (-not $fsParsed) {
            Log-Warning "No usable times in the file listing CSV(s)."
        }
    }
    else {
        Log "  No `$MFT or file listing in this collection (`$MFT is collected by newer collector versions)."
    }
    Log "  File system parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 9. USN Journal Parser
# ----------------------------------------------------------
function Parse-UsnJournal {
    Log "--- Parsing USN Journal ---"

    $usnFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @('$UsnJrnl_$J.txt', 'UsnJrnl.txt', 'usn_journal.txt')

    if ($usnFiles.Count -eq 0) {
        Log-Warning "No USN Journal text file found. Skipping."
        Log ""
        return
    }

    # fsutil writes "Time stamp" in the collector host's local time zone and culture
    $collInfo = Get-CollectionInfo
    $usnCulture = $collInfo.CollectorCulture
    $usnTimeZone = $collInfo.CollectorTimeZone
    Log "  USN time stamps are collector-local time ($($usnTimeZone.Id)); converting to UTC."
    if ($MaxUsnEntries -gt 0) { Log "  Keeping the newest $MaxUsnEntries entries per journal file (-MaxUsnEntries, 0 = unlimited)." }

    # Leading fields of an fsutil "usn readjournal csv" line:
    # Usn,"File name",File name length,Reason #,"Reason","Time stamp",File attributes #,...
    $usnLineRegex = New-Object System.Text.RegularExpressions.Regex('^\d+,"(.*?)",\d+,0x[0-9A-Fa-f]+,"([^"]*)","([^"]*)"', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    foreach ($usnFile in $usnFiles) {
        Log "  Parsing: $($usnFile.FullName)"
        $total = 0
        $skipped = 0
        $unparsed = 0
        $outOfRange = 0
        $dropped = 0
        $reader = $null
        $timeCache = @{}
        # Ring buffer: once full, the oldest row is dropped for each new one
        $kept = New-Object 'System.Collections.Generic.Queue[object]'
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $reader = New-Object System.IO.StreamReader($usnFile.FullName)
            $headerFound = $false

            while ($null -ne ($line = $reader.ReadLine())) {
                if ($line.Length -lt 10) { continue }

                # Skip header lines (metadata and CSV header)
                if (-not $headerFound) {
                    if ($line -match '^Usn,') {
                        $headerFound = $true
                    }
                    continue
                }

                $m = $usnLineRegex.Match($line)
                if (-not $m.Success) { $unparsed++; continue }
                $total++

                # Skip pure "Close" or "Basic info change | Close" entries to reduce noise
                $reason = $m.Groups[2].Value
                if ($reason -eq "Close" -or $reason -eq "Basic info change | Close") {
                    $skipped++
                    continue
                }

                # Many rows share a time stamp, so cache the conversions
                $tsStr = $m.Groups[3].Value
                $ts = $timeCache[$tsStr]
                if ($null -eq $ts) {
                    $ts = [datetime]::MinValue
                    $local = ConvertFrom-LocalText -Text $tsStr -Culture $usnCulture
                    if ($null -ne $local) { $ts = Convert-LocalToUtc -Local $local -TimeZone $usnTimeZone }
                    $timeCache[$tsStr] = $ts
                }
                if ($ts -eq [datetime]::MinValue) { $unparsed++; continue }

                # Apply the date filter here so the ring buffer keeps rows that will be used
                if (($StartDate -and $ts -lt $StartDate.ToUniversalTime()) -or ($EndDate -and $ts -gt $EndDate.ToUniversalTime())) {
                    $outOfRange++
                    continue
                }

                if ($MaxUsnEntries -gt 0 -and $kept.Count -ge $MaxUsnEntries) {
                    [void]$kept.Dequeue()
                    $dropped++
                }
                $kept.Enqueue(@($ts, $m.Groups[1].Value, $reason))
            }
        }
        catch {
            Log-Warning "  Failed to read USN Journal: $($_.Exception.Message)"
        }
        finally {
            if ($reader) { $reader.Dispose() }
        }

        $readSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
        $minTs = $null
        $maxTs = $null
        foreach ($item in $kept) {
            $ts = $item[0]
            $fileName = $item[1]
            $reason = $item[2]
            if ($null -eq $minTs -or $ts -lt $minTs) { $minTs = $ts }
            if ($null -eq $maxTs -or $ts -gt $maxTs) { $maxTs = $ts }

            $desc = "USN: $fileName"
            if ($reason -match "File delete|Rename: old name") { $desc = "USN deleted: $fileName" }
            elseif ($reason -match "Rename: new name") { $desc = "USN renamed to: $fileName" }
            elseif ($reason -match "File create") { $desc = "USN created: $fileName" }
            elseif ($reason -match "Data extend|Data overwrite|Data truncation") { $desc = "USN modified: $fileName" }
            elseif ($reason -match "Security change") { $desc = "USN security changed: $fileName" }
            elseif ($reason -match "Basic info change") { $desc = "USN attr changed: $fileName" }

            Add-TimelineEntry -Timestamp $ts -Source "UsnJournal" -EventType "FileAccess" `
                -Description $desc -Details "Reason=$reason" `
                -Artifact "UsnJournal" -RawPath $usnFile.FullName
        }

        Log "  Read $total USN row(s) in $readSeconds s (skipped $skipped noisy close events, $unparsed unparsed line(s), $outOfRange outside the date filter)."
        if ($kept.Count -gt 0) {
            Log "  Kept $($kept.Count) USN entries from $($minTs.ToString('yyyy-MM-dd HH:mm:ss')) to $($maxTs.ToString('yyyy-MM-dd HH:mm:ss')) UTC."
        }
        if ($dropped -gt 0) {
            Log-Warning "  Dropped the $dropped oldest USN entries (limit $MaxUsnEntries). Use -MaxUsnEntries 0 to keep all."
        }
        $kept.Clear()
    }
    Log "  USN Journal parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 10. Network Artifacts Parser
# ----------------------------------------------------------

# Parse text written by Format-Table (through Out-File) into objects whose
# property names are the column headers. Column edges come from the dashed
# separator line plus the gutter that is blank on every line, so values with
# spaces and right-aligned numbers stay whole. Headers split by -Wrap are
# rejoined; a data line with an empty first column is a -Wrap continuation
# and is appended to the row above. A table ends at the next blank line.
function ConvertFrom-FormatTableText {
    param([string[]]$Lines)
    $objects = New-Object System.Collections.Generic.List[object]
    if (-not $Lines) { return $objects }
    $i = 1
    while ($i -lt $Lines.Count) {
        if ($Lines[$i] -notmatch '^\s*-+(\s+-+)*\s*$' -or -not $Lines[$i - 1].Trim()) { $i++; continue }
        $sep = $Lines[$i]
        $hStart = $i - 1
        while ($hStart -gt 0 -and $Lines[$hStart - 1].Trim()) { $hStart-- }
        $dEnd = $i + 1
        while ($dEnd -lt $Lines.Count -and $Lines[$dEnd].Trim()) { $dEnd++ }
        $headerLines = @($Lines[$hStart..($i - 1)])
        $dataLines = @()
        if ($dEnd -gt $i + 1) { $dataLines = @($Lines[($i + 1)..($dEnd - 1)]) }
        $allLines = $headerLines + $dataLines

        # Column c starts after the last position between dash runs c-1 and c
        # that is blank on every header and data line
        $runs = [regex]::Matches($sep, '-+')
        $starts = @(0)
        for ($c = 1; $c -lt $runs.Count; $c++) {
            $start = $runs[$c].Index
            for ($p = $runs[$c].Index - 1; $p -ge ($runs[$c - 1].Index + $runs[$c - 1].Length); $p--) {
                $blank = $true
                foreach ($l in $allLines) {
                    if ($p -lt $l.Length -and $l[$p] -ne ' ') { $blank = $false; break }
                }
                if ($blank) { $start = $p + 1; break }
            }
            $starts += $start
        }
        $maxLen = ($allLines | ForEach-Object { $_.TrimEnd().Length } | Measure-Object -Maximum).Maximum
        $widths = @()
        for ($c = 0; $c -lt $starts.Count; $c++) {
            if ($c + 1 -lt $starts.Count) { $widths += ($starts[$c + 1] - 1 - $starts[$c]) } else { $widths += ($maxLen - $starts[$c]) }
        }

        # Raw cells of a line, a new empty row, and appending a line's cells to
        # a row (wrapped pieces are joined with a space unless the previous
        # piece filled the column, i.e. a word was broken)
        $cellsOf = {
            param([string]$l)
            $cells = @()
            for ($c = 0; $c -lt $starts.Count; $c++) {
                $from = $starts[$c]
                $to = if ($c + 1 -lt $starts.Count) { [Math]::Min($starts[$c + 1], $l.Length) } else { $l.Length }
                if ($from -ge $to) { $cells += "" } else { $cells += $l.Substring($from, $to - $from) }
            }
            , $cells
        }
        $newRow = { [PSCustomObject]@{ Values = [string[]](@("") * $starts.Count); LastLen = [int[]](@(0) * $starts.Count) } }
        $appendCells = {
            param($row, $cells)
            for ($c = 0; $c -lt $cells.Count; $c++) {
                $piece = $cells[$c].Trim()
                if (-not $piece) { continue }
                if ($row.Values[$c] -and $row.LastLen[$c] -lt $widths[$c]) { $row.Values[$c] += " " }
                $row.Values[$c] += $piece
                $row.LastLen[$c] = $cells[$c].TrimEnd().Length
            }
        }

        # Header names (rejoined when -Wrap split them over several lines)
        $header = & $newRow
        foreach ($l in $headerLines) { & $appendCells $header (& $cellsOf $l) }
        $names = @()
        for ($c = 0; $c -lt $starts.Count; $c++) {
            $name = $header.Values[$c]
            if (-not $name -or $names -contains $name) { $name = "Column$($c + 1)" }
            $names += $name
        }

        # Data rows; a line with an empty first column continues the row above
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($l in $dataLines) {
            $cells = & $cellsOf $l
            if ($rows.Count -eq 0 -or $cells[0].Trim()) { $rows.Add((& $newRow)) }
            & $appendCells $rows[$rows.Count - 1] $cells
        }
        foreach ($row in $rows) {
            $obj = [ordered]@{}
            for ($c = 0; $c -lt $names.Count; $c++) { $obj[$names[$c]] = $row.Values[$c] }
            $objects.Add([PSCustomObject]$obj)
        }
        $i = $dEnd
    }
    return $objects
}

# ----------------------------------------------------------
# Email artifacts (the triage collector's Email category, Email\<user>\)
# ----------------------------------------------------------
# Listing CSVs the collector writes per user. Same columns in all: User,
# Program, Store, Profile, Path, RelativePath, SizeBytes, CreatedUtc,
# ModifiedUtc, AccessedUtc (UTC, ISO 8601), Status (Copied, Listed or
# "Skipped: <reason>") and CollectedAs (path of the copy in the collection).
$script:EmailListingFiles = @("outlook_temp_files.csv", "olk_files.csv", "outlook_data_files.csv", "thunderbird_mail_files.csv", "windows_mail_files.csv")
# Newest messages added per Thunderbird search index
$script:EmailMaxMessages = 20000
# Description of an attachment row (and of its "modified" row) per program,
# and how the file got there (Details: Origin). Classic Outlook saves an
# attachment to its temp folder to open it; the new Outlook's Attachments\
# also keeps attachments that were sent or received, and is not cleaned up.
$script:EmailAttachmentLabels = @{
    "Classic Outlook" = "Outlook attachment in temp folder"
    "New Outlook"     = "New Outlook attachment file"
    "Windows Mail"    = "Windows Mail attachment in mail store"
}
$script:EmailAttachmentOrigins = @{
    "Classic Outlook" = "Opened from a message"
    "New Outlook"     = "Opened, sent or received (not proof of opening)"
    "Windows Mail"    = "Stored with a message (not proof of opening)"
}
# Thunderbird socketType and authMethod values (nsMsgSocketType, nsMsgAuthMethod)
$script:ThunderbirdSocketTypes = @{ "0" = "None"; "1" = "STARTTLS if available"; "2" = "STARTTLS"; "3" = "SSL/TLS" }
$script:ThunderbirdAuthMethods = @{
    "1" = "None"; "2" = "Old"; "3" = "Password"; "4" = "EncryptedPassword"; "5" = "Kerberos"
    "6" = "NTLM"; "7" = "TLSCertificate"; "8" = "AnySecure"; "9" = "Any"; "10" = "OAuth2"
}

# Email\ rows of collection_manifest.csv by RelativePath: SHA256, SourcePath,
# Size and the original file's Created/Modified/Accessed times (UTC). A copy
# taken from the shadow copy is recorded as "(shadow)<path below the target
# root>"; its SourcePath is given the target root again ("C:\Users\...").
# Read through the shared reader (Get-CollectionManifest): the manifest
# nearest to -InputPath, whose folder is the collection root that
# Get-RelativeCollectionPath looks the RelativePath keys up against.
function Get-EmailManifestRows {
    $rows = @{}
    $manifestRows = @((Get-CollectionManifest).Rows)
    if ($manifestRows.Count -eq 0) { return $rows }
    $targetRoot = (Get-CollectionInfo).TargetRoot
    try {
        foreach ($row in $manifestRows) {
            if (-not $row.PSObject.Properties["RelativePath"] -or $row.RelativePath -notlike "Email\*") { continue }
            $sourcePath = $row.SourcePath
            if ($sourcePath -like "(shadow)*") {
                $sourcePath = $sourcePath.Substring(8).TrimStart('\')
                if ($targetRoot) { $sourcePath = $targetRoot.TrimEnd('\') + '\' + $sourcePath }
            }
            $rows[$row.RelativePath] = [PSCustomObject]@{
                SHA256     = $row.SHA256
                SourcePath = $sourcePath
                Size       = $row.SizeBytes
                Created    = ConvertFrom-UtcText (Get-ArtifactRowValue $row @("SourceCreatedUtc"))
                Modified   = ConvertFrom-UtcText (Get-ArtifactRowValue $row @("SourceModifiedUtc"))
                Accessed   = ConvertFrom-UtcText (Get-ArtifactRowValue $row @("SourceAccessedUtc"))
            }
        }
    }
    catch { Log-Warning "  Could not read the Email\ rows of the collection manifest: $($_.Exception.Message)" }
    return $rows
}

# Text cut to -MaxLength characters (long recipient lists)
function Limit-EmailText {
    param([string]$Text, [int]$MaxLength = 1000)
    if ($Text.Length -le $MaxLength) { return $Text }
    return $Text.Substring(0, $MaxLength) + "... (cut, $($Text.Length) characters)"
}

# A row at a file's created time ("<CreatedText>: <Name>") and, when at least
# a second later, one at its modified time ("<ModifiedText>: <Name>").
# FileAccess rows. Returns the number of rows added.
function Add-EmailFileTimeRows {
    param(
        [string]$Source,
        [string]$CreatedText,
        [string]$ModifiedText,
        [string]$Name,
        $Created,
        $Modified,
        [string]$User,
        [System.Collections.IDictionary]$Details,
        [string]$RawPath
    )
    $detailText = Format-ArtifactDetails $Details
    $rows = @(, @($Created, "${CreatedText}: $Name"))
    if ($Modified -and (-not $Created -or ($Modified - $Created).TotalSeconds -ge 1)) {
        $rows += , @($Modified, "${ModifiedText}: $Name")
    }
    $count = 0
    foreach ($row in $rows) {
        if ($null -eq $row[0]) { continue }
        Add-TimelineEntry -Timestamp $row[0] -Source $Source -EventType "FileAccess" `
            -Description $row[1] `
            -User $User -Details $detailText `
            -Artifact "Email" -RawPath $RawPath
        $count++
    }
    return $count
}

# Rows for one attachment in a mail client's temp folder or store (a listing
# row, or a manifest row when the listing is missing): when it was saved
# there -- Outlook saves an attachment to its temp folder when it is opened --
# and when it was modified, if later (edited and saved). Times and SHA256 of
# a copied file come from the manifest. Returns the number of rows added.
function Add-EmailAttachmentRows {
    param(
        [string]$Program,
        [string]$Path,
        [string]$Size,
        $Created,
        $Modified,
        $Accessed,
        [string]$Status,
        [object]$Copy,
        [string]$User,
        [string]$RawPath
    )
    $sha256 = ""
    if ($Copy) {
        if ($Copy.Created) { $Created = $Copy.Created }
        if ($Copy.Modified) { $Modified = $Copy.Modified }
        if ($Copy.Accessed) { $Accessed = $Copy.Accessed }
        $sha256 = $Copy.SHA256
    }
    $label = $script:EmailAttachmentLabels[$Program]
    if (-not $label) { $label = "$Program attachment file" }
    $details = [ordered]@{
        Program     = $Program
        Origin      = $script:EmailAttachmentOrigins[$Program]
        Folder      = [System.IO.Path]::GetDirectoryName($Path)
        Size        = $Size
        SHA256      = $sha256
        Collected   = $(if ($Status -eq "Copied") { "Yes" } else { "No" })
        Status      = $(if ($Status -ne "Copied") { $Status } else { "" })
        CreatedUtc  = Format-UtcDetailTime $Created
        ModifiedUtc = Format-UtcDetailTime $Modified
        AccessedUtc = Format-UtcDetailTime $Accessed
    }
    return Add-EmailFileTimeRows -Source "Email-Attachments" -CreatedText $label -ModifiedText "$label modified" `
        -Name ([System.IO.Path]::GetFileName($Path)) -Created $Created -Modified $Modified -User $User -Details $details -RawPath $RawPath
}

# Thunderbird mail folders of one listing (Mail\<account>\..., ImapMail\
# <account>\...): an mbox file is a folder when it has a .msf summary next
# to it or no extension (maildir message files in cur\, new\, tmp\ are left
# out). Rows at the folder file's created and last modified times; the
# account's message filter rules (msgFilterRules.dat) likewise. Returns the
# number of rows added.
function Add-ThunderbirdMailFolderRows {
    param([object[]]$Rows, [string]$CsvUser, [string]$RawPath)
    $known = @{}
    foreach ($r in $Rows) { $known["$($r.Profile)|$($r.RelativePath)"] = $true }
    $count = 0
    foreach ($r in $Rows) {
        $parts = @($r.RelativePath -split '\\')
        if ($parts.Count -lt 3 -or @("Mail", "ImapMail") -notcontains $parts[0]) { continue }
        $name = $parts[$parts.Count - 1]
        $account = $parts[1]
        $user = if ($r.User) { $r.User } else { $CsvUser }
        $details = [ordered]@{
            Program     = "Thunderbird"
            Profile     = $r.Profile
            Account     = $account
            Storage     = $parts[0]
            Folder      = ""
            Path        = $r.Path
            Size        = $r.SizeBytes
            CreatedUtc  = Format-UtcDetailTime (ConvertFrom-UtcText $r.CreatedUtc)
            ModifiedUtc = Format-UtcDetailTime (ConvertFrom-UtcText $r.ModifiedUtc)
        }
        if ($name -eq "msgFilterRules.dat" -and $parts.Count -eq 3) {
            $count += Add-EmailFileTimeRows -Source "Email-MailFolders" -CreatedText "Thunderbird message filter rules created" `
                -ModifiedText "Thunderbird message filter rules last modified" -Name $account `
                -Created (ConvertFrom-UtcText $r.CreatedUtc) -Modified (ConvertFrom-UtcText $r.ModifiedUtc) -User $user -Details $details -RawPath $RawPath
            continue
        }
        $inMaildir = $parts.Count -ge 4 -and @($parts[2..($parts.Count - 2)] | Where-Object { @("cur", "new", "tmp") -contains $_ }).Count -gt 0
        $isFolder = $known.ContainsKey("$($r.Profile)|$($r.RelativePath).msf") -or ([System.IO.Path]::GetExtension($name) -eq "" -and -not $inMaildir)
        if (-not $isFolder) { continue }
        # INBOX.sbd\Work -> INBOX/Work
        $folder = (@($parts[2..($parts.Count - 1)]) | ForEach-Object { $_ -replace '\.sbd$', '' }) -join "/"
        $details["Folder"] = $folder
        $count += Add-EmailFileTimeRows -Source "Email-MailFolders" -CreatedText "Thunderbird mail folder created" `
            -ModifiedText "Thunderbird mail folder last modified" -Name "$account/$folder" `
            -Created (ConvertFrom-UtcText $r.CreatedUtc) -Modified (ConvertFrom-UtcText $r.ModifiedUtc) -User $user -Details $details -RawPath $RawPath
    }
    return $count
}

# Rows from one email listing CSV: attachments (classic Outlook temp folder,
# new Outlook Attachments\, Windows Mail store attachments), data files
# (OST/PST, Windows Mail databases) and Thunderbird mail folders. Other
# listed files (the new Outlook's WebView data, ...) get no rows. Copies
# with a listing row are recorded in -ListedCopies. Returns the row count.
function Add-EmailListingRows {
    param([System.IO.FileInfo]$File, [hashtable]$ManifestRows, [hashtable]$ListedCopies)
    $rows = @(Import-Csv -LiteralPath $File.FullName -ErrorAction Stop)
    $csvUser = Get-CollectionUser $File.FullName
    $count = 0
    $mailRows = @()
    foreach ($r in $rows) {
        $user = if ($r.User) { $r.User } else { $csvUser }
        $isAttachment = $r.Store -eq "SecureTemp" -or ($r.Store -eq "Olk" -and $r.RelativePath -like "Attachments\*") -or
            ($r.Store -eq "WindowsMail" -and $r.RelativePath -like "*\Attachments\*")
        if ($isAttachment) {
            $copy = $null
            $rawPath = $File.FullName
            if ($r.Status -eq "Copied" -and $r.CollectedAs) {
                $ListedCopies[$r.CollectedAs] = $true
                $copy = $ManifestRows[$r.CollectedAs]
                # Email\<user>\<program>\<listing>.csv: the collection root is three levels up
                $rawPath = Join-Path $File.Directory.Parent.Parent.Parent.FullName $r.CollectedAs
            }
            $count += Add-EmailAttachmentRows -Program $r.Program -Path $r.Path -Size $r.SizeBytes `
                -Created (ConvertFrom-UtcText $r.CreatedUtc) -Modified (ConvertFrom-UtcText $r.ModifiedUtc) -Accessed (ConvertFrom-UtcText $r.AccessedUtc) `
                -Status $r.Status -Copy $copy -User $user -RawPath $rawPath
        }
        elseif ($r.Store -eq "DataFile" -or ($r.Store -eq "WindowsMail" -and @(".hxd", ".vol") -contains [System.IO.Path]::GetExtension($r.Path))) {
            if ($r.Store -eq "DataFile") {
                $texts = @("Outlook data file created", "Outlook data file last modified")
                $name = [System.IO.Path]::GetFileName($r.Path)
            }
            else {
                $texts = @("Windows Mail store file created", "Windows Mail store file last modified")
                $name = $r.RelativePath
            }
            $details = [ordered]@{
                Program     = $r.Program
                Type        = [System.IO.Path]::GetExtension($r.Path).TrimStart('.').ToUpperInvariant()
                Path        = $r.Path
                Size        = $r.SizeBytes
                CreatedUtc  = Format-UtcDetailTime (ConvertFrom-UtcText $r.CreatedUtc)
                ModifiedUtc = Format-UtcDetailTime (ConvertFrom-UtcText $r.ModifiedUtc)
                AccessedUtc = Format-UtcDetailTime (ConvertFrom-UtcText $r.AccessedUtc)
            }
            $count += Add-EmailFileTimeRows -Source "Email-DataFiles" -CreatedText $texts[0] -ModifiedText $texts[1] -Name $name `
                -Created (ConvertFrom-UtcText $r.CreatedUtc) -Modified (ConvertFrom-UtcText $r.ModifiedUtc) -User $user -Details $details -RawPath $File.FullName
        }
        elseif ($r.Store -eq "ThunderbirdMail") {
            $mailRows += $r
        }
    }
    if ($mailRows.Count -gt 0) {
        $count += Add-ThunderbirdMailFolderRows -Rows $mailRows -CsvUser $csvUser -RawPath $File.FullName
    }
    return $count
}

# New Outlook UserSettings.json: one Snapshot row per signed-in account
# (Identities.IdentityMap: account -> identity id). Nothing else in the file
# is read. Returns the number of rows added.
function Add-NewOutlookAccountRows {
    param([System.IO.FileInfo]$File, [hashtable]$ManifestRows)
    $text = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($text)) { return 0 }
    # The JSON parser's error is not passed on (Windows PowerShell quotes the text)
    try { $json = $text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "not valid JSON (damaged or incomplete file)" }
    if (-not $json -or -not $json.PSObject.Properties["Identities"] -or -not $json.Identities.PSObject.Properties["IdentityMap"]) { return 0 }
    $snapshotTs = Get-SnapshotTimeUtc -File $File
    if (-not $snapshotTs) { return 0 }
    $settings = $ManifestRows[(Get-RelativeCollectionPath $File.FullName)]
    $user = Get-CollectionUser $File.FullName
    $count = 0
    foreach ($identity in $json.Identities.IdentityMap.PSObject.Properties) {
        if (-not $identity.Name) { continue }
        Add-TimelineEntry -Timestamp $snapshotTs -Source "Email-Accounts" -EventType "Snapshot" `
            -Description "New Outlook account: $($identity.Name)" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                Program             = "New Outlook"
                Account             = $identity.Name
                IdentityId          = "$($identity.Value)"
                SettingsModifiedUtc = $(if ($settings) { Format-UtcDetailTime $settings.Modified } else { "" })
            })) `
            -Artifact "Email" -RawPath $File.FullName
        $count++
    }
    return $count
}

# Thunderbird prefs.js: user_pref("name", value); lines as a hashtable of
# name -> value text (JavaScript string escapes decoded)
function Read-ThunderbirdPrefs {
    param([string]$Path)
    $prefs = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        if ($line -notmatch '^\s*user_pref\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*(.*?)\s*\)\s*;\s*$') { continue }
        $name = $Matches[1]
        $value = $Matches[2]
        if ($value -match '^"((?:[^"\\]|\\.)*)"$') {
            $value = [regex]::Replace($Matches[1], '\\(u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|.)', {
                param($m)
                $code = $m.Groups[1].Value
                if ($code.Length -gt 1) { return [string][char][Convert]::ToInt32($code.Substring(1), 16) }
                switch -CaseSensitive ($code) { "n" { return "`n" } "t" { return "`t" } "r" { return "`r" } default { return $code } }
            })
        }
        $prefs[$name] = $value
    }
    return $prefs
}

# Thunderbird prefs.js: one Snapshot row per mail account (server type, host,
# user name, connection security, identity email, outgoing server). Only
# these settings are read -- never a password or token. Returns the number
# of rows added.
function Add-ThunderbirdAccountRows {
    param([System.IO.FileInfo]$File, [hashtable]$ManifestRows)
    $prefs = Read-ThunderbirdPrefs -Path $File.FullName
    $snapshotTs = Get-SnapshotTimeUtc -File $File
    if (-not $snapshotTs) { return 0 }
    $prefsCopy = $ManifestRows[(Get-RelativeCollectionPath $File.FullName)]
    $user = Get-CollectionUser $File.FullName
    $profileName = $File.Directory.Name
    # Accounts in the account manager's order; without that list, every server
    $accounts = @("$($prefs['mail.accountmanager.accounts'])" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $servers = @(foreach ($account in $accounts) { [PSCustomObject]@{ Account = $account; Server = "$($prefs["mail.account.$account.server"])" } })
    if ($servers.Count -eq 0) {
        $servers = @($prefs.Keys | Where-Object { $_ -match '^mail\.server\.([^.]+)\.type$' } | Sort-Object |
            ForEach-Object { [PSCustomObject]@{ Account = ""; Server = ($_ -replace '^mail\.server\.([^.]+)\.type$', '$1') } })
    }
    $count = 0
    foreach ($entry in $servers) {
        $server = $entry.Server
        if (-not $server) { continue }
        $serverType = "$($prefs["mail.server.$server.type"])"
        # "none" is Local Folders, not an account
        if (-not $serverType -or $serverType -eq "none") { continue }
        $serverHost = "$($prefs["mail.server.$server.realhostname"])"
        if (-not $serverHost) { $serverHost = "$($prefs["mail.server.$server.hostname"])" }
        $userName = "$($prefs["mail.server.$server.realuserName"])"
        if (-not $userName) { $userName = "$($prefs["mail.server.$server.userName"])" }
        $emails = @()
        $smtpHosts = @()
        $smtpUsers = @()
        if ($entry.Account) {
            foreach ($identity in @("$($prefs["mail.account.$($entry.Account).identities"])" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $email = "$($prefs["mail.identity.$identity.useremail"])"
                if ($email) { $emails += $email }
                $smtp = "$($prefs["mail.identity.$identity.smtpServer"])"
                if (-not $smtp) { $smtp = "$($prefs['mail.smtp.defaultserver'])" }
                if ($smtp) {
                    $smtpHost = "$($prefs["mail.smtpserver.$smtp.hostname"])"
                    $smtpUser = "$($prefs["mail.smtpserver.$smtp.username"])"
                    if ($smtpHost -and $smtpHosts -notcontains $smtpHost) { $smtpHosts += $smtpHost }
                    if ($smtpUser -and $smtpUsers -notcontains $smtpUser) { $smtpUsers += $smtpUser }
                }
            }
        }
        $label = if ($emails.Count -gt 0) { $emails[0] } elseif ($userName) { $userName } else { $serverHost }
        $socketType = "$($prefs["mail.server.$server.socketType"])"
        $authMethod = "$($prefs["mail.server.$server.authMethod"])"
        Add-TimelineEntry -Timestamp $snapshotTs -Source "Email-Accounts" -EventType "Snapshot" `
            -Description "Thunderbird account: $label ($($serverType.ToUpperInvariant()) $serverHost)" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                Program          = "Thunderbird"
                Profile          = $profileName
                AccountId        = $entry.Account
                ServerType       = $serverType
                Host             = $serverHost
                Port             = $prefs["mail.server.$server.port"]
                UserName         = $userName
                Security         = $(if ($socketType) { Get-AntiVirusCodeName -Names $script:ThunderbirdSocketTypes -Code $socketType } else { "" })
                AuthMethod       = $(if ($authMethod) { Get-AntiVirusCodeName -Names $script:ThunderbirdAuthMethods -Code $authMethod } else { "" })
                Email            = $emails -join ", "
                SmtpHost         = $smtpHosts -join ", "
                SmtpUser         = $smtpUsers -join ", "
                Directory        = ("$($prefs["mail.server.$server.directory-rel"])" -replace '^\[ProfD\]', '')
                PrefsModifiedUtc = $(if ($prefsCopy) { Format-UtcDetailTime $prefsCopy.Modified } else { "" })
            })) `
            -Artifact "Email" -RawPath $File.FullName
        $count++
    }
    return $count
}

# $true if sqlite3.exe has the JSON functions (built in since 3.38)
function Test-Sqlite3Json {
    param([string]$Sqlite3Exe)
    try {
        $output = & $Sqlite3Exe ":memory:" "SELECT json_valid('[1]');" 2>&1
        return ($LASTEXITCODE -eq 0 -and "$output".Trim() -eq "1")
    }
    catch {
        Write-Verbose "sqlite3 JSON check failed: $($_.Exception.Message)"
        return $false
    }
}

# SQL for one message's addresses of a gloda attribute ("from", "to", "cc",
# "bcc"), as "Name <address>; ..." text. Thunderbird keeps them in the
# message's jsonAttributes ({"<attribute id>": identity id or [ids]}), with
# the attribute ids in attributeDefinitions and the addresses in identities
# (display name: the identity's contact).
function Get-GlodaAddressSql {
    param([string]$Attribute, [bool]$HasContacts)
    $nameSql = "i.value"
    $contactJoin = ""
    if ($HasContacts) {
        $nameSql = "CASE WHEN coalesce(c.name, '') IN ('', i.value) THEN i.value ELSE c.name || ' <' || i.value || '>' END"
        $contactJoin = " LEFT JOIN contacts c ON c.id = i.contactID"
    }
    $json = "CASE WHEN json_valid(m.jsonAttributes) THEN m.jsonAttributes ELSE '{}' END"
    $list = "(SELECT group_concat($nameSql, '; ') FROM json_each($json) j" +
            " JOIN json_each(CASE WHEN j.type = 'array' THEN j.value ELSE json_array(j.value) END) v" +
            " JOIN identities i ON i.id = v.value$contactJoin" +
            " WHERE j.key IN (SELECT CAST(id AS TEXT) FROM attributeDefinitions WHERE name = '$Attribute' AND extensionName = 'built-in'))"
    return "replace(replace(coalesce($list, ''), char(13), ' '), char(10), ' ')"
}

# Thunderbird global-messages-db.sqlite (the "gloda" search index): one row
# per indexed message at its Date header (PRTime, the sender's clock), newest
# $script:EmailMaxMessages. From, To, Cc and Bcc are the message's addresses
# as gloda stored them (jsonAttributes -> identities); subject and
# attachment names come from the full-text table's content
# (messagesText_content), with the folder. The message text (the body
# column) is never selected. Only when a message has no stored addresses are
# the full-text author and recipients columns used, as AuthorText and
# RecipientsText: they are not the headers (recipients is the To header only,
# and Thunderbird appends address book names, or "undefined", to both).
# Returns the number of rows added.
function Add-ThunderbirdMessageRows {
    param([string]$Sqlite3Exe, [System.IO.FileInfo]$File)
    $schema = Get-Sqlite3TableColumns -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName `
        -Tables @("messages", "messagesText_content", "folderLocations", "attributeDefinitions", "identities", "contacts")
    $m = $schema["messages"]
    if (-not $m -or $m -notcontains "date") { return 0 }
    $t = $schema["messagesText_content"]
    $f = $schema["folderLocations"]
    # Text columns are c<n><name> (c0body, c1subject, ...); never add the body
    $textSql = @()
    foreach ($name in @("subject", "author", "recipients", "attachmentNames")) {
        $column = @($t | Where-Object { $_ -match "^c\d+$name$" }) | Select-Object -First 1
        if (-not $column) { $textSql += "''" }
        elseif ($name -eq "attachmentNames") { $textSql += "replace(replace(coalesce(t.$column, ''), char(13), ''), char(10), '; ')" }
        else { $textSql += (Get-SqliteColumnSql -Columns $t -Alias "t" -Names $column) }
    }
    $joins = ""
    if ($t -and $t -contains "docid") { $joins += " LEFT JOIN messagesText_content t ON t.docid = m.id" }
    else { $textSql = @("''", "''", "''", "''") }
    $folderSql = @("''", "''")
    if ($f -and $m -contains "folderID") {
        $joins += " LEFT JOIN folderLocations f ON f.id = m.folderID"
        $folderSql = @(Get-SqliteColumnSql -Columns $f -Alias "f" -Names @("name", "folderURI"))
    }
    $addressSql = @("''", "''", "''", "''")
    $attributeColumns = $schema["attributeDefinitions"]
    $identityColumns = $schema["identities"]
    if ($m -contains "jsonAttributes" -and $attributeColumns -contains "extensionName" -and $identityColumns -contains "contactID" -and
        (Test-Sqlite3Json -Sqlite3Exe $Sqlite3Exe)) {
        $hasContacts = [bool]($schema["contacts"] -and $schema["contacts"] -contains "name")
        $addressSql = @(foreach ($attribute in @("from", "to", "cc", "bcc")) { Get-GlodaAddressSql -Attribute $attribute -HasContacts $hasContacts })
    }
    else { Log "    No stored addresses (older index, or sqlite3 without JSON functions): the full-text author and recipients are used." }
    $numbers = @(Get-SqliteColumnSql -Columns $m -Alias "m" -Number -Names @("date", "deleted"))
    $messageId = @(Get-SqliteColumnSql -Columns $m -Alias "m" -Names @("headerMessageID"))
    $query = "SELECT (SELECT COUNT(*) FROM messages WHERE date > 0), " + (($numbers + $messageId + $folderSql + $textSql + $addressSql) -join ", ") +
             " FROM messages m$joins WHERE m.date > 0 ORDER BY m.date DESC LIMIT $($script:EmailMaxMessages);"
    $rows = @(Invoke-Sqlite3Query -Sqlite3Exe $Sqlite3Exe -DbPath $File.FullName -Query $query)

    $user = Get-CollectionUser $File.FullName
    $profileName = $File.Directory.Name
    $total = 0
    $count = 0
    $header = @("Total", "Date", "Deleted", "MessageId", "Folder", "FolderUri", "Subject", "AuthorText", "RecipientsText", "Attachments", "From", "To", "Cc", "Bcc")
    foreach ($r in ($rows | ConvertFrom-Csv -Header $header)) {
        if ($total -eq 0) { [void][int]::TryParse([string]$r.Total, [ref]$total) }
        $ts = ConvertFrom-UnixTime $r.Date -Unit Microseconds
        if ($null -eq $ts) { continue }
        $subject = if ($r.Subject) { $r.Subject } else { "(no subject)" }
        # Full-text author / recipients only without stored addresses, with
        # the "undefined" Thunderbird appends for names not in the address book removed
        $authorText = if (-not $r.From) { $r.AuthorText -replace '(\s+undefined)+\s*$', '' } else { "" }
        $recipientsText = if (-not ($r.To -or $r.Cc -or $r.Bcc)) { $r.RecipientsText -replace '(\s+undefined)+\s*$', '' } else { "" }
        Add-TimelineEntry -Timestamp $ts -Source "Email-Messages" -EventType "NetworkConnection" `
            -Description "Email (Thunderbird): $subject" `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                Program        = "Thunderbird"
                From           = $r.From
                To             = Limit-EmailText $r.To
                Cc             = Limit-EmailText $r.Cc
                Bcc            = Limit-EmailText $r.Bcc
                AuthorText     = $authorText
                RecipientsText = Limit-EmailText $recipientsText
                Attachments    = Limit-EmailText $r.Attachments
                Folder         = $r.Folder
                FolderURI      = $r.FolderUri
                MessageID      = $r.MessageId
                Deleted        = $(if ($r.Deleted -ne "0") { "Yes" } else { "" })
                TimeSource     = "Date header (sender clock)"
                Profile        = $profileName
            })) `
            -Artifact "Email" -RawPath $File.FullName
        $count++
    }
    if ($total -gt $script:EmailMaxMessages) {
        Log-Warning "    $total messages in the index; only the newest $($script:EmailMaxMessages) were added (cap)."
    }
    return $count
}

function Parse-Email {
    Log "--- Parsing Email Artifacts ---"

    $listingFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames $script:EmailListingFiles | Where-Object { -not $_.PSIsContainer })
    $settingsFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("UserSettings.json") |
        Where-Object { -not $_.PSIsContainer -and $_.Directory.Name -eq "NewOutlook" })
    $prefsFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("prefs.js") |
        Where-Object { -not $_.PSIsContainer -and $_.Directory.Parent -and $_.Directory.Parent.Name -eq "Thunderbird" })
    $glodaFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("global-messages-db.sqlite") |
        Where-Object { -not $_.PSIsContainer -and (Test-FileSignature -Path $_.FullName -Signature "SQLite format 3") })
    $manifestRows = Get-EmailManifestRows
    # Copied attachments (in the manifest) whose listing CSV is missing
    $attachmentCopies = @($manifestRows.Keys | Where-Object { Test-EmailAttachmentCopy $_ })
    if ($listingFiles.Count + $settingsFiles.Count + $prefsFiles.Count + $glodaFiles.Count + $attachmentCopies.Count -eq 0) {
        Log "  No email artifacts in the collection (the collector's Email category)."
        Log ""
        return
    }

    $emailRows = 0
    # Listings: attachments, data files, Thunderbird mail folders
    $listedCopies = @{}
    foreach ($csv in $listingFiles) {
        Log "  Parsing: $($csv.Name) ($(Get-CollectionUser $csv.FullName))"
        try {
            $added = Add-EmailListingRows -File $csv -ManifestRows $manifestRows -ListedCopies $listedCopies
            Log "    $added row(s) added."
            $emailRows += $added
        }
        catch { Log-Warning "    Could not parse $($csv.FullName): $($_.Exception.Message)" }
    }
    $unlisted = @($attachmentCopies | Where-Object { -not $listedCopies.ContainsKey($_) } | Sort-Object)
    if ($unlisted.Count -gt 0) {
        Log "  $($unlisted.Count) copied attachment(s) without a listing row: rows from the manifest"
        foreach ($relative in $unlisted) {
            $copy = $manifestRows[$relative]
            $program = if ($relative -match '\\NewOutlook\\') { "New Outlook" } else { "Classic Outlook" }
            $copyPath = Join-Path $script:collectionRoot $relative
            $emailRows += Add-EmailAttachmentRows -Program $program -Path $copy.SourcePath -Size $copy.Size `
                -Created $null -Modified $null -Accessed $null -Status "Copied" -Copy $copy -User (Get-CollectionUser $copyPath) -RawPath $copyPath
        }
    }

    # Accounts (Snapshot rows)
    foreach ($settingsFile in $settingsFiles) {
        Log "  Parsing: New Outlook UserSettings.json ($(Get-CollectionUser $settingsFile.FullName))"
        try {
            $added = Add-NewOutlookAccountRows -File $settingsFile -ManifestRows $manifestRows
            Log "    $added account(s) added."
            $emailRows += $added
        }
        catch { Log-Warning "    Could not read $($settingsFile.FullName): $($_.Exception.Message)" }
    }
    foreach ($prefsFile in $prefsFiles) {
        Log "  Parsing: Thunderbird prefs.js, profile $($prefsFile.Directory.Name) ($(Get-CollectionUser $prefsFile.FullName))"
        try {
            $added = Add-ThunderbirdAccountRows -File $prefsFile -ManifestRows $manifestRows
            Log "    $added account(s) added."
            $emailRows += $added
        }
        catch { Log-Warning "    Could not read $($prefsFile.FullName): $($_.Exception.Message)" }
    }

    # Thunderbird search index (needs sqlite3.exe)
    if ($glodaFiles.Count -gt 0) {
        $sqlite3Exe = Find-Sqlite3Exe
        if (-not $sqlite3Exe) {
            Log-Warning "  sqlite3.exe not available -- Thunderbird messages (global-messages-db.sqlite) skipped."
        }
        foreach ($gloda in $glodaFiles) {
            if (-not $sqlite3Exe) { break }
            Log "  Parsing: Thunderbird global-messages-db.sqlite, profile $($gloda.Directory.Name) ($(Get-CollectionUser $gloda.FullName))"
            try {
                $added = Add-ThunderbirdMessageRows -Sqlite3Exe $sqlite3Exe -File $gloda
                Log "    $added message(s) added."
                $emailRows += $added
            }
            catch { Log-Warning "    Could not parse $($gloda.FullName): $($_.Exception.Message)" }
        }
    }

    Log "  Email parsing complete: $emailRows row(s)."
    Log ""
}

function Parse-Network {
    Log "--- Parsing Network Artifacts ---"

    $networkParsed = $false

    # Live network state is point-in-time: every row in this section is a
    # Snapshot at collection time (Get-SnapshotTimeUtc), not an event.

    # TCP connections CSV
    $tcpCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("tcp_connections.csv")
    foreach ($csv in $tcpCsv) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $csv
            $rowCount = 0
            $connections = Import-Csv -Path $csv.FullName -ErrorAction Stop
            foreach ($conn in $connections) {
                $endpoints = @()
                foreach ($pair in @(@("LocalAddress", "LocalPort"), @("RemoteAddress", "RemotePort"))) {
                    $addr = Get-ArtifactRowValue $conn @($pair[0])
                    if ($addr -match ':') { $addr = "[$addr]" }
                    $endpoints += "${addr}:$(Get-ArtifactRowValue $conn @($pair[1]))"
                }
                $state = Get-ArtifactRowValue $conn @("State")
                $process = Get-ArtifactRowValue $conn @("ProcessName", "Process")
                $procId = Get-ArtifactRowValue $conn @("OwningProcess")
                $label = (@($state, $process) | Where-Object { $_ }) -join ", "

                Add-TimelineEntry -Timestamp $ts -Source "Network-TCP" -EventType "Snapshot" `
                    -Description "TCP connection: $($endpoints[0]) -> $($endpoints[1]) ($label)" `
                    -Details (Format-ArtifactDetails ([ordered]@{ State = $state; Process = $process; PID = $procId })) `
                    -Artifact "Network" -RawPath $csv.FullName
                $rowCount++
                $networkParsed = $true
            }
            Log "    $rowCount snapshot row(s)"
        }
        catch { Log-Warning "  Failed to parse TCP connections: $($_.Exception.Message)" }
    }

    # DNS cache (Get-DnsClientCache | Format-Table -Wrap; the header and long
    # values wrap onto extra lines, which the table reader rejoins)
    $dnsFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("dns_cache.txt")
    foreach ($dnsFile in $dnsFiles) {
        Log "  Parsing: $($dnsFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $dnsFile
            $records = @(ConvertFrom-FormatTableText -Lines (Get-Content -Path $dnsFile.FullName -ErrorAction Stop))
            if ($records.Count -eq 0) { Log "    No DNS cache table found." }
            $seen = @{}
            foreach ($rec in $records) {
                $entry = Get-ArtifactRowValue $rec @("Entry", "Name")
                if (-not $entry) { continue }
                $recordName = Get-ArtifactRowValue $rec @("RecordName")
                $type = Get-ArtifactRowValue $rec @("RecordType", "Type")
                $status = Get-ArtifactRowValue $rec @("Status")
                $data = Get-ArtifactRowValue $rec @("Data")
                $desc = "DNS cache: $entry"
                if ($type) { $desc += " ($type)" }
                if ($data) { $desc += " -> $data" }
                elseif ($recordName -and $recordName.TrimEnd('.') -ne $entry) { $desc += " -> $recordName" }
                if ($status -and $status -ne "Success") { $desc += " [$status]" }
                # The cache repeats a record once per answer; keep one row each
                if ($seen.ContainsKey($desc)) { continue }
                $seen[$desc] = $true

                Add-TimelineEntry -Timestamp $ts -Source "Network-DNS" -EventType "Snapshot" `
                    -Description $desc `
                    -Details (Format-ArtifactDetails ([ordered]@{
                        RecordName = $recordName
                        Type       = $type
                        Status     = $status
                        Section    = Get-ArtifactRowValue $rec @("Section")
                        TTL        = Get-ArtifactRowValue $rec @("TimeToLive")
                        Data       = $data
                    })) `
                    -Artifact "Network" -RawPath $dnsFile.FullName
                $networkParsed = $true
            }
            Log "    $($seen.Count) snapshot row(s) from $($records.Count) cache record(s)"
        }
        catch { Log-Warning "  Failed to parse DNS cache: $($_.Exception.Message)" }
    }

    # ARP / neighbor cache (Get-NetNeighbor | Format-Table, or arp -a text).
    # Only resolved unicast neighbours are listed: entries without a MAC and
    # multicast / broadcast mappings carry no evidence of a peer.
    $arpFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("arp_cache.txt")
    foreach ($arpFile in $arpFiles) {
        Log "  Parsing: $($arpFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $arpFile
            $content = Get-Content -Path $arpFile.FullName -ErrorAction Stop
            $neighbors = @(ConvertFrom-FormatTableText -Lines $content)
            if ($neighbors.Count -eq 0) {
                # arp -a: "  10.0.0.1     00-11-22-33-44-55     dynamic"
                foreach ($line in $content) {
                    if ($line -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-f-]{17})\s+(\w+)') {
                        $neighbors += [PSCustomObject]@{ IPAddress = $Matches[1]; LinkLayerAddress = $Matches[2]; State = $Matches[3] }
                    }
                }
            }
            $rowCount = 0
            foreach ($n in $neighbors) {
                $ip = Get-ArtifactRowValue $n @("IPAddress")
                $mac = Get-ArtifactRowValue $n @("LinkLayerAddress")
                if (-not $ip -or -not $mac -or $mac -match '^(33-33-|01-00-5E-|FF-FF-FF-FF-FF-FF|00-00-00-00-00-00)') { continue }
                $state = Get-ArtifactRowValue $n @("State")
                Add-TimelineEntry -Timestamp $ts -Source "Network-ARP" -EventType "Snapshot" `
                    -Description "ARP entry: $ip -> $mac ($state)" `
                    -Details (Format-ArtifactDetails ([ordered]@{ InterfaceIndex = Get-ArtifactRowValue $n @("ifIndex"); State = $state; Store = Get-ArtifactRowValue $n @("PolicyStore") })) `
                    -Artifact "Network" -RawPath $arpFile.FullName
                $rowCount++
                $networkParsed = $true
            }
            Log "    $rowCount snapshot row(s) from $($neighbors.Count) neighbor entr(ies)"
        }
        catch { Log-Warning "  Failed to parse ARP cache: $($_.Exception.Message)" }
    }

    # Network shares (Get-SmbShare | Format-Table: Name, ScopeName, Path,
    # Description) and mapped drives (Get-SmbMapping: Status, Local Path, Remote Path)
    $shareFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("network_shares.txt")
    foreach ($shareFile in $shareFiles) {
        Log "  Parsing: $($shareFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $shareFile
            $rowCount = 0
            foreach ($item in @(ConvertFrom-FormatTableText -Lines (Get-Content -Path $shareFile.FullName -ErrorAction Stop))) {
                $remote = Get-ArtifactRowValue $item @("Remote Path", "RemotePath")
                if ($remote) {
                    $local = Get-ArtifactRowValue $item @("Local Path", "LocalPath")
                    $desc = "Mapped network drive: $local -> $remote"
                    $details = Format-ArtifactDetails ([ordered]@{ Status = Get-ArtifactRowValue $item @("Status") })
                }
                else {
                    $name = Get-ArtifactRowValue $item @("Name")
                    if (-not $name) { continue }
                    $path = Get-ArtifactRowValue $item @("Path")
                    $desc = "Network share: $name"
                    if ($path) { $desc += " -> $path" }
                    $details = Format-ArtifactDetails ([ordered]@{ Scope = Get-ArtifactRowValue $item @("ScopeName"); Description = Get-ArtifactRowValue $item @("Description") })
                }
                Add-TimelineEntry -Timestamp $ts -Source "Network-Shares" -EventType "Snapshot" `
                    -Description $desc -Details $details `
                    -Artifact "Network" -RawPath $shareFile.FullName
                $rowCount++
                $networkParsed = $true
            }
            Log "    $rowCount snapshot row(s)"
        }
        catch { Log-Warning "  Failed to parse network shares: $($_.Exception.Message)" }
    }

    # WiFi profiles (netsh wlan show profiles)
    $wifiFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("wifi_profiles.txt")
    foreach ($wifiFile in $wifiFiles) {
        Log "  Parsing: $($wifiFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $wifiFile
            $rowCount = 0
            $content = Get-Content -Path $wifiFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($line -match '(All User Profile|Current User Profile)\s*:\s*(.+)$') {
                    Add-TimelineEntry -Timestamp $ts -Source "Network-WiFi" -EventType "Snapshot" `
                        -Description "WiFi profile: $($Matches[2].Trim())" `
                        -Details "ProfileType=$($Matches[1])" `
                        -Artifact "Network" -RawPath $wifiFile.FullName
                    $rowCount++
                    $networkParsed = $true
                }
            }
            Log "    $rowCount snapshot row(s)"
        }
        catch { Log-Warning "  Failed to parse WiFi profiles: $($_.Exception.Message)" }
    }

    if (-not $networkParsed) { Log-Warning "No network artifacts found." }
    Log "  Network parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 11. USB Artifacts Parser
# ----------------------------------------------------------
# Readable name for a device instance path, e.g.
#   USBSTOR\Disk&Ven_PNY&Prod_USB_3.1_FD&Rev_PMAP\07000ABE2CA4FB67&0
#   -> "PNY USB 3.1 FD (serial 07000ABE2CA4FB67)"
# A second character of "&" marks an instance ID made up by Windows
# because the device has no serial number.
function Get-DeviceInstanceLabel {
    param([string]$InstancePath)
    if (-not $InstancePath) { return "" }
    $suffix = ""
    if ($InstancePath -match '^SWD\\WPDBUSENUM\\') { $suffix = " [portable device]" }
    elseif ($InstancePath -match '^STORAGE\\VOLUME\\') { $suffix = " [volume]" }

    if ($InstancePath -match '(?i)(?:USBSTOR|SCSI)[\\#][A-Za-z]*&Ven_([^&\\#]*)&Prod_([^&\\#]*)(?:&Rev_[^\\#]*)?[\\#]([^\\#]+)') {
        $name = (($Matches[1] + " " + $Matches[2]) -replace '_', ' ' -replace '\s+', ' ').Trim()
        $instance = $Matches[3] -replace '&\d+$', ''
        if ($instance.Length -gt 1 -and $instance[1] -ne '&') { return "$name (serial $instance)$suffix" }
        return "$name (no serial)$suffix"
    }
    if ($InstancePath -match '(?i)^USB\\(VID_[0-9A-F]{4})&(PID_[0-9A-F]{4})(?:&(MI_[0-9A-F]{2}))?\\(.+)$') {
        $name = "USB device $($Matches[1]) $($Matches[2])"
        if ($Matches[3]) { $name += " interface $($Matches[3])" }
        if ($Matches[4].Length -gt 1 -and $Matches[4][1] -ne '&') { $name += " (serial $($Matches[4]))" }
        return $name
    }
    return "$InstancePath"
}

# $true for the device instance path of a USB device: USB\VID_..., a USB
# storage device (USBSTOR\..., also inside a portable-device or volume path
# like SWD\WPDBUSENUM\_??_USBSTOR#...), an ID with a USB vendor ID
# (HID\VID_..., SWC\VID_...), or the portable device Windows makes for a
# volume on a removable drive (SWD\WPDBUSENUM\{volume GUID}#<partition
# offset>), nearly always a USB drive (an SD card in a built-in reader
# gives one too). Bluetooth IDs write "_VID&" and do not match.
function Test-UsbDeviceInstance {
    param([string]$InstancePath)
    return ($InstancePath -match '(?i)USBSTOR|^USB\\|VID_[0-9A-F]{4}|^SWD\\WPDBUSENUM\\\{')
}

# The setupapi.dev*.log files under -InputPath. A log shortened on
# extraction to fit the path limit (setupapi.dev.log becomes e.g.
# setupapi~1A2B3C4D.log) is found by its full-length name. Like
# Find-ArtifactFiles, it skips email attachment copies and the Secrets\
# folder (only the file name is shortened, so the folder still shows).
function Find-SetupApiLogFiles {
    $files = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("setupapi.dev*.log") |
        Where-Object { $_.Name -like "setupapi.dev*.log" })
    if ($script:shortenedNames) {
        foreach ($shortPath in @($script:shortenedNames.Keys)) {
            if ([System.IO.Path]::GetFileName($script:shortenedNames[$shortPath]) -like "setupapi.dev*.log" -and [System.IO.File]::Exists($shortPath) -and
                -not (Test-EmailAttachmentCopy (Get-RelativeCollectionPath $shortPath)) -and -not (Test-SecretsPath $shortPath)) {
                $files += Get-Item -LiteralPath $shortPath
            }
        }
    }
    return @($files | Sort-Object FullName -Unique)
}

# The setupapi.dev*.log files collection_manifest.csv lists (relative
# paths): Listed, and Missing = those not among $Found (the files the USB
# parser found). A missing log was saved by the collector but lost
# afterwards, and its device installs are not in the timeline. A found log
# that was shortened on extraction counts by its full-length name. Email
# attachment copies and files in the Secrets\ folder are not listed: the
# parser never reads them. Both are empty without a manifest.
function Compare-ManifestSetupApiLogs {
    param([object[]]$Found)
    $result = [PSCustomObject]@{ Listed = @(); Missing = @() }
    $manifest = Get-CollectionManifest
    if (-not $manifest.Path) { return $result }
    $foundPaths = @($Found | Where-Object { $_ } | ForEach-Object {
            if ($script:shortenedNames -and $script:shortenedNames.ContainsKey($_.FullName)) { $script:shortenedNames[$_.FullName] } else { $_.FullName }
        })
    $result.Listed = @($manifest.RelativePaths | Where-Object {
            [System.IO.Path]::GetFileName($_) -like "setupapi.dev*.log" -and -not (Test-EmailAttachmentCopy $_) -and
            -not (Test-SecretsPath (Join-Path $manifest.Folder $_))
        } | Sort-Object)
    $result.Missing = @($result.Listed | Where-Object { $foundPaths -notcontains (Join-Path $manifest.Folder $_) })
    return $result
}

# One MountedDevices value, decoded into the columns of the collector's
# USB\mounted_devices.csv (the same decoder as the collector's). Kind:
#   GPT         "DMIO:ID:" + partition GUID (24 bytes; also dynamic volumes)
#   MBR         disk signature (4 bytes) + partition offset in bytes (8)
#   DevicePath  UTF-16 device path starting "_??_" or "\??\", such as
#               _??_USBSTOR#Disk&Ven_...&Prod_...#<serial>&0#{...}
#   Other       anything else, including a value that is not binary
# HexData is the raw data (as text for a value that is not binary)
function ConvertFrom-MountedDeviceValue {
    param([string]$Name, $Data)
    $row = [ordered]@{
        Name            = $Name
        Kind            = "Other"
        DiskSignature   = ""
        PartitionOffset = ""
        PartitionGuid   = ""
        DevicePath      = ""
        DataLength      = 0
        HexData         = ""
    }
    if ($Data -isnot [byte[]]) {
        if ($null -ne $Data) { $row.HexData = (@($Data) | ForEach-Object { "$_" }) -join "; " }
        return [PSCustomObject]$row
    }
    $row.DataLength = $Data.Length
    $row.HexData = [BitConverter]::ToString($Data).Replace("-", "")
    if ($Data.Length -eq 24 -and [System.Text.Encoding]::ASCII.GetString($Data, 0, 8) -eq "DMIO:ID:") {
        $row.Kind = "GPT"
        $row.PartitionGuid = (New-Object Guid (, [byte[]]$Data[8..23])).ToString("B")
    }
    elseif ($Data.Length -eq 12) {
        $row.Kind = "MBR"
        $row.DiskSignature = "{0:X8}" -f [BitConverter]::ToUInt32($Data, 0)
        $row.PartitionOffset = [string][BitConverter]::ToUInt64($Data, 4)
    }
    elseif ($Data.Length -ge 8 -and $Data.Length % 2 -eq 0 -and $Data[1] -eq 0) {
        $text = [System.Text.Encoding]::Unicode.GetString($Data).TrimEnd([char]0)
        if ($text -match '^(_\?\?_|\\\?\?\\)') {
            $row.Kind = "DevicePath"
            $row.DevicePath = $text
        }
    }
    return [PSCustomObject]$row
}

# Values of the mounted_devices.txt older collectors wrote: Format-List
# output of the MountedDevices key that shows only the first 4 bytes of
# each value, followed by "..." (or the ellipsis character), e.g.
#   \DosDevices\G:                                   : {182, 240, 19, 166...}
#   \??\Volume{00000000-0000-11f0-8000-000000000001} : {95, 0, 63, 0...}
# The first bytes still tell the kind: "DMIO" is GPT, "_?" or "\?" in
# UTF-16 a device path, anything else is taken for MBR, whose first 4
# bytes are the whole disk signature. A value shown in full (up to 4
# bytes) is decoded. Rows have the mounted_devices.csv columns; a cut-off
# value has DataLength "", the known bytes plus "..." as HexData and
# Truncated = $true. Other lines (PSPath, ..., or the decoded
# "Name : ..." lists of newer collectors) are ignored.
function ConvertFrom-MountedDevicesText {
    param([string[]]$Lines)
    $ellipsis = [regex]::Escape([string][char]0x2026)
    $pattern = '^(\\DosDevices\\[A-Za-z]:|\\\?\?\\Volume\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\})\s+:\s\{((?:\d{1,3}, )*\d{1,3})?(\.\.\.|' + $ellipsis + ')?\}\s*$'
    $rows = @()
    foreach ($line in $Lines) {
        if ($line -notmatch $pattern) { continue }
        $name = $Matches[1]
        $cut = [bool]$Matches[3]
        $numbers = @()
        if ($Matches[2]) { $numbers = @($Matches[2] -split ', ' | ForEach-Object { [int]$_ }) }
        if (@($numbers | Where-Object { $_ -gt 255 }).Count -gt 0) { continue }
        $bytes = [byte[]]$numbers
        if (-not $cut) {
            $row = ConvertFrom-MountedDeviceValue -Name $name -Data $bytes
            $row | Add-Member -NotePropertyName KeyLastWriteUtc -NotePropertyValue ""
            $row | Add-Member -NotePropertyName Truncated -NotePropertyValue $false
            $rows += $row
            continue
        }
        $row = [PSCustomObject]@{
            Name = $name; Kind = "Other"; DiskSignature = ""; PartitionOffset = ""; PartitionGuid = ""; DevicePath = ""
            DataLength = ""; HexData = [BitConverter]::ToString($bytes).Replace("-", "") + "..."; KeyLastWriteUtc = ""; Truncated = $true
        }
        if ($bytes.Length -ge 4) {
            if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -eq "DMIO") { $row.Kind = "GPT" }
            elseif (($bytes[0] -eq 95 -or $bytes[0] -eq 92) -and $bytes[1] -eq 0 -and $bytes[2] -eq 63 -and $bytes[3] -eq 0) { $row.Kind = "DevicePath" }
            else {
                $row.Kind = "MBR"
                $row.DiskSignature = "{0:X8}" -f [BitConverter]::ToUInt32($bytes, 0)
            }
        }
        $rows += $row
    }
    return $rows
}

# MountedDevices values of a loaded SYSTEM hive (the key is at the hive
# root, not in a control set), decoded, with the key's last-write time as
# KeyLastWriteUtc (ISO 8601, as in mounted_devices.csv). Empty when the
# hive has no MountedDevices key.
function Get-OfflineMountedDeviceRows {
    param([Microsoft.Win32.RegistryKey]$SystemRoot)
    $rows = @()
    $key = $SystemRoot.OpenSubKey("MountedDevices")
    if (-not $key) { return $rows }
    try {
        $lastWrite = Get-RegistryKeyLastWriteUtc $key
        $lastWriteText = if ($lastWrite) { $lastWrite.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture) } else { "" }
        foreach ($valueName in $key.GetValueNames()) {
            if (-not $valueName) { continue }
            $row = ConvertFrom-MountedDeviceValue -Name $valueName -Data $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $row | Add-Member -NotePropertyName KeyLastWriteUtc -NotePropertyValue $lastWriteText
            $rows += $row
        }
    }
    finally { $key.Close() }
    return $rows
}

# MountedDevices of the examined system, from the best source in the
# collection:
#   1. mounted_devices.csv with at least one row (decoded by the collector;
#      live collections)
#   2. MountedDevices at the root of the collected SYSTEM hive (also
#      mounted-image collections)
#   3. mounted_devices.txt of older collectors (first 4 bytes of each
#      value only, see ConvertFrom-MountedDevicesText)
# Returns Rows (mounted_devices.csv columns), Source (for the log) and
# File (where the rows came from); Rows is empty when no source has a value.
function Read-CollectionMountedDevices {
    $result = [PSCustomObject]@{ Rows = @(); Source = ""; File = $null }
    foreach ($csvFile in @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("mounted_devices.csv") | Where-Object { -not $_.PSIsContainer })) {
        Log "  Parsing: $($csvFile.FullName)"
        try { $rows = @(Import-Csv -LiteralPath $csvFile.FullName -ErrorAction Stop | Where-Object { $_.Name }) }
        catch {
            Log-Warning "  Failed to parse mounted devices CSV: $($_.Exception.Message)"
            continue
        }
        if ($rows.Count -gt 0) {
            $result.Rows = $rows
            $result.Source = $csvFile.FullName
            $result.File = $csvFile
            return $result
        }
        Log "    No values in $($csvFile.Name)."
    }

    $systemHive = Find-OfflineHiveFile "SYSTEM"
    if ($systemHive) {
        $mount = $null
        try {
            $mount = Mount-TimelineHive -HiveFile $systemHive -Prefix "TEMP_TLUSB"
            if ($mount -and $mount.Root) {
                # The machine's names for the User column too
                Add-TimelineMachineName (Get-OfflineComputerNames $mount.Root)
                $rows = @(Get-OfflineMountedDeviceRows -SystemRoot $mount.Root)
                if ($rows.Count -gt 0) {
                    $result.Rows = $rows
                    $result.Source = "the SYSTEM hive $($systemHive.FullName)"
                    $result.File = $systemHive
                }
                else { Log "    No MountedDevices values in the SYSTEM hive." }
            }
        }
        catch { Log-Warning "  Failed to read MountedDevices from the SYSTEM hive: $($_.Exception.Message)" }
        finally { Dismount-TimelineHive $mount }
        if ($result.Rows.Count -gt 0) { return $result }
    }

    foreach ($txtFile in @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("mounted_devices.txt") | Where-Object { -not $_.PSIsContainer })) {
        Log "  Parsing: $($txtFile.FullName)"
        # Read-AntiVirusTextLines reads any of the encodings collectors wrote
        # (UTF-8 with a BOM from Windows PowerShell 5.1, without one from 7)
        try { $rows = @(ConvertFrom-MountedDevicesText -Lines (Read-AntiVirusTextLines $txtFile.FullName)) }
        catch {
            Log-Warning "  Failed to parse mounted devices: $($_.Exception.Message)"
            continue
        }
        if (@($rows | Where-Object { $_.Truncated }).Count -gt 0) {
            Log-Warning "  $($txtFile.Name) is from an older collector: it shows only the first 4 bytes of each value, so partition GUIDs, offsets and device names are missing (they are read from the SYSTEM hive when the collection has one that loads)."
        }
        if ($rows.Count -gt 0) {
            $result.Rows = $rows
            $result.Source = $txtFile.FullName
            $result.File = $txtFile
            return $result
        }
        Log "    No MountedDevices values in $($txtFile.Name)."
    }
    return $result
}

# Device instance ID of a device path from MountedDevices, e.g.
#   _??_USBSTOR#Disk&Ven_Generic-&Prod_SD#MMC&Rev_1.00#0123456789&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
#   -> USBSTOR\Disk&Ven_Generic-&Prod_SD/MMC&Rev_1.00\0123456789&0
# The path writes each "\" of the ID as "#" and ends with the interface
# class GUID. A "/" in the ID (Prod_SD/MMC) is a "#" in the path too, so
# the fields between the first and the last are joined with "/". "" when
# the path has fewer than three fields.
function ConvertTo-DeviceInstanceId {
    param([string]$DevicePath)
    $fields = @(($DevicePath -replace '^(_\?\?_|\\\?\?\\)', '').TrimEnd([char]0) -split '#')
    if ($fields.Count -gt 1 -and $fields[-1] -match '^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') {
        $fields = @($fields[0..($fields.Count - 2)])
    }
    if ($fields.Count -lt 3) { return "" }
    return (@($fields[0], (@($fields[1..($fields.Count - 2)]) -join "/"), $fields[-1]) -join "\")
}

# Volume GUID Windows uses for an MBR partition (e.g. the MountPoints2 key
# name): the disk signature, two zero groups, then the 8 bytes of the
# partition offset, {<signature>-0000-0000-<offset bytes>}. "" when the
# signature (hex) or the offset (decimal) cannot be read.
function Get-MbrVolumeGuid {
    param([string]$DiskSignature, [string]$PartitionOffset)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $signature = [uint32]0
    $offset = [uint64]0
    if (-not [uint32]::TryParse($DiskSignature, [System.Globalization.NumberStyles]::AllowHexSpecifier, $invariant, [ref]$signature)) { return "" }
    if (-not [uint64]::TryParse($PartitionOffset, [System.Globalization.NumberStyles]::None, $invariant, [ref]$offset)) { return "" }
    $bytes = [byte[]]([BitConverter]::GetBytes($signature) + (New-Object byte[] 4) + [BitConverter]::GetBytes($offset))
    return (New-Object Guid (, $bytes)).ToString("B")
}

# Timeline text for decoded MountedDevices values (rows with the
# mounted_devices.csv columns). One object per value with Name, Kind,
# Description and Details, e.g. "Drive letter H: -> MBR disk 0A1B2C3D,
# partition at offset 1048576" or "Volume {...} -> USB storage <device>".
# Details: Kind and the decoded fields; VolumeGuid (the \??\Volume{} name
# of a value with the same data, else for GPT the partition GUID and for
# MBR {<signature>-0000-0000-<offset bytes>}, the names MountPoints2
# uses); InstanceId, Serial and DevicePath of a device path; SameDataAs
# (values with the same bytes); SameDisk (other values with the same MBR
# disk signature); KeyLastWriteUtc; PnPRecord for a USBSTOR device path
# when $StorageSerials is given (usb_storage_devices.csv as serial ->
# instance ID; $null when that file was not read); CollectorDrive=yes for
# the drive letter of the collector's output folder. The times inside
# volume GUIDs (version 1 UUIDs) are not used: they are not mount times.
function ConvertTo-MountedDeviceEntries {
    param([object[]]$Rows, [hashtable]$StorageSerials = $null, [string]$CollectorDrive = "")
    $values = @(foreach ($row in $Rows) {
            $name = Get-ArtifactRowValue $row @("Name")
            if (-not $name) { continue }
            $volume = ""
            if ($name -match '^\\\?\?\\Volume(\{[0-9A-Fa-f-]{36}\})$') { $volume = $Matches[1] }
            [PSCustomObject]@{
                Row       = $row
                Name      = $name
                Kind      = Get-ArtifactRowValue $row @("Kind")
                Volume    = $volume
                Hex       = (Get-ArtifactRowValue $row @("HexData")).ToUpperInvariant()
                Signature = (Get-ArtifactRowValue $row @("DiskSignature")).ToUpperInvariant()
                Truncated = "$($row.Truncated)" -eq "True"
            }
        })
    $entries = @()
    for ($i = 0; $i -lt $values.Count; $i++) {
        $v = $values[$i]
        $row = $v.Row
        $sameData = @(for ($j = 0; $j -lt $values.Count; $j++) {
                if ($j -ne $i -and -not $v.Truncated -and -not $values[$j].Truncated -and $v.Hex -and $values[$j].Hex -eq $v.Hex) { $values[$j].Name }
            })
        $sameDisk = @(for ($j = 0; $j -lt $values.Count; $j++) {
                if ($j -ne $i -and $v.Kind -eq "MBR" -and $v.Signature -and $values[$j].Kind -eq "MBR" -and $values[$j].Signature -eq $v.Signature -and $sameData -notcontains $values[$j].Name) { $values[$j].Name }
            })
        $volumes = @(for ($j = 0; $j -lt $values.Count; $j++) {
                if ($values[$j].Volume -and ($j -eq $i -or $sameData -contains $values[$j].Name)) { $values[$j].Volume }
            })

        if ($v.Name -match '^\\DosDevices\\([A-Za-z]:)$') { $what = "Drive letter $($Matches[1].ToUpperInvariant())" }
        elseif ($v.Volume) { $what = "Volume $($v.Volume)" }
        else { $what = "Value $($v.Name)" }

        # Empty fields are left out of Details
        $details = [ordered]@{
            Kind            = $v.Kind
            PartitionGuid   = ""
            DiskSignature   = ""
            PartitionOffset = ""
            VolumeGuid      = $volumes -join ", "
            InstanceId      = ""
            Serial          = ""
            DevicePath      = ""
            HexData         = ""
            SameDataAs      = $sameData -join ", "
            SameDisk        = $sameDisk -join ", "
            KeyLastWriteUtc = Format-UtcDetailTime (ConvertFrom-UtcText (Get-ArtifactRowValue $row @("KeyLastWriteUtc")))
            PnPRecord       = ""
            CollectorDrive  = ""
            Truncated       = ""
        }
        if ($v.Kind -eq "GPT") {
            $details.PartitionGuid = Get-ArtifactRowValue $row @("PartitionGuid")
            if (-not $details.VolumeGuid) { $details.VolumeGuid = $details.PartitionGuid }
            $target = "GPT partition $($details.PartitionGuid)"
        }
        elseif ($v.Kind -eq "MBR") {
            $details.DiskSignature = $v.Signature
            $details.PartitionOffset = Get-ArtifactRowValue $row @("PartitionOffset")
            if (-not $details.VolumeGuid) { $details.VolumeGuid = Get-MbrVolumeGuid -DiskSignature $v.Signature -PartitionOffset $details.PartitionOffset }
            $target = "MBR disk $($v.Signature)"
            if ($details.PartitionOffset) { $target += ", partition at offset $($details.PartitionOffset)" }
        }
        elseif ($v.Kind -eq "DevicePath") {
            $details.DevicePath = Get-ArtifactRowValue $row @("DevicePath")
            $details.InstanceId = ConvertTo-DeviceInstanceId $details.DevicePath
            if ($details.InstanceId) {
                # The last field is the serial number plus "&<LUN>", or an ID
                # made up by Windows ("&" as its second character)
                $instance = ($details.InstanceId -split '\\')[-1] -replace '&\d+$', ''
                if ($instance.Length -gt 1 -and $instance[1] -ne '&') { $details.Serial = $instance }
                if ($details.InstanceId -like "USBSTOR\*") {
                    $target = "USB storage $(Get-DeviceInstanceLabel $details.InstanceId)"
                    if ($null -ne $StorageSerials) {
                        if ($StorageSerials.ContainsKey($instance)) { $details.PnPRecord = "in USBSTOR at collection time: $($StorageSerials[$instance])" }
                        else { $details.PnPRecord = "not in USBSTOR at collection time" }
                    }
                }
                else { $target = "device $(Get-DeviceInstanceLabel $details.InstanceId)" }
            }
            elseif ($details.DevicePath) { $target = "device path $($details.DevicePath)" }
            else { $target = "device path" }
        }
        else {
            $details.HexData = Get-ArtifactRowValue $row @("HexData")
            $length = Get-ArtifactRowValue $row @("DataLength")
            if ($v.Truncated -or -not $length) { $target = "unrecognized data" }
            elseif ($length -eq "0" -and $v.Hex) { $target = "unrecognized value (not binary)" }
            else { $target = "unrecognized data ($length bytes)" }
        }
        if ($v.Truncated) {
            # mounted_devices.txt of an older collector: only the kind (and an
            # MBR disk signature) can be read from the first 4 bytes
            $details.HexData = Get-ArtifactRowValue $row @("HexData")
            $details.Truncated = "yes (only the first 4 bytes are in mounted_devices.txt; the kind is taken from them)"
            if ($v.Kind -eq "GPT") { $target = "GPT partition" }
            elseif ($v.Kind -eq "DevicePath") { $target = "device path" }
            $target += " (value cut off)"
        }
        if ($CollectorDrive -and $v.Name -match '^\\DosDevices\\([A-Za-z]:)$' -and $Matches[1] -eq $CollectorDrive) { $details.CollectorDrive = "yes" }
        $entries += [PSCustomObject]@{
            Name        = $v.Name
            Kind        = $v.Kind
            Description = "$what -> $target"
            Details     = Format-ArtifactDetails $details
        }
    }
    return $entries
}

# Parse Format-List text ("Name : value" blocks separated by blank lines,
# long values wrapped onto indented lines) into ordered hashtables
function ConvertFrom-FormatListBlocks {
    param([string[]]$Lines)
    $blocks = New-Object System.Collections.Generic.List[object]
    $current = $null
    $lastKey = $null
    foreach ($line in $Lines) {
        if ($line.Trim() -eq "") {
            if ($current) { $blocks.Add($current) }
            $current = $null
            $lastKey = $null
        }
        elseif ($line -match '^([A-Za-z_]\w*)\s*:\s?(.*)$') {
            if (-not $current) { $current = [ordered]@{} }
            $lastKey = $Matches[1]
            $current[$lastKey] = $Matches[2]
        }
        elseif ($current -and $lastKey) {
            # Wrapped continuation of the previous value
            $current[$lastKey] = $current[$lastKey] + $line.TrimStart()
        }
    }
    if ($current) { $blocks.Add($current) }
    return ,$blocks
}

function Parse-USB {
    Log "--- Parsing USB Artifacts ---"

    $usbParsed = $false

    # USB storage devices with PnP install/arrival/removal times (newer collectors, live only)
    $haveStorageCsv = $false
    # Serial -> instance ID of these devices, for the mounted devices below
    # ($null when there is no usb_storage_devices.csv)
    $storageSerials = $null
    $usbCsvFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("usb_storage_devices.csv")
    foreach ($csvFile in $usbCsvFiles) {
        Log "  Parsing: $($csvFile.FullName)"
        try {
            $rows = @(Import-Csv -Path $csvFile.FullName -ErrorAction Stop)
            if ($null -eq $storageSerials) { $storageSerials = @{} }
            foreach ($row in $rows) {
                $serial = Get-ArtifactRowValue $row @("Serial")
                if (-not $serial) { $serial = ("$($row.InstanceId)" -split '\\')[-1] }
                $serial = $serial -replace '&\d+$', ''
                if ($serial) { $storageSerials[$serial] = Get-ArtifactRowValue $row @("InstanceId") }
            }
            $count = 0
            foreach ($row in $rows) {
                $name = $row.FriendlyName
                if (-not $name) { $name = Get-DeviceInstanceLabel $row.InstanceId }
                $details = "Serial=$($row.Serial) InstanceId=$($row.InstanceId) FirstInstallUtc=$($row.FirstInstallUtc) InstallUtc=$($row.InstallUtc) LastArrivalUtc=$($row.LastArrivalUtc) LastRemovalUtc=$($row.LastRemovalUtc)"
                $hasTime = $false
                foreach ($field in @("FirstInstallUtc", "LastArrivalUtc", "LastRemovalUtc")) {
                    $ts = ConvertFrom-UtcText $row.$field
                    if (-not $ts) { continue }
                    $what = "USB storage first installed (first connected)"
                    if ($field -eq "LastArrivalUtc") { $what = "USB storage last connected" }
                    elseif ($field -eq "LastRemovalUtc") { $what = "USB storage last removed" }
                    Add-TimelineEntry -Timestamp $ts -Source "USB" -EventType "USBDevice" `
                        -Description "${what}: $name" `
                        -Details $details `
                        -Artifact "USB" -RawPath $csvFile.FullName
                    $hasTime = $true
                    $count++
                }
                if (-not $hasTime) {
                    $snapTime = Get-SnapshotTimeUtc -File $csvFile
                    if ($snapTime) {
                        Add-TimelineEntry -Timestamp $snapTime -Source "USB" -EventType "Snapshot" `
                            -Description "USB storage device (no PnP times): $name" `
                            -Details $details `
                            -Artifact "USB" -RawPath $csvFile.FullName
                        $count++
                    }
                }
            }
            if ($rows.Count -gt 0) { $haveStorageCsv = $true }
            if ($count -gt 0) { $usbParsed = $true }
            Log "  Parsed $($rows.Count) USB storage device(s) ($count row(s))."
        }
        catch { Log-Warning "  Failed to parse USB storage CSV: $($_.Exception.Message)" }
    }

    # Registry device lists (Format-List text): state at collection time, one Snapshot row per device.
    # usb_storage_devices.txt is only needed when the CSV above is missing (older collectors).
    $usbTextNames = @("usb_devices.txt")
    if (-not $haveStorageCsv) { $usbTextNames += "usb_storage_devices.txt" }
    $usbFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames $usbTextNames
    foreach ($usbFile in $usbFiles) {
        Log "  Parsing: $($usbFile.FullName)"
        try {
            $snapTime = Get-SnapshotTimeUtc -File $usbFile
            $isStorage = $usbFile.Name -like "usb_storage_devices*"
            $blocks = ConvertFrom-FormatListBlocks -Lines @(Get-Content -Path $usbFile.FullName -ErrorAction Stop)
            $seen = @{}
            $count = 0
            foreach ($block in $blocks) {
                # FriendlyName, else the readable part of DeviceDesc ("@usbstor.inf,%...%;USB Mass Storage Device")
                $name = "$($block['FriendlyName'])".Trim()
                if (-not $name -and $block['DeviceDesc']) { $name = ("$($block['DeviceDesc'])".Trim() -split ';')[-1].Trim() }
                $hardwareIds = "$($block['HardwareID'])".Trim().Trim('{', '}').Trim()
                $firstHwId = ($hardwareIds -split ',\s*')[0]
                $instance = "$($block['PSChildName'])".Trim()
                if (-not $name -and -not $firstHwId -and -not $instance) { continue }
                if (-not $name) { $name = $firstHwId }

                $key = "$name|$hardwareIds|$instance"
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true

                if ($isStorage) {
                    # PSChildName is the serial number plus "&<LUN>" (or a Windows-made ID if the device has none)
                    $serial = $instance -replace '&\d+$', ''
                    $desc = "USB storage device in registry: $name"
                    $details = "Instance=$instance HardwareID=$hardwareIds"
                    if ($serial.Length -gt 1 -and $serial[1] -ne '&') {
                        $desc += " (serial $serial)"
                        $details = "Serial=$serial $details"
                    }
                }
                else {
                    $desc = "USB device in registry: $name"
                    if ($firstHwId -match '(VID_[0-9A-Fa-f]{4})&(PID_[0-9A-Fa-f]{4})') { $desc += " ($($Matches[1]) $($Matches[2]))" }
                    $details = "Instance=$instance HardwareID=$hardwareIds"
                }
                foreach ($extra in @("Service", "Mfg", "ContainerID")) {
                    if ($block[$extra]) { $details += " $extra=$("$($block[$extra])".Trim())" }
                }

                if ($snapTime) {
                    Add-TimelineEntry -Timestamp $snapTime -Source "USB" -EventType "Snapshot" `
                        -Description $desc `
                        -Details $details `
                        -Artifact "USB" -RawPath $usbFile.FullName
                    $usbParsed = $true
                    $count++
                }
            }
            Log "  Parsed $count device(s)."
        }
        catch { Log-Warning "  Failed to parse USB devices: $($_.Exception.Message)" }
    }

    # Mounted devices (state at collection time): the disk, partition or
    # device each drive letter and volume GUID last belonged to, one
    # Snapshot row per MountedDevices value (sources: see
    # Read-CollectionMountedDevices; Details: see ConvertTo-MountedDeviceEntries)
    try {
        $mounted = Read-CollectionMountedDevices
        if ($mounted.Rows.Count -gt 0) {
            # The collector's output drive: a drive letter of the examined
            # system only in a live collection
            $collectorDrive = ""
            if ((Get-CollectionInfo).Mode -eq "Live") {
                $outputFolder = Get-CollectorOutputFolder
                if ($outputFolder.Path -match '^([A-Za-z]:)') { $collectorDrive = $Matches[1].ToUpperInvariant() }
            }
            $entries = @(ConvertTo-MountedDeviceEntries -Rows $mounted.Rows -StorageSerials $storageSerials -CollectorDrive $collectorDrive)
            $ts = Get-SnapshotTimeUtc -File $mounted.File
            if ($ts) {
                foreach ($entry in $entries) {
                    Add-TimelineEntry -Timestamp $ts -Source "USB-MountedDevices" -EventType "Snapshot" `
                        -Description $entry.Description `
                        -Details $entry.Details `
                        -Artifact "USB" -RawPath $mounted.File.FullName
                    $usbParsed = $true
                }
            }
            $kindCounts = "$(@($entries | Where-Object { $_.Kind -eq 'GPT' }).Count) GPT, $(@($entries | Where-Object { $_.Kind -eq 'MBR' }).Count) MBR, $(@($entries | Where-Object { $_.Kind -eq 'DevicePath' }).Count) device path"
            $otherCount = @($entries | Where-Object { @("GPT", "MBR", "DevicePath") -notcontains $_.Kind }).Count
            if ($otherCount -gt 0) { $kindCounts += ", $otherCount other" }
            Log "  Parsed $($entries.Count) mounted device value(s) ($kindCounts) from $($mounted.Source)"
        }
    }
    catch { Log-Warning "  Failed to parse mounted devices: $($_.Exception.Message)" }

    # SetupAPI device logs (device first-install times). Windows rotates setupapi.dev.log
    # to setupapi.dev.<yyyymmdd_hhmmss>.log, so every setupapi.dev*.log is parsed.
    # Times are the examined system's local time. The logs record every device
    # and driver install (graphics card, audio, Bluetooth, software devices, ...):
    # USB devices are USBDevice rows, all others Installation rows.
    $setupApiFiles = @(Find-SetupApiLogFiles)
    Log "  Found $($setupApiFiles.Count) SetupAPI log(s)."
    # Logs the collector saved but that are not here were lost after collection
    $setupApiManifest = Compare-ManifestSetupApiLogs -Found $setupApiFiles
    if ($setupApiManifest.Missing.Count -gt 0) {
        Log-Warning "  SetupAPI log(s) missing: the collection manifest lists $($setupApiManifest.Listed.Count), $($setupApiManifest.Missing.Count) of them are not here -- their device installs are not in the timeline: $($setupApiManifest.Missing -join ', ')"
    }
    $seenSetupApi = @{}
    $sectionFormats = [string[]]@("yyyy/MM/dd HH:mm:ss.fff", "yyyy/MM/dd HH:mm:ss")
    foreach ($logFile2 in $setupApiFiles) {
        Log "  Parsing: $($logFile2.FullName)"
        try {
            $content = [System.IO.File]::ReadAllLines($logFile2.FullName)
            $count = 0
            $usbCount = 0
            $dupes = 0
            for ($i = 0; $i -lt $content.Length; $i++) {
                $line = $content[$i]
                if (-not $line.StartsWith(">>>")) { continue }
                # e.g. ">>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_...\SERIAL&0]"
                if ($line -notmatch '^>>>\s+\[(Device Install \(([^)]*)\)|Delete Device) - (.+)\]\s*$') { continue }
                $isDelete = $Matches[1] -eq "Delete Device"
                $trigger = $Matches[2]
                $instance = $Matches[3].Trim()
                $isUsb = Test-UsbDeviceInstance $instance
                # Deletions are only interesting for USB devices
                if ($isDelete -and -not $isUsb) { continue }

                # ">>>  Section start 2026/10/06 20:19:08.123" follows the header
                $localText = $null
                for ($j = $i + 1; $j -le $i + 3 -and $j -lt $content.Length; $j++) {
                    if ($content[$j] -match '^>>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)') {
                        $localText = $Matches[1] -replace '\s+', ' '
                        break
                    }
                }
                if (-not $localText) { continue }
                $local = [datetime]::MinValue
                if (-not [datetime]::TryParseExact($localText, $sectionFormats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$local)) { continue }
                $ts = ConvertFrom-TargetLocalTime $local

                # Rotated logs can overlap -- report each event once
                $key = "$isDelete|$instance|$($ts.Ticks)"
                if ($seenSetupApi.ContainsKey($key)) { $dupes++; continue }
                $seenSetupApi[$key] = $true

                $label = Get-DeviceInstanceLabel $instance
                if ($isDelete) {
                    $desc = "Device deleted (setupapi): $label"
                    $details = "Instance=$instance Action=Delete Device LogTime=$localText (target local time)"
                }
                else {
                    $desc = "Device install: $label"
                    $details = "Instance=$instance Action=Device Install ($trigger) LogTime=$localText (target local time)"
                }
                $eventType = "Installation"
                if ($isUsb) {
                    $eventType = "USBDevice"
                    $usbCount++
                }
                Add-TimelineEntry -Timestamp $ts -Source "USB-SetupAPI" -EventType $eventType `
                    -Description $desc `
                    -Details $details `
                    -Artifact "USB" -RawPath $logFile2.FullName
                $usbParsed = $true
                $count++
            }
            Log "  Parsed $count SetupAPI device event(s): $usbCount USB, $($count - $usbCount) other device or driver install(s) ($dupes duplicate(s) from other log files skipped)."
        }
        catch { Log-Warning "  Failed to parse SetupAPI log: $($_.Exception.Message)" }
    }

    if (-not $usbParsed) { Log-Warning "No USB artifacts found." }
    Log "  USB parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 12. Persistence Artifacts Parser
# ----------------------------------------------------------

# Split collector text into "=== <title> ===" sections. Returns objects with
# Title and Lines (the lines up to the next section header).
function Split-CollectorTextSections {
    param([string[]]$Lines)
    $sections = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^=== (.+) ===\s*$') {
            $current = [PSCustomObject]@{ Title = $Matches[1].Trim(); Lines = (New-Object System.Collections.Generic.List[string]) }
            $sections.Add($current)
        }
        elseif ($current) {
            $current.Lines.Add($line)
        }
    }
    return $sections
}

# Parse Format-List text ("Name   : value", long values continued on
# indented lines) into Name/Value objects; a blank line ends an entry
function ConvertFrom-FormatListText {
    param([string[]]$Lines)
    $entries = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($line in $Lines) {
        if (-not $line.Trim()) { $current = $null; continue }
        if ($line -match '^(\S.*?)\s+: ?(.*)$') {
            $current = [PSCustomObject]@{ Name = $Matches[1]; Value = $Matches[2] }
            $entries.Add($current)
        }
        elseif ($current -and $line -match '^\s+\S') {
            # Wrapped value: the break keeps its trailing space, if any
            $current.Value += $line.TrimStart()
        }
    }
    foreach ($e in $entries) { $e.Value = $e.Value.Trim() }
    return $entries
}

function Parse-Persistence {
    Log "--- Parsing Persistence Artifacts ---"

    $persistParsed = $false

    # Run / RunOnce keys. run_keys.csv (newer collectors) carries the key's
    # last-write time; the older run_keys.txt (Format-List text, still written
    # for humans) only gives Snapshot rows and is skipped next to a CSV.
    $runKeyCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("run_keys.csv")
    foreach ($csv in $runKeyCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $snapshotTs = Get-SnapshotTimeUtc -File $csv
            $rowCount = 0
            foreach ($rk in (Import-Csv -Path $csv.FullName -ErrorAction Stop)) {
                $hive = Get-ArtifactRowValue $rk @("Hive")
                $keyPath = Get-ArtifactRowValue $rk @("KeyPath")
                $fullKey = if ($hive -and $keyPath -notmatch '^HK') { "$hive\$keyPath" } else { $keyPath }
                $valueName = Get-ArtifactRowValue $rk @("ValueName")
                $details = Format-ArtifactDetails ([ordered]@{ Command = Get-ArtifactRowValue $rk @("Command"); Key = $fullKey })
                $rkUser = Get-ArtifactRowValue $rk @("User")
                $keyWrite = ConvertFrom-UtcText (Get-ArtifactRowValue $rk @("KeyLastWriteUtc"))
                if ($keyWrite) {
                    Add-TimelineEntry -Timestamp $keyWrite -Source "Persistence-RunKeys" -EventType "PersistenceChange" `
                        -Description "Run key last written: $fullKey (value: $valueName)" `
                        -User $rkUser -Details $details `
                        -Artifact "Persistence" -RawPath $csv.FullName
                }
                elseif ($snapshotTs) {
                    Add-TimelineEntry -Timestamp $snapshotTs -Source "Persistence-RunKeys" -EventType "Snapshot" `
                        -Description "Run key value: $valueName [$fullKey]" `
                        -User $rkUser -Details $details `
                        -Artifact "Persistence" -RawPath $csv.FullName
                }
                $rowCount++
                $persistParsed = $true
            }
            Log "    $rowCount row(s)"
        }
        catch { Log-Warning "  Failed to parse run keys CSV: $($_.Exception.Message)" }
    }

    $runKeyFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("run_keys.txt")
    foreach ($rkFile in $runKeyFiles) {
        if (Test-Path (Join-Path $rkFile.DirectoryName "run_keys.csv")) { continue }
        Log "  Parsing: $($rkFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $rkFile
            $rowCount = 0
            foreach ($section in (Split-CollectorTextSections -Lines (Get-Content -Path $rkFile.FullName -ErrorAction Stop))) {
                # Shell Folders / User Shell Folders hold folder locations, not autostart entries
                if ($section.Title -match 'Shell Folders') { continue }
                foreach ($v in (ConvertFrom-FormatListText -Lines $section.Lines.ToArray())) {
                    # Get-ItemProperty adds PS* provider properties to every key
                    if ($v.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
                    Add-TimelineEntry -Timestamp $ts -Source "Persistence-RunKeys" -EventType "Snapshot" `
                        -Description "Run key value: $($v.Name) [$($section.Title)]" `
                        -Details "Command=$($v.Value)" `
                        -Artifact "Persistence" -RawPath $rkFile.FullName
                    $rowCount++
                    $persistParsed = $true
                }
            }
            Log "    $rowCount snapshot row(s)"
        }
        catch { Log-Warning "  Failed to parse run keys: $($_.Exception.Message)" }
    }

    # Startup entries CSV (Win32_StartupCommand: collection-time list, no times)
    $startupCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("startup_entries.csv")
    foreach ($csv in $startupCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $csv
            $entries = Import-Csv -Path $csv.FullName -ErrorAction Stop
            foreach ($entry in $entries) {
                $name = Get-ArtifactRowValue $entry @("Name")
                if (-not $name) { $name = "Unknown" }
                $location = Get-ArtifactRowValue $entry @("Location")
                $desc = "Startup entry: $name"
                if ($location) { $desc += " [$location]" }

                Add-TimelineEntry -Timestamp $ts -Source "Persistence-Startup" -EventType "Snapshot" `
                    -Description $desc `
                    -User (Get-ArtifactRowValue $entry @("User")) `
                    -Details (Format-ArtifactDetails ([ordered]@{ Command = Get-ArtifactRowValue $entry @("Command"); Location = $location })) `
                    -Artifact "Persistence" -RawPath $csv.FullName
                $persistParsed = $true
            }
        }
        catch { Log-Warning "  Failed to parse startup entries: $($_.Exception.Message)" }
    }

    # Startup folders. startup_folders.csv (newer collectors) has the items'
    # original created / modified times; the older startup_folders.txt
    # (Format-Table per folder) only gives Snapshot rows.
    $startupFolderCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("startup_folders.csv")
    foreach ($csv in $startupFolderCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $snapshotTs = Get-SnapshotTimeUtc -File $csv
            $rowCount = 0
            foreach ($sfRow in (Import-Csv -Path $csv.FullName -ErrorAction Stop)) {
                $name = Get-ArtifactRowValue $sfRow @("Name")
                if (-not $name -or $name -eq "desktop.ini") { continue }
                $folder = Get-ArtifactRowValue $sfRow @("Folder")
                $itemPath = if ($folder) { $folder.TrimEnd('\') + "\" + $name } else { $name }
                $sfUser = Get-ArtifactRowValue $sfRow @("User")
                $details = Format-ArtifactDetails ([ordered]@{ Scope = Get-ArtifactRowValue $sfRow @("Scope"); User = $sfUser })
                $created = ConvertFrom-UtcText (Get-ArtifactRowValue $sfRow @("CreatedUtc"))
                $modified = ConvertFrom-UtcText (Get-ArtifactRowValue $sfRow @("ModifiedUtc"))
                if ($created) {
                    Add-TimelineEntry -Timestamp $created -Source "Persistence-StartupFolder" -EventType "PersistenceChange" `
                        -Description "Startup folder item created: $itemPath" `
                        -User $sfUser -Details $details `
                        -Artifact "Persistence" -RawPath $csv.FullName
                    $rowCount++
                }
                if ($modified -and (-not $created -or $modified -ne $created)) {
                    Add-TimelineEntry -Timestamp $modified -Source "Persistence-StartupFolder" -EventType "PersistenceChange" `
                        -Description "Startup folder item modified: $itemPath" `
                        -User $sfUser -Details $details `
                        -Artifact "Persistence" -RawPath $csv.FullName
                    $rowCount++
                }
                if (-not $created -and -not $modified -and $snapshotTs) {
                    Add-TimelineEntry -Timestamp $snapshotTs -Source "Persistence-StartupFolder" -EventType "Snapshot" `
                        -Description "Startup folder item: $itemPath" `
                        -User $sfUser -Details $details `
                        -Artifact "Persistence" -RawPath $csv.FullName
                    $rowCount++
                }
                $persistParsed = $true
            }
            Log "    $rowCount row(s)"
        }
        catch { Log-Warning "  Failed to parse startup folders CSV: $($_.Exception.Message)" }
    }

    $startupFolderFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("startup_folders.txt")
    foreach ($sf in $startupFolderFiles) {
        if (Test-Path (Join-Path $sf.DirectoryName "startup_folders.csv")) { continue }
        Log "  Parsing: $($sf.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $sf
            $rowCount = 0
            foreach ($section in (Split-CollectorTextSections -Lines (Get-Content -Path $sf.FullName -ErrorAction Stop))) {
                foreach ($item in @(ConvertFrom-FormatTableText -Lines $section.Lines.ToArray())) {
                    $name = Get-ArtifactRowValue $item @("Name")
                    if (-not $name -or $name -eq "desktop.ini") { continue }
                    # LastWriteTime is the collector's local-time rendering, kept as text
                    Add-TimelineEntry -Timestamp $ts -Source "Persistence-StartupFolder" -EventType "Snapshot" `
                        -Description "Startup folder item: $($section.Title.TrimEnd('\'))\$name" `
                        -Details (Format-ArtifactDetails ([ordered]@{ LastWriteTime = Get-ArtifactRowValue $item @("LastWriteTime"); Length = Get-ArtifactRowValue $item @("Length") })) `
                        -Artifact "Persistence" -RawPath $sf.FullName
                    $rowCount++
                    $persistParsed = $true
                }
            }
            Log "    $rowCount snapshot row(s)"
        }
        catch { Log-Warning "  Failed to parse startup folders: $($_.Exception.Message)" }
    }

    # Drivers CSV (Win32_SystemDriver): same handling as services.csv
    $driverCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("drivers.csv")
    foreach ($csv in $driverCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $count = Add-ServiceListEntries -Csv $csv -Kind "Driver" -Source "Persistence-Drivers" -Artifact "Persistence"
            if ($count -gt 0) { $persistParsed = $true }
        }
        catch { Log-Warning "  Failed to parse drivers CSV: $($_.Exception.Message)" }
    }

    # WMI event subscriptions CSV (Type, Filter, Consumer, Details). The
    # collector records no creation time, so these are listed at collection
    # time; they stay PersistenceChange so they stand out.
    $wmiCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("wmi_subscriptions.csv")
    foreach ($csv in $wmiCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $csv
            # "No WMI event subscriptions found." leaves a CSV without a Type column
            $subs = @(Import-Csv -Path $csv.FullName -ErrorAction Stop | Where-Object { $_.PSObject.Properties["Type"] -or $_.PSObject.Properties["Name"] })
            foreach ($sub in $subs) {
                $type = Get-ArtifactRowValue $sub @("Type", "__CLASS")
                $filter = Get-ArtifactRowValue $sub @("Filter")
                $consumer = Get-ArtifactRowValue $sub @("Consumer", "Name")
                $info = Get-ArtifactRowValue $sub @("Details")
                if ($type -eq "Binding") {
                    $desc = "WMI filter-to-consumer binding (present at collection): $filter -> $consumer"
                    $details = ""
                }
                elseif ($type -eq "Filter") {
                    $desc = "WMI event filter (present at collection): $filter"
                    $details = Format-ArtifactDetails ([ordered]@{ Query = $info })
                }
                else {
                    # Consumer: Details holds the consumer's Format-List text; keep
                    # the properties that say what it runs
                    $props = [ordered]@{}
                    foreach ($p in (ConvertFrom-FormatListText -Lines ($info -split "`r?`n"))) {
                        if ($p.Name -match '^(__CLASS|CommandLineTemplate|ExecutablePath|WorkingDirectory|ScriptingEngine|ScriptFileName|ScriptText|SourceName|EventID|URL)$') {
                            $props[$p.Name] = $p.Value
                        }
                    }
                    $class = $props["__CLASS"]
                    $desc = "WMI event consumer (present at collection): $consumer"
                    if ($class) { $desc += " ($class)" }
                    elseif ($type -and $type -ne "Consumer") { $desc += " ($type)" }
                    $props.Remove("__CLASS")
                    $details = Format-ArtifactDetails $props
                    if ($details.Length -gt 1000) { $details = $details.Substring(0, 1000) + "..." }
                }

                Add-TimelineEntry -Timestamp $ts -Source "Persistence-WMI" -EventType "PersistenceChange" `
                    -Description $desc -Details $details `
                    -Artifact "Persistence" -RawPath $csv.FullName
                $persistParsed = $true
            }
            Log "    $($subs.Count) row(s)"
        }
        catch { Log-Warning "  Failed to parse WMI subscriptions: $($_.Exception.Message)" }
    }

    # Modules loaded from outside Windows / Program Files at collection time
    # (Format-Table -Wrap of ProcessName, PID, FileName)
    $dllFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("loaded_dlls_suspicious.txt")
    foreach ($dllFile in $dllFiles) {
        Log "  Parsing: $($dllFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $dllFile
            $rowCount = 0
            foreach ($module in @(ConvertFrom-FormatTableText -Lines (Get-Content -Path $dllFile.FullName -ErrorAction Stop))) {
                $file = Get-ArtifactRowValue $module @("FileName")
                if (-not $file) { continue }
                $proc = Get-ArtifactRowValue $module @("ProcessName")
                $procId = Get-ArtifactRowValue $module @("PID", "Id")
                Add-TimelineEntry -Timestamp $ts -Source "Persistence-SuspiciousDLL" -EventType "Snapshot" `
                    -Description "Module loaded from outside Windows/Program Files: $file ($proc, PID $procId)" `
                    -Details (Format-ArtifactDetails ([ordered]@{ Process = $proc; PID = $procId })) `
                    -Artifact "Persistence" -RawPath $dllFile.FullName
                $rowCount++
                $persistParsed = $true
            }
            Log "    $rowCount snapshot row(s)"
        }
        catch { Log-Warning "  Failed to parse suspicious DLLs: $($_.Exception.Message)" }
    }

    if (-not $persistParsed) { Log-Warning "No persistence artifacts found." }
    Log "  Persistence parsing complete."
    Log ""
}

# ----------------------------------------------------------
# SRUM Parser (System Resource Usage Monitor)
# ----------------------------------------------------------
# Execution\SRUM\SRUDB.dat from the collector is an ESE (Extensible Storage
# Engine) database that Windows updates about once an hour with
# per-application, per-user resource use. It is read with the Windows ESE
# engine itself (esent.dll) through the C# below:
# - The database is attached read-only to a private ESE instance with
#   recovery off (nothing is logged or written), using the page size from
#   the database header (offset 236; 0 means 4 KB), which must match.
# - A copy in dirty-shutdown state is first brought to a clean state by
#   soft recovery in this process (EseRecovery: the collected transaction
#   logs are replayed into the temp copy, event logging off).
# - Column names, ids and types come from JetGetTableColumnInfo
#   (JET_ColInfoList: a temporary table with one row per column); records
#   are read with JetMove / JetRetrieveColumn.
# - SruDbIdMapTable maps the AppId and UserId of every record to text:
#   IdType 3 entries hold a binary user SID, the others a UTF-16 application
#   path or name (IdBlob).
# - Network Data Usage {973F5D5C-1D90-4944-BE8E-24B94231A174} and
#   Application Resource Usage {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} hold
#   one record per application and user per hour (TimeStamp: an OLE
#   Automation date in UTC). Records are summed per application, user and
#   UTC day in C#, so a large database stays fast and the timeline readable.
#   A read error (damaged page) stops a table's scan but keeps the sums of
#   the records read before it (SrumTableResult.Error).
# C# 5 (Windows PowerShell 5.1 compiler): no interpolation, no "=>" members.
# The ESE constants and signatures follow esent.h (Microsoft ESE headers).
function Initialize-SrumReader {
    if ($null -ne $script:srumReaderReady) { return $script:srumReaderReady }
    $script:srumReaderReady = $false
    try {
        if (-not ([System.Management.Automation.PSTypeName]'TimelineEse.SrumReader').Type) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace TimelineEse
{
    // An ESENT call that failed, with its JET_ERR code
    public sealed class EseException : Exception
    {
        public EseException(string api, int error)
            : base(api + " failed: " + EseErrors.Describe(error))
        {
            Api = api;
            Error = error;
        }
        public string Api { get; private set; }
        public int Error { get; private set; }
    }

    public static class EseErrors
    {
        // Name of the common JET_ERR codes (esent.h), else the number
        public static string Describe(int error)
        {
            string name = null;
            switch (error)
            {
                case -327: name = "JET_errBadPageLink"; break;
                case -501: name = "JET_errLogFileCorrupt"; break;
                case -528: name = "JET_errMissingLogFile"; break;
                case -533: name = "JET_errCheckpointCorrupt"; break;
                case -539: name = "JET_errDatabaseLogSetMismatch"; break;
                case -541: name = "JET_errLogFileSizeMismatch"; break;
                case -543: name = "JET_errRequiredLogFilesMissing"; break;
                case -550: name = "JET_errDatabaseDirtyShutdown"; break;
                case -1003: name = "JET_errInvalidParameter"; break;
                case -1008: name = "JET_errDatabaseFileReadOnly"; break;
                case -1011: name = "JET_errOutOfMemory"; break;
                case -1018: name = "JET_errReadVerifyFailure"; break;
                case -1019: name = "JET_errPageNotInitialized"; break;
                case -1022: name = "JET_errDiskIO"; break;
                case -1023: name = "JET_errInvalidPath"; break;
                case -1030: name = "JET_errAlreadyInitialized"; break;
                case -1032: name = "JET_errFileAccessDenied"; break;
                case -1206: name = "JET_errDatabaseCorrupted"; break;
                case -1209: name = "JET_errInvalidDatabaseVersion"; break;
                case -1213: name = "JET_errPageSizeMismatch"; break;
                case -1216: name = "JET_errAttachedDatabaseMismatch"; break;
                case -1305: name = "JET_errObjectNotFound"; break;
                case -1414: name = "JET_errSecondaryIndexCorrupted"; break;
                case -1507: name = "JET_errColumnNotFound"; break;
                case -1603: name = "JET_errNoCurrentRecord"; break;
                case -1811: name = "JET_errFileNotFound"; break;
            }
            if (name == null) return "JET error " + error.ToString(CultureInfo.InvariantCulture);
            return name + " (" + error.ToString(CultureInfo.InvariantCulture) + ")";
        }
    }

    // JET_COLUMNLIST
    [StructLayout(LayoutKind.Sequential)]
    internal struct JetColumnList
    {
        public uint cbStruct;
        public IntPtr tableid;
        public uint cRecord;
        public uint columnidPresentationOrder;
        public uint columnidcolumnname;
        public uint columnidcolumnid;
        public uint columnidcoltyp;
        public uint columnidCountry;
        public uint columnidLangid;
        public uint columnidCp;
        public uint columnidCollate;
        public uint columnidcbMax;
        public uint columnidgrbit;
        public uint columnidDefault;
        public uint columnidBaseTableName;
        public uint columnidBaseColumnName;
        public uint columnidDefinitionName;
    }

    // esent.dll exports (Unicode variants). JET_INSTANCE, JET_SESID and
    // JET_TABLEID are pointer-sized; JET_DBID, JET_COLUMNID and JET_GRBIT
    // are 32-bit unsigned; JET_ERR is a 32-bit signed result.
    internal static class NativeMethods
    {
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetCreateInstance2W(out IntPtr pinstance, string szInstanceName, string szDisplayName, uint grbit);

        // pinstance NULL: process-wide parameter (database page size)
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetSetSystemParameterW(IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "JetSetSystemParameterW")]
        internal static extern int JetSetInstanceParameterW(ref IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetInit(ref IntPtr pinstance);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetTerm2(IntPtr instance, uint grbit);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetBeginSessionW(IntPtr instance, out IntPtr psesid, string szUserName, string szPassword);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetEndSession(IntPtr sesid, uint grbit);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetAttachDatabase2W(IntPtr sesid, string szFilename, uint cpgDatabaseSizeMax, uint grbit);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetDetachDatabaseW(IntPtr sesid, string szFilename);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetOpenDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint pdbid, uint grbit);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetCloseDatabase(IntPtr sesid, uint dbid, uint grbit);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetOpenTableW(IntPtr sesid, uint dbid, string szTableName, IntPtr pvParameters, uint cbParameters, uint grbit, out IntPtr ptableid);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);

        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetGetTableColumnInfoW(IntPtr sesid, IntPtr tableid, string szColumnName, ref JetColumnList pvResult, uint cbMax, uint infoLevel);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetMove(IntPtr sesid, IntPtr tableid, int cRow, uint grbit);

        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetRetrieveColumn(IntPtr sesid, IntPtr tableid, uint columnid, byte[] pvData, uint cbData, out uint pcbActual, uint grbit, IntPtr pretinfo);
    }

    // Database file header (DBFILEHDR) fields: magic 0x89ABCDEF at offset 4,
    // format version at 8, database state at 52, page size at 236
    public sealed class EseHeader
    {
        public bool IsEse { get; private set; }
        public uint FormatVersion { get; private set; }
        public int State { get; private set; }
        public int PageSize { get; private set; }

        // JET_dbstate
        public string StateName
        {
            get
            {
                switch (State)
                {
                    case 1: return "just created";
                    case 2: return "dirty shutdown";
                    case 3: return "clean shutdown";
                    case 4: return "being converted";
                    case 5: return "force detach";
                    case 6: return "incremental reseed in progress";
                    case 7: return "dirty and patched shutdown";
                    case 8: return "revert in progress";
                }
                return "unknown state " + State.ToString(CultureInfo.InvariantCulture);
            }
        }

        public bool IsClean { get { return State == 3; } }

        public static EseHeader Read(string path)
        {
            EseHeader header = new EseHeader();
            byte[] buffer = new byte[240];
            int read = 0;
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                while (read < buffer.Length)
                {
                    int n = stream.Read(buffer, read, buffer.Length - read);
                    if (n <= 0) break;
                    read += n;
                }
            }
            if (read < buffer.Length || BitConverter.ToUInt32(buffer, 4) != 0x89ABCDEF) return header;
            header.IsEse = true;
            header.FormatVersion = BitConverter.ToUInt32(buffer, 8);
            header.State = BitConverter.ToInt32(buffer, 52);
            int pageSize = BitConverter.ToInt32(buffer, 236);
            header.PageSize = pageSize == 0 ? 4096 : pageSize;
            return header;
        }
    }

    public sealed class EseColumn
    {
        public string Name { get; set; }
        public uint ColumnId { get; set; }
        public uint ColumnType { get; set; }
        public int CodePage { get; set; }
    }

    // A database attached read-only to its own ESE instance with recovery
    // off, so the file is never written. Dispose closes everything.
    public sealed class EseDatabase : IDisposable
    {
        internal const uint ParamSystemPath = 0;
        internal const uint ParamTempPath = 1;
        internal const uint ParamLogFilePath = 2;
        internal const uint ParamBaseName = 3;
        internal const uint ParamLogFileSize = 11;
        internal const uint ParamRecovery = 34;
        internal const uint ParamEnableIndexChecking = 45;
        internal const uint ParamNoInformationEvent = 50;
        internal const uint ParamEventLoggingLevel = 51;
        internal const uint ParamDatabasePageSize = 64;
        internal const uint ParamCreatePathIfNotExist = 100;
        internal const uint ParamAlternateDatabaseRecoveryPath = 113;
        const uint BitDbReadOnly = 0x1;
        const uint BitTableReadOnly = 0x4;
        const uint BitTableSequential = 0x8000;
        const uint BitTermComplete = 0x1;
        const uint BitTermAbrupt = 0x2;
        internal const int ErrNoCurrentRecord = -1603;
        const int ErrObjectNotFound = -1305;
        internal const int ErrAlreadyInitialized = -1030;

        IntPtr instance;
        IntPtr sesid;
        uint dbid;
        bool attached;
        bool opened;
        readonly string path;

        // engineFolder: an empty folder for the instance's own files (its
        // temporary database)
        public EseDatabase(string databasePath, string engineFolder, int pageSize)
        {
            path = Path.GetFullPath(databasePath);
            string folder = Path.GetFullPath(engineFolder).TrimEnd('\\') + "\\";
            try
            {
                // Process-wide, so it is set before the instance is created
                int err = NativeMethods.JetSetSystemParameterW(IntPtr.Zero, IntPtr.Zero, ParamDatabasePageSize, new IntPtr(pageSize), null);
                if (err < 0 && err != ErrAlreadyInitialized) throw new EseException("JetSetSystemParameter(DatabasePageSize)", err);
                Check("JetCreateInstance2", NativeMethods.JetCreateInstance2W(out instance, "TimelineEse" + Guid.NewGuid().ToString("N"), "Timeline builder", 0));
                SetString(ParamSystemPath, folder);
                SetString(ParamTempPath, folder);
                SetString(ParamLogFilePath, folder);
                SetString(ParamBaseName, "tln");
                SetString(ParamRecovery, "Off");
                SetNumber(ParamCreatePathIfNotExist, 1);
                // Event logging off: normally nothing goes to the analysis
                // machine's Application event log (for a damaged database
                // ESE may still log a diagnostic event, ID 901)
                SetNumber(ParamNoInformationEvent, 1);
                SetNumber(ParamEventLoggingLevel, 0);
                // Indexes are not checked against this machine's sort order
                // (the database comes from another Windows build)
                SetNumber(ParamEnableIndexChecking, 0);
                // On failure JetInit frees the instance and sets it to 0
                Check("JetInit", NativeMethods.JetInit(ref instance));
                Check("JetBeginSession", NativeMethods.JetBeginSessionW(instance, out sesid, null, null));
                Check("JetAttachDatabase2", NativeMethods.JetAttachDatabase2W(sesid, path, 0, BitDbReadOnly));
                attached = true;
                Check("JetOpenDatabase", NativeMethods.JetOpenDatabaseW(sesid, path, null, out dbid, BitDbReadOnly));
                opened = true;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal IntPtr Session { get { return sesid; } }

        static void Check(string api, int err)
        {
            if (err < 0) throw new EseException(api, err);
        }

        void SetString(uint param, string value)
        {
            Check("JetSetSystemParameter(" + param.ToString(CultureInfo.InvariantCulture) + ")",
                NativeMethods.JetSetInstanceParameterW(ref instance, IntPtr.Zero, param, IntPtr.Zero, value));
        }

        void SetNumber(uint param, int value)
        {
            Check("JetSetSystemParameter(" + param.ToString(CultureInfo.InvariantCulture) + ")",
                NativeMethods.JetSetInstanceParameterW(ref instance, IntPtr.Zero, param, new IntPtr(value), null));
        }

        // The table, or null if the database has no table of that name
        public EseTable OpenTable(string name)
        {
            IntPtr tableid;
            int err = NativeMethods.JetOpenTableW(sesid, dbid, name, IntPtr.Zero, 0, BitTableReadOnly | BitTableSequential, out tableid);
            if (err == ErrObjectNotFound) return null;
            Check("JetOpenTable(" + name + ")", err);
            try { return new EseTable(this, name, tableid); }
            catch
            {
                NativeMethods.JetCloseTable(sesid, tableid);
                throw;
            }
        }

        public void Dispose()
        {
            try
            {
                if (opened) NativeMethods.JetCloseDatabase(sesid, dbid, 0);
            }
            finally
            {
                opened = false;
                try
                {
                    if (attached) NativeMethods.JetDetachDatabaseW(sesid, path);
                }
                finally
                {
                    attached = false;
                    try
                    {
                        if (sesid != IntPtr.Zero) NativeMethods.JetEndSession(sesid, 0);
                    }
                    finally
                    {
                        sesid = IntPtr.Zero;
                        if (instance != IntPtr.Zero && NativeMethods.JetTerm2(instance, BitTermComplete) < 0)
                        {
                            NativeMethods.JetTerm2(instance, BitTermAbrupt);
                        }
                        instance = IntPtr.Zero;
                    }
                }
            }
        }
    }

    // Soft recovery of a database copy in this process: a private instance
    // with recovery on replays the transaction logs in logFolder (base name,
    // checkpoint and logs) into the database file in databaseFolder. The
    // logs name the database by its original path;
    // JET_paramAlternateDatabaseRecoveryPath makes the engine look for it in
    // databaseFolder only, so the original is never touched. Event logging
    // is off, as in the reader. logFileSizeKb: the size of the collected log
    // files (JET_paramLogFileSize must match them), 0 for the default.
    // Throws EseException when JetInit fails; the caller reads the database
    // header to see whether the copy is now clean.
    public static class EseRecovery
    {
        public static void Recover(string logFolder, string baseName, string databaseFolder, string engineFolder, int pageSize, int logFileSizeKb)
        {
            string logs = Path.GetFullPath(logFolder).TrimEnd('\\') + "\\";
            string databases = Path.GetFullPath(databaseFolder).TrimEnd('\\');
            string engine = Path.GetFullPath(engineFolder).TrimEnd('\\') + "\\";
            IntPtr instance = IntPtr.Zero;
            try
            {
                // Process-wide, so it is set before the instance is created
                int err = NativeMethods.JetSetSystemParameterW(IntPtr.Zero, IntPtr.Zero, EseDatabase.ParamDatabasePageSize, new IntPtr(pageSize), null);
                if (err < 0 && err != EseDatabase.ErrAlreadyInitialized) throw new EseException("JetSetSystemParameter(DatabasePageSize)", err);
                Check("JetCreateInstance2", NativeMethods.JetCreateInstance2W(out instance, "TimelineEseRecovery" + Guid.NewGuid().ToString("N"), "Timeline builder recovery", 0));
                // Checkpoint (system path) and logs: the collected ones
                SetString(ref instance, EseDatabase.ParamSystemPath, logs);
                SetString(ref instance, EseDatabase.ParamLogFilePath, logs);
                SetString(ref instance, EseDatabase.ParamTempPath, engine);
                SetString(ref instance, EseDatabase.ParamBaseName, baseName);
                SetString(ref instance, EseDatabase.ParamRecovery, "On");
                SetString(ref instance, EseDatabase.ParamAlternateDatabaseRecoveryPath, databases);
                if (logFileSizeKb > 0) SetNumber(ref instance, EseDatabase.ParamLogFileSize, logFileSizeKb);
                SetNumber(ref instance, EseDatabase.ParamCreatePathIfNotExist, 1);
                SetNumber(ref instance, EseDatabase.ParamNoInformationEvent, 1);
                SetNumber(ref instance, EseDatabase.ParamEventLoggingLevel, 0);
                SetNumber(ref instance, EseDatabase.ParamEnableIndexChecking, 0);
                // Recovery runs inside JetInit; on failure JetInit frees the
                // instance and sets it to 0
                Check("JetInit (soft recovery)", NativeMethods.JetInit(ref instance));
            }
            finally
            {
                if (instance != IntPtr.Zero && NativeMethods.JetTerm2(instance, 0x1) < 0)   // JET_bitTermComplete
                {
                    NativeMethods.JetTerm2(instance, 0x2);                                  // JET_bitTermAbrupt
                }
            }
        }

        static void Check(string api, int err)
        {
            if (err < 0) throw new EseException(api, err);
        }

        static void SetString(ref IntPtr instance, uint param, string value)
        {
            Check("JetSetSystemParameter(" + param.ToString(CultureInfo.InvariantCulture) + ")",
                NativeMethods.JetSetInstanceParameterW(ref instance, IntPtr.Zero, param, IntPtr.Zero, value));
        }

        static void SetNumber(ref IntPtr instance, uint param, int value)
        {
            Check("JetSetSystemParameter(" + param.ToString(CultureInfo.InvariantCulture) + ")",
                NativeMethods.JetSetInstanceParameterW(ref instance, IntPtr.Zero, param, new IntPtr(value), null));
        }
    }

    // A read-only cursor on one table, with its columns by name
    public sealed class EseTable : IDisposable
    {
        const uint ColInfoList = 1;
        const int WrnColumnNull = 1004;
        const int WrnBufferTruncated = 1006;
        readonly EseDatabase database;
        IntPtr tableid;
        byte[] buffer = new byte[256];
        readonly Dictionary<string, EseColumn> columns = new Dictionary<string, EseColumn>(StringComparer.OrdinalIgnoreCase);

        internal EseTable(EseDatabase database, string name, IntPtr tableid)
        {
            this.database = database;
            this.tableid = tableid;
            Name = name;
            ReadColumns();
        }

        public string Name { get; private set; }

        public EseColumn GetColumn(string name)
        {
            EseColumn column;
            return columns.TryGetValue(name, out column) ? column : null;
        }

        public string[] ColumnNames
        {
            get
            {
                string[] names = new string[columns.Count];
                columns.Keys.CopyTo(names, 0);
                Array.Sort(names, StringComparer.Ordinal);
                return names;
            }
        }

        // JetGetTableColumnInfo with JET_ColInfoList opens a temporary table
        // with one row per column (it must be closed with JetCloseTable)
        void ReadColumns()
        {
            IntPtr sesid = database.Session;
            JetColumnList list = new JetColumnList();
            list.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnList));
            int err = NativeMethods.JetGetTableColumnInfoW(sesid, tableid, null, ref list, list.cbStruct, ColInfoList);
            if (err < 0) throw new EseException("JetGetTableColumnInfo(" + Name + ")", err);
            try
            {
                err = NativeMethods.JetMove(sesid, list.tableid, int.MinValue, 0);   // JET_MoveFirst
                while (err >= 0)
                {
                    byte[] nameBytes = Retrieve(list.tableid, list.columnidcolumnname);
                    byte[] idBytes = Retrieve(list.tableid, list.columnidcolumnid);
                    byte[] typeBytes = Retrieve(list.tableid, list.columnidcoltyp);
                    byte[] cpBytes = Retrieve(list.tableid, list.columnidCp);
                    if (nameBytes != null && idBytes != null && idBytes.Length >= 4 && typeBytes != null && typeBytes.Length >= 4)
                    {
                        EseColumn column = new EseColumn();
                        // Unicode API: the names are UTF-16
                        column.Name = Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');
                        column.ColumnId = BitConverter.ToUInt32(idBytes, 0);
                        column.ColumnType = BitConverter.ToUInt32(typeBytes, 0);
                        column.CodePage = (cpBytes != null && cpBytes.Length >= 2) ? BitConverter.ToUInt16(cpBytes, 0) : 0;
                        columns[column.Name] = column;
                    }
                    err = NativeMethods.JetMove(sesid, list.tableid, 1, 0);         // JET_MoveNext
                }
                if (err != EseDatabase.ErrNoCurrentRecord) throw new EseException("JetMove(column list of " + Name + ")", err);
            }
            finally
            {
                NativeMethods.JetCloseTable(sesid, list.tableid);
            }
        }

        // Reads a column of the current record into the buffer; returns its
        // length, or -1 when the column is NULL
        int RetrieveIntoBuffer(IntPtr table, uint columnid)
        {
            uint actual;
            int err = NativeMethods.JetRetrieveColumn(database.Session, table, columnid, buffer, (uint)buffer.Length, out actual, 0, IntPtr.Zero);
            if (err == WrnBufferTruncated)
            {
                buffer = new byte[Math.Max((int)actual, buffer.Length * 2)];
                err = NativeMethods.JetRetrieveColumn(database.Session, table, columnid, buffer, (uint)buffer.Length, out actual, 0, IntPtr.Zero);
            }
            if (err == WrnColumnNull) return -1;
            if (err < 0) throw new EseException("JetRetrieveColumn(" + Name + ")", err);
            return (int)Math.Min(actual, (uint)buffer.Length);
        }

        byte[] Retrieve(IntPtr table, uint columnid)
        {
            int length = RetrieveIntoBuffer(table, columnid);
            if (length < 0) return null;
            byte[] value = new byte[length];
            Buffer.BlockCopy(buffer, 0, value, 0, length);
            return value;
        }

        public bool MoveFirst()
        {
            int err = NativeMethods.JetMove(database.Session, tableid, int.MinValue, 0);
            if (err == EseDatabase.ErrNoCurrentRecord) return false;
            if (err < 0) throw new EseException("JetMove(" + Name + ")", err);
            return true;
        }

        public bool MoveNext()
        {
            int err = NativeMethods.JetMove(database.Session, tableid, 1, 0);
            if (err == EseDatabase.ErrNoCurrentRecord) return false;
            if (err < 0) throw new EseException("JetMove(" + Name + ")", err);
            return true;
        }

        // Raw bytes of a column of the current record; null when NULL
        public byte[] GetBytes(EseColumn column)
        {
            if (column == null) return null;
            return Retrieve(tableid, column.ColumnId);
        }

        // Integer column (also Bit, Currency and unsigned types) of the
        // current record; false when NULL or not an integer type
        public bool TryGetInt64(EseColumn column, out long value)
        {
            value = 0;
            if (column == null) return false;
            int length = RetrieveIntoBuffer(tableid, column.ColumnId);
            if (length < 0) return false;
            switch (column.ColumnType)
            {
                case 1:  // Bit
                case 2:  // UnsignedByte
                    if (length < 1) return false;
                    value = buffer[0];
                    return true;
                case 3:  // Short
                    if (length < 2) return false;
                    value = BitConverter.ToInt16(buffer, 0);
                    return true;
                case 17: // UnsignedShort
                    if (length < 2) return false;
                    value = BitConverter.ToUInt16(buffer, 0);
                    return true;
                case 4:  // Long
                    if (length < 4) return false;
                    value = BitConverter.ToInt32(buffer, 0);
                    return true;
                case 14: // UnsignedLong
                    if (length < 4) return false;
                    value = BitConverter.ToUInt32(buffer, 0);
                    return true;
                case 5:  // Currency (8-byte signed integer)
                case 15: // LongLong
                case 18: // UnsignedLongLong (values above 2^63 do not occur in SRUM)
                    if (length < 8) return false;
                    value = BitConverter.ToInt64(buffer, 0);
                    return true;
            }
            return false;
        }

        // Date column of the current record as UTC: JET_coltypDateTime (an
        // OLE Automation date) or an 8-byte FILETIME; false when NULL/invalid
        public bool TryGetUtcTime(EseColumn column, out DateTime value)
        {
            value = DateTime.MinValue;
            if (column == null) return false;
            int length = RetrieveIntoBuffer(tableid, column.ColumnId);
            if (length < 8) return false;
            if (column.ColumnType == 8)
            {
                double oa = BitConverter.ToDouble(buffer, 0);
                // DateTime.FromOADate accepts -657435 (year 100) to 2958466 (year 9999)
                if (double.IsNaN(oa) || oa <= -657435.0 || oa >= 2958466.0) return false;
                value = DateTime.SpecifyKind(DateTime.FromOADate(oa), DateTimeKind.Utc);
                return true;
            }
            if (column.ColumnType == 5 || column.ColumnType == 15 || column.ColumnType == 18)
            {
                long fileTime = BitConverter.ToInt64(buffer, 0);
                if (fileTime <= 0 || fileTime > DateTime.MaxValue.ToFileTimeUtc()) return false;
                value = DateTime.FromFileTimeUtc(fileTime);
                return true;
            }
            return false;
        }

        public void Dispose()
        {
            if (tableid != IntPtr.Zero)
            {
                NativeMethods.JetCloseTable(database.Session, tableid);
                tableid = IntPtr.Zero;
            }
        }
    }

    // One SruDbIdMapTable entry: an application (path or name) or a user SID
    public sealed class SrumIdEntry
    {
        public long IdType { get; set; }
        public long IdIndex { get; set; }
        public string Value { get; set; }
        public bool IsSid { get; set; }
    }

    // Records of one application for one user on one UTC day, summed
    public sealed class SrumDayTotal
    {
        readonly Dictionary<string, long> sums = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        readonly SortedDictionary<long, bool> interfaceTypes = new SortedDictionary<long, bool>();
        readonly SortedDictionary<long, bool> profileIds = new SortedDictionary<long, bool>();

        public long AppId { get; set; }
        public long UserId { get; set; }
        public DateTime Day { get; set; }
        public DateTime FirstUtc { get; set; }
        public DateTime LastUtc { get; set; }
        public long Records { get; set; }

        // Sum of a column over the records, or null if the table has no
        // such column
        public object Sum(string column)
        {
            long value;
            if (sums.TryGetValue(column, out value)) return value;
            return null;
        }

        internal void Add(string column, long value)
        {
            long current;
            sums.TryGetValue(column, out current);
            sums[column] = current + value;
        }

        internal void AddInterface(long ifType) { interfaceTypes[ifType] = true; }
        internal void AddProfile(long profileId) { profileIds[profileId] = true; }

        // IANA interface types (IfType of the InterfaceLuid) seen that day
        public long[] InterfaceTypes
        {
            get
            {
                long[] values = new long[interfaceTypes.Count];
                interfaceTypes.Keys.CopyTo(values, 0);
                return values;
            }
        }

        // Non-zero L2ProfileId values seen that day
        public long[] ProfileIds
        {
            get
            {
                long[] values = new long[profileIds.Count];
                profileIds.Keys.CopyTo(values, 0);
                return values;
            }
        }
    }

    public sealed class SrumTableResult
    {
        public SrumTableResult()
        {
            Days = new List<SrumDayTotal>();
            MissingColumns = new List<string>();
        }
        public string Table { get; set; }
        public bool Found { get; set; }
        public long RecordsRead { get; set; }
        public long RecordsWithoutTime { get; set; }
        public DateTime FirstUtc { get; set; }
        public DateTime LastUtc { get; set; }
        // The read error that stopped the scan (a damaged page), or null;
        // the sums cover the records read before it
        public string Error { get; set; }
        public List<string> MissingColumns { get; private set; }
        public List<SrumDayTotal> Days { get; private set; }
    }

    public static class SrumReader
    {
        // SruDbIdMapTable entries, or null if the database has no such table.
        // error: the read error that stopped the scan, or null; the entries
        // read before it are returned.
        public static List<SrumIdEntry> ReadIdMap(EseDatabase database, out string error)
        {
            error = null;
            EseTable table = database.OpenTable("SruDbIdMapTable");
            if (table == null) return null;
            List<SrumIdEntry> entries = new List<SrumIdEntry>();
            try
            {
                EseColumn typeColumn = table.GetColumn("IdType");
                EseColumn indexColumn = table.GetColumn("IdIndex");
                EseColumn blobColumn = table.GetColumn("IdBlob");
                if (typeColumn == null || indexColumn == null || blobColumn == null)
                {
                    throw new InvalidDataException("SruDbIdMapTable has no IdType, IdIndex or IdBlob column");
                }
                try
                {
                    bool more = table.MoveFirst();
                    while (more)
                    {
                        long idType;
                        long idIndex;
                        if (table.TryGetInt64(typeColumn, out idType) && table.TryGetInt64(indexColumn, out idIndex))
                        {
                            SrumIdEntry entry = new SrumIdEntry();
                            entry.IdType = idType;
                            entry.IdIndex = idIndex;
                            byte[] blob = table.GetBytes(blobColumn);
                            if (idType == 3)
                            {
                                entry.Value = SidToString(blob);
                                entry.IsSid = entry.Value != null;
                            }
                            if (entry.Value == null) entry.Value = BlobToText(blob);
                            entries.Add(entry);
                        }
                        more = table.MoveNext();
                    }
                }
                catch (EseException e)
                {
                    error = e.Message;
                }
            }
            finally
            {
                table.Dispose();
            }
            return entries;
        }

        // Binary SID (revision 1, sub-authority count, 6-byte big-endian
        // authority, 32-bit little-endian sub-authorities) as S-1-...
        public static string SidToString(byte[] data)
        {
            if (data == null || data.Length < 8 || data[0] != 1) return null;
            int count = data[1];
            if (count > 15 || data.Length < 8 + 4 * count) return null;
            long authority = 0;
            for (int i = 2; i < 8; i++) authority = (authority << 8) | data[i];
            StringBuilder text = new StringBuilder("S-1-");
            text.Append(authority.ToString(CultureInfo.InvariantCulture));
            for (int i = 0; i < count; i++)
            {
                text.Append('-').Append(BitConverter.ToUInt32(data, 8 + 4 * i).ToString(CultureInfo.InvariantCulture));
            }
            return text.ToString();
        }

        // IdBlob of an application: UTF-16 text; other data as hex
        static string BlobToText(byte[] blob)
        {
            if (blob == null || blob.Length == 0) return "";
            if (blob.Length % 2 == 0)
            {
                string text = Encoding.Unicode.GetString(blob).TrimEnd('\0');
                bool printable = text.Length > 0;
                foreach (char c in text)
                {
                    if (c < ' ' || c == '?') { printable = false; break; }
                }
                if (printable) return text;
            }
            int shown = Math.Min(blob.Length, 64);
            string hex = BitConverter.ToString(blob, 0, shown).Replace("-", "");
            return "0x" + hex + (shown < blob.Length ? "..." : "");
        }

        // Names of the common IANA interface types (ifType of a NET_LUID)
        public static string InterfaceTypeName(long ifType)
        {
            switch (ifType)
            {
                case 6: return "Ethernet";
                case 23: return "PPP";
                case 24: return "Loopback";
                case 71: return "Wi-Fi";
                case 131: return "Tunnel";
                case 243:
                case 244: return "Mobile broadband";
            }
            return "IfType " + ifType.ToString(CultureInfo.InvariantCulture);
        }

        // Sums the records of a SRUM table per AppId, UserId and UTC day of
        // TimeStamp: record count, first and last record time, the sum of
        // each listed column the table has, and (when present) the interface
        // types of InterfaceLuid and the L2ProfileId values
        public static SrumTableResult Aggregate(EseDatabase database, string tableName, string[] sumColumns)
        {
            SrumTableResult result = new SrumTableResult();
            result.Table = tableName;
            EseTable table = database.OpenTable(tableName);
            if (table == null) return result;
            result.Found = true;
            try
            {
                EseColumn timeColumn = table.GetColumn("TimeStamp");
                EseColumn appColumn = table.GetColumn("AppId");
                EseColumn userColumn = table.GetColumn("UserId");
                EseColumn luidColumn = table.GetColumn("InterfaceLuid");
                EseColumn profileColumn = table.GetColumn("L2ProfileId");
                foreach (string name in new string[] { "TimeStamp", "AppId", "UserId" })
                {
                    if (table.GetColumn(name) == null) result.MissingColumns.Add(name);
                }
                List<EseColumn> sumList = new List<EseColumn>();
                foreach (string name in sumColumns)
                {
                    EseColumn column = table.GetColumn(name);
                    if (column == null) result.MissingColumns.Add(name);
                    else sumList.Add(column);
                }
                if (timeColumn == null || appColumn == null) return result;

                Dictionary<string, SrumDayTotal> totals = new Dictionary<string, SrumDayTotal>(StringComparer.Ordinal);
                long[] values = new long[sumList.Count];
                try
                {
                    bool more = table.MoveFirst();
                    while (more)
                    {
                        // Every column of the record is read before anything
                        // is added, so a read error never leaves half a record
                        DateTime time;
                        if (!table.TryGetUtcTime(timeColumn, out time))
                        {
                            result.RecordsRead++;
                            result.RecordsWithoutTime++;
                            more = table.MoveNext();
                            continue;
                        }
                        long appId;
                        long userId;
                        if (!table.TryGetInt64(appColumn, out appId)) appId = 0;
                        if (!table.TryGetInt64(userColumn, out userId)) userId = 0;
                        for (int i = 0; i < sumList.Count; i++)
                        {
                            if (!table.TryGetInt64(sumList[i], out values[i])) values[i] = 0;
                        }
                        long luid;
                        if (!table.TryGetInt64(luidColumn, out luid)) luid = 0;
                        long profileId;
                        if (!table.TryGetInt64(profileColumn, out profileId)) profileId = 0;

                        result.RecordsRead++;
                        DateTime day = time.Date;
                        string key = appId.ToString(CultureInfo.InvariantCulture) + "|" + userId.ToString(CultureInfo.InvariantCulture) + "|" + day.Ticks.ToString(CultureInfo.InvariantCulture);
                        SrumDayTotal total;
                        if (!totals.TryGetValue(key, out total))
                        {
                            total = new SrumDayTotal();
                            total.AppId = appId;
                            total.UserId = userId;
                            total.Day = DateTime.SpecifyKind(day, DateTimeKind.Utc);
                            total.FirstUtc = time;
                            total.LastUtc = time;
                            totals[key] = total;
                        }
                        total.Records++;
                        if (time < total.FirstUtc) total.FirstUtc = time;
                        if (time > total.LastUtc) total.LastUtc = time;
                        if (result.RecordsRead - result.RecordsWithoutTime == 1 || time < result.FirstUtc) result.FirstUtc = time;
                        if (time > result.LastUtc) result.LastUtc = time;
                        for (int i = 0; i < sumList.Count; i++) total.Add(sumList[i].Name, values[i]);
                        if (luid != 0) total.AddInterface((luid >> 48) & 0xFFFF);
                        if (profileId != 0) total.AddProfile(profileId);
                        more = table.MoveNext();
                    }
                }
                catch (EseException e)
                {
                    // A damaged page: keep what was read before it
                    result.Error = e.Message;
                }
                result.Days.AddRange(totals.Values);
                result.Days.Sort(delegate (SrumDayTotal a, SrumDayTotal b)
                {
                    int c = a.Day.CompareTo(b.Day);
                    if (c == 0) c = a.AppId.CompareTo(b.AppId);
                    if (c == 0) c = a.UserId.CompareTo(b.UserId);
                    return c;
                });
            }
            finally
            {
                table.Dispose();
            }
            return result;
        }
    }
}
'@
        }
        $script:srumReaderReady = $true
    }
    catch {
        Log-Warning "  SRUM reader could not be compiled: $($_.Exception.Message)"
    }
    return $script:srumReaderReady
}

# Byte count as text: "512 bytes", "1.5 KB", "120.4 MB" (1 KB = 1024 bytes)
function Format-SrumBytes {
    param([long]$Bytes)
    if ($Bytes -lt 1024) { return "$Bytes bytes" }
    $units = @("KB", "MB", "GB", "TB", "PB")
    $value = [double]$Bytes / 1024
    $unit = 0
    # 1023.95 would print as "1024.0"
    while ($value -ge 1023.95 -and $unit -lt $units.Count - 1) {
        $value = $value / 1024
        $unit++
    }
    return $value.ToString("0.0", [System.Globalization.CultureInfo]::InvariantCulture) + " " + $units[$unit]
}

# Runs esentutl.exe on the temp copy (never on the collection): returns its
# exit code and the line with its result ("Operation completed ..." /
# "Operation terminated with error ...")
function Invoke-SrumEsentutl {
    param([string]$Arguments, [string]$WorkingDirectory)
    $esentutl = Join-Path $env:SystemRoot "System32\esentutl.exe"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $esentutl
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        # Recovery and repair take seconds to minutes; never wait forever
        if (-not $process.WaitForExit(600000)) {
            try { $process.Kill() } catch { Write-Verbose "Could not stop esentutl: $($_.Exception.Message)" }
            return [PSCustomObject]@{ ExitCode = -1; Result = "esentutl did not finish within 10 minutes (stopped)" }
        }
        $text = "$($stdout.Result)`n$($stderr.Result)"
        $resultLine = @($text -split "`r?`n" | Where-Object { $_ -match 'Operation (completed|terminated)' } | Select-Object -Last 1)
        $result = if ($resultLine.Count -gt 0) { $resultLine[0].Trim() } else { "exit code $($process.ExitCode)" }
        return [PSCustomObject]@{ ExitCode = $process.ExitCode; Result = $result }
    }
    finally { $process.Dispose() }
}

# SID -> account name for the SRUM user SIDs, in the User column's form
# (ConvertTo-TimelineUserName: NT AUTHORITY\SYSTEM for S-1-5-18, ...): the
# collector's bam_entries.csv (Sid,User) and ProfileList in the collected
# SOFTWARE hive (loaded only if a user SID is still unknown) are added to
# the User column's SID names (Add-TimelineSidName), and the SIDs are named
# from those, with what the parsers before SRUM gathered (ProfileList wins
# over bam_entries.csv); else the SID
function Get-SrumSidNames {
    param([string[]]$Sids)
    foreach ($csv in (Find-ArtifactFiles -BasePath $InputPath -FileNames @("bam_entries.csv"))) {
        try {
            foreach ($row in (Import-Csv -LiteralPath $csv.FullName -ErrorAction Stop)) {
                Add-TimelineSidName -Sid (Get-ArtifactRowValue $row @("Sid")) -Name (Get-ArtifactRowValue $row @("User"))
            }
        }
        catch { Log-Warning "  Could not read $($csv.FullName) for SID names: $($_.Exception.Message)" }
    }
    $known = Get-TimelineSidNames
    $unknown = @($Sids | Where-Object { $_ -match '^S-1-(5-21|12-1)-' -and -not $known.ContainsKey($_) })
    if ($unknown.Count -gt 0) {
        $softwareHive = Find-OfflineHiveFile "SOFTWARE"
        if ($softwareHive) {
            $mount = $null
            try {
                $mount = Mount-TimelineHive -HiveFile $softwareHive -Prefix "TEMP_TLSRUM"
                if ($mount -and $mount.Root) { Add-OfflineProfileNames $mount.Root }
            }
            catch { Log-Warning "  Failed to read ProfileList from SOFTWARE hive: $($_.Exception.Message)" }
            finally { Dismount-TimelineHive $mount }
        }
    }
    $names = Get-TimelineSidNames
    $result = @{}
    foreach ($sid in $Sids) {
        $name = ConvertTo-TimelineUserName -Value $sid -SidNames $names
        if ($name -and $name -ne $sid) { $result[$sid] = $name }
    }
    return $result
}

# Repairs the temp copy of a SRUM database (esentutl /p): works on the
# database file alone, so records that were only in the transaction logs
# are lost and damaged pages are dropped. Sets Header and Method of the copy
# (from Get-SrumWorkingCopy); returns $true if the copy is now clean.
function Repair-SrumWorkingCopy {
    param([object]$Copy, [string]$TempDir)
    Log "  Repairing the temp copy (esentutl /p)..."
    $repair = Invoke-SrumEsentutl -Arguments ("/p `"{0}`" /o" -f $Copy.Database) -WorkingDirectory $TempDir
    $Copy.Header = [TimelineEse.EseHeader]::Read($Copy.Database)
    if ($Copy.Header.IsClean) {
        $Copy.Method = "repair (esentutl /p)"
        Log-Warning "  Repair was needed: records that were only in the transaction logs or on damaged pages may be missing. esentutl: $($repair.Result)"
        return $true
    }
    Log-Warning "  Repair failed: $($repair.Result)"
    return $false
}

# Copies SRUDB.dat and its ESE companion files (SRU*.log, SRU.chk,
# SRUres*.jrs, SRUDB.jfm) from the collection to the (empty) folder
# -TempDir in the work folder's scratch folder and brings the copy to a
# clean state if needed: soft recovery with the collected logs (in this
# process, else esentutl /r), else repair (esentutl /p, which can lose
# data). The collection itself is never changed. Returns
# Database (the copy), Header (Header.IsEse is false for a file that is not
# an ESE database, Header.IsClean false if neither recovery nor repair
# worked) and Method (what was needed: "" for a clean copy).
function Get-SrumWorkingCopy {
    param([System.IO.FileInfo]$File, [string]$TempDir)
    $copy = [PSCustomObject]@{ Database = (Join-Path $TempDir "SRUDB.dat"); Header = $null; Method = "" }
    Copy-Item -LiteralPath $File.FullName -Destination $copy.Database -Force -ErrorAction Stop
    $companions = @(Get-ChildItem -LiteralPath $File.DirectoryName -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^SRU.*\.(log|jtx|chk|jrs)$' -or $_.Name -eq "SRUDB.jfm" })
    foreach ($companion in $companions) {
        Copy-Item -LiteralPath $companion.FullName -Destination (Join-Path $TempDir $companion.Name) -Force -ErrorAction SilentlyContinue
    }
    # A transaction log the collector saved (listed in collection_manifest.csv)
    # that is not here any more was deleted after the collection
    $relDb = Get-RelativeCollectionPath $File.FullName
    if ($relDb) {
        $relDir = [System.IO.Path]::GetDirectoryName($relDb)
        foreach ($rel in @((Get-CollectionManifest).RelativePaths | Sort-Object)) {
            $leaf = [System.IO.Path]::GetFileName($rel)
            if ($leaf -notmatch '^SRU.*\.(log|jtx)$' -or [System.IO.Path]::GetDirectoryName($rel) -ne $relDir) { continue }
            $logSrc = Join-Path $File.DirectoryName $leaf
            if (-not (Test-Path -LiteralPath $logSrc)) {
                Log-Warning "  Transaction log missing: $logSrc is in the collection manifest but not here -- the database is read without it (records not yet written to the database are lost)"
            }
        }
    }
    # Copies keep the attributes of the collection's files; a read-only copy
    # (evidence marked read-only, read-only media) cannot be recovered or
    # repaired
    foreach ($tempFile in @(Get-ChildItem -LiteralPath $TempDir -File -Force)) {
        $tempFile.Attributes = [System.IO.FileAttributes]::Normal
    }
    $logs = @($companions | Where-Object { $_.Extension -in ".log", ".jtx" })
    $logCount = $logs.Count
    $copy.Header = [TimelineEse.EseHeader]::Read($copy.Database)
    if (-not $copy.Header.IsEse) { return $copy }
    Log "  ESE database: $($copy.Header.PageSize)-byte pages, $($copy.Header.StateName); $logCount SRUM transaction log file(s) next to it"
    if ($copy.Header.IsClean) { return $copy }

    # A copy of an open database (live collection, shadow copy) is normally
    # in dirty-shutdown state: replay the collected logs into the temp copy.
    if ($logCount -gt 0) {
        # In this process first: writes nothing to the Application event
        # log. The engine must be told the size of the logs (all the same).
        Log "  Soft recovery of the temp copy with the $logCount collected log file(s)..."
        $logSizeKb = 0
        $logLength = @($logs | Sort-Object { $_.Name -ne "SRU.log" } | Select-Object -First 1)[0].Length
        if ($logLength -gt 0 -and $logLength % 1024 -eq 0) { $logSizeKb = [int]($logLength / 1024) }
        $inProcessError = ""
        try {
            [TimelineEse.EseRecovery]::Recover($TempDir, "SRU", $TempDir, (Join-Path $TempDir "recovery"), $copy.Header.PageSize, $logSizeKb)
        }
        catch {
            $failure = $_.Exception
            if ($failure.InnerException) { $failure = $failure.InnerException }
            $inProcessError = $failure.Message
        }
        $copy.Header = [TimelineEse.EseHeader]::Read($copy.Database)
        if ($copy.Header.IsClean) {
            $copy.Method = "soft recovery (in-process)"
            Log "  Soft recovery succeeded."
            return $copy
        }
        if (-not $inProcessError) { $inProcessError = "the database is still in state '$($copy.Header.StateName)'" }
        Log-Warning "  Soft recovery in this process failed: $inProcessError -- trying esentutl /r."

        # esentutl /r (writes ESENT events to the Application event log).
        # /d makes it look for the database in the temp folder (by default
        # it uses the original path recorded in the logs).
        $recovery = Invoke-SrumEsentutl -Arguments ("/r sru `"/l{0}`" `"/s{0}`" `"/d{0}`" /i /o" -f $TempDir) -WorkingDirectory $TempDir
        $copy.Header = [TimelineEse.EseHeader]::Read($copy.Database)
        if ($copy.Header.IsClean) {
            $copy.Method = "soft recovery (esentutl /r)"
            Log "  Soft recovery with esentutl succeeded: $($recovery.Result)"
            return $copy
        }
        Log-Warning "  Soft recovery with esentutl failed: $($recovery.Result)"
    }
    else {
        Log-Warning "  No SRUM transaction logs (SRU*.log) next to SRUDB.dat: soft recovery is not possible."
    }

    $null = Repair-SrumWorkingCopy -Copy $copy -TempDir $TempDir
    return $copy
}

# SRUM rows of one SRUDB.dat: per application, user and UTC day, one
# NetworkConnection row (Source SRUM-Network) from Network Data Usage and one
# Execution row (Source SRUM-AppUsage) from Application Resource Usage, timed
# at the last record of that day
function Add-SrumTimelineEntries {
    param([System.IO.FileInfo]$File)
    Log "  Parsing: $($File.FullName) ($([Math]::Round($File.Length / 1MB, 1)) MB)"
    # Scratch copy in the work folder, not %TEMP% (Windows cleans that up
    # during the run)
    $tempDir = Join-Path (Get-ScratchFolder) "TimelineSrum_$(Get-Random)"
    $database = $null
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        $copy = Get-SrumWorkingCopy -File $File -TempDir $tempDir
        if (-not $copy.Header.IsEse) {
            Log-Warning "  $($File.FullName) is not an ESE database (no 0x89ABCDEF header) -- skipped."
            return
        }
        if (-not $copy.Header.IsClean) {
            Log-Warning "  SRUM database could not be brought to a clean state -- skipped."
            return
        }
        # A database whose header says clean can still have damaged pages
        # (the catalog, for example): those are repaired once and opened again
        for ($attempt = 1; $attempt -le 2 -and -not $database; $attempt++) {
            try {
                $database = New-Object TimelineEse.EseDatabase($copy.Database, (Join-Path $tempDir "engine"), $copy.Header.PageSize)
            }
            catch {
                $failure = $_.Exception
                if ($failure.InnerException) { $failure = $failure.InnerException }
                $damaged = $failure -is [TimelineEse.EseException] -and $failure.Error -in @(-327, -1018, -1019, -1022, -1206)
                if ($attempt -eq 1 -and $damaged -and $copy.Method -notlike "repair*") {
                    Log-Warning "  Could not open the SRUM database: $($failure.Message)"
                    if (Repair-SrumWorkingCopy -Copy $copy -TempDir $tempDir) { continue }
                }
                Log-Warning "  Could not open the SRUM database: $($failure.Message) -- skipped."
                return
            }
        }

        # Id map: AppId / UserId -> application or SID
        $idMap = $null
        $idMapError = $null
        try { $idMap = [TimelineEse.SrumReader]::ReadIdMap($database, [ref]$idMapError) }
        catch {
            $failure = $_.Exception
            if ($failure.InnerException) { $failure = $failure.InnerException }
            Log-Warning "  Could not read SruDbIdMapTable: $($failure.Message)"
        }
        if ($idMapError) {
            Log-Warning "  SruDbIdMapTable: read error after $(@($idMap).Count) entries: $idMapError -- applications and users after it are shown by their ids."
        }
        $ids = @{}
        if ($null -eq $idMap) { Log-Warning "  No SruDbIdMapTable: applications and users are shown by their ids." }
        else {
            foreach ($entry in $idMap) { $ids[[long]$entry.IdIndex] = $entry }
            $sidCount = @($idMap | Where-Object { $_.IsSid }).Count
            Log "  SruDbIdMapTable: $($idMap.Count) entries ($sidCount user SID(s))"
        }
        $sids = @($ids.Values | Where-Object { $_.IsSid } | ForEach-Object { $_.Value } | Sort-Object -Unique)
        $sidNames = @{}
        if ($sids.Count -gt 0) {
            $sidNames = Get-SrumSidNames -Sids $sids
            $mapped = @($sids | ForEach-Object { if ($sidNames.ContainsKey($_)) { "$_=$($sidNames[$_])" } else { "$_ (no name)" } })
            Log "  User SIDs: $($mapped -join ', ')"
        }

        $tables = @(
            [PSCustomObject]@{ Id = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"; Label = "Network Data Usage"; Source = "SRUM-Network"; EventType = "NetworkConnection"
                Sums = @("BytesSent", "BytesRecvd") }
            [PSCustomObject]@{ Id = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"; Label = "Application Resource Usage"; Source = "SRUM-AppUsage"; EventType = "Execution"
                Sums = @("ForegroundCycleTime", "BackgroundCycleTime", "FaceTime", "ForegroundBytesRead", "ForegroundBytesWritten", "BackgroundBytesRead", "BackgroundBytesWritten") }
        )
        foreach ($table in $tables) {
            try { $result = [TimelineEse.SrumReader]::Aggregate($database, $table.Id, [string[]]$table.Sums) }
            catch {
                $failure = $_.Exception
                if ($failure.InnerException) { $failure = $failure.InnerException }
                Log-Warning "  Could not read SRUM $($table.Label) $($table.Id): $($failure.Message)"
                continue
            }
            if (-not $result.Found) {
                Log "  SRUM $($table.Label) table $($table.Id) not in this database."
                continue
            }
            if ($result.MissingColumns.Count -gt 0) {
                Log-Warning "  SRUM $($table.Label): column(s) not in this database: $($result.MissingColumns -join ', ')"
            }
            $before = $script:timelineEntries.Count
            $totalSent = 0L
            $totalRecvd = 0L
            $totalRead = 0L
            $totalWritten = 0L
            foreach ($day in $result.Days) {
                $app = $ids[[long]$day.AppId]
                $appName = if (-not $app) { "AppId $($day.AppId) (not in SruDbIdMapTable)" }
                    elseif (-not $app.Value) { "AppId $($day.AppId) (no name in SruDbIdMapTable)" }
                    else { $app.Value }
                $userEntry = $ids[[long]$day.UserId]
                $userSid = if ($userEntry -and $userEntry.IsSid) { $userEntry.Value } else { "" }
                $user = $userSid
                if ($userSid -and $sidNames.ContainsKey($userSid)) { $user = $sidNames[$userSid] }
                $pairs = [ordered]@{
                    Day     = $day.Day.ToString("yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture)
                    App     = $appName
                    AppId   = $day.AppId
                    UserSid = $userSid
                    User    = $(if ($user -ne $userSid) { $user } else { "" })
                    UserId  = $(if (-not $userSid) { $day.UserId } else { "" })
                }
                if ($table.Source -eq "SRUM-Network") {
                    $sent = [long]$day.Sum("BytesSent")
                    $recvd = [long]$day.Sum("BytesRecvd")
                    $totalSent += $sent
                    $totalRecvd += $recvd
                    $description = "SRUM network usage: $appName sent $(Format-SrumBytes $sent), received $(Format-SrumBytes $recvd)"
                    $pairs["BytesSent"] = $sent
                    $pairs["BytesRecvd"] = $recvd
                }
                else {
                    $read = [long]$day.Sum("ForegroundBytesRead") + [long]$day.Sum("BackgroundBytesRead")
                    $written = [long]$day.Sum("ForegroundBytesWritten") + [long]$day.Sum("BackgroundBytesWritten")
                    $totalRead += $read
                    $totalWritten += $written
                    $description = "SRUM app activity: $appName"
                    foreach ($column in $table.Sums) { $pairs[$column] = $day.Sum($column) }
                    $pairs["BytesRead"] = $read
                    $pairs["BytesWritten"] = $written
                }
                $pairs["Records"] = $day.Records
                $pairs["FirstRecordUtc"] = Format-UtcDetailTime $day.FirstUtc
                $pairs["LastRecordUtc"] = Format-UtcDetailTime $day.LastUtc
                if ($day.InterfaceTypes.Count -gt 0) {
                    $pairs["Interfaces"] = (@($day.InterfaceTypes | ForEach-Object { [TimelineEse.SrumReader]::InterfaceTypeName($_) }) -join ", ")
                }
                if ($day.ProfileIds.Count -gt 0) { $pairs["L2ProfileIds"] = ($day.ProfileIds -join ", ") }
                $pairs["Time"] = "last SRUM record of the day (UTC)"
                if ($copy.Method) { $pairs["Database"] = $copy.Method }
                if ($result.Error) { $pairs["Partial"] = "yes (read error; later records of this table are missing)" }
                Add-TimelineEntry -Timestamp $day.LastUtc -Source $table.Source -EventType $table.EventType `
                    -Description $description -User $user -Details (Format-ArtifactDetails $pairs) `
                    -Artifact "SRUM" -RawPath $File.FullName
            }
            $added = $script:timelineEntries.Count - $before
            $range = ""
            if ($result.RecordsRead -gt $result.RecordsWithoutTime) {
                $range = " from $(Format-UtcDetailTime $result.FirstUtc) to $(Format-UtcDetailTime $result.LastUtc) UTC"
            }
            $summary = "  SRUM $($table.Label): $($result.RecordsRead) record(s)$range -> $($result.Days.Count) app/user/day row(s), $added added"
            if ($table.Source -eq "SRUM-Network") { $summary += "; sent $(Format-SrumBytes $totalSent), received $(Format-SrumBytes $totalRecvd) in total" }
            else { $summary += "; read $(Format-SrumBytes $totalRead), written $(Format-SrumBytes $totalWritten) in total" }
            Log "$summary."
            if ($result.Error) {
                Log-Warning "  SRUM $($table.Label): read error after $($result.RecordsRead) record(s): $($result.Error) -- the rows cover only the records before it (Partial=yes in Details)."
            }
            if ($result.RecordsWithoutTime -gt 0) {
                Log-Warning "  SRUM $($table.Label): $($result.RecordsWithoutTime) record(s) without a valid TimeStamp skipped."
            }
        }
    }
    catch {
        $failure = $_.Exception
        if ($failure.InnerException) { $failure = $failure.InnerException }
        Log-Warning "  Failed to parse SRUM database $($File.FullName): $($failure.Message)"
    }
    finally {
        if ($database) { $database.Dispose() }
        if (Test-Path -LiteralPath $tempDir) {
            for ($attempt = 1; $attempt -le 5 -and (Test-Path -LiteralPath $tempDir); $attempt++) {
                Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $tempDir) { Start-Sleep -Seconds 1 }
            }
            if (Test-Path -LiteralPath $tempDir) { Log-Warning "  Could not remove the SRUM temp copy: $tempDir (delete it manually)" }
        }
    }
}

function Parse-Srum {
    Log "--- Parsing SRUM ---"
    # -Force: a copy may keep the Hidden/System attributes of the original
    $dbFiles = @(Get-ChildItem -Path $InputPath -Filter "SRUDB.dat" -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "SRUDB.dat" -and -not (Test-SecretsPath $_.FullName) })
    if ($dbFiles.Count -eq 0) {
        Log "  No SRUM database (SRUDB.dat) in this collection (collected by newer collector versions, Execution\SRUM)."
        Log ""
        return
    }
    if (Initialize-SrumReader) {
        foreach ($dbFile in $dbFiles) { Add-SrumTimelineEntries -File $dbFile }
    }
    Log "  SRUM parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 13. Amcache Parser
# ----------------------------------------------------------
function Parse-Amcache {
    Log "--- Parsing Amcache ---"

    $amcacheFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("Amcache.hve")

    if ($amcacheFiles.Count -eq 0) {
        Log-Warning "No Amcache.hve found. Skipping."
        Log ""
        return
    }

    foreach ($amcache in $amcacheFiles) {
        $hiveName = "TEMP_AMCACHE_$(Get-Random)"
        $loaded = $false
        $tempHiveDir = $null

        try {
            # Copy hive + transaction logs to a scratch folder so reg load can
            # replay dirty hive logs automatically (fixes "registry database is
            # corrupt")
            $tempHiveDir = Join-Path (Get-ScratchFolder) "AmcacheRepair_$(Get-Random)"
            New-Item -ItemType Directory -Path $tempHiveDir -Force | Out-Null

            $srcDir = Split-Path $amcache.FullName -Parent
            $tempHive = Join-Path $tempHiveDir "Amcache.hve"
            Copy-Item -Path $amcache.FullName -Destination $tempHive -Force

            # Copy transaction logs if they exist (enables dirty hive recovery)
            $logsCopied = 0
            foreach ($logExt in @(".LOG1", ".LOG2")) {
                $logSrc = Join-Path $srcDir "Amcache.hve${logExt}"
                if (Test-Path -LiteralPath $logSrc) {
                    Copy-Item -Path $logSrc -Destination (Join-Path $tempHiveDir "Amcache.hve${logExt}") -Force
                    $logsCopied++
                }
                elseif (Test-ManifestListsFile $logSrc) {
                    Log-Warning "  Transaction log missing: $logSrc is in the collection manifest but not here -- the hive is loaded without it (changes not yet written to the hive are lost)"
                }
            }

            if ($logsCopied -gt 0) {
                Log "  Copied hive + $logsCopied transaction log(s) for recovery"
            }

            Log "  Loading Amcache hive: $tempHive"
            Register-RunHive $hiveName
            $regLoadResult = & reg load "HKLM\$hiveName" $tempHive 2>&1
            if ($LASTEXITCODE -eq 0) {
                $loaded = $true
                $count = 0

                # Event times are each entry's registry key last-write time (when
                # Windows recorded or last updated the entry). LinkDate is the PE
                # compile timestamp from the file header -- often meaningless
                # (e.g. 2105 for reproducible builds) -- so it only goes in Details.
                $noTimeCount = 0
                $readErrorCount = 0

                # Read through .NET RegistryKey objects and close every handle:
                # keys opened through the PowerShell registry provider stay open,
                # which makes "reg unload" fail and leaves the hive loaded.
                $rootKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$hiveName\Root")
                try {
                    # Parse InventoryApplicationFile entries (Win10+)
                    $listKey = $null
                    if ($rootKey) { $listKey = $rootKey.OpenSubKey("InventoryApplicationFile") }
                    if ($listKey) {
                        try {
                            foreach ($subName in $listKey.GetSubKeyNames()) {
                                $entry = $listKey.OpenSubKey($subName)
                                if (-not $entry) { continue }
                                try {
                                    $name = $entry.GetValue("Name")
                                    $path2 = $entry.GetValue("LowerCaseLongPath")
                                    if (-not $name -and $path2) { $name = Split-Path $path2 -Leaf }
                                    if (-not $name) { continue }   # hash-only stub entries
                                    $publisher = $entry.GetValue("Publisher")
                                    $version = $entry.GetValue("Version")
                                    $linkDate = $entry.GetValue("LinkDate")
                                    # FileId = "0000" + SHA1 of the file
                                    $hash = [string]$entry.GetValue("FileId")
                                    if ($hash.Length -eq 44 -and $hash.StartsWith("0000")) { $hash = $hash.Substring(4) }

                                    $ts = Get-RegistryKeyLastWriteUtc $entry
                                    if (-not $ts) { $noTimeCount++; continue }

                                    Add-TimelineEntry -Timestamp $ts -Source "Amcache" -EventType "Execution" `
                                        -Description "Amcache file entry recorded: $name" `
                                        -Details "Path=$path2 Publisher=$publisher Version=$version SHA1=$hash LinkDate(PE compile time)=$linkDate Time=registry key last write" `
                                        -Artifact "Amcache" -RawPath $amcache.FullName
                                    $count++
                                }
                                catch { $readErrorCount++; $lastReadError = $_.Exception.Message }
                                finally { $entry.Close() }
                            }
                        }
                        finally { $listKey.Close() }
                    }

                    # Parse InventoryApplication entries (installed applications)
                    $listKey = $null
                    if ($rootKey) { $listKey = $rootKey.OpenSubKey("InventoryApplication") }
                    if ($listKey) {
                        try {
                            foreach ($subName in $listKey.GetSubKeyNames()) {
                                $entry = $listKey.OpenSubKey($subName)
                                if (-not $entry) { continue }
                                try {
                                    $name = $entry.GetValue("Name")
                                    if (-not $name) { continue }
                                    $publisher = $entry.GetValue("Publisher")
                                    $version = $entry.GetValue("Version")
                                    $installDate = $entry.GetValue("InstallDate")
                                    $source = $entry.GetValue("Source")
                                    $rootDir = $entry.GetValue("RootDirPath")

                                    $ts = Get-RegistryKeyLastWriteUtc $entry
                                    if (-not $ts) { $noTimeCount++; continue }

                                    Add-TimelineEntry -Timestamp $ts -Source "Amcache-App" -EventType "Installation" `
                                        -Description "Amcache application recorded: $name" `
                                        -Details "Publisher=$publisher Version=$version Source=$source InstallDate=$installDate RootDir=$rootDir Time=registry key last write" `
                                        -Artifact "Amcache" -RawPath $amcache.FullName
                                    $count++
                                }
                                catch { $readErrorCount++; $lastReadError = $_.Exception.Message }
                                finally { $entry.Close() }
                            }
                        }
                        finally { $listKey.Close() }
                    }
                }
                finally {
                    if ($rootKey) { $rootKey.Close() }
                }
                if ($noTimeCount -gt 0) { Log-Warning "  $noTimeCount Amcache entr(ies) skipped: key last-write time unavailable." }
                if ($readErrorCount -gt 0) { Log-Warning "  $readErrorCount Amcache entr(ies) skipped: could not be read (last error: $lastReadError)" }

                Log "  Parsed $count Amcache entries."
            }
            else {
                Unregister-RunHive $hiveName
                $regLoadText = (@($regLoadResult) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join " "
                Log-Warning "  Could not load Amcache hive: $regLoadText -- No Amcache data available."
            }
        }
        catch {
            Log-Warning "  Failed to parse Amcache: $($_.Exception.Message)"
        }
        finally {
            if ($loaded) {
                $unloaded = $false
                for ($attempt = 1; $attempt -le 3 -and -not $unloaded; $attempt++) {
                    [gc]::Collect()
                    [gc]::WaitForPendingFinalizers()
                    Start-Sleep -Milliseconds 500
                    & reg unload "HKLM\$hiveName" 2>&1 | Out-Null
                    $unloaded = ($LASTEXITCODE -eq 0)
                }
                if ($unloaded) {
                    Log "  Unloaded Amcache hive."
                    Unregister-RunHive $hiveName
                }
                # Tried again at the end of the run, before the work folder is deleted
                else { Log-Warning "  Failed to unload Amcache hive -- run: reg unload HKLM\$hiveName" }
            }
            # The temp copy holds a copy of the hive; loading it also creates
            # transaction-log files (.blf/.regtrans-ms) that stay locked briefly
            # after unload, so retry before giving up
            if ($tempHiveDir -and (Test-Path -LiteralPath $tempHiveDir)) {
                for ($attempt = 1; $attempt -le 5 -and (Test-Path -LiteralPath $tempHiveDir); $attempt++) {
                    Remove-Item -LiteralPath $tempHiveDir -Recurse -Force -ErrorAction SilentlyContinue
                    if (Test-Path -LiteralPath $tempHiveDir) { Start-Sleep -Seconds 1 }
                }
                if (Test-Path -LiteralPath $tempHiveDir) {
                    Log-Warning "  Could not remove temp copy of the Amcache hive: $tempHiveDir (delete it manually)"
                }
            }
        }
    }
    Log "  Amcache parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 14. PowerShell History Parser
# ----------------------------------------------------------
# Account name for a BAM SID: well-known service SIDs, then the SID -> profile
# map (ProfileList), else the SID itself
function Resolve-BamUser {
    param([string]$Sid, [hashtable]$SidNames)
    switch -Regex ($Sid) {
        '^S-1-5-18$'         { return "SYSTEM" }
        '^S-1-5-19$'         { return "LOCAL SERVICE" }
        '^S-1-5-20$'         { return "NETWORK SERVICE" }
        '^S-1-5-90-0-(\d+)$' { return "DWM-$($Matches[1])" }
        '^S-1-5-96-0-(\d+)$' { return "UMFD-$($Matches[1])" }
    }
    if ($SidNames -and $SidNames.ContainsKey($Sid) -and $SidNames[$Sid]) { return $SidNames[$Sid] }
    return $Sid
}

# SID -> profile folder name from a loaded SOFTWARE hive (ProfileList)
function Get-ProfileListMap {
    param([Microsoft.Win32.RegistryKey]$SoftwareRoot)
    $map = @{}
    $pl = $SoftwareRoot.OpenSubKey("Microsoft\Windows NT\CurrentVersion\ProfileList")
    if (-not $pl) { return $map }
    try {
        foreach ($sid in $pl.GetSubKeyNames()) {
            $k = $pl.OpenSubKey($sid)
            if (-not $k) { continue }
            try {
                $p = $k.GetValue("ProfileImagePath", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($p) { $map[$sid] = ([string]$p).TrimEnd('\') -replace '^.*\\', '' }
            }
            finally { $k.Close() }
        }
    }
    finally { $pl.Close() }
    return $map
}

# Current control set of a loaded SYSTEM hive (Select\Current; a saved hive
# has no CurrentControlSet link). $null if none found.
function Get-OfflineControlSetName {
    param([Microsoft.Win32.RegistryKey]$SystemRoot)
    $name = $null
    $sel = $SystemRoot.OpenSubKey("Select")
    if ($sel) {
        try {
            $cur = $sel.GetValue("Current")
            if ($null -ne $cur) { $name = "ControlSet{0:D3}" -f [int]$cur }
        }
        finally { $sel.Close() }
    }
    foreach ($candidate in @($name, "ControlSet001", "CurrentControlSet")) {
        if (-not $candidate) { continue }
        $k = $SystemRoot.OpenSubKey($candidate)
        if ($k) { $k.Close(); return $candidate }
    }
    return $null
}

# Names of the examined machine from a loaded SYSTEM hive, for the User
# column: the computer name (NetBIOS) and the TCP/IP host names (Hostname,
# and NV Hostname, the name after a pending rename) of the current control
# set. Anything but a registry key (no hive) gives none; a key that cannot
# be read gives fewer names and a warning, never an error.
function Get-OfflineComputerNames {
    param($SystemRoot)
    $names = @()
    if ($SystemRoot -isnot [Microsoft.Win32.RegistryKey]) { return $names }
    try {
        $controlSet = Get-OfflineControlSetName $SystemRoot
        if ($controlSet) {
            foreach ($item in @(@("Control\ComputerName\ComputerName", "ComputerName"), @("Services\Tcpip\Parameters", "Hostname"), @("Services\Tcpip\Parameters", "NV Hostname"))) {
                $key = $SystemRoot.OpenSubKey("$controlSet\$($item[0])")
                if (-not $key) { continue }
                try { $names += "$($key.GetValue($item[1]))".Trim() }
                finally { $key.Close() }
            }
        }
    }
    catch { Log-Warning "  Could not read the computer name from the SYSTEM hive (User column): $($_.Exception.Message)" }
    return @($names | Where-Object { $_ })
}

# Account names by SID from a loaded SOFTWARE hive's ProfileList, kept for
# the User column (Add-TimelineSidName). Anything but a registry key gives
# none; a ProfileList that cannot be read gives a warning, never an error.
function Add-OfflineProfileNames {
    param($SoftwareRoot)
    if ($SoftwareRoot -isnot [Microsoft.Win32.RegistryKey]) { return }
    try {
        $profiles = Get-ProfileListMap $SoftwareRoot
        foreach ($sid in $profiles.Keys) { Add-TimelineSidName -Sid $sid -Name $profiles[$sid] -ProfileList }
    }
    catch { Log-Warning "  Could not read ProfileList from the SOFTWARE hive (User column): $($_.Exception.Message)" }
}

# BAM/DAM values from a loaded SYSTEM hive: one object per value whose data
# starts with a FILETIME (Sid, Path, LastExecutionUtc, Source, Key).
# Windows 10 1809+ uses Services\bam\State\UserSettings, older builds
# Services\bam\UserSettings.
function Get-OfflineBamEntries {
    param([Microsoft.Win32.RegistryKey]$SystemRoot, [string]$ControlSet)
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($rel in @("Services\bam\State\UserSettings", "Services\bam\UserSettings", "Services\dam\State\UserSettings", "Services\dam\UserSettings")) {
        $us = $SystemRoot.OpenSubKey("$ControlSet\$rel")
        if (-not $us) { continue }
        $source = if ($rel -like "Services\dam\*") { "DAM" } else { "BAM" }
        try {
            foreach ($sid in $us.GetSubKeyNames()) {
                $sk = $us.OpenSubKey($sid)
                if (-not $sk) { continue }
                try {
                    foreach ($val in $sk.GetValueNames()) {
                        $data = $sk.GetValue($val)
                        if (-not ($data -is [byte[]]) -or $data.Length -lt 8) { continue }
                        $ft = [BitConverter]::ToInt64($data, 0)
                        if ($ft -le 0) { continue }
                        try { $t = [datetime]::FromFileTimeUtc($ft) } catch { continue }
                        $entries.Add([PSCustomObject]@{ Sid = $sid; Path = $val; LastExecutionUtc = $t; Source = $source; Key = "$ControlSet\$rel" })
                    }
                }
                finally { $sk.Close() }
            }
        }
        finally { $us.Close() }
    }
    return $entries
}

# Parse the Format-List text of old collectors (bam_entries.txt). Only value
# names survive (the FILETIME was truncated), so this returns Sid + Path pairs.
# One block per SID key; indented lines continue the previous property.
function ConvertFrom-BamListText {
    param([string[]]$Lines)
    $results = New-Object System.Collections.Generic.List[object]
    $props = New-Object System.Collections.Generic.List[object]
    $current = $null
    $psProps = @("Version", "SequenceNumber", "PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")
    foreach ($line in @($Lines) + @("")) {
        if ($line -match '^(\S.*?)\s+:\s?(.*)$') {
            $current = [PSCustomObject]@{ Name = $Matches[1]; Value = $Matches[2].Trim() }
            $props.Add($current)
        }
        elseif ($line.Trim() -eq "") {
            # End of a block: the SID is in PSChildName, after the values
            if ($props.Count -gt 0) {
                $sid = ""
                foreach ($p in $props) { if ($p.Name -eq "PSChildName") { $sid = $p.Value -replace '\s', '' } }
                foreach ($p in $props) {
                    if ($psProps -notcontains $p.Name) { $results.Add([PSCustomObject]@{ Sid = $sid; Path = $p.Name }) }
                }
                $props.Clear()
            }
            $current = $null
        }
        elseif ($current) {
            # Wrapped continuation of the previous value
            $current.Value += $line.Trim()
        }
    }
    return $results
}

# AppCompatCache value bytes from a loaded SYSTEM hive, or $null
function Get-OfflineAppCompatCache {
    param([Microsoft.Win32.RegistryKey]$SystemRoot, [string]$ControlSet)
    $k = $SystemRoot.OpenSubKey("$ControlSet\Control\Session Manager\AppCompatCache")
    if (-not $k) { return $null }
    try { $data = $k.GetValue("AppCompatCache") }
    finally { $k.Close() }
    if ($data -is [byte[]]) { return ,$data }
    return $null
}

# AppCompatCache bytes from a text export: "reg query" output
# ("    AppCompatCache    REG_BINARY    <hex>") or a .reg file
# ("AppCompatCache"=hex:34,00,...). $null if not found.
function Get-AppCompatCacheFromRegText {
    param([string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $hex = $null
    if ($text -match 'AppCompatCache\s+REG_BINARY\s+([0-9A-Fa-f]+)') { $hex = $Matches[1] }
    elseif ($text -match '"AppCompatCache"=hex:([0-9A-Fa-f,\\\s]+)') { $hex = $Matches[1] -replace '[^0-9A-Fa-f]', '' }
    if (-not $hex -or ($hex.Length % 2) -ne 0) { return $null }

    $bytes = $null
    # .NET 5+ (PowerShell 7)
    try { $bytes = [Convert]::FromHexString($hex) }
    catch { Write-Verbose "Convert.FromHexString not available, trying SoapHexBinary: $($_.Exception.Message)" }
    if ($null -eq $bytes) {
        # .NET Framework (Windows PowerShell 5.1)
        try {
            Add-Type -AssemblyName System.Runtime.Remoting -ErrorAction Stop
            $bytes = [System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary]::Parse($hex).Value
        } catch { Write-Verbose "SoapHexBinary not available, decoding hex manually: $($_.Exception.Message)" }
    }
    if ($null -eq $bytes) {
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    }
    return ,$bytes
}

# Parse a Windows 10/11 AppCompatCache (ShimCache) value. The first DWORD is
# the header size (0x30 or 0x34); then "10ts" entries:
# [sig 4][unknown 4][entry data size 4][path length 2][path UTF-16]
# [FILETIME 8 = file last-modified time][data length 4][data].
# Returns the entries in cache order (Position 1 = most recently inserted).
function ConvertFrom-AppCompatCacheBinary {
    param([byte[]]$Data)
    $entries = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Data -or $Data.Length -lt 0x34) { throw "AppCompatCache value too short" }
    $headerSize = [BitConverter]::ToInt32($Data, 0)
    if (($headerSize -ne 0x30 -and $headerSize -ne 0x34) -or $headerSize + 4 -gt $Data.Length -or
        [System.Text.Encoding]::ASCII.GetString($Data, $headerSize, 4) -ne "10ts") {
        throw ("Unsupported AppCompatCache format (header size 0x{0:X}); only the Windows 10/11 format is parsed" -f $headerSize)
    }
    $pos = $headerSize
    $index = 0
    while ($pos + 14 -le $Data.Length) {
        if ([System.Text.Encoding]::ASCII.GetString($Data, $pos, 4) -ne "10ts") { break }
        $entrySize = [int][BitConverter]::ToUInt32($Data, $pos + 8)
        $pathLen = [int][BitConverter]::ToUInt16($Data, $pos + 12)
        $pathStart = $pos + 14
        if ($pathStart + $pathLen + 12 -gt $Data.Length) { break }
        $path = [System.Text.Encoding]::Unicode.GetString($Data, $pathStart, $pathLen)
        $ft = [BitConverter]::ToInt64($Data, $pathStart + $pathLen)
        $dataLen = [int][BitConverter]::ToUInt32($Data, $pathStart + $pathLen + 8)
        $modified = $null
        if ($ft -gt 0) {
            try { $modified = [datetime]::FromFileTimeUtc($ft) }
            catch { Write-Verbose "Invalid AppCompatCache file time for $path, entry kept without it: $($_.Exception.Message)" }
        }
        $index++
        $entries.Add([PSCustomObject]@{ Position = $index; Path = $path; LastModifiedUtc = $modified; DataSize = $dataLen })
        # Next entry: after the 12-byte entry header plus the entry data size
        $next = $pos + 12 + $entrySize
        if ($next -le $pos) { break }
        $pos = $next
    }
    return $entries
}

function Parse-PowerShellHistory {
    Log "--- Parsing PowerShell History ---"

    $psParsed = $false

    # ConsoleHost_history.txt from triage collection
    $histFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("ConsoleHost_history.txt")


    foreach ($histFile in $histFiles) {
        Log "  Parsing: $($histFile.FullName)"
        try {
            # Account from the collection layout (UserActivity\<user>\), never
            # from the analyst machine's path
            $user = Get-CollectionUser $histFile.FullName

            $commands = @(Get-Content -LiteralPath $histFile.FullName -ErrorAction Stop)
            # The file has no per-command times: every command gets the file's
            # last-write time (the original file's when the manifest has it)
            $ts = $histFile.LastWriteTimeUtc
            $srcTimes = Get-SourceFileTimes $histFile.FullName
            if ($srcTimes -and $srcTimes.Modified) { $ts = $srcTimes.Modified }
            $count = 0
            $lineNo = 0

            foreach ($cmd in $commands) {
                $lineNo++
                $cmd = $cmd.Trim()
                if ($cmd -and $cmd.Length -gt 1) {
                    Add-TimelineEntry -Timestamp $ts -Source "PowerShellHistory" -EventType "Execution" `
                        -Description "PS command: $cmd" `
                        -User $user -Details "Line=$lineNo of $($commands.Count); Time=history file last write (command ran at or before this)" `
                        -Artifact "PowerShellHistory" -RawPath $histFile.FullName
                    $psParsed = $true
                    $count++
                }
            }
            Log "  Parsed $count PowerShell history commands for user $user."
        }
        catch { Log-Warning "  Failed to parse PS history: $($_.Exception.Message)" }
    }

    # --- BAM/DAM (last execution time per program and user) and AppCompatCache ---
    # BAM sources, best first: Execution\bam_entries.csv (FILETIMEs decoded by
    # the collector), the collected SYSTEM hive (offline), bam_entries.txt
    # (old collectors: the times were truncated, so Snapshot rows only).
    # AppCompatCache: the SYSTEM hive, else Execution\appcompat_cache.reg.
    $bamCsvFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("bam_entries.csv") | Where-Object { -not $_.PSIsContainer })
    $bamTxtFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("bam_entries.txt") | Where-Object { -not $_.PSIsContainer })
    $shimFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("appcompat_cache.reg") | Where-Object { -not $_.PSIsContainer })
    $systemHive = Find-OfflineHiveFile "SYSTEM"

    $hiveBam = @()
    $hiveBamRead = $false
    $shimData = $null
    $shimSource = ""

    if ($systemHive) {
        $mount = $null
        try {
            $mount = Mount-TimelineHive -HiveFile $systemHive -Prefix "TEMP_TLSYS"
            if ($mount -and $mount.Root) {
                # The machine's names for the User column too
                Add-TimelineMachineName (Get-OfflineComputerNames $mount.Root)
                $controlSet = Get-OfflineControlSetName $mount.Root
                if ($controlSet) {
                    Log "  SYSTEM hive current control set: $controlSet"
                    if ($bamCsvFiles.Count -eq 0) {
                        $hiveBam = @(Get-OfflineBamEntries -SystemRoot $mount.Root -ControlSet $controlSet)
                        $hiveBamRead = $true
                        Log "  Read $($hiveBam.Count) BAM/DAM value(s) from the SYSTEM hive."
                    }
                    $shimData = Get-OfflineAppCompatCache -SystemRoot $mount.Root -ControlSet $controlSet
                    if ($null -ne $shimData) { $shimSource = $systemHive.FullName }
                }
                else { Log-Warning "  No control set found in SYSTEM hive $($systemHive.FullName)" }
            }
        }
        catch { Log-Warning "  Failed to read SYSTEM hive: $($_.Exception.Message)" }
        finally { Dismount-TimelineHive $mount }
    }

    # BAM from bam_entries.csv (contract: Sid,User,Path,LastExecutionUtc)
    foreach ($csv in $bamCsvFiles) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $count = 0
            foreach ($row in (Import-Csv -LiteralPath $csv.FullName -ErrorAction Stop)) {
                if (-not $row.Path) { continue }
                $bamUser = [string]$row.User
                # The collector's name for the SID, for the User column
                Add-TimelineSidName -Sid $row.Sid -Name $bamUser
                if (-not $bamUser) { $bamUser = Resolve-BamUser -Sid $row.Sid -SidNames @{} }
                $ts = ConvertFrom-UtcText $row.LastExecutionUtc
                if ($ts) {
                    Add-TimelineEntry -Timestamp $ts -Source "BAM" -EventType "Execution" `
                        -Description "BAM execution: $($row.Path)" `
                        -User $bamUser -Details "SID=$($row.Sid); Time=last execution (BAM)" `
                        -Artifact "Registry" -RawPath $csv.FullName
                }
                else {
                    $snapTime = Get-SnapshotTimeUtc -File $csv
                    if (-not $snapTime) { continue }
                    Add-TimelineEntry -Timestamp $snapTime -Source "BAM" -EventType "Snapshot" `
                        -Description "BAM entry ($bamUser): $($row.Path)" `
                        -User $bamUser -Details "SID=$($row.Sid); no execution time recorded; listed at collection time" `
                        -Artifact "Registry" -RawPath $csv.FullName
                }
                $psParsed = $true
                $count++
            }
            Log "  Parsed $count BAM entries."
        }
        catch { Log-Warning "  Failed to parse BAM entries: $($_.Exception.Message)" }
    }

    # BAM from the SYSTEM hive; SIDs mapped to profile names via SOFTWARE\ProfileList
    if ($hiveBam.Count -gt 0) {
        $sidNames = @{}
        $softwareHive = Find-OfflineHiveFile "SOFTWARE"
        if ($softwareHive) {
            $swMount = $null
            try {
                $swMount = Mount-TimelineHive -HiveFile $softwareHive -Prefix "TEMP_TLSW"
                if ($swMount -and $swMount.Root) {
                    $sidNames = Get-ProfileListMap $swMount.Root
                    # For the User column too
                    foreach ($sid in $sidNames.Keys) { Add-TimelineSidName -Sid $sid -Name $sidNames[$sid] -ProfileList }
                }
            }
            catch { Log-Warning "  Failed to read ProfileList from SOFTWARE hive: $($_.Exception.Message)" }
            finally { Dismount-TimelineHive $swMount }
        }
        foreach ($b in $hiveBam) {
            Add-TimelineEntry -Timestamp $b.LastExecutionUtc -Source $b.Source -EventType "Execution" `
                -Description "$($b.Source) execution: $($b.Path)" `
                -User (Resolve-BamUser -Sid $b.Sid -SidNames $sidNames) `
                -Details "SID=$($b.Sid); Time=last execution ($($b.Source), SYSTEM\$($b.Key))" `
                -Artifact "Registry" -RawPath $systemHive.FullName
        }
        $psParsed = $true
    }

    # Old collectors: bam_entries.txt only (Format-List output, no usable times)
    if ($bamCsvFiles.Count -eq 0 -and -not $hiveBamRead) {
        foreach ($bamFile in $bamTxtFiles) {
            Log "  Parsing: $($bamFile.FullName) (old format: execution times were not saved -- Snapshot rows only)"
            try {
                $snapTime = Get-SnapshotTimeUtc -File $bamFile
                if (-not $snapTime) {
                    Log-Warning "  Collection time unknown -- BAM entries skipped."
                    continue
                }
                $count = 0
                foreach ($e in @(ConvertFrom-BamListText (Get-Content -LiteralPath $bamFile.FullName -ErrorAction Stop))) {
                    # User in the description too: all rows share one timestamp
                    $bamUser = Resolve-BamUser -Sid $e.Sid -SidNames @{}
                    Add-TimelineEntry -Timestamp $snapTime -Source "BAM" -EventType "Snapshot" `
                        -Description "BAM entry ($bamUser): $($e.Path)" `
                        -User $bamUser `
                        -Details "SID=$($e.Sid); execution time not saved by this collector version; listed at collection time" `
                        -Artifact "Registry" -RawPath $bamFile.FullName
                    $psParsed = $true
                    $count++
                }
                Log "  Parsed $count BAM entries (no times)."
            }
            catch { Log-Warning "  Failed to parse BAM entries: $($_.Exception.Message)" }
        }
    }

    # AppCompatCache (ShimCache): text export when the hive gave nothing
    if ($null -eq $shimData) {
        foreach ($shimFile in $shimFiles) {
            try {
                $shimData = Get-AppCompatCacheFromRegText $shimFile.FullName
                if ($null -ne $shimData) { $shimSource = $shimFile.FullName; break }
                Log-Warning "  No AppCompatCache binary data found in $($shimFile.FullName)"
            }
            catch { Log-Warning "  Failed to read $($shimFile.FullName) : $($_.Exception.Message)" }
        }
    }

    if ($null -ne $shimData) {
        Log "  Parsing AppCompatCache from: $shimSource"
        try {
            $shimEntries = @(ConvertFrom-AppCompatCacheBinary -Data $shimData)
            $total = $shimEntries.Count
            $timed = 0
            $snapTime = $null
            $seenNoTime = @{}
            foreach ($e in $shimEntries) {
                $entryName = $e.Path
                $entryNote = ""
                if ($e.Path.Contains("`t")) {
                    # Packaged (UWP) app entry: tab-separated fields ending in
                    # architecture, package name and publisher ID; no file time
                    $fields = @($e.Path.Split("`t") | Where-Object { $_ -ne "" })
                    if ($fields.Count -ge 6) {
                        $entryName = "$($fields[4])_$($fields[5])"
                        $entryNote = "Packaged app; Arch=$($fields[3]); "
                    }
                    else { $entryName = $e.Path -replace "`t", " " }
                }
                if ($e.LastModifiedUtc) {
                    # The time is the file's last-modified time, not when it
                    # ran (on Windows 10/11 an entry alone does not prove
                    # that it ran): FileLastModified, not Execution
                    Add-TimelineEntry -Timestamp $e.LastModifiedUtc -Source "AppCompatCache" -EventType "FileLastModified" `
                        -Description "ShimCache entry (file last modified): $entryName" `
                        -Details "$($entryNote)Time=file last-modified time (NOT an execution time); CachePosition=$($e.Position) of $total (1 = most recent)" `
                        -Artifact "Registry" -RawPath $shimSource
                    $timed++
                }
                else {
                    # One Snapshot row per name (packaged apps repeat per architecture)
                    if ($seenNoTime.ContainsKey($entryName)) { continue }
                    $seenNoTime[$entryName] = $true
                    if (-not $snapTime) { $snapTime = Get-SnapshotTimeUtc }
                    if (-not $snapTime) { continue }
                    Add-TimelineEntry -Timestamp $snapTime -Source "AppCompatCache" -EventType "Snapshot" `
                        -Description "ShimCache entry: $entryName" `
                        -Details "$($entryNote)No file time in cache entry; listed at collection time; CachePosition=$($e.Position) of $total (1 = most recent)" `
                        -Artifact "Registry" -RawPath $shimSource
                }
                $psParsed = $true
            }
            Log "  Parsed $total AppCompatCache entries: $timed with file times (file last-modified times, not execution times), $($seenNoTime.Count) distinct without."
        }
        catch { Log-Warning "  Failed to parse AppCompatCache: $($_.Exception.Message)" }
    }

    if (-not $psParsed) { Log-Warning "No PowerShell history or BAM data found." }
    Log "  PowerShell/BAM/ShimCache parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 15. Memory Dump Parser (Volatility 3)
# ----------------------------------------------------------
$script:memoryDumpPathWarned = $false   # Find-MemoryDump has reported a bad -MemoryDumpPath
$script:memoryDumpNotices = New-Object 'System.Collections.Generic.HashSet[string]'   # the lines Find-MemoryDump has logged in this run
$script:memoryDumpFromManifest = $false   # the last dump Find-MemoryDump returned is the manifest's
$script:memoryDumpListedPath = ""   # ... found on a drive with another letter: the path the manifest lists

# Logs a line of Find-MemoryDump once per run: a dump that is offered and
# then analyzed is looked for twice
function Write-MemoryDumpNotice {
    param([string]$Text, [switch]$Warning)
    if ($null -eq $script:memoryDumpNotices) { $script:memoryDumpNotices = New-Object 'System.Collections.Generic.HashSet[string]' }
    if (-not $script:memoryDumpNotices.Add($Text)) { return }
    if ($Warning) { Log-Warning $Text }
    else { Log $Text }
}

# Ready fixed and removable drives, as roots ("E:\"): the drives the
# collector's memory prompt offers for the dump. A function of its own so
# the tests can stand in for the machine's drives
function Get-MemoryDumpDriveRoots {
    $roots = @()
    try {
        foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
            try {
                if ($drive.IsReady -and ($drive.DriveType -eq [System.IO.DriveType]::Fixed -or $drive.DriveType -eq [System.IO.DriveType]::Removable)) {
                    $roots += $drive.RootDirectory.FullName
                }
            }
            catch { Write-Verbose "Checking drive $($drive.Name): $($_.Exception.Message)" }
        }
    }
    catch { Write-Verbose "Listing drives: $($_.Exception.Message)" }
    return $roots
}

# The file at a path that may come from collection_manifest.csv, or $null
# when there is none (also for a path Windows PowerShell 5.1 refuses, e.g.
# one with | in it)
function Get-MemoryDumpFile {
    param([string]$Path)
    try {
        $file = New-Object System.IO.FileInfo($Path)
        if ($file.Exists) { return $file }
    }
    catch { Write-Verbose "Memory dump ${Path}: $($_.Exception.Message)" }
    return $null
}

# Where Find-MemoryDump looks for the dump next to the collection, by name.
# -Zip: next to the selected zip (browse mode, or a zip as -InputPath),
# <zip name>_memory_dump.dmp and .raw. -Folder: next to the collection
# folder (the folder of collection_manifest.csv, else -InputPath) and next
# to -InputPath (an outer folder that holds the collection), only under
# the collection folder's name: a folder such as the collector's reports\
# holds the dumps of other collections too. Windows "Extract All" of
# <name>.zip makes <name>\<name>\, so the dump next to the zip is then
# next to the outer folder.
function Get-MemoryDumpSiblingPaths {
    param([switch]$Zip, [switch]$Folder)
    $extensions = @("dmp", "raw")
    $paths = @()
    if ($Zip -and $script:selectedZipPath -and (Test-Path -LiteralPath $script:selectedZipPath)) {
        $zipDir = Split-Path $script:selectedZipPath -Parent
        $zipBaseName = [System.IO.Path]::GetFileNameWithoutExtension($script:selectedZipPath)
        foreach ($ext in $extensions) { $paths += Join-Path $zipDir "${zipBaseName}_memory_dump.$ext" }
    }
    if ($Folder) {
        $root = Get-CollectionRootFolder
        $collectionName = [System.IO.Path]::GetFileName($root)
        $parentDir = [System.IO.Path]::GetDirectoryName($root)
        if ($collectionName -and $parentDir) {
            $dumpDirs = @($parentDir)
            $outerParentDir = [System.IO.Path]::GetDirectoryName($parentDir)
            if ($outerParentDir -and [System.IO.Path]::GetFileName($parentDir) -eq $collectionName) { $dumpDirs += $outerParentDir }
            $inputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath).TrimEnd('\')
            $inputParentDir = [System.IO.Path]::GetDirectoryName($inputDir)
            if ($inputParentDir -and $dumpDirs -notcontains $inputParentDir) { $dumpDirs += $inputParentDir }
            foreach ($dumpDir in $dumpDirs) {
                foreach ($ext in $extensions) { $paths += Join-Path $dumpDir "${collectionName}_memory_dump.$ext" }
            }
        }
    }
    return $paths
}

# The size collection_manifest.csv lists for the dump (SizeBytes) against
# a file's length: "" when they are the same, else "<length> bytes, but
# collection_manifest.csv lists <size> bytes" (or "no size")
function Get-MemoryDumpSizeMismatch {
    param([object]$Listed, [long]$Length)
    $listedSize = [long]-1
    if ([long]::TryParse($Listed.SizeBytes, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$listedSize) -and $listedSize -eq $Length) { return "" }
    $listedText = "no size"
    if ($Listed.SizeBytes) { $listedText = "$($Listed.SizeBytes) bytes" }
    return "$Length bytes, but collection_manifest.csv lists $listedText"
}

# The end of the log line for a dump of the size the manifest lists
function Get-MemoryDumpHashNote {
    param([object]$Listed)
    return "SHA-256 in the manifest: $($Listed.Sha256) -- the dump is not hashed again here (it is as large as RAM); Get-FileHash -Algorithm SHA256 checks it."
}

# The memory dump collection_manifest.csv lists: the collector records a
# complete dump as "(memory dump via DumpIt)" (WinPmem, MagnetRAM), with
# its size and SHA-256. Where it is:
# - in the collection (RelativePath Memory\memory_dump.dmp or .raw; before
#   the RelativePath column only DestPath, <collection>\Memory\...): the
#   collector's default. When zipping, the collector moves it next to the
#   zip, so in a zipped collection it is missing, which is normal (the
#   other checks find it next to the zip).
# - outside it (RelativePath empty): DestPath, the folder of the
#   collector's -MemoryOutputPath or of the drive picked at its memory
#   prompt, e.g. D:\TriageMemory\<collection>_memory_dump.dmp (a collector
#   that changes the row when it moves the dump names the path next to the
#   zip). When no file of the listed size is there, the same path on the
#   other fixed and removable drives is tried: the drive (e.g. a USB drive)
#   may have another letter now, on another machine or plugged in again.
# A manifest comes from the examined machine, so it must not make the
# builder read just any file or connect to a server: only the names the
# collector writes are used (Memory\memory_dump.<ext>, and outside the
# collection <collection folder name>_memory_dump.<ext>), and outside the
# collection only a path on a drive letter, or a path the builder looks at
# anyway next to the collection zip or folder it was given (e.g. on a
# network share). The dump is not hashed (it is as large as RAM), but its
# size must match the manifest. Only string methods are used on the
# manifest's paths: Windows PowerShell 5.1's Path methods throw on
# characters such as | in a path.
# Returns Status: None (no such row), Found, Missing, SizeMismatch or
# Refused (for these two, Reason says why); Path (the full path it names,
# or the file found on another drive; RelativePath for a refused one in
# the collection); ListedPath (the DestPath it names when the file is on
# another drive, else ""); OtherDrives ($true when other drives were
# tried); Extension (.dmp or .raw when the name is one the collector
# writes: Find-MemoryDump then checks the size of a dump of that type it
# finds elsewhere); InCollection, RelativePath, Sha256 and SizeBytes (as
# listed).
function Get-ManifestMemoryDump {
    $result = [PSCustomObject]@{ Status = "None"; Path = ""; ListedPath = ""; OtherDrives = $false; Extension = ""; InCollection = $false; RelativePath = ""; Sha256 = ""; SizeBytes = ""; Reason = "" }
    $manifest = Get-CollectionManifest
    $row = $null
    foreach ($candidate in $manifest.Rows) {
        if ("$($candidate.SourcePath)" -match '^\(memory dump via .+\)$') { $row = $candidate; break }
    }
    if (-not $row) { return $result }
    $result.Sha256 = "$($row.SHA256)".Trim()
    $result.SizeBytes = "$($row.SizeBytes)".Trim()
    $destPath = "$($row.DestPath)".Trim()
    $relPath = ""
    if ($row.PSObject.Properties["RelativePath"]) { $relPath = "$($row.RelativePath)".Trim() }
    if (-not $relPath -and $destPath -match '\\(Memory\\memory_dump\.(?:dmp|raw))$') { $relPath = $Matches[1] }

    if ($relPath) {
        $result.InCollection = $true
        $result.RelativePath = $relPath
        $result.Path = $relPath
        if (-not ($relPath -match '^Memory\\memory_dump(\.(?:dmp|raw))$')) {
            $result.Status = "Refused"
            $result.Reason = "not a name the collector gives a memory dump in the collection (Memory\memory_dump.dmp or .raw)"
            return $result
        }
        $result.Extension = $Matches[1].ToLowerInvariant()
        $result.Path = Join-Path (Get-CollectionRootFolder) $relPath
    }
    else {
        $result.Path = $destPath
        # The collection folder's name now, and as the collector named it
        # (DestPath minus RelativePath of the other rows): a renamed folder
        $names = @([System.IO.Path]::GetFileName((Get-CollectionRootFolder)))
        foreach ($other in $manifest.Rows) {
            if (-not $other.PSObject.Properties["RelativePath"]) { break }
            $otherRel = "$($other.RelativePath)"
            $otherDest = "$($other.DestPath)"
            if ($otherRel -and $otherDest.Length -gt $otherRel.Length + 1 -and $otherDest.EndsWith('\' + $otherRel, [System.StringComparison]::OrdinalIgnoreCase)) {
                $folderThen = $otherDest.Substring(0, $otherDest.Length - $otherRel.Length - 1)
                $names += $folderThen.Substring($folderThen.LastIndexOf('\') + 1)
                break
            }
        }
        $leaf = $destPath.Substring($destPath.LastIndexOf('\') + 1)
        $leafName = ""
        $leafExtension = ""
        if ($leaf -match '^(.+)_memory_dump(\.(?:dmp|raw))$') {
            $leafName = $Matches[1]
            $leafExtension = $Matches[2].ToLowerInvariant()
        }
        if (-not $leafName -or $names -notcontains $leafName) {
            $result.Status = "Refused"
            $result.Reason = "not a name the collector gives this collection's memory dump ($($names[0])_memory_dump.dmp or .raw)"
            return $result
        }
        $result.Extension = $leafExtension
        if ($destPath -notmatch '^[A-Za-z]:\\' -and @(Get-MemoryDumpSiblingPaths -Zip -Folder) -notcontains $destPath) {
            $result.Status = "Refused"
            $result.Reason = "not a path on a drive letter (a network or device path named in a collection is opened only when it is next to the collection zip or folder)"
            return $result
        }
    }

    # The file it names, then the same path on the other drives; the first
    # file of the listed size is the dump
    $wrongSize = $null
    $savedTo = "there"
    $file = Get-MemoryDumpFile $result.Path
    if ($file) {
        if (-not (Get-MemoryDumpSizeMismatch -Listed $result -Length $file.Length)) {
            $result.Path = $file.FullName
            $result.Status = "Found"
            return $result
        }
        $wrongSize = $file
    }
    if (-not $result.InCollection -and $destPath -match '^[A-Za-z]:\\') {
        $result.OtherDrives = $true
        foreach ($root in @(Get-MemoryDumpDriveRoots)) {
            $moved = "$root".TrimEnd('\') + $destPath.Substring(2)
            if ($moved -eq $destPath) { continue }
            $movedFile = Get-MemoryDumpFile $moved
            if (-not $movedFile) { continue }
            if (-not (Get-MemoryDumpSizeMismatch -Listed $result -Length $movedFile.Length)) {
                $result.ListedPath = $destPath
                $result.Path = $movedFile.FullName
                $result.Status = "Found"
                return $result
            }
            if (-not $wrongSize) {
                $wrongSize = $movedFile
                $savedTo = "to $destPath"
                $result.ListedPath = $destPath
            }
        }
    }
    if (-not $wrongSize) {
        $result.Status = "Missing"
        return $result
    }
    $result.Status = "SizeMismatch"
    $result.Path = $wrongSize.FullName
    $result.Reason = "$(Get-MemoryDumpSizeMismatch -Listed $result -Length $wrongSize.Length) for the dump the collector saved $savedTo"
    return $result
}

# A dump that checks 3 to 5 of Find-MemoryDump found: not the file of
# another size that check 2 found (NotThis), and, when
# collection_manifest.csv lists this collection's dump of the same type
# (.dmp or .raw) and the file has a name the collector writes, of the size
# the manifest lists. A file of another size (e.g. a copy cut short) gets
# one warning and is not used; with that size, the manifest's SHA-256 is
# logged. Returns $true to use it.
function Test-MemoryDumpCandidate {
    param([string]$Path, [object]$Listed, [string]$NotThis = "")
    if ($NotThis -and $Path -eq $NotThis) { return $false }
    $leaf = $Path.Substring($Path.LastIndexOf('\') + 1)
    if (-not $Listed.Extension -or $leaf -notmatch '(?:^|_)memory_dump\.(?:dmp|raw)$' -or -not $leaf.EndsWith($Listed.Extension, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $file = Get-MemoryDumpFile $Path
    if (-not $file) { return $true }
    $mismatch = Get-MemoryDumpSizeMismatch -Listed $Listed -Length $file.Length
    if ($mismatch) {
        Write-MemoryDumpNotice -Warning "Memory dump not used: $Path is $mismatch for this collection's dump (a copy cut short?)."
        return $false
    }
    Write-MemoryDumpNotice "Memory dump: $Path ($($Listed.SizeBytes) bytes, as collection_manifest.csv lists for this collection's dump). $(Get-MemoryDumpHashNote $Listed)"
    return $true
}

# Memory dump for this collection: where the collector saved it
# (collection_manifest.csv, Get-ManifestMemoryDump); by default the
# collector saves it next to the zip and the collection folder
# (<collection>_memory_dump.dmp / .raw, named after the folder, like the
# zip) because it is too large to zip; with -NoCompress it stays in the
# collection's Memory\ folder. DumpIt writes Microsoft crash dumps (.dmp);
# WinPmem and Magnet RAM Capture write raw images (.raw). Returns the full
# path or $null. A dump that is offered and then analyzed is looked for
# twice, so each notice is logged once per run (Write-MemoryDumpNotice).
function Find-MemoryDump {
    $script:memoryDumpFromManifest = $false
    $script:memoryDumpListedPath = ""

    # Check 1: -MemoryDumpPath. A path that is not a file is reported once,
    # and the other places are tried.
    if ($MemoryDumpPath) {
        $dumpItem = $null
        try { $dumpItem = Get-Item -LiteralPath $MemoryDumpPath -Force -ErrorAction Stop }
        catch { Write-Verbose "-MemoryDumpPath ${MemoryDumpPath}: $($_.Exception.Message)" }
        if ($dumpItem -is [System.IO.FileInfo]) { return $dumpItem.FullName }
        if (-not $script:memoryDumpPathWarned) {
            Log-Warning "-MemoryDumpPath is not an existing file: $MemoryDumpPath -- looking for the memory dump where the collector saved it and in and next to the collection instead."
            $script:memoryDumpPathWarned = $true
        }
    }

    # Check 2: where the collector saved it, by collection_manifest.csv,
    # also on a drive with another letter now. Not there (outside the
    # collection): moved, deleted, its drive not connected, or this is
    # another machine; the other places are tried. A file of another size
    # is not the dump the collector saved (e.g. a copy cut short): it is
    # not used, here or by the checks below, which check the size of the
    # dumps they find as well (Test-MemoryDumpCandidate).
    $listed = Get-ManifestMemoryDump
    $notThis = ""
    switch ($listed.Status) {
        "Found" {
            $where = "Memory dump where the collector saved it (collection_manifest.csv)"
            if ($listed.ListedPath) { $where = "Memory dump where the collector saved it, on a drive with another letter now (collection_manifest.csv lists $($listed.ListedPath))" }
            Write-MemoryDumpNotice "${where}: $($listed.Path) ($($listed.SizeBytes) bytes, as listed). $(Get-MemoryDumpHashNote $listed)"
            $script:memoryDumpFromManifest = $true
            $script:memoryDumpListedPath = $listed.ListedPath
            return $listed.Path
        }
        "Missing" {
            if (-not $listed.InCollection) {
                $otherDrives = ""
                if ($listed.OtherDrives) { $otherDrives = ", nor at that path on another drive" }
                Write-MemoryDumpNotice "The collector saved the memory dump to $($listed.Path) (collection_manifest.csv); it is not there now$otherDrives (moved, deleted, its drive not connected, or this is another machine). Looking in and next to the collection instead."
            }
        }
        "SizeMismatch" {
            Write-MemoryDumpNotice -Warning "Memory dump not used: $($listed.Path) is $($listed.Reason) (a copy cut short?)."
            $notThis = $listed.Path
        }
        "Refused" {
            Write-MemoryDumpNotice -Warning "Memory dump in collection_manifest.csv not used: $($listed.Path) is $($listed.Reason)."
        }
    }

    # Check 3: Sibling of the selected zip (browse mode, or a zip as -InputPath)
    foreach ($siblingDump in @(Get-MemoryDumpSiblingPaths -Zip)) {
        if ((Test-Path -LiteralPath $siblingDump) -and (Test-MemoryDumpCandidate -Path $siblingDump -Listed $listed -NotThis $notThis)) { return $siblingDump }
    }

    # Check 4: Inside the collection directory (uncompressed collections)
    $memFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("memory_dump.dmp", "memory_dump.raw", "memdump.raw", "memory.raw", "physmem.raw"))
    foreach ($memFile in $memFiles) {
        if (Test-MemoryDumpCandidate -Path $memFile.FullName -Listed $listed -NotThis $notThis) { return $memFile.FullName }
    }

    # Check 5: Next to the collection folder and next to -InputPath, by the
    # collection folder's name only (Get-MemoryDumpSiblingPaths)
    foreach ($namedDump in @(Get-MemoryDumpSiblingPaths -Folder)) {
        if ((Test-Path -LiteralPath $namedDump -PathType Leaf) -and (Test-MemoryDumpCandidate -Path $namedDump -Listed $listed -NotThis $notThis)) { return $namedDump }
    }
    return $null
}

# What to say when Find-MemoryDump found no dump to use. Note: what
# collection_manifest.csv lists. Remedy: how to have the dump analyzed,
# which works from Run-TimelineBuilder.bat too (it cannot pass
# -MemoryDumpPath): copy the dump where Find-MemoryDump looks, next to the
# collection zip (else next to the collection folder) under its name, or
# connect the drive the collector saved it to.
function Get-MemoryDumpNotFoundText {
    param([object]$Listed)
    $extension = $Listed.Extension
    if (-not $extension) { $extension = ".dmp" }
    $targets = @(Get-MemoryDumpSiblingPaths -Zip)
    if ($targets.Count -eq 0) { $targets = @(Get-MemoryDumpSiblingPaths -Folder) }
    $target = @($targets | Where-Object { $_.EndsWith("_memory_dump$extension", [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    $remedy = "copy the dump next to the collection zip or folder as <collection folder name>_memory_dump$extension"
    if ($target) { $remedy = "copy the dump to $target" }
    if (-not $Listed.Extension) { $remedy += " (_memory_dump.raw for a raw image)" }
    elseif ($Listed.SizeBytes) { $remedy += " (collection_manifest.csv lists $($Listed.SizeBytes) bytes)" }
    $note = switch ($Listed.Status) {
        "None" {
            if ((Get-CollectionManifest).Path) { "collection_manifest.csv lists none (the collector saved no complete dump)" }
            else { "there is no collection_manifest.csv that says where the collector saved one" }
        }
        "Missing" {
            if ($Listed.InCollection) {
                "collection_manifest.csv lists one in the collection ($($Listed.RelativePath)), which the collector moves next to the zip as $([System.IO.Path]::GetFileName((Get-CollectionRootFolder)))_memory_dump$($Listed.Extension) when it zips the collection"
            }
            else {
                $otherDrives = ""
                if ($Listed.OtherDrives) { $otherDrives = ", nor at that path on another drive" }
                "the collector saved it to $($Listed.Path) (collection_manifest.csv), and it is not there now$otherDrives"
            }
        }
        default { "collection_manifest.csv lists one at $($Listed.Path), which was not used (see the warning above)" }
    }
    if ($Listed.Status -eq "Missing" -and $Listed.OtherDrives) { $remedy = "connect the drive the collector saved it to, or $remedy" }
    return [PSCustomObject]@{ Note = $note; Remedy = $remedy }
}

# The offer step found no dump: when collection_manifest.csv lists one,
# say what became of it and how to have it analyzed. This is all a user of
# Run-TimelineBuilder.bat sees of it (Memory is not in its -Sources, so
# the Memory parser does not run), and the .bat cannot pass -MemoryDumpPath
function Write-NoMemoryDumpToOffer {
    $listed = Get-ManifestMemoryDump
    if ($listed.Status -eq "None") { return }
    $notFound = Get-MemoryDumpNotFoundText -Listed $listed
    Log ""
    Log "No memory dump to offer: $($notFound.Note)."
    Log "  To have it analyzed, $($notFound.Remedy), then run the builder again."
    Log ""
}

# A memory dump as the user is shown it: "<path in the collection> in the
# collection" when it is inside the collection folder (for a zip, in the
# work folder), else its full path (next to the zip, on another drive, ...)
function Get-MemoryDumpDisplayName {
    param([string]$Path)
    $root = Get-CollectionRootFolder
    if ($Path.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        return "$($Path.Substring($root.Length + 1)) in the collection"
    }
    return $Path
}

# What the header of a memory dump says, read once:
# - Architecture: of a Microsoft crash dump ("PAGEDU64": machine type at
#   0x30; "PAGEDUMP": 32-bit x86); "Raw" for raw images, "Unknown" if the
#   header can't be read.
# - CaptureTimeUtc: when the memory was captured. 64-bit crash dumps store
#   it as DUMP_HEADER64.SystemTime at 0xFA8 (DumpIt: the start of the
#   acquisition). Raw images, 32-bit dumps and a header time that is zero,
#   before 1980 or more than a day after the file's last write fall back to
#   the file's last-write time. TimeSource says which one it is.
# - LastWriteUtc: the file's last-write time, the end of the acquisition.
# The file is opened read-only, also while another program has it open.
function Get-MemoryDumpInfo {
    param([string]$Path)
    $info = [PSCustomObject]@{ Architecture = "Unknown"; CaptureTimeUtc = $null; TimeSource = ""; LastWriteUtc = $null }
    $header = New-Object byte[] 0xFB0
    $read = 0
    try {
        $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $info.LastWriteUtc = $file.LastWriteTimeUtc
        $info.CaptureTimeUtc = $file.LastWriteTimeUtc
        $info.TimeSource = "dump file last-write time"
        $stream = New-Object System.IO.FileStream($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            while ($read -lt $header.Length) {
                $count = $stream.Read($header, $read, $header.Length - $read)
                if ($count -le 0) { break }
                $read += $count
            }
        }
        finally { $stream.Dispose() }
    }
    catch {
        Write-Verbose "Could not read memory dump header of ${Path}: $($_.Exception.Message)"
        return $info
    }
    if ($read -lt 0x40) { return $info }
    $signature = [System.Text.Encoding]::ASCII.GetString($header, 0, 8)
    if ($signature -eq "PAGEDUMP") { $info.Architecture = "x86"; return $info }
    if ($signature -ne "PAGEDU64") { $info.Architecture = "Raw"; return $info }
    switch ([BitConverter]::ToUInt32($header, 0x30)) {
        0x8664 { $info.Architecture = "x64" }
        0xAA64 { $info.Architecture = "ARM64" }
    }
    if ($read -lt 0xFB0) { return $info }
    $fileTime = [BitConverter]::ToInt64($header, 0xFA8)
    if ($fileTime -le 0 -or $fileTime -gt [datetime]::MaxValue.ToFileTimeUtc()) { return $info }
    $systemTime = [datetime]::FromFileTimeUtc($fileTime)
    if ($systemTime.Year -ge 1980 -and $systemTime -le $info.LastWriteUtc.AddDays(1)) {
        $info.CaptureTimeUtc = $systemTime
        $info.TimeSource = "crash dump header"
    }
    return $info
}

# Runs one Volatility 3 plugin on the dump with JSON output. The JSON goes
# to a file in the work folder's scratch folder and is read back; the file
# is deleted again. stderr is kept in memory: a 2> redirection cannot write
# to a path with [ ] in it (-WorkDir may have them), and its lines must not
# stop the run (Windows PowerShell makes them errors). Returns Json (the
# output, "" for none) and Errors (the stderr lines).
function Invoke-VolatilityPlugin {
    param([string]$VolExe, [string]$DumpPath, [string]$Plugin)
    $ErrorActionPreference = "Continue"
    $jsonFile = Join-Path (Get-ScratchFolder) "vol3_$($Plugin -replace '\.','_')_$(Get-Random).json"
    $errorLines = New-Object System.Collections.Generic.List[string]
    try {
        & $VolExe -f $DumpPath -r json $Plugin 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $errorLines.Add("$_") } else { $_ }
        } | Out-File -LiteralPath $jsonFile -Encoding utf8
        $json = ""
        if (Test-Path -LiteralPath $jsonFile) { $json = [System.IO.File]::ReadAllText($jsonFile) }
        return [PSCustomObject]@{ Json = $json; Errors = ($errorLines -join "`n") }
    }
    finally { Remove-Item -LiteralPath $jsonFile -Force -ErrorAction SilentlyContinue }
}

# Own time of a Volatility entry (pslist CreateTime, netscan Created): text,
# or a [datetime] where PowerShell 7's ConvertFrom-Json made one. TimeUtc is
# set when the time is valid, from 1980 up to -LatestUtc. Text is a time
# that is there but not used: in UTC as yyyy-MM-dd HH:mm:ss.fff when it
# parses (the same in both PowerShell versions), else as found.
function Get-MemoryEntryTime {
    param($Value, [datetime]$LatestUtc)
    $result = [PSCustomObject]@{ TimeUtc = $null; Text = "" }
    $raw = "$Value".Trim()
    if ($raw -eq "" -or $raw -eq "N/A") { return $result }
    $time = ConvertFrom-UtcText $Value
    if ($null -eq $time) { $result.Text = $raw }
    elseif ($time.Year -lt 1980 -or $time -gt $LatestUtc) {
        $result.Text = $time.ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    else { $result.TimeUtc = $time }
    return $result
}

# A number of a Volatility 3 entry (PID, PPID, Threads, SessionId, a port)
# as text for a row: "" when it is absent (null, empty or N/A). 0 is a
# value and is kept: PID 0, PPID 0 (System), SessionId 0 (services),
# Threads 0 (a process that has exited), port 0.
function Get-MemoryFieldText {
    param($Value)
    $text = "$Value".Trim()
    if ($text -eq "N/A") { return "" }
    return $text
}

# Timeline rows for the entries of one Volatility 3 plugin (its JSON output
# through ConvertFrom-Json). Every row starts as a Snapshot row at the
# dump's capture time and is an event only when its entry has a valid time
# of its own (Get-MemoryEntryTime, up to a day after the end of the
# acquisition):
# - pslist: CreateTime -> ProcessCreation at that time
# - netscan: Created -> NetworkConnection at that time
# - cmdline, svcscan: always Snapshot. A command line is read from the
#   process's own memory, which the process can change, and a service
#   record is the service's state; neither says when something happened.
# A time that is there but not valid is kept in Details (CreateTime=,
# Created=). Returns the row counts: Entries, Timed and Snapshot.
function Add-MemoryPluginRows {
    param(
        [string]$Plugin,
        [string]$Source,
        [object[]]$Entries,
        [datetime]$CaptureTimeUtc,
        [datetime]$AcquisitionEndUtc,
        [string]$DumpPath
    )
    $latestUtc = $AcquisitionEndUtc.AddDays(1)
    $timed = 0
    $snapshot = 0

    foreach ($entry in $Entries) {
        $ts = $CaptureTimeUtc
        $eventType = "Snapshot"

        # The counters are inside each branch: "continue" in a switch only
        # leaves the switch, so a counter after it would count skipped entries
        switch ($Plugin) {
            "windows.pslist" {
                $created = Get-MemoryEntryTime -Value $entry.CreateTime -LatestUtc $latestUtc
                $procId = Get-MemoryFieldText $entry.PID
                $ppid = Get-MemoryFieldText $entry.PPID
                $name = if ($entry.ImageFileName) { $entry.ImageFileName } else { "Unknown" }
                $threads = Get-MemoryFieldText $entry.Threads
                $session = Get-MemoryFieldText $entry.SessionId
                $details = "Threads=$threads SessionId=$session"
                if ($null -ne $created.TimeUtc) {
                    $ts = $created.TimeUtc
                    $eventType = "ProcessCreation"
                    $timed++
                }
                else {
                    if ($created.Text) { $details += " CreateTime=$($created.Text)" }
                    $snapshot++
                }

                Add-TimelineEntry -Timestamp $ts -Source $Source -EventType $eventType `
                    -Description "Process in memory: $name (PID: $procId, PPID: $ppid)" `
                    -Details $details `
                    -Artifact "MemoryDump" -RawPath $DumpPath
            }
            "windows.netscan" {
                $created = Get-MemoryEntryTime -Value $entry.Created -LatestUtc $latestUtc
                $proto = if ($entry.Proto) { $entry.Proto } else { "" }
                $localAddr = if ($entry.LocalAddr) { "$($entry.LocalAddr):$(Get-MemoryFieldText $entry.LocalPort)" } else { "" }
                $foreignAddr = if ($entry.ForeignAddr) { "$($entry.ForeignAddr):$(Get-MemoryFieldText $entry.ForeignPort)" } else { "" }
                $state = if ($entry.State) { $entry.State } else { "" }
                $procId = Get-MemoryFieldText $entry.PID
                # Owner is the process that owns the socket, not an account
                $details = "PID=$procId"
                if ($entry.Owner) { $details += " Process=$($entry.Owner)" }
                if ($null -ne $created.TimeUtc) {
                    $ts = $created.TimeUtc
                    $eventType = "NetworkConnection"
                    $timed++
                }
                else {
                    if ($created.Text) { $details += " Created=$($created.Text)" }
                    $snapshot++
                }

                Add-TimelineEntry -Timestamp $ts -Source $Source -EventType $eventType `
                    -Description "Memory network: $proto $localAddr -> $foreignAddr ($state)" `
                    -Details $details `
                    -Artifact "MemoryDump" -RawPath $DumpPath
            }
            "windows.cmdline" {
                $procId = Get-MemoryFieldText $entry.PID
                $procName = if ($entry.Process) { $entry.Process } else { "" }
                $cmdArgs = if ($entry.Args) { $entry.Args } else { "" }
                if (-not $cmdArgs -or $cmdArgs -eq "N/A") { continue }

                Add-TimelineEntry -Timestamp $ts -Source $Source -EventType $eventType `
                    -Description "Process command line: $procName (PID: $procId)" `
                    -Details "Args=$cmdArgs" `
                    -Artifact "MemoryDump" -RawPath $DumpPath
                $snapshot++
            }
            "windows.svcscan" {
                $svcName = if ($entry.Name) { $entry.Name } else { "" }
                $display = if ($entry.Display) { $entry.Display } else { $svcName }
                $binary = if ($entry.Binary) { $entry.Binary } else { "" }
                $state = if ($entry.State) { $entry.State } else { "" }
                $start = if ($entry.Start) { $entry.Start } else { "" }
                $procId = Get-MemoryFieldText $entry.PID

                Add-TimelineEntry -Timestamp $ts -Source $Source -EventType $eventType `
                    -Description "Service in memory: $display ($svcName)" `
                    -Details "State=$state StartType=$start Binary=$binary PID=$procId" `
                    -Artifact "MemoryDump" -RawPath $DumpPath
                $snapshot++
            }
        }
    }
    return [PSCustomObject]@{ Entries = $timed + $snapshot; Timed = $timed; Snapshot = $snapshot }
}

# Volatility 3 next to the builder (tools\volatility3\, tools\ or the
# builder's folder). Returns the full path or $null. A function of its own
# so a test can put a stub in its place.
function Find-VolatilityExe {
    $volLocations = @(
        (Join-Path $PSScriptRoot "tools\volatility3\vol.exe"),
        (Join-Path $PSScriptRoot "tools\volatility3\volatility3.exe"),
        (Join-Path $PSScriptRoot "tools\vol.exe"),
        (Join-Path $PSScriptRoot "vol.exe")
    )
    foreach ($loc in $volLocations) {
        if (Test-Path $loc) { return $loc }
    }
    return $null
}

function Parse-Memory {
    Log "--- Parsing Memory Dump (Volatility 3) ---"

    $memParsed = $false

    # --- Find the memory dump file ---
    $dumpPath = Find-MemoryDump

    if (-not $dumpPath) {
        # What collection_manifest.csv said, and how to have the dump found
        $notFound = Get-MemoryDumpNotFoundText -Listed (Get-ManifestMemoryDump)
        Log-Warning "No memory dump found in or next to the collection; $($notFound.Note). To have it analyzed, $($notFound.Remedy), or pass the file as -MemoryDumpPath."
        Log "  Memory parsing complete."
        Log ""
        return
    }

    $dumpSizeGB = [math]::Round((Get-Item -LiteralPath $dumpPath).Length / 1GB, 2)
    $dumpInfo = Get-MemoryDumpInfo -Path $dumpPath
    $dumpArch = $dumpInfo.Architecture
    Log "  Found memory dump: $dumpPath ($dumpSizeGB GB, $dumpArch)"
    # The time of the Snapshot rows (entries without a valid time of their own)
    Log "  Dump time: $($dumpInfo.CaptureTimeUtc.ToString('yyyy-MM-dd HH:mm:ss.fff', [System.Globalization.CultureInfo]::InvariantCulture)) UTC ($($dumpInfo.TimeSource))"

    # Volatility 3's Windows support is for Intel x86/x64 memory only
    if ($dumpArch -eq "ARM64") {
        Log-Warning "  This is a Windows ARM64 memory dump. Volatility 3 cannot analyze Windows ARM64 memory, so memory analysis is skipped."
        Log "  The .dmp file is a Microsoft crash dump: open it in WinDbg to examine it manually."
        Log "  Memory parsing complete."
        Log ""
        return
    }
    Log "  Analyzing in-place (not copied to temp)"

    # --- Find Volatility 3 ---
    $volExe = Find-VolatilityExe

    if (-not $volExe) {
        Log-Warning "  Volatility 3 not found in tools\ directory."
        Log ""
        Log "  To enable memory analysis:"
        Log "    1. Download Volatility 3 standalone from:"
        Log "       https://github.com/volatilityfoundation/volatility3/releases"
        Log "    2. Place vol.exe in: $(Join-Path $PSScriptRoot 'tools\volatility3\vol.exe')"
        Log ""
        Log "  Skipping memory analysis."
        Log "  Memory parsing complete."
        Log ""
        return
    }

    Log "  Using Volatility 3: $volExe"

    # --- Define plugins to run ---
    # The EventType of each row depends on the entry (Add-MemoryPluginRows)
    $plugins = @(
        @{ Name = "windows.pslist";  Source = "Memory-Processes";   Desc = "Running processes" },
        @{ Name = "windows.netscan"; Source = "Memory-Network";     Desc = "Network connections" },
        @{ Name = "windows.cmdline"; Source = "Memory-CommandLine"; Desc = "Process command lines" },
        @{ Name = "windows.svcscan"; Source = "Memory-Services";    Desc = "Windows services" }
    )

    $totalMemEntries = 0

    foreach ($plugin in $plugins) {
        $pluginTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Log "  Running $($plugin.Name) ($($plugin.Desc))..."

        try {
            # Run Volatility 3 with JSON output
            $volResult = Invoke-VolatilityPlugin -VolExe $volExe -DumpPath $dumpPath -Plugin $plugin.Name

            if (-not $volResult.Json.Trim()) {
                $errContent = if ($volResult.Errors) { $volResult.Errors } else { "No output" }
                Log-Warning "    $($plugin.Name) produced no output. Error: $($errContent.Substring(0, [Math]::Min(200, $errContent.Length)))"
                continue
            }

            $entries = $volResult.Json | ConvertFrom-Json -ErrorAction Stop
            $rowCounts = Add-MemoryPluginRows -Plugin $plugin.Name -Source $plugin.Source -Entries $entries `
                -CaptureTimeUtc $dumpInfo.CaptureTimeUtc -AcquisitionEndUtc $dumpInfo.LastWriteUtc -DumpPath $dumpPath

            $pluginTimer.Stop()
            $elapsed = [math]::Round($pluginTimer.Elapsed.TotalSeconds, 1)
            Log "    $($plugin.Name): $($rowCounts.Entries) entries ($($rowCounts.Timed) timed, $($rowCounts.Snapshot) snapshot) in $elapsed seconds"
            $totalMemEntries += $rowCounts.Entries
            $memParsed = $true
        }
        catch {
            Log-Warning "    $($plugin.Name) failed: $($_.Exception.Message)"
        }
    }

    if ($memParsed) {
        Log-Success "  Memory analysis complete: $totalMemEntries entries from $dumpSizeGB GB dump"
    } else {
        Log-Warning "  No memory artifacts extracted. Check Volatility 3 compatibility."
    }
    Log "  Memory parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 16. System Info Parser
# ----------------------------------------------------------
# "Name:   value" lines of systeminfo output (English) as a hashtable; the
# indented lines of lists (processors, hotfixes, NICs) are left out, and a
# name seen twice keeps its first value
function ConvertFrom-SystemInfoText {
    param([string[]]$Lines)
    $values = @{}
    foreach ($line in $Lines) {
        if ($line -match '^(\S[^:]*?):\s+(\S.*?)\s*$' -and -not $values.ContainsKey($Matches[1])) { $values[$Matches[1]] = $Matches[2] }
    }
    return $values
}

function Parse-SystemInfo {
    Log "--- Parsing System Info ---"

    # systeminfo.txt (live collections only). Install and boot times are local
    # time of the collector host in its culture (e.g. "9/18/2025, 2:25:51 PM").
    $infoFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("systeminfo.txt"))
    if ($infoFiles.Count -eq 0) { Log-Warning "No systeminfo.txt found in the collection." }
    foreach ($file in $infoFiles) {
        Log "  Parsing: $($file.FullName)"
        try {
            $values = ConvertFrom-SystemInfoText -Lines (Get-Content -Path $file.FullName -ErrorAction Stop)
            if (-not $values["OS Name"]) {
                Log-Warning "    No 'OS Name' line found (systeminfo output in another language?) -- skipped."
                continue
            }
            $user = Get-CollectionUser $file.FullName
            $osVersion = [string]$values["OS Version"]
            $version = if ($osVersion -match '^(\d+(?:\.\d+)+)') { $Matches[1] } else { $osVersion }
            $build = if ($osVersion -match 'Build (\d+)') { $Matches[1] } else { "" }
            $osDetails = [ordered]@{ Host = $values["Host Name"]; OS = $values["OS Name"]; Version = $version; Build = $build }
            $rows = 0

            foreach ($spec in @(@("Original Install Date", "Installation", "Windows installed"), @("System Boot Time", "ServiceChange", "System booted"))) {
                $text = $values[$spec[0]]
                if (-not $text) { continue }
                $utc = ConvertFrom-CollectorLocalText $text
                if (-not $utc) {
                    Log-Warning "    Could not parse $($spec[0]): '$text'"
                    continue
                }
                $details = [ordered]@{}
                foreach ($k in $osDetails.Keys) { $details[$k] = $osDetails[$k] }
                $details["LocalTime"] = "$text (collector time zone $((Get-CollectionInfo).CollectorTimeZone.Id))"
                Add-TimelineEntry -Timestamp $utc -Source "SystemInfo" -EventType $spec[1] `
                    -Description $spec[2] `
                    -User $user -Details (Format-ArtifactDetails $details) `
                    -Artifact "SystemInfo" -RawPath $file.FullName
                $rows++
            }

            # The system as collected
            $snapshotTs = Get-SnapshotTimeUtc -File $file
            if ($snapshotTs) {
                $desc = "System: $($values['OS Name'])"
                if ($version) { $desc += " $version" }
                if ($build) { $desc += " build $build" }
                if ($values["System Type"]) { $desc += " ($($values['System Type']))" }
                if ($values["Domain"]) { $desc += ", domain $($values['Domain'])" }
                $details = [ordered]@{}
                foreach ($k in $osDetails.Keys) { $details[$k] = $osDetails[$k] }
                $details["SystemType"] = $values["System Type"]
                $details["Domain"] = $values["Domain"]
                $details["Configuration"] = $values["OS Configuration"]
                $details["Model"] = (@($values["System Manufacturer"], $values["System Model"]) | Where-Object { $_ }) -join " "
                $details["TimeZone"] = $values["Time Zone"]
                Add-TimelineEntry -Timestamp $snapshotTs -Source "SystemInfo" -EventType "Snapshot" `
                    -Description $desc `
                    -User $user -Details (Format-ArtifactDetails $details) `
                    -Artifact "SystemInfo" -RawPath $file.FullName
                $rows++
            }
            Log "    Added $rows timeline entries"
        }
        catch { Log-Warning "  Failed to parse $($file.Name): $($_.Exception.Message)" }
    }

    # Enabled firewall rules (Get-NetFirewallRule -Enabled True | Format-Table
    # DisplayName, Direction, Action, Profile). Only inbound allow rules --
    # what lets other hosts connect in -- become Snapshot rows.
    $fwFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("firewall_rules.txt"))
    foreach ($file in $fwFiles) {
        Log "  Parsing: $($file.FullName)"
        try {
            $snapshotTs = Get-SnapshotTimeUtc -File $file
            $rules = @(ConvertFrom-FormatTableText -Lines (Get-Content -Path $file.FullName -ErrorAction Stop))
            if ($rules.Count -eq 0) {
                Log "    No firewall rule table found."
                continue
            }
            if (-not $rules[0].PSObject.Properties["Direction"] -or -not $rules[0].PSObject.Properties["Action"]) {
                # Format-Table drops columns that do not fit the console width
                Log-Warning "    $($rules.Count) rule(s) listed without Direction/Action columns (the table was too wide when collected) -- inbound allow rules cannot be identified; none added."
                continue
            }
            if (-not $snapshotTs) {
                Log-Warning "    Collection time unknown -- firewall rules skipped."
                continue
            }
            # A long name wrapped by -Wrap continues on lines whose other
            # columns are empty: join those to the rule above
            $merged = New-Object System.Collections.Generic.List[object]
            foreach ($rule in $rules) {
                $name = Get-ArtifactRowValue $rule @("DisplayName", "Name")
                if ($merged.Count -gt 0 -and -not (Get-ArtifactRowValue $rule @("Direction")) -and -not (Get-ArtifactRowValue $rule @("Action"))) {
                    $merged[$merged.Count - 1].Name += " $name"
                    continue
                }
                $merged.Add([PSCustomObject]@{
                    Name      = $name
                    Direction = Get-ArtifactRowValue $rule @("Direction")
                    Action    = Get-ArtifactRowValue $rule @("Action")
                    Enabled   = Get-ArtifactRowValue $rule @("Enabled")
                    Profile   = Get-ArtifactRowValue $rule @("Profile")
                })
            }
            $user = Get-CollectionUser $file.FullName
            $added = 0
            foreach ($rule in $merged) {
                # Enum names, or the numbers (Inbound = 1, Allow = 2)
                if (@("Inbound", "1") -notcontains $rule.Direction -or @("Allow", "2") -notcontains $rule.Action) { continue }
                if ($rule.Enabled -and @("True", "1") -notcontains $rule.Enabled) { continue }
                $name = $rule.Name.Trim()
                if (-not $name) { continue }
                Add-TimelineEntry -Timestamp $snapshotTs -Source "Firewall" -EventType "Snapshot" `
                    -Description "Firewall rule (enabled, inbound allow): $name" `
                    -User $user `
                    -Details (Format-ArtifactDetails ([ordered]@{ Direction = "Inbound"; Action = "Allow"; Profile = $rule.Profile })) `
                    -Artifact "SystemInfo" -RawPath $file.FullName
                $added++
            }
            Log "    $added inbound allow rule(s) of $($merged.Count) enabled rule(s) (snapshot)"
        }
        catch { Log-Warning "  Failed to parse $($file.Name): $($_.Exception.Message)" }
    }

    Log "  System info parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 17. Antivirus Log Parser
# ----------------------------------------------------------
# Third-party antivirus logs that the collector copies to AntiVirus\<vendor>\
# (file names kept, folders flattened):
#   Symantec_SEP\    Symantec AntiVirus / SEP risk and scan logs (Logs\AV\MMDDYYYY.Log)
#   Sophos\          Sophos Anti-Virus for Windows SAV.txt
#   McAfee_Trellix\  McAfee VirusScan Enterprise AccessProtectionLog.txt
#   ESET\            virlog.dat ("Detected threats" log; binary, best effort)
# Detections, blocks, remediation results and protection failures become
# SecurityAlert rows. Routine records (scan started/finished, definitions
# loaded, engine version) are counted and skipped: they are frequent, have no
# EventType of their own and add little to an investigation -- the log is
# still named in RawPath. Other files and vendor folders are skipped
# (Write-Verbose). Microsoft Defender's event log, Get-MpThreatDetection
# output and support logs are covered by Parse-EventLogs; its
# DetectionHistory files and quarantine entries are read here (see
# Read-DefenderDetectionHistory and Read-DefenderQuarantineEntry).

# Lines of a text log. A byte order mark decides the encoding; without one,
# UTF-16LE is recognized by its zero high bytes, then strict UTF-8 is tried,
# and anything else is read in the ANSI code page.
function Read-AntiVirusTextLines {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $start = 0
    $encoding = $null
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $encoding = [System.Text.Encoding]::UTF8; $start = 3 }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $encoding = [System.Text.Encoding]::Unicode; $start = 2 }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { $encoding = [System.Text.Encoding]::BigEndianUnicode; $start = 2 }
    elseif ($bytes.Length -ge 4 -and $bytes[0] -ne 0 -and $bytes[1] -eq 0 -and $bytes[2] -ne 0 -and $bytes[3] -eq 0) { $encoding = [System.Text.Encoding]::Unicode }

    if ($encoding) {
        $text = $encoding.GetString($bytes, $start, $bytes.Length - $start)
    }
    else {
        try { $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) }
        catch {
            Write-Verbose "$Path is not UTF-8, reading it as ANSI: $($_.Exception.Message)"
            $text = [System.Text.Encoding]::Default.GetString($bytes)
        }
    }
    return ,($text -split '\r?\n')
}

# Name for a numeric code from a lookup table; the code itself if unknown
function Get-AntiVirusCodeName {
    param([hashtable]$Names, [string]$Code)
    $c = "$Code".Trim()
    if ($Names.ContainsKey($c)) { return $Names[$c] }
    return $c
}

# Fields of one comma-separated line: "..." quotes a field, "" inside quotes
# is a literal quote. Splitting on the quotes first keeps this linear.
function Split-AntiVirusCsvLine {
    param([string]$Line)
    $fields = New-Object System.Collections.Generic.List[string]
    $current = New-Object System.Text.StringBuilder
    $parts = $Line.Split([char]'"')
    for ($i = 0; $i -lt $parts.Length; $i++) {
        if ($i % 2 -eq 1) {
            # Odd parts are inside quotes
            [void]$current.Append($parts[$i])
            continue
        }
        if ($parts[$i] -eq "") {
            # Nothing between two quoted parts: an escaped quote ("")
            if ($i -gt 0 -and $i -lt $parts.Length - 1) { [void]$current.Append('"') }
            continue
        }
        $pieces = $parts[$i].Split([char]',')
        [void]$current.Append($pieces[0])
        for ($j = 1; $j -lt $pieces.Length; $j++) {
            $fields.Add($current.ToString())
            [void]$current.Clear()
            [void]$current.Append($pieces[$j])
        }
    }
    $fields.Add($current.ToString())
    return ,$fields.ToArray()
}

# Symantec log time: six hex octets = years since 1970, month (0-11), day,
# hour, minute, second, e.g. 2A0A1E0A2F1D = 2012-11-30 10:47:29. It is the
# examined machine's local time (plaso reads it the same way; in the public
# sample the Unix-time scan ID of a scan fits a local time of UTC-7).
# Returns Kind=Unspecified or $null.
function ConvertFrom-SymantecHexTime {
    param([string]$Hex)
    if ($Hex -notmatch '^[0-9A-Fa-f]{12}$') { return $null }
    $o = @(foreach ($i in 0..5) { [Convert]::ToInt32($Hex.Substring($i * 2, 2), 16) })
    try { return New-Object DateTime (1970 + $o[0]), ($o[1] + 1), $o[2], $o[3], $o[4], $o[5] }
    catch {
        Write-Verbose "Invalid Symantec log time '$Hex': $($_.Exception.Message)"
        return $null
    }
}

# Symantec AntiVirus / SEP AV log (one comma-separated record per line).
# Fields used (0-based): 0 time, 1 event, 2 category, 3 logger, 4 computer,
# 5 user, 6 threat, 7 file, 8 first action, 9 second action, 10 action taken,
# 13 message. Code meanings from the SEPparser "Log Line Info" wiki page.
function Read-SymantecAvLog {
    param([System.IO.FileInfo]$File, [string[]]$Lines, [System.TimeZoneInfo]$TimeZone)

    # Events kept as SecurityAlert ("NAME|description"): detections and their
    # remediation, Tamper Protection, and protection that failed or was turned
    # off. Any other event is kept too if it names a threat or has category 1
    # (Infection); everything else (scans, definition loads, service start/stop,
    # licensing, client check-ins) is routine.
    $alertEvents = @{
        5  = "INFECTION|threat detected"
        11 = "TRAP|Auto-Protect not fully operational"
        17 = "TOO_MANY_VIRUSES|too many threats found"
        22 = "RTS_LOAD_ERROR|Auto-Protect failed to load"
        40 = "BAD_DEFS_UNPROTECTED|bad definitions, client unprotected"
        42 = "RTS_ERROR|Auto-Protect error"
        45 = "SECURITY_SYMPROTECT_POLICYVIOLATION|Tamper Protection blocked access"
        46 = "ANOMALY_START|threat remediation started"
        47 = "DETECTION_ACTION_TAKEN|action taken on threat"
        48 = "REMEDIATION_ACTION_PENDING|remediation pending"
        49 = "REMEDIATION_ACTION_FAILED|remediation failed"
        50 = "REMEDIATION_ACTION_SUCCESSFUL|remediation succeeded"
        51 = "ANOMALY_FINISH|threat remediation finished"
        72 = "INTERESTING_PROCESS_DETECTED_START|suspicious process detected"
        73 = "LOAD_ERROR_BASH|SONAR failed to load"
        74 = "LOAD_ERROR_BASH_DEFINITIONS|SONAR definitions failed to load"
        75 = "INTERESTING_PROCESS_DETECTED_FINISH|suspicious process detection finished"
        77 = "HEUR_THREAT_NOW_KNOWN|heuristic detection now identified"
        78 = "DISABLE_BASH|SONAR disabled"
        80 = "DEFS_LOAD_FAILED|definitions failed to load"
        86 = "ELAM_LOAD_FAILED|ELAM driver failed to load"
        89 = "ELAM_DISABLE|ELAM disabled"
        90 = "ELAM_BAD|ELAM detected a bad driver"
        91 = "ELAM_BAD_REPORTED_AS_UNKNOWN|ELAM bad driver reported as unknown"
        92 = "DISABLE_SYMPROTECT|Tamper Protection disabled"
    }
    $categoryNames = @{ "1" = "Infection"; "2" = "Summary"; "3" = "Pattern"; "4" = "Security" }
    $loggerNames = @{ "0" = "Scheduled scan"; "1" = "Manual scan"; "2" = "Auto-Protect"; "3" = "Integrity Shield";
        "6" = "Console"; "7" = "VPDOWN"; "8" = "System"; "9" = "Startup scan"; "10" = "Idle scan"; "11" = "DefWatch";
        "12" = "Licensing"; "13" = "Manual quarantine"; "14" = "Tamper Protection"; "15" = "Reboot processing";
        "16" = "SONAR"; "17" = "ELAM"; "18" = "Power Eraser"; "19" = "EOC scan" }
    # 0 = no action
    $actionNames = @{ "0" = ""; "1" = "Quarantine"; "2" = "Rename"; "3" = "Delete"; "4" = "Leave alone"; "5" = "Clean";
        "6" = "Remove macros"; "7" = "Save file as"; "8" = "Sent to backend"; "9" = "Restore from quarantine";
        "10" = "Rename back"; "11" = "Undo action"; "12" = "Error"; "13" = "Backup to quarantine";
        "14" = "Pending analysis"; "15" = "Partially fixed"; "16" = "Terminate process required";
        "17" = "Exclude from scanning"; "18" = "Reboot processing"; "19" = "Clean by deletion"; "20" = "Access denied";
        "21" = "Terminate process only"; "22" = "No repair"; "23" = "Fail"; "24" = "Run Power Eraser";
        "25" = "No repair (Power Eraser)" }

    $added = 0
    $routine = 0
    $unreadable = 0
    foreach ($line in $Lines) {
        if ($line -notmatch '^[0-9A-Fa-f]{12},') { continue }
        $f = Split-AntiVirusCsvLine $line
        $code = 0
        if ($f.Count -lt 14 -or -not [int]::TryParse($f[1], [ref]$code)) { $unreadable++; continue }
        $virus = $f[6].Trim()
        $path = $f[7].Trim()
        if (-not $alertEvents.ContainsKey($code) -and $f[2].Trim() -ne "1" -and -not $virus) { $routine++; continue }
        $local = ConvertFrom-SymantecHexTime $f[0]
        if ($null -eq $local) { $unreadable++; continue }

        $names = @("", "event $code")
        if ($alertEvents.ContainsKey($code)) { $names = $alertEvents[$code] -split '\|' }
        $actionTaken = Get-AntiVirusCodeName $actionNames $f[10]
        $message = $f[13].Trim()
        $subject = (@($virus, $path) | Where-Object { $_ }) -join " in "
        if (-not $subject) { $subject = $message }
        $desc = "Symantec $($names[1])"
        if ($subject) { $desc += ": $subject" }
        if ($actionTaken) { $desc += " ($actionTaken)" }

        Add-TimelineEntry -Timestamp (Convert-LocalToUtc -Local $local -TimeZone $TimeZone) -Source "AV-Symantec" -EventType "SecurityAlert" `
            -Description $desc `
            -User $f[5].Trim() `
            -Details (Format-ArtifactDetails ([ordered]@{
                Event        = "$code $($names[0])".Trim()
                Category     = Get-AntiVirusCodeName $categoryNames $f[2]
                Logger       = Get-AntiVirusCodeName $loggerNames $f[3]
                Threat       = $virus
                File         = $path
                ActionTaken  = $actionTaken
                FirstAction  = Get-AntiVirusCodeName $actionNames $f[8]
                SecondAction = Get-AntiVirusCodeName $actionNames $f[9]
                Computer     = $f[4]
                Message      = $message
                LogTime      = $local.ToString("yyyy-MM-dd HH:mm:ss") + " (target local time)"
            })) `
            -Artifact "AntiVirus" -RawPath $File.FullName
        $added++
    }
    $note = "$routine routine record(s) skipped"
    if ($unreadable -gt 0) { $note += ", $unreadable unreadable line(s)" }
    Log "    Added $added timeline entries ($note)"
}

# Sophos Anti-Virus SAV.txt: "yyyyMMdd HHmmss <message>" per line, usually
# UTF-16LE. Times are the examined machine's local time (as plaso assumes;
# Sophos does not document the time zone). Messages are English text, so
# known detection/remediation sentences are matched, then alert keywords.
function Read-SophosSavLog {
    param([System.IO.FileInfo]$File, [string[]]$Lines, [System.TimeZoneInfo]$TimeZone)
    $alertPattern = '(?i)virus/spyware|adware|\bPUA\b|suspicious (?:file|behaviou?r)|malicious|quarantined|infected file|(?:was|been) blocked|could not be (?:cleaned|deleted|removed|quarantined)|clean(?:ing|up) (?:failed|impossible)|could not (?:be )?scan|\bHIPS\b'
    $added = 0
    $routine = 0
    foreach ($line in $Lines) {
        if ($line -notmatch '^\s*(\d{8}\s\d{6})\s+(.+?)\s*$') { continue }
        $logTime = $Matches[1] -replace '\s', ' '
        $message = $Matches[2]
        $local = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($logTime, "yyyyMMdd HHmmss", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$local)) { continue }

        if ($message -match '^File "(.+)" belongs to (.+?) ''(.+)''\.?$') {
            $desc = "Sophos threat detected: $($Matches[3]) in $($Matches[1])"
            $info = [ordered]@{ Threat = $Matches[3]; ThreatType = $Matches[2]; File = $Matches[1] }
        }
        elseif ($message -match '^(.+?) ''(.+?)'' detected in ''(.+)''(?:\.\s*(.*))?$') {
            $desc = "Sophos threat detected: $($Matches[2]) in $($Matches[3])"
            if ($Matches[4]) { $desc += " ($($Matches[4].Trim().TrimEnd('.')))" }
            $info = [ordered]@{ Threat = $Matches[2]; ThreatType = $Matches[1]; File = $Matches[3]; Result = $Matches[4] }
        }
        elseif ($message -match '^Infected file "(.+)" moved (?:in|to) "(.+)"\.?$') {
            $desc = "Sophos moved infected file to quarantine: $($Matches[1])"
            $info = [ordered]@{ File = $Matches[1]; MovedTo = $Matches[2] }
        }
        elseif ($message -match '^The file "(.+)" (?:was|has been) (cleaned|deleted|removed|quarantined)\.?$') {
            $desc = "Sophos $($Matches[2]) file: $($Matches[1])"
            $info = [ordered]@{ File = $Matches[1]; Action = $Matches[2] }
        }
        elseif ($message -match '^The (.+?) ''(.+)'' (?:was|has been) (cleaned|deleted|removed|quarantined)\.?$') {
            $desc = "Sophos $($Matches[3]) threat: $($Matches[2])"
            $info = [ordered]@{ Threat = $Matches[2]; ThreatType = $Matches[1]; Action = $Matches[3] }
        }
        elseif ($message -match '"(.+)" returned a SAV error (.+?)\.?$') {
            # The file could not be scanned (e.g. "File is crypted")
            $desc = "Sophos could not scan file: $($Matches[1])"
            $info = [ordered]@{ File = $Matches[1]; Error = $Matches[2] }
        }
        elseif ($message -match 'sent for Sophos Live Protection: File: ''(.+)'' Checksum: ''(.+)''') {
            $desc = "Sophos sent file sample to Live Protection: $($Matches[1])"
            $info = [ordered]@{ File = $Matches[1]; Checksum = $Matches[2] }
        }
        elseif ($message -match $alertPattern) {
            $desc = "Sophos: $message"
            $info = [ordered]@{}
        }
        else {
            $routine++
            continue
        }
        $info["LogTime"] = $local.ToString("yyyy-MM-dd HH:mm:ss") + " (target local time)"
        # Keyword match only: keep the whole message
        if ($info.Count -eq 1) { $info["Message"] = $message }

        Add-TimelineEntry -Timestamp (Convert-LocalToUtc -Local $local -TimeZone $TimeZone) -Source "AV-Sophos" -EventType "SecurityAlert" `
            -Description $desc `
            -Details (Format-ArtifactDetails $info) `
            -Artifact "AntiVirus" -RawPath $File.FullName
        $added++
    }
    Log "    Added $added timeline entries ($routine routine record(s) skipped)"
}

# McAfee writes date and time in the examined machine's regional format
# (en-US "9/27/2013" and "2:42:26 PM"). Day-first is decided per file by the
# caller. Returns Kind=Unspecified or $null.
function ConvertFrom-McAfeeLogTime {
    param([string]$Date, [string]$Time, [bool]$DayFirst)
    if ($Date -notmatch '^\s*(\d{1,4})[./-](\d{1,2})[./-](\d{1,4})\s*$') { return $null }
    $part1 = $Matches[1]
    $part2 = [int]$Matches[2]
    $part3 = [int]$Matches[3]
    if ($part1.Length -eq 4) { $year = [int]$part1; $month = $part2; $day = $part3 }
    elseif ($DayFirst) { $year = $part3; $month = $part2; $day = [int]$part1 }
    else { $year = $part3; $month = [int]$part1; $day = $part2 }
    if ($year -lt 100) { $year += 2000 }

    if ($Time -notmatch '^\s*(\d{1,2}):(\d{2}):(\d{2})\s*([AaPp])?\.?(?:[Mm]\.?)?\s*$') { return $null }
    $hour = [int]$Matches[1]
    $minute = [int]$Matches[2]
    $second = [int]$Matches[3]
    if ($Matches[4]) {
        if ($hour -eq 12) { $hour = 0 }
        if ("Pp".Contains($Matches[4])) { $hour += 12 }
    }
    try { return New-Object DateTime $year, $month, $day, $hour, $minute, $second }
    catch {
        Write-Verbose "Invalid McAfee log time '$Date $Time': $($_.Exception.Message)"
        return $null
    }
}

# McAfee VirusScan Enterprise AccessProtectionLog.txt, tab-separated, local
# time of the examined machine (as plaso reads it):
#   date, time, status, user, process, target, rule, action
# Port blocking lines have no user/action: date, time, status, process, rule,
# destination. "Would be blocked ... (rule is currently not enforced)" lines
# are report-only rule hits and are kept, marked as not enforced.
function Read-McAfeeAccessProtectionLog {
    param([System.IO.FileInfo]$File, [string[]]$Lines, [System.TimeZoneInfo]$TimeZone)
    $rows = @(foreach ($line in $Lines) {
        $cols = $line.Split([char]"`t")
        if ($cols.Count -ge 6 -and $cols[0] -match '^\s*\d{1,4}[./-]\d{1,2}[./-]\d{1,4}\s*$') { ,$cols }
    })
    # Day-first dates: "." separators (27.09.2013) or a first number over 12
    $dayFirst = $false
    foreach ($cols in $rows) {
        if ($cols[0] -match '^\s*(\d{1,2})([./-])\d{1,2}[./-]\d{2,4}\s*$' -and ($Matches[2] -eq '.' -or [int]$Matches[1] -gt 12)) {
            $dayFirst = $true
            break
        }
    }

    $added = 0
    $unreadable = 0
    foreach ($cols in $rows) {
        $local = ConvertFrom-McAfeeLogTime -Date $cols[0] -Time $cols[1] -DayFirst $dayFirst
        if ($null -eq $local) { $unreadable++; continue }
        $status = $cols[2].Trim()
        if ($cols.Count -ge 8) {
            $user = $cols[3].Trim()
            $process = $cols[4].Trim()
            $target = $cols[5].Trim()
            $rule = $cols[6].Trim()
            $action = ($cols[7] -replace '^\s*Action blocked\s*:\s*', '').Trim()
        }
        else {
            $user = ""
            if ($cols.Count -ge 7) { $user = $cols[3].Trim() }
            $process = $cols[$cols.Count - 3].Trim()
            $rule = $cols[$cols.Count - 2].Trim()
            $target = $cols[$cols.Count - 1].Trim()
            $action = ""
        }

        $kind = "Access Protection"
        if ($status -match 'port blocking') { $kind = "port blocking" }
        if ($status -match '^Would be blocked') { $what = "$kind would have blocked (rule not enforced)" }
        elseif ($status -match '^Blocked') { $what = "$kind blocked" }
        else { $what = "$kind ($status)" }
        $desc = "McAfee ${what}: $process -> $target"
        if ($action) { $desc += " ($action)" }

        Add-TimelineEntry -Timestamp (Convert-LocalToUtc -Local $local -TimeZone $TimeZone) -Source "AV-McAfee" -EventType "SecurityAlert" `
            -Description $desc `
            -User $user `
            -Details (Format-ArtifactDetails ([ordered]@{
                Rule    = $rule
                Action  = $action
                Process = $process
                Target  = $target
                Status  = $status
                LogTime = $local.ToString("yyyy-MM-dd HH:mm:ss") + " (target local time)"
            })) `
            -Artifact "AntiVirus" -RawPath $File.FullName
        $added++
    }
    $note = ""
    if ($unreadable -gt 0) { $note = " ($unreadable line(s) with unreadable date/time skipped)" }
    Log "    Added $added timeline entries$note"
}

# Fields of an ESET log record payload as a hashtable (field id -> value).
# Each field is uint16 id, uint16 type, then a value by type:
#   0x4E 'N' uint32 byte count + UTF-16LE text    0x45 'E' 4-byte number
#   0x42 'B' uint32 byte count + bytes (as hex)   0x46 'F' 8-byte number
#   0x41 'A' assumed like 'B' (only seen empty)   0x43 'C' 1-byte number
# An unknown type ends the record: its size, and so the rest, is unknown.
function Read-EsetRecordFields {
    param([byte[]]$Bytes, [int]$Start, [int]$End)
    $fields = @{}
    $p = $Start
    while ($p + 4 -le $End) {
        $id = [int][BitConverter]::ToUInt16($Bytes, $p)
        $type = [int][BitConverter]::ToUInt16($Bytes, $p + 2)
        $p += 4
        if ($type -eq 0x45 -and $p + 4 -le $End) { $value = [BitConverter]::ToUInt32($Bytes, $p); $p += 4 }
        elseif ($type -eq 0x46 -and $p + 8 -le $End) { $value = [BitConverter]::ToInt64($Bytes, $p); $p += 8 }
        elseif ($type -eq 0x43 -and $p + 1 -le $End) { $value = $Bytes[$p]; $p += 1 }
        elseif (@(0x4E, 0x42, 0x41) -contains $type -and $p + 4 -le $End) {
            $length = [BitConverter]::ToInt32($Bytes, $p)
            $p += 4
            if ($length -lt 0 -or $p + $length -gt $End) { break }
            if ($type -eq 0x4E) { $value = [System.Text.Encoding]::Unicode.GetString($Bytes, $p, $length).TrimEnd([char]0) }
            elseif ($length -gt 0) { $value = [BitConverter]::ToString($Bytes, $p, $length).Replace("-", "") }
            else { $value = "" }
            $p += $length
        }
        else { break }
        $fields[$id] = $value
    }
    return $fields
}

# ESET virlog.dat ("Detected threats" log). BEST EFFORT: ESET does not
# document this binary format. The layout below was worked out from one
# public sample (ESET NOD32 / Smart Security, 2017) and other versions may
# differ; records that do not fit are skipped. Little-endian throughout.
#   file:    56-byte header (signature, sizes, record count, FILETIMEs)
#   record:  signature DC CF 8B 63 | uint32 record size | uint32 size of the
#            rest of the header (36) | 4 bytes ? | uint32 record number |
#            FILETIME detection time | 16 bytes ? | uint32 payload size,
#            then the payload (see Read-EsetRecordFields)
#   fields:  0x0BBE detected object, 0x1D4D threat name, 0x03EE user,
#            0x0BC4 process, 0x139E SHA1 of the object (matches the EICAR
#            file in the sample), 0x139D a second 20-byte hash (meaning
#            unknown), 0x139F first-seen time (Unix seconds), 0x2717
#            detection engine version. Action and scanner are not decoded.
# FILETIMEs are UTC (the Windows convention; in the sample the detection
# times also fall a few minutes after the Unix-epoch first-seen time).
function Read-EsetVirlog {
    param([System.IO.FileInfo]$File)
    $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
    # One char per byte, to find record signatures with String.IndexOf
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $view = $latin1.GetString($bytes)
    $signature = $latin1.GetString([byte[]](0xDC, 0xCF, 0x8B, 0x63))
    $unixEpoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)

    $added = 0
    $unreadable = 0
    $pos = $view.IndexOf($signature, [System.StringComparison]::Ordinal)
    while ($pos -ge 0 -and $pos + 48 -le $bytes.Length) {
        $recordSize = [BitConverter]::ToInt32($bytes, $pos + 4)
        $headerRest = [BitConverter]::ToInt32($bytes, $pos + 8)
        $payloadStart = $pos + 12 + $headerRest
        if ($recordSize -lt 48 -or $headerRest -lt 16 -or $pos + $recordSize -gt $bytes.Length -or $payloadStart -gt $pos + $recordSize) {
            # Signature bytes inside other data -- keep looking
            $pos = $view.IndexOf($signature, $pos + 1, [System.StringComparison]::Ordinal)
            continue
        }
        $recordNumber = [BitConverter]::ToUInt32($bytes, $pos + 16)
        $fileTime = [BitConverter]::ToInt64($bytes, $pos + 20)
        $fields = Read-EsetRecordFields -Bytes $bytes -Start $payloadStart -End ($pos + $recordSize)
        $threat = "$($fields[0x1D4D])"
        $object = "$($fields[0x0BBE])"

        $detected = $null
        if ($fileTime -gt 0 -and $fileTime -lt 2650467743999999999) { $detected = [DateTime]::FromFileTimeUtc($fileTime) }
        if ($null -eq $detected -or (-not $threat -and -not $object)) {
            $unreadable++
        }
        else {
            $firstSeen = ""
            $unixTime = $fields[0x139F]
            if ($unixTime -is [long] -and $unixTime -gt 0 -and $unixTime -lt 4102444800) {
                $firstSeen = $unixEpoch.AddSeconds($unixTime).ToString("yyyy-MM-dd HH:mm:ss")
            }
            $desc = "ESET threat detected: $threat"
            if (-not $threat) { $desc = "ESET threat detected" }
            if ($object) { $desc += " in $object" }
            Add-TimelineEntry -Timestamp $detected -Source "AV-ESET" -EventType "SecurityAlert" `
                -Description $desc `
                -User "$($fields[0x03EE])" `
                -Details (Format-ArtifactDetails ([ordered]@{
                    Threat       = $threat
                    Object       = $object
                    Process      = $fields[0x0BC4]
                    SHA1         = $fields[0x139E]
                    OtherHash    = $fields[0x139D]
                    FirstSeenUtc = $firstSeen
                    Engine       = $fields[0x2717]
                    Record       = $recordNumber
                })) `
                -Artifact "AntiVirus" -RawPath $File.FullName
            $added++
        }
        $pos = $view.IndexOf($signature, $pos + $recordSize, [System.StringComparison]::Ordinal)
    }

    if ($added -eq 0 -and $bytes.Length -gt 256) {
        Log-Warning "    No readable detection records in $($File.Name) ($($bytes.Length) bytes) -- this ESET version's log format may differ"
    }
    else {
        $note = ""
        if ($unreadable -gt 0) { $note = " ($unreadable record(s) without time or threat skipped)" }
        Log "    Added $added timeline entries$note (best-effort parse of ESET's binary log)"
    }
}

# --- Microsoft Defender DetectionHistory and quarantine entries ---
# The collector copies them to AntiVirus\Defender\DetectionHistory\ and
# AntiVirus\Defender\Quarantine\Entries\; any folder of these names is read
# (e.g. a copied ProgramData tree). Defender's event log, Get-MpThreatDetection
# and support log rows (Parse-EventLogs) can describe the same detection:
# these rows have their own Source (Defender-DetectionHistory,
# Defender-Quarantine), and their DetectionID, ThreatID, threat name and path
# link them to those rows (quarantine entries have no DetectionID).

# Values of a DetectionHistory file (format: see Read-DefenderDetectionHistory)
# as objects with Type, Offset and Size of the data, and the decoded Value:
# a number (types 0x00, 0x05, 0x06: uint32; 0x08: uint64), a FILETIME as
# Int64 (0x0A), text (0x15), "{GUID}" text (0x1E), or $null for other types
# (binary data is read through Offset and Size). Every value states its
# size, so values of unknown types are skipped; reading stops at the first
# value that runs past the end of the file.
function Get-DefenderHistoryValues {
    param([byte[]]$Bytes)
    $values = New-Object System.Collections.Generic.List[object]
    $p = 0
    while ($p + 8 -le $Bytes.Length) {
        $size = [long][BitConverter]::ToUInt32($Bytes, $p)
        $type = [long][BitConverter]::ToUInt32($Bytes, $p + 4)
        $data = $p + 8
        if ($size -gt $Bytes.Length - $data) { break }
        $value = $null
        if (($type -eq 0x00 -or $type -eq 0x05 -or $type -eq 0x06) -and $size -eq 4) { $value = [long][BitConverter]::ToUInt32($Bytes, $data) }
        elseif ($type -eq 0x08 -and $size -eq 8) { $value = [BitConverter]::ToUInt64($Bytes, $data) }
        elseif ($type -eq 0x0A -and $size -eq 8) { $value = [BitConverter]::ToInt64($Bytes, $data) }
        elseif ($type -eq 0x15) { $value = [System.Text.Encoding]::Unicode.GetString($Bytes, $data, [int]($size - ($size % 2))).Split([char]0)[0] }
        elseif ($type -eq 0x1E -and $size -eq 16) {
            $guidBytes = New-Object byte[] 16
            [Array]::Copy($Bytes, $data, $guidBytes, 0, 16)
            $value = "{" + (New-Object System.Guid (, $guidBytes)).ToString().ToUpperInvariant() + "}"
        }
        $values.Add([PSCustomObject]@{ Type = $type; Offset = $data; Size = [int]$size; Value = $value })
        $p = $data + [int]$size
        if ($p % 8 -ne 0) { $p += 8 - ($p % 8) }
    }
    return , $values.ToArray()
}

# Value of a DetectionHistory value set at an index if it has one of the
# given types, else $null
function Get-DefenderHistorySetValue {
    param([object[]]$Set, [int]$Index, [int[]]$Types)
    if ($Index -lt $Set.Count -and $Types -contains $Set[$Index].Type) { return $Set[$Index].Value }
    return $null
}

# FILETIME of a Defender file -> UTC [datetime], or $null when zero, out of
# range or before 1980: Add-TimelineEntry drops such times, so a damaged
# value must not win over a fallback time
function ConvertFrom-DefenderFileTime {
    param([long]$FileTime)
    $utc = ConvertFrom-JumpListFileTime $FileTime
    if ($null -ne $utc -and $utc.Year -lt 1980) { return $null }
    return $utc
}

# Threat tracking data of a DetectionHistory resource (bytes Start to
# Start + Size) as a hashtable of key -> number or text. Layout: either a
# header (uint32 1, uint32 header size, uint32 values size, uint32 total
# size, uint32 ?) and a uint32 values size, or only a uint32 values size;
# then the values: uint32 key size, UTF-16LE key, uint32 type, and by type
# 3 uint32, 4 uint64, 5 uint8, 6 uint32 size + UTF-16LE text, 7 five bytes.
# An unknown type ends the list (the size of its data is unknown).
function Read-DefenderThreatTracking {
    param([byte[]]$Bytes, [int]$Start, [int]$Size)
    $result = @{}
    if ($Size -lt 4 -or $Start + $Size -gt $Bytes.Length) { return $result }
    $end = $Start + $Size
    $first = [long][BitConverter]::ToUInt32($Bytes, $Start)
    if ($first -eq 1) {
        if ($Size -lt 20) { return $result }
        $headerSize = [long][BitConverter]::ToUInt32($Bytes, $Start + 4)
        $totalSize = [long][BitConverter]::ToUInt32($Bytes, $Start + 12)
        if ($headerSize -lt 20 -or $headerSize -ge $Size) { return $result }
        $p = $Start + [int]$headerSize + 4
        if ($totalSize -lt $Size) { $end = $Start + [int]$totalSize }
    }
    else {
        $p = $Start + 4
        if ($first -lt $Size) { $end = $Start + [int]$first }
    }
    while ($p + 4 -le $end) {
        $keySize = [long][BitConverter]::ToUInt32($Bytes, $p)
        if ($keySize -lt 2 -or $keySize -gt 1024 -or $p + 8 + $keySize -gt $end) { break }
        $key = [System.Text.Encoding]::Unicode.GetString($Bytes, $p + 4, [int]($keySize - ($keySize % 2))).Split([char]0)[0]
        $p += 4 + [int]$keySize
        $valueType = [BitConverter]::ToUInt32($Bytes, $p)
        $p += 4
        $value = $null
        if ($valueType -eq 3 -and $p + 4 -le $end) { $value = [long][BitConverter]::ToUInt32($Bytes, $p); $p += 4 }
        elseif ($valueType -eq 4 -and $p + 8 -le $end) { $value = [BitConverter]::ToInt64($Bytes, $p); $p += 8 }
        elseif ($valueType -eq 5 -and $p + 1 -le $end) { $value = [long]$Bytes[$p]; $p += 1 }
        elseif ($valueType -eq 6 -and $p + 4 -le $end) {
            $textSize = [long][BitConverter]::ToUInt32($Bytes, $p)
            if ($p + 4 + $textSize -gt $end) { break }
            $value = [System.Text.Encoding]::Unicode.GetString($Bytes, $p + 4, [int]($textSize - ($textSize % 2))).Split([char]0)[0]
            $p += 4 + [int]$textSize
        }
        elseif ($valueType -eq 7 -and $p + 5 -le $end) { $value = [BitConverter]::ToString($Bytes, $p, 5).Replace("-", ""); $p += 5 }
        else { break }
        if ($key) { $result[$key] = $value }
    }
    return $result
}

# Defender DetectionHistory file (Scans\History\Service\DetectionHistory\
# <nn>\<DetectionID>), one per detection (Windows 10 and later). Format from
# the public write-ups (libyal dtformats "Windows Defender scan
# DetectionHistory file format", plaso's windefender_history parser, ERNW
# quarantine-formats) and checked on plaso's sample files: a list of values,
# each uint32 data size, uint32 data type, the data, then padding to an
# 8-byte boundary (see Get-DefenderHistoryValues). A text value
# "Magic.Version:1.2" (index 0 of its set) starts each value set after the
# first. Indexes used:
#   set 1      0 threat ID, 1 detection ID (a GUID, also the file name)
#   set 2      1 threat name, 3 severity ID, 4 category ID, 7 threat status
#              ID (3 and 7 are only guessed at in the write-ups; in the
#              samples their values match Get-MpThreat SeverityID and
#              Get-MpThreatDetection ThreatStatusID)
#   set 3...   one set per resource: 1 type ("file", "webfile",
#              "containerfile", "regkey", "process", ...), 2 location,
#              5 threat tracking data (see Read-DefenderThreatTracking)
#   last set   the detection's own values follow its resource: 6 last threat
#              status change time, 12 domain\user, 14 process, 18 initial
#              detection time, 20 remediation time (FILETIMEs, UTC; 0 =
#              not set; the time names are the write-ups' guesses, which
#              the samples bear out)
# Values are only used when they have the expected type. One row per file,
# at the initial detection time, else ThreatTrackingStartTime, else the
# status change time, else the file's original creation time (manifest);
# times before 1980 count as missing.
# The path (Description "on <path>", Details Path) is the location of the
# first file resource, else containerfile, else webfile (its location is
# "<path>|<url>|..."), else the threat tracking value CONTEXT_DATA_FILENAME
# (plaso uses it for detections without a file resource), else the location
# of a registry, run key, startup, service or scheduled task resource.
# Process, behavior, command line and other resources have no path: their
# locations (e.g. "pid:...") are only listed in Resources.
# Defender deletes these files after ScanPurgeItemsAfterDelay days (default
# 15): a missing file does not prove there was no detection.
# Returns the number of rows passed to Add-TimelineEntry (0: no time found),
# or -1 if the file is not a DetectionHistory file.
function Read-DefenderDetectionHistory {
    param([System.IO.FileInfo]$File)
    $numberTypes = @(0x00, 0x05, 0x06, 0x08)
    $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
    $values = Get-DefenderHistoryValues -Bytes $bytes

    # Value sets, split at the "Magic.Version:" values
    $sets = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[object]
    foreach ($v in $values) {
        if ($v.Type -eq 0x15 -and "$($v.Value)".StartsWith("Magic.Version:", [System.StringComparison]::Ordinal)) {
            $sets.Add($current.ToArray())
            $current = New-Object System.Collections.Generic.List[object]
        }
        $current.Add($v)
    }
    $sets.Add($current.ToArray())
    if ($sets.Count -lt 2) { return -1 }
    $detectionId = Get-DefenderHistorySetValue -Set $sets[0] -Index 1 -Types 0x1E
    $threat = Get-DefenderHistorySetValue -Set $sets[1] -Index 1 -Types 0x15
    if (-not $detectionId -or -not $threat) { return -1 }
    $threatId = Get-DefenderHistorySetValue -Set $sets[0] -Index 0 -Types $numberTypes
    $severityId = Get-DefenderHistorySetValue -Set $sets[1] -Index 3 -Types $numberTypes
    $categoryId = Get-DefenderHistorySetValue -Set $sets[1] -Index 4 -Types $numberTypes
    $statusId = Get-DefenderHistorySetValue -Set $sets[1] -Index 7 -Types $numberTypes

    # Resources (the path: see above)
    $resources = @()
    for ($i = 2; $i -lt $sets.Count; $i++) {
        $resourceType = Get-DefenderHistorySetValue -Set $sets[$i] -Index 1 -Types 0x15
        $location = Get-DefenderHistorySetValue -Set $sets[$i] -Index 2 -Types 0x15
        if (-not $resourceType -and -not $location) { continue }
        $tracking = @{}
        if ($sets[$i].Count -gt 5 -and $sets[$i][5].Type -eq 0x28) {
            $tracking = Read-DefenderThreatTracking -Bytes $bytes -Start $sets[$i][5].Offset -Size $sets[$i][5].Size
        }
        $resources += [PSCustomObject]@{ Type = "$resourceType"; Location = "$location"; Tracking = $tracking }
    }
    $path = ""
    foreach ($pathType in @("file", "containerfile", "webfile")) {
        $match = @($resources | Where-Object { $_.Type -eq $pathType -and $_.Location } | Select-Object -First 1)
        if ($match.Count -gt 0) { $path = ($match[0].Location -split '\|')[0]; break }
    }
    if (-not $path) {
        foreach ($resource in $resources) {
            $contextFile = $resource.Tracking["CONTEXT_DATA_FILENAME"]
            if ($contextFile -is [string] -and $contextFile) { $path = $contextFile; break }
        }
    }
    if (-not $path) {
        $match = @($resources | Where-Object { $_.Location -and @("regkey", "regkeyvalue", "runkey", "startup", "service", "taskscheduler") -contains $_.Type } | Select-Object -First 1)
        if ($match.Count -gt 0) { $path = $match[0].Location }
    }
    # SHA-256 and tracking start time: from the first file resource, else the first that has them
    $ordered = @(@($resources | Where-Object { $_.Type -eq "file" }) + @($resources))
    $sha256 = ""
    $trackingStart = $null
    foreach ($resource in $ordered) {
        if (-not $sha256 -and $resource.Tracking["ThreatTrackingSha256"]) { $sha256 = "$($resource.Tracking['ThreatTrackingSha256'])" }
        if ($null -eq $trackingStart -and $resource.Tracking["ThreatTrackingStartTime"] -is [long]) {
            $trackingStart = ConvertFrom-DefenderFileTime $resource.Tracking["ThreatTrackingStartTime"]
        }
    }

    # The detection's own values, after the last resource
    $user = ""; $process = ""; $initial = $null; $statusChange = $null; $remediation = $null
    if ($sets.Count -gt 2) {
        $last = $sets[$sets.Count - 1]
        $user = "$(Get-DefenderHistorySetValue -Set $last -Index 12 -Types 0x15)"
        $process = "$(Get-DefenderHistorySetValue -Set $last -Index 14 -Types 0x15)"
        $initial = ConvertFrom-DefenderFileTime ([long](Get-DefenderHistorySetValue -Set $last -Index 18 -Types 0x0A))
        $statusChange = ConvertFrom-DefenderFileTime ([long](Get-DefenderHistorySetValue -Set $last -Index 6 -Types 0x0A))
        $remediation = ConvertFrom-DefenderFileTime ([long](Get-DefenderHistorySetValue -Set $last -Index 20 -Types 0x0A))
    }

    $timeNote = ""
    $time = $initial
    if ($null -eq $time -and $null -ne $trackingStart) { $time = $trackingStart; $timeNote = "ThreatTrackingStartTime (no valid initial detection time in the file)" }
    if ($null -eq $time -and $null -ne $statusChange) { $time = $statusChange; $timeNote = "last threat status change (no valid detection time in the file)" }
    if ($null -eq $time) {
        $fileTimes = Get-SourceFileTimes $File.FullName
        if ($fileTimes -and $fileTimes.Created -and $fileTimes.Created.Year -ge 1980) { $time = $fileTimes.Created; $timeNote = "DetectionHistory file created (no valid time in the file)" }
    }
    if ($null -eq $time) { return 0 }

    $resourceTexts = @($resources | ForEach-Object { "$($_.Type):_$($_.Location)" })
    if ($resourceTexts.Count -gt 10) { $resourceTexts = @($resourceTexts[0..9]) + "(+$($resourceTexts.Count - 10) more)" }
    $severity = "$severityId"
    if ($null -ne $severityId -and $script:DefenderSeverityNames.ContainsKey("$severityId")) { $severity = "$($script:DefenderSeverityNames["$severityId"]) ($severityId)" }
    $status = "$statusId"
    if ($null -ne $statusId -and $script:DefenderThreatStatusNames.ContainsKey("$statusId")) { $status = $script:DefenderThreatStatusNames["$statusId"] }
    $desc = "Defender detection (DetectionHistory): $threat"
    if ($path) { $desc += " on $path" }
    Add-TimelineEntry -Timestamp $time -Source "Defender-DetectionHistory" -EventType "SecurityAlert" `
        -Description $desc `
        -User $user `
        -Details (Format-ArtifactDetails ([ordered]@{
            ThreatName      = $threat
            ThreatID        = $threatId
            Severity        = $severity
            CategoryID      = $categoryId
            Status          = $status
            Path            = $path
            Resources       = ($resourceTexts -join "; ")
            User            = $user
            Process         = $process
            SHA256          = $sha256
            StatusChangeUtc = Format-UtcDetailTime $statusChange
            RemediationUtc  = Format-UtcDetailTime $remediation
            TimeNote        = $timeNote
            DetectionID     = $detectionId
        })) `
        -Artifact "AntiVirus" -RawPath $File.FullName
    return 1
}

# RC4 of Count bytes of Data from Offset with Defender's static quarantine
# key (state after the key schedule cached in $script:DefenderRc4State).
# The key is the 256 bytes from mpengine.dll first published by the Cuckoo
# Sandbox project; ERNW's quarantine-formats and N. Knezevic's defender-dump
# give the same bytes.
function ConvertFrom-DefenderRc4 {
    param([byte[]]$Data, [int]$Offset, [int]$Count)
    if ($null -eq $script:DefenderRc4State) {
        $keyHex = "1E87781B8DBAA844CE69702C0C78B786A3F623B738F5EDF9AF83530FB3FC54FAA21EB9CF1331FD0F0DA954F687CB9E18279697900E53FB317C9CBCE48E23D053" +
            "71ECC15951B8F3649D7CA33ED68DC9047E82C9BAAD9799D0D458CB847CA9FFBE3C8A775233557DDE13A8B14087CC1BC8F10F6ECDD083A959CFF84A9D1D50755E" +
            "3E191818AF23E2293558766D2C07E25712B2CA0B535ED8F6C56CE73D24BDD0291771861A54B4C285A9A3DB7ACA6D224AEACD621DB9F2A22ED1E9E11D75BED7DC" +
            "0ECB0A8E68A2FF1263408DC808DFFD164B116774CD0B9B8D05411ED6262E429BA495676B8398DB2F35D3C1B9CED52636F2765E1A95CB7CA4C3DDABDDBFF38253"
        $state = New-Object int[] 256
        for ($n = 0; $n -lt 256; $n++) { $state[$n] = $n }
        $j = 0
        for ($n = 0; $n -lt 256; $n++) {
            $j = ($j + $state[$n] + [Convert]::ToInt32($keyHex.Substring($n * 2, 2), 16)) -band 0xFF
            $swap = $state[$n]; $state[$n] = $state[$j]; $state[$j] = $swap
        }
        $script:DefenderRc4State = $state
    }
    $s = [int[]]$script:DefenderRc4State.Clone()
    $out = New-Object byte[] $Count
    $i = 0
    $j = 0
    for ($n = 0; $n -lt $Count; $n++) {
        $i = ($i + 1) -band 0xFF
        $j = ($j + $s[$i]) -band 0xFF
        $swap = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $swap
        $out[$n] = $Data[$Offset + $n] -bxor $s[($s[$i] + $s[$j]) -band 0xFF]
    }
    return , $out
}

# Path without its \\?\ or \\?\UNC\ prefix
function ConvertFrom-DefenderLongPath {
    param([string]$Path)
    if ($Path.StartsWith("\\?\UNC\", [System.StringComparison]::OrdinalIgnoreCase)) { return "\\" + $Path.Substring(8) }
    if ($Path.StartsWith("\\?\", [System.StringComparison]::Ordinal)) { return $Path.Substring(4) }
    return $Path
}

# Fields of a quarantine entry resource: Count fields from Start in part 2
# (Data), each at a 4-byte boundary of part 2: uint16 data size, uint16
# identifier (low 12 bits) and data type (high 4 bits), the data. The layout
# is in ERNW's quarantine-formats and Fox-IT's write-up; the identifiers are
# Fox-IT's (dissect.target). Returns a hashtable of the fields read here:
# ResourceID (0x02: the ID of the quarantined copy, as hex; the copy itself
# is not read), PhysicalPath (0x0C, UTF-16LE), Created and Modified (0x0F,
# 0x11: the original file's creation and last write FILETIMEs, UTC) and
# FileSize (0x12). Other fields are skipped; reading stops at a field that
# runs past the end of part 2.
function Read-DefenderQuarantineFields {
    param([byte[]]$Data, [int]$Start, [int]$Count)
    $result = @{}
    $p = $Start
    for ($n = 0; $n -lt $Count -and $n -lt 64; $n++) {
        if ($p % 4 -ne 0) { $p += 4 - ($p % 4) }
        if ($p + 4 -gt $Data.Length) { break }
        $size = [int][BitConverter]::ToUInt16($Data, $p)
        $id = [int][BitConverter]::ToUInt16($Data, $p + 2) -band 0x0FFF
        $d = $p + 4
        if ($d + $size -gt $Data.Length) { break }
        if ($id -eq 0x02 -and $size -gt 0 -and $size -le 64) { $result["ResourceID"] = [BitConverter]::ToString($Data, $d, $size).Replace("-", "") }
        elseif ($id -eq 0x0C -and $size -ge 2) { $result["PhysicalPath"] = [System.Text.Encoding]::Unicode.GetString($Data, $d, $size - ($size % 2)).Split([char]0)[0] }
        elseif ($id -eq 0x0F -and $size -eq 8) { $result["Created"] = ConvertFrom-DefenderFileTime ([BitConverter]::ToInt64($Data, $d)) }
        elseif ($id -eq 0x11 -and $size -eq 8) { $result["Modified"] = ConvertFrom-DefenderFileTime ([BitConverter]::ToInt64($Data, $d)) }
        elseif ($id -eq 0x12 -and $size -eq 4) { $result["FileSize"] = [long][BitConverter]::ToUInt32($Data, $d) }
        elseif ($id -eq 0x12 -and $size -eq 8) { $result["FileSize"] = [BitConverter]::ToUInt64($Data, $d) }
        $p = $d + $size
    }
    return $result
}

# Defender quarantine entry (Quarantine\Entries\{GUID}): the metadata of one
# quarantined threat. Format from the public write-ups (Fox-IT / NCC Group
# "Reverse, Reveal, Recover: Windows Defender Quarantine Forensics", ERNW
# quarantine-formats, defender-dump), which agree on it: three parts, each
# RC4-encrypted on its own with the static key (see ConvertFrom-DefenderRc4):
#   header  0x3C bytes: magic DB E8 C5 01, ..., uint32 size of part 1 at
#           0x28, uint32 size of part 2 at 0x2C
#   part 1  entry GUID, scan GUID, FILETIME (UTC) of the quarantine at 0x20,
#           uint64 threat ID at 0x28, ..., threat name at 0x34
#           (NUL-terminated UTF-8)
#   part 2  uint32 resource count, then a uint32 offset (from the start of
#           part 2) per resource. A resource: original path (NUL-terminated
#           UTF-16LE, may start with \\?\), uint16 field count, type
#           (NUL-terminated ASCII: "file", "regkey", ...), then the fields
#           (see Read-DefenderQuarantineFields)
# One row per resource, at the quarantine time (a time before 1980 counts as
# missing: the entry file's original creation time from the manifest is used
# instead). Only these metadata files are read: the quarantined files
# themselves (Quarantine\ResourceData) are never read or decrypted.
# Returns the number of rows passed to Add-TimelineEntry (0: no time found),
# or -1 if the file is not a quarantine entry.
function Read-DefenderQuarantineEntry {
    param([System.IO.FileInfo]$File)
    $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
    if ($bytes.Length -lt 0x3C) { return -1 }
    $header = ConvertFrom-DefenderRc4 -Data $bytes -Offset 0 -Count 0x3C
    if ($header[0] -ne 0xDB -or $header[1] -ne 0xE8 -or $header[2] -ne 0xC5 -or $header[3] -ne 0x01) { return -1 }
    $size1 = [long][BitConverter]::ToUInt32($header, 0x28)
    $size2 = [long][BitConverter]::ToUInt32($header, 0x2C)
    if ($size1 -lt 0x35 -or 0x3C + $size1 + $size2 -gt $bytes.Length) { return -1 }
    $part1 = ConvertFrom-DefenderRc4 -Data $bytes -Offset 0x3C -Count ([int]$size1)
    $part2 = ConvertFrom-DefenderRc4 -Data $bytes -Offset (0x3C + [int]$size1) -Count ([int]$size2)

    $nameEnd = [Array]::IndexOf($part1, [byte]0, 0x34)
    if ($nameEnd -lt 0) { $nameEnd = $part1.Length }
    $threat = [System.Text.Encoding]::UTF8.GetString($part1, 0x34, $nameEnd - 0x34)
    if (-not $threat) { $threat = "unknown threat" }
    $threatId = [BitConverter]::ToUInt64($part1, 0x28)
    $time = ConvertFrom-DefenderFileTime ([BitConverter]::ToInt64($part1, 0x20))
    $timeNote = ""
    if ($null -eq $time) {
        $fileTimes = Get-SourceFileTimes $File.FullName
        if ($fileTimes -and $fileTimes.Created -and $fileTimes.Created.Year -ge 1980) { $time = $fileTimes.Created; $timeNote = "quarantine entry file created (no valid time in the entry)" }
    }
    if ($null -eq $time) { return 0 }

    # Resources (at most 100 per entry)
    $resources = @()
    if ($size2 -ge 4) {
        $count = [long][BitConverter]::ToUInt32($part2, 0)
        $maxCount = [long](($size2 - 4 - (($size2 - 4) % 4)) / 4)
        if ($count -gt $maxCount) { $count = $maxCount }
        if ($count -gt 100) { $count = 100 }
        for ($r = 0; $r -lt $count; $r++) {
            $start = [long][BitConverter]::ToUInt32($part2, 4 + 4 * $r)
            if ($start -lt 4 + 4 * $count -or $start -ge $size2) { continue }
            # Path: UTF-16LE up to its NUL character
            $q = [int]$start
            while ($q + 1 -lt $size2 -and ($part2[$q] -ne 0 -or $part2[$q + 1] -ne 0)) { $q += 2 }
            if ($q + 1 -ge $size2) { continue }
            $path = ConvertFrom-DefenderLongPath ([System.Text.Encoding]::Unicode.GetString($part2, [int]$start, $q - [int]$start))
            # Type: after the NUL and the uint16 field count; then the fields
            $typeStart = $q + 4
            $resourceType = ""
            $fields = @{}
            if ($typeStart -lt $size2) {
                $fieldCount = [int][BitConverter]::ToUInt16($part2, $q + 2)
                $typeEnd = [Array]::IndexOf($part2, [byte]0, $typeStart)
                if ($typeEnd -lt 0) { $typeEnd = [int]$size2 }
                $resourceType = [System.Text.Encoding]::ASCII.GetString($part2, $typeStart, $typeEnd - $typeStart)
                $fields = Read-DefenderQuarantineFields -Data $part2 -Start ($typeEnd + 1) -Count $fieldCount
            }
            if ($path) { $resources += [PSCustomObject]@{ Path = $path; Type = $resourceType; Fields = $fields } }
        }
    }
    if ($resources.Count -eq 0) { $resources = @([PSCustomObject]@{ Path = ""; Type = ""; Fields = @{} }) }

    foreach ($resource in $resources) {
        $shown = $resource.Path
        if (-not $shown) { $shown = "(no path recorded)" }
        # The physical path only when it differs from the detection path
        $physicalPath = ""
        if ($resource.Fields["PhysicalPath"]) { $physicalPath = ConvertFrom-DefenderLongPath $resource.Fields["PhysicalPath"] }
        if ($physicalPath -and [string]::Equals($physicalPath, $resource.Path, [System.StringComparison]::OrdinalIgnoreCase)) { $physicalPath = "" }
        Add-TimelineEntry -Timestamp $time -Source "Defender-Quarantine" -EventType "SecurityAlert" `
            -Description "Defender quarantined: $shown ($threat)" `
            -Details (Format-ArtifactDetails ([ordered]@{
                ThreatName      = $threat
                ThreatID        = $threatId
                Path            = $resource.Path
                PhysicalPath    = $physicalPath
                ResourceType    = $resource.Type
                ResourceID      = $resource.Fields["ResourceID"]
                FileSize        = $resource.Fields["FileSize"]
                FileCreatedUtc  = Format-UtcDetailTime $resource.Fields["Created"]
                FileModifiedUtc = Format-UtcDetailTime $resource.Fields["Modified"]
                ResourceCount   = $(if ($resources.Count -gt 1) { $resources.Count } else { "" })
                TimeNote        = $timeNote
            })) `
            -Artifact "AntiVirus" -RawPath $File.FullName
    }
    return $resources.Count
}

# Defender DetectionHistory files and quarantine entries in the collection
# (folders found by Parse-AntiVirus). Files over 1 MB are not read (real ones
# are a few KB).
function Read-DefenderDetectionFiles {
    param([System.IO.DirectoryInfo[]]$HistoryDirs, [System.IO.DirectoryInfo[]]$EntriesDirs)
    $kinds = @(
        @{ Quarantine = $false; Label = "Defender DetectionHistory file(s)"
           Files = @($HistoryDirs | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -File -Recurse -ErrorAction SilentlyContinue } | Sort-Object FullName) },
        @{ Quarantine = $true; Label = "Defender quarantine entry file(s)"
           Files = @($EntriesDirs | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -File -ErrorAction SilentlyContinue } | Sort-Object FullName) }
    )
    $parsed = 0
    foreach ($kind in $kinds) {
        if ($kind.Files.Count -eq 0) { continue }
        Log "  Parsing: $($kind.Files.Count) $($kind.Label)"
        # Rows really added (Add-TimelineEntry drops rows outside -StartDate / -EndDate)
        $entriesBefore = $script:timelineEntries.Count
        $unreadable = 0; $noTime = 0; $tooLarge = 0
        foreach ($file in $kind.Files) {
            if ($file.Length -gt 1MB) { $tooLarge++; continue }
            try {
                if ($kind.Quarantine) { $result = Read-DefenderQuarantineEntry -File $file }
                else { $result = Read-DefenderDetectionHistory -File $file }
                if ($result -lt 0) { $unreadable++ }
                elseif ($result -eq 0) { $noTime++ }
            }
            catch {
                $unreadable++
                Log-Warning "    Failed to parse $($file.FullName): $($_.Exception.Message)"
            }
        }
        $notes = @()
        if ($unreadable -gt 0) { $notes += "$unreadable not in the expected format" }
        if ($noTime -gt 0) { $notes += "$noTime without a time" }
        if ($tooLarge -gt 0) { $notes += "$tooLarge over 1 MB not read" }
        $note = ""
        if ($notes.Count -gt 0) { $note = " (skipped: $($notes -join ', '))" }
        Log "    Added $($script:timelineEntries.Count - $entriesBefore) timeline entries$note"
        $parsed += $kind.Files.Count
    }
    return $parsed
}

function Parse-AntiVirus {
    Log "--- Parsing Antivirus Logs ---"

    $timeZone = (Get-CollectionInfo).TargetTimeZone
    $symantecPattern = '^[0-9A-Fa-f]{12},\d+,\d+,\d+,'
    $sophosPattern = '^\s*\d{8}\s\d{6}\s'
    $mcafeePattern = '^\s*\d{1,4}[./-]\d{1,2}[./-]\d{1,4}\t[^\t]*\t\s*(?:Would be blocked|Blocked) by (?:Access Protection|port blocking) rule'

    # Secrets\ is never parsed: filtering $allDirs here covers the vendor
    # folders, the Defender DetectionHistory folders and the Quarantine Entries
    # folders, which are all derived from it below.
    $allDirs = @(Get-ChildItem -Path $InputPath -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object { -not (Test-SecretsPath $_.FullName) })
    $vendorDirs = @($allDirs | Where-Object { $_.Parent -and $_.Parent.Name -eq "AntiVirus" } | Sort-Object FullName)
    $parsedFiles = 0
    foreach ($dir in $vendorDirs) {
        $vendor = $dir.Name
        # Defender: read below (DetectionHistory, quarantine entries) and by Parse-EventLogs
        if ($vendor -eq "Defender") { continue }
        if (@("Symantec_SEP", "Sophos", "McAfee_Trellix", "ESET") -notcontains $vendor) {
            Write-Verbose "No antivirus log parser for $($dir.FullName)"
            continue
        }
        foreach ($file in @(Get-ChildItem -Path $dir.FullName -File -Recurse -ErrorAction SilentlyContinue | Sort-Object Name)) {
            try {
                # Recognize the log by folder, file name and first lines
                $lines = @()
                if (@(".log", ".txt") -contains $file.Extension) { $lines = Read-AntiVirusTextLines $file.FullName }
                $head = @($lines | Where-Object { $_.Trim() } | Select-Object -First 20)
                $kind = ""
                if ($vendor -eq "Symantec_SEP") {
                    if ($file.Extension -eq ".log" -and $head.Count -gt 0 -and $head[0] -match $symantecPattern) { $kind = "Symantec" }
                }
                elseif ($vendor -eq "Sophos") {
                    if ($file.Name -like "sav*.txt" -and $head.Count -gt 0 -and $head[0] -match $sophosPattern) { $kind = "Sophos" }
                }
                elseif ($vendor -eq "McAfee_Trellix") {
                    if ($file.Name -like "AccessProtectionLog*.txt" -or @($head | Where-Object { $_ -match $mcafeePattern }).Count -gt 0) { $kind = "McAfee" }
                }
                elseif ($vendor -eq "ESET") {
                    if ($file.Name -like "virlog*.dat") { $kind = "ESET" }
                }
                if (-not $kind) {
                    Write-Verbose "Skipping $($file.FullName): not a supported $vendor log"
                    continue
                }

                Log "  Parsing: $($file.FullName)"
                if ($kind -eq "Symantec") { Read-SymantecAvLog -File $file -Lines $lines -TimeZone $timeZone }
                elseif ($kind -eq "Sophos") { Read-SophosSavLog -File $file -Lines $lines -TimeZone $timeZone }
                elseif ($kind -eq "McAfee") { Read-McAfeeAccessProtectionLog -File $file -Lines $lines -TimeZone $timeZone }
                else { Read-EsetVirlog -File $file }
                $parsedFiles++
            }
            catch {
                Log-Warning "  Failed to parse $($file.FullName): $($_.Exception.Message)"
            }
        }
    }

    if ($parsedFiles -eq 0) { Log "  No supported third-party antivirus logs (Symantec, Sophos, McAfee, ESET) in the collection." }

    # Microsoft Defender DetectionHistory files and quarantine entries. Only
    # Quarantine\Entries is read, never Quarantine\ResourceData.
    $historyDirs = @($allDirs | Where-Object { $_.Name -eq "DetectionHistory" })
    $entriesDirs = @($allDirs | Where-Object { $_.Name -eq "Entries" -and $_.Parent -and $_.Parent.Name -eq "Quarantine" })
    if ((Read-DefenderDetectionFiles -HistoryDirs $historyDirs -EntriesDirs $entriesDirs) -eq 0) {
        Log "  No Defender DetectionHistory files or quarantine entries in the collection."
    }
    Log "  Antivirus log parsing complete."
    Log ""
}

# =============================================================
# Auto-detect memory dump and prompt for analysis
# =============================================================
if ($Sources -notcontains "Memory") {
    # Check if a memory dump exists alongside the collection
    $detectedDump = Find-MemoryDump
    if (-not $detectedDump) {
        # Nothing to offer: what became of a dump collection_manifest.csv
        # lists, and how to have it analyzed
        Write-NoMemoryDumpToOffer
    }
    elseif ((Get-MemoryDumpInfo -Path $detectedDump).Architecture -eq "ARM64") {
        # Volatility 3 cannot analyze Windows ARM64 memory: don't offer it
        Log ""
        Log "Memory dump detected: $(Get-MemoryDumpDisplayName $detectedDump) (Windows ARM64)."
        Log "  Volatility 3 cannot analyze Windows ARM64 memory, so it is not offered."
        Log "  Open the .dmp file in WinDbg to examine it manually."
        Log ""
        $detectedDump = $null
    }

    # If dump found, check if Volatility 3 is available
    if ($detectedDump) {
        $volAvailable = $false
        $volLocations = @(
            (Join-Path $PSScriptRoot "tools\volatility3\vol.exe"),
            (Join-Path $PSScriptRoot "tools\volatility3\volatility3.exe"),
            (Join-Path $PSScriptRoot "tools\vol.exe")
        )
        foreach ($loc in $volLocations) {
            if (Test-Path $loc) { $volAvailable = $true; break }
        }

        if ($volAvailable) {
            $dumpSizeGB = [math]::Round((Get-Item -LiteralPath $detectedDump).Length / 1GB, 2)
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Memory Dump Detected" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Found: $(Get-MemoryDumpDisplayName $detectedDump) ($dumpSizeGB GB)" -ForegroundColor Green
            if ($script:memoryDumpListedPath) {
                Write-Host "  (where the collector saved it, on a drive with another letter now:" -ForegroundColor Green
                Write-Host "   collection_manifest.csv lists $($script:memoryDumpListedPath))" -ForegroundColor Green
            } elseif ($script:memoryDumpFromManifest) {
                Write-Host "  (where the collector saved it, as collection_manifest.csv says)" -ForegroundColor Green
            }
            Write-Host "  Volatility 3 is available in tools\" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Memory analysis extracts processes, network connections," -ForegroundColor White
            Write-Host "  command lines, and services from the RAM dump." -ForegroundColor White
            Write-Host "  Adds 5-30 minutes depending on dump size." -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  [1] Yes -- analyze memory dump (recommended for IR)" -ForegroundColor Green
            Write-Host "  [2] No  -- skip, build timeline from disk artifacts only" -ForegroundColor White
            Write-Host ""

            do {
                $memChoice = Read-Host "Include memory analysis? (1-2)"
            } while ($memChoice -notin @("1", "2"))

            if ($memChoice -eq "1") {
                $Sources = $Sources + @("Memory")
                Write-Host ""
                Write-Host "Memory analysis enabled." -ForegroundColor Cyan
                Write-Host ""
            } else {
                Write-Host ""
                Write-Host "Memory analysis skipped." -ForegroundColor DarkGray
                Write-Host ""
            }
        } else {
            Log ""
            Log "Memory dump detected ($(Get-MemoryDumpDisplayName $detectedDump)) but Volatility 3 not found in tools\ directory."
            Log "  To enable memory analysis, place vol.exe in: $(Join-Path $PSScriptRoot 'tools\volatility3\')"
            Log "  Download from: https://github.com/volatilityfoundation/volatility3/releases"
            Log ""
        }
    }
}

# =============================================================
# Main Execution
# =============================================================
Log "=== Beginning Timeline Construction ==="
Log ""

$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

# Run selected parsers
if ($Sources -contains "EventLogs")        { Parse-EventLogs }
if ($Sources -contains "Prefetch")         { Parse-Prefetch }
if ($Sources -contains "RecentFiles")      { Parse-RecentFiles }
if ($Sources -contains "Registry")         { Parse-Registry }
if ($Sources -contains "Browser")          { Parse-BrowserHistory }
if ($Sources -contains "ScheduledTasks")   { Parse-ScheduledTasks }
if ($Sources -contains "Services")         { Parse-Services }
if ($Sources -contains "FileSystem")       { Parse-FileSystem }
if ($Sources -contains "UsnJournal")       { Parse-UsnJournal }
if ($Sources -contains "Network")          { Parse-Network }
if ($Sources -contains "USB")              { Parse-USB }
if ($Sources -contains "Persistence")      { Parse-Persistence }
if ($Sources -contains "Amcache")          { Parse-Amcache }
if ($Sources -contains "PowerShellHistory") { Parse-PowerShellHistory }
if ($Sources -contains "SystemInfo")       { Parse-SystemInfo }
if ($Sources -contains "AntiVirus")        { Parse-AntiVirus }
if ($Sources -contains "Email")            { Parse-Email }
if ($Sources -contains "SRUM")             { Parse-Srum }
if ($Sources -contains "Memory")           { Parse-Memory }

# =============================================================
# Input files: a file deleted while the timeline was built (by a cleanup
# tool or antivirus) left no error, only rows missing from the timeline.
# List them; the run then ends with exit code 2. Checked once, after all
# parsers: a file deleted after its parser read it has all its rows.
# =============================================================
$missingInputs = @(Get-MissingInputFiles)
$script:missingInputCount = $missingInputs.Count
if ($missingInputs.Count -gt 0) {
    Log-Error "$($missingInputs.Count) of $($script:inputFiles.Count) input file(s) disappeared during the run -- rows from them may be missing from the timeline (not if a file was deleted after its parser read it):"
    Write-MissingInputFiles -Files $missingInputs -BaseFolder $script:collectionRoot
    Log ""
}
elseif ($script:inputFiles.Count -gt 0) {
    Log "All $($script:inputFiles.Count) input file(s) were still present at the end of parsing."
    Log ""
}

# =============================================================
# Post-Processing: Deduplicate, Sort, Keyword Flag
# =============================================================
Log "--- Post-Processing Timeline ---"

$entryCount = $script:timelineEntries.Count
Log "  Raw entries collected: $entryCount"

if ($entryCount -eq 0) {
    Log-Warning "No timeline entries were collected. Check input path and selected sources."
    if (Write-RunEndBanner -NoOutput) { exit 2 }
    exit 0
}

# User column: one form per account (ConvertTo-TimelineUserName), with the
# names gathered while parsing. Before deduplication, so rows are compared
# in that form. The computer name the collector recorded is the examined
# system's only in a live collection (a mounted image is collected on
# another machine).
if ((Get-CollectionInfo).Mode -eq "Live") { Add-TimelineMachineName (Get-CollectionInfo).ComputerName }
$userPass = Update-TimelineUserColumn -Entries $script:timelineEntries -SidNames (Get-TimelineSidNames) -MachineNames @((Get-TimelineUserContext).MachineNames)
Log "  User column: $($userPass.Rows) row(s) changed to one form per account ($($userPass.Transitions.Count) distinct value(s)); $($userPass.SidRows) row(s) whose SID got a name keep it in Details (UserSID=)"
if ($userPass.Unresolved.Count -gt 0) {
    $sidList = @($userPass.Unresolved | Select-Object -First 20 | ForEach-Object { "$($_.Sid) ($($_.Rows) row(s))" }) -join ", "
    if ($userPass.Unresolved.Count -gt 20) { $sidList += ", and $($userPass.Unresolved.Count - 20) more" }
    Log "  User column: $($userPass.Unresolved.Count) SID(s) not named by the sources read in this run (SOFTWARE ProfileList is read with -Sources Registry, bam_entries.csv with PowerShellHistory), left as they are: $sidList"
}

# Deduplicate: an entry is a duplicate only if Timestamp, Source, EventType,
# Description, User and Details are all identical (case-sensitive). The first
# occurrence is kept and, when there were more, "Occurrences=N" is appended to
# its Details once all keys are built (so the count is never part of a key).
# A dictionary of key -> position of the kept row keeps this fast on very
# large timelines; only rows that have duplicates are touched afterwards.
Log "  Deduplicating..."
$dedupPositions = [System.Collections.Generic.Dictionary[string, int]]::new($entryCount, [System.StringComparer]::Ordinal)
$deduped = [System.Collections.Generic.List[object]]::new($entryCount)
# Extra occurrences per kept position, and the positions that have any
$extraCount = New-Object int[] $entryCount
$withDuplicates = [System.Collections.Generic.List[int]]::new()
foreach ($entry in $script:timelineEntries) {
    # NUL separator: cannot occur in the values (removed by Add-TimelineEntry)
    $dedupKey = [string]$entry.Timestamp + "`0" + $entry.Source + "`0" + $entry.EventType + "`0" +
        $entry.Description + "`0" + $entry.User + "`0" + $entry.Details
    if ($dedupPositions.ContainsKey($dedupKey)) {
        $firstPosition = $dedupPositions[$dedupKey]
        if ($extraCount[$firstPosition] -eq 0) { $withDuplicates.Add($firstPosition) }
        $extraCount[$firstPosition]++
    }
    else {
        $dedupPositions[$dedupKey] = $deduped.Count
        $deduped.Add($entry)
    }
}
$dedupPositions = $null
foreach ($firstPosition in $withDuplicates) {
    $kept = $deduped[$firstPosition]
    $occurrenceText = "Occurrences=$($extraCount[$firstPosition] + 1)"
    $kept.Details = if ($kept.Details) { "$($kept.Details) | $occurrenceText" } else { $occurrenceText }
}
$extraCount = $null
$dedupedCount = $deduped.Count
$removedCount = $entryCount - $dedupedCount
Log "  Removed $removedCount duplicate(s) ($($withDuplicates.Count) row(s) now carry Occurrences=N). Unique entries: $dedupedCount"
$withDuplicates = $null

# Sort chronologically. Timestamps are fixed-width "yyyy-MM-dd HH:mm:ss.fff"
# text, so an ordinal sort is chronological. The original position is appended
# to each key so entries with the same time keep their order (stable sort).
Log "  Sorting chronologically..."
$sortKeys = New-Object string[] $dedupedCount
for ($i = 0; $i -lt $dedupedCount; $i++) {
    $sortKeys[$i] = [string]$deduped[$i].Timestamp + $i.ToString("D10")
}
[object[]]$sorted = $deduped.ToArray()
# The [Array] casts select Sort(Array, Array, IComparer), which sorts $sorted in
# place (without them PowerShell may pass a converted copy of the items array)
[Array]::Sort([Array]$sortKeys, [Array]$sorted, [System.Collections.IComparer][System.StringComparer]::Ordinal)
$sortKeys = $null
$deduped = $null

# Add Flagged column if keywords specified
if ($Keywords -and $Keywords.Count -gt 0) {
    Log "  Applying keyword flags for: $($Keywords -join ', ')"
    $keywordPattern = ($Keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $keywordRegex = New-Object System.Text.RegularExpressions.Regex($keywordPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $flaggedCount = 0
    foreach ($entry in $sorted) {
        $searchText = "$($entry.Description) $($entry.Details) $($entry.User) $($entry.Source)"
        $flag = "FALSE"
        if ($keywordRegex.IsMatch($searchText)) {
            $flag = "TRUE"
            $flaggedCount++
        }
        # Added as the last column of the CSV/Excel output
        $entry.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new('Flagged', $flag))
    }
    Log "  Flagged entries: $flaggedCount"
}

# =============================================================
# Export to CSV
# =============================================================
Log "--- Exporting Timeline ---"
Log "  Output file: $OutputFile"

$sorted | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
$fileSizeMB = [math]::Round((Get-Item $OutputFile).Length / 1MB, 2)
Log-Success "  Timeline exported: $OutputFile ($fileSizeMB MB)"

# =============================================================
# Generate Color-Coded Excel (.xlsx) via ImportExcel module
# =============================================================
$xlsxFile = $OutputFile -replace '\.csv$', '.xlsx'
$xlsxGenerated = $false

Log ""
Log "--- Generating Color-Coded Excel Timeline ---"

# Excel worksheets hold at most 1,048,576 rows (1 header + 1,048,575 data rows)
$excelMaxDataRows = 1048575
$skipExcel = $false
if ($NoExcel) {
    Log "  -NoExcel: skipping Excel generation (CSV only)."
    $skipExcel = $true
}
elseif ($dedupedCount -gt $excelMaxDataRows) {
    Log-Warning "  Timeline has $dedupedCount entries, more than Excel's limit of $excelMaxDataRows rows."
    Log-Warning "  Skipping Excel generation -- use the CSV (or narrow with -StartDate/-EndDate, -Sources, -MaxUsnEntries)."
    $skipExcel = $true
}

# Column letter(s) for a 1-based column number (1 -> A, 26 -> Z, 27 -> AA)
function Get-ExcelColumnLetter {
    param([int]$Number)
    $letters = ""
    while ($Number -gt 0) {
        $rem = ($Number - 1) % 26
        $letters = [string][char](65 + $rem) + $letters
        $Number = ($Number - 1 - $rem) / 26
    }
    return $letters
}

# Auto-install ImportExcel module if not present
if (-not $skipExcel -and -not (Get-Module -ListAvailable -Name ImportExcel)) {
    Log "  ImportExcel module not found. Installing from PSGallery..."
    try {
        # Ensure NuGet provider is available (required for Install-Module)
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [version]"2.8.5.201") {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        Install-Module -Name ImportExcel -Force -Scope CurrentUser -ErrorAction Stop
        Log-Success "  ImportExcel module installed."
    }
    catch {
        Log-Warning "  Failed to install ImportExcel module: $($_.Exception.Message)"
        Log "  Install manually: Install-Module -Name ImportExcel -Scope CurrentUser"
        Log "  Skipping Excel generation -- CSV is still available."
    }
}

if (-not $skipExcel -and (Get-Module -ListAvailable -Name ImportExcel)) {
    try {
        Import-Module ImportExcel -ErrorAction Stop

        # Define color map: EventType -> background color (RGB hex)
        $colorMap = @{
            "Logon"               = "92D050"   # Green
            "Execution"           = "FFC000"   # Orange
            "ProcessCreation"     = "FFC000"   # Orange
            "PersistenceChange"   = "FF6B6B"   # Red
            "AccountChange"       = "FF6B6B"   # Red
            "SecurityAlert"       = "FF4D4D"   # Bright red (bold text)
            "NetworkConnection"   = "6BB5FF"   # Blue
            "FileAccess"          = "D9D9D9"   # Light gray
            "FileLastModified"    = "E2C9A0"   # Tan (ShimCache file time, not an execution)
            "Snapshot"            = "F2F2F2"   # Very light gray (state, not an event)
            "ServiceChange"       = "FFFF00"   # Yellow
            "ScheduledTaskChange" = "FFFF00"   # Yellow
            "USBDevice"           = "CC99FF"   # Purple
            "Installation"        = "B4C6E7"   # Light blue
        }
        # EventTypes whose rows are also set in bold so they stand out
        $boldTypes = @("SecurityAlert")

        Log "  Exporting to Excel with conditional formatting..."

        # Second-pass sanitization for Excel compatibility:
        # 1. Remove XML-invalid characters (same rule as Add-TimelineEntry)
        # 2. Truncate strings to Excel's 32,767 char cell limit (prevents "Repaired Records")
        $maxCellLength = 32767
        foreach ($row in $sorted) {
            foreach ($prop in $row.PSObject.Properties) {
                if ($prop.Value -is [string] -and $prop.Value.Length -gt 0) {
                    $prop.Value = $script:xmlInvalidRegex.Replace($prop.Value, '')
                    if ($prop.Value.Length -gt $maxCellLength) {
                        # Do not cut an emoji (surrogate pair) in half
                        $cut = $maxCellLength - 12
                        if ([char]::IsHighSurrogate($prop.Value[$cut - 1])) { $cut-- }
                        $prop.Value = $prop.Value.Substring(0, $cut) + " [TRUNCATED]"
                    }
                }
            }
        }

        # Export CSV data to Excel
        $sorted | Export-Excel -Path $xlsxFile -WorksheetName "Timeline" `
            -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -ErrorAction Stop

        # Open the workbook to apply row-level color formatting
        $excelPkg = Open-ExcelPackage -Path $xlsxFile
        $ws = $excelPkg.Workbook.Worksheets["Timeline"]

        if ($ws) {
            $totalRows = $ws.Dimension.End.Row
            $totalCols = $ws.Dimension.End.Column

            # Find the EventType column index
            $eventTypeCol = -1
            for ($c = 1; $c -le $totalCols; $c++) {
                if ($ws.Cells[1, $c].Text -eq "EventType") {
                    $eventTypeCol = $c
                    break
                }
            }

            if ($eventTypeCol -gt 0) {
                Log "  Colorizing $($totalRows - 1) rows by EventType (column $eventTypeCol)..."
                $lastColLetter = Get-ExcelColumnLetter $totalCols

                # Build each fill color once
                $fillColors = @{}
                foreach ($type in $colorMap.Keys) {
                    $hex = $colorMap[$type]
                    $fillColors[$type] = [System.Drawing.Color]::FromArgb(
                        [Convert]::ToInt32($hex.Substring(0,2), 16),
                        [Convert]::ToInt32($hex.Substring(2,2), 16),
                        [Convert]::ToInt32($hex.Substring(4,2), 16)
                    )
                }

                # Style whole row ranges instead of single cells: consecutive rows
                # with the same EventType are colored with one range (A<start>:<last><end>)
                $coloredRows = 0
                $runStart = 2
                $runType = $ws.Cells[2, $eventTypeCol].Text
                for ($r = 3; $r -le ($totalRows + 1); $r++) {
                    $eventType = ""
                    if ($r -le $totalRows) { $eventType = $ws.Cells[$r, $eventTypeCol].Text }
                    if ($r -le $totalRows -and $eventType -ceq $runType) { continue }

                    # End of a run: rows $runStart .. ($r - 1) share $runType
                    if ($runType -and $fillColors.ContainsKey($runType)) {
                        $runEnd = $r - 1
                        $address = "A${runStart}:${lastColLetter}${runEnd}"
                        $ws.Cells[$address].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                        $ws.Cells[$address].Style.Fill.BackgroundColor.SetColor($fillColors[$runType])
                        if ($boldTypes -contains $runType) { $ws.Cells[$address].Style.Font.Bold = $true }
                        $coloredRows += $runEnd - $runStart + 1
                    }
                    $runStart = $r
                    $runType = $eventType
                }
                Log-Success "  Color-coded $coloredRows of $($totalRows - 1) rows across $($colorMap.Count) event types."
            } else {
                Log-Warning "  Could not find EventType column -- skipping colorization."
            }
        }

        Close-ExcelPackage $excelPkg

        # Note: Excel may show a "Repaired Records" dialog when opening the xlsx.
        # This is a known ImportExcel/EPPlus library issue -- the file data is intact.
        # Excel repairs minor XML formatting differences and opens normally.

        $xlsxSizeMB = [math]::Round((Get-Item $xlsxFile).Length / 1MB, 2)
        Log-Success "  Excel timeline: $xlsxFile ($xlsxSizeMB MB)"
        $xlsxGenerated = $true

        # Print color legend
        Log ""
        Log "  Color legend:"
        Log "    Green        Logon                -- authentication events"
        Log "    Orange       Execution            -- program execution evidence"
        Log "    Orange       ProcessCreation      -- new processes (Sysmon/4688)"
        Log "    Red          PersistenceChange    -- autostart, services, tasks modified"
        Log "    Red          AccountChange        -- user accounts created/modified"
        Log "    Bright red   SecurityAlert        -- AV detections, security tampering (bold)"
        Log "    Blue         NetworkConnection    -- network activity, browser, DNS"
        Log "    Gray         FileAccess           -- file system activity"
        Log "    Tan          FileLastModified     -- file last-modified time (ShimCache), not execution"
        Log "    Yellow       ServiceChange        -- service state changes"
        Log "    Yellow       ScheduledTaskChange  -- task scheduler changes"
        Log "    Purple       USBDevice            -- USB device connections"
        Log "    Light Blue   Installation         -- application, device and driver installs"
        Log "    Light gray   Snapshot             -- state when collected or captured, not an event"
    }
    catch {
        Log-Warning "  Failed to generate Excel file: $($_.Exception.Message)"
        Log "  CSV is still available: $OutputFile"
    }
}

# =============================================================
# Summary Statistics
# =============================================================

# Rows per Artifact for "Events by artifact source". Pass the rows of the
# finished timeline (after deduplication, as written to the CSV), so the
# counts add up to the total. Returns Name/Count objects, the largest count
# first and equal counts in name order.
function Get-ArtifactRowCounts {
    param([object[]]$Rows)
    $counts = @{}
    foreach ($row in $Rows) {
        $artifact = [string]$row.Artifact
        if ($counts.ContainsKey($artifact)) { $counts[$artifact]++ } else { $counts[$artifact] = 1 }
    }
    $counts.GetEnumerator() |
        Sort-Object @{ Expression = "Value"; Descending = $true }, @{ Expression = "Key"; Descending = $false } |
        ForEach-Object { [PSCustomObject]@{ Name = $_.Key; Count = $_.Value } }
}

$totalTimer.Stop()
Log ""
Log "============================================================="
Log "  TIMELINE BUILDER SUMMARY"
Log "============================================================="
Log "  Total events     : $dedupedCount"
Log "  Duplicates removed: $removedCount"
Log "  Output file      : $OutputFile"
Log "  File size        : $fileSizeMB MB"
Log "  Processing time  : $([math]::Round($totalTimer.Elapsed.TotalSeconds, 1)) seconds"
Log ""

# Date range ($sorted is chronological: first and last entries)
$earliest = [datetime]::ParseExact($sorted[0].Timestamp, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
$latest = [datetime]::ParseExact($sorted[$sorted.Count - 1].Timestamp, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
Log "  Date range       : $($earliest.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Log "                   : $($latest.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Log "  Span             : $(($latest - $earliest).Days) days"
Log ""

# Per-source breakdown of the rows in the timeline: counted after
# deduplication, so the counts add up to "Total events"
Log "  Events by artifact source:"
foreach ($artifact in (Get-ArtifactRowCounts -Rows $sorted)) {
    Log "    $($artifact.Name.PadRight(25)) : $($artifact.Count)"
}

if ($Keywords -and $Keywords.Count -gt 0) {
    Log ""
    Log "  Keyword-flagged  : $flaggedCount entries"
}

Log ""
Log "============================================================="
# The exit code is decided here: an error while opening a viewer (below)
# does not change it
$timelineIncomplete = Write-RunEndBanner
Log ""
Log "============================================================="

# --- Let user choose how to view the timeline ---
Log ""
Log "  Output files:"
Log "    CSV: $OutputFile"
if ($xlsxGenerated) { Log "    Excel (color-coded): $xlsxFile" }
Log ""

if ($Viewer) {
    # -Viewer given: no menu (scripts, automation, tests)
    $selectedAction = switch ($Viewer) {
        "Excel"            { "excel" }
        "TimelineExplorer" { "te" }
        "Both"             { "both" }
        default            { "none" }
    }
    if (($selectedAction -eq "excel" -or $selectedAction -eq "both") -and -not $xlsxGenerated) {
        Log-Warning "  -Viewer ${Viewer}: no Excel file was generated, so Excel is not opened."
        if ($selectedAction -eq "both") { $selectedAction = "te" } else { $selectedAction = "none" }
    }
    Log "  Viewer selection: $Viewer (-Viewer)"
}
else {
    # Build viewer menu dynamically based on what's available
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  How would you like to view the timeline?" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $menuOptions = @()

    if ($xlsxGenerated) {
        $menuOptions += @{ Key = "1"; Label = "Excel (color-coded .xlsx)"; Action = "excel" }
        Write-Host "  [1] Excel -- rows pre-colored by EventType, ready to analyze" -ForegroundColor Green
        Write-Host "       (Logon=Green, Execution=Orange, Persistence=Red, Network=Blue, etc.)" -ForegroundColor DarkGray
    }

    $teOptionNum = $menuOptions.Count + 1
    $menuOptions += @{ Key = "$teOptionNum"; Label = "Timeline Explorer (Eric Zimmerman)"; Action = "te" }
    Write-Host "  [$teOptionNum] Timeline Explorer -- powerful forensic CSV viewer (no colors," -ForegroundColor White
    Write-Host "       requires manual conditional formatting setup per session)" -ForegroundColor DarkGray

    if ($xlsxGenerated) {
        $bothOptionNum = $menuOptions.Count + 1
        $menuOptions += @{ Key = "$bothOptionNum"; Label = "Both"; Action = "both" }
        Write-Host "  [$bothOptionNum] Both -- open Excel (colored) and Timeline Explorer side by side" -ForegroundColor White
    }

    $noneOptionNum = $menuOptions.Count + 1
    $menuOptions += @{ Key = "$noneOptionNum"; Label = "None"; Action = "none" }
    Write-Host "  [$noneOptionNum] None -- just save the files, don't open anything" -ForegroundColor DarkGray
    Write-Host ""

    $maxOption = $menuOptions.Count
    do {
        $viewerChoice = Read-Host "Select a viewer (1-$maxOption)"
    } while (-not ($menuOptions.Key -contains $viewerChoice))

    $selectedAction = ($menuOptions | Where-Object { $_.Key -eq $viewerChoice }).Action
    Log "  Viewer selection: $($($menuOptions | Where-Object { $_.Key -eq $viewerChoice }).Label)"
}

# --- Helper: ensure Timeline Explorer is available ---
function Get-TimelineExplorer {
    $teLocations = @(
        (Join-Path $PSScriptRoot "tools\TimelineExplorer\TimelineExplorer\TimelineExplorer.exe"),
        (Join-Path $PSScriptRoot "tools\TimelineExplorer\TimelineExplorer.exe"),
        (Join-Path $PSScriptRoot "reports\TimelineExplorer\TimelineExplorer\TimelineExplorer.exe"),
        (Join-Path $PSScriptRoot "reports\TimelineExplorer\TimelineExplorer.exe"),
        (Join-Path $PSScriptRoot "TimelineExplorer\TimelineExplorer.exe"),
        (Join-Path $PSScriptRoot "TimelineExplorer.exe")
    )
    foreach ($loc in $teLocations) {
        if (Test-Path $loc) { return $loc }
    }

    # Not found -- download it
    Log ""
    Log "Timeline Explorer not found. Downloading latest from Eric Zimmerman's tools..."
    Log "  Credit: Timeline Explorer by Eric Zimmerman (https://ericzimmerman.github.io/)"
    $teDir = Join-Path $PSScriptRoot "tools\TimelineExplorer"
    $teZip = Join-Path $env:TEMP "TimelineExplorer_download.zip"
    try {
        $teUrl = "https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip"
        try {
            $page = Invoke-WebRequest -Uri "https://ericzimmerman.github.io/#!index.md" -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
            $match = [regex]::Match($page.Content, 'https://download\.ericzimmermanstools\.com/[^"'']+TimelineExplorer\.zip')
            if ($match.Success) {
                $teUrl = $match.Value
                Log "  Found latest URL: $teUrl"
            }
        }
        catch {
            Log "  Could not check for latest version, using known URL."
        }

        Invoke-WebRequest -Uri $teUrl -OutFile $teZip -UseBasicParsing -ErrorAction Stop
        New-Item -ItemType Directory -Path $teDir -Force | Out-Null
        Expand-Archive -Path $teZip -DestinationPath $teDir -Force -ErrorAction Stop

        $found = Get-ChildItem -Path $teDir -Filter "TimelineExplorer.exe" -Recurse | Select-Object -First 1
        if ($found) {
            Log-Success "  Downloaded Timeline Explorer to: $($found.FullName)"
            return $found.FullName
        }
    }
    catch {
        Log-Warning "  Failed to download Timeline Explorer: $($_.Exception.Message)"
        Log "  You can manually download from: https://ericzimmerman.github.io/#!index.md"
    }
    finally {
        Remove-Item $teZip -Force -ErrorAction SilentlyContinue
    }
    return $null
}

# --- Launch selected viewer(s) ---
if ($selectedAction -eq "excel" -or $selectedAction -eq "both") {
    Log ""
    Log "--- Opening Color-Coded Timeline in Excel ---"
    try {
        Start-Process -FilePath $xlsxFile
        Log-Success "  Excel launched with color-coded timeline."
        Log "  NOTE: Excel may prompt to repair the file -- click Yes. This is a known"
        Log "  ImportExcel library issue. The data and formatting are intact."
    }
    catch {
        Log-Warning "  Could not open Excel: $($_.Exception.Message)"
    }
}

if ($selectedAction -eq "te" -or $selectedAction -eq "both") {
    $teExe = Get-TimelineExplorer
    if ($teExe) {
        Log ""
        Log "Opening timeline in Timeline Explorer (Eric Zimmerman)..."
        Log "  https://ericzimmerman.github.io/"
        try {
            Start-Process -FilePath $teExe -ArgumentList "`"$OutputFile`""
            Log-Success "  Timeline Explorer launched."
            Log ""
            Log "  TIP: Color-code your timeline by EventType for easier analysis:"
            Log "    1. Right-click any cell in the EventType column"
            Log "    2. Conditional Formatting -> Highlight Cell Rules -> Text That Contains"
            Log "    3. Enter an event type (e.g. Logon, Execution, PersistenceChange)"
            Log "    4. Pick a color and CHECK 'Apply formatting to an entire row'"
            Log "    5. Repeat for each EventType. File -> Save Session to keep your setup."
        }
        catch {
            Log-Warning "  Could not launch Timeline Explorer: $($_.Exception.Message)"
            Log "  Open manually: $teExe"
        }
    }
}

if ($selectedAction -eq "none") {
    Log ""
    Log "  No viewer launched. Files saved to:"
    Log "    CSV: $OutputFile"
    if ($xlsxGenerated) { Log "    Excel: $xlsxFile" }
}

Log "============================================================="

# Exit code 2: the timeline was written, but input files went missing or
# an unexpected error skipped part of a step
if ($timelineIncomplete) { exit 2 }

# End of the main try block that starts after the "Started" log lines (the
# body in between is intentionally not re-indented). The finally block runs
# on normal completion, on exit, on Ctrl+C and on terminating errors.
}
finally {
    # Hives first: their scratch copies are in the work folder
    Dismount-RunHives
    Remove-RunWorkFolder
}
