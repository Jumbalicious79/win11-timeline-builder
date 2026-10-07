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
        $validSources = @("EventLogs", "Prefetch", "RecentFiles", "Registry", "FileSystem", "Browser", "ScheduledTasks", "Services", "Network", "USB", "Persistence", "UsnJournal", "Amcache", "PowerShellHistory", "SystemInfo", "Memory")
        foreach ($name in ("$_" -split ',')) {
            if ($name.Trim() -and $validSources -notcontains $name.Trim()) {
                throw "Unknown source '$($name.Trim())'. Valid sources: $($validSources -join ', ')"
            }
        }
        $true
    })]
    [string[]]$Sources = @("EventLogs", "Prefetch", "RecentFiles", "Registry", "FileSystem", "Browser", "ScheduledTasks", "Services", "Network", "USB", "Persistence", "UsnJournal", "Amcache", "PowerShellHistory", "SystemInfo"),

    [Parameter(Mandatory = $false)]
    [string[]]$Keywords,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 2147483647)]
    [int]$MaxUsnEntries = 0,

    # $MFT file-system events: only times within this many days before the
    # collection are added (0 = all). A full $MFT can hold millions of times.
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 36500)]
    [int]$MftDays = 30
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

    # Extract to a short temp path to avoid Windows 260-char path limit
    # (the iCloud path is already very deep). A marker file next to the
    # folder is written only when extraction finishes, so a half-extracted
    # folder left by an earlier failed run is never reused.
    $script:browseExtractDir = Join-Path $env:TEMP ("TriageExtract_" + $selectedZip.BaseName)
    $extractDir = $script:browseExtractDir
    $extractMarker = "$extractDir.complete"

    if ((Test-Path -LiteralPath $extractMarker) -and (Test-Path -LiteralPath $extractDir)) {
        Write-Host "Using existing extracted folder: $extractDir" -ForegroundColor Cyan
    } else {
        if (Test-Path -LiteralPath $extractDir) {
            Write-Host "Removing incomplete extraction from an earlier run: $extractDir" -ForegroundColor Yellow
            Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Extracting $($selectedZip.Name) to temp..." -ForegroundColor Cyan
        try {
            # Entry by entry (not Expand-Archive) so over-long paths can be
            # shortened instead of failing the whole extraction
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($selectedZip.FullName)
            $renamedCount = 0
            try {
                foreach ($entry in $zipArchive.Entries) {
                    if (-not $entry.Name) { continue }   # folder entry
                    $entryDest = Join-Path $extractDir $entry.FullName.Replace('/', '\')
                    if ($entryDest.Length -gt 240) {
                        # Keep the name's start and add a hash so it stays unique
                        $entryDir = Split-Path $entryDest -Parent
                        $ext = [System.IO.Path]::GetExtension($entry.Name)
                        $sha1 = New-Object System.Security.Cryptography.SHA1Managed
                        $nameHash = [System.BitConverter]::ToString($sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($entry.Name))).Replace("-", "").Substring(0, 8)
                        $keep = [Math]::Max(8, 240 - $entryDir.Length - 1 - $ext.Length - 9)
                        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)
                        if ($baseName.Length -gt $keep) { $baseName = $baseName.Substring(0, $keep) }
                        $entryDest = Join-Path $entryDir "$baseName~$nameHash$ext"
                        $renamedCount++
                    }
                    # Never write outside the extraction folder (".." entries)
                    if (-not [System.IO.Path]::GetFullPath($entryDest).StartsWith($extractDir + '\', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                    New-Item -ItemType Directory -Path (Split-Path $entryDest -Parent) -Force | Out-Null
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryDest, $true)
                }
            }
            finally {
                $zipArchive.Dispose()
            }
            Set-Content -LiteralPath $extractMarker -Value $selectedZip.FullName
            Write-Host "Extracted to: $extractDir" -ForegroundColor Green
            if ($renamedCount -gt 0) {
                Write-Host "  ($renamedCount over-long file name(s) shortened to fit the 260-character path limit)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "ERROR: Failed to extract zip: $($_.Exception.Message)" -ForegroundColor Red
            Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
            pause
            exit 1
        }
    }

    # The extracted folder may contain a single subfolder -- find the actual collection root
    $children = Get-ChildItem -Path $extractDir -Directory
    if ($children.Count -eq 1 -and -not (Get-ChildItem -Path $extractDir -File)) {
        $InputPath = $children[0].FullName
    } else {
        $InputPath = $extractDir
    }

    Write-Host "Input path: $InputPath" -ForegroundColor Cyan
    Write-Host ""
}

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportDir = Join-Path $PSScriptRoot "reports\timeline_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$logFile = Join-Path $reportDir "timeline_builder_log.txt"

# Set default output file if not specified
if (-not $OutputFile) {
    $OutputFile = Join-Path $reportDir "timeline.csv"
}

# =============================================================
# Logging
# =============================================================
function Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $logFile -Value $entry
}

function Log-Warning {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WARNING: $Message"
    Write-Host $entry -ForegroundColor Yellow
    Add-Content -Path $logFile -Value $entry
}

function Log-Error {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR: $Message"
    Write-Host $entry -ForegroundColor Red
    Add-Content -Path $logFile -Value $entry
}

function Log-Success {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry -ForegroundColor Green
    Add-Content -Path $logFile -Value $entry
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
Log ""

if (-not (Test-Path $InputPath)) {
    Log-Error "Input path does not exist: $InputPath"
    exit 1
}

# =============================================================
# Timeline Entry Collection
# =============================================================
$script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:artifactStats = @{}

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

    # Track stats
    if (-not $script:artifactStats.ContainsKey($Artifact)) {
        $script:artifactStats[$Artifact] = 0
    }
    $script:artifactStats[$Artifact]++
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
    return $results
}

# =============================================================
# Shared helpers: collection metadata, time conversion, users
# Used by several parsers. collection_info.json and the extra
# collection_manifest.csv columns are written by the triage
# collector (see its README); older collections fall back to
# collection_log.txt and file times.
# =============================================================
$script:collectionRoot = [System.IO.Path]::GetFullPath($InputPath).TrimEnd('\')
$script:collectionInfo = $null
$script:manifestTimes = $null

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

# Account an artifact belongs to, from the collection's own folder layout
# (Registry\<user>\, UserActivity\<user>\, Browser\<user>\) or a Users\<user>\
# segment inside the collection -- never from the analyst machine's path.
function Get-CollectionUser {
    param([string]$FullPath)
    $rel = Get-RelativeCollectionPath $FullPath
    if (-not $rel) { return "" }
    if ($rel -match '^(?:Registry|UserActivity|Browser)\\([^\\]+)\\') { return $Matches[1] }
    if ($rel -match '(?:^|\\)Users\\([^\\]+)\\') { return $Matches[1] }
    return ""
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
# install (its own logs, e.g. setupapi.dev.log, are in this zone).
function Get-CollectionInfo {
    if ($script:collectionInfo) { return $script:collectionInfo }

    $info = [PSCustomObject]@{
        Source             = "defaults (analysis machine)"
        Mode               = ""
        CollectionStartUtc = $null
        CollectorTimeZone  = [System.TimeZoneInfo]::Local
        TargetTimeZone     = $null
        CollectorCulture   = $null
    }

    $jsonFile = Get-ChildItem -Path $InputPath -Filter "collection_info.json" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $collLog = Get-ChildItem -Path $InputPath -Filter "collection_log.txt" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($jsonFile) {
        try {
            $j = Get-Content -Path $jsonFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
            $info.Source = "collection_info.json"
            if ($j.Mode) { $info.Mode = [string]$j.Mode }
            $info.CollectionStartUtc = ConvertFrom-UtcText $j.CollectionStartUtc
            $tz = Get-TimeZoneById ([string]$j.CollectorTimeZoneId)
            if ($tz) { $info.CollectorTimeZone = $tz }
            $info.TargetTimeZone = Get-TimeZoneById ([string]$j.TargetTimeZoneId)
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
# record them (older collectors, command output, reg save exports).
function Get-SourceFileTimes {
    param([string]$FullPath)
    if ($null -eq $script:manifestTimes) {
        $script:manifestTimes = @{}
        $mf = Get-ChildItem -Path $InputPath -Filter "collection_manifest.csv" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($mf) {
            try {
                foreach ($row in (Import-Csv -Path $mf.FullName -ErrorAction Stop)) {
                    if ($row.PSObject.Properties["RelativePath"] -and $row.RelativePath -and $row.PSObject.Properties["SourceModifiedUtc"]) {
                        $script:manifestTimes[$row.RelativePath] = [PSCustomObject]@{
                            Created  = ConvertFrom-UtcText $row.SourceCreatedUtc
                            Modified = ConvertFrom-UtcText $row.SourceModifiedUtc
                            Accessed = ConvertFrom-UtcText $row.SourceAccessedUtc
                        }
                    }
                }
            }
            catch { Log-Warning "Could not read collection manifest: $($_.Exception.Message)" }
        }
        if ($script:manifestTimes.Count -eq 0) {
            Log-Warning "Collection manifest has no original file times (older collector) -- file-time events will be limited."
        }
    }
    $rel = Get-RelativeCollectionPath $FullPath
    if (-not $rel) { return $null }
    return $script:manifestTimes[$rel]
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

# Events with the given IDs from an .evtx file (nothing if there are none)
function Get-EvtxEventsById {
    param([string]$Path, [int[]]$Ids, [string]$Label)
    $xpath = "*[System[(" + (($Ids | ForEach-Object { "EventID=$_" }) -join " or ") + ")]]"
    try {
        return @(Get-WinEvent -Path $Path -FilterXPath $xpath -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound*" -and $_.Exception.Message -notmatch "No events were found") {
            Log-Warning "    Error reading $Label events from $(Split-Path $Path -Leaf) : $($_.Exception.Message)"
        }
        return @()
    }
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

            # Security log events
            if ($logName -eq "Security") {
                $targetIds = @(4624, 4625, 4648, 4672, 4688, 4720, 4726, 4732)
                try {
                    $events = Get-WinEvent -Path $filePath -FilterXPath (
                        "*[System[(" + (($targetIds | ForEach-Object { "EventID=$_" }) -join " or ") + ")]]"
                    ) -ErrorAction Stop
                }
                catch [Exception] {
                    if ($_.Exception.Message -notmatch "No events were found") {
                        Log-Warning "    Error reading Security events from $fileName : $($_.Exception.Message)"
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
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Successful logon ($logonTypeDesc)" `
                                -User "$($eventData['TargetDomainName'])\$($eventData['TargetUserName'])" `
                                -Details "LogonType=$logonType Source=$($eventData['IpAddress']):$($eventData['IpPort']) LogonID=$($eventData['TargetLogonId'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4625 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Failed logon attempt (Status=$($eventData['Status']))" `
                                -User "$($eventData['TargetDomainName'])\$($eventData['TargetUserName'])" `
                                -Details "FailureReason=$($eventData['SubStatus']) Source=$($eventData['IpAddress'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4648 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Logon using explicit credentials" `
                                -User "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])" `
                                -Details "TargetUser=$($eventData['TargetDomainName'])\$($eventData['TargetUserName']) TargetServer=$($eventData['TargetServerName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4672 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Logon" `
                                -Description "Special privileges assigned to new logon" `
                                -User "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])" `
                                -Details "Privileges=$($eventData['PrivilegeList'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4688 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ProcessCreation" `
                                -Description "New process created: $($eventData['NewProcessName'])" `
                                -User "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])" `
                                -Details "CommandLine=$($eventData['CommandLine']) ParentProcess=$($eventData['ParentProcessName']) PID=$($eventData['NewProcessId'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4720 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "AccountChange" `
                                -Description "User account created: $($eventData['TargetUserName'])" `
                                -User "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])" `
                                -Details "NewAccount=$($eventData['TargetDomainName'])\$($eventData['TargetUserName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4726 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "AccountChange" `
                                -Description "User account deleted: $($eventData['TargetUserName'])" `
                                -User "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])" `
                                -Details "DeletedAccount=$($eventData['TargetDomainName'])\$($eventData['TargetUserName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4732 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "AccountChange" `
                                -Description "Member added to security-enabled local group" `
                                -User "$($eventData['SubjectDomainName'])\$($eventData['SubjectUserName'])" `
                                -Details "MemberSID=$($eventData['MemberSid']) Group=$($eventData['TargetUserName'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                    }
                }
            }

            # System log events
            if ($logName -eq "System") {
                $targetIds = @(7034, 7036, 7040, 7045, 1074, 6008)
                try {
                    $events = Get-WinEvent -Path $filePath -FilterXPath (
                        "*[System[(" + (($targetIds | ForEach-Object { "EventID=$_" }) -join " or ") + ")]]"
                    ) -ErrorAction Stop
                }
                catch [Exception] {
                    if ($_.Exception.Message -notmatch "No events were found") {
                        Log-Warning "    Error reading System events from $fileName : $($_.Exception.Message)"
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
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "ServiceChange" `
                                -Description "Service start type changed: $($eventData['param1'])" `
                                -Details "OldType=$($eventData['param2']) NewType=$($eventData['param3'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        7045 {
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "PersistenceChange" `
                                -Description "New service installed: $($eventData['ServiceName'])" `
                                -User $eventData['AccountName'] `
                                -Details "ImagePath=$($eventData['ImagePath']) StartType=$($eventData['StartType'])" `
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

                    switch ($evt.Id) {
                        4104 {
                            $scriptBlock = $eventData['ScriptBlockText']
                            if ($scriptBlock.Length -gt 500) { $scriptBlock = $scriptBlock.Substring(0, 500) + "..." }
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Execution" `
                                -Description "PowerShell script block executed" `
                                -User $eventData['UserName'] `
                                -Details "ScriptBlock=$scriptBlock Path=$($eventData['ScriptBlockId'])" `
                                -Artifact "EventLogs" -RawPath $filePath
                        }
                        4103 {
                            $payload = $eventData['Payload']
                            if ($payload -and $payload.Length -gt 500) { $payload = $payload.Substring(0, 500) + "..." }
                            Add-TimelineEntry -Timestamp $evt.TimeCreated -Source $fileName -EventType "Execution" `
                                -Description "PowerShell module logging event" `
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
                $events = @(Get-EvtxEventsById -Path $filePath -Ids @(1006, 1007, 1008, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012, 5013) -Label "Defender")
                $routineConfig = 0
                foreach ($evt in $events) {
                    $f = Get-EvtxEventFields $evt
                    $id = $evt.Id
                    if ($id -eq 5007) {
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
                            -Details (Format-ArtifactDetails ([ordered]@{ EventID = $evt.Id; JobId = $f["Id"]; Url = $f["url"]; Result = $hr; BytesTransferred = $f["bytesTransferred"]; BytesTotal = $f["bytesTotal"]; UserSID = $evt.UserId })) `
                            -Artifact "EventLogs" -RawPath $filePath
                    }
                }
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
    $threatStatusNames = @{ "0" = "Unknown"; "1" = "Detected"; "2" = "Cleaned"; "3" = "Quarantined"; "4" = "Removed";
        "5" = "Allowed"; "6" = "Blocked"; "102" = "QuarantineFailed"; "103" = "RemoveFailed"; "104" = "AllowFailed";
        "105" = "Abandoned"; "107" = "BlockedFailed" }
    $detectionCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("defender_detections.csv")
    foreach ($csv in $detectionCsvs) {
        Log "  Parsing: $($csv.Name)"
        try {
            # A collection without detections holds only a text placeholder line
            $detections = @(Import-Csv -Path $csv.FullName -ErrorAction Stop | Where-Object { $_.PSObject.Properties["ThreatName"] })
            if ($detections.Count -eq 0) {
                Log "    No Defender detections recorded."
                continue
            }
            $entriesBefore = $script:timelineEntries.Count
            foreach ($det in $detections) {
                $threat = Get-ArtifactRowValue $det @("ThreatName")
                $statusId = Get-ArtifactRowValue $det @("ThreatStatusID")
                $status = if ($threatStatusNames.ContainsKey($statusId)) { $threatStatusNames[$statusId] } else { $statusId }
                $details = Format-ArtifactDetails ([ordered]@{
                    Resources   = Get-ArtifactRowValue $det @("Resources")
                    Process     = Get-ArtifactRowValue $det @("ProcessName")
                    Status      = $status
                    DetectionID = Get-ArtifactRowValue $det @("DetectionID")
                    ThreatID    = Get-ArtifactRowValue $det @("ThreatID")
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

function Parse-RecentFiles {
    Log "--- Parsing Recent Files (LNK Shortcuts) ---"

    # Only the collection's own .lnk files -- never the analysis machine's Recent folders
    $lnkFiles = Find-ArtifactFiles -BasePath $InputPath -Extensions @(".lnk")

    if ($lnkFiles.Count -eq 0) {
        Log-Warning "No .lnk files found in the collection. Skipping recent files parsing."
        return
    }

    Log "Found $($lnkFiles.Count) LNK file(s)"

    # WScript.Shell resolves the target path; the rows are still written without it
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop }
    catch { Log-Warning "  WScript.Shell unavailable ($($_.Exception.Message)) -- LNK target paths will be blank." }

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
    Log "  LNK times: $fromSource file(s) with original file times, $fromCopy with the collected copy's last-write time only."
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

# Load an offline hive under HKLM\<name> from a temp copy (plus any .LOG1/.LOG2
# transaction logs, so reg load can replay a dirty hive). The collected file
# is never modified. Returns Name/TempDir/Root (open .NET RegistryKey) or $null.
# Always pair with Dismount-TimelineHive.
function Mount-TimelineHive {
    param([System.IO.FileInfo]$HiveFile, [string]$Prefix = "TEMP_TL")
    $hiveName = "$($Prefix)_$(Get-Random)"
    $tempDir = Join-Path $env:TEMP "TimelineHive_$(Get-Random)"
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
        }
        Log "  Loading hive: $($HiveFile.FullName)"
        $regLoadResult = & reg load "HKLM\$hiveName" $tempHive 2>&1
        if ($LASTEXITCODE -ne 0) {
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
        Remove-Item -LiteralPath $Mount.TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
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
# TypedPaths, TypedURLs, RunMRU, UserAssist, RecentDocs and the per-user Run
# keys. MRU-style keys record only one time -- the key's last write, which
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
    $i = [Array]::IndexOf($Data, [byte]0xEF, 6)
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

function Parse-Registry {
    Log "--- Parsing Registry Artifacts ---"

    $registryParsed = $false

    # Try to find offline registry hives in the input path
    $ntUserFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("NTUSER.DAT") | Where-Object { -not $_.PSIsContainer })

    # Parse NTUSER.DAT hives (RecentDocs, RunMRU, TypedPaths, TypedURLs, UserAssist, Run keys)
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

# Run a query with sqlite3 against a temp copy of the database (plus its -wal
# file, so recent history not yet checkpointed is included). Returns the CSV
# output lines, decoded as UTF-8.
function Invoke-Sqlite3Query {
    param([string]$Sqlite3Exe, [string]$DbPath, [string]$Query)
    $tempDb = Join-Path $env:TEMP "timeline_browser_$(Get-Random).db"
    $prevEncoding = $null
    try {
        Copy-Item -LiteralPath $DbPath -Destination $tempDb -Force -ErrorAction Stop
        if (Test-Path -LiteralPath "$DbPath-wal") {
            Copy-Item -LiteralPath "$DbPath-wal" -Destination "$tempDb-wal" -Force -ErrorAction SilentlyContinue
        }
        # sqlite3 writes UTF-8; without this, titles are decoded with the OEM code page
        try { $prevEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
        catch { Write-Verbose "Could not set console output encoding to UTF-8: $($_.Exception.Message)" }
        $output = & $Sqlite3Exe -csv $tempDb $Query 2>&1
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
        foreach ($tmp in @($tempDb, "$tempDb-wal", "$tempDb-shm", "$tempDb-journal")) {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
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

# Browser profile folder (e.g. "Default") from the collection layout, or ""
function Get-BrowserProfileName {
    param([string]$FullPath)
    $rel = Get-RelativeCollectionPath $FullPath
    if ($rel -and $rel -match '^Browser\\[^\\]+\\[^\\]+\\(.+)\\[^\\]+$') { return $Matches[1] }
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

function Parse-BrowserHistory {
    Log "--- Parsing Browser History ---"

    $browserParsed = $false
    # Newest visits kept per database
    $maxVisits = 20000

    # Find browser history databases (SQLite files only)
    $chromeHistoryPaths = @()
    $firefoxHistoryPaths = @()

    $historyFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("History", "places.sqlite")
    foreach ($f in $historyFiles) {
        if ($f.PSIsContainer) { continue }
        if (-not (Test-FileSignature -Path $f.FullName -Signature "SQLite format 3")) { continue }
        if ($f.Name -eq "History") { $chromeHistoryPaths += $f }
        if ($f.Name -eq "places.sqlite") { $firefoxHistoryPaths += $f }
    }

    $totalBrowserFiles = $chromeHistoryPaths.Count + $firefoxHistoryPaths.Count
    if ($totalBrowserFiles -eq 0) {
        Log-Warning "No browser history databases found. Skipping."
        Log ""
        return
    }

    Log "  Found $totalBrowserFiles browser database(s)"

    # --- Ensure sqlite3.exe is available (auto-download if needed) ---
    $sqlite3Exe = Find-Sqlite3Exe
    if (-not $sqlite3Exe) {
        Log-Warning "  sqlite3.exe not available. Skipping browser parsing."
        Log "  Browser history parsing complete."
        Log ""
        return
    }

    Log "  Using sqlite3: $sqlite3Exe"

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

function Parse-ScheduledTasks {
    Log "--- Parsing Scheduled Tasks ---"

    $tasksParsed = $false

    # scheduled_tasks.csv from the triage collector (live systems). Newer
    # collectors add RegistrationDateUtc and LastRunTimeUtc; a task with
    # neither (and every task from older collectors) becomes one Snapshot row.
    $tasksCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("scheduled_tasks.csv")

    foreach ($csv in $tasksCsv) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $tasks = Import-Csv -Path $csv.FullName -ErrorAction Stop
            $snapshotTs = Get-SnapshotTimeUtc -File $csv
            $eventRows = 0
            $snapshotRows = 0
            foreach ($task in $tasks) {
                $taskName = Get-ArtifactRowValue $task @("TaskName", "Name")
                if (-not $taskName) { $taskName = "Unknown" }
                $taskPath = Get-ArtifactRowValue $task @("TaskPath")
                $fullName = if ($taskPath) { $taskPath.TrimEnd('\') + "\" + $taskName } else { $taskName }
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
                $lastRun = ConvertFrom-UtcText (Get-ArtifactRowValue $task @("LastRunTimeUtc"))
                # Task Scheduler reports 11/30/1999 for tasks that never ran
                if ($lastRun -and $lastRun.Year -lt 2000) { $lastRun = $null }

                if ($registered) {
                    Add-TimelineEntry -Timestamp $registered -Source "ScheduledTasks" -EventType "ScheduledTaskChange" `
                        -Description "Scheduled task registered: $fullName" `
                        -User $taskUser -Details (Format-ArtifactDetails $pairs) `
                        -Artifact "ScheduledTasks" -RawPath $csv.FullName
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
        }
        catch {
            Log-Warning "  Failed to parse scheduled tasks CSV: $($_.Exception.Message)"
        }
    }

    # Task XML definitions copied from a mounted image (Windows\System32\Tasks).
    # RegistrationInfo/Date gives the registration time; tasks without it
    # become Snapshot rows.
    $xmlDirs = @(Get-ChildItem -Path $InputPath -Directory -Recurse -Filter "ScheduledTasks_XML" -ErrorAction SilentlyContinue)
    foreach ($dir in $xmlDirs) {
        $taskFiles = @(Get-ChildItem -Path $dir.FullName -File -Recurse -ErrorAction SilentlyContinue)
        Log "  Parsing: $($dir.FullName) ($($taskFiles.Count) file(s))"
        $eventRows = 0
        $snapshotRows = 0
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
                $details = Format-ArtifactDetails ([ordered]@{
                    Actions  = ($actions -join "; ")
                    UserId   = $userId
                    Author   = $author
                    Enabled  = Get-TaskXmlText $taskNode "Settings/Enabled"
                    Triggers = ($triggers -join ", ")
                })

                $registered = ConvertFrom-TaskDateText (Get-TaskXmlText $taskNode "RegistrationInfo/Date")
                if ($registered) {
                    Add-TimelineEntry -Timestamp $registered -Source "ScheduledTasks-XML" -EventType "ScheduledTaskChange" `
                        -Description "Scheduled task registered: $fullName" `
                        -User $taskUser -Details $details `
                        -Artifact "ScheduledTasks" -RawPath $tf.FullName
                    $eventRows++
                }
                else {
                    $snapshotTs = Get-SnapshotTimeUtc -File $tf
                    if ($snapshotTs) {
                        Add-TimelineEntry -Timestamp $snapshotTs -Source "ScheduledTasks-XML" -EventType "Snapshot" `
                            -Description "Scheduled task: $fullName" `
                            -User $taskUser -Details $details `
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
    }

    public sealed class MftResult
    {
        public MftResult() { Rows = new List<MftRow>(); }
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
        static readonly long MaxFileTime = DateTime.MaxValue.ToFileTimeUtc();
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

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
                if (baseRecord < count && baseRecord != rec && (curName != null || curSize >= 0))
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
                    extensions.Add(part);
                }
                return;
            }

            byte st = StValid;
            if ((flags & 0x01) != 0) st |= StInUse;
            if ((flags & 0x02) != 0) st |= StDir;
            if (curHasSI) st |= StHasSI;
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
                }
                else if (type == 0x80 && nameLength == 0)
                {
                    // Non-resident: the first extent (start VCN 0x10 = 0) holds the real size (0x30)
                    if (len < 0x40) return false;
                    if (BitConverter.ToInt64(b, o + a + 0x10) == 0) curSize = BitConverter.ToInt64(b, o + a + 0x30);
                }
                a += len;
            }
            return true;
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

        // Possible timestomping: SI Created more than 1 s before FN Created, or SI
        // Created and Modified on whole seconds while FN Created is not
        static string TimestompReason(long created, long modified, long fnCreatedTime)
        {
            if (!IsValidTime(created) || !IsValidTime(fnCreatedTime)) return null;
            string reason = null;
            if (created < fnCreatedTime - TicksPerSecond) reason = "SI Created is more than 1 s earlier than FN Created";
            if (created % TicksPerSecond == 0 && IsValidTime(modified) && modified % TicksPerSecond == 0 && fnCreatedTime % TicksPerSecond != 0)
            {
                const string wholeSeconds = "SI Created and Modified have no sub-second part but FN Created has one";
                reason = reason == null ? wholeSeconds : reason + "; " + wholeSeconds;
            }
            return reason == null ? null : "possible timestomping: " + reason;
        }

        static void AppendTime(StringBuilder sb, string label, long fileTime)
        {
            if (!IsValidTime(fileTime)) return;
            sb.Append(" | ").Append(label).Append('=').Append(DateTime.FromFileTimeUtc(fileTime).ToString(TimeFormat, Inv));
        }

        string Details(int r, bool createdRow, string stomp)
        {
            StringBuilder sb = new StringBuilder(256);
            sb.Append("MftRecord=").Append(r.ToString(Inv)).Append(" | Seq=").Append(seq[r].ToString(Inv));
            if ((state[r] & StDir) == 0 && dataSize[r] >= 0) sb.Append(" | Size=").Append(dataSize[r].ToString(Inv));
            if (createdRow) AppendTime(sb, "SI.Modified", siModified[r]);
            else AppendTime(sb, "SI.Created", siCreated[r]);
            AppendTime(sb, "SI.MftChanged", siChanged[r]);
            AppendTime(sb, "SI.Accessed", siAccessed[r]);
            AppendTime(sb, "FN.Created", fnCreated[r]);
            if (stomp != null) sb.Append(" | Timestomp=").Append(stomp);
            return sb.ToString();
        }

        void AddRow(long fileTime, string description, string user, string details)
        {
            MftRow row = new MftRow();
            row.Time = DateTime.FromFileTimeUtc(fileTime);
            row.Description = description;
            row.User = user;
            row.Details = details;
            result.Rows.Add(row);
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
                if ((st & StValid) == 0 || (st & StHasSI) == 0) continue;
                long created = siCreated[r];
                long modified = siModified[r];
                string stomp = TimestompReason(created, modified, fnCreated[r]);
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
                if (!createdRow && !modifiedRow) continue;

                string path = FullPath(r);
                if (path.StartsWith(OrphanPrefix, StringComparison.Ordinal)) result.OrphanPaths++;
                bool isDir = (st & StDir) != 0;
                string noun;
                if ((st & StInUse) == 0) noun = isDir ? "Deleted folder" : "Deleted file";
                else noun = isDir ? "Folder" : "File";
                string marker = stomp != null ? " [SI<FN]" : "";
                string user = UserFromPath(path);
                if (createdRow) AddRow(created, noun + " created: " + path + marker, user, Details(r, true, stomp));
                if (modifiedRow) AddRow(modified, noun + " modified: " + path + marker, user, Details(r, false, stomp));
                if (stomp != null) result.TimestompRows += (createdRow ? 1 : 0) + (modifiedRow ? 1 : 0);
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
    foreach ($row in $mftResult.Rows) {
        Add-TimelineEntry -Timestamp $row.Time -Source "MFT" -EventType "FileAccess" `
            -Description $row.Description -User $row.User -Details $row.Details `
            -Artifact "FileSystem" -RawPath $rawPath
    }
    $added = $script:timelineEntries.Count - $before
    $summary = "  Added $added row(s); $($mftResult.OutsideWindow) time(s) outside the window skipped"
    if ($mftResult.Rows.Count -gt $added) { $summary += "; $($mftResult.Rows.Count - $added) row(s) dropped by -StartDate/-EndDate or dated before 1980" }
    Log "$summary."
    if ($mftResult.TimestompRecords -gt 0) {
        Log "  $($mftResult.TimestompRecords) record(s) flagged [SI<FN] (possible timestomping; see Details): $($mftResult.TimestompRows) row(s), $($mftResult.KeptForTimestomp) of them outside the window."
    }
    if ($mftResult.OrphanPaths -gt 0) {
        Log "  $($mftResult.OrphanPaths) record(s) with rows have a missing or reused parent folder (path starts with <orphan>)."
    }
    Log "  `$MFT done in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) s."
}

function Parse-FileSystem {
    Log "--- Parsing File System Metadata ---"

    # Raw $MFT from newer collectors (FileSystem\$MFT). -Force: a copy may keep
    # the Hidden/System attributes of the original.
    $mftFiles = @(Get-ChildItem -Path $InputPath -Filter '$MFT' -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq '$MFT' })
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
    $usbCsvFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("usb_storage_devices.csv")
    foreach ($csvFile in $usbCsvFiles) {
        Log "  Parsing: $($csvFile.FullName)"
        try {
            $rows = @(Import-Csv -Path $csvFile.FullName -ErrorAction Stop)
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

    # Mounted devices (state at collection time)
    $mountedFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("mounted_devices.txt")
    foreach ($mountFile in $mountedFiles) {
        Log "  Parsing: $($mountFile.FullName)"
        try {
            $ts = Get-SnapshotTimeUtc -File $mountFile
            $content = Get-Content -Path $mountFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($ts -and $line -match '(\\DosDevices\\[A-Z]:|\\\?\?\\Volume\{)') {
                    Add-TimelineEntry -Timestamp $ts -Source "USB-MountedDevices" -EventType "Snapshot" `
                        -Description "Mounted device: $($line.Trim() -replace '\s{2,}', ' ')" `
                        -Artifact "USB" -RawPath $mountFile.FullName
                    $usbParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse mounted devices: $($_.Exception.Message)" }
    }

    # SetupAPI device logs (device first-install times). Windows rotates setupapi.dev.log
    # to setupapi.dev.<yyyymmdd_hhmmss>.log, so every setupapi.dev*.log is parsed.
    # Times are the examined system's local time.
    $setupApiFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("setupapi.dev*.log") |
        Where-Object { $_.Name -like "setupapi.dev*.log" } | Sort-Object FullName -Unique)
    $seenSetupApi = @{}
    $sectionFormats = [string[]]@("yyyy/MM/dd HH:mm:ss.fff", "yyyy/MM/dd HH:mm:ss")
    foreach ($logFile2 in $setupApiFiles) {
        Log "  Parsing: $($logFile2.FullName)"
        try {
            $content = [System.IO.File]::ReadAllLines($logFile2.FullName)
            $count = 0
            $dupes = 0
            for ($i = 0; $i -lt $content.Length; $i++) {
                $line = $content[$i]
                if (-not $line.StartsWith(">>>")) { continue }
                # e.g. ">>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_...\SERIAL&0]"
                if ($line -notmatch '^>>>\s+\[(Device Install \(([^)]*)\)|Delete Device) - (.+)\]\s*$') { continue }
                $isDelete = $Matches[1] -eq "Delete Device"
                $trigger = $Matches[2]
                $instance = $Matches[3].Trim()
                # Deletions are only interesting for USB devices
                if ($isDelete -and $instance -notmatch '(?i)USBSTOR|^USB\\|VID_[0-9A-F]{4}') { continue }

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
                Add-TimelineEntry -Timestamp $ts -Source "USB-SetupAPI" -EventType "USBDevice" `
                    -Description $desc `
                    -Details $details `
                    -Artifact "USB" -RawPath $logFile2.FullName
                $usbParsed = $true
                $count++
            }
            Log "  Parsed $count SetupAPI device event(s) ($dupes duplicate(s) from other log files skipped)."
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
            # Copy hive + transaction logs to a temp dir so reg load can replay
            # dirty hive logs automatically (fixes "registry database is corrupt")
            $tempHiveDir = Join-Path $env:TEMP "AmcacheRepair_$(Get-Random)"
            New-Item -ItemType Directory -Path $tempHiveDir -Force | Out-Null

            $srcDir = Split-Path $amcache.FullName -Parent
            $tempHive = Join-Path $tempHiveDir "Amcache.hve"
            Copy-Item -Path $amcache.FullName -Destination $tempHive -Force

            # Copy transaction logs if they exist (enables dirty hive recovery)
            $logsCopied = 0
            foreach ($logExt in @(".LOG1", ".LOG2")) {
                $logSrc = Join-Path $srcDir "Amcache.hve${logExt}"
                if (Test-Path $logSrc) {
                    Copy-Item -Path $logSrc -Destination (Join-Path $tempHiveDir "Amcache.hve${logExt}") -Force
                    $logsCopied++
                }
            }

            if ($logsCopied -gt 0) {
                Log "  Copied hive + $logsCopied transaction log(s) to temp for recovery"
            }

            Log "  Loading Amcache hive: $tempHive"
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
                Log-Warning "  Could not load Amcache hive: $(($regLoadResult | Out-String).Trim()) -- No Amcache data available."
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
                if ($unloaded) { Log "  Unloaded Amcache hive." }
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
                if ($swMount -and $swMount.Root) { $sidNames = Get-ProfileListMap $swMount.Root }
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
                    # The time is the file's last-modified time, not when it ran
                    Add-TimelineEntry -Timestamp $e.LastModifiedUtc -Source "AppCompatCache" -EventType "Execution" `
                        -Description "ShimCache entry: $entryName" `
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
# Memory dump for this collection: the collector saves it next to the zip
# (<zip name>_memory_dump.dmp / .raw) because it is too large to zip.
# DumpIt writes Microsoft crash dumps (.dmp); WinPmem and Magnet RAM
# Capture write raw images (.raw). Returns the full path or $null.
function Find-MemoryDump {
    $extensions = @("dmp", "raw")

    # Check 1: Sibling of the selected zip (browse mode)
    if ($script:selectedZipPath -and (Test-Path -LiteralPath $script:selectedZipPath)) {
        $zipDir = Split-Path $script:selectedZipPath -Parent
        $zipBaseName = [System.IO.Path]::GetFileNameWithoutExtension($script:selectedZipPath)
        foreach ($ext in $extensions) {
            $siblingDump = Join-Path $zipDir "${zipBaseName}_memory_dump.$ext"
            if (Test-Path -LiteralPath $siblingDump) { return $siblingDump }
        }
    }

    # Check 2: Inside the collection directory (uncompressed collections)
    $memFiles = @(Find-ArtifactFiles -BasePath $InputPath -FileNames @("memory_dump.dmp", "memory_dump.raw", "memdump.raw", "memory.raw", "physmem.raw"))
    if ($memFiles.Count -gt 0) { return $memFiles[0].FullName }

    # Check 3: Alongside the InputPath directory
    $parentDir = Split-Path $InputPath -Parent
    foreach ($ext in $extensions) {
        $dumpFiles = @(Get-ChildItem -LiteralPath $parentDir -Filter "*_memory_dump.$ext" -File -ErrorAction SilentlyContinue)
        if ($dumpFiles.Count -gt 0) { return $dumpFiles[0].FullName }
    }
    return $null
}

# CPU architecture of a Microsoft crash dump from its header ("PAGEDU64":
# machine type at 0x30; "PAGEDUMP": 32-bit x86). "Raw" for raw images,
# "Unknown" if the header can't be read.
function Get-MemoryDumpArchitecture {
    param([string]$Path)
    $header = New-Object byte[] 0x40
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try { $read = $stream.Read($header, 0, $header.Length) } finally { $stream.Dispose() }
    }
    catch {
        Write-Verbose "Could not read memory dump header of ${Path}: $($_.Exception.Message)"
        return "Unknown"
    }
    if ($read -lt $header.Length) { return "Unknown" }
    $signature = [System.Text.Encoding]::ASCII.GetString($header, 0, 8)
    if ($signature -eq "PAGEDUMP") { return "x86" }
    if ($signature -ne "PAGEDU64") { return "Raw" }
    switch ([BitConverter]::ToUInt32($header, 0x30)) {
        0x8664 { return "x64" }
        0xAA64 { return "ARM64" }
        default { return "Unknown" }
    }
}

function Parse-Memory {
    Log "--- Parsing Memory Dump (Volatility 3) ---"

    $memParsed = $false

    # --- Find the memory dump file ---
    $dumpPath = Find-MemoryDump

    if (-not $dumpPath) {
        Log-Warning "No memory dump found in collection or alongside zip."
        Log "  Memory parsing complete."
        Log ""
        return
    }

    $dumpSizeGB = [math]::Round((Get-Item -LiteralPath $dumpPath).Length / 1GB, 2)
    $dumpArch = Get-MemoryDumpArchitecture -Path $dumpPath
    Log "  Found memory dump: $dumpPath ($dumpSizeGB GB, $dumpArch)"

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
    $volExe = $null
    $volLocations = @(
        (Join-Path $PSScriptRoot "tools\volatility3\vol.exe"),
        (Join-Path $PSScriptRoot "tools\volatility3\volatility3.exe"),
        (Join-Path $PSScriptRoot "tools\vol.exe"),
        (Join-Path $PSScriptRoot "vol.exe")
    )
    foreach ($loc in $volLocations) {
        if (Test-Path $loc) { $volExe = $loc; break }
    }

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
    $plugins = @(
        @{ Name = "windows.pslist";  EventType = "ProcessCreation";   Source = "Memory-Processes";   Desc = "Running processes" },
        @{ Name = "windows.netscan"; EventType = "NetworkConnection"; Source = "Memory-Network";     Desc = "Network connections" },
        @{ Name = "windows.cmdline"; EventType = "Execution";         Source = "Memory-CommandLine"; Desc = "Process command lines" },
        @{ Name = "windows.svcscan"; EventType = "ServiceChange";     Source = "Memory-Services";    Desc = "Windows services" }
    )

    $dumpTimestamp = (Get-Item $dumpPath).LastWriteTimeUtc
    $totalMemEntries = 0

    foreach ($plugin in $plugins) {
        $pluginTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Log "  Running $($plugin.Name) ($($plugin.Desc))..."

        $jsonFile = Join-Path $env:TEMP "vol3_$($plugin.Name -replace '\.','_')_$(Get-Random).json"
        $errFile = Join-Path $env:TEMP "vol3_$($plugin.Name -replace '\.','_')_err.txt"

        try {
            # Run Volatility 3 with JSON output
            & $volExe -f $dumpPath -r json $plugin.Name 2>$errFile | Out-File $jsonFile -Encoding utf8

            if (-not (Test-Path $jsonFile) -or (Get-Item $jsonFile).Length -eq 0) {
                $errContent = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { "No output" }
                Log-Warning "    $($plugin.Name) produced no output. Error: $($errContent.Substring(0, [Math]::Min(200, $errContent.Length)))"
                continue
            }

            $jsonContent = Get-Content $jsonFile -Raw -ErrorAction Stop
            $entries = $jsonContent | ConvertFrom-Json -ErrorAction Stop
            $pluginCount = 0

            foreach ($entry in $entries) {
                $ts = $dumpTimestamp  # default timestamp

                switch ($plugin.Name) {
                    "windows.pslist" {
                        # Parse CreateTime if available
                        if ($entry.CreateTime -and $entry.CreateTime -ne "N/A" -and $entry.CreateTime -notmatch "^0") {
                            try { $ts = [datetime]::Parse($entry.CreateTime) }
                            catch { Write-Verbose "Could not parse CreateTime '$($entry.CreateTime)', using dump time: $($_.Exception.Message)" }
                        }
                        $procId = if ($entry.PID) { $entry.PID } else { "" }
                        $ppid = if ($entry.PPID) { $entry.PPID } else { "" }
                        $name = if ($entry.ImageFileName) { $entry.ImageFileName } else { "Unknown" }
                        $threads = if ($entry.Threads) { $entry.Threads } else { "" }
                        $session = if ($entry.SessionId) { $entry.SessionId } else { "" }

                        Add-TimelineEntry -Timestamp $ts -Source $plugin.Source -EventType $plugin.EventType `
                            -Description "Process in memory: $name (PID: $procId, PPID: $ppid)" `
                            -Details "Threads=$threads SessionId=$session" `
                            -Artifact "MemoryDump" -RawPath $dumpPath
                        $pluginCount++
                    }
                    "windows.netscan" {
                        if ($entry.Created -and $entry.Created -ne "N/A" -and $entry.Created -notmatch "^0") {
                            try { $ts = [datetime]::Parse($entry.Created) }
                            catch { Write-Verbose "Could not parse Created '$($entry.Created)', using dump time: $($_.Exception.Message)" }
                        }
                        $proto = if ($entry.Proto) { $entry.Proto } else { "" }
                        $localAddr = if ($entry.LocalAddr) { "$($entry.LocalAddr):$($entry.LocalPort)" } else { "" }
                        $foreignAddr = if ($entry.ForeignAddr) { "$($entry.ForeignAddr):$($entry.ForeignPort)" } else { "" }
                        $state = if ($entry.State) { $entry.State } else { "" }
                        $procId = if ($entry.PID) { $entry.PID } else { "" }
                        $owner = if ($entry.Owner) { $entry.Owner } else { "" }

                        Add-TimelineEntry -Timestamp $ts -Source $plugin.Source -EventType $plugin.EventType `
                            -Description "Memory network: $proto $localAddr -> $foreignAddr ($state)" `
                            -User $owner -Details "PID=$procId" `
                            -Artifact "MemoryDump" -RawPath $dumpPath
                        $pluginCount++
                    }
                    "windows.cmdline" {
                        $procId = if ($entry.PID) { $entry.PID } else { "" }
                        $procName = if ($entry.Process) { $entry.Process } else { "" }
                        $cmdArgs = if ($entry.Args) { $entry.Args } else { "" }
                        if (-not $cmdArgs -or $cmdArgs -eq "N/A") { continue }

                        Add-TimelineEntry -Timestamp $ts -Source $plugin.Source -EventType $plugin.EventType `
                            -Description "Process command line: $procName (PID: $procId)" `
                            -Details "Args=$cmdArgs" `
                            -Artifact "MemoryDump" -RawPath $dumpPath
                        $pluginCount++
                    }
                    "windows.svcscan" {
                        $svcName = if ($entry.Name) { $entry.Name } else { "" }
                        $display = if ($entry.Display) { $entry.Display } else { $svcName }
                        $binary = if ($entry.Binary) { $entry.Binary } else { "" }
                        $state = if ($entry.State) { $entry.State } else { "" }
                        $start = if ($entry.Start) { $entry.Start } else { "" }
                        $procId = if ($entry.PID) { $entry.PID } else { "" }

                        Add-TimelineEntry -Timestamp $ts -Source $plugin.Source -EventType $plugin.EventType `
                            -Description "Service in memory: $display ($svcName)" `
                            -Details "State=$state StartType=$start Binary=$binary PID=$procId" `
                            -Artifact "MemoryDump" -RawPath $dumpPath
                        $pluginCount++
                    }
                }
            }

            $pluginTimer.Stop()
            $elapsed = [math]::Round($pluginTimer.Elapsed.TotalSeconds, 1)
            Log "    $($plugin.Name): $pluginCount entries ($elapsed seconds)"
            $totalMemEntries += $pluginCount
            $memParsed = $true
        }
        catch {
            Log-Warning "    $($plugin.Name) failed: $($_.Exception.Message)"
        }
        finally {
            Remove-Item $jsonFile -Force -ErrorAction SilentlyContinue
            Remove-Item $errFile -Force -ErrorAction SilentlyContinue
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
function Parse-SystemInfo {
    Log "--- Parsing System Info ---"
    Log "  System info parsing complete."
    Log ""
}

# =============================================================
# Auto-detect memory dump and prompt for analysis
# =============================================================
if ($Sources -notcontains "Memory") {
    # Check if a memory dump exists alongside the collection
    $detectedDump = Find-MemoryDump
    if ($detectedDump -and (Get-MemoryDumpArchitecture -Path $detectedDump) -eq "ARM64") {
        # Volatility 3 cannot analyze Windows ARM64 memory: don't offer it
        Log ""
        Log "Memory dump detected: $(Split-Path $detectedDump -Leaf) (Windows ARM64)."
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
            $dumpSizeGB = [math]::Round((Get-Item $detectedDump).Length / 1GB, 2)
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Memory Dump Detected" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Found: $(Split-Path $detectedDump -Leaf) ($dumpSizeGB GB)" -ForegroundColor Green
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
            Log "Memory dump detected but Volatility 3 not found in tools\ directory."
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
if ($Sources -contains "Memory")           { Parse-Memory }

# =============================================================
# Post-Processing: Deduplicate, Sort, Keyword Flag
# =============================================================
Log "--- Post-Processing Timeline ---"

$entryCount = $script:timelineEntries.Count
Log "  Raw entries collected: $entryCount"

if ($entryCount -eq 0) {
    Log-Warning "No timeline entries were collected. Check input path and selected sources."
    Log "=== Timeline Builder Finished (no output generated) ==="
    exit 0
}

# Deduplicate: an entry is a duplicate only if Timestamp, Source, EventType,
# Description, User and Details are all identical (case-sensitive). The first
# occurrence is kept. A HashSet keeps this fast on very large timelines.
Log "  Deduplicating..."
$dedupKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$deduped = [System.Collections.Generic.List[object]]::new($entryCount)
foreach ($entry in $script:timelineEntries) {
    # NUL separator: cannot occur in the values (removed by Add-TimelineEntry)
    $dedupKey = [string]$entry.Timestamp + "`0" + $entry.Source + "`0" + $entry.EventType + "`0" +
        $entry.Description + "`0" + $entry.User + "`0" + $entry.Details
    if ($dedupKeys.Add($dedupKey)) { $deduped.Add($entry) }
}
$dedupKeys = $null
$dedupedCount = $deduped.Count
$removedCount = $entryCount - $dedupedCount
Log "  Removed $removedCount duplicate(s). Unique entries: $dedupedCount"

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
if ($dedupedCount -gt $excelMaxDataRows) {
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
        Log "    Yellow       ServiceChange        -- service state changes"
        Log "    Yellow       ScheduledTaskChange  -- task scheduler changes"
        Log "    Purple       USBDevice            -- USB device connections"
        Log "    Light Blue   Installation         -- application installs"
        Log "    Light gray   Snapshot             -- state at collection time, not an event"
    }
    catch {
        Log-Warning "  Failed to generate Excel file: $($_.Exception.Message)"
        Log "  CSV is still available: $OutputFile"
    }
}

# =============================================================
# Summary Statistics
# =============================================================
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

# Per-source breakdown
Log "  Events by artifact source:"
foreach ($artifact in ($script:artifactStats.GetEnumerator() | Sort-Object Value -Descending)) {
    Log "    $($artifact.Key.PadRight(25)) : $($artifact.Value)"
}

if ($Keywords -and $Keywords.Count -gt 0) {
    Log ""
    Log "  Keyword-flagged  : $flaggedCount entries"
}

Log ""
Log "============================================================="
Log "=== Timeline Builder Completed Successfully ==="
Log ""
Log "============================================================="

# --- Let user choose how to view the timeline ---
Log ""
Log "  Output files:"
Log "    CSV: $OutputFile"
if ($xlsxGenerated) { Log "    Excel (color-coded): $xlsxFile" }
Log ""

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

# Cleanup: remove temp extraction directory from browse mode
if ($script:browseExtractDir -and (Test-Path $script:browseExtractDir)) {
    Log ""
    Log "Cleaning up temp extraction: $($script:browseExtractDir)"
    # Marker first: if the folder can't be fully removed, the next run re-extracts
    Remove-Item -LiteralPath "$($script:browseExtractDir).complete" -Force -ErrorAction SilentlyContinue
    # Give any lingering file handles time to release (e.g., reg unload)
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    $cleaned = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Remove-Item -Path $script:browseExtractDir -Recurse -Force -ErrorAction Stop
            Log "  Temp folder removed."
            $cleaned = $true
            break
        }
        catch {
            if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
        }
    }
    if (-not $cleaned) {
        Log-Warning "  Could not remove temp folder (file in use)."
        Log-Warning "  You can manually delete: $($script:browseExtractDir)"
    }
}
