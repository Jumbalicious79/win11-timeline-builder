# =============================================================
# Windows 11 Forensic Timeline Builder
# Builds a unified chronological CSV timeline from forensic
# artifacts collected by triage-collector.ps1 or manually.
# Pure PowerShell alternative to log2timeline/plaso.
# Use Run-TimelineBuilder.bat to launch (handles elevation + policy)
# =============================================================

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

    [Parameter(Mandatory = $false)]
    [ValidateSet("EventLogs", "Prefetch", "RecentFiles", "Registry", "FileSystem", "Browser", "ScheduledTasks", "Services", "Network", "USB", "Persistence", "UsnJournal", "Amcache", "PowerShellHistory", "Memory")]
    [string[]]$Sources = @("EventLogs", "Prefetch", "RecentFiles", "Registry", "FileSystem", "Browser", "ScheduledTasks", "Services", "Network", "USB", "Persistence", "UsnJournal", "Amcache", "PowerShellHistory"),

    [Parameter(Mandatory = $false)]
    [string[]]$Keywords
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
    # (the iCloud path is already very deep)
    $script:browseExtractDir = Join-Path $env:TEMP ("TriageExtract_" + $selectedZip.BaseName)
    $extractDir = $script:browseExtractDir

    if (Test-Path $extractDir) {
        Write-Host "Using existing extracted folder: $extractDir" -ForegroundColor Cyan
    } else {
        Write-Host "Extracting $($selectedZip.Name) to temp..." -ForegroundColor Cyan
        try {
            Expand-Archive -Path $selectedZip.FullName -DestinationPath $extractDir -Force -ErrorAction Stop
            Write-Host "Extracted to: $extractDir" -ForegroundColor Green
        } catch {
            Write-Host "ERROR: Failed to extract zip: $_" -ForegroundColor Red
            pause
            exit 1
        }
    }

    # The extracted folder may contain a single subfolder — find the actual collection root
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

    # Sanitize strings: remove XML-invalid control characters (0x00-0x08, 0x0B-0x0C, 0x0E-0x1F)
    # These cause "Repaired Records" errors when Excel opens the .xlsx
    $xmlClean = '[^\x09\x0A\x0D\x20-\xFFFF]'
    $Description = [regex]::Replace($Description, $xmlClean, '')
    $Details     = [regex]::Replace($Details, $xmlClean, '')
    $User        = [regex]::Replace($User, $xmlClean, '')
    $Source      = [regex]::Replace($Source, $xmlClean, '')
    $RawPath     = [regex]::Replace($RawPath, $xmlClean, '')

    $entry = [PSCustomObject]@{
        Timestamp   = $utcTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
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

# ----------------------------------------------------------
# 1. Event Log Parser
# ----------------------------------------------------------
function Parse-EventLogs {
    Log "--- Parsing Event Logs ---"
    $evtxFiles = Find-ArtifactFiles -BasePath $InputPath -Extensions @(".evtx")

    if ($evtxFiles.Count -eq 0) {
        Log-Warning "No event log files found. Skipping event log parsing."
        return
    }

    Log "Found $($evtxFiles.Count) event log file(s)"

    foreach ($evtxFile in $evtxFiles) {
        $fileName = $evtxFile.Name
        $filePath = $evtxFile.FullName
        Log "  Parsing: $fileName"

        try {
            # Determine which events to look for based on the log name
            $filterXml = $null
            $events = @()

            # Security log events
            if ($fileName -match "Security") {
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
            if ($fileName -match "System") {
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
            if ($fileName -match "PowerShell") {
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
            if ($fileName -match "Sysmon") {
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
            if ($fileName -match "TaskScheduler") {
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

        }
        catch {
            Log-Warning "  Failed to parse $fileName : $($_.Exception.Message)"
        }
    }

    Log "  Event log parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 2. Prefetch Parser
# ----------------------------------------------------------
function Parse-Prefetch {
    Log "--- Parsing Prefetch Files ---"

    # Look for prefetch files in input path or standard Windows location
    $pfFiles = Find-ArtifactFiles -BasePath $InputPath -Extensions @(".pf")

    if ($pfFiles.Count -eq 0) {
        Log-Warning "No prefetch files found. Skipping prefetch parsing."
        return
    }

    Log "Found $($pfFiles.Count) prefetch file(s)"

    foreach ($pf in $pfFiles) {
        try {
            # Extract executable name from prefetch filename
            # Format: EXECUTABLENAME-HASH.pf
            $pfName = $pf.BaseName
            $exeName = $pfName
            if ($pfName -match '^(.+)-[A-F0-9]{8}$') {
                $exeName = $Matches[1]
            }

            # Creation time = first known execution, Modification time = last execution
            Add-TimelineEntry -Timestamp $pf.CreationTimeUtc -Source "Prefetch" -EventType "Execution" `
                -Description "Prefetch first execution: $exeName" `
                -Details "PrefetchFile=$($pf.Name) Size=$($pf.Length)" `
                -Artifact "Prefetch" -RawPath $pf.FullName

            Add-TimelineEntry -Timestamp $pf.LastWriteTimeUtc -Source "Prefetch" -EventType "Execution" `
                -Description "Prefetch last execution: $exeName" `
                -Details "PrefetchFile=$($pf.Name) Size=$($pf.Length)" `
                -Artifact "Prefetch" -RawPath $pf.FullName
        }
        catch {
            Log-Warning "  Failed to parse prefetch file $($pf.Name) : $($_.Exception.Message)"
        }
    }

    Log "  Prefetch parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 3. Recent Files (LNK) Parser
# ----------------------------------------------------------
function Parse-RecentFiles {
    Log "--- Parsing Recent Files (LNK Shortcuts) ---"

    $lnkFiles = Find-ArtifactFiles -BasePath $InputPath -Extensions @(".lnk")

    if ($lnkFiles.Count -eq 0) {
        # Check standard Recent locations for all user profiles
        $recentPaths = @()
        $recentPaths += "$env:APPDATA\Microsoft\Windows\Recent"
        # Also check other user profiles
        Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Recent"
            if (Test-Path $p) { $recentPaths += $p }
        }

        foreach ($rp in $recentPaths) {
            $lnkFiles += Get-ChildItem -Path $rp -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
        }
    }

    if ($lnkFiles.Count -eq 0) {
        Log-Warning "No .lnk files found. Skipping recent files parsing."
        return
    }

    Log "Found $($lnkFiles.Count) LNK file(s)"

    $shell = New-Object -ComObject WScript.Shell

    foreach ($lnk in $lnkFiles) {
        try {
            $shortcut = $shell.CreateShortcut($lnk.FullName)
            $targetPath = $shortcut.TargetPath
            $arguments = $shortcut.Arguments
            $workDir = $shortcut.WorkingDirectory

            # Determine user from path
            $user = ""
            if ($lnk.FullName -match "C:\\Users\\([^\\]+)\\") {
                $user = $Matches[1]
            }

            Add-TimelineEntry -Timestamp $lnk.CreationTimeUtc -Source "RecentFiles" -EventType "FileAccess" `
                -Description "LNK created: $($lnk.BaseName) -> $targetPath" `
                -User $user `
                -Details "Target=$targetPath Args=$arguments WorkDir=$workDir" `
                -Artifact "RecentFiles" -RawPath $lnk.FullName

            Add-TimelineEntry -Timestamp $lnk.LastWriteTimeUtc -Source "RecentFiles" -EventType "FileAccess" `
                -Description "LNK modified: $($lnk.BaseName) -> $targetPath" `
                -User $user `
                -Details "Target=$targetPath Args=$arguments WorkDir=$workDir" `
                -Artifact "RecentFiles" -RawPath $lnk.FullName

            # Release COM object reference for this shortcut
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
        }
        catch {
            Log-Warning "  Failed to parse LNK file $($lnk.Name) : $($_.Exception.Message)"
        }
    }

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    Log "  Recent files parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 4. Registry Parser
# ----------------------------------------------------------
function Parse-Registry {
    Log "--- Parsing Registry Artifacts ---"

    $registryParsed = $false
    $hivesLoaded = @()

    # Try to find offline registry hives in the input path
    $ntUserFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("NTUSER.DAT")
    $samFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("SAM")
    $systemFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("SYSTEM")
    $softwareFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("SOFTWARE")

    # Parse NTUSER.DAT hives (RecentDocs, RunMRU, TypedPaths, TypedURLs, UserAssist)
    foreach ($ntuser in $ntUserFiles) {
        $hiveName = "TEMP_TL_$(Get-Random)"
        $hivePath = "HKLM:\$hiveName"
        $loaded = $false

        try {
            Log "  Loading hive: $($ntuser.FullName)"
            $regLoadResult = & reg load "HKLM\$hiveName" $ntuser.FullName 2>&1
            if ($LASTEXITCODE -eq 0) {
                $loaded = $true
                $hivesLoaded += $hiveName

                # Determine user from path
                $user = ""
                if ($ntuser.FullName -match "Users\\([^\\]+)\\") {
                    $user = $Matches[1]
                }

                # Use .NET RegistryKey directly (not PowerShell provider) so we can
                # explicitly Close/Dispose every handle — prevents hive unload failures
                $hiveRoot = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($hiveName)
                if ($hiveRoot) {

                # --- TypedPaths (Explorer address bar) ---
                try {
                    $typedPathsKey = $hiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
                    if ($typedPathsKey) {
                        foreach ($val in $typedPathsKey.GetValueNames()) {
                            if ($val -ne "") {
                                $typedPath = $typedPathsKey.GetValue($val)
                                Add-TimelineEntry -Timestamp $ntuser.LastWriteTimeUtc -Source "Registry-TypedPaths" -EventType "FileAccess" `
                                    -Description "Explorer typed path: $typedPath" `
                                    -User $user -Details "ValueName=$val" `
                                    -Artifact "Registry" -RawPath $ntuser.FullName
                            }
                        }
                        $typedPathsKey.Close(); $typedPathsKey.Dispose()
                        $registryParsed = $true
                    }
                }
                catch { Log-Warning "    Failed to parse TypedPaths: $($_.Exception.Message)" }

                # --- TypedURLs ---
                try {
                    $typedUrlsKey = $hiveRoot.OpenSubKey("Software\Microsoft\Internet Explorer\TypedURLs")
                    if ($typedUrlsKey) {
                        foreach ($val in $typedUrlsKey.GetValueNames()) {
                            if ($val -ne "") {
                                $url = $typedUrlsKey.GetValue($val)
                                Add-TimelineEntry -Timestamp $ntuser.LastWriteTimeUtc -Source "Registry-TypedURLs" -EventType "NetworkConnection" `
                                    -Description "IE typed URL: $url" `
                                    -User $user -Details "ValueName=$val" `
                                    -Artifact "Registry" -RawPath $ntuser.FullName
                            }
                        }
                        $typedUrlsKey.Close(); $typedUrlsKey.Dispose()
                        $registryParsed = $true
                    }
                }
                catch { Log-Warning "    Failed to parse TypedURLs: $($_.Exception.Message)" }

                # --- RunMRU ---
                try {
                    $runMruKey = $hiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
                    if ($runMruKey) {
                        foreach ($val in $runMruKey.GetValueNames()) {
                            if ($val -ne "" -and $val -ne "MRUList") {
                                $cmd = $runMruKey.GetValue($val)
                                Add-TimelineEntry -Timestamp $ntuser.LastWriteTimeUtc -Source "Registry-RunMRU" -EventType "Execution" `
                                    -Description "Run dialog command: $cmd" `
                                    -User $user -Details "MRUEntry=$val" `
                                    -Artifact "Registry" -RawPath $ntuser.FullName
                            }
                        }
                        $runMruKey.Close(); $runMruKey.Dispose()
                        $registryParsed = $true
                    }
                }
                catch { Log-Warning "    Failed to parse RunMRU: $($_.Exception.Message)" }

                # --- UserAssist (ROT13 decoded) ---
                try {
                    $userAssistKey = $hiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
                    if ($userAssistKey) {
                        foreach ($guidName in $userAssistKey.GetSubKeyNames()) {
                            $guidKey = $userAssistKey.OpenSubKey($guidName)
                            $countKey = $guidKey.OpenSubKey("Count")
                            if ($countKey) {
                                foreach ($val in $countKey.GetValueNames()) {
                                    if ($val -ne "") {
                                        # ROT13 decode the value name
                                        $decoded = $val -replace '[a-zA-Z]', {
                                            $c = [char]$_.Value
                                            $base = if ($c -cmatch '[a-z]') { [int][char]'a' } else { [int][char]'A' }
                                            [char](($([int]$c - $base + 13) % 26) + $base)
                                        }

                                        # Parse the binary data for run count and last run time
                                        $data = $countKey.GetValue($val)
                                        $runCount = 0
                                        $lastRun = [datetime]::MinValue
                                        if ($data -is [byte[]] -and $data.Length -ge 72) {
                                            $runCount = [BitConverter]::ToInt32($data, 4)
                                            $fileTime = [BitConverter]::ToInt64($data, 60)
                                            if ($fileTime -gt 0) {
                                                try { $lastRun = [datetime]::FromFileTimeUtc($fileTime) } catch {}
                                            }
                                        }

                                        if ($lastRun -gt [datetime]::MinValue) {
                                            Add-TimelineEntry -Timestamp $lastRun -Source "Registry-UserAssist" -EventType "Execution" `
                                                -Description "UserAssist execution: $decoded" `
                                                -User $user -Details "RunCount=$runCount GUID=$guidName" `
                                                -Artifact "Registry" -RawPath $ntuser.FullName
                                        }
                                    }
                                }
                                $countKey.Close(); $countKey.Dispose()
                            }
                            $guidKey.Close(); $guidKey.Dispose()
                        }
                        $userAssistKey.Close(); $userAssistKey.Dispose()
                        $registryParsed = $true
                    }
                }
                catch { Log-Warning "    Failed to parse UserAssist: $($_.Exception.Message)" }

                # --- RecentDocs ---
                try {
                    $recentDocsKey = $hiveRoot.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
                    if ($recentDocsKey) {
                        foreach ($val in $recentDocsKey.GetValueNames()) {
                            if ($val -ne "" -and $val -ne "MRUListEx") {
                                $data = $recentDocsKey.GetValue($val)
                                if ($data -is [byte[]]) {
                                    # Extract unicode string from the binary data
                                    $nullIndex = 0
                                    for ($i = 0; $i -lt $data.Length - 1; $i += 2) {
                                        if ($data[$i] -eq 0 -and $data[$i + 1] -eq 0) {
                                            $nullIndex = $i
                                            break
                                        }
                                    }
                                    if ($nullIndex -gt 0) {
                                        $docName = [System.Text.Encoding]::Unicode.GetString($data, 0, $nullIndex)
                                        Add-TimelineEntry -Timestamp $ntuser.LastWriteTimeUtc -Source "Registry-RecentDocs" -EventType "FileAccess" `
                                            -Description "Recent document: $docName" `
                                            -User $user -Details "MRUIndex=$val" `
                                            -Artifact "Registry" -RawPath $ntuser.FullName
                                    }
                                }
                            }
                        }
                        $recentDocsKey.Close(); $recentDocsKey.Dispose()
                        $registryParsed = $true
                    }
                }
                catch { Log-Warning "    Failed to parse RecentDocs: $($_.Exception.Message)" }

                # Close the root handle
                $hiveRoot.Close(); $hiveRoot.Dispose()
                }
            }
            else {
                Log-Warning "  Could not load hive $($ntuser.FullName) : $regLoadResult"
            }
        }
        catch {
            Log-Warning "  Failed to process NTUSER.DAT at $($ntuser.FullName) : $($_.Exception.Message)"
        }
    }

    # BAM/DAM data is parsed from bam_entries.txt in the PowerShell History section

    # Cleanup: Unload any hives we loaded
    foreach ($hiveName in $hivesLoaded) {
        # Force release all PowerShell references to the hive before unloading
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        [gc]::Collect()
        Start-Sleep -Milliseconds 1000
        $unloaded = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $unloadResult = & reg unload "HKLM\$hiveName" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Log "  Unloaded hive: $hiveName"
                $unloaded = $true
                break
            }
            Start-Sleep -Milliseconds 1000
        }
        if (-not $unloaded) {
            Log-Warning "  Failed to unload hive $hiveName -- may need manual cleanup via: reg unload HKLM\$hiveName"
        }
    }

    if (-not $registryParsed) {
        Log-Warning "No registry artifacts found or parseable."
    }
    Log "  Registry parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 5. Browser History Parser
# ----------------------------------------------------------
function Parse-BrowserHistory {
    Log "--- Parsing Browser History ---"

    $browserParsed = $false

    # --- Ensure sqlite3.exe is available (auto-download if needed) ---
    $sqlite3Exe = $null
    $sqlite3Locations = @(
        (Join-Path $PSScriptRoot "tools\sqlite3\sqlite3.exe"),
        (Join-Path $PSScriptRoot "sqlite3.exe"),
        (Join-Path $PSScriptRoot "reports\sqlite3\sqlite3.exe"),
        (Join-Path $env:TEMP "sqlite3_timeline\sqlite3.exe")
    )
    foreach ($loc in $sqlite3Locations) {
        if (Test-Path $loc) { $sqlite3Exe = $loc; break }
    }

    if (-not $sqlite3Exe) {
        Log "  sqlite3.exe not found locally. Downloading from sqlite.org..."
        $sqlite3Dir = Join-Path $PSScriptRoot "tools\sqlite3"
        $sqlite3Zip = Join-Path $env:TEMP "sqlite3_download.zip"
        try {
            $sqliteUrl = "https://www.sqlite.org/2025/sqlite-tools-win-x64-3490100.zip"
            Invoke-WebRequest -Uri $sqliteUrl -OutFile $sqlite3Zip -UseBasicParsing -ErrorAction Stop
            New-Item -ItemType Directory -Path $sqlite3Dir -Force | Out-Null
            Expand-Archive -Path $sqlite3Zip -DestinationPath $sqlite3Dir -Force -ErrorAction Stop
            # The zip may contain a subfolder — find sqlite3.exe
            $found = Get-ChildItem -Path $sqlite3Dir -Filter "sqlite3.exe" -Recurse | Select-Object -First 1
            if ($found) {
                $sqlite3Exe = $found.FullName
                Log-Success "  Downloaded sqlite3.exe to: $sqlite3Exe"
            }
        }
        catch {
            Log-Warning "  Failed to download sqlite3.exe: $($_.Exception.Message)"
            Log-Warning "  Browser history parsing will be skipped."
            Log-Warning "  To fix: manually place sqlite3.exe next to this script."
        }
        finally {
            Remove-Item $sqlite3Zip -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $sqlite3Exe) {
        Log-Warning "  sqlite3.exe not available. Skipping browser parsing."
        Log "  Browser history parsing complete."
        Log ""
        return
    }

    Log "  Using sqlite3: $sqlite3Exe"

    # Find browser history databases
    $chromeHistoryPaths = @()
    $firefoxHistoryPaths = @()

    # Search in input path first
    $historyFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("History", "places.sqlite")
    foreach ($f in $historyFiles) {
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

    # Helper: run sqlite3 query and return CSV lines
    function Invoke-Sqlite3Query {
        param([string]$DbPath, [string]$Query)
        $tempDb = Join-Path $env:TEMP "timeline_browser_$(Get-Random).db"
        try {
            Copy-Item -Path $DbPath -Destination $tempDb -Force -ErrorAction Stop
            $output = & $sqlite3Exe -csv $tempDb $Query 2>&1
            if ($LASTEXITCODE -eq 0) { return $output }
            else {
                Log-Warning "    sqlite3 error: $output"
                return @()
            }
        }
        catch { return @() }
        finally { Remove-Item $tempDb -Force -ErrorAction SilentlyContinue }
    }

    # Parse Chrome/Edge history (Chromium format)
    foreach ($histDb in $chromeHistoryPaths) {
        $browserName = "Chrome History"
        if ($histDb.FullName -match "Edge") { $browserName = "Edge History" }
        elseif ($histDb.FullName -match "Brave") { $browserName = "Brave History" }
        elseif ($histDb.FullName -match "Opera") { $browserName = "Opera History" }
        elseif ($histDb.FullName -match "OperaGX") { $browserName = "OperaGX History" }
        elseif ($histDb.FullName -match "Vivaldi") { $browserName = "Vivaldi History" }

        $user = ""
        if ($histDb.FullName -match "Users\\([^\\]+)\\" -or $histDb.FullName -match "Browser\\([^\\]+)\\") {
            $user = $Matches[1]
        }

        Log "  Parsing: $browserName ($user)"

        $query = "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 10000;"
        $rows = Invoke-Sqlite3Query -DbPath $histDb.FullName -Query $query

        foreach ($row in $rows) {
            if (-not $row -or $row.Length -lt 5) { continue }
            try {
                # Parse CSV: url,title,visit_count,visit_time
                $fields = @()
                $inQuote = $false; $field = ""
                for ($i = 0; $i -lt $row.Length; $i++) {
                    $c = $row[$i]
                    if ($c -eq '"') { $inQuote = -not $inQuote; continue }
                    if ($c -eq ',' -and -not $inQuote) { $fields += $field; $field = ""; continue }
                    $field += $c
                }
                $fields += $field

                if ($fields.Count -ge 4 -and $fields[3]) {
                    $ts = [datetime]::Parse($fields[3])
                    Add-TimelineEntry -Timestamp $ts -Source $browserName -EventType "NetworkConnection" `
                        -Description "Browser visit: $($fields[1])" `
                        -User $user -Details "URL=$($fields[0]) VisitCount=$($fields[2])" `
                        -Artifact "Browser" -RawPath $histDb.FullName
                    $browserParsed = $true
                }
            }
            catch {}
        }
    }

    # Parse Firefox places.sqlite
    foreach ($placesDb in $firefoxHistoryPaths) {
        $user = ""
        if ($placesDb.FullName -match "Users\\([^\\]+)\\") { $user = $Matches[1] }

        Log "  Parsing: Firefox History ($user)"

        $query = "SELECT p.url, p.title, p.visit_count, datetime(h.visit_date/1000000, 'unixepoch') FROM moz_places p JOIN moz_historyvisits h ON p.id = h.place_id ORDER BY h.visit_date DESC LIMIT 10000;"
        $rows = Invoke-Sqlite3Query -DbPath $placesDb.FullName -Query $query

        foreach ($row in $rows) {
            if (-not $row -or $row.Length -lt 5) { continue }
            try {
                $fields = @()
                $inQuote = $false; $field = ""
                for ($i = 0; $i -lt $row.Length; $i++) {
                    $c = $row[$i]
                    if ($c -eq '"') { $inQuote = -not $inQuote; continue }
                    if ($c -eq ',' -and -not $inQuote) { $fields += $field; $field = ""; continue }
                    $field += $c
                }
                $fields += $field

                if ($fields.Count -ge 4 -and $fields[3]) {
                    $ts = [datetime]::Parse($fields[3])
                    Add-TimelineEntry -Timestamp $ts -Source "Firefox History" -EventType "NetworkConnection" `
                        -Description "Browser visit: $($fields[1])" `
                        -User $user -Details "URL=$($fields[0]) VisitCount=$($fields[2])" `
                        -Artifact "Browser" -RawPath $placesDb.FullName
                    $browserParsed = $true
                }
            }
            catch {}
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
function Parse-ScheduledTasks {
    Log "--- Parsing Scheduled Tasks ---"

    $tasksParsed = $false

    # Look for scheduled_tasks.csv from triage collection
    $tasksCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("scheduled_tasks.csv")

    if ($tasksCsv.Count -gt 0) {
        foreach ($csv in $tasksCsv) {
            Log "  Parsing: $($csv.FullName)"
            try {
                $tasks = Import-Csv -Path $csv.FullName -ErrorAction Stop
                foreach ($task in $tasks) {
                    # Try to get a timestamp from the CSV columns
                    $ts = [datetime]::UtcNow
                    $dateFields = @("Date", "LastRunTime", "NextRunTime", "CreateDate", "Timestamp")
                    foreach ($field in $dateFields) {
                        if ($task.PSObject.Properties[$field] -and $task.$field) {
                            try {
                                $ts = [datetime]::Parse($task.$field)
                                break
                            }
                            catch {}
                        }
                    }

                    $taskName = if ($task.PSObject.Properties["TaskName"]) { $task.TaskName }
                                elseif ($task.PSObject.Properties["Name"]) { $task.Name }
                                else { "Unknown" }
                    $taskPath = if ($task.PSObject.Properties["TaskPath"]) { $task.TaskPath } else { "" }
                    $state = if ($task.PSObject.Properties["State"]) { $task.State } else { "" }
                    $author = if ($task.PSObject.Properties["Author"]) { $task.Author } else { "" }

                    Add-TimelineEntry -Timestamp $ts -Source "ScheduledTasks" -EventType "ScheduledTaskChange" `
                        -Description "Scheduled task: $taskName" `
                        -User $author `
                        -Details "Path=$taskPath State=$state" `
                        -Artifact "ScheduledTasks" -RawPath $csv.FullName
                    $tasksParsed = $true
                }
            }
            catch {
                Log-Warning "  Failed to parse scheduled tasks CSV: $($_.Exception.Message)"
            }
        }
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
function Parse-Services {
    Log "--- Parsing Services ---"

    $servicesParsed = $false

    # Look for services.csv from triage collection
    $servicesCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("services.csv")

    if ($servicesCsv.Count -gt 0) {
        foreach ($csv in $servicesCsv) {
            Log "  Parsing: $($csv.FullName)"
            try {
                $services = Import-Csv -Path $csv.FullName -ErrorAction Stop
                foreach ($svc in $services) {
                    $ts = [datetime]::UtcNow
                    $dateFields = @("Timestamp", "Date", "InstallDate")
                    foreach ($field in $dateFields) {
                        if ($svc.PSObject.Properties[$field] -and $svc.$field) {
                            try {
                                $ts = [datetime]::Parse($svc.$field)
                                break
                            }
                            catch {}
                        }
                    }

                    $svcName = if ($svc.PSObject.Properties["Name"]) { $svc.Name }
                               elseif ($svc.PSObject.Properties["ServiceName"]) { $svc.ServiceName }
                               else { "Unknown" }
                    $displayName = if ($svc.PSObject.Properties["DisplayName"]) { $svc.DisplayName } else { "" }
                    $startType = if ($svc.PSObject.Properties["StartType"]) { $svc.StartType } else { "" }
                    $binaryPath = if ($svc.PSObject.Properties["PathName"]) { $svc.PathName }
                                  elseif ($svc.PSObject.Properties["BinaryPathName"]) { $svc.BinaryPathName }
                                  else { "" }
                    $status = if ($svc.PSObject.Properties["Status"]) { $svc.Status }
                              elseif ($svc.PSObject.Properties["State"]) { $svc.State }
                              else { "" }

                    Add-TimelineEntry -Timestamp $ts -Source "Services" -EventType "ServiceChange" `
                        -Description "Service: $svcName ($displayName)" `
                        -Details "BinaryPath=$binaryPath StartType=$startType Status=$status" `
                        -Artifact "Services" -RawPath $csv.FullName
                    $servicesParsed = $true
                }
            }
            catch {
                Log-Warning "  Failed to parse services CSV: $($_.Exception.Message)"
            }
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
function Parse-FileSystem {
    Log "--- Parsing File System Metadata ---"

    $fsParsed = $false

    # Look for file_listing.csv or similar from triage collection
    $fileCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("file_listing.csv", "file_list.csv", "filesystem.csv", "files.csv")

    if ($fileCsvs.Count -gt 0) {
        foreach ($csv in $fileCsvs) {
            Log "  Parsing: $($csv.FullName)"
            try {
                $files = Import-Csv -Path $csv.FullName -ErrorAction Stop
                $count = 0
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
                            catch {}
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
                            catch {}
                        }
                    }

                    # Throttle to avoid massive timelines from full file listings
                    if ($count -ge 50000) {
                        Log-Warning "  File system entries capped at 50,000 to prevent excessive output."
                        break
                    }
                }
            }
            catch {
                Log-Warning "  Failed to parse file listing CSV: $($_.Exception.Message)"
            }
        }
    }
    else {
        Log "  No file listing CSV found in collection."
    }

    if (-not $fsParsed) {
        Log-Warning "No file system data found."
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

    foreach ($usnFile in $usnFiles) {
        Log "  Parsing: $($usnFile.FullName)"
        $count = 0
        $skipped = 0
        try {
            $reader = [System.IO.StreamReader]::new($usnFile.FullName)
            $headerFound = $false
            # Column indices (from CSV header)
            $colFileName = 1    # "File name"
            $colReason = 4      # "Reason"
            $colTimestamp = 5   # "Time stamp"
            $colAttributes = 7  # "File attributes"

            while (-not $reader.EndOfStream -and $count -lt 100000) {
                $line = $reader.ReadLine()
                if (-not $line -or $line.Length -lt 10) { continue }

                # Skip header lines (metadata and CSV header)
                if (-not $headerFound) {
                    if ($line -match '^Usn,') {
                        $headerFound = $true
                    }
                    continue
                }

                # Parse CSV line — fields are quoted with commas inside quotes
                # Format: USN,"filename",len,reason#,"reason","timestamp",attr#,"attributes",fileID,parentID,...
                try {
                    # Simple CSV split that handles quoted fields
                    $fields = @()
                    $inQuote = $false
                    $field = ""
                    for ($i = 0; $i -lt $line.Length; $i++) {
                        $c = $line[$i]
                        if ($c -eq '"') { $inQuote = -not $inQuote; continue }
                        if ($c -eq ',' -and -not $inQuote) {
                            $fields += $field
                            $field = ""
                            continue
                        }
                        $field += $c
                    }
                    $fields += $field

                    if ($fields.Count -lt 6) { continue }

                    $fileName = $fields[$colFileName]
                    $reason = $fields[$colReason]
                    $tsStr = $fields[$colTimestamp]

                    # Skip pure "Close" or "Basic info change | Close" entries to reduce noise
                    if ($reason -eq "Close" -or $reason -eq "Basic info change | Close") {
                        $skipped++
                        continue
                    }

                    $ts = [datetime]::Parse($tsStr)

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
                    $count++
                }
                catch {}
            }
            $reader.Close()
            $reader.Dispose()
            Log "  Parsed $count USN journal entries (skipped $skipped noisy close events)."
        }
        catch {
            Log-Warning "  Failed to parse USN Journal: $($_.Exception.Message)"
        }
    }
    Log "  USN Journal parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 10. Network Artifacts Parser
# ----------------------------------------------------------
function Parse-Network {
    Log "--- Parsing Network Artifacts ---"

    $networkParsed = $false

    # TCP connections CSV
    $tcpCsv = Find-ArtifactFiles -BasePath $InputPath -FileNames @("tcp_connections.csv")
    foreach ($csv in $tcpCsv) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $connections = Import-Csv -Path $csv.FullName -ErrorAction Stop
            foreach ($conn in $connections) {
                $ts = $csv.LastWriteTimeUtc
                $localAddr = if ($conn.PSObject.Properties["LocalAddress"]) { $conn.LocalAddress } else { "" }
                $localPort = if ($conn.PSObject.Properties["LocalPort"]) { $conn.LocalPort } else { "" }
                $remoteAddr = if ($conn.PSObject.Properties["RemoteAddress"]) { $conn.RemoteAddress } else { "" }
                $remotePort = if ($conn.PSObject.Properties["RemotePort"]) { $conn.RemotePort } else { "" }
                $state = if ($conn.PSObject.Properties["State"]) { $conn.State } else { "" }
                $process = if ($conn.PSObject.Properties["OwningProcess"]) { $conn.OwningProcess }
                           elseif ($conn.PSObject.Properties["Process"]) { $conn.Process } else { "" }

                Add-TimelineEntry -Timestamp $ts -Source "Network-TCP" -EventType "NetworkConnection" `
                    -Description "TCP connection: ${localAddr}:${localPort} -> ${remoteAddr}:${remotePort} ($state)" `
                    -Details "Process=$process State=$state" `
                    -Artifact "Network" -RawPath $csv.FullName
                $networkParsed = $true
            }
        }
        catch { Log-Warning "  Failed to parse TCP connections: $($_.Exception.Message)" }
    }

    # DNS cache
    $dnsFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("dns_cache.txt")
    foreach ($dnsFile in $dnsFiles) {
        Log "  Parsing: $($dnsFile.FullName)"
        try {
            $ts = $dnsFile.LastWriteTimeUtc
            $content = Get-Content -Path $dnsFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                $line = $line.Trim()
                if ($line -and $line -notmatch '^(---|Record|Entry|Name|$)' -and $line.Length -gt 3) {
                    # Parse "hostname : ip" or similar formats
                    if ($line -match '^\s*(\S+)\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                        $hostname = $Matches[1]
                        $ip = $Matches[2]
                        Add-TimelineEntry -Timestamp $ts -Source "Network-DNS" -EventType "NetworkConnection" `
                            -Description "DNS cache: $hostname -> $ip" `
                            -Artifact "Network" -RawPath $dnsFile.FullName
                        $networkParsed = $true
                    }
                    elseif ($line -match '^\s*(\S+)') {
                        Add-TimelineEntry -Timestamp $ts -Source "Network-DNS" -EventType "NetworkConnection" `
                            -Description "DNS cache entry: $($Matches[1])" `
                            -Artifact "Network" -RawPath $dnsFile.FullName
                        $networkParsed = $true
                    }
                }
            }
        }
        catch { Log-Warning "  Failed to parse DNS cache: $($_.Exception.Message)" }
    }

    # ARP cache
    $arpFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("arp_cache.txt")
    foreach ($arpFile in $arpFiles) {
        Log "  Parsing: $($arpFile.FullName)"
        try {
            $ts = $arpFile.LastWriteTimeUtc
            $content = Get-Content -Path $arpFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($line -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-f-]{17})\s+(\w+)') {
                    Add-TimelineEntry -Timestamp $ts -Source "Network-ARP" -EventType "NetworkConnection" `
                        -Description "ARP entry: $($Matches[1]) -> $($Matches[2]) ($($Matches[3]))" `
                        -Artifact "Network" -RawPath $arpFile.FullName
                    $networkParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse ARP cache: $($_.Exception.Message)" }
    }

    # Network shares
    $shareFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("network_shares.txt")
    foreach ($shareFile in $shareFiles) {
        Log "  Parsing: $($shareFile.FullName)"
        try {
            $ts = $shareFile.LastWriteTimeUtc
            $content = Get-Content -Path $shareFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($line -match '(\S+)\s+(\S+)\s+(Disk|Print|IPC)') {
                    Add-TimelineEntry -Timestamp $ts -Source "Network-Shares" -EventType "NetworkConnection" `
                        -Description "Network share: $($Matches[1]) -> $($Matches[2])" `
                        -Details "Type=$($Matches[3])" `
                        -Artifact "Network" -RawPath $shareFile.FullName
                    $networkParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse network shares: $($_.Exception.Message)" }
    }

    # WiFi profiles
    $wifiFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("wifi_profiles.txt")
    foreach ($wifiFile in $wifiFiles) {
        Log "  Parsing: $($wifiFile.FullName)"
        try {
            $ts = $wifiFile.LastWriteTimeUtc
            $content = Get-Content -Path $wifiFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($line -match 'All User Profile\s*:\s*(.+)') {
                    Add-TimelineEntry -Timestamp $ts -Source "Network-WiFi" -EventType "NetworkConnection" `
                        -Description "WiFi profile: $($Matches[1].Trim())" `
                        -Artifact "Network" -RawPath $wifiFile.FullName
                    $networkParsed = $true
                }
            }
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
function Parse-USB {
    Log "--- Parsing USB Artifacts ---"

    $usbParsed = $false

    # USB devices text
    $usbFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("usb_devices.txt", "usb_storage_devices.txt")
    foreach ($usbFile in $usbFiles) {
        Log "  Parsing: $($usbFile.FullName)"
        try {
            $ts = $usbFile.LastWriteTimeUtc
            $content = Get-Content -Path $usbFile.FullName -ErrorAction Stop
            $currentDevice = ""
            foreach ($line in $content) {
                if ($line -match '^\s*(DeviceID|InstanceId|FriendlyName|Description|Caption|Name)\s*[:=]\s*(.+)') {
                    $prop = $Matches[1]
                    $val = $Matches[2].Trim()
                    if ($prop -eq "FriendlyName" -or $prop -eq "Description" -or $prop -eq "Caption" -or $prop -eq "Name") {
                        $currentDevice = $val
                    }
                    if ($prop -eq "DeviceID" -or $prop -eq "InstanceId") {
                        Add-TimelineEntry -Timestamp $ts -Source "USB" -EventType "USBDevice" `
                            -Description "USB device: $currentDevice" `
                            -Details "DeviceID=$val" `
                            -Artifact "USB" -RawPath $usbFile.FullName
                        $usbParsed = $true
                    }
                }
                # Also handle CSV-like or object output
                elseif ($line -match 'USB\\VID_[0-9A-F]+&PID_[0-9A-F]+') {
                    Add-TimelineEntry -Timestamp $ts -Source "USB" -EventType "USBDevice" `
                        -Description "USB device detected" `
                        -Details "$line" `
                        -Artifact "USB" -RawPath $usbFile.FullName
                    $usbParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse USB devices: $($_.Exception.Message)" }
    }

    # Mounted devices
    $mountedFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("mounted_devices.txt")
    foreach ($mountFile in $mountedFiles) {
        Log "  Parsing: $($mountFile.FullName)"
        try {
            $ts = $mountFile.LastWriteTimeUtc
            $content = Get-Content -Path $mountFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($line -match '(\\DosDevices\\[A-Z]:|\\\?\?\\Volume\{)') {
                    Add-TimelineEntry -Timestamp $ts -Source "USB-MountedDevices" -EventType "USBDevice" `
                        -Description "Mounted device: $($line.Trim())" `
                        -Artifact "USB" -RawPath $mountFile.FullName
                    $usbParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse mounted devices: $($_.Exception.Message)" }
    }

    # SetupAPI log (USB connection timestamps)
    $setupApiFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("setupapi.dev.log")
    foreach ($logFile2 in $setupApiFiles) {
        Log "  Parsing: $($logFile2.FullName)"
        try {
            $content = Get-Content -Path $logFile2.FullName -ErrorAction Stop
            $count = 0
            for ($i = 0; $i -lt $content.Count -and $count -lt 5000; $i++) {
                $line = $content[$i]
                # Look for device install entries with timestamps
                if ($line -match '>>>\s+\[Device Install.*\]') {
                    $deviceLine = $line
                    # Next line usually has the timestamp
                    if ($i + 1 -lt $content.Count -and $content[$i + 1] -match '>>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})') {
                        $tsStr = $Matches[1]
                        try {
                            $ts = [datetime]::ParseExact($tsStr, "yyyy/MM/dd HH:mm:ss", $null)
                            Add-TimelineEntry -Timestamp $ts -Source "USB-SetupAPI" -EventType "USBDevice" `
                                -Description "Device install: $deviceLine" `
                                -Artifact "USB" -RawPath $logFile2.FullName
                            $usbParsed = $true
                            $count++
                        }
                        catch {}
                    }
                }
            }
            Log "  Parsed $count SetupAPI device install entries."
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
function Parse-Persistence {
    Log "--- Parsing Persistence Artifacts ---"

    $persistParsed = $false

    # Run keys
    $runKeyFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("run_keys.txt")
    foreach ($rkFile in $runKeyFiles) {
        Log "  Parsing: $($rkFile.FullName)"
        try {
            $ts = $rkFile.LastWriteTimeUtc
            $content = Get-Content -Path $rkFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                $line = $line.Trim()
                if ($line -and $line -notmatch '^(---|$|HKEY|Name\s)' -and $line.Length -gt 3) {
                    Add-TimelineEntry -Timestamp $ts -Source "Persistence-RunKeys" -EventType "PersistenceChange" `
                        -Description "Run key entry: $line" `
                        -Artifact "Persistence" -RawPath $rkFile.FullName
                    $persistParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse run keys: $($_.Exception.Message)" }
    }

    # Startup entries CSV
    $startupCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("startup_entries.csv")
    foreach ($csv in $startupCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $entries = Import-Csv -Path $csv.FullName -ErrorAction Stop
            foreach ($entry in $entries) {
                $ts = $csv.LastWriteTimeUtc
                $name = if ($entry.PSObject.Properties["Name"]) { $entry.Name } else { "Unknown" }
                $command = if ($entry.PSObject.Properties["Command"]) { $entry.Command }
                           elseif ($entry.PSObject.Properties["Location"]) { $entry.Location } else { "" }
                $user = if ($entry.PSObject.Properties["User"]) { $entry.User } else { "" }

                Add-TimelineEntry -Timestamp $ts -Source "Persistence-Startup" -EventType "PersistenceChange" `
                    -Description "Startup entry: $name" `
                    -User $user -Details "Command=$command" `
                    -Artifact "Persistence" -RawPath $csv.FullName
                $persistParsed = $true
            }
        }
        catch { Log-Warning "  Failed to parse startup entries: $($_.Exception.Message)" }
    }

    # Startup folders
    $startupFolderFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("startup_folders.txt")
    foreach ($sf in $startupFolderFiles) {
        Log "  Parsing: $($sf.FullName)"
        try {
            $ts = $sf.LastWriteTimeUtc
            $content = Get-Content -Path $sf.FullName -ErrorAction Stop
            foreach ($line in $content) {
                $line = $line.Trim()
                if ($line -and $line -notmatch '^(---|$)' -and $line.Length -gt 3) {
                    Add-TimelineEntry -Timestamp $ts -Source "Persistence-StartupFolder" -EventType "PersistenceChange" `
                        -Description "Startup folder item: $line" `
                        -Artifact "Persistence" -RawPath $sf.FullName
                    $persistParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse startup folders: $($_.Exception.Message)" }
    }

    # Drivers CSV
    $driverCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("drivers.csv")
    foreach ($csv in $driverCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $drivers = Import-Csv -Path $csv.FullName -ErrorAction Stop
            foreach ($drv in $drivers) {
                $ts = $csv.LastWriteTimeUtc
                if ($drv.PSObject.Properties["Date"] -and $drv.Date) {
                    try { $ts = [datetime]::Parse($drv.Date) } catch {}
                }
                $name = if ($drv.PSObject.Properties["Name"]) { $drv.Name }
                        elseif ($drv.PSObject.Properties["DisplayName"]) { $drv.DisplayName } else { "Unknown" }
                $path = if ($drv.PSObject.Properties["PathName"]) { $drv.PathName }
                        elseif ($drv.PSObject.Properties["DriverFile"]) { $drv.DriverFile } else { "" }
                $state = if ($drv.PSObject.Properties["State"]) { $drv.State } else { "" }

                Add-TimelineEntry -Timestamp $ts -Source "Persistence-Drivers" -EventType "PersistenceChange" `
                    -Description "Driver: $name" `
                    -Details "Path=$path State=$state" `
                    -Artifact "Persistence" -RawPath $csv.FullName
                $persistParsed = $true
            }
        }
        catch { Log-Warning "  Failed to parse drivers CSV: $($_.Exception.Message)" }
    }

    # WMI subscriptions CSV
    $wmiCsvs = Find-ArtifactFiles -BasePath $InputPath -FileNames @("wmi_subscriptions.csv")
    foreach ($csv in $wmiCsvs) {
        Log "  Parsing: $($csv.FullName)"
        try {
            $subs = Import-Csv -Path $csv.FullName -ErrorAction Stop
            foreach ($sub in $subs) {
                $ts = $csv.LastWriteTimeUtc
                $name = if ($sub.PSObject.Properties["Name"]) { $sub.Name } else { "Unknown" }
                $type = if ($sub.PSObject.Properties["Type"]) { $sub.Type }
                        elseif ($sub.PSObject.Properties["__CLASS"]) { $sub.__CLASS } else { "" }

                Add-TimelineEntry -Timestamp $ts -Source "Persistence-WMI" -EventType "PersistenceChange" `
                    -Description "WMI subscription: $name ($type)" `
                    -Artifact "Persistence" -RawPath $csv.FullName
                $persistParsed = $true
            }
        }
        catch { Log-Warning "  Failed to parse WMI subscriptions: $($_.Exception.Message)" }
    }

    # Suspicious loaded DLLs
    $dllFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("loaded_dlls_suspicious.txt")
    foreach ($dllFile in $dllFiles) {
        Log "  Parsing: $($dllFile.FullName)"
        try {
            $ts = $dllFile.LastWriteTimeUtc
            $content = Get-Content -Path $dllFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                $line = $line.Trim()
                if ($line -and $line.Length -gt 3 -and $line -notmatch '^(---|$)') {
                    Add-TimelineEntry -Timestamp $ts -Source "Persistence-SuspiciousDLL" -EventType "PersistenceChange" `
                        -Description "Suspicious DLL: $line" `
                        -Artifact "Persistence" -RawPath $dllFile.FullName
                    $persistParsed = $true
                }
            }
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
        $hivePath = "HKLM:\$hiveName"
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

                # Parse InventoryApplicationFile entries (Win10+)
                $invAppFilePath = "$hivePath\Root\InventoryApplicationFile"
                if (Test-Path $invAppFilePath) {
                    $entries = Get-ChildItem $invAppFilePath -ErrorAction SilentlyContinue
                    foreach ($entry in $entries) {
                        try {
                            $name = $entry.GetValue("Name")
                            $path2 = $entry.GetValue("LowerCaseLongPath")
                            $publisher = $entry.GetValue("Publisher")
                            $version = $entry.GetValue("Version")
                            $linkDate = $entry.GetValue("LinkDate")
                            $hash = $entry.GetValue("FileId")

                            $ts = $amcache.LastWriteTimeUtc
                            if ($linkDate) {
                                try { $ts = [datetime]::Parse($linkDate) } catch {}
                            }

                            Add-TimelineEntry -Timestamp $ts -Source "Amcache" -EventType "Execution" `
                                -Description "Amcache entry: $name" `
                                -Details "Path=$path2 Publisher=$publisher Version=$version Hash=$hash" `
                                -Artifact "Amcache" -RawPath $amcache.FullName
                            $count++
                        }
                        catch {}
                    }
                }

                # Parse InventoryApplication entries
                $invAppPath = "$hivePath\Root\InventoryApplication"
                if (Test-Path $invAppPath) {
                    $entries = Get-ChildItem $invAppPath -ErrorAction SilentlyContinue
                    foreach ($entry in $entries) {
                        try {
                            $name = $entry.GetValue("Name")
                            $publisher = $entry.GetValue("Publisher")
                            $version = $entry.GetValue("Version")
                            $installDate = $entry.GetValue("InstallDate")
                            $source = $entry.GetValue("Source")

                            $ts = $amcache.LastWriteTimeUtc
                            if ($installDate) {
                                try { $ts = [datetime]::Parse($installDate) } catch {}
                            }

                            Add-TimelineEntry -Timestamp $ts -Source "Amcache-App" -EventType "Execution" `
                                -Description "Amcache application: $name" `
                                -Details "Publisher=$publisher Version=$version Source=$source" `
                                -Artifact "Amcache" -RawPath $amcache.FullName
                            $count++
                        }
                        catch {}
                    }
                }

                Log "  Parsed $count Amcache entries."
            }
            else {
                Log-Warning "  Could not load Amcache hive (dirty/corrupt). No Amcache data available."
            }
        }
        catch {
            Log-Warning "  Failed to parse Amcache: $($_.Exception.Message)"
        }
        finally {
            if ($loaded) {
                [gc]::Collect()
                Start-Sleep -Milliseconds 500
                & reg unload "HKLM\$hiveName" 2>&1 | Out-Null
                Log "  Unloaded Amcache hive."
            }
            if ($tempHiveDir -and (Test-Path $tempHiveDir)) {
                Remove-Item -Path $tempHiveDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Log "  Amcache parsing complete."
    Log ""
}

# ----------------------------------------------------------
# 14. PowerShell History Parser
# ----------------------------------------------------------
function Parse-PowerShellHistory {
    Log "--- Parsing PowerShell History ---"

    $psParsed = $false

    # ConsoleHost_history.txt from triage collection
    $histFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("ConsoleHost_history.txt")


    foreach ($histFile in $histFiles) {
        Log "  Parsing: $($histFile.FullName)"
        try {
            # Determine user from path
            $user = ""
            if ($histFile.FullName -match 'Users\\([^\\]+)\\' -or $histFile.FullName -match 'UserActivity\\([^\\]+)\\') {
                $user = $Matches[1]
            }

            $commands = Get-Content -Path $histFile.FullName -ErrorAction Stop
            $ts = $histFile.LastWriteTimeUtc
            $count = 0

            foreach ($cmd in $commands) {
                $cmd = $cmd.Trim()
                if ($cmd -and $cmd.Length -gt 1) {
                    # Use file modification time as base, offset slightly for ordering
                    Add-TimelineEntry -Timestamp $ts -Source "PowerShellHistory" -EventType "Execution" `
                        -Description "PS command: $cmd" `
                        -User $user `
                        -Artifact "PowerShellHistory" -RawPath $histFile.FullName
                    $psParsed = $true
                    $count++
                }
            }
            Log "  Parsed $count PowerShell history commands for user $user."
        }
        catch { Log-Warning "  Failed to parse PS history: $($_.Exception.Message)" }
    }

    # Also parse BAM entries text file (not from live registry)
    $bamFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("bam_entries.txt")
    foreach ($bamFile in $bamFiles) {
        Log "  Parsing: $($bamFile.FullName)"
        try {
            $content = Get-Content -Path $bamFile.FullName -ErrorAction Stop
            foreach ($line in $content) {
                if ($line -match '^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+)') {
                    try {
                        $ts = [datetime]::Parse($Matches[1])
                        $exe = $Matches[2].Trim()
                        Add-TimelineEntry -Timestamp $ts -Source "BAM-Offline" -EventType "Execution" `
                            -Description "BAM execution: $exe" `
                            -Artifact "Registry" -RawPath $bamFile.FullName
                        $psParsed = $true
                    }
                    catch {}
                }
                elseif ($line -match '\\Device\\HarddiskVolume\d+\\(.+)' -or $line -match '([A-Z]:\\[^\s]+\.exe)') {
                    Add-TimelineEntry -Timestamp $bamFile.LastWriteTimeUtc -Source "BAM-Offline" -EventType "Execution" `
                        -Description "BAM execution: $($Matches[0])" `
                        -Artifact "Registry" -RawPath $bamFile.FullName
                    $psParsed = $true
                }
            }
        }
        catch { Log-Warning "  Failed to parse BAM entries: $($_.Exception.Message)" }
    }

    # AppCompatCache (ShimCache) .reg file
    $shimFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("appcompat_cache.reg")
    foreach ($shimFile in $shimFiles) {
        Log "  Parsing: $($shimFile.FullName)"
        try {
            $ts = $shimFile.LastWriteTimeUtc
            $content = Get-Content -Path $shimFile.FullName -ErrorAction Stop -Raw
            # .reg files have binary data; extract what we can from comments or readable sections
            # The hex data in a .reg export isn't easily parseable, note it as collected
            Add-TimelineEntry -Timestamp $ts -Source "AppCompatCache" -EventType "Execution" `
                -Description "AppCompatCache (ShimCache) registry export collected" `
                -Details "File=$($shimFile.FullName) - requires RECmd for full parsing" `
                -Artifact "Registry" -RawPath $shimFile.FullName
            $psParsed = $true
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
function Parse-Memory {
    Log "--- Parsing Memory Dump (Volatility 3) ---"

    $memParsed = $false

    # --- Find the memory dump file ---
    $dumpPath = $null

    # Check 1: Sibling of the selected zip (browse mode)
    if ($script:selectedZipPath -and (Test-Path $script:selectedZipPath)) {
        $zipDir = Split-Path $script:selectedZipPath -Parent
        $zipBaseName = [System.IO.Path]::GetFileNameWithoutExtension($script:selectedZipPath)
        $siblingDump = Join-Path $zipDir "${zipBaseName}_memory_dump.raw"
        if (Test-Path $siblingDump) {
            $dumpPath = $siblingDump
        }
    }

    # Check 2: Inside the collection directory
    if (-not $dumpPath) {
        $memFiles = Find-ArtifactFiles -BasePath $InputPath -FileNames @("memory_dump.raw", "memdump.raw", "memory.raw", "physmem.raw")
        if ($memFiles.Count -gt 0) {
            $dumpPath = $memFiles[0].FullName
        }
    }

    # Check 3: Alongside the InputPath directory
    if (-not $dumpPath) {
        $parentDir = Split-Path $InputPath -Parent
        $dumpFiles = Get-ChildItem -Path $parentDir -Filter "*_memory_dump.raw" -File -ErrorAction SilentlyContinue
        if ($dumpFiles.Count -gt 0) {
            $dumpPath = $dumpFiles[0].FullName
        }
    }

    if (-not $dumpPath) {
        Log-Warning "No memory dump found in collection or alongside zip."
        Log "  Memory parsing complete."
        Log ""
        return
    }

    $dumpSizeGB = [math]::Round((Get-Item $dumpPath).Length / 1GB, 2)
    Log "  Found memory dump: $dumpPath ($dumpSizeGB GB)"
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
                            try { $ts = [datetime]::Parse($entry.CreateTime) } catch {}
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
                            try { $ts = [datetime]::Parse($entry.Created) } catch {}
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

# =============================================================
# Auto-detect memory dump and prompt for analysis
# =============================================================
if ($Sources -notcontains "Memory") {
    # Check if a memory dump exists alongside the collection
    $detectedDump = $null

    # Check 1: Sibling of the selected zip (browse mode)
    if ($script:selectedZipPath -and (Test-Path $script:selectedZipPath)) {
        $zipDir = Split-Path $script:selectedZipPath -Parent
        $zipBaseName = [System.IO.Path]::GetFileNameWithoutExtension($script:selectedZipPath)
        $siblingDump = Join-Path $zipDir "${zipBaseName}_memory_dump.raw"
        if (Test-Path $siblingDump) { $detectedDump = $siblingDump }
    }

    # Check 2: Inside the collection directory
    if (-not $detectedDump) {
        $memFiles = Get-ChildItem -Path $InputPath -Filter "memory_dump.raw" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($memFiles) { $detectedDump = $memFiles.FullName }
    }

    # Check 3: Alongside the InputPath
    if (-not $detectedDump) {
        $parentDir = Split-Path $InputPath -Parent
        $dumpFiles = Get-ChildItem -Path $parentDir -Filter "*_memory_dump.raw" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($dumpFiles) { $detectedDump = $dumpFiles.FullName }
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

# Deduplicate based on Timestamp + Source + Description
Log "  Deduplicating..."
$deduped = $script:timelineEntries |
    Sort-Object Timestamp, Source, Description -Unique
$dedupedCount = ($deduped | Measure-Object).Count
$removedCount = $entryCount - $dedupedCount
Log "  Removed $removedCount duplicate(s). Unique entries: $dedupedCount"

# Sort chronologically
Log "  Sorting chronologically..."
$sorted = $deduped | Sort-Object Timestamp

# Add Flagged column if keywords specified
if ($Keywords -and $Keywords.Count -gt 0) {
    Log "  Applying keyword flags for: $($Keywords -join ', ')"
    $keywordPattern = ($Keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $sorted = $sorted | Select-Object *, @{
        Name       = 'Flagged'
        Expression = {
            $entry = $_
            $searchText = "$($entry.Description) $($entry.Details) $($entry.User) $($entry.Source)"
            if ($searchText -match $keywordPattern) { "TRUE" } else { "FALSE" }
        }
    }
    $flaggedCount = ($sorted | Where-Object { $_.Flagged -eq "TRUE" } | Measure-Object).Count
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

# Auto-install ImportExcel module if not present
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
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

if (Get-Module -ListAvailable -Name ImportExcel) {
    try {
        Import-Module ImportExcel -ErrorAction Stop

        # Define color map: EventType -> background color (RGB hex)
        $colorMap = @{
            "Logon"               = "92D050"   # Green
            "Execution"           = "FFC000"   # Orange
            "ProcessCreation"     = "FFC000"   # Orange
            "PersistenceChange"   = "FF6B6B"   # Red
            "AccountChange"       = "FF6B6B"   # Red
            "NetworkConnection"   = "6BB5FF"   # Blue
            "FileAccess"          = "D9D9D9"   # Light gray
            "ServiceChange"       = "FFFF00"   # Yellow
            "ScheduledTaskChange" = "FFFF00"   # Yellow
            "USBDevice"           = "CC99FF"   # Purple
            "Installation"        = "B4C6E7"   # Light blue
        }

        Log "  Exporting to Excel with conditional formatting..."

        # Second-pass sanitization for Excel compatibility:
        # 1. Remove XML-invalid control characters
        # 2. Truncate strings to Excel's 32,767 char cell limit (prevents "Repaired Records")
        $xmlInvalid = '[\x00-\x08\x0B\x0C\x0E-\x1F\xFFFE\xFFFF]'
        $maxCellLength = 32767
        foreach ($row in $sorted) {
            foreach ($prop in $row.PSObject.Properties) {
                if ($prop.Value -is [string] -and $prop.Value.Length -gt 0) {
                    $prop.Value = [regex]::Replace($prop.Value, $xmlInvalid, '')
                    if ($prop.Value.Length -gt $maxCellLength) {
                        $prop.Value = $prop.Value.Substring(0, $maxCellLength - 12) + " [TRUNCATED]"
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
                for ($r = 2; $r -le $totalRows; $r++) {
                    $eventType = $ws.Cells[$r, $eventTypeCol].Text
                    if ($colorMap.ContainsKey($eventType)) {
                        $color = [System.Drawing.Color]::FromArgb(
                            [Convert]::ToInt32($colorMap[$eventType].Substring(0,2), 16),
                            [Convert]::ToInt32($colorMap[$eventType].Substring(2,2), 16),
                            [Convert]::ToInt32($colorMap[$eventType].Substring(4,2), 16)
                        )
                        for ($c = 1; $c -le $totalCols; $c++) {
                            $ws.Cells[$r, $c].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                            $ws.Cells[$r, $c].Style.Fill.BackgroundColor.SetColor($color)
                        }
                    }
                }
                Log-Success "  Color-coded $($totalRows - 1) rows across $($colorMap.Count) event types."
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
        Log "    Green        Logon               -- authentication events"
        Log "    Orange       Execution            -- program execution evidence"
        Log "    Orange       ProcessCreation      -- new processes (Sysmon/4688)"
        Log "    Red          PersistenceChange    -- autostart, services, tasks modified"
        Log "    Red          AccountChange        -- user accounts created/modified"
        Log "    Blue         NetworkConnection    -- network activity, browser, DNS"
        Log "    Gray         FileAccess           -- file system activity"
        Log "    Yellow       ServiceChange        -- service state changes"
        Log "    Yellow       ScheduledTaskChange  -- task scheduler changes"
        Log "    Purple       USBDevice            -- USB device connections"
        Log "    Light Blue   Installation         -- application installs"
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

# Date range
$timestamps = $sorted | ForEach-Object { [datetime]::Parse($_.Timestamp) }
$earliest = ($timestamps | Measure-Object -Minimum).Minimum
$latest = ($timestamps | Measure-Object -Maximum).Maximum
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
    $teExe = $null
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
