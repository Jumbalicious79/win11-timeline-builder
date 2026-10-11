# =============================================================
# Windows ARM64 memory dumps: timeline rows from the debugger engine
# helper's entries
# Part of win11-timeline-builder. timeline-builder.ps1 dot-sources this file
# at script level (the builder's own process); without it, a Windows ARM64
# dump is not analyzed and the reason names this file.
#
# The helper (lib\memory\TimelineDbgEng.ps1, in a process of its own) sends
# P and C lines (the processes and command lines: Add-MemoryPluginRows in
# timeline-builder.ps1, the rows of Volatility's windows.pslist and
# windows.cmdline), E lines (the areas' entries: "TBDBG|E|<Kind>|<Key>:
# <Base64>|...", read by Receive-DbgEngWorkerLine into one PSCustomObject
# per entry, its properties the keys) and AREA lines (what each area read).
# This file turns the entries into rows:
#   Proc entries      merged into their process's P entry by Offset
#                     (Merge-DbgEngProcessEntries: the P entry gets .Proc),
#                     then Set-DbgEngProcessRowFields sets .User,
#                     .ExtraDetails (and .ImageFileName, .Anomaly) on the P
#                     and C entries; Add-MemoryPluginRows passes .User to the
#                     User column and appends .ExtraDetails to Details
#   other kinds       Add-DbgEngEntryRows calls the kind's function (the
#                     table in Get-DbgEngRowKinds) with every entry of that
#                     kind; it adds the rows (Add-DbgEngEntryRow) and returns
#                     the counts (New-DbgEngRowCounts)
#   account names     Register-DbgEngLogonNames, called just before the
#                     builder's User column pass (fallback names only)
# Each work package fills only its own functions below (marked with its
# package); the helpers above them are shared.
#
# Row conventions (every new memory Source): Artifact MemoryDump, RawPath the
# dump; a Snapshot row at the dump's capture time unless the entry has a
# valid time of its own (Get-MemoryEntryTime: 1980 up to a day after the
# acquisition ended); pipe-style Details (Format-DbgEngDetails); every
# per-process row carries "PID=<n> | ProcessCreated=<yyyy-MM-dd HH:mm:ss.fff>"
# (the owner's create time; the findings report leaves the collector's own
# processes out by these two, see CollectorRows in
# lib\report\TimelineReport.Engine.ps1); the User column is the owner's
# token SID (the User pass names it).
# =============================================================

# --- Shared (WP0) -------------------------------------------------------------------

# The areas of the helper, in the order the "analyzed with" line lists them,
# with what that line calls them
function Get-DbgEngAreaLabels {
    return @(
        [PSCustomObject]@{ Name = "ProcessDetails"; Label = "process users and paths" }
        [PSCustomObject]@{ Name = "Modules"; Label = "DLLs" }
        [PSCustomObject]@{ Name = "Drivers"; Label = "kernel drivers" }
        [PSCustomObject]@{ Name = "Handles"; Label = "handles" }
        [PSCustomObject]@{ Name = "PrivateCode"; Label = "executable private memory" }
        [PSCustomObject]@{ Name = "Registry"; Label = "registry hives" }
        [PSCustomObject]@{ Name = "Console"; Label = "console history" }
        [PSCustomObject]@{ Name = "Network"; Label = "network connections" }
        [PSCustomObject]@{ Name = "Services"; Label = "services" }
    )
}

# The entry kinds that become rows, in row order: the Source of their rows
# and the function that adds them (Proc entries have no rows of their own)
function Get-DbgEngRowKinds {
    return @(
        [PSCustomObject]@{ Kind = "Module"; Source = "Memory-Modules"; Function = "Add-DbgEngModuleRows" }
        [PSCustomObject]@{ Kind = "PrivateCode"; Source = "Memory-PrivateCode"; Function = "Add-DbgEngPrivateCodeRows" }
        [PSCustomObject]@{ Kind = "Driver"; Source = "Memory-Drivers"; Function = "Add-DbgEngDriverRows" }
        [PSCustomObject]@{ Kind = "Handle"; Source = "Memory-Handles"; Function = "Add-DbgEngHandleRows" }
        [PSCustomObject]@{ Kind = "Hive"; Source = "Memory-Registry"; Function = "Add-DbgEngHiveRows" }
        [PSCustomObject]@{ Kind = "RunValue"; Source = "Memory-Registry"; Function = "Add-DbgEngRunValueRows" }
        [PSCustomObject]@{ Kind = "Console"; Source = "Memory-ConsoleHistory"; Function = "Add-DbgEngConsoleRows" }
        [PSCustomObject]@{ Kind = "Net"; Source = "Memory-Network"; Function = "Add-DbgEngNetRows" }
        [PSCustomObject]@{ Kind = "Service"; Source = "Memory-Services"; Function = "Add-DbgEngServiceRows" }
    )
}

# The counts a rows function returns (as Add-MemoryPluginRows does)
function New-DbgEngRowCounts {
    param([int]$Timed = 0, [int]$Snapshot = 0)
    return [PSCustomObject]@{ Entries = $Timed + $Snapshot; Timed = $Timed; Snapshot = $Snapshot }
}

# Pipe-style Details ("Key=value | Key=value": the report's DetailParser
# reads them in pipe mode) from ordered pairs, in their order: a $null value
# leaves its pair out, "" keeps "Key="
function Format-DbgEngDetails {
    param([System.Collections.IDictionary]$Pairs)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($Pairs.Keys)) {
        if ($null -ne $Pairs[$key]) { $parts.Add("$key=$($Pairs[$key])") }
    }
    return ($parts.ToArray() -join " | ")
}

# One row of a memory Source: an event (-EventType) at the entry's own time
# (-Time: text such as "2026-10-11T12:21:33.1234567+00:00" or "yyyy-MM-dd
# HH:mm:ss.fff", or "") when it is valid, else a Snapshot row at the
# capture time. Returns Timed (the row is an event) and Text (a time that
# was there but not used, for the caller's Details; "" otherwise).
function Add-DbgEngEntryRow {
    param(
        [string]$Source, [string]$EventType = "Snapshot", [string]$Description, [string]$User = "", [string]$Details = "",
        $Time, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath
    )
    $own = Get-MemoryEntryTime -Value $Time -LatestUtc $AcquisitionEndUtc.AddDays(1)
    $timed = ($null -ne $own.TimeUtc -and $EventType -and $EventType -ne "Snapshot")
    $timestamp = if ($timed) { $own.TimeUtc } else { $CaptureTimeUtc }
    $type = if ($timed) { $EventType } else { "Snapshot" }
    Add-TimelineEntry -Timestamp $timestamp -Source $Source -EventType $type -Description $Description -User $User -Details $Details -Artifact "MemoryDump" -RawPath $DumpPath
    return [PSCustomObject]@{ Timed = $timed; Text = $own.Text }
}

# Each Proc entry onto the P entry (windows.pslist entry) of the same
# EPROCESS (Offset, "0x..."): that entry gets a Proc property (the Proc
# entry). Returns Merged and Unmatched (Proc entries without a process).
function Merge-DbgEngProcessEntries {
    param([object[]]$Processes, [object[]]$ProcEntries)
    $byOffset = @{}
    foreach ($process in @($Processes)) {
        if ($null -ne $process -and $process.Offset) { $byOffset["$($process.Offset)".ToLowerInvariant()] = $process }
    }
    $merged = 0
    $unmatched = 0
    foreach ($entry in @($ProcEntries)) {
        if ($null -eq $entry) { continue }
        $key = "$($entry.Offset)".ToLowerInvariant()
        if ($key -and $byOffset.ContainsKey($key)) {
            $byOffset[$key] | Add-Member -NotePropertyName "Proc" -NotePropertyValue $entry -Force
            $merged++
        }
        else { $unmatched++ }
    }
    return [PSCustomObject]@{ Merged = $merged; Unmatched = $unmatched }
}

# The entries of one kind as an array: a List[object] of the worker state
# (@() around such a list fails in both PowerShell editions with "Argument
# types do not match"), or what a test gives
function ConvertTo-DbgEngEntryArray {
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [System.Collections.Generic.List[object]]) { return , $Value.ToArray() }
    return , @($Value)
}

# The rows of every entry kind that has them (Get-DbgEngRowKinds), in that
# order. -Entries: kind -> the entries (the builder's worker state). Returns
# one result per kind that had entries: Kind, Source, Received (entries),
# Rows, Timed, Snapshot, and Unknown for a kind the builder has no rows for
# (its entries are counted, not used). A kind whose function fails has its
# Error (the rows it added before stay).
function Add-DbgEngEntryRows {
    param([System.Collections.IDictionary]$Entries, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $results = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Entries) { return }
    $known = @{ Proc = $true }
    foreach ($kind in @(Get-DbgEngRowKinds)) {
        $known[$kind.Kind] = $true
        $list = @()
        if ($Entries.Contains($kind.Kind)) { $list = ConvertTo-DbgEngEntryArray $Entries[$kind.Kind] }
        if ($list.Count -eq 0) { continue }
        $result = [PSCustomObject]@{ Kind = $kind.Kind; Source = $kind.Source; Received = $list.Count; Rows = 0; Timed = 0; Snapshot = 0; Unknown = $false; Error = "" }
        try {
            $counts = & $kind.Function -Entries $list -Source $kind.Source -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
            $result.Rows = [int]$counts.Entries
            $result.Timed = [int]$counts.Timed
            $result.Snapshot = [int]$counts.Snapshot
        }
        catch { $result.Error = $_.Exception.Message }
        $results.Add($result)
    }
    foreach ($name in @($Entries.Keys)) {
        if ($known.ContainsKey([string]$name)) { continue }
        $results.Add([PSCustomObject]@{ Kind = [string]$name; Source = ""; Received = (ConvertTo-DbgEngEntryArray $Entries[$name]).Count; Rows = 0; Timed = 0; Snapshot = 0; Unknown = $true; Error = "" })
    }
    return $results.ToArray()
}

# What the "Memory dump analyzed with the Windows debugger engine" line says
# was read and was not: "read processes, command lines, DLLs, ...; not read
# handles (<why>), ..." in the order of Get-DbgEngAreaLabels (no "; not
# read" part when everything was read). No colon: the report's notes and
# caveats have one, the line's own. -Areas: the helper's AREA lines (Name,
# State, Note); an area without one was not reported by the helper.
# -PartialReason: why the command lines were not read ("" when they were).
# A why is short and has no ";", ": " or parentheses (the report splits the
# line on them).
function Get-DbgEngReadText {
    param([object[]]$Areas, [string]$PartialReason = "")
    $read = New-Object System.Collections.Generic.List[string]
    $notRead = New-Object System.Collections.Generic.List[string]
    $read.Add("processes")
    if ($PartialReason) { $notRead.Add("command lines ($(Get-DbgEngShortError ($PartialReason -replace '^its command lines ', '')))") }
    else { $read.Add("command lines") }
    foreach ($label in @(Get-DbgEngAreaLabels)) {
        $area = @($Areas | Where-Object { $null -ne $_ -and $_.Name -eq $label.Name }) | Select-Object -First 1
        if ($null -eq $area) { $notRead.Add("$($label.Label) (not reported by the debugger engine helper)") }
        elseif ($area.State -eq "NotRead") {
            $why = Get-DbgEngShortError ([string]$area.Note)
            if (-not $why) { $why = "no reason given" }
            $notRead.Add("$($label.Label) ($why)")
        }
        else { $read.Add($label.Label) }
    }
    $text = "read " + ($read.ToArray() -join ", ")
    if ($notRead.Count -gt 0) { $text += "; not read " + ($notRead.ToArray() -join ", ") }
    return $text
}

# The "Memory dump coverage: <area> -- <note>" texts (after "Memory dump
# coverage: "): one per area that was read, fully or in part, with a note
# (what a live copy left unreadable, and the like), in the order of
# Get-DbgEngAreaLabels
function Get-DbgEngCoverageTexts {
    param([object[]]$Areas)
    $texts = New-Object System.Collections.Generic.List[string]
    foreach ($label in @(Get-DbgEngAreaLabels)) {
        $area = @($Areas | Where-Object { $null -ne $_ -and $_.Name -eq $label.Name }) | Select-Object -First 1
        if ($null -eq $area -or $area.State -eq "NotRead" -or -not "$($area.Note)".Trim()) { continue }
        # One colon in the report's note: the line's own
        $note = ("$($area.Note)".Trim().TrimEnd('.') -replace ':\s+', ' - ' -replace '\s+--\s+', ' - ')
        $texts.Add("$($label.Label) -- $note")
    }
    return $texts.ToArray()
}

# --- WP1: process details (items a and b) ---------------------------------------------

# The fields of a Proc entry (lib\memory\TimelineDbgEng.Tokens.ps1) that go
# into Details of a Memory-Processes row, in their order: the token's first,
# then those whose values can hold spaces (Get-DbgEngProcessDetailsText)
function Get-DbgEngProcessDetailKeys {
    return @("Integrity", "Elevation", "Elevated", "AdminGroup", "TokenSession", "LogonId", "AppContainer", "UIAccess", "Protection", "Privileges",
        "LogonAccount", "ImagePath", "CurrentDirectory", "PebImagePath")
}

# A field of an entry as text ("" when it has none)
function Get-DbgEngEntryField {
    param($Entry, [string]$Name)
    if ($null -eq $Entry -or -not $Entry.PSObject.Properties[$Name]) { return "" }
    return [string]$Entry.$Name
}

# What a Proc entry adds to its Memory-Processes row's Details (space style,
# as the rest of that row): "Integrity=System Elevation=Default ...
# LogonAccount=<Authority>\<Account> ImagePath=<path> CurrentDirectory=<path>
# [PebImagePath=<path>]", each field only when the helper read it
function Get-DbgEngProcessDetailsText {
    param($Proc)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in @(Get-DbgEngProcessDetailKeys)) {
        $value = Get-DbgEngEntryField -Entry $Proc -Name $key
        if ($value) { $parts.Add("$key=$value") }
    }
    return ($parts.ToArray() -join " ")
}

# Sets what the Proc entries say (Merge-DbgEngProcessEntries put each on its
# P entry as .Proc) on the process (P) and command line (C) entries before
# their rows are made:
#   P: .User (the token's user SID), .ExtraDetails (Get-DbgEngProcessDetailsText),
#      .ImageFileName the full file name (FullName) when the helper read it
#      (EPROCESS.ImageFileName keeps 14 characters), .Anomaly the scan's
#      tokens and the helper's (ImageNameChanged, PebImageNameMismatch,
#      SystemChildOfUser), comma-separated
#   C: .User and .Process (the full name) of its process: the P entry of the
#      same PID and short name (several such entries: only when they agree)
# Entries without a Proc entry are left as they are (Volatility's, a helper
# whose ProcessDetails area was not read).
function Set-DbgEngProcessRowFields {
    param([object[]]$Processes, [object[]]$CommandLines)
    $byPid = @{}
    foreach ($process in @($Processes)) {
        if ($null -eq $process -or -not $process.PSObject.Properties["Proc"] -or $null -eq $process.Proc) { continue }
        $proc = $process.Proc
        $short = [string]$process.ImageFileName
        $user = (Get-DbgEngEntryField -Entry $proc -Name "User").Trim()
        $full = Get-DbgEngEntryField -Entry $proc -Name "FullName"
        if ($user) { $process | Add-Member -NotePropertyName "User" -NotePropertyValue $user -Force }
        $extra = Get-DbgEngProcessDetailsText -Proc $proc
        if ($extra) { $process | Add-Member -NotePropertyName "ExtraDetails" -NotePropertyValue $extra -Force }
        if ($full) { $process.ImageFileName = $full }
        $added = Get-DbgEngEntryField -Entry $proc -Name "Anomaly"
        if ($added) {
            $tokens = New-Object System.Collections.Generic.List[string]
            foreach ($token in @("$($process.Anomaly)" -split ',') + @($added -split ',')) {
                $t = $token.Trim()
                if ($t -and -not $tokens.Contains($t)) { $tokens.Add($t) }
            }
            $process | Add-Member -NotePropertyName "Anomaly" -NotePropertyValue ($tokens.ToArray() -join ",") -Force
        }
        $key = "$($process.PID)"
        if (-not $byPid.ContainsKey($key)) { $byPid[$key] = New-Object System.Collections.Generic.List[object] }
        $byPid[$key].Add([PSCustomObject]@{ Short = $short; Full = $(if ($full) { $full } else { $short }); User = $user })
    }
    foreach ($commandLine in @($CommandLines)) {
        if ($null -eq $commandLine) { continue }
        $key = "$($commandLine.PID)"
        if (-not $byPid.ContainsKey($key)) { continue }
        $same = @($byPid[$key] | Where-Object { $_.Short -ceq [string]$commandLine.Process })
        if ($same.Count -eq 0) { continue }
        $fulls = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $users = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($candidate in $same) { [void]$fulls.Add($candidate.Full); [void]$users.Add($candidate.User) }
        if ($fulls.Count -ne 1 -or $users.Count -ne 1) { continue }
        $commandLine.Process = $same[0].Full
        if ($same[0].User) { $commandLine | Add-Member -NotePropertyName "User" -NotePropertyValue $same[0].User -Force }
    }
}

# Account names the dump's logon sessions hold, registered as fallback
# names for the User column (Add-TimelineSidName without -ProfileList, so
# the SOFTWARE hive's ProfileList and bam_entries.csv still win). -Entries:
# kind -> entries of this run's dump (empty when none was analyzed). A
# Proc entry gives its token's user SID (User) and its logon session's
# "<Authority>\<Account>" (LogonAccount), in the User column's one form
# (ConvertTo-TimelineUserName: the examined computer's own name as the
# authority is dropped). Only local, domain and Entra ID accounts
# (S-1-5-21-..., S-1-12-1-...); a SID whose processes name two different
# accounts is left out (a logon session of another account than the
# token's user cannot name it).
function Register-DbgEngLogonNames {
    param([System.Collections.IDictionary]$Entries)
    if ($null -eq $Entries -or -not $Entries.Contains("Proc")) { return }
    $context = Get-TimelineUserContext
    $machines = @($context.MachineNames)
    $names = [ordered]@{}
    foreach ($entry in (ConvertTo-DbgEngEntryArray $Entries["Proc"])) {
        $sid = (Get-DbgEngEntryField -Entry $entry -Name "User").Trim()
        $account = (Get-DbgEngEntryField -Entry $entry -Name "LogonAccount").Trim()
        if (-not $account -or $sid -notmatch '^S-1-(5-21|12-1)(-\d+)+$') { continue }
        $name = ConvertTo-TimelineUserName -Value $account -SidNames @{} -MachineNames $machines
        if (-not $name) { continue }
        if (-not $names.Contains($sid)) { $names[$sid] = $name }
        elseif ($names[$sid] -cne $name) { $names[$sid] = "" }
    }
    $used = 0
    foreach ($sid in @($names.Keys)) {
        if (-not $names[$sid]) { continue }
        if (-not $context.ProfileSids.ContainsKey($sid) -and -not $context.BamSids.ContainsKey($sid)) { $used++ }
        Add-TimelineSidName -Sid $sid -Name $names[$sid]
    }
    if ($used -gt 0) { Log "  User column: $used account name(s) from the memory dump's logon sessions, for SIDs that ProfileList and bam_entries.csv do not name" }
}

# --- WP2: DLLs and executable private memory (items c and f) ---------------------------

# A field of an entry as text, or $null when it is missing or empty (for
# Format-DbgEngDetails, which leaves $null out)
function Get-DbgEngOptionalField {
    param($Entry, [string]$Name)
    $value = [string]$Entry.$Name
    if ($value) { return $value }
    return $null
}

# Memory-Modules rows (item c, lib\memory\TimelineDbgEng.Modules.ps1): one per
# Module entry, a DLL outside the Windows folder or one the helper judged
# (Anomaly= NotInLoaderLists, NoImageMapping, NameMismatch). ModuleLoad at
# the loader's load time when the helper sent one (it sends only a time
# inside the process's lifetime), else a Snapshot row at the capture time.
#   Description  Module in memory: <file name> (PID: <n>, Process: <name>)
#   Details      PID | ProcessCreated | Path | Base | Size [| LoadReason] |
#                FoundBy [| Protection] [| Managed=Yes] [| Anomaly]
#                [| LoaderPath]
# (Protection and Managed only on an image in no loader list: the mapping's
# protection, read-only for a resource-only load, and Managed=Yes for a .NET
# assembly its runtime mapped.)
# User: the process token's SID. An entry without a Base is not a module and
# is skipped.
function Add-DbgEngModuleRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $timed = 0
    $snapshot = 0
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry -or "$($entry.Base)" -cnotmatch '^0x[0-9a-f]{1,16}$') { continue }
        $name = [string]$entry.Name
        if (-not $name) { $name = ([string]$entry.Path -split '\\')[-1] }
        $details = Format-DbgEngDetails ([ordered]@{
                PID = [string]$entry.PID; ProcessCreated = [string]$entry.ProcessCreated; Path = [string]$entry.Path; Base = [string]$entry.Base; Size = [string]$entry.Size
                LoadReason = (Get-DbgEngOptionalField $entry "LoadReason"); FoundBy = [string]$entry.FoundBy; Protection = (Get-DbgEngOptionalField $entry "Protection"); Managed = (Get-DbgEngOptionalField $entry "Managed")
                Anomaly = (Get-DbgEngOptionalField $entry "Anomaly"); LoaderPath = (Get-DbgEngOptionalField $entry "LoaderPath")
            })
        $row = Add-DbgEngEntryRow -Source $Source -EventType "ModuleLoad" -Description "Module in memory: $name (PID: $($entry.PID), Process: $($entry.Process))" `
            -User ([string]$entry.User) -Details $details -Time ([string]$entry.LoadTime) -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
        if ($row.Timed) { $timed++ } else { $snapshot++ }
    }
    return (New-DbgEngRowCounts -Timed $timed -Snapshot $snapshot)
}

# A region's size for a description: "64 MB", "1076 KB", or "<n> bytes"
function Format-DbgEngRegionSize {
    param([uint64]$Size)
    if ($Size -gt 0 -and $Size % 1048576 -eq 0) { return "$([uint64]($Size / 1048576)) MB" }
    if ($Size -gt 0 -and $Size % 1024 -eq 0) { return "$([uint64]($Size / 1024)) KB" }
    return "$Size bytes"
}

# Memory-PrivateCode rows (item f, lib\memory\TimelineDbgEng.PrivateCode.ps1):
# one Snapshot row per executable private region at the capture time (a
# region has no time of its own).
#   Description  Executable private memory: <size> at <start> (PID: <n>,
#                Process: <name>)
#   Details      PID | ProcessCreated | Start | Size | Protection | FirstBytes
#                | JitHost [| ProcessProtected=Yes] [| Anomaly=PeHeader]
# User: the process token's SID. An entry without a Start is not a region
# and is skipped.
function Add-DbgEngPrivateCodeRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $snapshot = 0
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry -or "$($entry.Start)" -cnotmatch '^0x[0-9a-f]{1,16}$') { continue }
        $size = [uint64]0
        if ("$($entry.Size)" -cmatch '^0x([0-9a-f]{1,16})$') { $size = [Convert]::ToUInt64($Matches[1], 16) }
        $details = Format-DbgEngDetails ([ordered]@{
                PID = [string]$entry.PID; ProcessCreated = [string]$entry.ProcessCreated; Start = [string]$entry.Start; Size = [string]$entry.Size
                Protection = [string]$entry.Protection; FirstBytes = [string]$entry.FirstBytes; JitHost = [string]$entry.JitHost; ProcessProtected = (Get-DbgEngOptionalField $entry "ProcessProtected")
                Anomaly = (Get-DbgEngOptionalField $entry "Anomaly")
            })
        [void](Add-DbgEngEntryRow -Source $Source -Description "Executable private memory: $(Format-DbgEngRegionSize $size) at $($entry.Start) (PID: $($entry.PID), Process: $($entry.Process))" `
                -User ([string]$entry.User) -Details $details -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath)
        $snapshot++
    }
    return (New-DbgEngRowCounts -Snapshot $snapshot)
}

# --- WP3: kernel drivers and handles (items d and e) -----------------------------------

# Memory-Drivers rows (lib\memory\TimelineDbgEng.Drivers.ps1's Driver
# entries; no User: a kernel module belongs to no process):
#   State=Loaded    Snapshot "Kernel module in memory: <name>", Details
#                   "Path=<drive-letter path> | Base=0x.. | Size=0x.. |
#                   FoundBy=ModuleList[,DriverObject][ | DriverObject=\Driver\
#                   <n>[,..]][ | Anomaly=NotInModuleList]"
#   State=Unloaded  DriverUnload at its unload time (a Snapshot row with
#                   UnloadTime= when that time is not valid), "Kernel module
#                   unloaded: <name>", Details "Base=0x.. | Size=0x.. |
#                   FoundBy=UnloadedDriverList"
function Add-DbgEngDriverRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $timed = 0
    $snapshot = 0
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $name = [string]$entry.Name
        if ("$($entry.State)" -eq "Unloaded") {
            $details = [ordered]@{ Base = [string]$entry.Base; Size = [string]$entry.Size; FoundBy = [string]$entry.FoundBy }
            $own = Get-MemoryEntryTime -Value $entry.Time -LatestUtc $AcquisitionEndUtc.AddDays(1)
            if ($null -eq $own.TimeUtc -and $own.Text) { $details["UnloadTime"] = $own.Text }
            $row = Add-DbgEngEntryRow -Source $Source -EventType "DriverUnload" -Description "Kernel module unloaded: $name" -Details (Format-DbgEngDetails $details) `
                -Time $entry.Time -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
        }
        else {
            $details = [ordered]@{ Path = [string]$entry.Path; Base = [string]$entry.Base; Size = [string]$entry.Size; FoundBy = [string]$entry.FoundBy }
            if ($entry.DriverObject) { $details["DriverObject"] = [string]$entry.DriverObject }
            if ($entry.Anomaly) { $details["Anomaly"] = [string]$entry.Anomaly }
            $row = Add-DbgEngEntryRow -Source $Source -Description "Kernel module in memory: $name" -Details (Format-DbgEngDetails $details) `
                -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
        }
        if ($row.Timed) { $timed++ } else { $snapshot++ }
    }
    return (New-DbgEngRowCounts -Timed $timed -Snapshot $snapshot)
}

# Memory-Handles rows (lib\memory\TimelineDbgEng.Handles.ps1's Handle
# entries: the useful subset of the handles), Snapshot rows at the capture
# time, User the holder's token SID: "Handle in memory: <Type> <target>
# (PID: n, Process: <holder>)", Details "PID=n | ProcessCreated=.. |
# Type=Process|Thread|File|Key|Mutant | Handle=0x.. | Access=0x<mask> |
# Target=<process, path, key or name>[ | TargetPID=n | TargetProcess=<name> |
# TargetCreated=..][ | TargetTID=n][ | Handles=n][ | Anomaly=..]". PID= and
# ProcessCreated= are the holder's (option C of the findings report).
function Add-DbgEngHandleRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $snapshot = 0
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $details = [ordered]@{
            PID = [string]$entry.Pid; ProcessCreated = [string]$entry.ProcessCreated; Type = [string]$entry.Type; Handle = [string]$entry.Handle
            Access = [string]$entry.Access; Target = [string]$entry.Target
        }
        if ("$($entry.TargetPid)" -ne "") {
            $details["TargetPID"] = [string]$entry.TargetPid
            $details["TargetProcess"] = [string]$entry.TargetProcess
            $details["TargetCreated"] = [string]$entry.TargetCreated
        }
        if ("$($entry.TargetTid)" -ne "") { $details["TargetTID"] = [string]$entry.TargetTid }
        if ("$($entry.Handles)" -ne "") { $details["Handles"] = [string]$entry.Handles }
        if ($entry.Anomaly) { $details["Anomaly"] = [string]$entry.Anomaly }
        $description = "Handle in memory: $($entry.Type) $($entry.Target) (PID: $($entry.Pid), Process: $($entry.Process))"
        $row = Add-DbgEngEntryRow -Source $Source -Description $description -User ([string]$entry.User) -Details (Format-DbgEngDetails $details) `
            -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
        if (-not $row.Timed) { $snapshot++ }
    }
    return (New-DbgEngRowCounts -Snapshot $snapshot)
}

# --- WP4: registry hives in memory (item g) ---------------------------------------------

# Memory-Registry rows of the hives (Hive entries of
# lib\memory\TimelineDbgEng.Registry.ps1): one Snapshot row per hive of the
# kernel's hive list, "Registry hive in memory: <root path>", Details
# "File=<its file> | Readable=<n>% | Root=Read|Unreadable|NotRead |
# FoundBy=HiveListForward,HiveListBackward[ | NotRead=CredentialHive|
# NamesNotInDump] | Offset=0x<_CMHIVE>"; User: the SID of a user's hive.
function Add-DbgEngHiveRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $snapshot = 0
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $root = "$($entry.Root)"
        if (-not $root) { $root = "(no root path)" }
        $readable = $null
        if ("$($entry.Readable)" -match '^\d+$') { $readable = "$($entry.Readable)%" }
        $notRead = $null
        if ("$($entry.NotRead)") { $notRead = "$($entry.NotRead)" }
        $details = Format-DbgEngDetails ([ordered]@{
                File = "$($entry.File)"; Readable = $readable; Root = "$($entry.RootState)"; FoundBy = "$($entry.FoundBy)"; NotRead = $notRead; Offset = "$($entry.Offset)"
            })
        [void](Add-DbgEngEntryRow -Source $Source -Description "Registry hive in memory: $root" -User "$($entry.Sid)" -Details $details `
                -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath)
        $snapshot++
    }
    return (New-DbgEngRowCounts -Snapshot $snapshot)
}

# "<hive id>|<key path>" -> value name -> its commands, and the hive ids
# whose Run keys the collection read, from the rows already in the timeline (Memory is parsed
# last): Persistence-RunKeys (the collector's run_keys.csv / run_keys.txt,
# read live: "HKLM" and "HKU\<SID>") and Registry-UserRunKey (a collected
# NTUSER.DAT: "FOLDER:<profile folder>"). A hive id counts as read when one
# of its Run values is in the timeline (the collector reads every Run key of
# a hive in one pass), or, for a collected NTUSER.DAT, when any Registry-*
# row of that file is (Read-NtUserHive reads its Run keys with the rest).
# Ids, paths and names are lower case. -Rows: the timeline's rows.
function Get-DbgEngOnDiskRunKeys {
    param([object]$Rows)
    $parsed = @{}
    $values = @{}
    $seenFiles = @{}
    $add = {
        param([string]$HiveId, [string]$KeyPath, [string]$Name, [string]$Command)
        $HiveId = $HiveId.ToLowerInvariant()
        $parsed[$HiveId] = $true
        $key = "$HiveId|$($KeyPath.Trim('\').ToLowerInvariant())"
        if (-not $values.ContainsKey($key)) { $values[$key] = @{} }
        $name = $Name.ToLowerInvariant()
        if (-not $values[$key].ContainsKey($name)) { $values[$key][$name] = New-Object System.Collections.Generic.List[string] }
        $values[$key][$name].Add($Command.Trim())
    }
    if ($null -eq $Rows) { return [PSCustomObject]@{ Parsed = $parsed; Values = $values } }
    foreach ($row in $Rows) {
        $source = [string]$row.Source
        if ($source -eq "Persistence-RunKeys") {
            $description = [string]$row.Description
            $fullKey = $null
            $name = $null
            if ($description -match '^Run key last written: (.+) \(value: (.*)\)$') { $fullKey = $Matches[1]; $name = $Matches[2] }
            elseif ($description -match '^Run key value: (.*) \[(.+)\]$') { $name = $Matches[1]; $fullKey = $Matches[2] -replace ' \([^)]*\)$', '' }
            if ($null -eq $fullKey) { continue }
            # "Command=<data> | Key=<key>" (run_keys.csv), "Command=<data>" (run_keys.txt)
            $command = ""
            if ([string]$row.Details -match '^Command=(.*?)(?: \| Key=[^|]*)?$') { $command = $Matches[1] }
            if ($fullKey -match '^HKLM\\(.+)$') { & $add "HKLM" $Matches[1] $name $command }
            elseif ($fullKey -match '^(?:HKU|HKEY_USERS)\\([^\\]+)\\(.+)$') { & $add "HKU\$($Matches[1])" $Matches[2] $name $command }
        }
        elseif ($source.StartsWith("Registry-", [System.StringComparison]::Ordinal)) {
            $rawPath = [string]$row.RawPath
            $folder = $null
            if ($seenFiles.ContainsKey($rawPath)) { $folder = $seenFiles[$rawPath] }
            else {
                if ($rawPath -match '\\Registry\\([^\\]+)\\NTUSER\.DAT$') { $folder = $Matches[1] }
                $seenFiles[$rawPath] = $folder
            }
            if (-not $folder) { continue }
            $parsed["folder:$($folder.ToLowerInvariant())"] = $true
            if ($source -eq "Registry-UserRunKey") {
                # "User Run key: <name> = <command>", "Key=HKCU\<path>; Time=..."
                $name = $null
                $command = ""
                $keyPath = $null
                if ([string]$row.Description -match '^User Run key: (.*?) = (.*)$') { $name = $Matches[1]; $command = $Matches[2] }
                if ([string]$row.Details -match '(?:^|; |\| )Key=HKCU\\([^;|]+?)\s*(?:;|\||$)') { $keyPath = $Matches[1] }
                if ($null -ne $name -and $keyPath) { & $add "FOLDER:$folder" $keyPath $name $command }
            }
        }
    }
    return [PSCustomObject]@{ Parsed = $parsed; Values = $values }
}

# Whether a Run value of memory is in the collection's copy of the same
# hive's Run key: Yes (that key has a value of this name with the same
# data, case aside), Changed (a value of this name with other data), No
# (the hive's Run keys were read and this key has no value of this name) or
# Unknown (the collection did not read that hive's Run keys). A value is
# looked for in the live read of the hive (HKLM, HKU\<SID>) and in its
# collected NTUSER.DAT (the profile folder of the hive's file); Yes wins,
# then Changed, then No.
function Get-DbgEngRunValueOnDisk {
    param($Entry, $OnDisk)
    $hive = "$($Entry.Hive)"
    $ids = New-Object System.Collections.Generic.List[string]
    $ids.Add($hive.ToLowerInvariant())
    if ("$($Entry.HiveFile)" -match '\\Users\\([^\\]+)\\NTUSER\.DAT$') { $ids.Add("folder:$($Matches[1].ToLowerInvariant())") }
    $keyPath = "$($Entry.Key)"
    if ($keyPath.StartsWith("$hive\", [System.StringComparison]::OrdinalIgnoreCase)) { $keyPath = $keyPath.Substring($hive.Length + 1) }
    if ($hive -eq "HKLM" -and $keyPath -notmatch '^SOFTWARE\\') { $keyPath = "SOFTWARE\$keyPath" }
    $keyPath = $keyPath.Trim('\').ToLowerInvariant()
    $name = "$($Entry.Name)".ToLowerInvariant()
    $command = "$($Entry.Command)".Trim()
    $unreadable = "$($Entry.Data)" -eq "Unreadable"
    $answer = "Unknown"
    foreach ($id in $ids) {
        if (-not $OnDisk.Parsed.ContainsKey($id)) { continue }
        $key = "$id|$keyPath"
        if ($OnDisk.Values.ContainsKey($key) -and $OnDisk.Values[$key].ContainsKey($name)) {
            # Data not in the dump: the name is all there is to compare
            if ($unreadable) { return "Yes" }
            foreach ($diskCommand in $OnDisk.Values[$key][$name]) { if ([string]::Equals($diskCommand, $command, [System.StringComparison]::OrdinalIgnoreCase)) { return "Yes" } }
            $answer = "Changed"
        }
        elseif ($answer -ne "Changed") { $answer = "No" }
    }
    return $answer
}

# Memory-Registry rows of the Run and RunOnce values (RunValue entries):
# "Run key value in memory: <name> [<key>]", PersistenceChange at the key's
# last write time (a Snapshot row when that is not valid); Details
# "Command=<data> | Key=<key> | Time=key last write | OnDisk=Yes|Changed|No|Unknown"
# (Get-DbgEngRunValueOnDisk, against the Registry-UserRunKey and
# Persistence-RunKeys rows already in the timeline: Memory is parsed last),
# then "Data=Unreadable" when the value's data is not in the dump; User: the
# SID of a user's hive.
function Add-DbgEngRunValueRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $timed = 0
    $snapshot = 0
    $entryList = @($Entries | Where-Object { $null -ne $_ })
    if ($entryList.Count -eq 0) { return (New-DbgEngRowCounts) }
    $onDisk = Get-DbgEngOnDiskRunKeys -Rows $script:timelineEntries
    foreach ($entry in $entryList) {
        $time = Get-MemoryEntryTime -Value "$($entry.LastWrite)" -LatestUtc $AcquisitionEndUtc.AddDays(1)
        $timeText = if ($null -ne $time.TimeUtc) { "key last write" } elseif ($time.Text) { "capture time (the key's last write time $($time.Text) is not valid)" } else { "capture time" }
        $data = $null
        if ("$($entry.Data)" -eq "Unreadable") { $data = "Unreadable" }
        $details = Format-DbgEngDetails ([ordered]@{
                Command = "$($entry.Command)"; Key = "$($entry.Key)"; Time = $timeText; OnDisk = (Get-DbgEngRunValueOnDisk -Entry $entry -OnDisk $onDisk); Data = $data
            })
        $row = Add-DbgEngEntryRow -Source $Source -EventType "PersistenceChange" -Description "Run key value in memory: $($entry.Name) [$($entry.Key)]" -User "$($entry.Sid)" `
            -Details $details -Time "$($entry.LastWrite)" -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
        if ($row.Timed) { $timed++ } else { $snapshot++ }
    }
    return (New-DbgEngRowCounts -Timed $timed -Snapshot $snapshot)
}

# --- WP5: console command history (item h) -----------------------------------------------

# Memory-ConsoleHistory rows: one Snapshot row at the capture time per
# command of a console host's history (lib\memory\TimelineDbgEng.Console.ps1;
# a command has no time of its own). Description "Console command in memory:
# <program> (conhost PID: n)"; Details "PID=<console host> |
# ProcessCreated=<its create time> | App=<program> | ClientPID=<n or empty> |
# Index=<0 = oldest> | HistoryCount=n | FoundBy=ConsoleHistoryList |
# Args=<command>": the command last, so text typed in it (which may hold
# " | Key=") never comes before the console host's own PID= and
# ProcessCreated=, by which the findings report leaves the collector's own
# console out. The User column: the console host's token SID. An entry
# without a command adds no row.
function Add-DbgEngConsoleRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $snapshot = 0
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $command = [string]$entry.Command
        if (-not $command) { continue }
        $app = [string]$entry.App
        $appText = if ($app) { $app } else { "unknown program" }
        $details = Format-DbgEngDetails ([ordered]@{
                PID = [string]$entry.PID; ProcessCreated = [string]$entry.ProcessCreated; App = $app; ClientPID = [string]$entry.ClientPID
                Index = [string]$entry.Index; HistoryCount = [string]$entry.HistoryCount; FoundBy = [string]$entry.FoundBy; Args = $command
            })
        $null = Add-DbgEngEntryRow -Source $Source -EventType "Snapshot" -Description "Console command in memory: $appText (conhost PID: $($entry.PID))" -User ([string]$entry.User) `
            -Details $details -Time "" -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
        $snapshot++
    }
    return (New-DbgEngRowCounts -Snapshot $snapshot)
}

# --- WP6: network connections (item i) ----------------------------------------------------

# Memory-Network rows (Add-MemoryPluginRows "windows.netscan", with the
# ARM64 fields in .ExtraDetails). Not built yet.
function Add-DbgEngNetRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# --- WP7: services (item j) ------------------------------------------------------------------

# Memory-Services rows (Add-MemoryPluginRows "windows.svcscan", with the
# ARM64 fields in .ExtraDetails). Not built yet.
function Add-DbgEngServiceRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}
