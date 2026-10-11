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

# Sets what the Proc entries say on the process (P) and command line (C)
# entries before their rows are made: .User (the token's SID), .ExtraDetails
# (appended to Details), and the full name and anomalies. Not built yet.
function Set-DbgEngProcessRowFields {
    param([object[]]$Processes, [object[]]$CommandLines)
    $null = $Processes, $CommandLines
}

# Account names the dump's logon sessions hold, registered as fallback
# names for the User column (Add-TimelineSidName without -ProfileList, so
# ProfileList and bam still win). -Entries: kind -> entries of this run's
# dump (empty when none was analyzed). Not built yet.
function Register-DbgEngLogonNames {
    param([System.Collections.IDictionary]$Entries)
    $null = $Entries
}

# --- WP2: DLLs and executable private memory (items c and f) ---------------------------

# Memory-Modules rows. Not built yet.
function Add-DbgEngModuleRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# Memory-PrivateCode rows. Not built yet.
function Add-DbgEngPrivateCodeRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# --- WP3: kernel drivers and handles (items d and e) -----------------------------------

# Memory-Drivers rows. Not built yet.
function Add-DbgEngDriverRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# Memory-Handles rows. Not built yet.
function Add-DbgEngHandleRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# --- WP4: registry hives in memory (item g) ---------------------------------------------

# Memory-Registry rows of the hives. Not built yet.
function Add-DbgEngHiveRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# Memory-Registry rows of the Run and RunOnce values (OnDisk= from the
# Registry-UserRunKey and Persistence-RunKeys rows already in the timeline:
# Memory is parsed last). Not built yet.
function Add-DbgEngRunValueRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
}

# --- WP5: console command history (item h) -----------------------------------------------

# Memory-ConsoleHistory rows. Not built yet.
function Add-DbgEngConsoleRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $null = $Entries, $Source, $CaptureTimeUtc, $AcquisitionEndUtc, $DumpPath
    return (New-DbgEngRowCounts)
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

# Memory-Services rows: the Service entries of the service control
# manager's list (lib\memory\TimelineDbgEng.Services.ps1) through
# Add-MemoryPluginRows "windows.svcscan", as Volatility's rows on x64 dumps
# ("Service in memory: <display> (<name>)", Snapshot at the capture time,
# "State=.. StartType=.. Binary=.. PID=n"), with the ARM64 fields appended in
# space style, the ones whose values can hold spaces last:
# " Type=.. Order=n FoundBy=ScmList[,Registry][ Anomaly=..][ Account=..]
# [ RegistryBinary=..][ ServiceDll=..]" (a field the entry does not have is
# left out). User: the token user of a running service's process (empty
# when not known). A record whose name was not in the dump is named by its
# address.
function Add-DbgEngServiceRows {
    param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
    $services = New-Object System.Collections.Generic.List[object]
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $extra = New-Object System.Collections.Generic.List[string]
        foreach ($pair in @(@("Type", "Type"), @("Order", "Order"), @("FoundBy", "FoundBy"), @("Anomaly", "Anomaly"), @("Account", "Account"),
                @("RegistryBinary", "RegistryBinary"), @("ServiceDll", "Dll"))) {
            $value = "$($entry.($pair[1]))".Trim()
            if ($value) { $extra.Add("$($pair[0])=$value") }
        }
        $name = [string]$entry.Name
        $display = [string]$entry.Display
        if (-not $name -and -not $display) { $display = "service record at $($entry.Offset)" }
        $services.Add([PSCustomObject]@{
                Name = $name; Display = $display; Binary = [string]$entry.Binary; State = [string]$entry.State; Start = [string]$entry.Start
                PID = [string]$entry.PID; User = [string]$entry.User; ExtraDetails = ($extra.ToArray() -join " ")
            })
    }
    if ($services.Count -eq 0) { return (New-DbgEngRowCounts) }
    $counts = Add-MemoryPluginRows -Plugin "windows.svcscan" -Source $Source -Entries $services.ToArray() -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath
    return (New-DbgEngRowCounts -Timed $counts.Timed -Snapshot $counts.Snapshot)
}
