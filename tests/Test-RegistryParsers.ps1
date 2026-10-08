# =============================================================
# Registry parser test
# Builds SOFTWARE, SYSTEM and NTUSER.DAT test hives with known values,
# runs timeline-builder.ps1 (-Sources Registry,ScheduledTasks) on them and
# checks the rows of the registry parsers: IFEO / SilentProcessExit,
# Winlogon, AppInit_DLLs, TaskCache, Defender exclusions, LSA packages,
# WDigest, Office TrustRecords / File MRU / OutlookSecureTempFolder,
# Terminal Server Client, Open/Save dialog MRUs and WordWheelQuery. The
# fixture collection also has a scheduled_tasks.csv (a task listed there
# gets no TaskCache rows) and a collection_log.txt (the collector's own
# Defender exclusion). Hives the builder leaves loaded fail the test and
# are unloaded.
#
# The hives are made by writing the values below a temporary key,
# HKCU\Software\TriageTimelineTest_<guid>, and saving its subkeys with
# reg save; the temporary key is deleted again (also on failure). That
# changes the registry, so the test only runs in GitHub Actions or with
# -AllowSystemChanges; otherwise it prints SKIP and exits 0. reg save and
# the builder's reg load need Administrator rights (GitHub Actions Windows
# runners are elevated); without them the test fails.
# Exit code 0 = pass (or skipped), 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-RegistryParsers.ps1 -AllowSystemChanges
# =============================================================
param(
    # Allow the temporary HKCU key outside GitHub Actions
    [switch]$AllowSystemChanges,
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

# FAIL line, plus an annotation in GitHub Actions
function Write-TestFailure {
    param([string]$Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-RegistryParsers.ps1::$Message" }
}

# Create a subkey (and its parents) below $Root and set its values; each
# value is @(name, data, Microsoft.Win32.RegistryValueKind)
function Set-TestKey {
    param([Microsoft.Win32.RegistryKey]$Root, [string]$Path, [object[]]$Values = @())
    $key = $Root.CreateSubKey($Path)
    try {
        foreach ($v in $Values) { $key.SetValue($v[0], $v[1], $v[2]) }
    }
    finally { $key.Close() }
}

# FILETIME bytes (little-endian) of a UTC time
function ConvertTo-FileTimeBytes {
    param([datetime]$Utc)
    return , [BitConverter]::GetBytes($Utc.ToFileTimeUtc())
}

# MRUListEx data: the value numbers, most recent first, then 0xFFFFFFFF
function New-MruListEx {
    param([int[]]$Order)
    $bytes = @()
    foreach ($n in $Order) { $bytes += [BitConverter]::GetBytes([int]$n) }
    $bytes += [BitConverter]::GetBytes([int]-1)
    return , [byte[]]$bytes
}

# Shell items for synthetic PIDLs: the My Computer root folder, a drive,
# and a file (0x32) or folder (0x31) entry whose long name is in a version 9
# 0xBEEF0004 extension block (the layout Get-ShellItemName reads)
function New-ShellItemMyComputer {
    $guid = New-Object System.Guid "20D04FE0-3AEA-1069-A2D8-08002B30309D"
    return , [byte[]](@(0x14, 0x00, 0x1F, 0x50) + $guid.ToByteArray())
}

function New-ShellItemDrive {
    param([string]$Drive)
    $item = New-Object byte[] 25
    $item[0] = 25
    $item[2] = 0x2F
    $text = [System.Text.Encoding]::ASCII.GetBytes($Drive)
    [Array]::Copy($text, 0, $item, 3, $text.Length)
    return , $item
}

function New-ShellItemEntry {
    param([string]$Name, [switch]$Folder)
    # Header: size, type, unknown, file size, DOS date/time, attributes,
    # short name (ASCII, NUL-terminated, padded to an even length)
    $short = [System.Text.Encoding]::ASCII.GetBytes($Name.ToUpperInvariant() + [char]0)
    if ($short.Length % 2) { $short = [byte[]]($short + [byte]0) }
    $header = New-Object byte[] (14 + $short.Length)
    $header[2] = $(if ($Folder) { 0x31 } else { 0x32 })
    [Array]::Copy($short, 0, $header, 14, $short.Length)
    # Extension block: size, version 9, signature 04 00 EF BE, then fields
    # up to offset 46, the long name (UTF-16, NUL) and a 2-byte offset
    $long = [System.Text.Encoding]::Unicode.GetBytes($Name + [char]0)
    $extension = New-Object byte[] (46 + $long.Length + 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]$extension.Length), 0, $extension, 0, 2)
    $extension[2] = 9
    $extension[4] = 0x04
    $extension[6] = 0xEF
    $extension[7] = 0xBE
    [Array]::Copy($long, 0, $extension, 46, $long.Length)
    $item = [byte[]]($header + $extension)
    [Array]::Copy([BitConverter]::GetBytes([uint16]$item.Length), 0, $item, 0, 2)
    return , $item
}

# PIDL: the items followed by a 2-byte 0
function New-Pidl {
    param([object[]]$Items)
    $bytes = @()
    foreach ($item in $Items) { $bytes += $item }
    $bytes += @(0, 0)
    return , [byte[]]$bytes
}

# TaskCache Actions value (format version 3) with one exec action
function New-TaskActions {
    param([string]$Command, [string]$Arguments)
    $bytes = @(3, 0)
    foreach ($text in @("Author")) {
        $utf16 = [System.Text.Encoding]::Unicode.GetBytes($text)
        $bytes += [BitConverter]::GetBytes([uint32]$utf16.Length) + $utf16
    }
    $bytes += @(0x66, 0x66)
    foreach ($text in @("", $Command, $Arguments, "")) {
        $utf16 = [System.Text.Encoding]::Unicode.GetBytes($text)
        $bytes += [BitConverter]::GetBytes([uint32]$utf16.Length)
        if ($utf16.Length) { $bytes += $utf16 }
    }
    $bytes += @(0, 0)
    return , [byte[]]$bytes
}

# TaskCache Actions value (format version 3) with one COM handler action
# whose data size (0x80000000) runs past the end of the value
function New-TaskComActions {
    param([string]$ClassId)
    $bytes = @(3, 0) + [BitConverter]::GetBytes([uint32]0) + @(0x77, 0x77) + [BitConverter]::GetBytes([uint32]0)
    $bytes += (New-Object System.Guid $ClassId).ToByteArray()
    $bytes += [BitConverter]::GetBytes([uint32]2147483648)
    return , [byte[]]$bytes
}

# TaskCache DynamicInfo value, 36-byte form: magic 3, created, last run,
# task state, last error code, last successful run (times may be $null)
function New-TaskDynamicInfo {
    param($Created, $LastRun, [uint32]$ErrorCode = 0, $LastSuccess)
    $data = New-Object byte[] 36
    $data[0] = 3
    foreach ($field in @(@(4, $Created), @(12, $LastRun), @(28, $LastSuccess))) {
        if ($null -ne $field[1]) { [Array]::Copy([BitConverter]::GetBytes(([datetime]$field[1]).ToFileTimeUtc()), 0, $data, $field[0], 8) }
    }
    [Array]::Copy([BitConverter]::GetBytes($ErrorCode), 0, $data, 24, 4)
    return , $data
}

# Fixed times stored inside value data (UTC)
$script:FixtureTimes = @{
    TaskRegistered        = [datetime]::SpecifyKind([datetime]"2024-01-02 03:04:05", [System.DateTimeKind]::Utc)
    TaskLastRun           = [datetime]::SpecifyKind([datetime]"2024-01-03 04:05:06", [System.DateTimeKind]::Utc)
    ListedRegistered      = [datetime]::SpecifyKind([datetime]"2024-01-04 01:02:03", [System.DateTimeKind]::Utc)
    ListedLastRun         = [datetime]::SpecifyKind([datetime]"2024-01-04 02:03:04", [System.DateTimeKind]::Utc)
    UnlistedRegistered    = [datetime]::SpecifyKind([datetime]"2024-01-04 05:06:07", [System.DateTimeKind]::Utc)
    FolderTaskRegistered  = [datetime]::SpecifyKind([datetime]"2024-01-04 08:09:10", [System.DateTimeKind]::Utc)
    FolderTaskLastRun     = [datetime]::SpecifyKind([datetime]"2024-01-04 09:10:11", [System.DateTimeKind]::Utc)
    FolderTaskLastSuccess = [datetime]::SpecifyKind([datetime]"2024-01-04 07:08:09", [System.DateTimeKind]::Utc)
    TrustMacros           = [datetime]::SpecifyKind([datetime]"2024-01-05 06:07:08", [System.DateTimeKind]::Utc)
    TrustEditing          = [datetime]::SpecifyKind([datetime]"2024-01-05 07:08:09", [System.DateTimeKind]::Utc)
    OfficeFileOpened      = [datetime]::SpecifyKind([datetime]"2024-01-06 08:09:10", [System.DateTimeKind]::Utc)
    OfficeFolder          = [datetime]::SpecifyKind([datetime]"2024-01-06 08:09:11", [System.DateTimeKind]::Utc)
}
$script:HiddenTaskId = "{6A1F0C3E-0D2B-4C55-9E7A-0B1C2D3E4F50}"
$script:ListedTaskId = "{7B2E1D4F-1E3C-4D66-8F8B-1C2D3E4F5061}"
$script:UnlistedTaskId = "{8C3F2E50-2F4D-4E77-908C-2D3E4F506172}"
$script:FolderTaskId = "{9D403F61-3051-4F88-A19D-3E4F50617283}"
$script:ComHandlerId = "0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9"
# The collector's output folder, with a non-ASCII character (o with
# umlaut) that the two PowerShell editions write to collection_log.txt in
# different encodings
$script:CollectorOutput = "C:\TriageOut\J$([char]0x00F6)rg\TriageCollection_2026-01-01_00-00"

# Write the test values. $Software, $System and $NtUser are the keys that
# become the roots of the SOFTWARE, SYSTEM and NTUSER.DAT hives.
function New-TestRegistryFixture {
    param([Microsoft.Win32.RegistryKey]$Software, [Microsoft.Win32.RegistryKey]$System, [Microsoft.Win32.RegistryKey]$NtUser)
    $sz = [Microsoft.Win32.RegistryValueKind]::String
    $dword = [Microsoft.Win32.RegistryValueKind]::DWord
    $qword = [Microsoft.Win32.RegistryValueKind]::QWord
    $multi = [Microsoft.Win32.RegistryValueKind]::MultiString
    $binary = [Microsoft.Win32.RegistryValueKind]::Binary
    $times = $script:FixtureTimes

    # --- SOFTWARE: IFEO, SilentProcessExit, Winlogon, AppInit_DLLs ---
    $ifeo = "Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    Set-TestKey -Root $Software -Path "$ifeo\sethc.exe" -Values @(, @("Debugger", "C:\Windows\System32\cmd.exe", $sz))
    Set-TestKey -Root $Software -Path "$ifeo\notepad.exe" -Values @(, @("GlobalFlag", 0x200, $dword))
    Set-TestKey -Root $Software -Path "$ifeo\winword.exe" -Values @(, @("MitigationOptions", [long]256, $qword))
    Set-TestKey -Root $Software -Path "$ifeo\calc.exe" -Values @(, @("UseFilter", 1, $dword))
    Set-TestKey -Root $Software -Path "$ifeo\calc.exe\filter1" -Values @(@("FilterFullPath", "C:\Tools\calc.exe", $sz), @("Debugger", "C:\ProgramData\calcdebug.exe", $sz))
    Set-TestKey -Root $Software -Path "Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Values @(
        @("MonitorProcess", "C:\ProgramData\monitor.exe", $sz), @("ReportingMode", 1, $dword))
    # ReportingMode 2 writes a dump and does not launch the monitor; no
    # GlobalFlag 0x200, so not active
    Set-TestKey -Root $Software -Path "Microsoft\Windows NT\CurrentVersion\SilentProcessExit\mspaint.exe" -Values @(
        @("MonitorProcess", "C:\ProgramData\monitor2.exe", $sz), @("ReportingMode", 2, $dword), @("LocalDumpFolder", "C:\ProgramData\dumps", $sz))
    Set-TestKey -Root $Software -Path "Microsoft\Windows NT\CurrentVersion\Winlogon" -Values @(
        @("Shell", "explorer.exe, C:\ProgramData\shell.exe", $sz), @("Userinit", "C:\Windows\system32\userinit.exe,", $sz))
    Set-TestKey -Root $Software -Path "Microsoft\Windows NT\CurrentVersion\Windows" -Values @(
        @("AppInit_DLLs", "C:\ProgramData\appinit.dll", $sz), @("LoadAppInit_DLLs", 1, $dword))
    Set-TestKey -Root $Software -Path "Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Values @(
        @("AppInit_DLLs", "", $sz), @("LoadAppInit_DLLs", 0, $dword))

    # --- SOFTWARE: TaskCache. No SD value: \HiddenTask (hidden task) and
    #     \HiddenFolder (hidden folder); \Folder has one. The collection's
    #     scheduled_tasks.csv lists \Folder\ListedTask, so its TaskCache
    #     times are left to the ScheduledTasks source. ---
    $cache = "Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
    $sd = [byte[]](1, 0, 4, 0x80, 0x14, 0, 0, 0)
    Set-TestKey -Root $Software -Path "$cache\Tree\HiddenTask" -Values @(@("Id", $script:HiddenTaskId, $sz), @("Index", 3, $dword))
    Set-TestKey -Root $Software -Path "$cache\Tree\Folder" -Values @(, @("SD", $sd, $binary))
    Set-TestKey -Root $Software -Path "$cache\Tree\Folder\ListedTask" -Values @(
        @("Id", $script:ListedTaskId, $sz), @("Index", 1, $dword), @("SD", $sd, $binary))
    Set-TestKey -Root $Software -Path "$cache\Tree\Folder\UnlistedTask" -Values @(
        @("Id", $script:UnlistedTaskId, $sz), @("Index", 1, $dword), @("SD", $sd, $binary))
    Set-TestKey -Root $Software -Path "$cache\Tree\HiddenFolder\InnerTask" -Values @(
        @("Id", $script:FolderTaskId, $sz), @("Index", 1, $dword), @("SD", $sd, $binary))
    Set-TestKey -Root $Software -Path "$cache\Tasks\$($script:HiddenTaskId)" -Values @(
        @("Path", "\HiddenTask", $sz), @("Author", "TESTHOST\tester", $sz),
        @("Actions", (New-TaskActions -Command "C:\ProgramData\updater.exe" -Arguments "-silent"), $binary),
        @("DynamicInfo", (New-TaskDynamicInfo -Created $times.TaskRegistered -LastRun $times.TaskLastRun), $binary))
    Set-TestKey -Root $Software -Path "$cache\Tasks\$($script:ListedTaskId)" -Values @(
        @("Path", "\Folder\ListedTask", $sz),
        @("DynamicInfo", (New-TaskDynamicInfo -Created $times.ListedRegistered -LastRun $times.ListedLastRun), $binary))
    # A malformed COM handler action must not stop the other tasks
    Set-TestKey -Root $Software -Path "$cache\Tasks\$($script:UnlistedTaskId)" -Values @(
        @("Path", "\Folder\UnlistedTask", $sz), @("Actions", (New-TaskComActions $script:ComHandlerId), $binary),
        @("DynamicInfo", (New-TaskDynamicInfo -Created $times.UnlistedRegistered), $binary))
    Set-TestKey -Root $Software -Path "$cache\Tasks\$($script:FolderTaskId)" -Values @(
        @("Path", "\HiddenFolder\InnerTask", $sz),
        @("DynamicInfo", (New-TaskDynamicInfo -Created $times.FolderTaskRegistered -LastRun $times.FolderTaskLastRun -ErrorCode 1 -LastSuccess $times.FolderTaskLastSuccess), $binary))

    # --- SOFTWARE: Defender exclusions (with the collector's own) ---
    Set-TestKey -Root $Software -Path "Microsoft\Windows Defender\Exclusions\Paths" -Values @(
        @("C:\Users\Public\Tools", 0, $dword), @($script:CollectorOutput, 0, $dword),
        @("C:\TriageOut\TriageCollection_2025-12-31_23-59", 0, $dword))
    Set-TestKey -Root $Software -Path "Microsoft\Windows Defender\Exclusions\Extensions" -Values @(, @(".dat", 0, $dword))
    Set-TestKey -Root $Software -Path "Policies\Microsoft\Windows Defender\Exclusions\Paths" -Values @(, @("D:\Shared", "0", $sz))

    # --- SYSTEM: LSA packages, WDigest ---
    Set-TestKey -Root $System -Path "Select" -Values @(@("Current", 1, $dword), @("Default", 1, $dword))
    Set-TestKey -Root $System -Path "ControlSet001\Control\Lsa" -Values @(
        @("Authentication Packages", [string[]]@("msv1_0"), $multi),
        @("Notification Packages", [string[]]@("scecli", "pwfilter"), $multi),
        @("Security Packages", [string[]]@('""', "testssp"), $multi))
    Set-TestKey -Root $System -Path "ControlSet001\Control\Lsa\OSConfig" -Values @(
        , @("Security Packages", [string[]]@("kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "osconfigssp"), $multi))
    Set-TestKey -Root $System -Path "ControlSet001\Control\SecurityProviders\WDigest" -Values @(, @("UseLogonCredential", 1, $dword))

    # --- NTUSER: Office ---
    $office = "Software\Microsoft\Office\16.0"
    $trustTail = [byte[]](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    Set-TestKey -Root $NtUser -Path "$office\Word\Security\Trusted Documents\TrustRecords" -Values @(
        @("%USERPROFILE%/Downloads/invoice.docm", [byte[]]((ConvertTo-FileTimeBytes $times.TrustMacros) + $trustTail + @(0xFF, 0xFF, 0xFF, 0x7F)), $binary),
        @("%USERPROFILE%/Documents/notes.docx", [byte[]]((ConvertTo-FileTimeBytes $times.TrustEditing) + $trustTail + @(1, 0, 0, 0)), $binary))
    $fileTime = "{0:X16}" -f $times.OfficeFileOpened.ToFileTimeUtc()
    $folderTime = "{0:X16}" -f $times.OfficeFolder.ToFileTimeUtc()
    Set-TestKey -Root $NtUser -Path "$office\Excel\User MRU\ADAL_TEST\File MRU" -Values @(
        @("Item 1", "[F00000000][T$fileTime][O00000000]*C:\Users\testuser\Documents\budget.xlsx", $sz),
        @("FOLDERID_Documents", "C:\Users\testuser\Documents\", $sz))
    Set-TestKey -Root $NtUser -Path "$office\Excel\User MRU\ADAL_TEST\Place MRU" -Values @(
        , @("Item 1", "[F00000000][T$folderTime][O00000000]*C:\Users\testuser\Documents\", $sz))
    Set-TestKey -Root $NtUser -Path "$office\Outlook\Security" -Values @(
        , @("OutlookSecureTempFolder", "C:\Users\testuser\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\TEST1234\", $sz))

    # --- NTUSER: Remote Desktop client ---
    Set-TestKey -Root $NtUser -Path "Software\Microsoft\Terminal Server Client\Default" -Values @(
        @("MRU0", "10.20.30.40", $sz), @("MRU1", "fileserver.example.test", $sz))
    Set-TestKey -Root $NtUser -Path "Software\Microsoft\Terminal Server Client\Servers\10.20.30.40" -Values @(
        @("UsernameHint", "EXAMPLE\admin", $sz), @("CertHash", [byte[]](1, 2, 3, 4), $binary))

    # --- NTUSER: Open/Save dialogs and Explorer search ---
    $comDlg = "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    $filePidl = New-Pidl @((New-ShellItemMyComputer), (New-ShellItemDrive "C:\"), (New-ShellItemEntry "Data" -Folder), (New-ShellItemEntry "report.txt"))
    Set-TestKey -Root $NtUser -Path "$comDlg\OpenSavePidlMRU\*" -Values @(@("0", $filePidl, $binary), @("MRUListEx", (New-MruListEx @(0)), $binary))
    Set-TestKey -Root $NtUser -Path "$comDlg\OpenSavePidlMRU\txt" -Values @(@("0", $filePidl, $binary), @("MRUListEx", (New-MruListEx @(0)), $binary))
    $folderPidl = New-Pidl @((New-ShellItemMyComputer), (New-ShellItemDrive "C:\"), (New-ShellItemEntry "Data" -Folder))
    $lastVisited = [byte[]]([System.Text.Encoding]::Unicode.GetBytes("notepad.exe" + [char]0) + $folderPidl)
    Set-TestKey -Root $NtUser -Path "$comDlg\LastVisitedPidlMRU" -Values @(@("0", $lastVisited, $binary), @("MRUListEx", (New-MruListEx @(0)), $binary))
    Set-TestKey -Root $NtUser -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" -Values @(
        @("0", [System.Text.Encoding]::Unicode.GetBytes("quarterly report" + [char]0), $binary), @("MRUListEx", (New-MruListEx @(0)), $binary))
}

# Rows the builder must produce from the fixture. Time = exact UTC text for
# times stored in value data, $null for key last-write times (checked
# against the test's time window). Details = substrings that must appear.
function Get-ExpectedRegistryRows {
    $times = @{}
    foreach ($name in $script:FixtureTimes.Keys) {
        $times[$name] = $script:FixtureTimes[$name].ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $ifeo = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $lastSuccess = $script:FixtureTimes.FolderTaskLastSuccess.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
    # Rows timed with a key's last-write time must say so in Time= (the
    # fallback, the hive file time, falls inside the test window too)
    $rows = @(
        @("Registry-IFEO", "PersistenceChange", "IFEO Debugger set for sethc.exe (accessibility program): C:\Windows\System32\cmd.exe", $null, "",
            @("AccessibilityProgram=yes", "Key=$ifeo\sethc.exe", "Time=key last write")),
        @("Registry-IFEO", "PersistenceChange", "IFEO Debugger set for calc.exe: C:\ProgramData\calcdebug.exe", $null, "",
            @("FilterFullPath=C:\Tools\calc.exe", "Key=$ifeo\calc.exe\filter1", "Time=key last write")),
        @("Registry-SilentProcessExit", "PersistenceChange", "SilentProcessExit monitor process for notepad.exe: C:\ProgramData\monitor.exe", $null, "",
            @("ReportingMode=1 (launch monitor process)", "GlobalFlag=0x00000200", "Active=yes", "Time=key last write")),
        @("Registry-SilentProcessExit", "PersistenceChange", "SilentProcessExit dump on exit for mspaint.exe: C:\ProgramData\dumps", $null, "",
            @("MonitorProcess=C:\ProgramData\monitor2.exe", "ReportingMode=2 (local dump)", "GlobalFlag=not set", "Active=no (IFEO GlobalFlag lacks 0x200)", "Time=key last write")),
        @("Registry-Winlogon", "PersistenceChange", "Non-default Winlogon Shell: explorer.exe, C:\ProgramData\shell.exe", $null, "",
            @("Default=explorer.exe", "Time=Winlogon key last write")),
        @("Registry-AppInitDLLs", "PersistenceChange", "AppInit_DLLs set (loading enabled): C:\ProgramData\appinit.dll", $null, "",
            @("LoadAppInit_DLLs=1", "Key=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "Time=Windows key last write")),
        @("Registry-TaskCache", "ScheduledTaskChange", "Hidden scheduled task (no SD value in TaskCache\Tree): \HiddenTask", $null, "",
            @("Actions=C:\ProgramData\updater.exe -silent", "Index=3", "Time=TaskCache\Tree key last write")),
        @("Registry-TaskCache", "ScheduledTaskChange", "Scheduled task registered: \HiddenTask", $times.TaskRegistered, "",
            @("Hidden=yes (no SD value in TaskCache\Tree)", "Author=TESTHOST\tester", "Time=TaskCache DynamicInfo created (registered) time")),
        @("Registry-TaskCache", "Execution", "Scheduled task last run: \HiddenTask", $times.TaskLastRun, "",
            @("Actions=C:\ProgramData\updater.exe -silent", "LastErrorCode=0x00000000", "Time=TaskCache DynamicInfo last run time")),
        @("Registry-TaskCache", "ScheduledTaskChange", "Scheduled task registered: \Folder\UnlistedTask", $times.UnlistedRegistered, "",
            @("Id=$($script:UnlistedTaskId)", "Actions=COM handler {$($script:ComHandlerId)}")),
        @("Registry-TaskCache", "ScheduledTaskChange", "Hidden scheduled task folder (no SD value in TaskCache\Tree): \HiddenFolder", $null, "",
            @("Tasks=\HiddenFolder\InnerTask", "Time=TaskCache\Tree key last write")),
        @("Registry-TaskCache", "ScheduledTaskChange", "Scheduled task registered: \HiddenFolder\InnerTask", $times.FolderTaskRegistered, "",
            @("Hidden=yes (folder \HiddenFolder has no SD value in TaskCache\Tree)")),
        @("Registry-TaskCache", "Execution", "Scheduled task last run: \HiddenFolder\InnerTask", $times.FolderTaskLastRun, "",
            @("LastErrorCode=0x00000001", "LastSuccessfulRunUtc=$lastSuccess")),
        @("Registry-DefenderExclusions", "SecurityAlert", "Defender exclusion in effect (Paths): C:\Users\Public\Tools", $null, "",
            @("Key=HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", "Time=Exclusions\Paths key last write", "this exclusion is older")),
        @("Registry-DefenderExclusions", "Snapshot", "Defender exclusion in effect (Paths): $($script:CollectorOutput) (triage collector's own temporary exclusion)", $null, "",
            @("Origin=triage collector: output folder of this collection, excluded while the collector ran; collection_log.txt records that it was removed",
                "Time=Exclusions\Paths key last write (when the triage collector added this exclusion)")),
        @("Registry-DefenderExclusions", "SecurityAlert", "Defender exclusion in effect (Paths): C:\TriageOut\TriageCollection_2025-12-31_23-59", $null, "",
            @("so this one was left behind", "Time=Exclusions\Paths key last write")),
        @("Registry-DefenderExclusions", "SecurityAlert", "Defender exclusion in effect (Extensions): .dat", $null, "",
            @("Type=Extensions", "Time=Exclusions\Extensions key last write")),
        @("Registry-DefenderExclusions", "SecurityAlert", "Defender exclusion in effect (Paths): D:\Shared", $null, "",
            @("Policy=yes (Group Policy)", "Key=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths", "Time=Exclusions\Paths key last write")),
        @("Registry-LSA", "PersistenceChange", "Non-default LSA Notification Package (password filter): pwfilter", $null, "",
            @("AllEntries=scecli; pwfilter", "Key=HKLM\SYSTEM\ControlSet001\Control\Lsa", "Time=Lsa key last write")),
        @("Registry-LSA", "PersistenceChange", "Non-default LSA Security Package: testssp", $null, "",
            @("Value=Security Packages", "Time=Lsa key last write")),
        @("Registry-LSA", "PersistenceChange", "Non-default LSA Security Package (OSConfig): osconfigssp", $null, "",
            @("Key=HKLM\SYSTEM\ControlSet001\Control\Lsa\OSConfig", "Time=Lsa\OSConfig key last write")),
        @("Registry-WDigest", "SecurityAlert", "WDigest UseLogonCredential=1: Windows keeps clear-text passwords in LSASS memory", $null, "",
            @("Key=HKLM\SYSTEM\ControlSet001\Control\SecurityProviders\WDigest", "Time=WDigest key last write")),
        @("Registry-TrustRecords", "Execution", "Office macros enabled on document (Word): %USERPROFILE%\Downloads\invoice.docm", $times.TrustMacros, "testuser",
            @("Trust=macros (active content) enabled", "Document=%USERPROFILE%/Downloads/invoice.docm", "Time=TrustRecords FILETIME")),
        @("Registry-TrustRecords", "FileAccess", "Office editing enabled on document (Word): %USERPROFILE%\Documents\notes.docx", $times.TrustEditing, "testuser",
            @("Trust=editing enabled", "Path=%USERPROFILE%\Documents\notes.docx")),
        @("Registry-OfficeMRU", "FileAccess", "Office recent file (Excel): C:\Users\testuser\Documents\budget.xlsx", $times.OfficeFileOpened, "testuser",
            @("Item=Item 1", "Account=ADAL_TEST", "Time=MRU item time")),
        @("Registry-OfficeMRU", "FileAccess", "Office recent folder (Excel): C:\Users\testuser\Documents\", $times.OfficeFolder, "testuser",
            @("Key=HKCU\Software\Microsoft\Office\16.0\Excel\User MRU\ADAL_TEST\Place MRU")),
        @("Registry-OutlookSecureTemp", "Snapshot", "Outlook attachment temp folder (OutlookSecureTempFolder): C:\Users\testuser\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\TEST1234\", $null, "testuser",
            @("Version=16.0", "Time=Outlook\Security key last write")),
        @("Registry-RDPClient", "NetworkConnection", "Outbound RDP target (Remote Desktop MRU): 10.20.30.40", $null, "testuser",
            @("MRU=MRU0", "Time=Terminal Server Client\Default key last write; MRU position 1 (most recent entry)")),
        @("Registry-RDPClient", "NetworkConnection", "Outbound RDP target (Remote Desktop MRU): fileserver.example.test", $null, "testuser",
            @("Time=Terminal Server Client\Default key last write; MRU position 2")),
        @("Registry-RDPClient", "NetworkConnection", "Outbound RDP target (saved server, user EXAMPLE\admin): 10.20.30.40", $null, "testuser",
            @("UsernameHint=EXAMPLE\admin", "Time=Servers\<host> key last write")),
        @("Registry-OpenSaveMRU", "FileAccess", "Open/Save dialog item: C:\Data\report.txt", $null, "testuser",
            @("Extension=txt", "MRUIndex=*\0", "Time=OpenSavePidlMRU\* key last write; MRU position 1")),
        @("Registry-LastVisitedMRU", "FileAccess", "Open/Save dialog folder last used by notepad.exe: C:\Data", $null, "testuser",
            @("Program=notepad.exe", "Time=LastVisitedPidlMRU key last write; MRU position 1")),
        @("Registry-WordWheelQuery", "FileAccess", "Explorer search: quarterly report", $null, "testuser",
            @("MRUIndex=0", "Time=key last write; MRU position 1 (most recent entry)"))
    )
    foreach ($r in $rows) {
        [PSCustomObject]@{ Source = $r[0]; EventType = $r[1]; Description = $r[2]; Time = $r[3]; User = $r[4]; Details = $r[5] }
    }
}

# Sources of the registry rows covered by this test
$script:TestedSources = @("Registry-IFEO", "Registry-SilentProcessExit", "Registry-Winlogon", "Registry-AppInitDLLs",
    "Registry-TaskCache", "Registry-DefenderExclusions", "Registry-LSA", "Registry-WDigest", "Registry-TrustRecords",
    "Registry-OfficeMRU", "Registry-OutlookSecureTemp", "Registry-RDPClient", "Registry-OpenSaveMRU",
    "Registry-LastVisitedMRU", "Registry-WordWheelQuery")

# Compare the timeline rows (objects with Timestamp, Source, EventType,
# Description, User, Details) with the expected rows. Rows of the tested
# sources that are not expected (e.g. a default LSA package, a hidden-task
# row for a task with SD, a TaskCache row for the task scheduled_tasks.csv
# lists) and rows timed with the hive file time are failures too. The task
# listed in scheduled_tasks.csv must have exactly one registered and one
# last-run row (from the ScheduledTasks source). Returns the number of
# failures.
function Test-RegistryRows {
    param([object[]]$Rows, [datetime]$WindowStart, [datetime]$WindowEnd)
    $failures = 0
    $f = "yyyy-MM-dd HH:mm:ss.fff"
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $matched = @{}
    foreach ($exp in (Get-ExpectedRegistryRows)) {
        $hits = @($Rows | Where-Object { $_.Source -eq $exp.Source -and $_.EventType -eq $exp.EventType -and $_.Description -ceq $exp.Description })
        if ($hits.Count -ne 1) {
            Write-TestFailure "$($hits.Count) rows (expected 1): [$($exp.Source)] $($exp.Description)"
            $failures++
            continue
        }
        $row = $hits[0]
        $matched[[string]$row.Source + "`t" + $row.Description] = $true
        $problems = @()
        if ($exp.Time) {
            if ($row.Timestamp -ne $exp.Time) { $problems += "Timestamp $($row.Timestamp) (expected $($exp.Time))" }
        }
        else {
            # Key last-write time: set while the test wrote the fixture
            $rowTime = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($row.Timestamp, $f, $invariant, [System.Globalization.DateTimeStyles]::None, [ref]$rowTime) -or
                $rowTime -lt $WindowStart -or $rowTime -gt $WindowEnd) {
                $problems += "Timestamp $($row.Timestamp) not within the test run ($($WindowStart.ToString($f, $invariant)) - $($WindowEnd.ToString($f, $invariant)) UTC)"
            }
        }
        if ($row.User -ne $exp.User) { $problems += "User '$($row.User)' (expected '$($exp.User)')" }
        foreach ($part in $exp.Details) {
            if (-not $row.Details.Contains($part)) { $problems += "Details lack '$part' (Details: $($row.Details))" }
        }
        if ($problems.Count -gt 0) {
            Write-TestFailure "[$($exp.Source)] $($exp.Description): $($problems -join '; ')"
            $failures++
        }
        else {
            Write-Host "PASS: [$($exp.Source)] $($exp.Description)" -ForegroundColor Green
        }
    }
    foreach ($row in $Rows) {
        if ($script:TestedSources -notcontains $row.Source) { continue }
        if ($row.Details.Contains("hive file time")) {
            Write-TestFailure "row timed with the hive file time instead of its own time: [$($row.Source)] $($row.Description)"
            $failures++
        }
        if ($matched.ContainsKey([string]$row.Source + "`t" + $row.Description)) { continue }
        Write-TestFailure "unexpected row: [$($row.Source)] $($row.EventType) $($row.Description)"
        $failures++
    }
    foreach ($what in @("registered", "last run")) {
        $description = "Scheduled task ${what}: \Folder\ListedTask"
        $hits = @($Rows | Where-Object { $_.Description -ceq $description })
        if ($hits.Count -ne 1 -or $hits[0].Source -ne "ScheduledTasks") {
            Write-TestFailure "$($hits.Count) row(s) '$description' from $(@($hits | ForEach-Object { $_.Source }) -join ', ') (expected one, from scheduled_tasks.csv)"
            $failures++
        }
        else { Write-Host "PASS: one row '$description' (scheduled_tasks.csv; TaskCache adds none)" -ForegroundColor Green }
    }
    return $failures
}

# scheduled_tasks.csv of the fixture collection (written by the live
# collector): lists \Folder\ListedTask with a last run time
function New-TestScheduledTasksCsv {
    param([string]$Path)
    $f = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $row = [PSCustomObject]@{
        TaskName = "ListedTask"; TaskPath = "\Folder\"; State = "Ready"; Author = "TESTHOST\tester"; UserId = "SYSTEM"
        Actions = "C:\ProgramData\listed.exe"; Triggers = ""
        RegistrationDateUtc = $script:FixtureTimes.ListedRegistered.ToString($f, $invariant)
        LastRunTimeUtc = $script:FixtureTimes.ListedLastRun.ToString($f, $invariant)
        NextRunTimeUtc = ""; LastTaskResult = "0"
    }
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    $row | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

# collection_log.txt of the fixture collection: the output folder and the
# removal of the Defender exclusion, written in the encoding the OTHER
# PowerShell edition's Add-Content uses (ANSI from Windows PowerShell 5.1,
# UTF-8 without BOM from PowerShell 7), so the builder must not rely on its
# own edition's default
function New-TestCollectionLog {
    param([string]$Path)
    $text = "[2026-01-01 00:00:00] === Windows Forensic Triage Collection Started ===`r`n" +
        "[2026-01-01 00:00:00] Output directory: $($script:CollectorOutput)`r`n" +
        "[2026-01-01 00:00:00] OK: Temporary Defender exclusion added for output path (will be removed at end).`r`n" +
        "[2026-01-01 00:10:00] Removing temporary Defender exclusion...`r`n" +
        "[2026-01-01 00:10:00] OK: Defender exclusion removed.`r`n"
    $encoding = if ($PSVersionTable.PSEdition -eq "Core") { [System.Text.Encoding]::GetEncoding(1252) } else { New-Object System.Text.UTF8Encoding($false) }
    [System.IO.File]::WriteAllText($Path, $text, $encoding)
}

# Hives the builder loads (HKLM\TEMP_TL*) and their temp copies
# (%TEMP%\TimelineHive_*)
function Get-BuilderHiveState {
    return [PSCustomObject]@{
        Hives = @([Microsoft.Win32.Registry]::LocalMachine.GetSubKeyNames() | Where-Object { $_ -like "TEMP_TL*" })
        Dirs  = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "TimelineHive_*" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
}

# Unload the hives and delete the temp copies that were not there in
# $Before (Get-BuilderHiveState); returns what was left behind
function Remove-BuilderHiveLeftovers {
    param($Before)
    $now = Get-BuilderHiveState
    $left = @()
    foreach ($hive in $now.Hives) {
        if ($Before.Hives -contains $hive) { continue }
        $left += "loaded hive HKLM\$hive"
        [gc]::Collect()
        try { $null = & reg unload "HKLM\$hive" 2>&1 }
        catch { Write-Host "WARNING: could not unload HKLM\$hive : $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    foreach ($dir in $now.Dirs) {
        if ($Before.Dirs -contains $dir) { continue }
        $left += "temp hive copy $dir"
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $left
}

# =============================================================
# Main
# =============================================================
if (-not $env:GITHUB_ACTIONS -and -not $AllowSystemChanges) {
    Write-Host "SKIP: this test writes a temporary HKCU key and saves it with reg save; run it with -AllowSystemChanges (as Administrator) or in GitHub Actions" -ForegroundColor Yellow
    exit 0
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-TestFailure "this test needs Administrator rights (reg save, and reg load in the builder)"
    exit 1
}

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$powershellExe = (Get-Process -Id $PID).Path
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("registry-test-" + [guid]::NewGuid().ToString("N"))
$collection = Join-Path $workDir (Split-Path $script:CollectorOutput -Leaf)
$testKeyPath = "Software\TriageTimelineTest_" + [guid]::NewGuid().ToString("N")
$reportsDir = Join-Path $repoRoot "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$failures = 0
$hivesBefore = $null
try {
    $windowStart = [datetime]::UtcNow.AddMinutes(-2)
    New-Item -ItemType Directory -Path (Join-Path $collection "Registry\testuser") -Force | Out-Null

    # Values below the temporary key, saved as three hives
    Write-Host "Writing test values below HKCU\$testKeyPath ..."
    $baseKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKeyPath)
    $hiveKeys = @{}
    try {
        foreach ($name in @("SOFTWARE", "SYSTEM", "NTUSER")) { $hiveKeys[$name] = $baseKey.CreateSubKey($name) }
        New-TestRegistryFixture -Software $hiveKeys["SOFTWARE"] -System $hiveKeys["SYSTEM"] -NtUser $hiveKeys["NTUSER"]
    }
    finally {
        foreach ($k in $hiveKeys.Values) { $k.Close() }
        $baseKey.Close()
    }
    $hiveFiles = [ordered]@{
        SOFTWARE = Join-Path $collection "Registry\SOFTWARE"
        SYSTEM   = Join-Path $collection "Registry\SYSTEM"
        NTUSER   = Join-Path $collection "Registry\testuser\NTUSER.DAT"
    }
    foreach ($name in $hiveFiles.Keys) {
        $saveOutput = & reg save "HKCU\$testKeyPath\$name" $hiveFiles[$name] /y 2>&1
        if ($LASTEXITCODE -ne 0) { throw "reg save of $name failed: $saveOutput" }
    }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKeyPath)

    # Collector metadata: the Defender exclusion of the output folder is
    # recognised from collection_log.txt, the scheduled task list decides
    # which TaskCache times are new to the timeline
    $info = [ordered]@{
        SchemaVersion = 1; ComputerName = "TESTHOST"; CollectorUser = "TESTHOST\tester"; Mode = "Live"
        TargetDrive = "C"; TargetRoot = "C:\"; CollectionStartUtc = "2026-01-01T00:00:00.0000000Z"
        CollectorTimeZoneId = "UTC"; CollectorCulture = "en-US"; TargetTimeZoneId = "UTC"
    }
    [System.IO.File]::WriteAllText((Join-Path $collection "collection_info.json"), ($info | ConvertTo-Json))
    New-TestCollectionLog -Path (Join-Path $collection "collection_log.txt")
    New-TestScheduledTasksCsv -Path (Join-Path $collection "Persistence\scheduled_tasks.csv")

    $timelineCsv = Join-Path $workDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $hivesBefore = Get-BuilderHiveState
    $builderOutput = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath $collection -Sources "Registry,ScheduledTasks" -OutputFile $timelineCsv -NoExcel -NoReport -Viewer None 2>&1
    $windowEnd = [datetime]::UtcNow.AddMinutes(2)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestFailure "the builder exited with code $LASTEXITCODE or wrote no timeline"
        exit 1
    }
    # Every hive must be unloaded again (open key handles block reg unload)
    # and its temp copy deleted; leftovers are cleaned up here
    foreach ($line in @($builderOutput | Where-Object { "$_" -match 'Failed to unload hive|Could not load hive' })) {
        Write-TestFailure "builder: $line"
        $failures++
    }
    foreach ($left in @(Remove-BuilderHiveLeftovers $hivesBefore)) {
        Write-TestFailure "the builder left behind a $left"
        $failures++
    }

    $rows = @(Import-Csv -LiteralPath $timelineCsv)
    $failures += Test-RegistryRows -Rows $rows -WindowStart $windowStart -WindowEnd $windowEnd
    if ($failures -gt 0) {
        Write-Host "FAIL: $failures problem(s) in the registry parser rows" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all $(@(Get-ExpectedRegistryRows).Count) expected registry rows found, no unexpected rows" -ForegroundColor Green
    exit 0
}
catch {
    Write-TestFailure "test error: $($_.Exception.Message)"
    exit 1
}
finally {
    # Undo the registry change even when the test failed half-way
    try {
        $leftover = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKeyPath)
        if ($leftover) {
            $leftover.Close()
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKeyPath)
        }
    }
    catch { Write-Host "WARNING: could not delete HKCU\$testKeyPath : $($_.Exception.Message)" -ForegroundColor Yellow }
    # Hives the builder left loaded when the test stopped early
    if ($hivesBefore) {
        foreach ($left in @(Remove-BuilderHiveLeftovers $hivesBefore)) { Write-Host "Cleaned up the builder's $left" -ForegroundColor Yellow }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the one from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
