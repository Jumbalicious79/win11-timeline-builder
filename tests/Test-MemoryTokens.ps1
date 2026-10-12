# =============================================================
# Memory test: process users and paths (work package WP1, items a and b:
# the token's user, integrity and elevation, and the full program path)
# The ProcessDetails area (lib\memory\TimelineDbgEng.Tokens.ps1 and
# TimelineDbgEng.ImagePaths.ps1) on synthetic memory through
# tests\MemoryTestKit.ps1 (no dump, no admin): tokens with their groups,
# privileges and logon sessions, the kernel's and the PEB's program paths,
# the device-to-drive map, the three anomalies, every guard (no token, a
# token not in the dump, too many groups, a SID that is not one, a logon
# session of another logon id, a process whose address space is gone,
# non-ASCII and 8.3 names, minimal processes, a junction, two drive letters
# for one device), the time cap, missing symbols; then the builder's side
# (lib\memory\TimelineMemoryRows.ps1): the Proc entries through the protocol
# onto the process and command line rows (full names, User, the Details
# fields in their order, anomalies merged), and the account names of the
# logon sessions as fallback names for the User column. The rules on these
# rows are checked by tests\Test-ReportRules.ps1
# (tests\fixtures\report\rules\cases-memory-process.csv).
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryTokens.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }

# The kernel's types as 'dt -v' gives them on Windows 11 24H2 ARM64 (the
# offsets of the real symbols; any would do)
function Get-TestProcessDetailsDt {
    param([switch]$NoToken)
    $dt = @{
        "_EPROCESS"                       = New-TestDtText -Type "_EPROCESS" -Size 0x900 -Fields @(
            @(0x320, "ImageFilePointer", "Ptr64 to struct _FILE_OBJECT, 30 elements, 0xd8 bytes"), @(0x340, "SeAuditProcessCreationInfo", "struct _SE_AUDIT_PROCESS_CREATION_INFO, 1 elements, 0x8 bytes"),
            @(0x6bc, "Flags3", "Uint4B"), @(0x6bc, "Minimal", "Bitfield Pos 0, 1 Bit"))
        "_SE_AUDIT_PROCESS_CREATION_INFO" = New-TestDtText -Type "_SE_AUDIT_PROCESS_CREATION_INFO" -Size 8 -Fields @(@(0, "ImageFileName", "Ptr64 to struct _OBJECT_NAME_INFORMATION, 1 elements, 0x10 bytes"))
        "_OBJECT_NAME_INFORMATION"        = New-TestDtText -Type "_OBJECT_NAME_INFORMATION" -Size 0x10 -Fields @(@(0, "Name", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
        "_FILE_OBJECT"                    = New-TestDtText -Type "_FILE_OBJECT" -Size 0xd8 -Fields @(@(0x58, "FileName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
        "_PEB"                            = New-TestDtText -Type "_PEB" -Size 0x7d8 -Fields @(@(0x20, "ProcessParameters", "Ptr64 to struct _RTL_USER_PROCESS_PARAMETERS, 40 elements, 0x450 bytes"))
        "_RTL_USER_PROCESS_PARAMETERS"    = New-TestDtText -Type "_RTL_USER_PROCESS_PARAMETERS" -Size 0x450 -Fields @(
            @(0x38, "CurrentDirectory", "struct _CURDIR, 2 elements, 0x18 bytes"), @(0x60, "ImagePathName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
        "_CURDIR"                         = New-TestDtText -Type "_CURDIR" -Size 0x18 -Fields @(@(0, "DosPath", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
    }
    if (-not $NoToken) {
        $dt["_TOKEN"] = New-TestDtText -Type "_TOKEN" -Size 0x5c8 -Fields @(
            @(0x18, "AuthenticationId", "struct _LUID, 2 elements, 0x8 bytes"), @(0x40, "Privileges", "struct _SEP_TOKEN_PRIVILEGES, 3 elements, 0x18 bytes"),
            @(0x78, "SessionId", "Uint4B"), @(0x7c, "UserAndGroupCount", "Uint4B"), @(0x84, "VariableLength", "Uint4B"),
            @(0x98, "UserAndGroups", "Ptr64 to struct _SID_AND_ATTRIBUTES, 2 elements, 0x10 bytes"), @(0xc8, "TokenFlags", "Uint4B"), @(0xd0, "IntegrityLevelIndex", "Uint4B"),
            @(0xd8, "LogonSession", "Ptr64 to struct _SEP_LOGON_SESSION_REFERENCES, 18 elements, 0xc8 bytes"), @(0x310, "Package", "Ptr64 to Void"))
        $dt["_SID_AND_ATTRIBUTES"] = New-TestDtText -Type "_SID_AND_ATTRIBUTES" -Size 0x10 -Fields @(@(0, "Sid", "Ptr64 to Void"), @(8, "Attributes", "Uint4B"))
        $dt["_SEP_TOKEN_PRIVILEGES"] = New-TestDtText -Type "_SEP_TOKEN_PRIVILEGES" -Size 0x18 -Fields @(@(0, "Present", "Uint8B"), @(8, "Enabled", "Uint8B"), @(0x10, "EnabledByDefault", "Uint8B"))
        $dt["_SEP_LOGON_SESSION_REFERENCES"] = New-TestDtText -Type "_SEP_LOGON_SESSION_REFERENCES" -Size 0xc8 -Fields @(
            @(8, "LogonId", "struct _LUID, 2 elements, 0x8 bytes"), @(0x10, "BuddyLogonId", "struct _LUID, 2 elements, 0x8 bytes"),
            @(0x40, "AccountName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"), @(0x50, "AuthorityName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
    }
    return $dt
}

# A SID's bytes (revision, count, 6-byte big-endian authority, sub-authorities)
function ConvertTo-TestSidBytes {
    param([string]$Sid, [int]$Revision = 1)
    $parts = $Sid.Split('-')
    $subs = @()
    if ($parts.Count -gt 3) { $subs = @($parts[3..($parts.Count - 1)]) }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte]$Revision)
    $bytes.Add([byte]$subs.Count)
    $authority = [uint64]$parts[2]
    for ($shift = 40; $shift -ge 0; $shift -= 8) { $bytes.Add([byte](($authority -shr $shift) -band 0xFF)) }
    foreach ($sub in $subs) { $bytes.AddRange([BitConverter]::GetBytes([uint32]$sub)) }
    return , $bytes.ToArray()
}

function Add-TestAddress {
    param([uint64]$Base, [uint64]$Offset)
    return [uint64]($Base + $Offset)
}

# A token at -Address (the 24H2 layout above): the user, then -Groups
# (@(sid, attributes) each), then the integrity label when -Integrity is 0
# or more; the SID_AND_ATTRIBUTES array and the SIDs in its variable part
function Write-TestToken {
    param(
        $Memory, [uint64]$Address, [string]$User, [object[]]$Groups = @(), [int]$Integrity = -1, [uint32]$Flags = 0, [uint64]$Enabled = 0,
        [uint64]$LogonSession = 0, [uint64]$LogonId = 0, [uint32]$SessionId = 0, [uint64]$Package = 0, [uint32]$CountOverride = 0, [int]$UserRevision = 1
    )
    $entries = New-Object System.Collections.Generic.List[object]
    $entries.Add(@($User, 0, $UserRevision))
    foreach ($group in $Groups) { $entries.Add(@($group[0], $group[1], 1)) }
    $index = 0
    if ($Integrity -ge 0) { $entries.Add(@("S-1-16-$Integrity", 0x60, 1)); $index = $entries.Count - 1 }
    $array = Add-TestAddress $Address 0x5c8
    $sidAt = Add-TestAddress $array ([uint64](16 * $entries.Count))
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $sidBytes = ConvertTo-TestSidBytes -Sid $entries[$i][0] -Revision $entries[$i][2]
        $Memory.Write(0, $sidAt, $sidBytes)
        $Memory.WriteU64(0, (Add-TestAddress $array ([uint64](16 * $i))), $sidAt)
        $Memory.WriteU32(0, (Add-TestAddress $array ([uint64](16 * $i + 8))), [uint32]$entries[$i][1])
        $sidAt = Add-TestAddress $sidAt ([uint64](4 * [Math]::Ceiling($sidBytes.Length / 4)))
    }
    $count = if ($CountOverride -gt 0) { $CountOverride } else { [uint32]$entries.Count }
    $Memory.WriteU64(0, (Add-TestAddress $Address 0x18), $LogonId)
    $Memory.WriteU64(0, (Add-TestAddress $Address 0x48), $Enabled)
    $Memory.WriteU32(0, (Add-TestAddress $Address 0x78), $SessionId)
    $Memory.WriteU32(0, (Add-TestAddress $Address 0x7c), $count)
    $Memory.WriteU32(0, (Add-TestAddress $Address 0x84), [uint32]($sidAt - $array))
    $Memory.WriteU64(0, (Add-TestAddress $Address 0x98), $array)
    $Memory.WriteU32(0, (Add-TestAddress $Address 0xc8), $Flags)
    $Memory.WriteU32(0, (Add-TestAddress $Address 0xd0), [uint32]$index)
    $Memory.WriteU64(0, (Add-TestAddress $Address 0xd8), $LogonSession)
    $Memory.WriteU64(0, (Add-TestAddress $Address 0x310), $Package)
}

# A logon session (_SEP_LOGON_SESSION_REFERENCES) at -Address
function Write-TestLogonSession {
    param($Memory, [uint64]$Address, [uint64]$LogonId, [uint64]$Buddy = 0, [string]$Account, [string]$Authority)
    $Memory.WriteU64(0, (Add-TestAddress $Address 8), $LogonId)
    $Memory.WriteU64(0, (Add-TestAddress $Address 0x10), $Buddy)
    $Memory.WriteUnicodeString(0, (Add-TestAddress $Address 0x40), (Add-TestAddress $Address 0x100), $Account)
    $Memory.WriteUnicodeString(0, (Add-TestAddress $Address 0x50), (Add-TestAddress $Address 0x180), $Authority)
}

# A process's paths: the kernel's record (-Audit), the image's file object
# (-FileObject), its PEB in its own address space (-Peb, -PebImage,
# -CurrentDirectory), EPROCESS.Minimal (-Minimal)
function Write-TestProcessPaths {
    param($Memory, [uint64]$Eprocess, [string]$Audit, [string]$FileObject, [uint64]$Peb = 0, [string]$PebImage, [string]$CurrentDirectory, [switch]$Minimal)
    $Memory.WriteU32(0, (Add-TestAddress $Eprocess 0x6bc), $(if ($Minimal) { [uint32]0x10001 } else { [uint32]0x10000 }))
    if ($Audit) {
        $info = Add-TestAddress $Eprocess 0x2000
        $Memory.WriteU64(0, (Add-TestAddress $Eprocess 0x340), $info)
        $Memory.WriteUnicodeString(0, $info, (Add-TestAddress $info 0x10), $Audit)
    }
    if ($FileObject) {
        $file = Add-TestAddress $Eprocess 0x3000
        $Memory.WriteU64(0, (Add-TestAddress $Eprocess 0x320), $file)
        $Memory.WriteUnicodeString(0, (Add-TestAddress $file 0x58), (Add-TestAddress $file 0x100), $FileObject)
    }
    if ($Peb -ne 0) {
        $parameters = Add-TestAddress $Peb 0x10000
        $Memory.WriteU64($Eprocess, (Add-TestAddress $Peb 0x20), $parameters)
        if ($PebImage) { $Memory.WriteUnicodeString($Eprocess, (Add-TestAddress $parameters 0x60), (Add-TestAddress $parameters 0x200), $PebImage) }
        if ($CurrentDirectory) { $Memory.WriteUnicodeString($Eprocess, (Add-TestAddress $parameters 0x38), (Add-TestAddress $parameters 0x600), $CurrentDirectory) }
    }
}

# The fields of the area's Proc entries, by PID
function Get-TestProcFields {
    param($Area)
    $byPid = @{}
    foreach ($entry in $Area.Entries) {
        $fields = Get-TestEntryFields $entry
        $byPid[[string]$fields["Pid"]] = $fields
    }
    return $byPid
}

# Key=value of chosen keys of an entry's fields ("Key=" when it has none)
function Format-TestFields {
    param($Fields, [string[]]$Keys)
    return (@($Keys | ForEach-Object { "$_=$(if ($Fields -and $Fields.Contains($_)) { $Fields[$_] } else { '' })" }) -join " ")
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryTokens"
    $kernelBase = [Convert]::ToUInt64("ffffc10000000000", 16)
    $userBase = [uint64]0x7ff600000000
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    $memory = New-TestMemory
    # SE_GROUP_* attributes: mandatory 1, enabled by default 2, enabled 4, deny only 0x10
    $adminEnabled = @("S-1-5-32-544", 0xF)
    $adminDenyOnly = @("S-1-5-32-544", 0x10)
    $everyone = @("S-1-1-0", 7)
    $usersGroup = @("S-1-5-32-545", 7)
    # Privilege bits (LUIDs): SeCreateToken 2, SeTcb 7, SeLoadDriver 10,
    # SeBackup 17, SeDebug 20, SeChangeNotify 23, SeImpersonate 29
    $priv = { param([int[]]$Luids) $v = [uint64]0; foreach ($l in $Luids) { $v = $v -bor ([uint64]1 -shl $l) }; $v }
    $alice = "S-1-5-21-1-2-3-1001"

    # Logon sessions: SYSTEM (0x3e7), alice's split token (0x1f2e3d filtered,
    # 0x1f2e40 elevated, each the other's buddy), one of another logon id
    $sessionSystem = Add-TestAddress $kernelBase 0x900000
    $sessionLimited = Add-TestAddress $kernelBase 0x901000
    $sessionFull = Add-TestAddress $kernelBase 0x902000
    Write-TestLogonSession -Memory $memory -Address $sessionSystem -LogonId 0x3e7 -Account "FIXTURE-PC$" -Authority "WORKGROUP"
    Write-TestLogonSession -Memory $memory -Address $sessionLimited -LogonId 0x1f2e3d -Buddy 0x1f2e40 -Account "alice" -Authority "FIXTURE"
    Write-TestLogonSession -Memory $memory -Address $sessionFull -LogonId 0x1f2e40 -Buddy 0x1f2e3d -Account "alice" -Authority "FIXTURE"

    # The processes (create times in minutes before the capture)
    $specs = @(
        # PID, PPID, short name, minutes before, token kind, audit path, PEB image path, current folder, extra
        @{ Pid = 4; Ppid = 0; Short = "System"; Minutes = 600; Token = "system"; Audit = "\Device\HarddiskVolume3\Windows\System32\ntoskrnl.exe"; Peb = $false }
        @{ Pid = 1000; Ppid = 900; Short = "fixture-longna"; Minutes = 300; Token = "limited"; Audit = "\Device\HarddiskVolume3\Users\alice\AppData\Local\fixture-longname-user.exe"; FileObject = "\Users\alice\AppData\Local\fixture-longname-user.exe"; PebImage = "C:\Users\alice\AppData\Local\fixture-longname-user.exe"; Cwd = "C:\Users\alice\" }
        @{ Pid = 1004; Ppid = 1000; Short = "fixture-admin."; Minutes = 200; Token = "full"; Audit = "\Device\HarddiskVolume3\Program Files\Fixture\fixture-admin.exe"; FileObject = "\Program Files\Fixture\fixture-admin.exe"; PebImage = "\??\C:\Program Files\Fixture\fixture-admin.exe"; Cwd = "C:\Windows\system32\" }
        @{ Pid = 1008; Ppid = 1000; Short = "fixture-box.exe"; Minutes = 190; Token = "box"; Protection = 0x31; Audit = "\Device\HarddiskVolume3\Program Files\Fixture\fixture-box.exe"; PebImage = "C:\Program Files\Fixture\fixture-box.exe" }
        @{ Pid = 1012; Ppid = 1000; Short = "fixture-esc.exe"; Minutes = 100; Token = "system"; Audit = "\Device\HarddiskVolume3\Users\alice\AppData\Local\fixture-esc.exe"; PebImage = "C:\Users\alice\AppData\Local\fixture-esc.exe" }
        @{ Pid = 1016; Ppid = 1040; Short = "fixture-reuse.e"; Minutes = 90; Token = "system"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-reuse.exe"; PebImage = "C:\Windows\System32\fixture-reuse.exe" }
        @{ Pid = 1040; Ppid = 1000; Short = "fixture-late.ex"; Minutes = 80; Token = "limited"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-late.exe"; PebImage = "C:\Windows\System32\fixture-late.exe" }
        @{ Pid = 1020; Ppid = 1004; Short = "fixture-svcchil"; Minutes = 70; Token = "system"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-svcchild.exe"; PebImage = "C:\Windows\System32\fixture-svcchild.exe" }
        @{ Pid = 1024; Ppid = 700; Short = "svchost.exe"; Minutes = 60; Token = "limited"; Audit = "\Device\HarddiskVolume3\Users\alice\AppData\Roaming\fixture-renamed.exe"; PebImage = "C:\Users\alice\AppData\Roaming\fixture-renamed.exe" }
        @{ Pid = 1028; Ppid = 700; Short = "fixture-" + [char]0xFFFD; Minutes = 59; Token = "limited"; Audit = "\Device\HarddiskVolume3\Tools\fixture-" + [char]0xFC + ".exe"; PebImage = "C:\Tools\fixture-" + [char]0xFC + ".exe" }
        @{ Pid = 88; Ppid = 4; Short = "Registry"; Minutes = 600; Token = "system"; Audit = "Registry"; Peb = $false; Minimal = $true }
        @{ Pid = 1032; Ppid = 700; Short = "fixture-real.ex"; Minutes = 50; Token = "limited"; Audit = "\Device\HarddiskVolume3\Users\alice\AppData\Local\fixture-real.exe"; PebImage = "C:\Windows\System32\fixture-claimed.exe" }
        @{ Pid = 1036; Ppid = 700; Short = "fixture-juncti"; Minutes = 49; Token = "limited"; Audit = "\Device\HarddiskVolume3\Data\Apps\fixture-junction.exe"; PebImage = "C:\Apps\fixture-junction.exe" }
        @{ Pid = 1044; Ppid = 700; Short = "fixture-short.e"; Minutes = 48; Token = "limited"; Audit = "\Device\HarddiskVolume3\Program Files\Fixture\fixture-short.exe"; PebImage = "C:\PROGRA~1\FIXTUR~1\FIXTUR~1.EXE" }
        @{ Pid = 1048; Ppid = 4; Short = "fixture-smss.ex"; Minutes = 599; Token = "system"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-smss.exe"; PebImage = "\SystemRoot\System32\fixture-smss.exe" }
        @{ Pid = 1052; Ppid = 700; Short = "fixture-gone.ex"; Minutes = 47; Token = "none"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-gone.exe"; Refuse = $true; Exited = $true }
        @{ Pid = 1056; Ppid = 700; Short = "fixture-nopage"; Minutes = 46; Token = "unreadable"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-nopage.exe"; PebImage = "C:\Windows\System32\fixture-nopage.exe" }
        @{ Pid = 1060; Ppid = 700; Short = "fixture-many.ex"; Minutes = 45; Token = "toomany"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-many.exe"; PebImage = "C:\Windows\System32\fixture-many.exe" }
        @{ Pid = 1064; Ppid = 700; Short = "fixture-rev.exe"; Minutes = 44; Token = "badsid"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-rev.exe"; PebImage = "C:\Windows\System32\fixture-rev.exe" }
        @{ Pid = 1068; Ppid = 700; Short = "fixture-luid.ex"; Minutes = 43; Token = "otherluid"; Audit = "\Device\HarddiskVolume3\Windows\System32\fixture-luid.exe"; PebImage = "C:\Windows\System32\fixture-luid.exe" }
        @{ Pid = 1072; Ppid = 700; Short = "fixture-d.exe"; Minutes = 42; Token = "limited"; Audit = "\Device\HarddiskVolume5\Tools\fixture-d.exe"; PebImage = "D:\Tools\fixture-d.exe" }
        @{ Pid = 1076; Ppid = 700; Short = "fixture-e.exe"; Minutes = 41; Token = "limited"; Audit = "\Device\HarddiskVolume5\Other\fixture-e.exe"; PebImage = "E:\Other\fixture-e.exe" }
    )
    $processes = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $specs.Count; $i++) {
        $s = $specs[$i]
        $eprocess = Add-TestAddress $kernelBase ([uint64](0x10000 * ($i + 1)))
        $token = Add-TestAddress $eprocess 0x4000
        $peb = [uint64]0
        if ($s.Peb -ne $false) { $peb = Add-TestAddress $userBase ([uint64](0x100000 * ($i + 1))) }
        switch ($s.Token) {
            "system" { Write-TestToken -Memory $memory -Address $token -User "S-1-5-18" -Groups @($adminEnabled, $everyone) -Integrity 0x4000 -Enabled (& $priv @(7, 20, 23, 29)) -LogonSession $sessionSystem -LogonId 0x3e7 }
            "limited" { Write-TestToken -Memory $memory -Address $token -User $alice -Groups @($everyone, $adminDenyOnly, $usersGroup) -Integrity 0x2000 -Flags 0x800 -Enabled (& $priv @(23)) -LogonSession $sessionLimited -LogonId 0x1f2e3d -SessionId 1 }
            "full" { Write-TestToken -Memory $memory -Address $token -User $alice -Groups @($everyone, $adminEnabled, $usersGroup) -Integrity 0x3000 -Enabled (& $priv @(20, 17, 23)) -LogonSession $sessionFull -LogonId 0x1f2e40 -SessionId 1 }
            "box" { Write-TestToken -Memory $memory -Address $token -User $alice -Groups @($everyone, $adminDenyOnly) -Integrity 0x1000 -Flags (0x800 -bor 0x1000 -bor 0x4000) -LogonSession $sessionLimited -LogonId 0x1f2e3d -SessionId 1 -Package (Add-TestAddress $kernelBase 0x990000) }
            "unreadable" { }
            "toomany" { Write-TestToken -Memory $memory -Address $token -User $alice -Groups @($everyone) -Integrity 0x2000 -LogonSession $sessionLimited -LogonId 0x1f2e3d -CountOverride 2000 }
            "badsid" { Write-TestToken -Memory $memory -Address $token -User $alice -Groups @($everyone) -Integrity 0x2000 -LogonSession $sessionLimited -LogonId 0x1f2e3d -UserRevision 2 }
            "otherluid" { Write-TestToken -Memory $memory -Address $token -User $alice -Groups @($everyone, $adminDenyOnly) -Integrity 0x2000 -Flags 0x800 -LogonSession $sessionLimited -LogonId 0x777 -SessionId 1 }
        }
        Write-TestProcessPaths -Memory $memory -Eprocess $eprocess -Audit $s.Audit -FileObject $s.FileObject -Peb $peb -PebImage $s.PebImage -CurrentDirectory $s.Cwd -Minimal:([bool]$s.Minimal)
        if ($s.Refuse) { $memory.Refuse($eprocess) }
        $created = $capture.AddMinutes(-[int]$s.Minutes)
        $info = @{ Eprocess = $eprocess; Pid = [long]$s.Pid; Ppid = [long]$s.Ppid; CreateTime = $created; Peb = $peb; ShortName = [string]$s.Short; Protection = [byte]$(if ($s.Protection) { $s.Protection } else { 0 }) }
        $info.Token = if ($s.Token -eq "none") { [uint64]0 } else { $token }
        if ($s.Exited) { $info.ExitTime = $capture.AddMinutes(-1) }
        $processes.Add($info)
    }

    # --- The area -------------------------------------------------------------------
    Set-TestEngineCommands -Dt (Get-TestProcessDetailsDt)
    $context = New-TestContext -Memory $memory -Processes $processes.ToArray() -CaptureFileTime $capture.ToFileTimeUtc()
    $area = Invoke-TestArea -Name "ProcessDetails" -Context $context
    $byPid = Get-TestProcFields -Area $area
    Assert-KitEqual -Name "the ProcessDetails area: read, one Proc entry per process, Offset as the P line's (lowercase hex of the EPROCESS)" `
        -Expected "Read|$($specs.Count)|0x$((Add-TestAddress $kernelBase 0x10000).ToString('x'))" -Actual "$($area.State)|$($area.Entries.Count)|$($byPid['4']['Offset'])"
    $tokenKeys = @("User", "Integrity", "Elevation", "Elevated", "AdminGroup", "TokenSession", "LogonId", "AppContainer", "UIAccess", "Protection", "Privileges", "LogonAccount")
    Assert-KitEqual -Name "a SYSTEM token: S-1-5-18, System, Default (no linked logon session), elevated by its enabled Administrators group, the notable enabled privileges only (not SeImpersonate, SeChangeNotify)" `
        -Expected "User=S-1-5-18 Integrity=System Elevation=Default Elevated=Yes AdminGroup=Enabled TokenSession=0 LogonId=0x3e7 AppContainer= UIAccess= Protection= Privileges=SeDebugPrivilege,SeTcbPrivilege LogonAccount=WORKGROUP\FIXTURE-PC$" `
        -Actual (Format-TestFields $byPid["4"] $tokenKeys)
    Assert-KitEqual -Name "a standard user's token: the filtered half of a split token is Limited, Administrators deny-only, Medium" `
        -Expected "User=$alice Integrity=Medium Elevation=Limited Elevated=No AdminGroup=DenyOnly TokenSession=1 LogonId=0x1f2e3d AppContainer= UIAccess= Protection= Privileges= LogonAccount=FIXTURE\alice" `
        -Actual (Format-TestFields $byPid["1000"] $tokenKeys)
    Assert-KitEqual -Name "the elevated half: Full, High, Administrators enabled, SeDebugPrivilege and SeBackupPrivilege enabled (in the rows' order)" `
        -Expected "User=$alice Integrity=High Elevation=Full Elevated=Yes AdminGroup=Enabled TokenSession=1 LogonId=0x1f2e40 AppContainer= UIAccess= Protection= Privileges=SeDebugPrivilege,SeBackupPrivilege LogonAccount=FIXTURE\alice" `
        -Actual (Format-TestFields $byPid["1004"] $tokenKeys)
    Assert-KitEqual -Name "an AppContainer (LowBox flag, package) with UIAccess, Low integrity, protected as PPL-Antimalware" `
        -Expected "Integrity=Low Elevation=Limited AppContainer=Yes UIAccess=Yes Protection=PPL-Antimalware" -Actual (Format-TestFields $byPid["1008"] @("Integrity", "Elevation", "AppContainer", "UIAccess", "Protection"))
    $guardText = @("1052", "1056", "1060", "1064") | ForEach-Object { "$_=$(if ($byPid[$_].Contains('User')) { 'user' } else { 'none' })" }
    Assert-KitEqual -Name "no token (an exited process), a token not in the dump, more than 1024 groups, a SID of another revision: no token fields, never guessed" `
        -Expected "1052=none|1056=none|1060=none|1064=none" -Actual ($guardText -join "|")
    Assert-KitEqual -Name "a logon session of another logon id: the user and integrity are kept, the session's elevation and account name are not used" `
        -Expected "User=$alice Integrity=Medium Elevation= Elevated= LogonAccount=" -Actual (Format-TestFields $byPid["1068"] @("User", "Integrity", "Elevation", "Elevated", "LogonAccount"))

    $pathKeys = @("FullName", "ImagePath", "CurrentDirectory", "PebImagePath", "Anomaly")
    Assert-KitEqual -Name "paths: the full name from the kernel's record (the 14-character short name starts it), the device as its drive letter (learned from the PEB), the current folder" `
        -Expected "FullName=fixture-longname-user.exe ImagePath=C:\Users\alice\AppData\Local\fixture-longname-user.exe CurrentDirectory=C:\Users\alice\ PebImagePath= Anomaly=" -Actual (Format-TestFields $byPid["1000"] $pathKeys)
    Assert-KitEqual -Name "paths: a PEB path with \??\ is the same path (no PebImagePath); a 15-character short name" `
        -Expected "FullName=fixture-admin.exe PebImagePath= Anomaly=|FullName=fixture-box.exe" -Actual "$(Format-TestFields $byPid['1004'] @('FullName', 'PebImagePath', 'Anomaly'))|$(Format-TestFields $byPid['1008'] @('FullName'))"
    Assert-KitEqual -Name "anomalies: SystemChildOfUser for a SYSTEM child of a Medium user process; not for a PPID whose process was created after the child (a reused PID), nor for an elevated (High) parent" `
        -Expected "1012=SystemChildOfUser|1016=|1020=" -Actual ((@("1012", "1016", "1020") | ForEach-Object { "$_=$($byPid[$_]['Anomaly'])" }) -join "|")
    Assert-KitEqual -Name "anomalies: ImageNameChanged when the short name does not start the kernel's file name (the row keeps the short name); not for non-ASCII names, System or a minimal process" `
        -Expected "1024=ImageNameChanged/|1028=/|4=/|88=/" -Actual ((@("1024", "1028", "4", "88") | ForEach-Object { "$_=$($byPid[$_]['Anomaly'])/$($byPid[$_]['FullName'])" }) -join "|")
    Assert-KitEqual -Name "anomalies: PebImageNameMismatch for another file name in the PEB (PebImagePath shown); a folder-only difference, an 8.3 name and \SystemRoot\ are shown but never flagged" `
        -Expected "1032=PebImageNameMismatch/C:\Windows\System32\fixture-claimed.exe|1036=/C:\Apps\fixture-junction.exe|1044=/C:\PROGRA~1\FIXTUR~1\FIXTUR~1.EXE|1048=/\SystemRoot\System32\fixture-smss.exe" `
        -Actual ((@("1032", "1036", "1044", "1048") | ForEach-Object { "$_=$($byPid[$_]['Anomaly'])/$($byPid[$_]['PebImagePath'])" }) -join "|")
    Assert-KitEqual -Name "the drive map: one device mapped to C:, a device two drive letters were learned for keeps its device name (and its PEB path is shown)" `
        -Expected "1|C:|\Device\HarddiskVolume5\Tools\fixture-d.exe|D:\Tools\fixture-d.exe" -Actual "$($context.DriveMap.Count)|$($context.DriveMap['\Device\HarddiskVolume3'])|$($byPid['1072']['ImagePath'])|$($byPid['1072']['PebImagePath'])"
    Assert-KitEqual -Name "an exited process whose address space is gone: its kernel path still read, no PEB fields" -Expected "ImagePath=C:\Windows\System32\fixture-gone.exe CurrentDirectory= PebImagePath=" `
        -Actual (Format-TestFields $byPid["1052"] @("ImagePath", "CurrentDirectory", "PebImagePath"))
    $info1000 = $context.Processes[1]
    Assert-KitEqual -Name "the processes of the context get UserSid, Integrity, Elevated, FullName and ImagePath (for the other areas)" `
        -Expected "$alice|Medium|No|fixture-longname-user.exe|C:\Users\alice\AppData\Local\fixture-longname-user.exe|fixture-longname-user.exe" -Actual "$($info1000.UserSid)|$($info1000.Integrity)|$($info1000.Elevated)|$($info1000.FullName)|$($info1000.ImagePath)|$($info1000.Name)"
    Assert-KitEqual -Name "the area's counts for the log" `
        -Expected "processes 22, tokens read 18, logon sessions read 17, without a token 1, tokens not in the dump 1, tokens not readable as such 2, logon sessions of another logon id 1, kernel paths read 21, full names longer than the short name 13, file objects agreeing 2, PEB paths read 19, PEB paths shown as differing 6, current folders read 2, devices mapped to drive letters 1, devices with conflicting drive letters 1, address spaces not readable 1, ImageNameChanged 1, PebImageNameMismatch 1, SystemChildOfUser 1" `
        -Actual $area.Coverage.CountsText
    Assert-KitEqual -Name "the area's note for the report: what a live copy left unreadable, no colon, no parentheses" `
        -Expected "the token of 4 processes could not be read, as when a process has ended; the PEB of 1 process could not be read, as when a process has ended or its memory was paged out; 2 program paths keep their volume's device name, no drive letter was learned for the volume" `
        -Actual $area.Note

    # The time cap, and symbols without the token's or the paths' types
    $capped = Invoke-TestArea -Name "ProcessDetails" -Context (New-TestContext -Memory $memory -Processes $processes.ToArray()) -CapSeconds 0.000000001
    Assert-KitEqual -Name "the time cap: partly read, says so" -Expected "Partial|0|True" -Actual "$($capped.State)|$($capped.Entries.Count)|$($capped.Note -like 'stopped at its time limit*')"
    Set-TestEngineCommands -Dt (Get-TestProcessDetailsDt -NoToken)
    $noToken = Invoke-TestArea -Name "ProcessDetails" -Context (New-TestContext -Memory $memory -Processes $processes.ToArray())
    $noTokenFields = Get-TestProcFields -Area $noToken
    Assert-KitEqual -Name "symbols without the token's types: the paths are read, the users are not, and the note names the missing fields" `
        -Expected "Partial|22|C:\Users\alice\AppData\Local\fixture-longname-user.exe||True" -Actual "$($noToken.State)|$($noToken.Entries.Count)|$($noTokenFields['1000']['ImagePath'])|$($noTokenFields['1000']['User'])|$($noToken.Note.EndsWith('; the users of the processes were not read, the kernel''s symbols do not describe _TOKEN, _SID_AND_ATTRIBUTES, _SEP_TOKEN_PRIVILEGES, _SEP_LOGON_SESSION_REFERENCES as expected'))"
    Set-TestEngineCommands -Dt @{}
    $nothing = Invoke-TestArea -Name "ProcessDetails" -Context (New-TestContext -Memory $memory -Processes $processes.ToArray())
    Assert-KitEqual -Name "symbols without any of the types: not read, and says why (no colon)" -Expected "NotRead|0|the kernel's symbols do not describe _TOKEN, _SID_AND_ATTRIBUTES, _SEP_TOKEN_PRIVILEGES, _SEP_LOGON_SESSION_REFERENCES, _EPROCESS, _SE_AUDIT_PROCESS_CREATION_INFO, _OBJECT_NAME_INFORMATION, _PEB, _RTL_USER_PROCESS_PARAMETERS, _CURDIR as expected" -Actual "$($nothing.State)|$($nothing.Entries.Count)|$($nothing.Note)"
    Set-TestEngineCommands -Dt (Get-TestProcessDetailsDt)

    # --- The builder: the Proc entries through the protocol onto the rows ----------
    $offsetOf = { param([long]$ProcId) "0x$((Add-TestAddress $kernelBase ([uint64](0x10000 * ([array]::IndexOf(@($specs | ForEach-Object { [long]$_.Pid }), $ProcId) + 1)))).ToString('x'))" }
    $result = New-DbgEngResult
    $result.Processes = @(
        [PSCustomObject]@{ PID = [long]1000; PPID = [long]900; Threads = [long]5; SessionId = [long]1; Offset = (& $offsetOf 1000); ImageFileName = "fixture-longna"; CreateTime = "2026-10-11T07:30:00.1234567+00:00"; ExitTime = $null; FoundBy = "ListForward,ListBackward,ProcessIdTable"; TableId = ""; Anomaly = "" }
        [PSCustomObject]@{ PID = [long]1012; PPID = [long]1000; Threads = [long]2; SessionId = [long]1; Offset = (& $offsetOf 1012); ImageFileName = "fixture-esc.exe"; CreateTime = "2026-10-11T10:50:00+00:00"; ExitTime = $null; FoundBy = "ProcessIdTable"; TableId = ""; Anomaly = "NotInProcessList" }
        [PSCustomObject]@{ PID = [long]1024; PPID = [long]700; Threads = [long]2; SessionId = [long]1; Offset = (& $offsetOf 1024); ImageFileName = "svchost.exe"; CreateTime = "2026-10-11T11:30:00+00:00"; ExitTime = $null; FoundBy = "ListForward,ListBackward,ProcessIdTable"; TableId = ""; Anomaly = "" }
        [PSCustomObject]@{ PID = [long]2000; PPID = [long]4; Threads = [long]1; SessionId = [long]0; Offset = "0xffffc10000990000"; ImageFileName = "fixture-noproc"; CreateTime = "2026-10-11T11:00:00+00:00"; ExitTime = $null; FoundBy = "ListForward"; TableId = ""; Anomaly = "" }
    )
    $result.CommandLines = @(
        [PSCustomObject]@{ PID = [long]1000; Process = "fixture-longna"; Args = "fixture-longname-user.exe /run" }
        [PSCustomObject]@{ PID = [long]2000; Process = "fixture-noproc"; Args = "fixture-noproc.exe" }
    )
    $result.Entries = @($area.Entries | Where-Object { @("1000", "1012", "1024") -contains $_.Get("Pid") })
    $result.Areas = @(New-DbgEngAreaSummary -Name "ProcessDetails" -State $area.State -Rows 3 -Seconds 0.1 -Note $area.Note)
    [void](Get-TestProtocolLines)
    Write-DbgEngWorkerResult $result
    $state = New-DbgEngWorkerState
    foreach ($line in (Get-TestProtocolLines)) { Receive-DbgEngWorkerLine -Line $line -State $state }
    $merge = Merge-DbgEngProcessEntries -Processes $state.Processes.ToArray() -ProcEntries $state.Entries["Proc"].ToArray()
    Set-DbgEngProcessRowFields -Processes $state.Processes.ToArray() -CommandLines $state.CommandLines.ToArray()
    [void](Get-TestRows)
    [void](Add-MemoryPluginRows -Plugin "windows.pslist" -Source "Memory-Processes" -Entries $state.Processes.ToArray() -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp")
    [void](Add-MemoryPluginRows -Plugin "windows.cmdline" -Source "Memory-CommandLine" -Entries $state.CommandLines.ToArray() -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp")
    $rows = @(Get-TestRows -Keep)
    Assert-KitEqual -Name "the protocol: the Proc entries arrive whole and merge onto their processes by Offset" -Expected "True|0|3|0" -Actual "$($state.Ended)|$($state.BadLines)|$($merge.Merged)|$($merge.Unmatched)"
    Assert-KitEqual -Name "Memory-Processes rows: the full name, the token's SID as User, the token's fields then those that can hold spaces, after the scan's fields" `
        -Expected "Memory-Processes|2026-10-11 07:30:00.123|ProcessCreation|Process in memory: fixture-longname-user.exe (PID: 1000, PPID: 900)|$alice|Threads=5 SessionId=1 FoundBy=ListForward,ListBackward,ProcessIdTable Integrity=Medium Elevation=Limited Elevated=No AdminGroup=DenyOnly TokenSession=1 LogonId=0x1f2e3d LogonAccount=FIXTURE\alice ImagePath=C:\Users\alice\AppData\Local\fixture-longname-user.exe CurrentDirectory=C:\Users\alice\" `
        -Actual $rows[0]
    Assert-KitEqual -Name "Memory-Processes rows: the helper's anomaly joins the scan's (one Anomaly= field, the scan's first)" `
        -Expected "Process in memory: fixture-esc.exe (PID: 1012, PPID: 1000)|S-1-5-18|Threads=2 SessionId=1 FoundBy=ProcessIdTable Anomaly=NotInProcessList,SystemChildOfUser Integrity=System Elevation=Default Elevated=Yes AdminGroup=Enabled TokenSession=0 LogonId=0x3e7 Privileges=SeDebugPrivilege,SeTcbPrivilege LogonAccount=WORKGROUP\FIXTURE-PC$ ImagePath=C:\Users\alice\AppData\Local\fixture-esc.exe" `
        -Actual ($rows[1].Split('|')[3..5] -join '|')
    Assert-KitEqual -Name "Memory-Processes rows: a renamed process keeps its short name, with ImageNameChanged; a process without a Proc entry is as before" `
        -Expected "Process in memory: svchost.exe (PID: 1024, PPID: 700)|Anomaly=ImageNameChanged|Process in memory: fixture-noproc (PID: 2000, PPID: 4)||Threads=1 SessionId=0 FoundBy=ListForward" `
        -Actual "$($rows[2].Split('|')[3])|$(([regex]::Match($rows[2], 'Anomaly=\S+')).Value)|$($rows[3].Split('|')[3..5] -join '|')"
    Assert-KitEqual -Name "Memory-CommandLine rows: the full name and the token's SID of their process; Details unchanged (Args= only); one without a Proc entry as before" `
        -Expected "Memory-CommandLine|2026-10-11 12:30:00.000|Snapshot|Process command line: fixture-longname-user.exe (PID: 1000)|$alice|Args=fixture-longname-user.exe /run|Process command line: fixture-noproc (PID: 2000)|" `
        -Actual "$($rows[4])|$($rows[5].Split('|')[3..4] -join '|')"

    # Two processes with one PID and short name (one ended, its PID reused):
    # their command line gets their full name and user only when they agree
    $twins = @(
        [PSCustomObject]@{ PID = [long]3000; ImageFileName = "fixture-twin"; Offset = "0xa"; Proc = [PSCustomObject]@{ Offset = "0xa"; User = "S-1-5-18"; FullName = "fixture-twin-one.exe" } }
        [PSCustomObject]@{ PID = [long]3000; ImageFileName = "fixture-twin"; Offset = "0xb"; Proc = [PSCustomObject]@{ Offset = "0xb"; User = "S-1-5-18"; FullName = "fixture-twin-two.exe" } }
        [PSCustomObject]@{ PID = [long]3004; ImageFileName = "fixture-same"; Offset = "0xc"; Proc = [PSCustomObject]@{ Offset = "0xc"; User = $alice; FullName = "fixture-same.exe" } }
        [PSCustomObject]@{ PID = [long]3004; ImageFileName = "fixture-same"; Offset = "0xd"; Proc = [PSCustomObject]@{ Offset = "0xd"; User = $alice; FullName = "fixture-same.exe" } }
    )
    $twinLines = @([PSCustomObject]@{ PID = [long]3000; Process = "fixture-twin"; Args = "x" }, [PSCustomObject]@{ PID = [long]3004; Process = "fixture-same"; Args = "y" })
    Set-DbgEngProcessRowFields -Processes $twins -CommandLines $twinLines
    Assert-KitEqual -Name "Set-DbgEngProcessRowFields: a command line of a PID two processes had gets their name and user only when they agree" `
        -Expected "fixture-twin||fixture-same.exe|$alice" -Actual "$($twinLines[0].Process)|$($twinLines[0].User)|$($twinLines[1].Process)|$($twinLines[1].User)"

    # --- Account names: fallback names for the User column ------------------------
    $script:timelineUserContext = $null
    Add-TimelineMachineName "FIXTURE"
    $entries = @{ Proc = $state.Entries["Proc"] }
    Register-DbgEngLogonNames -Entries $entries
    $named = Get-TimelineSidNames
    [void](Update-TimelineUserColumn -Entries $script:timelineEntries -SidNames $named -MachineNames @((Get-TimelineUserContext).MachineNames))
    $passRows = @(Get-TestRows)
    Assert-KitEqual -Name "Register-DbgEngLogonNames: a user SID gets its logon session's account (the examined computer's name dropped); the User pass names the rows and keeps the SID (UserSID=)" `
        -Expected "alice|alice|True|NT AUTHORITY\SYSTEM|True" `
        -Actual "$($named[$alice])|$($passRows[0].Split('|')[4])|$($passRows[0].EndsWith(' | UserSID=' + $alice))|$($passRows[1].Split('|')[4])|$($passRows[1].EndsWith(' | UserSID=S-1-5-18'))"
    $script:timelineUserContext = $null
    Add-TimelineSidName -Sid $alice -Name "alice.profile" -ProfileList
    Add-TimelineSidName -Sid "S-1-5-21-1-2-3-1002" -Name "bob.bam"
    $conflict = @(
        [PSCustomObject]@{ Offset = "0x1"; User = "S-1-5-21-1-2-3-1002"; LogonAccount = "FIXTURE\bob" }
        [PSCustomObject]@{ Offset = "0x2"; User = "S-1-5-21-1-2-3-1003"; LogonAccount = "FIXTURE\carol" }
        [PSCustomObject]@{ Offset = "0x3"; User = "S-1-5-21-1-2-3-1003"; LogonAccount = "FIXTURE\dave" }
        [PSCustomObject]@{ Offset = "0x4"; User = "S-1-12-1-11-22-33-44"; LogonAccount = "AzureAD\erin" }
        [PSCustomObject]@{ Offset = "0x5"; User = "S-1-5-18"; LogonAccount = "WORKGROUP\FIXTURE-PC$" }
        [PSCustomObject]@{ Offset = "0x6"; User = $alice; LogonAccount = "FIXTURE\alice" }
    )
    Register-DbgEngLogonNames -Entries @{ Proc = $conflict }
    $named = Get-TimelineSidNames
    Assert-KitEqual -Name "Register-DbgEngLogonNames: ProfileList and bam_entries.csv names win, a SID with two accounts is left out, an Entra ID account kept as it is, SYSTEM never" `
        -Expected "alice.profile|bob.bam|False|AzureAD\erin|False" `
        -Actual "$($named[$alice])|$($named['S-1-5-21-1-2-3-1002'])|$($named.ContainsKey('S-1-5-21-1-2-3-1003'))|$($named['S-1-12-1-11-22-33-44'])|$($named.ContainsKey('S-1-5-18'))"
    $script:timelineUserContext = $null
    Register-DbgEngLogonNames -Entries @{}
    Assert-KitEqual -Name "Register-DbgEngLogonNames: no dump analyzed, nothing registered" -Expected "0" -Actual "$((Get-TimelineSidNames).Count)"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
