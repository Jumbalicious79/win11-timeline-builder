# =============================================================
# Memory test: services (work package WP7, item j)
# The Services area of the debugger engine helper
# (lib\memory\TimelineDbgEng.Services.ps1) on synthetic memory through
# tests\MemoryTestKit.ps1 (no dump, no admin): a services.exe process
# whose PEB gives its image base, a PE image whose .data section holds the
# list's first and last record pointers (beside pairs that only look like
# them), five service records in its heap (a shared service, one of its own
# whose process is not in the process list, a driver, a stopped service, a
# per-user service instance) with their image records and strings. Checked:
#   - the list read whole, in list order, each entry's fields (the svcscan
#     shape: Offset, Order, PID only for a service that is not stopped,
#     Start, State, Type, Name, Display, Binary, Account, FoundBy, Anomaly
#     HostNotListed, User from the host process), the log counts and the
#     records offered to the joins
#   - the entries through the protocol (E lines) and the builder's rows
#     (Add-DbgEngServiceRows: Memory-Services rows as Volatility's
#     windows.svcscan, the ARM64 fields appended in space style)
#   - the join with the registry in memory: an object shaped as the
#     Registry area's (read by member name), the view itself, a Services
#     key read in part (no NoRegistryKey, a note) and one not read
#   - a record whose page is not in the dump (walked forward and backward,
#     partly read, in list order), the search of services.exe's memory when
#     the list's ends are not found (a stale copy left out), the image base
#     from the memory regions when the PEB is not in the dump, records that
#     are not this layout (not read, or the registry alone), no services.exe,
#     its memory not in the dump, the time limit, the order of candidates
#   - the rules: PERSIST-SERVICE-MEMORY-SUSPICIOUS on the rows, and
#     INTEG-SERVICE-NO-REGISTRY-KEY (switched off until work package WP8)
#     switched on for this test on the rows and on
#     tests\fixtures\report\rules\cases-memory-services.csv
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryServices.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("memsvc-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8))

function ConvertTo-TestAddress { param([string]$Hex) return [Convert]::ToUInt64($Hex, 16) }

# The synthetic dump's addresses
$scm = ConvertTo-TestAddress "ffffa00000007000"
$wininit = ConvertTo-TestAddress "ffffa00000006000"
$svchost = ConvertTo-TestAddress "ffffa00000008000"
$peb = ConvertTo-TestAddress "000000d0e1a00000"
$image = ConvertTo-TestAddress "00007ff7b0000000"
$heap = ConvertTo-TestAddress "000001f2a0c00000"
$nodeImage = ConvertTo-TestAddress "ffffb10000001000"
$nodeHeap = ConvertTo-TestAddress "ffffb10000002000"
$subsection = ConvertTo-TestAddress "ffffb20000001000"
function Get-TestRecordAddress { param([int]$N) return $heap + [uint64]($N * 0x1000 + 0x40) }
function Get-TestStringAddress { param([int]$N) return $heap + [uint64](0x10000 + $N * 0x100) }

function Write-TestWide {
    param($Memory, [uint64]$Address, [string]$Text)
    $Memory.Write($scm, $Address, [System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))
}

# One service record (tag 'Sc19' at +8) and its strings
$script:stringSlot = 0
function Write-TestRecord {
    param($Memory, [uint64]$Address, [uint64]$Back, [uint64]$Next, [uint32]$Order, [uint32]$Start, [uint32]$Type, [uint32]$State, [string]$Name, [string]$Display, [uint64]$Extra)
    $Memory.WriteU32($scm, $Address + 8, [uint32]0x39316353)
    $Memory.WriteU64($scm, $Address + 0x10, $Back)
    $Memory.WriteU64($scm, $Address + 0x18, $Next)
    $Memory.WriteU32($scm, $Address + 0x20, $Order)
    $Memory.WriteU32($scm, $Address + 0x24, $Start)
    foreach ($pair in @(@(0x38, $Name), @(0x40, $Display))) {
        $script:stringSlot++
        $at = Get-TestStringAddress $script:stringSlot
        Write-TestWide -Memory $Memory -Address $at -Text $pair[1]
        $Memory.WriteU64($scm, $Address + [uint64]$pair[0], $at)
    }
    $Memory.WriteU32($scm, $Address + 0x50, $Type)
    $Memory.WriteU32($scm, $Address + 0x54, $State)
    $Memory.WriteU64($scm, $Address + 0x150, $Extra)
}

# An image record (tag 'Sc16' at +0): path +0x18, process ID +0x28, account +0x58
function Write-TestImageRecord {
    param($Memory, [uint64]$Address, [string]$Path, [uint32]$ProcessId, [string]$Account)
    $Memory.WriteU32($scm, $Address, [uint32]0x36316353)
    $script:stringSlot++
    $at = Get-TestStringAddress $script:stringSlot
    Write-TestWide -Memory $Memory -Address $at -Text $Path
    $Memory.WriteU64($scm, $Address + 0x18, $at)
    $Memory.WriteU32($scm, $Address + 0x28, $ProcessId)
    if ($Account) {
        $script:stringSlot++
        $at = Get-TestStringAddress $script:stringSlot
        Write-TestWide -Memory $Memory -Address $at -Text $Account
        $Memory.WriteU64($scm, $Address + 0x58, $at)
    }
}

# The synthetic services.exe: PEB, PE headers, .data with the list's ends
# (and pairs that only look like them), five records, two image records,
# a stale copy of a record; -States overrides every record's state
function New-TestServicesMemory {
    param([uint32]$State = 0)
    $script:stringSlot = 0
    $m = New-TestMemory
    $m.WriteU64($scm, $peb + 0x10, $image)
    # PE headers: e_lfanew 0x100, 3 sections, optional header 0xF0 bytes
    $m.Write($scm, $image, [byte[]](0x4D, 0x5A))
    $m.WriteU32($scm, $image + 0x3C, [uint32]0x100)
    $m.WriteU32($scm, $image + 0x100, [uint32]0x00004550)
    $m.WriteU16($scm, $image + 0x104, [uint16]0xAA64)
    $m.WriteU16($scm, $image + 0x106, [uint16]3)
    $m.WriteU16($scm, $image + 0x114, [uint16]0xF0)
    $table = $image + 0x100 + 24 + 0xF0
    $sections = @(@(".text", 0x1000, 0x1000, [uint32]0x60000020), @(".rdata", 0x2000, 0x1000, [uint32]0x40000040), @(".data", 0x3000, 0x2000, [Convert]::ToUInt32("C0000040", 16)))
    for ($i = 0; $i -lt 3; $i++) {
        $at = $table + [uint64](40 * $i)
        $m.Write($scm, $at, [System.Text.Encoding]::ASCII.GetBytes($sections[$i][0]))
        $m.WriteU32($scm, $at + 8, [uint32]$sections[$i][2])
        $m.WriteU32($scm, $at + 12, [uint32]$sections[$i][1])
        $m.WriteU32($scm, $at + 36, $sections[$i][3])
    }
    $r = @{}
    foreach ($n in 1..5) { $r[$n] = Get-TestRecordAddress $n }
    $imageShared = $heap + 0x20000
    $imageOwn = $heap + 0x21000
    $driverPath = $heap + 0x22000
    Write-TestImageRecord -Memory $m -Address $imageShared -Path "C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p" -ProcessId 900 -Account ""
    Write-TestImageRecord -Memory $m -Address $imageOwn -Path """C:\Users\Public\fixture-own.exe"" -service" -ProcessId 1300 -Account "LocalSystem"
    Write-TestWide -Memory $m -Address $driverPath -Text "\Driver\fixturedrv"
    $s = @{}
    foreach ($n in 1..5) { $s[$n] = if ($State -gt 0) { $State } else { @{ 1 = 4; 2 = 4; 3 = 4; 4 = 1; 5 = 4 }[$n] } }
    Write-TestRecord -Memory $m -Address $r[1] -Back 0 -Next $r[2] -Order 12 -Start 2 -Type 0x20 -State $s[1] -Name "FixtureDhcp" -Display "Fixture DHCP Client" -Extra $imageShared
    Write-TestRecord -Memory $m -Address $r[2] -Back $r[1] -Next $r[3] -Order 13 -Start 2 -Type 0x10 -State $s[2] -Name "FixtureOwn" -Display "Fixture Own" -Extra $imageOwn
    Write-TestRecord -Memory $m -Address $r[3] -Back $r[2] -Next $r[4] -Order 14 -Start 1 -Type 0x1 -State $s[3] -Name "fixturedrv" -Display "Fixture Driver" -Extra $driverPath
    Write-TestRecord -Memory $m -Address $r[4] -Back $r[3] -Next $r[5] -Order 15 -Start 3 -Type 0x10 -State $s[4] -Name "FixtureStopped" -Display "Fixture Stopped" -Extra 0
    Write-TestRecord -Memory $m -Address $r[5] -Back $r[4] -Next 0 -Order 16 -Start 3 -Type 0xE0 -State $s[5] -Name "FixtureUser_1a2b3" -Display "Fixture User Service" -Extra $imageShared
    # A stale copy: its neighbours do not link back to it
    Write-TestRecord -Memory $m -Address ($heap + 0x9040) -Back $r[1] -Next $r[2] -Order 99 -Start 2 -Type 0x10 -State 4 -Name "FixtureStale" -Display "Fixture Stale" -Extra 0
    # .data: a pair of untagged pointers, a pair of tagged records that are
    # not the list's ends, then the ends
    $data = $image + 0x3000
    $m.WriteU64($scm, $data + 0x100, $heap + 0x30000)
    $m.WriteU64($scm, $data + 0x108, $heap + 0x30100)
    $m.WriteU64($scm, $data + 0x200, $r[2])
    $m.WriteU64($scm, $data + 0x208, $r[3])
    $m.WriteU64($scm, $data + 0x3C0, $r[1])
    $m.WriteU64($scm, $data + 0x3C8, $r[5])
    return $m
}

# services.exe's memory regions: its image (a file, \Windows\System32\
# services.exe) and its heap (private read-write), as two VAD nodes
$vadDt = @{
    "_EPROCESS"          = New-TestDtText -Type "_EPROCESS" -Size 0x900 -Fields @(@(0x618, "VadRoot", "struct _RTL_AVL_TREE, 1 elements, 0x8 bytes"), @(0x628, "VadCount", "Uint8B"))
    "_EX_FAST_REF"       = New-TestDtText -Type "_EX_FAST_REF" -Size 8 -Fields @(@(0, "RefCnt", "Bitfield Pos 0, 4 Bits"))
    "_RTL_BALANCED_NODE" = New-TestDtText -Type "_RTL_BALANCED_NODE" -Size 0x18 -Fields @(@(0, "Left", "Ptr64 to struct _RTL_BALANCED_NODE"), @(8, "Right", "Ptr64 to struct _RTL_BALANCED_NODE"), @(0x10, "ParentValue", "Uint8B"))
    "_MMVAD_SHORT"       = New-TestDtText -Type "_MMVAD_SHORT" -Size 0x40 -Fields @(@(0x18, "StartingVpn", "Uint4B"), @(0x1c, "EndingVpn", "Uint4B"), @(0x20, "StartingVpnHigh", "UChar"), @(0x21, "EndingVpnHigh", "UChar"), @(0x30, "u", "union <unnamed-tag>, 6 elements, 0x4 bytes"))
    "_MMVAD_FLAGS"       = New-TestDtText -Type "_MMVAD_FLAGS" -Size 4 -Fields @(@(0, "VadType", "Bitfield Pos 4, 3 Bits"), @(0, "Protection", "Bitfield Pos 7, 5 Bits"), @(0, "PrivateMemory", "Bitfield Pos 21, 1 Bit"))
    "_MMVAD"             = New-TestDtText -Type "_MMVAD" -Size 0x88 -Fields @(@(0, "Core", "struct _MMVAD_SHORT"), @(0x48, "Subsection", "Ptr64 to struct _SUBSECTION"))
    "_SUBSECTION"        = New-TestDtText -Type "_SUBSECTION" -Size 0x38 -Fields @(@(0, "ControlArea", "Ptr64 to struct _CONTROL_AREA"))
    "_CONTROL_AREA"      = New-TestDtText -Type "_CONTROL_AREA" -Size 0x80 -Fields @(@(0x40, "FilePointer", "struct _EX_FAST_REF, 3 elements, 0x8 bytes"))
    "_FILE_OBJECT"       = New-TestDtText -Type "_FILE_OBJECT" -Size 0xd8 -Fields @(@(0x58, "FileName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
}
$pebDt = @{ "_PEB" = New-TestDtText -Type "_PEB" -Size 0x7d8 -Fields @(@(0x10, "ImageBaseAddress", "Ptr64 to Void")) }
function Get-TestDt {
    param([switch]$Vad)
    $all = @{}
    foreach ($key in $pebDt.Keys) { $all[$key] = $pebDt[$key] }
    if ($Vad) { foreach ($key in $vadDt.Keys) { $all[$key] = $vadDt[$key] } }
    return $all
}

function Write-TestVads {
    param($Memory)
    $nodes = @(
        @($nodeHeap, $heap, [uint64]0x30000, 0, 4, 1, [uint64]0),
        @($nodeImage, $image, [uint64]0x5000, 2, 7, 0, $subsection)
    )
    foreach ($n in $nodes) {
        $node = $n[0]
        $startVpn = [uint64]$n[1] -shr 12
        $endVpn = ([uint64]$n[1] + $n[2] - 1) -shr 12
        $Memory.WriteU32(0, $node + 0x18, [uint32]($startVpn -band [uint64]4294967295))
        $Memory.WriteU32(0, $node + 0x1c, [uint32]($endVpn -band [uint64]4294967295))
        $Memory.WriteU8(0, $node + 0x20, [byte]($startVpn -shr 32))
        $Memory.WriteU8(0, $node + 0x21, [byte]($endVpn -shr 32))
        $Memory.WriteU32(0, $node + 0x30, [uint32](($n[3] -shl 4) -bor ($n[4] -shl 7) -bor ($n[5] -shl 21)))
        $Memory.WriteU64(0, $node + 0x48, $n[6])
    }
    # The image node is the root, the heap node its left child
    $Memory.WriteU64(0, $nodeImage, $nodeHeap)
    $Memory.WriteU64(0, $nodeHeap + 0x10, $nodeImage)
    $control = $subsection + 0x100
    $file = $subsection + 0x200
    $Memory.WriteU64(0, $subsection, $control)
    $Memory.WriteU64(0, $control + 0x40, $file -bor 1)
    $Memory.WriteUnicodeString(0, $file + 0x58, $file + 0x80, "\Windows\System32\services.exe")
}

# The processes of the scan: wininit, services.exe (its VAD root in its
# block), a svchost whose token user is LOCAL SERVICE
function Get-TestProcesses {
    param([switch]$Fake)
    $block = New-Object byte[] 0x900
    [Array]::Copy([BitConverter]::GetBytes($nodeImage), 0, $block, 0x618, 8)
    [Array]::Copy([BitConverter]::GetBytes([long]2), 0, $block, 0x628, 8)
    $boot = [datetime]::new(2026, 10, 11, 8, 0, 0, [DateTimeKind]::Utc)
    $list = @(
        @{ Eprocess = $wininit; Pid = [long]600; Ppid = [long]500; ShortName = "wininit.exe"; CreateTime = $boot },
        @{ Eprocess = $scm; Pid = [long]700; Ppid = [long]600; ShortName = "services.exe"; CreateTime = $boot.AddSeconds(1); Peb = $peb; Block = $block },
        @{ Eprocess = $svchost; Pid = [long]900; Ppid = [long]700; ShortName = "svchost.exe"; CreateTime = $boot.AddSeconds(2); UserSid = "S-1-5-19" }
    )
    if ($Fake) {
        # Another services.exe, started earlier by a process that is not wininit
        $list += @{ Eprocess = (ConvertTo-TestAddress "ffffa00000009000"); Pid = [long]4400; Ppid = [long]4000; ShortName = "services.exe"; CreateTime = $boot.AddSeconds(-5); Peb = (ConvertTo-TestAddress "000000d0e1b00000") }
    }
    return $list
}

# The area on a memory: its AreaResult (-Vad: the kernel's symbols describe
# the VADs; -Registry: what the Registry area offers)
function Invoke-TestServices {
    param($Memory, [switch]$Vad, $Registry, [switch]$NoProcesses, [switch]$Fake, [double]$CapSeconds = 30)
    Set-TestEngineCommands -Dt (Get-TestDt -Vad:$Vad)
    $processes = if ($NoProcesses) { @(@{ Eprocess = $svchost; Pid = [long]900; Ppid = [long]700; ShortName = "svchost.exe" }) } else { Get-TestProcesses -Fake:$Fake }
    $script:testContext = New-TestContext -Memory $Memory -Processes $processes
    if ($null -ne $Registry) { $script:testContext.Shared["RegistryServices"] = $Registry }
    return (Invoke-TestArea -Name "Services" -Context $script:testContext -CapSeconds $CapSeconds)
}

# Each entry as "Name|Order|PID|Start|State|Type|Binary|Account|FoundBy|Anomaly|User|RegistryBinary|Dll"
function Get-TestServiceText {
    param($Area)
    return @($Area.Entries | ForEach-Object {
            $f = Get-TestEntryFields $_
            "$($f['Name'])|$($f['Order'])|$($f['PID'])|$($f['Start'])|$($f['State'])|$($f['Type'])|$($f['Binary'])|$($f['Account'])|$($f['FoundBy'])|$($f['Anomaly'])|$($f['User'])|$($f['RegistryBinary'])|$($f['Dll'])"
        }) -join " / "
}

# The Registry area's Services key, as a C# object of the same shape (the
# Services area reads it by member name, so the Registry area's own type
# is not needed to compile it)
$shapeSource = @'
using System;
using System.Collections.Generic;
namespace TimelineDbgEngServicesTest
{
    public sealed class RegistryKeyShape
    {
        public string Name = "";
        public string ImagePath;
        public string ServiceDll;
        public string ObjectName;
        public string DisplayName;
        public long Start = -1;
        public long Type = -1;
    }
    public sealed class RegistryShape
    {
        public string State = "Read";
        public string Why = "";
        public bool Complete;
        public readonly Dictionary<string, RegistryKeyShape> Keys = new Dictionary<string, RegistryKeyShape>(StringComparer.OrdinalIgnoreCase);
        public RegistryKeyShape Add(string name, string imagePath, string serviceDll, string objectName, long start, long type)
        {
            RegistryKeyShape k = new RegistryKeyShape();
            k.Name = name; k.ImagePath = imagePath; k.ServiceDll = serviceDll; k.ObjectName = objectName; k.DisplayName = "@fixture.dll,-" + name.Length; k.Start = start; k.Type = type;
            Keys[name] = k;
            return k;
        }
    }
}
'@
function New-TestRegistry {
    param([bool]$Complete = $true, [string]$State = "Read")
    $registry = New-Object TimelineDbgEngServicesTest.RegistryShape
    $registry.Complete = $Complete
    $registry.State = $State
    [void]$registry.Add("FixtureDhcp", "%SystemRoot%\system32\svchost.exe -k LocalServiceNetworkRestricted -p", "%SystemRoot%\system32\dhcpcore.dll", "NT AUTHORITY\LocalService", 2, 0x20)
    [void]$registry.Add("fixtureown", """C:\Users\Public\fixture-own.exe"" -service", $null, "LocalSystem", 2, 0x10)
    [void]$registry.Add("fixturedrv", "\SystemRoot\System32\drivers\fixturedrv.sys", $null, $null, 1, 1)
    [void]$registry.Add("FixtureStoppedGone", "C:\Program Files\Fixture\gone.exe", $null, "LocalSystem", 3, 0x10)
    return $registry
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryServices"
    if (-not ([System.Management.Automation.PSTypeName]'TimelineDbgEngServicesTest.RegistryShape').Type) { Add-Type -TypeDefinition $shapeSource -ErrorAction Stop }
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    $first = "0x" + (Get-TestRecordAddress 1).ToString("x")
    $wholeList = @(
        "FixtureDhcp|12|900|SERVICE_AUTO_START|SERVICE_RUNNING|SERVICE_WIN32_SHARE_PROCESS|C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p||ScmList||S-1-5-19||",
        "FixtureOwn|13|1300|SERVICE_AUTO_START|SERVICE_RUNNING|SERVICE_WIN32_OWN_PROCESS|""C:\Users\Public\fixture-own.exe"" -service|LocalSystem|ScmList|HostNotListed|||",
        "fixturedrv|14||SERVICE_SYSTEM_START|SERVICE_RUNNING|SERVICE_KERNEL_DRIVER|\Driver\fixturedrv||ScmList||||",
        "FixtureStopped|15||SERVICE_DEMAND_START|SERVICE_STOPPED|SERVICE_WIN32_OWN_PROCESS|||ScmList||||",
        "FixtureUser_1a2b3|16|900|SERVICE_DEMAND_START|SERVICE_RUNNING|SERVICE_WIN32_SHARE_PROCESS,SERVICE_USER_SERVICE,SERVICE_USERSERVICE_INSTANCE|C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p||ScmList||S-1-5-19||"
    ) -join " / "

    # --- The whole list -----------------------------------------------------------
    $memory = New-TestServicesMemory
    $area = Invoke-TestServices -Memory $memory
    $shared = $script:testContext.Shared["ServiceRecords"]
    Assert-KitEqual -Name "the list from the pointers in .data (not the untagged pair, not two records that are not its ends): read, five entries in list order with their fields" `
        -Expected "Read||5|$wholeList" -Actual "$($area.State)|$($area.Note)|$($area.Entries.Count)|$(Get-TestServiceText $area)"
    $firstFields = Get-TestEntryFields $area.Entries[0]
    Assert-KitEqual -Name "an entry: Offset is the record's address, the keys in the svcscan order, the records offered to the joins" `
        -Expected "$first|Offset,Order,PID,Start,State,Type,Name,Display,Binary,FoundBy,User|Fixture DHCP Client|5|$($area.Entries[0].Get('Name'))" `
        -Actual "$($firstFields['Offset'])|$(@($area.Entries[0].Keys) -join ',')|$($firstFields['Display'])|$($shared.Count)|$($shared[0].Name)"
    Assert-KitEqual -Name "the log counts: records, walks, running, drivers, image records, hosts, accounts" `
        -Expected "service records 5, walked forward 5, running 4, drivers 1, driver paths 1, image records 3, host process IDs 3, hosts not in the process list 1, accounts 1" `
        -Actual $area.Coverage.CountsText
    $peCommands = @($script:testEngineCommands | Where-Object { $_ -like "dt -v *" })
    Assert-KitEqual -Name "the kernel's symbols asked for the PEB only (no VAD walker when the list is found whole)" -Expected "dt -v nt!_PEB" -Actual ($peCommands -join ",")

    # --- The protocol and the builder's rows -------------------------------------------
    $state = New-DbgEngWorkerState
    foreach ($entry in $area.Entries) { Receive-DbgEngWorkerLine -Line $entry.ToLine() -State $state }
    $lineFields = Get-TestEntryFields $area.Entries[1].ToLine()
    Assert-KitEqual -Name "the E line (Base64 in C#) gives back the fields; the builder reads all five" -Expected "FixtureOwn|""C:\Users\Public\fixture-own.exe"" -service|HostNotListed|5|0" `
        -Actual "$($lineFields['Name'])|$($lineFields['Binary'])|$($lineFields['Anomaly'])|$($state.EntryCount)|$($state.BadLines)"
    [void](Get-TestRows)
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    $counts = Add-DbgEngServiceRows -Entries (ConvertTo-DbgEngEntryArray $state.Entries["Service"]) -Source "Memory-Services" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    $rows = @(Get-TestRows)
    Assert-KitEqual -Name "Add-DbgEngServiceRows: five Snapshot rows at the capture time as windows.svcscan's, the ARM64 fields appended (spaces last), User from the host" -Expected (@(
            "Memory-Services|2026-10-11 12:30:00.000|Snapshot|Service in memory: Fixture DHCP Client (FixtureDhcp)|S-1-5-19|State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary=C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p PID=900 Type=SERVICE_WIN32_SHARE_PROCESS Order=12 FoundBy=ScmList",
            "Memory-Services|2026-10-11 12:30:00.000|Snapshot|Service in memory: Fixture Own (FixtureOwn)||State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary=""C:\Users\Public\fixture-own.exe"" -service PID=1300 Type=SERVICE_WIN32_OWN_PROCESS Order=13 FoundBy=ScmList Anomaly=HostNotListed Account=LocalSystem",
            "Memory-Services|2026-10-11 12:30:00.000|Snapshot|Service in memory: Fixture Driver (fixturedrv)||State=SERVICE_RUNNING StartType=SERVICE_SYSTEM_START Binary=\Driver\fixturedrv PID= Type=SERVICE_KERNEL_DRIVER Order=14 FoundBy=ScmList",
            "Memory-Services|2026-10-11 12:30:00.000|Snapshot|Service in memory: Fixture Stopped (FixtureStopped)||State=SERVICE_STOPPED StartType=SERVICE_DEMAND_START Binary= PID= Type=SERVICE_WIN32_OWN_PROCESS Order=15 FoundBy=ScmList",
            "Memory-Services|2026-10-11 12:30:00.000|Snapshot|Service in memory: Fixture User Service (FixtureUser_1a2b3)|S-1-5-19|State=SERVICE_RUNNING StartType=SERVICE_DEMAND_START Binary=C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p PID=900 Type=SERVICE_WIN32_SHARE_PROCESS,SERVICE_USER_SERVICE,SERVICE_USERSERVICE_INSTANCE Order=16 FoundBy=ScmList",
            "5|0|5") -join " / ") -Actual ((@($rows) + @("$($counts.Entries)|$($counts.Timed)|$($counts.Snapshot)")) -join " / ")
    $nameless = Add-DbgEngServiceRows -Entries @([PSCustomObject]@{ Offset = "0x1f2a0c05040"; Name = ""; Display = ""; State = "SERVICE_RUNNING"; Start = "SERVICE_AUTO_START"; Binary = "" }) -Source "Memory-Services" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture -DumpPath "C:\dumps\fixture.dmp"
    $empty = Add-DbgEngServiceRows -Entries @() -Source "Memory-Services" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture -DumpPath "C:\dumps\fixture.dmp"
    Assert-KitEqual -Name "Add-DbgEngServiceRows: a record whose name was not in the dump is named by its address; no entries, no rows" `
        -Expected "Service in memory: service record at 0x1f2a0c05040 ()|State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary= PID=|1|0" `
        -Actual "$(@(Get-TestRows -Objects | ForEach-Object { "$($_.Description)|$($_.Details)" }) -join ' / ')|$($nameless.Entries)|$($empty.Entries)"

    # --- The registry in memory -----------------------------------------------------------
    $joinedText = @(
        "FixtureDhcp|12|900|SERVICE_AUTO_START|SERVICE_RUNNING|SERVICE_WIN32_SHARE_PROCESS|C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p|NT AUTHORITY\LocalService|ScmList,Registry||S-1-5-19|%SystemRoot%\system32\svchost.exe -k LocalServiceNetworkRestricted -p|%SystemRoot%\system32\dhcpcore.dll",
        "FixtureOwn|13|1300|SERVICE_AUTO_START|SERVICE_RUNNING|SERVICE_WIN32_OWN_PROCESS|""C:\Users\Public\fixture-own.exe"" -service|LocalSystem|ScmList,Registry|HostNotListed||""C:\Users\Public\fixture-own.exe"" -service|",
        "fixturedrv|14||SERVICE_SYSTEM_START|SERVICE_RUNNING|SERVICE_KERNEL_DRIVER|\Driver\fixturedrv||ScmList,Registry|||\SystemRoot\System32\drivers\fixturedrv.sys|",
        "FixtureStopped|15||SERVICE_DEMAND_START|SERVICE_STOPPED|SERVICE_WIN32_OWN_PROCESS|||ScmList||||",
        "FixtureUser_1a2b3|16|900|SERVICE_DEMAND_START|SERVICE_RUNNING|SERVICE_WIN32_SHARE_PROCESS,SERVICE_USER_SERVICE,SERVICE_USERSERVICE_INSTANCE|C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p||ScmList|NoRegistryKey|S-1-5-19||"
    )
    $joined = Invoke-TestServices -Memory (New-TestServicesMemory) -Registry (New-TestRegistry)
    Assert-KitEqual -Name "the join with the Registry area's Services key (read by member name, names in any case): RegistryBinary, Dll, the key's account when the record has none, ScmList,Registry; NoRegistryKey for a running service without a key, never a stopped one" `
        -Expected "Read||$($joinedText -join ' / ')" -Actual "$($joined.State)|$($joined.Note)|$(Get-TestServiceText $joined)"
    Assert-KitEqual -Name "the join's counts" -Expected "joined with the registry in memory 3, not in the registry's Services key 1" `
        -Actual (($joined.Coverage.CountsText -split ', ' | Select-Object -Last 2) -join ', ')
    $state = New-DbgEngWorkerState
    foreach ($entry in $joined.Entries) { Receive-DbgEngWorkerLine -Line $entry.ToLine() -State $state }
    [void](Add-DbgEngServiceRows -Entries (ConvertTo-DbgEngEntryArray $state.Entries["Service"]) -Source "Memory-Services" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture -DumpPath "C:\dumps\fixture.dmp")
    $joinedRows = @(Get-TestRows -Objects)
    Assert-KitEqual -Name "a joined row: Account, RegistryBinary and ServiceDll last, in that order" `
        -Expected "State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary=C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p PID=900 Type=SERVICE_WIN32_SHARE_PROCESS Order=12 FoundBy=ScmList,Registry Account=NT AUTHORITY\LocalService RegistryBinary=%SystemRoot%\system32\svchost.exe -k LocalServiceNetworkRestricted -p ServiceDll=%SystemRoot%\system32\dhcpcore.dll" `
        -Actual $joinedRows[0].Details
    $partialKey = Invoke-TestServices -Memory (New-TestServicesMemory) -Registry (New-TestRegistry -Complete $false)
    Assert-KitEqual -Name "a Services key read in part: joined, no NoRegistryKey, and a note says why" `
        -Expected "Read|the registry's Services key in memory was not read in full, so a service without a key there is not marked|3|0" `
        -Actual "$($partialKey.State)|$($partialKey.Note)|$(@($partialKey.Entries | Where-Object { $_.Get('FoundBy') -eq 'ScmList,Registry' }).Count)|$(@($partialKey.Entries | Where-Object { $_.Get('Anomaly') -match 'NoRegistryKey' }).Count)"
    $notRead = Invoke-TestServices -Memory (New-TestServicesMemory) -Registry (New-TestRegistry -State "NotRead")
    Assert-KitEqual -Name "a Services key that was not read: no join, no note, the list as without one" -Expected "Read||$wholeList|False" `
        -Actual "$($notRead.State)|$($notRead.Note)|$(Get-TestServiceText $notRead)|$($notRead.Coverage.CountsText.Contains('registry'))"
    $view = New-Object TimelineDbgEng.ServiceRegistryView
    $view.Complete = $true
    $viewKey = New-Object TimelineDbgEng.ServiceRegistryKey
    $viewKey.Name = "FixtureDhcp"; $viewKey.ImagePath = "%SystemRoot%\system32\svchost.exe -k fixture"
    $view.Keys["FixtureDhcp"] = $viewKey
    $viewArea = Invoke-TestServices -Memory (New-TestServicesMemory) -Registry $view
    Assert-KitEqual -Name "a ServiceRegistryView as given: joined as is (only FixtureDhcp has a key, the other running ones are marked)" `
        -Expected "ScmList,Registry|%SystemRoot%\system32\svchost.exe -k fixture|HostNotListed,NoRegistryKey|NoRegistryKey||NoRegistryKey" `
        -Actual "$($viewArea.Entries[0].Get('FoundBy'))|$($viewArea.Entries[0].Get('RegistryBinary'))|$($viewArea.Entries[1].Get('Anomaly'))|$($viewArea.Entries[2].Get('Anomaly'))|$($viewArea.Entries[3].Get('Anomaly'))|$($viewArea.Entries[4].Get('Anomaly'))"
    $problem = ""
    $none = [TimelineDbgEng.ServiceRegistryView]::From($null, [ref]$problem)
    $oddView = [TimelineDbgEng.ServiceRegistryView]::From((New-Object System.Text.StringBuilder), [ref]$problem)
    Assert-KitEqual -Name "ServiceRegistryView.From: nothing offered, or an object without Keys, is no view (with why)" -Expected "True|True|the registry's Services key is not in a form this area knows" `
        -Actual "$($null -eq $none)|$($null -eq $oddView)|$problem"

    # --- What a live copy leaves out --------------------------------------------------------
    $gap = New-TestServicesMemory
    $gap.Remove($scm, (Get-TestRecordAddress 3))
    $gapArea = Invoke-TestServices -Memory $gap
    Assert-KitEqual -Name "a record not in the dump: walked forward to it and backward from the last record, partly read, in list order, the note and the counts say so" `
        -Expected ("Partial|FixtureDhcp,FixtureOwn,FixtureStopped,FixtureUser_1a2b3|" +
            "services.exe's memory regions could not be read, the kernel's symbols do not describe them; the service control manager's list was read in part, 4 records, as when a live copy leaves part of the memory of services.exe out|" +
            "service records 4, walked forward 2, walked backward 2") `
        -Actual "$($gapArea.State)|$(@($gapArea.Entries | ForEach-Object { $_.Get('Name') }) -join ',')|$($gapArea.Note)|$(($gapArea.Coverage.CountsText -split ', ' | Select-Object -First 3) -join ', ')"
    $gapVad = New-TestServicesMemory
    Write-TestVads -Memory $gapVad
    $gapVad.Remove($scm, (Get-TestRecordAddress 3))
    $gapVadArea = Invoke-TestServices -Memory $gapVad -Vad
    Assert-KitEqual -Name "the same with the memory regions: services.exe's heap searched, nothing more found (the stale copy left out), still partly read" `
        -Expected "Partial|4|found by a search of services.exe's memory 0, stale copies left out 1" `
        -Actual "$($gapVadArea.State)|$($gapVadArea.Entries.Count)|$(($gapVadArea.Coverage.CountsText -split ', ' | Where-Object { $_ -match 'search|stale' }) -join ', ')"
    $noEnds = New-TestServicesMemory
    Write-TestVads -Memory $noEnds
    $noEnds.WriteU64($scm, $image + 0x33C0, [uint64]0)
    $noEndsArea = Invoke-TestServices -Memory $noEnds -Vad
    Assert-KitEqual -Name "the list's ends not in .data: services.exe's heap searched for the record tag, every record linked back found (FoundBy=MemoryScan), the stale copy left out, the list whole" `
        -Expected "Read|FixtureDhcp,FixtureOwn,fixturedrv,FixtureStopped,FixtureUser_1a2b3|MemoryScan|found by a search of services.exe's memory 5, stale copies left out 1" `
        -Actual "$($noEndsArea.State)|$(@($noEndsArea.Entries | ForEach-Object { $_.Get('Name') }) -join ',')|$(@($noEndsArea.Entries | ForEach-Object { $_.Get('FoundBy') } | Sort-Object -Unique) -join ',')|$(($noEndsArea.Coverage.CountsText -split ', ' | Where-Object { $_ -match 'search|stale' }) -join ', ')"
    $noEndsNoVad = New-TestServicesMemory
    $noEndsNoVad.WriteU64($scm, $image + 0x33C0, [uint64]0)
    $noEndsNoVadArea = Invoke-TestServices -Memory $noEndsNoVad
    Assert-KitEqual -Name "the list's ends not in .data and no memory regions: not read, and why" -Expected "NotRead|the service control manager's list was not found in the memory of services.exe|0" `
        -Actual "$($noEndsNoVadArea.State)|$($noEndsNoVadArea.Note)|$($noEndsNoVadArea.Entries.Count)"
    $noPeb = New-TestServicesMemory
    Write-TestVads -Memory $noPeb
    $noPeb.Remove($scm, $peb)
    $noPebArea = Invoke-TestServices -Memory $noPeb -Vad
    Assert-KitEqual -Name "the PEB not in the dump: the image base from services.exe's memory region of services.exe, the list found whole" `
        -Expected "Read|5|$wholeList" -Actual "$($noPebArea.State)|$($noPebArea.Entries.Count)|$(Get-TestServiceText $noPebArea)"
    $noPebNoVadArea = Invoke-TestServices -Memory $noPeb
    Assert-KitEqual -Name "the PEB not in the dump and no memory regions: not read, and why" -Expected "NotRead|the program image of services.exe is not in the dump" `
        -Actual "$($noPebNoVadArea.State)|$($noPebNoVadArea.Note)"

    # --- Not this layout, no services.exe, its memory gone, the time limit -----------------------
    $odd = Invoke-TestServices -Memory (New-TestServicesMemory -State 99)
    Assert-KitEqual -Name "records whose states are not this layout's: not read, no entries, the counts kept for the log" `
        -Expected "NotRead|the service records are not in the layout this helper knows for Windows 11 build 26100|0|service records 5, plausible 0" `
        -Actual "$($odd.State)|$($odd.Note)|$($odd.Entries.Count)|$($odd.Coverage.CountsText)"
    $oddRegistry = Invoke-TestServices -Memory (New-TestServicesMemory -State 99) -Registry (New-TestRegistry)
    Assert-KitEqual -Name "... with the registry's Services key: its services alone (FoundBy=Registry, by name, no state or process), partly read, and why" `
        -Expected ("Partial|the service control manager's list was not read, the service records are not in the layout this helper knows for Windows 11 build 26100, so the services come from the registry in memory alone|" +
            "FixtureDhcp|||SERVICE_AUTO_START||SERVICE_WIN32_SHARE_PROCESS||NT AUTHORITY\LocalService|Registry|||%SystemRoot%\system32\svchost.exe -k LocalServiceNetworkRestricted -p|%SystemRoot%\system32\dhcpcore.dll / " +
            "fixturedrv|||SERVICE_SYSTEM_START||SERVICE_KERNEL_DRIVER|||Registry|||\SystemRoot\System32\drivers\fixturedrv.sys| / " +
            "fixtureown|||SERVICE_AUTO_START||SERVICE_WIN32_OWN_PROCESS||LocalSystem|Registry|||""C:\Users\Public\fixture-own.exe"" -service| / " +
            "FixtureStoppedGone|||SERVICE_DEMAND_START||SERVICE_WIN32_OWN_PROCESS||LocalSystem|Registry|||C:\Program Files\Fixture\gone.exe|") `
        -Actual "$($oddRegistry.State)|$($oddRegistry.Note)|$(Get-TestServiceText $oddRegistry)"
    $nobody = Invoke-TestServices -Memory (New-TestServicesMemory) -NoProcesses
    Assert-KitEqual -Name "no services.exe among the processes: not read, and no symbol asked for" -Expected "NotRead|services.exe is not among the processes|0" `
        -Actual "$($nobody.State)|$($nobody.Note)|$(@($script:testEngineCommands).Count)"
    $refused = New-TestServicesMemory
    $refused.Refuse($scm)
    $refusedArea = Invoke-TestServices -Memory $refused
    Assert-KitEqual -Name "services.exe's memory not in the dump (its switch refused): not read, and why" -Expected "NotRead|the memory of services.exe is not in the dump" `
        -Actual "$($refusedArea.State)|$($refusedArea.Note)"
    $late = Invoke-TestServices -Memory (New-TestServicesMemory) -CapSeconds 0.000001
    Assert-KitEqual -Name "the time limit reached: not read, and why" -Expected "NotRead|it stopped at its time limit of 0 s" -Actual "$($late.State)|$($late.Note)"
    $fake = Invoke-TestServices -Memory (New-TestServicesMemory) -Fake
    $scan = New-Object TimelineDbgEng.ServiceScan -ArgumentList $script:testContext, (New-Object TimelineDbgEng.AreaResult -ArgumentList "Services", 30)
    Assert-KitEqual -Name "two services.exe: the one wininit.exe started is tried first (the other started earlier), the list found in it" `
        -Expected "700,4400|Read|5" -Actual "$(@($scan.FindCandidates() | ForEach-Object { $_.Pid }) -join ',')|$($fake.State)|$($fake.Entries.Count)"

    # --- The rules ------------------------------------------------------------------------------
    . (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\TimelineReport.Engine.ps1")
    $rules = Import-ReportRules -Path (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\report-rules.json")
    $suspicious = @($rules.Rules | Where-Object { $_.Id -eq "PERSIST-SERVICE-MEMORY-SUSPICIOUS" })[0]
    $noKey = @($rules.Rules | Where-Object { $_.Id -eq "INTEG-SERVICE-NO-REGISTRY-KEY" })[0]
    Assert-KitEqual -Name "the rules file: PERSIST-SERVICE-MEMORY-SUSPICIOUS switched on (Medium), INTEG-SERVICE-NO-REGISTRY-KEY switched off until WP8 (Medium)" `
        -Expected "True|Medium|False|Medium" -Actual "$($suspicious.Enabled)|$($suspicious.Severity)|$($noKey.Enabled)|$($noKey.Severity)"
    $noKey.Enabled = $true
    try {
        # The joined rows of the synthetic dump, as the timeline has them
        $csvPath = Join-Path $workDir "rows.csv"
        $joinedRows | Select-Object Timestamp, Source, EventType, Description, User, Details, Artifact, RawPath | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        $findings = @(Invoke-ReportRules -Rows @(Import-TimelineCsvForReport -Path $csvPath) -Rules $rules | Where-Object { $_.RuleId -match '^(PERSIST-SERVICE-MEMORY-SUSPICIOUS|INTEG-SERVICE-NO-REGISTRY-KEY|PERSIST-SERVICE-REMOTEACCESS)$' })
        Assert-KitEqual -Name "the rules on the joined rows: the service from \Users\Public\ is a lead, the service without a registry key is one (rule switched on here)" `
            -Expected "INTEG-SERVICE-NO-REGISTRY-KEY:Fixture User Service (FixtureUser_1a2b3):6|PERSIST-SERVICE-MEMORY-SUSPICIOUS:Fixture Own (FixtureOwn):3" `
            -Actual (@($findings | Sort-Object RuleId | ForEach-Object { "$($_.RuleId):$($_.GroupKey):$(@($_.RowNumbers) -join ',')" }) -join "|")
        $casesPath = Join-Path $PSScriptRoot "fixtures\report\rules\cases-memory-services.csv"
        $caseRows = @(Import-TimelineCsvForReport -Path $casesPath)
        $caseFindings = @(Invoke-ReportRules -Rows $caseRows -Rules $rules | Where-Object { $_.RuleId -eq "INTEG-SERVICE-NO-REGISTRY-KEY" })
        $flagged = @($caseFindings | ForEach-Object { $_.RowNumbers } | ForEach-Object { [int]$_ } | Sort-Object)
        $expectedRows = @(for ($i = 0; $i -lt $caseRows.Count; $i++) { if ("$($caseRows[$i].Details)" -match '(?:^|\s)Anomaly=[^\s|]*\bNoRegistryKey\b') { $i + 2 } })
        Assert-KitEqual -Name "INTEG-SERVICE-NO-REGISTRY-KEY switched on over cases-memory-services.csv: exactly its rows with Anomaly=...NoRegistryKey (not the name, not HostNotListed alone)" `
            -Expected "$($expectedRows -join ',')|2" -Actual "$($flagged -join ',')|$($expectedRows.Count)"
    }
    finally { $noKey.Enabled = $false }
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
Complete-KitTest
