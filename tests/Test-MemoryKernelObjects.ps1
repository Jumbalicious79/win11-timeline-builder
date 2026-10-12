# =============================================================
# Memory test: kernel drivers and handles (work package WP3, items d and e)
# On a synthetic kernel through tests\MemoryTestKit.ps1 (no dump, no admin;
# the layouts are those of Windows 11 24H2 ARM64, given as the engine's
# "dt -v" text): object headers (the type index mixed with the cookie and
# the header's address, names, full names), the object directory and its
# symbolic links (\SystemRoot, \??\C:, \Device\BootDevice) as drive-letter
# paths; the drivers area (the module list both ways, the driver objects of
# \Driver and \FileSystem, a hidden driver, a driver object whose entry moved,
# one without a module, the walks broken one way and both ways, the recently
# unloaded drivers with times since boot and absolute ones, a slot that
# fails its checks, a list whose layout does not fit); the handles area
# (one- and two-level handle tables, a page not in the dump, every row kind
# and what is left out: rights that cannot change a process, parent and
# child, the System process, thread handles folded into a process row, the
# process family of the anomaly, a target outside the scan, file names with
# drive letters and relative names, key paths through hive mount points,
# Image File Execution Options and Services keys, named and unnamed
# mutexes, objects not in the dump, the holder's SID read from its token,
# the lookup for the joins); missing symbols and the time limit; then the
# builder's rows (Add-DbgEngDriverRows, Add-DbgEngHandleRows through the
# protocol) and the findings rules on them (INTEG-DRIVER-HIDDEN,
# PERSIST-DRIVER-USERPATH, and INTEG-HANDLE-WRITE-ACCESS switched on here).
# The rules' own HIT and MISS rows: tests\fixtures\report\rules\
# cases-memory-kernelobjects.csv (Test-ReportRules.ps1).
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryKernelObjects.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }

# A kernel address from its hex digits (never a PowerShell hex literal:
# 0xFFFF... is a negative Int64)
function K([string]$Hex) { return [Convert]::ToUInt64($Hex, 16) }
# An address plus an offset (both as unsigned)
function At([uint64]$Address, [long]$Offset) {
    if ($Offset -ge 0) { return $Address + [uint64]$Offset }
    return $Address - [uint64](-$Offset)
}

# --- The synthetic kernel's memory: allocations, strings, objects --------------------

# Small structures and strings, 16-byte aligned
function New-TestAlloc([int]$Size) {
    $address = $script:heap
    $script:heap = At $script:heap ([long]([Math]::Ceiling($Size / 16.0) * 16 + 16))
    return $address
}
# A _UNICODE_STRING at -At whose text is in a new allocation
function Write-TestString([uint64]$Address, [string]$Text) {
    $buffer = New-TestAlloc ([Math]::Max(2, $Text.Length * 2))
    $script:memory.WriteUnicodeString(0, $Address, $buffer, $Text)
}
# An object's body: one per 4 KB page, at +0x100 (its header 0x30 before
# it, its name header 0x20 before that)
function New-TestBody {
    $body = $script:nextBody
    $script:nextBody = At $script:nextBody 0x1000
    return $body
}
# The type of an index: an _OBJECT_TYPE in nt!ObTypeIndexTable
function Add-TestType([string]$Name, [int]$Index) {
    $type = New-TestAlloc 0xe0
    Write-TestString (At $type 0x10) $Name
    $script:memory.WriteU8(0, (At $type 0x28), [byte]$Index)
    $script:memory.WriteU64(0, (At $script:typeTable ($Index * 8)), $type)
    $script:typeIndex[$Name] = $Index
}
# An object's header: its type (index XOR cookie XOR the header's second
# byte) and, with -Name, its name header (in -Directory)
function Set-TestObject([uint64]$Body, [string]$Type, [string]$Name = $null, [uint64]$Directory = 0, [int]$RawIndex = -1) {
    $header = At $Body (-0x30)
    $index = if ($RawIndex -ge 0) { $RawIndex } else { $script:typeIndex[$Type] }
    $encoded = $index -bxor $script:cookie -bxor [int](($header -shr 8) -band 0xFF)
    $script:memory.WriteU8(0, (At $header 0x18), [byte]$encoded)
    $mask = 0
    if ($null -ne $Name) {
        $mask = 2
        $info = At $header (-0x20)
        $script:memory.WriteU64(0, $info, $Directory)
        Write-TestString (At $info 8) $Name
    }
    $script:memory.WriteU8(0, (At $header 0x1a), [byte]$mask)
}
# A new object (its body)
function New-TestObject([string]$Type, [string]$Name = $null, [uint64]$Directory = 0) {
    $body = New-TestBody
    Set-TestObject -Body $body -Type $Type -Name $Name -Directory $Directory
    return $body
}
# A directory's hash chains: -Entries, the bodies of its objects (entry i
# in chain i % 37)
function Set-TestDirectory([uint64]$Directory, [uint64[]]$Entries) {
    $tails = @{}
    for ($i = 0; $i -lt $Entries.Count; $i++) {
        $entry = New-TestAlloc 0x18
        $script:memory.WriteU64(0, (At $entry 8), $Entries[$i])
        $bucket = $i % 37
        if ($tails.ContainsKey($bucket)) { $script:memory.WriteU64(0, $tails[$bucket], $entry) }
        else { $script:memory.WriteU64(0, (At $Directory ($bucket * 8)), $entry) }
        $tails[$bucket] = $entry
    }
}
function New-TestLink([string]$Name, [uint64]$Directory, [string]$Target) {
    $link = New-TestObject -Type "SymbolicLink" -Name $Name -Directory $Directory
    Write-TestString (At $link 8) $Target
    return $link
}
# A module list entry (_KLDR_DATA_TABLE_ENTRY)
function New-TestModule([uint64]$Base, [int]$Size, [string]$FullName, [string]$Name) {
    $entry = New-TestAlloc 0xa0
    $script:memory.WriteU64(0, (At $entry 0x30), $Base)
    $script:memory.WriteU32(0, (At $entry 0x40), [uint32]$Size)
    Write-TestString (At $entry 0x48) $FullName
    Write-TestString (At $entry 0x58) $Name
    return $entry
}
function Set-TestLinks([uint64]$Entry, [uint64]$Forward, [uint64]$Back) {
    $script:memory.WriteU64(0, $Entry, $Forward)
    $script:memory.WriteU64(0, (At $Entry 8), $Back)
}
# A driver object (_DRIVER_OBJECT) in a directory
function New-TestDriver([string]$Name, [uint64]$Directory, [string]$DriverName, [uint64]$Section, [uint64]$Start, [int]$Size) {
    $driver = New-TestObject -Type "Driver" -Name $Name -Directory $Directory
    $script:memory.WriteU64(0, (At $driver 0x18), $Start)
    $script:memory.WriteU32(0, (At $driver 0x20), [uint32]$Size)
    $script:memory.WriteU64(0, (At $driver 0x28), $Section)
    Write-TestString (At $driver 0x38) $DriverName
    return $driver
}
# A handle table entry's two halves: the header pointer in
# ObjectPointerBits (bit 20, 44 bits, the address shifted right by 4) and
# the access in GrantedAccessBits
function Set-TestHandle([uint64]$Page, [int]$Slot, [uint64]$Body, [uint32]$Access) {
    $header = At $Body (-0x30)
    $bits = ($header -shr 4) -band (K "00000FFFFFFFFFFF")
    $script:memory.WriteU64(0, (At $Page ($Slot * 16)), (($bits -shl 20) -bor 1))
    $script:memory.WriteU64(0, (At $Page ($Slot * 16 + 8)), [uint64]$Access)
}
# A process's handle table: -Pages leaf pages (level 0 for one, else level 1);
# returns the leaf pages. -MissingPage: a level-1 pointer to a page not in the dump.
function New-TestHandleTable([uint64]$Eprocess, [int]$Pages = 1, [switch]$MissingPage) {
    $table = New-TestAlloc 0x100
    $script:memory.WriteU64(0, (At $Eprocess 0x300), $table)
    $leaves = @(for ($i = 0; $i -lt $Pages; $i++) { $page = At $script:pages ($i * 0x1000); $script:memory.WriteU64(0, $page, 0); $page })
    $script:pages = At $script:pages ($Pages * 0x1000 + 0x1000)
    if ($Pages -eq 1 -and -not $MissingPage) { $script:memory.WriteU64(0, (At $table 8), $leaves[0]) }
    else {
        $top = $script:pages
        $script:pages = At $script:pages 0x1000
        for ($i = 0; $i -lt $Pages; $i++) { $script:memory.WriteU64(0, (At $top ($i * 8)), $leaves[$i]) }
        if ($MissingPage) { $script:memory.WriteU64(0, (At $top ($Pages * 8)), (K "FFFFE0000F000000")) }
        $script:memory.WriteU64(0, (At $table 8), ($top -bor 1))
    }
    return , $leaves
}
# A key control block: its name (compressed: one byte per character), its
# hive and its parent
function New-TestKcb([string]$Name, [uint64]$Hive, [uint64]$Parent, [switch]$Wide, [switch]$NoName) {
    $kcb = New-TestAlloc 0x138
    $script:memory.WriteU64(0, (At $kcb 0x20), $Hive)
    $script:memory.WriteU64(0, (At $kcb 0x48), $Parent)
    if ($NoName) { $script:memory.WriteU64(0, (At $kcb 0x50), (K "FFFFE0000E000000")); return $kcb }
    $block = New-TestAlloc (0x20 + $Name.Length * 2)
    $script:memory.WriteU64(0, (At $kcb 0x50), $block)
    if ($Wide) {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Name)
        $script:memory.WriteU32(0, $block, 0)
    }
    else {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Name)
        $script:memory.WriteU32(0, $block, 1)
    }
    $script:memory.WriteU16(0, (At $block 0x18), [uint16]$bytes.Length)
    $script:memory.Write(0, (At $block 0x1a), $bytes)
    return $kcb
}
# A key object (_CM_KEY_BODY) of a key control block
function New-TestKey([uint64]$Kcb) {
    $key = New-TestObject -Type "Key"
    $script:memory.WriteU64(0, (At $key 8), $Kcb)
    return $key
}
# A file object: its name, its volume's device and the file it is relative to
function New-TestFile([string]$Name, [uint64]$Device, [uint64]$Related = 0) {
    $file = New-TestObject -Type "File"
    $script:memory.WriteU64(0, (At $file 8), $Device)
    $script:memory.WriteU64(0, (At $file 0x40), $Related)
    if ($Name) { Write-TestString (At $file 0x58) $Name }
    return $file
}
# A thread object (_ETHREAD): its process and thread ID
function New-TestThread([uint64]$Process, [long]$ProcessId, [long]$ThreadId) {
    $thread = New-TestObject -Type "Thread"
    $script:memory.WriteU64(0, (At $thread 0x240), $Process)
    $script:memory.WriteU64(0, (At $thread 0x4e8), [uint64]$ProcessId)
    $script:memory.WriteU64(0, (At $thread 0x4f0), [uint64]$ThreadId)
    return $thread
}
# An entry's fields as "Key=value|Key=value" (the protocol's order)
function Get-TestEntryText($Entry) {
    $fields = Get-TestEntryFields $Entry
    return (@($fields.Keys | Where-Object { $_ -ne "Kind" } | ForEach-Object { "$_=$($fields[$_])" }) -join "|")
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryKernelObjects"

    # --- The layouts of Windows 11 24H2 ARM64 ("dt -v nt!<type>") and the kernel's symbols ---
    $us = "struct _UNICODE_STRING, 3 elements, 0x10 bytes"
    $dt = @{
        "_OBJECT_HEADER"           = New-TestDtText -Type "_OBJECT_HEADER" -Size 0x38 -Fields @(@(0x18, "TypeIndex", "UChar"), @(0x1a, "InfoMask", "UChar"), @(0x30, "Body", "struct _QUAD, 2 elements, 0x8 bytes"))
        "_OBJECT_HEADER_NAME_INFO" = New-TestDtText -Type "_OBJECT_HEADER_NAME_INFO" -Size 0x20 -Fields @(@(0, "Directory", "Ptr64 to struct _OBJECT_DIRECTORY, 8 elements, 0x158 bytes"), @(8, "Name", $us))
        "_OBJECT_TYPE"             = New-TestDtText -Type "_OBJECT_TYPE" -Size 0xe0 -Fields @(@(0x10, "Name", $us), @(0x28, "Index", "UChar"))
        "_OBJECT_DIRECTORY"        = New-TestDtText -Type "_OBJECT_DIRECTORY" -Size 0x158 -Fields @(@(0, "HashBuckets", "[37] Ptr64 to struct _OBJECT_DIRECTORY_ENTRY, 3 elements, 0x18 bytes"))
        "_OBJECT_DIRECTORY_ENTRY"  = New-TestDtText -Type "_OBJECT_DIRECTORY_ENTRY" -Size 0x18 -Fields @(@(0, "ChainLink", "Ptr64 to struct _OBJECT_DIRECTORY_ENTRY, 3 elements, 0x18 bytes"), @(8, "Object", "Ptr64 to Void"))
        "_OBJECT_SYMBOLIC_LINK"    = New-TestDtText -Type "_OBJECT_SYMBOLIC_LINK" -Size 0x28 -Fields @(@(8, "LinkTarget", $us))
        "_KLDR_DATA_TABLE_ENTRY"   = New-TestDtText -Type "_KLDR_DATA_TABLE_ENTRY" -Size 0xa0 -Fields @(@(0, "InLoadOrderLinks", "struct _LIST_ENTRY, 2 elements, 0x10 bytes"), @(0x30, "DllBase", "Ptr64 to Void"),
            @(0x40, "SizeOfImage", "Uint4B"), @(0x48, "FullDllName", $us), @(0x58, "BaseDllName", $us))
        "_DRIVER_OBJECT"           = New-TestDtText -Type "_DRIVER_OBJECT" -Size 0x150 -Fields @(@(0x18, "DriverStart", "Ptr64 to Void"), @(0x20, "DriverSize", "Uint4B"), @(0x28, "DriverSection", "Ptr64 to Void"), @(0x38, "DriverName", $us))
        "_EPROCESS"                = New-TestDtText -Type "_EPROCESS" -Size 0x400 -Fields @(@(0x1d0, "UniqueProcessId", "Ptr64 to Void"), @(0x1e8, "CreateTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"),
            @(0x2e0, "InheritedFromUniqueProcessId", "Ptr64 to Void"), @(0x300, "ObjectTable", "Ptr64 to struct _HANDLE_TABLE, 17 elements, 0x100 bytes"))
        "_HANDLE_TABLE"            = New-TestDtText -Type "_HANDLE_TABLE" -Size 0x100 -Fields @(@(8, "TableCode", "Uint8B"))
        "_HANDLE_TABLE_ENTRY"      = New-TestDtText -Type "_HANDLE_TABLE_ENTRY" -Size 0x10 -Kind "union" -Fields @(@(0, "ObjectPointerBits", "Bitfield Pos 20, 44 Bits"), @(8, "GrantedAccessBits", "Bitfield Pos 0, 25 Bits"))
        "_KTHREAD"                 = New-TestDtText -Type "_KTHREAD" -Size 0x4a0 -Fields @(@(0x240, "Process", "Ptr64 to struct _KPROCESS, 63 elements, 0x1b8 bytes"))
        "_ETHREAD"                 = New-TestDtText -Type "_ETHREAD" -Size 0x778 -Fields @(@(0x4e8, "Cid", "struct _CLIENT_ID, 2 elements, 0x10 bytes"))
        "_CLIENT_ID"               = New-TestDtText -Type "_CLIENT_ID" -Size 0x10 -Fields @(@(0, "UniqueProcess", "Ptr64 to Void"), @(8, "UniqueThread", "Ptr64 to Void"))
        "_FILE_OBJECT"             = New-TestDtText -Type "_FILE_OBJECT" -Size 0xd8 -Fields @(@(8, "DeviceObject", "Ptr64 to struct _DEVICE_OBJECT, 25 elements, 0x150 bytes"),
            @(0x40, "RelatedFileObject", "Ptr64 to struct _FILE_OBJECT, 30 elements, 0xd8 bytes"), @(0x58, "FileName", $us))
        "_CM_KEY_BODY"             = New-TestDtText -Type "_CM_KEY_BODY" -Size 0x70 -Fields @(@(8, "KeyControlBlock", "Ptr64 to struct _CM_KEY_CONTROL_BLOCK, 56 elements, 0x138 bytes"))
        "_CM_KEY_CONTROL_BLOCK"    = New-TestDtText -Type "_CM_KEY_CONTROL_BLOCK" -Size 0x138 -Fields @(@(0x20, "KeyHive", "Ptr64 to struct _HHIVE, 50 elements, 0x608 bytes"),
            @(0x48, "ParentKcb", "Ptr64 to struct _CM_KEY_CONTROL_BLOCK, 56 elements, 0x138 bytes"), @(0x50, "NameBlock", "Ptr64 to struct _CM_NAME_CONTROL_BLOCK, 7 elements, 0x20 bytes"))
        "_CM_NAME_CONTROL_BLOCK"   = New-TestDtText -Type "_CM_NAME_CONTROL_BLOCK" -Size 0x20 -Fields @(@(0, "Compressed", "Bitfield Pos 0, 1 Bit"), @(0x18, "NameLength", "Uint2B"), @(0x1a, "Name", "[1] Wchar"))
        "_TOKEN"                   = New-TestDtText -Type "_TOKEN" -Size 0x5c8 -Fields @(@(0x98, "UserAndGroups", "Ptr64 to struct _SID_AND_ATTRIBUTES, 2 elements, 0x10 bytes"))
        "_SID_AND_ATTRIBUTES"      = New-TestDtText -Type "_SID_AND_ATTRIBUTES" -Size 0x10 -Fields @(@(0, "Sid", "Ptr64 to Void"))
    }
    $symbols = @{
        "nt!ObHeaderCookie" = (K "FFFFF80000001000"); "nt!ObTypeIndexTable" = (K "FFFFF80000002000"); "nt!ObpInfoMaskToOffset" = (K "FFFFF80000003000")
        "nt!ObpRootDirectoryObject" = (K "FFFFF80000004000"); "nt!PsLoadedModuleList" = (K "FFFFF80000005000"); "nt!MmUnloadedDrivers" = (K "FFFFF80000006000")
        "nt!MmLastUnloadedDriver" = (K "FFFFF80000006008"); "nt!KeBootTime" = (K "FFFFF80000007000")
    }
    Set-TestEngineCommands -Dt $dt -Symbols $symbols

    $script:memory = New-TestMemory
    $script:heap = K "FFFFB00000010000"
    $script:nextBody = K "FFFFC00000000100"
    $script:pages = K "FFFFD00000000000"
    $script:typeTable = $symbols["nt!ObTypeIndexTable"]
    $script:typeIndex = @{}
    $script:cookie = 0x5A
    $memory.WriteU8(0, $symbols["nt!ObHeaderCookie"], [byte]$script:cookie)
    $memory.Write(0, $symbols["nt!ObpInfoMaskToOffset"], [byte[]]@(0, 0x20, 0x20, 0x40))
    $typeNumber = 3
    foreach ($typeName in @("Directory", "SymbolicLink", "Device", "Driver", "Process", "Thread", "File", "Key", "Mutant", "Event")) { Add-TestType -Name $typeName -Index ($typeNumber++) }

    # The namespace: \Driver, \FileSystem, \GLOBAL?? (C: and D: -> the
    # volume), \Device (the volume, BootDevice -> the volume), \SystemRoot
    # (-> \Device\BootDevice\Windows), \BaseNamedObjects
    $root = New-TestObject -Type "Directory"
    $memory.WriteU64(0, $symbols["nt!ObpRootDirectoryObject"], $root)
    $driverDir = New-TestObject -Type "Directory" -Name "Driver" -Directory $root
    $fileSystemDir = New-TestObject -Type "Directory" -Name "FileSystem" -Directory $root
    $globalDir = New-TestObject -Type "Directory" -Name "GLOBAL??" -Directory $root
    $deviceDir = New-TestObject -Type "Directory" -Name "Device" -Directory $root
    $namedDir = New-TestObject -Type "Directory" -Name "BaseNamedObjects" -Directory $root
    $systemRoot = New-TestLink -Name "SystemRoot" -Directory $root -Target "\Device\BootDevice\Windows"
    Set-TestDirectory -Directory $root -Entries @($driverDir, $fileSystemDir, $globalDir, $deviceDir, $namedDir, $systemRoot)
    $volume = New-TestObject -Type "Device" -Name "HarddiskVolume3" -Directory $deviceDir
    Set-TestDirectory -Directory $deviceDir -Entries @($volume, (New-TestLink -Name "BootDevice" -Directory $deviceDir -Target "\Device\HarddiskVolume3"))
    Set-TestDirectory -Directory $globalDir -Entries @((New-TestLink -Name "D:" -Directory $globalDir -Target "\Device\HarddiskVolume3"), (New-TestLink -Name "C:" -Directory $globalDir -Target "\Device\HarddiskVolume3\"),
        (New-TestLink -Name "PhysicalDrive0" -Directory $globalDir -Target "\Device\Harddisk0\DR0"))
    $mutex = New-TestObject -Type "Mutant" -Name "fixture-mutex" -Directory $namedDir
    Set-TestDirectory -Directory $namedDir -Entries @($mutex)

    # --- 1. Kernel objects ---
    $context = New-TestContext -Memory $memory
    $objects = Get-DbgEngKernelObjects -Context $context
    Assert-KitEqual -Name "objects: the layout and symbols are complete, the cookie and tables read" -Expected "||True" -Actual "$($objects.MissingFields)|$($objects.Problem)|$($null -ne $context.Shared['KernelObjects'])"
    $listing = @($objects.List($root) | ForEach-Object { "$($_.Name):$($_.TypeName)" }) -join ","
    Assert-KitEqual -Name "objects: the root directory's names and types (type index decoded with the cookie and the header's address)" -Expected "Driver:Directory,FileSystem:Directory,GLOBAL??:Directory,Device:Directory,BaseNamedObjects:Directory,SystemRoot:SymbolicLink" -Actual $listing
    Assert-KitEqual -Name "objects: full names through the name headers' directories" -Expected "\Device\HarddiskVolume3|\BaseNamedObjects\fixture-mutex" -Actual "$($objects.FullName($volume))|$($objects.FullName($mutex))"
    Assert-KitEqual -Name "objects: symbolic links resolved through the namespace" -Expected "\Device\HarddiskVolume3\Windows\x.sys|\Device\HarddiskVolume3\y.sys|\Device\Nothere\z" -Actual "$($objects.Resolve('\SystemRoot\x.sys'))|$($objects.Resolve('\??\C:\y.sys'))|$($objects.Resolve('\Device\Nothere\z'))"
    Assert-KitEqual -Name "objects: drive letters (the first of two letters), NT paths as drive-letter paths" -Expected "C:|C:\Windows\system32\drivers\a.sys|D:\x.sys|C:\Windows\b.sys|\\server\share\c.sys|\Device\Harddisk0\DR0\d|relative.sys" `
        -Actual "$($objects.DriveLetters()['\Device\HarddiskVolume3'])|$($objects.ToDrivePath('\SystemRoot\system32\drivers\a.sys'))|$($objects.ToDrivePath('\??\D:\x.sys'))|$($objects.ToDrivePath('\Device\HarddiskVolume3\Windows\b.sys'))|$($objects.ToDrivePath('\??\UNC\server\share\c.sys'))|$($objects.ToDrivePath('\Device\Harddisk0\DR0\d'))|$($objects.ToDrivePath('relative.sys'))"
    $badType = New-TestBody
    Set-TestObject -Body $badType -Type "" -RawIndex 0x77
    Assert-KitEqual -Name "objects: a type index with no type behind it is unknown" -Expected "|Mutant" -Actual "$($objects.TypeOfObject($badType))|$($objects.TypeOfObject($mutex))"

    # --- 2. Drivers ---
    # The module list (forwards: fixture-a, fixture-b, ntoskrnl), a hidden
    # module (its driver object only), an entry that moved (inside
    # fixture-a's range), a driver object without a module entry
    $head = $symbols["nt!PsLoadedModuleList"]
    $entryA = New-TestModule -Base (K "FFFFF80011000000") -Size 0x10000 -FullName "\SystemRoot\system32\drivers\fixture-a.sys" -Name "fixture-a.sys"
    $entryB = New-TestModule -Base (K "FFFFF80011100000") -Size 0x8000 -FullName "\??\C:\Windows\System32\drivers\fixture-b.sys" -Name "fixture-b.sys"
    $entryK = New-TestModule -Base (K "FFFFF80010000000") -Size 0x800000 -FullName "\SystemRoot\system32\ntoskrnl.exe" -Name "ntoskrnl.exe"
    $entryH = New-TestModule -Base (K "FFFFF80012000000") -Size 0x6000 -FullName "\SystemRoot\System32\drivers\fixture-hidden.sys" -Name "fixture-hidden.sys"
    $entryS = New-TestModule -Base (K "FFFFF80011004000") -Size 0x1000 -FullName "\SystemRoot\System32\drivers\fixture-moved.sys" -Name "fixture-moved.sys"
    Set-TestLinks -Entry $head -Forward $entryA -Back $entryK
    Set-TestLinks -Entry $entryA -Forward $entryB -Back $head
    Set-TestLinks -Entry $entryB -Forward $entryK -Back $entryA
    Set-TestLinks -Entry $entryK -Forward $head -Back $entryB
    Set-TestLinks -Entry $entryH -Forward $entryH -Back $entryH
    $drivers = @(
        (New-TestDriver -Name "fixture-a" -Directory $driverDir -DriverName "\Driver\fixture-a" -Section $entryA -Start (K "FFFFF80011000000") -Size 0x10000),
        (New-TestDriver -Name "fixture-hidden" -Directory $driverDir -DriverName "\Driver\fixture-hidden" -Section $entryH -Start (K "FFFFF80012000000") -Size 0x6000),
        (New-TestDriver -Name "fixture-nosection" -Directory $driverDir -DriverName "\Driver\fixture-nosection" -Section 0 -Start 0 -Size 0),
        (New-TestDriver -Name "fixture-moved" -Directory $driverDir -DriverName "" -Section $entryS -Start (K "FFFFF80011004000") -Size 0x1000),
        (New-TestObject -Type "Device" -Name "fixture-device" -Directory $driverDir)
    )
    Set-TestDirectory -Directory $driverDir -Entries $drivers
    Set-TestDirectory -Directory $fileSystemDir -Entries @((New-TestDriver -Name "fixture-fs" -Directory $fileSystemDir -DriverName "\FileSystem\fixture-fs" -Section $entryB -Start (K "FFFFF80011100000") -Size 0x8000))
    # The unloaded drivers: slot 0 a time since boot (5 s), slot 1 a
    # system time (older Windows), slot 2 an end before its start; the
    # next slot to write is 3
    $boot = [datetime]::new(2026, 3, 2, 6, 0, 0, [DateTimeKind]::Utc)
    $memory.WriteU64(0, $symbols["nt!KeBootTime"], [uint64]$boot.ToFileTimeUtc())
    $unloaded = New-TestAlloc (50 * 0x28)
    $memory.WriteU64(0, $symbols["nt!MmUnloadedDrivers"], $unloaded)
    $memory.WriteU32(0, $symbols["nt!MmLastUnloadedDriver"], 3)
    $slots = @(
        @("fixture-early.sys", (K "FFFFF80013000000"), (K "FFFFF80013004000"), [long]50000000),
        @("fixture-older.sys", (K "FFFFF80013100000"), (K "FFFFF80013108000"), [datetime]::new(2026, 3, 2, 7, 0, 0, [DateTimeKind]::Utc).ToFileTimeUtc()),
        @("fixture-bad.sys", (K "FFFFF80013200000"), (K "FFFFF80013100000"), [long]60000000)
    )
    for ($i = 0; $i -lt $slots.Count; $i++) {
        $slot = At $unloaded ($i * 0x28)
        Write-TestString $slot $slots[$i][0]
        $memory.WriteU64(0, (At $slot 0x10), $slots[$i][1])
        $memory.WriteU64(0, (At $slot 0x18), $slots[$i][2])
        $memory.WriteU64(0, (At $slot 0x20), [uint64]$slots[$i][3])
    }
    $capture = [datetime]::new(2026, 3, 2, 12, 0, 0, [DateTimeKind]::Utc)
    $context = New-TestContext -Memory $memory -CaptureFileTime $capture.ToFileTimeUtc()
    $driversArea = Invoke-TestArea -Name "Drivers" -Context $context
    $driverTexts = @($driversArea.Entries | ForEach-Object { Get-TestEntryText $_ })
    $expectedDrivers = @(
        "State=Loaded|Name=fixture-a.sys|Path=C:\Windows\system32\drivers\fixture-a.sys|Base=0xfffff80011000000|Size=0x10000|FoundBy=ModuleList,DriverObject|DriverObject=\Driver\fixture-a",
        "State=Loaded|Name=fixture-b.sys|Path=C:\Windows\System32\drivers\fixture-b.sys|Base=0xfffff80011100000|Size=0x8000|FoundBy=ModuleList,DriverObject|DriverObject=\FileSystem\fixture-fs",
        "State=Loaded|Name=ntoskrnl.exe|Path=C:\Windows\system32\ntoskrnl.exe|Base=0xfffff80010000000|Size=0x800000|FoundBy=ModuleList",
        "State=Loaded|Name=fixture-hidden.sys|Path=C:\Windows\System32\drivers\fixture-hidden.sys|Base=0xfffff80012000000|Size=0x6000|FoundBy=DriverObject|DriverObject=\Driver\fixture-hidden|Anomaly=NotInModuleList",
        "State=Unloaded|Name=fixture-early.sys|Base=0xfffff80013000000|Size=0x4000|Time=2026-03-02T06:00:05.0000000+00:00|FoundBy=UnloadedDriverList",
        "State=Unloaded|Name=fixture-older.sys|Base=0xfffff80013100000|Size=0x8000|Time=2026-03-02T07:00:00.0000000+00:00|FoundBy=UnloadedDriverList"
    )
    Assert-KitEqual -Name "drivers: the listed modules (paths with drive letters, their driver objects), the hidden one, the unloaded ones oldest first (a time since boot added to nt!KeBootTime)" -Expected ($expectedDrivers -join "`n") -Actual ($driverTexts -join "`n")
    Assert-KitEqual -Name "drivers: read, the counts for the log and the note of a bad unloaded slot" `
        -Expected "Read|kernel modules 3, driver objects 5, driver objects without a module entry 1, hidden from the module list 1, driver objects whose module entry moved 1, unloaded drivers 2|1 slot(s) of the list of recently unloaded drivers were not readable" `
        -Actual "$($driversArea.State)|$($driversArea.Coverage.CountsText)|$($driversArea.Note)"
    # The backward walk alone reaches the head: hidden drivers are still judged
    Set-TestLinks -Entry $entryA -Forward (K "FFFFE00000100000") -Back $head
    $context = New-TestContext -Memory $memory -CaptureFileTime $capture.ToFileTimeUtc()
    $oneWay = Invoke-TestArea -Name "Drivers" -Context $context
    $scan = $context.Shared["DriverScan"]
    Assert-KitEqual -Name "drivers: forwards cut, backwards complete -- every module found, the hidden one judged, the list noted as inconsistent" `
        -Expected "False|True|3|1|Read|the kernel's module list was inconsistent in places, as when memory is copied while Windows runs" `
        -Actual "$($scan.ForwardWalk.Complete)|$($scan.BackwardWalk.Complete)|$(@($oneWay.Entries | Where-Object { $_.Get('FoundBy').StartsWith('ModuleList') }).Count)|$(@($oneWay.Entries | Where-Object { $_.Get('Anomaly') }).Count)|$($oneWay.State)|$(($oneWay.Coverage.Notes | Select-Object -First 1))"
    # Neither walk ends: nothing is judged hidden
    Set-TestLinks -Entry $head -Forward (K "FFFFE00000100000") -Back (K "FFFFE00000200000")
    $context = New-TestContext -Memory $memory -CaptureFileTime $capture.ToFileTimeUtc()
    $noWalk = Invoke-TestArea -Name "Drivers" -Context $context
    Assert-KitEqual -Name "drivers: both walks cut -- partly read, the driver objects' modules listed without Anomaly" `
        -Expected "Partial|4|0|4|the kernel's module list could not be walked to its end either way (forwards it stopped at an entry that is not in the dump), so drivers hidden from it were not judged" `
        -Actual "$($noWalk.State)|$(@($noWalk.Entries | Where-Object { $_.Get('State') -eq 'Loaded' }).Count)|$(@($noWalk.Entries | Where-Object { $_.Get('Anomaly') }).Count)|$($context.Shared['DriverScan'].NotJudged)|$(($noWalk.Coverage.Notes | Select-Object -First 1))"
    Set-TestLinks -Entry $head -Forward $entryA -Back $entryK
    Set-TestLinks -Entry $entryA -Forward $entryB -Back $head
    # An unloaded-driver list whose slots all fail their checks: not used
    for ($i = 0; $i -lt 2; $i++) { $memory.WriteU64(0, (At $unloaded ($i * 0x28 + 0x18)), 0) }
    $context = New-TestContext -Memory $memory -CaptureFileTime $capture.ToFileTimeUtc()
    $badList = Invoke-TestArea -Name "Drivers" -Context $context
    Assert-KitEqual -Name "drivers: an unloaded-driver list whose layout does not fit is not used (a note says so)" `
        -Expected "0|True" -Actual "$(@($badList.Entries | Where-Object { $_.Get('State') -eq 'Unloaded' }).Count)|$(@($badList.Coverage.Notes) -contains 'the list of recently unloaded drivers does not have the layout the builder reads, so it was not used')"
    for ($i = 0; $i -lt 2; $i++) { $memory.WriteU64(0, (At $unloaded ($i * 0x28 + 0x18)), $slots[$i][2]) }
    # The hidden driver's range in an unload record (slot 3, the oldest):
    # unloaded 30 s before the capture started (within the churn margin), it
    # is a driver unloaded while memory was copied, not marked; unloaded an
    # hour before, it is still marked
    $hiddenSlot = At $unloaded (3 * 0x28)
    Write-TestString $hiddenSlot "fixture-hidden.sys"
    $memory.WriteU64(0, (At $hiddenSlot 0x10), (K "FFFFF80012000000"))
    $memory.WriteU64(0, (At $hiddenSlot 0x18), (K "FFFFF80012006000"))
    $unloadVerdicts = @()
    foreach ($before in @(30, 3600)) {
        $memory.WriteU64(0, (At $hiddenSlot 0x20), [uint64]$capture.AddSeconds(-$before).ToFileTimeUtc())
        $context = New-TestContext -Memory $memory -CaptureFileTime $capture.ToFileTimeUtc()
        $unloadArea = Invoke-TestArea -Name "Drivers" -Context $context
        $unloadVerdicts += "$(@($unloadArea.Entries | Where-Object { $_.Get('Anomaly') }).Count)/$($unloadArea.Coverage.Get('driver objects of drivers unloaded during the capture'))/$(@($unloadArea.Entries | Where-Object { $_.Get('State') -eq 'Unloaded' }).Count)"
        if ($before -eq 30) { $unloadNote = @($unloadArea.Coverage.Notes | Where-Object { $_ -like "*unloaded while memory was copied*" }) -join "" }
    }
    Assert-KitEqual -Name "drivers: a driver object outside the list whose driver was unloaded during the capture (an unload record covers it) is not marked hidden, and noted; one unloaded an hour before is" `
        -Expected "0/1/3|1/0/3|1 driver object(s) outside the kernel's module list belong to drivers unloaded while memory was copied, as their unload records show, and are not marked hidden" -Actual "$($unloadVerdicts -join '|')|$unloadNote"
    $memory.Write(0, $hiddenSlot, (New-Object byte[] 0x28))

    # --- 3. Handles ---
    # The processes: A (a user's, PID 1000) and its child C and grandchild G;
    # B and T unrelated to A; a SYSTEM process; the System process (PID 4); a
    # console (its first process, the console host, a client); two processes
    # of one application and a third program of the same parent; one that
    # exited (no handle table); and a process object outside the scan
    $t0 = [datetime]::new(2026, 3, 2, 8, 0, 0, [DateTimeKind]::Utc)
    $user1 = "S-1-5-21-1-2-3-1001"
    $specs = [ordered]@{
        A = @{ Pid = 1000; Ppid = 800; Name = "fixture-a.exe"; Sid = $user1; Minutes = 0 }
        B = @{ Pid = 2000; Ppid = 900; Name = "fixture-b.exe"; Sid = ""; Minutes = 1 }
        C = @{ Pid = 1100; Ppid = 1000; Name = "fixture-c.exe"; Sid = $user1; Minutes = 2 }
        G = @{ Pid = 1104; Ppid = 1100; Name = "fixture-g.exe"; Sid = $user1; Minutes = 3 }
        T = @{ Pid = 2100; Ppid = 900; Name = "fixture-t.exe"; Sid = $user1; Minutes = 4 }
        S = @{ Pid = 600; Ppid = 500; Name = "fixture-sys.exe"; Sid = "S-1-5-18"; Minutes = -60 }
        Four = @{ Pid = 4; Ppid = 0; Name = "System"; Sid = "S-1-5-18"; Minutes = -61 }
        Cmd = @{ Pid = 3000; Ppid = 800; Name = "fixture-cmd.exe"; Sid = $user1; Minutes = 5 }
        Con = @{ Pid = 3004; Ppid = 3000; Name = "conhost.exe"; Sid = $user1; Minutes = 6 }
        Shell = @{ Pid = 3008; Ppid = 3000; Name = "fixture-shell.exe"; Sid = $user1; Minutes = 7 }
        Tool = @{ Pid = 3012; Ppid = 3008; Name = "fixture-tool.exe"; Sid = $user1; Minutes = 8 }
        App1 = @{ Pid = 4000; Ppid = 3900; Name = "fixture-app.exe"; Sid = $user1; Minutes = 9 }
        App2 = @{ Pid = 4004; Ppid = 3900; Name = "fixture-app.exe"; Sid = $user1; Minutes = 10 }
        Other = @{ Pid = 4008; Ppid = 3900; Name = "fixture-other.exe"; Sid = $user1; Minutes = 11 }
        Gone = @{ Pid = 5000; Ppid = 800; Name = "fixture-exited.exe"; Sid = $user1; Minutes = 12 }
    }
    $eprocess = @{}
    $processSpecs = New-Object System.Collections.Generic.List[object]
    foreach ($key in $specs.Keys) {
        $spec = $specs[$key]
        $body = New-TestObject -Type "Process"
        $eprocess[$key] = $body
        $processSpecs.Add(@{ Eprocess = $body; Pid = [long]$spec.Pid; Ppid = [long]$spec.Ppid; ShortName = $spec.Name; UserSid = $spec.Sid; CreateTime = $t0.AddMinutes($spec.Minutes) })
    }
    # B's user comes from its token (the ProcessDetails area did not set it)
    $token = New-TestAlloc 0x5c8
    $groups = New-TestAlloc 0x20
    $sid = New-TestAlloc 0x20
    $memory.WriteU64(0, (At $token 0x98), $groups)
    $memory.WriteU64(0, $groups, $sid)
    $memory.Write(0, $sid, [byte[]]@(1, 5, 0, 0, 0, 0, 0, 5))
    $memory.Write(0, (At $sid 8), [byte[]](@(21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0) + [BitConverter]::GetBytes([uint32]1002)))
    $processSpecs[1]["Token"] = $token
    # A process object the scan does not have (its EPROCESS: type 3, PID, parent, name)
    $outside = New-TestObject -Type "Process"
    $memory.WriteU8(0, $outside, 3)
    $memory.WriteU64(0, (At $outside 0x1d0), 6000)
    $memory.WriteU64(0, (At $outside 0x2e0), 5900)
    $memory.Write(0, (At $outside 0x338), [System.Text.Encoding]::ASCII.GetBytes("fixture-gone"))
    $processLayout = New-TestLayout -Offsets @{ "_EPROCESS.UniqueProcessId" = 0x1d0; "_EPROCESS.InheritedFromUniqueProcessId" = 0x2e0; "_EPROCESS.CreateTime" = 0x1e8; "_EPROCESS.ImageFileName" = 0x338 } -Sizes @{ "_EPROCESS" = 0x400 }

    # Objects of the handles: threads, files, keys, mutexes, an event
    $threadB = New-TestThread -Process $eprocess["B"] -ProcessId 2000 -ThreadId 2004
    $threadT = New-TestThread -Process $eprocess["T"] -ProcessId 2100 -ThreadId 2104
    $public = New-TestFile -Name "\Users\Public\fixture.txt" -Device $volume
    $system = New-TestFile -Name "\Windows\System32\fixture.dll" -Device $volume
    $unnamed = New-TestFile -Name "" -Device $volume
    $downloads = New-TestFile -Name "\Users\alice\Downloads" -Device $volume
    $relative = New-TestFile -Name "fixture-rel.zip" -Device $volume -Related $downloads
    $master = K "FFFFE00001000000"
    $softwareHive = K "FFFFE00002000000"
    $systemHive = K "FFFFE00003000000"
    $kRegistry = New-TestKcb -Name "REGISTRY" -Hive $master -Parent 0
    $kMachine = New-TestKcb -Name "MACHINE" -Hive $master -Parent $kRegistry
    $kSoftLink = New-TestKcb -Name "SOFTWARE" -Hive $master -Parent $kMachine
    $kSoftRoot = New-TestKcb -Name "SOFTWARE" -Hive $softwareHive -Parent $kSoftLink
    $kMicrosoft = New-TestKcb -Name "Microsoft" -Hive $softwareHive -Parent $kSoftRoot
    $kWindows = New-TestKcb -Name "Windows" -Hive $softwareHive -Parent $kMicrosoft
    $kVersion = New-TestKcb -Name "CurrentVersion" -Hive $softwareHive -Parent $kWindows -Wide
    $kRun = New-TestKcb -Name "Run" -Hive $softwareHive -Parent $kVersion
    $kNt = New-TestKcb -Name "Windows NT" -Hive $softwareHive -Parent $kMicrosoft
    $kNtVersion = New-TestKcb -Name "CurrentVersion" -Hive $softwareHive -Parent $kNt
    $kIfeo = New-TestKcb -Name "Image File Execution Options" -Hive $softwareHive -Parent $kNtVersion
    $kIfeoExe = New-TestKcb -Name "fixture.exe" -Hive $softwareHive -Parent $kIfeo
    $kSysLink = New-TestKcb -Name "SYSTEM" -Hive $master -Parent $kMachine
    $kSysRoot = New-TestKcb -Name "SYSTEM" -Hive $systemHive -Parent $kSysLink
    $kSet = New-TestKcb -Name "ControlSet001" -Hive $systemHive -Parent $kSysRoot
    $kServices = New-TestKcb -Name "Services" -Hive $systemHive -Parent $kSet
    $kService = New-TestKcb -Name "fixture-svc" -Hive $systemHive -Parent $kServices
    $kParameters = New-TestKcb -Name "Parameters" -Hive $systemHive -Parent $kService
    $kBroken = New-TestKcb -Name "" -Hive $systemHive -Parent $kService -NoName
    $unnamedMutex = New-TestObject -Type "Mutant"
    $eventObject = New-TestObject -Type "Event"
    $undecoded = New-TestBody
    Set-TestObject -Body $undecoded -Type "" -RawIndex 0x77
    $notInDump = K "FFFFE0000D000100"

    # A's table: two pages (level 1); B, S, the System process, the console
    # host: one page; App1: one page and a pointer to a page not in the dump
    $pagesA = New-TestHandleTable -Eprocess $eprocess["A"] -Pages 2
    $all = [uint32]0x1fffff
    $aHandles = @(
        @(1, $eprocess["B"], $all), @(2, $eprocess["C"], $all), @(3, $eprocess["T"], [uint32]0x1000), @(4, $threadB, $all), @(5, $threadT, [uint32]0x10),
        @(6, $eprocess["G"], $all), @(7, $outside, [uint32]0x2), @(8, $public, [uint32]0x12019f), @(9, $public, [uint32]0x12019f), @(10, $system, [uint32]0x120089),
        @(11, $unnamed, [uint32]0x100080), @(12, $relative, [uint32]0x12019f), @(13, (New-TestKey $kRun), [uint32]0x20019), @(14, (New-TestKey $kIfeo), [uint32]0x20019),
        @(15, (New-TestKey $kIfeoExe), [uint32]0x20019), @(16, (New-TestKey $kService), [uint32]0x20019), @(17, (New-TestKey $kParameters), [uint32]0x20019),
        @(18, (New-TestKey $kBroken), [uint32]0x20019), @(19, $mutex, [uint32]0x1f0001), @(20, $unnamedMutex, [uint32]0x1f0001), @(21, $undecoded, [uint32]0x1f0003),
        @(22, $notInDump, [uint32]0x1f0003)
    )
    foreach ($h in $aHandles) { Set-TestHandle -Page $pagesA[0] -Slot $h[0] -Body $h[1] -Access $h[2] }
    Set-TestHandle -Page $pagesA[1] -Slot 1 -Body $eventObject -Access ([uint32]0x1f0003)
    $pagesB = New-TestHandleTable -Eprocess $eprocess["B"]
    Set-TestHandle -Page $pagesB[0] -Slot 1 -Body $eprocess["A"] -Access $all
    $pagesS = New-TestHandleTable -Eprocess $eprocess["S"]
    Set-TestHandle -Page $pagesS[0] -Slot 1 -Body $eprocess["B"] -Access ([uint32]0x28)
    $pagesFour = New-TestHandleTable -Eprocess $eprocess["Four"]
    Set-TestHandle -Page $pagesFour[0] -Slot 1 -Body $eprocess["B"] -Access $all
    $pagesCon = New-TestHandleTable -Eprocess $eprocess["Con"]
    Set-TestHandle -Page $pagesCon[0] -Slot 1 -Body $eprocess["Shell"] -Access $all
    Set-TestHandle -Page $pagesCon[0] -Slot 2 -Body $eprocess["Cmd"] -Access $all
    Set-TestHandle -Page $pagesCon[0] -Slot 3 -Body $eprocess["Tool"] -Access $all
    $pagesApp = New-TestHandleTable -Eprocess $eprocess["App1"] -MissingPage
    Set-TestHandle -Page $pagesApp[0] -Slot 1 -Body $eprocess["App2"] -Access $all
    Set-TestHandle -Page $pagesApp[0] -Slot 2 -Body $eprocess["Other"] -Access ([uint32]0x2)
    foreach ($key in @("C", "G", "T", "Cmd", "Shell", "Tool", "App2", "Other")) { [void](New-TestHandleTable -Eprocess $eprocess[$key]) }
    $memory.WriteU64(0, (At $eprocess["Gone"] 0x300), 0)

    $context = New-TestContext -Memory $memory -Processes $processSpecs.ToArray() -ProcessLayout $processLayout -CaptureFileTime $capture.ToFileTimeUtc()
    $handlesArea = Invoke-TestArea -Name "Handles" -Context $context
    $handleTexts = @($handlesArea.Entries | ForEach-Object { Get-TestEntryText $_ })
    $created = { param($key) $t0.AddMinutes($specs[$key].Minutes).ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture) }
    $aPrefix = "Pid=1000|ProcessCreated=$(& $created 'A')|Process=fixture-a.exe|User=$user1"
    $expectedHandles = @(
        "$aPrefix|Type=Process|Handle=0x4|Access=0x1fffff|Target=fixture-b.exe|TargetPid=2000|TargetProcess=fixture-b.exe|TargetCreated=$(& $created 'B')|Anomaly=WriteAccessUnrelated",
        "$aPrefix|Type=Thread|Handle=0x14|Access=0x10|Target=fixture-t.exe|TargetPid=2100|TargetProcess=fixture-t.exe|TargetCreated=$(& $created 'T')|TargetTid=2104|Anomaly=WriteAccessUnrelated",
        "$aPrefix|Type=Process|Handle=0x18|Access=0x1fffff|Target=fixture-g.exe|TargetPid=1104|TargetProcess=fixture-g.exe|TargetCreated=$(& $created 'G')",
        "$aPrefix|Type=Process|Handle=0x1c|Access=0x2|Target=fixture-gone|TargetPid=6000|TargetProcess=fixture-gone|TargetCreated=|Anomaly=WriteAccessUnrelated",
        "$aPrefix|Type=File|Handle=0x20|Access=0x12019f|Target=C:\Users\Public\fixture.txt",
        "$aPrefix|Type=File|Handle=0x30|Access=0x12019f|Target=C:\Users\alice\Downloads\fixture-rel.zip",
        "$aPrefix|Type=Key|Handle=0x34|Access=0x20019|Target=\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "$aPrefix|Type=Key|Handle=0x3c|Access=0x20019|Target=\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fixture.exe",
        "$aPrefix|Type=Key|Handle=0x40|Access=0x20019|Target=\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\fixture-svc",
        "$aPrefix|Type=Mutant|Handle=0x4c|Access=0x1f0001|Target=\BaseNamedObjects\fixture-mutex",
        "Pid=2000|ProcessCreated=$(& $created 'B')|Process=fixture-b.exe|User=S-1-5-21-1-2-3-1002|Type=Process|Handle=0x4|Access=0x1fffff|Target=fixture-a.exe|TargetPid=1000|TargetProcess=fixture-a.exe|TargetCreated=$(& $created 'A')|Anomaly=WriteAccessUnrelated",
        "Pid=600|ProcessCreated=$(& $created 'S')|Process=fixture-sys.exe|User=S-1-5-18|Type=Process|Handle=0x4|Access=0x28|Target=fixture-b.exe|TargetPid=2000|TargetProcess=fixture-b.exe|TargetCreated=$(& $created 'B')",
        "Pid=3004|ProcessCreated=$(& $created 'Con')|Process=conhost.exe|User=$user1|Type=Process|Handle=0x4|Access=0x1fffff|Target=fixture-shell.exe|TargetPid=3008|TargetProcess=fixture-shell.exe|TargetCreated=$(& $created 'Shell')",
        "Pid=3004|ProcessCreated=$(& $created 'Con')|Process=conhost.exe|User=$user1|Type=Process|Handle=0xc|Access=0x1fffff|Target=fixture-tool.exe|TargetPid=3012|TargetProcess=fixture-tool.exe|TargetCreated=$(& $created 'Tool')",
        "Pid=4000|ProcessCreated=$(& $created 'App1')|Process=fixture-app.exe|User=$user1|Type=Process|Handle=0x4|Access=0x1fffff|Target=fixture-app.exe|TargetPid=4004|TargetProcess=fixture-app.exe|TargetCreated=$(& $created 'App2')",
        "Pid=4000|ProcessCreated=$(& $created 'App1')|Process=fixture-app.exe|User=$user1|Type=Process|Handle=0x8|Access=0x2|Target=fixture-other.exe|TargetPid=4008|TargetProcess=fixture-other.exe|TargetCreated=$(& $created 'Other')|Anomaly=WriteAccessUnrelated"
    )
    Assert-KitEqual -Name "handles: the entries (rights that change an unrelated process, files in user folders, persistence keys, named mutexes) and what is left out" -Expected ($expectedHandles -join "`n") -Actual ($handleTexts -join "`n")
    $scan = $context.Shared["HandleLookup"]
    Assert-KitEqual -Name "handles: counts for the log (handles, tables, folded thread rows, the anomaly and the process family, objects not read, an exited process)" `
        -Expected "29|14|1|5|4|1|1|1|1|1|1|1" `
        -Actual "$($handlesArea.Coverage.Get('handles'))|$($handlesArea.Coverage.Get('handle tables read'))|$($handlesArea.Coverage.Get('thread rows folded into process rows'))|$($handlesArea.Coverage.Get('rows of a user account changing an unrelated process'))|$($handlesArea.Coverage.Get(""rows of a user account in the target's process family""))|$($handlesArea.Coverage.Get('handles whose object could not be read') - 1)|$($handlesArea.Coverage.Get('file handles without a readable name'))|$($handlesArea.Coverage.Get('key handles whose path could not be built'))|$($handlesArea.Coverage.Get('exited processes without a handle table'))|$($handlesArea.Coverage.Get('type Event'))|$($handlesArea.Coverage.Get('type Thread') - 1)|$($handlesArea.Coverage.Get('thread rows'))"
    Assert-KitEqual -Name "handles: read, with the note of what a live copy left unreadable" `
        -Expected "Read|1 page(s) of handle entries were not in the dump, the objects of 2 handle(s) could not be read, 1 registry key handle(s) without a readable path were left out, as when memory is copied while Windows runs" `
        -Actual "$($handlesArea.State)|$($handlesArea.Note)"
    $first = $scan.Lookup($eprocess["A"], 4)
    $secondPage = $scan.Lookup($eprocess["A"], 0x404)
    Assert-KitEqual -Name "handles: the lookup for the joins (a handle of the first page, of the second page, none)" -Expected "Process|True|Event||True" `
        -Actual "$($first.Type)|$($first.Object -eq $eprocess['B'])|$($secondPage.Type)|$($scan.Lookup($eprocess['A'], 0x408))|$($context.Shared['HandleLookup'] -eq $scan)"
    Assert-KitEqual -Name "handles: a process object outside the scan without the fields to judge it (no exit time in the layout, no create time) is counted, not listed" -Expected "1|1|0|0" `
        -Actual "$($handlesArea.Coverage.Get('process objects reached only through a handle'))|$($handlesArea.Coverage.Get('of them not judged'))|$($handlesArea.Coverage.Get('of them hidden from the process scan'))|$(@($handlesArea.Entries | Where-Object { $_.Kind -eq 'HandleProcess' }).Count)"

    # Process objects that only handles reach, judged as the process scan
    # judges: hidden (no exit time, created an hour before the capture),
    # exited, created 30 s before the capture (churn), not a process ID
    # Windows gives; one holder with handles to each (no rights to change
    # them, so no Process rows), a second holder of the hidden one
    $judgedLayout = New-TestLayout -Offsets @{ "_EPROCESS.UniqueProcessId" = 0x1d0; "_EPROCESS.InheritedFromUniqueProcessId" = 0x2e0; "_EPROCESS.CreateTime" = 0x1e8; "_EPROCESS.ExitTime" = 0x1f0; "_EPROCESS.ImageFileName" = 0x338 } -Sizes @{ "_EPROCESS" = 0x400 }
    $outsiders = [ordered]@{
        Hidden = @{ Pid = 6100; Created = $capture.AddHours(-1); Exited = $null; Name = "fixture-hide" }
        Exited = @{ Pid = 6104; Created = $capture.AddHours(-1); Exited = $capture.AddMinutes(-5); Name = "fixture-ended" }
        Churn = @{ Pid = 6108; Created = $capture.AddSeconds(-30); Exited = $null; Name = "fixture-new" }
        Odd = @{ Pid = 6111; Created = $capture.AddHours(-1); Exited = $null; Name = "fixture-odd" }
    }
    $outsideBodies = @{}
    foreach ($key in $outsiders.Keys) {
        $o = $outsiders[$key]
        $body = New-TestObject -Type "Process"
        $memory.WriteU8(0, $body, 3)
        $memory.WriteU64(0, (At $body 0x1d0), [uint64]$o.Pid)
        $memory.WriteU64(0, (At $body 0x2e0), 5900)
        $memory.WriteU64(0, (At $body 0x1e8), [uint64]$o.Created.ToFileTimeUtc())
        if ($null -ne $o.Exited) { $memory.WriteU64(0, (At $body 0x1f0), [uint64]([datetime]$o.Exited).ToFileTimeUtc()) }
        $memory.Write(0, (At $body 0x338), [System.Text.Encoding]::ASCII.GetBytes($o.Name))
        $outsideBodies[$key] = $body
    }
    $holderOne = New-TestObject -Type "Process"
    $holderTwo = New-TestObject -Type "Process"
    $holderPages = New-TestHandleTable -Eprocess $holderOne
    $slot = 1
    foreach ($key in $outsiders.Keys) { Set-TestHandle -Page $holderPages[0] -Slot $slot -Body $outsideBodies[$key] -Access ([uint32]0x1000); $slot++ }
    Set-TestHandle -Page $holderPages[0] -Slot $slot -Body $outsideBodies["Hidden"] -Access ([uint32]0x1000)
    $holderTwoPages = New-TestHandleTable -Eprocess $holderTwo
    Set-TestHandle -Page $holderTwoPages[0] -Slot 1 -Body $outsideBodies["Hidden"] -Access ([uint32]0x1000)
    $holders = @(
        @{ Eprocess = $holderOne; Pid = [long]7000; Ppid = [long]800; ShortName = "fixture-holder.exe"; UserSid = "S-1-5-18"; CreateTime = $t0; FoundBy = "ListForward,ListBackward,ProcessIdTable" },
        @{ Eprocess = $holderTwo; Pid = [long]7004; Ppid = [long]800; ShortName = "fixture-holder2.exe"; UserSid = "S-1-5-18"; CreateTime = $t0; FoundBy = "ListForward,ListBackward,ProcessIdTable" }
    )
    $judgedContext = New-TestContext -Memory $memory -Processes $holders -ProcessLayout $judgedLayout -CaptureFileTime $capture.ToFileTimeUtc()
    $judgedArea = Invoke-TestArea -Name "Handles" -Context $judgedContext
    $hiddenFound = @($judgedArea.Entries | Where-Object { $_.Kind -eq "HandleProcess" } | ForEach-Object { Get-TestEntryText $_ })
    Assert-KitEqual -Name "handles: a process object only handles reach, without an exit time and created an hour before the capture, is a HandleProcess entry (its holders once each); the exited, churn and odd-ID ones only counted" `
        -Expected ("PID=6100|PPID=5900|ImageFileName=fixture-hide|Offset=0x$($outsideBodies['Hidden'].ToString('x'))|CreateTime=2026-03-02T11:00:00.0000000+00:00|FoundBy=HandleTable|Anomaly=NotInProcessList|HeldBy=7000,7004" +
            "|4|1|1|1|1|0") `
        -Actual ("$($hiddenFound -join '/')|$($judgedArea.Coverage.Get('process objects reached only through a handle'))|$($judgedArea.Coverage.Get('of them hidden from the process scan'))|$($judgedArea.Coverage.Get('of them exited'))|" +
            "$($judgedArea.Coverage.Get('of them created during the capture or within its churn margin'))|$($judgedArea.Coverage.Get('of them not process objects'))|$(@($judgedArea.Entries | Where-Object { $_.Kind -eq 'Handle' }).Count)")
    Assert-KitEqual -Name "handles: the note of a process reached only through a handle" -Expected "1" `
        -Actual "$(@($judgedArea.Coverage.Notes | Where-Object { $_ -like '1 process(es) without an exit time, created before the capture, were reached only through a handle*FoundBy=HandleTable' }).Count)"
    $noStart = Invoke-TestArea -Name "Handles" -Context (New-TestContext -Memory $memory -Processes $holders -ProcessLayout $judgedLayout)
    Assert-KitEqual -Name "handles: without the capture start nothing is judged hidden" -Expected "0|4" -Actual "$(@($noStart.Entries | Where-Object { $_.Kind -eq 'HandleProcess' }).Count)|$($noStart.Coverage.Get('process objects reached only through a handle'))"
    $noTable = @($holders | ForEach-Object { $copy = $_.Clone(); $copy["FoundBy"] = "ListForward,ListBackward"; $copy })
    $noTableArea = Invoke-TestArea -Name "Handles" -Context (New-TestContext -Memory $memory -Processes $noTable -ProcessLayout $judgedLayout -CaptureFileTime $capture.ToFileTimeUtc())
    Assert-KitEqual -Name "handles: when the process scan did not read the process ID table (or used the engine's own list) nothing is judged hidden" -Expected "0|3" -Actual "$(@($noTableArea.Entries | Where-Object { $_.Kind -eq 'HandleProcess' }).Count)|$($noTableArea.Coverage.Get('of them not judged'))"

    # The caps of named entries: 60 named mutexes in one process, 50 listed
    $floodHolder = New-TestObject -Type "Process"
    $floodPages = New-TestHandleTable -Eprocess $floodHolder
    for ($m = 1; $m -le 60; $m++) { Set-TestHandle -Page $floodPages[0] -Slot $m -Body (New-TestObject -Type "Mutant" -Name ("fixture-flood-{0:d2}" -f $m) -Directory $namedDir) -Access ([uint32]0x1f0001) }
    $floodContext = New-TestContext -Memory $memory -Processes @(@{ Eprocess = $floodHolder; Pid = [long]7100; Ppid = [long]800; ShortName = "fixture-flood.exe"; UserSid = $user1; CreateTime = $t0 }) -ProcessLayout $processLayout -CaptureFileTime $capture.ToFileTimeUtc()
    $floodArea = Invoke-TestArea -Name "Handles" -Context $floodContext
    $floodRows = @($floodArea.Entries | Where-Object { $_.Get("Type") -eq "Mutant" })
    Assert-KitEqual -Name "handles: at most 50 named mutexes of one process are listed (the first by handle value), the rest counted and noted" `
        -Expected "50|\BaseNamedObjects\fixture-flood-50|10|10 more named mutexes in 1 process(es) were only counted, as at most 50 per process and 2000 per dump are listed" `
        -Actual "$($floodRows.Count)|$($floodRows[-1].Get('Target'))|$($floodArea.Coverage.Get('named mutexes only counted'))|$(@($floodArea.Coverage.Notes | Where-Object { $_ -like '*named mutexes*' }) -join '')"
    Assert-KitEqual -Name "handles: the caps" -Expected "50|25|2000|1000|500" -Actual "$([TimelineDbgEng.HandleTableScan]::MaxNamedPerProcess)|$([TimelineDbgEng.HandleTableScan]::MaxKeysPerProcess)|$([TimelineDbgEng.HandleTableScan]::MaxMutantsPerDump)|$([TimelineDbgEng.HandleTableScan]::MaxFilesPerDump)|$([TimelineDbgEng.HandleTableScan]::MaxKeysPerDump)"

    # --- 4. Missing symbols and the time limit ---
    $slowContext = New-TestContext -Memory $memory -Processes $processSpecs.ToArray() -ProcessLayout $processLayout
    $slow = Invoke-TestArea -Name "Handles" -Context $slowContext -CapSeconds 0.000001
    Assert-KitEqual -Name "handles: the time limit stops the area (partly read)" -Expected "Partial|True" -Actual "$($slow.State)|$($slow.Note.Contains('stopped at its time limit'))"
    $noEntry = $dt.Clone()
    $noEntry.Remove("_HANDLE_TABLE_ENTRY")
    Set-TestEngineCommands -Dt $noEntry -Symbols $symbols
    $missing = Invoke-TestArea -Name "Handles" -Context (New-TestContext -Memory $memory -Processes $processSpecs.ToArray())
    Assert-KitEqual -Name "handles: not read when the symbols lack the handle table entry" -Expected "NotRead|the kernel's symbols do not give _HANDLE_TABLE_ENTRY.ObjectPointerBits, _HANDLE_TABLE_ENTRY.GrantedAccessBits|0" -Actual "$($missing.State)|$($missing.Note)|$($missing.Entries.Count)"
    $noCookie = $symbols.Clone()
    $noCookie.Remove("nt!ObHeaderCookie")
    Set-TestEngineCommands -Dt $dt -Symbols $noCookie
    $missingContext = New-TestContext -Memory $memory -Processes $processSpecs.ToArray()
    $missingDrivers = Invoke-TestArea -Name "Drivers" -Context $missingContext
    $missingHandles = Invoke-TestArea -Name "Handles" -Context $missingContext
    Assert-KitEqual -Name "drivers and handles: not read without the object header cookie" -Expected "NotRead|the kernel's symbols do not give nt!ObHeaderCookie|NotRead" -Actual "$($missingDrivers.State)|$($missingDrivers.Note)|$($missingHandles.State)"
    $noList = $symbols.Clone()
    $noList.Remove("nt!PsLoadedModuleList")
    Set-TestEngineCommands -Dt $dt -Symbols $noList
    $missingList = Invoke-TestArea -Name "Drivers" -Context (New-TestContext -Memory $memory)
    Assert-KitEqual -Name "drivers: not read without nt!PsLoadedModuleList" -Expected "NotRead|the kernel's symbols do not give nt!PsLoadedModuleList" -Actual "$($missingList.State)|$($missingList.Note)"
    Set-TestEngineCommands -Dt $dt -Symbols $symbols

    # --- 5. The builder's rows, through the protocol ---
    $state = New-DbgEngWorkerState
    foreach ($entry in @($driversArea.Entries) + @($handlesArea.Entries)) { Receive-DbgEngWorkerLine -Line $entry.ToLine() -State $state }
    Assert-KitEqual -Name "rows: the builder reads every Driver and Handle line" -Expected "0|6|16" -Actual "$($state.BadLines)|$((ConvertTo-DbgEngEntryArray $state.Entries['Driver']).Count)|$((ConvertTo-DbgEngEntryArray $state.Entries['Handle']).Count)"
    [void](Get-TestRows)
    $driverCounts = Add-DbgEngDriverRows -Entries (ConvertTo-DbgEngEntryArray $state.Entries["Driver"]) -Source "Memory-Drivers" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    $driverRowObjects = @(Get-TestRows -Objects -Keep)
    $driverRows = @(Get-TestRows)
    Assert-KitEqual -Name "rows: Memory-Drivers (Snapshot rows of the loaded modules, DriverUnload at the unload times)" -Expected "6|2|4" -Actual "$($driverCounts.Entries)|$($driverCounts.Timed)|$($driverCounts.Snapshot)"
    Assert-KitEqual -Name "rows: a loaded module, the hidden one and an unloaded one" `
        -Expected (@(
            "Memory-Drivers|2026-03-02 12:00:00.000|Snapshot|Kernel module in memory: fixture-a.sys||Path=C:\Windows\system32\drivers\fixture-a.sys | Base=0xfffff80011000000 | Size=0x10000 | FoundBy=ModuleList,DriverObject | DriverObject=\Driver\fixture-a",
            "Memory-Drivers|2026-03-02 12:00:00.000|Snapshot|Kernel module in memory: fixture-hidden.sys||Path=C:\Windows\System32\drivers\fixture-hidden.sys | Base=0xfffff80012000000 | Size=0x6000 | FoundBy=DriverObject | DriverObject=\Driver\fixture-hidden | Anomaly=NotInModuleList",
            "Memory-Drivers|2026-03-02 06:00:05.000|DriverUnload|Kernel module unloaded: fixture-early.sys||Base=0xfffff80013000000 | Size=0x4000 | FoundBy=UnloadedDriverList") -join "`n") `
        -Actual (@($driverRows[0], $driverRows[3], $driverRows[4]) -join "`n")
    $late = Add-DbgEngDriverRows -Entries @([PSCustomObject]@{ State = "Unloaded"; Name = "fixture-late.sys"; Base = "0x1"; Size = "0x2"; Time = "2026-03-09T00:00:00.0000000+00:00"; FoundBy = "UnloadedDriverList" }) -Source "Memory-Drivers" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    Assert-KitEqual -Name "rows: an unload time past the acquisition is a Snapshot row with UnloadTime=" -Expected "0|Memory-Drivers|2026-03-02 12:00:00.000|Snapshot|Kernel module unloaded: fixture-late.sys||Base=0x1 | Size=0x2 | FoundBy=UnloadedDriverList | UnloadTime=2026-03-09 00:00:00.000" -Actual "$($late.Timed)|$(@(Get-TestRows) -join '/')"
    $handleCounts = Add-DbgEngHandleRows -Entries (ConvertTo-DbgEngEntryArray $state.Entries["Handle"]) -Source "Memory-Handles" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    $handleRows = @(Get-TestRows -Keep)
    Assert-KitEqual -Name "rows: Memory-Handles (Snapshot rows)" -Expected "16|0|16" -Actual "$($handleCounts.Entries)|$($handleCounts.Timed)|$($handleCounts.Snapshot)"
    Assert-KitEqual -Name "rows: a process handle, a thread handle and a key handle (PID= and ProcessCreated= of the holder, User its SID)" `
        -Expected (@(
            "Memory-Handles|2026-03-02 12:00:00.000|Snapshot|Handle in memory: Process fixture-b.exe (PID: 1000, Process: fixture-a.exe)|$user1|PID=1000 | ProcessCreated=$(& $created 'A') | Type=Process | Handle=0x4 | Access=0x1fffff | Target=fixture-b.exe | TargetPID=2000 | TargetProcess=fixture-b.exe | TargetCreated=$(& $created 'B') | Anomaly=WriteAccessUnrelated",
            "Memory-Handles|2026-03-02 12:00:00.000|Snapshot|Handle in memory: Thread fixture-t.exe (PID: 1000, Process: fixture-a.exe)|$user1|PID=1000 | ProcessCreated=$(& $created 'A') | Type=Thread | Handle=0x14 | Access=0x10 | Target=fixture-t.exe | TargetPID=2100 | TargetProcess=fixture-t.exe | TargetCreated=$(& $created 'T') | TargetTID=2104 | Anomaly=WriteAccessUnrelated",
            "Memory-Handles|2026-03-02 12:00:00.000|Snapshot|Handle in memory: Key \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (PID: 1000, Process: fixture-a.exe)|$user1|PID=1000 | ProcessCreated=$(& $created 'A') | Type=Key | Handle=0x34 | Access=0x20019 | Target=\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") -join "`n") `
        -Actual (@($handleRows[0], $handleRows[1], $handleRows[6]) -join "`n")

    # --- The join (TimelineDbgEng.Joins.ps1): a target with a program header in its private memory ---
    $peCode = [System.Collections.Generic.HashSet[uint64]]::new()
    [void]$peCode.Add($eprocess["B"])
    $context.Shared["PeCodeProcesses"] = $peCode
    [void](Get-TestProtocolLines)
    Invoke-DbgEngJoins -Context $context
    Invoke-DbgEngJoins -Context $context
    $joined = @($handlesArea.Entries | Where-Object { $_.Get('Anomaly') -match 'TargetHasPeCode' } | ForEach-Object { "$($_.Get('Pid'))>$($_.Get('TargetPid')):$($_.Get('Anomaly'))" })
    $joinLines = Get-TestProtocolLines
    $joinLog = @($joinLines | Where-Object { $_.StartsWith('TBDBG|LOG|') } | ForEach-Object { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.Split('|')[3])) } | Select-Object -Last 1)
    Assert-KitEqual -Name "joins: the handle entries whose target has a program header in its private memory get TargetHasPeCode once (an anomaly they had is kept), the count in the log; nothing to join without the private memory area" `
        -Expected "1000>2000:WriteAccessUnrelated,TargetHasPeCode,600>2000:TargetHasPeCode|    Joins: handle entries whose target has a program header in its executable private memory 2|-1" `
        -Actual "$($joined -join ',')|$($joinLog -join '')|$([TimelineDbgEng.MemoryJoins]::MarkPeCodeTargets((New-TestContext -Memory $memory)))"

    # --- 6. The findings rules on these rows ---
    $rowsForRules = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($driverRowObjects) + @(Get-TestRows -Objects)) { $rowsForRules.Add($row) }
    . (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\TimelineReport.Engine.ps1")
    $rules = Import-ReportRules -Path (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\report-rules.json")
    $shipped = @(Invoke-ReportRules -Rows $rowsForRules -Rules $rules | Where-Object { $_.RuleId -in @("INTEG-DRIVER-HIDDEN", "PERSIST-DRIVER-USERPATH", "INTEG-HANDLE-WRITE-ACCESS") } | ForEach-Object { "$($_.RuleId):$($_.GroupKey):$(@($_.RowNumbers).Count)" })
    Assert-KitEqual -Name "rules as shipped: the hidden driver is a lead (INTEG-DRIVER-HIDDEN); no driver path lead; the handle rule is switched off" -Expected "INTEG-DRIVER-HIDDEN:fixture-hidden.sys:1" -Actual ($shipped -join ",")
    ($rules.Rules | Where-Object { $_.Id -eq "INTEG-HANDLE-WRITE-ACCESS" }).Enabled = $true
    $switchedOn = @(Invoke-ReportRules -Rows $rowsForRules -Rules $rules | Where-Object { $_.RuleId -eq "INTEG-HANDLE-WRITE-ACCESS" } | Sort-Object GroupKey | ForEach-Object { "$($_.GroupKey):$(@($_.RowNumbers).Count)" })
    Assert-KitEqual -Name "INTEG-HANDLE-WRITE-ACCESS switched on: one lead per holder of the WriteAccessUnrelated rows only (not the SYSTEM process, the process family or files)" -Expected "fixture-a.exe:3,fixture-app.exe:1,fixture-b.exe:1" -Actual ($switchedOn -join ",")

    # The process reached only through handles: through the protocol, a
    # process of the builder's windows.pslist rows (FoundBy=HandleTable,
    # Anomaly=NotInProcessList, HeldBy=), a lead of INTEG-PROCESS-HIDDEN
    $hiddenState = New-DbgEngWorkerState
    foreach ($entry in $judgedArea.Entries) { Receive-DbgEngWorkerLine -Line $entry.ToLine() -State $hiddenState }
    $hiddenState.Processes.Add([PSCustomObject]@{ PID = [long]7000; PPID = [long]800; ImageFileName = "fixture-holder."; Offset = "0x1"; Threads = [long]1; SessionId = [long]0; CreateTime = "2026-03-02T08:00:00.0000000+00:00"; ExitTime = $null; FoundBy = "ListForward,ListBackward,ProcessIdTable"; TableId = ""; Anomaly = "" })
    $addedProcesses = Add-DbgEngHandleProcesses -Processes $hiddenState.Processes -Entries $hiddenState.Entries
    [void](Get-TestRows)
    [void](Add-MemoryPluginRows -Plugin "windows.pslist" -Source "Memory-Processes" -Entries $hiddenState.Processes.ToArray() -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp")
    $processRows = @(Get-TestRows -Objects)
    Assert-KitEqual -Name "rows: the process reached only through handles is a Memory-Processes row of its own" -Expected "1|Memory-Processes|2026-03-02 11:00:00.000|ProcessCreation|Process in memory: fixture-hide (PID: 6100, PPID: 5900)|Threads= SessionId= FoundBy=HandleTable Anomaly=NotInProcessList HeldBy=7000,7004" `
        -Actual "$addedProcesses|$($processRows[1].Source)|$($processRows[1].Timestamp)|$($processRows[1].EventType)|$($processRows[1].Description)|$($processRows[1].Details)"
    $hiddenLeads = @(Invoke-ReportRules -Rows ([System.Collections.Generic.List[object]]@($processRows)) -Rules $rules | Where-Object { $_.RuleId -eq "INTEG-PROCESS-HIDDEN" } | ForEach-Object { "$($_.GroupKey):$(@($_.RowNumbers).Count)" })
    Assert-KitEqual -Name "rules: INTEG-PROCESS-HIDDEN makes the lead of the process reached only through handles" -Expected "fixture-hide:1" -Actual ($hiddenLeads -join ",")
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
