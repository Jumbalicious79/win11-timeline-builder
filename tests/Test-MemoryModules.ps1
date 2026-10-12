# =============================================================
# Memory test: DLLs and executable private memory (work package WP2, items c and f)
# The Modules and PrivateCode areas of the debugger engine helper
# (lib\memory\TimelineDbgEng.Modules.ps1, TimelineDbgEng.PrivateCode.ps1) on
# synthetic memory through tests\MemoryTestKit.ps1 (no dump, no admin):
# canned "dt -v" output for the kernel's types, processes with loader lists
# (64-bit and a WoW64 process's 32-bit list), VAD trees with image mappings
# (file names, volume devices, PE headers) and private regions. Then their
# entries through the protocol into the builder's rows
# (lib\memory\TimelineMemoryRows.ps1), and those rows through the real
# report rules (lib\report\report-rules.json; the rules' own cases are in
# tests\fixtures\report\rules\cases-memory-modules.csv, checked by
# Test-ReportRules.ps1).
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryModules.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }

# --- Synthetic memory -----------------------------------------------------------------

# The kernel's types as 'dt -v' gives them (Windows 11 26100 ARM64 offsets)
function Get-TestModulesDt {
    $listEntry = "struct _LIST_ENTRY, 2 elements, 0x10 bytes"
    $unicode = "struct _UNICODE_STRING, 3 elements, 0x10 bytes"
    return @{
        "_EPROCESS"             = New-TestDtText -Type "_EPROCESS" -Size 0x900 -Fields @(@(0x618, "VadRoot", "struct _RTL_AVL_TREE, 1 elements, 0x8 bytes"), @(0x628, "VadCount", "Uint8B"))
        "_EX_FAST_REF"          = New-TestDtText -Type "_EX_FAST_REF" -Size 8 -Fields @(@(0, "RefCnt", "Bitfield Pos 0, 4 Bits"))
        "_RTL_BALANCED_NODE"    = New-TestDtText -Type "_RTL_BALANCED_NODE" -Size 0x18 -Fields @(@(0, "Left", "Ptr64 to struct _RTL_BALANCED_NODE"), @(8, "Right", "Ptr64 to struct _RTL_BALANCED_NODE"), @(0x10, "ParentValue", "Uint8B"))
        "_MMVAD_SHORT"          = New-TestDtText -Type "_MMVAD_SHORT" -Size 0x40 -Fields @(@(0x18, "StartingVpn", "Uint4B"), @(0x1c, "EndingVpn", "Uint4B"), @(0x20, "StartingVpnHigh", "UChar"), @(0x21, "EndingVpnHigh", "UChar"), @(0x30, "u", "union <unnamed-tag>, 6 elements, 0x4 bytes"))
        "_MMVAD_FLAGS"          = New-TestDtText -Type "_MMVAD_FLAGS" -Size 4 -Fields @(@(0, "VadType", "Bitfield Pos 4, 3 Bits"), @(0, "Protection", "Bitfield Pos 7, 5 Bits"), @(0, "PrivateMemory", "Bitfield Pos 21, 1 Bit"))
        "_MMVAD"                = New-TestDtText -Type "_MMVAD" -Size 0x88 -Fields @(@(0, "Core", "struct _MMVAD_SHORT"), @(0x48, "Subsection", "Ptr64 to struct _SUBSECTION"))
        "_SUBSECTION"           = New-TestDtText -Type "_SUBSECTION" -Size 0x38 -Fields @(@(0, "ControlArea", "Ptr64 to struct _CONTROL_AREA"))
        "_CONTROL_AREA"         = New-TestDtText -Type "_CONTROL_AREA" -Size 0x80 -Fields @(@(0x40, "FilePointer", "struct _EX_FAST_REF, 3 elements, 0x8 bytes"))
        "_FILE_OBJECT"          = New-TestDtText -Type "_FILE_OBJECT" -Size 0xd8 -Fields @(@(8, "DeviceObject", "Ptr64 to struct _DEVICE_OBJECT, 25 elements, 0x150 bytes"), @(0x58, "FileName", $unicode))
        "_PEB"                  = New-TestDtText -Type "_PEB" -Size 0x7d8 -Fields @(@(0x18, "Ldr", "Ptr64 to struct _PEB_LDR_DATA, 9 elements, 0x58 bytes"))
        "_PEB_LDR_DATA"         = New-TestDtText -Type "_PEB_LDR_DATA" -Size 0x58 -Fields @(@(0x10, "InLoadOrderModuleList", $listEntry))
        "_LDR_DATA_TABLE_ENTRY" = New-TestDtText -Type "_LDR_DATA_TABLE_ENTRY" -Size 0x138 -Fields @(
            @(0, "InLoadOrderLinks", $listEntry), @(0x30, "DllBase", "Ptr64 to Void"), @(0x40, "SizeOfImage", "Uint4B"), @(0x48, "FullDllName", $unicode), @(0x58, "BaseDllName", $unicode),
            @(0x100, "LoadTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"), @(0x10c, "LoadReason", "Enum _LDR_DLL_LOAD_REASON,  11 total enums"))
        "_LIST_ENTRY"           = New-TestDtText -Type "_LIST_ENTRY" -Size 0x10 -Fields @(@(0, "Flink", "Ptr64 to struct _LIST_ENTRY, 2 elements, 0x10 bytes"), @(8, "Blink", "Ptr64 to struct _LIST_ENTRY, 2 elements, 0x10 bytes"))
        "_EWOW64PROCESS"        = New-TestDtText -Type "_EWOW64PROCESS" -Size 0x18 -Fields @(@(0, "Peb", "Ptr64 to Void"))
        "_LDR_DLL_LOAD_REASON"  = "Enum _LDR_DLL_LOAD_REASON,  11 total enums`n   LoadReasonStaticDependency = 0n0`n   LoadReasonStaticForwarderDependency = 0n1`n   LoadReasonDynamicLoad = 0n4`n   LoadReasonUnknown = 0n-1`n"
    }
}

function ConvertTo-TestAddress { param([string]$Hex) return [Convert]::ToUInt64($Hex, 16) }

# A VAD tree of -Regions (@{ Start; Size; Type (2: image); Protection; Private;
# File (an image's file name); Device }) as a chain of right children in
# address order, its nodes from -NodeBase (one page each): Root and Count
function Write-TestVadTree {
    param($Memory, [uint64]$NodeBase, [object[]]$Regions)
    $sorted = @($Regions | Sort-Object { [uint64]$_.Start })
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $region = $sorted[$i]
        $node = $NodeBase + [uint64]($i * 0x1000)
        $parent = if ($i -gt 0) { $NodeBase + [uint64](($i - 1) * 0x1000) } else { [uint64]0 }
        $right = if ($i + 1 -lt $sorted.Count) { $NodeBase + [uint64](($i + 1) * 0x1000) } else { [uint64]0 }
        $Memory.WriteU64(0, $node, [uint64]0)
        $Memory.WriteU64(0, $node + 8, $right)
        $Memory.WriteU64(0, $node + 0x10, $parent)
        $startVpn = [uint64]$region.Start -shr 12
        $endVpn = ([uint64]$region.Start + [uint64]$region.Size - [uint64]1) -shr 12
        $Memory.WriteU32(0, $node + 0x18, [uint32]($startVpn -band [uint64]4294967295))
        $Memory.WriteU32(0, $node + 0x1c, [uint32]($endVpn -band [uint64]4294967295))
        $Memory.WriteU8(0, $node + 0x20, [byte](($startVpn -shr 32) -band [uint64]0xFF))
        $Memory.WriteU8(0, $node + 0x21, [byte](($endVpn -shr 32) -band [uint64]0xFF))
        $Memory.WriteU32(0, $node + 0x30, (([uint32]$region.Type -shl 4) -bor ([uint32]$region.Protection -shl 7) -bor ([uint32]$region.Private -shl 21)))
        if ($region.File) {
            $subsection = $node + [uint64]0x100
            $control = $node + [uint64]0x200
            $file = $node + [uint64]0x300
            $Memory.WriteU64(0, $node + 0x48, $subsection)
            $Memory.WriteU64(0, $subsection, $control)
            $Memory.WriteU64(0, $control + 0x40, $file -bor [uint64]1)
            $Memory.WriteU64(0, $file + 8, [uint64]$region.Device)
            $Memory.WriteUnicodeString(0, $file + 0x58, $file + 0x80, [string]$region.File)
        }
    }
    $root = if ($sorted.Count -gt 0) { $NodeBase } else { [uint64]0 }
    return [PSCustomObject]@{ Root = $root; Count = $sorted.Count }
}

# The process's 64-bit loader list (PEB.Ldr -> InLoadOrderModuleList) of
# -Modules (@{ Base; Size; Path; LoadTime (FILETIME); Reason }); -BrokenAfter
# n: the n-th entry's Flink points to memory that is not in the dump
function Write-TestLoaderList {
    param($Memory, [uint64]$Process, [uint64]$Peb, [object[]]$Modules, [int]$BrokenAfter = -1)
    $ldr = [uint64]0x10000
    $head = $ldr + [uint64]0x10
    $Memory.WriteU64($Process, $Peb + [uint64]0x18, $ldr)
    $entries = @(for ($i = 0; $i -lt $Modules.Count; $i++) { [uint64](0x20000 + $i * 0x200) })
    $Memory.WriteU64($Process, $head, $(if ($entries.Count -gt 0) { $entries[0] } else { $head }))
    $Memory.WriteU64($Process, $head + [uint64]8, $(if ($entries.Count -gt 0) { $entries[-1] } else { $head }))
    for ($i = 0; $i -lt $Modules.Count; $i++) {
        $module = $Modules[$i]
        $entry = $entries[$i]
        $flink = if ($i -eq $BrokenAfter) { [uint64]0x7999000 } elseif ($i + 1 -lt $entries.Count) { $entries[$i + 1] } else { $head }
        $blink = if ($i -gt 0) { $entries[$i - 1] } else { $head }
        $strings = [uint64](0x40000 + $i * 0x800)
        $Memory.WriteU64($Process, $entry, $flink)
        $Memory.WriteU64($Process, $entry + 8, $blink)
        $Memory.WriteU64($Process, $entry + 0x30, [uint64]$module.Base)
        $Memory.WriteU32($Process, $entry + 0x40, [uint32]$module.Size)
        $Memory.WriteUnicodeString($Process, $entry + 0x48, $strings, [string]$module.Path)
        $Memory.WriteUnicodeString($Process, $entry + 0x58, $strings + [uint64]0x400, ([string]$module.Path -split '\\')[-1])
        $Memory.WriteU64($Process, $entry + 0x100, [uint64][long]$module.LoadTime)
        $Memory.WriteU32($Process, $entry + 0x10c, [uint32]$module.Reason)
    }
}

# A WoW64 process's 32-bit loader list (fixed 32-bit offsets): the 32-bit
# PEB at -Peb32 (below 4 GB), the EWOW64PROCESS at -Wow64 (kernel)
function Write-TestLoaderList32 {
    param($Memory, [uint64]$Process, [uint64]$Wow64, [uint64]$Peb32, [object[]]$Modules)
    $Memory.WriteU64(0, $Wow64, $Peb32)
    $ldr = [uint64]0x310000
    $head = $ldr + [uint64]0x0C
    $Memory.WriteU32($Process, $Peb32 + [uint64]0x0C, [uint32]$ldr)
    $entries = @(for ($i = 0; $i -lt $Modules.Count; $i++) { [uint64](0x320000 + $i * 0x100) })
    $Memory.WriteU32($Process, $head, [uint32]$entries[0])
    $Memory.WriteU32($Process, $head + [uint64]4, [uint32]$entries[-1])
    for ($i = 0; $i -lt $Modules.Count; $i++) {
        $entry = $entries[$i]
        $flink = if ($i + 1 -lt $entries.Count) { $entries[$i + 1] } else { $head }
        $blink = if ($i -gt 0) { $entries[$i - 1] } else { $head }
        $strings = [uint64](0x330000 + $i * 0x400)
        $path = [string]$Modules[$i].Path
        $leaf = ($path -split '\\')[-1]
        $Memory.WriteU32($Process, $entry, [uint32]$flink)
        $Memory.WriteU32($Process, $entry + 4, [uint32]$blink)
        $Memory.WriteU32($Process, $entry + 0x18, [uint32]$Modules[$i].Base)
        $Memory.WriteU32($Process, $entry + 0x20, [uint32]$Modules[$i].Size)
        foreach ($pair in @(@(0x24, $path, 0), @(0x2C, $leaf, 0x200))) {
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($pair[1])
            $Memory.WriteU16($Process, $entry + [uint64]$pair[0], [uint16]$bytes.Length)
            $Memory.WriteU16($Process, $entry + [uint64]$pair[0] + 2, [uint16]($bytes.Length + 2))
            $Memory.WriteU32($Process, $entry + [uint64]$pair[0] + 4, [uint32]($strings + [uint64]$pair[2]))
            $Memory.Write($Process, $strings + [uint64]$pair[2], $bytes)
        }
    }
}

# A PE header at an image's base: 64-bit, with a CLR header (-Managed) or not
function Write-TestPeHeader {
    param($Memory, [uint64]$Process, [uint64]$Base, [switch]$Managed)
    $header = New-Object byte[] 0x200
    $header[0] = 0x4D; $header[1] = 0x5A
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x80), 0, $header, 0x3C, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x4550), 0, $header, 0x80, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x20B), 0, $header, 0x98, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $header, 0x98 + 108, 4)
    if ($Managed) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x2000), 0, $header, 0x98 + 112 + 14 * 8, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x48), 0, $header, 0x98 + 112 + 14 * 8 + 4, 4)
    }
    $Memory.Write($Process, $Base, $header)
}

# An EPROCESS block with its VAD tree's root and VadCount
function New-TestProcessBlock {
    param($Tree, [long]$CountDelta = 0)
    $block = New-Object byte[] 0x900
    [Array]::Copy([BitConverter]::GetBytes([uint64]$Tree.Root), 0, $block, 0x618, 8)
    [Array]::Copy([BitConverter]::GetBytes([long]$Tree.Count + $CountDelta), 0, $block, 0x628, 8)
    return , $block
}

# The synthetic dump: Memory and Processes (hashtables for New-TestContext).
#   A fixture-app.exe   (4321) 64-bit, a full loader list, image mappings in
#                       and out of it, private regions of every kind
#   B fixture-av.exe    (5000) protected: its mapped-only images are counted
#   C fixture32.exe     (6000) WoW64: a 64-bit and a 32-bit loader list
#   D fixture-jit.exe   (7000) a loader list cut short, a run-time compiler
#   E fixture-gone.exe  (8000) exited: its address space cannot be read
#   F Registry          (88)   no PEB, no regions
# -VadCountDelta: A's VadCount off by this (an inconsistent tree)
function New-TestModulesDump {
    param([long]$VadCountDelta = 0)
    $memory = New-TestMemory
    $created = [datetime]::new(2026, 10, 11, 8, 0, 0, [DateTimeKind]::Utc)
    $t0 = $created.ToFileTimeUtc()
    $second = [long]10000000
    $deviceC = ConvertTo-TestAddress "ffffb4000000a000"
    $deviceD = ConvertTo-TestAddress "ffffb4000000b000"
    $peb = [uint64]0x7ff70000
    $exec = 7; $readOnly = 1
    $procA = ConvertTo-TestAddress "ffffc00000001000"; $procB = ConvertTo-TestAddress "ffffc00000002000"; $procC = ConvertTo-TestAddress "ffffc00000003000"
    $procD = ConvertTo-TestAddress "ffffc00000004000"; $procE = ConvertTo-TestAddress "ffffc00000005000"; $procF = ConvertTo-TestAddress "ffffc00000006000"
    $image = { param($start, $size, $file, $protection = 7, $device = $deviceC) @{ Start = [uint64]$start; Size = [uint64]$size; Type = 2; Protection = $protection; Private = 0; File = $file; Device = $device } }
    $private = { param($start, $size, $protection) @{ Start = [uint64]$start; Size = [uint64]$size; Type = 0; Protection = $protection; Private = 1; File = ""; Device = 0 } }

    # A: loader entries 0-5, mapped-only images, private regions
    Write-TestLoaderList -Memory $memory -Process $procA -Peb $peb -Modules @(
        @{ Base = [uint64]0x7ff600000000; Size = 0x20000; Path = "C:\Program Files\Fixture\fixture-app.exe"; LoadTime = $t0 + $second; Reason = 0 }
        @{ Base = [uint64]0x7ffb00000000; Size = 0x200000; Path = "C:\Windows\System32\ntdll.dll"; LoadTime = $t0 + $second; Reason = 0 }
        @{ Base = [uint64]0x7ffa00000000; Size = 0x10000; Path = "C:\Users\alice\AppData\Local\Temp\fixture-tmp.dll"; LoadTime = $t0 + 60 * $second; Reason = 4 }
        @{ Base = [uint64]0x7ffa10000000; Size = 0x10000; Path = "C:\Program Files\Fixture\fixture-good.dll"; LoadTime = $t0 + 61 * $second; Reason = 4 }
        @{ Base = [uint64]0x7ffa20000000; Size = 0x10000; Path = "C:\Program Files\Fixture\fixture-ghost.dll"; LoadTime = $t0 + 62 * $second; Reason = 4 }
        @{ Base = [uint64]0x7ffa30000000; Size = 0x10000; Path = "C:\Program Files\Fixture\fixture-early.dll"; LoadTime = $t0 - 86400 * $second; Reason = 7 })
    foreach ($base in @([uint64]0x7ff600000000, [uint64]0x7ff800000000, [uint64]0x7ff830000000, [uint64]0x7ff840000000)) { Write-TestPeHeader -Memory $memory -Process $procA -Base $base }
    Write-TestPeHeader -Memory $memory -Process $procA -Base ([uint64]0x7ff820000000) -Managed
    $peRegion = New-Object byte[] 0x100
    $peRegion[0] = 0x4D; $peRegion[1] = 0x5A
    $memory.Write($procA, [uint64]0x1000000, $peRegion)
    $memory.Write($procA, [uint64]0x2000000, (New-Object byte[] 0x1000))
    $erased = New-Object byte[] 0x100
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x80), 0, $erased, 0x3C, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x4550), 0, $erased, 0x80, 4)
    $memory.Write($procA, [uint64]0x5000000, $erased)
    $memory.Write($procA, [uint64]0x6000000, [byte[]](0xFD, 0x7B, 0xBF, 0xA9))
    $treeA = Write-TestVadTree -Memory $memory -NodeBase (ConvertTo-TestAddress "ffffb10000000000") -Regions @(
        (& $image 0x7ff600000000 0x20000 "\Program Files\Fixture\fixture-app.exe")
        (& $image 0x7ffb00000000 0x200000 "\Windows\System32\ntdll.dll")
        (& $image 0x7ffa00000000 0x10000 "\Users\alice\AppData\Local\Temp\fixture-tmp.dll")
        (& $image 0x7ffa10000000 0x10000 "\Program Files\Fixture\fixture-other.dll")
        (& $image 0x7ffa30000000 0x10000 "\Program Files\Fixture\fixture-early.dll")
        (& $image 0x7ff800000000 0x10000 "\Users\alice\Downloads\fixture-hidden.dll")
        (& $image 0x7ff810000000 0x10000 "\Windows\System32\fixture-res.dll" $readOnly)
        (& $image 0x7ff820000000 0x10000 "\Program Files\Fixture\fixture-managed.dll")
        (& $image 0x7ff830000000 0x10000 "\Program Files\Fixture\fixture-mapped.dll")
        (& $image 0x7ff840000000 0x10000 "\Data\fixture-d2.dll" $exec $deviceD)
        (& $private 0x1000000 0x10000 6)
        (& $private 0x2000000 0x2000 3)
        (& $private 0x3000000 0x1000 4)
        (& $private 0x4000000 0x1000 6)
        (& $private 0x5000000 0x1000 6)
        (& $private 0x6000000 0x3000 2))

    # B (protected): its own program, ntdll, two mapped-only images, a private region
    Write-TestLoaderList -Memory $memory -Process $procB -Peb $peb -Modules @(
        @{ Base = [uint64]0x7ff600000000; Size = 0x20000; Path = "C:\ProgramData\Fixture\fixture-av.exe"; LoadTime = $t0 + $second; Reason = 0 }
        @{ Base = [uint64]0x7ffb00000000; Size = 0x200000; Path = "C:\Windows\System32\ntdll.dll"; LoadTime = $t0 + $second; Reason = 0 })
    $memory.Write($procB, [uint64]0x1000000, [byte[]](1, 2, 3, 4))
    $treeB = Write-TestVadTree -Memory $memory -NodeBase (ConvertTo-TestAddress "ffffb10000100000") -Regions @(
        (& $image 0x7ff600000000 0x20000 "\ProgramData\Fixture\fixture-av.exe")
        (& $image 0x7ffb00000000 0x200000 "\Windows\System32\ntdll.dll")
        (& $image 0x7ff800000000 0x10000 "\Users\alice\Downloads\fixture-scanned.exe" $readOnly)
        (& $image 0x7ff810000000 0x10000 "\Program Files\Fixture\fixture-scanned2.dll")
        (& $private 0x1000000 0x1000 6))

    # C (WoW64): 64-bit list (the program, ntdll), 32-bit list (the program,
    # the 32-bit ntdll, a DLL), and a mapped-only 32-bit DLL
    $wow64 = ConvertTo-TestAddress "ffffb30000000000"
    Write-TestLoaderList -Memory $memory -Process $procC -Peb $peb -Modules @(
        @{ Base = [uint64]0x400000; Size = 0x10000; Path = "C:\Program Files (x86)\Fixture\fixture32.exe"; LoadTime = $t0 + $second; Reason = 0 }
        @{ Base = [uint64]0x7ffb00000000; Size = 0x200000; Path = "C:\Windows\System32\ntdll.dll"; LoadTime = $t0 + $second; Reason = 0 })
    Write-TestLoaderList32 -Memory $memory -Process $procC -Wow64 $wow64 -Peb32 ([uint64]0x300000) -Modules @(
        @{ Base = 0x400000; Size = 0x10000; Path = "C:\Program Files (x86)\Fixture\fixture32.exe" }
        @{ Base = 0x77000000; Size = 0x100000; Path = "C:\Windows\SysWOW64\ntdll.dll" }
        @{ Base = 0x10000000; Size = 0x10000; Path = "C:\Program Files (x86)\Fixture\fixture32.dll" })
    $treeC = Write-TestVadTree -Memory $memory -NodeBase (ConvertTo-TestAddress "ffffb10000200000") -Regions @(
        (& $image 0x400000 0x10000 "\Program Files (x86)\Fixture\fixture32.exe")
        (& $image 0x7ffb00000000 0x200000 "\Windows\System32\ntdll.dll")
        (& $image 0x77000000 0x100000 "\Windows\SysWOW64\ntdll.dll")
        (& $image 0x10000000 0x10000 "\Program Files (x86)\Fixture\fixture32.dll")
        (& $image 0x20000000 0x10000 "\Program Files (x86)\Fixture\fixture32-hidden.dll"))
    Write-TestPeHeader -Memory $memory -Process $procC -Base ([uint64]0x20000000)

    # D: the list stops after its second entry (the .NET compiler); a
    # mapped-only image is then not judged; a private region
    Write-TestLoaderList -Memory $memory -Process $procD -Peb $peb -BrokenAfter 1 -Modules @(
        @{ Base = [uint64]0x7ff600000000; Size = 0x20000; Path = "C:\Program Files\Fixture\fixture-jit.exe"; LoadTime = $t0 + $second; Reason = 0 }
        @{ Base = [uint64]0x7ffc00000000; Size = 0x100000; Path = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll"; LoadTime = $t0 + 2 * $second; Reason = 4 }
        @{ Base = [uint64]0x7ffb00000000; Size = 0x200000; Path = "C:\Windows\System32\ntdll.dll"; LoadTime = $t0 + $second; Reason = 0 })
    $memory.Write($procD, [uint64]0x1000000, [byte[]](1, 2, 3, 4))
    Write-TestPeHeader -Memory $memory -Process $procD -Base ([uint64]0x7ff810000000)
    $treeD = Write-TestVadTree -Memory $memory -NodeBase (ConvertTo-TestAddress "ffffb10000300000") -Regions @(
        (& $image 0x7ff600000000 0x20000 "\Program Files\Fixture\fixture-jit.exe")
        (& $image 0x7ffc00000000 0x100000 "\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll")
        (& $image 0x7ffb00000000 0x200000 "\Windows\System32\ntdll.dll")
        (& $image 0x7ff810000000 0x10000 "\Program Files\Fixture\fixture-unjudged.dll")
        (& $private 0x1000000 0x1000 6))
    $memory.Refuse($procE)
    $empty = [PSCustomObject]@{ Root = [uint64]0; Count = 0 }
    $processes = @(
        @{ Eprocess = $procA; Pid = 4321; Ppid = 3000; CreateTime = $created; Peb = $peb; ShortName = "fixture-app.exe"; UserSid = "S-1-5-21-1-2-3-1001"; Block = (New-TestProcessBlock $treeA $VadCountDelta) }
        @{ Eprocess = $procB; Pid = 5000; Ppid = 700; CreateTime = $created; Peb = $peb; ShortName = "fixture-av.exe"; Protection = [byte]0x31; Block = (New-TestProcessBlock $treeB) }
        @{ Eprocess = $procC; Pid = 6000; Ppid = 3000; CreateTime = $created; Peb = $peb; Wow64 = $wow64; ShortName = "fixture32.exe"; Block = (New-TestProcessBlock $treeC) }
        @{ Eprocess = $procD; Pid = 7000; Ppid = 3000; CreateTime = $created; Peb = $peb; ShortName = "fixture-jit.exe"; Block = (New-TestProcessBlock $treeD) }
        @{ Eprocess = $procE; Pid = 8000; Ppid = 3000; CreateTime = $created; ExitTime = $created.AddHours(1); Peb = $peb; ShortName = "fixture-gone.ex"; Block = (New-TestProcessBlock $empty) }
        @{ Eprocess = $procF; Pid = 88; Ppid = 4; CreateTime = $created; Peb = [uint64]0; ShortName = "Registry"; Block = (New-TestProcessBlock $empty) }
    )
    return [PSCustomObject]@{ Memory = $memory; Processes = $processes }
}

# An entry as "Kind:Key=value|Key=value" (its keys in order, -Keys only those)
function Format-TestEntry {
    param($Entry, [string[]]$Keys = @())
    $fields = Get-TestEntryFields $Entry
    $parts = @(foreach ($key in @($fields.Keys)) { if ($key -ne "Kind" -and ($Keys.Count -eq 0 -or $Keys -contains $key)) { "$key=$($fields[$key])" } })
    return "$($fields['Kind']):$($parts -join '|')"
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryModules"
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    $end = $capture.AddMinutes(3)

    # --- The Modules area -------------------------------------------------------------------
    Set-TestEngineCommands -Dt (Get-TestModulesDt)
    $dump = New-TestModulesDump
    $context = New-TestContext -Memory $dump.Memory -Processes $dump.Processes
    $modules = Invoke-TestArea -Name "Modules" -Context $context -CapSeconds 60
    $moduleLines = @($modules.Entries | ForEach-Object { Format-TestEntry $_ -Keys @("PID", "Name", "Base", "FoundBy", "Anomaly", "Protection", "Managed", "LoaderPath") })
    Assert-KitEqual -Name "Modules: read, one entry per DLL outside the Windows folder (its Temp folder counts) or judged, in process and address order; the protected process's mapped-only images and the cut-short list's not judged" `
        -Expected (@(
            "Module:PID=4321|Name=fixture-app.exe|Base=0x7ff600000000|FoundBy=LoaderList,ImageMapping"
            "Module:PID=4321|Name=fixture-hidden.dll|Base=0x7ff800000000|FoundBy=ImageMapping|Protection=ExecuteWriteCopy|Anomaly=NotInLoaderLists"
            "Module:PID=4321|Name=fixture-res.dll|Base=0x7ff810000000|FoundBy=ImageMapping|Protection=ReadOnly|Anomaly=NotInLoaderLists"
            "Module:PID=4321|Name=fixture-managed.dll|Base=0x7ff820000000|FoundBy=ImageMapping|Protection=ExecuteWriteCopy|Managed=Yes|Anomaly=NotInLoaderLists"
            "Module:PID=4321|Name=fixture-mapped.dll|Base=0x7ff830000000|FoundBy=ImageMapping|Protection=ExecuteWriteCopy|Anomaly=NotInLoaderLists"
            "Module:PID=4321|Name=fixture-d2.dll|Base=0x7ff840000000|FoundBy=ImageMapping|Protection=ExecuteWriteCopy|Anomaly=NotInLoaderLists"
            "Module:PID=4321|Name=fixture-tmp.dll|Base=0x7ffa00000000|FoundBy=LoaderList,ImageMapping"
            "Module:PID=4321|Name=fixture-other.dll|Base=0x7ffa10000000|FoundBy=LoaderList,ImageMapping|Anomaly=NameMismatch|LoaderPath=C:\Program Files\Fixture\fixture-good.dll"
            "Module:PID=4321|Name=fixture-ghost.dll|Base=0x7ffa20000000|FoundBy=LoaderList|Anomaly=NoImageMapping"
            "Module:PID=4321|Name=fixture-early.dll|Base=0x7ffa30000000|FoundBy=LoaderList,ImageMapping"
            "Module:PID=5000|Name=fixture-av.exe|Base=0x7ff600000000|FoundBy=LoaderList,ImageMapping"
            "Module:PID=6000|Name=fixture32.exe|Base=0x400000|FoundBy=LoaderList,LoaderList32,ImageMapping"
            "Module:PID=6000|Name=fixture32.dll|Base=0x10000000|FoundBy=LoaderList32,ImageMapping"
            "Module:PID=6000|Name=fixture32-hidden.dll|Base=0x20000000|FoundBy=ImageMapping|Protection=ExecuteWriteCopy|Anomaly=NotInLoaderLists"
            "Module:PID=7000|Name=fixture-jit.exe|Base=0x7ff600000000|FoundBy=LoaderList,ImageMapping"
            "Module:PID=7000|Name=fixture-unjudged.dll|Base=0x7ff810000000|FoundBy=ImageMapping|Protection=ExecuteWriteCopy") -join " / ") `
        -Actual ($moduleLines -join " / ")
    Assert-KitEqual -Name "Modules: the area is Read" -Expected "Read" -Actual $modules.State
    $first = Format-TestEntry $modules.Entries[0]
    Assert-KitEqual -Name "Modules: an entry's fields (process, its token's user, the path with the drive learned from the loader, sizes, the load reason by its name, the load time in the process's lifetime)" `
        -Expected "Module:PID=4321|ProcessCreated=2026-10-11 08:00:00.000|Process=fixture-app.exe|User=S-1-5-21-1-2-3-1001|Name=fixture-app.exe|Path=C:\Program Files\Fixture\fixture-app.exe|Base=0x7ff600000000|Size=0x20000|LoadReason=StaticDependency|LoadTime=2026-10-11T08:00:01.0000000+00:00|FoundBy=LoaderList,ImageMapping" `
        -Actual $first
    $byName = @{}
    foreach ($entry in $modules.Entries) { $byName[$entry.Get("Name")] = $entry }
    Assert-KitEqual -Name "Modules: paths (a mapped-only image on a known volume gets its drive letter, one on another volume none; a loader entry without a mapping its loader path; a WoW64 32-bit DLL), load reasons (a name, a number the symbols do not name), a load time before the process started left out" `
        -Expected "C:\Users\alice\Downloads\fixture-hidden.dll|\Data\fixture-d2.dll|C:\Program Files\Fixture\fixture-ghost.dll|C:\Program Files (x86)\Fixture\fixture32.dll|DynamicLoad|7|False|True|False" `
        -Actual "$($byName['fixture-hidden.dll'].Get('Path'))|$($byName['fixture-d2.dll'].Get('Path'))|$($byName['fixture-ghost.dll'].Get('Path'))|$($byName['fixture32.dll'].Get('Path'))|$($byName['fixture-tmp.dll'].Get('LoadReason'))|$($byName['fixture-early.dll'].Get('LoadReason'))|$($byName['fixture-early.dll'].Has('LoadTime'))|$($byName['fixture-tmp.dll'].Has('LoadTime'))|$($byName['fixture32.dll'].Has('LoadTime'))"
    Assert-KitEqual -Name "Modules: the log's counts" `
        -Expected ("processes 6, loader lists complete 3, loader lists not in the dump 1, loader lists cut short 1, loader entries 12, 32-bit loader entries 3, loader links not pointing back 0, image mappings 23, " +
            "image file names not read 0, mapped but in no loader list 6, mapped but in no loader list in protected processes 2, mapped images not judged 2, loader entries without an image mapping 1, " +
            "loader names unlike the mapped file 1, outside the Windows folder 17, managed images mapped by their runtime 1, load times outside the process lifetime 1, volume drive letters learned 1, inconsistent memory-region trees 0, entries 16") `
        -Actual $modules.Coverage.CountsText
    Assert-KitEqual -Name "Modules: the coverage note (loader lists not read to their end)" -Expected "the loader lists of 2 processes could not be read to their end, exited or paged out, so their images were not judged" -Actual $modules.Note
    $shared = "$($context.Shared['VadWalks'].Count)|$($context.Shared['ModuleNames'].Count)|$($context.Shared['Dlls'].Count)|$($context.Shared['ModuleNames'][$dump.Processes[3].Eprocess].Contains('clrjit.dll'))"
    Assert-KitEqual -Name "Modules: what it leaves for the other areas and the joins (the VAD walks, module names, DLLs per process)" -Expected "6|6|6|True" -Actual $shared

    # An inconsistent VAD tree: no loader entry is judged as without a mapping
    Set-TestEngineCommands -Dt (Get-TestModulesDt)
    $smeared = New-TestModulesDump -VadCountDelta 1
    $smearedArea = Invoke-TestArea -Name "Modules" -Context (New-TestContext -Memory $smeared.Memory -Processes $smeared.Processes) -CapSeconds 60
    $ghost = @($smearedArea.Entries | Where-Object { $_.Get("Name") -eq "fixture-ghost.dll" })
    Assert-KitEqual -Name "Modules: a VAD tree that does not add up (VadCount): the loader entry without a mapping is listed but not judged, and the note says why" `
        -Expected "1||True" -Actual "$($ghost.Count)|$($ghost[0].Get('Anomaly'))|$($smearedArea.Note.Contains('the memory-region trees of 1 process did not add up, as when memory is copied while Windows runs'))"

    # Without the symbols: not read; without the VAD types: the loader lists only
    Set-TestEngineCommands -Dt @{}
    $noSymbols = Invoke-TestArea -Name "Modules" -Context (New-TestContext -Memory $dump.Memory -Processes $dump.Processes)
    $loaderOnlyDt = Get-TestModulesDt
    foreach ($type in @("_RTL_BALANCED_NODE", "_MMVAD_SHORT", "_MMVAD_FLAGS", "_MMVAD")) { $loaderOnlyDt.Remove($type) }
    Set-TestEngineCommands -Dt $loaderOnlyDt
    $loaderOnlyContext = New-TestContext -Memory $dump.Memory -Processes $dump.Processes
    $loaderOnly = Invoke-TestArea -Name "Modules" -Context $loaderOnlyContext
    $noWalks = Invoke-TestArea -Name "PrivateCode" -Context $loaderOnlyContext
    Assert-KitEqual -Name "Modules: without the kernel's symbols for them not read (why); without the memory-region types the loader lists only (Partial, why), and PrivateCode then not read" `
        -Expected "NotRead|the kernel's symbols do not describe the loader lists or the memory regions|Partial|True|9|0|NotRead|the kernel's symbols do not describe the memory regions" `
        -Actual "$($noSymbols.State)|$($noSymbols.Note)|$($loaderOnly.State)|$($loaderOnly.Note.StartsWith('the image mappings were not read, the kernel''s symbols do not describe the memory regions'))|$($loaderOnly.Entries.Count)|$(@($loaderOnly.Entries | Where-Object { $_.Get('FoundBy') -match 'ImageMapping' }).Count)|$($noWalks.State)|$($noWalks.Note)"
    Set-TestEngineCommands -Dt (Get-TestModulesDt)
    $capped = Invoke-TestArea -Name "Modules" -Context (New-TestContext -Memory $dump.Memory -Processes $dump.Processes) -CapSeconds 0.0000001
    Assert-KitEqual -Name "Modules: its time limit stops it (Partial, the note says so)" -Expected "Partial|0|True" -Actual "$($capped.State)|$($capped.Entries.Count)|$($capped.Note.Contains('stopped at its time limit'))"

    # --- The PrivateCode area -----------------------------------------------------------------
    $private = Invoke-TestArea -Name "PrivateCode" -Context $context
    $privateLines = @($private.Entries | ForEach-Object { Format-TestEntry $_ -Keys @("PID", "Start", "Size", "Protection", "FirstBytes", "JitHost", "ProcessProtected", "Anomaly") })
    Assert-KitEqual -Name "PrivateCode: one entry per executable private region (not a read-write one): a program header (MZ, or PE at e_lfanew with MZ erased), zero, data, not in the dump; JitHost from the module names; a protected process marked" `
        -Expected (@(
            "PrivateCode:PID=4321|Start=0x1000000|Size=0x10000|Protection=ExecuteReadWrite|FirstBytes=PE|JitHost=No|Anomaly=PeHeader"
            "PrivateCode:PID=4321|Start=0x2000000|Size=0x2000|Protection=ExecuteRead|FirstBytes=Zero|JitHost=No"
            "PrivateCode:PID=4321|Start=0x4000000|Size=0x1000|Protection=ExecuteReadWrite|FirstBytes=Unreadable|JitHost=No"
            "PrivateCode:PID=4321|Start=0x5000000|Size=0x1000|Protection=ExecuteReadWrite|FirstBytes=PE|JitHost=No|Anomaly=PeHeader"
            "PrivateCode:PID=4321|Start=0x6000000|Size=0x3000|Protection=Execute|FirstBytes=Data|JitHost=No"
            "PrivateCode:PID=5000|Start=0x1000000|Size=0x1000|Protection=ExecuteReadWrite|FirstBytes=Data|JitHost=No|ProcessProtected=Yes"
            "PrivateCode:PID=7000|Start=0x1000000|Size=0x1000|Protection=ExecuteReadWrite|FirstBytes=Data|JitHost=Yes") -join " / ") `
        -Actual ($privateLines -join " / ")
    Assert-KitEqual -Name "PrivateCode: Read, the log's counts (the Modules area's walks reused), the processes with a program header for the joins" `
        -Expected "Read|processes 6, memory-region trees from the DLLs area 6, not walked 0, executable private regions 7, in processes 3, with a program header 2, first page zero 1, other data 3, first page not in the dump 1, in processes with a run-time compiler 1|1" `
        -Actual "$($private.State)|$($private.Coverage.CountsText)|$($context.Shared['PeCodeProcesses'].Count)"
    Assert-KitEqual -Name "PrivateCode: an entry's fields" -Expected "PrivateCode:PID=4321|ProcessCreated=2026-10-11 08:00:00.000|Process=fixture-app.exe|User=S-1-5-21-1-2-3-1001|Start=0x1000000|Size=0x10000|Protection=ExecuteReadWrite|FirstBytes=PE|JitHost=No|Anomaly=PeHeader" `
        -Actual (Format-TestEntry $private.Entries[0])
    # On its own (no Modules area): walks the regions itself, JitHost from the image mappings
    Set-TestEngineCommands -Dt (Get-TestModulesDt)
    $alone = Invoke-TestArea -Name "PrivateCode" -Context (New-TestContext -Memory $dump.Memory -Processes $dump.Processes)
    Assert-KitEqual -Name "PrivateCode: without the Modules area, the same entries from its own walks" -Expected "Read|7|0|$($privateLines -join ' / ')" `
        -Actual "$($alone.State)|$($alone.Entries.Count)|$($alone.Coverage.Get('memory-region trees from the DLLs area'))|$(@($alone.Entries | ForEach-Object { Format-TestEntry $_ -Keys @('PID', 'Start', 'Size', 'Protection', 'FirstBytes', 'JitHost', 'ProcessProtected', 'Anomaly') }) -join ' / ')"
    Set-TestEngineCommands -Dt @{}
    $noRegions = Invoke-TestArea -Name "PrivateCode" -Context (New-TestContext -Memory $dump.Memory -Processes $dump.Processes)
    Assert-KitEqual -Name "PrivateCode: without the memory-region types not read (why)" -Expected "NotRead|the kernel's symbols do not describe the memory regions|0" -Actual "$($noRegions.State)|$($noRegions.Note)|$($noRegions.Entries.Count)"
    $classes = @(
        [TimelineDbgEng.PrivateCodeArea]::Classify([byte[]](0x4D, 0x5A, 0x90, 0)), [TimelineDbgEng.PrivateCodeArea]::Classify((New-Object byte[] 16)), [TimelineDbgEng.PrivateCodeArea]::Classify((New-Object byte[] 0)),
        [TimelineDbgEng.PrivateCodeArea]::Classify([byte[]](0x5A, 0x4D, 1)), [TimelineDbgEng.PrivateCodeArea]::ExecuteName(0x1E), [TimelineDbgEng.PrivateCodeArea]::ExecuteName(4), [TimelineDbgEng.PrivateCodeArea]::ExecuteName(0x11),
        [TimelineDbgEng.PrivateCodeArea]::IsJitRuntime("CoreCLR.dll"), [TimelineDbgEng.PrivateCodeArea]::IsJitRuntime("fixture.dll"))
    Assert-KitEqual -Name "PrivateCode: classification of a first page, protection names (cache and guard bits ignored), run-time compiler names" -Expected "PE|Zero|Unreadable|Data|ExecuteReadWrite|||True|False" -Actual (($classes | ForEach-Object { "$_" }) -join "|")

    # --- Through the protocol into the builder's rows ---------------------------------------------
    $result = New-DbgEngResult
    $result.Entries = @($modules.Entries) + @($private.Entries)
    $result.Areas = @((New-DbgEngAreaSummary -Name "Modules" -State $modules.State -Rows $modules.Rows -Note $modules.Note), (New-DbgEngAreaSummary -Name "PrivateCode" -State $private.State -Rows $private.Rows))
    [void](Get-TestProtocolLines)
    Write-DbgEngWorkerResult $result
    $state = New-DbgEngWorkerState
    foreach ($line in (Get-TestProtocolLines)) { Receive-DbgEngWorkerLine -Line $line -State $state }
    [void](Get-TestRows)
    $kinds = @(Add-DbgEngEntryRows -Entries $state.Entries -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp")
    Assert-KitEqual -Name "Rows: the protocol read back cleanly; Memory-Modules and Memory-PrivateCode rows for every entry (ModuleLoad where the loader's time was sent)" `
        -Expected "True|0|Module:Memory-Modules:16:16:7:9|PrivateCode:Memory-PrivateCode:7:7:0:7" `
        -Actual "$($state.Ended)|$($state.BadLines)|$(@($kinds | ForEach-Object { "$($_.Kind):$($_.Source):$($_.Received):$($_.Rows):$($_.Timed):$($_.Snapshot)" }) -join '|')"
    $rows = @(Get-TestRows -Objects)
    $rowText = @($rows | ForEach-Object { "$($_.Source)|$($_.Timestamp)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)|$($_.Artifact)|$($_.RawPath)" })
    Assert-KitEqual -Name "Rows: a DLL loaded by the loader (ModuleLoad at its load time, the User the token's SID, pipe-style Details)" `
        -Expected "Memory-Modules|2026-10-11 08:00:01.000|ModuleLoad|Module in memory: fixture-app.exe (PID: 4321, Process: fixture-app.exe)|S-1-5-21-1-2-3-1001|PID=4321 | ProcessCreated=2026-10-11 08:00:00.000 | Path=C:\Program Files\Fixture\fixture-app.exe | Base=0x7ff600000000 | Size=0x20000 | LoadReason=StaticDependency | FoundBy=LoaderList,ImageMapping|MemoryDump|C:\dumps\fixture.dmp" `
        -Actual $rowText[0]
    Assert-KitEqual -Name "Rows: an image in no loader list (a Snapshot row, its protection and anomaly)" `
        -Expected "Memory-Modules|2026-10-11 12:30:00.000|Snapshot|Module in memory: fixture-hidden.dll (PID: 4321, Process: fixture-app.exe)|S-1-5-21-1-2-3-1001|PID=4321 | ProcessCreated=2026-10-11 08:00:00.000 | Path=C:\Users\alice\Downloads\fixture-hidden.dll | Base=0x7ff800000000 | Size=0x10000 | FoundBy=ImageMapping | Protection=ExecuteWriteCopy | Anomaly=NotInLoaderLists|MemoryDump|C:\dumps\fixture.dmp" `
        -Actual $rowText[1]
    Assert-KitEqual -Name "Rows: a loader name unlike the mapped file (LoaderPath last), a load time before the process started (Snapshot)" `
        -Expected "PID=4321 | ProcessCreated=2026-10-11 08:00:00.000 | Path=C:\Program Files\Fixture\fixture-other.dll | Base=0x7ffa10000000 | Size=0x10000 | LoadReason=DynamicLoad | FoundBy=LoaderList,ImageMapping | Anomaly=NameMismatch | LoaderPath=C:\Program Files\Fixture\fixture-good.dll|Snapshot" `
        -Actual "$($rows[7].Details)|$($rows[9].EventType)"
    Assert-KitEqual -Name "Rows: executable private memory (Snapshot, its size in the description, a program header's anomaly; a protected process marked)" `
        -Expected ("Memory-PrivateCode|2026-10-11 12:30:00.000|Snapshot|Executable private memory: 64 KB at 0x1000000 (PID: 4321, Process: fixture-app.exe)|S-1-5-21-1-2-3-1001|PID=4321 | ProcessCreated=2026-10-11 08:00:00.000 | Start=0x1000000 | Size=0x10000 | Protection=ExecuteReadWrite | FirstBytes=PE | JitHost=No | Anomaly=PeHeader|MemoryDump|C:\dumps\fixture.dmp" +
            " / Executable private memory: 4 KB at 0x1000000 (PID: 5000, Process: fixture-av.exe)|PID=5000 | ProcessCreated=2026-10-11 08:00:00.000 | Start=0x1000000 | Size=0x1000 | Protection=ExecuteReadWrite | FirstBytes=Data | JitHost=No | ProcessProtected=Yes") `
        -Actual "$($rowText[16]) / $($rows[21].Description)|$($rows[21].Details)"
    $skipped = Add-DbgEngModuleRows -Entries @([PSCustomObject]@{ PID = "1"; Name = "x.dll" }) -Source "Memory-Modules" -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp"
    $skippedPrivate = Add-DbgEngPrivateCodeRows -Entries @([PSCustomObject]@{ PID = "1" }) -Source "Memory-PrivateCode" -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp"
    Assert-KitEqual -Name "Rows: an entry without a Base (module) or Start (region) is not one and adds no row" -Expected "0|0|0" -Actual "$($skipped.Entries)|$($skippedPrivate.Entries)|$(@(Get-TestRows -Keep | Where-Object { $_ -match 'x\.dll|PID=1 ' }).Count)"

    # --- The rows through the real report rules ---------------------------------------------------
    $builderRoot = Split-Path $BuilderPath -Parent
    . (Join-Path $builderRoot "lib\report\TimelineReport.Engine.ps1")
    $rules = Import-ReportRules -Path (Join-Path $builderRoot "lib\report\report-rules.json")
    $findings = @(Invoke-ReportRules -Rows $rows -Rules $rules)
    $ours = @("EXEC-MODULE-USERPATH", "INTEG-MODULE-UNLINKED-USERPATH", "INTEG-MODULE-UNLINKED", "INTEG-MODULE-NAME-MISMATCH", "INTEG-PRIVATE-CODE-PE", "INTEG-PRIVATE-CODE")
    [string[]]$leads = @($findings | Where-Object { $ours -contains $_.RuleId } | ForEach-Object { "$($_.RuleId):$($_.GroupKey):$($_.Severity)" })
    [Array]::Sort($leads, [StringComparer]::Ordinal)
    $others = @($findings | Where-Object { $ours -notcontains $_.RuleId } | ForEach-Object { $_.RuleId })
    Assert-KitEqual -Name "Rules: the rows give these leads (a DLL from Temp or Downloads, the unlinked one from Downloads, unlinked native images elsewhere, the name mismatch, program headers in private memory, private code without a run-time compiler) and no other rule's" `
        -Expected (@(
            "EXEC-MODULE-USERPATH:fixture-hidden.dll:Medium", "EXEC-MODULE-USERPATH:fixture-tmp.dll:Medium",
            "INTEG-MODULE-NAME-MISMATCH:fixture-other.dll:Info",
            "INTEG-MODULE-UNLINKED-USERPATH:fixture-hidden.dll:Medium",
            "INTEG-MODULE-UNLINKED:fixture-d2.dll:Info", "INTEG-MODULE-UNLINKED:fixture-mapped.dll:Info", "INTEG-MODULE-UNLINKED:fixture32-hidden.dll:Info",
            "INTEG-PRIVATE-CODE-PE:fixture-app.exe:High",
            "INTEG-PRIVATE-CODE:fixture-app.exe:Info") -join " / ") `
        -Actual "$($leads -join ' / ')$(if ($others.Count -gt 0) { "| other rules: $($others -join ',')" })"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
