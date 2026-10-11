# =============================================================
# Memory test: network connections (work package WP6, item i)
# The pass over the dump file (lib\memory\TimelineDbgEng.PoolScan.ps1) on
# small synthetic full memory dump files written to %TEMP% (no real dump),
# the Network area (lib\memory\TimelineDbgEng.Network.ps1) on them with
# synthetic kernel memory (tests\MemoryTestKit.ps1), its entries through the
# real protocol into the builder's rows (Add-DbgEngNetRows in
# lib\memory\TimelineMemoryRows.ps1), and those rows through the report
# engine's own Details parser and the network rules
# (lib\report\report-rules.json; the rule that ships switched off is
# switched on in memory for its cases, tests\fixtures\memory\
# net-rules-switched-off.csv). The rules' other cases are in
# tests\fixtures\report\rules\cases-memory-network.csv (Test-ReportRules.ps1).
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryNetwork.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "Test-MemoryNetwork-$PID"

# A 64-bit address from hex (Windows PowerShell reads a hex literal above
# 0x7FFFFFFFFFFFFFFF as a negative number)
function U {
    param([string]$Hex)
    return [Convert]::ToUInt64($Hex, 16)
}

# The sum of two addresses (both [uint64]: PowerShell would make a mix a double)
function Add-U {
    param([uint64]$A, [uint64]$B)
    return [uint64]($A + $B)
}

# A full memory dump file of 64-bit Windows: the header ("PAGEDU64",
# DumpType at +0xF98, the runs at +0x88) and the pages, zero but for
# -Objects (@(@(<offset in the memory part>, <byte[]>), ...)). -Runs:
# @(@(<base page>, <pages>), ...). -RunCount, -Pages: header values that
# differ from the runs; -CutTo: the file's length afterwards.
function New-TestDumpFile {
    param([string]$Path, [object[]]$Runs = @(, @(0x80000, 32)), [uint32]$DumpType = 1, [object[]]$Objects = @(), [string]$Signature = "PAGEDU64",
        [long]$RunCount = -1, [long]$Pages = -1, [long]$CutTo = -1)
    $header = New-Object byte[] 0x2000
    $signatureBytes = [System.Text.Encoding]::ASCII.GetBytes($Signature)
    [Array]::Copy($signatureBytes, 0, $header, 0, $signatureBytes.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0xAA64), 0, $header, 0x30, 4)
    [Array]::Copy([BitConverter]::GetBytes($DumpType), 0, $header, 0xF98, 4)
    $total = [long]0
    for ($i = 0; $i -lt @($Runs).Count; $i++) {
        [Array]::Copy([BitConverter]::GetBytes([uint64]$Runs[$i][0]), 0, $header, 0x98 + $i * 16, 8)
        [Array]::Copy([BitConverter]::GetBytes([uint64]$Runs[$i][1]), 0, $header, 0xA0 + $i * 16, 8)
        $total += [long]$Runs[$i][1]
    }
    $runsValue = if ($RunCount -ge 0) { $RunCount } else { @($Runs).Count }
    $pagesValue = if ($Pages -ge 0) { $Pages } else { $total }
    [Array]::Copy([BitConverter]::GetBytes([uint32]$runsValue), 0, $header, 0x88, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint64]$pagesValue), 0, $header, 0x90, 8)
    $stream = [System.IO.File]::Create($Path)
    try {
        $stream.Write($header, 0, $header.Length)
        $stream.SetLength(0x2000 + $total * 0x1000)
        foreach ($object in @($Objects)) {
            $stream.Position = 0x2000 + [long]$object[0]
            $bytes = [byte[]]$object[1]
            $stream.Write($bytes, 0, $bytes.Length)
        }
        if ($CutTo -ge 0) { $stream.SetLength($CutTo) }
    }
    finally { $stream.Dispose() }
}

# A pool allocation as the pass finds it: the 16-byte pool header (BlockSize
# at +2 as on ARM64, the tag at +4) and the object after it; -U64, -U32,
# -Raw: values at offsets from the object's start
function New-TestPoolObject {
    param([string]$Tag, [int]$BlockBytes, [int]$Size = 0x3F0, [hashtable]$U64 = @{}, [hashtable]$U32 = @{}, [hashtable]$Raw = @{})
    $bytes = New-Object byte[] (16 + $Size)
    $bytes[2] = [byte]($BlockBytes / 16)
    [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes($Tag), 0, $bytes, 4, 4)
    foreach ($key in $U64.Keys) { [Array]::Copy([BitConverter]::GetBytes([uint64]$U64[$key]), 0, $bytes, 16 + [int]$key, 8) }
    foreach ($key in $U32.Keys) { [Array]::Copy([BitConverter]::GetBytes([uint32]$U32[$key]), 0, $bytes, 16 + [int]$key, 4) }
    foreach ($key in $Raw.Keys) { $value = [byte[]]$Raw[$key]; [Array]::Copy($value, 0, $bytes, 16 + [int]$key, $value.Length) }
    return , $bytes
}

# A port as the objects keep it (big-endian)
function ConvertTo-TestPort {
    param([int]$Port)
    return , ([byte[]]@([byte]($Port -shr 8), [byte]($Port -band 0xFF)))
}

function ConvertTo-TestAddress {
    param([string]$Text)
    return , ([System.Net.IPAddress]::Parse($Text).GetAddressBytes())
}

# Kernel memory for the objects' pointers: a fresh 4 KB page each
$script:nextKernelPage = U "FFFFC00000100000"
function New-TestKernelPage {
    $page = $script:nextKernelPage
    $script:nextKernelPage = Add-U $script:nextKernelPage 0x1000
    return $page
}

# An address family object (pool tag InNl, the family at +0x18); -Tag: another tag
function New-TestInetAf {
    param($Memory, [int]$Family, [string]$Tag = "InNl")
    $page = New-TestKernelPage
    $object = Add-U $page 0x10
    $Memory.Write(0, (Add-U $page 4), [System.Text.Encoding]::ASCII.GetBytes($Tag))
    $Memory.WriteU16(0, (Add-U $object 0x18), [uint16]$Family)
    return $object
}

# The address block of a TCP connection: the local address at
# ptr(ptr(ptr(it) + 0x10)), the remote one at ptr(it + 0x10); -NoRemote:
# the remote address's page is not in the dump
function New-TestConnectionAddresses {
    param($Memory, [byte[]]$Local, [byte[]]$Remote, [switch]$NoRemote)
    $x = New-TestKernelPage; $l1 = New-TestKernelPage; $l2 = New-TestKernelPage; $l3 = New-TestKernelPage; $r1 = New-TestKernelPage
    $Memory.WriteU64(0, $x, $l1)
    $Memory.WriteU64(0, (Add-U $l1 0x10), $l2)
    $Memory.WriteU64(0, $l2, $l3)
    $Memory.Write(0, $l3, $Local)
    $Memory.WriteU64(0, (Add-U $x 0x10), $r1)
    if (-not $NoRemote) { $Memory.Write(0, $r1, $Remote) }
    return $x
}

# A listener's local address (bytes at ptr(ptr(it + 0x10))) or a UDP
# endpoint's (bytes at ptr(ptr(it + 0x18)) + 0x18)
function New-TestLocalAddress {
    param($Memory, [byte[]]$Address, [switch]$Udp)
    $p = New-TestKernelPage; $q = New-TestKernelPage; $c = New-TestKernelPage
    if ($Udp) {
        $Memory.WriteU64(0, (Add-U $p 0x18), $q)
        $Memory.WriteU64(0, $q, $c)
        $Memory.Write(0, (Add-U $c 0x18), $Address)
    }
    else {
        $Memory.WriteU64(0, (Add-U $p 0x10), $q)
        $Memory.WriteU64(0, $q, $c)
        $Memory.Write(0, $c, $Address)
    }
    return $p
}

# A process object outside the scan, at the test _EPROCESS layout below
function Add-TestProcessObject {
    param($Memory, [uint64]$Address, [byte]$Type = 3, [long]$ProcessId, [datetime]$Created, $Exited = $null, [string]$Name)
    $Memory.WriteU8(0, $Address, $Type)
    $Memory.WriteU64(0, (Add-U $Address 0x100), [uint64]$ProcessId)
    $Memory.WriteU64(0, (Add-U $Address 0x110), (U "FFFFF80000200000"))
    $Memory.WriteU64(0, (Add-U $Address 0x118), (U "FFFFF80000200000"))
    $Memory.WriteU64(0, (Add-U $Address 0x120), [uint64]$Created.ToFileTimeUtc())
    if ($null -ne $Exited) { $Memory.WriteU64(0, (Add-U $Address 0x128), [uint64]([datetime]$Exited).ToFileTimeUtc()) }
    $Memory.WriteU64(0, (Add-U $Address 0x130), (U "FFFFB00000001007"))
    $Memory.Write(0, (Add-U $Address 0x140), [System.Text.Encoding]::ASCII.GetBytes($Name))
}

# The kernel's types as 'dt' shows them (ARM64's pool header: BlockSize a
# byte of its own at +2) and nt!NtBuildNumber
function Set-TestNetworkSymbols {
    param($Memory, [uint32]$Build = 26100, [switch]$NoPoolHeader)
    $dt = @{
        "_EPROCESS"    = New-TestDtText -Type "_EPROCESS" -Size 0x200 -Fields @(
            @(0, "Pcb", "struct _KPROCESS, 37 elements, 0x100 bytes"), @(0x100, "UniqueProcessId", "Ptr64 to Void"), @(0x108, "InheritedFromUniqueProcessId", "Ptr64 to Void"),
            @(0x110, "ActiveProcessLinks", "struct _LIST_ENTRY, 2 elements, 0x10 bytes"), @(0x120, "CreateTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"),
            @(0x128, "ExitTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"), @(0x130, "Token", "struct _EX_FAST_REF, 3 elements, 0x8 bytes"), @(0x140, "ImageFileName", "[15] UChar"))
        "_EX_FAST_REF" = New-TestDtText -Type "_EX_FAST_REF" -Size 8 -Fields @(@(0, "RefCnt", "Bitfield Pos 0, 4 Bits"))
    }
    if (-not $NoPoolHeader) {
        $dt["_POOL_HEADER"] = New-TestDtText -Type "_POOL_HEADER" -Size 0x10 -Fields @(
            @(0, "PreviousSize", "Bitfield Pos 0, 8 Bits"), @(1, "PoolIndex", "Bitfield Pos 0, 8 Bits"), @(2, "BlockSize", "Bitfield Pos 0, 8 Bits"),
            @(3, "PoolType", "Bitfield Pos 0, 8 Bits"), @(4, "PoolTag", "Uint4B"), @(8, "ProcessBilled", "Ptr64 to struct _EPROCESS"))
    }
    $buildAddress = U "FFFFF80000300000"
    $Memory.WriteU32(0, $buildAddress, [uint32]([Convert]::ToUInt32("F0000000", 16) + $Build))
    Set-TestEngineCommands -Dt $dt -Symbols @{ "nt!NtBuildNumber" = $buildAddress }
}

# An entry's fields as "Key=value;Key=value" in their order
function Get-TestEntryText {
    param($Entry)
    $fields = Get-TestEntryFields -Entry $Entry
    return ((@($fields.Keys | Where-Object { $_ -ne "Kind" }) | ForEach-Object { "$_=$($fields[$_])" }) -join ";")
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryNetwork"
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $t0 = [datetime]::new(2026, 5, 17, 8, 0, 0, [DateTimeKind]::Utc)
    $iso = { param([datetime]$t) $t.ToString("yyyy-MM-ddTHH:mm:ss.fffffff+00:00", [System.Globalization.CultureInfo]::InvariantCulture) }

    # --- 1. The dump file's layout ---------------------------------------------------
    $readHeader = {
        param([string]$Path)
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $header = New-Object byte[] 0x2000
        [Array]::Copy($bytes, $header, [Math]::Min(0x2000, $bytes.Length))
        return [TimelineDbgEng.DumpFileLayout]::FromHeader($header, $bytes.Length)
    }
    $layoutFile = Join-Path $tempRoot "layout.dmp"
    New-TestDumpFile -Path $layoutFile -Runs @(@(0x100, 4), @(0x800, 4))
    $d = & $readHeader $layoutFile
    Assert-KitEqual -Name "a full dump's runs: their pages, file offsets and size" -Expected "|1|2|0x2000,0x6000|0x8000|0x8000" -Actual "$($d.Problem)|$($d.DumpType)|$($d.RunBase.Length)|$(($d.RunFile | ForEach-Object { '0x' + $_.ToString('x') }) -join ',')|0x$($d.MemoryBytes.ToString('x'))|0x$($d.FileBytes.ToString('x'))"
    Assert-KitEqual -Name "a file offset's physical address and where its run ends" -Expected "0x101abc|0x6000|0x800000|0xa000|$([uint64]::MaxValue)" -Actual ("0x" + $d.PhysicalOf(0x3abc).ToString("x") + "|0x" + $d.RunEnd(0x3abc).ToString("x") + "|0x" + $d.PhysicalOf(0x6000).ToString("x") + "|0x" + $d.RunEnd(0x6000).ToString("x") + "|" + $d.PhysicalOf(0xa000))
    New-TestDumpFile -Path $layoutFile -Runs @(@(0x100, 4), @(0x800, 4)) -CutTo (0x2000 + 0x5800)
    $d = & $readHeader $layoutFile
    Assert-KitEqual -Name "a file cut short: only its whole pages count" -Expected "|0x5000|0x7000" -Actual "$($d.Problem)|0x$($d.FileBytes.ToString('x'))|0x$($d.RunEnd(0x6000).ToString('x'))"
    $problems = @()
    New-TestDumpFile -Path $layoutFile -DumpType 5; $problems += (& $readHeader $layoutFile).Problem
    New-TestDumpFile -Path $layoutFile -Signature "PAGEDUMP"; $problems += (& $readHeader $layoutFile).Problem
    New-TestDumpFile -Path $layoutFile -Pages 33; $problems += (& $readHeader $layoutFile).Problem
    New-TestDumpFile -Path $layoutFile -RunCount 43; $problems += (& $readHeader $layoutFile).Problem
    New-TestDumpFile -Path $layoutFile -Runs @(, @(0x100, 0)); $problems += (& $readHeader $layoutFile).Problem
    Assert-KitEqual -Name "dumps the pass does not read, and why" -Expected ("the dump file is not a full memory dump [dump type 5]|the dump file is not a crash dump of 64-bit Windows|" +
        "the dump file's physical memory runs do not add up|the dump file's list of physical memory runs cannot be read|the dump file's list of physical memory runs cannot be read") -Actual ($problems -join "|")

    # --- 2. The pass over the dump file -------------------------------------------------
    $memory = New-TestMemory
    Set-TestNetworkSymbols -Memory $memory
    $passFile = Join-Path $tempRoot "pass.dmp"
    $marker = New-TestPoolObject -Tag "TTcb" -BlockBytes 0x500 -Raw @{ 0x1F0 = [byte[]](0xAB, 0xCD) }
    $udpAtRunEnd = New-TestPoolObject -Tag "UdpA" -BlockBytes 0x1A0 -Size 0xF0
    $service = New-Object byte[] 16
    [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("Sc19"), 0, $service, 8, 4)
    $nearMiss = New-TestPoolObject -Tag "TTcX" -BlockBytes 0x500 -Size 0x10
    New-TestDumpFile -Path $passFile -Runs @(@(0x100, 4), @(0x800, 4)) -Objects @(
        @(0x1200, $marker), @(0x3F00, $udpAtRunEnd), @(0x4040, $service), @(0x4080, $nearMiss))
    $context = New-TestContext -Memory $memory -DumpPath $passFile
    Start-DbgEngRawPass -Context $context
    $pass = $context.RawPass
    $ended = $pass.Wait(30000)
    $tcb = @($pass.HitsOf("TTcb"))
    $udp = @($pass.HitsOf("UdpA"))
    $svc = @($pass.HitsOf("Sc19"))
    Assert-KitEqual -Name "the pass reads the whole file and finds each tag at its offset in the unit (Sc19 at +8; a near miss is no hit)" -Expected "True|Done|0x8000|1|1|1|0|0" -Actual "$ended|$($pass.State)|0x$($pass.ScannedBytes.ToString('x'))|$($tcb.Count)|$($udp.Count)|$($svc.Count)|$(@($pass.HitsOf('TcpL')).Count)|$(@($pass.HitsOf('TTcX')).Count)"
    Assert-KitEqual -Name "a hit's physical address, page offset and copy (0x400 bytes)" -Expected "0x101200|0x200|1024|0xab" -Actual ("0x" + $tcb[0].Physical.ToString("x") + "|0x" + $tcb[0].PageOffset.ToString("x") + "|" + $tcb[0].Bytes.Length + "|0x" + $tcb[0].Bytes[0x200].ToString("x"))
    Assert-KitEqual -Name "a copy stops at the end of its run of physically adjacent pages" -Expected "0x103f00|256|0x800040" -Actual ("0x" + $udp[0].Physical.ToString("x") + "|" + $udp[0].Bytes.Length + "|0x" + $svc[0].Physical.ToString("x"))
    $pass.Dispose()
    Assert-KitEqual -Name "a pass that has ended can be disposed (twice)" -Expected "Done|True" -Actual "$($pass.State)|$(try { $pass.Dispose(); $true } catch { $false })"

    # A hit whose copy runs past the 16 MB the pass reads at a time
    $bigFile = Join-Path $tempRoot "big.dmp"
    $edge = 16MB - 0x100
    New-TestDumpFile -Path $bigFile -Runs @(, @(0x10000, 4098)) -Objects @(, @($edge, (New-TestPoolObject -Tag "TcpL" -BlockBytes 0x160 -Raw @{ 0x1F0 = [byte[]](0x5A) })))
    $big = New-Object TimelineDbgEng.RawPass -ArgumentList $bigFile, 300.0
    $big.AddTag("TcpL", 4, 0x400)
    $big.Start()
    [void]$big.Wait(60000)
    $edgeHits = @($big.HitsOf("TcpL"))
    Assert-KitEqual -Name "a copy across the pass's 16 MB reads is read afterwards, whole" -Expected "Done|1|1024|0x5a" -Actual "$($big.State)|$($edgeHits.Count)|$($edgeHits[0].Bytes.Length)|0x$($edgeHits[0].Bytes[0x200].ToString('x'))"
    $big.Dispose()

    # At most MaxHitsPerTag hits of a tag are kept
    $manyFile = Join-Path $tempRoot "many.dmp"
    $many = New-Object byte[] (([TimelineDbgEng.RawPass]::MaxHitsPerTag + 1) * 16)
    for ($i = 0; $i -le [TimelineDbgEng.RawPass]::MaxHitsPerTag; $i++) { [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("AfdE"), 0, $many, $i * 16 + 4, 4) }
    New-TestDumpFile -Path $manyFile -Runs @(, @(0x100, 40)) -Objects @(, @(0, $many))
    $manyPass = New-Object TimelineDbgEng.RawPass -ArgumentList $manyFile, 300.0
    $manyPass.AddTag("AfdE", 4, 0x40)
    $manyPass.Start()
    [void]$manyPass.Wait(30000)
    Assert-KitEqual -Name "the hits past the cap of a tag are counted, not kept" -Expected "$([TimelineDbgEng.RawPass]::MaxHitsPerTag)|1" -Actual "$(@($manyPass.HitsOf('AfdE')).Count)|$($manyPass.DroppedOf('AfdE'))"
    $manyPass.Dispose()

    # Its time limit, and passes that cannot start
    $limited = New-Object TimelineDbgEng.RawPass -ArgumentList $passFile, 0.0000001
    $limited.AddTag("TTcb", 4, 0x400)
    $limited.Start()
    [void]$limited.Wait(30000)
    Assert-KitEqual -Name "a pass past its time limit stops (TimeLimit), with the hits of what it read" -Expected "TimeLimit|0" -Actual "$($limited.State)|$($limited.ScannedBytes)"
    $limited.Dispose()
    $missing = New-TestContext -Memory $memory -DumpPath (Join-Path $tempRoot "no-such.dmp")
    Start-DbgEngRawPass -Context $missing
    $notFull = Join-Path $tempRoot "kernel.dmp"
    New-TestDumpFile -Path $notFull -DumpType 6
    $kernelDump = New-TestContext -Memory $memory -DumpPath $notFull
    Start-DbgEngRawPass -Context $kernelDump
    Set-TestNetworkSymbols -Memory $memory -NoPoolHeader
    $noPool = New-TestContext -Memory $memory -DumpPath $passFile
    Start-DbgEngRawPass -Context $noPool
    Assert-KitEqual -Name "passes that cannot start are NotRead and say why" -Expected ("NotRead|the dump file is not there to be read|NotRead|the dump file is not a full memory dump [dump type 6]|" +
        "NotRead|the kernel's symbols do not describe its pool header as expected") -Actual "$($missing.RawPass.State)|$($missing.RawPass.Why)|$($kernelDump.RawPass.State)|$($kernelDump.RawPass.Why)|$($noPool.RawPass.State)|$($noPool.RawPass.Why)"
    $areas = @(
        (Invoke-TestArea -Name "Network" -Context $missing -CapSeconds 300),
        (Invoke-TestArea -Name "Network" -Context $kernelDump -CapSeconds 300),
        (Invoke-TestArea -Name "Network" -Context $noPool -CapSeconds 300),
        (Invoke-TestArea -Name "Network" -Context (New-TestContext -Memory $memory -DumpPath $passFile) -CapSeconds 300))
    Assert-KitEqual -Name "the Network area is not read when the pass is not, with its reason" -Expected ("NotRead|the dump file is not there to be read|0;NotRead|the dump file is not a full memory dump [dump type 6]|0;" +
        "NotRead|the kernel's symbols do not describe its pool header as expected|0;NotRead|the pass over the dump file was not started|0") -Actual ((@($areas | ForEach-Object { "$($_.State)|$($_.Note)|$($_.Entries.Count)" })) -join ";")

    # --- 3. The Network area on a synthetic dump --------------------------------------------
    $memory = New-TestMemory
    Set-TestNetworkSymbols -Memory $memory
    $capture = $t0.AddHours(3)
    $p1 = U "FFFFA00000010000"; $p2 = U "FFFFA00000020000"; $p3 = U "FFFFA00000030000"; $p4 = U "FFFFA00000040000"
    $u1 = U "FFFFA00000050000"; $u2 = U "FFFFA00000060000"; $u3 = U "FFFFA00000070000"
    Add-TestProcessObject -Memory $memory -Address $u1 -ProcessId 7600 -Created $t0 -Name "fixture-unlist"
    Add-TestProcessObject -Memory $memory -Address $u2 -ProcessId 7604 -Created $t0 -Exited $t0.AddHours(1) -Name "fixture-gone"
    Add-TestProcessObject -Memory $memory -Address $u3 -Type 6 -ProcessId 7608 -Created $t0 -Name "fixture-thread"
    $processes = @(
        @{ Eprocess = $p1; Pid = 4321; Ppid = 4000; CreateTime = $t0; ShortName = "fixture-net.ex"; FullName = "fixture-net.exe"; ImagePath = "C:\Users\Public\Fixture Tools\fixture-net.exe"; UserSid = "S-1-5-21-1-2-3-1001" }
        @{ Eprocess = $p2; Pid = 7300; Ppid = 4000; CreateTime = $t0; ShortName = "fixture-hidden"; Anomaly = "NotInProcessList" }
        @{ Eprocess = $p3; Pid = 7400; Ppid = 4000; CreateTime = $t0; ExitTime = $t0.AddHours(1); ShortName = "fixture-exit" }
        @{ Eprocess = $p4; Pid = 7500; Ppid = 4000; CreateTime = $t0.AddHours(2); ShortName = "fixture-later" }
    )
    $v4 = New-TestInetAf -Memory $memory -Family 2
    $v6 = New-TestInetAf -Memory $memory -Family 23
    $notAf = New-TestInetAf -Memory $memory -Family 2 -Tag "Xxxx"
    $tcbFields = {
        param([uint64]$Af, [uint64]$Addresses, [uint32]$State, [int]$LocalPort, [int]$RemotePort, [uint64]$Owner, [datetime]$Created)
        return @{ U64 = @{ 0x18 = $Af; 0x20 = $Addresses; 0x350 = $Owner; 0x360 = [uint64]$Created.ToFileTimeUtc() }; U32 = @{ 0x70 = $State }; Raw = @{ 0x74 = (ConvertTo-TestPort $LocalPort); 0x76 = (ConvertTo-TestPort $RemotePort) } }
    }
    $newTcb = {
        param([hashtable]$Fields, [int]$BlockBytes = 0x500)
        return , (New-TestPoolObject -Tag "TTcb" -BlockBytes $BlockBytes -U64 $Fields.U64 -U32 $Fields.U32 -Raw $Fields.Raw)
    }
    $here = ConvertTo-TestAddress "192.168.56.10"
    $objects = New-Object System.Collections.Generic.List[object]
    # 0: a live connection to a public address
    $objects.Add(@(0x0100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "8.8.4.4")) 4 50123 443 $p1 $t0.AddMinutes(10)))))
    # 1: closed
    $objects.Add(@(0x1100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "8.8.4.4")) 0 50124 443 $p1 $t0.AddMinutes(11)))))
    # 2: owned by a listed process that is hidden from the process list
    $objects.Add(@(0x2100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "10.0.0.5")) 4 50125 8443 $p2 $t0.AddMinutes(12)))))
    # 3: owned by a process object no way of the scan found (IPv6)
    $objects.Add(@(0x3100, (& $newTcb (& $tcbFields $v6 (New-TestConnectionAddresses -Memory $memory -Local (ConvertTo-TestAddress "fe80::1") -Remote (ConvertTo-TestAddress "2606:4700:4700::1111")) 4 50126 443 $u1 $t0.AddMinutes(13)))))
    # 4: owned by such a process that has exited
    $objects.Add(@(0x4100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "8.8.4.4")) 4 50127 443 $u2 $t0.AddMinutes(14)))))
    # 5: owned by memory that is not a process (a thread object)
    $objects.Add(@(0x5100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "8.8.4.4")) 4 50128 443 $u3 $t0.AddMinutes(15)))))
    # 6: made before its owner started (the owner's memory is a later process's)
    $objects.Add(@(0x6100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "8.8.4.4")) 4 50129 443 $p4 $t0.AddHours(1)))))
    # 7: owned by a listed process that has exited
    $objects.Add(@(0x7100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote (ConvertTo-TestAddress "169.254.1.1")) 7 50130 443 $p3 $t0.AddMinutes(16)))))
    # 8: no known TCP state; 9: no address family object; 10: another size; 11: across a page boundary
    $objects.Add(@(0x8100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote $here) 10 50131 443 $p1 $t0.AddMinutes(17)))))
    $objects.Add(@(0x9100, (& $newTcb (& $tcbFields $notAf (New-TestConnectionAddresses -Memory $memory -Local $here -Remote $here) 4 50132 443 $p1 $t0.AddMinutes(18)))))
    $objects.Add(@(0xA100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote $here) 4 50133 443 $p1 $t0.AddMinutes(19)) 0x330)))
    $objects.Add(@(0xBD00, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote $here) 4 50134 443 $p1 $t0.AddMinutes(20)))))
    # 12: its remote address is not in the dump
    $objects.Add(@(0xC100, (& $newTcb (& $tcbFields $v4 (New-TestConnectionAddresses -Memory $memory -Local $here -Remote $here -NoRemote) 4 50135 443 $p1 $t0.AddMinutes(21)))))
    # Listeners: on every address (IPv4), on ::1
    $objects.Add(@(0xD100, (New-TestPoolObject -Tag "TcpL" -BlockBytes 0x160 -Size 0x150 -U64 @{ 0x30 = $v4; 0x38 = $p1; 0x48 = [uint64]$t0.AddMinutes(1).ToFileTimeUtc() } -Raw @{ 0x7A = (ConvertTo-TestPort 445) })))
    $objects.Add(@(0xE100, (New-TestPoolObject -Tag "TcpL" -BlockBytes 0x160 -Size 0x150 -U64 @{ 0x30 = $v6; 0x38 = $p1; 0x48 = [uint64]$t0.AddMinutes(2).ToFileTimeUtc(); 0x68 = (New-TestLocalAddress -Memory $memory -Address (ConvertTo-TestAddress "::1")) } -Raw @{ 0x7A = (ConvertTo-TestPort 8080) })))
    # UDP endpoints: on 127.0.0.1, on every address (IPv6)
    $objects.Add(@(0xF100, (New-TestPoolObject -Tag "UdpA" -BlockBytes 0x1A0 -Size 0x190 -U64 @{ 0x28 = $v4; 0x30 = $p1; 0x60 = [uint64]$t0.AddMinutes(3).ToFileTimeUtc(); 0xB0 = (New-TestLocalAddress -Memory $memory -Address (ConvertTo-TestAddress "127.0.0.1") -Udp) } -Raw @{ 0xA8 = (ConvertTo-TestPort 5353) })))
    $objects.Add(@(0x10100, (New-TestPoolObject -Tag "UdpA" -BlockBytes 0x1A0 -Size 0x190 -U64 @{ 0x28 = $v6; 0x30 = $p1; 0x60 = [uint64]$t0.AddMinutes(4).ToFileTimeUtc() } -Raw @{ 0xA8 = (ConvertTo-TestPort 5355) })))
    # Counted only: two connections in TIME_WAIT, three sockets (two of a listed process)
    $objects.Add(@(0x11100, (New-TestPoolObject -Tag "TcTW" -BlockBytes 0xC0 -Size 0xB0)))
    $objects.Add(@(0x11200, (New-TestPoolObject -Tag "TcTW" -BlockBytes 0xC0 -Size 0xB0)))
    $objects.Add(@(0x11300, (New-TestPoolObject -Tag "AfdE" -BlockBytes 0x200 -Size 0x70 -U64 @{ 0x30 = $p1 })))
    $objects.Add(@(0x11400, (New-TestPoolObject -Tag "AfdE" -BlockBytes 0x200 -Size 0x70 -U64 @{ 0x30 = $p1 })))
    $objects.Add(@(0x11500, (New-TestPoolObject -Tag "AfdE" -BlockBytes 0x200 -Size 0x70 -U64 @{ 0x30 = $u3 })))
    $netFile = Join-Path $tempRoot "net.dmp"
    New-TestDumpFile -Path $netFile -Runs @(, @(0x80000, 32)) -Objects $objects.ToArray()
    $context = New-TestContext -Memory $memory -Processes $processes -DumpPath $netFile -CaptureFileTime $capture.ToFileTimeUtc()
    Start-DbgEngRawPass -Context $context
    [void](Get-TestProtocolLines)
    $area = Invoke-TestArea -Name "Network" -Context $context -CapSeconds 300
    $context.RawPass.Dispose()
    $byOffset = @{}
    foreach ($entry in $area.Entries) { $byOffset[$entry.Get("Offset")] = Get-TestEntryText $entry }
    Assert-KitEqual -Name "the Network area: read, its entries and its note" -Expected "Read|13|2 connections in TIME_WAIT were found but are not listed, as their local addresses are not read; 1 network object lies across a page boundary and is not read" -Actual "$($area.State)|$($area.Entries.Count)|$($area.Note)"
    Assert-KitEqual -Name "the area's counts for the log" -Expected ("TCP connections 9, TCP listeners 2, UDP endpoints 2, Stale=Yes 5, OwnerHidden 2, owners found only through the network object 2, owner exited 2, " +
        "owner memory not a process 1, owner memory of a later process 1, connections in no known state 1, objects without an address family 1, other objects with these tags 1, objects across a page boundary 1, " +
        "addresses not readable 1, TIME_WAIT connections counted 2, sockets counted 3, sockets of listed processes 2") -Actual $area.Coverage.CountsText
    $userPath = "C:\Users\Public\Fixture Tools\fixture-net.exe"
    $expected = [ordered]@{
        "0x80000110" = "Offset=0x80000110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50123;ForeignAddr=8.8.4.4;ForeignPort=443;State=ESTABLISHED;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(10));PoolTag=TTcb;Stale=No;RemoteScope=Public;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
        "0x80001110" = "Offset=0x80001110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50124;ForeignAddr=8.8.4.4;ForeignPort=443;State=CLOSED;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(11));PoolTag=TTcb;Stale=Yes;RemoteScope=Public;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
        "0x80002110" = "Offset=0x80002110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50125;ForeignAddr=10.0.0.5;ForeignPort=8443;State=ESTABLISHED;PID=7300;Owner=fixture-hidden;Created=$(& $iso $t0.AddMinutes(12));PoolTag=TTcb;Stale=No;RemoteScope=Private;OwnerCreated=2026-05-17 08:00:00.000;Anomaly=OwnerHidden"
        "0x80003110" = "Offset=0x80003110;Proto=TCPv6;LocalAddr=fe80::1;LocalPort=50126;ForeignAddr=2606:4700:4700::1111;ForeignPort=443;State=ESTABLISHED;PID=7600;Owner=fixture-unlist;Created=$(& $iso $t0.AddMinutes(13));PoolTag=TTcb;Stale=No;RemoteScope=Public;OwnerCreated=2026-05-17 08:00:00.000;Anomaly=OwnerHidden"
        "0x80004110" = "Offset=0x80004110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50127;ForeignAddr=8.8.4.4;ForeignPort=443;State=ESTABLISHED;PID=7604;Owner=fixture-gone;Created=$(& $iso $t0.AddMinutes(14));PoolTag=TTcb;Stale=Yes;RemoteScope=Public;OwnerCreated=2026-05-17 08:00:00.000"
        "0x80005110" = "Offset=0x80005110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50128;ForeignAddr=8.8.4.4;ForeignPort=443;State=ESTABLISHED;Created=$(& $iso $t0.AddMinutes(15));PoolTag=TTcb;Stale=Yes;RemoteScope=Public"
        "0x80006110" = "Offset=0x80006110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50129;ForeignAddr=8.8.4.4;ForeignPort=443;State=ESTABLISHED;Created=$(& $iso $t0.AddHours(1));PoolTag=TTcb;Stale=Yes;RemoteScope=Public"
        "0x80007110" = "Offset=0x80007110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50130;ForeignAddr=169.254.1.1;ForeignPort=443;State=CLOSE_WAIT;PID=7400;Owner=fixture-exit;Created=$(& $iso $t0.AddMinutes(16));PoolTag=TTcb;Stale=Yes;RemoteScope=LinkLocal;OwnerCreated=2026-05-17 08:00:00.000"
        "0x8000c110" = "Offset=0x8000c110;Proto=TCPv4;LocalAddr=192.168.56.10;LocalPort=50135;ForeignAddr=?;ForeignPort=443;State=ESTABLISHED;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(21));PoolTag=TTcb;Stale=No;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
        "0x8000d110" = "Offset=0x8000d110;Proto=TCPv4;LocalAddr=0.0.0.0;LocalPort=445;ForeignAddr=0.0.0.0;ForeignPort=0;State=LISTENING;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(1));PoolTag=TcpL;Stale=No;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
        "0x8000e110" = "Offset=0x8000e110;Proto=TCPv6;LocalAddr=::1;LocalPort=8080;ForeignAddr=::;ForeignPort=0;State=LISTENING;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(2));PoolTag=TcpL;Stale=No;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
        "0x8000f110" = "Offset=0x8000f110;Proto=UDPv4;LocalAddr=127.0.0.1;LocalPort=5353;ForeignAddr=*;ForeignPort=0;State=;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(3));PoolTag=UdpA;Stale=No;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
        "0x80010110" = "Offset=0x80010110;Proto=UDPv6;LocalAddr=::;LocalPort=5355;ForeignAddr=*;ForeignPort=0;State=;PID=4321;Owner=fixture-net.exe;Created=$(& $iso $t0.AddMinutes(4));PoolTag=UdpA;Stale=No;OwnerCreated=2026-05-17 08:00:00.000;OwnerPath=$userPath;OwnerSid=S-1-5-21-1-2-3-1001"
    }
    $labels = @("a live connection to a public address", "a closed connection: Stale=Yes", "a hidden listed owner: OwnerHidden", "an owner found only through the connection (IPv6): OwnerHidden",
        "an owner outside the scan that has exited: Stale=Yes", "owner memory that is not a process: Stale=Yes, no PID", "made before its owner started: Stale=Yes, no PID",
        "a listed owner that has exited: Stale=Yes", "a remote address not in the dump: ?", "a listener on every address", "an IPv6 listener on ::1", "a UDP endpoint on 127.0.0.1", "a UDP endpoint on every IPv6 address")
    $i = 0
    foreach ($offset in $expected.Keys) {
        Assert-KitEqual -Name "entry: $($labels[$i])" -Expected $expected[$offset] -Actual "$($byOffset[$offset])"
        $i++
    }
    $logLines = @(Get-TestProtocolLines | Where-Object { $_.StartsWith("TBDBG|LOG|") } | ForEach-Object { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.Split('|')[3])) })
    Assert-KitEqual -Name "the log line of the pass" -Expected 1 -Actual @($logLines | Where-Object { $_ -match '^    The pass over the dump file: 0\.0 GB in \d+\.\d s \(the whole file\), Windows build 26100$' }).Count

    # The address scopes
    $scopes = @("8.8.8.8", "10.1.2.3", "172.16.0.1", "172.32.0.1", "192.168.1.1", "100.64.0.1", "127.0.0.1", "169.254.9.9", "0.0.0.0", "224.0.0.251", "255.255.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1",
        "::1", "::", "fe80::1", "fd00::1", "ff02::1", "2001:db8::1", "2606:4700::1", "::ffff:10.0.0.1", "::ffff:8.8.8.8") | ForEach-Object {
        $bytes = ConvertTo-TestAddress $_
        [TimelineDbgEng.NetAddress]::Scope($bytes, $(if ($bytes.Length -eq 16) { 23 } else { 2 }))
    }
    Assert-KitEqual -Name "remote address scopes" -Expected "Public,Private,Private,Public,Private,Private,Loopback,LinkLocal,Other,Other,Other,Other,Other,Other,Loopback,Other,LinkLocal,Private,Other,Other,Public,Private,Public" -Actual ($scopes -join ",")

    # --- 4. The self-checks, and builds the table does not know ------------------------------------
    $bad = New-Object System.Collections.Generic.List[object]
    for ($k = 0; $k -lt 4; $k++) { $bad.Add(@((0x100 + $k * 0x1000), (& $newTcb (& $tcbFields $notAf (New-TestConnectionAddresses -Memory $memory -Local $here -Remote $here) 4 50200 443 $p1 $t0.AddMinutes(30))))) }
    $badFile = Join-Path $tempRoot "bad.dmp"
    New-TestDumpFile -Path $badFile -Runs @(, @(0x90000, 8)) -Objects $bad.ToArray()
    $badContext = New-TestContext -Memory $memory -Processes $processes -DumpPath $badFile -CaptureFileTime $capture.ToFileTimeUtc()
    Start-DbgEngRawPass -Context $badContext
    $badArea = Invoke-TestArea -Name "Network" -Context $badContext -CapSeconds 300
    $badContext.RawPass.Dispose()
    $bad.Add(@(0x4100, (New-TestPoolObject -Tag "TcpL" -BlockBytes 0x160 -Size 0x150 -U64 @{ 0x30 = $v4; 0x38 = $p1; 0x48 = [uint64]$t0.AddMinutes(1).ToFileTimeUtc() } -Raw @{ 0x7A = (ConvertTo-TestPort 445) })))
    New-TestDumpFile -Path $badFile -Runs @(, @(0x90000, 8)) -Objects $bad.ToArray()
    $partContext = New-TestContext -Memory $memory -Processes $processes -DumpPath $badFile -CaptureFileTime $capture.ToFileTimeUtc()
    Start-DbgEngRawPass -Context $partContext
    $partArea = Invoke-TestArea -Name "Network" -Context $partContext -CapSeconds 300
    $partContext.RawPass.Dispose()
    Assert-KitEqual -Name "objects that fail the self-checks are not listed: not read when no kind passes, partly read when another kind does" -Expected ("NotRead|the network objects in this dump do not have the layout this builder knows for Windows build 26100|0;" +
        "Partial|the TCP connections in this dump do not have the layout this builder knows for Windows build 26100, so they are not listed|1") -Actual "$($badArea.State)|$($badArea.Note)|$($badArea.Entries.Count);$($partArea.State)|$($partArea.Note)|$($partArea.Entries.Count)"
    Set-TestNetworkSymbols -Memory $memory -Build 22621
    $oldContext = New-TestContext -Memory $memory -Processes $processes -DumpPath $netFile -CaptureFileTime $capture.ToFileTimeUtc()
    Start-DbgEngRawPass -Context $oldContext
    $oldArea = Invoke-TestArea -Name "Network" -Context $oldContext -CapSeconds 300
    $oldContext.RawPass.Dispose()
    Assert-KitEqual -Name "a Windows build the table does not know: not read" -Expected "NotRead|the network objects of Windows build 22621 are not known to this builder|0" -Actual "$($oldArea.State)|$($oldArea.Note)|$($oldArea.Entries.Count)"
    Set-TestNetworkSymbols -Memory $memory
    $limitContext = New-TestContext -Memory $memory -Processes $processes -DumpPath $netFile -CaptureFileTime $capture.ToFileTimeUtc()
    $limitContext.RawPass = New-Object TimelineDbgEng.RawPass -ArgumentList $netFile, 0.0000001
    $limitContext.RawPass.PoolLayout = New-DbgEngLayout -Session $null -Spec (Get-DbgEngPoolHeaderSpec)
    $limitContext.RawPass.AddTag("TTcb", 4, 0x400)
    $limitContext.RawPass.Start()
    $limitArea = Invoke-TestArea -Name "Network" -Context $limitContext -CapSeconds 300
    $limitContext.RawPass.Dispose()
    Assert-KitEqual -Name "a pass stopped at its time limit: partly read, and the note says how far" -Expected "Partial|the pass over the dump file stopped at its time limit of 0 s after 0% of it, so connections in the rest are not listed" -Actual "$($limitArea.State)|$($limitArea.Note)"

    # --- 5. Through the protocol into the builder's rows ---------------------------------------------
    $state = New-DbgEngWorkerState
    foreach ($entry in $area.Entries) { Receive-DbgEngWorkerLine -Line $entry.ToLine() -State $state }
    $netEntries = ConvertTo-DbgEngEntryArray $state.Entries["Net"]
    [void](Get-TestRows)
    $acquisitionEnd = $capture.AddMinutes(5)
    $counts = Add-DbgEngNetRows -Entries $netEntries -Source "Memory-Network" -CaptureTimeUtc $capture -AcquisitionEndUtc $acquisitionEnd -DumpPath "C:\dumps\fixture.dmp"
    $rows = @(Get-TestRows -Objects)
    Assert-KitEqual -Name "Add-DbgEngNetRows: one row per entry, each at its own create time" -Expected "0|13|13|0|13" -Actual "$($state.BadLines)|$($counts.Entries)|$($counts.Timed)|$($counts.Snapshot)|$($rows.Count)"
    $row = $rows[0]
    Assert-KitEqual -Name "a connection's row: the Volatility netscan shape with the ARM64 fields appended" -Expected ("Memory-Network|2026-05-17 08:10:00.000|NetworkConnection|Memory network: TCPv4 192.168.56.10:50123 -> 8.8.4.4:443 (ESTABLISHED)|S-1-5-21-1-2-3-1001|" +
        "PID=4321 Process=fixture-net.exe FoundBy=PoolScan PoolTag=TTcb Stale=No RemoteScope=Public OwnerCreated=2026-05-17 08:00:00.000 OwnerPath=$userPath|MemoryDump|C:\dumps\fixture.dmp") -Actual "$($row.Source)|$($row.Timestamp)|$($row.EventType)|$($row.Description)|$($row.User)|$($row.Details)|$($row.Artifact)|$($row.RawPath)"
    $byDescription = @{}
    foreach ($r in $rows) { $byDescription[$r.Description] = $r }
    $checks = [ordered]@{
        "Memory network: TCPv4 192.168.56.10:50125 -> 10.0.0.5:8443 (ESTABLISHED)"         = "|PID=7300 Process=fixture-hidden FoundBy=PoolScan PoolTag=TTcb Stale=No RemoteScope=Private OwnerCreated=2026-05-17 08:00:00.000 Anomaly=OwnerHidden"
        "Memory network: TCPv4 192.168.56.10:50128 -> 8.8.4.4:443 (ESTABLISHED)"           = "|PID= FoundBy=PoolScan PoolTag=TTcb Stale=Yes RemoteScope=Public"
        "Memory network: TCPv4 0.0.0.0:445 -> 0.0.0.0:0 (LISTENING)"                      = "S-1-5-21-1-2-3-1001|PID=4321 Process=fixture-net.exe FoundBy=PoolScan PoolTag=TcpL Stale=No OwnerCreated=2026-05-17 08:00:00.000 OwnerPath=$userPath"
        "Memory network: UDPv4 127.0.0.1:5353 -> *:0 ()"                                   = "S-1-5-21-1-2-3-1001|PID=4321 Process=fixture-net.exe FoundBy=PoolScan PoolTag=UdpA Stale=No OwnerCreated=2026-05-17 08:00:00.000 OwnerPath=$userPath"
    }
    foreach ($description in $checks.Keys) {
        $r = $byDescription[$description]
        Assert-KitEqual -Name "row: $description" -Expected $checks[$description] -Actual "$($r.User)|$($r.Details)"
    }
    # A time that is not valid: a Snapshot row at the capture time, the
    # time kept in Details before the ARM64 fields
    $odd = @(
        [PSCustomObject]@{ Proto = "TCPv4"; LocalAddr = "10.0.0.1"; LocalPort = "1"; ForeignAddr = "10.0.0.2"; ForeignPort = "2"; State = "ESTABLISHED"; PID = "4"; Owner = "System"; Created = "2099-01-01T00:00:00.0000000+00:00"; PoolTag = "TTcb"; Stale = "No"; RemoteScope = "Private" }
        [PSCustomObject]@{ Proto = "UDPv4"; LocalAddr = "0.0.0.0"; LocalPort = "3"; ForeignAddr = "*"; ForeignPort = "0"; State = ""; PID = "4"; Owner = "System"; Created = ""; PoolTag = "UdpA"; Stale = "No" }
    )
    $oddCounts = Add-DbgEngNetRows -Entries $odd -Source "Memory-Network" -CaptureTimeUtc $capture -AcquisitionEndUtc $acquisitionEnd -DumpPath "C:\dumps\fixture.dmp"
    $oddRows = @(Get-TestRows)
    Assert-KitEqual -Name "entries without a valid time: Snapshot rows at the capture time" -Expected ("0|2|Memory-Network|2026-05-17 11:00:00.000|Snapshot|Memory network: TCPv4 10.0.0.1:1 -> 10.0.0.2:2 (ESTABLISHED)||PID=4 Process=System Created=2099-01-01 00:00:00.000 FoundBy=PoolScan PoolTag=TTcb Stale=No RemoteScope=Private;" +
        "Memory-Network|2026-05-17 11:00:00.000|Snapshot|Memory network: UDPv4 0.0.0.0:3 -> *:0 ()||PID=4 Process=System FoundBy=PoolScan PoolTag=UdpA Stale=No") -Actual "$($oddCounts.Timed)|$($oddCounts.Snapshot)|$($oddRows -join ';')"

    # --- 6. The report engine on these rows: its Details parser and the network rules ------------------
    . (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\TimelineReport.Engine.ps1")
    $details = $row.Details
    Assert-KitEqual -Name "the report engine reads the owner's PID, name, create time (option C) and path from a row" -Expected "4321|fixture-net.exe|2026-05-17 08:00:00.000|$userPath|No|OwnerCreated" -Actual ("$([TimelineReport.DetailParser]::Get($details, 'PID'))|$([TimelineReport.DetailParser]::Get($details, 'Process'))|" +
        "$([TimelineReport.DetailParser]::Get($details, 'OwnerCreated'))|$([TimelineReport.DetailParser]::Get($details, 'OwnerPath'))|$([TimelineReport.DetailParser]::Get($details, 'Stale'))|$([TimelineReport.CollectorRows]::OwnerTimeKey('Memory-Network'))")
    $rulesPath = Join-Path (Split-Path $BuilderPath -Parent) "lib\report\report-rules.json"
    $imported = Import-ReportRules -Path $rulesPath
    $netRules = @($imported.Rules | Where-Object { @("INTEG-NET-OWNER-HIDDEN", "EXEC-NET-LISTENER-USERPATH", "EXEC-NET-SCRIPTHOST-PUBLIC") -contains $_.Id } | ForEach-Object { "$($_.Id) $($_.Severity) $($_.Enabled)" })
    Assert-KitEqual -Name "the network rules: two switched on, the script-host rule switched off" -Expected "INTEG-NET-OWNER-HIDDEN High True,EXEC-NET-LISTENER-USERPATH Medium True,EXEC-NET-SCRIPTHOST-PUBLIC Medium False" -Actual ($netRules -join ",")
    $reportRows = @($rows | ForEach-Object { [PSCustomObject]@{ Timestamp = $_.Timestamp; Source = $_.Source; EventType = $_.EventType; Description = $_.Description; User = $_.User; Details = $_.Details; Artifact = $_.Artifact; RawPath = $_.RawPath } })
    $found = @(Invoke-ReportRules -Rows $reportRows -Rules $imported | Where-Object { @("INTEG-NET-OWNER-HIDDEN", "EXEC-NET-LISTENER-USERPATH", "EXEC-NET-SCRIPTHOST-PUBLIC") -contains $_.RuleId } | ForEach-Object { "$($_.RuleId) $($_.GroupKey) $(@($_.RowNumbers).Count)" } | Sort-Object)
    Assert-KitEqual -Name "the area's rows through the rules: the hidden owners' connections, the listeners of the program in a user folder" -Expected "EXEC-NET-LISTENER-USERPATH fixture-net.exe 4,INTEG-NET-OWNER-HIDDEN fixture-hidden 1,INTEG-NET-OWNER-HIDDEN fixture-unlist 1" -Actual ($found -join ",")

    # The switched-off rule, switched on in memory, on its cases
    foreach ($rule in $imported.Rules) { if ($rule.Id -eq "EXEC-NET-SCRIPTHOST-PUBLIC") { $rule.Enabled = $true } }
    $caseRows = @(Import-TimelineCsvForReport -Path (Join-Path $PSScriptRoot "fixtures\memory\net-rules-switched-off.csv"))
    $caseFindings = @(Invoke-ReportRules -Rows $caseRows -Rules $imported | Where-Object { $_.RuleId -eq "EXEC-NET-SCRIPTHOST-PUBLIC" })
    $inFinding = @{}
    foreach ($finding in $caseFindings) { foreach ($n in $finding.RowNumbers) { $inFinding[[int]$n] = $finding } }
    $caseProblems = New-Object System.Collections.Generic.List[string]
    $caseCount = 0
    for ($r = 0; $r -lt $caseRows.Count; $r++) {
        foreach ($tag in @("$($caseRows[$r].RawPath)" -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            $caseCount++
            $parts = $tag -split '\s+', 3
            $finding = $inFinding[$r + 2]
            switch ($parts[0]) {
                "HIT" { if ($null -eq $finding -or ($parts.Count -ge 3 -and $finding.Severity -ne $parts[2])) { $caseProblems.Add("row $($r + 2): $tag") } }
                "KEY" { if ($null -eq $finding -or $finding.GroupKey -ne $parts[2]) { $caseProblems.Add("row $($r + 2): $tag") } }
                "MISS" { if ($null -ne $finding) { $caseProblems.Add("row $($r + 2): $tag") } }
            }
        }
    }
    Assert-KitEqual -Name "EXEC-NET-SCRIPTHOST-PUBLIC switched on: its cases (fixtures\memory\net-rules-switched-off.csv), 4 leads" -Expected "|4|14" -Actual "$($caseProblems -join ' / ')|$($caseFindings.Count)|$caseCount"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Complete-KitTest
