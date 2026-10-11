# =============================================================
# Memory test: console command history (work package WP5, item h)
# The Console area of the debugger engine helper (lib\memory\
# TimelineDbgEng.Console.ps1) on synthetic memory through
# tests\MemoryTestKit.ps1 (no dump in CI), and the builder's rows of its
# entries (Add-DbgEngConsoleRows in lib\memory\TimelineMemoryRows.ps1).
# The console hosts are built in a sparse memory map as Microsoft's console
# code lays them out: an image with a PE section table, the list of command
# histories in its writable section, history nodes, std::wstring texts in
# place and behind pointers, and the console's record of an attached client.
# Checked:
#   - the lists found in the data section (decoys that are not lists left
#     out), the commands oldest first, the program names, the client's
#     process ID only when it is a process of the scan with that program name
#   - a console host whose image header is not in the dump (the list's offset
#     from another host), one without a readable PEB (the image base from
#     another host), one whose list page is not in the dump, one whose
#     address space cannot be read, a command whose page is not in the dump:
#     counted, Partial, and the note says why
#   - more than one list in one host (the offset another host confirms is
#     used), no list where this Windows keeps it (not read: the layout is
#     unknown, never wrong rows), no PEB in the kernel's symbols, no console
#     host at all, the time limit, OpenConsole.exe
#   - the entries' E lines read back by the builder (Receive-DbgEngWorkerLine)
#     and their rows: Source Memory-ConsoleHistory, Snapshot at the capture
#     time, the console host's token SID as User, Details with PID= and
#     ProcessCreated= before the typed command (Args= last: the report's
#     DetailParser reads the console host's own PID= even when the command
#     holds " | PID=")
# The rules that read these rows (the command-content rules) are checked by
# tests\Test-ReportRules.ps1 with tests\fixtures\report\rules\
# cases-memory-console.csv.
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryConsole.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }

# The image every synthetic console host maps: a header page, .text, a
# writable .data of three pages, .rdata
$script:imageBase = [uint64]0x7FF6A0000000
$script:listRva = [uint64]0x6370

function ConvertTo-TestU64 { param([string]$Hex) return [Convert]::ToUInt64($Hex, 16) }

function New-TestPeHeader {
    $h = New-Object byte[] 4096
    $h[0] = 0x4D; $h[1] = 0x5A
    $put = { param([int]$At, [byte[]]$Bytes) [Array]::Copy($Bytes, 0, $h, $At, $Bytes.Length) }
    & $put 0x3C ([BitConverter]::GetBytes([uint32]0x80))
    & $put 0x80 ([BitConverter]::GetBytes([uint32]0x4550))
    & $put 0x84 ([BitConverter]::GetBytes([uint16]0xAA64))
    & $put 0x86 ([BitConverter]::GetBytes([uint16]3))
    & $put 0x94 ([BitConverter]::GetBytes([uint16]0xF0))
    $table = 0x80 + 24 + 0xF0
    $sections = @(
        @(".text", 0x1000, 0x3000, [Convert]::ToUInt32("60000020", 16)),
        @(".data", 0x5000, 0x2800, [Convert]::ToUInt32("C0000040", 16)),
        @(".rdata", 0x8000, 0x1000, [Convert]::ToUInt32("40000040", 16))
    )
    for ($i = 0; $i -lt $sections.Count; $i++) {
        $s = $table + 40 * $i
        & $put $s ([System.Text.Encoding]::ASCII.GetBytes($sections[$i][0]))
        & $put ($s + 8) ([BitConverter]::GetBytes([uint32]$sections[$i][2]))
        & $put ($s + 12) ([BitConverter]::GetBytes([uint32]$sections[$i][1]))
        & $put ($s + 16) ([BitConverter]::GetBytes([uint32]$sections[$i][2]))
        & $put ($s + 36) ([BitConverter]::GetBytes([uint32]$sections[$i][3]))
    }
    return , $h
}

# A console host's image in its address space: the header (unless
# -NoHeader) and the .data pages (but -MissingPages, 0 to 2), zeroed
function Add-TestConsoleImage {
    param($Memory, [uint64]$Process, [uint64]$Peb, [switch]$NoHeader, [switch]$NoPeb, [int[]]$MissingPages = @())
    if (-not $NoPeb) { $Memory.WriteU64($Process, $Peb + 0x10, $script:imageBase) }
    if (-not $NoHeader) { $Memory.Write($Process, $script:imageBase, (New-TestPeHeader)) }
    foreach ($page in 0..2) {
        if ($MissingPages -notcontains $page) { $Memory.Write($Process, $script:imageBase + [uint64](0x5000 + 0x1000 * $page), (New-Object byte[] 4096)) }
    }
}

# A std::wstring at -At: in place (7 characters or fewer, no -Buffer) or
# its text at -Buffer (-NoText: the pointer only, the text not in memory)
function Write-TestWString {
    param($Memory, [uint64]$Process, [uint64]$At, [string]$Text, [uint64]$Buffer = 0, [switch]$NoText)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
    if ($Buffer -eq 0) {
        $inPlace = New-Object byte[] 16
        [Array]::Copy($bytes, $inPlace, $bytes.Length)
        $Memory.Write($Process, $At, $inPlace)
        $capacity = 7
    }
    else {
        $Memory.WriteU64($Process, $At, $Buffer)
        if (-not $NoText) { $Memory.Write($Process, $Buffer, $bytes) }
        $capacity = [Math]::Max(15, $Text.Length + 8)
    }
    $Memory.WriteU64($Process, $At + 0x10, [uint64]$Text.Length)
    $Memory.WriteU64($Process, $At + 0x18, [uint64]$capacity)
}

# One history node: links, the commands vector (-First: -Count used of
# -Capacity), _maxCommands, the program name, the client record, Flags
function Write-TestHistoryNode {
    param($Memory, [uint64]$Process, [uint64]$Node, [uint64]$Next, [uint64]$Prev, [uint64]$First = 0, [int]$Count = 0, [int]$Capacity = 0,
        [int]$Max = 50, [string]$App = "cmd.exe", [uint64]$AppBuffer = 0, [uint64]$Client = 0, [uint32]$Flags = 1)
    $Memory.WriteU64($Process, $Node, $Next)
    $Memory.WriteU64($Process, $Node + 0x08, $Prev)
    $Memory.WriteU64($Process, $Node + 0x10, $First)
    $last = if ($First -ne 0) { $First + [uint64](32 * $Count) } else { [uint64]0 }
    $end = if ($First -ne 0) { $First + [uint64](32 * [Math]::Max($Count, $Capacity)) } else { [uint64]0 }
    $Memory.WriteU64($Process, $Node + 0x18, $last)
    $Memory.WriteU64($Process, $Node + 0x20, $end)
    $Memory.WriteU32($Process, $Node + 0x28, [uint32]$Max)
    Write-TestWString -Memory $Memory -Process $Process -At ($Node + 0x30) -Text $App -Buffer $AppBuffer
    $Memory.WriteU64($Process, $Node + 0x50, $Client)
    $Memory.WriteU32($Process, $Node + 0x58, $Flags)
    $Memory.WriteU32($Process, $Node + 0x5C, [uint32]::MaxValue)
}

# A list's head node and its (head, size) pair at the image's list offset
# (or -Rva)
function Write-TestListHead {
    param($Memory, [uint64]$Process, [uint64]$Head, [uint64]$First, [uint64]$Last, [int]$Count, [uint64]$Rva = $script:listRva, [uint64]$Base = $script:imageBase)
    $Memory.WriteU64($Process, $Head, $First)
    $Memory.WriteU64($Process, $Head + 0x08, $Last)
    $Memory.WriteU64($Process, $Base + $Rva, $Head)
    $Memory.WriteU64($Process, $Base + $Rva + 0x08, [uint64]$Count)
}

function Get-TestEntryText {
    param($Area)
    return (@($Area.Entries | ForEach-Object { $f = Get-TestEntryFields $_; (@($f.Keys | ForEach-Object { "$_=$($f[$_])" }) -join ";") }) -join "`n")
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryConsole"
    $pebDt = New-TestDtText -Type "_PEB" -Size 0x7d0 -Fields @(@(0x0, "InheritedAddressSpace", "UChar"), @(0x8, "Mutant", "Ptr64 Void"), @(0x10, "ImageBaseAddress", "Ptr64 Void"))
    Set-TestEngineCommands -Dt @{ "_PEB" = $pebDt }

    $created = [datetime]::new(2026, 10, 11, 12, 0, 0, 125, [DateTimeKind]::Utc)
    $userSid = "S-1-5-21-1-2-3-1001"
    $hostA = ConvertTo-TestU64 "ffffc00000001000"; $client = ConvertTo-TestU64 "ffffc00000002000"; $hostB = ConvertTo-TestU64 "ffffc00000003000"
    $hostC = ConvertTo-TestU64 "ffffc00000004000"; $hostD = ConvertTo-TestU64 "ffffc00000005000"; $hostE = ConvertTo-TestU64 "ffffc00000006000"
    $other = ConvertTo-TestU64 "ffffc00000007000"
    $peb = [uint64]0x6F0000000
    $memory = New-TestMemory

    # Host A: its own header and data; decoys in .data (a pair whose
    # "list" leads nowhere, a ring of one node that is not a history, a
    # size of 0); a list of two histories: cmd.exe (attached client 4510,
    # two commands: one in place, one behind a pointer) and fixture-tool.exe
    # (a program name behind a pointer, no client, no commands)
    Add-TestConsoleImage -Memory $memory -Process $hostA -Peb $peb
    $heapA = [uint64]0x20000010000
    $memory.WriteU64($hostA, $script:imageBase + 0x5010, $heapA + 0x9000); $memory.WriteU64($hostA, $script:imageBase + 0x5018, [uint64]3)
    $memory.WriteU64($hostA, $heapA + 0x9000, $heapA + 0x9F00)
    $decoy = $heapA + 0xA000
    $memory.WriteU64($hostA, $script:imageBase + 0x5100, $decoy); $memory.WriteU64($hostA, $script:imageBase + 0x5108, [uint64]1)
    $memory.WriteU64($hostA, $decoy, $decoy + 0x100); $memory.WriteU64($hostA, $decoy + 8, $decoy + 0x100)
    Write-TestHistoryNode -Memory $memory -Process $hostA -Node ($decoy + 0x100) -Next $decoy -Prev $decoy -First ($heapA + 0xB000) -Count 2 -Capacity 2 -Max 100000
    $memory.WriteU64($hostA, $script:imageBase + 0x5200, $heapA); $memory.WriteU64($hostA, $script:imageBase + 0x5208, [uint64]0)
    $n1 = $heapA + 0x100; $n2 = $heapA + 0x200; $vectorA = $heapA + 0x1000; $recordA = $heapA + 0x2000
    Write-TestListHead -Memory $memory -Process $hostA -Head $heapA -First $n1 -Last $n2 -Count 2
    Write-TestHistoryNode -Memory $memory -Process $hostA -Node $n1 -Next $n2 -Prev $heapA -First $vectorA -Count 2 -Capacity 3 -App "cmd.exe" -Client $recordA
    Write-TestHistoryNode -Memory $memory -Process $hostA -Node $n2 -Next $heapA -Prev $n1 -App "fixture-tool.exe" -AppBuffer ($heapA + 0x3000) -Flags 0
    Write-TestWString -Memory $memory -Process $hostA -At $vectorA -Text "dir"
    Write-TestWString -Memory $memory -Process $hostA -At ($vectorA + 32) -Text "fixture-stage.exe -connect 203.0.113.7" -Buffer ($heapA + 0x4000)
    $memory.WriteU32($hostA, $recordA + 0x1C, [uint32]4510)

    # Host B: no image header in the dump, so the list's offset comes from
    # host A; one history whose client record names process 4400 (not a
    # cmd.exe: not confirmed), two commands, the second not in the dump
    Add-TestConsoleImage -Memory $memory -Process $hostB -Peb $peb -NoHeader
    $heapB = [uint64]0x30000010000
    $nB = $heapB + 0x100; $vectorB = $heapB + 0x1000; $recordB = $heapB + 0x2000
    Write-TestListHead -Memory $memory -Process $hostB -Head $heapB -First $nB -Last $nB -Count 1
    Write-TestHistoryNode -Memory $memory -Process $hostB -Node $nB -Next $heapB -Prev $heapB -First $vectorB -Count 2 -Capacity 2 -Client $recordB
    Write-TestWString -Memory $memory -Process $hostB -At $vectorB -Text "ver"
    Write-TestWString -Memory $memory -Process $hostB -At ($vectorB + 32) -Text "fixture-gone.exe /all" -Buffer ($heapB + 0x8000) -NoText
    $memory.WriteU32($hostB, $recordB + 0x1C, [uint32]4400)

    # Host C: no readable PEB, so the image base and the offset come from
    # host A; one history, one command
    Add-TestConsoleImage -Memory $memory -Process $hostC -Peb $peb -NoPeb
    $heapC = [uint64]0x40000010000
    Write-TestListHead -Memory $memory -Process $hostC -Head $heapC -First ($heapC + 0x100) -Last ($heapC + 0x100) -Count 1
    Write-TestHistoryNode -Memory $memory -Process $hostC -Node ($heapC + 0x100) -Next $heapC -Prev $heapC -First ($heapC + 0x1000) -Count 1 -Capacity 1 -App "fixture-shell.exe" -AppBuffer ($heapC + 0x3000) -Flags 0
    Write-TestWString -Memory $memory -Process $hostC -At ($heapC + 0x1000) -Text "cls"

    # Host D: the .data page with the list is not in the dump
    Add-TestConsoleImage -Memory $memory -Process $hostD -Peb $peb -MissingPages @(1)

    # Host E: OpenConsole.exe whose address space cannot be read
    $memory.Refuse($hostE)

    $processes = @(
        @{ Eprocess = $hostA; Pid = 4500; Ppid = 4000; CreateTime = $created; Peb = $peb; ShortName = "conhost.exe"; UserSid = $userSid }
        @{ Eprocess = $client; Pid = 4510; Ppid = 4000; CreateTime = $created.AddSeconds(1); Peb = $peb; ShortName = "cmd.exe" }
        @{ Eprocess = $hostB; Pid = 4600; Ppid = 4000; CreateTime = $created.AddSeconds(2); Peb = $peb; ShortName = "CONHOST.EXE" }
        @{ Eprocess = $hostC; Pid = 4700; Ppid = 4000; CreateTime = $created.AddSeconds(3); Peb = $peb; ShortName = "conhost.exe" }
        @{ Eprocess = $hostD; Pid = 4800; Ppid = 4000; CreateTime = $created.AddSeconds(4); Peb = $peb; ShortName = "conhost.exe" }
        @{ Eprocess = $hostE; Pid = 4900; Ppid = 4000; CreateTime = $created.AddSeconds(5); Peb = $peb; ShortName = "OpenConsole.ex" }
        @{ Eprocess = $other; Pid = 4400; Ppid = 4000; CreateTime = $created.AddSeconds(6); Peb = $peb; ShortName = "notepad.exe" }
    )
    $context = New-TestContext -Memory $memory -Processes $processes
    $area = Invoke-TestArea -Name "Console" -Context $context
    $createdText = "2026-10-11 12:00:00.125"
    Assert-KitEqual -Name "the Console area: Partial, four commands, the note names the hosts not read and the command not in the dump" `
        -Expected ("Partial|4|the command history of 2 of 5 console hosts could not be read because their memory is not in the dump, as when it was paged out or the console had closed; " +
            "1 command of the console history could not be read because the memory is not in the dump") -Actual "$($area.State)|$($area.Entries.Count)|$($area.Note)"
    Assert-KitEqual -Name "the Console area: the entries in host, history and command order (oldest first), the client confirmed only by its program name, the host's token SID" `
        -Expected (@(
            "Kind=Console;PID=4500;ProcessCreated=$createdText;App=cmd.exe;ClientPID=4510;Index=0;HistoryCount=2;FoundBy=ConsoleHistoryList;Command=dir;User=$userSid",
            "Kind=Console;PID=4500;ProcessCreated=$createdText;App=cmd.exe;ClientPID=4510;Index=1;HistoryCount=2;FoundBy=ConsoleHistoryList;Command=fixture-stage.exe -connect 203.0.113.7;User=$userSid",
            "Kind=Console;PID=4600;ProcessCreated=2026-10-11 12:00:02.125;App=cmd.exe;ClientPID=;Index=0;HistoryCount=2;FoundBy=ConsoleHistoryList;Command=ver;User=",
            "Kind=Console;PID=4700;ProcessCreated=2026-10-11 12:00:03.125;App=fixture-shell.exe;ClientPID=;Index=0;HistoryCount=1;FoundBy=ConsoleHistoryList;Command=cls;User=") -join "`n") `
        -Actual (Get-TestEntryText $area)
    Assert-KitEqual -Name "the Console area: its counts for the log" `
        -Expected ("console hosts 5, history lists 3, found at another console host's offset 2, histories 4, attached clients 2, client ids confirmed 1, client ids not confirmed 1, commands 4, " +
            "commands not in the dump 1, hosts without readable memory 1, hosts whose list is not in the dump 1, data pages not in the dump 1") -Actual $area.Coverage.CountsText

    # The C# pieces on their own
    $reader = New-Object TimelineDbgEng.ConsoleHistoryReader -ArgumentList $context.Reader, 0x10
    $scanA = $reader.Scan($context.Processes[0], (New-Object TimelineDbgEng.AreaResult -ArgumentList "Console", 30.0))
    Assert-KitEqual -Name "Scan: host A's image base from its PEB, its 3 writable pages, one list (the decoys are not lists) at the list's offset" `
        -Expected "True|True|3|0|1|0x6370|2" -Actual "$($scanA.BaseRead)|$($scanA.HeaderRead)|$($scanA.WritablePages)|$($scanA.MissingPages)|$($scanA.Candidates.Count)|0x$($scanA.Candidates[0].Rva.ToString('x'))|$($scanA.Candidates[0].Histories.Count)"
    $notPe = New-Object byte[] 4096
    $badPe = New-TestPeHeader; $badPe[0x80] = 0
    $farPe = New-TestPeHeader; [Array]::Copy([BitConverter]::GetBytes([uint32]0x2000), 0, $farPe, 0x3C, 4)
    $sections = [TimelineDbgEng.ConsoleHistoryReader]::WritableSections((New-TestPeHeader))
    Assert-KitEqual -Name "WritableSections: only the writable section of a PE header; null for no MZ, no PE signature, a PE header outside the page" `
        -Expected "1|0x5000/0x2800|True|True|True" -Actual ("$($sections.Count)|0x$($sections[0].Key.ToString('x'))/0x$($sections[0].Value.ToString('x'))|" +
            "$($null -eq [TimelineDbgEng.ConsoleHistoryReader]::WritableSections($notPe))|$($null -eq [TimelineDbgEng.ConsoleHistoryReader]::WritableSections($badPe))|$($null -eq [TimelineDbgEng.ConsoleHistoryReader]::WritableSections($farPe))")
    $node = New-Object byte[] 0x60
    $setNode = { param([int]$At, [uint64]$Value) [Array]::Copy([BitConverter]::GetBytes($Value), 0, $node, $At, 8) }
    & $setNode 0x10 ([uint64]0x10000); & $setNode 0x18 ([uint64]0x10040); & $setNode 0x20 ([uint64]0x10060); & $setNode 0x28 ([uint64]50); & $setNode 0x40 ([uint64]3); & $setNode 0x48 ([uint64]7)
    $good = [TimelineDbgEng.ConsoleHistoryReader]::Parse(1, $node)
    $parseResults = @()
    foreach ($bad in @(@(0x18, 0x10080), @(0x18, 0x10041), @(0x28, 100000), @(0x40, 8), @(0x48, 6), @(0x50, 0x10001), @(0x10, 0))) {
        $copy = [byte[]]$node.Clone()
        [Array]::Copy([BitConverter]::GetBytes([uint64]$bad[1]), 0, $copy, $bad[0], 8)
        $parseResults += ($null -eq [TimelineDbgEng.ConsoleHistoryReader]::Parse(1, $copy))
    }
    Assert-KitEqual -Name "Parse: a plausible history (2 commands, maximum 50); none when the vector is out of order or not whole strings, the maximum is too large, the program name is longer than its capacity or its capacity is too small, the client record is not aligned, the vector has an end but no start" `
        -Expected "2|50|True,True,True,True,True,True,True" -Actual "$($good.CommandCount)|$($good.MaxCommands)|$($parseResults -join ',')"
    $strings = New-Object byte[] 96
    [Array]::Copy([System.Text.Encoding]::Unicode.GetBytes("abc"), 0, $strings, 0, 6)
    [Array]::Copy([BitConverter]::GetBytes([uint64]3), 0, $strings, 0x10, 8); [Array]::Copy([BitConverter]::GetBytes([uint64]7), 0, $strings, 0x18, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint64]($heapA + 0x4000)), 0, $strings, 0x20, 8); [Array]::Copy([BitConverter]::GetBytes([uint64]17), 0, $strings, 0x30, 8); [Array]::Copy([BitConverter]::GetBytes([uint64]47), 0, $strings, 0x38, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint64]9), 0, $strings, 0x50, 8); [Array]::Copy([BitConverter]::GetBytes([uint64]7), 0, $strings, 0x58, 8)
    Assert-KitEqual -Name "WString: in place, behind a pointer (its size, not to the end of the text), null when the size is more than the capacity" `
        -Expected "abc|fixture-stage.exe|True" -Actual "$($reader.WString($hostA, $strings, 0))|$($reader.WString($hostA, $strings, 0x20))|$($null -eq $reader.WString($hostA, $strings, 0x40))"
    $names = @(
        @{ ShortName = "conhost.exe" }, @{ ShortName = "CONHOST.EXE" }, @{ ShortName = "OpenConsole.ex" }, @{ ShortName = "x"; FullName = "OpenConsole.exe" },
        @{ ShortName = "conhost.exe2" }, @{ ShortName = "OpenCon" }, @{ ShortName = "cmd.exe" })
    $hostNames = @(foreach ($n in $names) { $p = New-Object TimelineDbgEng.ProcessInfo; foreach ($k in $n.Keys) { $p.$k = $n[$k] }; [TimelineDbgEng.ConsoleHistoryReader]::IsConsoleHost($p) })
    $longName = New-Object TimelineDbgEng.ProcessInfo; $longName.ShortName = "fixturelongpro"
    Assert-KitEqual -Name "IsConsoleHost and NameMatches: conhost.exe in any case, OpenConsole.exe (cut to 14 characters or full); a name cut to 14 characters matches the program name it starts" `
        -Expected "True,True,True,True,False,False,False|True|False" `
        -Actual "$($hostNames -join ',')|$([TimelineDbgEng.ConsoleHistoryReader]::NameMatches($longName, 'fixturelongprogram.exe'))|$([TimelineDbgEng.ConsoleHistoryReader]::NameMatches($longName, 'fixturelong.exe'))"

    # More than one list in one host: the one at the offset another host
    # confirms is used
    $memory2 = New-TestMemory
    $hostF = ConvertTo-TestU64 "ffffc00000011000"; $hostG = ConvertTo-TestU64 "ffffc00000012000"
    foreach ($h in @($hostF, $hostG)) {
        Add-TestConsoleImage -Memory $memory2 -Process $h -Peb $peb
        $heap = [uint64]0x50000010000
        Write-TestListHead -Memory $memory2 -Process $h -Head $heap -First ($heap + 0x100) -Last ($heap + 0x100) -Count 1
        Write-TestHistoryNode -Memory $memory2 -Process $h -Node ($heap + 0x100) -Next $heap -Prev $heap -First ($heap + 0x1000) -Count 1 -Capacity 1
        Write-TestWString -Memory $memory2 -Process $h -At ($heap + 0x1000) -Text "real"
    }
    $other2 = [uint64]0x50000020000
    Write-TestListHead -Memory $memory2 -Process $hostG -Head $other2 -First ($other2 + 0x100) -Last ($other2 + 0x100) -Count 1 -Rva 0x5400
    Write-TestHistoryNode -Memory $memory2 -Process $hostG -Node ($other2 + 0x100) -Next $other2 -Prev $other2 -First ($other2 + 0x1000) -Count 1 -Capacity 1
    Write-TestWString -Memory $memory2 -Process $hostG -At ($other2 + 0x1000) -Text "fake"
    $context2 = New-TestContext -Memory $memory2 -Processes @(
        @{ Eprocess = $hostF; Pid = 5100; CreateTime = $created; Peb = $peb; ShortName = "conhost.exe" }
        @{ Eprocess = $hostG; Pid = 5200; CreateTime = $created; Peb = $peb; ShortName = "conhost.exe" })
    $area2 = Invoke-TestArea -Name "Console" -Context $context2
    $commands2 = @($area2.Entries | ForEach-Object { "$($_.Get('PID')):$($_.Get('Command'))" }) -join ","
    Assert-KitEqual -Name "the Console area: two lists in one host, the one at the offset another host has is used (and counted)" -Expected "Read|5100:real,5200:real|1" `
        -Actual "$($area2.State)|$commands2|$($area2.Coverage.Get('hosts with more than one list'))"

    # No list where this Windows keeps it: a host whose data is all in the
    # dump has only a ring whose back link is wrong -- not read, never rows
    $memory3 = New-TestMemory
    $hostH = ConvertTo-TestU64 "ffffc00000021000"
    Add-TestConsoleImage -Memory $memory3 -Process $hostH -Peb $peb
    $heapH = [uint64]0x60000010000
    Write-TestListHead -Memory $memory3 -Process $hostH -Head $heapH -First ($heapH + 0x100) -Last ($heapH + 0x100) -Count 1
    Write-TestHistoryNode -Memory $memory3 -Process $hostH -Node ($heapH + 0x100) -Next $heapH -Prev ($heapH + 0x800) -First ($heapH + 0x1000) -Count 1 -Capacity 1
    Write-TestWString -Memory $memory3 -Process $hostH -At ($heapH + 0x1000) -Text "never"
    $context3 = New-TestContext -Memory $memory3 -Processes @(@{ Eprocess = $hostH; Pid = 5300; CreateTime = $created; Peb = $peb; ShortName = "conhost.exe" })
    $area3 = Invoke-TestArea -Name "Console" -Context $context3
    Assert-KitEqual -Name "the Console area: no list in a host whose data is in the dump (a ring with a wrong back link is none) is not read, with no entries" `
        -Expected "NotRead|0|the console's command history was not found where this Windows version is known to keep it" -Actual "$($area3.State)|$($area3.Entries.Count)|$($area3.Note)"

    # No console host; the time limit; no PEB in the kernel's symbols
    $context4 = New-TestContext -Memory (New-TestMemory) -Processes @(@{ Eprocess = $other; Pid = 4400; Peb = $peb; ShortName = "notepad.exe" })
    $area4 = Invoke-TestArea -Name "Console" -Context $context4
    Assert-KitEqual -Name "the Console area: no console host is read, with nothing to say" -Expected "Read|0||console hosts 0, history lists 0, histories 0, attached clients 0, client ids confirmed 0, commands 0" `
        -Actual "$($area4.State)|$($area4.Entries.Count)|$($area4.Note)|$($area4.Coverage.CountsText)"
    $area5 = Invoke-TestArea -Name "Console" -Context (New-TestContext -Memory $memory -Processes $processes) -CapSeconds 0.000001
    Assert-KitEqual -Name "the Console area: at its time limit it stops, Partial, and counts the hosts not reached" -Expected "Partial|0|stopped at its time limit of 0 s|5" `
        -Actual "$($area5.State)|$($area5.Entries.Count)|$($area5.Note)|$($area5.Coverage.Get('hosts not reached before the time limit'))"
    Set-TestEngineCommands -Dt @{}
    $area6 = Invoke-TestArea -Name "Console" -Context (New-TestContext -Memory $memory -Processes $processes)
    Assert-KitEqual -Name "the Console area: without the PEB in the kernel's symbols it is not read, and says why" -Expected "NotRead|0|the kernel's symbols do not describe the PEB" `
        -Actual "$($area6.State)|$($area6.Entries.Count)|$($area6.Note)"
    Set-TestEngineCommands -Dt @{ "_PEB" = $pebDt }

    # The builder: the E lines read back, the rows of the entries
    $state = New-DbgEngWorkerState
    foreach ($line in @([TimelineDbgEng.EntryWriter]::Lines($area.Entries))) { Receive-DbgEngWorkerLine -Line $line -State $state }
    $state.Entries["Console"].Add([PSCustomObject]@{ PID = "4600"; ProcessCreated = "2026-10-11 12:00:02.125"; App = ""; ClientPID = ""; Index = "5"; HistoryCount = "6"; FoundBy = "ConsoleHistoryList"; Command = "echo x | PID=7001 | ProcessCreated=2026-10-11 11:59:00.000"; User = "" })
    $state.Entries["Console"].Add([PSCustomObject]@{ PID = "4600"; App = "cmd.exe"; Command = "" })
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    [void](Get-TestRows)
    $kinds = @(Add-DbgEngEntryRows -Entries $state.Entries -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp")
    $rows = @(Get-TestRows -Objects)
    $rowTexts = @($rows | ForEach-Object { "$($_.Source)|$($_.Timestamp)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)|$($_.Artifact)|$($_.RawPath)" })
    Assert-KitEqual -Name "Add-DbgEngConsoleRows: from the E lines, one Snapshot row per command at the capture time, the host's SID as User, the command last in Details; no row without a command" `
        -Expected (@(
            "Memory-ConsoleHistory|2026-10-11 12:30:00.000|Snapshot|Console command in memory: cmd.exe (conhost PID: 4500)|$userSid|PID=4500 | ProcessCreated=$createdText | App=cmd.exe | ClientPID=4510 | Index=0 | HistoryCount=2 | FoundBy=ConsoleHistoryList | Args=dir|MemoryDump|C:\dumps\fixture.dmp",
            "Memory-ConsoleHistory|2026-10-11 12:30:00.000|Snapshot|Console command in memory: cmd.exe (conhost PID: 4500)|$userSid|PID=4500 | ProcessCreated=$createdText | App=cmd.exe | ClientPID=4510 | Index=1 | HistoryCount=2 | FoundBy=ConsoleHistoryList | Args=fixture-stage.exe -connect 203.0.113.7|MemoryDump|C:\dumps\fixture.dmp",
            "Memory-ConsoleHistory|2026-10-11 12:30:00.000|Snapshot|Console command in memory: cmd.exe (conhost PID: 4600)||PID=4600 | ProcessCreated=2026-10-11 12:00:02.125 | App=cmd.exe | ClientPID= | Index=0 | HistoryCount=2 | FoundBy=ConsoleHistoryList | Args=ver|MemoryDump|C:\dumps\fixture.dmp",
            "Memory-ConsoleHistory|2026-10-11 12:30:00.000|Snapshot|Console command in memory: fixture-shell.exe (conhost PID: 4700)||PID=4700 | ProcessCreated=2026-10-11 12:00:03.125 | App=fixture-shell.exe | ClientPID= | Index=0 | HistoryCount=1 | FoundBy=ConsoleHistoryList | Args=cls|MemoryDump|C:\dumps\fixture.dmp",
            "Memory-ConsoleHistory|2026-10-11 12:30:00.000|Snapshot|Console command in memory: unknown program (conhost PID: 4600)||PID=4600 | ProcessCreated=2026-10-11 12:00:02.125 | App= | ClientPID= | Index=5 | HistoryCount=6 | FoundBy=ConsoleHistoryList | Args=echo x | PID=7001 | ProcessCreated=2026-10-11 11:59:00.000|MemoryDump|C:\dumps\fixture.dmp"
        ) -join "`n") -Actual ($rowTexts -join "`n")
    $consoleKind = @($kinds | Where-Object { $_.Kind -eq "Console" })
    Assert-KitEqual -Name "Add-DbgEngEntryRows: the Console kind's counts" -Expected "1|Memory-ConsoleHistory|6|5|0|5|" `
        -Actual "$($consoleKind.Count)|$($consoleKind[0].Source)|$($consoleKind[0].Received)|$($consoleKind[0].Rows)|$($consoleKind[0].Timed)|$($consoleKind[0].Snapshot)|$($consoleKind[0].Error)"

    # The rules file: the command-content rules take these rows beside the
    # memory command lines (one source alternation in each, read from the
    # JSON; their patterns are checked by Test-ReportRules.ps1), and the
    # rules that key on program names and paths do not
    $rulesJson = Get-Content -LiteralPath (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\report-rules.json") -Raw | ConvertFrom-Json
    $consoleSource = '^Memory-(?:CommandLine|ConsoleHistory)$'
    $withConsole = @(foreach ($id in @("EXEC-PS-ENCODED", "EXEC-PS-DOWNLOAD", "EXEC-PS-DOWNLOAD-FILE", "EXEC-LOLBIN-URL", "EXEC-PS-AMSI-CRED", "EXEC-DEFENDER-TAMPER-CMD")) {
            $rule = @($rulesJson.rules | Where-Object { $_.id -eq $id })
            $branches = @($rule | ForEach-Object { @($_.anyOf) } | Where-Object { $_.PSObject.Properties["source"] })
            "${id}:$(@($branches | Where-Object { $_.source -ceq $consoleSource }).Count)/$(@($branches | Where-Object { $_.source -ceq '^Memory-CommandLine$' }).Count)"
        })
    $withoutConsole = @(foreach ($id in @("EXEC-STAGING", "EXEC-HACKTOOL-RAN", "INITIAL-EMAIL-RUN", "INITIAL-EMAIL-ATTACH")) {
            $rule = @($rulesJson.rules | Where-Object { $_.id -eq $id })
            "${id}:$(@($rule).Count):$((($rule | ConvertTo-Json -Depth 8 -Compress) -match 'ConsoleHistory'))"
        })
    Assert-KitEqual -Name "report-rules.json: the six command-content rules have one branch for memory command lines and console history (none for command lines alone); the name and path rules have none" `
        -Expected "EXEC-PS-ENCODED:1/0,EXEC-PS-DOWNLOAD:1/0,EXEC-PS-DOWNLOAD-FILE:1/0,EXEC-LOLBIN-URL:1/0,EXEC-PS-AMSI-CRED:1/0,EXEC-DEFENDER-TAMPER-CMD:1/0|EXEC-STAGING:1:False,EXEC-HACKTOOL-RAN:1:False,INITIAL-EMAIL-RUN:1:False,INITIAL-EMAIL-ATTACH:1:False" `
        -Actual "$($withConsole -join ',')|$($withoutConsole -join ',')"

    # The findings report reads the console host's own PID= and
    # ProcessCreated= (the collector's console is left out by them), also
    # when the typed command holds " | PID="
    . (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\TimelineReport.Engine.ps1")
    $typed = $rows[4].Details
    Assert-KitEqual -Name "the report's DetailParser: PID= and ProcessCreated= of a console row are the console host's, the typed command is Args=" `
        -Expected "4600|2026-10-11 12:00:02.125|echo x | PID=7001 | ProcessCreated=2026-10-11 11:59:00.000" `
        -Actual "$([TimelineReport.DetailParser]::Get($typed, 'PID'))|$([TimelineReport.DetailParser]::Get($typed, 'ProcessCreated'))|$($typed.Substring($typed.IndexOf('Args=') + 5))"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
