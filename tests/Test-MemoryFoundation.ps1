# =============================================================
# Memory foundation test
# The shared layer of the Windows ARM64 memory areas (no dump, no admin):
#   - the area files load and their C# compiles as one unit with the host;
#     a fragment that does not compile is left out (only its areas are not
#     read), in a process of its own
#   - the reader (lib\memory\TimelineDbgEng.Reader.ps1): the reads and
#     strings of MemoryReader over a sparse memory map, SessionReader's page
#     cache, sticky process switch, refused processes and cache limit
#   - layouts from canned 'dt -v' output (New-DbgEngLayout: missing fields
#     and types, bitfields, symbols, the type cache), ProcessInfo from an
#     EPROCESS block, the VAD walker on a synthetic tree (address order,
#     images and their file names cached per control area, loops, a node
#     not in the dump, order and parent errors, the cap, VadCount)
#   - entries and areas: MemoryEntry and its E line (Base64 of UTF-8), the
#     area dispatcher (Invoke-DbgEngAreas: the fixed order, "not built yet",
#     a missing file, an area that fails before or after its entries, the
#     time cap, the raw pass started and disposed, the joins after all
#     areas, no areas without the reader), and the AREA and END lines
#   - the builder's side: the protocol reader (E, AREA, END with three
#     counts, bad lines), Merge-DbgEngProcessEntries, User and ExtraDetails
#     on the four Add-MemoryPluginRows branches, Add-DbgEngEntryRows and
#     Add-DbgEngEntryRow, the "analyzed with" and coverage texts
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryFoundation.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuilderPath) { $BuilderPath = Join-Path $repoRoot "timeline-builder.ps1" }
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("memory-foundation-test-" + [guid]::NewGuid().ToString("N"))
[void][System.IO.Directory]::CreateDirectory($workDir)

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "memory foundation"
    $memoryFolder = Join-Path (Split-Path $BuilderPath -Parent) "lib\memory"

    # --- The area files and the one compile unit ---------------------------------
    $areaFiles = @(Get-DbgEngAreaFiles)
    $present = @($areaFiles | Where-Object { Test-Path -LiteralPath (Join-Path $memoryFolder $_) -PathType Leaf })
    Assert-KitEqual -Name "the helper's area files: all 14 in lib\memory\, the reader first, the joins last" -Expected "14|14|TimelineDbgEng.Reader.ps1|TimelineDbgEng.Joins.ps1" -Actual "$($areaFiles.Count)|$($present.Count)|$($areaFiles[0])|$($areaFiles[-1])"
    $compileProblems = @($script:DbgEngCompileProblems.Keys)
    $types = @("Session", "SessionReader", "FuncReader", "FuncProcessMemory", "Layout", "ProcessInfo", "MemoryContext", "AreaResult", "Coverage", "Deadline", "MemoryEntry", "EntryWriter", "VadWalker", "Bytes", "Fmt") |
        Where-Object { -not ([System.Management.Automation.PSTypeName]"TimelineDbgEng.$_").Type }
    Assert-KitEqual -Name "the host and every area file's C# compile as one unit (no fragment left out, every reader type there)" -Expected "0|" -Actual "$($compileProblems.Count)|$($types -join ',')"
    foreach ($file in $areaFiles) {
        $errors = $null
        $fileAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $memoryFolder $file), [ref]$null, [ref]$errors)
        $scriptLevel = @($fileAst.EndBlock.Statements | Where-Object { $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] }).Count
        $stem = Get-DbgEngFileStem $file
        $sourceFunction = [bool](Get-Command -Name "Get-DbgEng${stem}Source" -CommandType Function -ErrorAction SilentlyContinue)
        $usingLine = [regex]::IsMatch((& "Get-DbgEng${stem}Source"), '(?m)^\s*using\s+[\w.]+\s*;')
        Assert-KitEqual -Name "${file}: parses, has Get-DbgEng${stem}Source, its C# has no using line, no script-level code" -Expected "0|True|False|0" -Actual "$(@($errors).Count)|$sourceFunction|$usingLine|$scriptLevel"
    }

    # Every file of lib\memory\: no extension ("!") command is sent to the
    # engine, and no attacker-tool name of report-rules.json is in the text
    # (Defender's AMSI scans these scripts; the names live only in the JSON)
    $memoryFiles = @(Get-ChildItem -LiteralPath $memoryFolder -Filter "*.ps1" -File)
    $bangCommands = @($memoryFiles | Where-Object { [regex]::IsMatch([System.IO.File]::ReadAllText($_.FullName), '(?:-Command|Execute\()\s*["'']\s*!') } | ForEach-Object { $_.Name })
    $rulesJson = Get-Content -LiteralPath (Join-Path (Split-Path $memoryFolder -Parent) "report\report-rules.json") -Raw | ConvertFrom-Json
    $toolPatterns = @($rulesJson.lists.attackerTools)
    $named = @(foreach ($file in $memoryFiles) {
            $fileText = [System.IO.File]::ReadAllText($file.FullName)
            if (@($toolPatterns | Where-Object { $_ -and [regex]::IsMatch($fileText, '\b(?:' + $_ + ')', 'IgnoreCase') }).Count -gt 0) { $file.Name }
        })
    Assert-KitEqual -Name "lib\memory\ ($($memoryFiles.Count) files): no extension command, no attacker-tool name ($($toolPatterns.Count) names checked)" -Expected "||True" -Actual "$($bangCommands -join ',')|$($named -join ',')|$($toolPatterns.Count -gt 10)"
    # A fragment that does not compile is left out, the others compiled, and
    # only its areas are not read (in a process of its own: a compiled type
    # stays for the life of the process)
    $childScript = Join-Path $workDir "compile-fallback.ps1"
    $childText = @'
param([string]$Kit, [string]$Memory)
$ErrorActionPreference = "Stop"
. $Kit
[void](Import-MemoryTestFunctions -Path (Join-Path $Memory "TimelineDbgEng.ps1"))
foreach ($file in @(Get-DbgEngAreaFiles)) { [void](Import-MemoryTestFunctions -Path (Join-Path $Memory $file)) }
function Get-DbgEngModulesSource { return "namespace TimelineDbgEng { public static class BrokenModules { public static int X() { return ; } } }" }
function Get-DbgEngConsoleSource { return "namespace TimelineDbgEng { public static class ConsoleProbe { public static int Lines() { return 3; } } }" }
Initialize-DbgEngHost
$problems = @($script:DbgEngCompileProblems.Keys | Sort-Object) -join ","
$why = $script:DbgEngCompileProblems["Modules"]
"RESULT|$problems|$([bool]([System.Management.Automation.PSTypeName]'TimelineDbgEng.MemoryContext').Type)|$([bool]([System.Management.Automation.PSTypeName]'TimelineDbgEng.ConsoleProbe').Type)|$([bool]([System.Management.Automation.PSTypeName]'TimelineDbgEng.BrokenModules').Type)|$($why -like 'the code of lib\memory\TimelineDbgEng.Modules.ps1 could not be compiled `[*`]')|$((Get-DbgEngFileProblem 'Modules') -ne '')"
'@
    [System.IO.File]::WriteAllText($childScript, $childText)
    $hostExe = (Get-Process -Id $PID).Path
    $childOutput = @(& $hostExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $childScript -Kit (Join-Path $PSScriptRoot "MemoryTestKit.ps1") -Memory $memoryFolder 2>&1 | ForEach-Object { "$_" })
    $childResult = @($childOutput | Where-Object { $_.StartsWith("RESULT|") }) | Select-Object -Last 1
    Assert-KitEqual -Name "a fragment that does not compile: left out with the compiler's reason, the reader and another area's C# compiled" -Expected "RESULT|Modules|True|True|False|True|True" -Actual "$childResult$(if (-not $childResult) { $childOutput -join ' / ' })"

    # --- MemoryReader over a sparse memory ------------------------------------------
    $memory = New-TestMemory
    $kernel = [Convert]::ToUInt64("ffffb00000010000", 16)
    $user = [uint64]0x7ff600000000
    $procA = [Convert]::ToUInt64("ffffc00000001000", 16)
    $procB = [Convert]::ToUInt64("ffffc00000002000", 16)
    $memory.WriteU64(0, $kernel, [uint64]0x1122334455667788)
    $memory.WriteU32(0, $kernel + 8, [Convert]::ToUInt32("CAFEBABE", 16))
    $memory.WriteU16(0, $kernel + 12, [uint16]0xBEEF)
    $memory.Write(0, $kernel + 0xFFC, [byte[]](1, 2, 3, 4))     # the page's last 4 bytes; the next page is not there
    $memory.WriteUnicodeString(0, $kernel + 0x100, $kernel + 0x200, "C:\Windows\x $([char]0x00E9).dll")
    $memory.WriteU16(0, $kernel + 0x120, 3); $memory.WriteU16(0, $kernel + 0x122, 10); $memory.WriteU64(0, $kernel + 0x128, $kernel + 0x200)     # odd length
    $memory.WriteU16(0, $kernel + 0x130, 12); $memory.WriteU16(0, $kernel + 0x132, 4); $memory.WriteU64(0, $kernel + 0x138, $kernel + 0x200)    # longer than its maximum
    $memory.WriteU16(0, $kernel + 0x140, 8); $memory.WriteU16(0, $kernel + 0x142, 8); $memory.WriteU64(0, $kernel + 0x148, $kernel + 0x5000)  # buffer not in the dump
    $memory.WriteUnicodeString(0, $kernel + 0x150, $kernel + 0x300, "ab$([char]0)cd")
    $memory.WriteU16(0, $kernel + 0x160, 0); $memory.WriteU16(0, $kernel + 0x162, 0); $memory.WriteU64(0, $kernel + 0x168, 0)                    # empty
    $memory.WriteU16(0, $kernel + 0x170, 6); $memory.WriteU16(0, $kernel + 0x172, 8); $memory.WriteU32(0, $kernel + 0x174, [uint32]0x10400)    # 32-bit
    $memory.Write($procA, [uint64]0x10400, [System.Text.Encoding]::Unicode.GetBytes("w32"))
    $memory.WriteU16($procA, [uint64]0x10500, 6); $memory.WriteU16($procA, [uint64]0x10502, 8); $memory.WriteU32($procA, [uint64]0x10504, [uint32]0x10400)
    $memory.Write(0, $kernel + 0x400, [System.Text.Encoding]::ASCII.GetBytes("Registry`0junk"))
    $memory.WriteU64($procA, $user, [uint64]0xA)
    $memory.WriteU64($procB, $user, [uint64]0xB)
    $reader = New-TestFuncReader -Memory $memory
    $partial = $reader.Read(0, $kernel + 0xFFC, 8)
    $tryBytes = $null
    $tryOk = $reader.TryRead(0, $kernel + 0xFFC, 8, [ref]$tryBytes)
    Assert-KitEqual -Name "MemoryReader: little-endian reads, a read cut where the next page is not in the dump, TryRead only for every byte" -Expected "1122334455667788|CAFEBABE|BEEF|4|False|True" `
        -Actual "$($reader.U64(0, $kernel).ToString('X'))|$($reader.U32(0, $kernel + 8).ToString('X'))|$($reader.U16(0, $kernel + 12).ToString('X'))|$($partial.Length)|$tryOk|$($null -eq $tryBytes)"
    $strings = @(
        $reader.UnicodeString(0, $kernel + 0x100), $reader.UnicodeString(0, $kernel + 0x120), $reader.UnicodeString(0, $kernel + 0x130), $reader.UnicodeString(0, $kernel + 0x140),
        $reader.UnicodeString(0, $kernel + 0x150), $reader.UnicodeString(0, $kernel + 0x160), $reader.UnicodeString(0, $kernel + 0x5000), $reader.UnicodeString32($procA, [uint64]0x10500),
        $reader.Ascii(0, $kernel + 0x400, 32)
    ) | ForEach-Object { if ($null -eq $_) { "<null>" } else { "[$_]" } }
    Assert-KitEqual -Name "MemoryReader strings: a UNICODE_STRING, odd length / longer than its maximum / buffer not in the dump (null), cut at a NUL, empty, not in the dump, a 32-bit one, ASCII to its NUL" `
        -Expected "[C:\Windows\x $([char]0x00E9).dll]|<null>|<null>|<null>|[ab]|[]|<null>|[w32]|[Registry]" -Actual ($strings -join "|")
    $addressChecks = @(
        [TimelineDbgEng.MemoryReader]::IsKernelAddress($kernel), [TimelineDbgEng.MemoryReader]::IsKernelAddress([uint64]0x7ff6), [TimelineDbgEng.MemoryReader]::IsKernelPointer($kernel + 4),
        [TimelineDbgEng.MemoryReader]::IsKernelPointer($kernel), [TimelineDbgEng.MemoryReader]::IsUserAddress($user), [TimelineDbgEng.MemoryReader]::IsUserAddress([uint64]0), [TimelineDbgEng.MemoryReader]::IsUserAddress($kernel)
    )
    Assert-KitEqual -Name "MemoryReader: kernel address, kernel pointer (8-byte aligned), user address" -Expected "True|False|False|True|True|False|False" -Actual ($addressChecks -join "|")

    # --- SessionReader: the page cache, the sticky switch, refused processes -----
    $sessionMemory = New-TestMemory
    $sessionMemory.WriteU64(0, $kernel, [uint64]7)
    $sessionMemory.WriteU64(0, $kernel + 0x1000, [uint64]8)
    $sessionMemory.WriteU64($procA, $user, [uint64]0xA)
    $sessionMemory.WriteU64($procA, $user + 0x1000, [uint64]0xAA)
    $sessionMemory.WriteU64($procB, $user, [uint64]0xB)
    $procGone = [Convert]::ToUInt64("ffffc00000003000", 16)
    $sessionMemory.WriteU64($procGone, $user, [uint64]0xC)
    $sessionMemory.Refuse($procGone)
    $session = New-TestSessionReader -Memory $sessionMemory
    $values = @($session.U64(0, $kernel), $session.U64(0, $kernel + 8), $session.U64(0, $kernel + 0x1000), $session.U64($procA, $user), $session.U64($procA, $user + 8), $session.U64($procA, $user + 0x1000),
        $session.U64($procB, $user), $session.U64($procA, $user), $session.U64($procGone, $user), $session.U64($procGone, $user), $session.U64(0, $user))
    Assert-KitEqual -Name "SessionReader: kernel pages cached for all processes, user pages per process, a process switched to only when another's page is needed, a refused process remembered, a user address without a process unread" `
        -Expected "7|0|8|10|0|170|11|10|0|0|0|5|3|1|1" -Actual "$($values -join '|')|$($sessionMemory.Reads)|$($sessionMemory.Switches)|$($session.UnreadableProcessCount)|$([int]$session.IsUnreadableProcess($procGone))"
    Assert-KitEqual -Name "SessionReader: its counters (reads, engine page reads, cache hits, switches and refusals)" -Expected "11|5|3|3|1" -Actual "$($session.Stats.Requests)|$($session.Stats.EngineReads)|$($session.Stats.CacheHits)|$($session.Stats.Switches)|$($session.Stats.SwitchFailures)"
    $small = New-TestSessionReader -Memory $sessionMemory -CacheBytes 4096
    for ($page = 0; $page -lt 20; $page++) { [void]$small.Read(0, $kernel + [uint64]($page * 0x1000), 8) }
    $crossing = $small.Read(0, $kernel + 0xFF8, 16)
    Assert-KitEqual -Name "SessionReader: a full cache (at least 16 pages) is emptied, a read across two pages joins them" -Expected "1|16|0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0" -Actual "$($small.Stats.Evictions)|$($crossing.Length)|$($crossing -join ',')"

    # --- Layouts from 'dt -v' ---------------------------------------------------------
    $dt = @{
        "_EPROCESS"    = New-TestDtText -Type "_EPROCESS" -Size 0x900 -Fields @(
            @(0x1c0, "UniqueProcessId", "Ptr64 to Void"), @(0x1e8, "CreateTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"), @(0x238, "Token", "struct _EX_FAST_REF, 3 elements, 0x8 bytes"),
            @(0x2c0, "InheritedFromUniqueProcessId", "Ptr64 to Void"), @(0x2d0, "Peb", "Ptr64 to struct _PEB, 124 elements, 0x7d8 bytes"), @(0x300, "WoW64Process", "Ptr64 to struct _EWOW64PROCESS, 3 elements, 0x18 bytes"),
            @(0x328, "ImageFileName", "[15] UChar"), @(0x370, "ActiveThreads", "Uint4B"), @(0x618, "VadRoot", "struct _RTL_AVL_TREE, 1 elements, 0x8 bytes"), @(0x628, "VadCount", "Uint8B"),
            @(0x680, "ExitTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"), @(0x6ba, "Protection", "Uint4B"))
        "_EX_FAST_REF" = New-TestDtText -Type "_EX_FAST_REF" -Size 8 -Fields @(@(0, "Object", "Ptr64 to Void"), @(0, "RefCnt", "Bitfield Pos 0, 3 Bits"), @(0, "Value", "Uint8B"))
    }
    Set-TestEngineCommands -Dt $dt -Symbols @{ "nt!PsLoadedModuleList" = $kernel }
    $layout = New-DbgEngLayout -Session $null -Spec (Get-DbgEngProcessLayoutSpec) -Symbols @("nt!PsLoadedModuleList", "nt!NoSuchSymbol")
    $layout = New-DbgEngLayout -Session $null -Spec @{ "_NO_SUCH_TYPE" = @{ X = "" }; "_EPROCESS" = @{ Peb = '^Ptr64\b' } } -Layout $layout
    $dtSent = @($script:testEngineCommands | Where-Object { $_ -like 'dt -v *' })
    Assert-KitEqual -Name "New-DbgEngLayout: offsets as _TYPE.Field, the size, a bitfield and the fast-ref mask, a symbol; a field of another type, a type and a symbol that are not there named in Missing; each type asked once" `
        -Expected "488|2304|0,3|7|$kernel|_EPROCESS.Protection,nt!NoSuchSymbol,_NO_SUCH_TYPE|3" `
        -Actual "$($layout.Off('_EPROCESS.CreateTime'))|$($layout.Size('_EPROCESS'))|$($layout.Bits['_EX_FAST_REF.RefCnt'] -join ',')|$($layout.FastRefMask)|$($layout.Symbol('nt!PsLoadedModuleList'))|$(@($layout.Missing) -join ',')|$($dtSent.Count)"
    $block = New-Object byte[] 0x900
    [Array]::Copy([BitConverter]::GetBytes([long]4321), 0, $block, 0x1c0, 8)
    [Array]::Copy([BitConverter]::GetBytes([long]3000), 0, $block, 0x2c0, 8)
    $created = [datetime]::new(2026, 10, 11, 12, 21, 33, 123, [DateTimeKind]::Utc).AddTicks(4567)
    [Array]::Copy([BitConverter]::GetBytes($created.ToFileTimeUtc()), 0, $block, 0x1e8, 8)
    [Array]::Copy([BitConverter]::GetBytes(([uint64]$kernel + 0x5000) -bor 5), 0, $block, 0x238, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint64]0x7ff7000), 0, $block, 0x2d0, 8)
    [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("fixture-stage.e"), 0, $block, 0x328, 15)
    $info = [TimelineDbgEng.ProcessInfo]::FromBlock($procA, $block, $layout)
    Assert-KitEqual -Name "ProcessInfo.FromBlock: PID, parent, create time (to the millisecond in ProcessCreated= form), PEB, token masked, 15-byte name, protection left 0 when the layout lacks it" `
        -Expected "4321|3000|2026-10-11 12:21:33.123|$(0x7ff7000)|$($kernel + 0x5000)|fixture-stage.e|0|False|fixture-stage.e" `
        -Actual "$($info.Pid)|$($info.Ppid)|$($info.CreatedText)|$($info.Peb)|$($info.Token)|$($info.ShortName)|$($info.Protection)|$($info.IsProtected)|$($info.Name)"

    # --- The VAD walker on a synthetic tree --------------------------------------------
    $vadDt = @{
        "_EPROCESS"          = $dt["_EPROCESS"]
        "_EX_FAST_REF"       = New-TestDtText -Type "_EX_FAST_REF" -Size 8 -Fields @(@(0, "RefCnt", "Bitfield Pos 0, 4 Bits"))
        "_RTL_BALANCED_NODE" = New-TestDtText -Type "_RTL_BALANCED_NODE" -Size 0x18 -Fields @(@(0, "Left", "Ptr64 to struct _RTL_BALANCED_NODE"), @(8, "Right", "Ptr64 to struct _RTL_BALANCED_NODE"), @(0x10, "ParentValue", "Uint8B"))
        "_MMVAD_SHORT"       = New-TestDtText -Type "_MMVAD_SHORT" -Size 0x40 -Fields @(@(0x18, "StartingVpn", "Uint4B"), @(0x1c, "EndingVpn", "Uint4B"), @(0x20, "StartingVpnHigh", "UChar"), @(0x21, "EndingVpnHigh", "UChar"), @(0x30, "u", "union <unnamed-tag>, 6 elements, 0x4 bytes"))
        "_MMVAD_FLAGS"       = New-TestDtText -Type "_MMVAD_FLAGS" -Size 4 -Fields @(@(0, "VadType", "Bitfield Pos 4, 3 Bits"), @(0, "Protection", "Bitfield Pos 7, 5 Bits"), @(0, "PrivateMemory", "Bitfield Pos 21, 1 Bit"))
        "_MMVAD"             = New-TestDtText -Type "_MMVAD" -Size 0x88 -Fields @(@(0, "Core", "struct _MMVAD_SHORT"), @(0x48, "Subsection", "Ptr64 to struct _SUBSECTION"))
        "_SUBSECTION"        = New-TestDtText -Type "_SUBSECTION" -Size 0x38 -Fields @(@(0, "ControlArea", "Ptr64 to struct _CONTROL_AREA"))
        "_CONTROL_AREA"      = New-TestDtText -Type "_CONTROL_AREA" -Size 0x80 -Fields @(@(0x40, "FilePointer", "struct _EX_FAST_REF, 3 elements, 0x8 bytes"))
        "_FILE_OBJECT"       = New-TestDtText -Type "_FILE_OBJECT" -Size 0xd8 -Fields @(@(0x58, "FileName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"))
    }
    $nodeBase = [Convert]::ToUInt64("ffffb10000000000", 16)
    $subsectionBase = [Convert]::ToUInt64("ffffb20000000000", 16)
    # Nodes 1..7 in address order, each on its own page; root 4 (2: 1, 3; 6: 5, 7)
    $shape = @{ 4 = @(2, 6, 0); 2 = @(1, 3, 4); 6 = @(5, 7, 4); 1 = @(0, 0, 2); 3 = @(0, 0, 2); 5 = @(0, 0, 6); 7 = @(0, 0, 6) }
    # VadType, Protection, PrivateMemory, control area (0: none)
    $kinds = @{ 1 = @(2, 7, 0, 1); 2 = @(0, 4, 1, 0); 3 = @(2, 7, 0, 2); 4 = @(0, 4, 1, 0); 5 = @(0, 6, 1, 0); 6 = @(0, 1, 0, 3); 7 = @(2, 7, 0, 1) }
    function Get-TestNode { param([int]$N) if ($N -eq 0) { return [uint64]0 }; return $nodeBase + [uint64]($N * 0x1000) }
    function Write-TestTree {
        param($Memory, [hashtable]$Shape, [hashtable]$Starts = @{})
        foreach ($n in 1..7) {
            $node = Get-TestNode $n
            $Memory.WriteU64(0, $node, (Get-TestNode $Shape[$n][0]))
            $Memory.WriteU64(0, $node + 8, (Get-TestNode $Shape[$n][1]))
            $Memory.WriteU64(0, $node + 0x10, (Get-TestNode $Shape[$n][2]) -bor 1)
            $start = if ($Starts.ContainsKey($n)) { $Starts[$n] } else { [uint32]($n * 0x10) }
            $Memory.WriteU32(0, $node + 0x18, $start)
            $Memory.WriteU32(0, $node + 0x1c, [uint32]($start + 0xF))
            $flags = ([uint32]$kinds[$n][0] -shl 4) -bor ([uint32]$kinds[$n][1] -shl 7) -bor ([uint32]$kinds[$n][2] -shl 21)
            $Memory.WriteU32(0, $node + 0x30, $flags)
            $area = $kinds[$n][3]
            if ($area -gt 0) {
                $subsection = $subsectionBase + [uint64]($n * 0x100)
                $control = $subsectionBase + [uint64](0x10000 + $area * 0x100)
                $file = $subsectionBase + [uint64](0x20000 + $area * 0x100)
                $Memory.WriteU64(0, $node + 0x48, $subsection)
                $Memory.WriteU64(0, $subsection, $control)
                $Memory.WriteU64(0, $control + 0x40, $file -bor 3)
                $Memory.WriteUnicodeString(0, $file + 0x58, $file + 0x80, @{ 1 = "\Windows\System32\fixture-a.dll"; 2 = "\Users\fixture\fixture-b.dll"; 3 = "\Windows\Fonts\fixture.ttf" }[$area])
            }
        }
    }
    function New-TestVadProcess { param([uint64]$Root, [long]$Count)
        $vadBlock = New-Object byte[] 0x900
        [Array]::Copy([BitConverter]::GetBytes($Root), 0, $vadBlock, 0x618, 8)
        [Array]::Copy([BitConverter]::GetBytes($Count), 0, $vadBlock, 0x628, 8)
        $p = New-Object TimelineDbgEng.ProcessInfo
        $p.Eprocess = $procA
        $p.Block = $vadBlock
        return $p
    }
    $vadMemory = New-TestMemory
    Write-TestTree -Memory $vadMemory -Shape $shape
    Set-TestEngineCommands -Dt $vadDt
    $vadContext = New-TestContext -Memory $vadMemory
    $walker = Get-DbgEngVadWalker -Context $vadContext
    $walk = $walker.Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 7))
    $starts = @($walk.Nodes | ForEach-Object { "{0:x}" -f $_.Start })
    $names = @($walk.Nodes | Where-Object { $_.IsImage } | ForEach-Object { $walker.FileName($_) })
    $privateExec = @($walk.Nodes | Where-Object { $_.PrivateMemory -and $_.Protection -eq 6 }).Count
    Assert-KitEqual -Name "VAD walker: every node in address order, the type, protection and private bit, consistent, the same walker for the context" -Expected "10000,20000,30000,40000,50000,60000,70000|7|7|1|True|0|0|0|True|$($walker.Ready)" `
        -Actual "$($starts -join ',')|$($walk.Nodes.Count)|$($walk.VadCount)|$privateExec|$($walk.Consistent)|$($walk.Loops)|$($walk.OrderErrors)|$($walk.ParentMismatches)|$([object]::ReferenceEquals($walker, (Get-DbgEngVadWalker -Context $vadContext)))|True"
    Assert-KitEqual -Name "VAD walker: image file names through subsection, control area and file object, cached per control area; a region's end; a private region has no file" `
        -Expected "\Windows\System32\fixture-a.dll|\Users\fixture\fixture-b.dll|\Windows\System32\fixture-a.dll|1|1ffff||\Windows\Fonts\fixture.ttf" `
        -Actual "$($names -join '|')|$($walker.NameCacheHits)|$("{0:x}" -f $walk.Nodes[0].End)|$($walker.FileName($walk.Nodes[1]))|$($walker.FileName($walk.Nodes[5]))"
    # A loop, a node not in the dump, an order error, a parent link, the cap,
    # a VadCount that differs, an empty tree
    $loopShape = $shape.Clone(); $loopShape[7] = @(0, 4, 6)
    $loopMemory = New-TestMemory; Write-TestTree -Memory $loopMemory -Shape $loopShape
    $loop = (Get-DbgEngVadWalker -Context (New-TestContext -Memory $loopMemory)).Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 7))
    $goneMemory = New-TestMemory; Write-TestTree -Memory $goneMemory -Shape $shape; $goneMemory.Remove(0, (Get-TestNode 5))
    $gone = (Get-DbgEngVadWalker -Context (New-TestContext -Memory $goneMemory)).Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 7))
    $orderMemory = New-TestMemory; Write-TestTree -Memory $orderMemory -Shape $shape -Starts @{ 1 = [uint32]0x30; 3 = [uint32]0x10 }
    $order = (Get-DbgEngVadWalker -Context (New-TestContext -Memory $orderMemory)).Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 7))
    $parentShape = $shape.Clone(); $parentShape[6] = @(5, 7, 2)
    $parentMemory = New-TestMemory; Write-TestTree -Memory $parentMemory -Shape $parentShape
    $parentWalk = (Get-DbgEngVadWalker -Context (New-TestContext -Memory $parentMemory)).Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 7))
    $capped = $walker.Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 7), 3)
    $countOff = $walker.Walk((New-TestVadProcess -Root (Get-TestNode 4) -Count 9))
    $empty = $walker.Walk((New-TestVadProcess -Root 0 -Count 0))
    Assert-KitEqual -Name "VAD walker: a loop, a node not in the dump, out of order, the cap, VadCount make it inconsistent; a wrong parent link is only counted; an empty tree" `
        -Expected "7|1|False|6|1|False|1|False|1|True|True|False|False|0|True" `
        -Actual "$($loop.Nodes.Count)|$($loop.Loops)|$($loop.Consistent)|$($gone.Nodes.Count)|$($gone.Unreadable)|$($gone.Consistent)|$([int]($order.OrderErrors -gt 0))|$($order.Consistent)|$($parentWalk.ParentMismatches)|$($parentWalk.Consistent)|$($capped.Capped)|$($capped.Consistent)|$($countOff.Consistent)|$($empty.Nodes.Count)|$($empty.Consistent)"
    $noLayout = New-Object TimelineDbgEng.VadWalker -ArgumentList $reader, (New-Object TimelineDbgEng.Layout)
    Assert-KitEqual -Name "VAD walker: without its layout it is not ready, says what is missing and walks nothing" -Expected "False|True|0" -Actual "$($noLayout.Ready)|$($noLayout.MissingFields -like '_EPROCESS.VadRoot, *')|$($noLayout.Walk($info).Nodes.Count)"

    # --- Entries and areas -----------------------------------------------------------------
    $entry = New-Object TimelineDbgEng.MemoryEntry -ArgumentList "Module"
    [void]$entry.Set("PID", [long]4321).Set("Path", "C:\Users\fixture\b $([char]0x00E9) $([char]0xFFFE).dll").SetHex("Base", [uint64]0x7ff600000000).Set("Empty", "")
    [void]$entry.Set("PID", [long]4322)
    $badKeys = foreach ($key in @("", "1a", "a b", "a|b", "a:b", ("k" * 65))) { try { [void]$entry.Set($key, "x"); "set" } catch { "refused" } }
    $line = $entry.ToLine()
    $fields = Get-TestEntryFields $line
    Assert-KitEqual -Name "MemoryEntry: its E line (keys in the order set, a key set again keeps its place, Base64 of UTF-8 in C#), keys that are not a letter and letters or digits refused" `
        -Expected "Module|PID,Path,Base,Empty|4322|C:\Users\fixture\b $([char]0x00E9) $([char]0xFFFE).dll|0x7ff600000000||refused,refused,refused,refused,refused,refused|True" `
        -Actual "$($fields['Kind'])|$(@($entry.Keys) -join ',')|$($fields['PID'])|$($fields['Path'])|$($fields['Base'])|$($fields['Empty'])|$($badKeys -join ',')|$($line.StartsWith('TBDBG|E|Module|PID:NDMyMg==|Path:'))"
    $areaResult = New-Object TimelineDbgEng.AreaResult -ArgumentList "Modules", 0.05
    $areaResult.Coverage.Count("loader lists", 3); $areaResult.Coverage.Count("unreadable", 1); $areaResult.Coverage.Count("loader lists", 2)
    $areaResult.Coverage.Note("the loader lists of 2 processes could not be read"); $areaResult.Coverage.Note("the loader lists of 2 processes could not be read")
    Start-Sleep -Milliseconds 80
    $timeUp = $areaResult.TimeUp()
    Assert-KitEqual -Name "AreaResult: counts in order, a note once, the time cap makes it Partial and says so" -Expected "loader lists 5, unreadable 1|True|Partial|the loader lists of 2 processes could not be read; stopped at its time limit of 0 s" `
        -Actual "$($areaResult.Coverage.CountsText)|$timeUp|$($areaResult.State)|$($areaResult.Note)"

    # The dispatcher: the fixed order, the stubs, a test area that reads, one
    # that fails after its entries and one before, a missing file, the raw
    # pass and the joins
    Set-TestEngineCommands -Dt $vadDt
    $dispatchMemory = New-TestMemory
    $switch = [Delegate]::CreateDelegate([Func[uint64, bool]], $dispatchMemory, "Switch")
    $read = [Delegate]::CreateDelegate([Func[uint64, uint64, int, byte[]]], $dispatchMemory, "Read")
    $processMemory = New-Object TimelineDbgEng.FuncProcessMemory -ArgumentList $switch, $read
    $scanEntries = @([PSCustomObject]@{ PID = [long]4321; PPID = [long]3000; ImageFileName = "fixture-stage.e"; Offset = "0x$($procA.ToString('x'))"; FoundBy = "ListForward"; Anomaly = "" })
    $script:areaOrder = New-Object System.Collections.Generic.List[string]
    $script:rawPass = New-Object System.IO.MemoryStream
    $realModules = ${function:Invoke-DbgEngModulesArea}; $realPrivate = ${function:Invoke-DbgEngPrivateCodeArea}; $realDrivers = ${function:Invoke-DbgEngDriversArea}
    $realRaw = ${function:Start-DbgEngRawPass}; $realJoins = ${function:Invoke-DbgEngJoins}
    try {
        ${function:Invoke-DbgEngModulesArea} = { param($Context, $Area) $script:areaOrder.Add("Modules:$($Context.Processes.Count):$($Context.RawPass -ne $null)"); [void]$Area.Add("Module").Set("PID", $Context.Processes[0].Pid).Set("ProcessCreated", $Context.Processes[0].CreatedText); $Area.Coverage.Count("modules", 1); $Area.Coverage.Note("1 process's loader list could not be read") }
        ${function:Invoke-DbgEngPrivateCodeArea} = { param($Context, $Area) $null = $Context; [void]$Area.Add("PrivateCode").Set("PID", "1"); throw "boom: after one entry" }
        ${function:Invoke-DbgEngDriversArea} = { param($Context, $Area) $null = $Context, $Area; throw "boom (before any entry)" }
        ${function:Start-DbgEngRawPass} = { param($Context) $Context.RawPass = $script:rawPass }
        ${function:Invoke-DbgEngJoins} = { param($Context) $script:areaOrder.Add("Joins:$($Context.Areas.Count)"); $Context.Areas["Modules"].Entries[0].Set("Joined", "yes") | Out-Null }
        $script:DbgEngFileProblems = @{ Console = "lib\memory\TimelineDbgEng.Console.ps1 is missing" }
        $run = Invoke-DbgEngAreas -Session $null -Memory $processMemory -Processes $scanEntries -Blocks @(, $block) -DumpPath "C:\dumps\fixture.dmp"
    }
    finally {
        ${function:Invoke-DbgEngModulesArea} = $realModules; ${function:Invoke-DbgEngPrivateCodeArea} = $realPrivate; ${function:Invoke-DbgEngDriversArea} = $realDrivers
        ${function:Start-DbgEngRawPass} = $realRaw; ${function:Invoke-DbgEngJoins} = $realJoins
        $script:DbgEngFileProblems = @{}
    }
    $summary = @($run.Areas | ForEach-Object { "$($_.Name)=$($_.State)/$($_.Rows)/$($_.Note)" })
    Assert-KitEqual -Name "Invoke-DbgEngAreas: the areas in their fixed order; stubs not built yet; a missing file names it; a failure after entries is Partial (entries kept), before them NotRead" `
        -Expected ("ProcessDetails=NotRead/0/not built yet|Modules=Read/1/1 process's loader list could not be read|PrivateCode=Partial/1/it stopped [boom - after one entry]|" +
            "Drivers=NotRead/0/it stopped [boom [before any entry]]|Handles=NotRead/0/not built yet|Registry=NotRead/0/not built yet|Console=NotRead/0/lib\memory\TimelineDbgEng.Console.ps1 is missing|Services=NotRead/0/not built yet|Network=NotRead/0/not built yet") `
        -Actual ($summary -join "|")
    $runFields = @($run.Entries | ForEach-Object { $f = Get-TestEntryFields $_; "$($f['Kind']):$($f['PID']):$($f['ProcessCreated']):$($f['Joined'])" })
    Assert-KitEqual -Name "Invoke-DbgEngAreas: the context's processes from the scan's blocks, the raw pass started first and disposed at the end, the joins after every area, the entries in area order" `
        -Expected "Modules:1:True|Joins:9|Module:4321:2026-10-11 12:21:33.123:yes|PrivateCode:1::|False" -Actual "$($script:areaOrder -join '|')|$($runFields -join '|')|$($script:rawPass.CanRead)"
    $script:DbgEngFileProblems = @{ Reader = "lib\memory\TimelineDbgEng.Reader.ps1 is missing" }
    try { $noReader = Invoke-DbgEngAreas -Session $null -Memory $processMemory -Processes $scanEntries }
    finally { $script:DbgEngFileProblems = @{} }
    Assert-KitEqual -Name "Invoke-DbgEngAreas: without the reader every area is not read, and says why" -Expected "9|9|0" -Actual "$(@($noReader.Areas).Count)|$(@($noReader.Areas | Where-Object { $_.State -eq 'NotRead' -and $_.Note -eq 'lib\memory\TimelineDbgEng.Reader.ps1 is missing' }).Count)|$(@($noReader.Entries).Count)"

    # The protocol: P, C, E, AREA, END with three counts; read back by the builder
    $result = New-DbgEngResult
    $result.Processes = @([PSCustomObject]@{ PID = [long]4321; PPID = [long]3000; Threads = [long]3; SessionId = [long]1; Offset = "0x$($procA.ToString('x'))"; ImageFileName = "fixture-stage.e"; CreateTime = "2026-10-11T12:21:33.1234567+00:00"; ExitTime = $null; FoundBy = "ListForward"; TableId = ""; Anomaly = "" })
    $result.CommandLines = @([PSCustomObject]@{ PID = [long]4321; Process = "fixture-stage.e"; Args = "fixture-stage.exe -x" })
    $result.Entries = @($run.Entries) + @([PSCustomObject]@{ Kind = "Proc"; Fields = [ordered]@{ Offset = "0x$($procA.ToString('x'))"; User = "S-1-5-18" } })
    $result.Areas = @($run.Areas)
    [void](Get-TestProtocolLines)
    Write-DbgEngWorkerResult $result
    $lines = Get-TestProtocolLines
    $kindRuns = New-Object System.Collections.Generic.List[string]
    foreach ($protocolLine in $lines) {
        $lineKind = $protocolLine.Split('|')[1]
        if ($lineKind -ne "R" -and ($kindRuns.Count -eq 0 -or $kindRuns[$kindRuns.Count - 1] -ne $lineKind)) { $kindRuns.Add($lineKind) }
    }
    $kinds = $kindRuns.ToArray() -join ","
    Assert-KitEqual -Name "Write-DbgEngWorkerResult: P, C, E (C# and a test's entries), AREA lines, then END with the numbers of P, C and E lines" -Expected "P,C,E,AREA,END|TBDBG|END|1|1|3|9" `
        -Actual "$kinds|$($lines[-1])|$(@($lines | Where-Object { $_.StartsWith('TBDBG|AREA|') }).Count)"
    $state = New-DbgEngWorkerState
    foreach ($protocolLine in $lines) { Receive-DbgEngWorkerLine -Line $protocolLine -State $state }
    $moduleEntry = $state.Entries["Module"][0]
    Assert-KitEqual -Name "Receive-DbgEngWorkerLine: the entries by kind with their fields, the areas, END with three counts accepted" `
        -Expected "True|0|Module,PrivateCode,Proc|4321|2026-10-11 12:21:33.123|yes|9|Partial|it stopped [boom - after one entry]|3" `
        -Actual "$($state.Ended)|$($state.BadLines)|$(@($state.Entries.Keys | Sort-Object) -join ',')|$($moduleEntry.PID)|$($moduleEntry.ProcessCreated)|$($moduleEntry.Joined)|$($state.Areas.Count)|$($state.Areas[2].State)|$($state.Areas[2].Note)|$($state.EntryCount)"
    # A bad line in place of the first line of its kind: a bad END or E line
    # means the run did not end cleanly (the E count no longer fits); a bad
    # AREA line leaves that area unreported
    $badCases = @(
        @("TBDBG|END|1|1", "END with two counts"), @("TBDBG|END|1|1|2", "an E count that does not fit"), @("TBDBG|E|Mod ule|A:QQ==", "a kind that is not a name"),
        @("TBDBG|E|Module|PID", "a field without a colon"), @("TBDBG|E|Module|1x:QQ==", "a key that is not a name"), @("TBDBG|E|Module|A:QQ==|A:QQ==", "a key twice"),
        @("TBDBG|E|Module|A:@@@", "a value that is not Base64"), @("TBDBG|AREA|Modules|Done|1|0.1|", "an area state that is not one"), @("TBDBG|AREA|Modules|Read|1|0.1", "an area line without its note field")
    )
    foreach ($case in $badCases) {
        $badState = New-DbgEngWorkerState
        $prefix = $case[0].Substring(0, $case[0].IndexOf('|', 6) + 1)
        $replaced = $false
        foreach ($protocolLine in $lines) {
            if (-not $replaced -and $protocolLine.StartsWith($prefix)) { $replaced = $true; Receive-DbgEngWorkerLine -Line $case[0] -State $badState; continue }
            Receive-DbgEngWorkerLine -Line $protocolLine -State $badState
        }
        # (A bad E line makes the END line a bad one too: its E count no longer fits)
        $expected = if ($case[0].StartsWith("TBDBG|AREA|")) { "1|True|8" } elseif ($case[0].StartsWith("TBDBG|E|")) { "2|False|9" } else { "1|False|9" }
        Assert-KitEqual -Name "Receive-DbgEngWorkerLine: $($case[1]) is a bad line (bad lines|ended cleanly|areas)" -Expected $expected -Actual "$($badState.BadLines)|$($badState.Ended)|$($badState.Areas.Count)"
    }

    # --- The builder's rows ---------------------------------------------------------------
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    $end = $capture.AddMinutes(3)
    $merge = Merge-DbgEngProcessEntries -Processes $state.Processes.ToArray() -ProcEntries ($state.Entries["Proc"].ToArray() + @([PSCustomObject]@{ Offset = "0xffff000000000001" }))
    Assert-KitEqual -Name "Merge-DbgEngProcessEntries: a Proc entry onto its process by Offset (any case), one without a process counted" -Expected "1|1|S-1-5-18" -Actual "$($merge.Merged)|$($merge.Unmatched)|$($state.Processes[0].Proc.User)"
    [void](Get-TestRows)
    $pslist = [PSCustomObject]@{ PID = 4321; PPID = 3000; ImageFileName = "fixture-stage.exe"; Threads = 3; SessionId = 1; CreateTime = "2026-10-11T12:21:33.1234567+00:00"; FoundBy = "ListForward"; User = "S-1-5-18"; ExtraDetails = " Integrity=System Elevated=Yes" }
    $cmdline = [PSCustomObject]@{ PID = 4321; Process = "fixture-stage.exe"; Args = "fixture-stage.exe -x"; User = "S-1-5-18"; ExtraDetails = "Probe=1" }
    $netscan = [PSCustomObject]@{ Proto = "TCPv4"; LocalAddr = "10.0.0.5"; LocalPort = 5; ForeignAddr = "192.0.2.7"; ForeignPort = 443; State = "ESTABLISHED"; PID = 4321; Owner = "fixture-stage.exe"; Created = "2026-10-11T12:22:00+00:00"; User = "S-1-5-18"; ExtraDetails = "FoundBy=PoolScan Stale=No" }
    $svcscan = [PSCustomObject]@{ Name = "FixtureSvc"; Display = "Fixture"; Binary = "C:\x.exe"; State = "SERVICE_RUNNING"; Start = "SERVICE_AUTO_START"; PID = 4321; ExtraDetails = "Type=SERVICE_WIN32_OWN_PROCESS Order=7" }
    foreach ($pair in @(@("windows.pslist", $pslist), @("windows.cmdline", $cmdline), @("windows.netscan", $netscan), @("windows.svcscan", $svcscan))) {
        [void](Add-MemoryPluginRows -Plugin $pair[0] -Source "S-$($pair[0])" -Entries @($pair[1]) -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp")
    }
    $volatility = [PSCustomObject]@{ PID = 8; PPID = 4; ImageFileName = "x.exe"; Threads = 1; SessionId = 0; CreateTime = "2026-10-11T12:00:00+00:00" }
    [void](Add-MemoryPluginRows -Plugin "windows.pslist" -Source "S-vol" -Entries @($volatility) -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp")
    Assert-KitEqual -Name "Add-MemoryPluginRows: User and ExtraDetails of a debugger engine entry on all four branches; a Volatility entry as before" -Expected (@(
            "S-windows.pslist|2026-10-11 12:21:33.123|ProcessCreation|Process in memory: fixture-stage.exe (PID: 4321, PPID: 3000)|S-1-5-18|Threads=3 SessionId=1 FoundBy=ListForward Integrity=System Elevated=Yes",
            "S-windows.cmdline|2026-10-11 12:30:00.000|Snapshot|Process command line: fixture-stage.exe (PID: 4321)|S-1-5-18|Args=fixture-stage.exe -x Probe=1",
            "S-windows.netscan|2026-10-11 12:22:00.000|NetworkConnection|Memory network: TCPv4 10.0.0.5:5 -> 192.0.2.7:443 (ESTABLISHED)|S-1-5-18|PID=4321 Process=fixture-stage.exe FoundBy=PoolScan Stale=No",
            "S-windows.svcscan|2026-10-11 12:30:00.000|Snapshot|Service in memory: Fixture (FixtureSvc)||State=SERVICE_RUNNING StartType=SERVICE_AUTO_START Binary=C:\x.exe PID=4321 Type=SERVICE_WIN32_OWN_PROCESS Order=7",
            "S-vol|2026-10-11 12:00:00.000|ProcessCreation|Process in memory: x.exe (PID: 8, PPID: 4)||Threads=1 SessionId=0") -join " / ") -Actual (@(Get-TestRows) -join " / ")

    Assert-KitEqual -Name "Format-DbgEngDetails: pipe style in order, a `$null value left out, an empty one kept" -Expected "PID=4321 | ProcessCreated= | Path=C:\x y.dll" -Actual (Format-DbgEngDetails ([ordered]@{ PID = 4321; ProcessCreated = ""; Skipped = $null; Path = "C:\x y.dll" }))
    $timedRow = Add-DbgEngEntryRow -Source "Memory-Modules" -EventType "ModuleLoad" -Description "Module in memory: b.dll (PID: 4321, Process: fixture-stage.exe)" -User "S-1-5-18" -Details "PID=4321" -Time "2026-10-11 12:25:00.250" -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp"
    $lateRow = Add-DbgEngEntryRow -Source "Memory-Modules" -EventType "ModuleLoad" -Description "late" -Time "2026-10-20 00:00:00.000" -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp"
    $noTimeRow = Add-DbgEngEntryRow -Source "Memory-Drivers" -Description "Kernel module in memory: fixture.sys" -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp"
    $entryRows = @(Get-TestRows -Objects)
    Assert-KitEqual -Name "Add-DbgEngEntryRow: an event at a valid own time, a Snapshot row at the capture time otherwise (the time past the end given back), MemoryDump and the dump on every row" `
        -Expected "True|False|2026-10-20 00:00:00.000|False|2026-10-11 12:25:00.250 ModuleLoad|2026-10-11 12:30:00.000 Snapshot|2026-10-11 12:30:00.000 Snapshot|3" `
        -Actual "$($timedRow.Timed)|$($lateRow.Timed)|$($lateRow.Text)|$($noTimeRow.Timed)|$(@($entryRows | ForEach-Object { "$($_.Timestamp) $($_.EventType)" }) -join '|')|$(@($entryRows | Where-Object { $_.Artifact -eq 'MemoryDump' -and $_.RawPath -eq 'C:\dumps\fixture.dmp' }).Count)"
    $realModuleRows = ${function:Add-DbgEngModuleRows}
    try {
        ${function:Add-DbgEngModuleRows} = {
            param([object[]]$Entries, [string]$Source, [datetime]$CaptureTimeUtc, [datetime]$AcquisitionEndUtc, [string]$DumpPath)
            foreach ($e in $Entries) { [void](Add-DbgEngEntryRow -Source $Source -Description "Module in memory: $($e.PID)" -Details (Format-DbgEngDetails ([ordered]@{ PID = $e.PID; ProcessCreated = $e.ProcessCreated })) -CaptureTimeUtc $CaptureTimeUtc -AcquisitionEndUtc $AcquisitionEndUtc -DumpPath $DumpPath) }
            return (New-DbgEngRowCounts -Snapshot @($Entries).Count)
        }
        $state.Entries["Mystery"] = New-Object System.Collections.Generic.List[object]
        $state.Entries["Mystery"].Add([PSCustomObject]@{ A = "1" })
        $kindResults = @(Add-DbgEngEntryRows -Entries $state.Entries -CaptureTimeUtc $capture -AcquisitionEndUtc $end -DumpPath "C:\dumps\fixture.dmp")
    }
    finally { ${function:Add-DbgEngModuleRows} = $realModuleRows }
    $kindText = @($kindResults | ForEach-Object { "$($_.Kind):$($_.Source):$($_.Received):$($_.Rows):$($_.Unknown)" }) -join "|"
    Assert-KitEqual -Name "Add-DbgEngEntryRows: each kind's function with its entries and Source, the stubs add no rows, a kind without rows counted" -Expected "Module:Memory-Modules:1:1:False|PrivateCode:Memory-PrivateCode:1:0:False|Mystery::1:0:True|Memory-Modules|PID=4321 | ProcessCreated=2026-10-11 12:21:33.123" `
        -Actual "$kindText|$(@(Get-TestRows -Objects | ForEach-Object { "$($_.Source)|$($_.Details)" }) -join ' / ')"

    $readText = Get-DbgEngReadText -Areas $state.Areas.ToArray()
    $partialText = Get-DbgEngReadText -Areas @($state.Areas | Where-Object { $_.Name -ne "Services" }) -PartialReason "its command lines could not be read [the command did not finish within 300 s]"
    Assert-KitEqual -Name "Get-DbgEngReadText: what was read in the report's order, what was not with its reason (no colon, no parentheses inside), an area the helper did not report" `
        -Expected ("read processes, command lines, DLLs, executable private memory; not read process users and paths (not built yet), kernel drivers (it stopped [boom [before any entry]]), handles (not built yet), " +
            "registry hives (not built yet), console history (lib\memory\TimelineDbgEng.Console.ps1 is missing), network connections (not built yet), services (not built yet)|" +
            "read processes, DLLs, executable private memory; not read command lines (could not be read [the command did not finish within 300 s]), process users and paths (not built yet)") `
        -Actual "$readText|$(($partialText -split '; not read ')[0]); not read $((($partialText -split '; not read ')[1] -split ', ')[0..1] -join ', ')"
    Assert-KitEqual -Name "Get-DbgEngReadText: an area the helper did not report says so" -Expected "True" -Actual "$($partialText.EndsWith('services (not reported by the debugger engine helper)'))"
    $coverage = @(Get-DbgEngCoverageTexts -Areas (@([PSCustomObject]@{ Name = "Handles"; State = "Partial"; Rows = 3; Note = "stopped at its time limit of 60 s: 2 tables -- unread" }) + $state.Areas.ToArray()))
    Assert-KitEqual -Name "Get-DbgEngCoverageTexts: one per area read with a note, in the report's order, its colons and dashes made plain" `
        -Expected "DLLs -- 1 process's loader list could not be read|handles -- stopped at its time limit of 60 s - 2 tables - unread|executable private memory -- it stopped [boom - after one entry]" -Actual ($coverage -join "|")
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
Complete-KitTest
