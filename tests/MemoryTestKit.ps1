# =============================================================
# Memory test kit: what the tests of the Windows ARM64 memory areas share
# Dot-source it from a test (". (Join-Path $PSScriptRoot 'MemoryTestKit.ps1')"),
# then:
#   Initialize-MemoryTestKit [-RepoRoot <root>] [-Builder] [-BuilderPath <copy>]
#     loads the debugger engine helper's functions and every area file's
#     (lib\memory\TimelineDbgEng*.ps1) from their syntax trees -- their
#     script-level code never runs (the helper's param block would clobber
#     the test's $DumpPath and the like, and nothing opens a dump) --
#     compiles their C# as the helper does (Initialize-DbgEngHost: one unit)
#     and the kit's own test C#, and captures the protocol lines the helper
#     writes (Get-TestProtocolLines). -Builder also loads the builder's
#     functions and lib\memory\TimelineMemoryRows.ps1 (rows into
#     $script:timelineEntries; Get-TestRows).
#   New-TestMemory                a sparse byte map of 4 KB pages per address
#                                 space (process 0: the kernel's): Write,
#                                 WriteU8/U16/U32/U64, WriteUnicodeString,
#                                 Remove (a page not in the dump), Refuse (a
#                                 process whose switch fails), Read
#   New-TestFuncReader -Memory    a FuncReader over it (no cache)
#   New-TestSessionReader -Memory a SessionReader over it (cache, sticky
#                                 switch, refused processes), and
#                                 $memory.Switches / .Reads to check it
#   New-TestLayout -Offsets @{ "_TYPE.Field" = 0x10 } -Sizes @{ "_TYPE" = 0x40 }
#                  -Bits @{ "_TYPE.Field" = @(4, 3) } -Symbols @{ "nt!X" = addr }
#   New-TestDtText -Type _X -Size 0x40 -Fields @(@(0x10, "Name", "Ptr64 to Void"), ...)
#                                 the engine's "dt -v nt!_X" text
#   Set-TestEngineCommands -Dt @{ "_X" = <dt text> } -Symbols @{ "nt!X" = addr }
#                                 Invoke-DbgEngCommand answers those (dt -v,
#                                 "? name"); any other command throws
#   New-TestContext -Memory -Processes @(@{ Eprocess = ...; Pid = ...; ... })
#                   [-ProcessLayout] [-Session]
#                                 a MemoryContext with a SessionReader over the
#                                 memory and one ProcessInfo per hashtable
#   Invoke-TestArea -Name <Area> -Context [-CapSeconds]
#                                 runs Invoke-DbgEng<Area>Area as the helper
#                                 does: its AreaResult
#   Get-TestEntryFields -Entry    an entry's fields (MemoryEntry, a test's
#                                 PSCustomObject, or an E line) as [ordered]
#   Read-TestCannedEntries -Path  tests\fixtures\memory\canned-*.txt: Entries
#                                 and Areas (see fixtures\memory\README.txt)
#   Assert-KitEqual / Write-KitResult / Complete-KitTest (exit 0 or 1)
# Windows PowerShell 5.1 and PowerShell 7; no admin rights, no dump.
# =============================================================

$script:kitFailures = 0
$script:kitChecks = 0
$script:kitName = "memory test"

function Write-KitResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    $script:kitChecks++
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:kitFailures++
    Write-Host "FAIL: $Name" -ForegroundColor Red
    if ($Message) { Write-Host "  $($Message -replace "`n", "`n  ")" }
    if ($env:GITHUB_ACTIONS) {
        $oneLine = ($Message -replace "`r?`n", " / ")
        Write-Host "::error::$($script:kitName): $Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-KitEqual {
    param([string]$Name, $Expected, $Actual)
    Write-KitResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# The summary line and the exit code (0: every check passed)
function Complete-KitTest {
    if ($script:kitFailures -gt 0) {
        Write-Host "FAIL: $($script:kitFailures) of $($script:kitChecks) check(s) failed ($($script:kitName), PowerShell $($PSVersionTable.PSVersion))" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all $($script:kitChecks) checks passed ($($script:kitName), PowerShell $($PSVersionTable.PSVersion))" -ForegroundColor Green
    exit 0
}

# The top-level functions of a script file, defined in the test's script
# scope (not run: only the function definitions are taken). -Except: names
# to leave out.
function Import-MemoryTestFunctions {
    param([string]$Path, [string[]]$Except = @())
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    if (@($errors).Count -gt 0) { throw "$Path does not parse: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($function in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false))) {
        if ($Except -contains $function.Name) { continue }
        $body = $function.Body.Extent.Text
        Set-Item -LiteralPath "function:script:$($function.Name)" -Value ([scriptblock]::Create($body.Substring(1, $body.Length - 2)))
        $names.Add($function.Name)
    }
    return , $names.ToArray()
}

# The kit's own C#: a sparse memory of 4 KB pages
function Get-MemoryTestKitSource {
    return @'
using System;
using System.Collections.Generic;

namespace TimelineDbgEngTest
{
    public sealed class SparseMemory
    {
        public const int PageSize = 4096;
        readonly Dictionary<string, byte[]> pages = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        readonly HashSet<ulong> refused = new HashSet<ulong>();
        public int Switches;
        public int Reads;

        static ulong Space(ulong process, ulong address) { return address >= 0x8000000000000000UL ? 0 : process; }
        static string Key(ulong space, ulong page) { return space.ToString("x") + "/" + page.ToString("x"); }

        // Bytes at address (pages are made, zeroed, as needed)
        public void Write(ulong process, ulong address, byte[] bytes)
        {
            ulong space = Space(process, address);
            for (int i = 0; i < bytes.Length; i++)
            {
                ulong a = address + (ulong)i;
                string key = Key(space, a >> 12);
                byte[] page;
                if (!pages.TryGetValue(key, out page)) { page = new byte[PageSize]; pages[key] = page; }
                page[(int)(a & 0xFFF)] = bytes[i];
            }
        }
        public void WriteU8(ulong process, ulong address, byte value) { Write(process, address, new byte[] { value }); }
        public void WriteU16(ulong process, ulong address, ushort value) { Write(process, address, BitConverter.GetBytes(value)); }
        public void WriteU32(ulong process, ulong address, uint value) { Write(process, address, BitConverter.GetBytes(value)); }
        public void WriteU64(ulong process, ulong address, ulong value) { Write(process, address, BitConverter.GetBytes(value)); }
        // A 64-bit _UNICODE_STRING at address whose text is at buffer
        public void WriteUnicodeString(ulong process, ulong address, ulong buffer, string text)
        {
            byte[] b = System.Text.Encoding.Unicode.GetBytes(text ?? "");
            WriteU16(process, address, (ushort)b.Length);
            WriteU16(process, address + 2, (ushort)(b.Length + 2));
            WriteU64(process, address + 8, buffer);
            Write(process, buffer, b);
        }
        // The page at address is not in the dump
        public void Remove(ulong process, ulong address) { pages.Remove(Key(Space(process, address), address >> 12)); }
        // The engine cannot switch to this process (an exited one)
        public void Refuse(ulong process) { refused.Add(process); }

        public bool Switch(ulong process) { Switches++; return !refused.Contains(process); }

        // Up to count bytes at address, to the first page not in the dump
        public byte[] Read(ulong process, ulong address, int count)
        {
            Reads++;
            if (count <= 0) return new byte[0];
            ulong space = Space(process, address);
            List<byte> result = new List<byte>(count);
            ulong a = address;
            while (result.Count < count)
            {
                byte[] page;
                if (!pages.TryGetValue(Key(space, a >> 12), out page)) break;
                int offset = (int)(a & 0xFFF);
                int n = Math.Min(PageSize - offset, count - result.Count);
                for (int i = 0; i < n; i++) result.Add(page[offset + i]);
                a += (ulong)n;
            }
            return result.ToArray();
        }
    }
}
'@
}

# Loads the helper's and the area files' functions, compiles their C# and
# the kit's, and captures the protocol lines. -Builder: the builder's
# functions and lib\memory\TimelineMemoryRows.ps1 too (from -BuilderPath, a
# copy of timeline-builder.ps1 with lib\ beside it, or the repository's).
function Initialize-MemoryTestKit {
    param([string]$RepoRoot = (Split-Path $PSScriptRoot -Parent), [switch]$Builder, [string]$BuilderPath = "", [string]$Name = "")
    if ($Name) { $script:kitName = $Name }
    $script:kitRepoRoot = $RepoRoot
    $memory = Join-Path $RepoRoot "lib\memory"
    if ($Builder) {
        if (-not $BuilderPath) { $BuilderPath = Join-Path $RepoRoot "timeline-builder.ps1" }
        $memory = Join-Path (Split-Path $BuilderPath -Parent) "lib\memory"
        [void](Import-MemoryTestFunctions -Path $BuilderPath)
        [void](Import-MemoryTestFunctions -Path (Join-Path $memory "TimelineMemoryRows.ps1"))
        $script:xmlInvalidPattern = '[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]'
        $script:xmlInvalidRegex = New-Object System.Text.RegularExpressions.Regex($script:xmlInvalidPattern)
        $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
        $script:dbgEngEntries = @{}
    }
    # The helper's functions (the builder has functions of the same name,
    # Get-DbgEngShortError and Get-DbgEngErrorText, with the same bodies)
    [void](Import-MemoryTestFunctions -Path (Join-Path $memory "TimelineDbgEng.ps1"))
    $script:DbgEngFileProblems = @{}
    foreach ($file in @(Get-DbgEngAreaFiles)) {
        $path = Join-Path $memory $file
        if (Test-Path -LiteralPath $path -PathType Leaf) { [void](Import-MemoryTestFunctions -Path $path) }
        else { $script:DbgEngFileProblems[(Get-DbgEngFileStem $file)] = "lib\memory\$file is missing" }
    }
    Initialize-DbgEngHost
    if (-not ([System.Management.Automation.PSTypeName]'TimelineDbgEngTest.SparseMemory').Type) { Add-Type -TypeDefinition (Get-MemoryTestKitSource) -ErrorAction Stop }
    $script:testProtocolLines = New-Object System.Collections.Generic.List[string]
    Set-Item -LiteralPath "function:script:Write-DbgEngWorkerLine" -Value { param([string]$Line) $script:testProtocolLines.Add($Line) }
    # Nothing is ever downloaded in a test
    Set-Item -LiteralPath "function:script:Save-KernelSymbolDownload" -Value { param([string]$Url, [string]$Path) throw "the tests download nothing ($Url -> $Path)" }
}

# The protocol lines captured since the last call (-Keep: do not clear)
function Get-TestProtocolLines {
    param([switch]$Keep)
    $lines = $script:testProtocolLines.ToArray()
    if (-not $Keep) { $script:testProtocolLines.Clear() }
    return , $lines
}

function New-TestMemory {
    return (New-Object TimelineDbgEngTest.SparseMemory)
}

function New-TestFuncReader {
    param($Memory)
    $read = [Delegate]::CreateDelegate([Func[uint64, uint64, int, byte[]]], $Memory, "Read")
    return (New-Object TimelineDbgEng.FuncReader -ArgumentList $read)
}

# A SessionReader over the memory, through a FuncProcessMemory (the
# switch refuses the processes the memory refuses)
function New-TestSessionReader {
    param($Memory, [int]$CacheBytes = 64MB)
    $switch = [Delegate]::CreateDelegate([Func[uint64, bool]], $Memory, "Switch")
    $read = [Delegate]::CreateDelegate([Func[uint64, uint64, int, byte[]]], $Memory, "Read")
    $processMemory = New-Object TimelineDbgEng.FuncProcessMemory -ArgumentList $switch, $read
    return (New-Object TimelineDbgEng.SessionReader -ArgumentList $processMemory, $CacheBytes)
}

function New-TestLayout {
    param([hashtable]$Offsets = @{}, [hashtable]$Sizes = @{}, [hashtable]$Bits = @{}, [hashtable]$Symbols = @{})
    $layout = New-Object TimelineDbgEng.Layout
    foreach ($key in $Offsets.Keys) { $layout.Set([string]$key, [int]$Offsets[$key]) }
    foreach ($key in $Sizes.Keys) { $layout.SetSize([string]$key, [int]$Sizes[$key]) }
    foreach ($key in $Bits.Keys) { $layout.SetBits([string]$key, [int]$Bits[$key][0], [int]$Bits[$key][1]) }
    foreach ($key in $Symbols.Keys) { $layout.SetSymbol([string]$key, [uint64]$Symbols[$key]) }
    return $layout
}

# The engine's "dt -v nt!<Type>" text: -Fields @(@(<offset>, <name>,
# <type text>), ...); a bitfield's type text is "Bitfield Pos <p>, <w> Bits"
function New-TestDtText {
    param([string]$Type, [int]$Size, [object[]]$Fields = @(), [string]$Kind = "struct")
    # One field given as @(@(...)) arrives unrolled: @(offset, name, type)
    if (@($Fields).Count -gt 0 -and $Fields[0] -isnot [array]) { $Fields = @(, $Fields) }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$Kind $Type, $(@($Fields).Count) elements, 0x$($Size.ToString('x')) bytes")
    foreach ($field in @($Fields)) { $lines.Add("   +0x$(([int]$field[0]).ToString('x3')) $($field[1].PadRight(16)) : $($field[2])") }
    return ($lines.ToArray() -join "`n") + "`n"
}

# Invoke-DbgEngCommand answers "dt -v nt!<type>" from -Dt (else "Symbol not
# found") and "? <name>" from -Symbols (else the engine's error); any other
# command throws. The commands sent: $script:testEngineCommands.
function Set-TestEngineCommands {
    param([hashtable]$Dt = @{}, [hashtable]$Symbols = @{})
    $script:testDt = $Dt
    $script:testSymbols = $Symbols
    $script:testEngineCommands = New-Object System.Collections.Generic.List[string]
    $script:DbgEngTypeCache = @{}
    Set-Item -LiteralPath "function:script:Invoke-DbgEngCommand" -Value {
        param($Session, [string]$Command, [int]$TimeoutSeconds = 300)
        $null = $Session, $TimeoutSeconds
        $script:testEngineCommands.Add($Command)
        if ($Command -match '^dt -v nt!(\w+)$') {
            if ($script:testDt.ContainsKey($Matches[1])) { return $script:testDt[$Matches[1]] }
            return "Symbol nt!$($Matches[1]) not found.`n"
        }
        if ($Command -match '^\? (\S+)$') {
            if ($script:testSymbols.ContainsKey($Matches[1])) {
                $hex = ([uint64]$script:testSymbols[$Matches[1]]).ToString("x16")
                return "Evaluate expression: -1 = " + $hex.Substring(0, 8) + [char]0x60 + $hex.Substring(8) + "`n"
            }
            return "Couldn't resolve error at '$($Matches[1])'`n"
        }
        throw "the test engine has no answer for: $Command"
    }
}

# A MemoryContext over the memory: one ProcessInfo per hashtable of
# -Processes (keys: the ProcessInfo fields, e.g. Eprocess, Pid, Ppid,
# CreateTime (a FILETIME or a [datetime]), ExitTime, Peb, Wow64, Token,
# Protection, ShortName, FoundBy, Anomaly, Block)
function New-TestContext {
    param($Memory, [object[]]$Processes = @(), $ProcessLayout, $Session, [string]$DumpPath = "C:\dumps\test.dmp", [long]$CaptureFileTime = 0)
    $context = New-Object TimelineDbgEng.MemoryContext
    if ($null -ne $Memory) { $context.Reader = New-TestSessionReader -Memory $Memory }
    if ($null -eq $ProcessLayout) { $ProcessLayout = New-Object TimelineDbgEng.Layout }
    $context.ProcessLayout = $ProcessLayout
    if ($null -ne $Session) { $context.Session = $Session }
    $context.DumpPath = $DumpPath
    $context.CaptureFileTime = $CaptureFileTime
    foreach ($spec in @($Processes)) {
        $info = New-Object TimelineDbgEng.ProcessInfo
        foreach ($key in $spec.Keys) {
            $value = $spec[$key]
            if (($key -eq "CreateTime" -or $key -eq "ExitTime") -and $value -is [datetime]) { $value = $value.ToFileTimeUtc() }
            $info.$key = $value
        }
        $context.Add($info)
    }
    return $context
}

# Runs one area as the helper does (Invoke-DbgEngAreas: its function with
# -Context and -Area, a failure as "it stopped [...]"): its AreaResult
function Invoke-TestArea {
    param([string]$Name, $Context, [double]$CapSeconds = 30)
    $area = New-Object TimelineDbgEng.AreaResult -ArgumentList $Name, $CapSeconds
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try { & "Invoke-DbgEng$($Name)Area" -Context $Context -Area $area }
    catch {
        $why = "it stopped [$(Get-DbgEngShortError (Get-DbgEngErrorText $_))]"
        if ($area.Entries.Count -gt 0 -and $area.State -ne "NotRead") { $area.SetPartial($why) } else { $area.SetNotRead($why) }
    }
    $area.Seconds = $timer.Elapsed.TotalSeconds
    if ($null -ne $Context) { $Context.Areas[$Name] = $area }
    return $area
}

# An entry's fields as [ordered]@{ Kind = ...; <key> = <value>; ... }: a
# MemoryEntry, a test's [PSCustomObject]@{ Kind; Fields }, or an E line
function Get-TestEntryFields {
    param($Entry)
    $fields = [ordered]@{}
    if ($Entry -is [string]) {
        $parts = $Entry.Substring($Entry.IndexOf("TBDBG|") + 6).Split('|')
        if ($parts[0] -ne "E") { throw "not an entry line: $Entry" }
        $fields["Kind"] = $parts[1]
        for ($i = 2; $i -lt $parts.Count; $i++) {
            $colon = $parts[$i].IndexOf(':')
            $text = $parts[$i].Substring($colon + 1)
            $fields[$parts[$i].Substring(0, $colon)] = if ($text) { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($text)) } else { "" }
        }
        return $fields
    }
    if ($Entry.GetType().FullName -eq "TimelineDbgEng.MemoryEntry") {
        $fields["Kind"] = $Entry.Kind
        foreach ($key in $Entry.Keys) { $fields[$key] = $Entry.Get($key) }
        return $fields
    }
    $fields["Kind"] = $Entry.Kind
    foreach ($key in @($Entry.Fields.Keys)) { $fields[$key] = [string]$Entry.Fields[$key] }
    return $fields
}

# The canned entries of tests\fixtures\memory\canned-*.txt (one file or a
# folder of them): Entries (in file order: [PSCustomObject]@{ Kind; Fields })
# and Areas (from "#AREA" lines: Name, State, Rows (its entries), Seconds 0,
# Note). See tests\fixtures\memory\README.txt for the format.
function Read-TestCannedEntries {
    param([string]$Path)
    $files = if (Test-Path -LiteralPath $Path -PathType Container) { @(Get-ChildItem -LiteralPath $Path -Filter "canned-*.txt" -File | Sort-Object Name | ForEach-Object { $_.FullName }) } else { @($Path) }
    $entries = New-Object System.Collections.Generic.List[object]
    $areas = New-Object System.Collections.Generic.List[object]
    foreach ($file in $files) {
        $fileEntries = 0
        $fileAreas = New-Object System.Collections.Generic.List[object]
        foreach ($line in [System.IO.File]::ReadAllLines($file)) {
            if (-not $line.Trim()) { continue }
            if ($line.StartsWith("#AREA`t")) {
                $parts = $line.Split("`t")
                $fileAreas.Add([PSCustomObject]@{ Name = $parts[1]; State = $parts[2]; Rows = 0; Seconds = 0.0; Note = $(if ($parts.Count -gt 3) { $parts[3] } else { "" }) })
                continue
            }
            if ($line.StartsWith("#")) { continue }
            $parts = $line.Split("`t")
            $fields = [ordered]@{}
            for ($i = 1; $i -lt $parts.Count; $i++) {
                $equals = $parts[$i].IndexOf('=')
                if ($equals -lt 1) { throw "$file : not Key=value: $($parts[$i])" }
                $fields[$parts[$i].Substring(0, $equals)] = $parts[$i].Substring($equals + 1)
            }
            $entries.Add([PSCustomObject]@{ Kind = $parts[0]; Fields = $fields })
            $fileEntries++
        }
        foreach ($area in $fileAreas) {
            if ($area.State -ne "NotRead") { $area.Rows = $fileEntries }
            $areas.Add($area)
        }
    }
    return [PSCustomObject]@{ Entries = $entries.ToArray(); Areas = $areas.ToArray() }
}

# The rows the builder added since the last call, as "Source|Timestamp|
# EventType|Description|User|Details" (-Objects: the row objects), one by
# one down the pipeline (wrap the call in @() for an array)
function Get-TestRows {
    param([switch]$Objects, [switch]$Keep)
    $rows = $script:timelineEntries.ToArray()
    if (-not $Keep) { $script:timelineEntries.Clear() }
    if ($Objects) { return $rows }
    foreach ($row in $rows) { "$($row.Source)|$($row.Timestamp)|$($row.EventType)|$($row.Description)|$($row.User)|$($row.Details)" }
}
