# =============================================================
# Console mode test
# With QuickEdit on, a click in a console window starts a text selection,
# and while it is shown every write to the console waits. The builder's
# Log functions write to the console before the log file, so a stray
# click stopped whole runs. The builder turns QuickEdit off for the run
# and puts the console's mode back at the end. Checks:
#  - Get-ConsoleModeWithoutQuickEdit on known modes: QuickEdit cleared,
#    ENABLE_EXTENDED_FLAGS set (needed for the change), other bits kept;
#  - Disable-ConsoleQuickEdit and Restore-ConsoleMode in a child
#    PowerShell whose input is redirected (as in CI or a script run with
#    redirected input): nothing changed, no error and no output, also
#    when called twice (the type is compiled once);
#  - the same in a child with a new, hidden console of its own (never the
#    console this test runs in): QuickEdit off after
#    Disable-ConsoleQuickEdit, still off after a Read-Host (the child
#    types the answer into its own console), and the mode from before
#    after Restore-ConsoleMode. Skipped when the child gets no console of
#    its own;
#  - in the builder's syntax tree, that QuickEdit is turned off at the
#    start of the main body, before its first long step, with the log
#    line, and put back last in the main body's finally block.
# Only Get-ConsoleModeWithoutQuickEdit is loaded here (from the builder's
# AST), so the script itself and its Administrator check do not run, and
# the console of this test is never changed: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ConsoleMode.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param(
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$builder = [System.IO.Path]::GetFullPath($builder)
$script:failures = 0
$script:checks = 0
$expectedLogLine = "Console QuickEdit is off for this run, so a click in the window cannot pause it (copy text with the window menu: Edit > Mark)."

function Write-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    $script:checks++
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Name" -ForegroundColor Red
    if ($Message) { Write-Host "  $($Message -replace "`n", "`n  ")" }
    if ($env:GITHUB_ACTIONS) {
        $oneLine = ($Message -replace "`r?`n", " / ")
        Write-Host "::error file=tests/Test-ConsoleMode.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

function Format-Mode {
    param($Mode)
    if ($null -eq $Mode) { return "null" }
    return ('0x{0:X4}' -f [uint32]$Mode)
}

# --- The builder's syntax tree ----------------------------------------------
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-TestResult -Name "builder parses" -Passed $false -Message "$($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
    exit 1
}

# The function named $Name outside every other function, or $null
function Get-BuilderFunction {
    param([string]$Name)
    $functionName = $Name
    return @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)) | Select-Object -First 1
}

# The builder's commands named -Name that are outside every function (the
# script's main flow)
function Find-MainFlowCommand {
    param([string]$Name)
    # Read here: PSReviewUnusedParameter does not see uses inside the predicate
    $commandName = $Name
    return @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -like $commandName }, $true) | Where-Object {
            $parent = $_.Parent
            while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
            $null -eq $parent
        })
}

# $true when $Inner is $Outer or inside it
function Test-AstWithin {
    param($Inner, $Outer)
    for ($node = $Inner; $node; $node = $node.Parent) { if ($node -eq $Outer) { return $true } }
    return $false
}

# A child PowerShell of this test's edition
$childExe = (Get-Process -Id $PID).Path
$childScript = @'
param([string]$BuilderPath, [string]$Mode, [string]$ResultPath)
$ErrorActionPreference = "Stop"
$result = [ordered]@{}
function Format-Mode {
    param($Mode)
    if ($null -eq $Mode) { return "null" }
    return ('0x{0:X4}' -f [uint32]$Mode)
}
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($BuilderPath, [ref]$null, [ref]$null)
    $names = @('Get-ConsoleModeWithoutQuickEdit', 'Disable-ConsoleQuickEdit', 'Restore-ConsoleMode')
    foreach ($functionAst in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $node.Name }, $true)) {
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }
    if ($Mode -eq "Redirected") {
        # Input is a pipe: nothing may change and nothing may be written
        $first = Disable-ConsoleQuickEdit
        $result.TypeCompiled = [bool](([System.Management.Automation.PSTypeName]'TimelineNative.ConsoleMode').Type)
        $second = Disable-ConsoleQuickEdit
        Restore-ConsoleMode $first
        Restore-ConsoleMode ([uint32]0x01F7)
        $result.First = Format-Mode $first
        $result.Second = Format-Mode $second
    }
    else {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace TimelineConsoleTest {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KEY_EVENT_RECORD { public int bKeyDown; public ushort wRepeatCount; public ushort wVirtualKeyCode; public ushort wVirtualScanCode; public char UnicodeChar; public uint dwControlKeyState; }
    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct INPUT_RECORD { [FieldOffset(0)] public ushort EventType; [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent; }
    public static class Native {
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern uint GetConsoleProcessList(uint[] lpdwProcessList, uint dwProcessCount);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool WriteConsoleInputW(IntPtr hConsoleInput, INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsWritten);
        public static long GetMode() { uint mode; if (GetConsoleMode(GetStdHandle(-10), out mode)) { return mode; } return -1; }
        public static bool SetMode(uint mode) { return SetConsoleMode(GetStdHandle(-10), mode); }
        public static uint ProcessCount() { uint[] list = new uint[16]; return GetConsoleProcessList(list, (uint)list.Length); }
        // Key down and key up for each character, as typed
        public static bool Type(string text) {
            INPUT_RECORD[] records = new INPUT_RECORD[text.Length * 2];
            for (int i = 0; i < text.Length; i++) {
                char c = text[i];
                ushort key = c == '\r' ? (ushort)0x0D : (ushort)char.ToUpperInvariant(c);
                for (int up = 0; up < 2; up++) {
                    records[i * 2 + up].EventType = 1;
                    records[i * 2 + up].KeyEvent.bKeyDown = up == 0 ? 1 : 0;
                    records[i * 2 + up].KeyEvent.wRepeatCount = 1;
                    records[i * 2 + up].KeyEvent.wVirtualKeyCode = key;
                    records[i * 2 + up].KeyEvent.UnicodeChar = c;
                }
            }
            uint written;
            return WriteConsoleInputW(GetStdHandle(-10), records, (uint)records.Length, out written) && written == records.Length;
        }
    }
}
"@
        $initial = [TimelineConsoleTest.Native]::GetMode()
        if ($initial -lt 0) { $result.Status = "no console input" }
        elseif ([TimelineConsoleTest.Native]::ProcessCount() -ne 1) {
            # Never change a console another process uses
            $result.Status = "console shared with another process"
        }
        else {
            # A known start: QuickEdit on
            $start = [uint32]($initial -bor 0xC0)
            [void][TimelineConsoleTest.Native]::SetMode($start)
            $result.Start = Format-Mode ([TimelineConsoleTest.Native]::GetMode())
            $original = Disable-ConsoleQuickEdit
            $result.Returned = Format-Mode $original
            $result.AfterDisable = Format-Mode ([TimelineConsoleTest.Native]::GetMode())
            $result.SecondReturned = Format-Mode (Disable-ConsoleQuickEdit)
            if ([TimelineConsoleTest.Native]::Type("42`r")) {
                $result.ReadHost = "$(Read-Host 'Answer')"
                $result.AfterReadHost = Format-Mode ([TimelineConsoleTest.Native]::GetMode())
            }
            else { $result.ReadHost = "(could not type into the console)" }
            Restore-ConsoleMode $original
            $result.AfterRestore = Format-Mode ([TimelineConsoleTest.Native]::GetMode())
            [void][TimelineConsoleTest.Native]::SetMode([uint32]$initial)
            $result.Status = "ok"
        }
    }
}
catch { $result.Error = "$($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
$json = $result | ConvertTo-Json -Compress
if ($ResultPath) { [System.IO.File]::WriteAllText($ResultPath, $json) }
else { Write-Output "RESULT $json" }
'@

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "TimelineConsoleTest_$([guid]::NewGuid().ToString('N'))"
try {
    [void][System.IO.Directory]::CreateDirectory($tempDir)
    $childPath = Join-Path $tempDir "Child-ConsoleMode.ps1"
    [System.IO.File]::WriteAllText($childPath, $childScript, (New-Object System.Text.UTF8Encoding($true)))

    # --- Get-ConsoleModeWithoutQuickEdit ---------------------------------------
    Write-Host "Testing Get-ConsoleModeWithoutQuickEdit ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."
    . ([scriptblock]::Create((Get-BuilderFunction "Get-ConsoleModeWithoutQuickEdit").Extent.Text))
    $cases = @(
        @{ Name = "QuickEdit on (a console's usual mode)"; Mode = 0x01F7; Expected = 0x01B7 },
        @{ Name = "QuickEdit already off: unchanged"; Mode = 0x01B7; Expected = 0x01B7 },
        @{ Name = "extended flag missing: added, so the change takes effect"; Mode = 0x0007; Expected = 0x0087 },
        @{ Name = "QuickEdit on, extended flag missing"; Mode = 0x0047; Expected = 0x0087 },
        @{ Name = "virtual terminal input and other bits kept"; Mode = 0x03F7; Expected = 0x03B7 },
        @{ Name = "no bits"; Mode = 0x0000; Expected = 0x0080 },
        @{ Name = "every bit (no sign trouble in 5.1)"; Mode = [uint32]::MaxValue; Expected = [uint32]0xFFFFFFBFL }
    )
    foreach ($case in $cases) {
        $actual = Get-ConsoleModeWithoutQuickEdit ([uint32]$case.Mode)
        Assert-Equal -Name "mode without QuickEdit: $($case.Name) ($(Format-Mode $case.Mode))" -Expected (Format-Mode $case.Expected) -Actual (Format-Mode $actual)
    }
    Assert-Equal -Name "mode without QuickEdit: a UInt32, as SetConsoleMode takes it" -Expected "System.UInt32" -Actual (Get-ConsoleModeWithoutQuickEdit 0x01F7).GetType().FullName

    # --- No console input: a child with redirected input -----------------------
    Write-Host "Testing Disable-ConsoleQuickEdit and Restore-ConsoleMode with redirected input ..."
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $childExe
    $startInfo.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$childPath`" -BuilderPath `"$builder`" -Mode Redirected"
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $child = [System.Diagnostics.Process]::Start($startInfo)
    $child.StandardInput.Close()
    $stdoutTask = $child.StandardOutput.ReadToEndAsync()
    $stderrTask = $child.StandardError.ReadToEndAsync()
    if (-not $child.WaitForExit(120000)) {
        $child.Kill()
        Write-TestResult -Name "redirected input: the child finishes" -Passed $false -Message "no exit after 120 s"
    }
    else {
        $child.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        Assert-Equal -Name "redirected input: the child exits with 0" -Expected 0 -Actual $child.ExitCode
        Assert-Equal -Name "redirected input: no error output" -Expected "" -Actual $stderr.Trim()
        $resultLines = @($stdout -split "`r?`n" | Where-Object { $_ -like "RESULT *" })
        $otherLines = @($stdout -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notlike "RESULT *" })
        Assert-Equal -Name "redirected input: the helpers write no output" -Expected "" -Actual ($otherLines -join " / ")
        if ($resultLines.Count -ne 1) {
            Write-TestResult -Name "redirected input: the child reports its result" -Passed $false -Message "stdout: $stdout"
        }
        else {
            $result = $resultLines[0].Substring(7) | ConvertFrom-Json
            Assert-Equal -Name "redirected input: no error in the child" -Expected "" -Actual "$($result.Error)"
            Assert-Equal -Name "redirected input: the console type compiles (Add-Type)" -Expected "True" -Actual "$($result.TypeCompiled)"
            Assert-Equal -Name "redirected input: Disable-ConsoleQuickEdit changes nothing (returns null)" -Expected "null" -Actual "$($result.First)"
            Assert-Equal -Name "redirected input: a second call (type already there) changes nothing" -Expected "null" -Actual "$($result.Second)"
        }
    }

    # --- A console of the child's own ----------------------------------------
    Write-Host "Testing Disable-ConsoleQuickEdit and Restore-ConsoleMode in a new hidden console ..."
    $resultPath = Join-Path $tempDir "console-result.json"
    $consoleChild = $null
    try {
        $consoleChild = Start-Process -FilePath $childExe -WindowStyle Hidden -PassThru -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$childPath`"", "-BuilderPath", "`"$builder`"", "-Mode", "Console", "-ResultPath", "`"$resultPath`"")
    }
    catch { Write-Host "SKIP: new console: could not start a child with its own console ($($_.Exception.Message))" -ForegroundColor Yellow }
    if ($consoleChild) {
        if (-not $consoleChild.WaitForExit(120000)) {
            $consoleChild.Kill()
            Write-TestResult -Name "new console: the child finishes" -Passed $false -Message "no exit after 120 s (Read-Host waiting?)"
        }
        elseif (-not (Test-Path -LiteralPath $resultPath)) {
            Write-TestResult -Name "new console: the child reports its result" -Passed $false -Message "exit code $($consoleChild.ExitCode), no result file"
        }
        else {
            $result = [System.IO.File]::ReadAllText($resultPath) | ConvertFrom-Json
            if ("$($result.Error)") {
                Write-TestResult -Name "new console: no error in the child" -Passed $false -Message "$($result.Error)"
            }
            elseif ($result.Status -ne "ok") {
                Write-Host "SKIP: new console: $($result.Status)" -ForegroundColor Yellow
            }
            else {
                $start = [Convert]::ToUInt32("$($result.Start)".Substring(2), 16)
                Assert-Equal -Name "new console: Disable-ConsoleQuickEdit returns the mode from before" -Expected $result.Start -Actual $result.Returned
                Assert-Equal -Name "new console: QuickEdit off, extended flags on, other bits kept" -Expected (Format-Mode (Get-ConsoleModeWithoutQuickEdit $start)) -Actual $result.AfterDisable
                Assert-Equal -Name "new console: a second call changes nothing (returns null)" -Expected "null" -Actual $result.SecondReturned
                Assert-Equal -Name "new console: Read-Host reads the answer with QuickEdit off" -Expected "42" -Actual $result.ReadHost
                $afterReadHost = [Convert]::ToUInt32("$($result.AfterReadHost)".Substring(2), 16)
                Assert-Equal -Name "new console: QuickEdit still off after Read-Host" -Expected "0x0000 0x0080" -Actual "$(Format-Mode ($afterReadHost -band 0x40)) $(Format-Mode ($afterReadHost -band 0x80))"
                Assert-Equal -Name "new console: Restore-ConsoleMode puts back the mode from before" -Expected $result.Start -Actual $result.AfterRestore
            }
        }
    }

    # --- Where the builder calls them ----------------------------------------
    Write-Host "Testing where the builder turns QuickEdit off and back on ..."
    $topStatements = @($ast.EndBlock.Statements)
    $mainTry = $topStatements[-1]
    Write-TestResult -Name "main body: the script ends with its try/finally" -Passed ($mainTry -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $mainTry.Finally) -Message "last statement: $($mainTry.Extent.StartLineNumber)"
    $disableCalls = @(Find-MainFlowCommand -Name "Disable-ConsoleQuickEdit")
    Assert-Equal -Name "Disable-ConsoleQuickEdit: called once in the main flow" -Expected 1 -Actual $disableCalls.Count
    if ($mainTry -is [System.Management.Automation.Language.TryStatementAst] -and $disableCalls.Count -eq 1) {
        $disableStatement = $disableCalls[0].Parent
        while ($disableStatement -and $disableStatement.Parent -ne $mainTry.Body) { $disableStatement = $disableStatement.Parent }
        $bodyStatements = @($mainTry.Body.Statements)
        $disableIndex = [array]::IndexOf($bodyStatements, $disableStatement)
        Write-TestResult -Name "Disable-ConsoleQuickEdit: the first statement of the main body (so every exit after it passes the finally block)" -Passed ($disableIndex -eq 0) -Message "statement index $disableIndex in the main body"
        Assert-Equal -Name "Disable-ConsoleQuickEdit: its result is kept for the restore" -Expected '$script:consoleModeToRestore = Disable-ConsoleQuickEdit' -Actual $disableStatement.Extent.Text

        # Before the first long step and every exit of the main body
        $disableOffset = $disableCalls[0].Extent.StartOffset
        foreach ($stepName in @("New-RunWorkFolder", "Expand-CollectionZip", "Add-ManifestInputFiles", "Parse-*")) {
            $stepCalls = @(Find-MainFlowCommand -Name $stepName | Where-Object { Test-AstWithin $_ $mainTry.Body })
            Write-TestResult -Name "Disable-ConsoleQuickEdit: before $stepName in the main body" -Passed ($stepCalls.Count -gt 0 -and @($stepCalls | Where-Object { $_.Extent.StartOffset -lt $disableOffset }).Count -eq 0) -Message "$($stepCalls.Count) call(s); first at line $(@($stepCalls | Sort-Object { $_.Extent.StartOffset })[0].Extent.StartLineNumber)"
        }
        $exits = @($mainTry.Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true) | Where-Object {
                $parent = $_.Parent
                while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
                $null -eq $parent
            })
        Write-TestResult -Name "Disable-ConsoleQuickEdit: before every exit of the main body" -Passed ($exits.Count -gt 0 -and @($exits | Where-Object { $_.Extent.StartOffset -lt $disableOffset }).Count -eq 0) -Message "$($exits.Count) exit(s)"

        # The log line, only when the mode was changed
        $logStatement = if ($bodyStatements.Count -gt 1) { $bodyStatements[1] } else { $null }
        $logCalls = @()
        if ($logStatement -is [System.Management.Automation.Language.IfStatementAst] -and $logStatement.Clauses.Count -eq 1 -and -not $logStatement.ElseClause) {
            Assert-Equal -Name "log line: only when the mode was changed" -Expected '$null -ne $script:consoleModeToRestore' -Actual $logStatement.Clauses[0].Item1.Extent.Text
            $logCalls = @($logStatement.Clauses[0].Item2.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Log" }, $true))
        }
        $logText = if ($logCalls.Count -eq 1 -and $logCalls[0].CommandElements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $logCalls[0].CommandElements[1].Value } else { "(no Log call with a constant text right after it)" }
        Assert-Equal -Name "log line: right after Disable-ConsoleQuickEdit, the agreed text" -Expected $expectedLogLine -Actual $logText

        # Put back last, also when the clean-up fails
        $restoreCalls = @(Find-MainFlowCommand -Name "Restore-ConsoleMode")
        Assert-Equal -Name "Restore-ConsoleMode: called once in the main flow" -Expected 1 -Actual $restoreCalls.Count
        if ($restoreCalls.Count -eq 1) {
            Assert-Equal -Name "Restore-ConsoleMode: given the mode Disable-ConsoleQuickEdit returned" -Expected 'Restore-ConsoleMode $script:consoleModeToRestore' -Actual $restoreCalls[0].Extent.Text
            $cleanupTry = @($mainTry.Finally.Statements) | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] } | Select-Object -First 1
            $inInnerFinally = $null -ne $cleanupTry -and $null -ne $cleanupTry.Finally -and (Test-AstWithin $restoreCalls[0] $cleanupTry.Finally)
            Write-TestResult -Name "Restore-ConsoleMode: in the main body's finally block, in a finally of its own (runs also when the clean-up fails)" -Passed $inInnerFinally -Message "line $($restoreCalls[0].Extent.StartLineNumber)"
            $cleanupCalls = @(Find-MainFlowCommand -Name "Remove-RunWorkFolder") + @(Find-MainFlowCommand -Name "Dismount-RunHives")
            $cleanupInFinally = @($cleanupCalls | Where-Object { $null -ne $cleanupTry -and (Test-AstWithin $_ $cleanupTry.Body) })
            Write-TestResult -Name "Restore-ConsoleMode: after the hives and the work folder (a click cannot pause the clean-up)" -Passed ($cleanupInFinally.Count -eq 2) -Message "$($cleanupInFinally.Count) of Dismount-RunHives / Remove-RunWorkFolder in the try block before it"
        }
    }

    # --- The helpers themselves ---------------------------------------------
    $disableFunction = Get-BuilderFunction "Disable-ConsoleQuickEdit"
    $addTypes = @($disableFunction.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Add-Type" }, $true))
    $guarded = $addTypes.Count -eq 1
    if ($guarded) {
        $guard = $addTypes[0].Parent
        while ($guard -and -not ($guard -is [System.Management.Automation.Language.IfStatementAst])) { $guard = $guard.Parent }
        $tryAround = $addTypes[0].Parent
        while ($tryAround -and -not ($tryAround -is [System.Management.Automation.Language.TryStatementAst])) { $tryAround = $tryAround.Parent }
        $guarded = $guard -and $guard.Clauses[0].Item1.Extent.Text -match "PSTypeName\]'TimelineNative\.ConsoleMode'\)\.Type" -and
            $tryAround -and $tryAround.CatchClauses.Count -gt 0 -and $addTypes[0].Extent.Text -match '-ErrorAction Stop'
    }
    Write-TestResult -Name "Disable-ConsoleQuickEdit: Add-Type only when the type is not there yet, failures caught" -Passed $guarded -Message "$($addTypes.Count) Add-Type call(s)"
    $throws = @(foreach ($name in @("Get-ConsoleModeWithoutQuickEdit", "Disable-ConsoleQuickEdit", "Restore-ConsoleMode")) {
            (Get-BuilderFunction $name).FindAll({ param($node) $node -is [System.Management.Automation.Language.ThrowStatementAst] }, $true)
        })
    Assert-Equal -Name "console helpers: no throw statement" -Expected 0 -Actual $throws.Count
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
