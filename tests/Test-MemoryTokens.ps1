# =============================================================
# Memory test: process users and paths (work package WP1, items a and b: tokens (user, integrity, elevation) and full image paths)
# NOT BUILT YET: this checks only that the area keeps its place -- the
# helper reports it as "not read (not built yet)" and its rows functions in
# lib\memory\TimelineMemoryRows.ps1 add no rows. WP1 replaces it with the
# real tests: synthetic memory through tests\MemoryTestKit.ps1 (no dump in
# CI), its rows and their rules (tests\fixtures\report\rules\cases-memory-*.csv
# are checked by Test-ReportRules.ps1).
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryTokens.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }
try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryTokens"
    $context = New-TestContext -Memory (New-TestMemory)
    $area = Invoke-TestArea -Name "ProcessDetails" -Context $context
    Assert-KitEqual -Name "the ProcessDetails area: not read (not built yet), no entries" -Expected "NotRead|not built yet|0" -Actual "$($area.State)|$($area.Note)|$($area.Entries.Count)"
    $process = [PSCustomObject]@{ PID = 4321; PPID = 3000; ImageFileName = "fixture-stage.e"; Offset = "0xffffa00000001000" }
    [void](Merge-DbgEngProcessEntries -Processes @($process) -ProcEntries @([PSCustomObject]@{ Offset = "0xffffa00000001000"; Pid = "4321" }))
    Set-DbgEngProcessRowFields -Processes @($process) -CommandLines @()
    Register-DbgEngLogonNames -Entries @{ Proc = @([PSCustomObject]@{ Offset = "0xffffa00000001000" }) }
    Assert-KitEqual -Name "the process rows: not built yet, the process entry unchanged (no User, no ExtraDetails)" -Expected "fixture-stage.e||" -Actual "$($process.ImageFileName)|$($process.User)|$($process.ExtraDetails)"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
