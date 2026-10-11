# =============================================================
# Memory test: registry hives in memory (work package WP4, item g)
# NOT BUILT YET: this checks only that the area keeps its place -- the
# helper reports it as "not read (not built yet)" and its rows functions in
# lib\memory\TimelineMemoryRows.ps1 add no rows. WP4 replaces it with the
# real tests: synthetic memory through tests\MemoryTestKit.ps1 (no dump in
# CI), its rows and their rules (tests\fixtures\report\rules\cases-memory-*.csv
# are checked by Test-ReportRules.ps1).
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryRegistry.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }
try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryRegistry"
    $context = New-TestContext -Memory (New-TestMemory)
    $area = Invoke-TestArea -Name "Registry" -Context $context
    Assert-KitEqual -Name "the Registry area: not read (not built yet), no entries" -Expected "NotRead|not built yet|0" -Actual "$($area.State)|$($area.Note)|$($area.Entries.Count)"
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    $counts = Add-DbgEngHiveRows -Entries @([PSCustomObject]@{ PID = "4321" }) -Source "Memory-Test" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    Assert-KitEqual -Name "Add-DbgEngHiveRows: not built yet, no rows" -Expected "0|0|0|0" -Actual "$($counts.Entries)|$($counts.Timed)|$($counts.Snapshot)|$(@(Get-TestRows).Count)"
    $counts = Add-DbgEngRunValueRows -Entries @([PSCustomObject]@{ PID = "4321" }) -Source "Memory-Test" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    Assert-KitEqual -Name "Add-DbgEngRunValueRows: not built yet, no rows" -Expected "0|0|0|0" -Actual "$($counts.Entries)|$($counts.Timed)|$($counts.Snapshot)|$(@(Get-TestRows).Count)"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
