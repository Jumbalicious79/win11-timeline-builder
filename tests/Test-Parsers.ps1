# =============================================================
# Parser regression test
# Runs timeline-builder.ps1 on the fixture collection in
# tests\fixtures\av\ and compares the timeline with expected.csv.
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-Parsers.ps1
#   ... -UpdateExpected   rewrite expected.csv from the current output
#                         (only after an intended change; review the diff)
# =============================================================
param(
    [switch]$UpdateExpected,
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$fixtureDir = Join-Path $PSScriptRoot "fixtures\av"
$expectedFile = Join-Path $fixtureDir "expected.csv"
# RawPath is left out: it holds machine-specific absolute paths
$columns = @("Timestamp", "Source", "EventType", "Description", "User", "Details", "Artifact")

# Run the builder with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-test-" + [guid]::NewGuid().ToString("N"))
$reportsDir = Join-Path $repoRoot "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    $timelineCsv = Join-Path $workDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $fixtureDir\collection ..."
    $builderOutput = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath (Join-Path $fixtureDir "collection") -Sources "AntiVirus" `
        -OutputFile $timelineCsv -NoExcel -Viewer None 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-Host "FAIL: the builder exited with code $LASTEXITCODE or wrote no timeline" -ForegroundColor Red
        exit 1
    }

    $actual = @(Import-Csv -LiteralPath $timelineCsv | Select-Object $columns)
    if ($UpdateExpected) {
        $actual | Export-Csv -LiteralPath $expectedFile -NoTypeInformation -Encoding UTF8
        Write-Host "Updated $expectedFile ($($actual.Count) rows). Review the diff before committing." -ForegroundColor Yellow
        exit 0
    }

    # Compare rows as tab-joined text, in order
    $expected = @(Import-Csv -LiteralPath $expectedFile | Select-Object $columns)
    $actualLines = @($actual | ForEach-Object { $row = $_; ($columns | ForEach-Object { $row.$_ }) -join "`t" })
    $expectedLines = @($expected | ForEach-Object { $row = $_; ($columns | ForEach-Object { $row.$_ }) -join "`t" })
    $differences = @(Compare-Object -ReferenceObject $expectedLines -DifferenceObject $actualLines -SyncWindow 0 -CaseSensitive)

    if ($differences.Count -eq 0) {
        Write-Host "PASS: $($actual.Count) rows match expected.csv" -ForegroundColor Green
        $actual | Group-Object Source | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-14} {1,3} rows" -f $_.Name, $_.Count) }
        exit 0
    }

    Write-Host "FAIL: the timeline differs from expected.csv ($($expected.Count) rows expected, $($actual.Count) produced)" -ForegroundColor Red
    foreach ($difference in ($differences | Select-Object -First 20)) {
        $label = if ($difference.SideIndicator -eq "<=") { "missing " } else { "unexpected" }
        Write-Host "  $label $($difference.InputObject)"
        if ($env:GITHUB_ACTIONS) {
            Write-Host "::error file=tests/fixtures/av/expected.csv::$label row: $($difference.InputObject.Substring(0, [Math]::Min(200, $difference.InputObject.Length)))"
        }
    }
    exit 1
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the one from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
