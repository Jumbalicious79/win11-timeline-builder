# =============================================================
# Parser regression test
# Runs timeline-builder.ps1 on every fixture collection in
# tests\fixtures\<name>\ and compares each timeline with its expected
# rows. A fixture folder holds:
#   collection\    the collection passed as -InputPath
#   sources.txt    the -Sources to run (e.g. "AntiVirus"; names separated
#                  by commas or on separate lines)
#   expected.csv   the rows the builder must produce
# Folders with neither sources.txt nor expected.csv are not fixtures of
# this test and are skipped.
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). For a local run without them, pass
# -BuilderPath with a copy of the builder that has no admin check, kept
# inside the repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-Parsers.ps1
#   ... -Fixture setupapi   only the named fixture folder(s)
#   ... -UpdateExpected     rewrite expected.csv from the current output
#                           (only after an intended change; review the
#                           diff). Also creates it for a new fixture.
# =============================================================
param(
    [switch]$UpdateExpected,
    # Fixture folder name(s) to run (default: all)
    [string[]]$Fixture = @(),
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$builder = (Resolve-Path -LiteralPath $builder).Path
$builderDir = Split-Path $builder -Parent
$fixturesRoot = Join-Path $PSScriptRoot "fixtures"
# RawPath is left out: it holds machine-specific absolute paths
$columns = @("Timestamp", "Source", "EventType", "Description", "User", "Details", "Artifact")
$script:failures = 0

# FAIL line, annotated on GitHub Actions
function Write-Failure {
    param([string]$Message, [string]$File = "tests/Test-Parsers.ps1")
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=${File}::$($Message.Substring(0, [Math]::Min(300, $Message.Length)))" }
}

# The builder refuses to run without Administrator rights and then waits
# at a "pause" (a -BuilderPath copy may not need them)
if (-not $BuilderPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Failure -Message "Administrator rights are required (the builder needs them). Run elevated, or pass -BuilderPath with a builder copy without the admin check."
        exit 1
    }
}

# Fixture folders: every folder with a sources.txt or an expected.csv
$Fixture = @($Fixture | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$fixtureDirs = @(Get-ChildItem -LiteralPath $fixturesRoot -Directory | Where-Object {
        (Test-Path -LiteralPath (Join-Path $_.FullName "sources.txt")) -or (Test-Path -LiteralPath (Join-Path $_.FullName "expected.csv"))
    } | Sort-Object Name)
if ($Fixture.Count -gt 0) {
    foreach ($name in $Fixture) {
        if (-not ($fixtureDirs | Where-Object { $_.Name -eq $name })) { Write-Failure -Message "no fixture folder tests\fixtures\$name with a sources.txt or expected.csv" }
    }
    $fixtureDirs = @($fixtureDirs | Where-Object { $Fixture -contains $_.Name })
}
if ($fixtureDirs.Count -eq 0) {
    Write-Failure -Message "no fixture to run in $fixturesRoot"
    exit 1
}

# Run the builder with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path

# Runs the builder on a collection (CSV only); returns its exit code and output
function Invoke-TimelineBuilder {
    param([string]$CollectionPath, [string]$Sources, [string]$OutputFile)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath $CollectionPath -Sources $Sources -OutputFile $OutputFile -NoExcel -NoReport -Viewer None 2>&1
    return [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Lines = @($output | ForEach-Object { "$_" }) }
}

# A row as tab-joined text of the compared columns
function ConvertTo-RowLine {
    param($Row)
    return ($columns | ForEach-Object { $Row.$_ }) -join "`t"
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-test-" + [guid]::NewGuid().ToString("N"))
$reportsDir = Join-Path $builderDir "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    foreach ($dir in $fixtureDirs) {
        $name = $dir.Name
        $expectedFile = Join-Path $dir.FullName "expected.csv"
        $expectedRef = "tests/fixtures/$name/expected.csv"
        $sourcesFile = Join-Path $dir.FullName "sources.txt"
        $collection = Join-Path $dir.FullName "collection"
        Write-Host ""
        if (-not (Test-Path -LiteralPath $sourcesFile)) {
            Write-Failure -Message "[$name] no sources.txt (the -Sources to run)" -File $expectedRef
            continue
        }
        $sources = @(Get-Content -LiteralPath $sourcesFile | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ","
        if (-not $sources) {
            Write-Failure -Message "[$name] sources.txt names no source" -File "tests/fixtures/$name/sources.txt"
            continue
        }
        if (-not (Test-Path -LiteralPath $collection -PathType Container)) {
            Write-Failure -Message "[$name] no collection folder" -File $expectedRef
            continue
        }
        if (-not $UpdateExpected -and -not (Test-Path -LiteralPath $expectedFile)) {
            Write-Failure -Message "[$name] no expected.csv (create it with -UpdateExpected and review it)" -File "tests/fixtures/$name/sources.txt"
            continue
        }

        $timelineCsv = Join-Path $workDir "$name.csv"
        Write-Host "[$name] Running the builder ($powershellExe) on $collection with -Sources $sources ..."
        $run = Invoke-TimelineBuilder -CollectionPath $collection -Sources $sources -OutputFile $timelineCsv
        if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
            $run.Lines | ForEach-Object { Write-Host "  | $_" }
            Write-Failure -Message "[$name] the builder exited with code $($run.ExitCode) or wrote no timeline" -File $expectedRef
            continue
        }

        $actual = @(Import-Csv -LiteralPath $timelineCsv | Select-Object $columns)
        if ($UpdateExpected) {
            # UTF-8 with BOM and CRLF in both PowerShell editions
            $csvLines = @($actual | ConvertTo-Csv -NoTypeInformation)
            [System.IO.File]::WriteAllLines($expectedFile, [string[]]$csvLines, (New-Object System.Text.UTF8Encoding($true)))
            Write-Host "[$name] Updated $expectedFile ($($actual.Count) rows). Review the diff before committing." -ForegroundColor Yellow
            continue
        }

        # Compare rows as tab-joined text, in order
        $expected = @(Import-Csv -LiteralPath $expectedFile | Select-Object $columns)
        $actualLines = @($actual | ForEach-Object { ConvertTo-RowLine $_ })
        $expectedLines = @($expected | ForEach-Object { ConvertTo-RowLine $_ })
        $differences = @(Compare-Object -ReferenceObject $expectedLines -DifferenceObject $actualLines -SyncWindow 0 -CaseSensitive)

        if ($differences.Count -eq 0) {
            Write-Host "PASS: [$name] $($actual.Count) rows match expected.csv" -ForegroundColor Green
            $actual | Group-Object Source, EventType | Sort-Object Name | ForEach-Object {
                Write-Host ("  {0,-14} {1,-14} {2,3} rows" -f $_.Group[0].Source, $_.Group[0].EventType, $_.Count)
            }
            continue
        }

        Write-Failure -Message "[$name] the timeline differs from expected.csv ($($expected.Count) rows expected, $($actual.Count) produced)" -File $expectedRef
        foreach ($difference in ($differences | Select-Object -First 20)) {
            $label = if ($difference.SideIndicator -eq "<=") { "missing " } else { "unexpected" }
            Write-Host "  $label $($difference.InputObject)"
            if ($env:GITHUB_ACTIONS) {
                Write-Host "::error file=${expectedRef}::$label row: $($difference.InputObject.Substring(0, [Math]::Min(200, $difference.InputObject.Length)))"
            }
        }
    }
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\ next to
    # it; remove the ones from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) failure(s) in $($fixtureDirs.Count) fixture(s)" -ForegroundColor Red
    exit 1
}
if ($UpdateExpected) { exit 0 }
Write-Host "PASS: all $($fixtureDirs.Count) fixture(s) match" -ForegroundColor Green
exit 0
