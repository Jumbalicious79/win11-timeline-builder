# =============================================================
# ShimCache parser test
# Builds a synthetic Windows 10/11 AppCompatCache (ShimCache) value and
# saves it in a synthetic collection as Execution\appcompat_cache.reg, the
# way the collector does ("reg query ... /v AppCompatCache" output), then
# runs the PowerShellHistory parser (it also reads BAM and the ShimCache) on
# it. An entry with a file time must be a FileLastModified row at that
# time: the time is the file's last-modified time, not an execution time,
# so the row must not be Execution. An entry without a time must be a
# Snapshot row at the collection time (a packaged app once, not once per
# architecture). The same value in a regedit export ("AppCompatCache"=hex:
# ..., UTF-16) must give the same rows. It also checks that the Excel color
# map has FileLastModified in tan (E2C9A0) and that the console color
# legend lists exactly the EventTypes of the color map.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ShimCacheParser.ps1
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
$script:failures = 0
$script:checks = 0

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
        Write-Host "::error file=tests/Test-ShimCacheParser.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# --- Load the builder's functions ------------------------------------------
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-TestResult -Name "builder parses" -Passed $false -Message "$($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
    exit 1
}
$functionAsts = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
        $parent = $_.Parent
        while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
        $null -eq $parent
    })
foreach ($functionAst in $functionAsts) { . ([scriptblock]::Create($functionAst.Extent.Text)) }
# The XML-invalid character filter used by Add-TimelineEntry
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        @('$script:xmlInvalidPattern', '$script:xmlInvalidRegex') -contains $node.Left.Extent.Text }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

# --- Synthetic AppCompatCache value -----------------------------------------
# Windows 10/11 layout (see ConvertFrom-AppCompatCacheBinary): a 0x34-byte
# header that starts with its size, then per entry "10ts", 4 unknown bytes,
# the size of the rest of the entry, the path length, the UTF-16 path, the
# FILETIME (0 = none), the data length and the data
function New-ShimCacheValue {
    param([object[]]$Entries)
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    $writer.Write([uint32]0x34)
    $writer.Write((New-Object byte[] (0x34 - 4)))
    foreach ($entry in $Entries) {
        $pathBytes = [System.Text.Encoding]::Unicode.GetBytes($entry.Path)
        $data = New-Object byte[] $entry.DataLength
        $writer.Write([System.Text.Encoding]::ASCII.GetBytes("10ts"))
        $writer.Write([uint32]0x5EED5EED)
        $writer.Write([uint32](2 + $pathBytes.Length + 8 + 4 + $data.Length))
        $writer.Write([uint16]$pathBytes.Length)
        $writer.Write($pathBytes)
        $writer.Write([long]$entry.FileTime)
        $writer.Write([uint32]$data.Length)
        $writer.Write($data)
    }
    $writer.Flush()
    return , $stream.ToArray()
}

# "reg query <key> /v AppCompatCache" output, as the collector saves it
function ConvertTo-RegQueryText {
    param([byte[]]$Value)
    $hex = [BitConverter]::ToString($Value) -replace '-', ''
    return "`r`nHKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`r`n    AppCompatCache    REG_BINARY    $hex`r`n`r`n"
}

# A regedit export: hex:xx,xx,... wrapped with ",\" and an indent
function ConvertTo-RegExportText {
    param([byte[]]$Value)
    $pairs = @($Value | ForEach-Object { $_.ToString("x2") })
    $lines = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $pairs.Count; $i += 24) {
        $lines.Add(($pairs[$i..([Math]::Min($i + 23, $pairs.Count - 1))] -join ","))
    }
    return "Windows Registry Editor Version 5.00`r`n`r`n[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache]`r`n" +
        '"AppCompatCache"=hex:' + ($lines -join ",\`r`n  ") + "`r`n`r`n"
}

# Run Parse-PowerShellHistory on a synthetic collection (collected on
# 2025-06-30 12:00 UTC) whose Execution\appcompat_cache.reg has -Text: its
# rows as "Timestamp|Source|EventType|Description|Details|Artifact|RawPath"
# and what was logged
function Invoke-ShimCacheParser {
    param([string]$Name, [string]$Text, [System.Text.Encoding]$Encoding)
    $collection = Join-Path $testRoot $Name
    New-Item -ItemType Directory -Path (Join-Path $collection "Execution") -Force | Out-Null
    $info = '{ "SchemaVersion": 1, "Mode": "Live", "CollectionStartUtc": "2025-06-30T12:00:00Z", "CollectorTimeZoneId": "UTC", "TargetTimeZoneId": "UTC" }'
    [System.IO.File]::WriteAllText((Join-Path $collection "collection_info.json"), $info)
    $regFile = Join-Path $collection "Execution\appcompat_cache.reg"
    [System.IO.File]::WriteAllText($regFile, $Text, $Encoding)
    $script:InputPath = $collection
    $script:collectionRoot = $collection
    $script:collectionInfo = $null
    $script:collectionManifest = $null
    $script:manifestTimes = $null
    $script:shortenedNames = @{}
    $script:logFile = Join-Path $testRoot "$Name.log"
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    Parse-PowerShellHistory 6>$null | Out-Null
    return [PSCustomObject]@{
        Rows    = @($script:timelineEntries | ForEach-Object { "$($_.Timestamp)|$($_.Source)|$($_.EventType)|$($_.Description)|$($_.Details)|$($_.Artifact)|$($_.RawPath)" })
        Log     = [System.IO.File]::ReadAllText($script:logFile)
        RegFile = $regFile
    }
}

# Entries in cache order (CachePosition 1 = most recent). Made up: paths,
# package name and publisher ID.
$packaged = "0005000A`t0001`tPackage`t{0}`tContoso.SyntheticApp`t0123456789abc"
$cacheEntries = @(
    @{ Path = "C:\Tools\TestApp\testapp.exe"; FileTime = [datetime]::new(2025, 6, 29, 18, 45, 12, 345, [System.DateTimeKind]::Utc).AddTicks(6789).ToFileTimeUtc(); DataLength = 6 },
    @{ Path = ($packaged -f "x64"); FileTime = 0; DataLength = 0 },
    @{ Path = ($packaged -f "x86"); FileTime = 0; DataLength = 0 },
    @{ Path = "C:\Program Files\Synthetic\old.exe"; FileTime = [datetime]::new(2013, 8, 22, 11, 0, 0, [System.DateTimeKind]::Utc).ToFileTimeUtc(); DataLength = 0 },
    @{ Path = "C:\Tools\NoTime\notime.exe"; FileTime = 0; DataLength = 4 }
)
$shimValue = New-ShimCacheValue -Entries $cacheEntries

# The rows of $cacheEntries from the file at -RawPath
function Get-ExpectedShimRows {
    param([string]$RawPath)
    $fileTime = "Time=file last-modified time (NOT an execution time)"
    $noTime = "No file time in cache entry; listed at collection time"
    return @(
        "2025-06-29 18:45:12.345|AppCompatCache|FileLastModified|ShimCache entry (file last modified): C:\Tools\TestApp\testapp.exe|$fileTime; CachePosition=1 of 5 (1 = most recent)|Registry|$RawPath",
        "2025-06-30 12:00:00.000|AppCompatCache|Snapshot|ShimCache entry: Contoso.SyntheticApp_0123456789abc|Packaged app; Arch=x64; $noTime; CachePosition=2 of 5 (1 = most recent)|Registry|$RawPath",
        "2013-08-22 11:00:00.000|AppCompatCache|FileLastModified|ShimCache entry (file last modified): C:\Program Files\Synthetic\old.exe|$fileTime; CachePosition=4 of 5 (1 = most recent)|Registry|$RawPath",
        "2025-06-30 12:00:00.000|AppCompatCache|Snapshot|ShimCache entry: C:\Tools\NoTime\notime.exe|$noTime; CachePosition=5 of 5 (1 = most recent)|Registry|$RawPath"
    )
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("shimcache-parser-test-" + [guid]::NewGuid().ToString("N"))
try {
    Write-Host "Testing the ShimCache rows of Parse-PowerShellHistory ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."
    $parsedLine = "Parsed 5 AppCompatCache entries: 2 with file times (file last-modified times, not execution times), 2 distinct without."

    # --- appcompat_cache.reg as the collector writes it (reg query output) ---
    $run = Invoke-ShimCacheParser -Name "regquery" -Text (ConvertTo-RegQueryText $shimValue) -Encoding (New-Object System.Text.UTF8Encoding($true))
    Assert-Equal -Name "reg query output: rows (time, Source, EventType, Description, Details, Artifact, RawPath)" -Expected ((Get-ExpectedShimRows -RawPath $run.RegFile) -join "`n") -Actual ($run.Rows -join "`n")
    $types = @($script:timelineEntries | Group-Object EventType | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })
    Assert-Equal -Name "reg query output: entries with a file time are FileLastModified, none is Execution" -Expected "FileLastModified=2,Snapshot=2" -Actual ($types -join ",")
    Assert-Equal -Name "reg query output: the file and the counts are logged" -Expected "True|True" -Actual "$($run.Log.Contains("Parsing AppCompatCache from: $($run.RegFile)"))|$($run.Log.Contains($parsedLine))"

    # --- A regedit export of the same value ----------------------------------
    $run = Invoke-ShimCacheParser -Name "regedit" -Text (ConvertTo-RegExportText $shimValue) -Encoding ([System.Text.Encoding]::Unicode)
    Assert-Equal -Name "regedit export: the same rows" -Expected ((Get-ExpectedShimRows -RawPath $run.RegFile) -join "`n") -Actual ($run.Rows -join "`n")
    Assert-Equal -Name "regedit export: the counts are logged" -Expected $true -Actual $run.Log.Contains($parsedLine)

    # --- Excel color map and console legend ----------------------------------
    Write-Host "Testing the Excel color map and the color legend ..."
    $colorMapAst = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$colorMap' }, $true))
    Assert-Equal -Name "color map: assigned once" -Expected 1 -Actual $colorMapAst.Count
    $colorMap = & ([scriptblock]::Create($colorMapAst[0].Right.Extent.Text))
    Assert-Equal -Name "color map: FileLastModified is tan (E2C9A0), FileAccess stays light gray" -Expected "E2C9A0|D9D9D9" -Actual "$($colorMap['FileLastModified'])|$($colorMap['FileAccess'])"

    # The legend: the Log lines after "  Color legend:" in the same block
    $legendStart = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq "Log" -and $node.CommandElements.Count -eq 2 -and
                $node.CommandElements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $node.CommandElements[1].Value -eq "  Color legend:" }, $true))
    Assert-Equal -Name "color legend: found once" -Expected 1 -Actual $legendStart.Count
    $legendBlock = $legendStart[0].Parent.Parent
    $legend = @()
    $afterStart = $false
    foreach ($statement in $legendBlock.Statements) {
        if (-not $afterStart) { $afterStart = ($statement -eq $legendStart[0].Parent); continue }
        if ($statement -isnot [System.Management.Automation.Language.PipelineAst]) { break }
        $command = $statement.PipelineElements[0]
        if ($command -isnot [System.Management.Automation.Language.CommandAst] -or $command.GetCommandName() -ne "Log") { break }
        $legend += $command.CommandElements[1].Value
    }
    $legendTypes = @($legend | ForEach-Object { if ($_ -match '^ {4}[A-Za-z]+(?: [A-Za-z]+)? +([A-Za-z]+) +-- ') { $Matches[1] } else { "(unrecognized line: $_)" } })
    Assert-Equal -Name "color legend: one line per EventType of the color map" -Expected (@($colorMap.Keys | Sort-Object) -join ",") -Actual (@($legendTypes | Sort-Object) -join ",")
    Assert-Equal -Name "color legend: the FileLastModified line" -Expected "    Tan          FileLastModified     -- file last-modified time (ShimCache), not execution" -Actual (@($legend | Where-Object { $_ -match ' FileLastModified ' }) -join "`n")
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
