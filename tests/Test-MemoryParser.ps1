# =============================================================
# Memory parser test
# Checks where the Memory parser finds a collection's memory dump
# (Find-MemoryDump) on synthetic folders: -MemoryDumpPath first (also a
# relative path and one with [ ] in it; a path that is not a file is
# reported once, then the other places are tried), the dump next to the
# collection zip (.dmp or .raw), Memory\ inside the collection (never the
# Secrets\ folder of -IncludeSecrets or the email attachment copies), and the
# dump next to the collection folder or next to -InputPath (an outer
# folder of another name, also given as a relative path), which must be
# named after the collection folder: another collection's dump in the same
# folder (e.g. the collector's reports\) is never used. The collection
# folder is the folder of collection_manifest.csv (also below -InputPath
# and in the <name>\<name>\ layout of Windows "Extract All"), else
# -InputPath. Parse-Memory without a dump must point to -MemoryDumpPath.
# Volatility 3 is not run.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryParser.ps1
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
        Write-Host "::error file=tests/Test-MemoryParser.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
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

# A small file (the content does not matter to Find-MemoryDump), with its folders
function New-TestFile {
    param([string]$Path)
    [void][System.IO.Directory]::CreateDirectory((Split-Path $Path -Parent))
    [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] 16))
}

# A collection folder with an (empty) collection_manifest.csv
function New-TestCollection {
    param([string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    [System.IO.File]::WriteAllText((Join-Path $Path "collection_manifest.csv"), "SHA256,SourcePath,DestPath,SizeBytes,CollectedAt,RelativePath`r`n")
}

# The script-scope state the builder sets up for a run: -InputPath (the
# extracted folder for a zip), the zip, -MemoryDumpPath, the collection
# root and a new log file
function Set-TestRunState {
    param([string]$Collection, [string]$Zip = "", [string]$DumpPath = "")
    $script:InputPath = $Collection
    $script:selectedZipPath = $Zip
    $script:MemoryDumpPath = $DumpPath
    $script:collectionManifest = $null
    $script:memoryDumpPathWarned = $false
    # Find-ArtifactFiles skips the email attachment copies (relative to the
    # collection root) and the Secrets\ folder, which the builder looks up
    # once per run
    $script:collectionRoot = Get-CollectionRootFolder
    $script:secretsRoot = $null
    $script:logFile = Join-Path $workDir ("builder-" + [guid]::NewGuid().ToString("N") + ".log")
}

# Find-MemoryDump for one run: the dump found ("" for none) and what was logged
function Invoke-FindMemoryDump {
    param([string]$Collection, [string]$Zip = "", [string]$DumpPath = "")
    Set-TestRunState -Collection $Collection -Zip $Zip -DumpPath $DumpPath
    $found = Find-MemoryDump
    return [PSCustomObject]@{ Path = "$found"; Log = (Get-TestLog) }
}

function Get-TestLog {
    if (-not (Test-Path -LiteralPath $script:logFile)) { return "" }
    return [System.IO.File]::ReadAllText($script:logFile)
}

# Synthetic collection names, as the collector makes them (TriageCollection_<time>)
$nameA = "TriageCollection_2025-06-30_12-00"   # zip and dump in reports\, also a folder
$nameB = "TriageCollection_2025-06-29_08-15"   # another collection: only its dump
$nameC = "TriageCollection_2025-06-28_17-40"   # no dump of its own next to it
$nameD = "TriageCollection_2025-06-27_09-05"   # -NoCompress: Memory\memory_dump.raw inside
$nameE = "TriageCollection_2025-06-26_14-30"   # Windows "Extract All" layout
$nameF = "TriageCollection_2025-06-25_10-10"   # manifest below -InputPath
$nameG = "TriageCollection_2025-06-24_16-45"   # a folder named like its dump
$nameH = "TriageCollection_2025-06-23_11-20"   # no collection_manifest.csv
$nameR = "TriageCollection_2025-06-22_13-55"   # a raw image next to the zip
$nameI = "TriageCollection_2025-06-21_15-35"   # extracted into a folder of another name
$nameJ = "TriageCollection_2025-06-20_18-25"   # -IncludeSecrets: dump names in excluded folders
$missingWarning = "-MemoryDumpPath is not an existing file:"

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("memory-parser-test-" + [guid]::NewGuid().ToString("N"))
$pushed = $false
try {
    Write-Host "Testing Find-MemoryDump ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."
    $reports = Join-Path $workDir "reports"
    $extracted = Join-Path $workDir "work\in"
    $dumps = Join-Path $workDir "dumps"
    $cases = Join-Path $workDir "cases"
    $caseDir = Join-Path $workDir "Case001"   # <zip>, its dump, Extracted\<collection>\

    foreach ($name in @($nameA, $nameC, $nameR)) {
        New-TestFile (Join-Path $reports "$name.zip")
        New-TestCollection (Join-Path $extracted $name)
    }
    $dumpA = Join-Path $reports "${nameA}_memory_dump.dmp"
    $dumpB = Join-Path $reports "${nameB}_memory_dump.dmp"
    $dumpR = Join-Path $reports "${nameR}_memory_dump.raw"
    $dumpE = Join-Path $reports "${nameE}_memory_dump.raw"
    $dumpF = Join-Path $cases "${nameF}_memory_dump.dmp"
    $dumpH = Join-Path $reports "${nameH}_memory_dump.dmp"
    $dumpD = Join-Path $reports "$nameD\Memory\memory_dump.raw"
    $elsewhereA = Join-Path $dumps "${nameA}_memory_dump.dmp"
    $elsewhereC = Join-Path $dumps "${nameC}_memory_dump.dmp"
    $bracketedC = Join-Path $workDir "dumps [7]\${nameC}_memory_dump.dmp"
    $dumpI = Join-Path $caseDir "${nameI}_memory_dump.dmp"
    $otherI = Join-Path $caseDir "${nameB}_memory_dump.dmp"
    $dumpJ = Join-Path $reports "${nameJ}_memory_dump.dmp"
    foreach ($file in @($dumpA, $dumpB, $dumpR, $dumpE, $dumpF, $dumpH, $dumpD, $elsewhereA, $elsewhereC, $bracketedC, $dumpI, $otherI, $dumpJ)) { New-TestFile $file }
    foreach ($name in @($nameA, $nameC, $nameD, $nameG)) { New-TestCollection (Join-Path $reports $name) }
    New-TestCollection (Join-Path $reports "$nameE\$nameE")
    New-TestCollection (Join-Path $reports "Extracted\$nameC")
    New-TestCollection (Join-Path $cases $nameF)
    New-TestCollection (Join-Path $caseDir "Extracted\$nameI")
    New-TestFile (Join-Path $reports "$nameH\USB\setupapi.dev.log")
    [void][System.IO.Directory]::CreateDirectory((Join-Path $reports "${nameG}_memory_dump.dmp"))
    # A collection made with the collector's -IncludeSecrets: files named like
    # a dump in its Secrets\ folder and in both email attachment folders,
    # which no parser reads
    $collectionJ = Join-Path $reports $nameJ
    New-TestCollection $collectionJ
    [System.IO.File]::WriteAllText((Join-Path $collectionJ "collection_info.json"), '{"SchemaVersion":1,"SecretsIncluded":true}')
    foreach ($rel in @("Secrets\memory_dump.raw", "Email\alice\Outlook\SecureTemp\memory_dump.dmp", "Email\alice\NewOutlook\Attachments\memory.raw")) {
        New-TestFile (Join-Path $collectionJ $rel)
    }

    # --- Next to the collection zip (browse mode, or a zip as -InputPath) -----
    $zipA = Join-Path $reports "$nameA.zip"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA
    Assert-Equal -Name "zip: the dump next to it" -Expected $dumpA -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameR) -Zip (Join-Path $reports "$nameR.zip")
    Assert-Equal -Name "zip: a raw image next to it" -Expected $dumpR -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameC) -Zip (Join-Path $reports "$nameC.zip")
    Assert-Equal -Name "zip without a dump of its own: other collections' dumps next to it are not used" -Expected "" -Actual $run.Path

    # --- -MemoryDumpPath ------------------------------------------------------
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA -DumpPath $elsewhereA
    Assert-Equal -Name "-MemoryDumpPath: used before the dump next to the zip, nothing logged" -Expected "$elsewhereA|" -Actual "$($run.Path)|$($run.Log)"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath $elsewhereC
    Assert-Equal -Name "-MemoryDumpPath: a collection folder with no dump next to it" -Expected $elsewhereC -Actual $run.Path
    Push-Location -LiteralPath $dumps
    $pushed = $true
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath ".\${nameC}_memory_dump.dmp"
    Pop-Location
    $pushed = $false
    Assert-Equal -Name "-MemoryDumpPath: a relative path becomes a full path" -Expected $elsewhereC -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath $bracketedC
    Assert-Equal -Name "-MemoryDumpPath: [ ] in the path are not wildcards" -Expected "$bracketedC|" -Actual "$($run.Path)|$($run.Log)"

    $missing = Join-Path $dumps "missing_memory_dump.dmp"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA -DumpPath $missing
    Assert-Equal -Name "-MemoryDumpPath missing: warning, then the dump next to the zip" -Expected "$dumpA|True" -Actual "$($run.Path)|$($run.Log.Contains("WARNING: $missingWarning $missing -- looking for the memory dump in and next to the collection instead."))"
    $again = Find-MemoryDump
    $warnings = ([regex]::Matches((Get-TestLog), [regex]::Escape($missingWarning))).Count
    Assert-Equal -Name "-MemoryDumpPath missing: reported once when the dump is looked for twice" -Expected "$dumpA|1" -Actual "$again|$warnings"
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC) -DumpPath $dumps
    Assert-Equal -Name "-MemoryDumpPath is a folder: warning, no dump" -Expected "|True" -Actual "$($run.Path)|$($run.Log.Contains("$missingWarning $dumps "))"

    # A drive letter that does not exist: Get-Item fails, which must not escape
    $usedDrives = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() }) + @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpperInvariant() })
    $freeDrive = @([char[]]"ZYXWVUTSRQPONMLKJIHGFED" | Where-Object { $usedDrives -notcontains [string]$_ }) | Select-Object -First 1
    if ($freeDrive) {
        $noDrive = "${freeDrive}:\dumps\${nameA}_memory_dump.dmp"
        $run = Invoke-FindMemoryDump -Collection (Join-Path $extracted $nameA) -Zip $zipA -DumpPath $noDrive
        Assert-Equal -Name "-MemoryDumpPath on a drive that does not exist: warning, then the dump next to the zip" -Expected "$dumpA|True" -Actual "$($run.Path)|$($run.Log.Contains("$missingWarning $noDrive "))"
    }

    # --- Inside the collection folder (-NoCompress) ---------------------------
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameD)
    Assert-Equal -Name "collection folder: Memory\memory_dump.raw inside it" -Expected $dumpD -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection $collectionJ
    Assert-Equal -Name "collection folder: nothing taken from Secrets\ or the email attachment copies, the dump next to it instead" -Expected $dumpJ -Actual $run.Path

    # --- Next to the collection folder ----------------------------------------
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameA)
    Assert-Equal -Name "collection folder: the dump named after it, next to it" -Expected $dumpA -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameC)
    Assert-Equal -Name "collection folder: other collections' dumps next to it are not used" -Expected "" -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameG)
    Assert-Equal -Name "collection folder: a folder named like its dump is not used" -Expected "" -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameH)
    Assert-Equal -Name "collection folder without collection_manifest.csv: named after -InputPath" -Expected $dumpH -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports $nameE)
    Assert-Equal -Name "Extract All: the outer folder as -InputPath, the dump next to it" -Expected $dumpE -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports "$nameE\$nameE")
    Assert-Equal -Name "Extract All: the inner folder as -InputPath, the dump next to the outer one" -Expected $dumpE -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection $cases
    Assert-Equal -Name "manifest below -InputPath: the dump named after the manifest's folder" -Expected $dumpF -Actual $run.Path

    # An outer folder of another name as -InputPath (e.g. 7-Zip "Extract
    # files..." into Case001\Extracted\): the dump next to the zip is next to
    # -InputPath, not next to the collection folder
    $run = Invoke-FindMemoryDump -Collection (Join-Path $caseDir "Extracted")
    Assert-Equal -Name "outer folder of another name as -InputPath: the dump named after the collection, next to -InputPath" -Expected $dumpI -Actual $run.Path
    Push-Location -LiteralPath $caseDir
    $pushed = $true
    $run = Invoke-FindMemoryDump -Collection ".\Extracted"
    Pop-Location
    $pushed = $false
    Assert-Equal -Name "outer folder as a relative -InputPath: the dump next to it" -Expected $dumpI -Actual $run.Path
    $run = Invoke-FindMemoryDump -Collection (Join-Path $reports "Extracted")
    Assert-Equal -Name "outer folder as -InputPath: other collections' dumps next to it are not used" -Expected "" -Actual $run.Path

    # --- Parse-Memory without a dump ------------------------------------------
    $noDumpWarning = "WARNING: No memory dump found in the collection or next to it (pass -MemoryDumpPath with the dump file if it was saved elsewhere)."
    Set-TestRunState -Collection (Join-Path $reports $nameC)
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory without a dump: the warning names -MemoryDumpPath, then it stops" -Expected "True|False|True" -Actual "$($log.Contains($noDumpWarning))|$($log.Contains('Found memory dump'))|$($log.Contains('Memory parsing complete.'))"
    Set-TestRunState -Collection (Join-Path $reports $nameC) -DumpPath $missing
    Parse-Memory | Out-Null
    $log = Get-TestLog
    Assert-Equal -Name "Parse-Memory with a missing -MemoryDumpPath and no other dump: both warnings" -Expected "True|True|False" -Actual "$($log.Contains("$missingWarning $missing "))|$($log.Contains($noDumpWarning))|$($log.Contains('Found memory dump'))"
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    if ($pushed) { Pop-Location }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
