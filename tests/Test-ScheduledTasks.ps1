# =============================================================
# Scheduled tasks test
# The registration date in scheduled_tasks.csv (RegistrationDateUtc, or Date
# of older collectors) and in the task XML files of mounted images
# (RegistrationInfo/Date) is set by whoever wrote the task, not recorded by
# Windows: Windows' own tasks carry dates years before the install. The time
# Windows recorded is the TaskCache registered row (Registry source, checked
# by Test-RegistryParsers.ps1). Runs the ScheduledTasks parser on synthetic
# collections, with and without the TaskCache times the Registry source
# leaves for it, and checks that an XML date is a "Scheduled task
# registration date (author-supplied)" row with a Time= note, that a date
# less than 2 seconds from the task's TaskCache time is not added again (the
# task then gets a Snapshot row unless it has a last run row), that last run
# and Snapshot rows are unchanged, and the counts in the log. It also checks
# the 2-second boundary and that the main flow runs the Registry source
# before the ScheduledTasks source.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ScheduledTasks.ps1
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
        Write-Host "::error file=tests/Test-ScheduledTasks.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
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

# A synthetic collection folder taken on 2025-06-30 12:00 UTC from a system
# in W. Europe time (task XML dates without an offset are in that zone)
function New-TestCollection {
    param([string]$Name, [string]$Mode)
    $collection = Join-Path $testRoot $Name
    New-Item -ItemType Directory -Path $collection -Force | Out-Null
    $info = '{ "SchemaVersion": 1, "Mode": "' + $Mode + '", "CollectionStartUtc": "2025-06-30T12:00:00Z", ' +
        '"CollectorTimeZoneId": "W. Europe Standard Time", "TargetTimeZoneId": "W. Europe Standard Time" }'
    [System.IO.File]::WriteAllText((Join-Path $collection "collection_info.json"), $info)
    return $collection
}

# Task XML as in Windows\System32\Tasks (UTF-16 with a byte order mark); no
# <Date> when -Date is empty
function New-TaskXmlFile {
    param([string]$Path, [string]$Uri, [string]$Date, [string]$Author, [string]$Command)
    $dateNode = if ($Date) { "<Date>$Date</Date>" } else { "" }
    $xml = '<?xml version="1.0" encoding="UTF-16"?>' + "`r`n" +
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + "`r`n" +
        "  <RegistrationInfo>$dateNode<Author>$Author</Author><URI>$Uri</URI></RegistrationInfo>`r`n" +
        "  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>`r`n" +
        '  <Principals><Principal id="Author"><UserId>SYSTEM</UserId></Principal></Principals>' + "`r`n" +
        "  <Settings><Enabled>true</Enabled></Settings>`r`n" +
        '  <Actions Context="Author"><Exec><Command>' + $Command + '</Command></Exec></Actions>' + "`r`n" +
        "</Task>`r`n"
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, $xml, [System.Text.Encoding]::Unicode)
}

# Kind=Utc time from "yyyy-MM-dd HH:mm:ss.fff"
function Get-UtcTime {
    param([string]$Text)
    return [datetime]::SpecifyKind([datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture), [System.DateTimeKind]::Utc)
}

# Run Parse-ScheduledTasks on -Collection with -CacheTimes as the TaskCache
# registered times Read-TaskCache recorded (task path in lower case -> UTC
# times; $null when the Registry source did not run): its rows as
# "Timestamp|Source|EventType|Description|User|Details", sorted, and what
# was logged
function Invoke-ScheduledTasksParser {
    param([string]$Collection, [hashtable]$CacheTimes)
    $script:InputPath = $Collection
    $script:collectionRoot = $Collection
    $script:collectionInfo = $null
    $script:collectionManifest = $null
    $script:manifestTimes = $null
    $script:shortenedNames = @{}
    $script:logFile = Join-Path $testRoot ("parser-" + [guid]::NewGuid().ToString("N") + ".log")
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:taskCacheRegistered = $CacheTimes
    Parse-ScheduledTasks 6>$null | Out-Null
    return [PSCustomObject]@{
        Rows = @($script:timelineEntries | ForEach-Object { "$($_.Timestamp)|$($_.Source)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)" } | Sort-Object)
        Log  = [System.IO.File]::ReadAllText($script:logFile)
    }
}

# The expected rows, sorted like Invoke-ScheduledTasksParser sorts them
function Format-ExpectedRows {
    param([string[]]$Rows)
    return (@($Rows | Sort-Object) -join "`n")
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("scheduled-tasks-test-" + [guid]::NewGuid().ToString("N"))
try {
    Write-Host "Testing the ScheduledTasks parser ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."
    $authorNote = "Time=task XML RegistrationInfo/Date (author-supplied, not recorded by Windows)"
    $snapshotTime = "2025-06-30 12:00:00.000"
    $sameLine = "registration date(s) not added: the same time as the task's TaskCache registered row"

    # --- scheduled_tasks.csv of the live collector --------------------------
    # \Vendor\Updater: an old author-supplied date, its TaskCache time is
    # another one. \Same\NeverRan and \Same\Ran: the date is the TaskCache
    # time in whole seconds (0.95 and 1.999 seconds apart). \Near\TwoSeconds:
    # 2 seconds apart, so not the same. \Plain: no times at all.
    $live = New-TestCollection -Name "live" -Mode "Live"
    $liveTasks = @(
        @("Updater", "\Vendor\", "Vendor", "SYSTEM", "C:\Program Files\Vendor\update.exe /silent", "Daily", "2005-06-23T21:48:00Z", "2025-06-29T08:00:00Z", "0"),
        @("NeverRan", "\Same\", "TESTHOST\tester", "TESTHOST\tester", "C:\Tools\job.cmd", "Logon", "2025-03-01T10:00:00Z", "", ""),
        @("Ran", "\Same\", "TESTHOST\tester", "SYSTEM", "C:\Tools\ran.cmd", "Boot", "2025-03-02T10:00:00Z", "2025-06-28T07:00:00Z", "1"),
        @("TwoSeconds", "\Near\", "TESTHOST\tester", "SYSTEM", "C:\Tools\near.cmd", "", "2025-03-03T10:00:00Z", "", ""),
        @("Plain", "\", "", "SYSTEM", "C:\Tools\plain.cmd", "", "", "", "")
    )
    $csvRows = foreach ($t in $liveTasks) {
        [PSCustomObject]@{
            TaskName = $t[0]; TaskPath = $t[1]; State = "Ready"; Author = $t[2]; UserId = $t[3]; Actions = $t[4]; Triggers = $t[5]
            RegistrationDateUtc = $t[6]; LastRunTimeUtc = $t[7]; NextRunTimeUtc = ""; LastTaskResult = $t[8]
        }
    }
    New-Item -ItemType Directory -Path (Join-Path $live "Persistence") -Force | Out-Null
    $csvRows | Export-Csv -LiteralPath (Join-Path $live "Persistence\scheduled_tasks.csv") -NoTypeInformation -Encoding UTF8
    $cacheTimes = @{
        "\vendor\updater"    = @(Get-UtcTime "2025-01-10 09:00:00.123")
        "\same\neverran"     = @(Get-UtcTime "2025-03-01 10:00:00.950")
        "\same\ran"          = @(Get-UtcTime "2025-03-02 10:00:01.999")
        "\near\twoseconds"   = @(Get-UtcTime "2025-03-03 10:00:02.000")
        "\other\unlistedtask" = @(Get-UtcTime "2025-03-01 10:00:00.000")
    }
    $updater = "Actions=C:\Program Files\Vendor\update.exe /silent | UserId=SYSTEM | Author=Vendor | State=Ready | Triggers=Daily"
    $neverRan = "Actions=C:\Tools\job.cmd | UserId=TESTHOST\tester | Author=TESTHOST\tester | State=Ready | Triggers=Logon"
    $ran = "Actions=C:\Tools\ran.cmd | UserId=SYSTEM | Author=TESTHOST\tester | State=Ready | Triggers=Boot"
    $near = "Actions=C:\Tools\near.cmd | UserId=SYSTEM | Author=TESTHOST\tester | State=Ready"
    $plain = "$snapshotTime|ScheduledTasks|Snapshot|Scheduled task: \Plain|SYSTEM|Actions=C:\Tools\plain.cmd | UserId=SYSTEM | State=Ready"
    $commonRows = @(
        "2005-06-23 21:48:00.000|ScheduledTasks|ScheduledTaskChange|Scheduled task registration date (author-supplied): \Vendor\Updater|SYSTEM|$updater | $authorNote",
        "2025-06-29 08:00:00.000|ScheduledTasks|Execution|Scheduled task last run: \Vendor\Updater|SYSTEM|$updater | LastTaskResult=0",
        "2025-06-28 07:00:00.000|ScheduledTasks|Execution|Scheduled task last run: \Same\Ran|SYSTEM|$ran | LastTaskResult=1",
        "2025-03-03 10:00:00.000|ScheduledTasks|ScheduledTaskChange|Scheduled task registration date (author-supplied): \Near\TwoSeconds|SYSTEM|$near | $authorNote",
        $plain
    )

    $run = Invoke-ScheduledTasksParser -Collection $live -CacheTimes $cacheTimes
    Assert-Equal -Name "scheduled_tasks.csv with TaskCache times: author-supplied dates, none that is the TaskCache time, a Snapshot row for a task left without a row" `
        -Expected (Format-ExpectedRows ($commonRows + "$snapshotTime|ScheduledTasks|Snapshot|Scheduled task: \Same\NeverRan|TESTHOST\tester|$neverRan")) `
        -Actual ($run.Rows -join "`n")
    Assert-Equal -Name "scheduled_tasks.csv with TaskCache times: the counts are logged" -Expected "True|True" `
        -Actual "$($run.Log.Contains("    4 dated row(s), 2 snapshot row(s)"))|$($run.Log.Contains("    2 $sameLine"))"

    $run = Invoke-ScheduledTasksParser -Collection $live -CacheTimes $null
    Assert-Equal -Name "scheduled_tasks.csv without the Registry source: every date is an author-supplied row" `
        -Expected (Format-ExpectedRows ($commonRows + @(
                "2025-03-01 10:00:00.000|ScheduledTasks|ScheduledTaskChange|Scheduled task registration date (author-supplied): \Same\NeverRan|TESTHOST\tester|$neverRan | $authorNote",
                "2025-03-02 10:00:00.000|ScheduledTasks|ScheduledTaskChange|Scheduled task registration date (author-supplied): \Same\Ran|SYSTEM|$ran | $authorNote"))) `
        -Actual ($run.Rows -join "`n")
    Assert-Equal -Name "scheduled_tasks.csv without the Registry source: the counts are logged, no date left out" -Expected "True|False" `
        -Actual "$($run.Log.Contains("    6 dated row(s), 1 snapshot row(s)"))|$($run.Log.Contains($sameLine))"

    # --- Older collectors: Name and Date (local time), no TaskPath -----------
    # RootTask's date is its TaskCache time (\RootTask); OldRoot's is not
    $old = New-TestCollection -Name "old" -Mode "Live"
    $oldRows = @(
        [PSCustomObject]@{ Name = "RootTask"; Date = "2025-03-04T12:00:00"; Author = "TESTHOST\tester"; Actions = "C:\Tools\root.cmd"; State = "Ready" },
        [PSCustomObject]@{ Name = "OldRoot"; Date = "2006-11-10T21:29:55"; Author = "Vendor"; Actions = "C:\Tools\oldroot.cmd"; State = "Disabled" }
    )
    $oldRows | Export-Csv -LiteralPath (Join-Path $old "scheduled_tasks.csv") -NoTypeInformation -Encoding UTF8
    $run = Invoke-ScheduledTasksParser -Collection $old -CacheTimes @{ "\roottask" = @(Get-UtcTime "2025-03-04 11:00:00.300") }
    Assert-Equal -Name "older scheduled_tasks.csv: Date in W. Europe time, the TaskCache time found under \<name>" `
        -Expected (Format-ExpectedRows @(
            "$snapshotTime|ScheduledTasks|Snapshot|Scheduled task: RootTask|TESTHOST\tester|Actions=C:\Tools\root.cmd | Author=TESTHOST\tester | State=Ready",
            "2006-11-10 20:29:55.000|ScheduledTasks|ScheduledTaskChange|Scheduled task registration date (author-supplied): OldRoot|Vendor|Actions=C:\Tools\oldroot.cmd | Author=Vendor | State=Disabled | $authorNote")) `
        -Actual ($run.Rows -join "`n")

    # --- Task XML of a mounted image -----------------------------------------
    # OldTask: an old date (summer time, UTC+2); ByUser: the TaskCache time
    # with seven decimal places; NoDate: no <Date>
    $mounted = New-TestCollection -Name "mounted" -Mode "MountedImage"
    $xmlDir = Join-Path $mounted "Persistence\ScheduledTasks_XML"
    New-TaskXmlFile -Path (Join-Path $xmlDir "Contoso\Test\OldTask") -Uri "\Contoso\Test\OldTask" -Date "2005-06-23T23:48:00" -Author "Contoso" -Command "%windir%\system32\oldtask.exe"
    New-TaskXmlFile -Path (Join-Path $xmlDir "ByUser") -Uri "\ByUser" -Date "2025-06-20T14:00:00.1234567" -Author "TESTHOST\tester" -Command "C:\Users\Public\job.cmd"
    New-TaskXmlFile -Path (Join-Path $xmlDir "NoDate") -Uri "\NoDate" -Date "" -Author "TESTHOST\tester" -Command "C:\Tools\nodate.cmd"
    $xmlCache = @{
        "\contoso\test\oldtask" = @(Get-UtcTime "2024-05-01 06:00:00.000")
        "\byuser"               = @(Get-UtcTime "2025-06-20 12:00:00.700")
    }
    $run = Invoke-ScheduledTasksParser -Collection $mounted -CacheTimes $xmlCache
    $xmlDetails = "UserId=SYSTEM | Author={0} | Enabled=true | Triggers=LogonTrigger"
    Assert-Equal -Name "task XML: author-supplied date, the TaskCache time not added again (Snapshot row instead)" `
        -Expected (Format-ExpectedRows @(
            "2005-06-23 21:48:00.000|ScheduledTasks-XML|ScheduledTaskChange|Scheduled task registration date (author-supplied): \Contoso\Test\OldTask|SYSTEM|Actions=%windir%\system32\oldtask.exe | $($xmlDetails -f 'Contoso') | $authorNote",
            "$snapshotTime|ScheduledTasks-XML|Snapshot|Scheduled task: \ByUser|SYSTEM|Actions=C:\Users\Public\job.cmd | $($xmlDetails -f 'TESTHOST\tester')",
            "$snapshotTime|ScheduledTasks-XML|Snapshot|Scheduled task: \NoDate|SYSTEM|Actions=C:\Tools\nodate.cmd | $($xmlDetails -f 'TESTHOST\tester')")) `
        -Actual ($run.Rows -join "`n")
    Assert-Equal -Name "task XML: the counts are logged" -Expected "True|True" `
        -Actual "$($run.Log.Contains("    1 dated row(s), 2 snapshot row(s)"))|$($run.Log.Contains("    1 $sameLine"))"

    # --- The 2-second rule -----------------------------------------------------
    $script:taskCacheRegistered = $null
    $results = @("$(Test-TaskCacheRegistered -TaskName '\Task' -Time (Get-UtcTime '2025-03-01 10:00:00.000'))")
    $script:taskCacheRegistered = @{ "\folder\task" = @((Get-UtcTime "2024-01-01 00:00:00.000"), (Get-UtcTime "2025-03-01 10:00:00.000")) }
    foreach ($check in @(@("\Folder\Task", "2025-03-01 10:00:01.999"), @("\Folder\Task", "2025-03-01 10:00:02.000"),
            @("\Folder\Task", "2025-03-01 09:59:58.001"), @("\Folder\Task", "2025-03-01 09:59:58.000"),
            @("\FOLDER\TASK", "2024-01-01 00:00:00.000"), @("\Folder\Other", "2025-03-01 10:00:00.000"), @("", "2025-03-01 10:00:00.000"))) {
        $results += "$(Test-TaskCacheRegistered -TaskName $check[0] -Time (Get-UtcTime $check[1]))"
    }
    Assert-Equal -Name "same time: less than 2 seconds apart either way, any of the task's times, path in any case" `
        -Expected "False|True|False|True|False|True|False|False" -Actual ($results -join "|")

    # --- Main flow ---------------------------------------------------------------
    # Parse-ScheduledTasks needs the TaskCache times, so the Registry source
    # must run first, after the times are reset
    $mainFlow = @($ast.FindAll({ param($node)
                ($node -is [System.Management.Automation.Language.CommandAst] -and @("Parse-Registry", "Parse-ScheduledTasks") -contains $node.GetCommandName()) -or
                ($node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$script:taskCacheRegistered') }, $true) | Where-Object {
            $parent = $_.Parent
            while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
            $null -eq $parent
        } | Sort-Object { $_.Extent.StartOffset } | ForEach-Object {
            if ($_ -is [System.Management.Automation.Language.CommandAst]) { $_.GetCommandName() } else { $_.Extent.Text }
        })
    Assert-Equal -Name "main flow: TaskCache times reset, then the Registry source, then ScheduledTasks" `
        -Expected '$script:taskCacheRegistered = @{}|Parse-Registry|Parse-ScheduledTasks' -Actual ($mainFlow -join "|")
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
