# =============================================================
# Event log parser tests, Phase 2 logs: Windows PowerShell, WMI-Activity,
# TerminalServices-RDPClient, NTLM, Windows Firewall, Shell-Core, OAlerts,
# the antivirus products' own logs (AntiVirus\*.evtx) and the 4624 details
#
# Part 1 -- unit checks (no admin, always run): loads the builder's
#   functions without running it and feeds the handlers synthetic event
#   records (our own XML, laid out like the real records), checking every
#   row they add; then runs Parse-EventLogs itself on synthetic records, with
#   Get-WinEvent replaced, to check which IDs each channel reads.
# Part 2 -- real records (no admin, always run): starts Windows PowerShell
#   with an encoded command (events 400 / 403), exports the last 30 days of
#   the Phase 2 channels that exist on this machine with wevtutil, runs the
#   builder (-Sources EventLogs) and checks the PowerShell rows and that no
#   log fails to parse. Needs a builder that runs here: the repository's
#   needs Administrator, -BuilderPath can name a copy without that check.
# Part 3 -- system test (needs Administrator; runs only in GitHub Actions or
#   with -AllowSystemChanges): adds, changes and deletes a disabled firewall
#   rule and changes and restores the Public profile's log size (firewall
#   events). In GitHub Actions only, also: a temporary WMI permanent event
#   subscription (5861), NTLM auditing with a loopback SMB connection
#   (8001 / 8002, Security 4624) and an RDP client connection attempt to an
#   unused loopback address (1024 / 1026). Everything is undone in a finally
#   block; the event records stay in the logs. Then the logs are exported,
#   the builder is run and the rows are checked.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-EventLogParsers2.ps1
#   ... -AllowSystemChanges   also run part 3 on this machine (admin)
#   ... -BuilderPath <file>   test another copy of timeline-builder.ps1
# Exit code 0 = pass, 1 = fail.
# =============================================================
param(
    [switch]$AllowSystemChanges,
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

# Continue: native tools (wevtutil, net) must not turn stderr output into
# terminating errors; cmdlets whose failure matters use -ErrorAction Stop
$ErrorActionPreference = "Continue"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$script:failures = 0

function Write-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Name -- $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-EventLogParsers2.ps1::$Name -- $Message" }
}

# =============================================================
# Part 1: unit checks
# =============================================================
Write-Host "Part 1: Phase 2 event log handlers on synthetic records ($builder)"

# Load every top-level function of the builder, and the script-level tables
# the event log handlers use, without running the script
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
if ($parseErrors) {
    Write-TestResult -Name "builder parses" -Passed $false -Message ((@($parseErrors) | Select-Object -First 3 | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "; ")
    exit 1
}
$functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
    $parent = $_.Parent
    while ($parent -and $parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $parent = $parent.Parent }
    $null -eq $parent
}
foreach ($function in $functions) { . ([ScriptBlock]::Create($function.Extent.Text)) }
$tableNames = @("xmlInvalidPattern", "xmlInvalidRegex", "ThirdPartyAvProviders")
$tables = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Parent.Parent -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -eq $node.Parent.Parent.Parent }, $true) |
    Where-Object { $_.Left.Extent.Text -match '^\$script:(\w+)$' -and $tableNames -contains $Matches[1] } | Sort-Object { $_.Extent.StartOffset }
foreach ($table in $tables) { . ([ScriptBlock]::Create($table.Extent.Text)) }
foreach ($name in $tableNames) {
    if ($null -eq (Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue)) {
        Write-TestResult -Name "builder table `$script:$name" -Passed $false -Message "not found in $builder"
    }
}

$script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:artifactStats = @{}
$logFile = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx2-unit-" + [guid]::NewGuid().ToString("N") + ".log")
$script:nextRecordId = 0
$eventNs = "http://schemas.microsoft.com/win/2004/08/events/event"

# XML-escaped <Data Name="..."> elements (or unnamed <Data> for a plain list)
function New-EventDataXml {
    param($Data)
    $parts = @()
    if ($Data -is [System.Collections.IDictionary]) {
        foreach ($key in $Data.Keys) { $parts += "<Data Name='$key'>$([System.Security.SecurityElement]::Escape([string]$Data[$key]))</Data>" }
    }
    else {
        foreach ($value in $Data) { $parts += "<Data>$([System.Security.SecurityElement]::Escape([string]$value))</Data>" }
    }
    return "<EventData>" + ($parts -join "") + "</EventData>"
}

# <UserData><Wrapper xmlns=...><Name>value</Name>...</Wrapper></UserData>
function New-UserDataXml {
    param([string]$Wrapper, [System.Collections.IDictionary]$Data)
    $parts = foreach ($key in $Data.Keys) { "<$key>$([System.Security.SecurityElement]::Escape([string]$Data[$key]))</$key>" }
    return "<UserData><$Wrapper xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>" + ($parts -join "") + "</$Wrapper></UserData>"
}

# A stand-in for an EventLogRecord: the properties the handlers read and a
# ToXml() method, with the System\Correlation ActivityID and System\Execution
# ProcessID of real records when given. $Time is UTC "yyyy-MM-dd HH:mm:ss".
function New-TestRecord {
    param([string]$Provider, [int]$Id, [string]$Time, [string]$Body = "", [string]$UserSid = "", [int]$Level = 4,
        [string]$Message = "", [string[]]$Values = @(), [string]$ActivityId = "", [string]$ProcessId = "")
    $script:nextRecordId++
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $timeUtc = [datetime]::ParseExact($Time, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    $correlation = if ($ActivityId) { "<Correlation ActivityID='{$ActivityId}'/>" } else { "<Correlation/>" }
    $execution = if ($ProcessId) { "<Execution ProcessID='$ProcessId' ThreadID='1'/>" } else { "" }
    $security = if ($UserSid) { "<Security UserID='$UserSid'/>" } else { "<Security/>" }
    $xml = "<Event xmlns='$eventNs'><System><Provider Name='$Provider'/><EventID>$Id</EventID><Level>$Level</Level>" +
        "<TimeCreated SystemTime='$($timeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ"))'/><EventRecordID>$($script:nextRecordId)</EventRecordID>" +
        "$correlation$execution$security</System>$Body</Event>"
    $record = [PSCustomObject]@{
        Id           = $Id
        ProviderName = $Provider
        TimeCreated  = $timeUtc
        RecordId     = $script:nextRecordId
        UserId       = $UserSid
        Level        = $Level
        Message      = $Message
        Properties   = @($Values | ForEach-Object { [PSCustomObject]@{ Value = $_ } })
        EventXml     = $xml
    }
    $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.EventXml }
    return $record
}

# Runs $Action and compares the rows it adds with $Expected (in order; each
# expected row lists only the columns to check, compared case-sensitively)
function Test-Case {
    param([string]$Name, [scriptblock]$Action, [object[]]$Expected)
    $before = $script:timelineEntries.Count
    try { & $Action }
    catch {
        Write-TestResult -Name $Name -Passed $false -Message "threw: $($_.Exception.Message)"
        return
    }
    $rows = @()
    for ($i = $before; $i -lt $script:timelineEntries.Count; $i++) { $rows += $script:timelineEntries[$i] }
    $problems = @()
    if ($rows.Count -ne $Expected.Count) { $problems += "expected $($Expected.Count) row(s), got $($rows.Count)" }
    for ($i = 0; $i -lt [Math]::Min($rows.Count, $Expected.Count); $i++) {
        foreach ($key in $Expected[$i].Keys) {
            $actual = [string]$rows[$i].$key
            if ($actual -cne [string]$Expected[$i][$key]) { $problems += "row $($i + 1) $key='$actual', expected '$($Expected[$i][$key])'" }
        }
    }
    if ($problems.Count -gt 0 -and $rows.Count -ne $Expected.Count) {
        $problems += ($rows | ForEach-Object { "got: $($_.Description) | $($_.Details)" })
    }
    Write-TestResult -Name $Name -Passed ($problems.Count -eq 0) -Message ($problems -join "; ")
}

# Log lines written since $Before lines
function Get-NewLogLines {
    param([int]$Before)
    return @(Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue | Select-Object -Skip $Before | ForEach-Object { $_ -replace '^\[[^\]]+\] ', '' })
}
function Get-LogLineCount {
    if (Test-Path -LiteralPath $logFile) { return @(Get-Content -LiteralPath $logFile).Count }
    return 0
}

$alice = "S-1-5-21-1111-2222-3333-1001"

# --- Windows PowerShell.evtx ---
# Context text of a classic PowerShell event, as Windows writes it
function New-PowerShellContext {
    param([string]$HostApplication, [string]$Engine = "5.1.26100.1", [string]$HostId = "11111111-0000-0000-0000-000000000001", [string]$Extra = "")
    return "`tNewEngineState=Available`n`tPreviousEngineState=None`n`n`tSequenceNumber=13`n`n`tHostName=ConsoleHost`n`tHostVersion=$Engine`n" +
        "`tHostId=$HostId`n`tHostApplication=$HostApplication`n`tEngineVersion=$Engine`n`tRunspaceId=22222222-0000-0000-0000-000000000002`n" +
        "`tPipelineId=$Extra`n`tCommandName=`n`tCommandType=`n`tScriptName=`n`tCommandPath=`n`tCommandLine="
}
$psFile = "Windows PowerShell.evtx"
$psPath = "X:\EventLogs\Windows PowerShell.evtx"
$encodedScript = "Write-Output 'tlt-encoded'"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodedScript))
$longApp = "powershell.exe -NoProfile -Command " + ("x" * 1100)
Test-Case -Name "Windows PowerShell 400 / 403 / 800 (encoded command decoded, 2.0 downgrade, 800 only for 2.0)" -Action {
    $plain = "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\Scripts\a.ps1"
    $records = @(
        (New-TestRecord -Provider "PowerShell" -Id 400 -Time "2026-02-01 10:00:00" -Body (New-EventDataXml -Data @("Available", "None", (New-PowerShellContext -HostApplication $plain)))),
        (New-TestRecord -Provider "PowerShell" -Id 403 -Time "2026-02-01 10:00:05" -Body (New-EventDataXml -Data @("Stopped", "Available", (New-PowerShellContext -HostApplication $plain)))),
        (New-TestRecord -Provider "PowerShell" -Id 400 -Time "2026-02-01 10:01:00" -Body (New-EventDataXml -Data @("Available", "None", (New-PowerShellContext -HostApplication "powershell.exe -NoP -W Hidden -enc $encoded" -HostId "33333333-0000-0000-0000-000000000003")))),
        (New-TestRecord -Provider "PowerShell" -Id 400 -Time "2026-02-01 10:02:00" -Body (New-EventDataXml -Data @("Available", "None", (New-PowerShellContext -HostApplication "powershell.exe -Version 2 -Command Get-Date" -Engine "2.0")))),
        (New-TestRecord -Provider "PowerShell" -Id 800 -Time "2026-02-01 10:02:01" -Body (New-EventDataXml -Data @("Get-Date", "`tDetailSequence=1`n`tUserId=TESTHOST\alice`n`tHostName=ConsoleHost`n`tHostApplication=powershell.exe -Version 2 -Command Get-Date`n`tEngineVersion=2.0`n`tScriptName=`n`tCommandLine=Get-Date", "CommandInvocation(Get-Date): `"Get-Date`"`nCommandInvocation(Out-Default): `"Out-Default`"`nCommandInvocation(Get-Date): `"Get-Date`""))),
        (New-TestRecord -Provider "PowerShell" -Id 800 -Time "2026-02-01 10:03:00" -Body (New-EventDataXml -Data @("Add-Type -TypeDefinition `$code", "`tUserId=TESTHOST\alice`n`tHostApplication=powershell.exe`n`tEngineVersion=5.1.26100.1", "CommandInvocation(Add-Type): `"Add-Type`""))),
        (New-TestRecord -Provider "PowerShell" -Id 400 -Time "2026-02-01 10:04:00" -Body (New-EventDataXml -Data @("Available", "None", (New-PowerShellContext -HostApplication $longApp))))
    )
    $logBefore = Get-LogLineCount
    Add-WindowsPowerShellEntries -Records $records -FileName $psFile -FilePath $psPath
    $skipLine = @(Get-NewLogLines $logBefore | Where-Object { $_ -match 'Skipped 1 event\(s\): 800 pipeline details of PowerShell 3\.0 and later' })
    if ($skipLine.Count -ne 1) { throw "no log line counting the skipped 800 event" }
} -Expected @(
    @{ Timestamp = "2026-02-01 10:00:00.000"; Source = $psFile; EventType = "Execution"; Description = "PowerShell engine started: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\Scripts\a.ps1"; User = ""
        Details = "EventID=400 | EngineVersion=5.1.26100.1 | HostName=ConsoleHost | HostVersion=5.1.26100.1 | HostApplication=C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\Scripts\a.ps1 | HostId=11111111-0000-0000-0000-000000000001 | RunspaceId=22222222-0000-0000-0000-000000000002"
        Artifact = "EventLogs"; RawPath = $psPath },
    @{ EventType = "Execution"; Description = "PowerShell engine stopped: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\Scripts\a.ps1"
        Details = "EventID=403 | EngineVersion=5.1.26100.1 | HostName=ConsoleHost | HostVersion=5.1.26100.1 | HostApplication=C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\Scripts\a.ps1 | HostId=11111111-0000-0000-0000-000000000001 | RunspaceId=22222222-0000-0000-0000-000000000002" },
    @{ Description = "PowerShell engine started: powershell.exe -NoP -W Hidden -enc $encoded"
        Details = "EventID=400 | EngineVersion=5.1.26100.1 | HostName=ConsoleHost | HostVersion=5.1.26100.1 | HostApplication=powershell.exe -NoP -W Hidden -enc $encoded | EncodedCommand=$encodedScript | HostId=33333333-0000-0000-0000-000000000003 | RunspaceId=22222222-0000-0000-0000-000000000002" },
    @{ EventType = "Execution"; Description = "PowerShell 2.0 engine started (possible downgrade): powershell.exe -Version 2 -Command Get-Date"
        Details = "EventID=400 | EngineVersion=2.0 | HostName=ConsoleHost | HostVersion=2.0 | HostApplication=powershell.exe -Version 2 -Command Get-Date | HostId=11111111-0000-0000-0000-000000000001 | RunspaceId=22222222-0000-0000-0000-000000000002" },
    @{ EventType = "Execution"; Description = "PowerShell 2.0 pipeline executed: Get-Date"; User = "TESTHOST\alice"
        Details = "EventID=800 | CommandLine=Get-Date | Commands=Get-Date, Out-Default | EngineVersion=2.0 | HostName=ConsoleHost | HostApplication=powershell.exe -Version 2 -Command Get-Date" },
    @{ Description = "PowerShell engine started: " + $longApp.Substring(0, 200) + "..."
        Details = "EventID=400 | EngineVersion=5.1.26100.1 | HostName=ConsoleHost | HostVersion=5.1.26100.1 | HostApplication=" + $longApp.Substring(0, 1000) + "... | HostId=11111111-0000-0000-0000-000000000001 | RunspaceId=22222222-0000-0000-0000-000000000002" }
)

Test-Case -Name "Helpers: -EncodedCommand decoding, MOF properties, firewall profiles" -Action {
    $abc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("abc def"))
    $binary = [Convert]::ToBase64String([byte[]](0, 1, 2, 3, 4, 5, 6, 7, 8, 9))
    $checks = @(
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe -e $abc"), "abc def"),
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe /EncodedCommand $abc"), "abc def"),
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe -ec '$abc'"), "abc def"),
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe -EncodedC $abc -NoExit"), "abc def"),
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe -ExecutionPolicy Unrestricted -File x.ps1"), ""),
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe -enc NotBase64Text!"), ""),
        @((ConvertFrom-PowerShellEncodedCommand "powershell.exe -enc $binary"), ""),
        @((ConvertFrom-PowerShellEncodedCommand "C:\Tools\enc.exe -encrypt $abc"), ""),
        @((Get-WmiMofProperty "instance of X`n{`n`tCommandLineTemplate = `"cmd /c \`"a\\b\`"`";`n`tName = `"n`";`n};" "CommandLineTemplate"), "cmd /c `"a\b`""),
        @((Get-WmiMofProperty "`tScriptText = `"line1\nline2\tx\\n`";" "scripttext"), "line1`nline2`tx\n"),
        @((Get-WmiMofProperty "`tName = `"n`";" "Query"), ""),
        @((ConvertFrom-FirewallProfileMask "7"), "Domain, Private, Public"),
        @((ConvertFrom-FirewallProfileMask "2147483647"), "All"),
        @((ConvertFrom-FirewallProfileMask "6"), "Private, Public"),
        @((ConvertFrom-FirewallProfileMask "x"), "x")
    )
    foreach ($check in $checks) {
        if ($check[0] -cne $check[1]) { throw "got '$($check[0])', expected '$($check[1])'" }
    }
} -Expected @()

# --- WMI-Activity ---
$wmiFile = "Microsoft-Windows-WMI-Activity%4Operational.evtx"
$wmiProvider = "Microsoft-Windows-WMI-Activity"
# PossibleCause of 5861: the filter and consumer instances as MOF text
function New-WmiBindingCause {
    param([string]$FilterName, [string]$Query, [string]$ConsumerClass, [string[]]$ConsumerLines)
    return "Binding EventFilter: `ninstance of __EventFilter`n{`n`tCreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0};`n`tEventNamespace = `"root\\cimv2`";`n" +
        "`tName = `"$FilterName`";`n`tQuery = `"$Query`";`n`tQueryLanguage = `"WQL`";`n};`nPerm. Consumer: `ninstance of $ConsumerClass`n{`n" +
        (($ConsumerLines | ForEach-Object { "`t$_`n" }) -join "") + "};`n"
}
$wmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
Test-Case -Name "WMI-Activity 5861 permanent / 5860 temporary subscriptions (folded), 5857-5859 counted" -Action {
    $cmdCause = New-WmiBindingCause -FilterName "UpdFilter" -Query $wmiQuery -ConsumerClass "CommandLineEventConsumer" -ConsumerLines @(
        "CommandLineTemplate = `"cmd.exe /c \`"C:\\Users\\Public\\run.bat\`"`";", "CreatorSID = {1, 2};", "Name = `"UpdConsumer`";")
    $cmd = [ordered]@{ Namespace = "//./root/subscription"; ESS = "UpdFilter"; CONSUMER = "CommandLineEventConsumer=`"UpdConsumer`""; PossibleCause = $cmdCause }
    $scriptCause = New-WmiBindingCause -FilterName "ScriptFilter" -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'" -ConsumerClass "ActiveScriptEventConsumer" -ConsumerLines @(
        "Name = `"ScriptConsumer`";", "ScriptingEngine = `"VBScript`";", "ScriptText = `"Set o = CreateObject(\`"WScript.Shell\`")\no.Run \`"calc.exe\`"`";")
    $script = [ordered]@{ Namespace = "//./root/subscription"; ESS = "ScriptFilter"; CONSUMER = "ActiveScriptEventConsumer=`"ScriptConsumer`""; PossibleCause = $scriptCause }
    $scmCause = New-WmiBindingCause -FilterName "SCM Event Log Filter" -Query "select * from MSFT_SCMEventLogEvent" -ConsumerClass "NTEventLogEventConsumer" -ConsumerLines @(
        "Category = 0;", "EventType = 1;", "Name = `"SCM Event Log Consumer`";", "NameOfUserSIDProperty = `"sid`";", "SourceName = `"Service Control Manager`";")
    $scm = [ordered]@{ Namespace = "//./root/subscription"; ESS = "SCM Event Log Filter"; CONSUMER = "NTEventLogEventConsumer=`"SCM Event Log Consumer`""; PossibleCause = $scmCause }
    $temp = [ordered]@{ NamespaceName = "ROOT\SecurityCenter"; Query = "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct'"; User = "NT AUTHORITY\LOCAL SERVICE"; Processid = "4321"; ClientMachine = "TESTHOST"; PossibleCause = "Temporary" }
    $records = @(
        (New-TestRecord -Provider $wmiProvider -Id 5861 -Time "2026-02-02 08:00:00" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_ESStoConsumerBinding" -Data $cmd)),
        (New-TestRecord -Provider $wmiProvider -Id 5861 -Time "2026-02-02 08:00:01" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_ESStoConsumerBinding" -Data $scm)),
        (New-TestRecord -Provider $wmiProvider -Id 5860 -Time "2026-02-02 08:00:30" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_TemporaryEssStarted" -Data $temp)),
        (New-TestRecord -Provider $wmiProvider -Id 5857 -Time "2026-02-02 08:01:00" -Body (New-UserDataXml -Wrapper "Operation_StartedOperational" -Data ([ordered]@{ ProviderName = "CIMWin32"; Code = "0x0"; HostProcess = "wmiprvse.exe"; ProcessID = "100"; ProviderPath = "%systemroot%\system32\wbem\cimwin32.dll" }))),
        (New-TestRecord -Provider $wmiProvider -Id 5858 -Time "2026-02-02 08:01:01" -Level 2 -Body (New-UserDataXml -Wrapper "Operation_ClientFailure" -Data ([ordered]@{ Id = "{0}"; ClientMachine = "TESTHOST"; User = "TESTHOST\alice"; ClientProcessId = "5"; Component = "Unknown"; Operation = "x"; ResultCode = "0x80041032"; PossibleCause = "Unknown" }))),
        (New-TestRecord -Provider $wmiProvider -Id 5858 -Time "2026-02-02 08:01:02" -Level 2 -Body (New-UserDataXml -Wrapper "Operation_ClientFailure" -Data ([ordered]@{ Id = "{0}"; Operation = "y" }))),
        (New-TestRecord -Provider $wmiProvider -Id 5859 -Time "2026-02-02 08:01:03" -Body (New-UserDataXml -Wrapper "Operation_EssStarted" -Data ([ordered]@{ NamespaceName = "//./root/CIMV2"; Query = "select * from MSFT_SCMEventLogEvent"; User = "S-1-5-32-544"; Processid = "3444"; Provider = "SCM Event Provider"; queryid = "0"; PossibleCause = "Permanent" }))),
        # The same binding again at a later WMI start, the temporary query again
        # the same day and on the next day
        (New-TestRecord -Provider $wmiProvider -Id 5861 -Time "2026-02-03 09:00:00" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_ESStoConsumerBinding" -Data $cmd)),
        (New-TestRecord -Provider $wmiProvider -Id 5860 -Time "2026-02-02 20:00:00" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_TemporaryEssStarted" -Data $temp)),
        (New-TestRecord -Provider $wmiProvider -Id 5860 -Time "2026-02-03 08:00:30" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_TemporaryEssStarted" -Data $temp)),
        (New-TestRecord -Provider $wmiProvider -Id 5861 -Time "2026-02-03 10:00:00" -UserSid "S-1-5-18" -Body (New-UserDataXml -Wrapper "Operation_ESStoConsumerBinding" -Data $script))
    )
    $logBefore = Get-LogLineCount
    Add-WmiActivityEntries -Records $records -FileName $wmiFile -FilePath "X:\wmi.evtx"
    $lines = Get-NewLogLines $logBefore
    foreach ($expected in @("Skipped 1 event(s): 5857 WMI provider started (routine)", "Skipped 2 event(s): 5858 WMI operation failed (routine)",
            "Skipped 1 event(s): 5859 event filter activated for a permanent consumer (routine)", "Folded 2 repeated WMI subscription event(s) (5860 / 5861) into their first row (Count, LastSeen)")) {
        if (@($lines | Where-Object { $_.Trim() -ceq $expected }).Count -ne 1) { throw "log line missing: $expected (log: $($lines -join ' || '))" }
    }
} -Expected @(
    @{ Timestamp = "2026-02-02 08:00:00.000"; Source = $wmiFile; EventType = "PersistenceChange"; Description = "WMI permanent event subscription: filter `"UpdFilter`" -> CommandLineEventConsumer=`"UpdConsumer`""; User = ""
        Details = "EventID=5861 | Namespace=//./root/subscription | Filter=UpdFilter | Query=$wmiQuery | EventNamespace=root\cimv2 | ConsumerType=CommandLineEventConsumer | Consumer=UpdConsumer | CommandLineTemplate=cmd.exe /c `"C:\Users\Public\run.bat`" | Count=2 | LastSeen=2026-02-03 09:00:00"
        Artifact = "EventLogs" },
    @{ EventType = "PersistenceChange"; Description = "WMI permanent event subscription: filter `"SCM Event Log Filter`" -> NTEventLogEventConsumer=`"SCM Event Log Consumer`" (Windows default)"
        Details = "EventID=5861 | Namespace=//./root/subscription | Filter=SCM Event Log Filter | Query=select * from MSFT_SCMEventLogEvent | EventNamespace=root\cimv2 | ConsumerType=NTEventLogEventConsumer | Consumer=SCM Event Log Consumer | SourceName=Service Control Manager" },
    @{ Timestamp = "2026-02-02 08:00:30.000"; EventType = "Execution"; Description = "WMI temporary event subscription: SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct'"; User = "NT AUTHORITY\LOCAL SERVICE"
        Details = "EventID=5860 | Namespace=ROOT\SecurityCenter | Query=SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct' | User=NT AUTHORITY\LOCAL SERVICE | ClientProcessId=4321 | ClientMachine=TESTHOST | Count=2 | LastSeen=2026-02-02 20:00:00" },
    @{ Timestamp = "2026-02-03 08:00:30.000"; EventType = "Execution"
        Details = "EventID=5860 | Namespace=ROOT\SecurityCenter | Query=SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct' | User=NT AUTHORITY\LOCAL SERVICE | ClientProcessId=4321 | ClientMachine=TESTHOST" },
    @{ Timestamp = "2026-02-03 10:00:00.000"; EventType = "PersistenceChange"; Description = "WMI permanent event subscription: filter `"ScriptFilter`" -> ActiveScriptEventConsumer=`"ScriptConsumer`""
        Details = "EventID=5861 | Namespace=//./root/subscription | Filter=ScriptFilter | Query=SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' | EventNamespace=root\cimv2 | ConsumerType=ActiveScriptEventConsumer | Consumer=ScriptConsumer | ScriptingEngine=VBScript | ScriptText=Set o = CreateObject(`"WScript.Shell`")`no.Run `"calc.exe`"" }
)

# --- TerminalServices-RDPClient ---
$rdpFile = "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx"
$rdpProvider = "Microsoft-Windows-TerminalServices-ClientActiveXCore"
$activityA = "f6818d5d-ae3d-444f-bf3f-61ea8fbb0000"
$activityB = "0a0a0a0a-1111-2222-3333-444444444444"
Test-Case -Name "RDPClient 1024 / 1102 / 1027 / 1029 / 1026 / 1009 (server named by ActivityID)" -Action {
    $records = @(
        (New-TestRecord -Provider $rdpProvider -Id 1024 -Time "2026-02-04 10:00:00" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ Name = "Server Name"; Value = "srv01.contoso.test"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1102 -Time "2026-02-04 10:00:01" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ Name = "Server Address"; Value = "10.1.2.3"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1029 -Time "2026-02-04 10:00:02" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ TraceMessage = "rpMTvXv3Qz1W9VsU1g7o5Q5V6w0Tq2bhkuN3aW1J9cE=-" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1027 -Time "2026-02-04 10:00:03" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ DomainName = "CONTOSO"; SessionId = "2" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1026 -Time "2026-02-04 10:30:00" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ Name = "Disconnect Reason"; Value = "2055"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1102 -Time "2026-02-04 11:00:00" -UserSid $alice -ActivityId $activityB -Body (New-EventDataXml -Data ([ordered]@{ Name = "Server Address"; Value = "192.0.2.10"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1026 -Time "2026-02-04 11:00:05" -UserSid $alice -ActivityId $activityB -Body (New-EventDataXml -Data ([ordered]@{ Name = "Disconnect Reason"; Value = "9999"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1009 -Time "2026-02-04 12:00:00" -Level 3 -Body (New-EventDataXml -Data ([ordered]@{ TraceMessage = ""; "Error Code" = "0" })))
    )
    Add-RdpClientEntries -Records $records -FileName $rdpFile -FilePath "X:\rdp.evtx"
} -Expected @(
    @{ Timestamp = "2026-02-04 10:00:00.000"; Source = $rdpFile; EventType = "NetworkConnection"; Description = "Outbound RDP connection to srv01.contoso.test"; User = $alice
        Details = "EventID=1024 | Server=srv01.contoso.test | ActivityID=$activityA | UserSID=$alice"; Artifact = "EventLogs" },
    @{ EventType = "NetworkConnection"; Description = "Outbound RDP connection to srv01.contoso.test: multi-transport connection to 10.1.2.3"
        Details = "EventID=1102 | ServerAddress=10.1.2.3 | Server=srv01.contoso.test | ActivityID=$activityA | UserSID=$alice" },
    @{ Description = "Outbound RDP connection to srv01.contoso.test: user name hash rpMTvXv3Qz1W9VsU1g7o5Q5V6w0Tq2bhkuN3aW1J9cE=-"
        Details = "EventID=1029 | UserNameHash=rpMTvXv3Qz1W9VsU1g7o5Q5V6w0Tq2bhkuN3aW1J9cE=- | Server=srv01.contoso.test | ActivityID=$activityA | UserSID=$alice" },
    @{ Description = "Outbound RDP connection to srv01.contoso.test: connected (domain CONTOSO, session 2)"
        Details = "EventID=1027 | Domain=CONTOSO | SessionID=2 | Server=srv01.contoso.test | ActivityID=$activityA | UserSID=$alice" },
    @{ Description = "Outbound RDP connection to srv01.contoso.test: disconnected (reason 2055, login failed)"
        Details = "EventID=1026 | DisconnectReason=2055 | Server=srv01.contoso.test | ActivityID=$activityA | UserSID=$alice" },
    @{ Description = "Outbound RDP connection to 192.0.2.10: multi-transport connection to 192.0.2.10" },
    @{ Description = "Outbound RDP connection to 192.0.2.10: disconnected (reason 9999)"; Details = "EventID=1026 | DisconnectReason=9999 | Server=192.0.2.10 | ActivityID=$activityB | UserSID=$alice" },
    @{ Timestamp = "2026-02-04 12:00:00.000"; Description = "Outbound RDP connection: credentials not accepted by the server"; User = ""; Details = "EventID=1009" }
)

# --- NTLM/Operational ---
$ntlmFile = "Microsoft-Windows-NTLM%4Operational.evtx"
Test-Case -Name "NTLM 8001-8004 and 4020 / 4022 (NTLM version)" -Action {
    $events = @(
        @("Microsoft-Windows-NTLM", 8001, [ordered]@{ TargetName = "cifs/fs01"; UserName = "bob"; DomainName = "CONTOSO"; CallerPID = "4"; ProcessName = ""; ClientLUID = "0x3e7"; ClientUserName = "TESTHOST$"; ClientDomainName = "WORKGROUP"; MechanismOID = "(NULL)" }),
        @("Microsoft-Windows-NTLM", 8002, [ordered]@{ CallerPID = "4"; ProcessName = "System"; ClientLUID = "0x3e7"; ClientUserName = "alice"; ClientDomainName = "TESTHOST"; MechanismOID = "1.3.6.1.4.1.311.2.2.10" }),
        @("Microsoft-Windows-NTLM", 8003, [ordered]@{ UserName = "bob"; DomainName = "CONTOSO"; Workstation = "WKS-9"; CallerPID = "700"; ProcessName = "C:\Windows\System32\lsass.exe"; LogonType = "3"; InProc = "true"; MechanismOID = "(NULL)" }),
        @("Microsoft-Windows-Security-Netlogon", 8004, [ordered]@{ SChannelName = "FS01"; UserName = "bob"; DomainName = "CONTOSO"; WorkstationName = "WKS-9"; SChannelType = "2" }),
        @("Microsoft-Windows-NTLM", 4020, [ordered]@{ ProcessName = "C:\Windows\explorer.exe"; ProcessPID = "0x1234"; Username = "alice"; DomainName = "TESTHOST"; Hostname = "TESTHOST"; SingleSignOn = "Yes"; TargetMachine = "fs01"; TargetDomain = ""; TargetService = "cifs/fs01"; TargetIP = "10.0.0.5"; TargetNetworkName = ""; NtlmUsageId = "1"; NtlmUsageReason = "No Kerberos"; NegotiatedFlags = "0xe2888215"; NtlmVersion = "NTLMv2"; SessionKeyStatus = "OK"; ChannelBindingStatus = "None"; ServiceBinding = "cifs/fs01"; "Mic Status" = "Present"; AvlFlags = "0x2"; AvlFlagsStr = "MIC" }),
        @("Microsoft-Windows-NTLM", 4022, [ordered]@{ ProcessName = "System"; ProcessPID = "0x4"; Username = "bob"; DomainName = "CONTOSO"; RemoteClientMachine = "WKS-9"; ClientIP = "10.0.0.9"; ClientNetworkName = ""; NegotiatedFlags = "0x1"; NtlmVersion = "NTLMv1"; SessionKeyStatus = ""; ChannelBindingStatus = ""; ServiceBinding = ""; TargetMachine = "TESTHOST"; TargetDomain = ""; "Mic Status" = "Absent"; AvFlags = "0x0"; AvFlagsStr = ""; Status = "0x0"; StatusMsg = "0" })
    )
    $minute = 0
    foreach ($e in $events) {
        Add-NtlmEventEntry -Record (New-TestRecord -Provider $e[0] -Id $e[1] -Time ("2026-02-05 10:{0:D2}:00" -f $minute) -Body (New-EventDataXml -Data $e[2])) -FileName $ntlmFile -FilePath "X:\ntlm.evtx"
        $minute++
    }
} -Expected @(
    @{ Source = $ntlmFile; EventType = "NetworkConnection"; Description = "Outgoing NTLM authentication to cifs/fs01"; User = "CONTOSO\bob"
        Details = "EventID=8001 | Target=cifs/fs01 | Account=CONTOSO\bob | PID=4 | ProcessAccount=WORKGROUP\TESTHOST$"; Artifact = "EventLogs" },
    @{ EventType = "Logon"; Description = "Incoming NTLM authentication (process System, account TESTHOST\alice)"; User = "TESTHOST\alice"
        Details = "EventID=8002 | Process=System | PID=4 | ProcessAccount=TESTHOST\alice | MechanismOID=1.3.6.1.4.1.311.2.2.10" },
    @{ EventType = "Logon"; Description = "NTLM authentication in this domain: CONTOSO\bob from WKS-9"; User = "CONTOSO\bob"
        Details = "EventID=8003 | Account=CONTOSO\bob | Workstation=WKS-9 | LogonType=3 | Process=C:\Windows\System32\lsass.exe | PID=700" },
    @{ EventType = "Logon"; Description = "NTLM authentication passed to this domain controller: CONTOSO\bob from WKS-9 (secure channel FS01)"
        Details = "EventID=8004 | Account=CONTOSO\bob | Workstation=WKS-9 | SecureChannel=FS01 | SecureChannelType=2" },
    @{ EventType = "NetworkConnection"; Description = "Outgoing NTLM authentication to fs01 (NTLMv2)"; User = "TESTHOST\alice"
        Details = "EventID=4020 | Target=fs01 | TargetIP=10.0.0.5 | TargetService=cifs/fs01 | NtlmVersion=NTLMv2 | Account=TESTHOST\alice | Process=C:\Windows\explorer.exe | PID=0x1234 | Reason=No Kerberos | ServiceBinding=cifs/fs01 | MicStatus=Present" },
    @{ EventType = "Logon"; Description = "Incoming NTLM authentication from WKS-9 (NTLMv1)"; User = "CONTOSO\bob"
        Details = "EventID=4022 | Account=CONTOSO\bob | ClientMachine=WKS-9 | ClientIP=10.0.0.9 | NtlmVersion=NTLMv1 | Process=System | PID=0x4 | Status=0x0 | MicStatus=Absent" }
)

# --- Windows Firewall ---
$fwFile = "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
$fwProvider = "Microsoft-Windows-Windows Firewall With Advanced Security"
$mpssvc = "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052"
# Rule fields of 2004 / 2005 (2071 / 2073 / 2097 / 2099 add ErrorCode, 2097 / 2099 also PolicyAppId)
function New-FirewallRuleData {
    param([string]$RuleId, [string]$Name, [string]$App, [string]$Direction, [string]$Protocol, [string]$LocalPorts, [string]$Action, [string]$Profiles, [string]$User, [string]$ErrorCode = $null)
    $data = [ordered]@{ RuleId = $RuleId; RuleName = $Name; Origin = "1"; ApplicationPath = $App; ServiceName = ""; Direction = $Direction; Protocol = $Protocol; LocalPorts = $LocalPorts; RemotePorts = "*"
        Action = $Action; Profiles = $Profiles; LocalAddresses = "*"; RemoteAddresses = "*"; RemoteMachineAuthorizationList = ""; RemoteUserAuthorizationList = ""; EmbeddedContext = ""; Flags = "1"; Active = "1"
        EdgeTraversal = "0"; LooseSourceMapped = "0"; SecurityOptions = "0"; ModifyingUser = $User; ModifyingApplication = "C:\Windows\System32\netsh.exe"; SchemaVersion = "545"; RuleStatus = "65536"; LocalOnlyMapped = "0" }
    if ($null -ne $ErrorCode) { $data["PolicyAppId"] = ""; $data["ErrorCode"] = $ErrorCode }
    return $data
}
Test-Case -Name "Firewall rule added / modified / deleted, all deleted, reset, settings (old and new IDs; firewall service rules counted)" -Action {
    $records = @(
        (New-TestRecord -Provider $fwProvider -Id 2097 -Time "2026-02-06 10:00:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data (New-FirewallRuleData -RuleId "{AAAA}" -Name "Open RDP" -App "" -Direction "1" -Protocol "6" -LocalPorts "3389" -Action "3" -Profiles "7" -User $alice -ErrorCode "0"))),
        (New-TestRecord -Provider $fwProvider -Id 2099 -Time "2026-02-06 10:01:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data (New-FirewallRuleData -RuleId "{BBBB}" -Name "Block EDR" -App "C:\Program Files\EDR\agent.exe" -Direction "2" -Protocol "256" -LocalPorts "" -Action "2" -Profiles "2147483647" -User "S-1-5-18" -ErrorCode "2"))),
        (New-TestRecord -Provider $fwProvider -Id 2052 -Time "2026-02-06 10:02:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ RuleId = "{AAAA}"; RuleName = "Open RDP"; ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\wbem\WmiPrvSE.exe"; ErrorCode = "0" }))),
        (New-TestRecord -Provider $fwProvider -Id 2004 -Time "2026-02-06 10:03:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data (New-FirewallRuleData -RuleId "{CCCC}" -Name "Old add" -App "C:\Temp\x.exe" -Direction "1" -Protocol "17" -LocalPorts "53" -Action "1" -Profiles "4" -User $alice))),
        (New-TestRecord -Provider $fwProvider -Id 2006 -Time "2026-02-06 10:04:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ RuleId = "{CCCC}"; RuleName = "Old add"; ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\netsh.exe" }))),
        (New-TestRecord -Provider $fwProvider -Id 2033 -Time "2026-02-06 10:05:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ "Store Type" = "2"; ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\netsh.exe" }))),
        (New-TestRecord -Provider $fwProvider -Id 2060 -Time "2026-02-06 10:06:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\netsh.exe"; ErrorCode = "0" }))),
        (New-TestRecord -Provider $fwProvider -Id 2082 -Time "2026-02-06 10:07:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ Profiles = "4"; SettingType = "1"; SettingValueSize = "4"; SettingValue = "00000000"; SettingValueString = "No"; Origin = "1"; ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\netsh.exe"; ErrorCode = "0" }))),
        (New-TestRecord -Provider $fwProvider -Id 2003 -Time "2026-02-06 10:08:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ Profiles = "1"; SettingType = "17"; SettingValueSize = "4"; SettingValue = "00000000"; SettingValueString = "Allow"; Origin = "1"; ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\netsh.exe" }))),
        (New-TestRecord -Provider $fwProvider -Id 2082 -Time "2026-02-06 10:09:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ Profiles = "2"; SettingType = "99"; SettingValueString = "1"; ModifyingUser = "S-1-5-18"; ModifyingApplication = "C:\Windows\System32\svchost.exe"; ErrorCode = "0" }))),
        (New-TestRecord -Provider $fwProvider -Id 2083 -Time "2026-02-06 10:10:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ SettingType = "4"; SettingValueSize = "4"; SettingValue = "01000000"; SettingValueDisplay = "Yes"; Origin = "1"; ModifyingUser = $alice; ModifyingApplication = "C:\Windows\System32\netsh.exe"; ErrorCode = "0" }))),
        # The firewall service's own packaged-app rules: counted only
        (New-TestRecord -Provider $fwProvider -Id 2097 -Time "2026-02-06 10:11:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data (New-FirewallRuleData -RuleId "App_8wekyb3d8bbweS-1-5-21-1-In-Allow" -Name "Store App" -App "" -Direction "1" -Protocol "256" -LocalPorts "" -Action "3" -Profiles "7" -User $mpssvc -ErrorCode "0"))),
        (New-TestRecord -Provider $fwProvider -Id 2052 -Time "2026-02-06 10:12:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ RuleId = "App"; RuleName = "Store App"; ModifyingUser = $mpssvc; ModifyingApplication = "C:\WINDOWS\System32\svchost.exe"; ErrorCode = "0" }))),
        (New-TestRecord -Provider $fwProvider -Id 2059 -Time "2026-02-06 10:13:00" -UserSid "S-1-5-19" -Body (New-EventDataXml -Data ([ordered]@{ "Store Type" = "12"; ModifyingUser = $mpssvc; ModifyingApplication = "C:\WINDOWS\System32\svchost.exe"; ErrorCode = "0" })))
    )
    $logBefore = Get-LogLineCount
    Add-FirewallEntries -Records $records -FileName $fwFile -FilePath "X:\fw.evtx"
    if (@(Get-NewLogLines $logBefore | Where-Object { $_ -match 'Skipped 3 event\(s\): rules the firewall service adds and removes for packaged \(Store\) apps' }).Count -ne 1) {
        throw "no log line counting the firewall service's rule events"
    }
} -Expected @(
    @{ Timestamp = "2026-02-06 10:00:00.000"; Source = $fwFile; EventType = "PersistenceChange"; Description = "Firewall rule added: Open RDP (Inbound, Allow)"; User = $alice
        Details = "EventID=2097 | RuleName=Open RDP | RuleId={AAAA} | Direction=Inbound | Action=Allow | Protocol=TCP | LocalPorts=3389 | RemotePorts=* | RemoteAddresses=* | Profiles=Domain, Private, Public | Active=Yes | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=$alice"
        Artifact = "EventLogs" },
    @{ EventType = "PersistenceChange"; Description = "Firewall rule modified: Block EDR (Outbound, Block)"; User = "SYSTEM"
        Details = "EventID=2099 | RuleName=Block EDR | RuleId={BBBB} | ApplicationPath=C:\Program Files\EDR\agent.exe | Direction=Outbound | Action=Block | Protocol=Any | RemotePorts=* | RemoteAddresses=* | Profiles=All | Active=Yes | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=S-1-5-18 | ErrorCode=2" },
    @{ EventType = "PersistenceChange"; Description = "Firewall rule deleted: Open RDP"
        Details = "EventID=2052 | RuleName=Open RDP | RuleId={AAAA} | ModifyingApplication=C:\Windows\System32\wbem\WmiPrvSE.exe | ModifyingUser=$alice" },
    @{ EventType = "PersistenceChange"; Description = "Firewall rule added: Old add (Inbound, Allow bypass)"
        Details = "EventID=2004 | RuleName=Old add | RuleId={CCCC} | ApplicationPath=C:\Temp\x.exe | Direction=Inbound | Action=Allow bypass | Protocol=UDP | LocalPorts=53 | RemotePorts=* | RemoteAddresses=* | Profiles=Public | Active=Yes | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=$alice" },
    @{ EventType = "PersistenceChange"; Description = "Firewall rule deleted: Old add" },
    @{ EventType = "SecurityAlert"; Description = "All firewall rules deleted"; Details = "EventID=2033 | StoreType=2 | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=$alice" },
    @{ EventType = "SecurityAlert"; Description = "Firewall reset to its default configuration"; Details = "EventID=2060 | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=$alice" },
    @{ EventType = "SecurityAlert"; Description = "Firewall setting changed (Public profile): Enable firewall = No"
        Details = "EventID=2082 | Profiles=Public | Setting=Enable firewall | SettingType=1 | Value=No | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=$alice" },
    @{ EventType = "SecurityAlert"; Description = "Firewall setting changed (Domain profile): Default inbound action = Allow" },
    @{ EventType = "SecurityAlert"; Description = "Firewall setting changed (Private profile): setting type 99 = 1"; User = "SYSTEM" },
    @{ EventType = "SecurityAlert"; Description = "Firewall global setting changed: global setting type 4 = Yes"
        Details = "EventID=2083 | Setting=global setting type 4 | SettingType=4 | Value=Yes | ModifyingApplication=C:\Windows\System32\netsh.exe | ModifyingUser=$alice" }
)

# --- Shell-Core ---
$shellFile = "Microsoft-Windows-Shell-Core%4Operational.evtx"
$shellProvider = "Microsoft-Windows-Shell-Core"
Test-Case -Name "Shell-Core 9705-9708: Run / RunOnce commands at logon (start and launch paired per Explorer process)" -Action {
    $records = @(
        (New-TestRecord -Provider $shellProvider -Id 9705 -Time "2026-02-07 08:00:00" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ KeyName = "Software\Microsoft\Windows\CurrentVersion\Run" }))),
        (New-TestRecord -Provider $shellProvider -Id 9707 -Time "2026-02-07 08:00:01" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ Command = "updater.exe`" /silent" }))),
        # Another Explorer process, at the same time
        (New-TestRecord -Provider $shellProvider -Id 9708 -Time "2026-02-07 08:00:01" -UserSid $alice -ProcessId "5555" -Body (New-EventDataXml -Data ([ordered]@{ PID = "777"; Command = "orphan.exe" }))),
        (New-TestRecord -Provider $shellProvider -Id 9708 -Time "2026-02-07 08:00:03" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ PID = "4242"; Command = "updater.exe`" /silent" }))),
        (New-TestRecord -Provider $shellProvider -Id 9706 -Time "2026-02-07 08:00:03" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ KeyName = "Software\Microsoft\Windows\CurrentVersion\Run" }))),
        (New-TestRecord -Provider $shellProvider -Id 9705 -Time "2026-02-07 08:00:04" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ KeyName = "Software\Microsoft\Windows\CurrentVersion\RunOnce" }))),
        (New-TestRecord -Provider $shellProvider -Id 9707 -Time "2026-02-07 08:00:05" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ Command = "stage2.cmd" }))),
        (New-TestRecord -Provider $shellProvider -Id 9706 -Time "2026-02-07 08:00:06" -UserSid $alice -ProcessId "9688" -Body (New-EventDataXml -Data ([ordered]@{ KeyName = "Software\Microsoft\Windows\CurrentVersion\RunOnce" })))
    )
    Add-ShellCoreEntries -Records $records -FileName $shellFile -FilePath "X:\shell.evtx"
} -Expected @(
    @{ Timestamp = "2026-02-07 08:00:01.000"; Source = $shellFile; EventType = "Execution"; Description = "Run key command started at logon: updater.exe`" /silent"; User = $alice
        Details = "EventID=9707 | Command=updater.exe`" /silent | ProcessId=4242 | RegistryKey=Software\Microsoft\Windows\CurrentVersion\Run | Launched=2026-02-07 08:00:03 | UserSID=$alice"; Artifact = "EventLogs" },
    @{ Timestamp = "2026-02-07 08:00:01.000"; Description = "Run or RunOnce key command started at logon: orphan.exe"; Details = "EventID=9708 | Command=orphan.exe | ProcessId=777 | UserSID=$alice" },
    @{ Timestamp = "2026-02-07 08:00:05.000"; Description = "RunOnce key command started at logon: stage2.cmd"
        Details = "EventID=9707 | Command=stage2.cmd | RegistryKey=Software\Microsoft\Windows\CurrentVersion\RunOnce | UserSID=$alice" }
)

# --- OAlerts ---
$longAlert = "Microsoft Word has blocked macros. " + ("y" * 1100)
Test-Case -Name "OAlerts 300: Office alerts (diagnostic events counted)" -Action {
    $records = @(
        (New-TestRecord -Provider "Microsoft Office 16 Alerts" -Id 300 -Time "2026-02-08 09:00:00" -Body (New-EventDataXml -Data @("Microsoft Word`n", "SECURITY WARNING  Macros have been disabled.`n", "200054`n", "16.0.19231.20156`n", "0x0`n", "invoice.docm`n"))),
        (New-TestRecord -Provider "Microsoft Office 16 Alerts" -Id 300 -Time "2026-02-08 09:01:00" -Body (New-EventDataXml -Data @("Compositor Type: 1", "EXCEL"))),
        (New-TestRecord -Provider "Microsoft Office 16 Alerts" -Id 300 -Time "2026-02-08 09:02:00" -Level 2 -Body (New-EventDataXml -Data @("Microsoft Word", $longAlert, "100", "16.0.1", "", "")))
    )
    $logBefore = Get-LogLineCount
    Add-OfficeAlertEntries -Records $records -FileName "OAlerts.evtx" -FilePath "X:\OAlerts.evtx"
    if (@(Get-NewLogLines $logBefore | Where-Object { $_ -match 'Skipped 1 event\(s\): Office diagnostics that are not alerts' }).Count -ne 1) { throw "no log line counting the diagnostic event" }
} -Expected @(
    @{ Timestamp = "2026-02-08 09:00:00.000"; Source = "OAlerts.evtx"; EventType = "Execution"; Description = "Office alert (Microsoft Word): SECURITY WARNING Macros have been disabled."; User = ""
        Details = "EventID=300 | Application=Microsoft Word | Message=SECURITY WARNING Macros have been disabled. | P1=200054 | Version=16.0.19231.20156 | P3=0x0 | Document=invoice.docm"; Artifact = "EventLogs" },
    @{ Description = "Office alert (Microsoft Word): " + $longAlert.Substring(0, 200) + "..."
        Details = "EventID=300 | Application=Microsoft Word | Message=" + $longAlert.Substring(0, 1000) + "... | P1=100 | Version=16.0.1" }
)

# --- Antivirus products' own logs (AntiVirus\*.evtx) ---
Test-Case -Name "AntiVirus\*.evtx: every event through the antivirus filter (routine Information events counted)" -Action {
    $records = @(
        (New-TestRecord -Provider "Symantec Endpoint Protection Client" -Id 7 -Time "2026-02-09 10:00:00" -Message "New virus definition file loaded."),
        (New-TestRecord -Provider "SepScan" -Id 51 -Time "2026-02-09 10:01:00" -Message "Security Risk Found!  Trojan.Gen in File: C:\Users\bob\y.exe by: Auto-Protect scan.  Action: Quarantine succeeded."),
        (New-TestRecord -Provider "CrowdStrike-Falcon Sensor" -Id 3 -Time "2026-02-09 10:02:00" -Level 3 -UserSid "S-1-5-18" -Values @("Sensor heartbeat failed", "(NULL)", "cloud unreachable"))
    )
    $logBefore = Get-LogLineCount
    Add-AntiVirusLogEntries -Records $records -FileName "Symantec_SEP_EventLog.evtx" -FilePath "X:\AntiVirus\Symantec_SEP_EventLog.evtx"
    if (@(Get-NewLogLines $logBefore | Where-Object { $_ -match 'Skipped 1 event\(s\): antivirus Information events that report no detection' }).Count -ne 1) { throw "no log line counting the routine event" }
} -Expected @(
    @{ Timestamp = "2026-02-09 10:01:00.000"; Source = "Symantec_SEP_EventLog.evtx"; EventType = "SecurityAlert"; Description = "Antivirus event (SepScan 51): Security Risk Found! Trojan.Gen in File: C:\Users\bob\y.exe by: Auto-Protect scan. Action: Quarantine succeeded."
        Details = "EventID=51 | Provider=SepScan | Level=Information | Message=Security Risk Found! Trojan.Gen in File: C:\Users\bob\y.exe by: Auto-Protect scan. Action: Quarantine succeeded."; Artifact = "AntiVirus"; RawPath = "X:\AntiVirus\Symantec_SEP_EventLog.evtx" },
    @{ EventType = "SecurityAlert"; Description = "Antivirus event (CrowdStrike-Falcon Sensor 3): Sensor heartbeat failed | cloud unreachable"
        Details = "EventID=3 | Provider=CrowdStrike-Falcon Sensor | Level=Warning | Message=Sensor heartbeat failed | cloud unreachable | UserSID=S-1-5-18"; Artifact = "AntiVirus" }
)

# --- Parse-EventLogs dispatch ---
# Parse-EventLogs itself on synthetic records, with Get-WinEvent replaced by
# Get-TestWinEvent, which applies the EventID and provider terms of the XPath
# it is given. Checks which IDs each new channel reads (other IDs must give
# no row), that AntiVirus\*.evtx are read whole, that no query has more than
# 20 terms, and the details of Security 4624.
$script:mockEvtx = @{ Records = @{}; Queries = 0; MaxTerms = 0 }
function Get-TestWinEvent {
    [CmdletBinding()]
    param([string]$Path, [string]$FilterXPath)
    $ids = @([regex]::Matches($FilterXPath, 'EventID=(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
    $providers = @([regex]::Matches($FilterXPath, "@Name='([^']+)'") | ForEach-Object { $_.Groups[1].Value })
    $script:mockEvtx.Queries++
    $script:mockEvtx.MaxTerms = [Math]::Max($script:mockEvtx.MaxTerms, $ids.Count + $providers.Count)
    foreach ($record in @($script:mockEvtx.Records[(Split-Path $Path -Leaf)])) {
        if ($null -eq $record) { continue }
        if ($ids.Count -gt 0 -and $ids -notcontains [int]$record.Id) { continue }
        if ($providers.Count -gt 0 -and $providers -notcontains $record.ProviderName) { continue }
        $record
    }
}

$dispatchDir = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx2-dispatch-" + [guid]::NewGuid().ToString("N"))
try {
    $files = @("EventLogs\Security.evtx", "EventLogs\$psFile", "EventLogs\$wmiFile", "EventLogs\$rdpFile", "EventLogs\$ntlmFile", "EventLogs\$fwFile", "EventLogs\$shellFile",
        "EventLogs\OAlerts.evtx", "AntiVirus\Symantec_SEP_EventLog.evtx", "AntiVirus\CrowdStrike_EventLog.evtx")
    foreach ($name in $files) {
        $path = Join-Path $dispatchDir $name
        New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
        Set-Content -LiteralPath $path -Value "placeholder" -Encoding ASCII
    }
    $auditing = "Microsoft-Windows-Security-Auditing"
    $subject = [ordered]@{ SubjectUserSid = "S-1-5-18"; SubjectUserName = "TESTHOST$"; SubjectDomainName = "WORKGROUP"; SubjectLogonId = "0x3e7" }
    $ntlmLogon = [ordered]@{ TargetUserSid = "S-1-5-21-1111-2222-3333-1002"; TargetUserName = "bob"; TargetDomainName = "TESTHOST"; TargetLogonId = "0x99"; LogonType = "3"; LogonProcessName = "NtLmSsp "
        AuthenticationPackageName = "NTLM"; WorkstationName = "WKS-9"; LmPackageName = "NTLM V1"; KeyLength = "0"; IpAddress = "10.0.0.9"; IpPort = "51515" }
    $kerberosLogon = [ordered]@{ TargetUserSid = $alice; TargetUserName = "alice"; TargetDomainName = "TESTHOST"; TargetLogonId = "0x77"; LogonType = "2"; LogonProcessName = "User32 "
        AuthenticationPackageName = "Negotiate"; WorkstationName = "-"; LmPackageName = "-"; KeyLength = "0"; IpAddress = "-"; IpPort = "-" }
    foreach ($key in $subject.Keys) { $ntlmLogon[$key] = $subject[$key]; $kerberosLogon[$key] = $subject[$key] }
    $script:mockEvtx.Records["Security.evtx"] = @(
        (New-TestRecord -Provider $auditing -Id 4624 -Time "2026-02-10 08:00:00" -Body (New-EventDataXml -Data $ntlmLogon)),
        (New-TestRecord -Provider $auditing -Id 4624 -Time "2026-02-10 08:00:01" -Body (New-EventDataXml -Data $kerberosLogon))
    )
    $script:mockEvtx.Records[$psFile] = @(
        (New-TestRecord -Provider "PowerShell" -Id 400 -Time "2026-02-10 09:00:00" -Body (New-EventDataXml -Data @("Available", "None", (New-PowerShellContext -HostApplication "powershell.exe -c 1")))),
        (New-TestRecord -Provider "PowerShell" -Id 403 -Time "2026-02-10 09:00:01" -Body (New-EventDataXml -Data @("Stopped", "Available", (New-PowerShellContext -HostApplication "powershell.exe -c 1")))),
        (New-TestRecord -Provider "PowerShell" -Id 600 -Time "2026-02-10 09:00:02" -Body (New-EventDataXml -Data @("Variable", "Started", "x"))),
        (New-TestRecord -Provider "PowerShell" -Id 300 -Time "2026-02-10 09:00:03" -Level 3 -Body (New-EventDataXml -Data @("x", "y")))
    )
    $tempData = [ordered]@{ NamespaceName = "root\cimv2"; Query = "SELECT * FROM Win32_ProcessStartTrace"; User = "TESTHOST\alice"; Processid = "1"; ClientMachine = "TESTHOST"; PossibleCause = "Temporary" }
    $script:mockEvtx.Records[$wmiFile] = @(
        (New-TestRecord -Provider $wmiProvider -Id 5861 -Time "2026-02-10 10:00:00" -Body (New-UserDataXml -Wrapper "Operation_ESStoConsumerBinding" -Data ([ordered]@{ Namespace = "//./root/subscription"; ESS = "F"; CONSUMER = "CommandLineEventConsumer=`"C`""; PossibleCause = (New-WmiBindingCause -FilterName "F" -Query "q" -ConsumerClass "CommandLineEventConsumer" -ConsumerLines @("CommandLineTemplate = `"cmd`";", "Name = `"C`";")) }))),
        (New-TestRecord -Provider $wmiProvider -Id 5860 -Time "2026-02-10 10:00:01" -Body (New-UserDataXml -Wrapper "Operation_TemporaryEssStarted" -Data $tempData)),
        (New-TestRecord -Provider $wmiProvider -Id 5858 -Time "2026-02-10 10:00:02" -Level 2 -Body (New-UserDataXml -Wrapper "Operation_ClientFailure" -Data ([ordered]@{ Operation = "x" }))),
        (New-TestRecord -Provider $wmiProvider -Id 5603 -Time "2026-02-10 10:00:03" -Body (New-UserDataXml -Wrapper "Other" -Data ([ordered]@{ X = "y" })))
    )
    $script:mockEvtx.Records[$rdpFile] = @(
        (New-TestRecord -Provider $rdpProvider -Id 1024 -Time "2026-02-10 11:00:00" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ Name = "Server Name"; Value = "srv01"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1102 -Time "2026-02-10 11:00:01" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ Name = "Server Address"; Value = "10.1.2.3"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1027 -Time "2026-02-10 11:00:02" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ DomainName = "CONTOSO"; SessionId = "2" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1029 -Time "2026-02-10 11:00:03" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ TraceMessage = "hash=" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1009 -Time "2026-02-10 11:00:04" -UserSid $alice -ActivityId $activityA -Level 3 -Body (New-EventDataXml -Data ([ordered]@{ TraceMessage = ""; "Error Code" = "0" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1026 -Time "2026-02-10 11:00:05" -UserSid $alice -ActivityId $activityA -Body (New-EventDataXml -Data ([ordered]@{ Name = "Disconnect Reason"; Value = "1"; CustomLevel = "Info" }))),
        (New-TestRecord -Provider $rdpProvider -Id 1105 -Time "2026-02-10 11:00:06" -UserSid $alice -ActivityId $activityA),
        (New-TestRecord -Provider $rdpProvider -Id 226 -Time "2026-02-10 11:00:07" -UserSid $alice -ActivityId $activityA -Level 3)
    )
    $script:mockEvtx.Records[$ntlmFile] = @(
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 8001 -Time "2026-02-10 12:00:00" -Body (New-EventDataXml -Data ([ordered]@{ TargetName = "cifs/fs01"; UserName = "bob"; DomainName = "CONTOSO" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 8002 -Time "2026-02-10 12:00:01" -Body (New-EventDataXml -Data ([ordered]@{ ProcessName = "System"; ClientUserName = "alice"; ClientDomainName = "TESTHOST" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 8003 -Time "2026-02-10 12:00:02" -Body (New-EventDataXml -Data ([ordered]@{ UserName = "bob"; DomainName = "CONTOSO"; Workstation = "WKS-9" }))),
        (New-TestRecord -Provider "Microsoft-Windows-Security-Netlogon" -Id 8004 -Time "2026-02-10 12:00:03" -Body (New-EventDataXml -Data ([ordered]@{ SChannelName = "FS01"; UserName = "bob"; DomainName = "CONTOSO"; WorkstationName = "WKS-9" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 4020 -Time "2026-02-10 12:00:04" -Body (New-EventDataXml -Data ([ordered]@{ TargetMachine = "fs01"; NtlmVersion = "NTLMv2" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 4021 -Time "2026-02-10 12:00:05" -Level 3 -Body (New-EventDataXml -Data ([ordered]@{ TargetMachine = "fs02"; NtlmVersion = "NTLMv1" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 4022 -Time "2026-02-10 12:00:06" -Body (New-EventDataXml -Data ([ordered]@{ RemoteClientMachine = "WKS-9"; NtlmVersion = "NTLMv2" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 4023 -Time "2026-02-10 12:00:07" -Level 3 -Body (New-EventDataXml -Data ([ordered]@{ ClientIP = "10.0.0.8"; NtlmVersion = "NTLMv1" }))),
        (New-TestRecord -Provider "Microsoft-Windows-NTLM" -Id 4001 -Time "2026-02-10 12:00:08" -Level 3 -Body (New-EventDataXml -Data ([ordered]@{ TargetName = "x" })))
    )
    $fwIds = @(2004, 2071, 2097, 2005, 2073, 2099, 2006, 2052, 2033, 2059, 2032, 2060, 2003, 2082, 2002, 2083, 2010, 2084)
    $second = 0
    $script:mockEvtx.Records[$fwFile] = @(foreach ($id in $fwIds) {
            $second++
            New-TestRecord -Provider $fwProvider -Id $id -Time ("2026-02-10 13:00:{0:D2}" -f $second) -Body (New-EventDataXml -Data ([ordered]@{ RuleName = "R$id"; Direction = "1"; Action = "3"; SettingType = "1"; SettingValueString = "No"; Profiles = "4"; ModifyingUser = $alice }))
        })
    $script:mockEvtx.Records[$shellFile] = @(
        (New-TestRecord -Provider $shellProvider -Id 9705 -Time "2026-02-10 14:00:00" -ProcessId "1" -Body (New-EventDataXml -Data ([ordered]@{ KeyName = "Software\Microsoft\Windows\CurrentVersion\Run" }))),
        (New-TestRecord -Provider $shellProvider -Id 9707 -Time "2026-02-10 14:00:01" -ProcessId "1" -Body (New-EventDataXml -Data ([ordered]@{ Command = "a.exe" }))),
        (New-TestRecord -Provider $shellProvider -Id 9708 -Time "2026-02-10 14:00:02" -ProcessId "1" -Body (New-EventDataXml -Data ([ordered]@{ PID = "5"; Command = "a.exe" }))),
        (New-TestRecord -Provider $shellProvider -Id 9706 -Time "2026-02-10 14:00:03" -ProcessId "1" -Body (New-EventDataXml -Data ([ordered]@{ KeyName = "Software\Microsoft\Windows\CurrentVersion\Run" }))),
        (New-TestRecord -Provider $shellProvider -Id 62170 -Time "2026-02-10 14:00:04" -ProcessId "1")
    )
    $script:mockEvtx.Records["OAlerts.evtx"] = @(
        (New-TestRecord -Provider "Microsoft Office 16 Alerts" -Id 300 -Time "2026-02-10 15:00:00" -Body (New-EventDataXml -Data @("Microsoft Excel", "Protected View", "1", "16.0", "", "a.xlsx"))),
        (New-TestRecord -Provider "Microsoft Office 16 Alerts" -Id 301 -Time "2026-02-10 15:00:01" -Body (New-EventDataXml -Data @("x", "y", "z")))
    )
    $script:mockEvtx.Records["Symantec_SEP_EventLog.evtx"] = @(
        (New-TestRecord -Provider "Symantec Endpoint Protection Client" -Id 45 -Time "2026-02-10 16:00:00" -Level 2 -Message "Tamper protection blocked a change")
    )
    $script:mockEvtx.Records["CrowdStrike_EventLog.evtx"] = @(
        (New-TestRecord -Provider "CSFalconService" -Id 1 -Time "2026-02-10 16:01:00" -Message "Sensor started"),
        (New-TestRecord -Provider "CSFalconService" -Id 2 -Time "2026-02-10 16:02:00" -Message "Malware detected and quarantined: C:\x.exe")
    )

    $expectedRows = @(
        @("Security.evtx", "Logon", "Successful logon (Network)", "LogonType=3 | Source=10.0.0.9:51515 | LogonID=0x99 | IpAddress=10.0.0.9 | WorkstationName=WKS-9 | AuthenticationPackageName=NTLM | LmPackageName=NTLM V1 | KeyLength=0"),
        @("Security.evtx", "Logon", "Successful logon (Interactive)", "LogonType=2 | Source=-:- | LogonID=0x77 | AuthenticationPackageName=Negotiate | KeyLength=0"),
        @($psFile, "Execution", "PowerShell engine started: powershell.exe -c 1", "EventID=400 | *"),
        @($psFile, "Execution", "PowerShell engine stopped: powershell.exe -c 1", "EventID=403 | *"),
        @($wmiFile, "PersistenceChange", "WMI permanent event subscription: filter `"F`" -> CommandLineEventConsumer=`"C`"", "*CommandLineTemplate=cmd"),
        @($wmiFile, "Execution", "WMI temporary event subscription: SELECT * FROM Win32_ProcessStartTrace", "EventID=5860 | *"),
        @($rdpFile, "NetworkConnection", "Outbound RDP connection to srv01", "EventID=1024 | *"),
        @($rdpFile, "NetworkConnection", "Outbound RDP connection to srv01: multi-transport connection to 10.1.2.3", "EventID=1102 | *"),
        @($rdpFile, "NetworkConnection", "Outbound RDP connection to srv01: connected (domain CONTOSO, session 2)", "EventID=1027 | *"),
        @($rdpFile, "NetworkConnection", "Outbound RDP connection to srv01: user name hash hash=", "EventID=1029 | *"),
        @($rdpFile, "NetworkConnection", "Outbound RDP connection to srv01: credentials not accepted by the server", "EventID=1009 | *"),
        @($rdpFile, "NetworkConnection", "Outbound RDP connection to srv01: disconnected (reason 1, local disconnection)", "EventID=1026 | *"),
        @($ntlmFile, "NetworkConnection", "Outgoing NTLM authentication to cifs/fs01", "EventID=8001 | *"),
        @($ntlmFile, "Logon", "Incoming NTLM authentication (process System, account TESTHOST\alice)", "EventID=8002 | *"),
        @($ntlmFile, "Logon", "NTLM authentication in this domain: CONTOSO\bob from WKS-9", "EventID=8003 | *"),
        @($ntlmFile, "Logon", "NTLM authentication passed to this domain controller: CONTOSO\bob from WKS-9 (secure channel FS01)", "EventID=8004 | *"),
        @($ntlmFile, "NetworkConnection", "Outgoing NTLM authentication to fs01 (NTLMv2)", "EventID=4020 | *"),
        @($ntlmFile, "NetworkConnection", "Outgoing NTLM authentication to fs02 (NTLMv1)", "EventID=4021 | *"),
        @($ntlmFile, "Logon", "Incoming NTLM authentication from WKS-9 (NTLMv2)", "EventID=4022 | *"),
        @($ntlmFile, "Logon", "Incoming NTLM authentication from 10.0.0.8 (NTLMv1)", "EventID=4023 | *"),
        @($shellFile, "Execution", "Run key command started at logon: a.exe", "EventID=9707 | Command=a.exe | ProcessId=5 | *"),
        @("OAlerts.evtx", "Execution", "Office alert (Microsoft Excel): Protected View", "EventID=300 | *"),
        @("Symantec_SEP_EventLog.evtx", "SecurityAlert", "Antivirus event (Symantec Endpoint Protection Client 45): Tamper protection blocked a change", "EventID=45 | *Level=Error*"),
        @("CrowdStrike_EventLog.evtx", "SecurityAlert", "Antivirus event (CSFalconService 2): Malware detected and quarantined: C:\x.exe", "EventID=2 | *")
    )
    foreach ($id in @(2004, 2071, 2097)) { $expectedRows += , @($fwFile, "PersistenceChange", "Firewall rule added: R$id (Inbound, Allow)", "EventID=$id | *") }
    foreach ($id in @(2005, 2073, 2099)) { $expectedRows += , @($fwFile, "PersistenceChange", "Firewall rule modified: R$id (Inbound, Allow)", "EventID=$id | *") }
    foreach ($id in @(2006, 2052)) { $expectedRows += , @($fwFile, "PersistenceChange", "Firewall rule deleted: R$id", "EventID=$id | *") }
    foreach ($id in @(2033, 2059)) { $expectedRows += , @($fwFile, "SecurityAlert", "All firewall rules deleted", "EventID=$id | *") }
    foreach ($id in @(2032, 2060)) { $expectedRows += , @($fwFile, "SecurityAlert", "Firewall reset to its default configuration", "EventID=$id | *") }
    foreach ($id in @(2003, 2082)) { $expectedRows += , @($fwFile, "SecurityAlert", "Firewall setting changed (Public profile): Enable firewall = No", "EventID=$id | *") }
    foreach ($id in @(2002, 2083)) { $expectedRows += , @($fwFile, "SecurityAlert", "Firewall global setting changed: global setting type 1 = No", "EventID=$id | *") }

    $logBefore = Get-LogLineCount
    $before = $script:timelineEntries.Count
    & {
        # Local to this block: the builder's Get-WinEvent calls reach the stand-in
        Set-Alias -Name Get-WinEvent -Value Get-TestWinEvent
        Set-Variable -Name InputPath -Value $dispatchDir
        Parse-EventLogs
    }
    $rows = @()
    for ($i = $before; $i -lt $script:timelineEntries.Count; $i++) { $rows += $script:timelineEntries[$i] }
    $problems = @()
    foreach ($expected in $expectedRows) {
        $match = @($rows | Where-Object { $_.Source -eq $expected[0] -and $_.EventType -eq $expected[1] -and $_.Description -ceq $expected[2] -and $_.Details -clike $expected[3] })
        if ($match.Count -ne 1) { $problems += "$($match.Count) row(s) like [$($expected[0])] $($expected[2]) / $($expected[3])" }
    }
    if ($rows.Count -ne $expectedRows.Count) {
        $problems += "expected $($expectedRows.Count) row(s), got $($rows.Count)"
        $problems += ($rows | ForEach-Object { "got: [$($_.Source)] $($_.Description) | $($_.Details)" })
    }
    $antivirusRows = @($rows | Where-Object { $_.Source -like "*_EventLog.evtx" -and $_.Artifact -ne "AntiVirus" })
    if ($antivirusRows.Count -gt 0) { $problems += "antivirus log rows without Artifact AntiVirus: $($antivirusRows.Count)" }
    if ($script:mockEvtx.MaxTerms -gt 20) { $problems += "a query had $($script:mockEvtx.MaxTerms) EventID / provider terms (at most 20)" }
    $warnings = @(Get-NewLogLines $logBefore | Where-Object { $_ -match "WARNING:" })
    if ($warnings.Count -gt 0) { $problems += "warnings: $($warnings -join '; ')" }
    Write-TestResult -Name "Parse-EventLogs reads the handled IDs of each Phase 2 channel ($($script:mockEvtx.Queries) queries)" -Passed ($problems.Count -eq 0) -Message ($problems -join "; ")
}
finally {
    Remove-Item -LiteralPath $dispatchDir -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $logFile -Force -ErrorAction SilentlyContinue

# =============================================================
# Shared by parts 2 and 3: export logs and run the builder
# =============================================================
# Exports the given channels (only events of the last $Minutes minutes) into
# <collection>\EventLogs; returns the channels that could be exported
function Export-TestChannels {
    param([string]$Collection, [string[]]$Channels, [int]$Minutes)
    $exported = @()
    New-Item -ItemType Directory -Path (Join-Path $Collection "EventLogs") -Force | Out-Null
    foreach ($channel in $Channels) {
        $file = Join-Path $Collection ("EventLogs\" + ($channel -replace '/', '%4') + ".evtx")
        $null = & wevtutil.exe epl $channel $file "/q:*[System[TimeCreated[timediff(@SystemTime) <= $([long]$Minutes * 60000)]]]" 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $file)) { $exported += $channel }
        else { Write-Host "  (channel '$channel' could not be exported here: not checked)" }
    }
    $tzId = [System.TimeZoneInfo]::Local.Id
    $info = [ordered]@{ SchemaVersion = 1; ComputerName = $env:COMPUTERNAME; Mode = "Live"; CollectionStartUtc = (Get-Date).ToUniversalTime().ToString("o")
        CollectorTimeZoneId = $tzId; CollectorCulture = "en-US"; TargetTimeZoneId = $tzId }
    $info | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Collection "collection_info.json") -Encoding ASCII
    return $exported
}

# Runs the builder (-Sources EventLogs) on a collection with the same
# PowerShell edition as this script; returns @{ Rows; Output } or $null
function Invoke-TestBuilder {
    param([string]$Collection, [string]$WorkDir, [string]$Label)
    $powershellExe = (Get-Process -Id $PID).Path
    $timelineCsv = Join-Path $WorkDir "timeline.csv"
    $reportsDir = Join-Path (Split-Path $builder -Parent) "reports"
    $reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    try {
        Write-Host "Running the builder ($powershellExe) on $Collection ..."
        $output = @(& $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder -InputPath $Collection -Sources "EventLogs" `
                -OutputFile $timelineCsv -NoExcel -Viewer None 2>&1 | ForEach-Object { "$_" })
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
            $output | ForEach-Object { Write-Host "  | $_" }
            Write-TestResult -Name "${Label}: builder run" -Passed $false -Message "the builder exited with code $LASTEXITCODE or wrote no timeline"
            return $null
        }
        return @{ Rows = @(Import-Csv -LiteralPath $timelineCsv); Output = $output }
    }
    finally {
        # The builder also writes a report folder (log) under reports\; remove the one from this run
        Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $reportsBefore -notcontains $_.FullName } |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# Checks for one expected row: @(name, source file, EventType, Description
# pattern, Details pattern)
function Test-ExpectedRows {
    param([object[]]$Rows, [object[]]$Checks, [string]$Label)
    foreach ($check in $Checks) {
        $match = @($Rows | Where-Object { $_.Source -eq $check[1] -and $_.EventType -eq $check[2] -and $_.Description -like $check[3] -and $_.Details -like $check[4] })
        $near = @($Rows | Where-Object { $_.Source -eq $check[1] } | Select-Object -Last 5 | ForEach-Object { "$($_.Description) | $($_.Details)" })
        Write-TestResult -Name "${Label}: $($check[0])" -Passed ($match.Count -gt 0) -Message "no row like '$($check[3])' / '$($check[4])'. Last rows of $($check[1]): $($near -join ' || ')"
    }
}

$phase2Channels = @("Windows PowerShell", "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-TerminalServices-RDPClient/Operational",
    "Microsoft-Windows-NTLM/Operational", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-Shell-Core/Operational", "OAlerts")

# =============================================================
# Part 2: real records (no admin)
# =============================================================
Write-Host ""
Write-Host "Part 2: real records of this machine"
$tag = "TLT" + (Get-Random -Minimum 100000 -Maximum 999999)
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-evtx2-test-" + [guid]::NewGuid().ToString("N"))
$collection = Join-Path $workDir "collection"
try {
    # Windows PowerShell 5.1 started with an encoded command: events 400 / 403
    $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $script = "Write-Output '$tag'"
    $encodedTag = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
    $null = & $windowsPowerShell -NoProfile -NonInteractive -EncodedCommand $encodedTag 2>&1
    Start-Sleep -Seconds 2
    $exported = @(Export-TestChannels -Collection $collection -Channels $phase2Channels -Minutes 43200)
    if ($exported -notcontains "Windows PowerShell") {
        Write-Host "SKIPPED: Part 2 (the Windows PowerShell log could not be exported)" -ForegroundColor Yellow
    }
    else {
        $result = Invoke-TestBuilder -Collection $collection -WorkDir $workDir -Label "Part 2"
        if ($result) {
            $hostId = ""
            $started = @($result.Rows | Where-Object { $_.Source -eq "Windows PowerShell.evtx" -and $_.Details -like "*EncodedCommand=$script*" })
            if ($started.Count -gt 0 -and $started[0].Details -match 'HostId=([0-9a-f-]+)') { $hostId = $Matches[1] }
            Test-ExpectedRows -Rows $result.Rows -Label "Part 2" -Checks @(
                , @("Windows PowerShell 400 with the decoded -EncodedCommand", "Windows PowerShell.evtx", "Execution", "PowerShell engine started: *powershell.exe*-EncodedCommand $encodedTag*",
                    "EventID=400 | EngineVersion=5.1.* | HostName=ConsoleHost | *HostApplication=*-EncodedCommand $encodedTag | EncodedCommand=$script | HostId=*")
            )
            if ($hostId) {
                Test-ExpectedRows -Rows $result.Rows -Label "Part 2" -Checks @(
                    , @("Windows PowerShell 403 of the same session", "Windows PowerShell.evtx", "Execution", "PowerShell engine stopped: *-EncodedCommand $encodedTag*", "EventID=403 | *HostId=$hostId*")
                )
            }
            # Every exported log parses without warnings
            $problems = @($result.Output | Where-Object { $_ -match "WARNING: .*(Error reading|Failed to parse)" })
            Write-TestResult -Name "Part 2: the exported logs ($($exported -join ', ')) parse without errors" -Passed ($problems.Count -eq 0) -Message ($problems -join " || ")
            $counts = @($result.Rows | Group-Object Source | Sort-Object Name | ForEach-Object { "$($_.Name) $($_.Count)" })
            Write-Host "  Rows per log: $($counts -join ', ')"
        }
    }
}
catch {
    Write-TestResult -Name "Part 2" -Passed $false -Message $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

# =============================================================
# Part 3: system test (changes this machine)
# =============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $env:GITHUB_ACTIONS -and -not $AllowSystemChanges) {
    Write-Host ""
    Write-Host "SKIPPED: Part 3 (system test). It changes this machine (a disabled firewall rule and the Public profile's log size,"
    Write-Host "         undone afterwards; in GitHub Actions also a WMI subscription, NTLM auditing and an RDP client attempt)"
    Write-Host "         and runs only in GitHub Actions or with -AllowSystemChanges (as Administrator)."
}
elseif (-not $isAdmin) {
    Write-TestResult -Name "Part 3 system test" -Passed $false -Message "needs Administrator rights (run elevated, or let GitHub Actions run it)"
}
else {
    Write-Host ""
    Write-Host "Part 3: real events on this machine"
    $onCi = [bool]$env:GITHUB_ACTIONS
    $ruleName = "TimelineTest-$tag"
    $wmiFilterName = "TimelineTestFilter$tag"
    $wmiConsumerName = "TimelineTestConsumer$tag"
    $msvKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $ntlmValues = @("RestrictSendingNTLMTraffic", "AuditReceivingNTLMTraffic")
    $ntlmBackup = @{}
    $logSizeBefore = $null
    $mstsc = $null
    $wmiCreated = $false
    $generated = $false
    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-evtx2-system-" + [guid]::NewGuid().ToString("N"))
    $collection = Join-Path $workDir "collection"
    try {
        # Firewall: a disabled rule added (2097 / 2004), changed (2099 / 2005),
        # deleted (2052 / 2006); the Public profile's log size changed and back
        $null = New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 49123 `
            -Program "$env:SystemRoot\System32\cmd.exe" -Enabled False -ErrorAction Stop
        Set-NetFirewallRule -Name $ruleName -LocalPort 49124 -ErrorAction Stop
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        $logSizeBefore = (Get-NetFirewallProfile -Name Public -ErrorAction Stop).LogMaxSizeKilobytes
        $newSize = if ($logSizeBefore -ge 32767) { $logSizeBefore - 1 } else { $logSizeBefore + 1 }
        Set-NetFirewallProfile -Name Public -LogMaxSizeKilobytes $newSize -ErrorAction Stop

        if ($onCi) {
            # A permanent WMI event subscription whose filter never fires
            # (5861); removed again below
            $filter = New-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -ErrorAction Stop -Property @{
                Name = $wmiFilterName; EventNamespace = "root\cimv2"; QueryLanguage = "WQL"
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Year = 1999"
            }
            $wmiCreated = $true
            $consumer = New-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -ErrorAction Stop -Property @{
                Name = $wmiConsumerName; CommandLineTemplate = "cmd.exe /c rem $tag"
            }
            $null = New-CimInstance -Namespace "root/subscription" -ClassName "__FilterToConsumerBinding" -ErrorAction Stop -Property @{ Filter = [ref]$filter; Consumer = [ref]$consumer }

            # NTLM auditing on (outgoing: audit all; incoming: all accounts),
            # then an SMB connection to the loopback address, which uses NTLM
            foreach ($name in $ntlmValues) { $ntlmBackup[$name] = (Get-ItemProperty -Path $msvKey -Name $name -ErrorAction SilentlyContinue).$name }
            Set-ItemProperty -Path $msvKey -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path $msvKey -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord -ErrorAction Stop
            Start-Sleep -Seconds 2
            $null = & net.exe use "\\127.0.0.1\IPC$" 2>&1
            $null = & net.exe use "\\127.0.0.1\IPC$" /delete /y 2>&1

            # Remote Desktop client to an unused loopback address (1024, 1026)
            try {
                $mstsc = Start-Process -FilePath "mstsc.exe" -ArgumentList "/v:127.0.0.2" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 20
            }
            catch { Write-Host "  (the Remote Desktop client could not be started: $($_.Exception.Message))" }
        }
        else {
            Write-Host "  (WMI subscription, NTLM auditing and RDP client run only in GitHub Actions: not checked here)"
        }
        Start-Sleep -Seconds 2
        $generated = $true
    }
    catch {
        Write-TestResult -Name "Part 3: generate events" -Passed $false -Message $_.Exception.Message
    }
    finally {
        # Undo every change that is still in place, whatever happened above
        if ($mstsc) { Stop-Process -Id $mstsc.Id -Force -ErrorAction SilentlyContinue }
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        if ($null -ne $logSizeBefore) { Set-NetFirewallProfile -Name Public -LogMaxSizeKilobytes $logSizeBefore -ErrorAction SilentlyContinue }
        if ($wmiCreated) {
            Get-CimInstance -Namespace "root/subscription" -ClassName "__FilterToConsumerBinding" -ErrorAction SilentlyContinue |
                Where-Object { "$($_.Filter)" -like "*$wmiFilterName*" } | Remove-CimInstance -ErrorAction SilentlyContinue
            Get-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -Filter "Name='$wmiConsumerName'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
            Get-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -Filter "Name='$wmiFilterName'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
        }
        foreach ($name in $ntlmBackup.Keys) {
            if ($null -eq $ntlmBackup[$name]) { Remove-ItemProperty -Path $msvKey -Name $name -ErrorAction SilentlyContinue }
            else { Set-ItemProperty -Path $msvKey -Name $name -Value $ntlmBackup[$name] -Type DWord -ErrorAction SilentlyContinue }
        }
    }

    if ($generated) {
        try {
            $exported = @(Export-TestChannels -Collection $collection -Channels (@("Security") + $phase2Channels) -Minutes 15)
            $result = Invoke-TestBuilder -Collection $collection -WorkDir $workDir -Label "Part 3"
            if ($result) {
                $rows = $result.Rows
                $fw = "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
                $checks = @(
                    @("firewall rule added", $fw, "PersistenceChange", "Firewall rule added: $ruleName (Inbound, Allow)", "EventID=* | RuleName=$ruleName | *Direction=Inbound | Action=Allow | Protocol=TCP | LocalPorts=49123 | *ModifyingUser=S-1-5-*"),
                    @("firewall rule modified", $fw, "PersistenceChange", "Firewall rule modified: $ruleName (Inbound, Allow)", "*LocalPorts=49124*"),
                    @("firewall rule deleted", $fw, "PersistenceChange", "Firewall rule deleted: $ruleName", "EventID=* | RuleName=$ruleName | *"),
                    @("firewall profile setting changed", $fw, "SecurityAlert", "Firewall setting changed (Public profile): Log max file size = *", "*Setting=Log max file size | SettingType=8 | *")
                )
                if ($exported -contains "Security") {
                    $checks += , @("Security 4624 carries the authentication package", "Security.evtx", "Logon", "Successful logon (*", "*AuthenticationPackageName=*")
                }
                if ($onCi) {
                    $checks += , @("WMI permanent subscription (5861)", "Microsoft-Windows-WMI-Activity%4Operational.evtx", "PersistenceChange", "WMI permanent event subscription: filter `"$wmiFilterName`" -> *$wmiConsumerName*",
                        "*Filter=$wmiFilterName | Query=SELECT * FROM __InstanceModificationEvent * | ConsumerType=CommandLineEventConsumer | Consumer=$wmiConsumerName | CommandLineTemplate=cmd.exe /c rem $tag*")
                }
                Test-ExpectedRows -Rows $rows -Checks $checks -Label "Part 3"

                # Generated only if this runner records them: each event in the
                # export must have its row
                $optional = @(
                    @("NTLM outgoing (8001)", "Microsoft-Windows-NTLM%4Operational.evtx", 8001, "NetworkConnection", "Outgoing NTLM authentication to *"),
                    @("NTLM incoming (8002)", "Microsoft-Windows-NTLM%4Operational.evtx", 8002, "Logon", "Incoming NTLM authentication (*"),
                    @("RDP client connecting (1024)", "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx", 1024, "NetworkConnection", "Outbound RDP connection to 127.0.0.2"),
                    @("RDP client disconnected (1026)", "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx", 1026, "NetworkConnection", "Outbound RDP connection to 127.0.0.2: disconnected (reason *")
                )
                foreach ($o in $optional) {
                    if (-not $onCi) { continue }
                    $file = Join-Path $collection "EventLogs\$($o[1])"
                    $events = @()
                    if (Test-Path -LiteralPath $file) { $events = @(Get-WinEvent -Path $file -FilterXPath "*[System[EventID=$($o[2])]]" -ErrorAction SilentlyContinue) }
                    if ($events.Count -eq 0) {
                        Write-Host "SKIPPED: Part 3: $($o[0]) -- this runner wrote no such event" -ForegroundColor Yellow
                        continue
                    }
                    $match = @($rows | Where-Object { $_.Source -eq $o[1] -and $_.EventType -eq $o[3] -and $_.Description -like $o[4] -and $_.Details -like "EventID=$($o[2]) | *" })
                    Write-TestResult -Name "Part 3: $($o[0])" -Passed ($match.Count -gt 0) -Message "$($events.Count) event(s) in the log, no row like '$($o[4])'"
                }
                $ntlmLogons = @($rows | Where-Object { $_.Source -eq "Security.evtx" -and $_.Description -like "Successful logon*" -and $_.Details -like "*AuthenticationPackageName=NTLM*" })
                if ($ntlmLogons.Count -gt 0) {
                    $withVersion = @($ntlmLogons | Where-Object { $_.Details -like "*LmPackageName=NTLM V*" -and $_.Details -like "*KeyLength=*" })
                    Write-TestResult -Name "Part 3: NTLM logons (4624) carry LmPackageName and KeyLength" -Passed ($withVersion.Count -gt 0) -Message "$($ntlmLogons.Count) NTLM logon row(s), none with LmPackageName=NTLM V*"
                }
                $problems = @($result.Output | Where-Object { $_ -match "WARNING: .*(Error reading|Failed to parse)" })
                Write-TestResult -Name "Part 3: the exported logs parse without errors" -Passed ($problems.Count -eq 0) -Message ($problems -join " || ")
            }
        }
        catch {
            Write-TestResult -Name "Part 3" -Passed $false -Message $_.Exception.Message
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "FAILED: $($script:failures) check(s)" -ForegroundColor Red
    exit 1
}
Write-Host "All Phase 2 event log parser checks passed" -ForegroundColor Green
exit 0
