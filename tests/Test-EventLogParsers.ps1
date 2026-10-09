# =============================================================
# Event log parser tests (Security, System, Defender, Application)
#
# Part 1 -- unit checks (no admin, always run): loads the builder's
#   functions without running it and feeds the event log handlers
#   synthetic event records (our own XML), checking every row they add.
#   It also runs Parse-EventLogs itself on synthetic records, with
#   Get-WinEvent replaced, to check which IDs and providers each channel
#   reads and that every query stays within the event log's XPath limit.
# Part 2 -- system test (needs Administrator; runs only in GitHub Actions
#   or with -AllowSystemChanges): generates real events on this machine
#   (audit policy, a temporary local user and group membership, a
#   temporary scheduled task and service, a temporary classic event log
#   that is cleared), exports Security, System and Application with
#   wevtutil into a fixture collection, runs the builder (-Sources
#   EventLogs) and checks the expected rows by pattern. The audit policy,
#   user, task, service and classic log are removed again in a finally
#   block, but the event records this produces stay in the machine's
#   Security and System logs (they cannot be removed without clearing the
#   logs). In GitHub Actions only, the Security log is cleared first (event
#   1102) and synthetic Application events are written under the real
#   MsiInstaller / Application Error / ESENT / SecurityCenter sources (and a
#   third-party antivirus source): on a workstation they would stay in its
#   Application log and look like real findings in its later timelines.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-EventLogParsers.ps1
#   ... -AllowSystemChanges   also run part 2 on this machine (admin)
#   ... -BuilderPath <file>   test another copy of timeline-builder.ps1
# Exit code 0 = pass, 1 = fail.
# =============================================================
param(
    [switch]$AllowSystemChanges,
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

# Continue: native tools (wevtutil, auditpol) must not turn stderr output into
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
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-EventLogParsers.ps1::$Name -- $Message" }
}

# =============================================================
# Part 1: unit checks
# =============================================================
Write-Host "Part 1: event log handlers on synthetic records ($builder)"

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
$tableNames = @("xmlInvalidPattern", "xmlInvalidRegex", "AuditCategoryNames", "AuditSubcategoryNames", "AuditChangeNames",
    "ServiceTypeNames", "ServiceStartTypeNames", "AsrRuleNames", "ThirdPartyAvProviders", "TimelineUserAliases")
# Any assignment that is not inside a function: most of the builder runs
# inside its main try block, so the tables are not top-level statements
$tables = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) | Where-Object {
    $parent = $_.Parent
    while ($parent -and $parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $parent = $parent.Parent }
    $null -eq $parent -and $_.Left.Extent.Text -match '^\$script:(\w+)$' -and $tableNames -contains $Matches[1]
} | Sort-Object { $_.Extent.StartOffset }
foreach ($table in $tables) { . ([ScriptBlock]::Create($table.Extent.Text)) }
foreach ($name in $tableNames) {
    if ($null -eq (Get-Variable -Name $name -Scope Script -ErrorAction SilentlyContinue)) {
        Write-TestResult -Name "builder table `$script:$name" -Passed $false -Message "not found in $builder"
    }
}

$script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$logFile = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx-unit-" + [guid]::NewGuid().ToString("N") + ".log")
$script:nextRecordId = 0
$eventNs = "http://schemas.microsoft.com/win/2004/08/events/event"

# XML-escaped <Data Name="..."> elements (or unnamed <Data> for a plain list)
function New-EventDataXml {
    param($Data, [string]$Binary = "")
    $parts = @()
    if ($Data -is [System.Collections.IDictionary]) {
        foreach ($key in $Data.Keys) { $parts += "<Data Name='$key'>$([System.Security.SecurityElement]::Escape([string]$Data[$key]))</Data>" }
    }
    else {
        foreach ($value in $Data) { $parts += "<Data>$([System.Security.SecurityElement]::Escape([string]$value))</Data>" }
    }
    if ($Binary) { $parts += "<Binary>$Binary</Binary>" }
    return "<EventData>" + ($parts -join "") + "</EventData>"
}

# <UserData><Wrapper xmlns=...><Name>value</Name>...</Wrapper></UserData>
function New-UserDataXml {
    param([string]$Wrapper, [System.Collections.IDictionary]$Data)
    $parts = foreach ($key in $Data.Keys) { "<$key>$([System.Security.SecurityElement]::Escape([string]$Data[$key]))</$key>" }
    return "<UserData><$Wrapper xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>" + ($parts -join "") + "</$Wrapper></UserData>"
}

# A stand-in for an EventLogRecord: the properties the handlers read and a
# ToXml() method. $Time is UTC "yyyy-MM-dd HH:mm:ss".
function New-TestRecord {
    param([string]$Provider, [int]$Id, [string]$Time, [string]$Body = "", [string]$UserSid = "", [int]$Level = 4,
        [string]$Message = "", [string[]]$Values = @())
    $script:nextRecordId++
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $timeUtc = [datetime]::ParseExact($Time, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    $xml = "<Event xmlns='$eventNs'><System><Provider Name='$Provider'/><EventID>$Id</EventID><Level>$Level</Level>" +
        "<TimeCreated SystemTime='$($timeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ"))'/><EventRecordID>$($script:nextRecordId)</EventRecordID></System>$Body</Event>"
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

$sec = "Security.evtx"
$secPath = "X:\EventLogs\Security.evtx"
$auditing = "Microsoft-Windows-Security-Auditing"
$alice = [ordered]@{ SubjectUserSid = "S-1-5-21-1111-2222-3333-1001"; SubjectUserName = "alice"; SubjectDomainName = "TESTHOST"; SubjectLogonId = "0x5a3f1" }
function Join-Subject {
    param([System.Collections.IDictionary]$Extra)
    $all = [ordered]@{}
    foreach ($key in $alice.Keys) { $all[$key] = $alice[$key] }
    foreach ($key in $Extra.Keys) { $all[$key] = $Extra[$key] }
    return $all
}

# --- Security.evtx ---
Test-Case -Name "Security 1102 audit log cleared (UserData)" -Action {
    $body = New-UserDataXml -Wrapper "LogFileCleared" -Data $alice
    Add-SecurityEventEntry -Record (New-TestRecord -Provider "Microsoft-Windows-Eventlog" -Id 1102 -Time "2026-01-02 10:00:00" -Body $body) -FileName $sec -FilePath $secPath
} -Expected @(
    @{ Timestamp = "2026-01-02 10:00:00.000"; Source = $sec; EventType = "SecurityAlert"; Description = "Security audit log cleared"; User = "TESTHOST\alice"
        Details = "EventID=1102 | ClearedBy=TESTHOST\alice | SubjectSID=S-1-5-21-1111-2222-3333-1001 | LogonID=0x5a3f1"; Artifact = "EventLogs"; RawPath = $secPath }
)

Test-Case -Name "Security 4719 audit policy changed (%% references resolved)" -Action {
    $system = [ordered]@{ SubjectUserSid = "S-1-5-18"; SubjectUserName = "TESTHOST$"; SubjectDomainName = "WORKGROUP"; SubjectLogonId = "0x3e7" }
    $one = [ordered]@{ CategoryId = "%%8274"; SubcategoryId = "%%12807"; SubcategoryGuid = "{0CCE9223-69AE-11D9-BED3-505054503030}"; AuditPolicyChanges = "%%8448, %%8450" }
    $two = [ordered]@{ CategoryId = "%%8278"; SubcategoryId = "%%13824"; SubcategoryGuid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; AuditPolicyChanges = "%%8449, %%8451" }
    $three = [ordered]@{ CategoryId = "%%8280"; SubcategoryId = "%%14399"; SubcategoryGuid = ""; AuditPolicyChanges = "%%8449" }
    foreach ($data in @($one, $two, $three)) {
        $all = [ordered]@{}
        foreach ($key in $system.Keys) { $all[$key] = $system[$key] }
        foreach ($key in $data.Keys) { $all[$key] = $data[$key] }
        Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id 4719 -Time "2026-01-02 10:01:00" -Body (New-EventDataXml -Data $all)) -FileName $sec -FilePath $secPath
    }
} -Expected @(
    @{ EventType = "SecurityAlert"; Description = "System audit policy changed: Object Access\Handle Manipulation (Success removed, Failure removed)"; User = "WORKGROUP\TESTHOST$"
        Details = "EventID=4719 | Category=Object Access | Subcategory=Handle Manipulation | SubcategoryGuid={0CCE9223-69AE-11D9-BED3-505054503030} | Changes=Success removed, Failure removed" },
    @{ Description = "System audit policy changed: Account Management\User Account Management (Success added, Failure added)" },
    @{ Description = "System audit policy changed: Account Logon\%%14399 (Success added)" }
)

Test-Case -Name "Security 4697 service installed" -Action {
    $data = Join-Subject ([ordered]@{ ServiceName = "TestSvc"; ServiceFileName = "C:\Temp\svc.exe -k run"; ServiceType = "0x10"; ServiceStartType = "3"; ServiceAccount = "LocalSystem"; ClientProcessStartKey = "1234"; ClientProcessId = "4242"; ParentProcessId = "1000" })
    Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id 4697 -Time "2026-01-02 10:02:00" -Body (New-EventDataXml -Data $data)) -FileName $sec -FilePath $secPath
} -Expected @(
    @{ EventType = "PersistenceChange"; Description = "New service installed: TestSvc"; User = "TESTHOST\alice"
        Details = "EventID=4697 | ServiceName=TestSvc | ImagePath=C:\Temp\svc.exe -k run | ServiceType=0x10 (own process) | StartType=3 (demand start) | Account=LocalSystem | ClientProcessId=4242" }
)

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>TESTHOST\alice</Author><URI>\TestTask</URI></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Actions Context="Author">
    <Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/c echo timeline-test &gt; C:\Temp\out.txt</Arguments></Exec>
  </Actions>
</Task>
"@
$comTaskXml = "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Principals><Principal><GroupId>S-1-5-32-545</GroupId></Principal></Principals><Actions><ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler></Actions></Task>"
# Two Exec actions, the first without arguments: each keeps its own arguments
$twoActionXml = "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals><Actions>" +
    "<Exec><Command>C:\Windows\System32\a.exe</Command></Exec><Exec><Command>C:\Users\Public\b.exe</Command><Arguments>-x run</Arguments></Exec>" +
    "<ComHandler><ClassId>{22222222-2222-3333-4444-555555555555}</ClassId></ComHandler></Actions></Task>"
Test-Case -Name "Security 4698-4702 scheduled task events (action from TaskContent)" -Action {
    $events = @(
        @(4698, "TaskContent", $taskXml),
        @(4702, "TaskContentNew", $comTaskXml),
        @(4701, "TaskContent", "<not xml"),
        @(4700, "TaskContent", ""),
        @(4699, "TaskContent", $taskXml),
        @(4698, "TaskContent", $twoActionXml)
    )
    $minute = 3
    foreach ($e in $events) {
        $data = Join-Subject ([ordered]@{ TaskName = "\TestTask" })
        $data[$e[1]] = $e[2]
        Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id $e[0] -Time "2026-01-02 10:0$($minute):00" -Body (New-EventDataXml -Data $data)) -FileName $sec -FilePath $secPath
        $minute++
    }
} -Expected @(
    @{ EventType = "ScheduledTaskChange"; Description = "Scheduled task registered: \TestTask"; User = "TESTHOST\alice"
        Details = "EventID=4698 | TaskName=\TestTask | Command=C:\Windows\System32\cmd.exe | Arguments=/c echo timeline-test > C:\Temp\out.txt | RunAs=S-1-5-18" },
    @{ EventType = "ScheduledTaskChange"; Description = "Scheduled task updated: \TestTask"; Details = "EventID=4702 | TaskName=\TestTask | Actions=ComHandler {11111111-2222-3333-4444-555555555555} | RunAs=S-1-5-32-545" },
    @{ Description = "Scheduled task disabled: \TestTask"; Details = "EventID=4701 | TaskName=\TestTask" },
    @{ Description = "Scheduled task enabled: \TestTask"; Details = "EventID=4700 | TaskName=\TestTask" },
    @{ Description = "Scheduled task deleted: \TestTask"; Details = "EventID=4699 | TaskName=\TestTask | Command=C:\Windows\System32\cmd.exe | Arguments=/c echo timeline-test > C:\Temp\out.txt | RunAs=S-1-5-18" },
    @{ Description = "Scheduled task registered: \TestTask"
        Details = "EventID=4698 | TaskName=\TestTask | Actions=C:\Windows\System32\a.exe; C:\Users\Public\b.exe -x run; ComHandler {22222222-2222-3333-4444-555555555555} | RunAs=S-1-5-18" }
)

Test-Case -Name "Security 4732/4728/4756 member added to a group (member named from its SID, group SID kept)" -Action {
    # bob's SID -> name: from a logon first, then from his creation (4720),
    # which wins; alice's from the subject of the logon
    $logon = [ordered]@{ SubjectUserSid = "S-1-5-18"; SubjectUserName = "TESTHOST$"; SubjectDomainName = "WORKGROUP"; SubjectLogonId = "0x3e7"
        TargetUserSid = "S-1-5-21-1111-2222-3333-1002"; TargetUserName = "bob-logon"; TargetDomainName = "TESTHOST"; TargetLogonId = "0x99"; LogonType = "2" }
    $created = Join-Subject ([ordered]@{ TargetUserName = "bob"; TargetDomainName = "TESTHOST"; TargetSid = "S-1-5-21-1111-2222-3333-1002" })
    $names = Get-SecuritySidNames -Records @(
        (New-TestRecord -Provider $auditing -Id 4624 -Time "2026-01-02 10:09:00" -Body (New-EventDataXml -Data $logon)),
        (New-TestRecord -Provider $auditing -Id 4720 -Time "2026-01-02 10:09:30" -Body (New-EventDataXml -Data $created)),
        (New-TestRecord -Provider $auditing -Id 4634 -Time "2026-01-02 10:09:40" -Body (New-EventDataXml -Data ([ordered]@{ TargetUserSid = "S-1-5-21-1111-2222-3333-1009"; TargetUserName = "eve"; TargetDomainName = "TESTHOST" })))
    )
    $nameText = (@($names.Keys | Sort-Object | ForEach-Object { "$_=$($names[$_].Name)/$($names[$_].EventId)" })) -join ", "
    if ($nameText -cne "S-1-5-18=WORKGROUP\TESTHOST$/4624, S-1-5-21-1111-2222-3333-1001=TESTHOST\alice/4720, S-1-5-21-1111-2222-3333-1002=TESTHOST\bob/4720") {
        throw "Get-SecuritySidNames gave: $nameText"
    }
    $groups = @(
        @(4732, "-", "Administrators", "Builtin", "S-1-5-32-544", "S-1-5-21-1111-2222-3333-1002"),
        @(4732, "-", "Remote Desktop Users", "Builtin", "S-1-5-32-555", "S-1-5-21-1111-2222-3333-1009"),
        @(4728, "CN=Bob,CN=Users,DC=test,DC=local", "Domain Admins", "TEST", "S-1-5-21-9-9-9-512", "S-1-5-21-1111-2222-3333-1002"),
        @(4756, "CN=Bob,CN=Users,DC=test,DC=local", "Enterprise Admins", "TEST", "S-1-5-21-9-9-9-519", "S-1-5-21-1111-2222-3333-1002")
    )
    foreach ($g in $groups) {
        $data = [ordered]@{ MemberName = $g[1]; MemberSid = $g[5]; TargetUserName = $g[2]; TargetDomainName = $g[3]; TargetSid = $g[4] }
        foreach ($key in $alice.Keys) { $data[$key] = $alice[$key] }
        $data["PrivilegeList"] = "-"
        Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id $g[0] -Time "2026-01-02 10:10:00" -Body (New-EventDataXml -Data $data)) -FileName $sec -FilePath $secPath -SidNames $names
    }
} -Expected @(
    @{ EventType = "AccountChange"; Description = "Member added to security-enabled local group: Administrators (member TESTHOST\bob)"; User = "TESTHOST\alice"
        Details = "EventID=4732 | Group=Builtin\Administrators | GroupSID=S-1-5-32-544 | Member=TESTHOST\bob | MemberSID=S-1-5-21-1111-2222-3333-1002 | MemberNameFrom=event 4720" },
    @{ Description = "Member added to security-enabled local group: Remote Desktop Users (member S-1-5-21-1111-2222-3333-1009)"
        Details = "EventID=4732 | Group=Builtin\Remote Desktop Users | GroupSID=S-1-5-32-555 | MemberSID=S-1-5-21-1111-2222-3333-1009" },
    @{ EventType = "AccountChange"; Description = "Member added to security-enabled global group: Domain Admins (member CN=Bob,CN=Users,DC=test,DC=local)"
        Details = "EventID=4728 | Group=TEST\Domain Admins | GroupSID=S-1-5-21-9-9-9-512 | Member=CN=Bob,CN=Users,DC=test,DC=local | MemberSID=S-1-5-21-1111-2222-3333-1002" },
    @{ Description = "Member added to security-enabled universal group: Enterprise Admins (member CN=Bob,CN=Users,DC=test,DC=local)" }
)

Test-Case -Name "Security 4724 password reset and 4740 lockout" -Action {
    $reset = [ordered]@{ TargetUserName = "bob"; TargetDomainName = "TESTHOST"; TargetSid = "S-1-5-21-1111-2222-3333-1002" }
    foreach ($key in $alice.Keys) { $reset[$key] = $alice[$key] }
    Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id 4724 -Time "2026-01-02 10:11:00" -Body (New-EventDataXml -Data $reset)) -FileName $sec -FilePath $secPath
    $lockout = [ordered]@{ TargetUserName = "bob"; TargetDomainName = "WKS-07"; TargetSid = "S-1-5-21-1111-2222-3333-1002"; SubjectUserSid = "S-1-5-18"; SubjectUserName = "TESTHOST$"; SubjectDomainName = "WORKGROUP"; SubjectLogonId = "0x3e7" }
    Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id 4740 -Time "2026-01-02 10:12:00" -Body (New-EventDataXml -Data $lockout)) -FileName $sec -FilePath $secPath
} -Expected @(
    @{ EventType = "AccountChange"; Description = "Password reset attempted for account: TESTHOST\bob"; User = "TESTHOST\alice"
        Details = "EventID=4724 | Account=TESTHOST\bob | AccountSID=S-1-5-21-1111-2222-3333-1002" },
    @{ EventType = "AccountChange"; Description = "User account locked out: bob"; User = "bob"
        Details = "EventID=4740 | Account=bob | AccountSID=S-1-5-21-1111-2222-3333-1002 | CallerComputer=WKS-07 | ReportedBy=WORKGROUP\TESTHOST$" }
)

Test-Case -Name "Security 4778/4779 session reconnected / disconnected" -Action {
    $session = [ordered]@{ AccountName = "bob"; AccountDomain = "TESTHOST"; LogonID = "0x1234"; SessionName = "RDP-Tcp#3"; ClientName = "LAPTOP-9"; ClientAddress = "203.0.113.7" }
    Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id 4778 -Time "2026-01-02 10:13:00" -Body (New-EventDataXml -Data $session)) -FileName $sec -FilePath $secPath
    $session["ClientName"] = ""
    Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id 4779 -Time "2026-01-02 10:14:00" -Body (New-EventDataXml -Data $session)) -FileName $sec -FilePath $secPath
} -Expected @(
    @{ EventType = "Logon"; Description = "Session reconnected to window station (client LAPTOP-9, 203.0.113.7)"; User = "TESTHOST\bob"
        Details = "EventID=4778 | Account=TESTHOST\bob | ClientName=LAPTOP-9 | ClientAddress=203.0.113.7 | SessionName=RDP-Tcp#3 | LogonID=0x1234" },
    @{ EventType = "Logon"; Description = "Session disconnected from window station (client 203.0.113.7)" }
)

# --- System.evtx ---
$sys = "System.evtx"
Test-Case -Name "System 104 log cleared, 6005/6006 event log service (other providers ignored)" -Action {
    $cleared = New-UserDataXml -Wrapper "LogFileCleared" -Data ([ordered]@{ SubjectUserName = "alice"; SubjectDomainName = "TESTHOST"; Channel = "Microsoft-Windows-PowerShell/Operational"; BackupPath = "" })
    Add-SystemEventEntry -Record (New-TestRecord -Provider "Microsoft-Windows-Eventlog" -Id 104 -Time "2026-01-02 11:00:00" -Body $cleared) -FileName $sys -FilePath "X:\System.evtx"
    Add-SystemEventEntry -Record (New-TestRecord -Provider "Some-Other-Provider" -Id 104 -Time "2026-01-02 11:00:01" -Body (New-EventDataXml -Data @("x"))) -FileName $sys -FilePath "X:\System.evtx"
    Add-SystemEventEntry -Record (New-TestRecord -Provider "EventLog" -Id 6006 -Time "2026-01-02 11:01:00" -Body (New-EventDataXml -Data @() -Binary "0100000000000000")) -FileName $sys -FilePath "X:\System.evtx"
    Add-SystemEventEntry -Record (New-TestRecord -Provider "EventLog" -Id 6005 -Time "2026-01-02 11:02:00" -Body (New-EventDataXml -Data @() -Binary "EA07")) -FileName $sys -FilePath "X:\System.evtx"
} -Expected @(
    @{ EventType = "SecurityAlert"; Description = "Event log cleared: Microsoft-Windows-PowerShell/Operational"; User = "TESTHOST\alice"
        Details = "EventID=104 | Channel=Microsoft-Windows-PowerShell/Operational | ClearedBy=TESTHOST\alice" },
    @{ EventType = "ServiceChange"; Description = "Event log service stopped (clean shutdown)"; Details = "EventID=6006" },
    @{ EventType = "ServiceChange"; Description = "Event log service started (system startup)"; Details = "EventID=6005" }
)

# --- Defender Operational ---
$def = "Microsoft-Windows-Windows Defender%4Operational.evtx"
$defender = "Microsoft-Windows-Windows Defender"
Test-Case -Name "Defender 1013 history deleted / purged by retention, 1121/1122 ASR rule blocked / audited" -Action {
    $history = [ordered]@{ "Product Name" = "Microsoft Defender Antivirus"; "Product Version" = "4.18.1.1"; Timestamp = "2026-01-02T11:59:58Z"; Unused = ""; Unused2 = ""; Unused3 = ""; Unused4 = ""; Domain = "TESTHOST"; User = "alice"; SID = "S-1-5-21-1111-2222-3333-1001" }
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1013 -Time "2026-01-02 12:00:00" -Body (New-EventDataXml -Data $history)) -FileName $def -FilePath "X:\def.evtx"
    # The service's own daily purge: SYSTEM, cutoff 15 days before the event
    $history["Timestamp"] = "2025-12-18T12:00:00Z"
    $history["Domain"] = "NT AUTHORITY"
    $history["User"] = "SYSTEM"
    $history["SID"] = "S-1-5-18"
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1013 -Time "2026-01-02 12:00:00" -Body (New-EventDataXml -Data $history)) -FileName $def -FilePath "X:\def.evtx"
    # SYSTEM, but the history up to now removed: not the retention purge
    $history["Timestamp"] = "2026-01-02T11:59:00Z"
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1013 -Time "2026-01-02 12:00:00" -Body (New-EventDataXml -Data $history)) -FileName $def -FilePath "X:\def.evtx"
    $asr = [ordered]@{ "Product Name" = "Microsoft Defender Antivirus"; "Product Version" = "4.18.1.1"; Unused = ""; ID = "{D4F940AB-401B-4EFC-AADC-AD5F3C50688A}"; "Detection Time" = "2026-01-02T12:01:00.000Z"
        User = "TESTHOST\alice"; Path = "C:\Windows\System32\cmd.exe"; "Process Name" = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"; "Security intelligence Version" = "1.1"; "Engine Version" = "1.1"; RuleType = "0"
        "Target Commandline" = "cmd.exe /c echo test"; "Parent Commandline" = "WINWORD.EXE /n C:\Users\alice\Downloads\doc.docm"; "Involved File" = ""; "Inhertiance Flags" = "0" }
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1121 -Time "2026-01-02 12:01:00" -Body (New-EventDataXml -Data $asr)) -FileName $def -FilePath "X:\def.evtx"
    $asr["ID"] = "00000000-1111-2222-3333-444444444444"
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1122 -Time "2026-01-02 12:02:00" -Body (New-EventDataXml -Data $asr)) -FileName $def -FilePath "X:\def.evtx"
} -Expected @(
    @{ EventType = "SecurityAlert"; Description = "Defender malware detection history deleted by TESTHOST\alice"; User = "TESTHOST\alice"
        Details = "EventID=1013 | Trigger=User | DeletedBefore=2026-01-02T11:59:58Z | DeletedBy=TESTHOST\alice | SID=S-1-5-21-1111-2222-3333-1001" },
    @{ EventType = "SecurityAlert"; Description = "Defender malware detection history purged by retention (items before 2025-12-18T12:00:00Z)"; User = "NT AUTHORITY\SYSTEM"
        Details = "EventID=1013 | Trigger=Retention | DeletedBefore=2025-12-18T12:00:00Z | DeletedBy=NT AUTHORITY\SYSTEM | SID=S-1-5-18" },
    @{ Description = "Defender malware detection history deleted by NT AUTHORITY\SYSTEM"; Details = "EventID=1013 | Trigger=User | DeletedBefore=2026-01-02T11:59:00Z | DeletedBy=NT AUTHORITY\SYSTEM | SID=S-1-5-18" },
    @{ EventType = "SecurityAlert"; Description = "Defender attack surface reduction rule blocked: Block all Office applications from creating child processes"; User = "TESTHOST\alice"
        Details = "EventID=1121 | RuleID=D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Path=C:\Windows\System32\cmd.exe | Process=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE | TargetCommandline=cmd.exe /c echo test | ParentCommandline=WINWORD.EXE /n C:\Users\alice\Downloads\doc.docm" },
    @{ Description = "Defender attack surface reduction rule audited: 00000000-1111-2222-3333-444444444444" }
)

Test-Case -Name "Defender 1122 ASR audits folded per rule, path, process and UTC day" -Action {
    $lsassRule = "{9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2}"
    $audits = @(
        @("2026-01-02 13:00:00", "C:\Windows\System32\lsass.exe", "C:\Tools\scan.exe", "scan.exe /third"),
        @("2026-01-02 12:02:00", "C:\Windows\System32\lsass.exe", "C:\Tools\scan.exe", "scan.exe /first"),
        @("2026-01-02 12:03:00", "C:\Windows\System32\lsass.exe", "C:\Tools\other.exe", "other.exe"),
        @("2026-01-02 12:05:00", "C:\WINDOWS\system32\LSASS.EXE", "C:\Tools\scan.exe", "scan.exe /second"),
        @("2026-01-03 00:00:01", "C:\Windows\System32\lsass.exe", "C:\Tools\scan.exe", "scan.exe /next-day")
    )
    $items = foreach ($a in $audits) {
        $data = [ordered]@{ "Product Name" = "Microsoft Defender Antivirus"; ID = $lsassRule; User = "TESTHOST\alice"; Path = $a[1]; "Process Name" = $a[2]; "Target Commandline" = $a[3] }
        $record = New-TestRecord -Provider $defender -Id 1122 -Time $a[0] -Body (New-EventDataXml -Data $data)
        [PSCustomObject]@{ Record = $record; Fields = Get-EvtxEventFields $record }
    }
    Add-DefenderAsrAuditEntries -Items $items -FileName $def -FilePath "X:\def.evtx"
} -Expected @(
    @{ Timestamp = "2026-01-02 12:02:00.000"; EventType = "SecurityAlert"; Description = "Defender attack surface reduction rule audited: Block credential stealing from the Windows local security authority subsystem"
        Details = "EventID=1122 | RuleID=9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | Path=C:\Windows\System32\lsass.exe | Process=C:\Tools\scan.exe | TargetCommandline=scan.exe /first | Count=3 | LastSeen=2026-01-02 13:00:00" },
    @{ Timestamp = "2026-01-02 12:03:00.000"; Details = "EventID=1122 | RuleID=9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | Path=C:\Windows\System32\lsass.exe | Process=C:\Tools\other.exe | TargetCommandline=other.exe" },
    @{ Timestamp = "2026-01-03 00:00:01.000"; Details = "EventID=1122 | RuleID=9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | Path=C:\Windows\System32\lsass.exe | Process=C:\Tools\scan.exe | TargetCommandline=scan.exe /next-day" }
)

# --- Application.evtx ---
$app = "Application.evtx"
$productCode = "{12345678-1234-1234-1234-123456789ABC}"
$productHex = [System.BitConverter]::ToString([System.Text.Encoding]::ASCII.GetBytes($productCode)).Replace("-", "") + "30303030"
$crash = [ordered]@{ AppName = "badapp.exe"; AppVersion = "1.0.0.0"; AppTimeStamp = "5f000000"; ModuleName = "badmod.dll"; ModuleVersion = "2.0.0.0"; ModuleTimeStamp = "5f000001"
    ExceptionCode = "c0000005"; FaultingOffset = "0000000000001234"; ProcessId = "0x1a2b"; ProcessCreationTime = "0x1d70000"; AppPath = "C:\Users\bob\AppData\Local\Temp\badapp.exe"
    ModulePath = "C:\Users\bob\AppData\Local\Temp\badmod.dll"; IntegratorReportId = "r1"; PackageFullName = ""; PackageRelativeAppId = "" }
$oldCrash = @("oldapp.exe", "1.0.0.0", "5f000000", "oldmod.dll", "2.0.0.0", "5f000001", "c0000409", "0000000000004321", "0x10", "0x1d7", "C:\Apps\oldapp.exe", "C:\Apps\oldmod.dll", "r2")
$hang = [ordered]@{ AppName = "slowapp.exe"; AppVersion = "3.1"; ProcessId = "0x99"; StartTime = "0x1d7"; TerminationTime = "4294967295"; ExeFileName = "C:\Apps\slowapp.exe"; ReportId = "r3"; PackageFullName = ""; PackageRelativeAppId = ""; HangType = "Quiesce" }
$longText = "Threat found: " + ("x" * 250)
Test-Case -Name "Application: MSI, crashes, hangs, Security Center, ESENT, third-party antivirus" -Action {
    $records = @(
        (New-TestRecord -Provider "MsiInstaller" -Id 11707 -Time "2026-01-03 09:00:01" -Body (New-EventDataXml -Data @("Product: Test Product -- Installation completed successfully.", "(NULL)") -Binary $productHex)),
        (New-TestRecord -Provider "MsiInstaller" -Id 1033 -Time "2026-01-03 09:00:00" -UserSid "S-1-5-21-1111-2222-3333-1001" -Body (New-EventDataXml -Data @("Test Product", "1.2.3", "1033", "0", "Test Corp", "(NULL)") -Binary $productHex)),
        (New-TestRecord -Provider "MsiInstaller" -Id 11707 -Time "2026-01-03 09:05:00" -Body (New-EventDataXml -Data @("Product: Lone Product -- Installation completed successfully."))),
        (New-TestRecord -Provider "MsiInstaller" -Id 1034 -Time "2026-01-03 09:10:00" -UserSid "S-1-5-18" -Body (New-EventDataXml -Data @("Old Product", "2.0", "1033", "1603", "Old Corp", "(NULL)"))),
        (New-TestRecord -Provider "Application Error" -Id 1000 -Time "2026-01-03 09:20:00" -Level 2 -Body (New-EventDataXml -Data $crash)),
        (New-TestRecord -Provider "Application Error" -Id 1000 -Time "2026-01-03 09:21:00" -Level 2 -Body (New-EventDataXml -Data $oldCrash)),
        (New-TestRecord -Provider "Application Hang" -Id 1002 -Time "2026-01-03 09:30:00" -Level 2 -Body (New-EventDataXml -Data $hang)),
        (New-TestRecord -Provider "SecurityCenter" -Id 15 -Time "2026-01-03 10:00:00" -Body (New-EventDataXml -Data @("Test AV", "SECURITY_PRODUCT_STATE_ON"))),
        (New-TestRecord -Provider "SecurityCenter" -Id 15 -Time "2026-01-03 10:05:00" -Body (New-EventDataXml -Data @("Test AV", "SECURITY_PRODUCT_STATE_ON"))),
        (New-TestRecord -Provider "SecurityCenter" -Id 15 -Time "2026-01-03 10:10:00" -Body (New-EventDataXml -Data @("Test AV", "SECURITY_PRODUCT_STATE_OFF"))),
        (New-TestRecord -Provider "SecurityCenter" -Id 16 -Time "2026-01-03 10:15:00" -Level 2 -Body (New-EventDataXml -Data @("Test AV", "SECURITY_PRODUCT_STATE_SNOOZED") -Binary "02000000")),
        (New-TestRecord -Provider "ESENT" -Id 325 -Time "2026-01-03 11:00:00" -Body (New-EventDataXml -Data @("TestProc", "4321,D,0,0", "TestInstance: ", "1", "C:\Temp\copy\ntds.dit", "0", "[1] 0.0", "0 0", "dbv = 1"))),
        (New-TestRecord -Provider "ESENT" -Id 326 -Time "2026-01-03 11:01:00" -Body (New-EventDataXml -Data @("TestProc", "4321,D,0,0", "", "1", "C:\Temp\copy\ntds.dit", "0", "[1] 0.0", "0 0", "dbv = 1"))),
        (New-TestRecord -Provider "ESENT" -Id 327 -Time "2026-01-03 11:02:00" -Body (New-EventDataXml -Data @("TestProc", "4321,D,0,0", "", "1", "C:\Temp\copy\ntds.dit", "0", "[1] 0.0", "0 0", "dbv = 1"))),
        (New-TestRecord -Provider "ESENT" -Id 216 -Time "2026-01-03 11:03:00" -Level 3 -Body (New-EventDataXml -Data @("lsass", "600,D,50,0", "NTDSA: ", "C:\Windows\NTDS\ntds.dit", "D:\Restore\ntds.dit"))),
        (New-TestRecord -Provider "Sophos Anti-Virus" -Id 6 -Time "2026-01-03 12:00:00" -Level 2 -Values @("Virus 'Test-Virus' found", "", "(NULL)", "C:\Users\bob\x.exe") -Body (New-EventDataXml -Data @("Virus 'Test-Virus' found", "", "(NULL)", "C:\Users\bob\x.exe"))),
        (New-TestRecord -Provider "McLogEvent" -Id 258 -Time "2026-01-03 12:01:00" -Level 3 -Message "$longText`r`n  second   line" -UserSid "S-1-5-18"),
        (New-TestRecord -Provider "Some Other Provider" -Id 1000 -Time "2026-01-03 12:02:00"),
        # Routine antivirus Information events (skipped) and one reporting a detection (kept)
        (New-TestRecord -Provider "Symantec AntiVirus" -Id 7 -Time "2026-01-03 12:03:00" -Message "New virus definition file loaded. Version: 260101001."),
        (New-TestRecord -Provider "Symantec AntiVirus" -Id 3 -Time "2026-01-03 12:04:00" -Message "Scan Complete: Risks: 0 Scanned: 1234 Files/Folders/Drives Omitted: 0"),
        (New-TestRecord -Provider "McLogEvent" -Id 5000 -Time "2026-01-03 12:05:00" -Message "The update was successful."),
        (New-TestRecord -Provider "Symantec AntiVirus" -Id 51 -Time "2026-01-03 12:06:00" -Message "Security Risk Found! Trojan.Gen in File: C:\Users\bob\y.exe by: Auto-Protect scan. Action: Quarantine succeeded.")
    )
    Add-ApplicationEventEntries -Records $records -FileName $app -FilePath "X:\Application.evtx"
} -Expected @(
    @{ Timestamp = "2026-01-03 09:00:00.000"; EventType = "Installation"; Description = "Software installed: Test Product 1.2.3"; User = "S-1-5-21-1111-2222-3333-1001"
        Details = "EventID=1033 | Product=Test Product | Version=1.2.3 | Manufacturer=Test Corp | Status=0 (success) | ProductCode=$productCode | UserSID=S-1-5-21-1111-2222-3333-1001" },
    @{ EventType = "Installation"; Description = "Software installed: Lone Product"; User = ""; Details = "EventID=11707 | Product=Lone Product | Message=Product: Lone Product -- Installation completed successfully." },
    @{ EventType = "Installation"; Description = "Software removal failed: Old Product 2.0 (status 1603)"; User = "SYSTEM"; Details = "EventID=1034 | Product=Old Product | Version=2.0 | Manufacturer=Old Corp | Status=1603 (fatal error) | UserSID=S-1-5-18" },
    @{ EventType = "Execution"; Description = "Application crashed: badapp.exe (exception 0xc0000005 in badmod.dll)"
        Details = "EventID=1000 | Application=badapp.exe | Version=1.0.0.0 | Module=badmod.dll | ModuleVersion=2.0.0.0 | ExceptionCode=0xc0000005 | FaultOffset=0x0000000000001234 | Path=C:\Users\bob\AppData\Local\Temp\badapp.exe | ModulePath=C:\Users\bob\AppData\Local\Temp\badmod.dll" },
    @{ EventType = "Execution"; Description = "Application crashed: oldapp.exe (exception 0xc0000409 in oldmod.dll)"
        Details = "EventID=1000 | Application=oldapp.exe | Version=1.0.0.0 | Module=oldmod.dll | ModuleVersion=2.0.0.0 | ExceptionCode=0xc0000409 | FaultOffset=0x0000000000004321 | Path=C:\Apps\oldapp.exe | ModulePath=C:\Apps\oldmod.dll" },
    @{ EventType = "Execution"; Description = "Application hung and was closed: slowapp.exe"; Details = "EventID=1002 | Application=slowapp.exe | Version=3.1 | Path=C:\Apps\slowapp.exe | HangType=Quiesce" },
    @{ Timestamp = "2026-01-03 10:00:00.000"; EventType = "Snapshot"; Description = "Security product state: Test AV ON"; Details = "EventID=15 | Product=Test AV | State=ON" },
    @{ Timestamp = "2026-01-03 10:10:00.000"; EventType = "SecurityAlert"; Description = "Security product state: Test AV OFF"; Details = "EventID=15 | Product=Test AV | State=OFF | PreviousState=ON" },
    @{ EventType = "SecurityAlert"; Description = "Security Center could not update product state: Test AV SNOOZED"; Details = "EventID=16 | Product=Test AV | State=SNOOZED" },
    @{ EventType = "FileAccess"; Description = "ESE database created: C:\Temp\copy\ntds.dit"; Details = "EventID=325 | Database=C:\Temp\copy\ntds.dit | Process=TestProc | ProcessId=4321 | Instance=TestInstance" },
    @{ EventType = "FileAccess"; Description = "ESE database attached: C:\Temp\copy\ntds.dit"; Details = "EventID=326 | Database=C:\Temp\copy\ntds.dit | Process=TestProc | ProcessId=4321" },
    @{ EventType = "FileAccess"; Description = "ESE database detached: C:\Temp\copy\ntds.dit" },
    @{ EventType = "FileAccess"; Description = "ESE database location changed: C:\Windows\NTDS\ntds.dit -> D:\Restore\ntds.dit"
        Details = "EventID=216 | OldPath=C:\Windows\NTDS\ntds.dit | NewPath=D:\Restore\ntds.dit | Process=lsass | ProcessId=600 | Instance=NTDSA" },
    @{ EventType = "SecurityAlert"; Description = "Antivirus event (Sophos Anti-Virus 6): Virus 'Test-Virus' found | C:\Users\bob\x.exe"
        Details = "EventID=6 | Provider=Sophos Anti-Virus | Level=Error | Message=Virus 'Test-Virus' found | C:\Users\bob\x.exe" },
    @{ EventType = "SecurityAlert"; Description = "Antivirus event (McLogEvent 258): " + ("$longText second line").Substring(0, 200) + "..."; User = ""
        Details = "EventID=258 | Provider=McLogEvent | Level=Warning | Message=$longText second line | UserSID=S-1-5-18" },
    @{ EventType = "SecurityAlert"; Description = "Antivirus event (Symantec AntiVirus 51): Security Risk Found! Trojan.Gen in File: C:\Users\bob\y.exe by: Auto-Protect scan. Action: Quarantine succeeded."
        Details = "EventID=51 | Provider=Symantec AntiVirus | Level=Information | Message=Security Risk Found! Trojan.Gen in File: C:\Users\bob\y.exe by: Auto-Protect scan. Action: Quarantine succeeded." }
)

Test-Case -Name "Helpers: unknown codes kept as text" -Action {
    $checks = @(
        @((Format-EvtxCodeText -Text "0x120" -Names $script:ServiceTypeNames), "0x120 (interactive share process)"),
        @((Format-EvtxCodeText -Text "0x400" -Names $script:ServiceTypeNames), "0x400"),
        @((Format-EvtxCodeText -Text "auto" -Names $script:ServiceStartTypeNames), "auto"),
        @((ConvertFrom-AuditPolicyText -Text "%%8272, %%99999, text"), "System, %%99999, text"),
        @((ConvertFrom-AuditPolicyText -Text "%%99999999999, %%8449"), "%%99999999999, Success added"),
        @((Join-EvtxAccountName -Domain "-" -Name "bob"), "bob")
    )
    foreach ($check in $checks) {
        if ($check[0] -cne $check[1]) { throw "got '$($check[0])', expected '$($check[1])'" }
    }
} -Expected @()

# --- User column (ConvertTo-TimelineUserName, Update-TimelineUserColumn) ---
# SID names as Get-TimelineSidNames gives them, and the examined machine's
# names (the computer name and a host name after a rename)
$userSidNames = @{ "S-1-5-21-1111-2222-3333-1001" = "alice"; "S-1-5-80-1111-2222-3333-4444-5555" = "NT SERVICE\TestSvc" }
$userMachines = @("TESTHOST", "TestHost-New")
Test-Case -Name "User column: one form per account (ConvertTo-TimelineUserName)" -Action {
    # @(value, expected)
    $cases = @(
        @("", ""),
        @("-", ""),
        @("-\-", ""),
        @("\admin", "admin"),
        @("-\admin", "admin"),
        @("TESTHOST\-", "TESTHOST"),
        @("  alice  ", "alice"),
        @("TESTHOST\alice", "alice"),
        @("testhost\alice", "alice"),
        @("TestHost-New\alice", "alice"),
        @(" TESTHOST \ alice ", "alice"),
        @(".\alice", "alice"),
        @("OTHERHOST\alice", "OTHERHOST\alice"),
        @("WORKGROUP\TESTHOST$", "WORKGROUP\TESTHOST$"),
        @("MicrosoftAccount\alice@example.com", "MicrosoftAccount\alice@example.com"),
        @("AzureAD\AliceExample", "AzureAD\AliceExample"),
        @("NT VIRTUAL MACHINE\00000000-0000-0000-0000-000000000001", "NT VIRTUAL MACHINE\00000000-0000-0000-0000-000000000001"),
        @("NT SERVICE\TrustedInstaller", "NT SERVICE\TrustedInstaller"),
        @("NT AUTHORITY\ANONYMOUS LOGON", "NT AUTHORITY\ANONYMOUS LOGON"),
        @("BUILTIN\Users", "BUILTIN\Users"),
        @("Users", "Users"),
        @("S-1-5-18", "NT AUTHORITY\SYSTEM"),
        @("S-1-5-19", "NT AUTHORITY\LOCAL SERVICE"),
        @("S-1-5-20", "NT AUTHORITY\NETWORK SERVICE"),
        @("S-1-5-90-0-3", "Window Manager\DWM-3"),
        @("S-1-5-96-0-1", "Font Driver Host\UMFD-1"),
        @("S-1-5-21-1111-2222-3333-1001", "alice"),
        @(" S-1-5-21-1111-2222-3333-1001 ", "alice"),
        @("S-1-5-80-1111-2222-3333-4444-5555", "NT SERVICE\TestSvc"),
        @("S-1-5-21-1111-2222-3333-1009", "S-1-5-21-1111-2222-3333-1009"),
        @("S-1-5-21-1111-2222-3333-100", "S-1-5-21-1111-2222-3333-100"),
        @("S-1-5-32-544", "S-1-5-32-544"),
        @("SYSTEM", "NT AUTHORITY\SYSTEM"),
        @("system", "NT AUTHORITY\SYSTEM"),
        @("LocalSystem", "NT AUTHORITY\SYSTEM"),
        @("NT AUTHORITY\SYSTEM", "NT AUTHORITY\SYSTEM"),
        @("nt authority\system", "NT AUTHORITY\SYSTEM"),
        @("NT AUTHORITY\LocalSystem", "NT AUTHORITY\SYSTEM"),
        @(".\LocalSystem", "NT AUTHORITY\SYSTEM"),
        @("TESTHOST\SYSTEM", "NT AUTHORITY\SYSTEM"),
        @("LOCAL SERVICE", "NT AUTHORITY\LOCAL SERVICE"),
        @("LocalService", "NT AUTHORITY\LOCAL SERVICE"),
        @("NT AUTHORITY\LocalService", "NT AUTHORITY\LOCAL SERVICE"),
        @("NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\LOCAL SERVICE"),
        @("NETWORK SERVICE", "NT AUTHORITY\NETWORK SERVICE"),
        @("NetworkService", "NT AUTHORITY\NETWORK SERVICE"),
        @("NT AUTHORITY\NetworkService", "NT AUTHORITY\NETWORK SERVICE"),
        @("DWM-1", "Window Manager\DWM-1"),
        @("Window Manager\DWM-1", "Window Manager\DWM-1"),
        @("UMFD-0", "Font Driver Host\UMFD-0")
    )
    $wrong = @()
    foreach ($case in $cases) {
        $got = ConvertTo-TimelineUserName -Value $case[0] -SidNames $userSidNames -MachineNames $userMachines
        if ($got -cne $case[1]) { $wrong += "'$($case[0])' -> '$got' (expected '$($case[1])')" }
    }
    # Without machine names or SID names nothing is stripped or named
    foreach ($case in @(@("TESTHOST\alice", "TESTHOST\alice"), @("S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1001"), @(".\alice", "alice"))) {
        $got = ConvertTo-TimelineUserName -Value $case[0] -SidNames @{} -MachineNames @()
        if ($got -cne $case[1]) { $wrong += "no names: '$($case[0])' -> '$got' (expected '$($case[1])')" }
    }
    if ($wrong.Count -gt 0) { throw ($wrong -join "; ") }
} -Expected @()

Test-Case -Name "User column: SID names from ProfileList (wins) and bam_entries.csv, machine names" -Action {
    $script:timelineUserContext = $null
    try {
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1001" -Name "alice-bam"
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1001" -Name "alice" -ProfileList
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1002" -Name "bob" -ProfileList
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1002" -Name "bob-bam"
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1003" -Name " carol "
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1003" -Name "carol-later"
        Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1004" -Name ""
        Add-TimelineSidName -Sid "S-1-12-1-1111-2222-3333-4444" -Name "dave" -ProfileList
        Add-TimelineSidName -Sid "S-1-5-80-1111-2222-3333-4444-5555" -Name "TestSvc" -ProfileList
        # Profile folders of the built-in accounts and a group are not account names
        Add-TimelineSidName -Sid "S-1-5-18" -Name "systemprofile" -ProfileList
        Add-TimelineSidName -Sid "S-1-5-19" -Name "LocalService" -ProfileList
        Add-TimelineSidName -Sid "S-1-5-20" -Name "NetworkService" -ProfileList
        Add-TimelineSidName -Sid "S-1-5-32-544" -Name "Administrators"
        $names = Get-TimelineSidNames
        $keys = [string[]]@($names.Keys)
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $text = (@($keys | ForEach-Object { "$_=$($names[$_])" })) -join ", "
        $expected = "S-1-12-1-1111-2222-3333-4444=dave, S-1-5-21-1111-2222-3333-1001=alice, S-1-5-21-1111-2222-3333-1002=bob, " +
            "S-1-5-21-1111-2222-3333-1003=carol, S-1-5-80-1111-2222-3333-4444-5555=NT SERVICE\TestSvc"
        if ($text -cne $expected) { throw "Get-TimelineSidNames gave: $text" }
        Add-TimelineMachineName @("TESTHOST", " testhost ", "", "TestHost-New")
        Add-TimelineMachineName $null
        $machines = [string[]]@((Get-TimelineUserContext).MachineNames)
        [Array]::Sort($machines, [System.StringComparer]::Ordinal)
        if (($machines -join ",") -cne "TESTHOST,TestHost-New") { throw "machine names: $($machines -join ',')" }
        if (@(Get-OfflineComputerNames "not a registry key").Count -ne 0) { throw "Get-OfflineComputerNames read names from a string" }
    }
    finally { $script:timelineUserContext = $null }
} -Expected @()

# Parse-PowerShellHistory keeps the Sid/User pairs of bam_entries.csv for the
# User column (a synthetic collection with only that file)
$bamDir = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx-bam-" + [guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path (Join-Path $bamDir "Execution") -Force | Out-Null
    $bamCsv = '"Sid","User","Path","LastExecutionUtc"' + "`r`n" +
        '"S-1-5-21-1111-2222-3333-1003","carol","\Device\HarddiskVolume3\Tools\a.exe","2026-01-05T10:00:00Z"' + "`r`n" +
        '"S-1-5-18","SYSTEM","\Device\HarddiskVolume3\Windows\b.exe","2026-01-05T10:01:00Z"' + "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $bamDir "Execution\bam_entries.csv"), $bamCsv)
    Test-Case -Name "User column: Parse-PowerShellHistory keeps the Sid/User pairs of bam_entries.csv" -Action {
        $script:timelineUserContext = $null
        try {
            & {
                # Local to this block, as in a builder run
                Set-Variable -Name InputPath -Value $bamDir
                $script:collectionRoot = $bamDir
                $script:collectionInfo = $null
                $script:collectionManifest = $null
                $script:manifestTimes = $null
                $script:shortenedNames = @{}
                # The builder looks up the collection's Secrets\ folder once per run
                $script:secretsRoot = $null
                Parse-PowerShellHistory 6>$null | Out-Null
            }
            $names = Get-TimelineSidNames
            $text = (@($names.Keys | ForEach-Object { "$_=$($names[$_])" })) -join ", "
            if ($text -cne "S-1-5-21-1111-2222-3333-1003=carol") { throw "Get-TimelineSidNames gave: $text" }
        }
        finally {
            $script:timelineUserContext = $null
            $script:collectionInfo = $null
            $script:secretsRoot = $null
        }
    } -Expected @(
        @{ Source = "BAM"; EventType = "Execution"; Description = "BAM execution: \Device\HarddiskVolume3\Tools\a.exe"; User = "carol" },
        @{ Source = "BAM"; EventType = "Execution"; Description = "BAM execution: \Device\HarddiskVolume3\Windows\b.exe"; User = "SYSTEM" }
    )

    # The SRUM parser names its user SIDs the same way (Get-SrumSidNames):
    # in the User column's form, from the names the parsers before it
    # gathered (here a ProfileList name for alice, which wins over
    # bam_entries.csv) and from bam_entries.csv, which it adds to them. The
    # collection has no SOFTWARE hive, so the unknown SID stays unnamed.
    Test-Case -Name "User column: Get-SrumSidNames names SRUM's SIDs in the User column's form and keeps the bam_entries.csv names" -Action {
        $script:timelineUserContext = $null
        try {
            Add-TimelineSidName -Sid "S-1-5-21-1111-2222-3333-1001" -Name "alice" -ProfileList
            [System.IO.File]::AppendAllText((Join-Path $bamDir "Execution\bam_entries.csv"),
                '"S-1-5-21-1111-2222-3333-1001","alice-bam","\Device\HarddiskVolume3\Tools\c.exe","2026-01-05T10:02:00Z"' + "`r`n")
            $srumSids = @("S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1003", "S-1-5-21-1111-2222-3333-1009", "S-1-5-18", "S-1-5-19", "S-1-5-90-0-2")
            $srumNames = & {
                Set-Variable -Name InputPath -Value $bamDir
                $script:collectionRoot = $bamDir
                $script:collectionInfo = $null
                $script:secretsRoot = $null
                Get-SrumSidNames -Sids $srumSids
            }
            $keys = [string[]]@($srumNames.Keys)
            [Array]::Sort($keys, [System.StringComparer]::Ordinal)
            $text = (@($keys | ForEach-Object { "$_=$($srumNames[$_])" })) -join ", "
            $expected = "S-1-5-18=NT AUTHORITY\SYSTEM, S-1-5-19=NT AUTHORITY\LOCAL SERVICE, S-1-5-21-1111-2222-3333-1001=alice, " +
                "S-1-5-21-1111-2222-3333-1003=carol, S-1-5-90-0-2=Window Manager\DWM-2"
            if ($text -cne $expected) { throw "Get-SrumSidNames gave: $text" }
            $names = Get-TimelineSidNames
            $keys = [string[]]@($names.Keys)
            [Array]::Sort($keys, [System.StringComparer]::Ordinal)
            $text = (@($keys | ForEach-Object { "$_=$($names[$_])" })) -join ", "
            if ($text -cne "S-1-5-21-1111-2222-3333-1001=alice, S-1-5-21-1111-2222-3333-1003=carol") { throw "Get-TimelineSidNames gave: $text" }
        }
        finally {
            $script:timelineUserContext = $null
            $script:collectionInfo = $null
            $script:secretsRoot = $null
        }
    } -Expected @()
}
finally {
    Remove-Item -LiteralPath $bamDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Get-OfflineComputerNames and Add-OfflineProfileNames on this machine's own
# SYSTEM and SOFTWARE keys (read only; a loaded hive has the same layout):
# the computer name, and the current account's profile folder by its SID
Test-Case -Name "User column: computer name and ProfileList read from SYSTEM and SOFTWARE keys (this machine's, read only)" -Action {
    $script:timelineUserContext = $null
    $systemKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM")
    $softwareKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE")
    try {
        $computerNames = @(Get-OfflineComputerNames $systemKey)
        $nameValue = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName", "")
        if ($computerNames -notcontains $env:COMPUTERNAME -or -not $nameValue -or $computerNames -cnotcontains $nameValue) {
            throw "Get-OfflineComputerNames did not give this computer's name ($($computerNames.Count) name(s))"
        }
        Add-OfflineProfileNames $softwareKey
        $names = Get-TimelineSidNames
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($me -match '^S-1-(5-21|12-1)-' -and $names[$me] -ne (Split-Path $env:USERPROFILE -Leaf)) { throw "the current account's SID is not named after its profile folder" }
        foreach ($builtIn in @("S-1-5-18", "S-1-5-19", "S-1-5-20")) {
            if ($names.ContainsKey($builtIn)) { throw "$builtIn named from its profile folder: $($names[$builtIn])" }
        }
    }
    finally {
        $systemKey.Close()
        $softwareKey.Close()
        $script:timelineUserContext = $null
    }
} -Expected @()

Test-Case -Name "User column pass: rows rewritten once per value, a named SID kept in Details, counts (Update-TimelineUserColumn)" -Action {
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $userRows = @(
        @("TESTHOST\alice", "EventID=4624"),
        @("testhost\alice", ""),
        @("TESTHOST\alice", "EventID=4672"),
        @("S-1-5-21-1111-2222-3333-1001", ""),
        @("S-1-5-21-1111-2222-3333-1001", "EventID=1033 | UserSID=S-1-5-21-1111-2222-3333-1001"),
        @("S-1-5-21-1111-2222-3333-1001", "SID=S-1-5-21-1111-2222-3333-1001; Time=last execution (BAM)"),
        @("S-1-5-21-1111-2222-3333-1001", "MemberSID=S-1-5-21-1111-2222-3333-10011"),
        # The SID as the value of a field that is not named ...SID (firewall
        # ModifyingUser, scheduled task UserId) is in Details already; inside
        # a path it is not
        @("S-1-5-21-1111-2222-3333-1001", "EventID=2052 | RuleName=Open RDP | ModifyingUser=S-1-5-21-1111-2222-3333-1001"),
        @("S-1-5-21-1111-2222-3333-1001", "Actions=x.exe | UserId=S-1-5-21-1111-2222-3333-1001 | State=Ready"),
        @("S-1-5-21-1111-2222-3333-1001", "Location=HKU\S-1-5-21-1111-2222-3333-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        @("S-1-5-18", "ScriptBlock=Get-Date ScriptBlockId={00000000-0000-0000-0000-000000000001}"),
        @("S-1-5-21-1111-2222-3333-1009", "x"),
        @("S-1-5-21-1111-2222-3333-1009", ""),
        @("S-1-5-32-544", ""),
        @("LocalSystem", "a=1"),
        @("WORKGROUP\TESTHOST$", ""),
        # Values that differ only in case are kept apart
        @("OTHERHOST\Alice", ""),
        @("OTHERHOST\alice", ""),
        @("", "no user")
    )
    foreach ($row in $userRows) { $entries.Add([PSCustomObject]@{ Timestamp = "2026-01-05 00:00:00.000"; Source = "Test"; User = $row[0]; Details = $row[1] }) }
    $result = Update-TimelineUserColumn -Entries $entries -SidNames $userSidNames -MachineNames $userMachines
    $rowsText = (@($entries | ForEach-Object { "$($_.User)|$($_.Details)" })) -join "`n"
    $expectedRows = @(
        "alice|EventID=4624",
        "alice|",
        "alice|EventID=4672",
        "alice|UserSID=S-1-5-21-1111-2222-3333-1001",
        "alice|EventID=1033 | UserSID=S-1-5-21-1111-2222-3333-1001",
        "alice|SID=S-1-5-21-1111-2222-3333-1001; Time=last execution (BAM)",
        "alice|MemberSID=S-1-5-21-1111-2222-3333-10011 | UserSID=S-1-5-21-1111-2222-3333-1001",
        "alice|EventID=2052 | RuleName=Open RDP | ModifyingUser=S-1-5-21-1111-2222-3333-1001",
        "alice|Actions=x.exe | UserId=S-1-5-21-1111-2222-3333-1001 | State=Ready",
        "alice|Location=HKU\S-1-5-21-1111-2222-3333-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | UserSID=S-1-5-21-1111-2222-3333-1001",
        "NT AUTHORITY\SYSTEM|ScriptBlock=Get-Date ScriptBlockId={00000000-0000-0000-0000-000000000001} | UserSID=S-1-5-18",
        "S-1-5-21-1111-2222-3333-1009|x",
        "S-1-5-21-1111-2222-3333-1009|",
        "S-1-5-32-544|",
        "NT AUTHORITY\SYSTEM|a=1",
        "WORKGROUP\TESTHOST$|",
        "OTHERHOST\Alice|",
        "OTHERHOST\alice|",
        "|no user"
    ) -join "`n"
    if ($rowsText -cne $expectedRows) { throw "rows:`n$rowsText" }
    $transitions = (@($result.Transitions | ForEach-Object { "$($_.From) -> $($_.To) x$($_.Rows)" })) -join "; "
    $expectedTransitions = "S-1-5-21-1111-2222-3333-1001 -> alice x7; TESTHOST\alice -> alice x2; LocalSystem -> NT AUTHORITY\SYSTEM x1; " +
        "S-1-5-18 -> NT AUTHORITY\SYSTEM x1; testhost\alice -> alice x1"
    if ($transitions -cne $expectedTransitions) { throw "transitions: $transitions" }
    $unresolved = (@($result.Unresolved | ForEach-Object { "$($_.Sid) x$($_.Rows)" })) -join "; "
    if ($unresolved -cne "S-1-5-21-1111-2222-3333-1009 x2; S-1-5-32-544 x1") { throw "unresolved: $unresolved" }
    if ("$($result.Rows)|$($result.SidRows)" -ne "12|4") { throw "rows changed|given UserSID: $($result.Rows)|$($result.SidRows)" }
    if (@($entries | Where-Object { $_.Timestamp -ne "2026-01-05 00:00:00.000" -or $_.Source -ne "Test" }).Count -gt 0) { throw "other columns changed" }
} -Expected @()

# In the builder's main flow, the pass runs once, on the collected rows,
# after the exit for a run without rows and before deduplication (which
# compares User)
$outside = { param($node) $p = $node.Parent; while ($p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $p = $p.Parent }; $null -eq $p }
$passCalls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq "Update-TimelineUserColumn" }, $true) | Where-Object { & $outside $_ })
$noRowsExit = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.Extent.Text -eq "Write-RunEndBanner -NoOutput" }, $true) | Where-Object { & $outside $_ })
$dedupLoop = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ForEachStatementAst] -and $node.Condition.Extent.Text -eq '$script:timelineEntries' }, $true) | Where-Object { & $outside $_ })
Test-Case -Name "User column pass in the main flow: after the no-rows exit, before deduplication" -Action {
    if ($passCalls.Count -ne 1 -or $noRowsExit.Count -ne 1 -or $dedupLoop.Count -ne 1) { throw "found $($passCalls.Count) pass call(s), $($noRowsExit.Count) no-rows exit(s), $($dedupLoop.Count) loop(s) over the rows" }
    if ($passCalls[0].Extent.Text -notmatch '-Entries \$script:timelineEntries\b') { throw "the pass is not given the collected rows: $($passCalls[0].Extent.Text)" }
    $order = "$($noRowsExit[0].Extent.StartOffset -lt $passCalls[0].Extent.StartOffset)|$($passCalls[0].Extent.StartOffset -lt $dedupLoop[0].Extent.StartOffset)"
    if ($order -ne "True|True") { throw "order (no-rows exit < pass | pass < deduplication): $order" }
} -Expected @()

# The main flow's own User column statements (after the no-rows exit, up to
# the last that uses $userPass) on synthetic rows, with Log captured: the
# computer name of collection_info.json is a name of the examined machine
# only in a live collection (a mounted image is collected on another
# machine), and the two log lines
Test-Case -Name "User column pass in the main flow: collection_info.json's computer name only for a live collection, the log lines" -Action {
    $statement = $passCalls[0]
    while ($statement.Parent -and $statement.Parent -isnot [System.Management.Automation.Language.NamedBlockAst] -and $statement.Parent -isnot [System.Management.Automation.Language.StatementBlockAst]) { $statement = $statement.Parent }
    $siblings = @($statement.Parent.Statements)
    $first = -1
    $last = -1
    for ($i = 0; $i -lt $siblings.Count; $i++) {
        if ($siblings[$i].Extent.StartOffset -le $noRowsExit[0].Extent.StartOffset -and $siblings[$i].Extent.EndOffset -ge $noRowsExit[0].Extent.EndOffset) { $first = $i + 1 }
        if ($siblings[$i].Extent.Text -match '\$userPass\b') { $last = $i }
    }
    if ($first -lt 1 -or $last -lt $first) { throw "the User column statements were not found after the no-rows exit ($first..$last)" }
    $userStatements = [ScriptBlock]::Create((@($siblings[$first..$last] | ForEach-Object { $_.Extent.Text }) -join "`n"))
    $collectedRows = $script:timelineEntries
    try {
        # @(Mode, User of the "COLLECTORPC\alice" row afterwards, rows changed)
        foreach ($case in @(@("MountedImage", "COLLECTORPC\alice", 0), @("Live", "alice", 1))) {
            $script:timelineUserContext = $null
            $script:collectionInfo = [PSCustomObject]@{ Mode = $case[0]; ComputerName = "COLLECTORPC" }
            $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($user in @("COLLECTORPC\alice", "S-1-5-21-1111-2222-3333-1009")) { $script:timelineEntries.Add([PSCustomObject]@{ User = $user; Details = "" }) }
            $logged = [System.Collections.Generic.List[string]]::new()
            & {
                function Log { param([string]$Message) $logged.Add($Message) }
                . $userStatements
            }
            $users = (@($script:timelineEntries | ForEach-Object { $_.User })) -join ", "
            if ($users -cne "$($case[1]), S-1-5-21-1111-2222-3333-1009") { throw "Mode $($case[0]): rows $users" }
            $summary = "^  User column: $($case[2]) row\(s\) changed to one form per account \($($case[2]) distinct value\(s\)\); 0 row\(s\) whose SID got a name keep it in Details \(UserSID=\)$"
            $unnamed = '^  User column: 1 SID\(s\) not named by the sources read in this run \(.*-Sources Registry.*\), left as they are: S-1-5-21-1111-2222-3333-1009 \(1 row\(s\)\)$'
            if ($logged.Count -ne 2 -or $logged[0] -cnotmatch $summary -or $logged[1] -cnotmatch $unnamed) { throw "Mode $($case[0]): logged $($logged -join ' / ')" }
        }
    }
    finally {
        $script:timelineEntries = $collectedRows
        $script:timelineUserContext = $null
        $script:collectionInfo = $null
    }
} -Expected @()

# --- Parse-EventLogs dispatch ---
# Parse-EventLogs itself on synthetic records, with Get-WinEvent replaced by
# Get-TestWinEvent, which applies the EventID and provider terms of the XPath
# it is given. Checks which IDs and providers each channel reads (an ID
# missing from a channel's list gives no row; events of other IDs and
# providers must give none) and that no query has more than 20 terms (the
# event log rejects an XPath with about 23 or more).
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
        # Provider names match case-insensitively, as in the event log
        if ($providers.Count -gt 0 -and $providers -notcontains $record.ProviderName) { continue }
        $record
    }
}

$dispatchDir = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx-dispatch-" + [guid]::NewGuid().ToString("N"))
try {
    $defName = "Microsoft-Windows-Windows Defender%4Operational.evtx"
    $psName = "Microsoft-Windows-PowerShell%4Operational.evtx"
    $bitsName = "Microsoft-Windows-Bits-Client%4Operational.evtx"
    New-Item -ItemType Directory -Path (Join-Path $dispatchDir "EventLogs") -Force | Out-Null
    foreach ($name in @("Security.evtx", "System.evtx", $defName, "Application.evtx", $psName, $bitsName)) {
        Set-Content -LiteralPath (Join-Path $dispatchDir "EventLogs\$name") -Value "placeholder" -Encoding ASCII
    }
    $bobSid = "S-1-5-21-1111-2222-3333-1002"
    $bob = [ordered]@{ TargetUserName = "bob"; TargetDomainName = "TESTHOST"; TargetSid = $bobSid }
    $logon = Join-Subject ([ordered]@{ TargetUserSid = "S-1-5-21-1111-2222-3333-1001"; TargetUserName = "alice"; TargetDomainName = "TESTHOST"; LogonType = "2"; IpAddress = "-"; IpPort = "-"; TargetLogonId = "0x77" })
    $session = [ordered]@{ AccountName = "bob"; AccountDomain = "TESTHOST"; LogonID = "0x1234"; SessionName = "RDP-Tcp#3"; ClientName = "LAPTOP-9"; ClientAddress = "203.0.113.7" }
    $security = @(
        @(4624, (New-EventDataXml -Data $logon)),
        @(4720, (New-EventDataXml -Data (Join-Subject $bob))),
        @(4732, (New-EventDataXml -Data (Join-Subject ([ordered]@{ MemberName = "-"; MemberSid = $bobSid; TargetUserName = "Administrators"; TargetDomainName = "Builtin"; TargetSid = "S-1-5-32-544" })))),
        @(4728, (New-EventDataXml -Data (Join-Subject ([ordered]@{ MemberName = "CN=Bob,DC=test"; MemberSid = $bobSid; TargetUserName = "Domain Admins"; TargetDomainName = "TEST"; TargetSid = "S-1-5-21-9-9-9-512" })))),
        @(4756, (New-EventDataXml -Data (Join-Subject ([ordered]@{ MemberName = "CN=Bob,DC=test"; MemberSid = $bobSid; TargetUserName = "Enterprise Admins"; TargetDomainName = "TEST"; TargetSid = "S-1-5-21-9-9-9-519" })))),
        @(4724, (New-EventDataXml -Data (Join-Subject $bob))),
        @(4740, (New-EventDataXml -Data ([ordered]@{ TargetUserName = "bob"; TargetDomainName = "WKS-07"; TargetSid = $bobSid; SubjectUserSid = "S-1-5-18"; SubjectUserName = "TESTHOST$"; SubjectDomainName = "WORKGROUP" }))),
        @(4778, (New-EventDataXml -Data $session)),
        @(4779, (New-EventDataXml -Data $session)),
        @(1102, (New-UserDataXml -Wrapper "LogFileCleared" -Data $alice)),
        @(4719, (New-EventDataXml -Data (Join-Subject ([ordered]@{ CategoryId = "%%8278"; SubcategoryId = "%%13824"; SubcategoryGuid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; AuditPolicyChanges = "%%8449" })))),
        @(4697, (New-EventDataXml -Data (Join-Subject ([ordered]@{ ServiceName = "TestSvc"; ServiceFileName = "C:\Temp\svc.exe -k run"; ServiceType = "0x10"; ServiceStartType = "3"; ServiceAccount = "LocalSystem" })))),
        @(4698, (New-EventDataXml -Data (Join-Subject ([ordered]@{ TaskName = "\TestTask"; TaskContent = $taskXml })))),
        @(4702, (New-EventDataXml -Data (Join-Subject ([ordered]@{ TaskName = "\TestTask"; TaskContentNew = $taskXml })))),
        @(4701, (New-EventDataXml -Data (Join-Subject ([ordered]@{ TaskName = "\TestTask"; TaskContent = $taskXml })))),
        @(4700, (New-EventDataXml -Data (Join-Subject ([ordered]@{ TaskName = "\TestTask"; TaskContent = $taskXml })))),
        @(4699, (New-EventDataXml -Data (Join-Subject ([ordered]@{ TaskName = "\TestTask"; TaskContent = $taskXml })))),
        @(4726, (New-EventDataXml -Data (Join-Subject $bob))),
        @(4634, (New-EventDataXml -Data ([ordered]@{ TargetUserName = "alice" }))),
        # Accounts with "-" parts: a failed logon without a domain, and a
        # process created without a subject account
        @(4625, (New-EventDataXml -Data ([ordered]@{ TargetUserName = "bob"; TargetDomainName = "-"; Status = "0xc000006d"; SubStatus = "0xc000006a"; IpAddress = "203.0.113.7" }))),
        @(4688, (New-EventDataXml -Data ([ordered]@{ SubjectUserSid = "S-1-0-0"; SubjectUserName = "-"; SubjectDomainName = "-"; NewProcessId = "0x1a0"; NewProcessName = "C:\Windows\System32\smss.exe"; CommandLine = ""; ParentProcessName = "" })))
    )
    $script:mockEvtx.Records["Security.evtx"] = @(foreach ($e in $security) {
            $provider = if ($e[0] -eq 1102) { "Microsoft-Windows-Eventlog" } else { $auditing }
            New-TestRecord -Provider $provider -Id $e[0] -Time "2026-01-04 08:00:00" -Body $e[1]
        })
    $script:mockEvtx.Records["System.evtx"] = @(
        (New-TestRecord -Provider "Microsoft-Windows-Eventlog" -Id 104 -Time "2026-01-04 09:00:00" -Body (New-UserDataXml -Wrapper "LogFileCleared" -Data ([ordered]@{ SubjectUserName = "alice"; SubjectDomainName = "TESTHOST"; Channel = "TestLog" }))),
        (New-TestRecord -Provider "EventLog" -Id 6005 -Time "2026-01-04 09:01:00" -Body (New-EventDataXml -Data @())),
        (New-TestRecord -Provider "EventLog" -Id 6006 -Time "2026-01-04 09:02:00" -Body (New-EventDataXml -Data @())),
        (New-TestRecord -Provider "Service Control Manager" -Id 7040 -Time "2026-01-04 09:03:00" -Body (New-EventDataXml -Data ([ordered]@{ param1 = "Test Service"; param2 = "demand start"; param3 = "disabled"; param4 = "TestSvc" }))),
        (New-TestRecord -Provider "Service Control Manager" -Id 7045 -Time "2026-01-04 09:04:00" -Body (New-EventDataXml -Data ([ordered]@{ ServiceName = "TestSvc"; ImagePath = "C:\Temp\svc.exe -k run"; ServiceType = "user mode service"; StartType = "demand start"; AccountName = "LocalSystem" }))),
        (New-TestRecord -Provider "Some Other Provider" -Id 9999 -Time "2026-01-04 09:05:00")
    )
    $asrData = [ordered]@{ ID = "{9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2}"; User = "TESTHOST\alice"; Path = "C:\Windows\System32\lsass.exe"; "Process Name" = "C:\Tools\scan.exe" }
    $blockData = [ordered]@{ ID = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; User = "TESTHOST\alice"; Path = "C:\Windows\System32\cmd.exe"; "Process Name" = "C:\Office\WINWORD.EXE" }
    $script:mockEvtx.Records[$defName] = @(
        (New-TestRecord -Provider $defender -Id 1013 -Time "2026-01-04 10:00:00" -Body (New-EventDataXml -Data ([ordered]@{ Timestamp = "2025-12-20T10:00:00Z"; Domain = "NT AUTHORITY"; User = "SYSTEM"; SID = "S-1-5-18" }))),
        (New-TestRecord -Provider $defender -Id 1121 -Time "2026-01-04 10:01:00" -Body (New-EventDataXml -Data $blockData)),
        (New-TestRecord -Provider $defender -Id 1122 -Time "2026-01-04 10:02:00" -Body (New-EventDataXml -Data $asrData)),
        (New-TestRecord -Provider $defender -Id 1122 -Time "2026-01-04 10:03:00" -Body (New-EventDataXml -Data $asrData)),
        (New-TestRecord -Provider $defender -Id 1116 -Time "2026-01-04 10:04:00" -Body (New-EventDataXml -Data ([ordered]@{ "Threat Name" = "Trojan:Win32/Test"; Path = "file:_C:\x.exe" }))),
        (New-TestRecord -Provider $defender -Id 1150 -Time "2026-01-04 10:05:00")
    )
    $appRecords = @(
        (New-TestRecord -Provider "MsiInstaller" -Id 1033 -Time "2026-01-04 11:00:00" -Body (New-EventDataXml -Data @("Test Product", "1.2.3", "1033", "0", "Test Corp", "(NULL)"))),
        (New-TestRecord -Provider "MsiInstaller" -Id 11724 -Time "2026-01-04 11:01:00" -Body (New-EventDataXml -Data @("Product: Lone Product -- Removal completed successfully."))),
        (New-TestRecord -Provider "Application Error" -Id 1000 -Time "2026-01-04 11:02:00" -Level 2 -Body (New-EventDataXml -Data $crash)),
        (New-TestRecord -Provider "Application Hang" -Id 1002 -Time "2026-01-04 11:03:00" -Level 2 -Body (New-EventDataXml -Data $hang)),
        (New-TestRecord -Provider "SecurityCenter" -Id 15 -Time "2026-01-04 11:04:00" -Body (New-EventDataXml -Data @("Test AV", "SECURITY_PRODUCT_STATE_OFF"))),
        (New-TestRecord -Provider "SecurityCenter" -Id 16 -Time "2026-01-04 11:05:00" -Level 2 -Body (New-EventDataXml -Data @("Test AV", "SECURITY_PRODUCT_STATE_SNOOZED"))),
        (New-TestRecord -Provider "ESENT" -Id 216 -Time "2026-01-04 11:06:00" -Level 3 -Body (New-EventDataXml -Data @("lsass", "600,D,50,0", "NTDSA: ", "C:\Windows\NTDS\ntds.dit", "D:\Restore\ntds.dit"))),
        (New-TestRecord -Provider "ESENT" -Id 325 -Time "2026-01-04 11:07:00" -Body (New-EventDataXml -Data @("TestProc", "4321,D,0,0", "", "1", "C:\Temp\copy\ntds.dit"))),
        (New-TestRecord -Provider "ESENT" -Id 326 -Time "2026-01-04 11:08:00" -Body (New-EventDataXml -Data @("TestProc", "4321,D,0,0", "", "1", "C:\Temp\copy\ntds.dit"))),
        (New-TestRecord -Provider "ESENT" -Id 327 -Time "2026-01-04 11:09:00" -Body (New-EventDataXml -Data @("TestProc", "4321,D,0,0", "", "1", "C:\Temp\copy\ntds.dit"))),
        (New-TestRecord -Provider "ESENT" -Id 102 -Time "2026-01-04 11:10:00" -Body (New-EventDataXml -Data @("svchost", "1,D,0,0", "", "started"))),
        (New-TestRecord -Provider "Windows Error Reporting" -Id 1001 -Time "2026-01-04 11:11:00" -Body (New-EventDataXml -Data @("LiveKernelEvent"))),
        (New-TestRecord -Provider "Some Other Provider" -Id 1000 -Time "2026-01-04 11:12:00")
    )
    $second = 0
    foreach ($provider in $script:ThirdPartyAvProviders) {
        $second++
        $appRecords += New-TestRecord -Provider $provider -Id 1 -Time ("2026-01-04 12:00:{0:D2}" -f $second) -Level 2 -Message "Threat detected by $provider"
    }
    $script:mockEvtx.Records["Application.evtx"] = $appRecords
    # PowerShell 4104 / 4103 and BITS 59: the account is only the record's
    # UserID (4105 is not read)
    $psProvider = "Microsoft-Windows-PowerShell"
    $script:mockEvtx.Records[$psName] = @(
        (New-TestRecord -Provider $psProvider -Id 4104 -Time "2026-01-04 13:00:00" -Level 5 -UserSid "S-1-5-21-1111-2222-3333-1001" -Body (New-EventDataXml -Data ([ordered]@{
                MessageNumber = "1"; MessageTotal = "1"; ScriptBlockText = "Get-Process"; ScriptBlockId = "{00000000-0000-0000-0000-000000004104}"; Path = "C:\Scripts\test.ps1" }))),
        (New-TestRecord -Provider $psProvider -Id 4104 -Time "2026-01-04 13:01:00" -Level 5 -UserSid "S-1-5-18" -Body (New-EventDataXml -Data ([ordered]@{
                MessageNumber = "1"; MessageTotal = "1"; ScriptBlockText = "Get-Date"; ScriptBlockId = "{00000000-0000-0000-0000-000000004105}"; Path = "" }))),
        (New-TestRecord -Provider $psProvider -Id 4103 -Time "2026-01-04 13:02:00" -UserSid "S-1-5-21-1111-2222-3333-1001" -Body (New-EventDataXml -Data ([ordered]@{
                ContextInfo = "Host Name = ConsoleHost"; UserData = ""; Payload = "CommandInvocation(Get-Process): Get-Process" }))),
        (New-TestRecord -Provider $psProvider -Id 4105 -Time "2026-01-04 13:03:00" -UserSid "S-1-5-21-1111-2222-3333-1001" -Body (New-EventDataXml -Data ([ordered]@{ ScriptBlockId = "{00000000-0000-0000-0000-000000004104}"; RunspaceId = "{00000000-0000-0000-0000-000000000001}" })))
    )
    $bitsProvider = "Microsoft-Windows-Bits-Client"
    $script:mockEvtx.Records[$bitsName] = @(
        (New-TestRecord -Provider $bitsProvider -Id 3 -Time "2026-01-04 14:00:00" -UserSid "S-1-5-21-1111-2222-3333-1001" -Body (New-EventDataXml -Data ([ordered]@{
                jobTitle = "TestJob"; jobId = "{00000000-0000-0000-0000-0000000b1753}"; jobOwner = "TESTHOST\alice"; processPath = "C:\Tools\dl.exe"; processId = "4242" }))),
        (New-TestRecord -Provider $bitsProvider -Id 59 -Time "2026-01-04 14:00:01" -UserSid "S-1-5-21-1111-2222-3333-1001" -Body (New-EventDataXml -Data ([ordered]@{
                transferId = "{00000000-0000-0000-0000-000000000059}"; name = "TestJob"; Id = "{00000000-0000-0000-0000-0000000b1753}"; url = "https://dl.example.com/x.bin"; bytesTotal = "1024"; bytesTransferred = "0" })))
    )

    $expectedRows = @(
        @("Security.evtx", "Logon", "Successful logon (Interactive)", "*"),
        @("Security.evtx", "AccountChange", "User account created: bob", "NewAccount=TESTHOST\bob | AccountSID=$bobSid"),
        @("Security.evtx", "AccountChange", "Member added to security-enabled local group: Administrators (member TESTHOST\bob)", "*GroupSID=S-1-5-32-544 | Member=TESTHOST\bob | MemberSID=$bobSid | MemberNameFrom=event 4720"),
        @("Security.evtx", "AccountChange", "Member added to security-enabled global group: Domain Admins (member CN=Bob,DC=test)", "*"),
        @("Security.evtx", "AccountChange", "Member added to security-enabled universal group: Enterprise Admins (member CN=Bob,DC=test)", "*"),
        @("Security.evtx", "AccountChange", "Password reset attempted for account: TESTHOST\bob", "*"),
        @("Security.evtx", "AccountChange", "User account locked out: bob", "*CallerComputer=WKS-07*"),
        @("Security.evtx", "Logon", "Session reconnected to window station (client LAPTOP-9, 203.0.113.7)", "*"),
        @("Security.evtx", "Logon", "Session disconnected from window station (client LAPTOP-9, 203.0.113.7)", "*"),
        @("Security.evtx", "SecurityAlert", "Security audit log cleared", "EventID=1102 | ClearedBy=TESTHOST\alice*"),
        @("Security.evtx", "SecurityAlert", "System audit policy changed: Account Management\User Account Management (Success added)", "*"),
        @("Security.evtx", "PersistenceChange", "New service installed: TestSvc", "EventID=4697 | ServiceName=TestSvc | ImagePath=C:\Temp\svc.exe -k run*"),
        @("Security.evtx", "ScheduledTaskChange", "Scheduled task registered: \TestTask", "*Command=C:\Windows\System32\cmd.exe*"),
        @("Security.evtx", "ScheduledTaskChange", "Scheduled task updated: \TestTask", "*"),
        @("Security.evtx", "ScheduledTaskChange", "Scheduled task disabled: \TestTask", "*"),
        @("Security.evtx", "ScheduledTaskChange", "Scheduled task enabled: \TestTask", "*"),
        @("Security.evtx", "ScheduledTaskChange", "Scheduled task deleted: \TestTask", "*"),
        @("Security.evtx", "AccountChange", "User account deleted: bob", "DeletedAccount=TESTHOST\bob | AccountSID=$bobSid"),
        @("Security.evtx", "Logon", "Failed logon attempt (Status=0xc000006d)", "FailureReason=0xc000006a Source=203.0.113.7"),
        @("Security.evtx", "ProcessCreation", "New process created: C:\Windows\System32\smss.exe", "*PID=0x1a0"),
        @($psName, "Execution", "PowerShell script block executed", "ScriptBlock=Get-Process ScriptBlockId={00000000-0000-0000-0000-000000004104} Path=C:\Scripts\test.ps1"),
        @($psName, "Execution", "PowerShell script block executed", "ScriptBlock=Get-Date ScriptBlockId={00000000-0000-0000-0000-000000004105}"),
        @($psName, "Execution", "PowerShell module logging event", "Payload=CommandInvocation(Get-Process): Get-Process"),
        @($bitsName, "NetworkConnection", "BITS job created: TestJob", "EventID=3 | JobId={00000000-0000-0000-0000-0000000b1753} | Process=C:\Tools\dl.exe | PID=4242"),
        @($bitsName, "NetworkConnection", "BITS transfer started: TestJob -> https://dl.example.com/x.bin", "EventID=59 | JobId={00000000-0000-0000-0000-0000000b1753} | Url=https://dl.example.com/x.bin | BytesTransferred=0 | BytesTotal=1024 | UserSID=S-1-5-21-1111-2222-3333-1001"),
        @("System.evtx", "SecurityAlert", "Event log cleared: TestLog", "EventID=104 | Channel=TestLog | ClearedBy=TESTHOST\alice"),
        @("System.evtx", "ServiceChange", "Event log service started (system startup)", "EventID=6005"),
        @("System.evtx", "ServiceChange", "Event log service stopped (clean shutdown)", "EventID=6006"),
        @("System.evtx", "ServiceChange", "Service start type changed: Test Service", "Service=TestSvc | OldType=demand start | NewType=disabled"),
        @("System.evtx", "PersistenceChange", "New service installed: TestSvc", "ImagePath=C:\Temp\svc.exe -k run | StartType=demand start"),
        @($defName, "SecurityAlert", "Defender malware detection history purged by retention (items before 2025-12-20T10:00:00Z)", "EventID=1013 | Trigger=Retention*"),
        @($defName, "SecurityAlert", "Defender attack surface reduction rule blocked: Block all Office applications from creating child processes", "*"),
        @($defName, "SecurityAlert", "Defender attack surface reduction rule audited: Block credential stealing from the Windows local security authority subsystem", "*Count=2 | LastSeen=2026-01-04 10:03:00"),
        @($defName, "SecurityAlert", "Defender detected threat: Trojan:Win32/Test", "*"),
        @("Application.evtx", "Installation", "Software installed: Test Product 1.2.3", "*"),
        @("Application.evtx", "Installation", "Software removed: Lone Product", "*"),
        @("Application.evtx", "Execution", "Application crashed: badapp.exe (exception 0xc0000005 in badmod.dll)", "*"),
        @("Application.evtx", "Execution", "Application hung and was closed: slowapp.exe", "*"),
        @("Application.evtx", "SecurityAlert", "Security product state: Test AV OFF", "*"),
        @("Application.evtx", "SecurityAlert", "Security Center could not update product state: Test AV SNOOZED", "*"),
        @("Application.evtx", "FileAccess", "ESE database location changed: C:\Windows\NTDS\ntds.dit -> D:\Restore\ntds.dit", "*"),
        @("Application.evtx", "FileAccess", "ESE database created: C:\Temp\copy\ntds.dit", "*"),
        @("Application.evtx", "FileAccess", "ESE database attached: C:\Temp\copy\ntds.dit", "*"),
        @("Application.evtx", "FileAccess", "ESE database detached: C:\Temp\copy\ntds.dit", "*")
    )
    foreach ($provider in $script:ThirdPartyAvProviders) {
        $expectedRows += , @("Application.evtx", "SecurityAlert", "Antivirus event ($provider 1): Threat detected by $provider", "*Level=Error*")
    }

    $logBefore = if (Test-Path -LiteralPath $logFile) { @(Get-Content -LiteralPath $logFile).Count } else { 0 }
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
    if ($script:mockEvtx.MaxTerms -gt 20) { $problems += "a query had $($script:mockEvtx.MaxTerms) EventID / provider terms (at most 20)" }
    $warnings = @(Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue | Select-Object -Skip $logBefore | Where-Object { $_ -match "WARNING:" })
    if ($warnings.Count -gt 0) { $problems += "warnings: $($warnings -join '; ')" }
    Write-TestResult -Name "Parse-EventLogs reads the handled IDs and providers of each channel ($($script:mockEvtx.Queries) queries)" -Passed ($problems.Count -eq 0) -Message ($problems -join "; ")

    # User as the parsers write it (the User column pass names SIDs and
    # strips the computer name later): joined without "-" parts, and the
    # record's UserID for PowerShell 4104 / 4103 and BITS 59
    $userChecks = @(
        @("Security.evtx", "Successful logon (Interactive)", "*", "TESTHOST\alice"),
        @("Security.evtx", "Failed logon attempt (Status=0xc000006d)", "*", "bob"),
        @("Security.evtx", "New process created: C:\Windows\System32\smss.exe", "*", ""),
        @("Security.evtx", "User account created: bob", "*", "TESTHOST\alice"),
        @($psName, "PowerShell script block executed", "ScriptBlock=Get-Process *", "S-1-5-21-1111-2222-3333-1001"),
        @($psName, "PowerShell script block executed", "ScriptBlock=Get-Date *", "S-1-5-18"),
        @($psName, "PowerShell module logging event", "*", "S-1-5-21-1111-2222-3333-1001"),
        @($bitsName, "BITS job created: TestJob", "*", "TESTHOST\alice"),
        @($bitsName, "BITS transfer started: TestJob -> https://dl.example.com/x.bin", "*", "S-1-5-21-1111-2222-3333-1001")
    )
    $problems = @()
    foreach ($check in $userChecks) {
        $match = @($rows | Where-Object { $_.Source -eq $check[0] -and $_.Description -ceq $check[1] -and $_.Details -clike $check[2] })
        if ($match.Count -ne 1 -or $match[0].User -cne $check[3]) {
            $problems += "[$($check[0])] $($check[1]): User '$(@($match | ForEach-Object { $_.User }) -join "', '")', expected '$($check[3])'"
        }
    }
    Write-TestResult -Name "Parse-EventLogs: User of Security logon / process rows, PowerShell 4104 / 4103 and BITS rows" -Passed ($problems.Count -eq 0) -Message ($problems -join "; ")
}
finally {
    Remove-Item -LiteralPath $dispatchDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Get-EvtxEventsById on a damaged .evtx: one warning, not one per query
# group, and no further queries once a -State hashtable records the failure
$damagedEvtx = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx-damaged-" + [guid]::NewGuid().ToString("N") + ".evtx")
try {
    [System.IO.File]::WriteAllBytes($damagedEvtx, [byte[]](@(0x45) * 4096))
    $logBefore = if (Test-Path -LiteralPath $logFile) { @(Get-Content -LiteralPath $logFile).Count } else { 0 }
    $readState = @{ Failed = $false }
    $found = @(Get-EvtxEventsById -Path $damagedEvtx -Ids (1..45) -Label "test" -State $readState)
    $found += @(Get-EvtxEventsById -Path $damagedEvtx -Ids (1..5) -Providers $script:ThirdPartyAvProviders -Label "test" -State $readState)
    $warnings = @(Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue | Select-Object -Skip $logBefore | Where-Object { $_ -match "Error reading" })
    Write-TestResult -Name "Get-EvtxEventsById reports a damaged .evtx once" -Passed ($found.Count -eq 0 -and $warnings.Count -eq 1 -and $readState.Failed) `
        -Message "$($found.Count) event(s), Failed=$($readState.Failed), $($warnings.Count) warning(s): $($warnings -join '; ')"
}
finally {
    Remove-Item -LiteralPath $damagedEvtx -Force -ErrorAction SilentlyContinue
}

# Get-EvtxEventsById on a real (empty) .evtx: more IDs and providers than one
# event log XPath query takes must be read in groups, not fail
$emptyEvtx = Join-Path ([System.IO.Path]::GetTempPath()) ("evtx-empty-" + [guid]::NewGuid().ToString("N") + ".evtx")
try {
    $null = & wevtutil.exe epl Application $emptyEvtx "/q:*[System[EventRecordID=0]]" 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $emptyEvtx)) {
        # Reading the Application log can be restricted for standard users
        Write-Host "SKIP: Get-EvtxEventsById query groups (could not export an empty .evtx with wevtutil)" -ForegroundColor Yellow
    }
    else {
        $logBefore = if (Test-Path -LiteralPath $logFile) { @(Get-Content -LiteralPath $logFile).Count } else { 0 }
        $found = @(Get-EvtxEventsById -Path $emptyEvtx -Ids (1..45) -Label "test")
        $found += @(Get-EvtxEventsById -Path $emptyEvtx -Ids (1..30) -Providers $script:ThirdPartyAvProviders -Label "test")
        $found += @(Get-EvtxEventsById -Path $emptyEvtx -Providers $script:ThirdPartyAvProviders -Label "test")
        $warnings = @(Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue | Select-Object -Skip $logBefore | Where-Object { $_ -match "Error reading" })
        Write-TestResult -Name "Get-EvtxEventsById reads long ID / provider lists in valid query groups" -Passed ($found.Count -eq 0 -and $warnings.Count -eq 0) -Message "$($found.Count) event(s), warnings: $($warnings -join '; ')"
    }
}
finally {
    Remove-Item -LiteralPath $emptyEvtx -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $logFile -Force -ErrorAction SilentlyContinue
}

# =============================================================
# Part 2: system test (real events)
# =============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $env:GITHUB_ACTIONS -and -not $AllowSystemChanges) {
    Write-Host ""
    Write-Host "SKIPPED: Part 2 (system test). It changes this machine (audit policy, a temporary user, task, service and event log;"
    Write-Host "         the event records it produces stay in the Security and System logs) and runs only in GitHub Actions"
    Write-Host "         or with -AllowSystemChanges (as Administrator)."
}
elseif (-not $isAdmin) {
    Write-TestResult -Name "Part 2 system test" -Passed $false -Message "needs Administrator rights (run elevated, or let GitHub Actions run it)"
}
else {
    Write-Host ""
    Write-Host "Part 2: real events on this machine"
    $tag = "TLT" + (Get-Random -Minimum 100000 -Maximum 999999)
    $userName = "tlt" + $tag.Substring(3)
    $taskName = "TimelineTest-$tag"
    $serviceName = "TimelineTest$tag"
    $classicLog = "TLTest" + $tag.Substring(3, 2)
    $classicSource = "TimelineTestSource$tag"
    $avSource = "Sophos Anti-Virus"
    $createdAvSource = $false
    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-evtx-test-" + [guid]::NewGuid().ToString("N"))
    $collection = Join-Path $workDir "collection"
    $auditBackup = Join-Path $workDir "auditpol-backup.csv"
    $reportsDir = Join-Path $repoRoot "reports"
    $reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
    # Event Log Readers: a local group a new user is not already in
    $groupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-573")).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $applicationSources = @{}
    $generated = $false
    $keepWorkDir = $false
    New-Item -ItemType Directory -Path (Join-Path $collection "EventLogs") -Force | Out-Null
    try {
        # Security events need these audit subcategories (GUIDs: language
        # independent). Each change logs 4719; User Account Management is
        # turned off first so that it changes even if it was already on.
        $null = & auditpol.exe /backup "/file:$auditBackup"
        if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed" }
        if ($env:GITHUB_ACTIONS) {
            # Event 1102. Only on CI runners: never clear a real machine's Security log
            $null = & wevtutil.exe cl Security
            if ($LASTEXITCODE -ne 0) { throw "wevtutil cl Security failed" }
        }
        $null = & auditpol.exe /set "/subcategory:{0CCE9235-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
        $subcategories = @(
            "{0CCE9235-69AE-11D9-BED3-505054503030}",   # User Account Management
            "{0CCE9237-69AE-11D9-BED3-505054503030}",   # Security Group Management
            "{0CCE9227-69AE-11D9-BED3-505054503030}",   # Other Object Access Events (tasks)
            "{0CCE9211-69AE-11D9-BED3-505054503030}"    # Security System Extension (4697)
        )
        foreach ($guid in $subcategories) {
            $null = & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable
            if ($LASTEXITCODE -ne 0) { throw "auditpol /set $guid failed" }
        }

        # Local user: created (4720), added to a group (4732), password reset (4724), deleted (4726)
        $chars = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        $passwordText = "Tl#" + (-join (1..16 | ForEach-Object { $chars | Get-Random })) + "9a!"
        $user = $computer.Create("User", $userName)
        $user.SetPassword($passwordText)
        $user.SetInfo()
        ([ADSI]"WinNT://$env:COMPUTERNAME/$groupName,group").Add("WinNT://$env:COMPUTERNAME/$userName,user")
        $user.SetPassword($passwordText + "x")
        $passwordText = $null
        $computer.Delete("User", $userName)

        # Scheduled task: created (4698), updated (4702), disabled (4701), enabled (4700), deleted (4699)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -ErrorAction Stop
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(30) -ErrorAction Stop
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo $tag" -ErrorAction Stop
        $null = Register-ScheduledTask -TaskName $taskName -TaskPath "\" -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop
        $null = Set-ScheduledTask -TaskName $taskName -TaskPath "\" -Action (New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo $tag updated") -ErrorAction Stop
        $null = Disable-ScheduledTask -TaskName $taskName -TaskPath "\" -ErrorAction Stop
        $null = Enable-ScheduledTask -TaskName $taskName -TaskPath "\" -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $taskName -TaskPath "\" -Confirm:$false -ErrorAction Stop

        # Service: installed (System 7045, Security 4697), start type changed (7040), deleted
        $null = New-Service -Name $serviceName -BinaryPathName "C:\Windows\System32\cmd.exe /c echo $tag" -StartupType Manual -ErrorAction Stop
        Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
        $null = & sc.exe delete $serviceName

        # Classic event log written to and cleared: System 104
        [System.Diagnostics.EventLog]::CreateEventSource($classicSource, $classicLog)
        [System.Diagnostics.EventLog]::WriteEntry($classicSource, "timeline test entry $tag", [System.Diagnostics.EventLogEntryType]::Information, 1)
        $null = & wevtutil.exe cl $classicLog
        if ($LASTEXITCODE -ne 0) { throw "wevtutil cl $classicLog failed" }

        # Application events from the real sources (where they exist on this
        # machine). Only on CI runners: on a workstation these synthetic
        # records (an ntds.dit attach, antivirus OFF, a crash, an install)
        # would stay in its Application log and read as real findings later.
        $appEvents = @()
        if ($env:GITHUB_ACTIONS) {
            $appEvents = @(
                @{ Source = "MsiInstaller"; Id = 1033; Type = "Information"; Values = @("TimelineTest Product $tag", "1.2.3", "1033", "0", "TimelineTest Corp") },
                @{ Source = "Application Error"; Id = 1000; Type = "Error"; Values = @("tlt$tag.exe", "1.0.0.0", "5f000000", "tltmod.dll", "2.0.0.0", "5f000001", "c0000005", "0000000000001234", "0x10", "0x1d7", "C:\TimelineTest\tlt$tag.exe", "C:\TimelineTest\tltmod.dll", "00000000-0000-0000-0000-000000000000") },
                @{ Source = "ESENT"; Id = 326; Type = "Information"; Values = @("TimelineTest", "4321,D,0,0", "", "1", "C:\TimelineTest$tag\ntds.dit", "0", "[1] 0.0", "0 0", "dbv = 1") },
                @{ Source = "SecurityCenter"; Id = 15; Type = "Information"; Values = @("TimelineTest AV $tag", "SECURITY_PRODUCT_STATE_OFF") }
            )
            if (-not [System.Diagnostics.EventLog]::SourceExists($avSource)) {
                [System.Diagnostics.EventLog]::CreateEventSource($avSource, "Application")
                $createdAvSource = $true
                $appEvents += @{ Source = $avSource; Id = 32; Type = "Warning"; Values = @("TimelineTest virus found $tag") }
            }
        }
        else {
            Write-Host "  (synthetic Application events are written only in GitHub Actions: their rows are not checked here)"
        }
        foreach ($e in $appEvents) {
            if (-not [System.Diagnostics.EventLog]::SourceExists($e.Source)) {
                Write-Host "  (source '$($e.Source)' does not exist here: its row is not checked)"
                continue
            }
            $instance = New-Object System.Diagnostics.EventInstance([long]$e.Id, 0, [System.Diagnostics.EventLogEntryType]$e.Type)
            [System.Diagnostics.EventLog]::WriteEvent($e.Source, $instance, [object[]]$e.Values)
            $applicationSources[$e.Source] = $true
        }
        Start-Sleep -Seconds 2

        # Fixture collection: the three logs and collection metadata
        foreach ($log in @("Security", "System", "Application")) {
            $null = & wevtutil.exe epl $log (Join-Path $collection "EventLogs\$log.evtx")
            if ($LASTEXITCODE -ne 0) { throw "wevtutil epl $log failed" }
        }
        $tzId = [System.TimeZoneInfo]::Local.Id
        $info = [ordered]@{ SchemaVersion = 1; ComputerName = $env:COMPUTERNAME; Mode = "Live"; CollectionStartUtc = (Get-Date).ToUniversalTime().ToString("o")
            CollectorTimeZoneId = $tzId; CollectorCulture = "en-US"; TargetTimeZoneId = $tzId }
        $info | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $collection "collection_info.json") -Encoding ASCII
        $generated = $true
    }
    catch {
        Write-TestResult -Name "Part 2: generate events" -Passed $false -Message $_.Exception.Message
    }
    finally {
        # Undo every change that is still in place, whatever happened above
        try { $computer.Delete("User", $userName) } catch { Write-Verbose "No test user left to delete: $($_.Exception.Message)" }
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $taskName -TaskPath "\" -Confirm:$false }
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { $null = & sc.exe delete $serviceName }
        try { if ([System.Diagnostics.EventLog]::Exists($classicLog)) { [System.Diagnostics.EventLog]::Delete($classicLog) } } catch { Write-Verbose "Could not delete log ${classicLog}: $($_.Exception.Message)" }
        if ($createdAvSource) {
            try { [System.Diagnostics.EventLog]::DeleteEventSource($avSource) } catch { Write-Verbose "Could not delete source ${avSource}: $($_.Exception.Message)" }
        }
        if (Test-Path -LiteralPath $auditBackup) {
            $null = & auditpol.exe /restore "/file:$auditBackup"
            if ($LASTEXITCODE -ne 0) {
                $keepWorkDir = $true
                Write-TestResult -Name "Part 2: restore audit policy" -Passed $false -Message "auditpol /restore failed; restore it with: auditpol /restore /file:$auditBackup"
            }
        }
    }

    if ($generated) {
        $powershellExe = (Get-Process -Id $PID).Path
        $timelineCsv = Join-Path $workDir "timeline.csv"
        try {
            Write-Host "Running the builder ($powershellExe) on $collection ..."
            $builderOutput = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder -InputPath $collection -Sources "EventLogs" `
                -OutputFile $timelineCsv -NoExcel -Viewer None 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
                $builderOutput | ForEach-Object { Write-Host "  | $_" }
                Write-TestResult -Name "Part 2: builder run" -Passed $false -Message "the builder exited with code $LASTEXITCODE or wrote no timeline"
            }
            else {
                $rows = @(Import-Csv -LiteralPath $timelineCsv)
                $checks = @(
                    @("Security 4719 audit policy changed", "Security.evtx", "SecurityAlert", "System audit policy changed: Account Management\User Account Management (*", "*"),
                    @("Security 4720 user created", "Security.evtx", "AccountChange", "User account created: $userName", "NewAccount=*\$userName | AccountSID=S-1-5-21-*"),
                    # The event gives the local member's SID only: the name comes from the user's 4720 / 4724 / 4726
                    @("Security 4732 member added to a local group", "Security.evtx", "AccountChange", "Member added to security-enabled local group: $groupName (member *$userName*)", "*GroupSID=S-1-5-32-573 | Member=*$userName* | MemberSID=S-1-5-21-*"),
                    @("Security 4724 password reset", "Security.evtx", "AccountChange", "Password reset attempted for account: *\$userName", "*AccountSID=S-1-5-21-*"),
                    @("Security 4726 user deleted", "Security.evtx", "AccountChange", "User account deleted: $userName", "DeletedAccount=*\$userName | AccountSID=S-1-5-21-*"),
                    @("Security 4698 task registered", "Security.evtx", "ScheduledTaskChange", "Scheduled task registered: \$taskName", "*Command=cmd.exe | Arguments=/c echo $tag | RunAs=*"),
                    @("Security 4702 task updated", "Security.evtx", "ScheduledTaskChange", "Scheduled task updated: \$taskName", "*Arguments=/c echo $tag updated*"),
                    @("Security 4701 task disabled", "Security.evtx", "ScheduledTaskChange", "Scheduled task disabled: \$taskName", "*"),
                    @("Security 4700 task enabled", "Security.evtx", "ScheduledTaskChange", "Scheduled task enabled: \$taskName", "*"),
                    @("Security 4699 task deleted", "Security.evtx", "ScheduledTaskChange", "Scheduled task deleted: \$taskName", "*"),
                    @("Security 4697 service installed", "Security.evtx", "PersistenceChange", "New service installed: $serviceName", "*ImagePath=C:\Windows\System32\cmd.exe /c echo $tag | ServiceType=0x10 (own process) | StartType=3 (demand start)*"),
                    @("System 7045 service installed", "System.evtx", "PersistenceChange", "New service installed: $serviceName", "ImagePath=C:\Windows\System32\cmd.exe /c echo $tag | StartType=*"),
                    @("System 7040 start type changed", "System.evtx", "ServiceChange", "Service start type changed: $serviceName", "Service=$serviceName | OldType=* | NewType=disabled"),
                    @("System 104 event log cleared", "System.evtx", "SecurityAlert", "Event log cleared: $classicLog", "EventID=104 | Channel=$classicLog | ClearedBy=*")
                )
                if ($env:GITHUB_ACTIONS) { $checks += , @("Security 1102 audit log cleared", "Security.evtx", "SecurityAlert", "Security audit log cleared", "EventID=1102 | ClearedBy=*") }
                $bootEvents = @(Get-WinEvent -Path (Join-Path $collection "EventLogs\System.evtx") -FilterXPath "*[System[Provider[@Name='EventLog'] and EventID=6005]]" -MaxEvents 1 -ErrorAction SilentlyContinue)
                if ($bootEvents.Count -gt 0) { $checks += , @("System 6005 event log service started", "System.evtx", "ServiceChange", "Event log service started (system startup)", "EventID=6005") }
                if ($applicationSources["MsiInstaller"]) { $checks += , @("Application MsiInstaller 1033", "Application.evtx", "Installation", "Software installed: TimelineTest Product $tag 1.2.3", "*Manufacturer=TimelineTest Corp | Status=0 (success)*") }
                if ($applicationSources["Application Error"]) { $checks += , @("Application Error 1000", "Application.evtx", "Execution", "Application crashed: tlt$tag.exe (exception 0xc0000005 in tltmod.dll)", "*Path=C:\TimelineTest\tlt$tag.exe*") }
                if ($applicationSources["ESENT"]) { $checks += , @("Application ESENT 326", "Application.evtx", "FileAccess", "ESE database attached: C:\TimelineTest$tag\ntds.dit", "*Process=TimelineTest*") }
                if ($applicationSources["SecurityCenter"]) { $checks += , @("Application SecurityCenter 15", "Application.evtx", "SecurityAlert", "Security product state: TimelineTest AV $tag OFF", "*") }
                if ($applicationSources[$avSource]) { $checks += , @("Application third-party antivirus", "Application.evtx", "SecurityAlert", "Antivirus event ($avSource 32): *$tag*", "*Level=Warning*") }
                foreach ($check in $checks) {
                    $match = @($rows | Where-Object { $_.Source -eq $check[1] -and $_.EventType -eq $check[2] -and $_.Description -like $check[3] -and $_.Details -like $check[4] })
                    $near = @($rows | Where-Object { $_.Description -like "*$tag*" -or $_.Description -like "*$userName*" -or $_.Description -like "*$classicLog*" } | ForEach-Object { "$($_.Description) | $($_.Details)" })
                    Write-TestResult -Name "Part 2: $($check[0])" -Passed ($match.Count -gt 0) -Message "no row like '$($check[3])' / '$($check[4])'. Rows of this test: $($near -join ' || ')"
                }
                # User column: the account that created the user is a local
                # account of this machine, so its computer name is dropped.
                # The collection has no SYSTEM hive: the name comes from
                # collection_info.json (a live collection).
                $createdRows = @($rows | Where-Object { $_.Source -eq "Security.evtx" -and $_.Description -eq "User account created: $userName" })
                Write-TestResult -Name "Part 2: User column (local account without the computer name of collection_info.json)" `
                    -Passed ($createdRows.Count -gt 0 -and $createdRows[0].User -eq $env:USERNAME) -Message "User '$(@($createdRows | ForEach-Object { $_.User }) -join "', '")', expected '$env:USERNAME'"
            }
        }
        finally {
            Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $reportsBefore -notcontains $_.FullName } |
                ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    if (-not $keepWorkDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
if ($script:failures -gt 0) {
    Write-Host "FAILED: $($script:failures) check(s)" -ForegroundColor Red
    exit 1
}
Write-Host "All event log parser checks passed" -ForegroundColor Green
exit 0
