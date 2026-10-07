# =============================================================
# Event log parser tests (Security, System, Defender, Application)
#
# Part 1 -- unit checks (no admin, always run): loads the builder's
#   functions without running it and feeds the event log handlers
#   synthetic event records (our own XML), checking every row they add.
# Part 2 -- system test (needs Administrator; runs only in GitHub Actions
#   or with -AllowSystemChanges): generates real events on this machine
#   (audit policy, a temporary local user and group membership, a
#   temporary scheduled task and service, a temporary classic event log
#   that is cleared, Application events), exports Security, System and
#   Application with wevtutil into a fixture collection, runs the builder
#   (-Sources EventLogs) and checks the expected rows by pattern. Every
#   change is undone in a finally block. In GitHub Actions only, the
#   Security log is cleared first (event 1102).
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
    "ServiceTypeNames", "ServiceStartTypeNames", "AsrRuleNames", "ThirdPartyAvProviders")
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
        Details = "EventID=4697 | ServiceName=TestSvc | ServiceFileName=C:\Temp\svc.exe -k run | ServiceType=0x10 (own process) | StartType=3 (demand start) | Account=LocalSystem | ClientProcessId=4242" }
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
Test-Case -Name "Security 4698-4702 scheduled task events (action from TaskContent)" -Action {
    $events = @(
        @(4698, "TaskContent", $taskXml),
        @(4702, "TaskContentNew", $comTaskXml),
        @(4701, "TaskContent", "<not xml"),
        @(4700, "TaskContent", ""),
        @(4699, "TaskContent", $taskXml)
    )
    $minute = 3
    foreach ($e in $events) {
        $data = Join-Subject ([ordered]@{ TaskName = "\TestTask" })
        $data[$e[1]] = $e[2]
        Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id $e[0] -Time "2026-01-02 10:0$($minute):00" -Body (New-EventDataXml -Data $data)) -FileName $sec -FilePath $secPath
        $minute++
    }
} -Expected @(
    @{ EventType = "ScheduledTaskChange"; Description = "Scheduled task created: \TestTask"; User = "TESTHOST\alice"
        Details = "EventID=4698 | TaskName=\TestTask | Command=C:\Windows\System32\cmd.exe | Arguments=/c echo timeline-test > C:\Temp\out.txt | RunAs=S-1-5-18" },
    @{ EventType = "ScheduledTaskChange"; Description = "Scheduled task updated: \TestTask"; Details = "EventID=4702 | TaskName=\TestTask | ComHandler={11111111-2222-3333-4444-555555555555} | RunAs=S-1-5-32-545" },
    @{ Description = "Scheduled task disabled: \TestTask"; Details = "EventID=4701 | TaskName=\TestTask" },
    @{ Description = "Scheduled task enabled: \TestTask"; Details = "EventID=4700 | TaskName=\TestTask" },
    @{ Description = "Scheduled task deleted: \TestTask"; Details = "EventID=4699 | TaskName=\TestTask | Command=C:\Windows\System32\cmd.exe | Arguments=/c echo timeline-test > C:\Temp\out.txt | RunAs=S-1-5-18" }
)

Test-Case -Name "Security 4732/4728/4756 member added to a group (group SID kept)" -Action {
    $groups = @(
        @(4732, "-", "Administrators", "Builtin", "S-1-5-32-544"),
        @(4728, "CN=Bob,CN=Users,DC=test,DC=local", "Domain Admins", "TEST", "S-1-5-21-9-9-9-512"),
        @(4756, "CN=Bob,CN=Users,DC=test,DC=local", "Enterprise Admins", "TEST", "S-1-5-21-9-9-9-519")
    )
    foreach ($g in $groups) {
        $data = [ordered]@{ MemberName = $g[1]; MemberSid = "S-1-5-21-1111-2222-3333-1002"; TargetUserName = $g[2]; TargetDomainName = $g[3]; TargetSid = $g[4] }
        foreach ($key in $alice.Keys) { $data[$key] = $alice[$key] }
        $data["PrivilegeList"] = "-"
        Add-SecurityEventEntry -Record (New-TestRecord -Provider $auditing -Id $g[0] -Time "2026-01-02 10:10:00" -Body (New-EventDataXml -Data $data)) -FileName $sec -FilePath $secPath
    }
} -Expected @(
    @{ EventType = "AccountChange"; Description = "Member added to security-enabled local group: Administrators"; User = "TESTHOST\alice"
        Details = "EventID=4732 | Group=Builtin\Administrators | GroupSID=S-1-5-32-544 | MemberSID=S-1-5-21-1111-2222-3333-1002" },
    @{ EventType = "AccountChange"; Description = "Member added to security-enabled global group: Domain Admins"
        Details = "EventID=4728 | Group=TEST\Domain Admins | GroupSID=S-1-5-21-9-9-9-512 | Member=CN=Bob,CN=Users,DC=test,DC=local | MemberSID=S-1-5-21-1111-2222-3333-1002" },
    @{ Description = "Member added to security-enabled universal group: Enterprise Admins" }
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
    @{ EventType = "AccountChange"; Description = "User account locked out: bob"; User = "WORKGROUP\TESTHOST$"
        Details = "EventID=4740 | Account=bob | AccountSID=S-1-5-21-1111-2222-3333-1002 | CallerComputer=WKS-07" }
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
Test-Case -Name "Defender 1013 history deleted, 1121/1122 ASR rule blocked / audited" -Action {
    $history = [ordered]@{ "Product Name" = "Microsoft Defender Antivirus"; "Product Version" = "4.18.1.1"; Timestamp = "2026-01-01T00:00:00Z"; Unused = ""; Unused2 = ""; Unused3 = ""; Unused4 = ""; Domain = "TESTHOST"; User = "alice"; SID = "S-1-5-21-1111-2222-3333-1001" }
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1013 -Time "2026-01-02 12:00:00" -Body (New-EventDataXml -Data $history)) -FileName $def -FilePath "X:\def.evtx"
    $asr = [ordered]@{ "Product Name" = "Microsoft Defender Antivirus"; "Product Version" = "4.18.1.1"; Unused = ""; ID = "{D4F940AB-401B-4EFC-AADC-AD5F3C50688A}"; "Detection Time" = "2026-01-02T12:01:00.000Z"
        User = "TESTHOST\alice"; Path = "C:\Windows\System32\cmd.exe"; "Process Name" = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"; "Security intelligence Version" = "1.1"; "Engine Version" = "1.1"; RuleType = "0"
        "Target Commandline" = "cmd.exe /c echo test"; "Parent Commandline" = "WINWORD.EXE /n C:\Users\alice\Downloads\doc.docm"; "Involved File" = ""; "Inhertiance Flags" = "0" }
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1121 -Time "2026-01-02 12:01:00" -Body (New-EventDataXml -Data $asr)) -FileName $def -FilePath "X:\def.evtx"
    $asr["ID"] = "00000000-1111-2222-3333-444444444444"
    Add-DefenderEventEntry -Record (New-TestRecord -Provider $defender -Id 1122 -Time "2026-01-02 12:02:00" -Body (New-EventDataXml -Data $asr)) -FileName $def -FilePath "X:\def.evtx"
} -Expected @(
    @{ EventType = "SecurityAlert"; Description = "Defender malware detection history deleted"; User = "TESTHOST\alice"
        Details = "EventID=1013 | DeletedBefore=2026-01-01T00:00:00Z | DeletedBy=TESTHOST\alice | SID=S-1-5-21-1111-2222-3333-1001" },
    @{ EventType = "SecurityAlert"; Description = "Defender attack surface reduction rule blocked: Block all Office applications from creating child processes"; User = "TESTHOST\alice"
        Details = "EventID=1121 | RuleID=D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Path=C:\Windows\System32\cmd.exe | Process=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE | TargetCommandline=cmd.exe /c echo test | ParentCommandline=WINWORD.EXE /n C:\Users\alice\Downloads\doc.docm" },
    @{ Description = "Defender attack surface reduction rule audited: 00000000-1111-2222-3333-444444444444" }
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
        (New-TestRecord -Provider "Some Other Provider" -Id 1000 -Time "2026-01-03 12:02:00")
    )
    Add-ApplicationEventEntries -Records $records -FileName $app -FilePath "X:\Application.evtx"
} -Expected @(
    @{ Timestamp = "2026-01-03 09:00:00.000"; EventType = "Installation"; Description = "Software installed: Test Product 1.2.3"; User = ""
        Details = "EventID=1033 | Product=Test Product | Version=1.2.3 | Manufacturer=Test Corp | Status=0 (success) | ProductCode=$productCode | UserSID=S-1-5-21-1111-2222-3333-1001" },
    @{ EventType = "Installation"; Description = "Software installed: Lone Product"; Details = "EventID=11707 | Product=Lone Product | Message=Product: Lone Product -- Installation completed successfully." },
    @{ EventType = "Installation"; Description = "Software removal failed: Old Product 2.0 (status 1603)"; Details = "EventID=1034 | Product=Old Product | Version=2.0 | Manufacturer=Old Corp | Status=1603 (fatal error) | UserSID=S-1-5-18" },
    @{ EventType = "Execution"; Description = "Application crashed: badapp.exe (exception 0xc0000005 in badmod.dll)"
        Details = "EventID=1000 | Application=badapp.exe | Version=1.0.0.0 | Module=badmod.dll | ModuleVersion=2.0.0.0 | ExceptionCode=0xc0000005 | FaultOffset=0x0000000000001234 | Path=C:\Users\bob\AppData\Local\Temp\badapp.exe | ModulePath=C:\Users\bob\AppData\Local\Temp\badmod.dll" },
    @{ EventType = "Execution"; Description = "Application crashed: oldapp.exe (exception 0xc0000409 in oldmod.dll)"
        Details = "EventID=1000 | Application=oldapp.exe | Version=1.0.0.0 | Module=oldmod.dll | ModuleVersion=2.0.0.0 | ExceptionCode=0xc0000409 | FaultOffset=0x0000000000004321 | Path=C:\Apps\oldapp.exe | ModulePath=C:\Apps\oldmod.dll" },
    @{ EventType = "Execution"; Description = "Application hung and was closed: slowapp.exe"; Details = "EventID=1002 | Application=slowapp.exe | Version=3.1 | Path=C:\Apps\slowapp.exe | HangType=Quiesce" },
    @{ Timestamp = "2026-01-03 10:00:00.000"; EventType = "SecurityAlert"; Description = "Security product state: Test AV ON"; Details = "EventID=15 | Product=Test AV | State=ON" },
    @{ Timestamp = "2026-01-03 10:10:00.000"; EventType = "SecurityAlert"; Description = "Security product state: Test AV OFF"; Details = "EventID=15 | Product=Test AV | State=OFF | PreviousState=ON" },
    @{ EventType = "SecurityAlert"; Description = "Security Center could not update product state: Test AV SNOOZED"; Details = "EventID=16 | Product=Test AV | State=SNOOZED" },
    @{ EventType = "FileAccess"; Description = "ESE database created: C:\Temp\copy\ntds.dit"; Details = "EventID=325 | Database=C:\Temp\copy\ntds.dit | Process=TestProc | ProcessId=4321 | Instance=TestInstance" },
    @{ EventType = "FileAccess"; Description = "ESE database attached: C:\Temp\copy\ntds.dit"; Details = "EventID=326 | Database=C:\Temp\copy\ntds.dit | Process=TestProc | ProcessId=4321" },
    @{ EventType = "FileAccess"; Description = "ESE database detached: C:\Temp\copy\ntds.dit" },
    @{ EventType = "FileAccess"; Description = "ESE database location changed: C:\Windows\NTDS\ntds.dit -> D:\Restore\ntds.dit"
        Details = "EventID=216 | OldPath=C:\Windows\NTDS\ntds.dit | NewPath=D:\Restore\ntds.dit | Process=lsass | ProcessId=600 | Instance=NTDSA" },
    @{ EventType = "SecurityAlert"; Description = "Antivirus event (Sophos Anti-Virus 6): Virus 'Test-Virus' found | C:\Users\bob\x.exe"
        Details = "EventID=6 | Provider=Sophos Anti-Virus | Level=Error | Message=Virus 'Test-Virus' found | C:\Users\bob\x.exe" },
    @{ EventType = "SecurityAlert"; Description = "Antivirus event (McLogEvent 258): " + ("$longText second line").Substring(0, 200) + "..."
        Details = "EventID=258 | Provider=McLogEvent | Level=Warning | Message=$longText second line | UserSID=S-1-5-18" }
)

Test-Case -Name "Helpers: unknown codes kept as text" -Action {
    $checks = @(
        @((Format-EvtxCodeText -Text "0x120" -Names $script:ServiceTypeNames), "0x120 (interactive share process)"),
        @((Format-EvtxCodeText -Text "0x400" -Names $script:ServiceTypeNames), "0x400"),
        @((Format-EvtxCodeText -Text "auto" -Names $script:ServiceStartTypeNames), "auto"),
        @((ConvertFrom-AuditPolicyText -Text "%%8272, %%99999, text"), "System, %%99999, text"),
        @((Join-EvtxAccountName -Domain "-" -Name "bob"), "bob")
    )
    foreach ($check in $checks) {
        if ($check[0] -cne $check[1]) { throw "got '$($check[0])', expected '$($check[1])'" }
    }
} -Expected @()

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
    Write-Host "SKIPPED: Part 2 (system test). It changes this machine (audit policy, a temporary user, task, service and event log)"
    Write-Host "         and runs only in GitHub Actions or with -AllowSystemChanges (as Administrator)."
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

        # Application events from the real sources (where they exist on this machine)
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
                    @("Security 4720 user created", "Security.evtx", "AccountChange", "User account created: $userName", "*"),
                    @("Security 4732 member added to a local group", "Security.evtx", "AccountChange", "Member added to security-enabled local group: $groupName", "*GroupSID=S-1-5-32-573 | MemberSID=S-1-5-21-*"),
                    @("Security 4724 password reset", "Security.evtx", "AccountChange", "Password reset attempted for account: *\$userName", "*AccountSID=S-1-5-21-*"),
                    @("Security 4726 user deleted", "Security.evtx", "AccountChange", "User account deleted: $userName", "*"),
                    @("Security 4698 task created", "Security.evtx", "ScheduledTaskChange", "Scheduled task created: \$taskName", "*Command=cmd.exe | Arguments=/c echo $tag | RunAs=*"),
                    @("Security 4702 task updated", "Security.evtx", "ScheduledTaskChange", "Scheduled task updated: \$taskName", "*Arguments=/c echo $tag updated*"),
                    @("Security 4701 task disabled", "Security.evtx", "ScheduledTaskChange", "Scheduled task disabled: \$taskName", "*"),
                    @("Security 4700 task enabled", "Security.evtx", "ScheduledTaskChange", "Scheduled task enabled: \$taskName", "*"),
                    @("Security 4699 task deleted", "Security.evtx", "ScheduledTaskChange", "Scheduled task deleted: \$taskName", "*"),
                    @("Security 4697 service installed", "Security.evtx", "PersistenceChange", "New service installed: $serviceName", "*ServiceFileName=C:\Windows\System32\cmd.exe /c echo $tag | ServiceType=0x10 (own process) | StartType=3 (demand start)*"),
                    @("System 7045 service installed", "System.evtx", "PersistenceChange", "New service installed: $serviceName", "*"),
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
