# =============================================================
# Report engine test (Phase 3)
# Loads report\TimelineReport.Engine.ps1 and checks it on the synthetic
# fixtures in tests\fixtures\report\engine\ (rules.json, timeline.csv,
# collection_info.json, collection_log.txt, timeline_builder_log.txt):
#   - every rule feature: match / anyOf / not* conditions, lists, groupBy
#     (rule, description, user, source, capture and detail:<Key> with both
#     Details styles), threshold windows, escalate with sameKey, allowlist
#     (per rule and "*", duringCollection), disabled rules, numbering and
#     ordering, evidence caps and Excel row numbers, maxFindings roll-ups,
#     activityTime, and the stop of a rule whose pattern keeps timing out;
#   - leads from during the collection: DuringCollection (event times),
#     CapturedDuringCollection (Snapshot rows) and MemoryOnly (every row
#     from the memory dump: "Captured in the memory dump" in MemoryOnlyNote,
#     findings.csv and report-model.json, with its rows' numbers);
#   - invalid rules files fail with an error that names the rule and field;
#   - {{list:...}} is expanded in the C# helper (a synthetic list of
#     harmless words, used several times) and fails closed: a blocked call,
#     no regex or an empty one is a rules-file error; the shipped rules
#     import with no error and no empty condition;
#   - the report model: coverage per source, log clears, boots, audit notes,
#     collector errors and warnings, activity per day / hour / source / user
#     (accounts as the User column names them, unnamed service SIDs, file
#     times), caveats (assumed time zone, stale workbook, mounted image), the
#     examined computer of a mounted image, an incomplete builder run (exit
#     code 2), a memory dump the builder did not analyze (its log line in
#     Coverage.Notes and a caveat), top findings (one per rule first), the
#     lead window, rule titles, file hashes;
#   - findings.csv, report-model.json and Import-TimelineCsvForReport
#     (fields with line breaks, quotes and commas).
# Needs no Administrator rights and does not run the builder.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ReportEngine.ps1
#   pwsh -File tests\Test-ReportEngine.ps1
# =============================================================

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$fixtureDir = Join-Path $PSScriptRoot "fixtures\report\engine"
$script:failures = 0
$script:checks = 0

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    $script:checks++
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-ReportEngine.ps1::$Message" }
}

# Compares two values as text (case-sensitive) and reports the result
function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    $ok = "$Actual" -ceq "$Expected"
    $detail = if ($ok) { "" } else { " (expected '$Expected', got '$Actual')" }
    Write-TestResult -Succeeded $ok -Message "$Message$detail"
}

# "yyyy-MM-dd HH:mm:ss" of a UTC [datetime], or "" for $null
function Format-TestUtc {
    param($Value)
    if ($null -eq $Value) { return "" }
    return $Value.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Writes a text file (UTF-8, no BOM)
function New-TestTextFile {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

. (Join-Path $repoRoot "report\TimelineReport.Engine.ps1")

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("report-engine-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    $timelinePath = Join-Path $fixtureDir "timeline.csv"
    $columns = @("Timestamp", "Source", "EventType", "Description", "User", "Details", "Artifact", "RawPath")
    # Reference rows, read independently with Import-Csv
    $expectedRows = @(Import-Csv -LiteralPath $timelinePath)
    # Excel row number of a fixture row by its time (every time is unique)
    $rowOf = @{}
    for ($i = 0; $i -lt $expectedRows.Count; $i++) { $rowOf[$expectedRows[$i].Timestamp.Substring(0, 19)] = $i + 2 }

    # =========================================================
    # Import-TimelineCsvForReport
    # =========================================================
    $rows = @(Import-TimelineCsvForReport -Path $timelinePath)
    Assert-Equal $rows.Count 69 -Message "Import-TimelineCsvForReport reads all 69 rows (one field holds a line break)"
    Assert-Equal $expectedRows.Count 69 -Message "Import-Csv reads the same 69 rows"
    Assert-Equal ($rows[0].PSObject.Properties.Name -join ",") ($columns -join ",") -Message "rows have the CSV's columns in order"
    $mismatches = 0
    for ($i = 0; $i -lt [Math]::Min($rows.Count, $expectedRows.Count); $i++) {
        foreach ($column in $columns) {
            # Import-Csv may turn the CRLF inside a quoted field into LF
            if (($rows[$i].$column -replace "`r`n", "`n") -cne ($expectedRows[$i].$column -replace "`r`n", "`n")) { $mismatches++ }
        }
    }
    Assert-Equal $mismatches 0 -Message "every field matches Import-Csv"
    Assert-Equal ($rows[$rowOf["2026-03-09 08:30:00"] - 2].Details -ceq "Privileges=SeTcbPrivilege`r`nSeDebugPrivilege") "True" -Message "a quoted field keeps its line break (CRLF)"
    Assert-Equal $rows[$rowOf["2026-03-09 12:00:00"] - 2].Description 'Run key last written: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (value: "Updater, beta")' -Message "doubled quotes and a comma inside a quoted field"
    Assert-Equal $rows[$rowOf["2026-03-10 07:05:01"] - 2].Details "" -Message "an empty quoted field is empty"

    # Edge cases: LF line ends, no final line break, unquoted fields, missing
    # trailing fields, a header-only file and a file that is not a timeline
    $edgeCsv = Join-Path $workDir "edge.csv"
    New-TestTextFile $edgeCsv ("Timestamp,Source,EventType,Description,User,Details`n" +
        "2026-01-01 00:00:00.000,S1,E1,""multi`nline"",u1,d1`n`n" +
        "2026-01-01 00:00:01.000,S2,E2,plain text,u2`n" +
        "2026-01-01 00:00:02.000,S3,E3,""say """"hi"""""",,last")
    $edgeRows = @(Import-TimelineCsvForReport -Path $edgeCsv)
    Assert-Equal $edgeRows.Count 3 -Message "LF-only CSV: 3 rows (a blank line is skipped)"
    Assert-Equal ($edgeRows[0].Description -ceq "multi`nline") "True" -Message "LF-only CSV: a quoted field keeps its LF"
    Assert-Equal ($null -eq $edgeRows[1].Details) "True" -Message "a row with fewer fields gets `$null for the missing ones (like Import-Csv)"
    Assert-Equal $edgeRows[2].Description 'say "hi"' -Message "last line without a line break, with doubled quotes"
    Assert-Equal $edgeRows[2].Details "last" -Message "the last field of a file without a final line break"
    New-TestTextFile (Join-Path $workDir "header-only.csv") "Timestamp,Source,EventType,Description`r`n"
    Assert-Equal @(Import-TimelineCsvForReport -Path (Join-Path $workDir "header-only.csv")).Count 0 -Message "a header-only CSV has no rows"
    New-TestTextFile (Join-Path $workDir "not-timeline.csv") "Name,Value`r`na,b`r`n"
    $message = ""
    try { $null = Import-TimelineCsvForReport -Path (Join-Path $workDir "not-timeline.csv") } catch { $message = $_.Exception.Message }
    Write-TestResult -Succeeded ($message -match 'Not a timeline CSV') -Message "a CSV without the timeline columns is refused ($message)"

    # =========================================================
    # Details parser (both styles)
    # =========================================================
    $detailCases = @(
        @("LogonType=5 Source=-:-", "Source", "-:-"),
        @("FailureReason=0xc000006a Source=10.0.0.5 | Occurrences=3", "Source", "10.0.0.5"),
        @("FailureReason=0xc000006a Source=10.0.0.5 | Occurrences=3", "FailureReason", "0xc000006a"),
        @("FailureReason=0xc000006a Source=10.0.0.5 | Occurrences=3", "Occurrences", "3"),
        @("LogonType=3 | Source=10.0.0.5:0 | IpAddress=10.0.0.5", "ipaddress", "10.0.0.5"),
        @("LogonType=3 | Source=10.0.0.5:0 | IpAddress=10.0.0.5", "Source", "10.0.0.5:0"),
        @("Publisher=CN=Contoso, O=Contoso Ltd, L=Redmond, C=US Version=1.0 Source=AppxPackage", "Publisher", "CN=Contoso, O=Contoso Ltd, L=Redmond, C=US"),
        @("Publisher=CN=Contoso, O=Contoso Ltd, L=Redmond, C=US Version=1.0 Source=AppxPackage", "Version", "1.0"),
        @("Time=file last-modified time (NOT an execution time); CachePosition=7 of 1024", "Time", "file last-modified time (NOT an execution time)"),
        @("Time=file last-modified time (NOT an execution time); CachePosition=7 of 1024", "CachePosition", "7 of 1024"),
        @("Reason=File delete | Close | Occurrences=2", "Reason", "File delete | Close"),
        @("Path=C:\a b\c.exe Publisher= Version=1.0.0.0 SHA1=abc LinkDate(PE compile time)=03/10/2055 20:52:47 Time=registry key last write", "Path", "C:\a b\c.exe"),
        @("Path=C:\a b\c.exe Publisher= Version=1.0.0.0 SHA1=abc LinkDate(PE compile time)=03/10/2055 20:52:47 Time=registry key last write", "SHA1", "abc"),
        @("Path=C:\a b\c.exe Publisher= Version=1.0.0.0 SHA1=abc LinkDate(PE compile time)=03/10/2055 20:52:47 Time=registry key last write", "LinkDate(PE compile time)", "03/10/2055 20:52:47"),
        @("Path=C:\a b\c.exe Publisher= Version=1.0.0.0 SHA1=abc LinkDate(PE compile time)=03/10/2055 20:52:47 Time=registry key last write", "Publisher", ""),
        @("ScriptBlock=Get-Process | Select-Object Name Path=abc", "ScriptBlock", "Get-Process | Select-Object Name"),
        @("ScriptBlock=Get-Process | Select-Object Name Path=abc", "Path", "abc"),
        @("Command=cmd /c a | b | Key=HKLM\Run", "Command", "cmd /c a | b"),
        @("Command=cmd /c a | b | Key=HKLM\Run", "Key", "HKLM\Run"),
        @("Command=x | Key=y", "Missing", ""),
        # The User column pass appends " | UserSID=<sid>" to space-separated
        # Details (4104 script blocks): the pair does not switch the row to
        # " | " style, so the space-separated keys are still read
        @("ScriptBlock=Get-ChildItem C:\Users ScriptBlockId=0f1e Path=C:\Users\Public\stage.ps1 | UserSID=S-1-5-21-1-2-3-1001", "Path", "C:\Users\Public\stage.ps1"),
        @("ScriptBlock=Get-ChildItem C:\Users ScriptBlockId=0f1e Path=C:\Users\Public\stage.ps1 | UserSID=S-1-5-21-1-2-3-1001", "ScriptBlockId", "0f1e"),
        @("ScriptBlock=Get-ChildItem C:\Users ScriptBlockId=0f1e Path=C:\Users\Public\stage.ps1 | UserSID=S-1-5-21-1-2-3-1001", "UserSID", "S-1-5-21-1-2-3-1001"),
        @("FailureReason=0xc000006a Source=203.0.113.9 | UserSID=S-1-5-21-1-2-3-1001 | Occurrences=2", "Source", "203.0.113.9"),
        @("JobId={1} | Url=http://x/a b | Result=0x0 | UserSID=S-1-5-21-1-2-3-1001", "Url", "http://x/a b"),
        @("JobId={1} | Url=http://x/a b | Result=0x0 | UserSID=S-1-5-21-1-2-3-1001", "UserSID", "S-1-5-21-1-2-3-1001")
    )
    foreach ($case in $detailCases) {
        Assert-Equal ([TimelineReport.DetailParser]::Get($case[0], $case[1])) $case[2] -Message "Details '$($case[0])' -> $($case[1])"
    }

    # =========================================================
    # Rules: load and evaluate
    # =========================================================
    $rules = Import-ReportRules -Path (Join-Path $fixtureDir "rules.json")
    Assert-Equal $rules.SchemaVersion 1 -Message "rules: schemaVersion 1"
    Assert-Equal $rules.Rules.Count 14 -Message "rules: 14 rules loaded"
    Assert-Equal $rules.Allowlist.Count 2 -Message "rules: 2 allowlist entries loaded"
    Assert-Equal ($rules.Lists["tools"] -join ",") "alphatool,betatool,gamma.tool" -Message "rules: list values kept"
    Assert-Equal ($rules.Rules[0].References -join ",") "MITRE ATT&CK T1204" -Message "rules: references kept"
    Assert-Equal ($rules.Rules | Where-Object { $_.Id -eq "T-DISABLED" }).Enabled "False" -Message "rules: enabled=false kept"

    $collectionInfo = Get-Content -LiteralPath (Join-Path $fixtureDir "collection_info.json") -Raw | ConvertFrom-Json
    $statistics = @{}
    $findings = @(Invoke-ReportRules -Rows $rows -Rules $rules -CollectionInfo $collectionInfo -Statistics $statistics)

    # Id | rule | severity | group | count | first time, in report order
    $expected = @(
        "F001|T-ACCOUNT|High|User account created: svc_backup|1|2026-03-09 08:10:00",
        "F002|T-AV|High|Detection: Trojan:Win32/Fakeware.A|2|2026-03-09 09:30:00",
        "F003|T-BURST|High|10.0.0.5|6|2026-03-09 10:00:00",
        "F004|T-SVC|High|UpdaterSvc|1|2026-03-09 11:50:00",
        "F005|T-SVC|High|CmdSvc|1|2026-03-09 11:55:00",
        "F006|T-RENAME|High|lockd|4|2026-03-10 09:30:00",
        "F007|T-TOOL|Medium|Prefetch execution: ALPHATOOL.EXE (run 1 of 2)|1|2026-03-09 09:00:00",
        "F008|T-TOOL|Medium|BAM execution: \Device\HarddiskVolume3\Tools\gamma.tool.exe|1|2026-03-09 09:06:00",
        "F009|T-EXCL|Medium||1|2026-03-09 09:41:00",
        "F010|T-PS|Medium|Microsoft-Windows-PowerShell%4Operational.evtx|1|2026-03-09 11:58:00",
        "F011|T-ACCOUNT|Medium|User account created: tempuser|1|2026-03-10 09:00:00",
        "F012|T-BURST|Medium|10.0.0.7|5|2026-03-10 10:00:00",
        "F013|T-TOOL|Medium|Prefetch execution: BETATOOL.EXE (run 1 of 1)|1|2026-03-10 12:10:00",
        "F014|T-LOGONTYPE|Info|3|3|2026-03-09 10:08:00",
        "F015|T-LOGONTYPE|Info|10|1|2026-03-09 10:30:00",
        "F016|T-NOTSOURCE|Info||1|2026-03-09 10:30:05",
        "F017|T-EXPLICIT|Info|CORP\alice|2|2026-03-09 10:40:00",
        "F018|T-EXPLICIT|Info|CORP\bob|1|2026-03-09 10:41:00",
        "F019|T-LOGONTYPE|Info|5|1|2026-03-09 11:30:00",
        "F020|T-FORMULA|Info||1|2026-03-09 12:30:00",
        "F021|T-USN-DEL|Info||5|2026-03-10 09:40:00"
    )
    $actual = @($findings | ForEach-Object { "$($_.Id)|$($_.RuleId)|$($_.Severity)|$($_.GroupKey)|$($_.Count)|$(Format-TestUtc $_.FirstSeenUtc)" })
    Assert-Equal $findings.Count $expected.Count -Message "21 findings (13 High/Medium, 8 Info)"
    for ($i = 0; $i -lt [Math]::Max($expected.Count, $actual.Count); $i++) {
        Assert-Equal $actual[$i] $expected[$i] -Message "finding $($i + 1): numbering, order, rule, severity, group, count, first time"
    }
    $byId = @{}
    foreach ($finding in $findings) { $byId[$finding.Id] = $finding }

    # Every evidence row is the timeline row with that Excel row number
    $badEvidence = 0
    $badOrder = 0
    foreach ($finding in $findings) {
        foreach ($row in $finding.Evidence) {
            $source = $expectedRows[$row.RowNumber - 2]
            if ($source.Timestamp -cne $row.Timestamp -or $source.Description -cne $row.Description -or $source.Source -cne $row.Source -or $source.RawPath -cne $row.RawPath) { $badEvidence++ }
        }
        $numbers = @($finding.RowNumbers)
        for ($n = 1; $n -lt $numbers.Count; $n++) { if ($numbers[$n] -le $numbers[$n - 1]) { $badOrder++ } }
    }
    Assert-Equal $badEvidence 0 -Message "every evidence row matches the timeline row at its RowNumber (row i = Excel row i + 2)"
    Assert-Equal $badOrder 0 -Message "RowNumbers are ascending"

    # match + not*: the TESTFILE detection is excluded; text copied from the rule
    $av = $byId["F002"]
    Assert-Equal ((@($av.Evidence | ForEach-Object { $_.RowNumber })) -join ",") "$($rowOf['2026-03-09 09:30:00']),$($rowOf['2026-03-10 12:06:00'])" -Message "match + notDescription: two detections, the TESTFILE one excluded"
    Assert-Equal "$($av.Why)|$($av.Technical)|$($av.NextSteps)|$($av.FalsePositives)|$($av.References -join ',')|$($av.Category)" "The antivirus flagged a file.|Defender detection rows, test files excluded.|Check the file and where it came from.|Antivirus test files.|MITRE ATT&CK T1204|Antivirus" -Message "finding carries why, technical, nextSteps, falsePositives, references and category"
    Assert-Equal "$(Format-TestUtc $av.LastSeenUtc)|$($av.DuringCollection)|$($av.Escalated)|$($av.EvidenceTruncated)" "2026-03-10 12:06:00|False|False|False" -Message "LastSeenUtc, DuringCollection, Escalated and EvidenceTruncated"
    Assert-Equal $av.FirstSeenUtc.Kind "Utc" -Message "FirstSeenUtc is a UTC [datetime]"

    # lists: gamma.tool is escaped (gammaxtool does not match)
    Write-TestResult -Succeeded (-not @($findings | Where-Object { $_.GroupKey -match 'gammaxtool' }).Count) -Message "list values are escaped: 'gamma.tool' does not match 'gammaxtool'"
    Assert-Equal $byId["F013"].DuringCollection "True" -Message "a finding whose rows are all after the collection start is DuringCollection"

    # anyOf and {{group}} in the title; the service without a match is not flagged
    Assert-Equal "$($byId['F004'].Title)|$($byId['F005'].Title)" "Suspicious service: UpdaterSvc|Suspicious service: CmdSvc" -Message "anyOf (either entry) and {{group}} in the title"
    Write-TestResult -Succeeded (-not @($findings | Where-Object { $_.GroupKey -eq "GoodSvc" }).Count) -Message "anyOf: a row matching no entry is not flagged"

    # threshold + escalate (sameKey detail:IpAddress,Source) + evidence cap
    $burst = $byId["F003"]
    $burstRows = @("2026-03-09 10:00:00", "2026-03-09 10:01:00", "2026-03-09 10:02:00", "2026-03-09 10:03:00", "2026-03-09 10:04:00", "2026-03-09 10:04:30", "2026-03-09 10:08:00") | ForEach-Object { $rowOf[$_] }
    Assert-Equal (@($burst.RowNumbers) -join ",") ($burstRows -join ",") -Message "threshold: only the rows in qualifying 5-minute windows, plus the escalation row (the later lone failure is left out)"
    Assert-Equal "$($burst.BaseSeverity)|$($burst.Severity)|$($burst.Escalated)|$($burst.EscalationCount)" "Medium|High|True|1" -Message "escalate: a successful logon from the same address within 10 minutes raises Medium to High"
    Assert-Equal (@($burst.Evidence | ForEach-Object { $_.RowNumber }) -join ",") (@($burstRows[0], $burstRows[1], $burstRows[2], $burstRows[6]) -join ",") -Message "maxEvidence 4: the escalation row plus the 3 earliest rows"
    Assert-Equal (@($burst.Evidence | Where-Object { $_.Escalation }) | ForEach-Object { $_.RowNumber }) $burstRows[6] -Message "the escalation evidence row is marked Escalation"
    Assert-Equal "$($burst.EvidenceTruncated)|$(Format-TestUtc $burst.LastSeenUtc)" "True|2026-03-09 10:08:00" -Message "EvidenceTruncated, and LastSeenUtc includes the escalation row"
    Assert-Equal "$($byId['F012'].Escalated)|$($byId['F012'].Count)" "False|5" -Message "threshold window is inclusive (5 rows spanning exactly 5 minutes); a logon from another address does not escalate"
    Write-TestResult -Succeeded (-not @($findings | Where-Object { $_.GroupKey -eq "10.0.0.9" }).Count) -Message "threshold: 5 failures spread over 20 minutes are not a burst"

    # escalate with sameKey user
    Assert-Equal "$($byId['F001'].Escalated)|$(Format-TestUtc $byId['F001'].LastSeenUtc)|$($byId['F001'].RowNumbers -join ',')" "True|2026-03-09 08:20:00|$($rowOf['2026-03-09 08:10:00']),$($rowOf['2026-03-09 08:20:00'])" -Message "escalate sameKey user: the same account added the new account to Administrators"
    Assert-Equal "$($byId['F011'].Escalated)|$($byId['F011'].Severity)" "False|Medium" -Message "escalate sameKey user: an add by another account does not escalate"

    # capture grouping + threshold
    Assert-Equal $byId["F006"].Title "Mass rename to .lockd" -Message "groupBy capture: the (?<key>...) group of match.description"
    Write-TestResult -Succeeded (-not @($findings | Where-Object { $_.RuleId -eq "T-RENAME" -and $_.GroupKey -eq "txt" }).Count) -Message "groupBy capture: 2 renames to .txt stay under the threshold"

    # allowlist: per rule, and "*" with duringCollection
    Assert-Equal "$($byId['F009'].AllowlistedCount)|$($byId['F009'].Evidence[0].RowNumber)" "1|$($rowOf['2026-03-09 09:41:00'])" -Message "allowlist (rule): the collector's exclusion is counted, not flagged"
    Assert-Equal "$($byId['F010'].AllowlistedCount)|$($byId['F010'].Evidence[0].RowNumber)" "1|$($rowOf['2026-03-09 11:58:00'])" -Message "allowlist (*, duringCollection): only the row after the collection start is allowlisted"
    Assert-Equal "$($statistics['T-EXCL'].AllowlistedRows)|$($statistics['T-EXCL'].Allowlisted[0].Reason)" "1|The collector's own exclusion." -Message "statistics: allowlisted rows per rule with the reason"
    Assert-Equal "$($statistics['T-PS'].Allowlisted[0].Reason)|$($statistics['T-PS'].MatchedRows)" "The collector's own activity.|2" -Message "statistics: '*' entry reason and matched rows"
    Assert-Equal $statistics.Count 13 -Message "statistics: one entry per enabled rule"
    Write-TestResult -Succeeded (-not @($findings | Where-Object { $_.RuleId -eq "T-DISABLED" }).Count) -Message "a disabled rule produces no finding"

    # groupBy user / detail (both styles) / rule; user + notUser conditions
    Assert-Equal (@($findings | Where-Object { $_.RuleId -eq "T-EXPLICIT" } | ForEach-Object { "$($_.GroupKey)=$($_.Count)" }) -join ",") "CORP\alice=2,CORP\bob=1" -Message "groupBy user; notUser drops NT AUTHORITY\SYSTEM"
    Assert-Equal (@($findings | Where-Object { $_.RuleId -eq "T-LOGONTYPE" } | ForEach-Object { "$($_.GroupKey)=$($_.Count)" }) -join ",") "3=3,10=1,5=1" -Message "groupBy detail:LogonType reads ' | ' and space-separated Details"
    Assert-Equal "$($byId['F021'].Count)|$(@($byId['F021'].Evidence).Count)|$($byId['F021'].EvidenceTruncated)|$(@($byId['F021'].RowNumbers).Count)" "5|3|True|5" -Message "maxEvidence 3: Count 5, 3 evidence rows, all 5 row numbers; notDetails drops the rename"
    Assert-Equal (@($byId['F021'].Evidence | ForEach-Object { $_.Timestamp.Substring(11, 8) }) -join ",") "09:40:00,09:41:00,09:42:00" -Message "evidence is the earliest rows by time"

    # Excel row -> finding ids (a row can belong to several findings)
    $rowMap = Get-ReportFindingRowMap -Findings $findings
    Assert-Equal $rowMap[$rowOf["2026-03-09 10:08:00"]] "F003, F014" -Message "Get-ReportFindingRowMap: a row in two findings lists both ids"
    Assert-Equal $rowMap.ContainsKey($rowOf["2026-03-09 09:31:00"]) "False" -Message "Get-ReportFindingRowMap: an unflagged row has no entry"

    # Without collection info, duringCollection can never hold
    $withoutInfo = @(Invoke-ReportRules -Rows $rows -Rules $rules)
    $ps = $withoutInfo | Where-Object { $_.RuleId -eq "T-PS" }
    Assert-Equal "$($ps.Count)|$($ps.AllowlistedCount)" "2|0" -Message "without a collection start, duringCollection: true never matches"

    # A different row list of the same length is read again (no stale cache)
    $changed = @($rows | Select-Object *)
    $changed[$rowOf["2026-03-09 12:30:00"] - 2].Description = "renamed"
    Write-TestResult -Succeeded (-not @(Invoke-ReportRules -Rows $changed -Rules $rules | Where-Object { $_.RuleId -eq "T-FORMULA" }).Count) -Message "rows are re-read for a new row list of the same length"

    # Hashtable rows, an ISO timestamp and an unreadable one; empty rows
    $miniRules = Join-Path $workDir "mini-rules.json"
    New-TestTextFile $miniRules '{ "schemaVersion": 1, "rules": [ { "id": "M1", "title": "Alpha", "category": "Other", "severity": "Medium", "match": { "description": "^alpha" }, "why": "w" } ] }'
    $mini = Import-ReportRules -Path $miniRules
    $hashRows = @(
        @{ Timestamp = "2026-01-01T00:00:05Z"; Source = "S"; EventType = "E"; Description = "alpha one"; User = ""; Details = "" },
        @{ Timestamp = "not a time"; Source = "S"; EventType = "E"; Description = "alpha two"; User = ""; Details = "" }
    )
    $miniFindings = @(Invoke-ReportRules -Rows $hashRows -Rules $mini)
    Assert-Equal "$($miniFindings.Count)|$($miniFindings[0].Count)|$(Format-TestUtc $miniFindings[0].FirstSeenUtc)|$(Format-TestUtc $miniFindings[0].LastSeenUtc)" "1|2|2026-01-01 00:00:05|2026-01-01 00:00:05" -Message "hashtable rows; ISO time read; an unreadable time is matched but not timed"
    $miniModel = New-ReportModel -Rows $hashRows -Findings $miniFindings
    Write-TestResult -Succeeded (@($miniModel.Coverage.Notes | Where-Object { $_ -match '^1 row\(s\) have a timestamp that could not be read' }).Count -eq 1) -Message "model notes rows with an unreadable time"
    $emptyFindings = @(Invoke-ReportRules -Rows @() -Rules $rules)
    $emptyModel = New-ReportModel -Rows @() -Findings $emptyFindings
    Assert-Equal "$($emptyFindings.Count)|$($emptyModel.TimeSpan.Rows)|$($null -eq $emptyModel.TimeSpan.FirstUtc)|$($emptyModel.Counts.High)" "0|0|True|0" -Message "an empty timeline: no findings, an empty model"
    Export-ReportModelJson -Model $emptyModel -Path (Join-Path $workDir "empty-model.json")
    Assert-Equal ((Get-Content -LiteralPath (Join-Path $workDir "empty-model.json") -Raw | ConvertFrom-Json).TimeSpan.Rows) 0 -Message "an empty model exports as JSON"

    # "." in a rule pattern also matches a line break (multi-line Details)
    $multilineRules = Join-Path $workDir "multiline-rules.json"
    New-TestTextFile -Path $multilineRules -Text '{ "schemaVersion": 1, "rules": [ { "id": "M2", "title": "Privileges", "category": "Other", "severity": "Info", "match": { "details": "^Privileges=SeTcbPrivilege.*SeDebugPrivilege$" }, "why": "w" } ] }'
    $multiline = @(Invoke-ReportRules -Rows $rows -Rules (Import-ReportRules -Path $multilineRules))
    Assert-Equal -Actual "$($multiline.Count)|$($multiline[0].Evidence[0].RowNumber)" -Expected "1|$($rowOf['2026-03-09 08:30:00'])" -Message "'.' in a rule pattern also matches a line break inside Details"
    $message = ""
    try { $null = Invoke-ReportRules -Rows $rows -Rules (Join-Path $fixtureDir "rules.json") } catch { $message = $_.Exception.Message }
    Write-TestResult -Succeeded ($message -match 'Import-ReportRules') -Message "Invoke-ReportRules refuses rules that were not imported ($message)"

    # maxFindings: the groups beyond the limit fold into one roll-up finding
    # (every row kept); activityTime false is carried to the findings
    $foldRules = Join-Path $workDir "fold-rules.json"
    New-TestTextFile $foldRules '{ "schemaVersion": 1, "rules": [ { "id": "FOLD", "title": "Burst from {{group}}", "category": "Access", "severity": "Medium", "match": { "description": "^fail from (?<key>\\S+)$" }, "groupBy": "capture", "maxFindings": 3, "activityTime": false, "why": "Failures from {{group}}." } ] }'
    $foldRows = @(foreach ($n in 1..6) { foreach ($k in 1..$n) { @{ Timestamp = ("2026-01-0{0} 00:00:{1:00}.000" -f $n, $k); Source = "S"; EventType = "E"; Description = "fail from ip$n"; User = ""; Details = "" } } })
    $foldStats = @{}
    $folded = @(Invoke-ReportRules -Rows $foldRows -Rules (Import-ReportRules -Path $foldRules) -Statistics $foldStats)
    $rollUp = $folded | Where-Object { $_.FoldedGroups -gt 0 }
    Assert-Equal "$($folded.Count)|$((@($folded | Where-Object { $_.FoldedGroups -eq 0 } | ForEach-Object { $_.GroupKey }) | Sort-Object) -join ',')|$($foldStats['FOLD'].Groups)|$($foldStats['FOLD'].Findings)" "3|ip5,ip6|6|3" -Message "maxFindings 3: the two groups with the most rows stay, 6 groups give 3 findings"
    Assert-Equal "$($rollUp.FoldedGroups)|$($rollUp.GroupKey)|$($rollUp.Count)|$(@($rollUp.RowNumbers).Count)|$($rollUp.Title)" "4|4 more: ip4, ip3, ip2, ip1|10|10|Burst from 4 more, folded into one lead" -Message "the roll-up finding folds the other 4 groups (most rows first) with all their rows"
    Write-TestResult -Succeeded ($rollUp.Why.StartsWith("Failures from several.") -and $rollUp.Why.Contains("folds together 4 more groups") -and (@($rollUp.FoldedKeys) -join ",") -eq "ip4,ip3,ip2,ip1") -Message "the roll-up's why says what it folds, and FoldedKeys lists the folded groups"
    $taggedRows = 0
    foreach ($f in $folded) { $taggedRows += @($f.RowNumbers).Count }
    Assert-Equal "$taggedRows|$(@($folded | Where-Object { $_.ActivityTime }).Count)" "21|0" -Message "every row is still in a finding (for the Finding column), and activityTime false is carried to every finding"
    $foldModel = New-ReportModel -Rows $foldRows -Findings $folded
    Assert-Equal "$($null -eq $foldModel.LeadSpan.FirstUtc)|$($foldModel.LeadSpan.FileTimeLeads)" "True|3" -Message "model.LeadSpan leaves out leads dated by file times (activityTime false)"
    $topRulesPath = Join-Path $workDir "top-rules.json"
    New-TestTextFile $topRulesPath '{ "schemaVersion": 1, "rules": [ { "id": "FILETIME", "title": "File time", "category": "FileSystem", "severity": "Medium", "match": { "description": "^old file" }, "activityTime": false, "why": "w" }, { "id": "ACTIVITY", "title": "Activity", "category": "Execution", "severity": "Medium", "match": { "description": "^new run" }, "why": "w" } ] }'
    $topRows = @(
        @{ Timestamp = "2020-01-01 00:00:00.000"; Source = "S"; EventType = "E"; Description = "old file"; User = ""; Details = "" },
        @{ Timestamp = "2026-01-01 00:00:00.000"; Source = "S"; EventType = "E"; Description = "new run"; User = ""; Details = "" })
    $topLeads = @(Invoke-ReportRules -Rows $topRows -Rules (Import-ReportRules -Path $topRulesPath))
    $topModel = New-ReportModel -Rows $topRows -Findings $topLeads
    $ruleOfId = @{}
    foreach ($lead in $topLeads) { $ruleOfId[$lead.Id] = $lead.RuleId }
    Assert-Equal "$(@($topLeads | ForEach-Object { $_.RuleId }) -join ',')|$(@($topModel.TopFindings | ForEach-Object { $ruleOfId[$_] }) -join ',')|$(Format-TestUtc $topModel.LeadSpan.FirstUtc)" "FILETIME,ACTIVITY|ACTIVITY,FILETIME|2026-01-01 00:00:00" -Message "numbering keeps time order, but the top leads and the lead window put a lead dated by an old file time after one dated by activity"

    # DuringCollection is about event times: a lead seen only in Snapshot rows
    # from during the collection (a task listed then) is
    # CapturedDuringCollection instead; one with an event row (Prefetch) from
    # during the collection is DuringCollection. A lead whose rows all come
    # from the memory dump (Memory-* sources, whatever their event type) is
    # MemoryOnly, "Captured in the memory dump", and never
    # CapturedDuringCollection; a process creation time in the dump after
    # the collection start still makes it DuringCollection
    $snapRulesPath = Join-Path $workDir "snapshot-rules.json"
    New-TestTextFile $snapRulesPath '{ "schemaVersion": 1, "rules": [ { "id": "SNAP", "title": "Seen: {{group}}", "category": "Execution", "severity": "High", "match": { "description": "^(?:Process command line|Process in memory|Prefetch execution|Listed task): (?<key>[^\\s(]+)" }, "groupBy": "capture", "why": "w" } ] }'
    $snapRows = @(
        @{ Timestamp = "2026-05-15 07:00:00.000"; Source = "Prefetch"; EventType = "Execution"; Description = "Prefetch execution: before.exe"; User = ""; Details = "" },
        @{ Timestamp = "2026-05-14 09:00:00.000"; Source = "Memory-CommandLine"; EventType = "Snapshot"; Description = "Process command line: olddump.exe (PID: 9)"; User = ""; Details = "Args=olddump.exe" },
        @{ Timestamp = "2026-05-15 08:59:00.000"; Source = "Prefetch"; EventType = "Execution"; Description = "Prefetch execution: mixed.exe"; User = ""; Details = "" },
        @{ Timestamp = "2026-05-15 08:59:30.000"; Source = "Memory-Processes"; EventType = "ProcessCreation"; Description = "Process in memory: memstart.exe (PID: 5, PPID: 4)"; User = ""; Details = "Threads=1 SessionId=1" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "Memory-CommandLine"; EventType = "Snapshot"; Description = "Process command line: memonly.exe (PID: 1)"; User = ""; Details = "Args=memonly.exe -x" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "Memory-CommandLine"; EventType = "Snapshot"; Description = "Process command line: mixed.exe (PID: 2)"; User = ""; Details = "Args=mixed.exe" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "Memory-CommandLine"; EventType = "Snapshot"; Description = "Process command line: before.exe (PID: 3)"; User = ""; Details = "Args=before.exe" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "Memory-CommandLine"; EventType = "Snapshot"; Description = "Process command line: memstart.exe (PID: 5)"; User = ""; Details = "Args=memstart.exe" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "Memory-CommandLine"; EventType = "Snapshot"; Description = "Process command line: memmix.exe (PID: 6)"; User = ""; Details = "Args=memmix.exe" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "ScheduledTasks"; EventType = "Snapshot"; Description = "Listed task: memmix.exe"; User = ""; Details = "" },
        @{ Timestamp = "2026-05-15 09:00:00.000"; Source = "ScheduledTasks"; EventType = "Snapshot"; Description = "Listed task: tasksnap.exe"; User = ""; Details = "" })
    $snapInfo = [PSCustomObject]@{ Mode = "Live"; ComputerName = "WS01"; CollectionStartUtc = "2026-05-15T08:58:00Z" }
    $snapLeads = @(Invoke-ReportRules -Rows $snapRows -Rules (Import-ReportRules -Path $snapRulesPath) -CollectionInfo $snapInfo)
    Assert-Equal (@($snapLeads | Sort-Object GroupKey | ForEach-Object { "$($_.GroupKey)=$($_.DuringCollection)/$($_.CapturedDuringCollection)/$($_.MemoryOnly)" }) -join ",") "before.exe=False/False/False,memmix.exe=False/True/False,memonly.exe=False/False/True,memstart.exe=True/False/True,mixed.exe=True/False/False,olddump.exe=False/False/True,tasksnap.exe=False/True/False" -Message "Snapshot and memory leads (DuringCollection/CapturedDuringCollection/MemoryOnly): every row from the memory dump is MemoryOnly and never CapturedDuringCollection, also when captured before the collection; a process start in the dump after the collection start is still DuringCollection; a task listed during the collection, alone or with a memory row, is CapturedDuringCollection; a Prefetch row then is DuringCollection"
    Assert-Equal (@($snapLeads | Sort-Object GroupKey | ForEach-Object { "$($_.GroupKey)=[$($_.MemoryOnlyNote)]" }) -join ",") "before.exe=[],memmix.exe=[],memonly.exe=[Captured in the memory dump],memstart.exe=[Captured in the memory dump],mixed.exe=[],olddump.exe=[Captured in the memory dump],tasksnap.exe=[]" -Message "MemoryOnlyNote is exactly 'Captured in the memory dump' for a memory-only lead and empty otherwise"
    $snapModel = New-ReportModel -Rows $snapRows -Findings $snapLeads -CollectionInfo $snapInfo
    Assert-Equal "$(Format-TestUtc $snapModel.LeadSpan.FirstUtc)|$(Format-TestUtc $snapModel.LeadSpan.LastUtc)|$($snapModel.LeadSpan.FileTimeLeads)|$($snapModel.Counts.High)" "2026-05-14 09:00:00|2026-05-15 09:00:00|0|7" -Message "Snapshot and memory-only leads stay High leads in the flagged-activity window (only their card note changes)"
    # findings.csv's summary line and report-model.json carry the note
    $snapCsv = Join-Path $workDir "snapshot-findings.csv"
    Export-ReportFindingsCsv -Findings $snapLeads -Path $snapCsv
    $snapLines = @(Import-Csv -LiteralPath $snapCsv)
    $snapSummaries = @{}
    foreach ($line in @($snapLines | Where-Object { -not $_.RowNumber })) { $snapSummaries[$line.Title] = $line.Description }
    Write-TestResult -Succeeded ($snapSummaries["Seen: memonly.exe"].EndsWith("; group: memonly.exe; Captured in the memory dump") -and $snapSummaries["Seen: memstart.exe"].EndsWith("; Captured in the memory dump") -and
        -not $snapSummaries["Seen: mixed.exe"].Contains("memory dump") -and -not $snapSummaries["Seen: memmix.exe"].Contains("memory dump")) -Message "findings.csv: a memory-only lead's summary line ends with 'Captured in the memory dump', a mixed lead's does not ($($snapSummaries['Seen: memonly.exe']))"
    # The memory-only lead's evidence lines point at its Memory-* rows
    $memstartLead = @($snapLeads | Where-Object { $_.MemoryOnly -and $_.GroupKey -eq "memstart.exe" })
    $memstartEvidence = @($snapLines | Where-Object { $memstartLead.Count -eq 1 -and $_.FindingId -eq $memstartLead[0].Id -and $_.RowNumber })
    Assert-Equal "$(@($memstartEvidence | ForEach-Object { "$($_.RowNumber)=$($_.Source)" }) -join ',')|$(@($memstartLead | ForEach-Object { $_.RowNumbers }) -join ',')" "5=Memory-Processes,9=Memory-CommandLine|5,9" -Message "findings.csv: the memory-only lead's evidence lines have the row numbers of its Memory-* rows (Excel rows, as its RowNumbers)"
    Export-ReportModelJson -Model $snapModel -Path (Join-Path $workDir "snapshot-model.json")
    $snapJson = Get-Content -LiteralPath (Join-Path $workDir "snapshot-model.json") -Raw | ConvertFrom-Json
    $memonlyJson = @($snapJson.Findings | Where-Object { $_.GroupKey -eq "memonly.exe" })[0]
    $mixedJson = @($snapJson.Findings | Where-Object { $_.GroupKey -eq "mixed.exe" })[0]
    Assert-Equal "$($memonlyJson.MemoryOnly)|$($memonlyJson.MemoryOnlyNote)|$($memonlyJson.CapturedDuringCollection)|$($mixedJson.MemoryOnly)|$($mixedJson.MemoryOnlyNote)" "True|Captured in the memory dump|False|False|" -Message "report-model.json: MemoryOnly and MemoryOnlyNote on every finding"

    # A task's author-supplied registration date (task XML, can be forged)
    # does not date a lead that has a time Windows recorded; a lead with
    # only such dates is left out of the activity window, like file times
    $taskRulesPath = Join-Path $workDir "task-rules.json"
    New-TestTextFile $taskRulesPath '{ "schemaVersion": 1, "rules": [ { "id": "TASK", "title": "Task {{group}}", "category": "Persistence", "severity": "High", "match": { "description": "^Scheduled task (?:registered|registration date \\(author-supplied\\)|last run): (?<key>.+)$" }, "groupBy": "capture", "why": "w" } ] }'
    $authorNote = "Time=task XML RegistrationInfo/Date (author-supplied, not recorded by Windows)"
    $taskRows = @(
        @{ Timestamp = "2004-01-01 00:00:00.000"; Source = "ScheduledTasks"; EventType = "ScheduledTaskChange"; Description = "Scheduled task registration date (author-supplied): \OnlyAuthor"; User = ""; Details = "Actions=b.exe | $authorNote" },
        @{ Timestamp = "2005-10-11 13:21:17.000"; Source = "ScheduledTasks"; EventType = "ScheduledTaskChange"; Description = "Scheduled task registration date (author-supplied): \EvilTask"; User = ""; Details = "Actions=a.exe | $authorNote" },
        @{ Timestamp = "2026-05-04 11:02:01.000"; Source = "Registry-TaskCache"; EventType = "ScheduledTaskChange"; Description = "Scheduled task registered: \EvilTask"; User = ""; Details = "Actions=a.exe | Time=TaskCache DynamicInfo created (registered) time" },
        @{ Timestamp = "2026-05-06 08:00:00.000"; Source = "ScheduledTasks"; EventType = "Execution"; Description = "Scheduled task last run: \EvilTask"; User = ""; Details = "Actions=a.exe" },
        @{ Timestamp = "2031-01-01 00:00:00.000"; Source = "ScheduledTasks-XML"; EventType = "ScheduledTaskChange"; Description = "Scheduled task registration date (author-supplied): \EvilTask"; User = ""; Details = "Actions=a.exe | $authorNote" })
    $taskLeads = @(Invoke-ReportRules -Rows $taskRows -Rules (Import-ReportRules -Path $taskRulesPath))
    Assert-Equal (@($taskLeads | ForEach-Object { "$($_.GroupKey)|$($_.Count)|$(Format-TestUtc $_.FirstSeenUtc)|$(Format-TestUtc $_.LastSeenUtc)|$($_.ActivityTime)|$($_.TimesAuthorSupplied)" }) -join " / ") "\OnlyAuthor|1|2004-01-01 00:00:00|2004-01-01 00:00:00|False|True / \EvilTask|4|2026-05-04 11:02:01|2026-05-06 08:00:00|True|False" -Message "author-supplied task dates (2005, 2031) do not set a lead's first and last time when it has times Windows recorded; a lead with only such dates keeps them and is not dated by activity"
    $taskModel = New-ReportModel -Rows $taskRows -Findings $taskLeads
    $taskRuleOf = @{}
    foreach ($lead in $taskLeads) { $taskRuleOf[$lead.Id] = $lead.GroupKey }
    Assert-Equal "$(Format-TestUtc $taskModel.LeadSpan.FirstUtc)|$(Format-TestUtc $taskModel.LeadSpan.LastUtc)|$($taskModel.LeadSpan.FileTimeLeads)|$(@($taskModel.TopFindings | ForEach-Object { $taskRuleOf[$_] }) -join ',')" "2026-05-04 11:02:01|2026-05-06 08:00:00|1|\EvilTask,\OnlyAuthor" -Message "the flagged-activity window and the top leads leave a lead dated only by an author-supplied date out of the window and put it last"

    # A pattern that keeps timing out stops its rule after a few timeouts
    # instead of costing the timeout on every row; other rules still run
    $script:ReportEngineRegexTimeout = [TimeSpan]::FromMilliseconds(50)
    $slowRules = Join-Path $workDir "slow-rules.json"
    New-TestTextFile $slowRules '{ "schemaVersion": 1, "rules": [ { "id": "SLOW", "title": "Slow", "category": "Other", "severity": "Medium", "match": { "description": "^(a+)+$" }, "why": "w" }, { "id": "FAST", "title": "Fast", "category": "Other", "severity": "Medium", "match": { "description": "^b" }, "why": "w" } ] }'
    $slowRows = @(foreach ($n in 1..20) { @{ Timestamp = "2026-01-01 00:00:00.000"; Source = "S"; EventType = "E"; Description = ("a" * 40) + "!"; User = ""; Details = "" } })
    $slowRows += @{ Timestamp = "2026-01-01 00:00:01.000"; Source = "S"; EventType = "E"; Description = "b row"; User = ""; Details = "" }
    $slowImported = Import-ReportRules -Path $slowRules
    $script:ReportEngineRegexTimeout = [TimeSpan]::FromSeconds(2)
    $slowStats = @{}
    $slowWarnings = $null
    $slowWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $slowFindings = @(Invoke-ReportRules -Rows $slowRows -Rules $slowImported -Statistics $slowStats -WarningVariable slowWarnings -WarningAction SilentlyContinue)
    $slowWatch.Stop()
    Assert-Equal "$($slowStats['SLOW'].RegexTimeouts)|$([bool]$slowStats['SLOW'].Abandoned)|$(@($slowFindings | Where-Object { $_.RuleId -eq 'SLOW' }).Count)|$(@($slowFindings | Where-Object { $_.RuleId -eq 'FAST' }).Count)" "3|True|0|1" -Message "a rule is stopped after 3 regex timeouts and reports nothing; the next rule still runs"
    Write-TestResult -Succeeded ((@($slowWarnings) -join " ") -match 'SLOW was stopped' -and $slowWatch.Elapsed.TotalSeconds -lt 10) -Message "the stop is logged as a warning, and the run takes the time of 3 timeouts, not 20 ($([Math]::Round($slowWatch.Elapsed.TotalSeconds, 1)) s)"

    # =========================================================
    # Invalid rules files: the error names the file, rule and field
    # =========================================================
    $badPath = Join-Path $workDir "invalid.json"
    $rule = '"id": "BAD-1", "title": "T", "category": "Other", "severity": "Medium", "why": "w"'
    $invalidCases = @(
        @('{ "schemaVersion": 1, "rules": [ ', @("invalid.json", "not valid JSON")),
        @(('{ "schemaVersion": 2, "rules": [ { ' + $rule + ', "match": { "description": "x" } } ] }'), @("invalid.json", "schemaVersion", "must be 1")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "{{list:missing}}" } } ] }'), @("rule 'BAD-1' (rules[0])", "match.description", "unknown list 'missing'")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "([" } } ] }'), @("rule 'BAD-1' (rules[0])", "match.description", "invalid regular expression")),
        @('{ "schemaVersion": 1, "rules": [ { "id": "BAD-1", "title": "T", "category": "Other", "severity": "Critical", "why": "w", "match": { "description": "x" } } ] }', @("rule 'BAD-1'", ".severity", "'Critical'")),
        @('{ "schemaVersion": 1, "rules": [ { "id": "BAD-1", "title": "T", "category": "Malware", "severity": "High", "why": "w", "match": { "description": "x" } } ] }', @("rule 'BAD-1'", ".category", "'Malware'")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" } }, { ' + $rule + ', "match": { "description": "y" } } ] }'), @("rule 'BAD-1' (rules[1])", "duplicate rule id")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "descripton": "x" } } ] }'), @("rule 'BAD-1'", "match.descripton", "unknown condition")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "severty": "High", "match": { "description": "x" } } ] }'), @("rule 'BAD-1'", "unknown field 'severty'")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "threshold": { "count": 0, "windowMinutes": 5 } } ] }'), @("rule 'BAD-1'", "threshold.count")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "threshold": { "count": 3 } } ] }'), @("rule 'BAD-1'", "threshold.windowMinutes")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "escalate": { "severity": "High", "withinMinutes": 5 } } ] }'), @("rule 'BAD-1'", "escalate.match", "is required")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "escalate": { "severity": "High", "withinMinutes": 5, "sameKey": "colour", "match": { "description": "y" } } } ] }'), @("rule 'BAD-1'", "escalate.sameKey", "'colour'")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "groupBy": "detail:" } ] }'), @("rule 'BAD-1'", ".groupBy")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "groupBy": "colour" } ] }'), @("rule 'BAD-1'", ".groupBy", "'colour'")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "source": "x" }, "groupBy": "capture" } ] }'), @("rule 'BAD-1'", ".groupBy", "capture")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { } } ] }'), @("rule 'BAD-1'", "match", "has no conditions")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ' } ] }'), @("rule 'BAD-1'", "has no conditions")),
        @('{ "schemaVersion": 1, "rules": [ { "id": "BAD-1", "title": "T", "category": "Other", "severity": "Medium", "match": { "description": "x" } } ] }', @("rule 'BAD-1'", ".why", "is required")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "" } } ] }'), @("rule 'BAD-1'", "match.description", "is empty")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": 5 } } ] }'), @("rule 'BAD-1'", "match.description", "must be a string")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x", "duringCollection": "yes" } } ] }'), @("rule 'BAD-1'", "match.duringCollection", "true or false")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "anyOf": [ "x" ] } ] }'), @("rule 'BAD-1'", "anyOf[0]", "must be an object")),
        @(('{ "schemaVersion": 1, "lists": { "names": [] }, "rules": [ { ' + $rule + ', "match": { "description": "x" } } ] }'), @("list 'names'", "non-empty array")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" } } ], "allowlist": [ { "ruleId": "NOPE", "match": { "description": "x" }, "reason": "r" } ] }'), @("allowlist[0].ruleId", "'NOPE'")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" } } ], "allowlist": [ { "ruleId": "BAD-1", "match": { "description": "x" } } ] }'), @("allowlist[0] (ruleId 'BAD-1')", ".reason", "is required")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" } } ], "allowlist": [ { "ruleId": "*", "match": { "user": "(" }, "reason": "r" } ] }'), @("allowlist[0] (ruleId '*')", "match.user", "invalid regular expression")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "maxFindings": 1 } ] }'), @("rule 'BAD-1'", ".maxFindings", "0 (no limit) or a whole number from 2")),
        @(('{ "schemaVersion": 1, "rules": [ { ' + $rule + ', "match": { "description": "x" }, "activityTime": "no" } ] }'), @("rule 'BAD-1'", ".activityTime", "true or false")),
        @('{ "schemaVersion": 1, "rules": [ ] }', @("invalid.json", "rules", "non-empty array")),
        @('{ "schemaVersion": 1, "rule": [ ] }', @("invalid.json", "unknown field 'rule'"))
    )
    foreach ($case in $invalidCases) {
        New-TestTextFile $badPath $case[0]
        $message = ""
        try { $null = Import-ReportRules -Path $badPath } catch { $message = $_.Exception.Message }
        $missing = @($case[1] | Where-Object { $message.IndexOf($_, [System.StringComparison]::Ordinal) -lt 0 })
        Write-TestResult -Succeeded ($message -and $missing.Count -eq 0) -Message "invalid rules are refused with a clear error: $(if ($message) { $message } else { '(no error)' })$(if ($missing.Count) { ' -- missing: ' + ($missing -join ' / ') })"
    }
    $message = ""
    try { $null = Import-ReportRules -Path (Join-Path $workDir "does-not-exist.json") } catch { $message = $_.Exception.Message }
    Write-TestResult -Succeeded ($message -match 'not found') -Message "a missing rules file is refused ($message)"

    # =========================================================
    # {{list:...}} expansion: in the C# helper, and fail closed
    # (PowerShell 7 hands .NET method arguments to AMSI, which blocked a
    # second expansion of a keyword list; an expansion that fails must
    # never leave a condition that matches every row). Harmless words only.
    # =========================================================
    $listRulesPath = Join-Path $workDir "list-rules.json"
    New-TestTextFile $listRulesPath ('{ "schemaVersion": 1, "lists": { "fruit": [ "apple", "pear.x", "kiwi (gold)" ] }, "rules": [ ' +
        '{ "id": "FRUIT-A", "title": "A", "category": "Other", "severity": "Medium", "why": "w", "anyOf": [ { "source": "^S$", "details": "\\b{{list:fruit}}\\b" }, { "source": "^T$", "details": "^{{list:fruit}}$" } ] }, ' +
        '{ "id": "FRUIT-B", "title": "B", "category": "Other", "severity": "Medium", "why": "w", "match": { "description": "{{list:fruit}}" } } ] }')
    $listErrors = $null
    $listRules = Import-ReportRules -Path $listRulesPath -ErrorVariable listErrors
    $fruitA = ($listRules.Rules | Where-Object { $_.Id -eq "FRUIT-A" }).Compiled
    $fruitB = ($listRules.Rules | Where-Object { $_.Id -eq "FRUIT-B" }).Compiled
    Assert-Equal "$(@($listErrors).Count)|$($fruitA.AnyOf[0].Details)|$($fruitA.AnyOf[1].Details)|$($fruitB.Match.Description)" ("0|\b(?:apple|pear\.x|kiwi\ \(gold\))\b|^(?:apple|pear\.x|kiwi\ \(gold\))$|(?:apple|pear\.x|kiwi\ \(gold\))") -Message "a list used three times expands every time, escaped, with no error"
    $listRows = @(
        @{ Timestamp = "2026-01-01 00:00:01.000"; Source = "S"; EventType = "E"; Description = "d"; User = ""; Details = "one pear.x here" },
        @{ Timestamp = "2026-01-01 00:00:02.000"; Source = "S"; EventType = "E"; Description = "d"; User = ""; Details = "one pearyx here" },
        @{ Timestamp = "2026-01-01 00:00:03.000"; Source = "T"; EventType = "E"; Description = "kiwi (gold)"; User = ""; Details = "kiwi (gold)" },
        @{ Timestamp = "2026-01-01 00:00:04.000"; Source = "U"; EventType = "E"; Description = "plain"; User = ""; Details = "plain" }
    )
    $listFindings = @(Invoke-ReportRules -Rows $listRows -Rules $listRules)
    Assert-Equal (@($listFindings | ForEach-Object { "$($_.RuleId):$(@($_.RowNumbers) -join '+')" }) -join ",") "FRUIT-A:2+4,FRUIT-B:4" -Message "expanded lists match their literal values only ('pear.x' is not 'pearyx'), and no row that holds none"
    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $direct = [TimelineReport.RulePattern]::Compile("x{{list:fruit}}y", @{ fruit = [string[]]@("a|b") }, $options, [TimeSpan]::FromSeconds(1))
    Assert-Equal "$direct" "x(?:a\|b)y" -Message "RulePattern.Compile expands a list in C# (escaped)"
    foreach ($case in @(
            @("{{list:none}}", @{ fruit = [string[]]@("a") }, "unknown list 'none'"),
            @("{{list:fruit}}", @{ fruit = [string[]]@() }, "list 'fruit' has no values"),
            @("{{list:fruit}}", @{ fruit = $null }, "unknown list 'fruit'"),
            @("", @{}, "is empty"),
            @("(", @{}, "invalid regular expression"))) {
        $message = ""
        try { $null = [TimelineReport.RulePattern]::Compile($case[0], $case[1], $options, [TimeSpan]::FromSeconds(1)) } catch { $message = $_.Exception.InnerException.Message }
        Write-TestResult -Succeeded ($message.Contains($case[2])) -Message "RulePattern.Compile refuses '$($case[0])': $message"
    }
    Assert-Equal "$([TimelineReport.RulePattern]::IsEmpty([regex]::new(''))):$([TimelineReport.RulePattern]::IsEmpty($null)):$([TimelineReport.RulePattern]::IsEmpty([regex]::new('a')))" "True:True:False" -Message "RulePattern.IsEmpty: an empty or missing regex"
    # A call that is blocked (as AMSI blocked it), or that gives no regex or
    # an empty one: a rules-file error naming the rule and field. The
    # stand-in replaces the helper only inside its script block: a pattern
    # without a list compiles as usual, one with a list gets -OnList.
    function Get-StandInImportError {
        param([scriptblock]$OnList)
        $onListResult = $OnList
        return & {
            function New-ReportEngineRuleRegex {
                param([string]$Pattern, [hashtable]$Lists, [System.Text.RegularExpressions.RegexOptions]$Options, [TimeSpan]$Timeout)
                if ($Pattern.Contains("{{list:")) { return (& $onListResult) }
                return [TimelineReport.RulePattern]::Compile($Pattern, $Lists, $Options, $Timeout)
            }
            try { $null = Import-ReportRules -Path $listRulesPath; "" } catch { $_.Exception.Message }
        }
    }
    $listField = "rule 'FRUIT-A' (rules[0]).anyOf[0].details"
    $blockedMessage = Get-StandInImportError { throw "This script contains malicious content and has been blocked by your antivirus software." }
    Write-TestResult -Succeeded ($blockedMessage.Contains($listField) -and $blockedMessage.Contains("could not be compiled") -and $blockedMessage.Contains("blocked by your antivirus")) -Message "a blocked expansion fails closed with a rules-file error ($blockedMessage)"
    $nullMessage = Get-StandInImportError { $null }
    Write-TestResult -Succeeded ($nullMessage.Contains($listField) -and $nullMessage.Contains("no regular expression")) -Message "an expansion that gives no regex fails closed ($nullMessage)"
    $emptyMessage = Get-StandInImportError { [regex]::new("") }
    Write-TestResult -Succeeded ($emptyMessage.Contains($listField) -and $emptyMessage.Contains("would match every row")) -Message "an expansion that gives an empty regex (it would match every row) fails closed ($emptyMessage)"
    # A statement-terminating error inside the call (outside a try it would
    # only skip its own statement, and the next one would give a regex)
    $silentMessage = Get-StandInImportError { [void][int]::Parse("not a number"); [regex]::new("ok") }
    Write-TestResult -Succeeded ($silentMessage.Contains($listField) -and $silentMessage.Contains("could not be compiled")) -Message "an error inside the call is not skipped over ($silentMessage)"
    Write-TestResult -Succeeded ((Get-StandInImportError { [regex]::new("ok") }) -eq "") -Message "the stand-in itself imports the rules when its call works"

    # The shipped rules import with no error, and no compiled condition is an
    # empty regex (one that would match every row)
    $shippedErrors = $null
    $shipped = Import-ReportRules -Path (Join-Path $repoRoot "report\report-rules.json") -ErrorVariable shippedErrors
    $emptyConditions = New-Object System.Collections.Generic.List[string]
    $conditionNames = @("Source", "EventType", "Description", "Details", "User", "NotSource", "NotEventType", "NotDescription", "NotDetails", "NotUser")
    foreach ($shippedRule in $shipped.Rules) {
        $specs = @($shippedRule.Compiled.Match) + @($shippedRule.Compiled.AnyOf) + @($shippedRule.Compiled.EscalateMatch) + @($shippedRule.Compiled.Allowlist)
        foreach ($spec in @($specs | Where-Object { $null -ne $_ })) {
            foreach ($name in $conditionNames) {
                if ($null -ne $spec.$name -and [TimelineReport.RulePattern]::IsEmpty($spec.$name)) { $emptyConditions.Add("$($shippedRule.Id).$name") }
            }
        }
    }
    Assert-Equal "$(@($shippedErrors).Count)|$(@($shipped.Rules).Count -gt 40)|$($emptyConditions -join ',')" "0|True|" -Message "report-rules.json: imports with no error, and no compiled condition is empty"

    # =========================================================
    # findings.csv (written before the model, which hashes it)
    # =========================================================
    $findingsCsv = Join-Path $workDir "findings.csv"
    Export-ReportFindingsCsv -Findings $findings -Path $findingsCsv
    $csvBytes = [System.IO.File]::ReadAllBytes($findingsCsv)
    Assert-Equal ($csvBytes[0] -eq 0xEF -and $csvBytes[1] -eq 0xBB -and $csvBytes[2] -eq 0xBF) "True" -Message "findings.csv starts with a UTF-8 BOM (Excel)"
    $csvText = [System.Text.Encoding]::UTF8.GetString($csvBytes)
    Assert-Equal ([regex]::Matches($csvText, "(?<!\r)\n").Count) 0 -Message "findings.csv uses CRLF line ends"
    $csvLines = @(Import-Csv -LiteralPath $findingsCsv)
    Assert-Equal (($csvText -split "`r`n")[0].TrimStart([char]0xFEFF)) '"FindingId","Severity","RuleId","Title","Category","RowNumber","Timestamp","Source","Description"' -Message "findings.csv header"
    $expectedLines = 0
    foreach ($finding in $findings) { $expectedLines += 1 + @($finding.Evidence).Count }
    Assert-Equal $csvLines.Count $expectedLines -Message "findings.csv: a summary line plus one line per evidence row for every finding"
    $summaries = @($csvLines | Where-Object { $_.RowNumber -eq "" })
    Assert-Equal $summaries.Count $findings.Count -Message "findings.csv: one summary line (blank RowNumber) per finding"
    $burstSummary = $summaries | Where-Object { $_.FindingId -eq "F003" }
    Write-TestResult -Succeeded ($burstSummary.Description -match '^Summary: 6 matching row\(s\), 2026-03-09 10:00:00\.000 to 2026-03-09 10:08:00\.000 UTC; group: 10\.0\.0\.5; escalated by 1 related row\(s\); first 4 rows listed$') -Message "findings.csv summary line: count, span, group, escalation, cap ($($burstSummary.Description))"
    Assert-Equal (@($csvLines | Where-Object { $_.FindingId -eq "F003" -and $_.RowNumber } | ForEach-Object { $_.RowNumber }) -join ",") (@($burst.Evidence | ForEach-Object { $_.RowNumber }) -join ",") -Message "findings.csv evidence lines carry the Excel row numbers"
    $formulaLine = $csvLines | Where-Object { $_.RuleId -eq "T-FORMULA" -and $_.RowNumber }
    Assert-Equal $formulaLine.Description "'=HYPERLINK(""http://example.invalid/"",""open"")" -Message "findings.csv: a value starting with '=' gets a leading apostrophe (no formula)"

    # =========================================================
    # Report model
    # =========================================================
    $model = New-ReportModel -Rows $rows -Findings $findings -CollectionInfo $collectionInfo `
        -CollectorLogPath (Join-Path $fixtureDir "collection_log.txt") -BuilderLogPath (Join-Path $fixtureDir "timeline_builder_log.txt") `
        -TimelinePath $timelinePath -Rules $rules -RuleStatistics $statistics -FindingsCsvPath $findingsCsv
    Assert-Equal "$($model.SchemaVersion)|$($model.GeneratedUtc.Kind)" "1|Utc" -Message "model: SchemaVersion 1, GeneratedUtc in UTC"

    $c = $model.Collection
    Assert-Equal "$($c.ComputerName)|$($c.OS)|$($c.Mode)|$($c.TargetTimeZoneId)|$(Format-TestUtc $c.CollectionStartUtc)|$($c.CollectorUser)|$($c.SecretsIncluded)|$($c.ThunderbirdIndexIncluded)" `
        "WS01|Microsoft Windows 11 Pro (build 26100)|Live|Pacific Standard Time|2026-03-10 12:00:00|CORP\examiner|True|False" -Message "model.Collection from collection_info.json and the SystemInfo row"
    $users = @($c.Users)
    Write-TestResult -Succeeded (($users -contains "alice") -and ($users -contains "CORP\alice") -and ($users -contains "CORP\bob") -and ($users -contains "CORP\admin1") -and ($users -contains "CORP\carol") -and
        -not ($users -contains "bob") -and -not ($users -contains "NT AUTHORITY\SYSTEM") -and -not ($users -contains "SYSTEM")) -Message "model.Collection.Users: people as the User column names them (the local alice and CORP\alice apart), no system accounts ($($users -join ', '))"
    Assert-Equal "$($c.ComputerNameSource)|$($c.CollectorHost)" "collection_info.json|" -Message "model.Collection: a live collection's computer name comes from collection_info.json, and there is no separate collector host"

    Assert-Equal "$(Format-TestUtc $model.TimeSpan.FirstUtc)|$(Format-TestUtc $model.TimeSpan.LastUtc)|$($model.TimeSpan.Rows)" "2026-03-09 08:00:00|2026-03-10 12:10:00|69" -Message "model.TimeSpan"
    Assert-Equal "$($model.Counts.High)|$($model.Counts.Medium)|$($model.Counts.Info)" "6|7|8" -Message "model.Counts"
    Assert-Equal ($model.TopFindings -join ",") "F001,F002,F003,F004,F006" -Message "model.TopFindings: the first lead of each rule, High first (F005 is a second T-SVC lead, so F006 takes its place)"
    Assert-Equal "$(@($model.Findings).Count)|$(@($model.InfoFindings).Count)|$(@($model.Findings | Where-Object { $_.Severity -eq 'Info' }).Count)" "13|8|0" -Message "model.Findings holds High and Medium, InfoFindings the rest"
    Assert-Equal "$(Format-TestUtc $model.LeadSpan.FirstUtc)|$(Format-TestUtc $model.LeadSpan.LastUtc)" "2026-03-09 08:10:00|2026-03-10 12:10:00" -Message "model.LeadSpan: earliest and latest High/Medium time"

    # Coverage per source, against an independent count
    $sourceErrors = 0
    $expectedSources = @($expectedRows | Group-Object Source | Sort-Object Name)
    foreach ($group in $expectedSources) {
        $entry = $model.Coverage.Sources | Where-Object { $_.Source -eq $group.Name }
        $times = @($group.Group | ForEach-Object { $_.Timestamp.Substring(0, 19) } | Sort-Object)
        if (-not $entry -or $entry.Rows -ne $group.Count -or (Format-TestUtc $entry.FirstUtc) -ne $times[0] -or (Format-TestUtc $entry.LastUtc) -ne $times[-1]) { $sourceErrors++ }
    }
    Assert-Equal "$(@($model.Coverage.Sources).Count)|$sourceErrors" "$($expectedSources.Count)|0" -Message "model.Coverage.Sources: rows, first and last time per source"
    $system = $model.Coverage.Sources | Where-Object { $_.Source -eq "System.evtx" }
    Assert-Equal "$($system.LargestGapHours)|$(Format-TestUtc $system.LargestGapStartUtc)|$(Format-TestUtc $system.LargestGapEndUtc)" "23|2026-03-09 08:00:00|2026-03-10 07:00:00" -Message "model.Coverage.Sources: largest gap in a source"
    Assert-Equal (@($model.Coverage.LogClears | ForEach-Object { "$($_.RowNumber):$($_.Description)" }) -join ",") "$($rowOf['2026-03-10 08:00:00']):Security audit log cleared,$($rowOf['2026-03-10 08:01:00']):Event log cleared: System" -Message "model.Coverage.LogClears (Security 1102, System 104)"
    Assert-Equal (@($model.Coverage.Boots | ForEach-Object { "$(Format-TestUtc $_.Utc) $($_.Kind)" }) -join ",") "2026-03-09 08:00:00 Startup,2026-03-09 08:00:05 Booted,2026-03-10 07:00:00 ShutdownInitiated,2026-03-10 07:00:10 Shutdown,2026-03-10 07:05:00 Startup,2026-03-10 07:05:01 UnexpectedShutdown" -Message "model.Coverage.Boots: kinds in time order"
    $notes = @($model.Coverage.AuditNotes)
    foreach ($fragment in @("(Security event 4688) recorded nothing", "(Security events 4698-4702) recorded nothing", "(event 4104) recorded nothing", "Sysmon is not installed", "Task Scheduler Operational log", "Defender Operational log is not in this timeline", "The Security log covers only 26.8 hours", "The USN journal covers 0.2 hours")) {
        Write-TestResult -Succeeded (@($notes | Where-Object { $_.Contains($fragment) }).Count -eq 1) -Message "model.Coverage.AuditNotes: '$fragment'"
    }
    $collectorErrors = $model.Coverage.CollectorErrors
    Assert-Equal "$($collectorErrors.Available)|$($collectorErrors.Count)|$($collectorErrors.WarningCount)|$($collectorErrors.LineCount)" "True|2|1|3" -Message "model.Coverage.CollectorErrors: the collector's error count, its warning count and its ERROR/WARNING lines"
    Write-TestResult -Succeeded (@($collectorErrors.Lines)[0] -match 'WARNING: Could not copy') -Message "model.Coverage.CollectorErrors.Lines keep the log lines"
    Assert-Equal "$($model.Coverage.BuilderWarnings.Count)" "1" -Message "model.Coverage.BuilderWarnings: the builder log's warnings"
    Write-TestResult -Succeeded (@($model.Coverage.Notes) -contains "Sources parsed by the builder: EventLogs, Prefetch, FileSystem, UsnJournal, SystemInfo.") -Message "model.Coverage.Notes: the sources the builder parsed"

    # Activity, against an independent count
    $zone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time")
    $perDay = @($expectedRows | Group-Object { $_.Timestamp.Substring(0, 10) } | Sort-Object Name | ForEach-Object {
        "$($_.Name)=$($_.Count)/$(@($_.Group | Where-Object { $_.EventType -ne 'FileAccess' -and $_.EventType -ne 'FileLastModified' -and $_.EventType -ne 'Snapshot' }).Count)"
    })
    Assert-Equal (@($model.Activity.PerDay | ForEach-Object { "$($_.Day)=$($_.Rows)/$($_.NonFileRows)" }) -join ",") ($perDay -join ",") -Message "model.Activity.PerDay (rows / rows that are not file-system or snapshot)"
    $hoursUtc = New-Object int[] 24
    $hoursLocal = New-Object int[] 24
    foreach ($row in $expectedRows) {
        $utc = [datetime]::ParseExact($row.Timestamp, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        $hoursUtc[$utc.Hour]++
        $hoursLocal[[System.TimeZoneInfo]::ConvertTimeFromUtc($utc, $zone).Hour]++
    }
    Assert-Equal ($model.Activity.PerHourUtc -join ",") ($hoursUtc -join ",") -Message "model.Activity.PerHourUtc"
    Assert-Equal ($model.Activity.PerHourLocal -join ",") ($hoursLocal -join ",") -Message "model.Activity.PerHourLocal (target time zone, daylight saving applied)"
    Assert-Equal $model.Activity.LocalTimeZoneId "Pacific Standard Time" -Message "model.Activity.LocalTimeZoneId"
    $topSource = $expectedRows | Group-Object Source | Sort-Object @{ Expression = { $_.Count }; Descending = $true }, Name | Select-Object -First 1
    Assert-Equal "$($model.Activity.TopSources[0].Source)=$($model.Activity.TopSources[0].Rows)" "$($topSource.Name)=$($topSource.Count)" -Message "model.Activity.TopSources: busiest source first"
    # One entry per account as the User column names it: the local alice and
    # the domain account CORP\alice are different accounts
    $localAliceRows = @($expectedRows | Where-Object { $_.User -eq "alice" }).Count
    $domainAliceRows = @($expectedRows | Where-Object { $_.User -eq "CORP\alice" }).Count
    $alice = $model.Activity.PerUser | Where-Object { $_.User -eq "alice" }
    $corpAlice = $model.Activity.PerUser | Where-Object { $_.User -eq "CORP\alice" }
    Assert-Equal "$($alice.Rows)|$($alice.IsSystem)|$($corpAlice.Rows)|$($corpAlice.IsSystem)" "$localAliceRows|False|$domainAliceRows|False" -Message "model.Activity.PerUser keeps 'alice' and 'CORP\alice' apart ($localAliceRows and $domainAliceRows rows)"
    Assert-Equal ($model.Activity.PerUser | Where-Object { $_.User -eq "NT AUTHORITY\SYSTEM" }).IsSystem "True" -Message "model.Activity.PerUser shows NT AUTHORITY\SYSTEM as the timeline names it and marks it as a system account"
    Write-TestResult -Succeeded (-not @($model.Activity.PerUser | Where-Object { $_.User -eq "SYSTEM" -or $_.User -eq "bob" }).Count) -Message "model.Activity.PerUser: no name without its domain (SYSTEM, bob)"
    Write-TestResult -Succeeded (@($model.Coverage.Notes | Where-Object { $_ -match '^3 account SID\(s\) in the User column have no name' }).Count -eq 1) -Message "model.Coverage.Notes: the builder log's 'User column: 3 SID(s) not named' line"

    # Caveats: the static list plus the ones this collection needs
    $caveats = @($model.Caveats)
    Assert-Equal $caveats.Count 13 -Message "model.Caveats: 9 standard + secrets, -MftDays, collector errors, no workbook"
    foreach ($fragment in @("leads to review, not a verdict", "-IncludeSecrets", "(-MftDays 7)", "The collector logged 2 error(s)", "workbook (timeline.xlsx) was not created")) {
        Write-TestResult -Succeeded (@($caveats | Where-Object { $_.Contains($fragment) }).Count -eq 1) -Message "model.Caveats: '$fragment'"
    }
    Assert-Equal "$(@($model.Rules).Count)|$(($model.Rules | Where-Object { $_.Id -eq 'T-DISABLED' }).Enabled)|$($model.Rules[0].Id)|$($model.Rules[0].Severity)|$($model.Rules[0].Category)" "14|False|T-AV|High|Antivirus" -Message "model.Rules: every rule with id, severity, category and Enabled"
    Assert-Equal (@($model.Allowlisted | ForEach-Object { "$($_.RuleId):$($_.Rows)" }) -join ",") "T-EXCL:1,T-PS:1" -Message "model.Allowlisted: allowlisted rows per rule"
    Assert-Equal "$($model.Workbook.FileName)|$($model.Workbook.Available)|$($model.Workbook.TimelineSheet)|$($model.Workbook.FindingsSheet)" "timeline.xlsx|False|Timeline|Findings" -Message "model.Workbook"
    $hashes = @($model.Files.Hashes)
    $timelineHash = ($hashes | Where-Object { $_.Name -eq "timeline.csv" })
    Assert-Equal "$($model.Files.TimelineCsv)|$($model.Files.FindingsCsv)|$($timelineHash.Sha256)|$($timelineHash.Bytes)" "timeline.csv|findings.csv|$((Get-FileHash -LiteralPath $timelinePath -Algorithm SHA256).Hash)|$((Get-Item -LiteralPath $timelinePath).Length)" -Message "model.Files: names and the timeline's SHA-256"
    Write-TestResult -Succeeded (@($hashes | Where-Object { $_.Name -eq "findings.csv" }).Count -eq 1) -Message "model.Files.Hashes includes findings.csv"
    Write-TestResult -Succeeded ($model.Method[0] -match 'from the 69 rows') -Message "model.Method describes the method"

    # Other collection-info shapes: none (log only), and the builder's object
    $workbook = Join-Path $workDir "timeline.xlsx"
    New-TestTextFile $workbook "not really a workbook"
    $logOnly = New-ReportModel -Rows $rows -Findings $findings -CollectorLogPath (Join-Path $fixtureDir "collection_log.txt") -WorkbookPath $workbook -MftDays 0
    Assert-Equal "$($logOnly.Collection.ComputerName)|$($logOnly.Collection.CollectorUser)|$($logOnly.Collection.Mode)|$($logOnly.Collection.TargetTimeZoneId)|$($logOnly.Workbook.Available)" "WS01|examiner|Live||True" -Message "model without collection_info.json: facts from the collector log and the SystemInfo rows"
    $logOnlyCaveats = @($logOnly.Caveats)
    Write-TestResult -Succeeded ((@($logOnlyCaveats | Where-Object { $_ -match 'time zone is unknown' }).Count -eq 1) -and (@($logOnlyCaveats | Where-Object { $_ -match 'metadata' }).Count -eq 1) -and -not (@($logOnlyCaveats | Where-Object { $_ -match 'workbook|MftDays' }).Count)) -Message "caveats: unknown time zone and metadata; none for an existing workbook or -MftDays 0"
    Write-TestResult -Succeeded (@($logOnly.Files.Hashes | Where-Object { $_.Name -eq "timeline.xlsx" }).Count -eq 1) -Message "an available workbook is hashed"
    # Get-CollectionInfo's shape: for a mounted image its ComputerName is the
    # computer the collector ran on, not the examined one
    $builderInfo = [PSCustomObject]@{
        Source = "collection_info.json"; Mode = "MountedImage"; CollectionStartUtc = [datetime]::new(2026, 3, 10, 12, 0, 0, [System.DateTimeKind]::Utc)
        TargetTimeZone = $zone; SecretsIncluded = $false; ThunderbirdIndexIncluded = $false; ComputerName = "COLLECTORPC"
    }
    $builderModel = New-ReportModel -Rows $rows -Findings $findings -CollectionInfo $builderInfo
    Assert-Equal "$($builderModel.Collection.TargetTimeZoneId)|$(Format-TestUtc $builderModel.Collection.CollectionStartUtc)|$($builderModel.Collection.Mode)|$($builderModel.Collection.ComputerName)|$($builderModel.Collection.ComputerNameSource)|$($builderModel.Collection.CollectorHost)" "Pacific Standard Time|2026-03-10 12:00:00|MountedImage|WS01|systeminfo.txt|COLLECTORPC" -Message "model from the builder's Get-CollectionInfo object: a mounted image's computer from the SystemInfo row, not the collector host"
    Write-TestResult -Succeeded (@($builderModel.Caveats | Where-Object { $_ -match 'mounted disk image' }).Count -eq 1) -Message "caveats: a mounted-image collection"
    $builderInfo | Add-Member -NotePropertyName TargetTimeZoneAssumed -NotePropertyValue $true
    $assumedModel = New-ReportModel -Rows $rows -Findings $findings -CollectionInfo $builderInfo -WorkbookPath $workbook -WorkbookAvailable:$false
    Write-TestResult -Succeeded ($assumedModel.Collection.TargetTimeZoneAssumed -and @($assumedModel.Caveats | Where-Object { $_.Contains("time zone was not recorded in the collection: Pacific Standard Time") }).Count -eq 1) -Message "an assumed time zone is marked in the model and named in a caveat"
    Write-TestResult -Succeeded (@($assumedModel.Caveats | Where-Object { $_.Contains("any Findings sheet or Finding column in it is from an earlier report") }).Count -eq 1 -and -not @($assumedModel.Files.Hashes | Where-Object { $_.Name -eq "timeline.xlsx" }).Count) -Message "a workbook that exists but was not updated: the caveat says its findings are stale, and it is not hashed"
    Assert-Equal (($model.Rules | Where-Object { $_.Id -eq "T-SVC" }).Title) "Suspicious service" -Message "model.Rules: titles without the {{group}} placeholder"

    # --- Users, file times and Snapshot rows (synthetic rows) ---
    function New-TestRow {
        param([string]$Time, [string]$User = "", [string]$Source = "Prefetch", [string]$EventType = "Execution", [string]$Description = "Prefetch execution: A.EXE")
        return @{ Timestamp = $Time; Source = $Source; EventType = $EventType; Description = $Description; User = $User; Details = "" }
    }
    $userRows = @(
        (New-TestRow "2026-02-01 10:00:00.000" "WS01\alice"), (New-TestRow "2026-02-01 10:00:01.000" "alice"), (New-TestRow "2026-02-01 10:00:02.000" ".\Alice"),
        (New-TestRow "2026-02-01 10:00:03.000" "OTHERHOST\alice"), (New-TestRow "2026-02-01 10:00:04.000" "CONTOSO\alice"), (New-TestRow "2026-02-01 10:00:05.000" "CONTOSO\alice"),
        (New-TestRow "2026-02-01 10:00:06.000" "S-1-5-80-1111-2222-3333-4444-5555"), (New-TestRow "2026-02-01 10:00:07.000" "S-1-5-82-1-2-3-4-5"),
        (New-TestRow "2026-02-01 10:00:08.000" "S-1-5-83-1-2-3-4-5"), (New-TestRow "2026-02-01 10:00:09.000" "S-1-5-90-0-3"), (New-TestRow "2026-02-01 10:00:10.000" "S-1-5-21-1-2-3-1001"),
        (New-TestRow "2026-02-01 10:00:11.000" "NT AUTHORITY\SYSTEM"), (New-TestRow "2026-02-01 10:00:12.000" "MicrosoftAccount\alice@example.com"),
        (New-TestRow -Time "2019-05-01 08:00:00.000" -Source "AppCompatCache" -EventType "FileLastModified" -Description "ShimCache entry (file last modified): C:\tools\x.exe"),
        (New-TestRow -Time "2026-02-01 11:00:00.000" -Source "Memory-Processes" -EventType "Snapshot" -Description "Process in memory: x.exe (PID: 1, PPID: 0)")
    )
    $userModel = New-ReportModel -Rows $userRows -CollectionInfo ([PSCustomObject]@{ Mode = "Live"; ComputerName = "WS01" })
    $perUser = @{}
    foreach ($entry in $userModel.Activity.PerUser) { $perUser[$entry.User] = "$($entry.Rows)/$($entry.IsSystem)" }
    Assert-Equal "$($perUser['alice'])|$($perUser['OTHERHOST\alice'])|$($perUser['CONTOSO\alice'])|$($perUser['MicrosoftAccount\alice@example.com'])|$($perUser['NT AUTHORITY\SYSTEM'])" "3/False|1/False|2/False|1/False|1/True" -Message "PerUser: an older timeline's WS01\alice and .\Alice count with alice (the examined computer); OTHERHOST\alice, CONTOSO\alice and MicrosoftAccount\... stay apart"
    Assert-Equal "$($perUser['S-1-5-80-1111-2222-3333-4444-5555'])|$($perUser['S-1-5-82-1-2-3-4-5'])|$($perUser['S-1-5-83-1-2-3-4-5'])|$($perUser['S-1-5-90-0-3'])|$($perUser['S-1-5-21-1-2-3-1001'])" "1/True|1/True|1/True|1/True|1/False" -Message "PerUser: unnamed service, AppPool, virtual machine and Window Manager SIDs are not people; an account SID is"
    Assert-Equal (@($userModel.Collection.Users) -join ",") "alice,CONTOSO\alice,MicrosoftAccount\alice@example.com,OTHERHOST\alice" -Message "Key facts users: one entry per account, no system accounts or SIDs"
    $oldDay = $userModel.Activity.PerDay | Where-Object { $_.Day -eq "2019-05-01" }
    Assert-Equal "$($oldDay.Rows)|$($oldDay.NonFileRows)" "1|0" -Message "PerDay: a ShimCache FileLastModified row (a file time) is not counted as activity (NonFileRows)"
    Write-TestResult -Succeeded (@($userModel.Coverage.Notes | Where-Object { $_ -eq "1 row(s) are Snapshot rows: the state when the evidence was collected (or when a memory dump was captured), not events." }).Count -eq 1) -Message "Notes: Snapshot rows are the state when collected or when the memory dump was captured"
    # The collector user as the User column names it: a live collection's
    # local account without the computer's name (a domain account and a
    # mounted image's collector account stay as they are)
    $collectorUsers = @(foreach ($pair in @(@("Live", "WS01\examiner"), @("Live", ".\examiner"), @("Live", "ws01\examiner"), @("Live", "CORP\examiner"), @("MountedImage", "WS01\examiner"))) {
            (New-ReportModel -Rows $userRows -CollectionInfo ([PSCustomObject]@{ Mode = $pair[0]; ComputerName = "WS01"; CollectorUser = $pair[1] })).Collection.CollectorUser
        })
    Assert-Equal ($collectorUsers -join "|") "examiner|examiner|examiner|CORP\examiner|WS01\examiner" -Message "Collection.CollectorUser: a live collection's WS01\examiner or .\examiner is examiner, as in the User column; CORP\examiner and a mounted image's collector account are kept"

    # --- The examined computer of a mounted-image collection ---
    $imageJson = [PSCustomObject]@{ Mode = "MountedImage"; ComputerName = "COLLECTORPC"; CollectionStartUtc = "2026-02-02T00:00:00Z" }
    $imageModel = New-ReportModel -Rows $userRows -CollectionInfo $imageJson
    $imageCaveats = @($imageModel.Caveats)
    Assert-Equal "$($imageModel.Collection.ComputerName)|$($imageModel.Collection.ComputerNameSource)|$($imageModel.Collection.CollectorHost)" "||COLLECTORPC" -Message "mounted image, name not known: no computer name (collection_info.json names only the collector host)"
    Write-TestResult -Succeeded (@($imageCaveats | Where-Object { $_.StartsWith("The examined computer's name is not known") -and $_.Contains("COLLECTORPC is the computer the collection was made on, not the examined one") }).Count -eq 1) -Message "caveats: the examined computer's name is not known, and the collector host is named as such"
    Write-TestResult -Succeeded (@($imageCaveats | Where-Object { $_.Contains("running programs and network connections come only from the memory dump") }).Count -eq 1 -and -not @($imageCaveats | Where-Object { $_.Contains("live state (running programs") }).Count) -Message "caveats: a mounted image with memory rows says running programs come from the memory dump"
    Write-TestResult -Succeeded (@($imageModel.Activity.PerUser | Where-Object { $_.User -eq "WS01\alice" }).Count -eq 1) -Message "PerUser: without the examined computer's name, an older HOST\alice stays as it is"
    $hiveLog = Join-Path $workDir "hive_builder_log.txt"
    New-TestTextFile $hiveLog ("[2026-02-02 01:00:00] === Windows 11 Forensic Timeline Builder Started ===`r`n" +
        "[2026-02-02 01:00:05]   Examined computer name (SYSTEM hive): WS01`r`n[2026-02-02 01:00:06]   Examined computer name (SYSTEM hive): LATER`r`n")
    $hiveModel = New-ReportModel -Rows $userRows -CollectionInfo $imageJson -BuilderLogPath $hiveLog
    Assert-Equal "$($hiveModel.Collection.ComputerName)|$($hiveModel.Collection.ComputerNameSource)|$($hiveModel.Collection.CollectorHost)|$(@($hiveModel.Caveats | Where-Object { $_ -match 'name is not known' }).Count)" "WS01|SYSTEM hive|COLLECTORPC|0" -Message "mounted image: the computer name from the builder log's SYSTEM hive line (-ReportOnly), the collector host kept apart"
    Assert-Equal (($hiveModel.Activity.PerUser | Where-Object { $_.User -eq "alice" }).Rows) 3 -Message "PerUser: with the hive's name, an older WS01\alice counts with alice"
    $reportView = [PSCustomObject]@{ Mode = "MountedImage"; ComputerName = "IMAGED-PC"; ComputerNameSource = "SYSTEM hive"; CollectorHost = "COLLECTORPC"; ExaminedComputerName = "IMAGED-PC" }
    $viewModel = New-ReportModel -Rows $userRows -CollectionInfo $reportView -BuilderLogPath $hiveLog
    Assert-Equal "$($viewModel.Collection.ComputerName)|$($viewModel.Collection.ComputerNameSource)|$($viewModel.Collection.CollectorHost)" "IMAGED-PC|SYSTEM hive|COLLECTORPC" -Message "mounted image: the builder's report view (a name with its source) is used as it is"
    $againModel = New-ReportModel -Rows $userRows -CollectionInfo $viewModel.Collection
    Assert-Equal "$($againModel.Collection.ComputerName)|$($againModel.Collection.CollectorHost)" "IMAGED-PC|COLLECTORPC" -Message "an earlier model's Collection gives the same computer and collector host"

    # --- A builder run that ended incomplete (exit code 2) ---
    $incompleteLog = Join-Path $workDir "incomplete_builder_log.txt"
    New-TestTextFile $incompleteLog ("[2026-02-02 01:00:00] === Windows 11 Forensic Timeline Builder Started ===`r`n" +
        "[2026-02-02 01:00:10] ERROR: Unexpected error at line 4321 (rest of this step skipped): Exception calling ""Open"" with ""1"" argument(s).`r`n" +
        "[2026-02-02 01:00:20] ERROR: Unexpected error at line 9876 (rest of this step skipped): You cannot call a method on a null-valued expression.`r`n" +
        "[2026-02-02 01:00:30] ERROR: 2 of 40 input file(s) disappeared during the run -- rows from them may be missing from the timeline (not if a file was deleted after its parser read it):`r`n" +
        "[2026-02-02 01:00:30] WARNING:   Missing in USB\: 2 file(s)`r`n")
    $incomplete = New-ReportModel -Rows $userRows -CollectionInfo ([PSCustomObject]@{ Mode = "Live"; ComputerName = "WS01" }) -BuilderLogPath $incompleteLog
    $completeness = $incomplete.Coverage.TimelineCompleteness
    Assert-Equal "$($completeness.Incomplete)|$($completeness.MissingInputFiles)|$($completeness.UnexpectedErrors)|$(@($completeness.Lines).Count)" "True|2|2|2" -Message "Coverage.TimelineCompleteness: input files gone and unexpected errors from the builder log"
    $incompleteCaveats = @($incomplete.Caveats)
    Write-TestResult -Succeeded ($incompleteCaveats[1].StartsWith("The timeline is incomplete: 2 input file(s) disappeared while it was built (the builder ended with exit code 2)") -and
        $incompleteCaveats[2].StartsWith("The builder hit 2 unexpected error(s) and skipped the rest of those steps")) -Message "caveats: the incomplete timeline right after the leads-not-verdict caveat"
    Write-TestResult -Succeeded (@($incomplete.Coverage.Notes | Where-Object { $_.StartsWith("The timeline is incomplete:") -or $_.StartsWith("The builder hit ") }).Count -eq 0) -Message "Coverage.Notes does not repeat the incomplete timeline (the report shows TimelineCompleteness first in Evidence coverage, and the caveats)"
    $bannerLog = Join-Path $workDir "banner_builder_log.txt"
    New-TestTextFile $bannerLog ("[2026-02-02 01:00:30] ERROR: 3 of 40 input file(s) disappeared during the run -- rows from them may be missing`r`n" +
        "[2026-02-02 01:05:00] ERROR: === Timeline Builder Completed WITH 4 MISSING INPUT FILE(S) -- timeline incomplete ===`r`n" +
        "[2026-02-02 01:05:00] ERROR: === Timeline Builder Completed WITH 1 UNEXPECTED ERROR(S) -- timeline may be incomplete ===`r`n")
    $banner = (New-ReportModel -Rows $userRows -BuilderLogPath $bannerLog).Coverage.TimelineCompleteness
    Assert-Equal "$($banner.Incomplete)|$($banner.MissingInputFiles)|$($banner.UnexpectedErrors)" "True|4|1" -Message "-ReportOnly: the end banners of the original run's log count (the larger count wins)"
    $passed = (New-ReportModel -Rows $userRows -MissingInputFiles 5 -UnexpectedErrors 0).Coverage.TimelineCompleteness
    Assert-Equal "$($passed.Incomplete)|$($passed.MissingInputFiles)|$($passed.UnexpectedErrors)|$(@($passed.Lines).Count)" "True|5|0|1" -Message "the builder's own counts (-MissingInputFiles) without a log"
    Assert-Equal "$($model.Coverage.TimelineCompleteness.Incomplete)|$(@($model.Caveats | Where-Object { $_ -match 'incomplete' }).Count)" "False|0" -Message "a complete run: no incomplete caveat"

    # --- A memory dump the builder found but did not analyze (Windows ARM64,
    # skipped at its prompt, no Volatility 3, or not found) ---
    $memoryLog = Join-Path $workDir "memory_builder_log.txt"
    New-TestTextFile $memoryLog ("[2026-02-02 01:00:00] === Windows 11 Forensic Timeline Builder Started ===`r`n" +
        "[2026-02-02 01:00:05] Memory dump detected: C:\x\T_memory_dump.dmp (Windows ARM64).`r`n" +
        "[2026-02-02 01:00:05]   Memory dump not analyzed: T_memory_dump.dmp (8.0 GB): a Windows ARM64 dump, which Volatility 3 cannot analyze; examine it in WinDbg.`r`n")
    $memoryModel = New-ReportModel -Rows $userRows -BuilderLogPath $memoryLog
    $memoryNotes = @($memoryModel.Coverage.Notes | Where-Object { $_ -eq "A memory dump of this collection was not analyzed: T_memory_dump.dmp (8.0 GB): a Windows ARM64 dump, which Volatility 3 cannot analyze; examine it in WinDbg." })
    $memoryCaveats = @($memoryModel.Caveats | Where-Object { $_.StartsWith("A memory dump of this collection exists but was not analyzed") })
    Assert-Equal "$($memoryNotes.Count)|$($memoryCaveats.Count)" "1|1" -Message "a memory dump not analyzed: named in Coverage.Notes with the reason, and a caveat"
    Assert-Equal "$(@($model.Coverage.Notes | Where-Object { $_ -match 'memory dump of this collection' }).Count)|$(@($model.Caveats | Where-Object { $_ -match 'memory dump of this collection' }).Count)" "0|0" -Message "no such log line: no memory-dump note or caveat"

    # =========================================================
    # report-model.json
    # =========================================================
    $jsonPath = Join-Path $workDir "report-model.json"
    Export-ReportModelJson -Model $model -Path $jsonPath
    $jsonBytes = [System.IO.File]::ReadAllBytes($jsonPath)
    Assert-Equal "$($jsonBytes[0])|$(@($jsonBytes | Where-Object { $_ -gt 127 }).Count)" "123|0" -Message "report-model.json: no BOM, ASCII only"
    $jsonText = [System.IO.File]::ReadAllText($jsonPath)
    Assert-Equal ([regex]::Matches($jsonText, "(?<!\r)\n").Count) 0 -Message "report-model.json uses CRLF line ends"
    Write-TestResult -Succeeded ($jsonText.Contains('"CollectionStartUtc": "2026-03-10T12:00:00.000Z"')) -Message "report-model.json: dates are ISO 8601 UTC"
    $parsed = $jsonText | ConvertFrom-Json
    Assert-Equal "$($parsed.Counts.High)|$($parsed.Findings[0].Id)|$($parsed.Findings[2].Evidence[3].RowNumber)|$(@($parsed.Activity.PerHourUtc).Count)" "6|F001|$($burstRows[6])|24" -Message "report-model.json parses back with the same content"
    $special = [TimelineReport.Json]::Serialize([PSCustomObject]@{
        Text  = "caf" + [char]0xE9 + " <b>&" + [char]0x2603 + "`t"
        When  = [datetime]::new(2026, 1, 2, 3, 4, 5, 6, [System.DateTimeKind]::Utc)
        List  = @(1, $null, $true, 2.5)
        Empty = @()
        Map   = [ordered]@{ a = "x" }
    })
    Write-TestResult -Succeeded ($special.Contains('"Text": "caf\u00e9 \u003cb\u003e\u0026\u2603\t"') -and $special.Contains('"When": "2026-01-02T03:04:05.006Z"') -and $special.Contains('"Empty": []') -and $special -match '"List": \[\s+1,\s+null,\s+true,\s+2\.5\s+\]' -and $special -match '"Map": \{\s+"a": "x"\s+\}') -Message "JSON writer: \u escapes for non-ASCII and < > &, ISO dates, arrays, nulls, dictionaries"

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all $($script:checks) report engine checks passed (PowerShell $($PSVersionTable.PSVersion))" -ForegroundColor Green
    exit 0
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    exit 1
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
