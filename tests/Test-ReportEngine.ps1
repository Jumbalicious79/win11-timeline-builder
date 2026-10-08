# =============================================================
# Report engine test (Phase 3)
# Loads report\TimelineReport.Engine.ps1 and checks it on the synthetic
# fixtures in tests\fixtures\report\engine\ (rules.json, timeline.csv,
# collection_info.json, collection_log.txt, timeline_builder_log.txt):
#   - every rule feature: match / anyOf / not* conditions, lists, groupBy
#     (rule, description, user, source, capture and detail:<Key> with both
#     Details styles), threshold windows, escalate with sameKey, allowlist
#     (per rule and "*", duringCollection), disabled rules, numbering and
#     ordering, evidence caps and Excel row numbers;
#   - invalid rules files fail with an error that names the rule and field;
#   - the report model: coverage per source, log clears, boots, audit notes,
#     collector errors, activity per day / hour / source / user, caveats,
#     top findings, file hashes;
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
        @("Command=x | Key=y", "Missing", "")
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
    Write-TestResult -Succeeded (($users -contains "alice") -and ($users -contains "bob") -and ($users -contains "admin1") -and ($users -contains "carol") -and -not ($users -contains "SYSTEM")) -Message "model.Collection.Users: people, domain removed, no system accounts ($($users -join ', '))"

    Assert-Equal "$(Format-TestUtc $model.TimeSpan.FirstUtc)|$(Format-TestUtc $model.TimeSpan.LastUtc)|$($model.TimeSpan.Rows)" "2026-03-09 08:00:00|2026-03-10 12:10:00|69" -Message "model.TimeSpan"
    Assert-Equal "$($model.Counts.High)|$($model.Counts.Medium)|$($model.Counts.Info)" "6|7|8" -Message "model.Counts"
    Assert-Equal ($model.TopFindings -join ",") "F001,F002,F003,F004,F005" -Message "model.TopFindings: the first 5 High/Medium findings"
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
    Assert-Equal "$($collectorErrors.Available)|$($collectorErrors.Count)|$($collectorErrors.LineCount)" "True|2|3" -Message "model.Coverage.CollectorErrors: the collector's error count and its ERROR/WARNING lines"
    Write-TestResult -Succeeded (@($collectorErrors.Lines)[0] -match 'WARNING: Could not copy') -Message "model.Coverage.CollectorErrors.Lines keep the log lines"
    Assert-Equal "$($model.Coverage.BuilderWarnings.Count)" "1" -Message "model.Coverage.BuilderWarnings: the builder log's warnings"
    Write-TestResult -Succeeded (@($model.Coverage.Notes) -contains "Sources parsed by the builder: EventLogs, Prefetch, FileSystem, UsnJournal, SystemInfo.") -Message "model.Coverage.Notes: the sources the builder parsed"

    # Activity, against an independent count
    $zone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time")
    $perDay = @($expectedRows | Group-Object { $_.Timestamp.Substring(0, 10) } | Sort-Object Name | ForEach-Object {
        "$($_.Name)=$($_.Count)/$(@($_.Group | Where-Object { $_.EventType -ne 'FileAccess' -and $_.EventType -ne 'Snapshot' }).Count)"
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
    $aliceRows = @($expectedRows | Where-Object { $_.User -eq "alice" -or $_.User -eq "CORP\alice" }).Count
    $alice = $model.Activity.PerUser | Where-Object { $_.User -eq "alice" }
    Assert-Equal "$($alice.Rows)|$($alice.IsSystem)" "$aliceRows|False" -Message "model.Activity.PerUser merges 'CORP\alice' and 'alice'"
    Assert-Equal ($model.Activity.PerUser | Where-Object { $_.User -eq "SYSTEM" }).IsSystem "True" -Message "model.Activity.PerUser marks system accounts"

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
    $builderInfo = [PSCustomObject]@{
        Source = "collection_info.json"; Mode = "MountedImage"; CollectionStartUtc = [datetime]::new(2026, 3, 10, 12, 0, 0, [System.DateTimeKind]::Utc)
        TargetTimeZone = $zone; SecretsIncluded = $false; ThunderbirdIndexIncluded = $false
    }
    $builderModel = New-ReportModel -Rows $rows -Findings $findings -CollectionInfo $builderInfo
    Assert-Equal "$($builderModel.Collection.TargetTimeZoneId)|$(Format-TestUtc $builderModel.Collection.CollectionStartUtc)|$($builderModel.Collection.Mode)|$($builderModel.Collection.ComputerName)" "Pacific Standard Time|2026-03-10 12:00:00|MountedImage|WS01" -Message "model from the builder's Get-CollectionInfo object"
    Write-TestResult -Succeeded (@($builderModel.Caveats | Where-Object { $_ -match 'mounted disk image' }).Count -eq 1) -Message "caveats: a mounted-image collection"

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
