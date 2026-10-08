# =============================================================
# Report rules test
# Dot-sources report\TimelineReport.Engine.ps1 (built by the engine
# workstream; present after integration), loads the real report rules
# (report\report-rules.json) and runs them over a synthetic timeline of
# cases (tests\fixtures\report\rules\cases.csv).
#
# Each fixture row carries its expectation in the RawPath column (the
# engine ignores RawPath when matching), as one or more ";"-separated tags:
#   HIT  <RuleId> [Severity]   the row's Excel row number must appear in a
#                              finding of that rule (and, if given, that
#                              finding's severity must match)
#   MISS <RuleId>              the row must NOT appear in any finding of
#                              that rule
# Row i of the CSV (0-based among data rows) is Excel row i + 2, the same
# numbering Invoke-ReportRules uses.
#
# Exit code 0 = every expectation held (or the engine is not present yet),
# 1 = a failure. Runs in Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-ReportRules.ps1
#   ... -EnginePath <TimelineReport.Engine.ps1>   (override the engine path)
# =============================================================
param(
    [string]$EnginePath = "",
    [string]$RulesPath = "",
    [string]$CasesPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $RulesPath) { $RulesPath = Join-Path $repoRoot "report\report-rules.json" }
if (-not $CasesPath) { $CasesPath = Join-Path $PSScriptRoot "fixtures\report\rules\cases.csv" }

# --- Locate the engine ---------------------------------------
if (-not $EnginePath) {
    $candidates = @(
        (Join-Path $repoRoot "report\TimelineReport.Engine.ps1"),
        "C:\Users\buzz\code\.wt\p3-engine\report\TimelineReport.Engine.ps1"
    )
    $EnginePath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $EnginePath -or -not (Test-Path -LiteralPath $EnginePath)) {
    Write-Host "SKIP: TimelineReport.Engine.ps1 not found (it is built by the engine workstream and will be present after integration). Pass -EnginePath to run now." -ForegroundColor Yellow
    exit 0
}
if (-not (Test-Path -LiteralPath $RulesPath)) {
    Write-Host "FAIL: report rules file not found: $RulesPath" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $CasesPath)) {
    Write-Host "FAIL: cases fixture not found: $CasesPath" -ForegroundColor Red
    exit 1
}

. $EnginePath
Write-Host "Engine : $EnginePath"
Write-Host "Rules  : $RulesPath"
Write-Host "Cases  : $CasesPath"
Write-Host "PowerShell $($PSVersionTable.PSVersion)"
Write-Host ""

# --- Load rules and cases ------------------------------------
$imported = Import-ReportRules -Path $RulesPath
$ruleIds = @{}
foreach ($rule in $imported.Rules) { $ruleIds[$rule.Id] = $true }

# Use the engine's own loader so Excel row numbers match exactly
$rows = Import-TimelineCsvForReport -Path $CasesPath
$findings = Invoke-ReportRules -Rows $rows -Rules $imported

# ruleId -> set of row numbers; "ruleId|rowNumber" -> finding severity
$ruleRows = @{}
$ruleRowSeverity = @{}
foreach ($finding in $findings) {
    $id = [string]$finding.RuleId
    if (-not $ruleRows.ContainsKey($id)) { $ruleRows[$id] = New-Object 'System.Collections.Generic.HashSet[int]' }
    foreach ($rowNumber in $finding.RowNumbers) {
        [void]$ruleRows[$id].Add([int]$rowNumber)
        $ruleRowSeverity["$id|$([int]$rowNumber)"] = [string]$finding.Severity
    }
}

function Test-RuleRow {
    param([string]$Id, [int]$RowNumber)
    return ($ruleRows.ContainsKey($Id) -and $ruleRows[$Id].Contains($RowNumber))
}

# --- Check every tagged case ---------------------------------
$pass = 0
$fail = 0
$hitRules = @{}
$missRules = @{}
for ($i = 0; $i -lt $rows.Count; $i++) {
    $rowNumber = $i + 2
    $raw = "$($rows[$i].RawPath)".Trim()
    if (-not $raw) { continue }
    foreach ($tagText in ($raw -split ';')) {
        $tag = $tagText.Trim()
        if (-not $tag) { continue }
        $parts = @($tag -split '\s+')
        $verb = $parts[0].ToUpperInvariant()
        $id = if ($parts.Count -ge 2) { $parts[1] } else { "" }
        $wantSeverity = if ($parts.Count -ge 3) { $parts[2] } else { "" }
        $label = "row $rowNumber  $tag"

        if ($verb -ne "HIT" -and $verb -ne "MISS") {
            Write-Host "  FAIL  $label -- tag must start with HIT or MISS" -ForegroundColor Red
            if ($env:GITHUB_ACTIONS) { Write-Host "::error::$label -- bad tag" }
            $fail++; continue
        }
        if (-not $id -or -not $ruleIds.ContainsKey($id)) {
            Write-Host "  FAIL  $label -- unknown rule id '$id'" -ForegroundColor Red
            if ($env:GITHUB_ACTIONS) { Write-Host "::error::$label -- unknown rule id" }
            $fail++; continue
        }

        $inFinding = Test-RuleRow -Id $id -RowNumber $rowNumber
        if ($verb -eq "HIT") {
            $hitRules[$id] = $true
            if (-not $inFinding) {
                Write-Host "  FAIL  $label -- expected this row in a '$id' finding, but it is not" -ForegroundColor Red
                if ($env:GITHUB_ACTIONS) { Write-Host "::error::$label -- row not flagged by $id" }
                $fail++; continue
            }
            if ($wantSeverity) {
                $got = $ruleRowSeverity["$id|$rowNumber"]
                if ($got -ne $wantSeverity) {
                    Write-Host "  FAIL  $label -- expected severity $wantSeverity, got $got" -ForegroundColor Red
                    if ($env:GITHUB_ACTIONS) { Write-Host "::error::$label -- severity $got, expected $wantSeverity" }
                    $fail++; continue
                }
            }
            $pass++
        }
        else {
            $missRules[$id] = $true
            if ($inFinding) {
                Write-Host "  FAIL  $label -- this row must NOT be in a '$id' finding, but it is" -ForegroundColor Red
                if ($env:GITHUB_ACTIONS) { Write-Host "::error::$label -- row wrongly flagged by $id" }
                $fail++; continue
            }
            $pass++
        }
    }
}

# --- Coverage: every enabled rule should have a HIT and a MISS case ---
$missingHit = @()
$missingMiss = @()
foreach ($rule in $imported.Rules) {
    if (-not $rule.Enabled) { continue }
    if (-not $hitRules.ContainsKey($rule.Id)) { $missingHit += $rule.Id }
    if (-not $missRules.ContainsKey($rule.Id)) { $missingMiss += $rule.Id }
}
if ($missingHit.Count -gt 0) {
    Write-Host "  FAIL  no HIT case for rule(s): $($missingHit -join ', ')" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error::no HIT case for: $($missingHit -join ', ')" }
    $fail += $missingHit.Count
}
if ($missingMiss.Count -gt 0) {
    Write-Host "  FAIL  no MISS (near-miss) case for rule(s): $($missingMiss -join ', ')" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error::no MISS case for: $($missingMiss -join ', ')" }
    $fail += $missingMiss.Count
}

Write-Host ""
Write-Host "Checked $($imported.Rules.Count) rule(s) against $($rows.Count) case row(s); $($findings.Count) finding(s) produced."
if ($fail -gt 0) {
    Write-Host "FAIL: $fail check(s) failed, $pass passed." -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $pass expectation(s) held; every rule has a hit and a near-miss case." -ForegroundColor Green
exit 0
