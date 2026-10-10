# =============================================================
# Secrets handling parser test
# Builds a synthetic triage collection made as if by the collector's
# -IncludeSecrets switch: the browser settings and session files are
# UNREDACTED (Chromium Local State / Preferences / Secure Preferences,
# Firefox prefs.js, and Chromium / Firefox session files all still hold
# canary secret values), collection_info.json has SecretsIncluded true, and
# there is a top-level Secrets\ folder with DPAPI credential material (and, to
# exercise every exclusion, files named $MFT, Preferences, a ScheduledTasks_XML
# task, SRUDB.dat and an AntiVirus vendor folder there, all holding the
# canary). A control user profile folder named "Secrets" (not the top-level
# credential folder) holds an ordinary artifact that must still be parsed.
#
# Runs timeline-builder.ps1 -Sources Browser,FileSystem,ScheduledTasks,SRUM,
# AntiVirus and checks:
#   - the canary appears nowhere in the timeline CSV, the builder log or the
#     builder output (the builder blanks the secret members before parsing
#     the unredacted browser files);
#   - no timeline row has a RawPath under the top-level Secrets\ folder (no
#     parser reads it: the $MFT, ScheduledTasks_XML, SRUDB.dat and AntiVirus
#     searches and every Find-ArtifactFiles caller all skip it);
#   - the "Secrets" control user's ordinary artifacts still produced rows;
#   - the "made with -IncludeSecrets" log line appears;
#   - the browser files were actually parsed (non-secret settings and URLs
#     produced rows), so the canary-free result is not vacuous.
#
# Needs Administrator rights, like the builder itself (GitHub Actions Windows
# runners are elevated). For a local run without them, pass -BuilderPath with
# a copy of the builder that has no admin check, kept inside the repository
# (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-SecretsHandling.ps1
# =============================================================
param(
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$builder = (Resolve-Path -LiteralPath $builder).Path
# Written into every secret or private field; must never reach the output
$canary = "CANARY-SECRET-VALUE"
$script:failures = 0

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-SecretsHandling.ps1::$Message" }
}

# The builder refuses to run without Administrator rights (a -BuilderPath
# copy may not)
if (-not $BuilderPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-TestResult -Succeeded $false -Message "Administrator rights are required (the builder needs them). Run elevated, or pass -BuilderPath with a builder copy without the admin check."
        exit 1
    }
}

# Run the builder with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path

# Runs the builder on a collection (CSV only). Every source whose parser walks
# the whole collection with its own recursive search is selected, so the
# Secrets\ exclusions on all of them are exercised.
function Invoke-TimelineBuilder {
    param([string]$CollectionPath, [string]$OutputFile)
    $ErrorActionPreference = "Continue"
    # One comma-joined string: powershell.exe -File would otherwise treat the
    # second source as a positional argument (the builder splits on commas)
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath $CollectionPath -Sources "Browser,FileSystem,ScheduledTasks,SRUM,AntiVirus" -OutputFile $OutputFile -NoExcel -NoReport -Viewer None 2>&1
    return , @($output | ForEach-Object { "$_" })
}

# Writes a text file (UTF-8, no BOM)
function New-TestTextFile {
    param([string]$Path, [string]$Text)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function New-TestBinaryFile {
    param([string]$Path, [byte[]]$Bytes)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

# base::Pickle as Chromium writes it (see Test-BrowserParsers.ps1)
function New-TestPickle {
    param([object[]]$Fields)
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    $writer.Write([int32]0)
    foreach ($field in $Fields) {
        switch ($field[0]) {
            "int"   { $writer.Write([int32]$field[1]) }
            "int64" { $writer.Write([int64]$field[1]) }
            default {
                if ($field[0] -eq "str16") { $bytes = [System.Text.Encoding]::Unicode.GetBytes([string]$field[1]) }
                else { $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$field[1]) }
                $length = if ($field[0] -eq "str16") { ([string]$field[1]).Length } else { $bytes.Length }
                $writer.Write([int32]$length)
                $writer.Write($bytes)
                while (($stream.Length % 4) -ne 0) { $writer.Write([byte]0) }
            }
        }
    }
    $writer.Flush()
    $data = $stream.ToArray()
    [System.BitConverter]::GetBytes([int32]($data.Length - 4)).CopyTo($data, 0)
    return , $data
}

# SNSS file (version 3) with one navigation entry per URL and -PageState
function New-TestSnss {
    param([int]$CommandId, [string[]]$Urls, [string]$PageState)
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    $writer.Write([System.Text.Encoding]::ASCII.GetBytes("SNSS"))
    $writer.Write([int32]3)
    $index = 0
    foreach ($url in $Urls) {
        $payload = New-TestPickle @(@("int", 1), @("int", $index), @("str", $url), @("str16", "Title $index"), @("str", $PageState),
            @("int", 1), @("int", 0), @("str", ""), @("int", 1), @("str", $url), @("int", 0), @("int64", 13418000000000000), @("str16", ""), @("int", 200))
        $writer.Write([uint16]($payload.Length + 1))
        $writer.Write([byte]$CommandId)
        $writer.Write($payload)
        $index++
    }
    $writer.Flush()
    return , $stream.ToArray()
}

# mozLz4 file whose LZ4 block holds the text uncompressed (literals only)
function New-TestMozLz4 {
    param([string]$Text)
    $data = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $out = New-Object System.Collections.Generic.List[byte]
    $out.AddRange([System.Text.Encoding]::ASCII.GetBytes("mozLz40" + [char]0))
    $out.AddRange([System.BitConverter]::GetBytes([int32]$data.Length))
    $out.Add([byte]([Math]::Min($data.Length, 15) * 16))
    if ($data.Length -ge 15) {
        $rest = $data.Length - 15
        while ($rest -ge 255) { $out.Add([byte]255); $rest -= 255 }
        $out.Add([byte]$rest)
    }
    $out.AddRange($data)
    return , $out.ToArray()
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("secrets-handling-test-" + [guid]::NewGuid().ToString("N"))
# The builder writes its log under <builder dir>\reports\timeline_<ts>\
$reportsDir = Join-Path (Split-Path $builder -Parent) "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
try {
    $collection = Join-Path $workDir "collection"
    $userDir = Join-Path $collection "Browser\alice"
    $chromeDir = Join-Path $userDir "Chrome"
    $profileDir = Join-Path $chromeDir "Default"
    $ffDir = Join-Path $userDir "Firefox\abcd1234.default-release"

    New-TestTextFile -Path (Join-Path $collection "collection_info.json") `
        -Text '{"SchemaVersion":1,"Mode":"Live","TargetDrive":"C","TargetRoot":"C:\\","CollectionStartUtc":"2026-03-03T00:00:00Z","CollectorTimeZoneId":"UTC","TargetTimeZoneId":"UTC","SecretsIncluded":true,"ThunderbirdIndexIncluded":false}'

    # --- Unredacted browser files: a non-secret setting (produces a row) and
    # every member the collector would blank still holding the canary ---
    New-TestTextFile -Path (Join-Path $chromeDir "Local State") -Text ('{"browser":{"enabled_labs_experiments":["enable-quic@2"]},' +
        '"os_crypt":{"encrypted_key":"' + $canary + '-1","app_bound_encrypted_key":"' + $canary + '-2"},' +
        '"private_key_encrypted_data":"' + $canary + '-3","sync":{"keystore_encryption_key_state":"' + $canary + '-4"},' +
        '"gcm":{"cached_target_token":"' + $canary + '-5"},"media":{"device_id_salt":"' + $canary + '-6"}}')
    New-TestTextFile -Path (Join-Path $profileDir "Preferences") -Text ('{"homepage":"https://home.example.com/","homepage_is_newtabpage":false,' +
        '"download":{"default_directory":"D:\\Drop"},' +
        '"password_hash_data_list":[{"hash":"' + $canary + '-7","salt":"' + $canary + '-8"}],' +
        '"account_info":[{"email":"' + $canary + '@example.com"}],' +
        '"gcm":{"cached_target_token":"' + $canary + '-9"},"media":{"device_id_salt":"' + $canary + '-10"},' +
        '"profile":{"content_settings":{"exceptions":{"cookies":{"https://' + $canary + '.example,*":{"setting":1}}}}}}')
    New-TestTextFile -Path (Join-Path $profileDir "Secure Preferences") -Text ('{"extensions":{"settings":{}},' +
        '"edge":{"policy_recovery_token":"' + $canary + '-11"},"protection":{"macs":{"homepage":"' + $canary + '-12"}}}')
    New-TestBinaryFile -Path (Join-Path $profileDir "Sessions\Session_13418000000000002") `
        -Bytes (New-TestSnss -CommandId 6 -Urls @("https://session.example.com/") -PageState "$canary-13 form contents")

    New-TestTextFile -Path (Join-Path $ffDir "prefs.js") -Text (@(
        '// Mozilla User Preferences',
        'user_pref("network.proxy.type", 1);',
        'user_pref("network.proxy.http", "10.0.0.5");',
        ('user_pref("services.sync.tokenserver.token", "' + $canary + '-14");'),
        ('user_pref("dom.push.userAgentID", "' + $canary + '-15");'),
        ('user_pref("extensions.example.secret", "' + $canary + '-16");')
    ) -join "`r`n")
    $ffLastAccessed = [DateTimeOffset]::new([datetime]::new(2026, 3, 2, 14, 0, 0, [System.DateTimeKind]::Utc)).ToUnixTimeMilliseconds()
    New-TestBinaryFile -Path (Join-Path $ffDir "sessionstore.jsonlz4") `
        -Bytes (New-TestMozLz4 ('{"windows":[{"tabs":[{"entries":[{"url":"https://ff-open.example.org/","title":"FF Open",' +
            '"formdata":{"id":{"q":"' + $canary + '-17"}},"postdata_b64":"' + $canary + '-18"}],"index":1,' +
            '"storage":{"https://ff-open.example.org":{"k":"' + $canary + '-19"}},"userTypedValue":"' + $canary + '-20",' +
            '"lastAccessed":' + $ffLastAccessed + '}],' +
            '"cookies":[{"host":".example.org","name":"sid","value":"' + $canary + '-21"}]}]}'))

    # --- Secrets\ folder: credential material the builder must never read,
    # plus files with names several recursive searches look for (a $MFT, a
    # Preferences file, a ScheduledTasks_XML task, a SRUDB.dat and an AntiVirus
    # vendor folder), all under Secrets\, to prove every such search skips it ---
    New-TestTextFile -Path (Join-Path $collection "Secrets\alice\AppData\Roaming\Microsoft\Protect\S-1-5-21-1-2-3-1001\11111111-2222-3333-4444-555555555555") -Text "$canary-masterkey"
    New-TestTextFile -Path (Join-Path $collection "Secrets\alice\AppData\Local\Microsoft\Vault\GUID\Policy.vpol") -Text "$canary-vault"
    New-TestTextFile -Path (Join-Path $collection "Secrets\alice\Preferences") -Text ('{"homepage":"https://' + $canary + '.secret/"}')
    New-TestTextFile -Path (Join-Path $collection "Secrets\System\System32\Microsoft\Protect\S-1-5-18\`$MFT") -Text "$canary-notanmft"
    # A valid scheduled-task XML planted in a ScheduledTasks_XML folder under
    # Secrets\: if parsed it would add a row (RawPath under Secrets, canary in
    # the action) -- it must not be.
    New-TestTextFile -Path (Join-Path $collection "Secrets\alice\AppData\Local\Microsoft\Vault\ScheduledTasks_XML\PlantedUnderSecrets") -Text (@(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<Task>',
        '  <RegistrationInfo><Date>2026-03-01T12:00:00</Date><URI>\PlantedUnderSecrets</URI></RegistrationInfo>',
        ('  <Actions><Exec><Command>' + $canary + '-task.exe</Command></Exec></Actions>'),
        '</Task>'
    ) -join "`r`n")
    # A SRUDB.dat and an AntiVirus vendor folder under Secrets\: the SRUM and
    # AntiVirus searches must skip them too.
    New-TestTextFile -Path (Join-Path $collection "Secrets\alice\AppData\Local\Microsoft\Vault\SRUDB.dat") -Text "$canary-srudb"
    New-TestTextFile -Path (Join-Path $collection "Secrets\alice\AppData\Local\Microsoft\Vault\AntiVirus\Symantec_SEP\probe.log") -Text ("0123456789AB,1,2,3," + $canary + "-av,infected")

    # Control: a user profile folder that happens to be named "Secrets" (not
    # the top-level credential folder). Its ordinary artifacts MUST still be
    # parsed -- the exclusion is anchored to the collection's top-level
    # Secrets\, so this user is unaffected.
    $secretsUserFlag = "probe-flag-secretsuser@7"
    New-TestTextFile -Path (Join-Path $collection "Browser\Secrets\Chrome\Local State") -Text ('{"browser":{"enabled_labs_experiments":["' + $secretsUserFlag + '"]}}')

    $timelineCsv = Join-Path $workDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $builderOutput = Invoke-TimelineBuilder -CollectionPath $collection -OutputFile $timelineCsv
    if (-not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the builder wrote no timeline"
        exit 1
    }
    $rows = @(Import-Csv -LiteralPath $timelineCsv)
    $csvText = [System.IO.File]::ReadAllText($timelineCsv)
    $outputText = ($builderOutput -join "`n")

    # The canary must appear nowhere
    Write-TestResult -Succeeded ($csvText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or private value (canary) in the timeline CSV"
    Write-TestResult -Succeeded ($outputText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or private value (canary) in the builder output"
    $newReports = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $reportsBefore -notcontains $_.FullName })
    $logFiles = @($newReports | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter "*.txt" -File -ErrorAction SilentlyContinue })
    $logText = ($logFiles | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n"
    Write-TestResult -Succeeded ($logFiles.Count -gt 0 -and $logText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or private value (canary) in the builder log"

    # No row has a RawPath under the collection's top-level Secrets\ folder
    # (anchored to that folder, so the "Secrets" control user is not caught)
    $secretsRootPath = (Join-Path $collection "Secrets") + '\'
    $hasRawPath = $rows.Count -eq 0 -or ($null -ne $rows[0].PSObject.Properties["RawPath"])
    $secretRows = @($rows | Where-Object { $_.PSObject.Properties["RawPath"] -and $_.RawPath -and $_.RawPath.StartsWith($secretsRootPath, [System.StringComparison]::OrdinalIgnoreCase) })
    Write-TestResult -Succeeded ($hasRawPath -and $secretRows.Count -eq 0) -Message "no timeline row has a RawPath under the top-level Secrets\ folder$(if ($secretRows.Count) { ' (' + $secretRows.Count + ' found: ' + (($secretRows | ForEach-Object { $_.RawPath }) -join '; ') + ')' })"

    # No parser even walked into the top-level Secrets\ folder: its path never
    # appears in the builder log or output (a recursive search that reached in
    # would log "Parsing: ...\Secrets\..."). This catches the SRUDB.dat and
    # AntiVirus searches, whose planted files do not themselves produce rows.
    $secretsPathSeen = ($logText.IndexOf($secretsRootPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($outputText.IndexOf($secretsRootPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    Write-TestResult -Succeeded (-not $secretsPathSeen) -Message "no parser logged walking into the top-level Secrets\ folder"

    # The SecretsIncluded log line appears (log or console)
    $secretsLine = ($logText -match 'made with -IncludeSecrets') -or ($outputText -match 'made with -IncludeSecrets')
    Write-TestResult -Succeeded $secretsLine -Message "the builder logs that the collection was made with -IncludeSecrets"

    # The browser files were actually parsed (non-secret values produced rows),
    # so the canary-free result above is not simply because nothing was read
    $browserRows = @($rows | Where-Object { $_.Artifact -eq "Browser" })
    Write-TestResult -Succeeded ($browserRows.Count -gt 0) -Message "the unredacted browser files were parsed ($($browserRows.Count) Browser row(s))"
    Write-TestResult -Succeeded ($csvText.Contains("https://home.example.com/")) -Message "a non-secret Chromium setting (homepage) reached the timeline"
    Write-TestResult -Succeeded ($csvText.Contains("https://session.example.com/")) -Message "a non-secret Chromium session URL reached the timeline"
    Write-TestResult -Succeeded ($csvText.Contains("https://ff-open.example.org/")) -Message "a non-secret Firefox session URL reached the timeline"

    # Control: the user profile named "Secrets" is NOT the credential folder;
    # its ordinary artifacts must still be parsed (the exclusion is anchored to
    # the top-level Secrets\ folder, not any folder segment named Secrets)
    Write-TestResult -Succeeded ($csvText.Contains($secretsUserFlag)) -Message "the 'Secrets' control user's artifacts still reached the timeline"

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all secrets handling checks passed ($($rows.Count) rows)" -ForegroundColor Green
    exit 0
}
catch {
    Write-TestResult -Succeeded $false -Message "test setup or run error: $($_.Exception.Message)"
    exit 1
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
