# =============================================================
# Browser store parser test
# Builds synthetic Chromium and Firefox databases with sqlite3.exe at
# test time (History downloads, Login Data, Cookies, Web Data,
# places.sqlite downloads, cookies.sqlite, formhistory.sqlite,
# permissions.sqlite, logins.json), lays them out like a triage
# collection (Browser\<user>\<browser>\<profile>\), runs
# timeline-builder.ps1 -Sources Browser and checks every row, its time
# and its Details. Every secret column (saved passwords, cookie values,
# autofill and form values, payment cards, addresses, Firefox encrypted
# logins) holds a canary string that must appear nowhere in the
# timeline, the builder log or its output -- also not from a logins.json
# cut off inside an encrypted password. A Cookies database copied
# mid-transaction must be read through its journal.
#
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). For a local run without them, pass
# -BuilderPath with a copy of the builder that has no admin check, kept
# inside the repository (e.g. under the git-ignored reports\ folder).
# sqlite3.exe is looked for where the builder looks; if it is missing,
# the builder is run once so that its Find-Sqlite3Exe downloads it.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-BrowserParsers.ps1
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
$builderDir = Split-Path $builder -Parent
# Written into every secret column; must never reach the timeline or the log
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
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-BrowserParsers.ps1::$Message" }
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

# Runs the builder on a collection (Browser source, CSV only); returns its output
function Invoke-TimelineBuilder {
    param([string]$CollectionPath, [string]$OutputFile)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath $CollectionPath -Sources "Browser" -OutputFile $OutputFile -NoExcel -Viewer None 2>&1
    return , @($output | ForEach-Object { "$_" })
}

# sqlite3.exe in the places the builder's Find-Sqlite3Exe looks, or $null
function Find-TestSqlite3 {
    $onPath = Get-Command "sqlite3" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { return $onPath.Path }
    $toolsDir = Join-Path $builderDir "tools\sqlite3"
    $locations = @(
        (Join-Path $toolsDir "sqlite3.exe"),
        (Join-Path $builderDir "tools\sqlite3.exe"),
        (Join-Path $builderDir "sqlite3.exe"),
        (Join-Path $builderDir "reports\sqlite3\sqlite3.exe"),
        (Join-Path $env:TEMP "sqlite3_timeline\sqlite3.exe")
    )
    foreach ($loc in $locations) {
        if (Test-Path -LiteralPath $loc) { return $loc }
    }
    if (Test-Path -LiteralPath $toolsDir) {
        $found = Get-ChildItem -LiteralPath $toolsDir -Filter "sqlite3.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

# Creates a SQLite database from SQL text (sqlite3 stops at the first error)
function New-TestDatabase {
    param([string]$Path, [string]$Sql)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    $ErrorActionPreference = "Continue"
    $output = $Sql | & $script:sqlite3 -bail $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sqlite3 could not create $Path : $output" }
}

# Creates a database from $Sql, then copies it and its rollback journal to
# $Path and "$Path-journal" while a transaction ($Transaction) is open: with
# a 1-page cache the change spills into the database file, so the copy is
# half-written, like one read from disk mid-write. Only the journal brings
# it back to its committed state.
function New-TestHotJournalDatabase {
    param([string]$Path, [string]$Sql, [string]$Transaction)
    $work = Join-Path $workDir ("hot-" + [guid]::NewGuid().ToString("N") + ".db")
    New-TestDatabase -Path $work -Sql $Sql
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    # .system runs a command while the transaction is open; \\ in "..." is one \
    $copy = '.system copy /y "{0}" "{1}"'
    $commands = @("PRAGMA cache_size = 1;", "BEGIN;", $Transaction,
        ($copy -f $work.Replace('\', '\\'), $Path.Replace('\', '\\')),
        ($copy -f "$work-journal".Replace('\', '\\'), "$Path-journal".Replace('\', '\\')),
        "ROLLBACK;") -join "`n"
    $ErrorActionPreference = "Continue"
    $output = $commands | & $script:sqlite3 -bail $work 2>&1
    if (-not (Test-Path -LiteralPath $Path) -or -not (Test-Path -LiteralPath "$Path-journal")) {
        throw "sqlite3 could not copy $work during a transaction: $output"
    }
}

# Writes an ASCII text file (no BOM)
function New-TestTextFile {
    param([string]$Path, [string]$Text)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::ASCII)
}

# Test time ("yyyy-MM-dd HH:mm:ss.fff" UTC text) as a browser stores it:
# Chromium = microseconds since 1601, PRTime = microseconds since 1970,
# UnixMs / UnixSeconds = milliseconds / seconds since 1970
function ConvertTo-StoredTime {
    param([string]$Text, [ValidateSet("Chromium", "PRTime", "UnixMs", "UnixSeconds")][string]$Format)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $time = [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    # Ticks of 1601-01-01 and 1970-01-01 UTC
    $epoch = if ($Format -eq "Chromium") { 504911232000000000L } else { 621355968000000000L }
    $ticksPerUnit = switch ($Format) { "UnixMs" { 10000L } "UnixSeconds" { 10000000L } default { 10L } }
    $remainder = 0L
    return [Math]::DivRem([long]($time.Ticks - $epoch), $ticksPerUnit, [ref]$remainder)
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("browser-test-" + [guid]::NewGuid().ToString("N"))
$reportsDir = Join-Path $builderDir "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    # --- sqlite3.exe: the builder's copy, or let the builder download it ---
    $script:sqlite3 = Find-TestSqlite3
    if (-not $script:sqlite3) {
        Write-Host "sqlite3.exe not found; running the builder once so that it downloads sqlite3.exe ..."
        $bootstrapDir = Join-Path $workDir "bootstrap"
        # Only the file signature is checked before the builder looks for sqlite3.exe
        New-TestTextFile -Path (Join-Path $bootstrapDir "Browser\setup\Chrome\Default\Top Sites") -Text ("SQLite format 3" + [char]0)
        $null = Invoke-TimelineBuilder -CollectionPath $bootstrapDir -OutputFile (Join-Path $workDir "bootstrap.csv")
        $script:sqlite3 = Find-TestSqlite3
    }
    if (-not $script:sqlite3) {
        Write-TestResult -Succeeded $false -Message "sqlite3.exe is not available (not found, and the builder could not download it)"
        exit 1
    }
    Write-Host "Using sqlite3: $($script:sqlite3)"

    # --- Synthetic collection ---
    $collection = Join-Path $workDir "collection"
    $userDir = Join-Path $collection "Browser\alice"
    New-TestTextFile -Path (Join-Path $collection "collection_info.json") -Text '{"Mode":"Live","CollectionStartUtc":"2026-03-03T00:00:00Z","CollectorTimeZoneId":"UTC","TargetTimeZoneId":"UTC"}'

    # Chromium History (Chrome, current schema): one visit and two downloads.
    # Download 1 took 150 s and was opened (start, completed and opened rows);
    # download 2 was cancelled after 2 s (start row only).
    $visit = ConvertTo-StoredTime "2026-03-01 09:59:00.000" Chromium
    $start1 = ConvertTo-StoredTime "2026-03-01 10:05:00.123" Chromium
    $end1 = ConvertTo-StoredTime "2026-03-01 10:07:30.000" Chromium
    $open1 = ConvertTo-StoredTime "2026-03-01 10:08:00.000" Chromium
    $start2 = ConvertTo-StoredTime "2026-03-01 11:00:00.000" Chromium
    $end2 = ConvertTo-StoredTime "2026-03-01 11:00:02.000" Chromium
    New-TestDatabase -Path (Join-Path $userDir "Chrome\Default\History") -Sql @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '70');
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,external_referrer_url TEXT,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,opener_visit INTEGER,originator_cache_guid TEXT,originator_visit_id INTEGER,originator_from_visit INTEGER,originator_opener_visit INTEGER,is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,visited_link_id INTEGER DEFAULT 0 NOT NULL,app_id TEXT);
CREATE TABLE downloads (id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,interrupt_reason INTEGER NOT NULL,hash BLOB NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,last_access_time INTEGER NOT NULL,transient INTEGER NOT NULL,referrer VARCHAR NOT NULL,site_url VARCHAR NOT NULL,embedder_download_data VARCHAR NOT NULL,tab_url VARCHAR NOT NULL,tab_referrer_url VARCHAR NOT NULL,http_method VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,by_web_app_id VARCHAR NOT NULL,etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL,mime_type VARCHAR(255) NOT NULL,original_mime_type VARCHAR(255) NOT NULL);
CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index) );
CREATE TABLE downloads_slices (download_id INTEGER NOT NULL,offset INTEGER NOT NULL,received_bytes INTEGER NOT NULL,finished INTEGER NOT NULL DEFAULT 0,PRIMARY KEY (download_id, offset) );
INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (1, 'https://example.com/', 'Example Domain', 1, 1, $visit, 0);
INSERT INTO visits (id, url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (1, 1, $visit, 0, 805306369, 0, 0);
INSERT INTO downloads (id, guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, hash, end_time, opened, last_access_time, transient, referrer, site_url, embedder_download_data, tab_url, tab_referrer_url, http_method, by_ext_id, by_ext_name, by_web_app_id, etag, last_modified, mime_type, original_mime_type)
  VALUES (1, 'guid-1', 'C:\Users\alice\Downloads\setup.exe', 'C:\Users\alice\Downloads\setup.exe', $start1, 1048576, 1048576, 1, 4, 0, X'00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF', $end1, 1, $open1, 0, 'https://dl.example.com/page', 'https://dl.example.com/', '', 'https://dl.example.com/page', 'https://search.example/?q=setup', 'GET', '', '', '', '', '', 'application/x-msdownload', 'application/x-msdownload');
INSERT INTO downloads (id, guid, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, hash, end_time, opened, last_access_time, transient, referrer, site_url, embedder_download_data, tab_url, tab_referrer_url, http_method, by_ext_id, by_ext_name, by_web_app_id, etag, last_modified, mime_type, original_mime_type)
  VALUES (2, 'guid-2', 'C:\Users\alice\Downloads\report.crdownload', 'C:\Users\alice\Downloads\report.pdf', $start2, 500, 1000, 2, 0, 40, X'', $end2, 0, 0, 0, '', '', '', 'https://docs.example.org/', '', 'GET', '', '', '', '', '', 'application/pdf', 'application/pdf');
INSERT INTO downloads_url_chains VALUES (1, 0, 'https://dl.example.com/get?id=1');
INSERT INTO downloads_url_chains VALUES (1, 1, 'https://cdn.example.net/setup.exe');
INSERT INTO downloads_url_chains VALUES (2, 0, 'https://docs.example.org/report.pdf');
"@

    # Chromium History (Brave, older downloads schema: no tab_url, site_url,
    # mime_type, last_access_time or hash)
    $start3 = ConvertTo-StoredTime "2026-02-14 09:00:00.000" Chromium
    $end3 = ConvertTo-StoredTime "2026-02-14 09:00:05.000" Chromium
    New-TestDatabase -Path (Join-Path $userDir "Brave\Default\History") -Sql @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '29');
CREATE TABLE urls(id INTEGER PRIMARY KEY,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL,favicon_id INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,is_indexed BOOLEAN,visit_duration INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE downloads (id INTEGER PRIMARY KEY,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,interrupt_reason INTEGER NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,referrer VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL);
CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index) );
INSERT INTO downloads VALUES (1, 'C:\Users\alice\Downloads\old.zip', 'C:\Users\alice\Downloads\old.zip', $start3, 2048, 2048, 1, 0, 0, $end3, 0, 'https://old.example.com/', 'abcdefghijklmnop', 'Helper Extension', '', '');
INSERT INTO downloads_url_chains VALUES (1, 0, 'https://old.example.com/old.zip');
"@

    # Chromium Login Data (current schema): a saved login (created, used,
    # password changed), a "never save" entry, and a login never used after
    # it was saved (Chromium sets date_last_used at the form submit, seconds
    # before the user clicks Save, which sets date_created: no "used" row)
    $created1 = ConvertTo-StoredTime "2026-02-01 08:00:00.000" Chromium
    $used1 = ConvertTo-StoredTime "2026-03-01 09:00:00.000" Chromium
    $changed1 = ConvertTo-StoredTime "2026-02-15 12:00:00.000" Chromium
    $created2 = ConvertTo-StoredTime "2026-02-02 08:00:00.000" Chromium
    $submitted3 = ConvertTo-StoredTime "2026-02-20 10:00:00.000" Chromium
    $created3 = ConvertTo-StoredTime "2026-02-20 10:00:07.000" Chromium
    New-TestDatabase -Path (Join-Path $userDir "Chrome\Default\Login Data") -Sql @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '43');
CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, form_data BLOB, display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR, skip_zero_click INTEGER, generation_upload_status INTEGER, possible_username_pairs BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, moving_blocked_for BLOB, date_password_modified INTEGER NOT NULL DEFAULT 0, sender_email VARCHAR, sender_name VARCHAR, date_received INTEGER, sharing_notification_displayed INTEGER NOT NULL DEFAULT 0, keychain_identifier BLOB, sender_profile_image_url VARCHAR, date_last_filled INTEGER NOT NULL DEFAULT 0, actor_login_approved INTEGER NOT NULL DEFAULT 0, UNIQUE (origin_url, username_element, username_value, password_element, signon_realm));
CREATE TABLE password_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER NOT NULL REFERENCES logins ON UPDATE CASCADE ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, key VARCHAR NOT NULL, value BLOB, date_created INTEGER NOT NULL, confidential INTEGER, UNIQUE (parent_id, key));
INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, password_value, submit_element, signon_realm, date_created, blacklisted_by_user, scheme, password_type, times_used, form_data, display_name, icon_url, federation_url, skip_zero_click, generation_upload_status, possible_username_pairs, date_last_used, moving_blocked_for, date_password_modified, date_last_filled)
  VALUES ('https://mail.example.com/', 'https://mail.example.com/login', 'email', 'alice@example.com', 'pass', CAST('$canary-password-1' AS BLOB), '', 'https://mail.example.com/', $created1, 0, 0, 0, 7, X'', '', '', '', 0, 0, X'', $used1, X'', $changed1, $used1);
INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, password_value, submit_element, signon_realm, date_created, blacklisted_by_user, scheme, password_type, times_used, form_data, display_name, icon_url, federation_url, skip_zero_click, generation_upload_status, possible_username_pairs, date_last_used, moving_blocked_for, date_password_modified, date_last_filled)
  VALUES ('https://bank.example.org/', '', '', '', '', CAST('$canary-password-2' AS BLOB), '', 'https://bank.example.org/', $created2, 1, 0, 0, 0, X'', '', '', '', 0, 0, X'', 0, X'', $created2, 0);
INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, password_value, submit_element, signon_realm, date_created, blacklisted_by_user, scheme, password_type, times_used, form_data, display_name, icon_url, federation_url, skip_zero_click, generation_upload_status, possible_username_pairs, date_last_used, moving_blocked_for, date_password_modified, date_last_filled)
  VALUES ('https://shop.example.net/', 'https://shop.example.net/signin', 'user', 'bob', 'pw', CAST('$canary-password-3' AS BLOB), '', 'https://shop.example.net/', $created3, 0, 0, 0, 1, X'', '', '', '', 0, 0, X'', $submitted3, X'', $submitted3, 0);
INSERT INTO password_notes (parent_id, key, value, date_created, confidential) VALUES (1, 'note', CAST('$canary-note' AS BLOB), $created1, 1);
"@

    # Chromium cookies, current schema at <profile>\Network\Cookies: two
    # cookies on one host, one cookie (created = last accessed) on another
    $cookieSql = @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '24');
CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,has_cross_site_ancestor INTEGER NOT NULL);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port);
"@
    $insertCookie = "INSERT INTO cookies VALUES ({0}, '{1}', '', '{2}', '$canary-value', CAST('$canary-encrypted' AS BLOB), '/', {3}, {4}, {5}, {6}, 1, {7}, 1, 0, 2, 443, {0}, 0, 0);"
    New-TestDatabase -Path (Join-Path $userDir "Chrome\Default\Network\Cookies") -Sql ($cookieSql + "`n" + (@(
        ($insertCookie -f (ConvertTo-StoredTime "2026-01-10 00:00:00.000" Chromium), ".example.com", "sid", (ConvertTo-StoredTime "2027-01-10 00:00:00.000" Chromium), 1, 1, (ConvertTo-StoredTime "2026-03-01 10:00:00.000" Chromium), 1),
        ($insertCookie -f (ConvertTo-StoredTime "2026-01-12 00:00:00.000" Chromium), ".example.com", "pref", (ConvertTo-StoredTime "2026-06-12 00:00:00.000" Chromium), 0, 0, (ConvertTo-StoredTime "2026-02-01 00:00:00.000" Chromium), 1),
        ($insertCookie -f (ConvertTo-StoredTime "2026-02-20 05:00:00.000" Chromium), "tracker.example.net", "id", 0, 1, 0, (ConvertTo-StoredTime "2026-02-20 05:00:00.000" Chromium), 0)
    ) -join "`n"))
    # Opera keeps no profile folder: Browser\<user>\Opera\Network\Cookies
    New-TestDatabase -Path (Join-Path $userDir "Opera\Network\Cookies") -Sql ($cookieSql + "`n" +
        ($insertCookie -f (ConvertTo-StoredTime "2026-01-05 00:00:00.000" Chromium), ".opera.example", "o", 0, 0, 0, (ConvertTo-StoredTime "2026-01-05 00:00:00.000" Chromium), 0))
    # Legacy <profile>\Cookies with the old flag column names (secure, httponly, persistent)
    New-TestDatabase -Path (Join-Path $userDir "Edge\Default\Cookies") -Sql @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '9');
CREATE TABLE cookies (creation_utc INTEGER NOT NULL UNIQUE PRIMARY KEY,host_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,secure INTEGER NOT NULL,httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL DEFAULT 1, persistent INTEGER NOT NULL DEFAULT 1,priority INTEGER NOT NULL DEFAULT 1,encrypted_value BLOB DEFAULT '',firstpartyonly INTEGER NOT NULL DEFAULT 0);
INSERT INTO cookies VALUES ($(ConvertTo-StoredTime "2025-12-01 00:00:00.000" Chromium), '.legacy.example', 'old', '$canary-value', '/', 0, 1, 0, $(ConvertTo-StoredTime "2025-12-05 00:00:00.000" Chromium), 0, 1, 1, CAST('$canary-encrypted' AS BLOB), 0);
"@
    # Network\Cookies copied mid-transaction with its Cookies-journal (the
    # collector collects it): 400 committed cookies on journal.example; the
    # open transaction deletes half and moves the rest to another host
    $journalCreated = ConvertTo-StoredTime "2026-01-20 00:00:00.000" Chromium
    $journalAccessed = ConvertTo-StoredTime "2026-02-21 00:00:00.000" Chromium
    New-TestHotJournalDatabase -Path (Join-Path $userDir "Vivaldi\Default\Network\Cookies") -Sql ($cookieSql + "`n" +
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 400) INSERT INTO cookies SELECT $journalCreated + i, 'journal.example', '', 'c' || i, " +
        "'$canary-' || hex(randomblob(200)), CAST('$canary-encrypted' AS BLOB), '/', 0, 1, 1, $journalAccessed + i, 1, 1, 1, 0, 2, 443, $journalCreated + i, 0, 0 FROM n;") `
        -Transaction "DELETE FROM cookies WHERE rowid % 2 = 0; UPDATE cookies SET host_key = 'uncommitted.example', value = '$canary-' || hex(randomblob(300));"

    # Chromium Web Data: autofill (times in seconds since 1970), search
    # engines (prepopulated, custom, auto-generated -- used when it was added,
    # so no "last used" row -- and a custom one whose name starts with '#',
    # which ConvertFrom-Csv would take for a comment line) and the payment
    # card and address tables, which must never be read
    $engineColumns = "id, short_name, keyword, favicon_url, url, safe_for_autoreplace, originating_url, date_created, usage_count, input_encodings, suggest_url, prepopulate_id, created_by_policy, last_modified, sync_guid, alternate_urls, image_url, search_url_post_params, suggest_url_post_params, image_url_post_params, new_tab_url, last_visited, created_from_play_api, is_active, starter_pack_id, enforced_by_policy, featured_by_policy, url_hash"
    New-TestDatabase -Path (Join-Path $userDir "Chrome\Default\Web Data") -Sql @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '139');
CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value));
CREATE TABLE keywords (id INTEGER PRIMARY KEY,short_name VARCHAR NOT NULL,keyword VARCHAR NOT NULL,favicon_url VARCHAR NOT NULL,url VARCHAR NOT NULL,safe_for_autoreplace INTEGER,originating_url VARCHAR,date_created INTEGER DEFAULT 0,usage_count INTEGER DEFAULT 0,input_encodings VARCHAR,suggest_url VARCHAR,prepopulate_id INTEGER DEFAULT 0,created_by_policy INTEGER DEFAULT 0,last_modified INTEGER DEFAULT 0,sync_guid VARCHAR,alternate_urls VARCHAR,image_url VARCHAR,search_url_post_params VARCHAR,suggest_url_post_params VARCHAR,image_url_post_params VARCHAR,new_tab_url VARCHAR,last_visited INTEGER DEFAULT 0,created_from_play_api INTEGER DEFAULT 0,is_active INTEGER DEFAULT 0,starter_pack_id INTEGER DEFAULT 0,enforced_by_policy INTEGER DEFAULT 0,featured_by_policy INTEGER DEFAULT 0,url_hash BLOB);
CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, origin VARCHAR DEFAULT '', use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, billing_address_id VARCHAR, nickname VARCHAR);
CREATE TABLE addresses (guid VARCHAR PRIMARY KEY, use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, date_modified INTEGER NOT NULL DEFAULT 0, language_code VARCHAR, label VARCHAR, initial_creator_id INTEGER DEFAULT 0, last_modifier_id INTEGER DEFAULT 0, record_type INTEGER);
CREATE TABLE address_type_tokens (guid VARCHAR, type INTEGER, value VARCHAR, verification_status INTEGER DEFAULT 0, observations BLOB, PRIMARY KEY (guid, type));
INSERT INTO autofill VALUES ('email', '$canary-email', lower('$canary-email'), $(ConvertTo-StoredTime "2026-02-03 07:00:00.000" UnixSeconds), $(ConvertTo-StoredTime "2026-02-28 07:00:00.000" UnixSeconds), 3);
INSERT INTO autofill VALUES ('q', '$canary-search', lower('$canary-search'), $(ConvertTo-StoredTime "2026-02-04 06:00:00.000" UnixSeconds), $(ConvertTo-StoredTime "2026-02-04 06:00:00.000" UnixSeconds), 1);
INSERT INTO keywords ($engineColumns) VALUES (2, 'Google', 'google.com', 'https://www.google.com/favicon.ico', 'https://www.google.com/search?q={searchTerms}', 1, '', 0, 0, 'UTF-8', '', 1, 0, 0, 'guid-google', '[]', '', '', '', '', '', $(ConvertTo-StoredTime "2026-03-01 09:30:00.000" Chromium), 0, 1, 0, 0, 0, NULL);
INSERT INTO keywords ($engineColumns) VALUES (5, 'Evil Search', 'evil', '', 'https://search.evil.example/?q={searchTerms}', 0, '', $(ConvertTo-StoredTime "2026-02-10 03:00:00.000" Chromium), 0, '', '', 0, 0, $(ConvertTo-StoredTime "2026-02-11 03:00:00.000" Chromium), 'guid-evil', '[]', '', '', '', '', '', 0, 0, 1, 0, 0, 0, NULL);
INSERT INTO keywords ($engineColumns) VALUES (6, 'Shop', 'shop.example', '', 'https://shop.example/search?q={searchTerms}', 1, 'https://shop.example/opensearch.xml', $(ConvertTo-StoredTime "2026-02-12 00:00:00.000" Chromium), 0, '', '', 0, 0, $(ConvertTo-StoredTime "2026-02-12 00:00:00.000" Chromium), 'guid-shop', '[]', '', '', '', '', '', $(ConvertTo-StoredTime "2026-02-12 00:00:00.000" Chromium), 0, 1, 0, 0, 0, NULL);
INSERT INTO keywords ($engineColumns) VALUES (7, '#hijack', 'h', '', 'https://hijack.example/?q={searchTerms}', 0, '', $(ConvertTo-StoredTime "2026-02-13 00:00:00.000" Chromium), 0, '', '', 0, 0, $(ConvertTo-StoredTime "2026-02-13 00:00:00.000" Chromium), 'guid-hijack', '[]', '', '', '', '', '', 0, 0, 1, 0, 0, 0, NULL);
INSERT INTO credit_cards VALUES ('card-1', '$canary-name', 12, 2030, CAST('$canary-card' AS BLOB), 0, '', 1, 0, '', '$canary-nickname');
INSERT INTO addresses VALUES ('address-1', 1, 0, 0, 'en', '', 0, 0, 0);
INSERT INTO address_type_tokens VALUES ('address-1', 3, '$canary-address', 0, NULL);
"@

    # Firefox profile
    $ffDir = Join-Path $userDir "Firefox\abcd1234.default-release"
    # places.sqlite: one visit and two downloads: one completed after 5
    # minutes, whose download visit (type 7) comes from a page visit (the
    # referrer), and one blocked by the reputation check after 1 s
    New-TestDatabase -Path (Join-Path $ffDir "places.sqlite") -Sql @"
CREATE TABLE moz_places ( id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL, description TEXT, preview_image_url TEXT, site_name TEXT, origin_id INTEGER REFERENCES moz_origins(id), recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0);
CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL, triggeringPlaceId INTEGER);
CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, position INTEGER, title LONGVARCHAR, keyword_id INTEGER, folder_type TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT, syncStatus INTEGER NOT NULL DEFAULT 0, syncChangeCounter INTEGER NOT NULL DEFAULT 1);
CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
INSERT INTO moz_places (id, url, title, rev_host, visit_count, typed, frecency, last_visit_date, guid) VALUES (1, 'https://www.mozilla.org/', 'Mozilla', 'gro.allizom.www.', 1, 1, 100, $(ConvertTo-StoredTime "2026-03-02 12:00:00.000" PRTime), 'placeguid001');
INSERT INTO moz_places (id, url, title, rev_host, visit_count, frecency, guid) VALUES (2, 'https://files.example.org/tool.zip', 'tool.zip', 'gro.elpmaxe.selif.', 0, 0, 'placeguid002');
INSERT INTO moz_places (id, url, title, rev_host, visit_count, frecency, guid) VALUES (3, 'https://bad.example/payload.exe', 'payload.exe', 'elpmaxe.dab.', 0, 0, 'placeguid003');
INSERT INTO moz_places (id, url, title, rev_host, visit_count, frecency, guid) VALUES (4, 'https://files.example.org/tools.html', 'Tools', 'gro.elpmaxe.selif.', 1, 100, 'placeguid004');
INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session, source) VALUES (1, 0, 1, $(ConvertTo-StoredTime "2026-03-02 12:00:00.000" PRTime), 2, 0, 0);
INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session, source) VALUES (2, 0, 4, $(ConvertTo-StoredTime "2026-03-02 12:09:30.000" PRTime), 1, 0, 0);
INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session, source) VALUES (3, 2, 2, $(ConvertTo-StoredTime "2026-03-02 12:10:00.000" PRTime), 7, 0, 0);
INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
INSERT INTO moz_anno_attributes VALUES (2, 'downloads/metaData');
INSERT INTO moz_annos VALUES (1, 2, 1, 'file:///C:/Users/alice/Downloads/tool%20v2.zip', 0, 4, 3, $(ConvertTo-StoredTime "2026-03-02 12:10:00.000" PRTime), $(ConvertTo-StoredTime "2026-03-02 12:10:00.000" PRTime));
INSERT INTO moz_annos VALUES (2, 2, 2, '{"state":1,"deleted":false,"endTime":$(ConvertTo-StoredTime "2026-03-02 12:15:00.000" UnixMs),"fileSize":2048}', 0, 4, 3, $(ConvertTo-StoredTime "2026-03-02 12:15:00.000" PRTime), $(ConvertTo-StoredTime "2026-03-02 12:15:00.000" PRTime));
INSERT INTO moz_annos VALUES (3, 3, 1, 'file:///C:/Users/alice/Downloads/payload.exe', 0, 4, 3, $(ConvertTo-StoredTime "2026-03-02 12:20:00.000" PRTime), $(ConvertTo-StoredTime "2026-03-02 12:20:00.000" PRTime));
INSERT INTO moz_annos VALUES (4, 3, 2, '{"state":8,"deleted":false,"endTime":$(ConvertTo-StoredTime "2026-03-02 12:20:01.000" UnixMs),"reputationCheckVerdict":"Malware"}', 0, 4, 3, $(ConvertTo-StoredTime "2026-03-02 12:20:01.000" PRTime), $(ConvertTo-StoredTime "2026-03-02 12:20:01.000" PRTime));
"@
    New-TestDatabase -Path (Join-Path $ffDir "cookies.sqlite") -Sql @"
CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0, isPartitionedAttributeSet INTEGER DEFAULT 0, updateTime INTEGER, CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes));
INSERT INTO moz_cookies VALUES (1, '', 'a', '$canary-value-a', '.mozilla.org', '/', $(ConvertTo-StoredTime "2027-02-05 00:00:00.000" UnixMs), $(ConvertTo-StoredTime "2026-03-02 12:00:00.000" PRTime), $(ConvertTo-StoredTime "2026-02-05 00:00:00.000" PRTime), 1, 0, 0, 0, 2, 0, $(ConvertTo-StoredTime "2026-02-05 00:00:00.000" PRTime));
INSERT INTO moz_cookies VALUES (2, '', 'b', '$canary-value-b', '.mozilla.org', '/', $(ConvertTo-StoredTime "2027-02-06 00:00:00.000" UnixMs), $(ConvertTo-StoredTime "2026-02-06 00:00:00.000" PRTime), $(ConvertTo-StoredTime "2026-02-06 00:00:00.000" PRTime), 0, 1, 0, 0, 2, 0, $(ConvertTo-StoredTime "2026-02-06 00:00:00.000" PRTime));
"@
    New-TestDatabase -Path (Join-Path $ffDir "formhistory.sqlite") -Sql @"
CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
CREATE TABLE moz_deleted_formhistory (id INTEGER PRIMARY KEY, timeDeleted INTEGER, guid TEXT);
CREATE TABLE moz_sources (id INTEGER PRIMARY KEY, source TEXT NOT NULL);
CREATE TABLE moz_history_to_sources (history_id INTEGER, source_id INTEGER, PRIMARY KEY (history_id, source_id), FOREIGN KEY (history_id) REFERENCES moz_formhistory(id) ON DELETE CASCADE, FOREIGN KEY (source_id) REFERENCES moz_sources(id) ON DELETE CASCADE) WITHOUT ROWID;
INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', '$canary-search', 4, $(ConvertTo-StoredTime "2026-02-07 10:00:00.000" PRTime), $(ConvertTo-StoredTime "2026-03-02 11:00:00.000" PRTime), 'formguid0001');
"@
    New-TestDatabase -Path (Join-Path $ffDir "permissions.sqlite") -Sql @"
CREATE TABLE moz_perms ( id INTEGER PRIMARY KEY,origin TEXT,type TEXT,permission INTEGER,expireType INTEGER,expireTime INTEGER,modificationTime INTEGER);
INSERT INTO moz_perms VALUES (1, 'https://push.example.com', 'desktop-notification', 1, 0, 0, $(ConvertTo-StoredTime "2026-02-25 16:00:00.000" UnixMs));
INSERT INTO moz_perms VALUES (2, 'https://cam.example.com', 'camera', 2, 2, $(ConvertTo-StoredTime "2026-03-25 16:00:00.000" UnixMs), $(ConvertTo-StoredTime "2026-02-26 16:00:00.000" UnixMs));
"@
    # logins.json: times in milliseconds; the first password was never
    # changed; the second login was never used after it was saved (Firefox
    # sets all three times when a login is saved: only a "created" row)
    $loginCreated = ConvertTo-StoredTime "2026-01-20 10:00:00.000" UnixMs
    $loginUsed = ConvertTo-StoredTime "2026-03-02 13:00:00.000" UnixMs
    $loginSaved = ConvertTo-StoredTime "2026-03-02 10:00:00.000" UnixMs
    New-TestTextFile -Path (Join-Path $ffDir "logins.json") -Text ('{"nextId":3,"logins":[{"id":1,"hostname":"https://forum.example.com","httpRealm":null,' +
        '"formSubmitURL":"https://forum.example.com/login","usernameField":"user","passwordField":"pass",' +
        '"encryptedUsername":"' + $canary + '-username","encryptedPassword":"' + $canary + '-password",' +
        '"guid":"{11111111-2222-3333-4444-555555555555}","encType":1,"timeCreated":' + $loginCreated + ',"timeLastUsed":' + $loginUsed +
        ',"timePasswordChanged":' + $loginCreated + ',"timesUsed":5},' +
        '{"id":2,"hostname":"https://new.example.com","httpRealm":null,"formSubmitURL":"https://new.example.com/","usernameField":"email","passwordField":"pw",' +
        '"encryptedUsername":"' + $canary + '-username-2","encryptedPassword":"' + $canary + '-password-2",' +
        '"guid":"{22222222-3333-4444-5555-666666666666}","encType":1,"timeCreated":' + $loginSaved + ',"timeLastUsed":' + $loginSaved +
        ',"timePasswordChanged":' + $loginSaved + ',"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}')
    # A second profile with a logins.json cut off inside an encrypted
    # password (a damaged or partial copy): reported, never quoted
    New-TestTextFile -Path (Join-Path $userDir "Firefox\trunc5678.default\logins.json") -Text ('{"nextId":2,"logins":[{"id":1,"hostname":"https://cut.example.com",' +
        '"httpRealm":null,"formSubmitURL":"","usernameField":"u","passwordField":"p","encryptedUsername":"' + $canary + '-username-3",' +
        '"encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcE' + $canary + '-password-3')
    # key4.db (the Firefox key store) is collected but must never be read
    New-TestTextFile -Path (Join-Path $ffDir "key4.db") -Text "$canary-key4"

    # --- Run the builder ---
    $timelineCsv = Join-Path $workDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $builderOutput = Invoke-TimelineBuilder -CollectionPath $collection -OutputFile $timelineCsv
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the builder exited with code $LASTEXITCODE or wrote no timeline"
        exit 1
    }
    $rows = @(Import-Csv -LiteralPath $timelineCsv)

    # --- Expected rows: time, source, event type, description, and text the
    # Details must (Has) or must not (Lacks) contain ---
    $setupLabel = "C:\Users\alice\Downloads\setup.exe (https://cdn.example.net/setup.exe)"
    $setupDetails = @("Path=C:\Users\alice\Downloads\setup.exe", "URL=https://cdn.example.net/setup.exe", "OriginalURL=https://dl.example.com/get?id=1",
        "Referrer=https://dl.example.com/page", "TabURL=https://dl.example.com/page", "TabReferrer=https://search.example/?q=setup",
        "SiteURL=https://dl.example.com/", "MimeType=application/x-msdownload", "State=COMPLETE", "DangerType=MAYBE_DANGEROUS_CONTENT",
        "Bytes=1048576", "Opened=Yes", "StartUtc=2026-03-01 10:05:00", "EndUtc=2026-03-01 10:07:30", "LastOpenedUtc=2026-03-01 10:08:00",
        "SHA256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "Profile=Default")
    $mailLogin = "https://mail.example.com/ (user: alice@example.com)"
    $mailDetails = @("URL=https://mail.example.com/", "Action=https://mail.example.com/login", "Realm=https://mail.example.com/", "Username=alice@example.com",
        "TimesUsed=7", "CreatedUtc=2026-02-01 08:00:00", "LastUsedUtc=2026-03-01 09:00:00", "PasswordChangedUtc=2026-02-15 12:00:00", "Profile=Default")
    $exampleCookies = @("Host=.example.com", "Cookies=2", "Names=pref, sid", "Persistent=2", "Secure=1", "HttpOnly=1",
        "FirstSetUtc=2026-01-10 00:00:00", "LastAccessUtc=2026-03-01 10:00:00", "LatestExpiryUtc=2027-01-10 00:00:00", "Profile=Default")
    $evilEngine = @("Name=Evil Search", "Keyword=evil", "URL=https://search.evil.example/?q={searchTerms}", "Kind=Custom", "CreatedUtc=2026-02-10 03:00:00", "ModifiedUtc=2026-02-11 03:00:00")
    $toolLabel = "C:\Users\alice\Downloads\tool v2.zip (https://files.example.org/tool.zip)"
    $toolDetails = @("Path=C:\Users\alice\Downloads\tool v2.zip", "URL=https://files.example.org/tool.zip", "Referrer=https://files.example.org/tools.html",
        "State=COMPLETE", "FirefoxState=FINISHED", "Bytes=2048", "StartUtc=2026-03-02 12:10:00", "EndUtc=2026-03-02 12:15:00", "Profile=abcd1234.default-release")
    $journalCookies = @("Host=journal.example", "Cookies=400", "Persistent=400", "Secure=400", "HttpOnly=400", "FirstSetUtc=2026-01-20 00:00:00",
        "LastAccessUtc=2026-02-21 00:00:00", "Profile=Default")
    $mozillaCookies = @("Host=.mozilla.org", "Cookies=2", "Names=a, b", "Secure=1", "HttpOnly=1", "FirstSetUtc=2026-02-05 00:00:00", "LastAccessUtc=2026-03-02 12:00:00")
    $forumLogin = @("URL=https://forum.example.com", "Action=https://forum.example.com/login", "UsernameField=user", "TimesUsed=5",
        "CreatedUtc=2026-01-20 10:00:00", "LastUsedUtc=2026-03-02 13:00:00", "Profile=abcd1234.default-release")
    $expected = @(
        # Existing visit parsing still works
        @{ Time = "2026-03-01 09:59:00.000"; Source = "Chrome History"; Type = "NetworkConnection"; Text = "Browser visit: Example Domain" }
        @{ Time = "2026-03-02 12:00:00.000"; Source = "Firefox History"; Type = "NetworkConnection"; Text = "Browser visit: Mozilla" }
        # Chromium downloads
        @{ Time = "2026-03-01 10:05:00.123"; Source = "Chrome Downloads"; Type = "FileAccess"; Text = "Download started: $setupLabel"; Has = $setupDetails }
        @{ Time = "2026-03-01 10:07:30.000"; Source = "Chrome Downloads"; Type = "FileAccess"; Text = "Download completed: $setupLabel"; Has = $setupDetails }
        @{ Time = "2026-03-01 10:08:00.000"; Source = "Chrome Downloads"; Type = "FileAccess"; Text = "Download opened: $setupLabel"; Has = $setupDetails }
        @{ Time = "2026-03-01 11:00:00.000"; Source = "Chrome Downloads"; Type = "FileAccess"; Text = "Download started: C:\Users\alice\Downloads\report.pdf (https://docs.example.org/report.pdf)"
            Has = @("State=CANCELLED", "InterruptReason=USER_CANCELED", "DangerType=NOT_DANGEROUS", "Bytes=500", "TotalBytes=1000", "Opened=No",
                "TabURL=https://docs.example.org/", "CurrentPath=C:\Users\alice\Downloads\report.crdownload", "EndUtc=2026-03-01 11:00:02")
            Lacks = @("OriginalURL=", "LastOpenedUtc=", "SHA256=", "Referrer=") }
        @{ Time = "2026-02-14 09:00:00.000"; Source = "Brave Downloads"; Type = "FileAccess"; Text = "Download started: C:\Users\alice\Downloads\old.zip (https://old.example.com/old.zip)"
            Has = @("State=COMPLETE", "Referrer=https://old.example.com/", "Extension=Helper Extension", "Bytes=2048", "Opened=No")
            Lacks = @("TabURL=", "MimeType=", "TotalBytes=", "SHA256=", "LastOpenedUtc=") }
        # Chromium saved logins
        @{ Time = "2026-02-01 08:00:00.000"; Source = "Chrome Logins"; Type = "NetworkConnection"; Text = "Saved login created: $mailLogin"; Has = $mailDetails; Lacks = @("NeverSave=") }
        @{ Time = "2026-03-01 09:00:00.000"; Source = "Chrome Logins"; Type = "NetworkConnection"; Text = "Saved login last used: $mailLogin"; Has = $mailDetails }
        @{ Time = "2026-02-15 12:00:00.000"; Source = "Chrome Logins"; Type = "NetworkConnection"; Text = "Saved password changed: $mailLogin"; Has = $mailDetails }
        @{ Time = "2026-02-02 08:00:00.000"; Source = "Chrome Logins"; Type = "NetworkConnection"; Text = "Saved login declined: https://bank.example.org/ (never save for this site)"
            Has = @("URL=https://bank.example.org/", "NeverSave=Yes", "CreatedUtc=2026-02-02 08:00:00"); Lacks = @("Username=") }
        @{ Time = "2026-02-20 10:00:07.000"; Source = "Chrome Logins"; Type = "NetworkConnection"; Text = "Saved login created: https://shop.example.net/ (user: bob)"
            Has = @("Username=bob", "TimesUsed=1", "CreatedUtc=2026-02-20 10:00:07", "LastUsedUtc=2026-02-20 10:00:00", "PasswordChangedUtc=2026-02-20 10:00:00") }
        # Chromium cookies, per host
        @{ Time = "2026-01-10 00:00:00.000"; Source = "Chrome Cookies"; Type = "NetworkConnection"; Text = "Cookies first set: .example.com (2 cookies)"; Has = $exampleCookies }
        @{ Time = "2026-03-01 10:00:00.000"; Source = "Chrome Cookies"; Type = "NetworkConnection"; Text = "Cookies last accessed: .example.com (2 cookies)"; Has = $exampleCookies }
        @{ Time = "2026-02-20 05:00:00.000"; Source = "Chrome Cookies"; Type = "NetworkConnection"; Text = "Cookies first set: tracker.example.net (1 cookie)"
            Has = @("Names=id", "Persistent=0", "Secure=1", "HttpOnly=0"); Lacks = @("LatestExpiryUtc=") }
        @{ Time = "2025-12-01 00:00:00.000"; Source = "Edge Cookies"; Type = "NetworkConnection"; Text = "Cookies first set: .legacy.example (1 cookie)"
            Has = @("Names=old", "Persistent=1", "Secure=1", "HttpOnly=0", "Profile=Default") }
        @{ Time = "2025-12-05 00:00:00.000"; Source = "Edge Cookies"; Type = "NetworkConnection"; Text = "Cookies last accessed: .legacy.example (1 cookie)" }
        @{ Time = "2026-01-05 00:00:00.000"; Source = "Opera Cookies"; Type = "NetworkConnection"; Text = "Cookies first set: .opera.example (1 cookie)"; Lacks = @("Profile=") }
        # Copied mid-transaction: read in its committed state through the journal
        @{ Time = "2026-01-20 00:00:00.000"; Source = "Vivaldi Cookies"; Type = "NetworkConnection"; Text = "Cookies first set: journal.example (400 cookies)"; Has = $journalCookies }
        @{ Time = "2026-02-21 00:00:00.000"; Source = "Vivaldi Cookies"; Type = "NetworkConnection"; Text = "Cookies last accessed: journal.example (400 cookies)"; Has = $journalCookies }
        # Chromium autofill and search engines
        @{ Time = "2026-02-03 07:00:00.000"; Source = "Chrome Autofill"; Type = "NetworkConnection"; Text = "Form entry saved: field email"
            Has = @("Field=email", "TimesUsed=3", "FirstUsedUtc=2026-02-03 07:00:00", "LastUsedUtc=2026-02-28 07:00:00", "Profile=Default") }
        @{ Time = "2026-02-28 07:00:00.000"; Source = "Chrome Autofill"; Type = "NetworkConnection"; Text = "Form entry last used: field email" }
        @{ Time = "2026-02-04 06:00:00.000"; Source = "Chrome Autofill"; Type = "NetworkConnection"; Text = "Form entry saved: field q"; Has = @("TimesUsed=1") }
        @{ Time = "2026-03-01 09:30:00.000"; Source = "Chrome Search Engines"; Type = "NetworkConnection"; Text = "Search engine last used: Google (https://www.google.com/search?q={searchTerms})"
            Has = @("Kind=Prepopulated", "Keyword=google.com", "LastUsedUtc=2026-03-01 09:30:00"); Lacks = @("CreatedUtc=") }
        @{ Time = "2026-02-10 03:00:00.000"; Source = "Chrome Search Engines"; Type = "NetworkConnection"; Text = "Search engine added: Evil Search (https://search.evil.example/?q={searchTerms})"; Has = $evilEngine }
        @{ Time = "2026-02-11 03:00:00.000"; Source = "Chrome Search Engines"; Type = "NetworkConnection"; Text = "Search engine modified: Evil Search (https://search.evil.example/?q={searchTerms})"; Has = $evilEngine }
        @{ Time = "2026-02-12 00:00:00.000"; Source = "Chrome Search Engines"; Type = "NetworkConnection"; Text = "Search engine added: Shop (https://shop.example/search?q={searchTerms})"
            Has = @("Kind=AutoGenerated", "OriginatingURL=https://shop.example/opensearch.xml", "LastUsedUtc=2026-02-12 00:00:00") }
        @{ Time = "2026-02-13 00:00:00.000"; Source = "Chrome Search Engines"; Type = "NetworkConnection"; Text = "Search engine added: #hijack (https://hijack.example/?q={searchTerms})"
            Has = @("Name=#hijack", "Keyword=h", "Kind=Custom") }
        # Firefox downloads
        @{ Time = "2026-03-02 12:10:00.000"; Source = "Firefox Downloads"; Type = "FileAccess"; Text = "Download started: $toolLabel"; Has = $toolDetails }
        @{ Time = "2026-03-02 12:15:00.000"; Source = "Firefox Downloads"; Type = "FileAccess"; Text = "Download completed: $toolLabel"; Has = $toolDetails }
        @{ Time = "2026-03-02 12:20:00.000"; Source = "Firefox Downloads"; Type = "FileAccess"; Text = "Download started: C:\Users\alice\Downloads\payload.exe (https://bad.example/payload.exe)"
            Has = @("State=BLOCKED", "FirefoxState=DIRTY", "DangerType=Malware", "EndUtc=2026-03-02 12:20:01"); Lacks = @("Bytes=", "Referrer=") }
        # The referrer page visit and the download visit
        @{ Time = "2026-03-02 12:09:30.000"; Source = "Firefox History"; Type = "NetworkConnection"; Text = "Browser visit: Tools" }
        @{ Time = "2026-03-02 12:10:00.000"; Source = "Firefox History"; Type = "NetworkConnection"; Text = "Browser visit: tool.zip"; Has = @("Transition=DOWNLOAD") }
        # Firefox cookies, form history, permissions and saved logins
        @{ Time = "2026-02-05 00:00:00.000"; Source = "Firefox Cookies"; Type = "NetworkConnection"; Text = "Cookies first set: .mozilla.org (2 cookies)"; Has = $mozillaCookies; Lacks = @("Persistent=") }
        @{ Time = "2026-03-02 12:00:00.000"; Source = "Firefox Cookies"; Type = "NetworkConnection"; Text = "Cookies last accessed: .mozilla.org (2 cookies)"; Has = $mozillaCookies }
        @{ Time = "2026-02-07 10:00:00.000"; Source = "Firefox Form History"; Type = "NetworkConnection"; Text = "Form entry saved: field searchbar-history"
            Has = @("Field=searchbar-history", "TimesUsed=4", "LastUsedUtc=2026-03-02 11:00:00") }
        @{ Time = "2026-03-02 11:00:00.000"; Source = "Firefox Form History"; Type = "NetworkConnection"; Text = "Form entry last used: field searchbar-history" }
        @{ Time = "2026-02-25 16:00:00.000"; Source = "Firefox Permissions"; Type = "NetworkConnection"; Text = "Site permission set: https://push.example.com desktop-notification=ALLOW"
            Has = @("Origin=https://push.example.com", "Type=desktop-notification", "Permission=ALLOW", "Expiry=NEVER"); Lacks = @("ExpiresUtc=") }
        @{ Time = "2026-02-26 16:00:00.000"; Source = "Firefox Permissions"; Type = "NetworkConnection"; Text = "Site permission set: https://cam.example.com camera=DENY"
            Has = @("Permission=DENY", "Expiry=TIME", "ExpiresUtc=2026-03-25 16:00:00") }
        @{ Time = "2026-01-20 10:00:00.000"; Source = "Firefox Logins"; Type = "NetworkConnection"; Text = "Saved login created: https://forum.example.com"; Has = $forumLogin; Lacks = @("Username=") }
        @{ Time = "2026-03-02 13:00:00.000"; Source = "Firefox Logins"; Type = "NetworkConnection"; Text = "Saved login last used: https://forum.example.com"; Has = $forumLogin }
        @{ Time = "2026-03-02 10:00:00.000"; Source = "Firefox Logins"; Type = "NetworkConnection"; Text = "Saved login created: https://new.example.com"
            Has = @("UsernameField=email", "TimesUsed=1", "CreatedUtc=2026-03-02 10:00:00", "LastUsedUtc=2026-03-02 10:00:00", "PasswordChangedUtc=2026-03-02 10:00:00") }
    )

    # --- Checks ---
    $byKey = @{}
    foreach ($row in $rows) { $byKey["$($row.Timestamp) | $($row.Source) | $($row.EventType) | $($row.Description)"] = $row }
    $expectedKeys = @()
    foreach ($e in $expected) {
        $key = "$($e.Time) | $($e.Source) | $($e.Type) | $($e.Text)"
        $expectedKeys += $key
        if (-not $byKey.ContainsKey($key)) {
            Write-TestResult -Succeeded $false -Message "missing row: $key"
            continue
        }
        $details = $byKey[$key].Details
        $problems = @()
        foreach ($text in @($e.Has)) { if ($text -and -not $details.Contains($text)) { $problems += "Details lacks '$text'" } }
        foreach ($text in @($e.Lacks)) { if ($text -and $details.Contains($text)) { $problems += "Details has '$text'" } }
        if ($byKey[$key].User -ne "alice") { $problems += "User is '$($byKey[$key].User)'" }
        if ($problems.Count -gt 0) { Write-TestResult -Succeeded $false -Message "$key -- $($problems -join '; ') (Details: $details)" }
        else { Write-TestResult -Succeeded $true -Message $key }
    }
    # Hashtable keys are case-insensitive; compare the row texts exactly
    $unexpected = @($byKey.Keys | Where-Object { $expectedKeys -cnotcontains $_ })
    foreach ($key in $unexpected) { Write-TestResult -Succeeded $false -Message "unexpected row: $key" }
    Write-TestResult -Succeeded ($rows.Count -eq $expected.Count) -Message "$($rows.Count) rows in the timeline ($($expected.Count) expected)"

    # The canary is in every secret column: it must appear nowhere
    $csvText = [System.IO.File]::ReadAllText($timelineCsv)
    Write-TestResult -Succeeded ($csvText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret value (canary) in the timeline CSV"
    $newReports = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $reportsBefore -notcontains $_.FullName })
    $logFiles = @($newReports | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter "*.txt" -File -ErrorAction SilentlyContinue })
    $logText = ($logFiles | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n"
    Write-TestResult -Succeeded ($logFiles.Count -gt 0 -and $logText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret value (canary) in the builder log"
    Write-TestResult -Succeeded ((($builderOutput -join "`n").IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase)) -lt 0) -Message "no secret value (canary) in the builder output"
    # The cut-off logins.json is reported (the canary checks above show its
    # encrypted values are not)
    $damaged = @($builderOutput | Where-Object { $_ -like "*Could not read saved logins*trunc5678.default*not valid JSON*" })
    Write-TestResult -Succeeded ($damaged.Count -gt 0) -Message "the cut-off logins.json is reported as not valid JSON"

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all browser parser checks passed ($($rows.Count) rows)" -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the ones from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
