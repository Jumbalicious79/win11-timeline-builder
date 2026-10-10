# =============================================================
# Browser extras parser test
# Builds a synthetic triage collection at test time (nothing is
# committed): Chromium Secure Preferences / Preferences (installed
# extensions, settings; also a Brave profile), Local State, extension
# manifests (one with comments) and messages.json, SNSS Session_* / Tabs_*
# files (closed tabs, a closed window, the selected entry of each tab), a
# live History with two history snapshots (Snapshots\<version>\<profile>\)
# and one snapshot without a live History, a collection manifest with the
# original file times, Favicons (live and snapshot), and Firefox
# extensions.json / addons.json, prefs.js and mozLz4 session files
# (compressed here with a small LZ4 compressor). Runs timeline-builder.ps1
# -Sources Browser and checks every row, its time and its Details, and that
# nothing else is added: no row for built-in extensions, on-demand
# favicons, bookmarked pages, pages still in history, a Thunderbird
# prefs.js or an app's Preferences file outside a browser profile. A canary
# string in every secret or private field (encrypted keys, password hashes,
# site settings, form data, cookies, POST data, page state, a token pref)
# must appear nowhere in the timeline, the builder log or its output, and
# the builder's JSON reader must return those members blanked (checked
# directly, with the builder's own functions). A damaged session file must
# be reported.
#
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). For a local run without them, pass
# -BuilderPath with a copy of the builder that has no admin check, kept
# inside the repository (e.g. under the git-ignored reports\ folder).
# sqlite3.exe is looked for where the builder looks; if it is missing,
# the builder is run once so that its Find-Sqlite3Exe downloads it.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-BrowserExtrasParsers.ps1
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
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-BrowserExtrasParsers.ps1::$Message" }
}

# The builder functions loaded for the direct checks log through Log-Warning
function Log-Warning {
    param([string]$Message)
    Write-Host "WARNING: $Message" -ForegroundColor Yellow
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
        -InputPath $CollectionPath -Sources "Browser" -OutputFile $OutputFile -NoExcel -NoReport -Viewer None 2>&1
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

# Test time ("yyyy-MM-dd HH:mm:ss.fff" UTC text) as a browser stores it:
# Chromium = microseconds since 1601, UnixMs = milliseconds since 1970
function ConvertTo-StoredTime {
    param([string]$Text, [ValidateSet("Chromium", "UnixMs")][string]$Format)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $time = [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    # Ticks of 1601-01-01 and 1970-01-01 UTC
    $epoch = if ($Format -eq "Chromium") { 504911232000000000L } else { 621355968000000000L }
    $ticksPerUnit = if ($Format -eq "UnixMs") { 10000L } else { 10L }
    $remainder = 0L
    return [Math]::DivRem([long]($time.Ticks - $epoch), $ticksPerUnit, [ref]$remainder)
}

# base::Pickle as Chromium writes it: uint32 payload size, then 4-byte
# aligned fields. Each field: @("int", n), @("int64", n), @("str", text)
# (UTF-8, int32 byte count) or @("str16", text) (UTF-16, int32 char count).
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
                # Assigned in the branches: an if expression would turn an
                # empty array into $null
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

# Payload of an UpdateTabNavigation command (SerializedNavigationEntry)
function New-TestNavigation {
    param([int]$TabId, [int]$Index, [string]$Url, [string]$Title, [int]$Transition, [string]$Referrer, [long]$Time)
    return , (New-TestPickle @(@("int", $TabId), @("int", $Index), @("str", $Url), @("str16", $Title),
        @("str", "$canary-page-state"), @("int", $Transition), @("int", 0), @("str", $Referrer), @("int", 1),
        @("str", $Url), @("int", 0), @("int64", $Time), @("str16", ""), @("int", 200)))
}

# SNSS file: "SNSS", int32 version, then per command uint16 size (id
# included), uint8 id and the payload. Each command: @(id, [byte[]]payload).
function New-TestSnss {
    param([int]$Version, [object[]]$Commands, [byte[]]$Tail)
    $stream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($stream)
    $writer.Write([System.Text.Encoding]::ASCII.GetBytes("SNSS"))
    $writer.Write([int32]$Version)
    foreach ($command in $Commands) {
        [byte[]]$payload = $command[1]
        $writer.Write([uint16]($payload.Length + 1))
        $writer.Write([byte]$command[0])
        $writer.Write($payload)
    }
    if ($Tail) { $writer.Write($Tail) }
    $writer.Flush()
    return , $stream.ToArray()
}

# Fixed-layout payload: int32 id, int32 index (or padding), int64 time
function New-TestIdTimePayload {
    param([int]$Id, [int]$Index, [long]$Time)
    $bytes = New-Object byte[] 16
    [System.BitConverter]::GetBytes([int32]$Id).CopyTo($bytes, 0)
    [System.BitConverter]::GetBytes([int32]$Index).CopyTo($bytes, 4)
    [System.BitConverter]::GetBytes([int64]$Time).CopyTo($bytes, 8)
    return , $bytes
}

# mozLz4 writer for the Firefox session files: a small greedy LZ4 block
# compressor (literals, back-references, long lengths), C# 5
if (-not ([System.Management.Automation.PSTypeName]'BrowserExtrasTest.Lz4').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BrowserExtrasTest
{
    public static class Lz4
    {
        public static byte[] CompressMozLz4(byte[] src)
        {
            MemoryStream o = new MemoryStream();
            o.Write(Encoding.ASCII.GetBytes("mozLz40\0"), 0, 8);
            o.Write(BitConverter.GetBytes(src.Length), 0, 4);
            Dictionary<int, int> seen = new Dictionary<int, int>();
            int n = src.Length;
            int anchor = 0;
            int i = 0;
            // The last match must start at least 12 bytes before the end
            while (i < n - 12)
            {
                int key = BitConverter.ToInt32(src, i);
                int candidate;
                if (seen.TryGetValue(key, out candidate) && i - candidate <= 65535)
                {
                    int length = 4;
                    while (i + length < n - 5 && src[candidate + length] == src[i + length]) { length++; }
                    WriteSequence(o, src, anchor, i - anchor, i - candidate, length);
                    seen[key] = i;
                    i += length;
                    anchor = i;
                    continue;
                }
                seen[key] = i;
                i++;
            }
            WriteSequence(o, src, anchor, n - anchor, 0, 0);
            return o.ToArray();
        }

        static void WriteSequence(MemoryStream o, byte[] src, int start, int literals, int offset, int matchLength)
        {
            int matchCode = matchLength > 0 ? matchLength - 4 : 0;
            o.WriteByte((byte)((Math.Min(literals, 15) << 4) | Math.Min(matchCode, 15)));
            if (literals >= 15) { WriteLength(o, literals - 15); }
            o.Write(src, start, literals);
            if (matchLength == 0) { return; }
            o.WriteByte((byte)(offset & 0xFF));
            o.WriteByte((byte)(offset >> 8));
            if (matchCode >= 15) { WriteLength(o, matchCode - 15); }
        }

        static void WriteLength(MemoryStream o, int value)
        {
            while (value >= 255) { o.WriteByte(255); value -= 255; }
            o.WriteByte((byte)value);
        }
    }
}
'@
}

# Chromium extension ids (32 letters a-p)
$idTab = "abcdefghijklmnopabcdefghijklmnop"
$idDev = "bcdefghijklmnopabcdefghijklmnopa"
$idLoader = "cdefghijklmnopabcdefghijklmnopab"
$idComponent = "defghijklmnopabcdefghijklmnopabc"
$idStub = "efghijklmnopabcdefghijklmnopabcd"
$idPolicy = "fghijklmnopabcdefghijklmnopabcde"

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("browser-extras-test-" + [guid]::NewGuid().ToString("N"))
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
    $chromeDir = Join-Path $userDir "Chrome"
    $profileDir = Join-Path $chromeDir "Default"
    New-TestTextFile -Path (Join-Path $collection "collection_info.json") -Text '{"Mode":"Live","CollectionStartUtc":"2026-03-03T00:00:00Z","CollectorTimeZoneId":"UTC","TargetTimeZoneId":"UTC"}'

    # Secure Preferences: extensions.settings (Windows keeps them here). Tab
    # Helper: from the store, name from messages.json (key in other case),
    # sets a proxy; Dev Tool: unpacked, disabled by the user, overrides the
    # search engine, older install_time key; Loader: --load-extension, no
    # manifest in the settings (the collected one is used), disable reasons
    # as a list; a component extension and a permissions-only entry (no
    # rows); Policy Ext: force-installed, no install time (Snapshot row)
    $chromeTime = @{}
    foreach ($t in @("2026-01-05 10:00:00.000", "2026-02-10 08:30:00.000", "2026-02-14 22:15:00.000", "2026-02-28 03:00:00.000", "2026-01-01 00:00:00.000", "2026-03-01 18:45:00.000")) {
        $chromeTime[$t] = ConvertTo-StoredTime $t Chromium
    }
    New-TestTextFile -Path (Join-Path $profileDir "Secure Preferences") -Text (@"
{"extensions":{"settings":{
 "$idTab":{"location":1,"from_webstore":true,"state":1,"path":"$idTab\\1.2.3_0","first_install_time":"$($chromeTime['2026-01-05 10:00:00.000'])",
  "manifest":{"name":"__MSG_extName__","version":"1.2.3","default_locale":"en","update_url":"https://clients2.google.com/service/update2/crx"},
  "granted_permissions":{"api":["tabs","storage"],"explicit_host":["<all_urls>"],"manifest_permissions":[],"scriptable_host":["<all_urls>"]},
  "content_settings":[{"canary":"$canary-content"}],
  "preferences":{"proxy":{"mode":"fixed_servers","server":"10.9.9.9:3128"}},"regular_only_preferences":{}},
 "$idDev":{"location":4,"from_webstore":false,"path":"C:\\Users\\alice\\dev\\ext","install_time":"$($chromeTime['2026-02-14 22:15:00.000'])","disable_reasons":1,
  "manifest":{"name":"Dev Tool","version":"0.1","chrome_settings_overrides":{"search_provider":{"name":"Dev","search_url":"https://dev.example/?q={searchTerms}"}}},
  "active_permissions":{"api":["webRequest"],"explicit_host":["https://*/*"],"manifest_permissions":[],"scriptable_host":[]}},
 "$idLoader":{"location":8,"from_webstore":false,"path":"$idLoader\\2.0_0","first_install_time":"$($chromeTime['2026-02-28 03:00:00.000'])","disable_reasons":[8192,8388608,536870912]},
 "$idComponent":{"location":5,"path":"C:\\Program Files\\Google\\Chrome\\Application\\120.0\\resources\\pdf","first_install_time":"$($chromeTime['2026-01-01 00:00:00.000'])","manifest":{"name":"Built-in PDF","version":"1"}},
 "$idStub":{"active_permissions":{"api":[]},"granted_permissions":{"api":[]}},
 "$idPolicy":{"location":7,"from_webstore":false,"path":"$idPolicy\\3.1_0","manifest":{"name":"Policy Ext","version":"3.1","update_url":"https://updates.evil.example/crx"}}
}},
"protection":{"macs":{"homepage":"$canary-mac"}}}
"@)
    # Preferences: the settings, Tab Helper's last update (merged with its
    # Secure Preferences entry), the Clear browsing data dialog choices and
    # an iOS-only last-clear time (no rows), and secret and site fields that
    # must never be read. The content_settings member would give a "Clear
    # data on exit" row with the canary if it were read.
    New-TestTextFile -Path (Join-Path $profileDir "Preferences") -Text (@"
{"extensions":{"settings":{"$idTab":{"last_update_time":"$($chromeTime['2026-02-10 08:30:00.000'])"}}},
 "proxy":{"mode":"pac_script","pac_url":"http://wpad.evil.example/proxy.pac"},
 "download":{"default_directory":"D:\\Drop","prompt_for_download":false},
 "session":{"restore_on_startup":4,"startup_urls":["https://start.example.com/","https://second.example.com/"]},
 "homepage":"https://home.example.com/","homepage_is_newtabpage":false,
 "default_search_provider_data":{"template_url_data":{"short_name":"Evil Search","keyword":"evil","url":"https://search.evil.example/?q={searchTerms}"}},
 "browser":{"clear_data_on_exit":{"browsing_history":true,"cookies":false},"last_clear_browsing_data_time":"$($chromeTime['2026-03-01 18:45:00.000'])",
  "clear_data":{"browsing_history":true,"cookies":true,"cache":false,"time_period":4}},
 "signin":{"cookie_clear_on_exit_migration_notice_complete":true},
 "history":{"saving_disabled":true},"incognito":{"mode_availability":2},
 "profile":{"name":"Person 1","default_content_setting_values":{"cookies":4},"content_settings":{"clear_on_exit_$canary":true,"exceptions":{"cookies":{"https://$canary.example,*":{"setting":1}}}}},
 "password_hash_data_list":[{"hash":"$canary-hash","salt":"$canary-salt","username":"alice"}],
 "account_info":[{"email":"$canary@example.com"}],
 "os_crypt":{"encrypted_key":"$canary-key"}}
"@)
    # Collected extension files: Tab Helper's messages.json, Loader's
    # manifest (with comments and a trailing comma, which Chromium accepts)
    New-TestTextFile -Path (Join-Path $profileDir "Extensions\$idTab\1.2.3_0\_locales\en\messages.json") -Text '{"extname":{"message":"Tab Helper","description":"name"}}'
    New-TestTextFile -Path (Join-Path $profileDir "Extensions\$idLoader\2.0_0\manifest.json") -Text ("{`r`n  // Extension manifest`r`n  ""manifest_version"": 3, /* MV3 */`r`n" +
        "  ""name"": ""Loader"",`r`n  ""description"": ""a // b /* c */"",`r`n  ""version"": ""2.0"",`r`n}")
    # Brave: its clear-on-exit settings (browser.clear_data.*_on_exit) and
    # startup mode 6
    New-TestTextFile -Path (Join-Path $userDir "Brave\Default\Preferences") -Text ('{"browser":{"clear_data":{"browsing_history_on_exit":true,"cookies_on_exit":true,"cache_on_exit":false,"browsing_history":true}},' +
        '"session":{"restore_on_startup":6,"startup_urls":["https://brave-start.example/"]}}')
    # Local State: experimental flags; the encrypted key is never read
    New-TestTextFile -Path (Join-Path $chromeDir "Local State") -Text ('{"browser":{"enabled_labs_experiments":["enable-quic@2","extension-mime-request-handling@1"]},' +
        '"os_crypt":{"encrypted_key":"' + $canary + '-local-state"},"profile":{"info_cache":{"Default":{"name":"Person 1"}}}}')
    # An app's Preferences file outside any browser profile (no History next to it)
    New-TestTextFile -Path (Join-Path $collection "UserActivity\alice\SomeApp\Preferences") -Text '{"proxy":{"mode":"fixed_servers","server":"10.1.1.1:80"}}'

    # History: the live one and two snapshots. kept = in all three (no
    # snapshot row); deleted = in both snapshots, within Chromium's 90 days
    # (one row, from the newest snapshot); old = older than 90 days; and
    # one visit only in the older snapshot
    $historySchema = @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,external_referrer_url TEXT,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,opener_visit INTEGER,originator_cache_guid TEXT,originator_visit_id INTEGER,originator_from_visit INTEGER,originator_opener_visit INTEGER,is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,visited_link_id INTEGER DEFAULT 0 NOT NULL,app_id TEXT);
CREATE INDEX visits_time_index ON visits (visit_time);
"@
    $visitSql = "INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES ({0}, '{1}', '{2}', 1, {3}); INSERT INTO visits (url, visit_time, transition) VALUES ({0}, {3}, {4});"
    $kept = $visitSql -f 1, "https://kept.example.com/", "Kept", (ConvertTo-StoredTime "2026-02-20 10:00:00.000" Chromium), 805306369
    $deleted = $visitSql -f 2, "https://deleted.example.com/", "Deleted Page", (ConvertTo-StoredTime "2026-02-25 12:00:00.000" Chromium), 0
    # The live History also has the visit of one session entry (20 s after
    # the entry's time: InHistory=Yes)
    New-TestDatabase -Path (Join-Path $profileDir "History") -Sql ($historySchema + $kept +
        ($visitSql -f 5, "https://news.example.com/story", "Story", (ConvertTo-StoredTime "2026-03-02 08:05:20.000" Chromium), 0))
    # Edge Case Page: 91 days before the collection, but within 90 days of
    # the live History's last write (2026-03-01, from the manifest): Deleted
    New-TestDatabase -Path (Join-Path $chromeDir "Snapshots\120.0.6099.71\Default\History") -Sql ($historySchema + $kept + $deleted +
        ($visitSql -f 3, "https://old.example.com/", "Old Page", (ConvertTo-StoredTime "2025-10-01 12:00:00.000" Chromium), 1) +
        ($visitSql -f 6, "https://edge-case.example.com/", "Edge Case Page", (ConvertTo-StoredTime "2025-12-02 12:00:00.000" Chromium), 0))
    New-TestDatabase -Path (Join-Path $chromeDir "Snapshots\119.0.6045.199\Default\History") -Sql ($historySchema + $deleted +
        ($visitSql -f 4, "https://older-snap.example.com/", "Older Snapshot Page", (ConvertTo-StoredTime "2026-01-15 12:00:00.000" Chromium), 0))
    # A snapshot of a profile whose live History was not collected
    New-TestDatabase -Path (Join-Path $userDir "Edge\Snapshots\118.0.2088.46\Profile 1\History") -Sql ($historySchema +
        ($visitSql -f 1, "https://nolive.example.com/", "No Live Page", (ConvertTo-StoredTime "2026-02-01 12:00:00.000" Chromium), 0))
    # A Windows account named "Snapshots": its History is live history, not
    # a snapshot
    New-TestDatabase -Path (Join-Path $collection "Browser\Snapshots\Chrome\Default\History") -Sql ($historySchema +
        ($visitSql -f 1, "https://snapshots-user.example.com/", "Snapshots User Page", (ConvertTo-StoredTime "2026-02-03 12:00:00.000" Chromium), 1))
    # Collection manifest: original times of the History files (when each
    # snapshot was taken; the live History's last write)
    $manifestRows = @(
        @("Browser\alice\Chrome\Default\History", "2025-06-01T00:00:00.0000000Z", "2026-03-01T00:00:00.0000000Z"),
        @("Browser\alice\Chrome\Snapshots\120.0.6099.71\Default\History", "2026-02-26T03:00:00.0000000Z", "2026-02-25T23:00:00.0000000Z"),
        @("Browser\alice\Chrome\Snapshots\119.0.6045.199\Default\History", "2026-02-01T00:00:00.0000000Z", "2026-01-31T00:00:00.0000000Z")
    )
    $manifestText = '"SHA256","SourcePath","DestPath","SizeBytes","CollectedAt","RelativePath","SourceCreatedUtc","SourceModifiedUtc","SourceAccessedUtc"' + "`r`n"
    foreach ($m in $manifestRows) {
        $manifestText += '"0","C:\Users\alice\' + $m[0] + '","' + (Join-Path $collection $m[0]) + '","1","2026-03-03 00:00:00","' + $m[0] + '","' + $m[1] + '","' + $m[2] + '",""' + "`r`n"
    }
    New-TestTextFile -Path (Join-Path $collection "collection_manifest.csv") -Text $manifestText

    # Bookmarks: its page's icon is kept in Favicons (no favicon row)
    New-TestTextFile -Path (Join-Path $profileDir "Bookmarks") -Text ('{"checksum":"","roots":{"bookmark_bar":{"children":[{"date_added":"' + (ConvertTo-StoredTime "2026-01-20 00:00:00.000" Chromium) +
        '","id":"5","name":"Bookmarked","type":"url","url":"https://bookmarked.example.com/"}],"date_added":"0","id":"1","name":"Bookmarks bar","type":"folder"},' +
        '"other":{"children":[],"date_added":"0","id":"2","name":"Other bookmarks","type":"folder"}},"version":1}')

    # Favicons (live): rows only for http(s) pages with an icon stored on a
    # visit that are in neither History nor Bookmarks. cleared.example.com/a
    # has two icons: the row takes the time and URL of the newer one. One
    # icon serves two pages (PagesSharingIcon=2).
    $faviconSchema = @"
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY,page_url LONGVARCHAR NOT NULL,icon_id INTEGER, page_url_type INTEGER DEFAULT 0);
CREATE TABLE favicons(id INTEGER PRIMARY KEY,url LONGVARCHAR NOT NULL,icon_type INTEGER DEFAULT 1);
CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY,icon_id INTEGER NOT NULL,last_updated INTEGER DEFAULT 0,image_data BLOB,width INTEGER DEFAULT 0,height INTEGER DEFAULT 0,last_requested INTEGER DEFAULT 0);
"@
    $iconSql = "INSERT INTO favicons VALUES ({0}, '{1}', 1); INSERT INTO icon_mapping (page_url, icon_id) VALUES ('{2}', {0}); INSERT INTO favicon_bitmaps (icon_id, last_updated, image_data, width, height, last_requested) VALUES ({0}, {3}, X'00', 16, 16, {4});"
    New-TestDatabase -Path (Join-Path $profileDir "Favicons") -Sql ($faviconSchema +
        ($iconSql -f 1, "https://cleared.example.com/favicon.ico", "https://cleared.example.com/a", (ConvertTo-StoredTime "2026-02-27 07:00:00.000" Chromium), 0) +
        ($iconSql -f 2, "https://kept.example.com/favicon.ico", "https://kept.example.com/", (ConvertTo-StoredTime "2026-02-20 10:00:01.000" Chromium), 0) +
        ($iconSql -f 3, "https://bookmarked.example.com/favicon.ico", "https://bookmarked.example.com/", (ConvertTo-StoredTime "2026-01-20 00:00:01.000" Chromium), 0) +
        ($iconSql -f 4, "https://tiles.example.net/ntp.png", "https://ntp-tile.example.com/", 0, (ConvertTo-StoredTime "2026-02-01 00:00:00.000" Chromium)) +
        ($iconSql -f 5, "chrome://theme/IDR_SETTINGS_FAVICON", "chrome://settings/", (ConvertTo-StoredTime "2026-02-02 00:00:00.000" Chromium), 0) +
        ($iconSql -f 6, "https://old-icon.example.com/favicon.ico", "https://old-icon.example.com/", (ConvertTo-StoredTime "2025-09-01 07:00:00.000" Chromium), 0) +
        ($iconSql -f 7, "https://shared.example.com/favicon.ico", "https://shared.example.com/one", (ConvertTo-StoredTime "2026-02-15 09:00:00.000" Chromium), 0) +
        "INSERT INTO icon_mapping (page_url, icon_id) VALUES ('https://shared.example.com/two', 7);" +
        ($iconSql -f 8, "https://cleared.example.com/touch.png", "https://cleared.example.com/a", (ConvertTo-StoredTime "2026-02-20 07:00:00.000" Chromium), 0))
    # Favicons in the newest snapshot: a page already reported from the live
    # Favicons, a page in that snapshot's History (reported as a visit) and
    # one page only here
    New-TestDatabase -Path (Join-Path $chromeDir "Snapshots\120.0.6099.71\Default\Favicons") -Sql ($faviconSchema +
        ($iconSql -f 1, "https://cleared.example.com/favicon.ico", "https://cleared.example.com/a", (ConvertTo-StoredTime "2026-02-26 07:00:00.000" Chromium), 0) +
        ($iconSql -f 2, "https://deleted.example.com/favicon.ico", "https://deleted.example.com/", (ConvertTo-StoredTime "2026-02-25 12:00:01.000" Chromium), 0) +
        ($iconSql -f 3, "https://snapfav.example.com/favicon.ico", "https://snapfav.example.com/", (ConvertTo-StoredTime "2026-02-10 07:00:00.000" Chromium), 0))

    # SNSS session file: tab 1 (window 10) with two navigations (the first
    # written twice, the title changed), the second selected, then closed;
    # tab 2 a new tab page (no row); tab 3 in window 11, which was closed;
    # tab 4 still open (window 10); and a command cut off at the end
    $idPair = { param([int]$First, [int]$Second) , [byte[]]([System.BitConverter]::GetBytes([int32]$First) + [System.BitConverter]::GetBytes([int32]$Second)) }
    $sessionFile = New-TestSnss -Version 1 -Commands @(
        @(0, (& $idPair 10 1)), @(0, (& $idPair 10 2)), @(0, (& $idPair 11 3)), @(0, (& $idPair 10 4)),
        @(6, (New-TestNavigation -TabId 1 -Index 0 -Url "https://news.example.com/" -Title "News" -Transition 0x30000001 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-02 08:00:00.000" Chromium))),
        @(6, (New-TestNavigation -TabId 1 -Index 0 -Url "https://news.example.com/" -Title "News - Updated" -Transition 0x30000001 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-02 08:00:00.000" Chromium))),
        @(6, (New-TestNavigation -TabId 1 -Index 1 -Url "https://news.example.com/story" -Title "Story" -Transition 0 -Referrer "https://news.example.com/" -Time (ConvertTo-StoredTime "2026-03-02 08:05:00.000" Chromium))),
        @(7, (& $idPair 1 1)),
        @(6, (New-TestNavigation -TabId 2 -Index 0 -Url "chrome://newtab/" -Title "New Tab" -Transition 1 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-02 08:10:00.000" Chromium))),
        @(6, (New-TestNavigation -TabId 3 -Index 0 -Url "https://window-closed.example.com/" -Title "Window Closed Page" -Transition 1 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-02 07:00:00.000" Chromium))),
        @(6, (New-TestNavigation -TabId 4 -Index 0 -Url "https://open-tab.example.com/" -Title "Open Tab" -Transition 1 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-02 10:00:00.000" Chromium))),
        @(17, (New-TestIdTimePayload -Id 11 -Index 0 -Time (ConvertTo-StoredTime "2026-03-02 07:30:00.000" Chromium))),
        @(16, (New-TestIdTimePayload -Id 1 -Index 0 -Time (ConvertTo-StoredTime "2026-03-02 09:00:00.000" Chromium)))
    ) -Tail ([byte[]]@(0x40, 0x00, 6, 1, 2, 3))
    New-TestBinaryFile -Path (Join-Path $profileDir "Sessions\Session_13418000000000000") -Bytes $sessionFile
    # SNSS tab-restore file (version 3): a closed tab (close time in
    # SelectedNavigationInTab), reopened later (RestoredEntry); a closed
    # window (Window command: id 20, 2 tabs, close time) whose tabs have no
    # time of their own. The selected entry is counted among the tab's
    # entries in the file: tab 21 shows its 2nd entry, tab 22 its only one.
    $windowCommand = New-TestPickle @(@("int", 20), @("int", 0), @("int", 2), @("int64", (ConvertTo-StoredTime "2026-03-01 12:00:00.000" Chromium)),
        @("int", 0), @("int", 0), @("int", 800), @("int", 600), @("int", 1), @("str", ""), @("int", 0))
    $tabsFile = New-TestSnss -Version 3 -Commands @(
        @(4, (New-TestIdTimePayload -Id 5 -Index 0 -Time (ConvertTo-StoredTime "2026-03-01 16:30:00.000" Chromium))),
        @(1, (New-TestNavigation -TabId 5 -Index 0 -Url "https://closed-tab.example.net/" -Title "Closed Tab" -Transition 1 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-01 16:00:00.000" Chromium))),
        @(9, $windowCommand),
        @(4, (New-TestIdTimePayload -Id 21 -Index 1 -Time 0)),
        @(1, (New-TestNavigation -TabId 21 -Index 4 -Url "https://w-first.example.net/" -Title "W First" -Transition 1 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-01 11:00:00.000" Chromium))),
        @(1, (New-TestNavigation -TabId 21 -Index 5 -Url "https://w-second.example.net/" -Title "W Second" -Transition 0 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-01 11:30:00.000" Chromium))),
        @(4, (New-TestIdTimePayload -Id 22 -Index 0 -Time 0)),
        @(1, (New-TestNavigation -TabId 22 -Index 3 -Url "https://w-other.example.net/" -Title "W Other" -Transition 1 -Referrer "" -Time (ConvertTo-StoredTime "2026-03-01 11:45:00.000" Chromium))),
        @(2, [System.BitConverter]::GetBytes([int32]5))
    )
    New-TestBinaryFile -Path (Join-Path $profileDir "Sessions\Tabs_13418000000000001") -Bytes $tabsFile

    # --- Firefox profile ---
    $ffDir = Join-Path $userDir "Firefox\abcd1234.default-release"
    $ffInstall1 = ConvertTo-StoredTime "2026-01-12 09:00:00.000" UnixMs
    $ffUpdate1 = ConvertTo-StoredTime "2026-02-20 09:00:00.000" UnixMs
    $ffInstall2 = ConvertTo-StoredTime "2026-02-22 23:00:00.000" UnixMs
    New-TestTextFile -Path (Join-Path $ffDir "extensions.json") -Text (@"
{"schemaVersion":36,"addons":[
 {"id":"helper@example.com","version":"1.4","type":"extension","location":"app-profile","active":true,"userDisabled":false,"installDate":$ffInstall1,"updateDate":$ffUpdate1,
  "defaultLocale":{"name":"Helper","creator":"Example"},"sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/helper.xpi","signedState":2,"foreignInstall":false,
  "userPermissions":{"permissions":["tabs","cookies"],"origins":["<all_urls>"]},"installTelemetryInfo":{"source":"amo","method":"amWebAPI"},
  "startupData":{"persistentListeners":{"webRequest":{"onBeforeRequest":[]}}},"locales":[]},
 {"id":"{11111111-2222-3333-4444-555555555555}","version":"0.9","type":"extension","location":"winreg-app-user","active":false,"userDisabled":true,"installDate":$ffInstall2,"updateDate":$ffInstall2,
  "defaultLocale":{"creator":null},"signedState":0,"foreignInstall":true,"userPermissions":{"permissions":["nativeMessaging"],"origins":[]}},
 {"id":"formautofill@mozilla.org","version":"1.0","type":"extension","location":"app-builtin","active":true,"installDate":$ffInstall1,"updateDate":$ffInstall1,"defaultLocale":{"name":"Form Autofill"}},
 {"id":"screenshots@mozilla.org","version":"39.0","type":"extension","location":"app-system-defaults","active":true,"installDate":$ffInstall1,"updateDate":$ffInstall1,"defaultLocale":{"name":"Screenshots"}},
 {"id":"default-theme@mozilla.org","version":"1.3","type":"theme","location":"app-builtin","active":true,"installDate":$ffInstall1,"updateDate":$ffInstall1,"defaultLocale":{"name":"System theme"}}
]}
"@)
    New-TestTextFile -Path (Join-Path $ffDir "addons.json") -Text '{"schema":6,"addons":[{"id":"{11111111-2222-3333-4444-555555555555}","name":"Sideloaded Tool","type":"extension"}]}'
    New-TestTextFile -Path (Join-Path $ffDir "prefs.js") -Text (@(
        '// Mozilla User Preferences',
        'user_pref("browser.download.dir", "E:\\Loot");',
        'user_pref("browser.download.folderList", 2);',
        'user_pref("browser.privatebrowsing.autostart", true);',
        'user_pref("browser.startup.homepage", "https://ff-home.example.com|https://ff-two.example.com");',
        'user_pref("browser.startup.page", 3);',
        'user_pref("network.proxy.http", "10.0.0.5");',
        'user_pref("network.proxy.http_port", 8080);',
        'user_pref("network.proxy.ssl", "10.0.0.5");',
        'user_pref("network.proxy.ssl_port", 8443);',
        'user_pref("network.proxy.type", 1);',
        'user_pref("network.cookie.lifetimePolicy", 2);',
        'user_pref("places.history.enabled", false);',
        'user_pref("privacy.clearOnShutdown.cache", false);',
        'user_pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", false);',
        'user_pref("privacy.clearOnShutdown_v2.siteSettings", true);',
        'user_pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs2", true);',
        'user_pref("privacy.sanitize.sanitizeOnShutdown", true);',
        ('user_pref("services.sync.tokenserver.token", "' + $canary + '-token");')
    ) -join "`r`n")
    # A Thunderbird prefs.js (the email collection): no Firefox rows
    New-TestTextFile -Path (Join-Path $collection "Email\alice\Thunderbird\xyz.default\prefs.js") -Text 'user_pref("network.proxy.type", 1);'

    # Session store: an open tab (current entry 2 of 2) and a new tab page,
    # a recently closed tab, a closed window; form data, cookies, page
    # state, POST data and typed text hold the canary
    $ms = @{}
    foreach ($t in @("2026-03-02 14:00:00.000", "2026-03-02 13:00:00.000", "2026-03-02 13:30:00.000", "2026-03-01 19:00:00.000", "2026-03-01 20:00:00.000", "2026-03-02 14:05:00.000")) {
        $ms[$t] = ConvertTo-StoredTime $t UnixMs
    }
    # A title that looks like a date stays text (PowerShell 7 turns such
    # strings into dates unless ConvertFrom-Json has -DateKind, from 7.5;
    # on 7.0 to 7.4 the title is an ordinary one)
    $windowTitle = "Window Page"
    if ($PSVersionTable.PSEdition -eq "Desktop" -or (Get-Command ConvertFrom-Json).Parameters.ContainsKey("DateKind")) { $windowTitle = "2026-03-01T19:00:00" }
    $session = @"
{"version":["sessionrestore",1],"windows":[{"tabs":[
 {"entries":[{"url":"https://first.example.org/","title":"First","ID":1,"cacheKey":0},
  {"url":"https://open.example.org/page","title":"Open Page","ID":2,"formdata":{"id":{"q":"$canary-formdata"}},"structuredCloneState":"$canary-state","postdata_b64":"$canary-post","scroll":"0,100"}],
  "index":2,"lastAccessed":$($ms['2026-03-02 14:00:00.000']),"hidden":false,"userTypedValue":"$canary-typed","image":"data:image/png;base64,$canary"},
 {"entries":[{"url":"about:newtab","title":"New Tab"}],"index":1,"lastAccessed":$($ms['2026-03-02 14:05:00.000'])}],
 "_closedTabs":[{"state":{"entries":[{"url":"https://closed.example.org/","title":"Closed Page","referrerInfo":"$canary-referrer"}],"index":1,"lastAccessed":$($ms['2026-03-02 13:00:00.000'])},
  "title":"Closed Page","closedAt":$($ms['2026-03-02 13:30:00.000']),"closedId":1}],
 "cookies":[{"host":".example.org","name":"sid","value":"$canary-cookie"}],"selected":1}],
"_closedWindows":[{"tabs":[{"entries":[{"url":"https://window.example.org/","title":"$windowTitle"}],"index":1,"lastAccessed":$($ms['2026-03-01 19:00:00.000'])}],
 "_closedTabs":[],"closedAt":$($ms['2026-03-01 20:00:00.000'])}],
"session":{"lastUpdate":$($ms['2026-03-02 14:05:00.000']),"startTime":$($ms['2026-03-02 13:00:00.000'])},
"global":{},"cookies":[{"host":".example.org","name":"sid2","value":"$canary-cookie-2"}]}
"@
    # Repeated padding inside a blanked member gives the compressor long matches
    $session = $session.Replace('"scroll":"0,100"', '"scroll":"' + ("0,100;" * 200) + '"')
    $compressed = [BrowserExtrasTest.Lz4]::CompressMozLz4([System.Text.Encoding]::UTF8.GetBytes($session))
    New-TestBinaryFile -Path (Join-Path $ffDir "sessionstore.jsonlz4") -Bytes $compressed
    # The same session as a backup: its rows are merged with the first file's
    New-TestBinaryFile -Path (Join-Path $ffDir "sessionstore-backups\recovery.baklz4") -Bytes $compressed
    # A damaged session file (cut off): reported, nothing added
    New-TestBinaryFile -Path (Join-Path $userDir "Firefox\broken.default\sessionstore.jsonlz4") -Bytes ($compressed[0..([int]($compressed.Length / 2))])

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
    $snapshotTime = "2026-03-03 00:00:00.000"
    $tabHelper = "Tab Helper ($idTab)"
    $tabHelperDetails = @("ID=$idTab", "Name=Tab Helper", "Version=1.2.3", "Location=Internal", "LocationCode=1", "State=Enabled", "FromWebstore=Yes",
        "UpdateURL=https://clients2.google.com/service/update2/crx", "Permissions=tabs, storage", "HostPermissions=<all_urls>",
        "InstallTimeUtc=2026-01-05 10:00:00", "UpdateTimeUtc=2026-02-10 08:30:00", "Profile=Default")
    $helperDetails = @("ID=helper@example.com", "Name=Helper", "Version=1.4", "Type=extension", "Location=app-profile", "Active=Yes", "SignedState=Signed",
        "SourceURI=https://addons.mozilla.org/firefox/downloads/file/1/helper.xpi", "InstallSource=amo", "Permissions=tabs, cookies",
        "HostPermissions=<all_urls>", "InstallTimeUtc=2026-01-12 09:00:00", "UpdateTimeUtc=2026-02-20 09:00:00", "Profile=abcd1234.default-release")
    $chromeSetting = "Chrome Preferences"
    $ffSetting = "Firefox Preferences"
    $expected = @(
        # Chromium extensions
        @{ Time = "2026-01-05 10:00:00.000"; Source = "Chrome Extensions"; Type = "Installation"; Text = "Browser extension installed: $tabHelper"; Has = $tabHelperDetails; Lacks = @("DisableReasons=", "Path=", "InstalledByDefault=") }
        @{ Time = "2026-02-10 08:30:00.000"; Source = "Chrome Extensions"; Type = "Installation"; Text = "Browser extension updated: $tabHelper"; Has = $tabHelperDetails }
        @{ Time = "2026-02-14 22:15:00.000"; Source = "Chrome Extensions"; Type = "Installation"; Text = "Browser extension installed: Dev Tool ($idDev)"
            Has = @("Location=Unpacked", "LocationCode=4", "State=Disabled", "DisableReasons=USER_ACTION", "Path=C:\Users\alice\dev\ext", "Overrides=search_provider",
                "FromWebstore=No", "Permissions=webRequest", "HostPermissions=https://*/*", "InstallTimeUtc=2026-02-14 22:15:00"); Lacks = @("UpdateTimeUtc=") }
        @{ Time = "2026-02-28 03:00:00.000"; Source = "Chrome Extensions"; Type = "Installation"; Text = "Browser extension installed: Loader ($idLoader)"
            Has = @("Name=Loader", "Version=2.0", "Location=CommandLine", "LocationCode=8", "State=Disabled", "DisableReasons=EXTERNAL_EXTENSION, UNSUPPORTED_MANIFEST_VERSION, 536870912") }
        @{ Time = $snapshotTime; Source = "Chrome Extensions"; Type = "Snapshot"; Text = "Browser extension present: Policy Ext ($idPolicy)"
            Has = @("Location=ExternalPolicyDownload", "LocationCode=7", "Version=3.1", "UpdateURL=https://updates.evil.example/crx", "State=Enabled"); Lacks = @("InstallTimeUtc=") }
        # Chromium settings (no row for the last-clear time, an iOS-only pref)
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Proxy = pac_script http://wpad.evil.example/proxy.pac"; Has = @("Setting=Proxy", "Pref=proxy", "Profile=Default") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Proxy = fixed_servers 10.9.9.9:3128"
            Has = @("SetByExtension=$idTab", "Pref=extensions.settings.$idTab.preferences.proxy") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Download directory = D:\Drop"; Has = @("PromptForDownload=No", "Pref=download.default_directory") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Startup = Open specific pages: https://start.example.com/, https://second.example.com/" }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Homepage = https://home.example.com/"; Has = @("HomepageIsNewTabPage=No") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Default search engine = Evil Search (https://search.evil.example/?q={searchTerms})"; Has = @("Keyword=evil") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Clear data on exit = On (browsing_history)"; Has = @("Pref=browser.clear_data_on_exit.browsing_history") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Clear data on exit = On (cookies and site data: kept for the session only)" }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: History disabled = Yes"; Has = @("Pref=history.saving_disabled") }
        @{ Time = $snapshotTime; Source = $chromeSetting; Type = "Snapshot"; Text = "Browser setting: Private browsing always on = Yes"; Has = @("Pref=incognito.mode_availability") }
        @{ Time = $snapshotTime; Source = "Chrome Local State"; Type = "Snapshot"; Text = "Browser setting: Experimental flags = enable-quic@2, extension-mime-request-handling@1"; Lacks = @("Profile=") }
        @{ Time = $snapshotTime; Source = "Brave Preferences"; Type = "Snapshot"; Text = "Browser setting: Clear data on exit = On (browsing_history_on_exit, cookies_on_exit)"
            Has = @("Pref=browser.clear_data.browsing_history_on_exit, browser.clear_data.cookies_on_exit", "Profile=Default") }
        @{ Time = $snapshotTime; Source = "Brave Preferences"; Type = "Snapshot"; Text = "Browser setting: Startup = Restore last session and open specific pages: https://brave-start.example/" }
        # Firefox add-ons
        @{ Time = "2026-01-12 09:00:00.000"; Source = "Firefox Extensions"; Type = "Installation"; Text = "Browser extension installed: Helper (helper@example.com)"; Has = $helperDetails; Lacks = @("ForeignInstall=", "UserDisabled=") }
        @{ Time = "2026-02-20 09:00:00.000"; Source = "Firefox Extensions"; Type = "Installation"; Text = "Browser extension updated: Helper (helper@example.com)"; Has = $helperDetails }
        @{ Time = "2026-02-22 23:00:00.000"; Source = "Firefox Extensions"; Type = "Installation"; Text = "Browser extension installed: Sideloaded Tool ({11111111-2222-3333-4444-555555555555})"
            Has = @("Name=Sideloaded Tool", "Location=winreg-app-user", "Active=No", "UserDisabled=Yes", "SignedState=Missing", "ForeignInstall=Yes", "Permissions=nativeMessaging") }
        # Firefox settings. Clear data on exit: the privacy.clearOnShutdown_v2
        # items (migrated) with their defaults overlaid by prefs.js
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Proxy = Manual http=10.0.0.5:8080 ssl=10.0.0.5:8443"; Has = @("Pref=network.proxy.type", "Profile=abcd1234.default-release") }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Homepage = https://ff-home.example.com, https://ff-two.example.com" }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Startup = Restore previous session" }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Download directory = E:\Loot"; Has = @("FolderList=2") }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Clear data on exit = On (cleared: cookiesAndStorage, cache, siteSettings)"
            Has = @("Pref=privacy.sanitize.sanitizeOnShutdown", "Cleared=cookiesAndStorage, cache, siteSettings", "Kept=historyFormDataAndDownloads", "PrefBranch=privacy.clearOnShutdown_v2") }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Clear data on exit = On (cookies and site data: kept for the session only)"; Has = @("Pref=network.cookie.lifetimePolicy") }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: History disabled = Yes"; Has = @("Pref=places.history.enabled") }
        @{ Time = $snapshotTime; Source = $ffSetting; Type = "Snapshot"; Text = "Browser setting: Private browsing always on = Yes"; Has = @("Pref=browser.privatebrowsing.autostart") }
        # Firefox sessions: open tabs at lastAccessed, closed tabs at closedAt
        @{ Time = "2026-03-02 14:00:00.000"; Source = "Firefox Sessions"; Type = "NetworkConnection"; Text = "Browser session tab: Open Page"
            Has = @("URL=https://open.example.org/page", "Title=Open Page", "Entries=2", "LastAccessedUtc=2026-03-02 14:00:00", "Profile=abcd1234.default-release", "Occurrences=2"); Lacks = @("ClosedUtc=") }
        @{ Time = "2026-03-02 13:30:00.000"; Source = "Firefox Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: Closed Page"
            Has = @("URL=https://closed.example.org/", "ClosedUtc=2026-03-02 13:30:00", "LastAccessedUtc=2026-03-02 13:00:00"); Lacks = @("ClosedWindow=") }
        @{ Time = "2026-03-01 20:00:00.000"; Source = "Firefox Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: $windowTitle"
            Has = @("URL=https://window.example.org/", "Title=$windowTitle", "ClosedWindow=Yes", "LastAccessedUtc=2026-03-01 19:00:00") }
        # Chromium Session file: visits at the entry's time, closed tabs at
        # the close time (a tab closed with its window: the window's time)
        @{ Time = "2026-03-02 08:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: News - Updated"
            Has = @("URL=https://news.example.com/", "Transition=TYPED", "InHistory=No", "ClosedUtc=2026-03-02 09:00:00", "Profile=Default"); Lacks = @("Referrer=", "Current=", "ClosedWindow=") }
        @{ Time = "2026-03-02 08:05:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: Story"
            Has = @("URL=https://news.example.com/story", "Title=Story", "Transition=LINK", "Referrer=https://news.example.com/", "Current=Yes", "InHistory=Yes", "ClosedUtc=2026-03-02 09:00:00") }
        @{ Time = "2026-03-02 09:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: Story"
            Has = @("URL=https://news.example.com/story", "Entries=2", "VisitedUtc=2026-03-02 08:05:00", "ClosedUtc=2026-03-02 09:00:00"); Lacks = @("ClosedWindow=", "Reopened=") }
        @{ Time = "2026-03-02 07:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: Window Closed Page"
            Has = @("Current=Yes", "InHistory=No", "ClosedUtc=2026-03-02 07:30:00", "ClosedWindow=Yes") }
        @{ Time = "2026-03-02 07:30:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: Window Closed Page"
            Has = @("URL=https://window-closed.example.com/", "Entries=1", "VisitedUtc=2026-03-02 07:00:00", "ClosedWindow=Yes") }
        @{ Time = "2026-03-02 10:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in session tab: Open Tab"
            Has = @("URL=https://open-tab.example.com/", "Current=Yes", "InHistory=No"); Lacks = @("ClosedUtc=", "ClosedWindow=") }
        # Chromium Tabs file
        @{ Time = "2026-03-01 16:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: Closed Tab"
            Has = @("URL=https://closed-tab.example.net/", "Transition=TYPED", "Current=Yes", "InHistory=No", "ClosedUtc=2026-03-01 16:30:00", "Reopened=Yes"); Lacks = @("ClosedWindow=") }
        @{ Time = "2026-03-01 16:30:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: Closed Tab"
            Has = @("Entries=1", "VisitedUtc=2026-03-01 16:00:00", "ClosedUtc=2026-03-01 16:30:00", "Reopened=Yes") }
        @{ Time = "2026-03-01 11:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: W First"
            Has = @("ClosedUtc=2026-03-01 12:00:00", "ClosedWindow=Yes"); Lacks = @("Current=") }
        @{ Time = "2026-03-01 11:30:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: W Second"
            Has = @("Current=Yes", "ClosedUtc=2026-03-01 12:00:00", "ClosedWindow=Yes") }
        @{ Time = "2026-03-01 12:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: W Second"
            Has = @("URL=https://w-second.example.net/", "Entries=2", "VisitedUtc=2026-03-01 11:30:00", "ClosedWindow=Yes") }
        @{ Time = "2026-03-01 11:45:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser visit in closed tab: W Other"
            Has = @("Current=Yes", "ClosedWindow=Yes") }
        @{ Time = "2026-03-01 12:00:00.000"; Source = "Chrome Sessions"; Type = "NetworkConnection"; Text = "Browser closed tab: W Other"
            Has = @("Entries=1", "VisitedUtc=2026-03-01 11:45:00") }
        # Live history and bookmarks still parsed as before (also for an
        # account named "Snapshots"); snapshot History files give only their
        # visits that are not in the live History
        @{ Time = "2026-02-20 10:00:00.000"; Source = "Chrome History"; Type = "NetworkConnection"; Text = "Browser visit: Kept" }
        @{ Time = "2026-03-02 08:05:20.000"; Source = "Chrome History"; Type = "NetworkConnection"; Text = "Browser visit: Story" }
        @{ Time = "2026-02-03 12:00:00.000"; Source = "Chrome History"; Type = "NetworkConnection"; Text = "Browser visit: Snapshots User Page"; User = "Snapshots" }
        @{ Time = "2026-01-20 00:00:00.000"; Source = "Chrome Bookmarks"; Type = "NetworkConnection"; Text = "Bookmark added: Bookmarked (https://bookmarked.example.com/)" }
        @{ Time = "2026-02-25 12:00:00.000"; Source = "Chrome History Snapshot"; Type = "NetworkConnection"; Text = "Browser visit only in history snapshot: Deleted Page"
            Has = @("URL=https://deleted.example.com/", "Reason=Deleted", "Snapshot=120.0.6099.71", "SnapshotTakenUtc=2026-02-26 03:00:00",
                "LiveHistoryModifiedUtc=2026-03-01 00:00:00", "Transition=LINK", "Profile=Default") }
        @{ Time = "2025-10-01 12:00:00.000"; Source = "Chrome History Snapshot"; Type = "NetworkConnection"; Text = "Browser visit only in history snapshot: Old Page"
            Has = @("URL=https://old.example.com/", "Reason=Expired or deleted", "Snapshot=120.0.6099.71", "Transition=TYPED") }
        @{ Time = "2025-12-02 12:00:00.000"; Source = "Chrome History Snapshot"; Type = "NetworkConnection"; Text = "Browser visit only in history snapshot: Edge Case Page"
            Has = @("Reason=Deleted", "Snapshot=120.0.6099.71") }
        @{ Time = "2026-01-15 12:00:00.000"; Source = "Chrome History Snapshot"; Type = "NetworkConnection"; Text = "Browser visit only in history snapshot: Older Snapshot Page"
            Has = @("Reason=Deleted", "Snapshot=119.0.6045.199", "SnapshotTakenUtc=2026-02-01 00:00:00") }
        @{ Time = "2026-02-01 12:00:00.000"; Source = "Edge History Snapshot"; Type = "NetworkConnection"; Text = "Browser visit only in history snapshot: No Live Page"
            Has = @("Reason=No live History", "Snapshot=118.0.2088.46", "Profile=Profile 1"); Lacks = @("SnapshotTakenUtc=", "LiveHistoryModifiedUtc=") }
        # Favicons: pages not in history, at the icon's last update
        @{ Time = "2026-02-27 07:00:00.000"; Source = "Chrome Favicons"; Type = "NetworkConnection"; Text = "Browser favicon for page not in history: https://cleared.example.com/a"
            Has = @("IconURL=https://cleared.example.com/favicon.ico", "IconUpdatedUtc=2026-02-27 07:00:00", "PagesSharingIcon=1", "Profile=Default"); Lacks = @("Snapshot=", "Reason=") }
        @{ Time = "2025-09-01 07:00:00.000"; Source = "Chrome Favicons"; Type = "NetworkConnection"; Text = "Browser favicon for page not in history: https://old-icon.example.com/"
            Has = @("PagesSharingIcon=1") }
        @{ Time = "2026-02-15 09:00:00.000"; Source = "Chrome Favicons"; Type = "NetworkConnection"; Text = "Browser favicon for page not in history: https://shared.example.com/one"
            Has = @("IconURL=https://shared.example.com/favicon.ico", "PagesSharingIcon=2") }
        @{ Time = "2026-02-15 09:00:00.000"; Source = "Chrome Favicons"; Type = "NetworkConnection"; Text = "Browser favicon for page not in history: https://shared.example.com/two"
            Has = @("IconURL=https://shared.example.com/favicon.ico", "PagesSharingIcon=2") }
        @{ Time = "2026-02-10 07:00:00.000"; Source = "Chrome Favicons"; Type = "NetworkConnection"; Text = "Browser favicon for page not in history: https://snapfav.example.com/"
            Has = @("Snapshot=120.0.6099.71", "Profile=Default"); Lacks = @("Reason=") }
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
        $expectedUser = if ($e.User) { $e.User } else { "alice" }
        if ($byKey[$key].User -ne $expectedUser) { $problems += "User is '$($byKey[$key].User)'" }
        if ($problems.Count -gt 0) { Write-TestResult -Succeeded $false -Message "$key -- $($problems -join '; ') (Details: $details)" }
        else { Write-TestResult -Succeeded $true -Message $key }
    }
    # Hashtable keys are case-insensitive; compare the row texts exactly
    $unexpected = @($byKey.Keys | Where-Object { $expectedKeys -cnotcontains $_ })
    foreach ($key in $unexpected) { Write-TestResult -Succeeded $false -Message "unexpected row: $key" }
    Write-TestResult -Succeeded ($rows.Count -eq $expected.Count) -Message "$($rows.Count) rows in the timeline ($($expected.Count) expected)"

    # The canary is in every secret or private field: it must appear nowhere
    $csvText = [System.IO.File]::ReadAllText($timelineCsv)
    Write-TestResult -Succeeded ($csvText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or private value (canary) in the timeline CSV"
    $newReports = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $reportsBefore -notcontains $_.FullName })
    $logFiles = @($newReports | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter "*.txt" -File -ErrorAction SilentlyContinue })
    $logText = ($logFiles | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n"
    Write-TestResult -Succeeded ($logFiles.Count -gt 0 -and $logText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or private value (canary) in the builder log"
    Write-TestResult -Succeeded ((($builderOutput -join "`n").IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase)) -lt 0) -Message "no secret or private value (canary) in the builder output"
    # Built-in extensions are counted, not listed; the damaged session file is reported
    Write-TestResult -Succeeded (@($builderOutput | Where-Object { $_ -like "*1 built-in component extension(s) not listed*" }).Count -gt 0) -Message "the Chromium component extension is counted in the log"
    Write-TestResult -Succeeded (@($builderOutput | Where-Object { $_ -like "*3 built-in Firefox add-on(s) not listed*" }).Count -gt 0) -Message "the 3 built-in Firefox add-ons are counted in the log"
    Write-TestResult -Succeeded (@($builderOutput | Where-Object { $_ -like "*Could not read session file*broken.default*" }).Count -gt 0) -Message "the damaged Firefox session file is reported"

    # The builder's JSON reading itself: the members it must never read come
    # back blanked, with no canary left in what it parsed (the rows above
    # would not show a reader that skipped the blanking). The builder's own
    # functions and member lists are loaded from its source.
    $builderAst = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$null)
    $wantedFunctions = @("Initialize-BrowserReader", "Read-BrowserJsonFile", "ConvertFrom-BrowserJsonText")
    foreach ($definition in $builderAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($wantedFunctions -contains $definition.Name) { . ([scriptblock]::Create($definition.Extent.Text)) }
    }
    foreach ($assignment in $builderAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -match '^\$script:(jsonDateKindSupported|ChromiumPrefsBlankMembers|FirefoxSessionBlankMembers)$' }, $true)) {
        . ([scriptblock]::Create($assignment.Extent.Text))
    }
    $parsedDocs = @()
    foreach ($jsonFile in @((Join-Path $profileDir "Preferences"), (Join-Path $profileDir "Secure Preferences"), (Join-Path $chromeDir "Local State"))) {
        $parsedDocs += Read-BrowserJsonFile -Path $jsonFile -Blank $script:ChromiumPrefsBlankMembers
    }
    $parsedText = ($parsedDocs | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 100 -Compress }) -join "`n"
    $membersBlanked = $null -eq $parsedDocs[0].os_crypt -and $null -eq $parsedDocs[0].password_hash_data_list -and $null -eq $parsedDocs[0].account_info -and
        $null -eq $parsedDocs[0].profile.content_settings -and $null -eq $parsedDocs[1].protection -and $null -eq $parsedDocs[2].os_crypt -and
        $parsedDocs[0].download.default_directory -eq "D:\Drop"
    Write-TestResult -Succeeded ($membersBlanked -and $parsedText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) `
        -Message "the builder's JSON reader blanks the key, password hash, account and site members (Preferences, Secure Preferences, Local State)"
    $sessionBytes = [TimelineBrowser.Reader]::DecompressMozLz4([System.IO.File]::ReadAllBytes((Join-Path $ffDir "sessionstore.jsonlz4")))
    $sessionDoc = ConvertFrom-BrowserJsonText ([TimelineBrowser.Reader]::BlankJsonMembers([System.Text.Encoding]::UTF8.GetString($sessionBytes), [string[]]$script:FirefoxSessionBlankMembers))
    $sessionJson = ConvertTo-Json -InputObject $sessionDoc -Depth 100 -Compress
    Write-TestResult -Succeeded ($sessionJson.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and $sessionJson.Contains("https://open.example.org/page")) `
        -Message "the builder's Firefox session reading blanks form data, cookies, POST data, page state and typed text"

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all browser extras parser checks passed ($($rows.Count) rows)" -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the ones from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
