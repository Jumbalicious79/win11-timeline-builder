# =============================================================
# Email parser test
# Lays out a synthetic triage collection the way the collector's Email
# category writes it (Email\<user>\: the listing CSVs, copied attachments,
# the new Outlook UserSettings.json, a Thunderbird prefs.js and a
# global-messages-db.sqlite search index built with sqlite3.exe at test
# time, declared with Thunderbird's own full-text tokenizer as real ones
# are), runs timeline-builder.ps1 -Sources Email,RecentFiles and checks
# every email row, its time and its Details: attachments in the Outlook
# temp folders (copied, skipped, and copied from the shadow copy without a
# listing row), OST/PST and Windows Mail store files, Thunderbird mail
# folders and filter rules, accounts, and indexed messages (From, To, Cc and
# Bcc from the addresses gloda stores, not its full-text columns). A
# message text, a saved password, an OAuth token and a settings token hold
# a canary string that must appear nowhere in the timeline, the builder log
# or its output. A shortcut (.lnk) copied as an attachment must not be
# parsed as one of the system's recent files (the same file under
# UserActivity\ is), also when -InputPath is a relative path; nor an
# attachment named $MFT as the system's MFT.
#
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). For a local run without them, pass
# -BuilderPath with a copy of the builder that has no admin check, kept
# inside the repository (e.g. under the git-ignored reports\ folder).
# sqlite3.exe is looked for where the builder looks; if it is missing,
# the builder is run once so that its Find-Sqlite3Exe downloads it.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-EmailParsers.ps1
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
# Written into every secret and message text; must never reach the timeline or the log
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
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-EmailParsers.ps1::$Message" }
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

# Runs the builder on a collection (CSV only); returns its output
function Invoke-TimelineBuilder {
    param([string]$CollectionPath, [string]$OutputFile, [string]$Sources)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath $CollectionPath -Sources $Sources -OutputFile $OutputFile -NoExcel -Viewer None 2>&1
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

# Writes a text file (UTF-8 without BOM)
function New-TestTextFile {
    param([string]$Path, [string]$Text)
    New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

# Writes a CSV the way the collector does (all fields quoted)
function New-TestCsv {
    param([string]$Path, [string[]]$Columns, [object[]]$Rows)
    $lines = @('"' + ($Columns -join '","') + '"')
    foreach ($row in $Rows) {
        $lines += (($Columns | ForEach-Object { '"' + ([string]$row[$_]).Replace('"', '""') + '"' }) -join ',')
    }
    New-TestTextFile -Path $Path -Text (($lines -join "`r`n") + "`r`n")
}

# Test time ("yyyy-MM-dd HH:mm:ss" UTC) as the collector writes it (ISO 8601 "o")
function ConvertTo-IsoTime {
    param([string]$Text)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture, $styles).ToString("o")
}

# Test time ("yyyy-MM-dd HH:mm:ss" UTC) as PRTime (microseconds since 1970)
function ConvertTo-PRTime {
    param([string]$Text)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $time = [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
    return [long](($time.Ticks - 621355968000000000L) / 10L)
}

# One listing row (columns as the collector writes them)
function New-ListingRow {
    param([string]$User = "alice", [string]$Program, [string]$Store, [string]$ProfileName = "", [string]$Path, [string]$RelativePath,
          [long]$Size, [string]$Created, [string]$Modified, [string]$Accessed = "", [string]$Status = "Listed", [string]$CollectedAs = "")
    return @{
        User = $User; Program = $Program; Store = $Store; Profile = $ProfileName; Path = $Path; RelativePath = $RelativePath; SizeBytes = $Size
        CreatedUtc = $(if ($Created) { ConvertTo-IsoTime $Created } else { "" })
        ModifiedUtc = $(if ($Modified) { ConvertTo-IsoTime $Modified } else { "" })
        AccessedUtc = $(if ($Accessed) { ConvertTo-IsoTime $Accessed } else { "" })
        Status = $Status; CollectedAs = $CollectedAs
    }
}

$listingColumns = @("User", "Program", "Store", "Profile", "Path", "RelativePath", "SizeBytes", "CreatedUtc", "ModifiedUtc", "AccessedUtc", "Status", "CollectedAs")
$manifestColumns = @("SHA256", "SourcePath", "DestPath", "SizeBytes", "CollectedAt", "RelativePath", "SourceCreatedUtc", "SourceModifiedUtc", "SourceAccessedUtc")

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("email-test-" + [guid]::NewGuid().ToString("N"))
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
        $null = Invoke-TimelineBuilder -CollectionPath $bootstrapDir -OutputFile (Join-Path $workDir "bootstrap.csv") -Sources "Browser"
        $script:sqlite3 = Find-TestSqlite3
    }
    if (-not $script:sqlite3) {
        Write-TestResult -Succeeded $false -Message "sqlite3.exe is not available (not found, and the builder could not download it)"
        exit 1
    }
    Write-Host "Using sqlite3: $($script:sqlite3)"

    # --- Synthetic collection ---
    $collection = Join-Path $workDir "collection"
    New-TestTextFile -Path (Join-Path $collection "collection_info.json") -Text '{"Mode":"Live","TargetRoot":"C:\\","CollectionStartUtc":"2026-03-03T00:00:00Z","CollectorTimeZoneId":"UTC","TargetTimeZoneId":"UTC"}'
    $alice = "Email\alice"
    $tempFolder = "C:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABCD1234"
    $profileName = "abcd1234.default-release"
    $manifest = @()

    # Copied files: the collection path, contents, and the original's times
    $copies = @(
        @{ Relative = "$alice\Outlook\SecureTemp\INetCache\ABCD1234\invoice.docm"; Source = "$tempFolder\invoice.docm"; Text = "macro document"
           Created = "2026-03-01 10:00:00"; Modified = "2026-03-01 10:20:00"; Accessed = "2026-03-01 10:25:00" }
        @{ Relative = "$alice\NewOutlook\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf"
           Source = "C:\Users\alice\AppData\Local\Microsoft\Olk\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf"; Text = "pdf"
           Created = "2026-03-02 08:00:00"; Modified = "2026-03-02 08:00:00"; Accessed = "2026-03-02 08:00:00" }
        @{ Relative = "$alice\NewOutlook\UserSettings.json"; Source = "C:\Users\alice\AppData\Local\Microsoft\Olk\UserSettings.json"
           Text = '{"Flights":{"Version":"1"},"Identities":{"IdentityProperties":{"11111111-2222-3333-4444-555555555555":{"1":"1"}},' +
                  '"IdentityMap":{"alice@example.com":"11111111-2222-3333-4444-555555555555","alice@contoso.com":"66666666-7777-8888-9999-000000000000"}},' +
                  '"Session":{"token":"' + $canary + '-settings-token"}}'
           Created = "2026-01-15 07:00:00"; Modified = "2026-03-01 07:00:00"; Accessed = "2026-03-02 07:00:00" }
        # No listing CSV for bob: rows come from the manifest. Copied from the
        # shadow copy: the manifest has the path below the target root
        @{ Relative = "Email\bob\Outlook\SecureTemp\INetCache\ZZZZ9999\payload.js"
           Source = "(shadow)Users\bob\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ZZZZ9999\payload.js"; Text = "WScript.Echo('x');"
           Created = "2026-02-27 13:00:00"; Modified = "2026-02-27 13:00:00"; Accessed = "2026-02-27 13:05:00" }
    )
    $hashes = @{}
    foreach ($copy in $copies) {
        $path = Join-Path $collection $copy.Relative
        New-TestTextFile -Path $path -Text $copy.Text
        $hashes[$copy.Relative] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $manifest += @{ SHA256 = $hashes[$copy.Relative]; SourcePath = $copy.Source; DestPath = $path; SizeBytes = (Get-Item -LiteralPath $path).Length
            CollectedAt = "2026-03-03 00:01:00"; RelativePath = $copy.Relative; SourceCreatedUtc = (ConvertTo-IsoTime $copy.Created)
            SourceModifiedUtc = (ConvertTo-IsoTime $copy.Modified); SourceAccessedUtc = (ConvertTo-IsoTime $copy.Accessed) }
    }

    # A shortcut attached to a mail (copied from the temp folder) and the
    # same shortcut as one of alice's recent files: only the second is a
    # RecentFiles row
    $lnkRelative = "$alice\Outlook\SecureTemp\INetCache\ABCD1234\shortcut.lnk"
    $recentRelative = "UserActivity\alice\RecentFiles\shortcut.lnk"
    $shell = New-Object -ComObject WScript.Shell
    try {
        foreach ($relative in @($lnkRelative, $recentRelative)) {
            $lnkPath = Join-Path $collection $relative
            New-Item -ItemType Directory -Path (Split-Path $lnkPath -Parent) -Force | Out-Null
            $shortcut = $shell.CreateShortcut($lnkPath)
            $shortcut.TargetPath = Join-Path $env:SystemRoot "System32\notepad.exe"
            $shortcut.Save()
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)
            $manifest += @{ SHA256 = (Get-FileHash -LiteralPath $lnkPath -Algorithm SHA256).Hash; SourcePath = "C:\Users\alice\$relative"; DestPath = $lnkPath
                SizeBytes = (Get-Item -LiteralPath $lnkPath).Length; CollectedAt = "2026-03-03 00:01:00"; RelativePath = $relative
                SourceCreatedUtc = (ConvertTo-IsoTime "2026-03-01 11:00:00"); SourceModifiedUtc = (ConvertTo-IsoTime "2026-03-01 11:00:00"); SourceAccessedUtc = "" }
        }
    }
    finally { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    # An attachment named $MFT (not listed, not in the manifest): not the system's MFT
    New-TestTextFile -Path (Join-Path $collection "$alice\Outlook\SecureTemp\INetCache\ABCD1234\`$MFT") -Text ("FILE0" + ("x" * 1019))

    # Classic Outlook temp folder listing: the copied macro document (later
    # edited), the shortcut, and a file over the per-file cap
    New-TestCsv -Path (Join-Path $collection "$alice\Outlook\outlook_temp_files.csv") -Columns $listingColumns -Rows @(
        (New-ListingRow -Program "Classic Outlook" -Store "SecureTemp" -Path "$tempFolder\invoice.docm" -RelativePath "ABCD1234\invoice.docm" -Size 14 `
            -Created "2026-03-01 10:00:00" -Modified "2026-03-01 10:20:00" -Accessed "2026-03-01 10:25:00" -Status "Copied" -CollectedAs "$alice\Outlook\SecureTemp\INetCache\ABCD1234\invoice.docm"),
        (New-ListingRow -Program "Classic Outlook" -Store "SecureTemp" -Path "$tempFolder\shortcut.lnk" -RelativePath "ABCD1234\shortcut.lnk" -Size 1200 `
            -Created "2026-03-01 11:00:00" -Modified "2026-03-01 11:00:00" -Status "Copied" -CollectedAs $lnkRelative),
        (New-ListingRow -Program "Classic Outlook" -Store "SecureTemp" -Path "$tempFolder\big.iso" -RelativePath "ABCD1234\big.iso" -Size 73400320 `
            -Created "2026-02-28 09:00:00" -Modified "2026-02-28 09:00:00" -Status "Skipped: over the 50 MB per-file cap")
    )
    # OST/PST listing
    New-TestCsv -Path (Join-Path $collection "$alice\Outlook\outlook_data_files.csv") -Columns $listingColumns -Rows @(
        (New-ListingRow -Program "Classic Outlook" -Store "DataFile" -Path "C:\Users\alice\AppData\Local\Microsoft\Outlook\alice@example.com.ost" `
            -RelativePath "AppData\Local\Microsoft\Outlook\alice@example.com.ost" -Size 2147483648 -Created "2025-11-01 08:00:00" -Modified "2026-03-02 23:59:00"),
        (New-ListingRow -Program "Classic Outlook" -Store "DataFile" -Path "C:\Users\alice\Documents\Outlook Files\archive.pst" `
            -RelativePath "Documents\Outlook Files\archive.pst" -Size 1048576 -Created "2024-05-01 12:00:00" -Modified "2024-05-01 12:00:00")
    )
    # New Outlook folder listing: settings, an attachment, WebView mail data
    $olk = "C:\Users\alice\AppData\Local\Microsoft\Olk"
    New-TestCsv -Path (Join-Path $collection "$alice\NewOutlook\olk_files.csv") -Columns $listingColumns -Rows @(
        (New-ListingRow -Program "New Outlook" -Store "Olk" -Path "$olk\UserSettings.json" -RelativePath "UserSettings.json" -Size 300 `
            -Created "2026-01-15 07:00:00" -Modified "2026-03-01 07:00:00" -Status "Copied" -CollectedAs "$alice\NewOutlook\UserSettings.json"),
        (New-ListingRow -Program "New Outlook" -Store "Olk" -Path "$olk\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf" `
            -RelativePath "Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf" -Size 3 -Created "2026-03-02 08:00:00" -Modified "2026-03-02 08:00:00" `
            -Status "Copied" -CollectedAs "$alice\NewOutlook\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\report.pdf"),
        (New-ListingRow -Program "New Outlook" -Store "Olk" -Path "$olk\EBWebView\Default\IndexedDB\https_outlook.office.com_0.indexeddb.leveldb\000003.log" `
            -RelativePath "EBWebView\Default\IndexedDB\https_outlook.office.com_0.indexeddb.leveldb\000003.log" -Size 5000 -Created "2026-01-15 07:01:00" -Modified "2026-03-02 22:00:00")
    )
    # Thunderbird mail folder listing: mbox folders (with .msf summaries, a
    # dotted name, a subfolder), filter rules, a maildir message file and a
    # log file (no rows for the last two and the .msf files)
    $tbProfile = "C:\Users\alice\AppData\Roaming\Thunderbird\Profiles\$profileName"
    $mailListing = @(
        @("Mail\Local Folders\Inbox", "2026-01-05 10:00:00", "2026-03-02 09:00:00"),
        @("Mail\Local Folders\Inbox.msf", "2026-01-05 10:00:00", "2026-03-02 09:00:01"),
        @("Mail\Local Folders\Archives.2024", "2026-01-10 10:00:00", "2026-01-10 10:00:00"),
        @("Mail\Local Folders\Archives.2024.msf", "2026-01-10 10:00:00", "2026-01-10 10:00:00"),
        @("Mail\Local Folders\Drafts\cur\1700000000", "2026-02-02 10:00:00", "2026-02-02 10:00:00"),
        @("ImapMail\imap.example.com\INBOX", "2026-01-06 10:00:00", "2026-03-02 10:00:00"),
        @("ImapMail\imap.example.com\INBOX.msf", "2026-01-06 10:00:00", "2026-03-02 10:00:01"),
        @("ImapMail\imap.example.com\INBOX.sbd\Work", "2026-02-01 10:00:00", "2026-02-01 10:00:00"),
        @("ImapMail\imap.example.com\INBOX.sbd\Work.msf", "2026-02-01 10:00:00", "2026-02-01 10:00:00"),
        @("ImapMail\imap.example.com\msgFilterRules.dat", "2026-01-06 10:05:00", "2026-03-01 22:00:00"),
        @("ImapMail\imap.example.com\filterlog.html", "2026-01-06 10:05:00", "2026-03-01 22:00:00")
    )
    New-TestCsv -Path (Join-Path $collection "$alice\Thunderbird\thunderbird_mail_files.csv") -Columns $listingColumns -Rows @(
        foreach ($item in $mailListing) {
            New-ListingRow -Program "Thunderbird" -Store "ThunderbirdMail" -ProfileName $profileName -Path "$tbProfile\$($item[0])" -RelativePath $item[0] `
                -Size 4096 -Created $item[1] -Modified $item[2]
        }
    )
    # Windows Mail store listing: the Hx store, an attachment, a log, the Unistore database
    $windowsMail = "C:\Users\alice\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe"
    New-TestCsv -Path (Join-Path $collection "$alice\WindowsMail\windows_mail_files.csv") -Columns $listingColumns -Rows @(
        (New-ListingRow -Program "Windows Mail" -Store "WindowsMail" -Path "$windowsMail\LocalState\HxStore.hxd" -RelativePath "LocalState\HxStore.hxd" -Size 8388608 `
            -Created "2025-12-01 00:00:00" -Modified "2026-03-02 20:00:00"),
        (New-ListingRow -Program "Windows Mail" -Store "WindowsMail" -Path "$windowsMail\LocalState\Files\S0\3\Attachments\quote[1].pdf" `
            -RelativePath "LocalState\Files\S0\3\Attachments\quote[1].pdf" -Size 2000 -Created "2026-02-20 15:00:00" -Modified "2026-02-20 15:00:00"),
        (New-ListingRow -Program "Windows Mail" -Store "WindowsMail" -Path "$windowsMail\LocalState\HxCommAlwaysOnLog.etl" -RelativePath "LocalState\HxCommAlwaysOnLog.etl" `
            -Size 100 -Created "2026-03-02 20:00:00" -Modified "2026-03-02 20:00:00"),
        (New-ListingRow -Program "Windows Mail" -Store "WindowsMail" -Path "C:\Users\alice\AppData\Local\Comms\UnistoreDB\store.vol" -RelativePath "UnistoreDB\store.vol" `
            -Size 1048576 -Created "2025-12-01 00:00:00" -Modified "2026-03-02 20:05:00")
    )

    # Thunderbird prefs.js: an IMAP account (OAuth), Local Folders (not an
    # account) and a POP3 account using the default outgoing server; a saved
    # password and a refresh token hold the canary
    $prefsPath = Join-Path $collection "$alice\Thunderbird\$profileName\prefs.js"
    New-TestTextFile -Path $prefsPath -Text (@(
        '// Mozilla User Preferences'
        'user_pref("mail.accountmanager.accounts", "account1,account2,account3");'
        'user_pref("mail.account.account1.identities", "id1");'
        'user_pref("mail.account.account1.server", "server1");'
        'user_pref("mail.account.account2.server", "server2");'
        'user_pref("mail.account.account3.identities", "id3");'
        'user_pref("mail.account.account3.server", "server3");'
        'user_pref("mail.server.server1.type", "imap");'
        'user_pref("mail.server.server1.hostname", "imap.example.com");'
        'user_pref("mail.server.server1.userName", "alice@example.com");'
        'user_pref("mail.server.server1.port", 993);'
        'user_pref("mail.server.server1.socketType", 3);'
        'user_pref("mail.server.server1.authMethod", 10);'
        'user_pref("mail.server.server1.directory-rel", "[ProfD]ImapMail/imap.example.com");'
        ('user_pref("mail.server.server1.password", "' + $canary + '-password");')
        ('user_pref("mail.server.server1.oauth2.refreshToken", "' + $canary + '-token");')
        'user_pref("mail.server.server2.type", "none");'
        'user_pref("mail.server.server2.hostname", "Local Folders");'
        'user_pref("mail.server.server2.userName", "nobody");'
        'user_pref("mail.server.server3.type", "pop3");'
        'user_pref("mail.server.server3.hostname", "pop.example.org");'
        'user_pref("mail.server.server3.realhostname", "pop3.example.org");'
        'user_pref("mail.server.server3.userName", "alice.sm\u00EFth");'
        'user_pref("mail.server.server3.socketType", 2);'
        'user_pref("mail.server.server3.authMethod", 3);'
        'user_pref("mail.identity.id1.useremail", "alice@example.com");'
        'user_pref("mail.identity.id1.fullName", "Alice \"Al\" Example");'
        'user_pref("mail.identity.id1.smtpServer", "smtp1");'
        'user_pref("mail.identity.id3.useremail", "alice.smith@example.org");'
        'user_pref("mail.smtpserver.smtp1.hostname", "smtp.example.com");'
        'user_pref("mail.smtpserver.smtp1.username", "alice@example.com");'
        'user_pref("mail.smtpserver.smtp2.hostname", "smtp.example.org");'
        'user_pref("mail.smtpserver.smtp2.username", "alice.smith");'
        'user_pref("mail.smtp.defaultserver", "smtp2");'
    ) -join "`r`n")
    $manifest += @{ SHA256 = (Get-FileHash -LiteralPath $prefsPath -Algorithm SHA256).Hash; SourcePath = "$tbProfile\prefs.js"; DestPath = $prefsPath
        SizeBytes = (Get-Item -LiteralPath $prefsPath).Length; CollectedAt = "2026-03-03 00:01:00"; RelativePath = "$alice\Thunderbird\$profileName\prefs.js"
        SourceCreatedUtc = (ConvertTo-IsoTime "2026-01-05 10:00:00"); SourceModifiedUtc = (ConvertTo-IsoTime "2026-03-02 21:00:00"); SourceAccessedUtc = "" }

    # global-messages-db.sqlite (gloda): indexed messages with their
    # addresses in jsonAttributes ({"<attribute id>": identity id or [ids]},
    # gloda's from/to/cc/bcc attributes in attributeDefinitions, addresses in
    # identities, names in contacts): one with To and Cc, one deleted (no
    # subject or attachments) with Bcc, one whose jsonAttributes is damaged
    # (the full-text author and recipients are used instead), and a ghost
    # message without a date. Attribute 20 is "to" of another extension and
    # 14 ("involves") is not an address list; neither is read. The full-text
    # author and recipients end with the " undefined" Thunderbird appends for
    # names that are not in the address book. Thunderbird declares the
    # full-text table with its own tokenizer (mozporter), which sqlite3.exe
    # does not have: the schema is rewritten to that after the rows are
    # added, as in a real database.
    $glodaPath = Join-Path $collection "$alice\Thunderbird\$profileName\global-messages-db.sqlite"
    New-TestDatabase -Path $glodaPath -Sql @"
CREATE TABLE folderLocations (id INTEGER PRIMARY KEY, folderURI TEXT NOT NULL, dirtyStatus INTEGER NOT NULL, name TEXT NOT NULL, indexingPriority INTEGER NOT NULL);
CREATE TABLE messages (id INTEGER PRIMARY KEY, folderID INTEGER, messageKey INTEGER, conversationID INTEGER NOT NULL, date INTEGER, headerMessageID TEXT, deleted INTEGER NOT NULL default 0, jsonAttributes TEXT, notability INTEGER NOT NULL default 255);
CREATE TABLE attributeDefinitions (id INTEGER PRIMARY KEY, attributeType INTEGER NOT NULL, extensionName TEXT NOT NULL, name TEXT NOT NULL, parameter BLOB);
CREATE TABLE contacts (id INTEGER PRIMARY KEY, directoryUUID TEXT, contactUUID TEXT, popularity INTEGER, frecency INTEGER, name TEXT, jsonAttributes TEXT);
CREATE TABLE identities (id INTEGER PRIMARY KEY, contactID INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, description NOT NULL, relay INTEGER NOT NULL);
CREATE VIRTUAL TABLE messagesText USING fts3(body, subject, attachmentNames, author, recipients);
INSERT INTO attributeDefinitions VALUES (10, 0, 'built-in', 'from', NULL);
INSERT INTO attributeDefinitions VALUES (11, 0, 'built-in', 'to', NULL);
INSERT INTO attributeDefinitions VALUES (12, 0, 'built-in', 'cc', NULL);
INSERT INTO attributeDefinitions VALUES (13, 0, 'built-in', 'bcc', NULL);
INSERT INTO attributeDefinitions VALUES (14, 1, 'built-in', 'involves', NULL);
INSERT INTO attributeDefinitions VALUES (20, 0, 'other-extension', 'to', NULL);
INSERT INTO contacts VALUES (1, NULL, NULL, 10, 10, 'Mallory', '{}');
INSERT INTO contacts VALUES (2, NULL, NULL, 10, 10, 'Alice', '{}');
INSERT INTO contacts VALUES (3, NULL, NULL, 10, 10, 'carol@example.org', '{}');
INSERT INTO contacts VALUES (4, NULL, NULL, 10, 10, 'Bob', '{}');
INSERT INTO contacts VALUES (5, NULL, NULL, 10, 10, 'Dave', '{}');
INSERT INTO contacts VALUES (6, NULL, NULL, 10, 10, 'Decoy', '{}');
INSERT INTO identities VALUES (1, 1, 'email', 'billing@evil.example', '', 0);
INSERT INTO identities VALUES (2, 2, 'email', 'alice@example.com', '', 0);
INSERT INTO identities VALUES (3, 3, 'email', 'carol@example.org', '', 0);
INSERT INTO identities VALUES (4, 4, 'email', 'bob@example.org', '', 0);
INSERT INTO identities VALUES (5, 5, 'email', 'dave@example.net', '', 0);
INSERT INTO identities VALUES (6, 6, 'email', 'decoy@example.com', '', 0);
INSERT INTO folderLocations VALUES (1, 'imap://alice%40example.com@imap.example.com/INBOX', 0, 'Inbox', 0);
INSERT INTO folderLocations VALUES (2, 'mailbox://nobody@Local%20Folders/Trash', 0, 'Trash', 0);
INSERT INTO messages VALUES (1, 1, 101, 1, $(ConvertTo-PRTime "2026-03-02 09:15:00"), 'msg1@example.com', 0, '{"10":1,"11":[2],"12":[3],"14":[1,2,3,6],"20":[6],"43":"x"}', 255);
INSERT INTO messages VALUES (2, 2, 102, 2, $(ConvertTo-PRTime "2026-03-01 18:00:00"), 'msg2@example.org', 1, '{"10":4,"11":[2],"12":[],"13":[5]}', 255);
INSERT INTO messages VALUES (3, 1, 103, 3, $(ConvertTo-PRTime "2026-02-28 07:00:00"), 'msg3@example.com', 0, '{"10":', 255);
INSERT INTO messages VALUES (4, NULL, NULL, 1, NULL, 'ghost@example.net', 0, NULL, 255);
INSERT INTO messagesText (docid, body, subject, attachmentNames, author, recipients) VALUES (1, '$canary-body-1', 'Invoice 4471 overdue', 'invoice.docm' || char(10) || 'terms.pdf', 'Mallory <billing@evil.example> undefined', 'Alice <alice@example.com> undefined undefined');
INSERT INTO messagesText (docid, body, subject, attachmentNames, author, recipients) VALUES (2, '$canary-body-2', '', NULL, 'Bob <bob@example.org> undefined', 'alice@example.com undefined undefined');
INSERT INTO messagesText (docid, body, subject, attachmentNames, author, recipients) VALUES (3, '$canary-body-3', 'Shipping notice', NULL, 'Eve <eve@example.com> undefined', 'alice@example.com undefined');
.dbconfig defensive off
PRAGMA writable_schema = ON;
UPDATE sqlite_master SET sql = 'CREATE VIRTUAL TABLE messagesText USING fts3(tokenize mozporter, body, subject, attachmentNames, author, recipients)' WHERE name = 'messagesText';
PRAGMA writable_schema = OFF;
"@

    # Manifest
    New-TestCsv -Path (Join-Path $collection "collection_manifest.csv") -Columns $manifestColumns -Rows $manifest

    # --- Run the builder ---
    $timelineCsv = Join-Path $workDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $builderOutput = Invoke-TimelineBuilder -CollectionPath $collection -OutputFile $timelineCsv -Sources "Email,RecentFiles"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the builder exited with code $LASTEXITCODE or wrote no timeline"
        exit 1
    }
    $rows = @(Import-Csv -LiteralPath $timelineCsv)
    $emailRows = @($rows | Where-Object { $_.Source -like "Email-*" })

    # --- Expected email rows: time, source, event type, description, user,
    # and text the Details must (Has) or must not (Lacks) contain ---
    $invoiceDetails = @("Program=Classic Outlook", "Origin=Opened from a message", "Folder=$tempFolder", "Size=14", "SHA256=$($hashes["$alice\Outlook\SecureTemp\INetCache\ABCD1234\invoice.docm"])",
        "Collected=Yes", "CreatedUtc=2026-03-01 10:00:00", "ModifiedUtc=2026-03-01 10:20:00", "AccessedUtc=2026-03-01 10:25:00")
    $ostDetails = @("Program=Classic Outlook", "Type=OST", "Path=C:\Users\alice\AppData\Local\Microsoft\Outlook\alice@example.com.ost", "Size=2147483648",
        "CreatedUtc=2025-11-01 08:00:00", "ModifiedUtc=2026-03-02 23:59:00")
    $inboxDetails = @("Program=Thunderbird", "Profile=$profileName", "Account=imap.example.com", "Storage=ImapMail", "Folder=INBOX", "Path=$tbProfile\ImapMail\imap.example.com\INBOX")
    $filterDetails = @("Account=imap.example.com", "Storage=ImapMail", "CreatedUtc=2026-01-06 10:05:00", "ModifiedUtc=2026-03-01 22:00:00")
    $hxDetails = @("Program=Windows Mail", "Type=HXD", "Path=$windowsMail\LocalState\HxStore.hxd", "Size=8388608")
    $imapAccount = @("Program=Thunderbird", "Profile=$profileName", "AccountId=account1", "ServerType=imap", "Host=imap.example.com", "Port=993",
        "UserName=alice@example.com", "Security=SSL/TLS", "AuthMethod=OAuth2", "Email=alice@example.com", "SmtpHost=smtp.example.com",
        "SmtpUser=alice@example.com", "Directory=ImapMail/imap.example.com", "PrefsModifiedUtc=2026-03-02 21:00:00")
    $popAccount = @("AccountId=account3", "ServerType=pop3", "Host=pop3.example.org", ("UserName=alice.sm" + [char]0x00EF + "th"), "Security=STARTTLS",
        "AuthMethod=Password", "Email=alice.smith@example.org", "SmtpHost=smtp.example.org", "SmtpUser=alice.smith")
    $snapshot = "2026-03-03 00:00:00.000"
    $expected = @(
        # Classic Outlook temp folder
        @{ Time = "2026-03-01 10:00:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "Outlook attachment in temp folder: invoice.docm"; Has = $invoiceDetails; Lacks = @("Status=") }
        @{ Time = "2026-03-01 10:20:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "Outlook attachment in temp folder modified: invoice.docm"; Has = $invoiceDetails }
        @{ Time = "2026-03-01 11:00:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "Outlook attachment in temp folder: shortcut.lnk"; Has = @("Collected=Yes", "Size=1200") }
        @{ Time = "2026-02-28 09:00:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "Outlook attachment in temp folder: big.iso"
            Has = @("Program=Classic Outlook", "Size=73400320", "Collected=No", "Status=Skipped: over the 50 MB per-file cap"); Lacks = @("SHA256=") }
        # Copied, but no listing row (bob): from the manifest
        @{ Time = "2026-02-27 13:00:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "Outlook attachment in temp folder: payload.js"; User = "bob"
            Has = @("Program=Classic Outlook", "Folder=C:\Users\bob\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ZZZZ9999", "Size=18",
                    "SHA256=$($hashes['Email\bob\Outlook\SecureTemp\INetCache\ZZZZ9999\payload.js'])", "Collected=Yes", "AccessedUtc=2026-02-27 13:05:00")
            Lacks = @("(shadow)") }
        # New Outlook: its Attachments\ also keeps sent and received attachments
        @{ Time = "2026-03-02 08:00:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "New Outlook attachment file: report.pdf"
            Has = @("Program=New Outlook", "Origin=Opened, sent or received (not proof of opening)", "Folder=$olk\Attachments\0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
                    "Size=3", "Collected=Yes", "SHA256=") }
        @{ Time = $snapshot; Source = "Email-Accounts"; Type = "Snapshot"; Text = "New Outlook account: alice@example.com"
            Has = @("Program=New Outlook", "Account=alice@example.com", "IdentityId=11111111-2222-3333-4444-555555555555", "SettingsModifiedUtc=2026-03-01 07:00:00") }
        @{ Time = $snapshot; Source = "Email-Accounts"; Type = "Snapshot"; Text = "New Outlook account: alice@contoso.com"; Has = @("IdentityId=66666666-7777-8888-9999-000000000000") }
        # OST/PST
        @{ Time = "2025-11-01 08:00:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Outlook data file created: alice@example.com.ost"; Has = $ostDetails }
        @{ Time = "2026-03-02 23:59:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Outlook data file last modified: alice@example.com.ost"; Has = $ostDetails }
        @{ Time = "2024-05-01 12:00:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Outlook data file created: archive.pst"; Has = @("Type=PST", "Size=1048576") }
        # Windows Mail
        @{ Time = "2025-12-01 00:00:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Windows Mail store file created: LocalState\HxStore.hxd"; Has = $hxDetails }
        @{ Time = "2026-03-02 20:00:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Windows Mail store file last modified: LocalState\HxStore.hxd"; Has = $hxDetails }
        @{ Time = "2025-12-01 00:00:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Windows Mail store file created: UnistoreDB\store.vol"; Has = @("Type=VOL") }
        @{ Time = "2026-03-02 20:05:00.000"; Source = "Email-DataFiles"; Type = "FileAccess"; Text = "Windows Mail store file last modified: UnistoreDB\store.vol"; Has = @("Type=VOL") }
        @{ Time = "2026-02-20 15:00:00.000"; Source = "Email-Attachments"; Type = "FileAccess"; Text = "Windows Mail attachment in mail store: quote[1].pdf"
            Has = @("Program=Windows Mail", "Origin=Stored with a message (not proof of opening)", "Folder=$windowsMail\LocalState\Files\S0\3\Attachments", "Collected=No", "Status=Listed")
            Lacks = @("SHA256=") }
        # Thunderbird mail folders and filter rules
        @{ Time = "2026-01-05 10:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird mail folder created: Local Folders/Inbox"
            Has = @("Account=Local Folders", "Storage=Mail", "Folder=Inbox") }
        @{ Time = "2026-03-02 09:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird mail folder last modified: Local Folders/Inbox" }
        @{ Time = "2026-01-10 10:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird mail folder created: Local Folders/Archives.2024" }
        @{ Time = "2026-01-06 10:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird mail folder created: imap.example.com/INBOX"; Has = $inboxDetails }
        @{ Time = "2026-03-02 10:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird mail folder last modified: imap.example.com/INBOX"; Has = $inboxDetails }
        @{ Time = "2026-02-01 10:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird mail folder created: imap.example.com/INBOX/Work"; Has = @("Folder=INBOX/Work") }
        @{ Time = "2026-01-06 10:05:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird message filter rules created: imap.example.com"; Has = $filterDetails }
        @{ Time = "2026-03-01 22:00:00.000"; Source = "Email-MailFolders"; Type = "FileAccess"; Text = "Thunderbird message filter rules last modified: imap.example.com"; Has = $filterDetails }
        # Thunderbird accounts
        @{ Time = $snapshot; Source = "Email-Accounts"; Type = "Snapshot"; Text = "Thunderbird account: alice@example.com (IMAP imap.example.com)"; Has = $imapAccount }
        @{ Time = $snapshot; Source = "Email-Accounts"; Type = "Snapshot"; Text = "Thunderbird account: alice.smith@example.org (POP3 pop3.example.org)"; Has = $popAccount; Lacks = @("Port=") }
        # Thunderbird search index: addresses from jsonAttributes, never the
        # full-text "undefined" suffixes, another extension's "to" or "involves"
        @{ Time = "2026-03-02 09:15:00.000"; Source = "Email-Messages"; Type = "NetworkConnection"; Text = "Email (Thunderbird): Invoice 4471 overdue"
            Has = @("Program=Thunderbird", "From=Mallory <billing@evil.example> | To=Alice <alice@example.com> | Cc=carol@example.org | Attachments=invoice.docm; terms.pdf",
                    "Folder=Inbox", "FolderURI=imap://alice%40example.com@imap.example.com/INBOX", "MessageID=msg1@example.com",
                    "TimeSource=Date header (sender clock)", "Profile=$profileName")
            Lacks = @("Deleted=", "Bcc=", "AuthorText=", "RecipientsText=", "undefined", "decoy@", "Decoy") }
        @{ Time = "2026-03-01 18:00:00.000"; Source = "Email-Messages"; Type = "NetworkConnection"; Text = "Email (Thunderbird): (no subject)"
            Has = @("From=Bob <bob@example.org> | To=Alice <alice@example.com> | Bcc=Dave <dave@example.net>", "Folder=Trash", "Deleted=Yes", "MessageID=msg2@example.org")
            Lacks = @("Attachments=", "Cc=", "undefined", "RecipientsText=") }
        # Damaged jsonAttributes: the full-text author and recipients, named as such
        @{ Time = "2026-02-28 07:00:00.000"; Source = "Email-Messages"; Type = "NetworkConnection"; Text = "Email (Thunderbird): Shipping notice"
            Has = @("AuthorText=Eve <eve@example.com> | RecipientsText=alice@example.com | Folder=Inbox", "MessageID=msg3@example.com")
            Lacks = @("From=", "To=", "undefined") }
    )

    # --- Checks ---
    $byKey = @{}
    foreach ($row in $emailRows) { $byKey["$($row.Timestamp) | $($row.Source) | $($row.EventType) | $($row.Description)"] = $row }
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
        if ($byKey[$key].Artifact -ne "Email") { $problems += "Artifact is '$($byKey[$key].Artifact)'" }
        if ($problems.Count -gt 0) { Write-TestResult -Succeeded $false -Message "$key -- $($problems -join '; ') (Details: $details)" }
        else { Write-TestResult -Succeeded $true -Message $key }
    }
    # Hashtable keys are case-insensitive; compare the row texts exactly
    $unexpected = @($byKey.Keys | Where-Object { $expectedKeys -cnotcontains $_ })
    foreach ($key in $unexpected) { Write-TestResult -Succeeded $false -Message "unexpected row: $key" }
    Write-TestResult -Succeeded ($emailRows.Count -eq $expected.Count) -Message "$($emailRows.Count) email rows in the timeline ($($expected.Count) expected)"

    # The shortcut copied as an attachment is not one of alice's recent files
    $recentRows = @($rows | Where-Object { $_.Source -eq "RecentFiles" })
    $fromAttachment = @($recentRows | Where-Object { $_.RawPath -like "*\Email\*" })
    $fromRecent = @($recentRows | Where-Object { $_.RawPath -like "*\UserActivity\alice\RecentFiles\shortcut.lnk" })
    Write-TestResult -Succeeded ($fromRecent.Count -gt 0) -Message "the shortcut under UserActivity\ is parsed as a recent file ($($fromRecent.Count) row(s))"
    Write-TestResult -Succeeded ($fromAttachment.Count -eq 0) -Message "the shortcut copied from the Outlook temp folder is not parsed as a recent file"

    # Again with a relative -InputPath, resolved against the PowerShell
    # location (not the process working directory), and with FileSystem: the
    # attachment copies stay excluded, the user is still known, and the
    # attachment named $MFT is not parsed as the system's MFT
    $relativeCsv = Join-Path $workDir "timeline-relative.csv"
    Write-Host "Running the builder again with a relative -InputPath ..."
    $ErrorActionPreference = "Continue"
    $relativeOutput = @(& $powershellExe -NoProfile -ExecutionPolicy Bypass -Command ("Set-Location -LiteralPath '$workDir'; & '$builder' -InputPath '.\collection' " +
        "-Sources Email,RecentFiles,FileSystem -OutputFile '$relativeCsv' -NoExcel -Viewer None") 2>&1 | ForEach-Object { "$_" })
    $ErrorActionPreference = "Stop"
    if (Test-Path -LiteralPath $relativeCsv) {
        $relativeRows = @(Import-Csv -LiteralPath $relativeCsv)
        $relativeRecent = @($relativeRows | Where-Object { $_.Source -eq "RecentFiles" })
        $relativeEmail = @($relativeRows | Where-Object { $_.Source -like "Email-*" })
        Write-TestResult -Succeeded (@($relativeRecent | Where-Object { $_.RawPath -like "*\Email\*" }).Count -eq 0 -and @($relativeRecent | Where-Object { $_.User -eq "alice" }).Count -gt 0) `
            -Message "relative -InputPath: the attached shortcut is not a recent file, the UserActivity one is (User=alice)"
        Write-TestResult -Succeeded ($relativeEmail.Count -eq $expected.Count -and @($relativeEmail | Where-Object { -not $_.User }).Count -eq 0) `
            -Message "relative -InputPath: $($relativeEmail.Count) email rows, all with a user ($($expected.Count) expected)"
    }
    else {
        $relativeOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "relative -InputPath: the builder wrote no timeline"
    }
    $relativeText = $relativeOutput -join "`n"
    Write-TestResult -Succeeded ($relativeText.Contains("No `$MFT or file listing in this collection") -and -not $relativeText.Contains("not an `$MFT copy")) `
        -Message "an attachment named `$MFT is not parsed as the system's MFT"

    # The canary is in every secret and message text: it must appear nowhere
    $csvText = [System.IO.File]::ReadAllText($timelineCsv)
    Write-TestResult -Succeeded ($csvText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or message text (canary) in the timeline CSV"
    $newReports = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $reportsBefore -notcontains $_.FullName })
    $logFiles = @($newReports | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter "*.txt" -File -ErrorAction SilentlyContinue })
    $logText = ($logFiles | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n"
    Write-TestResult -Succeeded ($logFiles.Count -gt 0 -and $logText.IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) -Message "no secret or message text (canary) in the builder log"
    Write-TestResult -Succeeded ((($builderOutput -join "`n").IndexOf($canary, [System.StringComparison]::OrdinalIgnoreCase)) -lt 0) -Message "no secret or message text (canary) in the builder output"
    # The test collection is in %TEMP%, which the builder warns about
    $emailWarnings = @($builderOutput | Where-Object { $_ -match 'WARNING: ' -and $_ -notmatch 'No \.lnk|Jump|The input folder is inside a temp folder' })
    Write-TestResult -Succeeded ($emailWarnings.Count -eq 0) -Message "no warnings from the builder$(if ($emailWarnings) { ': ' + $emailWarnings[0] })"

    if ($script:failures -gt 0) {
        Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS: all email parser checks passed ($($emailRows.Count) email rows)" -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the ones from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
