# =============================================================
# Defender DetectionHistory and quarantine entry parser test
# Builds synthetic Microsoft Defender DetectionHistory files and quarantine
# Entries files at test time from their documented formats (our own made-up
# threats, paths and hashes; no real detections, no malware), lays them out
# like a triage collection, runs timeline-builder.ps1 -Sources AntiVirus and
# checks every row, its time and its Details: detections with file, webfile,
# container, registry, behavior, process and command line resources (the
# path, or none), the fallback times (threat tracking start time, the
# manifest's file creation time; times before 1980 count as missing),
# unknown value types, damaged and oversize files, quarantine entries with
# one and several resources (\\?\ and \\?\UNC\ paths, the resource fields:
# ID, physical path, original file times and size), and entries with a wrong
# header or sizes. Files under Quarantine\ResourceData and
# Quarantine\Resources, and an "Entries" folder outside Quarantine, hold
# valid entries with a canary threat name that must not reach the timeline.
# The quarantine entries are RC4-encrypted here with this test's own RC4 code
# and its own copy of the published key (checked against the key's SHA-256
# and a standard RC4 test vector), so the builder's decryption is checked
# independently.
#
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). For a local run without them, pass
# -BuilderPath with a copy of the builder that has no admin check, kept
# inside the repository (e.g. under the git-ignored reports\ folder).
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-DefenderParsers.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
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
$script:failures = 0
$script:checks = 0

function Write-TestResult {
    param([string]$Name, [bool]$Passed, [string]$Message = "")
    $script:checks++
    if ($Passed) {
        Write-Host "PASS: $Name" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Name" -ForegroundColor Red
    if ($Message) { Write-Host "  $($Message -replace "`n", "`n  ")" }
    if ($env:GITHUB_ACTIONS) {
        $oneLine = ($Message -replace "`r?`n", " / ")
        Write-Host "::error file=tests/Test-DefenderParsers.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# The builder refuses to run without Administrator rights (a -BuilderPath
# copy may not)
if (-not $BuilderPath) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-TestResult -Name "Administrator rights" -Passed $false -Message "the builder needs them. Run elevated, or pass -BuilderPath with a builder copy without the admin check."
        exit 1
    }
}

function Get-Utc {
    param([string]$Text)
    return [datetime]::SpecifyKind([datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture), [System.DateTimeKind]::Utc)
}

function Join-Bytes {
    param([object[]]$Parts)
    $list = New-Object System.Collections.Generic.List[byte]
    foreach ($part in $Parts) { if ($null -ne $part) { $list.AddRange([byte[]]$part) } }
    return , $list.ToArray()
}

function Get-UInt32Bytes { param([long]$Value) return , [BitConverter]::GetBytes([uint32]$Value) }
function Get-UInt16Bytes { param([int]$Value) return , [BitConverter]::GetBytes([uint16]$Value) }

# --- DetectionHistory values ------------------------------------------------
# uint32 size, uint32 type, data, zero padding to 8 bytes (see the builder's
# Read-DefenderDetectionHistory comment for the layout)
function New-HistoryValue {
    param([int]$Type, [byte[]]$Data)
    $padding = (8 - ($Data.Length % 8)) % 8
    return , (Join-Bytes @((Get-UInt32Bytes $Data.Length), (Get-UInt32Bytes $Type), $Data, (New-Object byte[] $padding)))
}
function New-HistoryText { param([string]$Text) return , (New-HistoryValue -Type 0x15 -Data ([System.Text.Encoding]::Unicode.GetBytes($Text + [char]0))) }
function New-HistoryNumber { param([long]$Value, [int]$Type = 0x06) return , (New-HistoryValue -Type $Type -Data (Get-UInt32Bytes $Value)) }
function New-HistoryNumber64 { param([long]$Value) return , (New-HistoryValue -Type 0x08 -Data ([BitConverter]::GetBytes([uint64]$Value))) }
function New-HistoryGuid { param([string]$Guid) return , (New-HistoryValue -Type 0x1E -Data (New-Object System.Guid $Guid).ToByteArray()) }
function New-HistoryFileTime {
    param($Utc)
    $fileTime = 0L
    if ($null -ne $Utc) { $fileTime = ([datetime]$Utc).ToFileTimeUtc() }
    return , (New-HistoryValue -Type 0x0A -Data ([BitConverter]::GetBytes([long]$fileTime)))
}

# Threat tracking data: values (key -> @(type, value)), with the header
# (version 1, header size 20, values size, total size, 0, values size) or
# only the values size; -HeaderOnly: the header with no values
function New-ThreatTracking {
    param([System.Collections.Specialized.OrderedDictionary]$Values, [switch]$NoHeader, [switch]$HeaderOnly)
    if ($HeaderOnly) { return , (Join-Bytes @((Get-UInt32Bytes 1), (Get-UInt32Bytes 20), (Get-UInt32Bytes 0), (Get-UInt32Bytes 20), (Get-UInt32Bytes 0))) }
    $parts = @()
    foreach ($key in $Values.Keys) {
        $keyBytes = [System.Text.Encoding]::Unicode.GetBytes($key + [char]0)
        $type = [int]$Values[$key][0]
        $value = $Values[$key][1]
        $data = switch ($type) {
            3 { Get-UInt32Bytes $value }
            4 { , [BitConverter]::GetBytes([long]$value) }
            5 { , [byte[]]@([byte]$value) }
            6 { $text = [System.Text.Encoding]::Unicode.GetBytes([string]$value + [char]0); , (Join-Bytes @((Get-UInt32Bytes $text.Length), $text)) }
            default { , [byte[]]$value }
        }
        $parts += , (Join-Bytes @((Get-UInt32Bytes $keyBytes.Length), $keyBytes, (Get-UInt32Bytes $type), $data))
    }
    $valueBytes = Join-Bytes $parts
    $valuesSize = 4 + $valueBytes.Length
    if ($NoHeader) { return , (Join-Bytes @((Get-UInt32Bytes $valuesSize), $valueBytes)) }
    return , (Join-Bytes @((Get-UInt32Bytes 1), (Get-UInt32Bytes 20), (Get-UInt32Bytes $valuesSize), (Get-UInt32Bytes (20 + $valuesSize)), (Get-UInt32Bytes 0),
        (Get-UInt32Bytes $valuesSize), $valueBytes))
}

# A whole DetectionHistory file. $Resources: objects with Type, Location and
# Tracking (bytes); $Own: the detection's own values after the last resource
# (StatusChange, User, Process, Initial, Remediation), or $null; $Extra: bytes
# appended after everything
function New-DetectionHistoryFile {
    param([long]$ThreatId, [string]$DetectionId, [string]$Threat, [int]$Severity, [int]$Category, [int]$Status,
          [object[]]$Resources, $Own, [byte[]]$Extra = $null)
    $magic = New-HistoryText "Magic.Version:1.2"
    $parts = @((New-HistoryNumber64 $ThreatId), (New-HistoryGuid $DetectionId), $magic, (New-HistoryText $Threat),
        (New-HistoryNumber 0), (New-HistoryNumber $Severity), (New-HistoryNumber $Category), (New-HistoryNumber 63),
        (New-HistoryNumber 0), (New-HistoryNumber $Status), (New-HistoryNumber 1), (New-HistoryNumber 3), (New-HistoryNumber 2),
        (New-HistoryNumber 3), (New-HistoryNumber 6), (New-HistoryNumber $Resources.Count))
    foreach ($resource in $Resources) {
        $tracking = [byte[]]$resource.Tracking
        $parts += @($magic, (New-HistoryText $resource.Type), (New-HistoryText $resource.Location), (New-HistoryNumber 0x10000001),
            (New-HistoryNumber $tracking.Length), (New-HistoryValue -Type 0x28 -Data $tracking))
    }
    if ($Own) {
        # Indexes 6 to 31 of the last resource set
        $parts += @((New-HistoryFileTime $Own.StatusChange), (New-HistoryNumber 0 -Type 0x05), (New-HistoryNumber 0), (New-HistoryGuid ([guid]::Empty)),
            (New-HistoryNumber 1), (New-HistoryNumber 1), (New-HistoryText $Own.User), (New-HistoryNumber 3), (New-HistoryText $Own.Process),
            (New-HistoryNumber 3), (New-HistoryNumber 4), (New-HistoryNumber 0), (New-HistoryFileTime $Own.Initial), (New-HistoryNumber 0),
            (New-HistoryFileTime $Own.Remediation), (New-HistoryNumber 0), (New-HistoryNumber 0 -Type 0x00), (New-HistoryNumber 0), (New-HistoryText ""))
        for ($i = 25; $i -le 31; $i++) { $parts += , (New-HistoryNumber 0) }
    }
    if ($Extra) { $parts += , $Extra }
    return , (Join-Bytes $parts)
}

# --- Quarantine entries -------------------------------------------------------
# The RC4 key published for Defender's quarantine files (Cuckoo Sandbox; ERNW
# quarantine-formats; defender-dump), as hex. Its SHA-256 is checked below.
$script:QuarantineKeyHex = "1E87781B8DBAA844CE69702C0C78B786A3F623B738F5EDF9AF83530FB3FC54FAA21EB9CF1331FD0F0DA954F687CB9E18279697900E53FB317C9CBCE48E23D053" +
    "71ECC15951B8F3649D7CA33ED68DC9047E82C9BAAD9799D0D458CB847CA9FFBE3C8A775233557DDE13A8B14087CC1BC8F10F6ECDD083A959CFF84A9D1D50755E" +
    "3E191818AF23E2293558766D2C07E25712B2CA0B535ED8F6C56CE73D24BDD0291771861A54B4C285A9A3DB7ACA6D224AEACD621DB9F2A22ED1E9E11D75BED7DC" +
    "0ECB0A8E68A2FF1263408DC808DFFD164B116774CD0B9B8D05411ED6262E429BA495676B8398DB2F35D3C1B9CED52636F2765E1A95CB7CA4C3DDABDDBFF38253"
$script:QuarantineKeySha256 = "7331FC5CDFCDB24D92D3AE171CE24D888566B0F16A741BA5DEE8F997C3E1905C"

function ConvertFrom-HexText {
    param([string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    return , $bytes
}

# Plain RC4 (encrypting and decrypting are the same operation)
function Invoke-TestRc4 {
    param([byte[]]$Key, [byte[]]$Data)
    $s = New-Object int[] 256
    for ($i = 0; $i -lt 256; $i++) { $s[$i] = $i }
    $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $s[$i] + $Key[$i % $Key.Length]) % 256
        $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t
    }
    $out = New-Object byte[] $Data.Length
    $i = 0; $j = 0
    for ($n = 0; $n -lt $Data.Length; $n++) {
        $i = ($i + 1) % 256
        $j = ($j + $s[$i]) % 256
        $t = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $t
        $out[$n] = $Data[$n] -bxor $s[($s[$i] + $s[$j]) % 256]
    }
    return , $out
}

# A quarantine entry resource field: uint16 data size, uint16 identifier
# (low 12 bits) and data type (high 4 bits), the data, zero padding to 4
# bytes. -Size: the data size written (default: the data's length)
function New-QuarantineField {
    param([int]$Id, [int]$Type, [byte[]]$Data, [int]$Size = -1)
    if ($Size -lt 0) { $Size = $Data.Length }
    $field = Join-Bytes @((Get-UInt16Bytes $Size), (Get-UInt16Bytes (($Type -shl 12) -bor $Id)), $Data)
    return , (Join-Bytes @($field, (New-Object byte[] ((4 - ($field.Length % 4)) % 4))))
}

# A quarantine entry: header, part 1 and part 2, each RC4-encrypted on its own.
# $Resources: @(path, type) or @(path, type, fields) (fields: the bytes from
# New-QuarantineField; default: a flags DWORD and a detection context
# string, which the builder does not read). -Magic: first header bytes;
# -SizeAdjust: added to the part 2 size written in the header (a size past
# the end)
function New-QuarantineEntry {
    param([string]$Threat, $Time, [object[]]$Resources, [long]$ThreatId = 2147700001,
          [byte[]]$Magic = @(0xDB, 0xE8, 0xC5, 0x01, 0x01, 0x00, 0x01, 0x00), [int]$SizeAdjust = 0)
    $key = ConvertFrom-HexText $script:QuarantineKeyHex
    $fileTime = 0L
    if ($null -ne $Time) { $fileTime = ([datetime]$Time).ToFileTimeUtc() }
    $part1 = Join-Bytes @((New-Object System.Guid "0000A1B2-0000-4C3D-8E4F-5A6B7C8D9E0F").ToByteArray(), [guid]::NewGuid().ToByteArray(),
        [BitConverter]::GetBytes([long]$fileTime), [BitConverter]::GetBytes([long]$ThreatId), (Get-UInt32Bytes 1),
        [System.Text.Encoding]::UTF8.GetBytes($Threat + [char]0))

    # Part 2: count, offsets, then each resource (path, field count, type,
    # padding to 4 bytes, the fields)
    $bodies = @()
    foreach ($resource in $Resources) {
        $fields = @((New-QuarantineField -Id 0x0A -Type 3 -Data (Get-UInt32Bytes 0)),
            (New-QuarantineField -Id 0x0D -Type 2 -Data ([System.Text.Encoding]::Unicode.GetBytes("ctx" + [char]0))))
        if ($resource.Count -gt 2) { $fields = @($resource[2]) }
        $body = Join-Bytes @([System.Text.Encoding]::Unicode.GetBytes($resource[0] + [char]0), (Get-UInt16Bytes $fields.Count), [System.Text.Encoding]::ASCII.GetBytes($resource[1] + [char]0))
        $body = Join-Bytes @($body, (New-Object byte[] ((4 - ($body.Length % 4)) % 4)))
        $bodies += , (Join-Bytes (@(, $body) + $fields))
    }
    $offset = 4 + 4 * $bodies.Count
    $offsets = @()
    foreach ($body in $bodies) { $offsets += , (Get-UInt32Bytes $offset); $offset += $body.Length }
    $part2 = Join-Bytes (@(, (Get-UInt32Bytes $bodies.Count)) + $offsets + $bodies)

    $header = New-Object byte[] 0x3C
    [Array]::Copy($Magic, 0, $header, 0, $Magic.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$part1.Length), 0, $header, 0x28, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]($part2.Length + $SizeAdjust)), 0, $header, 0x2C, 4)
    return , (Join-Bytes @((Invoke-TestRc4 -Key $key -Data $header), (Invoke-TestRc4 -Key $key -Data $part1), (Invoke-TestRc4 -Key $key -Data $part2)))
}

# --- Fixture -------------------------------------------------------------------
$sha1 = "3f8a1c0d9e2b4a6f7c8d9e0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e"
$sha2 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
$t = @{
    D1Initial   = Get-Utc "2026-03-01 10:00:00.123"
    D1Tracking  = Get-Utc "2026-03-01 09:59:59.900"
    D1Status    = Get-Utc "2026-03-01 10:00:05.000"
    D2Tracking  = Get-Utc "2026-03-02 11:30:00.250"
    D2Status    = Get-Utc "2026-03-02 11:31:00.000"
    D3Initial   = Get-Utc "2026-03-03 08:15:30.500"
    D6Created   = Get-Utc "2026-03-04 07:00:00.000"
    D9Initial   = Get-Utc "2026-03-06 14:20:00.000"
    D10Tracking = Get-Utc "2026-03-07 09:45:10.750"
    Q1          = Get-Utc "2026-03-01 10:00:05.000"
    Q1Created   = Get-Utc "2026-02-28 18:12:44.000"
    Q1Modified  = Get-Utc "2026-02-28 18:12:45.000"
    Q2          = Get-Utc "2026-03-02 11:31:00.000"
    Q5Created   = Get-Utc "2026-03-05 06:00:00.000"
    Q6Created   = Get-Utc "2026-03-08 16:30:00.000"
    # A damaged FILETIME: not zero, but before 1980
    Bogus       = Get-Utc "1601-01-02 00:00:00.000"
}
$did1 = "11111111-2222-4333-8444-555555555551"
$did2 = "11111111-2222-4333-8444-555555555552"
$did3 = "11111111-2222-4333-8444-555555555553"
$did6 = "11111111-2222-4333-8444-555555555556"
$did7 = "11111111-2222-4333-8444-555555555557"
$did9 = "11111111-2222-4333-8444-555555555559"
$did10 = "11111111-2222-4333-8444-55555555555A"
$canary = "Canary:Win32/MustNotBeRead"

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("defender-parser-test-" + [guid]::NewGuid().ToString("N"))
$reportsDir = Join-Path (Split-Path $builder -Parent) "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
try {
    # --- Independent checks of this test's RC4 code and key copy ---
    $vector = Invoke-TestRc4 -Key ([System.Text.Encoding]::ASCII.GetBytes("Key")) -Data ([System.Text.Encoding]::ASCII.GetBytes("Plaintext"))
    Assert-Equal -Name "test RC4 matches the standard test vector" -Expected "BBF316E8D940AF0AD3" -Actual ([BitConverter]::ToString($vector).Replace("-", ""))
    $keySha = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash((ConvertFrom-HexText $script:QuarantineKeyHex))).Replace("-", "")
    Assert-Equal -Name "test copy of the published quarantine key (SHA-256)" -Expected $script:QuarantineKeySha256 -Actual $keySha

    $collection = Join-Path $workDir "collection"
    $historyDir = Join-Path $collection "AntiVirus\Defender\DetectionHistory"
    $entriesDir = Join-Path $collection "AntiVirus\Defender\Quarantine\Entries"
    # A copied ProgramData tree (not the collector's layout) is read too
    $copiedHistoryDir = Join-Path $collection "C\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
    foreach ($dir in @("$historyDir\02", "$historyDir\03", "$copiedHistoryDir\05", $entriesDir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText((Join-Path $collection "collection_info.json"),
        '{ "SchemaVersion": 1, "Mode": "Live", "CollectionStartUtc": "2026-09-01T12:00:00Z", "CollectorTimeZoneId": "UTC", "TargetTimeZoneId": "UTC" }')

    # D1: file and webfile resources, all the detection's own values
    $tracking1 = New-ThreatTracking ([ordered]@{
        ThreatTrackingSha256     = @(6, $sha1)
        ThreatTrackingSigSeq     = @(4, 24633351302744)
        ThreatTrackingId         = @(6, "7A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9")
        ThreatTrackingStartTime  = @(4, $t.D1Tracking.ToFileTimeUtc())
        ThreatTrackingThreatName = @(6, "Trojan:Win32/TimelineTest.A")
        ThreatTrackingSize       = @(4, 33280)
        ThreatTrackingIsEsuSig   = @(5, 0)
        ThreatTrackingThreatId   = @(3, 2147700001)
        ThreatTrackingResearchData = @(7, [byte[]](1, 2, 3, 4, 5))
        ThreatTrackingScanSource = @(3, 3)
    })
    $tracking1b = New-ThreatTracking ([ordered]@{ ThreatTrackingSha256 = @(6, $sha2); ThreatTrackingStartTime = @(4, $t.D2Tracking.ToFileTimeUtc()) })
    $webLocation = "C:\Users\alice\Downloads\invoice.exe|https://downloads.example.com/invoice.exe|pid:4242,ProcessStart:133700000000000000"
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "02\{$($did1.ToUpperInvariant())}"), (New-DetectionHistoryFile -ThreatId 2147700001 -DetectionId $did1 `
        -Threat "Trojan:Win32/TimelineTest.A" -Severity 5 -Category 8 -Status 3 -Resources @(
            [PSCustomObject]@{ Type = "file"; Location = "C:\Users\alice\Downloads\invoice.exe"; Tracking = $tracking1 },
            [PSCustomObject]@{ Type = "webfile"; Location = $webLocation; Tracking = $tracking1b }) `
        -Own ([PSCustomObject]@{ StatusChange = $t.D1Status; User = "CONTOSO\alice"; Process = "C:\Program Files\Mozilla Firefox\firefox.exe"; Initial = $t.D1Initial; Remediation = $t.D1Status })))

    # D2 (copied ProgramData tree): a container (threat tracking header only)
    # before the file; no initial detection time, so the threat tracking
    # start time is used. The file's tracking data has no header and an
    # unknown value type after the start time; an unknown value type is
    # appended to the file.
    $tracking2 = New-ThreatTracking -NoHeader ([ordered]@{
        ThreatTrackingSha256     = @(6, $sha2)
        ThreatTrackingStartTime  = @(4, $t.D2Tracking.ToFileTimeUtc())
        ThreatTrackingFuture     = @(9, [byte[]](9, 9, 9, 9))
        ThreatTrackingThreatName = @(6, "not read")
    })
    [System.IO.File]::WriteAllBytes((Join-Path $copiedHistoryDir "05\{$($did2.ToUpperInvariant())}"), (New-DetectionHistoryFile -ThreatId 2147700002 -DetectionId $did2 `
        -Threat "Backdoor:Win32/TimelineTest.B" -Severity 4 -Category 6 -Status 1 -Resources @(
            [PSCustomObject]@{ Type = "containerfile"; Location = "C:\Users\bob\Downloads\tools.zip"; Tracking = (New-ThreatTracking -HeaderOnly) },
            [PSCustomObject]@{ Type = "file"; Location = "C:\Users\bob\Downloads\tools.zip->agent.exe"; Tracking = $tracking2 }) `
        -Own ([PSCustomObject]@{ StatusChange = $t.D2Status; User = "CONTOSO\bob"; Process = "Unknown"; Initial = $null; Remediation = $null }) `
        -Extra (New-HistoryValue -Type 0x99 -Data ([byte[]](1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)))))

    # D3: registry resource only (no file), minimal threat tracking
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{$($did3.ToUpperInvariant())}"), (New-DetectionHistoryFile -ThreatId 2147700003 -DetectionId $did3 `
        -Threat "PUA:Win32/TimelineTest.C" -Severity 1 -Category 27 -Status 6 -Resources @(
            [PSCustomObject]@{ Type = "regkey"; Location = "HKLM\SOFTWARE\Contoso\Toolbar"; Tracking = (New-ThreatTracking ([ordered]@{ ThreatTrackingScanType = @(3, 1) })) }) `
        -Own ([PSCustomObject]@{ StatusChange = $null; User = "NT AUTHORITY\SYSTEM"; Process = "Unknown"; Initial = $t.D3Initial; Remediation = $null })))

    # D4: not a DetectionHistory file; D5: cut off before the threat name
    $random = New-Object System.Random 20261007
    $noise = New-Object byte[] 3000
    $random.NextBytes($noise)
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{11111111-2222-4333-8444-555555555554}"), $noise)
    $full = [System.IO.File]::ReadAllBytes((Join-Path $historyDir "02\{$($did1.ToUpperInvariant())}"))
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{11111111-2222-4333-8444-555555555555}"), [byte[]]$full[0..99])

    # D6: a value whose size runs past the end of the file right after the
    # threat values (no resources, no times): the time comes from the
    # manifest's original creation time. D7: the same, but the manifest's
    # creation time is before 1980 (no time)
    $broken = Join-Bytes @((New-HistoryNumber64 2147700006), (New-HistoryGuid $did6), (New-HistoryText "Magic.Version:1.2"),
        (New-HistoryText "Trojan:Win32/TimelineTest.D"), (New-HistoryNumber 0), (New-HistoryNumber 5), (New-HistoryNumber 8),
        (Get-UInt32Bytes 0x7FFFFFF0), (Get-UInt32Bytes 0x06), (New-Object byte[] 8))
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{$($did6.ToUpperInvariant())}"), $broken)
    $broken7 = Join-Bytes @((New-HistoryNumber64 2147700007), (New-HistoryGuid $did7), (New-HistoryText "Magic.Version:1.2"), (New-HistoryText "Trojan:Win32/TimelineTest.E"))
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{$($did7.ToUpperInvariant())}"), $broken7)

    # D8: over 1 MB, not read
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{11111111-2222-4333-8444-555555555558}"), (Join-Bytes @($full, (New-Object byte[] (1MB)))))

    # D9: behavior and process resources (no file resource): the path is the
    # threat tracking's CONTEXT_DATA_FILENAME, not a "pid:" location
    $tracking9 = New-ThreatTracking ([ordered]@{
        ThreatTrackingStartTime = @(4, $t.D9Initial.ToFileTimeUtc())
        CONTEXT_DATA_FILENAME   = @(6, "C:\Users\dave\AppData\Local\Temp\helper.dll")
        CONTEXT_DATA_PROCESS_PPID = @(6, "5120")
    })
    $behaviorLocation = "pid:7312:111594416347043"
    $processLocation = "pid:7312,ProcessStart:133700000000000000"
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{$($did9.ToUpperInvariant())}"), (New-DetectionHistoryFile -ThreatId 2147700009 -DetectionId $did9 `
        -Threat "Behavior:Win32/TimelineTest.I" -Severity 5 -Category 46 -Status 3 -Resources @(
            [PSCustomObject]@{ Type = "behavior"; Location = $behaviorLocation; Tracking = $tracking9 },
            [PSCustomObject]@{ Type = "process"; Location = $processLocation; Tracking = (New-ThreatTracking -HeaderOnly) }) `
        -Own ([PSCustomObject]@{ StatusChange = $null; User = "CONTOSO\dave"; Process = "C:\Windows\System32\rundll32.exe"; Initial = $t.D9Initial; Remediation = $null })))

    # D10: process and command line resources only (no path at all); a
    # damaged initial detection time (before 1980): the threat tracking start
    # time is used instead
    $cmdLocation = "C:\Windows\System32\cmd.exe /c timelinetest.cmd"
    [System.IO.File]::WriteAllBytes((Join-Path $historyDir "03\{$($did10.ToUpperInvariant())}"), (New-DetectionHistoryFile -ThreatId 2147700010 -DetectionId $did10 `
        -Threat "Behavior:Win32/TimelineTest.J" -Severity 4 -Category 46 -Status 1 -Resources @(
            [PSCustomObject]@{ Type = "process"; Location = $processLocation; Tracking = (New-ThreatTracking ([ordered]@{ ThreatTrackingStartTime = @(4, $t.D10Tracking.ToFileTimeUtc()) })) },
            [PSCustomObject]@{ Type = "CmdLine"; Location = $cmdLocation; Tracking = (New-ThreatTracking -HeaderOnly) }) `
        -Own ([PSCustomObject]@{ StatusChange = $t.Bogus; User = "CONTOSO\erin"; Process = "Unknown"; Initial = $t.Bogus; Remediation = $null })))

    # Quarantine entries: Q1 one resource with a \\?\ path and the fields the
    # builder reads (resource ID, physical path, original file times and
    # size) among others, one of odd size; Q2 three resources (file, \\?\UNC\
    # file whose physical path is the same, registry key whose last field
    # runs past the end); Q3 wrong header magic; Q4 part 2 size past the end
    # of the file; Q5 no time and Q6 a time before 1980 (manifest time used)
    $resourceId = [byte[]](0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90, 0x01, 0x12, 0x23, 0x34)
    $q1Fields = @(
        (New-QuarantineField -Id 0x02 -Type 4 -Data $resourceId),
        (New-QuarantineField -Id 0x0A -Type 3 -Data (Get-UInt32Bytes 1)),
        (New-QuarantineField -Id 0x0D -Type 5 -Data ([byte[]](1, 2, 3, 4, 5))),
        (New-QuarantineField -Id 0x0C -Type 2 -Data ([System.Text.Encoding]::Unicode.GetBytes("\\?\C:\Users\alice\AppData\Local\Temp\invoice.exe" + [char]0))),
        (New-QuarantineField -Id 0x0F -Type 6 -Data ([BitConverter]::GetBytes($t.Q1Created.ToFileTimeUtc()))),
        (New-QuarantineField -Id 0x10 -Type 6 -Data ([BitConverter]::GetBytes($t.Q1.ToFileTimeUtc()))),
        (New-QuarantineField -Id 0x11 -Type 6 -Data ([BitConverter]::GetBytes($t.Q1Modified.ToFileTimeUtc()))),
        (New-QuarantineField -Id 0x12 -Type 6 -Data ([BitConverter]::GetBytes([long]33280))))
    [System.IO.File]::WriteAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000001}"),
        (New-QuarantineEntry -Threat "Trojan:Win32/TimelineTest.A" -Time $t.Q1 -Resources @(, @("\\?\C:\Users\alice\Downloads\invoice.exe", "file", $q1Fields))))
    $uncFields = @((New-QuarantineField -Id 0x0C -Type 2 -Data ([System.Text.Encoding]::Unicode.GetBytes("\\?\UNC\fileserver\share\drop.exe" + [char]0))),
        (New-QuarantineField -Id 0x12 -Type 3 -Data (Get-UInt32Bytes 4096)))
    $cutFields = @((New-QuarantineField -Id 0x0A -Type 3 -Data (Get-UInt32Bytes 0)),
        (New-QuarantineField -Id 0x0F -Type 6 -Data ([BitConverter]::GetBytes($t.Q1Created.ToFileTimeUtc())) -Size 0x7FFF))
    [System.IO.File]::WriteAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000002}"),
        (New-QuarantineEntry -Threat "Backdoor:Win32/TimelineTest.B" -ThreatId 2147700002 -Time $t.Q2 -Resources @(
            @("C:\Users\bob\AppData\Roaming\agent.exe", "file"),
            @("\\?\UNC\fileserver\share\drop.exe", "file", $uncFields),
            @("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\agent", "regkeyvalue", $cutFields))))
    [System.IO.File]::WriteAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000003}"),
        (New-QuarantineEntry -Threat "Trojan:Win32/TimelineTest.F" -Time $t.Q1 -Resources @(, @("C:\x.exe", "file")) -Magic ([byte[]](0x01, 0x02, 0x03, 0x04))))
    [System.IO.File]::WriteAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000004}"),
        (New-QuarantineEntry -Threat "Trojan:Win32/TimelineTest.G" -Time $t.Q1 -Resources @(, @("C:\y.exe", "file")) -SizeAdjust 64))
    [System.IO.File]::WriteAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000005}"),
        (New-QuarantineEntry -Threat "Trojan:Win32/TimelineTest.H" -ThreatId 2147700008 -Time $null -Resources @(, @("C:\Users\carol\Desktop\setup.exe", "file"))))
    [System.IO.File]::WriteAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000006}"),
        (New-QuarantineEntry -Threat "Trojan:Win32/TimelineTest.K" -ThreatId 2147700011 -Time $t.Bogus -Resources @(, @("C:\Users\frank\Desktop\tool.exe", "file"))))

    # Valid entries in places that must never be read
    $canaryEntry = New-QuarantineEntry -Threat $canary -Time $t.Q1 -Resources @(, @("C:\canary.exe", "file"))
    foreach ($place in @("AntiVirus\Defender\Quarantine\ResourceData\AB", "AntiVirus\Defender\Quarantine\Resources\AB", "AntiVirus\Other\Entries")) {
        New-Item -ItemType Directory -Path (Join-Path $collection $place) -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $collection "$place\AB0123456789ABCDEF0123456789ABCDEF012345"), $canaryEntry)
    }

    # Manifest: original creation times of D6, Q5 and Q6, and of D7 one before
    # 1980 (not used: D7 stays without a time)
    $manifest = @('"SHA256","SourcePath","DestPath","SizeBytes","CollectedAt","RelativePath","SourceCreatedUtc","SourceModifiedUtc","SourceAccessedUtc"')
    foreach ($row in @(@("AntiVirus\Defender\DetectionHistory\03\{$($did6.ToUpperInvariant())}", $t.D6Created),
                       @("AntiVirus\Defender\DetectionHistory\03\{$($did7.ToUpperInvariant())}", (Get-Utc "1975-06-01 00:00:00.000")),
                       @("AntiVirus\Defender\Quarantine\Entries\{0000A1B2-0000-0000-0000-000000000005}", $t.Q5Created),
                       @("AntiVirus\Defender\Quarantine\Entries\{0000A1B2-0000-0000-0000-000000000006}", $t.Q6Created))) {
        $created = $row[1].ToString("o")
        $manifest += '"00","C:\ProgramData\x","C:\out\x","1","2026-09-01 12:00:00","' + $row[0] + '","' + $created + '","' + $created + '","' + $created + '"'
    }
    [System.IO.File]::WriteAllLines((Join-Path $collection "collection_manifest.csv"), $manifest)

    # --- Run the builder ---
    $timelineCsv = Join-Path $workDir "timeline.csv"
    $powershellExe = (Get-Process -Id $PID).Path
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $builderOutput = @(& $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder -InputPath $collection -Sources "AntiVirus" `
        -OutputFile $timelineCsv -NoExcel -Viewer None 2>&1 | ForEach-Object { "$_" })
    $ErrorActionPreference = $previous
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Name "builder run" -Passed $false -Message "the builder exited with code $LASTEXITCODE or wrote no timeline"
        throw "no timeline"
    }
    $rows = @(Import-Csv -LiteralPath $timelineCsv)
    $log = $builderOutput -join "`n"

    # --- Checks ---
    function Test-Row {
        param([string]$Name, [string]$Description, [string]$Timestamp, [string]$Source, [string]$User, [string]$Details)
        $match = @($rows | Where-Object { $_.Description -ceq $Description })
        if ($match.Count -ne 1) {
            Write-TestResult -Name "row: $Name" -Passed $false -Message "expected 1 row '$Description', found $($match.Count)"
            return
        }
        Assert-Equal -Name "$Name time" -Expected $Timestamp -Actual $match[0].Timestamp
        Assert-Equal -Name "$Name source / type / artifact" -Expected "$Source SecurityAlert AntiVirus" -Actual "$($match[0].Source) $($match[0].EventType) $($match[0].Artifact)"
        Assert-Equal -Name "$Name user" -Expected $User -Actual $match[0].User
        Assert-Equal -Name "$Name details" -Expected $Details -Actual $match[0].Details
    }

    Assert-Equal -Name "row count" -Expected 12 -Actual $rows.Count
    Assert-Equal -Name "DetectionHistory rows" -Expected 6 -Actual @($rows | Where-Object { $_.Source -eq "Defender-DetectionHistory" }).Count
    Assert-Equal -Name "quarantine rows" -Expected 6 -Actual @($rows | Where-Object { $_.Source -eq "Defender-Quarantine" }).Count

    Test-Row -Name "D1 (file + webfile)" -Source "Defender-DetectionHistory" -Timestamp "2026-03-01 10:00:00.123" -User "CONTOSO\alice" `
        -Description "Defender detection (DetectionHistory): Trojan:Win32/TimelineTest.A on C:\Users\alice\Downloads\invoice.exe" `
        -Details ("ThreatName=Trojan:Win32/TimelineTest.A | ThreatID=2147700001 | Severity=Severe (5) | CategoryID=8 | Status=Quarantined | " +
            "Path=C:\Users\alice\Downloads\invoice.exe | Resources=file:_C:\Users\alice\Downloads\invoice.exe; webfile:_$webLocation | User=CONTOSO\alice | " +
            "Process=C:\Program Files\Mozilla Firefox\firefox.exe | SHA256=$sha1 | StatusChangeUtc=2026-03-01 10:00:05 | " +
            "RemediationUtc=2026-03-01 10:00:05 | DetectionID={$($did1.ToUpperInvariant())}")
    Test-Row -Name "D2 (container, tracking start time)" -Source "Defender-DetectionHistory" -Timestamp "2026-03-02 11:30:00.250" -User "CONTOSO\bob" `
        -Description "Defender detection (DetectionHistory): Backdoor:Win32/TimelineTest.B on C:\Users\bob\Downloads\tools.zip->agent.exe" `
        -Details ("ThreatName=Backdoor:Win32/TimelineTest.B | ThreatID=2147700002 | Severity=High (4) | CategoryID=6 | Status=Detected | " +
            "Path=C:\Users\bob\Downloads\tools.zip->agent.exe | " +
            "Resources=containerfile:_C:\Users\bob\Downloads\tools.zip; file:_C:\Users\bob\Downloads\tools.zip->agent.exe | User=CONTOSO\bob | " +
            "Process=Unknown | SHA256=$sha2 | StatusChangeUtc=2026-03-02 11:31:00 | " +
            "TimeNote=ThreatTrackingStartTime (no valid initial detection time in the file) | DetectionID={$($did2.ToUpperInvariant())}")
    Test-Row -Name "D3 (registry resource)" -Source "Defender-DetectionHistory" -Timestamp "2026-03-03 08:15:30.500" -User "NT AUTHORITY\SYSTEM" `
        -Description "Defender detection (DetectionHistory): PUA:Win32/TimelineTest.C on HKLM\SOFTWARE\Contoso\Toolbar" `
        -Details ("ThreatName=PUA:Win32/TimelineTest.C | ThreatID=2147700003 | Severity=Low (1) | CategoryID=27 | Status=Blocked | " +
            "Path=HKLM\SOFTWARE\Contoso\Toolbar | Resources=regkey:_HKLM\SOFTWARE\Contoso\Toolbar | User=NT AUTHORITY\SYSTEM | Process=Unknown | " +
            "DetectionID={$($did3.ToUpperInvariant())}")
    Test-Row -Name "D6 (damaged after the threat, manifest time)" -Source "Defender-DetectionHistory" -Timestamp "2026-03-04 07:00:00.000" -User "" `
        -Description "Defender detection (DetectionHistory): Trojan:Win32/TimelineTest.D" `
        -Details ("ThreatName=Trojan:Win32/TimelineTest.D | ThreatID=2147700006 | Severity=Severe (5) | CategoryID=8 | " +
            "TimeNote=DetectionHistory file created (no valid time in the file) | DetectionID={$($did6.ToUpperInvariant())}")
    Test-Row -Name "D9 (behavior + process, CONTEXT_DATA_FILENAME path)" -Source "Defender-DetectionHistory" -Timestamp "2026-03-06 14:20:00.000" -User "CONTOSO\dave" `
        -Description "Defender detection (DetectionHistory): Behavior:Win32/TimelineTest.I on C:\Users\dave\AppData\Local\Temp\helper.dll" `
        -Details ("ThreatName=Behavior:Win32/TimelineTest.I | ThreatID=2147700009 | Severity=Severe (5) | CategoryID=46 | Status=Quarantined | " +
            "Path=C:\Users\dave\AppData\Local\Temp\helper.dll | Resources=behavior:_$behaviorLocation; process:_$processLocation | User=CONTOSO\dave | " +
            "Process=C:\Windows\System32\rundll32.exe | DetectionID={$($did9.ToUpperInvariant())}")
    Test-Row -Name "D10 (no path, initial time before 1980)" -Source "Defender-DetectionHistory" -Timestamp "2026-03-07 09:45:10.750" -User "CONTOSO\erin" `
        -Description "Defender detection (DetectionHistory): Behavior:Win32/TimelineTest.J" `
        -Details ("ThreatName=Behavior:Win32/TimelineTest.J | ThreatID=2147700010 | Severity=High (4) | CategoryID=46 | Status=Detected | " +
            "Resources=process:_$processLocation; CmdLine:_$cmdLocation | User=CONTOSO\erin | Process=Unknown | " +
            "TimeNote=ThreatTrackingStartTime (no valid initial detection time in the file) | DetectionID={$($did10.ToUpperInvariant())}")

    $resourceIdHex = [BitConverter]::ToString($resourceId).Replace("-", "")
    Test-Row -Name "Q1 (\\?\ path, resource fields)" -Source "Defender-Quarantine" -Timestamp "2026-03-01 10:00:05.000" -User "" `
        -Description "Defender quarantined: C:\Users\alice\Downloads\invoice.exe (Trojan:Win32/TimelineTest.A)" `
        -Details ("ThreatName=Trojan:Win32/TimelineTest.A | ThreatID=2147700001 | Path=C:\Users\alice\Downloads\invoice.exe | " +
            "PhysicalPath=C:\Users\alice\AppData\Local\Temp\invoice.exe | ResourceType=file | ResourceID=$resourceIdHex | FileSize=33280 | " +
            "FileCreatedUtc=2026-02-28 18:12:44 | FileModifiedUtc=2026-02-28 18:12:45")
    Test-Row -Name "Q2 resource 1" -Source "Defender-Quarantine" -Timestamp "2026-03-02 11:31:00.000" -User "" `
        -Description "Defender quarantined: C:\Users\bob\AppData\Roaming\agent.exe (Backdoor:Win32/TimelineTest.B)" `
        -Details "ThreatName=Backdoor:Win32/TimelineTest.B | ThreatID=2147700002 | Path=C:\Users\bob\AppData\Roaming\agent.exe | ResourceType=file | ResourceCount=3"
    Test-Row -Name "Q2 resource 2 (\\?\UNC\ path, same physical path)" -Source "Defender-Quarantine" -Timestamp "2026-03-02 11:31:00.000" -User "" `
        -Description "Defender quarantined: \\fileserver\share\drop.exe (Backdoor:Win32/TimelineTest.B)" `
        -Details "ThreatName=Backdoor:Win32/TimelineTest.B | ThreatID=2147700002 | Path=\\fileserver\share\drop.exe | ResourceType=file | FileSize=4096 | ResourceCount=3"
    Test-Row -Name "Q2 resource 3 (registry, field past the end)" -Source "Defender-Quarantine" -Timestamp "2026-03-02 11:31:00.000" -User "" `
        -Description "Defender quarantined: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\agent (Backdoor:Win32/TimelineTest.B)" `
        -Details "ThreatName=Backdoor:Win32/TimelineTest.B | ThreatID=2147700002 | Path=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\agent | ResourceType=regkeyvalue | ResourceCount=3"
    Test-Row -Name "Q5 (no time, manifest time)" -Source "Defender-Quarantine" -Timestamp "2026-03-05 06:00:00.000" -User "" `
        -Description "Defender quarantined: C:\Users\carol\Desktop\setup.exe (Trojan:Win32/TimelineTest.H)" `
        -Details ("ThreatName=Trojan:Win32/TimelineTest.H | ThreatID=2147700008 | Path=C:\Users\carol\Desktop\setup.exe | ResourceType=file | " +
            "TimeNote=quarantine entry file created (no valid time in the entry)")
    Test-Row -Name "Q6 (time before 1980, manifest time)" -Source "Defender-Quarantine" -Timestamp "2026-03-08 16:30:00.000" -User "" `
        -Description "Defender quarantined: C:\Users\frank\Desktop\tool.exe (Trojan:Win32/TimelineTest.K)" `
        -Details ("ThreatName=Trojan:Win32/TimelineTest.K | ThreatID=2147700011 | Path=C:\Users\frank\Desktop\tool.exe | ResourceType=file | " +
            "TimeNote=quarantine entry file created (no valid time in the entry)")
    Assert-Equal -Name "no 'pid:' location as a path" -Expected 0 -Actual @($rows | Where-Object { $_.Description -match ' on pid:' -or $_.Details -match '(^| )Path=pid:' }).Count

    Assert-Equal -Name "no row from ResourceData, Resources or an Entries folder outside Quarantine" -Expected 0 -Actual @($rows | Where-Object {
        "$($_.Description) $($_.Details)".Contains($canary) }).Count
    Assert-Equal -Name "no row for a wrong header or sizes" -Expected 0 -Actual @($rows | Where-Object { $_.Description -match 'TimelineTest\.[FG]\)' }).Count
    $parseLines = (@($builderOutput | Where-Object { $_ -match 'Parsing: |Added \d+ timeline' }) -join "`n")
    Write-TestResult -Name "log: DetectionHistory files and skips" -Message $parseLines -Passed (
        $log -match "Parsing: 10 Defender DetectionHistory file\(s\)\s*\n[^\n]*Added 6 timeline entries \(skipped: 2 not in the expected format, 1 without a time, 1 over 1 MB not read\)")
    Write-TestResult -Name "log: quarantine entries and skips" -Message $parseLines -Passed (
        $log -match "Parsing: 6 Defender quarantine entry file\(s\)\s*\n[^\n]*Added 6 timeline entries \(skipped: 2 not in the expected format\)")
    $warnings = @($builderOutput | Where-Object { $_ -match 'WARNING:|ERROR:' })
    Write-TestResult -Name "log: no warnings or errors" -Passed ($warnings.Count -eq 0) -Message ($warnings -join "`n")
    Assert-Equal -Name "log: ResourceData never named" -Expected $false -Actual ($log -match 'ResourceData')

    # --- Damaged files, read with the builder's functions in this process ---
    # Every truncation (every byte up to 600, then every 5th) and 200 random
    # corruptions of D1, D2, D9, Q1 and Q2 must be read without an exception
    Write-Host "Reading truncated and corrupted copies with the builder's functions ..."
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
    $functionAsts = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
            $parent = $_.Parent
            while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
            $null -eq $parent
        })
    foreach ($functionAst in $functionAsts) { . ([scriptblock]::Create($functionAst.Extent.Text)) }
    $tableNames = @('$script:xmlInvalidPattern', '$script:xmlInvalidRegex', '$script:DefenderSeverityNames', '$script:DefenderThreatStatusNames')
    $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $tableNames -contains $node.Left.Extent.Text }, $false) |
        Sort-Object { $_.Extent.StartOffset } | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:artifactStats = @{}
    $script:manifestTimes = @{}
    $script:collectionRoot = $collection
    $script:logFile = Join-Path $workDir "unit.log"
    $damagedPath = Join-Path $workDir "damaged.bin"
    $exceptions = New-Object System.Collections.Generic.List[string]
    $reads = 0
    $samples = @(
        @{ Name = "D1"; Quarantine = $false; Bytes = $full },
        @{ Name = "D2"; Quarantine = $false; Bytes = [System.IO.File]::ReadAllBytes((Join-Path $copiedHistoryDir "05\{$($did2.ToUpperInvariant())}")) },
        @{ Name = "D9"; Quarantine = $false; Bytes = [System.IO.File]::ReadAllBytes((Join-Path $historyDir "03\{$($did9.ToUpperInvariant())}")) },
        @{ Name = "Q1"; Quarantine = $true; Bytes = [System.IO.File]::ReadAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000001}")) },
        @{ Name = "Q2"; Quarantine = $true; Bytes = [System.IO.File]::ReadAllBytes((Join-Path $entriesDir "{0000A1B2-0000-0000-0000-000000000002}")) }
    )
    foreach ($sample in $samples) {
        $variants = New-Object System.Collections.Generic.List[object]
        for ($length = 0; $length -lt $sample.Bytes.Length; $length += $(if ($length -lt 600) { 1 } else { 5 })) {
            $cut = New-Object byte[] $length
            [Array]::Copy($sample.Bytes, $cut, $length)
            $variants.Add($cut)
        }
        for ($n = 0; $n -lt 200; $n++) {
            $changed = [byte[]]$sample.Bytes.Clone()
            for ($k = 0; $k -le $random.Next(4); $k++) { $changed[$random.Next($changed.Length)] = [byte]$random.Next(256) }
            $variants.Add($changed)
        }
        foreach ($variant in $variants) {
            [System.IO.File]::WriteAllBytes($damagedPath, [byte[]]$variant)
            $reads++
            try {
                if ($sample.Quarantine) { $null = Read-DefenderQuarantineEntry -File (New-Object System.IO.FileInfo $damagedPath) }
                else { $null = Read-DefenderDetectionHistory -File (New-Object System.IO.FileInfo $damagedPath) }
            }
            catch { $exceptions.Add("$($sample.Name), $($variant.Length) bytes: $($_.Exception.Message)") }
        }
    }
    Write-TestResult -Name "damaged files: $reads read without an exception" -Passed ($exceptions.Count -eq 0) -Message (@($exceptions | Select-Object -First 5) -join "`n")
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the one from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName -and $_.Name -like "timeline_*" } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
