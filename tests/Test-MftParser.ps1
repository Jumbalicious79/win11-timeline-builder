# =============================================================
# $MFT parser test (Mark of the Web)
# Builds a small synthetic $MFT at test time (FILE records with update
# sequence fixups, $STANDARD_INFORMATION, $FILE_NAME, unnamed and named
# $DATA streams), runs the builder's Parse-FileSystem on it and checks the
# rows: the "Downloaded file (Mark of the Web, ...)" rows from resident
# Zone.Identifier streams (ANSI, UTF-8 and UTF-16 text, in the base record or
# an extension record), a non-resident one, a deleted and a timestomped
# file, the -MftDays window, and that "File created" rows keep their
# Description and only gain ZoneId/HostUrl at the end of Details.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MftParser.ps1
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
        Write-Host "::error file=tests/Test-MftParser.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# --- Synthetic $MFT -------------------------------------------------------
# Record size 1024, two 512-byte sectors. Attribute layouts as described in
# the builder's "File System Parser" comment.

function ConvertTo-PaddedLength {
    param([int]$Length)
    return [int](8 * [Math]::Ceiling($Length / 8))
}

function New-ResidentAttribute {
    param([uint32]$Type, [string]$Name = "", [byte[]]$Content = @())
    $nameBytes = [System.Text.Encoding]::Unicode.GetBytes($Name)
    $contentOffset = ConvertTo-PaddedLength (0x18 + $nameBytes.Length)
    $length = ConvertTo-PaddedLength ($contentOffset + $Content.Length)
    $bytes = New-Object byte[] $length
    $writer = [System.IO.BinaryWriter]::new([System.IO.MemoryStream]::new($bytes))
    $writer.Write([uint32]$Type)
    $writer.Write([uint32]$length)
    $writer.Write([byte]0)                  # resident
    $writer.Write([byte]$Name.Length)
    $writer.Write([uint16]0x18)             # name offset
    $writer.Write([uint16]0)                # flags
    $writer.Write([uint16]0)                # attribute id
    $writer.Write([uint32]$Content.Length)
    $writer.Write([uint16]$contentOffset)
    $writer.Write([uint16]0)
    $writer.Write($nameBytes)
    $writer.BaseStream.Position = $contentOffset
    $writer.Write($Content)
    return ,$bytes
}

function New-NonResidentAttribute {
    param([uint32]$Type, [string]$Name = "", [long]$RealSize)
    $nameBytes = [System.Text.Encoding]::Unicode.GetBytes($Name)
    $runOffset = ConvertTo-PaddedLength (0x40 + $nameBytes.Length)
    $length = $runOffset + 8
    $clusters = [long][Math]::Max(1, [Math]::Ceiling($RealSize / 4096))
    $bytes = New-Object byte[] $length
    $writer = [System.IO.BinaryWriter]::new([System.IO.MemoryStream]::new($bytes))
    $writer.Write([uint32]$Type)
    $writer.Write([uint32]$length)
    $writer.Write([byte]1)                  # non-resident
    $writer.Write([byte]$Name.Length)
    $writer.Write([uint16]0x40)             # name offset
    $writer.Write([uint16]0)
    $writer.Write([uint16]0)
    $writer.Write([long]0)                  # start VCN
    $writer.Write([long]($clusters - 1))    # last VCN
    $writer.Write([uint16]$runOffset)
    $writer.Write([uint16]0)
    $writer.Write([uint32]0)
    $writer.Write([long]($clusters * 4096)) # allocated size
    $writer.Write([long]$RealSize)
    $writer.Write([long]$RealSize)          # initialized size
    $writer.Write($nameBytes)
    # One data run: 3-byte length, 1-byte cluster offset
    $writer.BaseStream.Position = $runOffset
    $writer.Write([byte]0x13)
    $writer.Write([byte]($clusters -band 0xFF))
    $writer.Write([byte](($clusters -shr 8) -band 0xFF))
    $writer.Write([byte](($clusters -shr 16) -band 0xFF))
    $writer.Write([byte]0x10)
    return ,$bytes
}

# $STANDARD_INFORMATION content; MFT changed and accessed are 1 and 2 s after modified
function New-StandardInformation {
    param([datetime]$Created, [datetime]$Modified)
    $stream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($stream)
    foreach ($time in @($Created, $Modified, $Modified.AddSeconds(1), $Modified.AddSeconds(2))) {
        $writer.Write([long]$time.ToFileTimeUtc())
    }
    $writer.Write([uint32]0x20)             # archive
    $writer.Write((New-Object byte[] 0x24)) # max versions .. USN
    $writer.Flush()
    return ,$stream.ToArray()
}

function New-FileNameContent {
    param([long]$ParentRecord, [int]$ParentSeq, [datetime]$Created, [string]$Name, [long]$Size)
    $stream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($stream)
    $writer.Write([long]($ParentRecord -bor ([long]$ParentSeq -shl 48)))
    foreach ($index in 1..4) { $writer.Write([long]$Created.ToFileTimeUtc()) }
    $writer.Write([long]$Size)
    $writer.Write([long]$Size)
    $writer.Write([uint32]0x20)
    $writer.Write([uint32]0)
    $writer.Write([byte]$Name.Length)
    $writer.Write([byte]3)                  # Win32 + DOS namespace
    $writer.Write([System.Text.Encoding]::Unicode.GetBytes($Name))
    $writer.Flush()
    return ,$stream.ToArray()
}

# FILE record with fixups applied: the update sequence value replaces the
# last 2 bytes of each sector, whose real bytes are kept in the array
function New-MftRecord {
    param([int]$RecordNumber, [int]$Sequence = 1, [int]$Flags = 1, [long]$BaseReference = 0, [object[]]$Attributes)
    $record = New-Object byte[] 1024
    $writer = [System.IO.BinaryWriter]::new([System.IO.MemoryStream]::new($record))
    $writer.Write([uint32]0x454C4946)       # "FILE"
    $writer.Write([uint16]0x30)             # update sequence array offset
    $writer.Write([uint16]3)                # its count: the value + one per sector
    $writer.Write([long]0)                  # $LogFile sequence number
    $writer.Write([uint16]$Sequence)
    $writer.Write([uint16]1)                # hard links
    $writer.Write([uint16]0x38)             # first attribute
    $writer.Write([uint16]$Flags)           # 0x01 in use, 0x02 directory
    $writer.Write([uint32]0)                # bytes in use (below)
    $writer.Write([uint32]1024)             # bytes allocated
    $writer.Write([long]$BaseReference)
    $writer.Write([uint16]0)
    $writer.Write([uint16]0)
    $writer.Write([uint32]$RecordNumber)
    $writer.BaseStream.Position = 0x38
    foreach ($attribute in $Attributes) { $writer.Write([byte[]]$attribute) }
    $writer.Write([uint32]::MaxValue)       # end of attributes
    $writer.Write([uint32]0)
    $used = [int]$writer.BaseStream.Position
    $writer.BaseStream.Position = 0x18
    $writer.Write([uint32]$used)
    $record[0x30] = 0x2A
    $record[0x31] = 0x00
    foreach ($sector in 1..2) {
        $end = $sector * 512 - 2
        $record[0x30 + 2 * $sector] = $record[$end]
        $record[0x31 + 2 * $sector] = $record[$end + 1]
        $record[$end] = 0x2A
        $record[$end + 1] = 0x00
    }
    return ,$record
}

function New-TestFileRecord {
    param(
        [int]$RecordNumber, [string]$Name, [int]$Parent = 18, [int]$ParentSeq = 1,
        [int]$Flags = 1, [int]$Sequence = 1, [datetime]$Created, [datetime]$Modified,
        [datetime]$FnCreated, [long]$Size = 5, [object[]]$Streams = @()
    )
    $attributes = New-Object System.Collections.Generic.List[object]
    $attributes.Add((New-ResidentAttribute -Type 0x10 -Content (New-StandardInformation -Created $Created -Modified $Modified)))
    $attributes.Add((New-ResidentAttribute -Type 0x30 -Content (New-FileNameContent -ParentRecord $Parent -ParentSeq $ParentSeq -Created $FnCreated -Name $Name -Size $Size)))
    if (($Flags -band 2) -eq 0) {
        if ($Size -le 64) { $attributes.Add((New-ResidentAttribute -Type 0x80 -Content (New-Object byte[] $Size))) }
        else { $attributes.Add((New-NonResidentAttribute -Type 0x80 -RealSize $Size)) }
    }
    foreach ($stream in $Streams) { $attributes.Add($stream) }
    return New-MftRecord -RecordNumber $RecordNumber -Sequence $Sequence -Flags $Flags -Attributes $attributes.ToArray()
}

function New-ZoneStream {
    param([byte[]]$Text, [string]$Name = "Zone.Identifier")
    return New-ResidentAttribute -Type 0x80 -Name $Name -Content $Text
}

function Get-Utc {
    param([string]$Text)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss.fffffff", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Format-DetailTime {
    param([datetime]$Time)
    return $Time.ToString("yyyy-MM-dd HH:mm:ss.fffffff", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-RowTime {
    param([datetime]$Time)
    return $Time.ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Details of a "File created" row as the parser wrote them before Mark of the Web support
function Get-CreatedDetails {
    param([int]$Record, [int]$Sequence = 1, [long]$Size, [datetime]$Modified, [datetime]$FnCreated, [string]$Timestomp = "")
    $text = "MftRecord=$Record | Seq=$Sequence | Size=$Size | SI.Modified=$(Format-DetailTime $Modified) | " +
        "SI.MftChanged=$(Format-DetailTime $Modified.AddSeconds(1)) | SI.Accessed=$(Format-DetailTime $Modified.AddSeconds(2)) | " +
        "FN.Created=$(Format-DetailTime $FnCreated)"
    if ($Timestomp) { $text += " | Timestomp=$Timestomp" }
    return $text
}

# Record and time fields of a Mark of the Web row (after the stream's own fields)
function Get-ZoneRecordDetails {
    param([int]$Record, [int]$Sequence = 1, [long]$Size, [datetime]$Created, [datetime]$Modified, [datetime]$FnCreated)
    return "MftRecord=$Record | Seq=$Sequence | Size=$Size | SI.Created=$(Format-DetailTime $Created) | " +
        "SI.Modified=$(Format-DetailTime $Modified) | SI.MftChanged=$(Format-DetailTime $Modified.AddSeconds(1)) | " +
        "SI.Accessed=$(Format-DetailTime $Modified.AddSeconds(2)) | FN.Created=$(Format-DetailTime $FnCreated)"
}

$ansi = [System.Text.Encoding]::GetEncoding(28591)   # Latin-1: same as Windows-1252 for these bytes
$eAcute = [string][char]0xE9
$crlf = "`r`n"
$old = Get-Utc "2024-01-01 00:00:00.5000000"

# Times of each file (the -MftDays window is 2026-08-25 12:00 to the collection start 2026-09-01 12:00 UTC)
$times = @{}
foreach ($spec in @(
        @(20, "2026-08-30 08:15:30.1234567", "2026-08-30 08:15:42.7654321"),
        @(21, "2026-08-31 10:00:00.5000000", "2026-08-31 10:00:03.5000000"),
        @(22, "2026-08-29 07:00:00.2500000", "2026-08-29 07:01:00.2500000"),
        @(23, "2026-08-28 12:34:56.7890123", "2026-08-28 12:40:00.0000001"),
        @(24, "2026-08-27 09:09:09.0909090", "2026-08-27 09:10:00.0000002"),
        @(26, "2025-01-10 10:00:00.1000000", "2025-01-10 10:05:00.1000000"),
        @(27, "2026-08-26 14:00:00.3000000", "2026-08-26 14:00:05.3000000"),
        @(28, "2019-05-05 10:00:00.0000000", "2019-05-05 10:00:00.0000000"),
        @(29, "2026-08-31 11:11:11.1111111", "2026-08-31 11:11:12.1111111"),
        @(30, "2026-08-31 12:00:00.5000000", "2026-08-31 12:00:00.5000000"))) {
    $times[$spec[0]] = @{ Created = Get-Utc $spec[1]; Modified = Get-Utc $spec[2] }
}
$payloadFnCreated = Get-Utc "2026-08-30 09:00:00.1234567"

# Zone.Identifier texts
$setupZone = $ansi.GetBytes("[ZoneTransfer]${crlf}ZoneId=3${crlf}ReferrerUrl=https://download.example.com/r${eAcute}sum${eAcute}${crlf}HostUrl=https://download.example.com/setup.exe${crlf}")
$reportZone = [byte[]](@(0xFF, 0xFE) + [System.Text.Encoding]::Unicode.GetBytes(
        "[ZoneTransfer]${crlf}ZoneId=3${crlf}ReferrerUrl=https://mail.example.org/inbox${crlf}HostUrl=https://files.example.org/report.pdf${crlf}" +
        "LastWriterPackageFamilyName=Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe${crlf}AppZoneId=4${crlf}"))
$toolZone = [byte[]](@(0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::UTF8.GetBytes("[ZoneTransfer]${crlf}zoneid=2${crlf}hosturl=https://intranet.example.net/caf${eAcute}/tool.msi${crlf}"))
$oldZone = $ansi.GetBytes("[ZoneTransfer]`nZoneId=3`nHostUrl=https://images.example.com/old.iso`n")
$invoiceZone = $ansi.GetBytes("[ZoneTransfer]${crlf}ZoneId=3${crlf}HostUrl=https://cdn.example.com/invoice.js${crlf}")
$payloadZone = $ansi.GetBytes("[ZoneTransfer]${crlf}ZoneId=3${crlf}HostUrl=http://203.0.113.7/payload.exe${crlf}")
$readmeZone = $ansi.GetBytes("[ZoneTransfer]${crlf}HostUrl=about:internet${crlf}")
$folderZone = $ansi.GetBytes("[ZoneTransfer]${crlf}ZoneId=3${crlf}")

$records = @{}
$records[0] = New-TestFileRecord -RecordNumber 0 -Name '$MFT' -Parent 5 -ParentSeq 5 -Created $old -Modified $old -FnCreated $old -Size 40960
$records[5] = New-TestFileRecord -RecordNumber 5 -Name "." -Parent 5 -ParentSeq 5 -Sequence 5 -Flags 3 -Created $old -Modified $old -FnCreated $old -Size 0
$records[16] = New-TestFileRecord -RecordNumber 16 -Name "Users" -Parent 5 -ParentSeq 5 -Flags 3 -Created $old -Modified $old -FnCreated $old -Size 0
$records[17] = New-TestFileRecord -RecordNumber 17 -Name "alice" -Parent 16 -Flags 3 -Created $old -Modified $old -FnCreated $old -Size 0
$records[18] = New-TestFileRecord -RecordNumber 18 -Name "Downloads" -Parent 17 -Flags 3 -Created $old -Modified $old -FnCreated $old -Size 0
# ANSI text (a byte that is not valid UTF-8) and another named stream that must be ignored
$records[20] = New-TestFileRecord -RecordNumber 20 -Name "setup.exe" -Created $times[20].Created -Modified $times[20].Modified -FnCreated $times[20].Created -Size 123456 `
    -Streams @((New-ZoneStream -Text $setupZone), (New-ZoneStream -Name "SmartScreen" -Text $ansi.GetBytes("Anaheim")))
# UTF-16 with a BOM; the text crosses the sector end at 0x1FE, so the fixups must be undone
$records[21] = New-TestFileRecord -RecordNumber 21 -Name "report.pdf" -Created $times[21].Created -Modified $times[21].Modified -FnCreated $times[21].Created `
    -Streams (, (New-ZoneStream -Text $reportZone))
# Non-resident Zone.Identifier: its text is not in the $MFT
$records[22] = New-TestFileRecord -RecordNumber 22 -Name "big.zip" -Created $times[22].Created -Modified $times[22].Modified -FnCreated $times[22].Created -Size 5000000 `
    -Streams (, (New-NonResidentAttribute -Type 0x80 -Name "Zone.Identifier" -RealSize 2100))
# No Mark of the Web
$records[23] = New-TestFileRecord -RecordNumber 23 -Name "notes.txt" -Created $times[23].Created -Modified $times[23].Modified -FnCreated $times[23].Created
# Zone.Identifier (lower-case name, UTF-8 with a BOM, lower-case keys) in extension record 25
$records[24] = New-TestFileRecord -RecordNumber 24 -Name "tool.msi" -Created $times[24].Created -Modified $times[24].Modified -FnCreated $times[24].Created -Size 48000
$records[25] = New-MftRecord -RecordNumber 25 -BaseReference (24 -bor (1L -shl 48)) -Attributes (, (New-ZoneStream -Name "zone.identifier" -Text $toolZone))
# Created before the -MftDays window; LF line ends
$records[26] = New-TestFileRecord -RecordNumber 26 -Name "old.iso" -Created $times[26].Created -Modified $times[26].Modified -FnCreated $times[26].Created -Size 700000000 `
    -Streams (, (New-ZoneStream -Text $oldZone))
# Deleted (record not in use)
$records[27] = New-TestFileRecord -RecordNumber 27 -Name "invoice.js" -Flags 0 -Sequence 2 -Created $times[27].Created -Modified $times[27].Modified -FnCreated $times[27].Created `
    -Streams (, (New-ZoneStream -Text $invoiceZone))
# Timestomped: SI Created on a whole second, years before FN Created
$records[28] = New-TestFileRecord -RecordNumber 28 -Name "payload.exe" -Created $times[28].Created -Modified $times[28].Modified -FnCreated $payloadFnCreated -Size 64 `
    -Streams (, (New-ZoneStream -Text $payloadZone))
# No ZoneId line
$records[29] = New-TestFileRecord -RecordNumber 29 -Name "readme.txt" -Created $times[29].Created -Modified $times[29].Modified -FnCreated $times[29].Created `
    -Streams (, (New-ZoneStream -Text $readmeZone))
# A folder with a Zone.Identifier stream: no Mark of the Web row
$records[30] = New-TestFileRecord -RecordNumber 30 -Name "extracted" -Flags 3 -Created $times[30].Created -Modified $times[30].Modified -FnCreated $times[30].Created -Size 0 `
    -Streams (, (New-ZoneStream -Text $folderZone))

# --- Load the builder's functions ------------------------------------------
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Write-TestResult -Name "builder parses" -Passed $false -Message "$($parseErrors[0].Message) (line $($parseErrors[0].Extent.StartLineNumber))"
    exit 1
}
$functionAsts = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
        $parent = $_.Parent
        while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
        $null -eq $parent
    })
foreach ($functionAst in $functionAsts) { . ([scriptblock]::Create($functionAst.Extent.Text)) }
# The XML-invalid character filter used by Add-TimelineEntry
$ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        @('$script:xmlInvalidPattern', '$script:xmlInvalidRegex') -contains $node.Left.Extent.Text }, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mft-parser-test-" + [guid]::NewGuid().ToString("N"))
try {
    $collection = Join-Path $workDir "collection"
    New-Item -ItemType Directory -Path (Join-Path $collection "FileSystem") -Force | Out-Null
    $mftBytes = New-Object byte[] (40 * 1024)
    foreach ($number in $records.Keys) { [Array]::Copy([byte[]]$records[$number], 0, $mftBytes, $number * 1024, 1024) }
    [System.IO.File]::WriteAllBytes((Join-Path $collection 'FileSystem\$MFT'), $mftBytes)
    $collectionInfo = '{ "SchemaVersion": 1, "Mode": "Live", "CollectionStartUtc": "2026-09-01T12:00:00Z", "CollectorTimeZoneId": "UTC", "TargetTimeZoneId": "UTC" }'
    [System.IO.File]::WriteAllText((Join-Path $collection "collection_info.json"), $collectionInfo)

    # Script-scope state the builder's functions read
    $script:InputPath = $collection
    $script:collectionRoot = $collection
    $script:collectionInfo = $null
    $script:artifactStats = @{}

    Write-Host "Running Parse-FileSystem ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) on a synthetic `$MFT, -MftDays 7 ..."
    $script:MftDays = 7
    $script:logFile = Join-Path $workDir "builder-days7.log"
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    Parse-FileSystem | Out-Null
    $rows = @($script:timelineEntries)
    $log = Get-Content -LiteralPath $script:logFile -Raw

    function Find-Row {
        param([object[]]$Rows, [string]$Description)
        return @($Rows | Where-Object { $_.Description -ceq $Description })
    }

    function Test-Row {
        param([object[]]$Rows, [string]$Description, [string]$Timestamp, [string]$Details)
        $match = @(Find-Row -Rows $Rows -Description $Description)
        if ($match.Count -ne 1) {
            Write-TestResult -Name "row: $Description" -Passed $false -Message "expected 1 row, found $($match.Count)"
            return
        }
        Assert-Equal -Name "row time: $Description" -Expected $Timestamp -Actual $match[0].Timestamp
        Assert-Equal -Name "row details: $Description" -Expected $Details -Actual $match[0].Details
    }

    Assert-Equal -Name "no parse failures" -Expected $true -Actual ($log -match "Read 40 record\(s\) of 1024 bytes .* 0 parse failure\(s\)")
    Assert-Equal -Name "row count (-MftDays 7)" -Expected 26 -Actual $rows.Count
    $motwRows = @($rows | Where-Object { $_.Description -match 'downloaded file \(Mark of the Web, ' })
    Assert-Equal -Name "Mark of the Web row count" -Expected 8 -Actual $motwRows.Count
    Assert-Equal -Name "all rows Source MFT, EventType FileAccess, Artifact FileSystem, User alice" -Expected 0 -Actual @($rows | Where-Object {
            $_.Source -cne "MFT" -or $_.EventType -cne "FileAccess" -or $_.Artifact -cne "FileSystem" -or $_.User -cne "alice" }).Count

    $dl = '\Users\alice\Downloads'
    $t = $times[20]
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, Internet zone): $dl\setup.exe" -Timestamp (Format-RowTime $t.Created) `
        -Details ("ZoneId=3 | HostUrl=https://download.example.com/setup.exe | ReferrerUrl=https://download.example.com/r${eAcute}sum${eAcute} | " +
            (Get-ZoneRecordDetails -Record 20 -Size 123456 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Test-Row -Rows $rows -Description "File created: $dl\setup.exe" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 20 -Size 123456 -Modified $t.Modified -FnCreated $t.Created) + " | ZoneId=3 | HostUrl=https://download.example.com/setup.exe")
    Test-Row -Rows $rows -Description "File modified: $dl\setup.exe" -Timestamp (Format-RowTime $t.Modified) `
        -Details ("MftRecord=20 | Seq=1 | Size=123456 | SI.Created=$(Format-DetailTime $t.Created) | SI.MftChanged=$(Format-DetailTime $t.Modified.AddSeconds(1)) | " +
            "SI.Accessed=$(Format-DetailTime $t.Modified.AddSeconds(2)) | FN.Created=$(Format-DetailTime $t.Created)")

    $t = $times[21]
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, Internet zone): $dl\report.pdf" -Timestamp (Format-RowTime $t.Created) `
        -Details ("ZoneId=3 | HostUrl=https://files.example.org/report.pdf | ReferrerUrl=https://mail.example.org/inbox | " +
            "LastWriterPackageFamilyName=Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe | AppZoneId=4 | " +
            (Get-ZoneRecordDetails -Record 21 -Size 5 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Test-Row -Rows $rows -Description "File created: $dl\report.pdf" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 21 -Size 5 -Modified $t.Modified -FnCreated $t.Created) + " | ZoneId=3 | HostUrl=https://files.example.org/report.pdf")

    $t = $times[22]
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, zone unknown): $dl\big.zip" -Timestamp (Format-RowTime $t.Created) `
        -Details ("ZoneIdentifier=non-resident (its text is not in the `$MFT) | " +
            (Get-ZoneRecordDetails -Record 22 -Size 5000000 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Test-Row -Rows $rows -Description "File created: $dl\big.zip" -Timestamp (Format-RowTime $t.Created) `
        -Details (Get-CreatedDetails -Record 22 -Size 5000000 -Modified $t.Modified -FnCreated $t.Created)

    $t = $times[23]
    Test-Row -Rows $rows -Description "File created: $dl\notes.txt" -Timestamp (Format-RowTime $t.Created) `
        -Details (Get-CreatedDetails -Record 23 -Size 5 -Modified $t.Modified -FnCreated $t.Created)
    Assert-Equal -Name "no Mark of the Web row for a file without Zone.Identifier" -Expected 0 -Actual @($motwRows | Where-Object { $_.Description -like '*\notes.txt' }).Count

    $t = $times[24]
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, Trusted sites zone): $dl\tool.msi" -Timestamp (Format-RowTime $t.Created) `
        -Details ("ZoneId=2 | HostUrl=https://intranet.example.net/caf${eAcute}/tool.msi | " +
            (Get-ZoneRecordDetails -Record 24 -Size 48000 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Test-Row -Rows $rows -Description "File created: $dl\tool.msi" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 24 -Size 48000 -Modified $t.Modified -FnCreated $t.Created) + " | ZoneId=2 | HostUrl=https://intranet.example.net/caf${eAcute}/tool.msi")

    $t = $times[26]
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, Internet zone): $dl\old.iso" -Timestamp (Format-RowTime $t.Created) `
        -Details ("ZoneId=3 | HostUrl=https://images.example.com/old.iso | " +
            (Get-ZoneRecordDetails -Record 26 -Size 700000000 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Assert-Equal -Name "no File created row before the -MftDays window" -Expected 0 -Actual (Find-Row -Rows $rows -Description "File created: $dl\old.iso").Count

    $t = $times[27]
    Test-Row -Rows $rows -Description "Deleted downloaded file (Mark of the Web, Internet zone): $dl\invoice.js" -Timestamp (Format-RowTime $t.Created) `
        -Details ("ZoneId=3 | HostUrl=https://cdn.example.com/invoice.js | " +
            (Get-ZoneRecordDetails -Record 27 -Sequence 2 -Size 5 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Test-Row -Rows $rows -Description "Deleted file created: $dl\invoice.js" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 27 -Sequence 2 -Size 5 -Modified $t.Modified -FnCreated $t.Created) + " | ZoneId=3 | HostUrl=https://cdn.example.com/invoice.js")

    $t = $times[28]
    $stompReason = "possible timestomping: executable/script whose SI Created is on a whole second and more than 1 s earlier than FN Created"
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, Internet zone): $dl\payload.exe [SI<FN]" -Timestamp (Format-RowTime $payloadFnCreated) `
        -Details ("ZoneId=3 | HostUrl=http://203.0.113.7/payload.exe | " +
            (Get-ZoneRecordDetails -Record 28 -Size 64 -Created $t.Created -Modified $t.Modified -FnCreated $payloadFnCreated) + " | Timestomp=$stompReason")
    Test-Row -Rows $rows -Description "File created: $dl\payload.exe [SI<FN]" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 28 -Size 64 -Modified $t.Modified -FnCreated $payloadFnCreated -Timestomp $stompReason) + " | ZoneId=3 | HostUrl=http://203.0.113.7/payload.exe")

    $t = $times[29]
    Test-Row -Rows $rows -Description "Downloaded file (Mark of the Web, zone unknown): $dl\readme.txt" -Timestamp (Format-RowTime $t.Created) `
        -Details ("HostUrl=about:internet | " + (Get-ZoneRecordDetails -Record 29 -Size 5 -Created $t.Created -Modified $t.Modified -FnCreated $t.Created))
    Test-Row -Rows $rows -Description "File created: $dl\readme.txt" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 29 -Size 5 -Modified $t.Modified -FnCreated $t.Created) + " | HostUrl=about:internet")

    $t = $times[30]
    Test-Row -Rows $rows -Description "Folder created: $dl\extracted" -Timestamp (Format-RowTime $t.Created) `
        -Details ("MftRecord=30 | Seq=1 | SI.Modified=$(Format-DetailTime $t.Modified) | SI.MftChanged=$(Format-DetailTime $t.Modified.AddSeconds(1)) | " +
            "SI.Accessed=$(Format-DetailTime $t.Modified.AddSeconds(2)) | FN.Created=$(Format-DetailTime $t.Created)")

    Assert-Equal -Name "log: stream counts" -Expected $true -Actual ($log -match "Mark of the Web: 9 Zone\.Identifier stream\(s\), 8 resident \(text read from the \`$MFT\), 1 non-resident")
    Assert-Equal -Name "log: rows, zones, deleted, outside the window" -Expected $true -Actual ($log -match
        "Mark of the Web: 8 'Downloaded file' row\(s\) \(5 Internet zone, 1 Trusted sites zone, 2 zone unknown\), 1 of them deleted files; always added, 1 of them dated before the -MftDays window\.")
    Assert-Equal -Name "log: folder skipped" -Expected $true -Actual ($log -match "Mark of the Web: 1 folder\(s\) with a Zone\.Identifier stream skipped")

    # -MftDays 0: the same Mark of the Web rows; old.iso now also has its File created row
    Write-Host "Running Parse-FileSystem again with -MftDays 0 ..."
    $script:MftDays = 0
    $script:logFile = Join-Path $workDir "builder-days0.log"
    $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    Parse-FileSystem | Out-Null
    $allRows = @($script:timelineEntries)
    $allLog = Get-Content -LiteralPath $script:logFile -Raw
    Assert-Equal -Name "row count (-MftDays 0)" -Expected 38 -Actual $allRows.Count
    $motwText = ($motwRows | ForEach-Object { "$($_.Timestamp) $($_.Description) $($_.Details)" }) -join "`n"
    $allMotwText = (@($allRows | Where-Object { $_.Description -match 'downloaded file \(Mark of the Web, ' }) | ForEach-Object { "$($_.Timestamp) $($_.Description) $($_.Details)" }) -join "`n"
    Assert-Equal -Name "Mark of the Web rows do not depend on -MftDays" -Expected $motwText -Actual $allMotwText
    $t = $times[26]
    Test-Row -Rows $allRows -Description "File created: $dl\old.iso" -Timestamp (Format-RowTime $t.Created) `
        -Details ((Get-CreatedDetails -Record 26 -Size 700000000 -Modified $t.Modified -FnCreated $t.Created) + " | ZoneId=3 | HostUrl=https://images.example.com/old.iso")
    Assert-Equal -Name "log (-MftDays 0): none dated before a window" -Expected $true -Actual ($allLog -match "always added, 0 of them dated before the -MftDays window\.")
}
catch {
    Write-TestResult -Name "test run" -Passed $false -Message "$($_.Exception.Message) ($($_.InvocationInfo.PositionMessage))"
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) of $($script:checks) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all $($script:checks) checks passed" -ForegroundColor Green
exit 0
