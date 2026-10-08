# =============================================================
# Mounted devices test
# Checks the USB parser's MountedDevices part without a hive: the value
# decoder (GPT, MBR, device paths, unrecognized values), the instance ID
# rebuilt from a device path (Prod_SD#MMC -> SD/MMC), the MBR volume GUID,
# the salvage of the truncated mounted_devices.txt of older collectors
# ("..." and the ellipsis character), the Description and Details of each
# row (VolumeGuid, SameDataAs, SameDisk, PnPRecord, CollectorDrive), and,
# by running Parse-USB on synthetic collections, which source is used:
# mounted_devices.csv before mounted_devices.txt, the .txt only when the
# CSV has no row, and no rows from the decoded .txt of newer collectors.
# Reading MountedDevices from a collected SYSTEM hive needs reg load
# (admin); tests\Test-RegistryParsers.ps1 covers it.
# The builder's functions are loaded from its AST, so the script itself (and
# its Administrator check) does not run: no admin rights needed.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MountedDevices.ps1
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
        Write-Host "::error file=tests/Test-MountedDevices.ps1::$Name -- $($oneLine.Substring(0, [Math]::Min(300, $oneLine.Length)))"
    }
}

function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    Write-TestResult -Name $Name -Passed ("$Expected" -ceq "$Actual") -Message "expected: $Expected`nactual  : $Actual"
}

# --- Synthetic MountedDevices values (made up: GUIDs, signatures, serials) --
function New-GptValue {
    param([string]$Guid)
    return , [byte[]]([System.Text.Encoding]::ASCII.GetBytes("DMIO:ID:") + (New-Object Guid $Guid).ToByteArray())
}

function New-MbrValue {
    param([uint32]$Signature, [uint64]$Offset)
    return , [byte[]]([BitConverter]::GetBytes($Signature) + [BitConverter]::GetBytes($Offset))
}

function New-DevicePathValue {
    param([string]$Path)
    return , [System.Text.Encoding]::Unicode.GetBytes($Path)
}

$diskClass = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
$fixturePath = "_??_USBSTOR#Disk&Ven_Fixture&Prod_Test_Disk&Rev_1.00#FxSerial0001&0#$diskClass"
$sdPath = "_??_USBSTOR#Disk&Ven_Generic-&Prod_SD#MMC&Rev_1.00#FXSERIAL0002&0#$diskClass"
$cdPath = "\??\SCSI#CdRom&Ven_Fixture&Prod_DVD_Drive#5&1A2B3C4D&0&000000#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
$gptGuid = "{a0000000-0000-4000-8000-000000000001}"
# The volume GUID Windows gives the MBR partition at 1 MiB of disk 0A1B2C3D
$mbrVolume = "{0a1b2c3d-0000-0000-0000-100000000000}"
$volume1 = "\??\Volume{00000000-0000-11f0-8000-000000000101}"
$volume2 = "\??\Volume{00000000-0000-11f0-8000-000000000102}"
$volume3 = "\??\Volume{00000000-0000-11f0-8000-000000000103}"
$ellipsis = [string][char]0x2026

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

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mounted-devices-test-" + [guid]::NewGuid().ToString("N"))
try {
    Write-Host "Testing the MountedDevices decoder ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)) ..."

    # --- Decoder -------------------------------------------------------------
    $gpt = ConvertFrom-MountedDeviceValue -Name "\DosDevices\C:" -Data (New-GptValue $gptGuid)
    Assert-Equal -Name "GPT: kind, partition GUID, length" -Expected "GPT|$gptGuid|24" -Actual "$($gpt.Kind)|$($gpt.PartitionGuid)|$($gpt.DataLength)"
    Assert-Equal -Name "GPT: HexData" -Expected "444D494F3A49443A000000A0000000408000000000000001" -Actual $gpt.HexData
    $mbr = ConvertFrom-MountedDeviceValue -Name "\DosDevices\G:" -Data ([byte[]](0x01, 0x00, 0xED, 0x5E, 0x00, 0x7E, 0, 0, 0, 0, 0, 0))
    Assert-Equal -Name "MBR: signature and offset" -Expected "MBR|5EED0001|32256" -Actual "$($mbr.Kind)|$($mbr.DiskSignature)|$($mbr.PartitionOffset)"
    $mbrBig = ConvertFrom-MountedDeviceValue -Name "\DosDevices\I:" -Data (New-MbrValue 0x0A1B2C3D 5368709120)
    Assert-Equal -Name "MBR: offset above 4 GiB" -Expected "MBR|0A1B2C3D|5368709120" -Actual "$($mbrBig.Kind)|$($mbrBig.DiskSignature)|$($mbrBig.PartitionOffset)"
    $sdNul = ConvertFrom-MountedDeviceValue -Name $volume2 -Data (New-DevicePathValue ($sdPath + [char]0))
    Assert-Equal -Name "device path with a trailing NUL" -Expected "DevicePath|$sdPath" -Actual "$($sdNul.Kind)|$($sdNul.DevicePath)"
    $sd = ConvertFrom-MountedDeviceValue -Name $volume2 -Data (New-DevicePathValue $sdPath)
    Assert-Equal -Name "device path without a trailing NUL" -Expected "DevicePath|$sdPath" -Actual "$($sd.Kind)|$($sd.DevicePath)"
    $cd = ConvertFrom-MountedDeviceValue -Name $volume3 -Data (New-DevicePathValue ($cdPath + [char]0))
    Assert-Equal -Name "\??\ device path" -Expected "DevicePath|$cdPath" -Actual "$($cd.Kind)|$($cd.DevicePath)"
    $other = ConvertFrom-MountedDeviceValue -Name "\DosDevices\X:" -Data ([byte[]](1, 2, 3, 4, 5, 6))
    Assert-Equal -Name "unrecognized value is Other" -Expected "Other|6|010203040506" -Actual "$($other.Kind)|$($other.DataLength)|$($other.HexData)"
    $empty = ConvertFrom-MountedDeviceValue -Name "\DosDevices\Y:" -Data ([byte[]]@())
    Assert-Equal -Name "empty value is Other" -Expected "Other|0|" -Actual "$($empty.Kind)|$($empty.DataLength)|$($empty.HexData)"
    $text = ConvertFrom-MountedDeviceValue -Name "\DosDevices\Z:" -Data "not binary"
    Assert-Equal -Name "text value is Other" -Expected "Other|0|not binary" -Actual "$($text.Kind)|$($text.DataLength)|$($text.HexData)"
    $notPath = ConvertFrom-MountedDeviceValue -Name "\DosDevices\W:" -Data (New-DevicePathValue "C:\folder")
    Assert-Equal -Name "UTF-16 text that is not a device path is Other" -Expected "Other" -Actual $notPath.Kind

    # --- Instance ID, label, MBR volume GUID ---------------------------------
    $instance = ConvertTo-DeviceInstanceId $sdPath
    Assert-Equal -Name "instance ID: Prod_SD#MMC becomes SD/MMC" -Expected "USBSTOR\Disk&Ven_Generic-&Prod_SD/MMC&Rev_1.00\FXSERIAL0002&0" -Actual $instance
    Assert-Equal -Name "label of the rebuilt instance ID" -Expected "Generic- SD/MMC (serial FXSERIAL0002)" -Actual (Get-DeviceInstanceLabel $instance)
    Assert-Equal -Name "instance ID of a \??\ path" -Expected "SCSI\CdRom&Ven_Fixture&Prod_DVD_Drive\5&1A2B3C4D&0&000000" -Actual (ConvertTo-DeviceInstanceId $cdPath)
    Assert-Equal -Name "instance ID of a path with too few fields" -Expected "" -Actual (ConvertTo-DeviceInstanceId "_??_USBSTOR#$diskClass")
    Assert-Equal -Name "MBR volume GUID (1 MiB offset)" -Expected "{0a1b2c3d-0000-0000-0000-100000000000}" -Actual (Get-MbrVolumeGuid -DiskSignature "0A1B2C3D" -PartitionOffset "1048576")
    Assert-Equal -Name "MBR volume GUID (offset above 4 GiB)" -Expected "{0a1b2c3d-0000-0000-0000-004001000000}" -Actual (Get-MbrVolumeGuid -DiskSignature "0A1B2C3D" -PartitionOffset "5368709120")
    Assert-Equal -Name "MBR volume GUID of an unreadable offset" -Expected "" -Actual (Get-MbrVolumeGuid -DiskSignature "0A1B2C3D" -PartitionOffset "")

    # --- Truncated mounted_devices.txt of older collectors -------------------
    $oldLines = @(
        "",
        "\DosDevices\C:                                   : {68, 77, 73, 79...}",
        "\DosDevices\H:                                   : {61, 44, 27, 10...}",
        "\DosDevices\I:                                   : {61, 44, 27, 10$ellipsis}",
        "$volume1 : {95, 0, 63, 0...}",
        "\DosDevices\E:                                   : {92, 0, 63, 0$ellipsis}",
        "\DosDevices\J:                                   : {1, 2}",
        "\DosDevices\K:                                   : {300, 1, 2, 3...}",
        "PSPath                                           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\Mounte",
        "                                                   dDevices",
        "PSChildName                                      : MountedDevices"
    )
    $salvaged = @(ConvertFrom-MountedDevicesText -Lines $oldLines)
    Assert-Equal -Name "salvage: values read (300 is not a byte)" -Expected "\DosDevices\C:,\DosDevices\H:,\DosDevices\I:,$volume1,\DosDevices\E:,\DosDevices\J:" -Actual (($salvaged | ForEach-Object { $_.Name }) -join ",")
    Assert-Equal -Name "salvage: kinds from the first 4 bytes" -Expected "GPT,MBR,MBR,DevicePath,DevicePath,Other" -Actual (($salvaged | ForEach-Object { $_.Kind }) -join ",")
    Assert-Equal -Name "salvage: MBR disk signature from the first 4 bytes" -Expected "0A1B2C3D,0A1B2C3D" -Actual (($salvaged | Where-Object { $_.Kind -eq "MBR" } | ForEach-Object { $_.DiskSignature }) -join ",")
    Assert-Equal -Name "salvage: cut-off values are Truncated, a complete one is not" -Expected "True,True,True,True,True,False" -Actual (($salvaged | ForEach-Object { $_.Truncated }) -join ",")
    Assert-Equal -Name "salvage: HexData of a cut-off value" -Expected "3D2C1B0A..." -Actual $salvaged[1].HexData
    Assert-Equal -Name "salvage: a complete short value is decoded" -Expected "2|0102" -Actual "$($salvaged[5].DataLength)|$($salvaged[5].HexData)"
    $newLines = @("", "Name            : \DosDevices\C:", "Kind            : GPT", "PartitionGuid   : $gptGuid", "DataLength      : 24", "")
    Assert-Equal -Name "salvage: the decoded .txt of newer collectors gives no values" -Expected 0 -Actual @(ConvertFrom-MountedDevicesText -Lines $newLines).Count

    $salvageEntries = @(ConvertTo-MountedDeviceEntries -Rows $salvaged)
    Assert-Equal -Name "salvage row: GPT" -Expected "Drive letter C: -> GPT partition (value cut off)" -Actual $salvageEntries[0].Description
    Assert-Equal -Name "salvage row: MBR" -Expected "Drive letter H: -> MBR disk 0A1B2C3D (value cut off)" -Actual $salvageEntries[1].Description
    Assert-Equal -Name "salvage row: MBR details (same disk, no SameDataAs)" -Expected "Kind=MBR | DiskSignature=0A1B2C3D | HexData=3D2C1B0A... | SameDisk=\DosDevices\I: | Truncated=yes (only the first 4 bytes are in mounted_devices.txt; the kind is taken from them)" -Actual $salvageEntries[1].Details
    Assert-Equal -Name "salvage row: device path" -Expected "Volume {00000000-0000-11f0-8000-000000000101} -> device path (value cut off)" -Actual $salvageEntries[3].Description

    # --- Rows: Description and Details ---------------------------------------
    $rows = @(
        (ConvertFrom-MountedDeviceValue -Name "\DosDevices\C:" -Data (New-GptValue $gptGuid)),
        (ConvertFrom-MountedDeviceValue -Name "\??\Volume$gptGuid" -Data (New-GptValue $gptGuid)),
        (ConvertFrom-MountedDeviceValue -Name "\DosDevices\H:" -Data (New-MbrValue 0x0A1B2C3D 1048576)),
        (ConvertFrom-MountedDeviceValue -Name "\??\Volume$mbrVolume" -Data (New-MbrValue 0x0A1B2C3D 1048576)),
        (ConvertFrom-MountedDeviceValue -Name "\DosDevices\I:" -Data (New-MbrValue 0x0A1B2C3D 5368709120)),
        (ConvertFrom-MountedDeviceValue -Name $volume1 -Data (New-DevicePathValue ($fixturePath + [char]0))),
        (ConvertFrom-MountedDeviceValue -Name "\DosDevices\E:" -Data (New-DevicePathValue ($fixturePath + [char]0))),
        (ConvertFrom-MountedDeviceValue -Name $volume2 -Data (New-DevicePathValue ($sdPath + [char]0))),
        (ConvertFrom-MountedDeviceValue -Name $volume3 -Data (New-DevicePathValue ($cdPath + [char]0))),
        (ConvertFrom-MountedDeviceValue -Name "\DosDevices\X:" -Data ([byte[]](1, 2, 3, 4, 5, 6))),
        (ConvertFrom-MountedDeviceValue -Name "\DosDevices\Z:" -Data "not binary")
    )
    foreach ($row in $rows) { $row | Add-Member -NotePropertyName KeyLastWriteUtc -NotePropertyValue "2025-06-30T11:58:00.1234567Z" }
    # usb_storage_devices.csv lists the fixture disk (serial in upper case)
    $serials = @{ "FXSERIAL0001" = "USBSTOR\DISK&VEN_FIXTURE&PROD_TEST_DISK&REV_1.00\FXSERIAL0001&0" }
    $entries = @(ConvertTo-MountedDeviceEntries -Rows $rows -StorageSerials $serials -CollectorDrive "E:")
    $expected = @(
        @("Drive letter C: -> GPT partition $gptGuid",
            "Kind=GPT | PartitionGuid=$gptGuid | VolumeGuid=$gptGuid | SameDataAs=\??\Volume$gptGuid | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Volume $gptGuid -> GPT partition $gptGuid",
            "Kind=GPT | PartitionGuid=$gptGuid | VolumeGuid=$gptGuid | SameDataAs=\DosDevices\C: | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Drive letter H: -> MBR disk 0A1B2C3D, partition at offset 1048576",
            "Kind=MBR | DiskSignature=0A1B2C3D | PartitionOffset=1048576 | VolumeGuid=$mbrVolume | SameDataAs=\??\Volume$mbrVolume | SameDisk=\DosDevices\I: | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Volume $mbrVolume -> MBR disk 0A1B2C3D, partition at offset 1048576",
            "Kind=MBR | DiskSignature=0A1B2C3D | PartitionOffset=1048576 | VolumeGuid=$mbrVolume | SameDataAs=\DosDevices\H: | SameDisk=\DosDevices\I: | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Drive letter I: -> MBR disk 0A1B2C3D, partition at offset 5368709120",
            "Kind=MBR | DiskSignature=0A1B2C3D | PartitionOffset=5368709120 | VolumeGuid={0a1b2c3d-0000-0000-0000-004001000000} | SameDisk=\DosDevices\H:, \??\Volume$mbrVolume | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Volume {00000000-0000-11f0-8000-000000000101} -> USB storage Fixture Test Disk (serial FxSerial0001)",
            "Kind=DevicePath | VolumeGuid={00000000-0000-11f0-8000-000000000101} | InstanceId=USBSTOR\Disk&Ven_Fixture&Prod_Test_Disk&Rev_1.00\FxSerial0001&0 | Serial=FxSerial0001 | DevicePath=$fixturePath | SameDataAs=\DosDevices\E: | KeyLastWriteUtc=2025-06-30 11:58:00 | PnPRecord=in USBSTOR at collection time: USBSTOR\DISK&VEN_FIXTURE&PROD_TEST_DISK&REV_1.00\FXSERIAL0001&0"),
        @("Drive letter E: -> USB storage Fixture Test Disk (serial FxSerial0001)",
            "Kind=DevicePath | VolumeGuid={00000000-0000-11f0-8000-000000000101} | InstanceId=USBSTOR\Disk&Ven_Fixture&Prod_Test_Disk&Rev_1.00\FxSerial0001&0 | Serial=FxSerial0001 | DevicePath=$fixturePath | SameDataAs=$volume1 | KeyLastWriteUtc=2025-06-30 11:58:00 | PnPRecord=in USBSTOR at collection time: USBSTOR\DISK&VEN_FIXTURE&PROD_TEST_DISK&REV_1.00\FXSERIAL0001&0 | CollectorDrive=yes"),
        @("Volume {00000000-0000-11f0-8000-000000000102} -> USB storage Generic- SD/MMC (serial FXSERIAL0002)",
            "Kind=DevicePath | VolumeGuid={00000000-0000-11f0-8000-000000000102} | InstanceId=USBSTOR\Disk&Ven_Generic-&Prod_SD/MMC&Rev_1.00\FXSERIAL0002&0 | Serial=FXSERIAL0002 | DevicePath=$sdPath | KeyLastWriteUtc=2025-06-30 11:58:00 | PnPRecord=not in USBSTOR at collection time"),
        @("Volume {00000000-0000-11f0-8000-000000000103} -> device Fixture DVD Drive (no serial)",
            "Kind=DevicePath | VolumeGuid={00000000-0000-11f0-8000-000000000103} | InstanceId=SCSI\CdRom&Ven_Fixture&Prod_DVD_Drive\5&1A2B3C4D&0&000000 | DevicePath=$cdPath | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Drive letter X: -> unrecognized data (6 bytes)",
            "Kind=Other | HexData=010203040506 | KeyLastWriteUtc=2025-06-30 11:58:00"),
        @("Drive letter Z: -> unrecognized value (not binary)",
            "Kind=Other | HexData=not binary | KeyLastWriteUtc=2025-06-30 11:58:00")
    )
    Assert-Equal -Name "one row per value" -Expected $expected.Count -Actual $entries.Count
    for ($i = 0; $i -lt [Math]::Min($expected.Count, $entries.Count); $i++) {
        Assert-Equal -Name "Description of $($rows[$i].Name)" -Expected $expected[$i][0] -Actual $entries[$i].Description
        Assert-Equal -Name "Details of $($rows[$i].Name)" -Expected $expected[$i][1] -Actual $entries[$i].Details
    }
    $noList = @(ConvertTo-MountedDeviceEntries -Rows $rows)
    Assert-Equal -Name "no PnPRecord and no CollectorDrive without usb_storage_devices.csv and a collector drive" -Expected 0 -Actual @($noList | Where-Object { $_.Details -match 'PnPRecord=|CollectorDrive=' }).Count
    $emptyList = @(ConvertTo-MountedDeviceEntries -Rows $rows -StorageSerials @{})
    Assert-Equal -Name "an empty usb_storage_devices.csv: USB storage not in USBSTOR" -Expected 3 -Actual @($emptyList | Where-Object { $_.Details -match 'PnPRecord=not in USBSTOR at collection time' }).Count

    # --- Parse-USB: which source is used -------------------------------------
    $csvColumns = @("Name", "Kind", "DiskSignature", "PartitionOffset", "PartitionGuid", "DevicePath", "DataLength", "HexData", "KeyLastWriteUtc")
    $csvText = (@($rows[0..3] | Select-Object -Property $csvColumns | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"
    $headerOnly = '"' + ($csvColumns -join '","') + '"' + "`r`n"
    $oldText = ($oldLines -join "`r`n") + "`r`n"
    $newText = ($newLines -join "`r`n") + "`r`n"
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    $utf8 = New-Object System.Text.UTF8Encoding($false)

    # Runs Parse-USB on a new collection with the given USB\ files (name ->
    # @(text, encoding)); returns its rows and log text
    function Invoke-ParseUsb {
        param([string]$Name, [System.Collections.IDictionary]$Files, [string]$Mode = "Live")
        $collection = Join-Path $workDir $Name
        New-Item -ItemType Directory -Path (Join-Path $collection "USB") -Force | Out-Null
        $info = '{ "SchemaVersion": 1, "Mode": "' + $Mode + '", "CollectionStartUtc": "2025-06-30T12:00:00Z", "CollectorTimeZoneId": "UTC", "TargetTimeZoneId": "UTC" }'
        [System.IO.File]::WriteAllText((Join-Path $collection "collection_info.json"), $info)
        [System.IO.File]::WriteAllText((Join-Path $collection "collection_log.txt"), "[2025-06-30 12:00:00] Output directory: c:\TriageOut\TriageCollection_2025-06-30_12-00`r`n")
        foreach ($file in $Files.Keys) { [System.IO.File]::WriteAllText((Join-Path $collection "USB\$file"), $Files[$file][0], $Files[$file][1]) }
        $script:InputPath = $collection
        $script:collectionRoot = $collection
        $script:collectionInfo = $null
        $script:collectionManifest = $null
        $script:shortenedNames = @{}
        $script:artifactStats = @{}
        $script:logFile = Join-Path $workDir "$Name.log"
        $script:timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
        Parse-USB 6>$null | Out-Null
        return [PSCustomObject]@{
            Rows = @($script:timelineEntries | Where-Object { $_.Source -eq "USB-MountedDevices" })
            Log  = [System.IO.File]::ReadAllText($script:logFile)
            Path = $collection
        }
    }

    Write-Host "Running Parse-USB on synthetic collections ..."
    $run = Invoke-ParseUsb -Name "csv" -Files ([ordered]@{ "mounted_devices.csv" = @($csvText, $utf8Bom); "mounted_devices.txt" = @($oldText, $utf8Bom) })
    Assert-Equal -Name "CSV and .txt: the rows come from the CSV" -Expected "4|$(Join-Path $run.Path 'USB\mounted_devices.csv')" -Actual "$($run.Rows.Count)|$(@($run.Rows | ForEach-Object { $_.RawPath } | Select-Object -Unique) -join ',')"
    Assert-Equal -Name "CSV: Snapshot rows at the collection time" -Expected "Snapshot|2025-06-30 12:00:00.000" -Actual "$(@($run.Rows | ForEach-Object { $_.EventType } | Select-Object -Unique) -join ',')|$(@($run.Rows | ForEach-Object { $_.Timestamp } | Select-Object -Unique) -join ',')"
    Assert-Equal -Name "CSV: the C: row is on the collector's output drive (live)" -Expected 1 -Actual @($run.Rows | Where-Object { $_.Description -like "Drive letter C:*" -and $_.Details -like "*CollectorDrive=yes" }).Count
    Assert-Equal -Name "CSV: log line" -Expected $true -Actual ($run.Log.Contains("Parsed 4 mounted device value(s) (2 GPT, 2 MBR, 0 device path) from $(Join-Path $run.Path 'USB\mounted_devices.csv')"))

    $run = Invoke-ParseUsb -Name "image" -Mode "MountedImage" -Files ([ordered]@{ "mounted_devices.csv" = @($csvText, $utf8Bom) })
    Assert-Equal -Name "mounted image: no CollectorDrive (its drive letters are not the collector's)" -Expected "4|0" -Actual "$($run.Rows.Count)|$(@($run.Rows | Where-Object { $_.Details -like '*CollectorDrive=*' }).Count)"

    $run = Invoke-ParseUsb -Name "emptycsv" -Files ([ordered]@{ "mounted_devices.csv" = @($headerOnly, $utf8Bom); "mounted_devices.txt" = @($oldText, $utf8Bom) })
    Assert-Equal -Name "empty CSV: the rows come from the old .txt" -Expected "6|$(Join-Path $run.Path 'USB\mounted_devices.txt')" -Actual "$($run.Rows.Count)|$(@($run.Rows | ForEach-Object { $_.RawPath } | Select-Object -Unique) -join ',')"
    Assert-Equal -Name "old .txt: cut-off values say so" -Expected 5 -Actual @($run.Rows | Where-Object { $_.Description -like "*(value cut off)" }).Count
    Assert-Equal -Name "old .txt: warning" -Expected $true -Actual ($run.Log -match "WARNING:   mounted_devices\.txt is from an older collector: it shows only the first 4 bytes")
    Assert-Equal -Name "old .txt: log line" -Expected $true -Actual ($run.Log.Contains("Parsed 6 mounted device value(s) (1 GPT, 2 MBR, 2 device path, 1 other) from $(Join-Path $run.Path 'USB\mounted_devices.txt')"))

    # PowerShell 7 writes UTF-8 without a byte order mark
    $run = Invoke-ParseUsb -Name "oldtxt-nobom" -Files ([ordered]@{ "mounted_devices.txt" = @($oldText, $utf8) })
    Assert-Equal -Name "old .txt without BOM: the ellipsis character is read" -Expected "6|Drive letter I: -> MBR disk 0A1B2C3D (value cut off)" -Actual "$($run.Rows.Count)|$($run.Rows[2].Description)"

    $run = Invoke-ParseUsb -Name "newtxt" -Files ([ordered]@{ "mounted_devices.txt" = @($newText, $utf8Bom) })
    Assert-Equal -Name "decoded .txt of a newer collector alone: no rows" -Expected "0|False" -Actual "$($run.Rows.Count)|$($run.Log.Contains('Parsed 0 mounted'))"

    $run = Invoke-ParseUsb -Name "none" -Files ([ordered]@{})
    Assert-Equal -Name "no MountedDevices source: no rows, nothing logged about it" -Expected "0|False" -Actual "$($run.Rows.Count)|$($run.Log -match 'mounted|MountedDevices')"
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
