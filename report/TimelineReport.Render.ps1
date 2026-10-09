# =============================================================
# Timeline report renderer (Phase 3)
# Turns the report model (New-ReportModel in TimelineReport.Engine.ps1, or
# report-model.json read back with ConvertFrom-Json) into report.html -- one
# self-contained offline file: embedded CSS, inline SVG charts, no scripts,
# no external resources -- and prints it to report.pdf with Microsoft Edge
# headless. Dot-sourced by timeline-builder.ps1 and the tests.
#
#   Export-ReportHtml   -Model <model> -Path <report.html> [-PaperSize Auto|Letter|A4] [-NoFileHashes]
#   ConvertTo-ReportPdf -HtmlPath <report.html> -PdfPath <report.pdf> [-EdgePath <msedge.exe>] [-TimeoutSeconds 180]
#
# Every model value is untrusted (it comes from the examined machine): it is
# HTML-escaped, and the page carries a Content-Security-Policy that allows no
# scripts or external loads. The output is ASCII (other characters become
# numeric entities) with CRLF line endings and no BOM. Dates may be
# [datetime], ISO 8601 text, the timeline's "yyyy-MM-dd HH:mm:ss.fff" text or
# "/Date(ms)/"; all are shown in UTC. Helper names contain "ReportHtml" or
# "ReportPdf" so they do not collide with the engine's.
# =============================================================

$script:ReportHtmlInvariant = [System.Globalization.CultureInfo]::InvariantCulture
# Characters that need escaping: anything but tab, line breaks and printable
# ASCII other than & " ' < > (markup, quotes, control and non-ASCII)
$script:ReportHtmlSpecialRegex = New-Object System.Text.RegularExpressions.Regex('[^\t\n\r\x20\x21\x23-\x25\x28-\x3B\x3D\x3F-\x7E]')
$script:ReportHtmlControlRegex = New-Object System.Text.RegularExpressions.Regex('[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')
# A surrogate pair first, so it becomes one code point entity
$script:ReportHtmlNonAsciiRegex = New-Object System.Text.RegularExpressions.Regex('[\uD800-\uDBFF][\uDC00-\uDFFF]|[^\x00-\x7F]')
$script:ReportHtmlNonAsciiEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($match)
    $chars = $match.Value
    if ($chars.Length -eq 2) { $codePoint = [char]::ConvertToUtf32($chars[0], $chars[1]) }
    elseif ([char]::IsSurrogate($chars[0])) { $codePoint = 0xFFFD }
    else { $codePoint = [int]$chars[0] }
    return "&#x" + $codePoint.ToString("X") + ";"
}
# Bidirectional-text controls and invisible characters become visible
# markers ("[U+202E]"): a right-to-left override in a file, service or user
# name would otherwise show it spoofed and reverse the report's own text that
# follows it (MITRE ATT&CK T1036.002). Zero-width joiners (U+200C/U+200D) are
# kept: scripts and emoji need them.
$script:ReportHtmlBidiRegex = New-Object System.Text.RegularExpressions.Regex('[' + (-join (@(0x061C, 0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF) | ForEach-Object { [string][char]$_ })) + ']')
$script:ReportHtmlBidiEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
    param($match)
    return "[U+" + ([int]$match.Value[0]).ToString("X4") + "]"
}
$script:ReportHtmlMsDateRegex = New-Object System.Text.RegularExpressions.Regex('^\\?/Date\((-?\d+)(?:[+-]\d{4})?\)\\?/$')
$script:ReportHtmlDateFormats = [string[]]@(
    "yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd",
    "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK", "yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mmK"
)
$script:ReportHtmlDateStyles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
# Evidence rows printed on one finding card (the PDF stays readable); the
# workbook's Findings sheet and findings.csv list up to the rule's maxEvidence
$script:ReportHtmlCardEvidenceRows = 15

# Report sections for the findings categories, in report order
$script:ReportHtmlCategorySections = @(
    @{ Category = "Antivirus"; Id = "antivirus"; Title = "Antivirus verdicts"
        Intro = "What the antivirus software detected, and any sign that it was turned off or told to ignore files. These are usually the most reliable signals, and their times are good places to start looking." },
    @{ Category = "Access"; Id = "access"; Title = "Access"
        Intro = "Who signed in and how: remote desktop, network sign-ins, bursts of failed passwords, new accounts and administrator rights, and remote-access software." },
    @{ Category = "Persistence"; Id = "persistence"; Title = "Persistence"
        Intro = "Ways a program can set itself up to start again automatically: services, scheduled tasks, Run keys and Startup folders, WMI subscriptions and hijacked system settings." },
    @{ Category = "Execution"; Id = "execution"; Title = "Execution"
        Intro = "Evidence that programs or scripts ran: PowerShell, known attacker tools, and programs started from folders that ordinary users can write to." },
    @{ Category = "InitialAccess"; Id = "initial-access"; Title = "Initial access"
        Intro = "How something may have arrived: risky downloads, opened email attachments, and documents with macros enabled." },
    @{ Category = "FileSystem"; Id = "file-system"; Title = "File system"
        Intro = "Changes to files that can hide or reveal activity: altered file times, mass renames, and deleted logs." }
)

# --- Value helpers ---

# A member of a model object (PSCustomObject or dictionary), or $null
function Get-ReportHtmlField {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

# A member that holds a list, as an array (never $null, no $null items)
function Get-ReportHtmlList {
    param([object]$Object, [string]$Name)
    $value = Get-ReportHtmlField -Object $Object -Name $Name
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -ne $value) {
        if ($value -is [string] -or $value -is [System.Collections.IDictionary] -or -not ($value -is [System.Collections.IEnumerable])) {
            $list.Add($value)
        }
        else {
            foreach ($item in $value) { if ($null -ne $item) { $list.Add($item) } }
        }
    }
    return , $list.ToArray()
}

# HTML-escaped text: markup characters and quotes become entities, control
# characters are dropped, bidirectional controls become visible markers
# ("[U+202E]"), other non-ASCII characters become numeric entities.
# -MaxLength cuts long values (" [...]" marks the cut).
function ConvertTo-ReportHtmlText {
    param([object]$Value, [int]$MaxLength = 0)
    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    if ($MaxLength -gt 0 -and $text.Length -gt $MaxLength) {
        $cut = $MaxLength
        if ([char]::IsHighSurrogate($text[$cut - 1])) { $cut-- }
        $text = $text.Substring(0, $cut) + " [...]"
    }
    if (-not $script:ReportHtmlSpecialRegex.IsMatch($text)) { return $text }
    $text = $script:ReportHtmlBidiRegex.Replace($text, $script:ReportHtmlBidiEvaluator)
    $text = $text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;").Replace("'", "&#39;")
    $text = $script:ReportHtmlControlRegex.Replace($text, "")
    return $script:ReportHtmlNonAsciiRegex.Replace($text, $script:ReportHtmlNonAsciiEvaluator)
}

# A CSS string literal ("...") that is safe inside a <style> element
function ConvertTo-ReportHtmlCssString {
    param([string]$Text)
    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append('"')
    foreach ($char in $Text.ToCharArray()) {
        # Compare code points: PowerShell compares characters case-insensitively
        $code = [int]$char
        if (($code -ge 97 -and $code -le 122) -or ($code -ge 65 -and $code -le 90) -or ($code -ge 48 -and $code -le 57) -or $code -eq 46 -or $code -eq 95 -or $code -eq 45) {
            $null = $builder.Append($char)
        }
        else {
            if ([char]::IsSurrogate($char) -or $code -lt 32) { $code = 0xFFFD }
            # Six hex digits plus the terminating space the CSS escape consumes
            $null = $builder.Append('\').Append($code.ToString("X6")).Append(' ')
        }
    }
    $null = $builder.Append('"')
    return $builder.ToString()
}

# A UTC [datetime] from a model value, or $null
function ConvertTo-ReportHtmlUtc {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    # Windows PowerShell's ConvertTo-Json writes a [datetime] as {value, DateTime}
    if (-not ($Value -is [string]) -and $null -ne (Get-ReportHtmlField -Object $Value -Name "value")) {
        return ConvertTo-ReportHtmlUtc -Value (Get-ReportHtmlField -Object $Value -Name "value")
    }
    $text = ([string]$Value).Trim()
    if ($text.Length -eq 0) { return $null }
    $match = $script:ReportHtmlMsDateRegex.Match($text)
    if ($match.Success) { return [System.DateTimeOffset]::FromUnixTimeMilliseconds([long]$match.Groups[1].Value).UtcDateTime }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParseExact($text, $script:ReportHtmlDateFormats, $script:ReportHtmlInvariant, $script:ReportHtmlDateStyles, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParse($text, $script:ReportHtmlInvariant, $script:ReportHtmlDateStyles, [ref]$parsed)) { return $parsed }
    return $null
}

# A calendar day (yyyy-MM-dd) from a model day value; a [datetime] keeps its
# own date (no time zone shift)
function ConvertTo-ReportHtmlDay {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString("yyyy-MM-dd", $script:ReportHtmlInvariant) }
    $text = ([string]$Value).Trim()
    if ($text -match '^\d{4}-\d{2}-\d{2}') { return $text.Substring(0, 10) }
    $utc = ConvertTo-ReportHtmlUtc -Value $Value
    if ($utc) { return $utc.ToString("yyyy-MM-dd", $script:ReportHtmlInvariant) }
    return $null
}

# Escaped time text: the parsed UTC time in -Format, or the raw value
function Format-ReportHtmlTime {
    param([object]$Value, [string]$Format = "yyyy-MM-dd HH:mm:ss")
    $utc = ConvertTo-ReportHtmlUtc -Value $Value
    if ($utc) { return $utc.ToString($Format, $script:ReportHtmlInvariant) }
    return ConvertTo-ReportHtmlText -Value $Value
}

# A number from a model value (0 when missing or not numeric)
function ConvertTo-ReportHtmlNumber {
    param([object]$Value)
    if ($null -eq $Value) { return [double]0 }
    $number = [double]0
    if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, $script:ReportHtmlInvariant, [ref]$number)) { return $number }
    return [double]0
}

# Escaped number text with thousands separators ("1,234")
function Format-ReportHtmlNumber {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $number = [double]0
    if (-not [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, $script:ReportHtmlInvariant, [ref]$number)) {
        return ConvertTo-ReportHtmlText -Value $Value
    }
    if ([Math]::Abs($number - [Math]::Round($number)) -lt 0.000001) { return ([long][Math]::Round($number)).ToString("N0", $script:ReportHtmlInvariant) }
    return $number.ToString("N1", $script:ReportHtmlInvariant)
}

# Short axis number ("950", "12k", "1.5M")
function Format-ReportHtmlCompactNumber {
    param([double]$Value)
    if ($Value -ge 1000000) { return ($Value / 1000000).ToString("0.#", $script:ReportHtmlInvariant) + "M" }
    if ($Value -ge 10000) { return ($Value / 1000).ToString("0", $script:ReportHtmlInvariant) + "k" }
    if ($Value -ge 1000) { return ($Value / 1000).ToString("0.#", $script:ReportHtmlInvariant) + "k" }
    return $Value.ToString("0", $script:ReportHtmlInvariant)
}

# "1 row" / "3 rows"
function Format-ReportHtmlCount {
    param([object]$Value, [string]$Singular, [string]$Plural)
    $number = ConvertTo-ReportHtmlNumber -Value $Value
    if ($number -eq 1) { return "1 " + $Singular }
    return (Format-ReportHtmlNumber -Value $number) + " " + $Plural
}

# "UTC-07:00"
function Format-ReportHtmlOffset {
    param([TimeSpan]$Offset)
    $sign = "+"
    if ($Offset -lt [TimeSpan]::Zero) { $sign = "-" }
    $abs = $Offset.Duration()
    return "UTC" + $sign + $abs.Hours.ToString("00") + ":" + $abs.Minutes.ToString("00")
}

# The machine's time zone, or $null when the id is unknown here
function Get-ReportHtmlTimeZone {
    param([string]$Id)
    if (-not $Id) { return $null }
    try { return [System.TimeZoneInfo]::FindSystemTimeZoneById($Id) }
    catch { Write-Verbose "Unknown time zone id: $Id"; return $null }
}

# Escaped "yyyy-MM-dd HH:mm UTC" plus the machine's local clock time
function Format-ReportHtmlUtcAndLocal {
    param([object]$Value, [object]$TimeZone)
    $utc = ConvertTo-ReportHtmlUtc -Value $Value
    if (-not $utc) { return ConvertTo-ReportHtmlText -Value $Value }
    $text = $utc.ToString("yyyy-MM-dd HH:mm", $script:ReportHtmlInvariant) + " UTC"
    if ($TimeZone) {
        $local = [System.TimeZoneInfo]::ConvertTimeFromUtc($utc, $TimeZone)
        $text += ' <span class="muted">(' + $local.ToString("yyyy-MM-dd HH:mm", $script:ReportHtmlInvariant) + " machine time, " +
            (Format-ReportHtmlOffset -Offset $TimeZone.GetUtcOffset($utc)) + ")</span>"
    }
    return $text
}

# Lower-case severity key for CSS classes: high, medium, info or other
function Get-ReportHtmlSeverityKey {
    param([object]$Severity)
    switch -Regex ([string]$Severity) {
        '^\s*high\s*$' { return "high" }
        '^\s*medium\s*$' { return "medium" }
        '^\s*info' { return "info" }
        default { return "other" }
    }
}

# Severity label: text plus color, never color alone
function New-ReportHtmlSeverityBadge {
    param([object]$Severity)
    $key = Get-ReportHtmlSeverityKey -Severity $Severity
    $label = switch ($key) { "high" { "High" } "medium" { "Medium" } "info" { "Info" } default { ConvertTo-ReportHtmlText -Value $Severity } }
    if (-not $label) { $label = "Unrated" }
    return '<span class="sev sev-' + $key + '">' + $label + '</span>'
}

# Anchor id for a finding (only letters, digits, _ and -)
function ConvertTo-ReportHtmlAnchor {
    param([object]$FindingId)
    return "finding-" + [regex]::Replace([string]$FindingId, '[^A-Za-z0-9_-]', '_')
}

# The workbook's relative link ("./timeline.xlsx", escaped): a bare file name,
# percent-encoded, so it can never be another scheme or folder
function Get-ReportHtmlWorkbookHref {
    param([string]$FileName)
    $name = [System.IO.Path]::GetFileName($FileName)
    return ConvertTo-ReportHtmlText -Value ("./" + [System.Uri]::EscapeDataString($name))
}

# SHA-256 of a file next to the report (or at a full path), or $null
function Get-ReportHtmlFileHash {
    param([string]$Directory, [string]$File)
    if (-not $File) { return $null }
    $candidates = @()
    if ([System.IO.Path]::IsPathRooted($File)) { $candidates += $File }
    $candidates += (Join-Path $Directory ([System.IO.Path]::GetFileName($File)))
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            try { return (Get-FileHash -LiteralPath $candidate -Algorithm SHA256 -ErrorAction Stop).Hash }
            catch { Write-Verbose "Could not hash ${candidate}: $($_.Exception.Message)" }
        }
    }
    return $null
}

# --- Model context ---

# Everything the section writers need, read once from the model
function New-ReportHtmlContext {
    param([object]$Model, [string]$OutputDirectory, [bool]$HashFiles)
    $collection = Get-ReportHtmlField -Object $Model -Name "Collection"
    $findings = Get-ReportHtmlList -Object $Model -Name "Findings"
    $infoFindings = Get-ReportHtmlList -Object $Model -Name "InfoFindings"
    $byId = @{}
    foreach ($finding in @($findings + $infoFindings)) {
        $id = [string](Get-ReportHtmlField -Object $finding -Name "Id")
        if ($id -and -not $byId.ContainsKey($id)) { $byId[$id] = $finding }
    }
    $workbook = Get-ReportHtmlField -Object $Model -Name "Workbook"
    $workbookName = [string](Get-ReportHtmlField -Object $workbook -Name "FileName")
    $workbookAvailable = [bool](Get-ReportHtmlField -Object $workbook -Name "Available") -and [bool]$workbookName
    $timelineSheet = [string](Get-ReportHtmlField -Object $workbook -Name "TimelineSheet")
    if (-not $timelineSheet) { $timelineSheet = "Timeline" }
    $findingsSheet = [string](Get-ReportHtmlField -Object $workbook -Name "FindingsSheet")
    if (-not $findingsSheet) { $findingsSheet = "Findings" }
    $hostName = [string](Get-ReportHtmlField -Object $collection -Name "ComputerName")
    $timeZoneId = [string](Get-ReportHtmlField -Object $collection -Name "TargetTimeZoneId")
    $rules = Get-ReportHtmlList -Object $Model -Name "Rules"
    # Without the workbook, row numbers are those of timeline.csv (header = 1)
    $timelineCsv = [System.IO.Path]::GetFileName([string](Get-ReportHtmlField -Object (Get-ReportHtmlField -Object $Model -Name "Files") -Name "TimelineCsv"))
    if (-not $timelineCsv) { $timelineCsv = "timeline.csv" }

    $counts = Get-ReportHtmlField -Object $Model -Name "Counts"
    $high = @($findings | Where-Object { (Get-ReportHtmlSeverityKey (Get-ReportHtmlField $_ "Severity")) -eq "high" }).Count
    $medium = @($findings | Where-Object { (Get-ReportHtmlSeverityKey (Get-ReportHtmlField $_ "Severity")) -eq "medium" }).Count
    $info = $infoFindings.Count
    if ($null -ne (Get-ReportHtmlField $counts "High")) { $high = [int](ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $counts "High")) }
    if ($null -ne (Get-ReportHtmlField $counts "Medium")) { $medium = [int](ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $counts "Medium")) }
    if ($null -ne (Get-ReportHtmlField $counts "Info")) { $info = [int](ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $counts "Info")) }

    return @{
        Model              = $Model
        Collection         = $collection
        Coverage           = Get-ReportHtmlField -Object $Model -Name "Coverage"
        Activity           = Get-ReportHtmlField -Object $Model -Name "Activity"
        Findings           = $findings
        InfoFindings       = $infoFindings
        FindingById        = $byId
        Rules              = $rules
        High               = $high
        Medium             = $medium
        Info               = $info
        HostName           = $hostName
        TimeZoneId         = $timeZoneId
        TimeZone           = Get-ReportHtmlTimeZone -Id $timeZoneId
        CollectionStartUtc = ConvertTo-ReportHtmlUtc -Value (Get-ReportHtmlField -Object $collection -Name "CollectionStartUtc")
        WorkbookAvailable  = $workbookAvailable
        WorkbookName       = [System.IO.Path]::GetFileName($workbookName)
        WorkbookHref       = $(if ($workbookAvailable) { Get-ReportHtmlWorkbookHref -FileName $workbookName } else { "" })
        TimelineCsv        = $timelineCsv
        RowHeading         = $(if ($workbookAvailable) { "Excel row" } else { "CSV row" })
        TimelineSheet      = $timelineSheet
        FindingsSheet      = $findingsSheet
        OutputDirectory    = $OutputDirectory
        HashFiles          = $HashFiles
        Sections           = (New-Object System.Collections.Generic.List[object])
    }
}

# Findings of one category (case-insensitive); "Other" also takes unknown ones
function Get-ReportHtmlCategoryFindings {
    param([object[]]$Findings, [string]$Category)
    $known = @("Integrity", "Antivirus", "Access", "Persistence", "Execution", "InitialAccess", "FileSystem")
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $Findings) {
        $value = ([string](Get-ReportHtmlField -Object $finding -Name "Category")).Trim()
        $isMatch = $value -eq $Category
        if (-not $isMatch -and $Category -eq "Other") { $isMatch = $known -notcontains $value }
        if ($isMatch) { $result.Add($finding) }
    }
    return , $result.ToArray()
}

# Row numbers of a finding's evidence rows, in evidence order
function Get-ReportHtmlRowNumbers {
    param([object]$Finding)
    $numbers = New-Object System.Collections.Generic.List[string]
    foreach ($row in (Get-ReportHtmlList -Object $Finding -Name "Evidence")) {
        $number = Get-ReportHtmlField -Object $row -Name "RowNumber"
        if ($null -ne $number -and "$number" -ne "") { $numbers.Add([string]([long](ConvertTo-ReportHtmlNumber $number))) }
    }
    return , $numbers.ToArray()
}

# How many timeline rows a finding has in all (its rule rows plus the rows
# that raised its severity): RowNumbers when the model has them, else Count,
# never fewer than its evidence rows
function Get-ReportHtmlRowTotal {
    param([object]$Finding)
    $total = (Get-ReportHtmlList $Finding "RowNumbers").Count
    if ($total -eq 0) { $total = [long](ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $Finding "Count")) }
    $evidence = (Get-ReportHtmlList $Finding "Evidence").Count
    if ($evidence -gt $total) { $total = $evidence }
    return $total
}

# Row number list text ("12, 40, 41 +299 more"): the first evidence rows,
# then how many more rows the finding has in all (not only evidence rows)
function Format-ReportHtmlRowList {
    param([object]$Finding, [int]$Max = 6)
    $numbers = Get-ReportHtmlRowNumbers -Finding $Finding
    if ($numbers.Count -eq 0) { return "" }
    $shown = @($numbers | Select-Object -First $Max)
    $text = $shown -join ", "
    $total = Get-ReportHtmlRowTotal -Finding $Finding
    if ($total -gt $shown.Count) { $text += " +" + ($total - $shown.Count).ToString("N0", $script:ReportHtmlInvariant) + " more" }
    return $text
}

# Leads whose times are activity times: a finding of a rule with
# "activityTime": false (file times, which can be old or forged) is left out
function Get-ReportHtmlActivityFindings {
    param([object[]]$Findings)
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $Findings) {
        if ((Get-ReportHtmlField $finding "ActivityTime") -eq $false) { continue }
        $result.Add($finding)
    }
    return , $result.ToArray()
}

# Earliest and latest time over a set of findings (FirstSeenUtc / LastSeenUtc)
function Get-ReportHtmlFindingSpan {
    param([object[]]$Findings)
    $first = $null
    $last = $null
    foreach ($finding in $Findings) {
        $f = ConvertTo-ReportHtmlUtc (Get-ReportHtmlField $finding "FirstSeenUtc")
        $l = ConvertTo-ReportHtmlUtc (Get-ReportHtmlField $finding "LastSeenUtc")
        if (-not $l) { $l = $f }
        if ($f -and (-not $first -or $f -lt $first)) { $first = $f }
        if ($l -and (-not $last -or $l -gt $last)) { $last = $l }
    }
    return @{ First = $first; Last = $last }
}

# Highest severity of the leads per day (yyyy-MM-dd), per month (yyyy-MM) and
# per UTC hour (0-23), from the evidence rows and first/last seen times
function Get-ReportHtmlLeadMarkers {
    param([object[]]$Findings)
    $days = @{}
    $months = @{}
    $hours = @{}
    foreach ($finding in $Findings) {
        $key = Get-ReportHtmlSeverityKey (Get-ReportHtmlField $finding "Severity")
        if ($key -ne "high" -and $key -ne "medium") { continue }
        $times = New-Object System.Collections.Generic.List[datetime]
        foreach ($row in (Get-ReportHtmlList $finding "Evidence")) {
            $utc = ConvertTo-ReportHtmlUtc (Get-ReportHtmlField $row "Timestamp")
            if ($utc) { $times.Add($utc) }
        }
        foreach ($name in @("FirstSeenUtc", "LastSeenUtc")) {
            $utc = ConvertTo-ReportHtmlUtc (Get-ReportHtmlField $finding $name)
            if ($utc) { $times.Add($utc) }
        }
        foreach ($utc in $times) {
            $day = $utc.ToString("yyyy-MM-dd", $script:ReportHtmlInvariant)
            $month = $utc.ToString("yyyy-MM", $script:ReportHtmlInvariant)
            if ($days[$day] -ne "high") { $days[$day] = $key }
            if ($months[$month] -ne "high") { $months[$month] = $key }
            if ($hours[$utc.Hour] -ne "high") { $hours[$utc.Hour] = $key }
        }
    }
    return @{ Days = $days; Months = $months; Hours = $hours }
}

# --- Charts ---

# Inline SVG bar chart. Each bar: @{ Value; Tip (plain text); Axis (plain
# text or ""); Marker ("high", "medium" or "") }. A log scale is used when one
# bar dwarfs the typical one, and the caption says so.
function New-ReportHtmlBarChart {
    param([object[]]$Bars, [string]$Label, [string]$AxisTitle)
    $width = 680
    $height = 196
    $left = 48
    $right = 8
    $top = 10
    $baseY = 150
    $plotWidth = $width - $left - $right
    $plotHeight = $baseY - $top
    $count = [Math]::Max(1, $Bars.Count)
    $values = @($Bars | ForEach-Object { [double]$_.Value })
    $max = 0.0
    foreach ($v in $values) { if ($v -gt $max) { $max = $v } }
    $nonZero = @($values | Where-Object { $_ -gt 0 } | Sort-Object)
    $median = 0.0
    if ($nonZero.Count -gt 0) { $median = [double]$nonZero[[int][Math]::Floor(($nonZero.Count - 1) / 2)] }
    $useLog = ($max -ge 100 -and $median -gt 0 -and ($max / $median) -ge 50)

    $ticks = New-Object System.Collections.Generic.List[double]
    if ($useLog) {
        $exponent = [Math]::Max(1, [int][Math]::Ceiling([Math]::Log10($max)))
        $topValue = [Math]::Pow(10, $exponent)
        for ($e = 1; $e -le $exponent; $e++) { $ticks.Add([Math]::Pow(10, $e)) }
    }
    else {
        $rough = [Math]::Max(1.0, $max / 4)
        $magnitude = [Math]::Pow(10, [Math]::Floor([Math]::Log10($rough)))
        $step = $magnitude
        foreach ($multiple in @(1, 2, 2.5, 5, 10)) { if ($multiple * $magnitude -ge $rough) { $step = $multiple * $magnitude; break } }
        $topValue = [Math]::Max($step, [Math]::Ceiling($max / $step) * $step)
        for ($t = $step; $t -le $topValue + 0.0001; $t += $step) { $ticks.Add($t) }
    }
    $scale = {
        param([double]$v)
        if ($v -le 0) { return 0.0 }
        if ($useLog) { return $plotHeight * [Math]::Log10(1 + $v) / [Math]::Log10(1 + $topValue) }
        return $plotHeight * $v / $topValue
    }
    $inv = $script:ReportHtmlInvariant
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<svg class="chart" viewBox="0 0 ' + $width + ' ' + $height + '" role="img" aria-label="' + (ConvertTo-ReportHtmlText $Label) + '" xmlns="http://www.w3.org/2000/svg">')
    $null = $sb.AppendLine()
    # Gridlines with their values
    $null = $sb.AppendLine('<line class="axis" x1="' + $left + '" y1="' + $baseY + '" x2="' + ($width - $right) + '" y2="' + $baseY + '"/>')
    $null = $sb.AppendLine('<text class="tick" x="' + ($left - 5) + '" y="' + ($baseY + 3) + '" text-anchor="end">0</text>')
    foreach ($tick in $ticks) {
        $y = ($baseY - (& $scale $tick)).ToString("0.#", $inv)
        $null = $sb.AppendLine('<line class="grid" x1="' + $left + '" y1="' + $y + '" x2="' + ($width - $right) + '" y2="' + $y + '"/><text class="tick" x="' + ($left - 5) + '" y="' + $y + '" dy="3" text-anchor="end">' + (Format-ReportHtmlCompactNumber $tick) + '</text>')
    }
    $slot = $plotWidth / $count
    $barWidth = [Math]::Max(1.0, $slot * 0.78)
    for ($i = 0; $i -lt $Bars.Count; $i++) {
        $bar = $Bars[$i]
        $x = $left + $i * $slot + ($slot - $barWidth) / 2
        $h = & $scale ([double]$bar.Value)
        if ($bar.Value -gt 0 -and $h -lt 1) { $h = 1 }
        $null = $sb.Append('<rect class="bar" x="' + $x.ToString("0.##", $inv) + '" y="' + ($baseY - $h).ToString("0.##", $inv) + '" width="' + $barWidth.ToString("0.##", $inv) + '" height="' + $h.ToString("0.##", $inv) + '"><title>' + (ConvertTo-ReportHtmlText $bar.Tip) + '</title></rect>')
        if ($bar.Marker -eq "high" -or $bar.Marker -eq "medium") {
            $cx = $x + $barWidth / 2
            $null = $sb.Append('<polygon class="mark-' + $bar.Marker + '" points="' + ($cx - 4).ToString("0.#", $inv) + ',' + ($baseY + 11) + ' ' + $cx.ToString("0.#", $inv) + ',' + ($baseY + 4) + ' ' + ($cx + 4).ToString("0.#", $inv) + ',' + ($baseY + 11) + '"/>')
        }
        if ($bar.Axis) {
            $null = $sb.Append('<text class="xlabel" x="' + ($x + $barWidth / 2).ToString("0.#", $inv) + '" y="' + ($baseY + 25) + '" text-anchor="middle">' + (ConvertTo-ReportHtmlText $bar.Axis) + '</text>')
        }
        $null = $sb.AppendLine()
    }
    $axisText = $AxisTitle
    if ($useLog) { $axisText += " - logarithmic scale: each gridline is 10 times the one below" }
    $null = $sb.AppendLine('<text class="axistitle" x="' + ($left + $plotWidth / 2).ToString("0", $inv) + '" y="' + ($height - 4) + '" text-anchor="middle">' + (ConvertTo-ReportHtmlText $axisText) + '</text>')
    $null = $sb.Append('</svg>')
    return $sb.ToString()
}

# Legend for the lead markers under the charts
function New-ReportHtmlMarkerLegend {
    param([string]$Unit)
    return '<p class="legend"><svg class="legend-mark" viewBox="0 0 10 8" aria-hidden="true"><polygon class="mark-high" points="0,8 5,0 10,8"/></svg> ' + $Unit + ' with a High lead' +
        ' &nbsp; <svg class="legend-mark" viewBox="0 0 10 8" aria-hidden="true"><polygon class="mark-medium" points="0,8 5,0 10,8"/></svg> ' + $Unit + ' with a Medium lead (and no High)</p>'
}

# --- Page parts ---

# Print-first stylesheet. Severity colors (shared with the workbook's
# Findings sheet): the bars use the timeline's Excel palette (SecurityAlert
# FF4D4D, Execution FFC000, Installation B4C6E7); the labels use Excel's
# "Bad" style (FFC7CE / 9C0006), a "Neutral"-like amber (FFEB9C / 7A4500) and
# a light blue (DDEBF7 / 1F4E79), always with the severity as text.
$script:ReportHtmlCss = @'
:root {
  --ink: #1F2933; --muted: #52606D; --line: #D5DCE3; --panel: #F4F6F8; --accent: #1F4E79;
  --high-bg: #FFC7CE; --high-ink: #9C0006; --high-bar: #FF4D4D;
  --medium-bg: #FFEB9C; --medium-ink: #7A4500; --medium-bar: #FFC000;
  --info-bg: #DDEBF7; --info-ink: #1F4E79; --info-bar: #B4C6E7;
  --other-bg: #E4E7EB; --other-ink: #323F4B; --other-bar: #BFC5CC;
}
@page {
  __PAGE_SIZE__
  margin: 16mm 14mm 17mm 14mm;
  @bottom-left { content: __FOOTER_TEXT__; font: 7.5pt "Segoe UI", Arial, sans-serif; color: #52606D; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 7.5pt "Segoe UI", Arial, sans-serif; color: #52606D; }
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif; font-size: 10pt; line-height: 1.42; color: var(--ink); background: #E9EDF1; }
/* A long unbroken value (a path, a hash, a name) wraps instead of widening
   the page: a printed page wider than the paper makes Chromium shrink every
   page of the PDF */
h1, h2, h3, h4, p, li, td, th, div, span, a { overflow-wrap: anywhere; }
main { max-width: 940px; margin: 0 auto; padding: 0 16px 40px; }
section.page { background: #fff; margin: 18px 0; padding: 26px 32px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
h1, h2, h3, h4 { color: #102A43; line-height: 1.2; margin: 0; break-after: avoid; page-break-after: avoid; }
h1 { font-size: 21pt; font-weight: 600; }
h2 { font-size: 14.5pt; font-weight: 600; padding-bottom: 4px; border-bottom: 2px solid var(--accent); margin-bottom: 8px; }
h3 { font-size: 11.5pt; font-weight: 600; }
h4 { font-size: 10pt; font-weight: 600; margin: 12px 0 4px; }
p { margin: 5px 0; }
a { color: var(--accent); }
.muted { color: var(--muted); }
b .muted { font-weight: 400; }
.small { font-size: 8.5pt; }
.mono { font-family: Consolas, "Cascadia Mono", "Courier New", monospace; font-size: 8pt; }
.nowrap { white-space: nowrap; }
.intro { color: var(--muted); margin: 0 0 10px; break-after: avoid; page-break-after: avoid; }
.secnum { color: var(--muted); font-weight: 400; margin-right: 6px; }
nav.toc { max-width: 940px; margin: 0 auto; padding: 14px 16px 0; font-size: 9pt; }
nav.toc a { margin-right: 12px; white-space: nowrap; }
.sev { display: inline-block; padding: 0 6px; border-radius: 3px; font-size: 7.5pt; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; vertical-align: 1px; border: 1px solid transparent; line-height: 1.5; }
.sev-high { background: var(--high-bg); color: var(--high-ink); border-color: #F19CA6; }
.sev-medium { background: var(--medium-bg); color: var(--medium-ink); border-color: #E8C65A; }
.sev-info { background: var(--info-bg); color: var(--info-ink); border-color: #9DB9DA; }
.sev-other { background: var(--other-bg); color: var(--other-ink); border-color: #BFC5CC; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 10px; font-size: 8.5pt; table-layout: fixed; }
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }
th { background: var(--panel); text-align: left; font-weight: 600; color: #243B53; border-bottom: 1px solid #BCCCDC; padding: 3px 5px; vertical-align: bottom; }
td { border-bottom: 1px solid var(--line); padding: 3px 5px; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }
td.num, th.num { text-align: right; }
td.mono { font-size: 7.5pt; }
.facts { table-layout: auto; font-size: 9pt; margin: 2px 0 6px; }
.facts th, .facts td { padding: 2px 5px; }
.facts th { width: 26%; background: none; border-bottom: 1px solid var(--line); color: var(--muted); font-weight: 600; vertical-align: top; }
.report-head { border-bottom: 3px solid var(--accent); padding-bottom: 8px; margin-bottom: 10px; }
.kicker { text-transform: uppercase; letter-spacing: 0.08em; font-size: 8pt; color: var(--accent); font-weight: 700; }
.report-head .sub { color: var(--muted); font-size: 9pt; margin-top: 2px; }
.bottom-line { background: var(--panel); border: 1px solid var(--line); border-radius: 5px; padding: 8px 14px; margin: 8px 0 8px; break-inside: avoid; }
.stats { display: flex; gap: 10px; margin-bottom: 6px; }
.stat { flex: 1; background: #fff; border: 1px solid var(--line); border-left: 6px solid var(--other-bar); border-radius: 4px; padding: 5px 10px; }
.stat .n { font-size: 18pt; font-weight: 600; line-height: 1.1; display: block; }
.stat .l { font-size: 8.5pt; color: var(--muted); }
.stat-high { border-left-color: var(--high-bar); }
.stat-medium { border-left-color: var(--medium-bar); }
.stat-info { border-left-color: var(--info-bar); }
.framing { font-size: 9pt; color: var(--muted); }
ol.top { margin: 3px 0 6px; padding-left: 20px; font-size: 9.5pt; }
ol.top li { margin: 2px 0 4px; break-inside: avoid; page-break-inside: avoid; }
ol.top .t { font-weight: 600; }
.caveats { border: 1px solid #9DB9DA; background: #F3F8FD; border-radius: 5px; padding: 6px 12px 5px; margin-top: 8px; }
.caveats h3 { font-size: 10pt; color: var(--accent); margin-bottom: 2px; }
.caveats ul { margin: 2px 0; padding-left: 14px; font-size: 8pt; line-height: 1.32; columns: 2; column-gap: 22px; }
.caveats li { margin: 0 0 2px; break-inside: avoid; page-break-inside: avoid; }
.note { border-left: 3px solid var(--accent); background: var(--panel); padding: 5px 10px; margin: 8px 0; font-size: 9pt; }
.incomplete { border-left: 4px solid var(--high-bar); background: #FFF1F2; padding: 5px 10px; margin: 8px 0; font-size: 9pt; break-inside: avoid; }
.empty { color: var(--muted); font-style: italic; }
article.finding { border-left: 5px solid var(--other-bar); padding: 2px 0 2px 12px; margin: 14px 0 18px; }
article.f-high { border-left-color: var(--high-bar); }
article.f-medium { border-left-color: var(--medium-bar); }
article.f-info { border-left-color: var(--info-bar); }
.finding-head { break-inside: avoid; page-break-inside: avoid; }
.finding-head h3 .fid { color: var(--muted); font-weight: 600; margin-right: 4px; }
.finding-meta { font-size: 8.5pt; color: var(--muted); margin: 2px 0 4px; }
.why { font-size: 10pt; margin: 4px 0; white-space: pre-line; }
table.fields { font-size: 9pt; margin: 5px 0 6px; }
table.fields col.k { width: 10.5em; }
table.fields th { background: none; border: 0; color: var(--muted); font-weight: 600; vertical-align: top; padding: 2px 10px 2px 0; }
table.fields td { border: 0; padding: 2px 0; white-space: pre-line; }
.flag { display: inline-block; font-size: 8pt; padding: 1px 6px; border-radius: 3px; background: var(--panel); border: 1px solid var(--line); margin: 2px 6px 2px 0; }
.flag-escalated { background: var(--high-bg); color: var(--high-ink); border-color: #F19CA6; }
table.evidence col.c-row { width: 8%; }
table.evidence col.c-time { width: 18%; }
table.evidence col.c-src { width: 15%; }
table.evidence col.c-desc { width: 49%; }
table.evidence col.c-user { width: 10%; }
.evidence .src { font-size: 8pt; }
.evidence .et { color: var(--muted); font-size: 7.5pt; }
.evidence .desc { white-space: pre-line; }
.evidence .details { color: var(--muted); font-size: 7.5pt; white-space: pre-line; margin-top: 1px; }
.excel { font-size: 8.5pt; color: var(--muted); margin-top: 2px; }
.chart { width: 100%; height: auto; display: block; margin: 4px 0 2px; }
.chart .bar { fill: #4F79A8; }
.chart .grid { stroke: #E1E6EB; stroke-width: 1; }
.chart .axis { stroke: #7B8794; stroke-width: 1; }
.chart .tick, .chart .xlabel { font-size: 9px; fill: #52606D; font-family: "Segoe UI", Arial, sans-serif; }
.chart .axistitle { font-size: 9.5px; fill: #52606D; font-family: "Segoe UI", Arial, sans-serif; }
.mark-high { fill: var(--high-bar); }
.mark-medium { fill: var(--medium-bar); }
.legend { font-size: 8pt; color: var(--muted); margin: 0 0 8px; }
.legend-mark { width: 10px; height: 8px; vertical-align: 0; }
.share { display: inline-block; height: 8px; background: #8DA9C9; vertical-align: 0; margin-right: 4px; }
.chart-block { break-inside: avoid; page-break-inside: avoid; }
ul.plain { margin: 4px 0 8px; padding-left: 18px; }
ul.plain li { margin: 2px 0; }
.lines { font-family: Consolas, "Cascadia Mono", "Courier New", monospace; font-size: 7.5pt; background: var(--panel); border: 1px solid var(--line); padding: 5px 8px; margin: 4px 0 8px; overflow-wrap: anywhere; }
.lines div { white-space: pre-wrap; }
.cols { display: flex; gap: 18px; }
.cols > div { flex: 1; min-width: 0; }
@media print {
  body { background: #fff; }
  main { max-width: none; padding: 0; margin: 0; }
  nav.toc { display: none; }
  section.page { margin: 0; padding: 0; border-radius: 0; box-shadow: none; break-before: page; page-break-before: always; }
  section.page.first { break-before: auto; page-break-before: auto; }
  section.page.flow { break-before: auto; page-break-before: auto; margin-top: 22px; }
  /* After a section with no leads (a few lines that may have spilled onto a
     new page), the next section follows it instead of leaving that page
     nearly empty */
  section.page.flow + section.page { break-before: auto; page-break-before: auto; margin-top: 22px; }
  /* The summary fills at least its sheet, and the leads index follows it
     directly: a summary that fits pushes the index to page 2, and one that
     runs over continues on page 2 with the index after it, never leaving a
     nearly empty page */
  section.page.first { min-height: __SUMMARY_MIN_HEIGHT__; }
  section.page.after-first { break-before: auto; page-break-before: auto; padding-top: 10px; }
  /* The section after the leads index follows it on the same page: an index
     that spills a few rows onto a new page would otherwise leave that page
     nearly empty */
  section.page.after-first + section.page { break-before: auto; page-break-before: auto; margin-top: 22px; }
  /* A short block (a section with no leads, a few appendix items) stays in
     one piece with its heading and intro */
  .keep { break-inside: avoid; page-break-inside: avoid; }
  section.first ol.top { font-size: 9pt; }
  section.first ol.top li { margin: 1px 0 3px; }
  section.first .caveats ul { font-size: 7.6pt; line-height: 1.28; }
  section.first .facts { font-size: 8.8pt; }
  a { text-decoration: none; }
  a.xl { text-decoration: underline; }
}
@media screen and (max-width: 700px) {
  section.page { padding: 16px; }
  .stats, .cols { flex-direction: column; }
}
'@

# Opening section tag and heading; records the section for the screen menu.
# -Keep opens a <div class="keep"> (the caller closes it) so a short section
# is not split between pages
function Add-ReportHtmlSectionStart {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context, [string]$Id, [string]$Number, [string]$Title, [string]$Intro, [string]$ExtraClass, [switch]$Keep)
    $Context.Sections.Add(@{ Id = $Id; Title = $Title })
    $class = "page"
    if ($ExtraClass) { $class += " " + $ExtraClass }
    $null = $Builder.AppendLine('<section class="' + $class + '" id="' + $Id + '">')
    if ($Keep) { $null = $Builder.AppendLine('<div class="keep">') }
    $numberHtml = ""
    if ($Number) { $numberHtml = '<span class="secnum">' + $Number + '</span>' }
    $null = $Builder.AppendLine('<h2>' + $numberHtml + $Title + '</h2>')
    if ($Intro) { $null = $Builder.AppendLine('<p class="intro">' + $Intro + '</p>') }
}

# One finding: title, severity, plain-English why, analyst fields, evidence
# rows with their Excel row numbers, and the link to the workbook
function Add-ReportHtmlFinding {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context, [object]$Finding)
    $id = [string](Get-ReportHtmlField $Finding "Id")
    $severity = Get-ReportHtmlField $Finding "Severity"
    $key = Get-ReportHtmlSeverityKey $severity
    # The title holds a data value (the group); the whole value is under
    # "Grouped by"
    $title = ConvertTo-ReportHtmlText (Get-ReportHtmlField $Finding "Title") -MaxLength 160
    if (-not $title) { $title = "(untitled rule)" }
    $count = Get-ReportHtmlField $Finding "Count"
    $evidence = Get-ReportHtmlList $Finding "Evidence"
    # The card prints at most $script:ReportHtmlCardEvidenceRows rows: the
    # ones that raised the severity, then the earliest. The Findings sheet,
    # findings.csv and the Finding column keep the rest.
    $printed = $evidence
    if ($evidence.Count -gt $script:ReportHtmlCardEvidenceRows) {
        $keepIndex = New-Object System.Collections.Generic.List[int]
        for ($e = 0; $e -lt $evidence.Count -and $keepIndex.Count -lt $script:ReportHtmlCardEvidenceRows; $e++) {
            if ([bool](Get-ReportHtmlField $evidence[$e] "Escalation")) { $keepIndex.Add($e) }
        }
        for ($e = 0; $e -lt $evidence.Count -and $keepIndex.Count -lt $script:ReportHtmlCardEvidenceRows; $e++) {
            if (-not $keepIndex.Contains($e)) { $keepIndex.Add($e) }
        }
        $keepIndex.Sort()
        $printed = @(foreach ($e in $keepIndex) { $evidence[$e] })
    }

    $null = $Builder.AppendLine('<article class="finding f-' + $key + '" id="' + (ConvertTo-ReportHtmlAnchor $id) + '">')
    $null = $Builder.AppendLine('<div class="finding-head">')
    $null = $Builder.AppendLine('<h3><span class="fid">' + (ConvertTo-ReportHtmlText $id) + '</span> ' + (New-ReportHtmlSeverityBadge $severity) + ' ' + $title + '</h3>')
    $meta = New-Object System.Collections.Generic.List[string]
    $category = ConvertTo-ReportHtmlText (Get-ReportHtmlField $Finding "Category")
    if ($category) { $meta.Add($category) }
    if ($null -ne $count) { $meta.Add((Format-ReportHtmlCount -Value $count -Singular "matching row" -Plural "matching rows")) }
    $first = Format-ReportHtmlTime (Get-ReportHtmlField $Finding "FirstSeenUtc")
    $last = Format-ReportHtmlTime (Get-ReportHtmlField $Finding "LastSeenUtc")
    if ($first -and $last -and $first -ne $last) { $meta.Add('<span class="nowrap">' + $first + '</span> to <span class="nowrap">' + $last + ' UTC</span>') }
    elseif ($first) { $meta.Add('<span class="nowrap">' + $first + ' UTC</span>') }
    $ruleId = ConvertTo-ReportHtmlText (Get-ReportHtmlField $Finding "RuleId")
    if ($ruleId) { $meta.Add("rule " + $ruleId) }
    $null = $Builder.AppendLine('<div class="finding-meta">' + ($meta -join " &middot; ") + '</div>')
    $why = ConvertTo-ReportHtmlText (Get-ReportHtmlField $Finding "Why")
    if ($why) { $null = $Builder.AppendLine('<p class="why">' + $why + '</p>') }
    $null = $Builder.AppendLine('</div>')

    $fields = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@("Technical", "Technical detail"), @("NextSteps", "What to check next"), @("FalsePositives", "Common benign causes"))) {
        $value = ConvertTo-ReportHtmlText (Get-ReportHtmlField $Finding $pair[0])
        if ($value) { $fields.Add('<tr><th>' + $pair[1] + '</th><td>' + $value + '</td></tr>') }
    }
    $referenceList = Get-ReportHtmlList $Finding "References"
    $references = @($referenceList | ForEach-Object { ConvertTo-ReportHtmlText $_ } | Where-Object { $_ })
    if ($references.Count -gt 0) { $fields.Add('<tr><th>References</th><td>' + ($references -join "; ") + '</td></tr>') }
    $groupKey = ConvertTo-ReportHtmlText (Get-ReportHtmlField $Finding "GroupKey") -MaxLength 300
    if ($groupKey -and $groupKey -ne $ruleId) { $fields.Add('<tr><th>Grouped by</th><td>' + $groupKey + '</td></tr>') }
    if ($fields.Count -gt 0) { $null = $Builder.AppendLine('<table class="fields"><colgroup><col class="k"><col></colgroup><tbody>' + ($fields -join "") + '</tbody></table>') }

    $flags = New-Object System.Collections.Generic.List[string]
    if ([bool](Get-ReportHtmlField $Finding "Escalated")) {
        $flags.Add('<span class="flag flag-escalated">Escalated: a related event soon after raised the severity (it is among the evidence rows)</span>')
    }
    $allowlisted = ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $Finding "AllowlistedCount")
    if ($allowlisted -gt 0) {
        $flags.Add('<span class="flag">' + (Format-ReportHtmlCount -Value $allowlisted -Singular "more matching row was" -Plural "more matching rows were") + ' set aside by the allowlist as known benign</span>')
    }
    if ([bool](Get-ReportHtmlField $Finding "DuringCollection")) {
        $flags.Add('<span class="flag">Every row is from during the collection: this may be the collector&#39;s own activity</span>')
    }
    elseif ([bool](Get-ReportHtmlField $Finding "CapturedDuringCollection")) {
        $flags.Add('<span class="flag">Seen only in Snapshot rows from during the collection (the state when it was collected or the memory dump captured): it may have started earlier. Check that it is not the collector or its memory tool</span>')
    }
    $folded = ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $Finding "FoldedGroups")
    if ($folded -gt 0) {
        $flags.Add('<span class="flag">Folds ' + (Format-ReportHtmlNumber $folded) + ' similar groups of this rule into one lead (the rule&#39;s limit of separate leads); they are listed under &quot;Grouped by&quot;</span>')
    }
    if ([bool](Get-ReportHtmlField $Finding "TimesAuthorSupplied")) {
        $flags.Add('<span class="flag">Dated only by a scheduled task&#39;s author-supplied registration date, which whoever wrote the task sets (it can be old or forged)</span>')
    }
    elseif ((Get-ReportHtmlField $Finding "ActivityTime") -eq $false) {
        $flags.Add('<span class="flag">Dated by file times, which can be older than the activity or altered</span>')
    }
    if ($flags.Count -gt 0) { $null = $Builder.AppendLine('<div>' + ($flags -join "") + '</div>') }

    if ($evidence.Count -gt 0) {
        $null = $Builder.AppendLine('<table class="evidence"><colgroup><col class="c-row"><col class="c-time"><col class="c-src"><col class="c-desc"><col class="c-user"></colgroup>')
        $null = $Builder.AppendLine('<thead><tr><th class="num">' + $Context.RowHeading + '</th><th>Time (UTC)</th><th>Source / event type</th><th>Description / details</th><th>User</th></tr></thead><tbody>')
        foreach ($row in $printed) {
            $rowNumber = Get-ReportHtmlField $row "RowNumber"
            $rowText = ""
            if ($null -ne $rowNumber -and "$rowNumber" -ne "") { $rowText = [string]([long](ConvertTo-ReportHtmlNumber $rowNumber)) }
            $timestamp = Get-ReportHtmlField $row "Timestamp"
            if ($timestamp -is [string]) { $timeText = ConvertTo-ReportHtmlText $timestamp }
            else { $timeText = Format-ReportHtmlTime -Value $timestamp -Format "yyyy-MM-dd HH:mm:ss.fff" }
            $details = ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "Details") -MaxLength 360
            $detailsHtml = ""
            if ($details) { $detailsHtml = '<div class="details">' + $details + '</div>' }
            $null = $Builder.AppendLine('<tr><td class="num mono">' + $rowText + '</td><td class="mono">' + $timeText + '</td><td class="src">' +
                (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "Source") -MaxLength 120) + '<div class="et">' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "EventType") -MaxLength 60) + '</div></td><td><div class="desc">' +
                (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "Description") -MaxLength 480) + '</div>' + $detailsHtml + '</td><td>' +
                (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "User") -MaxLength 80) + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
    }
    else {
        $null = $Builder.AppendLine('<p class="empty">No evidence rows were attached to this lead.</p>')
    }

    $excel = New-Object System.Collections.Generic.List[string]
    $total = Get-ReportHtmlRowTotal -Finding $Finding
    if ($printed.Count -gt 0 -and $total -gt $printed.Count) {
        $shownText = "Showing " + (Format-ReportHtmlNumber $printed.Count) + " of the " + (Format-ReportHtmlNumber $total) + " rows of this lead (the earliest"
        if (@($printed | Where-Object { [bool](Get-ReportHtmlField $_ "Escalation") }).Count -gt 0) { $shownText += ", and the rows that raised its severity" }
        $shownText += ")."
        if ($evidence.Count -gt $printed.Count) { $shownText += " findings.csv" + $(if ($Context.WorkbookAvailable) { " and the Findings sheet list " } else { " lists " }) + (Format-ReportHtmlNumber $evidence.Count) + "." }
        $excel.Add($shownText)
    }
    if ($Context.WorkbookAvailable) {
        $excel.Add('In Excel: <a class="xl" href="' + $Context.WorkbookHref + '">' + (ConvertTo-ReportHtmlText $Context.WorkbookName) + '</a>, sheet &quot;' +
            (ConvertTo-ReportHtmlText $Context.FindingsSheet) + '&quot;, or filter the &quot;Finding&quot; column of the &quot;' + (ConvertTo-ReportHtmlText $Context.TimelineSheet) + '&quot; sheet for ' + (ConvertTo-ReportHtmlText $id) + '.')
    }
    else {
        $excel.Add('Rows are numbered as in ' + (ConvertTo-ReportHtmlText $Context.TimelineCsv) + ' (the header is row 1, as Excel shows it); findings.csv lists the evidence rows of ' + (ConvertTo-ReportHtmlText $id) + '.')
    }
    if ($excel.Count -gt 0) { $null = $Builder.AppendLine('<p class="excel">' + ($excel -join " ") + '</p>') }
    $null = $Builder.AppendLine('</article>')
}

# Section 1: the plain-English summary page
function Add-ReportHtmlSummary {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context)
    $model = $Context.Model
    $collection = $Context.Collection
    $tz = $Context.TimeZone
    $Context.Sections.Add(@{ Id = "summary"; Title = "Summary" })
    $null = $Builder.AppendLine('<section class="page first" id="summary">')
    $hostText = ConvertTo-ReportHtmlText $Context.HostName
    if (-not $hostText) { $hostText = "Unknown computer" }
    $null = $Builder.AppendLine('<header class="report-head"><div class="kicker">Windows triage timeline report</div><h1>' + $hostText + '</h1>')
    $null = $Builder.AppendLine('<div class="sub">Leads to review, found by rules in the timeline built from this computer&#39;s triage collection. Report made ' +
        (Format-ReportHtmlTime -Value (Get-ReportHtmlField $model "GeneratedUtc") -Format "yyyy-MM-dd HH:mm") + ' UTC.</div></header>')

    # The bottom line
    $leads = $Context.High + $Context.Medium
    $null = $Builder.AppendLine('<div class="bottom-line"><h3>The bottom line</h3>')
    $null = $Builder.AppendLine('<div class="stats"><div class="stat stat-high"><span class="n">' + $Context.High + '</span><span class="l">High leads &ndash; review first</span></div>' +
        '<div class="stat stat-medium"><span class="n">' + $Context.Medium + '</span><span class="l">Medium leads &ndash; review</span></div>' +
        '<div class="stat stat-info"><span class="n">' + $Context.Info + '</span><span class="l">Informational items (Appendix A)</span></div></div>')
    if ($leads -gt 0) {
        # The window leaves out leads dated by file times (timestomp
        # candidates, Amcache/ShimCache) or only by a task author's date:
        # those times can be old or forged
        $timed = Get-ReportHtmlActivityFindings -Findings $Context.Findings
        $fileTimed = $Context.Findings.Count - $timed.Count
        $authorDated = @($Context.Findings | Where-Object { [bool](Get-ReportHtmlField $_ "TimesAuthorSupplied") }).Count
        $datedBy = "file times"
        if ($authorDated -gt 0 -and $authorDated -eq $fileTimed) { $datedBy = "author-supplied task dates" }
        elseif ($authorDated -gt 0) { $datedBy = "file times or author-supplied task dates" }
        $span = Get-ReportHtmlFindingSpan -Findings $timed
        $text = "The rules flagged " + (Format-ReportHtmlCount -Value $leads -Singular "lead" -Plural "leads") + " to review."
        if ($span.First) {
            $text += " The flagged activity falls between <b>" + (Format-ReportHtmlUtcAndLocal -Value $span.First -TimeZone $tz) + "</b> and <b>" + (Format-ReportHtmlUtcAndLocal -Value $span.Last -TimeZone $tz) + "</b>"
            if ($fileTimed -gt 0) { $text += " (plus " + (Format-ReportHtmlCount -Value $fileTimed -Singular "lead" -Plural "leads") + " dated by $datedBy, which can be older than the activity or altered)" }
            $text += "."
        }
        elseif ($fileTimed -gt 0) {
            $text += " The flagged items are dated by $datedBy, which can be older than the activity or altered, so they give no activity window."
        }
        $null = $Builder.AppendLine('<p>' + $text + '</p>')
        $null = $Builder.AppendLine('<p class="framing">A lead is a reason to look closer, not proof that the computer was compromised. Each one needs a person to review the evidence rows listed with it.</p>')
    }
    else {
        $null = $Builder.AppendLine('<p>The rules found <b>no High or Medium leads</b> in this timeline.</p>')
        $null = $Builder.AppendLine('<p class="framing">That is not proof that the computer is clean: the rules only look for known patterns, and the evidence has limits (see the box below and section 2).</p>')
    }
    $null = $Builder.AppendLine('</div>')

    # Key facts. The computer is the examined one; for a mounted image whose
    # name is not known, say so (the collection's own computer name is the
    # computer the collector ran on, not the examined one)
    $null = $Builder.AppendLine('<h3>Key facts</h3><table class="facts"><tbody>')
    $facts = New-Object System.Collections.Generic.List[object]
    $computerText = $hostText
    $collectorHost = ConvertTo-ReportHtmlText (Get-ReportHtmlField $collection "CollectorHost") -MaxLength 80
    $nameSource = [string](Get-ReportHtmlField $collection "ComputerNameSource")
    $imageMode = [string](Get-ReportHtmlField $collection "Mode") -eq "MountedImage"
    if (-not $Context.HostName) {
        $computerText = "Not known"
        if ($imageMode) { $computerText += ": the collection was made from a mounted disk image, and the image&#39;s computer name was not found (its SYSTEM hive was not read)" }
        if ($collectorHost) { $computerText += ". The collection was made on " + $collectorHost + ", which is not the examined computer" }
        $computerText += "."
    }
    elseif ($imageMode -and $nameSource -eq "SYSTEM hive") {
        $computerText += ' <span class="muted small">(from the image&#39;s SYSTEM hive)</span>'
    }
    $facts.Add(@("Computer", $computerText))
    $os = ConvertTo-ReportHtmlText (Get-ReportHtmlField $collection "OS")
    if ($os) { $facts.Add(@("Operating system", $os)) }
    $userList = Get-ReportHtmlList $collection "Users"
    $users = @($userList | ForEach-Object { ConvertTo-ReportHtmlText $_ -MaxLength 64 } | Where-Object { $_ })
    if ($users.Count -gt 0) {
        $usersText = (@($users | Select-Object -First 12) -join ", ")
        if ($users.Count -gt 12) { $usersText += " and " + ($users.Count - 12) + " more" }
        $facts.Add(@("User accounts", $usersText))
    }
    $start = Get-ReportHtmlField $collection "CollectionStartUtc"
    $mode = ConvertTo-ReportHtmlText (Get-ReportHtmlField $collection "Mode")
    $collector = ConvertTo-ReportHtmlText (Get-ReportHtmlField $collection "CollectorUser")
    $how = @()
    if ($mode) { $how += $mode + " collection" }
    if ($collector) { $how += "run by " + $collector }
    # One row for when and how (the summary must fit one page)
    if ($null -ne $start) {
        $collectedText = Format-ReportHtmlUtcAndLocal -Value $start -TimeZone $tz
        if ($how.Count -gt 0) { $collectedText += "; " + ($how -join ", ") }
        $facts.Add(@("Evidence collected", $collectedText))
    }
    elseif ($how.Count -gt 0) { $facts.Add(@("Collection", ($how -join ", "))) }
    if ($Context.TimeZoneId) {
        $tzText = ConvertTo-ReportHtmlText $Context.TimeZoneId
        if ($tz) {
            $at = $Context.CollectionStartUtc
            if (-not $at) { $at = [datetime]::UtcNow }
            $tzText += " (" + (Format-ReportHtmlOffset -Offset $tz.GetUtcOffset($at)) + " at collection time)"
        }
        if ([bool](Get-ReportHtmlField $collection "TargetTimeZoneAssumed")) {
            $tzText += ", <b>assumed</b>: the collection does not record the computer&#39;s time zone"
        }
        $tzText += ". All times in this report are UTC."
        $facts.Add(@("Machine time zone", $tzText))
    }
    $span = Get-ReportHtmlField $model "TimeSpan"
    $rows = Get-ReportHtmlField $span "Rows"
    $firstUtc = Get-ReportHtmlField $span "FirstUtc"
    $lastUtc = Get-ReportHtmlField $span "LastUtc"
    if ($null -ne $firstUtc -or $null -ne $rows) {
        $spanText = ""
        if ($null -ne $firstUtc) { $spanText = (Format-ReportHtmlTime $firstUtc "yyyy-MM-dd") + " to " + (Format-ReportHtmlTime $lastUtc "yyyy-MM-dd") }
        if ($null -ne $rows) { $spanText += " (" + (Format-ReportHtmlCount -Value $rows -Singular "timeline row" -Plural "timeline rows") + ")" }
        $bulk = Get-ReportHtmlBulkSpan -Activity $Context.Activity
        if ($bulk) { $spanText += "; 99% of the rows fall between " + $bulk.First + " and " + $bulk.Last }
        $facts.Add(@("Time span covered", $spanText.Trim()))
    }
    if ([bool](Get-ReportHtmlField $collection "SecretsIncluded")) {
        $facts.Add(@("Sensitive material", "This collection includes credential material (made with -IncludeSecrets). Store and share it as sensitive."))
    }
    if ($Context.WorkbookAvailable) {
        $workbookText = '<a class="xl" href="' + $Context.WorkbookHref + '">' + (ConvertTo-ReportHtmlText $Context.WorkbookName) + '</a> (in the same folder as this report; the row numbers in this report are its rows)'
        $facts.Add(@("Excel workbook", $workbookText))
    }
    else {
        # Built first: in @("a", "b" + "c") the comma binds before the plus,
        # which would make an array of the pieces and cut the sentence
        $noWorkbook = "Not created for this timeline (CSV only), or not updated for this report. Row numbers in this report are rows of " +
            (ConvertTo-ReportHtmlText $Context.TimelineCsv) + ", counting the header as row 1, as Excel would."
        $facts.Add(@("Excel workbook", $noWorkbook))
    }
    foreach ($fact in $facts) { $null = $Builder.AppendLine('<tr><th>' + $fact[0] + '</th><td>' + $fact[1] + '</td></tr>') }
    $null = $Builder.AppendLine('</tbody></table>')

    # Top findings, one plain sentence each
    $top = New-Object System.Collections.Generic.List[object]
    foreach ($item in (Get-ReportHtmlList $model "TopFindings")) {
        $topId = $item
        if (-not ($item -is [string]) -and $null -ne (Get-ReportHtmlField $item "Id")) { $topId = Get-ReportHtmlField $item "Id" }
        $topId = [string]$topId
        if ($Context.FindingById.ContainsKey($topId) -and $top.Count -lt 5) { $top.Add($Context.FindingById[$topId]) }
    }
    if ($top.Count -eq 0) {
        foreach ($finding in $Context.Findings) { if ($top.Count -lt 5) { $top.Add($finding) } }
    }
    if ($top.Count -gt 0) {
        $heading = "The top leads"
        if ($leads -gt $top.Count) { $heading += ' <span class="muted small">(' + $top.Count + " of " + $leads + "; all are listed on the next page)</span>" }
        $null = $Builder.AppendLine('<h3>' + $heading + '</h3><ol class="top">')
        # Leads of the same rule that are not in the list: "and N similar"
        # on the first listed lead of that rule
        $topIds = @{}
        foreach ($finding in $top) { $topIds[[string](Get-ReportHtmlField $finding "Id")] = $true }
        $similar = @{}
        foreach ($finding in $Context.Findings) {
            $ruleKey = [string](Get-ReportHtmlField $finding "RuleId")
            if ($ruleKey -and -not $topIds.ContainsKey([string](Get-ReportHtmlField $finding "Id"))) { $similar[$ruleKey] = 1 + [int]$similar[$ruleKey] }
        }
        $similarShown = @{}
        foreach ($finding in $top) {
            $id = Get-ReportHtmlField $finding "Id"
            $ruleKey = [string](Get-ReportHtmlField $finding "RuleId")
            $similarText = ""
            if ($ruleKey -and $similar[$ruleKey] -gt 0 -and -not $similarShown.ContainsKey($ruleKey)) {
                $similarShown[$ruleKey] = $true
                $similarText = ' <span class="muted small">(and ' + (Format-ReportHtmlCount -Value $similar[$ruleKey] -Singular "similar lead" -Plural "similar leads") + ')</span>'
            }
            # One plain sentence per lead: the first sentence of its "why"
            # (the whole text is on the lead's card)
            $whyText = ([string](Get-ReportHtmlField $finding "Why")).Trim()
            $sentence = [regex]::Match($whyText, '^.+?[.!?](?=\s+[A-Z(])', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            if ($sentence.Success) { $whyText = $sentence.Value }
            $why = ConvertTo-ReportHtmlText $whyText -MaxLength 300
            $when = Format-ReportHtmlTime (Get-ReportHtmlField $finding "FirstSeenUtc") "yyyy-MM-dd HH:mm"
            $whenText = ""
            if ($when) { $whenText = ' <span class="muted small nowrap">(first seen ' + $when + ' UTC)</span>' }
            $null = $Builder.AppendLine('<li>' + (New-ReportHtmlSeverityBadge (Get-ReportHtmlField $finding "Severity")) + ' <a class="t" href="#' + (ConvertTo-ReportHtmlAnchor $id) + '">' +
                (ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "Title") -MaxLength 110) + '</a>' + $similarText + ' &ndash; ' + $why + $whenText + '</li>')
        }
        $null = $Builder.AppendLine('</ol>')
    }

    # What this report can't tell you
    $caveatList = Get-ReportHtmlList $model "Caveats"
    $caveats = @($caveatList | ForEach-Object { ConvertTo-ReportHtmlText $_ } | Where-Object { $_ })
    $null = $Builder.AppendLine('<aside class="caveats"><h3>What this report can&#39;t tell you</h3><ul>')
    if ($caveats.Count -eq 0) { $caveats = @("A missing event proves nothing: much useful logging is off by default, and logs roll over.") }
    foreach ($caveat in $caveats) { $null = $Builder.AppendLine('<li>' + $caveat + '</li>') }
    $null = $Builder.AppendLine('</ul></aside>')
    $null = $Builder.AppendLine('</section>')
}

# The days that hold 99% of the rows ("yyyy-MM-dd" first/last), or $null when
# that is the whole span anyway
function Get-ReportHtmlBulkSpan {
    param([object]$Activity)
    $days = New-Object System.Collections.Generic.List[object]
    foreach ($entry in (Get-ReportHtmlList $Activity "PerDay")) {
        $day = ConvertTo-ReportHtmlDay (Get-ReportHtmlField $entry "Day")
        $rows = ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $entry "Rows")
        if ($day -and $rows -gt 0) { $days.Add(@{ Day = $day; Rows = $rows }) }
    }
    if ($days.Count -lt 2) { return $null }
    $sortedDays = @($days | Sort-Object { $_.Day })
    $total = 0.0
    foreach ($d in $sortedDays) { $total += $d.Rows }
    $limit = $total * 0.005
    $sum = 0.0
    $firstIndex = 0
    for ($i = 0; $i -lt $sortedDays.Count; $i++) { $sum += $sortedDays[$i].Rows; if ($sum -gt $limit) { $firstIndex = $i; break } }
    $sum = 0.0
    $lastIndex = $sortedDays.Count - 1
    for ($i = $sortedDays.Count - 1; $i -ge 0; $i--) { $sum += $sortedDays[$i].Rows; if ($sum -gt $limit) { $lastIndex = $i; break } }
    if ($firstIndex -eq 0 -and $lastIndex -eq $sortedDays.Count - 1) { return $null }
    return @{ First = $sortedDays[$firstIndex].Day; Last = $sortedDays[$lastIndex].Day }
}

# Section 1, second page: every High and Medium lead in one table
function Add-ReportHtmlLeadIndex {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context)
    if ($Context.Findings.Count -eq 0) { return }
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "leads" -Number "" -Title "All leads at a glance" -ExtraClass "after-first" `
        -Intro ("Every High and Medium lead, most severe first. Click an id to jump to its details. " + $Context.RowHeading + "s are the first evidence rows of each lead.")
    $null = $Builder.AppendLine('<table><colgroup><col style="width:7%"><col style="width:11%"><col style="width:33%"><col style="width:12%"><col style="width:7%"><col style="width:15%"><col style="width:15%"></colgroup>')
    $null = $Builder.AppendLine('<thead><tr><th>Id</th><th>Severity</th><th>Lead</th><th>Category</th><th class="num">Rows</th><th>First seen (UTC)</th><th>' + $Context.RowHeading + 's</th></tr></thead><tbody>')
    foreach ($finding in $Context.Findings) {
        $id = Get-ReportHtmlField $finding "Id"
        $null = $Builder.AppendLine('<tr><td><a href="#' + (ConvertTo-ReportHtmlAnchor $id) + '">' + (ConvertTo-ReportHtmlText $id) + '</a></td><td>' + (New-ReportHtmlSeverityBadge (Get-ReportHtmlField $finding "Severity")) +
            '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "Title") -MaxLength 160) + '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "Category")) +
            '</td><td class="num">' + (Format-ReportHtmlNumber (Get-ReportHtmlField $finding "Count")) + '</td><td class="mono">' + (Format-ReportHtmlTime (Get-ReportHtmlField $finding "FirstSeenUtc") "yyyy-MM-dd HH:mm") +
            '</td><td class="mono">' + (Format-ReportHtmlRowList -Finding $finding -Max 3) + '</td></tr>')
    }
    $null = $Builder.AppendLine('</tbody></table>')
    if (-not $Context.WorkbookAvailable) {
        $null = $Builder.AppendLine('<p class="note">The Excel workbook was not created for this timeline. Row numbers count the header as row 1, as they would in Excel.</p>')
    }
    $null = $Builder.AppendLine('</section>')
}

# The findings of one category, or a short "nothing here" note
function Add-ReportHtmlFindingList {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context, [string]$Category, [object[]]$Findings)
    if ($Findings.Count -gt 0) {
        foreach ($finding in $Findings) { Add-ReportHtmlFinding -Builder $Builder -Context $Context -Finding $finding }
        return
    }
    $ruleCount = @($Context.Rules | Where-Object { ([string](Get-ReportHtmlField $_ "Category")).Trim() -eq $Category }).Count
    $infoCount = (Get-ReportHtmlCategoryFindings -Findings $Context.InfoFindings -Category $Category).Count
    $text = "No High or Medium leads in this category."
    if ($ruleCount -gt 0) { $text += " " + (Format-ReportHtmlCount -Value $ruleCount -Singular "rule" -Plural "rules") + " in this category " + $(if ($ruleCount -eq 1) { "was" } else { "were" }) + " checked." }
    elseif ($Context.Rules.Count -gt 0) { $text += " No rules in this category were run." }
    if ($infoCount -gt 0) { $text += " " + (Format-ReportHtmlCount -Value $infoCount -Singular "informational item is" -Plural "informational items are") + " listed in Appendix A." }
    $null = $Builder.AppendLine('<p class="empty">' + $text + '</p>')
}

# Section 2: evidence coverage and integrity
function Add-ReportHtmlCoverage {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context, [string]$Number)
    $coverage = $Context.Coverage
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "coverage" -Number $Number -Title "Evidence coverage and integrity" `
        -Intro "What this report is based on: how far back each source reaches, signs that logs were cleared, and logging that was off. Gaps here limit every other section."

    # A builder run that ended incomplete (exit code 2) comes first
    $completeness = Get-ReportHtmlField $coverage "TimelineCompleteness"
    if ([bool](Get-ReportHtmlField $completeness "Incomplete")) {
        $lineList = Get-ReportHtmlList $completeness "Lines"
        $lines = @($lineList | ForEach-Object { ConvertTo-ReportHtmlText $_ } | Where-Object { $_ })
        if ($lines.Count -eq 0) { $lines = @("The builder ended with exit code 2: the timeline may be incomplete.") }
        $null = $Builder.AppendLine('<h3>Timeline incomplete</h3><div class="incomplete">')
        foreach ($line in $lines) { $null = $Builder.AppendLine('<p><b>' + $line + '</b></p>') }
        $null = $Builder.AppendLine('<p>The builder log (timeline_builder_log.txt) names the missing files and the errors. Before drawing conclusions from what the timeline does not show, build it again from a complete copy of the collection.</p></div>')
    }

    $integrity = Get-ReportHtmlCategoryFindings -Findings $Context.Findings -Category "Integrity"
    $null = $Builder.AppendLine('<h3>Integrity leads</h3>')
    Add-ReportHtmlFindingList -Builder $Builder -Context $Context -Category "Integrity" -Findings $integrity

    $auditList = Get-ReportHtmlList $coverage "AuditNotes"
    $auditNotes = @($auditList | ForEach-Object { ConvertTo-ReportHtmlText $_ } | Where-Object { $_ })
    $null = $Builder.AppendLine('<h3>Logging that was off or limited</h3>')
    if ($auditNotes.Count -gt 0) {
        $null = $Builder.AppendLine('<ul class="plain">')
        foreach ($note in $auditNotes) { $null = $Builder.AppendLine('<li>' + $note + '</li>') }
        $null = $Builder.AppendLine('</ul>')
    }
    else { $null = $Builder.AppendLine('<p class="empty">No logging gaps were noted.</p>') }

    $logClears = Get-ReportHtmlList $coverage "LogClears"
    $null = $Builder.AppendLine('<h3>Event log clears</h3>')
    if ($logClears.Count -gt 0) {
        $null = $Builder.AppendLine('<table><colgroup><col style="width:8%"><col style="width:21%"><col style="width:21%"><col style="width:36%"><col style="width:14%"></colgroup>')
        $null = $Builder.AppendLine('<thead><tr><th class="num">' + $Context.RowHeading + '</th><th>Time (UTC)</th><th>Source</th><th>Description</th><th>User</th></tr></thead><tbody>')
        foreach ($row in $logClears) {
            $rowNumber = Get-ReportHtmlField $row "RowNumber"
            $rowText = ""
            if ($null -ne $rowNumber -and "$rowNumber" -ne "") { $rowText = [string]([long](ConvertTo-ReportHtmlNumber $rowNumber)) }
            $timestamp = Get-ReportHtmlField $row "Timestamp"
            if ($timestamp -is [string]) { $timeText = ConvertTo-ReportHtmlText $timestamp } else { $timeText = Format-ReportHtmlTime $timestamp "yyyy-MM-dd HH:mm:ss.fff" }
            $null = $Builder.AppendLine('<tr><td class="num mono">' + $rowText + '</td><td class="mono">' + $timeText + '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "Source") -MaxLength 120) +
                '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "Description") -MaxLength 300) + '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $row "User") -MaxLength 80) + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
    }
    else { $null = $Builder.AppendLine('<p class="empty">No event log clears were found in the timeline.</p>') }

    # Sources: first and last time, how far back each reaches
    $sources = Get-ReportHtmlList $coverage "Sources"
    $null = $Builder.AppendLine('<h3>Sources and how far back they reach</h3>')
    if ($sources.Count -gt 0) {
        $start = $Context.CollectionStartUtc
        $null = $Builder.AppendLine('<table><colgroup><col style="width:40%"><col style="width:11%"><col style="width:17%"><col style="width:17%"><col style="width:15%"></colgroup>')
        $null = $Builder.AppendLine('<thead><tr><th>Source</th><th class="num">Rows</th><th>First (UTC)</th><th>Last (UTC)</th><th class="num">Days before collection</th></tr></thead><tbody>')
        $shortLogs = 0
        foreach ($source in $sources) {
            $name = [string](Get-ReportHtmlField $source "Source")
            $first = ConvertTo-ReportHtmlUtc (Get-ReportHtmlField $source "FirstUtc")
            $reach = ""
            if ($start -and $first) {
                $days = ($start - $first).TotalDays
                if ($days -lt 0) { $days = 0 }
                $reach = ([long][Math]::Floor($days)).ToString("N0", $script:ReportHtmlInvariant)
                if ($name -match '\.evtx$' -and $days -lt 7) { $reach += " *"; $shortLogs++ }
            }
            $null = $Builder.AppendLine('<tr><td>' + (ConvertTo-ReportHtmlText $name -MaxLength 160) + '</td><td class="num">' + (Format-ReportHtmlNumber (Get-ReportHtmlField $source "Rows")) +
                '</td><td class="mono">' + (Format-ReportHtmlTime (Get-ReportHtmlField $source "FirstUtc") "yyyy-MM-dd HH:mm") + '</td><td class="mono">' + (Format-ReportHtmlTime (Get-ReportHtmlField $source "LastUtc") "yyyy-MM-dd HH:mm") +
                '</td><td class="num">' + $reach + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
        if ($shortLogs -gt 0) {
            $null = $Builder.AppendLine('<p class="small muted">* This event log starts less than 7 days before the collection: older events may have rolled over (or the system is new).</p>')
        }
    }
    else { $null = $Builder.AppendLine('<p class="empty">No source summary is available.</p>') }

    # Boots and shutdowns
    $boots = Get-ReportHtmlList $coverage "Boots"
    $null = $Builder.AppendLine('<h3>Boots and shutdowns</h3>')
    if ($boots.Count -gt 0) {
        $kinds = [ordered]@{}
        foreach ($boot in $boots) {
            $kind = [string](Get-ReportHtmlField $boot "Kind")
            if (-not $kind) { $kind = "Event" }
            if ($kinds.Contains($kind)) { $kinds[$kind]++ } else { $kinds[$kind] = 1 }
        }
        $parts = @($kinds.Keys | ForEach-Object { (ConvertTo-ReportHtmlText $_) + ": " + (Format-ReportHtmlNumber $kinds[$_]) })
        $null = $Builder.AppendLine('<p>' + ($parts -join " &middot; ") + '</p>')
        $sortedBoots = @($boots | Sort-Object { $t = ConvertTo-ReportHtmlUtc (Get-ReportHtmlField $_ "Utc"); if ($t) { $t } else { [datetime]::MinValue } })
        $recent = @($sortedBoots | Select-Object -Last 15)
        if ($sortedBoots.Count -gt $recent.Count) {
            $null = $Builder.AppendLine('<p class="small muted">The ' + $recent.Count + ' most recent are listed; the other ' + ($sortedBoots.Count - $recent.Count) + ' are in the timeline.</p>')
        }
        $null = $Builder.AppendLine('<table class="narrow"><colgroup><col style="width:30%"><col style="width:70%"></colgroup><thead><tr><th>Time (UTC)</th><th>Event</th></tr></thead><tbody>')
        foreach ($boot in $recent) {
            $null = $Builder.AppendLine('<tr><td class="mono">' + (Format-ReportHtmlTime (Get-ReportHtmlField $boot "Utc") "yyyy-MM-dd HH:mm:ss") + '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $boot "Kind") -MaxLength 120) + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
    }
    else { $null = $Builder.AppendLine('<p class="empty">No boot or shutdown events were found.</p>') }

    # Collector errors and warnings, and other notes. Errors are the count in
    # the collector's summary (or its ERROR lines); WARNING lines are counted
    # apart, as warnings. A model without the log (Available false) says so.
    $errors = Get-ReportHtmlField $coverage "CollectorErrors"
    $errorLines = Get-ReportHtmlList $errors "Lines"
    $errorCountValue = Get-ReportHtmlField $errors "Count"
    $warningCountValue = Get-ReportHtmlField $errors "WarningCount"
    $warningCount = [long](ConvertTo-ReportHtmlNumber $warningCountValue)
    if ($null -eq $warningCountValue) { $warningCount = @($errorLines | Where-Object { "$_" -match '\] WARNING: ' }).Count }
    $errorCount = [long](ConvertTo-ReportHtmlNumber $errorCountValue)
    if ($null -eq $errorCountValue) { $errorCount = @($errorLines | Where-Object { "$_" -match '\] ERROR: ' }).Count }
    $null = $Builder.AppendLine('<h3>Collection problems</h3>')
    if ((Get-ReportHtmlField $errors "Available") -eq $false) {
        $null = $Builder.AppendLine('<p>The collector&#39;s log (collection_log.txt) was not available, so problems during the collection are unknown.</p>')
    }
    elseif ($errorCount -gt 0 -or $warningCount -gt 0 -or $errorLines.Count -gt 0) {
        $text = 'The collector logged ' + (Format-ReportHtmlCount -Value $errorCount -Singular "error" -Plural "errors") + ' and ' + (Format-ReportHtmlCount -Value $warningCount -Singular "warning" -Plural "warnings") + '.'
        if ($errorCount -gt 0) { $text += ' Evidence it could not collect is missing from this report.' }
        else { $text += ' A warning can mean that an artifact was skipped or only partly collected.' }
        $null = $Builder.AppendLine('<p>' + $text + '</p>')
        if ($errorLines.Count -gt 0) {
            $null = $Builder.AppendLine('<div class="lines">')
            foreach ($line in @($errorLines | Select-Object -First 25)) { $null = $Builder.AppendLine('<div>' + (ConvertTo-ReportHtmlText $line -MaxLength 400) + '</div>') }
            if ($errorLines.Count -gt 25) { $null = $Builder.AppendLine('<div>... ' + ($errorLines.Count - 25) + ' more in the collector log</div>') }
            $null = $Builder.AppendLine('</div>')
        }
    }
    else { $null = $Builder.AppendLine('<p class="empty">The collector logged no errors or warnings.</p>') }
    $noteList = Get-ReportHtmlList $coverage "Notes"
    $notes = @($noteList | ForEach-Object { ConvertTo-ReportHtmlText $_ } | Where-Object { $_ })
    if ($notes.Count -gt 0) {
        $null = $Builder.AppendLine('<h3>Notes</h3><ul class="plain">')
        foreach ($note in $notes) { $null = $Builder.AppendLine('<li>' + $note + '</li>') }
        $null = $Builder.AppendLine('</ul>')
    }
    $null = $Builder.AppendLine('</section>')
}

# Activity overview: events per day (recent window and, for a long span, per
# month), busiest hours, and rows per source and per user
function Add-ReportHtmlActivity {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context, [string]$Number)
    $activity = $Context.Activity
    $inv = $script:ReportHtmlInvariant
    $markers = Get-ReportHtmlLeadMarkers -Findings $Context.Findings
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "activity" -Number $Number -Title "Activity overview" `
        -Intro "How busy the computer was over time, which sources produced the most rows, and which accounts were active. Busy periods are not suspicious by themselves; they show where the evidence is."

    $perDay = @{}
    foreach ($entry in (Get-ReportHtmlList $activity "PerDay")) {
        $day = ConvertTo-ReportHtmlDay (Get-ReportHtmlField $entry "Day")
        if ($day) { $perDay[$day] = [double]$perDay[$day] + (ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $entry "Rows")) }
    }
    if ($perDay.Count -gt 0) {
        $dayKeys = @($perDay.Keys | Sort-Object)
        $firstDay = [datetime]::ParseExact($dayKeys[0], "yyyy-MM-dd", $inv)
        $lastDay = [datetime]::ParseExact($dayKeys[-1], "yyyy-MM-dd", $inv)
        $windowStart = $lastDay.AddDays(-59)
        if ($firstDay -gt $windowStart) { $windowStart = $firstDay }
        if (($lastDay - $windowStart).TotalDays -lt 13) { $windowStart = $lastDay.AddDays(-13) }
        $dayCount = [int]($lastDay - $windowStart).TotalDays + 1
        $labelEvery = [Math]::Max(1, [int][Math]::Ceiling($dayCount / 8.0))
        $bars = New-Object System.Collections.Generic.List[object]
        $busiest = $null
        $windowRows = 0.0
        for ($i = 0; $i -lt $dayCount; $i++) {
            $date = $windowStart.AddDays($i)
            $key = $date.ToString("yyyy-MM-dd", $inv)
            $value = [double]$perDay[$key]
            $windowRows += $value
            if (-not $busiest -or $value -gt $busiest.Value) { $busiest = @{ Day = $key; Value = $value } }
            $axis = ""
            if (($dayCount - 1 - $i) % $labelEvery -eq 0) { $axis = $date.ToString("MMM d", $inv) }
            $bars.Add(@{ Value = $value; Tip = $key + ": " + $value.ToString("N0", $inv) + " rows"; Axis = $axis; Marker = [string]$markers.Days[$key] })
        }
        $null = $Builder.AppendLine('<div class="chart-block"><h3>Events per day, ' + $windowStart.ToString("yyyy-MM-dd", $inv) + ' to ' + $lastDay.ToString("yyyy-MM-dd", $inv) + '</h3>')
        $null = $Builder.AppendLine((New-ReportHtmlBarChart -Bars $bars.ToArray() -Label ("Timeline rows per day from " + $windowStart.ToString("yyyy-MM-dd", $inv) + " to " + $lastDay.ToString("yyyy-MM-dd", $inv)) -AxisTitle "Day (UTC)"))
        $null = $Builder.AppendLine((New-ReportHtmlMarkerLegend -Unit "Day"))
        if ($busiest -and $busiest.Value -gt 0) {
            $null = $Builder.AppendLine('<p class="small">Busiest day in this window: <b>' + $busiest.Day + '</b> with ' + $busiest.Value.ToString("N0", $inv) + ' rows. The window holds ' + $windowRows.ToString("N0", $inv) + ' rows.</p>')
        }
        $null = $Builder.AppendLine('</div>')

        # Per month over the last two years when the data reaches back further
        if ($firstDay -lt $windowStart) {
            $perMonth = @{}
            foreach ($key in $dayKeys) { $month = $key.Substring(0, 7); $perMonth[$month] = [double]$perMonth[$month] + $perDay[$key] }
            $monthStart = (New-Object datetime($lastDay.Year, $lastDay.Month, 1)).AddMonths(-23)
            $firstMonth = New-Object datetime($firstDay.Year, $firstDay.Month, 1)
            if ($firstMonth -gt $monthStart) { $monthStart = $firstMonth }
            $monthBars = New-Object System.Collections.Generic.List[object]
            $monthIndex = 0
            for ($m = $monthStart; $m -le $lastDay; $m = $m.AddMonths(1)) {
                $key = $m.ToString("yyyy-MM", $inv)
                $value = [double]$perMonth[$key]
                $axis = ""
                if ($monthIndex % 3 -eq 0) { $axis = $m.ToString("MMM yyyy", $inv) }
                $monthBars.Add(@{ Value = $value; Tip = $key + ": " + $value.ToString("N0", $inv) + " rows"; Axis = $axis; Marker = [string]$markers.Months[$key] })
                $monthIndex++
            }
            $olderRows = 0.0
            $monthStartKey = $monthStart.ToString("yyyy-MM", $inv)
            foreach ($key in $perMonth.Keys) { if ($key -lt $monthStartKey) { $olderRows += $perMonth[$key] } }
            $null = $Builder.AppendLine('<div class="chart-block"><h3>Events per month, ' + $monthStart.ToString("MMMM yyyy", $inv) + ' to ' + $lastDay.ToString("MMMM yyyy", $inv) + '</h3>')
            $null = $Builder.AppendLine((New-ReportHtmlBarChart -Bars $monthBars.ToArray() -Label ("Timeline rows per month from " + $monthStart.ToString("yyyy-MM", $inv) + " to " + $lastDay.ToString("yyyy-MM", $inv)) -AxisTitle "Month (UTC)"))
            $null = $Builder.AppendLine((New-ReportHtmlMarkerLegend -Unit "Month"))
            if ($olderRows -gt 0) {
                $null = $Builder.AppendLine('<p class="small">' + $olderRows.ToString("N0", $inv) + ' older rows reach back to ' + $dayKeys[0] + '. Old times usually come from file system records and installed software, not from activity at that time.</p>')
            }
            $null = $Builder.AppendLine('</div>')
        }
    }
    else { $null = $Builder.AppendLine('<p class="empty">No per-day activity is available.</p>') }

    # Busiest hours (UTC)
    $hourList = Get-ReportHtmlList $activity "PerHourUtc"
    $hours = @($hourList | ForEach-Object { ConvertTo-ReportHtmlNumber $_ })
    if ($hours.Count -eq 24) {
        $hourBars = New-Object System.Collections.Generic.List[object]
        for ($h = 0; $h -lt 24; $h++) {
            $axis = ""
            if ($h % 3 -eq 0) { $axis = $h.ToString("00") + ":00" }
            $hourBars.Add(@{ Value = $hours[$h]; Tip = $h.ToString("00") + ":00-" + $h.ToString("00") + ":59 UTC: " + $hours[$h].ToString("N0", $inv) + " rows"; Axis = $axis; Marker = [string]$markers.Hours[$h] })
        }
        $null = $Builder.AppendLine('<div class="chart-block"><h3>Busiest hours of the day (UTC)</h3>')
        $null = $Builder.AppendLine((New-ReportHtmlBarChart -Bars $hourBars.ToArray() -Label "Timeline rows per hour of the day, UTC" -AxisTitle "Hour of day (UTC)"))
        $null = $Builder.AppendLine((New-ReportHtmlMarkerLegend -Unit "Hour"))
        $topHours = @(0..23 | Sort-Object { $hours[$_] } -Descending | Select-Object -First 3 | Where-Object { $hours[$_] -gt 0 })
        if ($topHours.Count -gt 0) {
            $text = "Busiest hours: " + (@($topHours | ForEach-Object { $_.ToString("00") + ":00 UTC (" + $hours[$_].ToString("N0", $inv) + " rows)" }) -join ", ") + "."
            if ($Context.TimeZone) {
                $at = $Context.CollectionStartUtc
                if (-not $at) { $at = [datetime]::UtcNow }
                $text += " The machine&#39;s clock was " + (Format-ReportHtmlOffset -Offset $Context.TimeZone.GetUtcOffset($at)) + " at collection time."
            }
            $null = $Builder.AppendLine('<p class="small">' + $text + '</p>')
        }
        $null = $Builder.AppendLine('</div>')
    }

    # Rows per source and per user
    $null = $Builder.AppendLine('<div class="cols"><div>')
    Add-ReportHtmlShareTable -Builder $Builder -Entries (Get-ReportHtmlList $activity "TopSources") -NameField "Source" -Heading "Sources with the most rows" -NameHeading "Source"
    $null = $Builder.AppendLine('</div><div>')
    Add-ReportHtmlShareTable -Builder $Builder -Entries (Get-ReportHtmlList $activity "PerUser") -NameField "User" -Heading "Rows per user" -NameHeading "User"
    $null = $Builder.AppendLine('</div></div>')
    $null = $Builder.AppendLine('</section>')
}

# A name / rows / share table with small bars
function Add-ReportHtmlShareTable {
    param([System.Text.StringBuilder]$Builder, [object[]]$Entries, [string]$NameField, [string]$Heading, [string]$NameHeading)
    $null = $Builder.AppendLine('<h3>' + $Heading + '</h3>')
    if ($Entries.Count -eq 0) { $null = $Builder.AppendLine('<p class="empty">None.</p>'); return }
    $max = 0.0
    $total = 0.0
    foreach ($entry in $Entries) { $rows = ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $entry "Rows"); $total += $rows; if ($rows -gt $max) { $max = $rows } }
    $null = $Builder.AppendLine('<table><colgroup><col style="width:52%"><col style="width:20%"><col style="width:28%"></colgroup><thead><tr><th>' + $NameHeading + '</th><th class="num">Rows</th><th></th></tr></thead><tbody>')
    foreach ($entry in $Entries) {
        $rows = ConvertTo-ReportHtmlNumber (Get-ReportHtmlField $entry "Rows")
        $width = 0
        if ($max -gt 0) { $width = [int][Math]::Round(100 * $rows / $max) }
        $name = ConvertTo-ReportHtmlText (Get-ReportHtmlField $entry $NameField) -MaxLength 120
        if (-not $name) { $name = '<span class="muted">(none)</span>' }
        $null = $Builder.AppendLine('<tr><td>' + $name + '</td><td class="num">' + (Format-ReportHtmlNumber $rows) + '</td><td><span class="share" style="width:' + $width + '%"></span></td></tr>')
    }
    $null = $Builder.AppendLine('</tbody></table>')
}

# Appendix: informational items, the rules used, the method, and the files
function Add-ReportHtmlAppendix {
    param([System.Text.StringBuilder]$Builder, [hashtable]$Context)
    $model = $Context.Model

    # A. Informational items. A short list follows the activity section and
    # stays in one piece (Appendix B then follows it), instead of taking a
    # page of its own
    $shortInfo = $Context.InfoFindings.Count -le 8
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "appendix-info" -Number "A" -Title "Informational items" `
        -Intro "Context that rules recorded at Info level: usually normal, but useful when piecing a story together. They are not leads." `
        -ExtraClass $(if ($shortInfo) { "flow" } else { "" }) -Keep:$shortInfo
    if ($Context.InfoFindings.Count -gt 0) {
        $null = $Builder.AppendLine('<table><colgroup><col style="width:7%"><col style="width:42%"><col style="width:12%"><col style="width:7%"><col style="width:17%"><col style="width:15%"></colgroup>')
        $null = $Builder.AppendLine('<thead><tr><th>Id</th><th>Item</th><th>Category</th><th class="num">Rows</th><th>First / last seen (UTC)</th><th>' + $Context.RowHeading + 's</th></tr></thead><tbody>')
        foreach ($finding in $Context.InfoFindings) {
            $id = Get-ReportHtmlField $finding "Id"
            $why = ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "Why") -MaxLength 300
            $whyHtml = ""
            if ($why) { $whyHtml = '<div class="small muted">' + $why + '</div>' }
            $group = ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "GroupKey") -MaxLength 160
            $groupHtml = ""
            if ($group -and $group -ne (ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "RuleId"))) { $groupHtml = '<div class="small">' + $group + '</div>' }
            $first = Format-ReportHtmlTime (Get-ReportHtmlField $finding "FirstSeenUtc") "yyyy-MM-dd HH:mm"
            $last = Format-ReportHtmlTime (Get-ReportHtmlField $finding "LastSeenUtc") "yyyy-MM-dd HH:mm"
            $when = $first
            if ($last -and $last -ne $first) { $when += "<br>" + $last }
            $null = $Builder.AppendLine('<tr id="' + (ConvertTo-ReportHtmlAnchor $id) + '"><td>' + (ConvertTo-ReportHtmlText $id) + '</td><td><b>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "Title")) + '</b>' + $groupHtml + $whyHtml +
                '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $finding "Category")) + '</td><td class="num">' + (Format-ReportHtmlNumber (Get-ReportHtmlField $finding "Count")) +
                '</td><td class="mono">' + $when + '</td><td class="mono">' + (Format-ReportHtmlRowList -Finding $finding -Max 6) + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
    }
    else { $null = $Builder.AppendLine('<p class="empty">No informational items.</p>') }
    if ($shortInfo) { $null = $Builder.AppendLine('</div>') }
    $null = $Builder.AppendLine('</section>')

    # B. Rules used
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "appendix-rules" -Number "B" -Title "Rules used" `
        -Intro "The rules from report-rules.json that were run on this timeline. A rule that is listed but found nothing produced no lead."
    if ($Context.Rules.Count -gt 0) {
        $null = $Builder.AppendLine('<table><colgroup><col style="width:22%"><col style="width:52%"><col style="width:11%"><col style="width:15%"></colgroup><thead><tr><th>Rule</th><th>Title</th><th>Severity</th><th>Category</th></tr></thead><tbody>')
        foreach ($rule in $Context.Rules) {
            # Without the {{group}} placeholder of the finding titles
            $ruleTitle = ([string](Get-ReportHtmlField $rule "Title") -replace '\s*[:(-]?\s*\{\{group\}\}\)?', '').Trim()
            $null = $Builder.AppendLine('<tr><td class="mono">' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $rule "Id")) + '</td><td>' + (ConvertTo-ReportHtmlText $ruleTitle) +
                '</td><td>' + (New-ReportHtmlSeverityBadge (Get-ReportHtmlField $rule "Severity")) + '</td><td>' + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $rule "Category")) + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
    }
    else { $null = $Builder.AppendLine('<p class="empty">The rule list is not available.</p>') }
    $null = $Builder.AppendLine('</section>')

    # C. Method
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "appendix-method" -Number "C" -Title "Method" -Intro "" -ExtraClass "flow"
    $timelineSheet = ConvertTo-ReportHtmlText $Context.TimelineSheet
    $findingsSheet = ConvertTo-ReportHtmlText $Context.FindingsSheet
    $null = $Builder.AppendLine('<ul class="plain">')
    $null = $Builder.AppendLine('<li>The timeline builder parsed the collected artifacts into one timeline (one row per event, all times in UTC), removed duplicates and sorted it by time. This report was made from those rows.</li>')
    if ($Context.WorkbookAvailable) {
        $null = $Builder.AppendLine('<li>Row numbers are the rows of the &quot;' + $timelineSheet + '&quot; sheet in the Excel workbook: the header is row 1, so the first event is row 2. The &quot;' + $findingsSheet + '&quot; sheet links to each evidence row, and the &quot;Finding&quot; column on the timeline sheet tags every row of each finding for filtering.</li>')
    }
    else {
        $null = $Builder.AppendLine('<li>There is no Excel workbook for this report, so row numbers are the rows of ' + (ConvertTo-ReportHtmlText $Context.TimelineCsv) + ': the header is row 1, so the first event is row 2 (the row Excel shows when it opens the CSV).</li>')
    }
    $null = $Builder.AppendLine('<li>Each rule (Appendix B) describes the rows to look for by source, event type, description, details and user, with case-insensitive patterns. A rule may group its rows (for example by user or by threat name), need several rows within a time window, or raise the severity when a related event follows soon after.</li>')
    $null = $Builder.AppendLine('<li>Rows that match the allowlist (known benign activity, such as the collector&#39;s own temporary antivirus exclusion) are set aside and counted, not reported.</li>')
    $null = $Builder.AppendLine('<li>Severity: <b>High</b> &ndash; review first; <b>Medium</b> &ndash; review; <b>Info</b> &ndash; context only (Appendix A). Severity says how strongly a pattern is linked to attacker activity in general, not that it happened here.</li>')
    $null = $Builder.AppendLine('<li>Each lead&#39;s card prints up to ' + $script:ReportHtmlCardEvidenceRows + ' evidence rows (the earliest, and any that raised its severity); findings.csv' + $(if ($Context.WorkbookAvailable) { ' and the Findings sheet list' } else { ' lists' }) + ' up to the rule&#39;s limit, and the count shows how many rows matched in all.' + $(if ($Context.WorkbookAvailable) { ' The &quot;Finding&quot; column tags every one of them.' } else { '' }) + '</li>')
    $null = $Builder.AppendLine('<li>A rule gives at most a set number of separate leads (20 unless the rule says otherwise); further groups are folded into one lead that lists them. The summary&#39;s activity window leaves out leads dated by file times (altered file times and file-existence records), which can be much older than the activity.</li>')
    $null = $Builder.AppendLine('</ul>')
    $null = $Builder.AppendLine('</section>')

    # D. Files and collection options
    Add-ReportHtmlSectionStart -Builder $Builder -Context $Context -Id "appendix-files" -Number "D" -Title "Files" -Intro "" -ExtraClass "flow"
    $files = New-Object System.Collections.Generic.List[object]
    $filesObject = Get-ReportHtmlField $model "Files"
    # Files.Hashes (from the report model): [{Name, Bytes, Sha256}] measured
    # when the model was built; used instead of hashing the files again
    $knownHashes = @{}
    foreach ($entry in (Get-ReportHtmlList $filesObject "Hashes")) {
        $hashName = [System.IO.Path]::GetFileName([string](Get-ReportHtmlField $entry "Name"))
        $hashValue = [string](Get-ReportHtmlField $entry "Sha256")
        if ($hashName -and $hashValue -and -not $knownHashes.ContainsKey($hashName)) { $knownHashes[$hashName] = $hashValue }
    }
    $listed = @{}
    if ($null -ne $filesObject) {
        $names = @()
        if ($filesObject -is [System.Collections.IDictionary]) { $names = @($filesObject.Keys) } else { $names = @($filesObject.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($name in $names) {
            if ([string]$name -eq "Hashes") { continue }
            $value = Get-ReportHtmlField $filesObject $name
            if ($null -eq $value) { continue }
            $label = switch ([string]$name) { "TimelineCsv" { "Timeline (CSV)" } "FindingsCsv" { "Findings (CSV)" } default { [string]$name } }
            $file = $value
            $hash = $null
            if (-not ($value -is [string])) {
                $file = Get-ReportHtmlField $value "Name"
                if (-not $file) { $file = Get-ReportHtmlField $value "Path" }
                $hash = Get-ReportHtmlField $value "Sha256"
            }
            if (-not $file) { continue }
            $leaf = [System.IO.Path]::GetFileName([string]$file)
            if (-not $hash -and $knownHashes.ContainsKey($leaf)) { $hash = $knownHashes[$leaf] }
            $listed[$leaf] = $true
            $files.Add(@{ Label = $label; File = [string]$file; Hash = $hash })
        }
    }
    if ($Context.WorkbookAvailable) {
        $hash = $null
        if ($knownHashes.ContainsKey($Context.WorkbookName)) { $hash = $knownHashes[$Context.WorkbookName] }
        $listed[$Context.WorkbookName] = $true
        $files.Add(@{ Label = "Timeline workbook (Excel)"; File = $Context.WorkbookName; Hash = $hash })
    }
    # Other hashed files, such as the collection zip
    foreach ($hashName in @($knownHashes.Keys | Sort-Object)) {
        if ($listed.ContainsKey($hashName)) { continue }
        $label = "File"
        if ($hashName -match '\.zip$') { $label = "Collection (zip)" }
        $files.Add(@{ Label = $label; File = $hashName; Hash = $knownHashes[$hashName] })
    }
    if ($files.Count -gt 0) {
        $null = $Builder.AppendLine('<table><colgroup><col style="width:22%"><col style="width:28%"><col style="width:50%"></colgroup><thead><tr><th>File</th><th>Name</th><th>SHA-256 (when the report was made)</th></tr></thead><tbody>')
        foreach ($entry in $files) {
            $hash = $entry.Hash
            if (-not $hash -and $Context.HashFiles) { $hash = Get-ReportHtmlFileHash -Directory $Context.OutputDirectory -File $entry.File }
            $hashHtml = '<span class="muted">not available</span>'
            if ($hash) { $hashHtml = '<span class="mono">' + (ConvertTo-ReportHtmlText ([string]$hash).ToUpperInvariant()) + '</span>' }
            $null = $Builder.AppendLine('<tr><td>' + (ConvertTo-ReportHtmlText $entry.Label) + '</td><td>' + (ConvertTo-ReportHtmlText ([System.IO.Path]::GetFileName($entry.File))) + '</td><td>' + $hashHtml + '</td></tr>')
        }
        $null = $Builder.AppendLine('</tbody></table>')
    }
    $collection = $Context.Collection
    $options = New-Object System.Collections.Generic.List[string]
    $options.Add("Collection mode: " + $(if (Get-ReportHtmlField $collection "Mode") { ConvertTo-ReportHtmlText (Get-ReportHtmlField $collection "Mode") } else { "unknown" }))
    $options.Add("Credential material included (-IncludeSecrets): " + $(if ([bool](Get-ReportHtmlField $collection "SecretsIncluded")) { "yes" } else { "no" }))
    $options.Add("Thunderbird search index included: " + $(if ([bool](Get-ReportHtmlField $collection "ThunderbirdIndexIncluded")) { "yes" } else { "no" }))
    $options.Add("Report model schema version: " + (ConvertTo-ReportHtmlText (Get-ReportHtmlField $model "SchemaVersion")))
    $null = $Builder.AppendLine('<ul class="plain small">')
    foreach ($option in $options) { $null = $Builder.AppendLine('<li>' + $option + '</li>') }
    $null = $Builder.AppendLine('</ul>')
    $null = $Builder.AppendLine('</section>')
}

# Writes the report as one self-contained offline HTML file. -PaperSize:
# Auto = A4 in metric regions, Letter elsewhere (the layout fits both).
# Unless -NoFileHashes, the files listed in the model (timeline.csv,
# findings.csv, the workbook) are hashed when they exist next to -Path, so
# write them before calling this.
function Export-ReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Model,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet("Auto", "Letter", "A4")]
        [string]$PaperSize = "Auto",

        [switch]$NoFileHashes
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $outputDirectory = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $outputDirectory)) { New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null }
    $context = New-ReportHtmlContext -Model $Model -OutputDirectory $outputDirectory -HashFiles (-not $NoFileHashes)

    $size = $PaperSize
    if ($size -eq "Auto") {
        $size = "Letter"
        try { if ([System.Globalization.RegionInfo]::CurrentRegion.IsMetric) { $size = "A4" } }
        catch { Write-Verbose "Region unknown; using Letter paper" }
    }
    $hostName = $script:ReportHtmlBidiRegex.Replace([string]$context.HostName, $script:ReportHtmlBidiEvaluator)
    if ($hostName.Length -gt 60) { $hostName = $hostName.Substring(0, 60) }
    $footer = "Timeline report"
    if ($hostName) { $footer += " - " + $hostName }
    # The printable height of one page (paper minus the @page margins of 16 and
    # 17 mm), less 3 mm so rounding never spills the summary onto a new page
    $summaryHeight = "243mm"
    if ($size -eq "A4") { $summaryHeight = "261mm" }
    $css = $script:ReportHtmlCss.Replace("__PAGE_SIZE__", "size: " + $size.ToLowerInvariant() + ";").Replace("__FOOTER_TEXT__", (ConvertTo-ReportHtmlCssString $footer)).Replace("__SUMMARY_MIN_HEIGHT__", $summaryHeight)

    # Body first (it records the sections for the menu), then the page
    $body = New-Object System.Text.StringBuilder (262144)
    Add-ReportHtmlSummary -Builder $body -Context $context
    Add-ReportHtmlLeadIndex -Builder $body -Context $context
    $number = 2
    Add-ReportHtmlCoverage -Builder $body -Context $context -Number ([string]$number)
    $categorySections = New-Object System.Collections.Generic.List[object]
    foreach ($section in $script:ReportHtmlCategorySections) { $categorySections.Add($section) }
    $other = Get-ReportHtmlCategoryFindings -Findings $context.Findings -Category "Other"
    if ($other.Count -gt 0) {
        $categorySections.Add(@{ Category = "Other"; Id = "other"; Title = "Other leads"; Intro = "Leads from rules outside the categories above." })
    }
    foreach ($section in $categorySections) {
        $number++
        $sectionFindings = Get-ReportHtmlCategoryFindings -Findings $context.Findings -Category $section.Category
        # The category sections follow one another instead of each starting a
        # page: a forced break after a section whose last card spilled a row
        # onto a new page left that page nearly empty. A section without
        # leads keeps its heading, intro and note together.
        $empty = $sectionFindings.Count -eq 0
        Add-ReportHtmlSectionStart -Builder $body -Context $context -Id $section.Id -Number ([string]$number) -Title $section.Title -Intro $section.Intro -ExtraClass "flow" -Keep:$empty
        Add-ReportHtmlFindingList -Builder $body -Context $context -Category $section.Category -Findings $sectionFindings
        if ($empty) { $null = $body.AppendLine('</div>') }
        $null = $body.AppendLine('</section>')
    }
    $number++
    Add-ReportHtmlActivity -Builder $body -Context $context -Number ([string]$number)
    Add-ReportHtmlAppendix -Builder $body -Context $context

    $titleText = "Timeline report"
    if ($context.HostName) { $titleText += " - " + (ConvertTo-ReportHtmlText $context.HostName) }
    $page = New-Object System.Text.StringBuilder ($body.Length + 32768)
    $null = $page.AppendLine('<!DOCTYPE html>')
    $null = $page.AppendLine('<html lang="en">')
    $null = $page.AppendLine('<head>')
    $null = $page.AppendLine('<meta charset="utf-8">')
    $null = $page.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; img-src data:">')
    $null = $page.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $page.AppendLine('<meta name="generator" content="win11-timeline-builder">')
    $null = $page.AppendLine('<title>' + $titleText + '</title>')
    $null = $page.AppendLine('<style>')
    $null = $page.AppendLine($css)
    $null = $page.AppendLine('</style>')
    $null = $page.AppendLine('</head>')
    $null = $page.AppendLine('<body>')
    $menu = @($context.Sections | ForEach-Object { '<a href="#' + $_.Id + '">' + $_.Title + '</a>' })
    $null = $page.AppendLine('<nav class="toc" aria-label="Sections">' + ($menu -join " ") + '</nav>')
    $null = $page.AppendLine('<main>')
    $null = $page.Append($body.ToString())
    $null = $page.AppendLine('</main>')
    $null = $page.AppendLine('</body>')
    $null = $page.AppendLine('</html>')

    # CRLF everywhere (values may hold bare LF or CR); ASCII, no BOM
    $html = [regex]::Replace($page.ToString(), "\r\n|\r|\n", "`r`n")
    [System.IO.File]::WriteAllText($fullPath, $html, (New-Object System.Text.UTF8Encoding($false)))
}

# --- PDF ---

# Why the last ConvertTo-ReportPdf call returned $false (for the caller's log)
$script:ReportPdfLastError = $null

# msedge.exe: -EdgePath if given (and it exists), else the usual install
# folders and the App Paths registry entries; $null when not found
function Find-ReportPdfEdge {
    param([string]$EdgePath)
    if ($EdgePath) {
        if (Test-Path -LiteralPath $EdgePath -PathType Leaf) { return (Resolve-Path -LiteralPath $EdgePath).ProviderPath }
        return $null
    }
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if ($root) { $candidates.Add((Join-Path $root "Microsoft\Edge\Application\msedge.exe")) }
    }
    foreach ($key in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe")) {
        try {
            $item = Get-Item -LiteralPath $key -ErrorAction Stop
            $value = [string]$item.GetValue("")
            if ($value) { $candidates.Add([Environment]::ExpandEnvironmentVariables($value.Trim().Trim('"'))) }
        }
        catch { Write-Verbose "No App Paths entry at $key" }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
    }
    return $null
}

# file:/// URL of a local path, each segment percent-encoded
function ConvertTo-ReportPdfFileUrl {
    param([string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.StartsWith("\\")) {
        $segments = $full.Substring(2).Split('\')
        return "file://" + ((@($segments | ForEach-Object { [System.Uri]::EscapeDataString($_) })) -join "/")
    }
    $segments = $full.Split('\')
    $encoded = @($segments[0]) + @($segments | Select-Object -Skip 1 | ForEach-Object { [System.Uri]::EscapeDataString($_) })
    return "file:///" + ($encoded -join "/")
}

# Ids of the Edge processes that use the given (temporary) profile folder
# (every Edge process has it on its command line); $null when the process
# list cannot be read
function Get-ReportPdfEdgeProcess {
    param([string]$ProfileDirectory)
    try {
        $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop |
            Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($ProfileDirectory, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
        return , [int[]]@($processes | ForEach-Object { [int]$_.ProcessId })
    }
    catch {
        Write-Verbose "Could not list Edge processes: $($_.Exception.Message)"
        return $null
    }
}

# Stops the Edge processes that use the given (temporary) profile folder
function Stop-ReportPdfEdgeProcess {
    param([string]$ProfileDirectory)
    $ids = Get-ReportPdfEdgeProcess -ProfileDirectory $ProfileDirectory
    foreach ($id in @($ids)) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
}

# Waits until Edge has finished: msedge.exe hands the work to a new browser
# process and exits at once, so wait until no process uses the temporary
# profile. Without a process list, wait until the PDF exists and its size
# stops changing. $false on timeout.
function Wait-ReportPdfEdge {
    param([string]$ProfileDirectory, [string]$PdfPath, [datetime]$DeadlineUtc)
    $lastLength = -1
    while ([datetime]::UtcNow -lt $DeadlineUtc) {
        $ids = Get-ReportPdfEdgeProcess -ProfileDirectory $ProfileDirectory
        if ($null -ne $ids) {
            if ($ids.Count -eq 0) { return $true }
        }
        elseif (Test-Path -LiteralPath $PdfPath -PathType Leaf) {
            $length = (Get-Item -LiteralPath $PdfPath).Length
            if ($length -gt 0 -and $length -eq $lastLength) { return $true }
            $lastLength = $length
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

# Chromium writes a relative link as an absolute file:/// URI, which breaks
# when the report folder is moved or copied and shows the local path. A link
# to a file in the PDF's own folder is rewritten in place to the relative
# form "./name" (a relative URI resolves against the PDF's location, per the
# PDF spec and in Chromium's, Firefox's and Acrobat's viewers). The new
# string is padded with spaces outside the string so every byte offset (and
# the xref table) stays valid. Returns how many links were rewritten.
function Update-ReportPdfLocalLinks {
    param([string]$PdfPath, [string]$BaseUrl)
    # Latin-1 maps every byte to one character and back unchanged
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString([System.IO.File]::ReadAllBytes($PdfPath))
    $prefix = [System.Uri]::UnescapeDataString($BaseUrl)
    $builder = New-Object System.Text.StringBuilder ($text.Length)
    $position = 0
    $rewritten = 0
    foreach ($match in [regex]::Matches($text, '/URI\s*\((file:///[^()\\\r\n]*)\)')) {
        $url = $match.Groups[1].Value
        $slash = $url.LastIndexOf('/')
        $directory = [System.Uri]::UnescapeDataString($url.Substring(0, $slash + 1))
        $name = $url.Substring($slash + 1)
        $replacement = "/URI (./" + $name + ")"
        if (-not $name -or -not $directory.Equals($prefix, [System.StringComparison]::OrdinalIgnoreCase) -or $replacement.Length -gt $match.Length) { continue }
        $null = $builder.Append($text, $position, $match.Index - $position)
        $null = $builder.Append($replacement).Append([char]' ', $match.Length - $replacement.Length)
        $position = $match.Index + $match.Length
        $rewritten++
    }
    if ($rewritten -gt 0) {
        $null = $builder.Append($text, $position, $text.Length - $position)
        [System.IO.File]::WriteAllBytes($PdfPath, $latin1.GetBytes($builder.ToString()))
    }
    return $rewritten
}

# Prints the HTML report to PDF with Microsoft Edge headless (a temporary
# profile folder, deleted afterwards). Returns $true when a PDF was written;
# $false (and $script:ReportPdfLastError says why) when Edge is missing,
# times out or fails. Never throws.
function ConvertTo-ReportPdf {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$PdfPath,

        [string]$EdgePath,

        [ValidateRange(10, 3600)]
        [int]$TimeoutSeconds = 180
    )
    $script:ReportPdfLastError = $null
    $profileDirectory = $null
    $process = $null
    try {
        $htmlFull = [System.IO.Path]::GetFullPath($HtmlPath)
        if (-not (Test-Path -LiteralPath $htmlFull -PathType Leaf)) {
            $script:ReportPdfLastError = "The HTML report was not found: $htmlFull"
            return $false
        }
        $edge = Find-ReportPdfEdge -EdgePath $EdgePath
        if (-not $edge) {
            if ($EdgePath) { $script:ReportPdfLastError = "Microsoft Edge was not found at $EdgePath" }
            else { $script:ReportPdfLastError = "Microsoft Edge (msedge.exe) was not found; the PDF was not created (report.html is complete)" }
            return $false
        }
        $pdfFull = [System.IO.Path]::GetFullPath($PdfPath)
        $pdfDirectory = Split-Path -Parent $pdfFull
        if (-not (Test-Path -LiteralPath $pdfDirectory)) { New-Item -ItemType Directory -Path $pdfDirectory -Force | Out-Null }
        if (Test-Path -LiteralPath $pdfFull) { Remove-Item -LiteralPath $pdfFull -Force -ErrorAction Stop }

        $profileDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("timeline-report-edge-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $profileDirectory -Force | Out-Null
        $htmlUrl = ConvertTo-ReportPdfFileUrl -Path $htmlFull
        $arguments = @(
            "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--no-pdf-header-footer", "--generate-pdf-document-outline",
            ('"--user-data-dir=' + $profileDirectory + '"'), ('"--print-to-pdf=' + $pdfFull + '"'), ('"' + $htmlUrl + '"')
        )
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $edge
        $startInfo.Arguments = $arguments -join " "
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
        $process = [System.Diagnostics.Process]::Start($startInfo)
        # Read both streams so Edge never blocks on a full pipe
        $null = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if ($finished) { $finished = Wait-ReportPdfEdge -ProfileDirectory $profileDirectory -PdfPath $pdfFull -DeadlineUtc $deadline }
        if (-not $finished) {
            try { if (-not $process.HasExited) { $process.Kill() } } catch { Write-Verbose "Edge already exited" }
            Stop-ReportPdfEdgeProcess -ProfileDirectory $profileDirectory
            Start-Sleep -Milliseconds 300
            if (Test-Path -LiteralPath $pdfFull) { Remove-Item -LiteralPath $pdfFull -Force -ErrorAction SilentlyContinue }
            $script:ReportPdfLastError = "Microsoft Edge did not finish printing the PDF within $TimeoutSeconds seconds"
            return $false
        }
        $ok = $false
        if (Test-Path -LiteralPath $pdfFull -PathType Leaf) {
            $stream = [System.IO.File]::OpenRead($pdfFull)
            try {
                $head = New-Object byte[] 5
                $read = $stream.Read($head, 0, 5)
                $ok = ($read -eq 5 -and [System.Text.Encoding]::ASCII.GetString($head) -eq "%PDF-")
            }
            finally { $stream.Dispose() }
        }
        if (-not $ok) {
            $detail = ""
            if ($errorTask.Wait(2000)) { $detail = ($errorTask.Result -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) }
            $script:ReportPdfLastError = "Microsoft Edge did not write a PDF (exit code $($process.ExitCode))"
            if ($detail) { $script:ReportPdfLastError += ": $detail" }
            if (Test-Path -LiteralPath $pdfFull) { Remove-Item -LiteralPath $pdfFull -Force -ErrorAction SilentlyContinue }
            return $false
        }
        if ((Split-Path -Parent $htmlFull) -eq $pdfDirectory) {
            $baseUrl = $htmlUrl.Substring(0, $htmlUrl.LastIndexOf('/') + 1)
            $null = Update-ReportPdfLocalLinks -PdfPath $pdfFull -BaseUrl $baseUrl
        }
        return $true
    }
    catch {
        $script:ReportPdfLastError = "PDF conversion failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        if ($process) { $process.Dispose() }
        if ($profileDirectory -and (Test-Path -LiteralPath $profileDirectory)) {
            # Edge's helper processes can hold the profile for a moment
            for ($attempt = 0; $attempt -lt 10; $attempt++) {
                if ($attempt -eq 2) { Stop-ReportPdfEdgeProcess -ProfileDirectory $profileDirectory }
                Remove-Item -LiteralPath $profileDirectory -Recurse -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath $profileDirectory)) { break }
                Start-Sleep -Milliseconds 300
            }
        }
    }
}
