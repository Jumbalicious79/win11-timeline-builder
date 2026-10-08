# =============================================================
# SRUM parser test
# Builds small SRUM databases at test time with the Windows ESE engine
# (esent.dll, the same interop the builder uses): SruDbIdMapTable with
# application names and user SIDs, Network Data Usage and Application
# Resource Usage records (plus a table the builder ignores), lays them out
# like a triage collection (Execution\SRUM\SRUDB.dat), runs
# timeline-builder.ps1 -Sources SRUM and checks every row: the per
# application, user and UTC day sums, the time (last record of the day),
# Description, User and Details. The collection also holds a SRUDB.dat that
# is not an ESE database (reported, skipped) and a bam_entries.csv that
# names one user SID. The database uses 32 KB pages, which the builder must
# take from the database header.
# Part 1 also makes a database in dirty-shutdown state (the engine stopped
# without flushing, as in a live copy), collected read-only with its logs:
# the builder must recover a temp copy in its own process (records that
# were only in the logs appear) without touching the database at the path
# recorded in the logs. A database with a damaged data page must give the
# rows of the records read before it, marked Partial. The builder's own ESE
# use must write no ESENT events to the Application event log.
#
# Part 2 checks the repair with esentutl /p: of the dirty database without
# its logs, and of a database whose header says clean but whose catalog page
# is damaged. esentutl writes ESENT events to the Application event log, so
# part 2 runs only in GitHub Actions or with -AllowSystemChanges; otherwise
# it prints SKIPPED. With Administrator rights it also saves a SOFTWARE hive
# with a ProfileList entry (a temporary HKCU key and reg save, undone
# afterwards) so a SID is named from it; without them that check is SKIPPED.
# Every run checks that the collection's files are not changed and that the
# builder's temp copies are removed.
#
# Needs Administrator rights, like the builder itself (GitHub Actions
# Windows runners are elevated). For a local run without them, pass
# -BuilderPath with a copy of the builder that has no admin check, kept
# inside the repository (e.g. under the git-ignored reports\ folder). The
# ESE databases are made in a temp folder; that needs no admin rights.
# Exit code 0 = pass, 1 = fail.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-SrumParsers.ps1
#   powershell -ExecutionPolicy Bypass -File tests\Test-SrumParsers.ps1 -AllowSystemChanges
# =============================================================
param(
    # Allow part 2 (Application event log entries from esentutl, and as
    # Administrator a temporary HKCU key) outside GitHub Actions
    [switch]$AllowSystemChanges,
    # Builder script to test (default: the repository's timeline-builder.ps1)
    [string]$BuilderPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$builder = $BuilderPath
if (-not $builder) { $builder = Join-Path $repoRoot "timeline-builder.ps1" }
$builder = (Resolve-Path -LiteralPath $builder).Path
$builderDir = Split-Path $builder -Parent
$script:failures = 0
$allowChanges = [bool]($env:GITHUB_ACTIONS -or $AllowSystemChanges)
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# PASS/FAIL line; failures are counted and annotated on GitHub Actions
function Write-TestResult {
    param([bool]$Succeeded, [string]$Message)
    if ($Succeeded) {
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failures++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    if ($env:GITHUB_ACTIONS) { Write-Host "::error file=tests/Test-SrumParsers.ps1::$Message" }
}

# The builder refuses to run without Administrator rights (a -BuilderPath
# copy may not)
if (-not $BuilderPath -and -not $isAdmin) {
    Write-TestResult -Succeeded $false -Message "Administrator rights are required (the builder needs them). Run elevated, or pass -BuilderPath with a builder copy without the admin check."
    exit 1
}

# Run the builder with the same PowerShell edition as this script
$powershellExe = (Get-Process -Id $PID).Path

# Runs the builder on a collection (SRUM source, CSV only); returns its output
function Invoke-TimelineBuilder {
    param([string]$CollectionPath, [string]$OutputFile)
    $ErrorActionPreference = "Continue"
    $output = & $powershellExe -NoProfile -ExecutionPolicy Bypass -File $builder `
        -InputPath $CollectionPath -Sources "SRUM" -OutputFile $OutputFile -NoExcel -Viewer None 2>&1
    return , @($output | ForEach-Object { "$_" })
}

# --- ESE test writer -------------------------------------------------------
# Writes a database the way an ESENT application does: an instance with
# transaction logs (base name SRU, logs and checkpoint in the log folder),
# tables, columns and committed rows. Event logging is off. Close($true)
# stops the engine with JET_bitTermDirty (no flush, like a crash): the
# database stays in dirty-shutdown state and the last changes are only in
# the logs. C# 5 for Windows PowerShell 5.1.
$writerSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SrumTestEse
{
    // JET_COLUMNDEF
    [StructLayout(LayoutKind.Sequential)]
    public struct JetColumnDef
    {
        public uint cbStruct;
        public uint columnid;
        public uint coltyp;
        public ushort wCountry;
        public ushort langid;
        public ushort cp;
        public ushort wCollate;
        public uint cbMax;
        public uint grbit;
    }

    internal static class Native
    {
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetCreateInstance2W(out IntPtr pinstance, string szInstanceName, string szDisplayName, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetSetSystemParameterW(IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "JetSetSystemParameterW")]
        internal static extern int JetSetInstanceParameterW(ref IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetInit(ref IntPtr pinstance);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetTerm2(IntPtr instance, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetBeginSessionW(IntPtr instance, out IntPtr psesid, string szUserName, string szPassword);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetEndSession(IntPtr sesid, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetCreateDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint pdbid, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetAttachDatabase2W(IntPtr sesid, string szFilename, uint cpgDatabaseSizeMax, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetDetachDatabaseW(IntPtr sesid, string szFilename);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetOpenDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint pdbid, uint grbit);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetCloseDatabase(IntPtr sesid, uint dbid, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetCreateTableW(IntPtr sesid, uint dbid, string szTableName, uint lPages, uint lDensity, out IntPtr ptableid);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetOpenTableW(IntPtr sesid, uint dbid, string szTableName, IntPtr pvParameters, uint cbParameters, uint grbit, out IntPtr ptableid);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetAddColumnW(IntPtr sesid, IntPtr tableid, string szColumnName, ref JetColumnDef pcolumndef, byte[] pvDefault, uint cbDefault, out uint pcolumnid);
        [DllImport("esent.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int JetGetTableColumnInfoW(IntPtr sesid, IntPtr tableid, string szColumnName, ref JetColumnDef pvResult, uint cbMax, uint infoLevel);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetBeginTransaction(IntPtr sesid);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetCommitTransaction(IntPtr sesid, uint grbit);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetRollback(IntPtr sesid, uint grbit);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetPrepareUpdate(IntPtr sesid, IntPtr tableid, uint prep);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetSetColumn(IntPtr sesid, IntPtr tableid, uint columnid, byte[] pvData, uint cbData, uint grbit, IntPtr psetinfo);
        [DllImport("esent.dll", ExactSpelling = true)]
        internal static extern int JetUpdate(IntPtr sesid, IntPtr tableid, IntPtr pvBookmark, uint cbBookmark, IntPtr pcbActual);
    }

    public sealed class TestColumn
    {
        public uint Id;
        public uint Type;
    }

    public sealed class TestEseWriter : IDisposable
    {
        IntPtr instance;
        IntPtr sesid;
        uint dbid;
        string databasePath;
        readonly Dictionary<string, IntPtr> tables = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, Dictionary<string, TestColumn>> columns = new Dictionary<string, Dictionary<string, TestColumn>>(StringComparer.OrdinalIgnoreCase);

        static void Check(string api, int err)
        {
            if (err < 0) throw new InvalidOperationException(api + " failed with JET error " + err);
        }

        void SetString(uint param, string value)
        {
            Check("JetSetSystemParameter " + param, Native.JetSetInstanceParameterW(ref instance, IntPtr.Zero, param, IntPtr.Zero, value));
        }

        void SetNumber(uint param, int value)
        {
            Check("JetSetSystemParameter " + param, Native.JetSetInstanceParameterW(ref instance, IntPtr.Zero, param, new IntPtr(value), null));
        }

        public TestEseWriter(string logFolder, string baseName, int pageSize)
        {
            string folder = Path.GetFullPath(logFolder).TrimEnd('\\') + "\\";
            // JET_paramDatabasePageSize (process-wide)
            Check("JetSetSystemParameter page size", Native.JetSetSystemParameterW(IntPtr.Zero, IntPtr.Zero, 64, new IntPtr(pageSize), null));
            Check("JetCreateInstance2", Native.JetCreateInstance2W(out instance, "SrumTest" + Guid.NewGuid().ToString("N"), "SRUM test writer", 0));
            SetString(0, folder);      // JET_paramSystemPath
            SetString(1, folder);      // JET_paramTempPath
            SetString(2, folder);      // JET_paramLogFilePath
            SetString(3, baseName);    // JET_paramBaseName
            SetNumber(100, 1);         // JET_paramCreatePathIfNotExist
            SetNumber(50, 1);          // JET_paramNoInformationEvent
            SetNumber(51, 0);          // JET_paramEventLoggingLevel: off
            Check("JetInit", Native.JetInit(ref instance));
            Check("JetBeginSession", Native.JetBeginSessionW(instance, out sesid, null, null));
        }

        public void CreateDatabase(string path)
        {
            databasePath = Path.GetFullPath(path);
            Check("JetCreateDatabase", Native.JetCreateDatabaseW(sesid, databasePath, null, out dbid, 0));
        }

        public void OpenDatabase(string path)
        {
            databasePath = Path.GetFullPath(path);
            Check("JetAttachDatabase2", Native.JetAttachDatabase2W(sesid, databasePath, 0, 0));
            Check("JetOpenDatabase", Native.JetOpenDatabaseW(sesid, databasePath, null, out dbid, 0));
        }

        public void CreateTable(string name)
        {
            IntPtr tableid;
            Check("JetCreateTable " + name, Native.JetCreateTableW(sesid, dbid, name, 0, 100, out tableid));
            tables[name] = tableid;
            columns[name] = new Dictionary<string, TestColumn>(StringComparer.OrdinalIgnoreCase);
        }

        // An existing table; its columns are looked up by name (JET_ColInfo)
        public void OpenTable(string name, string[] columnNames)
        {
            IntPtr tableid;
            Check("JetOpenTable " + name, Native.JetOpenTableW(sesid, dbid, name, IntPtr.Zero, 0, 0, out tableid));
            tables[name] = tableid;
            Dictionary<string, TestColumn> map = new Dictionary<string, TestColumn>(StringComparer.OrdinalIgnoreCase);
            foreach (string columnName in columnNames)
            {
                JetColumnDef def = new JetColumnDef();
                def.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef));
                Check("JetGetTableColumnInfo " + columnName, Native.JetGetTableColumnInfoW(sesid, tableid, columnName, ref def, def.cbStruct, 0));
                TestColumn column = new TestColumn();
                column.Id = def.columnid;
                column.Type = def.coltyp;
                map[columnName] = column;
            }
            columns[name] = map;
        }

        // coltyp: JET_coltyp value; grbit: JET_bitColumn* flags
        public void AddColumn(string table, string name, uint coltyp, uint grbit)
        {
            JetColumnDef def = new JetColumnDef();
            def.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef));
            def.coltyp = coltyp;
            def.grbit = grbit;
            if (coltyp == 10 || coltyp == 12) def.cp = 1200;
            uint columnid;
            Check("JetAddColumn " + name, Native.JetAddColumnW(sesid, tables[table], name, ref def, null, 0, out columnid));
            TestColumn column = new TestColumn();
            column.Id = columnid;
            column.Type = coltyp;
            columns[table][name] = column;
        }

        static byte[] ToBytes(uint coltyp, object value)
        {
            // Values passed from PowerShell may arrive wrapped in a PSObject
            if (value != null && value.GetType().FullName == "System.Management.Automation.PSObject")
            {
                value = value.GetType().GetProperty("BaseObject").GetValue(value, null);
            }
            switch (coltyp)
            {
                case 2: return new byte[] { Convert.ToByte(value) };
                case 4: return BitConverter.GetBytes(Convert.ToInt32(value));
                case 15: return BitConverter.GetBytes(Convert.ToInt64(value));
                case 8: return BitConverter.GetBytes(((DateTime)value).ToOADate());
                case 10:
                case 12: return Encoding.Unicode.GetBytes(Convert.ToString(value));
            }
            return (byte[])value;
        }

        // One committed row; null values stay NULL
        public void Insert(string table, string[] names, object[] values)
        {
            IntPtr tableid = tables[table];
            Check("JetBeginTransaction", Native.JetBeginTransaction(sesid));
            bool committed = false;
            try
            {
                Check("JetPrepareUpdate", Native.JetPrepareUpdate(sesid, tableid, 0));
                for (int i = 0; i < names.Length; i++)
                {
                    if (values[i] == null) continue;
                    TestColumn column = columns[table][names[i]];
                    byte[] data = ToBytes(column.Type, values[i]);
                    Check("JetSetColumn " + names[i], Native.JetSetColumn(sesid, tableid, column.Id, data, (uint)data.Length, 0, IntPtr.Zero));
                }
                Check("JetUpdate", Native.JetUpdate(sesid, tableid, IntPtr.Zero, 0, IntPtr.Zero));
                Check("JetCommitTransaction", Native.JetCommitTransaction(sesid, 0));
                committed = true;
            }
            finally
            {
                if (!committed) Native.JetRollback(sesid, 0);
            }
        }

        public void Close(bool dirty)
        {
            if (dirty)
            {
                Native.JetTerm2(instance, 0x8);   // JET_bitTermDirty
                instance = IntPtr.Zero;
                return;
            }
            foreach (IntPtr tableid in tables.Values) Native.JetCloseTable(sesid, tableid);
            tables.Clear();
            Native.JetCloseDatabase(sesid, dbid, 0);
            Native.JetDetachDatabaseW(sesid, databasePath);
            Native.JetEndSession(sesid, 0);
            Check("JetTerm2", Native.JetTerm2(instance, 0x1));   // JET_bitTermComplete
            instance = IntPtr.Zero;
        }

        public void Dispose()
        {
            if (instance != IntPtr.Zero)
            {
                Native.JetTerm2(instance, 0x2);   // JET_bitTermAbrupt
                instance = IntPtr.Zero;
            }
        }
    }
}
'@
if (-not ([System.Management.Automation.PSTypeName]'SrumTestEse.TestEseWriter').Type) {
    Add-Type -TypeDefinition $writerSource
}

# --- SRUM-like schema ------------------------------------------------------
# JET_coltyp: 2 UnsignedByte, 4 Long, 8 DateTime, 11 LongBinary, 15 LongLong;
# grbit 1 = JET_bitColumnFixed, 0x10 = JET_bitColumnAutoincrement
$idMapTable = "SruDbIdMapTable"
$networkTable = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
$appTable = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
$connectivityTable = "{DD6636C4-8929-4683-974E-22C046A43763}"
$schema = [ordered]@{
    $idMapTable        = @(@("IdType", 2, 1), @("IdIndex", 4, 1), @("IdBlob", 11, 0))
    $networkTable      = @(@("AutoIncId", 4, 0x10), @("TimeStamp", 8, 1), @("AppId", 4, 1), @("UserId", 4, 1), @("InterfaceLuid", 15, 1),
        @("L2ProfileId", 4, 1), @("L2ProfileFlags", 4, 1), @("BytesSent", 15, 1), @("BytesRecvd", 15, 1))
    $appTable          = @(@("AutoIncId", 4, 0x10), @("TimeStamp", 8, 1), @("AppId", 4, 1), @("UserId", 4, 1), @("ForegroundCycleTime", 15, 1),
        @("BackgroundCycleTime", 15, 1), @("FaceTime", 15, 1), @("ForegroundContextSwitches", 4, 1), @("BackgroundContextSwitches", 4, 1),
        @("ForegroundBytesRead", 15, 1), @("ForegroundBytesWritten", 15, 1), @("ForegroundNumReadOperations", 4, 1),
        @("ForegroundNumWriteOperations", 4, 1), @("ForegroundNumberOfFlushes", 4, 1), @("BackgroundBytesRead", 15, 1),
        @("BackgroundBytesWritten", 15, 1), @("BackgroundNumReadOperations", 4, 1), @("BackgroundNumWriteOperations", 4, 1),
        @("BackgroundNumberOfFlushes", 4, 1))
    $connectivityTable = @(@("AutoIncId", 4, 0x10), @("TimeStamp", 8, 1), @("AppId", 4, 1), @("UserId", 4, 1), @("InterfaceLuid", 15, 1),
        @("L2ProfileId", 4, 1), @("ConnectedTime", 4, 1), @("ConnectStartTime", 15, 1), @("L2ProfileFlags", 4, 1))
}
$networkNames = [string[]]@("TimeStamp", "AppId", "UserId", "InterfaceLuid", "L2ProfileId", "BytesSent", "BytesRecvd")
$appNames = [string[]]@("TimeStamp", "AppId", "UserId", "ForegroundCycleTime", "BackgroundCycleTime", "ForegroundBytesRead",
    "ForegroundBytesWritten", "BackgroundBytesRead", "BackgroundBytesWritten", "FaceTime")

# Test user SIDs: alice is named by bam_entries.csv, carol only by the
# ProfileList of the SOFTWARE hive (part 2, as Administrator)
$aliceSid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
$carolSid = "S-1-5-21-1111111111-2222222222-3333333333-1002"

# Record time as stored by SRUM (an OLE Automation date, UTC wall time)
function ConvertTo-RecordTime {
    param([string]$Text)
    return [datetime]::ParseExact($Text, "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Binary form of a SID string
function ConvertTo-SidBytes {
    param([string]$Sid)
    $identifier = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $bytes = [byte[]]::new($identifier.BinaryLength)
    $identifier.GetBinaryForm($bytes, 0)
    return , $bytes
}

# InterfaceLuid with the given IANA interface type in its top 16 bits
function New-InterfaceLuid {
    param([long]$IfType, [long]$Index)
    return ($IfType -shl 48) -bor ($Index -shl 24)
}

# Network Data Usage records, each @(time, AppId, UserId, InterfaceLuid,
# L2ProfileId, BytesSent, BytesRecvd); an empty time leaves TimeStamp NULL
function Add-NetworkRecords {
    param($Writer, [object[]]$Records)
    foreach ($r in $Records) {
        $timeValue = $null
        if ($r[0]) { $timeValue = ConvertTo-RecordTime $r[0] }
        $Writer.Insert($networkTable, $networkNames, [object[]]@($timeValue, [int]$r[1], [int]$r[2], [long]$r[3], [int]$r[4], [long]$r[5], [long]$r[6]))
    }
}

# Application Resource Usage records, each @(time, AppId, UserId,
# ForegroundCycleTime, BackgroundCycleTime, ForegroundBytesRead,
# ForegroundBytesWritten, BackgroundBytesRead, BackgroundBytesWritten,
# FaceTime)
function Add-AppRecords {
    param($Writer, [object[]]$Records)
    foreach ($r in $Records) {
        $values = @((ConvertTo-RecordTime $r[0]), [int]$r[1], [int]$r[2])
        foreach ($v in $r[3..9]) { $values += [long]$v }
        $Writer.Insert($appTable, $appNames, [object[]]$values)
    }
}

# A new SRUM database: the four tables and the id map. Returns the writer
# (open); the caller adds records and closes it.
function New-SrumDatabase {
    param([string]$DatabasePath, [string]$LogFolder, [int]$PageSize)
    New-Item -ItemType Directory -Path (Split-Path $DatabasePath -Parent), $LogFolder -Force | Out-Null
    $writer = New-Object SrumTestEse.TestEseWriter($LogFolder, "SRU", $PageSize)
    $writer.CreateDatabase($DatabasePath)
    foreach ($table in $schema.Keys) {
        $writer.CreateTable($table)
        foreach ($column in $schema[$table]) { $writer.AddColumn($table, $column[0], [uint32]$column[1], [uint32]$column[2]) }
    }
    # Id map: IdType 0, 1 and 2 entries name applications (UTF-16), IdType 3
    # entries hold a binary user SID
    $u = [System.Text.Encoding]::Unicode
    $entries = @(
        @(0, 1, $u.GetBytes("\device\harddiskvolume3\program files\google\chrome\application\chrome.exe")),
        @(0, 2, $u.GetBytes("\device\harddiskvolume3\users\alice\appdata\local\temp\upload tool.exe")),
        @(2, 3, $u.GetBytes("Microsoft.Windows.Photos_8wekyb3d8bbwe")),
        @(1, 4, $u.GetBytes("DiagTrack")),
        @(3, 10, (ConvertTo-SidBytes $aliceSid)),
        @(3, 11, (ConvertTo-SidBytes "S-1-5-18")),
        @(3, 12, (ConvertTo-SidBytes $carolSid))
    )
    foreach ($entry in $entries) {
        $writer.Insert($idMapTable, [string[]]@("IdType", "IdIndex", "IdBlob"), [object[]]@([int]$entry[0], [int]$entry[1], [byte[]]$entry[2]))
    }
    return $writer
}

# SHA256 of every file below a folder (relative path -> hash)
function Get-FolderHashes {
    param([string]$Path)
    $hashes = @{}
    foreach ($file in (Get-ChildItem -LiteralPath $Path -File -Recurse -Force)) {
        $hashes[$file.FullName.Substring($Path.Length)] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $hashes
}

function Test-SameHashes {
    param([hashtable]$Before, [hashtable]$After)
    if ($Before.Count -ne $After.Count) { return $false }
    foreach ($key in $Before.Keys) { if ($After[$key] -ne $Before[$key]) { return $false } }
    return $true
}

# Checks the rows of a timeline against the expected rows: each expected
# row (Time, Source, Type, Text = Description, User, Has / Lacks = text the
# Details must or must not contain) must be there exactly once; with
# -Exact, no other row may be there
function Test-TimelineRows {
    param([object[]]$Rows, [object[]]$Expected, [string]$Label, [switch]$Exact)
    $byKey = @{}
    foreach ($row in $Rows) {
        $key = "$($row.Timestamp) | $($row.Source) | $($row.EventType) | $($row.Description)"
        if (-not $byKey.ContainsKey($key)) { $byKey[$key] = New-Object System.Collections.Generic.List[object] }
        $byKey[$key].Add($row)
    }
    $expectedKeys = @()
    foreach ($e in $Expected) {
        $key = "$($e.Time) | $($e.Source) | $($e.Type) | $($e.Text)"
        $expectedKeys += $key
        if (-not $byKey.ContainsKey($key)) {
            Write-TestResult -Succeeded $false -Message "${Label}: missing row: $key"
            continue
        }
        $found = $byKey[$key]
        $row = $found[0]
        $problems = @()
        if ($found.Count -ne 1) { $problems += "$($found.Count) rows" }
        if ($row.User -cne $e.User) { $problems += "User is '$($row.User)' (expected '$($e.User)')" }
        foreach ($text in @($e.Has)) { if ($text -and -not $row.Details.Contains($text)) { $problems += "Details lacks '$text'" } }
        foreach ($text in @($e.Lacks)) { if ($text -and $row.Details.Contains($text)) { $problems += "Details has '$text'" } }
        if ($row.Artifact -ne "SRUM") { $problems += "Artifact is '$($row.Artifact)'" }
        if ($problems.Count -gt 0) { Write-TestResult -Succeeded $false -Message "${Label}: $key -- $($problems -join '; ') (Details: $($row.Details))" }
        else { Write-TestResult -Succeeded $true -Message "${Label}: $key" }
    }
    if ($Exact) {
        # Hashtable keys are case-insensitive; compare the row texts exactly
        foreach ($key in @($byKey.Keys | Where-Object { $expectedKeys -cnotcontains $_ })) {
            Write-TestResult -Succeeded $false -Message "${Label}: unexpected row: $key"
        }
        Write-TestResult -Succeeded ($Rows.Count -eq $Expected.Count) -Message "${Label}: $($Rows.Count) rows in the timeline ($($Expected.Count) expected)"
    }
}

# Damages a database page: XORs Count bytes at Offset (more than the page
# checksum's error correction can repair, so reading the page fails)
function Write-DamagedBytes {
    param([string]$Path, [long]$Offset, [int]$Count)
    $stream = [System.IO.File]::Open($Path, "Open", "ReadWrite", "None")
    try {
        $bytes = New-Object byte[] $Count
        $stream.Position = $Offset
        $read = $stream.Read($bytes, 0, $Count)
        for ($i = 0; $i -lt $read; $i++) { $bytes[$i] = $bytes[$i] -bxor 0x5A }
        $stream.Position = $Offset
        $stream.Write($bytes, 0, $read)
    }
    finally { $stream.Dispose() }
}

# Offset of a byte sequence in a file, or -1 (Latin-1 maps every byte to
# one character, so a string search finds it)
function Find-FileBytes {
    param([string]$Path, [byte[]]$Pattern)
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    return $latin1.GetString([System.IO.File]::ReadAllBytes($Path)).IndexOf($latin1.GetString($Pattern), [System.StringComparison]::Ordinal)
}

# A timeline collection folder with collection_info.json and bam_entries.csv
# (alice) and an empty Execution\SRUM folder; returns that SRUM folder
function New-TestCollection {
    param([string]$Path)
    $srum = Join-Path $Path "Execution\SRUM"
    New-Item -ItemType Directory -Path $srum -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $Path "collection_info.json"),
        '{"Mode":"Live","CollectionStartUtc":"2026-03-07T00:00:00Z","CollectorTimeZoneId":"UTC","TargetTimeZoneId":"UTC"}')
    # bam_entries.csv names alice's SID (the collector writes it on live systems)
    [System.IO.File]::WriteAllText((Join-Path $Path "Execution\bam_entries.csv"),
        "`"Sid`",`"User`",`"Path`",`"LastExecutionUtc`"`r`n`"$aliceSid`",`"alice`",`"\Device\HarddiskVolume3\Windows\notepad.exe`",`"2026-03-01T10:00:00.0000000Z`"`r`n")
    return $srum
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("srum-test-" + [guid]::NewGuid().ToString("N"))
$reportsDir = Join-Path $builderDir "reports"
$reportsBefore = @(Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$tempBefore = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "TimelineSrum_*" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$testKeyPath = "Software\TriageTimelineTest_" + [guid]::NewGuid().ToString("N")
$hiveMade = $false
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    # =========================================================
    # Part 1: a clean database (32 KB pages)
    # =========================================================
    $part1Start = Get-Date
    $collection = Join-Path $workDir "collection"
    $srumDir = New-TestCollection $collection

    $writer = New-SrumDatabase -DatabasePath (Join-Path $srumDir "SRUDB.dat") -LogFolder (Join-Path $workDir "clean-logs") -PageSize 32768
    try {
        $wifi = New-InterfaceLuid -IfType 71 -Index 1
        $ethernet = New-InterfaceLuid -IfType 6 -Index 2
        Add-NetworkRecords -Writer $writer -Records @(
            # chrome.exe / alice on 2026-03-01: three hourly records, one day
            # row at the last one (23:00): 100 MB + 20.4 MB sent, 1 MB + 2.2 MB
            # received
            @("2026-03-01 10:00:00", 1, 10, $wifi, 268435457, 104857600, 1048576),
            @("2026-03-01 11:00:00", 1, 10, $ethernet, 0, 21390131, 2306867),
            @("2026-03-01 23:00:00", 1, 10, $wifi, 268435457, 0, 0),
            # Next UTC day: its own row
            @("2026-03-02 00:30:00", 1, 10, $wifi, 268435457, 512, 1536),
            # upload tool.exe / alice: 5 GB sent
            @("2026-03-01 14:00:00", 2, 10, $ethernet, 0, 5368709120, 10240),
            # An AppId that is not in the id map, for a SID without a name
            @("2026-03-01 09:00:00", 99, 12, $wifi, 268435457, 2048, 4096),
            # A record without a time: skipped (and counted)
            @("", 1, 10, $wifi, 0, 777, 777)
        )
        # Application Resource Usage: Photos (packaged app) / alice, two
        # records; DiagTrack (service) / SYSTEM, one record
        Add-AppRecords -Writer $writer -Records @(
            @("2026-03-01 10:00:00", 3, 10, 1000, 200, 4096, 1024, 0, 0, 600000000),
            @("2026-03-01 12:00:00", 3, 10, 3000, 800, 4096, 1024, 2048, 512, 1200000000),
            @("2026-03-01 08:00:00", 4, 11, 0, 50000, 0, 0, 1048576, 2097152, 0)
        )
        # Network Connectivity (not parsed)
        $writer.Insert($connectivityTable, [string[]]@("TimeStamp", "AppId", "UserId", "ConnectedTime"), [object[]]@((ConvertTo-RecordTime "2026-03-01 10:00:00"), 1, 10, 3600))
        $writer.Close($false)
    }
    finally { $writer.Dispose() }

    # A SRUDB.dat that is not an ESE database: reported and skipped
    $bogus = Join-Path $collection "Other\SRUDB.dat"
    New-Item -ItemType Directory -Path (Split-Path $bogus -Parent) | Out-Null
    [System.IO.File]::WriteAllText($bogus, "not an ESE database")

    # Part 2 as Administrator: a SOFTWARE hive whose ProfileList names carol
    $carolUser = $carolSid
    if ($allowChanges -and $isAdmin) {
        $baseKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("$testKeyPath\Microsoft\Windows NT\CurrentVersion\ProfileList\$carolSid")
        try { $baseKey.SetValue("ProfileImagePath", "C:\Users\carol", [Microsoft.Win32.RegistryValueKind]::ExpandString) }
        finally { $baseKey.Close() }
        New-Item -ItemType Directory -Path (Join-Path $collection "Registry") | Out-Null
        $ErrorActionPreference = "Continue"
        $saveOutput = & reg save "HKCU\$testKeyPath" (Join-Path $collection "Registry\SOFTWARE") /y 2>&1
        $saveExit = $LASTEXITCODE
        $ErrorActionPreference = "Stop"
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKeyPath)
        if ($saveExit -ne 0) { throw "reg save failed: $saveOutput" }
        $hiveMade = $true
        $carolUser = "carol"
    }
    else {
        Write-Host "SKIPPED: SID name from the SOFTWARE hive's ProfileList (needs Administrator rights and GitHub Actions or -AllowSystemChanges)" -ForegroundColor Yellow
    }

    $hashesBefore = Get-FolderHashes $collection
    $timelineCsv = Join-Path $workDir "timeline.csv"
    Write-Host "Running the builder ($powershellExe) on $collection ..."
    $builderOutput = Invoke-TimelineBuilder -CollectionPath $collection -OutputFile $timelineCsv
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $timelineCsv)) {
        $builderOutput | ForEach-Object { Write-Host "  | $_" }
        Write-TestResult -Succeeded $false -Message "the builder exited with code $LASTEXITCODE or wrote no timeline"
        exit 1
    }
    $rows = @(Import-Csv -LiteralPath $timelineCsv)

    $chromePath = "\device\harddiskvolume3\program files\google\chrome\application\chrome.exe"
    $uploadPath = "\device\harddiskvolume3\users\alice\appdata\local\temp\upload tool.exe"
    $expected = @(
        @{ Time = "2026-03-01 23:00:00.000"; Source = "SRUM-Network"; Type = "NetworkConnection"; User = "alice"
            Text = "SRUM network usage: $chromePath sent 120.4 MB, received 3.2 MB"
            Has = @("Day=2026-03-01 | App=$chromePath | AppId=1 | UserSid=$aliceSid | User=alice | BytesSent=126247731 | BytesRecvd=3355443 | Records=3",
                "FirstRecordUtc=2026-03-01 10:00:00 | LastRecordUtc=2026-03-01 23:00:00", "Interfaces=Ethernet, Wi-Fi", "L2ProfileIds=268435457",
                "Time=last SRUM record of the day (UTC)")
            Lacks = @("UserId=", "Database=") }
        @{ Time = "2026-03-02 00:30:00.000"; Source = "SRUM-Network"; Type = "NetworkConnection"; User = "alice"
            Text = "SRUM network usage: $chromePath sent 512 bytes, received 1.5 KB"
            Has = @("Day=2026-03-02", "BytesSent=512 | BytesRecvd=1536 | Records=1", "Interfaces=Wi-Fi") }
        @{ Time = "2026-03-01 14:00:00.000"; Source = "SRUM-Network"; Type = "NetworkConnection"; User = "alice"
            Text = "SRUM network usage: $uploadPath sent 5.0 GB, received 10.0 KB"
            Has = @("App=$uploadPath | AppId=2", "BytesSent=5368709120 | BytesRecvd=10240", "Interfaces=Ethernet"); Lacks = @("L2ProfileIds=") }
        @{ Time = "2026-03-01 09:00:00.000"; Source = "SRUM-Network"; Type = "NetworkConnection"; User = $carolUser
            Text = "SRUM network usage: AppId 99 (not in SruDbIdMapTable) sent 2.0 KB, received 4.0 KB"
            Has = @("AppId=99 | UserSid=$carolSid", "BytesSent=2048 | BytesRecvd=4096") }
        @{ Time = "2026-03-01 12:00:00.000"; Source = "SRUM-AppUsage"; Type = "Execution"; User = "alice"
            Text = "SRUM app activity: Microsoft.Windows.Photos_8wekyb3d8bbwe"
            Has = @("Day=2026-03-01 | App=Microsoft.Windows.Photos_8wekyb3d8bbwe | AppId=3 | UserSid=$aliceSid | User=alice",
                "ForegroundCycleTime=4000 | BackgroundCycleTime=1000 | FaceTime=1800000000 | ForegroundBytesRead=8192 | ForegroundBytesWritten=2048 | BackgroundBytesRead=2048 | BackgroundBytesWritten=512",
                "BytesRead=10240 | BytesWritten=2560 | Records=2 | FirstRecordUtc=2026-03-01 10:00:00 | LastRecordUtc=2026-03-01 12:00:00")
            Lacks = @("BytesSent=", "Interfaces=") }
        @{ Time = "2026-03-01 08:00:00.000"; Source = "SRUM-AppUsage"; Type = "Execution"; User = "SYSTEM"
            Text = "SRUM app activity: DiagTrack"
            Has = @("App=DiagTrack | AppId=4 | UserSid=S-1-5-18 | User=SYSTEM", "ForegroundCycleTime=0 | BackgroundCycleTime=50000 | FaceTime=0", "BytesRead=1048576 | BytesWritten=2097152 | Records=1") }
    )
    Test-TimelineRows -Rows $rows -Expected $expected -Label "clean" -Exact

    $outputText = $builderOutput -join "`n"
    Write-TestResult -Succeeded ($outputText -match 'ESE database: 32768-byte pages, clean shutdown') -Message "clean: page size and state read from the database header"
    Write-TestResult -Succeeded ($outputText -match 'SRUM Network Data Usage: 7 record\(s\) from 2026-03-01 09:00:00 to 2026-03-02 00:30:00 UTC -> 4 app/user/day row\(s\), 4 added; sent 5\.1 GB, received 3\.2 MB in total') -Message "clean: network totals logged"
    Write-TestResult -Succeeded ($outputText -match 'Network Data Usage: 1 record\(s\) without a valid TimeStamp skipped') -Message "clean: the record without a time is reported"
    Write-TestResult -Succeeded ($outputText -match 'SRUM Application Resource Usage: 3 record\(s\) .* -> 2 app/user/day row\(s\), 2 added; read 1\.0 MB, written 2\.0 MB in total') -Message "clean: app usage totals logged"
    Write-TestResult -Succeeded ($outputText -match 'Other\\SRUDB\.dat is not an ESE database') -Message "clean: a SRUDB.dat that is not an ESE database is reported"
    Write-TestResult -Succeeded ($outputText -notmatch 'esentutl|Soft recovery|Repair') -Message "clean: no recovery or repair for a clean database"
    Write-TestResult -Succeeded ($outputText -notmatch 'SRUM reader could not be compiled|Could not open the SRUM database|Failed to parse SRUM') -Message "clean: no reader errors"
    Write-TestResult -Succeeded (Test-SameHashes $hashesBefore (Get-FolderHashes $collection)) -Message "clean: the collection's files are unchanged"
    if ($hiveMade) {
        Write-TestResult -Succeeded ($outputText -notmatch 'Failed to unload hive|Could not load hive') -Message "clean: the SOFTWARE hive was loaded and unloaded"
    }

    # =========================================================
    # Part 1, continued: a dirty-shutdown database with its logs
    # =========================================================
    # 8 KB pages; the 2026-03-05 records are written to the database file
    # (clean shutdown), the 2026-03-06 records only to the logs (the engine
    # then stops without flushing). The logs name the database by this
    # original path, which recovery must not touch.
    $dirtyDb = Join-Path $workDir "dirty\SRUDB.dat"
    $dirtyLogs = Join-Path $workDir "dirty-logs"
    $writer = New-SrumDatabase -DatabasePath $dirtyDb -LogFolder $dirtyLogs -PageSize 8192
    try {
        Add-NetworkRecords -Writer $writer -Records @(, @("2026-03-05 10:00:00", 1, 10, $wifi, 0, 1000, 2000))
        $writer.Close($false)
    }
    finally { $writer.Dispose() }
    $writer = New-Object SrumTestEse.TestEseWriter($dirtyLogs, "SRU", 8192)
    try {
        $writer.OpenDatabase($dirtyDb)
        $writer.OpenTable($networkTable, $networkNames)
        Add-NetworkRecords -Writer $writer -Records @(, @("2026-03-06 10:00:00", 2, 10, $ethernet, 0, 3000, 4000))
        $writer.Close($true)
    }
    finally { $writer.Dispose() }
    $dirtyHash = (Get-FileHash -LiteralPath $dirtyDb -Algorithm SHA256).Hash

    $day1 = @{ Time = "2026-03-05 10:00:00.000"; Source = "SRUM-Network"; Type = "NetworkConnection"; User = "alice"
        Text = "SRUM network usage: $chromePath sent 1000 bytes, received 2.0 KB" }
    $day2 = @{ Time = "2026-03-06 10:00:00.000"; Source = "SRUM-Network"; Type = "NetworkConnection"; User = "alice"
        Text = "SRUM network usage: $uploadPath sent 2.9 KB, received 3.9 KB" }

    # Runs the builder on a collection with a copy of the dirty database
    # (and the logs and checkpoint with -WithLogs); returns its output and
    # rows, or $null if it failed
    function Invoke-DirtyCase {
        param([string]$Case, [switch]$WithLogs, [switch]$ReadOnly)
        $caseCollection = Join-Path $workDir "collection-$Case"
        $caseSrum = New-TestCollection $caseCollection
        Copy-Item -Path (Join-Path (Split-Path $dirtyDb -Parent) "*") -Destination $caseSrum
        if ($WithLogs) { Copy-Item -Path (Join-Path $dirtyLogs "SRU*") -Destination $caseSrum }
        # Evidence is often marked read-only; the builder's temp copies must
        # still be recoverable
        if ($ReadOnly) {
            foreach ($file in (Get-ChildItem -LiteralPath $caseSrum -File)) { $file.Attributes = [System.IO.FileAttributes]::ReadOnly }
        }
        $stateByte = [System.IO.File]::ReadAllBytes((Join-Path $caseSrum "SRUDB.dat"))[52]
        Write-TestResult -Succeeded ($stateByte -eq 2) -Message "${Case}: the test database is in dirty-shutdown state"
        $caseBefore = Get-FolderHashes $caseCollection
        $caseCsv = Join-Path $workDir "timeline-$Case.csv"
        Write-Host "Running the builder on $caseCollection ..."
        $caseOutput = Invoke-TimelineBuilder -CollectionPath $caseCollection -OutputFile $caseCsv
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $caseCsv)) {
            $caseOutput | ForEach-Object { Write-Host "  | $_" }
            Write-TestResult -Succeeded $false -Message "${Case}: the builder exited with code $LASTEXITCODE or wrote no timeline"
            return $null
        }
        Write-TestResult -Succeeded (Test-SameHashes $caseBefore (Get-FolderHashes $caseCollection)) -Message "${Case}: the collection's files are unchanged"
        if ($ReadOnly) {
            $notReadOnly = @(Get-ChildItem -LiteralPath $caseSrum -File | Where-Object { -not $_.IsReadOnly })
            Write-TestResult -Succeeded ($notReadOnly.Count -eq 0) -Message "${Case}: the collection's files are still read-only"
        }
        Write-TestResult -Succeeded ((Get-FileHash -LiteralPath $dirtyDb -Algorithm SHA256).Hash -eq $dirtyHash) -Message "${Case}: the database at the path recorded in the logs is not touched"
        $caseText = $caseOutput -join "`n"
        Write-TestResult -Succeeded ($caseText -match 'ESE database: 8192-byte pages, dirty shutdown') -Message "${Case}: dirty-shutdown state and 8 KB pages read from the header"
        return [PSCustomObject]@{ Text = $caseText; Rows = @(Import-Csv -LiteralPath $caseCsv) }
    }

    # Soft recovery in the builder's process (no esentutl, no events), on
    # read-only evidence
    $recovery = Invoke-DirtyCase -Case "recovery" -WithLogs -ReadOnly
    if ($recovery) {
        Write-TestResult -Succeeded ($recovery.Text -match 'Soft recovery succeeded\.') -Message "recovery: soft recovery with the collected logs succeeded"
        Write-TestResult -Succeeded ($recovery.Text -notmatch 'esentutl|Repair') -Message "recovery: done in the builder's process (no esentutl, no repair)"
        $day1.Has = @("Database=soft recovery (in-process)")
        $day2.Has = @("Database=soft recovery (in-process)", "BytesSent=3000 | BytesRecvd=4000")
        # The 2026-03-06 record was only in the logs
        Test-TimelineRows -Rows $recovery.Rows -Expected @($day1, $day2) -Label "recovery" -Exact
    }

    # =========================================================
    # Part 1, continued: a damaged data page
    # =========================================================
    # 400 records on 2026-03-03, a marker record, 400 on 2026-03-04. The page
    # holding the marker is damaged: the scan stops there, the rows keep the
    # records read before it (marked Partial) and 2026-03-04 has no row.
    $damagedCollection = Join-Path $workDir "collection-damaged"
    $damagedSrum = New-TestCollection $damagedCollection
    $damagedDb = Join-Path $damagedSrum "SRUDB.dat"
    $writer = New-SrumDatabase -DatabasePath $damagedDb -LogFolder (Join-Path $workDir "damaged-logs") -PageSize 8192
    try {
        $records = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 400; $i++) { $records.Add(@(([datetime]"2026-03-03 00:00:00").AddMinutes($i).ToString("yyyy-MM-dd HH:mm:ss"), 1, 10, $wifi, 0, 100, 1)) }
        $records.Add(@("2026-03-03 23:00:00", 1, 10, $wifi, 0, 0x0123456789ABCDEF, 1))
        for ($i = 0; $i -lt 400; $i++) { $records.Add(@(([datetime]"2026-03-04 00:00:00").AddMinutes($i).ToString("yyyy-MM-dd HH:mm:ss"), 1, 10, $wifi, 0, 100, 1)) }
        Add-NetworkRecords -Writer $writer -Records $records.ToArray()
        $writer.Close($false)
    }
    finally { $writer.Dispose() }
    $markerOffset = Find-FileBytes -Path $damagedDb -Pattern ([BitConverter]::GetBytes([long]0x0123456789ABCDEF))
    if ($markerOffset -lt 0) {
        Write-TestResult -Succeeded $false -Message "damaged: marker record not found in the test database"
    }
    else {
        Write-DamagedBytes -Path $damagedDb -Offset $markerOffset -Count 32
        $damagedCsv = Join-Path $workDir "timeline-damaged.csv"
        Write-Host "Running the builder on $damagedCollection ..."
        $damagedOutput = Invoke-TimelineBuilder -CollectionPath $damagedCollection -OutputFile $damagedCsv
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $damagedCsv)) {
            $damagedOutput | ForEach-Object { Write-Host "  | $_" }
            Write-TestResult -Succeeded $false -Message "damaged: the builder exited with code $LASTEXITCODE or wrote no timeline"
        }
        else {
            $damagedText = $damagedOutput -join "`n"
            $damagedRows = @(Import-Csv -LiteralPath $damagedCsv)
            $partialRows = @($damagedRows | Where-Object { $_.Timestamp -like "2026-03-03 *" -and $_.Source -eq "SRUM-Network" })
            $partialCount = 0
            if ($partialRows.Count -eq 1 -and $partialRows[0].Details -match 'Records=(\d+)') { $partialCount = [int]$Matches[1] }
            Write-TestResult -Succeeded ($partialRows.Count -eq 1 -and $partialCount -gt 0 -and $partialCount -lt 400 -and $partialRows[0].Details -match 'Partial=yes') -Message "damaged: the records before the damaged page give a row marked Partial ($partialCount record(s))"
            Write-TestResult -Succeeded (-not ($damagedRows | Where-Object { $_.Timestamp -like "2026-03-04 *" })) -Message "damaged: no row from after the damaged page"
            # The ESE error depends on what the damage hits (checksum or
            # page structure): -1018 or -1206
            $errorReported = $damagedText -match 'Network Data Usage: read error after \d+ record\(s\): JetMove\(\{973F5D5C-1D90-4944-BE8E-24B94231A174\}\) failed: JET_err\w+ \(-\d+\)'
            Write-TestResult -Succeeded $errorReported -Message "damaged: the read error is reported"
            if (-not $errorReported) { $damagedOutput | Where-Object { $_ -match 'SRUM|ESE|error' } | ForEach-Object { Write-Host "  | $_" } }
            Write-TestResult -Succeeded ($damagedText -notmatch 'esentutl|Repair|Failed to parse SRUM') -Message "damaged: no repair and no parser failure"
        }
    }

    # The builder's own ESE use (reader and in-process recovery) writes
    # nothing to the Application event log
    $part1End = Get-Date
    $eventFilter = @{ LogName = "Application"; ProviderName = "ESENT"; StartTime = $part1Start; EndTime = $part1End.AddSeconds(5) }
    $eventError = $null
    $ownEvents = @(Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue -ErrorVariable eventError |
        Where-Object { $_.Message -match 'TimelineSrum_|TimelineEse|srum-test-' })
    # "No events found" is reported as an error too
    $readError = @($eventError | Where-Object { $_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' })
    if ($readError.Count -gt 0) {
        Write-Host "SKIPPED: ESENT event check (Application log not readable: $($readError[0].Exception.Message))" -ForegroundColor Yellow
    }
    else {
        Write-TestResult -Succeeded ($ownEvents.Count -eq 0) -Message "no ESENT events from the builder's reader and recovery$(if ($ownEvents) { ': event ID(s) ' + (($ownEvents | ForEach-Object { $_.Id }) -join ', ') })"
    }

    # =========================================================
    # Part 2: repair (esentutl /p)
    # =========================================================
    if (-not $allowChanges) {
        Write-Host "SKIPPED: repair with esentutl (it writes ESENT events to the Application event log); run with -AllowSystemChanges or in GitHub Actions" -ForegroundColor Yellow
    }
    else {
        # Without logs soft recovery is not possible: the copy is repaired
        $repair = Invoke-DirtyCase -Case "repair"
        if ($repair) {
            Write-TestResult -Succeeded ($repair.Text -match 'No SRUM transaction logs') -Message "repair: missing logs reported"
            Write-TestResult -Succeeded ($repair.Text -match 'Repair was needed') -Message "repair: the repair is reported"
            $day1.Has = @("Database=repair (esentutl /p)")
            # Records only in the (missing) logs are lost; the rows that
            # were in the database file must be there
            Test-TimelineRows -Rows $repair.Rows -Expected @($day1) -Label "repair"
        }

        # A database whose header says clean but whose catalog index page
        # (page 10, checked when the database is attached) is damaged cannot
        # be opened: it is repaired once and opened again
        $catalogCollection = Join-Path $workDir "collection-catalog"
        $catalogSrum = New-TestCollection $catalogCollection
        $catalogDb = Join-Path $catalogSrum "SRUDB.dat"
        $writer = New-SrumDatabase -DatabasePath $catalogDb -LogFolder (Join-Path $workDir "catalog-logs") -PageSize 8192
        try {
            Add-NetworkRecords -Writer $writer -Records @(, @("2026-03-05 10:00:00", 1, 10, $wifi, 0, 1000, 2000))
            $writer.Close($false)
        }
        finally { $writer.Dispose() }
        # Page n starts at (n + 1) * page size (two header pages)
        Write-DamagedBytes -Path $catalogDb -Offset (11 * 8192 + 100) -Count 32
        $catalogCsv = Join-Path $workDir "timeline-catalog.csv"
        $catalogBefore = Get-FolderHashes $catalogCollection
        Write-Host "Running the builder on $catalogCollection ..."
        $catalogOutput = Invoke-TimelineBuilder -CollectionPath $catalogCollection -OutputFile $catalogCsv
        Write-TestResult -Succeeded (Test-SameHashes $catalogBefore (Get-FolderHashes $catalogCollection)) -Message "catalog: the collection's files are unchanged"
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $catalogCsv)) {
            $catalogOutput | ForEach-Object { Write-Host "  | $_" }
            Write-TestResult -Succeeded $false -Message "catalog: the builder exited with code $LASTEXITCODE or wrote no timeline"
        }
        else {
            $catalogText = $catalogOutput -join "`n"
            Write-TestResult -Succeeded ($catalogText -match 'ESE database: 8192-byte pages, clean shutdown') -Message "catalog: the damaged database's header says clean"
            Write-TestResult -Succeeded ($catalogText -match 'Could not open the SRUM database: .*JET_errDatabaseCorrupted') -Message "catalog: the failed open is reported"
            Write-TestResult -Succeeded ($catalogText -match 'Repair was needed') -Message "catalog: the copy is repaired"
            $day1.Has = @("Database=repair (esentutl /p)")
            Test-TimelineRows -Rows @(Import-Csv -LiteralPath $catalogCsv) -Expected @($day1) -Label "catalog" -Exact
        }
    }

    # The builder's temp copies are removed
    $tempLeft = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "TimelineSrum_*" -ErrorAction SilentlyContinue | Where-Object { $tempBefore -notcontains $_.FullName })
    Write-TestResult -Succeeded ($tempLeft.Count -eq 0) -Message "the builder removed its SRUM temp copies$(if ($tempLeft) { ': left ' + (($tempLeft | ForEach-Object { $_.Name }) -join ', ') })"
}
catch {
    Write-TestResult -Succeeded $false -Message "test error: $($_.Exception.Message)"
}
finally {
    # Undo the registry change even when the test failed half-way
    try {
        $leftover = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($testKeyPath)
        if ($leftover) {
            $leftover.Close()
            [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKeyPath)
        }
    }
    catch { Write-Host "WARNING: could not delete HKCU\$testKeyPath : $($_.Exception.Message)" -ForegroundColor Yellow }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    # The builder also writes a report folder (log) under reports\; remove the ones from this run
    Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $reportsBefore -notcontains $_.FullName } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($script:failures -gt 0) {
    Write-Host "FAIL: $($script:failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all SRUM parser checks passed" -ForegroundColor Green
exit 0
