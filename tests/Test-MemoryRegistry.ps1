# =============================================================
# Memory test: registry hives in memory (work package WP4, item g)
# On synthetic memory through tests\MemoryTestKit.ps1 (no dump in CI):
# hives written cell by cell (a key node, value, subkey list and big-data
# cell writer of the registry file format, below), their cell maps in
# kernel memory and their bins in the Registry process's address space, a
# kernel hive list, and the structures' layouts as the engine's 'dt' gives
# them (with other offsets than Windows 11 26100's, so nothing is taken
# from anything but 'dt'). It checks:
#   - the hive list walked both ways (a hive found one way), the names
#     (FileUserName, FileFullPath; \??\ and devices mapped to drives), the
#     process of the hive's views, the root key from the base block, the
#     key control block or the first cell;
#   - SAM and SECURITY (and a hive whose root path is not in the dump)
#     listed by name only: not one page of their cell maps, bins, base
#     blocks or key control blocks is read;
#   - the Run keys of SOFTWARE and of a user's hive (lh, lf, li and ri
#     subkey lists, compressed and UTF-16 names, inline, cell and big data,
#     data not in the dump), a key absent vs one not reached;
#   - the Services key (the control set from Select\Current, Parameters\
#     ServiceDll) offered as $Context.Shared["RegistryServices"];
#   - how much of each hive is in the dump (blocks, a page not in the dump,
#     a map entry with an implausible offset), the counts and notes, the
#     time limit, the reasons it is not read;
#   - the E lines through the builder's protocol reader into
#     lib\memory\TimelineMemoryRows.ps1's rows (Memory-Registry), OnDisk=
#     against Persistence-RunKeys and Registry-UserRunKey rows, and the
#     findings report's rules on those rows.
# Exit code 0 = pass, 1 = fail. Windows PowerShell 5.1 and PowerShell 7.
#
#   powershell -ExecutionPolicy Bypass -File tests\Test-MemoryRegistry.ps1
#   ... -BuilderPath <copy>   test another copy of timeline-builder.ps1
# =============================================================
param([string]$BuilderPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "MemoryTestKit.ps1")
if (-not $BuilderPath) { $BuilderPath = Join-Path (Split-Path $PSScriptRoot -Parent) "timeline-builder.ps1" }

# A hive's cells written as the registry file format has them (key nodes,
# values, subkey lists, big data; bins with an "hbin" header of 0x20 bytes,
# the root key the first cell), and a reader of the memory that records the
# pages read
function Get-RegistryTestSource {
    return @'
using System;
using System.Collections.Generic;
using System.Text;

namespace TimelineDbgEngTest
{
    public sealed class TestValue
    {
        public string Name = "";
        public uint Type = 1;
        public byte[] Data = new byte[0];
        public bool Compressed;
        public bool OwnBin;                     // its data cell in a bin of its own
        public uint Cell;
        public uint DataCell;
        public static TestValue Text(string name, uint type, string text, bool compressed)
        {
            TestValue v = new TestValue();
            v.Name = name; v.Type = type; v.Compressed = compressed;
            v.Data = Encoding.Unicode.GetBytes(text + "\0");
            return v;
        }
        public static TestValue Number(string name, uint value)
        {
            TestValue v = new TestValue();
            v.Name = name; v.Type = 4; v.Compressed = true;
            v.Data = BitConverter.GetBytes(value);
            return v;
        }
    }

    public sealed class TestKey
    {
        public string Name = "";
        public bool Compressed = true;
        public long LastWrite;
        public string Index = "lh";             // lh, lf, li or ri (of lf lists)
        public bool OwnBin;                     // its subkey list in a bin of its own
        public readonly List<TestKey> Children = new List<TestKey>();
        public readonly List<TestValue> Values = new List<TestValue>();
        public uint Cell;                       // set by TestHive.Build
        public uint ListCell;
        public uint ValueListCell;
        public TestKey(string name, long lastWrite) { Name = name; LastWrite = lastWrite; }
        public TestKey Add(TestKey child) { Children.Add(child); return child; }
        public TestKey AddValue(TestValue value) { Values.Add(value); return this; }
    }

    public sealed class TestHive
    {
        public const int BinHeader = 0x20;
        readonly List<byte> storage = new List<byte>();
        readonly List<int> binStarts = new List<int>();    // block -> its bin's first block
        int binEnd;                                         // end of the current bin (offset)
        int at;                                             // next free offset

        public int Length { get { return storage.Count; } }
        public int Blocks { get { return storage.Count / 4096; } }

        void NewBin(int bytes)
        {
            int blocks = (bytes + BinHeader + 4095) / 4096;
            int start = storage.Count;
            for (int i = 0; i < blocks * 4096; i++) storage.Add(0);
            byte[] sig = Encoding.ASCII.GetBytes("hbin");
            for (int i = 0; i < 4; i++) storage[start + i] = sig[i];
            Set32(start + 4, (uint)start);
            Set32(start + 8, (uint)(blocks * 4096));
            for (int b = 0; b < blocks; b++) binStarts.Add(start / 4096);
            at = start + BinHeader;
            binEnd = start + blocks * 4096;
        }
        void Set32(int offset, uint value) { byte[] b = BitConverter.GetBytes(value); for (int i = 0; i < 4; i++) storage[offset + i] = b[i]; }

        // An allocated cell for size bytes of data (its size field negative)
        public uint Reserve(int size)
        {
            int cell = (size + 4 + 7) & ~7;
            if (binEnd == 0 || at + cell > binEnd) NewBin(cell);
            uint index = (uint)at;
            Set32(at, (uint)(-cell));
            at += cell;
            return index;
        }
        public void Put(uint cell, byte[] data) { for (int i = 0; i < data.Length; i++) storage[(int)cell + 4 + i] = data[i]; }
        public uint Cell(byte[] data) { uint c = Reserve(data.Length); Put(c, data); return c; }
        // The next cell starts a bin of its own
        public void BreakBin() { binEnd = 0; }
        // One empty bin more at the end
        public void AddFillerBin() { NewBin(16); BreakBin(); }

        static byte[] Name(string name, bool compressed)
        {
            if (!compressed) return Encoding.Unicode.GetBytes(name);
            byte[] b = new byte[name.Length];
            for (int i = 0; i < name.Length; i++) b[i] = (byte)name[i];
            return b;
        }
        public static uint Hash(string name)
        {
            uint h = 0;
            foreach (char c in name) h = unchecked(h * 37 + (uint)char.ToUpperInvariant(c));
            return h;
        }

        // The tree with its root key as the first cell (0x20)
        public void Build(TestKey root)
        {
            byte[] rootName = Name(root.Name, root.Compressed);
            uint rootCell = Reserve(0x4c + rootName.Length);
            root.Cell = rootCell;
            WriteKey(root, 0xFFFFFFFF, true);
        }

        void WriteKey(TestKey key, uint parent, bool isRoot)
        {
            byte[] name = Name(key.Name, key.Compressed);
            if (!isRoot) key.Cell = Reserve(0x4c + name.Length);
            foreach (TestKey child in key.Children) WriteKey(child, key.Cell, false);
            key.ListCell = 0xFFFFFFFF;
            if (key.Children.Count > 0)
            {
                if (key.OwnBin) BreakBin();
                key.ListCell = WriteIndex(key);
                if (key.OwnBin) BreakBin();
            }
            key.ValueListCell = 0xFFFFFFFF;
            if (key.Values.Count > 0)
            {
                byte[] list = new byte[4 * key.Values.Count];
                for (int i = 0; i < key.Values.Count; i++) Array.Copy(BitConverter.GetBytes(WriteValue(key.Values[i])), 0, list, 4 * i, 4);
                key.ValueListCell = Cell(list);
            }
            byte[] nk = new byte[0x4c + name.Length];
            nk[0] = (byte)'n'; nk[1] = (byte)'k';
            ushort flags = (ushort)((key.Compressed ? 0x20 : 0) | (isRoot ? 0x4 : 0));
            Array.Copy(BitConverter.GetBytes(flags), 0, nk, 2, 2);
            Array.Copy(BitConverter.GetBytes(key.LastWrite), 0, nk, 4, 8);
            Array.Copy(BitConverter.GetBytes(parent), 0, nk, 0x10, 4);
            Array.Copy(BitConverter.GetBytes((uint)key.Children.Count), 0, nk, 0x14, 4);
            Array.Copy(BitConverter.GetBytes(key.ListCell), 0, nk, 0x1c, 4);
            Array.Copy(BitConverter.GetBytes(0xFFFFFFFFu), 0, nk, 0x20, 4);
            Array.Copy(BitConverter.GetBytes((uint)key.Values.Count), 0, nk, 0x24, 4);
            Array.Copy(BitConverter.GetBytes(key.ValueListCell), 0, nk, 0x28, 4);
            Array.Copy(BitConverter.GetBytes((ushort)name.Length), 0, nk, 0x48, 2);
            Array.Copy(name, 0, nk, 0x4c, name.Length);
            Put(key.Cell, nk);
        }

        uint WriteIndex(TestKey key)
        {
            List<TestKey> c = key.Children;
            if (key.Index == "li")
            {
                byte[] li = new byte[4 + 4 * c.Count];
                li[0] = (byte)'l'; li[1] = (byte)'i';
                Array.Copy(BitConverter.GetBytes((ushort)c.Count), 0, li, 2, 2);
                for (int i = 0; i < c.Count; i++) Array.Copy(BitConverter.GetBytes(c[i].Cell), 0, li, 4 + 4 * i, 4);
                return Cell(li);
            }
            if (key.Index == "ri")
            {
                // One lf list per child
                byte[] ri = new byte[4 + 4 * c.Count];
                ri[0] = (byte)'r'; ri[1] = (byte)'i';
                Array.Copy(BitConverter.GetBytes((ushort)c.Count), 0, ri, 2, 2);
                for (int i = 0; i < c.Count; i++) Array.Copy(BitConverter.GetBytes(Leaf("lf", new List<TestKey>(new TestKey[] { c[i] }))), 0, ri, 4 + 4 * i, 4);
                return Cell(ri);
            }
            return Leaf(key.Index, c);
        }

        uint Leaf(string kind, List<TestKey> c)
        {
            byte[] leaf = new byte[4 + 8 * c.Count];
            leaf[0] = (byte)kind[0]; leaf[1] = (byte)kind[1];
            Array.Copy(BitConverter.GetBytes((ushort)c.Count), 0, leaf, 2, 2);
            for (int i = 0; i < c.Count; i++)
            {
                Array.Copy(BitConverter.GetBytes(c[i].Cell), 0, leaf, 4 + 8 * i, 4);
                uint hint;
                if (kind == "lh") hint = Hash(c[i].Name);
                else { byte[] h = new byte[4]; for (int j = 0; j < 4 && j < c[i].Name.Length; j++) h[j] = (byte)c[i].Name[j]; hint = BitConverter.ToUInt32(h, 0); }
                Array.Copy(BitConverter.GetBytes(hint), 0, leaf, 8 + 8 * i, 4);
            }
            return Cell(leaf);
        }

        uint WriteValue(TestValue v)
        {
            byte[] name = Name(v.Name, v.Compressed);
            byte[] vk = new byte[0x14 + name.Length];
            vk[0] = (byte)'v'; vk[1] = (byte)'k';
            Array.Copy(BitConverter.GetBytes((ushort)name.Length), 0, vk, 2, 2);
            uint length = (uint)v.Data.Length;
            if (v.Data.Length <= 4)
            {
                Array.Copy(BitConverter.GetBytes(length | 0x80000000u), 0, vk, 4, 4);
                Array.Copy(v.Data, 0, vk, 8, v.Data.Length);
            }
            else
            {
                Array.Copy(BitConverter.GetBytes(length), 0, vk, 4, 4);
                if (v.OwnBin) BreakBin();
                v.DataCell = v.Data.Length > 16344 ? BigData(v.Data) : Cell(v.Data);
                if (v.OwnBin) BreakBin();
                Array.Copy(BitConverter.GetBytes(v.DataCell), 0, vk, 8, 4);
            }
            Array.Copy(BitConverter.GetBytes(v.Type), 0, vk, 0xc, 4);
            Array.Copy(BitConverter.GetBytes((ushort)(v.Compressed ? 1 : 0)), 0, vk, 0x10, 2);
            Array.Copy(name, 0, vk, 0x14, name.Length);
            v.Cell = Cell(vk);
            return v.Cell;
        }

        uint BigData(byte[] data)
        {
            int count = (data.Length + 16343) / 16344;
            byte[] list = new byte[4 * count];
            for (int i = 0; i < count; i++)
            {
                int n = Math.Min(16344, data.Length - 16344 * i);
                byte[] part = new byte[n];
                Array.Copy(data, 16344 * i, part, 0, n);
                Array.Copy(BitConverter.GetBytes(Cell(part)), 0, list, 4 * i, 4);
            }
            uint listCell = Cell(list);
            byte[] db = new byte[8];
            db[0] = (byte)'d'; db[1] = (byte)'b';
            Array.Copy(BitConverter.GetBytes((ushort)count), 0, db, 2, 2);
            Array.Copy(BitConverter.GetBytes(listCell), 0, db, 4, 4);
            return Cell(db);
        }

        // The bins, laid out from offset 0 (contiguous: a cell is at the bins'
        // address + its index)
        public byte[] Bytes() { return storage.ToArray(); }
        // The cell map's entries, per block: BlockOffset, then
        // PermanentBinAddress (with a flag bit set) for bins at binBase
        public ulong[] MapEntries(ulong binBase)
        {
            ulong[] entries = new ulong[2 * Blocks];
            for (int b = 0; b < Blocks; b++)
            {
                int binStart = binStarts[b];
                entries[2 * b] = (ulong)((b - binStart) * 4096);
                entries[2 * b + 1] = (binBase + (ulong)binStart * 4096UL) | 1UL;
            }
            return entries;
        }
    }

    // A memory whose page reads are recorded ("<space>/<page>")
    public sealed class RecordingMemory
    {
        readonly Func<ulong, bool> switcher;
        readonly Func<ulong, ulong, int, byte[]> reader;
        public readonly HashSet<string> Pages = new HashSet<string>(StringComparer.Ordinal);
        public RecordingMemory(Func<ulong, bool> switcher, Func<ulong, ulong, int, byte[]> reader) { this.switcher = switcher; this.reader = reader; }
        public bool Switch(ulong process) { return switcher(process); }
        public byte[] Read(ulong process, ulong address, int count)
        {
            ulong space = address >= 0x8000000000000000UL ? 0 : process;
            for (ulong page = address >> 12; page <= (address + (ulong)Math.Max(count, 1) - 1) >> 12; page++) Pages.Add(space.ToString("x") + "/" + page.ToString("x"));
            return reader(process, address, count);
        }
        // Whether a page of [from, to) in that space was read
        public bool Touched(ulong process, ulong from, ulong to)
        {
            ulong space = from >= 0x8000000000000000UL ? 0 : process;
            for (ulong page = from >> 12; page < (to + 4095) >> 12; page++) { if (Pages.Contains(space.ToString("x") + "/" + page.ToString("x"))) return true; }
            return false;
        }
    }
}
'@
}

# --- The layout ('dt' text) the test engine answers -------------------------------
# Offsets of _CMHIVE and its views differ from Windows 11 26100's on purpose
$script:hiveOffsets = @{ HiveList = 0x660; FileFullPath = 0x720; FileUserName = 0x738; HiveRootPath = 0x748; RootKcb = 0xb80; BaseBlock = 0x40; Flat = 0x8c; ViewMap = 0xe8; Storage = 0x120; Tuple = 0x18; TupleProcess = 0x8 }
function Get-RegistryTestDt {
    param([string[]]$Without = @())
    $h = $script:hiveOffsets
    $dt = @{
        "_CMHIVE"               = New-TestDtText -Type "_CMHIVE" -Size 0x1300 -Fields @(@(0, "Hive", "struct _HHIVE, 50 elements, 0x608 bytes"), @($h.HiveList, "HiveList", "struct _LIST_ENTRY, 2 elements, 0x10 bytes"),
            @($h.FileFullPath, "FileFullPath", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"), @($h.FileUserName, "FileUserName", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"),
            @($h.HiveRootPath, "HiveRootPath", "struct _UNICODE_STRING, 3 elements, 0x10 bytes"), @($h.RootKcb, "RootKcb", "Ptr64 to struct _CM_KEY_CONTROL_BLOCK, 56 elements, 0x138 bytes"))
        "_HHIVE"                = New-TestDtText -Type "_HHIVE" -Size 0x608 -Fields @(@(0, "Signature", "Uint4B"), @($h.BaseBlock, "BaseBlock", "Ptr64 to struct _HBASE_BLOCK, 26 elements, 0x1000 bytes"),
            @($h.Flat, "Flat", "Bitfield Pos 0, 1 Bit"), @($h.ViewMap, "ViewMap", "struct _HVP_VIEW_MAP, 6 elements, 0x38 bytes"), @($h.Storage, "Storage", "[2] struct _DUAL, 7 elements, 0x278 bytes"))
        "_HVP_VIEW_MAP"         = New-TestDtText -Type "_HVP_VIEW_MAP" -Size 0x38 -Fields @(@(0, "SectionReference", "Ptr64 to Void"), @($h.Tuple, "ProcessTuple", "Ptr64 to struct _CMSI_PROCESS_TUPLE, 6 elements, 0x30 bytes"))
        "_CMSI_PROCESS_TUPLE"   = New-TestDtText -Type "_CMSI_PROCESS_TUPLE" -Size 0x30 -Fields @(@(0, "ProcessHandle", "Ptr64 to Void"), @($h.TupleProcess, "ProcessReference", "Ptr64 to Void"))
        "_DUAL"                 = New-TestDtText -Type "_DUAL" -Size 0x278 -Fields @(@(0, "Length", "Uint4B"), @(8, "Map", "Ptr64 to struct _HMAP_DIRECTORY, 1 elements, 0x2000 bytes"))
        "_HMAP_DIRECTORY"       = New-TestDtText -Type "_HMAP_DIRECTORY" -Size 0x2000 -Fields @(, @(0, "Directory", "[1024] Ptr64 to struct _HMAP_TABLE, 1 elements, 0x3000 bytes"))
        "_HMAP_TABLE"           = New-TestDtText -Type "_HMAP_TABLE" -Size 0x3000 -Fields @(, @(0, "Table", "[512] struct _HMAP_ENTRY, 3 elements, 0x18 bytes"))
        "_HMAP_ENTRY"           = New-TestDtText -Type "_HMAP_ENTRY" -Size 0x18 -Fields @(@(0, "BlockOffset", "Uint8B"), @(8, "PermanentBinAddress", "Uint8B"), @(0x10, "MemAlloc", "Uint4B"))
        "_CM_KEY_CONTROL_BLOCK" = New-TestDtText -Type "_CM_KEY_CONTROL_BLOCK" -Size 0x138 -Fields @(@(0x20, "KeyHive", "Ptr64 to struct _HHIVE, 50 elements, 0x608 bytes"), @(0x28, "KeyCell", "Uint4B"))
        "_HBASE_BLOCK"          = New-TestDtText -Type "_HBASE_BLOCK" -Size 0x1000 -Fields @(@(0, "Signature", "Uint4B"), @(0x24, "RootCell", "Uint4B"))
        "_CM_KEY_NODE"          = New-TestDtText -Type "_CM_KEY_NODE" -Size 0x50 -Fields @(@(0, "Signature", "Uint2B"), @(2, "Flags", "Uint2B"), @(4, "LastWriteTime", "union _LARGE_INTEGER, 4 elements, 0x8 bytes"),
            @(0x10, "Parent", "Uint4B"), @(0x14, "SubKeyCounts", "[2] Uint4B"), @(0x1c, "SubKeyLists", "[2] Uint4B"), @(0x24, "ValueList", "struct _CHILD_LIST, 2 elements, 0x8 bytes"),
            @(0x48, "NameLength", "Uint2B"), @(0x4a, "ClassLength", "Uint2B"), @(0x4c, "Name", "[1] Wchar"))
        "_CHILD_LIST"           = New-TestDtText -Type "_CHILD_LIST" -Size 8 -Fields @(@(0, "Count", "Uint4B"), @(4, "List", "Uint4B"))
        "_CM_KEY_VALUE"         = New-TestDtText -Type "_CM_KEY_VALUE" -Size 0x18 -Fields @(@(0, "Signature", "Uint2B"), @(2, "NameLength", "Uint2B"), @(4, "DataLength", "Uint4B"), @(8, "Data", "Uint4B"),
            @(0xc, "Type", "Uint4B"), @(0x10, "Flags", "Uint2B"), @(0x12, "Spare", "Uint2B"), @(0x14, "Name", "[1] Wchar"))
        "_CM_KEY_INDEX"         = New-TestDtText -Type "_CM_KEY_INDEX" -Size 8 -Fields @(@(0, "Signature", "Uint2B"), @(2, "Count", "Uint2B"), @(4, "List", "[1] Uint4B"))
        "_CM_INDEX"             = New-TestDtText -Type "_CM_INDEX" -Size 8 -Fields @(@(0, "Cell", "Uint4B"), @(4, "HashKey", "struct _CM_COMPONENT_HASH, 1 elements, 0x4 bytes"))
        "_CM_BIG_DATA"          = New-TestDtText -Type "_CM_BIG_DATA" -Size 8 -Fields @(@(0, "Signature", "Uint2B"), @(2, "Count", "Uint2B"), @(4, "List", "Uint4B"))
    }
    foreach ($type in $Without) { $dt.Remove($type) }
    return $dt
}

# --- The synthetic dump ----------------------------------------------------------
$script:kernelBase = [Convert]::ToUInt64("ffffa00000000000", 16)
$script:listHead = $script:kernelBase + [uint64]0x1000
$script:registryProcess = $script:kernelBase + [uint64]0x5000
$script:otherProcess = $script:kernelBase + [uint64]0x6000
function Get-HiveAddress { param([int]$Index, [int]$Offset = 0) return $script:kernelBase + [uint64](0x100000 + $Index * 0x20000 + $Offset) }
function Get-BinBase { param([int]$Index) return [uint64](0x20000000000 + $Index * 0x1000000) }
function ConvertTo-FileTime { param([int]$Day, [int]$Hour) return [datetime]::new(2026, 9, $Day, $Hour, 0, 0, [DateTimeKind]::Utc).ToFileTimeUtc() }

# A UNICODE_STRING at an address, its text at a buffer
function Write-TestString {
    param($Memory, [uint64]$Address, [uint64]$Buffer, [string]$Text)
    $Memory.WriteUnicodeString(0, $Address, $Buffer, $Text)
}

# Writes one hive: its _CMHIVE (names, storage, views, root key control
# block), base block and cell map in kernel memory, its bins in the
# Registry process. -Root: the TestKey tree (or $null: no cells). Options:
# NoBaseBlock, NoKcb, NoRootPath (its text not in the dump), NoTuple,
# Process (another one), BadEntry (an empty bin at the end whose map entry
# has an offset past 4 GB)
function Write-TestHive {
    param($Memory, [int]$Index, [string]$RootPath, [string]$FileUser = "", [string]$FileFull = "", $Root, [hashtable]$Options = @{})
    $h = $script:hiveOffsets
    $hive = Get-HiveAddress $Index
    $Memory.WriteU32(0, $hive, [Convert]::ToUInt32("BEE0BEE0", 16))
    if ($Options.NoRootPath) {
        # A length, and a buffer on a page that is not in the dump
        $Memory.WriteU16(0, $hive + [uint64]$h.HiveRootPath, [uint16]20)
        $Memory.WriteU16(0, $hive + [uint64]($h.HiveRootPath + 2), [uint16]22)
        $Memory.WriteU64(0, $hive + [uint64]($h.HiveRootPath + 8), $hive + [uint64]0x1F000)
    }
    else { Write-TestString -Memory $Memory -Address ($hive + [uint64]$h.HiveRootPath) -Buffer ($hive + [uint64]0x1000) -Text $RootPath }
    Write-TestString -Memory $Memory -Address ($hive + [uint64]$h.FileUserName) -Buffer ($hive + [uint64]0x1200) -Text $FileUser
    Write-TestString -Memory $Memory -Address ($hive + [uint64]$h.FileFullPath) -Buffer ($hive + [uint64]0x1400) -Text $FileFull
    $process = if ($Options.Process) { [uint64]$Options.Process } else { $script:registryProcess }
    $result = [PSCustomObject]@{ Address = $hive; Map = (Get-HiveAddress $Index 0x4000); Table = (Get-HiveAddress $Index 0x8000); BaseBlock = (Get-HiveAddress $Index 0xC000); Kcb = (Get-HiveAddress $Index 0xD000); Bins = (Get-BinBase $Index); Blocks = 0; Hive = $null; Process = $process }
    if ($null -eq $Root) { return $result }
    $cells = New-Object TimelineDbgEngTest.TestHive
    $cells.Build($Root)
    if ($Options.BadEntry) { $cells.AddFillerBin() }
    $result.Hive = $cells
    $result.Blocks = $cells.Blocks
    $Memory.Write($process, $result.Bins, $cells.Bytes())
    $Memory.WriteU64(0, $result.Map, $result.Table)
    $entries = $cells.MapEntries($result.Bins)
    for ($b = 0; $b -lt $cells.Blocks; $b++) {
        $Memory.WriteU64(0, $result.Table + [uint64](0x18 * $b), $entries[2 * $b])
        $Memory.WriteU64(0, $result.Table + [uint64](0x18 * $b + 8), $entries[2 * $b + 1])
    }
    $Memory.WriteU32(0, $hive + [uint64]$h.Storage, [uint32]$cells.Length)
    $Memory.WriteU64(0, $hive + [uint64]($h.Storage + 8), $result.Map)
    if (-not $Options.NoTuple) {
        $tuple = Get-HiveAddress $Index 0xE000
        $Memory.WriteU64(0, $hive + [uint64]($h.ViewMap + $h.Tuple), $tuple)
        $Memory.WriteU64(0, $tuple + [uint64]$h.TupleProcess, $process)
    }
    if (-not $Options.NoBaseBlock) {
        $Memory.WriteU64(0, $hive + [uint64]$h.BaseBlock, $result.BaseBlock)
        $Memory.Write(0, $result.BaseBlock, [System.Text.Encoding]::ASCII.GetBytes("regf"))
        $Memory.WriteU32(0, $result.BaseBlock + [uint64]0x24, [uint32]$Root.Cell)
    }
    if (-not $Options.NoKcb) {
        $Memory.WriteU64(0, $hive + [uint64]$h.RootKcb, $result.Kcb)
        $Memory.WriteU64(0, $result.Kcb + [uint64]0x20, $hive)
        $Memory.WriteU32(0, $result.Kcb + [uint64]0x28, [uint32]$Root.Cell)
    }
    if ($Options.BadEntry) { $Memory.WriteU64(0, $result.Table + [uint64](0x18 * ($cells.Blocks - 1)), [Convert]::ToUInt64("100000000", 16)) }
    return $result
}

# The hive list: head <-> hives in this order; -BrokenBlink, -BrokenFlink:
# the index (in list order) of a hive whose back or forward link is garbage
function Write-TestHiveList {
    param($Memory, [object[]]$Hives, [int]$BrokenBlink = -1, [int]$BrokenFlink = -1)
    $h = $script:hiveOffsets
    $links = @($script:listHead) + @($Hives | ForEach-Object { $_.Address + [uint64]$h.HiveList })
    for ($i = 0; $i -lt $links.Count; $i++) {
        $next = $links[($i + 1) % $links.Count]
        $previous = $links[($i - 1 + $links.Count) % $links.Count]
        if ($BrokenFlink -ge 0 -and $i - 1 -eq $BrokenFlink) { $next = [uint64]0x1234 }
        $Memory.WriteU64(0, $links[$i], $next)
        if ($BrokenBlink -ge 0 -and $i - 1 -eq $BrokenBlink) { $previous = [uint64]0x1234 }
        $Memory.WriteU64(0, $links[$i] + [uint64]8, $previous)
    }
}

function New-TestKey { param([string]$Name, [int]$Day = 1, [string]$Index = "lh", [switch]$Utf16) $k = New-Object TimelineDbgEngTest.TestKey -ArgumentList $Name, (ConvertTo-FileTime $Day 8); $k.Index = $Index; if ($Utf16) { $k.Compressed = $false }; return $k }
function New-TestText { param([string]$Name, [string]$Text, [uint32]$Type = 1, [switch]$Utf16) return [TimelineDbgEngTest.TestValue]::Text($Name, $Type, $Text, -not $Utf16) }

# A key path under a key: the keys (made as needed), the last one returned
function Add-TestPath {
    param($Key, [string]$Path, [int]$Day = 1, [string]$Index = "lh")
    $at = $Key
    foreach ($part in $Path.Split('\')) {
        $child = @($at.Children | Where-Object { $_.Name -eq $part })
        if ($child.Count -gt 0) { $at = $child[0]; continue }
        $at = $at.Add((New-TestKey $part -Day $Day -Index $Index))
    }
    return $at
}

# The whole synthetic dump: the memory (and its recording reader), the
# hives (by name), the context, the engine's answers. -Variant: Full,
# PartialUser (the user hive's Software subkey list not in the dump),
# PartialServices (a Services subkey list not in the dump), BrokenList
# (neither walk of the hive list gets back to its head)
function New-RegistryTestDump {
    param([string]$Variant = "Full", [hashtable]$Dt = (Get-RegistryTestDt), [hashtable]$Symbols = @{ "nt!CmpHiveListHead" = $script:listHead }, [switch]$NoHives)
    $memory = New-TestMemory
    $hives = [ordered]@{}
    $longCommand = "C:\Program Files\Fixture\long.exe " + ("x" * 9000)

    # SYSTEM: Select\Current = 2, ControlSet002\Services (lh), Parameters\ServiceDll
    $system = New-TestKey "ROOT"
    [void](Add-TestPath $system "Select").AddValue([TimelineDbgEngTest.TestValue]::Number("Current", 2))
    $services = Add-TestPath $system "ControlSet002\Services" -Day 2
    [void](Add-TestPath $system "ControlSet001\Services\FixtureOld")
    $svc = $services.Add((New-TestKey "FixtureSvc" -Day 3))
    [void]$svc.AddValue((New-TestText "ImagePath" "%SystemRoot%\System32\svchost.exe -k fixture" -Type 2)).AddValue([TimelineDbgEngTest.TestValue]::Number("Start", 2)).AddValue([TimelineDbgEngTest.TestValue]::Number("Type", 32))
    [void]$svc.AddValue((New-TestText "ObjectName" "LocalSystem")).AddValue((New-TestText "DisplayName" "Fixture service"))
    [void]$svc.Add((New-TestKey "Parameters")).AddValue((New-TestText "ServiceDll" "C:\Program Files\Fixture\fixture.dll" -Type 2))
    $drv = $services.Add((New-TestKey "FixtureDrv" -Day 4))
    [void]$drv.AddValue((New-TestText "ImagePath" "\SystemRoot\System32\drivers\fixture.sys")).AddValue([TimelineDbgEngTest.TestValue]::Number("Start", 1)).AddValue([TimelineDbgEngTest.TestValue]::Number("Type", 1))
    if ($Variant -eq "PartialServices") { $services.Index = "li"; $services.OwnBin = $true }

    # SOFTWARE: Run (li lists down the path), RunOnce empty, no Wow6432Node
    $software = New-TestKey "ROOT"
    $run = Add-TestPath $software "Microsoft\Windows\CurrentVersion\Run" -Day 5 -Index "li"
    [void]$run.AddValue((New-TestText "SecurityHealth" "%windir%\system32\SecurityHealthSystray.exe" -Type 2)).AddValue((New-TestText "FixtureTray" "C:\Program Files\Fixture\tray.exe"))
    [void](Add-TestPath $software "Microsoft\Windows\CurrentVersion\RunOnce" -Day 6)

    # A user's hive: Software (ri), Run with a UTF-16 name, data not in the
    # dump and a RunOnce value of big data
    $user = New-TestKey "ROOT"
    $userSoftware = $user.Add((New-TestKey "Software" -Index "ri"))
    $userSoftware.OwnBin = $true
    $userRun = Add-TestPath $userSoftware "Microsoft\Windows\CurrentVersion\Run" -Day 7 -Index "lf"
    [void]$userRun.AddValue((New-TestText "FixtureUpdater" "C:\Users\Public\fixture-updater.exe /background")).AddValue((New-TestText "Fixture$([char]0x00E9)Sync" "C:\Program Files\Fixture\sync.exe" -Utf16))
    $gone = New-TestText "FixtureGone" "C:\Program Files\Fixture\gone.exe --long-enough-for-a-cell"
    $gone.OwnBin = $true
    [void]$userRun.AddValue($gone)
    $userRunOnce = Add-TestPath $userSoftware "Microsoft\Windows\CurrentVersion\RunOnce" -Day 8
    [void]$userRunOnce.AddValue((New-TestText "FixtureLong" $longCommand))
    [void]$userRunOnce.AddValue((New-TestText "" "C:\Program Files\Fixture\default.exe"))

    # A system account's hive: its Software key not in the dump in PartialUser
    $service = New-TestKey "ROOT"
    $serviceRun = Add-TestPath $service "Software\Microsoft\Windows\CurrentVersion\Run" -Day 9
    [void]$serviceRun.AddValue((New-TestText "FixtureLocalService" "C:\Program Files\Fixture\ls.exe"))

    $app = New-TestKey "ROOT"
    [void](Add-TestPath $app "Settings")
    $wc = New-TestKey "ROOT"
    [void](Add-TestPath $wc "Container")

    if (-not $NoHives) {
        $hives["APP"] = Write-TestHive -Memory $memory -Index 0 -RootPath "\REGISTRY\A\{11111111-2222-3333-4444-555555555555}" -FileUser "\Device\HarddiskVolume3\ProgramData\Fixture\settings.dat" -Root $app -Options @{ NoBaseBlock = $true }
        $hives["SYSTEM"] = Write-TestHive -Memory $memory -Index 1 -RootPath "\REGISTRY\MACHINE\SYSTEM" -Root $system -Options @{ BadEntry = 1 }
        $hives["SOFTWARE"] = Write-TestHive -Memory $memory -Index 2 -RootPath "\REGISTRY\MACHINE\SOFTWARE" -FileUser "\SystemRoot\System32\Config\SOFTWARE" -Root $software
        $hives["USER"] = Write-TestHive -Memory $memory -Index 3 -RootPath "\REGISTRY\USER\S-1-5-21-1-2-3-1001" -FileUser "\??\C:\Users\alice\NTUSER.DAT" -Root $user -Options @{ NoTuple = $true }
        $hives["LOCALSERVICE"] = Write-TestHive -Memory $memory -Index 4 -RootPath "\REGISTRY\USER\S-1-5-19" -FileFull "\??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT" -Root $service
        $hives["SAM"] = Write-TestHive -Memory $memory -Index 5 -RootPath "\REGISTRY\MACHINE\SAM" -FileUser "\SystemRoot\System32\Config\SAM" -Root (New-TestKey "ROOT")
        $hives["SECURITY"] = Write-TestHive -Memory $memory -Index 6 -RootPath "\REGISTRY\MACHINE\NOTSAM" -FileUser "\SystemRoot\System32\Config\SECURITY" -Root (New-TestKey "ROOT")
        $hives["UNNAMED"] = Write-TestHive -Memory $memory -Index 7 -RootPath "\REGISTRY\MACHINE\HIDDEN" -FileUser "\SystemRoot\System32\Config\FIXTURE" -Root (New-TestKey "ROOT") -Options @{ NoRootPath = $true }
        $hives["WC"] = Write-TestHive -Memory $memory -Index 8 -RootPath "\REGISTRY\WC\Silo00000001user_sid" -FileUser "\??\C:\ProgramData\Fixture\wc.dat" -Root $wc -Options @{ NoBaseBlock = $true; NoKcb = $true }
        Write-TestHiveList $memory @($hives.Values) -BrokenBlink 1 -BrokenFlink $(if ($Variant -eq "BrokenList") { 7 } else { -1 })
        # A value's data cell not in the dump
        $memory.Remove($script:registryProcess, $hives["USER"].Bins + [uint64]$gone.DataCell)
        if ($Variant -eq "PartialUser") { $memory.Remove($script:registryProcess, $hives["USER"].Bins + [uint64]$userSoftware.ListCell) }
        if ($Variant -eq "PartialServices") { $memory.Remove($script:registryProcess, $hives["SYSTEM"].Bins + [uint64]$services.ListCell) }
    }
    else { Write-TestHiveList $memory @() }

    $recording = New-Object TimelineDbgEngTest.RecordingMemory -ArgumentList ([Delegate]::CreateDelegate([Func[uint64, bool]], $memory, "Switch")), ([Delegate]::CreateDelegate([Func[uint64, uint64, int, byte[]]], $memory, "Read"))
    $switch = [Delegate]::CreateDelegate([Func[uint64, bool]], $recording, "Switch")
    $read = [Delegate]::CreateDelegate([Func[uint64, uint64, int, byte[]]], $recording, "Read")
    $processMemory = New-Object TimelineDbgEng.FuncProcessMemory -ArgumentList $switch, $read
    $context = New-TestContext -Memory $null -Processes @(
        @{ Eprocess = $script:kernelBase + [uint64]0x4000; Pid = 4; Ppid = 0; ShortName = "System" },
        @{ Eprocess = $script:registryProcess; Pid = 120; Ppid = 4; ShortName = "Registry" },
        @{ Eprocess = $script:otherProcess; Pid = 900; Ppid = 4; ShortName = "Registry" })
    $context.Reader = New-Object TimelineDbgEng.SessionReader -ArgumentList $processMemory, 64MB
    $context.DriveMap["\Device\HarddiskVolume3"] = "C:"
    Set-TestEngineCommands -Dt $Dt -Symbols $Symbols
    return [PSCustomObject]@{ Memory = $memory; Recording = $recording; Context = $context; Hives = $hives; LongCommand = $longCommand }
}

# The entries of a kind as [ordered] fields, in order
function Get-TestKindFields {
    param($Area, [string]$Kind)
    return @($Area.Entries | Where-Object { $_.Kind -eq $Kind } | ForEach-Object { Get-TestEntryFields $_ })
}

function Format-TestFields {
    param($Fields)
    return (@($Fields.Keys | Where-Object { $_ -ne "Kind" } | ForEach-Object { "$_=$($Fields[$_])" }) -join "|")
}

try {
    Initialize-MemoryTestKit -Builder -BuilderPath $BuilderPath -Name "Test-MemoryRegistry"
    if (-not ([System.Management.Automation.PSTypeName]'TimelineDbgEngTest.TestHive').Type) { Add-Type -TypeDefinition (Get-RegistryTestSource) -ErrorAction Stop }
    Write-KitResult -Name "the registry area's C# compiled with the host (no compile problem for Registry)" -Passed ([bool]([System.Management.Automation.PSTypeName]'TimelineDbgEng.RegistryScan').Type -and -not ($script:DbgEngCompileProblems -and $script:DbgEngCompileProblems.Contains("Registry"))) -Message "$($script:DbgEngCompileProblems | Out-String)"

    # --- 1. The whole area on the synthetic dump ---------------------------------
    $dump = New-RegistryTestDump
    $area = Invoke-TestArea -Name "Registry" -Context $dump.Context
    $hiveFields = @(Get-TestKindFields $area "Hive")
    $runFields = @(Get-TestKindFields $area "RunValue")
    Assert-KitEqual -Name "the area is read: its state, entries (9 hives, 8 Run values), no root key note" -Expected "Read|9|8|" `
        -Actual "$($area.State)|$($hiveFields.Count)|$($runFields.Count)|$(@($area.Coverage.Notes | Where-Object { $_ -match 'root key' }) -join '/')"

    # The hives: names, files, roots, the walks, never-read hives, how much is in the dump
    $hiveText = @($hiveFields | ForEach-Object { "$($_.Root)>$($_.File)>$($_.RootState)>$($_.FoundBy)>$($_.Readable)>$($_.NotRead)>$($_.Sid)" }) -join "`n"
    $total = @{}
    foreach ($name in @($dump.Hives.Keys)) { $total[$name] = $dump.Hives[$name].Blocks }
    $expectedHives = @(
        "\REGISTRY\A\{11111111-2222-3333-4444-555555555555}>C:\ProgramData\Fixture\settings.dat>Read>HiveListForward>100>>",
        "\REGISTRY\MACHINE\SYSTEM>>Read>HiveListForward,HiveListBackward>$([Math]::Floor(100.0 * ($total['SYSTEM'] - 1) / $total['SYSTEM'] + 0.5))>>",
        "\REGISTRY\MACHINE\SOFTWARE>\SystemRoot\System32\Config\SOFTWARE>Read>HiveListForward,HiveListBackward>100>>",
        "\REGISTRY\USER\S-1-5-21-1-2-3-1001>C:\Users\alice\NTUSER.DAT>Read>HiveListForward,HiveListBackward>$([Math]::Floor(100.0 * ($total['USER'] - 1) / $total['USER'] + 0.5))>>S-1-5-21-1-2-3-1001",
        "\REGISTRY\USER\S-1-5-19>C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT>Read>HiveListForward,HiveListBackward>100>>S-1-5-19",
        "\REGISTRY\MACHINE\SAM>\SystemRoot\System32\Config\SAM>NotRead>HiveListForward,HiveListBackward>>CredentialHive>",
        "\REGISTRY\MACHINE\NOTSAM>\SystemRoot\System32\Config\SECURITY>NotRead>HiveListForward,HiveListBackward>>CredentialHive>",
        ">\SystemRoot\System32\Config\FIXTURE>NotRead>HiveListForward,HiveListBackward>>NamesNotInDump>",
        "\REGISTRY\WC\Silo00000001user_sid>C:\ProgramData\Fixture\wc.dat>Read>HiveListForward,HiveListBackward>100>>") -join "`n"
    Assert-KitEqual -Name "the hives: root path, file (FileUserName, else FileFullPath; \??\ and a known device mapped to drives), root key, walks, % in the dump, never read, SID" -Expected $expectedHives -Actual $hiveText
    $scan = $dump.Context.Shared["RegistryHives"]
    Assert-KitEqual -Name "the root key from the base block, the key control block (no base block) and the first cell (neither)" -Expected "BaseBlock|KeyControlBlock|FirstCell" `
        -Actual "$(@($scan | Where-Object { $_.RootPath -eq '\REGISTRY\MACHINE\SOFTWARE' })[0].RootFrom)|$(@($scan | Where-Object { $_.RootPath -like '\REGISTRY\A\*' })[0].RootFrom)|$(@($scan | Where-Object { $_.RootPath -like '\REGISTRY\WC\*' })[0].RootFrom)"
    Assert-KitEqual -Name "each hive read in the process its view map names, the Registry process for one without (not the other process named Registry)" -Expected "True|True" `
        -Actual "$(@($scan | Where-Object { $_.RootPath -eq '\REGISTRY\USER\S-1-5-21-1-2-3-1001' })[0].Process -eq $script:registryProcess)|$(@($scan | Where-Object { $_.NotRead -eq '' -and $_.Process -ne $script:registryProcess }).Count -eq 0)"

    # SAM, SECURITY and the hive without a root path: not one page of their data read
    $touched = @(foreach ($name in "SAM", "SECURITY", "UNNAMED") {
            $h = $dump.Hives[$name]
            $ranges = @(@(0, $h.Map, $h.Map + [uint64]0x2000), @(0, $h.Table, $h.Table + [uint64]0x3000), @(0, $h.BaseBlock, $h.BaseBlock + [uint64]0x1000), @(0, $h.Kcb, $h.Kcb + [uint64]0x1000),
                @($h.Process, $h.Bins, $h.Bins + [uint64]($h.Blocks * 4096)))
            foreach ($range in $ranges) { if ($dump.Recording.Touched([uint64]$range[0], [uint64]$range[1], [uint64]$range[2])) { "$name at 0x$(([uint64]$range[1]).ToString('x'))" } }
        })
    $samRead = $dump.Recording.Touched($script:registryProcess, $dump.Hives["SOFTWARE"].Bins, $dump.Hives["SOFTWARE"].Bins + [uint64]4096)
    Assert-KitEqual -Name "SAM, SECURITY (by its file) and a hive whose root path is not in the dump: no page of their cell map, base block, key control block or bins is read (SOFTWARE's are)" -Expected "|True" -Actual "$($touched -join ', ')|$samRead"

    # The Run values
    $runText = @($runFields | ForEach-Object { Format-TestFields $_ }) -join "`n"
    $userKey = "HKU\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion"
    $time = { param($day) [TimelineDbgEng.Fmt]::IsoTime((ConvertTo-FileTime $day 8)) }
    $expectedRun = @(
        "Hive=HKLM|Key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Name=SecurityHealth|Command=%windir%\system32\SecurityHealthSystray.exe|Data=Read|ValueType=REG_EXPAND_SZ|LastWrite=$(& $time 5)|HiveFile=\SystemRoot\System32\Config\SOFTWARE|Values=Complete",
        "Hive=HKLM|Key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Name=FixtureTray|Command=C:\Program Files\Fixture\tray.exe|Data=Read|ValueType=REG_SZ|LastWrite=$(& $time 5)|HiveFile=\SystemRoot\System32\Config\SOFTWARE|Values=Complete",
        "Hive=HKU\S-1-5-21-1-2-3-1001|Key=$userKey\Run|Name=FixtureUpdater|Command=C:\Users\Public\fixture-updater.exe /background|Data=Read|ValueType=REG_SZ|LastWrite=$(& $time 7)|Sid=S-1-5-21-1-2-3-1001|HiveFile=C:\Users\alice\NTUSER.DAT|Values=Complete",
        "Hive=HKU\S-1-5-21-1-2-3-1001|Key=$userKey\Run|Name=Fixture$([char]0x00E9)Sync|Command=C:\Program Files\Fixture\sync.exe|Data=Read|ValueType=REG_SZ|LastWrite=$(& $time 7)|Sid=S-1-5-21-1-2-3-1001|HiveFile=C:\Users\alice\NTUSER.DAT|Values=Complete",
        "Hive=HKU\S-1-5-21-1-2-3-1001|Key=$userKey\Run|Name=FixtureGone|Command=|Data=Unreadable|ValueType=REG_SZ|LastWrite=$(& $time 7)|Sid=S-1-5-21-1-2-3-1001|HiveFile=C:\Users\alice\NTUSER.DAT|Values=Complete",
        "Hive=HKU\S-1-5-21-1-2-3-1001|Key=$userKey\RunOnce|Name=FixtureLong|Command=$($dump.LongCommand)|Data=Read|ValueType=REG_SZ|LastWrite=$(& $time 8)|Sid=S-1-5-21-1-2-3-1001|HiveFile=C:\Users\alice\NTUSER.DAT|Values=Complete")
    # (the user's RunOnce also has a (Default) value, and S-1-5-19 one in Run)
    $expectedRun += "Hive=HKU\S-1-5-21-1-2-3-1001|Key=$userKey\RunOnce|Name=(Default)|Command=C:\Program Files\Fixture\default.exe|Data=Read|ValueType=REG_SZ|LastWrite=$(& $time 8)|Sid=S-1-5-21-1-2-3-1001|HiveFile=C:\Users\alice\NTUSER.DAT|Values=Complete"
    $expectedRun += "Hive=HKU\S-1-5-19|Key=HKU\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Name=FixtureLocalService|Command=C:\Program Files\Fixture\ls.exe|Data=Read|ValueType=REG_SZ|LastWrite=$(& $time 9)|Sid=S-1-5-19|HiveFile=C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT|Values=Complete"
    Assert-KitEqual -Name "the Run values: lh, lf, li and ri lists, compressed and UTF-16 names, cell and big data (16344-byte segments), data not in the dump, (Default), the key's last write time" `
        -Expected ($expectedRun -join "`n") -Actual $runText
    Assert-KitEqual -Name "Run keys: read, absent (subkey lists read in full), none not reached" -Expected "Run keys read 5|Run keys absent 10|Run keys not in the dump 0" `
        -Actual (@(($area.Coverage.CountsText -split ', ') | Where-Object { $_ -match '^Run keys (read|absent|not in the dump) ' }) -join "|")

    # The Services key for the joins
    $services = $dump.Context.Shared["RegistryServices"]
    $svc = $services.Find("fixturesvc")
    $drv = $services.Find("FixtureDrv")
    Assert-KitEqual -Name "Shared RegistryServices: ControlSet002 from Select\Current, complete, each service's values (ServiceDll from Parameters), case-insensitive lookup" `
        -Expected "Read|ControlSet002|Select|2|2|True|FixtureSvc|%SystemRoot%\System32\svchost.exe -k fixture|C:\Program Files\Fixture\fixture.dll|SERVICE_AUTO_START|32|LocalSystem|Fixture service|$(ConvertTo-FileTime 3 8)|\SystemRoot\System32\drivers\fixture.sys||SERVICE_SYSTEM_START|1|False" `
        -Actual "$($services.State)|$($services.ControlSet)|$($services.ControlSetFrom)|$($services.Listed)|$($services.Read)|$($services.Complete)|$($svc.Name)|$($svc.ImagePath)|$($svc.ServiceDll)|$($svc.StartText)|$($svc.Type)|$($svc.ObjectName)|$($svc.DisplayName)|$($svc.LastWrite)|$($drv.ImagePath)|$($drv.ServiceDll)|$($drv.StartText)|$($drv.Type)|$($null -ne $services.Find('FixtureOld'))"

    # Counts for the log: no names, only numbers
    $counts = $area.Coverage.CountsText
    Assert-KitEqual -Name "the log's counts: hives, both ways, never read, roots by way, blocks (a map entry past 4 GB skipped)" `
        -Expected "hives 9|found both ways 8|hives listed by name only 2|hives not read as their names are not in the dump 1|root keys read 6|from the base block 4|from the key control block 1|from the first cell 1|map entries skipped 1" `
        -Actual (@(($counts -split ', ') | Where-Object { $_ -match '^(hives \d|found both|hives listed|hives not read|root keys read|from the |map entries)' }) -join "|")
    Assert-KitEqual -Name "the note on how much of the hives is in the dump" -Expected "True" `
        -Actual "$(@($area.Coverage.Notes | Where-Object { $_ -match '^\d+% of the hives'' 4 KB blocks are in the dump, the rest was not in memory$' }).Count -eq 1)"

    # --- 2. Through the protocol into the builder's rows -----------------------------
    $state = New-DbgEngWorkerState
    foreach ($line in [TimelineDbgEng.EntryWriter]::Lines($area.Entries)) { Receive-DbgEngWorkerLine -Line $line -State $state }
    $capture = [datetime]::new(2026, 10, 11, 12, 30, 0, [DateTimeKind]::Utc)
    # What the collection read: run_keys.csv (HKLM: SecurityHealth same,
    # FixtureTray absent; the user's hive live: FixtureUpdater with other
    # data) and the user's collected NTUSER.DAT (a RecentDocs row: parsed)
    $null = Get-TestRows
    Add-TimelineEntry -Timestamp $capture.AddDays(-1) -Source "Persistence-RunKeys" -EventType "PersistenceChange" -Description "Run key last written: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (value: SecurityHealth)" `
        -Details "Command=%windir%\system32\SecurityHealthSystray.exe | Key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Artifact "Persistence" -RawPath "C:\cases\c1\Persistence\run_keys.csv"
    Add-TimelineEntry -Timestamp $capture.AddDays(-1) -Source "Persistence-RunKeys" -EventType "PersistenceChange" -Description "Run key last written: HKU\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (value: FixtureUpdater)" `
        -Details "Command=C:\Users\Public\fixture-updater.exe /other | Key=HKU\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Artifact "Persistence" -RawPath "C:\cases\c1\Persistence\run_keys.csv"
    Add-TimelineEntry -Timestamp $capture.AddDays(-2) -Source "Registry-RecentDocs" -EventType "FileAccess" -Description "Recent document: fixture.txt" -User "alice" -Details "MRUIndex=0" -Artifact "Registry" -RawPath "C:\cases\c1\Registry\alice\NTUSER.DAT"
    Add-TimelineEntry -Timestamp $capture.AddDays(-2) -Source "Registry-UserRunKey" -EventType "PersistenceChange" -Description "User Run key: FixtureLong = $($dump.LongCommand)" -User "alice" `
        -Details "Key=HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce; Time=key last write (key last changed; this value may be older)" -Artifact "Registry" -RawPath "C:\cases\c1\Registry\alice\NTUSER.DAT"
    $seeded = $script:timelineEntries.Count
    $results = @(Add-DbgEngEntryRows -Entries $state.Entries -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp")
    $rows = @(Get-TestRows -Objects -Keep | Select-Object -Skip $seeded)
    Assert-KitEqual -Name "Add-DbgEngEntryRows: the Hive and RunValue kinds become Memory-Registry rows (9 snapshot, 8 timed)" -Expected "Hive Memory-Registry 9 9 0 9|RunValue Memory-Registry 8 8 8 0" `
        -Actual (@($results | ForEach-Object { "$($_.Kind) $($_.Source) $($_.Received) $($_.Rows) $($_.Timed) $($_.Snapshot)" }) -join "|")
    $rowText = @($rows | ForEach-Object { "$($_.Timestamp)|$($_.Source)|$($_.EventType)|$($_.Description)|$($_.User)|$($_.Details)|$($_.Artifact)|$($_.RawPath)" })
    $hiveOffset = $hiveFields[3].Offset
    Assert-KitEqual -Name "a user's hive row: Snapshot at the capture time, the SID in User, the pipe-style Details" `
        -Expected "2026-10-11 12:30:00.000|Memory-Registry|Snapshot|Registry hive in memory: \REGISTRY\USER\S-1-5-21-1-2-3-1001|S-1-5-21-1-2-3-1001|File=C:\Users\alice\NTUSER.DAT | Readable=$($hiveFields[3].Readable)% | Root=Read | FoundBy=HiveListForward,HiveListBackward | Offset=$hiveOffset|MemoryDump|C:\dumps\fixture.dmp" `
        -Actual @($rowText | Where-Object { $_ -like "*|Registry hive in memory: \REGISTRY\USER\S-1-5-21-*" })[0]
    Assert-KitEqual -Name "SAM's row: listed by name, Root=NotRead, NotRead=CredentialHive, no Readable" `
        -Expected "Registry hive in memory: \REGISTRY\MACHINE\SAM||File=\SystemRoot\System32\Config\SAM | Root=NotRead | FoundBy=HiveListForward,HiveListBackward | NotRead=CredentialHive | Offset=$($hiveFields[5].Offset)" `
        -Actual @($rows | Where-Object { $_.Description -like "*\MACHINE\SAM" } | ForEach-Object { "$($_.Description)|$($_.User)|$($_.Details)" })[0]
    $onDisk = @($rows | Where-Object { $_.Description -like "Run key value in memory: *" } | ForEach-Object { "$(($_.Description -replace '^Run key value in memory: (.*?) \[.*$', '$1'))=$(($_.Details -replace '^OnDisk=(\w+) \|.*$', '$1'))" }) -join ","
    Assert-KitEqual -Name "OnDisk: Yes (same data in run_keys.csv), No (HKLM read, no such value), Changed (other data), the user's NTUSER.DAT read: No and Yes, Unknown (S-1-5-19 not read)" `
        -Expected "SecurityHealth=Yes,FixtureTray=No,FixtureUpdater=Changed,Fixture$([char]0x00E9)Sync=No,FixtureGone=No,FixtureLong=Yes,(Default)=No,FixtureLocalService=Unknown" -Actual $onDisk
    Assert-KitEqual -Name "a Run value row: PersistenceChange at the key's last write, the SID, OnDisk first and the value's data (Command) last, Data=Unreadable when its data is not in the dump" `
        -Expected "2026-09-07 08:00:00.000|Memory-Registry|PersistenceChange|Run key value in memory: FixtureGone [$userKey\Run]|S-1-5-21-1-2-3-1001|OnDisk=No | Key=$userKey\Run | Time=key last write | Data=Unreadable | Command=|MemoryDump|C:\dumps\fixture.dmp" `
        -Actual @($rowText | Where-Object { $_ -like "*|Run key value in memory: FixtureGone *" })[0]

    # The findings report's rules on these rows
    . (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\TimelineReport.Engine.ps1")
    $rules = Import-ReportRules -Path (Join-Path (Split-Path $BuilderPath -Parent) "lib\report\report-rules.json")
    $all = Get-TestRows -Objects
    $findings = @(Invoke-ReportRules -Rows ([System.Collections.Generic.List[object]]@($all)) -Rules $rules)
    $byRuleList = [string[]]@($findings | Where-Object { $_.RuleId -like "PERSIST-RUNKEY-*" } | ForEach-Object { "$($_.RuleId):$($_.GroupKey)" })
    [Array]::Sort($byRuleList, [System.StringComparer]::Ordinal)
    $byRule = $byRuleList -join ","
    $memoryOnly = @($rules.Rules | Where-Object { $_.Id -eq "PERSIST-RUNKEY-MEMORY-ONLY" })[0]
    $staging = "PERSIST-RUNKEY-STAGING:Run key last written: $userKey\Run (value: FixtureUpdater),PERSIST-RUNKEY-STAGING:Run key value in memory: FixtureUpdater [$userKey\Run]"
    $expectedFindings = if ($memoryOnly.Enabled) { "PERSIST-RUNKEY-MEMORY-ONLY:(Default),PERSIST-RUNKEY-MEMORY-ONLY:FixtureGone,PERSIST-RUNKEY-MEMORY-ONLY:FixtureTray,PERSIST-RUNKEY-MEMORY-ONLY:Fixture$([char]0x00E9)Sync,$staging" } else { $staging }
    Assert-KitEqual -Name "the rules on the rows: PERSIST-RUNKEY-MEMORY-ONLY for each OnDisk=No value (when enabled), PERSIST-RUNKEY-STAGING for the changed one in Users\Public (and its row of run_keys.csv)" -Expected $expectedFindings -Actual $byRule

    # --- 3. Gaps a live copy leaves -----------------------------------------------
    $partial = New-RegistryTestDump -Variant PartialUser
    $partialArea = Invoke-TestArea -Name "Registry" -Context $partial.Context
    Assert-KitEqual -Name "the user's Software subkey list not in the dump: its 5 Run keys not reached (not absent), the area partly read, a note" `
        -Expected "Partial|Run keys not in the dump 5|True|0" `
        -Actual "$($partialArea.State)|$(@(($partialArea.Coverage.CountsText -split ', ') | Where-Object { $_ -match '^Run keys not in the dump' }) -join '')|$(@($partialArea.Coverage.Notes | Where-Object { $_ -eq '5 Run key(s) could not be reached because a key above them is not in the dump' }).Count -eq 1)|$(@($partialArea.Entries | Where-Object { $_.Kind -eq 'RunValue' -and $_.Get('Hive') -like 'HKU\S-1-5-21-*' }).Count)"
    $partialServices = New-RegistryTestDump -Variant PartialServices
    $servicesArea = Invoke-TestArea -Name "Registry" -Context $partialServices.Context
    $incomplete = $partialServices.Context.Shared["RegistryServices"]
    Assert-KitEqual -Name "the Services subkey list not in the dump: not complete (so no service is called missing), partly read with its note" `
        -Expected "Partial|False|Partial|2|0|True" `
        -Actual "$($servicesArea.State)|$($incomplete.Complete)|$($incomplete.State)|$($incomplete.Listed)|$($incomplete.Read)|$(@($servicesArea.Coverage.Notes | Where-Object { $_ -eq "the Services key's subkey list is not all in the dump" }).Count -eq 1)"

    $brokenList = New-RegistryTestDump -Variant BrokenList
    $brokenArea = Invoke-TestArea -Name "Registry" -Context $brokenList.Context
    $brokenHives = @(Get-TestKindFields $brokenArea "Hive")
    Assert-KitEqual -Name "neither hive list walk gets back to its head: each hive found the way it was, partly read with a note" `
        -Expected "Partial|9|HiveListForward|HiveListBackward|True" `
        -Actual "$($brokenArea.State)|$($brokenHives.Count)|$(@($brokenHives | Where-Object { $_.Root -like '\REGISTRY\A\*' })[0].FoundBy)|$(@($brokenHives | Where-Object { $_.Root -like '\REGISTRY\WC\*' })[0].FoundBy)|$(@($brokenArea.Coverage.Notes | Where-Object { $_ -eq "neither walk of the kernel's hive list got back to its start, so a hive can be missing" }).Count -eq 1)"

    # --- 4. Not read, and the time limit ------------------------------------------------
    $noValueType = New-RegistryTestDump -Dt (Get-RegistryTestDt -Without "_CM_KEY_VALUE")
    $noType = Invoke-TestArea -Name "Registry" -Context $noValueType.Context
    $noHead = New-RegistryTestDump -Symbols @{}
    $noHeadArea = Invoke-TestArea -Name "Registry" -Context $noHead.Context
    $empty = New-RegistryTestDump -NoHives
    $emptyArea = Invoke-TestArea -Name "Registry" -Context $empty.Context
    Assert-KitEqual -Name "not read: a structure the symbols lack (named), no nt!CmpHiveListHead, an empty hive list; no entries" `
        -Expected "NotRead|the kernel's symbols do not describe the registry's structures as expected [_CM_KEY_VALUE.Signature, _CM_KEY_VALUE.NameLength, _CM_KEY_VALUE.DataLength, _CM_KEY_VALUE.Data, _CM_KEY_VALUE.Type, _CM_KEY_VALUE.Flags, _CM_KEY_VALUE.Name]|NotRead|nt!CmpHiveListHead is not in the kernel's symbols|NotRead|no hive was found in the kernel's hive list|0" `
        -Actual "$($noType.State)|$($noType.Note)|$($noHeadArea.State)|$($noHeadArea.Note)|$($emptyArea.State)|$($emptyArea.Note)|$($noType.Entries.Count + $noHeadArea.Entries.Count + $emptyArea.Entries.Count)"
    $slow = New-RegistryTestDump
    $capped = Invoke-TestArea -Name "Registry" -Context $slow.Context -CapSeconds 0.000001
    Assert-KitEqual -Name "the time limit: partly read with the limit's note, the hives still listed (not measured), no Run value" -Expected "Partial|True|9|0|0" `
        -Actual "$($capped.State)|$(@($capped.Coverage.Notes | Where-Object { $_ -match '^stopped at its time limit of ' }).Count -eq 1)|$(@($capped.Entries | Where-Object { $_.Kind -eq 'Hive' }).Count)|$(@($capped.Entries | Where-Object { $_.Kind -eq 'Hive' -and $_.Has('Readable') }).Count)|$(@($capped.Entries | Where-Object { $_.Kind -eq 'RunValue' }).Count)"

    # --- 5. The value and path texts -----------------------------------------------------
    $text = [TimelineDbgEng.RegistryText]
    $multi = [System.Text.Encoding]::Unicode.GetBytes("a`0b c`0`0")
    Assert-KitEqual -Name "value texts as run_keys.csv has them: REG_MULTI_SZ joined with '; ', DWORD, big-endian DWORD, QWORD, binary, an odd-length string, data not in the dump" `
        -Expected "a; b c|4294967295|16909060|-2|01-02-03|ab|null|REG_MULTI_SZ|0x99" `
        -Actual "$($text::Format(7, $multi))|$($text::Format(4, [byte[]](255, 255, 255, 255)))|$($text::Format(5, [byte[]](1, 2, 3, 4)))|$($text::Format(11, [BitConverter]::GetBytes([long]-2)))|$($text::Format(3, [byte[]](1, 2, 3)))|$($text::Format(1, [byte[]](97, 0, 98, 0, 99)))|$(if ($null -eq $text::Format(1, $null)) { 'null' })|$($text::TypeName(7))|$($text::TypeName(0x99))"
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $map["\Device\HarddiskVolume3"] = "C:"
    $map["\Device\HarddiskVolume30\"] = "E:\"
    Assert-KitEqual -Name "paths: \??\, \DosDevices\, the longest known device, an unknown device and \SystemRoot\ kept" `
        -Expected "C:\Users\a\NTUSER.DAT|D:\x|C:\Windows\x|E:\y|\Device\HarddiskVolume4\z|\SystemRoot\System32\Config\SYSTEM" `
        -Actual "$($text::MapPath('\??\C:\Users\a\NTUSER.DAT', $map))|$($text::MapPath('\DosDevices\D:\x', $map))|$($text::MapPath('\Device\HarddiskVolume3\Windows\x', $map))|$($text::MapPath('\Device\HarddiskVolume30\y', $map))|$($text::MapPath('\Device\HarddiskVolume4\z', $map))|$($text::MapPath('\SystemRoot\System32\Config\SYSTEM', $map))"
    Assert-KitEqual -Name "SAM and SECURITY by the last part of a root path or file name only" -Expected "True|True|True|False|False|False" `
        -Actual "$([TimelineDbgEng.RegistryScan]::IsCredential('\REGISTRY\MACHINE\SAM'))|$([TimelineDbgEng.RegistryScan]::IsCredential('\SystemRoot\System32\Config\security'))|$([TimelineDbgEng.RegistryScan]::IsCredential('C:\x\SAM\'))|$([TimelineDbgEng.RegistryScan]::IsCredential('\REGISTRY\MACHINE\SAMPLE'))|$([TimelineDbgEng.RegistryScan]::IsCredential(''))|$([TimelineDbgEng.RegistryScan]::IsCredential('\REGISTRY\MACHINE\SYSTEM'))"

    # --- 6. The OnDisk pass on its own ----------------------------------------------------
    $null = Get-TestRows
    Add-TimelineEntry -Timestamp $capture -Source "Persistence-RunKeys" -EventType "Snapshot" -Description "Run key value: Legacy [HKU\S-1-5-21-9-9-9-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (bob)]" -Details "Command=C:\legacy.exe" -Artifact "Persistence" -RawPath "C:\cases\c2\Persistence\run_keys.txt"
    $index = Get-DbgEngOnDiskRunKeys -Rows $script:timelineEntries
    $probe = { param($hive, $key, $name, $command, $file) Get-DbgEngRunValueOnDisk -Entry ([PSCustomObject]@{ Hive = $hive; Key = $key; Name = $name; Command = $command; HiveFile = $file; Data = "Read" }) -OnDisk $index }
    Assert-KitEqual -Name "OnDisk from run_keys.txt (the user in the section title left out): same data, other name, another key of a read hive, a hive not read" -Expected "Yes|No|No|Unknown" `
        -Actual "$(& $probe 'HKU\S-1-5-21-9-9-9-500' 'HKU\S-1-5-21-9-9-9-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'LEGACY' 'c:\LEGACY.exe' '')|$(& $probe 'HKU\S-1-5-21-9-9-9-500' 'HKU\S-1-5-21-9-9-9-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Other' 'x' '')|$(& $probe 'HKU\S-1-5-21-9-9-9-500' 'HKU\S-1-5-21-9-9-9-500\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' 'Legacy' 'C:\legacy.exe' '')|$(& $probe 'HKLM' 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Legacy' 'C:\legacy.exe' '')"
    $null = Get-TestRows
    $counts = Add-DbgEngRunValueRows -Entries @() -Source "Memory-Registry" -CaptureTimeUtc $capture -AcquisitionEndUtc $capture.AddMinutes(3) -DumpPath "C:\dumps\fixture.dmp"
    Assert-KitEqual -Name "no Run values: no rows" -Expected "0|0" -Actual "$($counts.Entries)|$(@(Get-TestRows).Count)"
}
catch {
    Write-KitResult -Name "test setup or run" -Passed $false -Message "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.ScriptStackTrace)"
}
Complete-KitTest
