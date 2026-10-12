# =============================================================
# Windows ARM64 memory dumps: registry hives in memory, Run values and the Services key (item g)
# Part of win11-timeline-builder (work package WP4). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads:
#   the hives    the kernel's hive list (nt!CmpHiveListHead, _CMHIVE.HiveList)
#                walked both ways, as the process list is: each hive's root
#                path and file, which walks found it, how much of it is in the
#                dump (its 4 KB blocks, found through the cell map and looked
#                up in the page tables, not read) and whether its root key
#                is. One Hive entry each.
#   Run values   Run, RunOnce (also under Wow6432Node) and Policies\Explorer\Run
#                of the SOFTWARE hive and of each user hive (\REGISTRY\USER\
#                <SID>, .DEFAULT), with the key's last write time. One
#                RunValue entry each.
#   Services     SYSTEM\<the current control set>\Services: per service key
#                its ImagePath, Parameters\ServiceDll (or its own ServiceDll),
#                Start, Type, ObjectName and DisplayName. No entries: offered
#                to the joins and the Services area as
#                $Context.Shared["RegistryServices"] (RegistryServices), with
#                Complete when its subkey list was read in full.
# SAM and SECURITY (by root path or file name), and a hive whose names are
# not in the dump, are listed by name only: none of their data is read.
#
# How cells are found: on this Windows the hive data (the bins) is mapped
# into the user address space of the "Registry" process, not the kernel's:
# a cell is read in the process the hive's view map names (_HHIVE.ViewMap
# .ProcessTuple.ProcessReference; else the process named Registry whose
# parent is System). Cell index -> _DUAL.Map
# (_HMAP_DIRECTORY) -> _HMAP_TABLE -> _HMAP_ENTRY: the cell is at
# (PermanentBinAddress & ~0xF) + BlockOffset + (index & 0xFFF), its data 4
# bytes on (after the cell's size). Every offset comes from the kernel's
# symbols ('dt'); the only fixed facts are the hive format's own (signatures
# 'regf', 'nk', 'vk', 'lf', 'lh', 'li', 'ri', 'db'; the key flags 0x4 hive
# entry and 0x20 compressed name; the value flag 0x1 compressed name; the
# inline-data bit 0x80000000 of DataLength; 16344 bytes per big-data
# segment), which are those of the registry file format and were checked on
# the three Windows 11 26100 ARM64 dumps this was built on.
#
# A live copy leaves much of the hives out (35-55% of their blocks were in
# those dumps): nothing is concluded from a key or value that is not there.
# A key is called absent only when its parent's subkey lists were read in
# full; otherwise it is "not reached" (counted, and a coverage note).
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngRegistrySource {
    return @'
namespace TimelineDbgEng
{
    // Whether addresses are in the dump, from the page tables alone
    // (IDebugDataSpaces2::VirtualToPhysical): no data page is read, so
    // measuring how much of a hive is in the dump costs a few page-table
    // pages instead of a read of every block
    public sealed partial class Session
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int VirtualToPhysicalFn(IntPtr self, ulong address, out ulong physical);
        static readonly Guid IidDataSpaces2 = new Guid("7a5e852f-96e9-468f-ac1b-0b3addc4a049");
        const int DataVirtualToPhysical = 23;   // IDebugDataSpaces2 (dbgeng.h)

        // For each address, whether it translates to a physical page in the
        // address space of eprocess (0: the kernel's); false for all when
        // the engine cannot switch to it. The process the engine had is put
        // back (callers that keep a sticky switch reset it). Returns how
        // many translate, or -1 when the engine has no VirtualToPhysical.
        public int CountInDump(ulong eprocess, ulong[] addresses, bool[] inDump)
        {
            if (client == IntPtr.Zero || addresses == null || inDump == null || inDump.Length < addresses.Length) return -1;
            IntPtr spaces2;
            Guid iid = IidDataSpaces2;
            if (Slot<QueryInterfaceFn>(client, 0)(client, ref iid, out spaces2) < 0 || spaces2 == IntPtr.Zero) return -1;
            int count = 0;
            try
            {
                if (eprocess != 0 && !SwitchProcess(eprocess)) return 0;
                VirtualToPhysicalFn translate = Slot<VirtualToPhysicalFn>(spaces2, DataVirtualToPhysical);
                for (int i = 0; i < addresses.Length; i++)
                {
                    ulong physical;
                    inDump[i] = addresses[i] != 0 && translate(spaces2, addresses[i], out physical) >= 0;
                    if (inDump[i]) count++;
                }
            }
            finally
            {
                RestoreProcess();
                Slot<ReleaseFn>(spaces2, 2)(spaces2);
            }
            return count;
        }
    }

    // The registry structures' offsets, from a Layout ('dt'), read once
    public sealed class RegistryOffsets
    {
        // The fields the area cannot do without ("_TYPE.Field")
        public static readonly string[] Required = new string[] {
            "_CMHIVE.HiveList", "_CMHIVE.FileFullPath", "_CMHIVE.HiveRootPath", "_CMHIVE.RootKcb",
            "_HHIVE.Signature", "_HHIVE.BaseBlock", "_HHIVE.Storage", "_DUAL.Length", "_DUAL.Map",
            "_HMAP_DIRECTORY.Directory", "_HMAP_TABLE.Table", "_HMAP_ENTRY.BlockOffset", "_HMAP_ENTRY.PermanentBinAddress",
            "_CM_KEY_CONTROL_BLOCK.KeyCell", "_CM_KEY_CONTROL_BLOCK.KeyHive", "_HBASE_BLOCK.Signature", "_HBASE_BLOCK.RootCell",
            "_CM_KEY_NODE.Signature", "_CM_KEY_NODE.Flags", "_CM_KEY_NODE.LastWriteTime", "_CM_KEY_NODE.SubKeyCounts",
            "_CM_KEY_NODE.SubKeyLists", "_CM_KEY_NODE.ValueList", "_CM_KEY_NODE.NameLength", "_CM_KEY_NODE.Name",
            "_CHILD_LIST.Count", "_CHILD_LIST.List",
            "_CM_KEY_VALUE.Signature", "_CM_KEY_VALUE.NameLength", "_CM_KEY_VALUE.DataLength", "_CM_KEY_VALUE.Data",
            "_CM_KEY_VALUE.Type", "_CM_KEY_VALUE.Flags", "_CM_KEY_VALUE.Name",
            "_CM_KEY_INDEX.Signature", "_CM_KEY_INDEX.Count", "_CM_KEY_INDEX.List", "_CM_INDEX.Cell",
            "_CM_BIG_DATA.Signature", "_CM_BIG_DATA.Count", "_CM_BIG_DATA.List" };

        public int HiveList, FileFullPath, FileUserName = -1, HiveRootPath, RootKcb, HiveSignature, BaseBlock, Storage, DualSize, DualLength, DualMap;
        public int Directory, Table, EntrySize, BlockOffset, BinAddress, KcbKeyCell, KcbKeyHive, BaseSignature, BaseRootCell;
        public int FlatOffset = -1, FlatPosition;
        public int NodeSignature, NodeFlags, NodeLastWrite, NodeSubKeyCounts, NodeSubKeyLists, NodeValueCount, NodeValueList, NodeNameLength, NodeName;
        public int ValueSignature, ValueNameLength, ValueDataLength, ValueData, ValueType, ValueFlags, ValueName;
        public int IndexSignature, IndexCount, IndexList, FastEntrySize, BigSignature, BigCount, BigList;
        // The bytes of a _CMHIVE the area reads (through RootKcb)
        public int HiveBytes;
        public ulong ListHead;           // nt!CmpHiveListHead
        // _HHIVE.ViewMap -> _HVP_VIEW_MAP.ProcessTuple -> _CMSI_PROCESS_TUPLE.ProcessReference:
        // the process whose address space holds the hive's views (-1: not in the symbols)
        public int ViewMapTuple = -1, TupleProcess = -1;

        public static RegistryOffsets From(Layout l)
        {
            RegistryOffsets o = new RegistryOffsets();
            int hive = Math.Max(0, l.Off("_CMHIVE.Hive"));
            o.HiveList = l.Off("_CMHIVE.HiveList");
            o.FileFullPath = l.Off("_CMHIVE.FileFullPath");
            o.FileUserName = l.Off("_CMHIVE.FileUserName");
            o.HiveRootPath = l.Off("_CMHIVE.HiveRootPath");
            o.RootKcb = l.Off("_CMHIVE.RootKcb");
            o.HiveSignature = hive + l.Off("_HHIVE.Signature");
            o.BaseBlock = hive + l.Off("_HHIVE.BaseBlock");
            o.Storage = hive + l.Off("_HHIVE.Storage");
            int[] flat;
            if (l.Bits.TryGetValue("_HHIVE.Flat", out flat)) { o.FlatOffset = hive + l.Off("_HHIVE.Flat"); o.FlatPosition = flat[0]; }
            o.DualSize = l.Size("_DUAL");
            o.DualLength = l.Off("_DUAL.Length");
            o.DualMap = l.Off("_DUAL.Map");
            o.Directory = l.Off("_HMAP_DIRECTORY.Directory");
            o.Table = l.Off("_HMAP_TABLE.Table");
            o.EntrySize = l.Size("_HMAP_ENTRY");
            o.BlockOffset = l.Off("_HMAP_ENTRY.BlockOffset");
            o.BinAddress = l.Off("_HMAP_ENTRY.PermanentBinAddress");
            o.KcbKeyCell = l.Off("_CM_KEY_CONTROL_BLOCK.KeyCell");
            o.KcbKeyHive = l.Off("_CM_KEY_CONTROL_BLOCK.KeyHive");
            o.BaseSignature = l.Off("_HBASE_BLOCK.Signature");
            o.BaseRootCell = l.Off("_HBASE_BLOCK.RootCell");
            o.NodeSignature = l.Off("_CM_KEY_NODE.Signature");
            o.NodeFlags = l.Off("_CM_KEY_NODE.Flags");
            o.NodeLastWrite = l.Off("_CM_KEY_NODE.LastWriteTime");
            o.NodeSubKeyCounts = l.Off("_CM_KEY_NODE.SubKeyCounts");
            o.NodeSubKeyLists = l.Off("_CM_KEY_NODE.SubKeyLists");
            o.NodeValueCount = l.Off("_CM_KEY_NODE.ValueList") + l.Off("_CHILD_LIST.Count");
            o.NodeValueList = l.Off("_CM_KEY_NODE.ValueList") + l.Off("_CHILD_LIST.List");
            o.NodeNameLength = l.Off("_CM_KEY_NODE.NameLength");
            o.NodeName = l.Off("_CM_KEY_NODE.Name");
            o.ValueSignature = l.Off("_CM_KEY_VALUE.Signature");
            o.ValueNameLength = l.Off("_CM_KEY_VALUE.NameLength");
            o.ValueDataLength = l.Off("_CM_KEY_VALUE.DataLength");
            o.ValueData = l.Off("_CM_KEY_VALUE.Data");
            o.ValueType = l.Off("_CM_KEY_VALUE.Type");
            o.ValueFlags = l.Off("_CM_KEY_VALUE.Flags");
            o.ValueName = l.Off("_CM_KEY_VALUE.Name");
            o.IndexSignature = l.Off("_CM_KEY_INDEX.Signature");
            o.IndexCount = l.Off("_CM_KEY_INDEX.Count");
            o.IndexList = l.Off("_CM_KEY_INDEX.List");
            o.FastEntrySize = l.Size("_CM_INDEX") > 0 ? l.Size("_CM_INDEX") : 8;
            o.BigSignature = l.Off("_CM_BIG_DATA.Signature");
            o.BigCount = l.Off("_CM_BIG_DATA.Count");
            o.BigList = l.Off("_CM_BIG_DATA.List");
            o.HiveBytes = Math.Max(Math.Max(o.HiveList + 16, Math.Max(o.FileFullPath, o.FileUserName) + 16), Math.Max(o.HiveRootPath + 16, o.RootKcb + 8));
            o.HiveBytes = Math.Max(o.HiveBytes, o.Storage + 2 * Math.Max(o.DualSize, o.DualMap + 8));
            o.ListHead = l.Symbol("nt!CmpHiveListHead");
            if (l.Has("_HHIVE.ViewMap") && l.Has("_HVP_VIEW_MAP.ProcessTuple") && l.Has("_CMSI_PROCESS_TUPLE.ProcessReference"))
            {
                o.ViewMapTuple = hive + l.Off("_HHIVE.ViewMap") + l.Off("_HVP_VIEW_MAP.ProcessTuple");
                o.TupleProcess = l.Off("_CMSI_PROCESS_TUPLE.ProcessReference");
                o.HiveBytes = Math.Max(o.HiveBytes, o.ViewMapTuple + 8);
            }
            return o;
        }
        // The sizes 'dt' must give, and whether they are plausible
        public bool SizesValid
        {
            get { return DualSize >= DualMap + 8 && EntrySize >= Math.Max(BlockOffset, BinAddress) + 8 && HiveBytes <= 0x10000; }
        }
    }

    // One hive of the kernel's hive list
    public sealed class HiveInfo
    {
        public ulong Address;                       // the _CMHIVE (its _HHIVE)
        public string RootPath;                     // HiveRootPath, null when not in the dump
        public string FilePath;                     // its file as the kernel has it, null when not in the dump
        public bool Forward;                        // found walking the list forward
        public bool Backward;                       // ... and backward
        // Never read: "CredentialHive" (SAM or SECURITY), "NamesNotInDump"
        // (its root path is not in the dump: it could be one of them); ""
        // when it is read
        public string NotRead = "";
        public bool Flat;
        public ulong BaseBlock;
        public ulong RootKcb;
        public ulong Process;                       // the process whose address space holds its views (0: none, kernel memory)
        public readonly ulong[] Maps = new ulong[2];       // Storage[Stable/Volatile].Map
        public readonly uint[] Lengths = new uint[2];      // Storage[...].Length (bytes)
        public uint RootCell = HiveCells.NoCell;
        public string RootFrom = "";                // BaseBlock, KeyControlBlock, FirstCell
        public string RootState = "";               // Read, Unreadable, NotRead
        public long Blocks = -1;                    // 4 KB blocks of its stable storage (-1: not measured)
        public long ReadableBlocks;
        public long SkippedEntries;                 // map entries with an implausible BlockOffset

        public string FoundBy
        {
            get
            {
                if (Forward && Backward) return "HiveListForward,HiveListBackward";
                return Forward ? "HiveListForward" : "HiveListBackward";
            }
        }
        // "45" (percent of its blocks in the dump), null when not measured
        public string ReadablePercent
        {
            get
            {
                if (Blocks < 0) return null;
                if (Blocks == 0) return "0";
                return ((long)Math.Floor(100.0 * ReadableBlocks / Blocks + 0.5)).ToString(CultureInfo.InvariantCulture);
            }
        }
        // The SID of a user hive (\REGISTRY\USER\<SID> or <SID>_Classes;
        // .DEFAULT is the system account's), else ""
        public string Sid
        {
            get
            {
                string leaf = UserLeaf;
                if (leaf == null) return "";
                if (leaf.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) leaf = leaf.Substring(0, leaf.Length - 8);
                if (string.Equals(leaf, ".DEFAULT", StringComparison.OrdinalIgnoreCase)) return "S-1-5-18";
                return RegistryText.IsSid(leaf) ? leaf : "";
            }
        }
        // A user's own hive (NTUSER.DAT, .DEFAULT; not _Classes)
        public bool IsUserHive
        {
            get
            {
                string leaf = UserLeaf;
                if (leaf == null || leaf.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return false;
                return string.Equals(leaf, ".DEFAULT", StringComparison.OrdinalIgnoreCase) || RegistryText.IsSid(leaf);
            }
        }
        string UserLeaf
        {
            get
            {
                const string prefix = "\\REGISTRY\\USER\\";
                if (RootPath == null || !RootPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
                string leaf = RootPath.Substring(prefix.Length);
                return leaf.Length == 0 || leaf.IndexOf('\\') >= 0 ? null : leaf;
            }
        }
        // "HKLM" for the SOFTWARE hive, "HKU\<SID>" (or HKU\.DEFAULT) for a user's
        public string KeyPrefix
        {
            get
            {
                if (IsMachine("SOFTWARE")) return "HKLM\\SOFTWARE";
                if (IsUserHive) return "HKU\\" + RootPath.Substring(15);
                return "";
            }
        }
        public bool IsMachine(string name)
        {
            return RootPath != null && string.Equals(RootPath, "\\REGISTRY\\MACHINE\\" + name, StringComparison.OrdinalIgnoreCase);
        }
    }

    // A key node ('nk')
    public sealed class RegKey
    {
        public uint Cell;
        public string Name = "";
        public ushort Flags;
        public long LastWrite;
        public readonly uint[] SubKeyCounts = new uint[2];
        public readonly uint[] SubKeyLists = new uint[2];
        public uint ValueCount;
        public uint ValueList;
    }

    // A value ('vk'): its data, null when not in the dump
    public sealed class RegValue
    {
        public string Name = "";
        public uint Type;
        public byte[] Data;
        public string Text { get { return RegistryText.Format(Type, Data); } }
        public long Number { get { return RegistryText.Number(Type, Data); } }
    }

    // Text forms of the registry's values
    public static class RegistryText
    {
        public static string TypeName(uint type)
        {
            switch (type)
            {
                case 0: return "REG_NONE";
                case 1: return "REG_SZ";
                case 2: return "REG_EXPAND_SZ";
                case 3: return "REG_BINARY";
                case 4: return "REG_DWORD";
                case 5: return "REG_DWORD_BIG_ENDIAN";
                case 6: return "REG_LINK";
                case 7: return "REG_MULTI_SZ";
                case 11: return "REG_QWORD";
                default: return "0x" + type.ToString("x", CultureInfo.InvariantCulture);
            }
        }
        // As the triage collector's run_keys.csv writes a value (not
        // expanded): text as stored (to its first NUL), a list joined with
        // "; ", a number in decimal, other bytes as "AA-BB-..."; null when
        // the data is not in the dump
        public static string Format(uint type, byte[] data)
        {
            if (data == null) return null;
            switch (type)
            {
                case 1: case 2: case 6:
                    {
                        string s = Utf16(data);
                        int nul = s.IndexOf('\0');
                        return nul >= 0 ? s.Substring(0, nul) : s;
                    }
                case 7:
                    {
                        string[] parts = Utf16(data).Split('\0');
                        List<string> kept = new List<string>();
                        foreach (string p in parts) { if (p.Length > 0) kept.Add(p); }
                        return string.Join("; ", kept.ToArray());
                    }
                case 4: case 5: case 11:
                    {
                        long n = Number(type, data);
                        return n < 0 && type != 11 ? BitConverter.ToString(data) : n.ToString(CultureInfo.InvariantCulture);
                    }
                default:
                    return BitConverter.ToString(data, 0, Math.Min(data.Length, 4096));
            }
        }
        // A DWORD or QWORD value; -1 when it is not one or not in the dump
        public static long Number(uint type, byte[] data)
        {
            if (data == null) return -1;
            if (type == 4 && data.Length >= 4) return BitConverter.ToUInt32(data, 0);
            if (type == 5 && data.Length >= 4) return ((long)data[0] << 24) | ((long)data[1] << 16) | ((long)data[2] << 8) | data[3];
            if (type == 11 && data.Length >= 8) return BitConverter.ToInt64(data, 0);
            return -1;
        }
        static string Utf16(byte[] data)
        {
            int n = data.Length - (data.Length % 2);
            return Encoding.Unicode.GetString(data, 0, n);
        }
        public static bool IsSid(string s)
        {
            if (string.IsNullOrEmpty(s) || !s.StartsWith("S-1-", StringComparison.Ordinal) || s.Length > 184) return false;
            for (int i = 4; i < s.Length; i++)
            {
                char c = s[i];
                if (!(c == '-' || (c >= '0' && c <= '9'))) return false;
            }
            return !s.EndsWith("-", StringComparison.Ordinal);
        }
        // A file path of the kernel as the rows give it: "\??\C:\x" -> "C:\x",
        // "\Device\HarddiskVolume3\x" through the device-to-drive map when it
        // knows the device, else as it is
        public static string MapPath(string path, Dictionary<string, string> driveMap)
        {
            if (string.IsNullOrEmpty(path)) return path ?? "";
            if (path.StartsWith("\\??\\", StringComparison.Ordinal) && path.Length >= 6 && path[5] == ':') return path.Substring(4);
            if (path.StartsWith("\\DosDevices\\", StringComparison.OrdinalIgnoreCase) && path.Length >= 14 && path[13] == ':') return path.Substring(12);
            if (driveMap != null && path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
            {
                string best = null, drive = null;
                foreach (KeyValuePair<string, string> pair in driveMap)
                {
                    string device = pair.Key.TrimEnd('\\');
                    if (device.Length > 0 && path.Length > device.Length && path[device.Length] == '\\' && path.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                        (best == null || device.Length > best.Length)) { best = device; drive = pair.Value; }
                }
                if (best != null && !string.IsNullOrEmpty(drive)) return drive.TrimEnd('\\') + path.Substring(best.Length);
            }
            return path;
        }
        // The name of a key's subkey list hash ('lh'): each character
        // upper-cased, hash = hash * 37 + character
        public static uint NameHash(string name)
        {
            uint h = 0;
            foreach (char c in name) h = unchecked(h * 37 + (uint)char.ToUpperInvariant(c));
            return h;
        }
    }

    // The cells of one hive, read through its cell map in the Registry
    // process's address space
    public sealed class HiveCells
    {
        public const uint NoCell = 0xFFFFFFFF;
        public const ushort SigKey = 0x6b6e, SigValue = 0x6b76, SigFastLeaf = 0x666c, SigHashLeaf = 0x686c, SigIndexLeaf = 0x696c, SigRootIndex = 0x6972, SigBigData = 0x6264;
        public const ushort KeyHiveEntry = 0x4, KeyCompressedName = 0x20, ValueCompressedName = 0x1;
        public const int BigDataSegment = 16344;
        public const int MaxCellBytes = 1 << 20;
        public const int MaxListCount = 1 << 16;

        readonly MemoryReader reader;
        readonly ulong process;
        readonly HiveInfo hive;
        readonly RegistryOffsets o;
        readonly Dictionary<uint, ulong> tables = new Dictionary<uint, ulong>();
        public long CellReads;
        public long CellsUnreadable;

        public HiveCells(MemoryReader reader, ulong process, HiveInfo hive, RegistryOffsets offsets)
        {
            this.reader = reader;
            this.process = process;
            this.hive = hive;
            o = offsets;
        }

        // The _HMAP_TABLE of a directory slot (0 when not in the dump)
        ulong Table(int type, uint dir)
        {
            uint key = ((uint)type << 10) | dir;
            ulong table;
            if (tables.TryGetValue(key, out table)) return table;
            table = 0;
            ulong map = hive.Maps[type];
            if (map != 0)
            {
                ulong t;
                if (reader.TryU64(process, map + (ulong)o.Directory + 8UL * dir, out t) && t != 0 && (t & 7) == 0) table = t;
            }
            tables[key] = table;
            return table;
        }

        // The map entry of a block: its bin's address plus the block's
        // offset in it; 0 when not in the dump. skipped: the entry's
        // BlockOffset is implausible (more than 4 GB).
        public ulong BlockAddress(int type, uint block, out bool skipped)
        {
            skipped = false;
            ulong table = Table(type, (block >> 9) & 0x3FF);
            if (table == 0) return 0;
            byte[] e;
            if (!reader.TryRead(process, table + (ulong)o.Table + (ulong)o.EntrySize * (block & 0x1FF), o.EntrySize, out e)) return 0;
            ulong offset = Bytes.U64(e, o.BlockOffset);
            ulong bin = Bytes.U64(e, o.BinAddress) & ~0xFUL;
            if (offset > 0xFFFFFFFFUL) { skipped = true; return 0; }
            if (bin == 0) return 0;
            return bin + offset;
        }

        // The address of a cell (its size field); 0 when it cannot be found
        public ulong CellAddress(uint cell)
        {
            if (cell == NoCell) return 0;
            int type = (int)(cell >> 31);
            uint offset = cell & 0x7FFFFFFF;
            if (offset >= hive.Lengths[type]) return 0;
            if (hive.Flat) return type == 0 && hive.BaseBlock != 0 ? hive.BaseBlock + 0x1000UL + offset : 0;
            bool skipped;
            ulong block = BlockAddress(type, offset >> 12, out skipped);
            return block == 0 ? 0 : block + (offset & 0xFFF);
        }

        // A cell's data (after its size): at most max bytes, fewer when the
        // cell is smaller; null when it is not in the dump or not an
        // allocated cell of a plausible size
        public byte[] Cell(uint cell, int max)
        {
            CellReads++;
            ulong address = CellAddress(cell);
            uint size;
            if (address == 0 || !reader.TryU32(process, address, out size)) { CellsUnreadable++; return null; }
            int length = -(int)size;
            if ((int)size >= 0 || length < 8 || length > MaxCellBytes) { CellsUnreadable++; return null; }
            int count = Math.Min(length - 4, max);
            byte[] data;
            if (!reader.TryRead(process, address + 4, count, out data)) { CellsUnreadable++; return null; }
            return data;
        }

        // A key node, null when not in the dump or not a key node
        public RegKey Key(uint cell)
        {
            byte[] b = Cell(cell, o.NodeName + 2 * 512);
            if (b == null || b.Length < o.NodeName || Bytes.U16(b, o.NodeSignature) != SigKey) return null;
            RegKey k = new RegKey();
            k.Cell = cell;
            k.Flags = Bytes.U16(b, o.NodeFlags);
            k.LastWrite = Bytes.I64(b, o.NodeLastWrite);
            for (int i = 0; i < 2; i++)
            {
                k.SubKeyCounts[i] = Bytes.U32(b, o.NodeSubKeyCounts + 4 * i);
                k.SubKeyLists[i] = Bytes.U32(b, o.NodeSubKeyLists + 4 * i);
            }
            k.ValueCount = Bytes.U32(b, o.NodeValueCount);
            k.ValueList = Bytes.U32(b, o.NodeValueList);
            int nameLength = Bytes.U16(b, o.NodeNameLength);
            if (o.NodeName + nameLength > b.Length) return null;
            k.Name = (k.Flags & KeyCompressedName) != 0 ? Latin1(b, o.NodeName, nameLength) : Encoding.Unicode.GetString(b, o.NodeName, nameLength - (nameLength % 2));
            return k;
        }

        static string Latin1(byte[] b, int offset, int count)
        {
            char[] c = new char[count];
            for (int i = 0; i < count; i++) c[i] = (char)b[offset + i];
            return new string(c);
        }

        // The cells of a key's subkeys (stable and volatile); complete: every
        // list the key names was read and holds as many subkeys as it says.
        // hash: only those of an 'lh' list with this name hash (0: all).
        public List<uint> SubKeys(RegKey key, uint hash, bool useHash, out bool complete)
        {
            List<uint> cells = new List<uint>();
            complete = true;
            for (int i = 0; i < 2; i++)
            {
                uint count = key.SubKeyCounts[i];
                if (count == 0) continue;
                if (count > MaxListCount) { complete = false; continue; }
                long listed = 0;
                if (!ReadIndex(key.SubKeyLists[i], hash, useHash, cells, ref listed, 0)) complete = false;
                if (listed != count) complete = false;
            }
            return cells;
        }

        // One subkey index cell (lf, lh, li, or ri of those); false when a
        // part is not in the dump
        bool ReadIndex(uint cell, uint hash, bool useHash, List<uint> cells, ref long listed, int depth)
        {
            byte[] b = Cell(cell, o.IndexList + 8 * MaxListCount);
            if (b == null || b.Length < o.IndexList) return false;
            ushort sig = Bytes.U16(b, o.IndexSignature);
            int count = Bytes.U16(b, o.IndexCount);
            if (sig == SigFastLeaf || sig == SigHashLeaf)
            {
                if (o.IndexList + o.FastEntrySize * count > b.Length) return false;
                for (int i = 0; i < count; i++)
                {
                    int at = o.IndexList + o.FastEntrySize * i;
                    listed++;
                    if (useHash && sig == SigHashLeaf && Bytes.U32(b, at + 4) != hash) continue;
                    cells.Add(Bytes.U32(b, at));
                }
                return true;
            }
            if (sig == SigIndexLeaf)
            {
                if (o.IndexList + 4 * count > b.Length) return false;
                for (int i = 0; i < count; i++) { listed++; cells.Add(Bytes.U32(b, o.IndexList + 4 * i)); }
                return true;
            }
            if (sig == SigRootIndex && depth == 0)
            {
                if (o.IndexList + 4 * count > b.Length) return false;
                bool all = true;
                for (int i = 0; i < count; i++)
                {
                    if (!ReadIndex(Bytes.U32(b, o.IndexList + 4 * i), hash, useHash, cells, ref listed, 1)) all = false;
                }
                return all;
            }
            return false;
        }

        // The subkey of this name (case-insensitive), null when there is
        // none or it cannot be read; absent: true only when there is none
        // and the subkey lists were read in full (a key that is not in the
        // dump is never "absent")
        public RegKey Child(RegKey key, string name, out bool absent)
        {
            absent = false;
            bool complete;
            List<uint> cells = SubKeys(key, RegistryText.NameHash(name), true, out complete);
            bool unread = false;
            foreach (uint c in cells)
            {
                RegKey k = Key(c);
                if (k == null) { unread = true; continue; }
                if (string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase)) return k;
            }
            absent = complete && !unread;
            return null;
        }

        // The key at a path of subkey names under key ("A\B\C"); absent as
        // for Child
        public RegKey Path(RegKey key, string path, out bool absent)
        {
            absent = false;
            RegKey at = key;
            foreach (string part in path.Split('\\'))
            {
                if (part.Length == 0) continue;
                at = Child(at, part, out absent);
                if (at == null) return null;
            }
            return at;
        }

        // A key's values; complete: its value list and every value cell were
        // read (a value's data may still be missing: RegValue.Data null)
        public List<RegValue> Values(RegKey key, out bool complete)
        {
            List<RegValue> values = new List<RegValue>();
            complete = true;
            if (key.ValueCount == 0) return values;
            if (key.ValueCount > MaxListCount) { complete = false; return values; }
            byte[] list = Cell(key.ValueList, 4 * (int)key.ValueCount);
            if (list == null || list.Length < 4 * key.ValueCount) { complete = false; return values; }
            for (int i = 0; i < key.ValueCount; i++)
            {
                RegValue v = Value(BitConverter.ToUInt32(list, 4 * i));
                if (v == null) { complete = false; continue; }
                values.Add(v);
            }
            return values;
        }

        // A value cell with its data (Data null when that is not in the dump)
        public RegValue Value(uint cell)
        {
            byte[] b = Cell(cell, o.ValueName + 2 * 16383);
            if (b == null || b.Length < o.ValueName || Bytes.U16(b, o.ValueSignature) != SigValue) return null;
            RegValue v = new RegValue();
            int nameLength = Bytes.U16(b, o.ValueNameLength);
            if (o.ValueName + nameLength > b.Length) return null;
            ushort flags = Bytes.U16(b, o.ValueFlags);
            v.Name = (flags & ValueCompressedName) != 0 ? Latin1(b, o.ValueName, nameLength) : Encoding.Unicode.GetString(b, o.ValueName, nameLength - (nameLength % 2));
            v.Type = Bytes.U32(b, o.ValueType);
            uint length = Bytes.U32(b, o.ValueDataLength);
            uint data = Bytes.U32(b, o.ValueData);
            if ((length & 0x80000000) != 0)
            {
                int n = (int)Math.Min(length & 0x7FFFFFFF, 4u);
                v.Data = new byte[n];
                Array.Copy(b, o.ValueData, v.Data, 0, n);
            }
            else if (length == 0) v.Data = new byte[0];
            else if (length <= MaxCellBytes) v.Data = Data(data, (int)length);
            return v;
        }

        // A value's data of length bytes: one cell, or big data ('db': a
        // list of segment cells); null when not in the dump
        byte[] Data(uint cell, int length)
        {
            byte[] b = Cell(cell, length);
            if (b == null) return null;
            if (length > BigDataSegment && b.Length >= 8 && Bytes.U16(b, o.BigSignature) == SigBigData)
            {
                int count = Bytes.U16(b, o.BigCount);
                byte[] list = Cell(Bytes.U32(b, o.BigList), 4 * count);
                if (list == null || list.Length < 4 * count) return null;
                byte[] all = new byte[length];
                int done = 0;
                for (int i = 0; i < count && done < length; i++)
                {
                    byte[] part = Cell(BitConverter.ToUInt32(list, 4 * i), Math.Min(BigDataSegment, length - done));
                    if (part == null) return null;
                    Buffer.BlockCopy(part, 0, all, done, part.Length);
                    done += part.Length;
                }
                return done == length ? all : null;
            }
            return b.Length == length ? b : null;
        }

        // The value of this name (case-insensitive), null when not read
        public RegValue Named(List<RegValue> values, string name)
        {
            foreach (RegValue v in values) { if (string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase)) return v; }
            return null;
        }
    }

    // One service key of SYSTEM\<control set>\Services as read from memory
    public sealed class RegistryServiceKey
    {
        public string Name = "";
        public long LastWrite;                      // FILETIME of the key
        public bool ValuesComplete;                 // every value of the key was read
        public string ImagePath;                    // null when absent or not in the dump
        public string ServiceDll;                   // Parameters\ServiceDll, else the key's own
        public string ObjectName;
        public string DisplayName;
        public long Start = -1;                     // -1: absent or not in the dump
        public long Type = -1;
        public string StartText { get { return ServiceText(Start, new string[] { "SERVICE_BOOT_START", "SERVICE_SYSTEM_START", "SERVICE_AUTO_START", "SERVICE_DEMAND_START", "SERVICE_DISABLED" }); } }
        static string ServiceText(long value, string[] names)
        {
            if (value >= 0 && value < names.Length) return names[value];
            return value < 0 ? "" : value.ToString(CultureInfo.InvariantCulture);
        }
    }

    // The Services key of the SYSTEM hive in memory, for the joins and the
    // Services area (MemoryContext.Shared["RegistryServices"])
    public sealed class RegistryServices
    {
        public string State = "NotRead";            // Read, Partial, NotRead
        public string Why = "";                     // why not (or not in full)
        public string ControlSet = "";              // "ControlSet001"
        public string ControlSetFrom = "";          // Select (SYSTEM\Select\Current), Link (CurrentControlSet), Default
        public long Listed;                         // subkeys the Services key says it has
        public long Read;                           // subkeys whose key was read
        public bool Complete;                       // every subkey listed and read: a service missing here is not in the key
        public readonly Dictionary<string, RegistryServiceKey> Keys = new Dictionary<string, RegistryServiceKey>(StringComparer.OrdinalIgnoreCase);
        public RegistryServiceKey Find(string name)
        {
            RegistryServiceKey k;
            return name != null && Keys.TryGetValue(name, out k) ? k : null;
        }
    }

    // The area
    public sealed class RegistryScan
    {
        // Relative to the SOFTWARE hive's root and to a user hive's Software key
        public static readonly string[] RunPaths = new string[] {
            "Microsoft\\Windows\\CurrentVersion\\Run", "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" };
        public const int ListCap = 4096;

        public readonly List<HiveInfo> Hives = new List<HiveInfo>();
        public readonly RegistryServices Services = new RegistryServices();
        public ulong RegistryProcess;
        public string RegistryProcessFrom = "";
        // Seconds per part ("hives 0.1, services 0.4, ..."), for the log
        public readonly List<string> Timings = new List<string>();
        public bool ListComplete;
        public long CellReads, CellsUnreadable;

        // How the blocks in the dump were counted: "page tables" (the engine's
        // translation of each block's address) or "reading" (a byte of each)
        public string MeasuredBy = "";
        bool byReading;
        readonly MemoryContext context;
        readonly AreaResult area;
        readonly RegistryOffsets o;
        readonly MemoryReader reader;

        RegistryScan(MemoryContext context, AreaResult area, RegistryOffsets offsets)
        {
            this.context = context;
            this.area = area;
            o = offsets;
            reader = context.Reader;
        }

        public static RegistryScan Run(MemoryContext context, AreaResult area, Layout layout) { return Run(context, area, layout, false); }

        // byReading: how much of each hive is in the dump by reading a byte
        // of each block, not from the page tables (as without the engine)
        public static RegistryScan Run(MemoryContext context, AreaResult area, Layout layout, bool byReading)
        {
            RegistryScan scan = new RegistryScan(context, area, RegistryOffsets.From(layout));
            scan.byReading = byReading;
            context.Shared["RegistryServices"] = scan.Services;
            context.Shared["RegistryHives"] = scan.Hives;
            scan.Go();
            return scan;
        }

        void Go()
        {
            if (!o.SizesValid) { area.SetNotRead("the kernel's registry structures have a layout the builder does not read"); return; }
            if (!MemoryReader.IsKernelPointer(o.ListHead)) { area.SetNotRead("nt!CmpHiveListHead is not in the kernel's symbols"); return; }
            Stopwatch watch = Stopwatch.StartNew();
            ReadHiveList();
            if (Hives.Count == 0) { area.SetNotRead("no hive was found in the kernel's hive list"); return; }
            foreach (HiveInfo h in Hives) ReadHive(h);
            FindRegistryProcess();
            List<HiveCells> cells = new List<HiveCells>();
            foreach (HiveInfo h in Hives) cells.Add(h.NotRead.Length > 0 ? null : new HiveCells(reader, h.Process, h, o));
            for (int i = 0; i < Hives.Count; i++) { if (cells[i] != null) FindRoot(Hives[i], cells[i]); }
            Lap("hives", watch);

            // What the rows and the joins need first, then how much of each
            // hive is in the dump
            ReadServices(cells);
            Lap("services", watch);
            ReadRunValues(cells);
            Lap("run values", watch);
            Measure(cells);
            Lap("blocks", watch);
            foreach (HiveCells c in cells) { if (c != null) { CellReads += c.CellReads; CellsUnreadable += c.CellsUnreadable; } }
            AddHiveEntries();
            Summarize();
        }

        // The area's time limit reached: it is partly read, and says so
        bool timeUp;
        bool Stop()
        {
            if (!timeUp && area.TimeUp()) timeUp = true;
            return timeUp;
        }

        void Lap(string name, Stopwatch watch)
        {
            Timings.Add(name + " " + watch.Elapsed.TotalSeconds.ToString("0.00", CultureInfo.InvariantCulture));
            watch.Reset();
            watch.Start();
        }

        // The Registry process, whose address space holds the hive data: the
        // process most hives' view maps name (a process of the scan), else
        // the process named Registry whose parent is System. A hive whose
        // view map names no process of the scan is read in it too (a hive
        // without views, such as HARDWARE, is in kernel memory, which any
        // process reads).
        void FindRegistryProcess()
        {
            Dictionary<ulong, int> votes = new Dictionary<ulong, int>();
            int best = 0;
            foreach (HiveInfo h in Hives)
            {
                if (h.Process == 0) continue;
                int n;
                votes.TryGetValue(h.Process, out n);
                votes[h.Process] = ++n;
                if (n > best) { best = n; RegistryProcess = h.Process; RegistryProcessFrom = "ViewMap"; }
            }
            if (RegistryProcess == 0)
            {
                foreach (ProcessInfo p in context.Processes)
                {
                    if (p.Ppid == 4 && p.ExitTime == 0 && string.Equals(p.ShortName, "Registry", StringComparison.Ordinal))
                    {
                        RegistryProcess = p.Eprocess;
                        RegistryProcessFrom = "Name";
                        break;
                    }
                }
            }
            int mapped = 0;
            foreach (HiveInfo h in Hives)
            {
                if (h.Process != 0) mapped++;
                else if (h.NotRead.Length == 0) h.Process = RegistryProcess;
            }
            area.Coverage.Count("hives whose views a process holds", mapped);
        }

        // The hive list walked both ways (as the process list is)
        void ReadHiveList()
        {
            bool forwardDone, backwardDone;
            List<ulong> forward = Walk(0, out forwardDone);
            List<ulong> backward = Walk(8, out backwardDone);
            ListComplete = forwardDone && backwardDone;
            Dictionary<ulong, HiveInfo> byAddress = new Dictionary<ulong, HiveInfo>();
            foreach (ulong link in forward) Add(link, true, byAddress);
            foreach (ulong link in backward) Add(link, false, byAddress);
            area.Coverage.Count("hives", Hives.Count);
            int both = 0;
            foreach (HiveInfo h in Hives) { if (h.Forward && h.Backward) both++; }
            area.Coverage.Count("found both ways", both);
            if (!forwardDone || !backwardDone)
            {
                area.Coverage.Count("hive list walks that did not end at the list head", (forwardDone ? 0 : 1) + (backwardDone ? 0 : 1));
                if (!forwardDone && !backwardDone) area.SetPartial("neither walk of the kernel's hive list got back to its start, so a hive can be missing");
            }
        }

        List<ulong> Walk(int linkOffset, out bool done)
        {
            List<ulong> links = new List<ulong>();
            HashSet<ulong> seen = new HashSet<ulong>();
            done = false;
            ulong at = o.ListHead;
            while (links.Count < ListCap)
            {
                ulong next;
                if (!reader.TryU64(0, at + (ulong)linkOffset, out next)) break;
                if (next == o.ListHead) { done = true; break; }
                if (!MemoryReader.IsKernelPointer(next) || !seen.Add(next)) break;
                links.Add(next);
                at = next;
            }
            return links;
        }

        void Add(ulong link, bool forward, Dictionary<ulong, HiveInfo> byAddress)
        {
            ulong address = link - (ulong)o.HiveList;
            HiveInfo h;
            if (!byAddress.TryGetValue(address, out h))
            {
                uint signature;
                if (!reader.TryU32(0, address + (ulong)o.HiveSignature, out signature) || signature != 0xBEE0BEE0) return;
                h = new HiveInfo();
                h.Address = address;
                byAddress[address] = h;
                Hives.Add(h);
            }
            if (forward) h.Forward = true; else h.Backward = true;
        }

        // The hive's names, storage and cell map, and whether it may be read
        void ReadHive(HiveInfo h)
        {
            h.RootPath = reader.UnicodeString(0, h.Address + (ulong)o.HiveRootPath);
            // The file: FileUserName ("\??\C:\Users\...\NTUSER.DAT",
            // "\SystemRoot\System32\Config\SOFTWARE"); FileFullPath, which
            // Windows 11 26100 leaves empty, when that has none
            string user = o.FileUserName >= 0 ? reader.UnicodeString(0, h.Address + (ulong)o.FileUserName) : null;
            string full = reader.UnicodeString(0, h.Address + (ulong)o.FileFullPath);
            h.FilePath = !string.IsNullOrEmpty(user) ? user : (!string.IsNullOrEmpty(full) ? full : (user ?? full));
            if (IsCredential(h.RootPath) || IsCredential(h.FilePath)) h.NotRead = "CredentialHive";
            else if (h.RootPath == null) h.NotRead = "NamesNotInDump";
            if (h.NotRead.Length > 0) { h.RootState = "NotRead"; return; }
            byte[] b = reader.Read(0, h.Address, o.HiveBytes);
            h.BaseBlock = Bytes.U64(b, o.BaseBlock);
            h.RootKcb = Bytes.U64(b, o.RootKcb);
            if (o.FlatOffset >= 0) h.Flat = ((Bytes.U32(b, o.FlatOffset) >> o.FlatPosition) & 1) != 0;
            if (o.ViewMapTuple >= 0)
            {
                ulong tuple = Bytes.U64(b, o.ViewMapTuple);
                ulong process;
                if (MemoryReader.IsKernelPointer(tuple) && reader.TryU64(0, tuple + (ulong)o.TupleProcess, out process) && context.Find(process) != null) h.Process = process;
            }
            for (int i = 0; i < 2; i++)
            {
                int dual = o.Storage + i * o.DualSize;
                h.Lengths[i] = Bytes.U32(b, dual + o.DualLength);
                ulong map = Bytes.U64(b, dual + o.DualMap);
                h.Maps[i] = MemoryReader.IsKernelPointer(map) || MemoryReader.IsUserAddress(map) ? map : 0;
            }
        }

        // SAM and SECURITY (the root path's or the file's last part): never read
        public static bool IsCredential(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string leaf = path.TrimEnd('\\');
            int slash = leaf.LastIndexOf('\\');
            if (slash >= 0) leaf = leaf.Substring(slash + 1);
            return string.Equals(leaf, "SAM", StringComparison.OrdinalIgnoreCase) || string.Equals(leaf, "SECURITY", StringComparison.OrdinalIgnoreCase);
        }

        // The root key: the base block's root cell when the base block is in
        // the dump ('regf'), else the root key control block's cell, else
        // the hive's first cell; a key node with the hive-entry flag (which
        // only a hive's root key has) whichever it is
        void FindRoot(HiveInfo h, HiveCells cells)
        {
            uint signature;
            uint cell;
            if (MemoryReader.IsKernelPointer(h.BaseBlock) || MemoryReader.IsUserAddress(h.BaseBlock))
            {
                if (reader.TryU32(h.Process, h.BaseBlock + (ulong)o.BaseSignature, out signature) && signature == 0x66676572 &&
                    reader.TryU32(h.Process, h.BaseBlock + (ulong)o.BaseRootCell, out cell) && IsRoot(cells, cell))
                {
                    h.RootCell = cell; h.RootFrom = "BaseBlock"; h.RootState = "Read";
                    return;
                }
            }
            ulong keyHive;
            if (MemoryReader.IsKernelPointer(h.RootKcb) && reader.TryU64(0, h.RootKcb + (ulong)o.KcbKeyHive, out keyHive) && keyHive == h.Address &&
                reader.TryU32(0, h.RootKcb + (ulong)o.KcbKeyCell, out cell) && IsRoot(cells, cell))
            {
                h.RootCell = cell; h.RootFrom = "KeyControlBlock"; h.RootState = "Read";
                return;
            }
            // The hive's first cell, just after the first bin's header: where
            // Windows creates the root key (the key control block names this
            // cell wherever it is in the dump)
            if (IsRoot(cells, FirstCell))
            {
                h.RootCell = FirstCell; h.RootFrom = "FirstCell"; h.RootState = "Read";
                return;
            }
            h.RootState = "Unreadable";
        }

        public const uint FirstCell = 0x20;

        static bool IsRoot(HiveCells cells, uint cell)
        {
            RegKey k = cells.Key(cell);
            return k != null && (k.Flags & HiveCells.KeyHiveEntry) != 0;
        }

        static RegKey Root(HiveInfo h, HiveCells cells)
        {
            return h.RootState == "Read" ? cells.Key(h.RootCell) : null;
        }

        // SYSTEM\<current control set>\Services
        void ReadServices(List<HiveCells> cells)
        {
            int index = -1;
            for (int i = 0; i < Hives.Count; i++) { if (Hives[i].IsMachine("SYSTEM") && cells[i] != null) { index = i; break; } }
            if (index < 0) { Services.Why = "the SYSTEM hive was not found in memory"; return; }
            HiveCells c = cells[index];
            RegKey root = Root(Hives[index], c);
            if (root == null) { Services.Why = "the SYSTEM hive's root key is not in the dump"; return; }
            bool absent;
            // The current control set: Select\Current, else the CurrentControlSet link
            RegKey select = c.Child(root, "Select", out absent);
            if (select != null)
            {
                bool complete;
                RegValue current = c.Named(c.Values(select, out complete), "Current");
                long n = current == null ? -1 : current.Number;
                if (n >= 1 && n <= 999) { Services.ControlSet = "ControlSet" + n.ToString("000", CultureInfo.InvariantCulture); Services.ControlSetFrom = "Select"; }
            }
            if (Services.ControlSet.Length == 0)
            {
                RegKey link = c.Child(root, "CurrentControlSet", out absent);
                if (link != null)
                {
                    bool complete;
                    RegValue target = c.Named(c.Values(link, out complete), "SymbolicLinkValue");
                    string text = target == null ? null : target.Text;
                    if (text != null)
                    {
                        int slash = text.LastIndexOf('\\');
                        string leaf = slash >= 0 ? text.Substring(slash + 1) : text;
                        if (leaf.StartsWith("ControlSet", StringComparison.OrdinalIgnoreCase) && leaf.Length == 13) { Services.ControlSet = leaf; Services.ControlSetFrom = "Link"; }
                    }
                }
            }
            if (Services.ControlSet.Length == 0) { Services.ControlSet = "ControlSet001"; Services.ControlSetFrom = "Default"; }
            RegKey services = c.Path(root, Services.ControlSet + "\\Services", out absent);
            if (services == null) { Services.Why = "the Services key is not in the dump"; return; }
            bool listComplete;
            List<uint> subkeys = c.SubKeys(services, 0, false, out listComplete);
            Services.Listed = (long)services.SubKeyCounts[0] + services.SubKeyCounts[1];
            area.Coverage.Count("Services subkeys", Services.Listed);
            int valuesComplete = 0;
            foreach (uint cell in subkeys)
            {
                if ((Services.Read & 63) == 0 && Stop()) break;
                RegKey k = c.Key(cell);
                if (k == null) continue;
                Services.Read++;
                RegistryServiceKey s = new RegistryServiceKey();
                s.Name = k.Name;
                s.LastWrite = k.LastWrite;
                bool complete;
                List<RegValue> values = c.Values(k, out complete);
                s.ValuesComplete = complete;
                if (complete) valuesComplete++;
                RegValue v;
                v = c.Named(values, "ImagePath"); if (v != null) s.ImagePath = v.Text;
                v = c.Named(values, "ObjectName"); if (v != null) s.ObjectName = v.Text;
                v = c.Named(values, "DisplayName"); if (v != null) s.DisplayName = v.Text;
                v = c.Named(values, "Start"); if (v != null) s.Start = v.Number;
                v = c.Named(values, "Type"); if (v != null) s.Type = v.Number;
                v = c.Named(values, "ServiceDll"); if (v != null) s.ServiceDll = v.Text;
                RegKey parameters = c.Child(k, "Parameters", out absent);
                if (parameters != null)
                {
                    bool parametersComplete;
                    v = c.Named(c.Values(parameters, out parametersComplete), "ServiceDll");
                    if (v != null) s.ServiceDll = v.Text;
                }
                if (!Services.Keys.ContainsKey(s.Name)) Services.Keys[s.Name] = s;
            }
            area.Coverage.Count("Services subkeys read", Services.Read);
            area.Coverage.Count("Services subkeys with every value read", valuesComplete);
            Services.Complete = listComplete && Services.Read == Services.Listed && subkeys.Count == Services.Listed;
            Services.State = Services.Complete ? "Read" : "Partial";
            if (!Services.Complete) Services.Why = timeUp ? "the area's time limit was reached" : "the Services key's subkey list is not all in the dump";
        }

        // The Run keys of the SOFTWARE hive and of each user's hive
        void ReadRunValues(List<HiveCells> cells)
        {
            int keysRead = 0, keysAbsent = 0, keysNotReached = 0, values = 0, noData = 0, partialLists = 0, hivesNotReached = 0;
            for (int i = 0; i < Hives.Count; i++)
            {
                HiveInfo h = Hives[i];
                string prefix = h.KeyPrefix;
                if (prefix.Length == 0 || cells[i] == null) continue;
                if (Stop()) break;
                HiveCells c = cells[i];
                RegKey root = Root(h, c);
                bool absent = false;
                RegKey software = root;
                if (root != null && h.IsUserHive) software = c.Child(root, "Software", out absent);
                if (software == null) { if (!absent) { hivesNotReached++; keysNotReached += RunPaths.Length; } continue; }
                foreach (string path in RunPaths)
                {
                    RegKey key = c.Path(software, path, out absent);
                    if (key == null) { if (absent) keysAbsent++; else keysNotReached++; continue; }
                    keysRead++;
                    bool complete;
                    List<RegValue> list = c.Values(key, out complete);
                    if (!complete) partialLists++;
                    string keyText = (h.IsUserHive ? prefix + "\\SOFTWARE" : prefix) + "\\" + path;
                    foreach (RegValue v in list)
                    {
                        values++;
                        string text = v.Text;
                        if (text == null) noData++;
                        MemoryEntry e = area.Add("RunValue");
                        e.Set("Hive", h.IsUserHive ? prefix : "HKLM");
                        e.Set("Key", keyText);
                        e.Set("Name", v.Name.Length == 0 ? "(Default)" : v.Name);
                        e.Set("Command", text ?? "");
                        e.Set("Data", text == null ? "Unreadable" : "Read");
                        e.Set("ValueType", RegistryText.TypeName(v.Type));
                        e.Set("LastWrite", Fmt.IsoTime(key.LastWrite));
                        if (h.IsUserHive) e.Set("Sid", h.Sid);
                        e.Set("HiveFile", RegistryText.MapPath(h.FilePath, context.DriveMap));
                        e.Set("Values", complete ? "Complete" : "Partial");
                    }
                }
            }
            area.Coverage.Count("Run keys read", keysRead);
            area.Coverage.Count("Run keys absent", keysAbsent);
            area.Coverage.Count("Run keys not in the dump", keysNotReached);
            area.Coverage.Count("Run values", values);
            if (noData > 0) area.Coverage.Count("Run values whose data is not in the dump", noData);
            if (partialLists > 0) area.Coverage.Count("Run keys whose value list is not all in the dump", partialLists);
            if (keysNotReached > 0)
                area.SetPartial(keysNotReached.ToString(CultureInfo.InvariantCulture) + " Run key(s) could not be reached because a key above them is not in the dump");
            if (hivesNotReached > 0) area.Coverage.Count("user hives whose Software key is not in the dump", hivesNotReached);
        }

        // How much of each hive's stable storage is in the dump: each 4 KB
        // block through the cell map
        void Measure(List<HiveCells> cells)
        {
            for (int i = 0; i < Hives.Count; i++)
            {
                HiveInfo h = Hives[i];
                HiveCells c = cells[i];
                if (c == null) continue;
                if (Stop()) return;
                long blocks = h.Lengths[0] / 4096;
                long readable = 0, skipped = 0;
                bool stopped = false;
                ulong[] addresses = new ulong[blocks];
                for (uint b = 0; b < blocks; b++)
                {
                    if ((b & 1023) == 1023 && Stop()) { stopped = true; break; }
                    bool skip = false;
                    if (h.Flat) addresses[b] = h.BaseBlock != 0 ? h.BaseBlock + 0x1000UL + 4096UL * b : 0;
                    else addresses[b] = c.BlockAddress(0, b, out skip);
                    if (skip) skipped++;
                }
                if (stopped) return;
                int translated = -1;
                if (context.Session != null && !byReading)
                {
                    bool[] inDump = new bool[addresses.Length];
                    translated = context.Session.CountInDump(h.Process, addresses, inDump);
                    // The engine's process was put back: the reader switches again
                    SessionReader sticky = reader as SessionReader;
                    if (sticky != null) sticky.Restore();
                }
                if (translated >= 0) { readable = translated; MeasuredBy = "page tables"; }
                else
                {
                    MeasuredBy = "reading";
                    for (int b = 0; b < addresses.Length; b++)
                    {
                        if ((b & 1023) == 1023 && Stop()) { stopped = true; break; }
                        byte[] one;
                        if (addresses[b] != 0 && reader.TryRead(h.Process, addresses[b], 1, out one)) readable++;
                    }
                    if (stopped) return;
                }
                h.Blocks = blocks;
                h.ReadableBlocks = readable;
                h.SkippedEntries = skipped;
            }
        }

        void AddHiveEntries()
        {
            foreach (HiveInfo h in Hives)
            {
                MemoryEntry e = area.Add("Hive");
                e.SetHex("Offset", h.Address);
                e.Set("Root", h.RootPath ?? "");
                e.Set("File", RegistryText.MapPath(h.FilePath, context.DriveMap));
                if (h.ReadablePercent != null) e.Set("Readable", h.ReadablePercent);
                e.Set("RootState", h.RootState);
                e.Set("FoundBy", h.FoundBy);
                if (h.NotRead.Length > 0) e.Set("NotRead", h.NotRead);
                if (h.Sid.Length > 0) e.Set("Sid", h.Sid);
            }
        }

        void Summarize()
        {
            long blocks = 0, readable = 0, skipped = 0;
            int credential = 0, unnamed = 0, roots = 0, fromBase = 0, fromKcb = 0, fromFirst = 0, unreadableRoots = 0, measured = 0, flat = 0;
            foreach (HiveInfo h in Hives)
            {
                if (h.NotRead.Length > 0) { if (h.NotRead == "CredentialHive") credential++; else unnamed++; continue; }
                if (h.Flat) flat++;
                if (h.RootState == "Read") { roots++; if (h.RootFrom == "BaseBlock") fromBase++; else if (h.RootFrom == "KeyControlBlock") fromKcb++; else fromFirst++; }
                else unreadableRoots++;
                if (h.Blocks >= 0) { measured++; blocks += h.Blocks; readable += h.ReadableBlocks; skipped += h.SkippedEntries; }
            }
            area.Coverage.Count("hives listed by name only", credential);
            if (unnamed > 0) area.Coverage.Count("hives not read as their names are not in the dump", unnamed);
            area.Coverage.Count("root keys read", roots);
            area.Coverage.Count("from the base block", fromBase);
            area.Coverage.Count("from the key control block", fromKcb);
            area.Coverage.Count("from the first cell", fromFirst);
            if (flat > 0) area.Coverage.Count("flat hives", flat);
            area.Coverage.Count("hive blocks", blocks);
            area.Coverage.Count("hive blocks in the dump", readable);
            area.Coverage.Count("map entries skipped", skipped);
            area.Coverage.Count("cells read", CellReads);
            area.Coverage.Count("cells not in the dump", CellsUnreadable);
            if (RegistryProcess == 0)
                area.SetPartial("the Registry process was not found, so hive data in its memory was not read");
            // (the time limit has its own note)
            if (!Services.Complete && !timeUp) area.SetPartial(Services.Why);
            bool software = false;
            foreach (HiveInfo h in Hives) { if (h.IsMachine("SOFTWARE") && h.NotRead.Length == 0) software = true; }
            if (!software) area.SetPartial("the SOFTWARE hive was not found in memory");
            if (unreadableRoots > 0)
                area.Coverage.Note("the root key of " + unreadableRoots.ToString(CultureInfo.InvariantCulture) + " of " + (Hives.Count - credential - unnamed).ToString(CultureInfo.InvariantCulture) + " hives is not in the dump");
            if (measured > 0 && blocks > 0)
            {
                long percent = (long)Math.Floor(100.0 * readable / blocks + 0.5);
                area.Coverage.Note(percent.ToString(CultureInfo.InvariantCulture) + "% of the hives' 4 KB blocks are in the dump, the rest was not in memory");
            }
        }
    }
}
'@
}

# The registry structures the area reads, and the type each field must have
function Get-DbgEngRegistryLayoutSpec {
    return @{
        "_CMHIVE"               = @{ Hive = '^struct _HHIVE\b'; HiveList = '^struct _LIST_ENTRY\b'; FileFullPath = '^struct _UNICODE_STRING\b'; FileUserName = '^struct _UNICODE_STRING\b'; HiveRootPath = '^struct _UNICODE_STRING\b'; RootKcb = '^Ptr64\b' }
        "_HHIVE"                = @{ Signature = '^Uint4B$'; BaseBlock = '^Ptr64\b'; Flat = '^Bitfield\b'; ViewMap = '^struct _HVP_VIEW_MAP\b'; Storage = '^\[2\] struct _DUAL\b' }
        "_HVP_VIEW_MAP"         = @{ ProcessTuple = '^Ptr64\b' }
        "_CMSI_PROCESS_TUPLE"   = @{ ProcessReference = '^Ptr64\b' }
        "_DUAL"                 = @{ Length = '^Uint4B$'; Map = '^Ptr64\b' }
        "_HMAP_DIRECTORY"       = @{ Directory = '^\[1024\] Ptr64\b' }
        "_HMAP_TABLE"           = @{ Table = '^\[512\] struct _HMAP_ENTRY\b' }
        "_HMAP_ENTRY"           = @{ BlockOffset = '^Uint8B$'; PermanentBinAddress = '^Uint8B$' }
        "_CM_KEY_CONTROL_BLOCK" = @{ KeyCell = '^Uint4B$'; KeyHive = '^Ptr64\b' }
        "_HBASE_BLOCK"          = @{ Signature = '^Uint4B$'; RootCell = '^Uint4B$' }
        "_CM_KEY_NODE"          = @{
            Signature = '^Uint2B$'; Flags = '^Uint2B$'; LastWriteTime = '^union _LARGE_INTEGER\b'; SubKeyCounts = '^\[2\] Uint4B$'
            SubKeyLists = '^\[2\] Uint4B$'; ValueList = '^struct _CHILD_LIST\b'; NameLength = '^Uint2B$'; Name = '^\[1\] Wchar$'
        }
        "_CHILD_LIST"           = @{ Count = '^Uint4B$'; List = '^Uint4B$' }
        "_CM_KEY_VALUE"         = @{ Signature = '^Uint2B$'; NameLength = '^Uint2B$'; DataLength = '^Uint4B$'; Data = '^Uint4B$'; Type = '^Uint4B$'; Flags = '^Uint2B$'; Name = '^\[1\] Wchar$' }
        "_CM_KEY_INDEX"         = @{ Signature = '^Uint2B$'; Count = '^Uint2B$'; List = '^\[1\] Uint4B$' }
        "_CM_INDEX"             = @{ Cell = '^Uint4B$' }
        "_CM_BIG_DATA"          = @{ Signature = '^Uint2B$'; Count = '^Uint2B$'; List = '^Uint4B$' }
    }
}

# The area: the hives, their Run values, and the Services key for the joins
# ($Context.Shared["RegistryServices"]; the hives as Shared["RegistryHives"])
function Invoke-DbgEngRegistryArea {
    param($Context, $Area)
    $layout = New-DbgEngLayout -Session $Context.Session -Spec (Get-DbgEngRegistryLayoutSpec) -Symbols @("nt!CmpHiveListHead")
    $missing = $layout.MissingOf([TimelineDbgEng.RegistryOffsets]::Required)
    if ($missing) {
        $Area.SetNotRead("the kernel's symbols do not describe the registry's structures as expected [$missing]")
        return
    }
    if ($layout.Symbol("nt!CmpHiveListHead") -eq 0) {
        $Area.SetNotRead("nt!CmpHiveListHead is not in the kernel's symbols")
        return
    }
    $scan = [TimelineDbgEng.RegistryScan]::Run($Context, $Area, $layout)
    if ($scan.Timings.Count -gt 0) {
        $from = switch ($scan.RegistryProcessFrom) { "ViewMap" { "the hives' view maps" } "Name" { "its name" } default { "nobody: not found" } }
        Write-DbgEngLog "    Registry: the Registry process by $from; blocks in the dump by $($scan.MeasuredBy); seconds per part: $($scan.Timings -join ', ')"
    }
}
