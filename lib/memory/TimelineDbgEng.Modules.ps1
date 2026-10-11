# =============================================================
# Windows ARM64 memory dumps: DLLs per process, mapped-but-unlinked ones included (item c)
# Part of win11-timeline-builder (work package WP2). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads, per process (every offset from the kernel's symbols, 'dt'):
#   the loader's list    PEB.Ldr -> _PEB_LDR_DATA.InLoadOrderModuleList, each
#                        _LDR_DATA_TABLE_ENTRY (DllBase, SizeOfImage,
#                        FullDllName, BaseDllName, LoadTime, LoadReason),
#                        walked with a visited set and a cap of 4096 entries;
#                        Blink links that do not point back are counted
#   the 32-bit list      of a WoW64 process (EPROCESS.WoW64Process ->
#                        _EWOW64PROCESS.Peb, the 32-bit PEB): these 32-bit
#                        structures are not in the kernel's symbols, so their
#                        documented fixed offsets are used (DllScanner below)
#   the image mappings   the image VADs of the shared VadWalker (VadImageMap),
#                        with the mapped file's name (control area -> file
#                        object) and its volume's device object
# One record per base address. Judged only where the copy allows it:
#   NotInLoaderLists     an image mapping no loader list has, only when every
#                        loader list of the process was walked to its end
#   NoImageMapping       a loader entry without an image mapping at its base,
#                        only when the process's VAD walk was consistent
#   NameMismatch         the loader's file name is not the mapped file's (an
#                        8.3 short name is never judged)
# A protected process (an anti-malware service maps files to scan them) is
# never judged: its mapped-only images are counted, not listed.
# Entries (Module, rows: Add-DbgEngModuleRows) for every DLL outside the
# Windows folder (its Temp folder counts as outside) and every judged one;
# the rest are counted for the log. An
# image in no loader list also gets the mapping's protection (ReadOnly: a
# resource-only load, no code runs from it; the loader's own mappings are
# ExecuteWriteCopy) and Managed=Yes when its PE header has a CLR header (a
# .NET assembly, which the .NET runtime maps itself, not the loader).
# The drive letter of a mapped file comes from the loader entries whose path
# is that file's: per volume device, learned over the whole dump.
# For the PrivateCode area (TimelineDbgEng.PrivateCode.ps1) and the joins it
# leaves in MemoryContext.Shared: "VadWalks" (EPROCESS -> VadWalk, so the
# regions are walked once), "ModuleNames" (EPROCESS -> the lower-case file
# names of its modules) and "Dlls" (EPROCESS -> DllProcess).
# Strings read from memory stay in C# until the entries are written.
# =============================================================

# The C# of this file (namespace blocks only; the host's using header). C# 5.
function Get-DbgEngModulesSource {
    return @'
namespace TimelineDbgEng
{
    // One DLL (or the program itself) of one process, by its base address:
    // from a loader list, an image mapping, or both
    public sealed class DllRecord
    {
        public ulong Base;
        public ulong Size;
        public bool InLoader64;
        public bool InLoader32;
        public bool Mapped;
        public string LoaderPath;               // FullDllName (null: not read)
        public string LoaderBaseName;           // BaseDllName (null: not read)
        public string MappedName;               // the mapped file's name, no volume (null: not read)
        public ulong Device;                    // its FILE_OBJECT.DeviceObject (0: not read)
        public int Protection = -1;             // the mapping's VAD protection index
        public long LoadTime;                   // FILETIME, 0 when none
        public int LoadReason = int.MinValue;   // int.MinValue: not read
        public string Anomaly = "";
        public string Path = "";
        public string Name = "";
        public bool OutsideWindows;
        public bool Managed;
        public bool InLoader { get { return InLoader64 || InLoader32; } }
    }

    // The DLLs of one process
    public sealed class DllProcess
    {
        public ProcessInfo Process;
        public readonly Dictionary<ulong, DllRecord> ByBase = new Dictionary<ulong, DllRecord>();
        public readonly List<DllRecord> Records = new List<DllRecord>();
        // How each loader list walk ended: Complete, NoPeb, NoLoaderData,
        // Unreadable (the PEB or the list head is not in the dump),
        // UnreadableEntry, BadLink, Loop, Capped; "" for the 32-bit list of a
        // process that is not WoW64
        public string Loader64 = "";
        public string Loader32 = "";
        public int BlinkMismatches;
        public VadWalk Walk;                    // null: the regions were not walked
        public bool LoaderComplete
        {
            get { return Loader64 == "Complete" && (Process == null || Process.Wow64 == 0 || Loader32 == "Complete"); }
        }
    }

    // Reads the DLLs of a process (its loader lists and its image mappings)
    public sealed class DllScanner
    {
        public const int ListCap = 4096;
        // What the loader list walk needs from the kernel's symbols
        public static readonly string[] Fields = new string[] {
            "_PEB.Ldr", "_PEB_LDR_DATA.InLoadOrderModuleList", "_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks", "_LDR_DATA_TABLE_ENTRY.DllBase",
            "_LDR_DATA_TABLE_ENTRY.SizeOfImage", "_LDR_DATA_TABLE_ENTRY.FullDllName", "_LDR_DATA_TABLE_ENTRY.BaseDllName",
            "_LIST_ENTRY.Flink", "_LIST_ENTRY.Blink" };

        // The 32-bit loader structures of a WoW64 process are not in the
        // kernel's symbols. Their layout is fixed and documented (PEB32.Ldr
        // +0x0C, PEB_LDR_DATA32.InLoadOrderModuleList +0x0C,
        // LDR_DATA_TABLE_ENTRY32: InLoadOrderLinks +0, DllBase +0x18,
        // SizeOfImage +0x20, FullDllName +0x24, BaseDllName +0x2C, each
        // UNICODE_STRING32 8 bytes), the same since Windows XP; the item-c
        // probe read complete 32-bit lists with them on Windows 11 26100.
        const int Peb32Ldr = 0x0C, Ldr32List = 0x0C, Entry32Base = 0x18, Entry32Size = 0x20, Entry32Full = 0x24, Entry32Name = 0x2C, Entry32Bytes = 0x34;

        readonly MemoryReader reader;
        readonly VadWalker walker;
        readonly int pebLdr, ldrList, links, flink, blink, dllBase, sizeOfImage, fullName, baseName, loadTime, loadReason, entryBytes;
        readonly int wowPeb, filePointer, deviceObject, controlAreaOffset;
        readonly ulong fastRefMask;
        readonly Dictionary<ulong, ulong> deviceByArea = new Dictionary<ulong, ulong>();

        public DllScanner(MemoryReader reader, Layout layout, VadWalker walker)
        {
            this.reader = reader;
            this.walker = (walker != null && walker.Ready) ? walker : null;
            pebLdr = layout.Off("_PEB.Ldr");
            ldrList = layout.Off("_PEB_LDR_DATA.InLoadOrderModuleList");
            links = layout.Off("_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks");
            flink = layout.Off("_LIST_ENTRY.Flink");
            blink = layout.Off("_LIST_ENTRY.Blink");
            dllBase = layout.Off("_LDR_DATA_TABLE_ENTRY.DllBase");
            sizeOfImage = layout.Off("_LDR_DATA_TABLE_ENTRY.SizeOfImage");
            fullName = layout.Off("_LDR_DATA_TABLE_ENTRY.FullDllName");
            baseName = layout.Off("_LDR_DATA_TABLE_ENTRY.BaseDllName");
            loadTime = layout.Off("_LDR_DATA_TABLE_ENTRY.LoadTime");
            loadReason = layout.Off("_LDR_DATA_TABLE_ENTRY.LoadReason");
            wowPeb = layout.Off("_EWOW64PROCESS.Peb");
            filePointer = layout.Off("_CONTROL_AREA.FilePointer");
            deviceObject = layout.Off("_FILE_OBJECT.DeviceObject");
            controlAreaOffset = layout.Off("_SUBSECTION.ControlArea");
            fastRefMask = layout.FastRefMask;
            int bytes = Math.Max(Math.Max(links + 16, dllBase + 8), Math.Max(sizeOfImage + 4, Math.Max(fullName + 16, baseName + 16)));
            if (loadTime >= 0) bytes = Math.Max(bytes, loadTime + 8);
            if (loadReason >= 0) bytes = Math.Max(bytes, loadReason + 4);
            entryBytes = bytes;
            Ready = layout.HasAll(Fields);
        }

        public readonly bool Ready;
        public bool MapsRead { get { return walker != null; } }

        // The DLLs of one process. walk: its VAD walk (null: walked here when
        // the walker can)
        public DllProcess Scan(ProcessInfo p, VadWalk walk)
        {
            DllProcess d = new DllProcess();
            d.Process = p;
            if (Ready)
            {
                if (p.Peb == 0) d.Loader64 = "NoPeb";
                else d.Loader64 = WalkLoader64(d);
                if (p.Wow64 != 0) d.Loader32 = WalkLoader32(d);
            }
            if (walk == null && walker != null) walk = walker.Walk(p);
            d.Walk = walk;
            if (walk != null)
            {
                foreach (VadNode n in walk.Nodes)
                {
                    if (!n.IsImage) continue;
                    DllRecord r = Get(d, n.Start);
                    r.Mapped = true;
                    r.Protection = n.Protection;
                    if (r.Size == 0) r.Size = n.Size;
                    if (walker != null)
                    {
                        r.MappedName = walker.FileName(n);
                        r.Device = DeviceOf(n);
                    }
                }
            }
            d.Records.Sort(delegate(DllRecord a, DllRecord b) { return a.Base.CompareTo(b.Base); });
            return d;
        }

        static DllRecord Get(DllProcess d, ulong address)
        {
            DllRecord r;
            if (d.ByBase.TryGetValue(address, out r)) return r;
            r = new DllRecord();
            r.Base = address;
            d.ByBase[address] = r;
            d.Records.Add(r);
            return r;
        }

        // A 64-bit UNICODE_STRING inside a block read from memory
        string StringIn(ulong process, byte[] b, int offset)
        {
            if (!Bytes.Has(b, offset, 16)) return null;
            ushort length = Bytes.U16(b, offset);
            ushort maximum = Bytes.U16(b, offset + 2);
            if (length == 0) return "";
            if ((length & 1) != 0 || (maximum != 0 && length > maximum)) return null;
            return reader.Utf16(process, Bytes.U64(b, offset + 8), length);
        }

        // A 32-bit one (Buffer is a 32-bit pointer at +4)
        string String32In(ulong process, byte[] b, int offset)
        {
            if (!Bytes.Has(b, offset, 8)) return null;
            ushort length = Bytes.U16(b, offset);
            ushort maximum = Bytes.U16(b, offset + 2);
            if (length == 0) return "";
            if ((length & 1) != 0 || (maximum != 0 && length > maximum)) return null;
            return reader.Utf16(process, Bytes.U32(b, offset + 4), length);
        }

        string WalkLoader64(DllProcess d)
        {
            ProcessInfo p = d.Process;
            ulong ldr;
            if (!reader.TryU64(p.Eprocess, p.Peb + (ulong)pebLdr, out ldr)) return "Unreadable";
            if (ldr == 0) return "NoLoaderData";
            if (!MemoryReader.IsUserAddress(ldr)) return "BadLink";
            ulong head = ldr + (ulong)ldrList;
            ulong first;
            if (!reader.TryU64(p.Eprocess, head + (ulong)flink, out first)) return "Unreadable";
            HashSet<ulong> visited = new HashSet<ulong>();
            ulong previous = head;
            ulong current = first;
            while (current != head)
            {
                if (visited.Count >= ListCap) return "Capped";
                if (!MemoryReader.IsUserAddress(current) || current < (ulong)links) return "BadLink";
                if (!visited.Add(current)) return "Loop";
                ulong entry = current - (ulong)links;
                byte[] b = reader.Read(p.Eprocess, entry, entryBytes);
                if (b == null || b.Length < entryBytes) return "UnreadableEntry";
                if (Bytes.U64(b, links + blink) != previous) d.BlinkMismatches++;
                ulong address = Bytes.U64(b, dllBase);
                if (address != 0)
                {
                    DllRecord r = Get(d, address);
                    r.InLoader64 = true;
                    if (r.Size == 0) r.Size = Bytes.U32(b, sizeOfImage);
                    if (r.LoaderPath == null) r.LoaderPath = StringIn(p.Eprocess, b, fullName);
                    if (r.LoaderBaseName == null) r.LoaderBaseName = StringIn(p.Eprocess, b, baseName);
                    if (loadTime >= 0 && r.LoadTime == 0) r.LoadTime = Bytes.I64(b, loadTime);
                    if (loadReason >= 0 && r.LoadReason == int.MinValue) r.LoadReason = (int)Bytes.U32(b, loadReason);
                }
                previous = current;
                current = Bytes.U64(b, links + flink);
            }
            return "Complete";
        }

        string WalkLoader32(DllProcess d)
        {
            ProcessInfo p = d.Process;
            if (wowPeb < 0 || !MemoryReader.IsKernelPointer(p.Wow64)) return "Unreadable";
            ulong peb32;
            if (!reader.TryU64(0, p.Wow64 + (ulong)wowPeb, out peb32)) return "Unreadable";
            if (peb32 == 0 || peb32 > 0xFFFFFFFFUL) return "NoPeb";
            uint ldr;
            if (!reader.TryU32(p.Eprocess, peb32 + Peb32Ldr, out ldr)) return "Unreadable";
            if (ldr == 0) return "NoLoaderData";
            ulong head = (ulong)ldr + Ldr32List;
            uint first;
            if (!reader.TryU32(p.Eprocess, head, out first)) return "Unreadable";
            HashSet<ulong> visited = new HashSet<ulong>();
            ulong previous = head;
            ulong current = first;
            while (current != head)
            {
                if (visited.Count >= ListCap) return "Capped";
                if (current == 0 || current > 0xFFFFFFFFUL) return "BadLink";
                if (!visited.Add(current)) return "Loop";
                byte[] b = reader.Read(p.Eprocess, current, Entry32Bytes);
                if (b == null || b.Length < Entry32Bytes) return "UnreadableEntry";
                if (Bytes.U32(b, 4) != previous) d.BlinkMismatches++;
                ulong address = Bytes.U32(b, Entry32Base);
                if (address != 0)
                {
                    DllRecord r = Get(d, address);
                    r.InLoader32 = true;
                    if (r.Size == 0) r.Size = Bytes.U32(b, Entry32Size);
                    if (r.LoaderPath == null) r.LoaderPath = String32In(p.Eprocess, b, Entry32Full);
                    if (r.LoaderBaseName == null) r.LoaderBaseName = String32In(p.Eprocess, b, Entry32Name);
                }
                previous = current;
                current = Bytes.U32(b, 0);
            }
            return "Complete";
        }

        // The device object of a mapped file's volume (cached per control area)
        ulong DeviceOf(VadNode n)
        {
            if (filePointer < 0 || deviceObject < 0 || controlAreaOffset < 0) return 0;
            ulong area = walker.ControlArea(n);
            if (area == 0) return 0;
            ulong device;
            if (deviceByArea.TryGetValue(area, out device)) return device;
            device = 0;
            ulong pointer;
            if (reader.TryU64(0, area + (ulong)filePointer, out pointer))
            {
                ulong file = pointer & ~fastRefMask;
                ulong value;
                if (MemoryReader.IsKernelPointer(file) && reader.TryU64(0, file + (ulong)deviceObject, out value) && MemoryReader.IsKernelPointer(value)) device = value;
            }
            deviceByArea[area] = device;
            return device;
        }

        // A managed (.NET) image: its PE header at base has a CLR header
        // (data directory 14, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR); false
        // when it does not or the header is not in the dump
        public bool IsManagedImage(ulong process, ulong address)
        {
            byte[] h = reader.Read(process, address, 0x1000);
            if (h == null || h.Length < 0x40 || h[0] != 0x4D || h[1] != 0x5A) return false;
            int pe = (int)Bytes.U32(h, 0x3C);
            if (pe < 0x40 || pe > h.Length - 0x100 || Bytes.U32(h, pe) != 0x4550) return false;
            int optional = pe + 24;
            ushort magic = Bytes.U16(h, optional);
            int count, directories;
            if (magic == 0x10B) { count = optional + 92; directories = optional + 96; }
            else if (magic == 0x20B) { count = optional + 108; directories = optional + 112; }
            else return false;
            if (Bytes.U32(h, count) <= 14 || !Bytes.Has(h, directories + 14 * 8, 8)) return false;
            return Bytes.U32(h, directories + 14 * 8) != 0 && Bytes.U32(h, directories + 14 * 8 + 4) != 0;
        }
    }

    // The Modules area: every process's DLLs, judged and turned into entries
    public static class DllsArea
    {
        // "\??\C:\x" and "\\?\C:\x" -> "C:\x"
        public static string StripPrefix(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (path.StartsWith("\\??\\", StringComparison.Ordinal) || path.StartsWith("\\\\?\\", StringComparison.Ordinal)) return path.Substring(4);
            return path;
        }

        static bool HasDrive(string path)
        {
            return path != null && path.Length > 2 && path[1] == ':' && path[2] == '\\' && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'));
        }

        // A path without its drive ("C:\Windows\x" -> "\Windows\x"); the
        // kernel's "\SystemRoot\" is the Windows folder; null when unknown
        public static string Relative(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            string p = StripPrefix(path);
            if (HasDrive(p)) return p.Substring(2);
            if (p.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) return "\\Windows\\" + p.Substring(12);
            return p;
        }

        // Under the Windows folder, but not its Temp folder (any user can
        // write there: a DLL from it is listed like one from a user folder)
        public static bool InWindowsFolder(string relative)
        {
            return relative != null && relative.StartsWith("\\Windows\\", StringComparison.OrdinalIgnoreCase) &&
                !relative.StartsWith("\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase);
        }

        public static string Leaf(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int slash = path.LastIndexOfAny(new char[] { '\\', '/' });
            return slash >= 0 ? path.Substring(slash + 1) : path;
        }

        // An 8.3 short name ("PROGRA~1"): never compared
        public static bool HasShortName(string path)
        {
            if (path == null) return false;
            for (int i = 0; i + 1 < path.Length; i++) { if (path[i] == '~' && path[i + 1] >= '0' && path[i + 1] <= '9') return true; }
            return false;
        }

        // The loader's file name is not the mapped file's
        public static bool NamesDiffer(DllRecord r)
        {
            if (string.IsNullOrEmpty(r.MappedName)) return false;
            string loader = !string.IsNullOrEmpty(r.LoaderPath) ? Leaf(r.LoaderPath) : r.LoaderBaseName;
            string mapped = Leaf(r.MappedName);
            if (string.IsNullOrEmpty(loader) || string.IsNullOrEmpty(mapped)) return false;
            if (HasShortName(r.LoaderPath) || HasShortName(r.MappedName) || HasShortName(loader)) return false;
            return !string.Equals(loader, mapped, StringComparison.OrdinalIgnoreCase);
        }

        // Judges the records of a process (see the file header)
        public static void Judge(DllProcess d)
        {
            bool unlinked = d.LoaderComplete;
            bool noMapping = d.Walk != null && d.Walk.Consistent;
            foreach (DllRecord r in d.Records)
            {
                List<string> a = new List<string>();
                if (r.Mapped && !r.InLoader && unlinked) a.Add("NotInLoaderLists");
                if (r.InLoader && !r.Mapped && noMapping) a.Add("NoImageMapping");
                if (r.InLoader && r.Mapped && NamesDiffer(r)) a.Add("NameMismatch");
                r.Anomaly = string.Join(",", a.ToArray());
                string mapped = string.IsNullOrEmpty(r.MappedName) ? null : r.MappedName;
                string loader = Relative(r.LoaderPath);
                r.OutsideWindows = (mapped != null && !InWindowsFolder(mapped)) || (loader != null && !InWindowsFolder(loader));
            }
        }

        // The drive letter of each volume device: from the loader entries
        // whose path is the mapped file's ("C:" + the mapped name); a device
        // seen with two letters gets none
        public static Dictionary<ulong, string> LearnDrives(IEnumerable<DllProcess> processes)
        {
            Dictionary<ulong, string> drives = new Dictionary<ulong, string>();
            HashSet<ulong> conflicting = new HashSet<ulong>();
            foreach (DllProcess d in processes)
            {
                foreach (DllRecord r in d.Records)
                {
                    if (r.Device == 0 || string.IsNullOrEmpty(r.MappedName) || string.IsNullOrEmpty(r.LoaderPath)) continue;
                    string loader = StripPrefix(r.LoaderPath);
                    if (!HasDrive(loader) || !string.Equals(loader.Substring(2), r.MappedName, StringComparison.OrdinalIgnoreCase)) continue;
                    string drive = char.ToUpperInvariant(loader[0]).ToString() + ":";
                    string known;
                    if (drives.TryGetValue(r.Device, out known)) { if (known != drive) conflicting.Add(r.Device); }
                    else drives[r.Device] = drive;
                }
            }
            foreach (ulong device in conflicting) drives.Remove(device);
            return drives;
        }

        // The path a row shows: the mapped file's (with its drive letter when
        // known), else the loader's
        public static string PathOf(DllRecord r, Dictionary<ulong, string> drives)
        {
            if (!string.IsNullOrEmpty(r.MappedName))
            {
                string drive;
                if (r.Device != 0 && drives != null && drives.TryGetValue(r.Device, out drive)) return drive + r.MappedName;
                string loader = StripPrefix(r.LoaderPath);
                if (HasDrive(loader) && string.Equals(loader.Substring(2), r.MappedName, StringComparison.OrdinalIgnoreCase)) return loader;
                return r.MappedName;
            }
            if (!string.IsNullOrEmpty(r.LoaderPath)) return StripPrefix(r.LoaderPath);
            return "";
        }

        // The name of a VAD protection index (the memory manager's, low 3
        // bits: 0 no access, 1 read-only, 2 execute, 3 execute-read,
        // 4 read-write, 5 write-copy, 6 execute-read-write, 7
        // execute-write-copy; the higher bits are caching and guard flags);
        // null when not read
        public static string ProtectionName(int protection)
        {
            if (protection < 0) return null;
            switch (protection & 7)
            {
                case 0: return "NoAccess";
                case 1: return "ReadOnly";
                case 2: return "Execute";
                case 3: return "ExecuteRead";
                case 4: return "ReadWrite";
                case 5: return "WriteCopy";
                case 6: return "ExecuteReadWrite";
                default: return "ExecuteWriteCopy";
            }
        }

        // "1 process", "2 processes"
        public static string Processes(long n)
        {
            return n.ToString(CultureInfo.InvariantCulture) + (n == 1 ? " process" : " processes");
        }

        // Runs the area. reasons: _LDR_DLL_LOAD_REASON value -> name (may be
        // empty: the number is written)
        public static void Run(MemoryContext context, AreaResult area, Layout layout, VadWalker walker, Dictionary<int, string> reasons)
        {
            DllScanner scanner = new DllScanner(context.Reader, layout, walker);
            Dictionary<ulong, VadWalk> walks = new Dictionary<ulong, VadWalk>();
            Dictionary<ulong, HashSet<string>> names = new Dictionary<ulong, HashSet<string>>();
            Dictionary<ulong, DllProcess> dlls = new Dictionary<ulong, DllProcess>();
            List<DllProcess> scanned = new List<DllProcess>();
            Coverage c = area.Coverage;
            c.Count("processes", 0);
            foreach (ProcessInfo p in context.Processes)
            {
                if (area.TimeUp()) break;
                if (dlls.ContainsKey(p.Eprocess)) continue;
                DllProcess d = scanner.Scan(p, null);
                scanned.Add(d);
                dlls[p.Eprocess] = d;
                if (d.Walk != null) walks[p.Eprocess] = d.Walk;
                HashSet<string> set = new HashSet<string>(StringComparer.Ordinal);
                foreach (DllRecord r in d.Records)
                {
                    string leaf = Leaf(!string.IsNullOrEmpty(r.MappedName) ? r.MappedName : (!string.IsNullOrEmpty(r.LoaderPath) ? r.LoaderPath : r.LoaderBaseName));
                    if (leaf.Length > 0) set.Add(leaf.ToLowerInvariant());
                }
                names[p.Eprocess] = set;
                c.Count("processes");
            }
            context.Shared["VadWalks"] = walks;
            context.Shared["ModuleNames"] = names;
            context.Shared["Dlls"] = dlls;

            Dictionary<ulong, string> drives = LearnDrives(scanned);
            long loaderComplete = 0, loaderLost = 0, loaderShort = 0, modules64 = 0, modules32 = 0, mapped = 0, unnamed = 0;
            long unlinked = 0, unlinkedProtected = 0, noMapping = 0, mismatch = 0, outside = 0, rows = 0, inconsistent = 0, blinks = 0, outsideLife = 0, managed = 0, notJudged = 0;
            foreach (DllProcess d in scanned)
            {
                ProcessInfo p = d.Process;
                if (d.LoaderComplete) loaderComplete++;
                else if (d.Loader64 == "Unreadable" || d.Loader32 == "Unreadable") loaderLost++;
                else if (d.Loader64 != "NoPeb" && d.Loader64 != "NoLoaderData" && d.Loader64 != "") loaderShort++;
                if (d.Walk != null && d.Walk.RootRead && !d.Walk.Consistent) inconsistent++;
                blinks += d.BlinkMismatches;
                Judge(d);
                bool judged = d.LoaderComplete;
                foreach (DllRecord r in d.Records)
                {
                    if (r.InLoader64) modules64++;
                    if (r.InLoader32) modules32++;
                    if (r.Mapped) mapped++;
                    if (r.Mapped && r.MappedName == null) unnamed++;
                    if (r.Mapped && !r.InLoader)
                    {
                        if (!judged) notJudged++;
                        else if (p.IsProtected) unlinkedProtected++;
                        else unlinked++;
                    }
                    r.Path = PathOf(r, drives);
                    r.Name = Leaf(r.Path);
                    if (r.Name.Length == 0 && !string.IsNullOrEmpty(r.LoaderBaseName)) r.Name = r.LoaderBaseName;
                    if (p.IsProtected) { r.Anomaly = ""; }
                    else
                    {
                        if (r.Anomaly.Contains("NoImageMapping")) noMapping++;
                        if (r.Anomaly.Contains("NameMismatch")) mismatch++;
                    }
                    if (r.OutsideWindows) outside++;
                    // A row: outside the Windows folder (in a protected
                    // process only what its loader lists have), or judged
                    bool row = (r.OutsideWindows && !(p.IsProtected && !r.InLoader)) || r.Anomaly.Length > 0;
                    if (!row || r.Path.Length == 0) continue;
                    // A mapped-only image: is it .NET's (the runtime maps
                    // assemblies itself), and can code run from the mapping
                    // (a resource-only load maps it read-only)
                    bool mappedOnly = r.Mapped && !r.InLoader;
                    if (mappedOnly && scanner.IsManagedImage(p.Eprocess, r.Base)) { r.Managed = true; managed++; }
                    MemoryEntry e = area.Add("Module");
                    e.Set("PID", p.Pid).Set("ProcessCreated", p.CreatedText).Set("Process", p.Name);
                    if (!string.IsNullOrEmpty(p.UserSid)) e.Set("User", p.UserSid);
                    e.Set("Name", r.Name).Set("Path", r.Path).SetHex("Base", r.Base).SetHex("Size", r.Size);
                    if (r.LoadReason != int.MinValue)
                    {
                        string reason;
                        e.Set("LoadReason", (reasons != null && reasons.TryGetValue(r.LoadReason, out reason)) ? reason : r.LoadReason.ToString(CultureInfo.InvariantCulture));
                    }
                    if (r.InLoader64 && r.LoadTime > 0)
                    {
                        // A load time in the process's lifetime only
                        bool inside = (p.CreateTime <= 0 || r.LoadTime >= p.CreateTime) && (p.ExitTime <= 0 || r.LoadTime <= p.ExitTime);
                        if (inside) e.Set("LoadTime", Fmt.IsoTime(r.LoadTime));
                        else outsideLife++;
                    }
                    List<string> foundBy = new List<string>();
                    if (r.InLoader64) foundBy.Add("LoaderList");
                    if (r.InLoader32) foundBy.Add("LoaderList32");
                    if (r.Mapped) foundBy.Add("ImageMapping");
                    e.Set("FoundBy", string.Join(",", foundBy.ToArray()));
                    if (mappedOnly && ProtectionName(r.Protection) != null) e.Set("Protection", ProtectionName(r.Protection));
                    if (r.Managed) e.Set("Managed", "Yes");
                    if (r.Anomaly.Length > 0) e.Set("Anomaly", r.Anomaly);
                    string loaderPath = StripPrefix(r.LoaderPath);
                    if (!string.IsNullOrEmpty(loaderPath) && !string.Equals(loaderPath, r.Path, StringComparison.OrdinalIgnoreCase)) e.Set("LoaderPath", loaderPath);
                    rows++;
                }
            }
            c.Count("loader lists complete", loaderComplete);
            c.Count("loader lists not in the dump", loaderLost);
            c.Count("loader lists cut short", loaderShort);
            c.Count("loader entries", modules64);
            c.Count("32-bit loader entries", modules32);
            c.Count("loader links not pointing back", blinks);
            c.Count("image mappings", mapped);
            c.Count("image file names not read", unnamed);
            c.Count("mapped but in no loader list", unlinked);
            c.Count("mapped but in no loader list in protected processes", unlinkedProtected);
            c.Count("mapped images not judged", notJudged);
            c.Count("loader entries without an image mapping", noMapping);
            c.Count("loader names unlike the mapped file", mismatch);
            c.Count("outside the Windows folder", outside);
            c.Count("managed images mapped by their runtime", managed);
            c.Count("load times outside the process lifetime", outsideLife);
            c.Count("volume drive letters learned", drives.Count);
            c.Count("inconsistent memory-region trees", inconsistent);
            c.Count("entries", rows);
            if (!scanner.Ready) area.SetPartial("the loader lists were not read, the kernel's symbols do not describe them");
            if (!scanner.MapsRead) area.SetPartial("the image mappings were not read, the kernel's symbols do not describe the memory regions");
            if (loaderLost + loaderShort > 0)
            {
                c.Note("the loader lists of " + Processes(loaderLost + loaderShort) + " could not be read to their end, exited or paged out, so their images were not judged");
            }
            if (inconsistent > 0)
            {
                c.Note("the memory-region trees of " + Processes(inconsistent) + " did not add up, as when memory is copied while Windows runs, so their loader entries without an image mapping were not judged");
            }
        }
    }
}
'@
}

# What the area needs from the kernel's symbols, besides the VAD walker's
# (Get-DbgEngVadWalker): the loader structures, the WoW64 process's 32-bit
# PEB, and a mapped file's volume device. LoadTime, LoadReason,
# _EWOW64PROCESS.Peb and the device fields may be missing (then not read).
function Get-DbgEngModulesLayoutSpec {
    return @{
        "_PEB"                  = @{ Ldr = '^Ptr64\b' }
        "_PEB_LDR_DATA"         = @{ InLoadOrderModuleList = '^struct _LIST_ENTRY\b' }
        "_LDR_DATA_TABLE_ENTRY" = @{
            InLoadOrderLinks = '^struct _LIST_ENTRY\b'; DllBase = '^Ptr64\b'; SizeOfImage = '^Uint4B$'; FullDllName = '^struct _UNICODE_STRING\b'
            BaseDllName = '^struct _UNICODE_STRING\b'; LoadTime = '^union _LARGE_INTEGER\b'; LoadReason = '^Enum _LDR_DLL_LOAD_REASON\b'
        }
        "_LIST_ENTRY"           = @{ Flink = '^Ptr64\b'; Blink = '^Ptr64\b' }
        "_EWOW64PROCESS"        = @{ Peb = '^Ptr64\b' }
        "_SUBSECTION"           = @{ ControlArea = '^Ptr64\b' }
        "_CONTROL_AREA"         = @{ FilePointer = '^struct _EX_FAST_REF\b' }
        "_FILE_OBJECT"          = @{ DeviceObject = '^Ptr64\b' }
        "_EX_FAST_REF"          = @{ RefCnt = '^Bitfield\b' }
    }
}

# The names of the loader's load reasons (_LDR_DLL_LOAD_REASON, from the
# kernel's symbols: "LoadReasonDynamicLoad = 0n4" -> 4 = "DynamicLoad");
# empty when the symbols do not have them (the number is written then)
function Get-DbgEngLoadReasonNames {
    param($Session)
    $names = New-Object 'System.Collections.Generic.Dictionary[int,string]'
    $text = ""
    try { $text = [string](Invoke-DbgEngCommand -Session $Session -Command "dt -v nt!_LDR_DLL_LOAD_REASON" -TimeoutSeconds 60) }
    catch { return $names }
    foreach ($line in ($text -split "\r?\n")) {
        if ($line -match '^\s+LoadReason(\w+)\s*=\s*0n(-?\d+)\s*$') {
            $value = [int]$Matches[2]
            if (-not $names.ContainsKey($value)) { $names[$value] = $Matches[1] }
        }
    }
    return $names
}

# The area: every process's DLLs (DllsArea in the C# above)
function Invoke-DbgEngModulesArea {
    param($Context, $Area)
    if (-not ([System.Management.Automation.PSTypeName]'TimelineDbgEng.DllsArea').Type) {
        $Area.SetNotRead("the code of lib\memory\TimelineDbgEng.Modules.ps1 was not compiled")
        return
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec (Get-DbgEngModulesLayoutSpec)
    $walker = Get-DbgEngVadWalker -Context $Context
    $loaderMissing = $layout.MissingOf([TimelineDbgEng.DllScanner]::Fields)
    if ($loaderMissing -and -not $walker.Ready) {
        $Area.SetNotRead("the kernel's symbols do not describe the loader lists or the memory regions")
        return
    }
    $reasons = Get-DbgEngLoadReasonNames -Session $Context.Session
    [TimelineDbgEng.DllsArea]::Run($Context, $Area, $layout, $walker, $reasons)
}
