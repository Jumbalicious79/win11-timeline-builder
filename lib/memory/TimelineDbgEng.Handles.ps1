# =============================================================
# Windows ARM64 memory dumps: handles (item e)
# Part of win11-timeline-builder (work package WP3). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract) and on TimelineDbgEng.Objects.ps1.
#
# What it reads (offsets from the kernel's symbol file, 'dt'): each
# process's handle table (EPROCESS.ObjectTable -> _HANDLE_TABLE.TableCode,
# whose low 2 bits are its levels: 0, a page of 256 entries; 1, a page of
# pointers to such pages; 2, two levels of pointer pages, as the process ID
# table the process scan reads), each entry (_HANDLE_TABLE_ENTRY: the
# object header from ObjectPointerBits, shifted left by 4 and sign-extended;
# the access from GrantedAccessBits) and its object's type through
# TimelineDbgEng.Objects.ps1. Every handle is decoded and counted per type
# (the log); only a subset becomes entries (Handle; rows: Add-DbgEngHandleRows
# in lib\memory\TimelineMemoryRows.ps1, Source Memory-Handles):
#   Process, Thread   a handle to another process (or one of its threads)
#                     with rights to change it -- process: memory operation
#                     and write, thread creation, or all access; thread: set
#                     context -- where the holder is neither the target's
#                     parent nor its child and is not the System process
#                     (PID 4); one entry per holder, target and type (the
#                     rights of its handles together, Handles=<n>).
#                     Anomaly=WriteAccessUnrelated when the holder runs as a
#                     user account (token user S-1-5-21-... or S-1-12-1-...)
#   File              a file in a folder users can write to or a Startup
#                     folder (HandleTableScan.FileFolders), once per process
#                     and path
#   Key               a registry key under Run, RunOnce, Services, Image File
#                     Execution Options or Winlogon, its path from the key
#                     control block chain (_CM_KEY_BODY.KeyControlBlock ->
#                     ParentKcb, NameBlock); a key whose path cannot be built
#                     is counted, not listed; once per process and path
#   Mutant            a named mutex, once per process and name
# Offers a handle lookup to the joins: $Context.Shared["HandleLookup"]
# (HandleTableLookup.Lookup(eprocess, handle value)), and the Process and
# Thread entries with their target's EPROCESS: $Context.Shared["HandleTargets"]
# (TimelineDbgEng.Joins.ps1 adds Anomaly TargetHasPeCode from them).
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngHandlesSource {
    return @'
namespace TimelineDbgEng
{
    // One handle of a process's handle table
    public sealed class HandleTableRecord
    {
        public ulong Process;    // the holder's EPROCESS
        public ulong Value;      // the handle value
        public ulong Header;     // the object's header
        public ulong Object;     // the object's body
        public string Type;      // the object's type ("Process", "File", ...)
        public uint Access;      // the granted access
    }

    // Every decoded handle by holder and handle value, for the joins
    public sealed class HandleTableLookup
    {
        readonly Dictionary<ulong, Dictionary<ulong, HandleTableRecord>> tables = new Dictionary<ulong, Dictionary<ulong, HandleTableRecord>>();
        public int Count;
        public void Add(HandleTableRecord r)
        {
            Dictionary<ulong, HandleTableRecord> table;
            if (!tables.TryGetValue(r.Process, out table)) { table = new Dictionary<ulong, HandleTableRecord>(); tables[r.Process] = table; }
            table[r.Value] = r;
            Count++;
        }
        // The handle of a process (its EPROCESS) with that value, or null
        public HandleTableRecord Lookup(ulong process, ulong handle)
        {
            Dictionary<ulong, HandleTableRecord> table;
            HandleTableRecord r;
            if (tables.TryGetValue(process, out table) && table.TryGetValue(handle, out r)) return r;
            return null;
        }
        public bool HasTable(ulong process) { return tables.ContainsKey(process); }
        public int Processes { get { return tables.Count; } }
    }

    // The handles area: every handle table decoded, the useful subset as entries
    public sealed class HandleTableScan
    {
        public static readonly string[] Fields = new string[] {
            "_EPROCESS.ObjectTable", "_EPROCESS.UniqueProcessId", "_EPROCESS.InheritedFromUniqueProcessId", "_EPROCESS.CreateTime",
            "_HANDLE_TABLE.TableCode", "_HANDLE_TABLE_ENTRY.ObjectPointerBits", "_HANDLE_TABLE_ENTRY.GrantedAccessBits" };
        public static readonly string[] ThreadFields = new string[] { "_KTHREAD.Process", "_ETHREAD.Cid", "_CLIENT_ID.UniqueThread" };
        public static readonly string[] FileFields = new string[] { "_FILE_OBJECT.DeviceObject", "_FILE_OBJECT.FileName", "_FILE_OBJECT.RelatedFileObject" };
        public static readonly string[] KeyFields = new string[] {
            "_CM_KEY_BODY.KeyControlBlock", "_CM_KEY_CONTROL_BLOCK.ParentKcb", "_CM_KEY_CONTROL_BLOCK.NameBlock", "_CM_KEY_CONTROL_BLOCK.KeyHive",
            "_CM_NAME_CONTROL_BLOCK.Compressed", "_CM_NAME_CONTROL_BLOCK.NameLength", "_CM_NAME_CONTROL_BLOCK.Name" };
        public static readonly string[] TokenFields = new string[] { "_TOKEN.UserAndGroups", "_SID_AND_ATTRIBUTES.Sid" };

        // Access rights (winnt.h): of a process, creating a thread (0x2),
        // memory operation (0x8) and memory write (0x20); all access
        // (0x1FFFFF) has them all. Of a thread, setting its context (0x10).
        const uint ProcessThreadCreate = 0x0002;
        const uint ProcessMemoryChange = 0x0008 | 0x0020;
        const uint ThreadContextSet = 0x0010;
        // File entries: folders users can write to (the userWritable and
        // stagingExec lists of lib\report\report-rules.json) and the
        // Startup folders; matched in the path without its volume
        public static readonly string[] FileFolders = new string[] {
            "\\Downloads\\", "\\Users\\Public\\", "\\PerfLogs\\", "\\$Recycle.Bin\\", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\", "\\Start Menu\\Programs\\Startup\\" };
        // Key entries: these keys and the keys under them (and the Services
        // key of a control set, IsWatchedKey)
        public static readonly string[] KeyTails = new string[] {
            "\\Microsoft\\Windows\\CurrentVersion\\Run", "\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" };
        // ... and only the keys under these: Windows' loader keeps the Image
        // File Execution Options key itself open in every process
        public static readonly string[] KeyParents = new string[] { "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" };
        // The console hosts: one holds a handle with all access to each
        // process of its console window (a sibling when the console's first
        // process started both)
        public static readonly string[] ConsoleHosts = new string[] { "conhost.exe", "OpenConsole.exe" };
        // At most this many pages of handle entries per process (256 handles
        // each), levels of a key path, and links of a relative file name
        const int MaxLeafPages = 16384;
        const int MaxKeyDepth = 64;
        const int MaxRelated = 4;
        const int EntrySize = 16;
        const int EntriesPerPage = 256;

        readonly MemoryContext context;
        readonly MemoryReader reader;
        readonly Layout layout;
        readonly KernelObjectReader objects;
        readonly int objectTable, tableCode, pidField, ppidField, createField, pointerPos, pointerWidth, accessField, accessPos, accessWidth;
        readonly bool threads, files, keys, tokens;
        readonly HashSet<ulong> unreadablePages = new HashSet<ulong>();
        readonly Dictionary<ulong, string> keyPaths = new Dictionary<ulong, string>();
        readonly Dictionary<ulong, string> devicePaths = new Dictionary<ulong, string>();
        readonly Dictionary<ulong, ProcessInfo> outsideScan = new Dictionary<ulong, ProcessInfo>();
        readonly Dictionary<ulong, string> sids = new Dictionary<ulong, string>();
        readonly Dictionary<string, long> typeCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        public readonly HandleTableLookup Lookup = new HandleTableLookup();
        // The Process and Thread entries with their target's EPROCESS, for
        // the joins (TimelineDbgEng.Joins.ps1)
        public readonly List<KeyValuePair<MemoryEntry, ulong>> Targets = new List<KeyValuePair<MemoryEntry, ulong>>();

        public long Handles, UndecodedHandles, UnreadableHeaders;
        public int TablesRead, NoTable, UnreadableTables, UnreadableLeafPages, MaxPerProcess;
        public int ProcessRows, ThreadRows, ThreadRowsFolded, FileRows, KeyRows, MutantRows, UnrelatedUserRows, FamilyRows;
        public int UnnamedFiles, KeyPathsUnreadable, TargetsUnreadable;

        public HandleTableScan(MemoryContext context, Layout layout, KernelObjectReader objects)
        {
            this.context = context;
            this.reader = context.Reader;
            this.layout = layout;
            this.objects = objects;
            objectTable = layout.Off("_EPROCESS.ObjectTable");
            pidField = layout.Off("_EPROCESS.UniqueProcessId");
            ppidField = layout.Off("_EPROCESS.InheritedFromUniqueProcessId");
            createField = layout.Off("_EPROCESS.CreateTime");
            tableCode = layout.Off("_HANDLE_TABLE.TableCode");
            int[] bits;
            pointerPos = layout.Bits.TryGetValue("_HANDLE_TABLE_ENTRY.ObjectPointerBits", out bits) ? bits[0] : -1;
            pointerWidth = bits != null ? bits[1] : 0;
            accessField = layout.Off("_HANDLE_TABLE_ENTRY.GrantedAccessBits");
            int[] access;
            accessPos = layout.Bits.TryGetValue("_HANDLE_TABLE_ENTRY.GrantedAccessBits", out access) ? access[0] : -1;
            accessWidth = access != null ? access[1] : 0;
            threads = layout.HasAll(ThreadFields);
            files = layout.HasAll(FileFields);
            keys = layout.HasAll(KeyFields) && layout.Bits.ContainsKey("_CM_NAME_CONTROL_BLOCK.Compressed");
            tokens = layout.HasAll(TokenFields);
        }

        // "" when the symbols give what every handle needs, else which are not
        public string MissingFields
        {
            get
            {
                string gone = layout.MissingOf(Fields);
                if (gone.Length == 0 && (pointerWidth < 32 || pointerWidth > 60 || pointerPos < 0 || pointerPos + pointerWidth > 64 || accessPos < 0 || accessWidth < 16))
                    gone = "_HANDLE_TABLE_ENTRY as a handle table entry the builder reads";
                return gone;
            }
        }
        // What the symbols lack for some entries ("" when nothing)
        public string PartlyMissing
        {
            get
            {
                List<string> parts = new List<string>();
                if (!threads) parts.Add("thread handles' processes");
                if (!files) parts.Add("file names");
                if (!keys) parts.Add("registry key paths");
                return string.Join(", ", parts.ToArray());
            }
        }

        // The object header of an entry's low half (0 for a free entry)
        ulong HeaderOf(ulong low)
        {
            ulong bits = Layout.Extract(low, pointerPos, pointerWidth);
            if (bits == 0) return 0;
            ulong header = bits << 4;
            int top = pointerWidth + 3;
            if (top < 63 && ((header >> top) & 1) != 0) header |= ~((1UL << (top + 1)) - 1);
            return header;
        }

        // The pages of handle entries of a table, each with the number of
        // the page (handle value = (page * 256 + slot) * 4); null when the
        // table is not in the dump
        List<KeyValuePair<long, ulong>> LeafPages(ulong table)
        {
            List<KeyValuePair<long, ulong>> pages = new List<KeyValuePair<long, ulong>>();
            ulong code;
            if (!reader.TryU64(0, table + (ulong)tableCode, out code)) return null;
            int level = (int)(code & 3);
            ulong top = code & ~3UL;
            if (!MemoryReader.IsKernelPointer(top) || level > 2) return null;
            if (level == 0) { pages.Add(new KeyValuePair<long, ulong>(0, top)); return pages; }
            byte[] first;
            if (!reader.TryRead(0, top, 4096, out first)) return null;
            for (int i = 0; i < 512 && pages.Count < MaxLeafPages; i++)
            {
                ulong p = BitConverter.ToUInt64(first, i * 8);
                if (p == 0 || !MemoryReader.IsKernelPointer(p)) continue;
                if (level == 1) { pages.Add(new KeyValuePair<long, ulong>(i, p)); continue; }
                byte[] middle;
                if (!reader.TryRead(0, p, 4096, out middle)) { UnreadableLeafPages++; continue; }
                for (int j = 0; j < 512 && pages.Count < MaxLeafPages; j++)
                {
                    ulong leaf = BitConverter.ToUInt64(middle, j * 8);
                    if (leaf != 0 && MemoryReader.IsKernelPointer(leaf)) pages.Add(new KeyValuePair<long, ulong>((long)i * 512 + j, leaf));
                }
            }
            return pages;
        }

        // A process by its EPROCESS: from the scan, else read (and kept)
        // when it is a process object; null when it is neither
        ProcessInfo ProcessAt(ulong eprocess)
        {
            ProcessInfo p = context.Find(eprocess);
            if (p != null) return p;
            if (outsideScan.TryGetValue(eprocess, out p)) return p;
            p = null;
            int size = context.ProcessLayout != null ? context.ProcessLayout.Size("_EPROCESS") : 0;
            if (size > 0 && MemoryReader.IsKernelPointer(eprocess))
            {
                byte[] block = reader.Read(0, eprocess, size);
                // Its dispatcher header's type: 3, a process
                if (block.Length == size && block[0] == 3) p = ProcessInfo.FromBlock(eprocess, block, context.ProcessLayout);
            }
            outsideScan[eprocess] = p;
            return p;
        }

        // The token user's SID of a process: the ProcessDetails area's, else
        // read here from its token (_TOKEN.UserAndGroups[0].Sid); "" when unknown
        string UserSid(ProcessInfo p)
        {
            if (!string.IsNullOrEmpty(p.UserSid)) return p.UserSid;
            string sid;
            if (sids.TryGetValue(p.Eprocess, out sid)) return sid;
            sid = "";
            if (tokens && MemoryReader.IsKernelPointer(p.Token))
            {
                ulong groups, pointer;
                if (reader.TryU64(0, p.Token + (ulong)layout.Off("_TOKEN.UserAndGroups"), out groups) && MemoryReader.IsKernelPointer(groups) &&
                    reader.TryU64(0, groups + (ulong)layout.Off("_SID_AND_ATTRIBUTES.Sid"), out pointer) && MemoryReader.IsKernelAddress(pointer))
                {
                    sid = SidText(pointer) ?? "";
                }
            }
            sids[p.Eprocess] = sid;
            return sid;
        }

        // A SID in memory as text ("S-1-5-18"); null when it is not one
        string SidText(ulong address)
        {
            byte[] head;
            if (!reader.TryRead(0, address, 8, out head) || head[0] != 1 || head[1] > 15) return null;
            int count = head[1];
            byte[] all;
            if (!reader.TryRead(0, address, 8 + 4 * count, out all)) return null;
            ulong authority = 0;
            for (int i = 2; i < 8; i++) authority = (authority << 8) | all[i];
            StringBuilder s = new StringBuilder("S-1-");
            s.Append(authority.ToString(CultureInfo.InvariantCulture));
            for (int i = 0; i < count; i++) s.Append('-').Append(BitConverter.ToUInt32(all, 8 + 4 * i).ToString(CultureInfo.InvariantCulture));
            return s.ToString();
        }

        static bool IsUserAccount(string sid)
        {
            return sid != null && (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.StartsWith("S-1-12-1-", StringComparison.Ordinal));
        }

        // Holder and target are parent and child (either way), with the
        // parent created first (a reused process ID is not a parent)
        static bool ParentOf(ProcessInfo parent, ProcessInfo child)
        {
            if (child.Ppid != parent.Pid) return false;
            return parent.CreateTime <= 0 || child.CreateTime <= 0 || parent.CreateTime <= child.CreateTime;
        }

        // The parent of a process in the scan (the latest process of its
        // parent's ID created before it), or null
        ProcessInfo ParentInScan(ProcessInfo p)
        {
            ProcessInfo best = null;
            foreach (ProcessInfo candidate in context.Processes)
            {
                if (candidate.Pid != p.Ppid || candidate.Eprocess == p.Eprocess || !ParentOf(candidate, p)) continue;
                if (best == null || candidate.CreateTime > best.CreateTime) best = candidate;
            }
            return best;
        }

        // ancestor started p, directly or through processes it started
        bool AncestorOf(ProcessInfo ancestor, ProcessInfo p)
        {
            ProcessInfo current = p;
            for (int depth = 0; depth < 16 && current != null; depth++)
            {
                if (ParentOf(ancestor, current)) return true;
                current = ParentInScan(current);
            }
            return false;
        }

        // The process family the anomaly leaves out: one process started the
        // other (at any depth); the holder is a console host and the target
        // one of its console's processes; or both have one parent and run
        // the same program as the same user (an application's own processes)
        bool Family(ProcessInfo holder, ProcessInfo target, string holderSid)
        {
            if (AncestorOf(holder, target) || AncestorOf(target, holder)) return true;
            if (IsConsoleHost(holder))
            {
                // The console's first process started the console host and,
                // directly or not, every other process of the console
                ProcessInfo first = ParentInScan(holder);
                if (first != null ? AncestorOf(first, target) : holder.Ppid == target.Ppid) return true;
            }
            return holder.Ppid == target.Ppid && string.Equals(holder.Name, target.Name, StringComparison.OrdinalIgnoreCase) && holderSid.Length > 0 && holderSid == UserSid(target);
        }

        static bool IsConsoleHost(ProcessInfo p)
        {
            foreach (string host in ConsoleHosts)
            {
                if (string.Equals(p.Name, host, StringComparison.OrdinalIgnoreCase)) return true;
                // A short name is cut to 14 characters
                if (p.FullName.Length == 0 && p.ShortName.Length >= 14 && host.StartsWith(p.ShortName, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        // A file object's full name: its device's name (with its drive
        // letter) and its own; relative names joined to the file they are
        // relative to. Null when it has none or it is not in the dump.
        string FileName(ulong file)
        {
            string name = reader.UnicodeString(0, file + (ulong)layout.Off("_FILE_OBJECT.FileName"));
            if (string.IsNullOrEmpty(name)) return null;
            ulong current = file;
            for (int i = 0; i < MaxRelated && name[0] != '\\'; i++)
            {
                ulong related;
                if (!reader.TryU64(0, current + (ulong)layout.Off("_FILE_OBJECT.RelatedFileObject"), out related) || !MemoryReader.IsKernelPointer(related)) break;
                string parent = reader.UnicodeString(0, related + (ulong)layout.Off("_FILE_OBJECT.FileName"));
                if (string.IsNullOrEmpty(parent)) break;
                name = parent.TrimEnd('\\') + "\\" + name;
                current = related;
            }
            ulong device;
            if (!reader.TryU64(0, file + (ulong)layout.Off("_FILE_OBJECT.DeviceObject"), out device) || !MemoryReader.IsKernelPointer(device)) return name;
            string devicePath;
            if (!devicePaths.TryGetValue(device, out devicePath))
            {
                devicePath = objects.FullName(device);
                devicePaths[device] = devicePath;
            }
            if (devicePath == null || name[0] != '\\') return name;
            return objects.WithDriveLetter(devicePath + name);
        }

        static bool InFileFolder(string path)
        {
            foreach (string folder in FileFolders) { if (path.IndexOf(folder, StringComparison.OrdinalIgnoreCase) >= 0) return true; }
            return false;
        }

        // A key's path from its key control block ("\REGISTRY\MACHINE\..."),
        // kept per block; null when a part is not in the dump. Where a hive
        // is mounted, the chain has the key it is linked to in the master
        // hive and the hive's root, both with the mount point's name (Windows
        // 11 24H2 keeps a block for each): the name is in the path once.
        string KeyPath(ulong kcb)
        {
            string path;
            if (keyPaths.TryGetValue(kcb, out path)) return path;
            List<string> parts = new List<string>();
            ulong current = kcb;
            path = null;
            int parentField = layout.Off("_CM_KEY_CONTROL_BLOCK.ParentKcb");
            int nameBlockField = layout.Off("_CM_KEY_CONTROL_BLOCK.NameBlock");
            int hiveField = layout.Off("_CM_KEY_CONTROL_BLOCK.KeyHive");
            int lengthField = layout.Off("_CM_NAME_CONTROL_BLOCK.NameLength");
            int nameField = layout.Off("_CM_NAME_CONTROL_BLOCK.Name");
            int compressedField = layout.Off("_CM_NAME_CONTROL_BLOCK.Compressed");
            string childName = null;
            ulong childHive = 0;
            for (int depth = 0; depth < MaxKeyDepth; depth++)
            {
                ulong parent, block, hive;
                if (!reader.TryU64(0, current + (ulong)parentField, out parent) || !reader.TryU64(0, current + (ulong)nameBlockField, out block) ||
                    !reader.TryU64(0, current + (ulong)hiveField, out hive) || !MemoryReader.IsKernelPointer(block)) break;
                ushort length;
                uint flags;
                if (!reader.TryU16(0, block + (ulong)lengthField, out length) || length == 0 || !reader.TryU32(0, block + (ulong)compressedField, out flags)) break;
                byte[] raw;
                if (!reader.TryRead(0, block + (ulong)nameField, length, out raw)) break;
                string name;
                if (layout.BitsOf(flags, "_CM_NAME_CONTROL_BLOCK.Compressed") != 0)
                {
                    // One byte per character (the registry's compressed names)
                    char[] chars = new char[raw.Length];
                    for (int i = 0; i < raw.Length; i++) chars[i] = (char)raw[i];
                    name = new string(chars);
                }
                else name = Encoding.Unicode.GetString(raw, 0, raw.Length - raw.Length % 2);
                bool mountPoint = childName != null && hive != childHive && string.Equals(name, childName, StringComparison.OrdinalIgnoreCase);
                if (!mountPoint) parts.Insert(0, name);
                if (parent == 0) { path = "\\" + string.Join("\\", parts.ToArray()); break; }
                if (!MemoryReader.IsKernelPointer(parent)) break;
                childName = name;
                childHive = hive;
                current = parent;
            }
            keyPaths[kcb] = path;
            return path;
        }

        // The path is the key tail (a whole name) or a key under it; with
        // under, only a key under it
        static bool HasKey(string path, string tail, bool under)
        {
            int at = path.IndexOf(tail, StringComparison.OrdinalIgnoreCase);
            while (at >= 0)
            {
                int end = at + tail.Length;
                if ((end == path.Length && !under) || (end < path.Length && path[end] == '\\' && end + 1 < path.Length)) return true;
                at = path.IndexOf(tail, at + 1, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        // A key whose handle becomes an entry: one of KeyTails or a key under
        // it, a key under one of KeyParents, or the Services key of a control
        // set or a service's own key (where its program is set); the keys
        // under a service's key (Parameters, Enum, ...) are read by every
        // process that uses the service and are only counted
        static bool IsWatchedKey(string path)
        {
            foreach (string tail in KeyTails) { if (HasKey(path, tail, false)) return true; }
            foreach (string tail in KeyParents) { if (HasKey(path, tail, true)) return true; }
            string[] parts = path.Split('\\');
            // "", REGISTRY, MACHINE, SYSTEM, ControlSet001 (or CurrentControlSet), Services[, <service>]
            return (parts.Length == 6 || parts.Length == 7) && string.Equals(parts[1], "REGISTRY", StringComparison.OrdinalIgnoreCase) && string.Equals(parts[2], "MACHINE", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(parts[3], "SYSTEM", StringComparison.OrdinalIgnoreCase) && parts[4].IndexOf("ControlSet", StringComparison.OrdinalIgnoreCase) >= 0 &&
                string.Equals(parts[5], "Services", StringComparison.OrdinalIgnoreCase);
        }

        // One entry of a holder ("PID=n | ProcessCreated=.." and the owner's
        // name and SID come first)
        MemoryEntry NewEntry(AreaResult area, ProcessInfo holder, string type, HandleTableRecord r)
        {
            MemoryEntry e = area.Add("Handle");
            e.Set("Pid", holder.Pid);
            e.Set("ProcessCreated", holder.CreatedText);
            e.Set("Process", holder.Name);
            e.Set("User", UserSid(holder));
            e.Set("Type", type);
            e.SetHex("Handle", r.Value);
            e.SetHex("Access", r.Access);
            return e;
        }

        // A process or thread handle that can change its target: its
        // target, when the holder and target are unrelated (else null)
        ProcessInfo ChangingTarget(ProcessInfo holder, HandleTableRecord r, out long threadId)
        {
            threadId = -1;
            ulong eprocess = r.Object;
            if (r.Type == "Process")
            {
                if ((r.Access & ProcessThreadCreate) == 0 && (r.Access & ProcessMemoryChange) != ProcessMemoryChange) return null;
            }
            else
            {
                if (!threads || (r.Access & ThreadContextSet) == 0) return null;
                byte[] cid;
                if (!reader.TryU64(0, r.Object + (ulong)layout.Off("_KTHREAD.Process"), out eprocess) ||
                    !reader.TryRead(0, r.Object + (ulong)layout.Off("_ETHREAD.Cid"), 16, out cid)) { TargetsUnreadable++; return null; }
                threadId = (long)BitConverter.ToUInt64(cid, layout.Off("_CLIENT_ID.UniqueThread"));
            }
            if (eprocess == holder.Eprocess) return null;
            ProcessInfo target = ProcessAt(eprocess);
            if (target == null) { TargetsUnreadable++; return null; }
            if (target.Pid == holder.Pid) return null;
            if (ParentOf(holder, target) || ParentOf(target, holder)) return null;
            return target;
        }

        sealed class Grouped
        {
            public HandleTableRecord First;
            public uint Access;
            public int Count;
            public ProcessInfo Target;
            public long ThreadId;
        }

        public void Run(AreaResult area)
        {
            // Offered to the joins (set here, in C#: no PowerShell wrapper)
            context.Shared["HandleLookup"] = Lookup;
            context.Shared["HandleTargets"] = Targets;
            foreach (ProcessInfo holder in context.Processes)
            {
                if (area.TimeUp()) break;
                ulong table = 0;
                if (Bytes.Has(holder.Block, objectTable, 8)) table = BitConverter.ToUInt64(holder.Block, objectTable);
                else reader.TryU64(0, holder.Eprocess + (ulong)objectTable, out table);
                // An exited process has no handle table
                if (table == 0) { NoTable++; continue; }
                List<KeyValuePair<long, ulong>> pages = MemoryReader.IsKernelPointer(table) ? LeafPages(table) : null;
                if (pages == null || pages.Count == 0) { UnreadableTables++; continue; }
                TablesRead++;
                ScanTable(area, holder, pages);
            }
            Report(area);
        }

        void ScanTable(AreaResult area, ProcessInfo holder, List<KeyValuePair<long, ulong>> pages)
        {
            int perProcess = 0;
            bool systemHolder = holder.Pid == 4;
            Dictionary<string, Grouped> changing = new Dictionary<string, Grouped>(StringComparer.Ordinal);
            List<string> changingOrder = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<KeyValuePair<HandleTableRecord, string>> named = new List<KeyValuePair<HandleTableRecord, string>>();
            foreach (KeyValuePair<long, ulong> page in pages)
            {
                if (area.TimeUp()) return;
                byte[] entries = reader.Read(0, page.Value, EntriesPerPage * EntrySize);
                if (entries.Length < EntriesPerPage * EntrySize) { UnreadableLeafPages++; if (entries.Length < EntrySize) continue; }
                int slots = entries.Length / EntrySize;
                for (int k = 0; k < slots; k++)
                {
                    ulong low = BitConverter.ToUInt64(entries, k * EntrySize);
                    if (low == 0) continue;
                    ulong header = HeaderOf(low);
                    if (header == 0) continue;
                    if (!MemoryReader.IsKernelPointer(header)) { UndecodedHandles++; continue; }
                    byte[] h = objects.Header(header);
                    if (h == null) { UnreadableHeaders++; continue; }
                    string type = objects.TypeOf(header, h);
                    if (type == null) { UndecodedHandles++; continue; }
                    ulong high = BitConverter.ToUInt64(entries, k * EntrySize + 8);
                    HandleTableRecord r = new HandleTableRecord();
                    r.Process = holder.Eprocess;
                    r.Value = (ulong)((page.Key * EntriesPerPage + k) * 4);
                    r.Header = header;
                    r.Object = header + (ulong)objects.BodyOffset;
                    r.Type = type;
                    r.Access = (uint)Layout.Extract(accessField == 8 ? high : (accessField == 0 ? low : 0), accessPos, accessWidth);
                    Lookup.Add(r);
                    Handles++;
                    perProcess++;
                    long n;
                    typeCounts.TryGetValue(type, out n);
                    typeCounts[type] = n + 1;
                    switch (type)
                    {
                        case "Process":
                        case "Thread":
                            if (systemHolder) break;
                            long threadId;
                            ProcessInfo target = ChangingTarget(holder, r, out threadId);
                            if (target == null) break;
                            string key = type + "|" + target.Eprocess.ToString("x", CultureInfo.InvariantCulture);
                            Grouped g;
                            if (!changing.TryGetValue(key, out g))
                            {
                                g = new Grouped();
                                g.First = r;
                                g.Target = target;
                                g.ThreadId = threadId;
                                changing[key] = g;
                                changingOrder.Add(key);
                            }
                            g.Access |= r.Access;
                            g.Count++;
                            break;
                        case "File":
                            if (!files) break;
                            string path = FileName(r.Object);
                            if (path == null) { UnnamedFiles++; break; }
                            if (InFileFolder(path) && seen.Add("F|" + path)) named.Add(new KeyValuePair<HandleTableRecord, string>(r, path));
                            break;
                        case "Key":
                            if (!keys) break;
                            ulong kcb;
                            if (!reader.TryU64(0, r.Object + (ulong)layout.Off("_CM_KEY_BODY.KeyControlBlock"), out kcb) || !MemoryReader.IsKernelPointer(kcb)) { KeyPathsUnreadable++; break; }
                            string keyPath = KeyPath(kcb);
                            if (keyPath == null) { KeyPathsUnreadable++; break; }
                            if (IsWatchedKey(keyPath) && seen.Add("K|" + keyPath)) named.Add(new KeyValuePair<HandleTableRecord, string>(r, keyPath));
                            break;
                        case "Mutant":
                            string mutex = objects.FullName(r.Object);
                            if (!string.IsNullOrEmpty(mutex) && seen.Add("M|" + mutex)) named.Add(new KeyValuePair<HandleTableRecord, string>(r, mutex));
                            break;
                    }
                }
            }
            if (perProcess > MaxPerProcess) MaxPerProcess = perProcess;
            string holderSid = UserSid(holder);
            bool userHolder = IsUserAccount(holderSid);
            foreach (string key in changingOrder)
            {
                Grouped g = changing[key];
                // Thread handles add nothing to a process handle that can
                // change the same process
                if (g.First.Type == "Thread" && changing.ContainsKey("Process|" + g.Target.Eprocess.ToString("x", CultureInfo.InvariantCulture))) { ThreadRowsFolded++; continue; }
                MemoryEntry e = NewEntry(area, holder, g.First.Type, g.First);
                e.SetHex("Access", g.Access);
                e.Set("Target", g.Target.Name);
                e.Set("TargetPid", g.Target.Pid);
                e.Set("TargetProcess", g.Target.Name);
                e.Set("TargetCreated", g.Target.CreatedText);
                if (g.ThreadId >= 0) e.Set("TargetTid", g.ThreadId);
                if (g.Count > 1) e.Set("Handles", g.Count);
                Targets.Add(new KeyValuePair<MemoryEntry, ulong>(e, g.Target.Eprocess));
                if (userHolder)
                {
                    if (Family(holder, g.Target, holderSid)) FamilyRows++;
                    else { e.Set("Anomaly", "WriteAccessUnrelated"); UnrelatedUserRows++; }
                }
                if (g.First.Type == "Process") ProcessRows++; else ThreadRows++;
            }
            foreach (KeyValuePair<HandleTableRecord, string> item in named)
            {
                MemoryEntry e = NewEntry(area, holder, item.Key.Type, item.Key);
                e.Set("Target", item.Value);
                if (item.Key.Type == "File") FileRows++;
                else if (item.Key.Type == "Key") KeyRows++;
                else MutantRows++;
            }
        }

        // The counts for the log and the notes for the report
        void Report(AreaResult area)
        {
            area.Coverage.Count("handles", Handles);
            area.Coverage.Count("handle tables read", TablesRead);
            area.Coverage.Count("most in one process", MaxPerProcess);
            area.Coverage.Count("process rows", ProcessRows);
            area.Coverage.Count("thread rows", ThreadRows);
            area.Coverage.Count("thread rows folded into process rows", ThreadRowsFolded);
            area.Coverage.Count("rows of a user account changing an unrelated process", UnrelatedUserRows);
            area.Coverage.Count("rows of a user account in the target's process family", FamilyRows);
            area.Coverage.Count("file rows", FileRows);
            area.Coverage.Count("key rows", KeyRows);
            area.Coverage.Count("mutex rows", MutantRows);
            List<KeyValuePair<string, long>> byCount = new List<KeyValuePair<string, long>>(typeCounts);
            byCount.Sort(delegate(KeyValuePair<string, long> a, KeyValuePair<string, long> b) { int c = b.Value.CompareTo(a.Value); return c != 0 ? c : string.CompareOrdinal(a.Key, b.Key); });
            foreach (KeyValuePair<string, long> t in byCount) area.Coverage.Count("type " + t.Key, t.Value);
            if (NoTable > 0) area.Coverage.Count("exited processes without a handle table", NoTable);
            if (UndecodedHandles + UnreadableHeaders > 0) area.Coverage.Count("handles whose object could not be read", UndecodedHandles + UnreadableHeaders);
            if (UnnamedFiles > 0) area.Coverage.Count("file handles without a readable name", UnnamedFiles);
            if (KeyPathsUnreadable > 0) area.Coverage.Count("key handles whose path could not be built", KeyPathsUnreadable);
            if (TargetsUnreadable > 0) area.Coverage.Count("process or thread handles whose target could not be read", TargetsUnreadable);
            List<string> gaps = new List<string>();
            if (UnreadableTables > 0) gaps.Add("the handle tables of " + UnreadableTables + " process(es) were not in the dump");
            if (UnreadableLeafPages > 0) gaps.Add(UnreadableLeafPages + " page(s) of handle entries were not in the dump");
            long lost = UndecodedHandles + UnreadableHeaders;
            if (lost > 0) gaps.Add("the objects of " + lost + " handle(s) could not be read");
            if (KeyPathsUnreadable > 0) gaps.Add(KeyPathsUnreadable + " registry key handle(s) without a readable path were left out");
            if (gaps.Count > 0) area.Coverage.Note(string.Join(", ", gaps.ToArray()) + ", as when memory is copied while Windows runs");
        }
    }
}
'@
}

# The layout of the area
function Get-DbgEngHandlesLayout {
    param($Context)
    $spec = @{
        "_EPROCESS"              = @{ ObjectTable = '^Ptr64\b'; UniqueProcessId = '^Ptr64\b'; InheritedFromUniqueProcessId = '^Ptr64\b'; CreateTime = '^union _LARGE_INTEGER\b' }
        "_HANDLE_TABLE"          = @{ TableCode = '^Uint8B$' }
        "_HANDLE_TABLE_ENTRY"    = @{ ObjectPointerBits = '^Bitfield\b'; GrantedAccessBits = '^Bitfield\b' }
        "_KTHREAD"               = @{ Process = '^Ptr64\b' }
        "_ETHREAD"               = @{ Cid = '^struct _CLIENT_ID\b' }
        "_CLIENT_ID"             = @{ UniqueThread = '^Ptr64\b' }
        "_FILE_OBJECT"           = @{ DeviceObject = '^Ptr64\b'; FileName = '^struct _UNICODE_STRING\b'; RelatedFileObject = '^Ptr64\b' }
        "_CM_KEY_BODY"           = @{ KeyControlBlock = '^Ptr64\b' }
        "_CM_KEY_CONTROL_BLOCK"  = @{ ParentKcb = '^Ptr64\b'; NameBlock = '^Ptr64\b'; KeyHive = '^Ptr64\b' }
        "_CM_NAME_CONTROL_BLOCK" = @{ Compressed = '^Bitfield\b'; NameLength = '^Uint2B$'; Name = '^\[\d+\] Wchar$' }
        "_TOKEN"                 = @{ UserAndGroups = '^Ptr64\b' }
        "_SID_AND_ATTRIBUTES"    = @{ Sid = '^Ptr64\b' }
    }
    return (New-DbgEngLayout -Session $Context.Session -Spec $spec)
}

# The area: every handle decoded and counted, the Handle entries of the
# useful subset, and the handle lookup for the joins
function Invoke-DbgEngHandlesArea {
    param($Context, $Area)
    $objects = Get-DbgEngKernelObjects -Context $Context
    if ($objects.Problem) { $Area.SetNotRead($objects.Problem); return }
    $layout = Get-DbgEngHandlesLayout -Context $Context
    $scan = New-Object TimelineDbgEng.HandleTableScan -ArgumentList $Context, $layout, $objects
    if ($scan.MissingFields) { $Area.SetNotRead("the kernel's symbols do not give $($scan.MissingFields)"); return }
    if ($scan.PartlyMissing) { $Area.SetPartial("the kernel's symbols do not describe the $($scan.PartlyMissing), so those handles were only counted") }
    $scan.Run($Area)
}
