# =============================================================
# Windows ARM64 memory dumps: services from the service control manager's memory (item j)
# Part of win11-timeline-builder (work package WP7). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads: the service control manager's list of service records in
# the memory of services.exe, as Volatility's windows.svcscan gives them on
# x64 dumps: each service's name, display name, start type, type, state,
# order, its program (the image record's path for a service, the record's
# own path for a driver), the process ID of a running service and its
# account. One Service entry each (rows: Add-DbgEngServiceRows in
# lib\memory\TimelineMemoryRows.ps1, Source Memory-Services).
#
# How the list is found: services.exe is taken from the processes of the
# scan (by its image name; the one started by wininit.exe first). Its image
# base comes from its PEB (_PEB.ImageBaseAddress, from the kernel's symbols),
# or from its memory regions when the PEB is not in the dump; the image's
# own section table gives its writable data sections, and the list's first
# and last record pointers are the pair of pointers there whose records carry
# the record tag and end the list (the first record has no previous one, the
# last no next one). The list is walked forward from its first record, and
# backward from its last when the forward walk does not reach the end (a
# page a live copy left out). When neither finds it whole, services.exe's
# private read-write memory is searched for the tag, and every record whose
# neighbours link back to it is added (FoundBy=MemoryScan); a record whose
# neighbours do not link back to it is a stale copy and is left out.
#
# The record layout is not in any symbol file. These are the offsets
# MemProcFS publishes for the 64-bit service control manager of Windows 11
# build 26100 and later (its vmmwinsvc.c; facts only, no code taken), and
# were checked on three Windows 11 26100 ARM64 dumps (615 records each, the
# list walked whole): record tag 'Sc19' at +0x08, previous record +0x10, next
# record +0x18, order +0x20, start type +0x24, name +0x38, display name +0x40,
# SERVICE_STATUS +0x50 (type +0x50, state +0x54), extra information +0x150 --
# for a driver its path, for a service its image record (tag 'Sc16' at
# +0x08, path +0x18, process ID +0x28, account +0x58). A self-check decides
# whether a dump has this layout (the states, start types, types and names
# of nine in ten records must be plausible): a dump that fails it is "not
# read", never given rows from a layout it does not have.
#
# The registry in memory (the Registry area runs before this one): when it
# offers the SYSTEM hive's Services key ($Context.Shared["RegistryServices"],
# any object with Complete and Keys -- name to an object with ImagePath,
# ServiceDll, ObjectName, DisplayName, Start and Type -- or a
# TimelineDbgEng.ServiceRegistryView), each record is joined with its key:
# RegistryBinary (the key's ImagePath), Dll (Parameters\ServiceDll), the
# account when the record has none, and FoundBy ScmList,Registry; a service
# that is not stopped and has no key while the Services key was read in full
# gets Anomaly=NoRegistryKey. Without it, these fields are not written. When
# the list is not found but the Services key is, the services come from the
# key alone (FoundBy=Registry) and the area is partly read.
#
# Offered to the joins: $Context.Shared["ServiceRecords"] (the records, a
# List of TimelineDbgEng.ServiceRecord).
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies), C# 5
function Get-DbgEngServicesSource {
    return @'
namespace TimelineDbgEng
{
    // One service record of the service control manager, with what the
    // rows need
    public sealed class ServiceRecord
    {
        public ulong Address;              // the record in services.exe's memory
        public long Order;
        public uint StartType;
        public uint ServiceType;
        public uint State;
        public string Name;                // null when not in the dump
        public string Display;
        public string Binary = "";         // the image record's path (a service), the record's own (a driver)
        public long Pid;                   // the image record's process ID (0: none)
        public string Account = "";        // the image record's account, else the registry's
        public bool HasImageRecord;
        public string FoundBy = "ScmList";
        public string User = "";           // the token user of the host process (ProcessDetails)
        public bool InRegistry;
        public string RegistryBinary;      // the Services key's ImagePath (null: not joined or none)
        public string ServiceDll;
        public readonly List<string> Anomalies = new List<string>();
        internal ulong Back;
        internal ulong Next;

        // SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_ADAPTER,
        // SERVICE_RECOGNIZER_DRIVER; a service of its own or shared (also a
        // per-user service)
        public bool IsDriver { get { return (ServiceType & 0x0F) != 0 && (ServiceType & 0x30) == 0; } }
        public bool IsService { get { return (ServiceType & 0x30) != 0; } }
        public bool IsStopped { get { return State == 1; } }
        public bool IsRunning { get { return State == 4; } }

        static readonly string[] States = new string[] { "", "SERVICE_STOPPED", "SERVICE_START_PENDING", "SERVICE_STOP_PENDING", "SERVICE_RUNNING",
            "SERVICE_CONTINUE_PENDING", "SERVICE_PAUSE_PENDING", "SERVICE_PAUSED" };
        static readonly string[] Starts = new string[] { "SERVICE_BOOT_START", "SERVICE_SYSTEM_START", "SERVICE_AUTO_START", "SERVICE_DEMAND_START", "SERVICE_DISABLED" };
        static readonly string[] Types = new string[] { "SERVICE_KERNEL_DRIVER", "SERVICE_FILE_SYSTEM_DRIVER", "SERVICE_ADAPTER", "SERVICE_RECOGNIZER_DRIVER",
            "SERVICE_WIN32_OWN_PROCESS", "SERVICE_WIN32_SHARE_PROCESS", "SERVICE_USER_SERVICE", "SERVICE_USERSERVICE_INSTANCE", "SERVICE_INTERACTIVE_PROCESS", "SERVICE_PKG_SERVICE" };

        public static string StateText(long state)
        {
            if (state >= 1 && state < States.Length) return States[state];
            return state < 0 ? "" : state.ToString(CultureInfo.InvariantCulture);
        }
        public static string StartText(long start)
        {
            if (start >= 0 && start < Starts.Length) return Starts[start];
            return start < 0 ? "" : start.ToString(CultureInfo.InvariantCulture);
        }
        // The type's flags by name, comma-separated (a flag without a name in hex)
        public static string TypeText(long type)
        {
            if (type < 0) return "";
            List<string> names = new List<string>();
            ulong rest = (ulong)type;
            for (int bit = 0; bit < Types.Length; bit++)
            {
                ulong flag = 1UL << bit;
                if ((rest & flag) != 0) { names.Add(Types[bit]); rest &= ~flag; }
            }
            if (rest != 0) names.Add(Fmt.Hex(rest));
            return string.Join(",", names.ToArray());
        }
        // Plausible for the record layout: a known state, start type and
        // type, and a name
        public bool Plausible
        {
            get { return State >= 1 && State <= 7 && StartType <= 4 && ServiceType != 0 && (ServiceType & ~0x3FFu) == 0 && !string.IsNullOrEmpty(Name); }
        }
    }

    // One key of SYSTEM\<control set>\Services as the Registry area read it
    public sealed class ServiceRegistryKey
    {
        public string Name = "";
        public string ImagePath;           // null: not there or not in the dump
        public string ServiceDll;
        public string ObjectName;
        public string DisplayName;
        public long Start = -1;            // -1: not there or not in the dump
        public long Type = -1;
    }

    // The Services key of the registry in memory, for the join
    public sealed class ServiceRegistryView
    {
        public bool Complete;              // every subkey was read: a service missing here has no key
        public string Why = "";
        public readonly Dictionary<string, ServiceRegistryKey> Keys = new Dictionary<string, ServiceRegistryKey>(StringComparer.OrdinalIgnoreCase);

        public ServiceRegistryKey Find(string name)
        {
            ServiceRegistryKey key;
            return name != null && Keys.TryGetValue(name, out key) ? key : null;
        }

        // The view of what the Registry area offers (MemoryContext.Shared):
        // a ServiceRegistryView, or any object with the same members (read by
        // name: Complete, Keys -- a dictionary of name to an object with
        // ImagePath, ServiceDll, ObjectName, DisplayName, Start and Type --,
        // and State and Why when it has them). null, with why, when there is
        // none or it is not in that form.
        public static ServiceRegistryView From(object shared, out string problem)
        {
            problem = "";
            shared = Unwrap(shared);
            if (shared == null) { problem = "the registry in memory was not read"; return null; }
            ServiceRegistryView given = shared as ServiceRegistryView;
            if (given != null) return given;
            System.Collections.IDictionary map = Unwrap(Member(shared, "Keys")) as System.Collections.IDictionary;
            if (map == null) { problem = "the registry's Services key is not in a form this area knows"; return null; }
            string state = Member(shared, "State") as string;
            string why = Member(shared, "Why") as string;
            if (state == "NotRead") { problem = string.IsNullOrEmpty(why) ? "the registry's Services key was not read" : why; return null; }
            ServiceRegistryView view = new ServiceRegistryView();
            object complete = Member(shared, "Complete");
            view.Complete = complete is bool && (bool)complete;
            view.Why = why ?? "";
            foreach (System.Collections.DictionaryEntry pair in map)
            {
                string name = pair.Key as string;
                object value = Unwrap(pair.Value);
                if (string.IsNullOrEmpty(name) || value == null) continue;
                ServiceRegistryKey key = new ServiceRegistryKey();
                key.Name = name;
                key.ImagePath = Member(value, "ImagePath") as string;
                key.ServiceDll = Member(value, "ServiceDll") as string;
                key.ObjectName = Member(value, "ObjectName") as string;
                key.DisplayName = Member(value, "DisplayName") as string;
                key.Start = Number(Member(value, "Start"));
                key.Type = Number(Member(value, "Type"));
                view.Keys[name] = key;
            }
            return view;
        }

        static object Unwrap(object o)
        {
            if (o != null && o.GetType().FullName == "System.Management.Automation.PSObject") return Member(o, "BaseObject");
            return o;
        }
        static object Member(object o, string name)
        {
            if (o == null) return null;
            System.Type type = o.GetType();
            System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance;
            System.Reflection.FieldInfo field = type.GetField(name, flags);
            if (field != null) return field.GetValue(o);
            System.Reflection.PropertyInfo property = type.GetProperty(name, flags);
            if (property != null && property.GetIndexParameters().Length == 0) return property.GetValue(o, null);
            return null;
        }
        static long Number(object o)
        {
            if (o == null) return -1;
            try { return Convert.ToInt64(o, CultureInfo.InvariantCulture); }
            catch (FormatException) { return -1; }
            catch (InvalidCastException) { return -1; }
            catch (OverflowException) { return -1; }
        }
    }

    // The Services area: the service control manager's list in services.exe
    public sealed class ServiceScan
    {
        // The record layout (64-bit services.exe of Windows 11 build 26100
        // and later: MemProcFS's published offsets, checked on three ARM64
        // dumps of build 26100; see the file's header)
        public const uint RecordTag = 0x39316353;      // "Sc19" (bytes 53 63 31 39)
        public const uint ImageTag = 0x36316353;       // "Sc16"
        public const int RecordBytes = 0x158;
        const int RecordTagAt = 0x08, BackAt = 0x10, NextAt = 0x18, OrderAt = 0x20, StartAt = 0x24, NameAt = 0x38, DisplayAt = 0x40;
        const int TypeAt = 0x50, StateAt = 0x54, ExtraAt = 0x150;
        const int ImageBytes = 0x60, ImageTagAt = 0x00, ImagePathAt = 0x18, ImagePidAt = 0x28, ImageAccountAt = 0x58;
        public const int MaxRecords = 16384;
        public const int NameChars = 256, DisplayChars = 512, PathChars = 4096;
        public const int MaxSectionBytes = 4 << 20;
        public const long MaxScanBytes = 256L << 20;
        // MMVAD protection index of read-write memory (MM_READWRITE)
        public const int ReadWrite = 4;
        // What the Registry area offers, and what this one offers the joins
        public const string RegistryShared = "RegistryServices";
        public const string RecordsShared = "ServiceRecords";

        readonly MemoryContext context;
        readonly AreaResult area;
        readonly MemoryReader reader;
        ulong process;
        public int PebImageBaseOffset = -1;    // _PEB.ImageBaseAddress (-1: not known)
        public ProcessInfo Scm;                // the services.exe the list was found in
        public List<ServiceRecord> Records = new List<ServiceRecord>();
        public bool ListFound;                 // the list's ends were found in services.exe's data
        public bool ListComplete;              // the records read make one whole list
        public bool WantsRegions;              // the memory regions would find more (no VAD walker was given)
        public bool RegionsScanned;
        public string Why = "";
        public string RegistryProblem = "";
        public bool RegistryComplete;
        // Counts for the log
        public int Candidates, ImageBases, ListEnds, Forward, Backward, Scanned, ScanHits, StaleHits, LinkMismatches, UnreadableRecords;
        public int ImageRecords, ImageRecordsUntagged, NamesUnreadable, Plausible;
        public long ScanBytes;

        public ServiceScan(MemoryContext context, AreaResult area)
        {
            if (context == null) throw new ArgumentNullException("context");
            if (area == null) throw new ArgumentNullException("area");
            this.context = context;
            this.area = area;
            reader = context.Reader;
        }

        // The services.exe processes of the scan that have not exited: the
        // one started by wininit.exe first, then by create time
        public List<ProcessInfo> FindCandidates()
        {
            List<ProcessInfo> found = new List<ProcessInfo>();
            foreach (ProcessInfo p in context.Processes)
            {
                if (p.ExitTime != 0 || !string.Equals(p.ShortName, "services.exe", StringComparison.OrdinalIgnoreCase)) continue;
                found.Add(p);
            }
            found.Sort(delegate(ProcessInfo a, ProcessInfo b)
            {
                int pa = FromWininit(a) ? 0 : 1, pb = FromWininit(b) ? 0 : 1;
                if (pa != pb) return pa.CompareTo(pb);
                return a.CreateTime.CompareTo(b.CreateTime);
            });
            return found;
        }

        bool FromWininit(ProcessInfo p)
        {
            foreach (ProcessInfo parent in context.WithPid(p.Ppid))
            {
                if (string.Equals(parent.ShortName, "wininit.exe", StringComparison.OrdinalIgnoreCase) && parent.CreateTime <= p.CreateTime) return true;
            }
            return false;
        }

        // Finds and reads the list (again from the start on each call):
        // walker (may be null) gives services.exe's memory regions, for its
        // image base when the PEB is not in the dump and for the search of
        // its memory when the list is not found whole. True when records
        // were read.
        public bool Read(VadWalker walker)
        {
            Records = new List<ServiceRecord>();
            Scm = null;
            ListFound = ListComplete = WantsRegions = RegionsScanned = false;
            Why = "";
            Candidates = ImageBases = ListEnds = Forward = Backward = Scanned = ScanHits = StaleHits = LinkMismatches = UnreadableRecords = 0;
            ImageRecords = ImageRecordsUntagged = NamesUnreadable = 0;
            ScanBytes = 0;
            bool regions = walker != null && walker.Ready;
            List<ProcessInfo> candidates = FindCandidates();
            Candidates = candidates.Count;
            if (Candidates == 0) { Why = "services.exe is not among the processes"; return false; }
            bool anyReadable = false;
            foreach (ProcessInfo p in candidates)
            {
                if (area.TimeUp()) break;
                process = p.Eprocess;
                ulong imageBase = ImageBase(p, regions ? walker : null);
                bool readable = !reader.IsUnreadableProcess(p.Eprocess);
                if (readable) anyReadable = true;
                if (imageBase == 0) { if (!regions && readable) WantsRegions = true; continue; }
                ImageBases++;
                Dictionary<ulong, ServiceRecord> best = null;
                List<ServiceRecord> bestOrder = null;
                foreach (ulong[] ends in FindListEnds(imageBase))
                {
                    Dictionary<ulong, ServiceRecord> seen = new Dictionary<ulong, ServiceRecord>();
                    List<ServiceRecord> order = new List<ServiceRecord>();
                    int forward, backward;
                    WalkFromEnds(ends[0], ends[1], seen, order, out forward, out backward);
                    if (best == null || order.Count > bestOrder.Count) { best = seen; bestOrder = order; Forward = forward; Backward = backward; }
                }
                if (best != null && bestOrder.Count > 0)
                {
                    ListFound = true;
                    Scm = p;
                    ListComplete = IsWholeList(best);
                    if (!ListComplete)
                    {
                        if (regions) ScanRegions(p, walker, best, bestOrder);
                        else if (!reader.IsUnreadableProcess(p.Eprocess)) WantsRegions = true;
                        ListComplete = IsWholeList(best);
                    }
                    Records = InListOrder(best, bestOrder);
                    return true;
                }
                if (regions)
                {
                    Dictionary<ulong, ServiceRecord> seen = new Dictionary<ulong, ServiceRecord>();
                    List<ServiceRecord> order = new List<ServiceRecord>();
                    ScanRegions(p, walker, seen, order);
                    if (order.Count > 0)
                    {
                        Scm = p;
                        ListComplete = IsWholeList(seen);
                        Records = InListOrder(seen, order);
                        return true;
                    }
                }
                else if (!reader.IsUnreadableProcess(p.Eprocess)) WantsRegions = true;
            }
            if (area.Deadline.Expired) Why = "it stopped at its time limit of " + area.Deadline.Seconds.ToString("0", CultureInfo.InvariantCulture) + " s";
            else if (!anyReadable) Why = "the memory of services.exe is not in the dump";
            else if (ImageBases == 0) Why = "the program image of services.exe is not in the dump";
            else Why = "the service control manager's list was not found in the memory of services.exe";
            return false;
        }

        // services.exe's image base: from its PEB, else its memory region of
        // services.exe
        ulong ImageBase(ProcessInfo p, VadWalker walker)
        {
            ulong value;
            if (PebImageBaseOffset >= 0 && MemoryReader.IsUserAddress(p.Peb) &&
                reader.TryU64(p.Eprocess, p.Peb + (ulong)PebImageBaseOffset, out value) && MemoryReader.IsUserAddress(value) && (value & 0xFFFF) == 0) return value;
            if (walker == null) return 0;
            VadWalk walk = walker.Walk(p);
            foreach (VadNode node in walk.Nodes)
            {
                if (!node.IsImage) continue;
                string file = walker.FileName(node);
                if (file != null && file.EndsWith("\\services.exe", StringComparison.OrdinalIgnoreCase)) return node.Start;
            }
            return 0;
        }

        // The pairs of pointers in the image's writable data sections (.data
        // first) that are the list's first and last records: both carry the
        // record tag, the first has no previous record and the last no next
        public List<ulong[]> FindListEnds(ulong imageBase)
        {
            List<ulong[]> pairs = new List<ulong[]>();
            byte[] head = reader.Read(process, imageBase, 0x1000);
            if (head == null || head.Length < 0x200 || Bytes.U16(head, 0) != 0x5A4D) return pairs;
            int pe = (int)Bytes.U32(head, 0x3C);
            if (pe <= 0 || pe > 0xE00 || Bytes.U32(head, pe) != 0x00004550) return pairs;
            int sectionCount = Bytes.U16(head, pe + 6);
            int table = pe + 24 + Bytes.U16(head, pe + 20);
            List<uint[]> sections = new List<uint[]>();
            for (int i = 0; i < sectionCount && i < 96; i++)
            {
                int at = table + 40 * i;
                if (!Bytes.Has(head, at, 40)) break;
                uint size = Bytes.U32(head, at + 8), rva = Bytes.U32(head, at + 12), flags = Bytes.U32(head, at + 36);
                bool writable = (flags & 0x80000000u) != 0, executable = (flags & 0x20000000u) != 0;
                if (!writable || executable || size == 0) continue;
                uint[] section = new uint[] { rva, (uint)Math.Min(size, (uint)MaxSectionBytes) };
                if (Bytes.Utf8Z(head, at, 8) == ".data") sections.Insert(0, section); else sections.Add(section);
            }
            HashSet<string> known = new HashSet<string>(StringComparer.Ordinal);
            foreach (uint[] section in sections)
            {
                ulong start = imageBase + section[0];
                int length = (int)section[1];
                byte[] data = new byte[length];
                // Per 8 bytes: read (a page a live copy left out is not)
                bool[] readable = new bool[length / 8 + 1];
                int offset = 0;
                while (offset < length)
                {
                    ulong at = start + (ulong)offset;
                    int want = (int)Math.Min(0x1000UL - (at & 0xFFF), (ulong)(length - offset));
                    byte[] part = reader.Read(process, at, want);
                    if (part != null && part.Length == want)
                    {
                        Buffer.BlockCopy(part, 0, data, offset, want);
                        for (int q = (offset + 7) / 8; q * 8 + 8 <= offset + want; q++) readable[q] = true;
                    }
                    offset += want;
                }
                for (int i = 0; i + 16 <= length; i += 8)
                {
                    if (!readable[i / 8] || !readable[i / 8 + 1]) continue;
                    ulong first = Bytes.U64(data, i), last = Bytes.U64(data, i + 8);
                    if (!Pointer(first) || !Pointer(last)) continue;
                    if (!Tagged(first, RecordTagAt, RecordTag) || !Tagged(last, RecordTagAt, RecordTag)) continue;
                    ulong back, next;
                    if (!reader.TryU64(process, first + BackAt, out back) || back != 0) continue;
                    if (!reader.TryU64(process, last + NextAt, out next) || next != 0) continue;
                    string key = first.ToString("x") + "/" + last.ToString("x");
                    if (!known.Add(key)) continue;
                    pairs.Add(new ulong[] { first, last });
                    ListEnds++;
                    if (pairs.Count >= 8) return pairs;
                }
            }
            return pairs;
        }

        static bool Pointer(ulong address) { return MemoryReader.IsUserAddress(address) && (address & 7) == 0; }

        bool Tagged(ulong address, int at, uint tag)
        {
            uint value;
            return reader.TryU32(process, address + (ulong)at, out value) && value == tag;
        }

        // Forward from the first record to a record without a next one,
        // and, when that does not end at the last record, backward from the
        // last until a record already read (the two walks meet) or one
        // without a previous record
        void WalkFromEnds(ulong first, ulong last, Dictionary<ulong, ServiceRecord> seen, List<ServiceRecord> order, out int forward, out int backward)
        {
            forward = backward = 0;
            ulong at = first, previous = 0;
            bool reachedEnd = false;
            while (true)
            {
                if (at == 0) { reachedEnd = true; break; }
                if (seen.ContainsKey(at) || seen.Count >= MaxRecords || !Pointer(at)) break;
                ServiceRecord r = ReadRecord(at);
                if (r == null) break;
                if (r.Back != previous) LinkMismatches++;
                seen[at] = r;
                order.Add(r);
                forward++;
                previous = at;
                at = r.Next;
                if ((seen.Count & 63) == 0 && area.TimeUp()) return;
            }
            if (reachedEnd && previous == last) return;
            List<ServiceRecord> tail = new List<ServiceRecord>();
            ulong later = 0;
            at = last;
            while (at != 0 && !seen.ContainsKey(at) && seen.Count < MaxRecords && Pointer(at))
            {
                ServiceRecord r = ReadRecord(at);
                if (r == null) break;
                if (r.Next != later) LinkMismatches++;
                seen[at] = r;
                tail.Add(r);
                backward++;
                later = at;
                at = r.Back;
                if ((seen.Count & 63) == 0 && area.TimeUp()) break;
            }
            tail.Reverse();
            order.AddRange(tail);
        }

        // One record at address (null when it is not in the dump or has no tag)
        ServiceRecord ReadRecord(ulong address)
        {
            byte[] b;
            if (!reader.TryRead(process, address, RecordBytes, out b)) { UnreadableRecords++; return null; }
            if (Bytes.U32(b, RecordTagAt) != RecordTag) return null;
            ServiceRecord r = new ServiceRecord();
            r.Address = address;
            r.Back = Bytes.U64(b, BackAt);
            r.Next = Bytes.U64(b, NextAt);
            r.Order = Bytes.U32(b, OrderAt);
            r.StartType = Bytes.U32(b, StartAt);
            r.ServiceType = Bytes.U32(b, TypeAt);
            r.State = Bytes.U32(b, StateAt);
            r.Name = WideZ(Bytes.U64(b, NameAt), NameChars);
            r.Display = WideZ(Bytes.U64(b, DisplayAt), DisplayChars);
            if (r.Name == null) NamesUnreadable++;
            ulong extra = Bytes.U64(b, ExtraAt);
            if (extra != 0 && Pointer(extra))
            {
                if (r.IsDriver) r.Binary = WideZ(extra, PathChars) ?? "";
                else if (r.IsService) ReadImageRecord(r, extra);
            }
            return r;
        }

        void ReadImageRecord(ServiceRecord r, ulong address)
        {
            byte[] b;
            if (!reader.TryRead(process, address, ImageBytes, out b)) return;
            if (Bytes.U32(b, ImageTagAt) != ImageTag) { ImageRecordsUntagged++; return; }
            ImageRecords++;
            r.HasImageRecord = true;
            r.Binary = WideZ(Bytes.U64(b, ImagePathAt), PathChars) ?? "";
            r.Pid = Bytes.U32(b, ImagePidAt);
            r.Account = WideZ(Bytes.U64(b, ImageAccountAt), NameChars) ?? "";
        }

        // A NUL-terminated UTF-16 string at address (at most maxChars):
        // "" for a null pointer, null when it is not in the dump
        string WideZ(ulong address, int maxChars)
        {
            if (address == 0) return "";
            if (!MemoryReader.IsUserAddress(address) || (address & 1) != 0) return null;
            StringBuilder text = new StringBuilder();
            ulong at = address;
            int left = maxChars * 2;
            while (left > 0)
            {
                int want = (int)Math.Min((ulong)left, 0x1000UL - (at & 0xFFF));
                byte[] b = reader.Read(process, at, want);
                if (b == null || b.Length < want) return null;
                for (int i = 0; i + 1 < b.Length; i += 2)
                {
                    char c = (char)(b[i] | (b[i + 1] << 8));
                    if (c == '\0') return text.ToString();
                    text.Append(c);
                }
                at += (ulong)want;
                left -= want;
            }
            return text.ToString();
        }

        // services.exe's private read-write memory searched for the record
        // tag: each record whose neighbours link back to it is added, with
        // the records linked to it the same way (FoundBy=MemoryScan)
        void ScanRegions(ProcessInfo p, VadWalker walker, Dictionary<ulong, ServiceRecord> seen, List<ServiceRecord> order)
        {
            RegionsScanned = true;
            List<ulong> hits = new List<ulong>();
            VadWalk walk = walker.Walk(p);
            foreach (VadNode node in walk.Nodes)
            {
                if (!node.PrivateMemory || node.IsImage || (node.Protection & 7) != ReadWrite) continue;
                for (ulong page = node.Start; page < node.End && ScanBytes < MaxScanBytes; page += 0x1000)
                {
                    ScanBytes += 0x1000;
                    if ((ScanBytes & 0xFFFFF) == 0 && area.TimeUp()) return;
                    byte[] b = reader.Read(process, page, 0x1000);
                    if (b == null || b.Length < 0x1000) continue;
                    for (int o = 0; o <= 0x1000 - RecordTagAt - 4; o += 8)
                    {
                        if (Bytes.U32(b, o + RecordTagAt) == RecordTag) hits.Add(page + (ulong)o);
                    }
                }
            }
            ScanHits = hits.Count;
            foreach (ulong hit in hits)
            {
                if (seen.ContainsKey(hit) || seen.Count >= MaxRecords) continue;
                ServiceRecord r = ReadRecord(hit);
                if (r == null) continue;
                if (!LinkedBack(r)) { StaleHits++; continue; }
                AddScanned(r, seen, order);
                // Its neighbours, as long as they link back
                ServiceRecord current = r;
                while (current.Next != 0 && !seen.ContainsKey(current.Next) && seen.Count < MaxRecords)
                {
                    ServiceRecord next = ReadRecord(current.Next);
                    if (next == null || next.Back != current.Address) break;
                    AddScanned(next, seen, order);
                    current = next;
                }
                current = r;
                while (current.Back != 0 && !seen.ContainsKey(current.Back) && seen.Count < MaxRecords)
                {
                    ServiceRecord back = ReadRecord(current.Back);
                    if (back == null || back.Next != current.Address) break;
                    AddScanned(back, seen, order);
                    current = back;
                }
                if (area.TimeUp()) return;
            }
        }

        void AddScanned(ServiceRecord r, Dictionary<ulong, ServiceRecord> seen, List<ServiceRecord> order)
        {
            r.FoundBy = "MemoryScan";
            seen[r.Address] = r;
            order.Add(r);
            Scanned++;
        }

        // A record found by the search is one of the list when a neighbour
        // links back to it (a record alone in the list has none)
        bool LinkedBack(ServiceRecord r)
        {
            if (!Pointer(r.Next) && r.Next != 0) return false;
            if (!Pointer(r.Back) && r.Back != 0) return false;
            bool confirmed = false;
            if (r.Next != 0)
            {
                ulong back;
                if (Tagged(r.Next, RecordTagAt, RecordTag) && reader.TryU64(process, r.Next + BackAt, out back))
                {
                    if (back != r.Address) return false;
                    confirmed = true;
                }
            }
            if (r.Back != 0)
            {
                ulong next;
                if (Tagged(r.Back, RecordTagAt, RecordTag) && reader.TryU64(process, r.Back + NextAt, out next))
                {
                    if (next != r.Address) return false;
                    confirmed = true;
                }
            }
            return confirmed || (r.Next == 0 && r.Back == 0);
        }

        // One whole list: one first record, one last, and every next record read
        static bool IsWholeList(Dictionary<ulong, ServiceRecord> records)
        {
            if (records.Count == 0) return false;
            int firsts = 0, lasts = 0;
            foreach (ServiceRecord r in records.Values)
            {
                if (r.Back == 0) firsts++;
                if (r.Next == 0) lasts++;
                else if (!records.ContainsKey(r.Next)) return false;
                if (r.Back != 0 && !records.ContainsKey(r.Back)) return false;
            }
            return firsts == 1 && lasts == 1;
        }

        // The records in list order: from the first record along the next
        // links, then any not reached that way in the order found
        static List<ServiceRecord> InListOrder(Dictionary<ulong, ServiceRecord> records, List<ServiceRecord> found)
        {
            List<ServiceRecord> ordered = new List<ServiceRecord>();
            HashSet<ulong> placed = new HashSet<ulong>();
            foreach (ServiceRecord start in found)
            {
                if (start.Back != 0 && records.ContainsKey(start.Back)) continue;
                ServiceRecord r = start;
                while (r != null && placed.Add(r.Address))
                {
                    ordered.Add(r);
                    ServiceRecord next;
                    r = r.Next != 0 && records.TryGetValue(r.Next, out next) ? next : null;
                }
            }
            foreach (ServiceRecord r in found) { if (placed.Add(r.Address)) ordered.Add(r); }
            return ordered;
        }

        // The checks, the joins and the entries: after Read
        public void Finish()
        {
            if (Records.Count > 0)
            {
                Plausible = 0;
                foreach (ServiceRecord r in Records) { if (r.Plausible) Plausible++; }
                // Nine in ten records plausible, else this is not the layout
                if (Plausible * 10 < Records.Count * 9)
                {
                    area.Coverage.Count("service records", Records.Count);
                    area.Coverage.Count("plausible", Plausible);
                    Records = new List<ServiceRecord>();
                    Why = "the service records are not in the layout this helper knows for Windows 11 build 26100";
                }
            }
            object shared;
            context.Shared.TryGetValue(RegistryShared, out shared);
            string problem;
            ServiceRegistryView registry = ServiceRegistryView.From(shared, out problem);
            RegistryProblem = problem;
            RegistryComplete = registry != null && registry.Complete;
            if (Records.Count == 0)
            {
                if (registry != null && registry.Keys.Count > 0)
                {
                    FromRegistry(registry);
                    area.SetPartial("the service control manager's list was not read, " + Why + ", so the services come from the registry in memory alone");
                    return;
                }
                area.SetNotRead(Why.Length > 0 ? Why : "no service record was found");
                return;
            }
            context.Shared[RecordsShared] = Records;
            int running = 0, hosts = 0, hostsNotListed = 0, joined = 0, noKey = 0, drivers = 0, driverPaths = 0, accounts = 0;
            foreach (ServiceRecord r in Records)
            {
                if (r.IsRunning) running++;
                if (r.IsDriver) { drivers++; if (r.Binary.Length > 0) driverPaths++; }
                if (r.Account.Length > 0) accounts++;
                if (r.Pid > 0 && !r.IsStopped)
                {
                    hosts++;
                    ProcessInfo host = Host(r.Pid);
                    if (host == null) { r.Anomalies.Add("HostNotListed"); hostsNotListed++; }
                    else if (!string.IsNullOrEmpty(host.UserSid)) r.User = host.UserSid;
                }
                if (registry == null) continue;
                ServiceRegistryKey key = registry.Find(r.Name);
                if (key != null)
                {
                    joined++;
                    r.InRegistry = true;
                    r.FoundBy += ",Registry";
                    r.RegistryBinary = key.ImagePath;
                    r.ServiceDll = key.ServiceDll;
                    if (r.Account.Length == 0 && !string.IsNullOrEmpty(key.ObjectName)) r.Account = key.ObjectName;
                }
                else if (registry.Complete && !r.IsStopped && !string.IsNullOrEmpty(r.Name)) { r.Anomalies.Add("NoRegistryKey"); noKey++; }
            }
            area.Coverage.Count("service records", Records.Count);
            area.Coverage.Count("walked forward", Forward);
            if (Backward > 0) area.Coverage.Count("walked backward", Backward);
            if (RegionsScanned) { area.Coverage.Count("found by a search of services.exe's memory", Scanned); area.Coverage.Count("stale copies left out", StaleHits); }
            area.Coverage.Count("running", running);
            area.Coverage.Count("drivers", drivers);
            area.Coverage.Count("driver paths", driverPaths);
            area.Coverage.Count("image records", ImageRecords);
            if (ImageRecordsUntagged > 0) area.Coverage.Count("image records without their tag", ImageRecordsUntagged);
            area.Coverage.Count("host process IDs", hosts);
            area.Coverage.Count("hosts not in the process list", hostsNotListed);
            area.Coverage.Count("accounts", accounts);
            if (NamesUnreadable > 0) area.Coverage.Count("names not in the dump", NamesUnreadable);
            if (LinkMismatches > 0) area.Coverage.Count("links that do not agree", LinkMismatches);
            if (registry != null)
            {
                area.Coverage.Count("joined with the registry in memory", joined);
                area.Coverage.Count("not in the registry's Services key", noKey);
            }
            if (!ListComplete)
            {
                area.SetPartial("the service control manager's list was read in part, " + Records.Count.ToString(CultureInfo.InvariantCulture) +
                    " records, as when a live copy leaves part of the memory of services.exe out");
            }
            if (registry != null && !registry.Complete)
            {
                area.Coverage.Note("the registry's Services key in memory was not read in full, so a service without a key there is not marked");
            }
            foreach (ServiceRecord r in Records) Add(r);
        }

        // The process of a running service's process ID: one that has not
        // exited first
        ProcessInfo Host(long pid)
        {
            ProcessInfo any = null;
            foreach (ProcessInfo p in context.WithPid(pid))
            {
                if (p.ExitTime == 0) return p;
                if (any == null) any = p;
            }
            return any;
        }

        void Add(ServiceRecord r)
        {
            MemoryEntry e = area.Add("Service");
            e.SetHex("Offset", r.Address);
            e.Set("Order", r.Order);
            if (r.Pid > 0 && !r.IsStopped) e.Set("PID", r.Pid);
            e.Set("Start", ServiceRecord.StartText(r.StartType));
            e.Set("State", ServiceRecord.StateText(r.State));
            e.Set("Type", ServiceRecord.TypeText(r.ServiceType));
            e.Set("Name", r.Name ?? "");
            e.Set("Display", r.Display ?? "");
            e.Set("Binary", r.Binary);
            if (r.RegistryBinary != null) e.Set("RegistryBinary", r.RegistryBinary);
            if (r.ServiceDll != null) e.Set("Dll", r.ServiceDll);
            if (r.Account.Length > 0) e.Set("Account", r.Account);
            e.Set("FoundBy", r.FoundBy);
            if (r.Anomalies.Count > 0) e.Set("Anomaly", string.Join(",", r.Anomalies.ToArray()));
            if (r.User.Length > 0) e.Set("User", r.User);
        }

        // The services of the registry's Services key alone (the list was
        // not read): FoundBy=Registry, without state or process
        void FromRegistry(ServiceRegistryView registry)
        {
            List<string> names = new List<string>(registry.Keys.Keys);
            names.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (string name in names)
            {
                ServiceRegistryKey key = registry.Keys[name];
                MemoryEntry e = area.Add("Service");
                e.Set("Start", ServiceRecord.StartText(key.Start));
                e.Set("Type", ServiceRecord.TypeText(key.Type));
                e.Set("Name", key.Name);
                e.Set("Display", key.DisplayName ?? "");
                if (key.ImagePath != null) e.Set("RegistryBinary", key.ImagePath);
                if (key.ServiceDll != null) e.Set("Dll", key.ServiceDll);
                if (!string.IsNullOrEmpty(key.ObjectName)) e.Set("Account", key.ObjectName);
                e.Set("FoundBy", "Registry");
            }
            area.Coverage.Count("services from the registry in memory", names.Count);
        }
    }
}
'@
}

# The area: services.exe's service records (see the file's header). Its C#
# does the reading; this only gives it the PEB's layout and, when the list
# needs them, services.exe's memory regions (the VAD walker, made here only
# then unless an earlier area made it).
function Invoke-DbgEngServicesArea {
    param($Context, $Area)
    $scan = New-Object TimelineDbgEng.ServiceScan -ArgumentList $Context, $Area
    if ($scan.FindCandidates().Count -gt 0) {
        $layout = New-DbgEngLayout -Session $Context.Session -Spec @{ "_PEB" = @{ ImageBaseAddress = '^Ptr64\b' } }
        $scan.PebImageBaseOffset = $layout.Off("_PEB.ImageBaseAddress")
        $walker = $null
        if ($Context.Shared.ContainsKey("VadWalker")) { $walker = $Context.Shared["VadWalker"] }
        [void]$scan.Read($walker)
        if ($scan.WantsRegions -and $null -eq $walker) {
            $walker = Get-DbgEngVadWalker -Context $Context
            if ($walker.Ready) { [void]$scan.Read($walker) }
            else { $Area.Coverage.Note("services.exe's memory regions could not be read, the kernel's symbols do not describe them") }
        }
    }
    else { [void]$scan.Read($null) }
    $scan.Finish()
}
