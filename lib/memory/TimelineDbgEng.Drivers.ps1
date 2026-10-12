# =============================================================
# Windows ARM64 memory dumps: kernel drivers, hidden ones included, and recently unloaded drivers (item d)
# Part of win11-timeline-builder (work package WP3). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract) and on TimelineDbgEng.Objects.ps1.
#
# What it reads (offsets from the kernel's symbol file, 'dt'):
#   loaded modules      the kernel's module list (nt!PsLoadedModuleList of
#                       _KLDR_DATA_TABLE_ENTRY: DllBase, SizeOfImage,
#                       FullDllName, BaseDllName), walked forwards and
#                       backwards (a link whose way back disagrees is
#                       counted, as a live copy can leave one)
#   driver objects      every _DRIVER_OBJECT of the object directories
#                       \Driver and \FileSystem: its DriverSection is the
#                       module list entry of its driver
#   hidden drivers      a driver object whose DriverSection is in neither
#                       walk and whose code is in no listed module: a driver
#                       unlinked from the module list (Anomaly=NotInModuleList).
#                       Judged one way only (modules without a driver object,
#                       such as the kernel, hal and libraries, are never
#                       flagged), only when a walk reached the list's end,
#                       and not when an unload record (below) covers its
#                       address with an unload time at or after the capture
#                       start less the process scan's churn margin: a driver
#                       unloaded while memory was copied (counted and noted)
#   unloaded drivers    nt!MmUnloadedDrivers, the kernel's record of the last
#                       50 drivers unloaded (name, address range, unload time),
#                       at the offsets of _UNLOADED_DRIVERS when the symbols
#                       describe it, else at the record's long-standing layout
#                       (DriverListScan.UnloadedLayout), each slot checked
# Entries: Driver (State Loaded or Unloaded; rows: Add-DbgEngDriverRows in
# lib\memory\TimelineMemoryRows.ps1, Source Memory-Drivers).
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngDriversSource {
    return @'
namespace TimelineDbgEng
{
    // One kernel module: from the module list, or a driver object's module
    // missing from it
    public sealed class KernelModuleRecord
    {
        public ulong Entry;              // its _KLDR_DATA_TABLE_ENTRY
        public ulong Base;
        public ulong Size;
        public string Name = "";         // BaseDllName
        public string FullName = "";     // FullDllName as the kernel has it
        public bool Forward;             // found by the forward walk
        public bool Backward;            // found by the backward walk
        public bool FromDriverObject;    // found through a driver object only
        public bool Hidden;              // Anomaly=NotInModuleList
        public readonly List<string> DriverObjects = new List<string>();
    }

    // A walk of the kernel's module list one way
    public sealed class KernelModuleWalk
    {
        public readonly List<ulong> Entries = new List<ulong>();
        public bool Complete;            // reached the list head again
        public int Mismatches;           // entries whose link back is not the entry before
        public string Stop = "";         // where it stopped early (a noun phrase)
    }

    // The drivers area: the module list both ways, the driver objects, the
    // hidden ones, the unloaded drivers; its entries go to an AreaResult
    public sealed class DriverListScan
    {
        public static readonly string[] Fields = new string[] {
            "_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks", "_KLDR_DATA_TABLE_ENTRY.DllBase", "_KLDR_DATA_TABLE_ENTRY.SizeOfImage",
            "_KLDR_DATA_TABLE_ENTRY.FullDllName", "_KLDR_DATA_TABLE_ENTRY.BaseDllName",
            "_DRIVER_OBJECT.DriverStart", "_DRIVER_OBJECT.DriverSize", "_DRIVER_OBJECT.DriverSection", "_DRIVER_OBJECT.DriverName" };
        public const int MaxModules = 4096;
        // The kernel keeps the last 50 unloaded drivers (MI_UNLOADED_DRIVERS
        // in the memory manager's mi.h of the Windows Research Kernel; the
        // same count on Windows 10 and 11)
        public const int UnloadedSlots = 50;
        // _UNLOADED_DRIVERS when the kernel's symbols do not describe it (the
        // 24H2 ARM64 symbols do not): Name (UNICODE_STRING) +0x0,
        // StartAddress +0x10, EndAddress +0x18, CurrentTime +0x20, 0x28 bytes
        // (mi.h of the Windows Research Kernel, unchanged since; the layout
        // Volatility 3's windows.unloadedmodules reads). Every slot is
        // checked before it is used.
        public static readonly int[] UnloadedLayout = new int[] { 0x0, 0x10, 0x18, 0x20, 0x28 };
        // The longest address range a driver plausibly has
        const ulong MaxDriverSize = 0x40000000;
        // A FILETIME of 2000-01-01: no driver was unloaded before
        const long Year2000 = 125911584000000000L;
        // Ten years in 100 ns units: the longest time since boot
        const long MaxSinceBoot = 3155760000000000L;

        readonly MemoryContext context;
        readonly MemoryReader reader;
        readonly Layout layout;
        readonly KernelObjectReader objects;
        readonly int[] unloaded;
        readonly int links, dllBase, sizeOfImage, fullName, baseName, entryBytes;
        readonly int driverStart, driverSize, driverSection, driverName, driverBytes;

        public readonly List<KernelModuleRecord> Modules = new List<KernelModuleRecord>();
        public KernelModuleWalk ForwardWalk, BackwardWalk;
        public int DriverObjects, DriverObjectsWithoutModule, DriverObjectsUnreadable, StaleSections, NotJudged, UnreadableNames;
        public int UnloadedRead, UnloadedRejected;

        // unloadedOffsets: Name, StartAddress, EndAddress, CurrentTime and
        // the record's size (UnloadedLayout when the symbols lack the type)
        public DriverListScan(MemoryContext context, Layout layout, KernelObjectReader objects, int[] unloadedOffsets)
        {
            this.context = context;
            this.reader = context.Reader;
            this.layout = layout;
            this.objects = objects;
            unloaded = (unloadedOffsets != null && unloadedOffsets.Length == 5) ? unloadedOffsets : UnloadedLayout;
            links = layout.Off("_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks");
            dllBase = layout.Off("_KLDR_DATA_TABLE_ENTRY.DllBase");
            sizeOfImage = layout.Off("_KLDR_DATA_TABLE_ENTRY.SizeOfImage");
            fullName = layout.Off("_KLDR_DATA_TABLE_ENTRY.FullDllName");
            baseName = layout.Off("_KLDR_DATA_TABLE_ENTRY.BaseDllName");
            entryBytes = Math.Max(layout.Size("_KLDR_DATA_TABLE_ENTRY"), Math.Max(fullName, baseName) + 16);
            driverStart = layout.Off("_DRIVER_OBJECT.DriverStart");
            driverSize = layout.Off("_DRIVER_OBJECT.DriverSize");
            driverSection = layout.Off("_DRIVER_OBJECT.DriverSection");
            driverName = layout.Off("_DRIVER_OBJECT.DriverName");
            driverBytes = Math.Max(layout.Size("_DRIVER_OBJECT"), Math.Max(Math.Max(driverStart, driverSection) + 8, driverName + 16));
        }

        public string MissingFields
        {
            get
            {
                string gone = layout.MissingOf(Fields);
                if (layout.Symbol("nt!PsLoadedModuleList") == 0) gone = gone.Length > 0 ? gone + ", nt!PsLoadedModuleList" : "nt!PsLoadedModuleList";
                return gone;
            }
        }

        // The module list from its head one way
        public KernelModuleWalk Walk(bool backward)
        {
            KernelModuleWalk walk = new KernelModuleWalk();
            ulong head = layout.Symbol("nt!PsLoadedModuleList");
            int next = backward ? 8 : 0;
            int back = backward ? 0 : 8;
            byte[] h;
            if (!reader.TryRead(0, head, 16, out h)) { walk.Stop = "the list head, which is not in the dump"; return walk; }
            HashSet<ulong> seen = new HashSet<ulong>();
            ulong previous = head;
            ulong link = BitConverter.ToUInt64(h, next);
            while (true)
            {
                if (link == head) { walk.Complete = true; break; }
                if (walk.Entries.Count >= MaxModules) { walk.Stop = "the first " + MaxModules + " entries"; break; }
                if (!MemoryReader.IsKernelPointer(link)) { walk.Stop = "a link that is not a kernel address"; break; }
                if (!seen.Add(link)) { walk.Stop = "a link to an entry already walked"; break; }
                byte[] l;
                if (!reader.TryRead(0, link, 16, out l)) { walk.Stop = "an entry that is not in the dump"; break; }
                if (BitConverter.ToUInt64(l, back) != previous) walk.Mismatches++;
                walk.Entries.Add(link - (ulong)links);
                previous = link;
                link = BitConverter.ToUInt64(l, next);
            }
            return walk;
        }

        // A module list entry's fields (null when it is not in the dump)
        KernelModuleRecord ReadEntry(ulong entry)
        {
            byte[] e = reader.Read(0, entry, entryBytes);
            if (e.Length < Math.Max(fullName, baseName) + 16) return null;
            KernelModuleRecord m = new KernelModuleRecord();
            m.Entry = entry;
            m.Base = Bytes.U64(e, dllBase);
            m.Size = Bytes.U32(e, sizeOfImage);
            string name = reader.UnicodeString(0, entry + (ulong)baseName);
            string path = reader.UnicodeString(0, entry + (ulong)fullName);
            if (name == null || path == null) UnreadableNames++;
            m.Name = name ?? "";
            m.FullName = path ?? "";
            if (m.Name.Length == 0 && m.FullName.Length > 0) m.Name = m.FullName.Substring(m.FullName.LastIndexOf('\\') + 1);
            return m;
        }

        bool InListedModule(ulong address)
        {
            if (address == 0) return false;
            foreach (KernelModuleRecord m in Modules)
            {
                if (!m.FromDriverObject && address >= m.Base && address - m.Base < m.Size) return true;
            }
            return false;
        }

        public void Run(AreaResult area)
        {
            ForwardWalk = Walk(false);
            BackwardWalk = Walk(true);
            Dictionary<ulong, KernelModuleRecord> byEntry = new Dictionary<ulong, KernelModuleRecord>();
            foreach (ulong entry in ForwardWalk.Entries)
            {
                KernelModuleRecord m = ReadEntry(entry);
                if (m == null) { UnreadableNames++; continue; }
                m.Forward = true;
                byEntry[entry] = m;
                Modules.Add(m);
            }
            // The backward walk in list order (it ran from the end)
            List<ulong> backwardEntries = new List<ulong>(BackwardWalk.Entries);
            backwardEntries.Reverse();
            foreach (ulong entry in backwardEntries)
            {
                KernelModuleRecord known;
                if (byEntry.TryGetValue(entry, out known)) { known.Backward = true; continue; }
                KernelModuleRecord m = ReadEntry(entry);
                if (m == null) { UnreadableNames++; continue; }
                m.Backward = true;
                byEntry[entry] = m;
                Modules.Add(m);
            }
            area.Coverage.Count("kernel modules", Modules.Count);
            bool walkEnded = ForwardWalk.Complete || BackwardWalk.Complete;
            if (!walkEnded)
            {
                area.SetPartial("the kernel's module list could not be walked to its end either way (forwards it stopped at " + ForwardWalk.Stop + "), so drivers hidden from it were not judged");
            }
            else if (!ForwardWalk.Complete || !BackwardWalk.Complete || ForwardWalk.Mismatches + BackwardWalk.Mismatches > 0)
            {
                area.Coverage.Note("the kernel's module list was inconsistent in places, as when memory is copied while Windows runs");
            }

            // The driver objects of \Driver and \FileSystem
            Dictionary<ulong, KernelModuleRecord> unlisted = new Dictionary<ulong, KernelModuleRecord>();
            List<ulong> unlistedOrder = new List<ulong>();
            foreach (string folder in new string[] { "Driver", "FileSystem" })
            {
                ulong directory = objects.RootDirectory(folder);
                if (directory == 0) { area.SetPartial("the object directory \\" + folder + " is not in the dump, so its drivers were not compared with the module list"); continue; }
                foreach (KernelDirectoryEntry d in objects.List(directory))
                {
                    if (area.TimeUp()) return;
                    if (d.TypeName != "Driver") continue;
                    DriverObjects++;
                    byte[] b = reader.Read(0, d.Object, driverBytes);
                    if (b.Length < driverName + 16) { DriverObjectsUnreadable++; continue; }
                    string label = reader.UnicodeString(0, d.Object + (ulong)driverName);
                    if (string.IsNullOrEmpty(label)) label = "\\" + folder + "\\" + (d.Name ?? "?");
                    ulong section = Bytes.U64(b, driverSection);
                    if (!MemoryReader.IsKernelPointer(section)) { DriverObjectsWithoutModule++; continue; }
                    KernelModuleRecord listed;
                    if (byEntry.TryGetValue(section, out listed))
                    {
                        if (!listed.DriverObjects.Contains(label)) listed.DriverObjects.Add(label);
                        continue;
                    }
                    KernelModuleRecord hidden;
                    if (!unlisted.TryGetValue(section, out hidden))
                    {
                        hidden = ReadEntry(section);
                        if (hidden == null)
                        {
                            hidden = new KernelModuleRecord();
                            hidden.Entry = section;
                            hidden.Base = Bytes.U64(b, driverStart);
                            hidden.Size = Bytes.U32(b, driverSize);
                            hidden.Name = label.Substring(label.LastIndexOf('\\') + 1);
                        }
                        // A driver object's own code range when its module entry has none
                        if (hidden.Base == 0) { hidden.Base = Bytes.U64(b, driverStart); hidden.Size = Bytes.U32(b, driverSize); }
                        hidden.FromDriverObject = true;
                        unlisted[section] = hidden;
                        unlistedOrder.Add(section);
                    }
                    if (!hidden.DriverObjects.Contains(label)) hidden.DriverObjects.Add(label);
                }
            }
            // The recently unloaded drivers first: they explain some driver
            // objects outside the list
            List<MemoryEntry> unloadedEntries = ReadUnloaded(area);
            // Judged one way: a driver object's module that is in neither walk,
            // whose code lies in no listed module (a moved or reused entry
            // whose driver is listed is not hidden), when a walk ended, and
            // that no driver unloaded during the capture (or within its churn
            // margin before it) explains: the kernel's list and its driver
            // objects are copied at different moments
            foreach (ulong section in unlistedOrder)
            {
                KernelModuleRecord m = unlisted[section];
                if (InListedModule(m.Base)) { StaleSections++; continue; }
                if (!walkEnded) NotJudged++;
                else if (UnloadedDuringCapture(m.Base)) UnloadedDuring++;
                else m.Hidden = true;
                Modules.Add(m);
            }
            area.Coverage.Count("driver objects", DriverObjects);
            if (DriverObjectsWithoutModule > 0) area.Coverage.Count("driver objects without a module entry", DriverObjectsWithoutModule);
            int hiddenCount = 0;
            foreach (KernelModuleRecord m in Modules) { if (m.Hidden) hiddenCount++; }
            area.Coverage.Count("hidden from the module list", hiddenCount);
            if (StaleSections > 0) area.Coverage.Count("driver objects whose module entry moved", StaleSections);
            if (UnloadedDuring > 0)
            {
                area.Coverage.Count("driver objects of drivers unloaded during the capture", UnloadedDuring);
                area.Coverage.Note(UnloadedDuring + " driver object(s) outside the kernel's module list belong to drivers unloaded while memory was copied, as their unload records show, and are not marked hidden");
            }
            if (DriverObjectsUnreadable > 0) area.Coverage.Note(DriverObjectsUnreadable + " driver object(s) were not in the dump");
            if (UnreadableNames > 0) area.Coverage.Note(UnreadableNames + " kernel module name(s) or entries were not in the dump");

            foreach (KernelModuleRecord m in Modules)
            {
                MemoryEntry e = area.Add("Driver");
                e.Set("State", "Loaded");
                e.Set("Name", m.Name);
                e.Set("Path", objects.ToDrivePath(m.FullName));
                e.SetHex("Base", m.Base);
                e.SetHex("Size", m.Size);
                List<string> ways = new List<string>();
                if (m.Forward || m.Backward) ways.Add("ModuleList");
                if (m.DriverObjects.Count > 0) ways.Add("DriverObject");
                e.Set("FoundBy", string.Join(",", ways.ToArray()));
                if (m.DriverObjects.Count > 0) e.Set("DriverObject", string.Join(",", m.DriverObjects.ToArray()));
                if (m.Hidden) e.Set("Anomaly", "NotInModuleList");
            }
            if (unloadedEntries != null)
            {
                foreach (MemoryEntry e in unloadedEntries) area.Entries.Add(e);
                area.Coverage.Count("unloaded drivers", UnloadedRead);
            }
        }

        // An unload record covers this address, with an unload time at or
        // after the capture start less the churn margin (any time when the
        // capture start is not known)
        bool UnloadedDuringCapture(ulong address)
        {
            if (address == 0) return false;
            foreach (UnloadRecord u in unloadRecords)
            {
                if (address < u.Start || address >= u.End) continue;
                if (context.CaptureFileTime <= 0 || u.Time >= context.CaptureFileTime - context.ChurnTicks) return true;
            }
            return false;
        }

        sealed class UnloadRecord
        {
            public ulong Start;
            public ulong End;
            public long Time;
        }
        readonly List<UnloadRecord> unloadRecords = new List<UnloadRecord>();
        public int UnloadedDuring;

        // nt!MmUnloadedDrivers: the last 50 unloaded drivers, oldest first
        // (their entries, or null when the list is not used; the coverage
        // notes are set here, the count by Run)
        List<MemoryEntry> ReadUnloaded(AreaResult area)
        {
            ulong arraySymbol = layout.Symbol("nt!MmUnloadedDrivers");
            if (arraySymbol == 0) { area.Coverage.Note("the list of recently unloaded drivers is not in the kernel's symbols"); return null; }
            ulong array;
            if (!reader.TryU64(0, arraySymbol, out array)) { area.Coverage.Note("the list of recently unloaded drivers is not in the dump"); return null; }
            if (array == 0) return new List<MemoryEntry>();
            int size = unloaded[4];
            byte[] all = MemoryReader.IsKernelPointer(array) ? reader.Read(0, array, UnloadedSlots * size) : new byte[0];
            if (all.Length < size) { area.Coverage.Note("the list of recently unloaded drivers is not in the dump"); return null; }
            uint last = 0;
            ulong lastSymbol = layout.Symbol("nt!MmLastUnloadedDriver");
            if (lastSymbol != 0) reader.TryU32(0, lastSymbol, out last);
            if (last >= UnloadedSlots) last = 0;
            long latest = context.CaptureFileTime > 0 ? context.CaptureFileTime + 864000000000L : long.MaxValue;
            // The record's time: the system time on older Windows; the time
            // since boot (interrupt time, 100 ns units) on Windows 11 24H2,
            // added to the boot time nt!KeBootTime
            long boot = 0;
            ulong bootSymbol = layout.Symbol("nt!KeBootTime");
            ulong bootValue;
            if (bootSymbol != 0 && reader.TryU64(0, bootSymbol, out bootValue) && (long)bootValue >= Year2000 && (long)bootValue <= latest) boot = (long)bootValue;
            List<MemoryEntry> found = new List<MemoryEntry>();
            int used = 0;
            for (int i = 0; i < UnloadedSlots; i++)
            {
                int slot = (int)((last + (uint)i) % UnloadedSlots);
                int at = slot * size;
                if (!Bytes.Has(all, at, size)) continue;
                ushort length = Bytes.U16(all, at + unloaded[0]);
                ushort maximum = Bytes.U16(all, at + unloaded[0] + 2);
                ulong buffer = Bytes.U64(all, at + unloaded[0] + 8);
                ulong start = Bytes.U64(all, at + unloaded[1]);
                ulong end = Bytes.U64(all, at + unloaded[2]);
                long time = Bytes.I64(all, at + unloaded[3]);
                if (length == 0 && buffer == 0 && start == 0 && end == 0) continue;
                used++;
                string name = null;
                if (length > 0 && (length & 1) == 0 && length <= maximum && MemoryReader.IsKernelPointer(buffer)) name = reader.Utf16(0, buffer, length);
                if (time > 0 && time < Year2000 && boot > 0 && time < MaxSinceBoot) time += boot;
                if (string.IsNullOrEmpty(name) || !MemoryReader.IsKernelAddress(start) || end <= start || end - start > MaxDriverSize || time < Year2000 || time > latest)
                {
                    UnloadedRejected++;
                    continue;
                }
                MemoryEntry e = new MemoryEntry("Driver");
                e.Set("State", "Unloaded");
                e.Set("Name", name);
                e.SetHex("Base", start);
                e.SetHex("Size", end - start);
                e.Set("Time", Fmt.IsoTime(time));
                e.Set("FoundBy", "UnloadedDriverList");
                found.Add(e);
                UnloadRecord record = new UnloadRecord();
                record.Start = start;
                record.End = end;
                record.Time = time;
                unloadRecords.Add(record);
            }
            // A layout that does not fit: most used slots fail the checks
            if (used > 0 && UnloadedRejected * 2 > used)
            {
                unloadRecords.Clear();
                area.Coverage.Note("the list of recently unloaded drivers does not have the layout the builder reads, so it was not used");
                return null;
            }
            UnloadedRead = found.Count;
            if (UnloadedRejected > 0) area.Coverage.Note(UnloadedRejected + " slot(s) of the list of recently unloaded drivers were not readable");
            return found;
        }
    }
}
'@
}

# The layout of the area: the module list entry and the driver object, and
# the unloaded-driver record when the symbols describe it (else
# DriverListScan.UnloadedLayout)
function Get-DbgEngDriversLayout {
    param($Context)
    $spec = @{
        "_KLDR_DATA_TABLE_ENTRY" = @{ InLoadOrderLinks = '^struct _LIST_ENTRY\b'; DllBase = '^Ptr64\b'; SizeOfImage = '^Uint4B$'; FullDllName = '^struct _UNICODE_STRING\b'; BaseDllName = '^struct _UNICODE_STRING\b' }
        "_DRIVER_OBJECT"         = @{ DriverStart = '^Ptr64\b'; DriverSize = '^Uint4B$'; DriverSection = '^Ptr64\b'; DriverName = '^struct _UNICODE_STRING\b' }
    }
    return (New-DbgEngLayout -Session $Context.Session -Spec $spec -Symbols @("nt!PsLoadedModuleList", "nt!MmUnloadedDrivers", "nt!MmLastUnloadedDriver", "nt!KeBootTime"))
}

# The unloaded-driver record's offsets (Name, StartAddress, EndAddress,
# CurrentTime, size) when the kernel's symbols describe _UNLOADED_DRIVERS,
# else $null (the scan uses its own)
function Get-DbgEngUnloadedDriverOffsets {
    param($Context)
    $spec = @{ "_UNLOADED_DRIVERS" = @{ Name = '^struct _UNICODE_STRING\b'; StartAddress = '^Ptr64\b'; EndAddress = '^Ptr64\b'; CurrentTime = '^union _LARGE_INTEGER\b' } }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec $spec
    if (-not $layout.Complete -or $layout.Size("_UNLOADED_DRIVERS") -lt 0x28) { return $null }
    return [int[]]@($layout.Off("_UNLOADED_DRIVERS.Name"), $layout.Off("_UNLOADED_DRIVERS.StartAddress"), $layout.Off("_UNLOADED_DRIVERS.EndAddress"),
        $layout.Off("_UNLOADED_DRIVERS.CurrentTime"), $layout.Size("_UNLOADED_DRIVERS"))
}

# The area: Driver entries of the loaded modules (with the driver objects
# that use them and the hidden ones) and of the recently unloaded drivers
function Invoke-DbgEngDriversArea {
    param($Context, $Area)
    $objects = Get-DbgEngKernelObjects -Context $Context
    if ($objects.Problem) { $Area.SetNotRead($objects.Problem); return }
    $layout = Get-DbgEngDriversLayout -Context $Context
    $offsets = $null
    $described = @(Get-DbgEngUnloadedDriverOffsets -Context $Context)
    if ($described.Count -eq 5) { $offsets = [int[]]$described }
    $scan = New-Object TimelineDbgEng.DriverListScan -ArgumentList $Context, $layout, $objects, $offsets
    if ($scan.MissingFields) { $Area.SetNotRead("the kernel's symbols do not give $($scan.MissingFields)"); return }
    $scan.Run($Area)
    $Context.Shared["DriverScan"] = $scan
}
