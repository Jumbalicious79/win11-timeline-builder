# =============================================================
# Windows ARM64 memory dumps: network connections, listeners and UDP endpoints (item i)
# Part of win11-timeline-builder (work package WP6). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads: the network objects that the pass over the dump file
# (TimelineDbgEng.PoolScan.ps1, $Context.RawPass) found by their pool tags,
# as Volatility's windows.netscan does on x64: TCP connections (TTcb), TCP
# listeners (TcpL) and UDP endpoints (UdpA). Their fields are read from the
# copy the pass kept; the pointers in them (the address family object, the
# addresses, the owner process) are followed in kernel memory through the
# reader, on this (the engine's) thread. tcpip.sys's structures are in no
# symbol file, so their offsets are a table per Windows build
# (NetLayouts), used only for builds it was confirmed on and only when the
# objects of a dump pass the self-checks (allocation size, the address
# family object's tag and family, a known TCP state, plausible create
# times, owners that are listed processes); a kind that fails them is not
# listed, and the coverage note says so. TIME_WAIT objects (TcTW) and
# sockets (AfdE) are counted in the log only.
#
# A scan of memory also finds objects that were freed: an entry that is
# closed (CLOSED, DELETE_TCB), whose owner has exited, or whose owner memory
# is no longer that process (not a process object, or a process created
# after the entry) is Stale=Yes and never flagged. Anomaly=OwnerHidden: the
# owner is a listed process with Anomaly=NotInProcessList, or a process
# object found only through the entry (no exit time, created more than the
# process scan's capture churn margin, Get-DbgEngChurnSeconds, before the
# capture started). The pass also finds whole-page copies of pool pages
# (the dump file's own cache pages, for example), each from another moment
# of the capture: a second or later copy of an object (the same owner
# pointer, create time and ports at another physical address) is
# Duplicate=Yes and never flagged.
#
#   Get-DbgEngNetworkSource   its C# (NetObjectLayout, NetLayouts, NetAddress, NetworkReader)
#   Invoke-DbgEngNetworkArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Net (rows: Add-DbgEngNetRows, lib\memory\TimelineMemoryRows.ps1)
#     Offset (the object's physical address), Proto (TCPv4, TCPv6, UDPv4,
#     UDPv6), LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID,
#     Owner (the owner's name), Created (ISO 8601), PoolTag, Stale (Yes, No),
#     RemoteScope (connections: Public, Private, Loopback, LinkLocal, Other),
#     OwnerCreated (yyyy-MM-dd HH:mm:ss.fff), OwnerPath, OwnerSid, Anomaly
#     (OwnerHidden), Duplicate (Yes: a later copy of an object already
#     listed); a field without a value is left out
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngNetworkSource {
    return @'
namespace TimelineDbgEng
{
    // One kind of tcpip.sys network object on one Windows build: offsets
    // from the object's start (the end of its 16-byte pool header).
    public sealed class NetObjectLayout
    {
        public string Tag;             // the pool tag
        public string Kind;            // Connection, Listener or Udp
        public int BlockBytes;         // the allocation's size (the pool header's BlockSize x 16, the header included)
        public int AddressFamily;      // pointer to the address family object (tag NetLayouts.FamilyTag)
        public int Owner;              // the owner process (EPROCESS)
        public int Created;            // when it was made (FILETIME)
        public int State = -1;         // the TCP state (connections)
        public int LocalPort;          // big-endian
        public int RemotePort = -1;
        // An address: the pointer at Base in the object, then for each step
        // of Path the pointer at (value + step), then the address bytes at
        // (value + BytesAt). A Base pointer of 0 in a listener or UDP
        // endpoint is the unspecified address (0.0.0.0 or ::).
        public int LocalBase = -1;
        public int[] LocalPath = new int[0];
        public int LocalBytesAt;
        public int RemoteBase = -1;
        public int[] RemotePath = new int[0];
        public int RemoteBytesAt;

        // Bytes of the object the fields need
        public int Needed
        {
            get
            {
                int n = 0;
                n = Math.Max(n, AddressFamily + 8);
                n = Math.Max(n, Owner + 8);
                n = Math.Max(n, Created + 8);
                if (State >= 0) n = Math.Max(n, State + 4);
                n = Math.Max(n, LocalPort + 2);
                if (RemotePort >= 0) n = Math.Max(n, RemotePort + 2);
                if (LocalBase >= 0) n = Math.Max(n, LocalBase + 8);
                if (RemoteBase >= 0) n = Math.Max(n, RemoteBase + 8);
                return n;
            }
        }
    }

    // The layouts of tcpip.sys's network objects per Windows build. Not in
    // any symbol file (the kernel's describes none of them; tcpip.pdb has
    // public symbols only), so these are facts with their source: the
    // offsets MemProcFS publishes for build 26100 (vmmnet.c: TcpE/TTcb,
    // TcpL, UdpA, the INET_AF family at +0x18), the same on ARM64 as on
    // x64, confirmed on three Windows 11 26100 ARM64 dumps (2026-10): the
    // owner at these offsets was a listed process for 32/32, 19/19 and
    // 50/50 connections, 32, 21 and 19 listeners and 40, 32 and 20 UDP
    // endpoints, every address family object had the tag InNl, the
    // allocation sizes were these, and every address read through these
    // paths was of a plausible kind. A build outside Known() is not read.
    public static class NetLayouts
    {
        public const string FamilyTag = "InNl";
        public const int FamilyOffset = 0x18;   // the family (2: IPv4, 23: IPv6) in the address family object
        // Counted only: a TIME_WAIT connection (TcTW; every one of the
        // dumps' 66, 51 and 1 had this size) and the owner process of an
        // afd.sys socket (AfdE; a listed process for 145 of 223, 90 of 102
        // and 111 of 126 on the dumps)
        public const int TimeWaitBlockBytes = 0xC0;
        public const int SocketOwner = 0x30;

        // Windows 11 24H2 and 25H2 (26100, 26200) and their preview builds
        public static bool Known(int build) { return build >= 26100 && build < 26300; }

        public static NetObjectLayout[] ForBuild(int build)
        {
            if (!Known(build)) return null;
            NetObjectLayout tcb = new NetObjectLayout();
            tcb.Tag = "TTcb"; tcb.Kind = "Connection"; tcb.BlockBytes = 0x500;
            tcb.AddressFamily = 0x18; tcb.State = 0x70; tcb.LocalPort = 0x74; tcb.RemotePort = 0x76;
            tcb.Owner = 0x350; tcb.Created = 0x360;
            // Both addresses through the pointer at +0x20: the local one at
            // ptr(ptr(ptr(it) + 0x10)), the remote one at ptr(it + 0x10)
            tcb.LocalBase = 0x20; tcb.LocalPath = new int[] { 0x0, 0x10, 0x0 }; tcb.LocalBytesAt = 0;
            tcb.RemoteBase = 0x20; tcb.RemotePath = new int[] { 0x10 }; tcb.RemoteBytesAt = 0;

            NetObjectLayout listener = new NetObjectLayout();
            listener.Tag = "TcpL"; listener.Kind = "Listener"; listener.BlockBytes = 0x160;
            listener.AddressFamily = 0x30; listener.Owner = 0x38; listener.Created = 0x48; listener.LocalPort = 0x7A;
            listener.LocalBase = 0x68; listener.LocalPath = new int[] { 0x10, 0x0 }; listener.LocalBytesAt = 0;

            NetObjectLayout udp = new NetObjectLayout();
            udp.Tag = "UdpA"; udp.Kind = "Udp"; udp.BlockBytes = 0x1A0;
            udp.AddressFamily = 0x28; udp.Owner = 0x30; udp.Created = 0x60; udp.LocalPort = 0xA8;
            udp.LocalBase = 0xB0; udp.LocalPath = new int[] { 0x18, 0x0 }; udp.LocalBytesAt = 0x18;
            return new NetObjectLayout[] { tcb, listener, udp };
        }

        // tcpip's TCP states, named as Volatility's windows.netscan names
        // them; null for a value that is not one
        public static string TcpState(uint state)
        {
            switch (state)
            {
                case 0: return "CLOSED";
                case 1: return "LISTENING";
                case 2: return "SYN_SENT";
                case 3: return "SYN_RCVD";
                case 4: return "ESTABLISHED";
                case 5: return "FIN_WAIT1";
                case 6: return "FIN_WAIT2";
                case 7: return "CLOSE_WAIT";
                case 8: return "CLOSING";
                case 9: return "LAST_ACK";
                case 12: return "TIME_WAIT";
                case 13: return "DELETE_TCB";
                default: return null;
            }
        }
    }

    // IP addresses as the rows give them
    public static class NetAddress
    {
        // "a.b.c.d", or IPv6 in its short form; "" for no address
        public static string Text(byte[] a, int family)
        {
            if (family == 2 && a != null && a.Length >= 4)
                return a[0].ToString(CultureInfo.InvariantCulture) + "." + a[1].ToString(CultureInfo.InvariantCulture) + "." + a[2].ToString(CultureInfo.InvariantCulture) + "." + a[3].ToString(CultureInfo.InvariantCulture);
            if (family == 23 && a != null && a.Length >= 16)
            {
                byte[] b = new byte[16];
                Buffer.BlockCopy(a, 0, b, 0, 16);
                return new System.Net.IPAddress(b).ToString();
            }
            return "";
        }

        // Where an address is: Public (routed on the internet), Private
        // (10/8, 172.16/12, 192.168/16, 100.64/10; fc00::/7), Loopback
        // (127/8, ::1), LinkLocal (169.254/16, fe80::/10) or Other
        // (unspecified, multicast, broadcast, documentation and other
        // reserved ranges); "" for no address
        public static string Scope(byte[] a, int family)
        {
            if (family == 23 && a != null && a.Length >= 16)
            {
                bool zeros10 = true;
                for (int i = 0; i < 10; i++) { if (a[i] != 0) zeros10 = false; }
                if (zeros10 && a[10] == 0xFF && a[11] == 0xFF) return Scope4(a[12], a[13], a[14], a[15]);
                bool zeros15 = zeros10 && a[10] == 0 && a[11] == 0 && a[12] == 0 && a[13] == 0 && a[14] == 0;
                if (zeros15 && a[15] == 1) return "Loopback";
                if (zeros15 && a[15] == 0) return "Other";
                if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return "LinkLocal";
                if ((a[0] & 0xFE) == 0xFC) return "Private";
                if ((a[0] & 0xE0) == 0x20 && !(a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8)) return "Public";
                return "Other";
            }
            if (family == 2 && a != null && a.Length >= 4) return Scope4(a[0], a[1], a[2], a[3]);
            return "";
        }

        static string Scope4(byte b0, byte b1, byte b2, byte b3)
        {
            if (b0 == 127) return "Loopback";
            if (b0 == 10 || (b0 == 172 && b1 >= 16 && b1 <= 31) || (b0 == 192 && b1 == 168) || (b0 == 100 && b1 >= 64 && b1 <= 127)) return "Private";
            if (b0 == 169 && b1 == 254) return "LinkLocal";
            if (b0 == 0 || b0 >= 224) return "Other";
            if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) return "Other";
            if ((b0 == 198 && (b1 == 18 || b1 == 19)) || (b0 == 198 && b1 == 51 && b2 == 100) || (b0 == 203 && b1 == 0 && b2 == 113)) return "Other";
            return "Public";
        }
    }

    // Reads the network objects of a pass over the dump file into Net
    // entries (see TimelineDbgEng.Network.ps1). layout: the pool header's
    // fields, the EPROCESS fields of an owner that is not a listed process,
    // and nt!NtBuildNumber, from the kernel's symbols.
    public sealed class NetworkReader
    {
        const int HeaderBytes = 16;
        const int PageBytes = 0x1000;

        sealed class OwnerInfo
        {
            // Listed (a process of the scan), Unlisted (a process object no
            // way of the scan found), NotProcess (memory that is not a
            // process), NotJudged (not a listed process, and the symbols do
            // not give the EPROCESS fields to judge it)
            public string Kind;
            public ProcessInfo Process;
        }

        // The EPROCESS fields an owner outside the process scan is judged by
        public static readonly string[] OwnerFields = new string[] {
            "_EPROCESS.Pcb", "_EPROCESS.UniqueProcessId", "_EPROCESS.ActiveProcessLinks", "_EPROCESS.CreateTime", "_EPROCESS.ExitTime", "_EPROCESS.ImageFileName", "_EPROCESS.Token" };

        readonly MemoryContext context;
        readonly MemoryReader reader;
        readonly Layout layout;
        readonly Dictionary<ulong, OwnerInfo> owners = new Dictionary<ulong, OwnerInfo>();
        readonly Dictionary<ulong, int> families = new Dictionary<ulong, int>();
        // The Windows build (nt!NtBuildNumber), 0 when not read
        public int Build;

        public NetworkReader(MemoryContext context, Layout layout)
        {
            if (context == null) throw new ArgumentNullException("context");
            this.context = context;
            reader = context.Reader;
            this.layout = layout ?? new Layout();
            ulong at = this.layout.Symbol("nt!NtBuildNumber");
            uint value;
            if (at != 0 && reader.TryU32(0, at, out value)) Build = (int)(value & 0xFFFF);
        }

        // A reason as the AREA line and the report take it: one line, no
        // ";", " -- ", ": " or parentheses
        static string Short(string text)
        {
            string t = (text ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
            t = t.Replace(";", ",").Replace(" -- ", " - ").Replace(": ", " - ").Replace("(", "[").Replace(")", "]").TrimEnd('.');
            if (t.Length > 120) t = t.Substring(0, 117) + "...";
            return t;
        }

        static string Plural(long n, string one, string many) { return n.ToString(CultureInfo.InvariantCulture) + " " + (n == 1 ? one : many); }

        // The allocation's size from its pool header (0 when the symbols do
        // not give BlockSize)
        int BlockBytesOf(PoolHit h)
        {
            int[] bits;
            if (!layout.Bits.TryGetValue("_POOL_HEADER.BlockSize", out bits)) return 0;
            int at = layout.Off("_POOL_HEADER.BlockSize");
            if (!Bytes.Has(h.Bytes, at, 8)) return 0;
            return (int)Layout.Extract(Bytes.U64(h.Bytes, at), bits[0], bits[1]) * 16;
        }

        // The family (2 or 23) of an address family object; 0 when the
        // pointer is not one (its pool tag is not InNl, or not readable)
        int FamilyOf(ulong pointer)
        {
            int family;
            if (families.TryGetValue(pointer, out family)) return family;
            family = 0;
            int tagAt = layout.Off("_POOL_HEADER.PoolTag");
            byte[] b;
            if (MemoryReader.IsKernelPointer(pointer) && tagAt >= 0 && pointer >= 0xFFFF000000000000UL &&
                reader.TryRead(0, pointer - HeaderBytes, HeaderBytes + NetLayouts.FamilyOffset + 2, out b) &&
                Encoding.ASCII.GetString(b, tagAt, 4) == NetLayouts.FamilyTag)
            {
                int f = BitConverter.ToUInt16(b, HeaderBytes + NetLayouts.FamilyOffset);
                if (f == 2 || f == 23) family = f;
            }
            families[pointer] = family;
            return family;
        }

        // The bytes of an address (4 or 16), null when a pointer on the way
        // is not readable
        byte[] AddressAt(byte[] obj, int baseOffset, int[] path, int bytesAt, int family, out bool unspecified)
        {
            unspecified = false;
            ulong value = Bytes.U64(obj, HeaderBytes + baseOffset);
            if (value == 0) { unspecified = true; return null; }
            foreach (int step in path)
            {
                if (!MemoryReader.IsKernelPointer(value)) return null;
                ulong next;
                if (!reader.TryU64(0, value + (ulong)step, out next)) return null;
                value = next;
            }
            if (!MemoryReader.IsKernelAddress(value)) return null;
            byte[] a;
            return reader.TryRead(0, value + (ulong)bytesAt, family == 23 ? 16 : 4, out a) ? a : null;
        }

        // An EPROCESS block of the owner pointer, when it is a process
        // object: the dispatcher type 3 at its start (_KPROCESS at +0), a
        // process ID Windows gives (a multiple of 4 below 2^32), links of
        // its process list entry and a token in kernel memory
        bool LooksLikeProcess(byte[] b)
        {
            if (layout.Off("_EPROCESS.Pcb") != 0 || b == null || b.Length == 0 || b[0] != 3) return false;
            long pid = Bytes.I64(b, layout.Off("_EPROCESS.UniqueProcessId"));
            if (pid <= 0 || pid >= 0x100000000L || (pid & 3) != 0) return false;
            int links = layout.Off("_EPROCESS.ActiveProcessLinks");
            if (links < 0 || !MemoryReader.IsKernelAddress(Bytes.U64(b, links)) || !MemoryReader.IsKernelAddress(Bytes.U64(b, links + 8))) return false;
            int token = layout.Off("_EPROCESS.Token");
            return token >= 0 && MemoryReader.IsKernelPointer(Bytes.U64(b, token) & ~layout.FastRefMask);
        }

        OwnerInfo OwnerOf(ulong pointer)
        {
            OwnerInfo o;
            if (owners.TryGetValue(pointer, out o)) return o;
            o = new OwnerInfo();
            o.Kind = "NotProcess";
            ProcessInfo listed = context.Find(pointer);
            if (listed != null) { o.Kind = "Listed"; o.Process = listed; }
            else if (!layout.HasAll(OwnerFields) || layout.Size("_EPROCESS") <= 0) o.Kind = "NotJudged";
            else if (MemoryReader.IsKernelPointer(pointer))
            {
                int size = layout.Size("_EPROCESS");
                byte[] block;
                if (size > 0 && size <= 0x4000 && reader.TryRead(0, pointer, size, out block) && LooksLikeProcess(block))
                {
                    o.Process = ProcessInfo.FromBlock(pointer, block, layout);
                    o.Process.FoundBy = "NetworkOwner";
                    o.Kind = "Unlisted";
                }
            }
            owners[pointer] = o;
            return o;
        }

        // A time from 1980 up to a day after the capture started (or now)
        bool Plausible(long fileTime)
        {
            long low = new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
            long high = context.CaptureFileTime > 0 ? context.CaptureFileTime + TimeSpan.TicksPerDay : DateTime.UtcNow.AddDays(1).ToFileTimeUtc();
            return fileTime >= low && fileTime <= high;
        }

        static bool HasToken(string list, string token)
        {
            if (string.IsNullOrEmpty(list)) return false;
            foreach (string t in list.Split(',')) { if (t.Trim() == token) return true; }
            return false;
        }

        // Waits for the pass (it started before the first area), then reads
        // its network objects into area. Never throws for what the dump
        // holds: what cannot be read is counted and noted.
        public void Run(RawPass pass, AreaResult area)
        {
            if (pass == null || pass.State == "NotStarted") { area.SetNotRead("the pass over the dump file was not started"); return; }
            while (!pass.Wait(250))
            {
                if (area.Deadline.Expired)
                {
                    pass.Dispose();
                    area.SetNotRead("the pass over the dump file did not end within its time limit of " + area.Deadline.Seconds.ToString("0", CultureInfo.InvariantCulture) + " s");
                    return;
                }
            }
            string state = pass.State;
            if (state == "NotRead" || state == "NotStarted") { area.SetNotRead(Short(pass.Why.Length > 0 ? pass.Why : "the pass over the dump file was not started")); return; }
            if (state == "Stopped") { area.SetNotRead("the pass over the dump file was stopped"); return; }
            if (Build != 0 && !NetLayouts.Known(Build))
            {
                area.SetNotRead("the network objects of Windows build " + Build.ToString(CultureInfo.InvariantCulture) + " are not known to this builder");
                return;
            }
            // A build not read: the newest table, and the self-checks decide
            NetObjectLayout[] kinds = NetLayouts.ForBuild(Build != 0 ? Build : 26100);
            if (!layout.Has("_POOL_HEADER.PoolTag") || !layout.Bits.ContainsKey("_POOL_HEADER.BlockSize"))
            {
                area.SetNotRead("the kernel's symbols do not describe its pool header as expected");
                return;
            }
            if (state == "TimeLimit")
            {
                long part = pass.TotalBytes > 0 ? pass.ScannedBytes * 100 / pass.TotalBytes : 0;
                area.SetPartial("the pass over the dump file stopped at its time limit of " + pass.CapSeconds.ToString("0", CultureInfo.InvariantCulture) +
                    " s after " + part.ToString(CultureInfo.InvariantCulture) + "% of it, so connections in the rest are not listed");
            }

            // The log's counts, in this order
            foreach (NetObjectLayout k in kinds) area.Coverage.Count(KindLabel(k), 0);
            area.Coverage.Count("Stale=Yes", 0);
            area.Coverage.Count("OwnerHidden", 0);
            int failedKinds = 0, kindsWithObjects = 0;
            foreach (NetObjectLayout k in kinds)
            {
                PoolHit[] hits = pass.HitsOf(k.Tag);
                int dropped = pass.DroppedOf(k.Tag);
                // Matches of another allocation size, left out by the pass
                // itself (they never count toward its cap)
                int rejected = pass.RejectedOf(k.Tag);
                if (rejected > 0) area.Coverage.Count("other objects with these tags", rejected);
                if (dropped > 0) area.SetPartial(Plural(dropped, "more object", "more objects") + " tagged " + k.Tag + " were not read, past the " + RawPass.MaxHitsPerTag.ToString(CultureInfo.InvariantCulture) + " the pass keeps");
                List<MemoryEntry> made = new List<MemoryEntry>();
                // The first copy of each object: a scan of physical memory
                // also finds whole-page copies of pool pages (the dump file's
                // own cache pages, for example), each a snapshot of another
                // moment; a later copy (the same owner pointer, create time
                // and ports at another physical address) is Duplicate=Yes
                Dictionary<string, bool> firstCopies = new Dictionary<string, bool>(StringComparer.Ordinal);
                int recognized = 0, valid = 0, plausible = 0, listedOwners = 0;
                foreach (PoolHit h in hits)
                {
                    if (area.Deadline.Expired) { area.TimeUp(); break; }
                    if (BlockBytesOf(h) != k.BlockBytes) { area.Coverage.Count("other objects with these tags"); continue; }
                    if (h.Bytes.Length < HeaderBytes + k.Needed) { area.Coverage.Count("objects cut short at the end of the memory"); continue; }
                    if (h.PageOffset + HeaderBytes + k.Needed > PageBytes) { area.Coverage.Count("objects across a page boundary"); continue; }
                    recognized++;
                    MemoryEntry e = Entry(k, h, ref valid, ref plausible, ref listedOwners, area);
                    if (e == null) continue;
                    long createdRaw = Bytes.I64(h.Bytes, HeaderBytes + k.Created);
                    if (createdRaw != 0)
                    {
                        string copyKey = Bytes.U64(h.Bytes, HeaderBytes + k.Owner).ToString("x", CultureInfo.InvariantCulture) + "|" + createdRaw.ToString(CultureInfo.InvariantCulture) + "|" +
                            e.Get("LocalPort") + "|" + e.Get("ForeignPort");
                        if (firstCopies.ContainsKey(copyKey)) e.Set("Duplicate", "Yes");
                        else firstCopies[copyKey] = true;
                    }
                    made.Add(e);
                }
                if (hits.Length == 0 && rejected < 16) continue;
                kindsWithObjects++;
                // The self-checks of this kind: when enough objects have its
                // size, most of them must read as such objects; many objects
                // with the tag and none of the size is another layout too
                // (each dump had 1 to 8 of other sizes with these tags)
                bool fails = (hits.Length + rejected >= 16 && recognized == 0) ||
                    (recognized >= 4 && (valid * 4 < recognized * 3 || plausible * 4 < valid * 3 || listedOwners * 4 < valid));
                if (fails)
                {
                    failedKinds++;
                    area.Coverage.Count(KindLabel(k) + " not listed", made.Count);
                    area.SetPartial("the " + KindLabel(k) + " in this dump do not have the layout this builder knows for Windows build " +
                        (Build != 0 ? Build.ToString(CultureInfo.InvariantCulture) : "unknown") + ", so they are not listed");
                    continue;
                }
                foreach (MemoryEntry e in made)
                {
                    area.Entries.Add(e);
                    area.Coverage.Count(KindLabel(k));
                    if (e.Get("Duplicate") == "Yes") { area.Coverage.Count("Duplicate=Yes"); continue; }
                    if (e.Get("Stale") == "Yes") area.Coverage.Count("Stale=Yes");
                    if (e.Has("Anomaly")) area.Coverage.Count("OwnerHidden");
                }
            }
            long copies = area.Coverage.Get("Duplicate=Yes");
            if (copies > 0)
            {
                area.Coverage.Note(copies == 1 ? "1 network object was found again at another physical address, a copy of the same object from another moment of the capture, and is listed with Duplicate=Yes, never flagged" :
                    Plural(copies, "network object", "network objects") + " were found again at other physical addresses, copies of the same objects from other moments of the capture, and are listed with Duplicate=Yes, never flagged");
            }
            if (kindsWithObjects > 0 && failedKinds == kindsWithObjects)
            {
                area.SetNotRead("the network objects in this dump do not have the layout this builder knows for Windows build " +
                    (Build != 0 ? Build.ToString(CultureInfo.InvariantCulture) : "unknown"));
                return;
            }

            // Counted only: connections in TIME_WAIT (their local address is
            // not read) and sockets
            int timeWait = 0;
            foreach (PoolHit h in pass.HitsOf("TcTW")) { if (BlockBytesOf(h) == NetLayouts.TimeWaitBlockBytes) timeWait++; }
            if (timeWait > 0)
            {
                area.Coverage.Count("TIME_WAIT connections counted", timeWait);
                area.Coverage.Note(timeWait == 1 ? "1 connection in TIME_WAIT was found but is not listed, as its local address is not read" :
                    Plural(timeWait, "connection", "connections") + " in TIME_WAIT were found but are not listed, as their local addresses are not read");
            }
            int sockets = 0, socketsOfListed = 0;
            foreach (PoolHit h in pass.HitsOf("AfdE"))
            {
                sockets++;
                if (Bytes.Has(h.Bytes, HeaderBytes + NetLayouts.SocketOwner, 8) && context.Find(Bytes.U64(h.Bytes, HeaderBytes + NetLayouts.SocketOwner)) != null) socketsOfListed++;
            }
            if (sockets > 0) { area.Coverage.Count("sockets counted", sockets); area.Coverage.Count("sockets of listed processes", socketsOfListed); }
            long crossing = area.Coverage.Get("objects across a page boundary");
            if (crossing > 0) area.Coverage.Note(Plural(crossing, "network object lies", "network objects lie") + " across a page boundary and " + (crossing == 1 ? "is" : "are") + " not read");
        }

        static string KindLabel(NetObjectLayout k)
        {
            switch (k.Kind)
            {
                case "Connection": return "TCP connections";
                case "Listener": return "TCP listeners";
                default: return "UDP endpoints";
            }
        }

        MemoryEntry Entry(NetObjectLayout k, PoolHit h, ref int valid, ref int plausible, ref int listedOwners, AreaResult area)
        {
            byte[] b = h.Bytes;
            int o = HeaderBytes;
            int family = FamilyOf(Bytes.U64(b, o + k.AddressFamily));
            if (family == 0) { area.Coverage.Count("objects without an address family"); return null; }
            string stateText = "";
            uint state = 0;
            if (k.State >= 0)
            {
                state = Bytes.U32(b, o + k.State);
                stateText = NetLayouts.TcpState(state);
                if (stateText == null) { area.Coverage.Count("connections in no known state"); return null; }
            }
            else if (k.Kind == "Listener") stateText = "LISTENING";
            valid++;
            long created = Bytes.I64(b, o + k.Created);
            bool timeOk = Plausible(created);
            if (timeOk) plausible++;

            // The owner, and whether this entry is still what it says
            OwnerInfo owner = OwnerOf(Bytes.U64(b, o + k.Owner));
            ProcessInfo p = owner.Process;
            bool stale = false;
            if (k.State >= 0 && (state == 0 || state == 13)) stale = true;
            if (owner.Kind == "NotProcess") { stale = true; area.Coverage.Count("owner memory not a process"); }
            else if (owner.Kind == "NotJudged") { stale = true; area.Coverage.Count("owners outside the process scan not judged"); }
            else if (timeOk && p.CreateTime > 0 && created < p.CreateTime)
            {
                // Made before its owner started: the owner's memory is a
                // later process's now
                stale = true;
                p = null;
                area.Coverage.Count("owner memory of a later process");
            }
            else if (p.ExitTime > 0) { stale = true; area.Coverage.Count("owner exited"); }
            if (p != null && owner.Kind == "Listed" && timeOk) listedOwners++;
            bool hidden = false;
            if (!stale && p != null)
            {
                // A listed owner: as the process scan judged it. An owner
                // found only through this object: as the scan judges, created
                // more than its capture churn margin before the capture
                // started (a process that ended and was deleted while memory
                // was copied can leave its EPROCESS copied before its exit)
                if (owner.Kind == "Listed") hidden = HasToken(p.Anomaly, "NotInProcessList");
                else
                {
                    hidden = context.BeforeChurn(p.CreateTime);
                    if (!hidden && context.CaptureFileTime > 0 && p.CreateTime > 0) area.Coverage.Count("owners found only through the network object, created within the capture churn margin");
                }
            }
            if (owner.Kind == "Unlisted" && p != null) area.Coverage.Count("owners found only through the network object");

            bool localUnspecified;
            byte[] local = AddressAt(b, k.LocalBase, k.LocalPath, k.LocalBytesAt, family, out localUnspecified);
            if (localUnspecified && k.Kind != "Connection") local = new byte[family == 23 ? 16 : 4];
            byte[] remote = null;
            if (k.RemoteBase >= 0)
            {
                bool remoteUnspecified;
                remote = AddressAt(b, k.RemoteBase, k.RemotePath, k.RemoteBytesAt, family, out remoteUnspecified);
            }
            if (local == null || (k.RemoteBase >= 0 && remote == null)) area.Coverage.Count("addresses not readable");

            string v = family == 23 ? "v6" : "v4";
            MemoryEntry e = new MemoryEntry("Net");
            e.SetHex("Offset", h.Physical + HeaderBytes);
            e.Set("Proto", (k.Kind == "Udp" ? "UDP" : "TCP") + v);
            e.Set("LocalAddr", local != null ? NetAddress.Text(local, family) : "?");
            e.Set("LocalPort", (long)((b[o + k.LocalPort] << 8) | b[o + k.LocalPort + 1]));
            if (k.Kind == "Connection")
            {
                e.Set("ForeignAddr", remote != null ? NetAddress.Text(remote, family) : "?");
                e.Set("ForeignPort", (long)((b[o + k.RemotePort] << 8) | b[o + k.RemotePort + 1]));
            }
            else if (k.Kind == "Listener") { e.Set("ForeignAddr", family == 23 ? "::" : "0.0.0.0"); e.Set("ForeignPort", 0L); }
            else { e.Set("ForeignAddr", "*"); e.Set("ForeignPort", 0L); }
            e.Set("State", stateText);
            if (p != null)
            {
                e.Set("PID", p.Pid);
                if (p.Name.Length > 0) e.Set("Owner", p.Name);
            }
            if (timeOk) e.Set("Created", Fmt.IsoTime(created));
            e.Set("PoolTag", k.Tag);
            e.Set("Stale", stale ? "Yes" : "No");
            if (k.Kind == "Connection" && remote != null) e.Set("RemoteScope", NetAddress.Scope(remote, family));
            if (p != null)
            {
                if (p.CreatedText.Length > 0) e.Set("OwnerCreated", p.CreatedText);
                if (p.ImagePath.Length > 0) e.Set("OwnerPath", p.ImagePath);
                if (p.UserSid.Length > 0) e.Set("OwnerSid", p.UserSid);
            }
            if (hidden) e.Set("Anomaly", "OwnerHidden");
            return e;
        }
    }
}
'@
}

# The fields the Network area reads from the kernel's symbols: the pool
# header's (Get-DbgEngPoolHeaderSpec), the EPROCESS fields of an owner that
# no way of the process scan found (to tell a process object from memory
# that was reused), and the reference count bits of its token
function Get-DbgEngNetworkLayoutSpec {
    $spec = Get-DbgEngPoolHeaderSpec
    $spec["_EPROCESS"] = @{
        Pcb = '^struct _KPROCESS\b'; UniqueProcessId = '^Ptr64\b'; InheritedFromUniqueProcessId = '^Ptr64\b'; ActiveProcessLinks = '^struct _LIST_ENTRY\b'
        CreateTime = '^union _LARGE_INTEGER\b'; ExitTime = '^union _LARGE_INTEGER\b'; ImageFileName = '^\[15\] UChar$'; Token = '^struct _EX_FAST_REF\b'
    }
    $spec["_EX_FAST_REF"] = @{ RefCnt = '^Bitfield\b' }
    return $spec
}

# The area: waits for the pass over the dump file, then reads its network
# objects (TimelineDbgEng.NetworkReader) into Net entries, and logs what the
# pass read
function Invoke-DbgEngNetworkArea {
    param($Context, $Area)
    $pass = $Context.RawPass
    if ($pass -isnot [TimelineDbgEng.RawPass]) {
        $Area.SetNotRead("the pass over the dump file was not started")
        return
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec (Get-DbgEngNetworkLayoutSpec) -Symbols @("nt!NtBuildNumber")
    $network = New-Object TimelineDbgEng.NetworkReader -ArgumentList $Context, $layout
    $network.Run($pass, $Area)
    if ($pass.TotalBytes -gt 0) {
        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        $gigabytes = ([double]$pass.ScannedBytes / 1GB).ToString("0.0", $invariant)
        $state = switch ($pass.State) { "Done" { "the whole file" } "TimeLimit" { "stopped at its time limit" } default { "$($pass.State)".ToLowerInvariant() } }
        $build = if ($network.Build -gt 0) { ", Windows build $($network.Build)" } else { "" }
        $sizes = if ($pass.ChecksSize("TTcb")) { ", allocation sizes checked during the pass" } else { "" }
        Write-DbgEngLog "    The pass over the dump file: $gigabytes GB in $(([double]$pass.Seconds).ToString('0.0', $invariant)) s ($state)$build$sizes"
    }
}
