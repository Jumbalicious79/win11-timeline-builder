# =============================================================
# Windows ARM64 memory dumps: the one read-only pass over the dump file (network objects; the services fallback)
# Part of win11-timeline-builder (work package WP6). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it does: the kernel keeps the network endpoints in pool memory that
# no symbol file describes, so they are found the way Volatility's
# windows.netscan finds them on x64: by the tag in each pool allocation's
# header. The pass reads the dump file itself (not through the debugger
# engine), from start to end once, on a thread of its own, while the other
# areas run: read-only, shared, sequential, 16 MB at a time. Only a full
# memory dump (DumpType 1: the physical memory runs one page after another
# after the 0x2000-byte header) is scanned; any other kind is "not read".
# It looks at every 16-byte unit for the tags it was given (a pool tag at
# _POOL_HEADER.PoolTag, from the kernel's symbols; a user-mode record tag at
# its own offset) and keeps a copy of the first bytes of each hit, with its
# physical address. The pass never calls the engine (the engine is used on
# the main thread only), has a time limit of its own (the Network area's,
# Get-DbgEngAreas) and stops when it is disposed.
#
#   Get-DbgEngPoolScanSource   its C# (DumpFileLayout, PoolHit, RawPass)
#   Get-DbgEngRawPassTags      the tags the pass looks for
#   Start-DbgEngRawPass -Context <MemoryContext>
#                              starts it before the first area and sets
#                              $Context.RawPass (a RawPass: disposed when the
#                              areas are done); a pass that cannot start is
#                              still set, with State NotRead and Why
# Other areas may use its hits: $Context.RawPass.Wait(ms), then
# .HitsOf("<tag>") (copies of the bytes from the tag's 16-byte unit on).
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngPoolScanSource {
    return @'
namespace TimelineDbgEng
{
    // The memory of a full crash dump of 64-bit Windows: a 0x2000-byte
    // header ("PAGE" "DU64"; DUMP_HEADER64 in Microsoft's dump format), then
    // the physical memory runs one 4 KB page after another. The runs are in
    // the header: PhysicalMemoryBlock at +0x88 (NumberOfRuns ULONG,
    // NumberOfPages ULONG64 at +0x90, then BasePage and PageCount, ULONG64
    // each, per run from +0x98; 700 bytes, room for 42 runs). DumpType is
    // at +0xF98 (1: a full dump). Only a full dump has its pages in this
    // order; the other kinds have a page map this does not read.
    public sealed class DumpFileLayout
    {
        public const int HeaderBytes = 0x2000;
        public const int PageBytes = 0x1000;
        public const int MaxRuns = 42;
        // Why the file cannot be scanned ("" when it can)
        public string Problem = "";
        public uint DumpType;
        public ulong[] RunBase = new ulong[0];     // first physical page of each run
        public ulong[] RunPages = new ulong[0];    // its pages
        public long[] RunFile = new long[0];       // the file offset of its first page
        public long MemoryBytes;                    // the memory the header describes
        public long FileBytes;                      // of it, what the file holds (less when it was cut short)

        public static DumpFileLayout FromHeader(byte[] header, long fileLength)
        {
            DumpFileLayout d = new DumpFileLayout();
            if (header == null || header.Length < HeaderBytes || fileLength < HeaderBytes) { d.Problem = "the dump file's header could not be read"; return d; }
            if (Bytes.U32(header, 0) != 0x45474150u || Bytes.U32(header, 4) != 0x34365544u) { d.Problem = "the dump file is not a crash dump of 64-bit Windows"; return d; }
            d.DumpType = Bytes.U32(header, 0xF98);
            if (d.DumpType != 1) { d.Problem = "the dump file is not a full memory dump [dump type " + d.DumpType.ToString(CultureInfo.InvariantCulture) + "]"; return d; }
            uint runs = Bytes.U32(header, 0x88);
            ulong pages = Bytes.U64(header, 0x90);
            if (runs == 0 || runs > MaxRuns) { d.Problem = "the dump file's list of physical memory runs cannot be read"; return d; }
            d.RunBase = new ulong[runs];
            d.RunPages = new ulong[runs];
            d.RunFile = new long[runs];
            ulong total = 0;
            long file = HeaderBytes;
            for (int r = 0; r < (int)runs; r++)
            {
                ulong basePage = Bytes.U64(header, 0x98 + r * 16);
                ulong count = Bytes.U64(header, 0xA0 + r * 16);
                // At most 2^36 pages (256 TB) per run, below 2^52 (the
                // physical address space): a header that is not damaged
                if (count == 0 || count > (1UL << 36) || basePage > (1UL << 52)) { d.Problem = "the dump file's list of physical memory runs cannot be read"; return d; }
                d.RunBase[r] = basePage;
                d.RunPages[r] = count;
                d.RunFile[r] = file;
                file += (long)count * PageBytes;
                total += count;
            }
            if (total != pages) { d.Problem = "the dump file's physical memory runs do not add up"; return d; }
            d.MemoryBytes = (long)total * PageBytes;
            d.FileBytes = Math.Min(d.MemoryBytes, fileLength - HeaderBytes);
            d.FileBytes -= d.FileBytes % PageBytes;
            return d;
        }

        int RunOf(long fileOffset)
        {
            for (int r = RunFile.Length - 1; r >= 0; r--)
            {
                if (fileOffset >= RunFile[r]) return fileOffset < RunFile[r] + (long)RunPages[r] * PageBytes ? r : -1;
            }
            return -1;
        }

        // The physical address of a file offset (ulong.MaxValue outside the memory)
        public ulong PhysicalOf(long fileOffset)
        {
            int r = RunOf(fileOffset);
            if (r < 0) return ulong.MaxValue;
            return RunBase[r] * PageBytes + (ulong)(fileOffset - RunFile[r]);
        }

        // Where the run of physically adjacent pages that holds fileOffset
        // ends in the file (fileOffset itself when it is outside the memory)
        public long RunEnd(long fileOffset)
        {
            int r = RunOf(fileOffset);
            if (r < 0) return fileOffset;
            return Math.Min(RunFile[r] + (long)RunPages[r] * PageBytes, HeaderBytes + FileBytes);
        }
    }

    // One hit of the pass: a 16-byte unit with one of the tags
    public sealed class PoolHit
    {
        public string Tag;
        public long FileOffset;          // of the unit (a pool tag's: its pool header)
        public ulong Physical;           // its physical address
        public int PageOffset;           // its offset in its 4 KB page
        // A copy of the bytes from the unit on (the tag's copy length; fewer
        // at the end of a run of physically adjacent pages). Bytes past the
        // unit's own page are the next physical page's, which is not always
        // the next page of the object (PageOffset says where the page ends).
        public byte[] Bytes;
        internal int Want;
    }

    // The one pass over a full memory dump file, on a thread of its own: the
    // hits of its tags. Start() reads the header (a dump that is not a full
    // one, or a file that cannot be opened, makes it NotRead at once) and
    // starts the thread. The engine is never called from here.
    public sealed class RawPass : IDisposable
    {
        public const int BufferBytes = 16 * 1024 * 1024;
        public const int MaxHitsPerTag = 8192;

        sealed class TagSpec
        {
            public string Tag;
            public uint Value;
            public int Offset;
            public int CopyBytes;
            public readonly List<PoolHit> Hits = new List<PoolHit>();
            public int Dropped;
        }

        public readonly string DumpPath;
        public readonly double CapSeconds;
        public DumpFileLayout Layout;
        // Kernel layout facts for the areas that read the hits (the pool
        // header's fields from the kernel's symbols)
        public Layout PoolLayout;
        readonly List<TagSpec> tags = new List<TagSpec>();
        readonly ManualResetEvent done = new ManualResetEvent(false);
        readonly Stopwatch watch = new Stopwatch();
        Thread thread;
        volatile bool cancel;
        volatile string state = "NotStarted";
        long scanned;
        bool disposed;

        // Why it was not read, or how it ended badly ("" otherwise)
        public string Why = "";
        public double Seconds;

        public RawPass(string dumpPath, double capSeconds)
        {
            DumpPath = dumpPath ?? "";
            CapSeconds = capSeconds;
        }

        // A tag to look for: its 4 ASCII characters at offsetInUnit of a
        // 16-byte unit; copyBytes of each hit are kept, from the unit on
        public void AddTag(string tag, int offsetInUnit, int copyBytes)
        {
            if (state != "NotStarted") throw new InvalidOperationException("the pass has started");
            if (tag == null || tag.Length != 4 || offsetInUnit < 0 || offsetInUnit > 12 || copyBytes < 16 || copyBytes > 0x4000) throw new ArgumentException("not a tag to look for: " + tag);
            TagSpec t = new TagSpec();
            t.Tag = tag;
            t.Value = (uint)tag[0] | ((uint)tag[1] << 8) | ((uint)tag[2] << 16) | ((uint)tag[3] << 24);
            t.Offset = offsetInUnit;
            t.CopyBytes = copyBytes;
            tags.Add(t);
        }

        // NotStarted, Running, Done (the whole file was read), TimeLimit (it
        // stopped at CapSeconds: the hits of the part read), Stopped
        // (disposed before the end), NotRead (Why says why)
        public string State { get { return state; } }
        public bool Finished { get { return done.WaitOne(0); } }
        // Waits up to milliseconds for the pass to end; true when it has
        public bool Wait(int milliseconds) { return done.WaitOne(Math.Max(0, milliseconds)); }
        public long ScannedBytes { get { return Interlocked.Read(ref scanned); } }
        public long TotalBytes { get { return Layout == null ? 0 : Layout.FileBytes; } }

        public void SetNotRead(string why)
        {
            if (state == "Running") throw new InvalidOperationException("the pass is running");
            state = "NotRead";
            Why = why ?? "";
            done.Set();
        }

        public void Start()
        {
            if (state != "NotStarted") return;
            watch.Start();
            if (tags.Count == 0) { SetNotRead("no tags to look for"); return; }
            byte[] header = new byte[DumpFileLayout.HeaderBytes];
            long length;
            try
            {
                using (FileStream fs = Open())
                {
                    length = fs.Length;
                    if (ReadFully(fs, header, header.Length) < header.Length) header = null;
                }
            }
            catch (Exception e) { SetNotRead("the dump file could not be opened [" + e.Message + "]"); return; }
            Layout = DumpFileLayout.FromHeader(header, length);
            if (Layout.Problem.Length > 0) { SetNotRead(Layout.Problem); return; }
            state = "Running";
            thread = new Thread(Run);
            thread.IsBackground = true;
            thread.Priority = ThreadPriority.BelowNormal;
            thread.Name = "TimelineDbgEng pass over the dump file";
            thread.Start();
        }

        FileStream Open()
        {
            return new FileStream(DumpPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
        }

        static int ReadFully(FileStream fs, byte[] buffer, int count)
        {
            int got = 0;
            while (got < count)
            {
                int n = fs.Read(buffer, got, count - got);
                if (n <= 0) break;
                got += n;
            }
            return got;
        }

        void Run()
        {
            try
            {
                // The tags by their offset in the unit, and a table of the
                // first characters at each offset (most units fail there)
                List<int> offsets = new List<int>();
                foreach (TagSpec t in tags) { if (!offsets.Contains(t.Offset)) offsets.Add(t.Offset); }
                int[] at = offsets.ToArray();
                bool[][] first = new bool[at.Length][];
                TagSpec[][] byOffset = new TagSpec[at.Length][];
                for (int o = 0; o < at.Length; o++)
                {
                    first[o] = new bool[256];
                    List<TagSpec> list = new List<TagSpec>();
                    foreach (TagSpec t in tags)
                    {
                        if (t.Offset != at[o]) continue;
                        first[o][t.Value & 0xFF] = true;
                        list.Add(t);
                    }
                    byOffset[o] = list.ToArray();
                }
                List<PoolHit> pending = new List<PoolHit>();
                using (FileStream fs = Open())
                {
                    byte[] buffer = new byte[BufferBytes];
                    long position = DumpFileLayout.HeaderBytes;
                    long end = DumpFileLayout.HeaderBytes + Layout.FileBytes;
                    fs.Position = position;
                    while (position < end)
                    {
                        if (cancel) { state = "Stopped"; break; }
                        if (CapSeconds > 0 && watch.Elapsed.TotalSeconds >= CapSeconds) { state = "TimeLimit"; break; }
                        int want = (int)Math.Min((long)BufferBytes, end - position);
                        int got = ReadFully(fs, buffer, want);
                        got -= got % 16;
                        if (got <= 0) break;
                        for (int i = 0; i + 16 <= got; i += 16)
                        {
                            for (int o = 0; o < at.Length; o++)
                            {
                                int p = i + at[o];
                                if (!first[o][buffer[p]]) continue;
                                uint v = (uint)buffer[p] | ((uint)buffer[p + 1] << 8) | ((uint)buffer[p + 2] << 16) | ((uint)buffer[p + 3] << 24);
                                foreach (TagSpec t in byOffset[o])
                                {
                                    if (t.Value == v) Record(t, buffer, i, got, position, pending);
                                }
                            }
                        }
                        position += got;
                        Interlocked.Exchange(ref scanned, position - DumpFileLayout.HeaderBytes);
                        if (got < want) break;
                    }
                    // The copies that ran past the end of a buffer
                    if (!cancel)
                    {
                        foreach (PoolHit h in pending)
                        {
                            byte[] copy = new byte[h.Want];
                            fs.Position = h.FileOffset;
                            int n = ReadFully(fs, copy, copy.Length);
                            if (n < copy.Length) { byte[] part = new byte[n]; Buffer.BlockCopy(copy, 0, part, 0, n); copy = part; }
                            h.Bytes = copy;
                        }
                    }
                }
                if (state == "Running") state = "Done";
            }
            catch (Exception e)
            {
                Why = "the dump file could not be read [" + e.Message + "]";
                state = "NotRead";
            }
            finally
            {
                Seconds = watch.Elapsed.TotalSeconds;
                done.Set();
            }
        }

        void Record(TagSpec t, byte[] buffer, int i, int got, long position, List<PoolHit> pending)
        {
            if (t.Hits.Count >= MaxHitsPerTag) { t.Dropped++; return; }
            long fileOffset = position + i;
            PoolHit h = new PoolHit();
            h.Tag = t.Tag;
            h.FileOffset = fileOffset;
            h.Physical = Layout.PhysicalOf(fileOffset);
            h.PageOffset = (int)((fileOffset - DumpFileLayout.HeaderBytes) & (DumpFileLayout.PageBytes - 1));
            int copy = (int)Math.Max(0L, Math.Min((long)t.CopyBytes, Layout.RunEnd(fileOffset) - fileOffset));
            if (i + copy <= got)
            {
                h.Bytes = new byte[copy];
                Buffer.BlockCopy(buffer, i, h.Bytes, 0, copy);
            }
            else
            {
                h.Bytes = new byte[0];
                h.Want = copy;
                pending.Add(h);
            }
            t.Hits.Add(h);
        }

        TagSpec Find(string tag)
        {
            foreach (TagSpec t in tags) { if (t.Tag == tag) return t; }
            return null;
        }

        // The hits of a tag, in file order (none while the pass runs)
        public PoolHit[] HitsOf(string tag)
        {
            TagSpec t = Find(tag);
            if (t == null || !Finished) return new PoolHit[0];
            return t.Hits.ToArray();
        }

        // Hits of a tag past MaxHitsPerTag (not kept)
        public int DroppedOf(string tag)
        {
            TagSpec t = Find(tag);
            return (t == null || !Finished) ? 0 : t.Dropped;
        }

        // Stops the pass (it ends at the next 16 MB) and waits for its thread
        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            cancel = true;
            Thread t = thread;
            if (t != null && t.IsAlive) t.Join(30000);
            done.Set();
        }
    }
}
'@
}

# The tags the pass looks for: Tag, Offset in the 16-byte unit (-1: the
# pool header's PoolTag, from the kernel's symbols) and Copy (the bytes kept
# from the unit on). The network objects of tcpip.sys (their layouts:
# TimelineDbgEng.Network.ps1): TTcb (a TCP connection), TcpL (a TCP
# listener), UdpA (a UDP endpoint), TcTW (a connection in TIME_WAIT,
# counted only); AfdE (a socket of afd.sys, counted per process). Sc19: a
# service record in services.exe's heap, the tag 8 bytes into its 16-byte
# unit, for the Services area when it cannot find the service list itself.
function Get-DbgEngRawPassTags {
    return @(
        [PSCustomObject]@{ Tag = "TTcb"; Offset = -1; Copy = 0x400 }
        [PSCustomObject]@{ Tag = "TcpL"; Offset = -1; Copy = 0x400 }
        [PSCustomObject]@{ Tag = "UdpA"; Offset = -1; Copy = 0x400 }
        [PSCustomObject]@{ Tag = "TcTW"; Offset = -1; Copy = 0x100 }
        [PSCustomObject]@{ Tag = "AfdE"; Offset = -1; Copy = 0x80 }
        [PSCustomObject]@{ Tag = "Sc19"; Offset = 8; Copy = 0x200 }
    )
}

# The pool header's fields the pass and its readers need, from the
# kernel's symbols
function Get-DbgEngPoolHeaderSpec {
    return @{ "_POOL_HEADER" = @{ PoolTag = '^Uint4B$'; BlockSize = '^Bitfield\b' } }
}

# Starts the pass over the dump file (TimelineDbgEng.RawPass) on a thread
# of its own and sets $Context.RawPass. Its time limit is the Network
# area's. A pass that cannot start (no dump file, not a full dump, no pool
# header in the kernel's symbols) is set too, NotRead with Why.
function Start-DbgEngRawPass {
    param($Context)
    $cap = 300
    foreach ($area in @(Get-DbgEngAreas)) { if ($area.Name -eq "Network") { $cap = [double]$area.CapSeconds } }
    $pass = New-Object TimelineDbgEng.RawPass -ArgumentList ([string]$Context.DumpPath), ([double]$cap)
    $Context.RawPass = $pass
    if (-not $Context.DumpPath -or -not (Test-Path -LiteralPath $Context.DumpPath -PathType Leaf)) {
        $pass.SetNotRead("the dump file is not there to be read")
        return
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec (Get-DbgEngPoolHeaderSpec)
    $pass.PoolLayout = $layout
    if (-not $layout.Has("_POOL_HEADER.PoolTag") -or $layout.Size("_POOL_HEADER") -ne 16) {
        $pass.SetNotRead("the kernel's symbols do not describe its pool header as expected")
        return
    }
    foreach ($tag in @(Get-DbgEngRawPassTags)) {
        $offset = if ($tag.Offset -lt 0) { $layout.Off("_POOL_HEADER.PoolTag") } else { [int]$tag.Offset }
        $pass.AddTag([string]$tag.Tag, [int]$offset, [int]$tag.Copy)
    }
    $pass.Start()
}
