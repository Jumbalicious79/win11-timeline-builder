# =============================================================
# Windows ARM64 memory dumps: the shared memory-reading layer
# Part of win11-timeline-builder. lib\memory\TimelineDbgEng.ps1 dot-sources
# this file (and the area files) in the helper's own PowerShell process;
# its C# fragment (Get-DbgEngReaderSource) is compiled with the host as one
# unit. Without this file, the processes and command lines are still read,
# and every other area is "not read (lib\memory\TimelineDbgEng.Reader.ps1 is
# missing)".
#
# What the areas (TimelineDbgEng.<Area>.ps1) get from it:
#   MemoryReader      reads of the dump's memory: Read (up to N bytes, fewer
#                     when part is not in the dump), TryRead, U8/U16/U32/U64,
#                     UnicodeString (64-bit and 32-bit), Utf16, Ascii,
#                     IsKernelAddress / IsKernelPointer / IsUserAddress.
#                     SessionReader (the engine, a page cache of at most
#                     64 MB keyed by process and page, a sticky process
#                     switch, the processes whose address space is gone)
#                     and FuncReader (a function: the tests).
#   Layout            structure offsets ("_TYPE.Field"), sizes ("_TYPE"),
#                     bitfields, kernel symbol addresses ("nt!Name") and the
#                     fields that are missing, from the kernel's symbols
#                     ('dt', New-DbgEngLayout); never hard-coded.
#   ProcessInfo       one process of the scan (EPROCESS, PID, parent, times,
#                     PEB, WoW64, token, protection, short name, FoundBy,
#                     Anomaly), with the fields ProcessDetails fills (UserSid,
#                     Integrity, Elevated, FullName, ImagePath) and the
#                     device-to-drive map it learns (DriveMap, one map shared
#                     by all processes).
#   MemoryContext     everything an area needs: Session, Reader, the
#                     processes (Processes, Find, WithPid), DriveMap, Shared
#                     (what an area offers the others and the joins, by
#                     name), Areas (the results so far), DumpPath,
#                     CaptureFileTime, ChurnTicks and BeforeChurn (the
#                     process scan's capture churn margin, so an area judges
#                     an object's age as the scan does) and RawPass (the
#                     background pass over the dump file,
#                     TimelineDbgEng.PoolScan.ps1).
#   AreaResult        what an area gives back: State (Read, Partial, NotRead),
#                     Entries (MemoryEntry: Kind and Key=value fields), the
#                     Coverage (counts for the log, notes for the report) and
#                     its Deadline (the area's time cap).
#   VadWalker         a process's memory regions (its VAD tree), walked in
#                     address order without recursion, with a visited set and
#                     a node cap; the inconsistencies of a live copy are
#                     counted (loops, order, parent links, VadCount), and the
#                     file name of a mapped region is cached per control area.
#   EntryWriter       the protocol lines of the entries ("TBDBG|E|<Kind>|
#                     <Key>:<Base64 of UTF-8>|..."): text read from memory
#                     stays in C# until it is Base64.
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies, see Get-DbgEngHostSource). C# 5.
function Get-DbgEngReaderSource {
    return @'
namespace TimelineDbgEng
{
    // Reads in a process's address space through the engine: the process
    // switch, and a read where the engine is (no switch per read)
    public interface IProcessMemory
    {
        // Makes 'eprocess' the process whose address space user addresses
        // are read in; false when that cannot be done (a process that has
        // exited: HRESULT 0xD0000147)
        bool SwitchProcess(ulong eprocess);
        // Up to count bytes at address, in the current process's address
        // space (a kernel address: any process); fewer, down to none, when
        // part of the range is not in the dump
        byte[] ReadCurrent(ulong address, int count);
        // Puts back the process the engine had before the first switch
        void RestoreProcess();
    }

    public sealed partial class Session : IProcessMemory
    {
        ReadVirtualFn readCurrentFn;
        U64Fn setProcessFn;
        OutU64Fn getProcessFn;
        ulong processBefore;
        bool processSaved;

        // The HRESULT of the last SwitchProcess
        public int LastSwitchHResult;

        public bool SwitchProcess(ulong eprocess)
        {
            if (systemObjects == IntPtr.Zero) return false;
            if (setProcessFn == null)
            {
                setProcessFn = Slot<U64Fn>(systemObjects, SystemSetImplicitProcess);
                getProcessFn = Slot<OutU64Fn>(systemObjects, SystemGetImplicitProcess);
            }
            if (!processSaved)
            {
                ulong current;
                if (getProcessFn(systemObjects, out current) >= 0) { processBefore = current; processSaved = true; }
            }
            int hr;
            try { hr = setProcessFn(systemObjects, eprocess); }
            catch (Exception) { hr = unchecked((int)0x80004005); }
            LastSwitchHResult = hr;
            return hr >= 0;
        }

        public byte[] ReadCurrent(ulong address, int count)
        {
            if (count <= 0 || dataSpaces == IntPtr.Zero) return new byte[0];
            if (readCurrentFn == null) readCurrentFn = Slot<ReadVirtualFn>(dataSpaces, DataReadVirtual);
            byte[] buffer = new byte[count];
            uint read;
            int hr = readCurrentFn(dataSpaces, address, buffer, (uint)count, out read);
            if (hr < 0 || read > (uint)count) read = 0;
            if (read == (uint)count) return buffer;
            byte[] part = new byte[read];
            Array.Copy(buffer, part, (int)read);
            return part;
        }

        public void RestoreProcess()
        {
            if (!processSaved || systemObjects == IntPtr.Zero || setProcessFn == null) return;
            try { setProcessFn(systemObjects, processBefore); } catch (Exception) { }
            processSaved = false;
        }
    }

    // Little-endian fields of a byte array; 0 (or "") outside it
    public static class Bytes
    {
        public static byte U8(byte[] b, int offset) { return (b != null && offset >= 0 && offset < b.Length) ? b[offset] : (byte)0; }
        public static ushort U16(byte[] b, int offset) { return (b != null && offset >= 0 && offset + 2 <= b.Length) ? BitConverter.ToUInt16(b, offset) : (ushort)0; }
        public static uint U32(byte[] b, int offset) { return (b != null && offset >= 0 && offset + 4 <= b.Length) ? BitConverter.ToUInt32(b, offset) : 0u; }
        public static ulong U64(byte[] b, int offset) { return (b != null && offset >= 0 && offset + 8 <= b.Length) ? BitConverter.ToUInt64(b, offset) : 0ul; }
        public static long I64(byte[] b, int offset) { return (long)U64(b, offset); }
        public static bool Has(byte[] b, int offset, int count) { return b != null && offset >= 0 && count >= 0 && offset + count <= b.Length; }
        // ASCII/UTF-8 text up to the first NUL (an invalid byte becomes U+FFFD)
        public static string Utf8Z(byte[] b, int offset, int maxBytes)
        {
            if (!Has(b, offset, 1)) return "";
            int end = offset;
            int limit = Math.Min(b.Length, offset + maxBytes);
            while (end < limit && b[end] != 0) end++;
            return Encoding.UTF8.GetString(b, offset, end - offset);
        }
    }

    // Text forms the rows use
    public static class Fmt
    {
        static readonly long MaxFileTime = DateTime.MaxValue.ToFileTimeUtc();
        // A FILETIME as the timeline gives a time (UTC, "yyyy-MM-dd
        // HH:mm:ss.fff"); "" for none (0 or less, or past the year 9999)
        public static string Time(long fileTime)
        {
            if (fileTime <= 0 || fileTime > MaxFileTime) return "";
            return DateTime.FromFileTimeUtc(fileTime).ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
        }
        // The same with all 7 decimals and the offset, as Volatility's JSON
        // and the P lines give it ("" for none)
        public static string IsoTime(long fileTime)
        {
            if (fileTime <= 0 || fileTime > MaxFileTime) return "";
            return DateTime.FromFileTimeUtc(fileTime).ToString("yyyy-MM-ddTHH:mm:ss.fffffff+00:00", CultureInfo.InvariantCulture);
        }
        public static string Hex(ulong value) { return "0x" + value.ToString("x", CultureInfo.InvariantCulture); }
        public static string Dec(long value) { return value.ToString(CultureInfo.InvariantCulture); }
    }

    public sealed class ReaderStats
    {
        public long Requests;          // Read calls
        public long EngineReads;       // pages read through the engine
        public long CacheHits;         // pages served from the cache
        public long Switches;          // process switches
        public long SwitchFailures;    // switches the engine refused
        public long UnreadablePages;   // pages not (fully) in the dump
        public long Evictions;         // times the full cache was emptied
        public override string ToString()
        {
            return "reads " + Requests + ", engine page reads " + EngineReads + ", cache hits " + CacheHits + ", process switches " + Switches +
                " (" + SwitchFailures + " refused), pages not in the dump " + UnreadablePages + ", cache emptied " + Evictions + " time(s)";
        }
    }

    // Reads of the dump's memory. process: the EPROCESS whose address space
    // a user address is in (0 for a kernel address, which is the same in
    // every process)
    public abstract class MemoryReader
    {
        // The most bytes a string read from memory may have
        public const int MaxStringBytes = 65536;
        // Addresses from here up are the kernel's (shared by all processes)
        public const ulong KernelStart = 0x8000000000000000UL;
        public readonly ReaderStats Stats = new ReaderStats();

        // Up to count bytes at address; fewer (down to none) when part of the
        // range is not in the dump
        public abstract byte[] Read(ulong process, ulong address, int count);

        // A process whose address space cannot be read (its switch failed)
        public virtual bool IsUnreadableProcess(ulong process) { return false; }

        public bool TryRead(ulong process, ulong address, int count, out byte[] bytes)
        {
            bytes = Read(process, address, count);
            if (bytes != null && bytes.Length == count) return true;
            bytes = null;
            return false;
        }

        public bool TryU8(ulong process, ulong address, out byte value)
        {
            byte[] b; value = 0;
            if (!TryRead(process, address, 1, out b)) return false;
            value = b[0]; return true;
        }
        public bool TryU16(ulong process, ulong address, out ushort value)
        {
            byte[] b; value = 0;
            if (!TryRead(process, address, 2, out b)) return false;
            value = BitConverter.ToUInt16(b, 0); return true;
        }
        public bool TryU32(ulong process, ulong address, out uint value)
        {
            byte[] b; value = 0;
            if (!TryRead(process, address, 4, out b)) return false;
            value = BitConverter.ToUInt32(b, 0); return true;
        }
        public bool TryU64(ulong process, ulong address, out ulong value)
        {
            byte[] b; value = 0;
            if (!TryRead(process, address, 8, out b)) return false;
            value = BitConverter.ToUInt64(b, 0); return true;
        }
        // The same, 0 when unreadable
        public ushort U16(ulong process, ulong address) { ushort v; TryU16(process, address, out v); return v; }
        public uint U32(ulong process, ulong address) { uint v; TryU32(process, address, out v); return v; }
        public ulong U64(ulong process, ulong address) { ulong v; TryU64(process, address, out v); return v; }

        // byteLength bytes of UTF-16 at buffer, cut at the first NUL (an
        // unpaired surrogate becomes U+FFFD); null when unreadable or longer
        // than MaxStringBytes
        public string Utf16(ulong process, ulong buffer, int byteLength)
        {
            if (byteLength < 0 || byteLength > MaxStringBytes) return null;
            byteLength -= byteLength % 2;
            if (byteLength == 0) return "";
            if (buffer == 0) return null;
            byte[] bytes;
            if (!TryRead(process, buffer, byteLength, out bytes)) return null;
            string text = Encoding.Unicode.GetString(bytes);
            int nul = text.IndexOf('\0');
            return nul >= 0 ? text.Substring(0, nul) : text;
        }

        // A _UNICODE_STRING of 64-bit Windows at address (Length +0,
        // MaximumLength +2, Buffer +8): its text, "" when empty, null when
        // unreadable or not a plausible string (odd length, longer than its
        // maximum or than MaxStringBytes)
        public string UnicodeString(ulong process, ulong address)
        {
            byte[] s;
            if (!TryRead(process, address, 16, out s)) return null;
            return StringAt(process, BitConverter.ToUInt16(s, 0), BitConverter.ToUInt16(s, 2), BitConverter.ToUInt64(s, 8));
        }

        // A UNICODE_STRING of a 32-bit (WoW64) process at address (Length +0,
        // MaximumLength +2, Buffer +4, a 32-bit pointer)
        public string UnicodeString32(ulong process, ulong address)
        {
            byte[] s;
            if (!TryRead(process, address, 8, out s)) return null;
            return StringAt(process, BitConverter.ToUInt16(s, 0), BitConverter.ToUInt16(s, 2), BitConverter.ToUInt32(s, 4));
        }

        // (A 16-bit length is never more than MaxStringBytes)
        string StringAt(ulong process, ushort length, ushort maximum, ulong buffer)
        {
            if (length == 0) return "";
            if ((length & 1) != 0 || (maximum != 0 && length > maximum)) return null;
            return Utf16(process, buffer, length);
        }

        // ASCII/UTF-8 text at address up to the first NUL (at most maxBytes)
        public string Ascii(ulong process, ulong address, int maxBytes)
        {
            if (maxBytes <= 0) return "";
            byte[] b = Read(process, address, Math.Min(maxBytes, MaxStringBytes));
            if (b == null || b.Length == 0) return null;
            return Bytes.Utf8Z(b, 0, b.Length);
        }

        // An address in the kernel's half: its top byte all ones
        public static bool IsKernelAddress(ulong address) { return (address >> 56) == 0xFF; }
        // A pointer of the kernel's structures: a kernel address, 8-byte
        // aligned (a small number of reused memory is not one)
        public static bool IsKernelPointer(ulong address) { return (address >> 56) == 0xFF && (address & 7) == 0; }
        // An address in a process's own (user) half
        public static bool IsUserAddress(ulong address) { return address != 0 && address < 0x0000800000000000UL; }
    }

    // The engine, through a page cache: every read is served from whole 4 KB
    // pages, kept by process and page (a kernel page once for all); a user
    // page is read in its process's address space, switched to only when
    // another process's page is needed (sticky). A process whose switch
    // fails is remembered (its user reads give nothing). The cache holds at
    // most maxCacheBytes and is emptied when full.
    public sealed class SessionReader : MemoryReader
    {
        struct PageKey : IEquatable<PageKey>
        {
            public readonly ulong Space;
            public readonly ulong Page;
            public PageKey(ulong space, ulong page) { Space = space; Page = page; }
            public bool Equals(PageKey other) { return Space == other.Space && Page == other.Page; }
            public override bool Equals(object obj) { return obj is PageKey && Equals((PageKey)obj); }
            public override int GetHashCode() { return (Space.GetHashCode() * 397) ^ Page.GetHashCode(); }
        }

        public const int PageSize = 4096;
        readonly IProcessMemory memory;
        readonly int maxPages;
        readonly Dictionary<PageKey, byte[]> cache = new Dictionary<PageKey, byte[]>();
        readonly HashSet<ulong> unreadable = new HashSet<ulong>();
        ulong current;
        bool switched;

        public SessionReader(IProcessMemory memory, int maxCacheBytes)
        {
            if (memory == null) throw new ArgumentNullException("memory");
            this.memory = memory;
            maxPages = Math.Max(16, maxCacheBytes / PageSize);
        }

        public int CachedPages { get { return cache.Count; } }
        public int UnreadableProcessCount { get { return unreadable.Count; } }
        public override bool IsUnreadableProcess(ulong process) { return unreadable.Contains(process); }

        public override byte[] Read(ulong process, ulong address, int count)
        {
            Stats.Requests++;
            if (count <= 0) return new byte[0];
            bool kernel = address >= KernelStart;
            ulong space = kernel ? 0 : process;
            if (!kernel && (process == 0 || unreadable.Contains(process))) return new byte[0];
            byte[] result = new byte[count];
            int done = 0;
            ulong at = address;
            while (done < count)
            {
                int offset = (int)(at & (PageSize - 1));
                byte[] page = Page(space, at >> 12);
                if (page == null || page.Length <= offset) break;
                int n = Math.Min(page.Length - offset, count - done);
                Buffer.BlockCopy(page, offset, result, done, n);
                done += n;
                at += (ulong)n;
                if (page.Length < PageSize || at == 0) break;
                // Never from the user half into the kernel half
                if (!kernel && at >= KernelStart) break;
            }
            if (done == count) return result;
            byte[] part = new byte[done];
            Buffer.BlockCopy(result, 0, part, 0, done);
            return part;
        }

        byte[] Page(ulong space, ulong pageNumber)
        {
            PageKey key = new PageKey(space, pageNumber);
            byte[] bytes;
            if (cache.TryGetValue(key, out bytes)) { Stats.CacheHits++; return bytes; }
            if (space != 0 && (!switched || current != space))
            {
                Stats.Switches++;
                if (!memory.SwitchProcess(space))
                {
                    Stats.SwitchFailures++;
                    unreadable.Add(space);
                    switched = false;
                    return null;
                }
                current = space;
                switched = true;
            }
            Stats.EngineReads++;
            bytes = memory.ReadCurrent(pageNumber << 12, PageSize);
            if (bytes == null) bytes = new byte[0];
            if (bytes.Length < PageSize) Stats.UnreadablePages++;
            if (cache.Count >= maxPages) { cache.Clear(); Stats.Evictions++; }
            cache[key] = bytes;
            return bytes;
        }

        // Puts back the engine's process (call when the areas are done)
        public void Restore()
        {
            memory.RestoreProcess();
            switched = false;
            current = 0;
        }
    }

    // Reads through a function (process, address, count) -> bytes: the
    // tests' memory maps
    public sealed class FuncReader : MemoryReader
    {
        readonly Func<ulong, ulong, int, byte[]> read;
        public FuncReader(Func<ulong, ulong, int, byte[]> read)
        {
            if (read == null) throw new ArgumentNullException("read");
            this.read = read;
        }
        public override byte[] Read(ulong process, ulong address, int count)
        {
            Stats.Requests++;
            if (count <= 0) return new byte[0];
            byte[] b = read(process, address, count);
            if (b == null) return new byte[0];
            if (b.Length <= count) return b;
            byte[] part = new byte[count];
            Buffer.BlockCopy(b, 0, part, 0, count);
            return part;
        }
    }

    // IProcessMemory through functions (the tests: a SessionReader without
    // the engine). switcher: false refuses a process; reader gets the
    // current process (0 for a kernel address)
    public sealed class FuncProcessMemory : IProcessMemory
    {
        readonly Func<ulong, bool> switcher;
        readonly Func<ulong, ulong, int, byte[]> reader;
        ulong current;
        public int SwitchCalls;
        public int ReadCalls;
        public int RestoreCalls;
        public FuncProcessMemory(Func<ulong, bool> switcher, Func<ulong, ulong, int, byte[]> reader)
        {
            if (reader == null) throw new ArgumentNullException("reader");
            this.switcher = switcher;
            this.reader = reader;
        }
        public bool SwitchProcess(ulong eprocess)
        {
            SwitchCalls++;
            if (switcher != null && !switcher(eprocess)) return false;
            current = eprocess;
            return true;
        }
        public byte[] ReadCurrent(ulong address, int count)
        {
            ReadCalls++;
            byte[] b = reader(address >= MemoryReader.KernelStart ? 0 : current, address, count);
            return b ?? new byte[0];
        }
        public void RestoreProcess() { RestoreCalls++; current = 0; }
    }

    // Structure offsets, sizes and bitfields from the kernel's symbols
    // ('dt'), and kernel symbol addresses: "_TYPE.Field" -> offset,
    // "_TYPE" -> size, "nt!Name" -> address. Missing: each field, type or
    // symbol asked for that the symbols do not give (or give with another
    // type than expected).
    public sealed class Layout
    {
        public readonly Dictionary<string, int> Offsets = new Dictionary<string, int>(StringComparer.Ordinal);
        public readonly Dictionary<string, string> Types = new Dictionary<string, string>(StringComparer.Ordinal);
        public readonly Dictionary<string, int[]> Bits = new Dictionary<string, int[]>(StringComparer.Ordinal);
        public readonly Dictionary<string, int> Sizes = new Dictionary<string, int>(StringComparer.Ordinal);
        public readonly Dictionary<string, ulong> Symbols = new Dictionary<string, ulong>(StringComparer.Ordinal);
        public readonly List<string> Missing = new List<string>();

        public int Off(string key) { int v; return Offsets.TryGetValue(key, out v) ? v : -1; }
        public bool Has(string key) { return Offsets.ContainsKey(key); }
        public int Size(string type) { int v; return Sizes.TryGetValue(type, out v) ? v : 0; }
        public ulong Symbol(string name) { ulong v; return Symbols.TryGetValue(name, out v) ? v : 0; }
        public bool Complete { get { return Missing.Count == 0; } }
        public bool HasAll(string[] keys)
        {
            foreach (string k in keys) { if (!Offsets.ContainsKey(k)) return false; }
            return true;
        }
        // Those of keys that are not here, comma-separated ("" for none)
        public string MissingOf(string[] keys)
        {
            List<string> gone = new List<string>();
            foreach (string k in keys) { if (!Offsets.ContainsKey(k)) gone.Add(k); }
            return string.Join(", ", gone.ToArray());
        }
        public void Set(string key, int offset) { Offsets[key] = offset; }
        public void SetBits(string key, int position, int width) { Bits[key] = new int[] { position, width }; if (!Offsets.ContainsKey(key)) Offsets[key] = 0; }
        public void SetSize(string type, int size) { Sizes[type] = size; }
        public void SetSymbol(string name, ulong address) { Symbols[name] = address; }

        // The bitfield key of value; 0 when the symbols do not give it
        public ulong BitsOf(ulong value, string key)
        {
            int[] b;
            if (!Bits.TryGetValue(key, out b)) return 0;
            return Extract(value, b[0], b[1]);
        }
        public static ulong Extract(ulong value, int position, int width)
        {
            if (position < 0 || width <= 0 || position + width > 64) return 0;
            ulong v = value >> position;
            return width == 64 ? v : v & ((1UL << width) - 1);
        }
        // The reference-count bits of an _EX_FAST_REF (RefCnt; 4 bits when
        // the symbols do not say), to mask off a pointer
        public ulong FastRefMask
        {
            get
            {
                int[] b;
                if (Bits.TryGetValue("_EX_FAST_REF.RefCnt", out b) && b[0] == 0 && b[1] >= 1 && b[1] <= 15) return (1UL << b[1]) - 1;
                return 0xF;
            }
        }
    }

    // One process of the scan, for the areas
    public sealed class ProcessInfo
    {
        public ulong Eprocess;
        public long Pid;
        public long Ppid;
        public long CreateTime;          // FILETIME, 0 when none
        public long ExitTime;
        public ulong Peb;
        public ulong Wow64;              // EPROCESS.WoW64Process (0: a 64-bit process)
        public ulong Token;              // EPROCESS.Token, reference count bits masked off
        public byte Protection;          // EPROCESS.Protection (_PS_PROTECTION)
        public string ShortName = "";    // EPROCESS.ImageFileName (at most 15 bytes)
        public string FoundBy = "";
        public string Anomaly = "";
        public byte[] Block;             // the EPROCESS's bytes, when read
        // (A process whose address space cannot be read: the reader's
        // IsUnreadableProcess, after its switch failed)
        // Filled by the ProcessDetails area (TimelineDbgEng.Tokens.ps1,
        // TimelineDbgEng.ImagePaths.ps1); "" until then
        public string UserSid = "";
        public string Integrity = "";
        public string Elevated = "";
        public string FullName = "";
        public string ImagePath = "";
        // The device-to-drive map ("\Device\HarddiskVolume3" -> "C:"), one
        // map for all processes (MemoryContext.DriveMap)
        public Dictionary<string, string> DriveMap;

        // The name the rows give: the full name when known, else the short one
        public string Name { get { return FullName.Length > 0 ? FullName : ShortName; } }
        // The create time as the rows' ProcessCreated= gives it ("" for none)
        public string CreatedText { get { return Fmt.Time(CreateTime); } }
        // A protected process (PP or PPL): _PS_PROTECTION.Type is not 0
        public bool IsProtected { get { return (Protection & 7) != 0; } }

        // A process from its EPROCESS bytes, at the offsets of layout
        // (fields the layout does not have stay 0)
        public static ProcessInfo FromBlock(ulong eprocess, byte[] block, Layout layout)
        {
            ProcessInfo p = new ProcessInfo();
            p.Eprocess = eprocess;
            p.Block = block;
            if (block == null || layout == null) return p;
            p.Pid = Bytes.I64(block, layout.Off("_EPROCESS.UniqueProcessId"));
            p.Ppid = Bytes.I64(block, layout.Off("_EPROCESS.InheritedFromUniqueProcessId"));
            p.CreateTime = Bytes.I64(block, layout.Off("_EPROCESS.CreateTime"));
            p.ExitTime = Bytes.I64(block, layout.Off("_EPROCESS.ExitTime"));
            p.Peb = Bytes.U64(block, layout.Off("_EPROCESS.Peb"));
            p.Wow64 = Bytes.U64(block, layout.Off("_EPROCESS.WoW64Process"));
            p.Token = Bytes.U64(block, layout.Off("_EPROCESS.Token")) & ~layout.FastRefMask;
            p.Protection = Bytes.U8(block, layout.Off("_EPROCESS.Protection"));
            int name = layout.Off("_EPROCESS.ImageFileName");
            if (name >= 0) p.ShortName = Bytes.Utf8Z(block, name, 15);
            return p;
        }
    }

    // Counts for the log, notes for the report
    public sealed class Coverage
    {
        readonly List<string> order = new List<string>();
        readonly Dictionary<string, long> counts = new Dictionary<string, long>(StringComparer.Ordinal);
        public readonly List<string> Notes = new List<string>();

        public void Count(string name) { Count(name, 1); }
        public void Count(string name, long n)
        {
            if (!counts.ContainsKey(name)) { order.Add(name); counts[name] = 0; }
            counts[name] += n;
        }
        public long Get(string name) { long v; return counts.TryGetValue(name, out v) ? v : 0; }
        // A note for the report (each once): a sentence part without ";",
        // " -- ", ": " or parentheses at its ends (the notes are joined with
        // "; " into the area's note)
        public void Note(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            if (!Notes.Contains(text)) Notes.Add(text);
        }
        public string Text { get { return string.Join("; ", Notes.ToArray()); } }
        // "name 1, other 2" in the order counted
        public string CountsText
        {
            get
            {
                List<string> parts = new List<string>();
                foreach (string k in order) parts.Add(k + " " + counts[k].ToString(CultureInfo.InvariantCulture));
                return string.Join(", ", parts.ToArray());
            }
        }
    }

    // An area's time cap
    public sealed class Deadline
    {
        readonly Stopwatch watch = Stopwatch.StartNew();
        public readonly double Seconds;
        public Deadline(double seconds) { Seconds = seconds; }
        public bool Expired { get { return Seconds > 0 && watch.Elapsed.TotalSeconds >= Seconds; } }
        public double Elapsed { get { return watch.Elapsed.TotalSeconds; } }
    }

    // One entry of the protocol: a Kind and Key=value fields in the order
    // set (keys: a letter, then letters and digits)
    public sealed class MemoryEntry
    {
        public readonly string Kind;
        readonly List<string> keys = new List<string>();
        readonly Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);

        public MemoryEntry(string kind)
        {
            if (!EntryWriter.IsName(kind)) throw new ArgumentException("not an entry kind: " + kind);
            Kind = kind;
        }
        public MemoryEntry Set(string key, string value)
        {
            if (!EntryWriter.IsName(key)) throw new ArgumentException("not an entry key: " + key);
            if (!values.ContainsKey(key)) keys.Add(key);
            values[key] = value ?? "";
            return this;
        }
        public MemoryEntry Set(string key, long value) { return Set(key, value.ToString(CultureInfo.InvariantCulture)); }
        public MemoryEntry SetHex(string key, ulong value) { return Set(key, Fmt.Hex(value)); }
        public string Get(string key) { string v; return values.TryGetValue(key, out v) ? v : ""; }
        public bool Has(string key) { return values.ContainsKey(key); }
        public void Remove(string key) { if (values.Remove(key)) keys.Remove(key); }
        public string[] Keys { get { return keys.ToArray(); } }
        public string ToLine() { return EntryWriter.Line(this); }
    }

    // The protocol lines of the entries; Base64 of UTF-8 here, in C#
    public static class EntryWriter
    {
        public static bool IsName(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length > 64) return false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bool letter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
                if (!letter && (i == 0 || c < '0' || c > '9')) return false;
            }
            return true;
        }
        public static string Base64(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
        }
        // "TBDBG|E|<Kind>|<Key>:<Base64>|..."
        public static string Line(MemoryEntry entry)
        {
            StringBuilder line = new StringBuilder("TBDBG|E|");
            line.Append(entry.Kind);
            foreach (string key in entry.Keys)
            {
                line.Append('|').Append(key).Append(':').Append(Base64(entry.Get(key)));
            }
            return line.ToString();
        }
        public static string[] Lines(IEnumerable<MemoryEntry> entries)
        {
            List<string> lines = new List<string>();
            if (entries != null) { foreach (MemoryEntry e in entries) { if (e != null) lines.Add(Line(e)); } }
            return lines.ToArray();
        }
    }

    // What one area gives back. State: Read, Partial (some of it: the notes
    // say what is missing) or NotRead (the note says why)
    public sealed class AreaResult
    {
        public readonly string Name;
        public string State = "Read";
        public readonly List<MemoryEntry> Entries = new List<MemoryEntry>();
        public readonly Coverage Coverage = new Coverage();
        public readonly Deadline Deadline;
        public double Seconds;

        public AreaResult(string name, double capSeconds)
        {
            Name = name;
            Deadline = new Deadline(capSeconds);
        }
        public MemoryEntry Add(string kind)
        {
            MemoryEntry e = new MemoryEntry(kind);
            Entries.Add(e);
            return e;
        }
        public void SetNotRead(string why)
        {
            State = "NotRead";
            Coverage.Notes.Clear();
            Coverage.Note(why);
        }
        public void SetPartial(string note)
        {
            if (State == "Read") State = "Partial";
            Coverage.Note(note);
        }
        // True when the area's time cap is reached (then it is Partial, and
        // says so): a loop checks it and stops
        public bool TimeUp()
        {
            if (!Deadline.Expired) return false;
            SetPartial("stopped at its time limit of " + Deadline.Seconds.ToString("0", CultureInfo.InvariantCulture) + " s");
            return true;
        }
        public string Note { get { return Coverage.Text; } }
        public int Rows { get { return Entries.Count; } }
    }

    // Everything an area needs
    public sealed class MemoryContext
    {
        public Session Session;              // null in the tests
        public MemoryReader Reader;
        public Layout ProcessLayout;         // the EPROCESS fields of ProcessInfo
        public readonly List<ProcessInfo> Processes = new List<ProcessInfo>();
        public readonly Dictionary<ulong, ProcessInfo> ByEprocess = new Dictionary<ulong, ProcessInfo>();
        public readonly Dictionary<string, string> DriveMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // What an area offers the others and the joins, by name (e.g. a
        // handle lookup, the in-memory Services key, the module lists)
        public readonly Dictionary<string, object> Shared = new Dictionary<string, object>(StringComparer.Ordinal);
        // The results of the areas run so far, by area name
        public readonly Dictionary<string, AreaResult> Areas = new Dictionary<string, AreaResult>(StringComparer.Ordinal);
        public string DumpPath = "";
        public long CaptureFileTime;         // when the capture started (FILETIME), 0 when not known
        // Capture churn (Get-DbgEngChurnSeconds in TimelineDbgEng.ps1): an
        // object created within this many 100 ns units before the capture
        // started can have been changed or removed while memory was copied
        public long ChurnTicks = 120L * 10000000L;
        // Created early enough before the capture to be judged (hidden, not
        // capture churn); false when the capture start or the time is unknown
        public bool BeforeChurn(long createTime)
        {
            return CaptureFileTime > 0 && createTime > 0 && createTime < CaptureFileTime - ChurnTicks;
        }
        // The background pass over the dump file (TimelineDbgEng.PoolScan.ps1),
        // or null; disposed when the areas are done if it is IDisposable
        public object RawPass;

        public void Add(ProcessInfo p)
        {
            if (p == null) return;
            p.DriveMap = DriveMap;
            Processes.Add(p);
            if (!ByEprocess.ContainsKey(p.Eprocess)) ByEprocess[p.Eprocess] = p;
        }
        public ProcessInfo Find(ulong eprocess) { ProcessInfo p; return ByEprocess.TryGetValue(eprocess, out p) ? p : null; }
        public List<ProcessInfo> WithPid(long pid)
        {
            List<ProcessInfo> found = new List<ProcessInfo>();
            foreach (ProcessInfo p in Processes) { if (p.Pid == pid) found.Add(p); }
            return found;
        }
    }

    // One memory region of a process (a VAD)
    public sealed class VadNode
    {
        public ulong Node;               // the VAD's kernel address
        public ulong Start;              // first byte
        public ulong End;                // last byte
        public int VadType;              // _MMVAD_FLAGS.VadType (VadWalker.VadImageMap: an image)
        public int Protection;           // _MMVAD_FLAGS.Protection (the memory manager's protection index)
        public bool PrivateMemory;       // _MMVAD_FLAGS.PrivateMemory
        public ulong Subsection;         // _MMVAD.Subsection (0 for private memory)
        public bool IsImage { get { return VadType == VadWalker.VadImageMap; } }
        public ulong Size { get { return End >= Start ? End - Start + 1 : 0; } }
    }

    // A walk of one process's VAD tree
    public sealed class VadWalk
    {
        public readonly List<VadNode> Nodes = new List<VadNode>();
        public bool RootRead;            // the tree's root pointer was read (0 is an empty tree)
        public int Loops;                // a node reached twice
        public int OrderErrors;          // a node that does not start after the one before it
        public int ParentMismatches;     // a child whose parent link is not its parent
        public int Unreadable;           // nodes not in the dump (or not kernel pointers)
        public bool Capped;              // the node cap was reached
        public long VadCount = -1;       // EPROCESS.VadCount (-1: not read)
        // Nothing a live copy can change was seen: the walk can be trusted
        // to be the whole tree
        public bool Consistent
        {
            get { return RootRead && Loops == 0 && OrderErrors == 0 && Unreadable == 0 && !Capped && (VadCount < 0 || VadCount == Nodes.Count); }
        }
    }

    // Walks VAD trees (EPROCESS.VadRoot, _RTL_AVL_TREE of _MMVAD nodes) in
    // address order, without recursion, with a visited set and a node cap.
    // A file name comes from _MMVAD.Subsection -> _SUBSECTION.ControlArea ->
    // _CONTROL_AREA.FilePointer (_EX_FAST_REF) -> _FILE_OBJECT.FileName,
    // cached per control area. MMVAD.FileObject is never used (never set on
    // the dumps this was checked on).
    public sealed class VadWalker
    {
        // _MI_VAD_TYPE is not in the kernel's symbols: VadImageMap is 2
        // (the item-c probe matched every loader DllBase to a VAD of this
        // type on Windows 11 26100 ARM64)
        public const int VadImageMap = 2;
        public const int DefaultCap = 20000;
        public static readonly string[] Fields = new string[] {
            "_EPROCESS.VadRoot", "_EPROCESS.VadCount", "_RTL_BALANCED_NODE.Left", "_RTL_BALANCED_NODE.Right", "_RTL_BALANCED_NODE.ParentValue",
            "_MMVAD_SHORT.StartingVpn", "_MMVAD_SHORT.EndingVpn", "_MMVAD_SHORT.StartingVpnHigh", "_MMVAD_SHORT.EndingVpnHigh", "_MMVAD_SHORT.u",
            "_MMVAD_FLAGS.VadType", "_MMVAD_FLAGS.Protection", "_MMVAD_FLAGS.PrivateMemory", "_MMVAD.Subsection",
            "_SUBSECTION.ControlArea", "_CONTROL_AREA.FilePointer", "_FILE_OBJECT.FileName" };

        readonly MemoryReader reader;
        readonly Layout layout;
        readonly int left, right, parent, startVpn, endVpn, startHigh, endHigh, flags, subsection, vadRoot, vadCount;
        readonly int nodeBytes;
        readonly Dictionary<ulong, string> names = new Dictionary<ulong, string>();
        public int NameCacheHits;

        public VadWalker(MemoryReader reader, Layout layout)
        {
            this.reader = reader;
            this.layout = layout;
            left = layout.Off("_RTL_BALANCED_NODE.Left");
            right = layout.Off("_RTL_BALANCED_NODE.Right");
            parent = layout.Off("_RTL_BALANCED_NODE.ParentValue");
            startVpn = layout.Off("_MMVAD_SHORT.StartingVpn");
            endVpn = layout.Off("_MMVAD_SHORT.EndingVpn");
            startHigh = layout.Off("_MMVAD_SHORT.StartingVpnHigh");
            endHigh = layout.Off("_MMVAD_SHORT.EndingVpnHigh");
            flags = layout.Off("_MMVAD_SHORT.u");
            subsection = layout.Off("_MMVAD.Subsection");
            vadRoot = layout.Off("_EPROCESS.VadRoot");
            vadCount = layout.Off("_EPROCESS.VadCount");
            int shortSize = Math.Max(layout.Size("_MMVAD_SHORT"), flags + 4);
            nodeBytes = Math.Max(shortSize, subsection + 8);
        }

        // "" when every field the walk needs is in the layout, else which are not
        public string MissingFields { get { return layout.MissingOf(Fields); } }
        public bool Ready { get { return layout.HasAll(Fields); } }

        public VadWalk Walk(ProcessInfo process) { return Walk(process, DefaultCap); }

        public VadWalk Walk(ProcessInfo process, int cap)
        {
            VadWalk walk = new VadWalk();
            if (!Ready || process == null) return walk;
            ulong root;
            byte[] block = process.Block;
            if (Bytes.Has(block, vadRoot, 8)) root = BitConverter.ToUInt64(block, vadRoot);
            else if (!reader.TryU64(0, process.Eprocess + (ulong)vadRoot, out root)) return walk;
            walk.RootRead = true;
            if (Bytes.Has(block, vadCount, 8)) walk.VadCount = (long)BitConverter.ToUInt64(block, vadCount);
            else { ulong c; if (reader.TryU64(0, process.Eprocess + (ulong)vadCount, out c)) walk.VadCount = (long)c; }
            if (root == 0) return walk;

            HashSet<ulong> visited = new HashSet<ulong>();
            Stack<KeyValuePair<ulong, byte[]>> stack = new Stack<KeyValuePair<ulong, byte[]>>();
            ulong node = root;
            ulong expectedParent = 0;
            bool isRoot = true;
            ulong previousEnd = 0;
            bool havePrevious = false;
            while (true)
            {
                // Down the left edge
                while (node != 0)
                {
                    if (visited.Count >= cap) { walk.Capped = true; node = 0; break; }
                    if (!MemoryReader.IsKernelPointer(node)) { walk.Unreadable++; node = 0; break; }
                    if (!visited.Add(node)) { walk.Loops++; node = 0; break; }
                    byte[] bytes = reader.Read(0, node, nodeBytes);
                    if (bytes == null || bytes.Length < flags + 4) { walk.Unreadable++; node = 0; break; }
                    if (!isRoot && (Bytes.U64(bytes, parent) & ~3UL) != expectedParent) walk.ParentMismatches++;
                    isRoot = false;
                    stack.Push(new KeyValuePair<ulong, byte[]>(node, bytes));
                    expectedParent = node;
                    node = Bytes.U64(bytes, left);
                }
                if (stack.Count == 0 || walk.Capped) break;
                KeyValuePair<ulong, byte[]> top = stack.Pop();
                VadNode v = Decode(top.Key, top.Value);
                if (havePrevious && v.Start <= previousEnd) walk.OrderErrors++;
                previousEnd = v.End;
                havePrevious = true;
                walk.Nodes.Add(v);
                expectedParent = top.Key;
                node = Bytes.U64(top.Value, right);
            }
            return walk;
        }

        VadNode Decode(ulong node, byte[] bytes)
        {
            VadNode v = new VadNode();
            v.Node = node;
            ulong start = Bytes.U32(bytes, startVpn) | ((ulong)Bytes.U8(bytes, startHigh) << 32);
            ulong end = Bytes.U32(bytes, endVpn) | ((ulong)Bytes.U8(bytes, endHigh) << 32);
            v.Start = start << 12;
            v.End = (end << 12) | 0xFFF;
            ulong f = Bytes.U32(bytes, flags);
            v.VadType = (int)layout.BitsOf(f, "_MMVAD_FLAGS.VadType");
            v.Protection = (int)layout.BitsOf(f, "_MMVAD_FLAGS.Protection");
            v.PrivateMemory = layout.BitsOf(f, "_MMVAD_FLAGS.PrivateMemory") != 0;
            if (!v.PrivateMemory && Bytes.Has(bytes, subsection, 8))
            {
                ulong s = BitConverter.ToUInt64(bytes, subsection);
                if (MemoryReader.IsKernelPointer(s)) v.Subsection = s;
            }
            return v;
        }

        // The control area of a mapped region (0 when it has none or it is
        // not in the dump)
        public ulong ControlArea(VadNode v)
        {
            if (v == null || v.Subsection == 0) return 0;
            ulong area;
            if (!reader.TryU64(0, v.Subsection + (ulong)layout.Off("_SUBSECTION.ControlArea"), out area)) return 0;
            return MemoryReader.IsKernelPointer(area) ? area : 0;
        }

        // The file name of a mapped region, as the file object has it (a
        // path without its volume, "\Windows\System32\ntdll.dll"); "" for
        // private memory or a mapping without a file, null when it is not in
        // the dump. Cached per control area.
        public string FileName(VadNode v)
        {
            ulong area = ControlArea(v);
            if (area == 0) return v != null && v.Subsection == 0 ? "" : null;
            string cached;
            if (names.TryGetValue(area, out cached)) { NameCacheHits++; return cached; }
            string name = null;
            ulong pointer;
            if (reader.TryU64(0, area + (ulong)layout.Off("_CONTROL_AREA.FilePointer"), out pointer))
            {
                ulong file = pointer & ~layout.FastRefMask;
                if (file == 0) name = "";
                else if (MemoryReader.IsKernelPointer(file)) name = reader.UnicodeString(0, file + (ulong)layout.Off("_FILE_OBJECT.FileName"));
            }
            names[area] = name;
            return name;
        }
    }
}
'@
}

# --- Layouts from the kernel's symbols -----------------------------------------

# The layout of one kernel type, once per run ('dt -v' through
# Get-DbgEngTypeLayout; Read-DbgEngDump empties the cache for each dump)
function Get-DbgEngCachedTypeLayout {
    param($Session, [string]$TypeName)
    if ($null -eq $script:DbgEngTypeCache) { $script:DbgEngTypeCache = @{} }
    if (-not $script:DbgEngTypeCache.ContainsKey($TypeName)) { $script:DbgEngTypeCache[$TypeName] = Get-DbgEngTypeLayout -Session $Session -TypeName $TypeName }
    return $script:DbgEngTypeCache[$TypeName]
}

# A Layout (offsets as "_TYPE.Field", sizes as "_TYPE", bitfields, symbol
# addresses as "nt!Name") from the kernel's symbols. -Spec: @{ "_TYPE" =
# @{ Field = '<regex its type text must match>' (or "" for any type) } }.
# A field the symbols do not have, or have with another type, is not set
# and is named in Missing ("_TYPE.Field"); a type they do not have at all
# is named as "_TYPE". -Symbols: names such as "nt!PsLoadedModuleList"
# (Missing names each one the engine cannot resolve). -Layout: one to add
# to (else a new one).
function New-DbgEngLayout {
    param($Session, [System.Collections.IDictionary]$Spec, [string[]]$Symbols = @(), $Layout)
    if ($null -eq $Layout) { $Layout = New-Object TimelineDbgEng.Layout }
    if ($Spec) {
        foreach ($typeName in @($Spec.Keys)) {
            $type = Get-DbgEngCachedTypeLayout -Session $Session -TypeName ([string]$typeName)
            # get_Count(): .Count of a hashtable with a field named Count
            # (_CHILD_LIST) is that field's offset
            if ($type.Offsets.get_Count() -eq 0) {
                if (-not $Layout.Missing.Contains([string]$typeName)) { $Layout.Missing.Add([string]$typeName) }
                continue
            }
            if ($type.Size -gt 0) { $Layout.SetSize([string]$typeName, [int]$type.Size) }
            $fields = $Spec[$typeName]
            foreach ($fieldName in @($fields.Keys)) {
                $key = "$typeName.$fieldName"
                $pattern = [string]$fields[$fieldName]
                if (-not $type.Offsets.ContainsKey([string]$fieldName) -or ($pattern -and $type.Types[[string]$fieldName] -notmatch $pattern)) {
                    if (-not $Layout.Missing.Contains($key)) { $Layout.Missing.Add($key) }
                    continue
                }
                $Layout.Set($key, [int]$type.Offsets[[string]$fieldName])
                $Layout.Types[$key] = [string]$type.Types[[string]$fieldName]
                if ($type.Bits.ContainsKey([string]$fieldName)) { $Layout.SetBits($key, [int]$type.Bits[[string]$fieldName][0], [int]$type.Bits[[string]$fieldName][1]) }
            }
        }
    }
    foreach ($name in @($Symbols)) {
        if (-not $name) { continue }
        $address = Get-DbgEngSymbolAddress -Session $Session -Name $name
        if ($address -eq 0) {
            if (-not $Layout.Missing.Contains($name)) { $Layout.Missing.Add($name) }
            continue
        }
        $Layout.SetSymbol($name, [uint64]$address)
    }
    return $Layout
}

# The EPROCESS fields of ProcessInfo, and the reference count bits of an
# _EX_FAST_REF (its Token). WoW64Process, Protection and ActiveThreads may
# be missing (ProcessInfo leaves them 0).
function Get-DbgEngProcessLayoutSpec {
    return @{
        "_EPROCESS"    = @{
            UniqueProcessId = '^Ptr64\b'; InheritedFromUniqueProcessId = '^Ptr64\b'; CreateTime = '^union _LARGE_INTEGER\b'; ExitTime = '^union _LARGE_INTEGER\b'
            Peb = '^Ptr64\b'; Token = '^struct _EX_FAST_REF\b'; ImageFileName = '^\[15\] UChar$'; ActiveThreads = '^Uint4B$'
            WoW64Process = '^Ptr64\b'; Protection = '^struct _PS_PROTECTION\b'; VadRoot = '^struct _RTL_AVL_TREE\b'; VadCount = '^Uint8B$'
        }
        "_EX_FAST_REF" = @{ RefCnt = '^Bitfield\b' }
    }
}

# The VAD walker's layout (VadWalker.Fields) and the walker, once per
# context (MemoryContext.Shared["VadWalker"]): the regions of a process for
# the Modules and PrivateCode areas. Its MissingFields says what the
# symbols lack.
function Get-DbgEngVadWalker {
    param($Context)
    if ($Context.Shared.ContainsKey("VadWalker")) { return $Context.Shared["VadWalker"] }
    $spec = @{
        "_EPROCESS"          = @{ VadRoot = '^struct _RTL_AVL_TREE\b'; VadCount = '' }
        "_RTL_BALANCED_NODE" = @{ Left = '^Ptr64\b'; Right = '^Ptr64\b'; ParentValue = '^Uint8B$' }
        "_MMVAD_SHORT"       = @{ StartingVpn = '^Uint4B$'; EndingVpn = '^Uint4B$'; StartingVpnHigh = '^UChar$'; EndingVpnHigh = '^UChar$'; u = '^union\b' }
        "_MMVAD_FLAGS"       = @{ VadType = '^Bitfield\b'; Protection = '^Bitfield\b'; PrivateMemory = '^Bitfield\b' }
        "_MMVAD"             = @{ Subsection = '^Ptr64\b' }
        "_SUBSECTION"        = @{ ControlArea = '^Ptr64\b' }
        "_CONTROL_AREA"      = @{ FilePointer = '^struct _EX_FAST_REF\b' }
        "_FILE_OBJECT"       = @{ FileName = '^struct _UNICODE_STRING\b' }
        "_EX_FAST_REF"       = @{ RefCnt = '^Bitfield\b' }
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec $spec
    $walker = New-Object TimelineDbgEng.VadWalker -ArgumentList $Context.Reader, $layout
    $Context.Shared["VadWalker"] = $walker
    return $walker
}

# --- The context the areas share -------------------------------------------------

# A MemoryContext for the areas: a SessionReader over -Memory (the engine
# session, or a test's IProcessMemory) with a page cache of -CacheBytes,
# and one ProcessInfo per process of the scan, in the scan's order: from
# its EPROCESS bytes (-Blocks, aligned with -Processes; read through the
# reader when a block is missing and the layout gives the EPROCESS size),
# else from the entry itself (the debugger engine's own list). FoundBy and
# Anomaly come from the entry.
function New-DbgEngContext {
    param($Session, $Memory, [object[]]$Processes, [object[]]$Blocks = @(), $ProcessLayout, [string]$DumpPath = "", [long]$CaptureFileTime = 0, [int]$CacheBytes = 64MB)
    if ($null -eq $Memory) { $Memory = $Session }
    $context = New-Object TimelineDbgEng.MemoryContext
    if ($Session -is [TimelineDbgEng.Session]) { $context.Session = $Session }
    $context.Reader = New-Object TimelineDbgEng.SessionReader -ArgumentList $Memory, $CacheBytes
    if ($null -eq $ProcessLayout) { $ProcessLayout = New-Object TimelineDbgEng.Layout }
    $context.ProcessLayout = $ProcessLayout
    $context.DumpPath = $DumpPath
    $context.CaptureFileTime = $CaptureFileTime
    # The process scan's churn margin, so the areas judge as it does
    if (Get-Command -Name "Get-DbgEngChurnSeconds" -CommandType Function -ErrorAction SilentlyContinue) { $context.ChurnTicks = [long](Get-DbgEngChurnSeconds) * 10000000L }
    $eprocessSize = $ProcessLayout.Size("_EPROCESS")
    $entries = @($Processes)
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $eprocess = [uint64]0
        if ("$($entry.Offset)" -match '^0x([0-9a-fA-F]{1,16})$') { $eprocess = [Convert]::ToUInt64($Matches[1], 16) }
        $block = $null
        if ($i -lt @($Blocks).Count -and $Blocks[$i] -is [byte[]]) { $block = [byte[]]$Blocks[$i] }
        elseif ($eprocessSize -gt 0 -and [TimelineDbgEng.MemoryReader]::IsKernelPointer($eprocess)) {
            $bytes = $context.Reader.Read(0, $eprocess, $eprocessSize)
            if ($bytes.Length -eq $eprocessSize) { $block = $bytes }
        }
        $info = [TimelineDbgEng.ProcessInfo]::FromBlock($eprocess, $block, $ProcessLayout)
        if ($null -eq $block) {
            # The engine's own list: what its entry has
            if ($null -ne $entry.PID) { $info.Pid = [long]$entry.PID }
            if ($null -ne $entry.PPID) { $info.Ppid = [long]$entry.PPID }
            $info.ShortName = [string]$entry.ImageFileName
            foreach ($pair in @(@("CreateTime", "CreateTime"), @("ExitTime", "ExitTime"))) {
                $text = [string]$entry.($pair[0])
                $time = [datetime]::MinValue
                if ($text -and [datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$time)) {
                    $info.($pair[1]) = $time.ToFileTimeUtc()
                }
            }
        }
        if ($entry.PSObject.Properties["FoundBy"]) { $info.FoundBy = [string]$entry.FoundBy }
        if ($entry.PSObject.Properties["Anomaly"]) { $info.Anomaly = [string]$entry.Anomaly }
        $context.Add($info)
    }
    return $context
}
