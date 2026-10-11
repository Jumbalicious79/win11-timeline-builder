# =============================================================
# Windows ARM64 memory dumps: console command history (item h)
# Part of win11-timeline-builder (work package WP5). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads: the commands typed in console windows (cmd.exe, a "set /p"
# answer, any console program that reads a line), as the console host keeps
# them: every conhost.exe (and OpenConsole.exe, the same code under another
# name) holds one command history per client program in a list of its own
# data section. PowerShell's own history (PSReadLine) is not kept there; the
# builder reads it from ConsoleHost_history.txt.
#
# The layout is in no symbol file: it is the declaration order of
# Microsoft's open-source console code (github.com/microsoft/terminal),
# compiled with Microsoft's C++ library for 64-bit Windows (the same on x64
# and ARM64), and was confirmed on three Windows 11 ARM64 dumps:
#   src/host/history.h        static std::list<CommandHistory> s_historyLists
#                             (head node, size); a node is {next, prev,
#                             value}; CommandHistory is {std::vector<std::wstring>
#                             _commands (first, last, end); int _maxCommands;
#                             std::wstring _appName; HANDLE _processHandle;
#                             DWORD Flags; int LastDisplayed}; the oldest
#                             command first
#   std::wstring              16 bytes of text in place (7 characters at
#                             most) or a pointer, size +0x10, capacity +0x18
#   src/server/ProcessHandle.h  _processHandle is the console's own record of
#                             the attached client (ConsoleProcessHandle), not
#                             a Windows handle: three pointers, a bool, then
#                             the client's process ID (+0x1C)
# How it is found: the image base from the process's PEB (offset from the
# kernel's symbols), its writable sections from the image's own section
# table, and in them every (head, size) pair whose nodes form a closed ring
# with consistent back links and plausible histories. Nothing else is
# trusted: a list that fails a check is not one, and when no console host
# whose data is in the dump has such a list, the area is "not read" (this
# Windows keeps it differently), never wrong rows. A console host whose own
# page with the list or image header is not in the dump gets the list's
# offset (and, without a PEB, the image base) from another host of the same
# program, checked the same way. A client process ID is given only when it
# is a process of the scan with the history's program name.
#
#   Get-DbgEngConsoleSource     its C#: namespace TimelineDbgEng { ... } blocks
#                               only, no using lines (the host's using
#                               header applies), C# 5
#   Invoke-DbgEngConsoleArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Console (rows: Add-DbgEngConsoleRows in TimelineMemoryRows.ps1)
#     PID, ProcessCreated (the console host's), App (the client program's
#     file name), ClientPID ("" when no client is attached or it is not
#     confirmed), Index (0 = the oldest), HistoryCount, FoundBy, Command,
#     User (the console host's token SID, when ProcessDetails read it)
# =============================================================

# The C# of this file. C# 5.
function Get-DbgEngConsoleSource {
    return @'
namespace TimelineDbgEng
{
    // One command history of a console host (a CommandHistory)
    public sealed class ConsoleHistoryRecord
    {
        public ulong Node;                  // its list node, in the console host
        public byte[] Raw;                  // the node's bytes
        public string App;                  // the client program's file name; null when not readable
        public ulong ClientRecord;          // the console's record of the attached client, 0 when none
        public long ClientPid = -1;         // the client's process ID when confirmed, else -1
        public bool ClientUnmatched;        // the record's process ID is no process of the scan with this program name
        public int MaxCommands;
        public uint Flags;
        public ulong CommandsFirst;
        public int CommandCount;
        // Oldest first; an item is null when it is not in the dump
        public readonly List<string> Commands = new List<string>();
    }

    // A list of histories found in a console host
    public sealed class ConsoleHistoryList
    {
        public ulong Rva;                   // where its (head, size) pair is, from the image base
        public ulong Head;
        public readonly List<ConsoleHistoryRecord> Histories = new List<ConsoleHistoryRecord>();
    }

    // What one console host gave
    public sealed class ConsoleHostScan
    {
        public ProcessInfo Process;
        public ulong ImageBase;
        public bool BaseRead;               // the image base from its own PEB
        public bool HeaderRead;             // its image's section table
        public int WritablePages;
        public int MissingPages;            // writable pages not in the dump
        public readonly List<ConsoleHistoryList> Candidates = new List<ConsoleHistoryList>();
        public ConsoleHistoryList List;     // the list used, null when none
        public bool FromSibling;            // found at another console host's offset (or image base)
        public bool Ambiguous;              // more than one list passed the checks
    }

    // Reads console command histories (see TimelineDbgEng.Console.ps1 for
    // where the layout comes from)
    public sealed class ConsoleHistoryReader
    {
        // std::list node and CommandHistory (src/host/history.h)
        public const int NodeNext = 0x00;
        public const int NodePrev = 0x08;
        public const int CommandsFirstAt = 0x10;
        public const int CommandsLastAt = 0x18;
        public const int CommandsEndAt = 0x20;
        public const int MaxCommandsAt = 0x28;
        public const int AppNameAt = 0x30;
        public const int ClientRecordAt = 0x50;
        public const int FlagsAt = 0x58;
        public const int NodeBytes = 0x60;
        // std::wstring of Microsoft's C++ library, 64-bit
        public const int WStringBytes = 0x20;
        public const int WStringSizeAt = 0x10;
        public const int WStringCapacityAt = 0x18;
        public const int WStringInPlace = 7;
        // ConsoleProcessHandle (src/server/ProcessHandle.h): the client's process ID
        public const int ClientProcessIdAt = 0x1C;
        // Checks: the console's own limits for the number of histories and
        // their size are 999; a little room above them
        public const int MaxHistories = 999;
        public const int MaxCommandCount = 9999;
        public const int MaxAppChars = 1024;
        // The most writable image pages searched per console host (1 MB)
        public const int MaxSectionPages = 256;
        public const int PageSize = 4096;
        const uint SectionWritable = 0x80000000;

        readonly MemoryReader reader;
        readonly int pebImageBase;

        public ConsoleHistoryReader(MemoryReader reader, int pebImageBaseOffset)
        {
            if (reader == null) throw new ArgumentNullException("reader");
            this.reader = reader;
            pebImageBase = pebImageBaseOffset;
        }

        // conhost.exe, or OpenConsole.exe (its short name is cut to 14 characters)
        public static bool IsConsoleHost(ProcessInfo p)
        {
            if (p == null) return false;
            string full = p.FullName ?? "";
            string name = p.ShortName ?? "";
            if (string.Equals(full, "conhost.exe", StringComparison.OrdinalIgnoreCase) || string.Equals(full, "OpenConsole.exe", StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(name, "conhost.exe", StringComparison.OrdinalIgnoreCase)) return true;
            return name.Length >= 14 && "OpenConsole.exe".StartsWith(name, StringComparison.OrdinalIgnoreCase);
        }

        // A process of the scan has the program name of a history: its full
        // name, or its short name (cut to 14 characters or more)
        public static bool NameMatches(ProcessInfo p, string app)
        {
            if (p == null || string.IsNullOrEmpty(app)) return false;
            if (string.Equals(p.FullName ?? "", app, StringComparison.OrdinalIgnoreCase)) return true;
            string name = p.ShortName ?? "";
            if (string.Equals(name, app, StringComparison.OrdinalIgnoreCase)) return true;
            return name.Length >= 14 && app.Length > name.Length && app.StartsWith(name, StringComparison.OrdinalIgnoreCase);
        }

        static bool IsImageBase(ulong address) { return MemoryReader.IsUserAddress(address) && (address & 0xFFFF) == 0; }
        static bool IsUserPointer(ulong address) { return MemoryReader.IsUserAddress(address) && (address & 7) == 0; }

        // The writable sections (rva, size) of the image whose first page
        // is header; null when it is not a PE image header
        public static List<KeyValuePair<uint, uint>> WritableSections(byte[] header)
        {
            if (!Bytes.Has(header, 0, 0x40) || header[0] != 0x4D || header[1] != 0x5A) return null;
            uint pe = Bytes.U32(header, 0x3C);
            if (pe < 0x40 || pe > (uint)header.Length - 24) return null;
            int at = (int)pe;
            if (Bytes.U32(header, at) != 0x00004550) return null;
            int count = Bytes.U16(header, at + 6);
            int table = at + 24 + Bytes.U16(header, at + 20);
            if (count == 0 || count > 96) return null;
            List<KeyValuePair<uint, uint>> sections = new List<KeyValuePair<uint, uint>>();
            for (int i = 0; i < count; i++)
            {
                int s = table + 40 * i;
                if (!Bytes.Has(header, s, 40)) return null;
                if ((Bytes.U32(header, s + 36) & SectionWritable) == 0) continue;
                uint size = Bytes.U32(header, s + 8);
                if (size == 0) size = Bytes.U32(header, s + 16);
                if (size == 0) continue;
                sections.Add(new KeyValuePair<uint, uint>(Bytes.U32(header, s + 12), size));
            }
            return sections;
        }

        // The image base from the process's PEB, the writable sections of
        // its image, and every list in them that passes the checks
        public ConsoleHostScan Scan(ProcessInfo p, AreaResult area)
        {
            ConsoleHostScan scan = new ConsoleHostScan();
            scan.Process = p;
            ulong process = p.Eprocess;
            ulong imageBase;
            if (pebImageBase < 0 || !MemoryReader.IsUserAddress(p.Peb) || !reader.TryU64(process, p.Peb + (ulong)pebImageBase, out imageBase) || !IsImageBase(imageBase)) return scan;
            scan.ImageBase = imageBase;
            scan.BaseRead = true;
            byte[] header;
            if (!reader.TryRead(process, imageBase, PageSize, out header)) return scan;
            List<KeyValuePair<uint, uint>> sections = WritableSections(header);
            if (sections == null) return scan;
            scan.HeaderRead = true;
            int budget = MaxSectionPages;
            foreach (KeyValuePair<uint, uint> section in sections)
            {
                long wanted = ((long)section.Value + PageSize - 1) / PageSize;
                int pages = (int)Math.Min(wanted, (long)budget);
                budget -= pages;
                ScanSection(scan, imageBase, section.Key, pages, area);
                if (budget <= 0 || area.TimeUp()) break;
            }
            return scan;
        }

        void ScanSection(ConsoleHostScan scan, ulong imageBase, uint rva, int pages, AreaResult area)
        {
            if (pages <= 0) return;
            ulong process = scan.Process.Eprocess;
            byte[] data = new byte[pages * PageSize];
            bool[] present = new bool[pages];
            for (int i = 0; i < pages; i++)
            {
                scan.WritablePages++;
                byte[] page;
                if (!reader.TryRead(process, imageBase + (ulong)rva + (ulong)i * PageSize, PageSize, out page)) { scan.MissingPages++; continue; }
                Buffer.BlockCopy(page, 0, data, i * PageSize, PageSize);
                present[i] = true;
            }
            for (int o = 0; o + 16 <= data.Length; o += 8)
            {
                if (!present[o / PageSize] || !present[(o + 15) / PageSize]) continue;
                ulong head = BitConverter.ToUInt64(data, o);
                ulong count = BitConverter.ToUInt64(data, o + 8);
                if (count == 0 || count > MaxHistories || !IsUserPointer(head)) continue;
                ConsoleHistoryList list = ReadList(process, head, (int)count);
                if (list == null) continue;
                list.Rva = (ulong)rva + (ulong)o;
                scan.Candidates.Add(list);
                if (scan.Candidates.Count >= 8 || area.TimeUp()) return;
            }
        }

        // The list whose (head, size) pair is at imageBase + rva in the
        // process; null when there is none that passes the checks
        public ConsoleHistoryList TryAt(ulong process, ulong imageBase, ulong rva)
        {
            byte[] pair;
            if (!reader.TryRead(process, imageBase + rva, 16, out pair)) return null;
            ulong head = BitConverter.ToUInt64(pair, 0);
            ulong count = BitConverter.ToUInt64(pair, 8);
            if (count == 0 || count > MaxHistories || !IsUserPointer(head)) return null;
            ConsoleHistoryList list = ReadList(process, head, (int)count);
            if (list != null) list.Rva = rva;
            return list;
        }

        // The ring of count nodes from head: each node's back link is the
        // node before it, the last one leads back to head (and head back to
        // it), no node twice, and each holds a plausible history. null when
        // it is not such a list.
        public ConsoleHistoryList ReadList(ulong process, ulong head, int count)
        {
            byte[] h;
            if (count <= 0 || !reader.TryRead(process, head, 16, out h)) return null;
            ConsoleHistoryList list = new ConsoleHistoryList();
            list.Head = head;
            HashSet<ulong> seen = new HashSet<ulong>();
            seen.Add(head);
            ulong previous = head;
            ulong node = BitConverter.ToUInt64(h, NodeNext);
            for (int i = 0; i < count; i++)
            {
                if (!IsUserPointer(node) || !seen.Add(node)) return null;
                byte[] b;
                if (!reader.TryRead(process, node, NodeBytes, out b)) return null;
                if (BitConverter.ToUInt64(b, NodePrev) != previous) return null;
                ConsoleHistoryRecord r = Parse(node, b);
                if (r == null) return null;
                list.Histories.Add(r);
                previous = node;
                node = BitConverter.ToUInt64(b, NodeNext);
            }
            if (node != head || BitConverter.ToUInt64(h, NodePrev) != previous) return null;
            return list;
        }

        // A history from its node's bytes; null when they are not a
        // plausible one
        public static ConsoleHistoryRecord Parse(ulong node, byte[] b)
        {
            if (!Bytes.Has(b, 0, NodeBytes)) return null;
            ulong first = Bytes.U64(b, CommandsFirstAt);
            ulong last = Bytes.U64(b, CommandsLastAt);
            ulong end = Bytes.U64(b, CommandsEndAt);
            if (first > last || last > end) return null;
            if ((last - first) % WStringBytes != 0 || (end - first) % WStringBytes != 0) return null;
            if (first != 0 && (!IsUserPointer(first) || !MemoryReader.IsUserAddress(end))) return null;
            if (first == 0 && end != 0) return null;
            ulong count = (last - first) / WStringBytes;
            if (count > MaxCommandCount) return null;
            int max = BitConverter.ToInt32(b, MaxCommandsAt);
            if (max < 0 || max > MaxCommandCount) return null;
            ulong appSize = Bytes.U64(b, AppNameAt + WStringSizeAt);
            ulong appCapacity = Bytes.U64(b, AppNameAt + WStringCapacityAt);
            if (appCapacity < WStringInPlace || appSize > appCapacity || appSize > MaxAppChars) return null;
            if (appCapacity > WStringInPlace && !MemoryReader.IsUserAddress(Bytes.U64(b, AppNameAt))) return null;
            ulong client = Bytes.U64(b, ClientRecordAt);
            if (client != 0 && !IsUserPointer(client)) return null;
            ConsoleHistoryRecord r = new ConsoleHistoryRecord();
            r.Node = node;
            r.Raw = b;
            r.CommandsFirst = first;
            r.CommandCount = (int)count;
            r.MaxCommands = max;
            r.ClientRecord = client;
            r.Flags = Bytes.U32(b, FlagsAt);
            return r;
        }

        // A std::wstring at offset of b: its text, null when it is not
        // readable or not a plausible one
        public string WString(ulong process, byte[] b, int offset)
        {
            if (!Bytes.Has(b, offset, WStringBytes)) return null;
            ulong size = Bytes.U64(b, offset + WStringSizeAt);
            ulong capacity = Bytes.U64(b, offset + WStringCapacityAt);
            if (size > capacity || size > (ulong)(MemoryReader.MaxStringBytes / 2)) return null;
            if (size == 0) return "";
            if (capacity <= WStringInPlace) return Encoding.Unicode.GetString(b, offset, (int)size * 2);
            ulong pointer = Bytes.U64(b, offset);
            if (!MemoryReader.IsUserAddress(pointer)) return null;
            return reader.Utf16(process, pointer, (int)size * 2);
        }

        // The program names and the commands of a list's histories, and
        // their clients' process IDs (confirmed against the scan)
        public void ReadTexts(MemoryContext context, ulong process, ConsoleHistoryList list)
        {
            foreach (ConsoleHistoryRecord r in list.Histories)
            {
                r.App = WString(process, r.Raw, AppNameAt);
                if (r.ClientRecord != 0)
                {
                    uint pid;
                    if (reader.TryU32(process, r.ClientRecord + ClientProcessIdAt, out pid))
                    {
                        foreach (ProcessInfo c in context.WithPid(pid)) { if (NameMatches(c, r.App)) { r.ClientPid = pid; break; } }
                    }
                    if (r.ClientPid < 0) r.ClientUnmatched = true;
                }
                if (r.CommandCount == 0) continue;
                byte[] all = reader.Read(process, r.CommandsFirst, r.CommandCount * WStringBytes);
                for (int i = 0; i < r.CommandCount; i++)
                {
                    if (all == null || all.Length < (i + 1) * WStringBytes) { r.Commands.Add(null); continue; }
                    r.Commands.Add(WString(process, all, i * WStringBytes));
                }
            }
        }
    }

    // The Console area: every console host's histories as Console entries
    public static class ConsoleHistoryArea
    {
        static string Key(ProcessInfo p) { return (p.ShortName ?? "").ToLowerInvariant(); }

        static void Learn<T>(Dictionary<string, List<T>> map, string key, T value)
        {
            List<T> values;
            if (!map.TryGetValue(key, out values)) { values = new List<T>(); map[key] = values; }
            if (!values.Contains(value)) values.Add(value);
        }

        public static void Run(MemoryContext context, AreaResult area, int pebImageBaseOffset)
        {
            ConsoleHistoryReader reader = new ConsoleHistoryReader(context.Reader, pebImageBaseOffset);
            List<ConsoleHostScan> scans = new List<ConsoleHostScan>();
            int hosts = 0;
            foreach (ProcessInfo p in context.Processes) { if (ConsoleHistoryReader.IsConsoleHost(p)) hosts++; }
            foreach (ProcessInfo p in context.Processes)
            {
                if (!ConsoleHistoryReader.IsConsoleHost(p)) continue;
                if (area.TimeUp()) break;
                scans.Add(reader.Scan(p, area));
            }

            // Where one console host keeps the list tells the others of the
            // same program: its offset from the image base, and the image
            // base (one per program while Windows runs)
            Dictionary<string, List<ulong>> offsets = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
            Dictionary<string, List<ulong>> bases = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
            foreach (ConsoleHostScan s in scans)
            {
                if (s.BaseRead) Learn(bases, Key(s.Process), s.ImageBase);
                if (s.Candidates.Count == 1) Learn(offsets, Key(s.Process), s.Candidates[0].Rva);
            }
            foreach (ConsoleHostScan s in scans)
            {
                if (s.Candidates.Count == 0) continue;
                s.List = s.Candidates[0];
                if (s.Candidates.Count == 1) continue;
                s.Ambiguous = true;
                List<ulong> known;
                if (!offsets.TryGetValue(Key(s.Process), out known)) continue;
                foreach (ConsoleHistoryList c in s.Candidates) { if (known.Contains(c.Rva)) { s.List = c; break; } }
            }
            foreach (ConsoleHostScan s in scans)
            {
                if (s.List != null || area.TimeUp()) continue;
                List<ulong> known;
                if (!offsets.TryGetValue(Key(s.Process), out known)) continue;
                List<ulong> tryBases = new List<ulong>();
                if (s.BaseRead) tryBases.Add(s.ImageBase);
                else
                {
                    List<ulong> siblingBases;
                    if (bases.TryGetValue(Key(s.Process), out siblingBases)) tryBases.AddRange(siblingBases);
                }
                foreach (ulong b in tryBases)
                {
                    foreach (ulong rva in known)
                    {
                        ConsoleHistoryList list = reader.TryAt(s.Process.Eprocess, b, rva);
                        if (list == null) continue;
                        s.List = list;
                        s.FromSibling = true;
                        break;
                    }
                    if (s.List != null) break;
                }
            }

            // The entries
            int lists = 0, histories = 0, attached = 0, confirmed = 0, unmatched = 0, commands = 0, empty = 0, unreadable = 0, noApp = 0;
            int noMemory = 0, noHeader = 0, noList = 0, fromSibling = 0, ambiguous = 0, missingPages = 0, completeData = 0;
            foreach (ConsoleHostScan s in scans)
            {
                missingPages += s.MissingPages;
                if (s.HeaderRead && s.MissingPages == 0 && s.WritablePages > 0) completeData++;
                if (s.List == null)
                {
                    if (!s.BaseRead) noMemory++;
                    else if (!s.HeaderRead) noHeader++;
                    else noList++;
                    continue;
                }
                lists++;
                if (s.FromSibling) fromSibling++;
                if (s.Ambiguous) ambiguous++;
                ProcessInfo p = s.Process;
                reader.ReadTexts(context, p.Eprocess, s.List);
                foreach (ConsoleHistoryRecord r in s.List.Histories)
                {
                    histories++;
                    if (r.App == null) noApp++;
                    if (r.ClientRecord != 0) attached++;
                    if (r.ClientPid >= 0) confirmed++;
                    if (r.ClientUnmatched) unmatched++;
                    for (int i = 0; i < r.Commands.Count; i++)
                    {
                        string text = r.Commands[i];
                        if (text == null) { unreadable++; continue; }
                        if (text.Length == 0) { empty++; continue; }
                        commands++;
                        area.Add("Console")
                            .Set("PID", p.Pid)
                            .Set("ProcessCreated", p.CreatedText)
                            .Set("App", r.App ?? "")
                            .Set("ClientPID", r.ClientPid >= 0 ? Fmt.Dec(r.ClientPid) : "")
                            .Set("Index", i)
                            .Set("HistoryCount", r.CommandCount)
                            .Set("FoundBy", "ConsoleHistoryList")
                            .Set("Command", text)
                            .Set("User", p.UserSid ?? "");
                    }
                }
            }

            Coverage cov = area.Coverage;
            cov.Count("console hosts", hosts);
            cov.Count("history lists", lists);
            if (fromSibling > 0) cov.Count("found at another console host's offset", fromSibling);
            cov.Count("histories", histories);
            cov.Count("attached clients", attached);
            cov.Count("client ids confirmed", confirmed);
            if (unmatched > 0) cov.Count("client ids not confirmed", unmatched);
            cov.Count("commands", commands);
            if (empty > 0) cov.Count("empty commands", empty);
            if (unreadable > 0) cov.Count("commands not in the dump", unreadable);
            if (noApp > 0) cov.Count("program names not in the dump", noApp);
            if (noMemory > 0) cov.Count("hosts without readable memory", noMemory);
            if (noHeader > 0) cov.Count("hosts whose image header is not in the dump", noHeader);
            if (noList > 0) cov.Count("hosts whose list is not in the dump", noList);
            if (ambiguous > 0) cov.Count("hosts with more than one list", ambiguous);
            if (missingPages > 0) cov.Count("data pages not in the dump", missingPages);
            if (scans.Count < hosts) cov.Count("hosts not reached before the time limit", hosts - scans.Count);

            // The layout check of this Windows: hosts whose data is all in
            // the dump, and not one list
            if (lists == 0 && completeData > 0)
            {
                area.SetNotRead("the console's command history was not found where this Windows version is known to keep it");
                return;
            }
            // (Hosts not reached before the time limit: its own note says so)
            int missed = scans.Count - lists;
            if (missed > 0)
            {
                area.SetPartial("the command history of " + missed.ToString(CultureInfo.InvariantCulture) + " of " + hosts.ToString(CultureInfo.InvariantCulture) +
                    " console host" + (hosts == 1 ? "" : "s") + " could not be read because " + (missed == 1 ? "its" : "their") + " memory is not in the dump, as when it was paged out or the console had closed");
            }
            if (unreadable > 0)
            {
                area.SetPartial(unreadable.ToString(CultureInfo.InvariantCulture) + " command" + (unreadable == 1 ? "" : "s") + " of the console history could not be read because the memory is not in the dump");
            }
        }
    }
}
'@
}

# The area: the PEB's ImageBaseAddress from the kernel's symbols, then the
# C# above reads every console host
function Invoke-DbgEngConsoleArea {
    param($Context, $Area)
    if ($null -eq $Context.Reader) {
        $Area.SetNotRead("there is no memory reader")
        return
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec @{ "_PEB" = @{ ImageBaseAddress = '^Ptr64\b' } }
    $offset = $layout.Off("_PEB.ImageBaseAddress")
    if ($offset -lt 0) {
        $Area.SetNotRead("the kernel's symbols do not describe the PEB")
        return
    }
    [TimelineDbgEng.ConsoleHistoryArea]::Run($Context, $Area, $offset)
}
