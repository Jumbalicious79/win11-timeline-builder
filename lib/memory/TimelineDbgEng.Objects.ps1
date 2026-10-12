# =============================================================
# Windows ARM64 memory dumps: kernel object decoding shared by the drivers and handles areas
# Part of win11-timeline-builder (work package WP3). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads, all from the kernel's own structures at the offsets of the
# kernel's symbol file ('dt'):
#   an object's type     the header before every kernel object
#                        (_OBJECT_HEADER) keeps its type as an index, mixed
#                        with a per-boot cookie and the header's address:
#                        TypeIndex XOR nt!ObHeaderCookie XOR the address's
#                        second byte; nt!ObTypeIndexTable holds the type
#                        (_OBJECT_TYPE, its Name), checked against the type's
#                        own Index
#   an object's name     the optional name header (_OBJECT_HEADER_NAME_INFO)
#                        sits nt!ObpInfoMaskToOffset[InfoMask & 3] bytes
#                        before the header when InfoMask has bit 1; its
#                        Directory gives the full name (\Device\...)
#   the object directory from nt!ObpRootDirectoryObject: 37 hash chains of
#                        _OBJECT_DIRECTORY_ENTRY per directory (\Driver,
#                        \FileSystem, \GLOBAL??, \Device, ...), each listed
#                        once and kept
#   NT paths as drive    symbolic links (_OBJECT_SYMBOLIC_LINK.LinkTarget)
#   letters              resolved through the namespace (\SystemRoot,
#                        \??\C:, \Device\BootDevice), and the volumes' drive
#                        letters from \GLOBAL?? ("C:" -> \Device\HarddiskVolume3)
# Get-DbgEngKernelObjects gives one KernelObjectReader per context
# (MemoryContext.Shared["KernelObjects"]), for both areas.
# No area function of its own: Invoke-DbgEngDriversArea and
# Invoke-DbgEngHandlesArea are in TimelineDbgEng.Drivers.ps1 and
# TimelineDbgEng.Handles.ps1.
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngObjectsSource {
    return @'
namespace TimelineDbgEng
{
    // One object of an object directory
    public sealed class KernelDirectoryEntry
    {
        public string Name;          // its name in the directory (null when not in the dump)
        public ulong Object;         // its body's address
        public string TypeName;      // its type's name ("Directory", "SymbolicLink", "Driver", ...), null when unknown
    }

    // Kernel objects: their type and name from the object header, the
    // object directory, symbolic links and NT paths as drive-letter paths
    public sealed class KernelObjectReader
    {
        public static readonly string[] Fields = new string[] {
            "_OBJECT_HEADER.TypeIndex", "_OBJECT_HEADER.InfoMask", "_OBJECT_HEADER.Body", "_OBJECT_HEADER_NAME_INFO.Directory", "_OBJECT_HEADER_NAME_INFO.Name",
            "_OBJECT_TYPE.Name", "_OBJECT_TYPE.Index", "_OBJECT_DIRECTORY.HashBuckets", "_OBJECT_DIRECTORY_ENTRY.ChainLink", "_OBJECT_DIRECTORY_ENTRY.Object",
            "_OBJECT_SYMBOLIC_LINK.LinkTarget" };
        public static readonly string[] SymbolNames = new string[] { "nt!ObHeaderCookie", "nt!ObTypeIndexTable", "nt!ObpInfoMaskToOffset", "nt!ObpRootDirectoryObject" };
        // InfoMask bit of the name header (_OBJECT_HEADER_NAME_INFO): the
        // optional headers are creator info (bit 0) then name info (bit 1),
        // and nt!ObpInfoMaskToOffset[InfoMask & 3] is the name header's
        // distance before the object header
        const int NameInfoBit = 2;
        // At most this many entries in one hash chain, directory levels in
        // one name, and symbolic links followed for one path
        public const int MaxChainEntries = 4096;
        const int MaxNameDepth = 16;
        const int MaxLinkHops = 8;
        // The type index table's slots (a byte index)
        const int TypeSlots = 256;

        readonly MemoryReader reader;
        readonly Layout layout;
        readonly int typeIndexField, infoMaskField, bodyField, nameDirectoryField, nameField, typeNameField, typeOwnIndexField;
        readonly int bucketsField, bucketCount, chainField, entryObjectField, entrySize, linkTargetField;
        byte cookie;
        byte[] typeTable;
        byte[] infoOffsets;
        ulong root;
        bool prepared;
        readonly Dictionary<int, string> typeNames = new Dictionary<int, string>();
        readonly Dictionary<ulong, List<KernelDirectoryEntry>> listings = new Dictionary<ulong, List<KernelDirectoryEntry>>();
        readonly Dictionary<ulong, string> fullNames = new Dictionary<ulong, string>();
        readonly Dictionary<string, string> resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string> driveLetters;

        // Why the objects cannot be read ("" when they can, after Prepare)
        public string Problem = "";
        // Hash chains of the directories listed that ended early (an entry
        // not in the dump, a loop or the cap)
        public int BrokenChains;

        public KernelObjectReader(MemoryReader reader, Layout layout)
        {
            this.reader = reader;
            this.layout = layout;
            typeIndexField = layout.Off("_OBJECT_HEADER.TypeIndex");
            infoMaskField = layout.Off("_OBJECT_HEADER.InfoMask");
            bodyField = layout.Off("_OBJECT_HEADER.Body");
            nameDirectoryField = layout.Off("_OBJECT_HEADER_NAME_INFO.Directory");
            nameField = layout.Off("_OBJECT_HEADER_NAME_INFO.Name");
            typeNameField = layout.Off("_OBJECT_TYPE.Name");
            typeOwnIndexField = layout.Off("_OBJECT_TYPE.Index");
            bucketsField = layout.Off("_OBJECT_DIRECTORY.HashBuckets");
            chainField = layout.Off("_OBJECT_DIRECTORY_ENTRY.ChainLink");
            entryObjectField = layout.Off("_OBJECT_DIRECTORY_ENTRY.Object");
            linkTargetField = layout.Off("_OBJECT_SYMBOLIC_LINK.LinkTarget");
            entrySize = Math.Max(layout.Size("_OBJECT_DIRECTORY_ENTRY"), Math.Max(chainField, entryObjectField) + 8);
            // HashBuckets is "[37] Ptr64 to ...": its element count
            bucketCount = ArrayLength(layout, "_OBJECT_DIRECTORY.HashBuckets");
        }

        static int ArrayLength(Layout layout, string key)
        {
            string type;
            if (!layout.Types.TryGetValue(key, out type) || type == null || !type.StartsWith("[")) return 0;
            int end = type.IndexOf(']');
            int n;
            if (end < 2 || !int.TryParse(type.Substring(1, end - 1), NumberStyles.None, CultureInfo.InvariantCulture, out n)) return 0;
            return n > 0 && n <= 1024 ? n : 0;
        }

        // "" when the symbols give every field and symbol, else which are not
        public string MissingFields
        {
            get
            {
                List<string> gone = new List<string>();
                string fields = layout.MissingOf(Fields);
                if (fields.Length > 0) gone.Add(fields);
                foreach (string s in SymbolNames) { if (layout.Symbol(s) == 0) gone.Add(s); }
                if (bucketCount == 0 && layout.Has("_OBJECT_DIRECTORY.HashBuckets")) gone.Add("_OBJECT_DIRECTORY.HashBuckets as an array");
                return string.Join(", ", gone.ToArray());
            }
        }

        // Reads the cookie, the type table, the name-header offsets and the
        // root directory once; false (Problem says why) when they cannot be read
        public bool Prepare()
        {
            if (prepared) return Problem.Length == 0;
            prepared = true;
            string missing = MissingFields;
            if (missing.Length > 0) { Problem = "the kernel's symbols do not give " + missing; return false; }
            if (!reader.TryU8(0, layout.Symbol("nt!ObHeaderCookie"), out cookie)) { Problem = "the object header cookie nt!ObHeaderCookie is not in the dump"; return false; }
            typeTable = reader.Read(0, layout.Symbol("nt!ObTypeIndexTable"), TypeSlots * 8);
            if (typeTable.Length < 64) { Problem = "the object type table nt!ObTypeIndexTable is not in the dump"; return false; }
            infoOffsets = reader.Read(0, layout.Symbol("nt!ObpInfoMaskToOffset"), 256);
            if (infoOffsets.Length < 4) { Problem = "the object header offsets nt!ObpInfoMaskToOffset are not in the dump"; return false; }
            if (!reader.TryU64(0, layout.Symbol("nt!ObpRootDirectoryObject"), out root) || !MemoryReader.IsKernelPointer(root)) { Problem = "the root of the object directory is not in the dump"; return false; }
            return true;
        }

        public ulong Root { get { return root; } }
        public int BodyOffset { get { return bodyField; } }
        public ulong HeaderOf(ulong body) { return body - (ulong)bodyField; }

        // The header's bytes up to the body (null when not in the dump)
        public byte[] Header(ulong header)
        {
            if (!MemoryReader.IsKernelPointer(header)) return null;
            byte[] b = reader.Read(0, header, bodyField);
            return b.Length == bodyField ? b : null;
        }

        // The object's type index, decoded (-1 without its header)
        public int TypeIndex(ulong header, byte[] headerBytes)
        {
            if (headerBytes == null || headerBytes.Length <= typeIndexField) return -1;
            return (headerBytes[typeIndexField] ^ cookie ^ (int)((header >> 8) & 0xFF)) & 0xFF;
        }

        // The name of a type index: null for a slot that holds no type (or
        // one whose own Index is another: not a type)
        public string TypeName(int index)
        {
            if (index < 2 || typeTable == null || index * 8 + 8 > typeTable.Length) return null;
            string name;
            if (typeNames.TryGetValue(index, out name)) return name;
            name = null;
            ulong type = Bytes.U64(typeTable, index * 8);
            byte own;
            if (MemoryReader.IsKernelPointer(type) && reader.TryU8(0, type + (ulong)typeOwnIndexField, out own) && own == index)
            {
                name = reader.UnicodeString(0, type + (ulong)typeNameField);
                if (name != null && name.Length == 0) name = null;
            }
            typeNames[index] = name;
            return name;
        }

        public string TypeOf(ulong header, byte[] headerBytes) { return TypeName(TypeIndex(header, headerBytes)); }

        // The type of the object at body (null when unknown)
        public string TypeOfObject(ulong body)
        {
            ulong header = HeaderOf(body);
            return TypeOf(header, Header(header));
        }

        // Where the name header is (0: the object has none)
        ulong NameInfo(ulong header, byte[] headerBytes)
        {
            if (headerBytes == null || headerBytes.Length <= infoMaskField) return 0;
            int mask = headerBytes[infoMaskField];
            if ((mask & NameInfoBit) == 0) return 0;
            int offset = infoOffsets[mask & 3];
            return offset == 0 ? 0 : header - (ulong)offset;
        }

        // The object's own name: null when it has none or it is not in the dump
        public string Name(ulong header, byte[] headerBytes)
        {
            ulong info = NameInfo(header, headerBytes);
            if (info == 0) return null;
            return reader.UnicodeString(0, info + (ulong)nameField);
        }

        // The object's full name in the namespace ("\Device\HarddiskVolume3"),
        // through the directories of its name header; null when it has no
        // name (or an empty one) or a part is not in the dump. Kept per object.
        public string FullName(ulong body)
        {
            string cached;
            if (fullNames.TryGetValue(body, out cached)) return cached;
            List<string> parts = new List<string>();
            ulong current = body;
            string result = null;
            for (int depth = 0; depth < MaxNameDepth; depth++)
            {
                ulong header = HeaderOf(current);
                byte[] h = Header(header);
                ulong info = NameInfo(header, h);
                if (info == 0) break;
                // An empty name is no name (an unnamed object, or a
                // directory part that is not in the dump)
                string name = reader.UnicodeString(0, info + (ulong)nameField);
                if (string.IsNullOrEmpty(name)) break;
                ulong directory;
                if (!reader.TryU64(0, info + (ulong)nameDirectoryField, out directory)) break;
                parts.Insert(0, name);
                if (directory == 0 || directory == root) { result = "\\" + string.Join("\\", parts.ToArray()); break; }
                if (!MemoryReader.IsKernelPointer(directory)) break;
                current = directory;
            }
            fullNames[body] = result;
            return result;
        }

        // The objects of a directory (its body), listed once and kept
        public List<KernelDirectoryEntry> List(ulong directory)
        {
            List<KernelDirectoryEntry> entries;
            if (listings.TryGetValue(directory, out entries)) return entries;
            entries = new List<KernelDirectoryEntry>();
            listings[directory] = entries;
            if (!MemoryReader.IsKernelPointer(directory) || bucketCount == 0) return entries;
            byte[] buckets = reader.Read(0, directory + (ulong)bucketsField, bucketCount * 8);
            for (int i = 0; i < bucketCount; i++)
            {
                if (!Bytes.Has(buckets, i * 8, 8)) { BrokenChains++; continue; }
                ulong link = BitConverter.ToUInt64(buckets, i * 8);
                HashSet<ulong> seen = new HashSet<ulong>();
                while (link != 0)
                {
                    if (!MemoryReader.IsKernelPointer(link) || !seen.Add(link) || seen.Count > MaxChainEntries) { BrokenChains++; break; }
                    byte[] e = reader.Read(0, link, entrySize);
                    if (e.Length < entrySize) { BrokenChains++; break; }
                    ulong body = Bytes.U64(e, entryObjectField);
                    if (MemoryReader.IsKernelPointer(body))
                    {
                        KernelDirectoryEntry entry = new KernelDirectoryEntry();
                        entry.Object = body;
                        ulong header = HeaderOf(body);
                        byte[] h = Header(header);
                        entry.Name = Name(header, h);
                        entry.TypeName = TypeOf(header, h);
                        entries.Add(entry);
                    }
                    link = Bytes.U64(e, chainField);
                }
            }
            return entries;
        }

        // The object of a name in a directory (case-insensitive), or null
        public KernelDirectoryEntry Find(ulong directory, string name)
        {
            foreach (KernelDirectoryEntry e in List(directory))
            {
                if (e.Name != null && string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)) return e;
            }
            return null;
        }

        // A directory of the root ("Driver", "FileSystem", "GLOBAL??"): its body, 0 when there is none
        public ulong RootDirectory(string name)
        {
            KernelDirectoryEntry e = Find(root, name);
            return e != null && e.TypeName == "Directory" ? e.Object : 0;
        }

        // A symbolic link's target (null when not in the dump)
        public string LinkTarget(ulong body) { return reader.UnicodeString(0, body + (ulong)linkTargetField); }

        // An NT path with its symbolic links resolved as far as the
        // namespace goes ("\??\C:\x" and "\SystemRoot\x" become
        // "\Device\HarddiskVolume3\..."); the path as it was when a part is
        // not found
        public string Resolve(string path)
        {
            if (string.IsNullOrEmpty(path) || path[0] != '\\') return path;
            string current = path;
            if (current.StartsWith("\\??\\", StringComparison.Ordinal)) current = "\\GLOBAL??\\" + current.Substring(4);
            for (int hop = 0; hop <= MaxLinkHops; hop++)
            {
                string[] parts = current.Substring(1).Split('\\');
                ulong directory = root;
                string next = null;
                for (int i = 0; i < parts.Length; i++)
                {
                    KernelDirectoryEntry e = Find(directory, parts[i]);
                    if (e == null) return current;
                    if (e.TypeName == "Directory") { directory = e.Object; continue; }
                    if (e.TypeName != "SymbolicLink") return current;
                    string target = LinkTarget(e.Object);
                    if (string.IsNullOrEmpty(target) || target[0] != '\\') return current;
                    next = target.TrimEnd('\\');
                    if (i + 1 < parts.Length) next += "\\" + string.Join("\\", parts, i + 1, parts.Length - i - 1);
                    break;
                }
                if (next == null) return current;
                current = next;
            }
            return current;
        }

        // The volumes' drive letters: device name -> "C:" (from the "X:"
        // symbolic links of \GLOBAL??; of two letters for one device, the first)
        public Dictionary<string, string> DriveLetters()
        {
            if (driveLetters != null) return driveLetters;
            driveLetters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ulong global = RootDirectory("GLOBAL??");
            if (global == 0) return driveLetters;
            List<KernelDirectoryEntry> letters = new List<KernelDirectoryEntry>();
            foreach (KernelDirectoryEntry e in List(global))
            {
                if (e.Name != null && e.Name.Length == 2 && e.Name[1] == ':' && char.IsLetter(e.Name[0]) && e.TypeName == "SymbolicLink") letters.Add(e);
            }
            letters.Sort(delegate(KernelDirectoryEntry a, KernelDirectoryEntry b) { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
            foreach (KernelDirectoryEntry e in letters)
            {
                string target = LinkTarget(e.Object);
                if (string.IsNullOrEmpty(target)) continue;
                target = target.TrimEnd('\\');
                if (!driveLetters.ContainsKey(target)) driveLetters[target] = e.Name.ToUpperInvariant();
            }
            return driveLetters;
        }

        // A path on a volume as a drive-letter path: "\Device\HarddiskVolume3\x"
        // -> "C:\x"; the path as it is when its device has no drive letter
        public string WithDriveLetter(string devicePath)
        {
            if (string.IsNullOrEmpty(devicePath) || !devicePath.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase)) return devicePath;
            int end = devicePath.IndexOf('\\', 8);
            string device = end < 0 ? devicePath : devicePath.Substring(0, end);
            string letter;
            if (!DriveLetters().TryGetValue(device, out letter)) return devicePath;
            return letter + (end < 0 ? "\\" : devicePath.Substring(end));
        }

        // A kernel module's or file's NT path as the rows give it:
        // \SystemRoot\, \??\ and \Device\<volume> mapped to drive letters
        // ("C:\Windows\..."), kept per path; other paths as they are
        public string ToDrivePath(string ntPath)
        {
            if (string.IsNullOrEmpty(ntPath) || ntPath[0] != '\\') return ntPath;
            string cached;
            if (resolved.TryGetValue(ntPath, out cached)) return cached;
            string path = ntPath;
            if (path.StartsWith("\\??\\UNC\\", StringComparison.OrdinalIgnoreCase)) path = "\\" + path.Substring(7);
            else if (path.StartsWith("\\??\\", StringComparison.Ordinal) && path.Length >= 6 && path[5] == ':' && char.IsLetter(path[4])) path = path.Substring(4);
            else if (path.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase) || path.StartsWith("\\??\\", StringComparison.Ordinal) ||
                path.StartsWith("\\GLOBAL??\\", StringComparison.OrdinalIgnoreCase) || path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
            {
                path = WithDriveLetter(Resolve(path));
            }
            resolved[ntPath] = path;
            return path;
        }
    }
}
'@
}

# The object reader of a context, made once (MemoryContext.Shared
# ["KernelObjects"]): its layout from the kernel's symbols, then Prepare.
# Its Problem says why objects cannot be read ("" when they can).
function Get-DbgEngKernelObjects {
    param($Context)
    if ($Context.Shared.ContainsKey("KernelObjects")) { return $Context.Shared["KernelObjects"] }
    $spec = @{
        "_OBJECT_HEADER"           = @{ TypeIndex = '^UChar$'; InfoMask = '^UChar$'; Body = '^struct _QUAD\b' }
        "_OBJECT_HEADER_NAME_INFO" = @{ Directory = '^Ptr64\b'; Name = '^struct _UNICODE_STRING\b' }
        "_OBJECT_TYPE"             = @{ Name = '^struct _UNICODE_STRING\b'; Index = '^UChar$' }
        "_OBJECT_DIRECTORY"        = @{ HashBuckets = '^\[\d+\] Ptr64\b' }
        "_OBJECT_DIRECTORY_ENTRY"  = @{ ChainLink = '^Ptr64\b'; Object = '^Ptr64\b' }
        "_OBJECT_SYMBOLIC_LINK"    = @{ LinkTarget = '^struct _UNICODE_STRING\b' }
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec $spec -Symbols ([TimelineDbgEng.KernelObjectReader]::SymbolNames)
    $objects = New-Object TimelineDbgEng.KernelObjectReader -ArgumentList $Context.Reader, $layout
    [void]$objects.Prepare()
    $Context.Shared["KernelObjects"] = $objects
    return $objects
}
