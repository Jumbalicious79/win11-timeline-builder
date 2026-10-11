# =============================================================
# Windows ARM64 memory dumps: full program paths and current folders (item b)
# Part of win11-timeline-builder (work package WP1). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
#   Get-DbgEngImagePathsSource   its C#: ProcessPaths, ImagePathReader and
#                     DriveMapper; namespace blocks only, C# 5
#   Get-DbgEngImagePathsLayoutSpec   the fields it needs ('dt')
# The area's function Invoke-DbgEngProcessDetailsArea (and the loop over the
# processes, ProcessDetailsArea) is in TimelineDbgEng.Tokens.ps1.
#
# Where a process's program is, three ways:
#   1. the kernel's own record of the file the process was started from
#      (EPROCESS.SeAuditProcessCreationInfo -> _OBJECT_NAME_INFORMATION.Name,
#      "\Device\HarddiskVolume3\Windows\System32\svchost.exe"): kernel memory,
#      the main value, and the source of the full file name (EPROCESS.
#      ImageFileName keeps only its first 14 characters);
#   2. the file object of the image (EPROCESS.ImageFilePointer ->
#      _FILE_OBJECT.FileName, the same path without its volume): a
#      cross-check, and the file name when the first is not in the dump;
#   3. the process's own PEB (PEB.ProcessParameters -> ImagePathName and
#      CurrentDirectory.DosPath), read in its own address space: what the
#      process says about itself, which it can change.
# The device name of a volume becomes its drive letter by what the processes
# themselves show: a process whose PEB path ("C:\...") and kernel path
# ("\Device\HarddiskVolume3\...") are the same after the drive and the device
# teaches that pair (MemoryContext.DriveMap, shared with the other areas). A
# device two drive letters were learned for, or a drive letter two devices
# were, is not mapped; a path on an unmapped volume keeps its device name.
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngImagePathsSource {
    return @'
namespace TimelineDbgEng
{
    // The paths of one process (ImagePathReader.Read); null where not read
    public sealed class ProcessPaths
    {
        public string Audit;              // the kernel's record of the program file (device form)
        public string FileObject;         // the image's file object name (no volume)
        public string PebImage;           // the PEB's ImagePathName
        public string CurrentDirectory;   // the PEB's current folder
        public bool PebReached;           // the PEB's ProcessParameters were read
        public bool AddressSpaceGone;     // the process's address space could not be switched to
    }

    // Reads the paths of a process at the offsets of a Layout
    public sealed class ImagePathReader
    {
        // Needed; _EPROCESS.ImageFilePointer with _FILE_OBJECT.FileName (the
        // cross-check) and _EPROCESS.Minimal are used when the symbols give them
        public static readonly string[] Fields = new string[] {
            "_EPROCESS.SeAuditProcessCreationInfo", "_SE_AUDIT_PROCESS_CREATION_INFO.ImageFileName", "_OBJECT_NAME_INFORMATION.Name",
            "_PEB.ProcessParameters", "_RTL_USER_PROCESS_PARAMETERS.ImagePathName", "_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory", "_CURDIR.DosPath" };

        readonly MemoryReader reader;
        readonly Layout layout;
        readonly int audit, fileObject, fileName, parameters, imagePathName, currentDirectory, minimal;

        public ImagePathReader(MemoryReader reader, Layout layout)
        {
            this.reader = reader;
            this.layout = layout;
            audit = (layout.Has("_EPROCESS.SeAuditProcessCreationInfo") && layout.Has("_SE_AUDIT_PROCESS_CREATION_INFO.ImageFileName"))
                ? layout.Off("_EPROCESS.SeAuditProcessCreationInfo") + layout.Off("_SE_AUDIT_PROCESS_CREATION_INFO.ImageFileName") : -1;
            fileObject = layout.Has("_FILE_OBJECT.FileName") ? layout.Off("_EPROCESS.ImageFilePointer") : -1;
            fileName = layout.Off("_FILE_OBJECT.FileName");
            parameters = layout.Off("_PEB.ProcessParameters");
            imagePathName = layout.Off("_RTL_USER_PROCESS_PARAMETERS.ImagePathName");
            currentDirectory = (layout.Has("_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory") && layout.Has("_CURDIR.DosPath"))
                ? layout.Off("_RTL_USER_PROCESS_PARAMETERS.CurrentDirectory") + layout.Off("_CURDIR.DosPath") : -1;
            minimal = layout.Off("_EPROCESS.Minimal");
        }

        // "" when the layout has every field needed, else those it lacks
        public static string MissingOf(Layout layout) { return layout.MissingOf(Fields); }

        // A minimal process (Registry, Memory Compression: no program file
        // of their own), when the symbols give EPROCESS.Minimal
        public bool IsMinimal(ProcessInfo p)
        {
            if (minimal < 0 || p == null) return false;
            uint flags;
            if (Bytes.Has(p.Block, minimal, 4)) flags = Bytes.U32(p.Block, minimal);
            else if (!reader.TryU32(0, p.Eprocess + (ulong)minimal, out flags)) return false;
            return layout.BitsOf(flags, "_EPROCESS.Minimal") != 0;
        }

        public ProcessPaths Read(ProcessInfo p)
        {
            ProcessPaths r = new ProcessPaths();
            if (p == null) return r;
            ulong info = Pointer(p, audit);
            if (MemoryReader.IsKernelPointer(info)) r.Audit = reader.UnicodeString(0, info + (ulong)layout.Off("_OBJECT_NAME_INFORMATION.Name"));
            if (fileObject >= 0)
            {
                ulong file = Pointer(p, fileObject);
                if (MemoryReader.IsKernelPointer(file)) r.FileObject = reader.UnicodeString(0, file + (ulong)fileName);
            }
            if (MemoryReader.IsUserAddress(p.Peb) && parameters >= 0)
            {
                ulong block;
                if (reader.TryU64(p.Eprocess, p.Peb + (ulong)parameters, out block) && MemoryReader.IsUserAddress(block))
                {
                    r.PebReached = true;
                    r.PebImage = reader.UnicodeString(p.Eprocess, block + (ulong)imagePathName);
                    if (currentDirectory >= 0) r.CurrentDirectory = reader.UnicodeString(p.Eprocess, block + (ulong)currentDirectory);
                }
                if (reader.IsUnreadableProcess(p.Eprocess)) r.AddressSpaceGone = true;
            }
            return r;
        }

        // A pointer field of the EPROCESS (its bytes when the scan read them)
        ulong Pointer(ProcessInfo p, int offset)
        {
            if (offset < 0) return 0;
            if (Bytes.Has(p.Block, offset, 8)) return Bytes.U64(p.Block, offset);
            ulong value;
            return reader.TryU64(0, p.Eprocess + (ulong)offset, out value) ? value : 0;
        }

        // A path: text with a backslash in it (the minimal processes' record
        // is a bare name)
        public static bool IsPath(string path) { return path != null && path.IndexOf('\\') >= 0; }

        // The file name of a path ("" when it ends with a backslash)
        public static string Leaf(string path)
        {
            if (path == null) return "";
            int slash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
            return slash >= 0 ? path.Substring(slash + 1) : path;
        }

        // Printable ASCII only (EPROCESS.ImageFileName is a byte copy of the
        // name: other characters do not survive it)
        public static bool IsAscii(string text)
        {
            if (text == null) return false;
            foreach (char ch in text) { if (ch < 0x20 || ch > 0x7E) return false; }
            return true;
        }

        // An 8.3 short name (a "~" and a digit: PROGRA~1, SETUP~2.EXE)
        public static bool IsShortName(string name)
        {
            if (name == null) return false;
            for (int i = 0; i + 1 < name.Length; i++) { if (name[i] == '~' && name[i + 1] >= '0' && name[i + 1] <= '9') return true; }
            return false;
        }

        // A path without its "\??\" or "\\?\" prefix
        public static string StripPrefix(string path)
        {
            if (path == null) return null;
            if (path.StartsWith("\\??\\", StringComparison.Ordinal) || path.StartsWith("\\\\?\\", StringComparison.Ordinal)) return path.Substring(4);
            return path;
        }
    }

    // Device names of volumes to drive letters (MemoryContext.DriveMap)
    public static class DriveMapper
    {
        // "\Device\HarddiskVolume3" and "\Windows\..." of a kernel path
        public static bool SplitDevice(string path, out string device, out string rest)
        {
            device = null;
            rest = null;
            if (path == null || !path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase)) return false;
            int slash = path.IndexOf('\\', 8);
            if (slash <= 8) return false;
            device = path.Substring(0, slash);
            rest = path.Substring(slash);
            return true;
        }

        // "C:" and "\Windows\..." of a drive-letter path ("\??\" and "\\?\" allowed)
        public static bool SplitDrive(string path, out string drive, out string rest)
        {
            drive = null;
            rest = null;
            string p = ImagePathReader.StripPrefix(path);
            if (p == null || p.Length < 3 || p[1] != ':' || p[2] != '\\') return false;
            char letter = char.ToUpperInvariant(p[0]);
            if (letter < 'A' || letter > 'Z') return false;
            drive = letter.ToString() + ":";
            rest = p.Substring(2);
            return true;
        }

        // Learns the pairs that agree (kernel path i and PEB path i are the
        // same after the device and the drive) into map; a device with more
        // than one drive letter, or a drive letter with more than one device,
        // is left out and counted in conflicts. Returns the devices mapped.
        public static int Learn(Dictionary<string, string> map, IList<string> kernelPaths, IList<string> pebPaths, out int conflicts)
        {
            conflicts = 0;
            Dictionary<string, HashSet<string>> drivesOf = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, HashSet<string>> devicesOf = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            int count = Math.Min(kernelPaths.Count, pebPaths.Count);
            for (int i = 0; i < count; i++)
            {
                string device, kernelRest, drive, pebRest;
                if (!SplitDevice(kernelPaths[i], out device, out kernelRest) || !SplitDrive(pebPaths[i], out drive, out pebRest)) continue;
                if (!string.Equals(kernelRest, pebRest, StringComparison.OrdinalIgnoreCase)) continue;
                if (!drivesOf.ContainsKey(device)) drivesOf[device] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                drivesOf[device].Add(drive);
                if (!devicesOf.ContainsKey(drive)) devicesOf[drive] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                devicesOf[drive].Add(device);
            }
            int learned = 0;
            foreach (KeyValuePair<string, HashSet<string>> pair in drivesOf)
            {
                string only = null;
                foreach (string d in pair.Value) { only = d; }
                if (pair.Value.Count == 1 && devicesOf[only].Count == 1) { map[pair.Key] = only; learned++; }
                else conflicts++;
            }
            return learned;
        }

        // A kernel path with its device as the drive letter learned for it
        // (else as it is; "" for none)
        public static string Map(Dictionary<string, string> map, string path)
        {
            string device, rest, drive;
            if (map != null && SplitDevice(path, out device, out rest) && map.TryGetValue(device, out drive)) return drive + rest;
            return path ?? "";
        }
    }
}
'@
}

# The fields the paths need, for New-DbgEngLayout (ImageFilePointer,
# _FILE_OBJECT.FileName and Minimal are used when the symbols give them)
function Get-DbgEngImagePathsLayoutSpec {
    return @{
        "_EPROCESS"                       = @{ SeAuditProcessCreationInfo = '^struct _SE_AUDIT_PROCESS_CREATION_INFO\b'; ImageFilePointer = '^Ptr64 to struct _FILE_OBJECT\b'; Minimal = '^Bitfield\b' }
        "_SE_AUDIT_PROCESS_CREATION_INFO" = @{ ImageFileName = '^Ptr64 to struct _OBJECT_NAME_INFORMATION\b' }
        "_OBJECT_NAME_INFORMATION"        = @{ Name = '^struct _UNICODE_STRING\b' }
        "_FILE_OBJECT"                    = @{ FileName = '^struct _UNICODE_STRING\b' }
        "_PEB"                            = @{ ProcessParameters = '^Ptr64 to struct _RTL_USER_PROCESS_PARAMETERS\b' }
        "_RTL_USER_PROCESS_PARAMETERS"    = @{ ImagePathName = '^struct _UNICODE_STRING\b'; CurrentDirectory = '^struct _CURDIR\b' }
        "_CURDIR"                         = @{ DosPath = '^struct _UNICODE_STRING\b' }
    }
}
