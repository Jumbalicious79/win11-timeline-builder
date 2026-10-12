# =============================================================
# Windows ARM64 memory dumps: executable private memory (item f)
# Part of win11-timeline-builder (work package WP2). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# What it reads: every process's private memory regions (VADs with
# _MMVAD_FLAGS.PrivateMemory, no file behind them) whose protection lets
# code run (the memory manager's protection index, low 3 bits: 2 execute,
# 3 execute-read, 6 execute-read-write, 7 execute-write-copy), from the
# regions the Modules area walked ("VadWalks" in MemoryContext.Shared; walked
# here when it did not). The region's first page is read and classified:
#   PE          it starts with a program header: MZ at the start, or
#               "PE\0\0" at a plausible e_lfanew with the MZ erased
#               (Anomaly=PeHeader)
#   Zero        all zero
#   Data        anything else (run-time compiled code, trampolines, ...)
#   Unreadable  not in the dump
# JitHost: Yes when the process has a run-time compiler loaded (.NET, a
# script or browser engine, Java, the x86/x64 emulator of Windows on Arm,
# from its module names: "ModuleNames" in MemoryContext.Shared, else its
# image mappings), which makes such memory all the time; No when its
# modules were read and have none; Unknown when they were not read.
# ProcessProtected=Yes: a protected process (PP or PPL), such as an
# anti-malware engine, which makes such memory as it works.
# Entries: PrivateCode (rows: Add-DbgEngPrivateCodeRows). For the joins it
# leaves "PeCodeProcesses" (the EPROCESS addresses with a PE region) in
# MemoryContext.Shared.
# =============================================================

# The C# of this file (namespace blocks only; the host's using header). C# 5.
# It uses only the reader's types (not those of the Modules area: either
# file's code can be left out on its own).
function Get-DbgEngPrivateCodeSource {
    return @'
namespace TimelineDbgEng
{
    public static class PrivateCodeArea
    {
        // The file names of run-time compilers: a process that loads one
        // makes executable private memory as it runs (lower case)
        static readonly HashSet<string> JitRuntimes = new HashSet<string>(new string[] {
            // .NET (Framework, Core) and Mono
            "clrjit.dll", "coreclr.dll", "clr.dll", "mscorwks.dll", "mono-2.0-bdwgc.dll", "mono-2.0-sgen.dll", "mono.dll",
            // script and browser engines
            "jscript9.dll", "chakra.dll", "chakracore.dll", "msedge.dll", "chrome.dll", "libcef.dll", "v8.dll", "node.dll", "xul.dll",
            // Java
            "jvm.dll",
            // the x86 and x64 emulators of Windows on Arm (they compile x86/x64 code to Arm64 code as it runs)
            "xtajit.dll", "xtajit64.dll", "xtajit64se.dll"
        }, StringComparer.Ordinal);

        public static bool IsJitRuntime(string fileName)
        {
            return !string.IsNullOrEmpty(fileName) && JitRuntimes.Contains(fileName.ToLowerInvariant());
        }

        // The protection name of an executable protection index; null when
        // the region's code cannot run (the memory manager's index: low 3
        // bits 2 MM_EXECUTE, 3 MM_EXECUTE_READ, 6 MM_EXECUTE_READWRITE,
        // 7 MM_EXECUTE_WRITECOPY; the higher bits are caching and guard
        // flags)
        public static string ExecuteName(int protection)
        {
            if (protection < 0) return null;
            switch (protection & 7)
            {
                case 2: return "Execute";
                case 3: return "ExecuteRead";
                case 6: return "ExecuteReadWrite";
                case 7: return "ExecuteWriteCopy";
                default: return null;
            }
        }

        // A program header at the start of a region: MZ, or "PE\0\0" at a
        // plausible e_lfanew (0x40 up to the page, 4-aligned) with the MZ
        // erased
        public static bool HasPeHeader(byte[] b)
        {
            if (b == null || b.Length < 2) return false;
            if (b[0] == 0x4D && b[1] == 0x5A) return true;
            if (b.Length < 0x40) return false;
            uint offset = Bytes.U32(b, 0x3C);
            if (offset < 0x40 || (offset & 3) != 0 || offset > (uint)(b.Length - 4)) return false;
            return Bytes.U32(b, (int)offset) == 0x00004550;
        }

        // PE, Zero, Data or Unreadable (see the file header)
        public static string Classify(byte[] b)
        {
            if (b == null || b.Length == 0) return "Unreadable";
            if (HasPeHeader(b)) return "PE";
            for (int i = 0; i < b.Length; i++) { if (b[i] != 0) return "Data"; }
            return "Zero";
        }

        static string Leaf(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            int slash = path.LastIndexOf('\\');
            return slash >= 0 ? path.Substring(slash + 1) : path;
        }

        // Yes, No or Unknown (see the file header)
        static string JitHostOf(ProcessInfo p, VadWalk walk, VadWalker walker, Dictionary<ulong, HashSet<string>> moduleNames)
        {
            HashSet<string> names;
            bool read = false;
            if (moduleNames != null && moduleNames.TryGetValue(p.Eprocess, out names) && names != null)
            {
                foreach (string name in names) { read = true; if (IsJitRuntime(name)) return "Yes"; }
            }
            if (walk != null && walker != null)
            {
                foreach (VadNode n in walk.Nodes)
                {
                    if (!n.IsImage) continue;
                    string leaf = Leaf(walker.FileName(n));
                    if (leaf.Length == 0) continue;
                    read = true;
                    if (IsJitRuntime(leaf)) return "Yes";
                }
            }
            return read ? "No" : "Unknown";
        }

        public static void Run(MemoryContext context, AreaResult area, VadWalker walker)
        {
            Dictionary<ulong, VadWalk> walks = null;
            Dictionary<ulong, HashSet<string>> moduleNames = null;
            object shared;
            if (context.Shared.TryGetValue("VadWalks", out shared)) walks = shared as Dictionary<ulong, VadWalk>;
            if (context.Shared.TryGetValue("ModuleNames", out shared)) moduleNames = shared as Dictionary<ulong, HashSet<string>>;
            if (walker != null && !walker.Ready) walker = null;
            HashSet<ulong> peProcesses = new HashSet<ulong>();
            HashSet<ulong> done = new HashSet<ulong>();
            Coverage c = area.Coverage;
            long processes = 0, reused = 0, notWalked = 0, regions = 0, pe = 0, zero = 0, data = 0, unreadable = 0, jit = 0, withRegions = 0;
            foreach (ProcessInfo p in context.Processes)
            {
                if (area.TimeUp()) break;
                if (!done.Add(p.Eprocess)) continue;
                processes++;
                VadWalk walk = null;
                if (walks != null && walks.TryGetValue(p.Eprocess, out walk)) reused++;
                else if (walker != null) walk = walker.Walk(p);
                if (walk == null) { notWalked++; continue; }
                string jitHost = null;
                bool any = false;
                foreach (VadNode n in walk.Nodes)
                {
                    if (!n.PrivateMemory) continue;
                    string protection = ExecuteName(n.Protection);
                    if (protection == null) continue;
                    if (jitHost == null) jitHost = JitHostOf(p, walk, walker, moduleNames);
                    any = true;
                    regions++;
                    int count = (int)Math.Min((ulong)SessionReader.PageSize, n.Size);
                    byte[] first = count > 0 ? context.Reader.Read(p.Eprocess, n.Start, count) : new byte[0];
                    string kind = Classify(first);
                    switch (kind)
                    {
                        case "PE": pe++; peProcesses.Add(p.Eprocess); break;
                        case "Zero": zero++; break;
                        case "Data": data++; break;
                        default: unreadable++; break;
                    }
                    if (jitHost == "Yes") jit++;
                    MemoryEntry e = area.Add("PrivateCode");
                    e.Set("PID", p.Pid).Set("ProcessCreated", p.CreatedText).Set("Process", p.Name);
                    if (!string.IsNullOrEmpty(p.UserSid)) e.Set("User", p.UserSid);
                    e.SetHex("Start", n.Start).SetHex("Size", n.Size).Set("Protection", protection).Set("FirstBytes", kind).Set("JitHost", jitHost);
                    if (p.IsProtected) e.Set("ProcessProtected", "Yes");
                    if (kind == "PE") e.Set("Anomaly", "PeHeader");
                }
                if (any) withRegions++;
            }
            context.Shared["PeCodeProcesses"] = peProcesses;
            c.Count("processes", processes);
            c.Count("memory-region trees from the DLLs area", reused);
            c.Count("not walked", notWalked);
            c.Count("executable private regions", regions);
            c.Count("in processes", withRegions);
            c.Count("with a program header", pe);
            c.Count("first page zero", zero);
            c.Count("other data", data);
            c.Count("first page not in the dump", unreadable);
            c.Count("in processes with a run-time compiler", jit);
            if (walker == null && (walks == null || walks.Count == 0)) area.SetNotRead("the kernel's symbols do not describe the memory regions");
            else if (notWalked > 0) area.SetPartial("the memory regions of " + notWalked.ToString(CultureInfo.InvariantCulture) + (notWalked == 1 ? " process" : " processes") + " were not walked");
        }
    }
}
'@
}

# The area: every process's executable private memory (PrivateCodeArea in
# the C# above), on the regions the Modules area walked
function Invoke-DbgEngPrivateCodeArea {
    param($Context, $Area)
    if (-not ([System.Management.Automation.PSTypeName]'TimelineDbgEng.PrivateCodeArea').Type) {
        $Area.SetNotRead("the code of lib\memory\TimelineDbgEng.PrivateCode.ps1 was not compiled")
        return
    }
    $walker = Get-DbgEngVadWalker -Context $Context
    $walks = if ($Context.Shared.ContainsKey("VadWalks")) { $Context.Shared["VadWalks"] } else { $null }
    if (-not $walker.Ready -and ($null -eq $walks -or $walks.Count -eq 0)) {
        $Area.SetNotRead("the kernel's symbols do not describe the memory regions")
        return
    }
    [TimelineDbgEng.PrivateCodeArea]::Run($Context, $Area, $walker)
}
