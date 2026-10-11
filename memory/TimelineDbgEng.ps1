# =============================================================
# Windows ARM64 memory dumps: Microsoft's debugger engine
# Part of win11-timeline-builder. timeline-builder.ps1 runs this file in a
# PowerShell process of its own (the same PowerShell and processor
# architecture), never in its own process: the debugger engine is native
# code, and a crash or a hang on a damaged dump must not take the timeline
# with it. Volatility 3 cannot read Windows ARM64 memory; the debugger
# engine that is part of Windows (dbgeng.dll, or a copy signed by Microsoft
# in tools\dbgeng\<arch>\) reads the dump's processes and command lines,
# as the rows Volatility's windows.pslist and windows.cmdline give.
#
# What it does: loads the engine by full path, opens the dump read-only
# where it is (nothing is copied), reads the kernel's symbol file ID from
# the dump, takes that one file from the symbol cache (tools\symbols\) or
# downloads it from Microsoft's symbol server, loads it, lists the
# processes with dx queries and reads each process's name and command line
# from memory. The engine never gets a symbol server of its own: its symbol
# path is a local folder, and _NT_SYMBOL_PATH is ignored.
#
# Output: protocol lines on stdout, "TBDBG|<kind>|..." (log lines, the
# entries and the counts; text fields in Base64 of UTF-8, so any character
# of a command line survives the pipe), ending with "TBDBG|END|..." when
# the analysis finished. The builder relays the log lines and adds the
# rows itself (Add-MemoryPluginRows).
#
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File TimelineDbgEng.ps1
#     -DumpPath <dump> -EngineFolder <folder> -EngineDlls <a.dll,b.dll>
#     -SymbolCache <builder>\tools\symbols -JobFolder <work folder>\scratch\dbgeng
# =============================================================
[CmdletBinding()]
param(
    # The memory dump (opened read-only, in place)
    [string]$DumpPath,
    # The folder of the debugger engine's DLLs, and the DLLs to load from
    # it by full path, comma-separated, dbgeng.dll last
    [string]$EngineFolder,
    [string]$EngineDlls,
    # The kernel symbol cache (<builder>\tools\symbols)
    [string]$SymbolCache,
    # A folder for this run's files (empty symbol and extension folders,
    # the symbol file when the cache cannot be written)
    [string]$JobFolder
)

# The C# host (C# 5: Windows PowerShell 5.1 compiles it too). The engine's
# COM interfaces are called through their vtables; dbgeng.dll is loaded by
# full path before DebugCreate is bound.
function Get-DbgEngHostSource {
    return @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace TimelineDbgEng
{
    // IDebugOutputCallbacksWide (dbgeng.h): the engine's output, as UTF-16
    [ComVisible(true), Guid("4c7fd663-c394-4e26-8ef1-34ad5ed3764c"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOutputCallbacksWide
    {
        [PreserveSig] int Output(uint mask, [MarshalAs(UnmanagedType.LPWStr)] string text);
    }

    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    public sealed class OutputSink : IOutputCallbacksWide
    {
        readonly StringBuilder buffer = new StringBuilder();
        // One command's output is at most this many characters (a dx page of
        // 100 rows is a few KB); more is dropped and Truncated is set
        public const int MaxChars = 16 * 1024 * 1024;
        public bool Truncated;
        public int Output(uint mask, string text)
        {
            if (text == null) return 0;
            lock (buffer)
            {
                if (buffer.Length + text.Length > MaxChars) { Truncated = true; return 0; }
                buffer.Append(text);
            }
            return 0;
        }
        public string Take()
        {
            lock (buffer) { string s = buffer.ToString(); buffer.Length = 0; return s; }
        }
    }

    public sealed class DbgEngException : Exception
    {
        public readonly int Code;
        public DbgEngException(string message, int code) : base(message) { Code = code; }
    }

    // One debugger engine session on one dump file. Every method runs on the
    // thread that created the session (the engine's rule); only the
    // interrupt of a command that runs too long comes from another thread.
    public sealed class Session : IDisposable
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr LoadLibraryExW(string path, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr GetModuleHandleW(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern uint GetModuleFileNameW(IntPtr module, StringBuilder buffer, uint size);
        // Bound by name only after LoadEngine has loaded dbgeng.dll by its
        // full path (a loaded module is used by name, never searched for)
        [DllImport("dbgeng.dll", EntryPoint = "DebugCreate")] static extern int DebugCreate(ref Guid iid, out IntPtr client);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int QueryInterfaceFn(IntPtr self, ref Guid iid, out IntPtr obj);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint ReleaseFn(IntPtr self);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int NoArgFn(IntPtr self);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int PtrFn(IntPtr self, IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int U32Fn(IntPtr self, uint value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int U64Fn(IntPtr self, ulong value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int OutU64Fn(IntPtr self, out ulong value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int WaitFn(IntPtr self, uint flags, uint timeoutMs);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] delegate int ExecuteWideFn(IntPtr self, uint outputControl, string command, uint flags);
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)] delegate int OpenDumpWideFn(IntPtr self, string path, ulong fileHandle);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ReadVirtualFn(IntPtr self, ulong offset, [Out] byte[] buffer, uint size, out uint bytesRead);

        // vtable slots (dbgeng.h; IUnknown is 0..2)
        const int ClientEndSession = 26, ClientOpenDumpFileWide = 60, ClientSetOutputCallbacksWide = 74;   // IDebugClient5
        const int ControlGetInterrupt = 3, ControlSetInterrupt = 4, ControlWaitForEvent = 93, ControlExecuteWide = 133;   // IDebugControl4
        const int SystemGetImplicitProcess = 35, SystemSetImplicitProcess = 36;   // IDebugSystemObjects2
        const int DataReadVirtual = 3;   // IDebugDataSpaces
        const uint DEBUG_INTERRUPT_PASSIVE = 1, DEBUG_END_PASSIVE = 0;
        const uint DEBUG_OUTCTL_THIS_CLIENT = 0, DEBUG_EXECUTE_NOT_LOGGED = 4, DEBUG_EXECUTE_NO_REPEAT = 0x100;
        const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100, LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
        const int S_FALSE = 1;

        static readonly Guid IidClient5 = new Guid("e3acb9d7-7ec2-4f0c-a0da-e81e0cbbe628");
        static readonly Guid IidControl4 = new Guid("94e60ce9-9b41-4b19-9fc0-6d9eb35272b3");
        static readonly Guid IidSystemObjects2 = new Guid("0ae9f5ff-1852-4679-b055-494bee6407ee");
        static readonly Guid IidDataSpaces = new Guid("88f7dfab-3ea7-4c3a-aefb-c4e8106173aa");

        IntPtr client, control, systemObjects, dataSpaces, sinkPtr;
        readonly OutputSink sink = new OutputSink();
        readonly object gate = new object();   // Interrupt (timer thread) against Dispose
        int interruptSent;
        volatile bool timedOut;

        // The HRESULT of the last Execute (its output is returned either way:
        // a failing command often says why in its output)
        public int LastHResult;

        static T Slot<T>(IntPtr obj, int index) where T : class
        {
            IntPtr vtable = Marshal.ReadIntPtr(obj);
            IntPtr fn = Marshal.ReadIntPtr(vtable, index * IntPtr.Size);
            return (T)(object)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }

        static void Check(int hr, string what)
        {
            if (hr < 0) throw new DbgEngException(what + " failed (HRESULT 0x" + hr.ToString("X8") + ")", hr);
        }

        // Full path of the module of this name loaded in this process, or null
        public static string LoadedPath(string moduleName)
        {
            IntPtr module = GetModuleHandleW(moduleName);
            if (module == IntPtr.Zero) return null;
            StringBuilder path = new StringBuilder(1024);
            uint length = GetModuleFileNameW(module, path, (uint)path.Capacity);
            return length == 0 ? "" : path.ToString();
        }

        // Loads the DLLs of an engine folder by full path, dbgeng.dll last.
        // Imports are looked for only in that folder and System32: never the
        // current folder, the application folder or PATH. A DLL of the same
        // name already loaded from another folder stops the load (the engine
        // would mix versions).
        public static void LoadEngine(string folder, string[] dllNames)
        {
            foreach (string name in dllNames)
            {
                string full = Path.Combine(folder, name);
                string loaded = LoadedPath(name);
                if (loaded != null)
                {
                    if (string.Equals(loaded, full, StringComparison.OrdinalIgnoreCase)) continue;
                    throw new DbgEngException(name + " is already loaded in this PowerShell from " + loaded, -1);
                }
                if (!File.Exists(full)) continue;
                if (LoadLibraryExW(full, IntPtr.Zero, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new DbgEngException(name + " could not be loaded (Windows error " + error + (error == 193 ? ": not a DLL for this PowerShell's processor architecture" : "") + ")", error);
                }
            }
            string engine = LoadedPath("dbgeng.dll");
            if (engine == null || !string.Equals(engine, Path.Combine(folder, "dbgeng.dll"), StringComparison.OrdinalIgnoreCase))
                throw new DbgEngException("dbgeng.dll was not loaded from " + folder, -1);
        }

        public Session()
        {
            if (LoadedPath("dbgeng.dll") == null) throw new DbgEngException("LoadEngine was not called", -1);
            try
            {
                Guid iid = IidClient5;
                Check(DebugCreate(ref iid, out client), "DebugCreate");
                iid = IidControl4; Check(Slot<QueryInterfaceFn>(client, 0)(client, ref iid, out control), "QueryInterface(IDebugControl4)");
                iid = IidSystemObjects2; Check(Slot<QueryInterfaceFn>(client, 0)(client, ref iid, out systemObjects), "QueryInterface(IDebugSystemObjects2)");
                iid = IidDataSpaces; Check(Slot<QueryInterfaceFn>(client, 0)(client, ref iid, out dataSpaces), "QueryInterface(IDebugDataSpaces)");
                sinkPtr = Marshal.GetComInterfaceForObject(sink, typeof(IOutputCallbacksWide));
                Check(Slot<PtrFn>(client, ClientSetOutputCallbacksWide)(client, sinkPtr), "SetOutputCallbacksWide");
            }
            catch { Dispose(); throw; }
        }

        // Opens the dump read-only, where it is (the engine maps it; nothing
        // is copied), and waits for the engine to finish loading it
        public void OpenDump(string dumpPath, uint timeoutMs)
        {
            Check(Slot<OpenDumpWideFn>(client, ClientOpenDumpFileWide)(client, dumpPath, 0), "OpenDumpFileWide");
            int hr = Slot<WaitFn>(control, ControlWaitForEvent)(control, 0, timeoutMs);
            if (hr == S_FALSE) throw new DbgEngException("the dump did not finish loading within " + (timeoutMs / 1000) + " s", hr);
            Check(hr, "WaitForEvent");
        }

        void Interrupt()
        {
            if (Interlocked.Exchange(ref interruptSent, 1) == 1) return;
            lock (gate)
            {
                if (control == IntPtr.Zero) return;
                try { Slot<U32Fn>(control, ControlSetInterrupt)(control, DEBUG_INTERRUPT_PASSIVE); } catch { }
            }
        }

        public bool OutputTruncated { get { return sink.Truncated; } }

        // Runs one engine command; returns its output, also when the command
        // failed (LastHResult). A command still running after timeoutMs is
        // interrupted: DbgEngException (Code 0x800705B4).
        public string Execute(string command, int timeoutMs)
        {
            sink.Take();
            sink.Truncated = false;
            Slot<NoArgFn>(control, ControlGetInterrupt)(control);   // clears an interrupt left from an earlier command
            interruptSent = 0;
            timedOut = false;
            Timer timer = new Timer(delegate(object state) { timedOut = true; Interrupt(); }, null, timeoutMs, Timeout.Infinite);
            int hr;
            try { hr = Slot<ExecuteWideFn>(control, ControlExecuteWide)(control, DEBUG_OUTCTL_THIS_CLIENT, command, DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT); }
            finally
            {
                using (ManualResetEvent stopped = new ManualResetEvent(false))
                {
                    if (timer.Dispose(stopped)) stopped.WaitOne();   // a running timer callback ends first
                }
            }
            LastHResult = hr;
            string text = sink.Take();
            if (timedOut) throw new DbgEngException("the command did not finish within " + (timeoutMs / 1000) + " s", unchecked((int)0x800705B4));
            return text;
        }

        // Reads up to byteCount bytes at address. processDataOffset: the
        // kernel object (EPROCESS) of the process whose address space a user
        // address belongs to, or 0 for a kernel address. Returns the bytes
        // read: fewer (down to none) when part of the range is not in the dump.
        public byte[] ReadVirtual(ulong processDataOffset, ulong address, int byteCount)
        {
            if (byteCount <= 0) return new byte[0];
            ulong saved = 0;
            bool switched = false;
            if (processDataOffset != 0)
            {
                Check(Slot<OutU64Fn>(systemObjects, SystemGetImplicitProcess)(systemObjects, out saved), "GetImplicitProcessDataOffset");
                Check(Slot<U64Fn>(systemObjects, SystemSetImplicitProcess)(systemObjects, processDataOffset), "SetImplicitProcessDataOffset");
                switched = true;
            }
            try
            {
                byte[] buffer = new byte[byteCount];
                uint read;
                int hr = Slot<ReadVirtualFn>(dataSpaces, DataReadVirtual)(dataSpaces, address, buffer, (uint)byteCount, out read);
                if (hr < 0 || read > (uint)byteCount) read = 0;
                if (read == (uint)byteCount) return buffer;
                byte[] part = new byte[read];
                Array.Copy(buffer, part, (int)read);
                return part;
            }
            finally
            {
                if (switched) Slot<U64Fn>(systemObjects, SystemSetImplicitProcess)(systemObjects, saved);
            }
        }

        // Ends the session (the dump file is closed) and releases every
        // interface and the output callback. Safe to call twice.
        public void Dispose()
        {
            if (client != IntPtr.Zero)
            {
                try { Slot<U32Fn>(client, ClientEndSession)(client, DEBUG_END_PASSIVE); } catch { }
                try { Slot<PtrFn>(client, ClientSetOutputCallbacksWide)(client, IntPtr.Zero); } catch { }
            }
            if (dataSpaces != IntPtr.Zero) { Slot<ReleaseFn>(dataSpaces, 2)(dataSpaces); dataSpaces = IntPtr.Zero; }
            if (systemObjects != IntPtr.Zero) { Slot<ReleaseFn>(systemObjects, 2)(systemObjects); systemObjects = IntPtr.Zero; }
            lock (gate)
            {
                if (control != IntPtr.Zero) { Slot<ReleaseFn>(control, 2)(control); control = IntPtr.Zero; }
            }
            if (client != IntPtr.Zero) { Slot<ReleaseFn>(client, 2)(client); client = IntPtr.Zero; }
            if (sinkPtr != IntPtr.Zero) { Marshal.Release(sinkPtr); sinkPtr = IntPtr.Zero; }
        }
    }
}
'@
}

function Initialize-DbgEngHost {
    if (-not ([System.Management.Automation.PSTypeName]'TimelineDbgEng.Session').Type) {
        Add-Type -TypeDefinition (Get-DbgEngHostSource) -ErrorAction Stop
    }
}

# --- Output to the builder (protocol lines on stdout) ----------------------

# Text as Base64 of its UTF-8 bytes: a field of a protocol line ("" stays "")
function ConvertTo-DbgEngBase64 {
    param([string]$Text)
    if (-not $Text) { return "" }
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
}

# One protocol line (the tests put their own function in its place)
function Write-DbgEngWorkerLine {
    param([string]$Line)
    [Console]::Out.WriteLine($Line)
}

# A line for the builder's log: as Log, or with -Warning as Log-Warning
# ("WARNING: " in front), with -Success as Log-Success
function Write-DbgEngLog {
    param([string]$Message, [switch]$Warning, [switch]$Success)
    $level = "I"
    if ($Warning) { $level = "W" }
    elseif ($Success) { $level = "S" }
    Write-DbgEngWorkerLine "TBDBG|LOG|$level|$(ConvertTo-DbgEngBase64 $Message)"
}

# The result of Read-DbgEngDump. Reason: why nothing was read ("" when the
# processes were read). PartialReason: why the command lines are missing
# when the processes were read. Processes and CommandLines: the entries,
# with the property names of Volatility's windows.pslist and
# windows.cmdline JSON. The counts are for the builder's log.
function New-DbgEngResult {
    return [PSCustomObject]@{
        Reason = ""; PartialReason = ""
        Processes = @(); CommandLines = @()
        BadItems = 0; Capped = $false; SessionIds = 0
        NoPeb = 0; Unreadable = 0; Empty = 0
        Seconds = 0.0
    }
}

# The result as protocol lines: the counts, one line per process ("P") and
# command line ("C"), then END with both numbers (the builder checks them)
function Write-DbgEngWorkerResult {
    param($Result)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    foreach ($name in @("Reason", "PartialReason")) {
        Write-DbgEngWorkerLine "TBDBG|R|$name|$(ConvertTo-DbgEngBase64 ([string]$Result.$name))"
    }
    foreach ($name in @("BadItems", "SessionIds", "NoPeb", "Unreadable", "Empty")) {
        Write-DbgEngWorkerLine "TBDBG|R|$name|$(ConvertTo-DbgEngBase64 ([string][long]$Result.$name))"
    }
    Write-DbgEngWorkerLine "TBDBG|R|Capped|$(ConvertTo-DbgEngBase64 ([string][bool]$Result.Capped))"
    Write-DbgEngWorkerLine "TBDBG|R|Seconds|$(ConvertTo-DbgEngBase64 (([double]$Result.Seconds).ToString('0.0', $invariant)))"
    $number = { param($value) if ($null -eq $value) { "" } else { ([long]$value).ToString($invariant) } }
    foreach ($entry in @($Result.Processes)) {
        Write-DbgEngWorkerLine ("TBDBG|P|" + (& $number $entry.PID) + "|" + (& $number $entry.PPID) + "|" + (& $number $entry.Threads) + "|" + (& $number $entry.SessionId) + "|" +
            $entry.Offset + "|" + (ConvertTo-DbgEngBase64 $entry.ImageFileName) + "|" + (ConvertTo-DbgEngBase64 $entry.CreateTime) + "|" + (ConvertTo-DbgEngBase64 $entry.ExitTime))
    }
    foreach ($entry in @($Result.CommandLines)) {
        Write-DbgEngWorkerLine ("TBDBG|C|" + (& $number $entry.PID) + "|" + (ConvertTo-DbgEngBase64 $entry.Process) + "|" + (ConvertTo-DbgEngBase64 $entry.Args))
    }
    Write-DbgEngWorkerLine "TBDBG|END|$(@($Result.Processes).Count)|$(@($Result.CommandLines).Count)"
}

# --- The engine ---------------------------------------------------------------

# An engine session with the dump open (read-only, in place). The symbol
# path is an empty local folder (never a symbol server: the engine itself
# downloads nothing), _NT_SYMBOL_PATH is ignored, no dialog is shown, and
# the extension DLL path is an empty folder too: the engine would otherwise
# look for extension DLLs in folders on PATH and under %LOCALAPPDATA%. The
# builder sends no extension ("!") command, but none could load anyway.
function Open-DbgEngSession {
    param([string]$EngineFolder, [string[]]$EngineDlls, [string]$DumpPath, [string]$SymbolFolder, [string]$ExtensionFolder)
    Initialize-DbgEngHost
    [TimelineDbgEng.Session]::LoadEngine($EngineFolder, [string[]]$EngineDlls)
    $session = New-Object TimelineDbgEng.Session
    try {
        # SYMOPT_IGNORE_NT_SYMPATH 0x1000, SYMOPT_FAIL_CRITICAL_ERRORS 0x200,
        # SYMOPT_NO_PROMPTS 0x80000, SYMOPT_DISABLE_SYMSRV_AUTODETECT 0x2000000
        $null = $session.Execute(".symopt+ 0x2081200", 60000)
        $null = $session.Execute(".sympath `"$SymbolFolder`"", 60000)
        $null = $session.Execute(".extpath `"$ExtensionFolder`"", 60000)
        $session.OpenDump($DumpPath, 300000)
    }
    catch {
        $session.Dispose()
        throw
    }
    return $session
}

function Close-DbgEngSession {
    param($Session)
    if ($Session) { $Session.Dispose() }
}

# One engine command (the tests put their own function in its place): its
# output, also when it failed; a failure without output gives an "Error:"
# line naming the HRESULT. A command still running after -TimeoutSeconds
# throws.
function Invoke-DbgEngCommand {
    param($Session, [string]$Command, [int]$TimeoutSeconds = 300)
    $text = [string]$Session.Execute($Command, $TimeoutSeconds * 1000)
    if ($Session.LastHResult -lt 0 -and -not $text.Trim()) { $text = "Error: the command failed (HRESULT 0x$($Session.LastHResult.ToString('X8')))" }
    return $text
}

# Bytes at an address (the tests put their own function in its place):
# -Process is the EPROCESS of the process whose address space a user
# address is in, 0 for a kernel address. Fewer bytes (or none) when part of
# the range is not in the dump.
function Read-DbgEngVirtual {
    param($Session, [uint64]$Process, [uint64]$Address, [int]$Count)
    return , ([byte[]]$Session.ReadVirtual($Process, $Address, $Count))
}

# A number of a dx row: decimal (may be negative) or with -Hex hex ("0x...",
# a ` in a 64-bit value allowed). $null when it is not a number.
function ConvertFrom-DbgEngNumber {
    param([string]$Text, [switch]$Hex)
    $t = "$Text".Trim().Replace('`', '')
    if ($Hex) {
        if ($t -match '^(?:0x)?([0-9a-fA-F]{1,16})$') { return [Convert]::ToUInt64($Matches[1], 16) }
        return $null
    }
    $value = [long]0
    if ([long]::TryParse($t, [System.Globalization.NumberStyles]::AllowLeadingSign, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value)) { return $value }
    return $null
}

# The items of one "dx -r1 <collection>.Select(...)" output: every
# "[0x..] : <value>" line is an item; a value that starts with "<Tag>|" and
# has -FieldCount fields after the tag is a row (its fields as strings),
# any other value (an engine error such as "Unable to read memory at
# Address 0x...", or a damaged row) is counted in Bad. Items counts both,
# for paging. The first line (the expression echoed, "@$cursession...")
# has no "[0x..]". A query that fails as a whole gives no item and no echo,
# only an "Error: ..." line: QueryError keeps it (or, without such a line
# and without the echo, the first line there is), so the reason can say why.
function ConvertFrom-DbgEngDxRows {
    param([string]$Text, [string]$Tag, [int]$FieldCount)
    $rows = New-Object System.Collections.Generic.List[object]
    $items = 0
    $bad = 0
    $firstBad = ""
    $errorLine = ""
    $otherLine = ""
    $echoed = $false
    foreach ($line in ("$Text" -split "\r?\n")) {
        if ($line -match '^\s*\[0x[0-9a-fA-F`]+\]\s*:\s?(.*?)\s*$') {
            $items++
            $value = $Matches[1]
            if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) { $value = $value.Substring(1, $value.Length - 2) }
            $fields = $value.Split('|')
            if ($fields[0] -ceq $Tag -and $fields.Count -eq $FieldCount + 1) { $rows.Add([string[]]($fields[1..$FieldCount])) }
            else {
                $bad++
                if (-not $firstBad) { $firstBad = $value }
            }
            continue
        }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith('@$')) { $echoed = $true }
        elseif (-not $errorLine -and $trimmed -match '^Error\b') { $errorLine = $trimmed }
        elseif (-not $otherLine) { $otherLine = $trimmed }
    }
    $queryError = ""
    if ($items -eq 0) {
        if ($errorLine) { $queryError = $errorLine }
        elseif (-not $echoed) {
            $queryError = $otherLine
            if (-not $queryError) { $queryError = "Error: no output" }
        }
    }
    return [PSCustomObject]@{ Items = $items; Rows = $rows.ToArray(); Bad = $bad; FirstBad = $firstBad; QueryError = $queryError }
}

# Runs a dx query page by page (dx shows at most 100 items of a list):
# -Template has {0} for the number of items to skip. Stops at the first
# page with fewer than 100 items, at a query that fails as a whole
# (QueryError), or after -MaxItems (a process list that loops in a damaged
# dump). Returns Rows, Items, Bad, FirstBad, QueryError, Capped.
function Get-DbgEngDxPages {
    param($Session, [string]$Template, [string]$Tag, [int]$FieldCount, [int]$MaxItems = 20000)
    $rows = New-Object System.Collections.Generic.List[object]
    $items = 0
    $bad = 0
    $firstBad = ""
    $queryError = ""
    $capped = $false
    for ($skip = 0; ; $skip += 100) {
        if ($skip -ge $MaxItems) { $capped = $true; break }
        $page = ConvertFrom-DbgEngDxRows -Text (Invoke-DbgEngCommand -Session $Session -Command ($Template -f $skip)) -Tag $Tag -FieldCount $FieldCount
        if ($page.QueryError) { $queryError = $page.QueryError; break }
        foreach ($row in $page.Rows) { $rows.Add($row) }
        $items += $page.Items
        $bad += $page.Bad
        if (-not $firstBad) { $firstBad = $page.FirstBad }
        if ($page.Items -lt 100) { break }
    }
    return [PSCustomObject]@{ Rows = $rows.ToArray(); Items = $items; Bad = $bad; FirstBad = $firstBad; QueryError = $queryError; Capped = $capped }
}

# The dx queries ({0}: items to skip). Every field but the tag is a number;
# each query reads only fields of the process's kernel object, which is
# always in a complete dump. The session id is a query of its own, so a
# process whose session cannot be read is still listed; when no session id
# can be read that way, the process token's session id is used. None of
# them is an extension ("!") command: those are never sent.
function Get-DbgEngQuery {
    param([ValidateSet("Process", "Session", "TokenSession")][string]$Name)
    $start = 'dx -r1 @$cursession.Processes.Skip({0}).Take(100).Select(p => '
    $address = '((unsigned __int64)&p.KernelObject).ToDisplayString("x")'
    switch ($Name) {
        "Process" {
            return $start + '"TBP|" + ' + $address + ' + "|" + ((__int64)p.KernelObject.UniqueProcessId).ToDisplayString("d") + "|" + ((__int64)p.KernelObject.InheritedFromUniqueProcessId).ToDisplayString("d") + "|" + p.KernelObject.CreateTime.QuadPart.ToDisplayString("d") + "|" + p.KernelObject.ExitTime.QuadPart.ToDisplayString("d") + "|" + ((__int64)p.KernelObject.ActiveThreads).ToDisplayString("d") + "|" + ((unsigned __int64)p.KernelObject.Peb).ToDisplayString("x") + "|" + ((unsigned __int64)&p.KernelObject.ImageFileName).ToDisplayString("x"))'
        }
        "Session" {
            return $start + '"TBS|" + ' + $address + ' + "|" + (((unsigned __int64)p.KernelObject.Session) == 0 ? (__int64)-1 : (__int64)((nt!_MM_SESSION_SPACE*)p.KernelObject.Session)->SessionId).ToDisplayString("d"))'
        }
        "TokenSession" {
            return $start + '"TBS|" + ' + $address + ' + "|" + ((__int64)((nt!_TOKEN*)(p.KernelObject.Token.Value & ~0xf))->SessionId).ToDisplayString("d"))'
        }
    }
}

# --- Kernel symbols -------------------------------------------------------------

# The kernel's symbol file name and its symbol server key, from the
# CodeView (RSDS) record of the kernel image in the dump: Name, Key (GUID as
# 32 hex digits, then the age in hex, as Microsoft's symbol server names
# it), or Error. Everything comes from the examined computer's memory, so it
# is checked strictly: only the kernel's own symbol file names are accepted,
# which keeps the download request to the kernel's name and ID. Kernel
# addresses are never PowerShell hex literals (0xFFFF... is a negative
# Int64): they are parsed with [Convert]::ToUInt64 and offsets added as
# [uint64].
function Get-KernelSymbolInfo {
    param($Session)
    $fail = { param($why) [PSCustomObject]@{ Name = ""; Key = ""; Error = $why } }
    $evaluated = Invoke-DbgEngCommand -Session $Session -Command "? nt" -TimeoutSeconds 60
    if ($evaluated -notmatch '=\s*([0-9a-fA-F]{8})`?([0-9a-fA-F]{8})') { return (& $fail "the kernel was not found in the dump") }
    $base = [Convert]::ToUInt64($Matches[1] + $Matches[2], 16)
    $header = Read-DbgEngVirtual -Session $Session -Process 0 -Address $base -Count 0x1000
    if ($header.Length -lt 0x200 -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) { return (& $fail "the kernel image header is not in the dump") }
    $pe = [BitConverter]::ToInt32($header, 0x3C)
    if ($pe -lt 0x40 -or $pe -gt 0xE00 -or [BitConverter]::ToUInt32($header, $pe) -ne 0x4550 -or [BitConverter]::ToUInt16($header, $pe + 0x18) -ne 0x20B -or
        [BitConverter]::ToUInt32($header, $pe + 0x18 + 0x6C) -lt 7) { return (& $fail "the kernel image header is not a 64-bit Windows image") }
    $debugRva = [BitConverter]::ToUInt32($header, $pe + 0x18 + 0x70 + 6 * 8)
    $debugSize = [BitConverter]::ToUInt32($header, $pe + 0x18 + 0x70 + 6 * 8 + 4)
    if ($debugRva -eq 0 -or $debugSize -lt 28 -or $debugSize -gt 28 * 16 -or $debugSize % 28 -ne 0) { return (& $fail "the kernel image has no usable debug directory") }
    $directory = Read-DbgEngVirtual -Session $Session -Process 0 -Address ($base + [uint64]$debugRva) -Count ([int]$debugSize)
    for ($offset = 0; $offset + 28 -le $directory.Length; $offset += 28) {
        if ([BitConverter]::ToUInt32($directory, $offset + 12) -ne 2) { continue }   # IMAGE_DEBUG_TYPE_CODEVIEW
        $size = [BitConverter]::ToUInt32($directory, $offset + 16)
        $rva = [BitConverter]::ToUInt32($directory, $offset + 20)
        if ($rva -eq 0 -or $size -lt 25 -or $size -gt 280) { continue }
        $record = Read-DbgEngVirtual -Session $Session -Process 0 -Address ($base + [uint64]$rva) -Count ([int]$size)
        if ($record.Length -ne $size -or [System.Text.Encoding]::ASCII.GetString($record, 0, 4) -cne "RSDS") { continue }
        $end = [Array]::IndexOf($record, [byte]0, 24)
        if ($end -lt 25) { continue }
        $name = [System.Text.Encoding]::ASCII.GetString($record, 24, $end - 24)
        $age = [BitConverter]::ToUInt32($record, 20)
        if (@("ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb", "ntkrla57.pdb") -notcontains $name.ToLowerInvariant() -or $age -eq 0) {
            return (& $fail "the kernel's symbol file record is not one of a Windows kernel")
        }
        $guidBytes = New-Object byte[] 16
        [Array]::Copy($record, 4, $guidBytes, 0, 16)
        $key = (New-Object Guid (, $guidBytes)).ToString("N").ToUpperInvariant() + $age.ToString("X", [System.Globalization.CultureInfo]::InvariantCulture)
        return [PSCustomObject]@{ Name = $name.ToLowerInvariant(); Key = $key; Error = "" }
    }
    return (& $fail "the kernel image has no symbol file record (RSDS)")
}

# Downloads one file (the tests put their own function in its place):
# Microsoft's symbol server only, HTTPS, the system's proxy settings, no
# progress bar (it slows Windows PowerShell's download down many times
# over). The only network access of the builder's memory analysis.
function Save-KernelSymbolDownload {
    param([string]$Url, [string]$Path)
    $ProgressPreference = "SilentlyContinue"
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 }
    catch { Write-Verbose "Could not enable TLS 1.2: $($_.Exception.Message)" }
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing -TimeoutSec 120 -MaximumRedirection 5 -ErrorAction Stop
}

# The message of an error: of the innermost exception (a .NET method's own
# message, not PowerShell's "Exception calling ..." around it). The same
# function is in timeline-builder.ps1.
function Get-DbgEngErrorText {
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    return $exception.Message
}

# A short, single-line form of an error message for a reason in the log:
# no ";", " -- ", ": " or parentheses (the report splits the line on them),
# at most 120 characters. The same function is in timeline-builder.ps1.
function Get-DbgEngShortError {
    param([string]$Message)
    $text = (("$Message" -split "\r?\n") | Where-Object { $_.Trim() } | Select-Object -First 1)
    $text = "$text".Trim().Replace(";", ",").Replace(" -- ", " - ").Replace(": ", " - ").Replace("(", "[").Replace(")", "]").TrimEnd('.')
    if ($text.Length -gt 120) { $text = $text.Substring(0, 117) + "..." }
    return $text
}

# The kernel's symbol file in the cache (tools\symbols\<name>\<key>\<name>,
# the layout of a symbol server's downstream store, so WinDbg can use the
# folder too), downloaded from Microsoft's symbol server when it is not
# there yet. Only the URL leaves the computer: the file name and its key.
# -Fallback: a folder used when -CacheRoot cannot be written (the file is
# then downloaded again next time). The download goes to a name of its own
# (<name>.<PID>.download: two runs at once do not share it), is checked
# (size, the PDB signature) and only then gets the final name; a file that
# another run put there first is kept. Returns Path, Folder, Downloaded,
# Url, Error.
function Get-KernelSymbolFile {
    param([string]$Name, [string]$Key, [string]$CacheRoot, [string]$Fallback)
    $url = "https://msdl.microsoft.com/download/symbols/$Name/$Key/$Name"
    $result = [PSCustomObject]@{ Path = ""; Folder = ""; Downloaded = $false; Url = $url; Error = "" }
    $folder = Join-Path $CacheRoot "$Name\$Key"
    $path = Join-Path $folder $Name
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and (Get-Item -LiteralPath $path -Force).Length -gt 0) {
        $result.Path = $path
        $result.Folder = $folder
        return $result
    }
    try {
        # A symbol path cannot hold a ";" (it separates its folders)
        if ($folder.Contains(";")) { throw "the path has a ; in it" }
        [void][System.IO.Directory]::CreateDirectory($folder)
    }
    catch {
        Write-DbgEngLog "  tools\symbols\ cannot be written ($(Get-DbgEngShortError (Get-DbgEngErrorText $_))): the symbol file goes to the work folder and is downloaded again next time."
        $folder = Join-Path $Fallback "$Name\$Key"
        $path = Join-Path $folder $Name
        try {
            if ($folder.Contains(";")) { throw "the work folder's path has a ; in it" }
            [void][System.IO.Directory]::CreateDirectory($folder)
        }
        catch {
            $result.Error = Get-DbgEngShortError (Get-DbgEngErrorText $_)
            return $result
        }
    }
    # Downloads of earlier runs that stopped half-way
    foreach ($stale in @(Get-ChildItem -LiteralPath $folder -Filter "*.download" -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -lt [datetime]::UtcNow.AddDays(-1) })) {
        Remove-Item -LiteralPath $stale.FullName -Force -ErrorAction SilentlyContinue
    }
    $partial = "$path.$PID.download"
    Write-DbgEngLog "  Downloading the Windows kernel symbol file (about 10 MB) from Microsoft's symbol server: $url"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Save-KernelSymbolDownload -Url $url -Path $partial
        $file = Get-Item -LiteralPath $partial -Force -ErrorAction Stop
        if ($file.Length -lt 64KB -or $file.Length -gt 512MB) { throw "the server sent $($file.Length) bytes, not a kernel symbol file" }
        $magic = New-Object byte[] 32
        $stream = [System.IO.File]::OpenRead($partial)
        try { [void]$stream.Read($magic, 0, 32) } finally { $stream.Dispose() }
        if ([System.Text.Encoding]::ASCII.GetString($magic, 0, 24) -cne "Microsoft C/C++ MSF 7.00") { throw "the server did not send a symbol (PDB) file" }
        try { [System.IO.File]::Move($partial, $path) }
        catch {
            # Another run finished the same download first: keep its file
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw }
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        $result.Error = Get-DbgEngShortError (Get-DbgEngErrorText $_)
        return $result
    }
    $megabytes = ([math]::Round((Get-Item -LiteralPath $path -Force).Length / 1MB, 1)).ToString([System.Globalization.CultureInfo]::InvariantCulture)
    $seconds = ([math]::Round($timer.Elapsed.TotalSeconds, 1)).ToString([System.Globalization.CultureInfo]::InvariantCulture)
    Write-DbgEngLog "  Downloaded $megabytes MB in $seconds s: $path"
    $result.Path = $path
    $result.Folder = $folder
    $result.Downloaded = $true
    return $result
}

# Loads the kernel's symbols from that one folder; $true when the engine
# matched them to the dump ("(pdb symbols)": dbghelp loads a symbol file
# only when its GUID and age are the kernel image's)
function Use-KernelSymbols {
    param($Session, [string]$Folder)
    $null = Invoke-DbgEngCommand -Session $Session -Command ".sympath `"$Folder`"" -TimeoutSeconds 60
    $null = Invoke-DbgEngCommand -Session $Session -Command ".reload /f nt" -TimeoutSeconds 300
    return ((Invoke-DbgEngCommand -Session $Session -Command "lm m nt" -TimeoutSeconds 60) -match '\(pdb symbols\)')
}

# --- Processes and command lines -------------------------------------------------

# EPROCESS.ImageFileName (15 bytes) as Volatility reads it: up to the
# first NUL, UTF-8 (an invalid byte becomes U+FFFD). "" when unreadable.
function Read-DbgEngImageFileName {
    param($Session, [uint64]$Address)
    if ($Address -eq 0) { return "" }
    $bytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address $Address -Count 15
    $end = [Array]::IndexOf($bytes, [byte]0)
    if ($end -lt 0) { $end = $bytes.Length }
    return [System.Text.Encoding]::UTF8.GetString($bytes, 0, $end)
}

# A process's command line as Volatility's windows.cmdline reads it: the
# PEB's ProcessParameters (PEB + 0x20) -> CommandLine (UNICODE_STRING at
# + 0x70; the 64-bit layout of x64 and ARM64 Windows), exactly Length
# bytes as UTF-16 (an unpaired surrogate becomes U+FFFD), cut at the first
# NUL. Read in the process's own address space. State: Read, Empty (no
# text), NoPeb (a kernel process: System, Registry, Memory Compression,
# Secure System, ...) or Unreadable (paged out, or the process has exited).
function Read-DbgEngCommandLine {
    param($Session, [uint64]$Process, [uint64]$Peb)
    $result = [PSCustomObject]@{ Text = ""; State = "Unreadable" }
    if ($Peb -eq 0) { $result.State = "NoPeb"; return $result }
    try {
        $pointer = Read-DbgEngVirtual -Session $Session -Process $Process -Address ($Peb + [uint64]0x20) -Count 8
        if ($pointer.Length -lt 8) { return $result }
        $parameters = [BitConverter]::ToUInt64($pointer, 0)
        if ($parameters -eq 0) { return $result }
        $unicode = Read-DbgEngVirtual -Session $Session -Process $Process -Address ($parameters + [uint64]0x70) -Count 16
        if ($unicode.Length -lt 16) { return $result }
        $length = [int][BitConverter]::ToUInt16($unicode, 0)
        $buffer = [BitConverter]::ToUInt64($unicode, 8)
        $length -= $length % 2
        if ($length -eq 0) { $result.State = "Empty"; return $result }
        if ($buffer -eq 0) { return $result }
        $bytes = Read-DbgEngVirtual -Session $Session -Process $Process -Address $buffer -Count $length
        if ($bytes.Length -ne $length) { return $result }
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
        $nul = $text.IndexOf([char]0)
        if ($nul -ge 0) { $text = $text.Substring(0, $nul) }
        $result.Text = $text
        $result.State = if ($text) { "Read" } else { "Empty" }
    }
    catch { Write-Verbose "Command line of process 0x$($Process.ToString('x')): $($_.Exception.Message)" }
    return $result
}

# A FILETIME as Volatility's JSON gives a time: ISO 8601 UTC text (all 7
# decimals), $null for 0 or less (no time), the number as text when it is
# past the year 9999 (kept in Details as CreateTime=<number>)
function ConvertFrom-DbgEngFileTime {
    param($FileTime)
    if ($null -eq $FileTime -or $FileTime -le 0) { return $null }
    if ($FileTime -gt [datetime]::MaxValue.ToFileTimeUtc()) { return "$FileTime" }
    return [datetime]::FromFileTimeUtc($FileTime).ToString("yyyy-MM-ddTHH:mm:ss.fffffff+00:00", [System.Globalization.CultureInfo]::InvariantCulture)
}

# The dump's processes and command lines (New-DbgEngResult). Nothing read:
# Reason says why. The processes read but not the command lines:
# PartialReason says why.
function Read-DbgEngDump {
    param([string]$DumpPath, [string]$EngineFolder, [string[]]$EngineDlls, [string]$SymbolCache, [string]$JobFolder)
    $result = New-DbgEngResult
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $emptySymbols = Join-Path $JobFolder "nosymbols"
    $emptyExtensions = Join-Path $JobFolder "noextensions"
    [void][System.IO.Directory]::CreateDirectory($emptySymbols)
    [void][System.IO.Directory]::CreateDirectory($emptyExtensions)
    $session = $null
    try {
        try { $session = Open-DbgEngSession -EngineFolder $EngineFolder -EngineDlls $EngineDlls -DumpPath $DumpPath -SymbolFolder $emptySymbols -ExtensionFolder $emptyExtensions }
        catch {
            $result.Reason = "the Windows debugger engine could not open it ($(Get-DbgEngShortError (Get-DbgEngErrorText $_)))"
            return $result
        }
        $kernel = Get-KernelSymbolInfo -Session $session
        if ($kernel.Error) { $result.Reason = "$($kernel.Error) (the Windows debugger engine needs the kernel's symbol file)"; return $result }
        $fallback = Join-Path $JobFolder "symbols"
        $symbols = Get-KernelSymbolFile -Name $kernel.Name -Key $kernel.Key -CacheRoot $SymbolCache -Fallback $fallback
        if (-not $symbols.Error -and -not $symbols.Downloaded) { Write-DbgEngLog "  Kernel symbols: $($symbols.Path) (downloaded earlier)" }
        if (-not $symbols.Error -and -not (Use-KernelSymbols -Session $session -Folder $symbols.Folder)) {
            # A cached copy that does not match (damaged): once more from the server
            Remove-Item -LiteralPath $symbols.Path -Force -ErrorAction SilentlyContinue
            if ($symbols.Downloaded) { $symbols.Error = "the downloaded file does not match the dump" }
            else {
                Write-DbgEngLog -Warning "  The cached kernel symbol file does not match the dump and was deleted; downloading it again."
                $symbols = Get-KernelSymbolFile -Name $kernel.Name -Key $kernel.Key -CacheRoot $SymbolCache -Fallback $fallback
                if (-not $symbols.Error -and -not (Use-KernelSymbols -Session $session -Folder $symbols.Folder)) {
                    Remove-Item -LiteralPath $symbols.Path -Force -ErrorAction SilentlyContinue
                    $symbols.Error = "the downloaded file does not match the dump"
                }
            }
        }
        if ($symbols.Error) {
            Write-DbgEngLog "  To analyze it without internet access here, download $($symbols.Url) on another computer and copy it to $(Join-Path $SymbolCache "$($kernel.Name)\$($kernel.Key)\$($kernel.Name)"), then run the builder again."
            $result.Reason = "the Windows kernel symbol file could not be downloaded from Microsoft's symbol server ($($symbols.Error)); connect to the internet and run the builder again, or see ""Windows kernel symbols"" in README.txt"
            return $result
        }

        # Processes (windows.pslist)
        $list = Get-DbgEngDxPages -Session $session -Template (Get-DbgEngQuery Process) -Tag "TBP" -FieldCount 8
        if ($list.Rows.Count -eq 0) {
            $why = $list.QueryError
            if (-not $why) { $why = $list.FirstBad }
            $whyText = if ($why) { " ($(Get-DbgEngShortError $why))" } else { "" }
            $result.Reason = "the Windows debugger engine listed no processes in it$whyText"
            return $result
        }
        if ($list.QueryError) { Write-DbgEngLog -Warning "  The process list stopped after $($list.Items) entries: $(Get-DbgEngShortError $list.QueryError)" }
        if ($list.Capped) { Write-DbgEngLog -Warning "  The process list did not end after 20000 entries (a damaged dump?): the first 20000 are used." }
        $result.Capped = $list.Capped
        # Session ids: of the session space (no session for System and
        # smss.exe, as Volatility gives it), else of the process token
        $sessions = @{}
        $sessionList = $null
        try {
            $sessionList = Get-DbgEngDxPages -Session $session -Template (Get-DbgEngQuery Session) -Tag "TBS" -FieldCount 2
            if ($sessionList.Rows.Count -eq 0) {
                $why = $sessionList.QueryError
                if (-not $why) { $why = $sessionList.FirstBad }
                if (-not $why) { $why = "none read" }
                Write-DbgEngLog "    Session ids: $(Get-DbgEngShortError $why); the token's session id is used instead"
                $sessionList = Get-DbgEngDxPages -Session $session -Template (Get-DbgEngQuery TokenSession) -Tag "TBS" -FieldCount 2
            }
        }
        catch { Write-DbgEngLog -Warning "  The session ids could not be read: $(Get-DbgEngShortError (Get-DbgEngErrorText $_))" }
        if ($sessionList) {
            foreach ($row in $sessionList.Rows) {
                $key = ConvertFrom-DbgEngNumber $row[0] -Hex
                $id = ConvertFrom-DbgEngNumber $row[1]
                if ($null -ne $key -and $null -ne $id -and $id -ge 0) { $sessions["$key"] = $id }
            }
        }
        $seen = @{}
        $processes = New-Object System.Collections.Generic.List[object]
        $pebs = New-Object System.Collections.Generic.List[object]
        $malformed = $list.Bad
        foreach ($row in $list.Rows) {
            $eprocess = ConvertFrom-DbgEngNumber $row[0] -Hex
            $procId = ConvertFrom-DbgEngNumber $row[1]
            $peb = ConvertFrom-DbgEngNumber $row[6] -Hex
            $nameAddress = ConvertFrom-DbgEngNumber $row[7] -Hex
            if ($null -eq $eprocess -or $null -eq $procId -or $null -eq $peb -or $null -eq $nameAddress) { $malformed++; continue }
            if ($seen.ContainsKey("$eprocess")) { continue }   # a list that loops
            $seen["$eprocess"] = $true
            # The idle process (PID 0) is not in the kernel's process list
            # that windows.pslist walks
            if ($procId -eq 0) { continue }
            $sessionId = $null
            if ($sessions.ContainsKey("$eprocess")) { $sessionId = $sessions["$eprocess"] }
            $processes.Add([PSCustomObject]@{
                    PID = $procId; PPID = (ConvertFrom-DbgEngNumber $row[2]); ImageFileName = (Read-DbgEngImageFileName -Session $session -Address $nameAddress)
                    Offset = "0x$($eprocess.ToString('x'))"; Threads = (ConvertFrom-DbgEngNumber $row[5]); SessionId = $sessionId
                    CreateTime = (ConvertFrom-DbgEngFileTime (ConvertFrom-DbgEngNumber $row[3])); ExitTime = (ConvertFrom-DbgEngFileTime (ConvertFrom-DbgEngNumber $row[4]))
                })
            $pebs.Add(@($eprocess, $peb))
        }
        $result.Processes = $processes.ToArray()
        $result.BadItems = $malformed
        $result.SessionIds = @($processes | Where-Object { $null -ne $_.SessionId }).Count

        # Command lines (windows.cmdline), from each process's own memory
        $commandLines = New-Object System.Collections.Generic.List[object]
        try {
            for ($i = 0; $i -lt $processes.Count; $i++) {
                $commandLine = Read-DbgEngCommandLine -Session $session -Process $pebs[$i][0] -Peb $pebs[$i][1]
                switch ($commandLine.State) {
                    "Read" { $commandLines.Add([PSCustomObject]@{ PID = $processes[$i].PID; Process = $processes[$i].ImageFileName; Args = $commandLine.Text }) }
                    "NoPeb" { $result.NoPeb++ }
                    "Empty" { $result.Empty++ }
                    default { $result.Unreadable++ }
                }
            }
            $result.CommandLines = $commandLines.ToArray()
        }
        catch {
            $result.CommandLines = @()
            $result.PartialReason = "its command lines could not be read [$(Get-DbgEngShortError (Get-DbgEngErrorText $_))]"
        }
    }
    catch {
        if (@($result.Processes).Count -eq 0) { $result.Reason = "the Windows debugger engine stopped ($(Get-DbgEngShortError (Get-DbgEngErrorText $_)))" }
        elseif (-not $result.PartialReason) { $result.PartialReason = "its command lines could not be read [$(Get-DbgEngShortError (Get-DbgEngErrorText $_))]" }
    }
    finally {
        Close-DbgEngSession $session
        $result.Seconds = $timer.Elapsed.TotalSeconds
    }
    return $result
}

# --- Run by the builder ---------------------------------------------------------
# (Nothing runs when a test loads this file's functions from its syntax tree)
if ($JobFolder) {
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"
    $workerResult = $null
    try {
        $workerResult = Read-DbgEngDump -DumpPath $DumpPath -EngineFolder $EngineFolder -EngineDlls @("$EngineDlls" -split ',' | Where-Object { $_ }) -SymbolCache $SymbolCache -JobFolder $JobFolder
    }
    catch {
        $workerResult = New-DbgEngResult
        $workerResult.Reason = "the Windows debugger engine stopped ($(Get-DbgEngShortError (Get-DbgEngErrorText $_)))"
    }
    Write-DbgEngWorkerResult $workerResult
    exit 0
}
