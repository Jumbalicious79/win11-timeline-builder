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
# downloads it from Microsoft's symbol server, loads it, finds the
# processes in the kernel's own structures (its process list walked both
# ways and its process ID table; see "Processes: the kernel's own
# structures" below) and reads each process's fields and command line from
# memory. The engine never gets a symbol server of its own: its symbol
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
#     -CaptureStart <the dump header's time, ISO 8601 UTC, or "">
#     -CaptureEnd <the dump file's last-write time, ISO 8601 UTC, or "">
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
    [string]$JobFolder,
    # When the capture started (the time in the dump's header, as
    # yyyy-MM-ddTHH:mm:ss.fffffffZ), or "" when it is not known: a process
    # that is missing from the kernel's process list, or held in its process
    # ID table under another ID, is judged against it (without it, nothing
    # is marked)
    [string]$CaptureStart,
    # When the capture ended (the dump file's last-write time, in the same
    # form), or "" when it is not known: a process created after the start
    # is capture churn only up to it
    [string]$CaptureEnd
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
# windows.cmdline JSON; a process found in the kernel's own structures also
# has FoundBy (the ways that found it), TableId (the ID the process ID table
# holds it under, when that is not its own) and Anomaly (what copying memory
# does not explain), each "" when there is nothing to say. The counts are
# for the builder's log.
function New-DbgEngResult {
    return [PSCustomObject]@{
        Reason = ""; PartialReason = ""
        Processes = @(); CommandLines = @()
        BadItems = 0; Capped = $false; SessionIds = 0
        NoPeb = 0; Unreadable = 0; Empty = 0
        Seconds = 0.0
    }
}

# The result as protocol lines: the counts, one line per process ("P":
# PID, PPID, Threads, SessionId, Offset, then in Base64 ImageFileName,
# CreateTime, ExitTime, FoundBy, TableId, Anomaly) and command line ("C"),
# then END with both numbers (the builder checks them)
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
            $entry.Offset + "|" + (ConvertTo-DbgEngBase64 $entry.ImageFileName) + "|" + (ConvertTo-DbgEngBase64 $entry.CreateTime) + "|" + (ConvertTo-DbgEngBase64 $entry.ExitTime) + "|" +
            (ConvertTo-DbgEngBase64 $entry.FoundBy) + "|" + (ConvertTo-DbgEngBase64 $entry.TableId) + "|" + (ConvertTo-DbgEngBase64 $entry.Anomaly))
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
# The engine's own "WARNING: ..." lines (such as "WARNING: corrupted linked
# list found" for a process list it could not follow to its end) are kept
# in Warnings, each once.
function ConvertFrom-DbgEngDxRows {
    param([string]$Text, [string]$Tag, [int]$FieldCount)
    $rows = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
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
        elseif ($trimmed -match '^WARNING:') { if (-not $warnings.Contains($trimmed)) { $warnings.Add($trimmed) } }
        elseif (-not $errorLine -and $trimmed -match '^Error\b') { $errorLine = $trimmed }
        elseif (-not $otherLine) { $otherLine = $trimmed }
    }
    $queryError = ""
    if ($items -eq 0) {
        if ($errorLine) { $queryError = $errorLine }
        elseif (-not $echoed) {
            $queryError = $otherLine
            if (-not $queryError -and $warnings.Count -gt 0) { $queryError = $warnings[0] }
            if (-not $queryError) { $queryError = "Error: no output" }
        }
    }
    return [PSCustomObject]@{ Items = $items; Rows = $rows.ToArray(); Bad = $bad; FirstBad = $firstBad; QueryError = $queryError; Warnings = $warnings.ToArray() }
}

# Runs a dx query page by page (dx shows at most 100 items of a list):
# -Template has {0} for the number of items to skip. Stops at the first
# page with fewer than 100 items, at a query that fails as a whole
# (QueryError), or after -MaxItems (a process list that loops in a damaged
# dump). Returns Rows, Items, Bad, FirstBad, QueryError, Capped and
# Warnings (the engine's warnings of every page, each once).
function Get-DbgEngDxPages {
    param($Session, [string]$Template, [string]$Tag, [int]$FieldCount, [int]$MaxItems = 20000)
    $rows = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    $items = 0
    $bad = 0
    $firstBad = ""
    $queryError = ""
    $capped = $false
    for ($skip = 0; ; $skip += 100) {
        if ($skip -ge $MaxItems) { $capped = $true; break }
        $page = ConvertFrom-DbgEngDxRows -Text (Invoke-DbgEngCommand -Session $Session -Command ($Template -f $skip)) -Tag $Tag -FieldCount $FieldCount
        foreach ($warning in $page.Warnings) { if (-not $warnings.Contains($warning)) { $warnings.Add($warning) } }
        if ($page.QueryError) { $queryError = $page.QueryError; break }
        foreach ($row in $page.Rows) { $rows.Add($row) }
        $items += $page.Items
        $bad += $page.Bad
        if (-not $firstBad) { $firstBad = $page.FirstBad }
        if ($page.Items -lt 100) { break }
    }
    return [PSCustomObject]@{ Rows = $rows.ToArray(); Items = $items; Bad = $bad; FirstBad = $firstBad; QueryError = $queryError; Capped = $capped; Warnings = $warnings.ToArray() }
}

# The dx queries of the debugger engine's own process list, used only when
# the kernel's symbols do not describe its process structures ({0}: items
# to skip). Every field but the tag is a number; each query reads only
# fields of the process's kernel object, which is always in a complete
# dump. The session id is a query of its own, so a process whose session
# cannot be read is still listed: -1 for a process without a session
# (EPROCESS.Session is 0: System, smss.exe), else the session space's id,
# or (TokenSession, for each process the first query gave none) the
# process token's. None of them is an extension ("!") command: those are
# never sent.
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
            return $start + '"TBS|" + ' + $address + ' + "|" + (((unsigned __int64)p.KernelObject.Session) == 0 ? (__int64)-1 : (__int64)((nt!_TOKEN*)(p.KernelObject.Token.Value & ~0xf))->SessionId).ToDisplayString("d"))'
        }
    }
}

# --- Kernel symbols -------------------------------------------------------------

# The address of a kernel symbol, as the engine evaluates it ("? nt",
# "? nt!PsActiveProcessHead": an engine command, not an extension); 0 when
# the engine cannot resolve the name. Kernel addresses are never
# PowerShell hex literals (0xFFFF... is a negative Int64): they are parsed
# with [Convert]::ToUInt64 and offsets added as [uint64].
function Get-DbgEngSymbolAddress {
    param($Session, [string]$Name)
    $evaluated = Invoke-DbgEngCommand -Session $Session -Command "? $Name" -TimeoutSeconds 60
    if ("$evaluated" -match '=\s*([0-9a-fA-F]{8})`?([0-9a-fA-F]{8})') { return [Convert]::ToUInt64($Matches[1] + $Matches[2], 16) }
    return [uint64]0
}

# The kernel's symbol file name and its symbol server key, from the
# CodeView (RSDS) record of the kernel image in the dump: Name, Key (GUID as
# 32 hex digits, then the age in hex, as Microsoft's symbol server names
# it), or Error. Everything comes from the examined computer's memory, so it
# is checked strictly: only the kernel's own symbol file names are accepted,
# which keeps the download request to the kernel's name and ID.
function Get-KernelSymbolInfo {
    param($Session)
    $fail = { param($why) [PSCustomObject]@{ Name = ""; Key = ""; Error = $why } }
    $base = Get-DbgEngSymbolAddress -Session $Session -Name "nt"
    if ($base -eq 0) { return (& $fail "the kernel was not found in the dump") }
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
# over). The only network access of the builder's memory analysis. The
# user agent is fixed, the one Microsoft's own symbol client (symsrv)
# sends, the same on every computer: PowerShell's own would name the
# analysis computer's Windows and PowerShell versions and its language.
function Save-KernelSymbolDownload {
    param([string]$Url, [string]$Path)
    $ProgressPreference = "SilentlyContinue"
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 }
    catch { Write-Verbose "Could not enable TLS 1.2: $($_.Exception.Message)" }
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing -UserAgent "Microsoft-Symbol-Server/10.0.0.0" -TimeoutSec 120 -MaximumRedirection 5 -ErrorAction Stop
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
# Url, Error and ErrorKind (Folder: neither folder can be made or written,
# Download: the download failed or was not a symbol file).
function Get-KernelSymbolFile {
    param([string]$Name, [string]$Key, [string]$CacheRoot, [string]$Fallback)
    $url = "https://msdl.microsoft.com/download/symbols/$Name/$Key/$Name"
    $result = [PSCustomObject]@{ Path = ""; Folder = ""; Downloaded = $false; Url = $url; Error = ""; ErrorKind = "" }
    $folder = Join-Path $CacheRoot "$Name\$Key"
    $path = Join-Path $folder $Name
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and (Get-Item -LiteralPath $path -Force).Length -gt 0) {
        $result.Path = $path
        $result.Folder = $folder
        return $result
    }
    # The folder, and the download's own file (empty for now: a folder
    # that can be made but not written is found here, not as a failed
    # download)
    $partial = "$path.$PID.download"
    try {
        # A symbol path cannot hold a ";" (it separates its folders)
        if ($folder.Contains(";")) { throw "the path has a semicolon in it" }
        [void][System.IO.Directory]::CreateDirectory($folder)
        [System.IO.File]::WriteAllBytes($partial, (New-Object byte[] 0))
    }
    catch {
        Write-DbgEngLog "  tools\symbols\ cannot be written ($(Get-DbgEngShortError (Get-DbgEngErrorText $_))): the symbol file goes to the work folder and is downloaded again next time."
        $folder = Join-Path $Fallback "$Name\$Key"
        $path = Join-Path $folder $Name
        $partial = "$path.$PID.download"
        try {
            if ($folder.Contains(";")) { throw "the work folder's path has a semicolon in it" }
            [void][System.IO.Directory]::CreateDirectory($folder)
            [System.IO.File]::WriteAllBytes($partial, (New-Object byte[] 0))
        }
        catch {
            $result.Error = Get-DbgEngShortError (Get-DbgEngErrorText $_)
            $result.ErrorKind = "Folder"
            return $result
        }
    }
    # Downloads of earlier runs that stopped half-way
    foreach ($stale in @(Get-ChildItem -LiteralPath $folder -Filter "*.download" -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -lt [datetime]::UtcNow.AddDays(-1) })) {
        Remove-Item -LiteralPath $stale.FullName -Force -ErrorAction SilentlyContinue
    }
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
        $result.ErrorKind = "Download"
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
# first NUL, UTF-8 (an invalid byte becomes U+FFFD)
function ConvertFrom-DbgEngImageFileName {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return "" }
    $end = [Array]::IndexOf($Bytes, [byte]0)
    if ($end -lt 0) { $end = $Bytes.Length }
    return [System.Text.Encoding]::UTF8.GetString($Bytes, 0, $end)
}

# The same, read at its address: "" when unreadable
function Read-DbgEngImageFileName {
    param($Session, [uint64]$Address)
    if ($Address -eq 0) { return "" }
    return (ConvertFrom-DbgEngImageFileName (Read-DbgEngVirtual -Session $Session -Process 0 -Address $Address -Count 15))
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

# --- Processes: the kernel's own structures --------------------------------------
# The debugger engine's own list of processes (dx @$cursession.Processes,
# what WinDbg shows) walks the kernel's process list (nt!PsActiveProcessHead,
# then EPROCESS.ActiveProcessLinks) forwards and ends at the first entry
# whose link back does not point to the entry before it ("WARNING:
# corrupted linked list found"). A dump made while Windows runs (DumpIt)
# copies memory page by page, and a process that starts or ends during the
# copy can leave such an entry. Windows adds new processes at the end of
# the list, so that list missed the newest processes, the collector's own
# among them. The helper therefore finds the processes itself, three ways,
# and lists each process that any of them found, once: the list walked
# forwards and backwards (an inconsistent link is counted, not an end) and
# the kernel's process ID table (nt!PspCidTable, which holds every process
# and thread by its ID). Each process's fields are read from its EPROCESS
# at the offsets the kernel's symbol file gives ("dt"). When the symbols do
# not describe those structures, the engine's own list is used (dx
# queries), and the log says so. When the ways disagree, the log has a
# warning that the findings report shows as a coverage note ("Memory dump
# process list: ..."). Copying explains a process missing from the list
# only when it ended or started during the copy: one that neither walk
# found, created before the capture started and without an exit time, is
# what a process hidden from the list (unlinked from it) looks like, and a
# process ID of 0, one that is not a multiple of 4, or one the process ID
# table does not hold the process under, is what a process ID changed in
# memory looks like. Those come first in the warning, by PID, and their
# rows say so (Anomaly=; every row says which ways found it, FoundBy=).
# Copying explains both for a process created during the copy or shortly
# before it (capture churn, Get-DbgEngChurnSeconds): the process ID table
# and a process's memory are copied at different moments, and a
# short-lived process that ends in between leaves its ID or its memory to
# a new process. The warning counts such processes as capture churn, and
# their rows keep FoundBy= and TableId= without a mark. Capture churn is
# judged by the process's own create time, between the capture's start
# (the dump header's time) less the margin and its end (the dump file's
# last-write time): a create time of 0, or one after the end, is not
# churn. Copying never explains an ID that is not a multiple of 4, nor 0
# for a process the table does not hold under another ID. Without the
# capture start, nothing is marked. A rootkit that can change a process's
# ID can also change its create time, and one that keeps it within the
# capture is not marked: the warning still names the process.

# Capture churn: how many seconds before the capture start (the dump
# header's time) a process can have been created and still be taken as
# part of the copy rather than older than it. A process created before the
# start shows up so only when it ended during the copy (a new process then
# took its ID or its memory), so the margin is set by how long the
# computer's short-lived processes live, not by when the capture tool
# starts (0.05 to 0.27 s before the header's time in four real ARM64
# dumps). In one of them, of a computer busy with polling loops that
# waited 5 and 10 seconds, the six processes the process ID table held
# under the ID of a process not in the dump were created during the copy
# but one, 0.78 s before the header's time. The processes that had ended
# (an exit time in the dump) in those four dumps had lived 0.1 to 24.1 s,
# apart from ones that ran for hours, and one 60.3 s: created 36.7 s
# before the header's time, it ended during the copy (the case that needs
# the margin). 120 seconds is twice the longest of those; a process
# created earlier is judged (marked when it is missing from the list or
# held under another ID), as a process hidden from the list is normally
# minutes to hours old.
function Get-DbgEngChurnSeconds {
    return 120
}

# How many seconds after the capture end (the dump file's last-write time)
# a create time is still taken as part of the copy: file times can be
# rounded to 2 seconds (FAT, ZIP). In four real ARM64 dumps the newest
# process was created 11.7 to 46.6 s before the file's last write.
function Get-DbgEngCaptureEndSlackSeconds {
    return 2
}

# When a process was created, against the capture (FILETIMEs; 0: not
# known): Before (more than the churn margin before the start: judged),
# Churn (during the copy, or within the margin before it), NoTime (no
# create time), Late (after the end and its slack), NoEnd (after the start
# while the end is not known), or "" (the start is not known)
function Get-DbgEngCreateWhen {
    param([long]$CreateTime, [long]$CaptureFileTime, [long]$CaptureEndFileTime)
    if ($CaptureFileTime -le 0) { return "" }
    if ($CreateTime -le 0) { return "NoTime" }
    if ($CreateTime -lt $CaptureFileTime - [long](Get-DbgEngChurnSeconds) * 10000000) { return "Before" }
    if ($CreateTime -le $CaptureFileTime) { return "Churn" }
    if ($CaptureEndFileTime -lt $CaptureFileTime) { return "NoEnd" }
    if ($CreateTime -le $CaptureEndFileTime + [long](Get-DbgEngCaptureEndSlackSeconds) * 10000000) { return "Churn" }
    return "Late"
}

# What a process ID that does not fit gets: Marked (Anomaly=
# ProcessIdChanged), Churn (a stale entry of the process ID table, which
# copying explains) or Unjudged (named, not marked). -Kind: Table (held in
# the table under another ID), Zero or Invalid (not a multiple of 4);
# -When: Get-DbgEngCreateWhen. Only a stale entry can be churn: an ID
# Windows never gives cannot come from one, and neither can 0 unless the
# table holds the process under an ID.
function Get-DbgEngIdChangeVerdict {
    param([string]$Kind, [int]$TableIdCount, [string]$When)
    if (-not $When) { return "Unjudged" }
    $staleEntry = $Kind -eq "Table" -or ($Kind -eq "Zero" -and $TableIdCount -gt 0)
    if (-not $staleEntry) { return "Marked" }
    if ($When -eq "Churn") { return "Churn" }
    if ($When -eq "NoEnd") { return "Unjudged" }
    return "Marked"
}

# A kernel address that a link or pointer of the kernel's structures can
# hold: its top byte all ones (the kernel half of a 48-bit or 57-bit
# address space) and 8-byte aligned. A link into user memory, or a small
# number such as 0x10001 (a field of memory that was reused), is not one.
function Test-DbgEngKernelAddress {
    param([uint64]$Address)
    return (($Address -shr 56) -eq 0xFF -and ($Address -band 7) -eq 0)
}

# The fields of one kernel type as the engine's "dt -v nt!<type>" shows them
# (an engine command, not an extension): Size (bytes; 0 when not shown),
# Offsets (field name -> offset; of fields of the same name, the first),
# Types (field name -> its type text) and Bits (field name -> @(position,
# width) of a bitfield). No fields: the symbols do not have the type
# ("Symbol nt!<type> not found.").
function Get-DbgEngTypeLayout {
    param($Session, [string]$TypeName)
    $layout = [PSCustomObject]@{ Size = 0; Offsets = @{}; Types = @{}; Bits = @{} }
    $text = Invoke-DbgEngCommand -Session $Session -Command "dt -v nt!$TypeName" -TimeoutSeconds 60
    foreach ($line in ("$text" -split "\r?\n")) {
        if ($line -match '^(?:struct|union) (\S+), \d+ elements?, 0x([0-9a-fA-F]+) bytes') {
            if ($Matches[1] -ceq $TypeName) { $layout.Size = [Convert]::ToInt32($Matches[2], 16) }
            continue
        }
        if ($line -notmatch '^\s+\+0x([0-9a-fA-F]+) (\w+)\s*: (.+?)\s*$') { continue }
        $offset = [Convert]::ToInt32($Matches[1], 16)
        $name = $Matches[2]
        $type = $Matches[3]
        if ($layout.Offsets.ContainsKey($name)) { continue }
        $layout.Offsets[$name] = $offset
        $layout.Types[$name] = $type
        if ($type -match '^Bitfield Pos (\d+), (\d+) Bits?$') { $layout.Bits[$name] = @([int]$Matches[1], [int]$Matches[2]) }
    }
    return $layout
}

# What the process scan reads, from the kernel's symbols:
#   Offsets, ProcessSize  the EPROCESS fields the rows need and its size
#                         (its first byte is the dispatcher header's type,
#                         3 for a process)
#   ListHead              nt!PsActiveProcessHead
#   TokenSessionId        _TOKEN.SessionId (-1: none), and TokenRefMask, the
#                         reference count bits of EPROCESS.Token (_EX_FAST_REF)
#   MmSessionId           _MM_SESSION_SPACE.SessionId (-1: the symbols do not
#                         have that type, as those of Windows 11 24H2 on ARM64)
#   CidTable, TableCode, EntrySize, PointerPosition, PointerWidth
#                         nt!PspCidTable, _HANDLE_TABLE.TableCode and
#                         _HANDLE_TABLE_ENTRY (its size; ObjectPointerBits)
# Error: why the scan cannot be made (the debugger engine's own list is
# used instead); CidError: why the process ID table cannot be read (the
# list is still walked both ways).
function Get-DbgEngKernelLayout {
    param($Session)
    $layout = [PSCustomObject]@{
        Error = ""; CidError = ""; Offsets = @{}; ProcessSize = 0; ListHead = [uint64]0
        TokenSessionId = -1; TokenRefMask = [uint64]15; MmSessionId = -1
        CidTable = [uint64]0; TableCode = 0; EntrySize = 0; PointerPosition = 0; PointerWidth = 0
    }
    $process = Get-DbgEngTypeLayout -Session $Session -TypeName "_EPROCESS"
    if ($process.Offsets.Count -eq 0) { $layout.Error = "the kernel's symbols do not describe its process structure _EPROCESS"; return $layout }
    # Each field the scan reads, and the type it must have
    $expected = [ordered]@{
        Pcb = '^struct _KPROCESS\b'; UniqueProcessId = '^Ptr64\b'; ActiveProcessLinks = '^struct _LIST_ENTRY\b'
        InheritedFromUniqueProcessId = '^Ptr64\b'; CreateTime = '^union _LARGE_INTEGER\b'; ExitTime = '^union _LARGE_INTEGER\b'
        ImageFileName = '^\[15\] UChar$'; ActiveThreads = '^Uint4B$'; Peb = '^Ptr64\b'; Token = '^struct _EX_FAST_REF\b'; Session = '^Ptr64\b'
    }
    $missing = @($expected.Keys | Where-Object { -not $process.Offsets.ContainsKey($_) -or $process.Types[$_] -notmatch $expected[$_] })
    if ($missing.Count -gt 0) { $layout.Error = "the kernel's symbols do not give _EPROCESS.$($missing -join ', _EPROCESS.') as expected"; return $layout }
    $last = 0
    foreach ($name in $expected.Keys) { $last = [Math]::Max($last, [int]$process.Offsets[$name]) }
    if ($process.Offsets["Pcb"] -ne 0 -or $process.Size -lt $last + 16 -or $process.Size -gt 0x4000) {
        $layout.Error = "the kernel's process structure _EPROCESS has a layout the builder does not read"
        return $layout
    }
    foreach ($name in $expected.Keys) { $layout.Offsets[$name] = [int]$process.Offsets[$name] }
    $layout.ProcessSize = $process.Size
    $layout.ListHead = Get-DbgEngSymbolAddress -Session $Session -Name "nt!PsActiveProcessHead"
    if (-not (Test-DbgEngKernelAddress $layout.ListHead)) { $layout.Error = "nt!PsActiveProcessHead is not in the kernel's symbols"; return $layout }
    # Session ids: of the session space when the symbols describe it, else
    # of the process token
    $token = Get-DbgEngTypeLayout -Session $Session -TypeName "_TOKEN"
    if ($token.Offsets.ContainsKey("SessionId") -and $token.Types["SessionId"] -eq "Uint4B") { $layout.TokenSessionId = [int]$token.Offsets["SessionId"] }
    $fastRef = Get-DbgEngTypeLayout -Session $Session -TypeName "_EX_FAST_REF"
    if ($fastRef.Bits.ContainsKey("RefCnt") -and $fastRef.Bits["RefCnt"][0] -eq 0 -and $fastRef.Bits["RefCnt"][1] -ge 1 -and $fastRef.Bits["RefCnt"][1] -le 15) {
        $layout.TokenRefMask = [uint64](([uint64]1 -shl $fastRef.Bits["RefCnt"][1]) - [uint64]1)
    }
    $space = Get-DbgEngTypeLayout -Session $Session -TypeName "_MM_SESSION_SPACE"
    if ($space.Offsets.ContainsKey("SessionId") -and $space.Types["SessionId"] -eq "Uint4B") { $layout.MmSessionId = [int]$space.Offsets["SessionId"] }
    # The process ID table
    $layout.CidTable = Get-DbgEngSymbolAddress -Session $Session -Name "nt!PspCidTable"
    $table = Get-DbgEngTypeLayout -Session $Session -TypeName "_HANDLE_TABLE"
    $entry = Get-DbgEngTypeLayout -Session $Session -TypeName "_HANDLE_TABLE_ENTRY"
    if (-not (Test-DbgEngKernelAddress $layout.CidTable)) { $layout.CidError = "nt!PspCidTable is not in the kernel's symbols" }
    elseif (-not $table.Offsets.ContainsKey("TableCode") -or $table.Types["TableCode"] -ne "Uint8B") { $layout.CidError = "the kernel's symbols do not give _HANDLE_TABLE.TableCode" }
    elseif ($entry.Size -ne 16 -or -not $entry.Bits.ContainsKey("ObjectPointerBits")) { $layout.CidError = "the kernel's symbols do not give _HANDLE_TABLE_ENTRY.ObjectPointerBits as expected" }
    else {
        $position = [int]$entry.Bits["ObjectPointerBits"][0]
        $width = [int]$entry.Bits["ObjectPointerBits"][1]
        if ($width -lt 32 -or $width -gt 60 -or $position + $width -gt 64) { $layout.CidError = "the kernel's process ID table has a layout the builder does not read" }
        else {
            $layout.TableCode = [int]$table.Offsets["TableCode"]
            $layout.EntrySize = 16
            $layout.PointerPosition = $position
            $layout.PointerWidth = $width
        }
    }
    return $layout
}

# The bytes of a process object at an address (the EPROCESS's size), else
# $null: not in the dump, or its dispatcher header's type is not 3 (a
# process object; most memory that was reused is not taken for a process).
# Its process ID is checked by the caller (Get-DbgEngProcessIdKind).
# -Cache (address -> bytes or $null) keeps every answer, so the walks and
# the process ID table read each address once.
function Get-DbgEngProcessBlock {
    param($Session, $Layout, [uint64]$Address, $Cache)
    if ($Cache.ContainsKey($Address)) {
        $cached = $Cache[$Address]
        if ($null -eq $cached) { return $null }
        return , $cached
    }
    $block = $null
    if (Test-DbgEngKernelAddress $Address) {
        $bytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address $Address -Count $Layout.ProcessSize
        if ($bytes.Length -eq $Layout.ProcessSize -and $bytes[0] -eq 3) { $block = $bytes }
    }
    $Cache[$Address] = $block
    if ($null -eq $block) { return $null }
    return , $block
}

# What the process ID in an EPROCESS is: Valid (a multiple of 4 from 4 to
# 2^32 - 4, as Windows gives them), Zero (only the idle process has 0, and
# it is in neither the process list nor the process ID table) or Invalid
function Get-DbgEngProcessIdKind {
    param($Layout, [byte[]]$Block)
    $procId = [BitConverter]::ToUInt64($Block, $Layout.Offsets["UniqueProcessId"])
    if ($procId -eq 0) { return "Zero" }
    if ($procId -lt [uint64]4294967296 -and ($procId -band 3) -eq 0) { return "Valid" }
    return "Invalid"
}

# $true when a process object's own fields look like a process's: both
# links of ActiveProcessLinks and its token are kernel addresses (a process
# taken out of the list keeps links, often to itself). Asked of an object
# whose process ID does not fit, before it is listed: memory that was
# reused and starts with a 3 by chance is not.
function Test-DbgEngProcessShape {
    param($Layout, [byte[]]$Block)
    $links = [int]$Layout.Offsets["ActiveProcessLinks"]
    $token = [BitConverter]::ToUInt64($Block, $Layout.Offsets["Token"]) -band (-bnot [uint64]$Layout.TokenRefMask)
    return ((Test-DbgEngKernelAddress ([BitConverter]::ToUInt64($Block, $links))) -and (Test-DbgEngKernelAddress ([BitConverter]::ToUInt64($Block, $links + 8))) -and
        (Test-DbgEngKernelAddress $token))
}

# The kernel's process list walked from its head (nt!PsActiveProcessHead)
# through ActiveProcessLinks: forwards (Flink), or with -Backward (Blink).
# An entry whose link back does not point to the entry before it is
# counted (Mismatches) and the walk goes on. The walk ends at the head
# (Complete), or, Stop saying why (a noun phrase, after "stopped at"), at a
# link that is not a kernel address, a link to an entry already walked, an
# entry that is not a process (Broken: the list itself is damaged there)
# or after -MaxEntries (Capped). A process object whose process ID does not
# fit is walked through only when its link back is consistent and its
# fields look like a process's (a real process whose ID was changed);
# otherwise it is memory that was reused. Entries: the EPROCESS addresses
# in walk order.
function Invoke-DbgEngProcessWalk {
    param($Session, $Layout, $Cache, [switch]$Backward, [int]$MaxEntries = 20000)
    $result = [PSCustomObject]@{
        Entries = (New-Object 'System.Collections.Generic.List[uint64]'); Mismatches = 0; Complete = $false; Broken = $false; Capped = $false; Stop = ""
    }
    $links = [int]$Layout.Offsets["ActiveProcessLinks"]
    $nextField = 0
    $backField = 8
    if ($Backward) { $nextField = 8; $backField = 0 }
    $head = [uint64]$Layout.ListHead
    $headBytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address $head -Count 16
    if ($headBytes.Length -lt 16) { $result.Stop = "the list head, which is not in the dump"; return $result }
    $seen = New-Object 'System.Collections.Generic.HashSet[uint64]'
    $previous = $head
    $link = [BitConverter]::ToUInt64($headBytes, $nextField)
    while ($true) {
        if ($link -eq $head) { $result.Complete = $true; break }
        if ($result.Entries.Count -ge $MaxEntries) { $result.Capped = $true; $result.Stop = "the first $MaxEntries entries"; break }
        $result.Broken = $true
        if (-not (Test-DbgEngKernelAddress $link)) { $result.Stop = "a link that is not a kernel address"; break }
        if (-not $seen.Add($link)) { $result.Stop = "a link to an entry already walked"; break }
        $address = $link - [uint64]$links
        $block = Get-DbgEngProcessBlock -Session $Session -Layout $Layout -Address $address -Cache $Cache
        if ($null -eq $block) { $result.Stop = "an entry that is not a process"; break }
        $consistent = [BitConverter]::ToUInt64($block, $links + $backField) -eq $previous
        if ((Get-DbgEngProcessIdKind -Layout $Layout -Block $block) -eq "Invalid" -and -not ($consistent -and (Test-DbgEngProcessShape -Layout $Layout -Block $block))) {
            $result.Stop = "an entry that is not a process"
            break
        }
        $result.Broken = $false
        if (-not $consistent) { $result.Mismatches++ }
        $result.Entries.Add($address)
        $previous = $link
        $link = [BitConverter]::ToUInt64($block, $links + $nextField)
    }
    return $result
}

# The non-zero kernel addresses in a page of 512 pointers (a level of the
# process ID table): @(index, address) each; $null when the page is not in
# the dump
function Get-DbgEngTablePointers {
    param($Session, [uint64]$Address)
    $page = Read-DbgEngVirtual -Session $Session -Process 0 -Address $Address -Count 4096
    if ($page.Length -lt 4096) { return $null }
    $pointers = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt 512; $i++) {
        $value = [BitConverter]::ToUInt64($page, $i * 8)
        if ($value -ne 0 -and (Test-DbgEngKernelAddress $value)) { $pointers.Add(@($i, $value)) }
    }
    return , $pointers.ToArray()
}

# The processes in the kernel's process ID table (nt!PspCidTable: a handle
# table of every process and thread, by ID). The low 2 bits of its
# TableCode are its levels: 0, one page of entries; 1, a page of pointers to
# such pages; 2, two levels of pointer pages. A 4 KB page holds 256
# entries of 16 bytes, entry k of page n for ID (n * 256 + k) * 4, and an
# entry's object is ObjectPointerBits shifted left by 4 and sign-extended
# (a kernel address). Of the objects, the processes (dispatcher type 3; a
# thread's is 6) are kept: those whose process ID is the entry's ID, and
# those whose ID is another (Mismatched) when their fields look like a
# process's (Test-DbgEngProcessShape; a free entry's bits can point
# anywhere). Entries: each process once (EPROCESS addresses, in ID order);
# Own: those held under their own ID; Mismatched: @(entry ID, EPROCESS) of
# each entry that holds a process under another ID; NotProcesses: entries
# whose process object does not look like a process (left out); Error: why
# the table could not be read; UnreadablePages: pages of entries not in the
# dump.
function Get-DbgEngCidProcesses {
    param($Session, $Layout, $Cache, [int]$MaxPages = 4096)
    $result = [PSCustomObject]@{
        Entries = (New-Object 'System.Collections.Generic.List[uint64]'); Own = (New-Object 'System.Collections.Generic.HashSet[uint64]')
        Mismatched = (New-Object System.Collections.Generic.List[object]); NotProcesses = 0; Error = ""; UnreadablePages = 0
    }
    $listed = New-Object 'System.Collections.Generic.HashSet[uint64]'
    $pointer = Read-DbgEngVirtual -Session $Session -Process 0 -Address $Layout.CidTable -Count 8
    $code = $null
    if ($pointer.Length -eq 8) {
        $table = [BitConverter]::ToUInt64($pointer, 0)
        if (Test-DbgEngKernelAddress $table) {
            $codeBytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address ($table + [uint64]$Layout.TableCode) -Count 8
            if ($codeBytes.Length -eq 8) { $code = [BitConverter]::ToUInt64($codeBytes, 0) }
        }
    }
    if ($null -eq $code) { $result.Error = "it is not in the dump"; return $result }
    $level = [int]($code -band 3)
    $base = $code -band (-bnot [uint64]3)
    # The pages of entries, each with its place in the table
    $pages = New-Object System.Collections.Generic.List[object]
    if ($level -eq 0) { $pages.Add(@(0, $base)) }
    elseif ($level -le 2) {
        $top = Get-DbgEngTablePointers -Session $Session -Address $base
        if ($null -eq $top) { $result.Error = "it is not in the dump"; return $result }
        foreach ($item in $top) {
            if ($level -eq 1) { $pages.Add($item); continue }
            $middle = Get-DbgEngTablePointers -Session $Session -Address $item[1]
            if ($null -eq $middle) { $result.UnreadablePages++; continue }
            foreach ($leaf in $middle) { $pages.Add(@(([long]$item[0] * 512 + $leaf[0]), $leaf[1])) }
        }
    }
    else { $result.Error = "it has a layout the builder does not read (level $level)"; return $result }
    if ($pages.Count -gt $MaxPages) { $result.Error = "it has more than $MaxPages pages (a damaged dump?)"; return $result }
    $perPage = [int](4096 / $Layout.EntrySize)
    $mask = [uint64](([uint64]1 -shl $Layout.PointerWidth) - [uint64]1)
    $signBit = [uint64]1 -shl ($Layout.PointerWidth + 3)
    $extend = -bnot [uint64](([uint64]1 -shl ($Layout.PointerWidth + 4)) - [uint64]1)
    $position = [int]$Layout.PointerPosition
    $pidOffset = [int]$Layout.Offsets["UniqueProcessId"]
    foreach ($page in $pages) {
        $bytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address $page[1] -Count 4096
        if ($bytes.Length -lt 4096) { $result.UnreadablePages++; continue }
        $first = [long]$page[0] * $perPage
        for ($k = 0; $k -lt $perPage; $k++) {
            $bits = ([BitConverter]::ToUInt64($bytes, $k * $Layout.EntrySize) -shr $position) -band $mask
            if ($bits -eq 0) { continue }
            $object = $bits -shl 4
            if (($object -band $signBit) -ne 0) { $object = $object -bor $extend }
            if (-not $Cache.ContainsKey($object)) {
                # A thread (most entries): one byte, its type
                $type = Read-DbgEngVirtual -Session $Session -Process 0 -Address $object -Count 1
                if ($type.Length -ne 1 -or $type[0] -ne 3) { $Cache[$object] = $null; continue }
            }
            $block = Get-DbgEngProcessBlock -Session $Session -Layout $Layout -Address $object -Cache $Cache
            if ($null -eq $block) { continue }
            $id = ($first + $k) * 4
            if ([BitConverter]::ToUInt64($block, $pidOffset) -eq [uint64]$id) { [void]$result.Own.Add($object) }
            elseif (Test-DbgEngProcessShape -Layout $Layout -Block $block) { $result.Mismatched.Add(@([long]$id, $object)) }
            else { $result.NotProcesses++; continue }
            if ($listed.Add($object)) { $result.Entries.Add($object) }
        }
    }
    if ($pages.Count -gt 0 -and $result.UnreadablePages -ge $pages.Count) { $result.Error = "its pages are not in the dump" }
    return $result
}

# The processes the walks and the process ID table found, each once (by
# its EPROCESS address): in the forward walk's order, then those the
# forward walk missed that the backward walk found (in list order), then
# those only the process ID table has (in ID order). Addresses, and Methods:
# for each, the ways that found it (1 forward, 2 backward, 4 the process
# ID table, added).
function Join-DbgEngProcessSets {
    param($Forward, $Backward, $Cid)
    $methods = New-Object 'System.Collections.Generic.Dictionary[uint64,int]'
    $order = New-Object 'System.Collections.Generic.List[uint64]'
    $backwardInListOrder = @($Backward)
    [Array]::Reverse($backwardInListOrder)
    foreach ($set in @(@(1, @($Forward)), @(2, $backwardInListOrder), @(4, @($Cid)))) {
        foreach ($address in $set[1]) {
            $key = [uint64]$address
            if (-not $methods.ContainsKey($key)) {
                $methods[$key] = 0
                $order.Add($key)
            }
            $methods[$key] = $methods[$key] -bor $set[0]
        }
    }
    return [PSCustomObject]@{ Addresses = $order.ToArray(); Methods = [int[]]@($order | ForEach-Object { $methods[$_] }) }
}

# The debugger engine's own list of processes, as WinDbg's
# dx @$cursession.Processes shows it (the idle process left out), to
# compare with the scan: Count (-1 when not read) and Corrupt (the engine
# reported "corrupted linked list": its list ends there)
function Get-DbgEngEngineProcessCount {
    param($Session)
    $result = [PSCustomObject]@{ Count = [long]-1; Corrupt = $false }
    $text = Invoke-DbgEngCommand -Session $Session -Command 'dx @$cursession.Processes.Where(p => p.Id != 0).Count()' -TimeoutSeconds 120
    foreach ($line in ("$text" -split "\r?\n")) {
        if ($line -match '\.Count\(\)\s*:\s*0x([0-9a-fA-F]+)\s*$') { $result.Count = [Convert]::ToInt64($Matches[1], 16) }
        elseif ($line -match '\.Count\(\)\s*:\s*(\d+)\s*$') { $result.Count = [long]$Matches[1] }
        elseif ($line -match '^\s*WARNING:.*corrupted linked list') { $result.Corrupt = $true }
    }
    return $result
}

# "1 process" or "2 processes": a count and the word for it
function Format-DbgEngCount {
    param([long]$Count, [string]$One, [string]$Many)
    if ($Count -eq 1) { return "1 $One" }
    return "$Count $Many"
}

# Items of a list in a sentence: "a", "a and b", "a, b and c"; with
# -Semicolons (items that have commas of their own) "a; b; c". After -Max
# items, "and N more".
function Join-DbgEngWords {
    param([string[]]$Items, [switch]$Semicolons, [int]$Max = 10)
    $all = @($Items)
    $shown = @($all | Select-Object -First $Max)
    $more = $all.Count - $shown.Count
    if ($Semicolons) {
        $text = $shown -join "; "
        if ($more -gt 0) { $text += "; and $more more" }
        return $text
    }
    if ($more -gt 0) { return ($shown -join ", ") + " and $more more" }
    if ($shown.Count -le 1) { return ($shown -join "") }
    return ($shown[0..($shown.Count - 2)] -join ", ") + " and " + $shown[-1]
}

# What the log says about the process scan. Info: what each way found
# (logged when the scan's processes are used); Ways: the same without the
# total (for the line that says the scan found none). Note: for an analyst
# to judge the dump when something does not fit, the ways disagree, the
# list was inconsistent, or the debugger engine's own list has another
# count ("" when all agree): the warning "Memory dump process list: <note>",
# which the findings report shows as a coverage note. What copying memory
# does not explain comes first: processes that look hidden from the list
# and process IDs that look changed, by PID; then the IDs that cannot be
# judged and the capture churn (counted). It has no ": " (the report's
# notes have one colon).
#   -Methods        the ways that found each process (Join-DbgEngProcessSets)
#   -Missed         each process both walks missed: Pid, Why: Hidden (not
#                   created during the copy or within the churn margin
#                   before it, no exit time, and a walk reached the list's
#                   end), Exited, New (created during the copy), JustBefore
#                   (created within the churn margin before it), Unwalked
#                   (both walks stopped early) or "" (the capture start, or
#                   for a process created after it the end, is not known),
#                   and When (Get-DbgEngCreateWhen)
#   -IdChanges      each process whose ID does not fit: Address, Pid, Kind
#                   (Zero, Invalid, or Table: held in the process ID table
#                   under another ID), TableIds and When
#                   (Get-DbgEngCreateWhen), judged by
#                   Get-DbgEngIdChangeVerdict
#   -StaleEntries   entries of the process ID table that hold a process
#                   that is there under its own ID too
#   -EngineCount    the engine's own list (-1: not read); -EngineCorrupt:
#                   it reported a corrupted list
function Get-DbgEngScanText {
    param($Forward, $Backward, $Cid, [int[]]$Methods, [object[]]$Missed = @(), [object[]]$IdChanges = @(), [int]$StaleEntries = 0, [long]$EngineCount = -1, [bool]$EngineCorrupt = $false)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $walkText = {
        param($walk)
        $parts = @()
        if ($walk.Mismatches -gt 0) { $parts += (Format-DbgEngCount -Count $walk.Mismatches -One "inconsistent link" -Many "inconsistent links") }
        if ($walk.Stop) { $parts += "stopped at $($walk.Stop)" }
        $text = "$($walk.Entries.Count)"
        if ($parts.Count -gt 0) { $text += " ($($parts -join ', '))" }
        return $text
    }
    $total = @($Methods).Count
    $ways = "the kernel's process list walked forwards $(& $walkText $Forward), backwards $(& $walkText $Backward)"
    if ($Cid.Error) { $ways += ", its process ID table not read [$($Cid.Error)]" }
    else {
        $ways += ", in its process ID table $($Cid.Entries.Count)"
        $tableParts = @()
        if ($Cid.UnreadablePages -gt 0) { $tableParts += "$(Format-DbgEngCount -Count $Cid.UnreadablePages -One 'page' -Many 'pages') of it not in the dump" }
        if ($Cid.NotProcesses -gt 0) { $tableParts += "$(Format-DbgEngCount -Count $Cid.NotProcesses -One 'entry' -Many 'entries') left out whose object only starts like a process" }
        if ($tableParts.Count -gt 0) { $ways += " ($($tableParts -join ', '))" }
    }
    if ($EngineCount -ge 0) { $ways += ", in the debugger engine's own list $EngineCount" }
    $info = "    Processes found: $total; $ways"

    # How many processes each combination of ways found
    $all = 3
    if (-not $Cid.Error) { $all = 7 }
    $counts = @{}
    foreach ($way in @($Methods)) { $counts[[int]$way] = 1 + [int]$counts[[int]$way] }
    $places = 0
    foreach ($walk in @($Forward, $Backward)) { $places = [Math]::Max($places, [int]$walk.Mismatches + [int][bool]$walk.Broken) }
    $partial = @($counts.Keys | Where-Object { $_ -ne $all })
    $engineDiffers = $EngineCount -ge 0 -and ($EngineCount -ne $total -or $EngineCorrupt)
    $missedList = @($Missed | Where-Object { $null -ne $_ })
    $changes = @($IdChanges | Where-Object { $null -ne $_ })
    if ($places -eq 0 -and $partial.Count -eq 0 -and -not $engineDiffers -and $changes.Count -eq 0 -and $StaleEntries -eq 0) {
        return [PSCustomObject]@{ Info = $info; Ways = $ways; Note = "" }
    }

    $sentences = New-Object System.Collections.Generic.List[string]
    $oddTimes = @("NoTime", "Late")
    # What copying memory does not explain, first
    $hidden = @($missedList | Where-Object { $_.Why -eq "Hidden" })
    if ($hidden.Count -gt 0) {
        $one = $hidden.Count -eq 1
        if (@($hidden | Where-Object { $_.When -ne "Before" }).Count -eq 0) {
            $ids = Join-DbgEngWords -Items @($hidden | ForEach-Object { ([long]$_.Pid).ToString($invariant) })
            if ($one) { $sentences.Add("PID $ids is in neither walk of the kernel's process list, only in its process ID table, yet it was created before the capture started and has no exit time.") }
            else { $sentences.Add("PIDs $ids are in neither walk of the kernel's process list, only in its process ID table, yet they were created before the capture started and have no exit time.") }
        }
        else {
            # A create time that is 0 or after the capture ended: said by PID
            $timeText = @{ NoTime = " (no create time)"; Late = " (created after the capture ended)" }
            $ids = Join-DbgEngWords -Items @($hidden | ForEach-Object { "$(([long]$_.Pid).ToString($invariant))$($timeText[[string]$_.When])" })
            if ($one) { $sentences.Add("PID $ids is in neither walk of the kernel's process list, only in its process ID table, yet it has no exit time and was not created while memory was being copied.") }
            else { $sentences.Add("PIDs $ids are in neither walk of the kernel's process list, only in its process ID table, yet they have no exit time and were not created while memory was being copied.") }
        }
        $sentences.Add("Copying memory does not explain that, as a process leaves the list only when it ends, and a process hidden from the list (unlinked from it) looks exactly like this.")
    }
    # The processes whose ID does not fit, by PID and address; -Times: when
    # each was created, against the capture
    $changeItems = {
        param([object[]]$List, [switch]$Times)
        $timeText = @{ Before = ", created before the capture started"; NoTime = ", without a create time"; Late = ", created after the capture ended"
            Churn = ", created during the copy or shortly before it"; NoEnd = ", created after the capture started" }
        $items = foreach ($change in $List) {
            $item = "PID $(([long]$change.Pid).ToString($invariant)) at 0x$(([uint64]$change.Address).ToString('x'))"
            if ($change.Kind -eq "Zero") { $item += ", an ID only the idle process has" }
            elseif ($change.Kind -eq "Invalid") { $item += ", not a multiple of 4 as Windows gives them" }
            $tableIds = @($change.TableIds | ForEach-Object { ([long]$_).ToString($invariant) })
            if ($tableIds.Count -eq 1) { $item += ", held in the process ID table under ID $($tableIds[0])" }
            elseif ($tableIds.Count -gt 1) { $item += ", held in the process ID table under IDs $(Join-DbgEngWords -Items $tableIds)" }
            if ($Times) { $item += $timeText[[string]$change.When] }
            $item
        }
        return (Join-DbgEngWords -Items @($items) -Semicolons)
    }
    $verdicts = @{ Marked = @(); Churn = @(); Unjudged = @() }
    foreach ($change in $changes) {
        $verdict = Get-DbgEngIdChangeVerdict -Kind $change.Kind -TableIdCount @($change.TableIds).Count -When $change.When
        $verdicts[$verdict] += $change
    }
    $changed = @($verdicts["Marked"])
    $churn = @($verdicts["Churn"])
    if ($changed.Count -gt 0) {
        $one = $changed.Count -eq 1
        $allBefore = @($changed | Where-Object { $_.When -ne "Before" }).Count -eq 0
        $sentences.Add("$(Format-DbgEngCount -Count $changed.Count -One 'process has a process ID that Windows did not give it' -Many 'processes have a process ID that Windows did not give them') ($(& $changeItems $changed -Times:(-not $allBefore))).")
        if ($allBefore) { $sentences.Add("Copying memory does not explain that, as $(if ($one) { 'it was' } else { 'they were' }) created before the capture started, and a process whose ID was changed in memory, to hide or disguise it, looks like this.") }
        else { $sentences.Add("Copying memory does not explain that, and a process whose ID was changed in memory, to hide or disguise it, looks like this.") }
    }
    # A create time of 0 or after the capture ended does not make churn
    if (@(@($hidden) + @($changed) | Where-Object { $oddTimes -contains [string]$_.When }).Count -gt 0) {
        $sentences.Add("Capture churn is a process created between the capture's start and end (the time in the dump's header and the dump file's last-write time) or shortly before: one without a create time, or created after the capture ended, is not.")
    }
    # Not judged: the capture start, or for a process created after it the
    # end, is not known
    foreach ($group in @(@("", "the capture's start time (the time in the dump's header)", "", ""), @("NoEnd", "the capture's end time (the dump file's last-write time)", ", as it was created after the capture started", ", as they were created after the capture started"))) {
        $unjudged = @($verdicts["Unjudged"] | Where-Object { [string]$_.When -eq $group[0] })
        if ($unjudged.Count -eq 0) { continue }
        $one = $unjudged.Count -eq 1
        $sentences.Add("$(Format-DbgEngCount -Count $unjudged.Count -One 'process has a process ID that does not fit' -Many 'processes have a process ID that does not fit') ($(& $changeItems $unjudged)).")
        $sentences.Add("Whether copying memory explains that cannot be judged without $($group[1])$(if ($one) { $group[2] } else { $group[3] }), so $(if ($one) { 'it is' } else { 'they are' }) not marked.")
    }
    # Capture churn: created while the memory was copied, or shortly before
    if ($churn.Count -gt 0) {
        $one = $churn.Count -eq 1
        $sentences.Add("$(Format-DbgEngCount -Count $churn.Count -One 'process is' -Many 'processes are') capture churn, started while memory was being copied (or at most $(Get-DbgEngChurnSeconds) seconds before it), with $(if ($one) { 'a stale process ID table entry' } else { 'stale process ID table entries' }) ($(& $changeItems $churn)).")
        $sentences.Add("The process ID table and a process's memory are copied at different moments, and a short-lived process that ends in between leaves its ID or its memory to a new process, so copying memory explains this; $(if ($one) { 'it is' } else { 'they are' }) not marked.")
    }
    if ($places -gt 0) {
        $sentences.Add("The kernel's list of processes was inconsistent in $(Format-DbgEngCount -Count $places -One 'place' -Many 'places'), as when memory is copied while Windows runs and processes start or end during the copy.")
    }
    if ($StaleEntries -gt 0) {
        $sentences.Add("$(Format-DbgEngCount -Count $StaleEntries -One 'entry' -Many 'entries') of the process ID table $(if ($StaleEntries -eq 1) { 'holds' } else { 'hold' }) a process that is there under its own ID too, as when the table changes during the copy.")
    }
    $only = @{ 1 = "only by walking forwards"; 2 = "only by walking backwards"; 4 = "only in the process ID table" }
    $missedBy = @{ 1 = "missed by walking forwards"; 2 = "missed by walking backwards"; 4 = "not in the process ID table" }
    $allWays = if ($all -eq 7) { "all three ways (walking the kernel's process list forwards, walking it backwards, and its process ID table)" } else { "both walks of the kernel's process list" }
    $found = "$(Format-DbgEngCount -Count $total -One 'process was' -Many 'processes were') found, $([int]$counts[$all]) of them by $allWays"
    foreach ($signature in @($partial | Sort-Object -Property @{ Expression = { $counts[$_] }; Descending = $true }, @{ Expression = { $_ } })) {
        $phrase = $only[$signature]
        if (-not $phrase) { $phrase = $missedBy[$all - $signature] }
        $found += ", $($counts[$signature]) $phrase"
        # The processes both walks missed, by PID
        if ($signature -eq 4 -and $missedList.Count -gt 0) {
            $why = @{ Exited = ", which had exited"; New = ", created after the capture started"; JustBefore = ", created at most $(Get-DbgEngChurnSeconds) seconds before the capture started" }
            $found += " ($(Join-DbgEngWords -Items @($missedList | ForEach-Object { "PID $(([long]$_.Pid).ToString($invariant))$($why[[string]$_.Why])" }) -Semicolons))"
        }
    }
    $sentences.Add("$found.")
    if (@($missedList | Where-Object { $_.Why -eq "Unwalked" }).Count -gt 0) {
        $sentences.Add("Both walks stopped before the end of the list, so a process only in the process ID table can be in the part of the list that neither walk reached.")
    }
    if ($Cid.Error) { $sentences.Add("The process ID table could not be read [$($Cid.Error)].") }
    if ($engineDiffers) {
        $engineText = "The debugger engine's own process list (dx @`$cursession.Processes in WinDbg) has $(Format-DbgEngCount -Count $EngineCount -One 'entry' -Many 'entries')"
        if ($EngineCorrupt) { $engineText += " and stops at the first inconsistent link" }
        $sentences.Add("$engineText.")
    }
    # After "Memory dump process list: " the note goes on in lower case
    $note = $sentences -join " "
    if ($note.StartsWith("The ")) { $note = "t" + $note.Substring(1) }
    return [PSCustomObject]@{ Info = $info; Ways = $ways; Note = $note }
}

# The session id of a process (its EPROCESS bytes): none when
# EPROCESS.Session is 0 (System, smss.exe and the other processes
# Volatility gives N/A), else the session space's id when the symbols
# describe it (_MM_SESSION_SPACE), else the process token's. Decided for
# each process: an id that cannot be read one way is read the other way;
# none when neither can be read (a process whose token is already gone).
function Get-DbgEngProcessSessionId {
    param($Session, $Layout, [byte[]]$Block)
    $space = [BitConverter]::ToUInt64($Block, $Layout.Offsets["Session"])
    if ($space -eq 0) { return $null }
    if ($Layout.MmSessionId -ge 0 -and (Test-DbgEngKernelAddress $space)) {
        $bytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address ($space + [uint64]$Layout.MmSessionId) -Count 4
        if ($bytes.Length -eq 4) { return [long][BitConverter]::ToUInt32($bytes, 0) }
    }
    if ($Layout.TokenSessionId -ge 0) {
        $token = [BitConverter]::ToUInt64($Block, $Layout.Offsets["Token"]) -band (-bnot $Layout.TokenRefMask)
        if (Test-DbgEngKernelAddress $token) {
            $bytes = Read-DbgEngVirtual -Session $Session -Process 0 -Address ($token + [uint64]$Layout.TokenSessionId) -Count 4
            if ($bytes.Length -eq 4) { return [long][BitConverter]::ToUInt32($bytes, 0) }
        }
    }
    return $null
}

# One windows.pslist entry from an EPROCESS's bytes, with the property
# names of Volatility's JSON (a process ID that does not fit is read as a
# signed number, as it is), and FoundBy, TableId and Anomaly, "" for now
function ConvertFrom-DbgEngProcessBlock {
    param($Session, $Layout, [uint64]$Address, [byte[]]$Block)
    $o = $Layout.Offsets
    $name = New-Object byte[] 15
    [Array]::Copy($Block, [int]$o["ImageFileName"], $name, 0, 15)
    return [PSCustomObject]@{
        PID = [BitConverter]::ToInt64($Block, $o["UniqueProcessId"]); PPID = [BitConverter]::ToInt64($Block, $o["InheritedFromUniqueProcessId"])
        ImageFileName = (ConvertFrom-DbgEngImageFileName $name); Offset = "0x$($Address.ToString('x'))"
        Threads = [long][BitConverter]::ToUInt32($Block, $o["ActiveThreads"]); SessionId = (Get-DbgEngProcessSessionId -Session $Session -Layout $Layout -Block $Block)
        CreateTime = (ConvertFrom-DbgEngFileTime ([BitConverter]::ToInt64($Block, $o["CreateTime"]))); ExitTime = (ConvertFrom-DbgEngFileTime ([BitConverter]::ToInt64($Block, $o["ExitTime"])))
        FoundBy = ""; TableId = ""; Anomaly = ""
    }
}

# The processes from the kernel's own structures (a layout without Error):
# Processes (windows.pslist entries, every process any way found, also one
# whose process ID does not fit, as windows.pslist lists what the list
# holds), Pebs (@(EPROCESS, PEB) of each, for its command line), Capped,
# and the log's text (Get-DbgEngScanText: Info, Ways, Note), which the
# caller logs only when these processes are used. Each entry says which
# ways found it (FoundBy: ListForward, ListBackward, ProcessIdTable), the
# ID the process ID table holds it under when that is not its own (TableId)
# and what copying memory does not explain (Anomaly: NotInProcessList, a
# process neither walk found, without an exit time, while a walk reached
# the list's end; ProcessIdChanged, an ID of 0, one that is not a multiple
# of 4, or one the table does not hold it under), judged by its create
# time against the capture (Get-DbgEngCreateWhen): one created during the
# copy or within the churn margin before it (Get-DbgEngChurnSeconds) is
# capture churn, which copying explains for a missed link or a stale table
# entry (Get-DbgEngIdChangeVerdict); one created earlier, without a create
# time or after the capture ended is marked; without -CaptureFileTime
# nothing is judged. -CaptureFileTime and -CaptureEndFileTime: when the
# capture started and ended (FILETIMEs), 0 when not known. Processes is
# empty when nothing was found.
function Read-DbgEngScannedProcesses {
    param($Session, $Layout, [long]$CaptureFileTime = 0, [long]$CaptureEndFileTime = 0)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $cache = New-Object 'System.Collections.Generic.Dictionary[uint64,object]'
    $forward = Invoke-DbgEngProcessWalk -Session $Session -Layout $Layout -Cache $cache
    $backward = Invoke-DbgEngProcessWalk -Session $Session -Layout $Layout -Cache $cache -Backward
    if ($Layout.CidError) {
        $cid = [PSCustomObject]@{ Entries = @(); Own = (New-Object 'System.Collections.Generic.HashSet[uint64]'); Mismatched = @(); NotProcesses = 0; Error = $Layout.CidError; UnreadablePages = 0 }
    }
    else { $cid = Get-DbgEngCidProcesses -Session $Session -Layout $Layout -Cache $cache }
    $joined = Join-DbgEngProcessSets -Forward $forward.Entries -Backward $backward.Entries -Cid $cid.Entries
    # The entries that hold a process under another ID than its own (a
    # List[object] from New-Object is walked as it is: @() around it fails
    # in both PowerShell editions with "Argument types do not match")
    $tableIds = @{}
    foreach ($entry in $cid.Mismatched) {
        $key = "$($entry[1])"
        if (-not $tableIds.ContainsKey($key)) { $tableIds[$key] = New-Object System.Collections.Generic.List[long] }
        $tableIds[$key].Add([long]$entry[0])
    }
    $walkEnded = $forward.Complete -or $backward.Complete
    $o = $Layout.Offsets
    $processes = New-Object System.Collections.Generic.List[object]
    $pebs = New-Object System.Collections.Generic.List[object]
    $missed = New-Object System.Collections.Generic.List[object]
    $idChanges = New-Object System.Collections.Generic.List[object]
    $staleEntries = 0
    for ($i = 0; $i -lt $joined.Addresses.Count; $i++) {
        $address = $joined.Addresses[$i]
        $methods = $joined.Methods[$i]
        $block = [byte[]]$cache[$address]
        $entry = ConvertFrom-DbgEngProcessBlock -Session $Session -Layout $Layout -Address $address -Block $block
        $entry.FoundBy = (@(@(1, "ListForward"), @(2, "ListBackward"), @(4, "ProcessIdTable")) | Where-Object { ($methods -band $_[0]) -ne 0 } | ForEach-Object { $_[1] }) -join ","
        $anomalies = @()
        # When it was created, against the capture (Get-DbgEngCreateWhen):
        # copying explains a missed link or a stale table entry only for a
        # process created during the copy or shortly before it (Churn)
        $createTime = [BitConverter]::ToInt64($block, $o["CreateTime"])
        $when = Get-DbgEngCreateWhen -CreateTime $createTime -CaptureFileTime $CaptureFileTime -CaptureEndFileTime $CaptureEndFileTime
        # Both walks missed it: did it end, start during the copy, or hide?
        if (($methods -band 3) -eq 0) {
            $exitTime = [BitConverter]::ToInt64($block, $o["ExitTime"])
            $why = ""
            if ($exitTime -gt 0) { $why = "Exited" }
            elseif ($when -eq "Churn" -and $createTime -ge $CaptureFileTime) { $why = "New" }
            elseif ($when -eq "Churn") { $why = "JustBefore" }
            elseif (-not $walkEnded) { $why = "Unwalked" }
            elseif ($when -eq "Before" -or $when -eq "NoTime" -or $when -eq "Late") { $why = "Hidden"; $anomalies += "NotInProcessList" }
            $missed.Add([PSCustomObject]@{ Pid = $entry.PID; Why = $why; When = $when })
        }
        # Its process ID: one Windows gives, and the one the table holds it
        # under? (Get-DbgEngIdChangeVerdict)
        $kind = Get-DbgEngProcessIdKind -Layout $Layout -Block $block
        $ids = @()
        if ($tableIds.ContainsKey("$address")) { $ids = @($tableIds["$address"]) }
        if ($ids.Count -gt 0) { $entry.TableId = (@($ids | ForEach-Object { $_.ToString($invariant) }) -join ",") }
        if ($kind -ne "Valid" -or ($ids.Count -gt 0 -and -not $cid.Own.Contains($address))) {
            $changeKind = if ($kind -ne "Valid") { $kind } else { "Table" }
            if ((Get-DbgEngIdChangeVerdict -Kind $changeKind -TableIdCount $ids.Count -When $when) -eq "Marked") { $anomalies += "ProcessIdChanged" }
            $idChanges.Add([PSCustomObject]@{ Address = $address; Pid = $entry.PID; Kind = $changeKind; TableIds = $ids; When = $when })
        }
        elseif ($ids.Count -gt 0) { $staleEntries += $ids.Count }
        $entry.Anomaly = $anomalies -join ","
        $processes.Add($entry)
        $pebs.Add(@($address, [BitConverter]::ToUInt64($block, $o["Peb"])))
    }
    $engine = [PSCustomObject]@{ Count = [long]-1; Corrupt = $false }
    try { $engine = Get-DbgEngEngineProcessCount -Session $Session }
    catch { Write-DbgEngLog "    The debugger engine's own process list could not be counted: $(Get-DbgEngShortError (Get-DbgEngErrorText $_))" }
    $text = Get-DbgEngScanText -Forward $forward -Backward $backward -Cid $cid -Methods $joined.Methods -Missed $missed.ToArray() -IdChanges $idChanges.ToArray() `
        -StaleEntries $staleEntries -EngineCount $engine.Count -EngineCorrupt $engine.Corrupt
    return [PSCustomObject]@{
        Processes = $processes.ToArray(); Pebs = $pebs.ToArray(); Capped = ($forward.Capped -or $backward.Capped); BadItems = 0
        Info = $text.Info; Ways = $text.Ways; Note = $text.Note
    }
}

# The processes from the debugger engine's own list (dx queries), when the
# kernel's symbols do not describe its process structures: Processes,
# Pebs, Capped, BadItems (list items that could not be read), and Why
# (why nothing was listed). The engine's list ends at the first
# inconsistent link of a dump copied while Windows ran; the engine says so
# ("corrupted linked list"), and so does the log, with the warning the
# findings report shows.
function Read-DbgEngEngineProcesses {
    param($Session)
    $found = [PSCustomObject]@{ Processes = @(); Pebs = @(); Capped = $false; BadItems = 0; Why = "" }
    $list = Get-DbgEngDxPages -Session $Session -Template (Get-DbgEngQuery Process) -Tag "TBP" -FieldCount 8
    if ($list.Rows.Count -eq 0) {
        $found.Why = $list.QueryError
        if (-not $found.Why) { $found.Why = $list.FirstBad }
        return $found
    }
    if ($list.QueryError) { Write-DbgEngLog -Warning "  The process list stopped after $($list.Items) entries: $(Get-DbgEngShortError $list.QueryError)" }
    if ($list.Capped) { Write-DbgEngLog -Warning "  The process list did not end after 20000 entries (a damaged dump?): the first 20000 are used." }
    $found.Capped = $list.Capped
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
        # Memory that was reused, taken for a process at a damaged link: no
        # process ID is negative, past 2^32 or not a multiple of 4
        if ($procId -lt 0 -or $procId -ge 4294967296 -or $procId % 4 -ne 0) { $malformed++; continue }
        if ($seen.ContainsKey("$eprocess")) { continue }   # a list that loops
        $seen["$eprocess"] = $true
        # The idle process (PID 0) is not in the kernel's process list
        # that windows.pslist walks
        if ($procId -eq 0) { continue }
        $processes.Add([PSCustomObject]@{
                PID = $procId; PPID = (ConvertFrom-DbgEngNumber $row[2]); ImageFileName = (Read-DbgEngImageFileName -Session $Session -Address $nameAddress)
                Offset = "0x$($eprocess.ToString('x'))"; Threads = (ConvertFrom-DbgEngNumber $row[5]); SessionId = $null
                CreateTime = (ConvertFrom-DbgEngFileTime (ConvertFrom-DbgEngNumber $row[3])); ExitTime = (ConvertFrom-DbgEngFileTime (ConvertFrom-DbgEngNumber $row[4]))
            })
        $pebs.Add(@($eprocess, $peb))
    }
    $found.BadItems = $malformed
    # The engine's warnings: a corrupted list (the processes after the
    # break, the newest, are missing) for the findings report; others as
    # they are
    foreach ($warning in @($list.Warnings)) {
        if ($warning -match 'corrupted linked list') {
            Write-DbgEngLog -Warning "  Memory dump process list: the debugger engine found the kernel's list of processes inconsistent (corrupted linked list), as when memory is copied while Windows runs and processes start or end during the copy, and lists only the $($processes.Count) processes before that place, so the newest processes can be missing. The kernel's own process structures could not be read to find them."
        }
        else { Write-DbgEngLog "    The debugger engine warned: $(Get-DbgEngShortError ($warning -replace '^WARNING:\s*', ''))" }
    }
    # Session ids, decided for each process: -1 (no session) or the session
    # space's id, else the process token's (Get-DbgEngQuery)
    $sessions = @{}
    try {
        $spaceList = Get-DbgEngDxPages -Session $Session -Template (Get-DbgEngQuery Session) -Tag "TBS" -FieldCount 2
        foreach ($row in $spaceList.Rows) {
            $key = ConvertFrom-DbgEngNumber $row[0] -Hex
            $id = ConvertFrom-DbgEngNumber $row[1]
            if ($null -ne $key -and $null -ne $id -and $id -ge -1) { $sessions["$key"] = $id }
        }
        $missing = @($pebs | Where-Object { -not $sessions.ContainsKey("$($_[0])") }).Count
        if ($missing -gt 0) {
            $why = $spaceList.QueryError
            if (-not $why) { $why = $spaceList.FirstBad }
            if (-not $why) { $why = "none read" }
            Write-DbgEngLog "    Session ids: $(Get-DbgEngShortError $why); the token's session id is used for $missing process(es)"
            $tokenList = Get-DbgEngDxPages -Session $Session -Template (Get-DbgEngQuery TokenSession) -Tag "TBS" -FieldCount 2
            foreach ($row in $tokenList.Rows) {
                $key = ConvertFrom-DbgEngNumber $row[0] -Hex
                $id = ConvertFrom-DbgEngNumber $row[1]
                if ($null -ne $key -and $null -ne $id -and $id -ge -1 -and -not $sessions.ContainsKey("$key")) { $sessions["$key"] = $id }
            }
        }
    }
    catch { Write-DbgEngLog -Warning "  The session ids could not be read: $(Get-DbgEngShortError (Get-DbgEngErrorText $_))" }
    for ($i = 0; $i -lt $processes.Count; $i++) {
        $key = "$($pebs[$i][0])"
        if ($sessions.ContainsKey($key) -and $sessions[$key] -ge 0) { $processes[$i].SessionId = $sessions[$key] }
    }
    $found.Processes = $processes.ToArray()
    $found.Pebs = $pebs.ToArray()
    return $found
}

# When the capture started (or ended), from -CaptureStart (-CaptureEnd),
# yyyy-MM-ddTHH:mm:ss.fffffffZ, as a FILETIME; 0 when it is empty or not
# such a time
function ConvertFrom-DbgEngCaptureStart {
    param([string]$Text)
    $time = [datetime]::MinValue
    if ($Text -and [datetime]::TryParseExact($Text.Trim(), "o", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$time) -and
        $time.Kind -eq [DateTimeKind]::Utc -and $time.Year -ge 1980) { return $time.ToFileTimeUtc() }
    return [long]0
}

# The dump's processes and command lines (New-DbgEngResult). Nothing read:
# Reason says why. The processes read but not the command lines:
# PartialReason says why. -CaptureStart, -CaptureEnd: as the script's
# parameters.
function Read-DbgEngDump {
    param([string]$DumpPath, [string]$EngineFolder, [string[]]$EngineDlls, [string]$SymbolCache, [string]$JobFolder, [string]$CaptureStart, [string]$CaptureEnd)
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
            if ($symbols.Downloaded) { $symbols.ErrorKind = "NotAccepted" }
            else {
                Write-DbgEngLog -Warning "  The cached kernel symbol file does not match the dump and was deleted; downloading it again."
                $symbols = Get-KernelSymbolFile -Name $kernel.Name -Key $kernel.Key -CacheRoot $SymbolCache -Fallback $fallback
                if (-not $symbols.Error -and -not (Use-KernelSymbols -Session $session -Folder $symbols.Folder)) {
                    Remove-Item -LiteralPath $symbols.Path -Force -ErrorAction SilentlyContinue
                    $symbols.ErrorKind = "NotAccepted"
                }
            }
        }
        # Why there are no symbols, and what helps: another engine when this
        # one did not accept the file the server sent (the internet worked,
        # and the same file would be refused again), a folder that can be
        # written, or internet access
        $symbolProblem = $symbols.ErrorKind
        if (-not $symbolProblem -and $symbols.Error) { $symbolProblem = "Download" }
        switch ($symbolProblem) {
            "NotAccepted" {
                Write-DbgEngLog -Warning "  The Windows debugger engine did not accept the kernel symbol file that Microsoft's symbol server sent for this dump, and it was deleted. This engine may be too old for the dump, or the file was damaged on the way: put a newer engine in tools\dbgeng\ (see ""Microsoft debugger engine"" in README.txt) and run the builder again."
                $result.Reason = "the Windows debugger engine did not accept the kernel symbol file from Microsoft's symbol server (this engine may be too old for the dump); put a newer engine in tools\dbgeng\ and run the builder again, see ""Microsoft debugger engine"" in README.txt"
                return $result
            }
            "Folder" {
                Write-DbgEngLog "  Neither tools\symbols\ nor the work folder can be written ($($symbols.Error)), so the kernel symbol file has nowhere to go."
                $result.Reason = "no folder for the Windows kernel symbol file could be written ($($symbols.Error)); make tools\symbols\ next to the builder writable, or use a -WorkDir that can be written, and run the builder again"
                return $result
            }
            "Download" {
                Write-DbgEngLog "  To analyze it without internet access here, download $($symbols.Url) on another computer and copy it to $(Join-Path $SymbolCache "$($kernel.Name)\$($kernel.Key)\$($kernel.Name)"), then run the builder again."
                $result.Reason = "the Windows kernel symbol file could not be downloaded from Microsoft's symbol server ($($symbols.Error)); connect to the internet and run the builder again, or see ""Windows kernel symbols"" in README.txt"
                return $result
            }
        }

        # Processes (windows.pslist): from the kernel's own structures, or,
        # when its symbols do not describe them, the debugger engine's list
        $layout = Get-DbgEngKernelLayout -Session $session
        $found = $null
        if (-not $layout.Error) {
            $found = Read-DbgEngScannedProcesses -Session $session -Layout $layout -CaptureFileTime (ConvertFrom-DbgEngCaptureStart $CaptureStart) -CaptureEndFileTime (ConvertFrom-DbgEngCaptureStart $CaptureEnd)
            if (@($found.Processes).Count -eq 0) {
                # Its counts and note are not about the rows the timeline gets
                Write-DbgEngLog "    No process was found in the kernel's own process structures: $($found.Ways)"
                $layout.Error = "no process was found in them"
                $found = $null
            }
            else {
                Write-DbgEngLog $found.Info
                if ($found.Note) { Write-DbgEngLog -Warning "  Memory dump process list: $($found.Note)" }
                if ($found.Capped) { Write-DbgEngLog -Warning "  The kernel's process list did not end after 20000 entries (a damaged dump?): the first 20000 each way are used." }
            }
        }
        if (-not $found) {
            Write-DbgEngLog -Warning "  The kernel's own process structures could not be read ($($layout.Error)): the debugger engine's own process list is used, which misses the newest processes when the list changed while the memory was copied."
            $found = Read-DbgEngEngineProcesses -Session $session
            if (@($found.Processes).Count -eq 0) {
                $whyText = if ($found.Why) { " ($(Get-DbgEngShortError $found.Why))" } else { "" }
                $result.Reason = "the Windows debugger engine listed no processes in it$whyText"
                return $result
            }
        }
        $processes = @($found.Processes)
        $pebs = @($found.Pebs)
        $result.Processes = $processes
        $result.BadItems = $found.BadItems
        $result.Capped = $found.Capped
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
        $workerResult = Read-DbgEngDump -DumpPath $DumpPath -EngineFolder $EngineFolder -EngineDlls @("$EngineDlls" -split ',' | Where-Object { $_ }) -SymbolCache $SymbolCache -JobFolder $JobFolder -CaptureStart $CaptureStart -CaptureEnd $CaptureEnd
    }
    catch {
        $workerResult = New-DbgEngResult
        $workerResult.Reason = "the Windows debugger engine stopped ($(Get-DbgEngShortError (Get-DbgEngErrorText $_)))"
    }
    Write-DbgEngWorkerResult $workerResult
    exit 0
}
