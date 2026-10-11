MICROSOFT DEBUGGER ENGINE -- Windows ARM64 memory dumps (optional)
==================================================================

The timeline builder reads Windows ARM64 memory dumps (DumpIt on a Windows
on Arm computer) with Microsoft's debugger engine, the engine of WinDbg:
Volatility 3 cannot read Windows ARM64 memory. The engine is part of
Windows (C:\Windows\System32\dbgeng.dll, dbghelp.dll, dbgmodel.dll), and
the builder uses that one: NOTHING HAS TO BE PUT IN THIS FOLDER.

This folder is for a newer copy of the engine, from Microsoft's NuGet
package, for an analysis computer whose own engine cannot read a dump of a
newer Windows (an older Windows 10, for example: the log and the findings
report then say the engine could not open the dump, did not accept the
kernel symbol file from Microsoft's symbol server, or listed no processes
in it). Everything in this folder except this README is ignored
by git and never committed; the DLLs are Microsoft's and are not
redistributed with this repository.


GET IT
------
  1. Open the package page:
       https://www.nuget.org/packages/Microsoft.Debugging.Platform.DbgEng
  2. Choose "Download package". You get a .nupkg file: rename it to .zip
     and open it.
  3. Copy EVERY file of its content\<arch>\ folder into a folder of the
     same name here:
       tools\dbgeng\arm64\     for an ARM64 PowerShell (Windows on Arm)
       tools\dbgeng\amd64\     for an x64 PowerShell
       tools\dbgeng\x86\       for a 32-bit PowerShell
     <arch> is the processor architecture of the PowerShell that runs the
     builder, not the dump's: Run-TimelineBuilder.bat on a Windows on Arm
     computer runs the ARM64 PowerShell, so arm64\.
     The folder must have at least dbgeng.dll, dbghelp.dll and
     dbgmodel.dll (the package also has dbgcore.dll, msdia140.dll and
     others: copy them all).

  The symbol server package (Microsoft.Debugging.Platform.SymSrv) is NOT
  needed: the builder downloads the one kernel symbol file it needs itself
  (see tools\symbols\README.txt), and the engine never gets a symbol server.


HOW THE BUILDER USES IT
-----------------------
  - Only for a Windows ARM64 memory dump (parser #15, Memory), and only
    when every DLL in tools\dbgeng\<arch>\ -- subfolders too -- has a valid
    Authenticode signature from Microsoft (signer and issuer "Microsoft
    Corporation"), and dbgeng.dll, dbghelp.dll and dbgmodel.dll are there.
    The builder runs as Administrator, so a DLL that is not Microsoft's
    must never load: one unsigned or foreign DLL (an extension added by
    hand, say), and the whole folder is not used. The log then says which
    file and why, and the engine of Windows is used instead.
  - The DLLs are loaded by their full path (dbghelp, dbgcore, msdia140,
    dbgmodel, then dbgeng), in a PowerShell process of its own
    (memory\TimelineDbgEng.ps1); their own imports are looked for only in
    this folder and in System32, never on the PATH or in the current folder.
  - The log names the engine: "Debugger engine: dbgeng.dll <version> from
    <folder> (signed by Microsoft)".
  - What it reads: the dump's processes (as Volatility's windows.pslist)
    and their command lines (as windows.cmdline). Network connections and
    services are not read from ARM64 dumps.

  Deleting this folder's contents is always safe: the engine of Windows is
  used again.
