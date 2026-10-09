VOLATILITY 3 -- memory analysis (optional)
==========================================

This folder is where the timeline builder looks for Volatility 3. The tool
itself is NOT included in this repository (it has its own license and
release cycle); download it yourself. Everything in this folder except this
README is ignored by git and never committed.


GET IT
------
  1. Open the Volatility 3 releases page:
       https://github.com/volatilityfoundation/volatility3/releases
  2. Download the Windows executables asset of the latest release:
       volatility3-win-exes-<version>.zip     (e.g. 2.28.2, ~42 MB)
     GitHub shows a SHA-256 digest for each asset; compare it with
     Get-FileHash before extracting.
  3. Extract it into this folder, so that this file exists:
       tools\volatility3\vol.exe
     (the zip also contains volshell.exe, README.md and LICENSE.txt)

  No Python install is needed. vol.exe is an x64 build; on Windows on ARM
  it runs under x64 emulation.


HOW THE BUILDER USES IT
-----------------------
  - When a memory dump is found where the collector saved it (next to the
    collection zip, or on another drive as collection_manifest.csv
    records: <collection>_memory_dump.dmp from DumpIt, or
    _memory_dump.raw), the builder offers memory analysis, or runs it with
    -Sources ...,Memory.
  - Plugins: windows.pslist, windows.netscan, windows.cmdline,
    windows.svcscan. Results are added to the timeline (Source Memory-*).
  - Expect 5-30 minutes depending on the dump size. On first use Volatility
    downloads Windows symbol tables from Microsoft's symbol server, so the
    first run needs internet access.


LIMITATION: WINDOWS ON ARM
--------------------------
  Volatility 3 analyzes Windows memory from Intel x86/x64 systems only. The
  triage collector CAN capture memory on Windows ARM64 (DumpIt has an ARM64
  build), but the builder detects ARM64 dumps from the crash dump header and
  skips Volatility for them. Open those .dmp files in WinDbg instead.
