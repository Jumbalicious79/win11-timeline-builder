WINDOWS KERNEL SYMBOLS -- for Windows ARM64 memory dumps (auto-downloaded)
==========================================================================

The timeline builder reads Windows ARM64 memory dumps with Microsoft's
debugger engine (Volatility 3 cannot read Windows ARM64 memory). The engine
needs the symbol file (PDB) of the exact Windows kernel in the dump to find
its processes. The builder downloads that one file the first time it
analyzes a dump of a Windows build and keeps it here, so later runs -- and
other dumps of the same Windows build -- need no internet access.
Everything in this folder except this README is ignored by git and never
committed.


LAYOUT
------
  tools\symbols\<name>\<ID>\<name>

  for example
  tools\symbols\ntkrnlmp.pdb\0A1B2C3D4E5F60718293A4B5C6D7E8F91\ntkrnlmp.pdb

  <name> is the kernel's symbol file name (ntkrnlmp.pdb on current Windows),
  <ID> its GUID (32 hex digits) and age (hex), read from the kernel image
  in the dump. This is the layout of a symbol server's downstream store, so
  WinDbg can use this folder as its cache too (below). About 10 MB per
  Windows build (9.7 MB for build 26100 on ARM64).


WHERE IT COMES FROM
-------------------
  Microsoft's public symbol server, over HTTPS:

    https://msdl.microsoft.com/download/symbols/<name>/<ID>/<name>

  Only this one file is downloaded, and only for an ARM64 memory dump that
  is analyzed. The request is the only thing that leaves the computer, and
  it names only that file: the kernel's file name and its GUID and age,
  which are the same for every computer running that Windows build.
  Nothing else about the dump, the collection or the examined computer is
  sent. Like any web request it comes from your public IP address and
  carries PowerShell's user agent (the analysis computer's Windows and
  PowerShell versions). The system's proxy settings are used; a proxy that
  needs a sign-in is not supported.

  The debugger engine itself never contacts a symbol server: its symbol
  path is a local folder, and _NT_SYMBOL_PATH is ignored.

  The download is checked (its size, the PDB signature "Microsoft C/C++ MSF
  7.00") and kept only when the debugger engine accepts it for the kernel
  in the dump (dbghelp loads a symbol file only when its GUID and age are
  the kernel's). A file here that does not match is deleted and downloaded
  again.


WITHOUT INTERNET ACCESS
-----------------------
  The builder reports the dump as not analyzed and logs the URL and the
  path, for example:

    To analyze it without internet access here, download
    https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/<ID>/ntkrnlmp.pdb
    on another computer and copy it to
    <builder>\tools\symbols\ntkrnlmp.pdb\<ID>\ntkrnlmp.pdb, then run the
    builder again.

  If this folder cannot be written (a read-only drive), the file goes to
  the run's work folder instead and is downloaded again next time.


WINDBG
------
  WinDbg and its command-line debuggers can share this folder:

    kdARM64.exe -z "<dump>" -y "srv*<builder>\tools\symbols*https://msdl.microsoft.com/download/symbols"

  (kd.exe of Debugging Tools for Windows takes the same options.)


DELETING
--------
  Deleting this folder's contents is always safe: a file is downloaded
  again the next time it is needed.
