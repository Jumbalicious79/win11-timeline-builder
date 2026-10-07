# Windows 11 Forensic Timeline Builder

A pure PowerShell script that builds a unified, chronological CSV timeline from
Windows forensic artifacts. Designed as a lightweight alternative to
log2timeline/plaso, focused specifically on Windows 11 artifacts.

Designed to be used with win11-triage-collector, which collects the forensic
artifacts this script parses. The timeline builder is a pure parser -- it
reads only from the triage collection and never queries the local system.
Both tools are available as separate repos for independent use.

  Companion project: https://github.com/Jumbalicious79/win11-triage-collector


## Setup

Both tools MUST be sibling directories (same parent folder) for the automatic
browse mode to function. The timeline builder locates triage collections by
looking for ..\win11-triage-collector\reports\ relative to its own location.

Required directory structure:

  any-parent-folder\
    win11-triage-collector\       <-- companion repo
      triage-collector.ps1
      Run-TriageCollector.bat
      reports\                    <-- collections save here
    win11-timeline-builder\       <-- this repo
      timeline-builder.ps1
      Run-TimelineBuilder.bat
      reports\                    <-- timelines save here
      tools\                      <-- auto-downloaded on first run
        sqlite3\                  <-- browser history parser
        TimelineExplorer\         <-- forensic CSV viewer

To set up:

  git clone https://github.com/Jumbalicious79/win11-triage-collector
  git clone https://github.com/Jumbalicious79/win11-timeline-builder

Or download both repos and extract them into the same parent folder. The parent
folder can be anywhere -- your desktop, a USB drive, a network share, etc.

If you pass -InputPath directly, the sibling requirement does not apply. But
for the zero-config double-click workflow (browse mode), both directories must
be siblings.


## Intended Workflow

These two tools are designed to work together as a complete collect-and-analyze
pipeline. Double-click to collect, double-click to analyze -- no configuration,
no dependencies, no command-line knowledge needed.

  1. COLLECT: Run triage-collector on the target system
  2. ANALYZE: Run timeline-builder on the collection (this tool)
  3. REVIEW: Timeline Explorer auto-opens with the timeline loaded

### Live System (Dirty Forensics)

For incident response, triage, or non-legal investigations:

  1. Copy both tools to a USB drive
  2. Plug the USB into the target machine
  3. Double-click Run-TriageCollector.bat (collects to reports\ on the USB)
  4. Unplug the USB, take it to your analysis workstation
  5. Double-click Run-TimelineBuilder.bat -- it auto-finds the triage zips
  6. Pick a collection, timeline builds, Timeline Explorer opens automatically

### Forensic Image (Clean Forensics)

For legal cases or chain-of-custody requirements:

  1. Create a forensic image of the target system FIRST
     Use FTK Imager, dd, or your preferred imaging tool
  2. Mount the image as read-only on your analysis workstation (e.g., E:)
  3. Double-click Run-TriageCollector.bat -- select the mounted drive from
     the menu (the collector auto-detects mounted Windows volumes)
  4. Double-click Run-TimelineBuilder.bat -- select the collection
  5. The collection manifest (SHA256 hashes) provides integrity verification

The triage collector auto-detects live vs mounted images and adjusts its
collection methods accordingly. See the triage collector README for details
on what gets collected in each mode.

### USB Deployment Kit

Both tools are designed to live side-by-side on a USB drive:

  USB_DRIVE\
    win11-triage-collector\
      triage-collector.ps1
      Run-TriageCollector.bat
      tools\                      <-- optional: winpmem.exe for memory capture
      reports\                    <-- collections save here
    win11-timeline-builder\
      timeline-builder.ps1
      Run-TimelineBuilder.bat
      tools\                      <-- auto-downloaded: sqlite3, Timeline Explorer
        volatility3\              <-- optional: vol.exe for memory analysis
      reports\                    <-- timelines save here

The timeline builder auto-discovers triage collections from the sibling
directory. sqlite3.exe and Timeline Explorer are auto-downloaded on first run
and cached in the tools\ directory for future use. For memory capture and
analysis, place winpmem.exe in the collector's tools\ and vol.exe in the
builder's tools\volatility3\ (see Optional Tools sections in each README).


## Quick Start

### Double-click (recommended)

  Run-TimelineBuilder.bat

  No arguments needed. The script automatically:
    1. Finds triage collection .zip files from sibling triage-collector\reports\
    2. Lists them with size and date, newest first
    3. You pick a number
    4. Extracts to a temp folder (cleaned up after)
    5. Builds the timeline (~2 minutes for ~36,000 events)
    6. Generates a color-coded Excel file (rows colored by EventType)
    7. Asks how you want to view: Excel (colored), Timeline Explorer, Both, None

  You can also pass a path directly, optionally followed by a comma-separated
  keyword list (both in quotes):

  Run-TimelineBuilder.bat "path\to\triage\collection"
  Run-TimelineBuilder.bat "path\to\collection" "mimikatz,psexec"

  The launcher asks for Administrator rights (UAC) and restarts itself
  elevated with the same arguments. Paths with spaces, apostrophes, & or !
  are fine, and a relative path is turned into a full path first (the
  elevated window starts in C:\Windows\System32).

### PowerShell (Admin)

  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -Browse
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\Collection"
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\Collection" -StartDate "2025-01-15" -EndDate "2025-01-20"
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\Collection" -Sources "EventLogs,Prefetch,Registry"
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\Collection" -Keywords "mimikatz,psexec,powershell -enc"
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\Collection" -MaxUsnEntries 200000

  With -File, PowerShell passes a list such as "a","b" or a,b to the script as
  one string ("a,b"). The script splits -Sources and -Keywords on commas
  itself, so both forms work. From a PowerShell prompt (.\timeline-builder.ps1)
  normal arrays (-Keywords "a","b") work as well.


## Parameters

  -Browse         Auto-find triage zips in sibling triage-collector\reports\
                  and present a numbered menu to select one. No InputPath needed.
  -InputPath      Path to a triage collection directory or any directory
                  containing supported artifacts.
  -OutputFile     Output CSV path. Defaults to reports\timeline_<timestamp>\timeline.csv
  -StartDate      Only include events after this date (UTC).
  -EndDate        Only include events before this date (UTC).
  -Sources        Parsers to run, as an array or a comma-separated string.
                  Defaults to all 14 (Memory excluded).
                  Valid: EventLogs, Prefetch, RecentFiles, Registry, FileSystem,
                  Browser, ScheduledTasks, Services, Network, USB, Persistence,
                  UsnJournal, Amcache, PowerShellHistory, Memory
                  Note: Memory is opt-in. Requires Volatility 3 in tools\ and
                  a memory dump in the collection. Adds 5-30 minutes.
  -Keywords       Strings to flag in the timeline, as an array or a
                  comma-separated string ("mimikatz,psexec"). Spaces around
                  each keyword are trimmed and empty items ignored. Matching is
                  case-insensitive against Description, Details, User and
                  Source. Adds a Flagged column (TRUE/FALSE) for quick
                  filtering. A keyword cannot itself contain a comma.
  -MaxUsnEntries  Maximum number of USN journal rows to keep. The NEWEST rows
                  are kept (older ones are dropped first). Default 0 =
                  unlimited. The USN journal is usually the largest source;
                  see "Known Limitations" for the Excel row limit.


## Auto-Downloaded Dependencies

The script auto-downloads tools on first run. All are cached in tools\ or
installed as PowerShell modules -- no manual installation needed.

### ImportExcel PowerShell module (PSGallery)
  Used for generating color-coded .xlsx timeline with rows pre-colored by
  EventType. Auto-installed from PowerShell Gallery on first run.
  Source:     https://github.com/dfinke/ImportExcel
  License:    Apache 2.0
  Installed:  Per-user scope (CurrentUser) -- no system-wide changes
  Used by:    Excel timeline generation (color-coded .xlsx output)

### sqlite3.exe (sqlite.org)
  Used for parsing browser history databases (Chrome, Edge, Firefox).
  Downloaded from: https://www.sqlite.org/download.html
  Cached in: tools\sqlite3\sqlite3.exe
  Lookup order: sqlite3.exe on the PATH, then tools\, then a download of
  the x64 build (sqlite.org has no ARM64 tools build; x64 runs under
  emulation on ARM64 Windows).

### Timeline Explorer (Eric Zimmerman)
  Used for viewing and analyzing the timeline CSV output. Downloaded only
  if the user selects Timeline Explorer from the viewer menu.
  Downloaded from: https://ericzimmerman.github.io/
  Cached in: tools\TimelineExplorer\

  Credit: Timeline Explorer is developed by Eric Zimmerman and is part of his
  comprehensive suite of free forensic tools. His work has been foundational to
  the DFIR community, providing investigators with powerful, free, and actively
  maintained tools for Windows forensic analysis.

  Eric Zimmerman's tools: https://ericzimmerman.github.io/

All downloads happen once. On subsequent runs, cached copies are reused.
All temp files (download zips, extraction dirs) are cleaned up automatically.


## Output

The script creates a timestamped report folder next to the script:

  win11-timeline-builder\
    reports\
      timeline_2026-04-08_09-43-57\
        timeline_builder_log.txt     -- Full processing log
        timeline.csv                 -- The unified timeline (~12 MB, ~36K events)
        timeline.xlsx                -- Color-coded Excel version (~2 MB)
    tools\
      sqlite3\                       -- Auto-downloaded, cached
      TimelineExplorer\              -- Auto-downloaded on first use, cached


## Output Format (CSV and Excel)

Both timeline.csv and timeline.xlsx contain the same columns:

  Timestamp     UTC-normalized datetime (yyyy-MM-dd HH:mm:ss.fff)
  Source        Which artifact produced the entry (e.g., Security.evtx, Prefetch)
  EventType     Category: Execution, FileAccess, Logon, NetworkConnection,
                PersistenceChange, AccountChange, ProcessCreation, ServiceChange,
                ScheduledTaskChange, USBDevice, Installation, SecurityAlert,
                Snapshot (see below)
  Description   Human-readable summary of what happened
  User          Account the artifact belongs to, if known (see below)
  Details       Additional context (command line, file path, IP, etc.)
  Artifact      Parser that produced the entry
  RawPath       Path of the collected artifact file
  Flagged       (Only when -Keywords used) TRUE if any keyword matched

  Rows are sorted by Timestamp; rows with the same time stay in the order the
  parsers produced them.

### Where the times come from

  Every Timestamp is taken from the artifact data itself, never from when
  the files were copied, extracted or parsed:
  - Prefetch: run times stored inside the .pf file
  - LNK files: the original file times recorded in the collection manifest
    (collected file times are not used)
  - Registry entries (TypedPaths, RunMRU, RecentDocs, run keys, services,
    ...): the registry key's last-write time
  - BAM: bam_entries.csv, or the collected SYSTEM hive
  - Browser history: visit times, which the browsers store in UTC
  - USN journal and setupapi logs: these are local-time text. They are
    converted to UTC with the time zones the collector recorded in
    collection_info.json (the collector host's zone for fsutil USN output,
    the examined system's zone for setupapi). Collections from older
    collector versions have no collection_info.json; the time zone is then
    read from collection_log.txt.

### Snapshot rows

  Some artifacts describe the state of the system when it was collected, not
  an event: the service and driver list, DNS and ARP cache, current TCP
  connections, shares, Wi-Fi profiles, loaded DLLs, and scheduled tasks,
  services or run keys that have no usable time of their own. These rows
  have EventType "Snapshot" and the collection time as their Timestamp. They
  are colored light gray in Excel. Filter them out (EventType <> Snapshot)
  to see only real events.

### User column

  The user is taken from the collection's own folder layout: Registry\<user>\,
  UserActivity\<user>\, Browser\<user>\ or a Users\<user>\ folder inside the
  collection. It is never taken from the analysis machine's path (for
  example the %TEMP% folder a browse-mode zip is extracted to). Rows that do
  not belong to a specific profile have an empty User.

### Duplicates

  A row is removed as a duplicate only if Timestamp, Source, EventType,
  Description, User and Details are all identical (case-sensitive); the
  first copy is kept. The count is shown in the summary.

### CSV vs Excel differences

  The CSV file contains the complete data from all parsers. Use it when you
  need full-fidelity data for SIEM import, scripted analysis, or when any cell
  value exceeds 32,767 characters.

  Both files keep all text as found, including accented and non-Latin
  characters (e.g. Japanese file names), symbols such as the euro sign and
  emoji. Only characters that an .xlsx file cannot store are removed from
  both: control characters other than tab/CR/LF, U+FFFE/U+FFFF and broken
  (unpaired) UTF-16 surrogates. The CSV is UTF-8.

  The Excel file (.xlsx) is color-coded by EventType for visual analysis.
  Differences from the CSV:

  1. Strings over 32,767 characters are truncated with a [TRUNCATED] marker.
     This is Excel's hard cell limit. The full data is always in the CSV.
     Affected fields are typically long UserAssist entries or command lines.

  2. Excel may show a "Repaired Records" or "Do you want to recover" prompt
     when opening the file. Click Yes -- this is a known ImportExcel/EPPlus
     library issue with XML formatting. The data and color-coding are intact.
     This does not indicate data loss or corruption.

  3. An Excel worksheet holds at most 1,048,575 data rows. If the timeline is
     larger (usually because of a very large USN journal), the .xlsx is not
     generated and a warning is logged; use the CSV, or narrow the run with
     -StartDate, -EndDate, -Sources or -MaxUsnEntries.


## What Each Parser Extracts (15 Parsers)

### 1. Event Logs
Parses .evtx files using Get-WinEvent. Targets high-value forensic events:
  - Security: Logon success/fail (4624/4625), explicit credentials (4648),
    special privileges (4672), process creation (4688), account changes
    (4720/4726/4732)
  - System: Service crashes (7034), state changes (7036), start type changes
    (7040), new service installs (7045), shutdowns (1074/6008)
  - PowerShell Operational: Script block logging (4104), module logging (4103)
  - Sysmon (if present): Process creation (1), network (3), image loads (7),
    file creation (11), registry changes (13)
  - Task Scheduler: Task registered (106), updated (140), deleted (141)
  - TerminalServices (RDP) logs: remote logons, session connect, disconnect
    and reconnect, with user and source address
  - Windows Defender Operational: malware detections and actions, and
    security-control changes such as real-time protection disabled or an
    exclusion added (EventType SecurityAlert)
  - BITS Client: background transfer jobs and the URLs they download from

### 2. Prefetch
Extracts execution evidence from the .pf files:
  - Executable name, run count and the last run times stored inside the
    .pf file (up to 8 on Windows 8 and later)
  - The times of the copied .pf file are not used (they are only the time
    the collector copied it)

### 3. Recent Files (LNK)
Parses Windows shortcut files from the collection's RecentFiles folders:
  - Target file path, arguments, working directory
  - Times: the shortcut's original created/modified times from the
    collection manifest
  - User from the collection folder (UserActivity\<user>\RecentFiles)
  - Only the collection is read. If it has no .lnk files there are no LNK
    rows; the analysis machine's own Recent folder is never used.

### 4. Registry
Parses registry hives for user activity:
  - TypedPaths: Explorer address bar history
  - TypedURLs: Internet Explorer typed URLs
  - RunMRU: Run dialog command history
  - UserAssist: ROT13-decoded program execution counts and last run times
  - RecentDocs: Recently opened documents
  - BAM/DAM: Background/Desktop Activity Moderator last execution times,
    from bam_entries.csv (current collector) or the collected SYSTEM hive
  - AppCompatCache (ShimCache): programs recorded by the compatibility
    cache, from the collected SYSTEM hive / appcompat_cache.reg
  - ShellBags: folders the user browsed in Explorer, from UsrClass.dat
    (BagMRU), timed with each key's last-write time
  - Per-user Run / RunOnce values from each NTUSER.DAT
MRU-style entries (TypedPaths, RunMRU, RecentDocs) are timed with the
registry key's last-write time, which is when the most recent entry was
added -- older entries in the same key happened before that time.
Parses offline hives from the triage collection (NTUSER.DAT via reg load).

### 5. Browser History
Parses Chromium (Chrome, Edge, Brave, Opera, Opera GX, Vivaldi) and Firefox
SQLite databases using auto-downloaded sqlite3.exe -- no DLLs needed:
  - URL, page title, visit timestamp (stored by the browser in UTC and kept
    as UTC), visit count
  - User from the collection folder (Browser\<user>\)

### 6. Scheduled Tasks
Parses scheduled_tasks.csv from the triage collection (live collections):
  - Task name, path, state, author, run-as user, actions (the command) and
    triggers
  - Registration and last run times; tasks with no usable time are
    Snapshot rows
Mounted-image collections have no scheduled_tasks.csv; the task XML files
the collector copies from Windows\System32\Tasks are parsed instead
(registration date, author, command).

### 7. Services
Parses services.csv from triage collection:
  - Service name, binary path, start mode, state, service account
  - Timed with the service registry key's last-write time when the
    collector recorded it (KeyLastWriteUtc); otherwise a Snapshot row

### 8. File System
Parses file listing CSVs from triage collection. Capped at 50,000 entries.

### 9. USN Journal
Parses $UsnJrnl_$J.txt exported by the triage collector:
  - File create, modify, delete, rename, security change events
  - Filters out noisy "Close" and "Basic info change | Close" entries
  - Keeps every row by default; with -MaxUsnEntries N only the NEWEST N
    rows are kept, so the most recent activity before collection is always
    included
  - The export has local-time text; it is converted to UTC with the
    collector's recorded time zone (see "Where the times come from")
  - Typically the highest-volume source with fine-grained file activity

### 10. Network
Parses network artifacts from triage collection (Snapshot rows -- state at
collection time):
  - TCP connections (tcp_connections.csv) with process info
  - DNS cache entries (dns_cache.txt)
  - ARP cache (arp_cache.txt)
  - Network shares (network_shares.txt)
  - WiFi profiles (wifi_profiles.txt)

### 11. USB
Parses USB device history:
  - USB storage devices from usb_storage_devices.csv: first install,
    install, last arrival (connected) and last removal times per device
  - All SetupAPI device install logs (setupapi.dev.log and the rotated
    setupapi.dev.<date>.log files): first-install times, converted from the
    examined system's local time to UTC
  - USB devices and storage devices (usb_devices.txt, usb_storage_devices.txt)
  - Mounted devices (mounted_devices.txt)

### 12. Persistence
Parses persistence mechanisms from triage collection:
  - Run keys (run_keys.csv) - HKLM and every user's Run/RunOnce values,
    timed with the key's last-write time
  - Startup folders (startup_folders.csv) - all-users and per-user Startup
    folder items with their created/modified times
  - Startup entries (startup_entries.csv) - startup folder items
  - Drivers (drivers.csv) - kernel and filesystem drivers (key last-write
    time, otherwise Snapshot)
  - WMI subscriptions (wmi_subscriptions.csv) - event consumers
  - Suspicious loaded DLLs (loaded_dlls_suspicious.txt) - Snapshot
Older collections only have run_keys.txt / startup_folders.txt; their
entries have no times and appear as Snapshot rows.

### 13. Amcache
Parses Amcache.hve registry hive for program installation/execution history:
  - InventoryApplicationFile: executables with paths, publishers, SHA1
    hashes (EventType Execution)
  - InventoryApplication: installed applications with versions
    (EventType Installation)
  - Times are each entry's registry key last-write time (when Windows
    recorded or last updated the entry). The PE compile time (LinkDate) is
    shown in Details only -- it is often meaningless (e.g. year 2105).
  - The collector copies the hive's transaction logs (.LOG1/.LOG2) so the
    hive can be loaded. If the hive is still dirty/corrupt, Amcache parsing
    is skipped for that collection with a warning

### 14. PowerShell History
Parses command history:
  - ConsoleHost_history.txt: PSReadLine command history per user. The file
    stores no per-command times; all commands get the time of the history
    file's last write (when the last command was added)

### 15. Memory Dump (opt-in, requires Volatility 3)
Analyzes raw memory dumps captured by the triage collector using Volatility 3.
Opt-in only -- not included in default Sources. Add "Memory" to -Sources to enable.
Requires vol.exe in tools\volatility3\ (see Optional Tools section below).
  - windows.pslist: Running processes with creation timestamps, PIDs, parent PIDs
  - windows.netscan: Network connections with protocol, addresses, ports, state
  - windows.cmdline: Full command line arguments for each process
  - windows.svcscan: Windows services with binary paths, state, start type
Memory artifacts use the same EventTypes as disk artifacts (ProcessCreation,
NetworkConnection, Execution, ServiceChange) and are color-coded automatically.
The Source column distinguishes them (Memory-Processes, Memory-Network, etc.).


## Viewing the Timeline

After the timeline builds, the script presents a viewer menu:

  [1] Excel -- rows pre-colored by EventType, ready to analyze
      (Logon=Green, Execution=Orange, Persistence=Red, Network=Blue, etc.)
  [2] Timeline Explorer -- powerful forensic CSV viewer (no colors,
      requires manual conditional formatting setup per session)
  [3] Both -- open Excel (colored) and Timeline Explorer side by side
  [4] None -- just save the files, don't open anything

Both output files are always generated regardless of viewer choice:
  - timeline.csv   -- plain CSV for any tool (Timeline Explorer, SIEM, etc.)
  - timeline.xlsx  -- color-coded Excel with rows pre-formatted by EventType


### Option 1: Excel (recommended for most users)

The .xlsx file has every row pre-colored by EventType using the ImportExcel
PowerShell module. No manual formatting needed -- open it and start analyzing.

Note: Excel may show a repair prompt when opening -- click Yes. This is a
known ImportExcel library issue, not data corruption. See "CSV vs Excel
differences" above for details.

  Color scheme (applied automatically):

    Logon                   Green       -- authentication events
    Execution               Orange      -- program execution evidence
    ProcessCreation         Orange      -- new processes (Sysmon/4688)
    PersistenceChange       Red         -- autostart, services, tasks modified
    AccountChange           Red         -- user accounts created/modified
    NetworkConnection       Blue        -- network activity, browser, DNS
    FileAccess              Gray        -- file system activity
    ServiceChange           Yellow      -- service state changes
    ScheduledTaskChange     Yellow      -- task scheduler changes
    USBDevice               Purple      -- USB device connections
    Installation            Light Blue  -- application installs
    SecurityAlert           Bright red  -- AV detections, security tampering
                                           (Defender disabled, exclusion added);
                                           text in bold
    Snapshot                Light gray  -- state at collection time, not an
                                           event (see "Snapshot rows")

  The Excel file includes AutoFilter on all columns and a frozen header row.
  Use column filters to narrow by EventType, Source, User, or date range.
  If you used -Keywords, filter the Flagged column to TRUE for quick hits.


### Option 2: Timeline Explorer (Eric Zimmerman)

A powerful forensic CSV viewer designed for timeline analysis. Downloaded
automatically on first selection and cached for future use.

  Tips for analysis:
  - Use column filters to narrow by EventType, Source, User, or date range
  - If you used -Keywords, filter the Flagged column to TRUE for quick hits
  - Right-click column headers to sort, group, or hide columns
  - Ctrl+F to search across all columns
  - File -> Save Session to preserve your filters, colors, and layout

  Manual color-coding (one-time per session):
    1. Right-click any cell in the EventType column
    2. Conditional Formatting -> Highlight Cell Rules -> Text That Contains
    3. Enter an event type (e.g., "Logon"), pick a color
    4. CHECK "Apply formatting to an entire row"
    5. Repeat for each event type. File -> Save Session to keep your setup.

  Note: Timeline Explorer does not support loading color profiles. Colors
  must be set up manually per session, then saved. This is why the Excel
  option exists -- it applies the same color scheme automatically.


### Option 3: Both

Opens Excel (colored) and Timeline Explorer side by side. Useful when you
want the visual color-coding in Excel and the forensic filtering power of
Timeline Explorer at the same time.


### Other options for reading the output:

  PowerShell:
    $timeline = Import-Csv ".\reports\timeline_<timestamp>\timeline.csv"
    $timeline | Where-Object { $_.EventType -eq "Logon" }
    $timeline | Where-Object { $_.EventType -eq "SecurityAlert" }
    $timeline | Where-Object { $_.EventType -ne "Snapshot" }
    $timeline | Where-Object { $_.User -match "admin" }
    $timeline | Where-Object { $_.Flagged -eq "TRUE" }


## Investigation Workflow

  1. COLLECT artifacts with triage-collector on the target system
     Companion: https://github.com/Jumbalicious79/win11-triage-collector

  2. BUILD the timeline
     Double-click Run-TimelineBuilder.bat, pick a collection
     Or: Run-TimelineBuilder.bat "path\to\collection" "mimikatz,psexec"

  3. REVIEW summary in the console output
     Total events, date range, per-source breakdown, keyword-flagged count

  4. CHOOSE a viewer when prompted
     Excel: pre-colored rows, ready to analyze immediately
     Timeline Explorer: powerful forensic CSV viewer (manual color setup)
     Both: side by side for maximum flexibility

  5. TRIAGE in your chosen viewer
     Filter EventType to SecurityAlert for AV detections and tampering
     Filter Flagged column to TRUE for keyword hits
     Sort by Timestamp for chronological review
     Group by EventType for category analysis (hide Snapshot rows to see
     only real events)

  6. INVESTIGATE
     Pivot on timestamps: what else happened +/- 5 minutes?
     Pivot on users: what else did this account do?
     Pivot on processes: where else does this executable appear?
     Check Browser entries for downloads preceding suspicious execution

  7. REFINE if needed
     Re-run with -StartDate/-EndDate to zoom into a timeframe
     Re-run with additional -Keywords based on findings
     Re-run with -Sources to focus on specific artifact types


## Known Limitations and Expected Warnings

  - "No file system data found" -- The triage collector does not produce a
    file_listing.csv. File system data comes from the USN Journal parser
    instead. This warning is normal.

  - USN journal size -- All USN rows are kept by default. On a very busy
    system the timeline can exceed Excel's row limit (see above); use
    -MaxUsnEntries N to keep only the newest N rows. The log says how many
    older rows were dropped.

  - "Could not load Amcache hive: ..." -- Usually a dirty hive: it needs its
    transaction logs (Amcache.hve.LOG1/.LOG2). Older versions of the triage
    collector dropped these hidden files by mistake, so collections made
    with them often hit this warning and Amcache parsing is skipped.
    Re-collect with the current collector to get the logs.

  - "No service data found" -- Appears for mounted-image collections, which
    have no services.csv (it needs live queries). Scheduled tasks of mounted
    images are parsed from the collected task XML files instead.

  - Collections from older collector versions -- Still supported, with less
    precise times: no collection_info.json (the time zone and collection
    time are read from collection_log.txt), no original file times in the
    manifest, no bam_entries.csv / run_keys.csv / startup_folders.csv /
    usb_storage_devices.csv (BAM is read from the SYSTEM hive; run keys and
    startup items become Snapshot rows), and only setupapi.dev.log is
    collected (it may be missing if Windows rotated it).

  - Snapshot rows -- Services, drivers, network state, DLLs and items with
    no recorded time are shown at the collection time with EventType
    Snapshot. Their Timestamp is when the state was observed, not when it
    was created.

  - Local-time sources -- USN and setupapi times are local-time text. Times
    inside the hour that repeats when daylight saving time ends cannot be
    told apart and may be off by one hour.

  - Excel row limit -- Timelines over 1,048,575 rows are written to CSV only.

  - Excel "Repaired Records" or recovery prompt -- Known ImportExcel/EPPlus
    library issue. Click Yes to proceed. Data and color-coding are intact.
    The CSV file contains the complete unmodified data. See "CSV vs Excel
    differences" above.

  - "windows.netscan: 0 entries" -- Volatility 3's netscan plugin may return
    no results on Windows 11 Build 26200+ due to kernel structure changes.
    This is a Volatility compatibility issue, not a script bug.


## Limitations vs. Full Tools (plaso/log2timeline)

  Feature          | timeline-builder.ps1           | log2timeline/plaso
  -----------------+--------------------------------+----------------------------
  Setup            | Zero dependencies (pure PS)    | Requires Python + plaso
  Speed            | Fast (1-2 minutes)             | Slow (hours for full parse)
  Event logs       | Targeted high-value event IDs  | All event IDs
  Prefetch         | Name, run count, run times     | Full binary parsing
  Registry         | Key artifacts (MRU, BAM, etc.) | Hundreds of plugins
  Browser          | URL history (auto sqlite3)     | Full history + cache
  USN Journal      | Parsed from text export        | Full $UsnJrnl binary parse
  $MFT             | Not supported                  | Full $MFT parsing
  Shellbags        | Folder names + key times       | Full shellbag parsing
  Output formats   | CSV + color-coded XLSX         | CSV, JSON, XLSX, and more
  Parsers          | 15 parsers (14 + memory opt-in) | 100+ parsers

  When to use this: Quick triage, initial timeline, no-install environments,
  USB kit deployment, when you need results in minutes not hours.

  When to use plaso: Full forensic investigation, court-ready analysis, when
  you need exhaustive artifact coverage or $MFT timeline data.


## Requirements

  - Windows 10 or Windows 11
  - PowerShell 5.1 or later
  - Administrator privileges (the .bat launcher handles elevation)
  - Internet connection on first run (to install ImportExcel module and
    auto-download sqlite3.exe; Timeline Explorer downloaded on first use
    if selected). After first run, cached copies are used offline.


## Third-Party Dependencies (Auto-Downloaded)

The script auto-downloads dependencies on first run. Binaries are cached in
tools\ and reused. The PowerShell module is installed per-user. No manual
installation or configuration is needed.

### ImportExcel PowerShell module
  Purpose:    Generates the color-coded .xlsx timeline file. Uses the EPPlus
              library to create Excel files with formatting -- no Excel
              installation required on the machine.
  Author:     Doug Finke
  Source:     https://github.com/dfinke/ImportExcel
  License:    Apache 2.0
  Install:    Auto-installed from PSGallery (Install-Module -Scope CurrentUser)
  Size:       ~5 MB
  Used by:    Excel timeline generation (color-coded .xlsx output)
  Known issue: Excel may show a "Repaired Records" or recovery prompt when
              opening the generated .xlsx file. This is a known EPPlus library
              issue with XML formatting -- not data corruption. Click Yes to
              proceed. All data and color-coding are intact. The CSV file
              contains the complete unmodified data as a fallback.

### sqlite3.exe
  Purpose:    Parses browser history databases (Chrome, Edge, Firefox).
              The browser History files are SQLite databases that cannot be
              read with pure PowerShell. sqlite3.exe provides a zero-dependency
              command-line interface to query them.
  Source:     https://www.sqlite.org/download.html
  License:    Public domain (https://www.sqlite.org/copyright.html)
  Cached at:  tools\sqlite3\sqlite3.exe
  Size:       ~6 MB (zip), ~2 MB (exe)
  Used by:    Parser #5 (Browser History)

### Timeline Explorer
  Purpose:    Forensic CSV viewer with filtering, sorting, grouping, and
              conditional formatting. Downloaded only if the user selects
              Timeline Explorer from the viewer menu.
  Author:     Eric Zimmerman
  Source:     https://ericzimmerman.github.io/
  Download:   https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip
  License:    Free for use (see Eric Zimmerman's tools page)
  Cached at:  tools\TimelineExplorer\
  Size:       ~86 MB (zip)
  Used by:    Auto-launched after timeline export
  Requires:   .NET 9 Runtime (Timeline Explorer will prompt to install if missing)

Both zips are downloaded to %TEMP%, extracted, and the zip is deleted. If
download fails (no internet, firewall), the script continues -- browser
parsing is skipped, and the timeline CSV can be opened manually.


## Optional Tools (User-Provided)

### Volatility 3 (Memory Analysis)
  Purpose:    Analyzes raw memory dumps to extract running processes, network
              connections, command lines, and services from RAM.
  Author:     Volatility Foundation
  Source:     https://github.com/volatilityfoundation/volatility3/releases
  License:    Volatility Software License (open source)
  Place at:   tools\volatility3\vol.exe
  Used by:    Parser #15 (Memory Dump) -- opt-in only

  Setup:
    1. Download the latest standalone Windows release from:
       https://github.com/volatilityfoundation/volatility3/releases
    2. Extract vol.exe (the standalone executable)
    3. Place it in: win11-timeline-builder\tools\volatility3\vol.exe

  The Memory parser is opt-in. Add "Memory" to -Sources to enable it.
  If vol.exe is not found, the parser logs download instructions and skips.

  Plugins run (4 core plugins):
    windows.pslist   -- running processes with creation timestamps
    windows.netscan  -- network connections with addresses, ports, state
    windows.cmdline  -- full command line arguments per process
    windows.svcscan  -- Windows services with binary paths and state

  Processing time: 5-30 minutes depending on dump size (16-64 GB typical).
  Memory artifacts are interleaved with disk artifacts in the timeline and
  color-coded by EventType like all other entries.


## Windows Built-In Tools Used

  reg.exe              Loads offline registry hives (NTUSER.DAT, SYSTEM,
                       Amcache.hve) via "reg load" for parsing UserAssist,
                       TypedPaths, RunMRU, RecentDocs, BAM, ShimCache and
                       Amcache entries, including key last-write times.
                       Unloads after.

  Get-WinEvent         Parses .evtx event log files with XPath filtering.
                       Used for targeted extraction of high-value Security,
                       System, PowerShell, Sysmon, Task Scheduler,
                       TerminalServices (RDP), Windows Defender and BITS
                       events.

  WScript.Shell COM    Reads LNK shortcut files to extract target paths,
                       arguments, and working directories for Recent Files.

  PowerShell cmdlets   Import-Csv, Export-Csv, Expand-Archive,
                       Invoke-WebRequest, ConvertFrom-Json.


## Credits and Acknowledgments

  Buzz Hillestad,      Design, testing, forensic workflow, and investigation
  GCFE                 methodology. Defined the parser selection, triage
                       workflow, USB deployment model, auto-download strategy,
                       and integration with the win11-triage-collector
                       companion project.

  Claude Code          Code generation and implementation. All PowerShell
  (Anthropic)          scripts, batch launchers, and supporting code were
                       written by Claude Code (claude.ai/code).

  Eric Zimmerman       Timeline Explorer is developed by Eric Zimmerman and
                       is part of his comprehensive suite of free forensic
                       tools. His work has been foundational to the DFIR
                       community, providing investigators with powerful, free,
                       and actively maintained tools for Windows forensic
                       analysis. This script auto-downloads and launches
                       Timeline Explorer for viewing results.
                       https://ericzimmerman.github.io/

  ImportExcel          The ImportExcel PowerShell module by Doug Finke
  (Doug Finke)         generates the color-coded .xlsx timeline using the
                       EPPlus library. No Excel installation required.
                       https://github.com/dfinke/ImportExcel

  SQLite Consortium    sqlite3.exe is developed by the SQLite Consortium and
                       released into the public domain. Used in this script
                       to parse Chromium and Firefox browser history databases.
                       https://www.sqlite.org/

  KAPE (Kroll)         The artifact parsing approach and triage-collector
                       integration are inspired by KAPE's Targets and Modules
                       workflow.
                       https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

  Volatility           Volatility 3 is developed by the Volatility Foundation
  Foundation           and is the gold standard for memory forensics. Optionally
                       used by the Memory parser to analyze RAM dumps.
                       https://github.com/volatilityfoundation/volatility3

  log2timeline/plaso   The timeline-building concept and CSV output format are
                       inspired by the plaso/log2timeline project, the gold
                       standard for forensic super-timelines.
                       https://github.com/log2timeline/plaso

  DFIR community       Artifact parsing logic, forensic value prioritization,
                       and event ID selection are informed by the broader DFIR
                       community's research, SANS forensic posters, and the
                       Forensic Artifact Reference.


## What It Modifies

This script is read-only with respect to the target system's artifacts. It only
creates files in its own reports\ directory and temp folders (cleaned up after).
No system files, registry keys, or artifacts are modified.

One-time actions (first run only):
  - Installs ImportExcel PowerShell module (CurrentUser scope)

Temporary actions (all cleaned up automatically):
  - Extracts triage zip to %TEMP% (browse mode) -- deleted after processing
  - Copies Amcache.hve to %TEMP% for reg load -- deleted after processing
  - Copies browser DBs to %TEMP% for sqlite3 -- deleted after processing
  - Downloads zip files to %TEMP% (first run) -- deleted after extraction
