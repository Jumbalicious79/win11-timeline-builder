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
      tools\
        dumpit\                   <-- optional: DumpIt for memory capture
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
analysis, extract Magnet DumpIt into the collector's tools\dumpit\ and
Volatility 3 into the builder's tools\volatility3\. Both folders are in the
repos with a README.txt explaining where to get the tool; the tools
themselves are never committed.


## Quick Start

### Double-click (recommended)

  Run-TimelineBuilder.bat

  No arguments needed. The script automatically:
    1. Finds triage collection .zip files from sibling triage-collector\reports\
    2. Lists them with size and date, newest first
    3. You pick a number
    4. Extracts it into a work folder in %LOCALAPPDATA%\TimelineBuilder,
       not %TEMP% (deleted after; see "Work folder" below)
    5. Builds the timeline (~2 minutes for ~36,000 events)
    6. Generates a color-coded Excel file (rows colored by EventType)
    7. Asks how you want to view: Excel (colored), Timeline Explorer, Both, None

  You can also pass a collection folder or a collection .zip directly (or
  drop either on the .bat), optionally followed by a comma-separated
  keyword list (both in quotes):

  Run-TimelineBuilder.bat "path\to\triage\collection"
  Run-TimelineBuilder.bat "path\to\TriageCollection_2026-04-08_09-30.zip"
  Run-TimelineBuilder.bat "path\to\collection" "mimikatz,psexec"

  The launcher asks for Administrator rights (UAC) and restarts itself
  elevated with the same arguments. Paths with spaces, apostrophes, & or !
  are fine, and a relative path is turned into a full path first (the
  elevated window starts in C:\Windows\System32).

### PowerShell (Admin)

  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -Browse
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\Collection"
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\TriageCollection_2025-01-20_14-05.zip" -WorkDir "D:\Work"
  powershell -ExecutionPolicy Bypass -NoProfile -File timeline-builder.ps1 -InputPath "D:\Cases\Case001\TriageCollection_2025-01-20_14-05.zip" -MemoryDumpPath "E:\Dumps\TriageCollection_2025-01-20_14-05_memory_dump.dmp"
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
  -InputPath      Path to a triage collection directory, a collection .zip
                  (extracted into the work folder, as in browse mode; a
                  memory dump next to it is found too), or any directory
                  containing supported artifacts.
  -OutputFile     Output CSV path. Defaults to reports\timeline_<timestamp>\timeline.csv
  -StartDate      Only include events after this date (UTC).
  -EndDate        Only include events before this date (UTC).
  -Sources        Parsers to run, as an array or a comma-separated string.
                  Defaults to all 18 (Memory excluded).
                  Valid: EventLogs, Prefetch, RecentFiles, Registry, FileSystem,
                  Browser, ScheduledTasks, Services, Network, USB, Persistence,
                  UsnJournal, Amcache, PowerShellHistory, SystemInfo,
                  AntiVirus, Email, SRUM, Memory
                  Note: Memory is opt-in. Requires Volatility 3 in tools\ and
                  a memory dump in or next to the collection, or
                  -MemoryDumpPath (see parser #15). Adds 5-30 minutes.
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
  -Viewer         Viewer to open at the end without the menu: Excel,
                  TimelineExplorer, Both or None (for scripts and automation).
  -NoExcel        CSV only: don't generate timeline.xlsx (ImportExcel is then
                  not needed).
  -MftDays        $MFT file-system events: only times within this many days
                  before the collection are added. Default 7; 0 = all. A
                  full $MFT can produce millions of rows, and one Windows
                  update alone can add hundreds of thousands. Possible
                  timestomping and Mark-of-the-Web (downloaded or
                  extracted file) rows are always reported (see parser #8).
  -WorkDir        Folder in which this run's work folder is made (the
                  extracted zip and scratch copies; see "Work folder").
                  Default %LOCALAPPDATA%\TimelineBuilder. Use a folder on
                  another local drive when the system drive is low on
                  space, and never a temp folder. A network share or mapped
                  network drive is refused (reg load cannot load hives
                  from there).
  -MemoryDumpPath The collection's memory dump file (a DumpIt .dmp or a
                  .raw image) when it is not next to the collection zip or
                  folder, e.g. a dump the triage collector saved on another
                  drive with -MemoryOutputPath
                  (<MemoryOutputPath>\<collection>_memory_dump.dmp). It is
                  used before the places listed under parser #15; if it is
                  not an existing file, a warning is logged and those
                  places are searched instead. It does not turn on the
                  Memory parser: add Memory to -Sources, or choose [1] when
                  the builder offers the dump. Run-TimelineBuilder.bat does
                  not pass it; start the script from PowerShell.


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
Download zips are deleted from %TEMP% after extraction; the work folder
(extracted collection, scratch copies) is deleted at the end of every run.


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

### Work folder

  A collection zip is extracted, and hives, browser databases and SRUM
  databases are copied for reading, into a work folder that exists only
  while the builder runs:

    %LOCALAPPDATA%\TimelineBuilder\w<PID>_<HHmmss>\
      .lock                          -- held open for the whole run
      in\                            -- the extracted collection zip
      scratch\                       -- copies for reg load, sqlite3 and
                                        the SRUM reader

  It is deleted at the end of every run, also after an error or Ctrl+C. A
  folder left by a run that was killed (window closed, crash) is deleted by
  the next run, once no builder holds its .lock. -WorkDir makes the work
  folder in another folder; if %LOCALAPPDATA% cannot be written, work\ next
  to the script is used. The log names the work folder. It must be on a
  local drive: reg load only loads a hive from a local file, so a network
  share (\\server\share) or a mapped network drive is not used, and with
  such a -WorkDir the run stops at the start.

  Why not %TEMP%: Windows Storage Sense deletes files older than 7 days from
  temp folders when disk space runs low, and extracted files keep the dates
  stored in the zip, which are often months old. This once deleted setupapi
  logs and browser databases while a timeline was being built. The builder
  warns when the work folder, or a folder passed as -InputPath, is inside a
  temp folder.

  Before extracting, the free space on the work folder's drive is checked:
  the builder stops below the zip's uncompressed size plus 256 MB, and warns
  below the size plus 1 GB, or when the system drive would be left with
  less than 10% free.

### Incomplete timeline (exit code 2)

  Missing input files. Every input file is recorded when the run starts:
  each file extracted from the zip, or, for a collection folder, each file
  listed in collection_manifest.csv that is present (memory dumps
  excepted). Files that disappear right after the extraction (e.g.
  antivirus) stop the run. After the parsers have run, all of them must
  still be there; files that disappeared are listed by collection folder
  (USB\, Browser\, ...; the console shows 20 names per folder, the log file
  all of them), and the run ends with

    === Timeline Builder Completed WITH N MISSING INPUT FILE(S) -- timeline incomplete ===

  The timeline is still written, but rows from those files may be missing.
  The check runs once, after all parsers, so a file deleted after its
  parser read it is listed too, although its rows are in the timeline.

  Unexpected errors. An error the builder does not handle itself (a bug,
  or input it does not expect) is logged as "Unexpected error at line N
  (rest of this step skipped)", and the rest of that step -- usually the
  rest of one parser -- is skipped. The run goes on with the next step and
  ends with

    === Timeline Builder Completed WITH N UNEXPECTED ERROR(S) -- timeline may be incomplete ===

  In both cases the exit code is 2 instead of 0. Exit code 1 means the run
  stopped early (input not found, a bad zip, no work folder, files gone
  right after the extraction).


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
    ...): the registry key's last-write time. Values that store a time of
    their own use it (TaskCache, Office TrustRecords and File/Place MRU)
  - BAM: bam_entries.csv, or the collected SYSTEM hive
  - Browser history, downloads, logins, cookies, form entries and
    permissions: times the browsers store in UTC
  - USN journal and setupapi logs: these are local-time text. They are
    converted to UTC with the time zones the collector recorded in
    collection_info.json (the collector host's zone for fsutil USN output,
    the examined system's zone for setupapi). Collections from older
    collector versions have no collection_info.json; the time zone is then
    read from collection_log.txt.
  - Email attachments, OST/PST files and Thunderbird mail folders: the
    original file times the collector recorded (manifest and listing CSVs);
    Thunderbird messages: the Date header (the sender's clock)
  - SRUM: the last hourly SRUM record of each UTC day
  - Defender DetectionHistory and quarantine entries: the times stored in
    the files

### Snapshot rows

  Some artifacts describe the state of the system when it was collected, not
  an event: the service and driver list, DNS and ARP cache, current TCP
  connections, shares, Wi-Fi profiles, loaded DLLs, browser settings, email
  accounts, the drive letters and volumes in MountedDevices, and scheduled
  tasks, services, run keys or browser extensions that have no usable time
  of their own. These rows have EventType "Snapshot" and the collection
  time as their Timestamp. A few context rows are Snapshot rows at a time
  of their own: a security product reported ON to Security Center (event
  time), the Outlook attachment folder and the triage collector's own
  Defender exclusion (registry key last-write time). Snapshot rows are
  colored light gray in Excel. Filter them out (EventType <> Snapshot) to
  see only real events.

### User column

  The user is taken from the collection's own folder layout: Registry\<user>\,
  UserActivity\<user>\, Browser\<user>\, Email\<user>\ or a Users\<user>\
  folder inside the collection. It is never taken from the analysis
  machine's path (for example the work folder a zip is extracted to). Rows
  that do not belong to a specific profile have an empty User.

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


## What Each Parser Extracts (19 Parsers)

### 1. Event Logs
Parses .evtx files using Get-WinEvent. Targets high-value forensic events
(the Source is the log file name, e.g. Security.evtx):
  - Security: Logon success/fail (4624/4625), explicit credentials (4648),
    special privileges (4672), process creation (4688), account created or
    deleted (4720/4726, with the account SID), session reconnected or
    disconnected (4778/4779, EventType Logon, with the client name and
    address)
  - Security account changes (EventType AccountChange): member added to a
    security-enabled global, local or universal group (4728/4732/4756;
    Details Group, GroupSID, Member, MemberSID -- a local member, which the
    event gives only by SID, is named from the other Security events),
    password reset attempt (4724), account locked out (4740, with the
    CallerComputer)
  - Security log and persistence changes: audit log cleared (1102, with
    ClearedBy) and system audit policy changed (4719, category and
    subcategory by name), both SecurityAlert; service installed (4697,
    PersistenceChange); scheduled task registered, updated, deleted,
    enabled or disabled (4698/4702/4699/4700/4701, ScheduledTaskChange,
    with Command, Arguments and RunAs from the task XML)
  - Security 4624 Details: LogonType, Source (address:port), LogonID,
    IpAddress, WorkstationName, AuthenticationPackageName, LmPackageName
    and KeyLength; LmPackageName "NTLM V1" is an NTLMv1 logon
  - System: Service crashes (7034), state changes (7036), start type changes
    (7040, with the service name), new service installs (7045), shutdowns
    (1074/6008), event log cleared (104, SecurityAlert, with the log name
    and who cleared it), event log service started/stopped (6005/6006: the
    markers of a boot and of a clean shutdown)
  - Application: software installed or removed (MsiInstaller 1033/1034,
    EventType Installation, with Product, Version, Manufacturer, Status and
    the installing account as User; 11707/11724 only when there is no
    matching 1033/1034), application crashes and hangs (Application Error
    1000, Application Hang 1002, EventType Execution, with the faulting
    Module and ExceptionCode), ESE database created, attached, detached or
    moved (ESENT 325/326/327/216, FileAccess -- shows copies of ntds.dit).
    Only these events and the security-product events below are read from
    this log; Windows Error Reporting 1001 is not (it repeats 1000/1002)
  - Application, security products: the state each product reports to
    Security Center (SecurityCenter 15: the first state per product and
    every change; 16: a failed state update). A product reported OFF,
    SNOOZED, EXPIRED or in an unknown state is a SecurityAlert; one
    reported ON is a Snapshot row at the event time (context). Events that
    third-party antivirus writes to this log (Symantec / Norton, McAfee /
    Trellix, Sophos, ESET, Trend Micro, Bitdefender, Kaspersky,
    Malwarebytes, Webroot, CrowdStrike) are SecurityAlert rows with the
    message text, trimmed: Critical, Error and Warning events, and
    Information events only when their text reports a detection
  - PowerShell Operational: Script block logging (4104), module logging (4103)
  - Sysmon (if present): Process creation (1), network (3), image loads (7),
    file creation (11), registry changes (13)
  - Task Scheduler: Task registered (106), updated (140), deleted (141)
  - TerminalServices (RDP) logs: remote logons, session connect, disconnect
    and reconnect, with user and source address
  - Windows Defender Operational: malware detections and actions,
    security-control changes such as real-time protection disabled or an
    exclusion added, malware detection history deleted (1013; the service's
    own daily retention purge is labelled as such), and attack surface
    reduction rules that blocked or audited an action (1121/1122, with the
    rule name; audits are folded into one row per rule, path, process and
    day, with Count and LastSeen) (EventType SecurityAlert)
  - BITS Client: background transfer jobs and the URLs they download from
  - Defender detections (defender_detections.csv) with the threat name and
    severity from defender_threats.csv
  - Defender support logs (MPLog-*.log): detections and remediations,
    exclusion lists and exclusion/protection-setting changes
    (EventType SecurityAlert; MPLog times are UTC)
  - Defender DetectionHistory files and quarantine entries are read by the
    Antivirus parser (#17), not here
  - Windows PowerShell (classic log, EventType Execution): engine started
    (400) with HostApplication (the command line that started PowerShell,
    kept whole, cut to 1000 characters), EngineVersion, HostId and
    RunspaceId, and for -EncodedCommand (-enc, -e, ...) the decoded script
    in EncodedCommand; a 2.0 engine reads "PowerShell 2.0 engine started
    (possible downgrade)". Engine stopped (403) is folded into its 400 as
    Stopped. Pipeline details (800): one row per session, "PowerShell
    pipeline executed: <first command line>", with CommandLines, Commands,
    Count and LastSeen (a 2.0 engine: one row per pipeline). Without module
    logging Windows writes 800 only for Add-Type, and these often outlive
    the PowerShell/Operational log
  - WMI-Activity: permanent event subscriptions (5861, PersistenceChange,
    "WMI permanent event subscription: filter "<name>" -> <consumer>") with
    the filter's query, the consumer and what it runs (CommandLineTemplate,
    ExecutablePath, ScriptText, ...), FilterCreatorSID and
    ConsumerCreatorSID (User: the consumer's creator); temporary
    subscriptions (5860, Execution) with the query, user and process. 5861
    is written again at every WMI service start, so repeats are folded into
    the first row (Count, LastSeen); Windows' own "SCM Event Log"
    subscription is marked "(Windows default)"; 5857-5859 are only counted
  - TerminalServices-RDPClient (NetworkConnection): outbound RDP
    connections from this machine, "Outbound RDP connection to <server>:
    ..." -- connecting and connected (1024/1025), multi-transport (1102),
    domain and session (1027), user name hash (1029), credentials not
    accepted (1009) and disconnected with the reason (1026, e.g. 2055 login
    failed). The server is found through the connection's ActivityID
  - NTLM Operational (only when NTLM auditing is on): outgoing NTLM
    authentication (8001, 4020/4021; NetworkConnection), incoming (8002,
    8003, 4022/4023; Logon), authentication passed to or processed by a
    domain controller (8004-8006, 4030-4033; Logon), a failed NTLMv1
    attempt (4013) and use of NTLMv1-derived credentials (4024). The 40xx
    events (Windows 11 24H2 / Server 2025) give NtlmVersion; NTLMv1 rows
    say "(NTLMv1" in the Description
  - Windows Firewall: rule added, modified or deleted (2004-2006 on older
    Windows 10; 2071/2097, 2073/2099 and 2052 later; PersistenceChange,
    with RuleName, ApplicationPath, Direction, Action, Protocol, ports,
    RemoteAddresses, Profiles, Origin, ModifyingApplication and
    ModifyingUser); all rules deleted (2033/2059), reset to defaults
    (2032/2060) and profile or global setting changes (2003/2082,
    2002/2083, e.g. "Enable firewall = No") are SecurityAlert. A change
    that failed reads "... failed (error N)". Only counted: changes to a
    rule that does not exist (ErrorCode 2), the Store app rules of the
    firewall service (NT SERVICE\mpssvc) and app-package (MSIX) rules that
    svchost.exe adds and removes as SYSTEM
  - Shell-Core (Execution): commands Explorer starts at logon (9707 with
    its 9708, placed by the 9705/9706 key and 62170/62171 task markers):
    "Run key command started at logon", "RunOnce key command started at
    logon", "Active Setup command started at logon" or "Command started at
    logon (key unknown)", with Command, ProcessId, RegistryKey and Finished.
    Windows logs neither the hive (HKLM or HKCU) nor the folder of the
    command, only the part after its last backslash
  - OAlerts (Execution): alerts shown by Office applications (300, "Office
    alert (<application>): <text>", with the document) and Office add-in
    events ("Office add-in event (<what>): <add-in>")
  - Antivirus products' own event logs collected under AntiVirus\
    (Symantec_SEP_EventLog.evtx, CrowdStrike_EventLog.evtx): every event
    goes through the same filter and wording as the antivirus events of the
    Application log (SecurityAlert, Artifact AntiVirus; read with -Sources
    EventLogs)

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
  - Jump Lists: AutomaticDestinations (DestList entries: path, last access
    time, access count, pinned) and CustomDestinations (target paths), per
    application -- the app name comes from the AppID (well-known IDs) or the
    program the list starts


### 4. Registry
Parses the offline hives of the triage collection (NTUSER.DAT, UsrClass.dat,
SOFTWARE and SYSTEM via reg load) for user activity, persistence and
security settings. Sources are named Registry-<item> (e.g. Registry-RunMRU,
Registry-TaskCache); Details give the Key and say where the time came from.
From each user's NTUSER.DAT:
  - TypedPaths: Explorer address bar history
  - TypedURLs: Internet Explorer typed URLs
  - RunMRU: Run dialog command history
  - UserAssist: ROT13-decoded program execution counts and last run times
  - RecentDocs: Recently opened documents
  - Per-user Run / RunOnce values
  - WordWheelQuery: Explorer search box terms
  - Open/Save dialogs (Registry-OpenSaveMRU, Registry-LastVisitedMRU):
    files picked in Open/Save dialogs and the folder each program's dialog
    last used; paths are decoded like ShellBags
  - Office trusted documents (Registry-TrustRecords): "Office macros
    enabled on document" (EventType Execution) when the user enabled
    macros, otherwise "Office editing enabled on document" (FileAccess),
    at the time the document was trusted
  - Office File MRU / Place MRU (Registry-OfficeMRU): recent documents and
    folders per Office app, at the time each was last opened
  - Outlook attachment temp folder (OutlookSecureTempFolder): one Snapshot
    row with the folder
  - Remote Desktop client (Registry-RDPClient, EventType
    NetworkConnection): outbound RDP targets from the MRU list and the
    saved servers with their user name hint
From UsrClass.dat:
  - ShellBags: folders the user browsed in Explorer (BagMRU), timed with
    each key's last-write time
From the SOFTWARE hive (EventType PersistenceChange unless noted):
  - Image File Execution Options Debugger values (Registry-IFEO). A
    Debugger on an accessibility program (sethc.exe, utilman.exe, osk.exe,
    narrator.exe, magnify.exe, displayswitch.exe, atbroker.exe) is marked
    "(accessibility program)": the Debugger then runs at the logon screen
    as SYSTEM
  - SilentProcessExit monitor processes and dumps on exit, described by
    what ReportingMode makes Windows do; Details say whether it is Active
    (that also needs IFEO GlobalFlag 0x200)
  - Winlogon Shell, Userinit and Taskman when not the Windows default
  - AppInit_DLLs when not empty (native and Wow6432Node), with
    LoadAppInit_DLLs
  - Scheduled tasks from the TaskCache (Registry-TaskCache): hidden tasks
    and task folders -- a Tree entry without an SD value, which schtasks
    and Task Scheduler do not list (ScheduledTaskChange); and, from
    DynamicInfo, "Scheduled task registered" (ScheduledTaskChange) and
    "Scheduled task last run" (Execution, with LastErrorCode) with the
    task's Actions, for tasks that scheduled_tasks.csv or the task XML
    files do not already put on the timeline
  - Defender exclusions (Registry-DefenderExclusions; Paths, Extensions,
    Processes, IpAddresses; local and Group Policy): one SecurityAlert row
    each; local ones are "ignored by policy" when Group Policy sets
    DisableLocalAdminMerge. The exclusion the triage collector adds for its
    own output folder while it runs is recognised from collection_log.txt
    and shown as a Snapshot row "(triage collector's own temporary
    exclusion)", or as a SecurityAlert when the log says the collector
    could not remove it
From the SYSTEM hive:
  - LSA Authentication, Notification (password filter) and Security
    Packages entries that are not Windows defaults (Registry-LSA,
    PersistenceChange)
  - WDigest UseLogonCredential=1: clear-text passwords kept in memory
    (Registry-WDigest, SecurityAlert)
  - BAM/DAM: Background/Desktop Activity Moderator last execution times,
    from bam_entries.csv (current collector) or the collected SYSTEM hive
  - AppCompatCache (ShimCache): programs recorded by the compatibility
    cache, from the collected SYSTEM hive / appcompat_cache.reg
MRU-style entries (TypedPaths, RunMRU, RecentDocs, Open/Save dialogs,
WordWheelQuery, Remote Desktop MRU) are timed with the registry key's
last-write time, which is when the most recent entry was added -- older
entries in the same key happened before that time. TrustRecords, Office
MRU and TaskCache DynamicInfo store their own times, which are used. The
settings (IFEO, Winlogon, AppInit_DLLs, Defender exclusions, LSA, WDigest,
hidden tasks) use their key's last-write time: when the key last changed,
so the value itself may be older.

### 5. Browser History
Parses Chromium (Chrome, Edge, Brave, Opera, Opera GX, Vivaldi) and Firefox
SQLite databases using auto-downloaded sqlite3.exe -- no DLLs needed. Each
database is read from a temporary copy with its -wal and -journal files, so
a copy taken while the browser was writing is read in its last committed
state. Sources are "<Browser> <store>", for example "Edge History",
"Chrome Downloads" or "Firefox Cookies":
  - URL, page title, visit timestamp (stored by the browser in UTC and kept
    as UTC), visit count
  - Bookmarks (Chromium Bookmarks file, Firefox moz_bookmarks): date added
  - Chromium address bar shortcuts (Shortcuts database): last used, hits
  - Chromium Top Sites (Snapshot rows; no times are stored)
  - Downloads ("<Browser> Downloads", EventType FileAccess; the Chromium
    History downloads table, the Firefox places.sqlite annotations): a row
    when the download started; one when it completed, was cancelled,
    interrupted or blocked, if that was at least a minute later; and, for
    Chromium, one when the file was last opened from the browser. Details:
    Path, URL (Chromium: the file's URL, the last of the redirect chain;
    Firefox: the URL the download started from), Referrer, State (COMPLETE,
    CANCELLED, INTERRUPTED, IN_PROGRESS, BLOCKED; Firefox's own name in
    FirefoxState), DangerType (Chromium danger type or the Firefox
    reputation verdict, e.g. Malware), Bytes, StartUtc, EndUtc; Chromium
    adds OriginalURL (the first URL of the chain), TabURL, MimeType,
    InterruptReason and SHA256
  - Saved logins ("<Browser> Logins", "Firefox Logins"; Chromium Login
    Data, Firefox logins.json): when a login was saved, last used (only if
    at least a minute after it was saved), its password changed, and when
    the user chose "never save" for a site. Details: URL, Action, Realm,
    Username (Chromium only -- Firefox stores user names encrypted),
    TimesUsed
  - Cookies ("<Browser> Cookies", "Firefox Cookies"; Chromium
    Network\Cookies or Cookies, Firefox cookies.sqlite), aggregated per
    host: a row when the host's oldest cookie was set and one when its
    cookies were last accessed. Details: Host, Cookies (count), Names
    (first 200 characters), Persistent / Secure / HttpOnly counts
  - Form entries ("<Browser> Autofill", "Firefox Form History"; Chromium
    Web Data, Firefox formhistory.sqlite): the form field name, when an
    entry was first saved and last used, and TimesUsed. The newest 20,000
    entries per database are kept
  - Search engines ("<Browser> Search Engines", Chromium Web Data): when
    each engine was added, modified and last used, with its Keyword and URL
    template. Kind: Prepopulated, Policy, StarterPack, AutoGenerated (from
    a site's search form) or Custom (added or edited by the user -- or by
    software that wrote to Web Data, a known search-hijack technique)
  - Firefox site permissions ("Firefox Permissions", permissions.sqlite):
    notifications, camera, microphone, location, pop-ups, add-on installs
    and more, with the value set (ALLOW, DENY, PROMPT) and when
  - Extensions ("<Browser> Extensions", "Firefox Extensions"; EventType
    Installation): "Browser extension installed: <name> (<id>)" and, when
    at least a minute later, "Browser extension updated: <name> (<id>)".
    Chromium: extensions.settings in Secure Preferences and Preferences,
    name and version from the manifest stored there or the collected
    manifest.json ("__MSG_" names resolved). Details: ID, Name, Version,
    Location (Internal, ExternalPref, ExternalRegistry, Unpacked,
    ExternalPolicy, ...), State, DisableReasons (Chromium's names, e.g.
    USER_ACTION, EXTERNAL_EXTENSION), FromWebstore, InstalledByDefault,
    Path (unpacked and command-line extensions), UpdateURL, Overrides
    (homepage, search_provider, startup_pages, newtab, ...), Permissions,
    HostPermissions, InstallTimeUtc, UpdateTimeUtc. An extension with no
    install time gets a Snapshot row "Browser extension present: ...".
    Firefox (extensions.json; names also from addons.json): ID, Name,
    Version, Type, Location, Active, UserDisabled, SignedState, SourceURI,
    ForeignInstall (sideloaded), InstallSource, Hidden, Permissions,
    HostPermissions. Add-ons that are part of the browser (Chromium
    component extensions, Firefox built-in and system add-ons) are only
    counted in the log
  - Settings ("<Browser> Preferences", "<Browser> Local State", "Firefox
    Preferences"; Snapshot rows at the collection time): "Browser setting:
    <Setting> = <Value>" (Details: Setting, Value, Pref, Profile) for
    Proxy (also one set by an extension: SetByExtension), Download
    directory, Startup, Homepage, Default search engine (Chromium), Clear
    data on exit (Firefox: Cleared and Kept items; also cookies kept for the
    session only), History disabled, Private browsing always on, and
    Experimental flags (Local State)
  - Sessions ("<Browser> Sessions", "Firefox Sessions"; NetworkConnection).
    Chromium Session_* / Tabs_*: "Browser visit in session tab: <title>"
    or "Browser visit in closed tab: <title>" for each page in a tab's
    back/forward list at its visit time, and "Browser closed tab: <title>"
    at the tab's close time. Details: URL, Title, Transition, Referrer,
    Current=Yes (the page the tab showed), InHistory (No: the profile's
    live History has no visit to the URL within a minute -- only the
    session file still holds it), ClosedUtc, ClosedWindow, Reopened.
    Firefox (sessionstore.jsonlz4 and its backups): "Browser session tab:
    <title>" for an open tab at its last access time and "Browser closed
    tab: <title>" for recently closed tabs and the tabs of closed windows
    (Firefox keeps no time per page). New-tab and blank pages are left out
  - History snapshots ("<Browser> History Snapshot"): visits in a
    Snapshots\<version>\<profile>\History copy (made before an update) that
    are not in the live History: "Browser visit only in history snapshot:
    <title>". Details: Snapshot (the browser version), SnapshotTakenUtc,
    LiveHistoryModifiedUtc and Reason: Deleted (within the 90 days Chromium
    keeps, so it did not expire), Expired or deleted, or No live History.
    The visit was removed between those two times. Chromium's own "Clear
    browsing data" also deletes the snapshots of the range it clears, so
    such a visit was removed some other way (history page, extension, sync,
    database edited outside the browser) or expired
  - Favicons ("<Browser> Favicons"): "Browser favicon for page not in
    history: <URL>" for an http(s) page whose icon mapping is in Favicons
    but that is in neither the live History nor the bookmarks. A lead, not
    proof of a deletion: Chromium removes a page's icon mappings itself
    when it deletes or expires its history. The row time is when the icon
    was last stored (IconUpdatedUtc), not a visit: one icon often serves
    many pages of a site (PagesSharingIcon). Icons fetched without a visit
    (new-tab tiles) are left out; nothing when the profile's History was
    not collected; the newest 5,000 pages per file
  - User from the collection folder (Browser\<user>\)
Downloads are FileAccess rows (a download writes a file to disk); extension
installs and updates are Installation; settings, Top Sites and extensions
without an install time are Snapshot; all other browser rows are
NetworkConnection.
The credential, cookie and form stores are read as metadata only: saved
passwords, cookie values, autofill and form values, payment cards,
addresses and Firefox's encrypted user names and passwords are never read
(the queries never select them, and in logins.json they are blanked before
parsing). key4.db is never opened. The same holds for the newer files: in
Preferences, Secure Preferences and Local State the members os_crypt,
password_hash_data_list, protection, account_info, gaia_cookie, the
per-site content settings, keystore_encryption_key_state and every member
whose name contains encrypted_key, _encrypted_data, token or _salt are
blanked before the JSON is parsed; Firefox session cookies, form data,
session storage, POST data, typed text and page state likewise; Chromium
session page state is skipped unread; and Firefox prefs named like a secret
(token, secret, password, userAgentID) are not read.

This blanking happens before the file is parsed, so it holds even when the
collection was made with the collector's -IncludeSecrets switch, which copies
these browser files UNREDACTED (see below): no secret value reaches the
timeline. The members blanked here cover every member the collector blanks.

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

### 8. File System ($MFT)
Parses the raw $MFT the collector copies (FileSystem\$MFT):
  - File and folder created/modified times ($STANDARD_INFORMATION), with
    full paths rebuilt from the parent references, MFT record number, size
    and the $FILE_NAME created time in Details
  - Deleted files and folders (record no longer in use) are included and
    labelled "Deleted file"; their paths may be partial (<orphan>\...)
  - Possible timestomping is flagged with [SI<FN] in the Description for an
    executable or script (.exe .dll .sys .ps1 .bat .vbs .js .scr .lnk ...)
    whose $STANDARD_INFORMATION created time is on a whole second and more
    than 1 s earlier than its $FILE_NAME created time -- the pattern
    backdating tools leave. Windows servicing and installers lay files down
    the same way, so WinSxS, servicing, SoftwareDistribution, Installer,
    assembly, dotnet and WindowsApps are not flagged (on a test system that
    cut 10,230 hits to 180). Treat a flag as a lead, not proof.
  - Downloads (Mark of the Web): a file saved from the internet by a
    browser or mail client carries a Zone.Identifier stream ([ZoneTransfer]
    ZoneId=3, HostUrl=..., ReferrerUrl=...). Its text is small and almost
    always stored inside the MFT record, so it is read from the collected
    $MFT, also for deleted files. Each such file gets a row
    "Downloaded file (Mark of the Web, Internet zone): <path>" (Source MFT,
    EventType FileAccess; "; record deleted" is added in the brackets when
    the record is no longer in use). Details: ZoneId, HostUrl, ReferrerUrl,
    any other key of the stream, the MFT record, size and all times.
    Zones: 0 Local machine, 1 Local intranet, 2 Trusted sites, 3 Internet,
    4 Restricted sites; "zone unknown" when there is no ZoneId
  - "Extracted file (Mark of the Web, <zone>): <path>": the stream has no
    HostUrl and a local or network path as ReferrerUrl. Explorer writes
    this for each file it extracts from an archive with Mark of the Web;
    ReferrerUrl is the archive, whose own row has the HostUrl
  - These rows are at the $STANDARD_INFORMATION created time, or at the
    $FILE_NAME created time (RowTime=FN.Created in Details) when the SI
    time is missing, before 1980 or more than 1 s earlier (backdated, or
    set from the archive entry on extraction). They are added whatever
    -MftDays (-StartDate/-EndDate still apply). The file's "File created"
    row, when in the window, gets ZoneId and HostUrl (or ReferrerUrl)
    appended to its Details
  - Only times within -MftDays (default 7) days before the collection are
    added; flagged records are kept when their $FILE_NAME time is in range
Older collections without a $MFT: file listing CSVs are parsed if present
(capped at 50,000 entries); otherwise an info line, not a warning.

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
    examined system's local time to UTC. The logs record every device and
    driver install, so only USB devices -- instance IDs that start with
    USB\ or contain USBSTOR or VID_xxxx, and volumes on removable drives
    (SWD\WPDBUSENUM\{volume GUID}#<partition offset>) -- are EventType
    USBDevice; all others (graphics card, audio, Bluetooth, software
    devices, driver packages, ...) are EventType Installation. Source is
    USB-SetupAPI for both. Device deletions are reported for USB devices
    only. The log says how many setupapi logs were found and warns when
    collection_manifest.csv lists one that is missing (lost after
    collection)
  - USB devices and storage devices (usb_devices.txt, usb_storage_devices.txt)
  - Mounted devices (HKLM\SYSTEM\MountedDevices): one Snapshot row per
    value (Source USB-MountedDevices) saying which disk, partition or
    device a drive letter or volume GUID last belonged to, e.g.
      Drive letter H: -> MBR disk 0A1B2C3D, partition at offset 1048576
      Volume {...} -> USB storage Generic- SD/MMC (serial 0123456789)
    Read from USB\mounted_devices.csv (decoded by the collector), else from
    MountedDevices in the collected SYSTEM hive (also for mounted-image
    collections), else from the mounted_devices.txt of older collectors,
    which shows only the first 4 bytes of each value (see Known
    Limitations). Details: Kind (GPT, MBR, DevicePath or Other) and the
    decoded fields (partition GUID; disk signature and partition offset;
    device path with its InstanceId and Serial); VolumeGuid (the
    \??\Volume{} name with the same data, else the GPT partition GUID, or
    {<disk signature>-0000-0000-<offset bytes>} for MBR -- the names
    MountPoints2 keys in NTUSER.DAT use); SameDataAs (values with the same
    data, e.g. a drive letter and its volume GUID); SameDisk (other
    partitions of the same MBR disk); KeyLastWriteUtc (when the key was
    last written); PnPRecord for USB storage, when usb_storage_devices.csv
    is there ("in USBSTOR at collection time: <instance ID>", or "not in
    USBSTOR at collection time" -- a device Windows no longer lists);
    CollectorDrive=yes for the drive letter the triage collector wrote its
    output to (live collections). The log says how many values of each kind
    were read and from where

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
Analyzes memory dumps captured by the triage collector using Volatility 3:
the crash dump from DumpIt (<collection>_memory_dump.dmp) or a raw image
(<collection>_memory_dump.raw). The collector saves it next to the zip, as
it is too large to zip. The dump is looked for in this order:
  1. -MemoryDumpPath, for a dump saved elsewhere (if it is not an existing
     file, a warning is logged and the places below are searched)
  2. next to the collection zip: <zip name>_memory_dump.dmp or .raw
  3. inside the collection folder (Memory\memory_dump.dmp or .raw, where
     the collector leaves it with -NoCompress)
  4. next to the collection folder (the folder of collection_manifest.csv)
     or next to -InputPath (an outer folder that holds the collection):
     only <folder name>_memory_dump.dmp or .raw, so the dump of another
     collection in the same folder (e.g. the collector's reports\) is
     never used. After Windows "Extract All" (<name>\<name>\), a dump next
     to the outer folder is found too
Opt-in only -- not included in default Sources. Add "Memory" to -Sources to enable.
Without it, the builder offers to analyze a dump it finds when vol.exe is
in tools\.
Requires vol.exe in tools\volatility3\ (see tools\volatility3\README.txt).
Windows ARM64 dumps are detected from the dump header and skipped:
Volatility 3 analyzes Intel x86/x64 Windows memory only (use WinDbg).
  - windows.pslist: Running processes with creation timestamps, PIDs, parent PIDs
  - windows.netscan: Network connections with protocol, addresses, ports, state
  - windows.cmdline: Full command line arguments for each process
  - windows.svcscan: Windows services with binary paths, state, start type
Memory artifacts use the same EventTypes as disk artifacts (ProcessCreation,
NetworkConnection, Execution, ServiceChange) and are color-coded automatically.
The Source column distinguishes them (Memory-Processes, Memory-Network, etc.).

### 16. System Info
Parses systeminfo.txt and the firewall rule list:
  - "Windows installed" (Original Install Date, EventType Installation) and
    "System booted" (System Boot Time) at their real times
  - One Snapshot row with OS name, version, build, system type and domain
  - Enabled inbound Allow firewall rules (Snapshot rows)

### 17. Antivirus Logs
Parses the third-party AV logs the collector copies to AntiVirus\<vendor>\
into SecurityAlert rows (detections, blocks, quarantines, failures; routine
scan/update lines are skipped):
  - Symantec / Broadcom Endpoint Protection: daily AV logs (AV\*.Log)
  - Sophos Anti-Virus: SAV.txt
  - McAfee VirusScan Enterprise: AccessProtectionLog.txt (blocked and
    would-be-blocked actions)
  - ESET: virlog.dat (binary; best effort -- the format is undocumented)
These logs record the examined machine's local time, converted to UTC.
Built and tested against public sample logs from the plaso project
(Symantec, Sophos, McAfee) and a public ESET sample. Other products
(CrowdStrike, SentinelOne, Carbon Black, Kaspersky, Malwarebytes, ...) are
collected but not parsed: no public sample logs, and several keep their
detections in the vendor's cloud console rather than in local logs.
Also reads Microsoft Defender's own detection files (the collector copies
them to AntiVirus\Defender\; any DetectionHistory folder, and any Entries
folder inside a Quarantine folder, is read; files over 1 MB are not):
  - DetectionHistory (Source Defender-DetectionHistory, SecurityAlert): one
    row per detection, "Defender detection (DetectionHistory): <threat> on
    <path>", at the initial detection time. The path is the detected file,
    else the container or web download, else the file a behavior detection
    names, else the registry key, run key, startup item, service or task;
    without one there is no "on <path>". Details: ThreatName, ThreatID,
    Severity, CategoryID, Status, Path, Resources, User, Process, SHA256,
    StatusChangeUtc, RemediationUtc, DetectionID
  - Quarantine entries (Source Defender-Quarantine, SecurityAlert): one row
    per quarantined file or registry item, "Defender quarantined: <path>
    (<threat>)", at the quarantine time. Details: ThreatName, ThreatID,
    Path, ResourceType and, when the entry has them, PhysicalPath (only if
    it differs from Path), ResourceID, FileSize, FileCreatedUtc and
    FileModifiedUtc. The entries are RC4-encrypted with a static key
    published by security researchers; only these metadata files are
    decrypted, never the quarantined files (Quarantine\ResourceData)
  - A time missing from a file, or before 1980 (damaged), is replaced by
    the next one available, ending with the file's original creation time
    from the collection manifest; TimeNote in Details says which
One detection can also appear as an event log row (1116/1117), a
defender_detections.csv row and an MPLog row. The Source column tells them
apart; DetectionID (event log, CSV, DetectionHistory) and ThreatID (CSV,
DetectionHistory, quarantine) link them.

### 18. Email
Parses what the triage collector's Email category writes (Email\<user>\;
User is that <user> folder; Artifact Email):
  - Attachments ("Email-Attachments", FileAccess): "Outlook attachment in
    temp folder: <name>" (classic Outlook, Content.Outlook), "New Outlook
    attachment file: <name>" (Olk\Attachments) or "Windows Mail attachment
    in mail store: <name>", at the file's created time, and "... modified:
    <name>" at its modified time when that is at least a second later.
    Details: Program, Origin, Folder, Size, SHA256 (copied files),
    Collected, Status (why a file was not copied) and the created, modified
    and accessed times. Origin: "Opened from a message" (classic Outlook),
    "Opened, sent or received (not proof of opening)" (new Outlook) or
    "Stored with a message (not proof of opening)" (Windows Mail). Copied
    files are timed with the original file times in the manifest
  - Data files ("Email-DataFiles", FileAccess): OST/PST files ("Outlook
    data file created: <name>" / "Outlook data file last modified: <name>";
    an OST's last modified time is roughly its last sync) and the Windows
    Mail databases (HxStore.hxd, store.vol: "Windows Mail store file
    created / last modified"). Details: Program, Type, Path, Size, times
  - Thunderbird mail folders ("Email-MailFolders", FileAccess):
    "Thunderbird mail folder created / last modified: <account>/<folder>"
    and "Thunderbird message filter rules created / last modified:
    <account>" (a change can mean a new forwarding or delete rule).
    Details: Profile, Account, Storage (Mail = POP3 and Local Folders,
    ImapMail = IMAP), Folder, Path
  - Accounts ("Email-Accounts", Snapshot rows at the collection time): "New
    Outlook account: <address>" (UserSettings.json) and "Thunderbird
    account: <address> (<TYPE> <host>)" (prefs.js; Details: ServerType,
    Host, Port, UserName, Security, AuthMethod, Email, SmtpHost, SmtpUser).
    Saved passwords and tokens are never read
  - Messages ("Email-Messages", NetworkConnection): Thunderbird's search
    index (global-messages-db.sqlite; in a collection only when the
    collector ran with -IncludeThunderbirdIndex): "Email (Thunderbird):
    <subject>" at the message's Date header, the newest 20,000 per index.
    Details: From, To, Cc, Bcc (the addresses Thunderbird stores per
    message), Attachments (names), Folder, FolderURI, MessageID, Deleted,
    TimeSource. Read with sqlite3.exe (3.38 or later for the addresses);
    the message text is never selected
Not parsed: OST/PST contents (deferred), the new Outlook's and Windows
Mail's mail stores (listed only), and other listed files (WebView data,
.msf summaries, logs). The attachment copies can have any name, so no other
parser reads them: an attached .lnk, .evtx or $MFT is not this system's
shortcut, event log or MFT.

### Collections made with the collector's -IncludeSecrets switch
A collection made with -IncludeSecrets holds two things this builder treats
specially (collection_info.json records SecretsIncluded: true, and the builder
logs one line about it at the start):
  - A top-level Secrets\ folder with DPAPI credential material (per-user and
    system master keys, Credentials, Vault). No parser ever reads anything
    there: the Secrets\ exclusion is applied at the Find-ArtifactFiles choke
    point (so all of its callers skip it), on every other recursive search
    that walks the whole collection -- the $MFT search, the ScheduledTasks_XML
    folders, the SRUDB.dat search and the AntiVirus vendor / Defender folders
    -- and on the setupapi logs whose names were shortened on extraction.
    A $MFT, Preferences, Task XML, SRUDB.dat or antivirus file left in Secrets\
    is not parsed. Only the collection's own top-level Secrets\ folder (next to
    collection_info.json) is excluded, so a user profile folder named "Secrets"
    is unaffected. Nothing from Secrets\ reaches the timeline, and no row has a
    RawPath under it.
  - UNREDACTED browser settings and session files (the collector did not blank
    them). The builder blanks the secret members itself, before the JSON is
    parsed (see "Browser" above), so no key, token, salt, password hash,
    cookie, form value or page state reaches the timeline either way. The
    builder's blank set covers every member the collector would have blanked.
collection_info.json also carries ThunderbirdIndexIncluded. Both fields are
additive (SchemaVersion stays 1); collections from older collectors lack them
and are treated as false.

### 19. SRUM (System Resource Usage Monitor)
Parses Execution\SRUM\SRUDB.dat, the ESE database in which Windows records,
about once an hour, the network bytes and CPU/disk use of each application
per user (usually the last 30-60 days). Read with the Windows ESE engine
(esent.dll) through a small C# reader compiled at run time; no third-party
tools. Artifact SRUM:
  - "SRUM network usage: <app> sent 120.4 MB, received 3.2 MB" (Source
    SRUM-Network, NetworkConnection): one row per application, user and UTC
    day from the Network Data Usage table
  - "SRUM app activity: <app>" (Source SRUM-AppUsage, Execution): one row
    per application, user and UTC day from the Application Resource Usage
    table
  - The row time is the day's last SRUM record. The app is shown as SRUM
    stores it (a \device\harddiskvolumeN\... path, a packaged app or a
    service name). User is the account name when the collection gives one
    (well-known SIDs, bam_entries.csv, the SOFTWARE hive's ProfileList),
    otherwise the SID
  - Details: Day, App, AppId, UserSid; BytesSent and BytesRecvd (network)
    or ForegroundCycleTime, BackgroundCycleTime, FaceTime, the foreground
    and background bytes read and written, BytesRead and BytesWritten
    (app); Records, FirstRecordUtc, LastRecordUtc, Interfaces (Wi-Fi,
    Ethernet, ...), L2ProfileIds (not resolved to network names), and
    Database=... and Partial=yes when they apply
  - The database is read from a scratch copy in the work folder (see "Work
    folder"); the collection is never changed. A transaction log listed in
    collection_manifest.csv but no longer in the collection is reported
    ("Transaction log missing: ..."). A copy of an open database is
    normally in "dirty shutdown" state: the collected logs are replayed
    into the copy in the builder's own process ("Database=soft recovery
    (in-process)"); if that fails, with esentutl /r, then by repairing the
    copy with esentutl /p ("Database=repair (esentutl /p)"), which can lose
    the newest records. A damaged page stops the reading of a table; its
    rows then carry "Partial=yes (read error; later records of this table
    are missing)"
  - Not parsed: the Network Connectivity, energy and push-notification
    tables. SRUM keeps hourly totals per application, not connections: a
    row says how much an app sent and received that day, not where to


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
    Installation            Light Blue  -- application installs, and device and
                                           driver installs (setupapi)
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

  - Secrets are never decrypted. The builder reads credential, cookie and
    form stores as metadata only and blanks secret members before parsing
    (see "Browser"); it never decrypts saved passwords or cookies and never
    reads the Secrets\ folder of a collection made with the collector's
    -IncludeSecrets switch. Decrypting those is a separate, offline step with
    other tools (the collector's README explains what is needed). In
    particular, Chrome/Edge App-Bound Encryption can only be undone on the
    live machine, so App-Bound-protected passwords and cookies cannot be
    recovered from a collection at all; this builder does not attempt it.

  - USN journal size -- All USN rows are kept by default. On a very busy
    system the timeline can exceed Excel's row limit (see above); use
    -MaxUsnEntries N to keep only the newest N rows. The log says how many
    older rows were dropped.

  - "Could not load Amcache hive: ..." -- Usually a dirty hive: it needs its
    transaction logs (Amcache.hve.LOG1/.LOG2). Older versions of the triage
    collector dropped these hidden files by mistake, so collections made
    with them often hit this warning and Amcache parsing is skipped.
    Re-collect with the current collector to get the logs.

  - "Transaction log missing: ..." -- A hive's .LOG1/.LOG2 file, or a SRUM
    database's SRU*.log file, is listed in collection_manifest.csv but is
    not in the collection any more. The hive or database is read without
    it, so changes Windows had not yet written into the hive or database
    file are missing.

  - "Completed WITH N MISSING INPUT FILE(S) -- timeline incomplete" (exit
    code 2) -- Input files were deleted while the timeline was being built,
    usually by a cleanup tool or antivirus; the log lists them. Rows from
    them may be missing (a browser store also logs "sqlite3 query skipped,
    input file missing"); a file deleted after its parser read it is listed
    too, although its rows are there. Build the timeline again from the
    zip, or from a copy of the collection outside any temp folder.

  - "Completed WITH N UNEXPECTED ERROR(S) -- timeline may be incomplete"
    (exit code 2) -- The log has an "Unexpected error at line N (rest of
    this step skipped)" line for each. The rest of that step, often the
    rest of one parser, produced no rows. Such an error used to skip only
    its own statement; since the main body runs in try/finally (to clean up
    the work folder on every exit), it skips the rest of the step, so the
    run says so. Please report it with the log line.

  - "No service data found" -- Appears for mounted-image collections, which
    have no services.csv (it needs live queries). Scheduled tasks of mounted
    images are parsed from the collected task XML files instead.

  - "N IFEO/SilentProcessExit key(s) could not be opened (access denied)"
    -- A collected hive keeps the key permissions of the system it came
    from. Keys that deny Administrators (e.g. IFEO\DefenderAgentScan.exe on
    Windows 11) are skipped and named in the warning.

  - Hidden scheduled tasks -- A task is reported as hidden when its
    TaskCache\Tree key has no SD value, so the check relies on Windows
    keeping SD values there. Hidden task folders are only reported when
    other folders in the same hive have an SD value; otherwise the log says
    "N TaskCache\Tree folder(s) without an SD value not reported".

  - TaskCache times -- "Scheduled task registered" / "last run" rows from
    Registry-TaskCache are only added for tasks that scheduled_tasks.csv or
    the task XML files do not already cover. With -Sources Registry but not
    ScheduledTasks they are added for every task (a few hundred Microsoft
    tasks on a normal system).

  - Mark of the Web -- Only Zone.Identifier text stored inside the MFT
    record (resident, almost always the case) can be read. A non-resident
    stream still gives a row, with "zone unknown" and no URL. curl.exe and
    Invoke-WebRequest usually set no Mark of the Web, and copies through
    FAT/exFAT drives and Unblock-File remove it.

  - Third-party antivirus in the Application log -- Of the event source
    names read, only Symantec AntiVirus, McLogEvent and Sophos Anti-Virus
    are documented; the others are the products' names as they register
    them, not verified against real logs. Events under any other source
    name are not read.

  - Old browser databases -- Each browser query uses the columns the
    database has. A Chromium store too old to have the key columns (e.g. a
    History downloads table without target_path, an autofill table without
    date_created) is skipped with "0 row(s) added" in the log.

  - SRUM: "Soft recovery in this process failed: ... -- trying esentutl /r"
    and "Repair was needed: ..." -- the database was collected without its
    logs, or with logs from another moment. A repair can lose the newest
    records; those rows say "Database=repair (esentutl /p)". esentutl
    writes ESENT events to the Application event log of the machine
    running the builder (see "What It Modifies"): build timelines on an
    analysis machine, not on the system under investigation.

  - "SRUM <table>: read error after N record(s): ..." -- a damaged page in
    the SRUM database; that table's rows carry Partial=yes and lack the
    later records.

  - Defender DetectionHistory and quarantine entries do not last: Defender
    deletes DetectionHistory files after ScanPurgeItemsAfterDelay days (15
    by default), and a quarantine entry goes when the item is restored or
    deleted. A missing file does not prove there was no detection.

  - Email -- Thunderbird message times are the Date header, set by the
    sender's clock (it can be wrong or forged). A new Outlook attachment
    file is not proof it was opened: that folder also keeps sent and
    received attachments. OST/PST contents are not parsed.

  - Logs that record less than they seem -- the NTLM log is written only
    when NTLM auditing is on; Shell-Core logs neither the hive (HKLM or
    HKCU) nor the folder of a logon command. Browsers store only settings
    that differ from the default, and settings enforced by policy
    (registry) are not in their files, so neither gives a row.

  - Collections from older collector versions -- Still supported, with less
    precise times: no collection_info.json (the time zone and collection
    time are read from collection_log.txt), no original file times in the
    manifest, no bam_entries.csv / run_keys.csv / startup_folders.csv /
    usb_storage_devices.csv (BAM is read from the SYSTEM hive; run keys and
    startup items become Snapshot rows), and only setupapi.dev.log is
    collected (it may be missing if Windows rotated it). They have no
    mounted_devices.csv either: MountedDevices is read from the collected
    SYSTEM hive, and only without one (or when it cannot be loaded) from
    mounted_devices.txt, whose values those collectors cut off after 4
    bytes. Such a row says "(value cut off)": the kind is taken from the
    first bytes (an MBR disk signature is complete in them), but the
    partition GUID, offset and device name are missing, and the log warns.

  - Snapshot rows -- Services, drivers, network state, DLLs and items with
    no recorded time are shown at the collection time with EventType
    Snapshot. Their Timestamp is when the state was observed, not when it
    was created.

  - Local-time sources -- USN and setupapi times are local-time text. Times
    inside the hour that repeats when daylight saving time ends cannot be
    told apart and may be off by one hour.

  - SetupAPI USB devices -- A setupapi install counts as a USB device
    (USBDevice) only by its instance ID (USB\, USBSTOR, VID_xxxx, or
    SWD\WPDBUSENUM\{volume GUID}#...). The disk of a USB drive that uses
    UAS (USB Attached SCSI) is installed as SCSI\Disk&Ven_...; that row is
    Installation, while the drive's own USB\VID_... install just before it
    is USBDevice. Bluetooth devices are Installation. The portable device
    Windows makes for a volume on a removable drive (the
    SWD\WPDBUSENUM\{volume GUID}#<partition offset> rows) is USBDevice,
    as it nearly always is a USB drive, but an SD card in a built-in card
    reader gives one too. Such a row names only the volume GUID and the
    partition offset, not the drive.

  - Mounted devices -- MountedDevices keeps the last disk, partition or
    device each drive letter and volume GUID belonged to, not when it was
    mounted: the rows are Snapshot rows, and KeyLastWriteUtc is the last
    change to any value. Volume GUIDs of removable drives are version 1
    UUIDs with a time inside, but that time is not a mount or install time
    (in a real collection it was hours before the devices' first setupapi
    installs, and different devices had times microseconds apart), so it
    gives no row. The instance ID is rebuilt from the device path, where
    every "\" of the ID and a "/" in a product name (SD/MMC) are both
    written "#": the fields between the first and the last are joined with
    "/". PnPRecord compares serial numbers with usb_storage_devices.csv
    (live collections only).

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
  Browser          | History, downloads, logins,    | Full history + cache
                   | cookies, forms (auto sqlite3)  |
  USN Journal      | Parsed from text export        | Full $UsnJrnl binary parse
  $MFT             | SI/FN, deleted, windowed, MotW | Full $MFT parsing
  Shellbags        | Folder names + key times       | Full shellbag parsing
  Output formats   | CSV + color-coded XLSX         | CSV, JSON, XLSX, and more
  Parsers          | 19 parsers (18 + memory opt-in) | 100+ parsers

  When to use this: Quick triage, initial timeline, no-install environments,
  USB kit deployment, when you need results in minutes not hours.

  When to use plaso: Full forensic investigation, court-ready analysis, when
  you need exhaustive artifact coverage.


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
  Used by:    Parser #5 (Browser History) and #18 (Email: Thunderbird
              search index)

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
  Purpose:    Analyzes memory dumps to extract running processes, network
              connections, command lines, and services from RAM.
  Author:     Volatility Foundation
  Source:     https://github.com/volatilityfoundation/volatility3/releases
  License:    Volatility Software License (open source); not redistributed
              with this repo
  Place at:   tools\volatility3\vol.exe (the folder and its README.txt are in
              the repo; the tool is not)
  Used by:    Parser #15 (Memory Dump) -- opt-in only

  Setup (details: tools\volatility3\README.txt):
    1. Download the Windows executables asset of the latest release,
       volatility3-win-exes-<version>.zip, from:
       https://github.com/volatilityfoundation/volatility3/releases
    2. Extract it into win11-timeline-builder\tools\volatility3\ so that
       tools\volatility3\vol.exe exists (x64 build; runs under emulation
       on Windows on ARM)
    Volatility 3 analyzes Intel x86/x64 Windows memory only; ARM64 dumps
    are skipped with a note.

  The Memory parser is opt-in. Add "Memory" to -Sources to enable it.
  If vol.exe is not found, the parser logs download instructions and skips.
  The dump is found next to the collection zip or folder, or inside the
  collection (see parser #15); pass -MemoryDumpPath for a dump saved
  elsewhere.

  Plugins run (4 core plugins):
    windows.pslist   -- running processes with creation timestamps
    windows.netscan  -- network connections with addresses, ports, state
    windows.cmdline  -- full command line arguments per process
    windows.svcscan  -- Windows services with binary paths and state

  Processing time: 5-30 minutes depending on dump size (16-64 GB typical).
  Memory artifacts are interleaved with disk artifacts in the timeline and
  color-coded by EventType like all other entries.


## Tests

  tests\Test-Parsers.ps1 runs the builder on every fixture collection in
  tests\fixtures\<name>\ and compares each timeline with that folder's
  expected.csv. A fixture folder holds collection\ (the collection),
  sources.txt (the -Sources to run) and expected.csv:
    av\        AntiVirus -- public Symantec, Sophos and McAfee sample logs
               from the plaso project (Apache-2.0, see that folder's
               README.txt)
    setupapi\  USB -- two synthetic setupapi logs (current and rotated)
               with USB and other device installs and deletions
    usb\       USB -- a synthetic mounted_devices.csv (GPT, MBR, USB and
               other device paths) and usb_storage_devices.csv
  CI runs it on every pull request in Windows PowerShell 5.1 and
  PowerShell 7.

  Run it locally from an elevated PowerShell (the builder needs admin), or
  pass -BuilderPath with a copy of the builder without the admin check;
  -Fixture <name> runs only that fixture:
    powershell -ExecutionPolicy Bypass -File tests\Test-Parsers.ps1

  After an intended change to the parser output, regenerate the expected rows
  with -UpdateExpected (with -Fixture <name> for one fixture; it also
  creates expected.csv for a new fixture folder) and review the diff before
  committing.

  The scripts below test the event log, browser, registry, $MFT, email,
  SRUM and Defender parsers, the USB parser's mounted devices, and how the
  builder handles its input (secrets, zip input). CI runs them after
  Test-Parsers.ps1 in both PowerShell versions (GitHub Actions runners are
  elevated):

  tests\Test-EventLogParsers.ps1 -- Part 1 feeds the Security, System,
  Defender and Application handlers synthetic event records and checks
  their rows and which event IDs and providers each log reads; it needs no
  admin and always runs. Part 2 generates real events (audit policy, a
  temporary local user and group membership, scheduled task, service and
  classic event log), exports the logs with wevtutil, runs the builder on
  them and checks the rows. It needs admin and runs only in GitHub Actions or with
  -AllowSystemChanges; otherwise it is skipped. It undoes its changes, but
  the event records stay in the Security and System logs. Only in CI does
  it also clear the Security log (1102) and write synthetic Application
  events.

  tests\Test-BrowserParsers.ps1 -- builds synthetic Chromium and Firefox
  databases with sqlite3.exe, runs the builder with -Sources Browser and
  checks every row, its time and its Details. Every secret column holds a
  canary string that must not appear in the timeline, the log or the
  output. Needs admin like the builder (or -BuilderPath with a copy
  without the admin check); it changes nothing on the system. If
  sqlite3.exe is missing, the builder is run once to download it.

  tests\Test-RegistryParsers.ps1 -- writes known values (IFEO, Winlogon, a
  hidden TaskCache task, Defender exclusions, Office, Remote Desktop,
  MountedDevices, ...) below a temporary key
  HKCU\Software\TriageTimelineTest_<guid>, saves them as SOFTWARE, SYSTEM
  and NTUSER.DAT hives with reg save, deletes the key, runs the builder
  with -Sources Registry,ScheduledTasks,USB and checks the rows and times
  (the MountedDevices rows must come from the SYSTEM hive, not from the
  empty mounted_devices.csv or the cut-off mounted_devices.txt of an older
  collector next to it). Needs admin;
  because it writes to the registry it runs only in GitHub Actions or with
  -AllowSystemChanges (otherwise it prints SKIP).

  tests\Test-MftParser.ps1 -- builds a small synthetic $MFT and checks the
  $MFT parser's rows (Mark of the Web: downloaded, extracted, deleted,
  timestomped and backdated files, stream encodings, extension records).
  No admin needed: it loads the builder's functions without running the
  script.

  tests\Test-EventLogParsers2.ps1 -- the Phase 2 logs (Windows PowerShell,
  WMI-Activity, RDP client, NTLM, Windows Firewall, Shell-Core, OAlerts,
  AntiVirus\*.evtx) and the 4624 details. Part 1 feeds the handlers
  synthetic records laid out like real ones and checks every row and which
  event IDs each log reads (no admin). Part 2 exports the last 30 days of
  these logs from this machine with wevtutil, runs the builder and checks
  that every Windows PowerShell 400 has its row and that every log parses;
  it only reads, but needs a builder that runs (admin, or -BuilderPath),
  otherwise it is SKIPPED. Part 3 needs admin and runs only in GitHub
  Actions or with -AllowSystemChanges: it starts Windows PowerShell with an
  encoded command, adds, changes and deletes a disabled firewall rule and
  changes the Public profile's log size and back; in GitHub Actions only,
  it also creates a temporary WMI event subscription, turns on NTLM
  auditing for a loopback SMB connection and starts the Remote Desktop
  client against an unused loopback address. All of it is undone; the
  event records stay in the logs.

  tests\Test-BrowserExtrasParsers.ps1 -- builds synthetic Chromium
  Preferences, Secure Preferences, Local State, extension manifests, SNSS
  session files, history snapshots and Favicons, and Firefox
  extensions.json, addons.json, prefs.js and mozLz4 session files, runs
  the builder with -Sources Browser and checks every row, its time and its
  Details, and that built-in add-ons, on-demand favicons, bookmarked pages
  and pages still in history give no rows. A canary string in every secret
  or private field must not appear in the timeline, the log or the output.

  tests\Test-SecretsHandling.ps1 -- builds a synthetic collection made as if
  by the collector's -IncludeSecrets switch: UNREDACTED Chromium Local State,
  Preferences and Secure Preferences, Firefox prefs.js and Chromium/Firefox
  session files that still hold canary secret values, collection_info.json
  with SecretsIncluded true, and a top-level Secrets\ folder with DPAPI
  credential material (plus a $MFT, a Preferences file, a ScheduledTasks_XML
  task, a SRUDB.dat and an AntiVirus vendor folder planted there, to exercise
  every exclusion). A control user profile named "Secrets" holds ordinary
  artifacts that must still be parsed. Runs the builder with -Sources
  Browser,FileSystem,ScheduledTasks,SRUM,AntiVirus and checks that the canary
  appears nowhere in the timeline, log or output (the builder blanks the secret
  members before parsing), that no row has a RawPath under the top-level
  Secrets\ folder (no parser reads it: the $MFT search, ScheduledTasks_XML,
  SRUDB.dat, AntiVirus and the Find-ArtifactFiles callers all skip it), that
  the "Secrets" control user's artifacts still produced rows, that the "made
  with -IncludeSecrets" log line appears, and that non-secret settings and URLs
  still produced rows (so the canary-free result is not vacuous).

  tests\Test-EmailParsers.ps1 -- lays out a synthetic Email\<user>\
  collection (listing CSVs, copied attachments, manifest,
  UserSettings.json, prefs.js and a global-messages-db.sqlite built with
  sqlite3.exe), runs the builder with -Sources Email,RecentFiles and checks
  every email row, its time and its Details. A message text, a saved
  password and tokens hold a canary that must not appear in the output,
  and a .lnk or $MFT copied as an attachment must not be parsed as the
  system's own.

  tests\Test-SrumParsers.ps1 -- builds SRUM-like ESE databases with the
  Windows ESE engine, runs the builder with -Sources SRUM and checks every
  row, its time, User and Details; also a database in dirty-shutdown state
  collected read-only with its logs (recovered in the builder's process,
  the collection unchanged), a damaged page (Partial rows), a SRUDB.dat
  that is not an ESE database, and that the builder's own ESE use writes
  no ESENT events. Part 2 checks the esentutl /p repair. esentutl writes
  ESENT events to the Application event log, so part 2 runs only in GitHub
  Actions or with -AllowSystemChanges; as Administrator it also saves a
  temporary HKCU key as a SOFTWARE hive to check SID names from
  ProfileList.

  tests\Test-DefenderParsers.ps1 -- builds synthetic DetectionHistory files
  and quarantine entries (encrypted with the test's own RC4 code), runs the
  builder with -Sources AntiVirus and checks every row and its Details,
  the fallback times, damaged, foreign and oversize files, and that files
  under Quarantine\ResourceData and Quarantine\Resources are never read.
  Thousands of truncated and corrupted copies must read without an
  exception.

  The browser extras, secrets, email, SRUM and Defender tests need admin like
  the builder, or -BuilderPath with a copy without the admin check (kept under
  the git-ignored reports\ folder); a missing sqlite3.exe is downloaded by
  one builder run. Apart from Test-SrumParsers part 2, they change nothing
  on the system.

  tests\Test-ZipInput.ps1 -- Part 1 loads the builder's functions and checks
  the zip extraction ("/" and "\" entry names, entry dates kept, over-long
  names shortened, no ".." entry written outside the folder, nothing
  extracted when the zip does not fit), the manifest lookups, the list of
  input files, the free-space and temp-folder checks, the refusal of a
  network work folder, the clean-up of work folders left by killed runs,
  the SRUM database copy (made in the work folder; a missing transaction
  log reported) and the end-of-run banners; it needs no admin. Part 2
  runs the builder on a synthetic collection zip dated 2025 with two
  setupapi logs: both must be parsed, the free space must be checked, the
  work folder must be outside %TEMP% and removed afterwards, and an input
  file deleted during the run (by a test hook) must give exit code 2 and
  the MISSING INPUT FILE(S) banner. Part 2 needs admin like the builder
  (or -BuilderPath with a copy without the admin check); it changes
  nothing on the system.

  tests\Test-MountedDevices.ps1 -- loads the builder's functions and checks
  the MountedDevices decoder (GPT, MBR, device paths, unrecognized values),
  the instance ID rebuilt from a device path (Prod_SD#MMC -> SD/MMC), the
  salvage of the cut-off mounted_devices.txt of older collectors ("..."
  and the ellipsis character), each row's Description and Details, and
  which source Parse-USB uses (mounted_devices.csv with rows first, then
  the SYSTEM hive, also after an empty CSV, then the .txt; the hive is
  unloaded also after a read error; no rows from the decoded .txt of newer
  collectors; no CSV or SYSTEM hive read from the Secrets\ folder or the
  email attachment copies). No admin needed: stubs stand in for loading
  and reading the hive; reading a real SYSTEM hive is covered by
  Test-RegistryParsers.ps1.

  tests\Test-MemoryParser.ps1 -- loads the builder's functions and checks
  where the memory dump is found, on synthetic folders: -MemoryDumpPath
  first (also a relative path and one with [ ] in it; a missing file or
  a folder gives one warning, then the other places are searched), next
  to the collection zip (.dmp or .raw), Memory\ inside the collection,
  and next to the collection folder or -InputPath only under the
  collection folder's name (another collection's dump in the same folder
  is not used; also with collection_manifest.csv below -InputPath, an
  outer -InputPath of another name and after Windows "Extract All"). It
  also checks the Memory parser's warning when there is no dump.
  Volatility 3 is not run; no admin needed.

  Run them from an elevated PowerShell; -AllowSystemChanges lets the event
  log, registry and SRUM tests change this machine:
    powershell -ExecutionPolicy Bypass -File tests\Test-EventLogParsers.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-EventLogParsers2.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-BrowserParsers.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-BrowserExtrasParsers.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-SecretsHandling.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-EmailParsers.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-SrumParsers.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-DefenderParsers.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-MftParser.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-ZipInput.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-MountedDevices.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-MemoryParser.ps1
    powershell -ExecutionPolicy Bypass -File tests\Test-EventLogParsers.ps1 -AllowSystemChanges
    powershell -ExecutionPolicy Bypass -File tests\Test-EventLogParsers2.ps1 -AllowSystemChanges
    powershell -ExecutionPolicy Bypass -File tests\Test-RegistryParsers.ps1 -AllowSystemChanges
    powershell -ExecutionPolicy Bypass -File tests\Test-SrumParsers.ps1 -AllowSystemChanges


## Windows Built-In Tools Used

  reg.exe              Loads offline registry hives (NTUSER.DAT,
                       UsrClass.dat, SOFTWARE, SYSTEM, Amcache.hve) via
                       "reg load" for parsing UserAssist, TypedPaths,
                       RunMRU, RecentDocs, ShellBags, Office and Remote
                       Desktop history, IFEO / Winlogon / AppInit_DLLs, the
                       TaskCache, Defender exclusions, LSA settings, BAM,
                       ShimCache, MountedDevices (when there is no
                       mounted_devices.csv) and Amcache entries, including
                       key last-write times. Unloads after.

  Get-WinEvent         Parses .evtx event log files with XPath filtering.
                       Used for targeted extraction of high-value Security,
                       System, Application, PowerShell, Sysmon, Task
                       Scheduler, TerminalServices (RDP), Windows Defender
                       and BITS events, and the Windows PowerShell,
                       WMI-Activity, RDP client, NTLM, Firewall, Shell-Core,
                       OAlerts and antivirus product logs.

  esent.dll            The Windows ESE database engine. Reads the SRUM
                       database (SRUDB.dat) from a scratch copy in the work
                       folder and replays its transaction logs into that
                       copy, with event logging off.

  esentutl.exe         Fallback only: recovery (/r) or repair (/p) of the
                       scratch copy of a SRUM database, when the recovery in
                       the builder's process fails or the copy is damaged.

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
creates files in its own reports\ directory, in its work folder
(%LOCALAPPDATA%\TimelineBuilder\w<PID>_<HHmmss>, or inside -WorkDir; deleted
at the end of the run) and in %TEMP% for downloads. No system files, registry
keys, or artifacts are modified. The one lasting trace: when a SRUM database
needs esentutl, it writes entries to this machine's Application event log
(see below).

One-time actions (first run only):
  - Installs ImportExcel PowerShell module (CurrentUser scope)

Temporary actions (all cleaned up automatically, also after an error or Ctrl+C):
  - Extracts a collection zip (browse mode, or a .zip as -InputPath) into the
    work folder, with the dates stored in the zip -- deleted after processing
  - Copies registry hives (NTUSER.DAT, UsrClass.dat, SOFTWARE, SYSTEM,
    Amcache.hve) into the work folder for reg load -- unloaded and deleted
    after processing (a hive a parser left loaded is unloaded at the end)
  - Copies browser DBs into the work folder for sqlite3 -- deleted after
    processing
  - Copies SRUDB.dat and its logs into the work folder
    (scratch\TimelineSrum_<n>) for recovery and reading (the copies are
    made writable) -- deleted after processing
  - Downloads zip files to %TEMP% (first run) -- deleted after extraction

Event log entries (not removed):
  - Only when the in-process recovery of a SRUM database fails, or a copy
    has to be repaired, esentutl.exe runs on the scratch copy. It writes
    ESENT events (information, and for a repair also warnings and an
    error) to the Application event log of the machine running the
    builder. If that machine is collected later, its timeline shows them
    as "ESE database attached/detached: ...\TimelineSrum_<n>\SRUDB.dat"
    rows. Reading a SRUM database and the normal in-process recovery run
    with event logging off.
