Canned entries of the debugger engine helper's areas (Windows ARM64 memory
dumps), for the tests that do not read a dump: tests\Test-ReportBuilder.ps1
(its canned helper sends them through the builder's real protocol reader
and rows), and any test through Read-TestCannedEntries (tests\MemoryTestKit.ps1).

One file per entry kind, canned-<kind>.txt, ASCII, CRLF. Each work package
adds and edits only its own files. A line is one of:
  # <comment>
  #AREA<TAB><area><TAB><Read|Partial|NotRead><TAB><note>
      the AREA line of that area (Name as in Get-DbgEngAreas: ProcessDetails,
      Modules, PrivateCode, Drivers, Handles, Registry, Console, Services,
      Network); its rows are the file's entries. An area that no file names
      is sent as NotRead "not built yet", as the helper's area stubs do.
  <Kind><TAB><Key>=<value><TAB><Key>=<value>...
      one entry (TBDBG|E|<Kind>|<Key>:<Base64>|...): a key is a letter, then
      letters and digits; the value is everything after the first "=" (no
      TAB in it).
The values are synthetic (fixture-*.exe and the like), never from a real dump.

net-rules-switched-off.csv (WP6): the cases of a network rule that ships
switched off (EXEC-NET-SCRIPTHOST-PUBLIC), in the format of
tests\fixtures\report\rules\cases*.csv; tests\Test-MemoryNetwork.ps1 runs
them with the rule switched on in memory (tests\Test-ReportRules.ps1 does
not run a switched-off rule, so its HIT cases cannot be there).
