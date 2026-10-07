ANTIVIRUS LOG FIXTURES
======================

A minimal triage collection used by tests\Test-Parsers.ps1 to check the
AntiVirus parser (timeline-builder.ps1, parser #17). The test runs the builder
on collection\ and compares its timeline with expected.csv.

  collection\
    collection_info.json                       -- fixture metadata (time zone:
                                                  Pacific Standard Time, so the
                                                  local -> UTC conversion is tested)
    AntiVirus\Symantec_SEP\Symantec.Log        -- Symantec AV log
    AntiVirus\Sophos\SAV.txt                   -- Sophos Anti-Virus log (UTF-16)
    AntiVirus\McAfee_Trellix\AccessProtectionLog.txt
                                               -- McAfee VirusScan Access
                                                  Protection log
  expected.csv                                 -- rows the parser must produce
  LICENSE-Apache-2.0.txt                       -- license of the three sample logs


SOURCE AND LICENSE OF THE SAMPLE LOGS
-------------------------------------
The three log files are unmodified copies of test data from the plaso
(log2timeline) project, renamed to the file names the triage collector uses:

  Symantec.Log             https://github.com/log2timeline/plaso/blob/main/test_data/Symantec.Log
  SAV.txt (sav.txt)        https://github.com/log2timeline/plaso/blob/main/test_data/sav.txt
  AccessProtectionLog.txt  https://github.com/log2timeline/plaso/blob/main/test_data/AccessProtectionLog.txt

Copyright The Plaso Project Authors
(https://github.com/log2timeline/plaso/blob/main/AUTHORS).
Licensed under the Apache License, Version 2.0 -- see LICENSE-Apache-2.0.txt
(a copy of plaso's LICENSE file). They are covered by that license, not by
this repository's MIT license.

The ESET parser is not tested here: the only public ESET sample (from the
GPL-3.0 project laciKE/EsetLogParser) is not included in this MIT-licensed
repository.


UPDATING
--------
If the parser output changes on purpose, regenerate expected.csv with:
  powershell -ExecutionPolicy Bypass -File tests\Test-Parsers.ps1 -UpdateExpected
and review the diff before committing it.
