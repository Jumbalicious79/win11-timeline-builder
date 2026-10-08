SETUPAPI LOG FIXTURE
====================

A minimal triage collection used by tests\Test-Parsers.ps1 to check the
SetupAPI part of the USB parser (timeline-builder.ps1, parser #11). The test
runs the builder with the -Sources in sources.txt (USB) on collection\ and
compares its timeline with expected.csv.

  collection\
    collection_info.json                     -- fixture metadata (time zone:
                                                W. Europe Standard Time, so the
                                                local -> UTC conversion is
                                                tested on both sides of the
                                                2025-03-30 DST change)
    USB\setupapi.dev.20250301_101500.log     -- rotated log (January-March)
    USB\setupapi.dev.log                     -- current log (March-June); its
                                                first section repeats the
                                                rotated log's last one
  sources.txt                                -- -Sources for the test run
  expected.csv                               -- rows the parser must produce


WHAT THE LOGS CONTAIN
---------------------
Both logs are synthetic: written for this test in the format of
setupapi.dev.log. Vendor and product IDs (VEN_FFF0, VID_FFF1), serial
numbers (FIXTURESERIAL000n), volume GUIDs (00000000-0000-11f0-...) and the
Bluetooth address (all zeros) are made up.

  USB devices -> EventType USBDevice:
    USB\VID_...\<serial>, USBSTOR\Disk&Ven_...\<serial>&0, the same disk as
    a portable device (SWD\WPDBUSENUM\_??_USBSTOR#...) and as a volume
    (STORAGE\VOLUME\_??_USBSTOR#...), HID\VID_...&MI_00\..., a
    lower-case software component swc\vid_..., and the portable device of
    a removable-drive volume (SWD\WPDBUSENUM\{volume GUID}#<offset>)
  Other device and driver installs -> EventType Installation:
    PCI (also a Windows Update driver for it), HDAUDIO, ROOT, a driver
    package installed by path (DiInstallDriver), Bluetooth (BTHENUM\..._VID&...
    does not count as USB) and the SCSI\Disk of a UAS drive
  Deletions: one USB\, one USBSTOR\ and one removable-drive volume device
    (rows), one PCI and one SWD\MMDEVAPI device (no rows: only USB
    deletions are reported)
  Ignored: a Driver Install (DrvSetupInstallDriver) section, and the
    repeated Bluetooth section (counted as a duplicate)


UPDATING
--------
If the parser output changes on purpose, regenerate expected.csv with:
  powershell -ExecutionPolicy Bypass -File tests\Test-Parsers.ps1 -Fixture setupapi -UpdateExpected
and review the diff before committing it.
