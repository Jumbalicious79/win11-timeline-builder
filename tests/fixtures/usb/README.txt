USB FIXTURE
===========

A minimal triage collection used by tests\Test-Parsers.ps1 to check the
mounted devices and USB storage parts of the USB parser
(timeline-builder.ps1, parser #11). The test runs the builder with the
-Sources in sources.txt (USB) on collection\ and compares its timeline with
expected.csv.

  collection\
    collection_info.json         -- fixture metadata (live collection,
                                    UTC, collected 2025-06-30 12:00:00)
    collection_log.txt           -- the collector's output directory is
                                    on E: (CollectorDrive)
    USB\mounted_devices.csv      -- MountedDevices as the collector
                                    decodes it
    USB\usb_storage_devices.csv  -- one USB storage device known to PnP
  sources.txt                    -- -Sources for the test run
  expected.csv                   -- rows the parser must produce


WHAT THE FILES CONTAIN
----------------------
Both CSV files are synthetic: written for this test in the collector's
format. Partition and volume GUIDs (a0000000-..., 00000000-0000-11f0-...),
disk signatures (5EED0001, 0A1B2C3D) and serial numbers (FxSerial000n,
FXSERIAL000n) are made up.

  mounted_devices.csv:
    GPT: C: and its \??\Volume{} name (same data: SameDataAs), and D:
    MBR: G: (offset 32256), and H: and I: on one disk (SameDisk; I: at
      an offset above 4 GiB)
    USB storage device paths: E: and its volume (the collector's output
      drive; listed in usb_storage_devices.csv, serial in another case),
      an SD/MMC reader (Prod_SD#MMC in the path -> SD/MMC; not in
      USBSTOR), and a device without a serial number
    A CD-ROM device path starting \??\ and an unrecognized value
  usb_storage_devices.csv: the device of E:, with first install, last
    arrival and last removal times (three USBDevice rows)


UPDATING
--------
If the parser output changes on purpose, regenerate expected.csv with:
  powershell -ExecutionPolicy Bypass -File tests\Test-Parsers.ps1 -Fixture usb -UpdateExpected
and review the diff before committing it.
