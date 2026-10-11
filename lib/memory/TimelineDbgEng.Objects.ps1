# =============================================================
# Windows ARM64 memory dumps: kernel object decoding shared by the drivers and handles areas
# Part of win11-timeline-builder (work package WP3). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngObjectsSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
# No area function of its own: Invoke-DbgEngDriversArea and
# Invoke-DbgEngHandlesArea are in TimelineDbgEng.Drivers.ps1 and
# TimelineDbgEng.Handles.ps1.
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngObjectsSource {
    return ""
}
