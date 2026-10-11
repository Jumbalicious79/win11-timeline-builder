# =============================================================
# Windows ARM64 memory dumps: console command history (item h)
# Part of win11-timeline-builder (work package WP5). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngConsoleSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngConsoleArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Console (rows: Add-DbgEngConsoleRows)
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngConsoleSource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngConsoleArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
