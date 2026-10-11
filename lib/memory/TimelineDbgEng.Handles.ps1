# =============================================================
# Windows ARM64 memory dumps: handles (item e)
# Part of win11-timeline-builder (work package WP3). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngHandlesSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngHandlesArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Handle (rows: Add-DbgEngHandleRows)
# Needs TimelineDbgEng.Objects.ps1. Offers a handle lookup to the joins
# through $Context.Shared.
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngHandlesSource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngHandlesArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
