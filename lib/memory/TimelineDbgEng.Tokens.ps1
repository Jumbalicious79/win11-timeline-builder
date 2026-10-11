# =============================================================
# Windows ARM64 memory dumps: process users, integrity and elevation (item a), from each process token
# Part of win11-timeline-builder (work package WP1). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngTokensSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngProcessDetailsArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Proc (merged into the process rows by Offset: Set-DbgEngProcessRowFields)
# TimelineDbgEng.ImagePaths.ps1 is the same area's other file.
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngTokensSource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngProcessDetailsArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
