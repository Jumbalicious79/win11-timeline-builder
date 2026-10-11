# =============================================================
# Windows ARM64 memory dumps: services from the service control manager's memory (item j)
# Part of win11-timeline-builder (work package WP7). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngServicesSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngServicesArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Service (rows: Add-DbgEngServiceRows)
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngServicesSource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngServicesArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
