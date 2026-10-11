# =============================================================
# Windows ARM64 memory dumps: DLLs per process, mapped-but-unlinked ones included (item c)
# Part of win11-timeline-builder (work package WP2). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngModulesSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngModulesArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Module (rows: Add-DbgEngModuleRows)
# The memory regions come from the shared VadWalker (Get-DbgEngVadWalker).
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngModulesSource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngModulesArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
