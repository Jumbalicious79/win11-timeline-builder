# =============================================================
# Windows ARM64 memory dumps: registry hives in memory, Run values and the Services key (item g)
# Part of win11-timeline-builder (work package WP4). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngRegistrySource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngRegistryArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Hive and RunValue (rows: Add-DbgEngHiveRows, Add-DbgEngRunValueRows)
# Offers the in-memory Services key to the joins through $Context.Shared. SAM
# and SECURITY: names only, never read.
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngRegistrySource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngRegistryArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
