# =============================================================
# Windows ARM64 memory dumps: network connections, listeners and UDP endpoints (item i)
# Part of win11-timeline-builder (work package WP6). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngNetworkSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
#   Invoke-DbgEngNetworkArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Net (rows: Add-DbgEngNetRows)
# Needs TimelineDbgEng.PoolScan.ps1 (its pass over the dump file,
# $Context.RawPass).
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngNetworkSource {
    return ""
}

# The area (not built yet)
function Invoke-DbgEngNetworkArea {
    param($Context, $Area)
    $null = $Context
    $Area.SetNotRead("not built yet")
}
