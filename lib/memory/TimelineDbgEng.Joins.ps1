# =============================================================
# Windows ARM64 memory dumps: the joins: what the areas found, combined, before the entries are written
# Part of win11-timeline-builder (work package WP8). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngJoinsSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
# Invoke-DbgEngJoins -Context runs after every area ($Context.Areas,
# $Context.Shared) and may change their entries.
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngJoinsSource {
    return ""
}

# The joins (not built yet: nothing to combine)
function Invoke-DbgEngJoins {
    param($Context)
    $null = $Context
}
