# =============================================================
# Windows ARM64 memory dumps: full program paths and current folders (item b)
# Part of win11-timeline-builder (work package WP1). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngImagePathsSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
# The area's function Invoke-DbgEngProcessDetailsArea is in
# TimelineDbgEng.Tokens.ps1.
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngImagePathsSource {
    return ""
}
