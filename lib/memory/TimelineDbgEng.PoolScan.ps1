# =============================================================
# Windows ARM64 memory dumps: the one read-only pass over the dump file (network objects; the services fallback)
# Part of win11-timeline-builder (work package WP6). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# NOT BUILT YET: this file holds the place of its code, so the area is
# reported as "not read (not built yet)". It must keep:
#   Get-DbgEngPoolScanSource   its C#: namespace TimelineDbgEng { ... } blocks only, no
#                     using lines (the host's using header applies), C# 5
# Start-DbgEngRawPass -Context starts it on a thread of its own before the
# first area and sets $Context.RawPass (disposed when the areas are done if it
# is IDisposable).
# =============================================================

# The C# of this file (none yet)
function Get-DbgEngPoolScanSource {
    return ""
}

# Starts the pass over the dump file (not built yet: nothing to start)
function Start-DbgEngRawPass {
    param($Context)
    $null = $Context
}
