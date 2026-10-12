# =============================================================
# Windows ARM64 memory dumps: the joins: what the areas found, combined, before the entries are written
# Part of win11-timeline-builder (work package WP8). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# Invoke-DbgEngJoins -Context runs after every area ($Context.Areas,
# $Context.Shared) and may change their entries; it never adds an area of
# its own. Most of what the areas combine needs nothing here, because the
# areas run in a fixed order and a later one reads what an earlier one
# offers:
#   process users      ProcessDetails runs first and sets each process's
#                      token user SID, full name and program path
#                      (ProcessInfo.UserSid, FullName, ImagePath); the DLL,
#                      private memory, handle, console, network and service
#                      entries take them from there (User=, Process=,
#                      OwnerSid=, OwnerPath=)
#   services and the   Registry runs before Services, which joins each
#   registry           service with its key of the in-memory Services key
#                      ($Context.Shared["RegistryServices"]: RegistryBinary,
#                      ServiceDll, Account, Anomaly NoRegistryKey only when
#                      that key was read in full)
#   network owners     the Network area judges each connection's owner
#                      against the process scan itself (Anomaly OwnerHidden,
#                      Stale)
#   console clients    the Console area reads each history's client process
#                      ID from the console host's own record of it (no
#                      handle is involved)
# The join made here: a Process or Thread handle entry (Handles) whose
# target process has executable private memory that starts with a program
# header (PrivateCode, $Context.Shared["PeCodeProcesses"]) gets Anomaly
# TargetHasPeCode added to its own (the targets: $Context.Shared
# ["HandleTargets"]). Counts go to the log.
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngJoinsSource {
    return @'
namespace TimelineDbgEng
{
    public static class MemoryJoins
    {
        // Adds a token to an entry's comma-separated Anomaly (once)
        public static void AddAnomaly(MemoryEntry entry, string token)
        {
            if (entry == null || string.IsNullOrEmpty(token)) return;
            string current = entry.Get("Anomaly");
            if (current.Length == 0) { entry.Set("Anomaly", token); return; }
            foreach (string part in current.Split(','))
            {
                if (string.Equals(part, token, StringComparison.Ordinal)) return;
            }
            entry.Set("Anomaly", current + "," + token);
        }

        // Handle entries whose target process has a private region with a
        // program header: Anomaly TargetHasPeCode. Returns how many entries
        // got it; -1 when either area offered nothing to join (not read)
        public static int MarkPeCodeTargets(MemoryContext context)
        {
            object targets, processes;
            if (context == null || !context.Shared.TryGetValue("HandleTargets", out targets) || !context.Shared.TryGetValue("PeCodeProcesses", out processes)) return -1;
            List<KeyValuePair<MemoryEntry, ulong>> list = targets as List<KeyValuePair<MemoryEntry, ulong>>;
            HashSet<ulong> withPeCode = processes as HashSet<ulong>;
            if (list == null || withPeCode == null) return -1;
            int marked = 0;
            foreach (KeyValuePair<MemoryEntry, ulong> item in list)
            {
                if (!withPeCode.Contains(item.Value)) continue;
                AddAnomaly(item.Key, "TargetHasPeCode");
                marked++;
            }
            return marked;
        }
    }
}
'@
}

# The joins, after every area: the handle entries' TargetHasPeCode (see
# above); one log line of counts
function Invoke-DbgEngJoins {
    param($Context)
    $marked = [TimelineDbgEng.MemoryJoins]::MarkPeCodeTargets($Context)
    if ($marked -ge 0) { Write-DbgEngLog "    Joins: handle entries whose target has a program header in its executable private memory $marked" }
}
