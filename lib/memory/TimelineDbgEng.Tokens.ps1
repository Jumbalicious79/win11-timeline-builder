# =============================================================
# Windows ARM64 memory dumps: process users, integrity and elevation (item a), from each process token
# Part of win11-timeline-builder (work package WP1). lib\memory\TimelineDbgEng.ps1
# dot-sources this file in the helper's own PowerShell process; it builds on
# the shared reading layer of TimelineDbgEng.Reader.ps1 (see "The areas" in
# TimelineDbgEng.ps1 for the contract).
#
# The ProcessDetails area (this file and TimelineDbgEng.ImagePaths.ps1): for
# each process of the scan, what its token says and where its program is.
#   Get-DbgEngTokensSource   its C#: TokenDetails, TokenReader and the area's
#                     loop (ProcessDetailsArea); namespace blocks only, C# 5
#   Get-DbgEngTokensLayoutSpec   the token's fields it needs ('dt')
#   Invoke-DbgEngProcessDetailsArea -Context <MemoryContext> -Area <AreaResult>
#   entries: Proc, one per process (Offset: its EPROCESS, as its P line),
#     merged into the process rows by the builder (Set-DbgEngProcessRowFields
#     in lib\memory\TimelineMemoryRows.ps1)
#
# The token (EPROCESS.Token, an _EX_FAST_REF) is read whole, its fixed part
# and its variable part (_TOKEN.VariableLength) in one read: the user is
# UserAndGroups[0], the integrity level the RID of UserAndGroups
# [IntegrityLevelIndex] (S-1-16-<rid>). Elevation: Default when the logon
# session has no linked one (_SEP_LOGON_SESSION_REFERENCES.BuddyLogonId 0),
# else Limited for the filtered half of a split token, Full for the other.
# The account name is the logon session's AuthorityName\AccountName, used
# only when the session's LogonId is the token's AuthenticationId. Every
# offset comes from the kernel's symbols; only the meaning of a few fixed
# bits is written here (TOKEN flags, group attributes and privilege numbers
# of the Windows SDK headers, each named where it is used). Guards: kernel
# pointers only, at most 1024 groups, a SID of revision 1 with at most 15
# sub-authorities; a token that fails one is counted, never guessed.
# =============================================================

# The C# of this file: namespace blocks only (no using lines; the host's
# using header applies). C# 5.
function Get-DbgEngTokensSource {
    return @'
namespace TimelineDbgEng
{
    // What one process token says (TokenReader.Read). Read: its user was
    // read; Problem says why not (NoToken: no token pointer, as for a process
    // that has ended; Unreadable: not in the dump; Invalid: not the shape of
    // a token)
    public sealed class TokenDetails
    {
        public bool Read;
        public string Problem = "";
        public string UserSid = "";
        public int IntegrityRid = -1;            // the RID of S-1-16-<rid>; -1 when not read
        public string AdminGroup = "";           // Enabled, DenyOnly, Absent; "" when not known
        public long SessionId = -1;
        public ulong LogonId;                    // _TOKEN.AuthenticationId (a LUID)
        public uint Flags;                       // _TOKEN.TokenFlags
        public bool HasPackage;                  // _TOKEN.Package set (an AppContainer)
        public ulong EnabledPrivileges;          // _SEP_TOKEN_PRIVILEGES.Enabled
        public bool LogonSessionRead;            // read, and its LogonId is the token's
        public bool LogonIdMismatch;             // read, but another logon id: not used
        public ulong BuddyLogonId;
        public string AccountName = "";
        public string AuthorityName = "";

        public string Integrity { get { return TokenReader.IntegrityName(IntegrityRid); } }
        public bool AppContainer { get { return (Flags & TokenReader.LowBoxFlag) != 0 || HasPackage; } }
        public bool UIAccess { get { return (Flags & TokenReader.UIAccessFlag) != 0; } }
        // Default (no linked token), Limited (the filtered half of a split
        // token), Full (its elevated half); "" when the logon session was not read
        public string Elevation
        {
            get
            {
                if (!Read || !LogonSessionRead) return "";
                if (BuddyLogonId == 0) return "Default";
                return (Flags & TokenReader.FilteredFlag) != 0 ? "Limited" : "Full";
            }
        }
        // Yes for a Full token, or a Default one whose Administrators group is enabled
        public string Elevated
        {
            get
            {
                string elevation = Elevation;
                if (elevation == "Full") return "Yes";
                if (elevation == "Limited") return "No";
                if (elevation == "Default") return AdminGroup == "Enabled" ? "Yes" : (AdminGroup.Length > 0 ? "No" : "");
                return "";
            }
        }
        // "<Authority>\<Account>" of the logon session ("" when not read)
        public string LogonAccount
        {
            get
            {
                if (!LogonSessionRead || AccountName.Length == 0) return "";
                return AuthorityName.Length > 0 ? AuthorityName + "\\" + AccountName : AccountName;
            }
        }
        public string Privileges { get { return TokenReader.PrivilegeNames(EnabledPrivileges); } }
        // A local, domain or Entra ID account (not a service account)
        public bool IsUserAccount { get { return TokenReader.IsUserAccountSid(UserSid); } }
        // SYSTEM, or System integrity
        public bool IsSystem { get { return Read && (UserSid == "S-1-5-18" || IntegrityRid == TokenReader.SystemRid); } }
    }

    // Reads process tokens at the offsets of a Layout (TokenReader.Fields)
    public sealed class TokenReader
    {
        public static readonly string[] Fields = new string[] {
            "_TOKEN.AuthenticationId", "_TOKEN.Privileges", "_TOKEN.SessionId", "_TOKEN.UserAndGroupCount", "_TOKEN.VariableLength",
            "_TOKEN.UserAndGroups", "_TOKEN.TokenFlags", "_TOKEN.IntegrityLevelIndex", "_TOKEN.LogonSession",
            "_SID_AND_ATTRIBUTES.Sid", "_SID_AND_ATTRIBUTES.Attributes", "_SEP_TOKEN_PRIVILEGES.Enabled",
            "_SEP_LOGON_SESSION_REFERENCES.LogonId", "_SEP_LOGON_SESSION_REFERENCES.BuddyLogonId",
            "_SEP_LOGON_SESSION_REFERENCES.AccountName", "_SEP_LOGON_SESSION_REFERENCES.AuthorityName" };
        public static readonly string[] Sizes = new string[] { "_TOKEN", "_SID_AND_ATTRIBUTES", "_SEP_LOGON_SESSION_REFERENCES" };

        // TokenFlags bits (TOKEN_IS_FILTERED, TOKEN_UIACCESS, TOKEN_LOWBOX of
        // the Windows SDK's ntifs.h; not in the kernel's symbols)
        public const uint FilteredFlag = 0x800;
        public const uint UIAccessFlag = 0x1000;
        public const uint LowBoxFlag = 0x4000;
        // Group attributes (SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY of winnt.h)
        public const uint GroupEnabled = 0x4;
        public const uint GroupDenyOnly = 0x10;
        public const int MaxGroups = 1024;
        public const int MaxSubAuthorities = 15;
        public const int MaxTokenBytes = 0x10000;
        public const int SystemRid = 0x4000;
        public const int MediumRid = 0x2000;
        public const string AdministratorsSid = "S-1-5-32-544";
        // The privileges a row lists when enabled: their numbers (the LUIDs
        // of winnt.h's SE_*_PRIVILEGE values, bit n of Enabled) and names,
        // in the order the rows give them
        static readonly int[] NotableLuids = new int[] { 20, 7, 10, 2, 3, 17, 18, 9 };
        static readonly string[] NotableNames = new string[] {
            "SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege" };

        readonly MemoryReader reader;
        readonly int tokenSize, authenticationId, privileges, privilegesEnabled, sessionId, groupCount, variableLength, groups;
        readonly int tokenFlags, integrityIndex, logonSession, package;
        readonly int entrySize, entrySid, entryAttributes;
        readonly int sessionSize, sessionLogonId, sessionBuddy, sessionAccount, sessionAuthority;
        readonly bool ready;
        public readonly string MissingFields;

        public TokenReader(MemoryReader reader, Layout layout)
        {
            this.reader = reader;
            List<string> missing = new List<string>();
            foreach (string f in Fields) { if (!layout.Has(f)) missing.Add(f); }
            foreach (string s in Sizes) { if (layout.Size(s) <= 0) missing.Add(s); }
            MissingFields = string.Join(", ", missing.ToArray());
            tokenSize = layout.Size("_TOKEN");
            authenticationId = layout.Off("_TOKEN.AuthenticationId");
            privileges = layout.Off("_TOKEN.Privileges");
            privilegesEnabled = layout.Off("_SEP_TOKEN_PRIVILEGES.Enabled");
            sessionId = layout.Off("_TOKEN.SessionId");
            groupCount = layout.Off("_TOKEN.UserAndGroupCount");
            variableLength = layout.Off("_TOKEN.VariableLength");
            groups = layout.Off("_TOKEN.UserAndGroups");
            tokenFlags = layout.Off("_TOKEN.TokenFlags");
            integrityIndex = layout.Off("_TOKEN.IntegrityLevelIndex");
            logonSession = layout.Off("_TOKEN.LogonSession");
            package = layout.Off("_TOKEN.Package");
            entrySize = layout.Size("_SID_AND_ATTRIBUTES");
            entrySid = layout.Off("_SID_AND_ATTRIBUTES.Sid");
            entryAttributes = layout.Off("_SID_AND_ATTRIBUTES.Attributes");
            sessionSize = layout.Size("_SEP_LOGON_SESSION_REFERENCES");
            sessionLogonId = layout.Off("_SEP_LOGON_SESSION_REFERENCES.LogonId");
            sessionBuddy = layout.Off("_SEP_LOGON_SESSION_REFERENCES.BuddyLogonId");
            sessionAccount = layout.Off("_SEP_LOGON_SESSION_REFERENCES.AccountName");
            sessionAuthority = layout.Off("_SEP_LOGON_SESSION_REFERENCES.AuthorityName");
            ready = missing.Count == 0 && tokenSize > 0 && tokenSize <= MaxTokenBytes && entrySize >= 12 && sessionSize > 0;
        }

        public bool Ready { get { return ready; } }

        // The token at its address (EPROCESS.Token with the reference count
        // bits masked off)
        public TokenDetails Read(ulong token)
        {
            TokenDetails d = new TokenDetails();
            if (!ready) { d.Problem = "Invalid"; return d; }
            if (token == 0) { d.Problem = "NoToken"; return d; }
            if (!MemoryReader.IsKernelPointer(token)) { d.Problem = "Invalid"; return d; }
            byte[] head;
            if (!reader.TryRead(0, token, tokenSize, out head)) { d.Problem = "Unreadable"; return d; }
            // The variable part (groups, SIDs) follows: one read for both
            uint variable = Bytes.U32(head, variableLength);
            byte[] whole = head;
            if (variable > 0 && variable <= (uint)(MaxTokenBytes - tokenSize))
            {
                byte[] more = reader.Read(0, token, tokenSize + (int)variable);
                if (more != null && more.Length > head.Length) whole = more;
            }
            TokenBytes bytes = new TokenBytes(reader, token, whole);
            uint count = Bytes.U32(head, groupCount);
            ulong table = Bytes.U64(head, groups);
            if (count == 0 || count > MaxGroups || !MemoryReader.IsKernelPointer(table)) { d.Problem = "Invalid"; return d; }
            byte[] entries = bytes.Read(table, (int)count * entrySize);
            if (entries == null) { d.Problem = "Unreadable"; return d; }
            string user = SidAt(bytes, Bytes.U64(entries, entrySid));
            if (user == null) { d.Problem = "Invalid"; return d; }
            d.Read = true;
            d.UserSid = user;
            d.SessionId = Bytes.U32(head, sessionId);
            d.LogonId = Bytes.U64(head, authenticationId);
            d.Flags = Bytes.U32(head, tokenFlags);
            d.HasPackage = package >= 0 && Bytes.U64(head, package) != 0;
            d.EnabledPrivileges = Bytes.U64(head, privileges + privilegesEnabled);

            // The integrity level, and the Administrators group
            uint index = Bytes.U32(head, integrityIndex);
            bool allGroups = true;
            string admin = "Absent";
            for (uint i = 0; i < count; i++)
            {
                int at = (int)i * entrySize;
                string sid = i == 0 ? user : SidAt(bytes, Bytes.U64(entries, at + entrySid));
                if (sid == null) { allGroups = false; continue; }
                uint attributes = Bytes.U32(entries, at + entryAttributes);
                if (i == index && sid.StartsWith("S-1-16-", StringComparison.Ordinal))
                {
                    uint rid;
                    if (uint.TryParse(sid.Substring(7), NumberStyles.None, CultureInfo.InvariantCulture, out rid) && rid <= 0x10000) d.IntegrityRid = (int)rid;
                }
                if (i > 0 && sid == AdministratorsSid)
                {
                    if ((attributes & GroupDenyOnly) != 0) admin = "DenyOnly";
                    else if ((attributes & GroupEnabled) != 0) admin = "Enabled";
                    else admin = "Disabled";
                }
            }
            d.AdminGroup = (admin == "Absent" && !allGroups) ? "" : admin;

            // The logon session: elevation and the account name
            ulong session = Bytes.U64(head, logonSession);
            byte[] sessionBytes;
            if (MemoryReader.IsKernelPointer(session) && reader.TryRead(0, session, sessionSize, out sessionBytes))
            {
                if (Bytes.U64(sessionBytes, sessionLogonId) != d.LogonId) d.LogonIdMismatch = true;
                else
                {
                    d.LogonSessionRead = true;
                    d.BuddyLogonId = Bytes.U64(sessionBytes, sessionBuddy);
                    d.AccountName = reader.UnicodeString(0, session + (ulong)sessionAccount) ?? "";
                    d.AuthorityName = reader.UnicodeString(0, session + (ulong)sessionAuthority) ?? "";
                }
            }
            return d;
        }

        // A SID at address as text (S-1-5-21-...); null when it cannot be read
        // or is not a SID (revision 1, at most 15 sub-authorities)
        static string SidAt(TokenBytes bytes, ulong address)
        {
            if (!MemoryReader.IsKernelAddress(address) || (address & 3) != 0) return null;
            byte[] head = bytes.Read(address, 8);
            if (head == null || head[0] != 1 || head[1] > MaxSubAuthorities) return null;
            int subCount = head[1];
            byte[] sid = subCount == 0 ? head : bytes.Read(address, 8 + 4 * subCount);
            if (sid == null) return null;
            return SidText(sid);
        }

        // The text of a SID's bytes (revision, count, 6-byte authority, sub-authorities)
        public static string SidText(byte[] sid)
        {
            if (sid == null || sid.Length < 8 || sid[0] != 1 || sid.Length < 8 + 4 * sid[1]) return null;
            ulong authority = 0;
            for (int i = 2; i < 8; i++) authority = (authority << 8) | sid[i];
            StringBuilder text = new StringBuilder("S-1-");
            if (authority < 0x100000000UL) text.Append(authority.ToString(CultureInfo.InvariantCulture));
            else text.Append("0x").Append(authority.ToString("X12", CultureInfo.InvariantCulture));
            for (int i = 0; i < sid[1]; i++) text.Append('-').Append(BitConverter.ToUInt32(sid, 8 + 4 * i).ToString(CultureInfo.InvariantCulture));
            return text.ToString();
        }

        // The integrity level's name (Windows' mandatory label RIDs);
        // another RID as hex, "" for none
        public static string IntegrityName(int rid)
        {
            switch (rid)
            {
                case -1: return "";
                case 0x0000: return "Untrusted";
                case 0x1000: return "Low";
                case 0x2000: return "Medium";
                case 0x2100: return "MediumPlus";
                case 0x3000: return "High";
                case 0x4000: return "System";
                case 0x5000: return "Protected";
                default: return "0x" + rid.ToString("x4", CultureInfo.InvariantCulture);
            }
        }

        // The notable privileges among the enabled ones, comma-separated
        public static string PrivilegeNames(ulong enabled)
        {
            List<string> names = new List<string>();
            for (int i = 0; i < NotableLuids.Length; i++) { if ((enabled & (1UL << NotableLuids[i])) != 0) names.Add(NotableNames[i]); }
            return string.Join(",", names.ToArray());
        }

        // A local, domain or Entra ID account's SID
        public static bool IsUserAccountSid(string sid)
        {
            return sid != null && (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.StartsWith("S-1-12-1-", StringComparison.Ordinal));
        }

        // The protection of a process (EPROCESS.Protection, _PS_PROTECTION:
        // Type in bits 0-2, Signer in bits 4-7; the signer names of
        // ntddk.h's PS_PROTECTED_SIGNER): "PPL-Antimalware", "PP-WinTcb", ...;
        // "" for none
        public static string ProtectionName(byte level)
        {
            int type = level & 7;
            if (type == 0) return "";
            string[] signers = new string[] { "None", "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem", "App" };
            int signer = (level >> 4) & 0xF;
            string prefix = type == 1 ? "PPL-" : (type == 2 ? "PP-" : "Type" + type.ToString(CultureInfo.InvariantCulture) + "-");
            return prefix + (signer < signers.Length ? signers[signer] : "Signer" + signer.ToString(CultureInfo.InvariantCulture));
        }
    }

    // Reads inside a token's bytes when an address is in them, else through
    // the reader (kernel memory)
    public sealed class TokenBytes
    {
        readonly MemoryReader reader;
        readonly ulong start;
        readonly byte[] bytes;
        public TokenBytes(MemoryReader reader, ulong start, byte[] bytes)
        {
            this.reader = reader;
            this.start = start;
            this.bytes = bytes ?? new byte[0];
        }
        // count bytes at address; null when not all can be read
        public byte[] Read(ulong address, int count)
        {
            if (count <= 0) return new byte[0];
            if (address >= start && address - start < (ulong)bytes.Length && (ulong)count <= (ulong)bytes.Length - (address - start))
            {
                byte[] part = new byte[count];
                Buffer.BlockCopy(bytes, (int)(address - start), part, 0, count);
                return part;
            }
            byte[] read;
            return reader.TryRead(0, address, count, out read) ? read : null;
        }
    }

    // The ProcessDetails area: every process's token and paths, the
    // device-to-drive map, the anomalies, one Proc entry per process
    public static class ProcessDetailsArea
    {
        public static void Run(MemoryContext context, Layout layout, AreaResult area, bool tokens, bool paths)
        {
            TokenReader tokenReader = tokens ? new TokenReader(context.Reader, layout) : null;
            ImagePathReader pathReader = paths ? new ImagePathReader(context.Reader, layout) : null;
            int n = context.Processes.Count;
            TokenDetails[] tokenOf = new TokenDetails[n];
            ProcessPaths[] pathsOf = new ProcessPaths[n];
            int done = 0;
            for (int i = 0; i < n; i++)
            {
                if (area.TimeUp()) break;
                ProcessInfo p = context.Processes[i];
                if (tokenReader != null) tokenOf[i] = tokenReader.Read(p.Token);
                if (pathReader != null) pathsOf[i] = pathReader.Read(p);
                done++;
            }
            Coverage c = area.Coverage;
            c.Count("processes", done);

            // Device names to drive letters, from the processes whose PEB path
            // and kernel path agree after the drive or device
            int mapped = 0, conflicts = 0;
            if (pathReader != null)
            {
                List<string> audits = new List<string>();
                List<string> pebs = new List<string>();
                for (int i = 0; i < done; i++) { audits.Add(pathsOf[i].Audit); pebs.Add(pathsOf[i].PebImage); }
                mapped = DriveMapper.Learn(context.DriveMap, audits, pebs, out conflicts);
            }

            int tokensRead = 0, noToken = 0, tokenUnreadable = 0, tokenInvalid = 0, sessionsRead = 0, sessionMismatch = 0;
            int auditRead = 0, auditMissing = 0, recovered = 0, fileAgree = 0, fileDiffer = 0, pebRead = 0, pebMissing = 0, gone = 0;
            int directories = 0, pebDiffers = 0, unmapped = 0;
            int nameChanged = 0, pebMismatch = 0, systemChild = 0;
            for (int i = 0; i < done; i++)
            {
                ProcessInfo p = context.Processes[i];
                TokenDetails t = tokenOf[i];
                ProcessPaths pp = pathsOf[i];
                MemoryEntry e = area.Add("Proc").Set("Offset", Fmt.Hex(p.Eprocess)).Set("Pid", p.Pid);
                List<string> anomalies = new List<string>();

                if (t != null)
                {
                    if (t.Read)
                    {
                        tokensRead++;
                        p.UserSid = t.UserSid;
                        p.Integrity = t.Integrity;
                        p.Elevated = t.Elevated;
                        e.Set("User", t.UserSid);
                        if (t.Integrity.Length > 0) e.Set("Integrity", t.Integrity);
                        if (t.Elevation.Length > 0) e.Set("Elevation", t.Elevation);
                        if (t.Elevated.Length > 0) e.Set("Elevated", t.Elevated);
                        if (t.AdminGroup.Length > 0) e.Set("AdminGroup", t.AdminGroup);
                        e.Set("TokenSession", t.SessionId);
                        e.SetHex("LogonId", t.LogonId);
                        if (t.AppContainer) e.Set("AppContainer", "Yes");
                        if (t.UIAccess) e.Set("UIAccess", "Yes");
                        if (t.LogonSessionRead) sessionsRead++;
                        if (t.LogonIdMismatch) sessionMismatch++;
                    }
                    else if (t.Problem == "NoToken") noToken++;
                    else if (t.Problem == "Unreadable") tokenUnreadable++;
                    else tokenInvalid++;
                }
                string protection = TokenReader.ProtectionName(p.Protection);
                if (protection.Length > 0) e.Set("Protection", protection);
                if (t != null && t.Read)
                {
                    if (t.Privileges.Length > 0) e.Set("Privileges", t.Privileges);
                    if (t.LogonAccount.Length > 0) e.Set("LogonAccount", t.LogonAccount);
                }

                if (pp != null)
                {
                    bool minimal = pathReader.IsMinimal(p);
                    string auditLeaf = ImagePathReader.IsPath(pp.Audit) ? ImagePathReader.Leaf(pp.Audit) : null;
                    if (auditLeaf != null) auditRead++;
                    else if (!minimal && p.Pid != 4) auditMissing++;
                    if (pp.FileObject != null && auditLeaf != null)
                    {
                        if (pp.Audit.EndsWith(pp.FileObject, StringComparison.OrdinalIgnoreCase)) fileAgree++; else fileDiffer++;
                    }
                    // The full name: the kernel's file name when the short
                    // name (EPROCESS.ImageFileName) starts it
                    string leaf = auditLeaf;
                    if (leaf == null && ImagePathReader.IsPath(pp.FileObject)) leaf = ImagePathReader.Leaf(pp.FileObject);
                    bool asciiNames = leaf != null && ImagePathReader.IsAscii(p.ShortName) && p.ShortName.Length > 0 && ImagePathReader.IsAscii(leaf);
                    if (asciiNames && leaf.StartsWith(p.ShortName, StringComparison.OrdinalIgnoreCase))
                    {
                        p.FullName = leaf;
                        e.Set("FullName", leaf);
                        if (leaf.Length > p.ShortName.Length) recovered++;
                    }
                    // A name changed in memory: the short name does not start
                    // the kernel's own record of the file (ASCII names only,
                    // not System or the minimal processes)
                    if (auditLeaf != null && !minimal && p.Pid != 4 && ImagePathReader.IsAscii(p.ShortName) && p.ShortName.Length > 0 && ImagePathReader.IsAscii(auditLeaf) &&
                        !auditLeaf.StartsWith(p.ShortName, StringComparison.OrdinalIgnoreCase))
                    {
                        anomalies.Add("ImageNameChanged");
                        nameChanged++;
                    }
                    string imagePath = "";
                    if (ImagePathReader.IsPath(pp.Audit))
                    {
                        imagePath = DriveMapper.Map(context.DriveMap, pp.Audit);
                        if (imagePath.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase)) unmapped++;
                        p.ImagePath = imagePath;
                        e.Set("ImagePath", imagePath);
                    }
                    if (pp.CurrentDirectory != null && pp.CurrentDirectory.Length > 0) { e.Set("CurrentDirectory", pp.CurrentDirectory); directories++; }
                    if (pp.AddressSpaceGone) gone++;
                    if (pp.PebImage != null && pp.PebImage.Length > 0)
                    {
                        pebRead++;
                        if (!string.Equals(ImagePathReader.StripPrefix(pp.PebImage), imagePath, StringComparison.OrdinalIgnoreCase))
                        {
                            e.Set("PebImagePath", pp.PebImage);
                            pebDiffers++;
                        }
                        // The file name the process reports about itself is
                        // another than the kernel's (a folder that differs is
                        // never one: junctions; 8.3 names are not judged)
                        string pebLeaf = ImagePathReader.Leaf(ImagePathReader.StripPrefix(pp.PebImage));
                        if (auditLeaf != null && pebLeaf.Length > 0 && !ImagePathReader.IsShortName(pebLeaf) && !ImagePathReader.IsShortName(auditLeaf) &&
                            !string.Equals(pebLeaf, auditLeaf, StringComparison.OrdinalIgnoreCase))
                        {
                            anomalies.Add("PebImageNameMismatch");
                            pebMismatch++;
                        }
                    }
                    else if (p.Peb != 0 && !minimal) pebMissing++;
                }

                // A SYSTEM process started by a standard user's process: its
                // parent (by PPID) is in the dump, was created before it (not
                // a process that reused the ID) and had not ended then, and
                // runs as a user account at Medium integrity or lower
                if (t != null && t.IsSystem && p.CreateTime > 0 && p.Ppid != p.Pid)
                {
                    int parent = ParentOf(context, p, done);
                    if (parent >= 0)
                    {
                        TokenDetails pt = tokenOf[parent];
                        if (pt != null && pt.Read && pt.IsUserAccount && pt.IntegrityRid >= 0 && pt.IntegrityRid <= TokenReader.MediumRid)
                        {
                            anomalies.Add("SystemChildOfUser");
                            systemChild++;
                        }
                    }
                }
                if (anomalies.Count > 0) e.Set("Anomaly", string.Join(",", anomalies.ToArray()));
            }

            if (tokenReader != null)
            {
                c.Count("tokens read", tokensRead);
                c.Count("logon sessions read", sessionsRead);
                if (noToken > 0) c.Count("without a token", noToken);
                if (tokenUnreadable > 0) c.Count("tokens not in the dump", tokenUnreadable);
                if (tokenInvalid > 0) c.Count("tokens not readable as such", tokenInvalid);
                if (sessionMismatch > 0) c.Count("logon sessions of another logon id", sessionMismatch);
                int missingTokens = noToken + tokenUnreadable + tokenInvalid;
                if (missingTokens > 0) c.Note("the token of " + Plural(missingTokens, "process", "processes") + " could not be read, as when a process has ended");
            }
            if (pathReader != null)
            {
                c.Count("kernel paths read", auditRead);
                c.Count("full names longer than the short name", recovered);
                c.Count("file objects agreeing", fileAgree);
                if (fileDiffer > 0) c.Count("file objects differing", fileDiffer);
                c.Count("PEB paths read", pebRead);
                c.Count("PEB paths shown as differing", pebDiffers);
                c.Count("current folders read", directories);
                c.Count("devices mapped to drive letters", mapped);
                if (conflicts > 0) c.Count("devices with conflicting drive letters", conflicts);
                if (gone > 0) c.Count("address spaces not readable", gone);
                if (auditMissing > 0) c.Note("the kernel's program path of " + Plural(auditMissing, "process", "processes") + " could not be read");
                if (pebMissing > 0) c.Note("the PEB of " + Plural(pebMissing, "process", "processes") + " could not be read, as when a process has ended or its memory was paged out");
                if (unmapped > 0) c.Note(Plural(unmapped, "program path keeps its", "program paths keep their") + " volume's device name, no drive letter was learned for the volume");
            }
            c.Count("ImageNameChanged", nameChanged);
            c.Count("PebImageNameMismatch", pebMismatch);
            c.Count("SystemChildOfUser", systemChild);
        }

        // The parent of p by its PPID: the process with that PID created
        // before p and not ended before p was created (the latest such);
        // -1 when there is none among the first done processes
        static int ParentOf(MemoryContext context, ProcessInfo p, int done)
        {
            int best = -1;
            long bestTime = 0;
            for (int j = 0; j < done; j++)
            {
                ProcessInfo q = context.Processes[j];
                if (q == p || q.Pid != p.Ppid || q.CreateTime <= 0 || q.CreateTime >= p.CreateTime) continue;
                if (q.ExitTime > 0 && q.ExitTime < p.CreateTime) continue;
                if (best < 0 || q.CreateTime > bestTime) { best = j; bestTime = q.CreateTime; }
            }
            return best;
        }

        static string Plural(int count, string one, string many)
        {
            return count.ToString(CultureInfo.InvariantCulture) + " " + (count == 1 ? one : many);
        }
    }
}
'@
}

# The token's fields the area needs, for New-DbgEngLayout (_TOKEN.Package is
# optional: without it, an AppContainer is known by its LowBox flag only)
function Get-DbgEngTokensLayoutSpec {
    return @{
        "_TOKEN"                        = @{
            AuthenticationId = '^struct _LUID\b'; Privileges = '^struct _SEP_TOKEN_PRIVILEGES\b'; SessionId = '^Uint4B$'; UserAndGroupCount = '^Uint4B$'
            VariableLength = '^Uint4B$'; UserAndGroups = '^Ptr64 to struct _SID_AND_ATTRIBUTES\b'; TokenFlags = '^Uint4B$'; IntegrityLevelIndex = '^Uint4B$'
            LogonSession = '^Ptr64 to struct _SEP_LOGON_SESSION_REFERENCES\b'; Package = '^Ptr64\b'
        }
        "_SID_AND_ATTRIBUTES"           = @{ Sid = '^Ptr64\b'; Attributes = '^Uint4B$' }
        "_SEP_TOKEN_PRIVILEGES"         = @{ Enabled = '^Uint8B$' }
        "_SEP_LOGON_SESSION_REFERENCES" = @{ LogonId = '^struct _LUID\b'; BuddyLogonId = '^struct _LUID\b'; AccountName = '^struct _UNICODE_STRING\b'; AuthorityName = '^struct _UNICODE_STRING\b' }
    }
}

# The ProcessDetails area: each process's token (this file) and paths
# (TimelineDbgEng.ImagePaths.ps1). Without the token's fields in the
# kernel's symbols the paths are still read (and the other way round): the
# area is then partly read, and says which fields were missing.
function Invoke-DbgEngProcessDetailsArea {
    param($Context, $Area)
    $spec = @{}
    foreach ($part in @((Get-DbgEngTokensLayoutSpec), (Get-DbgEngImagePathsLayoutSpec))) {
        foreach ($typeName in @($part.Keys)) {
            if (-not $spec.ContainsKey($typeName)) { $spec[$typeName] = @{} }
            foreach ($fieldName in @($part[$typeName].Keys)) { $spec[$typeName][$fieldName] = $part[$typeName][$fieldName] }
        }
    }
    $layout = New-DbgEngLayout -Session $Context.Session -Spec $spec
    $tokenReader = New-Object TimelineDbgEng.TokenReader -ArgumentList $Context.Reader, $layout
    $pathMissing = [TimelineDbgEng.ImagePathReader]::MissingOf($layout)
    # The types whose fields are missing ("_TOKEN.Privileges" -> _TOKEN), for a short reason
    $typesOf = { param([string]$Missing) (@($Missing -split ',\s*' | Where-Object { $_ } | ForEach-Object { ($_ -split '\.')[0] } | Select-Object -Unique) -join ", ") }
    if (-not $tokenReader.Ready -and $pathMissing) {
        $Area.SetNotRead("the kernel's symbols do not describe $(& $typesOf "$($tokenReader.MissingFields), $pathMissing") as expected")
        return
    }
    [TimelineDbgEng.ProcessDetailsArea]::Run($Context, $layout, $Area, $tokenReader.Ready, (-not $pathMissing))
    if (-not $tokenReader.Ready) { $Area.SetPartial("the users of the processes were not read, the kernel's symbols do not describe $(& $typesOf $tokenReader.MissingFields) as expected") }
    if ($pathMissing) { $Area.SetPartial("the program paths were not read, the kernel's symbols do not describe $(& $typesOf $pathMissing) as expected") }
}
