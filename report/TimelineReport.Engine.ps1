# =============================================================
# Timeline report: rules engine and report model (Phase 3)
# Dot-sourced by timeline-builder.ps1. Dot-source it at script level
# (not inside a function), so its functions and the compiled helper
# stay available. Defines:
#   Import-ReportRules           report-rules.json -> imported rules
#   Invoke-ReportRules           timeline rows + rules -> findings
#   New-ReportModel              rows + findings -> the report model
#   Export-ReportModelJson       report model -> report-model.json
#   Export-ReportFindingsCsv     findings -> findings.csv
#   Import-TimelineCsvForReport  timeline.csv -> rows (for -ReportOnly)
#   Get-ReportFindingRowMap      findings -> Excel row -> finding ids
#
# Keyword lists (tool names, folders) live ONLY in the rules JSON.
# Never put them in this file: Defender's AMSI blocks PowerShell
# code that holds attacker-tool names. The lists are read and expanded
# in the C# helper (RulePattern), never passed to a PowerShell method
# call: PowerShell 7 hands those arguments to AMSI too.
#
# Runs in Windows PowerShell 5.1 and PowerShell 7. The helper below
# does the per-row work (matching, grouping, statistics, CSV and
# JSON) in C# 5, the language Windows PowerShell's compiler accepts:
# a PowerShell loop over 300,000 rows per rule would take minutes.
# =============================================================

if (-not ([System.Management.Automation.PSTypeName]'TimelineReport.Engine').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;

namespace TimelineReport
{
    // One match object of a rule ("match", an "anyOf" entry, "escalate.match"
    // or an allowlist entry). A null regex is a condition that is not set.
    public sealed class MatchSpec
    {
        public Regex Source;
        public Regex EventType;
        public Regex Description;
        public Regex Details;
        public Regex User;
        public Regex NotSource;
        public Regex NotEventType;
        public Regex NotDescription;
        public Regex NotDetails;
        public Regex NotUser;
        // 0 = any row, 1 = only rows at or after the collection start,
        // 2 = only rows before it ("duringCollection": true / false)
        public int During;
    }

    // How rows are grouped (groupBy) or compared (escalate.sameKey). Kind is
    // rule, description, user, source, eventtype, detail, capture or none.
    public sealed class KeySpec
    {
        public string Kind;
        public string[] DetailKeys;
    }

    public sealed class CompiledRule
    {
        public string Id;
        public MatchSpec Match;
        public MatchSpec[] AnyOf;
        public KeySpec GroupBy;
        public int ThresholdCount;
        public long ThresholdWindowTicks;
        public MatchSpec EscalateMatch;
        public long EscalateWindowTicks;
        public KeySpec EscalateKey;
        public MatchSpec[] Allowlist;
    }

    // One group of a rule (one finding). Row values are 0-based indexes into
    // the row list (Excel row = index + 2).
    public sealed class GroupResult
    {
        public string Key;
        public List<int> Rows = new List<int>();
        public List<int> EscalationRows = new List<int>();
        public int Allowlisted;
        public int[] AllRows;
        public int[] RowNumbers;
        public int[] EvidenceRows;
        public long FirstTicks = -1;
        public long LastTicks = -1;
        // Every row is a Snapshot row (state when the evidence was collected or
        // a memory dump captured): its time is when it was seen, not an event
        public bool SnapshotOnly;
        // Every row comes from the memory dump (a Memory-* source)
        public bool MemoryOnly;
        // The only times are dates a task's author wrote (Engine.Summarize)
        public bool AuthorTimesOnly;
        // A roll-up group (Engine.Fold): how many groups it stands for, and their keys
        public int FoldedGroups;
        public List<string> FoldedKeys = new List<string>();
    }

    public sealed class RuleResult
    {
        public string RuleId;
        public int MatchedRows;
        public int AllowlistedRows;
        public int[] AllowlistedPerEntry;
        public List<GroupResult> Groups = new List<GroupResult>();
        public int RegexTimeouts;
        public double Milliseconds;
        // Set when the rule was stopped (repeated regex timeouts or its time
        // budget): Groups is then empty and Abandoned says why
        public string Abandoned;
    }

    // The timeline rows as column arrays, built once per row list: the rules
    // then read plain strings instead of PowerShell object properties.
    // Source, EventType and User are stored as ids into their distinct values,
    // so a condition on them is tested once per distinct value.
    public sealed class RowTable
    {
        public int Count;
        public object[] Rows;
        public string[] Timestamp;
        public string[] Description;
        public string[] Details;
        public long[] Ticks;
        public int[] SourceId;
        public int[] EventTypeId;
        public int[] UserId;
        public string[] Sources;
        public string[] EventTypes;
        public string[] Users;

        static readonly string[] Columns = new string[] { "Timestamp", "Source", "EventType", "Description", "User", "Details" };

        public static RowTable Build(IList rows)
        {
            int n = rows == null ? 0 : rows.Count;
            RowTable t = new RowTable();
            t.Count = n;
            t.Rows = new object[n];
            t.Timestamp = new string[n];
            t.Description = new string[n];
            t.Details = new string[n];
            t.Ticks = new long[n];
            t.SourceId = new int[n];
            t.EventTypeId = new int[n];
            t.UserId = new int[n];
            Dictionary<string, int> sourceIds = new Dictionary<string, int>(StringComparer.Ordinal);
            Dictionary<string, int> typeIds = new Dictionary<string, int>(StringComparer.Ordinal);
            Dictionary<string, int> userIds = new Dictionary<string, int>(StringComparer.Ordinal);
            List<string> sources = new List<string>();
            List<string> types = new List<string>();
            List<string> users = new List<string>();
            string[] values = new string[Columns.Length];
            for (int i = 0; i < n; i++)
            {
                object row = rows[i];
                t.Rows[i] = row;
                ReadRow(row, values);
                t.Timestamp[i] = values[0];
                t.Ticks[i] = ParseTicks(values[0]);
                t.SourceId[i] = Intern(values[1], sourceIds, sources);
                t.EventTypeId[i] = Intern(values[2], typeIds, types);
                t.Description[i] = values[3];
                t.UserId[i] = Intern(values[4], userIds, users);
                t.Details[i] = values[5];
            }
            t.Sources = sources.ToArray();
            t.EventTypes = types.ToArray();
            t.Users = users.ToArray();
            return t;
        }

        static int Intern(string value, Dictionary<string, int> ids, List<string> list)
        {
            int id;
            if (ids.TryGetValue(value, out id)) return id;
            id = list.Count;
            ids[value] = id;
            list.Add(value);
            return id;
        }

        static void ReadRow(object row, string[] values)
        {
            for (int c = 0; c < values.Length; c++) values[c] = "";
            if (row == null) return;
            PSObject pso = row as PSObject;
            object baseObject = pso != null ? pso.BaseObject : row;
            IDictionary dict = baseObject as IDictionary;
            if (dict != null)
            {
                for (int c = 0; c < Columns.Length; c++) values[c] = Text(dict[Columns[c]]);
                return;
            }
            if (pso == null) pso = PSObject.AsPSObject(row);
            for (int c = 0; c < Columns.Length; c++)
            {
                PSPropertyInfo p = pso.Properties[Columns[c]];
                if (p != null) values[c] = Text(p.Value);
            }
        }

        // Text of one field of a row object (PSObject, hashtable or .NET object)
        public static string FieldText(object row, string name)
        {
            if (row == null) return "";
            PSObject pso = row as PSObject;
            object baseObject = pso != null ? pso.BaseObject : row;
            IDictionary dict = baseObject as IDictionary;
            if (dict != null) return Text(dict[name]);
            if (pso == null) pso = PSObject.AsPSObject(row);
            PSPropertyInfo p = pso.Properties[name];
            return p == null ? "" : Text(p.Value);
        }

        internal static string Text(object value)
        {
            if (value == null) return "";
            PSObject pso = value as PSObject;
            if (pso != null) value = pso.BaseObject;
            string s = value as string;
            if (s != null) return s;
            if (value is DateTime)
            {
                DateTime d = (DateTime)value;
                if (d.Kind == DateTimeKind.Local) d = d.ToUniversalTime();
                return d.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
            }
            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        // "yyyy-MM-dd HH:mm:ss.fff" (UTC, the timeline format) -> UTC ticks;
        // other text is tried as invariant UTC; -1 when it cannot be read
        public static long ParseTicks(string s)
        {
            if (string.IsNullOrEmpty(s)) return -1;
            if (s.Length >= 19 && s[4] == '-' && s[7] == '-' && (s[10] == ' ' || s[10] == 'T') && s[13] == ':' && s[16] == ':')
            {
                int y, mo, d, h, mi, se;
                int ms = 0;
                if (Digits(s, 0, 4, out y) && Digits(s, 5, 2, out mo) && Digits(s, 8, 2, out d) &&
                    Digits(s, 11, 2, out h) && Digits(s, 14, 2, out mi) && Digits(s, 17, 2, out se))
                {
                    bool plain = s.Length == 19;
                    if (s.Length == 23 && s[19] == '.' && Digits(s, 20, 3, out ms)) plain = true;
                    if (plain && y >= 1 && mo >= 1 && mo <= 12 && d >= 1 && d <= DateTime.DaysInMonth(y, mo) && h < 24 && mi < 60 && se < 60)
                    {
                        return new DateTime(y, mo, d, h, mi, se, ms, DateTimeKind.Utc).Ticks;
                    }
                }
            }
            DateTime parsed;
            if (DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed))
            {
                return parsed.Ticks;
            }
            return -1;
        }

        static bool Digits(string s, int start, int length, out int value)
        {
            value = 0;
            for (int i = start; i < start + length; i++)
            {
                char c = s[i];
                if (c < '0' || c > '9') return false;
                value = value * 10 + (c - '0');
            }
            return true;
        }
    }

    // Reads Key=Value pairs from the Details column. Newer rows separate the
    // pairs with " | " ("Key=Value | Key2=Value2"); older rows use spaces
    // ("LogonType=5 Source=-:-"). Two steps of the builder append a pair
    // with " | " to any row: de-duplication " | Occurrences=N", and the User
    // column pass " | UserSID=<sid>" (a SID User that got a name). These
    // appended pairs do not count for the style: in a row with two or more
    // other " | " pairs a value runs to the next " | Key="; otherwise a value
    // runs to the next " Key=" (a key there starts with a capital letter and
    // has 3+ characters, so values like "CN=x, O=y" stay whole).
    public static class DetailParser
    {
        static readonly Regex PipeSplit = new Regex(@"\s\|\s(?=[A-Za-z][\w.]*(?:\([^()=|]*\))?=)", RegexOptions.CultureInvariant);
        static readonly Regex FirstKey = new Regex(@"^([A-Za-z][\w.]*(?:\([^()=]*\))?)=", RegexOptions.CultureInvariant);
        static readonly Regex SpaceKey = new Regex(@"(?<=\s)([A-Z][A-Za-z0-9.]{2,}(?:\([^()=]*\))?)=", RegexOptions.CultureInvariant);

        public static List<KeyValuePair<string, string>> Parse(string text)
        {
            List<KeyValuePair<string, string>> pairs = new List<KeyValuePair<string, string>>();
            if (string.IsNullOrEmpty(text)) return pairs;
            string[] segments = PipeSplit.Split(text);
            string[] keys = new string[segments.Length];
            int keyed = 0;
            for (int s = 0; s < segments.Length; s++)
            {
                Match m = FirstKey.Match(segments[s]);
                keys[s] = m.Success ? m.Groups[1].Value : null;
                if (keys[s] != null && !IsAppendedKey(keys[s])) keyed++;
            }
            bool pipeStyle = keyed >= 2;
            for (int s = 0; s < segments.Length; s++)
            {
                string segment = segments[s];
                string key = keys[s];
                if (key != null && (pipeStyle || IsAppendedKey(key)))
                {
                    pairs.Add(new KeyValuePair<string, string>(key, Clean(segment.Substring(key.Length + 1))));
                    continue;
                }
                // Space-separated pairs: each value runs to the next key
                int valueStart = 0;
                string current = null;
                if (key != null)
                {
                    current = key;
                    valueStart = key.Length + 1;
                }
                foreach (Match k in SpaceKey.Matches(segment, valueStart))
                {
                    if (current != null)
                    {
                        pairs.Add(new KeyValuePair<string, string>(current, Clean(segment.Substring(valueStart, k.Index - valueStart))));
                    }
                    current = k.Groups[1].Value;
                    valueStart = k.Index + k.Length;
                }
                if (current != null) pairs.Add(new KeyValuePair<string, string>(current, Clean(segment.Substring(valueStart))));
            }
            return pairs;
        }

        // Value of the first pair with this key (case-insensitive), or ""
        public static string Get(string text, string key)
        {
            if (string.IsNullOrEmpty(text) || text.IndexOf(key, StringComparison.OrdinalIgnoreCase) < 0) return "";
            foreach (KeyValuePair<string, string> pair in Parse(text))
            {
                if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase)) return pair.Value;
            }
            return "";
        }

        // A pair the builder appends to any row (see above)
        static bool IsAppendedKey(string key)
        {
            return string.Equals(key, "Occurrences", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(key, "UserSID", StringComparison.OrdinalIgnoreCase);
        }

        static string Clean(string value)
        {
            return value.Trim().TrimEnd(';').Trim();
        }
    }

    // Rule patterns of the rules file: {{list:<name>}} is expanded to
    // (?:escaped1|escaped2|...) and the regex compiled here, in C#, never
    // in PowerShell. The lists hold attacker-tool names and AMSI-bypass
    // strings, and PowerShell 7 hands the string arguments of every .NET
    // method call to AMSI: a call with an expanded list as its argument can
    // be blocked (antivirus), so the lists stay out of PowerShell's view.
    // Fails closed: an unknown or empty list, an expansion that comes out
    // empty, or an invalid regex throws ArgumentException with the problem
    // (the caller names the file, rule and field); there is never a regex
    // that matches every row in place of the intended one.
    public static class RulePattern
    {
        static readonly Regex ListReference = new Regex(@"\{\{list:([^{}]*)\}\}", RegexOptions.CultureInvariant);

        // The values of a list from the JSON (an array of non-empty
        // strings), or null when it is anything else or empty
        public static string[] ReadList(object value)
        {
            PSObject pso = value as PSObject;
            if (pso != null) value = pso.BaseObject;
            if (value == null || value is string) return null;
            IEnumerable items = value as IEnumerable;
            if (items == null) return null;
            List<string> list = new List<string>();
            foreach (object item in items)
            {
                object v = item;
                PSObject p = v as PSObject;
                if (p != null) v = p.BaseObject;
                string s = v as string;
                if (string.IsNullOrEmpty(s)) return null;
                list.Add(s);
            }
            return list.Count == 0 ? null : list.ToArray();
        }

        // The compiled regex of a pattern; lists maps a list name to its
        // values (string[], from ReadList)
        public static Regex Compile(string pattern, IDictionary lists, RegexOptions options, TimeSpan timeout)
        {
            if (string.IsNullOrEmpty(pattern)) throw new ArgumentException("is empty (an empty pattern matches every row)");
            StringBuilder text = new StringBuilder(pattern.Length + 256);
            int position = 0;
            foreach (Match m in ListReference.Matches(pattern))
            {
                text.Append(pattern, position, m.Index - position);
                string name = m.Groups[1].Value;
                object raw = (lists != null && lists.Contains(name)) ? lists[name] : null;
                if (raw == null) throw new ArgumentException("refers to an unknown list '" + name + "' (define it under \"lists\")");
                PSObject pso = raw as PSObject;
                if (pso != null) raw = pso.BaseObject;
                string[] values = raw as string[];
                if (values == null || values.Length == 0) throw new ArgumentException("list '" + name + "' has no values (it must be a non-empty array of strings)");
                text.Append("(?:");
                for (int v = 0; v < values.Length; v++)
                {
                    if (string.IsNullOrEmpty(values[v])) throw new ArgumentException("list '" + name + "' has an empty value");
                    if (v > 0) text.Append('|');
                    text.Append(Regex.Escape(values[v]));
                }
                text.Append(')');
                position = m.Index + m.Length;
            }
            text.Append(pattern, position, pattern.Length - position);
            if (text.Length == 0) throw new ArgumentException("is empty after its lists are expanded (it would match every row)");
            try
            {
                return new Regex(text.ToString(), options, timeout);
            }
            catch (ArgumentException e)
            {
                throw new ArgumentException("invalid regular expression: " + e.Message);
            }
        }

        // True for a missing regex or one with an empty pattern (it would
        // match every row)
        public static bool IsEmpty(Regex re)
        {
            return re == null || re.ToString().Length == 0;
        }
    }

    public static class Engine
    {
        // A rule is stopped after this many regex match timeouts (each match is
        // limited by the regex's own timeout), or when it has run this long: a
        // backtracking pattern in a custom rules file would otherwise cost the
        // timeout on every row
        public static int MaxRegexTimeouts = 3;
        public static long RuleBudgetMilliseconds = 120000;

        // A match object with its Source / EventType / User conditions already
        // tested against every distinct value of the row table
        sealed class Prepared
        {
            public MatchSpec Spec;
            public bool[] SourceOk;
            public bool[] EventTypeOk;
            public bool[] UserOk;
        }

        static bool Test(Regex re, string text, bool onTimeout, int[] timeouts)
        {
            try
            {
                return re.IsMatch(text == null ? "" : text);
            }
            catch (RegexMatchTimeoutException)
            {
                timeouts[0]++;
                return onTimeout;
            }
        }

        static bool[] Flags(string[] values, Regex include, Regex exclude, int[] timeouts)
        {
            bool[] ok = new bool[values.Length];
            for (int v = 0; v < values.Length; v++)
            {
                ok[v] = (include == null || Test(include, values[v], false, timeouts)) &&
                        (exclude == null || !Test(exclude, values[v], true, timeouts));
            }
            return ok;
        }

        static Prepared Prepare(RowTable t, MatchSpec spec, int[] timeouts)
        {
            Prepared p = new Prepared();
            p.Spec = spec;
            p.SourceOk = Flags(t.Sources, spec.Source, spec.NotSource, timeouts);
            p.EventTypeOk = Flags(t.EventTypes, spec.EventType, spec.NotEventType, timeouts);
            p.UserOk = Flags(t.Users, spec.User, spec.NotUser, timeouts);
            return p;
        }

        static Prepared[] PrepareAll(RowTable t, MatchSpec[] specs, int[] timeouts)
        {
            if (specs == null) return new Prepared[0];
            Prepared[] prepared = new Prepared[specs.Length];
            for (int i = 0; i < specs.Length; i++) prepared[i] = Prepare(t, specs[i], timeouts);
            return prepared;
        }

        // A regex timeout counts as "not matched" for a condition and as
        // "matched" for a not* condition: either way the row is not flagged
        static bool IsMatch(RowTable t, Prepared p, int i, long start, int[] timeouts)
        {
            if (!p.SourceOk[t.SourceId[i]] || !p.EventTypeOk[t.EventTypeId[i]] || !p.UserOk[t.UserId[i]]) return false;
            MatchSpec s = p.Spec;
            if (s.During == 1 && (start < 0 || t.Ticks[i] < start)) return false;
            if (s.During == 2 && start >= 0 && t.Ticks[i] >= start) return false;
            if (s.Description != null && !Test(s.Description, t.Description[i], false, timeouts)) return false;
            if (s.NotDescription != null && Test(s.NotDescription, t.Description[i], true, timeouts)) return false;
            if (s.Details != null && !Test(s.Details, t.Details[i], false, timeouts)) return false;
            if (s.NotDetails != null && Test(s.NotDetails, t.Details[i], true, timeouts)) return false;
            return true;
        }

        static int FirstMatch(RowTable t, Prepared[] list, int i, long start, int[] timeouts)
        {
            for (int a = 0; a < list.Length; a++)
            {
                if (IsMatch(t, list[a], i, start, timeouts)) return a;
            }
            return -1;
        }

        // Indexes of the rows that match one match object
        public static int[] FindRows(RowTable t, MatchSpec spec, long collectionStartTicks)
        {
            int[] timeouts = new int[1];
            Prepared p = Prepare(t, spec, timeouts);
            List<int> found = new List<int>();
            for (int i = 0; i < t.Count; i++)
            {
                if (IsMatch(t, p, i, collectionStartTicks, timeouts)) found.Add(i);
            }
            return found.ToArray();
        }

        static string Capture(Regex re, string text, int[] timeouts)
        {
            if (re == null) return "";
            try
            {
                Match m = re.Match(text == null ? "" : text);
                if (!m.Success) return "";
                Group named = m.Groups["key"];
                if (named.Success) return named.Value;
                if (m.Groups.Count > 1 && m.Groups[1].Success) return m.Groups[1].Value;
                return m.Value;
            }
            catch (RegexMatchTimeoutException)
            {
                timeouts[0]++;
                return "";
            }
        }

        // Group (or sameKey) value of a row
        public static string GetKey(RowTable t, int i, KeySpec key, MatchSpec captureFrom, int[] timeouts)
        {
            if (key == null) return "";
            switch (key.Kind)
            {
                case "description": return t.Description[i];
                case "user": return t.Users[t.UserId[i]];
                case "source": return t.Sources[t.SourceId[i]];
                case "eventtype": return t.EventTypes[t.EventTypeId[i]];
                case "detail":
                    for (int d = 0; d < key.DetailKeys.Length; d++)
                    {
                        string value = DetailParser.Get(t.Details[i], key.DetailKeys[d]);
                        if (value.Length > 0) return value;
                    }
                    return "";
                case "capture":
                    if (captureFrom == null) return "";
                    if (captureFrom.Description != null) return Capture(captureFrom.Description, t.Description[i], timeouts);
                    return Capture(captureFrom.Details, t.Details[i], timeouts);
                default:
                    return "";
            }
        }

        // Rows of one group that fall in a window of windowTicks holding at
        // least count rows (sorted by time, then row)
        static List<int> ApplyThreshold(RowTable t, List<int> rows, int count, long windowTicks)
        {
            List<int> timed = new List<int>();
            foreach (int r in rows)
            {
                if (t.Ticks[r] >= 0) timed.Add(r);
            }
            long[] ticks = t.Ticks;
            timed.Sort(delegate(int a, int b)
            {
                int c = ticks[a].CompareTo(ticks[b]);
                return c != 0 ? c : a.CompareTo(b);
            });
            bool[] keep = new bool[timed.Count];
            int left = 0;
            int markedUntil = -1;
            for (int right = 0; right < timed.Count; right++)
            {
                long tr = ticks[timed[right]];
                while (tr - ticks[timed[left]] > windowTicks) left++;
                if (right - left + 1 >= count)
                {
                    for (int k = Math.Max(left, markedUntil + 1); k <= right; k++) keep[k] = true;
                    markedUntil = right;
                }
            }
            List<int> kept = new List<int>();
            for (int k = 0; k < timed.Count; k++)
            {
                if (keep[k]) kept.Add(timed[k]);
            }
            kept.Sort();
            return kept;
        }

        // Why the rule must stop now (too many regex timeouts, or out of time),
        // or null to go on
        static string StopReason(int[] timeouts, Stopwatch watch)
        {
            if (timeouts[0] >= MaxRegexTimeouts)
            {
                return "its patterns timed out " + timeouts[0].ToString(CultureInfo.InvariantCulture) + " times (each match is limited, so a pattern that backtracks badly would cost that limit on every row)";
            }
            if (RuleBudgetMilliseconds > 0 && watch.ElapsedMilliseconds > RuleBudgetMilliseconds)
            {
                return "it ran longer than " + (RuleBudgetMilliseconds / 1000).ToString(CultureInfo.InvariantCulture) + " seconds";
            }
            return null;
        }

        static RuleResult Abandon(RuleResult result, string reason, int[] timeouts, Stopwatch watch)
        {
            result.Abandoned = reason;
            result.Groups.Clear();
            result.RegexTimeouts = timeouts[0];
            result.Milliseconds = watch.Elapsed.TotalMilliseconds;
            return result;
        }

        // Evaluates one rule over all rows: base match AND (any anyOf), minus
        // allowlisted rows, grouped, thresholded, then escalated. A rule that
        // keeps timing out or runs out of time is stopped (Abandoned).
        public static RuleResult Evaluate(RowTable t, CompiledRule rule, long collectionStartTicks)
        {
            Stopwatch watch = Stopwatch.StartNew();
            RuleResult result = new RuleResult();
            result.RuleId = rule.Id;
            int[] timeouts = new int[1];
            Prepared baseMatch = Prepare(t, rule.Match, timeouts);
            Prepared[] anyOf = PrepareAll(t, rule.AnyOf, timeouts);
            Prepared[] allow = PrepareAll(t, rule.Allowlist, timeouts);
            result.AllowlistedPerEntry = new int[allow.Length];
            string stop = StopReason(timeouts, watch);
            if (stop != null) return Abandon(result, stop, timeouts, watch);

            Dictionary<string, GroupResult> groups = new Dictionary<string, GroupResult>(StringComparer.OrdinalIgnoreCase);
            List<GroupResult> order = new List<GroupResult>();
            Dictionary<string, int> allowlistedByKey = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            long start = collectionStartTicks;
            int seenTimeouts = 0;
            for (int i = 0; i < t.Count; i++)
            {
                if (timeouts[0] != seenTimeouts || (i & 4095) == 0)
                {
                    seenTimeouts = timeouts[0];
                    stop = StopReason(timeouts, watch);
                    if (stop != null) return Abandon(result, stop, timeouts, watch);
                }
                if (!IsMatch(t, baseMatch, i, start, timeouts)) continue;
                if (anyOf.Length > 0 && FirstMatch(t, anyOf, i, start, timeouts) < 0) continue;
                result.MatchedRows++;
                string key = GetKey(t, i, rule.GroupBy, rule.Match, timeouts);
                int entry = FirstMatch(t, allow, i, start, timeouts);
                if (entry >= 0)
                {
                    result.AllowlistedRows++;
                    result.AllowlistedPerEntry[entry]++;
                    int seen;
                    allowlistedByKey.TryGetValue(key, out seen);
                    allowlistedByKey[key] = seen + 1;
                    continue;
                }
                GroupResult g;
                if (!groups.TryGetValue(key, out g))
                {
                    g = new GroupResult();
                    g.Key = key;
                    groups[key] = g;
                    order.Add(g);
                }
                g.Rows.Add(i);
            }

            foreach (GroupResult g in order)
            {
                if (rule.ThresholdCount > 0)
                {
                    List<int> qualifying = ApplyThreshold(t, g.Rows, rule.ThresholdCount, rule.ThresholdWindowTicks);
                    if (qualifying.Count == 0) continue;
                    g.Rows = qualifying;
                }
                int allowlisted;
                if (allowlistedByKey.TryGetValue(g.Key, out allowlisted)) g.Allowlisted = allowlisted;
                result.Groups.Add(g);
            }

            if (rule.EscalateMatch != null && result.Groups.Count > 0)
            {
                stop = Escalate(t, rule, result.Groups, allow, start, timeouts, watch);
                if (stop != null) return Abandon(result, stop, timeouts, watch);
            }
            result.RegexTimeouts = timeouts[0];
            result.Milliseconds = watch.Elapsed.TotalMilliseconds;
            return result;
        }

        // Adds to each group the rows that match escalate.match within the
        // window after one of the group's rows (with the same sameKey value).
        // Returns why the rule must stop, or null.
        static string Escalate(RowTable t, CompiledRule rule, List<GroupResult> groups, Prepared[] allow, long start, int[] timeouts, Stopwatch watch)
        {
            Prepared escalate = Prepare(t, rule.EscalateMatch, timeouts);
            bool anyKey = rule.EscalateKey == null || rule.EscalateKey.Kind == "none";
            List<int> candidates = new List<int>();
            List<string> candidateKeys = new List<string>();
            int seenTimeouts = -1;
            for (int i = 0; i < t.Count; i++)
            {
                if (timeouts[0] != seenTimeouts || (i & 4095) == 0)
                {
                    seenTimeouts = timeouts[0];
                    string stop = StopReason(timeouts, watch);
                    if (stop != null) return stop;
                }
                if (t.Ticks[i] < 0 || !IsMatch(t, escalate, i, start, timeouts)) continue;
                if (FirstMatch(t, allow, i, start, timeouts) >= 0) continue;
                string key = anyKey ? "" : GetKey(t, i, rule.EscalateKey, null, timeouts);
                if (!anyKey && key.Length == 0) continue;
                candidates.Add(i);
                candidateKeys.Add(key);
            }
            if (candidates.Count == 0) return null;

            foreach (GroupResult g in groups)
            {
                Dictionary<string, List<long>> times = new Dictionary<string, List<long>>(StringComparer.OrdinalIgnoreCase);
                HashSet<int> own = new HashSet<int>(g.Rows);
                foreach (int r in g.Rows)
                {
                    if (t.Ticks[r] < 0) continue;
                    string key = anyKey ? "" : GetKey(t, r, rule.EscalateKey, null, timeouts);
                    if (!anyKey && key.Length == 0) continue;
                    List<long> list;
                    if (!times.TryGetValue(key, out list))
                    {
                        list = new List<long>();
                        times[key] = list;
                    }
                    list.Add(t.Ticks[r]);
                }
                foreach (List<long> list in times.Values) list.Sort();
                for (int c = 0; c < candidates.Count; c++)
                {
                    int row = candidates[c];
                    if (own.Contains(row)) continue;
                    List<long> list;
                    if (!times.TryGetValue(candidateKeys[c], out list)) continue;
                    long tc = t.Ticks[row];
                    int at = list.BinarySearch(tc);
                    if (at < 0) at = ~at - 1;
                    if (at >= 0 && tc - list[at] <= rule.EscalateWindowTicks) g.EscalationRows.Add(row);
                }
            }
            return null;
        }

        // Keeps at most maxFindings groups of a rule. When there are more, the
        // first (maxFindings - 1) by priority stay and all the others fold into
        // one roll-up group at the end, so a rule can never flood the report
        // (one group per attacking address of a brute force, say). Priority:
        // escalated groups, then more rows, then the earlier first row, then
        // the key. The roll-up keeps every row (the Finding column tags them
        // all) and the folded keys, most rows first. maxFindings < 2: no limit.
        public static void Fold(RowTable t, RuleResult result, int maxFindings)
        {
            if (maxFindings < 2 || result.Groups.Count <= maxFindings) return;
            long[] ticks = t.Ticks;
            Dictionary<GroupResult, long> firstRow = new Dictionary<GroupResult, long>();
            foreach (GroupResult g in result.Groups)
            {
                long f = long.MaxValue;
                foreach (int r in g.Rows)
                {
                    if (ticks[r] >= 0 && ticks[r] < f) f = ticks[r];
                }
                firstRow[g] = f;
            }
            List<GroupResult> ranked = new List<GroupResult>(result.Groups);
            ranked.Sort(delegate(GroupResult a, GroupResult b)
            {
                int c = (b.EscalationRows.Count > 0).CompareTo(a.EscalationRows.Count > 0);
                if (c != 0) return c;
                c = b.Rows.Count.CompareTo(a.Rows.Count);
                if (c != 0) return c;
                c = firstRow[a].CompareTo(firstRow[b]);
                if (c != 0) return c;
                return StringComparer.OrdinalIgnoreCase.Compare(a.Key, b.Key);
            });
            HashSet<GroupResult> keep = new HashSet<GroupResult>();
            for (int k = 0; k < maxFindings - 1; k++) keep.Add(ranked[k]);
            GroupResult rollUp = new GroupResult();
            rollUp.Key = "";
            HashSet<int> escalation = new HashSet<int>();
            for (int k = maxFindings - 1; k < ranked.Count; k++)
            {
                GroupResult g = ranked[k];
                rollUp.Rows.AddRange(g.Rows);
                foreach (int r in g.EscalationRows) escalation.Add(r);
                rollUp.Allowlisted += g.Allowlisted;
                rollUp.FoldedGroups++;
                rollUp.FoldedKeys.Add(g.Key);
            }
            HashSet<int> own = new HashSet<int>(rollUp.Rows);
            foreach (int r in escalation)
            {
                if (!own.Contains(r)) rollUp.EscalationRows.Add(r);
            }
            rollUp.Rows.Sort();
            rollUp.EscalationRows.Sort();
            List<GroupResult> kept = new List<GroupResult>();
            foreach (GroupResult g in result.Groups)
            {
                if (keep.Contains(g)) kept.Add(g);
            }
            kept.Add(rollUp);
            result.Groups = kept;
        }

        // The builder's note on a row whose time is a date the task's author
        // wrote (task XML RegistrationInfo/Date), which can be old or forged
        public const string AuthorSuppliedTimeMark = "author-supplied, not recorded by Windows";

        public static bool IsAuthorSuppliedTime(string details)
        {
            return details != null && details.IndexOf(AuthorSuppliedTimeMark, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // A source the builder's Memory parser writes (Volatility 3 on the
        // memory dump): Memory-Processes, Memory-Network, Memory-CommandLine,
        // Memory-Services
        public static bool IsMemorySource(string source)
        {
            return source != null && source.StartsWith("Memory-", StringComparison.OrdinalIgnoreCase);
        }

        // All rows (rule rows and escalation rows, ascending), the first and
        // last time, and the evidence rows: escalation rows first (they are
        // why the severity was raised), then the earliest rule rows. A row
        // whose time is author-supplied does not set the first and last time
        // when the group has a row with a time Windows recorded (a forged old
        // date would otherwise date the whole lead); when it has none, those
        // dates are the times and AuthorTimesOnly is set. SnapshotOnly: every
        // row is a Snapshot row. MemoryOnly: every row is from a Memory-*
        // source (the memory dump), whatever its event type.
        public static void Summarize(RowTable t, GroupResult g, int maxEvidence)
        {
            List<int> all = new List<int>(g.Rows.Count + g.EscalationRows.Count);
            all.AddRange(g.Rows);
            all.AddRange(g.EscalationRows);
            all.Sort();
            g.AllRows = all.ToArray();
            g.RowNumbers = new int[g.AllRows.Length];
            for (int n = 0; n < g.AllRows.Length; n++) g.RowNumbers[n] = g.AllRows[n] + 2;
            int snapshotType = Array.IndexOf(t.EventTypes, "Snapshot");
            bool[] memorySource = new bool[t.Sources.Length];
            for (int s = 0; s < memorySource.Length; s++) memorySource[s] = IsMemorySource(t.Sources[s]);
            bool snapshotOnly = all.Count > 0;
            bool memoryOnly = all.Count > 0;
            long first = -1;
            long last = -1;
            long authorFirst = -1;
            long authorLast = -1;
            foreach (int r in all)
            {
                if (t.EventTypeId[r] != snapshotType) snapshotOnly = false;
                if (!memorySource[t.SourceId[r]]) memoryOnly = false;
                long tk = t.Ticks[r];
                if (tk < 0) continue;
                if (IsAuthorSuppliedTime(t.Details[r]))
                {
                    if (authorFirst < 0 || tk < authorFirst) authorFirst = tk;
                    if (tk > authorLast) authorLast = tk;
                    continue;
                }
                if (first < 0 || tk < first) first = tk;
                if (tk > last) last = tk;
            }
            g.AuthorTimesOnly = first < 0 && authorFirst >= 0;
            if (g.AuthorTimesOnly)
            {
                first = authorFirst;
                last = authorLast;
            }
            g.FirstTicks = first;
            g.LastTicks = last;
            g.SnapshotOnly = snapshotOnly;
            g.MemoryOnly = memoryOnly;
            if (maxEvidence < 1) maxEvidence = 1;
            if (all.Count <= maxEvidence)
            {
                g.EvidenceRows = g.AllRows;
                return;
            }
            List<int> picked = new List<int>();
            List<int> escalation = new List<int>(g.EscalationRows);
            escalation.Sort();
            for (int e = 0; e < escalation.Count && picked.Count < maxEvidence; e++) picked.Add(escalation[e]);
            List<int> own = new List<int>(g.Rows);
            own.Sort();
            for (int r = 0; r < own.Count && picked.Count < maxEvidence; r++) picked.Add(own[r]);
            picked.Sort();
            g.EvidenceRows = picked.ToArray();
        }
    }

    public sealed class SourceStat
    {
        public string Source;
        public int Rows;
        public long FirstTicks = -1;
        public long LastTicks = -1;
        public long GapStartTicks = -1;
        public long GapEndTicks = -1;
    }

    public sealed class DayStat
    {
        public string Day;
        public int Rows;
        public int NonFileRows;
    }

    public sealed class UserStat
    {
        public string Name;
        public int Rows;
        public bool IsSystem;
    }

    // Coverage and activity numbers for the report model, in one pass
    public sealed class Stats
    {
        public int Rows;
        public int TimedRows;
        public int FileRows;
        public int SnapshotRows;
        public long FirstTicks = -1;
        public long LastTicks = -1;
        public List<SourceStat> Sources = new List<SourceStat>();
        public List<DayStat> Days = new List<DayStat>();
        public int[] PerHourUtc = new int[24];
        public int[] PerHourLocal = new int[24];
        public List<UserStat> Users = new List<UserStat>();

        // Service accounts, built-in groups and profile folders that are not
        // people. A SID left unnamed by the builder (no ProfileList or BAM
        // name in that run) can be a service or virtual account: per-service
        // (S-1-5-80-...), IIS AppPool (82), Hyper-V VM (83), Window Manager
        // (90-0) and Font Driver Host (96-0) SIDs are not people either.
        static readonly Regex SystemName = new Regex(@"^(?:SYSTEM|LOCAL SYSTEM|LocalSystem|LOCAL SERVICE|LocalService|NETWORK SERVICE|NetworkService|ANONYMOUS LOGON|INTERACTIVE|SERVICE|BATCH|NETWORK|Everyone|Users|Administrators|Authenticated Users|Guests|Power Users|Remote Desktop Users|Default|Default User|DefaultAppPool|Public|All Users|defaultuser\d*|WDAGUtilityAccount|DWM-\d+|UMFD-\d+|S-1-5-(?:18|19|20|32-\d+|80(?:-\d+)+|82(?:-\d+)+|83(?:-\d+)+|90-0-\d+|96-0-\d+))$|\$$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly Regex SystemDomain = new Regex(@"^(?:NT AUTHORITY|NT SERVICE|BUILTIN|Window Manager|Font Driver Host|IIS APPPOOL|NT VIRTUAL MACHINE)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public static Stats Compute(RowTable t, TimeZoneInfo zone)
        {
            return Compute(t, zone, null);
        }

        // localDomains: the examined computer's names (see the Users part)
        public static Stats Compute(RowTable t, TimeZoneInfo zone, string[] localDomains)
        {
            Stats s = new Stats();
            s.Rows = t.Count;
            if (zone == null) zone = TimeZoneInfo.Utc;
            SourceStat[] bySource = new SourceStat[t.Sources.Length];
            for (int i = 0; i < bySource.Length; i++)
            {
                bySource[i] = new SourceStat();
                bySource[i].Source = t.Sources[i];
            }
            // File times are not activity: FileAccess (the $MFT, the USN
            // journal) and FileLastModified (ShimCache, often years old)
            int fileType = Array.IndexOf(t.EventTypes, "FileAccess");
            int fileModifiedType = Array.IndexOf(t.EventTypes, "FileLastModified");
            int snapshotType = Array.IndexOf(t.EventTypes, "Snapshot");
            Dictionary<long, DayStat> days = new Dictionary<long, DayStat>();
            // Local hour per 15-minute UTC slot (every UTC offset is a multiple of 15 minutes)
            Dictionary<long, int> localHours = new Dictionary<long, int>();
            long slotTicks = TimeSpan.TicksPerMinute * 15;
            int[] userRows = new int[t.Users.Length];
            for (int i = 0; i < t.Count; i++)
            {
                int type = t.EventTypeId[i];
                bool isFile = type == fileType || type == fileModifiedType;
                if (isFile) s.FileRows++;
                if (type == snapshotType) s.SnapshotRows++;
                userRows[t.UserId[i]]++;
                SourceStat ss = bySource[t.SourceId[i]];
                ss.Rows++;
                long tk = t.Ticks[i];
                if (tk < 0) continue;
                s.TimedRows++;
                if (s.FirstTicks < 0 || tk < s.FirstTicks) s.FirstTicks = tk;
                if (tk > s.LastTicks) s.LastTicks = tk;
                if (ss.FirstTicks < 0 || tk < ss.FirstTicks) ss.FirstTicks = tk;
                if (ss.LastTicks >= 0 && tk > ss.LastTicks)
                {
                    long gap = tk - ss.LastTicks;
                    if (ss.GapStartTicks < 0 || gap > ss.GapEndTicks - ss.GapStartTicks)
                    {
                        ss.GapStartTicks = ss.LastTicks;
                        ss.GapEndTicks = tk;
                    }
                }
                if (tk > ss.LastTicks) ss.LastTicks = tk;

                long dayNumber = tk / TimeSpan.TicksPerDay;
                DayStat day;
                if (!days.TryGetValue(dayNumber, out day))
                {
                    day = new DayStat();
                    day.Day = new DateTime(dayNumber * TimeSpan.TicksPerDay, DateTimeKind.Utc).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                    days[dayNumber] = day;
                }
                day.Rows++;
                if (!isFile && type != snapshotType) day.NonFileRows++;

                s.PerHourUtc[(int)((tk / TimeSpan.TicksPerHour) % 24)]++;
                long slot = tk / slotTicks;
                int localHour;
                if (!localHours.TryGetValue(slot, out localHour))
                {
                    try
                    {
                        localHour = TimeZoneInfo.ConvertTimeFromUtc(new DateTime(slot * slotTicks, DateTimeKind.Utc), zone).Hour;
                    }
                    catch (ArgumentException)
                    {
                        localHour = (int)((tk / TimeSpan.TicksPerHour) % 24);
                    }
                    localHours[slot] = localHour;
                }
                s.PerHourLocal[localHour]++;
            }
            s.Sources.AddRange(bySource);
            s.Sources.Sort(delegate(SourceStat a, SourceStat b) { return StringComparer.OrdinalIgnoreCase.Compare(a.Source, b.Source); });
            List<long> dayNumbers = new List<long>(days.Keys);
            dayNumbers.Sort();
            foreach (long d in dayNumbers) s.Days.Add(days[d]);

            // Users: one entry per account as the User column names it
            // (case-insensitive). The builder writes one form per account: a
            // local account of the examined computer is its bare name, and
            // CORP\alice, OTHERHOST\alice, AzureAD\... and NT AUTHORITY\SYSTEM
            // stay as they are, so accounts that share a name stay apart.
            // Timelines from older builders (-ReportOnly) can still hold
            // HOST\alice or .\alice: a domain of "." or one of localDomains is
            // dropped, so those rows count with "alice".
            HashSet<string> local = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            local.Add(".");
            if (localDomains != null)
            {
                foreach (string d in localDomains)
                {
                    if (d != null && d.Trim().Length > 0) local.Add(d.Trim());
                }
            }
            Dictionary<string, UserStat> users = new Dictionary<string, UserStat>(StringComparer.OrdinalIgnoreCase);
            for (int u = 0; u < t.Users.Length; u++)
            {
                string raw = t.Users[u].Trim();
                if (raw.Length == 0 || raw == "-" || userRows[u] == 0) continue;
                int slash = raw.LastIndexOf('\\');
                string domain = slash > 0 ? raw.Substring(0, slash).Trim() : "";
                string name = raw.Substring(slash + 1).Trim();
                if (name.Length == 0 || name == "-") continue;
                string key = raw;
                if (slash >= 0 && (domain.Length == 0 || domain == "-" || local.Contains(domain))) key = name;
                UserStat us;
                if (!users.TryGetValue(key, out us))
                {
                    us = new UserStat();
                    us.Name = key;
                    users[key] = us;
                }
                us.Rows += userRows[u];
                if (SystemName.IsMatch(name) || (domain.Length > 0 && SystemDomain.IsMatch(domain))) us.IsSystem = true;
            }
            s.Users.AddRange(users.Values);
            s.Users.Sort(delegate(UserStat a, UserStat b)
            {
                int c = b.Rows.CompareTo(a.Rows);
                return c != 0 ? c : StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name);
            });
            return s;
        }
    }

    // Streaming CSV reader for timeline.csv (RFC 4180: quoted fields may hold
    // commas, doubled quotes and line breaks). Rows become PSObjects with one
    // note property per header column, like Import-Csv. Reads blocks of
    // characters and copies runs of plain text at once.
    public sealed class CsvReader
    {
        readonly TextReader reader;
        readonly char[] buffer = new char[1 << 16];
        readonly StringBuilder field = new StringBuilder();
        int length;
        int position;

        CsvReader(TextReader reader)
        {
            this.reader = reader;
        }

        public static object[] ReadRows(string path)
        {
            List<object> rows = new List<object>();
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 16))
            using (StreamReader text = new StreamReader(stream, new UTF8Encoding(false), true, 1 << 16))
            {
                CsvReader csv = new CsvReader(text);
                List<string> fields = new List<string>();
                string[] header = null;
                while (csv.ReadRecord(fields))
                {
                    if (fields.Count == 1 && fields[0].Length == 0) continue;
                    if (header == null)
                    {
                        if (fields[0].StartsWith("#TYPE", StringComparison.Ordinal)) continue;
                        header = HeaderNames(fields);
                        continue;
                    }
                    PSObject row = new PSObject();
                    for (int c = 0; c < header.Length; c++)
                    {
                        // Names are unique (HeaderNames), so the duplicate check can be skipped
                        row.Members.Add(new PSNoteProperty(header[c], c < fields.Count ? fields[c] : null), true);
                    }
                    rows.Add(row);
                }
            }
            return rows.ToArray();
        }

        bool Fill()
        {
            if (position < length) return true;
            length = reader.Read(buffer, 0, buffer.Length);
            position = 0;
            if (length > 0) return true;
            length = 0;
            return false;
        }

        // One record into fields; false at the end of the input
        bool ReadRecord(List<string> fields)
        {
            fields.Clear();
            field.Length = 0;
            if (!Fill()) return false;
            bool quoted = false;
            while (true)
            {
                if (!Fill())
                {
                    fields.Add(field.ToString());
                    return true;
                }
                if (quoted)
                {
                    int quote = Array.IndexOf(buffer, '"', position, length - position);
                    if (quote < 0)
                    {
                        field.Append(buffer, position, length - position);
                        position = length;
                        continue;
                    }
                    field.Append(buffer, position, quote - position);
                    position = quote + 1;
                    if (Fill() && buffer[position] == '"')
                    {
                        field.Append('"');
                        position++;
                    }
                    else
                    {
                        quoted = false;
                    }
                    continue;
                }
                int start = position;
                while (position < length)
                {
                    char c = buffer[position];
                    if (c == ',' || c == '"' || c == '\r' || c == '\n') break;
                    position++;
                }
                if (position > start) field.Append(buffer, start, position - start);
                if (position >= length) continue;
                char special = buffer[position++];
                if (special == '"')
                {
                    quoted = true;
                    continue;
                }
                if (special == ',')
                {
                    fields.Add(field.ToString());
                    field.Length = 0;
                    continue;
                }
                if (special == '\r' && Fill() && buffer[position] == '\n') position++;
                fields.Add(field.ToString());
                return true;
            }
        }

        static string[] HeaderNames(List<string> fields)
        {
            string[] names = new string[fields.Count];
            HashSet<string> used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int c = 0; c < fields.Count; c++)
            {
                string name = fields[c].Trim();
                if (name.Length == 0) name = "H" + (c + 1).ToString(CultureInfo.InvariantCulture);
                string unique = name;
                int n = 2;
                while (used.Contains(unique))
                {
                    unique = name + "_" + n.ToString(CultureInfo.InvariantCulture);
                    n++;
                }
                used.Add(unique);
                names[c] = unique;
            }
            return names;
        }
    }

    public static class CsvText
    {
        // One CSV line, every field quoted. A field Excel would read as a
        // formula (= + - @, tab, CR first) gets a leading apostrophe: file and
        // account names in the timeline can be chosen by an attacker.
        public static string Line(object[] values)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < values.Length; i++)
            {
                if (i > 0) sb.Append(',');
                string text = RowTable.Text(values[i]);
                if (text.Length > 0 && "=+-@\t\r".IndexOf(text[0]) >= 0) text = "'" + text;
                sb.Append('"').Append(text.Replace("\"", "\"\"")).Append('"');
            }
            return sb.ToString();
        }
    }

    // JSON writer for the report model: ASCII only (other characters and
    // < > & are \u escapes, so the text is also safe inside HTML), dates as
    // ISO 8601 UTC, the same output in Windows PowerShell 5.1 and 7
    public static class Json
    {
        public static string Serialize(object value)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, value, 0);
            return sb.ToString();
        }

        static void NewLine(StringBuilder sb, int level)
        {
            sb.Append("\r\n");
            sb.Append(' ', level * 2);
        }

        static void Write(StringBuilder sb, object value, int level)
        {
            if (level > 64)
            {
                sb.Append("null");
                return;
            }
            PSObject pso = value as PSObject;
            if (pso != null)
            {
                if (pso.BaseObject is PSCustomObject)
                {
                    WriteObject(sb, pso, level);
                    return;
                }
                value = pso.BaseObject;
            }
            if (value == null || value is DBNull)
            {
                sb.Append("null");
                return;
            }
            string s = value as string;
            if (s != null)
            {
                WriteString(sb, s);
                return;
            }
            if (value is char)
            {
                WriteString(sb, value.ToString());
                return;
            }
            if (value is bool)
            {
                sb.Append((bool)value ? "true" : "false");
                return;
            }
            if (value is DateTime)
            {
                DateTime d = (DateTime)value;
                if (d.Kind == DateTimeKind.Local) d = d.ToUniversalTime();
                WriteString(sb, d.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
                return;
            }
            if (value is DateTimeOffset)
            {
                WriteString(sb, ((DateTimeOffset)value).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
                return;
            }
            if (value is Enum)
            {
                WriteString(sb, value.ToString());
                return;
            }
            if (value is int || value is long || value is short || value is byte || value is sbyte ||
                value is uint || value is ulong || value is ushort || value is decimal)
            {
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }
            if (value is double || value is float)
            {
                double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) sb.Append("null");
                else sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            IDictionary dict = value as IDictionary;
            if (dict != null)
            {
                WriteDictionary(sb, dict, level);
                return;
            }
            IEnumerable list = value as IEnumerable;
            if (list != null)
            {
                WriteArray(sb, list, level);
                return;
            }
            if (value is PSCustomObject)
            {
                sb.Append("{}");
                return;
            }
            WriteString(sb, Convert.ToString(value, CultureInfo.InvariantCulture));
        }

        static void WriteObject(StringBuilder sb, PSObject pso, int level)
        {
            bool any = false;
            sb.Append('{');
            foreach (PSPropertyInfo p in pso.Properties)
            {
                sb.Append(any ? "," : "");
                NewLine(sb, level + 1);
                WriteString(sb, p.Name);
                sb.Append(": ");
                Write(sb, p.Value, level + 1);
                any = true;
            }
            if (any) NewLine(sb, level);
            sb.Append('}');
        }

        static void WriteDictionary(StringBuilder sb, IDictionary dict, int level)
        {
            bool any = false;
            sb.Append('{');
            foreach (DictionaryEntry entry in dict)
            {
                sb.Append(any ? "," : "");
                NewLine(sb, level + 1);
                WriteString(sb, Convert.ToString(entry.Key, CultureInfo.InvariantCulture));
                sb.Append(": ");
                Write(sb, entry.Value, level + 1);
                any = true;
            }
            if (any) NewLine(sb, level);
            sb.Append('}');
        }

        static void WriteArray(StringBuilder sb, IEnumerable list, int level)
        {
            bool any = false;
            sb.Append('[');
            foreach (object item in list)
            {
                sb.Append(any ? "," : "");
                NewLine(sb, level + 1);
                Write(sb, item, level + 1);
                any = true;
            }
            if (any) NewLine(sb, level);
            sb.Append(']');
        }

        static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20 || c > 0x7E || c == '<' || c == '>' || c == '&')
                        {
                            sb.Append("\\u");
                            sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
'@
}

# =============================================================
# Rules file
# =============================================================

# Match timeout of every rule pattern (set it before Import-ReportRules). A
# rule is stopped after [TimelineReport.Engine]::MaxRegexTimeouts timeouts.
$script:ReportEngineRegexTimeout = [TimeSpan]::FromSeconds(2)

# The note of a lead seen only in the memory dump (every row from a Memory-*
# source): a finding's MemoryOnlyNote, findings.csv's summary line and the
# workbook's Findings sheet. The report's card shows the same words.
$script:ReportMemoryOnlyNote = "Captured in the memory dump"

# Message of an invalid-rules-file error: names the file, the rule and the field
function Format-ReportEngineRuleError {
    param([string]$File, [string]$Where, [string]$Problem)
    return "Invalid report rules file '$File': ${Where}: $Problem"
}

# Value of a member of a JSON object (ConvertFrom-Json), or $null. Arrays come
# back as arrays (also with one element).
function Get-ReportEngineMember {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if (-not $property) { return $null }
    return , $property.Value
}

function Test-ReportEngineJsonObject {
    param($Value)
    return ($null -ne $Value -and $Value -is [System.Management.Automation.PSCustomObject])
}

# $true for a whole number from JSON (Int32 in 5.1, Int64 in 7)
function Test-ReportEngineInteger {
    param($Value)
    if ($Value -is [int] -or $Value -is [long]) { return $true }
    if ($Value -is [double] -or $Value -is [decimal]) { return ([double]$Value -eq [Math]::Floor([double]$Value)) }
    return $false
}

function Test-ReportEngineNumber {
    param($Value)
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal])
}

# Member names a JSON object may have; "_..." members are comments
function Assert-ReportEngineMembers {
    param($Object, [string[]]$Allowed, [string]$File, [string]$Where)
    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name.StartsWith("_") -or $Allowed -contains $property.Name) { continue }
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "unknown field '$($property.Name)' (allowed: $($Allowed -join ', '); names starting with '_' are comments)")
    }
}

# The compiled regex of a rule pattern, from the C# helper
# ([TimelineReport.RulePattern], which also expands {{list:<name>}}). A
# function of its own, so a test can stand in for a call that fails or is
# blocked.
function New-ReportEngineRuleRegex {
    param([string]$Pattern, [hashtable]$Lists, [System.Text.RegularExpressions.RegexOptions]$Options, [TimeSpan]$Timeout)
    return [TimelineReport.RulePattern]::Compile($Pattern, $Lists, $Options, $Timeout)
}

# Regex from a rule pattern: {{list:<name>}} becomes (?:escaped1|escaped2|...).
# Case-insensitive, culture-invariant, and "." also matches line breaks
# (Details can hold multi-line script blocks and privilege lists). A match
# timeout ($script:ReportEngineRegexTimeout) plus the engine's stop after a
# few timeouts keep a runaway pattern from hanging the builder.
# The lists are expanded in the C# helper, never here: PowerShell 7 passes
# the string arguments of .NET method calls to AMSI, which can block a call
# that holds an expanded keyword list (see [TimelineReport.RulePattern]).
# Fails closed: a call that fails or is blocked, or that gives no regex or
# an empty one, is a rules-file error naming the rule and field, never a
# condition that matches every row.
function ConvertTo-ReportEngineRegex {
    param($Pattern, [hashtable]$Lists, [string]$File, [string]$Where)
    if (-not ($Pattern -is [string])) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "must be a string (a regular expression)")
    }
    if ($Pattern.Length -eq 0) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "is empty (an empty pattern matches every row)")
    }
    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant -bor
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    $timeout = $script:ReportEngineRegexTimeout
    if (-not ($timeout -is [TimeSpan]) -or $timeout -le [TimeSpan]::Zero) { $timeout = [TimeSpan]::FromSeconds(2) }
    if ($null -eq $Lists) { $Lists = @{} }
    $regex = $null
    $problem = ""
    try { $regex = New-ReportEngineRuleRegex -Pattern $Pattern -Lists $Lists -Options $options -Timeout $timeout }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        # The helper's own problems (unknown list, invalid regex) are
        # ArgumentExceptions; anything else (e.g. antivirus blocking the
        # call) is named as it is
        $problem = if ($inner -is [System.ArgumentException]) { $inner.Message } else { "could not be compiled: $($inner.Message)" }
        if (-not $problem) { $problem = "could not be compiled ($($inner.GetType().FullName))" }
    }
    if ($problem) { throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem $problem) }
    if (-not ($regex -is [System.Text.RegularExpressions.Regex]) -or [TimelineReport.RulePattern]::IsEmpty($regex)) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "could not be compiled: no regular expression (or an empty one, which would match every row) came back; antivirus may have blocked it")
    }
    return $regex
}

# Match object (JSON) -> [TimelineReport.MatchSpec]. All present conditions
# must hold. Conditions: source, eventType, description, details, user and
# their not* forms (the regex must NOT match), and duringCollection (bool).
function ConvertTo-ReportEngineMatchSpec {
    param($Object, [hashtable]$Lists, [string]$File, [string]$Where, [switch]$AllowEmpty)
    if (-not (Test-ReportEngineJsonObject $Object)) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "must be an object of conditions, e.g. { ""source"": ""^System\\.evtx$"" }")
    }
    $fields = @{
        source = "Source"; eventType = "EventType"; description = "Description"; details = "Details"; user = "User"
        notSource = "NotSource"; notEventType = "NotEventType"; notDescription = "NotDescription"; notDetails = "NotDetails"; notUser = "NotUser"
    }
    $spec = New-Object TimelineReport.MatchSpec
    $conditions = 0
    foreach ($property in $Object.PSObject.Properties) {
        $name = $property.Name
        if ($name.StartsWith("_")) { continue }
        if ($name -eq "duringCollection") {
            if (-not ($property.Value -is [bool])) {
                throw (Format-ReportEngineRuleError -File $File -Where "$Where.$name" -Problem "must be true or false")
            }
            $spec.During = if ($property.Value) { 1 } else { 2 }
            $conditions++
            continue
        }
        if (-not $fields.ContainsKey($name)) {
            throw (Format-ReportEngineRuleError -File $File -Where "$Where.$name" -Problem "unknown condition (allowed: $((@($fields.Keys | Sort-Object) + 'duringCollection') -join ', '))")
        }
        $spec.($fields[$name]) = ConvertTo-ReportEngineRegex -Pattern $property.Value -Lists $Lists -File $File -Where "$Where.$name"
        $conditions++
    }
    if ($conditions -eq 0 -and -not $AllowEmpty) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "has no conditions")
    }
    return $spec
}

# groupBy / sameKey text -> [TimelineReport.KeySpec]
function ConvertTo-ReportEngineKeySpec {
    param($Text, [string[]]$Kinds, [string]$File, [string]$Where)
    if (-not ($Text -is [string]) -or $Text.Length -eq 0) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "must be one of: $($Kinds -join ', ') or detail:<Key>")
    }
    $spec = New-Object TimelineReport.KeySpec
    if ($Text -match '^detail:(.+)$') {
        $keys = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() })
        foreach ($key in $keys) {
            if (-not $key -or $key -match '[=|]') {
                throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "detail:<Key> needs one or more key names separated by commas (no '=' or '|')")
            }
        }
        $spec.Kind = "detail"
        $spec.DetailKeys = [string[]]$keys
        return $spec
    }
    $kind = @($Kinds | Where-Object { $_ -eq $Text })[0]
    if (-not $kind) {
        throw (Format-ReportEngineRuleError -File $File -Where $Where -Problem "'$Text' is not one of: $($Kinds -join ', '), detail:<Key>")
    }
    $spec.Kind = $kind.ToLowerInvariant()
    $spec.DetailKeys = [string[]]@()
    return $spec
}

<#
.SYNOPSIS
Loads and checks report-rules.json.
.DESCRIPTION
Returns { SchemaVersion, Path, Rules, Allowlist, Lists }. Lists are expanded
and every regex is compiled once. An invalid file throws an error that names
the file, the rule and the field.
#>
function Import-ReportRules {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $file = Split-Path -Leaf $fullPath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "Report rules file not found: $fullPath" }
    try { $json = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($fullPath)) -ErrorAction Stop }
    catch { throw "Invalid report rules file '$file': not valid JSON ($($_.Exception.Message))" }
    if (-not (Test-ReportEngineJsonObject $json)) { throw "Invalid report rules file '$file': the file must hold one JSON object" }

    Assert-ReportEngineMembers -Object $json -Allowed @("schemaVersion", "lists", "rules", "allowlist", "comment", "description") -File $file -Where "top level"
    $schemaVersion = Get-ReportEngineMember $json "schemaVersion"
    if (-not (Test-ReportEngineInteger $schemaVersion) -or [int]$schemaVersion -ne 1) {
        throw (Format-ReportEngineRuleError -File $file -Where "schemaVersion" -Problem "must be 1 (found '$schemaVersion')")
    }

    $categories = @("Integrity", "Antivirus", "Access", "Persistence", "Execution", "InitialAccess", "FileSystem", "Other")
    $severities = @("High", "Medium", "Info")
    $groupKinds = @("rule", "description", "user", "source", "eventType", "capture")
    $sameKeyKinds = @("none", "user", "source", "description", "eventType")

    # --- Lists: name -> literal values, used in patterns as {{list:<name>}} ---
    $lists = @{}
    $listValues = [ordered]@{}
    $listsJson = Get-ReportEngineMember $json "lists"
    if ($null -ne $listsJson) {
        if (-not (Test-ReportEngineJsonObject $listsJson)) {
            throw (Format-ReportEngineRuleError -File $file -Where "lists" -Problem "must be an object of ""name"": [""value"", ...]")
        }
        foreach ($property in $listsJson.PSObject.Properties) {
            $where = "list '$($property.Name)'"
            if ($property.Name -notmatch '^[A-Za-z0-9_.-]+$') {
                throw (Format-ReportEngineRuleError -File $file -Where $where -Problem "a list name may use only letters, digits, '_', '.' and '-'")
            }
            # Read by the C# helper: list values (tool names, AMSI-bypass
            # strings) never become the argument of a PowerShell method call
            $values = $null
            if ($property.Value -is [array]) { $values = [TimelineReport.RulePattern]::ReadList($property.Value) }
            if ($null -eq $values) {
                throw (Format-ReportEngineRuleError -File $file -Where $where -Problem "must be a non-empty array of strings (every value a non-empty string)")
            }
            $lists[$property.Name] = $values
            $listValues[$property.Name] = $values
        }
    }

    # --- Rules ---
    $rulesJson = Get-ReportEngineMember $json "rules"
    if (-not ($rulesJson -is [array]) -or $rulesJson.Count -eq 0) {
        throw (Format-ReportEngineRuleError -File $file -Where "rules" -Problem "must be a non-empty array of rules")
    }
    $ruleFields = @("id", "title", "category", "severity", "match", "anyOf", "groupBy", "threshold", "escalate", "why",
        "technical", "nextSteps", "falsePositives", "references", "maxEvidence", "maxFindings", "activityTime", "enabled", "comment", "notes")
    $rules = New-Object System.Collections.Generic.List[object]
    $ruleIds = @{}
    for ($n = 0; $n -lt $rulesJson.Count; $n++) {
        $ruleJson = $rulesJson[$n]
        $where = "rules[$n]"
        if (-not (Test-ReportEngineJsonObject $ruleJson)) { throw (Format-ReportEngineRuleError -File $file -Where $where -Problem "must be an object") }
        $id = Get-ReportEngineMember $ruleJson "id"
        if (-not ($id -is [string]) -or $id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.id" -Problem "must be a string of letters, digits, '_', '.' or '-' (found '$id')")
        }
        $where = "rule '$id' (rules[$n])"
        if ($ruleIds.ContainsKey($id)) { throw (Format-ReportEngineRuleError -File $file -Where "$where.id" -Problem "duplicate rule id (also rules[$($ruleIds[$id])])") }
        $ruleIds[$id] = $n
        Assert-ReportEngineMembers -Object $ruleJson -Allowed $ruleFields -File $file -Where $where

        $texts = @{}
        foreach ($field in @("title", "why", "technical", "nextSteps", "falsePositives")) {
            $value = Get-ReportEngineMember $ruleJson $field
            if ($null -eq $value) { $value = "" }
            if (-not ($value -is [string])) { throw (Format-ReportEngineRuleError -File $file -Where "$where.$field" -Problem "must be a string") }
            $texts[$field] = $value.Trim()
        }
        foreach ($field in @("title", "why")) {
            if (-not $texts[$field]) { throw (Format-ReportEngineRuleError -File $file -Where "$where.$field" -Problem "is required") }
        }
        # @(...)[0], not Select-Object -First 1: in Windows PowerShell that
        # records a StopUpstreamCommandsException in -ErrorVariable, which
        # would look like an import error
        $category = @($categories | Where-Object { $_ -eq (Get-ReportEngineMember $ruleJson "category") })[0]
        if (-not $category) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.category" -Problem "must be one of: $($categories -join ', ') (found '$(Get-ReportEngineMember $ruleJson "category")')")
        }
        $severity = @($severities | Where-Object { $_ -eq (Get-ReportEngineMember $ruleJson "severity") })[0]
        if (-not $severity) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.severity" -Problem "must be one of: $($severities -join ', ') (found '$(Get-ReportEngineMember $ruleJson "severity")')")
        }
        $references = Get-ReportEngineMember $ruleJson "references"
        if ($null -eq $references) { $references = @() }
        if ($references -is [string]) { $references = @($references) }
        if (-not ($references -is [array]) -or @($references | Where-Object { -not ($_ -is [string]) }).Count -gt 0) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.references" -Problem "must be an array of strings")
        }
        $maxEvidence = Get-ReportEngineMember $ruleJson "maxEvidence"
        if ($null -eq $maxEvidence) { $maxEvidence = 25 }
        if (-not (Test-ReportEngineInteger $maxEvidence) -or [int]$maxEvidence -lt 1 -or [int]$maxEvidence -gt 10000) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.maxEvidence" -Problem "must be a whole number from 1 to 10000")
        }
        # maxFindings: at most this many findings from the rule; the groups
        # beyond it fold into one roll-up finding (0 = no limit)
        $maxFindings = Get-ReportEngineMember $ruleJson "maxFindings"
        if ($null -eq $maxFindings) { $maxFindings = 20 }
        if (-not (Test-ReportEngineInteger $maxFindings) -or [int]$maxFindings -lt 0 -or [int]$maxFindings -eq 1 -or [int]$maxFindings -gt 10000) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.maxFindings" -Problem "must be 0 (no limit) or a whole number from 2 to 10000")
        }
        # activityTime false: the rule's row times are file times (which can be
        # old or forged), not activity times; the summary leaves them out of
        # the flagged-activity window
        $activityTime = Get-ReportEngineMember $ruleJson "activityTime"
        if ($null -eq $activityTime) { $activityTime = $true }
        if (-not ($activityTime -is [bool])) { throw (Format-ReportEngineRuleError -File $file -Where "$where.activityTime" -Problem "must be true or false") }
        $enabled = Get-ReportEngineMember $ruleJson "enabled"
        if ($null -eq $enabled) { $enabled = $true }
        if (-not ($enabled -is [bool])) { throw (Format-ReportEngineRuleError -File $file -Where "$where.enabled" -Problem "must be true or false") }

        # Conditions: match AND (at least one anyOf entry)
        $compiled = New-Object TimelineReport.CompiledRule
        $compiled.Id = $id
        $matchJson = Get-ReportEngineMember $ruleJson "match"
        $anyOfJson = Get-ReportEngineMember $ruleJson "anyOf"
        if ($null -ne $anyOfJson -and (-not ($anyOfJson -is [array]) -or $anyOfJson.Count -eq 0)) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.anyOf" -Problem "must be a non-empty array of match objects")
        }
        if ($null -eq $matchJson -and $null -eq $anyOfJson) {
            throw (Format-ReportEngineRuleError -File $file -Where $where -Problem "has no conditions: give ""match"" and/or ""anyOf""")
        }
        if ($null -ne $matchJson) {
            $compiled.Match = ConvertTo-ReportEngineMatchSpec -Object $matchJson -Lists $lists -File $file -Where "$where.match" -AllowEmpty:($null -ne $anyOfJson)
        }
        else {
            $compiled.Match = New-Object TimelineReport.MatchSpec
        }
        $anyOf = New-Object System.Collections.Generic.List[TimelineReport.MatchSpec]
        if ($null -ne $anyOfJson) {
            for ($a = 0; $a -lt $anyOfJson.Count; $a++) {
                $anyOf.Add((ConvertTo-ReportEngineMatchSpec -Object $anyOfJson[$a] -Lists $lists -File $file -Where "$where.anyOf[$a]"))
            }
        }
        $compiled.AnyOf = $anyOf.ToArray()

        $groupBy = Get-ReportEngineMember $ruleJson "groupBy"
        if ($null -eq $groupBy) { $groupBy = "rule" }
        $compiled.GroupBy = ConvertTo-ReportEngineKeySpec -Text $groupBy -Kinds $groupKinds -File $file -Where "$where.groupBy"
        if ($compiled.GroupBy.Kind -eq "capture" -and -not $compiled.Match.Description -and -not $compiled.Match.Details) {
            throw (Format-ReportEngineRuleError -File $file -Where "$where.groupBy" -Problem """capture"" groups by a capture of match.description (or match.details), which this rule does not have")
        }

        $threshold = $null
        $thresholdJson = Get-ReportEngineMember $ruleJson "threshold"
        if ($null -ne $thresholdJson) {
            if (-not (Test-ReportEngineJsonObject $thresholdJson)) { throw (Format-ReportEngineRuleError -File $file -Where "$where.threshold" -Problem "must be an object { ""count"": N, ""windowMinutes"": M }") }
            Assert-ReportEngineMembers -Object $thresholdJson -Allowed @("count", "windowMinutes") -File $file -Where "$where.threshold"
            $count = Get-ReportEngineMember $thresholdJson "count"
            $window = Get-ReportEngineMember $thresholdJson "windowMinutes"
            if (-not (Test-ReportEngineInteger $count) -or [int]$count -lt 1) { throw (Format-ReportEngineRuleError -File $file -Where "$where.threshold.count" -Problem "must be a whole number of 1 or more") }
            if (-not (Test-ReportEngineNumber $window) -or [double]$window -le 0) { throw (Format-ReportEngineRuleError -File $file -Where "$where.threshold.windowMinutes" -Problem "must be a number greater than 0") }
            $compiled.ThresholdCount = [int]$count
            $compiled.ThresholdWindowTicks = [long]([double]$window * [TimeSpan]::TicksPerMinute)
            $threshold = [PSCustomObject]@{ Count = [int]$count; WindowMinutes = [double]$window }
        }

        $escalate = $null
        $escalateJson = Get-ReportEngineMember $ruleJson "escalate"
        if ($null -ne $escalateJson) {
            if (-not (Test-ReportEngineJsonObject $escalateJson)) { throw (Format-ReportEngineRuleError -File $file -Where "$where.escalate" -Problem "must be an object") }
            Assert-ReportEngineMembers -Object $escalateJson -Allowed @("severity", "withinMinutes", "sameKey", "match") -File $file -Where "$where.escalate"
            $escalateSeverity = @($severities | Where-Object { $_ -eq (Get-ReportEngineMember $escalateJson "severity") })[0]
            if (-not $escalateSeverity) { throw (Format-ReportEngineRuleError -File $file -Where "$where.escalate.severity" -Problem "must be one of: $($severities -join ', ')") }
            $within = Get-ReportEngineMember $escalateJson "withinMinutes"
            if (-not (Test-ReportEngineNumber $within) -or [double]$within -le 0) { throw (Format-ReportEngineRuleError -File $file -Where "$where.escalate.withinMinutes" -Problem "must be a number greater than 0") }
            $sameKey = Get-ReportEngineMember $escalateJson "sameKey"
            if ($null -eq $sameKey) { $sameKey = "none" }
            $escalateMatch = Get-ReportEngineMember $escalateJson "match"
            if ($null -eq $escalateMatch) { throw (Format-ReportEngineRuleError -File $file -Where "$where.escalate.match" -Problem "is required") }
            $compiled.EscalateMatch = ConvertTo-ReportEngineMatchSpec -Object $escalateMatch -Lists $lists -File $file -Where "$where.escalate.match"
            $compiled.EscalateWindowTicks = [long]([double]$within * [TimeSpan]::TicksPerMinute)
            $compiled.EscalateKey = ConvertTo-ReportEngineKeySpec -Text $sameKey -Kinds $sameKeyKinds -File $file -Where "$where.escalate.sameKey"
            $escalate = [PSCustomObject]@{ Severity = $escalateSeverity; WithinMinutes = [double]$within; SameKey = $sameKey }
        }

        $rules.Add([PSCustomObject]@{
            Id             = $id
            Title          = $texts["title"]
            Category       = $category
            Severity       = $severity
            Why            = $texts["why"]
            Technical      = $texts["technical"]
            NextSteps      = $texts["nextSteps"]
            FalsePositives = $texts["falsePositives"]
            References     = [string[]]@($references)
            GroupBy        = $groupBy
            Threshold      = $threshold
            Escalate       = $escalate
            MaxEvidence    = [int]$maxEvidence
            MaxFindings    = [int]$maxFindings
            ActivityTime   = $activityTime
            Enabled        = $enabled
            Compiled       = $compiled
        })
    }

    # --- Allowlist: rows that are known benign for one rule (or "*" = all) ---
    $allowlist = New-Object System.Collections.Generic.List[object]
    $allowlistJson = Get-ReportEngineMember $json "allowlist"
    if ($null -ne $allowlistJson) {
        if (-not ($allowlistJson -is [array])) { throw (Format-ReportEngineRuleError -File $file -Where "allowlist" -Problem "must be an array") }
        for ($n = 0; $n -lt $allowlistJson.Count; $n++) {
            $entry = $allowlistJson[$n]
            $where = "allowlist[$n]"
            if (-not (Test-ReportEngineJsonObject $entry)) { throw (Format-ReportEngineRuleError -File $file -Where $where -Problem "must be an object") }
            Assert-ReportEngineMembers -Object $entry -Allowed @("ruleId", "match", "reason", "comment") -File $file -Where $where
            $ruleId = Get-ReportEngineMember $entry "ruleId"
            if (-not ($ruleId -is [string]) -or -not $ruleId) { throw (Format-ReportEngineRuleError -File $file -Where "$where.ruleId" -Problem "is required (a rule id, or ""*"" for every rule)") }
            if ($ruleId -ne "*") {
                $known = @($rules | Where-Object { $_.Id -eq $ruleId })[0]
                if (-not $known) { throw (Format-ReportEngineRuleError -File $file -Where "$where.ruleId" -Problem "no rule has the id '$ruleId'") }
                $ruleId = $known.Id
            }
            $where = "allowlist[$n] (ruleId '$ruleId')"
            $reason = Get-ReportEngineMember $entry "reason"
            if (-not ($reason -is [string]) -or -not $reason.Trim()) { throw (Format-ReportEngineRuleError -File $file -Where "$where.reason" -Problem "is required (why these rows are benign)") }
            $matchJson = Get-ReportEngineMember $entry "match"
            if ($null -eq $matchJson) { throw (Format-ReportEngineRuleError -File $file -Where "$where.match" -Problem "is required") }
            $spec = ConvertTo-ReportEngineMatchSpec -Object $matchJson -Lists $lists -File $file -Where "$where.match"
            $allowlist.Add([PSCustomObject]@{ Index = $n; RuleId = $ruleId; Reason = $reason.Trim(); Match = $spec })
        }
    }
    foreach ($rule in $rules) {
        $entries = @($allowlist | Where-Object { $_.RuleId -eq "*" -or $_.RuleId -eq $rule.Id })
        $rule.Compiled.Allowlist = [TimelineReport.MatchSpec[]]@($entries | ForEach-Object { $_.Match })
        $rule | Add-Member -NotePropertyName AllowlistEntries -NotePropertyValue ([object[]]$entries)
    }

    return [PSCustomObject]@{
        SchemaVersion = 1
        Path          = $fullPath
        Rules         = $rules.ToArray()
        Allowlist     = $allowlist.ToArray()
        Lists         = $listValues
    }
}

# =============================================================
# Rule evaluation
# =============================================================

# Row table for a row list. Kept for the last list, so Invoke-ReportRules
# and New-ReportModel on the same rows read them once.
function Get-ReportEngineRowTable {
    param([System.Collections.IList]$Rows)
    if ($null -eq $Rows) { $Rows = @() }
    $cache = $script:ReportEngineRowTableCache
    if ($null -ne $cache -and [object]::ReferenceEquals($cache.Rows, $Rows) -and $cache.Table.Count -eq $Rows.Count) {
        return $cache.Table
    }
    $table = [TimelineReport.RowTable]::Build($Rows)
    $script:ReportEngineRowTableCache = @{ Rows = $Rows; Table = $table }
    return $table
}

# The first non-empty member of collection info, or $null. The builder's
# Get-CollectionInfo object, the parsed collection_info.json, a hashtable or
# an earlier model's Collection all work.
function Get-ReportEngineInfoValue {
    param($Info, [string[]]$Names)
    if ($null -eq $Info) { return $null }
    foreach ($name in $Names) {
        $value = $null
        if ($Info -is [System.Collections.IDictionary]) {
            if ($Info.Contains($name)) { $value = $Info[$name] }
        }
        else {
            $property = $Info.PSObject.Properties[$name]
            if ($property) { $value = $property.Value }
        }
        if ($null -ne $value -and "$value" -ne "") { return , $value }
    }
    return $null
}

# Collection start (UTC [datetime]) from collection info, or $null
function Get-ReportEngineCollectionStart {
    param($CollectionInfo)
    $value = Get-ReportEngineInfoValue $CollectionInfo @("CollectionStartUtc")
    if ($null -eq $value) { return $null }
    if ($value -is [datetime]) {
        if ($value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($value, [System.DateTimeKind]::Utc) }
        return $value.ToUniversalTime()
    }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertFrom-ReportEngineTicks {
    param([long]$Ticks)
    if ($Ticks -lt 0) { return $null }
    return [datetime]::new($Ticks, [System.DateTimeKind]::Utc)
}

# Text cut to a length for the report (the full value stays in the timeline)
function Limit-ReportEngineText {
    param([string]$Text, [int]$Max)
    if ($null -eq $Text -or $Text.Length -le $Max) { return $Text }
    $cut = $Max
    if ([char]::IsHighSurrogate($Text[$cut - 1])) { $cut-- }
    return $Text.Substring(0, $cut) + " [...]"
}

# One timeline row for the report, with its Excel row number
function New-ReportEngineRowObject {
    param($Table, [int]$Index, [bool]$Escalation = $false)
    $row = $Table.Rows[$Index]
    return [PSCustomObject]@{
        RowNumber   = $Index + 2
        Timestamp   = $Table.Timestamp[$Index]
        Source      = $Table.Sources[$Table.SourceId[$Index]]
        EventType   = $Table.EventTypes[$Table.EventTypeId[$Index]]
        Description = Limit-ReportEngineText $Table.Description[$Index] 1000
        User        = $Table.Users[$Table.UserId[$Index]]
        Details     = Limit-ReportEngineText $Table.Details[$Index] 2000
        Artifact    = [TimelineReport.RowTable]::FieldText($row, "Artifact")
        RawPath     = [TimelineReport.RowTable]::FieldText($row, "RawPath")
        Escalation  = $Escalation
    }
}

function Get-ReportEngineSeverityRank {
    param([string]$Severity)
    switch ($Severity) { "High" { return 3 } "Medium" { return 2 } default { return 1 } }
}

<#
.SYNOPSIS
Runs the imported rules over the timeline rows and returns the findings.
.DESCRIPTION
Rows must be in final timeline order: row i (0-based) is Excel row i + 2 on
the Timeline sheet. Findings are numbered F001... after sorting High, Medium,
Info, then by first time. Output: the findings (High, Medium and Info), one
object each. -Statistics (a hashtable) receives per-rule counts and timings.
#>
function Invoke-ReportRules {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][System.Collections.IList]$Rows,
        [Parameter(Mandatory = $true)]$Rules,
        $CollectionInfo,
        [hashtable]$Statistics
    )
    if ($null -eq $Rules -or -not $Rules.PSObject.Properties["Rules"] -or $Rules.SchemaVersion -ne 1) {
        throw "Invoke-ReportRules: -Rules must be the result of Import-ReportRules"
    }
    $table = Get-ReportEngineRowTable -Rows $Rows
    $collectionStart = Get-ReportEngineCollectionStart $CollectionInfo
    $startTicks = if ($collectionStart) { $collectionStart.Ticks } else { [long]-1 }

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $Rules.Rules) {
        if (-not $rule.Enabled) { continue }
        $result = [TimelineReport.Engine]::Evaluate($table, $rule.Compiled, $startTicks)
        if ($result.Abandoned) {
            Write-Warning "Report rule $($rule.Id) was stopped and reports nothing: $($result.Abandoned). Fix or disable its pattern in the rules file."
        }
        elseif ($result.RegexTimeouts -gt 0) {
            Write-Warning "Report rule $($rule.Id): $($result.RegexTimeouts) regular expression match(es) timed out; those rows were not flagged."
        }
        $groupsBeforeFold = $result.Groups.Count
        [TimelineReport.Engine]::Fold($table, $result, $rule.MaxFindings)
        foreach ($group in $result.Groups) {
            [TimelineReport.Engine]::Summarize($table, $group, $rule.MaxEvidence)
            $severity = $rule.Severity
            $escalated = $group.EscalationRows.Count -gt 0
            if ($escalated -and (Get-ReportEngineSeverityRank $rule.Escalate.Severity) -gt (Get-ReportEngineSeverityRank $severity)) {
                $severity = $rule.Escalate.Severity
            }
            $escalationRows = New-Object 'System.Collections.Generic.HashSet[int]'
            foreach ($index in $group.EscalationRows) { [void]$escalationRows.Add($index) }
            $evidence = @(foreach ($index in $group.EvidenceRows) { New-ReportEngineRowObject -Table $table -Index $index -Escalation $escalationRows.Contains($index) })
            $groupKey = $group.Key
            $title = $rule.Title.Replace("{{group}}", $groupKey)
            $why = $rule.Why.Replace("{{group}}", $groupKey)
            $foldedKeys = [string[]]@()
            if ($group.FoldedGroups -gt 0) {
                # The roll-up of the groups beyond maxFindings: its key lists
                # the folded values (most rows first), shortened for display
                $foldedKeys = [string[]]@($group.FoldedKeys | Select-Object -First 200)
                $shown = @($group.FoldedKeys | Select-Object -First 20 | ForEach-Object { if ("$_") { Limit-ReportEngineText "$_" 120 } else { "(blank)" } })
                $groupKey = "$($group.FoldedGroups) more: " + ($shown -join ", ")
                if ($group.FoldedGroups -gt $shown.Count) { $groupKey += ", ..." }
                $label = "$($group.FoldedGroups) more, folded into one lead"
                if ($rule.Title.Contains("{{group}}")) { $title = $rule.Title.Replace("{{group}}", $label) } else { $title = "$($rule.Title) ($label)" }
                $why = $rule.Why.Replace("{{group}}", "several") + " This lead folds together $($group.FoldedGroups) more groups of the rule (it keeps at most $($rule.MaxFindings) leads); every row is in the Findings sheet and findings.csv."
            }
            # Every row from the collection start on: maybe the collector's
            # own activity. When every row is a Snapshot row (the state seen
            # when the evidence was collected, such as a task listed then),
            # its time is when it was seen, not when it happened:
            # CapturedDuringCollection instead. A lead whose rows all come
            # from the memory dump (Memory-* sources, whatever their event
            # type) is MemoryOnly and says just that ($script:ReportMemoryOnlyNote),
            # not CapturedDuringCollection. DuringCollection stays: it comes
            # from a time Windows recorded (a process's creation time in the dump).
            $fromCollection = ($startTicks -ge 0 -and $group.FirstTicks -ge $startTicks)
            $memoryOnly = [bool]$group.MemoryOnly
            $findings.Add([PSCustomObject]@{
                Id                       = ""
                RuleId                   = $rule.Id
                Title                    = $title
                Category                 = $rule.Category
                Severity                 = $severity
                Why                      = $why
                Technical                = $rule.Technical
                NextSteps                = $rule.NextSteps
                FalsePositives           = $rule.FalsePositives
                References               = $rule.References
                GroupKey                 = $groupKey
                Count                    = $group.Rows.Count
                FirstSeenUtc             = ConvertFrom-ReportEngineTicks $group.FirstTicks
                LastSeenUtc              = ConvertFrom-ReportEngineTicks $group.LastTicks
                Evidence                 = [object[]]$evidence
                EvidenceTruncated        = $group.AllRows.Length -gt $group.EvidenceRows.Length
                Escalated                = $escalated
                AllowlistedCount         = $group.Allowlisted
                BaseSeverity             = $rule.Severity
                EscalationCount          = $group.EscalationRows.Count
                RowNumbers               = $group.RowNumbers
                DuringCollection         = ($fromCollection -and -not $group.SnapshotOnly)
                CapturedDuringCollection = ($fromCollection -and $group.SnapshotOnly -and -not $memoryOnly)
                MemoryOnly               = $memoryOnly
                MemoryOnlyNote           = $(if ($memoryOnly) { $script:ReportMemoryOnlyNote } else { "" })
                # A lead whose only times are a task author's dates is not
                # dated by activity either (left out of the activity window)
                ActivityTime             = ([bool]$rule.ActivityTime -and -not $group.AuthorTimesOnly)
                TimesAuthorSupplied      = [bool]$group.AuthorTimesOnly
                FoldedGroups             = $group.FoldedGroups
                FoldedKeys               = $foldedKeys
            })
        }
        if ($null -ne $Statistics) {
            $allowlisted = @(for ($e = 0; $e -lt $result.AllowlistedPerEntry.Length; $e++) {
                if ($result.AllowlistedPerEntry[$e] -gt 0) {
                    [PSCustomObject]@{ RuleId = $rule.Id; Reason = $rule.AllowlistEntries[$e].Reason; Rows = $result.AllowlistedPerEntry[$e] }
                }
            })
            $Statistics[$rule.Id] = [PSCustomObject]@{
                RuleId          = $rule.Id
                MatchedRows     = $result.MatchedRows
                AllowlistedRows = $result.AllowlistedRows
                Findings        = $result.Groups.Count
                Groups          = $groupsBeforeFold
                Milliseconds    = [Math]::Round($result.Milliseconds, 1)
                RegexTimeouts   = $result.RegexTimeouts
                Abandoned       = [string]$result.Abandoned
                Allowlisted     = [object[]]$allowlisted
            }
        }
    }

    # Number after sorting: High, Medium, Info, then first time, rule, group
    $sorted = @($findings | Sort-Object -Property `
        @{ Expression = { - (Get-ReportEngineSeverityRank $_.Severity) } },
        @{ Expression = { if ($_.FirstSeenUtc) { $_.FirstSeenUtc.Ticks } else { [long]::MaxValue } } },
        @{ Expression = { $_.RuleId } },
        @{ Expression = { $_.GroupKey } })
    for ($i = 0; $i -lt $sorted.Count; $i++) { $sorted[$i].Id = "F{0:D3}" -f ($i + 1) }
    return $sorted
}

<#
.SYNOPSIS
Excel row number -> finding ids ("F001, F004") for the Timeline sheet's
Finding column. Pass the findings to show (e.g. only High and Medium).
#>
function Get-ReportFindingRowMap {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][object[]]$Findings)
    $map = New-Object 'System.Collections.Generic.Dictionary[int,string]'
    foreach ($finding in $Findings) {
        if ($null -eq $finding) { continue }
        foreach ($rowNumber in $finding.RowNumbers) {
            if ($map.ContainsKey($rowNumber)) { $map[$rowNumber] = $map[$rowNumber] + ", " + $finding.Id }
            else { $map[$rowNumber] = $finding.Id }
        }
    }
    return $map
}

# =============================================================
# findings.csv and timeline.csv
# =============================================================

<#
.SYNOPSIS
Writes findings.csv: per finding, a summary line (RowNumber blank) and one
line per evidence row. UTF-8 with BOM (so Excel reads it as UTF-8), CRLF.
A value Excel would read as a formula gets a leading apostrophe.
#>
function Export-ReportFindingsCsv {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $columns = @("FindingId", "Severity", "RuleId", "Title", "Category", "RowNumber", "Timestamp", "Source", "Description")
    $writer = New-Object System.IO.StreamWriter($fullPath, $false, (New-Object System.Text.UTF8Encoding($true)))
    try {
        $writer.NewLine = "`r`n"
        $writer.WriteLine([TimelineReport.CsvText]::Line([object[]]$columns))
        foreach ($finding in $Findings) {
            if ($null -eq $finding) { continue }
            $first = if ($finding.FirstSeenUtc) { $finding.FirstSeenUtc.ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture) } else { "" }
            $last = if ($finding.LastSeenUtc) { $finding.LastSeenUtc.ToString("yyyy-MM-dd HH:mm:ss.fff", [System.Globalization.CultureInfo]::InvariantCulture) } else { "" }
            $summary = "Summary: $($finding.Count) matching row(s), $first to $last UTC"
            if ($finding.GroupKey) { $summary += "; group: $($finding.GroupKey)" }
            if ($finding.Escalated) { $summary += "; escalated by $($finding.EscalationCount) related row(s)" }
            if ($finding.EvidenceTruncated) { $summary += "; first $(@($finding.Evidence).Count) rows listed" }
            if ($finding.AllowlistedCount) { $summary += "; $($finding.AllowlistedCount) allowlisted row(s) not counted" }
            if ($finding.MemoryOnly) { $summary += "; $script:ReportMemoryOnlyNote" }
            $lead = @($finding.Id, $finding.Severity, $finding.RuleId, $finding.Title, $finding.Category)
            $writer.WriteLine([TimelineReport.CsvText]::Line([object[]]($lead + @("", $first, "", $summary))))
            foreach ($row in $finding.Evidence) {
                $writer.WriteLine([TimelineReport.CsvText]::Line([object[]]($lead + @($row.RowNumber, $row.Timestamp, $row.Source, $row.Description))))
            }
        }
    }
    finally {
        $writer.Dispose()
    }
}

<#
.SYNOPSIS
Reads timeline.csv for -ReportOnly: one object per row with the CSV's
columns (like Import-Csv, but streaming in C#; fields may contain line
breaks). Rows keep the file's order, so row i is Excel row i + 2.
#>
function Import-TimelineCsvForReport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "Timeline CSV not found: $fullPath" }
    $rows = [TimelineReport.CsvReader]::ReadRows($fullPath)
    if ($rows.Length -gt 0) {
        foreach ($column in @("Timestamp", "Source", "EventType", "Description")) {
            if (-not $rows[0].PSObject.Properties[$column]) { throw "Not a timeline CSV (no $column column): $fullPath" }
        }
    }
    return $rows
}

# =============================================================
# Report model
# =============================================================

# Text of a log file that may still be open for writing (UTF-8, or the ANSI
# code page when the bytes are not valid UTF-8: Windows PowerShell's
# Add-Content writes ANSI)
function Read-ReportEngineLogText {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        $bytes = $memory.ToArray()
    }
    finally { $stream.Dispose() }
    $start = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    try { return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes, $start, $bytes.Length - $start) }
    catch {
        try { $ansi = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage) }
        catch { $ansi = [System.Text.Encoding]::GetEncoding(28591) }
        return $ansi.GetString($bytes, $start, $bytes.Length - $start)
    }
}

# What the report needs from the collector's collection_log.txt
function Read-ReportEngineCollectorLog {
    param([string]$Path)
    $info = [PSCustomObject]@{ Available = $false; Computer = ""; User = ""; OS = ""; Live = $null; ErrorCount = $null; ProblemLines = @() }
    $text = Read-ReportEngineLogText $Path
    if ($null -eq $text) { return $info }
    $info.Available = $true
    $problems = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($text -split "\r?\n")) {
        if ($line -match '^\[[^\]]*\] (?:ERROR|WARNING): ') { $problems.Add($line.TrimEnd()) }
        elseif ($line -match '^\[[^\]]*\] Mode: (LIVE SYSTEM|MOUNTED IMAGE)') { $info.Live = ($Matches[1] -eq "LIVE SYSTEM") }
        elseif ($line -match '^\[[^\]]*\] Computer: (.+?)(?: \(collector host\))?\s*$') { $info.Computer = $Matches[1] }
        elseif ($line -match '^\[[^\]]*\] User: (.+?)\s*$') { $info.User = $Matches[1] }
        elseif ($line -match '^\[[^\]]*\] OS: (.+?)\s*$' -and $Matches[1] -notmatch '^\(') { $info.OS = $Matches[1] }
        elseif ($line -match '^\[[^\]]*\]\s+Errors:\s+(\d+)\s*$') { $info.ErrorCount = [int]$Matches[1] }
    }
    $info.ProblemLines = $problems.ToArray()
    return $info
}

# What the report needs from the builder's timeline_builder_log.txt. A run
# that ends with exit code 2 (timeline incomplete) logs each problem when it
# happens ("ERROR: N of M input file(s) disappeared during the run",
# "ERROR: Unexpected error at line N") and the end banner ("Timeline
# Builder Completed WITH N MISSING INPUT FILE(S)" / "... UNEXPECTED
# ERROR(S)"). The banner is written after the report of that run, so a full
# run counts the problem lines; -ReportOnly reads the banner too, and the
# larger count is kept.
function Read-ReportEngineBuilderLog {
    param([string]$Path)
    $info = [PSCustomObject]@{
        Available = $false; Sources = ""; StartDate = ""; EndDate = ""; MftDays = $null; UsnDropped = $false; ProblemLines = @()
        MissingInputFiles = 0; UnexpectedErrors = 0; UnnamedSids = 0; ExaminedComputerName = ""
        # A memory dump of the collection that the run did not analyze: what
        # and why ("" when there is none, or it was analyzed)
        MemoryDumpNotAnalyzed = ""
    }
    $text = Read-ReportEngineLogText $Path
    if ($null -eq $text) { return $info }
    $info.Available = $true
    $problems = New-Object System.Collections.Generic.List[string]
    $missingLogged = 0
    $missingBanner = 0
    $errorLines = 0
    $errorBanner = 0
    foreach ($line in ($text -split "\r?\n")) {
        if ($line -match '^\[[^\]]*\] (?:ERROR|WARNING): ') { $problems.Add($line.TrimEnd()) }
        if ($line -match '^\[[^\]]*\] Sources\s+: (.+?)\s*$') { $info.Sources = $Matches[1] }
        elseif ($line -match '^\[[^\]]*\] Start Date : (.+?)\s*$') { $info.StartDate = $Matches[1] }
        elseif ($line -match '^\[[^\]]*\] End Date\s+: (.+?)\s*$') { $info.EndDate = $Matches[1] }
        elseif ($line -match 'Window: times from .+ UTC, (\d+) day\(s\) before') { $info.MftDays = [int]$Matches[1] }
        elseif ($line -match '-MftDays 0: all') { $info.MftDays = 0 }
        elseif ($line -match 'Dropped the \d+ oldest USN entries') { $info.UsnDropped = $true }
        elseif ($line -match '^\[[^\]]*\] ERROR: (\d+) of \d+ input file\(s\) disappeared during the run') { $missingLogged = [Math]::Max($missingLogged, [int]$Matches[1]) }
        elseif ($line -match '^\[[^\]]*\] ERROR: Unexpected error at line \d+') { $errorLines++ }
        elseif ($line -match 'Timeline Builder (?:Completed|Finished) WITH (\d+) MISSING INPUT FILE\(S\)') { $missingBanner = [Math]::Max($missingBanner, [int]$Matches[1]) }
        elseif ($line -match 'Timeline Builder (?:Completed|Finished) WITH (\d+) UNEXPECTED ERROR\(S\)') { $errorBanner = [Math]::Max($errorBanner, [int]$Matches[1]) }
        elseif ($line -match '^\[[^\]]*\]\s+User column: (\d+) SID\(s\) not named') { $info.UnnamedSids = [int]$Matches[1] }
        elseif (-not $info.ExaminedComputerName -and $line -match '^\[[^\]]*\]\s+Examined computer name \(SYSTEM hive\): (.+?)\s*$') { $info.ExaminedComputerName = $Matches[1] }
        elseif (-not $info.MemoryDumpNotAnalyzed -and $line -match '^\[[^\]]*\]\s+Memory dump not analyzed: (.+?)\s*$') { $info.MemoryDumpNotAnalyzed = $Matches[1] }
    }
    $info.ProblemLines = $problems.ToArray()
    $info.MissingInputFiles = [Math]::Max($missingLogged, $missingBanner)
    $info.UnexpectedErrors = [Math]::Max($errorLines, $errorBanner)
    return $info
}

function New-ReportEngineMatch {
    param([string]$Source, [string]$EventType, [string]$Description)
    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $spec = New-Object TimelineReport.MatchSpec
    if ($Source) { $spec.Source = [System.Text.RegularExpressions.Regex]::new($Source, $options) }
    if ($EventType) { $spec.EventType = [System.Text.RegularExpressions.Regex]::new($EventType, $options) }
    if ($Description) { $spec.Description = [System.Text.RegularExpressions.Regex]::new($Description, $options) }
    return $spec
}

function Find-ReportEngineRows {
    param($Table, [string]$Source, [string]$EventType, [string]$Description)
    return , [TimelineReport.Engine]::FindRows($Table, (New-ReportEngineMatch -Source $Source -EventType $EventType -Description $Description), [long]-1)
}

function Format-ReportEngineUtc {
    param($Value)
    if ($null -eq $Value) { return "unknown" }
    return $Value.ToString("yyyy-MM-dd HH:mm", [System.Globalization.CultureInfo]::InvariantCulture) + " UTC"
}

function Format-ReportEngineSpan {
    param([long]$Ticks)
    $span = [TimeSpan]::FromTicks($Ticks)
    if ($span.TotalHours -lt 48) { return "{0:0.#} hours" -f $span.TotalHours }
    return "{0:0.#} days" -f $span.TotalDays
}

# SHA-256 of a file that may be open in another program
function Get-ReportEngineFileHash {
    param([string]$Path)
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "") }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

<#
.SYNOPSIS
Builds the report model from the timeline rows and the findings.
.DESCRIPTION
CollectionInfo may be the builder's Get-CollectionInfo object, the parsed
collection_info.json, the builder's report view of it
(Get-TimelineReportCollectionInfo), or the Collection of an earlier report
model; fields it lacks are taken from -CollectorLogPath (collection_log.txt),
-BuilderLogPath and the SystemInfo rows. Call it after the workbook is final
(its hash is recorded).

The computer named in the report is the examined one. collection_info.json's
ComputerName is the computer the collector ran on: the examined one only in
a live collection. For a mounted image it is used only when the info says
where it came from (ComputerNameSource, as the builder's report view and a
model's Collection do); otherwise it is the collector host (CollectorHost),
and the examined computer's name comes from ExaminedComputerName (the image's
SYSTEM hive, also read from the builder log) or the SystemInfo rows. When it
is not known, ComputerName is empty and the report says why.
#>
function New-ReportModel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][System.Collections.IList]$Rows,
        [AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        $CollectionInfo,
        [string]$CollectorLogPath,
        [string]$BuilderLogPath,
        [string]$TimelinePath,
        [string]$WorkbookPath,
        [switch]$WorkbookAvailable,
        # Imported rules (for the appendix's list of rules)
        $Rules,
        # The -Statistics hashtable filled by Invoke-ReportRules (allowlisted rows)
        [hashtable]$RuleStatistics,
        [string]$FindingsCsvPath,
        # -MftDays of the run (-1 = unknown: read from the builder log)
        [int]$MftDays = -1,
        # The collection folder or zip (a zip is hashed for the appendix)
        [string]$CollectionPath,
        # Input files that disappeared during the builder run and unexpected
        # errors it caught (exit code 2: timeline incomplete). The larger of
        # these and the builder log's counts is used.
        [int]$MissingInputFiles = 0,
        [int]$UnexpectedErrors = 0
    )
    $table = Get-ReportEngineRowTable -Rows $Rows
    $collectorLog = Read-ReportEngineCollectorLog $CollectorLogPath
    $builderLog = Read-ReportEngineBuilderLog $BuilderLogPath
    if ($MftDays -lt 0 -and $null -ne $builderLog.MftDays) { $MftDays = $builderLog.MftDays }
    $missingInputs = [Math]::Max([Math]::Max(0, $MissingInputFiles), [int]$builderLog.MissingInputFiles)
    $unexpectedErrors = [Math]::Max([Math]::Max(0, $UnexpectedErrors), [int]$builderLog.UnexpectedErrors)

    # --- Collection facts ---
    $zoneId = Get-ReportEngineInfoValue $CollectionInfo @("TargetTimeZoneId", "TargetTimeZone")
    if ($zoneId -is [System.TimeZoneInfo]) { $zoneId = $zoneId.Id }
    $zone = $null
    if ($zoneId) {
        try { $zone = [System.TimeZoneInfo]::FindSystemTimeZoneById([string]$zoneId) } catch { $zone = $null }
    }
    $collectionStart = Get-ReportEngineCollectionStart $CollectionInfo
    $mode = [string](Get-ReportEngineInfoValue $CollectionInfo @("Mode"))
    if (-not $mode -and $null -ne $collectorLog.Live) { $mode = if ($collectorLog.Live) { "Live" } else { "MountedImage" } }
    $live = (-not $mode -or $mode -eq "Live")

    # The examined computer (see .DESCRIPTION)
    $systemInfo = @(Find-ReportEngineRows -Table $table -Source '^SystemInfo$' -Description '^System: ')
    $systemDetails = if ($systemInfo.Count -gt 0) { $table.Details[$systemInfo[$systemInfo.Count - 1]] } else { "" }
    $infoComputer = [string](Get-ReportEngineInfoValue $CollectionInfo @("ComputerName"))
    $infoComputerSource = [string](Get-ReportEngineInfoValue $CollectionInfo @("ComputerNameSource"))
    $collectorHost = [string](Get-ReportEngineInfoValue $CollectionInfo @("CollectorHost"))
    $hiveComputer = [string](Get-ReportEngineInfoValue $CollectionInfo @("ExaminedComputerName"))
    if (-not $hiveComputer) { $hiveComputer = $builderLog.ExaminedComputerName }
    $computer = ""
    $computerSource = ""
    if ($infoComputer -and ($live -or $infoComputerSource)) {
        $computer = $infoComputer
        $computerSource = if ($infoComputerSource) { $infoComputerSource } else { "collection_info.json" }
    }
    elseif ($infoComputer -and -not $collectorHost) { $collectorHost = $infoComputer }
    if (-not $computer -and $hiveComputer) { $computer = $hiveComputer; $computerSource = "SYSTEM hive" }
    if (-not $computer) {
        $computer = [TimelineReport.DetailParser]::Get($systemDetails, "Host")
        if ($computer) { $computerSource = "systeminfo.txt" }
    }
    # The log's computer is the collector host: the examined one only when live
    if (-not $computer -and $mode -eq "Live" -and $collectorLog.Computer) { $computer = $collectorLog.Computer; $computerSource = "collection_log.txt" }
    if (-not $live -and -not $collectorHost -and $collectorLog.Computer) { $collectorHost = $collectorLog.Computer }
    if ($live) { $collectorHost = "" }

    # Rows per user: an older timeline's HOST\alice (the examined computer's
    # own name) counts with alice
    $localDomains = [string[]]@(@($computer, $hiveComputer) | Where-Object { $_ })
    $stats = [TimelineReport.Stats]::Compute($table, $zone, $localDomains)
    $os = [string](Get-ReportEngineInfoValue $CollectionInfo @("OS"))
    if (-not $os -and $systemDetails) {
        $os = [TimelineReport.DetailParser]::Get($systemDetails, "OS")
        $build = [TimelineReport.DetailParser]::Get($systemDetails, "Build")
        if ($os -and $build) { $os += " (build $build)" }
    }
    if (-not $os -and $mode -eq "Live") { $os = $collectorLog.OS }
    $collectorUser = [string](Get-ReportEngineInfoValue $CollectionInfo @("CollectorUser"))
    if (-not $collectorUser) { $collectorUser = $collectorLog.User }
    # A live collection's local account (HOST\examiner or .\examiner) as the
    # timeline's User column names it: examiner
    if ($live -and $collectorUser -match '^([^\\]+)\\(.+)$' -and ($Matches[1] -eq "." -or ($computer -and $Matches[1] -eq $computer))) {
        $collectorUser = $Matches[2]
    }
    # The accounts as the timeline's User column names them (CORP\alice and
    # a local alice are different accounts)
    $users = @(Get-ReportEngineInfoValue $CollectionInfo @("Users"))
    if ($users.Count -eq 0 -or $null -eq $users[0]) {
        $users = @($stats.Users | Where-Object { -not $_.IsSystem -and $_.Name -notmatch '^S-1-\d' } | Select-Object -First 20 | ForEach-Object { $_.Name })
    }
    $secrets = [bool](Get-ReportEngineInfoValue $CollectionInfo @("SecretsIncluded"))
    $thunderbird = [bool](Get-ReportEngineInfoValue $CollectionInfo @("ThunderbirdIndexIncluded"))
    # The builder assumes the collecting computer's zone when the collection
    # does not record the examined computer's (older collections, images)
    $zoneAssumed = [bool]$zoneId -and [bool](Get-ReportEngineInfoValue $CollectionInfo @("TargetTimeZoneAssumed"))
    $collection = [PSCustomObject]@{
        # The examined computer ("" when not known), where its name came
        # from, and for a mounted image the computer the collector ran on
        ComputerName             = $computer
        ComputerNameSource       = $computerSource
        CollectorHost            = $collectorHost
        OS                       = $os
        Users                    = [string[]]@($users)
        Mode                     = $mode
        TargetTimeZoneId         = if ($zoneId) { [string]$zoneId } else { "" }
        TargetTimeZoneAssumed    = $zoneAssumed
        CollectionStartUtc       = $collectionStart
        CollectorUser            = $collectorUser
        SecretsIncluded          = $secrets
        ThunderbirdIndexIncluded = $thunderbird
    }

    # --- Findings ---
    $all = @($Findings | Where-Object { $null -ne $_ })
    $leads = @($all | Where-Object { $_.Severity -eq "High" -or $_.Severity -eq "Medium" })
    $info = @($all | Where-Object { $_.Severity -ne "High" -and $_.Severity -ne "Medium" })
    $highCount = @($leads | Where-Object { $_.Severity -eq "High" }).Count
    # The flagged-activity window leaves out leads dated by file times
    # (activityTime false: timestomp candidates, Amcache/ShimCache entries)
    $timedLeads = @($leads | Where-Object { -not ($_.PSObject.Properties["ActivityTime"] -and $_.ActivityTime -eq $false) })
    $leadFirst = $timedLeads | Where-Object { $_.FirstSeenUtc } | ForEach-Object { $_.FirstSeenUtc } | Sort-Object | Select-Object -First 1
    $leadLast = $timedLeads | Where-Object { $_.LastSeenUtc } | ForEach-Object { $_.LastSeenUtc } | Sort-Object -Descending | Select-Object -First 1
    # Top leads: the first lead of each rule (High first, then by time), then
    # the next ones, so one rule cannot fill the summary page. Within a
    # severity, leads dated by file times come last: an old or forged file
    # time would otherwise put them first.
    $leadOrder = @{}
    for ($i = 0; $i -lt $leads.Count; $i++) { $leadOrder[[string]$leads[$i].Id] = $i }
    $candidates = @($leads | Sort-Object -Property @{ Expression = { - (Get-ReportEngineSeverityRank $_.Severity) } },
        @{ Expression = { if ($_.PSObject.Properties["ActivityTime"] -and $_.ActivityTime -eq $false) { 1 } else { 0 } } },
        @{ Expression = { $leadOrder[[string]$_.Id] } })
    $topIds = New-Object System.Collections.Generic.List[string]
    $topRules = @{}
    foreach ($lead in $candidates) {
        if ($topIds.Count -ge 5) { break }
        if ($topRules.ContainsKey([string]$lead.RuleId)) { continue }
        $topRules[[string]$lead.RuleId] = $true
        $topIds.Add([string]$lead.Id)
    }
    foreach ($lead in $candidates) {
        if ($topIds.Count -ge 5) { break }
        if (-not $topIds.Contains([string]$lead.Id)) { $topIds.Add([string]$lead.Id) }
    }
    $candidateOrder = @{}
    for ($i = 0; $i -lt $candidates.Count; $i++) { $candidateOrder[[string]$candidates[$i].Id] = $i }
    $topFindings = [string[]]@($topIds | Sort-Object { $candidateOrder[$_] })

    # --- Coverage ---
    $sources = @(foreach ($s in $stats.Sources) {
        $gapHours = if ($s.GapStartTicks -ge 0) { [Math]::Round(($s.GapEndTicks - $s.GapStartTicks) / [TimeSpan]::TicksPerHour, 1) } else { 0 }
        [PSCustomObject]@{
            Source             = $s.Source
            Rows               = $s.Rows
            FirstUtc           = ConvertFrom-ReportEngineTicks $s.FirstTicks
            LastUtc            = ConvertFrom-ReportEngineTicks $s.LastTicks
            LargestGapHours    = $gapHours
            LargestGapStartUtc = ConvertFrom-ReportEngineTicks $s.GapStartTicks
            LargestGapEndUtc   = ConvertFrom-ReportEngineTicks $s.GapEndTicks
        }
    })
    $logClears = @(foreach ($index in (Find-ReportEngineRows -Table $table -Description '^(?:Security audit log cleared|Event log cleared\b)')) {
        New-ReportEngineRowObject -Table $table -Index $index
    })
    $bootKinds = [ordered]@{
        '^Event log service started' = "Startup"
        '^Event log service stopped' = "Shutdown"
        '^System shutdown/restart initiated' = "ShutdownInitiated"
        '^Unexpected shutdown detected' = "UnexpectedShutdown"
    }
    $boots = New-Object System.Collections.Generic.List[object]
    foreach ($index in (Find-ReportEngineRows -Table $table -Source '^(?:System\.evtx|SystemInfo)$' -Description '^(?:Event log service (?:started|stopped)|System shutdown/restart initiated|Unexpected shutdown detected|System booted)')) {
        $description = $table.Description[$index]
        $kind = "Booted"
        foreach ($pattern in $bootKinds.Keys) { if ($description -match $pattern) { $kind = $bootKinds[$pattern]; break } }
        $boots.Add([PSCustomObject]@{ Utc = ConvertFrom-ReportEngineTicks $table.Ticks[$index]; Kind = $kind; RowNumber = $index + 2 })
        if ($boots.Count -ge 2000) { break }
    }

    $sourceRows = @{}
    foreach ($s in $stats.Sources) { $sourceRows[$s.Source] = $s }
    $auditNotes = New-Object System.Collections.Generic.List[string]
    $security = $sourceRows["Security.evtx"]
    if (-not $security) {
        $auditNotes.Add("The Security event log is not in this timeline (not collected, empty, or not parsed): no logon, account or audit-policy events.")
    }
    else {
        if ((Find-ReportEngineRows -Table $table -Source '^Security\.evtx$' -Description '^New process created').Count -eq 0) {
            $auditNotes.Add("Process creation auditing (Security event 4688) recorded nothing: which programs ran, and their command lines, are not in the Security log. Prefetch, Amcache, BAM and UserAssist still show execution.")
        }
        if ((Find-ReportEngineRows -Table $table -Source '^Security\.evtx$' -Description '^Scheduled task (?:registered|updated|deleted|enabled|disabled):').Count -eq 0) {
            $auditNotes.Add("Scheduled-task auditing (Security events 4698-4702) recorded nothing; task changes come only from the task files, the registry's TaskCache and the Task Scheduler log.")
        }
        $securitySpan = $security.LastTicks - $security.FirstTicks
        if ($security.FirstTicks -ge 0 -and $securitySpan -lt 7 * [TimeSpan]::TicksPerDay) {
            $auditNotes.Add("The Security log covers only $(Format-ReportEngineSpan $securitySpan) (from $(Format-ReportEngineUtc (ConvertFrom-ReportEngineTicks $security.FirstTicks))): it rolls over, so older logons and account changes are gone.")
        }
    }
    $psOperational = $sourceRows["Microsoft-Windows-PowerShell%4Operational.evtx"]
    if (-not $psOperational) {
        $auditNotes.Add("The PowerShell Operational log is not in this timeline: PowerShell script content (event 4104) is not available.")
    }
    elseif ((Find-ReportEngineRows -Table $table -Source '^Microsoft-Windows-PowerShell%4Operational\.evtx$' -Description '^PowerShell script block executed').Count -eq 0) {
        $auditNotes.Add("PowerShell script block logging (event 4104) recorded nothing: the content of PowerShell commands that ran is not recorded.")
    }
    if (-not @($stats.Sources | Where-Object { $_.Source -match 'Sysmon' }).Count) {
        $auditNotes.Add("Sysmon is not installed (or its log was not collected): there is no detailed process, network-connection or file-creation logging.")
    }
    if (-not @($stats.Sources | Where-Object { $_.Source -match 'TaskScheduler' }).Count) {
        $auditNotes.Add("The Task Scheduler Operational log has no events in this timeline (Windows turns it off by default).")
    }
    if (-not @($stats.Sources | Where-Object { $_.Source -match 'Windows Defender%4Operational' }).Count) {
        $auditNotes.Add("The Microsoft Defender Operational log is not in this timeline.")
    }
    $usn = $sourceRows["UsnJournal"]
    if ($usn -and $usn.FirstTicks -ge 0) {
        $auditNotes.Add("The USN journal covers $(Format-ReportEngineSpan ($usn.LastTicks - $usn.FirstTicks)) ($(Format-ReportEngineUtc (ConvertFrom-ReportEngineTicks $usn.FirstTicks)) to $(Format-ReportEngineUtc (ConvertFrom-ReportEngineTicks $usn.LastTicks))): file changes before that are not in it.")
    }
    elseif (-not $usn) {
        $auditNotes.Add("There are no USN journal rows: recent file creations, renames and deletions come only from the `$MFT.")
    }

    $collectorErrorCount = $collectorLog.ErrorCount
    if ($null -eq $collectorErrorCount -and $collectorLog.Available) {
        $collectorErrorCount = @($collectorLog.ProblemLines | Where-Object { $_ -match '\] ERROR: ' }).Count
    }
    $collectorErrors = [PSCustomObject]@{
        Available    = $collectorLog.Available
        Count        = $collectorErrorCount
        WarningCount = @($collectorLog.ProblemLines | Where-Object { $_ -match '\] WARNING: ' }).Count
        Lines        = [string[]]@($collectorLog.ProblemLines | Select-Object -First 50)
        LineCount    = @($collectorLog.ProblemLines).Count
    }
    $builderWarnings = [PSCustomObject]@{
        Available = $builderLog.Available
        Count     = @($builderLog.ProblemLines).Count
        Lines     = [string[]]@($builderLog.ProblemLines | Select-Object -First 50)
    }
    # The builder run: a timeline that ended incomplete (exit code 2)
    $incompleteTexts = New-Object System.Collections.Generic.List[string]
    if ($missingInputs -gt 0) {
        $incompleteTexts.Add("The timeline is incomplete: $missingInputs input file(s) disappeared while it was built (the builder ended with exit code 2), so rows from them may be missing and a missing event proves even less.")
    }
    if ($unexpectedErrors -gt 0) {
        $incompleteTexts.Add("The builder hit $unexpectedErrors unexpected error(s) and skipped the rest of those steps (exit code 2): the timeline may be incomplete.")
    }
    $completeness = [PSCustomObject]@{
        Incomplete        = ($missingInputs -gt 0 -or $unexpectedErrors -gt 0)
        MissingInputFiles = $missingInputs
        UnexpectedErrors  = $unexpectedErrors
        Lines             = $incompleteTexts.ToArray()
    }

    # (An incomplete timeline is not repeated here: the report shows
    # TimelineCompleteness first in Evidence coverage, and in the caveats)
    $notes = New-Object System.Collections.Generic.List[string]
    $notes.Add("The timeline has $($table.Count) rows from $($stats.Sources.Count) sources, $(Format-ReportEngineUtc (ConvertFrom-ReportEngineTicks $stats.FirstTicks)) to $(Format-ReportEngineUtc (ConvertFrom-ReportEngineTicks $stats.LastTicks)).")
    if ($stats.SnapshotRows -gt 0) { $notes.Add("$($stats.SnapshotRows) row(s) are Snapshot rows: the state when the evidence was collected (or when a memory dump was captured), not events.") }
    if ($table.Count -gt $stats.TimedRows) { $notes.Add("$($table.Count - $stats.TimedRows) row(s) have a timestamp that could not be read.") }
    if ($builderLog.Sources) { $notes.Add("Sources parsed by the builder: $($builderLog.Sources).") }
    if ($builderLog.Available -and $builderWarnings.Count -gt 0) { $notes.Add("The builder logged $($builderWarnings.Count) warning(s) or error(s).") }
    if ($collectorLog.Available -and $collectorErrorCount -gt 0) { $notes.Add("The collector logged $collectorErrorCount error(s).") }
    if ($builderLog.UnnamedSids -gt 0) {
        $notes.Add("$($builderLog.UnnamedSids) account SID(s) in the User column have no name (the SOFTWARE hive's ProfileList and bam_entries.csv were not read in this run, or do not list them): Rows per user can list such an account under its SID, apart from its name.")
    }
    # The builder logs "Memory dump not analyzed: <what and why>" for a dump
    # of the collection that it found (or that collection_manifest.csv
    # lists) but did not analyze: Windows ARM64, skipped at its prompt, no
    # Volatility 3, or not found
    if ($builderLog.MemoryDumpNotAnalyzed) {
        $notes.Add("A memory dump of this collection was not analyzed: $($builderLog.MemoryDumpNotAnalyzed)")
    }

    # --- Caveats: what this report can't tell you ---
    $caveats = New-Object System.Collections.Generic.List[string]
    @(
        "These are leads to review, not a verdict on whether this computer was compromised or is clean."
        $incompleteTexts
        "Useful logging is off by default (process command lines 4688, task and remote-session events 4698-4702 and 4778/4779, full PowerShell script logging, file-share access 5140/5145): a missing event proves nothing."
        "Domain sign-ins are logged on the domain controller (Kerberos and NTLM events 4768, 4769, 4776), not on this computer."
        "Logs roll over: each reaches back only to its first event (see Evidence coverage), so older activity may be gone."
        "All times are UTC (the computer's time zone is under Key facts). A wrong clock or altered file times (timestomping) can put events out of order."
        "ShimCache and Amcache show that a file existed, not that it ran; Prefetch shows that a program ran, not what it did."
        "Private browsing leaves no history and clearing history is not logged; encrypted cookies (App-Bound Encryption) need the live computer; Chrome's own DNS lookups are not in the Windows DNS cache."
        "Email headers can be forged, and a real but compromised mailbox passes SPF, DKIM and DMARC. Mailbox and sign-in logs are kept by the mail service (for example Microsoft 365)."
        "Analysis tools run on the collected computer leave their own traces in later collections."
    ) | ForEach-Object { $caveats.Add($_) }
    if ($null -eq $CollectionInfo -or -not $collectionStart) {
        $caveats.Add("The collection's metadata (collection_info.json) was not available: the collection time is unknown.")
    }
    if (-not $zoneId) {
        $caveats.Add("The computer's time zone is unknown: times that Windows records in local time were converted with an assumed time zone.")
    }
    elseif ($zoneAssumed) {
        $caveats.Add("The computer's time zone was not recorded in the collection: $zoneId (the collecting computer's) was assumed for times that Windows records in local time, and for the machine times shown here.")
    }
    if ($mode -eq "MountedImage") {
        if (@($stats.Sources | Where-Object { $_.Source -like "Memory-*" }).Count -gt 0) {
            $caveats.Add("The collection was made from a mounted disk image: live command output (the DNS cache, live network listings) is not included; running programs and network connections come only from the memory dump.")
        }
        else {
            $caveats.Add("The collection was made from a mounted disk image, so live state (running programs, network connections, the DNS cache) is not included.")
        }
        if (-not $computer) {
            $hostText = if ($collectorHost) { " $collectorHost is the computer the collection was made on, not the examined one." } else { "" }
            $caveats.Add("The examined computer's name is not known: the image's SYSTEM hive was not read (or had no name) and the collection records only the computer it was made on.$hostText")
        }
    }
    if ($secrets) {
        $caveats.Add("This collection was made with -IncludeSecrets: it holds keys that can decrypt saved passwords and cookies. Store and share it like a password vault.")
    }
    if ($MftDays -gt 0) {
        $caveats.Add("File times from the `$MFT cover only the $MftDays day(s) before the collection (-MftDays $MftDays); older file activity shows only where another artifact recorded it.")
    }
    if ($builderLog.UsnDropped) {
        $caveats.Add("The oldest USN journal entries were dropped (-MaxUsnEntries): older file changes are not in the timeline.")
    }
    if ($builderLog.MemoryDumpNotAnalyzed) {
        $caveats.Add("A memory dump of this collection exists but was not analyzed (see Evidence coverage): the programs, network connections and command lines in memory are not in this report.")
    }
    if ($builderLog.StartDate -or $builderLog.EndDate) {
        $range = @(@($builderLog.StartDate, $builderLog.EndDate) | Where-Object { $_ }) -join " to "
        $caveats.Add("The timeline was limited by -StartDate/-EndDate ($range): activity outside that range is not in this report.")
    }
    if ($collectorLog.Available -and $collectorErrorCount -gt 0) {
        $caveats.Add("The collector logged $collectorErrorCount error(s) (see Evidence coverage): some artifacts may be missing.")
    }

    # --- Workbook and files ---
    $timelineName = if ($TimelinePath) { Split-Path -Leaf $TimelinePath } else { "timeline.csv" }
    $workbookName = if ($WorkbookPath) { Split-Path -Leaf $WorkbookPath } else { [System.IO.Path]::ChangeExtension($timelineName, ".xlsx") }
    $workbookExists = [bool]($WorkbookPath -and (Test-Path -LiteralPath $WorkbookPath -PathType Leaf))
    $workbookOk = if ($PSBoundParameters.ContainsKey("WorkbookAvailable")) { [bool]$WorkbookAvailable } else { $workbookExists }
    if (-not $workbookOk -and $workbookExists) {
        $caveats.Add("The Excel workbook ($workbookName) was not updated for this report, so the report has no Excel links: any Findings sheet or Finding column in it is from an earlier report, and its finding ids do not match these. Row numbers are the rows of $timelineName (the header is row 1, as Excel shows it).")
    }
    elseif (-not $workbookOk) {
        $caveats.Add("The Excel workbook ($workbookName) was not created or not updated for this report, so the report has no Excel links. Its row numbers are the rows of $timelineName (the header is row 1, as Excel shows it).")
    }
    $findingsName = if ($FindingsCsvPath) { Split-Path -Leaf $FindingsCsvPath } else { "findings.csv" }
    $hashes = New-Object System.Collections.Generic.List[object]
    $hashTargets = @($TimelinePath, $FindingsCsvPath)
    if ($workbookOk) { $hashTargets += $WorkbookPath }
    if ($CollectionPath -and $CollectionPath -match '\.zip$') { $hashTargets += $CollectionPath }
    foreach ($target in $hashTargets) {
        if (-not $target -or -not (Test-Path -LiteralPath $target -PathType Leaf)) { continue }
        try {
            $hashes.Add([PSCustomObject]@{ Name = (Split-Path -Leaf $target); Bytes = (Get-Item -LiteralPath $target).Length; Sha256 = Get-ReportEngineFileHash $target })
        }
        catch { Write-Warning "Could not hash $target : $($_.Exception.Message)" }
    }

    # Rule titles without the {{group}} placeholder ("A known tool ran: {{group}}")
    $ruleList = @(foreach ($rule in @(if ($Rules) { $Rules.Rules })) {
        $ruleTitle = ($rule.Title -replace '\s*[:(-]?\s*\{\{group\}\}\)?', '').Trim()
        [PSCustomObject]@{ Id = $rule.Id; Title = $ruleTitle; Severity = $rule.Severity; Category = $rule.Category; Enabled = $rule.Enabled }
    })
    $allowlisted = @(if ($RuleStatistics) {
        foreach ($key in ($RuleStatistics.Keys | Sort-Object)) { foreach ($entry in $RuleStatistics[$key].Allowlisted) { $entry } }
    })

    return [PSCustomObject]@{
        SchemaVersion = 1
        GeneratedUtc  = [datetime]::UtcNow
        Collection    = $collection
        TimeSpan      = [PSCustomObject]@{
            FirstUtc = ConvertFrom-ReportEngineTicks $stats.FirstTicks
            LastUtc  = ConvertFrom-ReportEngineTicks $stats.LastTicks
            Rows     = $table.Count
        }
        Counts        = [PSCustomObject]@{ High = $highCount; Medium = $leads.Count - $highCount; Info = $info.Count }
        LeadSpan      = [PSCustomObject]@{ FirstUtc = $leadFirst; LastUtc = $leadLast; FileTimeLeads = $leads.Count - $timedLeads.Count }
        TopFindings   = $topFindings
        Findings      = [object[]]$leads
        InfoFindings  = [object[]]$info
        Coverage      = [PSCustomObject]@{
            Sources         = [object[]]$sources
            LogClears       = [object[]]$logClears
            Boots           = $boots.ToArray()
            AuditNotes      = $auditNotes.ToArray()
            CollectorErrors = $collectorErrors
            BuilderWarnings = $builderWarnings
            # Incomplete: the builder run ended with exit code 2 (input files
            # gone during the run, or unexpected errors); Lines say so
            TimelineCompleteness = $completeness
            Notes           = $notes.ToArray()
        }
        Activity      = [PSCustomObject]@{
            PerDay          = [object[]]@($stats.Days | ForEach-Object { [PSCustomObject]@{ Day = $_.Day; Rows = $_.Rows; NonFileRows = $_.NonFileRows } })
            PerHourUtc      = [int[]]$stats.PerHourUtc
            PerHourLocal    = [int[]]$stats.PerHourLocal
            LocalTimeZoneId = if ($zone) { $zone.Id } else { "UTC" }
            TopSources      = [object[]]@($stats.Sources | Sort-Object -Property @{ Expression = { $_.Rows }; Descending = $true }, @{ Expression = { $_.Source } } |
                Select-Object -First 15 | ForEach-Object { [PSCustomObject]@{ Source = $_.Source; Rows = $_.Rows } })
            PerUser         = [object[]]@($stats.Users | Select-Object -First 20 | ForEach-Object { [PSCustomObject]@{ User = $_.Name; Rows = $_.Rows; IsSystem = $_.IsSystem } })
        }
        Caveats       = $caveats.ToArray()
        Rules         = [object[]]$ruleList
        Allowlisted   = [object[]]$allowlisted
        Method        = [string[]]@(
            "The report is built from the $($table.Count) rows of the timeline ($timelineName), the same rows as the Timeline sheet of the workbook."
            "Each rule matches rows by their source, event type, description, details and user. Matching rows are grouped into findings; some rules need several rows within a time window, and some raise the severity when a related event follows soon after."
            "High and Medium findings are leads to review. Info findings are listed in the appendix. Rows matching the allowlist (known benign activity) are counted but not flagged."
            $(if ($workbookOk) { "Row numbers are Excel row numbers on the Timeline sheet (row 1 is the header)." }
                else { "Row numbers are row numbers in $timelineName (row 1 is the header), as Excel shows them." })
        )
        Workbook      = [PSCustomObject]@{ FileName = $workbookName; Available = $workbookOk; TimelineSheet = "Timeline"; FindingsSheet = "Findings" }
        Files         = [PSCustomObject]@{ TimelineCsv = $timelineName; FindingsCsv = $findingsName; Hashes = $hashes.ToArray() }
    }
}

<#
.SYNOPSIS
Writes the report model as JSON (ASCII, UTF-8 without BOM, CRLF; dates in
ISO 8601 UTC).
#>
function Export-ReportModelJson {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [Parameter(Mandatory = $true)][string]$Path)
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($fullPath, [TimelineReport.Json]::Serialize($Model) + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
}
