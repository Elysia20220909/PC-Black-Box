using System.Runtime.InteropServices;
using System.Text.Json;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    // Deterministic data only: the ordinary self-test never queries Defender or creates malware.
    private static void TestDefenderReadOnly(ref int checks)
    {
        TestDefenderQueryBoundary(ref checks);
        TestProtectionOverview(ref checks);
        const string timestamp = "20260917123456.000000+540";
        DateTimeOffset observed = new(2026, 9, 17, 3, 34, 56, TimeSpan.Zero);
        var status = new DefenderWmi.QueryResult(DefenderReadState.Complete, [new object?[] { true, true, false, timestamp }]);
        var emptyHistory = new DefenderWmi.QueryResult(DefenderReadState.Complete, []);
        DefenderSnapshot empty = DefenderWmi.Project(observed, status, emptyHistory);
        Require(empty.RetrievalComplete && empty.Detections.Count == 0, ref checks);
        Require(empty.Protection?.RealTimeProtectionEnabled == false, ref checks);
        Require(empty.ToDisplay(false).Contains("not proof of safety", StringComparison.Ordinal), ref checks);
        Require(empty.ToDisplay(true).Contains("安全の証明ではありません", StringComparison.Ordinal), ref checks);
        using (JsonDocument json = JsonDocument.Parse(empty.ToJson()))
        {
            Require(!json.RootElement.GetProperty("newScanPerformed").GetBoolean(), ref checks);
            Require(json.RootElement.GetProperty("malwareVerdict").GetString() == "not-assessed", ref checks);
            Require(json.RootElement.GetProperty("readOnly").GetBoolean(), ref checks);
        }
        Require(DefenderReader.Timestamp(timestamp) == observed, ref checks);
        Require(DefenderReader.Timestamp("20260917000000.000000-090")?.Offset == TimeSpan.FromMinutes(-90), ref checks);
        foreach (object? invalidValue in new object?[] { null, "", "20260917123456.000000+999", "20260230123456.000000+000", "20260917123456.******+000", "C:\\Users\\private\\secret.txt", true })
            Require(DefenderReader.Timestamp(invalidValue) is null, ref checks);
        Require(DefenderReader.Boolean("true") is null && DefenderReader.Boolean(1) is null, ref checks);
        Require(DefenderReader.NonnegativeInteger("9223372036854775807") == long.MaxValue, ref checks);
        foreach (object? invalidValue in new object?[] { -1, ulong.MaxValue, "9223372036854775808", "-1", "+1", " 1", "1.0", "１２", true, 1.5, null })
            Require(DefenderReader.NonnegativeInteger(invalidValue) is null, ref checks);
        Require(DefenderReader.Byte(256) is null && DefenderReader.Byte(255) == 255, ref checks);
        Require(DefenderReader.Unsigned((ulong)uint.MaxValue + 1) is null, ref checks);
        Require(DefenderReader.Classify(new UnauthorizedAccessException("secret")) == DefenderReadState.AccessDenied, ref checks);
        Require(DefenderReader.Classify(new COMException("secret", unchecked((int)0x80041003))) == DefenderReadState.AccessDenied, ref checks);
        Require(DefenderReader.Classify(new TimeoutException()) == DefenderReadState.Timeout, ref checks);
        Require(DefenderReader.Classify(new COMException("secret")) == DefenderReadState.Unavailable, ref checks);

        object?[] quarantined = ["2147483648", timestamp, timestamp, (byte)3, true, (uint)8];
        DefenderSnapshot history = DefenderWmi.Project(observed, status, new(DefenderReadState.Complete, [quarantined]));
        Require(history.RetrievalComplete && history.Detections.Single().StatusCode == "quarantined", ref checks);
        Require(history.Detections[0].AdditionalActions == 8, ref checks);
        Require(history.ToDisplay(false).Contains("not a verdict on the selected file", StringComparison.Ordinal), ref checks);
        Require(history.ToDisplay(false).Contains("not necessarily newest", StringComparison.Ordinal), ref checks);
        foreach (byte state in new byte[] { 0, 7, 101, 255 })
            Require((history.Detections[0] with { StatusId = state }).StatusCode == "unknown", ref checks);
        Require((history.Detections[0] with { StatusId = 102 }).StatusCode == "quarantine-failed", ref checks);

        DefenderSnapshot unavailable = DefenderWmi.Project(observed, status, new(DefenderReadState.AccessDenied, []));
        Require(!unavailable.RetrievalComplete && unavailable.Protection is not null, ref checks);
        Require(!unavailable.ToDisplay(false).Contains("Zero history records returned", StringComparison.Ordinal), ref checks);
        Require(DefenderWmi.Project(observed, emptyHistory, emptyHistory).ProtectionState == DefenderReadState.InvalidData, ref checks);
        object?[] unknown = ["C:\\Users\\private\\secret", "sensitive", null, "bad", "true", -1];
        DefenderSnapshot invalid = DefenderWmi.Project(observed, new(DefenderReadState.Complete, [unknown]), new(DefenderReadState.Complete, [unknown]));
        Require(!invalid.RetrievalComplete && invalid.Protection is null, ref checks);
        Require(invalid.HistoryState == DefenderReadState.Partial && invalid.Detections[0].StatusCode == "unknown", ref checks);
        Require(!invalid.ToJson().Contains("private", StringComparison.Ordinal) && !invalid.ToDisplay(true).Contains("sensitive", StringComparison.Ordinal), ref checks);
        DefenderSnapshot capped = DefenderWmi.Project(observed, status, new(DefenderReadState.Complete,
            Enumerable.Repeat(quarantined, DefenderReader.MaxHistory + 1).ToArray()));
        Require(capped.HistoryState == DefenderReadState.Partial && capped.Detections.Count == DefenderReader.MaxHistory, ref checks);
        DefenderSnapshot missing = DefenderWmi.Project(observed, new(DefenderReadState.Complete, [new object?[] { null, true, false, timestamp }]), emptyHistory);
        Require(missing.ProtectionState == DefenderReadState.Partial && missing.Protection?.ServiceEnabled is null, ref checks);
        DefenderSnapshot failed = new DefenderReader(() => throw new InvalidOperationException("private")).ReadAsync().GetAwaiter().GetResult();
        Require(failed.ProtectionState == DefenderReadState.Unavailable && !failed.ToJson().Contains("private", StringComparison.Ordinal), ref checks);

        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var finished = new ManualResetEventSlim();
        var slow = new DefenderReader(() =>
        {
            entered.Set();
            try { release.Wait(TimeSpan.FromSeconds(20)); return empty; }
            finally { finished.Set(); }
        });
        try
        {
            Task<DefenderSnapshot> first = slow.ReadAsync();
            Require(entered.Wait(TimeSpan.FromSeconds(5)), ref checks);
            Require(slow.ReadAsync().GetAwaiter().GetResult().ProtectionState == DefenderReadState.Busy, ref checks);
            Require(first.GetAwaiter().GetResult().ProtectionState == DefenderReadState.Timeout, ref checks);
            Require(slow.ReadAsync().GetAwaiter().GetResult().ProtectionState == DefenderReadState.Busy, ref checks);
        }
        finally
        {
            release.Set();
            finished.Wait(TimeSpan.FromSeconds(5));
        }
    }

    private static void TestDefenderQueryBoundary(ref int checks)
    {
        const int end = 1;
        const int waitTimeout = 0x40004;
        const int accessDenied = unchecked((int)0x80041003);
        const int notFound = unchecked((int)0x80041002);
        static DefenderWmi.QueryResult Run(DefenderTestCursor cursor, int limit = 1,
            Func<TimeSpan>? elapsed = null, string[]? fields = null) =>
            DefenderWmi.Query(cursor, fields ?? ["Value"], limit, elapsed ?? (() => TimeSpan.Zero));

        var empty = new DefenderTestCursor([new(end, 0)]);
        DefenderWmi.QueryResult result = Run(empty);
        Require(result.State == DefenderReadState.Complete && result.Rows.Count == 0, ref checks);
        Require(empty.OpenCount == 1 && empty.SecureCount == 1 && empty.NextCount == 1 && empty.DisposeCount == 1, ref checks);

        // A per-call wait timeout is not EOF; a later object must still be read and released.
        var row = new DefenderTestRow(_ => (0, true));
        var waiting = new DefenderTestCursor([new(waitTimeout, 0), new(0, 1, row), new(end, 0)]);
        result = Run(waiting);
        Require(result.State == DefenderReadState.Complete && result.Rows.Count == 1 && Equals(result.Rows[0][0], true), ref checks);
        Require(waiting.NextCount == 3 && waiting.DisposeCount == 1 && row.DisposeCount == 1 && row.GetCount == 1, ref checks);
        Require(waiting.Timeouts.All(timeout => timeout == 200), ref checks);

        // EOF may carry data. Do not discard the final row or request another one after EOF.
        var lastRow = new DefenderTestRow(_ => (0, 7));
        var final = new DefenderTestCursor([new(end, 1, lastRow)]);
        result = Run(final);
        Require(result.State == DefenderReadState.Complete && Equals(result.Rows.Single()[0], 7), ref checks);
        Require(final.NextCount == 1 && final.DisposeCount == 1 && lastRow.DisposeCount == 1, ref checks);

        foreach (int count in new[] { DefenderReader.MaxHistory, DefenderReader.MaxHistory + 1 })
        {
            DefenderTestRow[] rows = Enumerable.Range(0, count).Select(index => new DefenderTestRow(_ => (0, index))).ToArray();
            var cursor = new DefenderTestCursor(rows.Select(item => new DefenderTestStep(0, 1, item))
                .Append(new(end, 0)).ToArray());
            result = Run(cursor, DefenderReader.MaxHistory);
            Require(result.State == (count == DefenderReader.MaxHistory ? DefenderReadState.Complete : DefenderReadState.Partial), ref checks);
            Require(result.Rows.Count == DefenderReader.MaxHistory && cursor.NextCount == DefenderReader.MaxHistory + 1, ref checks);
            Require(rows.All(item => item.DisposeCount == 1) && cursor.DisposeCount == 1, ref checks);
            Require(rows.Take(DefenderReader.MaxHistory).All(item => item.GetCount == 1), ref checks);
            if (count > DefenderReader.MaxHistory) Require(rows[^1].GetCount == 0, ref checks);
        }

        foreach (DefenderQueryStage stage in Enum.GetValues<DefenderQueryStage>())
        {
            var good = new DefenderTestRow(_ => (0, 42));
            var rejected = new DefenderTestRow(_ => (accessDenied, null));
            var cursor = new DefenderTestCursor([new(0, 1, good),
                new(stage == DefenderQueryStage.Enumerate ? accessDenied : 0, 1, rejected)])
            {
                OpenError = stage == DefenderQueryStage.Query ? new COMException("private", accessDenied) : null,
                SecureError = stage == DefenderQueryStage.SecureProxy ? new COMException("private", accessDenied) : null
            };
            result = Run(cursor, 2);
            Require(result.State == DefenderReadState.AccessDenied && result.FailureStage == stage && result.ErrorCode == accessDenied, ref checks);
            Require(cursor.DisposeCount == 1, ref checks);
            bool enumerated = stage is DefenderQueryStage.Enumerate or DefenderQueryStage.Property;
            Require(result.Rows.Count == (enumerated ? 1 : 0), ref checks);
            Require(good.DisposeCount == (enumerated ? 1 : 0) && rejected.DisposeCount == (enumerated ? 1 : 0), ref checks);
            if (enumerated)
            {
                Require(Equals(result.Rows[0][0], 42), ref checks);
                Require(rejected.GetCount == (stage == DefenderQueryStage.Property ? 1 : 0), ref checks);
            }
            else Require(cursor.NextCount == 0, ref checks);
        }

        foreach (uint returned in new uint[] { 0, 1, 2 })
        {
            // Missing object for a reported row, unexpected count, and empty success without EOF.
            var invalidRow = returned == 1 ? null : new DefenderTestRow(_ => (0, true));
            var cursor = new DefenderTestCursor([new(0, returned, invalidRow)]);
            result = Run(cursor);
            Require(result.State == DefenderReadState.InvalidData && result.Rows.Count == 0, ref checks);
            Require(cursor.DisposeCount == 1 && (invalidRow is null || invalidRow.DisposeCount == 1), ref checks);
            Require(invalidRow is null || invalidRow.GetCount == 0, ref checks);
        }

        var requested = new List<string>();
        var values = new DefenderTestRow(name =>
        {
            requested.Add(name);
            return name switch
            {
                "Missing" => (notFound, "private"),
                "Object" => (0, new object()),
                "Long" => (0, new string('x', 26)),
                _ => (0, false)
            };
        });
        string[] fields = ["Missing", "Object", "Long", "Flag"];
        var filtered = new DefenderTestCursor([new(0, 1, values), new(end, 0)]);
        result = Run(filtered, fields: fields);
        Require(result.State == DefenderReadState.Complete && requested.SequenceEqual(fields), ref checks);
        Require(result.Rows.Single().Take(3).All(value => value is null) && Equals(result.Rows[0][3], false), ref checks);
        Require(values.DisposeCount == 1 && filtered.DisposeCount == 1, ref checks);

        TimeSpan elapsed = DefenderReader.QueryBudget;
        var expired = new DefenderTestCursor([]);
        result = Run(expired, elapsed: () => elapsed);
        Require(result.State == DefenderReadState.Timeout && result.FailureStage == DefenderQueryStage.Query, ref checks);
        Require(expired.OpenCount == 0 && expired.SecureCount == 0 && expired.NextCount == 0 && expired.DisposeCount == 1, ref checks);

        elapsed = TimeSpan.Zero;
        var timedWait = new DefenderTestCursor(Enumerable.Repeat(
            new DefenderTestStep(waitTimeout, 0, BeforeReturn: () => elapsed += TimeSpan.FromSeconds(1)), 8).ToArray());
        result = Run(timedWait, elapsed: () => elapsed);
        Require(result.State == DefenderReadState.Timeout && result.FailureStage == DefenderQueryStage.Enumerate && result.Rows.Count == 0, ref checks);
        Require(timedWait.NextCount == 8 && timedWait.DisposeCount == 1, ref checks);

        elapsed = TimeSpan.Zero;
        var lateRow = new DefenderTestRow(_ => (0, true));
        var lateNext = new DefenderTestCursor([new(0, 1, lateRow, () => elapsed = DefenderReader.QueryBudget)]);
        result = Run(lateNext, elapsed: () => elapsed);
        Require(result.State == DefenderReadState.Timeout && result.FailureStage == DefenderQueryStage.Enumerate, ref checks);
        Require(result.Rows.Count == 0 && lateRow.GetCount == 0 && lateRow.DisposeCount == 1 && lateNext.DisposeCount == 1, ref checks);

        // The last property can exhaust the budget too: never retain a row completed after it.
        elapsed = TimeSpan.Zero;
        var lateProperty = new DefenderTestRow(_ => { elapsed = DefenderReader.QueryBudget; return (0, true); });
        var lateGet = new DefenderTestCursor([new(0, 1, lateProperty), new(end, 0)]);
        result = Run(lateGet, elapsed: () => elapsed);
        Require(result.State == DefenderReadState.Timeout && result.FailureStage == DefenderQueryStage.Property, ref checks);
        Require(result.Rows.Count == 0 && lateGet.NextCount == 1, ref checks);
        Require(lateProperty.DisposeCount == 1 && lateGet.DisposeCount == 1, ref checks);
    }

    private static void TestProtectionOverview(ref int checks)
    {
        const string timestamp = "20260917123456.000000+540";
        DefenderSnapshot basic = DefenderWmi.Project(DateTimeOffset.UtcNow,
            new(DefenderReadState.Complete, [new object?[] { true, true, true, timestamp }]), new(DefenderReadState.Complete, []));
        Require(basic.ProtectionAssessment == "unknown", ref checks);
        object?[] enabled = [true, true, true, true, true, false, "Normal"];
        DefenderSnapshot complete = DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [enabled]));
        Require(complete.ProtectionAssessment == "reported-enabled" && complete.ExtendedProtectionState == DefenderReadState.Complete, ref checks);
        Require(complete.ToDisplay(false).Contains("not safety or complete isolation", StringComparison.Ordinal), ref checks);
        Require(complete.ToDisplay(true).Contains("再取得", StringComparison.Ordinal), ref checks);
        for (int index = 0; index < enabled.Length; index++)
        {
            object?[] missing = (object?[])enabled.Clone();
            missing[index] = null;
            DefenderSnapshot unknown = DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [missing]));
            Require(unknown.ExtendedProtectionState == DefenderReadState.Partial && unknown.ProtectionAssessment == "unknown", ref checks);
            Require(unknown.RetrievalComplete && unknown.Protection == basic.Protection, ref checks);
            object?[] disabled = (object?[])enabled.Clone();
            disabled[index] = index == 6 ? "Passive Mode" : index == 5;
            Require(DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [disabled])).ProtectionAssessment == "attention-required", ref checks);
        }
        foreach (string mode in new[] { "EDR Block Mode", "Not running" })
        {
            object?[] nonActive = (object?[])enabled.Clone();
            nonActive[6] = mode;
            Require(DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [nonActive])).ProtectionAssessment == "attention-required", ref checks);
        }
        object?[] untrusted = ["true", 1, null, null, null, "false", "private-provider-text"];
        DefenderSnapshot filtered = DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [untrusted]));
        Require(filtered.ProtectionAssessment == "unknown" && !filtered.ToJson().Contains("private-provider-text", StringComparison.Ordinal), ref checks);
        foreach (DefenderReadState state in new[] { DefenderReadState.AccessDenied, DefenderReadState.Timeout, DefenderReadState.Unavailable })
        {
            DefenderSnapshot failed = DefenderWmi.ProjectExtended(basic, new(state, [], DefenderQueryStage.Query, -1));
            Require(failed.RetrievalComplete && failed.ExtendedProtectionState == state && failed.ProtectionAssessment == "unknown", ref checks);
            Require(failed.ExtendedFailureStage == DefenderQueryStage.Query && failed.ExtendedErrorCode == -1, ref checks);
        }
        Require(DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [])).ExtendedProtectionState == DefenderReadState.InvalidData, ref checks);
        Require(DefenderWmi.ProjectExtended(basic, new(DefenderReadState.Complete, [new object?[] { true }])).ExtendedProtectionState == DefenderReadState.InvalidData, ref checks);
        Require((complete with { Protection = complete.Protection! with { RealTimeProtectionEnabled = false } }).ProtectionAssessment == "attention-required", ref checks);
        Require((complete with { Protection = null }).ProtectionAssessment == "unknown", ref checks);

        int calls = 0;
        IsolationPresenceSnapshot absent = IsolationToolReader.Probe((_, _, _) => { calls++; return false; }, () => TimeSpan.Zero);
        Require(calls == 12 && absent.State == DefenderReadState.Complete, ref checks);
        Require(absent.Tools.All(tool => tool.RegistrationObserved == false && tool.ProbeComplete), ref checks);
        Require(absent.ToDisplay(false).Contains("installation not ruled out", StringComparison.Ordinal), ref checks);
        IsolationPresenceSnapshot observed = IsolationToolReader.Probe((_, _, _) => true, () => TimeSpan.Zero);
        Require(observed.Tools.All(tool => tool.RegistrationObserved == true), ref checks);
        Require(observed.ToDisplay(true).Contains("隔離の有効性は未確認", StringComparison.Ordinal), ref checks);
        using (JsonDocument json = JsonDocument.Parse(observed.WithDefenderJson(complete)))
        {
            Require(!json.RootElement.GetProperty("isolationEstablished").GetBoolean(), ref checks);
            Require(json.RootElement.GetProperty("isolationTools").GetProperty("isolationState").GetString() == "not-verified", ref checks);
            Require(!json.RootElement.GetProperty("isolationTools").GetProperty("toolsLaunched").GetBoolean(), ref checks);
            Require(json.RootElement.GetProperty("defender").GetProperty("extendedProtectionState").GetString() == "Complete", ref checks);
        }
        IsolationPresenceSnapshot denied = IsolationToolReader.Probe((_, _, _) => throw new UnauthorizedAccessException("private-path"), () => TimeSpan.Zero);
        Require(denied.State == DefenderReadState.Partial && denied.Tools.All(tool => tool.RegistrationObserved is null), ref checks);
        Require(!denied.WithDefenderJson(complete).Contains("private-path", StringComparison.Ordinal), ref checks);
        calls = 0;
        IsolationPresenceSnapshot partial = IsolationToolReader.Probe((_, _, _) => ++calls == 1 ? true : throw new UnauthorizedAccessException(), () => TimeSpan.Zero);
        Require(partial.Tools[0].RegistrationObserved == true && !partial.Tools[0].ProbeComplete, ref checks);
        Require(partial.Tools[1].RegistrationObserved is null && partial.State == DefenderReadState.Partial, ref checks);
        calls = 0;
        IsolationPresenceSnapshot expired = IsolationToolReader.Probe((_, _, _) => { calls++; return true; }, () => IsolationToolReader.QueryBudget);
        Require(calls == 0 && expired.State == DefenderReadState.Timeout && expired.Tools.All(tool => tool.RegistrationObserved is null), ref checks);
        TimeSpan elapsed = TimeSpan.Zero;
        IsolationPresenceSnapshot late = IsolationToolReader.Probe((_, _, _) => { elapsed = IsolationToolReader.QueryBudget; return true; }, () => elapsed);
        Require(late.State == DefenderReadState.Timeout && late.Tools.All(tool => tool.RegistrationObserved is null), ref checks);
        Require(new IsolationToolReader(() => throw new InvalidOperationException("private")).ReadAsync().GetAwaiter().GetResult().State == DefenderReadState.Unavailable, ref checks);

        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        using var finished = new ManualResetEventSlim();
        var slow = new IsolationToolReader(() =>
        {
            entered.Set();
            try { release.Wait(TimeSpan.FromSeconds(10)); return absent; }
            finally { finished.Set(); }
        });
        try
        {
            Task<IsolationPresenceSnapshot> first = slow.ReadAsync();
            Require(entered.Wait(TimeSpan.FromSeconds(5)), ref checks);
            Require(slow.ReadAsync().GetAwaiter().GetResult().State == DefenderReadState.Busy, ref checks);
            Require(first.GetAwaiter().GetResult().State == DefenderReadState.Timeout, ref checks);
            Require(slow.ReadAsync().GetAwaiter().GetResult().State == DefenderReadState.Busy, ref checks);
        }
        finally { release.Set(); finished.Wait(TimeSpan.FromSeconds(5)); }

        using var extendedEntered = new ManualResetEventSlim();
        using var extendedRelease = new ManualResetEventSlim();
        using var extendedFinished = new ManualResetEventSlim();
        var stalledExtension = new DefenderReader(reportBasic =>
        {
            reportBasic(basic);
            extendedEntered.Set();
            try { extendedRelease.Wait(TimeSpan.FromSeconds(20)); return complete; }
            finally { extendedFinished.Set(); }
        });
        try
        {
            Task<DefenderSnapshot> first = stalledExtension.ReadAsync();
            Require(extendedEntered.Wait(TimeSpan.FromSeconds(5)), ref checks);
            DefenderSnapshot timedOut = first.GetAwaiter().GetResult();
            Require(timedOut.RetrievalComplete && timedOut.Protection == basic.Protection, ref checks);
            Require(timedOut.HistoryState == basic.HistoryState && timedOut.Detections == basic.Detections, ref checks);
            Require(timedOut.ExtendedProtectionState == DefenderReadState.Timeout && timedOut.ProtectionAssessment == "unknown", ref checks);
            Require(stalledExtension.ReadAsync().GetAwaiter().GetResult().ProtectionState == DefenderReadState.Busy, ref checks);
        }
        finally { extendedRelease.Set(); extendedFinished.Wait(TimeSpan.FromSeconds(5)); }
    }

    private sealed record DefenderTestStep(int Result, uint Returned, DefenderTestRow? Row = null, Action? BeforeReturn = null);

    private sealed class DefenderTestCursor(IReadOnlyList<DefenderTestStep> steps) : DefenderWmi.IQueryCursor
    {
        internal Exception? OpenError { get; init; }
        internal Exception? SecureError { get; init; }
        internal int OpenCount { get; private set; }
        internal int SecureCount { get; private set; }
        internal int NextCount { get; private set; }
        internal int DisposeCount { get; private set; }
        internal List<int> Timeouts { get; } = [];

        public void Open() { OpenCount++; if (OpenError is not null) throw OpenError; }
        public void Secure()
        {
            if (OpenCount != 1) throw new InvalidOperationException("Query must open before securing its proxy.");
            SecureCount++;
            if (SecureError is not null) throw SecureError;
        }
        public int Next(int timeout, out DefenderWmi.IQueryRow? item, out uint returned)
        {
            if (SecureCount != 1 || DisposeCount != 0) throw new InvalidOperationException("Query cursor is not active.");
            DefenderTestStep step = steps[NextCount++];
            Timeouts.Add(timeout);
            item = step.Row;
            returned = step.Returned;
            step.BeforeReturn?.Invoke();
            return step.Result;
        }
        public void Dispose() => DisposeCount++;
    }

    private sealed class DefenderTestRow(Func<string, (int Result, object? Value)> read) : DefenderWmi.IQueryRow
    {
        internal int GetCount { get; private set; }
        internal int DisposeCount { get; private set; }

        public int Get(string name, out object? value)
        {
            if (DisposeCount != 0) throw new InvalidOperationException("Query row was already released.");
            GetCount++;
            (int result, value) = read(name);
            return result;
        }
        public void Dispose() => DisposeCount++;
    }
}
