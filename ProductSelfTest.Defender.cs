using System.Runtime.InteropServices;
using System.Text.Json;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    // Deterministic data only: the ordinary self-test never queries Defender or creates malware.
    private static void TestDefenderReadOnly(ref int checks)
    {
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
}
