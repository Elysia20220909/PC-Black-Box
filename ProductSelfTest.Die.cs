using System.IO;
using System.Text;
using System.Text.Json;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    private static void TestDieEvidence(ref int checks)
    {
        string digest = new('A', 64);
        var scan = new ScanResult();
        scan.Files.Add(new FileAnalysis { Sha256 = digest });
        byte[] Envelope(object result, string? hash = null) => JsonSerializer.SerializeToUtf8Bytes(new { schema = "pcbb-die-v1", sha256 = hash ?? digest, result });
        byte[] valid = Envelope(new { detects = new[] { new { type = "format", name = "Plain text", version = "", info = "C:\\private\\secret" } } });
        var evidence = DieEvidence.Parse(valid, scan);
        Require(evidence.Labels.SequenceEqual(new[] { "type: format", "name: Plain text" }), ref checks);
        scan.Die = evidence;
        Require(ReportBuilder.Build(scan, "en").Contains("Plain text", StringComparison.Ordinal), ref checks);
        Require(!ReportBuilder.BuildJson(scan, "en").Contains("secret", StringComparison.Ordinal), ref checks);
        int riskBefore = scan.RiskScore;
        var completeCleanup = new DieCleanupStatus("complete", "complete", "complete");
        foreach (var cleanup in new[]
        {
            completeCleanup, new DieCleanupStatus("failed", "complete", "complete"),
            new DieCleanupStatus("complete", "failed", "complete"), new DieCleanupStatus("complete", "complete", "failed"),
            DieCleanupStatus.Unknown
        })
        {
            DieSessionClient.ApplyResponse(DieSessionResponse.Write(valid, "complete", cleanup), scan);
            Require(scan.DieStatus == "complete" && scan.Die is not null && scan.DieCleanup == cleanup, ref checks);
            Require(scan.RiskScore == riskBefore, ref checks);
            Require(ReportBuilder.Build(scan, "en").Contains(cleanup.Describe(false), StringComparison.Ordinal), ref checks);
            using var report = JsonDocument.Parse(ReportBuilder.BuildJson(scan, "en"));
            Require(report.RootElement.GetProperty("dieCleanup").GetProperty("temporaryData").GetString() == cleanup.TemporaryData, ref checks);
            Require(cleanup.NeedsAttention == (cleanup != completeCleanup), ref checks);
        }
        foreach (string status in new[] { "failed", "cancelled" })
        {
            DieSessionClient.ApplyResponse(DieSessionResponse.Write(null, status, new("failed", "not-required", "not-required")), scan);
            Require(scan.Die is null && scan.DieStatus == status && scan.DieCleanup.NeedsAttention, ref checks);
        }
        byte[] responseBytes = DieSessionResponse.Write(valid, "complete", completeCleanup);
        bool RejectResponse(byte[] response)
        {
            try { DieSessionClient.ApplyResponse(response, scan); return false; }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or InvalidOperationException or KeyNotFoundException) { return true; }
        }
        Require(RejectResponse(valid), ref checks); // Old sessions cannot assert successful cleanup.
        Require(RejectResponse(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(responseBytes).Replace("\"temporaryData\":\"complete\"", "\"temporaryData\":\"complete\",\"temporaryData\":\"failed\"", StringComparison.Ordinal))), ref checks);
        Require(RejectResponse(DieSessionResponse.Write(valid, "complete", new("unrecognized", "complete", "complete"))), ref checks);
        Require(RejectResponse(DieSessionResponse.Write(null, "complete", completeCleanup)), ref checks);
        Require(RejectResponse(DieSessionResponse.Write(valid, "failed", completeCleanup)), ref checks);
        Require(RejectResponse(new byte[DiePipeProtocol.MaxFrame + 1]), ref checks);
        foreach (byte[] invalidEvidence in new[] { Envelope(new { detects = Array.Empty<object>() }, new('B', 64)), Envelope(new { name = "C:\\private\\secret", type = "format", version = "" }) })
        {
            var failedCleanup = new DieCleanupStatus("failed", "failed", "complete");
            Require(RejectResponse(DieSessionResponse.Write(invalidEvidence, "complete", failedCleanup)), ref checks);
            Require(scan.Die is null && scan.DieStatus == "rejected-evidence" && scan.DieCleanup == failedCleanup, ref checks);
            Require(ReportBuilder.Build(scan, "en").Contains(failedCleanup.Describe(false), StringComparison.Ordinal), ref checks);
            using var rejectedReport = JsonDocument.Parse(ReportBuilder.BuildJson(scan, "en"));
            Require(rejectedReport.RootElement.GetProperty("dieCleanup").GetProperty("temporaryData").GetString() == "failed", ref checks);
        }
        scan.Die = evidence;
        bool Reject(byte[] bytes)
        {
            try { DieEvidence.Parse(bytes, scan); return false; }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or KeyNotFoundException) { return true; }
        }
        Require(Reject(Envelope(new { name = "text" }, new('B', 64))), ref checks);
        Require(Reject(Envelope(new { name = "C:\\secret" })), ref checks);
        Require(Reject(Envelope(new { name = "line\nspoof" })), ref checks);
        Require(Reject(Envelope(new { name = new string('x', 161) })), ref checks);
        Require(Reject(Envelope(new { unexpected = true })), ref checks);
        Require(Reject(Envelope(new { detects = (object?)null })), ref checks);
        var metadata = DieEvidence.Parse(Envelope(new { detects = Array.Empty<object>(), extra = new { name = "Alice" } }), scan);
        Require(metadata.Labels.Length == 0, ref checks);
        Require(Reject(new byte[DieEvidence.MaxBytes + 1]), ref checks);
        Require(Reject([.. valid, .. Encoding.UTF8.GetBytes("trailing")]), ref checks);
        scan.Files[0].Limits = InspectionLimit.Digest;
        Require(Reject(valid), ref checks);
        using var framed = new MemoryStream();
        DiePipeProtocol.WriteAsync(framed, valid, CancellationToken.None).GetAwaiter().GetResult();
        framed.Position = 0;
        Require(DiePipeProtocol.ReadAsync(framed, DiePipeProtocol.MaxFrame, CancellationToken.None).GetAwaiter().GetResult().SequenceEqual(valid), ref checks);
        using var oversized = new MemoryStream(new byte[] { 255, 255, 255, 127 });
        bool rejectedFrame = false;
        try { DiePipeProtocol.ReadAsync(oversized, 32768, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (InvalidDataException) { rejectedFrame = true; }
        Require(rejectedFrame, ref checks);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        bool cancellationObserved = false;
        try { DieSessionClient.AttachAsync(scan, "unused", cancelled.Token).GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { cancellationObserved = true; }
        Require(cancellationObserved, ref checks);
        scan.Files[0].Limits = InspectionLimit.None;
        scan.Files.Add(new FileAnalysis { Sha256 = digest });
        Require(Reject(valid), ref checks);
    }
}
