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
