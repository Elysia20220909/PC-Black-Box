using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;

namespace DestinyBlackBox;

internal sealed record ProductSelfTestResult(bool Passed, int Checks)
{
    public string SafeStatusLine => $"PC_BLACK_BOX_SELF_TEST passed={Passed.ToString().ToLowerInvariant()} checks={Checks}";
}

internal static class ProductSelfTest
{
    public static ProductSelfTestResult Run()
    {
        int checks = 0;
        try
        {
            var high = CreateFile("danger.ps1", "Script / active text", "NotSigned", "—", "example.invalid",
                new("danger", "process-injection", "プロセス注入", "Process injection", 60));
            var review = CreateFile("review.exe", "Windows PE", "Valid", "Microsoft Windows", "—",
                new("watch", "internet-zone", "インターネット由来", "Internet origin", 25));
            var low = CreateFile("note.txt", "Text", "Not checked", "—", "—",
                new("info", "low-signal", "弱い兆候", "Low signal", 4));
            var clear = CreateFile("readme.txt", "Text", "Not checked", "—", "—");
            FileAnalysis[] files = [high, review, low, clear];

            Require(FileViewQuery.Apply(files, "ALL", null).Count == 4, ref checks);
            Require(FileViewQuery.Apply(files, "HIGH", null).SequenceEqual([high]), ref checks);
            Require(FileViewQuery.Apply(files, "REVIEW", null).SequenceEqual([review]), ref checks);
            Require(FileViewQuery.Apply(files, "LOW", null).SequenceEqual([low]), ref checks);
            Require(FileViewQuery.Apply(files, "CLEAR", null).SequenceEqual([clear]), ref checks);
            Require(FileViewQuery.Apply(files, "ALL", "danger").SequenceEqual([high]), ref checks);
            Require(FileViewQuery.Apply(files, "ALL", "Microsoft").SequenceEqual([review]), ref checks);
            Require(FileViewQuery.Apply(files, "ALL", "injection").SequenceEqual([high]), ref checks);
            Require(FileViewQuery.Apply(files, "ALL", "example.invalid").SequenceEqual([high]), ref checks);
            Require(!SecurityPolicy.SanitizeText("safe\u202Etxt").Contains('\u202E'), ref checks);
            Require(!SecurityPolicy.WouldExceedCumulativeLimit(SecurityPolicy.MaxTargetBytes - 1, 1, SecurityPolicy.MaxTargetBytes), ref checks);
            Require(SecurityPolicy.WouldExceedCumulativeLimit(SecurityPolicy.MaxTargetBytes - 1, 2, SecurityPolicy.MaxTargetBytes), ref checks);
            Require(!FileInspector.WouldExceedDirectoryLimits(9999, 128), ref checks);
            Require(FileInspector.WouldExceedDirectoryLimits(10000, 128), ref checks);
            Require(FileInspector.WouldExceedDirectoryLimits(1, 129), ref checks);
            Require(!FileInspector.WouldExceedEnumerationLimit(19999), ref checks);
            Require(FileInspector.WouldExceedEnumerationLimit(20000), ref checks);
            Require(!FileInspector.WouldExceedRetainedPathLimit(8L * 1024 * 1024 - 1, 1), ref checks);
            Require(FileInspector.WouldExceedRetainedPathLimit(8L * 1024 * 1024 - 1, 2), ref checks);
            Require(TestValidEmptyArchivePreflight(), ref checks);
            Require(TestValidSingleEntryArchivePreflight(), ref checks);
            Require(TestValidEmptyZip64Preflight(), ref checks);
            Require(TestArchiveEntryFloodPreflight(), ref checks);
            Require(TestUnderreportedArchivePreflight(), ref checks);
            Require(TestAmbiguousEndRecordPreflight(), ref checks);
            Require(WindowsProcessHardening.Current.IsEnforced, ref checks);

            var result = new ScanResult
            {
                TargetName = "self-test.txt",
                SecurityProfile = SecurityPosture.ProfileId,
                SecurityControlsEnforced = WindowsProcessHardening.Current.EnforcedCount,
                SecurityControlsRequired = WindowsProcessHardening.Current.RequiredCount,
                StartedAt = DateTime.Now
            };
            result.Files.Add(clear);
            string report = ReportBuilder.Build(result, "en");
            Require(report.Contains("13/13 controls enforced", StringComparison.Ordinal), ref checks);
            Require(!report.Contains("C:\\Users\\", StringComparison.OrdinalIgnoreCase), ref checks);
            Require(TestGuardedReportReplacement(result), ref checks);
            return new ProductSelfTestResult(true, checks);
        }
        catch
        {
            return new ProductSelfTestResult(false, checks);
        }
    }

    private static FileAnalysis CreateFile(
        string relativePath,
        string fileType,
        string signatureStatus,
        string signer,
        string sourceHost,
        Indicator? indicator = null)
    {
        var file = new FileAnalysis
        {
            RelativePath = relativePath,
            FileType = fileType,
            SignatureStatus = signatureStatus,
            Signer = signer,
            SourceHost = sourceHost
        };
        if (indicator is not null) file.Indicators.Add(indicator);
        return file;
    }

    private static bool TestGuardedReportReplacement(ScanResult result)
    {
        string temporaryRoot = SecurityPolicy.ValidateLocalDirectory(Path.GetTempPath(), mustExist: true);
        string directory = Path.Combine(temporaryRoot, $"PCBlackBox-SelfTest-{Guid.NewGuid():N}");
        string reportPath = Path.Combine(directory, "report.md");
        bool replacementVerified = false;
        try
        {
            Directory.CreateDirectory(directory);
            SafeReportWriter.Write(reportPath, "first", result, ".md", allowOverwrite: false);
            SafeReportWriter.Write(reportPath, "second", result, ".md", allowOverwrite: true);
            using FileStream stream = SecureFileReader.OpenRead(reportPath, 4096);
            using var reader = new StreamReader(stream);
            replacementVerified = reader.ReadToEnd().Equals("second", StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                if (File.Exists(reportPath) && (File.GetAttributes(reportPath) & FileAttributes.ReparsePoint) == 0)
                {
                    File.Delete(reportPath);
                }
                if (Directory.Exists(directory) && (File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0)
                {
                    Directory.Delete(directory, recursive: false);
                }
            }
            catch { }
        }
        return replacementVerified &&
               !File.Exists(reportPath) && !Directory.Exists(reportPath) &&
               !File.Exists(directory) && !Directory.Exists(directory);
    }

    private static bool TestValidEmptyArchivePreflight()
    {
        using var stream = new MemoryStream();
        using (new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
        }
        stream.Position = 0;
        return FileInspector.IsArchiveStructureWithinLimits(stream);
    }

    private static bool TestArchiveEntryFloodPreflight()
    {
        byte[] endRecord = new byte[22];
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord, 0x06054B50);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord.AsSpan(8), 10001);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord.AsSpan(10), 10001);
        using var stream = new MemoryStream(endRecord, writable: false);
        return !FileInspector.IsArchiveStructureWithinLimits(stream);
    }

    private static bool TestValidSingleEntryArchivePreflight()
    {
        using MemoryStream stream = CreateSingleEntryArchive();
        return FileInspector.IsArchiveStructureWithinLimits(stream);
    }

    private static bool TestUnderreportedArchivePreflight()
    {
        using MemoryStream validArchive = CreateSingleEntryArchive();
        byte[] bytes = validArchive.ToArray();
        int endRecordOffset = bytes.Length - 22;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(endRecordOffset + 8), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(endRecordOffset + 10), 0);
        using var malformedArchive = new MemoryStream(bytes, writable: false);
        return !FileInspector.IsArchiveStructureWithinLimits(malformedArchive);
    }

    private static bool TestAmbiguousEndRecordPreflight()
    {
        using MemoryStream validArchive = CreateSingleEntryArchive();
        byte[] original = validArchive.ToArray();
        byte[] ambiguous = new byte[original.Length + 22];
        original.CopyTo(ambiguous, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(ambiguous.AsSpan(original.Length), 0x06054B50);
        using var stream = new MemoryStream(ambiguous, writable: false);
        return !FileInspector.IsArchiveStructureWithinLimits(stream);
    }

    private static MemoryStream CreateSingleEntryArchive()
    {
        var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry("one.txt", CompressionLevel.NoCompression);
            using Stream entryStream = entry.Open();
            entryStream.WriteByte(1);
        }
        stream.Position = 0;
        return stream;
    }

    private static bool TestValidEmptyZip64Preflight()
    {
        byte[] bytes = new byte[56 + 20 + 22];
        Span<byte> zip64End = bytes.AsSpan(0, 56);
        BinaryPrimitives.WriteUInt32LittleEndian(zip64End, 0x06064B50);
        BinaryPrimitives.WriteUInt64LittleEndian(zip64End[4..], 44);
        BinaryPrimitives.WriteUInt16LittleEndian(zip64End[12..], 45);
        BinaryPrimitives.WriteUInt16LittleEndian(zip64End[14..], 45);

        Span<byte> locator = bytes.AsSpan(56, 20);
        BinaryPrimitives.WriteUInt32LittleEndian(locator, 0x07064B50);
        BinaryPrimitives.WriteUInt64LittleEndian(locator[8..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(locator[16..], 1);

        Span<byte> endRecord = bytes.AsSpan(76, 22);
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord, 0x06054B50);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[4..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[6..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[8..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[10..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord[12..], UInt32.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord[16..], UInt32.MaxValue);

        using var stream = new MemoryStream(bytes, writable: false);
        return FileInspector.IsArchiveStructureWithinLimits(stream);
    }

    private static void Require(bool condition, ref int checks)
    {
        checks++;
        if (!condition) throw new InvalidOperationException("A product self-test check failed.");
    }
}
