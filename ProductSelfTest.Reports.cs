using System.Text.Json;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    private static ScanResult CreateBatchReportFixture(string targetPath, string targetName, string relativePath, long size = 12)
    {
        var result = new ScanResult { TargetPath = targetPath, TargetName = targetName };
        result.Files.Add(new FileAnalysis
        {
            FullPath = targetPath,
            RelativePath = relativePath,
            Size = size,
            Sha256 = new string('A', 64),
            FileType = "Text"
        });
        return result;
    }

    // Decode JSON before checking for leaks: raw JSON escapes path separators and Unicode.
    private static IEnumerable<string> ReportStringValues(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            yield return element.GetString()!;
        }
        else if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
                foreach (string value in ReportStringValues(property.Value))
                    yield return value;
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
                foreach (string value in ReportStringValues(item))
                    yield return value;
        }
    }

    private static bool TestBatchReportOmitsTargetPaths()
    {
        string[] paths =
        [
            @"C:\Users\BatchPrivate\私用\same.txt",
            @"\\private-server\private-share\same.txt",
            @"\\?\C:\BatchPrivate\same.txt",
            "/private-home/BatchPrivate/same.txt"
        ];
        ScanResult[] results = paths.Select(path => CreateBatchReportFixture(path, "same.txt", @"sub\same.txt")).ToArray();
        foreach (string language in new[] { "ja", "en" })
        {
            using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildBatchJson(results, language));
            JsonElement root = document.RootElement;
            if (root.GetProperty("schema").GetString() != "pc-black-box-batch-report-v4" ||
                root.GetProperty("targetCount").GetInt32() != paths.Length) return false;
            foreach (JsonElement target in root.GetProperty("targets").EnumerateArray())
            {
                JsonElement file = target.GetProperty("result").GetProperty("files")[0];
                if (target.TryGetProperty("path", out _) || target.GetProperty("target").GetString() != "same.txt" ||
                    file.GetProperty("path").GetString() != @"sub\same.txt" ||
                    file.GetProperty("Sha256").GetString() != new string('A', 64)) return false;
            }
            if (ReportStringValues(root).Any(value => paths.Any(path => value.Contains(path, StringComparison.OrdinalIgnoreCase)) ||
                value.Contains("BatchPrivate", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("private-server", StringComparison.OrdinalIgnoreCase))) return false;
        }
        return true;
    }

    // Every coverage field differs from its default, so a field dropped or swapped on one side is visible.
    private static ScanResult CreateCoverageFixture(bool archiveTotalKnown)
    {
        var result = new ScanResult
        {
            TargetPath = @"C:\Users\BatchPrivate\coverage.zip",
            TargetName = "coverage.zip",
            SecurityProfile = "fixture",
            SecurityControlsEnforced = 16,
            SecurityControlsRequired = 16,
            SecurityReinforcementsEnforced = 1,
            SecurityReinforcementsAvailable = 2,
            Duration = TimeSpan.FromSeconds(1.5),
            IsPartial = true,
            TraversalComplete = false,
            PartialReason = "Fixture coverage is incomplete."
        };
        var file = new FileAnalysis
        {
            FullPath = result.TargetPath,
            RelativePath = "coverage.zip",
            Size = 4096,
            Sha256 = new string('B', 64),
            FileType = "ZIP archive",
            Architecture = "x64",
            Entropy = 7.5,
            SignatureStatus = "Valid",
            Signer = "Fixture signer",
            InternetZone = 3,
            SourceHost = "example.invalid",
            ArchiveEntries = 9,
            EmbeddedZipPayload = true,
            ArchiveHasPrefix = true,
            ArchivePrefixBytes = 7,
            ArchiveContentScanApplicable = true,
            ArchiveContentTotalKnown = archiveTotalKnown,
            ArchiveContentEligibleBytes = 2048,
            ArchiveContentScannedBytes = 1024,
            ArchiveBudgetTailEntryBodies = 5,
            ArchiveBudgetTailActiveEntries = 2,
            ArchiveBudgetTailContainerEntries = 1,
            NestedArchivesInspected = 3,
            NestedArchiveEntriesInspected = 11,
            ArchiveMaxDepthInspected = 2,
            NestedArchiveBytesInspected = 512,
            ShortcutTarget = @"D:\Evidence\payload.exe",
            ShortcutArguments = "--fixture",
            Limits = InspectionLimit.Content | InspectionLimit.Structure,
            CapabilityScanApplicable = true,
            CapabilityScannedBytes = 256
        };
        file.Indicators.Add(new Indicator("watch", "fixture", "証拠", "Evidence", RiskBands.Review));
        result.Files.Add(file);
        return result;
    }

    // Field names differ in case for historical reasons, and only the batch holds files inside "result".
    private static bool BatchResultMatchesSingle(JsonElement single, JsonElement batch)
    {
        Dictionary<string, JsonElement> batchFields = batch.EnumerateObject()
            .Where(field => field.Name != "files")
            .ToDictionary(field => field.Name, field => field.Value, StringComparer.OrdinalIgnoreCase);
        List<JsonProperty> singleFields = single.EnumerateObject().ToList();
        return singleFields.Count == batchFields.Count &&
               singleFields.All(field =>
                   batchFields.TryGetValue(field.Name == "Count" ? "fileCount" : field.Name, out JsonElement value) &&
                   JsonElement.DeepEquals(field.Value, value));
    }

    private static bool TestBatchTargetMatchesSingleReport()
    {
        foreach (bool archiveTotalKnown in new[] { true, false })
        {
            ScanResult result = CreateCoverageFixture(archiveTotalKnown);
            foreach (string language in new[] { "ja", "en" })
            {
                using JsonDocument singleDocument = JsonDocument.Parse(ReportBuilder.BuildJson(result, language));
                using JsonDocument batchDocument = JsonDocument.Parse(ReportBuilder.BuildBatchJson([result], language));
                JsonElement single = singleDocument.RootElement;
                JsonElement target = batchDocument.RootElement.GetProperty("targets")[0];
                JsonElement batchResult = target.GetProperty("result");
                JsonElement batchFile = batchResult.GetProperty("files")[0];
                if (!JsonElement.DeepEquals(single.GetProperty("target"), target.GetProperty("target")) ||
                    !JsonElement.DeepEquals(single.GetProperty("security"), target.GetProperty("security")) ||
                    !JsonElement.DeepEquals(single.GetProperty("files"), batchResult.GetProperty("files")) ||
                    !BatchResultMatchesSingle(single.GetProperty("result"), batchResult)) return false;

                // Named values keep the comparison from passing because a field left both reports together.
                if (!batchFile.GetProperty("archiveHasPrefix").GetBoolean() ||
                    batchFile.GetProperty("archivePrefixBytes").GetInt64() != 7 ||
                    batchFile.GetProperty("archiveContentTotalKnown").GetBoolean() != archiveTotalKnown ||
                    batchFile.GetProperty("archiveBudgetTailEntryBodies").GetInt32() != 5 ||
                    batchFile.GetProperty("archiveBudgetTailActiveEntries").GetInt32() != 2 ||
                    batchFile.GetProperty("archiveBudgetTailContainerEntries").GetInt32() != 1 ||
                    batchFile.GetProperty("nestedArchivesInspected").GetInt32() != 3 ||
                    batchFile.GetProperty("nestedArchiveEntriesInspected").GetInt32() != 11 ||
                    batchFile.GetProperty("archiveMaxDepthInspected").GetInt32() != 2 ||
                    batchFile.GetProperty("nestedArchiveBytesInspected").GetInt64() != 512 ||
                    batchResult.GetProperty("capabilityEligibleBytes").GetInt64() != 4096 ||
                    batchResult.GetProperty("sha256BytesRead").GetInt64() != 4096 ||
                    batchResult.GetProperty("unexamined").GetProperty("structure").GetInt32() != 1) return false;

                JsonElement eligible = batchFile.GetProperty("archiveContentEligibleBytes");
                if (archiveTotalKnown ? eligible.GetInt64() != 2048 : eligible.ValueKind != JsonValueKind.Null) return false;
            }
        }
        return true;
    }

    private static bool BatchSummaryIs(
        IReadOnlyList<ScanResult> results, string assessment, string completeness, int incomplete, int skipped)
    {
        using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildBatchJson(results, "en"));
        JsonElement summary = document.RootElement.GetProperty("summary");
        return !summary.TryGetProperty("overallRisk", out _) &&
               summary.GetProperty("overallAssessment").GetString() == assessment &&
               summary.GetProperty("overallCompleteness").GetString() == completeness &&
               summary.GetProperty("incompleteTargets").GetInt32() == incomplete &&
               summary.GetProperty("skippedTargets").GetInt32() == skipped;
    }

    private static bool TestBatchSummaryDoesNotHideFailures()
    {
        var failed = new ScanResult { IsPartial = true, PartialReason = "Inspection failed safely; target was skipped." };
        var clear = new ScanResult { TargetName = "clear" };
        var low = new ScanResult { TargetName = "low" };
        low.Files.Add(CreateFile("download.txt", "Text", "Not checked", "—", "example.invalid",
            new("info", "internet-origin", "由来", "Origin", 0)));
        var high = new ScanResult { TargetName = "high" };
        high.Files.Add(CreateFile("danger.ps1", "Script / active text", "NotSigned", "—", "—",
            new("danger", "process-injection", "注入", "Injection", 60)));

        return BatchSummaryIs([failed], "INCOMPLETE", "INCOMPLETE", 1, 1) &&
               BatchSummaryIs([clear], "CLEAR", "COMPLETE", 0, 0) &&
               BatchSummaryIs([clear, low], "LOW", "COMPLETE", 0, 0) &&
               BatchSummaryIs([clear, failed], "INCOMPLETE", "INCOMPLETE", 1, 1) &&
               BatchSummaryIs([low, failed], "LOW+INCOMPLETE", "INCOMPLETE", 1, 1) &&
               BatchSummaryIs([high, failed], "HIGH+INCOMPLETE", "INCOMPLETE", 1, 1);
    }

    private static bool TestBatchExitCodeReportsIncompleteTargets() =>
        App.BatchExitCode([new ScanResult { TargetName = "complete" }]) == 0 &&
        App.BatchExitCode([new ScanResult { TargetName = "complete" }, new ScanResult { IsPartial = true }]) ==
            App.BatchIncompleteExitCode;

    private static bool TestRiskFilterFollowsDisplayedRiskCode()
    {
        FileAnalysis informational = CreateFile("download.txt", "Text", "Not checked", "—", "example.invalid",
            new("info", "internet-origin", "由来", "Origin", 0));
        FileAnalysis clear = CreateFile("plain.txt", "Text", "Not checked", "—", "—");
        FileAnalysis[] files = [informational, clear];

        return informational.RiskCode == "LOW" && clear.RiskCode == "CLEAR" &&
               FileViewQuery.Apply(files, "LOW", null).SequenceEqual([informational]) &&
               FileViewQuery.Apply(files, "CLEAR", null).SequenceEqual([clear]);
    }

    private static bool TestBatchReportPreservesOrderAndFailures()
    {
        ScanResult first = CreateBatchReportFixture(@"C:\Users\BatchPrivate\first\same", "same", "first.txt", 12);
        ScanResult second = CreateBatchReportFixture(@"C:\Users\BatchPrivate\second\same", "same", @"child\second.txt", 24);
        var skipped = new ScanResult
        {
            TargetPath = @"C:\Users\BatchPrivate\missing\",
            TargetName = String.Empty,
            IsPartial = true,
            PartialReason = "Inspection failed safely; target was skipped."
        };
        using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildBatchJson([first, second, skipped], "en"));
        JsonElement root = document.RootElement;
        JsonElement targets = root.GetProperty("targets");
        JsonElement failed = targets[2].GetProperty("result");
        return root.GetProperty("targetCount").GetInt32() == 3 &&
               targets[0].GetProperty("target").GetString() == "same" &&
               targets[1].GetProperty("target").GetString() == "same" &&
               targets[0].GetProperty("result").GetProperty("files")[0].GetProperty("path").GetString() == "first.txt" &&
               targets[1].GetProperty("result").GetProperty("files")[0].GetProperty("path").GetString() == @"child\second.txt" &&
               targets[2].GetProperty("target").GetString() == "target" &&
               !targets[2].TryGetProperty("path", out _) &&
               failed.GetProperty("completeness").GetString() == "INCOMPLETE" &&
               failed.GetProperty("fileCount").GetInt32() == 0 &&
               failed.GetProperty("partialReason").GetString() == skipped.PartialReason &&
               root.GetProperty("summary").GetProperty("totalBytes").GetInt64() == 36 &&
               root.GetProperty("summary").GetProperty("skippedTargets").GetInt32() == 1 &&
               !ReportStringValues(root).Any(value => value.Contains("BatchPrivate", StringComparison.OrdinalIgnoreCase));
    }

    private static bool TestReportTargetNamesAreLocalLabels()
    {
        (string? Name, string Expected)[] cases =
        [
            (@"C:\", "target"),
            (@"C:", "target"),
            (@"C:\Users\BatchPrivate\leaf.txt", "leaf.txt"),
            (@"\\private-server\private-share\", "target"),
            (@"\\private-server\private-share\folder\", "folder"),
            ("folder/leaf", "leaf"),
            ("/", "target"),
            (String.Empty, "target"),
            (null, "target"),
            ("note\u202E.txt", "note\uFFFD.txt")
        ];
        for (int index = 0; index < cases.Length; index++)
        {
            var test = cases[index];
            var result = new ScanResult { TargetPath = @"C:\Users\BatchPrivate\original", TargetName = test.Name! };
            using JsonDocument single = JsonDocument.Parse(ReportBuilder.BuildJson(result, "en"));
            using JsonDocument batch = JsonDocument.Parse(ReportBuilder.BuildBatchJson([result], "en"));
            string markdown = ReportBuilder.Build(result, "en");
            if (single.RootElement.GetProperty("target").GetString() != test.Expected ||
                batch.RootElement.GetProperty("targets")[0].GetProperty("target").GetString() != test.Expected ||
                !markdown.Contains($"- Target: `{test.Expected}`", StringComparison.Ordinal))
            {
                Console.Error.WriteLine($"REPORT_LABEL_FAILED case={index} single={single.RootElement.GetProperty("target").GetString() == test.Expected} batch={batch.RootElement.GetProperty("targets")[0].GetProperty("target").GetString() == test.Expected}");
                return false;
            }
        }
        return true;
    }

    private static bool TestBatchReportPreservesEvidencePaths()
    {
        const string evidencePath = @"D:\Evidence\payload.exe";
        const string evidenceArguments = @"--source E:\Evidence\input.dat";
        var result = new ScanResult { TargetPath = @"C:\Users\BatchPrivate\sample.lnk", TargetName = "sample.lnk" };
        var file = new FileAnalysis
        {
            FullPath = result.TargetPath,
            RelativePath = "sample.lnk",
            ShortcutTarget = evidencePath,
            ShortcutArguments = evidenceArguments
        };
        file.Indicators.Add(new Indicator("watch", "fixture", "証拠: " + evidencePath, "Evidence: " + evidencePath, 10));
        result.Files.Add(file);
        foreach (string language in new[] { "ja", "en" })
        {
            using JsonDocument document = JsonDocument.Parse(ReportBuilder.BuildBatchJson([result], language));
            JsonElement reported = document.RootElement.GetProperty("targets")[0].GetProperty("result").GetProperty("files")[0];
            if (reported.GetProperty("shortcutTarget").GetString() != evidencePath ||
                reported.GetProperty("shortcutArguments").GetString() != evidenceArguments ||
                !reported.GetProperty("indicators")[0].GetProperty("message").GetString()!.Contains(evidencePath, StringComparison.Ordinal) ||
                ReportStringValues(document.RootElement).Any(value => value.Contains("BatchPrivate", StringComparison.OrdinalIgnoreCase))) return false;
        }
        return true;
    }
}
