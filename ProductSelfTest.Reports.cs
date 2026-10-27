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
            if (root.GetProperty("schema").GetString() != "pc-black-box-batch-report-v2" ||
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
