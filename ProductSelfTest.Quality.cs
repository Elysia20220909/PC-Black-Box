using System.Globalization;
using System.IO;

namespace DestinyBlackBox;

internal static partial class ProductSelfTest
{
    private static FileAnalysis ScanSingleFile(string path) =>
        new FileInspector().ScanAsync(path, null, CancellationToken.None).GetAwaiter().GetResult().Files[0];

    private static bool TestInternetZoneMetadataIsReadOrReported() =>
        WithFixtureDirectory(directory =>
        {
            string plain = Path.Combine(directory, "plain.txt");
            File.WriteAllText(plain, "plain text");
            FileAnalysis unmarked = ScanSingleFile(plain);
            if (unmarked.InternetZone is not null || unmarked.InspectionLimited) return false;

            string marked = Path.Combine(directory, "marked.txt");
            File.WriteAllText(marked, "plain text");
            File.WriteAllText(marked + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/file\r\n");
            FileAnalysis zoned = ScanSingleFile(marked);
            if (zoned.InternetZone != 3 || zoned.SourceHost != "example.invalid" || zoned.InspectionLimited) return false;

            string oversized = Path.Combine(directory, "oversized.txt");
            File.WriteAllText(oversized, "plain text");
            File.WriteAllBytes(oversized + ":Zone.Identifier", new byte[SecurityPolicy.MaxZoneIdentifierBytes + 1]);
            FileAnalysis unread = ScanSingleFile(oversized);
            return unread.InternetZone is null &&
                   (unread.Limits & InspectionLimit.Structure) != 0 &&
                   unread.Indicators.Any(indicator => indicator.Code == "zone-metadata-unread");
        });

    private static bool TestReportFormattingIgnoresRegionalFormat()
    {
        CultureInfo original = CultureInfo.CurrentCulture;
        try
        {
            // de-DE changes the decimal separator; th-TH changes the calendar year.
            foreach (string culture in new[] { "de-DE", "th-TH" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var result = new ScanResult
                {
                    TargetName = "regional.txt",
                    StartedAt = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Local),
                    Duration = TimeSpan.FromSeconds(1.5)
                };
                string report = ReportBuilder.Build(result, "en");
                if (FileAnalysis.FormatSize(1536) != "1.5 KB" ||
                    new FileAnalysis { Entropy = 7.5 }.EntropyText != "7.50" ||
                    !report.Contains("2026-01-02 03:04:05", StringComparison.Ordinal) ||
                    !report.Contains("1.5 s", StringComparison.Ordinal))
                {
                    return false;
                }
            }
            return true;
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    private static bool TestCommandLineModes() =>
        App.ParseCommandLineMode([]) == App.CommandLineMode.Window &&
        App.ParseCommandLineMode(["--SELF-TEST"]) == App.CommandLineMode.SelfTest &&
        App.ParseCommandLineMode(["--security-status"]) == App.CommandLineMode.SecurityStatus &&
        App.ParseCommandLineMode(["--report", "target", "report.md"]) == App.CommandLineMode.Report &&
        App.ParseCommandLineMode(["--batch"]) == App.CommandLineMode.Batch &&
        App.ParseCommandLineMode(["--runtime-boundary-test-host"]) == App.CommandLineMode.BoundaryHost &&
        App.ParseCommandLineMode(["--report", "target"]) == App.CommandLineMode.Invalid &&
        App.ParseCommandLineMode(["--self-test", "extra"]) == App.CommandLineMode.Invalid &&
        App.ParseCommandLineMode(["--self-tset"]) == App.CommandLineMode.Invalid &&
        App.ParseCommandLineMode(["target.exe"]) == App.CommandLineMode.Invalid;

    private static bool BatchArgumentsAreRefused(string[] args)
    {
        try
        {
            _ = App.ParseBatchArguments(args);
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static bool TestBatchArgumentsRefuseRepeats() =>
        App.ParseBatchArguments(["--batch", "--OUTPUT", "report.json", "--file-list", "list.txt"]) == ("list.txt", "report.json") &&
        BatchArgumentsAreRefused(["--batch", "--file-list", "a.txt", "--file-list", "b.txt", "--output", "report.json"]) &&
        BatchArgumentsAreRefused(["--batch", "--file-list", "list.txt", "--output", "a.json", "--output", "b.json"]) &&
        BatchArgumentsAreRefused(["--batch", "--file-list", "list.txt", "--FILE-LIST", "list.txt", "--output", "report.json"]) &&
        BatchArgumentsAreRefused(["--batch", "--file-list", "list.txt", "--output"]) &&
        BatchArgumentsAreRefused(["--batch", "--file-list", "list.txt"]) &&
        BatchArgumentsAreRefused(["--batch", "--file-list", "list.txt", "--output", "report.json", "--extra"]);

    private static bool TestRiskBandsMatchEveryCount()
    {
        var result = new ScanResult { TargetName = "bands" };
        result.Files.Add(CreateFile("high.ps1", "Text", "Not checked", "—", "—", new("danger", "high", "高", "High", RiskBands.High)));
        result.Files.Add(CreateFile("review.ps1", "Text", "Not checked", "—", "—", new("watch", "review", "中", "Review", RiskBands.Review)));
        result.Files.Add(CreateFile("low.ps1", "Text", "Not checked", "—", "—", new("watch", "low", "低", "Low", RiskBands.Review - 1)));
        result.Files.Add(CreateFile("clear.txt", "Text", "Not checked", "—", "—"));

        return result.Files.Select(file => file.RiskCode).SequenceEqual(["HIGH", "REVIEW", "LOW", "CLEAR"]) &&
               result.HighCount == 1 && result.ReviewCount == 1 && result.RiskCode == "HIGH";
    }
}
