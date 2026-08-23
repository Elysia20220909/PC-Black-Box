using System.IO;

namespace DestinyBlackBox;

public sealed record Indicator(string Severity, string Code, string Japanese, string English, int Score);

/// <summary>
/// What an inspection did not finish looking at. The four file aspects are kept apart because "every byte
/// was hashed and every applicable capability surface was read, but the archive was never opened" and
/// "the content budget ran out before the payload was read" require different operator responses.
/// </summary>
[Flags]
public enum InspectionLimit
{
    None = 0,
    Digest = 1 << 0,
    Content = 1 << 1,
    Signature = 1 << 2,
    Structure = 1 << 3,
    Everything = Digest | Content | Signature | Structure
}

public static class InspectionAspects
{
    /// <summary>Reported in the order the inspection performs them, so the list reads as a sequence.</summary>
    public static IReadOnlyList<InspectionLimit> All { get; } = Array.AsReadOnly(new[]
    {
        InspectionLimit.Digest,
        InspectionLimit.Content,
        InspectionLimit.Signature,
        InspectionLimit.Structure
    });

    public static string Code(InspectionLimit aspect) => aspect switch
    {
        InspectionLimit.Digest => "digest",
        InspectionLimit.Content => "content",
        InspectionLimit.Signature => "signature",
        InspectionLimit.Structure => "structure",
        _ => throw new ArgumentOutOfRangeException(nameof(aspect))
    };

    public static string Describe(InspectionLimit aspect, bool japanese) => aspect switch
    {
        InspectionLimit.Digest => japanese ? "ダイジェスト" : "digest",
        InspectionLimit.Content => japanese ? "能力語の内容走査" : "capability content",
        InspectionLimit.Signature => japanese ? "署名確認" : "signature",
        InspectionLimit.Structure => japanese ? "構造の解析" : "structure",
        _ => throw new ArgumentOutOfRangeException(nameof(aspect))
    };
}

public sealed class FileAnalysis
{
    public string FullPath { get; init; } = String.Empty;
    public string RelativePath { get; init; } = String.Empty;
    public long Size { get; init; }
    public string SizeText => FormatSize(Size);
    public string Sha256 { get; set; } = String.Empty;
    public string Sha256Short => Sha256.Length >= 16 ? Sha256[..16] + "…" : Sha256;
    public string FileType { get; set; } = "Unknown";
    public string Architecture { get; set; } = "—";
    public string ProductName { get; set; } = "—";
    public string CompanyName { get; set; } = "—";
    public double? Entropy { get; set; }
    public string EntropyText => Entropy.HasValue ? Entropy.Value.ToString("F2") : "—";
    public string SignatureStatus { get; set; } = "Not checked";
    public string Signer { get; set; } = "—";
    public int? InternetZone { get; set; }
    public string SourceHost { get; set; } = "—";
    public int ArchiveEntries { get; set; }
    public bool EmbeddedZipPayload { get; set; }
    public bool ArchiveHasPrefix { get; set; }
    public long ArchivePrefixBytes { get; set; }
    public bool ArchiveContentScanApplicable { get; set; }
    public bool ArchiveContentTotalKnown { get; set; }
    public long ArchiveContentEligibleBytes { get; set; }
    public long ArchiveContentScannedBytes { get; set; }
    public int NestedArchivesInspected { get; set; }
    public int NestedArchiveEntriesInspected { get; set; }
    public int ArchiveMaxDepthInspected { get; set; }
    public long NestedArchiveBytesInspected { get; set; }
    public string ShortcutTarget { get; set; } = "—";
    public string ShortcutArguments { get; set; } = "—";
    public InspectionLimit Limits { get; internal set; }
    public bool InspectionLimited => Limits != InspectionLimit.None;
    public bool CapabilityScanApplicable { get; set; }
    public long CapabilityScannedBytes { get; set; }
    internal long ObservedLength { get; set; }
    internal DateTime ObservedLastWriteUtc { get; set; }
    internal SecureFileIdentity ObservedIdentity { get; set; }
    public List<Indicator> Indicators { get; } = [];
    public int RiskScore => Math.Clamp(Indicators.Sum(x => x.Score), 0, 100);
    public string RiskCode => RiskScore >= 60 ? "HIGH" : RiskScore >= 25 ? "REVIEW" : Indicators.Count > 0 ? "LOW" : "CLEAR";
    public string RiskDisplay => $"{RiskCode} {RiskScore}";

    public static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return $"{value:0.##} {units[unit]}";
    }
}

public sealed class ScanResult
{
    public string TargetPath { get; init; } = String.Empty;
    public string TargetName { get; init; } = String.Empty;
    public string SecurityProfile { get; init; } = String.Empty;
    public int SecurityControlsEnforced { get; init; }
    public int SecurityControlsRequired { get; init; }
    public int SecurityReinforcementsEnforced { get; init; }
    public int SecurityReinforcementsAvailable { get; init; }
    public DateTime StartedAt { get; init; }
    public bool TargetWasDirectory { get; init; }
    public TimeSpan Duration { get; set; }
    public bool IsPartial { get; set; }
    /// <summary>Whether every file the target holds was reached. The four aspects describe what was done to
    /// the files that were found; this says whether the list of files itself is the whole list.</summary>
    public bool TraversalComplete { get; set; } = true;
    public string PartialReason { get; set; } = String.Empty;
    public List<FileAnalysis> Files { get; } = [];
    public long TotalBytes => Files.Sum(x => x.Size);
    public int HighCount => Files.Count(x => x.RiskScore >= 60);
    public int ReviewCount => Files.Count(x => x.RiskScore is >= 25 and < 60);
    public int SignedCount => Files.Count(x => x.SignatureStatus.Equals("Valid", StringComparison.OrdinalIgnoreCase));
    public int ActiveContentCount => Files.Count(x => x.FileType == "Windows PE" || FileInspector.IsActiveContentExtension(FileInspector.GetInspectionExtension(x)));
    public long CapabilityEligibleBytes => Files.Where(x => x.CapabilityScanApplicable).Sum(x => x.Size);
    public long CapabilityScannedBytes => Files.Sum(x => x.CapabilityScannedBytes);
    public bool ArchiveContentScanApplicable => Files.Any(x => x.ArchiveContentScanApplicable);
    public bool ArchiveContentTotalKnown =>
        ArchiveContentScanApplicable && Files.Where(x => x.ArchiveContentScanApplicable).All(x => x.ArchiveContentTotalKnown);
    public long ArchiveContentEligibleBytes => SaturatingSum(Files.Select(x => x.ArchiveContentEligibleBytes));
    public long ArchiveContentScannedBytes => SaturatingSum(Files.Select(x => x.ArchiveContentScannedBytes));
    public int NestedArchivesInspected => Files.Sum(x => x.NestedArchivesInspected);
    public int NestedArchiveEntriesInspected => Files.Sum(x => x.NestedArchiveEntriesInspected);
    public int ArchiveMaxDepthInspected => Files.Count == 0 ? 0 : Files.Max(x => x.ArchiveMaxDepthInspected);
    public long NestedArchiveBytesInspected => SaturatingSum(Files.Select(x => x.NestedArchiveBytesInspected));
    public int RiskScore => Files.Count == 0 ? 0 : Files.Max(x => x.RiskScore);
    public string RiskCode => RiskScore >= 60 ? "HIGH" : RiskScore >= 25 ? "REVIEW" : Files.Any(x => x.Indicators.Count > 0) ? "LOW" : "CLEAR";
    public InspectionLimit Limits => Files.Aggregate(InspectionLimit.None, (all, file) => all | file.Limits);
    public int LimitedFileCount(InspectionLimit aspect) => Files.Count(file => (file.Limits & aspect) != 0);
    public string CompletenessCode => IsPartial ? "INCOMPLETE" : "COMPLETE";
    public string AssessmentCode => !IsPartial ? RiskCode : RiskCode == "CLEAR" ? "INCOMPLETE" : $"{RiskCode}+INCOMPLETE";

    private static long SaturatingSum(IEnumerable<long> values)
    {
        long total = 0;
        foreach (long value in values)
        {
            if (value > Int64.MaxValue - total) return Int64.MaxValue;
            total += value;
        }
        return total;
    }
}

public sealed record ScanProgress(int Completed, int Total, string CurrentFile);

public sealed record SignatureResult(string Status, string Signer);
