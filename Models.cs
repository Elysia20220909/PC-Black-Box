using System.IO;

namespace DestinyBlackBox;

public sealed record Indicator(string Severity, string Code, string Japanese, string English, int Score);

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
    public string ShortcutTarget { get; set; } = "—";
    public string ShortcutArguments { get; set; } = "—";
    public bool InspectionLimited { get; set; }
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
    public string PartialReason { get; set; } = String.Empty;
    public List<FileAnalysis> Files { get; } = [];
    public long TotalBytes => Files.Sum(x => x.Size);
    public int HighCount => Files.Count(x => x.RiskScore >= 60);
    public int ReviewCount => Files.Count(x => x.RiskScore is >= 25 and < 60);
    public int SignedCount => Files.Count(x => x.SignatureStatus.Equals("Valid", StringComparison.OrdinalIgnoreCase));
    public int ActiveContentCount => Files.Count(x => x.FileType == "Windows PE" || FileInspector.IsActiveContentExtension(FileInspector.GetInspectionExtension(x)));
    public long CapabilityEligibleBytes => Files.Where(x => x.CapabilityScanApplicable).Sum(x => x.Size);
    public long CapabilityScannedBytes => Files.Sum(x => x.CapabilityScannedBytes);
    public int RiskScore => Files.Count == 0 ? 0 : Files.Max(x => x.RiskScore);
    public string RiskCode => RiskScore >= 60 ? "HIGH" : RiskScore >= 25 ? "REVIEW" : Files.Any(x => x.Indicators.Count > 0) ? "LOW" : "CLEAR";
    public string CompletenessCode => IsPartial ? "INCOMPLETE" : "COMPLETE";
    public string AssessmentCode => !IsPartial ? RiskCode : RiskCode == "CLEAR" ? "INCOMPLETE" : $"{RiskCode}+INCOMPLETE";
}

public sealed record ScanProgress(int Completed, int Total, string CurrentFile);

public sealed record SignatureResult(string Status, string Signer);
