using System.Text;
using System.Text.Json;

namespace DestinyBlackBox;

public static class ReportBuilder
{
    public static string Build(ScanResult result, string language)
    {
        bool ja = !language.Equals("en", StringComparison.OrdinalIgnoreCase);
        var builder = new StringBuilder();
        builder.AppendLine("# PC Black Box — Download Inspection Report");
        builder.AppendLine();
        builder.AppendLine($"- {(ja ? "対象" : "Target")}: `{Escape(result.TargetName)}`");
        builder.AppendLine($"- {(ja ? "開始" : "Started")}: {result.StartedAt:yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine($"- {(ja ? "所要時間" : "Duration")}: {result.Duration.TotalSeconds:F1} s");
        builder.AppendLine($"- {(ja ? "セキュリティ基準" : "Security baseline")}: {Escape(result.SecurityProfile)} — {result.SecurityControlsEnforced}/{result.SecurityControlsRequired} {(ja ? "強制確認済み" : "controls enforced")}");
        builder.AppendLine($"- {(ja ? "判定" : "Assessment")}: **{result.RiskCode} ({result.RiskScore}/100)**");
        builder.AppendLine($"- {(ja ? "ファイル数" : "Files")}: {result.Files.Count}");
        builder.AppendLine($"- {(ja ? "合計サイズ" : "Total size")}: {FileAnalysis.FormatSize(result.TotalBytes)}");
        builder.AppendLine($"- {(ja ? "有効な署名" : "Valid signatures")}: {result.SignedCount}");
        builder.AppendLine($"- {(ja ? "アクティブコンテンツ" : "Active-content files")}: {result.ActiveContentCount}");
        if (result.IsPartial)
        {
            builder.AppendLine($"- {(ja ? "範囲" : "Scope")}: **PARTIAL** — {Escape(result.PartialReason)}");
        }
        builder.AppendLine();

        builder.AppendLine(ja ? "## 主な所見" : "## Key findings");
        builder.AppendLine();
        List<(FileAnalysis File, Indicator Indicator)> findings = result.Files
            .SelectMany(file => file.Indicators.Select(indicator => (file, indicator)))
            .OrderByDescending(item => item.indicator.Score)
            .ThenBy(item => item.file.RelativePath, StringComparer.OrdinalIgnoreCase)
            .Take(100)
            .Select(item => (item.file, item.indicator))
            .ToList();

        if (findings.Count == 0)
        {
            builder.AppendLine(ja
                ? "明白な危険指標は見つかりませんでした。ただし、安全性を保証する結果ではありません。"
                : "No obvious risk indicator was found. This result is not a guarantee of safety.");
        }
        else
        {
            foreach ((FileAnalysis file, Indicator indicator) in findings)
            {
                string message = ja ? indicator.Japanese : indicator.English;
                builder.AppendLine($"- **{indicator.Severity.ToUpperInvariant()}** `{Escape(file.RelativePath)}` — {Escape(message)} (+{indicator.Score})");
            }
        }
        builder.AppendLine();

        builder.AppendLine(ja ? "## ファイル一覧" : "## File inventory");
        builder.AppendLine();
        builder.AppendLine("| Risk | File | Size | Type | Signature | SHA-256 | Source host |");
        builder.AppendLine("|---:|---|---:|---|---|---|---|");
        foreach (FileAnalysis file in result.Files.OrderByDescending(x => x.RiskScore).ThenBy(x => x.RelativePath, StringComparer.OrdinalIgnoreCase).Take(500))
        {
            builder.AppendLine($"| {file.RiskScore} | `{Escape(file.RelativePath)}` | {file.SizeText} | {Escape(file.FileType)} | {Escape(file.SignatureStatus)} | `{file.Sha256}` | {Escape(file.SourceHost)} |");
        }
        if (result.Files.Count > 500)
        {
            builder.AppendLine();
            builder.AppendLine(ja ? $"一覧は500件で省略しました（全{result.Files.Count}件）。" : $"The inventory is truncated to 500 of {result.Files.Count} files.");
        }
        builder.AppendLine();

        builder.AppendLine(ja ? "## 判定の読み方" : "## How to read this result");
        builder.AppendLine();
        builder.AppendLine(ja
            ? "この点数は、署名、Internet Zone、拡張子偽装、スクリプト能力、圧縮ファイル構造などの静的な兆候を合算した優先順位です。マルウェア判定ではありません。正規の管理ツールやインストーラーも警告される場合があります。"
            : "The score prioritizes static indicators such as signatures, Internet Zone metadata, extension mismatches, script capabilities, and archive structure. It is not a malware verdict; legitimate administration tools and installers can also trigger warnings.");
        builder.AppendLine();

        builder.AppendLine(ja ? "## プライバシーと制約" : "## Privacy and limitations");
        builder.AppendLine();
        builder.AppendLine(ja
            ? "対象は実行していません。ファイルのアップロード、外部サイト照会、ネットワーク通信、プロセス注入、メモリ読み取りは行いません。レポートには絶対パス、Windowsユーザー名、IPアドレス、Steam ID、認証情報を含めません。"
            : "The target was not executed. No file upload, external lookup, network request, process injection, or memory read is performed. The report omits absolute paths, Windows user names, IP addresses, Steam IDs, and credentials.");
        return builder.ToString();
    }

    public static string BuildJson(ScanResult result, string language)
    {
        bool ja = !language.Equals("en", StringComparison.OrdinalIgnoreCase);
        var payload = new
        {
            schema = "pc-black-box-report-v2",
            generatedAt = DateTimeOffset.UtcNow,
            target = Clean(result.TargetName),
            security = new
            {
                profile = Clean(result.SecurityProfile),
                enforced = result.SecurityControlsEnforced == result.SecurityControlsRequired && result.SecurityControlsRequired > 0,
                controlsEnforced = result.SecurityControlsEnforced,
                controlsRequired = result.SecurityControlsRequired
            },
            result = new
            {
                risk = result.RiskCode,
                score = result.RiskScore,
                result.Files.Count,
                totalBytes = result.TotalBytes,
                result.HighCount,
                result.ReviewCount,
                result.SignedCount,
                result.ActiveContentCount,
                result.IsPartial,
                partialReason = Clean(result.PartialReason),
                durationSeconds = Math.Round(result.Duration.TotalSeconds, 3)
            },
            files = result.Files.Select(file => new
            {
                path = Clean(file.RelativePath),
                file.Size,
                fileType = Clean(file.FileType),
                architecture = Clean(file.Architecture),
                file.Sha256,
                file.Entropy,
                signatureStatus = Clean(file.SignatureStatus),
                signer = Clean(file.Signer),
                file.InternetZone,
                sourceHost = file.SourceHost == "—" ? null : Clean(file.SourceHost),
                file.ArchiveEntries,
                file.InspectionLimited,
                riskScore = file.RiskScore,
                risk = file.RiskCode,
                indicators = file.Indicators.Select(indicator => new
                {
                    severity = Clean(indicator.Severity),
                    code = Clean(indicator.Code),
                    score = indicator.Score,
                    message = Clean(ja ? indicator.Japanese : indicator.English)
                })
            })
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string Clean(string value) => SecurityPolicy.SanitizeText(value, 2048).Trim();

    private static string Escape(string value) => Clean(value).Replace("|", "/").Replace("`", "'");
}
