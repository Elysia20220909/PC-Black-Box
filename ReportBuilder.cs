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
        builder.AppendLine($"- {(ja ? "追加防御" : "Platform reinforcements")}: {result.SecurityReinforcementsEnforced}/{result.SecurityReinforcementsAvailable} {(ja ? "この環境で有効" : "active on this system")}");
        builder.AppendLine($"- {(ja ? "判定" : "Assessment")}: **{result.AssessmentCode} ({result.RiskScore}/100)**");
        builder.AppendLine($"- {(ja ? "ファイル数" : "Files")}: {result.Files.Count}");
        builder.AppendLine($"- {(ja ? "合計サイズ" : "Total size")}: {FileAnalysis.FormatSize(result.TotalBytes)}");
        builder.AppendLine($"- {(ja ? "SHA-256全読取" : "SHA-256 bytes read")}: {FileAnalysis.FormatSize(result.TotalBytes)}");
        if (result.CapabilityEligibleBytes > 0)
        {
            builder.AppendLine($"- {(ja ? "能力語の内容走査" : "Capability content scan")}: {FileAnalysis.FormatSize(result.CapabilityScannedBytes)} / {FileAnalysis.FormatSize(result.CapabilityEligibleBytes)}");
        }
        if (result.ArchiveContentScanApplicable)
        {
            string archiveCoverage = result.ArchiveContentTotalKnown
                ? $"{FileAnalysis.FormatSize(result.ArchiveContentScannedBytes)} / {FileAnalysis.FormatSize(result.ArchiveContentEligibleBytes)}"
                : ja
                    ? $"{FileAnalysis.FormatSize(result.ArchiveContentScannedBytes)} 走査 / 合計不明"
                    : $"{FileAnalysis.FormatSize(result.ArchiveContentScannedBytes)} scanned / total unknown";
            builder.AppendLine($"- {(ja ? "ZIP内部本文の走査" : "ZIP entry-content scan")}: {archiveCoverage}");
        }
        if (result.NestedArchivesInspected > 0)
        {
            builder.AppendLine($"- {(ja ? "入れ子ZIPの再帰調査" : "Nested ZIP recursion")}: " +
                (ja
                    ? $"{result.NestedArchivesInspected}件 / 内部{result.NestedArchiveEntriesInspected}項目 / 最大深さ{result.ArchiveMaxDepthInspected} / {FileAnalysis.FormatSize(result.NestedArchiveBytesInspected)}"
                    : $"{result.NestedArchivesInspected} archive(s) / {result.NestedArchiveEntriesInspected} inner entries / depth {result.ArchiveMaxDepthInspected} / {FileAnalysis.FormatSize(result.NestedArchiveBytesInspected)}"));
        }
        builder.AppendLine($"- {(ja ? "有効な署名" : "Valid signatures")}: {result.SignedCount}");
        builder.AppendLine($"- {(ja ? "アクティブコンテンツ" : "Active-content files")}: {result.ActiveContentCount}");
        if (result.IsPartial)
        {
            builder.AppendLine($"- {(ja ? "範囲" : "Scope")}: **INCOMPLETE** — {Escape(result.PartialReason)}");
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

        if (result.IsPartial && findings.Count == 0)
        {
            builder.AppendLine(ja
                ? "調査範囲が不完全なため、安全性を評価できません。"
                : "The inspection is incomplete, so safety cannot be assessed.");
        }
        else if (findings.Count == 0)
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

        List<FileAnalysis> shortcuts = result.Files
            .Where(file => file.FileType.Equals(FileInspector.ShortcutType, StringComparison.Ordinal))
            .Where(file => file.ShortcutTarget != "—" || file.ShortcutArguments != "—")
            .OrderByDescending(file => file.RiskScore)
            .Take(50)
            .ToList();
        if (shortcuts.Count > 0)
        {
            builder.AppendLine(ja ? "## ショートカットが起動するもの" : "## What the shortcuts would run");
            builder.AppendLine();
            builder.AppendLine(ja
                ? "| リスク | ファイル | 起動先 | 引数 |"
                : "| Risk | File | Target | Arguments |");
            builder.AppendLine("|---:|---|---|---|");
            foreach (FileAnalysis shortcut in shortcuts)
            {
                builder.AppendLine($"| {shortcut.RiskScore} | `{Escape(shortcut.RelativePath)}` | `{Escape(shortcut.ShortcutTarget)}` | `{Escape(shortcut.ShortcutArguments)}` |");
            }
            builder.AppendLine();
        }

        builder.AppendLine(ja ? "## ファイル一覧" : "## File inventory");
        builder.AppendLine();
        builder.AppendLine("| Risk | File | Size | Type | Signature | SHA-256 | Inspection | Source host |");
        builder.AppendLine("|---:|---|---:|---|---|---|---|---|");
        foreach (FileAnalysis file in result.Files.OrderByDescending(x => x.RiskScore).ThenBy(x => x.RelativePath, StringComparer.OrdinalIgnoreCase).Take(500))
        {
            string coverage = file.InspectionLimited ? "INCOMPLETE" : "complete";
            builder.AppendLine($"| {file.RiskScore} | `{Escape(file.RelativePath)}` | {file.SizeText} | {Escape(file.FileType)} | {Escape(file.SignatureStatus)} | `{file.Sha256}` | {coverage} | {Escape(file.SourceHost)} |");
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
            ? "対象は実行していません。ファイルのアップロード、外部サイト照会、ネットワーク通信、プロセス注入、メモリ読み取りは行いません。この環境の絶対パス、Windowsユーザー名、IPアドレス、Steam ID、認証情報はレポートに含めません。ショートカットの起動先や引数など、調査対象の中に書かれていた文字列は証拠として掲載します。"
            : "The target was not executed. No file upload, external lookup, network request, process injection, or memory read is performed. The report omits this machine's absolute paths, Windows user names, IP addresses, Steam IDs, and credentials. Strings held inside the target, such as a shortcut's command line, are shown as evidence.");
        return builder.ToString();
    }

    public static string BuildJson(ScanResult result, string language)
    {
        bool ja = !language.Equals("en", StringComparison.OrdinalIgnoreCase);
        var payload = new
        {
            schema = "pc-black-box-report-v5",
            generatedAt = DateTimeOffset.UtcNow,
            target = Clean(result.TargetName),
            security = new
            {
                profile = Clean(result.SecurityProfile),
                enforced = result.SecurityControlsEnforced == result.SecurityControlsRequired && result.SecurityControlsRequired > 0,
                controlsEnforced = result.SecurityControlsEnforced,
                controlsRequired = result.SecurityControlsRequired,
                reinforcementsEnforced = result.SecurityReinforcementsEnforced,
                reinforcementsAvailable = result.SecurityReinforcementsAvailable
            },
            result = new
            {
                risk = result.RiskCode,
                completeness = result.CompletenessCode,
                assessment = result.AssessmentCode,
                score = result.RiskScore,
                result.Files.Count,
                totalBytes = result.TotalBytes,
                result.HighCount,
                result.ReviewCount,
                result.SignedCount,
                result.ActiveContentCount,
                result.IsPartial,
                partialReason = Clean(result.PartialReason),
                sha256BytesRead = result.TotalBytes,
                capabilityEligibleBytes = result.CapabilityEligibleBytes,
                capabilityScannedBytes = result.CapabilityScannedBytes,
                archiveContentScanApplicable = result.ArchiveContentScanApplicable,
                archiveContentTotalKnown = result.ArchiveContentTotalKnown,
                archiveContentEligibleBytes = result.ArchiveContentTotalKnown ? result.ArchiveContentEligibleBytes : (long?)null,
                archiveContentScannedBytes = result.ArchiveContentScannedBytes,
                nestedArchivesInspected = result.NestedArchivesInspected,
                nestedArchiveEntriesInspected = result.NestedArchiveEntriesInspected,
                archiveMaxDepthInspected = result.ArchiveMaxDepthInspected,
                nestedArchiveBytesInspected = result.NestedArchiveBytesInspected,
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
                archiveEntries = file.ArchiveEntries,
                embeddedZipPayload = file.EmbeddedZipPayload,
                archiveHasPrefix = file.ArchiveHasPrefix,
                archivePrefixBytes = file.ArchivePrefixBytes,
                archiveContentScanApplicable = file.ArchiveContentScanApplicable,
                archiveContentTotalKnown = file.ArchiveContentTotalKnown,
                archiveContentEligibleBytes = file.ArchiveContentTotalKnown ? file.ArchiveContentEligibleBytes : (long?)null,
                archiveContentScannedBytes = file.ArchiveContentScannedBytes,
                nestedArchivesInspected = file.NestedArchivesInspected,
                nestedArchiveEntriesInspected = file.NestedArchiveEntriesInspected,
                archiveMaxDepthInspected = file.ArchiveMaxDepthInspected,
                nestedArchiveBytesInspected = file.NestedArchiveBytesInspected,
                shortcutTarget = file.ShortcutTarget == "—" ? null : Clean(file.ShortcutTarget),
                shortcutArguments = file.ShortcutArguments == "—" ? null : Clean(file.ShortcutArguments),
                file.InspectionLimited,
                file.CapabilityScanApplicable,
                file.CapabilityScannedBytes,
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
