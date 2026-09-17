using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DestinyBlackBox;

internal enum DefenderReadState { NotQueried, Complete, Partial, AccessDenied, Unavailable, Timeout, Busy, InvalidData }

internal sealed record DefenderProtection(bool? ServiceEnabled, bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled, DateTimeOffset? SignatureUpdated);

// Only typed, non-identifying fields cross the provider boundary. No paths, users, process names,
// computer IDs, raw exceptions, or provider-generated text are retained.
internal sealed record DefenderDetection(long? ThreatId, DateTimeOffset? DetectedAt,
    DateTimeOffset? ChangedAt, byte? StatusId, bool? ActionSucceeded, uint? AdditionalActions)
{
    internal string StatusCode => StatusId switch
    {
        1 => "detected",
        2 => "cleaned",
        3 => "quarantined",
        4 => "removed",
        5 => "allowed",
        6 => "blocked",
        102 => "quarantine-failed",
        103 => "remove-failed",
        104 => "allow-failed",
        105 => "abandoned",
        107 => "block-failed",
        _ => "unknown"
    };
}

internal sealed record DefenderSnapshot(DateTimeOffset ObservedAt, DefenderReadState ProtectionState,
    DefenderProtection? Protection, DefenderReadState HistoryState, IReadOnlyList<DefenderDetection> Detections)
{
    internal DefenderConnectionStage? ConnectionFailureStage { get; init; }
    internal int? ConnectionErrorCode { get; init; }
    internal DefenderQueryStage? ProtectionFailureStage { get; init; }
    internal int? ProtectionErrorCode { get; init; }
    internal DefenderQueryStage? HistoryFailureStage { get; init; }
    internal int? HistoryErrorCode { get; init; }
    internal bool RetrievalComplete => ProtectionState == DefenderReadState.Complete && HistoryState == DefenderReadState.Complete;
    internal static DefenderSnapshot Empty(DefenderReadState state) => new(DateTimeOffset.UtcNow, state, null, state, []);

    internal string ToJson() => JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        connectionFailureStage = ConnectionFailureStage?.ToString(),
        connectionErrorCode = ConnectionErrorCode,
        protectionFailureStage = ProtectionFailureStage?.ToString(),
        protectionErrorCode = ProtectionErrorCode,
        historyFailureStage = HistoryFailureStage?.ToString(),
        historyErrorCode = HistoryErrorCode,
        source = "local-microsoft-defender",
        readOnly = true,
        observedAt = ObservedAt,
        retrievalComplete = RetrievalComplete,
        newScanPerformed = false,
        malwareVerdict = "not-assessed",
        historyIsCurrentSafetyProof = false,
        protectionState = ProtectionState.ToString(),
        protection = Protection,
        historyState = HistoryState.ToString(),
        historyLimit = DefenderReader.MaxHistory,
        detections = Detections.Select(item => new
        {
            item.ThreatId,
            item.DetectedAt,
            item.ChangedAt,
            item.StatusId,
            state = item.StatusCode,
            item.ActionSucceeded,
            item.AdditionalActions
        })
    }, new JsonSerializerOptions { WriteIndented = true });

    internal string ToDisplay(bool japanese)
    {
        var text = new StringBuilder();
        text.AppendLine(japanese ? "Microsoft Defender — 読み取り専用" : "Microsoft Defender — read only");
        text.AppendLine($"{(japanese ? "取得時刻" : "Observed")}: {ObservedAt:O}");
        text.AppendLine(japanese
            ? "新しいスキャンは実行していません。履歴なしは安全の証明ではありません。"
            : "No new scan was performed. No history is not proof of safety.");
        text.AppendLine(japanese
            ? "Defenderの既存の記録です。選択ファイルの検査結果や、現在の隔離状態の保証ではありません。"
            : "Existing Defender records, not a verdict on the selected file or a guarantee of current quarantine.");
        text.AppendLine(japanese
            ? "Defender自身の通信・自動保護はWindows側の設定に従います。この機能は設定を変更しません。"
            : "Defender's own network and automatic protection follow Windows settings; this feature changes none.");
        text.AppendLine();
        if (ConnectionFailureStage is { } stage)
            text.AppendLine($"{(japanese ? "接続失敗箇所" : "Connection failure")}: {stage} / 0x{ConnectionErrorCode:X8}");
        text.AppendLine($"{(japanese ? "保護状態の取得" : "Protection retrieval")}: {Describe(ProtectionState, japanese)}");
        if (ProtectionFailureStage is { } protectionStage) text.AppendLine($"{protectionStage} / 0x{ProtectionErrorCode:X8}");
        if (Protection is { } protection)
        {
            text.AppendLine($"{(japanese ? "サービス" : "Service")}: {Flag(protection.ServiceEnabled, japanese)}");
            text.AppendLine($"Antivirus: {Flag(protection.AntivirusEnabled, japanese)}");
            text.AppendLine($"{(japanese ? "リアルタイム保護" : "Real-time protection")}: {Flag(protection.RealTimeProtectionEnabled, japanese)}");
            text.AppendLine($"{(japanese ? "定義更新" : "Signature updated")}: {Stamp(protection.SignatureUpdated)}");
        }
        text.AppendLine();
        text.AppendLine($"{(japanese ? "履歴の取得" : "History retrieval")}: {Describe(HistoryState, japanese)}");
        if (HistoryFailureStage is { } historyStage) text.AppendLine($"{historyStage} / 0x{HistoryErrorCode:X8}");
        text.AppendLine(japanese
            ? $"表示 {Detections.Count}件 / 上限 {DefenderReader.MaxHistory}件（Windowsの列挙順・最新順の保証なし）"
            : $"Showing {Detections.Count} / limit {DefenderReader.MaxHistory} (provider order, not necessarily newest)");
        if (HistoryState == DefenderReadState.Complete && Detections.Count == 0)
            text.AppendLine(japanese ? "取得できた履歴は0件です。感染の有無は判定していません。" : "Zero history records returned; infection status was not assessed.");
        foreach (DefenderDetection item in Detections)
        {
            text.AppendLine($"ID={item.ThreatId?.ToString(CultureInfo.InvariantCulture) ?? "unknown"} | {item.StatusCode} ({item.StatusId?.ToString(CultureInfo.InvariantCulture) ?? "?"})");
            text.AppendLine($"  {(japanese ? "検出" : "Detected")}: {Stamp(item.DetectedAt)} | {(japanese ? "状態更新" : "Changed")}: {Stamp(item.ChangedAt)}");
            text.AppendLine($"  {(japanese ? "対処成功の記録" : "Recorded action success")}: {Flag(item.ActionSucceeded, japanese)} | {(japanese ? "追加対処フラグ" : "Additional-action flags")}: {item.AdditionalActions?.ToString(CultureInfo.InvariantCulture) ?? "unknown"}");
        }
        return text.ToString();
    }

    private static string Flag(bool? value, bool ja) => value switch
    {
        true => ja ? "はい" : "yes",
        false => ja ? "いいえ" : "no",
        _ => ja ? "不明" : "unknown"
    };
    private static string Stamp(DateTimeOffset? value) => value?.ToString("O", CultureInfo.InvariantCulture) ?? "unknown";
    private static string Describe(DefenderReadState state, bool ja) => ja ? state switch
    {
        DefenderReadState.NotQueried => "未取得",
        DefenderReadState.Complete => "取得完了（安全判定ではありません）",
        DefenderReadState.Partial => "一部のみ取得",
        DefenderReadState.AccessDenied => "権限不足",
        DefenderReadState.Timeout => "時間切れ",
        DefenderReadState.Busy => "前の照会が終了していません",
        DefenderReadState.InvalidData => "応答を確認できません",
        _ => "利用できません"
    } : state.ToString();
}
