using System.IO;
using System.Text.Json;

namespace DestinyBlackBox;

/// <summary>Bridge cleanup evidence, separate from parser output and from the risk assessment.</summary>
public sealed record DieCleanupStatus(string TemporaryData, string AppContainerProfile, string DirectoryPermissions)
{
    public static DieCleanupStatus Unknown { get; } = new("unknown", "unknown", "unknown");
    public static DieCleanupStatus NotRequired { get; } = new("not-required", "not-required", "not-required");
    public bool NeedsAttention => new[] { TemporaryData, AppContainerProfile, DirectoryPermissions }.Any(s => s is "unknown" or "failed");

    internal string Describe(bool japanese) =>
        (NeedsAttention
            ? (japanese ? "DiEの後始末が失敗または未確認です。一時データやプロファイルが残っている可能性があります。" : "DiE cleanup failed or is unverified. Temporary data or a profile may remain.")
            : (japanese ? "DiEの後始末: 完了または不要。" : "DiE cleanup: completed or not required.")) +
        $" [temporaryData={TemporaryData}, appContainerProfile={AppContainerProfile}, directoryPermissions={DirectoryPermissions}]";
}

internal static class DieSessionResponse
{
    internal static byte[] Write(byte[]? evidence, string analysis, DieCleanupStatus cleanup)
    {
        using var document = evidence is null ? null : JsonDocument.Parse(evidence, new JsonDocumentOptions { MaxDepth = 24 });
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema = "pcbb-die-session-v1",
            analysis,
            cleanup = new { temporaryData = cleanup.TemporaryData, appContainerProfile = cleanup.AppContainerProfile, directoryPermissions = cleanup.DirectoryPermissions },
            evidence = document?.RootElement
        });
    }

    internal static (byte[]? Evidence, string Analysis, DieCleanupStatus Cleanup) Read(byte[] bytes)
    {
        if (bytes.Length > DiePipeProtocol.MaxFrame) throw new InvalidDataException("DiE session response exceeds the limit.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 28 });
        var root = document.RootElement;
        RequireKeys(root, "schema", "analysis", "cleanup", "evidence");
        if (root.GetProperty("schema").GetString() != "pcbb-die-session-v1") throw new InvalidDataException("Unknown DiE session schema.");
        string analysis = root.GetProperty("analysis").GetString() ?? "";
        if (analysis is not ("complete" or "failed" or "cancelled")) throw new InvalidDataException("Invalid DiE analysis status.");
        var cleanup = root.GetProperty("cleanup");
        RequireKeys(cleanup, "temporaryData", "appContainerProfile", "directoryPermissions");
        var status = new DieCleanupStatus(State("temporaryData"), State("appContainerProfile"), State("directoryPermissions"));
        var evidence = root.GetProperty("evidence");
        byte[]? parsed = analysis == "complete" ? System.Text.Encoding.UTF8.GetBytes(evidence.GetRawText()) : null;
        if (analysis != "complete" && evidence.ValueKind != JsonValueKind.Null) throw new InvalidDataException("Unexpected evidence for an incomplete analysis.");
        return (parsed, analysis, status);

        string State(string name)
        {
            string value = cleanup.GetProperty(name).GetString() ?? "";
            return value is "complete" or "failed" or "unknown" or "not-required"
                ? value : throw new InvalidDataException("Invalid DiE cleanup status.");
        }
    }

    private static void RequireKeys(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected a DiE response object.");
        var remaining = expected.ToHashSet(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!remaining.Remove(property.Name)) throw new InvalidDataException("Unknown or duplicate DiE response property.");
        if (remaining.Count != 0) throw new InvalidDataException("Incomplete DiE response.");
    }
}
