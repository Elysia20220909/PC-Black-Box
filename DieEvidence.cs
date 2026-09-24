using System.IO;
using System.Text;
using System.Text.Json;

namespace DestinyBlackBox;

/// <summary>Untrusted supplementary classification, never a safety verdict.</summary>
public sealed record DieEvidence(string Engine, string InputSha256, string[] Labels)
{
    public const int MaxBytes = 1024 * 1024;

    internal static DieEvidence Read(string path, ScanResult scan)
    {
        path = SecurityPolicy.ValidateTargetPath(path);
        using var stream = SecureFileReader.OpenRead(path);
        if (stream.Length > MaxBytes) throw new InvalidDataException("DiE result exceeds the limit.");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return Parse(buffer.ToArray(), scan);
    }

    internal static DieEvidence Parse(byte[] bytes, ScanResult scan)
    {
        if (bytes.Length > MaxBytes || scan.TargetWasDirectory || scan.Files.Count != 1)
            throw new InvalidDataException("DiE evidence requires one bounded file.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 24 });
        var root = document.RootElement;
        if (root.GetProperty("schema").GetString() != "pcbb-die-v1") throw new InvalidDataException("Unknown DiE schema.");
        string digest = root.GetProperty("sha256").GetString() ?? "";
        if (digest.Length != 64 || !digest.All(Uri.IsHexDigit) ||
            !digest.Equals(scan.Files[0].Sha256, StringComparison.OrdinalIgnoreCase) ||
            (scan.Files[0].Limits & InspectionLimit.Digest) != 0)
            throw new InvalidDataException("DiE input digest does not match this inspection.");
        var labels = new List<string>();
        var result = root.GetProperty("result");
        if (result.ValueKind != JsonValueKind.Object ||
            !(result.TryGetProperty("detects", out _) || result.TryGetProperty("name", out _)))
            throw new InvalidDataException("Unknown DiE result shape.");
        int nodes = 0;
        Visit(result, labels, ref nodes);
        if (labels.Count > 64) throw new InvalidDataException("Too many DiE labels.");
        return new("Detect It Easy 3.21 (external, untrusted evidence)", digest.ToUpperInvariant(), labels.Distinct().ToArray());
    }

    private static void Visit(JsonElement element, List<string> labels, ref int nodes)
    {
        if (++nodes > 256 || labels.Count > 64 || element.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Invalid DiE node.");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!keys.Add(property.Name)) throw new InvalidDataException("Duplicate DiE property.");
        string? children = element.TryGetProperty("detects", out _) ? "detects" : element.TryGetProperty("values", out _) ? "values" : null;
        if (children is not null)
        {
            var array = element.GetProperty(children);
            if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 64) throw new InvalidDataException("Invalid DiE children.");
            foreach (var item in array.EnumerateArray()) Visit(item, labels, ref nodes);
        }
        else
        {
            foreach (string key in new[] { "type", "name", "version" })
            {
                if (!element.TryGetProperty(key, out var field) || field.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("Invalid DiE leaf.");
                string value = field.GetString() ?? "";
                if (value.Length > 160 || value.Any(c => !(Char.IsLetterOrDigit(c) || " ._+-()[]".Contains(c))))
                    throw new InvalidDataException("Unexpected DiE label characters.");
                if (value.Length > 0) labels.Add(key + ": " + value);
            }
        }
    }
}
