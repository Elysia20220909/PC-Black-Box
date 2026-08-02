using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DestinyBlackBox;

public static class SafeReportWriter
{
    public static void Write(string path, string content, ScanResult result, string expectedExtension, bool allowOverwrite)
    {
        string fullPath = SecurityPolicy.ValidateReportPath(path);
        if (!Path.GetExtension(fullPath).Equals(expectedExtension, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException($"The report must use the {expectedExtension} extension.");
        }

        bool overlapsTarget = result.TargetWasDirectory
            ? SecurityPolicy.IsSameOrDescendant(fullPath, result.TargetPath)
            : fullPath.Equals(result.TargetPath, StringComparison.OrdinalIgnoreCase);
        if (overlapsTarget)
        {
            throw new IOException("Reports cannot be written over or inside the inspection target.");
        }

        if (!allowOverwrite)
        {
            WriteNew(fullPath, content);
            return;
        }

        string parent = Path.GetDirectoryName(fullPath)!;
        string temporaryPath = Path.Combine(parent, $".{Path.GetFileName(fullPath)}.{RandomNumberGenerator.GetHexString(16)}.tmp");
        try
        {
            WriteNew(temporaryPath, content);
            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); } catch { }
        }
    }

    private static void WriteNew(string path, string content)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        writer.Write(content);
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }
}
