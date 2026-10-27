using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

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

        WriteValidated(fullPath, content, allowOverwrite);
    }

    public static void WriteBatch(string path, string content, IReadOnlyList<string> targets, string expectedExtension, bool allowOverwrite)
    {
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count == 0) throw new ArgumentException("Batch report targets are required.", nameof(targets));

        string fullPath = SecurityPolicy.ValidateReportPath(path);
        if (!Path.GetExtension(fullPath).Equals(expectedExtension, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException($"The report must use the {expectedExtension} extension.");
        }

        // Use every original input, including failed inspections. File/directory type may be unknown,
        // so both equality and containment are protected before any output or temporary file exists.
        foreach (string target in targets)
        {
            string boundary = SecurityPolicy.ValidateReportTargetBoundary(target);
            if (SecurityPolicy.IsSameOrDescendant(fullPath, boundary))
            {
                throw new IOException("Batch reports cannot be written over or inside any inspection target.");
            }
        }

        WriteValidated(fullPath, content, allowOverwrite);
    }

    private static void WriteValidated(string fullPath, string content, bool allowOverwrite)
    {
        string parent = Path.GetDirectoryName(fullPath)!;
        using SafeFileHandle parentGuard = SecureFileReader.OpenDirectoryGuard(parent);

        if (!allowOverwrite)
        {
            WriteNew(fullPath, content);
            return;
        }

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
