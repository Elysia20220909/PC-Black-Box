using System.IO;
using System.Text;

namespace DestinyBlackBox;

/// <summary>
/// Reads the operator's batch target list through the same boundary as every other input: local drive
/// paths only, no reparse points, a bounded size, and a bounded number of targets. A UNC path is refused
/// before Windows is asked to open it, so naming a list can never start an SMB connection.
/// </summary>
internal static class BatchFileList
{
    internal const int MaxBytes = 1024 * 1024;
    internal const int MaxTargets = 1000;

    public static List<string> Read(string path)
    {
        string fullPath = SecurityPolicy.ValidateTargetPath(path);
        using FileStream stream = SecureFileReader.OpenRead(fullPath, 4096);
        if (stream.Length > MaxBytes) throw new IOException("The batch file list exceeds the safety limit.");

        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, 4096, leaveOpen: false);
        var targets = new List<string>();
        while (reader.ReadLine() is { } line)
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            if (targets.Count >= MaxTargets) throw new IOException("The batch file list names too many targets.");
            targets.Add(trimmed);
        }
        return targets;
    }
}
