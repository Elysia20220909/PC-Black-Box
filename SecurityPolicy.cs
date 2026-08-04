using System.Security;
using System.IO;
using System.Text;

namespace DestinyBlackBox;

public static class SecurityPolicy
{
    public const long MaxTargetBytes = 12L * 1024 * 1024 * 1024;
    public const long MaxArchiveInspectionBytes = 2L * 1024 * 1024 * 1024;
    public const long MaxArchiveDeclaredBytes = 20L * 1024 * 1024 * 1024;
    public const int MaxZoneIdentifierBytes = 64 * 1024;

    public static string ValidateTargetPath(string path)
    {
        string fullPath = ValidateLocalPath(path);
        if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
        {
            throw new FileNotFoundException("The selected target no longer exists.");
        }

        EnsureNoReparsePointInPath(fullPath);
        FileAttributes attributes = File.GetAttributes(fullPath);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new SecurityException("Reparse points and symbolic links are not accepted as inspection targets.");
        }

        if (File.Exists(fullPath) && new FileInfo(fullPath).Length > MaxTargetBytes)
        {
            throw new IOException($"The selected file exceeds the {FileAnalysis.FormatSize(MaxTargetBytes)} safety limit.");
        }

        return fullPath;
    }

    public static string ValidateReportPath(string path)
    {
        string fullPath = ValidateLocalPath(path);
        string? parent = Path.GetDirectoryName(fullPath);
        if (String.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException("The report folder must already exist.");
        }

        EnsureNoReparsePointInPath(parent);

        if (File.Exists(fullPath) && (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new SecurityException("A report cannot replace a reparse point or symbolic link.");
        }

        return fullPath;
    }

    public static string ValidateLocalDirectory(string path, bool mustExist)
    {
        string fullPath = ValidateLocalPath(path);
        if (mustExist && !Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException("The local storage folder does not exist.");
        }
        EnsureNoReparsePointInPath(fullPath);
        return fullPath;
    }

    private static void EnsureNoReparsePointInPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath) ?? throw new SecurityException("The path has no local drive root.");
        string current = root;
        string remainder = fullPath[root.Length..];
        foreach (string component in remainder.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if (!File.Exists(current) && !Directory.Exists(current)) break;
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new SecurityException("Paths through reparse points or symbolic links are not accepted.");
            }
        }
    }

    public static bool IsSameOrDescendant(string candidate, string root)
    {
        string candidatePath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        string rootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (candidatePath.Equals(rootPath, StringComparison.OrdinalIgnoreCase)) return true;
        return candidatePath.StartsWith(rootPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public static string SanitizeText(string? value, int maxLength = 1024)
    {
        if (String.IsNullOrEmpty(value)) return "—";
        string normalized;
        try { normalized = value.Normalize(NormalizationForm.FormC); }
        catch (ArgumentException) { normalized = value; }

        var builder = new StringBuilder(Math.Min(normalized.Length, maxLength));
        foreach (char character in normalized)
        {
            if (builder.Length >= maxLength) break;
            if (Char.IsControl(character) || IsDirectionalOrInvisibleControl(character))
            {
                builder.Append('\uFFFD');
                continue;
            }
            builder.Append(character);
        }

        if (normalized.Length > maxLength) builder.Append('…');
        return builder.Length == 0 ? "—" : builder.ToString();
    }

    public static bool ContainsDirectionalOrInvisibleControl(string value) => value.Any(IsDirectionalOrInvisibleControl);

    internal static bool WouldExceedCumulativeLimit(long consumedBytes, long nextBytes, long limitBytes) =>
        consumedBytes < 0 || nextBytes < 0 || limitBytes < 0 ||
        consumedBytes > limitBytes || nextBytes > limitBytes - consumedBytes;

    private static string ValidateLocalPath(string path)
    {
        if (String.IsNullOrWhiteSpace(path)) throw new ArgumentException("A path is required.", nameof(path));
        string fullPath = Path.GetFullPath(path);
        if (fullPath.Length > 32767) throw new PathTooLongException("The selected path is too long.");
        if (fullPath.Length < 3 || !Char.IsAsciiLetter(fullPath[0]) || fullPath[1] != ':' || fullPath[2] != Path.DirectorySeparatorChar)
        {
            throw new SecurityException("Only local drive paths are accepted. UNC, device, and network paths are blocked.");
        }
        if (fullPath.AsSpan(3).Contains(':'))
        {
            throw new SecurityException("Alternate data-stream paths are not accepted as targets.");
        }

        string root = Path.GetPathRoot(fullPath) ?? throw new SecurityException("The path has no local drive root.");
        DriveType driveType = new DriveInfo(root).DriveType;
        if (driveType is not DriveType.Fixed and not DriveType.Removable and not DriveType.Ram)
        {
            throw new SecurityException("Only fixed, removable, or RAM drives are accepted.");
        }

        return fullPath;
    }

    private static bool IsDirectionalOrInvisibleControl(char character) =>
        character is '\u061C' or '\u200B' or '\u200C' or '\u200D' or '\u200E' or '\u200F' or '\uFEFF' ||
        character is >= '\u202A' and <= '\u202E' ||
        character is >= '\u2066' and <= '\u2069';
}
