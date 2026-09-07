using System.IO;
using System.Text;

namespace DestinyBlackBox;

/// <summary>
/// Reads the fields of a Windows shortcut that decide what it would run, without resolving or launching it.
/// A shortcut is the one active-content format whose payload is a plain command line, so declining to read it
/// left the product blind to the delivery shape it is most likely to be handed.
///
/// Every size in MS-SHLLINK is attacker-controlled, so this walker never trusts one: each field is clamped
/// against what is left of the buffer, every loop has a hard step cap, and a structure that does not fit is
/// reported as truncated rather than repaired. Reading stops at the first field that does not fit.
/// </summary>
internal static class ShortcutInspector
{
    internal const int MaxShortcutBytes = 4 * 1024 * 1024;
    private const int HeaderSize = 0x4C;
    private const int MaxStringCharacters = 8 * 1024;
    private const int MaxExtraDataBlocks = 64;
    private const int MaxLinkInfoBytes = 64 * 1024;
    private const uint EnvironmentVariableDataSignature = 0xA0000001;
    private const int EnvironmentBlockSize = 0x0314;
    private const int EnvironmentAnsiOffset = 0x08;
    private const int EnvironmentUnicodeOffset = 0x010C;

    private static readonly byte[] LinkClassIdentifier =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ];

    private const uint HasLinkTargetIdList = 0x00000001;
    private const uint HasLinkInfoFlag = 0x00000002;
    private const uint HasName = 0x00000004;
    private const uint HasRelativePath = 0x00000008;
    private const uint HasWorkingDirectory = 0x00000010;
    private const uint HasArguments = 0x00000020;
    private const uint HasIconLocation = 0x00000040;
    private const uint IsUnicode = 0x00000080;
    private const uint ForceNoLinkInfo = 0x00000100;
    private const uint RunAsUser = 0x00002000;

    /// <summary>Recognizes a shortcut by its fixed header size and class identifier, never by extension.</summary>
    internal static bool LooksLikeShortcut(byte[] sample) =>
        sample.Length >= HeaderSize &&
        BitConverter.ToUInt32(sample, 0) == HeaderSize &&
        sample.AsSpan(4, 16).SequenceEqual(LinkClassIdentifier);

    internal static ShortcutDetails Read(FileStream stream, long length)
    {
        if (length < HeaderSize) return ShortcutDetails.Unreadable;

        bool truncated = length > MaxShortcutBytes;
        int budget = (int)Math.Min(length, MaxShortcutBytes);
        byte[] buffer = new byte[budget];
        stream.Position = 0;
        int filled = 0;
        while (filled < budget)
        {
            int read = stream.Read(buffer, filled, budget - filled);
            if (read == 0) break;
            filled += read;
        }

        if (filled < HeaderSize || !LooksLikeShortcut(buffer)) return ShortcutDetails.Unreadable;

        uint flags = BitConverter.ToUInt32(buffer, 0x14);
        int showCommand = (int)BitConverter.ToUInt32(buffer, 0x3C);
        bool unicode = (flags & IsUnicode) != 0;
        int offset = HeaderSize;

        if ((flags & HasLinkTargetIdList) != 0 &&
            (!TryReadUInt16(buffer, filled, ref offset, out ushort idListSize) || !TrySkip(filled, ref offset, idListSize)))
        {
            return ShortcutDetails.PartiallyRead(showCommand, (flags & RunAsUser) != 0);
        }

        string localBasePath = String.Empty;
        if ((flags & HasLinkInfoFlag) != 0 && (flags & ForceNoLinkInfo) == 0 &&
            !TryReadLinkInfo(buffer, filled, ref offset, out localBasePath))
        {
            return ShortcutDetails.PartiallyRead(showCommand, (flags & RunAsUser) != 0);
        }

        bool complete = true;
        string name = ReadStringData(buffer, filled, ref offset, unicode, (flags & HasName) != 0, ref complete);
        string relativePath = ReadStringData(buffer, filled, ref offset, unicode, (flags & HasRelativePath) != 0, ref complete);
        string workingDirectory = ReadStringData(buffer, filled, ref offset, unicode, (flags & HasWorkingDirectory) != 0, ref complete);
        string arguments = ReadStringData(buffer, filled, ref offset, unicode, (flags & HasArguments) != 0, ref complete);
        string iconLocation = ReadStringData(buffer, filled, ref offset, unicode, (flags & HasIconLocation) != 0, ref complete);
        string environmentTarget = ReadEnvironmentTarget(buffer, filled, offset);

        // An EnvironmentVariableDataBlock replaces the recorded path when the shell resolves the link, so it is
        // the honest answer to "what does this run"; the LinkInfo path is the fallback, the relative path last.
        string target = FirstNonEmpty(environmentTarget, localBasePath, relativePath);

        return new ShortcutDetails(
            target,
            arguments,
            workingDirectory,
            iconLocation,
            showCommand,
            (flags & RunAsUser) != 0,
            truncated || !complete)
        {
            Name = name,
        };
    }

    private static string FirstNonEmpty(string first, string second, string third) =>
        !String.IsNullOrWhiteSpace(first) ? first : !String.IsNullOrWhiteSpace(second) ? second : third;

    private static bool TryReadUInt16(byte[] buffer, int filled, ref int offset, out ushort value)
    {
        value = 0;
        if (offset < 0 || offset > filled - 2) return false;
        value = BitConverter.ToUInt16(buffer, offset);
        offset += 2;
        return true;
    }

    private static bool TrySkip(int filled, ref int offset, int count)
    {
        if (count < 0 || offset > filled - count) return false;
        offset += count;
        return true;
    }

    /// <summary>
    /// Walks LinkInfo only far enough to recover the local base path, then jumps the declared size.
    /// Every offset inside the structure is validated against the structure's own extent, so a hostile
    /// offset can fail the read but can never reach outside the block.
    /// </summary>
    private static bool TryReadLinkInfo(byte[] buffer, int filled, ref int offset, out string localBasePath)
    {
        localBasePath = String.Empty;
        int start = offset;
        if (start < 0 || start > filled - 0x1C) return false;

        uint declaredSize = BitConverter.ToUInt32(buffer, start);
        if (declaredSize < 0x1C || declaredSize > (uint)(filled - start)) return false;

        int size = (int)declaredSize;
        uint headerSize = BitConverter.ToUInt32(buffer, start + 0x04);
        uint infoFlags = BitConverter.ToUInt32(buffer, start + 0x08);

        // A LinkInfo past the extraction cap is legal — padding NetName or DeviceName is enough to build one —
        // so step over it and keep reading the command line that follows. Abandoning the walk here would make
        // breaking this parser cheaper for an attacker than passing it.
        if (declaredSize <= MaxLinkInfoBytes && (infoFlags & 0x1) != 0)
        {
            if (headerSize >= 0x24 && declaredSize >= 0x24)
            {
                uint unicodeOffset = BitConverter.ToUInt32(buffer, start + 0x1C);
                if (unicodeOffset >= 0x24 && unicodeOffset < declaredSize)
                {
                    localBasePath = ReadTerminatedString(buffer, start + (int)unicodeOffset, start + size, unicode: true);
                }
            }

            uint pathOffset = BitConverter.ToUInt32(buffer, start + 0x10);
            if (localBasePath.Length == 0 && pathOffset >= 0x1C && pathOffset < declaredSize)
            {
                localBasePath = ReadTerminatedString(buffer, start + (int)pathOffset, start + size, unicode: false);
            }
        }

        offset = start + size;
        return true;
    }

    private static string ReadStringData(byte[] buffer, int filled, ref int offset, bool unicode, bool present, ref bool complete)
    {
        if (!present) return String.Empty;
        if (!TryReadUInt16(buffer, filled, ref offset, out ushort characters))
        {
            complete = false;
            return String.Empty;
        }

        int capped = Math.Min((int)characters, MaxStringCharacters);
        int declaredBytes = unicode ? characters * 2 : characters;
        int cappedBytes = unicode ? capped * 2 : capped;
        if (offset < 0 || offset > filled - cappedBytes)
        {
            complete = false;
            return String.Empty;
        }

        string value = unicode
            ? Encoding.Unicode.GetString(buffer, offset, cappedBytes)
            : Encoding.Latin1.GetString(buffer, offset, cappedBytes);

        if (capped != characters) complete = false;
        if (!TrySkip(filled, ref offset, declaredBytes)) complete = false;
        return value;
    }

    /// <summary>Scans the ExtraData chain for the one block that can silently redirect the target.</summary>
    private static string ReadEnvironmentTarget(byte[] buffer, int filled, int offset)
    {
        for (int block = 0; block < MaxExtraDataBlocks; block++)
        {
            if (offset < 0 || offset > filled - 8) return String.Empty;

            uint blockSize = BitConverter.ToUInt32(buffer, offset);
            if (blockSize < 0x08 || blockSize > (uint)(filled - offset)) return String.Empty;

            uint signature = BitConverter.ToUInt32(buffer, offset + 4);
            if (signature == EnvironmentVariableDataSignature && blockSize >= EnvironmentBlockSize)
            {
                string unicodeTarget = ReadTerminatedString(buffer, offset + EnvironmentUnicodeOffset, offset + EnvironmentBlockSize, unicode: true);
                return unicodeTarget.Length > 0
                    ? unicodeTarget
                    : ReadTerminatedString(buffer, offset + EnvironmentAnsiOffset, offset + EnvironmentUnicodeOffset, unicode: false);
            }

            offset += (int)blockSize;
        }

        return String.Empty;
    }

    private static string ReadTerminatedString(byte[] buffer, int start, int limit, bool unicode)
    {
        if (start < 0 || limit > buffer.Length || start >= limit) return String.Empty;

        int step = unicode ? 2 : 1;
        int end = start;
        while (end + step <= limit)
        {
            bool terminator = unicode ? BitConverter.ToUInt16(buffer, end) == 0 : buffer[end] == 0;
            if (terminator) break;
            end += step;
        }

        int length = Math.Min(end - start, MaxStringCharacters * step);
        if (length <= 0) return String.Empty;
        return unicode ? Encoding.Unicode.GetString(buffer, start, length) : Encoding.Latin1.GetString(buffer, start, length);
    }
}

internal sealed record ShortcutDetails(
    string Target,
    string Arguments,
    string WorkingDirectory,
    string IconLocation,
    int ShowCommand,
    bool RunAsAdministrator,
    bool Truncated)
{
    internal string Name { get; init; } = String.Empty;

    internal static ShortcutDetails Unreadable { get; } =
        new(String.Empty, String.Empty, String.Empty, String.Empty, 0, false, true);

    internal static ShortcutDetails PartiallyRead(int showCommand, bool runAsAdministrator) =>
        new(String.Empty, String.Empty, String.Empty, String.Empty, showCommand, runAsAdministrator, true);

    /// <summary>The text a capability matcher should read: what it runs, with what, and from where.</summary>
    internal string CommandSurface => String.Join(
        ' ',
        new[] { Target, Arguments, WorkingDirectory, IconLocation, Name }.Where(part => !String.IsNullOrWhiteSpace(part)));
}
