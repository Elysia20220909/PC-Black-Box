using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace DestinyBlackBox;

internal readonly record struct SecureFileIdentity(ulong VolumeSerialNumber, ulong FileIdLow, ulong FileIdHigh);

internal readonly record struct SecureFileSnapshot(long Length, DateTime LastWriteUtc, SecureFileIdentity Identity);

internal static class SecureFileReader
{
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;

    public static FileStream OpenRead(string path, int bufferSize = 1024 * 1024)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            GenericRead,
            ShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("The file could not be opened through the secure reader.", new Win32Exception(error));
        }

        try
        {
            NativeFileInformation information = ReadNativeInformation(handle);
            FileAttributes attributes = (FileAttributes)information.FileAttributes;
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new SecurityException("A reparse point was blocked by the secure reader.");
            }
            if ((attributes & FileAttributes.Directory) != 0)
            {
                throw new IOException("The secure reader accepts files only.");
            }

            EnsureRequestedPathMatchesHandle(path, handle);

            return new FileStream(handle, FileAccess.Read, bufferSize, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenDirectoryGuard(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            FileReadAttributes,
            ShareRead | ShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("The directory could not be opened through the secure reader.", new Win32Exception(error));
        }

        try
        {
            NativeFileInformation information = ReadNativeInformation(handle);
            FileAttributes attributes = (FileAttributes)information.FileAttributes;
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new SecurityException("A reparse point was blocked by the secure directory guard.");
            }
            if ((attributes & FileAttributes.Directory) == 0)
            {
                throw new IOException("The secure directory guard accepts directories only.");
            }

            EnsureRequestedPathMatchesHandle(path, handle);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SecureFileSnapshot GetSnapshot(SafeFileHandle handle)
    {
        NativeFileInformation information = ReadNativeInformation(handle);
        ulong unsignedLength = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow;
        if (unsignedLength > Int64.MaxValue) throw new IOException("The file length exceeds the supported range.");

        ulong fileTime = ((ulong)information.LastWriteTimeHigh << 32) | information.LastWriteTimeLow;
        var identity = new SecureFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            0);

        var extendedIdentity = new NativeFileIdInformation();
        if (GetFileInformationByHandleEx(
            handle,
            FileInfoByHandleClass.FileIdInfo,
            ref extendedIdentity,
            (uint)Marshal.SizeOf<NativeFileIdInformation>()))
        {
            identity = new SecureFileIdentity(
                extendedIdentity.VolumeSerialNumber,
                extendedIdentity.FileIdLow,
                extendedIdentity.FileIdHigh);
        }

        return new SecureFileSnapshot((long)unsignedLength, DateTime.FromFileTimeUtc((long)fileTime), identity);
    }

    private static NativeFileInformation ReadNativeInformation(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out NativeFileInformation information))
        {
            throw new IOException(
                "Windows could not return stable file information.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
        return information;
    }

    private static void EnsureRequestedPathMatchesHandle(string requestedPath, SafeFileHandle handle)
    {
        string expected = NormalizeFinalPath(Path.GetFullPath(requestedPath));
        int capacity = 512;
        while (true)
        {
            var buffer = new StringBuilder(capacity);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0)
            {
                throw new IOException(
                    "Windows could not resolve the opened path.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
            if (length < buffer.Capacity)
            {
                string actual = NormalizeFinalPath(buffer.ToString());
                if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    throw new SecurityException("The opened handle resolved outside the requested path.");
                }
                return;
            }
            if (length >= 32767) throw new PathTooLongException("The resolved path is too long.");
            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizeFinalPath(string path)
    {
        string normalized = path;
        if (normalized.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = @"\\" + normalized[8..];
        }
        else if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[4..];
        }
        if (normalized.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^6];
        }
        return Path.GetFullPath(normalized);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out NativeFileInformation fileInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        ref NativeFileIdInformation fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        [Out] StringBuilder filePath,
        uint filePathLength,
        uint flags);

    private enum FileInfoByHandleClass
    {
        FileIdInfo = 18
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileIdInformation
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }
}
