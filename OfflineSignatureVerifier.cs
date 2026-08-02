using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace DestinyBlackBox;

public static class OfflineSignatureVerifier
{
    private const uint UiNone = 2;
    private const uint ChoiceFile = 1;
    private const uint ChoiceCatalog = 2;
    private const uint RevokeNone = 0;
    private const uint RevocationCheckNone = 0x00000010;
    private const uint CacheOnlyUrlRetrieval = 0x00001000;
    private const uint DisableWeakAlgorithms = 0x00002000;
    private const uint OfflineProviderFlags = RevocationCheckNone | CacheOnlyUrlRetrieval | DisableWeakAlgorithms;
    private static readonly Guid VerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static SignatureResult Verify(string path)
    {
        try
        {
            using FileStream stableFile = SecureFileReader.OpenRead(path);
            int embeddedResult = VerifyEmbeddedSignature(path, stableFile.SafeFileHandle);
            if (embeddedResult != unchecked((int)0x800B0100))
            {
                string status = MapStatus(embeddedResult);
                return new SignatureResult(status, status == "NotSigned" ? "—" : ReadSignerSubject(path));
            }

            SignatureResult? catalogResult = VerifyCatalogSignature(path, stableFile);
            return catalogResult ?? new SignatureResult("NotSigned", "—");
        }
        catch
        {
            return new SignatureResult("UnknownError", "—");
        }
    }

    private static int VerifyEmbeddedSignature(string path, SafeFileHandle stableHandle)
    {
        IntPtr pathPointer = IntPtr.Zero;
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            pathPointer = Marshal.StringToCoTaskMemUni(path);
            var fileInfo = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = pathPointer,
                FileHandle = stableHandle.DangerousGetHandle()
            };
            fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            WinTrustData data = CreateTrustData(ChoiceFile, fileInfoPointer);
            Guid action = VerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(fileInfoPointer);
            if (pathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    private static SignatureResult? VerifyCatalogSignature(string path, FileStream stableFile)
    {
        foreach (string? algorithm in new string?[] { null, "SHA256", "SHA1" })
        {
            SignatureResult? result = VerifyCatalogSignature(path, stableFile, algorithm);
            if (result is not null) return result;
        }

        return null;
    }

    private static SignatureResult? VerifyCatalogSignature(string path, FileStream stableFile, string? algorithm)
    {
        IntPtr catalogAdmin = IntPtr.Zero;
        IntPtr catalogContext = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out catalogAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) return null;

            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, stableFile.SafeFileHandle.DangerousGetHandle(), ref hashSize, null, 0) ||
                hashSize is 0 or > 128)
            {
                return null;
            }

            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, stableFile.SafeFileHandle.DangerousGetHandle(), ref hashSize, hash, 0))
            {
                return null;
            }

            catalogContext = CryptCATAdminEnumCatalogFromHash(catalogAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (catalogContext == IntPtr.Zero) return null;

            var catalogInfo = new CatalogInfo
            {
                StructSize = (uint)Marshal.SizeOf<CatalogInfo>(),
                CatalogFile = new string('\0', 260)
            };
            if (!CryptCATCatalogInfoFromContext(catalogContext, ref catalogInfo, 0) || String.IsNullOrWhiteSpace(catalogInfo.CatalogFile))
            {
                return null;
            }

            int trustResult = VerifyCatalogMember(path, stableFile.SafeFileHandle.DangerousGetHandle(), catalogInfo.CatalogFile, hash, catalogAdmin);
            string status = MapStatus(trustResult);
            return new SignatureResult(status, status == "NotSigned" ? "—" : ReadSignerSubject(catalogInfo.CatalogFile));
        }
        finally
        {
            if (catalogContext != IntPtr.Zero && catalogAdmin != IntPtr.Zero)
            {
                CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
            }
            if (catalogAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(catalogAdmin, 0);
        }
    }

    private static int VerifyCatalogMember(string memberPath, IntPtr memberHandle, string catalogPath, byte[] hash, IntPtr catalogAdmin)
    {
        IntPtr catalogPathPointer = IntPtr.Zero;
        IntPtr memberTagPointer = IntPtr.Zero;
        IntPtr memberPathPointer = IntPtr.Zero;
        IntPtr hashPointer = IntPtr.Zero;
        IntPtr catalogInfoPointer = IntPtr.Zero;
        try
        {
            catalogPathPointer = Marshal.StringToCoTaskMemUni(catalogPath);
            memberTagPointer = Marshal.StringToCoTaskMemUni(Convert.ToHexString(hash));
            memberPathPointer = Marshal.StringToCoTaskMemUni(memberPath);
            hashPointer = Marshal.AllocCoTaskMem(hash.Length);
            Marshal.Copy(hash, 0, hashPointer, hash.Length);

            var catalogInfo = new WinTrustCatalogInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                CatalogFilePath = catalogPathPointer,
                MemberTag = memberTagPointer,
                MemberFilePath = memberPathPointer,
                MemberFile = memberHandle,
                CalculatedFileHash = hashPointer,
                CalculatedFileHashLength = (uint)hash.Length,
                CatalogAdmin = catalogAdmin
            };
            catalogInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(catalogInfo, catalogInfoPointer, false);

            WinTrustData data = CreateTrustData(ChoiceCatalog, catalogInfoPointer);
            Guid action = VerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }
        finally
        {
            if (catalogInfoPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(catalogInfoPointer);
            if (hashPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(hashPointer);
            if (memberPathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(memberPathPointer);
            if (memberTagPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(memberTagPointer);
            if (catalogPathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(catalogPathPointer);
        }
    }

    private static WinTrustData CreateTrustData(uint choice, IntPtr unionPointer) => new()
    {
        StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
        UiChoice = UiNone,
        RevocationChecks = RevokeNone,
        UnionChoice = choice,
        UnionPointer = unionPointer,
        ProviderFlags = OfflineProviderFlags
    };

    private static string MapStatus(int result) => result switch
    {
        0 => "Valid",
        unchecked((int)0x800B0100) => "NotSigned",
        unchecked((int)0x80096010) => "HashMismatch",
        unchecked((int)0x800B0101) => "NotTimeValid",
        unchecked((int)0x800B0109) => "NotTrusted",
        unchecked((int)0x800B010C) => "Revoked",
        unchecked((int)0x800B0111) => "NotTrusted",
        unchecked((int)0x800B0004) => "NotTrusted",
        _ => "UnknownError"
    };

    private static string ReadSignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return SecurityPolicy.SanitizeText(certificate.Subject, 512);
        }
        catch
        {
            return "—";
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr window, [In] ref Guid action, [In] ref WinTrustData data);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catalogAdmin, IntPtr subsystem, string? hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catalogAdmin, IntPtr file, ref uint hashSize, byte[]? hash, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catalogAdmin, byte[] hash, uint hashSize, uint flags, IntPtr previousCatalogInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalogInfo, ref CatalogInfo info, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catalogAdmin, IntPtr catalogInfo, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfo
    {
        public uint StructSize;
        public uint CatalogVersion;
        public IntPtr CatalogFilePath;
        public IntPtr MemberTag;
        public IntPtr MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashLength;
        public IntPtr CatalogContext;
        public IntPtr CatalogAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint StructSize;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string CatalogFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr UnionPointer;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }
}
