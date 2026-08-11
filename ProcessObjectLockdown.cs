using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DestinyBlackBox;

/// <summary>
/// Replaces the default DACL on this process object so a later same-user OpenProcess request cannot
/// read its memory, write to it, start a thread inside it, or duplicate its file handles. The bytes of
/// an untrusted download live in this address space while it is being parsed. Handles obtained before
/// this DACL is applied cannot be revoked; kernel and administrator access also remain out of scope.
/// </summary>
internal static class ProcessObjectLockdown
{
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ReadControl = 0x00020000;
    private const uint Synchronize = 0x00100000;
    private const uint ProcessAllAccess = 0x001FFFFF;

    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>What the owning user keeps: see it in Task Manager, wait on it, and end it.</summary>
    private const uint OwnerRetainedAccess =
        ProcessTerminate | ProcessQueryLimitedInformation | ReadControl | Synchronize;

    internal static SecurityControlState Apply()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            SecurityIdentifier? user = identity.User;
            if (user is null) return SecurityControlState.NotEnforced;

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            // S-1-3-4 (OWNER RIGHTS). Present, it replaces the implicit READ_CONTROL|WRITE_DAC that
            // Windows grants an object owner, so the owning user cannot simply rewrite this DACL back.
            var ownerRights = new SecurityIdentifier("S-1-3-4");

            var acl = new RawAcl(GenericAcl.AclRevision, 3);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)ProcessAllAccess), system, false, null));
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)OwnerRetainedAccess), user, false, null));
            acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)OwnerRetainedAccess), ownerRights, false, null));

            var descriptor = new RawSecurityDescriptor(
                ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative,
                owner: user,
                group: null,
                systemAcl: null,
                discretionaryAcl: acl);

            byte[] binaryForm = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(binaryForm, 0);

            if (!SetKernelObjectSecurity(GetCurrentProcess(), DaclSecurityInformation, binaryForm))
            {
                return SecurityControlState.NotEnforced;
            }

            return StateOf(VerifyExpectedPolicy(system, user, ownerRights));
        }
        catch
        {
            return SecurityControlState.NotEnforced;
        }
    }

    /// <summary>Reads the complete expected policy back instead of accepting a merely restrictive DACL.</summary>
    internal static bool VerifyCurrentPolicy()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            SecurityIdentifier? user = identity.User;
            if (user is null) return false;

            return VerifyExpectedPolicy(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                user,
                new SecurityIdentifier("S-1-3-4"));
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyExpectedPolicy(
        SecurityIdentifier system,
        SecurityIdentifier user,
        SecurityIdentifier ownerRights)
    {
        if (!TryReadSecurityDescriptor(out RawSecurityDescriptor? descriptor) || descriptor is null) return false;
        if (descriptor.Owner != user) return false;

        RawAcl? acl = descriptor.DiscretionaryAcl;
        if (acl is null || acl.Count != 3) return false;

        bool systemSeen = false;
        bool userSeen = false;
        bool ownerRightsSeen = false;

        foreach (GenericAce ace in acl)
        {
            if (ace is not CommonAce common) return false;
            if (common.AceQualifier != AceQualifier.AccessAllowed || common.AceFlags != AceFlags.None) return false;

            uint mask = unchecked((uint)common.AccessMask);
            if (common.SecurityIdentifier == system && !systemSeen && mask == ProcessAllAccess)
            {
                systemSeen = true;
            }
            else if (common.SecurityIdentifier == user && !userSeen && mask == OwnerRetainedAccess)
            {
                userSeen = true;
            }
            else if (common.SecurityIdentifier == ownerRights && !ownerRightsSeen && mask == OwnerRetainedAccess)
            {
                ownerRightsSeen = true;
            }
            else
            {
                return false;
            }
        }

        return systemSeen && userSeen && ownerRightsSeen;
    }

    private static bool TryReadSecurityDescriptor(out RawSecurityDescriptor? descriptor)
    {
        descriptor = null;
        IntPtr process = GetCurrentProcess();
        uint requestedInformation = OwnerSecurityInformation | DaclSecurityInformation;

        if (GetKernelObjectSecurity(process, requestedInformation, null, 0, out uint required))
        {
            return false;
        }
        if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || required == 0)
        {
            return false;
        }

        byte[] buffer = new byte[required];
        if (!GetKernelObjectSecurity(process, requestedInformation, buffer, required, out _))
        {
            return false;
        }

        descriptor = new RawSecurityDescriptor(buffer, 0);
        return descriptor.DiscretionaryAcl is not null;
    }

    private static SecurityControlState StateOf(bool enforced) =>
        enforced ? SecurityControlState.Enforced : SecurityControlState.NotEnforced;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(
        IntPtr handle,
        uint securityInformation,
        byte[] securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(
        IntPtr handle,
        uint requestedInformation,
        byte[]? securityDescriptor,
        uint length,
        out uint lengthNeeded);
}
