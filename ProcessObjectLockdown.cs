using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DestinyBlackBox;

/// <summary>
/// Replaces the default DACL on this process object so that another program running as the same user
/// cannot read its memory, write to it, start a thread inside it, or steal its file handles. The bytes
/// of an untrusted download live in this address space while it is being parsed; the default Windows
/// DACL would let any same-user process read them out. Kernel and administrator access remain out of
/// scope — they are above this trust boundary and are documented as such.
/// </summary>
internal static class ProcessObjectLockdown
{
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessCreateThread = 0x0002;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessDupHandle = 0x0040;
    private const uint ProcessCreateProcess = 0x0080;
    private const uint ProcessSetInformation = 0x0200;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessSuspendResume = 0x0800;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint Synchronize = 0x00100000;
    private const uint ProcessAllAccess = 0x001FFFFF;

    private const uint DaclSecurityInformation = 0x00000004;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>What the owning user keeps: see it in Task Manager, wait on it, and end it.</summary>
    private const uint OwnerRetainedAccess =
        ProcessTerminate | ProcessQueryLimitedInformation | ReadControl | Synchronize;

    /// <summary>What no same-user caller may hold, including the implicit rights of the object owner.</summary>
    private const uint ForbiddenAccess =
        ProcessCreateThread | ProcessVmOperation | ProcessVmRead | ProcessVmWrite | ProcessDupHandle |
        ProcessCreateProcess | ProcessSetInformation | ProcessQueryInformation | ProcessSuspendResume |
        WriteDac | WriteOwner;

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

            return StateOf(VerifyNoForbiddenAccess(system));
        }
        catch
        {
            return SecurityControlState.NotEnforced;
        }
    }

    /// <summary>Reads the DACL back from the kernel rather than trusting that the write took effect.</summary>
    private static bool VerifyNoForbiddenAccess(SecurityIdentifier system)
    {
        if (!TryReadDacl(out RawAcl? acl)) return false;
        if (acl is null) return false;

        foreach (GenericAce ace in acl)
        {
            if (ace is not CommonAce common) return false;
            if (common.AceQualifier != AceQualifier.AccessAllowed) continue;
            if (common.SecurityIdentifier == system) continue;
            if ((unchecked((uint)common.AccessMask) & ForbiddenAccess) != 0) return false;
        }

        return true;
    }

    private static bool TryReadDacl(out RawAcl? acl)
    {
        acl = null;
        IntPtr process = GetCurrentProcess();

        if (GetKernelObjectSecurity(process, DaclSecurityInformation, null, 0, out uint required))
        {
            return false;
        }
        if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || required == 0)
        {
            return false;
        }

        byte[] buffer = new byte[required];
        if (!GetKernelObjectSecurity(process, DaclSecurityInformation, buffer, required, out _))
        {
            return false;
        }

        acl = new RawSecurityDescriptor(buffer, 0).DiscretionaryAcl;
        return acl is not null;
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
