using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

/// <summary>Prevent new DLLs or DB files being planted while existing file handles deny writes.</summary>
internal sealed class DirectorySeal : IDisposable
{
    private readonly List<(SafeFileHandle Handle, byte[] Original)> entries = [];

    public DirectorySeal(string root, SecurityIdentifier container)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            foreach (string path in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories).Prepend(root))
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Directory link rejected.");
                var handle = CreateFileW(path, 0x00060080, 3, 0, 3, 0x02200000, 0);
                if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
                bool owned = false;
                try
                {
                    entries.Add((handle, ReadDescriptor(handle)));
                    owned = true;
                    var acl = new DirectorySecurity();
                    acl.SetAccessRuleProtection(true, false);
                    foreach (var principal in new[] { identity.User!, new SecurityIdentifier("S-1-3-4"), container })
                        acl.AddAccessRule(new FileSystemAccessRule(principal, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
                    byte[] descriptor = acl.GetSecurityDescriptorBinaryForm();
                    if (!SetKernelObjectSecurity(handle, 0x80000004, descriptor)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    var actual = new RawSecurityDescriptor(ReadDescriptor(handle), 0);
                    var expected = new RawSecurityDescriptor(descriptor, 0);
                    if ((actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                        !AclBytes(actual).SequenceEqual(AclBytes(expected))) throw new IOException("Directory seal verification failed.");
                }
                finally { if (!owned) handle.Dispose(); }
            }
        }
        catch { Dispose(); throw; }
    }

    private static byte[] ReadDescriptor(SafeFileHandle handle)
    {
        GetKernelObjectSecurity(handle, 4, null, 0, out uint size);
        if (size == 0 || size > 65536) throw new IOException("Invalid directory security descriptor.");
        byte[] data = new byte[size];
        if (!GetKernelObjectSecurity(handle, 4, data, size, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return data;
    }

    private static byte[] AclBytes(RawSecurityDescriptor descriptor)
    {
        var acl = descriptor.DiscretionaryAcl ?? throw new IOException("Missing directory DACL.");
        byte[] data = new byte[acl.BinaryLength];
        acl.GetBinaryForm(data, 0);
        return data;
    }

    public void Dispose()
    {
        foreach (var item in entries.AsEnumerable().Reverse())
        {
            if (!SetKernelObjectSecurity(item.Handle, 4, item.Original)) Console.Error.WriteLine("PCBB_DIE directoryAclRestore=false");
            item.Handle.Dispose();
        }
        entries.Clear();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint creation, uint flags, nint template);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint info, byte[] descriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint info, byte[]? descriptor, uint length, out uint needed);
}
