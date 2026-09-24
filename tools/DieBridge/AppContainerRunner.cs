using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static class AppContainerRunner
{
    internal static async Task<string> RunAsync(string directory, Action? verifyStaging = null, CancellationToken cancellation = default, Action? started = null, CleanupTracker? cleanup = null)
    {
        cleanup ??= new CleanupTracker();
        string profile = "PCBB.Die." + Guid.NewGuid().ToString("N");
        nint sid = 0, attributes = 0, capabilities = 0, handleList = 0, environment = 0;
        nint job = 0;
        ProcessInformation process = default;
        bool createdProfile = false, initializedAttributes = false;
        DirectorySeal? seal = null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            Marshal.ThrowExceptionForHR(CreateAppContainerProfile(profile, profile, "Temporary offline DiE parser", 0, 0, out sid));
            createdProfile = true;
            cleanup.AppContainerProfile = "unknown";
            var principal = new SecurityIdentifier(sid);
            var directoryInfo = new DirectoryInfo(directory);
            var acl = directoryInfo.GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(principal, FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            directoryInfo.SetAccessControl(acl);
            cleanup.DirectoryPermissions = "unknown";
            seal = new DirectorySeal(directory, principal);
            verifyStaging?.Invoke();

            job = CreateJobObjectW(0, null);
            Check(job != 0);
            var limits = new ExtendedLimit { Basic = new BasicLimit { Flags = 0x2000 | 0x100 | 0x8, ActiveProcessLimit = 1 }, ProcessMemoryLimit = 256 * 1024 * 1024 };
            Check(SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf<ExtendedLimit>()));

            var sa = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Inherit = 1 };
            Check(CreatePipe(out var outputRead, out var outputWrite, ref sa, 0));
            using var readHandle = new SafeFileHandle(outputRead, true);
            using var writeHandle = new SafeFileHandle(outputWrite, true);
            Check(SetHandleInformation(outputRead, 1, 0));
            Check(CreatePipe(out var errorRead, out var errorWrite, ref sa, 0));
            using var errorReadHandle = new SafeFileHandle(errorRead, true);
            using var errorWriteHandle = new SafeFileHandle(errorWrite, true);
            Check(SetHandleInformation(errorRead, 1, 0));
            using var stdin = CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0, 0);
            Check(!stdin.IsInvalid);

            nuint size = 0;
            InitializeProcThreadAttributeList(0, 2, 0, ref size);
            attributes = Marshal.AllocHGlobal(checked((int)size));
            Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size));
            initializedAttributes = true;
            capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities { Sid = sid }, capabilities, false);
            Check(UpdateProcThreadAttribute(attributes, 0, 0x20009, capabilities, (nuint)Marshal.SizeOf<SecurityCapabilities>(), 0, 0));
            handleList = Marshal.AllocHGlobal(3 * IntPtr.Size);
            Marshal.WriteIntPtr(handleList, 0, outputWrite);
            Marshal.WriteIntPtr(handleList, IntPtr.Size, errorWrite);
            Marshal.WriteIntPtr(handleList, 2 * IntPtr.Size, stdin.DangerousGetHandle());
            Check(UpdateProcThreadAttribute(attributes, 0, 0x20002, handleList, (nuint)(3 * IntPtr.Size), 0, 0));
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            environment = Marshal.StringToHGlobalUni($"LOCALAPPDATA={local}\0SystemRoot={windows}\0TEMP={Path.GetTempPath()}\0TMP={Path.GetTempPath()}\0USERPROFILE={user}\0WINDIR={windows}\0\0");
            string exe = Path.Combine(directory, "diec.exe");
            var startup = new StartupInfoEx { Info = new StartupInfo { Size = Marshal.SizeOf<StartupInfoEx>(), Flags = 0x100, StdInput = stdin.DangerousGetHandle(), StdOutput = outputWrite, StdError = errorWrite }, Attributes = attributes };
            var command = new StringBuilder($"\"{exe}\" -j --database \"{Path.Combine(directory, "db")}\" --extradatabase \"{Path.Combine(directory, "empty-db")}\" --customdatabase \"{Path.Combine(directory, "empty-db")}\" \"{Path.Combine(directory, "sample.bin")}\"");
            timeout.Token.ThrowIfCancellationRequested();
            Check(CreateProcessW(exe, command, 0, 0, true, 0x80000 | 0x08000000 | 0x400 | 0x4, environment, directory, ref startup, out process));
            // Attach and inspect the suspended child before a single instruction of parser code runs.
            Check(AssignProcessToJobObject(job, process.Process));
            VerifyAppContainer(process.Process);
            using var killOnCancel = timeout.Token.Register(() => TerminateJobObject(job, 1));
            Check(ResumeThread(process.Thread) != uint.MaxValue);
            started?.Invoke();
            writeHandle.Dispose();
            errorWriteHandle.Dispose();
            using var outputStream = new FileStream(readHandle, FileAccess.Read);
            using var errorStream = new FileStream(errorReadHandle, FileAccess.Read);
            Task<string> stdout = Task.Run(() => ReadBounded(outputStream));
            Task<string> stderr = Task.Run(() => ReadBounded(errorStream));
            while (WaitForSingleObject(process.Process, 50) == 258)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (stdout.IsFaulted || stderr.IsFaulted) throw new InvalidDataException("DiE output budget exceeded.");
                await Task.Delay(25, timeout.Token);
            }
            Check(GetExitCodeProcess(process.Process, out uint exitCode));
            timeout.Token.ThrowIfCancellationRequested();
            string result = await stdout.WaitAsync(timeout.Token);
            string errors = await stderr.WaitAsync(timeout.Token);
            if (exitCode != 0) throw new IOException("DiE exited with code " + exitCode);
            Console.WriteLine("PCBB_DIE appContainer=true capabilities=0 jobLimit=1 parserExit=0");
            return result;
        }
        finally
        {
            if (process.Process != 0) { TerminateProcess(process.Process, 1); WaitForSingleObject(process.Process, 5000); }
            if (job != 0) { TerminateJobObject(job, 1); CloseHandle(job); }
            if (process.Thread != 0) CloseHandle(process.Thread);
            if (process.Process != 0) CloseHandle(process.Process);
            if (initializedAttributes) DeleteProcThreadAttributeList(attributes);
            if (attributes != 0) Marshal.FreeHGlobal(attributes);
            if (capabilities != 0) Marshal.FreeHGlobal(capabilities);
            if (handleList != 0) Marshal.FreeHGlobal(handleList);
            if (environment != 0) Marshal.FreeHGlobal(environment);
            if (sid != 0) FreeSid(sid);
            if (createdProfile) cleanup.DeleteProfile(() => DeleteAppContainerProfile(profile));
            if (seal is not null)
            {
                string disposed = CleanupTracker.Attempt(seal.Dispose);
                cleanup.DirectoryPermissions = disposed == "complete" && seal.Restored ? "complete" : "failed";
            }
        }
    }

    private static string ReadBounded(Stream stream)
    {
        using var result = new MemoryStream();
        byte[] block = new byte[4096];
        int read;
        while ((read = stream.Read(block)) > 0)
        {
            if (result.Length + read > 512 * 1024) throw new InvalidDataException("DiE output budget exceeded.");
            result.Write(block, 0, read);
        }
        return new UTF8Encoding(false, true).GetString(result.ToArray());
    }

    private static void VerifyAppContainer(nint process)
    {
        Check(OpenProcessToken(process, 8, out nint token));
        try
        {
            Check(GetTokenInformation(token, 29, out int value, 4, out _) && value == 1);
            // A zero-capability token has an empty TOKEN_GROUPS count.
            GetTokenInformationBuffer(token, 30, 0, 0, out int length);
            nint buffer = Marshal.AllocHGlobal(length);
            try { Check(GetTokenInformationBuffer(token, 30, buffer, length, out _) && Marshal.ReadInt32(buffer) == 0); }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(token); }
    }

    private static void Check(bool ok, [System.Runtime.CompilerServices.CallerArgumentExpression(nameof(ok))] string? operation = null)
    {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), "Sandbox operation failed: " + operation);
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public nint Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityCapabilities { public nint Sid, Capabilities; public uint Count, Reserved; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public nint Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfo { public int Size; public nint Reserved, Desktop, Title; public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags; public ushort Show, ReservedSize; public nint ReservedPointer, StdInput, StdOutput, StdError; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Info; public nint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimit { public long ProcessTime, JobTime; public uint Flags; public nuint MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit; public nuint Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimit { public BasicLimit Basic; public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int CreateAppContainerProfile(string name, string display, string description, nint capabilities, uint count, out nint sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll")] private static extern nint FreeSid(nint sid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(out nint read, out nint write, ref SecurityAttributes attributes, int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(nint handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, ref SecurityAttributes attributes, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(nint list, int count, int flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, nint value, nuint size, nint previous, nint returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(nint list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessW(string app, StringBuilder command, nint pa, nint ta, bool inherit, uint flags, nint environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CreateJobObjectW(nint attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(nint job, int info, ref ExtendedLimit limits, int length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(nint job, nint process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(nint thread);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(nint handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(nint process, out uint code);
    [DllImport("kernel32.dll")] private static extern bool TerminateJobObject(nint job, uint code);
    [DllImport("kernel32.dll")] private static extern bool TerminateProcess(nint process, uint code);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(nint handle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(nint process, uint access, out nint token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(nint token, int info, out int value, int size, out int returned);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)] private static extern bool GetTokenInformationBuffer(nint token, int info, nint value, int size, out int returned);
}
