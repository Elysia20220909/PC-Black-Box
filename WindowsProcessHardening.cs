using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DestinyBlackBox;

public sealed record SecurityControlStatus(string Code, bool Enforced);

public sealed class SecurityPosture
{
    public const string ProfileId = "SECURITY-BASELINE-1";

    internal SecurityPosture(IReadOnlyList<SecurityControlStatus> controls)
    {
        Controls = controls;
    }

    public IReadOnlyList<SecurityControlStatus> Controls { get; }
    public int EnforcedCount => Controls.Count(control => control.Enforced);
    public int RequiredCount => Controls.Count;
    public bool IsEnforced => RequiredCount > 0 && EnforcedCount == RequiredCount;
    public string SafeStatusLine =>
        $"PC_BLACK_BOX_SECURITY profile={ProfileId} enforced={IsEnforced.ToString().ToLowerInvariant()} controls={EnforcedCount}/{RequiredCount}";
}

public static class WindowsProcessHardening
{
    private const uint NoChildProcessCreation = 0x00000001;
    private const uint NoRemoteImages = 0x00000001;
    private const uint NoLowMandatoryLabelImages = 0x00000002;
    private const uint PreferSystem32Images = 0x00000004;
    private const uint StrictHandleChecks = 0x00000003;
    private const uint DisableExtensionPoints = 0x00000001;
    private const uint DisableNonSystemFonts = 0x00000001;
    private const uint EnableBottomUpAslr = 0x00000001;
    private const uint EnableHighEntropyAslr = 0x00000004;
    private const uint EnableControlFlowGuard = 0x00000001;
    private const uint EnableSehop = 0x00000001;
    private const uint LoadLibrarySearchApplicationDir = 0x00000200;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const uint FailCriticalErrors = 0x00000001;
    private const uint NoGeneralProtectionFaultBox = 0x00000002;
    private const uint NoOpenFileErrorBox = 0x00008000;

    private static readonly string[] BaselineControlCodes =
    [
        "regex-timeout",
        "child-process-block",
        "image-load-boundary",
        "strict-handle-checks",
        "legacy-extension-points",
        "non-system-fonts",
        "dep",
        "aslr",
        "control-flow-guard",
        "sehop",
        "dll-search-boundary",
        "current-directory-dll-search",
        "critical-error-mode"
    ];

    public static SecurityPosture Current { get; private set; } = new(Array.Empty<SecurityControlStatus>());

    internal static void Initialize()
    {
        var controls = new List<SecurityControlStatus>(BaselineControlCodes.Length);
        try
        {
            TimeSpan regexTimeout = TimeSpan.FromSeconds(2);
            AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", regexTimeout);
            controls.Add(new("regex-timeout", Equals(AppDomain.CurrentDomain.GetData("REGEX_DEFAULT_MATCH_TIMEOUT"), regexTimeout)));

            controls.Add(new("child-process-block", ApplyAndVerify(
                ProcessMitigationPolicy.ChildProcess,
                NoChildProcessCreation)));
            controls.Add(new("image-load-boundary", ApplyAndVerify(
                ProcessMitigationPolicy.ImageLoad,
                NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images)));
            controls.Add(new("strict-handle-checks", ApplyAndVerify(
                ProcessMitigationPolicy.StrictHandleCheck,
                StrictHandleChecks)));
            controls.Add(new("legacy-extension-points", ApplyAndVerify(
                ProcessMitigationPolicy.ExtensionPointDisable,
                DisableExtensionPoints)));
            controls.Add(new("non-system-fonts", ApplyAndVerify(
                ProcessMitigationPolicy.FontDisable,
                DisableNonSystemFonts)));

            controls.Add(new("dep", VerifyDep()));
            controls.Add(new("aslr", VerifyPolicy(
                ProcessMitigationPolicy.Aslr,
                EnableBottomUpAslr | EnableHighEntropyAslr)));
            controls.Add(new("control-flow-guard", VerifyPolicy(
                ProcessMitigationPolicy.ControlFlowGuard,
                EnableControlFlowGuard)));
            controls.Add(new("sehop", VerifyPolicy(
                ProcessMitigationPolicy.Sehop,
                EnableSehop)));

            controls.Add(new("dll-search-boundary", TrySetDefaultDllDirectories(
                LoadLibrarySearchApplicationDir | LoadLibrarySearchSystem32)));
            controls.Add(new("current-directory-dll-search", TryRemoveCurrentDirectoryFromDllSearch()));
            controls.Add(new("critical-error-mode", ConfigureAndVerifyErrorMode()));
        }
        catch
        {
            AddMissingControlsAsFailed(controls);
        }

        AddMissingControlsAsFailed(controls);
        Current = new SecurityPosture(controls.AsReadOnly());
    }

    private static bool ApplyAndVerify(ProcessMitigationPolicy policy, uint requiredFlags)
    {
        try
        {
            uint requestedFlags = requiredFlags;
            _ = SetProcessMitigationPolicy(policy, ref requestedFlags, (nuint)sizeof(uint));
            return VerifyPolicy(policy, requiredFlags);
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyPolicy(ProcessMitigationPolicy policy, uint requiredFlags)
    {
        try
        {
            if (!GetProcessMitigationPolicy(GetCurrentProcess(), policy, out uint actualFlags, (nuint)sizeof(uint)))
            {
                return false;
            }
            return (actualFlags & requiredFlags) == requiredFlags;
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyDep()
    {
        try
        {
            if (!GetProcessMitigationPolicy(
                GetCurrentProcess(),
                ProcessMitigationPolicy.Dep,
                out NativeDepPolicy policy,
                (nuint)Marshal.SizeOf<NativeDepPolicy>()))
            {
                return false;
            }
            return (policy.Flags & 0x00000001) != 0 && policy.Permanent != 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetDefaultDllDirectories(uint flags)
    {
        try { return SetDefaultDllDirectories(flags); }
        catch { return false; }
    }

    private static bool TryRemoveCurrentDirectoryFromDllSearch()
    {
        try { return SetDllDirectoryW(String.Empty); }
        catch { return false; }
    }

    private static bool ConfigureAndVerifyErrorMode()
    {
        try
        {
            uint required = FailCriticalErrors | NoGeneralProtectionFaultBox | NoOpenFileErrorBox;
            uint desired = GetErrorMode() | required;
            _ = SetErrorMode(desired);
            return (GetErrorMode() & required) == required;
        }
        catch
        {
            return false;
        }
    }

    private static void AddMissingControlsAsFailed(List<SecurityControlStatus> controls)
    {
        foreach (string code in BaselineControlCodes)
        {
            if (!controls.Any(control => control.Code.Equals(code, StringComparison.Ordinal)))
            {
                controls.Add(new(code, false));
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicy(
        ProcessMitigationPolicy mitigationPolicy,
        ref uint buffer,
        nuint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMitigationPolicy(
        IntPtr process,
        ProcessMitigationPolicy mitigationPolicy,
        out uint buffer,
        nuint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMitigationPolicy(
        IntPtr process,
        ProcessMitigationPolicy mitigationPolicy,
        out NativeDepPolicy buffer,
        nuint length);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectoryW(string pathName);

    [DllImport("kernel32.dll")]
    private static extern uint GetErrorMode();

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeDepPolicy
    {
        public uint Flags;
        public byte Permanent;
    }

    private enum ProcessMitigationPolicy
    {
        Dep = 0,
        Aslr = 1,
        StrictHandleCheck = 3,
        ExtensionPointDisable = 6,
        ControlFlowGuard = 7,
        FontDisable = 9,
        ImageLoad = 10,
        ChildProcess = 13,
        Sehop = 18
    }
}

internal static class ProcessSecurityBootstrap
{
    [ModuleInitializer]
    internal static void Initialize() => WindowsProcessHardening.Initialize();
}
