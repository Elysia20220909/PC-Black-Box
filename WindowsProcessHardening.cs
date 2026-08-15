using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DestinyBlackBox;

public enum SecurityControlTier
{
    /// <summary>Must be applied and read back, or inspection does not start.</summary>
    Required,

    /// <summary>Applied and read back when possible; unsupported and failed states remain distinguishable.</summary>
    PlatformReinforcement
}

public enum SecurityControlState
{
    NotEnforced,
    Enforced,
    Unavailable
}

public sealed record SecurityControlStatus(string Code, SecurityControlTier Tier, SecurityControlState State)
{
    public bool Enforced => State == SecurityControlState.Enforced;

    public string SafeLine => $"control={Code} tier={TierText} state={StateText}";

    private string TierText => Tier == SecurityControlTier.Required ? "required" : "reinforcement";

    private string StateText => State switch
    {
        SecurityControlState.Enforced => "enforced",
        SecurityControlState.Unavailable => "unavailable",
        _ => "not-enforced"
    };
}

public sealed class SecurityPosture
{
    public const string ProfileId = "SECURITY-BASELINE-2";

    internal SecurityPosture(IReadOnlyList<SecurityControlStatus> controls)
    {
        Controls = controls;
    }

    public IReadOnlyList<SecurityControlStatus> Controls { get; }

    public int EnforcedCount => Controls.Count(control => control.Tier == SecurityControlTier.Required && control.Enforced);
    public int RequiredCount => Controls.Count(control => control.Tier == SecurityControlTier.Required);
    public int ReinforcementEnforcedCount => Controls.Count(control => control.Tier == SecurityControlTier.PlatformReinforcement && control.Enforced);
    public int ReinforcementCount => Controls.Count(control => control.Tier == SecurityControlTier.PlatformReinforcement);

    /// <summary>Inspection is gated on the required tier only. Reinforcements are reported, never silently assumed.</summary>
    public bool IsEnforced => RequiredCount > 0 && EnforcedCount == RequiredCount;

    public string SafeStatusLine =>
        $"PC_BLACK_BOX_SECURITY profile={ProfileId} enforced={IsEnforced.ToString().ToLowerInvariant()} " +
        $"controls={EnforcedCount}/{RequiredCount} reinforcements={ReinforcementEnforcedCount}/{ReinforcementCount}";

    public IReadOnlyList<string> SafeControlLines => Controls.Select(control => control.SafeLine).ToList();

    /// <summary>
    /// Only the required controls that did not verify. The operator who is being turned away needs the
    /// name of what failed; every string here comes from the fixed baseline list, never from a target.
    /// </summary>
    public IReadOnlyList<string> SafeFailedRequiredControlLines => Controls
        .Where(control => control.Tier == SecurityControlTier.Required && !control.Enforced)
        .Select(control => control.SafeLine)
        .ToList();
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
    private const uint EnforceRedirectionTrust = 0x00000001;
    private const uint IsolateSecurityDomain = 0x00000002;
    private const uint DisablePageCombine = 0x00000004;
    private const uint SpeculativeStoreBypassDisable = 0x00000008;
    private const uint EnableUserShadowStack = 0x00000001;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorNotSupported = 50;
    private const int ErrorCallNotImplemented = 120;
    private const uint LoadLibrarySearchApplicationDir = 0x00000200;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const uint FailCriticalErrors = 0x00000001;
    private const uint NoGeneralProtectionFaultBox = 0x00000002;
    private const uint NoOpenFileErrorBox = 0x00008000;
    private const int HeapEnableTerminationOnCorruption = 1;

    private static readonly (string Code, SecurityControlTier Tier)[] BaselineControls =
    [
        ("regex-timeout", SecurityControlTier.Required),
        ("child-process-block", SecurityControlTier.Required),
        ("image-load-boundary", SecurityControlTier.Required),
        ("strict-handle-checks", SecurityControlTier.Required),
        ("legacy-extension-points", SecurityControlTier.Required),
        ("non-system-fonts", SecurityControlTier.Required),
        ("dep", SecurityControlTier.Required),
        ("aslr", SecurityControlTier.Required),
        ("control-flow-guard", SecurityControlTier.Required),
        ("sehop", SecurityControlTier.Required),
        ("dll-search-boundary", SecurityControlTier.Required),
        ("current-directory-dll-search", SecurityControlTier.Required),
        ("critical-error-mode", SecurityControlTier.Required),
        ("heap-terminate-on-corruption", SecurityControlTier.Required),
        ("managed-network-transport-absent", SecurityControlTier.Required),
        ("process-object-lockdown", SecurityControlTier.Required),
        ("redirection-trust", SecurityControlTier.PlatformReinforcement),
        ("security-domain-isolation", SecurityControlTier.PlatformReinforcement),
        ("speculative-store-bypass", SecurityControlTier.PlatformReinforcement),
        ("user-shadow-stack", SecurityControlTier.PlatformReinforcement)
    ];

    public static SecurityPosture Current { get; private set; } = new(Array.Empty<SecurityControlStatus>());

    internal static void Initialize()
    {
        var controls = new List<SecurityControlStatus>(BaselineControls.Length);
        try
        {
            // The network guard is armed first so a hostile load cannot slip in during the rest of setup.
            Record(controls, "managed-network-transport-absent", NetworkIsolationGuard.Arm());

            TimeSpan regexTimeout = TimeSpan.FromSeconds(2);
            AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", regexTimeout);
            Record(controls, "regex-timeout", StateOf(Equals(AppDomain.CurrentDomain.GetData("REGEX_DEFAULT_MATCH_TIMEOUT"), regexTimeout)));

            Record(controls, "child-process-block", ApplyAndVerify(
                ProcessMitigationPolicy.ChildProcess,
                NoChildProcessCreation));
            Record(controls, "image-load-boundary", ApplyAndVerify(
                ProcessMitigationPolicy.ImageLoad,
                NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images));
            Record(controls, "strict-handle-checks", ApplyAndVerify(
                ProcessMitigationPolicy.StrictHandleCheck,
                StrictHandleChecks));
            Record(controls, "legacy-extension-points", ApplyAndVerify(
                ProcessMitigationPolicy.ExtensionPointDisable,
                DisableExtensionPoints));
            Record(controls, "non-system-fonts", ApplyAndVerify(
                ProcessMitigationPolicy.FontDisable,
                DisableNonSystemFonts));

            Record(controls, "dep", StateOf(VerifyDep()));
            Record(controls, "aslr", VerifyPolicyState(
                ProcessMitigationPolicy.Aslr,
                EnableBottomUpAslr | EnableHighEntropyAslr));
            Record(controls, "control-flow-guard", VerifyPolicyState(
                ProcessMitigationPolicy.ControlFlowGuard,
                EnableControlFlowGuard));
            Record(controls, "sehop", VerifyPolicyState(
                ProcessMitigationPolicy.Sehop,
                EnableSehop));

            Record(controls, "dll-search-boundary", StateOf(TrySetDefaultDllDirectories(
                LoadLibrarySearchApplicationDir | LoadLibrarySearchSystem32)));
            Record(controls, "current-directory-dll-search", StateOf(TryRemoveCurrentDirectoryFromDllSearch()));
            Record(controls, "critical-error-mode", StateOf(ConfigureAndVerifyErrorMode()));
            Record(controls, "heap-terminate-on-corruption", StateOf(TryEnableHeapTerminationOnCorruption()));
            Record(controls, "process-object-lockdown", ProcessObjectLockdown.Apply());

            // Reinforcements: applied and read back where possible. Unsupported and failed states stay distinct.
            Record(controls, "redirection-trust", ApplyAndVerify(
                ProcessMitigationPolicy.RedirectionTrust,
                EnforceRedirectionTrust));
            Record(controls, "security-domain-isolation", ApplyAndVerify(
                ProcessMitigationPolicy.SideChannelIsolation,
                IsolateSecurityDomain | DisablePageCombine));
            Record(controls, "speculative-store-bypass", ApplyAndVerify(
                ProcessMitigationPolicy.SideChannelIsolation,
                SpeculativeStoreBypassDisable));
            Record(controls, "user-shadow-stack", VerifyHardwareShadowStack());
        }
        catch
        {
            AddMissingControlsAsFailed(controls);
        }

        AddMissingControlsAsFailed(controls);
        Current = new SecurityPosture(OrderAsBaseline(controls));
    }

    private static void Record(List<SecurityControlStatus> controls, string code, SecurityControlState state)
    {
        controls.Add(new SecurityControlStatus(code, TierOf(code), state));
    }

    private static SecurityControlTier TierOf(string code) =>
        BaselineControls.First(control => control.Code.Equals(code, StringComparison.Ordinal)).Tier;

    private static SecurityControlState StateOf(bool enforced) =>
        enforced ? SecurityControlState.Enforced : SecurityControlState.NotEnforced;

    private static IReadOnlyList<SecurityControlStatus> OrderAsBaseline(List<SecurityControlStatus> controls)
    {
        var ordered = new List<SecurityControlStatus>(BaselineControls.Length);
        foreach ((string code, _) in BaselineControls)
        {
            ordered.Add(controls.First(control => control.Code.Equals(code, StringComparison.Ordinal)));
        }
        return ordered.AsReadOnly();
    }

    private static SecurityControlState ApplyAndVerify(ProcessMitigationPolicy policy, uint requiredFlags)
    {
        try
        {
            if (!TryGetPolicy(policy, out uint currentFlags))
            {
                // The running kernel does not know this policy class at all.
                return SecurityControlState.Unavailable;
            }

            if ((currentFlags & requiredFlags) == requiredFlags)
            {
                return SecurityControlState.Enforced;
            }

            uint requestedFlags = currentFlags | requiredFlags;
            if (!SetProcessMitigationPolicy(policy, ref requestedFlags, (nuint)sizeof(uint)))
            {
                int error = Marshal.GetLastPInvokeError();
                return error is ErrorInvalidParameter or ErrorNotSupported or ErrorCallNotImplemented
                    ? SecurityControlState.Unavailable
                    : SecurityControlState.NotEnforced;
            }

            return TryGetPolicy(policy, out uint appliedFlags) && (appliedFlags & requiredFlags) == requiredFlags
                ? SecurityControlState.Enforced
                : SecurityControlState.NotEnforced;
        }
        catch (EntryPointNotFoundException)
        {
            return SecurityControlState.Unavailable;
        }
        catch (DllNotFoundException)
        {
            return SecurityControlState.Unavailable;
        }
        catch
        {
            return SecurityControlState.NotEnforced;
        }
    }

    private static SecurityControlState VerifyPolicyState(ProcessMitigationPolicy policy, uint requiredFlags) =>
        StateOf(VerifyPolicy(policy, requiredFlags));

    /// <summary>
    /// Hardware-enforced stack protection cannot be switched on for a running process, and a cleared flag
    /// is indistinguishable from a CPU without CET. It is therefore read only and never treated as a failure.
    /// </summary>
    private static SecurityControlState VerifyHardwareShadowStack()
    {
        if (!TryGetPolicy(ProcessMitigationPolicy.UserShadowStack, out uint flags))
        {
            return SecurityControlState.Unavailable;
        }
        return (flags & EnableUserShadowStack) != 0
            ? SecurityControlState.Enforced
            : SecurityControlState.Unavailable;
    }

    private static bool TryGetPolicy(ProcessMitigationPolicy policy, out uint flags)
    {
        try
        {
            return GetProcessMitigationPolicy(GetCurrentProcess(), policy, out flags, (nuint)sizeof(uint));
        }
        catch
        {
            flags = 0;
            return false;
        }
    }

    private static bool VerifyPolicy(ProcessMitigationPolicy policy, uint requiredFlags) =>
        TryGetPolicy(policy, out uint actualFlags) && (actualFlags & requiredFlags) == requiredFlags;

    /// <summary>
    /// Confirms that sequential side-channel updates did not replace flags already reported as enforced.
    /// </summary>
    internal static bool VerifyReportedSideChannelPolicy()
    {
        uint reportedFlags = 0;
        if (Current.Controls.Any(control =>
                control.Code.Equals("security-domain-isolation", StringComparison.Ordinal) && control.Enforced))
        {
            reportedFlags |= IsolateSecurityDomain | DisablePageCombine;
        }
        if (Current.Controls.Any(control =>
                control.Code.Equals("speculative-store-bypass", StringComparison.Ordinal) && control.Enforced))
        {
            reportedFlags |= SpeculativeStoreBypassDisable;
        }

        return reportedFlags == 0 || VerifyPolicy(ProcessMitigationPolicy.SideChannelIsolation, reportedFlags);
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

    /// <summary>
    /// Turns a corrupted heap into an immediate process kill instead of an exploitable allocator state.
    /// Windows exposes no query for this class, so the API result is the only available confirmation.
    /// </summary>
    private static bool TryEnableHeapTerminationOnCorruption()
    {
        try { return HeapSetInformation(IntPtr.Zero, HeapEnableTerminationOnCorruption, IntPtr.Zero, UIntPtr.Zero); }
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
        foreach ((string code, SecurityControlTier tier) in BaselineControls)
        {
            if (!controls.Any(control => control.Code.Equals(code, StringComparison.Ordinal)))
            {
                controls.Add(new SecurityControlStatus(code, tier, SecurityControlState.NotEnforced));
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HeapSetInformation(
        IntPtr heap,
        int informationClass,
        IntPtr information,
        UIntPtr informationLength);

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
        SideChannelIsolation = 14,
        UserShadowStack = 15,
        RedirectionTrust = 16,
        Sehop = 18
    }
}

internal static class ProcessSecurityBootstrap
{
    [ModuleInitializer]
    internal static void Initialize() => WindowsProcessHardening.Initialize();
}
