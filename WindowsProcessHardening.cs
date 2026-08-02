using System.Runtime.InteropServices;

namespace DestinyBlackBox;

public static class WindowsProcessHardening
{
    private const uint NoChildProcessCreation = 0x00000001;
    private const uint NoRemoteImages = 0x00000001;
    private const uint NoLowMandatoryLabelImages = 0x00000002;
    private const uint PreferSystem32Images = 0x00000004;

    public static bool ApplyRequiredPolicies()
    {
        try
        {
            AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", TimeSpan.FromSeconds(2));

            uint childPolicy = NoChildProcessCreation;
            if (!SetProcessMitigationPolicy(ProcessMitigationPolicy.ChildProcess, ref childPolicy, (nuint)sizeof(uint)))
            {
                return false;
            }

            uint imageLoadPolicy = NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images;
            return SetProcessMitigationPolicy(ProcessMitigationPolicy.ImageLoad, ref imageLoadPolicy, (nuint)sizeof(uint));
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicy(
        ProcessMitigationPolicy mitigationPolicy,
        ref uint buffer,
        nuint length);

    private enum ProcessMitigationPolicy
    {
        ImageLoad = 10,
        ChildProcess = 13
    }
}
