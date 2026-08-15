using System.Security.Principal;

namespace DestinyBlackBox;

/// <summary>
/// Whether this process holds an elevated administrator token. PC Black Box parses bytes it does not
/// trust, so it accepts the least privilege that can do the job: an elevated launch is refused instead
/// of accommodated, because the same parse would otherwise run under a token that can rewrite the
/// machine. A process cannot change its own elevation, so the answer is read once and cached.
/// </summary>
internal static class ProcessElevation
{
    /// <summary>Shown when the operator started the application with administrator rights.</summary>
    internal const string RefusalMessage =
        "PC Black Box does not run with administrator rights. Close this window and start it again normally.";

    /// <summary>Machine-readable counterpart for the command-line modes. Carries no inspected data.</summary>
    internal const string SafeRefusalLine = "PC_BLACK_BOX_ELEVATION elevated=true refusing=true";

    internal static bool IsElevated { get; } = DetectElevation();

    private static bool DetectElevation()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            // An unreadable token is not a licence to inspect. Fail closed, as the baseline does.
            return true;
        }
    }
}
