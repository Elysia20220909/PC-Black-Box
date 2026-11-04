using System.Runtime.InteropServices;

namespace DestinyBlackBox;

internal static class RuntimeExecutionInfo
{
    // Report the CLR and architecture of this product process, not an installed SDK or the OS.
    // Keep this protocol free of paths, environment variables, and arbitrary diagnostic text.
    public static string SafeStatusLine =>
        $"PC_BLACK_BOX_RUNTIME version={Environment.Version} processArchitecture={RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}";
}
