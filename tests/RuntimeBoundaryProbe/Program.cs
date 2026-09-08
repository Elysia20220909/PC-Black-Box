using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;

namespace PcBlackBox.RuntimeBoundaryProbe;

internal static class Program
{
    internal const int GuardBypassedExitCode = 86;

    private static int Main(string[] args)
    {
        if (args.Length != 2 || (args[0] != "--network-transport" && args[0] != "--hold"))
        {
            Console.Error.WriteLine("Usage: RuntimeBoundaryProbe <--network-transport|--hold> <PC Black Box.dll>");
            return 2;
        }

        string applicationAssembly = Path.GetFullPath(args[1]);
        if (!File.Exists(applicationAssembly))
        {
            Console.Error.WriteLine("The application assembly was not found.");
            return 3;
        }

        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Console.Error.WriteLine("The runtime probe requires a non-elevated process.");
            return 4;
        }

        Assembly application = Assembly.LoadFrom(applicationAssembly);
        RuntimeHelpers.RunModuleConstructor(application.ManifestModule.ModuleHandle);

        if (args[0] == "--hold")
        {
            // Exercise the production module initializer without starting WPF or opening a target.
            Type hardening = application.GetType("DestinyBlackBox.WindowsProcessHardening", throwOnError: true)!;
            object posture = hardening.GetProperty("Current")!.GetValue(null)!;
            bool enforced = (bool)posture.GetType().GetProperty("IsEnforced")!.GetValue(posture)!;
            if (!enforced) return 5;
            Console.WriteLine("BOUNDARY_PROBE_READY");
            Console.Out.Flush();
            // Bounded lifetime even if the parent fails before it can close this process.
            Thread.Sleep(TimeSpan.FromSeconds(30));
            return 0;
        }

        _ = Assembly.Load(new AssemblyName("System.Net.Sockets"));
        Console.Error.WriteLine("NETWORK_GUARD_BYPASSED");
        return GuardBypassedExitCode;
    }
}
