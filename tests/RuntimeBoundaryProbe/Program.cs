using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace PcBlackBox.RuntimeBoundaryProbe;

internal static class Program
{
    internal const int GuardBypassedExitCode = 86;

    private static int Main(string[] args)
    {
        if (args.Length != 2 || !args[0].Equals("--network-transport", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("Usage: RuntimeBoundaryProbe --network-transport <PC Black Box.dll>");
            return 2;
        }

        string applicationAssembly = Path.GetFullPath(args[1]);
        if (!File.Exists(applicationAssembly))
        {
            Console.Error.WriteLine("The application assembly was not found.");
            return 3;
        }

        Assembly application = Assembly.LoadFrom(applicationAssembly);
        RuntimeHelpers.RunModuleConstructor(application.ManifestModule.ModuleHandle);

        _ = Assembly.Load(new AssemblyName("System.Net.Sockets"));
        Console.Error.WriteLine("NETWORK_GUARD_BYPASSED");
        return GuardBypassedExitCode;
    }
}
