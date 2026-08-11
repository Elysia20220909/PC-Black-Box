using System.Reflection;

namespace DestinyBlackBox;

/// <summary>
/// Guards the standard .NET network transports used by this source tree: none may be present, and a
/// later load terminates the process before the caller can use it. This observes managed runtime state;
/// it is not an AppContainer or Windows Filtering Platform capability denial for arbitrary native code.
/// </summary>
internal static class NetworkIsolationGuard
{
    /// <summary>
    /// Standard .NET assemblies that provide HTTP, sockets, MsQuic, DNS, mail, ping, or WebSockets.
    ///
    /// Deliberately absent are the layers above them — System.Net.Requests, System.Net.WebClient,
    /// System.Net.ServicePoint, System.Net.Security, System.Net.Primitives. They describe requests but
    /// do not transmit without a lower transport, and System.Configuration loads several of
    /// them while opening a purely local app.config during WPF startup. Blocking them would abort the
    /// process on a local file read and teach the operator to distrust the alarm.
    /// </summary>
    private static readonly string[] TransmitCapableAssemblies =
    [
        "System.Net.Http",
        "System.Net.HttpListener",
        "System.Net.Mail",
        "System.Net.NameResolution",
        "System.Net.Ping",
        "System.Net.Quic",
        "System.Net.Sockets",
        "System.Net.WebSockets",
        "System.Net.WebSockets.Client"
    ];

    private static int _armed;

    /// <summary>
    /// Registers the fail-closed load hook and reports whether the process is currently free of
    /// transmit-capable assemblies.
    /// </summary>
    internal static SecurityControlState Arm()
    {
        try
        {
            if (Interlocked.Exchange(ref _armed, 1) == 0)
            {
                AppDomain.CurrentDomain.AssemblyLoad += OnAssemblyLoad;
            }

            return IsManagedTransportFree()
                ? SecurityControlState.Enforced
                : SecurityControlState.NotEnforced;
        }
        catch
        {
            return SecurityControlState.NotEnforced;
        }
    }

    internal static bool IsBlockedAssemblyName(string? simpleName) =>
        !String.IsNullOrEmpty(simpleName) &&
        TransmitCapableAssemblies.Contains(simpleName, StringComparer.OrdinalIgnoreCase);

    internal static bool IsArmedAndManagedTransportFree() =>
        Volatile.Read(ref _armed) == 1 && IsManagedTransportFree();

    private static void OnAssemblyLoad(object? sender, AssemblyLoadEventArgs args)
    {
        if (!IsTransmitCapable(args.LoadedAssembly)) return;

        // Fail closed: an offline tool that has just gained a transport is no longer the tool the
        // operator agreed to run, and the safest remaining action is to stop before it can send.
        // The name comes from the fixed list above, so this message carries no inspected data.
        string name = SafeName(args.LoadedAssembly);
        Environment.FailFast($"PC Black Box blocked a network transport ({name}) and stopped to stay offline.");
    }

    private static string SafeName(Assembly assembly)
    {
        try
        {
            string? name = assembly.GetName().Name;
            return TransmitCapableAssemblies.FirstOrDefault(
                blocked => blocked.Equals(name, StringComparison.OrdinalIgnoreCase)) ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }

    private static bool IsTransmitCapable(Assembly assembly)
    {
        try { return IsBlockedAssemblyName(assembly.GetName().Name); }
        catch { return true; }
    }

    private static bool IsManagedTransportFree()
    {
        try
        {
            return AppDomain.CurrentDomain.GetAssemblies().All(assembly => !IsTransmitCapable(assembly));
        }
        catch
        {
            return false;
        }
    }
}
