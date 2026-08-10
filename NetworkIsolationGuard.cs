using System.Reflection;

namespace DestinyBlackBox;

/// <summary>
/// PC Black Box promises that inspection is fully offline. This guard turns that promise into a
/// checked property of the running process: no assembly that can open a socket, resolve a name, or
/// issue a web request may be present, and any later attempt to load one kills the process before it
/// can transmit. Nothing here reaches the network to prove the point — it only observes managed state.
/// </summary>
internal static class NetworkIsolationGuard
{
    /// <summary>
    /// The assemblies that can actually move a byte off this machine. Every managed outbound path on
    /// Windows bottoms out in one of these: Berkeley sockets, the MsQuic binding, or the DNS resolver.
    ///
    /// Deliberately absent are the layers above them — System.Net.Requests, System.Net.WebClient,
    /// System.Net.ServicePoint, System.Net.Security, System.Net.Primitives. They describe requests but
    /// cannot transmit one without the socket layer below, and System.Configuration loads several of
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

            foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (IsTransmitCapable(assembly)) return SecurityControlState.NotEnforced;
            }

            return SecurityControlState.Enforced;
        }
        catch
        {
            return SecurityControlState.NotEnforced;
        }
    }

    internal static bool IsBlockedAssemblyName(string? simpleName) =>
        !String.IsNullOrEmpty(simpleName) &&
        TransmitCapableAssemblies.Contains(simpleName, StringComparer.OrdinalIgnoreCase);

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
        catch { return false; }
    }
}
