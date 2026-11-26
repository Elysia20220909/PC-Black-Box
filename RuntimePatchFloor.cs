namespace DestinyBlackBox;

/// <summary>
/// The .NET runtimes this application accepts: the serviced .NET 10 line, from <see cref="Minimum"/> on.
/// ZIP inflation runs inside the runtime's own native <c>System.IO.Compression.Native.dll</c>, and the
/// threat model treats that component as trusted only once servicing updates are applied. The
/// runtimeconfig still names 10.0.0, so without this check the host would start the parser on an
/// unserviced 10.0.x that lacks published security fixes.
/// </summary>
/// <remarks>
/// Another major version is refused as well. The host reaches one only when the operator forces
/// roll-forward, and the self-test does not pass on .NET 11.0.0. Raise <see cref="Minimum"/> when a
/// .NET 10 servicing release carries security fixes, and move it to the new line when the target
/// framework moves, updating the self-test and the README requirement in the same change.
/// </remarks>
internal static class RuntimePatchFloor
{
    /// <summary>10.0.15 (2026-11-10) is the latest .NET 10 security release at the time of writing.</summary>
    internal static readonly Version Minimum = new(10, 0, 15);

    /// <summary>
    /// Compares Major.Minor.Build only. <see cref="Environment.Version"/> reports three components on
    /// .NET 5 and later, and a fourth would otherwise make an equal patch compare above the floor.
    /// </summary>
    internal static bool IsRefused(Version runtime)
    {
        if (runtime.Major != Minimum.Major) return true;
        var patch = new Version(runtime.Major, runtime.Minor, Math.Max(runtime.Build, 0));
        return patch < Minimum;
    }

    internal static bool IsCurrentRefused => IsRefused(Environment.Version);

    /// <summary>Machine-readable counterpart for the command-line modes. Both values are numeric versions.</summary>
    internal static string SafeRefusalLine(Version runtime) =>
        $"PC_BLACK_BOX_RUNTIME_FLOOR version={runtime} minimum={Minimum} refusing=true";

    /// <summary>Says what to install instead, in the operator's language.</summary>
    internal static string BuildRefusalMessage(Version runtime, bool japanese) => japanese
        ? $"この PC で選ばれた .NET ランタイム（{runtime}）は、セキュリティ修正を確認できる範囲にないため、ファイルを調べずに終了します。" +
          $"{Environment.NewLine}{Environment.NewLine}.NET 10 Desktop Runtime を {Minimum} 以降に更新してから、起動し直してください。"
        : $"The .NET runtime selected on this PC ({runtime}) is outside the range whose security fixes are confirmed. PC Black Box will close without inspecting any files." +
          $"{Environment.NewLine}{Environment.NewLine}Update the .NET 10 Desktop Runtime to {Minimum} or later, then start PC Black Box again.";
}
