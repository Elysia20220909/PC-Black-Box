using System.Security.AccessControl;
using System.Security.Principal;
using DestinyBlackBox;

if (args.Length != 1) return 2;
string root = Path.Combine(Path.GetTempPath(), "PCBB-SandboxProbe-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var acl = new DirectorySecurity();
    acl.SetAccessRuleProtection(true, false);
    using var identity = WindowsIdentity.GetCurrent();
    acl.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
    // Regression: an unexpected writable group ACE must not survive the directory seal.
    acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
    new DirectoryInfo(root).SetAccessControl(acl);
    File.Copy(Path.GetFullPath(args[0]), Path.Combine(root, "diec.exe"));
    // Use the production cleanup path while a real Windows file handle denies deletion.
    string residual = Path.Combine(root, "cleanup-fixture");
    Directory.CreateDirectory(residual);
    var failedCleanup = new CleanupTracker();
    using (var locked = new FileStream(Path.Combine(residual, "sample.bin"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read))
    {
        failedCleanup.DeleteTemporaryDirectory(residual);
        if (failedCleanup.Snapshot.TemporaryData != "failed" || !File.Exists(locked.Name)) return 8;
        failedCleanup.DeleteProfile(() => unchecked((int)0x80070005));
        var response = DieSessionResponse.Read(DieSessionResponse.Write("{}"u8.ToArray(), "complete", failedCleanup.Snapshot));
        if (response.Analysis != "complete" || response.Evidence is null || !response.Cleanup.NeedsAttention ||
            response.Cleanup.AppContainerProfile != "failed") return 9;
    }
    failedCleanup.DeleteTemporaryDirectory(residual);
    if (failedCleanup.Snapshot.TemporaryData != "complete" || Directory.Exists(residual)) return 10;
    Console.WriteLine("PCBB_DIE_CLEANUP_TEST passed=true lockedFile=true profileFailure=true retry=true");
    using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
    listener.Start();
    using (var positive = new System.Net.Sockets.TcpClient())
    {
        await positive.ConnectAsync(System.Net.IPAddress.Loopback, ((System.Net.IPEndPoint)listener.LocalEndpoint).Port);
        using var accepted = await listener.AcceptTcpClientAsync();
    }
    File.WriteAllText(Path.Combine(root, "network-port"), ((System.Net.IPEndPoint)listener.LocalEndpoint).Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
    bool sealDeniedWrite = false;
    var successfulCleanup = new CleanupTracker();
    string result = await AppContainerRunner.RunAsync(root, () =>
    {
        try { File.WriteAllText(Path.Combine(root, "planted.txt"), "must not be created"); }
        catch (UnauthorizedAccessException) { sealDeniedWrite = true; }
        if (!sealDeniedWrite) throw new IOException("Same-user directory seal failed.");
    }, cleanup: successfulCleanup);
    if (successfulCleanup.Snapshot.NeedsAttention) return 11;
    Console.WriteLine(result);
    if (listener.Pending()) return 6;
    if (!result.Contains("\"networkDenied\":true", StringComparison.Ordinal) || !result.Contains("\"writeDenied\":true", StringComparison.Ordinal)) return 3;
    File.WriteAllText(Path.Combine(root, "flood"), "");
    bool floodRejected = false;
    try { await AppContainerRunner.RunAsync(root); } catch (InvalidDataException) { floodRejected = true; }
    if (!floodRejected) return 4;
    File.Delete(Path.Combine(root, "flood"));
    File.WriteAllText(Path.Combine(root, "hang"), "");
    bool timeout = false;
    try { await AppContainerRunner.RunAsync(root); } catch (OperationCanceledException) { timeout = true; }
    if (!timeout) return 5;
    using var cancel = new CancellationTokenSource();
    var cancellationCleanup = new CleanupTracker();
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    Task<string> running = AppContainerRunner.RunAsync(root, cancellation: cancel.Token, started: () => started.TrySetResult(), cleanup: cancellationCleanup);
    await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
    cancel.Cancel();
    bool cancelled = false;
    try { await running; } catch (OperationCanceledException) { cancelled = true; }
    if (!cancelled || cancellationCleanup.Snapshot.NeedsAttention) return 7;
    Console.WriteLine("PCBB_SANDBOX_PROBE passed=true networkDenied=true writeDenied=true outputLimit=true timeout=true directorySeal=true runningCancellation=true");
    return 0;
}
finally
{
    if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0) Directory.Delete(root, true);
}
