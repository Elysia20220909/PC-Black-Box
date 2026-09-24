using DestinyBlackBox;

/// <summary>Attempt every cleanup step; report failures without replacing the analysis outcome.</summary>
internal sealed class CleanupTracker
{
    internal string TemporaryData { get; set; } = "not-required";
    internal string AppContainerProfile { get; set; } = "not-required";
    internal string DirectoryPermissions { get; set; } = "not-required";
    internal DieCleanupStatus Snapshot => new(TemporaryData, AppContainerProfile, DirectoryPermissions);

    internal void DeleteTemporaryDirectory(string ownedRoot)
    {
        TemporaryData = Attempt(() =>
        {
            // Only a unique directory created by this invocation is passed here.
            // Do not use Directory.Exists to convert access errors into "already removed".
            try
            {
                if ((File.GetAttributes(ownedRoot) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Temporary root became a link.");
            }
            catch (DirectoryNotFoundException) { return; }
            catch (FileNotFoundException) { return; }
            Directory.Delete(ownedRoot, true);
        });
    }

    internal void DeleteProfile(Func<int> delete) =>
        AppContainerProfile = Attempt(() => System.Runtime.InteropServices.Marshal.ThrowExceptionForHR(delete()));

    internal static string Attempt(Action cleanup)
    {
        try { cleanup(); return "complete"; }
        catch { return "failed"; }
    }
}
