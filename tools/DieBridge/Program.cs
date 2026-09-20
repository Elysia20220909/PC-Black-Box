using System.Diagnostics;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using DestinyBlackBox;

// Deliberately separate from the protected application: no hardening gate is disabled.
internal static class Program
{
    private const string ArchiveHash = "7D7195F757C45F6B69364D167C9958FA60339D53876A87E4A1EDBCBF67D1E477";
    private const long MaxInput = 64L * 1024 * 1024;

    private static async Task<int> Main(string[] args)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) ||
            ProcessObjectLockdown.Apply() != SecurityControlState.Enforced || !ProcessObjectLockdown.VerifyCurrentPolicy()) return 2;
        if (args.Length == 0 || args[0] == "--session-test") return await SessionHost.RunAsync(args);
        return await RunLegacyAsync(args);
    }

    internal static async Task<byte[]> AnalyzeAsync(string archive, string target, CancellationToken cancellation)
    {
        byte[]? result = null;
        int code = await RunLegacyAsync(["--report", archive, target, "", ""], bytes => result = bytes, cancellation);
        if (code != 0 || result is null) throw new IOException("DiE analysis failed.");
        return result;
    }

    private static async Task<int> RunLegacyAsync(string[] args, Action<byte[]>? receive = null, CancellationToken cancellation = default)
    {
        if (args.Length != 5 || args[0] is not ("--report" or "--view"))
        {
            Console.Error.WriteLine("Usage: DieBridge --report|--view official-3.21.zip input-file main-app.dll report.md|unused");
            return 2;
        }
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
        if (ProcessObjectLockdown.Apply() != SecurityControlState.Enforced || !ProcessObjectLockdown.VerifyCurrentPolicy()) return 2;
        var held = new List<IDisposable>();
        var expectedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string root = Path.Combine(SecurityPolicy.ValidateLocalDirectory(Path.GetTempPath(), true), "PCBB-Die-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(root).SetAccessControl(acl);
            held.Add(SecureFileReader.OpenDirectoryGuard(root));
            string engine = Path.Combine(root, "engine");
            Directory.CreateDirectory(engine);
            using (var archive = SecureFileReader.OpenRead(SecurityPolicy.ValidateTargetPath(args[1])))
            {
                if (archive.Length > 128 * 1024 * 1024 || Convert.ToHexString(SHA256.HashData(archive)) != ArchiveHash)
                    throw new InvalidDataException("Official archive hash mismatch.");
                archive.Position = 0;
                using var zip = new ZipArchive(archive, ZipArchiveMode.Read);
                long total = 0;
                foreach (var entry in zip.Entries)
                {
                    cancellation.ThrowIfCancellationRequested();
                    string name = entry.FullName.Replace('\\', '/');
                    if (!name.StartsWith("die/", StringComparison.Ordinal)) throw new InvalidDataException("Archive layout.");
                    name = name[4..];
                    if (name.Length == 0 || name.EndsWith('/')) continue;
                    if (name.Split('/').Any(s => s is ".." or "." or "") || name.Contains(':')) throw new InvalidDataException("Archive path.");
                    bool runtime = name is "diec.exe" or "Qt5Core.dll" or "Qt5Script.dll" or "msvcp140.dll" or "msvcp140_1.dll" or "vcruntime140.dll";
                    if (!runtime && !name.StartsWith("db/", StringComparison.Ordinal)) continue;
                    total = checked(total + entry.Length);
                    if (entry.Length > 64 * 1024 * 1024 || total > 256 * 1024 * 1024) throw new InvalidDataException("Archive budget.");
                    string destination = Path.Combine(engine, name.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    using var source = entry.Open();
                    byte[] expected;
                    using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                    {
                        source.CopyTo(output);
                        output.Position = 0;
                        expected = SHA256.HashData(output);
                    }
                    HoldVerified(destination, expected, held);
                    expectedFiles.Add(destination);
                }
            }
            string target = SecurityPolicy.ValidateTargetPath(args[2]);
            using var input = SecureFileReader.OpenRead(target);
            if (input.Length > MaxInput) throw new InvalidDataException("Input exceeds 64 MiB.");
            string digest = Convert.ToHexString(SHA256.HashData(input));
            input.Position = 0;
            string staged = Path.Combine(engine, "sample.bin");
            using (var copy = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(copy);
            HoldVerified(staged, Convert.FromHexString(digest), held);
            expectedFiles.Add(staged);
            Directory.CreateDirectory(Path.Combine(engine, "empty-db"));
            foreach (var path in Directory.EnumerateDirectories(engine, "*", SearchOption.AllDirectories).Prepend(engine))
                held.Add(SecureFileReader.OpenDirectoryGuard(path));
            string json = await AppContainerRunner.RunAsync(engine, () =>
            {
                var actual = Directory.EnumerateFiles(engine, "*", SearchOption.AllDirectories).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (!actual.SetEquals(expectedFiles)) throw new InvalidDataException("Unexpected staged files.");
            }, cancellation);
            using var result = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 20 });
            string evidence = Path.Combine(root, "evidence.json");
            byte[] evidenceBytes = JsonSerializer.SerializeToUtf8Bytes(new { schema = "pcbb-die-v1", sha256 = digest, result = result.RootElement });
            if (receive is not null) { receive(evidenceBytes); return 0; }
            using (var evidenceStream = new FileStream(evidence, FileMode.CreateNew, FileAccess.Write, FileShare.None)) evidenceStream.Write(evidenceBytes);
            HoldVerified(evidence, SHA256.HashData(evidenceBytes), held);
            string app = SecurityPolicy.ValidateTargetPath(args[3]);
            if (!Path.GetFileName(app).Equals("PC Black Box.dll", StringComparison.Ordinal)) throw new InvalidDataException("Unexpected application.");
            // Use the framework host that launched this bridge, never PATH resolution.
            string host = Environment.ProcessPath!;
            if (!Path.GetFileName(host).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Run the bridge using dotnet and its DLL.");
            var start = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add(app);
            start.ArgumentList.Add(args[0] == "--report" ? "--die-report" : "--die-view");
            start.ArgumentList.Add(target);
            start.ArgumentList.Add(evidence);
            if (args[0] == "--report") start.ArgumentList.Add(Path.GetFullPath(args[4]));
            using var process = Process.Start(start) ?? throw new IOException("Application launch failed.");
            if (args[0] == "--report")
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                try { await process.WaitForExitAsync(deadline.Token); }
                catch (OperationCanceledException) { process.Kill(); throw; }
            }
            else await process.WaitForExitAsync();
            return process.ExitCode;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            Console.Error.WriteLine("PCBB_DIE failed=true error=" + ex.GetType().Name +
                (ex is System.ComponentModel.Win32Exception native ? " win32=" + native.NativeErrorCode : ""));
            return 1;
        }
        finally
        {
            foreach (var resource in held.AsEnumerable().Reverse()) resource.Dispose();
            // This unique directory is created by this invocation, never supplied by a caller.
            if (Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0)
            {
                try { Directory.Delete(root, true); }
                catch { Console.Error.WriteLine("PCBB_DIE cleanup=false (temporary data remains)"); }
            }
        }
    }

    private static void HoldVerified(string path, byte[] expected, List<IDisposable> held)
    {
        var stream = SecureFileReader.OpenRead(path);
        held.Add(stream);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream), expected)) throw new InvalidDataException("Staging integrity failed.");
    }
}
