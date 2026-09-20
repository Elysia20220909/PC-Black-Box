using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using DestinyBlackBox;

internal static class SessionHost
{
    internal static async Task<int> RunAsync(string[] args)
    {
        bool test = args.Length > 0;
        if (test && args.Length != 3) return 2;
        string root = AppContext.BaseDirectory;
        string app = Path.Combine(root, "app", "PC Black Box.dll");
        string archive = Path.Combine(root, "engine", "die_win32_portable_3.21_x86.zip");
        string host = Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..", "dotnet.exe"));
        if (!File.Exists(app) || !File.Exists(archive) || !File.Exists(host)) return 2;
        string name = "PCBB.Die." + Guid.NewGuid().ToString("N");
        using var stopped = new CancellationTokenSource();
        if (test) stopped.CancelAfter(TimeSpan.FromMinutes(4));
        using var first = NewPipe(name);
        var start = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(app)! };
        start.ArgumentList.Add(app);
        if (test)
        {
            start.ArgumentList.Add("--die-session-test");
            start.ArgumentList.Add(Path.GetFullPath(args[1]));
            start.ArgumentList.Add(Path.GetFullPath(args[2]));
        }
        start.Environment["PCBB_DIE_PIPE"] = name;
        start.Environment["PCBB_DIE_SERVER"] = Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        using var application = Process.Start(start) ?? throw new IOException("Main application launch failed.");
        Task serving = ServeAsync(first, (uint)application.Id, archive, stopped.Token);
        try
        {
            Task exited = application.WaitForExitAsync(stopped.Token);
            if (await Task.WhenAny(exited, serving) == serving && !stopped.IsCancellationRequested)
            {
                try { await serving; } catch (Exception ex) when (ex is IOException or InvalidOperationException) { }
                Console.Error.WriteLine("PCBB_DIE_SESSION serviceFailed=true");
                // Leave ordinary inspection usable; do not kill an interactive user's main window.
                if (test && !application.HasExited) application.Kill();
                await exited;
                return 1;
            }
            await exited;
        }
        catch (OperationCanceledException) { if (!application.HasExited) application.Kill(); return 1; }
        finally
        {
            stopped.Cancel();
            try { await serving; } catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException) { }
        }
        return application.ExitCode;
    }

    private static NamedPipeServerStream NewPipe(string name) => new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);

    private static async Task ServeAsync(NamedPipeServerStream pipe, uint client, string archive, CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            bool accepted = false;
            try
            {
                await pipe.WaitForConnectionAsync(stop);
                accepted = true;
                using var request = CancellationTokenSource.CreateLinkedTokenSource(stop);
                request.CancelAfter(TimeSpan.FromSeconds(80));
                try
                {
                    DiePipeProtocol.VerifyClient(pipe, client);
                    byte[] bytes = await DiePipeProtocol.ReadAsync(pipe, 32768, request.Token);
                    string target = new UTF8Encoding(false, true).GetString(bytes);
                    // EOF from the client cancels staging or parsing. No request can enqueue a second file.
                    Task disconnected = WatchDisconnectAsync(pipe, request);
                    try
                    {
                        byte[] result = await Task.Run(() => Program.AnalyzeAsync(archive, target, request.Token), request.Token);
                        await DiePipeProtocol.WriteAsync(pipe, result, request.Token);
                    }
                    finally
                    {
                        request.Cancel();
                        try { await disconnected; } catch (OperationCanceledException) { }
                    }
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException or ArgumentException)
                {
                    // Close this connection; the GUI reports failure instead of silently claiming a result.
                }
            }
            finally { if (accepted) pipe.Disconnect(); } // Broken pipes must also be reset before accepting another client.
        }
    }

    private static async Task WatchDisconnectAsync(Stream pipe, CancellationTokenSource request)
    {
        byte[] extra = new byte[1];
        int received = await pipe.ReadAsync(extra, request.Token);
        if (received >= 0) request.Cancel(); // EOF or unexpected extra input both end this request.
    }
}
