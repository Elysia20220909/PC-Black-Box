using System.IO;
using System.Windows;

namespace DestinyBlackBox;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        CommandLineMode mode = ParseCommandLineMode(e.Args);
        bool commandLineMode = mode != CommandLineMode.Window;

        // Refused before the baseline is consulted, so an elevated operator reads why this was
        // declined instead of a generic verification failure. The posture still follows on the
        // command line, because a refused launch is exactly when the detail is worth having.
        if (ProcessElevation.IsElevated)
        {
            base.OnStartup(e);
            if (commandLineMode)
            {
                try { Console.Error.WriteLine(ProcessElevation.SafeRefusalLine); } catch { }
                WriteLines(Console.Error, WindowsProcessHardening.Current);
            }
            else
            {
                MessageBox.Show(
                    BuildElevationRefusalMessage(IsJapanese()),
                    "PC Black Box",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            ExitWith(1);
            return;
        }

        SecurityPosture posture = WindowsProcessHardening.Current;
        if (!posture.IsEnforced)
        {
            base.OnStartup(e);
            if (commandLineMode)
            {
                WriteLines(Console.Error, posture);
            }
            else
            {
                MessageBox.Show(
                    BuildSecurityFailureMessage(posture, IsJapanese()),
                    "PC Black Box",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            ExitWith(1);
            return;
        }

        base.OnStartup(e);

        switch (mode)
        {
            case CommandLineMode.Window:
                new MainWindow().Show();
                break;
            case CommandLineMode.BoundaryHost:
                ExitWith(RunBoundaryTestHost(e.Args));
                break;
            case CommandLineMode.SecurityStatus:
                WriteRuntimeStatus();
                WriteLines(Console.Out, posture);
                ExitWith(0);
                break;
            case CommandLineMode.SelfTest:
                ExitWith(RunSelfTest());
                break;
            case CommandLineMode.Report:
                ExitWith(RunReport(e.Args[1], e.Args[2]));
                break;
            case CommandLineMode.Batch:
                ExitWith(RunBatch(e.Args));
                break;
            default:
                // A mistyped command must not open a window that an unattended script then waits on.
                try { Console.Error.WriteLine("PC_BLACK_BOX_USAGE invalid-arguments"); } catch { }
                ExitWith(1);
                break;
        }
    }

    private void ExitWith(int exitCode)
    {
        Environment.ExitCode = exitCode;
        Shutdown(exitCode);
    }

    internal enum CommandLineMode
    {
        Window,
        Report,
        SecurityStatus,
        SelfTest,
        Batch,
        BoundaryHost,
        Invalid
    }

    internal static CommandLineMode ParseCommandLineMode(IReadOnlyList<string> args)
    {
        if (args.Count == 0) return CommandLineMode.Window;
        return args[0].ToLowerInvariant() switch
        {
            "--report" when args.Count == 3 => CommandLineMode.Report,
            "--security-status" when args.Count == 1 => CommandLineMode.SecurityStatus,
            "--self-test" when args.Count == 1 => CommandLineMode.SelfTest,
            "--batch" => CommandLineMode.Batch,
            "--runtime-boundary-test-host" => CommandLineMode.BoundaryHost,
            _ => CommandLineMode.Invalid
        };
    }

    private static int RunSelfTest()
    {
        WriteRuntimeStatus();
        ProductSelfTestResult result = ProductSelfTest.Run();
        try { Console.Out.WriteLine(result.SafeStatusLine); } catch { }
        return result.Passed ? 0 : 1;
    }

    private static int RunReport(string target, string outputPath)
    {
        try
        {
            var inspector = new FileInspector();
            ScanResult result = inspector.ScanAsync(target, null, CancellationToken.None).GetAwaiter().GetResult();
            SafeReportWriter.Write(outputPath, ReportBuilder.Build(result, "en"), result, ".md", allowOverwrite: false);
            return 0;
        }
        catch
        {
            try { Console.Error.WriteLine("Inspection failed safely. No report was written."); } catch { }
            return 1;
        }
    }

    private static int RunBatch(string[] args)
    {
        try
        {
            string? fileListPath = null;
            string? outputPath = null;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i].Equals("--file-list", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    fileListPath = args[++i];
                else if (args[i].Equals("--output", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    outputPath = args[++i];
                else
                    throw new ArgumentException("--batch accepts only --file-list and --output.");
            }

            if (fileListPath is null || outputPath is null)
            {
                throw new ArgumentException("--batch requires --file-list and --output.");
            }

            List<string> targets = BatchFileList.Read(fileListPath);
            if (targets.Count == 0)
            {
                throw new ArgumentException("The file list contains no inspection targets.");
            }

            var inspector = new FileInspector();
            var results = new List<ScanResult>();
            foreach (string target in targets)
            {
                try
                {
                    results.Add(inspector.ScanAsync(target, null, CancellationToken.None).GetAwaiter().GetResult());
                }
                catch
                {
                    // 個別ターゲットの失敗はバッチ全体を止めず、次のターゲットへ進む。
                    results.Add(new ScanResult
                    {
                        TargetPath = target,
                        TargetName = Path.GetFileName(target),
                        StartedAt = DateTime.Now,
                        IsPartial = true,
                        PartialReason = "Inspection failed safely; target was skipped."
                    });
                }
            }

            string json = ReportBuilder.BuildBatchJson(results, "en");
            SafeReportWriter.WriteBatch(outputPath, json, targets, ".json", allowOverwrite: false);
            return BatchExitCode(results);
        }
        catch
        {
            try { Console.Error.WriteLine("Batch inspection failed safely. No report was written."); } catch { }
            return 1;
        }
    }

    /// <summary>Exit code for a batch whose report was written but which did not finish every target.</summary>
    internal const int BatchIncompleteExitCode = 2;

    /// <summary>
    /// A script that reads only the exit code must not mistake an unfinished batch for a finished one.
    /// Risk stays out of this code on purpose: it reports whether the inspection finished, not its verdict.
    /// </summary>
    internal static int BatchExitCode(IEnumerable<ScanResult> results) =>
        results.Any(result => result.IsPartial) ? BatchIncompleteExitCode : 0;

    // Only the test runner uses this bounded, redirected session. Reaching readiness requires the
    // same elevation and required-posture checks as normal startup, before any window is created.
    private static int RunBoundaryTestHost(string[] args)
    {
        try
        {
            if (args.Length != 1 || !Console.IsInputRedirected || !Console.IsOutputRedirected || !Console.IsErrorRedirected)
            {
                Console.Error.WriteLine("PC_BLACK_BOX_RUNTIME_BOUNDARY_HOST invalid-arguments-or-streams");
                return 1;
            }

            Console.Out.WriteLine(RuntimeExecutionInfo.SafeStatusLine);
            Console.Out.WriteLine("PC_BLACK_BOX_RUNTIME_BOUNDARY_HOST ready=true");
            Console.Out.Flush();
            // Console.In may wrap a synchronous reader, so its ReadLineAsync can block before
            // returning a task. Keep the bounded wait separate from that read.
            Task<string?> request = Task.Run(() => Console.In.ReadLine());
            if (request.Wait(TimeSpan.FromSeconds(30)) && request.Result == "release")
            {
                return 0;
            }

            Console.Error.WriteLine("PC_BLACK_BOX_RUNTIME_BOUNDARY_HOST invalid-release-or-timeout");
        }
        catch
        {
            try { Console.Error.WriteLine("PC_BLACK_BOX_RUNTIME_BOUNDARY_HOST failed"); } catch { }
        }

        return 1;
    }

    private static void WriteRuntimeStatus()
    {
        try { Console.Out.WriteLine(RuntimeExecutionInfo.SafeStatusLine); } catch { }
        // The verification runner rejects a missing line; never substitute an SDK or guessed value.
    }

    /// <summary>The operator's own language choice, read the way the main window reads it.</summary>
    private static bool IsJapanese()
    {
        try { return !SettingsStore.LoadLanguage().Equals("en", StringComparison.Ordinal); }
        catch { return true; }
    }

    /// <summary>
    /// Names the required controls that did not verify. A dialog that says only "the baseline" failed
    /// sends the operator looking for a fault in their machine instead of at the one line that is
    /// actually missing. Every name here comes from the fixed baseline list, never from a target.
    /// </summary>
    internal static string BuildSecurityFailureMessage(SecurityPosture posture, bool japanese)
    {
        IReadOnlyList<string> failedRequiredControls = posture.SafeFailedRequiredControlLines;
        string failedControls = failedRequiredControls.Count > 0
            ? String.Join(Environment.NewLine, failedRequiredControls)
            : "control=unknown tier=required state=not-enforced";

        return japanese
            ? $"必須のセキュリティ基準を確認できなかったため、ファイルを調べずに終了します。{Environment.NewLine}{Environment.NewLine}" +
              $"{posture.SafeStatusLine}{Environment.NewLine}{Environment.NewLine}確認できなかった必須項目:{Environment.NewLine}{failedControls}"
            : $"The required security baseline could not be verified. PC Black Box will close without inspecting any files.{Environment.NewLine}{Environment.NewLine}" +
              $"{posture.SafeStatusLine}{Environment.NewLine}{Environment.NewLine}Failed required control(s):{Environment.NewLine}{failedControls}";
    }

    /// <summary>Says what to do instead, in the operator's language. The machine-readable line stays fixed.</summary>
    internal static string BuildElevationRefusalMessage(bool japanese) => japanese
        ? "管理者権限では実行しません。この画面を閉じて、通常の権限で起動し直してください。"
        : ProcessElevation.RefusalMessage;

    /// <summary>Emits the posture summary and one line per control. Every line is sanitized and machine-readable.</summary>
    private static void WriteLines(TextWriter writer, SecurityPosture posture)
    {
        try
        {
            writer.WriteLine(posture.SafeStatusLine);
            foreach (string line in posture.SafeControlLines)
            {
                writer.WriteLine(line);
            }
        }
        catch
        {
        }
    }
}
