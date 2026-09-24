using System.IO;
using System.Windows;

namespace DestinyBlackBox;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        bool commandLineReport = e.Args.Length >= 3 && e.Args[0].Equals("--report", StringComparison.OrdinalIgnoreCase);
        bool commandLineSecurityStatus = e.Args.Length == 1 && e.Args[0].Equals("--security-status", StringComparison.OrdinalIgnoreCase);
        bool commandLineSelfTest = e.Args.Length == 1 && e.Args[0].Equals("--self-test", StringComparison.OrdinalIgnoreCase);
        bool commandLineDefender = e.Args.Length > 0 && e.Args[0].Equals("--defender-status", StringComparison.OrdinalIgnoreCase);
        bool commandLineProtection = e.Args.Length > 0 && e.Args[0].Equals("--protection-status", StringComparison.OrdinalIgnoreCase);
        bool dieImport = e.Args.Length > 0 && e.Args[0] is "--die-report" or "--die-view";
        bool dieSessionTest = e.Args.Length > 0 && e.Args[0] == "--die-session-test";
        bool commandLineMode = commandLineReport || commandLineSecurityStatus || commandLineSelfTest || commandLineDefender || commandLineProtection || dieImport || dieSessionTest;

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
            Environment.ExitCode = 1;
            Shutdown(1);
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
            Environment.ExitCode = 1;
            Shutdown(1);
            return;
        }

        base.OnStartup(e);

        if (dieSessionTest)
        {
            try
            {
                if (e.Args.Length != 3) throw new ArgumentException();
                ScanResult result = new FileInspector().ScanAsync(e.Args[1], null, CancellationToken.None).GetAwaiter().GetResult();
                DieSessionClient.DisconnectProbeAsync(false, e.Args[1]).GetAwaiter().GetResult();
                DieSessionClient.DisconnectProbeAsync(true, e.Args[1]).GetAwaiter().GetResult();
                bool cancelled = false;
                bool parserStarted = false;
                using (var cancelProbe = new CancellationTokenSource(TimeSpan.FromSeconds(90)))
                {
                    try
                    {
                        DieSessionClient.AttachAsync(result, e.Args[1], cancelProbe.Token, () =>
                        {
                            parserStarted = true;
                            cancelProbe.Cancel();
                        }).GetAwaiter().GetResult();
                    }
                    catch (OperationCanceledException) { cancelled = true; }
                }
                if (!cancelled || !parserStarted || !result.DieCleanup.NeedsAttention) throw new IOException("Post-start cancellation was not observed.");
                for (int i = 0; i < 2; i++)
                {
                    DieSessionClient.AttachAsync(result, e.Args[1], CancellationToken.None).GetAwaiter().GetResult();
                    if (result.Die is null || result.DieStatus != "complete" || result.DieCleanup.NeedsAttention) throw new IOException("DiE session or cleanup failed.");
                }
                if (!WindowsProcessHardening.Current.IsEnforced || !NetworkIsolationGuard.IsArmedAndManagedTransportFree()) throw new IOException();
                SafeReportWriter.Write(e.Args[2], ReportBuilder.Build(result, "en"), result, ".md", allowOverwrite: false);
                Console.WriteLine("PCBB_DIE_SESSION passed=true disconnectBeforeRequest=true disconnectAfterStart=true cancellationAfterStart=true repeatedRequests=2 cleanup=true controls=16/16");
                Shutdown(0);
            }
            catch { Console.Error.WriteLine("PCBB_DIE_SESSION passed=false"); Shutdown(1); }
            return;
        }

        if (dieImport)
        {
            try
            {
                bool headless = e.Args[0] == "--die-report";
                if (e.Args.Length != (headless ? 4 : 3)) throw new ArgumentException();
                ScanResult result = new FileInspector().ScanAsync(e.Args[1], null, CancellationToken.None).GetAwaiter().GetResult();
                result.Die = DieEvidence.Read(e.Args[2], result);
                result.DieStatus = "complete";
                // Legacy evidence files contain no post-cleanup acknowledgement.
                result.DieCleanup = DieCleanupStatus.Unknown;
                if (headless)
                {
                    SafeReportWriter.Write(e.Args[3], ReportBuilder.Build(result, "en"), result, ".md", allowOverwrite: false);
                    Console.WriteLine("PC_BLACK_BOX_DIE imported=true digestMatched=true");
                    Shutdown(0);
                }
                else
                {
                    var window = new MainWindow();
                    window.ShowImportedDieResult(result);
                    window.Show();
                }
            }
            catch
            {
                Console.Error.WriteLine("DiE evidence rejected or inspection failed. No safety verdict was produced.");
                Shutdown(1);
            }
            return;
        }

        if (commandLineDefender || commandLineProtection)
        {
            if (e.Args.Length != 1)
            {
                try { Console.Error.WriteLine("Protection status modes accept no additional arguments."); } catch { }
                Shutdown(1);
                return;
            }
            DefenderSnapshot snapshot = DefenderReader.Shared.ReadAsync().GetAwaiter().GetResult();
            IsolationPresenceSnapshot? tools = commandLineProtection ? IsolationToolReader.Shared.ReadAsync().GetAwaiter().GetResult() : null;
            bool guardsIntact = NetworkIsolationGuard.IsArmedAndManagedTransportFree() && ProcessObjectLockdown.VerifyCurrentPolicy();
            try { Console.Out.WriteLine(tools is null ? snapshot.ToJson() : tools.WithDefenderJson(snapshot)); } catch { guardsIntact = false; }
            WriteLines(Console.Error, WindowsProcessHardening.Current);
            // Exit 0 means retrieval completed, not that the machine or any file is safe.
            bool complete = snapshot.RetrievalComplete && (!commandLineProtection ||
                (snapshot.ExtendedProtectionState == DefenderReadState.Complete && tools?.State == DefenderReadState.Complete));
            Environment.ExitCode = guardsIntact && complete ? 0 : 1;
            Shutdown(Environment.ExitCode);
            return;
        }

        if (commandLineSecurityStatus)
        {
            WriteLines(Console.Out, posture);
            Environment.ExitCode = 0;
            Shutdown(0);
            return;
        }

        if (commandLineSelfTest)
        {
            ProductSelfTestResult result = ProductSelfTest.Run();
            try { Console.Out.WriteLine(result.SafeStatusLine); } catch { }
            Environment.ExitCode = result.Passed ? 0 : 1;
            Shutdown(Environment.ExitCode);
            return;
        }

        if (commandLineReport)
        {
            try
            {
                var inspector = new FileInspector();
                ScanResult result = inspector.ScanAsync(e.Args[1], null, CancellationToken.None).GetAwaiter().GetResult();
                SafeReportWriter.Write(e.Args[2], ReportBuilder.Build(result, "en"), result, ".md", allowOverwrite: false);
                Environment.ExitCode = 0;
            }
            catch
            {
                try { Console.Error.WriteLine("Inspection failed safely. No report was written."); } catch { }
                Environment.ExitCode = 1;
            }

            Shutdown(Environment.ExitCode);
            return;
        }

        new MainWindow().Show();
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
