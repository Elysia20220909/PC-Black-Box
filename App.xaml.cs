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
        bool commandLineMode = commandLineReport || commandLineSecurityStatus || commandLineSelfTest;

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
                    ProcessElevation.RefusalMessage,
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
                    "The required security baseline could not be verified. PC Black Box will close without inspecting files.",
                    "PC Black Box",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            Environment.ExitCode = 1;
            Shutdown(1);
            return;
        }

        base.OnStartup(e);

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
