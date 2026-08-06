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
        SecurityPosture posture = WindowsProcessHardening.Current;
        if (!posture.IsEnforced)
        {
            base.OnStartup(e);
            if (commandLineMode)
            {
                try { Console.Error.WriteLine(posture.SafeStatusLine); } catch { }
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
            try { Console.Out.WriteLine(posture.SafeStatusLine); } catch { }
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
}
