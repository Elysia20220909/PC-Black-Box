using System.IO;
using System.Windows;

namespace DestinyBlackBox;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        bool commandLineReport = e.Args.Length >= 3 && e.Args[0].Equals("--report", StringComparison.OrdinalIgnoreCase);
        if (!WindowsProcessHardening.ApplyRequiredPolicies())
        {
            base.OnStartup(e);
            if (commandLineReport)
            {
                try { Console.Error.WriteLine("Required Windows process protections could not be enabled."); } catch { }
            }
            else
            {
                MessageBox.Show(
                    "Required Windows process protections could not be enabled. PC Black Box will close without inspecting files.",
                    "PC Black Box",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            Environment.ExitCode = 1;
            Shutdown(1);
            return;
        }

        base.OnStartup(e);

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
